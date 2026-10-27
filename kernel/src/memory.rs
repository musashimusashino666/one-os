use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, Ordering};

use bootloader_api::info::{MemoryRegion, MemoryRegionKind};
use oneos_core::{
    validate_boot_memory_policy, BootMemoryPolicyError, Frame, FrameAllocator, FrameAllocatorError,
    FrameAllocatorStats, FrameSegment, PAGE_SIZE,
};

/// Bootstrap metadata limit: 16 GiB of aggregate usable RAM and 256 usable
/// memory regions. Exceeding either limit fails closed; later milestones can
/// move this metadata into allocator-managed memory after virtual mapping works.
const MAX_MANAGED_USABLE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_MANAGED_FRAMES: usize = (MAX_MANAGED_USABLE_BYTES / PAGE_SIZE) as usize;
const BITMAP_WORDS: usize = MAX_MANAGED_FRAMES / u64::BITS as usize;
const SEGMENT_CAPACITY: usize = 256;

pub enum MemoryError {
    Busy,
    AlreadyInitialized,
    NotInitialized,
    BootPolicy(BootMemoryPolicyError),
    Allocator(FrameAllocatorError),
}

impl MemoryError {
    pub const fn message(&self) -> &'static [u8] {
        match self {
            Self::Busy => b"Physical allocator is busy\n",
            Self::AlreadyInitialized => b"Physical allocator was initialized twice\n",
            Self::NotInitialized => b"Physical allocator is not initialized\n",
            Self::BootPolicy(error) => error.message(),
            Self::Allocator(error) => error.message(),
        }
    }
}

struct GlobalAllocator {
    lock: AtomicBool,
    initialized: AtomicBool,
    segments: UnsafeCell<[FrameSegment; SEGMENT_CAPACITY]>,
    bitmap: UnsafeCell<[u64; BITMAP_WORDS]>,
    allocator: UnsafeCell<MaybeUninit<FrameAllocator<'static>>>,
}

// SAFETY: every access to the allocator and its backing metadata is protected
// by lock. The backing buffers have static storage and are initialized once.
unsafe impl Sync for GlobalAllocator {}

impl GlobalAllocator {
    const fn new() -> Self {
        Self {
            lock: AtomicBool::new(false),
            initialized: AtomicBool::new(false),
            segments: UnsafeCell::new([FrameSegment::EMPTY; SEGMENT_CAPACITY]),
            bitmap: UnsafeCell::new([0; BITMAP_WORDS]),
            allocator: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    fn acquire(&self) -> Result<MemoryLock<'_>, MemoryError> {
        self.lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| MemoryError::Busy)?;
        Ok(MemoryLock(&self.lock))
    }
}

struct MemoryLock<'a>(&'a AtomicBool);

impl Drop for MemoryLock<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

static GLOBAL: GlobalAllocator = GlobalAllocator::new();

/// Initializes the global allocator from the bootloader's memory map.
///
/// Only regions explicitly marked Usable are eligible. Bootloader and unknown
/// regions remain reserved. The core allocator excludes physical frame zero
/// and rounds each region inward to complete 4 KiB frames.
pub fn initialize(
    regions: &[MemoryRegion],
    kernel_physical_start: u64,
    kernel_physical_len: u64,
) -> Result<FrameAllocatorStats, MemoryError> {
    let _guard = GLOBAL.acquire()?;
    if GLOBAL.initialized.load(Ordering::Acquire) {
        return Err(MemoryError::AlreadyInitialized);
    }

    validate_boot_memory_policy(
        regions.len(),
        |index| {
            let region = regions[index];
            (
                region.start,
                region.end,
                matches!(region.kind, MemoryRegionKind::Usable),
            )
        },
        kernel_physical_start,
        kernel_physical_len,
        SEGMENT_CAPACITY,
        MAX_MANAGED_FRAMES,
    )
    .map_err(MemoryError::BootPolicy)?;

    // SAFETY: GLOBAL has static storage; its lock is held; the arrays are
    // exclusively borrowed for the lifetime of the allocator stored below.
    let segment_storage: &'static mut [FrameSegment] = unsafe {
        core::slice::from_raw_parts_mut(
            GLOBAL.segments.get().cast::<FrameSegment>(),
            SEGMENT_CAPACITY,
        )
    };
    // SAFETY: same exclusivity and static-lifetime argument as segment_storage.
    let bitmap_storage: &'static mut [u64] =
        unsafe { core::slice::from_raw_parts_mut(GLOBAL.bitmap.get().cast::<u64>(), BITMAP_WORDS) };

    let allocator: FrameAllocator<'static> = FrameAllocator::initialize(
        regions.len(),
        |index| {
            let region = regions[index];
            (
                region.start,
                region.end,
                matches!(region.kind, MemoryRegionKind::Usable),
            )
        },
        segment_storage,
        bitmap_storage,
    )
    .map_err(MemoryError::Allocator)?;

    let stats = allocator.stats();
    // SAFETY: initialization is serialized and the initialized flag is false.
    unsafe {
        (*GLOBAL.allocator.get()).write(allocator);
    }
    GLOBAL.initialized.store(true, Ordering::Release);
    Ok(stats)
}

/// Allocates one physical frame from the global allocator.
///
/// The global lock serializes mutations. A concurrent or interrupt-context
/// attempt does not spin: it receives Busy and can retry in an appropriate
/// context. Returned addresses are physical; this API does not map or clear
/// the frame's contents.
pub fn allocate_frame() -> Result<Frame, MemoryError> {
    let _guard = GLOBAL.acquire()?;
    if !GLOBAL.initialized.load(Ordering::Acquire) {
        return Err(MemoryError::NotInitialized);
    }

    // SAFETY: the initialized flag was published after writing the allocator,
    // and the lock provides exclusive access for the duration of this call.
    let allocator = unsafe { (&mut *GLOBAL.allocator.get()).assume_init_mut() };
    allocator.allocate_frame().map_err(MemoryError::Allocator)
}

/// Permanently reserves an already mapped kernel frame before the first allocation.
///
/// Returns true when the physical address belongs to a managed Usable region and
/// is now unavailable to allocate_frame; false means it is outside managed memory.
/// All kernel PT_LOAD reservations must complete before any allocation attempt.
pub fn reserve_frame(physical_address: u64) -> Result<bool, MemoryError> {
    let _guard = GLOBAL.acquire()?;
    if !GLOBAL.initialized.load(Ordering::Acquire) {
        return Err(MemoryError::NotInitialized);
    }

    // SAFETY: the initialized flag was published after writing the allocator,
    // and the lock provides exclusive access for the duration of this call.
    let allocator = unsafe { (&mut *GLOBAL.allocator.get()).assume_init_mut() };
    allocator
        .reserve_frame(physical_address)
        .map_err(MemoryError::Allocator)
}

/// Queries whether a frame is currently allocated by the global allocator.
///
/// The allocator lock protects the bitmap read. The current page-table mutation
/// caller has interrupts disabled and runs under the single-CPU bootstrap contract,
/// so a frame cannot be freed/reallocated between this check and map publication.
/// This check is not a substitute for a retained ownership token or cross-CPU
/// synchronization if the kernel becomes preemptive or SMP.
pub fn is_frame_allocated(physical_address: u64) -> Result<bool, MemoryError> {
    let _guard = GLOBAL.acquire()?;
    if !GLOBAL.initialized.load(Ordering::Acquire) {
        return Err(MemoryError::NotInitialized);
    }

    // SAFETY: the initialized flag was published after writing the allocator,
    // and the lock provides exclusive access for the duration of this query.
    let allocator = unsafe { (&*GLOBAL.allocator.get()).assume_init_ref() };
    Ok(allocator.is_frame_allocated(physical_address))
}

/// Frees a frame token previously returned by this global allocator.
///
/// On failure the original token is returned with the error, so transient lock
/// contention or a mismatched allocator never silently discards ownership.
pub fn free_frame(frame: Frame) -> Result<(), (MemoryError, Frame)> {
    let _guard = match GLOBAL.acquire() {
        Ok(guard) => guard,
        Err(error) => return Err((error, frame)),
    };
    if !GLOBAL.initialized.load(Ordering::Acquire) {
        return Err((MemoryError::NotInitialized, frame));
    }

    // SAFETY: the initialized flag was published after writing the allocator,
    // and the lock provides exclusive access for the duration of this call.
    let allocator = unsafe { (&mut *GLOBAL.allocator.get()).assume_init_mut() };
    allocator
        .free_frame(frame)
        .map_err(|(error, frame)| (MemoryError::Allocator(error), frame))
}

/// Returns a rejected scan candidate without rewinding the allocator's forward
/// search hint. Ordinary frame releases should continue to use free_frame.
#[cfg(feature = "test-wx-runtime-audit")]
pub fn free_frame_preserving_hint(frame: Frame) -> Result<(), (MemoryError, Frame)> {
    let _guard = match GLOBAL.acquire() {
        Ok(guard) => guard,
        Err(error) => return Err((error, frame)),
    };
    if !GLOBAL.initialized.load(Ordering::Acquire) {
        return Err((MemoryError::NotInitialized, frame));
    }

    // SAFETY: the initialized flag was published after writing the allocator,
    // and the lock provides exclusive access for the duration of this call.
    let allocator = unsafe { (&mut *GLOBAL.allocator.get()).assume_init_mut() };
    allocator
        .free_frame_preserving_hint(frame)
        .map_err(|(error, frame)| (MemoryError::Allocator(error), frame))
}
