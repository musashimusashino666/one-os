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
    /// The allocator accepted a permanent reservation but its side metadata
    /// could not identify the corresponding managed frame.
    ReservationTrackingFailed,
}

impl MemoryError {
    pub const fn message(&self) -> &'static [u8] {
        match self {
            Self::Busy => b"Physical allocator is busy\n",
            Self::AlreadyInitialized => b"Physical allocator was initialized twice\n",
            Self::NotInitialized => b"Physical allocator is not initialized\n",
            Self::BootPolicy(error) => error.message(),
            Self::Allocator(error) => error.message(),
            Self::ReservationTrackingFailed => {
                b"Could not track permanent physical-frame reservation\n"
            }
        }
    }
}

struct GlobalAllocator {
    lock: AtomicBool,
    initialized: AtomicBool,
    segments: UnsafeCell<[FrameSegment; SEGMENT_CAPACITY]>,
    bitmap: UnsafeCell<[u64; BITMAP_WORDS]>,
    // A separate bitmap distinguishes permanent boot reservations from frames
    // allocated through ordinary Frame tokens. The allocator's main bitmap
    // deliberately marks both unavailable, so it cannot make this distinction.
    reserved_bitmap: UnsafeCell<[u64; BITMAP_WORDS]>,
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
            reserved_bitmap: UnsafeCell::new([0; BITMAP_WORDS]),
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

    // Clear the side bitmap before publishing the allocator. It tracks only
    // successful permanent reservations made by reserve_frame below.
    // SAFETY: GLOBAL's lock is held and initialization has not been published.
    unsafe { (*GLOBAL.reserved_bitmap.get()).fill(0) };

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
    let managed = allocator
        .reserve_frame(physical_address)
        .map_err(MemoryError::Allocator)?;
    if !managed {
        return Ok(false);
    }

    let index = allocator
        .managed_frame_index(physical_address)
        .ok_or(MemoryError::ReservationTrackingFailed)?;
    // SAFETY: GLOBAL's lock serializes writes to both allocator and side metadata.
    // The frame index was obtained from this allocator and is within its managed
    // usable-frame count, which is bounded by MAX_MANAGED_FRAMES.
    let bitmap = unsafe { &mut *GLOBAL.reserved_bitmap.get() };
    bitmap[index / u64::BITS as usize] |= 1u64 << (index % u64::BITS as usize);
    Ok(true)
}

/// Returns the current number of frames available to a bounded, exhaustive scan.
#[cfg(feature = "test-wx-runtime-audit")]
pub fn free_frame_count() -> Result<usize, MemoryError> {
    let _guard = GLOBAL.acquire()?;
    if !GLOBAL.initialized.load(Ordering::Acquire) {
        return Err(MemoryError::NotInitialized);
    }

    // SAFETY: the initialized flag was published after writing the allocator,
    // and the lock provides exclusive access for the duration of this query.
    let allocator = unsafe { (&*GLOBAL.allocator.get()).assume_init_ref() };
    Ok(allocator.stats().free_frames)
}

/// Returns whether the physical frame was permanently reserved before allocation.
///
/// This is distinct from is_frame_allocated: permanent reservations intentionally
/// have no releasable Frame token and must not be accepted as ordinary data-frame
/// mapping targets. The side bitmap is indexed by the allocator's managed-frame
/// ordering. Addresses outside managed Usable memory return false; lock or
/// initialization failures are propagated so security-sensitive callers can fail closed.
pub fn is_permanently_reserved(physical_address: u64) -> Result<bool, MemoryError> {
    let _guard = GLOBAL.acquire()?;
    if !GLOBAL.initialized.load(Ordering::Acquire) {
        return Err(MemoryError::NotInitialized);
    }

    // SAFETY: initialization is published after the allocator is written, and
    // GLOBAL's lock protects the allocator and reservation side bitmap.
    let allocator = unsafe { (&*GLOBAL.allocator.get()).assume_init_ref() };
    let Some(index) = allocator.managed_frame_index(physical_address) else {
        return Ok(false);
    };
    let bitmap = unsafe { &*GLOBAL.reserved_bitmap.get() };
    Ok(bitmap[index / u64::BITS as usize] & (1u64 << (index % u64::BITS as usize)) != 0)
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
