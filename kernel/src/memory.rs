use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, Ordering};

use bootloader_api::info::{MemoryRegion, MemoryRegionKind};
use oneos_core::{
    Frame, FrameAllocator, FrameAllocatorError, FrameAllocatorStats, FrameSegment, PAGE_SIZE,
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
    KernelImageRangeInvalid,
    KernelImageMarkedUsable,
    Allocator(FrameAllocatorError),
}

impl MemoryError {
    pub const fn message(&self) -> &'static [u8] {
        match self {
            Self::Busy => b"Physical allocator is busy\n",
            Self::AlreadyInitialized => b"Physical allocator was initialized twice\n",
            Self::NotInitialized => b"Physical allocator is not initialized\n",
            Self::KernelImageRangeInvalid => b"Kernel physical image range is invalid\n",
            Self::KernelImageMarkedUsable => b"Kernel image overlaps allocatable memory\n",
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

    let kernel_physical_end = kernel_physical_start
        .checked_add(kernel_physical_len)
        .filter(|_| kernel_physical_len != 0)
        .ok_or(MemoryError::KernelImageRangeInvalid)?;
    if regions.iter().any(|region| {
        matches!(region.kind, MemoryRegionKind::Usable)
            && region.start < kernel_physical_end
            && kernel_physical_start < region.end
    }) {
        // Refuse to manage a map that would permit the kernel image, including
        // this static metadata, to be reallocated as free physical frames.
        return Err(MemoryError::KernelImageMarkedUsable);
    }

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
