use core::sync::atomic::{AtomicU64, Ordering};

use super::{validate_memory_map, MemoryMapError};

/// Page size used by the initial x86_64 physical-frame allocator.
pub const PAGE_SIZE: u64 = 4096;

const BITS_PER_WORD: usize = u64::BITS as usize;

/// Storage for one usable physical region in the allocator's compact bitmap.
///
/// Construct storage with FrameSegment::EMPTY. Fields are intentionally private:
/// the allocator owns and maintains the segment metadata.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FrameSegment {
    physical_start: u64,
    frame_count: usize,
    bitmap_start: usize,
}

impl FrameSegment {
    /// Empty metadata slot for caller-provided fixed-capacity storage.
    pub const EMPTY: Self = Self {
        physical_start: 0,
        frame_count: 0,
        bitmap_start: 0,
    };
}

/// An owned allocation token for one physical frame.
///
/// The token is not Copy or Clone. It must be returned to the allocator that
/// issued it; dropping it without freeing intentionally leaks the frame rather
/// than silently making memory available for reuse.
#[must_use = "dropping a frame token without freeing it leaks the physical frame"]
#[derive(Debug, Eq, PartialEq)]
pub struct Frame {
    physical_address: u64,
    bitmap_index: usize,
    allocator_id: u64,
}

impl Frame {
    /// Returns the physical start address of this 4 KiB frame.
    pub const fn physical_address(&self) -> u64 {
        self.physical_address
    }
}

/// Snapshot of physical allocator capacity and use.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameAllocatorStats {
    /// Number of usable memory regions with at least one complete frame.
    pub usable_regions: usize,
    /// Number of allocatable 4 KiB frames at initialization.
    pub total_frames: usize,
    /// Number of frames unavailable for allocation (owned allocations plus permanent reservations).
    pub allocated_frames: usize,
    /// Number of frames currently available.
    pub free_frames: usize,
}

/// An initialization, allocation, or release error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameAllocatorError {
    /// The underlying physical memory map is structurally invalid.
    MemoryMap(MemoryMapError),
    /// No usable region contains a complete, non-zero physical frame.
    NoUsableFrames,
    /// The supplied region metadata cannot describe every usable segment.
    SegmentStorageTooSmall { required: usize, available: usize },
    /// The supplied bitmap cannot represent every usable frame.
    BitmapTooSmall {
        required_words: usize,
        available_words: usize,
    },
    /// A size or address calculation overflowed.
    CapacityOverflow,
    /// The process-wide allocator identity space was exhausted.
    AllocatorIdExhausted,
    /// All managed frames are currently allocated.
    Exhausted,
    /// The frame token was issued by a different allocator instance.
    ForeignFrame,
    /// The frame token does not represent a currently allocated frame.
    FrameNotAllocated,
    /// A reservation was attempted after the allocator returned to allocation callers.
    ReservationAfterAllocation,
    /// A permanent reservation requires an aligned, non-zero physical frame address.
    InvalidReservationAddress,
}

impl FrameAllocatorError {
    /// Stable, allocation-free diagnostic suitable for early kernel logging.
    pub const fn message(&self) -> &'static [u8] {
        match self {
            Self::MemoryMap(_) => b"Physical memory map is invalid\n",
            Self::NoUsableFrames => b"No complete usable physical frames\n",
            Self::SegmentStorageTooSmall { .. } => b"Physical region metadata capacity exceeded\n",
            Self::BitmapTooSmall { .. } => b"Physical frame bitmap capacity exceeded\n",
            Self::CapacityOverflow => b"Physical allocator size arithmetic overflowed\n",
            Self::AllocatorIdExhausted => b"Physical allocator identity space exhausted\n",
            Self::Exhausted => b"No free physical frames remain\n",
            Self::ForeignFrame => b"Frame token belongs to another allocator\n",
            Self::FrameNotAllocated => b"Frame token is not currently allocated\n",
            Self::ReservationAfterAllocation => {
                b"Kernel frame reservations must precede all allocations\n"
            }
            Self::InvalidReservationAddress => {
                b"Cannot reserve an invalid physical frame address\n"
            }
        }
    }
}

static NEXT_ALLOCATOR_ID: AtomicU64 = AtomicU64::new(1);

fn allocate_allocator_id() -> Option<u64> {
    NEXT_ALLOCATOR_ID
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .ok()
}

/// A fixed-capacity, no-alloc physical frame allocator.
///
/// Each bitmap bit represents one 4 KiB frame in the usable regions supplied
/// at initialization. Zero means free; one means allocated. Reserved and
/// unknown region kinds must be passed with usable=false and are never added
/// to the allocator. Physical address zero is always excluded.
///
/// The callback must return stable half-open address ranges and a stable
/// usability classification for each region throughout initialization.
pub struct FrameAllocator<'a> {
    segments: &'a mut [FrameSegment],
    segment_count: usize,
    bitmap: &'a mut [u64],
    bitmap_words: usize,
    total_frames: usize,
    allocated_frames: usize,
    next_hint: usize,
    allocator_id: u64,
    allocation_started: bool,
}

impl<'a> FrameAllocator<'a> {
    /// Validates a memory map and initializes a fixed-capacity bitmap allocator.
    ///
    /// This constructor does not allocate memory for its metadata. The caller
    /// must provide enough segment slots and bitmap words, and must keep that
    /// storage exclusively borrowed for the allocator's lifetime.
    pub fn initialize<F>(
        region_count: usize,
        region_bounds: F,
        segment_storage: &'a mut [FrameSegment],
        bitmap: &'a mut [u64],
    ) -> Result<Self, FrameAllocatorError>
    where
        F: Fn(usize) -> (u64, u64, bool),
    {
        validate_memory_map(region_count, |index| {
            let (start, end, _) = region_bounds(index);
            (start, end)
        })
        .map_err(FrameAllocatorError::MemoryMap)?;

        let mut required_segments = 0usize;
        let mut total_frames = 0usize;

        for index in 0..region_count {
            let (start, end, usable) = region_bounds(index);
            if !usable {
                continue;
            }

            if let Some((_, frame_count)) = aligned_frame_range(start, end)? {
                required_segments = required_segments
                    .checked_add(1)
                    .ok_or(FrameAllocatorError::CapacityOverflow)?;
                total_frames = total_frames
                    .checked_add(frame_count)
                    .ok_or(FrameAllocatorError::CapacityOverflow)?;
            }
        }

        if total_frames == 0 {
            return Err(FrameAllocatorError::NoUsableFrames);
        }

        if required_segments > segment_storage.len() {
            return Err(FrameAllocatorError::SegmentStorageTooSmall {
                required: required_segments,
                available: segment_storage.len(),
            });
        }

        let required_words = total_frames.div_ceil(BITS_PER_WORD);
        if required_words > bitmap.len() {
            return Err(FrameAllocatorError::BitmapTooSmall {
                required_words,
                available_words: bitmap.len(),
            });
        }

        let allocator_id =
            allocate_allocator_id().ok_or(FrameAllocatorError::AllocatorIdExhausted)?;

        let mut segment_index = 0usize;
        let mut bitmap_start = 0usize;
        for index in 0..region_count {
            let (start, end, usable) = region_bounds(index);
            if !usable {
                continue;
            }
            let Some((physical_start, frame_count)) = aligned_frame_range(start, end)? else {
                continue;
            };

            segment_storage[segment_index] = FrameSegment {
                physical_start,
                frame_count,
                bitmap_start,
            };
            segment_index += 1;
            bitmap_start = bitmap_start
                .checked_add(frame_count)
                .ok_or(FrameAllocatorError::CapacityOverflow)?;
        }

        segment_storage[segment_index..].fill(FrameSegment::EMPTY);
        bitmap[..required_words].fill(0);

        // Keep unused tail bits unavailable even if a future search path omits
        // a range mask. The allocator still bounds every search by total_frames.
        let tail_bits = total_frames % BITS_PER_WORD;
        if tail_bits != 0 {
            bitmap[required_words - 1] |= u64::MAX << tail_bits;
        }

        Ok(Self {
            segments: segment_storage,
            segment_count: required_segments,
            bitmap,
            bitmap_words: required_words,
            total_frames,
            allocated_frames: 0,
            next_hint: 0,
            allocator_id,
            allocation_started: false,
        })
    }

    /// Permanently excludes a physical frame from future allocations.
    ///
    /// This is used for frames already occupied by the loaded kernel image when
    /// the bootloader's memory map still labels their containing region Usable.
    /// The reservation carries no releasable Frame token. Reservations must be
    /// completed before the first allocation attempt; duplicate reservations are
    /// idempotent. Returns false when the address is outside managed Usable frames.
    pub fn reserve_frame(&mut self, physical_address: u64) -> Result<bool, FrameAllocatorError> {
        if self.allocation_started {
            return Err(FrameAllocatorError::ReservationAfterAllocation);
        }
        if physical_address == 0 || physical_address & (PAGE_SIZE - 1) != 0 {
            return Err(FrameAllocatorError::InvalidReservationAddress);
        }

        let Some(index) = self.frame_index_for_address(physical_address) else {
            return Ok(false);
        };
        if !self.is_allocated(index) {
            self.set_allocated(index, true);
            self.allocated_frames += 1;
        }
        Ok(true)
    }

    /// Allocates one frame using a word-level bitmap scan.
    pub fn allocate_frame(&mut self) -> Result<Frame, FrameAllocatorError> {
        self.allocation_started = true;
        let index = self
            .find_free_in_range(self.next_hint, self.total_frames)
            .or_else(|| self.find_free_in_range(0, self.next_hint))
            .ok_or(FrameAllocatorError::Exhausted)?;
        let physical_address = self
            .physical_address_for_index(index)
            .ok_or(FrameAllocatorError::CapacityOverflow)?;

        self.set_allocated(index, true);
        self.allocated_frames += 1;
        self.next_hint = if index + 1 == self.total_frames {
            0
        } else {
            index + 1
        };

        Ok(Frame {
            physical_address,
            bitmap_index: index,
            allocator_id: self.allocator_id,
        })
    }

    /// Returns an allocated frame to the allocator that issued its token.
    ///
    /// The token is consumed, preventing ordinary safe Rust code from freeing
    /// the same frame twice or returning it to two allocator instances. The hint
    /// is rewound so ordinary allocation can quickly reuse a recently freed frame.
    pub fn free_frame(&mut self, frame: Frame) -> Result<(), (FrameAllocatorError, Frame)> {
        self.free_frame_with_hint_policy(frame, true)
    }

    /// Returns a frame without rewinding the allocation hint.
    ///
    /// This is for bounded allocation scans that immediately release rejected
    /// candidates: rewinding to each rejected frame would cause the next scan to
    /// select the same candidate again. The hint remains the position reached by
    /// allocations, while ordinary free_frame retains its reuse behavior.
    pub fn free_frame_preserving_hint(
        &mut self,
        frame: Frame,
    ) -> Result<(), (FrameAllocatorError, Frame)> {
        self.free_frame_with_hint_policy(frame, false)
    }

    fn free_frame_with_hint_policy(
        &mut self,
        frame: Frame,
        rewind_hint: bool,
    ) -> Result<(), (FrameAllocatorError, Frame)> {
        if frame.allocator_id != self.allocator_id {
            return Err((FrameAllocatorError::ForeignFrame, frame));
        }

        let index = frame.bitmap_index;
        if index >= self.total_frames
            || self.physical_address_for_index(index) != Some(frame.physical_address)
            || !self.is_allocated(index)
        {
            return Err((FrameAllocatorError::FrameNotAllocated, frame));
        }

        self.set_allocated(index, false);
        self.allocated_frames -= 1;
        if rewind_hint && index < self.next_hint {
            self.next_hint = index;
        }
        Ok(())
    }

    /// Returns whether an exact, aligned non-zero physical frame is currently allocated.
    ///
    /// Addresses outside managed usable segments, free frames, reserved regions,
    /// and unaligned addresses all return false. This query does not prove that
    /// the caller owns the allocation token; synchronization with mapping/freeing
    /// remains the caller's responsibility.
    pub fn is_frame_allocated(&self, physical_address: u64) -> bool {
        self.frame_index_for_address(physical_address)
            .is_some_and(|index| self.is_allocated(index))
    }

    fn frame_index_for_address(&self, physical_address: u64) -> Option<usize> {
        if physical_address == 0 || physical_address & (PAGE_SIZE - 1) != 0 {
            return None;
        }

        for segment in &self.segments[..self.segment_count] {
            let segment_bytes = u64::try_from(segment.frame_count)
                .ok()?
                .checked_mul(PAGE_SIZE)?;
            let segment_end = segment.physical_start.checked_add(segment_bytes)?;
            if physical_address < segment.physical_start || physical_address >= segment_end {
                continue;
            }

            let frame_offset =
                usize::try_from((physical_address - segment.physical_start) / PAGE_SIZE).ok()?;
            let index = segment.bitmap_start.checked_add(frame_offset)?;
            return (index < self.total_frames).then_some(index);
        }

        None
    }

    /// Returns the current number of usable and allocated frames.
    pub fn stats(&self) -> FrameAllocatorStats {
        FrameAllocatorStats {
            usable_regions: self.segment_count,
            total_frames: self.total_frames,
            allocated_frames: self.allocated_frames,
            free_frames: self.total_frames - self.allocated_frames,
        }
    }

    fn find_free_in_range(&self, start: usize, end: usize) -> Option<usize> {
        if start >= end {
            return None;
        }

        let first_word = start / BITS_PER_WORD;
        let last_word = (end - 1) / BITS_PER_WORD;
        for word_index in first_word..=last_word {
            if word_index >= self.bitmap_words {
                return None;
            }
            let word_start = word_index * BITS_PER_WORD;
            let low_bit = start.saturating_sub(word_start);
            let high_bit = (end - word_start).min(BITS_PER_WORD);
            let low_mask = u64::MAX << low_bit;
            let high_mask = if high_bit == BITS_PER_WORD {
                u64::MAX
            } else {
                (1u64 << high_bit) - 1
            };
            let available = !self.bitmap[word_index] & low_mask & high_mask;
            if available != 0 {
                return Some(word_start + available.trailing_zeros() as usize);
            }
        }
        None
    }

    fn physical_address_for_index(&self, index: usize) -> Option<u64> {
        for segment in &self.segments[..self.segment_count] {
            let segment_end = segment.bitmap_start.checked_add(segment.frame_count)?;
            if index < segment.bitmap_start || index >= segment_end {
                continue;
            }

            let offset = u64::try_from(index - segment.bitmap_start)
                .ok()?
                .checked_mul(PAGE_SIZE)?;
            return segment.physical_start.checked_add(offset);
        }
        None
    }

    fn is_allocated(&self, index: usize) -> bool {
        let mask = 1u64 << (index % BITS_PER_WORD);
        self.bitmap[index / BITS_PER_WORD] & mask != 0
    }

    fn set_allocated(&mut self, index: usize, allocated: bool) {
        let mask = 1u64 << (index % BITS_PER_WORD);
        let word = &mut self.bitmap[index / BITS_PER_WORD];
        if allocated {
            *word |= mask;
        } else {
            *word &= !mask;
        }
    }
}

/// Aligns a region inward to complete 4 KiB frames and excludes physical frame
/// zero. Regions without a complete non-zero frame are ignored.
fn aligned_frame_range(start: u64, end: u64) -> Result<Option<(u64, usize)>, FrameAllocatorError> {
    let start = start.max(PAGE_SIZE);
    let Some(aligned_start) = start
        .checked_add(PAGE_SIZE - 1)
        .map(|value| value & !(PAGE_SIZE - 1))
    else {
        return Ok(None);
    };
    let aligned_end = end & !(PAGE_SIZE - 1);
    if aligned_start >= aligned_end {
        return Ok(None);
    }

    let frame_count = usize::try_from((aligned_end - aligned_start) / PAGE_SIZE)
        .map_err(|_| FrameAllocatorError::CapacityOverflow)?;
    if frame_count == 0 {
        return Ok(None);
    }

    Ok(Some((aligned_start, frame_count)))
}

#[cfg(test)]
mod tests {
    use super::{Frame, FrameAllocator, FrameAllocatorError, FrameSegment, PAGE_SIZE};
    use crate::MemoryMapError;
    use std::vec::Vec;

    const SLOT: FrameSegment = FrameSegment::EMPTY;

    fn make_allocator<'a>(
        regions: &[(u64, u64, bool)],
        slots: &'a mut [FrameSegment],
        bitmap: &'a mut [u64],
    ) -> Result<FrameAllocator<'a>, FrameAllocatorError> {
        FrameAllocator::initialize(regions.len(), |index| regions[index], slots, bitmap)
    }

    #[test]
    fn permanently_reserves_loaded_kernel_frames_before_allocation() {
        let regions = [(0x1000, 0x6000, true)];
        let mut slots = [SLOT; 1];
        let mut bitmap = [0u64; 1];
        let mut allocator = make_allocator(&regions, &mut slots, &mut bitmap).unwrap();

        assert!(allocator.reserve_frame(0x3000).unwrap());
        // A second virtual alias must not make the same physical frame available.
        assert!(allocator.reserve_frame(0x3000).unwrap());
        assert!(allocator.is_frame_allocated(0x3000));
        assert_eq!(allocator.stats().allocated_frames, 1);
        assert_eq!(allocator.stats().free_frames, 4);

        let mut allocated = Vec::new();
        for _ in 0..4 {
            let frame = allocator.allocate_frame().unwrap();
            assert_ne!(frame.physical_address(), 0x3000);
            allocated.push(frame);
        }
        assert_eq!(
            allocator.allocate_frame().err(),
            Some(FrameAllocatorError::Exhausted)
        );

        let released_address = allocated[0].physical_address();
        allocator.free_frame(allocated.remove(0)).unwrap();
        assert_eq!(
            allocator.allocate_frame().unwrap().physical_address(),
            released_address
        );
        assert!(allocator.is_frame_allocated(0x3000));
    }

    #[test]
    fn permanent_reservation_fails_closed_after_any_allocation_attempt() {
        let regions = [(0x1000, 0x5000, true)];
        let mut slots = [SLOT; 1];
        let mut bitmap = [0u64; 1];
        let mut allocator = make_allocator(&regions, &mut slots, &mut bitmap).unwrap();

        let _frame = allocator.allocate_frame().unwrap();
        assert_eq!(
            allocator.reserve_frame(0x3000),
            Err(FrameAllocatorError::ReservationAfterAllocation)
        );
    }

    #[test]
    fn permanent_reservation_rejects_invalid_addresses() {
        let regions = [(0x1000, 0x5000, true)];
        let mut slots = [SLOT; 1];
        let mut bitmap = [0u64; 1];
        let mut allocator = make_allocator(&regions, &mut slots, &mut bitmap).unwrap();

        assert_eq!(
            allocator.reserve_frame(0),
            Err(FrameAllocatorError::InvalidReservationAddress)
        );
        assert_eq!(
            allocator.reserve_frame(0x2001),
            Err(FrameAllocatorError::InvalidReservationAddress)
        );
        assert!(!allocator.reserve_frame(0x9000).unwrap());
    }

    #[test]
    fn allocates_only_usable_aligned_nonzero_frames() {
        let regions = [
            (0x1003, 0x5000, true),
            (0x5000, 0x9000, false),
            (0xA003, 0xD000, true),
        ];
        let mut slots = [SLOT; 4];
        let mut bitmap = [0u64; 1];
        let mut allocator = make_allocator(&regions, &mut slots, &mut bitmap).unwrap();

        let mut addresses = Vec::new();
        for _ in 0..5 {
            addresses.push(allocator.allocate_frame().unwrap().physical_address());
        }
        addresses.sort_unstable();

        assert_eq!(addresses, [0x2000, 0x3000, 0x4000, 0xB000, 0xC000]);
        assert_eq!(allocator.stats().total_frames, 5);
        assert_eq!(allocator.stats().allocated_frames, 5);
        assert_eq!(
            allocator.allocate_frame().err(),
            Some(FrameAllocatorError::Exhausted)
        );
    }

    #[test]
    fn allocation_state_query_fails_closed_for_free_reserved_and_unaligned_frames() {
        let regions = [(0x1000, 0x5000, true), (0x5000, 0x9000, false)];
        let mut slots = [SLOT; 2];
        let mut bitmap = [0u64; 1];
        let mut allocator = make_allocator(&regions, &mut slots, &mut bitmap).unwrap();

        assert!(!allocator.is_frame_allocated(0x1000));
        assert!(!allocator.is_frame_allocated(0x5000));
        assert!(!allocator.is_frame_allocated(0x1001));
        assert!(!allocator.is_frame_allocated(0));

        let frame = allocator.allocate_frame().unwrap();
        let address = frame.physical_address();
        assert!(allocator.is_frame_allocated(address));
        allocator.free_frame(frame).unwrap();
        assert!(!allocator.is_frame_allocated(address));
    }

    #[test]
    fn excludes_physical_frame_zero() {
        let regions = [(0, PAGE_SIZE * 3, true)];
        let mut slots = [SLOT; 1];
        let mut bitmap = [0u64; 1];
        let mut allocator = make_allocator(&regions, &mut slots, &mut bitmap).unwrap();

        assert_eq!(
            allocator.allocate_frame().unwrap().physical_address(),
            PAGE_SIZE
        );
    }

    #[test]
    fn frees_and_reuses_a_frame() {
        let regions = [(0x1000, 0x5000, true)];
        let mut slots = [SLOT; 1];
        let mut bitmap = [0u64; 1];
        let mut allocator = make_allocator(&regions, &mut slots, &mut bitmap).unwrap();

        let first = allocator.allocate_frame().unwrap();
        let second = allocator.allocate_frame().unwrap();
        let first_address = first.physical_address();
        allocator.free_frame(first).unwrap();

        let reused = allocator.allocate_frame().unwrap();
        assert_eq!(reused.physical_address(), first_address);
        assert_eq!(second.physical_address(), 0x2000);
        assert_eq!(allocator.stats().allocated_frames, 2);
    }

    #[test]
    fn releasing_candidate_pair_preserving_hint_advances_search() {
        let regions = [(0x1000, 0x9000, true)];
        let mut slots = [SLOT; 1];
        let mut bitmap = [0u64; 1];
        let mut allocator = make_allocator(&regions, &mut slots, &mut bitmap).unwrap();

        let rejected_first = allocator.allocate_frame().unwrap();
        let rejected_second = allocator.allocate_frame().unwrap();
        allocator
            .free_frame_preserving_hint(rejected_first)
            .unwrap();
        allocator
            .free_frame_preserving_hint(rejected_second)
            .unwrap();

        let next_first = allocator.allocate_frame().unwrap();
        let next_second = allocator.allocate_frame().unwrap();

        assert_eq!(next_first.physical_address(), 0x3000);
        assert_eq!(next_second.physical_address(), 0x4000);
        assert_eq!(allocator.stats().allocated_frames, 2);
    }

    #[test]
    fn rejects_a_frame_from_another_allocator() {
        let regions = [(0x1000, 0x5000, true)];
        let mut slots_a = [SLOT; 1];
        let mut bitmap_a = [0u64; 1];
        let mut slots_b = [SLOT; 1];
        let mut bitmap_b = [0u64; 1];
        let mut allocator_a = make_allocator(&regions, &mut slots_a, &mut bitmap_a).unwrap();
        let mut allocator_b = make_allocator(&regions, &mut slots_b, &mut bitmap_b).unwrap();
        let frame = allocator_a.allocate_frame().unwrap();

        let (error, frame) = allocator_b.free_frame(frame).unwrap_err();
        assert_eq!(error, FrameAllocatorError::ForeignFrame);
        assert_eq!(allocator_a.free_frame(frame), Ok(()));
        assert_eq!(allocator_a.stats().allocated_frames, 0);
        assert_eq!(allocator_b.stats().allocated_frames, 0);
    }

    #[test]
    fn rejects_an_invalid_memory_map() {
        let regions = [(0x3000, 0x5000, true), (0x1000, 0x4000, true)];
        let mut slots = [SLOT; 2];
        let mut bitmap = [0u64; 2];

        assert_eq!(
            make_allocator(&regions, &mut slots, &mut bitmap).err(),
            Some(FrameAllocatorError::MemoryMap(MemoryMapError::Overlap {
                first_region: 0,
                second_region: 1,
            }))
        );
    }

    #[test]
    fn rejects_insufficient_region_metadata() {
        let regions = [(0x1000, 0x3000, true), (0x4000, 0x6000, true)];
        let mut slots = [SLOT; 1];
        let mut bitmap = [0u64; 1];

        assert_eq!(
            make_allocator(&regions, &mut slots, &mut bitmap).err(),
            Some(FrameAllocatorError::SegmentStorageTooSmall {
                required: 2,
                available: 1
            })
        );
    }

    #[test]
    fn rejects_an_insufficient_bitmap() {
        let regions = [(0x1000, 0x1000 + PAGE_SIZE * 129, true)];
        let mut slots = [SLOT; 1];
        let mut bitmap = [0u64; 1];

        assert_eq!(
            make_allocator(&regions, &mut slots, &mut bitmap).err(),
            Some(FrameAllocatorError::BitmapTooSmall {
                required_words: 3,
                available_words: 1
            })
        );
    }

    #[test]
    fn rejects_maps_without_any_complete_usable_frame() {
        let regions = [(0, 0x1000, true), (0x1000, 0x9000, false)];
        let mut slots = [SLOT; 1];
        let mut bitmap = [0u64; 1];

        assert_eq!(
            make_allocator(&regions, &mut slots, &mut bitmap).err(),
            Some(FrameAllocatorError::NoUsableFrames)
        );
    }

    #[test]
    fn handles_word_boundaries_and_reuse() {
        let regions = [(0x1000, 0x1000 + PAGE_SIZE * 130, true)];
        let mut slots = [SLOT; 1];
        let mut bitmap = [0u64; 3];
        let mut allocator = make_allocator(&regions, &mut slots, &mut bitmap).unwrap();

        let mut frames = Vec::new();
        for _ in 0..130 {
            frames.push(allocator.allocate_frame().unwrap());
        }
        assert_eq!(
            allocator.allocate_frame().err(),
            Some(FrameAllocatorError::Exhausted)
        );

        let freed_address = frames[64].physical_address();
        let freed = frames.remove(64);
        allocator.free_frame(freed).unwrap();
        assert_eq!(
            allocator.allocate_frame().unwrap().physical_address(),
            freed_address
        );
    }

    #[test]
    fn detects_release_of_a_frame_that_is_already_free() {
        let regions = [(0x1000, 0x3000, true)];
        let mut slots = [SLOT; 1];
        let mut bitmap = [0u64; 1];
        let mut allocator = make_allocator(&regions, &mut slots, &mut bitmap).unwrap();
        let frame = allocator.allocate_frame().unwrap();
        let duplicate = Frame {
            physical_address: frame.physical_address,
            bitmap_index: frame.bitmap_index,
            allocator_id: frame.allocator_id,
        };
        allocator.free_frame(frame).unwrap();

        let (error, duplicate) = allocator.free_frame(duplicate).unwrap_err();
        assert_eq!(error, FrameAllocatorError::FrameNotAllocated);
        assert_eq!(duplicate.physical_address(), 0x1000);
    }
}
