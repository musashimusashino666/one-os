//! Host-testable policy helpers for auditing live bootstrap mappings.
//!
//! These helpers validate arithmetic and backing-frame policy independently of
//! the hardware page-table reader. The kernel supplies the actual translation
//! and physical-memory reservation operations.

use crate::{is_canonical_4level, PAGE_SIZE};

const LOWER_CANONICAL_LIMIT: u64 = 0x0000_8000_0000_0000;
const UPPER_CANONICAL_START: u64 = 0xffff_8000_0000_0000;

/// A malformed or unsupported virtual range supplied for bootstrap auditing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapMappingRangeError {
    /// The range is empty.
    Empty,
    /// The exclusive end cannot be represented in a 64-bit virtual address.
    AddressOverflow,
    /// The first address is not canonical for four-level paging.
    NonCanonicalStart,
    /// The final included address is not canonical for four-level paging.
    NonCanonicalEnd,
    /// The range crosses between the lower and upper canonical halves.
    CrossesCanonicalHole,
    /// The range intersects more pages than the caller permits.
    TooManyPages,
    /// The computed page count does not fit in usize.
    PageCountOverflow,
}

/// Returns the number of 4 KiB pages intersecting a virtual byte range.
///
/// start and length need not be page-aligned; every partially covered page
/// is counted. The entire range must stay within one canonical half, and the
/// caller-provided page budget is enforced before any page-table walk begins.
pub fn bootstrap_mapping_page_count(
    start: u64,
    length: u64,
    maximum_pages: u64,
) -> Result<usize, BootstrapMappingRangeError> {
    if length == 0 {
        return Err(BootstrapMappingRangeError::Empty);
    }
    let end_exclusive = start
        .checked_add(length)
        .ok_or(BootstrapMappingRangeError::AddressOverflow)?;
    if !is_canonical_4level(start) {
        return Err(BootstrapMappingRangeError::NonCanonicalStart);
    }
    let last = end_exclusive
        .checked_sub(1)
        .ok_or(BootstrapMappingRangeError::AddressOverflow)?;
    if !is_canonical_4level(last) {
        return Err(BootstrapMappingRangeError::NonCanonicalEnd);
    }

    let starts_in_lower_half = start < LOWER_CANONICAL_LIMIT;
    let ends_in_lower_half = last < LOWER_CANONICAL_LIMIT;
    let ends_in_upper_half = last >= UPPER_CANONICAL_START;
    if starts_in_lower_half && ends_in_upper_half {
        return Err(BootstrapMappingRangeError::CrossesCanonicalHole);
    }
    if starts_in_lower_half != ends_in_lower_half {
        return Err(BootstrapMappingRangeError::NonCanonicalEnd);
    }

    let first_page = start / PAGE_SIZE;
    let last_page = last / PAGE_SIZE;
    let count = last_page
        .checked_sub(first_page)
        .and_then(|pages_before_last| pages_before_last.checked_add(1))
        .ok_or(BootstrapMappingRangeError::PageCountOverflow)?;
    if count > maximum_pages {
        return Err(BootstrapMappingRangeError::TooManyPages);
    }
    usize::try_from(count).map_err(|_| BootstrapMappingRangeError::PageCountOverflow)
}

/// Memory-map ownership class for a frame backing a live bootstrap object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapBackingKind {
    /// The frame is owned by the bootloader and is excluded from the allocator.
    Bootloader,
    /// The frame is in a region admitted by the physical-frame allocator.
    Usable,
    /// The region is reserved, unknown, or otherwise not safe for this object.
    ReservedOrUnknown,
}

/// Failure while ensuring a bootstrap backing frame cannot be handed out again.
#[derive(Debug, Eq, PartialEq)]
pub enum BootstrapFrameReservationError<E> {
    /// The frame belongs to a reserved or unknown memory region.
    DisallowedRegion,
    /// The allocator does not manage a frame claimed to be Usable.
    FrameNotManaged,
    /// The allocator returned an error while reserving the frame.
    ReservationFailed(E),
}

/// Enforces the backing-frame policy for a live bootstrap object.
///
/// Bootloader frames are already excluded from allocation. Usable frames must
/// be successfully and permanently reserved. Reserved/unknown kinds are always
/// rejected. The closure is called only for Usable frames, making this policy
/// easy to test without mutating the kernel's global allocator.
pub fn reserve_bootstrap_backing_frame<E>(
    kind: BootstrapBackingKind,
    reserve_usable_frame: impl FnOnce() -> Result<bool, E>,
) -> Result<(), BootstrapFrameReservationError<E>> {
    match kind {
        BootstrapBackingKind::Bootloader => Ok(()),
        BootstrapBackingKind::Usable => match reserve_usable_frame() {
            Ok(true) => Ok(()),
            Ok(false) => Err(BootstrapFrameReservationError::FrameNotManaged),
            Err(error) => Err(BootstrapFrameReservationError::ReservationFailed(error)),
        },
        BootstrapBackingKind::ReservedOrUnknown => {
            Err(BootstrapFrameReservationError::DisallowedRegion)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        bootstrap_mapping_page_count, reserve_bootstrap_backing_frame, BootstrapBackingKind,
        BootstrapFrameReservationError as ReservationError, BootstrapMappingRangeError as RangeError,
    };
    use crate::PAGE_SIZE;

    #[test]
    fn rejects_empty_overflowing_and_noncanonical_ranges() {
        assert_eq!(bootstrap_mapping_page_count(0x1000, 0, 4096), Err(RangeError::Empty));
        assert_eq!(
            bootstrap_mapping_page_count(u64::MAX - 0x7ff, 0x1000, 4096),
            Err(RangeError::AddressOverflow)
        );
        assert_eq!(
            bootstrap_mapping_page_count(0x0000_8000_0000_0000, PAGE_SIZE, 4096),
            Err(RangeError::NonCanonicalStart)
        );
        assert_eq!(
            bootstrap_mapping_page_count(0x0000_7fff_ffff_f000, PAGE_SIZE * 2, 4096),
            Err(RangeError::NonCanonicalEnd)
        );
    }

    #[test]
    fn rejects_ranges_that_cross_the_canonical_hole() {
        let start = 0x0000_7fff_ffff_f000;
        let upper_half_start = 0xffff_8000_0000_0000;
        let length = upper_half_start - start + PAGE_SIZE;
        assert_eq!(
            bootstrap_mapping_page_count(start, length, 4096),
            Err(RangeError::CrossesCanonicalHole)
        );
    }

    #[test]
    fn rejects_ranges_larger_than_the_page_budget() {
        assert_eq!(
            bootstrap_mapping_page_count(0x20_0000, PAGE_SIZE * 4097, 4096),
            Err(RangeError::TooManyPages)
        );
        assert_eq!(
            bootstrap_mapping_page_count(0x20_0000, PAGE_SIZE * 4096, 4096),
            Ok(4096)
        );
    }

    #[test]
    fn counts_each_page_touched_by_an_unaligned_multi_page_range() {
        // A memory-region array may start near a page end and continue over
        // several pages. Count first and last partial pages too.
        let start = 0x4000_0ff0;
        let length = PAGE_SIZE * 2 + 0x20;
        assert_eq!(bootstrap_mapping_page_count(start, length, 4096), Ok(3));
    }

    #[test]
    fn bootloader_backing_does_not_require_allocator_reservation() {
        let result = reserve_bootstrap_backing_frame(
            BootstrapBackingKind::Bootloader,
            || -> Result<bool, ()> {
                panic!("Bootloader-owned frames must not be sent to the Usable allocator")
            },
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn reserved_or_unknown_backing_is_rejected_without_reservation() {
        let result =
            reserve_bootstrap_backing_frame(
                BootstrapBackingKind::ReservedOrUnknown,
                || -> Result<bool, ()> {
                    panic!("reserved frames must fail before allocator reservation")
                },
            );
        assert_eq!(result, Err(ReservationError::DisallowedRegion));
    }

    #[test]
    fn usable_backing_requires_a_successful_reservation() {
        assert_eq!(
            reserve_bootstrap_backing_frame(BootstrapBackingKind::Usable, || Ok::<bool, ()>(true)),
            Ok(())
        );
        assert_eq!(
            reserve_bootstrap_backing_frame(BootstrapBackingKind::Usable, || Ok::<bool, ()>(false)),
            Err(ReservationError::FrameNotManaged)
        );
        assert_eq!(
            reserve_bootstrap_backing_frame(BootstrapBackingKind::Usable, || {
                Err("allocator busy")
            }),
            Err(ReservationError::ReservationFailed("allocator busy"))
        );
    }
}
