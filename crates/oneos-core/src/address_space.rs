//! Ownership and address-range primitives for future per-process address spaces.
//!
//! These host-testable types are only a foundation for I1. They do not allocate
//! or initialize page tables, install shared kernel mappings, switch CR3,
//! invalidate TLB entries, or reclaim lower-level page tables. The caller must
//! complete and validate those operations before activating an address space.

use crate::{Frame, PAGE_SIZE};

/// Exclusive upper bound of the lower canonical half used for ring-3 addresses
/// under x86_64 four-level paging.
///
/// User ranges are represented as half-open ranges: start through start + length.
pub const USER_VIRTUAL_ADDRESS_LIMIT: u64 = 0x0000_8000_0000_0000;

/// A physical-frame validation failure when constructing an owned root handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressSpaceRootError {
    /// The CPU physical-address width is outside the supported 32 through 52-bit range.
    InvalidPhysicalAddressWidth {
        /// Physical-address width reported by the caller.
        bits: u8,
    },
    /// Physical frame zero cannot be an address-space root.
    ZeroRootFrame,
    /// The root frame address is not 4 KiB aligned.
    UnalignedRootFrame,
    /// The complete root frame exceeds the supported physical-address width.
    RootFrameOutOfRange,
}

/// Validation failure for a half-open virtual range intended for ring 3.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserVirtualRangeError {
    /// Empty ranges are not valid user-memory ranges.
    EmptyRange,
    /// Computing the exclusive end of the range overflowed u64.
    RangeOverflow,
    /// The range includes an address outside the lower canonical half.
    OutsideUserHalf,
}

/// Ownership-carrying handle for a physical frame designated as a PML4 root.
///
/// The owned Frame token prevents callers from accidentally duplicating the
/// root's allocator ownership. The constructor validates address shape and
/// physical-address width, but cannot inspect or initialize the frame's
/// contents. The caller must prepare the page-table root and its required
/// kernel mappings before publishing or activating it.
///
/// This type intentionally does not implement Copy or Clone. Calling
/// into_frame consumes the handle and returns the token; the caller must ensure
/// the root and all page-table resources reachable from it are no longer active
/// or reachable and required TLB invalidation has completed before returning
/// that token to the physical allocator.
#[must_use = "dropping an address-space root handle leaks its physical frame"]
#[derive(Debug)]
pub struct AddressSpaceRoot {
    frame: Frame,
    physical_address_bits: u8,
}

impl AddressSpaceRoot {
    /// Wraps an owned frame as a root candidate for four-level paging.
    ///
    /// The root frame must already have been safely initialized by the caller.
    /// On failure, the original frame token is returned with the error so the
    /// caller can free it through the allocator that issued it.
    pub fn try_from_frame(
        frame: Frame,
        physical_address_bits: u8,
    ) -> Result<Self, (AddressSpaceRootError, Frame)> {
        let address = frame.physical_address();
        if let Err(error) = validate_root_frame_address(address, physical_address_bits) {
            return Err((error, frame));
        }

        Ok(Self {
            frame,
            physical_address_bits,
        })
    }

    /// Returns the root frame's physical base address.
    pub const fn physical_address(&self) -> u64 {
        self.frame.physical_address()
    }

    /// Returns the physical-address width used when validating this root.
    pub const fn physical_address_bits(&self) -> u8 {
        self.physical_address_bits
    }

    /// Consumes the handle and returns its allocator ownership token.
    ///
    /// The caller is responsible for proving that the address space is no
    /// longer active and that all child tables and TLB references have been
    /// handled before releasing the returned token.
    pub fn into_frame(self) -> Frame {
        self.frame
    }
}

/// Checks whether a byte range is wholly inside the x86_64 four-level user half.
///
/// This function validates arithmetic and the user/kernel canonical-half
/// boundary only. It does not check mappings, page permissions, frame
/// ownership, guard regions, or whether address zero is intentionally unmapped.
pub fn validate_user_virtual_range(start: u64, length: u64) -> Result<(), UserVirtualRangeError> {
    if length == 0 {
        return Err(UserVirtualRangeError::EmptyRange);
    }

    let end = start
        .checked_add(length)
        .ok_or(UserVirtualRangeError::RangeOverflow)?;
    if start >= USER_VIRTUAL_ADDRESS_LIMIT || end > USER_VIRTUAL_ADDRESS_LIMIT {
        return Err(UserVirtualRangeError::OutsideUserHalf);
    }

    Ok(())
}

fn validate_root_frame_address(
    address: u64,
    physical_address_bits: u8,
) -> Result<(), AddressSpaceRootError> {
    if !(32..=52).contains(&physical_address_bits) {
        return Err(AddressSpaceRootError::InvalidPhysicalAddressWidth {
            bits: physical_address_bits,
        });
    }
    if address == 0 {
        return Err(AddressSpaceRootError::ZeroRootFrame);
    }
    if address & (PAGE_SIZE - 1) != 0 {
        return Err(AddressSpaceRootError::UnalignedRootFrame);
    }

    let physical_limit = 1u64 << physical_address_bits;
    let end = address
        .checked_add(PAGE_SIZE)
        .ok_or(AddressSpaceRootError::RootFrameOutOfRange)?;
    if end > physical_limit {
        return Err(AddressSpaceRootError::RootFrameOutOfRange);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        validate_root_frame_address, validate_user_virtual_range, AddressSpaceRoot,
        AddressSpaceRootError, UserVirtualRangeError, USER_VIRTUAL_ADDRESS_LIMIT,
    };
    use crate::{FrameAllocator, FrameAllocatorError, FrameSegment, PAGE_SIZE};

    fn make_allocator<'a>(
        regions: &[(u64, u64, bool)],
        slots: &'a mut [FrameSegment],
        bitmap: &'a mut [u64],
    ) -> Result<FrameAllocator<'a>, FrameAllocatorError> {
        FrameAllocator::initialize(regions.len(), |index| regions[index], slots, bitmap)
    }

    #[test]
    fn accepts_owned_root_and_returns_its_token_exactly_once() {
        let regions = [(0x1000, 0x5000, true)];
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let mut allocator = make_allocator(&regions, &mut slots, &mut bitmap).unwrap();
        let frame = allocator.allocate_frame().unwrap();
        let address = frame.physical_address();

        let root = AddressSpaceRoot::try_from_frame(frame, 32).unwrap();
        assert_eq!(root.physical_address(), address);
        assert_eq!(root.physical_address_bits(), 32);
        assert_eq!(allocator.stats().allocated_frames, 1);

        let frame = root.into_frame();
        assert_eq!(frame.physical_address(), address);
        allocator.free_frame(frame).unwrap();
        assert_eq!(allocator.stats().allocated_frames, 0);
    }

    #[test]
    fn invalid_physical_width_returns_frame_ownership_to_caller() {
        let regions = [(0x1000, 0x3000, true)];
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let mut allocator = make_allocator(&regions, &mut slots, &mut bitmap).unwrap();
        let frame = allocator.allocate_frame().unwrap();

        let (error, frame) = AddressSpaceRoot::try_from_frame(frame, 31).unwrap_err();
        assert_eq!(
            error,
            AddressSpaceRootError::InvalidPhysicalAddressWidth { bits: 31 }
        );
        allocator.free_frame(frame).unwrap();
    }

    #[test]
    fn root_outside_reported_physical_width_is_rejected_without_losing_frame() {
        let regions = [(0x1_0000_0000, 0x1_0000_3000, true)];
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let mut allocator = make_allocator(&regions, &mut slots, &mut bitmap).unwrap();
        let frame = allocator.allocate_frame().unwrap();

        let (error, frame) = AddressSpaceRoot::try_from_frame(frame, 32).unwrap_err();
        assert_eq!(error, AddressSpaceRootError::RootFrameOutOfRange);
        allocator.free_frame(frame).unwrap();
    }

    #[test]
    fn root_frame_shape_validation_rejects_zero_unaligned_and_out_of_range() {
        assert_eq!(
            validate_root_frame_address(0, 48),
            Err(AddressSpaceRootError::ZeroRootFrame)
        );
        assert_eq!(
            validate_root_frame_address(0x1001, 48),
            Err(AddressSpaceRootError::UnalignedRootFrame)
        );
        assert_eq!(validate_root_frame_address(0xffff_f000, 32), Ok(()));
        assert_eq!(
            validate_root_frame_address(0x1_0000_0000, 32),
            Err(AddressSpaceRootError::RootFrameOutOfRange)
        );
        assert_eq!(
            validate_root_frame_address(0x1000, 53),
            Err(AddressSpaceRootError::InvalidPhysicalAddressWidth { bits: 53 })
        );
    }

    #[test]
    fn accepts_user_ranges_inside_the_lower_canonical_half() {
        assert_eq!(validate_user_virtual_range(0x1000, 1), Ok(()));
        assert_eq!(validate_user_virtual_range(0, PAGE_SIZE), Ok(()));
        assert_eq!(
            validate_user_virtual_range(USER_VIRTUAL_ADDRESS_LIMIT - 1, 1),
            Ok(())
        );
        assert_eq!(
            validate_user_virtual_range(USER_VIRTUAL_ADDRESS_LIMIT - PAGE_SIZE, PAGE_SIZE),
            Ok(())
        );
    }

    #[test]
    fn rejects_empty_and_overflowing_user_ranges() {
        assert_eq!(
            validate_user_virtual_range(0x1000, 0),
            Err(UserVirtualRangeError::EmptyRange)
        );
        assert_eq!(
            validate_user_virtual_range(0x1000, u64::MAX),
            Err(UserVirtualRangeError::RangeOverflow)
        );
    }

    #[test]
    fn rejects_upper_half_and_cross_boundary_user_ranges() {
        assert_eq!(
            validate_user_virtual_range(USER_VIRTUAL_ADDRESS_LIMIT, 1),
            Err(UserVirtualRangeError::OutsideUserHalf)
        );
        assert_eq!(
            validate_user_virtual_range(0xffff_8000_0000_0000, 1),
            Err(UserVirtualRangeError::OutsideUserHalf)
        );
        assert_eq!(
            validate_user_virtual_range(USER_VIRTUAL_ADDRESS_LIMIT - 4, 8),
            Err(UserVirtualRangeError::OutsideUserHalf)
        );
    }
}
