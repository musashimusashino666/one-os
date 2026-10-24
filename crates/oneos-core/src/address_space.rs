//! Ownership and address-space initialization primitives for x86_64.
//!
//! These host-testable types initialize an inactive PML4 root by copying only
//! supervisor-only kernel-half entries from a validated kernel root. They do
//! not map user pages, switch CR3, invalidate TLB entries, or reclaim lower-level
//! page tables. The caller must keep the source root stable and complete those
//! operations before activating an address space.

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
    initialized: bool,
}

impl AddressSpaceRoot {
    /// Wraps an exclusively owned frame as an inactive four-level PML4 root.
    ///
    /// The frame contents are not inspected or initialized by this constructor.
    /// Call initialize_from_kernel_root before the root is eligible for
    /// activation. The frame must not already be reachable from a live page table.
    /// On validation failure, the original token is returned to the caller.
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
            initialized: false,
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

    /// Returns whether the root has been initialized with supervisor-only kernel mappings.
    pub const fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Initializes this inactive root from the kernel's validated PML4.
    ///
    /// The operation preflights all source entries and table-access requirements
    /// before the first write. It then clears the lower canonical half, copies
    /// only supervisor-only upper-half entries, and replaces the recursive slot
    /// with a supervisor-writable, non-executable self-reference.
    ///
    /// The editor must provide read/write access to the complete root frame and
    /// read access to the source root. Its write_entry operation must not fail
    /// after table_is_read_write_accessible returns true. The source root must
    /// remain stable for the duration of the call; callers are responsible for
    /// synchronization and for keeping this root inactive until construction is
    /// complete. The CPU must have NX enabled before this root is activated.
    pub fn initialize_from_kernel_root<E: AddressSpaceRootEditor>(
        &mut self,
        kernel_root_physical: u64,
        recursive_index: usize,
        editor: &mut E,
    ) -> Result<(), AddressSpaceRootInitializationError> {
        if self.initialized {
            return Err(AddressSpaceRootInitializationError::AlreadyInitialized);
        }

        let editor_bits = editor.physical_address_bits();
        if editor_bits != self.physical_address_bits {
            return Err(
                AddressSpaceRootInitializationError::PhysicalAddressWidthMismatch {
                    root_bits: self.physical_address_bits,
                    editor_bits,
                },
            );
        }

        initialize_root_entries(
            self.physical_address(),
            self.physical_address_bits,
            kernel_root_physical,
            recursive_index,
            editor,
        )?;
        self.initialized = true;
        Ok(())
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

const LOWER_HALF_PML4_ENTRIES: usize = 256;
const PML4_ENTRIES: usize = 512;
const PRESENT: u64 = 1;
const WRITABLE: u64 = 1 << 1;
const USER_ACCESSIBLE: u64 = 1 << 2;
const LARGE_PAGE: u64 = 1 << 7;
const NO_EXECUTE: u64 = 1 << 63;
const PHYSICAL_ADDRESS_FIELD_MASK: u64 = 0x000f_ffff_ffff_f000;
const PROTECTION_KEY_FIELD_MASK: u64 = 0x7800_0000_0000_0000;

/// Errors encountered while preparing an inactive address-space root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressSpaceRootInitializationError {
    /// The root has already been initialized.
    AlreadyInitialized,
    /// The editor and root were validated against different CPU address widths.
    PhysicalAddressWidthMismatch {
        /// Width recorded by the root handle.
        root_bits: u8,
        /// Width reported by the table editor.
        editor_bits: u8,
    },
    /// The supplied kernel-root frame is invalid for the selected address width.
    InvalidKernelRootFrame(AddressSpaceRootError),
    /// The recursive PML4 slot must be in the supervisor-only upper half.
    InvalidRecursiveIndex {
        /// Supplied four-level PML4 index.
        index: usize,
    },
    /// The destination root aliases the source kernel root.
    RootAliasesKernelRoot,
    /// The destination root cannot be accessed safely for writing.
    RootTableUnavailable,
    /// The source kernel root cannot be accessed safely.
    KernelRootTableUnavailable,
    /// The source recursive entry could not be read.
    KernelRootRecursiveEntryUnavailable,
    /// The source recursive entry is not a supervisor-writable self-reference.
    InvalidKernelRootRecursiveEntry,
    /// A source PML4 entry could not be read.
    KernelEntryUnavailable {
        /// PML4 index that could not be read.
        index: usize,
    },
    /// A source PML4 entry is malformed or points outside physical-address limits.
    MalformedKernelEntry {
        /// PML4 index containing the malformed entry.
        index: usize,
    },
    /// A present kernel-half entry permits user mode at the PML4 level.
    UserAccessibleKernelEntry {
        /// PML4 index that has its user-accessible bit set.
        index: usize,
    },
    /// A non-recursive kernel entry aliases the kernel PML4 frame.
    KernelEntryAliasesKernelRoot {
        /// PML4 index containing the alias.
        index: usize,
    },
    /// A kernel entry aliases the newly owned destination root.
    KernelEntryAliasesOwnedRoot {
        /// PML4 index containing the alias.
        index: usize,
    },
}

/// Access interface for preparing an inactive address-space root.
///
/// Implementations must verify access to the entire physical frame. Once
/// table_is_read_write_accessible returns true for the destination, write_entry
/// must be infallible for that frame and every valid PML4 index. This contract
/// lets the initializer finish all fallible checks before its first write.
pub trait AddressSpaceRootEditor {
    /// Returns the active CPU's physical-address width (MAXPHYADDR).
    fn physical_address_bits(&self) -> u8;

    /// Returns true only when the complete table frame is safely readable.
    fn table_is_readable(&mut self, table_physical: u64) -> bool;

    /// Returns true only when the complete table frame is safely readable and writable.
    fn table_is_read_write_accessible(&mut self, table_physical: u64) -> bool;

    /// Reads one entry from a four-level paging table.
    fn read_entry(&mut self, table_physical: u64, index: usize, level: u8) -> Option<u64>;

    /// Writes one entry to a table already validated as read/write accessible.
    fn write_entry(&mut self, table_physical: u64, index: usize, level: u8, value: u64);
}

fn initialize_root_entries<E: AddressSpaceRootEditor>(
    root_physical: u64,
    physical_address_bits: u8,
    kernel_root_physical: u64,
    recursive_index: usize,
    editor: &mut E,
) -> Result<(), AddressSpaceRootInitializationError> {
    validate_root_frame_address(kernel_root_physical, physical_address_bits)
        .map_err(AddressSpaceRootInitializationError::InvalidKernelRootFrame)?;

    if root_physical == kernel_root_physical {
        return Err(AddressSpaceRootInitializationError::RootAliasesKernelRoot);
    }
    if !(LOWER_HALF_PML4_ENTRIES..PML4_ENTRIES).contains(&recursive_index) {
        return Err(AddressSpaceRootInitializationError::InvalidRecursiveIndex {
            index: recursive_index,
        });
    }
    if !editor.table_is_read_write_accessible(root_physical) {
        return Err(AddressSpaceRootInitializationError::RootTableUnavailable);
    }
    if !editor.table_is_readable(kernel_root_physical) {
        return Err(AddressSpaceRootInitializationError::KernelRootTableUnavailable);
    }

    let recursive_entry = editor
        .read_entry(kernel_root_physical, recursive_index, 4)
        .ok_or(AddressSpaceRootInitializationError::KernelRootRecursiveEntryUnavailable)?;
    if recursive_entry & PRESENT == 0
        || recursive_entry & WRITABLE == 0
        || recursive_entry & USER_ACCESSIBLE != 0
        || recursive_entry & LARGE_PAGE != 0
        || recursive_entry & PROTECTION_KEY_FIELD_MASK != 0
        || recursive_entry & PHYSICAL_ADDRESS_FIELD_MASK != kernel_root_physical
    {
        return Err(AddressSpaceRootInitializationError::InvalidKernelRootRecursiveEntry);
    }

    let physical_limit = 1u64 << physical_address_bits;
    let mut upper_entries = [0u64; PML4_ENTRIES - LOWER_HALF_PML4_ENTRIES];

    // Preflight every entry before changing the destination root. A recursive
    // slot in the new root must refer to the new PML4 frame, never the old root.
    for index in LOWER_HALF_PML4_ENTRIES..PML4_ENTRIES {
        if index == recursive_index {
            upper_entries[index - LOWER_HALF_PML4_ENTRIES] =
                root_physical | PRESENT | WRITABLE | NO_EXECUTE;
            continue;
        }

        let entry = editor
            .read_entry(kernel_root_physical, index, 4)
            .ok_or(AddressSpaceRootInitializationError::KernelEntryUnavailable { index })?;
        validate_kernel_entry(
            entry,
            index,
            physical_limit,
            root_physical,
            kernel_root_physical,
        )?;
        upper_entries[index - LOWER_HALF_PML4_ENTRIES] = entry;
    }

    // No operation below this point can fail by the editor contract. The root
    // is not yet active, so readers cannot observe a partially initialized tree.
    for index in 0..LOWER_HALF_PML4_ENTRIES {
        editor.write_entry(root_physical, index, 4, 0);
    }
    for index in LOWER_HALF_PML4_ENTRIES..PML4_ENTRIES {
        let entry = upper_entries[index - LOWER_HALF_PML4_ENTRIES];
        editor.write_entry(root_physical, index, 4, entry);
    }
    Ok(())
}

fn validate_kernel_entry(
    entry: u64,
    index: usize,
    physical_limit: u64,
    root_physical: u64,
    kernel_root_physical: u64,
) -> Result<(), AddressSpaceRootInitializationError> {
    if entry & PRESENT == 0 {
        return if entry == 0 {
            Ok(())
        } else {
            Err(AddressSpaceRootInitializationError::MalformedKernelEntry { index })
        };
    }
    if entry & USER_ACCESSIBLE != 0 {
        return Err(AddressSpaceRootInitializationError::UserAccessibleKernelEntry { index });
    }
    if entry & LARGE_PAGE != 0 || entry & PROTECTION_KEY_FIELD_MASK != 0 {
        return Err(AddressSpaceRootInitializationError::MalformedKernelEntry { index });
    }

    let table_physical = entry & PHYSICAL_ADDRESS_FIELD_MASK;
    if table_physical == 0 || table_physical >= physical_limit {
        return Err(AddressSpaceRootInitializationError::MalformedKernelEntry { index });
    }
    if table_physical == kernel_root_physical {
        return Err(AddressSpaceRootInitializationError::KernelEntryAliasesKernelRoot { index });
    }
    if table_physical == root_physical {
        return Err(AddressSpaceRootInitializationError::KernelEntryAliasesOwnedRoot { index });
    }
    Ok(())
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
        AddressSpaceRootEditor, AddressSpaceRootError, AddressSpaceRootInitializationError,
        UserVirtualRangeError, LOWER_HALF_PML4_ENTRIES, NO_EXECUTE, PRESENT,
        USER_ACCESSIBLE, USER_VIRTUAL_ADDRESS_LIMIT, WRITABLE,
    };
    use crate::{Frame, FrameAllocator, FrameAllocatorError, FrameSegment, PAGE_SIZE};

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

    #[derive(Clone, Copy)]
    struct TestTable {
        physical_address: u64,
        entries: [u64; 512],
    }

    struct TestRootEditor {
        tables: [TestTable; 2],
        blocked_table: Option<u64>,
        unreadable_entry: Option<(u64, usize)>,
    }

    impl TestRootEditor {
        fn new(root: u64, kernel_root: u64) -> Self {
            Self {
                tables: [
                    TestTable {
                        physical_address: root,
                        entries: [0xdead_beef; 512],
                    },
                    TestTable {
                        physical_address: kernel_root,
                        entries: [0; 512],
                    },
                ],
                blocked_table: None,
                unreadable_entry: None,
            }
        }

        fn set_entry(&mut self, table: u64, index: usize, value: u64) {
            let table = self
                .tables
                .iter_mut()
                .find(|candidate| candidate.physical_address == table)
                .unwrap();
            table.entries[index] = value;
        }

        fn entry(&self, table: u64, index: usize) -> u64 {
            self.tables
                .iter()
                .find(|candidate| candidate.physical_address == table)
                .unwrap()
                .entries[index]
        }
    }

    impl AddressSpaceRootEditor for TestRootEditor {
        fn physical_address_bits(&self) -> u8 {
            32
        }

        fn table_is_readable(&mut self, table_physical: u64) -> bool {
            self.blocked_table != Some(table_physical)
                && self
                    .tables
                    .iter()
                    .any(|table| table.physical_address == table_physical)
        }

        fn table_is_read_write_accessible(&mut self, table_physical: u64) -> bool {
            self.table_is_readable(table_physical)
        }

        fn read_entry(
            &mut self,
            table_physical: u64,
            index: usize,
            _level: u8,
        ) -> Option<u64> {
            if self.unreadable_entry == Some((table_physical, index)) {
                return None;
            }
            self.tables
                .iter()
                .find(|table| table.physical_address == table_physical)
                .and_then(|table| table.entries.get(index).copied())
        }

        fn write_entry(
            &mut self,
            table_physical: u64,
            index: usize,
            _level: u8,
            value: u64,
        ) {
            let table = self
                .tables
                .iter_mut()
                .find(|table| table.physical_address == table_physical)
                .expect("writes are only allowed to a preflighted table");
            table.entries[index] = value;
        }
    }

    fn initialize_test_roots(
        allocator: &mut FrameAllocator<'_>,
    ) -> (AddressSpaceRoot, u64, Frame) {
        let root_frame = allocator.allocate_frame().unwrap();
        let kernel_frame = allocator.allocate_frame().unwrap();
        let kernel_address = kernel_frame.physical_address();
        let root = AddressSpaceRoot::try_from_frame(root_frame, 32).unwrap();
        (root, kernel_address, kernel_frame)
    }

    #[test]
    fn initializes_inactive_root_with_supervisor_kernel_half_and_private_recursive_slot() {
        let regions = [(0x1000, 0x9000, true)];
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let mut allocator = make_allocator(&regions, &mut slots, &mut bitmap).unwrap();
        let (mut root, kernel_address, kernel_frame) = initialize_test_roots(&mut allocator);
        let root_address = root.physical_address();
        let mut editor = TestRootEditor::new(root_address, kernel_address);
        editor.set_entry(kernel_address, 511, kernel_address | PRESENT | WRITABLE);
        editor.set_entry(kernel_address, 256, 0x3000 | PRESENT | WRITABLE);
        editor.set_entry(
            kernel_address,
            300,
            0x4000 | PRESENT | WRITABLE | NO_EXECUTE,
        );

        root.initialize_from_kernel_root(kernel_address, 511, &mut editor)
            .unwrap();

        assert!(root.is_initialized());
        for index in 0..LOWER_HALF_PML4_ENTRIES {
            assert_eq!(editor.entry(root_address, index), 0);
        }
        assert_eq!(editor.entry(root_address, 256), 0x3000 | PRESENT | WRITABLE);
        assert_eq!(
            editor.entry(root_address, 300),
            0x4000 | PRESENT | WRITABLE | NO_EXECUTE
        );
        assert_eq!(
            editor.entry(root_address, 511),
            root_address | PRESENT | WRITABLE | NO_EXECUTE
        );

        allocator.free_frame(root.into_frame()).unwrap();
        allocator.free_frame(kernel_frame).unwrap();
    }

    #[test]
    fn rejects_user_accessible_kernel_entry_without_mutating_destination_root() {
        let regions = [(0x1000, 0x9000, true)];
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let mut allocator = make_allocator(&regions, &mut slots, &mut bitmap).unwrap();
        let (mut root, kernel_address, kernel_frame) = initialize_test_roots(&mut allocator);
        let root_address = root.physical_address();
        let mut editor = TestRootEditor::new(root_address, kernel_address);
        editor.set_entry(kernel_address, 511, kernel_address | PRESENT | WRITABLE);
        editor.set_entry(kernel_address, 300, 0x4000 | PRESENT | USER_ACCESSIBLE);

        assert_eq!(
            root.initialize_from_kernel_root(kernel_address, 511, &mut editor),
            Err(AddressSpaceRootInitializationError::UserAccessibleKernelEntry { index: 300 })
        );
        assert!(!root.is_initialized());
        assert_eq!(editor.entry(root_address, 0), 0xdead_beef);
        assert_eq!(editor.entry(root_address, 511), 0xdead_beef);

        allocator.free_frame(root.into_frame()).unwrap();
        allocator.free_frame(kernel_frame).unwrap();
    }

    #[test]
    fn rejects_recursive_slot_in_user_half_before_writing_root() {
        let regions = [(0x1000, 0x9000, true)];
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let mut allocator = make_allocator(&regions, &mut slots, &mut bitmap).unwrap();
        let (mut root, kernel_address, kernel_frame) = initialize_test_roots(&mut allocator);
        let root_address = root.physical_address();
        let mut editor = TestRootEditor::new(root_address, kernel_address);

        assert_eq!(
            root.initialize_from_kernel_root(kernel_address, 255, &mut editor),
            Err(AddressSpaceRootInitializationError::InvalidRecursiveIndex { index: 255 })
        );
        assert_eq!(editor.entry(root_address, 0), 0xdead_beef);
        assert!(!root.is_initialized());

        allocator.free_frame(root.into_frame()).unwrap();
        allocator.free_frame(kernel_frame).unwrap();
    }

    #[test]
    fn does_not_allow_root_initialization_twice() {
        let regions = [(0x1000, 0x9000, true)];
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let mut allocator = make_allocator(&regions, &mut slots, &mut bitmap).unwrap();
        let (mut root, kernel_address, kernel_frame) = initialize_test_roots(&mut allocator);
        let root_address = root.physical_address();
        let mut editor = TestRootEditor::new(root_address, kernel_address);
        editor.set_entry(kernel_address, 511, kernel_address | PRESENT | WRITABLE);

        root.initialize_from_kernel_root(kernel_address, 511, &mut editor)
            .unwrap();
        let before = editor.entry(root_address, 511);
        assert_eq!(
            root.initialize_from_kernel_root(kernel_address, 511, &mut editor),
            Err(AddressSpaceRootInitializationError::AlreadyInitialized)
        );
        assert_eq!(editor.entry(root_address, 511), before);

        allocator.free_frame(root.into_frame()).unwrap();
        allocator.free_frame(kernel_frame).unwrap();
    }
}
