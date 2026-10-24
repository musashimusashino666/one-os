//! Ownership-safe, host-testable mapping helpers for user data pages.
//!
//! These helpers build on the generic four-level page-table mutation engine.
//! They map only writable, user-accessible, non-executable 4 KiB data pages.
//! The physical Frame token is retained by a per-address-space registry while
//! the mapping exists, and is returned only after unmap and translation
//! invalidation complete.
//!
//! The caller must serialize page-table mutation and frame ownership changes.
//! EFER.NXE must be enabled before using NX mappings. The invalidation hook must
//! invalidate positive and negative translations for the supplied root and
//! address before returning. The current kernel execution model is single-CPU;
//! this interface does not itself provide SMP synchronization or remote TLB
//! shootdowns. Intermediate page-table frames are retained by PageTableEditor
//! and are not reclaimed by these data-page helpers.

use crate::{
    map_4k, translate_4level, unmap_4k, validate_user_virtual_range, AddressSpaceRoot, Frame,
    FrameToken, PagePermissions, PageTableEditor, PageTableError, PageTableMutationError,
    UnmappedPage, UserVirtualRangeError, PAGE_SIZE,
};

/// Extension of the page-table editor with a root-aware translation invalidation hook.
///
/// Implementations must serialize this operation with address-space activation
/// and mutation, and must ensure no stale translation for the supplied
/// address-space root and virtual address can be used after the method returns.
/// The hook is called after both map and unmap, including after installing a
/// formerly non-present mapping because CPUs may cache non-present translations.
/// A local INVLPG is sufficient only when the implementation can establish that
/// it covers the target address space; future SMP support requires an explicit
/// remote-shootdown design.
pub trait UserAddressSpaceEditor: PageTableEditor {
    /// Invalidates the translation for one virtual page in the specified root.
    fn invalidate_translation(&mut self, root_table_physical: u64, virtual_address: u64);
}

/// Errors returned by user data-page mapping operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserPageMappingError {
    /// The address-space root has not completed initialization.
    AddressSpaceNotInitialized,
    /// Address zero is intentionally kept unmapped as a null guard.
    NullVirtualAddress,
    /// User data pages must be aligned to 4 KiB.
    UnalignedVirtualAddress,
    /// The complete page is not contained in the lower canonical user half.
    InvalidUserVirtualRange(UserVirtualRangeError),
    /// The fixed-capacity ownership registry has no free slot.
    RegistryFull,
    /// This virtual address is already mapped, reserved, or being prepared.
    DuplicateVirtualAddress,
    /// This physical frame is already mapped or reserved in this registry.
    DuplicatePhysicalFrame,
    /// The requested address has no mapping owned by this registry.
    NoOwnedMapping,
    /// The page-table translation disagrees with the registry's ownership record.
    MappingInvariantViolation,
    /// The generic page-table mutation engine rejected the operation.
    PageTable(PageTableMutationError),
    /// The current page-table walk could not establish a safe translation.
    Translation(PageTableError),
}

enum MappingSlot<T: FrameToken> {
    Empty,
    Reserved {
        virtual_address: u64,
        physical_address: u64,
    },
    Mapped {
        virtual_address: u64,
        token: T,
    },
}

/// Fixed-capacity registry retaining data-frame ownership for one address space.
///
/// Each live mapping has one non-Copy frame token. A slot is reserved before
/// page-table mutation begins, so registry exhaustion cannot occur after a
/// mapping has been published. This registry is address-space-local; it does
/// not replace the future global reverse-alias accounting needed for frame-wide
/// W^X across processes and kernel/direct-map aliases.
pub struct UserPageMappingRegistry<T: FrameToken, const CAPACITY: usize> {
    slots: [MappingSlot<T>; CAPACITY],
}

impl<T: FrameToken, const CAPACITY: usize> UserPageMappingRegistry<T, CAPACITY> {
    /// Creates an empty registry without allocating memory.
    pub fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| MappingSlot::Empty),
        }
    }

    /// Returns the number of unused ownership slots.
    pub fn available_slots(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| matches!(slot, MappingSlot::Empty))
            .count()
    }

    /// Returns whether the registry owns a live mapping at this virtual address.
    pub fn is_mapped(&self, virtual_address: u64) -> bool {
        self.slots.iter().any(|slot| {
            matches!(
                slot,
                MappingSlot::Mapped {
                    virtual_address: mapped,
                    ..
                } if *mapped == virtual_address
            )
        })
    }

    fn reserve_mapping(
        &mut self,
        virtual_address: u64,
        physical_address: u64,
    ) -> Result<usize, UserPageMappingError> {
        let mut free_slot = None;
        for (index, slot) in self.slots.iter().enumerate() {
            match slot {
                MappingSlot::Empty => {
                    if free_slot.is_none() {
                        free_slot = Some(index);
                    }
                }
                MappingSlot::Reserved {
                    virtual_address: reserved_virtual,
                    ..
                } if *reserved_virtual == virtual_address => {
                    return Err(UserPageMappingError::DuplicateVirtualAddress);
                }
                MappingSlot::Mapped {
                    virtual_address: mapped_virtual,
                    ..
                } if *mapped_virtual == virtual_address => {
                    return Err(UserPageMappingError::DuplicateVirtualAddress);
                }
                MappingSlot::Reserved {
                    physical_address: reserved_physical,
                    ..
                } if *reserved_physical == physical_address => {
                    return Err(UserPageMappingError::DuplicatePhysicalFrame);
                }
                MappingSlot::Mapped { token, .. } if token.frame_address() == physical_address => {
                    return Err(UserPageMappingError::DuplicatePhysicalFrame);
                }
                _ => {}
            }
        }

        let index = free_slot.ok_or(UserPageMappingError::RegistryFull)?;
        self.slots[index] = MappingSlot::Reserved {
            virtual_address,
            physical_address,
        };
        Ok(index)
    }

    fn cancel_reservation(&mut self, index: usize) {
        assert!(matches!(
            self.slots.get(index),
            Some(MappingSlot::Reserved { .. })
        ));
        self.slots[index] = MappingSlot::Empty;
    }

    fn publish_reserved(&mut self, index: usize, token: T) {
        let slot = core::mem::replace(&mut self.slots[index], MappingSlot::Empty);
        match slot {
            MappingSlot::Reserved {
                virtual_address,
                physical_address,
            } => {
                assert_eq!(
                    physical_address,
                    token.frame_address(),
                    "reserved physical frame must match the ownership token"
                );
                self.slots[index] = MappingSlot::Mapped {
                    virtual_address,
                    token,
                };
            }
            _ => panic!("mapping publication requires a reserved registry slot"),
        }
    }

    fn mapped_slot(&self, virtual_address: u64) -> Result<(usize, u64), UserPageMappingError> {
        for (index, slot) in self.slots.iter().enumerate() {
            match slot {
                MappingSlot::Mapped {
                    virtual_address: mapped,
                    token,
                } if *mapped == virtual_address => return Ok((index, token.frame_address())),
                MappingSlot::Reserved {
                    virtual_address: reserved,
                    ..
                } if *reserved == virtual_address => {
                    return Err(UserPageMappingError::DuplicateVirtualAddress);
                }
                _ => {}
            }
        }
        Err(UserPageMappingError::NoOwnedMapping)
    }

    fn take_mapped(&mut self, index: usize) -> T {
        match core::mem::replace(&mut self.slots[index], MappingSlot::Empty) {
            MappingSlot::Mapped { token, .. } => token,
            _ => panic!("unmap completion requires an owned mapping slot"),
        }
    }
}

impl<T: FrameToken, const CAPACITY: usize> Default for UserPageMappingRegistry<T, CAPACITY> {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_user_page_address(virtual_address: u64) -> Result<(), UserPageMappingError> {
    if virtual_address == 0 {
        return Err(UserPageMappingError::NullVirtualAddress);
    }
    if virtual_address & (PAGE_SIZE - 1) != 0 {
        return Err(UserPageMappingError::UnalignedVirtualAddress);
    }
    validate_user_virtual_range(virtual_address, PAGE_SIZE)
        .map_err(UserPageMappingError::InvalidUserVirtualRange)
}

/// Maps one owned frame as writable, user-accessible, non-executable data.
///
/// The frame token is moved into the registry only after map_4k succeeds. The
/// registry reserves its slot first, so metadata exhaustion fails before any
/// page-table mutation. On every error, the original frame token is returned.
/// This operation calls the editor's translation invalidation hook after
/// publishing the mapping, including to invalidate a previously cached
/// non-present translation.
///
/// Executable mappings are deliberately not supported by this helper. The
/// caller must enable EFER.NXE and use an editor whose allocation/ownership
/// checks meet PageTableEditor’s contract.
pub fn map_user_data_page<E: UserAddressSpaceEditor, const CAPACITY: usize>(
    root: &AddressSpaceRoot,
    virtual_address: u64,
    frame: Frame,
    registry: &mut UserPageMappingRegistry<Frame, CAPACITY>,
    editor: &mut E,
) -> Result<(), (UserPageMappingError, Frame)> {
    if !root.is_initialized() {
        return Err((UserPageMappingError::AddressSpaceNotInitialized, frame));
    }
    if let Err(error) = validate_user_page_address(virtual_address) {
        return Err((error, frame));
    }

    let root_physical = root.physical_address();
    let physical_address = frame.physical_address();
    let slot = match registry.reserve_mapping(virtual_address, physical_address) {
        Ok(slot) => slot,
        Err(error) => return Err((error, frame)),
    };

    if let Err(error) = map_4k(
        root_physical,
        virtual_address,
        physical_address,
        PagePermissions::new(true, true, false),
        editor,
    ) {
        registry.cancel_reservation(slot);
        return Err((UserPageMappingError::PageTable(error), frame));
    }

    registry.publish_reserved(slot, frame);
    editor.invalidate_translation(root_physical, virtual_address);
    Ok(())
}

/// Unmaps one registry-owned user data page and returns its frame after invalidation.
///
/// Before mutating the table, this checks that the complete translation is a
/// 4 KiB, user-accessible, writable, NX mapping to the physical frame retained
/// by the registry. unmap_4k then clears the leaf, and the translation
/// invalidation hook must complete before the ownership token is returned.
/// The caller may only free or reuse the returned frame after this function
/// succeeds. Intermediate page-table pages remain allocated for their owner.
pub fn unmap_user_data_page<E: UserAddressSpaceEditor, const CAPACITY: usize>(
    root: &AddressSpaceRoot,
    virtual_address: u64,
    registry: &mut UserPageMappingRegistry<Frame, CAPACITY>,
    editor: &mut E,
) -> Result<(UnmappedPage, Frame), UserPageMappingError> {
    if !root.is_initialized() {
        return Err(UserPageMappingError::AddressSpaceNotInitialized);
    }
    validate_user_page_address(virtual_address)?;

    let (slot, expected_physical) = registry.mapped_slot(virtual_address)?;
    let root_physical = root.physical_address();

    // translate_4level calls the reader in level order (4, 3, 2, 1). Keep
    // level tracking here because PageTableEditor validates access per level.
    let mut next_level = 4;
    let translation = translate_4level(virtual_address, root_physical, |table, index| {
        let current_level = next_level;
        next_level = next_level.saturating_sub(1);
        editor.read_entry(table, index, current_level)
    })
    .map_err(UserPageMappingError::Translation)?;

    if translation.page_size != PAGE_SIZE
        || translation.physical_address != expected_physical
        || !translation.user_accessible
        || !translation.writable
        || translation.executable
    {
        return Err(UserPageMappingError::MappingInvariantViolation);
    }

    let unmapped = unmap_4k(root_physical, virtual_address, editor)
        .map_err(UserPageMappingError::PageTable)?;

    // Keep the frame token in the registry through invalidation. A returned
    // token is therefore never available for reuse while a stale translation
    // may still authorize access to it.
    editor.invalidate_translation(root_physical, virtual_address);
    assert_eq!(
        unmapped.physical_address, expected_physical,
        "serialized page-table mutation must preserve the preflighted mapping"
    );
    let frame = registry.take_mapped(slot);
    Ok((unmapped, frame))
}

#[cfg(test)]
mod tests {
    use super::{
        map_user_data_page, unmap_user_data_page, UserAddressSpaceEditor, UserPageMappingError,
        UserPageMappingRegistry,
    };
    use crate::{
        AddressSpaceRoot, AddressSpaceRootEditor, Frame, FrameAllocator, FrameSegment,
        PagePermissions, PageTableEditor, PageTableMutationError,
    };

    const PRESENT: u64 = 1;
    const WRITABLE: u64 = 1 << 1;

    struct TestTable {
        physical_address: u64,
        entries: [u64; 512],
        in_use: bool,
    }

    impl TestTable {
        fn new(physical_address: u64, in_use: bool) -> Self {
            Self {
                physical_address,
                entries: [0; 512],
                in_use,
            }
        }
    }

    struct TestEditor {
        tables: [TestTable; 5],
        data_frame: u64,
        fail_allocation: bool,
        invalidations: usize,
        last_invalidation: Option<(u64, u64)>,
    }

    impl TestEditor {
        fn new(data_frame: u64) -> Self {
            let mut editor = Self {
                tables: [
                    TestTable::new(0x1000, true),
                    TestTable::new(0x2000, false),
                    TestTable::new(0x3000, false),
                    TestTable::new(0x4000, false),
                    TestTable::new(0x5000, true),
                ],
                data_frame,
                fail_allocation: false,
                invalidations: 0,
                last_invalidation: None,
            };
            editor.set_entry(0x1000, 511, 0x1000 | PRESENT | WRITABLE);
            editor
        }

        fn set_entry(&mut self, table: u64, index: usize, value: u64) {
            self.tables
                .iter_mut()
                .find(|candidate| candidate.physical_address == table)
                .expect("test table must exist")
                .entries[index] = value;
        }

        fn entry(&self, table: u64, index: usize) -> u64 {
            self.tables
                .iter()
                .find(|candidate| candidate.physical_address == table)
                .expect("test table must exist")
                .entries[index]
        }
    }

    impl AddressSpaceRootEditor for TestEditor {
        fn physical_address_bits(&self) -> u8 {
            32
        }

        fn table_is_readable(&mut self, table_physical: u64) -> bool {
            self.tables.iter().any(|table| {
                table.physical_address == table_physical && table.in_use
            })
        }

        fn table_is_read_write_accessible(&mut self, table_physical: u64) -> bool {
            self.tables.iter().any(|table| {
                table.physical_address == table_physical && table.in_use
            })
        }

        fn read_entry(&mut self, table_physical: u64, index: usize, _level: u8) -> Option<u64> {
            self.tables
                .iter()
                .find(|table| table.physical_address == table_physical && table.in_use)
                .and_then(|table| table.entries.get(index).copied())
        }

        fn write_entry(&mut self, table_physical: u64, index: usize, _level: u8, value: u64) {
            let table = self
                .tables
                .iter_mut()
                .find(|table| table.physical_address == table_physical && table.in_use)
                .expect("writes require a known, allocated table");
            table.entries[index] = value;
        }
    }

    impl PageTableEditor for TestEditor {
        fn physical_address_bits(&self) -> u8 {
            32
        }

        fn read_entry(&mut self, table_physical: u64, index: usize, _level: u8) -> Option<u64> {
            self.tables
                .iter()
                .find(|table| table.physical_address == table_physical && table.in_use)
                .and_then(|table| table.entries.get(index).copied())
        }

        fn write_entry(&mut self, table_physical: u64, index: usize, _level: u8, value: u64) {
            let table = self
                .tables
                .iter_mut()
                .find(|table| table.physical_address == table_physical && table.in_use)
                .expect("writes require a known, allocated table");
            table.entries[index] = value;
        }

        fn allocate_table(&mut self) -> Option<u64> {
            if self.fail_allocation {
                return None;
            }
            let table = self.tables.iter_mut().find(|table| {
                (0x2000..=0x4000).contains(&table.physical_address) && !table.in_use
            })?;
            table.entries.fill(0);
            table.in_use = true;
            Some(table.physical_address)
        }

        fn is_frame_allocated(&self, physical_address: u64) -> bool {
            physical_address == self.data_frame
                || self
                    .tables
                    .iter()
                    .any(|table| table.physical_address == physical_address && table.in_use)
        }

        fn is_page_table_or_reserved_frame(&self, physical_address: u64) -> bool {
            self.tables
                .iter()
                .any(|table| table.physical_address == physical_address && table.in_use)
        }

        fn executable_mapping_allowed(&self, _physical_address: u64) -> bool {
            false
        }

        fn free_table(&mut self, physical_address: u64) {
            if let Some(table) = self.tables.iter_mut().find(|table| {
                table.physical_address == physical_address
                    && (0x2000..=0x4000).contains(&table.physical_address)
            }) {
                table.entries.fill(0);
                table.in_use = false;
            }
        }
    }

    impl UserAddressSpaceEditor for TestEditor {
        fn invalidate_translation(&mut self, root_table_physical: u64, virtual_address: u64) {
            self.invalidations += 1;
            self.last_invalidation = Some((root_table_physical, virtual_address));
        }
    }

    fn setup<'a>(
        slots: &'a mut [FrameSegment],
        bitmap: &'a mut [u64],
    ) -> (FrameAllocator<'a>, AddressSpaceRoot, Frame, TestEditor) {
        let regions = [(0x5000, 0x9000, true)];
        let mut allocator =
            FrameAllocator::initialize(regions.len(), |index| regions[index], slots, bitmap)
                .unwrap();
        let root_frame = allocator.allocate_frame().unwrap();
        let data_frame = allocator.allocate_frame().unwrap();
        let data_address = data_frame.physical_address();
        let root = AddressSpaceRoot::try_from_frame(root_frame, 32).unwrap();
        let mut editor = TestEditor::new(data_address);
        let mut root = root;
        root.initialize_from_kernel_root(0x1000, 511, 510, &mut editor)
            .unwrap();
        (allocator, root, data_frame, editor)
    }

    #[test]
    fn maps_nx_user_data_and_returns_ownership_only_after_unmap_invalidation() {
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let (mut allocator, root, frame, mut editor) = setup(&mut slots, &mut bitmap);
        let physical = frame.physical_address();
        let virtual_address = 0x4000;
        let mut registry = UserPageMappingRegistry::<Frame, 2>::new();

        map_user_data_page(&root, virtual_address, frame, &mut registry, &mut editor).unwrap();

        assert!(registry.is_mapped(virtual_address));
        assert_eq!(registry.available_slots(), 1);
        assert_eq!(editor.invalidations, 1);
        assert_eq!(
            editor.last_invalidation,
            Some((root.physical_address(), virtual_address))
        );

        let (unmapped, returned_frame) =
            unmap_user_data_page(&root, virtual_address, &mut registry, &mut editor).unwrap();
        assert_eq!(unmapped.physical_address, physical);
        assert_eq!(
            unmapped.permissions,
            PagePermissions::new(true, true, false)
        );
        assert_eq!(returned_frame.physical_address(), physical);
        assert!(!registry.is_mapped(virtual_address));
        assert_eq!(registry.available_slots(), 2);
        assert_eq!(editor.invalidations, 2);

        allocator.free_frame(returned_frame).unwrap();
        allocator.free_frame(root.into_frame()).unwrap();
        assert_eq!(allocator.stats().allocated_frames, 0);
    }

    #[test]
    fn allocation_failure_keeps_the_root_and_registry_unchanged_and_returns_frame() {
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let (mut allocator, root, frame, mut editor) = setup(&mut slots, &mut bitmap);
        let physical = frame.physical_address();
        let virtual_address = 0x4000;
        let root_entry_before = editor.entry(root.physical_address(), 0);
        let mut registry = UserPageMappingRegistry::<Frame, 1>::new();
        editor.fail_allocation = true;

        let (error, returned_frame) =
            map_user_data_page(&root, virtual_address, frame, &mut registry, &mut editor)
                .unwrap_err();

        assert_eq!(
            error,
            UserPageMappingError::PageTable(PageTableMutationError::AllocationFailed)
        );
        assert_eq!(returned_frame.physical_address(), physical);
        assert_eq!(editor.entry(root.physical_address(), 0), root_entry_before);
        assert_eq!(editor.invalidations, 0);
        assert!(!registry.is_mapped(virtual_address));
        assert_eq!(registry.available_slots(), 1);

        allocator.free_frame(returned_frame).unwrap();
        allocator.free_frame(root.into_frame()).unwrap();
        assert_eq!(allocator.stats().allocated_frames, 0);
    }

    #[test]
    fn rejects_duplicate_virtual_mapping_before_page_table_mutation() {
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let (mut allocator, root, frame, mut editor) = setup(&mut slots, &mut bitmap);
        let virtual_address = 0x4000;
        let mut registry = UserPageMappingRegistry::<Frame, 2>::new();
        map_user_data_page(&root, virtual_address, frame, &mut registry, &mut editor).unwrap();

        let second_frame = allocator.allocate_frame().unwrap();
        let second_physical = second_frame.physical_address();
        let error = map_user_data_page(
            &root,
            virtual_address,
            second_frame,
            &mut registry,
            &mut editor,
        )
        .unwrap_err();

        assert_eq!(error.0, UserPageMappingError::DuplicateVirtualAddress);
        assert_eq!(error.1.physical_address(), second_physical);
        assert_eq!(editor.invalidations, 1);
        assert_eq!(registry.available_slots(), 1);

        allocator.free_frame(error.1).unwrap();
        let (_, first_frame) =
            unmap_user_data_page(&root, virtual_address, &mut registry, &mut editor).unwrap();
        allocator.free_frame(first_frame).unwrap();
        allocator.free_frame(root.into_frame()).unwrap();
        assert_eq!(allocator.stats().allocated_frames, 0);
    }
}
