//! Host-testable 4 KiB x86_64 page-table mutation primitives.
//!
//! This engine does not access hardware directly. A PageTableEditor supplies
//! safe entry access and table-frame allocation. The implementation remains
//! responsible for safe access to table frames, TLB invalidation, serializing
//! mutations, and enabling EFER.NXE before requesting non-executable mappings.
//! Callers relying on read-only page permissions to protect supervisor-mode writes
//! must also ensure CR0.WP is enabled on every CPU executing with these tables.
//! Kernel integration must establish and maintain this precondition before
//! relying on read-only mappings. This module neither reads nor changes CR0.WP
//! or EFER.NXE.

use crate::{is_canonical_4level, PAGE_SIZE};

const PRESENT: u64 = 1;
const WRITABLE: u64 = 1 << 1;
const USER_ACCESSIBLE: u64 = 1 << 2;
const LARGE_PAGE: u64 = 1 << 7;
const NO_EXECUTE: u64 = 1 << 63;
const PROTECTION_KEY_FIELD_MASK: u64 = 0x7800_0000_0000_0000;
const PHYSICAL_ADDRESS_FIELD_MASK: u64 = 0x000f_ffff_ffff_f000;
const MAX_PHYSICAL_ADDRESS_BITS: u8 = 52;
const MIN_PHYSICAL_ADDRESS_BITS: u8 = 32;
const TABLE_ENTRY_FLAGS: u64 = PRESENT | WRITABLE | USER_ACCESSIBLE;

/// Effective leaf permissions requested for a mapping.
///
/// Writable + executable mappings are rejected (W^X). Intermediate table
/// entries created by this module allow write and user access so they do not
/// accidentally restrict a later leaf mapping; the leaf entry still enforces
/// the requested permissions, and effective x86_64 permissions are the
/// intersection of all entries traversed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PagePermissions {
    pub writable: bool,
    pub user_accessible: bool,
    pub executable: bool,
}

impl PagePermissions {
    pub const fn new(writable: bool, user_accessible: bool, executable: bool) -> Self {
        Self {
            writable,
            user_accessible,
            executable,
        }
    }
}

/// Operations required to read, modify, and allocate page-table pages.
///
/// Implementations must not return a table frame that is already in use, and
/// must ensure each allocated frame is zero-filled before returning it.
pub trait PageTableEditor {
    /// Returns the active CPU's MAXPHYADDR, typically CPUID.80000008H:EAX[7:0].
    ///
    /// The value must describe the processor whose page tables this editor
    /// accesses. The mutation engine rejects values outside 32..=52 bits and
    /// rejects physical addresses with bits set above the reported width.
    fn physical_address_bits(&self) -> u8;

    /// Reads an entry from a table at the specified paging level.
    ///
    /// Returns None when the table cannot be safely accessed.
    fn read_entry(&mut self, table_physical: u64, index: usize, level: u8) -> Option<u64>;

    /// Writes an entry in a page-table page already known to be accessible.
    fn write_entry(&mut self, table_physical: u64, index: usize, level: u8, value: u64);

    /// Allocates and zeroes a fresh physical frame for a page-table page.
    fn allocate_table(&mut self) -> Option<u64>;

    /// Releases a page-table frame allocated by allocate_table.
    fn free_table(&mut self, physical_address: u64);
}

/// A failure from a page-table map or unmap operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PageTableMutationError {
    NonCanonicalVirtualAddress,
    UnalignedVirtualAddress,
    InvalidRootTable,
    InvalidPhysicalAddressWidth { bits: u8 },
    InvalidPhysicalAddress,
    WritableExecutable,
    TableUnavailable { level: u8 },
    NotMapped { level: u8 },
    MalformedEntry { level: u8 },
    LargePageConflict { level: u8 },
    RecursiveTableReference { level: u8 },
    InvalidPageTableFrame,
    AllocationFailed,
    AlreadyMapped,
    AncestorPermissionConflict { level: u8 },
}

/// The leaf mapping removed by unmap_4k.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnmappedPage {
    pub physical_address: u64,
    pub permissions: PagePermissions,
}

/// Installs one 4 KiB mapping into an existing four-level x86_64 page table.
///
/// The virtual and physical addresses must be page-aligned. Physical frame
/// zero is intentionally rejected. All missing intermediate tables are
/// allocated before any parent entry is changed; allocation failure releases
/// every newly allocated table and leaves the page-table tree unchanged.
///
/// Existing ancestors are never widened: if an existing ancestor denies a
/// requested writable, user-accessible, or executable mapping, the operation
/// fails with AncestorPermissionConflict. Repeated physical table frames along
/// one walk are rejected to prevent recursive/cyclic references from being
/// mistaken for ordinary levels.
///
/// The caller must enable CR0.WP on every CPU that uses these tables if
/// read-only mappings are expected to block supervisor-mode writes. EFER.NXE
/// must be enabled before using non-executable mappings. This function does not
/// verify either control bit, flush TLB entries, or provide synchronization.
pub fn map_4k<E: PageTableEditor>(
    root_table_physical: u64,
    virtual_address: u64,
    physical_address: u64,
    permissions: PagePermissions,
    editor: &mut E,
) -> Result<(), PageTableMutationError> {
    let physical_address_bits = editor.physical_address_bits();
    if physical_address_mask(physical_address_bits).is_none() {
        return Err(PageTableMutationError::InvalidPhysicalAddressWidth {
            bits: physical_address_bits,
        });
    }
    validate_root(root_table_physical, physical_address_bits)?;
    validate_virtual_page(virtual_address)?;
    if !valid_physical_page(physical_address, physical_address_bits) {
        return Err(PageTableMutationError::InvalidPhysicalAddress);
    }
    if permissions.writable && permissions.executable {
        return Err(PageTableMutationError::WritableExecutable);
    }

    let indices = indices(virtual_address);
    let mut tables = [0u64; 4];
    tables[0] = root_table_physical;
    let mut missing_parent = None;

    for (path_index, &entry_index) in indices.iter().take(3).enumerate() {
        let level = 4 - path_index as u8;
        let entry = editor
            .read_entry(tables[path_index], entry_index, level)
            .ok_or(PageTableMutationError::TableUnavailable { level })?;

        if entry & PRESENT == 0 {
            if entry != 0 {
                return Err(PageTableMutationError::MalformedEntry { level });
            }
            missing_parent = Some(path_index);
            break;
        }
        if entry & PROTECTION_KEY_FIELD_MASK != 0 {
            return Err(PageTableMutationError::MalformedEntry { level });
        }
        if entry & LARGE_PAGE != 0 {
            return Err(PageTableMutationError::LargePageConflict { level });
        }
        let next_table = entry & PHYSICAL_ADDRESS_FIELD_MASK;
        if !valid_physical_page(next_table, physical_address_bits) {
            return Err(PageTableMutationError::MalformedEntry { level });
        }
        if tables[..=path_index].contains(&next_table) {
            return Err(PageTableMutationError::RecursiveTableReference { level });
        }
        if !ancestor_allows(entry, permissions) {
            return Err(PageTableMutationError::AncestorPermissionConflict { level });
        }
        tables[path_index + 1] = next_table;
    }

    if missing_parent.is_none() {
        let entry = editor
            .read_entry(tables[3], indices[3], 1)
            .ok_or(PageTableMutationError::TableUnavailable { level: 1 })?;
        if entry & PRESENT != 0 {
            return Err(PageTableMutationError::AlreadyMapped);
        }
        if entry != 0 {
            return Err(PageTableMutationError::MalformedEntry { level: 1 });
        }
    }

    let mut allocated = [0u64; 3];
    let allocation_count = missing_parent.map_or(0, |index| 3 - index);
    for allocation_index in 0..allocation_count {
        let physical = match editor.allocate_table() {
            Some(physical) => physical,
            None => {
                release_allocated(&allocated, allocation_index, editor);
                return Err(PageTableMutationError::AllocationFailed);
            }
        };

        if !valid_physical_page(physical, physical_address_bits) {
            editor.free_table(physical);
            release_allocated(&allocated, allocation_index, editor);
            return Err(PageTableMutationError::InvalidPageTableFrame);
        }

        let aliases_existing = physical == root_table_physical
            || tables[..=missing_parent.expect("allocation requires a missing parent")]
                .contains(&physical)
            || allocated[..allocation_index].contains(&physical);
        if aliases_existing {
            release_allocated(&allocated, allocation_index, editor);
            return Err(PageTableMutationError::InvalidPageTableFrame);
        }
        allocated[allocation_index] = physical;
    }

    let leaf_entry = physical_address
        | PRESENT
        | if permissions.writable { WRITABLE } else { 0 }
        | if permissions.user_accessible {
            USER_ACCESSIBLE
        } else {
            0
        }
        | if permissions.executable {
            0
        } else {
            NO_EXECUTE
        };

    if let Some(missing_index) = missing_parent {
        // Initialize the complete missing subtree while every new table frame is
        // still unpublished. The editor must be able to access these reserved
        // Usable frames through its checked physical-memory-offset path.
        //
        // Once staging starts, write_entry is infallible by contract: each
        // destination has already been reached safely during the walk or was
        // validated and zeroed by allocate_table. Publish only the highest
        // missing parent after the child links and leaf are fully initialized.
        for allocation_index in 0..allocation_count {
            let table = allocated[allocation_index];
            if allocation_index + 1 < allocation_count {
                let child_path_index = missing_index + allocation_index + 1;
                editor.write_entry(
                    table,
                    indices[child_path_index],
                    4 - child_path_index as u8,
                    allocated[allocation_index + 1] | TABLE_ENTRY_FLAGS,
                );
            } else {
                editor.write_entry(table, indices[3], 1, leaf_entry);
            }
        }

        let parent_level = 4 - missing_index as u8;
        editor.write_entry(
            tables[missing_index],
            indices[missing_index],
            parent_level,
            allocated[0] | TABLE_ENTRY_FLAGS,
        );
    } else {
        editor.write_entry(tables[3], indices[3], 1, leaf_entry);
    }
    Ok(())
}

/// Removes one 4 KiB leaf mapping.
///
/// This clears the leaf entry but deliberately leaves now-empty intermediate
/// table pages allocated. Reclaiming page-table frames requires an ownership
/// registry and is kept out of this primitive. The caller must invalidate the
/// address in the local TLB (and coordinate other CPUs in a future SMP kernel).
pub fn unmap_4k<E: PageTableEditor>(
    root_table_physical: u64,
    virtual_address: u64,
    editor: &mut E,
) -> Result<UnmappedPage, PageTableMutationError> {
    let physical_address_bits = editor.physical_address_bits();
    if physical_address_mask(physical_address_bits).is_none() {
        return Err(PageTableMutationError::InvalidPhysicalAddressWidth {
            bits: physical_address_bits,
        });
    }
    validate_root(root_table_physical, physical_address_bits)?;
    validate_virtual_page(virtual_address)?;

    let indices = indices(virtual_address);
    let mut table_physical = root_table_physical;
    let mut visited_tables = [0u64; 4];
    visited_tables[0] = root_table_physical;
    let mut effective_writable = true;
    let mut effective_user = true;
    let mut effective_executable = true;

    for (path_index, &entry_index) in indices.iter().take(3).enumerate() {
        let level = 4 - path_index as u8;
        let entry = editor
            .read_entry(table_physical, entry_index, level)
            .ok_or(PageTableMutationError::TableUnavailable { level })?;
        if entry & PRESENT == 0 {
            if entry != 0 {
                return Err(PageTableMutationError::MalformedEntry { level });
            }
            return Err(PageTableMutationError::NotMapped { level });
        }
        if entry & PROTECTION_KEY_FIELD_MASK != 0 {
            return Err(PageTableMutationError::MalformedEntry { level });
        }
        if entry & LARGE_PAGE != 0 {
            return Err(PageTableMutationError::LargePageConflict { level });
        }
        effective_writable &= entry & WRITABLE != 0;
        effective_user &= entry & USER_ACCESSIBLE != 0;
        effective_executable &= entry & NO_EXECUTE == 0;

        let next_table = entry & PHYSICAL_ADDRESS_FIELD_MASK;
        if !valid_physical_page(next_table, physical_address_bits) {
            return Err(PageTableMutationError::MalformedEntry { level });
        }
        if visited_tables[..=path_index].contains(&next_table) {
            return Err(PageTableMutationError::RecursiveTableReference { level });
        }
        visited_tables[path_index + 1] = next_table;
        table_physical = next_table;
    }

    let leaf = editor
        .read_entry(table_physical, indices[3], 1)
        .ok_or(PageTableMutationError::TableUnavailable { level: 1 })?;
    if leaf & PRESENT == 0 {
        if leaf != 0 {
            return Err(PageTableMutationError::MalformedEntry { level: 1 });
        }
        return Err(PageTableMutationError::NotMapped { level: 1 });
    }
    let leaf_physical_address = leaf & PHYSICAL_ADDRESS_FIELD_MASK;
    if !valid_physical_address(leaf_physical_address, physical_address_bits) {
        return Err(PageTableMutationError::MalformedEntry { level: 1 });
    }

    effective_writable &= leaf & WRITABLE != 0;
    effective_user &= leaf & USER_ACCESSIBLE != 0;
    effective_executable &= leaf & NO_EXECUTE == 0;

    editor.write_entry(table_physical, indices[3], 1, 0);
    Ok(UnmappedPage {
        physical_address: leaf_physical_address,
        permissions: PagePermissions::new(effective_writable, effective_user, effective_executable),
    })
}

fn release_allocated<E: PageTableEditor>(allocated: &[u64; 3], count: usize, editor: &mut E) {
    for physical in allocated[..count].iter().rev() {
        editor.free_table(*physical);
    }
}

fn validate_root(
    root_table_physical: u64,
    physical_address_bits: u8,
) -> Result<(), PageTableMutationError> {
    if valid_physical_page(root_table_physical, physical_address_bits) {
        Ok(())
    } else {
        Err(PageTableMutationError::InvalidRootTable)
    }
}

fn validate_virtual_page(virtual_address: u64) -> Result<(), PageTableMutationError> {
    if !is_canonical_4level(virtual_address) {
        return Err(PageTableMutationError::NonCanonicalVirtualAddress);
    }
    if virtual_address & (PAGE_SIZE - 1) != 0 {
        return Err(PageTableMutationError::UnalignedVirtualAddress);
    }
    Ok(())
}

fn physical_address_mask(bits: u8) -> Option<u64> {
    if !(MIN_PHYSICAL_ADDRESS_BITS..=MAX_PHYSICAL_ADDRESS_BITS).contains(&bits) {
        return None;
    }
    Some(((1u64 << bits) - 1) & PHYSICAL_ADDRESS_FIELD_MASK)
}

fn valid_physical_address(address: u64, physical_address_bits: u8) -> bool {
    let Some(mask) = physical_address_mask(physical_address_bits) else {
        return false;
    };
    address & (PAGE_SIZE - 1) == 0 && address & !mask == 0
}

fn valid_physical_page(address: u64, physical_address_bits: u8) -> bool {
    address != 0 && valid_physical_address(address, physical_address_bits)
}

fn ancestor_allows(entry: u64, permissions: PagePermissions) -> bool {
    (!permissions.writable || entry & WRITABLE != 0)
        && (!permissions.user_accessible || entry & USER_ACCESSIBLE != 0)
        && (!permissions.executable || entry & NO_EXECUTE == 0)
}

fn indices(virtual_address: u64) -> [usize; 4] {
    [
        ((virtual_address >> 39) & 0x1ff) as usize,
        ((virtual_address >> 30) & 0x1ff) as usize,
        ((virtual_address >> 21) & 0x1ff) as usize,
        ((virtual_address >> 12) & 0x1ff) as usize,
    ]
}

#[cfg(test)]
mod tests {
    use super::{
        map_4k, unmap_4k, PagePermissions, PageTableEditor, PageTableMutationError, UnmappedPage,
        LARGE_PAGE, NO_EXECUTE, PHYSICAL_ADDRESS_FIELD_MASK, PRESENT, PROTECTION_KEY_FIELD_MASK,
        USER_ACCESSIBLE, WRITABLE,
    };
    use crate::{translate_4level, PageTableError, PAGE_SIZE};
    use std::boxed::Box;
    use std::collections::BTreeMap;

    struct TestTables {
        pages: BTreeMap<u64, Box<[u64; 512]>>,
        next_physical: u64,
        allocations_remaining: Option<usize>,
        physical_address_bits: u8,
    }

    impl TestTables {
        fn new(root: u64) -> Self {
            let mut pages = BTreeMap::new();
            pages.insert(root, Box::new([0; 512]));
            Self {
                pages,
                next_physical: 0x10_000,
                allocations_remaining: None,
                physical_address_bits: 48,
            }
        }

        fn read_any(&self, table: u64, index: usize) -> Option<u64> {
            self.pages.get(&table).map(|page| page[index])
        }
    }

    impl PageTableEditor for TestTables {
        fn physical_address_bits(&self) -> u8 {
            self.physical_address_bits
        }

        fn read_entry(&mut self, table: u64, index: usize, _level: u8) -> Option<u64> {
            self.read_any(table, index)
        }

        fn write_entry(&mut self, table: u64, index: usize, _level: u8, value: u64) {
            if let Some(page) = self.pages.get_mut(&table) {
                page[index] = value;
            }
        }

        fn allocate_table(&mut self) -> Option<u64> {
            if let Some(remaining) = self.allocations_remaining.as_mut() {
                if *remaining == 0 {
                    return None;
                }
                *remaining -= 1;
            }
            let physical = self.next_physical;
            self.next_physical += PAGE_SIZE;
            self.pages.insert(physical, Box::new([0; 512]));
            Some(physical)
        }

        fn free_table(&mut self, physical: u64) {
            self.pages.remove(&physical);
        }
    }

    fn map(
        tables: &mut TestTables,
        root: u64,
        virtual_address: u64,
        physical_address: u64,
        permissions: PagePermissions,
    ) -> Result<(), PageTableMutationError> {
        map_4k(root, virtual_address, physical_address, permissions, tables)
    }

    fn unmap(
        tables: &mut TestTables,
        root: u64,
        virtual_address: u64,
    ) -> Result<UnmappedPage, PageTableMutationError> {
        unmap_4k(root, virtual_address, tables)
    }

    #[test]
    fn maps_and_translates_a_writable_non_executable_kernel_page() {
        let root = 0x1000;
        let virtual_address = 0xffff_8000_1234_5000;
        let physical_address = 0x8000;
        let mut tables = TestTables::new(root);

        map(
            &mut tables,
            root,
            virtual_address,
            physical_address,
            PagePermissions::new(true, false, false),
        )
        .unwrap();

        let result = translate_4level(virtual_address + 0x123, root, |table, index| {
            tables.read_any(table, index)
        })
        .unwrap();
        assert_eq!(result.physical_address, physical_address + 0x123);
        assert_eq!(result.page_size, PAGE_SIZE);
        assert!(result.writable);
        assert!(!result.user_accessible);
        assert!(!result.executable);
    }

    #[test]
    fn maps_an_executable_read_only_page_and_sets_leaf_permissions() {
        let root = 0x1000;
        let virtual_address = 0xffff_8000_2000_0000;
        let physical_address = 0x9000;
        let mut tables = TestTables::new(root);

        map(
            &mut tables,
            root,
            virtual_address,
            physical_address,
            PagePermissions::new(false, false, true),
        )
        .unwrap();

        let indices = [
            ((virtual_address >> 39) & 0x1ff) as usize,
            ((virtual_address >> 30) & 0x1ff) as usize,
            ((virtual_address >> 21) & 0x1ff) as usize,
            ((virtual_address >> 12) & 0x1ff) as usize,
        ];
        let root_entry = tables.read_any(root, indices[0]).unwrap();
        assert_ne!(root_entry & PRESENT, 0);
        assert_ne!(root_entry & WRITABLE, 0);
        assert_ne!(root_entry & USER_ACCESSIBLE, 0);
        assert_eq!(root_entry & NO_EXECUTE, 0);
        let translation = translate_4level(virtual_address, root, |table, index| {
            tables.read_any(table, index)
        })
        .unwrap();
        assert!(!translation.writable);
        assert!(!translation.user_accessible);
        assert!(translation.executable);
    }

    #[test]
    fn unmaps_a_page_and_reports_its_effective_permissions() {
        let root = 0x1000;
        let virtual_address = 0xffff_8000_1234_5000;
        let physical_address = 0x8000;
        let mut tables = TestTables::new(root);
        let permissions = PagePermissions::new(true, false, false);

        map(
            &mut tables,
            root,
            virtual_address,
            physical_address,
            permissions,
        )
        .unwrap();
        assert_eq!(
            unmap(&mut tables, root, virtual_address),
            Ok(UnmappedPage {
                physical_address,
                permissions,
            })
        );
        assert_eq!(
            translate_4level(virtual_address, root, |table, index| {
                tables.read_any(table, index)
            }),
            Err(PageTableError::NotPresent { level: 1 })
        );
    }

    #[test]
    fn rejects_writable_executable_mapping_without_allocating_tables() {
        let root = 0x1000;
        let mut tables = TestTables::new(root);
        assert_eq!(
            map(
                &mut tables,
                root,
                0xffff_8000_1000_0000,
                0x8000,
                PagePermissions::new(true, false, true),
            ),
            Err(PageTableMutationError::WritableExecutable)
        );
        assert_eq!(tables.pages.len(), 1);
    }

    #[test]
    fn rejects_an_existing_mapping_without_overwriting_it() {
        let root = 0x1000;
        let virtual_address = 0xffff_8000_1234_5000;
        let mut tables = TestTables::new(root);
        map(
            &mut tables,
            root,
            virtual_address,
            0x8000,
            PagePermissions::new(true, false, false),
        )
        .unwrap();
        let page_count = tables.pages.len();

        assert_eq!(
            map(
                &mut tables,
                root,
                virtual_address,
                0x9000,
                PagePermissions::new(true, false, false),
            ),
            Err(PageTableMutationError::AlreadyMapped)
        );
        assert_eq!(tables.pages.len(), page_count);
        let translation = translate_4level(virtual_address, root, |table, index| {
            tables.read_any(table, index)
        })
        .unwrap();
        assert_eq!(translation.physical_address, 0x8000);
    }

    #[test]
    fn allocation_failure_releases_new_frames_and_leaves_the_tree_unchanged() {
        let root = 0x1000;
        let virtual_address = 0xffff_8000_1234_5000;
        let mut tables = TestTables::new(root);
        tables.allocations_remaining = Some(1);

        assert_eq!(
            map(
                &mut tables,
                root,
                virtual_address,
                0x8000,
                PagePermissions::new(true, false, false),
            ),
            Err(PageTableMutationError::AllocationFailed)
        );
        assert_eq!(tables.pages.len(), 1);
        let indices = ((virtual_address >> 39) & 0x1ff) as usize;
        assert_eq!(tables.read_any(root, indices), Some(0));
    }

    #[test]
    fn refuses_to_widen_an_existing_ancestor_permission() {
        let root = 0x1000;
        let virtual_address = 0xffff_8000_1234_5000;
        let indices = ((virtual_address >> 39) & 0x1ff) as usize;
        let mut tables = TestTables::new(root);
        // Present ancestor points to a table, but write permission is absent.
        tables.pages.get_mut(&root).unwrap()[indices] = 0x2000 | PRESENT;

        assert_eq!(
            map(
                &mut tables,
                root,
                virtual_address,
                0x8000,
                PagePermissions::new(true, false, false),
            ),
            Err(PageTableMutationError::AncestorPermissionConflict { level: 4 })
        );
        assert_eq!(tables.pages.len(), 1);
    }

    #[test]
    fn rejects_large_page_conflicts() {
        let root = 0x1000;
        let virtual_address = 0x0000_1234_5678_9000;
        let root_index = ((virtual_address >> 39) & 0x1ff) as usize;
        let mut tables = TestTables::new(root);
        tables.pages.get_mut(&root).unwrap()[root_index] = 0x2000 | PRESENT | LARGE_PAGE;

        assert_eq!(
            map(
                &mut tables,
                root,
                virtual_address,
                0x8000,
                PagePermissions::new(true, false, false),
            ),
            Err(PageTableMutationError::LargePageConflict { level: 4 })
        );
        assert_eq!(
            unmap(&mut tables, root, virtual_address),
            Err(PageTableMutationError::LargePageConflict { level: 4 })
        );
    }

    #[test]
    fn rejects_invalid_addresses_and_unaligned_pages() {
        let root = 0x1000;
        let mut tables = TestTables::new(root);
        let permissions = PagePermissions::new(true, false, false);

        assert_eq!(
            map(
                &mut tables,
                root,
                0x0000_8000_0000_0000,
                0x8000,
                permissions
            ),
            Err(PageTableMutationError::NonCanonicalVirtualAddress)
        );
        assert_eq!(
            map(
                &mut tables,
                root,
                0xffff_8000_0000_0001,
                0x8000,
                permissions
            ),
            Err(PageTableMutationError::UnalignedVirtualAddress)
        );
        assert_eq!(
            map(&mut tables, root, 0xffff_8000_0000_0000, 0, permissions),
            Err(PageTableMutationError::InvalidPhysicalAddress)
        );
        assert_eq!(
            unmap(&mut tables, root, 0xffff_8000_0000_0001),
            Err(PageTableMutationError::UnalignedVirtualAddress)
        );
        assert_eq!(tables.pages.len(), 1);
    }

    #[test]
    fn rejects_mapping_when_an_existing_leaf_table_is_unavailable() {
        let root = 0x1000;
        let virtual_address = 0xffff_8000_1234_5000;
        let mut tables = TestTables::new(root);
        let root_index = ((virtual_address >> 39) & 0x1ff) as usize;
        tables.pages.get_mut(&root).unwrap()[root_index] = 0x2000 | PRESENT | WRITABLE;

        assert_eq!(
            map(
                &mut tables,
                root,
                virtual_address,
                0x8000,
                PagePermissions::new(true, false, false),
            ),
            Err(PageTableMutationError::TableUnavailable { level: 3 })
        );
    }

    #[test]
    fn accepts_software_available_and_protection_key_bits_in_existing_entries() {
        let root = 0x1000;
        let virtual_address = 0xffff_8000_1234_5000;
        let mut tables = TestTables::new(root);
        map(
            &mut tables,
            root,
            virtual_address,
            0x8000,
            PagePermissions::new(true, false, false),
        )
        .unwrap();

        // Bits 58:52 are ignored/software-available in both non-leaf and leaf
        // entries. Bits 62:59 are valid protection-key attributes on leaf entries,
        // but are reserved on non-leaf entries.
        let software_available = 0x07f0_0000_0000_0000;
        let protection_key = PROTECTION_KEY_FIELD_MASK;
        let indices = [
            ((virtual_address >> 39) & 0x1ff) as usize,
            ((virtual_address >> 30) & 0x1ff) as usize,
            ((virtual_address >> 21) & 0x1ff) as usize,
            ((virtual_address >> 12) & 0x1ff) as usize,
        ];
        let l4 = tables.read_any(root, indices[0]).unwrap() & PHYSICAL_ADDRESS_FIELD_MASK;
        let l3 = tables.read_any(l4, indices[1]).unwrap() & PHYSICAL_ADDRESS_FIELD_MASK;
        let l2 = tables.read_any(l3, indices[2]).unwrap() & PHYSICAL_ADDRESS_FIELD_MASK;
        tables.pages.get_mut(&root).unwrap()[indices[0]] |= software_available;
        tables.pages.get_mut(&l4).unwrap()[indices[1]] |= software_available;
        tables.pages.get_mut(&l3).unwrap()[indices[2]] |= software_available;
        tables.pages.get_mut(&l2).unwrap()[indices[3]] |= software_available | protection_key;

        map(
            &mut tables,
            root,
            virtual_address + PAGE_SIZE,
            0x9000,
            PagePermissions::new(true, false, false),
        )
        .unwrap();

        assert_eq!(
            unmap(&mut tables, root, virtual_address),
            Ok(UnmappedPage {
                physical_address: 0x8000,
                permissions: PagePermissions::new(true, false, false),
            })
        );
    }

    #[test]
    fn rejects_protection_key_bits_in_non_leaf_entries_for_map_and_unmap() {
        let root = 0x1000;
        let virtual_address = 0xffff_8000_1234_5000;
        let permissions = PagePermissions::new(true, false, false);
        let mut tables = TestTables::new(root);
        map(&mut tables, root, virtual_address, 0x8000, permissions).unwrap();

        let indices = [
            ((virtual_address >> 39) & 0x1ff) as usize,
            ((virtual_address >> 30) & 0x1ff) as usize,
            ((virtual_address >> 21) & 0x1ff) as usize,
            ((virtual_address >> 12) & 0x1ff) as usize,
        ];
        let l3_table = tables.read_any(root, indices[0]).unwrap() & PHYSICAL_ADDRESS_FIELD_MASK;
        let l2_table = tables.read_any(l3_table, indices[1]).unwrap() & PHYSICAL_ADDRESS_FIELD_MASK;
        let leaf_table =
            tables.read_any(l2_table, indices[2]).unwrap() & PHYSICAL_ADDRESS_FIELD_MASK;
        let parent_tables = [root, l3_table, l2_table];
        let original_leaf = tables.read_any(leaf_table, indices[3]).unwrap();
        let page_count = tables.pages.len();

        for (path_index, &parent_table) in parent_tables.iter().enumerate() {
            let level = 4 - path_index as u8;
            let index = indices[path_index];
            let original_entry = tables.read_any(parent_table, index).unwrap();
            let malformed_entry = original_entry | PROTECTION_KEY_FIELD_MASK;
            tables.write_entry(parent_table, index, level, malformed_entry);

            assert_eq!(
                map(&mut tables, root, virtual_address, 0x9000, permissions,),
                Err(PageTableMutationError::MalformedEntry { level })
            );
            assert_eq!(
                unmap(&mut tables, root, virtual_address),
                Err(PageTableMutationError::MalformedEntry { level })
            );

            // Neither operation may alter the malformed parent, the leaf mapping,
            // nor the page-table allocation count when validation fails.
            assert_eq!(tables.read_any(parent_table, index), Some(malformed_entry));
            assert_eq!(tables.read_any(leaf_table, indices[3]), Some(original_leaf));
            assert_eq!(tables.pages.len(), page_count);

            tables.write_entry(parent_table, index, level, original_entry);
        }
    }

    #[test]
    fn rejects_physical_addresses_outside_the_cpu_supported_width() {
        let root = 0x1000;
        let virtual_address = 0xffff_8000_1234_5000;
        let mut tables = TestTables::new(root);
        tables.physical_address_bits = 36;

        assert_eq!(
            map(
                &mut tables,
                root,
                virtual_address,
                1u64 << 36,
                PagePermissions::new(true, false, false),
            ),
            Err(PageTableMutationError::InvalidPhysicalAddress)
        );
    }

    #[test]
    fn rejects_existing_table_addresses_outside_the_cpu_supported_width() {
        let root = 0x1000;
        let virtual_address = 0xffff_8000_1234_5000;
        let root_index = ((virtual_address >> 39) & 0x1ff) as usize;
        let mut tables = TestTables::new(root);
        tables.physical_address_bits = 36;
        tables.pages.get_mut(&root).unwrap()[root_index] =
            (1u64 << 40) | 0x2000 | PRESENT | WRITABLE;

        assert_eq!(
            map(
                &mut tables,
                root,
                virtual_address,
                0x8000,
                PagePermissions::new(true, false, false),
            ),
            Err(PageTableMutationError::MalformedEntry { level: 4 })
        );
    }

    #[test]
    fn rejects_invalid_physical_address_widths() {
        let root = 0x1000;
        let virtual_address = 0xffff_8000_1234_5000;
        let mut tables = TestTables::new(root);
        tables.physical_address_bits = 53;

        assert_eq!(
            map(
                &mut tables,
                root,
                virtual_address,
                0x8000,
                PagePermissions::new(true, false, false),
            ),
            Err(PageTableMutationError::InvalidPhysicalAddressWidth { bits: 53 })
        );
        assert_eq!(
            unmap(&mut tables, root, virtual_address),
            Err(PageTableMutationError::InvalidPhysicalAddressWidth { bits: 53 })
        );
    }

    #[test]
    fn unmaps_a_present_leaf_mapping_to_physical_address_zero() {
        let root = 0x1000;
        let virtual_address = 0xffff_8000_1234_5000;
        let mut tables = TestTables::new(root);
        let permissions = PagePermissions::new(true, false, false);
        map(&mut tables, root, virtual_address, 0x8000, permissions).unwrap();

        let indices = [
            ((virtual_address >> 39) & 0x1ff) as usize,
            ((virtual_address >> 30) & 0x1ff) as usize,
            ((virtual_address >> 21) & 0x1ff) as usize,
            ((virtual_address >> 12) & 0x1ff) as usize,
        ];
        let l4 = tables.read_any(root, indices[0]).unwrap() & PHYSICAL_ADDRESS_FIELD_MASK;
        let l3 = tables.read_any(l4, indices[1]).unwrap() & PHYSICAL_ADDRESS_FIELD_MASK;
        let l2 = tables.read_any(l3, indices[2]).unwrap() & PHYSICAL_ADDRESS_FIELD_MASK;
        let leaf = tables.read_any(l2, indices[3]).unwrap();
        tables.pages.get_mut(&l2).unwrap()[indices[3]] = leaf & !PHYSICAL_ADDRESS_FIELD_MASK;

        let present_zero_mapping = tables.read_any(l2, indices[3]).unwrap();
        assert_ne!(present_zero_mapping & PRESENT, 0);
        assert_eq!(present_zero_mapping & PHYSICAL_ADDRESS_FIELD_MASK, 0);
        assert_eq!(
            unmap(&mut tables, root, virtual_address),
            Ok(UnmappedPage {
                physical_address: 0,
                permissions,
            })
        );
        assert_eq!(tables.read_any(l2, indices[3]), Some(0));
    }

    #[test]
    fn rejects_recursive_mapping_without_changing_page_tables() {
        let root = 0x1000;
        // All four paging indices are 511, inside a recursive mapping that
        // self-references PML4[511] back to the PML4 frame.
        let virtual_address = 0xffff_ffff_ffff_f000;
        let recursive_entry = root | PRESENT | WRITABLE | USER_ACCESSIBLE;
        let mut tables = TestTables::new(root);
        tables.pages.get_mut(&root).unwrap()[511] = recursive_entry;
        let before = tables.pages.clone();

        assert_eq!(
            map(
                &mut tables,
                root,
                virtual_address,
                0x8000,
                PagePermissions::new(true, false, false),
            ),
            Err(PageTableMutationError::RecursiveTableReference { level: 4 })
        );
        assert_eq!(tables.pages, before);

        assert_eq!(
            unmap(&mut tables, root, virtual_address),
            Err(PageTableMutationError::RecursiveTableReference { level: 4 })
        );
        assert_eq!(tables.pages, before);
    }

    #[test]
    fn rejects_unmapping_an_absent_leaf() {
        let root = 0x1000;
        let mut tables = TestTables::new(root);
        assert_eq!(
            unmap(&mut tables, root, 0xffff_8000_1234_5000),
            Err(PageTableMutationError::NotMapped { level: 4 })
        );
    }
}
