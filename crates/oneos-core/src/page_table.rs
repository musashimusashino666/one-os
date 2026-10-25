//! Read-only helpers for walking x86_64 four-level page tables.
//!
//! This module deliberately does not access hardware or mutate page tables. The
//! caller supplies an entry reader so address-translation logic can be tested on
//! the host and privileged memory access stays inside the kernel.

use crate::PAGE_SIZE;

const PRESENT: u64 = 1;
const WRITABLE: u64 = 1 << 1;
const USER_ACCESSIBLE: u64 = 1 << 2;
const LARGE_PAGE: u64 = 1 << 7;
const NO_EXECUTE: u64 = 1 << 63;
const PHYSICAL_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const PROTECTION_KEY_FIELD_MASK: u64 = 0x7800_0000_0000_0000;
const PAGE_SIZE_2M: u64 = 1 << 21;
const PAGE_SIZE_1G: u64 = 1 << 30;

/// A failure encountered while translating a virtual address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PageTableError {
    /// The address is not canonical for 48-bit, four-level paging.
    NonCanonicalVirtualAddress,
    /// The supplied root table is zero, misaligned, or outside the supported
    /// physical-address field.
    InvalidRootTable,
    /// A page-table entry could not be safely read.
    TableUnavailable { level: u8 },
    /// The entry at this level is not present.
    NotPresent { level: u8 },
    /// A large-page bit was set at a level where it is reserved.
    LargePageAtInvalidLevel { level: u8 },
    /// Reserved alignment bits were set in a large-page entry.
    MalformedLargePage { level: u8 },
    /// A page-table entry points to physical frame zero or an invalid table.
    InvalidTableAddress { level: u8 },
}

impl PageTableError {
    /// Returns whether a failed translation may be retried with another mapping
    /// candidate. Table access can be unavailable for one recursive alias path;
    /// malformed or invalid page-table structures must remain hard errors.
    pub const fn is_retryable_for_mapping_candidate(self) -> bool {
        matches!(self, Self::TableUnavailable { .. })
    }
}

/// The result of a successful four-level address translation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageTranslation {
    /// Translated physical address, including the byte offset within its page.
    pub physical_address: u64,
    /// Size of the mapped page: 4 KiB, 2 MiB, or 1 GiB.
    pub page_size: u64,
    /// Page-table R/W permission: true only when every traversed entry allows writes.
    /// This bit aggregation alone does not account for CR0.WP or other CPU controls.
    pub writable: bool,
    /// Page-table U/S permission: true only when every traversed entry allows user access.
    /// Actual access also depends on the current privilege level and CPU controls.
    pub user_accessible: bool,
    /// NX-derived page-table permission: true when no traversed entry sets NX.
    /// CPU execution behavior also depends on IA32_EFER.NXE and other controls.
    pub executable: bool,
}

/// Returns whether an address is canonical for x86_64 four-level paging.
pub const fn is_canonical_4level(address: u64) -> bool {
    address <= 0x0000_7fff_ffff_ffff || address >= 0xffff_8000_0000_0000
}

/// Returns whether a recursive index can be used for pointer-based PML4 access.
///
/// Index zero is a valid hardware PML4 index, but its recursive PML4 alias is
/// virtual address zero. This kernel access path must reject it rather than
/// form a Rust pointer to the null address.
pub const fn is_safe_recursive_mapping_index(index: u16) -> bool {
    index != 0 && index < 512
}

/// Computes the virtual page address of a page-table page through the bootloader's
/// recursive PML4 mapping.
///
/// `table_level` is 4 for the PML4, 3 for the PDPT, 2 for a page directory,
/// and 1 for a page table. The caller must enable the bootloader recursive
/// mapping and use the index supplied in BootInfo.
pub fn recursive_table_page_virtual_address(
    recursive_index: u16,
    virtual_address: u64,
    table_level: u8,
) -> Option<u64> {
    if recursive_index >= 512 || !is_canonical_4level(virtual_address) {
        return None;
    }

    let recursive = u64::from(recursive_index);
    let pml4 = (virtual_address >> 39) & 0x1ff;
    let pdpt = (virtual_address >> 30) & 0x1ff;
    let pd = (virtual_address >> 21) & 0x1ff;
    let indices = match table_level {
        4 => [recursive, recursive, recursive, recursive],
        3 => [recursive, recursive, recursive, pml4],
        2 => [recursive, recursive, pml4, pdpt],
        1 => [recursive, pml4, pdpt, pd],
        _ => return None,
    };

    let raw = (indices[0] << 39) | (indices[1] << 30) | (indices[2] << 21) | (indices[3] << 12);
    let canonical = if raw & (1 << 47) == 0 {
        raw
    } else {
        raw | 0xffff_0000_0000_0000
    };

    if is_canonical_4level(canonical) {
        Some(canonical)
    } else {
        None
    }
}

/// Checks whether a PML4 entry is a valid self-reference to the active root table.
///
/// The caller must ensure that the entry value was read safely. This helper checks
/// the entry's present bit, reserved large-page bit, and physical frame address.
pub const fn recursive_entry_matches_root(entry: u64, root_table_physical: u64) -> bool {
    root_table_physical != 0
        && root_table_physical & (PAGE_SIZE - 1) == 0
        && root_table_physical & !PHYSICAL_ADDRESS_MASK == 0
        && entry & PRESENT != 0
        && entry & LARGE_PAGE == 0
        && entry & PHYSICAL_ADDRESS_MASK == root_table_physical
}

/// Returns whether a recursive PML4 entry is a valid kernel self-mapping.
///
/// In addition to referencing the root frame, the entry must be writable,
/// supervisor-only, non-executable, and must not carry a protection key.
pub const fn recursive_entry_is_valid_kernel_root(entry: u64, root_table_physical: u64) -> bool {
    recursive_entry_matches_root(entry, root_table_physical)
        && entry & WRITABLE != 0
        && entry & USER_ACCESSIBLE == 0
        && entry & NO_EXECUTE != 0
        && entry & PROTECTION_KEY_FIELD_MASK == 0
}

/// Returns whether a complete 4 KiB physical page is contained in one allowed region.
///
/// The region callback's third element must be true only for memory kinds that
/// are approved for page-table storage. The full half-open page range is checked;
/// merely containing its starting address is insufficient.
pub fn physical_page_is_in_allowed_region<F>(
    page_physical: u64,
    region_count: usize,
    mut region_bounds: F,
) -> bool
where
    F: FnMut(usize) -> (u64, u64, bool),
{
    if page_physical == 0 || page_physical & (PAGE_SIZE - 1) != 0 {
        return false;
    }
    let Some(page_end) = page_physical.checked_add(PAGE_SIZE) else {
        return false;
    };

    (0..region_count).any(|index| {
        let (start, end, allowed) = region_bounds(index);
        allowed && start <= page_physical && page_end <= end
    })
}

/// Walks an existing x86_64 four-level page table without changing it.
///
/// root_table_physical must be the physical base address of the PML4 table.
/// The reader receives a physical table address and an entry index (0..512).
/// It returns None when the corresponding table page cannot be safely read.
///
/// Only four-level paging is supported. The function accepts 4 KiB pages and
/// the architectural 2 MiB and 1 GiB large-page mappings. It checks canonical
/// addresses, presence bits, table addresses, and large-page reserved bits;
/// the caller remains responsible for validating that each table page is
/// backed by accessible memory before reading it.
pub fn translate_4level<F>(
    virtual_address: u64,
    root_table_physical: u64,
    mut read_entry: F,
) -> Result<PageTranslation, PageTableError>
where
    F: FnMut(u64, usize) -> Option<u64>,
{
    if !is_canonical_4level(virtual_address) {
        return Err(PageTableError::NonCanonicalVirtualAddress);
    }
    if root_table_physical == 0
        || root_table_physical & (PAGE_SIZE - 1) != 0
        || root_table_physical & !PHYSICAL_ADDRESS_MASK != 0
    {
        return Err(PageTableError::InvalidRootTable);
    }

    let pml4_index = ((virtual_address >> 39) & 0x1ff) as usize;
    let pdpt_index = ((virtual_address >> 30) & 0x1ff) as usize;
    let pd_index = ((virtual_address >> 21) & 0x1ff) as usize;
    let pt_index = ((virtual_address >> 12) & 0x1ff) as usize;

    let pml4_entry = present_entry(&mut read_entry, root_table_physical, pml4_index, 4)?;
    if pml4_entry & LARGE_PAGE != 0 {
        return Err(PageTableError::LargePageAtInvalidLevel { level: 4 });
    }

    let pdpt_physical = next_table(pml4_entry, 3)?;
    let pdpt_entry = present_entry(&mut read_entry, pdpt_physical, pdpt_index, 3)?;
    if pdpt_entry & LARGE_PAGE != 0 {
        if pdpt_entry & ((PAGE_SIZE_1G - 1) & !0x1fff) != 0 {
            return Err(PageTableError::MalformedLargePage { level: 3 });
        }
        let page_base = pdpt_entry & PHYSICAL_ADDRESS_MASK & !(PAGE_SIZE_1G - 1);
        return Ok(make_translation(
            page_base | (virtual_address & (PAGE_SIZE_1G - 1)),
            PAGE_SIZE_1G,
            &[pml4_entry, pdpt_entry],
        ));
    }

    let pd_physical = next_table(pdpt_entry, 2)?;
    let pd_entry = present_entry(&mut read_entry, pd_physical, pd_index, 2)?;
    if pd_entry & LARGE_PAGE != 0 {
        if pd_entry & ((PAGE_SIZE_2M - 1) & !0x1fff) != 0 {
            return Err(PageTableError::MalformedLargePage { level: 2 });
        }
        let page_base = pd_entry & PHYSICAL_ADDRESS_MASK & !(PAGE_SIZE_2M - 1);
        return Ok(make_translation(
            page_base | (virtual_address & (PAGE_SIZE_2M - 1)),
            PAGE_SIZE_2M,
            &[pml4_entry, pdpt_entry, pd_entry],
        ));
    }

    let pt_physical = next_table(pd_entry, 1)?;
    let pt_entry = present_entry(&mut read_entry, pt_physical, pt_index, 1)?;
    let page_base = pt_entry & PHYSICAL_ADDRESS_MASK;
    let offset = virtual_address & (PAGE_SIZE - 1);
    let physical_address = page_base
        .checked_add(offset)
        .ok_or(PageTableError::InvalidTableAddress { level: 1 })?;

    Ok(make_translation(
        physical_address,
        PAGE_SIZE,
        &[pml4_entry, pdpt_entry, pd_entry, pt_entry],
    ))
}

fn make_translation(physical_address: u64, page_size: u64, entries: &[u64]) -> PageTranslation {
    PageTranslation {
        physical_address,
        page_size,
        writable: entries.iter().all(|entry| entry & WRITABLE != 0),
        user_accessible: entries.iter().all(|entry| entry & USER_ACCESSIBLE != 0),
        executable: entries.iter().all(|entry| entry & NO_EXECUTE == 0),
    }
}

fn present_entry<F>(
    read_entry: &mut F,
    table_physical: u64,
    index: usize,
    level: u8,
) -> Result<u64, PageTableError>
where
    F: FnMut(u64, usize) -> Option<u64>,
{
    let entry =
        read_entry(table_physical, index).ok_or(PageTableError::TableUnavailable { level })?;
    if entry & PRESENT == 0 {
        return Err(PageTableError::NotPresent { level });
    }
    Ok(entry)
}

fn next_table(entry: u64, level: u8) -> Result<u64, PageTableError> {
    let table_physical = entry & PHYSICAL_ADDRESS_MASK;
    if table_physical == 0 {
        return Err(PageTableError::InvalidTableAddress { level });
    }
    Ok(table_physical)
}

#[cfg(test)]
mod tests {
    use super::{
        is_canonical_4level, is_safe_recursive_mapping_index, physical_page_is_in_allowed_region,
        recursive_entry_is_valid_kernel_root, recursive_entry_matches_root,
        recursive_table_page_virtual_address, translate_4level, PageTableError, PageTranslation,
    };
    use crate::PAGE_SIZE;

    #[test]
    fn rejects_recursive_index_zero_for_pointer_based_pml4_access() {
        assert!(!is_safe_recursive_mapping_index(0));
        assert!(is_safe_recursive_mapping_index(1));
        assert!(is_safe_recursive_mapping_index(511));
        assert!(!is_safe_recursive_mapping_index(512));
        assert_eq!(
            recursive_table_page_virtual_address(0, 0xffff_8000_0000_0000, 4),
            Some(0)
        );
    }

    #[test]
    fn recursive_mapping_addresses_select_the_expected_table_levels() {
        let virtual_address = 0xffff_8123_4567_89ab;
        let recursive = 510u16;
        let pml4 = (virtual_address >> 39) & 0x1ff;
        let pdpt = (virtual_address >> 30) & 0x1ff;
        let pd = (virtual_address >> 21) & 0x1ff;

        let pml4_page =
            recursive_table_page_virtual_address(recursive, virtual_address, 4).unwrap();
        let pdpt_page =
            recursive_table_page_virtual_address(recursive, virtual_address, 3).unwrap();
        let pd_page = recursive_table_page_virtual_address(recursive, virtual_address, 2).unwrap();
        let pt_page = recursive_table_page_virtual_address(recursive, virtual_address, 1).unwrap();

        assert_eq!(
            [
                (pml4_page >> 39) & 0x1ff,
                (pml4_page >> 30) & 0x1ff,
                (pml4_page >> 21) & 0x1ff,
                (pml4_page >> 12) & 0x1ff,
            ],
            [510, 510, 510, 510]
        );
        assert_eq!(
            [
                (pdpt_page >> 39) & 0x1ff,
                (pdpt_page >> 30) & 0x1ff,
                (pdpt_page >> 21) & 0x1ff,
                (pdpt_page >> 12) & 0x1ff,
            ],
            [510, 510, 510, pml4]
        );
        assert_eq!(
            [
                (pd_page >> 39) & 0x1ff,
                (pd_page >> 30) & 0x1ff,
                (pd_page >> 21) & 0x1ff,
                (pd_page >> 12) & 0x1ff,
            ],
            [510, 510, pml4, pdpt]
        );
        assert_eq!(
            [
                (pt_page >> 39) & 0x1ff,
                (pt_page >> 30) & 0x1ff,
                (pt_page >> 21) & 0x1ff,
                (pt_page >> 12) & 0x1ff,
            ],
            [510, pml4, pdpt, pd]
        );
        for page in [pml4_page, pdpt_page, pd_page, pt_page] {
            assert!(is_canonical_4level(page));
            assert_eq!(page & (PAGE_SIZE - 1), 0);
        }
    }

    #[test]
    fn recursive_alias_resolution_handles_multiple_canonical_virtual_paths() {
        let virtual_addresses = [
            0xffff_8123_4567_89ab,
            0xffff_ffff_ffff_f123,
            0x0000_7fff_fedc_ba98,
        ];
        let aliases: [[u64; 4]; 3] = virtual_addresses.map(|virtual_address| {
            [
                recursive_table_page_virtual_address(510, virtual_address, 4).unwrap(),
                recursive_table_page_virtual_address(510, virtual_address, 3).unwrap(),
                recursive_table_page_virtual_address(510, virtual_address, 2).unwrap(),
                recursive_table_page_virtual_address(510, virtual_address, 1).unwrap(),
            ]
        });

        for alias_set in &aliases {
            for &alias in alias_set {
                assert!(is_canonical_4level(alias));
                assert_eq!(alias & (PAGE_SIZE - 1), 0);
            }
        }

        // The PML4 page alias is shared, while lower-level table aliases follow
        // the target VA's PML4/PDPTE/PDE path and must not collide across paths.
        assert_eq!(aliases[0][0], aliases[1][0]);
        assert_ne!(aliases[0][1], aliases[1][1]);
        assert_ne!(aliases[0][2], aliases[1][2]);
        assert_ne!(aliases[0][3], aliases[1][3]);
        assert_ne!(aliases[0][3], aliases[2][3]);
    }

    #[test]
    fn rejects_invalid_recursive_mapping_inputs() {
        assert_eq!(
            recursive_table_page_virtual_address(512, 0xffff_8000_0000_0000, 4),
            None
        );
        assert_eq!(
            recursive_table_page_virtual_address(510, 0x0000_8000_0000_0000, 4),
            None
        );
        assert_eq!(
            recursive_table_page_virtual_address(510, 0xffff_8000_0000_0000, 0),
            None
        );
        assert_eq!(
            recursive_table_page_virtual_address(510, 0xffff_8000_0000_0000, 5),
            None
        );
    }

    #[test]
    fn recursive_entry_must_be_present_and_reference_the_root_frame() {
        let root = 0x1234_5000;
        let valid_entry = root | 1 | (1 << 1) | (1 << 63);
        assert!(recursive_entry_matches_root(valid_entry, root));
        assert!(!recursive_entry_matches_root(0, root));
        assert!(!recursive_entry_matches_root(0x2345_6003, root));
        assert!(!recursive_entry_matches_root(root | 1 | (1 << 7), root));
        assert!(!recursive_entry_matches_root(valid_entry, 0));
        assert!(!recursive_entry_matches_root(valid_entry, root + 1));
    }

    #[test]
    fn kernel_recursive_root_must_be_writable_supervisor_and_nx() {
        let root = 0x1234_5000;
        let valid_entry = root | 1 | (1 << 1) | (1 << 63);
        assert!(recursive_entry_is_valid_kernel_root(valid_entry, root));
        assert!(!recursive_entry_is_valid_kernel_root(
            valid_entry & !(1 << 63),
            root
        ));
        assert!(!recursive_entry_is_valid_kernel_root(
            valid_entry | (1 << 2),
            root
        ));
        assert!(!recursive_entry_is_valid_kernel_root(
            valid_entry & !(1 << 1),
            root
        ));
        assert!(!recursive_entry_is_valid_kernel_root(
            valid_entry | (1 << 59),
            root
        ));
    }

    #[test]
    fn permits_only_full_pages_inside_an_approved_region() {
        let regions = [(0x1000, 0x3800, true), (0x3800, 0x9000, false)];
        assert!(physical_page_is_in_allowed_region(
            0x2000,
            regions.len(),
            |index| { regions[index] }
        ));
        assert!(!physical_page_is_in_allowed_region(
            0x3000,
            regions.len(),
            |index| { regions[index] }
        ));
        assert!(!physical_page_is_in_allowed_region(
            0x4000,
            regions.len(),
            |index| { regions[index] }
        ));
        assert!(!physical_page_is_in_allowed_region(
            0x5000,
            regions.len(),
            |index| { regions[index] }
        ));
    }

    #[test]
    fn rejects_invalid_or_unaligned_page_ranges() {
        let regions = [(0x1000, 0x5000, true)];
        assert!(!physical_page_is_in_allowed_region(
            0,
            regions.len(),
            |index| regions[index]
        ));
        assert!(!physical_page_is_in_allowed_region(
            0x1001,
            regions.len(),
            |index| { regions[index] }
        ));
        assert!(!physical_page_is_in_allowed_region(
            0xffff_ffff_ffff_f000,
            regions.len(),
            |index| regions[index]
        ));
    }

    #[test]
    fn canonical_address_boundaries_are_checked() {
        assert!(is_canonical_4level(0));
        assert!(is_canonical_4level(0x0000_7fff_ffff_ffff));
        assert!(is_canonical_4level(0xffff_8000_0000_0000));
        assert!(is_canonical_4level(u64::MAX));
        assert!(!is_canonical_4level(0x0000_8000_0000_0000));
        assert!(!is_canonical_4level(0xffff_7fff_ffff_ffff));
    }

    #[test]
    fn translates_a_four_kib_page() {
        let virtual_address = 0x0000_1234_5678_9abc;
        let indices = [
            ((virtual_address >> 39) & 0x1ff) as usize,
            ((virtual_address >> 30) & 0x1ff) as usize,
            ((virtual_address >> 21) & 0x1ff) as usize,
            ((virtual_address >> 12) & 0x1ff) as usize,
        ];
        let result = translate_4level(virtual_address, 0x1000, |table, index| {
            match (table, index) {
                (0x1000, i) if i == indices[0] => Some(0x2003),
                (0x2000, i) if i == indices[1] => Some(0x3003),
                (0x3000, i) if i == indices[2] => Some(0x4003),
                (0x4000, i) if i == indices[3] => Some(0xabcde003),
                _ => Some(0),
            }
        })
        .unwrap();

        assert_eq!(
            result,
            PageTranslation {
                physical_address: 0xabcdeabc,
                page_size: PAGE_SIZE,
                writable: true,
                user_accessible: false,
                executable: true,
            }
        );
    }

    #[test]
    fn translates_a_four_kib_page_above_four_gib() {
        let virtual_address = 0x0000_1234_5678_9abc;
        let indices = [
            ((virtual_address >> 39) & 0x1ff) as usize,
            ((virtual_address >> 30) & 0x1ff) as usize,
            ((virtual_address >> 21) & 0x1ff) as usize,
            ((virtual_address >> 12) & 0x1ff) as usize,
        ];
        let result = translate_4level(virtual_address, 0x1000, |table, index| {
            match (table, index) {
                (0x1000, i) if i == indices[0] => Some(0x2003),
                (0x2000, i) if i == indices[1] => Some(0x3003),
                (0x3000, i) if i == indices[2] => Some(0x4003),
                (0x4000, i) if i == indices[3] => Some(0x1_abcde003),
                _ => Some(0),
            }
        })
        .unwrap();

        assert_eq!(result.physical_address, 0x1_abcdeabc);
        assert_eq!(result.page_size, PAGE_SIZE);
    }

    #[test]
    fn effective_permissions_are_intersected_across_all_levels() {
        let virtual_address = 0x0000_1234_5678_9abc;
        let indices = [
            ((virtual_address >> 39) & 0x1ff) as usize,
            ((virtual_address >> 30) & 0x1ff) as usize,
            ((virtual_address >> 21) & 0x1ff) as usize,
            ((virtual_address >> 12) & 0x1ff) as usize,
        ];
        let result = translate_4level(virtual_address, 0x1000, |table, index| {
            match (table, index) {
                (0x1000, i) if i == indices[0] => Some(0x2005),
                (0x2000, i) if i == indices[1] => Some(0x3007),
                (0x3000, i) if i == indices[2] => Some(0x4007),
                (0x4000, i) if i == indices[3] => Some(0xabcde003 | (1 << 63)),
                _ => Some(0),
            }
        })
        .unwrap();

        assert!(!result.writable);
        assert!(!result.user_accessible);
        assert!(!result.executable);
    }

    #[test]
    fn translates_a_two_mib_large_page() {
        let virtual_address = 0x0000_0000_0012_3456;
        let result = translate_4level(virtual_address, 0x1000, |table, index| {
            match (table, index) {
                (0x1000, 0) => Some(0x2003),
                (0x2000, 0) => Some(0x3003),
                (0x3000, 0) => Some(0x0080_0083),
                _ => Some(0),
            }
        })
        .unwrap();

        assert_eq!(result.page_size, 1 << 21);
        assert_eq!(result.physical_address, 0x0092_3456);
    }

    #[test]
    fn translates_a_one_gib_large_page() {
        let virtual_address = 0x0000_0000_2345_6789;
        let result = translate_4level(virtual_address, 0x1000, |table, index| {
            match (table, index) {
                (0x1000, 0) => Some(0x2003),
                (0x2000, 0) => Some(0x4000_0083),
                _ => Some(0),
            }
        })
        .unwrap();

        assert_eq!(result.page_size, 1 << 30);
        assert_eq!(result.physical_address, 0x6345_6789);
    }

    #[test]
    fn absent_entry_is_reported() {
        let error = translate_4level(0x1000, 0x1000, |_, _| Some(0)).unwrap_err();
        assert_eq!(error, PageTableError::NotPresent { level: 4 });
    }

    #[test]
    fn unavailable_table_is_reported() {
        let error = translate_4level(0x1000, 0x1000, |_, _| None).unwrap_err();
        assert_eq!(error, PageTableError::TableUnavailable { level: 4 });
    }

    #[test]
    fn only_unavailable_table_errors_allow_mapping_candidate_retry() {
        assert!(PageTableError::TableUnavailable { level: 3 }.is_retryable_for_mapping_candidate());
        assert!(!PageTableError::NotPresent { level: 4 }.is_retryable_for_mapping_candidate());
        assert!(
            !PageTableError::MalformedLargePage { level: 3 }.is_retryable_for_mapping_candidate()
        );
        assert!(!PageTableError::LargePageAtInvalidLevel { level: 2 }
            .is_retryable_for_mapping_candidate());
        assert!(
            !PageTableError::InvalidTableAddress { level: 1 }.is_retryable_for_mapping_candidate()
        );
        assert!(!PageTableError::InvalidRootTable.is_retryable_for_mapping_candidate());
        assert!(!PageTableError::NonCanonicalVirtualAddress.is_retryable_for_mapping_candidate());
    }

    #[test]
    fn rejects_noncanonical_addresses_and_invalid_roots() {
        assert_eq!(
            translate_4level(0x0000_8000_0000_0000, 0x1000, |_, _| Some(0)),
            Err(PageTableError::NonCanonicalVirtualAddress)
        );
        assert_eq!(
            translate_4level(0x1000, 0x1001, |_, _| Some(0)),
            Err(PageTableError::InvalidRootTable)
        );
        assert_eq!(
            translate_4level(0x1000, 0, |_, _| Some(0)),
            Err(PageTableError::InvalidRootTable)
        );
    }

    #[test]
    fn rejects_malformed_large_page_entries() {
        // Bit 13 is reserved in a 1 GiB mapping entry.
        let error = translate_4level(0x1000, 0x1000, |table, index| match (table, index) {
            (0x1000, 0) => Some(0x2003),
            (0x2000, 0) => Some(0x4000_2083),
            _ => Some(0),
        })
        .unwrap_err();
        assert_eq!(error, PageTableError::MalformedLargePage { level: 3 });
    }
}
