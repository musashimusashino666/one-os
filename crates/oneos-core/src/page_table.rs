//! Read-only helpers for walking x86_64 four-level page tables.
//!
//! This module deliberately does not access hardware or mutate page tables. The
//! caller supplies an entry reader so address-translation logic can be tested on
//! the host and privileged memory access stays inside the kernel.

use core::convert::TryFrom;

use crate::PAGE_SIZE;

const PRESENT: u64 = 1;
const LARGE_PAGE: u64 = 1 << 7;
const PHYSICAL_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
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

/// The result of a successful four-level address translation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageTranslation {
    /// Translated physical address, including the byte offset within its page.
    pub physical_address: u64,
    /// Size of the mapped page: 4 KiB, 2 MiB, or 1 GiB.
    pub page_size: u64,
}

/// Returns whether an address is canonical for x86_64 four-level paging.
pub const fn is_canonical_4level(address: u64) -> bool {
    address <= 0x0000_7fff_ffff_ffff || address >= 0xffff_8000_0000_0000
}

/// Returns whether a full page-table page is inside a caller-approved memory region.
///
/// The caller must classify the memory map and set the third tuple element only
/// for region kinds that are safe to inspect as page-table storage. Firmware
/// regions, MMIO, and any unknown kinds must be marked as not permitted.
pub fn page_table_page_is_permitted<F>(
    table_physical: u64,
    region_count: usize,
    mut region_bounds: F,
) -> bool
where
    F: FnMut(usize) -> (u64, u64, bool),
{
    if table_physical == 0 || table_physical & (PAGE_SIZE - 1) != 0 {
        return false;
    }
    let Some(table_end) = table_physical.checked_add(PAGE_SIZE) else {
        return false;
    };

    (0..region_count).any(|index| {
        let (start, end, permitted) = region_bounds(index);
        permitted && start <= table_physical && table_end <= end
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
        return Ok(PageTranslation {
            physical_address: page_base | (virtual_address & (PAGE_SIZE_1G - 1)),
            page_size: PAGE_SIZE_1G,
        });
    }

    let pd_physical = next_table(pdpt_entry, 2)?;
    let pd_entry = present_entry(&mut read_entry, pd_physical, pd_index, 2)?;
    if pd_entry & LARGE_PAGE != 0 {
        if pd_entry & ((PAGE_SIZE_2M - 1) & !0x1fff) != 0 {
            return Err(PageTableError::MalformedLargePage { level: 2 });
        }
        let page_base = pd_entry & PHYSICAL_ADDRESS_MASK & !(PAGE_SIZE_2M - 1);
        return Ok(PageTranslation {
            physical_address: page_base | (virtual_address & (PAGE_SIZE_2M - 1)),
            page_size: PAGE_SIZE_2M,
        });
    }

    let pt_physical = next_table(pd_entry, 1)?;
    let pt_entry = present_entry(&mut read_entry, pt_physical, pt_index, 1)?;
    let page_base = pt_entry & PHYSICAL_ADDRESS_MASK;
    let offset = virtual_address & (PAGE_SIZE - 1);
    let physical_address = page_base
        .checked_add(offset)
        .ok_or(PageTableError::InvalidTableAddress { level: 1 })?;

    // Keep conversion checked so this helper remains portable to host tests.
    let _ = usize::try_from(physical_address)
        .map_err(|_| PageTableError::InvalidTableAddress { level: 1 })?;

    Ok(PageTranslation {
        physical_address,
        page_size: PAGE_SIZE,
    })
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
        is_canonical_4level, page_table_page_is_permitted, translate_4level, PageTableError,
        PageTranslation,
    };
    use crate::PAGE_SIZE;

    #[test]
    fn permits_a_page_table_page_in_an_explicitly_allowed_region() {
        let regions = [
            (0x1000, 0x5000, true),
            (0x5000, 0x9000, false),
        ];

        assert!(page_table_page_is_permitted(0x2000, regions.len(), |index| regions[index]));
    }

    #[test]
    fn rejects_usable_mmio_reserved_and_unknown_regions() {
        // The caller only marks bootloader-owned regions as permitted. Usable
        // frames, MMIO/reserved firmware ranges, and unknown firmware kinds fail closed.
        let untrusted_regions = [
            (0x1000, 0x5000, false),
            (0x5000, 0x9000, false),
            (0x9000, 0xd000, false),
        ];

        assert!(!page_table_page_is_permitted(0x2000, untrusted_regions.len(), |index| {
            untrusted_regions[index]
        }));
        assert!(!page_table_page_is_permitted(0x6000, untrusted_regions.len(), |index| {
            untrusted_regions[index]
        }));
        assert!(!page_table_page_is_permitted(0xa000, untrusted_regions.len(), |index| {
            untrusted_regions[index]
        }));
    }

    #[test]
    fn rejects_page_table_page_spanning_regions() {
        let regions = [
            (0x1000, 0x2800, true),
            (0x2800, 0x5000, true),
        ];

        assert!(!page_table_page_is_permitted(0x2000, regions.len(), |index| regions[index]));
    }

    #[test]
    fn rejects_invalid_page_table_storage_addresses() {
        let regions = [(0x1000, 0x5000, true)];

        assert!(!page_table_page_is_permitted(0, regions.len(), |index| regions[index]));
        assert!(!page_table_page_is_permitted(0x1001, regions.len(), |index| regions[index]));
        assert!(!page_table_page_is_permitted(
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
            }
        );
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
