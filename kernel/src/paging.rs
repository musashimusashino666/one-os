//! Read-only inspection of the active x86_64 page tables.
//!
//! No page-table entry is written by this module. It verifies translations for
//! the inspector's code, the active stack, and BootInfo before bootstrap success
//! is reported. Five-level paging is intentionally rejected until it is tested.

use core::arch::asm;
use core::ptr;

use bootloader_api::info::{MemoryRegion, MemoryRegionKind, Optional};
use bootloader_api::BootInfo;
use oneos_core::{
    is_canonical_4level, page_table_page_is_permitted, translate_4level, PageTableError,
    PageTranslation, PAGE_SIZE,
};

const CR4_LA57: u64 = 1 << 12;
const PHYSICAL_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageTableInspection {
    pub root_table_physical: u64,
    pub verified_mappings: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PagingError {
    PhysicalMemoryMappingUnavailable,
    UnsupportedFiveLevelPaging,
    InvalidRootTable,
    Translation(PageTableError),
}

impl PagingError {
    pub const fn message(self) -> &'static [u8] {
        match self {
            Self::PhysicalMemoryMappingUnavailable => {
                b"Bootloader did not provide a physical-memory mapping\n"
            }
            Self::UnsupportedFiveLevelPaging => {
                b"Five-level paging is not supported by this inspector\n"
            }
            Self::InvalidRootTable => b"CR3 contains an invalid PML4 physical address\n",
            Self::Translation(PageTableError::NonCanonicalVirtualAddress) => {
                b"Page-table inspection received a non-canonical virtual address\n"
            }
            Self::Translation(PageTableError::InvalidRootTable) => {
                b"Page-table inspection rejected the CR3 root address\n"
            }
            Self::Translation(PageTableError::TableUnavailable { .. }) => {
                b"Page-table memory is outside the validated physical map\n"
            }
            Self::Translation(PageTableError::NotPresent { .. }) => {
                b"A required bootstrap virtual address is not mapped\n"
            }
            Self::Translation(PageTableError::LargePageAtInvalidLevel { .. }) => {
                b"Page table contains a large-page bit at an invalid level\n"
            }
            Self::Translation(PageTableError::MalformedLargePage { .. }) => {
                b"Page table contains malformed large-page alignment bits\n"
            }
            Self::Translation(PageTableError::InvalidTableAddress { .. }) => {
                b"Page table contains an invalid next-table address\n"
            }
        }
    }
}

/// Walks the current PML4 read-only and verifies core bootstrap mappings.
///
/// The bootloader's dynamic physical-memory mapping is required to read table
/// pages. Each table page must be fully contained in a region classified as
/// bootloader-owned by the supplied memory map before a volatile read. Usable,
/// unknown, reserved, and MMIO regions are rejected. Only table pages, never
/// allocated data frames, are read by this diagnostic path.
pub fn inspect_boot_mappings(boot_info: &BootInfo) -> Result<PageTableInspection, PagingError> {
    let physical_memory_offset = match &boot_info.physical_memory_offset {
        Optional::Some(offset) => *offset,
        Optional::None => return Err(PagingError::PhysicalMemoryMappingUnavailable),
    };

    let cr4: u64;
    let cr3: u64;
    // SAFETY: reading CR4 and CR3 is valid in the privileged x86_64 kernel.
    unsafe {
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    }

    // CR4.LA57 selects five-level paging, which uses a PML5 root and different
    // address-indexing semantics. Do not misinterpret it as a four-level table.
    if cr4 & CR4_LA57 != 0 {
        return Err(PagingError::UnsupportedFiveLevelPaging);
    }

    let root_table_physical = cr3 & PHYSICAL_ADDRESS_MASK;
    if root_table_physical == 0 || root_table_physical & (PAGE_SIZE - 1) != 0 {
        return Err(PagingError::InvalidRootTable);
    }

    let regions: &[MemoryRegion] = &boot_info.memory_regions;
    let mut stack_pointer: u64;
    // SAFETY: reading RSP in the current kernel context does not modify it.
    unsafe {
        asm!("mov {}, rsp", out(reg) stack_pointer, options(nomem, nostack, preserves_flags));
    }
    let addresses = [
        inspect_boot_mappings as *const () as usize as u64,
        stack_pointer,
        boot_info as *const BootInfo as usize as u64,
    ];

    for virtual_address in addresses {
        translate_virtual_address(
            virtual_address,
            root_table_physical,
            physical_memory_offset,
            regions,
        )
        .map_err(PagingError::Translation)?;
    }

    Ok(PageTableInspection {
        root_table_physical,
        verified_mappings: addresses.len(),
    })
}

fn translate_virtual_address(
    virtual_address: u64,
    root_table_physical: u64,
    physical_memory_offset: u64,
    regions: &[MemoryRegion],
) -> Result<PageTranslation, PageTableError> {
    translate_4level(
        virtual_address,
        root_table_physical,
        |table_physical, index| {
            read_page_table_entry(regions, physical_memory_offset, table_physical, index)
        },
    )
}

fn read_page_table_entry(
    regions: &[MemoryRegion],
    physical_memory_offset: u64,
    table_physical: u64,
    index: usize,
) -> Option<u64> {
    if table_physical == 0 || table_physical & (PAGE_SIZE - 1) != 0 {
        return None;
    }
    if !page_table_page_is_permitted(table_physical, regions.len(), |index| {
        let region = regions[index];
        (
            region.start,
            region.end,
            matches!(region.kind, MemoryRegionKind::Bootloader),
        )
    }) {
        return None;
    }

    let entry_offset = u64::try_from(index).ok()?.checked_mul(8)?;
    let entry_physical = table_physical.checked_add(entry_offset)?;
    let entry_virtual = physical_memory_offset.checked_add(entry_physical)?;
    if !is_canonical_4level(entry_virtual) || entry_virtual & 7 != 0 {
        return None;
    }
    let entry_pointer = usize::try_from(entry_virtual).ok()? as *const u64;

    // SAFETY: BOOTLOADER_CONFIG requests a physical-memory mapping; the entire
    // table page was confirmed to lie in a bootloader-owned memory-map region,
    // the entry address is aligned, and this is a volatile read-only inspection. This path never
    // creates a Rust reference to the bootloader-owned page-table storage.
    Some(unsafe { ptr::read_volatile(entry_pointer) })
}
