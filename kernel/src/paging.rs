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
    is_canonical_4level, recursive_table_page_virtual_address, translate_4level,
    PageTableError, PageTranslation, PAGE_SIZE,
};

const CR4_LA57: u64 = 1 << 12;
const PHYSICAL_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageTableInspection {
    pub root_table_physical: u64,
    pub validated_mappings: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PagingError {
    RecursiveMappingUnavailable,
    InvalidRecursiveIndex,
    UnsupportedFiveLevelPaging,
    InvalidRootTable,
    InvalidKernelImageRange,
    InvalidKernelCodeMapping,
    InvalidStackMapping,
    InvalidBootInfoMapping,
    Translation(PageTableError),
}

impl PagingError {
    pub const fn message(self) -> &'static [u8] {
        match self {
            Self::RecursiveMappingUnavailable => {
                b"Bootloader did not provide a recursive page-table mapping\n"
            }
            Self::InvalidRecursiveIndex => {
                b"Bootloader provided an invalid recursive table index\n"
            }
            Self::InvalidKernelImageRange => b"BootInfo kernel image range is invalid\n",
            Self::InvalidKernelCodeMapping => {
                b"Kernel code mapping does not match expected physical address/permissions\n"
            }
            Self::InvalidStackMapping => {
                b"Kernel stack mapping does not match expected range/permissions\n"
            }
            Self::InvalidBootInfoMapping => {
                b"BootInfo mapping does not match expected ownership/permissions\n"
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
                b"Page-table entry is unavailable through recursive mapping\n"
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
/// The bootloader's recursive page-table mapping is required to inspect active
/// table pages. This avoids aliasing Bootloader-owned frames through the physical
/// memory offset, which bootloader_api documents as safely accessible only for
/// Usable frames. This module never writes a page-table entry.
pub fn inspect_boot_mappings(boot_info: &BootInfo) -> Result<PageTableInspection, PagingError> {
    let recursive_index = match boot_info.recursive_index {
        Optional::Some(index) => index,
        Optional::None => return Err(PagingError::RecursiveMappingUnavailable),
    };
    if recursive_index >= 512 {
        return Err(PagingError::InvalidRecursiveIndex);
    }

    let cr4: u64;
    let cr3: u64;
    // SAFETY: reading CR4 and CR3 is valid in the privileged x86_64 kernel.
    unsafe {
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    }
    if cr4 & CR4_LA57 != 0 {
        return Err(PagingError::UnsupportedFiveLevelPaging);
    }

    let root_table_physical = cr3 & PHYSICAL_ADDRESS_MASK;
    if root_table_physical == 0 || root_table_physical & (PAGE_SIZE - 1) != 0 {
        return Err(PagingError::InvalidRootTable);
    }

    let regions: &[MemoryRegion] = &boot_info.memory_regions;
    let code_address = inspect_boot_mappings as *const () as usize as u64;
    let boot_info_address = boot_info as *const BootInfo as usize as u64;
    let mut stack_pointer: u64;
    // SAFETY: reading RSP in the current kernel context does not modify it.
    unsafe {
        asm!("mov {}, rsp", out(reg) stack_pointer, options(nomem, nostack, preserves_flags));
    }

    // BootInfo supplies physical and virtual kernel-image bases. Verify the
    // code mapping against this independent bootloader-provided relationship.
    let kernel_virtual_end = boot_info
        .kernel_image_offset
        .checked_add(boot_info.kernel_len)
        .filter(|_| boot_info.kernel_len != 0)
        .ok_or(PagingError::InvalidKernelImageRange)?;
    let kernel_physical_end = boot_info
        .kernel_addr
        .checked_add(boot_info.kernel_len)
        .ok_or(PagingError::InvalidKernelImageRange)?;
    if code_address < boot_info.kernel_image_offset || code_address >= kernel_virtual_end {
        return Err(PagingError::InvalidKernelImageRange);
    }
    let expected_code_physical = boot_info
        .kernel_addr
        .checked_add(code_address - boot_info.kernel_image_offset)
        .filter(|physical| *physical < kernel_physical_end)
        .ok_or(PagingError::InvalidKernelImageRange)?;

    let stack_end = boot_info
        .kernel_stack_bottom
        .checked_add(boot_info.kernel_stack_len)
        .filter(|_| boot_info.kernel_stack_len != 0)
        .ok_or(PagingError::InvalidStackMapping)?;
    if stack_pointer < boot_info.kernel_stack_bottom || stack_pointer >= stack_end {
        return Err(PagingError::InvalidStackMapping);
    }

    let code_translation =
        translate_virtual_address(code_address, root_table_physical, recursive_index)
            .map_err(PagingError::Translation)?;
    if code_translation.physical_address != expected_code_physical
        || !translation_preserves_page_offset(code_address, code_translation)
        || code_translation.writable
        || code_translation.user_accessible
        || !code_translation.executable
        || !is_bootloader_owned_physical_address(regions, code_translation.physical_address)
    {
        return Err(PagingError::InvalidKernelCodeMapping);
    }

    let stack_translation =
        translate_virtual_address(stack_pointer, root_table_physical, recursive_index)
            .map_err(PagingError::Translation)?;
    if !translation_preserves_page_offset(stack_pointer, stack_translation)
        || !stack_translation.writable
        || stack_translation.user_accessible
        || stack_translation.executable
        || !is_bootloader_owned_physical_address(regions, stack_translation.physical_address)
    {
        return Err(PagingError::InvalidStackMapping);
    }

    let boot_info_translation =
        translate_virtual_address(boot_info_address, root_table_physical, recursive_index)
            .map_err(PagingError::Translation)?;
    if !translation_preserves_page_offset(boot_info_address, boot_info_translation)
        || !boot_info_translation.writable
        || boot_info_translation.user_accessible
        || boot_info_translation.executable
        || !is_bootloader_owned_physical_address(regions, boot_info_translation.physical_address)
    {
        return Err(PagingError::InvalidBootInfoMapping);
    }

    Ok(PageTableInspection {
        root_table_physical,
        validated_mappings: 3,
    })
}

fn translation_preserves_page_offset(virtual_address: u64, translation: PageTranslation) -> bool {
    (translation.page_size == PAGE_SIZE
        || translation.page_size == (1 << 21)
        || translation.page_size == (1 << 30))
        && translation.physical_address & (translation.page_size - 1)
            == virtual_address & (translation.page_size - 1)
}

fn is_bootloader_owned_physical_address(regions: &[MemoryRegion], physical_address: u64) -> bool {
    regions.iter().any(|region| {
        region.start <= physical_address
            && physical_address < region.end
            && matches!(region.kind, MemoryRegionKind::Bootloader)
    })
}

fn translate_virtual_address(
    virtual_address: u64,
    root_table_physical: u64,
    recursive_index: u16,
) -> Result<PageTranslation, PageTableError> {
    let mut level = 4u8;
    translate_4level(virtual_address, root_table_physical, |table_physical, index| {
        let current_level = level;
        if current_level == 0
            || table_physical == 0
            || table_physical & (PAGE_SIZE - 1) != 0
            || (current_level == 4 && table_physical != root_table_physical)
        {
            return None;
        }

        let table_virtual = recursive_table_page_virtual_address(
            recursive_index,
            virtual_address,
            current_level,
        )?;
        let entry_offset = u64::try_from(index).ok()?.checked_mul(8)?;
        let entry_virtual = table_virtual.checked_add(entry_offset)?;
        if !is_canonical_4level(entry_virtual) || entry_virtual & 7 != 0 {
            return None;
        }
        let entry_pointer = usize::try_from(entry_virtual).ok()? as *const u64;

        // SAFETY: BOOTLOADER_CONFIG explicitly requests its recursive PML4
        // mapping, and BootInfo supplies that mapping's index. The address is
        // derived from the current virtual address and level, uses the active
        // paging structures rather than the physical-memory alias, and is
        // checked for canonicality and alignment before a volatile read.
        let entry = unsafe { ptr::read_volatile(entry_pointer) };
        level = level.checked_sub(1)?;
        Some(entry)
    })
}

