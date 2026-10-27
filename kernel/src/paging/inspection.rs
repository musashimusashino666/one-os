use super::*;

/// Walks the current PML4 read-only and verifies core bootstrap mappings.
///
/// The bootloader's recursive page-table mapping is required to inspect active
/// table pages. This avoids aliasing Bootloader-owned frames through the physical
/// memory offset, which bootloader_api documents as safely accessible only for
/// Usable frames. This module never writes a page-table entry.
pub(super) fn inspect_boot_mappings(boot_info: &BootInfo) -> Result<PageTableInspection, PagingError> {
    // Validate the index before deriving or dereferencing any recursive alias.
    // Index 0 produces virtual address 0 for the PML4 self-map and must fail closed.
    let recursive_index = match boot_info.recursive_index {
        Optional::Some(index) if is_safe_recursive_mapping_index(index) => index,
        Optional::Some(_) => return Err(PagingError::InvalidRecursiveIndex),
        Optional::None => return Err(PagingError::RecursiveMappingUnavailable),
    };

    let cr0: u64;
    let cr4: u64;
    let cr3: u64;
    // SAFETY: reading CR0, CR3, and CR4 is valid in the privileged x86_64 kernel.
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    }
    if cr4 & CR4_LA57 != 0 {
        return Err(PagingError::UnsupportedFiveLevelPaging);
    }
    // With CR0.WP clear, supervisor writes can bypass read-only PTEs. Require
    // write protection before treating R/W=0 as an enforced kernel restriction.
    validate_cr0_write_protect(cr0).map_err(map_paging_precondition_error)?;

    let root_table_physical = cr3 & PHYSICAL_ADDRESS_MASK;
    let regions: &[MemoryRegion] = &boot_info.memory_regions;
    if root_table_physical == 0
        || root_table_physical & (PAGE_SIZE - 1) != 0
        || !is_bootloader_owned_page(regions, root_table_physical)
    {
        return Err(PagingError::InvalidRootTable);
    }
    if !validate_recursive_mapping_entry(recursive_index, root_table_physical) {
        return Err(PagingError::InvalidRecursiveMapping);
    }
    let code_address = inspect_boot_mappings as *const () as usize as u64;
    let boot_info_address = boot_info as *const BootInfo as usize as u64;
    let mut stack_pointer: u64;
    // SAFETY: reading RSP in the current kernel context does not modify it.
    unsafe {
        asm!("mov {}, rsp", out(reg) stack_pointer, options(nomem, nostack, preserves_flags));
    }

    // kernel_len describes the in-memory ELF file, not the span of the
    // loaded virtual image (which can include gaps and zero-filled BSS).
    // Validate the physical ELF backing interval, but do not infer a virtual
    // upper bound from kernel_image_offset + kernel_len.
    let kernel_physical_end = boot_info
        .kernel_addr
        .checked_add(boot_info.kernel_len)
        .filter(|_| boot_info.kernel_len != 0)
        .ok_or(PagingError::InvalidKernelImageRange)?;
    // The bootloader maps file-backed ELF segments from frames within the
    // in-memory ELF slice using each PT_LOAD p_offset. Parse the table with a
    // bounded no-allocation parser, then validate every page belonging to every
    // PT_LOAD segment against live translations and effective permissions.

    if boot_info.kernel_addr & (PAGE_SIZE - 1) != 0 {
        return Err(PagingError::InvalidKernelImageRange);
    }

    // Read metadata only through the loaded kernel mapping. The helper validates
    // each translation against the original physical ELF file backing and requires
    // a read-only, supervisor-only, NX alias before performing raw byte loads.
    let mut elf_header = [0u8; ELF64_HEADER_SIZE];
    read_kernel_elf_bytes(
        boot_info,
        0,
        &mut elf_header,
        root_table_physical,
        recursive_index,
        regions,
    )?;
    let (program_header_offset, program_header_size) =
        elf64_program_header_table_range(&elf_header, boot_info.kernel_len)
            .map_err(|_| PagingError::InvalidKernelElf)?;
    let mut program_header_buffer = [0u8; MAX_ELF64_PROGRAM_HEADERS * ELF64_PROGRAM_HEADER_SIZE];
    let program_headers = &mut program_header_buffer[..program_header_size];
    read_kernel_elf_bytes(
        boot_info,
        program_header_offset,
        program_headers,
        root_table_physical,
        recursive_index,
        regions,
    )?;
    let load_image = parse_elf64_load_segments(&elf_header, program_headers, boot_info.kernel_len)
        .map_err(|_| PagingError::InvalidKernelElf)?;
    let validated_load_pages = validate_elf_load_mappings(
        &load_image,
        boot_info,
        code_address,
        root_table_physical,
        recursive_index,
        regions,
    )?;

    let stack_end = boot_info
        .kernel_stack_bottom
        .checked_add(boot_info.kernel_stack_len)
        .filter(|_| boot_info.kernel_stack_len != 0)
        .ok_or(PagingError::InvalidStackMapping)?;
    if stack_pointer < boot_info.kernel_stack_bottom || stack_pointer >= stack_end {
        return Err(PagingError::InvalidStackMapping);
    }

    // Validate every page intersecting these live bootstrap objects, not only
    // the page containing RSP/the BootInfo pointer. Any Usable-backed pages are
    // pinned before the first allocator allocation so they cannot be reused.
    let validated_stack_pages = validate_bootstrap_data_mapping_range(
        boot_info.kernel_stack_bottom,
        boot_info.kernel_stack_len,
        root_table_physical,
        recursive_index,
        regions,
        PagingError::InvalidStackMapping,
    )?;
    let boot_info_length =
        u64::try_from(size_of::<BootInfo>()).map_err(|_| PagingError::InvalidBootInfoMapping)?;
    let validated_boot_info_pages = validate_bootstrap_data_mapping_range(
        boot_info_address,
        boot_info_length,
        root_table_physical,
        recursive_index,
        regions,
        PagingError::InvalidBootInfoMapping,
    )?;
    // BootInfo stores the memory map through a slice pointer; its entries live
    // outside the BootInfo struct and must not be assumed to share its backing.
    let memory_regions_address = boot_info.memory_regions.as_ptr() as usize as u64;
    let memory_regions_bytes = boot_info
        .memory_regions
        .len()
        .checked_mul(size_of::<MemoryRegion>())
        .and_then(|length| u64::try_from(length).ok())
        .ok_or(PagingError::InvalidBootInfoMapping)?;
    let validated_memory_region_pages = validate_bootstrap_data_mapping_range(
        memory_regions_address,
        memory_regions_bytes,
        root_table_physical,
        recursive_index,
        regions,
        PagingError::InvalidBootInfoMapping,
    )?;

    let code_translation =
        translate_virtual_address(code_address, root_table_physical, recursive_index, regions)
            .map_err(PagingError::Translation)?;
    // Validate that the translated code byte is backed by the kernel ELF
    // slice reported by BootInfo; PT_LOAD file offsets need not equal vaddrs.
    if code_translation.physical_address < boot_info.kernel_addr
        || code_translation.physical_address >= kernel_physical_end
        || !translation_preserves_page_offset(code_address, code_translation)
        || code_translation.writable
        || code_translation.user_accessible
        || !code_translation.executable
    {
        return Err(PagingError::InvalidKernelCodeMapping);
    }

    // Collect a bounded, read-only inventory of current-root mappings whose
    // effective permissions include write or execute. Existing conflicts are
    // reported, not repaired here: boot/direct-map aliases still need the separate
    // transactional integration tracked by Issue #26. The recursive self-map is
    // intentionally excluded because it is a paging-structure view, not a data map.
    let physical_address_bits = (__cpuid(CPUID_PHYSICAL_ADDRESS_WIDTH).eax & 0xff) as u8;
    let (wx_audit, wx_audit_scope) = audit_registered_wx_roots(
        boot_info,
        root_table_physical,
        recursive_index,
        physical_address_bits,
    )?;

    Ok(PageTableInspection {
        root_table_physical,
        validated_mappings: validated_load_pages
            .saturating_add(validated_stack_pages)
            .saturating_add(validated_boot_info_pages)
            .saturating_add(validated_memory_region_pages),
        wx_audit,
        wx_audit_scope,
    })
}

