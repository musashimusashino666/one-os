//! Inspection and guarded mutation of the active x86_64 page tables.
//!
//! The inspector validates essential boot mappings. The mutation editor uses
//! checked recursive aliases for reachable tables and the bootloader-provided
//! physical-memory offset only for owned, unpublished Usable frames. Mutation
//! remains single-CPU and requires maskable interrupts disabled.

use core::arch::asm;
use core::arch::x86_64::__cpuid;
use core::mem::size_of;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use bootloader_api::info::{MemoryRegion, MemoryRegionKind, Optional};
use bootloader_api::BootInfo;
use oneos_core::{
    bootstrap_mapping_page_count, compare_exchange_entry_with_ad_retry, demote_large_page,
    elf64_program_header_table_range, initialize_user_frame, is_canonical_4level,
    is_safe_recursive_mapping_index, map_supervisor_4k, map_user_data_page,
    parse_elf64_load_segments, physical_page_is_in_allowed_region,
    recursive_entry_is_valid_kernel_root, recursive_entry_matches_root,
    recursive_table_page_virtual_address, reserve_bootstrap_backing_frame, translate_4level,
    unmap_4k, unmap_all_user_data_pages, validate_cr0_write_protect, validate_efer_nx_enable,
    validate_extended_cpuid_leaf, validate_paging_cpu_capabilities, ActiveAddressSpaceRoot,
    AddressSpaceRoot, BootstrapBackingKind, BootstrapFrameReservationError, Elf64LoadImage, Frame,
    FrameRegistryError, FrameWxAudit, FrameWxAuditScope, FrameWxAuditScopeSummary,
    FrameWxAuditSource, FrameWxAuditSummary, FrameWxAuditTableBudget, FrameWxError,
    FrameWxPermissions, FrameWxRegistry, LargePageDemotionEditor, LargePageDemotionReceipt,
    PagePermissions, PageTableEditor, PageTableError, PageTableFrameRegistry,
    PageTableMutationError, PageTranslation, PagingPreconditionError, PublishedFrameReleaseError,
    UserAddressSpaceEditor, UserFrameInitializationError, UserFrameInitializer,
    UserPageMappingError, UserPageMappingRegistry, UserPageTeardownFailure, ZeroedFrame,
    ATOMIC_ENTRY_CAS_MAX_ATTEMPTS, ELF64_HEADER_SIZE, ELF64_PROGRAM_HEADER_SIZE,
    FRAME_WX_AUDIT_MAX_TABLES, MAX_ELF64_PROGRAM_HEADERS, PAGE_SIZE, USER_VIRTUAL_ADDRESS_LIMIT,
};

const CR0_WP: u64 = 1 << 16;
const CR4_LA57: u64 = 1 << 12;
const EFER_MSR: u32 = 0xc000_0080;
const EFER_NXE: u64 = 1 << 11;
const CPUID_EXTENDED_FEATURES: u32 = 0x8000_0001;
const CPUID_PHYSICAL_ADDRESS_WIDTH: u32 = 0x8000_0008;
const WRITABLE: u64 = 1 << 1;
const USER_ACCESSIBLE: u64 = 1 << 2;
const PRESENT: u64 = 1;
const LARGE_PAGE: u64 = 1 << 7;
const NO_EXECUTE: u64 = 1 << 63;
const PHYSICAL_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const PROTECTION_KEY_FIELD_MASK: u64 = 0x7800_0000_0000_0000;
const TABLE_FRAME_CAPACITY: usize = 512;
// Keep lazy initialization bounded on the bootstrap kernel stack; exhaustion fails closed.
const WX_ALIAS_REGISTRY_CAPACITY: usize = 64;
const ADDRESS_SPACE_ROOT_CAPACITY: usize = 16;
const PML4_ENTRY_COUNT: usize = 512;
const LOWER_HALF_PML4_ENTRIES: usize = 256;
const FIRST_CANDIDATE_PML4_INDEX: u16 = 256;
const MAPPING_SMOKE_SENTINEL: u64 = 0x4f4e_454f_5356_4d31;
// Refuse malformed BootInfo ranges that would make bootstrap page auditing unbounded.
const MAX_BOOTSTRAP_MAPPING_PAGES: u64 = 4096;
// Bounds the read-only W^X walk. Exhaustion is an incomplete audit, never a clean result.
const MAX_WX_AUDIT_RANGES: usize = 128;
const MAX_WX_AUDIT_TABLES: usize = FRAME_WX_AUDIT_MAX_TABLES;
const MAX_WX_AUDIT_ROOTS: usize = ADDRESS_SPACE_ROOT_CAPACITY + 1;
const MAX_WX_AUDIT_RECURSIVE_FRAMES: usize = 2048;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageTableInspection {
    pub root_table_physical: u64,
    pub validated_mappings: usize,
    /// Read-only inventory of writable/executable aliases observed in the active root.
    pub wx_audit: FrameWxAuditSummary,
    /// Coverage status for the root-registry snapshot; only the active root is walked today.
    pub wx_audit_scope: FrameWxAuditScopeSummary,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PagingError {
    RecursiveMappingUnavailable,
    InvalidRecursiveIndex,
    InvalidRecursiveMapping,
    UnsupportedFiveLevelPaging,
    PagingDisabled,
    PcidUnsupported,
    SupervisorWriteProtectionDisabled,
    UnsupportedNx,
    ExtendedCpuidLeafUnavailable {
        required_leaf: u32,
        maximum_leaf: u32,
    },
    NxEnableDisabled,
    InvalidPhysicalAddressWidth {
        bits: u8,
    },
    PhysicalMemoryOffsetUnavailable,
    InterruptsEnabled,
    FrameAllocationFailed,
    FrameReleaseFailed,
    UserFrameInitializationFailed,
    NoUnusedVirtualAddress,
    MappingSmokeMismatch,
    LargePageDemotionFailed,
    MappingMutation(PageTableMutationError),
    InvalidRootTable,
    InvalidKernelImageRange,
    InvalidKernelElf,
    InvalidKernelLoadMapping,
    KernelFrameReservationFailed,
    BootstrapFrameReservationFailed,
    InvalidKernelCodeMapping,
    InvalidStackMapping,
    InvalidBootInfoMapping,
    WxAuditFailed,
    #[cfg(feature = "test-wx-runtime-audit")]
    WxSiblingFrameUnavailable,
    Translation(PageTableError),
    InactiveAddressSpaceInvalid,
    InactivePageTableUnavailable,
    InactivePageTableOwnershipViolation,
    InactivePageTableMalformed,
    UnregisteredUserPage,
    UserPageMapping(UserPageMappingError),
    UserPageTeardownFailed,
    PageTableFrameReleaseFailed,
    PrivatePageTableCapacityExceeded,
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
            Self::InvalidRecursiveMapping => {
                b"Recursive mapping entry does not reference the CR3 PML4 frame\n"
            }
            Self::InvalidKernelImageRange => b"BootInfo kernel image range is invalid\n",
            Self::InvalidKernelElf => b"Kernel ELF header or PT_LOAD metadata is malformed or inaccessible\n",
            Self::InvalidKernelLoadMapping => b"A kernel PT_LOAD page has a missing, conflicting, or unexpected translation or permission\n",
            Self::KernelFrameReservationFailed => b"A loaded kernel frame in Usable memory could not be permanently reserved before allocation\n",
            Self::BootstrapFrameReservationFailed => {
                b"A boot stack or BootInfo backing frame in Usable memory could not be reserved before allocation\n"
            }
            Self::InvalidKernelCodeMapping => {
                b"Kernel code translation is outside the ELF backing interval or has unexpected page-table permissions\n"
            }
            Self::InvalidStackMapping => {
                b"Kernel stack pointer is outside the expected virtual range or has unexpected page offset/page-table permissions\n"
            }
            Self::InvalidBootInfoMapping => {
                b"BootInfo mapping has an unexpected page offset or page-table permissions\n"
            }
            Self::WxAuditFailed => {
                b"Could not complete the bounded read-only W^X mapping inventory\n"
            }
            #[cfg(feature = "test-wx-runtime-audit")]
            Self::WxSiblingFrameUnavailable => {
                b"No unused Usable sibling frame could be reserved in the executable page's 2 MiB region\n"
            }
            Self::InactiveAddressSpaceInvalid => {
                b"Inactive address-space root failed validation\n"
            }
            Self::InactivePageTableUnavailable => {
                b"Inactive private page-table frame is not safely accessible\n"
            }
            Self::InactivePageTableOwnershipViolation => {
                b"Inactive page-table frame is not owned by the requested root\n"
            }
            Self::InactivePageTableMalformed => {
                b"Inactive user address-space page-table tree is malformed\n"
            }
            Self::UnregisteredUserPage => {
                b"Inactive address space contains an unregistered user mapping\n"
            }
            Self::UserPageMapping(_) => {
                b"Could not install or validate inactive user page mapping\n"
            }
            Self::UserPageTeardownFailed => {
                b"Inactive user-page teardown failed; frame ownership is retained\n"
            }
            Self::PageTableFrameReleaseFailed => {
                b"Could not safely release a detached private page-table frame\n"
            }
            Self::PrivatePageTableCapacityExceeded => {
                b"Private page-table tree exceeds the ownership registry capacity\n"
            }
            Self::UnsupportedFiveLevelPaging => {
                b"Five-level paging is not supported by this inspector\n"
            }
            Self::PagingDisabled => b"CR0.PG is disabled; paging is not active\n",
            Self::PcidUnsupported => {
                b"CR4.PCIDE is enabled; PCID-tagged CR3 switching is not supported\n"
            }
            Self::SupervisorWriteProtectionDisabled => {
                b"CR0.WP is disabled; supervisor writes may bypass read-only page-table entries\n"
            }
            Self::UnsupportedNx => b"CPU does not expose the required NX feature\n",
            Self::ExtendedCpuidLeafUnavailable { .. } => {
                b"CPU does not report the extended CPUID leaf required for physical-address width\n"
            }
            Self::NxEnableDisabled => {
                b"EFER.NXE is disabled after paging-control initialization\n"
            }
            Self::InvalidPhysicalAddressWidth { .. } => {
                b"CPU reported an unsupported physical-address width\n"
            }
            Self::PhysicalMemoryOffsetUnavailable => {
                b"Bootloader did not provide a physical-memory offset\n"
            }
            Self::InterruptsEnabled => {
                b"Page-table mutation requires maskable interrupts to remain disabled\n"
            }
            Self::FrameAllocationFailed => b"Could not allocate a data frame for the mapping smoke test\n",
            Self::FrameReleaseFailed => b"Could not release the mapping smoke-test frame\n",
            Self::UserFrameInitializationFailed => {
                b"Could not safely zero and verify a complete user data frame\n"
            }
            Self::NoUnusedVirtualAddress => b"No unused virtual address was available for the mapping smoke test\n",
            Self::MappingSmokeMismatch => b"Active page-table map/unmap smoke test failed\n",
            Self::LargePageDemotionFailed => {
                b"Live large-page demotion transaction or direct-map verification failed\n"
            }
            Self::MappingMutation(_) => b"Active page-table map/unmap operation failed\n",
            Self::InvalidRootTable => b"CR3 PML4 page is invalid or not fully Bootloader-owned\n",
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

pub(super) fn audit_registered_wx_roots(
    boot_info: &BootInfo,
    root_table_physical: u64,
    recursive_index: u16,
    physical_address_bits: u8,
) -> Result<(FrameWxAuditSummary, FrameWxAuditScopeSummary), PagingError> {
    if active_root_table_physical() != root_table_physical {
        return Err(PagingError::WxAuditFailed);
    }

    // All root and table-registry mutations use the current single-CPU,
    // maskable-interrupts-disabled contract. Refuse to snapshot otherwise.
    let mut active_editor =
        KernelPageTableEditor::new_for_readonly_audit(boot_info, 0, recursive_index)
            .map_err(|_| PagingError::WxAuditFailed)?;
    let mut audit = FrameWxAudit::<MAX_WX_AUDIT_RANGES>::new(physical_address_bits)
        .map_err(|_| PagingError::WxAuditFailed)?;
    let mut scope = FrameWxAuditScope::<MAX_WX_AUDIT_ROOTS>::new(physical_address_bits)
        .map_err(|_| PagingError::WxAuditFailed)?;

    let active_root_pointer = active_editor
        .audit_table_pointer(root_table_physical, 4)
        .ok_or(PagingError::WxAuditFailed)?;
    if find_root_recursive_index(
        active_root_pointer,
        root_table_physical,
        physical_address_bits,
    )? != recursive_index
    {
        return Err(PagingError::WxAuditFailed);
    }

    scope
        .declare_root(root_table_physical)
        .map_err(|_| PagingError::WxAuditFailed)?;

    // Snapshot registered roots into bounded local storage before sealing the
    // inventory. Reject malformed, duplicate, stale, or unowned entries rather
    // than silently shrinking the declared root set.
    let mut registered_roots = [0u64; ADDRESS_SPACE_ROOT_CAPACITY];
    let mut registered_root_count = 0usize;
    for slot in ADDRESS_SPACE_ROOT_FRAMES.iter() {
        let registered_root = slot.load(Ordering::Acquire);
        if registered_root == 0 {
            continue;
        }
        if !valid_physical_page(registered_root, physical_address_bits)
            || !is_address_space_root_frame(registered_root)
            || !matches!(super::memory::is_frame_allocated(registered_root), Ok(true))
            || registered_roots[..registered_root_count].contains(&registered_root)
        {
            return Err(PagingError::WxAuditFailed);
        }
        registered_roots[registered_root_count] = registered_root;
        registered_root_count += 1;
        if registered_root != root_table_physical {
            scope
                .declare_root(registered_root)
                .map_err(|_| PagingError::WxAuditFailed)?;
        }
    }
    scope
        .seal_root_inventory()
        .map_err(|_| PagingError::WxAuditFailed)?;

    let mut visited_path = [0u64; 4];
    let mut table_budget = FrameWxAuditTableBudget::<MAX_WX_AUDIT_TABLES>::new();
    let mut recursive_aliases = RecursiveAliasSet::new()?;

    // Walk the active root in full. Its non-recursive PML4 entries are the
    // reference for the shared kernel half in every kernel-created root.
    audit_wx_table(
        boot_info,
        recursive_index,
        physical_address_bits,
        root_table_physical,
        recursive_index,
        root_table_physical,
        4,
        0,
        true,
        true,
        AuditRootRange::All,
        true,
        Some(recursive_index),
        &mut recursive_aliases,
        &mut visited_path,
        0,
        &mut table_budget,
        &mut audit,
    )?;
    scope
        .mark_root_audited(root_table_physical)
        .map_err(|_| PagingError::WxAuditFailed)?;

    // Inactive roots inherit the upper-half mappings and keep private lower-half
    // tables. Verify every shared upper PML4 entry against the active root, then
    // walk every present lower-half mapping through a validated physical-offset
    // alias and per-root table-ownership records.
    for registered_root in registered_roots[..registered_root_count].iter().copied() {
        if registered_root == root_table_physical {
            continue;
        }

        let target_root_alias = active_editor
            .offset_alias(registered_root)
            .ok_or(PagingError::WxAuditFailed)?;
        if target_root_alias as usize & (PAGE_SIZE as usize - 1) != 0 {
            return Err(PagingError::WxAuditFailed);
        }
        let target_root_pointer = target_root_alias.cast::<u64>().cast_const();
        let target_recursive_index =
            find_root_recursive_index(target_root_pointer, registered_root, physical_address_bits)?;
        if target_recursive_index < LOWER_HALF_PML4_ENTRIES as u16
            || target_recursive_index == recursive_index
        {
            return Err(PagingError::WxAuditFailed);
        }
        validate_shared_kernel_half(
            active_root_pointer,
            target_root_pointer,
            recursive_index,
            target_recursive_index,
        )?;

        audit_wx_table(
            boot_info,
            recursive_index,
            physical_address_bits,
            registered_root,
            target_recursive_index,
            registered_root,
            4,
            0,
            true,
            true,
            AuditRootRange::LowerHalf,
            true,
            Some(target_recursive_index),
            &mut recursive_aliases,
            &mut visited_path,
            0,
            &mut table_budget,
            &mut audit,
        )?;
        scope
            .mark_root_audited(registered_root)
            .map_err(|_| PagingError::WxAuditFailed)?;
    }

    // Compare the collected recursive page-table aliases against the complete
    // leaf inventory only after all roots have been walked; doing this late avoids
    // missing executable leaves that appear later in page-table traversal order.
    recursive_aliases.check_conflicts(&mut audit)?;

    // All present W/X leaves in every declared root were enumerated before this
    // point, including any physical-offset/direct-map aliases; those aliases are
    // ordinary PTE-derived mappings, not a second mapping store. The recursive
    // self-reference slots are omitted from the ordinary walk, then separately
    // audited above for every root by observing each reachable table-frame alias
    // against the complete executable/writable leaf inventory.
    scope.account_source(FrameWxAuditSource::PhysicalMemoryOffsetAlias);
    scope.account_source(FrameWxAuditSource::RecursivePageTableView);
    scope.account_source(FrameWxAuditSource::SharedKernelMappings);
    scope.account_source(FrameWxAuditSource::LargePageLeaves);

    Ok((audit.summary(), scope.summary()))
}

fn find_root_recursive_index(
    root_pointer: *const u64,
    root_physical: u64,
    physical_address_bits: u8,
) -> Result<u16, PagingError> {
    if !valid_physical_page(root_physical, physical_address_bits) {
        return Err(PagingError::WxAuditFailed);
    }
    let mut found = None;
    for index in 0..PML4_ENTRY_COUNT {
        // SAFETY: the caller has already validated this complete PML4 page.
        let entry = unsafe { ptr::read_volatile(root_pointer.add(index)) };
        if entry & PRESENT == 0 || entry & PHYSICAL_ADDRESS_MASK != root_physical {
            continue;
        }
        if entry & LARGE_PAGE != 0
            || entry & WRITABLE == 0
            || entry & USER_ACCESSIBLE != 0
            || entry & NO_EXECUTE == 0
            || entry & PROTECTION_KEY_FIELD_MASK != 0
            || found.is_some()
        {
            return Err(PagingError::WxAuditFailed);
        }
        found = Some(index as u16);
    }
    found.ok_or(PagingError::WxAuditFailed)
}

fn validate_shared_kernel_half(
    active_root_pointer: *const u64,
    target_root_pointer: *const u64,
    active_recursive_index: u16,
    target_recursive_index: u16,
) -> Result<(), PagingError> {
    if active_recursive_index == target_recursive_index {
        return Err(PagingError::WxAuditFailed);
    }
    for index in LOWER_HALF_PML4_ENTRIES..PML4_ENTRY_COUNT {
        if index == usize::from(active_recursive_index)
            || index == usize::from(target_recursive_index)
        {
            continue;
        }
        // SAFETY: both root pointers refer to complete validated PML4 frames.
        let active_entry = unsafe { ptr::read_volatile(active_root_pointer.add(index)) };
        // SAFETY: same as above for the target root.
        let target_entry = unsafe { ptr::read_volatile(target_root_pointer.add(index)) };
        if active_entry != target_entry {
            return Err(PagingError::WxAuditFailed);
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuditRootRange {
    All,
    LowerHalf,
}

// Store audit scratch in BSS rather than the constrained bootstrap/kernel stack.
// The lease prevents re-entrant or concurrent walkers from observing each other's
// entries; this OS currently requires single-CPU, maskable-interrupts-disabled use.
static WX_AUDIT_RECURSIVE_FRAMES_BUSY: AtomicBool = AtomicBool::new(false);
static mut WX_AUDIT_RECURSIVE_FRAMES: [u64; MAX_WX_AUDIT_RECURSIVE_FRAMES] =
    [0; MAX_WX_AUDIT_RECURSIVE_FRAMES];
static mut WX_AUDIT_RECURSIVE_VIRTUALS: [u64; MAX_WX_AUDIT_RECURSIVE_FRAMES] =
    [0; MAX_WX_AUDIT_RECURSIVE_FRAMES];

/// Physical frames whose writable recursive aliases must be checked after the
/// complete ordinary leaf inventory has been collected. Shared page-table frames
/// are deduplicated because another root's recursive alias has the same physical
/// extent and effective W/NX rights once shared PML4 entries are validated equal.
struct RecursiveAliasSet {
    count: usize,
}

impl RecursiveAliasSet {
    fn new() -> Result<Self, PagingError> {
        WX_AUDIT_RECURSIVE_FRAMES_BUSY
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| PagingError::WxAuditFailed)?;
        Ok(Self { count: 0 })
    }

    fn observe(
        &mut self,
        physical_frame: u64,
        recursive_virtual_address: u64,
        effective_writable: bool,
    ) -> Result<(), PagingError> {
        if !is_canonical_4level(recursive_virtual_address)
            || recursive_virtual_address & (PAGE_SIZE - 1) != 0
        {
            return Err(PagingError::WxAuditFailed);
        }
        if !effective_writable {
            return Ok(());
        }

        // SAFETY: the atomic lease grants this audit exclusive use of the fixed
        // BSS buffer. The function is called only under the kernel's documented
        // single-CPU, maskable-interrupts-disabled inspection contract.
        let frames = core::ptr::addr_of_mut!(WX_AUDIT_RECURSIVE_FRAMES).cast::<u64>();
        for index in 0..self.count {
            // SAFETY: index is strictly below count, which is only increased after
            // writing a slot below MAX_WX_AUDIT_RECURSIVE_FRAMES.
            if unsafe { ptr::read(frames.add(index)) } == physical_frame {
                return Ok(());
            }
        }
        if self.count == MAX_WX_AUDIT_RECURSIVE_FRAMES {
            return Err(PagingError::WxAuditFailed);
        }
        // SAFETY: the exclusive lease is held and count is below the fixed capacity.
        unsafe {
            ptr::write(frames.add(self.count), physical_frame);
            ptr::write(
                core::ptr::addr_of_mut!(WX_AUDIT_RECURSIVE_VIRTUALS)
                    .cast::<u64>()
                    .add(self.count),
                recursive_virtual_address,
            );
        }
        self.count += 1;
        Ok(())
    }

    fn check_conflicts<const CAPACITY: usize>(
        &self,
        audit: &mut FrameWxAudit<CAPACITY>,
    ) -> Result<(), PagingError> {
        // SAFETY: this set still owns the exclusive lease; all indices are below count.
        let frames = core::ptr::addr_of!(WX_AUDIT_RECURSIVE_FRAMES).cast::<u64>();
        let virtuals = core::ptr::addr_of!(WX_AUDIT_RECURSIVE_VIRTUALS).cast::<u64>();
        for index in 0..self.count {
            // SAFETY: index is below the successfully populated candidate count.
            let physical_frame = unsafe { ptr::read(frames.add(index)) };
            // SAFETY: the same index was populated with the validated recursive VA.
            let virtual_address = unsafe { ptr::read(virtuals.add(index)) };
            audit
                .observe_alias(
                    virtual_address,
                    physical_frame,
                    PAGE_SIZE,
                    FrameWxPermissions::new(true, false),
                )
                .map_err(|_| PagingError::WxAuditFailed)?;
        }
        Ok(())
    }
}

impl Drop for RecursiveAliasSet {
    fn drop(&mut self) {
        WX_AUDIT_RECURSIVE_FRAMES_BUSY.store(false, Ordering::Release);
    }
}

/// Walks a bounded page-table subtree and optionally records ordinary leaves or
/// the writable/NX recursive alias of each reachable page-table frame.
#[allow(clippy::too_many_arguments)]
fn audit_wx_table<const CAPACITY: usize>(
    boot_info: &BootInfo,
    active_recursive_index: u16,
    physical_address_bits: u8,
    audit_root_physical: u64,
    audit_root_recursive_index: u16,
    table_physical: u64,
    level: u8,
    virtual_prefix: u64,
    ancestors_writable: bool,
    ancestors_executable: bool,
    root_range: AuditRootRange,
    record_leaf_mappings: bool,
    recursive_view_index: Option<u16>,
    recursive_aliases: &mut RecursiveAliasSet,
    visited_path: &mut [u64; 4],
    depth: usize,
    table_budget: &mut FrameWxAuditTableBudget<MAX_WX_AUDIT_TABLES>,
    audit: &mut FrameWxAudit<CAPACITY>,
) -> Result<(), PagingError> {
    if !(1..=4).contains(&level)
        || depth >= visited_path.len()
        || visited_path[..depth].contains(&table_physical)
    {
        return Err(PagingError::WxAuditFailed);
    }
    table_budget
        .visit()
        .map_err(|_| PagingError::WxAuditFailed)?;
    visited_path[depth] = table_physical;

    if let Some(view_index) = recursive_view_index {
        // The root self-reference is required to be supervisor-only, writable,
        // and NX. Ancestor permissions on the ordinary path remain effective
        // for aliases to lower-level tables. The virtual alias is validated now,
        // but physical conflicts are checked after all ordinary leaves are known.
        let view_virtual = recursive_table_page_virtual_address(
            view_index,
            if level == 4 { 0 } else { virtual_prefix },
            level,
        )
        .ok_or(PagingError::WxAuditFailed)?;
        recursive_aliases.observe(table_physical, view_virtual, ancestors_writable)?;
    }

    // The active root is read through its checked recursive alias. For an
    // inactive root, only its root frame and ownership-registered private
    // lower-half tables may be read through a validated physical-offset alias.
    let target_virtual_address = if level == 4 { 0 } else { virtual_prefix };
    let mut editor = KernelPageTableEditor::new_for_readonly_audit(
        boot_info,
        target_virtual_address,
        active_recursive_index,
    )
    .map_err(|_| PagingError::WxAuditFailed)?;
    let table_pointer = editor
        .audit_table_pointer_for_root(audit_root_physical, table_physical, level, virtual_prefix)
        .ok_or(PagingError::WxAuditFailed)?;

    let (first_entry, end_entry) = if level != 4 {
        (0, PML4_ENTRY_COUNT)
    } else {
        match root_range {
            AuditRootRange::All => (0, PML4_ENTRY_COUNT),
            AuditRootRange::LowerHalf => (0, LOWER_HALF_PML4_ENTRIES),
        }
    };
    for index in first_entry..end_entry {
        // Each root's recursive slot is omitted: recursive page-table views are
        // a separate source that must not be confused with ordinary leaf maps.
        if level == 4 && index == usize::from(audit_root_recursive_index) {
            continue;
        }
        // SAFETY: the table-pointer helper validated the complete table frame;
        // index is below both the selected entry bound and the PML4 entry count.
        let entry = unsafe { ptr::read_volatile(table_pointer.add(index)) };
        // Non-present entries may carry OS-defined software metadata.
        // Ignore their other bits rather than treating them as malformed mappings.
        if entry & PRESENT == 0 {
            continue;
        }
        let large_page = level > 1 && entry & LARGE_PAGE != 0;
        if level == 4 && large_page {
            return Err(PagingError::WxAuditFailed);
        }
        if level > 1 && !large_page && entry & PROTECTION_KEY_FIELD_MASK != 0 {
            return Err(PagingError::WxAuditFailed);
        }

        let raw_physical = entry & PHYSICAL_ADDRESS_MASK;
        if raw_physical >= (1u64 << physical_address_bits) {
            return Err(PagingError::WxAuditFailed);
        }
        let writable = ancestors_writable && entry & WRITABLE != 0;
        let executable = ancestors_executable && entry & NO_EXECUTE == 0;
        let shift = 12 + (9 * (level - 1));
        let virtual_start = if level == 4 {
            let prefix = (index as u64) << 39;
            if index >= LOWER_HALF_PML4_ENTRIES {
                prefix | 0xffff_0000_0000_0000
            } else {
                prefix
            }
        } else {
            virtual_prefix | ((index as u64) << shift)
        };

        if level == 1 || large_page {
            let page_size = if large_page { 1u64 << shift } else { PAGE_SIZE };
            if large_page && raw_physical & ((page_size - 1) & !(1 << 12)) != 0 {
                return Err(PagingError::WxAuditFailed);
            }
            let physical_start = raw_physical & !(page_size - 1);
            if record_leaf_mappings {
                audit
                    .record_alias(
                        virtual_start,
                        physical_start,
                        page_size,
                        FrameWxPermissions::new(writable, executable),
                    )
                    .map_err(|_| PagingError::WxAuditFailed)?;
            }
            continue;
        }

        let child_physical = raw_physical;
        if child_physical == 0 || child_physical & (PAGE_SIZE - 1) != 0 {
            return Err(PagingError::WxAuditFailed);
        }
        audit_wx_table(
            boot_info,
            active_recursive_index,
            physical_address_bits,
            audit_root_physical,
            audit_root_recursive_index,
            child_physical,
            level - 1,
            virtual_start,
            writable,
            executable,
            AuditRootRange::All,
            record_leaf_mappings,
            recursive_view_index,
            recursive_aliases,
            visited_path,
            depth + 1,
            table_budget,
            audit,
        )?;
    }
    Ok(())
}

/// Copies a small metadata range from the bootloader-owned in-memory ELF image.
///
/// Every touched physical page must be fully Bootloader-owned, and its direct-map
/// alias must translate to that exact page with supervisor, writable, NX access.
/// No Rust reference or slice to the aliased source memory is constructed.
fn read_kernel_elf_bytes(
    boot_info: &BootInfo,
    file_offset: u64,
    output: &mut [u8],
    root_table_physical: u64,
    recursive_index: u16,
    regions: &[MemoryRegion],
) -> Result<(), PagingError> {
    let output_len = u64::try_from(output.len()).map_err(|_| PagingError::InvalidKernelElf)?;
    let file_end = file_offset
        .checked_add(output_len)
        .filter(|end| *end <= boot_info.kernel_len)
        .ok_or(PagingError::InvalidKernelElf)?;
    if file_offset > boot_info.kernel_len || output.is_empty() || file_end <= file_offset {
        return Err(PagingError::InvalidKernelElf);
    }
    let physical_start = boot_info
        .kernel_addr
        .checked_add(file_offset)
        .ok_or(PagingError::InvalidKernelElf)?;
    let physical_end = boot_info
        .kernel_addr
        .checked_add(file_end)
        .ok_or(PagingError::InvalidKernelElf)?;
    let virtual_start = boot_info
        .kernel_image_offset
        .checked_add(file_offset)
        .ok_or(PagingError::InvalidKernelElf)?;
    let virtual_end = boot_info
        .kernel_image_offset
        .checked_add(file_end)
        .ok_or(PagingError::InvalidKernelElf)?;
    if physical_start & (PAGE_SIZE - 1) != virtual_start & (PAGE_SIZE - 1)
        || !canonical_range_stays_in_one_half(virtual_start, virtual_end)
    {
        return Err(PagingError::InvalidKernelElf);
    }

    let first_physical_page = physical_start & !(PAGE_SIZE - 1);
    let last_physical_page = (physical_end - 1) & !(PAGE_SIZE - 1);
    let first_virtual_page = virtual_start & !(PAGE_SIZE - 1);
    let last_virtual_page = (virtual_end - 1) & !(PAGE_SIZE - 1);
    let mut physical_page = first_physical_page;
    let mut virtual_page = first_virtual_page;
    loop {
        if !is_bootloader_owned_page(regions, physical_page) {
            return Err(PagingError::InvalidKernelElf);
        }
        let translation =
            translate_virtual_address(virtual_page, root_table_physical, recursive_index, regions)
                .map_err(|_| PagingError::InvalidKernelElf)?;
        if translation.page_size != PAGE_SIZE
            || translation.physical_address != physical_page
            || translation.writable
            || translation.user_accessible
            || translation.executable
        {
            return Err(PagingError::InvalidKernelElf);
        }
        if physical_page == last_physical_page && virtual_page == last_virtual_page {
            break;
        }
        physical_page = physical_page
            .checked_add(PAGE_SIZE)
            .ok_or(PagingError::InvalidKernelElf)?;
        virtual_page = virtual_page
            .checked_add(PAGE_SIZE)
            .ok_or(PagingError::InvalidKernelElf)?;
        if physical_page > last_physical_page || virtual_page > last_virtual_page {
            return Err(PagingError::InvalidKernelElf);
        }
    }

    for (index, byte) in output.iter_mut().enumerate() {
        let address = virtual_start
            .checked_add(u64::try_from(index).map_err(|_| PagingError::InvalidKernelElf)?)
            .ok_or(PagingError::InvalidKernelElf)?;
        // SAFETY: every source page was proved Bootloader-owned and mapped at
        // the corresponding virtual address as read-only, supervisor-only, NX.
        // This is a raw load from the kernel's own load mapping, not a reference
        // to a physical-memory-offset alias.
        *byte = unsafe { ptr::read_volatile(address as *const u8) };
    }
    Ok(())
}

fn kernel_backing_region_kind(
    regions: &[MemoryRegion],
    physical_page: u64,
) -> Option<MemoryRegionKind> {
    let page_end = physical_page.checked_add(PAGE_SIZE)?;
    regions
        .iter()
        .find(|region| region.start <= physical_page && page_end <= region.end)
        .map(|region| region.kind)
}

fn is_kernel_backed_page(regions: &[MemoryRegion], physical_page: u64) -> bool {
    matches!(
        kernel_backing_region_kind(regions, physical_page),
        Some(MemoryRegionKind::Usable | MemoryRegionKind::Bootloader)
    )
}

fn reserve_kernel_load_frame(
    regions: &[MemoryRegion],
    physical_page: u64,
) -> Result<(), PagingError> {
    match kernel_backing_region_kind(regions, physical_page) {
        Some(MemoryRegionKind::Bootloader) => Ok(()),
        Some(MemoryRegionKind::Usable) => {
            let reserved = crate::memory::reserve_frame(physical_page)
                .map_err(|_| PagingError::KernelFrameReservationFailed)?;
            if reserved {
                Ok(())
            } else {
                Err(PagingError::KernelFrameReservationFailed)
            }
        }
        _ => Err(PagingError::InvalidKernelLoadMapping),
    }
}

/// Validates every 4 KiB page touched by a live bootstrap data range.
///
/// The mapping must preserve the virtual/physical page offset and be writable,
/// supervisor-only, and NX. A frame may be either Bootloader-owned or Usable;
/// Usable frames are permanently reserved before the allocator can reuse them.
fn validate_bootstrap_data_mapping_range(
    virtual_start: u64,
    length: u64,
    root_table_physical: u64,
    recursive_index: u16,
    regions: &[MemoryRegion],
    mapping_error: PagingError,
) -> Result<usize, PagingError> {
    // Shared host-tested preflight rejects overflow, non-canonical ranges, and
    // excessive page counts before the hardware page-table walker is invoked.
    let page_count =
        bootstrap_mapping_page_count(virtual_start, length, MAX_BOOTSTRAP_MAPPING_PAGES)
            .map_err(|_| mapping_error)?;
    let first_virtual_page = virtual_start & !(PAGE_SIZE - 1);
    let mut virtual_page = first_virtual_page;
    for page_index in 0..page_count {
        let translation =
            translate_virtual_address(virtual_page, root_table_physical, recursive_index, regions)
                .map_err(|_| mapping_error)?;
        if !translation_preserves_page_offset(virtual_page, translation)
            || !translation.writable
            || translation.user_accessible
            || translation.executable
        {
            return Err(mapping_error);
        }

        let physical_page = translation.physical_address & !(PAGE_SIZE - 1);
        reserve_bootstrap_frame(regions, physical_page, mapping_error)?;
        if page_index + 1 < page_count {
            virtual_page = virtual_page.checked_add(PAGE_SIZE).ok_or(mapping_error)?;
        }
    }
    Ok(page_count)
}

/// Accepts only fully backed Bootloader/Usable pages. Usable pages are pinned
/// because the active stack, BootInfo, and memory-map array must outlive the allocator.
fn reserve_bootstrap_frame(
    regions: &[MemoryRegion],
    physical_page: u64,
    mapping_error: PagingError,
) -> Result<(), PagingError> {
    let kind = match kernel_backing_region_kind(regions, physical_page) {
        Some(MemoryRegionKind::Bootloader) => BootstrapBackingKind::Bootloader,
        Some(MemoryRegionKind::Usable) => BootstrapBackingKind::Usable,
        _ => BootstrapBackingKind::ReservedOrUnknown,
    };
    match reserve_bootstrap_backing_frame(kind, || crate::memory::reserve_frame(physical_page)) {
        Ok(()) => Ok(()),
        Err(BootstrapFrameReservationError::DisallowedRegion) => Err(mapping_error),
        Err(
            BootstrapFrameReservationError::FrameNotManaged
            | BootstrapFrameReservationError::ReservationFailed(_),
        ) => Err(PagingError::BootstrapFrameReservationFailed),
    }
}

fn canonical_range_stays_in_one_half(start: u64, end_exclusive: u64) -> bool {
    if end_exclusive <= start || !is_canonical_4level(start) {
        return false;
    }
    let Some(last) = end_exclusive.checked_sub(1) else {
        return false;
    };
    if !is_canonical_4level(last) {
        return false;
    }
    if start < 0x0000_8000_0000_0000 {
        last < 0x0000_8000_0000_0000
    } else {
        start >= 0xffff_8000_0000_0000 && last >= 0xffff_8000_0000_0000
    }
}

/// Audits all mapped pages described by ELF PT_LOAD headers.
///
/// The bootloader may copy writable segments while applying relocations and may
/// copy the final file-backed page when zeroing a partial-page BSS tail, so
/// exact source-frame correspondence is checked only for ordinary read-only
/// file-backed pages. Every PT_LOAD page must still exist as a 4 KiB kernel
/// mapping with effective U/S, R/W, and NX permissions matching the ELF flags.
fn validate_elf_load_mappings(
    image: &Elf64LoadImage,
    boot_info: &BootInfo,
    code_address: u64,
    root_table_physical: u64,
    recursive_index: u16,
    regions: &[MemoryRegion],
) -> Result<usize, PagingError> {
    let mut validated_pages = 0usize;
    let mut code_is_in_executable_segment = false;

    for segment in image.load_segments() {
        let load_start = boot_info
            .kernel_image_offset
            .checked_add(segment.virtual_address)
            .ok_or(PagingError::InvalidKernelLoadMapping)?;
        let load_end = load_start
            .checked_add(segment.memory_size)
            .ok_or(PagingError::InvalidKernelLoadMapping)?;
        if !canonical_range_stays_in_one_half(load_start, load_end) {
            return Err(PagingError::InvalidKernelLoadMapping);
        }
        if segment.executable() && code_address >= load_start && code_address < load_end {
            code_is_in_executable_segment = true;
        }

        let first_virtual_page = load_start & !(PAGE_SIZE - 1);
        let last_virtual_page = (load_end - 1) & !(PAGE_SIZE - 1);
        let source_first_page = boot_info
            .kernel_addr
            .checked_add(segment.offset & !(PAGE_SIZE - 1))
            .ok_or(PagingError::InvalidKernelLoadMapping)?;
        let file_end_virtual = load_start
            .checked_add(segment.file_size)
            .ok_or(PagingError::InvalidKernelLoadMapping)?;
        let last_file_page = if segment.file_size == 0 {
            None
        } else {
            Some((file_end_virtual - 1) & !(PAGE_SIZE - 1))
        };
        let partial_bss_tail_page = if segment.memory_size > segment.file_size
            && file_end_virtual & (PAGE_SIZE - 1) != 0
            && segment.file_size != 0
        {
            Some((file_end_virtual - 1) & !(PAGE_SIZE - 1))
        } else {
            None
        };

        let mut virtual_page = first_virtual_page;
        loop {
            let elf_virtual_page = virtual_page
                .checked_sub(boot_info.kernel_image_offset)
                .ok_or(PagingError::InvalidKernelLoadMapping)?;
            let translation = translate_virtual_address(
                virtual_page,
                root_table_physical,
                recursive_index,
                regions,
            )
            .map_err(|_| PagingError::InvalidKernelLoadMapping)?;
            if translation.page_size != PAGE_SIZE
                || translation.physical_address & (PAGE_SIZE - 1) != 0
                || !is_kernel_backed_page(regions, translation.physical_address)
                || translation.user_accessible
                || translation.writable
                    != (segment.writable()
                        && !image.page_is_read_only_after_relocation(elf_virtual_page))
                || translation.executable != segment.executable()
            {
                return Err(PagingError::InvalidKernelLoadMapping);
            }

            // A PT_LOAD frame can still be labelled Usable in the firmware map.
            // Pin it in the allocator before any allocation is permitted, so it
            // cannot be handed out as an ordinary free frame even if the loader
            // copied it for relocations or BSS.
            reserve_kernel_load_frame(regions, translation.physical_address)?;

            let file_backed_page = last_file_page
                .is_some_and(|last| virtual_page >= first_virtual_page && virtual_page <= last);
            let bss_tail_copy_page = partial_bss_tail_page == Some(virtual_page);
            if file_backed_page && !segment.writable() && !bss_tail_copy_page {
                let offset = virtual_page
                    .checked_sub(first_virtual_page)
                    .ok_or(PagingError::InvalidKernelLoadMapping)?;
                let expected_physical = source_first_page
                    .checked_add(offset)
                    .ok_or(PagingError::InvalidKernelLoadMapping)?;
                if translation.physical_address != expected_physical {
                    return Err(PagingError::InvalidKernelLoadMapping);
                }
            }

            validated_pages = validated_pages
                .checked_add(1)
                .ok_or(PagingError::InvalidKernelLoadMapping)?;
            if virtual_page == last_virtual_page {
                break;
            }
            virtual_page = virtual_page
                .checked_add(PAGE_SIZE)
                .ok_or(PagingError::InvalidKernelLoadMapping)?;
        }
    }

    if !code_is_in_executable_segment {
        return Err(PagingError::InvalidKernelLoadMapping);
    }
    Ok(validated_pages)
}

fn translation_preserves_page_offset(virtual_address: u64, translation: PageTranslation) -> bool {
    (translation.page_size == PAGE_SIZE
        || translation.page_size == (1 << 21)
        || translation.page_size == (1 << 30))
        && translation.physical_address & (translation.page_size - 1)
            == virtual_address & (translation.page_size - 1)
}

/// Checks the bootloader-provided recursive PML4 self-reference before walking other entries.
///
/// The first volatile read necessarily relies on BootInfo's contract: when the recursive
/// mapping is requested, the reported index maps the active PML4 frame back into itself.
/// This check catches a readable but inconsistent entry; it cannot make an absent or broken
/// recursive virtual mapping safe to probe without potentially taking a page fault.
fn read_recursive_mapping_entry(recursive_index: u16) -> Option<u64> {
    let table_virtual = recursive_table_page_virtual_address(recursive_index, 0, 4)?;
    let entry_offset = u64::from(recursive_index).checked_mul(8)?;
    let entry_virtual = table_virtual.checked_add(entry_offset)?;
    if !is_canonical_4level(entry_virtual) || entry_virtual & 7 != 0 {
        return None;
    }
    let entry_pointer = usize::try_from(entry_virtual).ok()?;

    // SAFETY: this access depends on the bootloader API's recursive-index guarantee,
    // and the physical CR3 frame was already confirmed to be a full Bootloader-owned page.
    // The value read is then checked against the physical CR3 root frame.
    Some(unsafe { ptr::read_volatile(entry_pointer as *const u64) })
}

fn validate_recursive_mapping_entry(recursive_index: u16, root_table_physical: u64) -> bool {
    read_recursive_mapping_entry(recursive_index).is_some_and(|entry| {
        recursive_entry_matches_root(entry, root_table_physical)
            && entry & USER_ACCESSIBLE == 0
            && entry & NO_EXECUTE != 0
    })
}

/// Validates the recursive self-reference used by a mapping editor.
///
/// A bootloader-owned source root may predate the kernel's stricter flags and is
/// checked for identity by the legacy validator. Once the root is allocator-owned
/// and kernel-created, the recursive alias gives access to page-table frames, so
/// it must also be supervisor-only, writable, non-executable, and free of unsupported
/// protection-key bits.
fn validate_editor_recursive_mapping_entry(
    recursive_index: u16,
    root_table_physical: u64,
    root_is_allocator_owned: bool,
) -> bool {
    let Some(entry) = read_recursive_mapping_entry(recursive_index) else {
        return false;
    };
    if root_is_allocator_owned {
        recursive_entry_is_valid_kernel_root(entry, root_table_physical)
    } else {
        recursive_entry_matches_root(entry, root_table_physical)
    }
}

/// Validates the recursive mapping for reads without requiring the R/W bit.
///
/// The recursive slot must still be a present self-reference, supervisor-only,
/// NX, and free of protection-key bits that are reserved on a PML4 entry.
fn validate_readonly_recursive_mapping_entry(
    recursive_index: u16,
    root_table_physical: u64,
) -> bool {
    read_recursive_mapping_entry(recursive_index).is_some_and(|entry| {
        recursive_entry_matches_root(entry, root_table_physical)
            && entry & USER_ACCESSIBLE == 0
            && entry & NO_EXECUTE != 0
            && entry & PROTECTION_KEY_FIELD_MASK == 0
    })
}

fn is_bootloader_owned_page(regions: &[MemoryRegion], page_physical: u64) -> bool {
    physical_page_is_in_allowed_region(page_physical, regions.len(), |index| {
        let region = regions[index];
        (
            region.start,
            region.end,
            matches!(region.kind, MemoryRegionKind::Bootloader),
        )
    })
}

fn translate_virtual_address(
    virtual_address: u64,
    root_table_physical: u64,
    recursive_index: u16,
    regions: &[MemoryRegion],
) -> Result<PageTranslation, PageTableError> {
    let mut level = 4u8;
    translate_4level(
        virtual_address,
        root_table_physical,
        |table_physical, index| {
            let current_level = level;
            if current_level == 0
                || table_physical == 0
                || table_physical & (PAGE_SIZE - 1) != 0
                || !is_bootloader_owned_page(regions, table_physical)
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
            // checked for canonicality and alignment. The current physical table
            // page was checked as a full Bootloader-owned range before this read.
            let entry = unsafe { ptr::read_volatile(entry_pointer) };
            level = level.checked_sub(1)?;
            Some(entry)
        },
    )
}

/// Establish CPU controls required before interpreting or changing leaf permissions.
///
/// NX is mandatory for this milestone: the kernel fails closed if the processor
/// does not advertise NX or the extended physical-address-width leaf.
pub fn initialize_paging_controls() -> Result<(), PagingError> {
    // SAFETY: CPUID is available at the x86_64 kernel privilege level.
    let maximum_extended_leaf = __cpuid(0x8000_0000).eax;
    validate_extended_cpuid_leaf(maximum_extended_leaf, CPUID_PHYSICAL_ADDRESS_WIDTH)
        .map_err(map_paging_precondition_error)?;
    // SAFETY: the maximum extended CPUID leaf was checked above.
    let features = __cpuid(CPUID_EXTENDED_FEATURES);
    // SAFETY: the extended physical-address-width CPUID leaf was checked above.
    let physical_address_bits = (__cpuid(CPUID_PHYSICAL_ADDRESS_WIDTH).eax & 0xff) as u8;
    validate_paging_cpu_capabilities(features.edx, physical_address_bits)
        .map_err(map_paging_precondition_error)?;

    let mut cr0: u64;
    // SAFETY: reading and writing CR0 is valid in privileged kernel execution.
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        cr0 |= CR0_WP;
        asm!("mov cr0, {}", in(reg) cr0, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
    }
    if cr0 & CR0_WP == 0 {
        return Err(PagingError::SupervisorWriteProtectionDisabled);
    }

    let mut low: u32;
    let mut high: u32;
    // SAFETY: EFER is the architectural extended-feature-enable MSR.
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") EFER_MSR,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags)
        );
    }
    let mut efer = (u64::from(high) << 32) | u64::from(low);
    if efer & EFER_NXE == 0 {
        efer |= EFER_NXE;
        low = efer as u32;
        high = (efer >> 32) as u32;
        // SAFETY: CPUID confirmed NX support; only the EFER.NXE bit is changed.
        unsafe {
            asm!(
                "wrmsr",
                in("ecx") EFER_MSR,
                in("eax") low,
                in("edx") high,
                options(nomem, nostack, preserves_flags)
            );
            asm!(
                "rdmsr",
                in("ecx") EFER_MSR,
                out("eax") low,
                out("edx") high,
                options(nomem, nostack, preserves_flags)
            );
        }
        efer = (u64::from(high) << 32) | u64::from(low);
    }
    validate_efer_nx_enable(efer).map_err(map_paging_precondition_error)?;

    Ok(())
}

fn map_paging_precondition_error(error: PagingPreconditionError) -> PagingError {
    match error {
        PagingPreconditionError::ExtendedLeafUnavailable {
            required_leaf,
            maximum_leaf,
        } => PagingError::ExtendedCpuidLeafUnavailable {
            required_leaf,
            maximum_leaf,
        },
        PagingPreconditionError::NxUnsupported => PagingError::UnsupportedNx,
        PagingPreconditionError::NxEnableDisabled => PagingError::NxEnableDisabled,
        PagingPreconditionError::InvalidPhysicalAddressWidth { bits } => {
            PagingError::InvalidPhysicalAddressWidth { bits }
        }
        PagingPreconditionError::SupervisorWriteProtectionDisabled => {
            PagingError::SupervisorWriteProtectionDisabled
        }
        PagingPreconditionError::MaskableInterruptsEnabled => PagingError::InterruptsEnabled,
        PagingPreconditionError::PagingDisabled => PagingError::PagingDisabled,
        PagingPreconditionError::FiveLevelPagingUnsupported => {
            PagingError::UnsupportedFiveLevelPaging
        }
        PagingPreconditionError::PcidUnsupported => PagingError::PcidUnsupported,
    }
}

struct TableFrameRegistry {
    held: AtomicBool,
    registry: core::cell::UnsafeCell<PageTableFrameRegistry<Frame, TABLE_FRAME_CAPACITY>>,
}

// SAFETY: every access to the UnsafeCell is through a TableFrameRegistryGuard.
// The non-blocking atomic guard serializes registry operations. Page-table tree
// mutation additionally remains a single-CPU, maskable-interrupts-disabled
// operation; disabling interrupts alone is not an SMP synchronization protocol.
unsafe impl Sync for TableFrameRegistry {}

struct TableFrameRegistryGuard<'a> {
    owner: &'a TableFrameRegistry,
}

impl core::ops::Deref for TableFrameRegistryGuard<'_> {
    type Target = PageTableFrameRegistry<Frame, TABLE_FRAME_CAPACITY>;

    fn deref(&self) -> &Self::Target {
        // SAFETY: this guard owns the registry's atomic access token.
        unsafe { &*self.owner.registry.get() }
    }
}

impl core::ops::DerefMut for TableFrameRegistryGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: this guard owns the registry's exclusive atomic access token.
        unsafe { &mut *self.owner.registry.get() }
    }
}

impl Drop for TableFrameRegistryGuard<'_> {
    fn drop(&mut self) {
        self.owner.held.store(false, Ordering::Release);
    }
}

impl TableFrameRegistry {
    const fn new() -> Self {
        Self {
            held: AtomicBool::new(false),
            registry: core::cell::UnsafeCell::new(PageTableFrameRegistry::new()),
        }
    }

    fn lock(&self) -> TableFrameRegistryGuard<'_> {
        if self
            .held
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // Never continue after losing exclusive registry access. This is a
            // deliberate fail-stop; a spin here could deadlock an NMI/interrupt.
            panic!("concurrent page-table frame registry access");
        }
        TableFrameRegistryGuard { owner: self }
    }
}

static TABLE_FRAMES: TableFrameRegistry = TableFrameRegistry::new();

struct KernelWxAliasRegistry {
    held: AtomicBool,
    registry: core::cell::UnsafeCell<Option<FrameWxRegistry<WX_ALIAS_REGISTRY_CAPACITY>>>,
}

// SAFETY: every access to the optional registry is protected by this non-blocking
// guard. Page-table mutations remain single-CPU with maskable interrupts disabled;
// this lock is not an SMP synchronization protocol.
unsafe impl Sync for KernelWxAliasRegistry {}

struct KernelWxAliasRegistryGuard<'a> {
    owner: &'a KernelWxAliasRegistry,
}

impl core::ops::Deref for KernelWxAliasRegistryGuard<'_> {
    type Target = Option<FrameWxRegistry<WX_ALIAS_REGISTRY_CAPACITY>>;

    fn deref(&self) -> &Self::Target {
        // SAFETY: the guard owns the registry access token.
        unsafe { &*self.owner.registry.get() }
    }
}

impl core::ops::DerefMut for KernelWxAliasRegistryGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: the guard owns the exclusive registry access token.
        unsafe { &mut *self.owner.registry.get() }
    }
}

impl Drop for KernelWxAliasRegistryGuard<'_> {
    fn drop(&mut self) {
        self.owner.held.store(false, Ordering::Release);
    }
}

impl KernelWxAliasRegistry {
    const fn new() -> Self {
        Self {
            held: AtomicBool::new(false),
            registry: core::cell::UnsafeCell::new(None),
        }
    }

    fn lock(&self) -> KernelWxAliasRegistryGuard<'_> {
        if self
            .held
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            panic!("concurrent kernel W^X alias registry access");
        }
        KernelWxAliasRegistryGuard { owner: self }
    }
}

static KERNEL_WX_ALIASES: KernelWxAliasRegistry = KernelWxAliasRegistry::new();

fn with_kernel_wx_registry<T>(
    physical_address_bits: u8,
    operation: impl FnOnce(&mut FrameWxRegistry<WX_ALIAS_REGISTRY_CAPACITY>) -> Result<T, FrameWxError>,
) -> Result<T, FrameWxError> {
    let mut guard = KERNEL_WX_ALIASES.lock();
    if guard.is_none() {
        *guard = Some(FrameWxRegistry::new(physical_address_bits)?);
    }
    let registry = guard
        .as_mut()
        .expect("W^X registry initialization must produce a value");
    if registry.physical_address_bits() != physical_address_bits {
        return Err(FrameWxError::InvalidPhysicalAddressWidth);
    }
    operation(registry)
}

fn reserve_kernel_wx_alias(
    root: u64,
    virtual_address: u64,
    physical_address: u64,
    permissions: PagePermissions,
    physical_address_bits: u8,
) -> Result<(), PageTableMutationError> {
    with_kernel_wx_registry(physical_address_bits, |registry| {
        registry
            .reserve_alias_range(
                root,
                virtual_address,
                physical_address,
                PAGE_SIZE,
                FrameWxPermissions::new(permissions.writable, permissions.executable),
            )
            .map(|_| ())
    })
    .map_err(|_| PageTableMutationError::WxAliasRegistryFailure)
}

fn commit_kernel_wx_alias(root: u64, virtual_address: u64, physical_address_bits: u8) {
    if with_kernel_wx_registry(physical_address_bits, |registry| {
        registry.commit_alias_at(root, virtual_address)
    })
    .is_err()
    {
        panic!("published mapping has no matching W^X reservation");
    }
}

fn begin_kernel_wx_alias_removal(
    root: u64,
    virtual_address: u64,
    physical_address: u64,
    permissions: PagePermissions,
    physical_address_bits: u8,
) -> Result<(), PageTableMutationError> {
    with_kernel_wx_registry(physical_address_bits, |registry| {
        registry.begin_removal_for_alias(
            root,
            virtual_address,
            physical_address,
            PAGE_SIZE,
            FrameWxPermissions::new(permissions.writable, permissions.executable),
        )
    })
    .map_err(|_| PageTableMutationError::WxAliasRegistryFailure)
}

fn complete_kernel_wx_alias_removal(root: u64, virtual_address: u64, physical_address_bits: u8) {
    if with_kernel_wx_registry(physical_address_bits, |registry| {
        registry.complete_removal_at(root, virtual_address)
    })
    .is_err()
    {
        panic!("detached mapping has no matching retiring W^X alias");
    }
}

// Address-space roots are page tables too, but their ownership is held by
// AddressSpaceRoot/ActiveAddressSpaceRoot rather than TABLE_FRAMES. Track every
// live kernel-created root frame so leaf mapping and user-frame zeroing reject
// roots that are not the current CR3 or the editor's immediate target.
//
// Zero is never a valid root physical address and is used as the empty marker.
// The kernel runs single-CPU with maskable interrupts disabled during these
// operations; atomics keep the individual slot operations race-free if that
// contract is later tightened.
static ADDRESS_SPACE_ROOT_FRAMES: [AtomicU64; ADDRESS_SPACE_ROOT_CAPACITY] =
    [const { AtomicU64::new(0) }; ADDRESS_SPACE_ROOT_CAPACITY];

/// Records one live kernel-created address-space root frame.
///
/// Returns false when the registry is full. Duplicate registration is
/// idempotent so a caller that already owns a root can safely revalidate it.
pub(super) fn register_address_space_root(physical_address: u64) -> bool {
    if physical_address == 0 || physical_address & (PAGE_SIZE - 1) != 0 {
        return false;
    }
    for slot in ADDRESS_SPACE_ROOT_FRAMES.iter() {
        if slot.load(Ordering::Acquire) == physical_address {
            return true;
        }
    }
    for slot in ADDRESS_SPACE_ROOT_FRAMES.iter() {
        if slot
            .compare_exchange(0, physical_address, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return true;
        }
    }
    false
}

/// Removes one released address-space root frame from the registry.
///
/// A missing entry is intentionally ignored: cleanup paths may run after a
/// failed registration or after a conservative leak decision.
pub(super) fn unregister_address_space_root(physical_address: u64) {
    for slot in ADDRESS_SPACE_ROOT_FRAMES.iter() {
        let _ = slot.compare_exchange(physical_address, 0, Ordering::AcqRel, Ordering::Acquire);
    }
}

/// Returns whether this frame is a live kernel-created address-space root.
fn is_address_space_root_frame(physical_address: u64) -> bool {
    physical_address != 0
        && ADDRESS_SPACE_ROOT_FRAMES
            .iter()
            .any(|slot| slot.load(Ordering::Acquire) == physical_address)
}

fn reserve_table_frame_slot() -> Option<usize> {
    // SAFETY: this mutation is only used in the single-core, interrupts-disabled
    // bootstrap mapping path, before SMP is introduced.
    TABLE_FRAMES.lock().reserve_slot()
}

fn clear_reserved_table_frame_slot(index: usize) {
    // SAFETY: registry mutations are serialized by the single-core,
    // interrupts-disabled bootstrap precondition.
    if TABLE_FRAMES.lock().cancel_reservation(index).is_err() {
        panic!("page-table frame registry reservation invariant violated");
    }
}

fn install_table_frame(index: usize, frame: Frame) {
    // SAFETY: registry mutations are serialized by the single-core,
    // interrupts-disabled bootstrap precondition.
    if let Err((_error, _frame)) = TABLE_FRAMES.lock().install_reserved(index, frame) {
        panic!("page-table frame registry reservation invariant violated");
    }
}

fn registered_table_frame(physical_address: u64) -> bool {
    // SAFETY: the registry is read only under the same single-core bootstrap
    // contract as its mutations.
    TABLE_FRAMES.lock().contains(physical_address)
}

/// Returns whether a physical frame is registered as an already-published page table.
///
/// Active-root walkers may encounter these frames after a large-page demotion,
/// even though the firmware memory map still classifies the backing pages as Usable.
pub(super) fn registered_published_page_table_frame(physical_address: u64) -> bool {
    TABLE_FRAMES
        .lock()
        .contains_published_unowned(physical_address)
}

fn unpublished_table_frame(physical_address: u64) -> bool {
    // SAFETY: the registry is read only under the same single-core bootstrap
    // contract as its mutations.
    TABLE_FRAMES.lock().contains_unpublished(physical_address)
}

fn mark_table_frame_published(physical_address: u64) {
    // SAFETY: registry mutations are serialized by the single-core,
    // interrupts-disabled bootstrap precondition. Bootloader-owned frames are
    // not in this registry, so their expected lookup miss is intentionally ignored.
    let _ = TABLE_FRAMES.lock().mark_published(physical_address);
}

fn mark_table_frame_published_for_root(root_physical: u64, physical_address: u64, table_level: u8) {
    // SAFETY: registry mutations are serialized by the single-core,
    // interrupts-disabled bootstrap precondition. The caller has just published
    // this table at the indicated level in the root's private lower-half tree.
    match unsafe {
        TABLE_FRAMES
            .lock()
            .mark_published_for_root(root_physical, physical_address, table_level)
    } {
        Ok(()) => {}
        Err(FrameRegistryError::FrameNotFound) => {
            panic!("private lower-half page table is missing from the frame registry")
        }
        Err(
            FrameRegistryError::InvalidOwnerRoot
            | FrameRegistryError::PublishedOwnerMismatch
            | FrameRegistryError::NotPublished
            | FrameRegistryError::NotDetached
            | FrameRegistryError::InvalidReservation
            | FrameRegistryError::DuplicateFrameAddress
            | FrameRegistryError::PublishedFrame,
        ) => panic!("private page-table root ownership invariant violated"),
    }
}

fn release_registered_table_frame(physical_address: u64) {
    // SAFETY: registry mutations are serialized by the single-core,
    // interrupts-disabled bootstrap precondition.
    let frame = match TABLE_FRAMES.lock().take_unpublished(physical_address) {
        Ok(frame) => frame,
        Err(FrameRegistryError::PublishedFrame) => {
            panic!("attempted to release a published page-table frame")
        }
        Err(FrameRegistryError::FrameNotFound) => {
            panic!("attempted to release an unregistered page-table frame")
        }
        Err(
            FrameRegistryError::InvalidReservation
            | FrameRegistryError::DuplicateFrameAddress
            | FrameRegistryError::InvalidOwnerRoot
            | FrameRegistryError::PublishedOwnerMismatch
            | FrameRegistryError::NotPublished
            | FrameRegistryError::NotDetached,
        ) => {
            panic!("page-table frame registry state is invalid")
        }
    };
    if let Err((_error, _frame)) = super::memory::free_frame(frame) {
        panic!("physical allocator rejected an owned page-table frame");
    }
}

struct KernelPageTableEditor<'a> {
    regions: &'a [MemoryRegion],
    physical_memory_offset: u64,
    root_table_physical: u64,
    recursive_index: u16,
    target_virtual_address: u64,
    physical_address_bits: u8,
    #[cfg(feature = "test-wx-runtime-audit")]
    wx_test_executable_frame: Option<u64>,
}

impl<'a> KernelPageTableEditor<'a> {
    fn new(boot_info: &'a BootInfo, target_virtual_address: u64) -> Result<Self, PagingError> {
        let recursive_index = match boot_info.recursive_index {
            Optional::Some(index) if is_safe_recursive_mapping_index(index) => index,
            Optional::Some(_) => return Err(PagingError::InvalidRecursiveIndex),
            Optional::None => return Err(PagingError::RecursiveMappingUnavailable),
        };
        Self::new_with_recursive_index(boot_info, target_virtual_address, recursive_index)
    }

    /// Constructs an editor for the currently active root and its known recursive slot.
    ///
    /// This is used when a newly activated root uses a private recursive index
    /// rather than the original bootloader index. The supplied index is checked
    /// against the root's self-reference before any subsequent page-table walk.
    fn new_with_recursive_index(
        boot_info: &'a BootInfo,
        target_virtual_address: u64,
        recursive_index: u16,
    ) -> Result<Self, PagingError> {
        Self::new_with_recursive_index_mode(
            boot_info,
            target_virtual_address,
            recursive_index,
            true,
        )
    }

    /// Constructs an editor handle for a read-only audit without requiring R/W
    /// permission on the recursive mapping. The mutation constructor above keeps
    /// the stricter writable-alias invariant.
    fn new_for_readonly_audit(
        boot_info: &'a BootInfo,
        target_virtual_address: u64,
        recursive_index: u16,
    ) -> Result<Self, PagingError> {
        Self::new_with_recursive_index_mode(
            boot_info,
            target_virtual_address,
            recursive_index,
            false,
        )
    }

    fn new_with_recursive_index_mode(
        boot_info: &'a BootInfo,
        target_virtual_address: u64,
        recursive_index: u16,
        require_writable_recursive_mapping: bool,
    ) -> Result<Self, PagingError> {
        let flags: u64;
        // SAFETY: PUSHFQ reads the current flags register; no flags are changed.
        unsafe {
            asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
        }
        if flags & (1 << 9) != 0 {
            return Err(PagingError::InterruptsEnabled);
        }
        if !is_canonical_4level(target_virtual_address)
            || target_virtual_address & (PAGE_SIZE - 1) != 0
        {
            return Err(PagingError::MappingSmokeMismatch);
        }
        if !is_safe_recursive_mapping_index(recursive_index) {
            return Err(PagingError::InvalidRecursiveIndex);
        }
        let physical_memory_offset = match boot_info.physical_memory_offset {
            Optional::Some(offset) => offset,
            Optional::None => return Err(PagingError::PhysicalMemoryOffsetUnavailable),
        };
        let root_table_physical = active_root_table_physical();

        // The original boot root is bootloader-owned; a later kernel root is
        // allocator-owned and remains allocated while CR3 references it.
        let root_is_bootloader_owned =
            is_bootloader_owned_page(&boot_info.memory_regions, root_table_physical);
        let root_is_allocator_owned =
            super::memory::is_frame_allocated(root_table_physical).unwrap_or(false);
        // SAFETY: active_root_table_physical reads CR3. The page is not dereferenced
        // until its alignment, full-frame ownership, and recursive self-reference
        // have been checked below.
        if root_table_physical == 0
            || root_table_physical & (PAGE_SIZE - 1) != 0
            || (!root_is_bootloader_owned && !root_is_allocator_owned)
        {
            return Err(PagingError::InvalidRootTable);
        }

        // SAFETY: the maximum extended leaf and NX support were checked during
        // initialize_paging_controls; read the width from the same CPU.
        let physical_address_bits = (__cpuid(CPUID_PHYSICAL_ADDRESS_WIDTH).eax & 0xff) as u8;
        if !valid_physical_page(root_table_physical, physical_address_bits) {
            return Err(PagingError::InvalidRootTable);
        }
        let recursive_mapping_valid = if require_writable_recursive_mapping {
            // Mapping mutations require a writable recursive alias. Keep this
            // invariant unchanged for every existing editor call site.
            validate_editor_recursive_mapping_entry(
                recursive_index,
                root_table_physical,
                root_is_allocator_owned,
            )
        } else {
            // Auditing only reads page-table entries. Require a valid supervisor
            // self-reference and NX, but do not confuse R/W=0 with unreadability.
            validate_readonly_recursive_mapping_entry(recursive_index, root_table_physical)
        };
        if !recursive_mapping_valid {
            return Err(PagingError::InvalidRecursiveMapping);
        }

        let cr0: u64;
        unsafe {
            asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        }
        if cr0 & CR0_WP == 0 {
            return Err(PagingError::SupervisorWriteProtectionDisabled);
        }
        let mut efer_low: u32;
        let mut efer_high: u32;
        unsafe {
            asm!(
                "rdmsr",
                in("ecx") EFER_MSR,
                out("eax") efer_low,
                out("edx") efer_high,
                options(nomem, nostack, preserves_flags)
            );
        }
        if ((u64::from(efer_high) << 32) | u64::from(efer_low)) & EFER_NXE == 0 {
            return Err(PagingError::UnsupportedNx);
        }

        Ok(Self {
            regions: &boot_info.memory_regions,
            physical_memory_offset,
            root_table_physical,
            recursive_index,
            target_virtual_address,
            physical_address_bits,
            #[cfg(feature = "test-wx-runtime-audit")]
            wx_test_executable_frame: None,
        })
    }

    fn is_usable_frame(&self, physical_address: u64) -> bool {
        physical_page_is_in_allowed_region(physical_address, self.regions.len(), |index| {
            let region = self.regions[index];
            (
                region.start,
                region.end,
                matches!(region.kind, MemoryRegionKind::Usable),
            )
        })
    }

    fn is_table_frame(&self, physical_address: u64) -> bool {
        is_bootloader_owned_page(self.regions, physical_address)
            || registered_table_frame(physical_address)
            || (physical_address == self.root_table_physical
                && super::memory::is_frame_allocated(physical_address).unwrap_or(false))
    }

    fn offset_alias(&mut self, physical_address: u64) -> Option<*mut u8> {
        if !valid_physical_page(physical_address, self.physical_address_bits)
            || !self.is_usable_frame(physical_address)
        {
            return None;
        }
        let address = self.physical_memory_offset.checked_add(physical_address)?;
        let last_byte = address.checked_add(PAGE_SIZE - 1)?;
        if address & (PAGE_SIZE - 1) != 0
            || !is_canonical_4level(address)
            || !is_canonical_4level(last_byte)
        {
            return None;
        }
        // Prove that the physical-memory offset actually maps this complete
        // Usable frame to the expected physical page and permits supervisor
        // writes before zeroing an unpublished page-table frame.
        let translation = translate_with_editor(self, self.root_table_physical, address).ok()?;
        if translation.physical_address != physical_address
            || !translation.writable
            || translation.user_accessible
            || translation.executable
        {
            return None;
        }
        let pointer = usize::try_from(address).ok()? as *mut u8;
        Some(pointer)
    }

    fn reachable_table_physical(&self, wanted_level: u8) -> Option<u64> {
        if !(1..=4).contains(&wanted_level)
            || !valid_physical_page(self.root_table_physical, self.physical_address_bits)
            || !self.is_table_frame(self.root_table_physical)
        {
            return None;
        }

        // Check the recursive self-reference first. Its R/W bit is part of the
        // effective write permission for every recursive alias.
        let root_alias = recursive_table_page_virtual_address(
            self.recursive_index,
            self.target_virtual_address,
            4,
        )?;
        let recursive_entry_pointer =
            entry_pointer_from_page(root_alias, usize::from(self.recursive_index))?;
        // SAFETY: the bootloader contract supplied this recursive index, and
        // the root frame was validated as Bootloader-owned above.
        let recursive_entry = unsafe { ptr::read_volatile(recursive_entry_pointer) };
        if !recursive_entry_matches_root(recursive_entry, self.root_table_physical)
            || recursive_entry & WRITABLE == 0
        {
            return None;
        }

        let mut current_physical = self.root_table_physical;
        let mut visited = [0u64; 4];
        visited[0] = current_physical;
        for current_level in (wanted_level + 1..=4).rev() {
            let table_alias = recursive_table_page_virtual_address(
                self.recursive_index,
                self.target_virtual_address,
                current_level,
            )?;
            let index = virtual_index(self.target_virtual_address, current_level)?;
            let pointer = entry_pointer_from_page(table_alias, index)?;
            // SAFETY: every ancestor entry is read through the validated recursive
            // alias. Recursive and target-path write permissions are checked below.
            let entry = unsafe { ptr::read_volatile(pointer) };
            if entry & PRESENT == 0 || entry & WRITABLE == 0 || entry & LARGE_PAGE != 0 {
                return None;
            }
            let next_physical = entry & PHYSICAL_ADDRESS_MASK;
            if !valid_physical_page(next_physical, self.physical_address_bits)
                || !self.is_table_frame(next_physical)
                || visited[..(5 - current_level) as usize].contains(&next_physical)
            {
                return None;
            }
            visited[(4 - current_level) as usize + 1] = next_physical;
            current_physical = next_physical;
        }
        Some(current_physical)
    }

    /// Read-only variant of reachable_table_physical for the alias audit.
    ///
    /// It checks the same canonical path, present bits, frame addresses, table
    /// ownership, and cycle constraints but deliberately does not require R/W.
    /// x86 permits supervisor reads through read-only paging entries.
    fn reachable_table_physical_readonly(&self, wanted_level: u8) -> Option<u64> {
        if !(1..=4).contains(&wanted_level)
            || !valid_physical_page(self.root_table_physical, self.physical_address_bits)
            || !self.is_table_frame(self.root_table_physical)
        {
            return None;
        }

        let recursive_entry = read_recursive_mapping_entry(self.recursive_index)?;
        if !recursive_entry_matches_root(recursive_entry, self.root_table_physical)
            || recursive_entry & USER_ACCESSIBLE != 0
            || recursive_entry & NO_EXECUTE == 0
            || recursive_entry & PROTECTION_KEY_FIELD_MASK != 0
        {
            return None;
        }

        let mut current_physical = self.root_table_physical;
        let mut visited = [0u64; 4];
        visited[0] = current_physical;
        for current_level in (wanted_level + 1..=4).rev() {
            let table_alias = recursive_table_page_virtual_address(
                self.recursive_index,
                self.target_virtual_address,
                current_level,
            )?;
            let index = virtual_index(self.target_virtual_address, current_level)?;
            let pointer = entry_pointer_from_page(table_alias, index)?;
            // SAFETY: the recursive alias index and root frame were validated;
            // the target path is read only and each table page is checked below.
            let entry = unsafe { ptr::read_volatile(pointer) };
            if entry & PRESENT == 0
                || entry & LARGE_PAGE != 0
                || entry & PROTECTION_KEY_FIELD_MASK != 0
            {
                return None;
            }
            let next_physical = entry & PHYSICAL_ADDRESS_MASK;
            if !valid_physical_page(next_physical, self.physical_address_bits)
                || !self.is_table_frame(next_physical)
                || visited[..(5 - current_level) as usize].contains(&next_physical)
            {
                return None;
            }
            visited[(4 - current_level) as usize + 1] = next_physical;
            current_physical = next_physical;
        }
        Some(current_physical)
    }

    /// Performs a strong atomic update of one validated page-table entry.
    ///
    /// This RMW allows the caller to observe hardware Accessed/Dirty changes
    /// instead of racing them with a read-then-write sequence. It does not
    /// invalidate translations or make a multi-entry page-table transaction
    /// safe by itself. Callers must retain the editor's single-CPU,
    /// interrupts-disabled, PCID-disabled mutation preconditions.
    fn compare_exchange_entry(
        &mut self,
        table_physical: u64,
        index: usize,
        level: u8,
        expected: u64,
        replacement: u64,
    ) -> Option<Result<(), u64>> {
        let (pointer, reachable) = self.entry_pointer(table_physical, index, level)?;
        // SAFETY: entry_pointer validates a naturally aligned pointer to one
        // page-table entry. AtomicU64::compare_exchange compiles to an x86_64
        // locked compare-exchange, so hardware-updated A/D bits cause a failed
        // comparison instead of being silently overwritten by this RMW.
        let result = {
            let atomic_entry = unsafe { AtomicU64::from_ptr(pointer) };
            atomic_entry
                .compare_exchange(expected, replacement, Ordering::AcqRel, Ordering::Acquire)
                .map(|_| ())
        };
        if result.is_ok() && reachable {
            self.mark_reachable_table_frames();
        }
        Some(result)
    }

    /// Smoke-checks the atomic entry primitive without changing the entry.
    ///
    /// The retry policy is shared with host-testable logic. This verifies the
    /// concrete editor's CAS path, but does not prove large-page break-before-make
    /// ordering or TLB/page-walk quiescence.
    fn verify_atomic_entry_compare_exchange(
        &mut self,
        table_physical: u64,
        index: usize,
        level: u8,
    ) -> bool {
        let Some(initial) = self.read_entry(table_physical, index, level) else {
            return false;
        };
        compare_exchange_entry_with_ad_retry(
            initial,
            ATOMIC_ENTRY_CAS_MAX_ATTEMPTS,
            |expected| expected,
            |expected, replacement| {
                self.compare_exchange_entry(table_physical, index, level, expected, replacement)
                    .unwrap_or(Err(expected))
            },
        )
        .is_ok()
    }

    fn entry_pointer(
        &mut self,
        table_physical: u64,
        index: usize,
        level: u8,
    ) -> Option<(*mut u64, bool)> {
        if index >= 512
            || !(1..=4).contains(&level)
            || !valid_physical_page(table_physical, self.physical_address_bits)
        {
            return None;
        }
        if self.reachable_table_physical(level) == Some(table_physical) {
            let table_alias = recursive_table_page_virtual_address(
                self.recursive_index,
                self.target_virtual_address,
                level,
            )?;
            return Some((entry_pointer_from_page(table_alias, index)?, true));
        }

        // The offset path is permitted only for a newly allocated, unpublished
        // table frame retained by this editor's ownership registry.
        if !unpublished_table_frame(table_physical) {
            return None;
        }
        let page = self.offset_alias(table_physical)?;
        let address = (page as usize).checked_add(index.checked_mul(size_of::<u64>())?)?;
        let pointer = address as *mut u64;
        if pointer as usize & (size_of::<u64>() - 1) != 0 {
            return None;
        }
        Some((pointer, false))
    }

    /// Returns a pointer to the first entry in one verified reachable table.
    ///
    /// The W^X audit reads all 512 entries through this pointer. Validating the
    /// recursive path once per table avoids re-walking every ancestor for every
    /// entry, while the caller remains read-only and checks the index bound.
    fn audit_table_pointer(&self, table_physical: u64, level: u8) -> Option<*const u64> {
        if !(1..=4).contains(&level)
            || !valid_physical_page(table_physical, self.physical_address_bits)
            || self.reachable_table_physical_readonly(level) != Some(table_physical)
        {
            return None;
        }
        let table_alias = recursive_table_page_virtual_address(
            self.recursive_index,
            self.target_virtual_address,
            level,
        )?;
        Some(entry_pointer_from_page(table_alias, 0)?.cast_const())
    }

    /// Returns a validated read-only pointer to a table owned by the audit root.
    ///
    /// Active-root tables are reached only through the recursive alias. Inactive
    /// roots are accessed through the physical-memory offset only when the root
    /// is registered and allocated, or a private lower-half table has a matching
    /// root-and-level ownership record.
    fn audit_table_pointer_for_root(
        &mut self,
        audit_root_physical: u64,
        table_physical: u64,
        level: u8,
        virtual_prefix: u64,
    ) -> Option<*const u64> {
        if audit_root_physical == self.root_table_physical {
            return self.audit_table_pointer(table_physical, level);
        }
        if !(1..=4).contains(&level)
            || !valid_physical_page(table_physical, self.physical_address_bits)
        {
            return None;
        }

        if level == 4 {
            if table_physical != audit_root_physical
                || !is_address_space_root_frame(audit_root_physical)
                || !matches!(
                    super::memory::is_frame_allocated(audit_root_physical),
                    Ok(true)
                )
            {
                return None;
            }
        } else if virtual_prefix >= 0x0000_8000_0000_0000
            || TABLE_FRAMES
                .lock()
                .published_table_level_for_root(audit_root_physical, table_physical)
                != Some(level)
        {
            // This walker deliberately audits only the inactive root's private
            // lower half. Shared kernel-half tables are read through the active
            // recursive mapping after their PML4 entries were compared.
            return None;
        }

        let alias = self.offset_alias(table_physical)?;
        if alias as usize & (size_of::<u64>() - 1) != 0 {
            return None;
        }
        Some(alias.cast::<u64>().cast_const())
    }

    fn mark_reachable_table_frames(&self) {
        // The root publication makes each staged table reachable. Record all
        // allocator-owned frames on this virtual path, not just the first child.
        // The lower canonical half is private to this address-space root, so its
        // table frames must carry root ownership before inactive-root teardown
        // can safely distinguish them from shared kernel-half tables.
        for level in 1..=3 {
            if let Some(physical_address) = self.reachable_table_physical(level) {
                if self.target_virtual_address < USER_VIRTUAL_ADDRESS_LIMIT {
                    mark_table_frame_published_for_root(
                        self.root_table_physical,
                        physical_address,
                        level,
                    );
                } else {
                    mark_table_frame_published(physical_address);
                }
            }
        }
    }
}

#[cfg(feature = "test-wx-runtime-audit")]
impl KernelPageTableEditor<'_> {
    /// Temporarily allow one test-owned frame to receive an RX alias after its
    /// physical-offset alias has been proven RO+NX. Ordinary executable mappings
    /// remain denied by the PageTableEditor implementation.
    fn allow_controlled_wx_test_executable_frame(
        &mut self,
        physical_page: u64,
    ) -> Result<(), PagingError> {
        if physical_page == 0
            || physical_page & (PAGE_SIZE - 1) != 0
            || !self.is_usable_frame(physical_page)
            || !PageTableEditor::is_frame_allocated(self, physical_page)
            || PageTableEditor::is_page_table_or_reserved_frame(self, physical_page)
            || is_address_space_root_frame(physical_page)
        {
            return Err(PagingError::WxSiblingFrameUnavailable);
        }

        let direct_alias = self
            .physical_memory_offset
            .checked_add(physical_page)
            .filter(|address| is_canonical_4level(*address) && (*address & (PAGE_SIZE - 1)) == 0)
            .ok_or(PagingError::PhysicalMemoryOffsetUnavailable)?;
        let root_table_physical = self.root_table_physical;
        let direct_mapping = translate_with_editor(self, root_table_physical, direct_alias)
            .map_err(PagingError::Translation)?;
        if direct_mapping.physical_address != physical_page
            || direct_mapping.page_size != PAGE_SIZE
            || direct_mapping.writable
            || direct_mapping.user_accessible
            || direct_mapping.executable
        {
            return Err(PagingError::LargePageDemotionFailed);
        }

        self.wx_test_executable_frame = Some(physical_page);
        Ok(())
    }
}

impl PageTableEditor for KernelPageTableEditor<'_> {
    fn physical_address_bits(&self) -> u8 {
        self.physical_address_bits
    }

    fn is_page_table_or_reserved_frame(&self, physical_address: u64) -> bool {
        // Only allocator-eligible Usable frames may be mapped as ordinary data.
        // Bootloader-owned, unknown/reserved, registered page-table frames, and
        // every live address-space root must never be accepted as leaf targets.
        !self.is_usable_frame(physical_address)
            || self.is_table_frame(physical_address)
            || is_address_space_root_frame(physical_address)
    }

    fn is_frame_allocated(&self, physical_address: u64) -> bool {
        // map_supervisor_4k runs with maskable interrupts disabled under the current
        // single-CPU contract. If the allocator cannot be queried (for example,
        // because it is unavailable or busy), reject the mapping.
        super::memory::is_frame_allocated(physical_address).unwrap_or(false)
    }

    fn executable_mapping_allowed(&self, _physical_address: u64) -> bool {
        // Normal executable mappings remain fail-closed while arbitrary writable
        // aliases are not fully tracked and controlled.
        #[cfg(feature = "test-wx-runtime-audit")]
        if self.wx_test_executable_frame == Some(_physical_address) {
            // This single test-owned frame is admitted only after the test helper
            // has revalidated its physical-offset alias as RO+NX and 4 KiB.
            return true;
        }
        false
    }

    fn reserve_wx_alias(
        &mut self,
        root: u64,
        virtual_address: u64,
        physical_address: u64,
        permissions: PagePermissions,
    ) -> Result<(), PageTableMutationError> {
        if root != self.root_table_physical || root != active_root_table_physical() {
            return Err(PageTableMutationError::WxAliasRegistryFailure);
        }
        reserve_kernel_wx_alias(
            root,
            virtual_address,
            physical_address,
            permissions,
            self.physical_address_bits,
        )
    }

    fn commit_wx_alias(&mut self, root: u64, virtual_address: u64) {
        if root != self.root_table_physical || root != active_root_table_physical() {
            panic!("active W^X alias committed against an unexpected root");
        }
        commit_kernel_wx_alias(root, virtual_address, self.physical_address_bits);
    }

    fn begin_wx_alias_removal(
        &mut self,
        root: u64,
        virtual_address: u64,
        physical_address: u64,
        permissions: PagePermissions,
    ) -> Result<(), PageTableMutationError> {
        if root != self.root_table_physical || root != active_root_table_physical() {
            return Err(PageTableMutationError::WxAliasRegistryFailure);
        }
        begin_kernel_wx_alias_removal(
            root,
            virtual_address,
            physical_address,
            permissions,
            self.physical_address_bits,
        )
    }

    fn complete_wx_alias_removal(&mut self, root: u64, virtual_address: u64) {
        if root != self.root_table_physical || root != active_root_table_physical() {
            panic!("active W^X alias removal used against an unexpected root");
        }
        // The PTE has already been cleared; invalidate before releasing the alias.
        invalidate_local_tlb(virtual_address);
        complete_kernel_wx_alias_removal(root, virtual_address, self.physical_address_bits);
    }

    fn read_entry(&mut self, table_physical: u64, index: usize, level: u8) -> Option<u64> {
        let (pointer, _reachable) = self.entry_pointer(table_physical, index, level)?;
        // SAFETY: entry_pointer validated the alias and alignment. Reachable
        // tables have writable ancestors; unlinked tables are owned Usable frames
        // accessed through the checked physical-memory offset.
        Some(unsafe { ptr::read_volatile(pointer) })
    }

    fn write_entry(&mut self, table_physical: u64, index: usize, level: u8, value: u64) {
        let Some((pointer, reachable)) = self.entry_pointer(table_physical, index, level) else {
            super::interrupts::write_hex(b"PAGE-TABLE WRITE PREFLIGHT TABLE: ", table_physical);
            super::interrupts::write_hex(b"PAGE-TABLE WRITE PREFLIGHT INDEX: ", index as u64);
            super::interrupts::write_hex(b"PAGE-TABLE WRITE PREFLIGHT LEVEL: ", level as u64);
            super::interrupts::write_hex(
                b"PAGE-TABLE WRITE PREFLIGHT TARGET VA: ",
                self.target_virtual_address,
            );
            super::interrupts::write_hex(
                b"PAGE-TABLE WRITE PREFLIGHT UNPUBLISHED: ",
                u64::from(unpublished_table_frame(table_physical)),
            );
            super::interrupts::write_hex(
                b"PAGE-TABLE WRITE PREFLIGHT USABLE: ",
                u64::from(self.is_usable_frame(table_physical)),
            );
            super::interrupts::write_hex(
                b"PAGE-TABLE WRITE PREFLIGHT REACHABLE MATCH: ",
                u64::from(self.reachable_table_physical(level) == Some(table_physical)),
            );
            panic!("page-table write destination failed preflight");
        };
        // SAFETY: every existing destination is validated as writable during the
        // walk; newly allocated frames were validated and zeroed before allocation
        // returned. A fault here violates the editor contract and fail-stops.
        unsafe { ptr::write_volatile(pointer, value) };
        if reachable {
            self.mark_reachable_table_frames();
        }
    }

    fn allocate_table(&mut self) -> Option<u64> {
        // Reserve ownership metadata before taking a physical frame, so registry
        // exhaustion cannot consume or leak an allocator frame.
        let slot = reserve_table_frame_slot()?;
        let frame = match super::memory::allocate_frame() {
            Ok(frame) => frame,
            Err(_) => {
                clear_reserved_table_frame_slot(slot);
                return None;
            }
        };
        let physical_address = frame.physical_address();
        if !valid_physical_page(physical_address, self.physical_address_bits)
            || !self.is_usable_frame(physical_address)
        {
            clear_reserved_table_frame_slot(slot);
            if let Err((_error, _frame)) = super::memory::free_frame(frame) {
                panic!("physical allocator rejected an invalid table frame");
            }
            return None;
        }
        let Some(alias) = self.offset_alias(physical_address) else {
            clear_reserved_table_frame_slot(slot);
            if let Err((_error, _frame)) = super::memory::free_frame(frame) {
                panic!("physical allocator rejected an inaccessible table frame");
            }
            return None;
        };

        install_table_frame(slot, frame);
        // SAFETY: the full frame lies within one Usable region and its canonical,
        // aligned physical-memory-offset alias was checked. Clearing it before
        // publication gives the hardware an initialized page table.
        #[cfg(feature = "test-vm-transitions")]
        super::interrupts::write_hex(b"ONE OS VM TABLE FRAME ALLOCATED: ", physical_address);
        unsafe { ptr::write_bytes(alias, 0, PAGE_SIZE as usize) };
        #[cfg(feature = "test-vm-transitions")]
        {
            let entries = alias.cast::<u64>();
            for index in 0..((PAGE_SIZE as usize) / size_of::<u64>()) {
                // SAFETY: alias was validated to map this aligned, owned, unpublished
                // frame as supervisor-writable. The frame has not yet been published
                // through any parent entry, and the volatile read verifies each slot
                // after zeroing via the same checked physical-memory-offset alias.
                if unsafe { ptr::read_volatile(entries.add(index)) } != 0 {
                    super::serial_write(
                        b"ONE OS VM TEST FAILED: table frame not zero before publication\n",
                    );
                    release_registered_table_frame(physical_address);
                    return None;
                }
            }
            // Include the physical frame address so the QEMU validator can
            // pair every successful 512-entry verification with one allocation.
            // This is emitted before map_supervisor_4k can publish the parent entry.
            super::interrupts::write_hex(
                b"ONE OS VM TABLE PREPUBLICATION ZERO VERIFIED: ",
                physical_address,
            );
        }
        Some(physical_address)
    }

    fn free_table(&mut self, physical_address: u64) {
        release_registered_table_frame(physical_address);
    }
}

/// Page-table editor bound to one initialized, inactive address-space root.
///
/// Unlike `KernelPageTableEditor`, this editor accesses only
/// the supplied root and table frames that the ownership registry records as
/// private to that root (plus table frames staged by the current mapping call).
/// Every table access still passes through the active root's checked
/// physical-memory-offset alias.
///
/// The root must never be active while this editor is alive. A root that was
/// previously active is eligible only after `switch_address_space`
/// has switched away with PCID rejected and the required local/global TLB flush
/// completed. New roots have no cached translations. Consequently, the
/// root-aware invalidation hook below can prove that no target-root translation
/// remains rather than issuing an `INVLPG` against the wrong CR3.
struct KernelInactiveAddressSpaceEditor<'a> {
    boot_info: &'a BootInfo,
    regions: &'a [MemoryRegion],
    physical_memory_offset: u64,
    active_root_physical: u64,
    active_recursive_index: u16,
    target_root_physical: u64,
    physical_address_bits: u8,
    staged_frames: [Option<u64>; 3],
}

impl<'a> KernelInactiveAddressSpaceEditor<'a> {
    fn new(
        boot_info: &'a BootInfo,
        root: &AddressSpaceRoot,
        active_root: &ActiveAddressSpaceRoot,
    ) -> Result<Self, PagingError> {
        let flags: u64;
        // SAFETY: reading RFLAGS does not change interrupt state.
        unsafe {
            asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
        }
        if flags & (1 << 9) != 0 {
            return Err(PagingError::InterruptsEnabled);
        }

        let active_root_physical = active_root.physical_address();
        let target_root_physical = root.physical_address();
        if !root.is_initialized()
            || target_root_physical == active_root_physical
            || active_root_table_physical() != active_root_physical
            || root.physical_address_bits() != active_root.physical_address_bits()
        {
            return Err(PagingError::InactiveAddressSpaceInvalid);
        }

        let active_recursive_index = active_root.recursive_index();
        let target_recursive_index = root
            .recursive_index()
            .ok_or(PagingError::InactiveAddressSpaceInvalid)?;
        if !is_safe_recursive_mapping_index(active_recursive_index)
            || !(LOWER_HALF_PML4_ENTRIES..PML4_ENTRY_COUNT)
                .contains(&(target_recursive_index as usize))
        {
            return Err(PagingError::InvalidRecursiveIndex);
        }

        let cr4: u64;
        // SAFETY: CR4 is readable from the privileged kernel context.
        unsafe {
            asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        }
        if cr4 & CR4_LA57 != 0 {
            return Err(PagingError::UnsupportedFiveLevelPaging);
        }
        if cr4 & (1 << 17) != 0 {
            return Err(PagingError::PcidUnsupported);
        }

        let physical_address_bits = (__cpuid(CPUID_PHYSICAL_ADDRESS_WIDTH).eax & 0xff) as u8;
        if !(32..=52).contains(&physical_address_bits)
            || physical_address_bits != root.physical_address_bits()
            || physical_address_bits != active_root.physical_address_bits()
        {
            return Err(PagingError::InvalidPhysicalAddressWidth {
                bits: physical_address_bits,
            });
        }

        let physical_memory_offset = match boot_info.physical_memory_offset {
            Optional::Some(offset) => offset,
            Optional::None => return Err(PagingError::PhysicalMemoryOffsetUnavailable),
        };

        let editor = Self {
            boot_info,
            regions: &boot_info.memory_regions,
            physical_memory_offset,
            active_root_physical,
            active_recursive_index,
            target_root_physical,
            physical_address_bits,
            staged_frames: [None; 3],
        };

        let root_pointer = editor
            .table_pointer(target_root_physical, 4)
            .ok_or(PagingError::InactivePageTableUnavailable)?;
        // SAFETY: table_pointer validated the full target root frame as an
        // allocator-owned Usable frame and verified its exact writable,
        // supervisor-only, NX physical-memory-offset translation.
        let recursive_entry =
            unsafe { ptr::read_volatile(root_pointer.add(usize::from(target_recursive_index))) };
        if !recursive_entry_is_valid_kernel_root(recursive_entry, target_root_physical) {
            return Err(PagingError::InactiveAddressSpaceInvalid);
        }

        Ok(editor)
    }

    fn is_usable_frame(&self, physical_address: u64) -> bool {
        physical_page_is_in_allowed_region(physical_address, self.regions.len(), |index| {
            let region = self.regions[index];
            (
                region.start,
                region.end,
                matches!(region.kind, MemoryRegionKind::Usable),
            )
        })
    }

    fn is_staged_table(&self, physical_address: u64) -> bool {
        self.staged_frames.contains(&Some(physical_address))
    }

    fn remove_staged_table(&mut self, physical_address: u64) -> bool {
        if let Some(slot) = self
            .staged_frames
            .iter_mut()
            .find(|slot| **slot == Some(physical_address))
        {
            *slot = None;
            true
        } else {
            false
        }
    }

    fn track_staged_table(&mut self, physical_address: u64) -> bool {
        if let Some(slot) = self.staged_frames.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(physical_address);
            true
        } else {
            false
        }
    }

    fn is_private_table(&self, physical_address: u64, table_level: u8) -> bool {
        // SAFETY: registry reads and writes share the single-CPU,
        // interrupts-disabled mutation contract.
        TABLE_FRAMES
            .lock()
            .published_table_level_for_root(self.target_root_physical, physical_address)
            == Some(table_level)
    }

    /// Obtains a validated writable supervisor-only NX alias for one allocated
    /// physical frame. The active root's page tables are used to prove the alias
    /// resolves to the complete expected frame before a pointer is returned.
    fn active_offset_alias(&self, physical_address: u64) -> Option<*mut u8> {
        if !valid_physical_page(physical_address, self.physical_address_bits)
            || !self.is_usable_frame(physical_address)
            || !matches!(
                super::memory::is_frame_allocated(physical_address),
                Ok(true)
            )
        {
            return None;
        }

        let alias = self.physical_memory_offset.checked_add(physical_address)?;
        if alias & (PAGE_SIZE - 1) != 0 || !is_canonical_4level(alias) {
            return None;
        }

        let mut active_editor = KernelPageTableEditor::new_with_recursive_index(
            self.boot_info,
            alias,
            self.active_recursive_index,
        )
        .ok()?;
        active_editor.offset_alias(physical_address)
    }

    fn table_pointer(&self, table_physical: u64, table_level: u8) -> Option<*mut u64> {
        if !valid_physical_page(table_physical, self.physical_address_bits)
            || !self.is_usable_frame(table_physical)
            || !matches!(super::memory::is_frame_allocated(table_physical), Ok(true))
        {
            return None;
        }

        let table_is_target_root = table_physical == self.target_root_physical && table_level == 4;
        if !table_is_target_root
            && !self.is_private_table(table_physical, table_level)
            && !self.is_staged_table(table_physical)
        {
            return None;
        }

        let alias = self.active_offset_alias(table_physical)?;
        if alias as usize & (size_of::<u64>() - 1) != 0 {
            return None;
        }
        Some(alias.cast::<u64>())
    }

    fn publish_staged_subtree(&mut self, table_physical: u64, table_level: u8) {
        if !(1..=3).contains(&table_level) || !self.is_staged_table(table_physical) {
            panic!("attempted to publish an untracked private page-table frame");
        }

        // SAFETY: this subtree is being linked only beneath the target
        // root's private lower-half PML4 entry, and each child was allocated by
        // this editor, zeroed before publication, and reached through that tree.
        if unsafe {
            TABLE_FRAMES
                .lock()
                .mark_published_for_root(self.target_root_physical, table_physical, table_level)
                .is_err()
        } {
            panic!("private page-table root ownership invariant violated");
        }
        if !self.remove_staged_table(table_physical) {
            panic!("published page-table frame was not staged by this editor");
        }

        if table_level == 1 {
            return;
        }

        let table = self
            .table_pointer(table_physical, table_level)
            .unwrap_or_else(|| panic!("published private table is not accessible"));
        for index in 0..PML4_ENTRY_COUNT {
            // SAFETY: table_pointer validated this complete table frame.
            let entry = unsafe { ptr::read_volatile(table.add(index)) };
            if entry == 0 {
                continue;
            }
            if entry & PRESENT == 0
                || entry & LARGE_PAGE != 0
                || entry & PROTECTION_KEY_FIELD_MASK != 0
            {
                panic!("staged private page-table subtree is malformed");
            }
            let child = entry & PHYSICAL_ADDRESS_MASK;
            self.publish_staged_subtree(child, table_level - 1);
        }
    }

    fn validate_private_child(
        &self,
        physical_address: u64,
        expected_table_level: u8,
        visited: &[u64; TABLE_FRAME_CAPACITY],
        visited_count: usize,
    ) -> Result<(), PagingError> {
        if physical_address == 0
            || physical_address == self.target_root_physical
            || !valid_physical_page(physical_address, self.physical_address_bits)
            || !self.is_private_table(physical_address, expected_table_level)
        {
            return Err(PagingError::InactivePageTableOwnershipViolation);
        }
        if visited[..visited_count].contains(&physical_address) {
            return Err(PagingError::InactivePageTableMalformed);
        }
        if visited_count >= TABLE_FRAME_CAPACITY {
            return Err(PagingError::PrivatePageTableCapacityExceeded);
        }
        Ok(())
    }
}

impl PageTableEditor for KernelInactiveAddressSpaceEditor<'_> {
    fn physical_address_bits(&self) -> u8 {
        self.physical_address_bits
    }

    fn is_page_table_or_reserved_frame(&self, physical_address: u64) -> bool {
        !self.is_usable_frame(physical_address)
            || registered_table_frame(physical_address)
            || physical_address == self.active_root_physical
            || physical_address == self.target_root_physical
            || is_address_space_root_frame(physical_address)
    }

    fn is_frame_allocated(&self, physical_address: u64) -> bool {
        matches!(
            super::memory::is_frame_allocated(physical_address),
            Ok(true)
        )
    }

    fn executable_mapping_allowed(&self, _physical_address: u64) -> bool {
        // No alias-wide executable publication is implemented yet.
        false
    }

    fn reserve_wx_alias(
        &mut self,
        root: u64,
        virtual_address: u64,
        physical_address: u64,
        permissions: PagePermissions,
    ) -> Result<(), PageTableMutationError> {
        if root != self.target_root_physical
            || active_root_table_physical() != self.active_root_physical
            || root == self.active_root_physical
        {
            return Err(PageTableMutationError::WxAliasRegistryFailure);
        }
        reserve_kernel_wx_alias(
            root,
            virtual_address,
            physical_address,
            permissions,
            self.physical_address_bits,
        )
    }

    fn commit_wx_alias(&mut self, root: u64, virtual_address: u64) {
        if root != self.target_root_physical
            || active_root_table_physical() != self.active_root_physical
            || root == self.active_root_physical
        {
            panic!("inactive W^X alias committed against an unexpected root");
        }
        commit_kernel_wx_alias(root, virtual_address, self.physical_address_bits);
    }

    fn begin_wx_alias_removal(
        &mut self,
        root: u64,
        virtual_address: u64,
        physical_address: u64,
        permissions: PagePermissions,
    ) -> Result<(), PageTableMutationError> {
        if root != self.target_root_physical
            || active_root_table_physical() != self.active_root_physical
            || root == self.active_root_physical
        {
            return Err(PageTableMutationError::WxAliasRegistryFailure);
        }
        begin_kernel_wx_alias_removal(
            root,
            virtual_address,
            physical_address,
            permissions,
            self.physical_address_bits,
        )
    }

    fn complete_wx_alias_removal(&mut self, root: u64, virtual_address: u64) {
        if root != self.target_root_physical
            || active_root_table_physical() != self.active_root_physical
            || root == self.active_root_physical
        {
            panic!("inactive W^X alias removal used against an unexpected root");
        }
        // The target is inactive. PCID is disabled and address-space switching
        // flushes non-global translations before the inactive root can be reused.
        complete_kernel_wx_alias_removal(root, virtual_address, self.physical_address_bits);
    }

    fn read_entry(&mut self, table_physical: u64, index: usize, level: u8) -> Option<u64> {
        if index >= PML4_ENTRY_COUNT || !(1..=4).contains(&level) {
            return None;
        }
        let table = self.table_pointer(table_physical, level)?;
        // SAFETY: table_pointer validated ownership and the complete checked
        // supervisor-writable alias for this physical table frame.
        Some(unsafe { ptr::read_volatile(table.add(index)) })
    }

    fn write_entry(&mut self, table_physical: u64, index: usize, level: u8, value: u64) {
        if index >= PML4_ENTRY_COUNT || !(1..=4).contains(&level) {
            panic!("invalid inactive page-table write index or level");
        }
        let is_reachable_parent = (table_physical == self.target_root_physical && level == 4)
            || self.is_private_table(table_physical, level);
        let table = self
            .table_pointer(table_physical, level)
            .unwrap_or_else(|| panic!("inactive page-table write destination failed preflight"));
        // SAFETY: all existing paths were validated before mutation; staged
        // table frames are private, allocated, zeroed, and accessed through the
        // checked physical-memory offset.
        unsafe { ptr::write_volatile(table.add(index), value) };

        // map_4k stages missing child tables, fills their entries, and then
        // publishes one top-level parent. Only that final link transitions the
        // staged subtree into root-owned state.
        if is_reachable_parent && level > 1 && value & PRESENT != 0 {
            let child = value & PHYSICAL_ADDRESS_MASK;
            if self.is_staged_table(child) {
                self.publish_staged_subtree(child, level - 1);
            }
        }
    }

    fn allocate_table(&mut self) -> Option<u64> {
        let slot = reserve_table_frame_slot()?;
        let frame = match super::memory::allocate_frame() {
            Ok(frame) => frame,
            Err(_) => {
                clear_reserved_table_frame_slot(slot);
                return None;
            }
        };
        let physical_address = frame.physical_address();
        if !valid_physical_page(physical_address, self.physical_address_bits)
            || !self.is_usable_frame(physical_address)
        {
            clear_reserved_table_frame_slot(slot);
            if let Err((_error, _frame)) = super::memory::free_frame(frame) {
                panic!("physical allocator rejected an invalid inactive table frame");
            }
            return None;
        }
        install_table_frame(slot, frame);
        if !self.track_staged_table(physical_address) {
            release_registered_table_frame(physical_address);
            return None;
        }
        let Some(alias) = self.active_offset_alias(physical_address) else {
            self.remove_staged_table(physical_address);
            release_registered_table_frame(physical_address);
            return None;
        };
        // SAFETY: the exact complete frame is allocated, Usable, staged and
        // writable through its validated supervisor-only NX offset alias.
        unsafe { ptr::write_bytes(alias, 0, PAGE_SIZE as usize) };
        Some(physical_address)
    }

    fn free_table(&mut self, physical_address: u64) {
        if !self.remove_staged_table(physical_address) {
            panic!("attempted to roll back a page-table frame not staged by this editor");
        }
        release_registered_table_frame(physical_address);
    }
}

/// Active-root adapter that binds the host-testable large-page transaction
/// to the kernel editor's checked recursive aliases, frame registry, atomic entry
/// update, and validated local all-TLB flush.
struct KernelLargePageDemotionEditor<'editor, 'boot> {
    editor: &'editor mut KernelPageTableEditor<'boot>,
    root_table_physical: u64,
    parent_table_physical: u64,
    parent_index: usize,
    source_level: u8,
    virtual_base: u64,
    allocated_table: Option<u64>,
    publication_reserved: bool,
    parent_pointer_published: bool,
    committed: bool,
}

impl<'editor, 'boot> KernelLargePageDemotionEditor<'editor, 'boot> {
    fn new(
        editor: &'editor mut KernelPageTableEditor<'boot>,
        parent_table_physical: u64,
        parent_index: usize,
        source_level: u8,
        virtual_base: u64,
    ) -> Result<Self, PagingError> {
        let root_table_physical = editor.root_table_physical;
        if root_table_physical != active_root_table_physical()
            || virtual_base < 0xffff_8000_0000_0000
            || !(2..=3).contains(&source_level)
            || parent_index >= PML4_ENTRY_COUNT
            || editor.reachable_table_physical(source_level) != Some(parent_table_physical)
            || virtual_base & ((1u64 << (12 + 9 * (source_level - 1))) - 1) != 0
        {
            return Err(PagingError::LargePageDemotionFailed);
        }
        Ok(Self {
            editor,
            root_table_physical,
            parent_table_physical,
            parent_index,
            source_level,
            virtual_base,
            allocated_table: None,
            publication_reserved: false,
            parent_pointer_published: false,
            committed: false,
        })
    }

    fn expected_range_length(&self) -> u64 {
        1u64 << (12 + 9 * (self.source_level - 1))
    }
}

impl LargePageDemotionEditor for KernelLargePageDemotionEditor<'_, '_> {
    fn physical_address_bits(&self) -> u8 {
        self.editor.physical_address_bits
    }

    fn read_entry(&mut self, table_physical: u64, index: usize, level: u8) -> Option<u64> {
        PageTableEditor::read_entry(self.editor, table_physical, index, level)
    }

    fn write_entry(&mut self, table_physical: u64, index: usize, level: u8, value: u64) {
        let is_final_parent_publication = table_physical == self.parent_table_physical
            && index == self.parent_index
            && level == self.source_level
            && value & PRESENT != 0
            && value & LARGE_PAGE == 0;
        if is_final_parent_publication {
            let child_table_physical = value & PHYSICAL_ADDRESS_MASK;
            if !self.publication_reserved
                || self.parent_pointer_published
                || self.allocated_table != Some(child_table_physical)
                || self.committed
            {
                panic!("large-page demotion parent publication violated its reservation");
            }
            let (pointer, reachable) = self
                .editor
                .entry_pointer(table_physical, index, level)
                .unwrap_or_else(|| panic!("large-page demotion parent became inaccessible"));
            if !reachable {
                panic!("large-page demotion parent was not reachable before publication");
            }
            // SAFETY: the transaction validated this parent entry before clearing
            // Present. It is now non-present, the full range has been flushed, and
            // the staged child table is fully initialized and still unpublished.
            // Bypass the generic write hook so ownership is committed only after
            // the transaction has actually installed this pointer.
            unsafe { ptr::write_volatile(pointer, value) };
            self.parent_pointer_published = true;
            return;
        }

        PageTableEditor::write_entry(self.editor, table_physical, index, level, value);
    }

    fn compare_exchange_entry(
        &mut self,
        table_physical: u64,
        index: usize,
        level: u8,
        expected: u64,
        replacement: u64,
    ) -> Result<(), u64> {
        self.editor
            .compare_exchange_entry(table_physical, index, level, expected, replacement)
            .unwrap_or(Err(expected))
    }

    fn allocate_table(&mut self) -> Option<u64> {
        if self.allocated_table.is_some() || self.committed {
            return None;
        }
        let child_table_physical = PageTableEditor::allocate_table(self.editor)?;
        self.allocated_table = Some(child_table_physical);
        Some(child_table_physical)
    }

    fn reserve_table_publication(
        &mut self,
        root_table_physical: u64,
        child_table_physical: u64,
        child_level: u8,
    ) -> bool {
        if root_table_physical != self.root_table_physical
            || root_table_physical != active_root_table_physical()
            || self.allocated_table != Some(child_table_physical)
            || child_level + 1 != self.source_level
            || self.publication_reserved
            || self.parent_pointer_published
            || self.committed
            || !unpublished_table_frame(child_table_physical)
            || self.editor.reachable_table_physical(self.source_level)
                != Some(self.parent_table_physical)
        {
            return false;
        }
        // allocate_table has already reserved and installed the owned Frame token
        // in TABLE_FRAMES before returning the zeroed frame. This reservation pins
        // that exact unpublished token to this parent/level transaction.
        self.publication_reserved = true;
        true
    }

    fn commit_table_publication(
        &mut self,
        root_table_physical: u64,
        child_table_physical: u64,
        child_level: u8,
    ) {
        if root_table_physical != self.root_table_physical
            || root_table_physical != active_root_table_physical()
            || self.allocated_table != Some(child_table_physical)
            || child_level + 1 != self.source_level
            || !self.publication_reserved
            || !self.parent_pointer_published
            || self.committed
            || !unpublished_table_frame(child_table_physical)
        {
            panic!("large-page demotion ownership commit violated its reservation");
        }

        if TABLE_FRAMES
            .lock()
            .mark_published(child_table_physical)
            .is_err()
        {
            panic!("large-page demotion could not commit page-table frame ownership");
        }
        self.publication_reserved = false;
        self.committed = true;
        // Reconcile all now-reachable tables after the child pointer is published.
        // This includes the new child level and remains idempotent with the explicit
        // registration above.
        self.editor.mark_reachable_table_frames();
    }

    fn release_unpublished_table(&mut self, child_table_physical: u64) {
        if self.allocated_table != Some(child_table_physical)
            || self.committed
            || self.parent_pointer_published
            || !unpublished_table_frame(child_table_physical)
        {
            panic!("large-page demotion attempted to release a foreign or published frame");
        }
        PageTableEditor::free_table(self.editor, child_table_physical);
        self.allocated_table = None;
        self.publication_reserved = false;
    }

    fn invalidate_local_range(&mut self, virtual_start: u64, length: u64) {
        if self.root_table_physical != active_root_table_physical()
            || self.editor.root_table_physical != self.root_table_physical
            || virtual_start != self.virtual_base
            || length != self.expected_range_length()
            || virtual_start & (length - 1) != 0
            || !is_canonical_4level(virtual_start)
            || !is_canonical_4level(virtual_start.saturating_add(length - 1))
        {
            panic!("large-page demotion requested an invalid TLB invalidation range");
        }
        // This validated helper disables PGE, reloads the same active CR3 with
        // PCID rejected, then restores CR4. Failure after Present was cleared is
        // an invariant violation, so fail-stop rather than return with ambiguity.
        if super::address_space::switch_address_space_flush_local_tlb(self.root_table_physical)
            .is_err()
        {
            panic!("large-page demotion could not flush the complete local TLB range");
        }
    }
}

/// Demotes one large leaf covering `virtual_address`, if its current walk
/// encounters a 1 GiB or 2 MiB mapping. All table access remains rooted in the
/// active editor and is validated before the transaction mutates a parent entry.
fn demote_large_page_for_address(
    boot_info: &BootInfo,
    virtual_address: u64,
) -> Result<Option<LargePageDemotionReceipt>, PagingError> {
    if !is_canonical_4level(virtual_address) || virtual_address & (PAGE_SIZE - 1) != 0 {
        return Err(PagingError::LargePageDemotionFailed);
    }
    let mut editor = KernelPageTableEditor::new(boot_info, virtual_address)?;
    let root_table_physical = editor.root_table_physical;
    if root_table_physical != active_root_table_physical() {
        return Err(PagingError::LargePageDemotionFailed);
    }

    let mut table_physical = root_table_physical;
    for table_level in (1..=4).rev() {
        let index = virtual_index(virtual_address, table_level)
            .ok_or(PagingError::LargePageDemotionFailed)?;
        let entry = PageTableEditor::read_entry(&mut editor, table_physical, index, table_level)
            .ok_or(PagingError::LargePageDemotionFailed)?;
        if entry & PRESENT == 0 || (entry & PROTECTION_KEY_FIELD_MASK != 0 && table_level > 1) {
            return Err(PagingError::LargePageDemotionFailed);
        }
        if table_level == 4 && entry & LARGE_PAGE != 0 {
            return Err(PagingError::LargePageDemotionFailed);
        }
        if (table_level == 2 || table_level == 3) && entry & LARGE_PAGE != 0 {
            let page_size = 1u64 << (12 + 9 * (table_level - 1));
            let virtual_base = virtual_address & !(page_size - 1);
            let mut transaction_editor = KernelLargePageDemotionEditor::new(
                &mut editor,
                table_physical,
                index,
                table_level,
                virtual_base,
            )?;
            let receipt = demote_large_page(
                &mut transaction_editor,
                root_table_physical,
                table_physical,
                table_level,
                index,
                virtual_base,
            )
            .map_err(|_| PagingError::LargePageDemotionFailed)?;
            return Ok(Some(receipt));
        }
        if table_level == 1 {
            return Ok(None);
        }
        if !valid_physical_page(entry & PHYSICAL_ADDRESS_MASK, editor.physical_address_bits) {
            return Err(PagingError::LargePageDemotionFailed);
        }
        table_physical = entry & PHYSICAL_ADDRESS_MASK;
    }
    Err(PagingError::LargePageDemotionFailed)
}

impl UserAddressSpaceEditor for KernelInactiveAddressSpaceEditor<'_> {
    fn invalidate_translation(&mut self, root_table_physical: u64, virtual_address: u64) {
        if root_table_physical != self.target_root_physical
            || active_root_table_physical() != self.active_root_physical
            || self.active_root_physical == self.target_root_physical
            || virtual_address >= USER_VIRTUAL_ADDRESS_LIMIT
            || virtual_address & (PAGE_SIZE - 1) != 0
        {
            panic!("inactive-root TLB invalidation precondition was violated");
        }

        // The target root is provably inactive. A never-activated root has no
        // cached translations; a formerly active root can become AddressSpaceRoot
        // only after switch_address_space completed the CR4.PGE-clear / CR3-write
        // / CR4-restore sequence with PCID disabled. INVLPG under active_root would
        // flush the wrong address space and is intentionally not treated as proof.
    }
}

fn preflight_private_user_tree<const CAPACITY: usize>(
    root_physical: u64,
    registry: &UserPageMappingRegistry<ZeroedFrame, CAPACITY>,
    editor: &mut KernelInactiveAddressSpaceEditor<'_>,
) -> Result<(), PagingError> {
    if registry.root_physical_address() != root_physical {
        return Err(PagingError::InactivePageTableOwnershipViolation);
    }
    if registry.has_reserved_mappings() {
        return Err(PagingError::InactivePageTableMalformed);
    }

    let mut visited = [0u64; TABLE_FRAME_CAPACITY];
    let mut visited_count = 0usize;
    for pml4_index in 0..LOWER_HALF_PML4_ENTRIES {
        let entry = editor
            .read_entry(root_physical, pml4_index, 4)
            .ok_or(PagingError::InactivePageTableUnavailable)?;
        if entry == 0 {
            continue;
        }
        if entry & PRESENT == 0
            || entry & LARGE_PAGE != 0
            || entry & PROTECTION_KEY_FIELD_MASK != 0
            || entry & WRITABLE == 0
            || entry & USER_ACCESSIBLE == 0
        {
            return Err(PagingError::InactivePageTableMalformed);
        }
        let pdpt_physical = entry & PHYSICAL_ADDRESS_MASK;
        editor.validate_private_child(pdpt_physical, 3, &visited, visited_count)?;
        visited[visited_count] = pdpt_physical;
        visited_count += 1;
        preflight_private_pdpt(
            root_physical,
            pdpt_physical,
            (pml4_index as u64) << 39,
            registry,
            editor,
            &mut visited,
            &mut visited_count,
        )?;
    }

    // Walk ownership metadata in the opposite direction too: every published
    // non-detached table owned by this root must be reachable from the root.
    // Detached tokens are the explicit exception: a previous allocator-release
    // failure leaves those frames in the root-scoped retry list.
    let mut owned_table_ordinal = 0usize;
    loop {
        let owned_table = TABLE_FRAMES
            .lock()
            .root_owned_table_at(root_physical, owned_table_ordinal);
        let Some((table_physical, table_level, published, detached)) = owned_table else {
            break;
        };
        owned_table_ordinal += 1;

        if !published || table_level.is_none() {
            return Err(PagingError::InactivePageTableOwnershipViolation);
        }
        if !detached && !visited[..visited_count].contains(&table_physical) {
            return Err(PagingError::InactivePageTableOwnershipViolation);
        }
    }

    // Walk the mapping registry in the opposite direction as well: every token
    // retained for a mapped VA must still have a present PTE that resolves to
    // its exact physical frame. This catches deleted/missing PTEs that a tree-only
    // walk cannot see.
    for slot_index in 0..CAPACITY {
        let Some((virtual_address, expected_physical)) = registry.mapped_entry_at(slot_index)
        else {
            continue;
        };
        if virtual_address == 0
            || virtual_address >= USER_VIRTUAL_ADDRESS_LIMIT
            || virtual_address & (PAGE_SIZE - 1) != 0
        {
            return Err(PagingError::InactivePageTableMalformed);
        }

        let mut level = 4u8;
        let translation =
            translate_4level(virtual_address, root_physical, |table_physical, index| {
                let current_level = level;
                level = level.saturating_sub(1);
                editor.read_entry(table_physical, index, current_level)
            })
            .map_err(|_| PagingError::InactivePageTableMalformed)?;
        if translation.page_size != PAGE_SIZE || translation.physical_address != expected_physical {
            return Err(PagingError::InactivePageTableOwnershipViolation);
        }
        if !translation.writable || !translation.user_accessible || translation.executable {
            return Err(PagingError::InactivePageTableMalformed);
        }
    }

    Ok(())
}

fn preflight_private_pdpt<const CAPACITY: usize>(
    root_physical: u64,
    pdpt_physical: u64,
    virtual_prefix: u64,
    registry: &UserPageMappingRegistry<ZeroedFrame, CAPACITY>,
    editor: &mut KernelInactiveAddressSpaceEditor<'_>,
    visited: &mut [u64; TABLE_FRAME_CAPACITY],
    visited_count: &mut usize,
) -> Result<(), PagingError> {
    for pdpt_index in 0..PML4_ENTRY_COUNT {
        let entry = editor
            .read_entry(pdpt_physical, pdpt_index, 3)
            .ok_or(PagingError::InactivePageTableUnavailable)?;
        if entry == 0 {
            continue;
        }
        if entry & PRESENT == 0
            || entry & LARGE_PAGE != 0
            || entry & PROTECTION_KEY_FIELD_MASK != 0
            || entry & WRITABLE == 0
            || entry & USER_ACCESSIBLE == 0
        {
            return Err(PagingError::InactivePageTableMalformed);
        }
        let pd_physical = entry & PHYSICAL_ADDRESS_MASK;
        editor.validate_private_child(pd_physical, 2, visited, *visited_count)?;
        visited[*visited_count] = pd_physical;
        *visited_count += 1;
        preflight_private_pd(
            root_physical,
            pd_physical,
            virtual_prefix | ((pdpt_index as u64) << 30),
            registry,
            editor,
            visited,
            visited_count,
        )?;
    }
    Ok(())
}

fn preflight_private_pd<const CAPACITY: usize>(
    root_physical: u64,
    pd_physical: u64,
    virtual_prefix: u64,
    registry: &UserPageMappingRegistry<ZeroedFrame, CAPACITY>,
    editor: &mut KernelInactiveAddressSpaceEditor<'_>,
    visited: &mut [u64; TABLE_FRAME_CAPACITY],
    visited_count: &mut usize,
) -> Result<(), PagingError> {
    for pd_index in 0..PML4_ENTRY_COUNT {
        let entry = editor
            .read_entry(pd_physical, pd_index, 2)
            .ok_or(PagingError::InactivePageTableUnavailable)?;
        if entry == 0 {
            continue;
        }
        if entry & PRESENT == 0
            || entry & LARGE_PAGE != 0
            || entry & PROTECTION_KEY_FIELD_MASK != 0
            || entry & WRITABLE == 0
            || entry & USER_ACCESSIBLE == 0
        {
            return Err(PagingError::InactivePageTableMalformed);
        }
        let pt_physical = entry & PHYSICAL_ADDRESS_MASK;
        editor.validate_private_child(pt_physical, 1, visited, *visited_count)?;
        visited[*visited_count] = pt_physical;
        *visited_count += 1;
        preflight_private_pt(
            root_physical,
            pt_physical,
            virtual_prefix | ((pd_index as u64) << 21),
            registry,
            editor,
        )?;
    }
    Ok(())
}

fn preflight_private_pt<const CAPACITY: usize>(
    root_physical: u64,
    pt_physical: u64,
    virtual_prefix: u64,
    registry: &UserPageMappingRegistry<ZeroedFrame, CAPACITY>,
    editor: &mut KernelInactiveAddressSpaceEditor<'_>,
) -> Result<(), PagingError> {
    for pt_index in 0..PML4_ENTRY_COUNT {
        let entry = editor
            .read_entry(pt_physical, pt_index, 1)
            .ok_or(PagingError::InactivePageTableUnavailable)?;
        if entry == 0 {
            continue;
        }
        if entry & PRESENT == 0
            || entry & WRITABLE == 0
            || entry & USER_ACCESSIBLE == 0
            || entry & PROTECTION_KEY_FIELD_MASK != 0
        {
            return Err(PagingError::InactivePageTableMalformed);
        }
        let leaf_physical = entry & PHYSICAL_ADDRESS_MASK;
        if !valid_physical_page(leaf_physical, editor.physical_address_bits())
            || !editor.is_frame_allocated(leaf_physical)
            || editor.is_page_table_or_reserved_frame(leaf_physical)
        {
            return Err(PagingError::InactivePageTableOwnershipViolation);
        }

        let virtual_address = virtual_prefix | ((pt_index as u64) << 12);
        if virtual_address == 0 || virtual_address >= USER_VIRTUAL_ADDRESS_LIMIT {
            return Err(PagingError::InactivePageTableMalformed);
        }
        let expected_physical = registry
            .mapped_physical_address(virtual_address)
            .ok_or(PagingError::UnregisteredUserPage)?;
        if leaf_physical != expected_physical
            || leaf_physical == root_physical
            || leaf_physical == editor.active_root_physical
            || leaf_physical == editor.target_root_physical
        {
            return Err(PagingError::InactivePageTableOwnershipViolation);
        }

        let mut level = 4u8;
        let translation =
            translate_4level(virtual_address, root_physical, |table_physical, index| {
                let current_level = level;
                level = level.saturating_sub(1);
                editor.read_entry(table_physical, index, current_level)
            })
            .map_err(PagingError::Translation)?;
        if translation.page_size != PAGE_SIZE || translation.physical_address != expected_physical {
            return Err(PagingError::InactivePageTableOwnershipViolation);
        }
        if !translation.writable || !translation.user_accessible || translation.executable {
            return Err(PagingError::InactivePageTableMalformed);
        }
    }
    Ok(())
}

fn verify_private_table_empty(
    table_physical: u64,
    table_level: u8,
    editor: &mut KernelInactiveAddressSpaceEditor<'_>,
) -> Result<(), PagingError> {
    for index in 0..PML4_ENTRY_COUNT {
        let entry = editor
            .read_entry(table_physical, index, table_level)
            .ok_or(PagingError::InactivePageTableUnavailable)?;
        if entry != 0 {
            return Err(PagingError::InactivePageTableMalformed);
        }
    }
    Ok(())
}

fn release_pending_detached_private_table<E>(
    table_physical: u64,
    table_level: u8,
    editor: &mut KernelInactiveAddressSpaceEditor<'_>,
    release_table_frame: &mut impl FnMut(Frame) -> Result<(), (E, Frame)>,
) -> Result<(), PagingError> {
    // A previously attempted release may have left this frame detached and
    // registry-owned. It is no longer accepted by table_pointer(), so validate
    // its exact physical-memory-offset alias directly before retrying release.
    let alias = editor
        .active_offset_alias(table_physical)
        .ok_or(PagingError::InactivePageTableUnavailable)?;
    let entries = alias.cast::<u64>();
    for index in 0..PML4_ENTRY_COUNT {
        // SAFETY: active_offset_alias validates a writable alias to the entire
        // allocated 4 KiB frame. Every word must remain zero while detached.
        if unsafe { ptr::read_volatile(entries.add(index)) } != 0 {
            return Err(PagingError::PageTableFrameReleaseFailed);
        }
    }

    // SAFETY: the frame was marked detached only after its parent entry was
    // cleared, the table was emptied, and the inactive-root/TLB contract held.
    // The registry transaction restores the ownership record if free_frame
    // returns the token on failure, so a later teardown can retry it.
    match unsafe {
        TABLE_FRAMES.lock().release_published_for_root_with(
            editor.target_root_physical,
            table_physical,
            table_level,
            release_table_frame,
        )
    } {
        Ok(()) => Ok(()),
        Err(PublishedFrameReleaseError::Registry(_))
        | Err(PublishedFrameReleaseError::Release(_)) => {
            Err(PagingError::PageTableFrameReleaseFailed)
        }
        Err(PublishedFrameReleaseError::Restore { error, token }) => {
            // Restoration failure is an invariant violation. The Frame token
            // has no Drop-based allocator behavior, so leaving this branch only
            // halts the kernel; it cannot make the still-allocated frame reusable.
            let _stranded_frame_physical = token.physical_address();
            panic!(
                "failed to restore detached page-table ownership after free failure: {:?}",
                error
            );
        }
    }
}

fn release_detached_private_table<E>(
    table_physical: u64,
    table_level: u8,
    editor: &mut KernelInactiveAddressSpaceEditor<'_>,
    release_table_frame: &mut impl FnMut(Frame) -> Result<(), (E, Frame)>,
) -> Result<(), PagingError> {
    let pointer = editor
        .table_pointer(table_physical, table_level)
        .ok_or(PagingError::InactivePageTableUnavailable)?;
    verify_private_table_empty(table_physical, table_level, editor)?;

    // The parent entry was cleared before this function was entered; the table
    // is empty and the target root is inactive under the validated TLB contract.
    // SAFETY: table_pointer proves this is a writable alias to the exact,
    // exclusively owned, root-private table frame. No parent/root can reach it.
    unsafe { ptr::write_bytes(pointer.cast::<u8>(), 0, PAGE_SIZE as usize) };
    for index in 0..PML4_ENTRY_COUNT {
        // SAFETY: pointer still names the complete detached 4 KiB table frame.
        if unsafe { ptr::read_volatile(pointer.add(index)) } != 0 {
            return Err(PagingError::PageTableFrameReleaseFailed);
        }
    }

    // SAFETY: the parent entry is already clear, the table is empty, and the
    // target root is inactive with the required translation flush completed.
    unsafe {
        TABLE_FRAMES.lock().mark_published_table_detached_for_root(
            editor.target_root_physical,
            table_physical,
            table_level,
        )
    }
    .map_err(|_| PagingError::PageTableFrameReleaseFailed)?;

    release_pending_detached_private_table(table_physical, table_level, editor, release_table_frame)
}

fn reclaim_pending_detached_private_tables<E>(
    root_physical: u64,
    editor: &mut KernelInactiveAddressSpaceEditor<'_>,
    release_table_frame: &mut impl FnMut(Frame) -> Result<(), (E, Frame)>,
) -> Result<(), PagingError> {
    loop {
        // A release failure restores the token as detached. On a subsequent
        // teardown attempt there is no parent entry to rediscover it, so consume
        // this root-scoped pending list before deciding the root is reclaimable.
        let pending = TABLE_FRAMES
            .lock()
            .detached_table_for_root(root_physical, 0);
        let Some((physical_address, table_level)) = pending else {
            return Ok(());
        };
        release_pending_detached_private_table(
            physical_address,
            table_level,
            editor,
            release_table_frame,
        )?;
    }
}

fn reclaim_private_pd<E>(
    pd_physical: u64,
    editor: &mut KernelInactiveAddressSpaceEditor<'_>,
    release_table_frame: &mut impl FnMut(Frame) -> Result<(), (E, Frame)>,
) -> Result<(), PagingError> {
    for pd_index in 0..PML4_ENTRY_COUNT {
        let entry = editor
            .read_entry(pd_physical, pd_index, 2)
            .ok_or(PagingError::InactivePageTableUnavailable)?;
        if entry == 0 {
            continue;
        }
        if entry & PRESENT == 0 || entry & LARGE_PAGE != 0 || entry & PROTECTION_KEY_FIELD_MASK != 0
        {
            return Err(PagingError::InactivePageTableMalformed);
        }
        let pt_physical = entry & PHYSICAL_ADDRESS_MASK;
        if !editor.is_private_table(pt_physical, 1) {
            return Err(PagingError::InactivePageTableOwnershipViolation);
        }
        verify_private_table_empty(pt_physical, 1, editor)?;
        editor.write_entry(pd_physical, pd_index, 2, 0);
        release_detached_private_table(pt_physical, 1, editor, release_table_frame)?;
    }
    verify_private_table_empty(pd_physical, 2, editor)
}

fn reclaim_private_pdpt<E>(
    pdpt_physical: u64,
    editor: &mut KernelInactiveAddressSpaceEditor<'_>,
    release_table_frame: &mut impl FnMut(Frame) -> Result<(), (E, Frame)>,
) -> Result<(), PagingError> {
    for pdpt_index in 0..PML4_ENTRY_COUNT {
        let entry = editor
            .read_entry(pdpt_physical, pdpt_index, 3)
            .ok_or(PagingError::InactivePageTableUnavailable)?;
        if entry == 0 {
            continue;
        }
        if entry & PRESENT == 0 || entry & LARGE_PAGE != 0 || entry & PROTECTION_KEY_FIELD_MASK != 0
        {
            return Err(PagingError::InactivePageTableMalformed);
        }
        let pd_physical = entry & PHYSICAL_ADDRESS_MASK;
        if !editor.is_private_table(pd_physical, 2) {
            return Err(PagingError::InactivePageTableOwnershipViolation);
        }
        reclaim_private_pd(pd_physical, editor, release_table_frame)?;
        editor.write_entry(pdpt_physical, pdpt_index, 3, 0);
        release_detached_private_table(pd_physical, 2, editor, release_table_frame)?;
    }
    verify_private_table_empty(pdpt_physical, 3, editor)
}

fn reclaim_private_user_tables<E>(
    root_physical: u64,
    editor: &mut KernelInactiveAddressSpaceEditor<'_>,
    release_table_frame: &mut impl FnMut(Frame) -> Result<(), (E, Frame)>,
) -> Result<(), PagingError> {
    for pml4_index in 0..LOWER_HALF_PML4_ENTRIES {
        let entry = editor
            .read_entry(root_physical, pml4_index, 4)
            .ok_or(PagingError::InactivePageTableUnavailable)?;
        if entry == 0 {
            continue;
        }
        if entry & PRESENT == 0 || entry & LARGE_PAGE != 0 || entry & PROTECTION_KEY_FIELD_MASK != 0
        {
            return Err(PagingError::InactivePageTableMalformed);
        }
        let pdpt_physical = entry & PHYSICAL_ADDRESS_MASK;
        if !editor.is_private_table(pdpt_physical, 3) {
            return Err(PagingError::InactivePageTableOwnershipViolation);
        }
        reclaim_private_pdpt(pdpt_physical, editor, release_table_frame)?;
        editor.write_entry(root_physical, pml4_index, 4, 0);
        release_detached_private_table(pdpt_physical, 3, editor, release_table_frame)?;
    }
    Ok(())
}

fn initialize_user_frame_or_release_on_error<E>(
    frame: Frame,
    initializer: &mut impl UserFrameInitializer,
    release_frame: &mut impl FnMut(Frame) -> Result<(), (E, Frame)>,
) -> Result<ZeroedFrame, PagingError> {
    match initialize_user_frame(frame, initializer) {
        Ok(zeroed) => Ok(zeroed),
        Err((_initialization_error, frame)) => match release_frame(frame) {
            Ok(()) => Err(PagingError::UserFrameInitializationFailed),
            Err((_release_error, frame)) => {
                // A failed release must not permit reuse of a frame whose token
                // is no longer tracked by a caller. Fail-stop while retaining it
                // as allocated in the physical allocator.
                let _unreleased_frame_physical = frame.physical_address();
                panic!(
                    "allocator failed to release a frame after user-frame initialization failure"
                );
            }
        },
    }
}

/// Exercises the initializer-failure path and verifies that the exact returned
/// frame token reaches the allocator-release callback instead of being dropped.
pub(super) fn verify_user_frame_initialization_failure_releases_frame_for_smoke(
) -> Result<(), PagingError> {
    let frame = super::memory::allocate_frame().map_err(|_| PagingError::FrameAllocationFailed)?;
    let expected_physical = frame.physical_address();
    let mut initializer = FailingUserFrameInitializer;
    let mut released_physical = None;
    let mut release_frame = |frame: Frame| {
        released_physical = Some(frame.physical_address());
        super::memory::free_frame(frame)
    };

    let result =
        initialize_user_frame_or_release_on_error(frame, &mut initializer, &mut release_frame);
    drop(release_frame);
    if !matches!(result, Err(PagingError::UserFrameInitializationFailed))
        || released_physical != Some(expected_physical)
    {
        return Err(PagingError::UserFrameInitializationFailed);
    }
    Ok(())
}

/// Allocates, zeroes, and maps one test user-data page into an inactive root.
///
/// This helper is used by the normal-boot lifecycle smoke test. The returned
/// registry retains the frame token until the root has switched away and
/// teardown removes its mapping. It does not enter Ring 3.
pub fn map_test_user_page_for_teardown(
    boot_info: &BootInfo,
    root: &AddressSpaceRoot,
    active_root: &ActiveAddressSpaceRoot,
) -> Result<(UserPageMappingRegistry<ZeroedFrame, 1>, u64), PagingError> {
    let mut editor = KernelInactiveAddressSpaceEditor::new(boot_info, root, active_root)?;
    let frame = super::memory::allocate_frame().map_err(|_| PagingError::FrameAllocationFailed)?;
    let data_frame_physical = frame.physical_address();
    // SAFETY: the initializer is bound to the current active root and the caller
    // keeps interrupts disabled and the active root stable for this operation.
    let mut initializer =
        unsafe { KernelUserFrameInitializer::new(boot_info, active_root.recursive_index()) };
    let mut release_frame = super::memory::free_frame;
    let zeroed =
        initialize_user_frame_or_release_on_error(frame, &mut initializer, &mut release_frame)?;

    let mut registry = UserPageMappingRegistry::new(root);
    if let Err((error, zeroed)) =
        map_user_data_page(root, 0x4000, zeroed, &mut registry, &mut editor)
    {
        if let Err((_error, _frame)) = super::memory::free_frame(zeroed.into_frame()) {
            panic!("allocator failed to release a zeroed, unpublished user frame");
        }
        return Err(PagingError::UserPageMapping(error));
    }
    Ok((registry, data_frame_physical))
}

/// Validates an inactive root's complete lower-half user page-table tree before
/// the CR3 switch path is allowed to activate it.
///
/// This is a read-only preflight. It requires every present lower-half leaf to be
/// represented by the matching registry and rejects foreign or shared private
/// tables, malformed entries, cycles, unsupported large pages, and capacity
/// exhaustion. The caller must serialize this check with all root mutations.
pub fn validate_inactive_user_address_space<const CAPACITY: usize>(
    boot_info: &BootInfo,
    root: &AddressSpaceRoot,
    active_root: &ActiveAddressSpaceRoot,
    registry: &UserPageMappingRegistry<ZeroedFrame, CAPACITY>,
) -> Result<(), PagingError> {
    let mut editor = KernelInactiveAddressSpaceEditor::new(boot_info, root, active_root)?;
    preflight_private_user_tree(root.physical_address(), registry, &mut editor)
}

/// Exercises preflight rejection of representative corrupted page-table states
/// on the real kernel alias, restoring every entry before returning.
pub(super) fn verify_teardown_corruption_preflight_for_smoke<const CAPACITY: usize>(
    boot_info: &BootInfo,
    root: &AddressSpaceRoot,
    active_root: &ActiveAddressSpaceRoot,
    registry: &UserPageMappingRegistry<ZeroedFrame, CAPACITY>,
    foreign_root_physical: u64,
    foreign_data_physical: u64,
) -> Result<(), PagingError> {
    const TEST_VA: u64 = 0x4000;
    let mut editor = KernelInactiveAddressSpaceEditor::new(boot_info, root, active_root)?;
    // The editor-level predicate must fail closed for every live address-space
    // root, not only for the mapping editor's immediate target. This is checked
    // independently of the teardown preflight, which also validates leaf ownership.
    if !editor.is_page_table_or_reserved_frame(root.physical_address())
        || !editor.is_page_table_or_reserved_frame(active_root.physical_address())
        || !editor.is_page_table_or_reserved_frame(foreign_root_physical)
    {
        return Err(PagingError::InactivePageTableOwnershipViolation);
    }
    verify_user_frame_initialization_failure_releases_frame_for_smoke()?;
    let root_physical = root.physical_address();
    let pml4_index = ((TEST_VA >> 39) & 0x1ff) as usize;
    let pdpt_index = ((TEST_VA >> 30) & 0x1ff) as usize;
    let pd_index = ((TEST_VA >> 21) & 0x1ff) as usize;
    let pt_index = ((TEST_VA >> 12) & 0x1ff) as usize;

    let root_entry = editor
        .read_entry(root_physical, pml4_index, 4)
        .filter(|entry| *entry != 0)
        .ok_or(PagingError::InactivePageTableMalformed)?;
    let pdpt_physical = root_entry & PHYSICAL_ADDRESS_MASK;
    let pdpt_entry = editor
        .read_entry(pdpt_physical, pdpt_index, 3)
        .filter(|entry| *entry != 0)
        .ok_or(PagingError::InactivePageTableMalformed)?;
    let pd_physical = pdpt_entry & PHYSICAL_ADDRESS_MASK;
    let pd_entry = editor
        .read_entry(pd_physical, pd_index, 2)
        .filter(|entry| *entry != 0)
        .ok_or(PagingError::InactivePageTableMalformed)?;
    let pt_physical = pd_entry & PHYSICAL_ADDRESS_MASK;
    let leaf_entry = editor
        .read_entry(pt_physical, pt_index, 1)
        .filter(|entry| *entry != 0)
        .ok_or(PagingError::InactivePageTableMalformed)?;

    macro_rules! expect_rejected {
        ($table:expr, $level:expr, $index:expr, $original:expr, $bad:expr, $expected:expr) => {{
            editor.write_entry($table, $index, $level, $bad);
            let observed = preflight_private_user_tree(root_physical, registry, &mut editor);
            editor.write_entry($table, $index, $level, $original);
            if observed != Err($expected)
                || editor.read_entry($table, $index, $level) != Some($original)
            {
                return Err(PagingError::InactivePageTableMalformed);
            }
        }};
    }

    // Root self-cycle / foreign table target: ownership preflight must reject it.
    expect_rejected!(
        root_physical,
        4,
        pml4_index,
        root_entry,
        (root_entry & !PHYSICAL_ADDRESS_MASK) | root_physical,
        PagingError::InactivePageTableOwnershipViolation
    );
    // A large-page flag at an intermediate level must be rejected before walking.
    expect_rejected!(
        root_physical,
        4,
        pml4_index,
        root_entry,
        root_entry | LARGE_PAGE,
        PagingError::InactivePageTableMalformed
    );
    // A non-present but non-zero leaf is malformed and must not start teardown.
    expect_rejected!(
        pt_physical,
        1,
        pt_index,
        leaf_entry,
        leaf_entry & !PRESENT,
        PagingError::InactivePageTableMalformed
    );
    // Pointing a user leaf at an owned page-table frame must fail as reserved.
    expect_rejected!(
        pt_physical,
        1,
        pt_index,
        leaf_entry,
        (leaf_entry & !PHYSICAL_ADDRESS_MASK) | pt_physical,
        PagingError::InactivePageTableOwnershipViolation
    );
    // A valid, allocated data frame owned by another address space must not
    // satisfy this root's mapping merely because it is a user-usable frame.
    expect_rejected!(
        pt_physical,
        1,
        pt_index,
        leaf_entry,
        (leaf_entry & !PHYSICAL_ADDRESS_MASK) | foreign_data_physical,
        PagingError::InactivePageTableOwnershipViolation
    );
    // Reject the target's own PML4 and another root's PML4 as user data frames.
    expect_rejected!(
        pt_physical,
        1,
        pt_index,
        leaf_entry,
        (leaf_entry & !PHYSICAL_ADDRESS_MASK) | root_physical,
        PagingError::InactivePageTableOwnershipViolation
    );
    expect_rejected!(
        pt_physical,
        1,
        pt_index,
        leaf_entry,
        (leaf_entry & !PHYSICAL_ADDRESS_MASK) | foreign_root_physical,
        PagingError::InactivePageTableOwnershipViolation
    );
    // Delete a registered mapping's PTE. The tree walk alone skips zero entries;
    // the registry-to-PTE pass must detect the now-missing translation.
    expect_rejected!(
        pt_physical,
        1,
        pt_index,
        leaf_entry,
        0,
        PagingError::InactivePageTableMalformed
    );

    // Register an allocated but unreachable table frame to prove reverse
    // ownership validation rejects an orphan before teardown can mutate the tree.
    let orphan_table_physical = editor
        .allocate_table()
        .ok_or(PagingError::FrameAllocationFailed)?;
    // SAFETY: the orphan is an exclusively allocated, zeroed table frame. This
    // injected bad state exists only to test that preflight rejects it.
    if unsafe {
        TABLE_FRAMES
            .lock()
            .mark_published_for_root(root_physical, orphan_table_physical, 1)
    }
    .is_err()
    {
        editor.free_table(orphan_table_physical);
        return Err(PagingError::InactivePageTableOwnershipViolation);
    }
    let orphan_rejected = matches!(
        preflight_private_user_tree(root_physical, registry, &mut editor),
        Err(PagingError::InactivePageTableOwnershipViolation)
    );

    // Restore a valid detached-pending state so the allocated test frame can be
    // reclaimed by the same production release transaction used by teardown.
    // SAFETY: this injected frame has no parent entry, is zeroed and unreachable.
    unsafe {
        TABLE_FRAMES.lock().mark_published_table_detached_for_root(
            root_physical,
            orphan_table_physical,
            1,
        )
    }
    .map_err(|_| PagingError::InactivePageTableOwnershipViolation)?;
    if !editor.remove_staged_table(orphan_table_physical) {
        return Err(PagingError::InactivePageTableOwnershipViolation);
    }
    let mut release_table_frame = super::memory::free_frame;
    release_pending_detached_private_table(
        orphan_table_physical,
        1,
        &mut editor,
        &mut release_table_frame,
    )?;
    if !orphan_rejected {
        return Err(PagingError::InactivePageTableMalformed);
    }

    if !registry.is_mapped(TEST_VA)
        || preflight_private_user_tree(root_physical, registry, &mut editor).is_err()
    {
        return Err(PagingError::InactivePageTableMalformed);
    }
    Ok(())
}

/// Failure from kernel-backed inactive address-space teardown.
///
/// A user-page mutation failure retains its partial result and the remaining
/// registry entries so a caller can decide whether to retry or fail-stop without
/// losing ownership of frames already removed. Do not free, reactivate, or reuse
/// the root merely because this error is returned.
#[derive(Debug)]
pub enum InactiveAddressSpaceTeardownError<const CAPACITY: usize> {
    Kernel(PagingError),
    UserPages(UserPageTeardownFailure<CAPACITY>),
}

impl<const CAPACITY: usize> From<PagingError> for InactiveAddressSpaceTeardownError<CAPACITY> {
    fn from(error: PagingError) -> Self {
        Self::Kernel(error)
    }
}

/// Tears down every registered user page in one inactive root, then reclaims
/// its private lower-half intermediate tables bottom-up.
///
/// The whole private tree is preflighted before the first destructive update.
/// Returned data frames are zeroed again before allocator reuse. The caller must
/// release the PML4 root separately after this succeeds.
pub fn teardown_inactive_user_address_space<const CAPACITY: usize>(
    boot_info: &BootInfo,
    root: &AddressSpaceRoot,
    active_root: &ActiveAddressSpaceRoot,
    registry: &mut UserPageMappingRegistry<ZeroedFrame, CAPACITY>,
) -> Result<(), InactiveAddressSpaceTeardownError<CAPACITY>> {
    let mut release_table_frame = super::memory::free_frame;
    teardown_inactive_user_address_space_with_table_release(
        boot_info,
        root,
        active_root,
        registry,
        &mut release_table_frame,
    )
}

pub(super) fn teardown_inactive_user_address_space_with_table_release<const CAPACITY: usize, E>(
    boot_info: &BootInfo,
    root: &AddressSpaceRoot,
    active_root: &ActiveAddressSpaceRoot,
    registry: &mut UserPageMappingRegistry<ZeroedFrame, CAPACITY>,
    release_table_frame: &mut impl FnMut(Frame) -> Result<(), (E, Frame)>,
) -> Result<(), InactiveAddressSpaceTeardownError<CAPACITY>> {
    let mut editor = KernelInactiveAddressSpaceEditor::new(boot_info, root, active_root)?;
    preflight_private_user_tree(root.physical_address(), registry, &mut editor)?;

    let mut teardown = match unmap_all_user_data_pages(root, registry, &mut editor) {
        Ok(result) => result,
        // Preserve the error value so its partial result retains every frame
        // token already detached and invalidated by the batch operation.
        Err(failure) => return Err(InactiveAddressSpaceTeardownError::UserPages(failure)),
    };

    let mut initializer =
        unsafe { KernelUserFrameInitializer::new(boot_info, active_root.recursive_index()) };
    let completed = teardown.completed_pages();
    for index in 0..completed {
        let frame = teardown
            .take_frame(index)
            .ok_or(PagingError::UserPageTeardownFailed)?;
        let zeroed = initialize_user_frame(frame, &mut initializer)
            .unwrap_or_else(|(_error, _frame)| panic!("could not re-zero a detached user frame"));
        if let Err((_error, _frame)) = super::memory::free_frame(zeroed.into_frame()) {
            panic!("allocator failed to release a re-zeroed user frame");
        }
    }
    if registry.available_slots() != CAPACITY {
        return Err(InactiveAddressSpaceTeardownError::Kernel(
            PagingError::UserPageTeardownFailed,
        ));
    }

    reclaim_private_user_tables(root.physical_address(), &mut editor, release_table_frame)?;
    reclaim_pending_detached_private_tables(
        root.physical_address(),
        &mut editor,
        release_table_frame,
    )?;

    // Do not release the PML4 or allow its physical address to be reused while
    // the registry still holds private table ownership records for this root.
    // This detects orphaned table tokens left behind by an earlier partial
    // teardown or a structural mismatch that was not reachable from the tree.
    let remaining_private_tables = TABLE_FRAMES
        .lock()
        .published_count_for_root(root.physical_address())
        .map_err(|_| PagingError::InactivePageTableOwnershipViolation)?;
    if remaining_private_tables != 0 {
        return Err(InactiveAddressSpaceTeardownError::Kernel(
            PagingError::InactivePageTableOwnershipViolation,
        ));
    }

    Ok(())
}

/// Returns whether a detached table token remains registered for a root.
///
/// Used by the normal-boot failure-injection smoke test to prove that a failed
/// allocator release leaves the frame pending and non-reusable.
pub(super) fn has_pending_detached_private_table(root_physical: u64) -> bool {
    TABLE_FRAMES
        .lock()
        .detached_table_for_root(root_physical, 0)
        .is_some()
}

/// Kernel implementation of the unsafe zero-before-publication contract.
///
/// The recursive PML4 index must describe the current CR3 root. It may be the
/// bootloader-provided index before activation or the private index selected for
/// an activated kernel root. The operation is single-CPU and requires maskable
/// interrupts to remain disabled, as enforced by the page-table editor.
pub struct KernelUserFrameInitializer<'a> {
    boot_info: &'a BootInfo,
    recursive_index: u16,
}

impl<'a> KernelUserFrameInitializer<'a> {
    /// Creates an initializer bound to BootInfo and the currently active root's
    /// recursive self-map slot.
    ///
    /// # Safety
    ///
    /// recursive_index must be the valid self-referential PML4 slot of the
    /// current CR3 root, and that root must remain active for the entire call.
    /// The caller must run under the kernel's documented single-CPU,
    /// maskable-interrupts-disabled contract. The implementation verifies the
    /// slot's entry and the full physical-memory-offset translation before use.
    pub unsafe fn new(boot_info: &'a BootInfo, recursive_index: u16) -> Self {
        Self {
            boot_info,
            recursive_index,
        }
    }
}

struct FailingUserFrameInitializer;

// SAFETY: this test initializer always fails and never claims that any frame is
// zeroed, so initialize_user_frame cannot create an invalid ZeroedFrame token.
unsafe impl UserFrameInitializer for FailingUserFrameInitializer {
    fn zero_frame(&mut self, _frame: &Frame) -> Result<(), UserFrameInitializationError> {
        Err(UserFrameInitializationError::InitializationFailed)
    }
}

// SAFETY: zero_frame verifies allocator ownership, excludes active/page-table
// frames, validates the full supervisor-writable/NX alias through the active
// page tables, and verifies all 4096 bytes after writing. Interrupts must remain
// disabled and the current root must not change, as required by the constructor.
unsafe impl UserFrameInitializer for KernelUserFrameInitializer<'_> {
    fn zero_frame(&mut self, frame: &Frame) -> Result<(), UserFrameInitializationError> {
        let physical_address = frame.physical_address();
        let root_physical = active_root_table_physical();
        if physical_address == root_physical
            || !super::memory::is_frame_allocated(physical_address).unwrap_or(false)
            || registered_table_frame(physical_address)
            || unpublished_table_frame(physical_address)
            || is_address_space_root_frame(physical_address)
        {
            return Err(UserFrameInitializationError::InitializationFailed);
        }

        let physical_memory_offset = match self.boot_info.physical_memory_offset {
            Optional::Some(offset) => offset,
            Optional::None => return Err(UserFrameInitializationError::InitializationFailed),
        };
        let Some(alias_virtual_address) = physical_memory_offset.checked_add(physical_address)
        else {
            return Err(UserFrameInitializationError::InitializationFailed);
        };
        let mut editor = match KernelPageTableEditor::new_with_recursive_index(
            self.boot_info,
            alias_virtual_address,
            self.recursive_index,
        ) {
            Ok(editor) => editor,
            Err(_) => return Err(UserFrameInitializationError::InitializationFailed),
        };
        if !editor.is_usable_frame(physical_address)
            || editor.is_table_frame(physical_address)
            || !editor.is_frame_allocated(physical_address)
        {
            return Err(UserFrameInitializationError::InitializationFailed);
        }
        let Some(alias) = editor.offset_alias(physical_address) else {
            return Err(UserFrameInitializationError::InitializationFailed);
        };
        if alias as usize & (PAGE_SIZE as usize - 1) != 0 {
            return Err(UserFrameInitializationError::InitializationFailed);
        }

        // SAFETY: offset_alias proved that all 4096 bytes resolve to this exact,
        // allocated Usable frame through a writable, supervisor-only, NX mapping.
        // Ownership is retained by the caller's Frame token and interrupts are
        // disabled, so this frame cannot be published concurrently in this model.
        unsafe { ptr::write_bytes(alias, 0, PAGE_SIZE as usize) };

        let entries = alias.cast::<u64>();
        for index in 0..(PAGE_SIZE as usize / size_of::<u64>()) {
            // SAFETY: the full page was validated through the same alias above.
            if unsafe { ptr::read_volatile(entries.add(index)) } != 0 {
                return Err(UserFrameInitializationError::InitializationFailed);
            }
        }
        Ok(())
    }
}

/// Exercise the kernel-backed user-frame initializer on an allocated, dirty
/// frame using the bootloader-provided recursive mapping. Dedicated acceptance
/// images call this before any CR3 switch; normal boot uses
/// `verify_user_frame_zeroing_test_with_recursive_index` after activation.
/// This validates the initialization/token gate, not live Ring-3 publication
/// or process isolation.
#[cfg(any(
    feature = "test-exception",
    feature = "test-general-protection",
    feature = "test-page-fault",
    feature = "test-double-fault",
    feature = "test-ist",
    feature = "test-supervisor-write-protection",
    feature = "test-nx-protection",
    feature = "test-vm-transitions"
))]
pub fn verify_user_frame_zeroing_test(boot_info: &BootInfo) -> Result<(), PagingError> {
    let recursive_index = match boot_info.recursive_index {
        Optional::Some(index) if is_safe_recursive_mapping_index(index) => index,
        _ => return Err(PagingError::InvalidRecursiveIndex),
    };
    verify_user_frame_zeroing_test_with_recursive_index(boot_info, recursive_index)
}

/// Runs the user-frame zeroing acceptance test against the supplied active
/// root's recursive self-map. The explicit index is used after CR3 activation,
/// when the bootloader's original recursive index is no longer authoritative.
pub fn verify_user_frame_zeroing_test_with_recursive_index(
    boot_info: &BootInfo,
    recursive_index: u16,
) -> Result<(), PagingError> {
    if !is_safe_recursive_mapping_index(recursive_index) {
        return Err(PagingError::InvalidRecursiveIndex);
    }
    super::interrupts::write_hex(
        b"ONE OS USER FRAME ZERO TEST RECURSIVE INDEX: ",
        u64::from(recursive_index),
    );

    let frame = super::memory::allocate_frame().map_err(|_| PagingError::FrameAllocationFailed)?;
    let physical_address = frame.physical_address();
    let physical_memory_offset = match boot_info.physical_memory_offset {
        Optional::Some(offset) => offset,
        _ => {
            let _ = release_data_frame(frame);
            return Err(PagingError::PhysicalMemoryOffsetUnavailable);
        }
    };
    let Some(alias_virtual_address) = physical_memory_offset.checked_add(physical_address) else {
        let _ = release_data_frame(frame);
        return Err(PagingError::PhysicalMemoryOffsetUnavailable);
    };
    let mut editor = match KernelPageTableEditor::new_with_recursive_index(
        boot_info,
        alias_virtual_address,
        recursive_index,
    ) {
        Ok(editor) => editor,
        Err(error) => {
            let _ = release_data_frame(frame);
            return Err(error);
        }
    };
    if !editor.is_usable_frame(physical_address)
        || editor.is_table_frame(physical_address)
        || !editor.is_frame_allocated(physical_address)
    {
        let _ = release_data_frame(frame);
        return Err(PagingError::UserFrameInitializationFailed);
    }
    let Some(alias) = editor.offset_alias(physical_address) else {
        let _ = release_data_frame(frame);
        return Err(PagingError::UserFrameInitializationFailed);
    };

    // Dirty every word, then require the concrete kernel initializer to clear
    // and verify every word before it can return a ZeroedFrame token.
    let words = alias.cast::<u64>();
    for index in 0..(PAGE_SIZE as usize / size_of::<u64>()) {
        let dirty_value = 0xa5a5_5a5a_f0f0_0f0f_u64 ^ index as u64;
        // SAFETY: the checked alias spans this complete allocated data frame.
        unsafe { ptr::write_volatile(words.add(index), dirty_value) };
    }
    super::interrupts::write_hex(b"ONE OS USER FRAME ZERO TEST DIRTY: ", physical_address);

    // SAFETY: recursive_index was supplied by the active-root owner (or
    // validated from BootInfo before the bootloader-root transition test).
    let mut initializer = unsafe { KernelUserFrameInitializer::new(boot_info, recursive_index) };
    match initialize_user_frame(frame, &mut initializer) {
        Ok(zeroed) => {
            if zeroed.physical_address() != physical_address {
                let _ = release_data_frame(zeroed.into_frame());
                return Err(PagingError::UserFrameInitializationFailed);
            }
            for index in 0..(PAGE_SIZE as usize / size_of::<u64>()) {
                // SAFETY: the initializer validated this exact alias and the
                // test retains the frame's ownership token until verification ends.
                if unsafe { ptr::read_volatile(words.add(index)) } != 0 {
                    let _ = release_data_frame(zeroed.into_frame());
                    return Err(PagingError::UserFrameInitializationFailed);
                }
            }
            super::interrupts::write_hex(
                b"ONE OS USER FRAME ZERO TEST VERIFIED: ",
                zeroed.physical_address(),
            );
            release_data_frame(zeroed.into_frame())?;
            super::serial_write(b"ONE OS USER FRAME ZERO TEST PASS\n");
            Ok(())
        }
        Err((_error, frame)) => {
            let _ = release_data_frame(frame);
            Err(PagingError::UserFrameInitializationFailed)
        }
    }
}

fn active_root_table_physical() -> u64 {
    let cr3: u64;
    // SAFETY: CR3 is readable in privileged x86_64 kernel execution.
    unsafe {
        asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    }
    cr3 & PHYSICAL_ADDRESS_MASK
}

fn valid_physical_page(address: u64, bits: u8) -> bool {
    if !(32..=52).contains(&bits) || address == 0 || address & (PAGE_SIZE - 1) != 0 {
        return false;
    }
    let mask = ((1u64 << bits) - 1) & PHYSICAL_ADDRESS_MASK;
    address & !mask == 0
}

fn virtual_index(virtual_address: u64, level: u8) -> Option<usize> {
    if !(1..=4).contains(&level) {
        return None;
    }
    let shift = 12 + u32::from(level - 1) * 9;
    Some(((virtual_address >> shift) & 0x1ff) as usize)
}

fn entry_pointer_from_page(table_virtual_address: u64, index: usize) -> Option<*mut u64> {
    if index >= 512
        || !is_canonical_4level(table_virtual_address)
        || table_virtual_address & (PAGE_SIZE - 1) != 0
    {
        return None;
    }
    let offset = u64::try_from(index)
        .ok()?
        .checked_mul(size_of::<u64>() as u64)?;
    let address = table_virtual_address.checked_add(offset)?;
    let end = address.checked_add(size_of::<u64>() as u64 - 1)?;
    if !is_canonical_4level(address) || !is_canonical_4level(end) || address & 7 != 0 {
        return None;
    }
    Some(usize::try_from(address).ok()? as *mut u64)
}

fn translate_with_editor(
    editor: &mut KernelPageTableEditor<'_>,
    root_table_physical: u64,
    virtual_address: u64,
) -> Result<PageTranslation, PageTableError> {
    // entry_pointer() derives recursive aliases from editor.target_virtual_address.
    // That context must describe the address being translated, not the unrelated
    // mapping candidate the editor was originally created for. Restore the prior
    // target afterwards so a caller can continue its existing map/unmap operation.
    let previous_target = editor.target_virtual_address;
    editor.target_virtual_address = virtual_address;
    let mut level = 4u8;
    let result = translate_4level(virtual_address, root_table_physical, |table, index| {
        let current_level = level;
        level = level.saturating_sub(1);
        editor.read_entry(table, index, current_level)
    });
    editor.target_virtual_address = previous_target;
    result
}

/// Exercise a real active-kernel map/access/unmap cycle before reporting
/// bootstrap completion. Dedicated protected-write and NX fault images remain
/// separate acceptance tests; this smoke test does not claim those tests exist.
pub fn verify_mapping_smoke_test(boot_info: &BootInfo) -> Result<(), PagingError> {
    // The caller has already initialized and smoke-tested the physical allocator.
    let data_frame =
        super::memory::allocate_frame().map_err(|_| PagingError::FrameAllocationFailed)?;
    let data_physical = data_frame.physical_address();
    let recursive_index = match boot_info.recursive_index {
        Optional::Some(index) if is_safe_recursive_mapping_index(index) => index,
        Optional::Some(_) => {
            let _ = release_data_frame(data_frame);
            return Err(PagingError::InvalidRecursiveIndex);
        }
        Optional::None => {
            let _ = release_data_frame(data_frame);
            return Err(PagingError::RecursiveMappingUnavailable);
        }
    };
    let root_table_physical = active_root_table_physical();
    let permissions = PagePermissions::new(true, false, false);

    let physical_memory_offset = match boot_info.physical_memory_offset {
        Optional::Some(offset) => offset,
        Optional::None => {
            let _ = release_data_frame(data_frame);
            return Err(PagingError::PhysicalMemoryOffsetUnavailable);
        }
    };

    let highest_physical_end = boot_info
        .memory_regions
        .iter()
        .map(|region| region.end)
        .max()
        .unwrap_or(0)
        .max(1u64 << 32);
    let Some(physical_mapping_end) = physical_memory_offset.checked_add(highest_physical_end)
    else {
        let _ = release_data_frame(data_frame);
        return Err(PagingError::PhysicalMemoryOffsetUnavailable);
    };

    // Probe one address at the base of each high-half PML4 slot. This avoids
    // repeatedly retrying the same 2 MiB leaf when a candidate conflicts with
    // a large page, and skips both the recursive slot and the bootloader's
    // physical-memory-offset range before attempting to mutate page tables.
    for candidate_pml4_index in FIRST_CANDIDATE_PML4_INDEX..512 {
        if candidate_pml4_index == recursive_index {
            continue;
        }
        let raw_candidate = u64::from(candidate_pml4_index) << 39;
        let candidate = raw_candidate | 0xffff_0000_0000_0000;
        if candidate >= physical_memory_offset && candidate < physical_mapping_end {
            continue;
        }
        let mut editor = match KernelPageTableEditor::new(boot_info, candidate) {
            Ok(editor) => editor,
            Err(error) => {
                let _ = release_data_frame(data_frame);
                return Err(error);
            }
        };
        // SAFETY: data_frame remains owned through the map/access/unmap smoke
        // cycle and is released only after this mapping has been removed.
        match unsafe {
            map_supervisor_4k(
                root_table_physical,
                candidate,
                data_physical,
                permissions,
                &mut editor,
            )
        } {
            Ok(()) => {
                invalidate_local_tlb(candidate);
                // SAFETY: map_supervisor_4k installed a writable, supervisor-only mapping to
                // the allocated frame and the new translation has been invalidated.
                unsafe {
                    ptr::write_volatile(candidate as *mut u64, MAPPING_SMOKE_SENTINEL);
                }
                // SAFETY: the same validated mapping is immediately read back.
                let observed = unsafe { ptr::read_volatile(candidate as *const u64) };
                let atomic_entry_update_correctly = if let (Some(table_physical), Some(index)) = (
                    editor.reachable_table_physical(1),
                    virtual_index(candidate, 1),
                ) {
                    editor.verify_atomic_entry_compare_exchange(table_physical, index, 1)
                } else {
                    false
                };
                let translation =
                    translate_with_editor(&mut editor, root_table_physical, candidate);
                let mapped_correctly = atomic_entry_update_correctly
                    && observed == MAPPING_SMOKE_SENTINEL
                    && translation.is_ok_and(|result| {
                        result.physical_address == data_physical
                            && result.page_size == PAGE_SIZE
                            && result.writable
                            && !result.user_accessible
                            && !result.executable
                    });
                let unmapped = unmap_4k(root_table_physical, candidate, &mut editor);
                if unmapped.is_err() {
                    // Never return a data frame to the allocator while it may
                    // still be reachable through a live page-table entry.
                    return Err(PagingError::MappingSmokeMismatch);
                }
                invalidate_local_tlb(candidate);
                let unmapped_page = unmapped.expect("checked successful unmap");
                let unmapped_translation =
                    translate_with_editor(&mut editor, root_table_physical, candidate);
                let removed_correctly = unmapped_page.physical_address == data_physical
                    && unmapped_page.permissions == permissions
                    && matches!(unmapped_translation, Err(PageTableError::NotPresent { .. }));
                let release_result = release_data_frame(data_frame);
                if release_result.is_err() || !mapped_correctly || !removed_correctly {
                    return Err(PagingError::MappingSmokeMismatch);
                }
                return Ok(());
            }
            Err(error) if error.is_retryable_for_mapping_candidate() => {
                // map_supervisor_4k reports these failures during its read-only preflight,
                // before allocating a table or writing a page-table entry.
                continue;
            }
            Err(error) => {
                let _ = release_data_frame(data_frame);
                return Err(PagingError::MappingMutation(error));
            }
        }
    }

    let _ = release_data_frame(data_frame);
    Err(PagingError::NoUnusedVirtualAddress)
}

/// Restricts the physical-memory-offset aliases for every validated executable PT_LOAD page.
///
/// This must run while the bootloader root and its recursive index are active, before
/// constructing the private kernel root. The upper-half/direct-map page tables are
/// shared into later roots. Executable extents are derived from the validated ELF
/// program headers and page-table translations, never from a VA == PA assumption.
pub fn enforce_kernel_executable_alias_wx(boot_info: &BootInfo) -> Result<usize, PagingError> {
    let recursive_index = match boot_info.recursive_index {
        Optional::Some(index) if is_safe_recursive_mapping_index(index) => index,
        Optional::Some(_) => return Err(PagingError::InvalidRecursiveIndex),
        Optional::None => return Err(PagingError::RecursiveMappingUnavailable),
    };
    let regions: &[MemoryRegion] = &boot_info.memory_regions;
    let root_table_physical = active_root_table_physical();
    if root_table_physical == 0
        || root_table_physical & (PAGE_SIZE - 1) != 0
        || !is_bootloader_owned_page(regions, root_table_physical)
        || !validate_recursive_mapping_entry(recursive_index, root_table_physical)
    {
        return Err(PagingError::InvalidRootTable);
    }

    let physical_memory_offset = match boot_info.physical_memory_offset {
        Optional::Some(offset) => offset,
        Optional::None => return Err(PagingError::PhysicalMemoryOffsetUnavailable),
    };
    let physical_address_bits = (__cpuid(CPUID_PHYSICAL_ADDRESS_WIDTH).eax & 0xff) as u8;
    if !(32..=52).contains(&physical_address_bits) {
        return Err(PagingError::InvalidPhysicalAddressWidth {
            bits: physical_address_bits,
        });
    }

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

    let mut executable_pages_checked = 0usize;
    for segment in load_image.load_segments() {
        if !segment.executable() || segment.memory_size == 0 {
            continue;
        }
        // A writable/executable PT_LOAD page cannot be repaired by downgrading
        // only the direct-map alias; reject it rather than claiming W^X success.
        if segment.writable() {
            return Err(PagingError::InvalidKernelCodeMapping);
        }
        let load_start = boot_info
            .kernel_image_offset
            .checked_add(segment.virtual_address)
            .ok_or(PagingError::InvalidKernelLoadMapping)?;
        let load_end = load_start
            .checked_add(segment.memory_size)
            .filter(|end| *end > load_start)
            .ok_or(PagingError::InvalidKernelLoadMapping)?;
        if !canonical_range_stays_in_one_half(load_start, load_end) {
            return Err(PagingError::InvalidKernelLoadMapping);
        }

        let first_page = load_start & !(PAGE_SIZE - 1);
        let last_page = (load_end - 1) & !(PAGE_SIZE - 1);
        let mut virtual_page = first_page;
        loop {
            let translation = translate_virtual_address(
                virtual_page,
                root_table_physical,
                recursive_index,
                regions,
            )
            .map_err(|_| PagingError::InvalidKernelLoadMapping)?;
            if translation.page_size != PAGE_SIZE
                || translation.physical_address & (PAGE_SIZE - 1) != 0
                || !is_kernel_backed_page(regions, translation.physical_address)
                || translation.user_accessible
                || translation.writable
                || !translation.executable
            {
                return Err(PagingError::InvalidKernelLoadMapping);
            }

            let direct_alias = physical_memory_offset
                .checked_add(translation.physical_address)
                .filter(|address| {
                    is_canonical_4level(*address) && (*address & (PAGE_SIZE - 1)) == 0
                })
                .ok_or(PagingError::PhysicalMemoryOffsetUnavailable)?;
            restrict_physical_offset_alias_read_only_nx(
                boot_info,
                root_table_physical,
                direct_alias,
                translation.physical_address,
            )?;

            // Verify the effective permissions through a fresh page-table walk
            // for every executable PT_LOAD page, not just the single CPU-fault
            // sample exercised by the dedicated acceptance profile.
            let mut verify_editor = KernelPageTableEditor::new(boot_info, direct_alias)?;
            let verified =
                translate_with_editor(&mut verify_editor, root_table_physical, direct_alias)
                    .map_err(PagingError::Translation)?;
            if verified.physical_address != translation.physical_address
                || verified.page_size != PAGE_SIZE
                || verified.writable
                || verified.user_accessible
                || verified.executable
            {
                return Err(PagingError::WxAuditFailed);
            }

            executable_pages_checked = executable_pages_checked
                .checked_add(1)
                .ok_or(PagingError::InvalidKernelLoadMapping)?;

            if virtual_page == last_page {
                break;
            }
            virtual_page = virtual_page
                .checked_add(PAGE_SIZE)
                .ok_or(PagingError::InvalidKernelLoadMapping)?;
        }
    }

    if executable_pages_checked == 0 {
        return Err(PagingError::InvalidKernelLoadMapping);
    }
    Ok(executable_pages_checked)
}

/// Returns the physical-offset alias of a supervisor-only executable kernel
/// mapping for the dedicated W^X CPU-enforcement test. The helper checks the
/// live root, mapping permissions, and physical backing; it does not independently
/// prove ELF PT_LOAD membership. The current caller passes a known kernel function
/// address, and this helper never assumes VA == PA.
#[cfg(feature = "test-wx-runtime-audit")]
pub fn kernel_executable_direct_alias_for_test(
    boot_info: &BootInfo,
    executable_virtual_address: u64,
    recursive_index: u16,
) -> Result<u64, PagingError> {
    let regions: &[MemoryRegion] = &boot_info.memory_regions;
    let root_table_physical = active_root_table_physical();
    if !is_canonical_4level(executable_virtual_address)
        || !is_safe_recursive_mapping_index(recursive_index)
        || !validate_recursive_mapping_entry(recursive_index, root_table_physical)
    {
        return Err(PagingError::InvalidRecursiveMapping);
    }

    // Page-table editors take a page-aligned target address. Keep the caller's
    // code pointer only as a page selector; the permission check applies to the
    // full executable leaf that contains it.
    let executable_virtual_page = executable_virtual_address & !(PAGE_SIZE - 1);

    // The active root is kernel-owned and may contain page-table frames in
    // Usable regions, so use the checked kernel editor rather than the boot-only
    // translator, which deliberately accepts only Bootloader-owned table frames.
    let mut executable_editor = KernelPageTableEditor::new_with_recursive_index(
        boot_info,
        executable_virtual_page,
        recursive_index,
    )?;
    let executable = translate_with_editor(
        &mut executable_editor,
        root_table_physical,
        executable_virtual_page,
    )
    .map_err(PagingError::Translation)?;
    if executable.page_size != PAGE_SIZE
        || executable.writable
        || executable.user_accessible
        || !executable.executable
    {
        return Err(PagingError::InvalidKernelCodeMapping);
    }
    let physical_page = executable.physical_address & !(PAGE_SIZE - 1);
    if !is_kernel_backed_page(regions, physical_page) {
        return Err(PagingError::InvalidKernelLoadMapping);
    }

    let physical_memory_offset = match boot_info.physical_memory_offset {
        Optional::Some(offset) => offset,
        Optional::None => return Err(PagingError::PhysicalMemoryOffsetUnavailable),
    };
    let direct_alias = physical_memory_offset
        .checked_add(physical_page)
        .filter(|address| is_canonical_4level(*address) && (*address & (PAGE_SIZE - 1)) == 0)
        .ok_or(PagingError::PhysicalMemoryOffsetUnavailable)?;
    let mut alias_editor =
        KernelPageTableEditor::new_with_recursive_index(boot_info, direct_alias, recursive_index)?;
    let alias = translate_with_editor(&mut alias_editor, root_table_physical, direct_alias)
        .map_err(PagingError::Translation)?;
    if alias.page_size != PAGE_SIZE
        || alias.physical_address != physical_page
        || alias.writable
        || alias.user_accessible
        || alias.executable
    {
        return Err(PagingError::WxAuditFailed);
    }
    Ok(direct_alias)
}

#[cfg(feature = "test-wx-runtime-audit")]
const WX_SIBLING_PRE_TRANSITION_SENTINEL: u64 = 0x4f4e_455f_5758_5052;
#[cfg(feature = "test-wx-runtime-audit")]
const WX_SIBLING_ALIAS_WRITE_SENTINEL: u64 = 0x4f4e_455f_5758_414c;
#[cfg(feature = "test-wx-runtime-audit")]
const WX_SIBLING_DIRECT_WRITE_SENTINEL: u64 = 0x4f4e_455f_5758_444d;

/// Keeps two allocator-owned Usable frames that share one original large direct-map
/// leaf and the same 2 MiB physical subregion. This provides a controlled test layout
/// even when the bootloader has reserved every unused page beside the loaded kernel.
#[cfg(feature = "test-wx-runtime-audit")]
pub struct WxSiblingRegressionTest {
    executable_frame: Option<Frame>,
    sibling_frame: Option<Frame>,
    pub executable_physical_page: u64,
    pub sibling_physical_page: u64,
    pub original_large_page_size: u64,
    executable_virtual_address: Option<u64>,
}

/// Forms overlapping adjacent-frame candidates without skipping allocation positions.
#[cfg(feature = "test-wx-runtime-audit")]
fn take_adjacent_wx_frame_pair<T>(previous: &mut Option<T>, current: T) -> Option<(T, T)> {
    match previous.take() {
        Some(previous) => Some((previous, current)),
        None => {
            *previous = Some(current);
            None
        }
    }
}

/// Finds an owned pair in a real writable large-page direct-map leaf.
///
/// The physical location of PT_LOAD segments is chosen by the bootloader and must not
/// be treated as a placement guarantee. Instead, allocate both test frames from memory
/// explicitly reported as Usable, and retain their allocator tokens for the lifetime
/// of the test. The test executable page is mapped RX separately before its physical
/// offset alias is restricted to RO+NX.
#[cfg(feature = "test-wx-runtime-audit")]
pub fn verify_wx_sibling_large_page_precondition(
    boot_info: &BootInfo,
) -> Result<WxSiblingRegressionTest, PagingError> {
    let recursive_index = match boot_info.recursive_index {
        Optional::Some(index) if is_safe_recursive_mapping_index(index) => index,
        Optional::Some(_) => return Err(PagingError::InvalidRecursiveIndex),
        Optional::None => return Err(PagingError::RecursiveMappingUnavailable),
    };
    let root_table_physical = active_root_table_physical();
    if root_table_physical == 0
        || !validate_recursive_mapping_entry(recursive_index, root_table_physical)
    {
        return Err(PagingError::InvalidRecursiveMapping);
    }
    let physical_memory_offset = match boot_info.physical_memory_offset {
        Optional::Some(offset) => offset,
        Optional::None => return Err(PagingError::PhysicalMemoryOffsetUnavailable),
    };

    // Search every frame that was free at entry, rather than stopping at an
    // arbitrary physical range. Keep a one-frame sliding window so an eligible
    // pair is found regardless of whether its two frames fall on odd/even
    // allocation positions. Rejected frames are freed without rewinding next_hint.
    let scan_budget =
        super::memory::free_frame_count().map_err(|_| PagingError::FrameAllocationFailed)?;
    if scan_budget < 2 {
        super::serial_write(b"ONE OS W^X PRECONDITION NO USABLE LARGE-PAGE SIBLING PAIR FOUND\n");
        return Err(PagingError::WxSiblingFrameUnavailable);
    }
    // Include one extra allocation to test the wraparound pair between the final
    // free frame and the first one in the allocator's cyclic search order.
    let scan_attempts = scan_budget
        .checked_add(1)
        .ok_or(PagingError::FrameAllocationFailed)?;
    let mut previous_frame: Option<Frame> = None;
    // Cache eligibility by aligned virtual 2 MiB region, not physical region:
    // the physical-memory offset need not be 2 MiB aligned, and one physical
    // region can straddle two independently mapped virtual large-page leaves.
    // Within one aligned virtual 2 MiB region, a 2 MiB/1 GiB leaf covers every
    // candidate; a 4 KiB page-table subtree cannot contain a large leaf.
    let mut checked_region: Option<(u64, Option<u64>)> = None;

    for _ in 0..scan_attempts {
        let current_frame = match super::memory::allocate_frame() {
            Ok(frame) => frame,
            Err(_) => {
                if let Some(frame) = previous_frame.take() {
                    let _ = release_data_frame_preserving_hint(frame);
                }
                return Err(PagingError::FrameAllocationFailed);
            }
        };
        let Some((executable_frame, current_frame)) =
            take_adjacent_wx_frame_pair(&mut previous_frame, current_frame)
        else {
            continue;
        };

        let executable_physical_page = executable_frame.physical_address();
        let sibling_physical_page = current_frame.physical_address();
        let same_2m_region = executable_physical_page != sibling_physical_page
            && executable_physical_page & !((1u64 << 21) - 1)
                == sibling_physical_page & !((1u64 << 21) - 1);

        if same_2m_region {
            let region_start = executable_physical_page & !((1u64 << 21) - 1);
            let direct_aliases = (|| -> Result<(u64, u64), PagingError> {
                let executable_direct_alias = physical_memory_offset
                    .checked_add(executable_physical_page)
                    .filter(|address| {
                        is_canonical_4level(*address) && (*address & (PAGE_SIZE - 1)) == 0
                    })
                    .ok_or(PagingError::PhysicalMemoryOffsetUnavailable)?;
                let sibling_direct_alias = physical_memory_offset
                    .checked_add(sibling_physical_page)
                    .filter(|address| {
                        is_canonical_4level(*address) && (*address & (PAGE_SIZE - 1)) == 0
                    })
                    .ok_or(PagingError::PhysicalMemoryOffsetUnavailable)?;
                Ok((executable_direct_alias, sibling_direct_alias))
            })();
            let (executable_direct_alias, sibling_direct_alias) = match direct_aliases {
                Ok(aliases) => aliases,
                Err(error) => {
                    let _ = release_data_frame_preserving_hint(executable_frame);
                    let _ = release_data_frame_preserving_hint(current_frame);
                    return Err(error);
                }
            };
            let virtual_region_start = executable_direct_alias & !((1u64 << 21) - 1);

            let large_page_size = match checked_region {
                Some((checked_start, page_size)) if checked_start == virtual_region_start => page_size,
                _ => {
                    let candidate = (|| -> Result<Option<u64>, PagingError> {
                        let mut editor = KernelPageTableEditor::new_with_recursive_index(
                            boot_info,
                            executable_direct_alias,
                            recursive_index,
                        )?;
                        let alias = translate_with_editor(
                            &mut editor,
                            root_table_physical,
                            executable_direct_alias,
                        )
                        .map_err(PagingError::Translation)?;

                        if (alias.page_size != (1u64 << 21) && alias.page_size != (1u64 << 30))
                            || alias.physical_address != executable_physical_page
                            || !alias.writable
                            || alias.user_accessible
                            || alias.executable
                            || executable_direct_alias & !(alias.page_size - 1)
                                != sibling_direct_alias & !(alias.page_size - 1)
                        {
                            return Ok(None);
                        }
                        Ok(Some(alias.page_size))
                    })();

                    match candidate {
                        Ok(page_size) => {
                            checked_region = Some((virtual_region_start, page_size));
                            page_size
                        }
                        Err(error) => {
                            let _ = release_data_frame_preserving_hint(executable_frame);
                            let _ = release_data_frame_preserving_hint(current_frame);
                            return Err(error);
                        }
                    }
                }
            };

            if let Some(original_page_size) = large_page_size {
                // A full large-page leaf covers both addresses. Verify that the
                // aliases really share that leaf before accepting the owned pair.
                if executable_direct_alias & !(original_page_size - 1)
                    == sibling_direct_alias & !(original_page_size - 1)
                {
                    // SAFETY: the direct-map alias belongs to an allocator-owned
                    // Usable frame and was checked as writable, supervisor-only, NX.
                    // Seed a single RET byte before installing the separate RX alias.
                    unsafe {
                        ptr::write_volatile(executable_direct_alias as *mut u8, 0xc3);
                        ptr::write_volatile(
                            sibling_direct_alias as *mut u64,
                            WX_SIBLING_PRE_TRANSITION_SENTINEL,
                        );
                    }
                    return Ok(WxSiblingRegressionTest {
                        executable_frame: Some(executable_frame),
                        sibling_frame: Some(current_frame),
                        executable_physical_page,
                        sibling_physical_page,
                        original_large_page_size,
                        executable_virtual_address: None,
                    });
                }
            }
        }

        // Advance by one allocation, not two: the current frame becomes the
        // previous candidate so overlapping pairs are checked on the next pass.
        let _ = release_data_frame_preserving_hint(executable_frame);
        previous_frame = Some(current_frame);
    }

    if let Some(frame) = previous_frame.take() {
        let _ = release_data_frame_preserving_hint(frame);
    }

    super::serial_write(b"ONE OS W^X PRECONDITION NO USABLE LARGE-PAGE SIBLING PAIR FOUND\n");
    Err(PagingError::WxSiblingFrameUnavailable)
}

/// Maps the owned test executable page as supervisor RX and ensures its direct-map
/// alias is RO+NX. If the kernel PT_LOAD transition already split this same 2 MiB
/// region, this verifies that the sibling remained writable; otherwise it invokes
/// the same guarded direct-map restriction primitive to exercise the demotion path.
#[cfg(feature = "test-wx-runtime-audit")]
pub fn apply_wx_sibling_test_transition(
    boot_info: &BootInfo,
    test: &mut WxSiblingRegressionTest,
) -> Result<(), PagingError> {
    let recursive_index = match boot_info.recursive_index {
        Optional::Some(index) if is_safe_recursive_mapping_index(index) => index,
        Optional::Some(_) => return Err(PagingError::InvalidRecursiveIndex),
        Optional::None => return Err(PagingError::RecursiveMappingUnavailable),
    };
    let root_table_physical = active_root_table_physical();
    if !validate_recursive_mapping_entry(recursive_index, root_table_physical)
        || test.executable_frame.as_ref().map(Frame::physical_address)
            != Some(test.executable_physical_page)
        || test.sibling_frame.as_ref().map(Frame::physical_address)
            != Some(test.sibling_physical_page)
        || test.original_large_page_size != (1u64 << 21)
            && test.original_large_page_size != (1u64 << 30)
        || test.executable_physical_page & !((1u64 << 21) - 1)
            != test.sibling_physical_page & !((1u64 << 21) - 1)
    {
        return Err(PagingError::WxSiblingFrameUnavailable);
    }
    let physical_memory_offset = match boot_info.physical_memory_offset {
        Optional::Some(offset) => offset,
        Optional::None => return Err(PagingError::PhysicalMemoryOffsetUnavailable),
    };
    let executable_direct_alias = physical_memory_offset
        .checked_add(test.executable_physical_page)
        .filter(|address| is_canonical_4level(*address) && (*address & (PAGE_SIZE - 1)) == 0)
        .ok_or(PagingError::PhysicalMemoryOffsetUnavailable)?;

    // The precondition is checked before the PT_LOAD transition. An original
    // 1 GiB leaf may now be a 2 MiB child if PT_LOAD demoted a different child,
    // or a 4 KiB leaf if PT_LOAD touched this same physical 2 MiB region.
    let mut direct_editor = KernelPageTableEditor::new_with_recursive_index(
        boot_info,
        executable_direct_alias,
        recursive_index,
    )?;
    let direct_before = translate_with_editor(
        &mut direct_editor,
        root_table_physical,
        executable_direct_alias,
    )
    .map_err(PagingError::Translation)?;
    let valid_demotion_progress = oneos_core::is_valid_large_page_demotion_progress(
        test.original_large_page_size,
        direct_before.page_size,
    );
    let direct_mapping_is_writable_supervisor_nx =
        direct_before.writable && !direct_before.user_accessible && !direct_before.executable;
    if direct_before.physical_address != test.executable_physical_page
        || !valid_demotion_progress
        || !direct_mapping_is_writable_supervisor_nx
    {
        return Err(PagingError::LargePageDemotionFailed);
    }

    // Restrict the owned test frame's physical-offset alias before publishing any
    // executable alias. This avoids a transient W+X alias even with interrupts off.
    // If PT_LOAD already demoted this exact 2 MiB child, this changes the frame's
    // writable 4 KiB alias to RO+NX; otherwise the helper performs the remaining
    // 1 GiB-to-2 MiB or 2 MiB-to-4 KiB demotion required for this test frame.
    restrict_physical_offset_alias_read_only_nx(
        boot_info,
        root_table_physical,
        executable_direct_alias,
        test.executable_physical_page,
    )?;

    let highest_physical_end = boot_info
        .memory_regions
        .iter()
        .map(|region| region.end)
        .max()
        .unwrap_or(0)
        .max(1u64 << 32);
    let physical_mapping_end = physical_memory_offset
        .checked_add(highest_physical_end)
        .ok_or(PagingError::PhysicalMemoryOffsetUnavailable)?;
    let mut mapped_virtual_address = None;
    for candidate_pml4_index in FIRST_CANDIDATE_PML4_INDEX..512 {
        if candidate_pml4_index == recursive_index {
            continue;
        }
        let raw_candidate = u64::from(candidate_pml4_index) << 39;
        let candidate = raw_candidate | 0xffff_0000_0000_0000;
        if candidate >= physical_memory_offset && candidate < physical_mapping_end {
            continue;
        }
        let mut editor = match KernelPageTableEditor::new_with_recursive_index(
            boot_info,
            candidate,
            recursive_index,
        ) {
            Ok(editor) => editor,
            Err(error) => return Err(error),
        };
        // This per-editor permission is available only in the dedicated regression
        // image and only after verifying this frame's direct-map alias is RO+NX.
        #[cfg(feature = "test-wx-runtime-audit")]
        editor.allow_controlled_wx_test_executable_frame(test.executable_physical_page)?;
        // SAFETY: the owned executable test frame remains allocated for the test's
        // lifetime. The mapping is supervisor-only and deliberately not writable.
        match unsafe {
            map_supervisor_4k(
                root_table_physical,
                candidate,
                test.executable_physical_page,
                PagePermissions::new(false, false, true),
                &mut editor,
            )
        } {
            Ok(()) => {
                invalidate_local_tlb(candidate);
                let mut verify_editor = KernelPageTableEditor::new_with_recursive_index(
                    boot_info,
                    candidate,
                    recursive_index,
                )?;
                let mapped =
                    translate_with_editor(&mut verify_editor, root_table_physical, candidate)
                        .map_err(PagingError::Translation)?;
                if mapped.physical_address != test.executable_physical_page
                    || mapped.page_size != PAGE_SIZE
                    || mapped.writable
                    || mapped.user_accessible
                    || !mapped.executable
                {
                    return Err(PagingError::InvalidKernelCodeMapping);
                }
                mapped_virtual_address = Some(candidate);
                break;
            }
            Err(error) if error.is_retryable_for_mapping_candidate() => continue,
            Err(error) => return Err(PagingError::MappingMutation(error)),
        }
    }
    let executable_virtual_address =
        mapped_virtual_address.ok_or(PagingError::NoUnusedVirtualAddress)?;
    test.executable_virtual_address = Some(executable_virtual_address);

    // Verify the actual effective permissions on both aliases after the change.
    let mut executable_alias_editor = KernelPageTableEditor::new_with_recursive_index(
        boot_info,
        executable_virtual_address,
        recursive_index,
    )?;
    let executable_alias = translate_with_editor(
        &mut executable_alias_editor,
        root_table_physical,
        executable_virtual_address,
    )
    .map_err(PagingError::Translation)?;
    let mut direct_alias_editor = KernelPageTableEditor::new_with_recursive_index(
        boot_info,
        executable_direct_alias,
        recursive_index,
    )?;
    let direct_alias = translate_with_editor(
        &mut direct_alias_editor,
        root_table_physical,
        executable_direct_alias,
    )
    .map_err(PagingError::Translation)?;
    let sibling_direct_alias = physical_memory_offset
        .checked_add(test.sibling_physical_page)
        .filter(|address| is_canonical_4level(*address) && (*address & (PAGE_SIZE - 1)) == 0)
        .ok_or(PagingError::PhysicalMemoryOffsetUnavailable)?;
    let mut sibling_alias_editor = KernelPageTableEditor::new_with_recursive_index(
        boot_info,
        sibling_direct_alias,
        recursive_index,
    )?;
    let sibling_alias = translate_with_editor(
        &mut sibling_alias_editor,
        root_table_physical,
        sibling_direct_alias,
    )
    .map_err(PagingError::Translation)?;
    if executable_alias.physical_address != test.executable_physical_page
        || executable_alias.page_size != PAGE_SIZE
        || executable_alias.writable
        || executable_alias.user_accessible
        || !executable_alias.executable
        || direct_alias.physical_address != test.executable_physical_page
        || direct_alias.page_size != PAGE_SIZE
        || direct_alias.writable
        || direct_alias.user_accessible
        || direct_alias.executable
        || sibling_alias.physical_address != test.sibling_physical_page
        || sibling_alias.page_size != PAGE_SIZE
        || !sibling_alias.writable
        || sibling_alias.user_accessible
        || sibling_alias.executable
    {
        return Err(PagingError::LargePageDemotionFailed);
    }
    Ok(())
}

/// Verifies that the controlled RX test frame's direct-map alias is read-only/NX
/// while the writable data sibling remains writable/NX after large-page demotion.
#[cfg(feature = "test-wx-runtime-audit")]
pub fn verify_wx_sibling_test_after_transition(
    boot_info: &BootInfo,
    test: &mut WxSiblingRegressionTest,
    recursive_index: u16,
) -> Result<(), PagingError> {
    if test.executable_frame.as_ref().map(Frame::physical_address)
        != Some(test.executable_physical_page)
        || test.sibling_frame.as_ref().map(Frame::physical_address)
            != Some(test.sibling_physical_page)
        || test.executable_physical_page & !((1u64 << 21) - 1)
            != test.sibling_physical_page & !((1u64 << 21) - 1)
    {
        return Err(PagingError::WxSiblingFrameUnavailable);
    }
    let executable_virtual_address = test
        .executable_virtual_address
        .ok_or(PagingError::InvalidKernelCodeMapping)?;
    let root_table_physical = active_root_table_physical();
    if !validate_recursive_mapping_entry(recursive_index, root_table_physical) {
        return Err(PagingError::InvalidRecursiveMapping);
    }
    let physical_memory_offset = match boot_info.physical_memory_offset {
        Optional::Some(offset) => offset,
        Optional::None => return Err(PagingError::PhysicalMemoryOffsetUnavailable),
    };
    let executable_direct_alias = physical_memory_offset
        .checked_add(test.executable_physical_page)
        .filter(|address| is_canonical_4level(*address) && (*address & (PAGE_SIZE - 1)) == 0)
        .ok_or(PagingError::PhysicalMemoryOffsetUnavailable)?;
    let sibling_direct_alias = physical_memory_offset
        .checked_add(test.sibling_physical_page)
        .filter(|address| is_canonical_4level(*address) && (*address & (PAGE_SIZE - 1)) == 0)
        .ok_or(PagingError::PhysicalMemoryOffsetUnavailable)?;

    let mut executable_editor = KernelPageTableEditor::new_with_recursive_index(
        boot_info,
        executable_virtual_address,
        recursive_index,
    )?;
    let executable_alias = translate_with_editor(
        &mut executable_editor,
        root_table_physical,
        executable_virtual_address,
    )
    .map_err(PagingError::Translation)?;
    let mut direct_editor = KernelPageTableEditor::new_with_recursive_index(
        boot_info,
        executable_direct_alias,
        recursive_index,
    )?;
    let direct_alias = translate_with_editor(
        &mut direct_editor,
        root_table_physical,
        executable_direct_alias,
    )
    .map_err(PagingError::Translation)?;
    let mut sibling_editor = KernelPageTableEditor::new_with_recursive_index(
        boot_info,
        sibling_direct_alias,
        recursive_index,
    )?;
    let sibling_alias = translate_with_editor(
        &mut sibling_editor,
        root_table_physical,
        sibling_direct_alias,
    )
    .map_err(PagingError::Translation)?;
    if executable_alias.physical_address != test.executable_physical_page
        || executable_alias.page_size != PAGE_SIZE
        || executable_alias.writable
        || executable_alias.user_accessible
        || !executable_alias.executable
        || direct_alias.physical_address != test.executable_physical_page
        || direct_alias.page_size != PAGE_SIZE
        || direct_alias.writable
        || direct_alias.user_accessible
        || direct_alias.executable
        || sibling_alias.physical_address != test.sibling_physical_page
        || sibling_alias.page_size != PAGE_SIZE
        || !sibling_alias.writable
        || sibling_alias.user_accessible
        || sibling_alias.executable
    {
        return Err(PagingError::LargePageDemotionFailed);
    }

    // Map the sibling frame through a second, independent virtual address.
    // The direct map and this test alias must see the same physical contents in both
    // write directions, including the value seeded before the large-page transition.
    let highest_physical_end = boot_info
        .memory_regions
        .iter()
        .map(|region| region.end)
        .max()
        .unwrap_or(0)
        .max(1u64 << 32);
    let physical_mapping_end = physical_memory_offset
        .checked_add(highest_physical_end)
        .ok_or(PagingError::PhysicalMemoryOffsetUnavailable)?;
    let mut sibling_virtual_address = None;
    for candidate_pml4_index in FIRST_CANDIDATE_PML4_INDEX..512 {
        if candidate_pml4_index == recursive_index {
            continue;
        }
        let raw_candidate = u64::from(candidate_pml4_index) << 39;
        let candidate = raw_candidate | 0xffff_0000_0000_0000;
        if candidate >= physical_memory_offset && candidate < physical_mapping_end {
            continue;
        }
        let mut editor = KernelPageTableEditor::new_with_recursive_index(
            boot_info,
            candidate,
            recursive_index,
        )?;
        // SAFETY: the sibling frame remains allocator-owned. This additional alias
        // is supervisor-only, writable, NX, and does not grant executable access.
        match unsafe {
            map_supervisor_4k(
                root_table_physical,
                candidate,
                test.sibling_physical_page,
                PagePermissions::new(true, false, false),
                &mut editor,
            )
        } {
            Ok(()) => {
                invalidate_local_tlb(candidate);
                sibling_virtual_address = Some(candidate);
                break;
            }
            Err(error) if error.is_retryable_for_mapping_candidate() => continue,
            Err(error) => return Err(PagingError::MappingMutation(error)),
        }
    }
    let sibling_virtual_address =
        sibling_virtual_address.ok_or(PagingError::NoUnusedVirtualAddress)?;

    let alias_check = (|| -> Result<(), PagingError> {
        let mut alias_editor = KernelPageTableEditor::new_with_recursive_index(
            boot_info,
            sibling_virtual_address,
            recursive_index,
        )?;
        let alias = translate_with_editor(
            &mut alias_editor,
            root_table_physical,
            sibling_virtual_address,
        )
        .map_err(PagingError::Translation)?;
        if alias.physical_address != test.sibling_physical_page
            || alias.page_size != PAGE_SIZE
            || !alias.writable
            || alias.user_accessible
            || alias.executable
        {
            return Err(PagingError::LargePageDemotionFailed);
        }

        // SAFETY: the additional alias is a validated writable mapping of the
        // retained sibling frame. This value was written before the transition.
        let before_transition =
            unsafe { ptr::read_volatile(sibling_virtual_address as *const u64) };
        if before_transition != WX_SIBLING_PRE_TRANSITION_SENTINEL {
            return Err(PagingError::LargePageDemotionFailed);
        }

        // SAFETY: the mapped alias is writable and addresses the retained frame.
        unsafe {
            ptr::write_volatile(
                sibling_virtual_address as *mut u64,
                WX_SIBLING_ALIAS_WRITE_SENTINEL,
            );
        }
        // SAFETY: this reads the same frame through the separately validated direct map.
        let through_direct_map =
            unsafe { ptr::read_volatile(sibling_direct_alias as *const u64) };
        if through_direct_map != WX_SIBLING_ALIAS_WRITE_SENTINEL {
            return Err(PagingError::LargePageDemotionFailed);
        }

        // SAFETY: the direct-map leaf was verified writable, supervisor-only, NX.
        unsafe {
            ptr::write_volatile(
                sibling_direct_alias as *mut u64,
                WX_SIBLING_DIRECT_WRITE_SENTINEL,
            );
        }
        // SAFETY: independently read the write through the additional virtual alias.
        let through_test_alias =
            unsafe { ptr::read_volatile(sibling_virtual_address as *const u64) };
        if through_test_alias != WX_SIBLING_DIRECT_WRITE_SENTINEL {
            return Err(PagingError::LargePageDemotionFailed);
        }
        Ok(())
    })();

    // Never release the data frame while its additional alias is still present.
    let mut cleanup_editor = KernelPageTableEditor::new_with_recursive_index(
        boot_info,
        sibling_virtual_address,
        recursive_index,
    )?;
    let unmapped = unmap_4k(root_table_physical, sibling_virtual_address, &mut cleanup_editor)
        .map_err(PagingError::MappingMutation)?;
    invalidate_local_tlb(sibling_virtual_address);
    let mut verify_unmap_editor = KernelPageTableEditor::new_with_recursive_index(
        boot_info,
        sibling_virtual_address,
        recursive_index,
    )?;
    let after_unmap = translate_with_editor(
        &mut verify_unmap_editor,
        root_table_physical,
        sibling_virtual_address,
    );
    let removed_correctly = unmapped.physical_address == test.sibling_physical_page
        && unmapped.permissions == PagePermissions::new(true, false, false)
        && matches!(after_unmap, Err(PageTableError::NotPresent { .. }));
    if !removed_correctly {
        return Err(PagingError::LargePageDemotionFailed);
    }
    alias_check?;

    // The sibling's independent alias is removed and its TLB entry invalidated.
    // Its physical-offset alias remains writable/NX; the RX test frame stays owned.
    let sibling_frame = test
        .sibling_frame
        .take()
        .ok_or(PagingError::WxSiblingFrameUnavailable)?;
    release_data_frame(sibling_frame)?;
    Ok(())
}

/// Demotes a physical-offset leaf as needed, then removes write access using
/// break-before-make so a stale writable TLB translation cannot survive the
/// permission transition. It preserves the physical frame, cache/PAT/global and
/// A/D state, and republishes the leaf as read-only + NX.
fn restrict_physical_offset_alias_read_only_nx(
    boot_info: &BootInfo,
    root_table_physical: u64,
    virtual_address: u64,
    expected_physical_page: u64,
) -> Result<(), PagingError> {
    if !is_canonical_4level(virtual_address)
        || virtual_address & (PAGE_SIZE - 1) != 0
        || expected_physical_page & (PAGE_SIZE - 1) != 0
        || active_root_table_physical() != root_table_physical
    {
        return Err(PagingError::LargePageDemotionFailed);
    }

    let mut demotions = 0usize;
    loop {
        let mut editor = KernelPageTableEditor::new(boot_info, virtual_address)?;
        let translation = translate_with_editor(&mut editor, root_table_physical, virtual_address)
            .map_err(PagingError::Translation)?;
        if translation.physical_address != expected_physical_page || translation.user_accessible {
            return Err(PagingError::WxAuditFailed);
        }
        if translation.page_size == PAGE_SIZE {
            break;
        }
        if demotions >= 2
            || (translation.page_size != (1u64 << 21) && translation.page_size != (1u64 << 30))
        {
            return Err(PagingError::LargePageDemotionFailed);
        }
        let receipt = demote_large_page_for_address(boot_info, virtual_address)?
            .ok_or(PagingError::LargePageDemotionFailed)?;
        let receipt_end = receipt
            .physical_start
            .checked_add(receipt.virtual_length)
            .ok_or(PagingError::LargePageDemotionFailed)?;
        if receipt.virtual_length != translation.page_size
            || expected_physical_page < receipt.physical_start
            || expected_physical_page >= receipt_end
        {
            return Err(PagingError::LargePageDemotionFailed);
        }
        demotions += 1;
    }

    let mut editor = KernelPageTableEditor::new(boot_info, virtual_address)?;
    let (leaf_table_physical, leaf_index, leaf_entry) = {
        let mut table_physical = root_table_physical;
        let mut level = 4u8;
        loop {
            let index = virtual_index(virtual_address, level).ok_or(PagingError::WxAuditFailed)?;
            let entry = editor
                .read_entry(table_physical, index, level)
                .ok_or(PagingError::WxAuditFailed)?;
            if entry & PRESENT == 0 || (level == 4 && entry & LARGE_PAGE != 0) {
                return Err(PagingError::WxAuditFailed);
            }
            if level == 1 {
                break (table_physical, index, entry);
            }
            if entry & LARGE_PAGE != 0 {
                return Err(PagingError::LargePageDemotionFailed);
            }
            table_physical = entry & PHYSICAL_ADDRESS_MASK;
            if !valid_physical_page(table_physical, editor.physical_address_bits) {
                return Err(PagingError::WxAuditFailed);
            }
            level = level.checked_sub(1).ok_or(PagingError::WxAuditFailed)?;
        }
    };

    if leaf_entry & PHYSICAL_ADDRESS_MASK != expected_physical_page
        || leaf_entry & PRESENT == 0
        || leaf_entry & USER_ACCESSIBLE != 0
    {
        return Err(PagingError::WxAuditFailed);
    }
    // Even if the PTE already advertises RO+NX, repeat the break-before-make
    // sequence so a stale writable TLB entry cannot be mistaken for enforcement.
    const ACCESSED_DIRTY_MASK: u64 = (1 << 5) | (1 << 6);
    // First clear Present atomically. Retry only if the hardware monotonically
    // sets A/D; any other mutation fails before the entry is made non-present.
    compare_exchange_entry_with_ad_retry(
        leaf_entry,
        ATOMIC_ENTRY_CAS_MAX_ATTEMPTS,
        |expected| expected & !PRESENT,
        |expected, replacement| {
            editor
                .compare_exchange_entry(leaf_table_physical, leaf_index, 1, expected, replacement)
                .unwrap_or(Err(expected))
        },
    )
    .map_err(|_| PagingError::WxAuditFailed)?;

    // Once Present is cleared, any inability to complete the transition must
    // fail-stop: never return with a partially unpublished direct-map leaf.
    if super::address_space::switch_address_space_flush_local_tlb(root_table_physical).is_err() {
        panic!("W^X direct-map transition could not flush the retired writable translation");
    }
    let cleared = editor
        .read_entry(leaf_table_physical, leaf_index, 1)
        .unwrap_or_else(|| panic!("W^X direct-map leaf became inaccessible after invalidation"));
    if cleared & PRESENT != 0
        || cleared & !(PRESENT | ACCESSED_DIRTY_MASK)
            != leaf_entry & !(PRESENT | ACCESSED_DIRTY_MASK)
        || (cleared & ACCESSED_DIRTY_MASK & leaf_entry) != (leaf_entry & ACCESSED_DIRTY_MASK)
    {
        panic!("W^X direct-map leaf changed unexpectedly after invalidation");
    }

    let replacement = (cleared | PRESENT) & !WRITABLE | NO_EXECUTE;
    editor.write_entry(leaf_table_physical, leaf_index, 1, replacement);
    if super::address_space::switch_address_space_flush_local_tlb(root_table_physical).is_err() {
        panic!("W^X direct-map transition could not flush the republished read-only translation");
    }
    let final_entry = editor
        .read_entry(leaf_table_physical, leaf_index, 1)
        .unwrap_or_else(|| panic!("W^X direct-map leaf became inaccessible after publication"));
    if final_entry & PRESENT == 0
        || final_entry & PHYSICAL_ADDRESS_MASK != expected_physical_page
        || final_entry & WRITABLE != 0
        || final_entry & NO_EXECUTE == 0
        || final_entry & USER_ACCESSIBLE != 0
    {
        panic!("W^X direct-map leaf did not retain the expected read-only/NX mapping");
    }
    Ok(())
}

/// Exercises the live large-page demotion adapter against a real
/// physical-memory-offset mapping. The smoke test insists the selected frame
/// starts inside a large leaf, demotes 1 GiB -> 2 MiB -> 4 KiB as required, then
/// verifies the physical translation and effective permissions are preserved.
pub fn verify_large_page_demotion_smoke_test(boot_info: &BootInfo) -> Result<bool, PagingError> {
    let data_frame =
        super::memory::allocate_frame().map_err(|_| PagingError::FrameAllocationFailed)?;
    let data_physical = data_frame.physical_address();

    let test_result = (|| {
        let physical_memory_offset = match boot_info.physical_memory_offset {
            Optional::Some(offset) => offset,
            Optional::None => return Err(PagingError::PhysicalMemoryOffsetUnavailable),
        };
        let virtual_address = physical_memory_offset
            .checked_add(data_physical)
            .filter(|address| is_canonical_4level(*address) && (*address & (PAGE_SIZE - 1)) == 0)
            .ok_or(PagingError::PhysicalMemoryOffsetUnavailable)?;
        let root_table_physical = active_root_table_physical();
        let mut editor = KernelPageTableEditor::new(boot_info, virtual_address)?;
        let initial = translate_with_editor(&mut editor, root_table_physical, virtual_address)
            .map_err(PagingError::Translation)?;
        if initial.physical_address != data_physical
            || !initial.writable
            || initial.user_accessible
            || initial.executable
            || initial.page_size < PAGE_SIZE
        {
            return Err(PagingError::LargePageDemotionFailed);
        }

        // A bootloader may already have split this direct-map area. Do not fail
        // a valid boot or claim to have tested demotion when no large leaf exists.
        if initial.page_size == PAGE_SIZE {
            return Ok(false);
        }

        let expected_permissions = (
            initial.writable,
            initial.user_accessible,
            initial.executable,
        );
        let mut current = initial;
        let mut completed_demotions = 0usize;
        while current.page_size > PAGE_SIZE && completed_demotions < 2 {
            let expected_physical_start = current
                .physical_address
                .checked_sub(virtual_address & (current.page_size - 1))
                .ok_or(PagingError::LargePageDemotionFailed)?;
            let receipt = demote_large_page_for_address(boot_info, virtual_address)?
                .ok_or(PagingError::LargePageDemotionFailed)?;
            if receipt.virtual_length != current.page_size
                || receipt.physical_start != expected_physical_start
            {
                return Err(PagingError::LargePageDemotionFailed);
            }
            completed_demotions += 1;

            let mut check_editor = KernelPageTableEditor::new(boot_info, virtual_address)?;
            current =
                translate_with_editor(&mut check_editor, root_table_physical, virtual_address)
                    .map_err(PagingError::Translation)?;
            if current.physical_address != data_physical
                || (
                    current.writable,
                    current.user_accessible,
                    current.executable,
                ) != expected_permissions
                || current.page_size >= receipt.virtual_length
            {
                return Err(PagingError::LargePageDemotionFailed);
            }
        }
        if completed_demotions == 0 || current.page_size != PAGE_SIZE {
            return Err(PagingError::LargePageDemotionFailed);
        }

        let mut access_editor = KernelPageTableEditor::new(boot_info, virtual_address)?;
        let alias = access_editor
            .offset_alias(data_physical)
            .ok_or(PagingError::LargePageDemotionFailed)?;
        const DEMOTION_SMOKE_SENTINEL: u64 = 0x4445_4d4f_5445_5631;
        // SAFETY: the owned data frame still has a validated writable,
        // supervisor-only, NX direct-map alias and remains allocated.
        unsafe { ptr::write_volatile(alias.cast::<u64>(), DEMOTION_SMOKE_SENTINEL) };
        // SAFETY: the same checked alias is read immediately after the write.
        let observed = unsafe { ptr::read_volatile(alias.cast::<u64>()) };
        if observed != DEMOTION_SMOKE_SENTINEL {
            return Err(PagingError::LargePageDemotionFailed);
        }
        Ok(true)
    })();

    let release_result = release_data_frame(data_frame);
    if release_result.is_err() {
        return Err(PagingError::FrameReleaseFailed);
    }
    test_result
}

/// Holds the owned data frame and target VA for one dedicated QEMU protection test.
/// The frame token deliberately remains alive for as long as the mapping is used.
#[cfg(any(
    feature = "test-supervisor-write-protection",
    feature = "test-nx-protection"
))]
pub struct ProtectionTestMapping {
    pub virtual_address: u64,
    pub physical_address: u64,
    _frame: Frame,
}

#[cfg(any(
    feature = "test-supervisor-write-protection",
    feature = "test-nx-protection"
))]
struct ProtectionTestFrameGuard<'a> {
    boot_info: &'a BootInfo,
    frame: Option<Frame>,
    mapped_virtual_address: Option<u64>,
}

#[cfg(any(
    feature = "test-supervisor-write-protection",
    feature = "test-nx-protection"
))]
impl<'a> ProtectionTestFrameGuard<'a> {
    fn new(boot_info: &'a BootInfo, frame: Frame) -> Self {
        Self {
            boot_info,
            frame: Some(frame),
            mapped_virtual_address: None,
        }
    }

    fn physical_address(&self) -> u64 {
        self.frame
            .as_ref()
            .expect("protection test guard owns a frame")
            .physical_address()
    }

    fn mark_mapped(&mut self, virtual_address: u64) {
        self.mapped_virtual_address = Some(virtual_address);
    }

    fn into_frame(mut self) -> Frame {
        self.mapped_virtual_address = None;
        self.frame
            .take()
            .expect("protection test guard owns a frame")
    }
}

#[cfg(any(
    feature = "test-supervisor-write-protection",
    feature = "test-nx-protection"
))]
impl Drop for ProtectionTestFrameGuard<'_> {
    fn drop(&mut self) {
        let Some(frame) = self.frame.take() else {
            return;
        };

        if let Some(virtual_address) = self.mapped_virtual_address {
            let root = active_root_table_physical();
            let Ok(mut editor) = KernelPageTableEditor::new(self.boot_info, virtual_address) else {
                // Keep the allocator's ownership bit set if safe unmapping cannot
                // be proven; a leaked frame is safer than a dangling live mapping.
                let _unreleased_frame = frame;
                return;
            };
            match unmap_4k(root, virtual_address, &mut editor) {
                Ok(unmapped) => {
                    // unmap_4k has cleared the leaf entry. Flush the stale
                    // translation before checking identity or deciding whether
                    // the frame can be returned to the allocator.
                    invalidate_local_tlb(virtual_address);
                    if unmapped.physical_address == frame.physical_address() {
                        if let Err((_error, _frame)) = super::memory::free_frame(frame) {
                            // Keep the frame allocated on release failure; never panic
                            // while cleaning up a failed test setup.
                        }
                    } else {
                        // The mapping was removed, but the returned frame identity
                        // is unexpected. Do not recycle the frame we still own.
                        let _unreleased_frame = frame;
                    }
                }
                Err(_) => {
                    // Do not recycle a frame while its mapping state is uncertain.
                    let _unreleased_frame = frame;
                }
            }
        } else if let Err((_error, _frame)) = super::memory::free_frame(frame) {
            // The frame remains allocated if the allocator rejects release.
        }
    }
}

#[cfg(any(
    feature = "test-supervisor-write-protection",
    feature = "test-nx-protection"
))]
#[derive(Clone, Copy)]
enum ProtectionTestPayload {
    Sentinel,
    Ud2,
}

#[cfg(feature = "test-supervisor-write-protection")]
/// Prepare a supervisor-readable, supervisor-read-only mapping whose attempted
/// supervisor write must raise a protection-violation page fault.
pub fn install_supervisor_write_protection_test(
    boot_info: &BootInfo,
) -> Result<ProtectionTestMapping, PagingError> {
    prepare_protection_test_mapping(
        boot_info,
        // The sentinel is data: keep its leaf NX so the persistent writable
        // physical-memory alias cannot create a frame-wide W+X combination.
        PagePermissions::new(false, false, false),
        ProtectionTestPayload::Sentinel,
    )
}

#[cfg(feature = "test-nx-protection")]
/// Prepare a supervisor-readable, supervisor-read-only, NX mapping containing
/// UD2. A successful instruction fetch would therefore fail the test with #UD.
pub fn install_nx_execution_protection_test(
    boot_info: &BootInfo,
) -> Result<ProtectionTestMapping, PagingError> {
    prepare_protection_test_mapping(
        boot_info,
        PagePermissions::new(false, false, false),
        ProtectionTestPayload::Ud2,
    )
}

#[cfg(any(
    feature = "test-supervisor-write-protection",
    feature = "test-nx-protection"
))]
fn prepare_protection_test_mapping(
    boot_info: &BootInfo,
    protected_permissions: PagePermissions,
    payload: ProtectionTestPayload,
) -> Result<ProtectionTestMapping, PagingError> {
    let frame = super::memory::allocate_frame().map_err(|_| PagingError::FrameAllocationFailed)?;
    let mut frame_guard = ProtectionTestFrameGuard::new(boot_info, frame);
    let physical_address = frame_guard.physical_address();
    let recursive_index = match boot_info.recursive_index {
        Optional::Some(index) if is_safe_recursive_mapping_index(index) => index,
        Optional::Some(_) => {
            return Err(PagingError::InvalidRecursiveIndex);
        }
        Optional::None => {
            return Err(PagingError::RecursiveMappingUnavailable);
        }
    };
    let physical_memory_offset = match boot_info.physical_memory_offset {
        Optional::Some(offset) => offset,
        Optional::None => {
            return Err(PagingError::PhysicalMemoryOffsetUnavailable);
        }
    };
    let highest_physical_end = boot_info
        .memory_regions
        .iter()
        .map(|region| region.end)
        .max()
        .unwrap_or(0)
        .max(1u64 << 32);
    let Some(physical_mapping_end) = physical_memory_offset.checked_add(highest_physical_end)
    else {
        return Err(PagingError::PhysicalMemoryOffsetUnavailable);
    };
    let root_table_physical = active_root_table_physical();

    for candidate_pml4_index in FIRST_CANDIDATE_PML4_INDEX..512 {
        if candidate_pml4_index == recursive_index {
            continue;
        }
        let raw_candidate = u64::from(candidate_pml4_index) << 39;
        let candidate = raw_candidate | 0xffff_0000_0000_0000;
        if candidate >= physical_memory_offset && candidate < physical_mapping_end {
            continue;
        }

        let mut editor = match KernelPageTableEditor::new(boot_info, candidate) {
            Ok(editor) => editor,
            Err(error) => return Err(error),
        };

        // Initialize the owned Usable data frame through the checked physical-
        // memory-offset alias. This avoids a temporary VA mapping and unmap, so
        // a candidate that fails map_supervisor_4k's read-only preflight leaves the page-table
        // tree untouched and can safely be skipped.
        let direct_alias = editor
            .offset_alias(physical_address)
            .ok_or(PagingError::PhysicalMemoryOffsetUnavailable)?;
        // SAFETY: offset_alias verifies that this Usable frame is mapped to the
        // expected physical page and that the alias permits supervisor writes.
        unsafe {
            match payload {
                ProtectionTestPayload::Sentinel => {
                    ptr::write_volatile(direct_alias.cast::<u64>(), MAPPING_SMOKE_SENTINEL);
                }
                ProtectionTestPayload::Ud2 => {
                    // x86 UD2 encoding is 0x0f, 0x0b in little-endian order.
                    ptr::write_volatile(direct_alias.cast::<u16>(), 0x0b0f);
                }
            }
        }

        // SAFETY: frame_guard retains the frame token until the test mapping is
        // explicitly unmapped and the frame is released by the guard.
        match unsafe {
            map_supervisor_4k(
                root_table_physical,
                candidate,
                physical_address,
                protected_permissions,
                &mut editor,
            )
        } {
            Ok(()) => frame_guard.mark_mapped(candidate),
            Err(error) if error.is_retryable_for_mapping_candidate() => continue,
            Err(error) => return Err(PagingError::MappingMutation(error)),
        }
        invalidate_local_tlb(candidate);

        let entries = read_active_leaf_path(&mut editor, root_table_physical, candidate)?;
        let ancestor_permissions_valid = entries[..3]
            .iter()
            .all(|entry| entry & PRESENT != 0 && entry & WRITABLE != 0 && entry & NO_EXECUTE == 0);
        let leaf = entries[3];
        let leaf_permissions_valid = leaf & PRESENT != 0
            && leaf & PHYSICAL_ADDRESS_MASK == physical_address
            && leaf & WRITABLE == 0
            && leaf & USER_ACCESSIBLE == 0
            && (leaf & NO_EXECUTE != 0) == !protected_permissions.executable;
        let cr0: u64;
        // SAFETY: reading CR0 is valid in privileged x86_64 kernel execution.
        unsafe {
            asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        }
        if !ancestor_permissions_valid || !leaf_permissions_valid || cr0 & CR0_WP == 0 {
            return Err(PagingError::MappingSmokeMismatch);
        }

        let mapped_value_valid = match payload {
            // SAFETY: reads are allowed through the present supervisor read-only mapping.
            ProtectionTestPayload::Sentinel => unsafe {
                ptr::read_volatile(candidate as *const u64) == MAPPING_SMOKE_SENTINEL
            },
            // Data reads remain legal on NX pages; only instruction fetch is denied.
            ProtectionTestPayload::Ud2 => unsafe {
                ptr::read_volatile(candidate as *const u16) == 0x0b0f
            },
        };
        let translation = translate_with_editor(&mut editor, root_table_physical, candidate);
        let effective_permissions_valid = translation.is_ok_and(|result| {
            result.physical_address == physical_address
                && result.page_size == PAGE_SIZE
                && !result.writable
                && !result.user_accessible
                && result.executable == protected_permissions.executable
        });
        if !mapped_value_valid || !effective_permissions_valid {
            return Err(PagingError::MappingSmokeMismatch);
        }

        return Ok(ProtectionTestMapping {
            virtual_address: candidate,
            physical_address,
            _frame: frame_guard.into_frame(),
        });
    }

    Err(PagingError::NoUnusedVirtualAddress)
}

#[cfg(any(
    feature = "test-supervisor-write-protection",
    feature = "test-nx-protection"
))]
fn read_active_leaf_path(
    editor: &mut KernelPageTableEditor<'_>,
    root_table_physical: u64,
    virtual_address: u64,
) -> Result<[u64; 4], PagingError> {
    let mut entries = [0u64; 4];
    let mut table_physical = root_table_physical;
    for (position, level) in [4u8, 3, 2, 1].into_iter().enumerate() {
        let index =
            virtual_index(virtual_address, level).ok_or(PagingError::MappingSmokeMismatch)?;
        let entry = editor
            .read_entry(table_physical, index, level)
            .ok_or(PagingError::MappingSmokeMismatch)?;
        if entry & PRESENT == 0 || (level > 1 && entry & LARGE_PAGE != 0) {
            return Err(PagingError::MappingSmokeMismatch);
        }
        entries[position] = entry;
        if level > 1 {
            table_physical = entry & PHYSICAL_ADDRESS_MASK;
            if !valid_physical_page(table_physical, editor.physical_address_bits())
                || !editor.is_table_frame(table_physical)
            {
                return Err(PagingError::MappingSmokeMismatch);
            }
        }
    }
    Ok(entries)
}

#[cfg(feature = "test-vm-transitions")]
const TRANSITION_FIRST_SENTINEL: u64 = 0x4f4e_455f_564d_4131;
#[cfg(feature = "test-vm-transitions")]
const TRANSITION_SECOND_SENTINEL: u64 = 0x4f4e_455f_564d_4232;

#[cfg(feature = "test-vm-transitions")]
#[derive(Clone, Copy, Eq, PartialEq)]
enum TransitionTestState {
    Unmapped,
    FirstMapped,
    UnmappedAfterFirst,
    SecondMapped,
    UnmappedAfterSecond,
}

/// Releases a test frame unless setup transfers its ownership into the test context.
#[cfg(feature = "test-vm-transitions")]
struct TransitionTestFrameGuard(Option<Frame>);

#[cfg(feature = "test-vm-transitions")]
impl TransitionTestFrameGuard {
    fn new(frame: Frame) -> Self {
        Self(Some(frame))
    }

    fn physical_address(&self) -> u64 {
        self.0
            .as_ref()
            .expect("guard owns a frame")
            .physical_address()
    }

    fn into_frame(mut self) -> Frame {
        self.0.take().expect("guard owns a frame")
    }

    fn disarm(mut self) {
        // Used only if allocator uniqueness is violated and the address appears twice.
        // Do not attempt to return two tokens that alias the same physical frame.
        let _ = self.0.take();
    }
}

#[cfg(feature = "test-vm-transitions")]
impl Drop for TransitionTestFrameGuard {
    fn drop(&mut self) {
        if let Some(frame) = self.0.take() {
            if let Err((_error, _frame)) = super::memory::free_frame(frame) {
                // Do not panic while handling a test setup error. On cleanup failure,
                // the allocator still regards the frame as allocated, so it is safer
                // to leave that capacity unavailable than risk a double release.
            }
        }
    }
}

/// Owns both data frames for the dedicated active map/unmap/remap QEMU case.
/// The same virtual address is first mapped to one frame and then to a distinct
/// frame so stale TLB translations are observable as stale payload data.
#[cfg(feature = "test-vm-transitions")]
pub struct MappingTransitionTest {
    pub virtual_address: u64,
    pub first_physical_address: u64,
    pub second_physical_address: u64,
    first_frame: Frame,
    second_frame: Frame,
    state: TransitionTestState,
}

#[cfg(feature = "test-vm-transitions")]
pub fn prepare_mapping_transition_test(
    boot_info: &BootInfo,
) -> Result<MappingTransitionTest, PagingError> {
    let first_frame = TransitionTestFrameGuard::new(
        super::memory::allocate_frame().map_err(|_| PagingError::FrameAllocationFailed)?,
    );
    let second_frame = TransitionTestFrameGuard::new(
        super::memory::allocate_frame().map_err(|_| PagingError::FrameAllocationFailed)?,
    );
    let first_physical_address = first_frame.physical_address();
    let second_physical_address = second_frame.physical_address();
    if first_physical_address == second_physical_address {
        // A duplicate address violates allocator uniqueness. Release only one
        // token so this failure path cannot attempt a duplicate free.
        second_frame.disarm();
        return Err(PagingError::MappingSmokeMismatch);
    }

    let recursive_index = match boot_info.recursive_index {
        Optional::Some(index) if is_safe_recursive_mapping_index(index) => index,
        Optional::Some(_) => return Err(PagingError::InvalidRecursiveIndex),
        Optional::None => return Err(PagingError::RecursiveMappingUnavailable),
    };
    let physical_memory_offset = match boot_info.physical_memory_offset {
        Optional::Some(offset) => offset,
        Optional::None => return Err(PagingError::PhysicalMemoryOffsetUnavailable),
    };
    let highest_physical_end = boot_info
        .memory_regions
        .iter()
        .map(|region| region.end)
        .max()
        .unwrap_or(0)
        .max(1u64 << 32);
    let Some(physical_mapping_end) = physical_memory_offset.checked_add(highest_physical_end)
    else {
        return Err(PagingError::PhysicalMemoryOffsetUnavailable);
    };
    let root_table_physical = active_root_table_physical();

    // Select a canonical high-half VA whose translation is currently absent.
    // Exclude the recursive PML4 slot and the complete bootloader direct-map
    // range before any page-table mutation is attempted.
    for candidate_pml4_index in FIRST_CANDIDATE_PML4_INDEX..512 {
        if candidate_pml4_index == recursive_index {
            continue;
        }
        let raw_candidate = u64::from(candidate_pml4_index) << 39;
        let candidate = raw_candidate | 0xffff_0000_0000_0000;
        if candidate >= physical_memory_offset && candidate < physical_mapping_end {
            continue;
        }
        let Ok(mut editor) = KernelPageTableEditor::new(boot_info, candidate) else {
            return Err(PagingError::MappingSmokeMismatch);
        };
        match translate_with_editor(&mut editor, root_table_physical, candidate) {
            Err(PageTableError::NotPresent { .. }) => {
                return Ok(MappingTransitionTest {
                    virtual_address: candidate,
                    first_physical_address,
                    second_physical_address,
                    first_frame: first_frame.into_frame(),
                    second_frame: second_frame.into_frame(),
                    state: TransitionTestState::Unmapped,
                });
            }
            // A recursive alias may be unavailable for this candidate without
            // implying that the active page tables are malformed. Keep searching.
            Err(error) if error.is_retryable_for_mapping_candidate() => continue,
            // Structural translation errors must never be treated as an empty slot.
            Err(error) => return Err(PagingError::Translation(error)),
            Ok(_) => {}
        }
    }

    Err(PagingError::NoUnusedVirtualAddress)
}

#[cfg(feature = "test-vm-transitions")]
impl MappingTransitionTest {
    pub fn map_first(&mut self, boot_info: &BootInfo) -> Result<(), PagingError> {
        if self.state != TransitionTestState::Unmapped {
            return Err(PagingError::MappingSmokeMismatch);
        }
        self.map_frame(boot_info, self.first_physical_address)?;
        self.state = TransitionTestState::FirstMapped;
        Ok(())
    }

    pub fn verify_first(&mut self, boot_info: &BootInfo) -> Result<(), PagingError> {
        if self.state != TransitionTestState::FirstMapped {
            return Err(PagingError::MappingSmokeMismatch);
        }
        // SAFETY: map_first installed a writable supervisor-only mapping to the
        // owned first frame and invalidated the target VA in the local TLB.
        unsafe {
            ptr::write_volatile(self.virtual_address as *mut u64, TRANSITION_FIRST_SENTINEL);
        }
        let observed = unsafe { ptr::read_volatile(self.virtual_address as *const u64) };
        if observed != TRANSITION_FIRST_SENTINEL {
            return Err(PagingError::MappingSmokeMismatch);
        }
        self.verify_translation(boot_info, self.first_physical_address)
    }

    pub fn unmap_first(&mut self, boot_info: &BootInfo) -> Result<(), PagingError> {
        if self.state != TransitionTestState::FirstMapped {
            return Err(PagingError::MappingSmokeMismatch);
        }
        self.unmap_frame(boot_info, self.first_physical_address)?;
        self.state = TransitionTestState::UnmappedAfterFirst;
        Ok(())
    }

    pub fn map_second(&mut self, boot_info: &BootInfo) -> Result<(), PagingError> {
        if self.state != TransitionTestState::UnmappedAfterFirst {
            return Err(PagingError::MappingSmokeMismatch);
        }
        let root_table_physical = active_root_table_physical();
        let mut editor = KernelPageTableEditor::new(boot_info, self.virtual_address)?;
        let direct_alias = editor
            .offset_alias(self.second_physical_address)
            .ok_or(PagingError::PhysicalMemoryOffsetUnavailable)?;
        // Initialize the second frame through its checked direct-map alias
        // before remapping the same VA. If INVLPG is missing after remap, the
        // stale translation still reads the first frame's different sentinel.
        unsafe {
            ptr::write_volatile(direct_alias.cast::<u64>(), TRANSITION_SECOND_SENTINEL);
        }
        // SAFETY: MappingTransitionTest retains both frame tokens until after
        // the corresponding mappings are removed and the test is finished.
        unsafe {
            map_supervisor_4k(
                root_table_physical,
                self.virtual_address,
                self.second_physical_address,
                PagePermissions::new(true, false, false),
                &mut editor,
            )
        }
        .map_err(PagingError::MappingMutation)?;
        invalidate_local_tlb(self.virtual_address);
        self.state = TransitionTestState::SecondMapped;
        Ok(())
    }

    pub fn verify_second(&mut self, boot_info: &BootInfo) -> Result<(), PagingError> {
        if self.state != TransitionTestState::SecondMapped {
            return Err(PagingError::MappingSmokeMismatch);
        }
        // Do not write through the test VA before checking: the preloaded second
        // sentinel detects stale TLB translations to the first physical frame.
        let observed = unsafe { ptr::read_volatile(self.virtual_address as *const u64) };
        if observed != TRANSITION_SECOND_SENTINEL {
            return Err(PagingError::MappingSmokeMismatch);
        }
        self.verify_translation(boot_info, self.second_physical_address)
    }

    pub fn unmap_second(&mut self, boot_info: &BootInfo) -> Result<(), PagingError> {
        if self.state != TransitionTestState::SecondMapped {
            return Err(PagingError::MappingSmokeMismatch);
        }
        self.unmap_frame(boot_info, self.second_physical_address)?;
        self.state = TransitionTestState::UnmappedAfterSecond;
        Ok(())
    }

    pub fn finish(self) -> Result<(), PagingError> {
        if self.state != TransitionTestState::UnmappedAfterSecond {
            return Err(PagingError::MappingSmokeMismatch);
        }
        release_data_frame(self.first_frame)?;
        release_data_frame(self.second_frame)
    }

    fn map_frame(
        &mut self,
        boot_info: &BootInfo,
        physical_address: u64,
    ) -> Result<(), PagingError> {
        let root_table_physical = active_root_table_physical();
        let mut editor = KernelPageTableEditor::new(boot_info, self.virtual_address)?;
        // SAFETY: MappingTransitionTest retains the frame token until the
        // corresponding mapping is removed and the test is finished.
        unsafe {
            map_supervisor_4k(
                root_table_physical,
                self.virtual_address,
                physical_address,
                PagePermissions::new(true, false, false),
                &mut editor,
            )
        }
        .map_err(PagingError::MappingMutation)?;
        invalidate_local_tlb(self.virtual_address);
        Ok(())
    }

    fn unmap_frame(
        &mut self,
        boot_info: &BootInfo,
        physical_address: u64,
    ) -> Result<(), PagingError> {
        let root_table_physical = active_root_table_physical();
        let mut editor = KernelPageTableEditor::new(boot_info, self.virtual_address)?;
        let removed = unmap_4k(root_table_physical, self.virtual_address, &mut editor)
            .map_err(PagingError::MappingMutation)?;
        invalidate_local_tlb(self.virtual_address);
        if removed.physical_address != physical_address
            || removed.permissions != PagePermissions::new(true, false, false)
            || !matches!(
                translate_with_editor(&mut editor, root_table_physical, self.virtual_address),
                Err(PageTableError::NotPresent { .. })
            )
        {
            return Err(PagingError::MappingSmokeMismatch);
        }
        Ok(())
    }

    fn verify_translation(
        &mut self,
        boot_info: &BootInfo,
        expected_physical_address: u64,
    ) -> Result<(), PagingError> {
        let root_table_physical = active_root_table_physical();
        let mut editor = KernelPageTableEditor::new(boot_info, self.virtual_address)?;
        let translation =
            translate_with_editor(&mut editor, root_table_physical, self.virtual_address)
                .map_err(PagingError::Translation)?;
        if translation.physical_address != expected_physical_address
            || translation.page_size != PAGE_SIZE
            || !translation.writable
            || translation.user_accessible
            || translation.executable
        {
            return Err(PagingError::MappingSmokeMismatch);
        }
        Ok(())
    }
}

fn invalidate_local_tlb(virtual_address: u64) {
    // SAFETY: INVLPG is available in the current x86_64 kernel and operates on
    // the target virtual address in the local CPU's translation cache.
    unsafe {
        asm!(
            "invlpg [{}]",
            in(reg) virtual_address,
            options(nostack, preserves_flags)
        );
    }
}

fn release_data_frame(frame: Frame) -> Result<(), PagingError> {
    match super::memory::free_frame(frame) {
        Ok(()) => Ok(()),
        Err((_error, _frame)) => Err(PagingError::FrameReleaseFailed),
    }
}

/// Releases a rejected W^X scan candidate without rewinding the allocator hint.
#[cfg(feature = "test-wx-runtime-audit")]
fn release_data_frame_preserving_hint(frame: Frame) -> Result<(), PagingError> {
    match super::memory::free_frame_preserving_hint(frame) {
        Ok(()) => Ok(()),
        Err((_error, _frame)) => Err(PagingError::FrameReleaseFailed),
    }
}
