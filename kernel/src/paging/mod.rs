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
    elf64_program_header_table_range, frame_wx_audit_leaf_extent, frame_wx_audit_snapshot_matches,
    frame_wx_audit_table_path_is_unique, initialize_user_frame, is_canonical_4level,
    is_safe_recursive_mapping_index, map_supervisor_4k, map_user_data_page,
    parse_elf64_load_segments, physical_page_is_in_allowed_region,
    recursive_entry_is_valid_kernel_root, recursive_entry_matches_root,
    recursive_table_page_virtual_address, reserve_bootstrap_backing_frame,
    shared_recursive_slots_are_valid, translate_4level, unmap_4k, unmap_all_user_data_pages,
    validate_cr0_write_protect, validate_efer_nx_enable, validate_extended_cpuid_leaf,
    validate_paging_cpu_capabilities, ActiveAddressSpaceRoot, AddressSpaceRoot,
    BootstrapBackingKind, BootstrapFrameReservationError, Elf64LoadImage, Frame,
    FrameRegistryError, FrameWxAudit, FrameWxAuditEffectivePermissions, FrameWxAuditScope,
    FrameWxAuditScopeSummary, FrameWxAuditSource, FrameWxAuditSummary, FrameWxAuditTableBudget,
    FrameWxDirectMapCoverage, FrameWxDirectMapCoverageSummary, FrameWxError, FrameWxPermissions,
    FrameWxRegistry, LargePageDemotionEditor, LargePageDemotionReceipt, PagePermissions,
    PageTableEditor, PageTableError, PageTableFrameRegistry, PageTableMutationError,
    PageTranslation, PagingPreconditionError, PublishedFrameReleaseError,
    SharedRecursiveSlotEntries, UserAddressSpaceEditor, UserFrameInitializationError,
    UserFrameInitializer, UserPageMappingError, UserPageMappingRegistry, UserPageTeardownFailure,
    ZeroedFrame, ATOMIC_ENTRY_CAS_MAX_ATTEMPTS, ELF64_HEADER_SIZE, ELF64_PROGRAM_HEADER_SIZE,
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
// Bounds the separate all-table path inventory; duplicates and exhaustion fail closed.
const MAX_WX_AUDIT_TABLE_PATHS: usize = 2048;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageTableInspection {
    pub root_table_physical: u64,
    pub validated_mappings: usize,
    /// Read-only inventory of writable/executable aliases observed across the declared roots.
    pub wx_audit: FrameWxAuditSummary,
    /// Coverage of the active root plus registered roots, with shared upper halves verified.
    pub wx_audit_scope: FrameWxAuditScopeSummary<MAX_WX_AUDIT_ROOTS>,
    /// Complete physical-memory-offset range checked for exact translation and NX permissions.
    pub wx_direct_map_coverage: FrameWxDirectMapCoverageSummary,
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
            if reserved
                && matches!(
                    crate::memory::is_permanently_reserved(physical_page),
                    Ok(true)
                )
            {
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
        Ok(()) if kind == BootstrapBackingKind::Bootloader => Ok(()),
        Ok(()) => {
            // Prove that a successful Usable-frame reservation was also recorded
            // in the side metadata used by ordinary mapping-target validation.
            if matches!(
                crate::memory::is_permanently_reserved(physical_page),
                Ok(true)
            ) {
                Ok(())
            } else {
                Err(PagingError::BootstrapFrameReservationFailed)
            }
        }
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

mod editor;
mod inspection;

pub(super) use editor::{
    audit_registered_wx_roots, enforce_kernel_executable_alias_wx,
    has_pending_detached_private_table, initialize_paging_controls,
    map_test_user_page_for_teardown, register_address_space_root,
    registered_published_page_table_frame, teardown_inactive_user_address_space,
    teardown_inactive_user_address_space_with_table_release, unregister_address_space_root,
    validate_inactive_user_address_space, verify_large_page_demotion_smoke_test,
    verify_mapping_smoke_test, verify_teardown_corruption_preflight_for_smoke,
    verify_user_frame_zeroing_test_with_recursive_index, InactiveAddressSpaceTeardownError,
};
pub(super) use inspection::inspect_boot_mappings;

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
pub(super) use editor::verify_user_frame_zeroing_test;

#[cfg(feature = "test-wx-runtime-audit")]
pub(super) use editor::{
    apply_wx_sibling_test_transition, kernel_executable_direct_alias_for_test,
    verify_wx_sibling_large_page_precondition, verify_wx_sibling_test_after_transition,
    WxSiblingRegressionTest,
};

#[cfg(any(
    feature = "test-supervisor-write-protection",
    feature = "test-nx-protection"
))]
pub(super) use editor::ProtectionTestMapping;

#[cfg(feature = "test-supervisor-write-protection")]
pub(super) use editor::install_supervisor_write_protection_test;

#[cfg(feature = "test-nx-protection")]
pub(super) use editor::install_nx_execution_protection_test;

#[cfg(feature = "test-vm-transitions")]
pub(super) use editor::{prepare_mapping_transition_test, MappingTransitionTest};
