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

use bootloader_api::info::{MemoryRegion, MemoryRegionKind, Optional};
use bootloader_api::BootInfo;
use oneos_core::{
    is_canonical_4level, map_4k, physical_page_is_in_allowed_region, recursive_entry_matches_root,
    recursive_table_page_virtual_address, translate_4level, unmap_4k, validate_cr0_write_protect,
    validate_efer_nx_enable, validate_extended_cpuid_leaf, validate_paging_cpu_capabilities, Frame,
    FrameRegistryError, PagePermissions, PageTableEditor, PageTableError, PageTableFrameRegistry,
    PageTableMutationError, PageTranslation, PagingPreconditionError, PAGE_SIZE,
};

const CR0_WP: u64 = 1 << 16;
const CR4_LA57: u64 = 1 << 12;
const EFER_MSR: u32 = 0xc000_0080;
const EFER_NXE: u64 = 1 << 11;
const CPUID_EXTENDED_FEATURES: u32 = 0x8000_0001;
const CPUID_PHYSICAL_ADDRESS_WIDTH: u32 = 0x8000_0008;
const WRITABLE: u64 = 1 << 1;
#[cfg(any(
    feature = "test-supervisor-write-protection",
    feature = "test-nx-protection"
))]
const USER_ACCESSIBLE: u64 = 1 << 2;
const PRESENT: u64 = 1;
const LARGE_PAGE: u64 = 1 << 7;
#[cfg(any(
    feature = "test-supervisor-write-protection",
    feature = "test-nx-protection"
))]
const NO_EXECUTE: u64 = 1 << 63;
const PHYSICAL_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const TABLE_FRAME_CAPACITY: usize = 512;
const FIRST_CANDIDATE_PML4_INDEX: u16 = 256;
const MAPPING_SMOKE_SENTINEL: u64 = 0x4f4e_454f_5356_4d31;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageTableInspection {
    pub root_table_physical: u64,
    pub validated_mappings: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PagingError {
    RecursiveMappingUnavailable,
    InvalidRecursiveIndex,
    InvalidRecursiveMapping,
    UnsupportedFiveLevelPaging,
    SupervisorWriteProtectionDisabled,
    UnsupportedNx,
    ExtendedCpuidLeafUnavailable {
        required_leaf: u32,
        maximum_leaf: u32,
    },
    NxEnableDisabled,
    InvalidPhysicalAddressWidth { bits: u8 },
    PhysicalMemoryOffsetUnavailable,
    InterruptsEnabled,
    FrameAllocationFailed,
    FrameReleaseFailed,
    NoUnusedVirtualAddress,
    MappingSmokeMismatch,
    MappingMutation(PageTableMutationError),
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
            Self::InvalidRecursiveMapping => {
                b"Recursive mapping entry does not reference the CR3 PML4 frame\n"
            }
            Self::InvalidKernelImageRange => b"BootInfo kernel image range is invalid\n",
            Self::InvalidKernelCodeMapping => {
                b"Kernel code translation is outside the ELF backing interval or has unexpected page-table permissions\n"
            }
            Self::InvalidStackMapping => {
                b"Kernel stack pointer is outside the expected virtual range or has unexpected page offset/page-table permissions\n"
            }
            Self::InvalidBootInfoMapping => {
                b"BootInfo mapping has an unexpected page offset or page-table permissions\n"
            }
            Self::UnsupportedFiveLevelPaging => {
                b"Five-level paging is not supported by this inspector\n"
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
            Self::NoUnusedVirtualAddress => b"No unused virtual address was available for the mapping smoke test\n",
            Self::MappingSmokeMismatch => b"Active page-table map/unmap smoke test failed\n",
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
    let recursive_index = match boot_info.recursive_index {
        Optional::Some(index) => index,
        Optional::None => return Err(PagingError::RecursiveMappingUnavailable),
    };
    if recursive_index >= 512 {
        return Err(PagingError::InvalidRecursiveIndex);
    }

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
    // in-memory ELF slice using each PT_LOAD p_offset. A virtual offset is not
    // generally equal to that file offset, so validate against the ELF backing
    // interval rather than deriving a physical address from the virtual offset.
    let stack_end = boot_info
        .kernel_stack_bottom
        .checked_add(boot_info.kernel_stack_len)
        .filter(|_| boot_info.kernel_stack_len != 0)
        .ok_or(PagingError::InvalidStackMapping)?;
    if stack_pointer < boot_info.kernel_stack_bottom || stack_pointer >= stack_end {
        return Err(PagingError::InvalidStackMapping);
    }

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

    let stack_translation =
        translate_virtual_address(stack_pointer, root_table_physical, recursive_index, regions)
            .map_err(PagingError::Translation)?;
    if !translation_preserves_page_offset(stack_pointer, stack_translation)
        || !stack_translation.writable
        || stack_translation.user_accessible
        || stack_translation.executable
    {
        return Err(PagingError::InvalidStackMapping);
    }

    let boot_info_translation = translate_virtual_address(
        boot_info_address,
        root_table_physical,
        recursive_index,
        regions,
    )
    .map_err(PagingError::Translation)?;
    if !translation_preserves_page_offset(boot_info_address, boot_info_translation)
        || !boot_info_translation.writable
        || boot_info_translation.user_accessible
        || boot_info_translation.executable
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

/// Checks the bootloader-provided recursive PML4 self-reference before walking other entries.
///
/// The first volatile read necessarily relies on BootInfo's contract: when the recursive
/// mapping is requested, the reported index maps the active PML4 frame back into itself.
/// This check catches a readable but inconsistent entry; it cannot make an absent or broken
/// recursive virtual mapping safe to probe without potentially taking a page fault.
fn validate_recursive_mapping_entry(recursive_index: u16, root_table_physical: u64) -> bool {
    let Some(table_virtual) = recursive_table_page_virtual_address(recursive_index, 0, 4) else {
        return false;
    };
    let Some(entry_offset) = u64::from(recursive_index).checked_mul(8) else {
        return false;
    };
    let Some(entry_virtual) = table_virtual.checked_add(entry_offset) else {
        return false;
    };
    if !is_canonical_4level(entry_virtual) || entry_virtual & 7 != 0 {
        return false;
    }
    let Ok(entry_pointer) = usize::try_from(entry_virtual) else {
        return false;
    };

    // SAFETY: this access depends on the bootloader API's recursive-index guarantee,
    // and the physical CR3 frame was already confirmed to be a full Bootloader-owned page.
    // The value read is then checked against the physical CR3 root frame.
    let entry = unsafe { ptr::read_volatile(entry_pointer as *const u64) };
    recursive_entry_matches_root(entry, root_table_physical)
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
    }
}

struct TableFrameRegistry {
    registry: core::cell::UnsafeCell<PageTableFrameRegistry<Frame, TABLE_FRAME_CAPACITY>>,
}

// SAFETY: mutations are permitted only during single-CPU bootstrap with
// maskable interrupts disabled. SMP must add cross-CPU synchronization first.
unsafe impl Sync for TableFrameRegistry {}

impl TableFrameRegistry {
    const fn new() -> Self {
        Self {
            registry: core::cell::UnsafeCell::new(PageTableFrameRegistry::new()),
        }
    }
}

static TABLE_FRAMES: TableFrameRegistry = TableFrameRegistry::new();

fn reserve_table_frame_slot() -> Option<usize> {
    // SAFETY: this mutation is only used in the single-core, interrupts-disabled
    // bootstrap mapping path, before SMP is introduced.
    unsafe { &mut *TABLE_FRAMES.registry.get() }.reserve_slot()
}

fn clear_reserved_table_frame_slot(index: usize) {
    // SAFETY: registry mutations are serialized by the single-core,
    // interrupts-disabled bootstrap precondition.
    if unsafe { &mut *TABLE_FRAMES.registry.get() }
        .cancel_reservation(index)
        .is_err()
    {
        panic!("page-table frame registry reservation invariant violated");
    }
}

fn install_table_frame(index: usize, frame: Frame) {
    // SAFETY: registry mutations are serialized by the single-core,
    // interrupts-disabled bootstrap precondition.
    if let Err((_error, _frame)) =
        unsafe { &mut *TABLE_FRAMES.registry.get() }.install_reserved(index, frame)
    {
        panic!("page-table frame registry reservation invariant violated");
    }
}

fn registered_table_frame(physical_address: u64) -> bool {
    // SAFETY: the registry is read only under the same single-core bootstrap
    // contract as its mutations.
    unsafe { &*TABLE_FRAMES.registry.get() }.contains(physical_address)
}

fn unpublished_table_frame(physical_address: u64) -> bool {
    // SAFETY: the registry is read only under the same single-core bootstrap
    // contract as its mutations.
    unsafe { &*TABLE_FRAMES.registry.get() }.contains_unpublished(physical_address)
}

fn mark_table_frame_published(physical_address: u64) {
    // SAFETY: registry mutations are serialized by the single-core,
    // interrupts-disabled bootstrap precondition. Bootloader-owned frames are
    // not in this registry, so their expected lookup miss is intentionally ignored.
    let _ = unsafe { &mut *TABLE_FRAMES.registry.get() }.mark_published(physical_address);
}

fn release_registered_table_frame(physical_address: u64) {
    // SAFETY: registry mutations are serialized by the single-core,
    // interrupts-disabled bootstrap precondition.
    let frame = match unsafe { &mut *TABLE_FRAMES.registry.get() }
        .take_unpublished(physical_address)
    {
        Ok(frame) => frame,
        Err(FrameRegistryError::PublishedFrame) => {
            panic!("attempted to release a published page-table frame")
        }
        Err(FrameRegistryError::FrameNotFound) => {
            panic!("attempted to release an unregistered page-table frame")
        }
        Err(FrameRegistryError::InvalidReservation | FrameRegistryError::DuplicateFrameAddress) => {
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
}

impl<'a> KernelPageTableEditor<'a> {
    fn new(boot_info: &'a BootInfo, target_virtual_address: u64) -> Result<Self, PagingError> {
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

        let recursive_index = match boot_info.recursive_index {
            Optional::Some(index) if index < 512 => index,
            Optional::Some(_) => return Err(PagingError::InvalidRecursiveIndex),
            Optional::None => return Err(PagingError::RecursiveMappingUnavailable),
        };
        let physical_memory_offset = match boot_info.physical_memory_offset {
            Optional::Some(offset) => offset,
            Optional::None => return Err(PagingError::PhysicalMemoryOffsetUnavailable),
        };
        let root_table_physical = active_root_table_physical();
        if root_table_physical == 0
            || root_table_physical & (PAGE_SIZE - 1) != 0
            || !is_bootloader_owned_page(&boot_info.memory_regions, root_table_physical)
        {
            return Err(PagingError::InvalidRootTable);
        }

        // SAFETY: the maximum extended leaf and NX support were checked during
        // initialize_paging_controls; read the width from the same CPU.
        let physical_address_bits = (__cpuid(CPUID_PHYSICAL_ADDRESS_WIDTH).eax & 0xff) as u8;
        if !(32..=52).contains(&physical_address_bits) {
            return Err(PagingError::InvalidPhysicalAddressWidth {
                bits: physical_address_bits,
            });
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
    }

    fn offset_alias(&self, physical_address: u64) -> Option<*mut u8> {
        if !self.is_usable_frame(physical_address) {
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
        let translation = translate_virtual_address(
            address,
            self.root_table_physical,
            self.recursive_index,
            self.regions,
        )
        .ok()?;
        if translation.physical_address != physical_address || !translation.writable {
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

    fn entry_pointer(
        &self,
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

    fn mark_reachable_table_frames(&self) {
        // The root publication makes each staged table reachable. Record all
        // allocator-owned frames on this virtual path, not just the first child.
        for level in 1..=3 {
            if let Some(physical_address) = self.reachable_table_physical(level) {
                mark_table_frame_published(physical_address);
            }
        }
    }
}

impl PageTableEditor for KernelPageTableEditor<'_> {
    fn physical_address_bits(&self) -> u8 {
        self.physical_address_bits
    }

    fn read_entry(&mut self, table_physical: u64, index: usize, level: u8) -> Option<u64> {
        let (pointer, _reachable) = self.entry_pointer(table_physical, index, level)?;
        // SAFETY: entry_pointer validated the alias and alignment. Reachable
        // tables have writable ancestors; unlinked tables are owned Usable frames
        // accessed through the checked physical-memory offset.
        Some(unsafe { ptr::read_volatile(pointer) })
    }

    fn write_entry(&mut self, table_physical: u64, index: usize, level: u8, value: u64) {
        let (pointer, reachable) = self
            .entry_pointer(table_physical, index, level)
            .unwrap_or_else(|| panic!("page-table write destination failed preflight"));
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
            // This is emitted before map_4k can publish the parent entry.
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
    let mut level = 4u8;
    translate_4level(virtual_address, root_table_physical, |table, index| {
        let current_level = level;
        level = level.saturating_sub(1);
        editor.read_entry(table, index, current_level)
    })
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
        Optional::Some(index) => index,
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
        match map_4k(
            root_table_physical,
            candidate,
            data_physical,
            permissions,
            &mut editor,
        ) {
            Ok(()) => {
                invalidate_local_tlb(candidate);
                // SAFETY: map_4k installed a writable, supervisor-only mapping to
                // the allocated frame and the new translation has been invalidated.
                unsafe {
                    ptr::write_volatile(candidate as *mut u64, MAPPING_SMOKE_SENTINEL);
                }
                // SAFETY: the same validated mapping is immediately read back.
                let observed = unsafe { ptr::read_volatile(candidate as *const u64) };
                let translation =
                    translate_with_editor(&mut editor, root_table_physical, candidate);
                let mapped_correctly = observed == MAPPING_SMOKE_SENTINEL
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
                // map_4k reports these failures during its read-only preflight,
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
        PagePermissions::new(false, false, true),
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
    let physical_address = frame.physical_address();
    let recursive_index = match boot_info.recursive_index {
        Optional::Some(index) if index < 512 => index,
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
        // a candidate that fails map_4k's read-only preflight leaves the page-table
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

        match map_4k(
            root_table_physical,
            candidate,
            physical_address,
            protected_permissions,
            &mut editor,
        ) {
            Ok(()) => {}
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
            _frame: frame,
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
        Optional::Some(index) if index < 512 => index,
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
        map_4k(
            root_table_physical,
            self.virtual_address,
            self.second_physical_address,
            PagePermissions::new(true, false, false),
            &mut editor,
        )
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
        map_4k(
            root_table_physical,
            self.virtual_address,
            physical_address,
            PagePermissions::new(true, false, false),
            &mut editor,
        )
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
