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
    recursive_table_page_virtual_address, translate_4level, unmap_4k, Frame, PagePermissions,
    PageTableEditor, PageTableError, PageTableMutationError, PageTranslation, PAGE_SIZE,
};

const CR0_WP: u64 = 1 << 16;
const CR4_LA57: u64 = 1 << 12;
const EFER_MSR: u32 = 0xc000_0080;
const EFER_NXE: u64 = 1 << 11;
const CPUID_EXTENDED_FEATURES: u32 = 0x8000_0001;
const CPUID_PHYSICAL_ADDRESS_WIDTH: u32 = 0x8000_0008;
const NX_FEATURE: u32 = 1 << 20;
const WRITABLE: u64 = 1 << 1;
const PRESENT: u64 = 1;
const LARGE_PAGE: u64 = 1 << 7;
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
                b"CR0.WP is disabled; supervisor writes may bypass read-only page-table entries\\n"
            }
            Self::UnsupportedNx => b"CPU does not expose the required NX feature\\n",
            Self::InvalidPhysicalAddressWidth { .. } => {
                b"CPU reported an unsupported physical-address width\\n"
            }
            Self::PhysicalMemoryOffsetUnavailable => {
                b"Bootloader did not provide a physical-memory offset\\n"
            }
            Self::InterruptsEnabled => {
                b"Page-table mutation requires maskable interrupts to remain disabled\\n"
            }
            Self::FrameAllocationFailed => b"Could not allocate a data frame for the mapping smoke test\\n",
            Self::FrameReleaseFailed => b"Could not release the mapping smoke-test frame\\n",
            Self::NoUnusedVirtualAddress => b"No unused virtual address was available for the mapping smoke test\\n",
            Self::MappingSmokeMismatch => b"Active page-table map/unmap smoke test failed\\n",
            Self::MappingMutation(_) => b"Active page-table map/unmap operation failed\\n",
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
    if cr0 & CR0_WP == 0 {
        return Err(PagingError::SupervisorWriteProtectionDisabled);
    }

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
    if maximum_extended_leaf < CPUID_PHYSICAL_ADDRESS_WIDTH {
        return Err(PagingError::UnsupportedNx);
    }
    // SAFETY: the maximum extended CPUID leaf was checked above.
    let features = __cpuid(CPUID_EXTENDED_FEATURES);
    if features.edx & NX_FEATURE == 0 {
        return Err(PagingError::UnsupportedNx);
    }
    // SAFETY: the extended physical-address-width CPUID leaf was checked above.
    let physical_address_bits = (__cpuid(CPUID_PHYSICAL_ADDRESS_WIDTH).eax & 0xff) as u8;
    if !(32..=52).contains(&physical_address_bits) {
        return Err(PagingError::InvalidPhysicalAddressWidth {
            bits: physical_address_bits,
        });
    }

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
    if efer & EFER_NXE == 0 {
        return Err(PagingError::UnsupportedNx);
    }

    Ok(())
}

enum TableFrameSlot {
    Empty,
    Reserved,
    Owned { frame: Frame, published: bool },
}

struct TableFrameRegistry {
    slots: core::cell::UnsafeCell<[TableFrameSlot; TABLE_FRAME_CAPACITY]>,
}

// SAFETY: mutations are currently permitted only during single-CPU bootstrap
// with maskable interrupts disabled. SMP support must replace this precondition
// with explicit cross-CPU synchronization before page-table mutations are used.
unsafe impl Sync for TableFrameRegistry {}

impl TableFrameRegistry {
    const fn new() -> Self {
        Self {
            slots: core::cell::UnsafeCell::new(
                [const { TableFrameSlot::Empty }; TABLE_FRAME_CAPACITY],
            ),
        }
    }

    fn slots_mut(&self) -> &mut [TableFrameSlot; TABLE_FRAME_CAPACITY] {
        // SAFETY: the mutation API checks that interrupts are disabled and is
        // only used in the current single-core bootstrap.
        unsafe { &mut *self.slots.get() }
    }

    fn slots(&self) -> &[TableFrameSlot; TABLE_FRAME_CAPACITY] {
        // SAFETY: callers only inspect the registry within the same bootstrap
        // mutation contract; no concurrent CPU can access these slots.
        unsafe { &*self.slots.get() }
    }
}

static TABLE_FRAMES: TableFrameRegistry = TableFrameRegistry::new();

fn reserve_table_frame_slot() -> Option<usize> {
    let slots = TABLE_FRAMES.slots_mut();
    let index = slots
        .iter()
        .position(|slot| matches!(slot, TableFrameSlot::Empty))?;
    slots[index] = TableFrameSlot::Reserved;
    Some(index)
}

fn clear_reserved_table_frame_slot(index: usize) {
    let slots = TABLE_FRAMES.slots_mut();
    if !matches!(slots.get(index), Some(TableFrameSlot::Reserved)) {
        panic!("page-table frame registry reservation invariant violated");
    }
    slots[index] = TableFrameSlot::Empty;
}

fn install_table_frame(index: usize, frame: Frame) {
    let slots = TABLE_FRAMES.slots_mut();
    if !matches!(slots.get(index), Some(TableFrameSlot::Reserved)) {
        panic!("page-table frame registry reservation invariant violated");
    }
    slots[index] = TableFrameSlot::Owned {
        frame,
        published: false,
    };
}

fn registered_table_frame(physical_address: u64) -> bool {
    TABLE_FRAMES.slots().iter().any(|slot| match slot {
        TableFrameSlot::Owned { frame, .. } => frame.physical_address() == physical_address,
        TableFrameSlot::Empty | TableFrameSlot::Reserved => false,
    })
}

fn unpublished_table_frame(physical_address: u64) -> bool {
    TABLE_FRAMES.slots().iter().any(|slot| match slot {
        TableFrameSlot::Owned {
            frame,
            published: false,
        } => frame.physical_address() == physical_address,
        TableFrameSlot::Empty
        | TableFrameSlot::Reserved
        | TableFrameSlot::Owned {
            published: true, ..
        } => false,
    })
}

fn mark_table_frame_published(physical_address: u64) {
    for slot in TABLE_FRAMES.slots_mut().iter_mut() {
        if let TableFrameSlot::Owned { frame, published } = slot {
            if frame.physical_address() == physical_address {
                *published = true;
                return;
            }
        }
    }
}

fn release_registered_table_frame(physical_address: u64) {
    let slots = TABLE_FRAMES.slots_mut();
    let Some(index) = slots.iter().position(|slot| {
        matches!(slot, TableFrameSlot::Owned { frame, .. } if frame.physical_address() == physical_address)
    }) else {
        panic!("attempted to release an unregistered page-table frame");
    };
    let slot = core::mem::replace(&mut slots[index], TableFrameSlot::Empty);
    let frame = match slot {
        TableFrameSlot::Owned {
            frame,
            published: false,
        } => frame,
        TableFrameSlot::Owned {
            published: true, ..
        } => panic!("attempted to release a published page-table frame"),
        TableFrameSlot::Empty | TableFrameSlot::Reserved => {
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
        let physical_address_bits =
            (unsafe { __cpuid(CPUID_PHYSICAL_ADDRESS_WIDTH) }.eax & 0xff) as u8;
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
        let recursive_entry_pointer = entry_pointer_from_page(root_alias, usize::from(self.recursive_index))?;
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
        unsafe { ptr::write_bytes(alias, 0, PAGE_SIZE as usize) };
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
            Err(PageTableMutationError::AlreadyMapped)
            | Err(PageTableMutationError::LargePageConflict { .. })
            | Err(PageTableMutationError::AncestorPermissionConflict { .. }) => {
                // This candidate is reserved or its existing ancestors cannot
                // satisfy the requested writable mapping. Try the next page.
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
