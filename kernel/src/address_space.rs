//! Kernel integration for constructing an inactive address-space root.
//!
//! This smoke test connects the host-testable AddressSpaceRoot initializer to
//! the bootloader's recursive mapping and the checked physical-memory offset.
//! It never switches CR3 and never publishes the new root to a running context.
//! The new root is released only after the complete root frame has been verified.

use core::arch::asm;
use core::arch::x86_64::__cpuid;
use core::mem::size_of;
use core::ptr;

use bootloader_api::info::{MemoryRegion, MemoryRegionKind, Optional};
use bootloader_api::BootInfo;
use oneos_core::{
    is_canonical_4level, physical_page_is_in_allowed_region, recursive_entry_matches_root,
    recursive_table_page_virtual_address, translate_4level, AddressSpaceRoot,
    AddressSpaceRootEditor, AddressSpaceRootError, AddressSpaceRootInitializationError,
    PAGE_SIZE,
};

const PRESENT: u64 = 1;
const WRITABLE: u64 = 1 << 1;
const USER_ACCESSIBLE: u64 = 1 << 2;
const NO_EXECUTE: u64 = 1 << 63;
const PHYSICAL_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const PROTECTION_KEY_FIELD_MASK: u64 = 0x7800_0000_0000_0000;
const PML4_ENTRY_COUNT: usize = 512;
const LOWER_HALF_PML4_ENTRIES: usize = 256;
const ROOT_ALIAS_TARGET: u64 = 0xffff_8000_0000_0000;
const CPUID_MAX_EXTENDED_LEAF: u32 = 0x8000_0000;
const CPUID_PHYSICAL_ADDRESS_WIDTH: u32 = 0x8000_0008;

/// A failure while constructing and checking an inactive address-space root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressSpaceError {
    RecursiveMappingUnavailable,
    InvalidRecursiveIndex,
    InvalidKernelRoot,
    PhysicalMemoryOffsetUnavailable,
    InvalidPhysicalAddressWidth { bits: u8 },
    FrameAllocationFailed,
    FrameReleaseFailed,
    InvalidOwnedRoot(AddressSpaceRootError),
    RootInitialization(AddressSpaceRootInitializationError),
    RootTableUnavailable,
    RootVerificationFailed { index: usize },
}

impl AddressSpaceError {
    pub const fn message(self) -> &'static [u8] {
        match self {
            Self::RecursiveMappingUnavailable => {
                b"Address-space root setup requires the bootloader recursive mapping\n"
            }
            Self::InvalidRecursiveIndex => {
                b"Address-space root setup received an invalid recursive index\n"
            }
            Self::InvalidKernelRoot => {
                b"Address-space root setup rejected the active kernel PML4 frame\n"
            }
            Self::PhysicalMemoryOffsetUnavailable => {
                b"Address-space root setup could not validate the physical-memory offset\n"
            }
            Self::InvalidPhysicalAddressWidth { .. } => {
                b"Address-space root setup found an unsupported physical-address width\n"
            }
            Self::FrameAllocationFailed => {
                b"Address-space root setup could not allocate an owned frame\n"
            }
            Self::FrameReleaseFailed => {
                b"Address-space root setup could not release its inactive root frame\n"
            }
            Self::InvalidOwnedRoot(_) => {
                b"Address-space root setup rejected the allocated root frame\n"
            }
            Self::RootInitialization(_) => {
                b"Address-space root initialization failed before publication\n"
            }
            Self::RootTableUnavailable => {
                b"Address-space root setup could not safely access a complete root frame\n"
            }
            Self::RootVerificationFailed { .. } => {
                b"Address-space root contents did not match the initialization contract\n"
            }
        }
    }
}

/// Builds an inactive PML4 from the active kernel root, verifies every entry,
/// and returns the frame to the allocator. No CR3 switch or user mapping occurs.
///
/// The caller must have disabled maskable interrupts and initialized the paging
/// controls. Access to the active root relies on the bootloader API's recursive
/// mapping contract, matching the assumptions used by the existing inspector.
pub fn verify_root_initialization_smoke_test(
    boot_info: &BootInfo,
) -> Result<(), AddressSpaceError> {
    let recursive_index = match boot_info.recursive_index {
        Optional::Some(index) if index < PML4_ENTRY_COUNT as u16 => index,
        Optional::Some(_) => return Err(AddressSpaceError::InvalidRecursiveIndex),
        Optional::None => return Err(AddressSpaceError::RecursiveMappingUnavailable),
    };
    let physical_memory_offset = match boot_info.physical_memory_offset {
        Optional::Some(offset) => offset,
        Optional::None => return Err(AddressSpaceError::PhysicalMemoryOffsetUnavailable),
    };

    let maximum_extended_leaf = __cpuid(CPUID_MAX_EXTENDED_LEAF).eax;
    if maximum_extended_leaf < CPUID_PHYSICAL_ADDRESS_WIDTH {
        return Err(AddressSpaceError::InvalidPhysicalAddressWidth { bits: 0 });
    }
    let physical_address_bits =
        (__cpuid(CPUID_PHYSICAL_ADDRESS_WIDTH).eax & 0xff) as u8;
    if !(32..=52).contains(&physical_address_bits) {
        return Err(AddressSpaceError::InvalidPhysicalAddressWidth {
            bits: physical_address_bits,
        });
    }

    let kernel_root_physical = active_root_table_physical();
    if !is_physical_page(kernel_root_physical, physical_address_bits)
        || !is_region_page(
            &boot_info.memory_regions,
            kernel_root_physical,
            MemoryRegionKind::Bootloader,
        )
    {
        return Err(AddressSpaceError::InvalidKernelRoot);
    }

    let frame = super::memory::allocate_frame()
        .map_err(|_| AddressSpaceError::FrameAllocationFailed)?;
    let mut root = match AddressSpaceRoot::try_from_frame(frame, physical_address_bits) {
        Ok(root) => root,
        Err((error, frame)) => {
            release_frame(frame)?;
            return Err(AddressSpaceError::InvalidOwnedRoot(error));
        }
    };

    let root_physical = root.physical_address();
    let mut editor = KernelAddressSpaceRootEditor {
        regions: &boot_info.memory_regions,
        physical_memory_offset,
        kernel_root_physical,
        root_physical,
        recursive_index,
        physical_address_bits,
        kernel_root_pointer: None,
        destination_root_pointer: None,
    };

    let initialization = root.initialize_from_kernel_root(
        kernel_root_physical,
        usize::from(recursive_index),
        &mut editor,
    );

    let verification = if initialization.is_ok() && root.is_initialized() {
        verify_initialized_entries(
            &mut editor,
            root_physical,
            kernel_root_physical,
            usize::from(recursive_index),
        )
    } else {
        Ok(())
    };

    // The root has never been active and no child tables were allocated. It
    // can therefore be returned to the allocator after all checks complete.
    release_frame(root.into_frame())?;
    initialization.map_err(AddressSpaceError::RootInitialization)?;
    verification?;
    Ok(())
}

fn verify_initialized_entries(
    editor: &mut KernelAddressSpaceRootEditor<'_>,
    root_physical: u64,
    kernel_root_physical: u64,
    recursive_index: usize,
) -> Result<(), AddressSpaceError> {
    for index in 0..LOWER_HALF_PML4_ENTRIES {
        if editor.read_entry(root_physical, index, 4) != Some(0) {
            return Err(AddressSpaceError::RootVerificationFailed { index });
        }
    }

    for index in LOWER_HALF_PML4_ENTRIES..PML4_ENTRY_COUNT {
        let expected = if index == recursive_index {
            root_physical | PRESENT | WRITABLE | NO_EXECUTE
        } else {
            editor
                .read_entry(kernel_root_physical, index, 4)
                .ok_or(AddressSpaceError::RootTableUnavailable)?
        };
        if editor.read_entry(root_physical, index, 4) != Some(expected) {
            return Err(AddressSpaceError::RootVerificationFailed { index });
        }
    }

    Ok(())
}

fn release_frame(frame: oneos_core::Frame) -> Result<(), AddressSpaceError> {
    super::memory::free_frame(frame)
        .map_err(|(_error, _frame)| AddressSpaceError::FrameReleaseFailed)
}

struct KernelAddressSpaceRootEditor<'a> {
    regions: &'a [MemoryRegion],
    physical_memory_offset: u64,
    kernel_root_physical: u64,
    root_physical: u64,
    recursive_index: u16,
    physical_address_bits: u8,
    kernel_root_pointer: Option<*mut u64>,
    destination_root_pointer: Option<*mut u64>,
}

impl KernelAddressSpaceRootEditor<'_> {
    fn kernel_root_pointer(&self) -> Option<*mut u64> {
        if !is_region_page(
            self.regions,
            self.kernel_root_physical,
            MemoryRegionKind::Bootloader,
        ) {
            return None;
        }

        let alias = recursive_table_page_virtual_address(
            self.recursive_index,
            ROOT_ALIAS_TARGET,
            4,
        )?;
        let pointer = entry_pointer_from_page(alias, 0)?;
        // SAFETY: the bootloader API promises that the reported recursive slot
        // maps the active PML4 to itself. The entry is checked immediately after
        // this read; as with the existing inspector, the first access relies on
        // that documented mapping contract.
        let recursive_entry = unsafe {
            ptr::read_volatile(entry_pointer_from_page(alias, usize::from(self.recursive_index))?)
        };
        if !recursive_entry_matches_root(recursive_entry, self.kernel_root_physical)
            || recursive_entry & WRITABLE == 0
            || recursive_entry & USER_ACCESSIBLE != 0
            || recursive_entry & PROTECTION_KEY_FIELD_MASK != 0
        {
            return None;
        }
        Some(pointer)
    }

    fn destination_root_pointer(&self) -> Option<*mut u64> {
        // Validate the recursive self-reference before translating the direct-map
        // alias, matching the precondition established by boot mapping inspection.
        let _validated_kernel_root = self.kernel_root_pointer()?;
        if !is_physical_page(self.root_physical, self.physical_address_bits)
            || !is_region_page(
                self.regions,
                self.root_physical,
                MemoryRegionKind::Usable,
            )
        {
            return None;
        }

        let alias = self
            .physical_memory_offset
            .checked_add(self.root_physical)?;
        let last_byte = alias.checked_add(PAGE_SIZE - 1)?;
        if alias & (PAGE_SIZE - 1) != 0
            || !is_canonical_4level(alias)
            || !is_canonical_4level(last_byte)
        {
            return None;
        }

        let translation = translate_active_alias(
            alias,
            self.kernel_root_physical,
            self.recursive_index,
            self.regions,
        )?;
        if translation.physical_address != self.root_physical
            || !translation.writable
            || translation.user_accessible
        {
            return None;
        }

        let pointer = usize::try_from(alias).ok()? as *mut u64;
        if pointer as usize & (size_of::<u64>() - 1) != 0 {
            return None;
        }
        Some(pointer)
    }
}

impl AddressSpaceRootEditor for KernelAddressSpaceRootEditor<'_> {
    fn physical_address_bits(&self) -> u8 {
        self.physical_address_bits
    }

    fn table_is_readable(&mut self, table_physical: u64) -> bool {
        if table_physical != self.kernel_root_physical {
            return false;
        }
        if self.kernel_root_pointer.is_none() {
            self.kernel_root_pointer = self.kernel_root_pointer();
        }
        self.kernel_root_pointer.is_some()
    }

    fn table_is_read_write_accessible(&mut self, table_physical: u64) -> bool {
        if table_physical != self.root_physical {
            return false;
        }
        if self.destination_root_pointer.is_none() {
            self.destination_root_pointer = self.destination_root_pointer();
        }
        self.destination_root_pointer.is_some()
    }

    fn read_entry(&mut self, table_physical: u64, index: usize, level: u8) -> Option<u64> {
        if index >= PML4_ENTRY_COUNT || level != 4 {
            return None;
        }
        let table = if table_physical == self.kernel_root_physical {
            self.kernel_root_pointer?
        } else if table_physical == self.root_physical {
            self.destination_root_pointer?
        } else {
            return None;
        };
        // SAFETY: the matching table was preflighted as readable or read/write,
        // the complete frame was validated, and index is within the PML4.
        Some(unsafe { ptr::read_volatile(table.add(index)) })
    }

    fn write_entry(&mut self, table_physical: u64, index: usize, level: u8, value: u64) {
        assert!(index < PML4_ENTRY_COUNT && level == 4);
        assert_eq!(table_physical, self.root_physical);
        let table = self
            .destination_root_pointer
            .expect("destination root was preflighted as writable");
        // SAFETY: initialize_from_kernel_root preflights the destination frame
        // before writing and only writes valid PML4 indices. It keeps the root
        // inactive until this infallible write phase is complete.
        unsafe { ptr::write_volatile(table.add(index), value) };
    }
}

fn translate_active_alias(
    virtual_address: u64,
    root_physical: u64,
    recursive_index: u16,
    regions: &[MemoryRegion],
) -> Option<oneos_core::PageTranslation> {
    let mut level = 4u8;
    translate_4level(virtual_address, root_physical, |table_physical, index| {
        let current_level = level;
        if current_level == 0
            || (current_level == 4 && table_physical != root_physical)
            || !is_region_page(regions, table_physical, MemoryRegionKind::Bootloader)
        {
            return None;
        }

        let table_virtual = recursive_table_page_virtual_address(
            recursive_index,
            virtual_address,
            current_level,
        )?;
        let pointer = entry_pointer_from_page(table_virtual, index)?;
        // SAFETY: the current table frame has been verified as Bootloader-owned,
        // and the address is derived from the validated recursive mapping.
        let entry = unsafe { ptr::read_volatile(pointer) };
        level = level.checked_sub(1)?;
        Some(entry)
    })
    .ok()
}

fn entry_pointer_from_page(table_virtual_address: u64, index: usize) -> Option<*mut u64> {
    if index >= PML4_ENTRY_COUNT
        || !is_canonical_4level(table_virtual_address)
        || table_virtual_address & (PAGE_SIZE - 1) != 0
    {
        return None;
    }
    let offset = u64::try_from(index).ok()?.checked_mul(size_of::<u64>() as u64)?;
    let address = table_virtual_address.checked_add(offset)?;
    let end = address.checked_add(size_of::<u64>() as u64 - 1)?;
    if !is_canonical_4level(address) || !is_canonical_4level(end) || address & 7 != 0 {
        return None;
    }
    Some(usize::try_from(address).ok()? as *mut u64)
}

fn active_root_table_physical() -> u64 {
    let cr3: u64;
    // SAFETY: CR3 is readable from privileged x86_64 kernel context.
    unsafe {
        asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    }
    cr3 & PHYSICAL_ADDRESS_MASK
}

fn is_physical_page(address: u64, bits: u8) -> bool {
    if !(32..=52).contains(&bits)
        || address == 0
        || address & (PAGE_SIZE - 1) != 0
        || address & !PHYSICAL_ADDRESS_MASK != 0
    {
        return false;
    }
    let physical_limit = 1u64 << bits;
    address
        .checked_add(PAGE_SIZE)
        .is_some_and(|end| end <= physical_limit)
}

fn is_region_page(
    regions: &[MemoryRegion],
    physical_address: u64,
    allowed_kind: MemoryRegionKind,
) -> bool {
    physical_page_is_in_allowed_region(physical_address, regions.len(), |index| {
        let region = regions[index];
        (region.start, region.end, region.kind == allowed_kind)
    })
}
