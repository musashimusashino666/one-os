//! Kernel integration for constructing and runtime-switching address-space roots.
//!
//! This module connects host-testable address-space-root initialization to the
//! bootloader's recursive mapping and the checked physical-memory offset. During
//! normal boot, the smoke test exercises an A -> B -> A CR3 switch between the
//! active kernel root and a temporary root with shared supervisor-only mappings.
//! It validates the paging context and CR3 readback, then clears and releases the
//! temporary root only after switching back. This does not implement user-process
//! isolation, lower-level page-table reclamation, or SMP/remote TLB shootdowns.

use core::arch::asm;
use core::arch::x86_64::__cpuid;
use core::mem::size_of;
use core::ptr;
#[cfg(feature = "test-cr3-activation-guard")]
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use bootloader_api::info::{MemoryRegion, MemoryRegionKind, Optional};
use bootloader_api::BootInfo;
use oneos_core::{
    is_canonical_4level, is_safe_recursive_mapping_index, physical_page_is_in_allowed_region,
    recursive_entry_is_valid_kernel_root, recursive_entry_matches_root,
    recursive_table_page_virtual_address, translate_4level, validate_kernel_root_activation_state,
    ActiveAddressSpaceRoot, AddressSpaceRoot, AddressSpaceRootEditor, AddressSpaceRootError,
    AddressSpaceRootInitializationError, PagingPreconditionError, UserPageMappingRegistry,
    ZeroedFrame, PAGE_SIZE,
};

const PRESENT: u64 = 1;
const WRITABLE: u64 = 1 << 1;
const ACCESSED: u64 = 1 << 5;
const USER_ACCESSIBLE: u64 = 1 << 2;
const NO_EXECUTE: u64 = 1 << 63;
const PHYSICAL_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;

#[cfg(feature = "test-cr3-activation-guard")]
static CR3_ACTIVATION_GUARD_TEST_TARGET: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "test-cr3-activation-guard")]
static CR3_ACTIVATION_GUARD_TEST_PASSED: AtomicBool = AtomicBool::new(false);
const PROTECTION_KEY_FIELD_MASK: u64 = 0x7800_0000_0000_0000;
const PML4_ENTRY_COUNT: usize = 512;
const LOWER_HALF_PML4_ENTRIES: usize = 256;
const ROOT_ALIAS_TARGET: u64 = 0xffff_8000_0000_0000;
const CPUID_MAX_EXTENDED_LEAF: u32 = 0x8000_0000;
const CPUID_PHYSICAL_ADDRESS_WIDTH: u32 = 0x8000_0008;
const EFER_MSR: u32 = 0xc000_0080;

/// A failure while constructing and checking an inactive address-space root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressSpaceError {
    RecursiveMappingUnavailable,
    InvalidRecursiveIndex,
    InvalidKernelRoot,
    PhysicalMemoryOffsetUnavailable,
    InvalidPhysicalAddressWidth {
        bits: u8,
    },
    FrameAllocationFailed,
    FrameReleaseFailed,
    InvalidOwnedRoot(AddressSpaceRootError),
    RootInitialization(AddressSpaceRootInitializationError),
    RootTableUnavailable,
    RootFrameRegistryFull,
    RootRegistryCleanupFailed,
    RootNotRegistered,
    #[cfg(any(
        feature = "test-cr3-switch-guard",
        feature = "test-cr3-activation-guard"
    ))]
    Cr3GuardTestFailed,
    #[cfg(feature = "test-wx-runtime-audit")]
    RootRegistryGuardFailed,
    NoUnusedRecursiveIndex,
    RootVerificationFailed {
        index: usize,
    },
    RootZeroizationFailed {
        index: usize,
    },
    KernelMappingNotInUpperHalf,
    PagingPrecondition(PagingPreconditionError),
    PagingIntegrationFailed,
    RootActivationFailed,
    #[cfg(feature = "test-root-leak-safety")]
    RootLeakSafetyFailed,
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
            Self::RootInitialization(error) => match error {
                AddressSpaceRootInitializationError::AlreadyInitialized => {
                    b"Address-space root was already initialized\n"
                }
                AddressSpaceRootInitializationError::PhysicalAddressWidthMismatch { .. } => {
                    b"Address-space root and editor physical-address widths differ\n"
                }
                AddressSpaceRootInitializationError::InvalidKernelRootFrame(_) => {
                    b"Address-space initializer rejected the kernel root frame\n"
                }
                AddressSpaceRootInitializationError::InvalidKernelRecursiveIndex { .. } => {
                    b"Address-space initializer rejected the bootloader recursive index\n"
                }
                AddressSpaceRootInitializationError::InvalidRecursiveIndex { .. } => {
                    b"Address-space initializer rejected the new root recursive index\n"
                }
                AddressSpaceRootInitializationError::RecursiveDestinationSlotOccupied { .. } => {
                    b"Address-space root recursive slot is already occupied by a kernel mapping\n"
                }
                AddressSpaceRootInitializationError::RootAliasesKernelRoot => {
                    b"Address-space root aliases the active kernel root\n"
                }
                AddressSpaceRootInitializationError::RootTableUnavailable => {
                    b"Address-space destination root is not writable through the checked offset\n"
                }
                AddressSpaceRootInitializationError::KernelRootTableUnavailable => {
                    b"Address-space source kernel root is not readable\n"
                }
                AddressSpaceRootInitializationError::KernelRootRecursiveEntryUnavailable => {
                    b"Address-space source recursive entry is unreadable\n"
                }
                AddressSpaceRootInitializationError::InvalidKernelRootRecursiveEntry => {
                    b"Address-space source recursive entry violates root permissions\n"
                }
                AddressSpaceRootInitializationError::KernelEntryUnavailable { .. } => {
                    b"Address-space source kernel PML4 entry is unreadable\n"
                }
                AddressSpaceRootInitializationError::MalformedKernelEntry { .. } => {
                    b"Address-space source kernel PML4 entry is malformed\n"
                }
                AddressSpaceRootInitializationError::UserAccessibleKernelEntry { .. } => {
                    b"Address-space source kernel PML4 entry permits user access\n"
                }
                AddressSpaceRootInitializationError::KernelEntryAliasesKernelRoot { .. } => {
                    b"Address-space source entry aliases the kernel root frame\n"
                }
                AddressSpaceRootInitializationError::KernelEntryAliasesOwnedRoot { .. } => {
                    b"Address-space source entry aliases the owned destination root\n"
                }
            },
            Self::RootTableUnavailable => {
                b"Address-space root setup could not safely access a complete root frame\n"
            }
            Self::RootFrameRegistryFull => {
                b"Address-space root frame registry is full\n"
            }
            Self::RootRegistryCleanupFailed => {
                b"Released address-space root could not be safely removed from its registry\n"
            }
            Self::RootNotRegistered => {
                b"Address-space activation rejected a root missing from the live-root registry\n"
            }
            #[cfg(any(
                feature = "test-cr3-switch-guard",
                feature = "test-cr3-activation-guard"
            ))]
            Self::Cr3GuardTestFailed => {
                b"Real CR3 guard rejection acceptance test failed\n"
            }
            #[cfg(feature = "test-wx-runtime-audit")]
            Self::RootRegistryGuardFailed => {
                b"W^X smoke test failed to reject missing live-root registration\n"
            }
            Self::NoUnusedRecursiveIndex => {
                b"Address-space root setup found no empty upper-half PML4 slot for its private recursive mapping\n"
            }
            Self::RootVerificationFailed { .. } => {
                b"Address-space root contents did not match the initialization contract\n"
            }
            Self::KernelMappingNotInUpperHalf => {
                b"Kernel code, stack, boot metadata, and physical-memory alias must use upper-half mappings before activation\n"
            }
            Self::PagingPrecondition(error) => error.message(),
            Self::PagingIntegrationFailed => {
                b"Inactive user-page lifecycle smoke test failed\n"
            }
            Self::RootActivationFailed => {
                b"CR3 did not report the newly activated address-space root\n"
            }
            #[cfg(feature = "test-root-leak-safety")]
            Self::RootLeakSafetyFailed => {
                b"Address-space root leak safety smoke test failed\n"
            }
            Self::RootZeroizationFailed { .. } => {
                b"Address-space root could not be zeroed before frame release\n"
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
        Optional::Some(index) if is_safe_recursive_mapping_index(index) => index,
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
    let physical_address_bits = (__cpuid(CPUID_PHYSICAL_ADDRESS_WIDTH).eax & 0xff) as u8;
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

    let frame =
        super::memory::allocate_frame().map_err(|_| AddressSpaceError::FrameAllocationFailed)?;
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
        kernel_root_is_owned: false,
        kernel_root_pointer: None,
        destination_root_pointer: None,
    };
    if !super::paging::register_address_space_root(root_physical) {
        clear_and_release_unregistered_root(root, &mut editor, root_physical)?;
        return Err(AddressSpaceError::RootFrameRegistryFull);
    }

    let kernel_root_readable = editor.table_is_readable(kernel_root_physical);
    let destination_root_writable = editor.table_is_read_write_accessible(root_physical);
    if !kernel_root_readable || !destination_root_writable {
        if destination_root_writable {
            clear_and_release_root(root, &mut editor, root_physical)?;
        } else {
            // The destination frame could not be safely accessed for zeroization.
            // Keep it allocated rather than recycle potentially stale contents.
            // Cleanup or access is uncertain. Preserve the allocator reservation.
            root.leak_frame();
        }
        return Err(AddressSpaceError::RootTableUnavailable);
    }
    let root_recursive_index = match editor.select_root_recursive_index() {
        Ok(index) => index,
        Err(error) => {
            clear_and_release_root(root, &mut editor, root_physical)?;
            return Err(error);
        }
    };

    let initialization = root.initialize_from_kernel_root(
        kernel_root_physical,
        usize::from(recursive_index),
        root_recursive_index,
        &mut editor,
    );

    let verification = if initialization.is_ok() && root.is_initialized() {
        verify_initialized_entries(
            &mut editor,
            root_physical,
            kernel_root_physical,
            usize::from(recursive_index),
            root_recursive_index,
            false,
        )
    } else {
        Ok(())
    };

    // The root has never been active and no child tables were allocated. Clear
    // every entry (including on initialization/verification/audit errors) before
    // the frame is made available to another caller of the allocator.
    clear_and_release_root(root, &mut editor, root_physical)?;
    initialization.map_err(AddressSpaceError::RootInitialization)?;
    verification?;
    Ok(())
}

/// Builds an inactive root from the currently active, owned kernel root.
///
/// The destination retains only the validated supervisor-only upper-half
/// mappings and receives a private recursive PML4 index. It is not activated
/// or populated with user pages by this function.
fn create_inactive_address_space_root(
    boot_info: &BootInfo,
    active_root: &ActiveAddressSpaceRoot,
) -> Result<AddressSpaceRoot, AddressSpaceError> {
    let (physical_address_bits, physical_memory_offset) =
        validate_runtime_root_context(boot_info, active_root)?;
    let kernel_root_physical = active_root.physical_address();
    let recursive_index = active_root.recursive_index();

    let frame =
        super::memory::allocate_frame().map_err(|_| AddressSpaceError::FrameAllocationFailed)?;
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
        kernel_root_is_owned: true,
        kernel_root_pointer: None,
        destination_root_pointer: None,
    };
    if !super::paging::register_address_space_root(root_physical) {
        clear_and_release_unregistered_root(root, &mut editor, root_physical)?;
        return Err(AddressSpaceError::RootFrameRegistryFull);
    }

    if !editor.table_is_readable(kernel_root_physical)
        || !editor.table_is_read_write_accessible(root_physical)
    {
        if editor.table_is_read_write_accessible(root_physical) {
            clear_and_release_root(root, &mut editor, root_physical)?;
        } else {
            // Do not recycle a frame whose contents could not be validated and
            // cleared through the checked physical-memory-offset alias.
            // Cleanup or access is uncertain. Preserve the allocator reservation.
            root.leak_frame();
        }
        return Err(AddressSpaceError::RootTableUnavailable);
    }

    let root_recursive_index = match editor.select_root_recursive_index() {
        Ok(index) => index,
        Err(error) => {
            clear_and_release_root(root, &mut editor, root_physical)?;
            return Err(error);
        }
    };

    if let Err(error) = root.initialize_from_kernel_root(
        kernel_root_physical,
        usize::from(recursive_index),
        root_recursive_index,
        &mut editor,
    ) {
        clear_and_release_root(root, &mut editor, root_physical)?;
        return Err(AddressSpaceError::RootInitialization(error));
    }
    if let Err(error) = verify_initialized_entries(
        &mut editor,
        root_physical,
        kernel_root_physical,
        usize::from(recursive_index),
        root_recursive_index,
        false,
    ) {
        clear_and_release_root(root, &mut editor, root_physical)?;
        return Err(error);
    }

    Ok(root)
}

/// Switches to a root with registered user mappings after a complete kernel-side
/// preflight of its private lower-half page-table tree.
fn activate_preflighted_user_root<const CAPACITY: usize>(
    current: ActiveAddressSpaceRoot,
    next: AddressSpaceRoot,
    boot_info: &BootInfo,
    registry: &UserPageMappingRegistry<ZeroedFrame, CAPACITY>,
) -> Result<(AddressSpaceRoot, ActiveAddressSpaceRoot), AddressSpaceError> {
    super::paging::validate_inactive_user_address_space(boot_info, &next, &current, registry)
        .map_err(|_| AddressSpaceError::PagingIntegrationFailed)?;
    switch_address_space(current, next, boot_info, true)
}

/// Flushes all local translations for the currently active root without
/// changing address-space ownership. Used by break-before-make page-table edits
/// after a parent Present bit is cleared. The root must remain active and the
/// existing single-CPU, interrupts-disabled, PCID-disabled contract must hold.
///
/// Keep the CR4.PGE-clear, CR3-reload, and CR4-restore sequence explicit so the
/// assembly validator checks this additional CR3 write path as well as root switches.
#[inline(never)]
pub(super) fn switch_address_space_flush_local_tlb(
    expected_root_physical: u64,
) -> Result<(), AddressSpaceError> {
    const CR4_PGE: u64 = 1 << 7;
    const CR4_PCIDE: u64 = 1 << 17;

    let cr0: u64;
    let cr4: u64;
    let efer_low: u32;
    let efer_high: u32;
    let rflags: u64;
    // SAFETY: these architectural registers are readable from privileged kernel
    // context. The values are checked immediately before changing CR4/CR3.
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        asm!("pushfq", "pop {}", out(reg) rflags, options(preserves_flags));
        asm!(
            "rdmsr",
            in("ecx") EFER_MSR,
            out("eax") efer_low,
            out("edx") efer_high,
            options(nomem, nostack, preserves_flags)
        );
    }
    let efer = (u64::from(efer_high) << 32) | u64::from(efer_low);
    validate_kernel_root_activation_state(cr0, cr4, efer, rflags)
        .map_err(AddressSpaceError::PagingPrecondition)?;

    // Re-read CR4 and CR3 after the validation call. The flush sequence below
    // must keep the original CR4 and current CR3 values visible to the assembly
    // validator without relying on caller-saved register contents across a call.
    let cr4: u64;
    let cr3: u64;
    // SAFETY: the root and control state were just validated; reread immediately
    // before the PGE-clear / CR3-reload / CR4-restore sequence.
    unsafe {
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    }
    if cr4 & CR4_PCIDE != 0
        || expected_root_physical == 0
        || expected_root_physical & (PAGE_SIZE - 1) != 0
        || cr3 & PHYSICAL_ADDRESS_MASK != expected_root_physical
    {
        return Err(AddressSpaceError::InvalidKernelRoot);
    }

    let cr4_without_pge = cr4 & !CR4_PGE;
    // SAFETY: the current root is validated and remains active; clearing PGE
    // invalidates global translations before the CR3 reload flushes the rest.
    unsafe {
        asm!(
            "mov cr4, {}",
            in(reg) cr4_without_pge,
            options(nomem, nostack, preserves_flags)
        );
    }
    // Intentionally omit nomem: the CR3 reload is a compiler memory-ordering boundary.
    // SAFETY: PCID is disabled and interrupts are disabled, so reloading the same
    // active root flushes local non-global entries without an address-space switch.
    unsafe {
        asm!(
            "mov cr3, {}",
            in(reg) cr3,
            options(nostack, preserves_flags)
        );
    }
    // SAFETY: restore the exact prior CR4 only after the flush-causing CR3 write.
    unsafe {
        asm!(
            "mov cr4, {}",
            in(reg) cr4,
            options(nomem, nostack, preserves_flags)
        );
    }

    let observed_cr3: u64;
    // SAFETY: CR3 is readable in kernel mode; verify the address-space identity
    // after the serializing switch sequence.
    unsafe {
        asm!("mov {}, cr3", out(reg) observed_cr3, options(nomem, nostack, preserves_flags));
    }
    if observed_cr3 & PHYSICAL_ADDRESS_MASK != expected_root_physical {
        return Err(AddressSpaceError::RootActivationFailed);
    }
    Ok(())
}

/// Rejects target roots that are not uniquely registered and allocator-owned.
/// This predicate is shared by both CR3 activation paths and the negative QEMU probe.
fn validate_registered_root_for_activation(root_physical: u64) -> Result<(), AddressSpaceError> {
    #[cfg(feature = "test-cr3-activation-guard")]
    let fault_injected_missing_registration = if CR3_ACTIVATION_GUARD_TEST_TARGET
        .compare_exchange(root_physical, 0, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        if !super::paging::remove_address_space_root_registration_for_cr3_test(root_physical) {
            return Err(AddressSpaceError::Cr3GuardTestFailed);
        }
        true
    } else {
        false
    };

    // Run the same registry and allocator predicate that production activation
    // relies on, while the dedicated test has actually removed the registry entry.
    let admission = if !super::paging::is_uniquely_registered_address_space_root(root_physical)
        || !matches!(super::memory::is_frame_allocated(root_physical), Ok(true))
    {
        Err(AddressSpaceError::RootNotRegistered)
    } else {
        Ok(())
    };

    #[cfg(feature = "test-cr3-activation-guard")]
    if fault_injected_missing_registration
        && !super::paging::register_address_space_root(root_physical)
    {
        return Err(AddressSpaceError::Cr3GuardTestFailed);
    }

    admission
}

#[cfg(feature = "test-cr3-activation-guard")]
pub(super) fn cr3_activation_guard_test_passed() -> bool {
    CR3_ACTIVATION_GUARD_TEST_PASSED.load(Ordering::Acquire)
}

#[cfg(any(
    feature = "test-cr3-switch-guard",
    feature = "test-cr3-activation-guard"
))]
pub(super) fn cr3_guard_test_exit(
    success: bool,
    pass_marker: &'static [u8],
    failure_marker: &'static [u8],
) -> ! {
    super::serial_write(if success { pass_marker } else { failure_marker });
    let exit_code = if success { 0x10u8 } else { 0x11u8 };
    // Dedicated QEMU acceptance profiles attach isa-debug-exit at port 0xf4.
    unsafe {
        asm!(
            "out dx, al",
            in("dx") 0xf4u16,
            in("al") exit_code,
            options(nomem, nostack, preserves_flags)
        );
    }
    loop {
        // If the test-exit device is missing, do not continue with consumed root handles.
        unsafe { asm!("hlt", options(nomem, nostack)) };
    }
}

/// Performs the validated hardware CR3 transition.
///
/// When `allow_user_mappings` is true, the caller must have just completed
/// `validate_inactive_user_address_space` for this exact root and registry.
/// Keep the actual CR4.PGE-disable, CR3-write, and CR4-restore sequence in this
/// function so CI inspects the instructions that execute on the real path.
#[inline(never)]
fn switch_address_space(
    current: ActiveAddressSpaceRoot,
    next: AddressSpaceRoot,
    boot_info: &BootInfo,
    allow_user_mappings: bool,
) -> Result<(AddressSpaceRoot, ActiveAddressSpaceRoot), AddressSpaceError> {
    const CR4_PGE: u64 = 1 << 7;

    let (physical_address_bits, physical_memory_offset) =
        validate_runtime_root_context(boot_info, &current)?;
    let current_physical = current.physical_address();
    let root_physical = next.physical_address();
    let current_recursive_index = current.recursive_index();
    let next_recursive_index = next
        .recursive_index()
        .filter(|index| (LOWER_HALF_PML4_ENTRIES as u16..PML4_ENTRY_COUNT as u16).contains(index))
        .ok_or(AddressSpaceError::RootActivationFailed)?;

    // Every kernel-created root that may become active must remain in the
    // authoritative live-root registry and retain allocator ownership. The
    // bootloader root is the sole exception: it is the source root, not next.
    validate_registered_root_for_activation(root_physical)?;

    if !next.is_initialized()
        || root_physical == current_physical
        || next.physical_address_bits() != physical_address_bits
        || active_root_table_physical() != current_physical
    {
        return Err(AddressSpaceError::InvalidKernelRoot);
    }

    // Revalidate the complete PML4 relationship immediately before the hardware
    // switch. Both roots must carry only the expected supervisor-only shared
    // kernel mappings, with their own recursive entries.
    let mut editor = KernelAddressSpaceRootEditor {
        regions: &boot_info.memory_regions,
        physical_memory_offset,
        kernel_root_physical: current_physical,
        root_physical,
        recursive_index: current_recursive_index,
        physical_address_bits,
        kernel_root_is_owned: true,
        kernel_root_pointer: None,
        destination_root_pointer: None,
    };
    if !editor.table_is_readable(current_physical)
        || !editor.table_is_read_write_accessible(root_physical)
    {
        return Err(AddressSpaceError::RootTableUnavailable);
    }
    verify_initialized_entries(
        &mut editor,
        root_physical,
        current_physical,
        usize::from(current_recursive_index),
        usize::from(next_recursive_index),
        allow_user_mappings,
    )?;

    // Use the same explicit CR4.PGE -> CR3 -> CR4 sequence that the optimized
    // assembly validator checks on every reachable CR3 write path.
    let cr4: u64;
    // SAFETY: current CPU control state was validated by
    // validate_runtime_root_context immediately before this operation.
    unsafe {
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
    }
    let cr4_without_pge = cr4 & !CR4_PGE;
    // SAFETY: this privileged kernel path may disable PGE to flush global
    // translations before switching away from the current root.
    unsafe {
        asm!(
            "mov cr4, {}",
            in(reg) cr4_without_pge,
            options(nomem, nostack, preserves_flags)
        );
    }
    // Intentionally omit nomem: CR3 is a compiler memory-ordering boundary.
    // SAFETY: both roots and their shared kernel mappings were verified above;
    // paging preconditions exclude PCID and maskable interrupts remain disabled.
    unsafe {
        asm!(
            "mov cr3, {}",
            in(reg) root_physical,
            options(nostack, preserves_flags)
        );
    }
    // SAFETY: restore the validated CR4 configuration only after the CR3 write.
    unsafe {
        asm!(
            "mov cr4, {}",
            in(reg) cr4,
            options(nomem, nostack, preserves_flags)
        );
    }

    let observed_root = active_root_table_physical();
    if observed_root != root_physical {
        // The hardware's active root is uncertain. These ownership wrappers do
        // not free allocator frames on drop, so the caller must fail-stop here.
        return Err(AddressSpaceError::RootActivationFailed);
    }

    // SAFETY: the CR3 readback identifies the initialized target root and the
    // target's private recursive index was checked above. The caller has not
    // enabled interrupts or preemption and retains the handle for this lifetime.
    let next_active = unsafe { ActiveAddressSpaceRoot::from_activated(next, next_recursive_index) };
    // SAFETY: CR3 was switched away from current_physical; PCID is disabled,
    // PGE was cleared around the CR3 write, and the original CR4 value is back.
    let previous_inactive = match unsafe { current.into_inactive_after_switch(observed_root) } {
        Ok(root) => root,
        Err((_still_active_handle, _error)) => {
            // A mismatch after the hardware switch is not recoverable in-place.
            // Dropping these wrappers does not return their frames to the allocator.
            return Err(AddressSpaceError::RootActivationFailed);
        }
    };

    Ok((previous_inactive, next_active))
}

/// Exercises A -> B -> A switching with a real, inactive user data mapping.
///
/// The test writes a sentinel through B's lower-half user mapping at CPL 0,
/// switches away, tears down the private user mapping and all owned lower-level
/// tables, re-zeroes the returned frame, and then releases B's empty root. This
/// does not enter Ring 3 or establish process isolation.
pub fn verify_runtime_address_space_switch_smoke_test(
    boot_info: &BootInfo,
    active_root: ActiveAddressSpaceRoot,
) -> Result<ActiveAddressSpaceRoot, AddressSpaceError> {
    verify_runtime_address_space_switch_smoke_test_impl(boot_info, active_root, None)
}

#[cfg(feature = "test-wx-runtime-audit")]
pub fn verify_runtime_address_space_switch_smoke_test_with_wx_probe(
    boot_info: &BootInfo,
    active_root: ActiveAddressSpaceRoot,
    executable_physical_page: u64,
    executable_virtual_address: u64,
) -> Result<ActiveAddressSpaceRoot, AddressSpaceError> {
    verify_runtime_address_space_switch_smoke_test_impl(
        boot_info,
        active_root,
        Some((executable_physical_page, executable_virtual_address)),
    )
}

#[cfg(not(feature = "test-cr3-switch-guard"))]
fn verify_runtime_address_space_switch_smoke_test_impl(
    boot_info: &BootInfo,
    active_root: ActiveAddressSpaceRoot,
    wx_probe: Option<(u64, u64)>,
) -> Result<ActiveAddressSpaceRoot, AddressSpaceError> {
    #[cfg(not(feature = "test-wx-runtime-audit"))]
    let _ = wx_probe;

    let original_physical = active_root.physical_address();
    let original_recursive_index = active_root.recursive_index();
    let second_root = create_inactive_address_space_root(boot_info, &active_root)?;
    let second_physical = second_root.physical_address();
    let second_recursive_index = second_root
        .recursive_index()
        .ok_or(AddressSpaceError::RootActivationFailed)?;
    if second_physical == original_physical || second_recursive_index == original_recursive_index {
        return Err(AddressSpaceError::RootActivationFailed);
    }

    // Both roots deliberately map the same VA to different, simultaneously
    // allocated physical frames.
    let third_root = create_inactive_address_space_root(boot_info, &active_root)?;
    let third_physical = third_root.physical_address();
    if third_physical == original_physical || third_physical == second_physical {
        return Err(AddressSpaceError::RootActivationFailed);
    }

    let (mut user_registry, user_frame_physical) =
        super::paging::map_test_user_page_for_teardown(boot_info, &second_root, &active_root)
            .map_err(|_| AddressSpaceError::PagingIntegrationFailed)?;
    let (mut peer_registry, peer_frame_physical) =
        super::paging::map_test_user_page_for_teardown(boot_info, &third_root, &active_root)
            .map_err(|_| AddressSpaceError::PagingIntegrationFailed)?;
    if user_frame_physical == peer_frame_physical {
        return Err(AddressSpaceError::PagingIntegrationFailed);
    }

    // Exercise real page-table corruption rejection before activating the root.
    // The helper restores every injected entry and verifies the valid tree again.
    super::paging::verify_teardown_corruption_preflight_for_smoke(
        boot_info,
        &second_root,
        &active_root,
        &user_registry,
        third_physical,
        peer_frame_physical,
    )
    .map_err(|_| AddressSpaceError::PagingIntegrationFailed)?;

    // Prove a live inactive root cannot be removed from the inventory merely
    // by calling the registry cleanup API; it must remain in a complete audit.
    #[cfg(feature = "test-wx-runtime-audit")]
    super::paging::verify_live_root_registry_unregistration_rejected_for_smoke(
        boot_info,
        &second_root,
        &active_root,
        |root_physical| {
            validate_registered_root_for_activation(root_physical)
                == Err(AddressSpaceError::RootNotRegistered)
        },
    )
    .map_err(|_| AddressSpaceError::RootRegistryGuardFailed)?;

    // The dedicated W^X audit profile injects a writable alias for the active
    // root's test RX frame into a real inactive root, requires the complete
    // all-root audit to find that cross-root conflict, then verifies cleanup
    // restores a conflict-free audit before the ordinary smoke check proceeds.
    #[cfg(feature = "test-wx-runtime-audit")]
    if let Some((executable_physical_page, executable_virtual_address)) = wx_probe {
        super::paging::verify_wx_audit_cross_root_alias_for_smoke(
            boot_info,
            &second_root,
            &active_root,
            executable_physical_page,
            executable_virtual_address,
        )
        .map_err(|_| AddressSpaceError::PagingIntegrationFailed)?;
    }

    // The two inactive roots now contain real private lower-half page-table
    // trees. Audit them before activation so the physical-offset/ownership path
    // must walk their actual child tables, not only inspect empty PML4 roots.
    let (physical_address_bits, _) = validate_runtime_root_context(boot_info, &active_root)?;
    #[cfg(feature = "test-wx-runtime-audit")]
    let (audit, scope, direct_map_coverage) = super::paging::audit_registered_wx_roots(
        boot_info,
        original_physical,
        original_recursive_index,
        physical_address_bits,
    )
    .map_err(|_| AddressSpaceError::PagingIntegrationFailed)?;
    #[cfg(not(feature = "test-wx-runtime-audit"))]
    let (audit, scope, direct_map_coverage) = super::paging::audit_registered_wx_roots(
        boot_info,
        original_physical,
        original_recursive_index,
        physical_address_bits,
    )
    .map_err(|_| AddressSpaceError::PagingIntegrationFailed)?;
    // This walk is read-only, but the normal-boot policy fails closed on a
    // conflict in its declared scope. Emit the first concrete conflict before
    // any gate can return a generic integration error, preserving diagnostics.
    super::serial_write(
        b"ONE OS W^X POST-ACTIVATION AUDIT: READ-ONLY; NORMAL BOOT FAILS CLOSED ON CONFLICT\n",
    );
    super::interrupts::write_hex(
        b"ONE OS W^X POST-ACTIVATION CONFLICT EVENTS: ",
        audit.conflicting_overlap_events,
    );
    super::interrupts::write_hex(
        b"ONE OS W^X POST-ACTIVATION DIRECT MAP OFFSET: ",
        direct_map_coverage.virtual_offset,
    );
    super::interrupts::write_hex(
        b"ONE OS W^X POST-ACTIVATION DIRECT MAP PHYSICAL END: ",
        direct_map_coverage.physical_end,
    );
    super::interrupts::write_hex(
        b"ONE OS W^X POST-ACTIVATION DIRECT MAP COVERED VIRTUAL END: ",
        direct_map_coverage.covered_virtual_end,
    );
    super::interrupts::write_hex(
        b"ONE OS W^X POST-ACTIVATION DIRECT MAP LEAF MAPPINGS: ",
        direct_map_coverage.covered_leaf_mappings,
    );
    super::interrupts::write_hex(
        b"ONE OS W^X POST-ACTIVATION ACCOUNTED SOURCE MASK: ",
        scope.accounted_sources as u64,
    );
    super::interrupts::write_hex(
        b"ONE OS W^X POST-ACTIVATION DIRECT MAP SOURCE ACCOUNTED: ",
        if scope.accounted_sources
            & oneos_core::FrameWxAuditSource::PhysicalMemoryOffsetAlias.mask()
            != 0
        {
            1
        } else {
            0
        },
    );
    super::interrupts::write_hex(
        b"ONE OS W^X POST-ACTIVATION RECURSIVE VIEW SOURCE ACCOUNTED: ",
        if scope.accounted_sources & oneos_core::FrameWxAuditSource::RecursivePageTableView.mask()
            != 0
        {
            1
        } else {
            0
        },
    );
    super::interrupts::write_hex(
        b"ONE OS W^X POST-ACTIVATION SHARED KERNEL SOURCE ACCOUNTED: ",
        if scope.accounted_sources & oneos_core::FrameWxAuditSource::SharedKernelMappings.mask()
            != 0
        {
            1
        } else {
            0
        },
    );
    super::interrupts::write_hex(
        b"ONE OS W^X POST-ACTIVATION LARGE PAGE SOURCE ACCOUNTED: ",
        if scope.accounted_sources & oneos_core::FrameWxAuditSource::LargePageLeaves.mask() != 0 {
            1
        } else {
            0
        },
    );
    for root in scope.roots[..scope.declared_roots].iter() {
        super::interrupts::write_hex(
            b"ONE OS W^X POST-ACTIVATION ROOT PHYSICAL: ",
            root.physical_address,
        );
        super::interrupts::write_hex(
            b"ONE OS W^X POST-ACTIVATION ROOT COMPLETE: ",
            if root.audited { 1 } else { 0 },
        );
    }
    if let Some(conflict) = audit.first_conflict {
        super::serial_write(b"ONE OS W^X POST-ACTIVATION FIRST CONFLICT\n");
        super::interrupts::write_hex(
            b"ONE OS W^X CONFLICT PHYSICAL START: ",
            conflict.physical_start,
        );
        super::interrupts::write_hex(b"ONE OS W^X CONFLICT LENGTH: ", conflict.length);
        super::interrupts::write_hex(
            b"ONE OS W^X CONFLICT FIRST VIRTUAL START: ",
            conflict.first_virtual_start,
        );
        super::interrupts::write_hex(
            b"ONE OS W^X CONFLICT SECOND VIRTUAL START: ",
            conflict.second_virtual_start,
        );
        let first_flags = (conflict.first_permissions.writable as u64)
            | ((conflict.first_permissions.executable as u64) << 1);
        let second_flags = (conflict.second_permissions.writable as u64)
            | ((conflict.second_permissions.executable as u64) << 1);
        super::interrupts::write_hex(
            b"ONE OS W^X CONFLICT FIRST RIGHTS (W=BIT0,X=BIT1): ",
            first_flags,
        );
        super::interrupts::write_hex(
            b"ONE OS W^X CONFLICT SECOND RIGHTS (W=BIT0,X=BIT1): ",
            second_flags,
        );
    }

    if scope.declared_roots < 3
        || scope.audited_roots != scope.declared_roots
        || scope.missing_sources != 0
        || scope.accounted_sources & oneos_core::FrameWxAuditSource::RecursivePageTableView.mask()
            == 0
        || !scope.complete
    {
        return Err(AddressSpaceError::PagingIntegrationFailed);
    }

    // The dedicated root-token leak test intentionally skips the direct-map
    // W^X transition so it can exercise ownership/teardown against the legacy
    // boot mapping. Its audit must complete, but may still report that known
    // conflict. Normal boot requires a conflict-free result.
    #[cfg(all(
        not(feature = "test-root-leak-safety"),
        not(feature = "test-wx-runtime-audit")
    ))]
    if audit.conflicting_overlap_events != 0 || audit.first_conflict.is_some() {
        return Err(AddressSpaceError::PagingIntegrationFailed);
    }

    #[cfg(feature = "test-wx-runtime-audit")]
    {
        if audit.conflicting_overlap_events != 0
            || audit.first_conflict.is_some()
            || (audit.conflicting_overlap_events == 0) != audit.first_conflict.is_none()
        {
            return Err(AddressSpaceError::PagingIntegrationFailed);
        }

        // Emit the audit captured after the owned kernel root is active. Keep this
        // distinct from the earlier bootloader-root inspection in main.rs: the
        // latter's identity mappings may not survive CR3 activation.
        // The walk is read-only. Normal boot treats conflicts as fatal, but the
        // bounded declared-root inventory is not a global W^X guarantee.
        super::serial_write(
            b"ONE OS W^X RUNTIME AUDIT COMPLETE FOR DECLARED SCOPE (READ-ONLY; NORMAL BOOT FAILS CLOSED ON CONFLICT)\n",
        );
        super::interrupts::write_hex(b"ONE OS W^X RUNTIME ACTIVE ROOT: ", original_physical);
        super::interrupts::write_hex(
            b"ONE OS W^X RUNTIME DECLARED ROOTS: ",
            scope.declared_roots as u64,
        );
        super::interrupts::write_hex(
            b"ONE OS W^X RUNTIME AUDITED ROOTS: ",
            scope.audited_roots as u64,
        );
        super::interrupts::write_hex(
            b"ONE OS W^X RUNTIME MISSING SOURCES: ",
            scope.missing_sources as u64,
        );
        super::interrupts::write_hex(
            b"ONE OS W^X RUNTIME ALIAS MAPPINGS: ",
            audit.tracked_alias_mappings,
        );
        super::interrupts::write_hex(
            b"ONE OS W^X RUNTIME TRACKED RANGES: ",
            audit.tracked_ranges as u64,
        );
        super::interrupts::write_hex(
            b"ONE OS W^X RUNTIME CONFLICT EVENTS: ",
            audit.conflicting_overlap_events,
        );
        if let Some(conflict) = audit.first_conflict {
            super::serial_write(
                b"ONE OS W^X RUNTIME FIRST CONFLICT (FIRST SAMPLE ONLY; NOT AN EXHAUSTIVE LIST)\n",
            );
            super::interrupts::write_hex(
                b"ONE OS W^X RUNTIME CONFLICT PHYSICAL START: ",
                conflict.physical_start,
            );
            super::interrupts::write_hex(b"ONE OS W^X RUNTIME CONFLICT LENGTH: ", conflict.length);
            super::interrupts::write_hex(
                b"ONE OS W^X RUNTIME CONFLICT FIRST VIRTUAL START: ",
                conflict.first_virtual_start,
            );
            super::interrupts::write_hex(
                b"ONE OS W^X RUNTIME CONFLICT SECOND VIRTUAL START: ",
                conflict.second_virtual_start,
            );
            let first_flags = (conflict.first_permissions.writable as u64)
                | ((conflict.first_permissions.executable as u64) << 1);
            let second_flags = (conflict.second_permissions.writable as u64)
                | ((conflict.second_permissions.executable as u64) << 1);
            super::interrupts::write_hex(
                b"ONE OS W^X RUNTIME FIRST RIGHTS FLAGS (W=BIT0,X=BIT1): ",
                first_flags,
            );
            super::interrupts::write_hex(
                b"ONE OS W^X RUNTIME SECOND RIGHTS FLAGS (W=BIT0,X=BIT1): ",
                second_flags,
            );
        } else {
            super::serial_write(
                b"ONE OS W^X RUNTIME AUDIT OBSERVED NO CONFLICTS IN DECLARED SCOPE\n",
            );
        }
    }

    let (original_inactive, second_active) =
        activate_preflighted_user_root(active_root, second_root, boot_info, &user_registry)?;
    if second_active.physical_address() != second_physical
        || second_active.recursive_index() != second_recursive_index
    {
        return Err(AddressSpaceError::RootActivationFailed);
    }

    const USER_PAGE_SENTINEL: u64 = 0x4f4e_455f_5553_4552;
    const PEER_PAGE_SENTINEL: u64 = 0x5045_4552_5f44_4154;
    let user_page = 0x4000usize as *mut u64;
    // SAFETY: page 0x4000 is an owned writable user-data mapping in second_active.
    // Maskable interrupts and preemption are disabled, and the registry retains
    // the exact frame token until teardown completes.
    unsafe { ptr::write_volatile(user_page, USER_PAGE_SENTINEL) };
    // SAFETY: same validated mapping and lifetime conditions as the preceding write.
    if unsafe { ptr::read_volatile(user_page) } != USER_PAGE_SENTINEL {
        return Err(AddressSpaceError::PagingIntegrationFailed);
    }

    let (second_inactive, restored_active) =
        switch_address_space(second_active, original_inactive, boot_info, false)?;
    if restored_active.physical_address() != original_physical
        || restored_active.recursive_index() != original_recursive_index
        || second_inactive.physical_address() != second_physical
    {
        return Err(AddressSpaceError::RootActivationFailed);
    }

    // Confirm that the peer root independently supports the same VA before
    // tearing down the first root. The physical frames must be distinct.
    let (original_inactive_for_peer, peer_active) =
        activate_preflighted_user_root(restored_active, third_root, boot_info, &peer_registry)?;
    if peer_active.physical_address() != third_physical {
        return Err(AddressSpaceError::RootActivationFailed);
    }
    let peer_page = 0x4000usize as *mut u64;
    // SAFETY: page 0x4000 is the peer root's separately owned writable user page.
    unsafe { ptr::write_volatile(peer_page, PEER_PAGE_SENTINEL) };
    // SAFETY: the peer root remains active and the page is still registered.
    if unsafe { ptr::read_volatile(peer_page) } != PEER_PAGE_SENTINEL {
        return Err(AddressSpaceError::PagingIntegrationFailed);
    }
    let (peer_inactive, restored_active) =
        switch_address_space(peer_active, original_inactive_for_peer, boot_info, false)?;
    if restored_active.physical_address() != original_physical
        || peer_inactive.physical_address() != third_physical
    {
        return Err(AddressSpaceError::RootActivationFailed);
    }

    // Inject a one-shot allocator failure after the child table has been
    // detached. The first attempt must retain the token as a pending frame;
    // a normal second attempt must drain it and finish teardown safely.
    let first_teardown_attempt = {
        let mut fail_next_table_release = true;
        let mut release_table_frame = |frame| {
            if fail_next_table_release {
                fail_next_table_release = false;
                Err((super::memory::MemoryError::Busy, frame))
            } else {
                super::memory::free_frame(frame)
            }
        };
        super::paging::teardown_inactive_user_address_space_with_table_release(
            boot_info,
            &second_inactive,
            &restored_active,
            &mut user_registry,
            &mut release_table_frame,
        )
    };
    if !matches!(
        first_teardown_attempt,
        Err(super::paging::InactiveAddressSpaceTeardownError::Kernel(
            super::paging::PagingError::PageTableFrameReleaseFailed
        ))
    ) || !super::paging::has_pending_detached_private_table(second_physical)
    {
        super::serial_write(b"ONE OS DETACHED TABLE RELEASE RETRY FAILED\n");
        return Err(AddressSpaceError::PagingIntegrationFailed);
    }

    super::paging::teardown_inactive_user_address_space(
        boot_info,
        &second_inactive,
        &restored_active,
        &mut user_registry,
    )
    .map_err(|error| {
        match error {
            super::paging::InactiveAddressSpaceTeardownError::Kernel(kernel_error) => {
                super::serial_write(kernel_error.message());
            }
            super::paging::InactiveAddressSpaceTeardownError::UserPages(failure) => {
                let _cause = failure.error();
                if failure.completed_pages() == 0 {
                    super::serial_write(b"ONE OS USER PAGE TEARDOWN FAILED BEFORE COMPLETION\n");
                } else {
                    super::serial_write(
                        b"ONE OS USER PAGE TEARDOWN FAILED AFTER PARTIAL COMPLETION\n",
                    );
                }
            }
        }
        AddressSpaceError::PagingIntegrationFailed
    })?;
    release_inactive_address_space_root(boot_info, &restored_active, second_inactive)?;

    // Re-enter the peer after the first root has been fully torn down and its
    // private tables reclaimed. Its same-VA mapping and data must be unchanged.
    let (original_inactive_for_peer_check, peer_active_check) =
        activate_preflighted_user_root(restored_active, peer_inactive, boot_info, &peer_registry)?;
    if peer_active_check.physical_address() != third_physical {
        return Err(AddressSpaceError::RootActivationFailed);
    }
    // SAFETY: this is the peer root's still-registered mapping at VA 0x4000.
    if unsafe { ptr::read_volatile(peer_page) } != PEER_PAGE_SENTINEL {
        return Err(AddressSpaceError::PagingIntegrationFailed);
    }
    let (peer_inactive, final_active) = switch_address_space(
        peer_active_check,
        original_inactive_for_peer_check,
        boot_info,
        false,
    )?;
    if final_active.physical_address() != original_physical
        || final_active.recursive_index() != original_recursive_index
        || peer_inactive.physical_address() != third_physical
    {
        return Err(AddressSpaceError::RootActivationFailed);
    }

    super::paging::teardown_inactive_user_address_space(
        boot_info,
        &peer_inactive,
        &final_active,
        &mut peer_registry,
    )
    .map_err(|error| {
        match error {
            super::paging::InactiveAddressSpaceTeardownError::Kernel(kernel_error) => {
                super::serial_write(kernel_error.message());
            }
            super::paging::InactiveAddressSpaceTeardownError::UserPages(failure) => {
                let _cause = failure.error();
                if failure.completed_pages() == 0 {
                    super::serial_write(b"ONE OS USER PAGE TEARDOWN FAILED BEFORE COMPLETION\n");
                } else {
                    super::serial_write(
                        b"ONE OS USER PAGE TEARDOWN FAILED AFTER PARTIAL COMPLETION\n",
                    );
                }
            }
        }
        AddressSpaceError::PagingIntegrationFailed
    })?;
    release_inactive_address_space_root(boot_info, &final_active, peer_inactive)?;
    #[cfg(feature = "test-root-leak-safety")]
    verify_root_leak_allocator_smoke_test(boot_info, &final_active)?;
    Ok(final_active)
}

#[cfg(feature = "test-cr3-switch-guard")]
fn verify_runtime_address_space_switch_smoke_test_impl(
    boot_info: &BootInfo,
    active_root: ActiveAddressSpaceRoot,
    _wx_probe: Option<(u64, u64)>,
) -> Result<ActiveAddressSpaceRoot, AddressSpaceError> {
    const PASS: &[u8] = b"ONE OS CR3 SWITCH UNREGISTERED ROOT REJECT PASS\n";
    const FAIL: &[u8] = b"ONE OS CR3 SWITCH UNREGISTERED ROOT REJECT FAIL\n";

    let original_physical = active_root.physical_address();
    let second_root = match create_inactive_address_space_root(boot_info, &active_root) {
        Ok(root) => root,
        Err(_) => cr3_guard_test_exit(false, PASS, FAIL),
    };
    let second_physical = second_root.physical_address();
    if second_root.recursive_index().is_none()
        || second_physical == original_physical
        || !super::paging::is_uniquely_registered_address_space_root(original_physical)
        || !super::paging::is_uniquely_registered_address_space_root(second_physical)
        || !matches!(
            super::memory::is_frame_allocated(original_physical),
            Ok(true)
        )
        || !matches!(super::memory::is_frame_allocated(second_physical), Ok(true))
    {
        cr3_guard_test_exit(false, PASS, FAIL);
    }
    if !super::paging::remove_address_space_root_registration_for_cr3_test(second_physical) {
        cr3_guard_test_exit(false, PASS, FAIL);
    }

    // Exercise the actual switching function. It consumes both ownership handles
    // even on an early error, so this image exits immediately after checking state.
    match switch_address_space(active_root, second_root, boot_info, false) {
        Err(AddressSpaceError::RootNotRegistered) => {
            let target_restored = super::paging::register_address_space_root(second_physical);
            let invariants_hold = target_restored
                && active_root_table_physical() == original_physical
                && super::paging::is_uniquely_registered_address_space_root(original_physical)
                && super::paging::is_uniquely_registered_address_space_root(second_physical)
                && matches!(
                    super::memory::is_frame_allocated(original_physical),
                    Ok(true)
                )
                && matches!(super::memory::is_frame_allocated(second_physical), Ok(true));
            cr3_guard_test_exit(invariants_hold, PASS, FAIL);
        }
        _ => cr3_guard_test_exit(false, PASS, FAIL),
    }
}

/// Clears and releases one inactive root after its user mappings and private
/// intermediate tables have already been removed by the root-scoped teardown.
fn release_inactive_address_space_root(
    boot_info: &BootInfo,
    active_root: &ActiveAddressSpaceRoot,
    root: AddressSpaceRoot,
) -> Result<(), AddressSpaceError> {
    let root_physical = root.physical_address();
    let (physical_address_bits, physical_memory_offset) =
        validate_runtime_root_context(boot_info, active_root)?;
    let mut editor = KernelAddressSpaceRootEditor {
        regions: &boot_info.memory_regions,
        physical_memory_offset,
        kernel_root_physical: active_root.physical_address(),
        root_physical,
        recursive_index: active_root.recursive_index(),
        physical_address_bits,
        kernel_root_is_owned: true,
        kernel_root_pointer: None,
        destination_root_pointer: None,
    };
    if !editor.table_is_readable(active_root.physical_address())
        || !editor.table_is_read_write_accessible(root_physical)
    {
        return Err(AddressSpaceError::RootTableUnavailable);
    }
    clear_and_release_root(root, &mut editor, root_physical)
}

/// Conservatively handles a CR3 readback that does not establish which root is
/// active. The token is abandoned without assuming that `root` is inactive.
fn abandon_uncertain_root_activation(root: AddressSpaceRoot) -> AddressSpaceError {
    root.leak_frame();
    AddressSpaceError::RootActivationFailed
}

/// Checks the real kernel allocator through the same conservative error handler
/// used by a CR3 readback mismatch. This is compiled only into the dedicated QEMU
/// acceptance image so normal boots do not permanently consume a test frame.
#[cfg(feature = "test-root-leak-safety")]
fn verify_root_leak_allocator_smoke_test(
    boot_info: &BootInfo,
    active_root: &ActiveAddressSpaceRoot,
) -> Result<(), AddressSpaceError> {
    let root = create_inactive_address_space_root(boot_info, active_root)?;
    let root_physical = root.physical_address();

    if abandon_uncertain_root_activation(root) != AddressSpaceError::RootActivationFailed {
        return Err(AddressSpaceError::RootLeakSafetyFailed);
    }

    match super::memory::is_frame_allocated(root_physical) {
        Ok(true) => {
            super::serial_write(b"ONE OS ROOT LEAK SAFETY PASS\n");
            Ok(())
        }
        Ok(false) | Err(_) => Err(AddressSpaceError::RootLeakSafetyFailed),
    }
}

/// Revalidates the live kernel context at the CR3-switch boundary.
///
/// The active handle, hardware CR3, CPU control state, current stack, BootInfo,
/// memory-region metadata, and physical-memory offset must all remain valid
/// through the shared upper-half mappings. The root frame itself is allocator
/// owned and must still be marked allocated.
fn validate_runtime_root_context(
    boot_info: &BootInfo,
    active_root: &ActiveAddressSpaceRoot,
) -> Result<(u8, u64), AddressSpaceError> {
    const KERNEL_HALF_START: u64 = 0xffff_8000_0000_0000;

    let recursive_index = active_root.recursive_index();
    if !(LOWER_HALF_PML4_ENTRIES as u16..PML4_ENTRY_COUNT as u16).contains(&recursive_index) {
        return Err(AddressSpaceError::InvalidRecursiveIndex);
    }

    let cr0: u64;
    let cr4: u64;
    let efer_low: u32;
    let efer_high: u32;
    let rflags: u64;
    let stack_pointer: u64;
    // SAFETY: these registers are readable in privileged x86_64 kernel context.
    // The values are re-read at each call to this runtime switch boundary.
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        asm!("mov {}, rsp", out(reg) stack_pointer, options(nomem, nostack, preserves_flags));
        asm!("pushfq", "pop {}", out(reg) rflags, options(preserves_flags));
        asm!(
            "rdmsr",
            in("ecx") EFER_MSR,
            out("eax") efer_low,
            out("edx") efer_high,
            options(nomem, nostack, preserves_flags)
        );
    }
    let efer = (u64::from(efer_high) << 32) | u64::from(efer_low);
    validate_kernel_root_activation_state(cr0, cr4, efer, rflags)
        .map_err(AddressSpaceError::PagingPrecondition)?;

    let physical_memory_offset = match boot_info.physical_memory_offset {
        Optional::Some(offset) => offset,
        Optional::None => return Err(AddressSpaceError::PhysicalMemoryOffsetUnavailable),
    };
    let code_address = validate_runtime_root_context as *const () as usize as u64;
    let boot_info_address = boot_info as *const BootInfo as usize as u64;
    let memory_regions_address = boot_info.memory_regions.as_ptr() as usize as u64;
    let kernel_stack_end = boot_info
        .kernel_stack_bottom
        .checked_add(boot_info.kernel_stack_len)
        .filter(|_| boot_info.kernel_stack_len != 0)
        .ok_or(AddressSpaceError::KernelMappingNotInUpperHalf)?;
    let kernel_stack_last = kernel_stack_end
        .checked_sub(1)
        .ok_or(AddressSpaceError::KernelMappingNotInUpperHalf)?;

    if !is_kernel_half_address(code_address, KERNEL_HALF_START)
        || !is_kernel_half_address(stack_pointer, KERNEL_HALF_START)
        || !is_kernel_half_address(boot_info_address, KERNEL_HALF_START)
        || !is_kernel_half_address(memory_regions_address, KERNEL_HALF_START)
        || !is_kernel_half_address(boot_info.kernel_image_offset, KERNEL_HALF_START)
        || !is_kernel_half_address(boot_info.kernel_stack_bottom, KERNEL_HALF_START)
        || !is_kernel_half_address(kernel_stack_last, KERNEL_HALF_START)
        || !is_kernel_half_address(physical_memory_offset, KERNEL_HALF_START)
        || stack_pointer < boot_info.kernel_stack_bottom
        || stack_pointer >= kernel_stack_end
    {
        return Err(AddressSpaceError::KernelMappingNotInUpperHalf);
    }

    let maximum_extended_leaf = __cpuid(CPUID_MAX_EXTENDED_LEAF).eax;
    if maximum_extended_leaf < CPUID_PHYSICAL_ADDRESS_WIDTH {
        return Err(AddressSpaceError::InvalidPhysicalAddressWidth { bits: 0 });
    }
    let physical_address_bits = (__cpuid(CPUID_PHYSICAL_ADDRESS_WIDTH).eax & 0xff) as u8;
    if !(32..=52).contains(&physical_address_bits)
        || active_root.physical_address_bits() != physical_address_bits
    {
        return Err(AddressSpaceError::InvalidPhysicalAddressWidth {
            bits: physical_address_bits,
        });
    }

    let root_physical = active_root_table_physical();
    if root_physical != active_root.physical_address()
        || !is_physical_page(root_physical, physical_address_bits)
        || !is_region_page(
            &boot_info.memory_regions,
            root_physical,
            MemoryRegionKind::Usable,
        )
        || !matches!(super::memory::is_frame_allocated(root_physical), Ok(true))
    {
        return Err(AddressSpaceError::InvalidKernelRoot);
    }

    // Check the active root's recursive self-reference before relying on it to
    // inspect any page-table entries. Its root frame is owned Usable memory,
    // unlike the original bootloader root used during initial activation.
    let editor = KernelAddressSpaceRootEditor {
        regions: &boot_info.memory_regions,
        physical_memory_offset,
        kernel_root_physical: root_physical,
        root_physical,
        recursive_index,
        physical_address_bits,
        kernel_root_is_owned: true,
        kernel_root_pointer: None,
        destination_root_pointer: None,
    };
    if editor.kernel_root_pointer().is_none() {
        return Err(AddressSpaceError::InvalidKernelRoot);
    }

    Ok((physical_address_bits, physical_memory_offset))
}

/// Constructs and activates a root that retains only validated supervisor-only
/// kernel-half mappings. The returned handle owns the active root frame and must
/// remain live for as long as this address space is active.
///
/// The bootloader must place the kernel image, stack, BootInfo, physical-memory
/// alias, and all boot-time dynamic mappings in the upper canonical half. The
/// checks below fail closed before changing CR3 if any required execution state
/// remains in the lower half. This routine is single-CPU and requires interrupts
/// to remain disabled, as established by kernel_main.
pub fn activate_supervisor_kernel_root(
    boot_info: &BootInfo,
) -> Result<ActiveAddressSpaceRoot, AddressSpaceError> {
    const KERNEL_HALF_START: u64 = 0xffff_8000_0000_0000;
    const CR4_PGE: u64 = 1 << 7;

    let recursive_index = match boot_info.recursive_index {
        Optional::Some(index) if is_safe_recursive_mapping_index(index) => index,
        Optional::Some(_) => return Err(AddressSpaceError::InvalidRecursiveIndex),
        Optional::None => return Err(AddressSpaceError::RecursiveMappingUnavailable),
    };
    let physical_memory_offset = match boot_info.physical_memory_offset {
        Optional::Some(offset) => offset,
        Optional::None => return Err(AddressSpaceError::PhysicalMemoryOffsetUnavailable),
    };

    let cr0: u64;
    let cr4: u64;
    let efer_low: u32;
    let efer_high: u32;
    let rflags: u64;
    let stack_pointer: u64;
    // SAFETY: paging controls, EFER, RFLAGS, and RSP are readable in the
    // privileged x86_64 kernel. These are re-read at the actual CR3-switch
    // boundary rather than assumed from earlier initialization.
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        asm!("mov {}, rsp", out(reg) stack_pointer, options(nomem, nostack, preserves_flags));
        asm!("pushfq", "pop {}", out(reg) rflags, options(preserves_flags));
        asm!(
            "rdmsr",
            in("ecx") EFER_MSR,
            out("eax") efer_low,
            out("edx") efer_high,
            options(nomem, nostack, preserves_flags)
        );
    }
    let efer = (u64::from(efer_high) << 32) | u64::from(efer_low);
    validate_kernel_root_activation_state(cr0, cr4, efer, rflags)
        .map_err(AddressSpaceError::PagingPrecondition)?;

    let code_address = activate_supervisor_kernel_root as *const () as usize as u64;
    let boot_info_address = boot_info as *const BootInfo as usize as u64;
    let memory_regions_address = boot_info.memory_regions.as_ptr() as usize as u64;
    let kernel_stack_end = boot_info
        .kernel_stack_bottom
        .checked_add(boot_info.kernel_stack_len)
        .filter(|_| boot_info.kernel_stack_len != 0)
        .ok_or(AddressSpaceError::KernelMappingNotInUpperHalf)?;
    let kernel_stack_last = kernel_stack_end
        .checked_sub(1)
        .ok_or(AddressSpaceError::KernelMappingNotInUpperHalf)?;

    // A new root clears every lower-half PML4 entry. Verify every pointer needed
    // after CR3 changes before preparing or publishing that root.
    if !is_kernel_half_address(code_address, KERNEL_HALF_START)
        || !is_kernel_half_address(stack_pointer, KERNEL_HALF_START)
        || !is_kernel_half_address(boot_info_address, KERNEL_HALF_START)
        || !is_kernel_half_address(memory_regions_address, KERNEL_HALF_START)
        || !is_kernel_half_address(boot_info.kernel_image_offset, KERNEL_HALF_START)
        || !is_kernel_half_address(boot_info.kernel_stack_bottom, KERNEL_HALF_START)
        || !is_kernel_half_address(kernel_stack_last, KERNEL_HALF_START)
        || !is_kernel_half_address(physical_memory_offset, KERNEL_HALF_START)
        || stack_pointer < boot_info.kernel_stack_bottom
        || stack_pointer >= kernel_stack_end
    {
        return Err(AddressSpaceError::KernelMappingNotInUpperHalf);
    }

    let maximum_extended_leaf = __cpuid(CPUID_MAX_EXTENDED_LEAF).eax;
    if maximum_extended_leaf < CPUID_PHYSICAL_ADDRESS_WIDTH {
        return Err(AddressSpaceError::InvalidPhysicalAddressWidth { bits: 0 });
    }
    let physical_address_bits = (__cpuid(CPUID_PHYSICAL_ADDRESS_WIDTH).eax & 0xff) as u8;
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

    let frame =
        super::memory::allocate_frame().map_err(|_| AddressSpaceError::FrameAllocationFailed)?;
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
        kernel_root_is_owned: false,
        kernel_root_pointer: None,
        destination_root_pointer: None,
    };
    if !super::paging::register_address_space_root(root_physical) {
        clear_and_release_unregistered_root(root, &mut editor, root_physical)?;
        return Err(AddressSpaceError::RootFrameRegistryFull);
    }

    let kernel_root_readable = editor.table_is_readable(kernel_root_physical);
    let destination_root_writable = editor.table_is_read_write_accessible(root_physical);
    if !kernel_root_readable || !destination_root_writable {
        if destination_root_writable {
            clear_and_release_root(root, &mut editor, root_physical)?;
        } else {
            // Keep an inaccessible allocation reserved rather than recycling
            // memory whose contents could not be safely zeroed.
            // Cleanup or access is uncertain. Preserve the allocator reservation.
            root.leak_frame();
        }
        return Err(AddressSpaceError::RootTableUnavailable);
    }

    let root_recursive_index = match editor.select_root_recursive_index() {
        Ok(index) => index,
        Err(error) => {
            clear_and_release_root(root, &mut editor, root_physical)?;
            return Err(error);
        }
    };

    // select_root_recursive_index searches only upper-half PML4 slots
    // (256..512), so this conversion preserves the private recursive index.
    let active_recursive_index = root_recursive_index as u16;

    let initialization = root.initialize_from_kernel_root(
        kernel_root_physical,
        usize::from(recursive_index),
        root_recursive_index,
        &mut editor,
    );
    if let Err(error) = initialization {
        clear_and_release_root(root, &mut editor, root_physical)?;
        return Err(AddressSpaceError::RootInitialization(error));
    }
    if let Err(error) = verify_initialized_entries(
        &mut editor,
        root_physical,
        kernel_root_physical,
        usize::from(recursive_index),
        root_recursive_index,
        false,
    ) {
        clear_and_release_root(root, &mut editor, root_physical)?;
        return Err(error);
    }

    // This initial activation path writes CR3 directly rather than using
    // switch_address_space; enforce the same live-root invariant at its boundary.
    #[cfg(feature = "test-cr3-activation-guard")]
    let cr3_before_guard_test = active_root_table_physical();
    #[cfg(feature = "test-cr3-activation-guard")]
    {
        CR3_ACTIVATION_GUARD_TEST_PASSED.store(false, Ordering::Release);
        CR3_ACTIVATION_GUARD_TEST_TARGET.store(root_physical, Ordering::Release);
    }

    if let Err(error) = validate_registered_root_for_activation(root_physical) {
        // Keep the production rejection/cleanup path intact in the test image.
        clear_and_release_root(root, &mut editor, root_physical)?;
        #[cfg(feature = "test-cr3-activation-guard")]
        if error == AddressSpaceError::RootNotRegistered {
            let rejection_invariants_hold = active_root_table_physical() == cr3_before_guard_test
                && matches!(super::memory::is_frame_allocated(root_physical), Ok(false))
                && !super::paging::is_uniquely_registered_address_space_root(root_physical);
            CR3_ACTIVATION_GUARD_TEST_PASSED.store(rejection_invariants_hold, Ordering::Release);
        }
        return Err(error);
    }

    // Always make the PGE-disabled state explicit before writing CR3.
    // This keeps the switch contract uniform even when PGE was already clear:
    // CR4.PGE is cleared, CR3 is written, and the original CR4 is restored on
    // every successful switch path. PCID is rejected above because its tagged
    // TLB behavior is outside this bootstrap contract.
    let cr4_without_pge = cr4 & !CR4_PGE;
    // SAFETY: PGE may be toggled by the privileged kernel; disabling it
    // flushes global translations before the root switch. Writing the same
    // value when PGE was already clear is harmless and simplifies verification.
    unsafe {
        asm!(
            "mov cr4, {}",
            in(reg) cr4_without_pge,
            options(nomem, nostack, preserves_flags)
        );
    }
    // This asm intentionally omits `nomem`: changing CR3 is a compiler
    // memory-ordering boundary. Keep page-table initialization and all memory
    // accesses that depend on the active address space ordered around the switch.
    // SAFETY: root initialization and complete required mapping checks have
    // succeeded; all execution-critical mappings are in the copied upper half.
    unsafe {
        asm!(
            "mov cr3, {}",
            in(reg) root_physical,
            options(nostack, preserves_flags)
        );
    }
    // SAFETY: restore the original paging-feature configuration after CR3
    // has switched and all old global translations have been flushed. This is
    // unconditional so every successful CR3 write has a matching restoration.
    unsafe {
        asm!(
            "mov cr4, {}",
            in(reg) cr4,
            options(nomem, nostack, preserves_flags)
        );
    }

    if active_root_table_physical() != root_physical {
        // The root may already be active. Never recycle its frame after a
        // switch attempt whose observed result is uncertain. The shared handler
        // deliberately does not assume that the root is inactive.
        return Err(abandon_uncertain_root_activation(root));
    }

    // SAFETY: CR3 readback above matched root_physical. This is the architecture
    // layer's successful activation boundary; it retains the root token rather
    // than exposing it for allocator reuse.
    Ok(unsafe { ActiveAddressSpaceRoot::from_activated(root, active_recursive_index) })
}

fn is_kernel_half_address(address: u64, kernel_half_start: u64) -> bool {
    is_canonical_4level(address) && address >= kernel_half_start
}

fn verify_initialized_entries(
    editor: &mut KernelAddressSpaceRootEditor<'_>,
    root_physical: u64,
    kernel_root_physical: u64,
    kernel_recursive_index: usize,
    root_recursive_index: usize,
    allow_user_mappings: bool,
) -> Result<(), AddressSpaceError> {
    if !allow_user_mappings {
        for index in 0..LOWER_HALF_PML4_ENTRIES {
            if editor.read_entry(root_physical, index, 4) != Some(0) {
                return Err(AddressSpaceError::RootVerificationFailed { index });
            }
        }
    }

    for index in LOWER_HALF_PML4_ENTRIES..PML4_ENTRY_COUNT {
        let expected = if index == root_recursive_index {
            root_physical | PRESENT | WRITABLE | NO_EXECUTE
        } else if index == kernel_recursive_index {
            0
        } else {
            editor
                .read_entry(kernel_root_physical, index, 4)
                .ok_or(AddressSpaceError::RootTableUnavailable)?
        };
        let observed = editor
            .read_entry(root_physical, index, 4)
            .ok_or(AddressSpaceError::RootTableUnavailable)?;
        // The processor sets the PML4 Accessed bit as it walks either root.
        // Treat only that hardware-maintained bit as mutable; continue requiring
        // every address and permission bit to match the expected entry.
        let comparison_mask = if expected & PRESENT != 0 {
            !ACCESSED
        } else {
            u64::MAX
        };
        if observed & comparison_mask != expected & comparison_mask {
            return Err(AddressSpaceError::RootVerificationFailed { index });
        }
    }

    Ok(())
}

/// Clears and verifies the entire PML4 frame before releasing its ownership token.
/// If zeroization fails, the frame is deliberately leaked rather than recycled.
/// Clears and releases a newly allocated root whose registry insertion failed.
///
/// This is used only before the root has been initialized or published. It must
/// not remove any registry entry because registration did not succeed.
fn clear_and_release_unregistered_root(
    root: AddressSpaceRoot,
    editor: &mut KernelAddressSpaceRootEditor<'_>,
    root_physical: u64,
) -> Result<(), AddressSpaceError> {
    if let Err(error) = clear_root_entries(editor, root_physical) {
        root.leak_frame();
        return Err(error);
    }
    release_frame(unsafe { root.into_frame() })
}

fn clear_and_release_root(
    root: AddressSpaceRoot,
    editor: &mut KernelAddressSpaceRootEditor<'_>,
    root_physical: u64,
) -> Result<(), AddressSpaceError> {
    // Validate the exact registry relationship before making the frame
    // allocator-reusable. If it is absent/duplicated, preserve ownership so a
    // stale registry reference can never alias an unrelated future allocation.
    if root_physical == active_root_table_physical()
        || !super::paging::is_uniquely_registered_address_space_root(root_physical)
    {
        root.leak_frame();
        return Err(AddressSpaceError::RootRegistryCleanupFailed);
    }

    if let Err(error) = clear_root_entries(editor, root_physical) {
        // Cleanup or access is uncertain. Preserve the allocator reservation and
        // keep the root registered so it cannot be mapped as ordinary data.
        root.leak_frame();
        return Err(error);
    }
    // SAFETY: the root PML4 was cleared and verified above. Callers either
    // release a never-activated construction root with no private child tables,
    // or call only after switching away and completing inactive-root teardown.
    let result = release_frame(unsafe { root.into_frame() });
    if result.is_ok() && !super::paging::unregister_address_space_root(root_physical) {
        return Err(AddressSpaceError::RootRegistryCleanupFailed);
    }
    result
}

fn clear_root_entries(
    editor: &mut KernelAddressSpaceRootEditor<'_>,
    root_physical: u64,
) -> Result<(), AddressSpaceError> {
    for index in 0..PML4_ENTRY_COUNT {
        editor.write_entry(root_physical, index, 4, 0);
    }
    for index in 0..PML4_ENTRY_COUNT {
        if editor.read_entry(root_physical, index, 4) != Some(0) {
            return Err(AddressSpaceError::RootZeroizationFailed { index });
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
    kernel_root_is_owned: bool,
    kernel_root_pointer: Option<*mut u64>,
    destination_root_pointer: Option<*mut u64>,
}

impl KernelAddressSpaceRootEditor<'_> {
    fn kernel_root_pointer(&self) -> Option<*mut u64> {
        let root_region_valid = if self.kernel_root_is_owned {
            is_region_page(
                self.regions,
                self.kernel_root_physical,
                MemoryRegionKind::Usable,
            ) && matches!(
                super::memory::is_frame_allocated(self.kernel_root_physical),
                Ok(true)
            )
        } else {
            is_region_page(
                self.regions,
                self.kernel_root_physical,
                MemoryRegionKind::Bootloader,
            )
        };
        if !root_region_valid {
            return None;
        }

        let alias =
            recursive_table_page_virtual_address(self.recursive_index, ROOT_ALIAS_TARGET, 4)?;
        let pointer = entry_pointer_from_page(alias, 0)?;
        // SAFETY: the bootloader API promises that the reported recursive slot
        // maps the active PML4 to itself. The entry is checked immediately after
        // this read; as with the existing inspector, the first access relies on
        // that documented mapping contract.
        let recursive_entry = unsafe {
            ptr::read_volatile(entry_pointer_from_page(
                alias,
                usize::from(self.recursive_index),
            )?)
        };
        let valid_recursive_entry = if self.kernel_root_is_owned {
            recursive_entry_is_valid_kernel_root(recursive_entry, self.kernel_root_physical)
        } else {
            // The bootloader-owned source root is allowed to use its original
            // recursive-entry flags; the owned active kernel root must also set NX.
            recursive_entry_matches_root(recursive_entry, self.kernel_root_physical)
                && recursive_entry & WRITABLE != 0
                && recursive_entry & USER_ACCESSIBLE == 0
                && recursive_entry & PROTECTION_KEY_FIELD_MASK == 0
        };
        if !valid_recursive_entry {
            return None;
        }
        Some(pointer)
    }

    fn select_root_recursive_index(&mut self) -> Result<usize, AddressSpaceError> {
        if !self.table_is_readable(self.kernel_root_physical) {
            return Err(AddressSpaceError::RootTableUnavailable);
        }

        for index in (LOWER_HALF_PML4_ENTRIES..PML4_ENTRY_COUNT).rev() {
            if index == usize::from(self.recursive_index) {
                continue;
            }
            match self.read_entry(self.kernel_root_physical, index, 4) {
                Some(0) => return Ok(index),
                Some(_) => continue,
                None => return Err(AddressSpaceError::RootTableUnavailable),
            }
        }
        Err(AddressSpaceError::NoUnusedRecursiveIndex)
    }

    fn destination_root_pointer(&self) -> Option<*mut u64> {
        // Validate the recursive self-reference before translating the direct-map
        // alias, matching the precondition established by boot mapping inspection.
        let _validated_kernel_root = self.kernel_root_pointer()?;
        if !is_physical_page(self.root_physical, self.physical_address_bits)
            || !is_region_page(self.regions, self.root_physical, MemoryRegionKind::Usable)
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
            self.kernel_root_is_owned,
        )?;
        if translation.physical_address != self.root_physical
            || !translation.writable
            || translation.user_accessible
            || translation.executable
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
    root_is_owned: bool,
) -> Option<oneos_core::PageTranslation> {
    let mut level = 4u8;
    translate_4level(virtual_address, root_physical, |table_physical, index| {
        let current_level = level;
        let table_region_allowed = if current_level == 4 && root_is_owned {
            table_physical == root_physical
                && is_region_page(regions, table_physical, MemoryRegionKind::Usable)
                && matches!(super::memory::is_frame_allocated(table_physical), Ok(true))
        } else {
            is_region_page(regions, table_physical, MemoryRegionKind::Bootloader)
                || super::paging::registered_published_page_table_frame(table_physical)
        };
        if current_level == 0
            || (current_level == 4 && table_physical != root_physical)
            || !table_region_allowed
        {
            return None;
        }

        let table_virtual =
            recursive_table_page_virtual_address(recursive_index, virtual_address, current_level)?;
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
    let offset = u64::try_from(index)
        .ok()?
        .checked_mul(size_of::<u64>() as u64)?;
    let address = table_virtual_address.checked_add(offset)?;
    let end = address.checked_add(size_of::<u64>() as u64 - 1)?;
    if address == 0
        || !is_canonical_4level(address)
        || !is_canonical_4level(end)
        || address & 7 != 0
    {
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
