//! Ownership and address-space initialization primitives for x86_64.
//!
//! These host-testable types initialize an inactive PML4 root by copying only
//! supervisor-only kernel-half entries from a validated kernel root. They do
//! not map user pages, switch CR3, invalidate TLB entries, or reclaim lower-level
//! page tables. The caller must keep the source root stable and complete those
//! operations before activating an address space.

use crate::{Frame, PAGE_SIZE};

/// Exclusive upper bound of the lower canonical half used for ring-3 addresses
/// under x86_64 four-level paging.
///
/// User ranges are represented as half-open ranges: start through start + length.
pub const USER_VIRTUAL_ADDRESS_LIMIT: u64 = 0x0000_8000_0000_0000;

/// A physical-frame validation failure when constructing an owned root handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressSpaceRootError {
    /// The CPU physical-address width is outside the supported 32 through 52-bit range.
    InvalidPhysicalAddressWidth {
        /// Physical-address width reported by the caller.
        bits: u8,
    },
    /// Physical frame zero cannot be an address-space root.
    ZeroRootFrame,
    /// The root frame address is not 4 KiB aligned.
    UnalignedRootFrame,
    /// The complete root frame exceeds the supported physical-address width.
    RootFrameOutOfRange,
}

/// Validation failure for a half-open virtual range intended for ring 3.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserVirtualRangeError {
    /// Empty ranges are not valid user-memory ranges.
    EmptyRange,
    /// Computing the exclusive end of the range overflowed u64.
    RangeOverflow,
    /// The range includes an address outside the lower canonical half.
    OutsideUserHalf,
}

/// Ownership-carrying handle for a physical frame designated as a PML4 root.
///
/// The owned Frame token prevents callers from accidentally duplicating the
/// root's allocator ownership. The constructor validates address shape and
/// physical-address width, but cannot inspect or initialize the frame's
/// contents. The caller must prepare the page-table root and its required
/// kernel mappings before publishing or activating it.
///
/// This type intentionally does not implement Copy or Clone. Calling
/// into_frame consumes the handle and returns the token; the caller must ensure
/// the root and all page-table resources reachable from it are no longer active
/// or reachable and required TLB invalidation has completed before returning
/// that token to the physical allocator.
#[must_use = "dropping an address-space root handle leaks its physical frame"]
#[derive(Debug)]
pub struct AddressSpaceRoot {
    frame: Frame,
    physical_address_bits: u8,
    initialized: bool,
    recursive_index: Option<u16>,
}

impl AddressSpaceRoot {
    /// Wraps an exclusively owned frame as an inactive four-level PML4 root.
    ///
    /// The frame contents are not inspected or initialized by this constructor.
    /// Call initialize_from_kernel_root before the root is eligible for
    /// activation. The frame must not already be reachable from a live page table.
    /// On validation failure, the original token is returned to the caller.
    pub fn try_from_frame(
        frame: Frame,
        physical_address_bits: u8,
    ) -> Result<Self, (AddressSpaceRootError, Frame)> {
        let address = frame.physical_address();
        if let Err(error) = validate_root_frame_address(address, physical_address_bits) {
            return Err((error, frame));
        }

        Ok(Self {
            frame,
            physical_address_bits,
            initialized: false,
            recursive_index: None,
        })
    }

    /// Returns the root frame's physical base address.
    pub const fn physical_address(&self) -> u64 {
        self.frame.physical_address()
    }

    /// Returns the physical-address width used when validating this root.
    pub const fn physical_address_bits(&self) -> u8 {
        self.physical_address_bits
    }

    /// Returns whether the root has been initialized with supervisor-only kernel mappings.
    pub const fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Returns the root's private recursive PML4 index after initialization.
    ///
    /// A newly allocated root has no recursive index until initialization succeeds.
    pub const fn recursive_index(&self) -> Option<u16> {
        self.recursive_index
    }

    /// Initializes this inactive root from the kernel's validated PML4.
    ///
    /// The source recursive index may be in either canonical half because it
    /// comes from the bootloader's active page tables. The destination recursive
    /// index must be in the upper half and must name an unused source PML4 slot.
    /// The active source recursive entry is omitted from the new root; the new
    /// root receives its own supervisor-writable, non-executable self-reference.
    ///
    /// The operation preflights all source entries and table-access requirements
    /// before the first write. It then clears the lower canonical half and copies
    /// only supervisor-only upper-half entries, excluding both recursive slots.
    /// The editor must provide read/write access to the complete root frame and
    /// read access to the source root. Its write_entry operation must not fail
    /// after table_is_read_write_accessible returns true. The source root must
    /// remain stable for the duration of the call; callers are responsible for
    /// synchronization and for keeping this root inactive until construction is
    /// complete. The CPU must have NX enabled before this root is activated.
    pub fn initialize_from_kernel_root<E: AddressSpaceRootEditor>(
        &mut self,
        kernel_root_physical: u64,
        kernel_recursive_index: usize,
        root_recursive_index: usize,
        editor: &mut E,
    ) -> Result<(), AddressSpaceRootInitializationError> {
        if self.initialized {
            return Err(AddressSpaceRootInitializationError::AlreadyInitialized);
        }

        let editor_bits = editor.physical_address_bits();
        if editor_bits != self.physical_address_bits {
            return Err(
                AddressSpaceRootInitializationError::PhysicalAddressWidthMismatch {
                    root_bits: self.physical_address_bits,
                    editor_bits,
                },
            );
        }

        initialize_root_entries(
            self.physical_address(),
            self.physical_address_bits,
            kernel_root_physical,
            kernel_recursive_index,
            root_recursive_index,
            editor,
        )?;
        // initialize_root_entries rejects any destination index outside the
        // 512-entry PML4 and constrains it to the upper half.
        self.recursive_index = Some(root_recursive_index as u16);
        self.initialized = true;
        Ok(())
    }

    /// Consumes an inactive root and returns its allocator ownership token.
    ///
    /// This operation transfers the token only; it does not clear page tables,
    /// detach mappings, or invalidate translations. A root returned by the
    /// kernel's CR3 activation path is represented by `ActiveAddressSpaceRoot`,
    /// which intentionally exposes no release API.
    ///
    /// # Safety
    ///
    /// The caller must ensure this root is not active or reachable by any CPU,
    /// and must not return the frame to its allocator or reuse its physical
    /// address until all root-private mappings and child page tables have been
    /// detached/reclaimed and the required TLB invalidation has completed. If
    /// cleanup or CPU state is uncertain, use `leak_frame()` rather than extracting
    /// the token, so the allocator can never reuse this physical frame.
    ///
    /// ```compile_fail
    /// use oneos_core::AddressSpaceRoot;
    ///
    /// fn extract_without_safety_contract(root: AddressSpaceRoot) {
    ///     let _frame = root.into_frame();
    /// }
    /// ```
    #[allow(unsafe_code)]
    pub unsafe fn into_frame(self) -> Frame {
        self.frame
    }

    /// Intentionally abandons this root's allocator token without releasing its frame.
    ///
    /// Unlike `into_frame`, this operation does not require the caller to prove that
    /// the root is inactive. It is appropriate when CR3 activation, CPU state, or
    /// cleanup is uncertain and recycling the physical frame could corrupt a live
    /// page table. The allocator's allocation record is deliberately left intact.
    pub fn leak_frame(self) {
        let _intentionally_leaked_root = core::mem::ManuallyDrop::new(self);
    }
}

/// A root that the kernel has activated in CR3.
///
/// Unlike `AddressSpaceRoot`, this type does not expose the root frame token.
/// Demotion back to `AddressSpaceRoot` is available only through an unsafe
/// architecture-layer transition that has already switched CR3 away and
/// completed the required TLB invalidation. Dropping this handle still leaks
/// the frame token by design; it never returns active memory to the allocator.
///
/// This wrapper records a kernel-established state transition. It is not a
/// substitute for synchronizing a CR3 switch with other CPUs; the initial
/// implementation remains single-CPU.
///
/// The active handle deliberately has no `into_frame` method and cannot be
/// constructed through a safe call:
///
/// ```compile_fail
/// use oneos_core::{ActiveAddressSpaceRoot, AddressSpaceRoot};
///
/// fn fabricate_active_root(root: AddressSpaceRoot) {
///     let _active = ActiveAddressSpaceRoot::from_activated(root, 511);
/// }
/// ```
///
/// ```compile_fail
/// use oneos_core::ActiveAddressSpaceRoot;
///
/// fn release_active_root(root: ActiveAddressSpaceRoot) {
///     let _frame = root.into_frame();
/// }
/// ```
#[must_use = "keep the active address-space root alive for its active lifetime"]
#[derive(Debug)]
pub struct ActiveAddressSpaceRoot {
    root: AddressSpaceRoot,
    recursive_index: u16,
}

/// Failure when an active root is being transitioned back to an inactive root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressSpaceRootDeactivationError {
    /// The observed CR3 root still names the root being demoted.
    RootStillActive,
    /// The observed CR3 root is invalid for the root's physical-address width.
    InvalidObservedRoot,
    /// The active handle's recursive index does not match the initialized root.
    RecursiveIndexMismatch,
}

impl ActiveAddressSpaceRoot {
    /// Records an already-activated root and its private recursive PML4 index.
    ///
    /// Calling this does not switch CR3 or verify hardware state. The constructor
    /// is unsafe so ordinary safe code cannot forge the active state.
    ///
    /// # Safety
    ///
    /// The root must have completed initialization, and its recorded recursive
    /// index must equal `recursive_index`. The caller must have switched CR3 to
    /// `root.physical_address()`, verified the resulting CR3 value, and verified
    /// that the index is the supervisor-writable self-reference in that active
    /// root. The caller must also preserve the address-space lifetime and
    /// synchronization contract.
    #[allow(unsafe_code)]
    pub unsafe fn from_activated(root: AddressSpaceRoot, recursive_index: u16) -> Self {
        Self {
            root,
            recursive_index,
        }
    }

    /// Returns the active root's physical base address without exposing its token.
    pub const fn physical_address(&self) -> u64 {
        self.root.physical_address()
    }

    /// Returns the recursive PML4 index associated with the active root.
    pub const fn recursive_index(&self) -> u16 {
        self.recursive_index
    }

    /// Returns the physical-address width used to validate this root.
    pub const fn physical_address_bits(&self) -> u8 {
        self.root.physical_address_bits()
    }

    /// Returns an active root to the inactive state after an architecture-layer switch.
    ///
    /// This only transitions ownership of the root handle. It does not remove
    /// child mappings, reclaim lower-level page tables, or free the root frame.
    ///
    /// # Safety
    ///
    /// The caller must have completed a real address-space switch away from this
    /// root, read and validate the resulting CR3 root physical address, and
    /// completed every required local/global TLB invalidation before calling
    /// this method. No CPU may still use the old root or stale translations, and
    /// the root must not be reactivated while the returned inactive handle exists.
    /// The supplied address must be the physical root extracted from that actual
    /// CR3 readback, with unsupported PCID state already rejected. The caller is
    /// responsible for detaching/reclaiming child tables before returning the
    /// root frame to the allocator.
    ///
    /// On validation failure, the original active handle is returned intact.
    #[allow(unsafe_code)]
    pub unsafe fn into_inactive_after_switch(
        self,
        observed_cr3_root_physical: u64,
    ) -> Result<AddressSpaceRoot, (Self, AddressSpaceRootDeactivationError)> {
        if self.root.recursive_index != Some(self.recursive_index) {
            return Err((
                self,
                AddressSpaceRootDeactivationError::RecursiveIndexMismatch,
            ));
        }
        if let Err(error) = validate_deactivation_root(
            self.root.physical_address(),
            self.root.physical_address_bits(),
            observed_cr3_root_physical,
        ) {
            return Err((self, error));
        }

        Ok(self.root)
    }
}

const LOWER_HALF_PML4_ENTRIES: usize = 256;
const PML4_ENTRIES: usize = 512;
const PRESENT: u64 = 1;
const WRITABLE: u64 = 1 << 1;
const USER_ACCESSIBLE: u64 = 1 << 2;
const LARGE_PAGE: u64 = 1 << 7;
const NO_EXECUTE: u64 = 1 << 63;
const PHYSICAL_ADDRESS_FIELD_MASK: u64 = 0x000f_ffff_ffff_f000;
const PROTECTION_KEY_FIELD_MASK: u64 = 0x7800_0000_0000_0000;

/// Errors encountered while preparing an inactive address-space root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressSpaceRootInitializationError {
    /// The root has already been initialized.
    AlreadyInitialized,
    /// The editor and root were validated against different CPU address widths.
    PhysicalAddressWidthMismatch {
        /// Width recorded by the root handle.
        root_bits: u8,
        /// Width reported by the table editor.
        editor_bits: u8,
    },
    /// The supplied kernel-root frame is invalid for the selected address width.
    InvalidKernelRootFrame(AddressSpaceRootError),
    /// The active kernel recursive PML4 index is outside the four-level table.
    InvalidKernelRecursiveIndex {
        /// Supplied source PML4 index from BootInfo.
        index: usize,
    },
    /// The new root's recursive PML4 slot must be in the upper half.
    InvalidRecursiveIndex {
        /// Supplied destination PML4 index.
        index: usize,
    },
    /// The chosen destination recursive slot is already used by the kernel root.
    RecursiveDestinationSlotOccupied {
        /// Upper-half PML4 index that cannot be reserved for the new root.
        index: usize,
    },
    /// The destination root aliases the source kernel root.
    RootAliasesKernelRoot,
    /// The destination root cannot be accessed safely for writing.
    RootTableUnavailable,
    /// The source kernel root cannot be accessed safely.
    KernelRootTableUnavailable,
    /// The source recursive entry could not be read.
    KernelRootRecursiveEntryUnavailable,
    /// The source recursive entry is not a supervisor-writable self-reference.
    InvalidKernelRootRecursiveEntry,
    /// A source PML4 entry could not be read.
    KernelEntryUnavailable {
        /// PML4 index that could not be read.
        index: usize,
    },
    /// A source PML4 entry is malformed or points outside physical-address limits.
    MalformedKernelEntry {
        /// PML4 index containing the malformed entry.
        index: usize,
    },
    /// A present kernel-half entry permits user mode at the PML4 level.
    UserAccessibleKernelEntry {
        /// PML4 index that has its user-accessible bit set.
        index: usize,
    },
    /// A non-recursive kernel entry aliases the kernel PML4 frame.
    KernelEntryAliasesKernelRoot {
        /// PML4 index containing the alias.
        index: usize,
    },
    /// A kernel entry aliases the newly owned destination root.
    KernelEntryAliasesOwnedRoot {
        /// PML4 index containing the alias.
        index: usize,
    },
}

/// Access interface for preparing an inactive address-space root.
///
/// Implementations must verify access to the entire physical frame. Once
/// table_is_read_write_accessible returns true for the destination, write_entry
/// must be infallible for that frame and every valid PML4 index. This contract
/// lets the initializer finish all fallible checks before its first write.
pub trait AddressSpaceRootEditor {
    /// Returns the active CPU's physical-address width (MAXPHYADDR).
    fn physical_address_bits(&self) -> u8;

    /// Returns true only when the complete table frame is safely readable.
    fn table_is_readable(&mut self, table_physical: u64) -> bool;

    /// Returns true only when the complete table frame is safely readable and writable.
    fn table_is_read_write_accessible(&mut self, table_physical: u64) -> bool;

    /// Reads one entry from a four-level paging table.
    fn read_entry(&mut self, table_physical: u64, index: usize, level: u8) -> Option<u64>;

    /// Writes one entry to a table already validated as read/write accessible.
    fn write_entry(&mut self, table_physical: u64, index: usize, level: u8, value: u64);
}

fn initialize_root_entries<E: AddressSpaceRootEditor>(
    root_physical: u64,
    physical_address_bits: u8,
    kernel_root_physical: u64,
    kernel_recursive_index: usize,
    root_recursive_index: usize,
    editor: &mut E,
) -> Result<(), AddressSpaceRootInitializationError> {
    validate_root_frame_address(kernel_root_physical, physical_address_bits)
        .map_err(AddressSpaceRootInitializationError::InvalidKernelRootFrame)?;

    if root_physical == kernel_root_physical {
        return Err(AddressSpaceRootInitializationError::RootAliasesKernelRoot);
    }
    if kernel_recursive_index >= PML4_ENTRIES {
        return Err(
            AddressSpaceRootInitializationError::InvalidKernelRecursiveIndex {
                index: kernel_recursive_index,
            },
        );
    }
    if !(LOWER_HALF_PML4_ENTRIES..PML4_ENTRIES).contains(&root_recursive_index) {
        return Err(AddressSpaceRootInitializationError::InvalidRecursiveIndex {
            index: root_recursive_index,
        });
    }
    if !editor.table_is_read_write_accessible(root_physical) {
        return Err(AddressSpaceRootInitializationError::RootTableUnavailable);
    }
    if !editor.table_is_readable(kernel_root_physical) {
        return Err(AddressSpaceRootInitializationError::KernelRootTableUnavailable);
    }

    let recursive_entry = editor
        .read_entry(kernel_root_physical, kernel_recursive_index, 4)
        .ok_or(AddressSpaceRootInitializationError::KernelRootRecursiveEntryUnavailable)?;
    if recursive_entry & PRESENT == 0
        || recursive_entry & WRITABLE == 0
        || recursive_entry & USER_ACCESSIBLE != 0
        || recursive_entry & LARGE_PAGE != 0
        || recursive_entry & PROTECTION_KEY_FIELD_MASK != 0
        || recursive_entry & PHYSICAL_ADDRESS_FIELD_MASK != kernel_root_physical
    {
        return Err(AddressSpaceRootInitializationError::InvalidKernelRootRecursiveEntry);
    }

    let physical_limit = 1u64 << physical_address_bits;
    let mut upper_entries = [0u64; PML4_ENTRIES - LOWER_HALF_PML4_ENTRIES];

    // Preflight every source entry before changing the destination root. The
    // source recursive slot is never copied: the new root uses its own slot.
    for index in LOWER_HALF_PML4_ENTRIES..PML4_ENTRIES {
        if index == root_recursive_index {
            let entry = editor
                .read_entry(kernel_root_physical, index, 4)
                .ok_or(AddressSpaceRootInitializationError::KernelEntryUnavailable { index })?;
            if entry != 0 {
                return Err(
                    AddressSpaceRootInitializationError::RecursiveDestinationSlotOccupied { index },
                );
            }
            upper_entries[index - LOWER_HALF_PML4_ENTRIES] =
                root_physical | PRESENT | WRITABLE | NO_EXECUTE;
            continue;
        }
        if index == kernel_recursive_index {
            upper_entries[index - LOWER_HALF_PML4_ENTRIES] = 0;
            continue;
        }

        let entry = editor
            .read_entry(kernel_root_physical, index, 4)
            .ok_or(AddressSpaceRootInitializationError::KernelEntryUnavailable { index })?;
        validate_kernel_entry(
            entry,
            index,
            physical_limit,
            root_physical,
            kernel_root_physical,
        )?;
        upper_entries[index - LOWER_HALF_PML4_ENTRIES] = entry;
    }

    // No operation below this point can fail by the editor contract. The root
    // is not yet active, so readers cannot observe a partially initialized tree.
    for index in 0..LOWER_HALF_PML4_ENTRIES {
        editor.write_entry(root_physical, index, 4, 0);
    }
    for index in LOWER_HALF_PML4_ENTRIES..PML4_ENTRIES {
        let entry = upper_entries[index - LOWER_HALF_PML4_ENTRIES];
        editor.write_entry(root_physical, index, 4, entry);
    }
    Ok(())
}

fn validate_kernel_entry(
    entry: u64,
    index: usize,
    physical_limit: u64,
    root_physical: u64,
    kernel_root_physical: u64,
) -> Result<(), AddressSpaceRootInitializationError> {
    if entry & PRESENT == 0 {
        return if entry == 0 {
            Ok(())
        } else {
            Err(AddressSpaceRootInitializationError::MalformedKernelEntry { index })
        };
    }
    if entry & USER_ACCESSIBLE != 0 {
        return Err(AddressSpaceRootInitializationError::UserAccessibleKernelEntry { index });
    }
    if entry & LARGE_PAGE != 0 || entry & PROTECTION_KEY_FIELD_MASK != 0 {
        return Err(AddressSpaceRootInitializationError::MalformedKernelEntry { index });
    }

    let table_physical = entry & PHYSICAL_ADDRESS_FIELD_MASK;
    if table_physical == 0 || table_physical >= physical_limit {
        return Err(AddressSpaceRootInitializationError::MalformedKernelEntry { index });
    }
    if table_physical == kernel_root_physical {
        return Err(AddressSpaceRootInitializationError::KernelEntryAliasesKernelRoot { index });
    }
    if table_physical == root_physical {
        return Err(AddressSpaceRootInitializationError::KernelEntryAliasesOwnedRoot { index });
    }
    Ok(())
}

/// Checks whether a byte range is wholly inside the x86_64 four-level user half.
///
fn validate_deactivation_root(
    root_physical_address: u64,
    physical_address_bits: u8,
    observed_cr3_root_physical: u64,
) -> Result<(), AddressSpaceRootDeactivationError> {
    if validate_root_frame_address(observed_cr3_root_physical, physical_address_bits).is_err() {
        return Err(AddressSpaceRootDeactivationError::InvalidObservedRoot);
    }
    if observed_cr3_root_physical == root_physical_address {
        return Err(AddressSpaceRootDeactivationError::RootStillActive);
    }
    Ok(())
}

/// This function validates arithmetic and the user/kernel canonical-half
/// boundary only. It does not check mappings, page permissions, frame
/// ownership, guard regions, or whether address zero is intentionally unmapped.
pub fn validate_user_virtual_range(start: u64, length: u64) -> Result<(), UserVirtualRangeError> {
    if length == 0 {
        return Err(UserVirtualRangeError::EmptyRange);
    }

    let end = start
        .checked_add(length)
        .ok_or(UserVirtualRangeError::RangeOverflow)?;
    if start >= USER_VIRTUAL_ADDRESS_LIMIT || end > USER_VIRTUAL_ADDRESS_LIMIT {
        return Err(UserVirtualRangeError::OutsideUserHalf);
    }

    Ok(())
}

fn validate_root_frame_address(
    address: u64,
    physical_address_bits: u8,
) -> Result<(), AddressSpaceRootError> {
    if !(32..=52).contains(&physical_address_bits) {
        return Err(AddressSpaceRootError::InvalidPhysicalAddressWidth {
            bits: physical_address_bits,
        });
    }
    if address == 0 {
        return Err(AddressSpaceRootError::ZeroRootFrame);
    }
    if address & (PAGE_SIZE - 1) != 0 {
        return Err(AddressSpaceRootError::UnalignedRootFrame);
    }

    let physical_limit = 1u64 << physical_address_bits;
    let end = address
        .checked_add(PAGE_SIZE)
        .ok_or(AddressSpaceRootError::RootFrameOutOfRange)?;
    if end > physical_limit {
        return Err(AddressSpaceRootError::RootFrameOutOfRange);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        validate_deactivation_root, validate_root_frame_address, validate_user_virtual_range,
        ActiveAddressSpaceRoot, AddressSpaceRoot, AddressSpaceRootDeactivationError,
        AddressSpaceRootEditor, AddressSpaceRootError, AddressSpaceRootInitializationError,
        UserVirtualRangeError, LOWER_HALF_PML4_ENTRIES, NO_EXECUTE, PRESENT, USER_ACCESSIBLE,
        USER_VIRTUAL_ADDRESS_LIMIT, WRITABLE,
    };
    use crate::{Frame, FrameAllocator, FrameAllocatorError, FrameSegment, PAGE_SIZE};

    fn make_allocator<'a>(
        regions: &[(u64, u64, bool)],
        slots: &'a mut [FrameSegment],
        bitmap: &'a mut [u64],
    ) -> Result<FrameAllocator<'a>, FrameAllocatorError> {
        FrameAllocator::initialize(regions.len(), |index| regions[index], slots, bitmap)
    }

    // This helper is restricted to host-side tests: TestEditor stores page-table
    // entries in ordinary test memory, and these tests never load a test root into
    // hardware CR3. No CPU or hardware TLB can retain a reference to these roots.
    #[allow(unsafe_code)]
    fn take_test_root_frame(root: AddressSpaceRoot) -> Frame {
        // SAFETY: unit tests use only the in-memory TestEditor model and never
        // activate these roots on hardware.
        unsafe { root.into_frame() }
    }

    #[test]
    fn leaking_root_keeps_its_frame_reserved_from_allocator_reuse() {
        let regions = [(0x1000, 0x9000, true)];
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let mut allocator = make_allocator(&regions, &mut slots, &mut bitmap).unwrap();
        let frame = allocator.allocate_frame().unwrap();
        let leaked_physical = frame.physical_address();
        let root = AddressSpaceRoot::try_from_frame(frame, 32).unwrap();

        root.leak_frame();

        assert_eq!(allocator.stats().allocated_frames, 1);
        let probe = allocator.allocate_frame().unwrap();
        assert_ne!(probe.physical_address(), leaked_physical);
        allocator.free_frame(probe).unwrap();
        assert_eq!(allocator.stats().allocated_frames, 1);
    }

    #[test]
    fn deactivation_requires_a_valid_different_cr3_root() {
        assert_eq!(
            validate_deactivation_root(0x3000, 32, 0x3000),
            Err(AddressSpaceRootDeactivationError::RootStillActive)
        );
        assert_eq!(validate_deactivation_root(0x3000, 32, 0x5000), Ok(()));
        assert_eq!(
            validate_deactivation_root(0x3000, 32, 0),
            Err(AddressSpaceRootDeactivationError::InvalidObservedRoot)
        );
        assert_eq!(
            validate_deactivation_root(0x3000, 32, 0x1_0000_0000),
            Err(AddressSpaceRootDeactivationError::InvalidObservedRoot)
        );
    }

    #[test]
    fn accepts_owned_root_and_returns_its_token_exactly_once() {
        let regions = [(0x1000, 0x5000, true)];
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let mut allocator = make_allocator(&regions, &mut slots, &mut bitmap).unwrap();
        let frame = allocator.allocate_frame().unwrap();
        let address = frame.physical_address();

        let root = AddressSpaceRoot::try_from_frame(frame, 32).unwrap();
        assert_eq!(root.physical_address(), address);
        assert_eq!(root.physical_address_bits(), 32);
        assert_eq!(allocator.stats().allocated_frames, 1);

        let frame = take_test_root_frame(root);
        assert_eq!(frame.physical_address(), address);
        allocator.free_frame(frame).unwrap();
        assert_eq!(allocator.stats().allocated_frames, 0);
    }

    #[test]
    fn invalid_physical_width_returns_frame_ownership_to_caller() {
        let regions = [(0x1000, 0x3000, true)];
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let mut allocator = make_allocator(&regions, &mut slots, &mut bitmap).unwrap();
        let frame = allocator.allocate_frame().unwrap();

        let (error, frame) = AddressSpaceRoot::try_from_frame(frame, 31).unwrap_err();
        assert_eq!(
            error,
            AddressSpaceRootError::InvalidPhysicalAddressWidth { bits: 31 }
        );
        allocator.free_frame(frame).unwrap();
    }

    #[test]
    fn root_outside_reported_physical_width_is_rejected_without_losing_frame() {
        let regions = [(0x1_0000_0000, 0x1_0000_3000, true)];
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let mut allocator = make_allocator(&regions, &mut slots, &mut bitmap).unwrap();
        let frame = allocator.allocate_frame().unwrap();

        let (error, frame) = AddressSpaceRoot::try_from_frame(frame, 32).unwrap_err();
        assert_eq!(error, AddressSpaceRootError::RootFrameOutOfRange);
        allocator.free_frame(frame).unwrap();
    }

    #[test]
    fn root_frame_shape_validation_rejects_zero_unaligned_and_out_of_range() {
        assert_eq!(
            validate_root_frame_address(0, 48),
            Err(AddressSpaceRootError::ZeroRootFrame)
        );
        assert_eq!(
            validate_root_frame_address(0x1001, 48),
            Err(AddressSpaceRootError::UnalignedRootFrame)
        );
        assert_eq!(validate_root_frame_address(0xffff_f000, 32), Ok(()));
        assert_eq!(
            validate_root_frame_address(0x1_0000_0000, 32),
            Err(AddressSpaceRootError::RootFrameOutOfRange)
        );
        assert_eq!(
            validate_root_frame_address(0x1000, 53),
            Err(AddressSpaceRootError::InvalidPhysicalAddressWidth { bits: 53 })
        );
    }

    #[test]
    fn accepts_user_ranges_inside_the_lower_canonical_half() {
        assert_eq!(validate_user_virtual_range(0x1000, 1), Ok(()));
        assert_eq!(validate_user_virtual_range(0, PAGE_SIZE), Ok(()));
        assert_eq!(
            validate_user_virtual_range(USER_VIRTUAL_ADDRESS_LIMIT - 1, 1),
            Ok(())
        );
        assert_eq!(
            validate_user_virtual_range(USER_VIRTUAL_ADDRESS_LIMIT - PAGE_SIZE, PAGE_SIZE),
            Ok(())
        );
    }

    #[test]
    fn rejects_empty_and_overflowing_user_ranges() {
        assert_eq!(
            validate_user_virtual_range(0x1000, 0),
            Err(UserVirtualRangeError::EmptyRange)
        );
        assert_eq!(
            validate_user_virtual_range(0x1000, u64::MAX),
            Err(UserVirtualRangeError::RangeOverflow)
        );
    }

    #[test]
    fn rejects_upper_half_and_cross_boundary_user_ranges() {
        assert_eq!(
            validate_user_virtual_range(USER_VIRTUAL_ADDRESS_LIMIT, 1),
            Err(UserVirtualRangeError::OutsideUserHalf)
        );
        assert_eq!(
            validate_user_virtual_range(0xffff_8000_0000_0000, 1),
            Err(UserVirtualRangeError::OutsideUserHalf)
        );
        assert_eq!(
            validate_user_virtual_range(USER_VIRTUAL_ADDRESS_LIMIT - 4, 8),
            Err(UserVirtualRangeError::OutsideUserHalf)
        );
    }

    #[derive(Clone, Copy)]
    struct TestTable {
        physical_address: u64,
        entries: [u64; 512],
    }

    struct TestRootEditor {
        tables: [TestTable; 2],
        blocked_table: Option<u64>,
        unreadable_entry: Option<(u64, usize)>,
        physical_address_bits: u8,
    }

    impl TestRootEditor {
        fn new(root: u64, kernel_root: u64) -> Self {
            Self {
                tables: [
                    TestTable {
                        physical_address: root,
                        entries: [0xdead_beef; 512],
                    },
                    TestTable {
                        physical_address: kernel_root,
                        entries: [0; 512],
                    },
                ],
                blocked_table: None,
                unreadable_entry: None,
                physical_address_bits: 32,
            }
        }

        fn set_entry(&mut self, table: u64, index: usize, value: u64) {
            let table = self
                .tables
                .iter_mut()
                .find(|candidate| candidate.physical_address == table)
                .unwrap();
            table.entries[index] = value;
        }

        fn entry(&self, table: u64, index: usize) -> u64 {
            self.tables
                .iter()
                .find(|candidate| candidate.physical_address == table)
                .unwrap()
                .entries[index]
        }
    }

    impl AddressSpaceRootEditor for TestRootEditor {
        fn physical_address_bits(&self) -> u8 {
            self.physical_address_bits
        }

        fn table_is_readable(&mut self, table_physical: u64) -> bool {
            self.blocked_table != Some(table_physical)
                && self
                    .tables
                    .iter()
                    .any(|table| table.physical_address == table_physical)
        }

        fn table_is_read_write_accessible(&mut self, table_physical: u64) -> bool {
            self.table_is_readable(table_physical)
        }

        fn read_entry(&mut self, table_physical: u64, index: usize, _level: u8) -> Option<u64> {
            if self.unreadable_entry == Some((table_physical, index)) {
                return None;
            }
            self.tables
                .iter()
                .find(|table| table.physical_address == table_physical)
                .and_then(|table| table.entries.get(index).copied())
        }

        fn write_entry(&mut self, table_physical: u64, index: usize, _level: u8, value: u64) {
            let table = self
                .tables
                .iter_mut()
                .find(|table| table.physical_address == table_physical)
                .expect("writes are only allowed to a preflighted table");
            table.entries[index] = value;
        }
    }

    fn initialize_test_roots(allocator: &mut FrameAllocator<'_>) -> (AddressSpaceRoot, u64, Frame) {
        let root_frame = allocator.allocate_frame().unwrap();
        let kernel_frame = allocator.allocate_frame().unwrap();
        let kernel_address = kernel_frame.physical_address();
        let root = AddressSpaceRoot::try_from_frame(root_frame, 32).unwrap();
        (root, kernel_address, kernel_frame)
    }

    fn initialized_test_root(allocator: &mut FrameAllocator<'_>) -> (AddressSpaceRoot, Frame) {
        let (mut root, kernel_address, kernel_frame) = initialize_test_roots(allocator);
        let root_address = root.physical_address();
        let mut editor = TestRootEditor::new(root_address, kernel_address);
        editor.set_entry(kernel_address, 511, kernel_address | PRESENT | WRITABLE);
        root.initialize_from_kernel_root(kernel_address, 511, 510, &mut editor)
            .unwrap();
        (root, kernel_frame)
    }

    // These host tests exercise the ownership API's defensive result paths only.
    // They do not execute privileged instructions or claim to verify a hardware CR3 switch.
    #[allow(unsafe_code)]
    #[test]
    fn into_inactive_after_switch_rejects_same_root_and_preserves_active_handle() {
        let regions = [(0x1000, 0x9000, true)];
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let mut allocator = make_allocator(&regions, &mut slots, &mut bitmap).unwrap();
        let (root, kernel_frame) = initialized_test_root(&mut allocator);
        let root_address = root.physical_address();
        let active = unsafe { ActiveAddressSpaceRoot::from_activated(root, 510) };

        let (active, error) =
            unsafe { active.into_inactive_after_switch(root_address) }.unwrap_err();

        assert_eq!(error, AddressSpaceRootDeactivationError::RootStillActive);
        assert_eq!(active.physical_address(), root_address);
        assert_eq!(active.recursive_index(), 510);
        assert_eq!(allocator.stats().allocated_frames, 2);

        let ActiveAddressSpaceRoot { root, .. } = active;
        allocator.free_frame(take_test_root_frame(root)).unwrap();
        allocator.free_frame(kernel_frame).unwrap();
        assert_eq!(allocator.stats().allocated_frames, 0);
    }

    // Construct an inconsistent internal handle to exercise the API's mismatch guard.
    // Such a handle cannot be created through a valid production activation path.
    #[allow(unsafe_code)]
    #[test]
    fn into_inactive_after_switch_rejects_recursive_index_mismatch_and_preserves_handle() {
        let regions = [(0x1000, 0x9000, true)];
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let mut allocator = make_allocator(&regions, &mut slots, &mut bitmap).unwrap();
        let (root, kernel_frame) = initialized_test_root(&mut allocator);
        let root_address = root.physical_address();
        let active = ActiveAddressSpaceRoot {
            root,
            recursive_index: 509,
        };

        let (active, error) = unsafe { active.into_inactive_after_switch(0x7000) }.unwrap_err();

        assert_eq!(
            error,
            AddressSpaceRootDeactivationError::RecursiveIndexMismatch
        );
        assert_eq!(active.physical_address(), root_address);
        assert_eq!(active.recursive_index(), 509);
        assert_eq!(active.root.recursive_index(), Some(510));
        assert_eq!(allocator.stats().allocated_frames, 2);

        let ActiveAddressSpaceRoot { root, .. } = active;
        allocator.free_frame(take_test_root_frame(root)).unwrap();
        allocator.free_frame(kernel_frame).unwrap();
        assert_eq!(allocator.stats().allocated_frames, 0);
    }

    #[allow(unsafe_code)]
    #[test]
    fn into_inactive_after_switch_returns_original_root_on_success() {
        let regions = [(0x1000, 0x9000, true)];
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let mut allocator = make_allocator(&regions, &mut slots, &mut bitmap).unwrap();
        let (root, kernel_frame) = initialized_test_root(&mut allocator);
        let root_address = root.physical_address();
        let active = unsafe { ActiveAddressSpaceRoot::from_activated(root, 510) };

        let inactive = unsafe { active.into_inactive_after_switch(0x7000) }.unwrap();

        assert_eq!(inactive.physical_address(), root_address);
        assert_eq!(inactive.recursive_index(), Some(510));
        assert!(inactive.is_initialized());
        assert_eq!(allocator.stats().allocated_frames, 2);

        allocator
            .free_frame(take_test_root_frame(inactive))
            .unwrap();
        allocator.free_frame(kernel_frame).unwrap();
        assert_eq!(allocator.stats().allocated_frames, 0);
    }

    #[test]
    fn initializes_inactive_root_with_supervisor_kernel_half_and_private_recursive_slot() {
        let regions = [(0x1000, 0x9000, true)];
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let mut allocator = make_allocator(&regions, &mut slots, &mut bitmap).unwrap();
        let (mut root, kernel_address, kernel_frame) = initialize_test_roots(&mut allocator);
        let root_address = root.physical_address();
        assert_eq!(root.recursive_index(), None);
        let mut editor = TestRootEditor::new(root_address, kernel_address);
        editor.set_entry(kernel_address, 2, kernel_address | PRESENT | WRITABLE);
        editor.set_entry(kernel_address, 256, 0x3000 | PRESENT | WRITABLE);
        editor.set_entry(
            kernel_address,
            300,
            0x4000 | PRESENT | WRITABLE | NO_EXECUTE,
        );

        root.initialize_from_kernel_root(kernel_address, 2, 510, &mut editor)
            .unwrap();

        assert!(root.is_initialized());
        assert_eq!(root.recursive_index(), Some(510));
        for index in 0..LOWER_HALF_PML4_ENTRIES {
            assert_eq!(editor.entry(root_address, index), 0);
        }
        assert_eq!(editor.entry(root_address, 2), 0);
        assert_eq!(editor.entry(root_address, 256), 0x3000 | PRESENT | WRITABLE);
        assert_eq!(
            editor.entry(root_address, 300),
            0x4000 | PRESENT | WRITABLE | NO_EXECUTE
        );
        assert_eq!(
            editor.entry(root_address, 510),
            root_address | PRESENT | WRITABLE | NO_EXECUTE
        );

        allocator.free_frame(take_test_root_frame(root)).unwrap();
        allocator.free_frame(kernel_frame).unwrap();
    }

    #[test]
    fn accepts_lower_half_kernel_recursive_slot_and_uses_private_upper_slot() {
        let regions = [(0x1000, 0x9000, true)];
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let mut allocator = make_allocator(&regions, &mut slots, &mut bitmap).unwrap();
        let (mut root, kernel_address, kernel_frame) = initialize_test_roots(&mut allocator);
        let root_address = root.physical_address();
        let mut editor = TestRootEditor::new(root_address, kernel_address);
        editor.set_entry(kernel_address, 2, kernel_address | PRESENT | WRITABLE);
        editor.set_entry(kernel_address, 256, 0x3000 | PRESENT | WRITABLE);

        root.initialize_from_kernel_root(kernel_address, 2, 511, &mut editor)
            .unwrap();

        assert_eq!(editor.entry(root_address, 2), 0);
        assert_eq!(
            editor.entry(root_address, 511),
            root_address | PRESENT | WRITABLE | NO_EXECUTE
        );
        assert_eq!(editor.entry(root_address, 256), 0x3000 | PRESENT | WRITABLE);

        allocator.free_frame(take_test_root_frame(root)).unwrap();
        allocator.free_frame(kernel_frame).unwrap();
    }

    #[test]
    fn refuses_to_replace_an_occupied_destination_recursive_slot() {
        let regions = [(0x1000, 0x9000, true)];
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let mut allocator = make_allocator(&regions, &mut slots, &mut bitmap).unwrap();
        let (mut root, kernel_address, kernel_frame) = initialize_test_roots(&mut allocator);
        let root_address = root.physical_address();
        let mut editor = TestRootEditor::new(root_address, kernel_address);
        editor.set_entry(kernel_address, 2, kernel_address | PRESENT | WRITABLE);
        editor.set_entry(kernel_address, 511, 0x6000 | PRESENT | WRITABLE);
        let before = editor.tables[0].entries;

        assert_eq!(
            root.initialize_from_kernel_root(kernel_address, 2, 511, &mut editor),
            Err(
                AddressSpaceRootInitializationError::RecursiveDestinationSlotOccupied {
                    index: 511
                }
            )
        );
        assert_eq!(editor.tables[0].entries, before);
        assert!(!root.is_initialized());

        allocator.free_frame(take_test_root_frame(root)).unwrap();
        allocator.free_frame(kernel_frame).unwrap();
    }

    #[test]
    fn rejects_out_of_range_kernel_recursive_index_without_mutating_destination() {
        let regions = [(0x1000, 0x9000, true)];
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let mut allocator = make_allocator(&regions, &mut slots, &mut bitmap).unwrap();
        let (mut root, kernel_address, kernel_frame) = initialize_test_roots(&mut allocator);
        let root_address = root.physical_address();
        let mut editor = TestRootEditor::new(root_address, kernel_address);
        let before = editor.tables[0].entries;

        assert_eq!(
            root.initialize_from_kernel_root(kernel_address, 512, 510, &mut editor),
            Err(AddressSpaceRootInitializationError::InvalidKernelRecursiveIndex { index: 512 })
        );
        assert_eq!(editor.tables[0].entries, before);
        assert!(!root.is_initialized());

        allocator.free_frame(take_test_root_frame(root)).unwrap();
        allocator.free_frame(kernel_frame).unwrap();
    }

    #[test]
    fn rejects_user_accessible_kernel_entry_without_mutating_destination_root() {
        let regions = [(0x1000, 0x9000, true)];
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let mut allocator = make_allocator(&regions, &mut slots, &mut bitmap).unwrap();
        let (mut root, kernel_address, kernel_frame) = initialize_test_roots(&mut allocator);
        let root_address = root.physical_address();
        let mut editor = TestRootEditor::new(root_address, kernel_address);
        editor.set_entry(kernel_address, 511, kernel_address | PRESENT | WRITABLE);
        editor.set_entry(kernel_address, 300, 0x4000 | PRESENT | USER_ACCESSIBLE);

        assert_eq!(
            root.initialize_from_kernel_root(kernel_address, 511, 510, &mut editor),
            Err(AddressSpaceRootInitializationError::UserAccessibleKernelEntry { index: 300 })
        );
        assert!(!root.is_initialized());
        assert_eq!(editor.entry(root_address, 0), 0xdead_beef);
        assert_eq!(editor.entry(root_address, 511), 0xdead_beef);

        allocator.free_frame(take_test_root_frame(root)).unwrap();
        allocator.free_frame(kernel_frame).unwrap();
    }

    #[test]
    fn rejects_recursive_slot_in_user_half_before_writing_root() {
        let regions = [(0x1000, 0x9000, true)];
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let mut allocator = make_allocator(&regions, &mut slots, &mut bitmap).unwrap();
        let (mut root, kernel_address, kernel_frame) = initialize_test_roots(&mut allocator);
        let root_address = root.physical_address();
        let mut editor = TestRootEditor::new(root_address, kernel_address);

        assert_eq!(
            root.initialize_from_kernel_root(kernel_address, 511, 255, &mut editor),
            Err(AddressSpaceRootInitializationError::InvalidRecursiveIndex { index: 255 })
        );
        assert_eq!(editor.entry(root_address, 0), 0xdead_beef);
        assert!(!root.is_initialized());

        allocator.free_frame(take_test_root_frame(root)).unwrap();
        allocator.free_frame(kernel_frame).unwrap();
    }

    #[test]
    fn does_not_allow_root_initialization_twice() {
        let regions = [(0x1000, 0x9000, true)];
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let mut allocator = make_allocator(&regions, &mut slots, &mut bitmap).unwrap();
        let (mut root, kernel_address, kernel_frame) = initialize_test_roots(&mut allocator);
        let root_address = root.physical_address();
        let mut editor = TestRootEditor::new(root_address, kernel_address);
        editor.set_entry(kernel_address, 511, kernel_address | PRESENT | WRITABLE);

        root.initialize_from_kernel_root(kernel_address, 511, 510, &mut editor)
            .unwrap();
        let before = editor.entry(root_address, 511);
        assert_eq!(
            root.initialize_from_kernel_root(kernel_address, 511, 510, &mut editor),
            Err(AddressSpaceRootInitializationError::AlreadyInitialized)
        );
        assert_eq!(editor.entry(root_address, 511), before);

        allocator.free_frame(take_test_root_frame(root)).unwrap();
        allocator.free_frame(kernel_frame).unwrap();
    }

    #[test]
    fn rejects_unreadable_kernel_root_without_mutating_destination() {
        let regions = [(0x1000, 0x9000, true)];
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let mut allocator = make_allocator(&regions, &mut slots, &mut bitmap).unwrap();
        let (mut root, kernel_address, kernel_frame) = initialize_test_roots(&mut allocator);
        let root_address = root.physical_address();
        let mut editor = TestRootEditor::new(root_address, kernel_address);
        let before = editor.tables[0].entries;
        editor.blocked_table = Some(kernel_address);

        assert_eq!(
            root.initialize_from_kernel_root(kernel_address, 511, 510, &mut editor),
            Err(AddressSpaceRootInitializationError::KernelRootTableUnavailable)
        );
        assert_eq!(editor.tables[0].entries, before);
        assert!(!root.is_initialized());

        allocator.free_frame(take_test_root_frame(root)).unwrap();
        allocator.free_frame(kernel_frame).unwrap();
    }

    #[test]
    fn rejects_unreadable_kernel_entry_without_mutating_destination() {
        let regions = [(0x1000, 0x9000, true)];
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let mut allocator = make_allocator(&regions, &mut slots, &mut bitmap).unwrap();
        let (mut root, kernel_address, kernel_frame) = initialize_test_roots(&mut allocator);
        let root_address = root.physical_address();
        let mut editor = TestRootEditor::new(root_address, kernel_address);
        editor.set_entry(kernel_address, 511, kernel_address | PRESENT | WRITABLE);
        editor.unreadable_entry = Some((kernel_address, 300));
        let before = editor.tables[0].entries;

        assert_eq!(
            root.initialize_from_kernel_root(kernel_address, 511, 510, &mut editor),
            Err(AddressSpaceRootInitializationError::KernelEntryUnavailable { index: 300 })
        );
        assert_eq!(editor.tables[0].entries, before);
        assert!(!root.is_initialized());

        allocator.free_frame(take_test_root_frame(root)).unwrap();
        allocator.free_frame(kernel_frame).unwrap();
    }

    #[test]
    fn rejects_invalid_kernel_recursive_entry_without_mutating_destination() {
        let regions = [(0x1000, 0x9000, true)];
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let mut allocator = make_allocator(&regions, &mut slots, &mut bitmap).unwrap();
        let (mut root, kernel_address, kernel_frame) = initialize_test_roots(&mut allocator);
        let root_address = root.physical_address();
        let mut editor = TestRootEditor::new(root_address, kernel_address);
        editor.set_entry(
            kernel_address,
            511,
            kernel_address | PRESENT | WRITABLE | USER_ACCESSIBLE,
        );
        let before = editor.tables[0].entries;

        assert_eq!(
            root.initialize_from_kernel_root(kernel_address, 511, 510, &mut editor),
            Err(AddressSpaceRootInitializationError::InvalidKernelRootRecursiveEntry)
        );
        assert_eq!(editor.tables[0].entries, before);
        assert!(!root.is_initialized());

        allocator.free_frame(take_test_root_frame(root)).unwrap();
        allocator.free_frame(kernel_frame).unwrap();
    }

    #[test]
    fn rejects_physical_address_width_mismatch_without_mutating_destination() {
        let regions = [(0x1000, 0x9000, true)];
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let mut allocator = make_allocator(&regions, &mut slots, &mut bitmap).unwrap();
        let (mut root, kernel_address, kernel_frame) = initialize_test_roots(&mut allocator);
        let root_address = root.physical_address();
        let mut editor = TestRootEditor::new(root_address, kernel_address);
        editor.physical_address_bits = 36;
        let before = editor.tables[0].entries;

        assert_eq!(
            root.initialize_from_kernel_root(kernel_address, 511, 510, &mut editor),
            Err(
                AddressSpaceRootInitializationError::PhysicalAddressWidthMismatch {
                    root_bits: 32,
                    editor_bits: 36,
                }
            )
        );
        assert_eq!(editor.tables[0].entries, before);
        assert!(!root.is_initialized());

        allocator.free_frame(take_test_root_frame(root)).unwrap();
        allocator.free_frame(kernel_frame).unwrap();
    }

    #[test]
    fn rejects_kernel_root_alias_without_mutating_destination() {
        let regions = [(0x1000, 0x9000, true)];
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let mut allocator = make_allocator(&regions, &mut slots, &mut bitmap).unwrap();
        let (mut root, _kernel_address, kernel_frame) = initialize_test_roots(&mut allocator);
        let root_address = root.physical_address();
        let mut editor = TestRootEditor::new(root_address, kernel_frame.physical_address());
        let before = editor.tables[0].entries;

        assert_eq!(
            root.initialize_from_kernel_root(root_address, 511, 510, &mut editor),
            Err(AddressSpaceRootInitializationError::RootAliasesKernelRoot)
        );
        assert_eq!(editor.tables[0].entries, before);
        assert!(!root.is_initialized());

        allocator.free_frame(take_test_root_frame(root)).unwrap();
        allocator.free_frame(kernel_frame).unwrap();
    }

    #[test]
    fn rejects_kernel_entry_aliasing_owned_root_without_mutating_destination() {
        let regions = [(0x1000, 0x9000, true)];
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let mut allocator = make_allocator(&regions, &mut slots, &mut bitmap).unwrap();
        let (mut root, kernel_address, kernel_frame) = initialize_test_roots(&mut allocator);
        let root_address = root.physical_address();
        let mut editor = TestRootEditor::new(root_address, kernel_address);
        editor.set_entry(kernel_address, 511, kernel_address | PRESENT | WRITABLE);
        editor.set_entry(kernel_address, 300, root_address | PRESENT | WRITABLE);
        let before = editor.tables[0].entries;

        assert_eq!(
            root.initialize_from_kernel_root(kernel_address, 511, 510, &mut editor),
            Err(AddressSpaceRootInitializationError::KernelEntryAliasesOwnedRoot { index: 300 })
        );
        assert_eq!(editor.tables[0].entries, before);
        assert!(!root.is_initialized());

        allocator.free_frame(take_test_root_frame(root)).unwrap();
        allocator.free_frame(kernel_frame).unwrap();
    }
}
