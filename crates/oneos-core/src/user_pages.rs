//! Ownership-safe, host-testable mapping helpers for user data pages.
//!
//! These helpers build on the generic four-level page-table mutation engine.
//! They map only writable, user-accessible, non-executable 4 KiB data pages.
//! A zeroed-frame token is retained by a per-address-space registry while
//! the mapping exists. Successful unmap returns a raw Frame token, because user
//! memory may have been modified and must be zero-initialized before reuse.
//!
//! The caller must serialize page-table mutation and frame ownership changes.
//! EFER.NXE must be enabled before using NX mappings. The invalidation hook must
//! invalidate positive and negative translations for the supplied root and
//! address before returning. The current kernel execution model is single-CPU;
//! this interface does not itself provide SMP synchronization or remote TLB
//! shootdowns. Intermediate page-table frames are retained by PageTableEditor
//! and are not reclaimed by these data-page helpers.

use crate::{
    map_4k, translate_4level, unmap_4k, validate_user_virtual_range, AddressSpaceRoot, Frame,
    FrameToken, PagePermissions, PageTableEditor, PageTableError, PageTableMutationError,
    UnmappedPage, UserVirtualRangeError, PAGE_SIZE,
};

/// Extension of the page-table editor with a root-aware translation invalidation hook.
///
/// Implementations must serialize this operation with address-space activation
/// and mutation, and must ensure no stale translation for the supplied
/// address-space root and virtual address can be used after the method returns.
/// The hook is called after both map and unmap, including after installing a
/// formerly non-present mapping because CPUs may cache non-present translations.
/// A local INVLPG is sufficient only when the implementation can establish that
/// it covers the target address space; future SMP support requires an explicit
/// remote-shootdown design.
pub trait UserAddressSpaceEditor: PageTableEditor {
    /// Invalidates the translation for one virtual page in the specified root.
    fn invalidate_translation(&mut self, root_table_physical: u64, virtual_address: u64);
}

/// Error returned when the kernel cannot establish a zero-filled user frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserFrameInitializationError {
    /// The frame could not be safely accessed or completely zeroed.
    InitializationFailed,
}

/// Architecture-provided operation for clearing a complete physical frame.
///
/// Trusted-kernel implementation contract:
///
/// Implementations must only report success after every byte in the specified
/// exclusively owned frame is zero. The frame must be accessed through a
/// validated writable supervisor-only alias, and an error must never produce a
/// `ZeroedFrame`. Implementations must preserve frame ownership on all paths.
/// A faulty implementation can violate confidentiality, so implementing this
/// trait is an unsafe operation. Only reviewed kernel code should implement it.
/// The host-testable core cannot validate physical memory contents by itself.
///
/// # Safety
///
/// An implementation must only return success after every byte in the complete
/// exclusively owned frame is zero, accessed through a validated writable
/// supervisor-only alias. It must preserve ownership on both success and failure,
/// and must not report success when zeroing could not be completed or verified.
#[allow(unsafe_code)]
pub unsafe trait UserFrameInitializer {
    /// Clears the complete 4 KiB frame, failing closed if it cannot be verified.
    fn zero_frame(&mut self, frame: &Frame) -> Result<(), UserFrameInitializationError>;
}

/// A frame whose complete contents were zeroed before it can be mapped to user mode.
///
/// The token is non-Copy and consumed by the user mapping API. It does not prove
/// system-wide W^X or prevent unrelated kernel code from writing through another
/// alias; callers must preserve ownership and the single-CPU mutation contract.
#[must_use = "a zeroed frame token must be retained or explicitly returned to its allocator"]
#[derive(Debug, Eq, PartialEq)]
pub struct ZeroedFrame {
    frame: Frame,
}

impl ZeroedFrame {
    /// Creates the private token after the initializer reports successful zeroing.
    ///
    /// The caller's initialization contract must still hold: every byte in the
    /// complete frame is zero, ownership is exclusive, and no uncontrolled writer
    /// may mutate the frame before publication to the intended user mapping.
    fn from_zeroed_frame(frame: Frame) -> Self {
        Self { frame }
    }

    /// Returns the physical base address without exposing the ownership token.
    pub const fn physical_address(&self) -> u64 {
        self.frame.physical_address()
    }

    /// Returns the underlying ownership token to a kernel allocator.
    pub fn into_frame(self) -> Frame {
        self.frame
    }
}

impl FrameToken for ZeroedFrame {
    fn frame_address(&self) -> u64 {
        self.frame.physical_address()
    }
}

/// Clears a frame before granting it the `ZeroedFrame` type.
///
/// On failure, the original frame token is returned to the caller.
pub fn initialize_user_frame<I: UserFrameInitializer>(
    frame: Frame,
    initializer: &mut I,
) -> Result<ZeroedFrame, (UserFrameInitializationError, Frame)> {
    if let Err(error) = initializer.zero_frame(&frame) {
        return Err((error, frame));
    }
    // The initializer contract guarantees that every byte is zero after Ok and
    // that the frame remains exclusively owned.
    Ok(ZeroedFrame::from_zeroed_frame(frame))
}

/// Errors returned by user data-page mapping operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserPageMappingError {
    /// The address-space root has not completed initialization.
    AddressSpaceNotInitialized,
    /// This registry is bound to a different address-space root.
    AddressSpaceRootMismatch {
        /// PML4 physical address captured when the registry was created.
        registry_root_physical: u64,
        /// PML4 physical address supplied to the operation.
        supplied_root_physical: u64,
    },
    /// Address zero is intentionally kept unmapped as a null guard.
    NullVirtualAddress,
    /// User data pages must be aligned to 4 KiB.
    UnalignedVirtualAddress,
    /// The complete page is not contained in the lower canonical user half.
    InvalidUserVirtualRange(UserVirtualRangeError),
    /// The fixed-capacity ownership registry has no free slot.
    RegistryFull,
    /// This virtual address is already mapped, reserved, or being prepared.
    DuplicateVirtualAddress,
    /// This physical frame is already mapped or reserved in this registry.
    DuplicatePhysicalFrame,
    /// The requested address has no mapping owned by this registry.
    NoOwnedMapping,
    /// Teardown found a registry reservation that was not published as a mapping.
    IncompleteMappingReservation,
    /// The page-table translation disagrees with the registry's ownership record.
    MappingInvariantViolation,
    /// The generic page-table mutation engine rejected the operation.
    PageTable(PageTableMutationError),
    /// The current page-table walk could not establish a safe translation.
    Translation(PageTableError),
}

/// Completed progress for a batch of user-data page removals.
///
/// Each returned frame has already been detached from its leaf mapping and its
/// translation invalidation hook has completed. The caller still owns every
/// returned token and must return it to the issuing allocator or retain it.
/// Unused slots are None. Dropping this result without taking/freeing its frames
/// intentionally leaks those allocations rather than making them reusable.
#[must_use = "retain and release every frame returned by user-page teardown"]
#[derive(Debug)]
pub struct UserPageTeardownResult<const CAPACITY: usize> {
    frames: [Option<Frame>; CAPACITY],
    completed_pages: usize,
}

impl<const CAPACITY: usize> UserPageTeardownResult<CAPACITY> {
    fn empty() -> Self {
        Self {
            frames: core::array::from_fn(|_| None),
            completed_pages: 0,
        }
    }

    /// Number of leaf mappings detached and invalidated by this operation.
    pub const fn completed_pages(&self) -> usize {
        self.completed_pages
    }

    /// Takes ownership of a returned frame by its completion-order index.
    ///
    /// Returns None for an out-of-range index or a frame already taken.
    pub fn take_frame(&mut self, index: usize) -> Option<Frame> {
        self.frames.get_mut(index).and_then(Option::take)
    }

    /// Consumes the result and returns the frame slots, with unused slots as None.
    pub fn into_frames(self) -> [Option<Frame>; CAPACITY] {
        self.frames
    }
}

/// Failure from batch user-data page teardown.
///
/// A preflight failure guarantees that no mappings were modified. If an editor
/// unexpectedly fails after mutation begins, partial_result retains all frame
/// tokens whose pages were already unmapped and invalidated; remaining mappings
/// and tokens stay in the registry and can be retried. Never free or reactivate
/// the address-space root merely because a partial batch completed.
#[must_use = "inspect partial teardown progress and retain every returned frame"]
#[derive(Debug)]
pub struct UserPageTeardownFailure<const CAPACITY: usize> {
    error: UserPageMappingError,
    partial_result: UserPageTeardownResult<CAPACITY>,
}

impl<const CAPACITY: usize> UserPageTeardownFailure<CAPACITY> {
    fn before_mutation(error: UserPageMappingError) -> Self {
        Self {
            error,
            partial_result: UserPageTeardownResult::empty(),
        }
    }

    /// The reason the teardown stopped.
    pub const fn error(&self) -> UserPageMappingError {
        self.error
    }

    /// Number of pages safely unmapped before the failure.
    pub const fn completed_pages(&self) -> usize {
        self.partial_result.completed_pages()
    }

    /// Borrow the partial result to retrieve already-detached frame tokens.
    pub fn partial_result_mut(&mut self) -> &mut UserPageTeardownResult<CAPACITY> {
        &mut self.partial_result
    }

    /// Consumes the failure and returns already-detached frame tokens.
    pub fn into_partial_result(self) -> UserPageTeardownResult<CAPACITY> {
        self.partial_result
    }
}

enum MappingSlot<T: FrameToken> {
    Empty,
    Reserved {
        virtual_address: u64,
        physical_address: u64,
    },
    Mapped {
        virtual_address: u64,
        token: T,
    },
}

/// Fixed-capacity registry retaining data-frame ownership for one address space.
///
/// Each live mapping has one non-Copy zeroed-frame token. A slot is reserved before
/// page-table mutation begins, so registry exhaustion cannot occur after a
/// mapping has been published. This registry is address-space-local; it does
/// not replace the future global reverse-alias accounting needed for frame-wide
/// W^X across processes and kernel/direct-map aliases.
pub struct UserPageMappingRegistry<T: FrameToken, const CAPACITY: usize> {
    root_physical: u64,
    slots: [MappingSlot<T>; CAPACITY],
}

impl<T: FrameToken, const CAPACITY: usize> UserPageMappingRegistry<T, CAPACITY> {
    /// Creates an empty registry bound to one address-space root.
    ///
    /// The binding is permanent for the registry lifetime. Mapping operations
    /// reject any different root before reading or mutating its page tables.
    pub fn new(root: &AddressSpaceRoot) -> Self {
        Self {
            root_physical: root.physical_address(),
            slots: core::array::from_fn(|_| MappingSlot::Empty),
        }
    }

    /// Physical address of the PML4 root this registry belongs to.
    pub const fn root_physical_address(&self) -> u64 {
        self.root_physical
    }

    fn validate_root(&self, root: &AddressSpaceRoot) -> Result<(), UserPageMappingError> {
        let supplied_root_physical = root.physical_address();
        if supplied_root_physical != self.root_physical {
            return Err(UserPageMappingError::AddressSpaceRootMismatch {
                registry_root_physical: self.root_physical,
                supplied_root_physical,
            });
        }
        Ok(())
    }

    /// Returns the number of unused ownership slots.
    pub fn available_slots(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| matches!(slot, MappingSlot::Empty))
            .count()
    }

    /// Returns whether the registry owns a live mapping at this virtual address.
    pub fn is_mapped(&self, virtual_address: u64) -> bool {
        self.slots.iter().any(|slot| {
            matches!(
                slot,
                MappingSlot::Mapped {
                    virtual_address: mapped,
                    ..
                } if *mapped == virtual_address
            )
        })
    }

    /// Returns the physical frame owned for a live mapping at `virtual_address`.
    ///
    /// The returned address is the page-aligned base from the registry's retained
    /// frame token, not a page-table walk. Callers that validate a mapping must
    /// compare this value with the actual page-table translation.
    pub fn mapped_physical_address(&self, virtual_address: u64) -> Option<u64> {
        self.slots.iter().find_map(|slot| match slot {
            MappingSlot::Mapped {
                virtual_address: mapped,
                token,
            } if *mapped == virtual_address => Some(token.frame_address()),
            _ => None,
        })
    }

    /// Returns the live mapping stored at a registry slot, as (virtual, physical).
    ///
    /// Empty and in-progress reservation slots return `None`; use
    /// `has_reserved_mappings` to reject incomplete transactions before walking
    /// the page table tree.
    pub fn mapped_entry_at(&self, slot_index: usize) -> Option<(u64, u64)> {
        match self.slots.get(slot_index)? {
            MappingSlot::Mapped {
                virtual_address,
                token,
            } => Some((*virtual_address, token.frame_address())),
            MappingSlot::Empty | MappingSlot::Reserved { .. } => None,
        }
    }

    /// Returns whether any mapping transaction is still reserved but unpublished.
    pub fn has_reserved_mappings(&self) -> bool {
        self.slots
            .iter()
            .any(|slot| matches!(slot, MappingSlot::Reserved { .. }))
    }

    fn reserve_mapping(
        &mut self,
        virtual_address: u64,
        physical_address: u64,
    ) -> Result<usize, UserPageMappingError> {
        let mut free_slot = None;
        for (index, slot) in self.slots.iter().enumerate() {
            match slot {
                MappingSlot::Empty => {
                    if free_slot.is_none() {
                        free_slot = Some(index);
                    }
                }
                MappingSlot::Reserved {
                    virtual_address: reserved_virtual,
                    ..
                } if *reserved_virtual == virtual_address => {
                    return Err(UserPageMappingError::DuplicateVirtualAddress);
                }
                MappingSlot::Mapped {
                    virtual_address: mapped_virtual,
                    ..
                } if *mapped_virtual == virtual_address => {
                    return Err(UserPageMappingError::DuplicateVirtualAddress);
                }
                MappingSlot::Reserved {
                    physical_address: reserved_physical,
                    ..
                } if *reserved_physical == physical_address => {
                    return Err(UserPageMappingError::DuplicatePhysicalFrame);
                }
                MappingSlot::Mapped { token, .. } if token.frame_address() == physical_address => {
                    return Err(UserPageMappingError::DuplicatePhysicalFrame);
                }
                _ => {}
            }
        }

        let index = free_slot.ok_or(UserPageMappingError::RegistryFull)?;
        self.slots[index] = MappingSlot::Reserved {
            virtual_address,
            physical_address,
        };
        Ok(index)
    }

    fn cancel_reservation(&mut self, index: usize) {
        assert!(matches!(
            self.slots.get(index),
            Some(MappingSlot::Reserved { .. })
        ));
        self.slots[index] = MappingSlot::Empty;
    }

    fn publish_reserved(&mut self, index: usize, token: T) {
        let slot = core::mem::replace(&mut self.slots[index], MappingSlot::Empty);
        match slot {
            MappingSlot::Reserved {
                virtual_address,
                physical_address,
            } => {
                assert_eq!(
                    physical_address,
                    token.frame_address(),
                    "reserved physical frame must match the ownership token"
                );
                self.slots[index] = MappingSlot::Mapped {
                    virtual_address,
                    token,
                };
            }
            _ => panic!("mapping publication requires a reserved registry slot"),
        }
    }

    fn mapped_slot(&self, virtual_address: u64) -> Result<(usize, u64), UserPageMappingError> {
        for (index, slot) in self.slots.iter().enumerate() {
            match slot {
                MappingSlot::Mapped {
                    virtual_address: mapped,
                    token,
                } if *mapped == virtual_address => return Ok((index, token.frame_address())),
                MappingSlot::Reserved {
                    virtual_address: reserved,
                    ..
                } if *reserved == virtual_address => {
                    return Err(UserPageMappingError::DuplicateVirtualAddress);
                }
                _ => {}
            }
        }
        Err(UserPageMappingError::NoOwnedMapping)
    }

    fn take_mapped(&mut self, index: usize) -> T {
        match core::mem::replace(&mut self.slots[index], MappingSlot::Empty) {
            MappingSlot::Mapped { token, .. } => token,
            _ => panic!("unmap completion requires an owned mapping slot"),
        }
    }
}

fn validate_user_page_address(virtual_address: u64) -> Result<(), UserPageMappingError> {
    if virtual_address == 0 {
        return Err(UserPageMappingError::NullVirtualAddress);
    }
    if virtual_address & (PAGE_SIZE - 1) != 0 {
        return Err(UserPageMappingError::UnalignedVirtualAddress);
    }
    validate_user_virtual_range(virtual_address, PAGE_SIZE)
        .map_err(UserPageMappingError::InvalidUserVirtualRange)
}

/// Maps one previously zeroed frame as writable, user-accessible, non-executable data.
///
/// A raw Frame cannot be passed directly; the compiler requires a ZeroedFrame:
///
/// ```compile_fail
/// use oneos_core::{
///     map_user_data_page, AddressSpaceRoot, Frame, UserAddressSpaceEditor,
///     UserPageMappingRegistry, ZeroedFrame,
/// };
/// fn bypass<E: UserAddressSpaceEditor>(
///     root: &AddressSpaceRoot,
///     frame: Frame,
///     registry: &mut UserPageMappingRegistry<ZeroedFrame, 1>,
///     editor: &mut E,
/// ) {
///     let _ = map_user_data_page(root, 0x1000, frame, registry, editor);
/// }
/// ```
///
/// The raw low-level mapper is not exported either:
///
/// ```compile_fail
/// use oneos_core::{map_4k, PagePermissions, PageTableEditor};
/// ```
///
/// The zeroed-frame token is moved into the registry only after the internal mapper succeeds. The
/// registry reserves its slot first, so metadata exhaustion fails before any
/// page-table mutation. On every error, the original frame token is returned.
/// This operation calls the editor's translation invalidation hook after
/// publishing the mapping, including to invalidate a previously cached
/// non-present translation.
///
/// This API requires `ZeroedFrame`, so a raw allocator token cannot be mapped
/// through the safe interface. The type is only produced by initialize_user_frame,
/// which relies on the initializer's unsafe implementation contract.
/// Executable mappings are deliberately not supported by this helper. The
/// caller must enable EFER.NXE and use an editor whose allocation/ownership
/// checks meet PageTableEditor’s contract.
pub fn map_user_data_page<E: UserAddressSpaceEditor, const CAPACITY: usize>(
    root: &AddressSpaceRoot,
    virtual_address: u64,
    frame: ZeroedFrame,
    registry: &mut UserPageMappingRegistry<ZeroedFrame, CAPACITY>,
    editor: &mut E,
) -> Result<(), (UserPageMappingError, ZeroedFrame)> {
    if let Err(error) = registry.validate_root(root) {
        return Err((error, frame));
    }
    if !root.is_initialized() {
        return Err((UserPageMappingError::AddressSpaceNotInitialized, frame));
    }
    if let Err(error) = validate_user_page_address(virtual_address) {
        return Err((error, frame));
    }

    let root_physical = root.physical_address();
    let physical_address = frame.physical_address();
    let slot = match registry.reserve_mapping(virtual_address, physical_address) {
        Ok(slot) => slot,
        Err(error) => return Err((error, frame)),
    };

    if let Err(error) = map_4k(
        root_physical,
        virtual_address,
        physical_address,
        PagePermissions::new(true, true, false),
        editor,
    ) {
        registry.cancel_reservation(slot);
        return Err((UserPageMappingError::PageTable(error), frame));
    }

    registry.publish_reserved(slot, frame);
    editor.invalidate_translation(root_physical, virtual_address);
    Ok(())
}

/// Unmaps one registry-owned user data page and returns a raw Frame after invalidation.
///
/// Before mutating the table, this checks that the complete translation is a
/// 4 KiB, user-accessible, writable, NX mapping to the physical frame retained
/// by the registry. unmap_4k clears the leaf, and translation invalidation must
/// complete before ownership is returned. Because user mode may have modified
/// any byte, the returned Frame is deliberately not a ZeroedFrame: it must pass
/// through initialize_user_frame again before reuse in this or another address
/// space. Intermediate page-table pages remain allocated for their owner.
pub fn unmap_user_data_page<E: UserAddressSpaceEditor, const CAPACITY: usize>(
    root: &AddressSpaceRoot,
    virtual_address: u64,
    registry: &mut UserPageMappingRegistry<ZeroedFrame, CAPACITY>,
    editor: &mut E,
) -> Result<(UnmappedPage, Frame), UserPageMappingError> {
    registry.validate_root(root)?;
    if !root.is_initialized() {
        return Err(UserPageMappingError::AddressSpaceNotInitialized);
    }
    validate_user_page_address(virtual_address)?;

    let (slot, expected_physical) = registry.mapped_slot(virtual_address)?;
    let root_physical = root.physical_address();

    // translate_4level calls the reader in level order (4, 3, 2, 1). Keep
    // level tracking here because PageTableEditor validates access per level.
    let mut next_level: u8 = 4;
    let translation = translate_4level(virtual_address, root_physical, |table, index| {
        let current_level = next_level;
        next_level = next_level.saturating_sub(1);
        editor.read_entry(table, index, current_level)
    })
    .map_err(UserPageMappingError::Translation)?;

    if translation.page_size != PAGE_SIZE
        || translation.physical_address != expected_physical
        || !translation.user_accessible
        || !translation.writable
        || translation.executable
    {
        return Err(UserPageMappingError::MappingInvariantViolation);
    }

    let unmapped = unmap_4k(root_physical, virtual_address, editor)
        .map_err(UserPageMappingError::PageTable)?;

    // Keep the frame token in the registry through invalidation. A returned
    // token is therefore never available for reuse while a stale translation
    // may still authorize access to it.
    editor.invalidate_translation(root_physical, virtual_address);
    assert_eq!(
        unmapped.physical_address, expected_physical,
        "serialized page-table mutation must preserve the preflighted mapping"
    );
    let frame = registry.take_mapped(slot).into_frame();
    Ok((unmapped, frame))
}

/// Validates that one registry-owned virtual address still maps the exact
/// writable, user-accessible, NX 4 KiB frame recorded by the ownership token.
fn preflight_user_data_mapping<E: UserAddressSpaceEditor>(
    root_physical: u64,
    virtual_address: u64,
    expected_physical: u64,
    editor: &mut E,
) -> Result<(), UserPageMappingError> {
    validate_user_page_address(virtual_address)?;

    // translate_4level calls the reader in level order (4, 3, 2, 1). Track the
    // level explicitly because PageTableEditor validates access per level.
    let mut next_level: u8 = 4;
    let translation = translate_4level(virtual_address, root_physical, |table, index| {
        let current_level = next_level;
        next_level = next_level.saturating_sub(1);
        editor.read_entry(table, index, current_level)
    })
    .map_err(UserPageMappingError::Translation)?;

    if translation.page_size != PAGE_SIZE
        || translation.physical_address != expected_physical
        || !translation.user_accessible
        || !translation.writable
        || translation.executable
    {
        return Err(UserPageMappingError::MappingInvariantViolation);
    }

    Ok(())
}

/// Removes all user-data mappings tracked by one address-space registry.
///
/// The root must already be inactive, and the caller must serialize teardown
/// with mapping, allocation, and any address-space activation. Every registry
/// entry is preflighted before the first leaf is changed. Consequently, a
/// detected bad mapping, unfinished reservation, wrong root, or invalid state
/// returns without changing any page table.
///
/// Each successful leaf removal is followed by root-aware translation
/// invalidation before its Frame token is returned. If the editor unexpectedly
/// fails after mutation begins, the error reports partial progress: completed
/// frames are returned in the failure value, and the still-mapped frames remain
/// owned by the registry. Callers must retain/release those completed frames
/// and may retry the remaining registry. Intermediate page-table pages and the
/// root frame are deliberately not reclaimed by this function.
///
/// The initial implementation is for the existing serialized, single-CPU
/// model. It does not provide remote TLB shootdowns or SMP safety.
pub fn unmap_all_user_data_pages<E: UserAddressSpaceEditor, const CAPACITY: usize>(
    root: &AddressSpaceRoot,
    registry: &mut UserPageMappingRegistry<ZeroedFrame, CAPACITY>,
    editor: &mut E,
) -> Result<UserPageTeardownResult<CAPACITY>, UserPageTeardownFailure<CAPACITY>> {
    if let Err(error) = registry.validate_root(root) {
        return Err(UserPageTeardownFailure::before_mutation(error));
    }
    if !root.is_initialized() {
        return Err(UserPageTeardownFailure::before_mutation(
            UserPageMappingError::AddressSpaceNotInitialized,
        ));
    }

    let root_physical = root.physical_address();
    let mut virtual_addresses = [0u64; CAPACITY];
    let mut mapping_count = 0usize;

    // Preflight every registered mapping before the first destructive write.
    for slot in &registry.slots {
        match slot {
            MappingSlot::Empty => {}
            MappingSlot::Reserved { .. } => {
                return Err(UserPageTeardownFailure::before_mutation(
                    UserPageMappingError::IncompleteMappingReservation,
                ));
            }
            MappingSlot::Mapped {
                virtual_address,
                token,
            } => {
                if let Err(error) = preflight_user_data_mapping(
                    root_physical,
                    *virtual_address,
                    token.frame_address(),
                    editor,
                ) {
                    return Err(UserPageTeardownFailure::before_mutation(error));
                }
                virtual_addresses[mapping_count] = *virtual_address;
                mapping_count += 1;
            }
        }
    }

    let mut progress = UserPageTeardownResult::empty();
    for virtual_address in virtual_addresses[..mapping_count].iter().copied() {
        match unmap_user_data_page(root, virtual_address, registry, editor) {
            Ok((_unmapped, frame)) => {
                progress.frames[progress.completed_pages] = Some(frame);
                progress.completed_pages += 1;
            }
            Err(error) => {
                return Err(UserPageTeardownFailure {
                    error,
                    partial_result: progress,
                });
            }
        }
    }

    Ok(progress)
}

#[cfg(test)]
mod tests {
    use super::{
        initialize_user_frame, map_user_data_page, unmap_all_user_data_pages, unmap_user_data_page,
        UserAddressSpaceEditor, UserFrameInitializationError, UserFrameInitializer,
        UserPageMappingError, UserPageMappingRegistry, ZeroedFrame,
    };
    use crate::{
        map_4k, unmap_4k, AddressSpaceRoot, AddressSpaceRootEditor, Frame, FrameAllocator,
        FrameSegment, PagePermissions, PageTableEditor, PageTableMutationError, PAGE_SIZE,
    };

    const PRESENT: u64 = 1;
    const WRITABLE: u64 = 1 << 1;

    struct TestTable {
        physical_address: u64,
        entries: [u64; 512],
        in_use: bool,
    }

    impl TestTable {
        fn new(physical_address: u64, in_use: bool) -> Self {
            Self {
                physical_address,
                entries: [0; 512],
                in_use,
            }
        }
    }

    const TEST_FRAME_MEMORY_SLOTS: usize = 4;

    #[derive(Clone, Copy)]
    struct TestFrameMemory {
        physical_address: u64,
        contents: [u8; PAGE_SIZE as usize],
    }

    impl TestFrameMemory {
        const EMPTY: Self = Self {
            physical_address: 0,
            contents: [0; PAGE_SIZE as usize],
        };
    }

    struct TestEditor {
        tables: [TestTable; 9],
        data_frames: [u64; TEST_FRAME_MEMORY_SLOTS],
        data_frame_count: usize,
        fail_allocation: bool,
        fail_after_successful_allocations: Option<usize>,
        successful_allocations: usize,
        invalidations: usize,
        last_invalidation: Option<(u64, u64)>,
        fail_after_first_unmap: bool,
        fail_read_at: Option<(u64, usize)>,
        frame_memory: [TestFrameMemory; TEST_FRAME_MEMORY_SLOTS],
        fail_zeroing: bool,
    }

    impl TestEditor {
        fn new(data_frame: u64) -> Self {
            let mut editor = Self {
                tables: [
                    TestTable::new(0x1000, true),
                    TestTable::new(0x2000, false),
                    TestTable::new(0x3000, false),
                    TestTable::new(0x4000, false),
                    TestTable::new(0x5000, true),
                    TestTable::new(0x7000, false),
                    TestTable::new(0xb000, false),
                    TestTable::new(0xc000, false),
                    TestTable::new(0xd000, false),
                ],
                data_frames: [data_frame, 0, 0, 0],
                data_frame_count: 1,
                fail_allocation: false,
                fail_after_successful_allocations: None,
                successful_allocations: 0,
                invalidations: 0,
                last_invalidation: None,
                fail_after_first_unmap: false,
                fail_read_at: None,
                frame_memory: [TestFrameMemory::EMPTY; TEST_FRAME_MEMORY_SLOTS],
                fail_zeroing: false,
            };
            editor
                .ensure_frame_memory(data_frame)
                .expect("test data frame must fit the memory model");
            editor.set_entry(0x1000, 511, 0x1000 | PRESENT | WRITABLE);
            editor
        }

        fn register_data_frame(&mut self, physical_address: u64) {
            if self.data_frames[..self.data_frame_count].contains(&physical_address) {
                return;
            }
            let slot = self.data_frame_count;
            assert!(
                slot < self.data_frames.len(),
                "test frame registry capacity exceeded"
            );
            self.data_frames[slot] = physical_address;
            self.data_frame_count += 1;
            self.ensure_frame_memory(physical_address)
                .expect("test data frame must fit the memory model");
        }

        fn ensure_frame_memory(&mut self, physical_address: u64) -> Option<usize> {
            if physical_address == 0 {
                return None;
            }
            if let Some(index) = self
                .frame_memory
                .iter()
                .position(|frame| frame.physical_address == physical_address)
            {
                return Some(index);
            }
            let index = self
                .frame_memory
                .iter()
                .position(|frame| frame.physical_address == 0)?;
            self.frame_memory[index].physical_address = physical_address;
            self.frame_memory[index].contents.fill(0xa5);
            Some(index)
        }

        fn frame_contents(&self, physical_address: u64) -> &[u8; PAGE_SIZE as usize] {
            &self
                .frame_memory
                .iter()
                .find(|frame| frame.physical_address == physical_address)
                .expect("the physical frame must exist in the test memory model")
                .contents
        }

        fn fill_frame_contents(&mut self, physical_address: u64, value: u8) {
            let index = self
                .ensure_frame_memory(physical_address)
                .expect("test memory model capacity must cover the allocated frames");
            self.frame_memory[index].contents.fill(value);
        }

        fn set_entry(&mut self, table: u64, index: usize, value: u64) {
            self.tables
                .iter_mut()
                .find(|candidate| candidate.physical_address == table)
                .expect("test table must exist")
                .entries[index] = value;
        }

        fn entry(&self, table: u64, index: usize) -> u64 {
            self.tables
                .iter()
                .find(|candidate| candidate.physical_address == table)
                .expect("test table must exist")
                .entries[index]
        }

        fn mark_table_in_use(&mut self, physical_address: u64) {
            self.tables
                .iter_mut()
                .find(|table| table.physical_address == physical_address)
                .expect("test table must exist")
                .in_use = true;
        }

        fn table_is_in_use(&self, physical_address: u64) -> bool {
            self.tables
                .iter()
                .find(|table| table.physical_address == physical_address)
                .expect("test table must exist")
                .in_use
        }
    }

    impl AddressSpaceRootEditor for TestEditor {
        fn physical_address_bits(&self) -> u8 {
            32
        }

        fn table_is_readable(&mut self, table_physical: u64) -> bool {
            self.tables
                .iter()
                .any(|table| table.physical_address == table_physical && table.in_use)
        }

        fn table_is_read_write_accessible(&mut self, table_physical: u64) -> bool {
            self.tables
                .iter()
                .any(|table| table.physical_address == table_physical && table.in_use)
        }

        fn read_entry(&mut self, table_physical: u64, index: usize, _level: u8) -> Option<u64> {
            self.tables
                .iter()
                .find(|table| table.physical_address == table_physical && table.in_use)
                .and_then(|table| table.entries.get(index).copied())
        }

        fn write_entry(&mut self, table_physical: u64, index: usize, _level: u8, value: u64) {
            let table = self
                .tables
                .iter_mut()
                .find(|table| table.physical_address == table_physical && table.in_use)
                .expect("writes require a known, allocated table");
            table.entries[index] = value;
        }
    }

    impl PageTableEditor for TestEditor {
        fn physical_address_bits(&self) -> u8 {
            32
        }

        fn read_entry(&mut self, table_physical: u64, index: usize, _level: u8) -> Option<u64> {
            if self.fail_read_at == Some((table_physical, index)) {
                self.fail_read_at = None;
                return None;
            }
            self.tables
                .iter()
                .find(|table| table.physical_address == table_physical && table.in_use)
                .and_then(|table| table.entries.get(index).copied())
        }

        fn write_entry(&mut self, table_physical: u64, index: usize, _level: u8, value: u64) {
            let table = self
                .tables
                .iter_mut()
                .find(|table| table.physical_address == table_physical && table.in_use)
                .expect("writes require a known, allocated table");
            table.entries[index] = value;
        }

        fn allocate_table(&mut self) -> Option<u64> {
            if self.fail_allocation
                || self.fail_after_successful_allocations == Some(self.successful_allocations)
            {
                return None;
            }
            let table = self.tables.iter_mut().find(|table| {
                matches!(
                    table.physical_address,
                    0x2000..=0x4000 | 0xb000..=0xd000
                ) && !table.in_use
            })?;
            table.entries.fill(0);
            table.in_use = true;
            self.successful_allocations += 1;
            Some(table.physical_address)
        }

        fn is_frame_allocated(&self, physical_address: u64) -> bool {
            self.data_frames[..self.data_frame_count].contains(&physical_address)
                || self
                    .tables
                    .iter()
                    .any(|table| table.physical_address == physical_address && table.in_use)
        }

        fn is_page_table_or_reserved_frame(&self, physical_address: u64) -> bool {
            self.tables
                .iter()
                .any(|table| table.physical_address == physical_address && table.in_use)
        }

        fn executable_mapping_allowed(&self, _physical_address: u64) -> bool {
            false
        }

        fn free_table(&mut self, physical_address: u64) {
            if let Some(table) = self.tables.iter_mut().find(|table| {
                table.physical_address == physical_address
                    && matches!(
                        table.physical_address,
                        0x2000..=0x4000 | 0xb000..=0xd000
                    )
            }) {
                table.entries.fill(0);
                table.in_use = false;
            }
        }
    }

    #[allow(unsafe_code)]
    unsafe impl UserFrameInitializer for TestEditor {
        fn zero_frame(&mut self, frame: &Frame) -> Result<(), UserFrameInitializationError> {
            if self.fail_zeroing {
                return Err(UserFrameInitializationError::InitializationFailed);
            }
            let index = self
                .ensure_frame_memory(frame.physical_address())
                .ok_or(UserFrameInitializationError::InitializationFailed)?;
            self.frame_memory[index].contents.fill(0);
            Ok(())
        }
    }

    impl UserAddressSpaceEditor for TestEditor {
        fn invalidate_translation(&mut self, root_table_physical: u64, virtual_address: u64) {
            // A test can arm one transient second-page read failure. Trigger it
            // only after the first target page has been unmapped and invalidated.
            if self.fail_after_first_unmap && virtual_address == 0x4000 {
                self.fail_after_first_unmap = false;
                self.fail_read_at = Some((0x4000, 8));
            }
            self.invalidations += 1;
            self.last_invalidation = Some((root_table_physical, virtual_address));
        }
    }

    fn setup<'a>(
        slots: &'a mut [FrameSegment],
        bitmap: &'a mut [u64],
    ) -> (FrameAllocator<'a>, AddressSpaceRoot, Frame, TestEditor) {
        let regions = [(0x5000, 0x9000, true)];
        let mut allocator =
            FrameAllocator::initialize(regions.len(), |index| regions[index], slots, bitmap)
                .unwrap();
        let root_frame = allocator.allocate_frame().unwrap();
        let data_frame = allocator.allocate_frame().unwrap();
        let data_address = data_frame.physical_address();
        let root = AddressSpaceRoot::try_from_frame(root_frame, 32).unwrap();
        let mut editor = TestEditor::new(data_address);
        let mut root = root;
        root.initialize_from_kernel_root(0x1000, 511, 510, &mut editor)
            .unwrap();
        (allocator, root, data_frame, editor)
    }

    // The production user-page API intentionally leaves intermediate tables
    // allocated. These test-only helpers disconnect inactive roots before
    // releasing mock table pages.
    fn disconnect_test_address_space(root: &AddressSpaceRoot, editor: &mut TestEditor) {
        for index in 0..512 {
            editor.set_entry(root.physical_address(), index, 0);
        }
    }

    fn release_test_page_tables(editor: &mut TestEditor) {
        for table_physical in [0x2000, 0x3000, 0x4000, 0xb000, 0xc000, 0xd000] {
            editor.free_table(table_physical);
        }
    }

    #[test]
    fn batch_teardown_unmaps_all_pages_and_returns_owned_frames_after_invalidation() {
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let (mut allocator, root, first_frame, mut editor) = setup(&mut slots, &mut bitmap);
        let first_physical = first_frame.physical_address();
        let second_frame = allocator.allocate_frame().unwrap();
        let second_physical = second_frame.physical_address();
        editor.register_data_frame(second_physical);

        let mut registry = UserPageMappingRegistry::<ZeroedFrame, 2>::new(&root);
        map_user_data_page(
            &root,
            0x4000,
            initialize_user_frame(first_frame, &mut editor).unwrap(),
            &mut registry,
            &mut editor,
        )
        .unwrap();
        map_user_data_page(
            &root,
            0x8000,
            initialize_user_frame(second_frame, &mut editor).unwrap(),
            &mut registry,
            &mut editor,
        )
        .unwrap();

        assert_eq!(registry.mapped_physical_address(0x4000), Some(first_physical));
        assert_eq!(registry.mapped_physical_address(0x8000), Some(second_physical));
        assert_eq!(registry.mapped_physical_address(0xc000), None);
        assert_eq!(registry.mapped_entry_at(0), Some((0x4000, first_physical)));
        assert_eq!(registry.mapped_entry_at(1), Some((0x8000, second_physical)));
        assert!(!registry.has_reserved_mappings());

        let mut result = unmap_all_user_data_pages(&root, &mut registry, &mut editor).unwrap();
        assert_eq!(result.completed_pages(), 2);
        assert!(!registry.is_mapped(0x4000));
        assert!(!registry.is_mapped(0x8000));
        assert_eq!(registry.available_slots(), 2);
        assert_eq!(editor.invalidations, 4);
        assert_eq!(
            editor.last_invalidation,
            Some((root.physical_address(), 0x8000))
        );

        let returned_first = result.take_frame(0).unwrap();
        let returned_second = result.take_frame(1).unwrap();
        assert_eq!(returned_first.physical_address(), first_physical);
        assert_eq!(returned_second.physical_address(), second_physical);
        assert!(result.take_frame(0).is_none());
        allocator.free_frame(returned_first).unwrap();
        allocator.free_frame(returned_second).unwrap();

        disconnect_test_address_space(&root, &mut editor);
        release_test_page_tables(&mut editor);
        allocator.free_frame(root.into_frame()).unwrap();
        assert_eq!(allocator.stats().allocated_frames, 0);
    }

    #[test]
    fn batch_teardown_recovers_from_mid_batch_failure_and_retries_remaining_mapping() {
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let (mut allocator, root, first_frame, mut editor) = setup(&mut slots, &mut bitmap);
        let first_physical = first_frame.physical_address();
        let second_frame = allocator.allocate_frame().unwrap();
        let second_physical = second_frame.physical_address();
        editor.register_data_frame(second_physical);

        let mut registry = UserPageMappingRegistry::<ZeroedFrame, 2>::new(&root);
        map_user_data_page(
            &root,
            0x4000,
            initialize_user_frame(first_frame, &mut editor).unwrap(),
            &mut registry,
            &mut editor,
        )
        .unwrap();
        map_user_data_page(
            &root,
            0x8000,
            initialize_user_frame(second_frame, &mut editor).unwrap(),
            &mut registry,
            &mut editor,
        )
        .unwrap();

        // Trigger a one-shot table-reader error only after the first mapping
        // has been removed and its translation invalidated.
        editor.fail_after_first_unmap = true;
        let failure = unmap_all_user_data_pages(&root, &mut registry, &mut editor)
            .expect_err("the second page's transient read failure must stop the batch");
        assert_eq!(failure.completed_pages(), 1);
        assert!(!registry.is_mapped(0x4000));
        assert!(registry.is_mapped(0x8000));
        assert_eq!(editor.invalidations, 3);

        // Completed frames are explicitly recoverable from the failure value
        // and can be released after the successful leaf removal/invalidation.
        let mut partial = failure.into_partial_result();
        assert_eq!(partial.completed_pages(), 1);
        let returned_first = partial.take_frame(0).unwrap();
        assert_eq!(returned_first.physical_address(), first_physical);
        assert!(partial.take_frame(0).is_none());
        allocator.free_frame(returned_first).unwrap();

        // The injected failure is one-shot. The remaining mapping and its frame
        // token are still registered and can be removed on a later attempt.
        let mut retry = unmap_all_user_data_pages(&root, &mut registry, &mut editor).unwrap();
        assert_eq!(retry.completed_pages(), 1);
        assert!(!registry.is_mapped(0x4000));
        assert!(!registry.is_mapped(0x8000));
        assert_eq!(registry.available_slots(), 2);
        let returned_second = retry.take_frame(0).unwrap();
        assert_eq!(returned_second.physical_address(), second_physical);
        allocator.free_frame(returned_second).unwrap();
        assert_eq!(editor.invalidations, 4);

        disconnect_test_address_space(&root, &mut editor);
        release_test_page_tables(&mut editor);
        allocator.free_frame(root.into_frame()).unwrap();
        assert_eq!(allocator.stats().allocated_frames, 0);
    }

    #[test]
    fn batch_teardown_preflights_every_page_before_mutating_any_leaf() {
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let (mut allocator, root, first_frame, mut editor) = setup(&mut slots, &mut bitmap);
        let first_physical = first_frame.physical_address();
        let second_frame = allocator.allocate_frame().unwrap();
        let second_physical = second_frame.physical_address();
        editor.register_data_frame(second_physical);

        let mut registry = UserPageMappingRegistry::<ZeroedFrame, 2>::new(&root);
        map_user_data_page(
            &root,
            0x4000,
            initialize_user_frame(first_frame, &mut editor).unwrap(),
            &mut registry,
            &mut editor,
        )
        .unwrap();
        map_user_data_page(
            &root,
            0x8000,
            initialize_user_frame(second_frame, &mut editor).unwrap(),
            &mut registry,
            &mut editor,
        )
        .unwrap();

        // Break the second leaf after both mappings are registered. Batch
        // preflight must detect it before removing the first, valid mapping.
        editor.set_entry(0x4000, 8, 0);
        let failure = unmap_all_user_data_pages(&root, &mut registry, &mut editor)
            .expect_err("batch teardown must reject a registry/table mismatch");
        assert!(matches!(
            failure.error(),
            UserPageMappingError::Translation(_) | UserPageMappingError::MappingInvariantViolation
        ));
        assert_eq!(failure.completed_pages(), 0);
        assert!(registry.is_mapped(0x4000));
        assert!(registry.is_mapped(0x8000));
        assert_eq!(
            editor.invalidations, 2,
            "preflight must not invalidate or mutate"
        );

        editor.set_entry(
            0x4000,
            8,
            second_physical | PRESENT | WRITABLE | (1 << 2) | (1 << 63),
        );
        let mut result = unmap_all_user_data_pages(&root, &mut registry, &mut editor).unwrap();
        assert_eq!(result.completed_pages(), 2);
        let returned_first = result.take_frame(0).unwrap();
        let returned_second = result.take_frame(1).unwrap();
        assert_eq!(returned_first.physical_address(), first_physical);
        assert_eq!(returned_second.physical_address(), second_physical);
        allocator.free_frame(returned_first).unwrap();
        allocator.free_frame(returned_second).unwrap();
        assert_eq!(editor.invalidations, 4);

        disconnect_test_address_space(&root, &mut editor);
        release_test_page_tables(&mut editor);
        allocator.free_frame(root.into_frame()).unwrap();
        assert_eq!(allocator.stats().allocated_frames, 0);
    }

    #[test]
    fn initialize_user_frame_zeroes_old_contents_before_returning_zeroed_token() {
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let (mut allocator, root, frame, mut editor) = setup(&mut slots, &mut bitmap);
        let physical = frame.physical_address();

        assert!(editor
            .frame_contents(physical)
            .iter()
            .any(|byte| *byte != 0));
        let zeroed = initialize_user_frame(frame, &mut editor).unwrap();

        assert_eq!(zeroed.physical_address(), physical);
        assert!(editor
            .frame_contents(physical)
            .iter()
            .all(|byte| *byte == 0));

        allocator.free_frame(zeroed.into_frame()).unwrap();
        disconnect_test_address_space(&root, &mut editor);
        release_test_page_tables(&mut editor);
        allocator.free_frame(root.into_frame()).unwrap();
        assert_eq!(allocator.stats().allocated_frames, 0);
    }

    #[test]
    fn failed_zeroing_returns_the_original_frame_token() {
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let (mut allocator, root, frame, mut editor) = setup(&mut slots, &mut bitmap);
        let physical = frame.physical_address();
        editor.fail_zeroing = true;

        let (error, returned) = initialize_user_frame(frame, &mut editor).unwrap_err();

        assert_eq!(error, UserFrameInitializationError::InitializationFailed);
        assert_eq!(returned.physical_address(), physical);
        assert!(editor
            .frame_contents(physical)
            .iter()
            .any(|byte| *byte != 0));
        allocator.free_frame(returned).unwrap();
        disconnect_test_address_space(&root, &mut editor);
        release_test_page_tables(&mut editor);
        allocator.free_frame(root.into_frame()).unwrap();
        assert_eq!(allocator.stats().allocated_frames, 0);
    }

    #[test]
    fn unmapped_frame_is_reinitialized_before_reuse_in_another_address_space() {
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let (mut allocator, root_a, frame, mut editor) = setup(&mut slots, &mut bitmap);
        let physical = frame.physical_address();
        let virtual_a = 0x4000;
        let virtual_b = 0x8000;

        let root_b_frame = allocator.allocate_frame().unwrap();
        let root_b_physical = root_b_frame.physical_address();
        editor.mark_table_in_use(root_b_physical);
        let mut root_b = AddressSpaceRoot::try_from_frame(root_b_frame, 32).unwrap();
        root_b
            .initialize_from_kernel_root(0x1000, 511, 510, &mut editor)
            .unwrap();

        let mut registry_a = UserPageMappingRegistry::<ZeroedFrame, 2>::new(&root_a);
        let mut registry_b = UserPageMappingRegistry::<ZeroedFrame, 2>::new(&root_b);

        map_user_data_page(
            &root_a,
            virtual_a,
            initialize_user_frame(frame, &mut editor).unwrap(),
            &mut registry_a,
            &mut editor,
        )
        .unwrap();

        let (_, returned_frame) =
            unmap_user_data_page(&root_a, virtual_a, &mut registry_a, &mut editor).unwrap();
        assert_eq!(returned_frame.physical_address(), physical);
        assert!(!registry_a.is_mapped(virtual_a));

        // Model process A having written secret bytes to the user-writable frame.
        editor.fill_frame_contents(physical, 0x5a);
        assert!(editor
            .frame_contents(physical)
            .iter()
            .all(|byte| *byte == 0x5a));

        // Unmap returns only Frame; a new ZeroedFrame requires explicit reinitialization.
        let zeroed_for_b = initialize_user_frame(returned_frame, &mut editor).unwrap();
        assert_eq!(zeroed_for_b.physical_address(), physical);
        assert!(editor
            .frame_contents(physical)
            .iter()
            .all(|byte| *byte == 0));

        map_user_data_page(
            &root_b,
            virtual_b,
            zeroed_for_b,
            &mut registry_b,
            &mut editor,
        )
        .unwrap();
        assert!(registry_b.is_mapped(virtual_b));
        let mut next_level = 4u8;
        let mapped_frame =
            crate::translate_4level(virtual_b, root_b.physical_address(), |table, index| {
                let level = next_level;
                next_level = next_level.saturating_sub(1);
                PageTableEditor::read_entry(&mut editor, table, index, level)
            })
            .unwrap();
        assert_eq!(mapped_frame.physical_address, physical);
        assert!(editor
            .frame_contents(mapped_frame.physical_address)
            .iter()
            .all(|byte| *byte == 0));

        let (_, returned_frame) =
            unmap_user_data_page(&root_b, virtual_b, &mut registry_b, &mut editor).unwrap();
        allocator.free_frame(returned_frame).unwrap();

        disconnect_test_address_space(&root_a, &mut editor);
        disconnect_test_address_space(&root_b, &mut editor);
        release_test_page_tables(&mut editor);
        allocator.free_frame(root_a.into_frame()).unwrap();
        allocator.free_frame(root_b.into_frame()).unwrap();
        assert_eq!(allocator.stats().allocated_frames, 0);
    }

    #[test]
    fn maps_nx_user_data_and_returns_ownership_only_after_unmap_invalidation() {
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let (mut allocator, root, frame, mut editor) = setup(&mut slots, &mut bitmap);
        let physical = frame.physical_address();
        let virtual_address = 0x4000;
        let mut registry = UserPageMappingRegistry::<ZeroedFrame, 2>::new(&root);

        map_user_data_page(
            &root,
            virtual_address,
            initialize_user_frame(frame, &mut editor).unwrap(),
            &mut registry,
            &mut editor,
        )
        .unwrap();

        assert!(registry.is_mapped(virtual_address));
        assert_eq!(registry.available_slots(), 1);
        assert_eq!(editor.invalidations, 1);
        assert_eq!(
            editor.last_invalidation,
            Some((root.physical_address(), virtual_address))
        );

        let (unmapped, returned_frame) =
            unmap_user_data_page(&root, virtual_address, &mut registry, &mut editor).unwrap();
        assert_eq!(unmapped.physical_address, physical);
        assert_eq!(
            unmapped.permissions,
            PagePermissions::new(true, true, false)
        );
        assert_eq!(returned_frame.physical_address(), physical);
        assert!(!registry.is_mapped(virtual_address));
        assert_eq!(registry.available_slots(), 2);
        assert_eq!(editor.invalidations, 2);

        allocator.free_frame(returned_frame).unwrap();
        disconnect_test_address_space(&root, &mut editor);
        release_test_page_tables(&mut editor);
        allocator.free_frame(root.into_frame()).unwrap();
        assert_eq!(allocator.stats().allocated_frames, 0);
    }

    #[test]
    fn allocation_failure_keeps_the_root_and_registry_unchanged_and_returns_frame() {
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let (mut allocator, root, frame, mut editor) = setup(&mut slots, &mut bitmap);
        let physical = frame.physical_address();
        let virtual_address = 0x4000;
        let root_entry_before = editor.entry(root.physical_address(), 0);
        let mut registry = UserPageMappingRegistry::<ZeroedFrame, 1>::new(&root);
        editor.fail_allocation = true;

        let (error, returned_frame) = map_user_data_page(
            &root,
            virtual_address,
            initialize_user_frame(frame, &mut editor).unwrap(),
            &mut registry,
            &mut editor,
        )
        .unwrap_err();

        assert_eq!(
            error,
            UserPageMappingError::PageTable(PageTableMutationError::AllocationFailed)
        );
        assert_eq!(returned_frame.physical_address(), physical);
        assert_eq!(editor.entry(root.physical_address(), 0), root_entry_before);
        assert_eq!(editor.invalidations, 0);
        assert!(!registry.is_mapped(virtual_address));
        assert_eq!(registry.available_slots(), 1);

        allocator.free_frame(returned_frame.into_frame()).unwrap();
        disconnect_test_address_space(&root, &mut editor);
        release_test_page_tables(&mut editor);
        allocator.free_frame(root.into_frame()).unwrap();
        assert_eq!(allocator.stats().allocated_frames, 0);
    }

    #[test]
    fn rejects_duplicate_virtual_mapping_before_page_table_mutation() {
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let (mut allocator, root, frame, mut editor) = setup(&mut slots, &mut bitmap);
        let virtual_address = 0x4000;
        let mut registry = UserPageMappingRegistry::<ZeroedFrame, 2>::new(&root);
        map_user_data_page(
            &root,
            virtual_address,
            initialize_user_frame(frame, &mut editor).unwrap(),
            &mut registry,
            &mut editor,
        )
        .unwrap();

        let second_frame = allocator.allocate_frame().unwrap();
        let second_physical = second_frame.physical_address();
        let error = map_user_data_page(
            &root,
            virtual_address,
            initialize_user_frame(second_frame, &mut editor).unwrap(),
            &mut registry,
            &mut editor,
        )
        .unwrap_err();

        assert_eq!(error.0, UserPageMappingError::DuplicateVirtualAddress);
        assert_eq!(error.1.physical_address(), second_physical);
        assert_eq!(editor.invalidations, 1);
        assert_eq!(registry.available_slots(), 1);

        allocator.free_frame(error.1.into_frame()).unwrap();
        let (_, first_frame) =
            unmap_user_data_page(&root, virtual_address, &mut registry, &mut editor).unwrap();
        allocator.free_frame(first_frame).unwrap();
        disconnect_test_address_space(&root, &mut editor);
        release_test_page_tables(&mut editor);
        allocator.free_frame(root.into_frame()).unwrap();
        assert_eq!(allocator.stats().allocated_frames, 0);
    }

    #[test]
    fn partial_intermediate_table_allocation_failure_rolls_back_every_table() {
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let (mut allocator, root, frame, mut editor) = setup(&mut slots, &mut bitmap);
        let physical = frame.physical_address();
        let virtual_address = 0x4000;
        let root_entry_before = editor.entry(root.physical_address(), 0);
        let mut registry = UserPageMappingRegistry::<ZeroedFrame, 1>::new(&root);
        // Allocate two of the three missing intermediate tables, then fail.
        editor.fail_after_successful_allocations = Some(2);

        let (error, returned_frame) = map_user_data_page(
            &root,
            virtual_address,
            initialize_user_frame(frame, &mut editor).unwrap(),
            &mut registry,
            &mut editor,
        )
        .unwrap_err();

        assert_eq!(
            error,
            UserPageMappingError::PageTable(PageTableMutationError::AllocationFailed)
        );
        assert_eq!(returned_frame.physical_address(), physical);
        assert_eq!(editor.entry(root.physical_address(), 0), root_entry_before);
        assert!(!editor.table_is_in_use(0x2000));
        assert!(!editor.table_is_in_use(0x3000));
        assert!(!editor.table_is_in_use(0x4000));
        assert_eq!(editor.invalidations, 0);
        assert!(!registry.is_mapped(virtual_address));
        assert_eq!(registry.available_slots(), 1);

        allocator.free_frame(returned_frame.into_frame()).unwrap();
        disconnect_test_address_space(&root, &mut editor);
        release_test_page_tables(&mut editor);
        allocator.free_frame(root.into_frame()).unwrap();
        assert_eq!(allocator.stats().allocated_frames, 0);
    }

    #[test]
    fn registry_capacity_exhaustion_returns_frame_before_page_table_mutation() {
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let (mut allocator, root, frame, mut editor) = setup(&mut slots, &mut bitmap);
        let physical = frame.physical_address();
        let virtual_address = 0x4000;
        let root_entry_before = editor.entry(root.physical_address(), 0);
        let mut registry = UserPageMappingRegistry::<ZeroedFrame, 0>::new(&root);

        let (error, returned_frame) = map_user_data_page(
            &root,
            virtual_address,
            initialize_user_frame(frame, &mut editor).unwrap(),
            &mut registry,
            &mut editor,
        )
        .unwrap_err();

        assert_eq!(error, UserPageMappingError::RegistryFull);
        assert_eq!(returned_frame.physical_address(), physical);
        assert_eq!(editor.entry(root.physical_address(), 0), root_entry_before);
        assert_eq!(editor.successful_allocations, 0);
        assert_eq!(editor.invalidations, 0);
        assert!(!registry.is_mapped(virtual_address));

        allocator.free_frame(returned_frame.into_frame()).unwrap();
        disconnect_test_address_space(&root, &mut editor);
        release_test_page_tables(&mut editor);
        allocator.free_frame(root.into_frame()).unwrap();
        assert_eq!(allocator.stats().allocated_frames, 0);
    }

    #[test]
    fn registry_reservation_rejects_duplicate_physical_frame_addresses() {
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let (mut allocator, root, frame, mut editor) = setup(&mut slots, &mut bitmap);
        let physical = frame.physical_address();
        let mut registry = UserPageMappingRegistry::<ZeroedFrame, 2>::new(&root);

        let first = registry.reserve_mapping(0x4000, physical).unwrap();
        assert_eq!(
            registry.reserve_mapping(0x8000, physical),
            Err(UserPageMappingError::DuplicatePhysicalFrame)
        );
        registry.cancel_reservation(first);
        assert_eq!(registry.available_slots(), 2);

        allocator.free_frame(frame).unwrap();
        disconnect_test_address_space(&root, &mut editor);
        release_test_page_tables(&mut editor);
        allocator.free_frame(root.into_frame()).unwrap();
        assert_eq!(allocator.stats().allocated_frames, 0);
    }

    #[test]
    fn rejects_mapping_and_unmapping_through_a_different_root_even_with_same_alias() {
        let mut slots = [FrameSegment::EMPTY; 1];
        let mut bitmap = [0u64; 1];
        let (mut allocator, root_a, frame, mut editor) = setup(&mut slots, &mut bitmap);
        let physical = frame.physical_address();
        let virtual_address = 0x4000;
        let mut registry = UserPageMappingRegistry::<ZeroedFrame, 2>::new(&root_a);
        map_user_data_page(
            &root_a,
            virtual_address,
            initialize_user_frame(frame, &mut editor).unwrap(),
            &mut registry,
            &mut editor,
        )
        .unwrap();

        // Prepare a separate root B, then deliberately create the same
        // virtual-address -> physical-frame alias through the lower-level API.
        let root_b_frame = allocator.allocate_frame().unwrap();
        let root_b_physical = root_b_frame.physical_address();
        editor.mark_table_in_use(root_b_physical);
        let mut root_b = AddressSpaceRoot::try_from_frame(root_b_frame, 32).unwrap();
        root_b
            .initialize_from_kernel_root(0x1000, 511, 510, &mut editor)
            .unwrap();

        // Mapping through the wrong root must return a distinct caller-owned
        // frame unchanged and must not touch either root's page tables.
        let extra_frame = allocator.allocate_frame().unwrap();
        let extra_physical = extra_frame.physical_address();
        let root_b_entry_before = editor.entry(root_b_physical, 0);
        let (map_error, returned_extra) = map_user_data_page(
            &root_b,
            0x8000,
            initialize_user_frame(extra_frame, &mut editor).unwrap(),
            &mut registry,
            &mut editor,
        )
        .unwrap_err();
        assert_eq!(
            map_error,
            UserPageMappingError::AddressSpaceRootMismatch {
                registry_root_physical: root_a.physical_address(),
                supplied_root_physical: root_b_physical,
            }
        );
        assert_eq!(returned_extra.physical_address(), extra_physical);
        assert_eq!(editor.entry(root_b_physical, 0), root_b_entry_before);
        allocator.free_frame(returned_extra.into_frame()).unwrap();

        map_4k(
            root_b_physical,
            virtual_address,
            physical,
            PagePermissions::new(true, true, false),
            &mut editor,
        )
        .unwrap();

        let invalidations_before_wrong_unmap = editor.invalidations;
        assert_eq!(
            unmap_user_data_page(&root_b, virtual_address, &mut registry, &mut editor),
            Err(UserPageMappingError::AddressSpaceRootMismatch {
                registry_root_physical: root_a.physical_address(),
                supplied_root_physical: root_b_physical,
            })
        );
        assert!(registry.is_mapped(virtual_address));
        assert_eq!(registry.available_slots(), 1);
        assert_eq!(editor.invalidations, invalidations_before_wrong_unmap);

        // Confirm B's duplicate alias still exists after the rejected unmap.
        let unmapped_b = unmap_4k(root_b_physical, virtual_address, &mut editor).unwrap();
        assert_eq!(unmapped_b.physical_address, physical);
        editor.invalidate_translation(root_b_physical, virtual_address);

        // Only A's root may detach the token that A's registry owns.
        let (unmapped_a, returned_frame) =
            unmap_user_data_page(&root_a, virtual_address, &mut registry, &mut editor).unwrap();
        assert_eq!(unmapped_a.physical_address, physical);
        assert_eq!(returned_frame.physical_address(), physical);
        assert!(!registry.is_mapped(virtual_address));
        allocator.free_frame(returned_frame).unwrap();

        disconnect_test_address_space(&root_a, &mut editor);
        disconnect_test_address_space(&root_b, &mut editor);
        release_test_page_tables(&mut editor);
        allocator.free_frame(root_a.into_frame()).unwrap();
        allocator.free_frame(root_b.into_frame()).unwrap();
        assert_eq!(allocator.stats().allocated_frames, 0);
    }
}
