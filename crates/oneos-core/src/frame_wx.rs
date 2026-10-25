//! Fixed-capacity accounting for physical-frame-wide writable/executable aliases.
//!
//! This is a policy primitive, not an automatic page-table walker. The kernel
//! must register every relevant alias, including direct-map and large-page
//! aliases, before using it to authorize executable mappings. Until that
//! coverage exists, the concrete kernel editor must continue to deny execution.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::{is_canonical_4level, PAGE_SIZE};

const LOWER_CANONICAL_LIMIT: u64 = 0x0000_8000_0000_0000;
const UPPER_CANONICAL_START: u64 = 0xffff_8000_0000_0000;

static NEXT_REGISTRY_ID: AtomicU64 = AtomicU64::new(1);

fn allocate_registry_id() -> Option<u64> {
    NEXT_REGISTRY_ID
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .ok()
}

/// Effective write/execute permissions for one physical alias range.
///
/// Read permission is implicit. W^X is enforced across aliases, not just within
/// this value: a writable alias and an executable alias of overlapping physical
/// bytes may not be reserved at the same time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameWxPermissions {
    /// Whether an access through this alias can write to memory.
    pub writable: bool,
    /// Whether an access through this alias can fetch instructions.
    pub executable: bool,
}

impl FrameWxPermissions {
    /// Constructs an alias permission request.
    pub const fn new(writable: bool, executable: bool) -> Self {
        Self {
            writable,
            executable,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SlotState {
    Empty,
    Reserved,
    Published,
    Retiring,
}

#[derive(Clone, Copy, Debug)]
struct AliasRecord {
    registry_id: u64,
    generation: u64,
    state: SlotState,
    root_physical: u64,
    virtual_start: u64,
    physical_start: u64,
    length: u64,
    permissions: FrameWxPermissions,
}

impl AliasRecord {
    const EMPTY: Self = Self {
        registry_id: 0,
        generation: 0,
        state: SlotState::Empty,
        root_physical: 0,
        virtual_start: 0,
        physical_start: 0,
        length: 0,
        permissions: FrameWxPermissions::new(false, false),
    };

    fn physical_end(self) -> u64 {
        // Ranges are checked and stored only by reserve_alias_range.
        self.physical_start + self.length
    }

    fn virtual_end(self) -> u64 {
        // Ranges are checked and stored only by reserve_alias_range.
        self.virtual_start + self.length
    }

    fn is_occupied(self) -> bool {
        self.state != SlotState::Empty
    }
}

/// Error returned by the physical-frame-wide W^X alias registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameWxError {
    /// MAXPHYADDR is outside the kernel's supported 32..=52-bit range.
    InvalidPhysicalAddressWidth,
    /// A root physical address is zero, unaligned, or outside MAXPHYADDR.
    InvalidRootAddress,
    /// A virtual range is empty, unaligned, overflowing, non-canonical, or
    /// crosses between the lower and upper canonical halves.
    InvalidVirtualRange,
    /// A physical range is empty, unaligned, overflowing, or outside MAXPHYADDR.
    InvalidPhysicalRange,
    /// A queried physical frame is unaligned or lies outside MAXPHYADDR.
    InvalidPhysicalFrameAddress,
    /// One alias itself requests both writable and executable permissions.
    WritableExecutableAlias,
    /// The root already has an overlapping virtual mapping in the registry.
    VirtualAliasConflict,
    /// Another registered, reserved, or retiring alias has conflicting W^X rights.
    PhysicalAliasWxConflict,
    /// No empty registry slot is available.
    CapacityExhausted,
    /// A registry identity or reservation generation could not be advanced safely.
    IdentifierExhausted,
    /// The supplied token does not identify a live reservation in this registry.
    InvalidReservation,
    /// No published alias exists for the specified root and virtual start.
    AliasNotFound,
    /// The matching alias exists but has not been published.
    AliasNotPublished,
    /// The matching alias is already being retired.
    AliasAlreadyRetiring,
}

impl FrameWxError {
    /// Allocation-free diagnostic text for callers that need to report a denial.
    pub const fn message(self) -> &'static [u8] {
        match self {
            Self::InvalidPhysicalAddressWidth => {
                b"W^X registry received an unsupported physical-address width\n"
            }
            Self::InvalidRootAddress => b"W^X registry rejected an invalid root address\n",
            Self::InvalidVirtualRange => b"W^X registry rejected an invalid virtual range\n",
            Self::InvalidPhysicalRange => b"W^X registry rejected an invalid physical range\n",
            Self::InvalidPhysicalFrameAddress => {
                b"W^X registry rejected an invalid physical frame query\n"
            }
            Self::WritableExecutableAlias => b"W^X registry rejected a writable executable alias\n",
            Self::VirtualAliasConflict => b"W^X registry rejected overlapping virtual aliases\n",
            Self::PhysicalAliasWxConflict => {
                b"W^X registry rejected conflicting physical aliases\n"
            }
            Self::CapacityExhausted => b"W^X alias registry capacity exhausted\n",
            Self::IdentifierExhausted => b"W^X alias registry identifier exhausted\n",
            Self::InvalidReservation => b"W^X alias registry reservation is invalid\n",
            Self::AliasNotFound => b"W^X alias registry mapping was not found\n",
            Self::AliasNotPublished => b"W^X alias registry mapping is not published\n",
            Self::AliasAlreadyRetiring => b"W^X alias registry mapping is already retiring\n",
        }
    }
}

/// Token for a reserved alias. It is intentionally neither Copy nor Clone.
#[must_use = "a W^X reservation must be committed or cancelled"]
#[derive(Debug)]
pub struct FrameWxReservation {
    registry_id: u64,
    slot: usize,
    generation: u64,
}

/// Token for an alias whose page-table entry has been removed but whose TLB
/// invalidation/reclamation contract has not yet been acknowledged by the caller.
#[must_use = "a retiring W^X alias must be completed or restored"]
#[derive(Debug)]
pub struct FrameWxRemoval {
    registry_id: u64,
    slot: usize,
    generation: u64,
}

/// A failed reservation operation that retains ownership of the reservation token.
///
/// The token can be recovered with into_parts and passed to the registry that
/// originally issued it, so a wrong-registry call does not strand a reserved slot.
#[must_use = "recover the reservation token from this error before retrying or cancelling"]
#[derive(Debug)]
pub struct FrameWxReservationError {
    error: FrameWxError,
    reservation: FrameWxReservation,
}

impl FrameWxReservationError {
    /// Returns the failure reason without consuming the token.
    pub const fn error(&self) -> FrameWxError {
        self.error
    }

    /// Returns both the failure reason and the original reservation token.
    pub fn into_parts(self) -> (FrameWxError, FrameWxReservation) {
        (self.error, self.reservation)
    }
}

/// A failed removal operation that retains ownership of the removal token.
#[must_use = "recover the removal token from this error before retrying or restoring"]
#[derive(Debug)]
pub struct FrameWxRemovalError {
    error: FrameWxError,
    removal: FrameWxRemoval,
}

impl FrameWxRemovalError {
    /// Returns the failure reason without consuming the token.
    pub const fn error(&self) -> FrameWxError {
        self.error
    }

    /// Returns both the failure reason and the original removal token.
    pub fn into_parts(self) -> (FrameWxError, FrameWxRemoval) {
        (self.error, self.removal)
    }
}

/// Fixed-capacity registry of physical aliases used to enforce frame-wide W^X.
///
/// Each record represents a contiguous physical/virtual range for one address
/// space. A 4 KiB mapping is represented by a 4 KiB range; a 2 MiB or 1 GiB
/// mapping can be represented by its complete range so that a 4 KiB alias
/// overlapping any part of a large mapping is detected.
///
/// Reservations participate in conflict checks before a PTE is published.
/// Retiring mappings continue to participate in conflict checks until the caller
/// confirms that page-table removal and all required TLB invalidation are complete.
///
/// # Security contract
///
/// This data structure does not discover aliases in hardware. The kernel must
/// account for all boot mappings, the physical-memory-offset/direct-map alias,
/// kernel mappings, every address space, and overlapping large pages before the
/// registry can authorize executable publication. Unknown aliases must keep the
/// kernel's executable-mapping policy fail-closed.
#[derive(Debug)]
pub struct FrameWxRegistry<const CAPACITY: usize> {
    registry_id: u64,
    physical_address_bits: u8,
    next_generation: u64,
    slots: [AliasRecord; CAPACITY],
}

impl<const CAPACITY: usize> FrameWxRegistry<CAPACITY> {
    /// Creates an empty registry for a processor with the supplied MAXPHYADDR.
    pub fn new(physical_address_bits: u8) -> Result<Self, FrameWxError> {
        if !(32..=52).contains(&physical_address_bits) {
            return Err(FrameWxError::InvalidPhysicalAddressWidth);
        }
        let registry_id = allocate_registry_id().ok_or(FrameWxError::IdentifierExhausted)?;
        Ok(Self {
            registry_id,
            physical_address_bits,
            next_generation: 1,
            slots: [AliasRecord::EMPTY; CAPACITY],
        })
    }

    /// Reserves one physical alias range before its page-table mapping is published.
    ///
    /// Length must be a nonzero multiple of 4 KiB. For a large-page alias, pass
    /// the complete physical extent (2 MiB or 1 GiB), not just its first frame.
    /// The caller must commit the reservation only after the mapping is published;
    /// on pre-publication failure it must cancel the reservation.
    pub fn reserve_alias_range(
        &mut self,
        root_physical: u64,
        virtual_start: u64,
        physical_start: u64,
        length: u64,
        permissions: FrameWxPermissions,
    ) -> Result<FrameWxReservation, FrameWxError> {
        self.validate_root(root_physical)?;
        validate_virtual_range(virtual_start, length)?;
        self.validate_physical_range(physical_start, length)?;

        if permissions.writable && permissions.executable {
            return Err(FrameWxError::WritableExecutableAlias);
        }

        let physical_end = physical_start + length;
        let virtual_end = virtual_start + length;
        for record in self
            .slots
            .iter()
            .copied()
            .filter(|record| record.is_occupied())
        {
            if record.root_physical == root_physical
                && ranges_overlap(
                    virtual_start,
                    virtual_end,
                    record.virtual_start,
                    record.virtual_end(),
                )
            {
                return Err(FrameWxError::VirtualAliasConflict);
            }

            let physical_overlap = ranges_overlap(
                physical_start,
                physical_end,
                record.physical_start,
                record.physical_end(),
            );
            let wx_conflict = (permissions.writable && record.permissions.executable)
                || (permissions.executable && record.permissions.writable);
            if physical_overlap && wx_conflict {
                return Err(FrameWxError::PhysicalAliasWxConflict);
            }
        }

        let slot = self
            .slots
            .iter()
            .position(|record| !record.is_occupied())
            .ok_or(FrameWxError::CapacityExhausted)?;
        let generation = self.next_generation;
        self.next_generation = generation
            .checked_add(1)
            .ok_or(FrameWxError::IdentifierExhausted)?;

        self.slots[slot] = AliasRecord {
            registry_id: self.registry_id,
            generation,
            state: SlotState::Reserved,
            root_physical,
            virtual_start,
            physical_start,
            length,
            permissions,
        };

        Ok(FrameWxReservation {
            registry_id: self.registry_id,
            slot,
            generation,
        })
    }

    /// Commits a reservation after the corresponding PTE/range is published.
    ///
    /// On failure, the error retains the token so the issuing registry can retry.
    pub fn commit_alias(
        &mut self,
        reservation: FrameWxReservation,
    ) -> Result<(), FrameWxReservationError> {
        let record = match self.validate_token(
            reservation.registry_id,
            reservation.slot,
            reservation.generation,
            SlotState::Reserved,
        ) {
            Ok(record) => record,
            Err(error) => return Err(FrameWxReservationError { error, reservation }),
        };
        self.slots[reservation.slot] = AliasRecord {
            state: SlotState::Published,
            ..record
        };
        Ok(())
    }

    /// Cancels a reservation only when the corresponding alias was not published.
    ///
    /// On failure, the error retains the token so the issuing registry can retry.
    pub fn cancel_alias(
        &mut self,
        reservation: FrameWxReservation,
    ) -> Result<(), FrameWxReservationError> {
        if let Err(error) = self.validate_token(
            reservation.registry_id,
            reservation.slot,
            reservation.generation,
            SlotState::Reserved,
        ) {
            return Err(FrameWxReservationError { error, reservation });
        }
        self.slots[reservation.slot] = AliasRecord::EMPTY;
        Ok(())
    }

    /// Marks a published mapping as retiring before removing its page-table entry.
    ///
    /// The alias continues to block conflicting W^X mappings in this state.
    /// Call complete_removal only after the PTE is detached and the required TLB
    /// invalidation completes. If unmapping fails before that point, call
    /// cancel_removal to restore the published state.
    pub fn begin_removal(
        &mut self,
        root_physical: u64,
        virtual_start: u64,
    ) -> Result<FrameWxRemoval, FrameWxError> {
        self.validate_root(root_physical)?;
        if virtual_start & (PAGE_SIZE - 1) != 0 || !is_canonical_4level(virtual_start) {
            return Err(FrameWxError::InvalidVirtualRange);
        }

        let Some(slot) = self.slots.iter().position(|record| {
            record.is_occupied()
                && record.root_physical == root_physical
                && record.virtual_start == virtual_start
        }) else {
            return Err(FrameWxError::AliasNotFound);
        };
        let record = self.slots[slot];
        match record.state {
            SlotState::Published => {
                self.slots[slot] = AliasRecord {
                    state: SlotState::Retiring,
                    ..record
                };
                Ok(FrameWxRemoval {
                    registry_id: self.registry_id,
                    slot,
                    generation: record.generation,
                })
            }
            SlotState::Reserved => Err(FrameWxError::AliasNotPublished),
            SlotState::Retiring => Err(FrameWxError::AliasAlreadyRetiring),
            SlotState::Empty => Err(FrameWxError::AliasNotFound),
        }
    }

    /// Restores a retiring alias when the corresponding unmap operation failed.
    ///
    /// On failure, the error retains the token so the issuing registry can retry.
    pub fn cancel_removal(
        &mut self,
        removal: FrameWxRemoval,
    ) -> Result<(), FrameWxRemovalError> {
        let record = match self.validate_token(
            removal.registry_id,
            removal.slot,
            removal.generation,
            SlotState::Retiring,
        ) {
            Ok(record) => record,
            Err(error) => return Err(FrameWxRemovalError { error, removal }),
        };
        self.slots[removal.slot] = AliasRecord {
            state: SlotState::Published,
            ..record
        };
        Ok(())
    }

    /// Removes a retiring alias after PTE detachment and TLB invalidation complete.
    ///
    /// On failure, the error retains the token so the issuing registry can retry.
    pub fn complete_removal(
        &mut self,
        removal: FrameWxRemoval,
    ) -> Result<(), FrameWxRemovalError> {
        if let Err(error) = self.validate_token(
            removal.registry_id,
            removal.slot,
            removal.generation,
            SlotState::Retiring,
        ) {
            return Err(FrameWxRemovalError { error, removal });
        }
        self.slots[removal.slot] = AliasRecord::EMPTY;
        Ok(())
    }

    /// Returns whether a registered alias overlapping this frame is writable.
    ///
    /// Rejects invalid query input rather than conflating it with a valid no-alias result.
    pub fn frame_has_writable_alias(
        &self,
        physical_frame: u64,
    ) -> Result<bool, FrameWxError> {
        self.validate_physical_frame(physical_frame)?;
        Ok(self.slots.iter().any(|record| {
            record.is_occupied()
                && record.permissions.writable
                && physical_frame >= record.physical_start
                && physical_frame < record.physical_end()
        }))
    }

    /// Returns whether a registered alias overlapping this frame is executable.
    ///
    /// Rejects invalid query input rather than conflating it with a valid no-alias result.
    pub fn frame_has_executable_alias(
        &self,
        physical_frame: u64,
    ) -> Result<bool, FrameWxError> {
        self.validate_physical_frame(physical_frame)?;
        Ok(self.slots.iter().any(|record| {
            record.is_occupied()
                && record.permissions.executable
                && physical_frame >= record.physical_start
                && physical_frame < record.physical_end()
        }))
    }

    /// Number of occupied records, including reservations and retiring aliases.
    pub fn occupied_slots(&self) -> usize {
        self.slots
            .iter()
            .filter(|record| record.is_occupied())
            .count()
    }

    /// Number of published aliases that have not started removal.
    pub fn published_aliases(&self) -> usize {
        self.slots
            .iter()
            .filter(|record| record.state == SlotState::Published)
            .count()
    }

    /// Whether any alias is reserved but not yet committed.
    pub fn has_pending_reservations(&self) -> bool {
        self.slots
            .iter()
            .any(|record| record.state == SlotState::Reserved)
    }

    fn validate_physical_frame(&self, physical_frame: u64) -> Result<(), FrameWxError> {
        let maximum_address = 1u64 << self.physical_address_bits;
        if physical_frame & (PAGE_SIZE - 1) != 0 || physical_frame >= maximum_address {
            return Err(FrameWxError::InvalidPhysicalFrameAddress);
        }
        Ok(())
    }

    fn validate_root(&self, root_physical: u64) -> Result<(), FrameWxError> {
        let maximum_address = 1u64 << self.physical_address_bits;
        if root_physical == 0
            || root_physical & (PAGE_SIZE - 1) != 0
            || root_physical >= maximum_address
        {
            return Err(FrameWxError::InvalidRootAddress);
        }
        Ok(())
    }

    fn validate_physical_range(
        &self,
        physical_start: u64,
        length: u64,
    ) -> Result<(), FrameWxError> {
        let maximum_address = 1u64 << self.physical_address_bits;
        if physical_start & (PAGE_SIZE - 1) != 0
            || length == 0
            || length & (PAGE_SIZE - 1) != 0
            || physical_start
                .checked_add(length)
                .filter(|end| *end <= maximum_address)
                .is_none()
        {
            return Err(FrameWxError::InvalidPhysicalRange);
        }
        Ok(())
    }

    fn validate_token(
        &self,
        registry_id: u64,
        slot: usize,
        generation: u64,
        expected_state: SlotState,
    ) -> Result<AliasRecord, FrameWxError> {
        if registry_id != self.registry_id || slot >= CAPACITY {
            return Err(FrameWxError::InvalidReservation);
        }
        let record = self.slots[slot];
        if record.registry_id != registry_id
            || record.generation != generation
            || record.state != expected_state
        {
            return Err(FrameWxError::InvalidReservation);
        }
        Ok(record)
    }
}

fn validate_virtual_range(virtual_start: u64, length: u64) -> Result<(), FrameWxError> {
    if virtual_start & (PAGE_SIZE - 1) != 0 || length == 0 || length & (PAGE_SIZE - 1) != 0 {
        return Err(FrameWxError::InvalidVirtualRange);
    }
    let end = virtual_start
        .checked_add(length)
        .ok_or(FrameWxError::InvalidVirtualRange)?;
    let last = end
        .checked_sub(1)
        .ok_or(FrameWxError::InvalidVirtualRange)?;
    if !is_canonical_4level(virtual_start) || !is_canonical_4level(last) {
        return Err(FrameWxError::InvalidVirtualRange);
    }

    let stays_in_canonical_half = if virtual_start < LOWER_CANONICAL_LIMIT {
        last < LOWER_CANONICAL_LIMIT
    } else {
        virtual_start >= UPPER_CANONICAL_START && last >= UPPER_CANONICAL_START
    };
    if !stays_in_canonical_half {
        return Err(FrameWxError::InvalidVirtualRange);
    }
    Ok(())
}

fn ranges_overlap(first_start: u64, first_end: u64, second_start: u64, second_end: u64) -> bool {
    first_start < second_end && second_start < first_end
}

#[cfg(test)]
mod tests {
    use super::{
        FrameWxError, FrameWxPermissions, FrameWxRegistry, LOWER_CANONICAL_LIMIT,
        UPPER_CANONICAL_START,
    };
    use crate::PAGE_SIZE;

    const ROOT_A: u64 = 0x1000;
    const ROOT_B: u64 = 0x2000;
    const VA_A: u64 = 0x4000;
    const VA_B: u64 = 0x8000;
    const FRAME_A: u64 = 0x20_000;
    const FRAME_B: u64 = 0x30_000;
    const TWO_MIB: u64 = 1 << 21;
    const ONE_GIB: u64 = 1 << 30;

    fn add<const N: usize>(
        registry: &mut FrameWxRegistry<N>,
        root: u64,
        virtual_start: u64,
        physical_start: u64,
        length: u64,
        permissions: FrameWxPermissions,
    ) {
        let reservation = registry
            .reserve_alias_range(root, virtual_start, physical_start, length, permissions)
            .unwrap();
        registry.commit_alias(reservation).unwrap();
    }

    #[test]
    fn rejects_an_alias_that_is_both_writable_and_executable() {
        let mut registry = FrameWxRegistry::<4>::new(48).unwrap();
        assert_eq!(
            registry
                .reserve_alias_range(
                    ROOT_A,
                    VA_A,
                    FRAME_A,
                    PAGE_SIZE,
                    FrameWxPermissions::new(true, true),
                )
                .unwrap_err(),
            FrameWxError::WritableExecutableAlias
        );
        assert_eq!(registry.occupied_slots(), 0);
    }

    #[test]
    fn writable_alias_blocks_executable_alias_in_another_address_space() {
        let mut registry = FrameWxRegistry::<4>::new(48).unwrap();
        add(
            &mut registry,
            ROOT_A,
            VA_A,
            FRAME_A,
            PAGE_SIZE,
            FrameWxPermissions::new(true, false),
        );

        assert_eq!(
            registry
                .reserve_alias_range(
                    ROOT_B,
                    VA_B,
                    FRAME_A,
                    PAGE_SIZE,
                    FrameWxPermissions::new(false, true),
                )
                .unwrap_err(),
            FrameWxError::PhysicalAliasWxConflict
        );
    }

    #[test]
    fn executable_alias_blocks_writable_alias_in_the_reverse_order() {
        let mut registry = FrameWxRegistry::<4>::new(48).unwrap();
        add(
            &mut registry,
            ROOT_A,
            VA_A,
            FRAME_A,
            PAGE_SIZE,
            FrameWxPermissions::new(false, true),
        );

        assert_eq!(
            registry
                .reserve_alias_range(
                    ROOT_B,
                    VA_B,
                    FRAME_A,
                    PAGE_SIZE,
                    FrameWxPermissions::new(true, false),
                )
                .unwrap_err(),
            FrameWxError::PhysicalAliasWxConflict
        );
    }

    #[test]
    fn large_page_range_blocks_conflicting_subpage_aliases() {
        let mut registry = FrameWxRegistry::<8>::new(48).unwrap();
        let large_physical = 0x20_0000;
        add(
            &mut registry,
            ROOT_A,
            0x20_0000,
            large_physical,
            TWO_MIB,
            FrameWxPermissions::new(true, false),
        );

        assert_eq!(
            registry
                .reserve_alias_range(
                    ROOT_B,
                    VA_A,
                    large_physical + 17 * PAGE_SIZE,
                    PAGE_SIZE,
                    FrameWxPermissions::new(false, true),
                )
                .unwrap_err(),
            FrameWxError::PhysicalAliasWxConflict
        );

        // A subpage just outside the large-page physical extent is unrelated.
        add(
            &mut registry,
            ROOT_B,
            VA_B,
            large_physical + TWO_MIB,
            PAGE_SIZE,
            FrameWxPermissions::new(false, true),
        );
    }

    #[test]
    fn tracks_physical_frame_zero_and_enforces_wx_in_both_orders() {
        let mut writable_first = FrameWxRegistry::<4>::new(48).unwrap();
        add(
            &mut writable_first,
            ROOT_A,
            VA_A,
            0,
            PAGE_SIZE,
            FrameWxPermissions::new(true, false),
        );
        assert!(writable_first.frame_has_writable_alias(0).unwrap());
        assert!(!writable_first.frame_has_executable_alias(0).unwrap());
        assert_eq!(
            writable_first
                .reserve_alias_range(
                    ROOT_B,
                    VA_B,
                    0,
                    PAGE_SIZE,
                    FrameWxPermissions::new(false, true),
                )
                .unwrap_err(),
            FrameWxError::PhysicalAliasWxConflict
        );

        let mut executable_first = FrameWxRegistry::<4>::new(48).unwrap();
        add(
            &mut executable_first,
            ROOT_A,
            VA_A,
            0,
            PAGE_SIZE,
            FrameWxPermissions::new(false, true),
        );
        assert!(executable_first.frame_has_executable_alias(0).unwrap());
        assert!(!executable_first.frame_has_writable_alias(0).unwrap());
        assert_eq!(
            executable_first
                .reserve_alias_range(
                    ROOT_B,
                    VA_B,
                    0,
                    PAGE_SIZE,
                    FrameWxPermissions::new(true, false),
                )
                .unwrap_err(),
            FrameWxError::PhysicalAliasWxConflict
        );
    }

    #[test]
    fn alias_queries_reject_unaligned_and_out_of_range_frame_addresses() {
        let registry = FrameWxRegistry::<4>::new(48).unwrap();
        for physical_frame in [1, 1u64 << 48] {
            assert_eq!(
                registry.frame_has_writable_alias(physical_frame),
                Err(FrameWxError::InvalidPhysicalFrameAddress)
            );
            assert_eq!(
                registry.frame_has_executable_alias(physical_frame),
                Err(FrameWxError::InvalidPhysicalFrameAddress)
            );
        }

        assert_eq!(registry.frame_has_writable_alias(0), Ok(false));
        assert_eq!(registry.frame_has_executable_alias(0), Ok(false));
    }

    #[test]
    fn wrong_registry_reservation_errors_retain_the_token() {
        let mut owner = FrameWxRegistry::<4>::new(48).unwrap();
        let mut other = FrameWxRegistry::<4>::new(48).unwrap();

        let reservation = owner
            .reserve_alias_range(
                ROOT_A,
                VA_A,
                FRAME_A,
                PAGE_SIZE,
                FrameWxPermissions::new(true, false),
            )
            .unwrap();
        let error = other.commit_alias(reservation).unwrap_err();
        assert_eq!(error.error(), FrameWxError::InvalidReservation);
        assert_eq!(other.occupied_slots(), 0);
        assert_eq!(owner.occupied_slots(), 1);
        let (reason, reservation) = error.into_parts();
        assert_eq!(reason, FrameWxError::InvalidReservation);
        owner.commit_alias(reservation).unwrap();
        assert_eq!(owner.published_aliases(), 1);

        let reservation = owner
            .reserve_alias_range(
                ROOT_A,
                VA_B,
                FRAME_B,
                PAGE_SIZE,
                FrameWxPermissions::new(false, false),
            )
            .unwrap();
        let error = other.cancel_alias(reservation).unwrap_err();
        assert_eq!(error.error(), FrameWxError::InvalidReservation);
        let (reason, reservation) = error.into_parts();
        assert_eq!(reason, FrameWxError::InvalidReservation);
        owner.cancel_alias(reservation).unwrap();
        assert_eq!(owner.occupied_slots(), 1);
        assert_eq!(other.occupied_slots(), 0);
    }

    #[test]
    fn wrong_registry_removal_errors_retain_the_token() {
        let mut owner = FrameWxRegistry::<4>::new(48).unwrap();
        let mut other = FrameWxRegistry::<4>::new(48).unwrap();
        add(
            &mut owner,
            ROOT_A,
            VA_A,
            FRAME_A,
            PAGE_SIZE,
            FrameWxPermissions::new(true, false),
        );

        let removal = owner.begin_removal(ROOT_A, VA_A).unwrap();
        let error = other.cancel_removal(removal).unwrap_err();
        assert_eq!(error.error(), FrameWxError::InvalidReservation);
        assert_eq!(other.occupied_slots(), 0);
        assert_eq!(owner.occupied_slots(), 1);
        let (reason, removal) = error.into_parts();
        assert_eq!(reason, FrameWxError::InvalidReservation);
        owner.cancel_removal(removal).unwrap();
        assert_eq!(owner.published_aliases(), 1);

        let removal = owner.begin_removal(ROOT_A, VA_A).unwrap();
        let error = other.complete_removal(removal).unwrap_err();
        assert_eq!(error.error(), FrameWxError::InvalidReservation);
        let (reason, removal) = error.into_parts();
        assert_eq!(reason, FrameWxError::InvalidReservation);
        owner.complete_removal(removal).unwrap();
        assert_eq!(owner.occupied_slots(), 0);
        assert_eq!(other.occupied_slots(), 0);
    }

    #[test]
    fn one_gib_alias_range_is_checked_for_a_subpage_overlap() {
        let mut registry = FrameWxRegistry::<4>::new(48).unwrap();
        let large_physical = 1u64 << 32;
        add(
            &mut registry,
            ROOT_A,
            UPPER_CANONICAL_START,
            large_physical,
            ONE_GIB,
            FrameWxPermissions::new(false, true),
        );

        assert_eq!(
            registry
                .reserve_alias_range(
                    ROOT_B,
                    VA_A,
                    large_physical + ONE_GIB - PAGE_SIZE,
                    PAGE_SIZE,
                    FrameWxPermissions::new(true, false),
                )
                .unwrap_err(),
            FrameWxError::PhysicalAliasWxConflict
        );
    }

    #[test]
    fn reserved_aliases_participate_in_conflict_checks_before_publication() {
        let mut registry = FrameWxRegistry::<4>::new(48).unwrap();
        let reservation = registry
            .reserve_alias_range(
                ROOT_A,
                VA_A,
                FRAME_A,
                PAGE_SIZE,
                FrameWxPermissions::new(true, false),
            )
            .unwrap();

        assert!(registry.has_pending_reservations());
        assert_eq!(
            registry
                .reserve_alias_range(
                    ROOT_B,
                    VA_B,
                    FRAME_A,
                    PAGE_SIZE,
                    FrameWxPermissions::new(false, true),
                )
                .unwrap_err(),
            FrameWxError::PhysicalAliasWxConflict
        );
        registry.cancel_alias(reservation).unwrap();
        assert_eq!(registry.occupied_slots(), 0);
    }

    #[test]
    fn retiring_alias_keeps_blocking_until_removal_and_tlb_completion() {
        let mut registry = FrameWxRegistry::<4>::new(48).unwrap();
        add(
            &mut registry,
            ROOT_A,
            VA_A,
            FRAME_A,
            PAGE_SIZE,
            FrameWxPermissions::new(true, false),
        );
        let removal = registry.begin_removal(ROOT_A, VA_A).unwrap();

        assert_eq!(registry.published_aliases(), 0);
        assert_eq!(registry.occupied_slots(), 1);
        assert_eq!(
            registry
                .reserve_alias_range(
                    ROOT_B,
                    VA_B,
                    FRAME_A,
                    PAGE_SIZE,
                    FrameWxPermissions::new(false, true),
                )
                .unwrap_err(),
            FrameWxError::PhysicalAliasWxConflict
        );

        registry.complete_removal(removal).unwrap();
        add(
            &mut registry,
            ROOT_B,
            VA_B,
            FRAME_A,
            PAGE_SIZE,
            FrameWxPermissions::new(false, true),
        );
    }

    #[test]
    fn failed_unmap_can_restore_the_published_alias() {
        let mut registry = FrameWxRegistry::<4>::new(48).unwrap();
        add(
            &mut registry,
            ROOT_A,
            VA_A,
            FRAME_A,
            PAGE_SIZE,
            FrameWxPermissions::new(true, false),
        );
        let removal = registry.begin_removal(ROOT_A, VA_A).unwrap();
        registry.cancel_removal(removal).unwrap();

        assert_eq!(registry.published_aliases(), 1);
        assert!(registry.frame_has_writable_alias(FRAME_A).unwrap());
        assert_eq!(
            registry
                .reserve_alias_range(
                    ROOT_B,
                    VA_B,
                    FRAME_A,
                    PAGE_SIZE,
                    FrameWxPermissions::new(false, true),
                )
                .unwrap_err(),
            FrameWxError::PhysicalAliasWxConflict
        );
    }

    #[test]
    fn read_only_aliases_can_coexist_with_writable_or_executable_aliases() {
        let mut registry = FrameWxRegistry::<6>::new(48).unwrap();
        add(
            &mut registry,
            ROOT_A,
            VA_A,
            FRAME_A,
            PAGE_SIZE,
            FrameWxPermissions::new(false, false),
        );
        add(
            &mut registry,
            ROOT_B,
            VA_B,
            FRAME_A,
            PAGE_SIZE,
            FrameWxPermissions::new(true, false),
        );
        assert!(registry.frame_has_writable_alias(FRAME_A).unwrap());
        assert!(!registry.frame_has_executable_alias(FRAME_A).unwrap());

        add(
            &mut registry,
            ROOT_A,
            VA_B,
            FRAME_A,
            PAGE_SIZE,
            FrameWxPermissions::new(false, false),
        );

        let removal = registry.begin_removal(ROOT_B, VA_B).unwrap();
        registry.complete_removal(removal).unwrap();
        add(
            &mut registry,
            ROOT_B,
            VA_B,
            FRAME_A,
            PAGE_SIZE,
            FrameWxPermissions::new(false, true),
        );
        assert!(registry.frame_has_executable_alias(FRAME_A).unwrap());
        assert!(!registry.frame_has_writable_alias(FRAME_A).unwrap());
    }

    #[test]
    fn rejects_overlapping_virtual_ranges_within_one_root() {
        let mut registry = FrameWxRegistry::<4>::new(48).unwrap();
        add(
            &mut registry,
            ROOT_A,
            VA_A,
            FRAME_A,
            TWO_MIB,
            FrameWxPermissions::new(false, false),
        );

        assert_eq!(
            registry
                .reserve_alias_range(
                    ROOT_A,
                    VA_A + PAGE_SIZE,
                    FRAME_B,
                    PAGE_SIZE,
                    FrameWxPermissions::new(false, false),
                )
                .unwrap_err(),
            FrameWxError::VirtualAliasConflict
        );
    }

    #[test]
    fn accepts_adjacent_non_overlapping_virtual_and_physical_ranges() {
        let mut registry = FrameWxRegistry::<4>::new(48).unwrap();
        add(
            &mut registry,
            ROOT_A,
            VA_A,
            FRAME_A,
            PAGE_SIZE,
            FrameWxPermissions::new(true, false),
        );
        add(
            &mut registry,
            ROOT_A,
            VA_A + PAGE_SIZE,
            FRAME_A + PAGE_SIZE,
            PAGE_SIZE,
            FrameWxPermissions::new(false, true),
        );
    }

    #[test]
    fn registry_capacity_exhaustion_does_not_evict_existing_aliases() {
        let mut registry = FrameWxRegistry::<1>::new(48).unwrap();
        add(
            &mut registry,
            ROOT_A,
            VA_A,
            FRAME_A,
            PAGE_SIZE,
            FrameWxPermissions::new(false, false),
        );
        assert_eq!(
            registry
                .reserve_alias_range(
                    ROOT_B,
                    VA_B,
                    FRAME_B,
                    PAGE_SIZE,
                    FrameWxPermissions::new(false, false),
                )
                .unwrap_err(),
            FrameWxError::CapacityExhausted
        );
        assert_eq!(registry.occupied_slots(), 1);
    }

    #[test]
    fn rejects_invalid_roots_ranges_widths_and_physical_overflow() {
        assert!(matches!(
            FrameWxRegistry::<4>::new(53),
            Err(FrameWxError::InvalidPhysicalAddressWidth)
        ));
        let mut registry = FrameWxRegistry::<4>::new(48).unwrap();
        for root in [0, ROOT_A + 1, 1u64 << 48] {
            assert_eq!(
                registry
                    .reserve_alias_range(
                        root,
                        VA_A,
                        FRAME_A,
                        PAGE_SIZE,
                        FrameWxPermissions::new(false, false),
                    )
                    .unwrap_err(),
                FrameWxError::InvalidRootAddress
            );
        }
        for (va, len) in [
            (VA_A + 1, PAGE_SIZE),
            (LOWER_CANONICAL_LIMIT - PAGE_SIZE, 2 * PAGE_SIZE),
            (UPPER_CANONICAL_START - PAGE_SIZE, 2 * PAGE_SIZE),
            (!(PAGE_SIZE - 1), 2 * PAGE_SIZE),
            (VA_A, 0),
            (VA_A, PAGE_SIZE + 1),
        ] {
            assert_eq!(
                registry
                    .reserve_alias_range(
                        ROOT_A,
                        va,
                        FRAME_A,
                        len,
                        FrameWxPermissions::new(false, false),
                    )
                    .unwrap_err(),
                FrameWxError::InvalidVirtualRange
            );
        }
        for (physical, len) in [
            (FRAME_A + 1, PAGE_SIZE),
            ((1u64 << 48) - PAGE_SIZE, 2 * PAGE_SIZE),
        ] {
            assert_eq!(
                registry
                    .reserve_alias_range(
                        ROOT_A,
                        VA_A,
                        physical,
                        len,
                        FrameWxPermissions::new(false, false),
                    )
                    .unwrap_err(),
                FrameWxError::InvalidPhysicalRange
            );
        }
    }

    #[test]
    fn removal_cannot_begin_for_an_unpublished_reservation() {
        let mut registry = FrameWxRegistry::<4>::new(48).unwrap();
        let _reservation = registry
            .reserve_alias_range(
                ROOT_A,
                VA_A,
                FRAME_A,
                PAGE_SIZE,
                FrameWxPermissions::new(true, false),
            )
            .unwrap();

        assert_eq!(
            registry.begin_removal(ROOT_A, VA_A).unwrap_err(),
            FrameWxError::AliasNotPublished
        );
    }
}
