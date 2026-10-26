#![no_std]
#![deny(unsafe_code)]

//! Small, testable security primitives for ONE OS.
//!
//! This crate models authorization decisions. It does not enforce access at a
//! hardware or process boundary by itself; the kernel must implement that
//! enforcement before these types can be relied on for system security.
//!
//! Authority identifiers are process-local, not globally unique. This model
//! must not be used to authenticate capabilities imported from another process.

#[cfg(test)]
extern crate std;

use core::sync::atomic::{AtomicU64, Ordering};

mod address_space;
mod bootstrap_mapping_audit;
mod elf64;
mod frame_allocator;
mod frame_registry;
mod frame_wx;
mod frame_wx_audit;
mod large_page;
mod memory_policy;
mod page_table;
mod page_table_mutation;
mod paging_preconditions;
mod user_pages;
pub use address_space::{
    validate_user_virtual_range, ActiveAddressSpaceRoot, AddressSpaceRoot,
    AddressSpaceRootDeactivationError, AddressSpaceRootEditor, AddressSpaceRootError,
    AddressSpaceRootInitializationError, UserVirtualRangeError, USER_VIRTUAL_ADDRESS_LIMIT,
};
pub use bootstrap_mapping_audit::{
    bootstrap_mapping_page_count, reserve_bootstrap_backing_frame, BootstrapBackingKind,
    BootstrapFrameReservationError, BootstrapMappingRangeError,
};
pub use elf64::{
    elf64_program_header_table_range, parse_elf64_load_segments, Elf64Error, Elf64LoadImage,
    Elf64LoadSegment, ELF64_HEADER_SIZE, ELF64_PROGRAM_HEADER_SIZE, MAX_ELF64_PROGRAM_HEADERS,
    MAX_ELF64_TOTAL_LOAD_BYTES,
};
pub use frame_allocator::{
    Frame, FrameAllocator, FrameAllocatorError, FrameAllocatorStats, FrameSegment, PAGE_SIZE,
};
pub use frame_registry::{
    FrameRegistryError, FrameToken, PageTableFrameRegistry, PublishedFrameReleaseError,
};
pub use frame_wx::{
    FrameWxError, FrameWxPermissions, FrameWxRegistry, FrameWxRemoval, FrameWxRemovalError,
    FrameWxReservation, FrameWxReservationError,
};
pub use frame_wx_audit::{
    FrameWxAudit, FrameWxAuditError, FrameWxAuditSummary, FrameWxAuditTableBudget,
    FrameWxAuditTableBudgetError, FRAME_WX_AUDIT_MAX_TABLES,
};
pub use large_page::{LargePageDemotion, LargePageDemotionError};
pub use memory_policy::{
    validate_boot_memory_policy, BootMemoryPolicyError, BootMemoryPolicyStats,
};
pub use page_table::{
    is_canonical_4level, is_safe_recursive_mapping_index, physical_page_is_in_allowed_region,
    recursive_entry_is_valid_kernel_root, recursive_entry_matches_root,
    recursive_table_page_virtual_address, translate_4level, PageTableError, PageTranslation,
};
pub(crate) use page_table_mutation::map_4k;
pub use page_table_mutation::{
    map_supervisor_4k, unmap_4k, PagePermissions, PageTableEditor, PageTableMutationError,
    UnmappedPage,
};
pub use paging_preconditions::{
    validate_cr0_write_protect, validate_efer_nx_enable, validate_extended_cpuid_leaf,
    validate_kernel_entry_stack, validate_kernel_root_activation_state,
    validate_paging_cpu_capabilities, PagingPreconditionError,
};
pub use user_pages::{
    initialize_user_frame, map_user_data_page, unmap_all_user_data_pages, unmap_user_data_page,
    UserAddressSpaceEditor, UserFrameInitializationError, UserFrameInitializer,
    UserPageMappingError, UserPageMappingRegistry, UserPageTeardownFailure, UserPageTeardownResult,
    ZeroedFrame,
};

/// Stable identifier for a resource managed by an authority.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ObjectId(u64);

impl ObjectId {
    /// Creates an identifier for a resource.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the numeric identifier.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A structural error found while validating a physical memory map.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryMapError {
    /// The map contains no regions.
    Empty,
    /// A region has an empty or inverted half-open range.
    InvalidRange {
        /// Index of the invalid region in the supplied map.
        region_index: usize,
    },
    /// Two regions overlap.
    Overlap {
        /// Index of the earlier region in the supplied map.
        first_region: usize,
        /// Index of the later region in the supplied map.
        second_region: usize,
    },
}

/// Validates physical memory-map ranges without allocating.
///
/// The region_bounds callback must return stable (start, end) pairs for each
/// index. Ranges are half-open: adjacent regions are valid, while empty,
/// inverted, or overlapping ranges are rejected. This interface lets the
/// kernel validate bootloader-owned entries without copying them.
///
/// This checks range structure only. It does not validate the backing pointer
/// used by the bootloader API, classify usable memory, or establish ownership.
pub fn validate_memory_map<F>(region_count: usize, region_bounds: F) -> Result<(), MemoryMapError>
where
    F: Fn(usize) -> (u64, u64),
{
    if region_count == 0 {
        return Err(MemoryMapError::Empty);
    }

    for region_index in 0..region_count {
        let (start, end) = region_bounds(region_index);
        if start >= end {
            return Err(MemoryMapError::InvalidRange { region_index });
        }

        for other_index in 0..region_index {
            let (other_start, other_end) = region_bounds(other_index);
            if start < other_end && other_start < end {
                return Err(MemoryMapError::Overlap {
                    first_region: other_index,
                    second_region: region_index,
                });
            }
        }
    }

    Ok(())
}

/// Rights which can be granted over a resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rights(u8);

impl Rights {
    const ALL_BITS: u8 = Self::READ.0 | Self::WRITE.0 | Self::EXECUTE.0;

    /// Read a resource.
    pub const READ: Self = Self(1 << 0);
    /// Modify a resource.
    pub const WRITE: Self = Self(1 << 1);
    /// Execute a resource.
    pub const EXECUTE: Self = Self(1 << 2);
    /// No permissions.
    pub const NONE: Self = Self(0);

    /// Creates rights from a bit field, rejecting unknown bits.
    pub const fn from_bits(bits: u8) -> Option<Self> {
        if bits & !Self::ALL_BITS == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    /// Returns the underlying permission bits.
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Returns true when no rights are set.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns true when every right in the other set is present.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Returns the union of two sets of rights.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// An authorization token.
///
/// The authority identifier is only process-local, not a globally unique
/// principal identifier. Do not serialize or import this token across process
/// boundaries as proof of provenance. A future kernel must validate tokens at
/// protected operations and must not trust user-provided memory as a token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capability {
    authority_id: u64,
    object: ObjectId,
    rights: Rights,
    generation: u64,
}

impl Capability {
    /// The object this capability refers to.
    pub const fn object(self) -> ObjectId {
        self.object
    }

    /// Rights carried by this capability.
    pub const fn rights(self) -> Rights {
        self.rights
    }
}

/// The reason an authorization request was denied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessError {
    /// A capability cannot be issued with no permissions.
    EmptyRights,
    /// The authority's generation counter can no longer advance safely.
    AuthorityExhausted,
    /// The capability was issued by a different authority.
    WrongAuthority,
    /// The capability belongs to an earlier generation and was revoked.
    Revoked,
    /// The capability is for a different object.
    WrongObject,
    /// The capability does not contain all requested permissions.
    InsufficientRights,
}

/// Generates process-local, never-reused authority identifiers.
///
/// Relaxed ordering is sufficient: the atomic operation is used only to
/// allocate a unique number, not to publish any other memory.
static NEXT_AUTHORITY_ID: AtomicU64 = AtomicU64::new(1);

fn allocate_authority_id(counter: &AtomicU64) -> Option<u64> {
    counter
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .ok()
}

/// Issues and checks capabilities within one revocation domain.
///
/// Each instance receives a unique domain ID within the current process, and
/// revoke_all invalidates only tokens issued by that instance. Independent
/// processes each start their own counter, so equal numeric IDs can identify
/// different authorities. This type is therefore process-local only; the model
/// provides no cross-process provenance or authentication. A future kernel
/// must use kernel-managed identities and validate the token's source at every
/// protected operation.
///
/// This simple generation scheme is coarse grained; per-object revocation and
/// delegation can be considered later.
#[derive(Debug)]
pub struct Authority {
    domain_id: Option<u64>,
    generation: u64,
    exhausted: bool,
}

impl Authority {
    /// Creates an authority with an ID unique only within this process.
    ///
    /// Separate processes can allocate the same numeric ID. Never treat this
    /// ID as a cross-process identity or as proof that a token came from a
    /// particular process.
    ///
    /// If IDs have been exhausted, this authority fails closed and cannot
    /// issue or validate capabilities.
    pub fn new() -> Self {
        let domain_id = allocate_authority_id(&NEXT_AUTHORITY_ID);

        Self {
            domain_id,
            generation: 1,
            exhausted: false,
        }
    }

    /// Issues a capability for an object with exactly the supplied rights.
    pub fn grant(&self, object: ObjectId, rights: Rights) -> Result<Capability, AccessError> {
        if self.exhausted || self.domain_id.is_none() {
            return Err(AccessError::AuthorityExhausted);
        }
        if rights.is_empty() {
            return Err(AccessError::EmptyRights);
        }

        Ok(Capability {
            authority_id: self.domain_id.expect("domain ID checked above"),
            object,
            rights,
            generation: self.generation,
        })
    }

    /// Checks that a capability is current and authorizes the requested action.
    pub fn authorize(
        &self,
        capability: &Capability,
        object: ObjectId,
        required: Rights,
    ) -> Result<(), AccessError> {
        let authority_id = self.domain_id.ok_or(AccessError::AuthorityExhausted)?;
        if self.exhausted {
            return Err(AccessError::AuthorityExhausted);
        }
        if capability.authority_id != authority_id {
            return Err(AccessError::WrongAuthority);
        }
        if capability.generation != self.generation {
            return Err(AccessError::Revoked);
        }
        if capability.object != object {
            return Err(AccessError::WrongObject);
        }
        if required.is_empty() || !capability.rights.contains(required) {
            return Err(AccessError::InsufficientRights);
        }

        Ok(())
    }

    /// Invalidates all currently issued capabilities.
    ///
    /// If the generation counter is exhausted, the authority fails closed:
    /// it can neither issue nor validate any capability.
    pub fn revoke_all(&mut self) {
        match self.generation.checked_add(1) {
            Some(next) => self.generation = next,
            None => self.exhausted = true,
        }
    }
}

impl Default for Authority {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        allocate_authority_id, validate_memory_map, AccessError, Authority, MemoryMapError,
        ObjectId, Rights,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    const FILE: ObjectId = ObjectId::new(7);
    const OTHER_FILE: ObjectId = ObjectId::new(8);

    #[test]
    fn refuses_authority_id_allocation_when_counter_is_exhausted() {
        // Use an isolated counter so this test cannot exhaust the process-wide ID source.
        let counter = AtomicU64::new(u64::MAX);

        assert_eq!(allocate_authority_id(&counter), None);
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    }

    #[test]
    fn domain_id_exhaustion_fails_closed() {
        let issuer = Authority::new();
        let capability = issuer.grant(FILE, Rights::READ).unwrap();
        let exhausted = Authority {
            domain_id: None,
            generation: 1,
            exhausted: false,
        };

        assert_eq!(
            exhausted.grant(FILE, Rights::READ),
            Err(AccessError::AuthorityExhausted)
        );
        assert_eq!(
            exhausted.authorize(&capability, FILE, Rights::READ),
            Err(AccessError::AuthorityExhausted)
        );
    }

    #[test]
    fn generation_overflow_fails_closed() {
        let mut authority = Authority::new();
        let capability = authority.grant(FILE, Rights::READ).unwrap();

        authority.generation = u64::MAX;
        authority.revoke_all();

        assert!(authority.exhausted);
        assert_eq!(
            authority.grant(FILE, Rights::READ),
            Err(AccessError::AuthorityExhausted)
        );
        assert_eq!(
            authority.authorize(&capability, FILE, Rights::READ),
            Err(AccessError::AuthorityExhausted)
        );
    }

    #[test]
    fn rejects_empty_memory_map() {
        assert_eq!(
            validate_memory_map(0, |_| (0, 0)),
            Err(MemoryMapError::Empty)
        );
    }

    #[test]
    fn rejects_empty_memory_region() {
        assert_eq!(
            validate_memory_map(1, |_| (0x1000, 0x1000)),
            Err(MemoryMapError::InvalidRange { region_index: 0 })
        );
    }

    #[test]
    fn rejects_inverted_memory_region() {
        assert_eq!(
            validate_memory_map(1, |_| (0x2000, 0x1000)),
            Err(MemoryMapError::InvalidRange { region_index: 0 })
        );
    }

    #[test]
    fn rejects_overlapping_memory_regions() {
        let regions = [(0x3000, 0x5000), (0x1000, 0x4000)];
        assert_eq!(
            validate_memory_map(regions.len(), |index| regions[index]),
            Err(MemoryMapError::Overlap {
                first_region: 0,
                second_region: 1
            })
        );
    }

    #[test]
    fn accepts_adjacent_memory_regions() {
        let regions = [(0x1000, 0x2000), (0x2000, 0x3000)];
        assert_eq!(
            validate_memory_map(regions.len(), |index| regions[index]),
            Ok(())
        );
    }

    #[test]
    fn accepts_non_overlapping_regions_out_of_address_order() {
        let regions = [(0x3000, 0x4000), (0x1000, 0x2000)];
        assert_eq!(
            validate_memory_map(regions.len(), |index| regions[index]),
            Ok(())
        );
    }

    #[test]
    fn grants_and_authorizes_requested_right() {
        let authority = Authority::new();
        let capability = authority.grant(FILE, Rights::READ).unwrap();

        assert_eq!(authority.authorize(&capability, FILE, Rights::READ), Ok(()));
    }

    #[test]
    fn denies_rights_not_granted() {
        let authority = Authority::new();
        let capability = authority.grant(FILE, Rights::READ).unwrap();

        assert_eq!(
            authority.authorize(&capability, FILE, Rights::WRITE),
            Err(AccessError::InsufficientRights)
        );
    }

    #[test]
    fn denies_access_to_another_object() {
        let authority = Authority::new();
        let capability = authority.grant(FILE, Rights::READ).unwrap();

        assert_eq!(
            authority.authorize(&capability, OTHER_FILE, Rights::READ),
            Err(AccessError::WrongObject)
        );
    }

    #[test]
    fn denies_empty_grants_and_empty_requests() {
        let authority = Authority::new();

        assert_eq!(
            authority.grant(FILE, Rights::NONE),
            Err(AccessError::EmptyRights)
        );

        let capability = authority.grant(FILE, Rights::READ).unwrap();
        assert_eq!(
            authority.authorize(&capability, FILE, Rights::NONE),
            Err(AccessError::InsufficientRights)
        );
    }

    #[test]
    fn revocation_invalidates_existing_capabilities() {
        let mut authority = Authority::new();
        let capability = authority.grant(FILE, Rights::READ).unwrap();

        authority.revoke_all();

        assert_eq!(
            authority.authorize(&capability, FILE, Rights::READ),
            Err(AccessError::Revoked)
        );
    }

    #[test]
    fn rejects_capabilities_issued_by_another_authority() {
        let issuer = Authority::new();
        let other = Authority::new();
        let capability = issuer.grant(FILE, Rights::READ).unwrap();

        assert_eq!(
            other.authorize(&capability, FILE, Rights::READ),
            Err(AccessError::WrongAuthority)
        );
    }

    #[test]
    fn revocation_is_independent_between_authorities() {
        let mut first = Authority::new();
        let second = Authority::new();
        let first_capability = first.grant(FILE, Rights::READ).unwrap();
        let second_capability = second.grant(FILE, Rights::READ).unwrap();

        first.revoke_all();

        assert_eq!(
            first.authorize(&first_capability, FILE, Rights::READ),
            Err(AccessError::Revoked)
        );
        assert_eq!(
            second.authorize(&second_capability, FILE, Rights::READ),
            Ok(())
        );
        assert_eq!(
            second.authorize(&first_capability, FILE, Rights::READ),
            Err(AccessError::WrongAuthority)
        );
    }

    #[test]
    fn rejects_unknown_rights_bits() {
        assert_eq!(Rights::from_bits(0b1000_0000), None);
        assert_eq!(Rights::from_bits(Rights::READ.bits()), Some(Rights::READ));
    }

    #[test]
    fn supports_combined_rights() {
        let authority = Authority::new();
        let rights = Rights::READ.union(Rights::WRITE);
        let capability = authority.grant(FILE, rights).unwrap();

        assert_eq!(
            authority.authorize(&capability, FILE, Rights::READ.union(Rights::WRITE)),
            Ok(())
        );
    }
}
