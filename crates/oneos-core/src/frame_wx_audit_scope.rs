//! Explicit coverage accounting for a physical-frame W^X audit.
//!
//! A walk that completed successfully is not necessarily a complete system audit.
//! This scope tracker requires an authoritative root inventory, a completed walk
//! of each declared root, and explicit accounting for mapping sources that the
//! ordinary tree walk may not cover. Callers must not mark the root inventory
//! sealed until every root that the kernel can activate has been declared.

const PHYSICAL_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const PAGE_SIZE: u64 = 4096;

/// Mapping sources that must be accounted for before an audit can claim global coverage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameWxAuditSource {
    /// Leaves reachable through the physical-memory-offset/direct-map alias.
    PhysicalMemoryOffsetAlias = 1 << 0,
    /// The writable/NX view created by a recursive page-table self-reference.
    RecursivePageTableView = 1 << 1,
    /// Shared or inherited kernel mappings reachable from more than one root.
    SharedKernelMappings = 1 << 2,
    /// 2 MiB and 1 GiB leaves, including overlap with smaller mappings.
    LargePageLeaves = 1 << 3,
}

impl FrameWxAuditSource {
    /// Bit corresponding to this mapping source in a coverage summary.
    pub const fn mask(self) -> u8 {
        self as u8
    }
}

/// Bit mask of all mapping sources required for a system-wide W^X coverage claim.
pub const FRAME_WX_AUDIT_REQUIRED_SOURCES: u8 = FrameWxAuditSource::PhysicalMemoryOffsetAlias as u8
    | FrameWxAuditSource::RecursivePageTableView as u8
    | FrameWxAuditSource::SharedKernelMappings as u8
    | FrameWxAuditSource::LargePageLeaves as u8;

/// Invalid state reported while constructing an audit coverage scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameWxAuditScopeError {
    /// CPU physical-address width is outside the supported 32..=52-bit range.
    InvalidPhysicalAddressWidth,
    /// Root is zero, unaligned, or outside the reported physical-address width.
    InvalidRootAddress,
    /// The fixed-capacity root inventory cannot represent another root.
    RootCapacityExhausted,
    /// The same physical root was declared more than once.
    DuplicateRoot,
    /// Roots cannot be added after the inventory has been sealed.
    RootInventorySealed,
    /// An empty root inventory cannot be sealed.
    EmptyRootInventory,
    /// The authoritative root inventory was already sealed.
    RootInventoryAlreadySealed,
    /// An audited root was not part of the declared inventory.
    RootNotDeclared,
    /// A root was marked complete more than once.
    RootAlreadyAudited,
}

/// Summary of audit coverage, independent of the observed alias-conflict count.
///
/// `complete` is true only when the root inventory was explicitly sealed,
/// every declared root was completely walked, all required mapping sources were
/// accounted for, and no audit failure was recorded. A zero conflict count is
/// not a substitute for this coverage proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameWxAuditScopeSummary {
    /// Number of roots in the declared inventory.
    pub declared_roots: usize,
    /// Number of declared roots whose complete tree walk succeeded.
    pub audited_roots: usize,
    /// True only after the caller certifies that every activatable root was declared.
    pub root_inventory_sealed: bool,
    /// Mapping-source coverage flags recorded by the caller.
    pub accounted_sources: u8,
    /// Required mapping-source flags that have not been accounted for.
    pub missing_sources: u8,
    /// Whether a root walk or another required audit stage failed.
    pub audit_failed: bool,
    /// False unless every root and every required mapping source was accounted for.
    pub complete: bool,
}

#[derive(Clone, Copy)]
struct RootSlot {
    physical_address: u64,
    audited: bool,
    occupied: bool,
}

impl RootSlot {
    const EMPTY: Self = Self {
        physical_address: 0,
        audited: false,
        occupied: false,
    };
}

/// Fixed-capacity coverage tracker for one intended system-wide W^X inventory.
///
/// The caller must enumerate roots from the kernel's authoritative root registry
/// before calling `seal_root_inventory`. Declaring one root and sealing that
/// list does not magically prove that the enumeration was authoritative; the
/// call site must establish that invariant. Incomplete walks must never be marked
/// audited. Source flags may be set only after the corresponding source has been
/// covered by a validated walk or another reviewed mechanism.
pub struct FrameWxAuditScope<const MAX_ROOTS: usize> {
    physical_address_bits: u8,
    roots: [RootSlot; MAX_ROOTS],
    root_count: usize,
    root_inventory_sealed: bool,
    accounted_sources: u8,
    audit_failed: bool,
}

impl<const MAX_ROOTS: usize> FrameWxAuditScope<MAX_ROOTS> {
    /// Creates an empty coverage scope for the reported CPU physical-address width.
    pub const fn new(physical_address_bits: u8) -> Result<Self, FrameWxAuditScopeError> {
        if physical_address_bits < 32 || physical_address_bits > 52 {
            return Err(FrameWxAuditScopeError::InvalidPhysicalAddressWidth);
        }
        Ok(Self {
            physical_address_bits,
            roots: [RootSlot::EMPTY; MAX_ROOTS],
            root_count: 0,
            root_inventory_sealed: false,
            accounted_sources: 0,
            audit_failed: false,
        })
    }

    /// Declares one root before the authoritative root inventory is sealed.
    pub fn declare_root(&mut self, physical_address: u64) -> Result<(), FrameWxAuditScopeError> {
        if self.root_inventory_sealed {
            self.audit_failed = true;
            return Err(FrameWxAuditScopeError::RootInventorySealed);
        }
        if !self.valid_root_address(physical_address) {
            self.audit_failed = true;
            return Err(FrameWxAuditScopeError::InvalidRootAddress);
        }
        if self.roots[..self.root_count]
            .iter()
            .any(|root| root.physical_address == physical_address)
        {
            self.audit_failed = true;
            return Err(FrameWxAuditScopeError::DuplicateRoot);
        }
        if self.root_count == MAX_ROOTS {
            self.audit_failed = true;
            return Err(FrameWxAuditScopeError::RootCapacityExhausted);
        }
        self.roots[self.root_count] = RootSlot {
            physical_address,
            audited: false,
            occupied: true,
        };
        self.root_count += 1;
        Ok(())
    }

    /// Seals the root inventory after every activatable root has been declared.
    ///
    /// The method validates non-emptiness but cannot independently enumerate the
    /// kernel's root registry. The caller is responsible for proving that the list
    /// is authoritative and stable for the duration of the audit.
    pub fn seal_root_inventory(&mut self) -> Result<(), FrameWxAuditScopeError> {
        if self.root_inventory_sealed {
            self.audit_failed = true;
            return Err(FrameWxAuditScopeError::RootInventoryAlreadySealed);
        }
        if self.root_count == 0 {
            self.audit_failed = true;
            return Err(FrameWxAuditScopeError::EmptyRootInventory);
        }
        self.root_inventory_sealed = true;
        Ok(())
    }

    /// Marks a declared root only after its entire supported page-table tree was audited.
    pub fn mark_root_audited(
        &mut self,
        physical_address: u64,
    ) -> Result<(), FrameWxAuditScopeError> {
        let Some(index) = self.roots[..self.root_count]
            .iter()
            .position(|root| root.physical_address == physical_address)
        else {
            self.audit_failed = true;
            return Err(FrameWxAuditScopeError::RootNotDeclared);
        };
        if self.roots[index].audited {
            self.audit_failed = true;
            return Err(FrameWxAuditScopeError::RootAlreadyAudited);
        }
        self.roots[index].audited = true;
        Ok(())
    }

    /// Records that a mapping source has been accounted for by a reviewed mechanism.
    pub fn account_source(&mut self, source: FrameWxAuditSource) {
        self.accounted_sources |= source.mask();
    }

    /// Permanently marks this scope as failed; later successes cannot yield complete coverage.
    pub fn mark_audit_failed(&mut self) {
        self.audit_failed = true;
    }

    /// Returns coverage state without converting a partial audit into success.
    pub fn summary(&self) -> FrameWxAuditScopeSummary {
        let audited_roots = self.roots[..self.root_count]
            .iter()
            .filter(|root| root.occupied && root.audited)
            .count();
        let missing_sources = FRAME_WX_AUDIT_REQUIRED_SOURCES & !self.accounted_sources;
        let complete = self.root_inventory_sealed
            && self.root_count > 0
            && audited_roots == self.root_count
            && missing_sources == 0
            && !self.audit_failed;
        FrameWxAuditScopeSummary {
            declared_roots: self.root_count,
            audited_roots,
            root_inventory_sealed: self.root_inventory_sealed,
            accounted_sources: self.accounted_sources,
            missing_sources,
            audit_failed: self.audit_failed,
            complete,
        }
    }

    fn valid_root_address(&self, address: u64) -> bool {
        if address == 0 || address & (PAGE_SIZE - 1) != 0 || address & !PHYSICAL_ADDRESS_MASK != 0 {
            return false;
        }
        let limit = 1u64 << self.physical_address_bits;
        address
            .checked_add(PAGE_SIZE)
            .is_some_and(|end| end <= limit)
    }
}


/// Returns whether a registered-root table still represents the exact root set
/// captured before a W^X audit.
///
/// `expected_roots` is the compact, validated list captured at audit start.
/// `read_slot` reads a slot from the live fixed-capacity registry. The function
/// rejects missing, added, replaced, zero-valued expected, or duplicate roots.
/// Slot reads may be repeated to detect duplicates without allocating another
/// root-sized scratch array. The caller must preserve the registry's serialization
/// contract for the duration of this check; the current kernel contract is single
/// CPU with maskable interrupts disabled.
pub fn frame_wx_root_registry_matches<F>(
    expected_roots: &[u64],
    slot_count: usize,
    mut read_slot: F,
) -> bool
where
    F: FnMut(usize) -> u64,
{
    if expected_roots.len() > slot_count || expected_roots.contains(&0) {
        return false;
    }
    for (index, root) in expected_roots.iter().enumerate() {
        if expected_roots[..index].contains(root) {
            return false;
        }
    }

    let mut observed_count = 0usize;
    for slot_index in 0..slot_count {
        let root = read_slot(slot_index);
        if root == 0 {
            continue;
        }
        if !expected_roots.contains(&root) {
            return false;
        }
        for previous_index in 0..slot_index {
            if read_slot(previous_index) == root {
                return false;
            }
        }
        observed_count += 1;
    }

    observed_count == expected_roots.len()
}

#[cfg(test)]
mod tests {
    use super::{
        FrameWxAuditScope, FrameWxAuditScopeError, FrameWxAuditSource,
        FRAME_WX_AUDIT_REQUIRED_SOURCES,
    };

    const ROOT_A: u64 = 0x1000;
    const ROOT_B: u64 = 0x2000;

    fn complete_scope() -> FrameWxAuditScope<2> {
        let mut scope = FrameWxAuditScope::<2>::new(48).unwrap();
        scope.declare_root(ROOT_A).unwrap();
        scope.declare_root(ROOT_B).unwrap();
        scope.seal_root_inventory().unwrap();
        scope.mark_root_audited(ROOT_A).unwrap();
        scope.mark_root_audited(ROOT_B).unwrap();
        scope.account_source(FrameWxAuditSource::PhysicalMemoryOffsetAlias);
        scope.account_source(FrameWxAuditSource::RecursivePageTableView);
        scope.account_source(FrameWxAuditSource::SharedKernelMappings);
        scope.account_source(FrameWxAuditSource::LargePageLeaves);
        scope
    }

    #[test]
    fn partial_active_root_walk_is_not_system_wide_coverage() {
        let mut scope = FrameWxAuditScope::<2>::new(48).unwrap();
        scope.declare_root(ROOT_A).unwrap();
        scope.mark_root_audited(ROOT_A).unwrap();
        scope.account_source(FrameWxAuditSource::LargePageLeaves);

        let summary = scope.summary();
        assert_eq!(summary.declared_roots, 1);
        assert_eq!(summary.audited_roots, 1);
        assert!(!summary.root_inventory_sealed);
        assert!(!summary.complete);
        assert_eq!(
            summary.missing_sources,
            FRAME_WX_AUDIT_REQUIRED_SOURCES & !FrameWxAuditSource::LargePageLeaves.mask()
        );
    }

    #[test]
    fn complete_requires_every_root_and_every_mapping_source() {
        let scope = complete_scope();
        let summary = scope.summary();

        assert!(summary.root_inventory_sealed);
        assert_eq!(summary.declared_roots, 2);
        assert_eq!(summary.audited_roots, 2);
        assert_eq!(summary.missing_sources, 0);
        assert!(summary.complete);
    }

    #[test]
    fn an_unwalked_declared_root_prevents_complete_coverage() {
        let mut scope = FrameWxAuditScope::<2>::new(48).unwrap();
        scope.declare_root(ROOT_A).unwrap();
        scope.declare_root(ROOT_B).unwrap();
        scope.seal_root_inventory().unwrap();
        scope.mark_root_audited(ROOT_A).unwrap();
        for source in [
            FrameWxAuditSource::PhysicalMemoryOffsetAlias,
            FrameWxAuditSource::RecursivePageTableView,
            FrameWxAuditSource::SharedKernelMappings,
            FrameWxAuditSource::LargePageLeaves,
        ] {
            scope.account_source(source);
        }
        let summary = scope.summary();
        assert_eq!(summary.audited_roots, 1);
        assert!(!summary.complete);
    }

    #[test]
    fn failed_audit_can_never_be_reported_complete() {
        let mut scope = complete_scope();
        scope.mark_audit_failed();
        let summary = scope.summary();
        assert!(summary.audit_failed);
        assert!(!summary.complete);
    }

    #[test]
    fn rejects_duplicate_roots_unknown_roots_and_post_seal_additions() {
        let mut scope = FrameWxAuditScope::<2>::new(48).unwrap();
        scope.declare_root(ROOT_A).unwrap();
        assert_eq!(
            scope.declare_root(ROOT_A),
            Err(FrameWxAuditScopeError::DuplicateRoot)
        );
        scope.seal_root_inventory().unwrap();
        assert_eq!(
            scope.declare_root(ROOT_B),
            Err(FrameWxAuditScopeError::RootInventorySealed)
        );
        assert_eq!(
            scope.mark_root_audited(ROOT_B),
            Err(FrameWxAuditScopeError::RootNotDeclared)
        );
        scope.mark_root_audited(ROOT_A).unwrap();
        assert_eq!(
            scope.mark_root_audited(ROOT_A),
            Err(FrameWxAuditScopeError::RootAlreadyAudited)
        );
    }

    #[test]
    fn rejects_invalid_addresses_and_capacity_exhaustion_without_corrupting_scope() {
        assert!(matches!(
            FrameWxAuditScope::<2>::new(31),
            Err(FrameWxAuditScopeError::InvalidPhysicalAddressWidth)
        ));
        let mut scope = FrameWxAuditScope::<1>::new(48).unwrap();
        assert_eq!(
            scope.declare_root(0),
            Err(FrameWxAuditScopeError::InvalidRootAddress)
        );
        assert_eq!(
            scope.declare_root(ROOT_A + 1),
            Err(FrameWxAuditScopeError::InvalidRootAddress)
        );
        scope.declare_root(ROOT_A).unwrap();
        assert_eq!(
            scope.declare_root(ROOT_B),
            Err(FrameWxAuditScopeError::RootCapacityExhausted)
        );
        assert_eq!(scope.summary().declared_roots, 1);
        assert!(!scope.summary().complete);
    }

    #[test]
    fn requires_a_non_empty_root_inventory_and_accounts_sources_idempotently() {
        let mut empty = FrameWxAuditScope::<1>::new(48).unwrap();
        assert_eq!(
            empty.seal_root_inventory(),
            Err(FrameWxAuditScopeError::EmptyRootInventory)
        );
        assert!(empty.summary().audit_failed);
        assert!(!empty.summary().complete);

        let mut scope = FrameWxAuditScope::<1>::new(48).unwrap();
        scope.declare_root(ROOT_A).unwrap();
        scope.seal_root_inventory().unwrap();
        scope.account_source(FrameWxAuditSource::LargePageLeaves);
        scope.account_source(FrameWxAuditSource::LargePageLeaves);
        assert_eq!(
            scope.summary().accounted_sources,
            FrameWxAuditSource::LargePageLeaves.mask()
        );
    }

    #[test]
    fn ignored_root_inventory_errors_cannot_become_a_complete_audit() {
        let mut scope = FrameWxAuditScope::<1>::new(48).unwrap();
        scope.declare_root(ROOT_A).unwrap();
        assert_eq!(
            scope.declare_root(ROOT_B),
            Err(FrameWxAuditScopeError::RootCapacityExhausted)
        );
        scope.seal_root_inventory().unwrap();
        scope.mark_root_audited(ROOT_A).unwrap();
        for source in [
            FrameWxAuditSource::PhysicalMemoryOffsetAlias,
            FrameWxAuditSource::RecursivePageTableView,
            FrameWxAuditSource::SharedKernelMappings,
            FrameWxAuditSource::LargePageLeaves,
        ] {
            scope.account_source(source);
        }
        let summary = scope.summary();
        assert!(summary.audit_failed);
        assert!(!summary.complete);
    }
    #[test]
    fn root_registry_snapshot_requires_exact_unique_membership() {
        use super::frame_wx_root_registry_matches;

        const ROOT_C: u64 = 0x3000;
        let expected = [ROOT_A, ROOT_B];
        let unchanged = [ROOT_A, 0, ROOT_B, 0];
        assert!(frame_wx_root_registry_matches(
            &expected,
            unchanged.len(),
            |index| unchanged[index],
        ));

        // Slot positions may change, but membership must remain exactly the same.
        let reordered = [0, ROOT_B, 0, ROOT_A];
        assert!(frame_wx_root_registry_matches(
            &expected,
            reordered.len(),
            |index| reordered[index],
        ));

        let added = [ROOT_A, ROOT_B, ROOT_C, 0];
        assert!(!frame_wx_root_registry_matches(
            &expected,
            added.len(),
            |index| added[index],
        ));

        let removed = [ROOT_A, 0, 0, 0];
        assert!(!frame_wx_root_registry_matches(
            &expected,
            removed.len(),
            |index| removed[index],
        ));

        let replaced = [ROOT_A, ROOT_C, 0, 0];
        assert!(!frame_wx_root_registry_matches(
            &expected,
            replaced.len(),
            |index| replaced[index],
        ));

        let duplicated = [ROOT_A, ROOT_A, 0, 0];
        assert!(!frame_wx_root_registry_matches(
            &expected,
            duplicated.len(),
            |index| duplicated[index],
        ));
        assert!(!frame_wx_root_registry_matches(
            &[ROOT_A, ROOT_A],
            duplicated.len(),
            |index| duplicated[index],
        ));

        let empty = [0, 0, 0];
        assert!(frame_wx_root_registry_matches(
            &[],
            empty.len(),
            |index| empty[index],
        ));
    }

}
