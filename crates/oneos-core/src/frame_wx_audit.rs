//! Host-testable inventory for auditing existing physical W^X aliases.
//!
//! Unlike `FrameWxRegistry`, this audit intentionally accepts conflicting aliases:
//! it observes mappings that already exist and reports overlaps without mutating
//! them. It is diagnostic only; callers must not use a successful audit as proof
//! that untracked roots or aliases are safe.

use crate::frame_wx::FrameWxPermissions;
use crate::{is_canonical_4level, PAGE_SIZE};

const LOWER_CANONICAL_LIMIT: u64 = 0x0000_8000_0000_0000;
const UPPER_CANONICAL_START: u64 = 0xffff_8000_0000_0000;

/// One concrete writable/executable physical overlap observed by the audit.
///
/// Virtual addresses identify the two alias views at the start of the overlapping
/// physical interval. For a single mapping that is itself W+X, both virtual
/// addresses and permission values refer to that same mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameWxAuditConflict {
    /// First physical byte of the overlapping interval.
    pub physical_start: u64,
    /// Length of the overlapping physical interval in bytes.
    pub length: u64,
    /// Virtual address corresponding to `physical_start` through the first alias.
    pub first_virtual_start: u64,
    /// Virtual address corresponding to `physical_start` through the second alias.
    pub second_virtual_start: u64,
    /// Effective permissions of the first alias.
    pub first_permissions: FrameWxPermissions,
    /// Effective permissions of the second alias.
    pub second_permissions: FrameWxPermissions,
}

/// Summary of a bounded inventory of existing writable/executable aliases.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameWxAuditSummary {
    /// Number of mapping leaves whose effective rights included write or execute.
    pub tracked_alias_mappings: u64,
    /// Number of stored ranges after adjacent compatible mappings were coalesced.
    pub tracked_ranges: usize,
    /// Number of stored ranges that are writable.
    pub writable_ranges: usize,
    /// Number of stored ranges that are executable.
    pub executable_ranges: usize,
    /// Number of detected overlapping alias events, including W+X within one mapping.
    ///
    /// This is a diagnostic counter, not a count of conflicting bytes or unique frames.
    pub conflicting_overlap_events: u64,
    /// First concrete overlap found, if any.
    pub first_conflict: Option<FrameWxAuditConflict>,
    /// Up to three additional concrete overlaps in discovery order. Together with
    /// `first_conflict`, this keeps a bounded sample of four diagnostic examples.
    pub additional_conflicts: [Option<FrameWxAuditConflict>; 3],
    /// Number of populated entries in `additional_conflicts`.
    pub additional_conflict_count: usize,
}

/// Error encountered while constructing or recording a W^X audit inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameWxAuditError {
    /// MAXPHYADDR is outside the supported 32..=52-bit range.
    InvalidPhysicalAddressWidth,
    /// The virtual alias range is unaligned, empty, overflowing, non-canonical,
    /// or crosses the canonical-address hole.
    InvalidVirtualRange,
    /// The physical alias range is unaligned, empty, overflowing, or exceeds MAXPHYADDR.
    InvalidPhysicalRange,
    /// The fixed-capacity inventory cannot represent another non-coalescible alias.
    CapacityExhausted,
}

/// Maximum number of page-table visits permitted in the bounded W^X audit.
pub const FRAME_WX_AUDIT_MAX_TABLES: usize = 16_384;

/// Tracks how many page tables a bounded W^X audit has visited.
///
/// This small policy object is shared with the kernel walker so host tests can
/// exercise the exact visit-budget boundary without constructing a page-table tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameWxAuditTableBudgetError {
    /// The configured number of page-table visits has already been reached.
    CapacityExhausted,
}

/// Fail-closed counter for a page-table walk's maximum number of table visits.
///
/// A rejected visit does not change the count, so callers cannot accidentally
/// treat an exhausted walk as having made progress.
pub struct FrameWxAuditTableBudget<const MAX_TABLES: usize> {
    visited_tables: usize,
}

impl<const MAX_TABLES: usize> FrameWxAuditTableBudget<MAX_TABLES> {
    /// Creates a visit counter with no tables visited.
    pub const fn new() -> Self {
        Self { visited_tables: 0 }
    }

    /// Accounts for one table visit, rejecting visits beyond the configured limit.
    pub fn visit(&mut self) -> Result<(), FrameWxAuditTableBudgetError> {
        if self.visited_tables >= MAX_TABLES {
            return Err(FrameWxAuditTableBudgetError::CapacityExhausted);
        }
        self.visited_tables += 1;
        Ok(())
    }

    /// Returns the number of accepted page-table visits.
    pub const fn visited_tables(&self) -> usize {
        self.visited_tables
    }
}

impl<const MAX_TABLES: usize> Default for FrameWxAuditTableBudget<MAX_TABLES> {
    fn default() -> Self {
        Self::new()
    }
}

/// Bounded, read-only inventory of mappings that are writable or executable.
///
/// Records describe byte ranges, not just page starts, so a 4 KiB alias conflicts
/// with an overlapping 2 MiB or 1 GiB alias. Adjacent mappings are coalesced only
/// when virtual and physical addresses are both contiguous and effective rights match.
pub struct FrameWxAudit<const CAPACITY: usize> {
    physical_address_bits: u8,
    aliases: [AliasRange; CAPACITY],
    alias_count: usize,
    tracked_alias_mappings: u64,
    conflicting_overlap_events: u64,
    first_conflict: Option<FrameWxAuditConflict>,
    additional_conflicts: [Option<FrameWxAuditConflict>; 3],
    additional_conflict_count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AliasRange {
    virtual_start: u64,
    physical_start: u64,
    length: u64,
    permissions: FrameWxPermissions,
}

impl AliasRange {
    const EMPTY: Self = Self {
        virtual_start: 0,
        physical_start: 0,
        length: 0,
        permissions: FrameWxPermissions::new(false, false),
    };

    fn virtual_end(self) -> u128 {
        u128::from(self.virtual_start) + u128::from(self.length)
    }

    fn physical_end(self) -> u64 {
        // Ranges are validated before they are stored.
        self.physical_start + self.length
    }
}

fn conflicting_intersection(first: AliasRange, second: AliasRange) -> Option<FrameWxAuditConflict> {
    let physical_start = first.physical_start.max(second.physical_start);
    let physical_end = first.physical_end().min(second.physical_end());
    let permissions_conflict = (first.permissions.writable && second.permissions.executable)
        || (first.permissions.executable && second.permissions.writable);
    if physical_start >= physical_end || !permissions_conflict {
        return None;
    }

    // Both ranges were validated on insertion/observation. The physical overlap
    // lies within each range, so adding its offset to either validated virtual
    // start cannot cross that range's checked canonical half-open boundary.
    let first_virtual_start = (u128::from(first.virtual_start)
        + u128::from(physical_start - first.physical_start)) as u64;
    let second_virtual_start = (u128::from(second.virtual_start)
        + u128::from(physical_start - second.physical_start)) as u64;
    Some(FrameWxAuditConflict {
        physical_start,
        length: physical_end - physical_start,
        first_virtual_start,
        second_virtual_start,
        first_permissions: first.permissions,
        second_permissions: second.permissions,
    })
}

impl<const CAPACITY: usize> FrameWxAudit<CAPACITY> {
    fn remember_conflict(&mut self, conflict: FrameWxAuditConflict) {
        if self.first_conflict.is_none() {
            self.first_conflict = Some(conflict);
            return;
        }
        if self.additional_conflict_count < self.additional_conflicts.len() {
            self.additional_conflicts[self.additional_conflict_count] = Some(conflict);
            self.additional_conflict_count += 1;
        }
    }

    /// Creates an empty audit inventory for the given CPU physical-address width.
    pub const fn new(physical_address_bits: u8) -> Result<Self, FrameWxAuditError> {
        if physical_address_bits < 32 || physical_address_bits > 52 {
            return Err(FrameWxAuditError::InvalidPhysicalAddressWidth);
        }
        Ok(Self {
            physical_address_bits,
            aliases: [AliasRange::EMPTY; CAPACITY],
            alias_count: 0,
            tracked_alias_mappings: 0,
            conflicting_overlap_events: 0,
            first_conflict: None,
            additional_conflicts: [None; 3],
            additional_conflict_count: 0,
        })
    }

    /// Records one effective mapping range. Read-only/NX mappings are omitted.
    ///
    /// Conflicts are accepted and counted because the inventory observes the current
    /// page tables; it does not publish or modify mappings. Capacity exhaustion is
    /// returned as an error so callers cannot report an incomplete inventory as complete.
    pub fn record_alias(
        &mut self,
        virtual_start: u64,
        physical_start: u64,
        length: u64,
        permissions: FrameWxPermissions,
    ) -> Result<(), FrameWxAuditError> {
        if !permissions.writable && !permissions.executable {
            return Ok(());
        }
        validate_virtual_range(virtual_start, length)?;
        self.validate_physical_range(physical_start, length)?;

        // Preflight the representation change before touching counters or records.
        // A capacity/arithmetic error therefore leaves the audit state unchanged.
        let merged_length = if self.alias_count > 0 {
            let previous = self.aliases[self.alias_count - 1];
            if previous.permissions == permissions
                && previous.virtual_end() == u128::from(virtual_start)
                && previous.physical_end() == physical_start
            {
                Some(
                    previous
                        .length
                        .checked_add(length)
                        .ok_or(FrameWxAuditError::InvalidPhysicalRange)?,
                )
            } else {
                None
            }
        } else {
            None
        };
        if merged_length.is_none() && self.alias_count == CAPACITY {
            return Err(FrameWxAuditError::CapacityExhausted);
        }

        let incoming = AliasRange {
            virtual_start,
            physical_start,
            length,
            permissions,
        };
        let own_conflict = conflicting_intersection(incoming, incoming);
        self.tracked_alias_mappings = self.tracked_alias_mappings.saturating_add(1);
        if let Some(conflict) = own_conflict {
            self.conflicting_overlap_events = self.conflicting_overlap_events.saturating_add(1);
            self.remember_conflict(conflict);
        }

        for existing in self.aliases[..self.alias_count].iter().copied() {
            if let Some(conflict) = conflicting_intersection(existing, incoming) {
                self.conflicting_overlap_events = self.conflicting_overlap_events.saturating_add(1);
                self.remember_conflict(conflict);
            }
        }

        if let Some(length) = merged_length {
            self.aliases[self.alias_count - 1].length = length;
            return Ok(());
        }
        self.aliases[self.alias_count] = AliasRange {
            virtual_start,
            physical_start,
            length,
            permissions,
        };
        self.alias_count += 1;
        Ok(())
    }

    /// Observes an additional W/X alias against the stored inventory without
    /// consuming range capacity.
    ///
    /// This is used for recursive page-table views: the walker already inventories
    /// all ordinary leaves, while each recursive alias only needs to be checked
    /// against those leaves for a writable/executable physical overlap. Recursive
    /// aliases must not be silently dropped due to the main range inventory being
    /// full, so this path records conflict evidence but does not store the alias.
    pub fn observe_alias(
        &mut self,
        virtual_start: u64,
        physical_start: u64,
        length: u64,
        permissions: FrameWxPermissions,
    ) -> Result<(), FrameWxAuditError> {
        if !permissions.writable && !permissions.executable {
            return Ok(());
        }
        validate_virtual_range(virtual_start, length)?;
        self.validate_physical_range(physical_start, length)?;

        let incoming = AliasRange {
            virtual_start,
            physical_start,
            length,
            permissions,
        };
        let own_conflict = conflicting_intersection(incoming, incoming);
        if let Some(conflict) = own_conflict {
            self.conflicting_overlap_events = self.conflicting_overlap_events.saturating_add(1);
            self.remember_conflict(conflict);
        }
        for existing in self.aliases[..self.alias_count].iter().copied() {
            if let Some(conflict) = conflicting_intersection(existing, incoming) {
                self.conflicting_overlap_events = self.conflicting_overlap_events.saturating_add(1);
                self.remember_conflict(conflict);
            }
        }
        Ok(())
    }

    /// Returns the bounded audit summary.
    pub fn summary(&self) -> FrameWxAuditSummary {
        let mut writable_ranges = 0usize;
        let mut executable_ranges = 0usize;
        for alias in self.aliases[..self.alias_count].iter() {
            if alias.permissions.writable {
                writable_ranges += 1;
            }
            if alias.permissions.executable {
                executable_ranges += 1;
            }
        }
        FrameWxAuditSummary {
            tracked_alias_mappings: self.tracked_alias_mappings,
            tracked_ranges: self.alias_count,
            writable_ranges,
            executable_ranges,
            conflicting_overlap_events: self.conflicting_overlap_events,
            first_conflict: self.first_conflict,
            additional_conflicts: self.additional_conflicts,
            additional_conflict_count: self.additional_conflict_count,
        }
    }

    fn validate_physical_range(
        &self,
        physical_start: u64,
        length: u64,
    ) -> Result<(), FrameWxAuditError> {
        let maximum_address = 1u64 << self.physical_address_bits;
        if physical_start & (PAGE_SIZE - 1) != 0
            || length == 0
            || length & (PAGE_SIZE - 1) != 0
            || physical_start
                .checked_add(length)
                .filter(|end| *end <= maximum_address)
                .is_none()
        {
            return Err(FrameWxAuditError::InvalidPhysicalRange);
        }
        Ok(())
    }
}

fn validate_virtual_range(start: u64, length: u64) -> Result<(), FrameWxAuditError> {
    if start & (PAGE_SIZE - 1) != 0 || length == 0 || length & (PAGE_SIZE - 1) != 0 {
        return Err(FrameWxAuditError::InvalidVirtualRange);
    }
    let end = u128::from(start) + u128::from(length);
    if end > (1u128 << 64) {
        return Err(FrameWxAuditError::InvalidVirtualRange);
    }
    let last = u64::try_from(end - 1).map_err(|_| FrameWxAuditError::InvalidVirtualRange)?;
    if !is_canonical_4level(start) || !is_canonical_4level(last) {
        return Err(FrameWxAuditError::InvalidVirtualRange);
    }
    let lower = start < LOWER_CANONICAL_LIMIT;
    let last_lower = last < LOWER_CANONICAL_LIMIT;
    let same_canonical_half = if lower {
        last_lower
    } else {
        start >= UPPER_CANONICAL_START && last >= UPPER_CANONICAL_START
    };
    if !same_canonical_half {
        return Err(FrameWxAuditError::InvalidVirtualRange);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        FrameWxAudit, FrameWxAuditError, FrameWxAuditTableBudget, FrameWxAuditTableBudgetError,
        FRAME_WX_AUDIT_MAX_TABLES,
    };
    use crate::frame_wx::FrameWxPermissions;

    const BASE_VA: u64 = 0xffff_8000_0000_0000;
    const BASE_PA: u64 = 0x20_0000;
    const LARGE_BASE_PA: u64 = 0x4000_0000;
    const PAGE: u64 = 4096;

    fn permissions(writable: bool, executable: bool) -> FrameWxPermissions {
        FrameWxPermissions::new(writable, executable)
    }

    #[test]
    fn detects_overlapping_aliases_in_either_insertion_order() {
        let mut executable_first = FrameWxAudit::<8>::new(48).unwrap();
        executable_first
            .record_alias(BASE_VA, BASE_PA, 1 << 21, permissions(false, true))
            .unwrap();
        executable_first
            .record_alias(
                BASE_VA + (4 * PAGE),
                BASE_PA + (4 * PAGE),
                PAGE,
                permissions(true, false),
            )
            .unwrap();
        assert!(executable_first.summary().conflicting_overlap_events > 0);

        let mut writable_first = FrameWxAudit::<8>::new(48).unwrap();
        writable_first
            .record_alias(
                BASE_VA + (4 * PAGE),
                BASE_PA + (4 * PAGE),
                PAGE,
                permissions(true, false),
            )
            .unwrap();
        writable_first
            .record_alias(BASE_VA, BASE_PA, 1 << 21, permissions(false, true))
            .unwrap();
        assert!(writable_first.summary().conflicting_overlap_events > 0);
    }

    #[test]
    fn detects_writable_executable_overlap_with_large_page_extents() {
        let mut audit = FrameWxAudit::<8>::new(48).unwrap();
        audit
            .record_alias(BASE_VA, LARGE_BASE_PA, 1 << 30, permissions(false, true))
            .unwrap();
        audit
            .record_alias(
                BASE_VA + (1 << 30),
                LARGE_BASE_PA + (1 << 21),
                1 << 21,
                permissions(true, false),
            )
            .unwrap();
        let summary = audit.summary();
        assert!(summary.conflicting_overlap_events > 0);
        let conflict = summary.first_conflict.expect("large-page overlap evidence");
        assert_eq!(conflict.physical_start, LARGE_BASE_PA + (1 << 21));
        assert_eq!(conflict.length, 1 << 21);
        assert_eq!(conflict.first_virtual_start, BASE_VA + (1 << 21));
        assert_eq!(conflict.second_virtual_start, BASE_VA + (1 << 30));
        assert_eq!(conflict.first_permissions, permissions(false, true));
        assert_eq!(conflict.second_permissions, permissions(true, false));
    }

    #[test]
    fn coalesces_adjacent_aliases_with_identical_effective_rights() {
        let mut audit = FrameWxAudit::<2>::new(48).unwrap();
        audit
            .record_alias(BASE_VA, BASE_PA, PAGE, permissions(true, false))
            .unwrap();
        audit
            .record_alias(
                BASE_VA + PAGE,
                BASE_PA + PAGE,
                PAGE,
                permissions(true, false),
            )
            .unwrap();
        let summary = audit.summary();
        assert_eq!(summary.tracked_alias_mappings, 2);
        assert_eq!(summary.tracked_ranges, 1);
        assert_eq!(summary.writable_ranges, 1);
    }

    #[test]
    fn read_only_nx_aliases_do_not_consume_inventory_capacity() {
        let mut audit = FrameWxAudit::<0>::new(48).unwrap();
        audit
            .record_alias(BASE_VA, BASE_PA, PAGE, permissions(false, false))
            .unwrap();
        assert_eq!(audit.summary().tracked_ranges, 0);
        assert_eq!(audit.summary().tracked_alias_mappings, 0);
    }

    #[test]
    fn rejects_invalid_ranges_and_reports_capacity_exhaustion() {
        assert!(matches!(
            FrameWxAudit::<1>::new(64),
            Err(FrameWxAuditError::InvalidPhysicalAddressWidth)
        ));
        let mut audit = FrameWxAudit::<1>::new(48).unwrap();
        assert_eq!(
            audit.record_alias(BASE_VA, BASE_PA + 1, PAGE, permissions(true, false)),
            Err(FrameWxAuditError::InvalidPhysicalRange)
        );
        audit
            .record_alias(BASE_VA, BASE_PA, PAGE, permissions(true, false))
            .unwrap();
        assert_eq!(
            audit.record_alias(
                BASE_VA + (2 * PAGE),
                BASE_PA + (2 * PAGE),
                PAGE,
                permissions(true, false),
            ),
            Err(FrameWxAuditError::CapacityExhausted)
        );
        assert_eq!(audit.summary().tracked_alias_mappings, 1);
        assert_eq!(audit.summary().tracked_ranges, 1);
    }

    #[test]
    fn observed_recursive_alias_detects_exec_overlap_without_consuming_capacity() {
        let mut audit = FrameWxAudit::<1>::new(48).unwrap();
        audit
            .record_alias(BASE_VA, BASE_PA, PAGE, permissions(false, true))
            .unwrap();
        let before = audit.summary();

        audit
            .observe_alias(
                BASE_VA + (8 * PAGE),
                BASE_PA,
                PAGE,
                permissions(true, false),
            )
            .unwrap();

        let after = audit.summary();
        assert!(after.conflicting_overlap_events > before.conflicting_overlap_events);
        assert_eq!(after.tracked_alias_mappings, before.tracked_alias_mappings);
        assert_eq!(after.tracked_ranges, before.tracked_ranges);
        let conflict = after
            .first_conflict
            .expect("recursive alias conflict evidence");
        assert_eq!(conflict.physical_start, BASE_PA);
        assert_eq!(conflict.length, PAGE);
        assert_eq!(conflict.first_virtual_start, BASE_VA);
        assert_eq!(conflict.second_virtual_start, BASE_VA + (8 * PAGE));
        assert_eq!(conflict.first_permissions, permissions(false, true));
        assert_eq!(conflict.second_permissions, permissions(true, false));
    }

    #[test]
    fn retains_multiple_physical_overlap_examples_in_discovery_order() {
        let mut audit = FrameWxAudit::<4>::new(48).unwrap();
        audit
            .record_alias(BASE_VA, LARGE_BASE_PA, PAGE * 3, permissions(false, true))
            .unwrap();
        audit
            .record_alias(
                BASE_VA + 0x20_000,
                LARGE_BASE_PA + PAGE,
                PAGE,
                permissions(true, false),
            )
            .unwrap();
        audit
            .record_alias(
                BASE_VA + 0x40_000,
                LARGE_BASE_PA + (2 * PAGE),
                PAGE,
                permissions(true, false),
            )
            .unwrap();

        let summary = audit.summary();
        assert_eq!(summary.conflicting_overlap_events, 2);
        let first = summary.first_conflict.expect("first overlap evidence");
        assert_eq!(first.physical_start, LARGE_BASE_PA + PAGE);
        assert_eq!(first.first_virtual_start, BASE_VA + PAGE);
        assert_eq!(first.second_virtual_start, BASE_VA + 0x20_000);
        assert_eq!(summary.additional_conflict_count, 1);
        let second = summary.additional_conflicts[0].expect("second overlap evidence");
        assert_eq!(second.physical_start, LARGE_BASE_PA + (2 * PAGE));
        assert_eq!(second.first_virtual_start, BASE_VA + (2 * PAGE));
        assert_eq!(second.second_virtual_start, BASE_VA + 0x40_000);
    }

    #[test]
    fn reports_a_single_mapping_that_is_both_writable_and_executable() {
        let mut audit = FrameWxAudit::<1>::new(48).unwrap();
        audit
            .record_alias(BASE_VA, BASE_PA, PAGE, permissions(true, true))
            .unwrap();
        let summary = audit.summary();
        assert_eq!(summary.conflicting_overlap_events, 1);
        let conflict = summary.first_conflict.expect("self-conflict evidence");
        assert_eq!(conflict.first_virtual_start, BASE_VA);
        assert_eq!(conflict.second_virtual_start, BASE_VA);
        assert_eq!(conflict.first_permissions, permissions(true, true));
        assert_eq!(conflict.second_permissions, permissions(true, true));
    }

    #[test]
    fn rejects_a_range_that_crosses_the_canonical_hole() {
        let mut audit = FrameWxAudit::<1>::new(48).unwrap();
        assert_eq!(
            audit.record_alias(0x0000_7fff_ffff_f000, 0, PAGE * 2, permissions(true, false),),
            Err(FrameWxAuditError::InvalidVirtualRange)
        );
    }

    #[test]
    fn fragmented_inventory_enforces_capacity_and_preserves_state_on_failure() {
        const CAPACITY: usize = 128;

        let mut audit = FrameWxAudit::<CAPACITY>::new(48).unwrap();
        for index in 0..CAPACITY {
            let offset = (index as u64) * 2 * PAGE;
            let rights = if index % 2 == 0 {
                permissions(true, false)
            } else {
                permissions(false, true)
            };
            audit
                .record_alias(BASE_VA + offset, BASE_PA + offset, PAGE, rights)
                .unwrap();
        }

        let full = audit.summary();
        assert_eq!(full.tracked_alias_mappings, CAPACITY as u64);
        assert_eq!(full.tracked_ranges, CAPACITY);
        assert_eq!(full.writable_ranges, CAPACITY / 2);
        assert_eq!(full.executable_ranges, CAPACITY / 2);

        // Read-only/NX entries do not consume W/X inventory capacity.
        audit
            .record_alias(
                BASE_VA + (257 * PAGE),
                BASE_PA + (257 * PAGE),
                PAGE,
                permissions(false, false),
            )
            .unwrap();
        assert_eq!(audit.summary(), full);

        // A compatible range adjacent to the final slot coalesces even at capacity.
        audit
            .record_alias(
                BASE_VA + (255 * PAGE),
                BASE_PA + (255 * PAGE),
                PAGE,
                permissions(false, true),
            )
            .unwrap();
        let coalesced = audit.summary();
        assert_eq!(coalesced.tracked_alias_mappings, CAPACITY as u64 + 1);
        assert_eq!(coalesced.tracked_ranges, CAPACITY);
        assert_eq!(coalesced.executable_ranges, CAPACITY / 2);

        // A non-coalescible 129th range is rejected without changing the summary.
        assert_eq!(
            audit.record_alias(
                BASE_VA + (258 * PAGE),
                BASE_PA + (258 * PAGE),
                PAGE,
                permissions(true, false),
            ),
            Err(FrameWxAuditError::CapacityExhausted)
        );
        assert_eq!(audit.summary(), coalesced);
    }

    #[test]
    fn table_budget_enforces_the_16k_visit_boundary_without_overcounting() {
        const MAX_TABLES: usize = FRAME_WX_AUDIT_MAX_TABLES;

        let mut budget = FrameWxAuditTableBudget::<MAX_TABLES>::new();
        assert_eq!(budget.visited_tables(), 0);

        for _ in 0..MAX_TABLES {
            budget.visit().unwrap();
        }
        assert_eq!(budget.visited_tables(), MAX_TABLES);
        assert_eq!(
            budget.visit(),
            Err(FrameWxAuditTableBudgetError::CapacityExhausted)
        );
        assert_eq!(budget.visited_tables(), MAX_TABLES);
    }

    #[test]
    fn zero_table_budget_rejects_the_first_visit_without_mutation() {
        let mut budget = FrameWxAuditTableBudget::<0>::new();

        assert_eq!(
            budget.visit(),
            Err(FrameWxAuditTableBudgetError::CapacityExhausted)
        );
        assert_eq!(budget.visited_tables(), 0);
    }
}
