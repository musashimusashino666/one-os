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

impl<const CAPACITY: usize> FrameWxAudit<CAPACITY> {
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

        self.tracked_alias_mappings = self.tracked_alias_mappings.saturating_add(1);
        if permissions.writable && permissions.executable {
            self.conflicting_overlap_events = self.conflicting_overlap_events.saturating_add(1);
        }

        let physical_end = physical_start + length;
        for existing in self.aliases[..self.alias_count].iter().copied() {
            let physical_overlap = physical_start < existing.physical_end()
                && existing.physical_start < physical_end;
            let conflicts = (permissions.writable && existing.permissions.executable)
                || (permissions.executable && existing.permissions.writable);
            if physical_overlap && conflicts {
                self.conflicting_overlap_events =
                    self.conflicting_overlap_events.saturating_add(1);
            }
        }

        if self.alias_count > 0 {
            let previous = &mut self.aliases[self.alias_count - 1];
            if previous.permissions == permissions
                && previous.virtual_end() == u128::from(virtual_start)
                && previous.physical_end() == physical_start
            {
                previous.length = previous
                    .length
                    .checked_add(length)
                    .ok_or(FrameWxAuditError::InvalidPhysicalRange)?;
                return Ok(());
            }
        }

        if self.alias_count == CAPACITY {
            return Err(FrameWxAuditError::CapacityExhausted);
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
    use super::{FrameWxAudit, FrameWxAuditError};
    use crate::frame_wx::FrameWxPermissions;

    const BASE_VA: u64 = 0xffff_8000_0000_0000;
    const BASE_PA: u64 = 0x20_0000;
    const PAGE: u64 = 4096;

    fn permissions(writable: bool, executable: bool) -> FrameWxPermissions {
        FrameWxPermissions::new(writable, executable)
    }

    #[test]
    fn detects_overlapping_aliases_in_either_insertion_order() {
        let mut executable_first = FrameWxAudit::<8>::new(48).unwrap();
        executable_first
            .record_alias(
                BASE_VA,
                BASE_PA,
                1 << 21,
                permissions(false, true),
            )
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
            .record_alias(
                BASE_VA,
                BASE_PA,
                1 << 21,
                permissions(false, true),
            )
            .unwrap();
        assert!(writable_first.summary().conflicting_overlap_events > 0);
    }

    #[test]
    fn detects_writable_executable_overlap_with_large_page_extents() {
        let mut audit = FrameWxAudit::<8>::new(48).unwrap();
        audit
            .record_alias(
                BASE_VA,
                BASE_PA,
                1 << 30,
                permissions(false, true),
            )
            .unwrap();
        audit
            .record_alias(
                BASE_VA + (1 << 30),
                BASE_PA + (1 << 21),
                1 << 21,
                permissions(true, false),
            )
            .unwrap();
        assert!(audit.summary().conflicting_overlap_events > 0);
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
    }
}
