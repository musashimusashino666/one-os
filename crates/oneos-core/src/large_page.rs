//! Validated, host-testable planning for demoting x86_64 large-page leaves.
//!
//! This module only derives child leaf entries. It does not allocate page-table
//! frames, publish a new table, change permissions, or invalidate the TLB. A
//! kernel caller must complete those operations transactionally before a direct
//! map permission transition can be considered complete.

const PRESENT: u64 = 1;
const LARGE_PAGE: u64 = 1 << 7;
const PHYSICAL_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const LARGE_PAGE_PAT: u64 = 1 << 12;
const SMALL_PAGE_PAT: u64 = 1 << 7;
const PAGE_SIZE_4K: u64 = 1 << 12;
const PAGE_SIZE_2M: u64 = 1 << 21;
const PAGE_SIZE_1G: u64 = 1 << 30;
const ENTRIES_PER_TABLE: usize = 512;
const MIN_PHYSICAL_ADDRESS_BITS: u8 = 32;
const MAX_PHYSICAL_ADDRESS_BITS: u8 = 52;

/// Errors returned while validating a large-page demotion source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LargePageDemotionError {
    /// MAXPHYADDR is outside the supported 32..=52-bit range.
    InvalidPhysicalAddressWidth,
    /// Only a 1 GiB PDPT leaf or a 2 MiB page-directory leaf can be demoted.
    UnsupportedSourceLevel,
    /// The source leaf is not present.
    NotPresent,
    /// The source entry does not have the large-page bit set.
    NotLargePage,
    /// Reserved alignment bits are set in the source large-page entry.
    MalformedLargePage,
    /// The source physical range exceeds the CPU's reported physical address width.
    PhysicalAddressOutOfRange,
}

/// A validated plan for replacing one large-page leaf with 512 smaller leaves.
///
/// source_level == 3 describes a 1 GiB PDPTE and creates 2 MiB PDE leaves.
/// source_level == 2 describes a 2 MiB PDE and creates 4 KiB PTE leaves.
/// All original access attributes are retained. The PAT bit is translated from
/// bit 12 in a large-page leaf to bit 7 when producing 4 KiB leaves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LargePageDemotion {
    source_level: u8,
    physical_base: u64,
    inherited_flags: u64,
    pat: bool,
    child_page_size: u64,
}

impl LargePageDemotion {
    /// Validates an existing large-page leaf before planning any child entries.
    ///
    /// source_level is 3 for a 1 GiB PDPTE or 2 for a 2 MiB PDE. This function
    /// rejects unsupported levels, absent/non-large entries, reserved alignment
    /// bits, unsupported MAXPHYADDR values, and source ranges that exceed
    /// MAXPHYADDR. It does not read or mutate a page table.
    pub fn new(
        source_entry: u64,
        source_level: u8,
        physical_address_bits: u8,
    ) -> Result<Self, LargePageDemotionError> {
        if !(MIN_PHYSICAL_ADDRESS_BITS..=MAX_PHYSICAL_ADDRESS_BITS).contains(&physical_address_bits) {
            return Err(LargePageDemotionError::InvalidPhysicalAddressWidth);
        }

        let source_page_size = match source_level {
            3 => PAGE_SIZE_1G,
            2 => PAGE_SIZE_2M,
            _ => return Err(LargePageDemotionError::UnsupportedSourceLevel),
        };

        if source_entry & PRESENT == 0 {
            return Err(LargePageDemotionError::NotPresent);
        }
        if source_entry & LARGE_PAGE == 0 {
            return Err(LargePageDemotionError::NotLargePage);
        }

        // In large-page entries bit 12 is PAT. Bits 13 through page-size-1 are
        // reserved alignment bits and must be zero.
        let reserved_alignment_mask = (source_page_size - 1) & !0x1fff;
        if source_entry & reserved_alignment_mask != 0 {
            return Err(LargePageDemotionError::MalformedLargePage);
        }

        let addressable_mask = ((1u64 << physical_address_bits) - 1) & PHYSICAL_ADDRESS_MASK;
        if source_entry & PHYSICAL_ADDRESS_MASK & !addressable_mask != 0 {
            return Err(LargePageDemotionError::PhysicalAddressOutOfRange);
        }

        let physical_base = source_entry & PHYSICAL_ADDRESS_MASK & !(source_page_size - 1);
        let address_limit = 1u64 << physical_address_bits;
        let Some(physical_end) = physical_base.checked_add(source_page_size) else {
            return Err(LargePageDemotionError::PhysicalAddressOutOfRange);
        };
        if physical_end > address_limit {
            return Err(LargePageDemotionError::PhysicalAddressOutOfRange);
        }

        let child_page_size = match source_level {
            3 => PAGE_SIZE_2M,
            2 => PAGE_SIZE_4K,
            _ => unreachable!("source level was validated"),
        };

        Ok(Self {
            source_level,
            physical_base,
            // Bit 12 is part of the physical-address field mask but represents
            // PAT in large-page entries, so preserve it separately below.
            inherited_flags: source_entry & !PHYSICAL_ADDRESS_MASK,
            pat: source_entry & LARGE_PAGE_PAT != 0,
            child_page_size,
        })
    }

    /// Paging level for the child leaf entries: 2 for 2 MiB, 1 for 4 KiB.
    pub const fn child_level(&self) -> u8 {
        self.source_level - 1
    }

    /// Size in bytes of each planned child mapping.
    pub const fn child_page_size(&self) -> u64 {
        self.child_page_size
    }

    /// Returns one of the 512 child leaf entries, or None for an invalid index.
    ///
    /// For 1 GiB to 2 MiB demotion, the child large-page bit remains set and
    /// PAT remains in bit 12. For 2 MiB to 4 KiB demotion, the large-page bit is
    /// cleared and PAT, if present, is moved to the 4 KiB PTE's bit 7.
    pub fn child_entry(&self, index: usize) -> Option<u64> {
        if index >= ENTRIES_PER_TABLE {
            return None;
        }

        let offset = (index as u64).checked_mul(self.child_page_size)?;
        let physical_address = self.physical_base.checked_add(offset)?;
        let flags = if self.source_level == 3 {
            self.inherited_flags | LARGE_PAGE | if self.pat { LARGE_PAGE_PAT } else { 0 }
        } else {
            (self.inherited_flags & !LARGE_PAGE) | if self.pat { SMALL_PAGE_PAT } else { 0 }
        };

        Some(physical_address | flags)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LargePageDemotion, LargePageDemotionError, LARGE_PAGE, LARGE_PAGE_PAT,
        PHYSICAL_ADDRESS_MASK, SMALL_PAGE_PAT,
    };

    const PRESENT: u64 = 1;
    const WRITABLE: u64 = 1 << 1;
    const USER: u64 = 1 << 2;
    const WRITE_THROUGH: u64 = 1 << 3;
    const CACHE_DISABLE: u64 = 1 << 4;
    const ACCESSED: u64 = 1 << 5;
    const DIRTY: u64 = 1 << 6;
    const GLOBAL: u64 = 1 << 8;
    const SOFTWARE: u64 = 0b101 << 9;
    const NX: u64 = 1 << 63;
    const PROTECTION_KEY: u64 = 0b1011 << 59;
    const FLAGS_TO_PRESERVE: u64 = WRITABLE
        | USER
        | WRITE_THROUGH
        | CACHE_DISABLE
        | ACCESSED
        | DIRTY
        | GLOBAL
        | SOFTWARE
        | NX
        | PROTECTION_KEY;

    #[test]
    fn demotes_1g_leaf_to_512_2m_leaves_without_losing_attributes() {
        let base = 0x4000_0000;
        let source = base | PRESENT | LARGE_PAGE | LARGE_PAGE_PAT | FLAGS_TO_PRESERVE;
        let plan = LargePageDemotion::new(source, 3, 48).unwrap();

        assert_eq!(plan.child_level(), 2);
        assert_eq!(plan.child_page_size(), 1 << 21);
        for index in [0, 1, 127, 255, 511] {
            let child = plan.child_entry(index).unwrap();
            let expected_base = base + index as u64 * (1 << 21);
            assert_eq!(
                child & PHYSICAL_ADDRESS_MASK & !((1 << 21) - 1),
                expected_base
            );
            assert_eq!(
                child & (FLAGS_TO_PRESERVE | PRESENT),
                FLAGS_TO_PRESERVE | PRESENT
            );
            assert_ne!(child & LARGE_PAGE, 0);
            assert_ne!(child & LARGE_PAGE_PAT, 0);
        }
        assert_eq!(plan.child_entry(512), None);
    }

    #[test]
    fn demotes_2m_leaf_to_512_4k_leaves_and_repositions_pat() {
        let base = 0x0240_0000;
        let source = base | PRESENT | LARGE_PAGE | LARGE_PAGE_PAT | FLAGS_TO_PRESERVE;
        let plan = LargePageDemotion::new(source, 2, 48).unwrap();

        assert_eq!(plan.child_level(), 1);
        assert_eq!(plan.child_page_size(), 1 << 12);
        for index in [0, 1, 17, 255, 511] {
            let child = plan.child_entry(index).unwrap();
            assert_eq!(
                child & PHYSICAL_ADDRESS_MASK,
                base + index as u64 * (1 << 12)
            );
            assert_eq!(
                child & (FLAGS_TO_PRESERVE | PRESENT),
                FLAGS_TO_PRESERVE | PRESENT
            );
            assert_ne!(child & SMALL_PAGE_PAT, 0);
        }
        assert_eq!(plan.child_entry(512), None);
    }

    #[test]
    fn demotion_without_pat_does_not_invent_a_pat_attribute() {
        let source = 0x0200_0000 | PRESENT | LARGE_PAGE | WRITABLE;
        let child = LargePageDemotion::new(source, 2, 48)
            .unwrap()
            .child_entry(7)
            .unwrap();
        assert_eq!(child & SMALL_PAGE_PAT, 0);
        assert_eq!(child & PHYSICAL_ADDRESS_MASK, 0x0200_7000);
    }

    #[test]
    fn rejects_invalid_source_entries_and_widths() {
        assert_eq!(
            LargePageDemotion::new(PRESENT | LARGE_PAGE, 2, 31).unwrap_err(),
            LargePageDemotionError::InvalidPhysicalAddressWidth
        );
        assert_eq!(
            LargePageDemotion::new(PRESENT | LARGE_PAGE, 1, 48).unwrap_err(),
            LargePageDemotionError::UnsupportedSourceLevel
        );
        assert_eq!(
            LargePageDemotion::new(LARGE_PAGE, 2, 48).unwrap_err(),
            LargePageDemotionError::NotPresent
        );
        assert_eq!(
            LargePageDemotion::new(PRESENT, 2, 48).unwrap_err(),
            LargePageDemotionError::NotLargePage
        );
        assert_eq!(
            LargePageDemotion::new(PRESENT | LARGE_PAGE | (1 << 13), 2, 48).unwrap_err(),
            LargePageDemotionError::MalformedLargePage
        );
        assert_eq!(
            LargePageDemotion::new((1u64 << 32) | PRESENT | LARGE_PAGE, 2, 32).unwrap_err(),
            LargePageDemotionError::PhysicalAddressOutOfRange
        );
    }
}
