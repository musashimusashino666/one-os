//! Host-testable transaction for demoting an x86_64 large-page leaf.
//!
//! This primitive stages all 512 child entries in an unlinked, zeroed table,
//! reserves ownership metadata, atomically invalidates the old leaf, publishes
//! the child table, and flushes again. The live kernel adapter supplies the
//! checked recursive aliases, frame ownership, atomic entry updates, and local
//! all-TLB invalidation. To avoid writes during the break interval, every child
//! leaf is conservatively pre-marked Accessed+Dirty; exact per-child A/D history
//! is intentionally not preserved. The current live contract remains single-CPU,
//! maskable interrupts disabled, and PCID disabled.

use super::{is_canonical_4level, LargePageDemotion, LargePageDemotionError};

const PRESENT: u64 = 1;
const WRITABLE: u64 = 1 << 1;
const USER_ACCESSIBLE: u64 = 1 << 2;
const ACCESSED: u64 = 1 << 5;
const DIRTY: u64 = 1 << 6;
const ACCESSED_DIRTY_MASK: u64 = ACCESSED | DIRTY;
const NO_EXECUTE: u64 = 1 << 63;
const PAGE_SIZE: u64 = 1 << 12;
const ENTRIES_PER_TABLE: usize = 512;
const MIN_PHYSICAL_ADDRESS_BITS: u8 = 32;
const MAX_PHYSICAL_ADDRESS_BITS: u8 = 52;

/// Operations required to stage and publish a large-page demotion.
///
/// Implementations must address page tables through a validated path rooted at
/// the supplied root. The parent table must be reachable at `parent_level` and
/// correspond to `virtual_base`. Mutation must be serialized by the caller.
/// `allocate_table` returns a newly owned, zero-filled, unlinked table frame.
/// The reservation callback must reserve all ownership metadata needed for
/// publication without making the table reachable; failure must leave metadata
/// unchanged. The commit callback and range invalidation are infallible by
/// contract: an inconsistent registry or failed invalidation must fail-stop.
///
/// `invalidate_local_range` must remove every local translation covering the
/// supplied range, not merely invalidate the first 4 KiB address. On its first
/// invocation, after Present is cleared, it must also ensure no prior page walk
/// can subsequently update A/D bits in the retired large-page entry. A second
/// invocation follows child-pointer publication. Remote CPUs and SMP
/// synchronization are deliberately outside this primitive.
pub trait LargePageDemotionEditor {
    /// Physical-address width of the CPU whose tables this editor accesses.
    fn physical_address_bits(&self) -> u8;

    /// Reads one entry from a reachable table, including a non-present entry.
    /// Returns `None` only if the validated table cannot be accessed.
    fn read_entry(&mut self, table_physical: u64, index: usize, level: u8) -> Option<u64>;

    /// Writes an entry to a validated, writable table. Infallible by contract.
    ///
    /// Use this for the unlinked child table and for publishing the final parent
    /// pointer after the previous large-page entry is non-present and flushed.
    fn write_entry(&mut self, table_physical: u64, index: usize, level: u8, value: u64);

    /// Strong atomic compare-exchange for the large-page parent entry.
    ///
    /// This must be atomic with respect to hardware page-walker updates of the
    /// accessed/dirty bits. On failure, return the exact value observed in the
    /// entry. On success, replace `expected` with `replacement` atomically.
    /// The transaction uses this to clear Present without losing hardware A/D
    /// updates; after a successful clear, the caller must flush the full virtual
    /// range before validating the retired entry's final A/D sample. The sample
    /// is not copied back into the children: all child leaves are pre-marked
    /// Accessed+Dirty before the break interval. Weak/spurious CAS is forbidden.
    fn compare_exchange_entry(
        &mut self,
        table_physical: u64,
        index: usize,
        level: u8,
        expected: u64,
        replacement: u64,
    ) -> Result<(), u64>;

    /// Allocates a fresh page-table frame and zeros all 4 KiB before return.
    fn allocate_table(&mut self) -> Option<u64>;

    /// Reserves publication metadata for a new child table.
    ///
    /// Return `false` without changing metadata if ownership/registry capacity
    /// cannot be reserved. A successful reservation must be canceled by
    /// `release_unpublished_table` on every pre-publication failure.
    fn reserve_table_publication(
        &mut self,
        root_table_physical: u64,
        child_table_physical: u64,
        child_level: u8,
    ) -> bool;

    /// Commits a previously reserved table registration after the parent points
    /// to the child. This callback must not fail; inconsistency must fail-stop.
    fn commit_table_publication(
        &mut self,
        root_table_physical: u64,
        child_table_physical: u64,
        child_level: u8,
    );

    /// Cancels any unpublished registration and releases a frame returned by
    /// `allocate_table`. Must not release a published or foreign frame.
    fn release_unpublished_table(&mut self, child_table_physical: u64);

    /// Invalidates all local TLB translations within the half-open virtual range.
    /// Must complete before this callback returns; inability to do so is fatal.
    fn invalidate_local_range(&mut self, virtual_start: u64, length: u64);
}

/// Errors returned by the staged large-page demotion transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LargePageDemotionTransactionError {
    /// The reported MAXPHYADDR is outside the supported range 32..=52.
    InvalidPhysicalAddressWidth,
    /// The root, parent, or allocated table address is invalid or unaligned.
    InvalidPhysicalAddress,
    /// Only level 3 (1 GiB) and level 2 (2 MiB) leaves can be demoted.
    InvalidSourceLevel,
    /// The requested index is outside a 512-entry paging-structure page.
    InvalidParentIndex,
    /// The virtual base is not aligned to the original large-page size.
    MisalignedVirtualAddress,
    /// The virtual range crosses a non-canonical region or is non-canonical.
    NonCanonicalVirtualAddress,
    /// The parent entry could not be read through the validated editor.
    ParentEntryUnavailable,
    /// The current entry is absent, malformed, or not a supported large page.
    InvalidSource(LargePageDemotionError),
    /// No page-table frame could be allocated.
    TableAllocationFailed,
    /// Ownership metadata for publication could not be reserved.
    TablePublicationReservationFailed,
    /// Non-A/D bits changed unexpectedly before the old leaf was invalidated.
    ParentEntryChanged,
    /// The validated planner unexpectedly failed to produce a child entry.
    ChildEntryUnavailable,
}

/// Evidence describing a completed demotion operation.
///
/// The result confirms that the parent pointer was replaced and the editor's
/// local invalidation callback returned. It does not establish global W^X or
/// prove that aliases outside this editor's root have been inventoried.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LargePageDemotionReceipt {
    pub root_table_physical: u64,
    pub parent_table_physical: u64,
    pub parent_index: usize,
    pub child_table_physical: u64,
    pub source_level: u8,
    pub child_level: u8,
    pub virtual_start: u64,
    pub virtual_length: u64,
    pub physical_start: u64,
}

/// Demotes the large-page entry at `parent_index` into a staged child table.
///
/// The editor must already have validated that `parent_table_physical` is the
/// table at `source_level` reachable from `root_table_physical` for
/// `virtual_base`. This function validates alignment, the source entry,
/// MAXPHYADDR, and the VA/index relationship itself. The caller must hold the
/// page-table mutation serialization required by the current kernel contract.
///
/// All fallible allocation and registration work completes before the original
/// leaf is changed. Every child is staged with Accessed+Dirty set before Present
/// is cleared. The function then atomically clears Present, invalidates the full
/// range, validates the retired parent and its final A/D sample, publishes the
/// child pointer, commits ownership, and invalidates the range again. It does
/// not reconstruct per-child A/D history: all 512 children may conservatively
/// appear accessed and dirty, including pages that were never touched. This
/// break-before-make ordering retires the old translation under the editor's
/// architecture contract.
/// Any failure after clearing Present is an invariant violation and must fail-stop;
/// it must not return while leaving the mapping partially published.
pub fn demote_large_page<E: LargePageDemotionEditor>(
    editor: &mut E,
    root_table_physical: u64,
    parent_table_physical: u64,
    source_level: u8,
    parent_index: usize,
    virtual_base: u64,
) -> Result<LargePageDemotionReceipt, LargePageDemotionTransactionError> {
    let physical_address_bits = editor.physical_address_bits();
    if !(MIN_PHYSICAL_ADDRESS_BITS..=MAX_PHYSICAL_ADDRESS_BITS).contains(&physical_address_bits) {
        return Err(LargePageDemotionTransactionError::InvalidPhysicalAddressWidth);
    }

    if !(2..=3).contains(&source_level) {
        return Err(LargePageDemotionTransactionError::InvalidSourceLevel);
    }
    if parent_index >= ENTRIES_PER_TABLE {
        return Err(LargePageDemotionTransactionError::InvalidParentIndex);
    }
    if !valid_table_frame(root_table_physical, physical_address_bits)
        || !valid_table_frame(parent_table_physical, physical_address_bits)
    {
        return Err(LargePageDemotionTransactionError::InvalidPhysicalAddress);
    }

    let source_page_size = 1u64 << (12 + 9 * (source_level - 1));
    if virtual_base & (source_page_size - 1) != 0 {
        return Err(LargePageDemotionTransactionError::MisalignedVirtualAddress);
    }
    let virtual_end = virtual_base
        .checked_add(source_page_size - 1)
        .ok_or(LargePageDemotionTransactionError::NonCanonicalVirtualAddress)?;
    if !is_canonical_4level(virtual_base) || !is_canonical_4level(virtual_end) {
        return Err(LargePageDemotionTransactionError::NonCanonicalVirtualAddress);
    }
    let index_shift = 12 + 9 * (source_level - 1);
    let address_index = ((virtual_base >> index_shift) & 0x1ff) as usize;
    if address_index != parent_index {
        return Err(LargePageDemotionTransactionError::InvalidParentIndex);
    }

    let original_parent = editor
        .read_entry(parent_table_physical, parent_index, source_level)
        .ok_or(LargePageDemotionTransactionError::ParentEntryUnavailable)?;
    let plan = LargePageDemotion::new(original_parent, source_level, physical_address_bits)
        .map_err(LargePageDemotionTransactionError::InvalidSource)?;

    let child_table_physical = editor
        .allocate_table()
        .ok_or(LargePageDemotionTransactionError::TableAllocationFailed)?;
    if !valid_table_frame(child_table_physical, physical_address_bits) {
        editor.release_unpublished_table(child_table_physical);
        return Err(LargePageDemotionTransactionError::InvalidPhysicalAddress);
    }

    let child_level = plan.child_level();
    if !editor.reserve_table_publication(root_table_physical, child_table_physical, child_level) {
        editor.release_unpublished_table(child_table_physical);
        return Err(LargePageDemotionTransactionError::TablePublicationReservationFailed);
    }

    // Stage a complete child table before making any reachable mapping change.
    // Conservatively pre-set A/D on every leaf: after Present is cleared, a direct-map
    // demotion may temporarily remove the only writable alias of this unlinked table.
    // Pre-setting both bits avoids any child-table write during that break window and
    // ensures no in-flight hardware A/D update can be lost.
    for index in 0..ENTRIES_PER_TABLE {
        let Some(child_entry) = plan.child_entry(index) else {
            editor.release_unpublished_table(child_table_physical);
            return Err(LargePageDemotionTransactionError::ChildEntryUnavailable);
        };
        editor.write_entry(
            child_table_physical,
            index,
            child_level,
            child_entry | ACCESSED_DIRTY_MASK,
        );
    }

    // Atomically clear Present. A hardware page walker may set A/D while the
    // large leaf is still present, so retry when those bits change. Any other
    // change violates the caller's mutation-serialization contract and aborts
    // before we invalidate or alter the mapping.
    let mut expected_parent = original_parent;
    loop {
        if expected_parent & !ACCESSED_DIRTY_MASK != original_parent & !ACCESSED_DIRTY_MASK {
            editor.release_unpublished_table(child_table_physical);
            return Err(LargePageDemotionTransactionError::ParentEntryChanged);
        }
        let invalid_parent = expected_parent & !PRESENT;
        match editor.compare_exchange_entry(
            parent_table_physical,
            parent_index,
            source_level,
            expected_parent,
            invalid_parent,
        ) {
            Ok(()) => break,
            Err(observed) => {
                let expected_ad = expected_parent & ACCESSED_DIRTY_MASK;
                let observed_ad = observed & ACCESSED_DIRTY_MASK;
                if observed & !ACCESSED_DIRTY_MASK != original_parent & !ACCESSED_DIRTY_MASK
                    || observed & PRESENT == 0
                    || observed_ad & expected_ad != expected_ad
                    || observed_ad == expected_ad
                {
                    editor.release_unpublished_table(child_table_physical);
                    return Err(LargePageDemotionTransactionError::ParentEntryChanged);
                }
                // Hardware only sets A/D bits. Use the newly observed value as
                // the expected word for the next strong CAS; the final state is
                // sampled again after invalidation to include in-flight updates.
                expected_parent = observed;
            }
        }
    }

    // Break-before-make: after this callback returns, the old large-page
    // translation is gone and no prior walk may still update its A/D bits.
    editor.invalidate_local_range(virtual_base, source_page_size);
    let invalidated_parent =
        match editor.read_entry(parent_table_physical, parent_index, source_level) {
            Some(value) => value,
            None => panic!("large-page parent became inaccessible after invalidation"),
        };
    if invalidated_parent & PRESENT != 0
        || invalidated_parent & !(ACCESSED_DIRTY_MASK | PRESENT)
            != original_parent & !(ACCESSED_DIRTY_MASK | PRESENT)
        || (invalidated_parent & ACCESSED_DIRTY_MASK & expected_parent)
            != (expected_parent & ACCESSED_DIRTY_MASK)
    {
        panic!("large-page parent changed unexpectedly after invalidation");
    }

    // The parent is now non-present and the old walk is quiescent. Validate
    // the final A/D sample, but do not rewrite child entries in this interval:
    // the demoted mapping may have been the only alias through which the
    // unpublished child table was writable. Both A/D bits were conservatively
    // pre-set in every child before Present was cleared, so late hardware updates
    // cannot be lost.
    let final_source = invalidated_parent | PRESENT;
    if LargePageDemotion::new(final_source, source_level, physical_address_bits).is_err() {
        panic!("invalidated large-page source no longer validates");
    }

    // Preserve effective access restrictions on the non-leaf pointer. A is
    // retained as a conservative indication that the walk accessed this path;
    // D is leaf state and remains conservatively set on every child, not on the pointer.
    // PAT, GLOBAL, software bits and protection-key bits likewise stay on leaves.
    let parent_flags =
        final_source & (PRESENT | WRITABLE | USER_ACCESSIBLE | NO_EXECUTE | ACCESSED);
    let new_parent = child_table_physical | parent_flags;

    // From here on, callbacks are infallible by contract. Publish only after the
    // final child contents are complete; then commit ownership and flush again.
    editor.write_entry(
        parent_table_physical,
        parent_index,
        source_level,
        new_parent,
    );
    editor.commit_table_publication(root_table_physical, child_table_physical, child_level);
    editor.invalidate_local_range(virtual_base, source_page_size);

    Ok(LargePageDemotionReceipt {
        root_table_physical,
        parent_table_physical,
        parent_index,
        child_table_physical,
        source_level,
        child_level,
        virtual_start: virtual_base,
        virtual_length: source_page_size,
        physical_start: plan.physical_base(),
    })
}

fn valid_table_frame(physical_address: u64, physical_address_bits: u8) -> bool {
    physical_address != 0
        && physical_address & (PAGE_SIZE - 1) == 0
        && physical_address < (1u64 << physical_address_bits)
}

#[cfg(test)]
mod tests {
    use super::{
        demote_large_page, LargePageDemotionEditor, LargePageDemotionTransactionError, PAGE_SIZE,
    };
    use crate::LargePageDemotionError;
    use std::collections::BTreeMap;
    use std::{vec, vec::Vec};

    const PRESENT: u64 = 1;
    const WRITABLE: u64 = 1 << 1;
    const USER_ACCESSIBLE: u64 = 1 << 2;
    const ACCESSED: u64 = 1 << 5;
    const DIRTY: u64 = 1 << 6;
    const ACCESSED_DIRTY_MASK: u64 = ACCESSED | DIRTY;
    const WRITE_THROUGH: u64 = 1 << 3;
    const CACHE_DISABLE: u64 = 1 << 4;
    const LARGE_PAGE: u64 = 1 << 7;
    const GLOBAL: u64 = 1 << 8;
    const LARGE_PAGE_PAT: u64 = 1 << 12;
    const NO_EXECUTE: u64 = 1 << 63;
    const PHYSICAL_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;

    const ROOT: u64 = 0x1000;
    const PARENT: u64 = 0x2000;
    const CHILD: u64 = 0x8000;

    struct MockEditor {
        tables: BTreeMap<u64, [u64; 512]>,
        width: u8,
        next_table: u64,
        fail_allocation: bool,
        fail_reservation: bool,
        change_parent_before_compare_exchange: bool,
        parent_change_injected: bool,
        inject_accessed_on_first_compare_exchange: bool,
        accessed_injected: bool,
        inject_dirty_during_first_invalidation: bool,
        dirty_injected: bool,
        parent_index: usize,
        reservations: Vec<(u64, u8)>,
        published: Vec<(u64, u8)>,
        freed: Vec<u64>,
        invalidations: Vec<(u64, u64)>,
    }

    impl MockEditor {
        fn new(parent_index: usize, source_entry: u64) -> Self {
            let mut tables = BTreeMap::new();
            tables.insert(ROOT, [0; 512]);
            let mut parent = [0; 512];
            parent[parent_index] = source_entry;
            tables.insert(PARENT, parent);
            Self {
                tables,
                width: 48,
                next_table: CHILD,
                fail_allocation: false,
                fail_reservation: false,
                change_parent_before_compare_exchange: false,
                parent_change_injected: false,
                inject_accessed_on_first_compare_exchange: false,
                accessed_injected: false,
                inject_dirty_during_first_invalidation: false,
                dirty_injected: false,
                parent_index,
                reservations: Vec::new(),
                published: Vec::new(),
                freed: Vec::new(),
                invalidations: Vec::new(),
            }
        }

        fn entry(&self, table: u64, index: usize) -> u64 {
            self.tables[&table][index]
        }

        fn allocated_child(&self) -> &[u64; 512] {
            &self.tables[&CHILD]
        }
    }

    impl LargePageDemotionEditor for MockEditor {
        fn physical_address_bits(&self) -> u8 {
            self.width
        }

        fn read_entry(&mut self, table: u64, index: usize, _level: u8) -> Option<u64> {
            self.tables.get(&table).map(|entries| entries[index])
        }

        fn write_entry(&mut self, table: u64, index: usize, _level: u8, value: u64) {
            self.tables.get_mut(&table).expect("validated table")[index] = value;
        }

        fn compare_exchange_entry(
            &mut self,
            table: u64,
            index: usize,
            _level: u8,
            expected: u64,
            replacement: u64,
        ) -> Result<(), u64> {
            if table == PARENT
                && self.change_parent_before_compare_exchange
                && !self.parent_change_injected
            {
                self.tables.get_mut(&PARENT).expect("parent table")[index] = 0;
                self.parent_change_injected = true;
            }
            if table == PARENT
                && self.inject_accessed_on_first_compare_exchange
                && !self.accessed_injected
            {
                self.tables.get_mut(&PARENT).expect("parent table")[index] |= ACCESSED;
                self.accessed_injected = true;
            }
            let current = *self
                .tables
                .get(&table)
                .expect("table exists")
                .get(index)
                .expect("entry index is valid");
            if current != expected {
                return Err(current);
            }
            self.tables.get_mut(&table).expect("validated table")[index] = replacement;
            Ok(())
        }

        fn allocate_table(&mut self) -> Option<u64> {
            if self.fail_allocation {
                return None;
            }
            let frame = self.next_table;
            self.next_table += PAGE_SIZE;
            self.tables.insert(frame, [0; 512]);
            Some(frame)
        }

        fn reserve_table_publication(&mut self, _root: u64, child: u64, level: u8) -> bool {
            if self.fail_reservation {
                return false;
            }
            self.reservations.push((child, level));
            true
        }

        fn commit_table_publication(&mut self, _root: u64, child: u64, level: u8) {
            self.reservations.retain(|entry| *entry != (child, level));
            self.published.push((child, level));
        }

        fn release_unpublished_table(&mut self, child: u64) {
            self.reservations.retain(|entry| entry.0 != child);
            self.tables.remove(&child);
            self.freed.push(child);
        }

        fn invalidate_local_range(&mut self, start: u64, length: u64) {
            if self.inject_dirty_during_first_invalidation && !self.dirty_injected {
                let parent = self.tables.get_mut(&PARENT).expect("parent table");
                if parent[self.parent_index] & PRESENT == 0 {
                    parent[self.parent_index] |= DIRTY;
                    self.dirty_injected = true;
                }
            }
            self.invalidations.push((start, length));
        }
    }

    #[test]
    fn demotes_2m_leaf_transactionally_and_preserves_effective_attributes() {
        let virtual_base = 0xffff_8000_0000_0000;
        let physical_base = 0x0200_0000;
        let source = physical_base
            | PRESENT
            | LARGE_PAGE
            | WRITABLE
            | WRITE_THROUGH
            | CACHE_DISABLE
            | LARGE_PAGE_PAT
            | GLOBAL
            | NO_EXECUTE;
        let mut editor = MockEditor::new(0, source);

        let receipt = demote_large_page(&mut editor, ROOT, PARENT, 2, 0, virtual_base).unwrap();

        assert_eq!(receipt.child_table_physical, CHILD);
        assert_eq!(receipt.source_level, 2);
        assert_eq!(receipt.child_level, 1);
        assert_eq!(receipt.virtual_length, 1 << 21);
        assert_eq!(receipt.physical_start, physical_base);
        assert_eq!(
            editor.entry(PARENT, 0),
            CHILD | PRESENT | WRITABLE | NO_EXECUTE
        );
        assert_eq!(
            editor.entry(CHILD, 0) & PHYSICAL_ADDRESS_MASK,
            physical_base
        );
        assert_eq!(
            editor.entry(CHILD, 511) & PHYSICAL_ADDRESS_MASK,
            physical_base + 511 * PAGE_SIZE
        );
        assert_ne!(
            editor.entry(CHILD, 0) & (1 << 7),
            0,
            "4 KiB PAT moves to bit 7"
        );
        assert_ne!(editor.entry(CHILD, 0) & WRITE_THROUGH, 0);
        assert_ne!(editor.entry(CHILD, 0) & CACHE_DISABLE, 0);
        assert_ne!(editor.entry(CHILD, 0) & GLOBAL, 0);
        assert_eq!(editor.published, vec![(CHILD, 1)]);
        assert!(editor.reservations.is_empty());
        assert_eq!(
            editor.invalidations,
            vec![(virtual_base, 1 << 21), (virtual_base, 1 << 21)]
        );
        assert!(editor.freed.is_empty());
    }

    #[test]
    fn demotes_1g_leaf_into_512_2m_leaves() {
        let virtual_base = 0x4000_0000;
        let physical_base = 0x4000_0000;
        let source = physical_base | PRESENT | LARGE_PAGE | LARGE_PAGE_PAT | USER_ACCESSIBLE;
        let mut editor = MockEditor::new(1, source);

        let receipt = demote_large_page(&mut editor, ROOT, PARENT, 3, 1, virtual_base).unwrap();

        assert_eq!(receipt.child_level, 2);
        assert_eq!(receipt.virtual_length, 1 << 30);
        assert_eq!(receipt.physical_start, physical_base);
        assert_eq!(editor.entry(PARENT, 1), CHILD | PRESENT | USER_ACCESSIBLE);
        assert_eq!(
            editor.allocated_child()[0] & PHYSICAL_ADDRESS_MASK & !((1 << 21) - 1),
            physical_base
        );
        assert_eq!(
            editor.allocated_child()[511] & PHYSICAL_ADDRESS_MASK & !((1 << 21) - 1),
            physical_base + 511 * (1 << 21)
        );
        assert_ne!(editor.allocated_child()[511] & LARGE_PAGE, 0);
        for (index, entry) in editor.allocated_child().iter().enumerate() {
            assert_eq!(
                entry & ACCESSED_DIRTY_MASK,
                ACCESSED_DIRTY_MASK,
                "child {index} is conservatively marked accessed and dirty before publication"
            );
        }
        assert_ne!(
            editor.allocated_child()[0] & LARGE_PAGE_PAT,
            0,
            "large-page PAT remains at bit 12 in 2 MiB children"
        );
        assert_eq!(
            editor.invalidations,
            vec![(virtual_base, 1 << 30), (virtual_base, 1 << 30)]
        );
    }

    #[test]
    fn allocation_failure_leaves_parent_unchanged() {
        let source = 0x0200_0000 | PRESENT | LARGE_PAGE;
        let mut editor = MockEditor::new(0, source);
        editor.fail_allocation = true;

        assert_eq!(
            demote_large_page(&mut editor, ROOT, PARENT, 2, 0, 0xffff_8000_0000_0000),
            Err(LargePageDemotionTransactionError::TableAllocationFailed)
        );
        assert_eq!(editor.entry(PARENT, 0), source);
        assert!(editor.invalidations.is_empty());
        assert!(editor.freed.is_empty());
    }

    #[test]
    fn registration_failure_releases_unpublished_table_without_parent_mutation() {
        let source = 0x0200_0000 | PRESENT | LARGE_PAGE;
        let mut editor = MockEditor::new(0, source);
        editor.fail_reservation = true;

        assert_eq!(
            demote_large_page(&mut editor, ROOT, PARENT, 2, 0, 0xffff_8000_0000_0000),
            Err(LargePageDemotionTransactionError::TablePublicationReservationFailed)
        );
        assert_eq!(editor.entry(PARENT, 0), source);
        assert_eq!(editor.freed, vec![CHILD]);
        assert!(editor.invalidations.is_empty());
    }

    #[test]
    fn refuses_to_overwrite_a_parent_changed_during_staging() {
        let source = 0x0200_0000 | PRESENT | LARGE_PAGE;
        let mut editor = MockEditor::new(0, source);
        editor.change_parent_before_compare_exchange = true;

        assert_eq!(
            demote_large_page(&mut editor, ROOT, PARENT, 2, 0, 0xffff_8000_0000_0000),
            Err(LargePageDemotionTransactionError::ParentEntryChanged)
        );
        assert_eq!(editor.entry(PARENT, 0), 0);
        assert_eq!(editor.freed, vec![CHILD]);
        assert!(editor.published.is_empty());
        assert!(editor.invalidations.is_empty());
    }

    #[test]
    fn recovers_hardware_accessed_and_dirty_updates_before_publishing_children() {
        let virtual_base = 0xffff_8000_0000_0000;
        let physical_base = 0x0200_0000;
        let source = physical_base | PRESENT | LARGE_PAGE | WRITABLE;
        let mut editor = MockEditor::new(0, source);
        editor.inject_accessed_on_first_compare_exchange = true;
        editor.inject_dirty_during_first_invalidation = true;

        let receipt = demote_large_page(&mut editor, ROOT, PARENT, 2, 0, virtual_base).unwrap();

        assert_eq!(receipt.physical_start, physical_base);
        assert!(editor.accessed_injected);
        assert!(editor.dirty_injected);
        assert_eq!(
            editor.entry(PARENT, 0) & ACCESSED_DIRTY_MASK,
            ACCESSED,
            "accessed state is conservatively retained on the new table pointer"
        );
        for index in 0..512 {
            assert_eq!(
                editor.entry(CHILD, index) & ACCESSED_DIRTY_MASK,
                ACCESSED_DIRTY_MASK,
                "child {index} must not lose hardware A/D state"
            );
        }
        assert_eq!(
            editor.invalidations,
            vec![(virtual_base, 1 << 21), (virtual_base, 1 << 21)]
        );
        assert!(editor.freed.is_empty());
    }

    #[test]
    fn rejects_misaligned_or_mismatched_virtual_ranges_before_allocation() {
        let source = 0x0200_0000 | PRESENT | LARGE_PAGE;
        let mut editor = MockEditor::new(0, source);

        assert_eq!(
            demote_large_page(&mut editor, ROOT, PARENT, 2, 0, 0xffff_8000_0000_1000),
            Err(LargePageDemotionTransactionError::MisalignedVirtualAddress)
        );
        assert_eq!(
            demote_large_page(&mut editor, ROOT, PARENT, 2, 1, 0xffff_8000_0000_0000),
            Err(LargePageDemotionTransactionError::InvalidParentIndex)
        );
        assert_eq!(editor.next_table, CHILD);
        assert!(editor.freed.is_empty());
    }

    #[test]
    fn rejects_zero_root_or_parent_frames_before_allocating() {
        let source = 0x0200_0000 | PRESENT | LARGE_PAGE;
        let mut editor = MockEditor::new(0, source);

        assert_eq!(
            demote_large_page(&mut editor, 0, PARENT, 2, 0, 0xffff_8000_0000_0000),
            Err(LargePageDemotionTransactionError::InvalidPhysicalAddress)
        );
        assert_eq!(
            demote_large_page(&mut editor, ROOT, 0, 2, 0, 0xffff_8000_0000_0000),
            Err(LargePageDemotionTransactionError::InvalidPhysicalAddress)
        );
        assert_eq!(editor.next_table, CHILD);
        assert_eq!(editor.entry(PARENT, 0), source);
        assert!(editor.freed.is_empty());
        assert!(editor.published.is_empty());
        assert!(editor.invalidations.is_empty());
    }

    #[test]
    fn releases_and_rejects_a_zero_child_table_frame() {
        let source = 0x0200_0000 | PRESENT | LARGE_PAGE;
        let mut editor = MockEditor::new(0, source);
        editor.next_table = 0;

        assert_eq!(
            demote_large_page(&mut editor, ROOT, PARENT, 2, 0, 0xffff_8000_0000_0000),
            Err(LargePageDemotionTransactionError::InvalidPhysicalAddress)
        );
        assert_eq!(editor.entry(PARENT, 0), source);
        assert_eq!(editor.freed, vec![0]);
        assert!(editor.published.is_empty());
        assert!(editor.invalidations.is_empty());
    }

    #[test]
    fn invalid_source_is_rejected_before_allocating_a_table() {
        let mut editor = MockEditor::new(0, PRESENT);
        assert!(matches!(
            demote_large_page(&mut editor, ROOT, PARENT, 2, 0, 0xffff_8000_0000_0000),
            Err(LargePageDemotionTransactionError::InvalidSource(
                LargePageDemotionError::NotLargePage
            ))
        ));
        assert_eq!(editor.next_table, CHILD);
    }
}
