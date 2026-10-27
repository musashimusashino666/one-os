use super::*;

pub fn audit_registered_wx_roots(
    boot_info: &BootInfo,
    root_table_physical: u64,
    recursive_index: u16,
    physical_address_bits: u8,
) -> Result<
    (
        FrameWxAuditSummary,
        FrameWxAuditScopeSummary<MAX_WX_AUDIT_ROOTS>,
    ),
    PagingError,
> {
    if active_root_table_physical() != root_table_physical {
        return Err(PagingError::WxAuditFailed);
    }

    // All root and table-registry mutations use the current single-CPU,
    // maskable-interrupts-disabled contract. Refuse to snapshot otherwise.
    let mut active_editor =
        KernelPageTableEditor::new_for_readonly_audit(boot_info, 0, recursive_index)
            .map_err(|_| PagingError::WxAuditFailed)?;
    let mut audit = FrameWxAudit::<MAX_WX_AUDIT_RANGES>::new(physical_address_bits)
        .map_err(|_| PagingError::WxAuditFailed)?;
    let mut scope = FrameWxAuditScope::<MAX_WX_AUDIT_ROOTS>::new(physical_address_bits)
        .map_err(|_| PagingError::WxAuditFailed)?;

    let active_root_pointer = active_editor
        .audit_table_pointer(root_table_physical, 4)
        .ok_or(PagingError::WxAuditFailed)?;
    if find_root_recursive_index(
        active_root_pointer,
        root_table_physical,
        physical_address_bits,
    )? != recursive_index
    {
        return Err(PagingError::WxAuditFailed);
    }

    scope
        .declare_root(root_table_physical)
        .map_err(|_| PagingError::WxAuditFailed)?;

    // Snapshot registered roots into bounded local storage before sealing the
    // inventory. Reject malformed, duplicate, stale, or unowned entries rather
    // than silently shrinking the declared root set.
    let mut registered_roots = [0u64; ADDRESS_SPACE_ROOT_CAPACITY];
    let mut registered_root_count = 0usize;
    for slot in ADDRESS_SPACE_ROOT_FRAMES.iter() {
        let registered_root = slot.load(Ordering::Acquire);
        if registered_root == 0 {
            continue;
        }
        if !valid_physical_page(registered_root, physical_address_bits)
            || !is_address_space_root_frame(registered_root)
            || !matches!(crate::memory::is_frame_allocated(registered_root), Ok(true))
            || registered_roots[..registered_root_count].contains(&registered_root)
        {
            return Err(PagingError::WxAuditFailed);
        }
        registered_roots[registered_root_count] = registered_root;
        registered_root_count += 1;
        if registered_root != root_table_physical {
            scope
                .declare_root(registered_root)
                .map_err(|_| PagingError::WxAuditFailed)?;
        }
    }
    scope
        .seal_root_inventory()
        .map_err(|_| PagingError::WxAuditFailed)?;

    let mut visited_path = [0u64; 4];
    let mut table_budget = FrameWxAuditTableBudget::<MAX_WX_AUDIT_TABLES>::new();
    let mut recursive_aliases = RecursiveAliasSet::new()?;

    // Walk the active root in full. Its non-recursive PML4 entries are the
    // reference for the shared kernel half in every kernel-created root.
    audit_wx_table(
        boot_info,
        recursive_index,
        physical_address_bits,
        root_table_physical,
        recursive_index,
        root_table_physical,
        4,
        0,
        true,
        true,
        AuditRootRange::All,
        true,
        Some(recursive_index),
        &mut recursive_aliases,
        &mut visited_path,
        0,
        &mut table_budget,
        &mut audit,
    )?;
    scope
        .mark_root_audited(root_table_physical)
        .map_err(|_| PagingError::WxAuditFailed)?;

    // Inactive roots inherit the upper-half mappings and keep private lower-half
    // tables. Verify every shared upper PML4 entry against the active root, then
    // walk every present lower-half mapping through a validated physical-offset
    // alias and per-root table-ownership records.
    for registered_root in registered_roots[..registered_root_count].iter().copied() {
        if registered_root == root_table_physical {
            continue;
        }

        let target_root_alias = active_editor
            .offset_alias(registered_root)
            .ok_or(PagingError::WxAuditFailed)?;
        if target_root_alias as usize & (PAGE_SIZE as usize - 1) != 0 {
            return Err(PagingError::WxAuditFailed);
        }
        let target_root_pointer = target_root_alias.cast::<u64>().cast_const();
        let target_recursive_index =
            find_root_recursive_index(target_root_pointer, registered_root, physical_address_bits)?;
        if target_recursive_index < LOWER_HALF_PML4_ENTRIES as u16
            || target_recursive_index == recursive_index
        {
            return Err(PagingError::WxAuditFailed);
        }
        validate_shared_kernel_half(
            active_root_pointer,
            target_root_pointer,
            root_table_physical,
            registered_root,
            recursive_index,
            target_recursive_index,
        )?;

        audit_wx_table(
            boot_info,
            recursive_index,
            physical_address_bits,
            registered_root,
            target_recursive_index,
            registered_root,
            4,
            0,
            true,
            true,
            AuditRootRange::LowerHalf,
            true,
            Some(target_recursive_index),
            &mut recursive_aliases,
            &mut visited_path,
            0,
            &mut table_budget,
            &mut audit,
        )?;
        scope
            .mark_root_audited(registered_root)
            .map_err(|_| PagingError::WxAuditFailed)?;
    }

    // Compare the collected recursive page-table aliases against the complete
    // leaf inventory only after all roots have been walked; doing this late avoids
    // missing executable leaves that appear later in page-table traversal order.
    recursive_aliases.check_conflicts(&mut audit)?;

    // All present W/X leaves in every declared root were enumerated before this
    // point, including any physical-offset/direct-map aliases; those aliases are
    // ordinary PTE-derived mappings, not a second mapping store. The recursive
    // self-reference slots are omitted from the ordinary walk, then separately
    // audited above for every root by observing each reachable table-frame alias
    // against the complete executable/writable leaf inventory.
    scope.account_source(FrameWxAuditSource::PhysicalMemoryOffsetAlias);
    scope.account_source(FrameWxAuditSource::RecursivePageTableView);
    scope.account_source(FrameWxAuditSource::SharedKernelMappings);
    scope.account_source(FrameWxAuditSource::LargePageLeaves);

    // A complete walk is meaningful only if the active CR3 and the authoritative
    // registered-root set remained stable throughout the audit. Revalidate both
    // before returning any summary; a changed or malformed inventory fails closed.
    if !frame_wx_audit_snapshot_matches(
        root_table_physical,
        active_root_table_physical(),
        &registered_roots[..registered_root_count],
        ADDRESS_SPACE_ROOT_FRAMES.len(),
        |index| ADDRESS_SPACE_ROOT_FRAMES[index].load(Ordering::Acquire),
    ) {
        return Err(PagingError::WxAuditFailed);
    }

    let scope_summary = scope.summary();
    if !scope_summary.complete {
        return Err(PagingError::WxAuditFailed);
    }

    Ok((audit.summary(), scope_summary))
}

fn find_root_recursive_index(
    root_pointer: *const u64,
    root_physical: u64,
    physical_address_bits: u8,
) -> Result<u16, PagingError> {
    if !valid_physical_page(root_physical, physical_address_bits) {
        return Err(PagingError::WxAuditFailed);
    }
    let mut found = None;
    for index in 0..PML4_ENTRY_COUNT {
        // SAFETY: the caller has already validated this complete PML4 page.
        let entry = unsafe { ptr::read_volatile(root_pointer.add(index)) };
        if entry & PRESENT == 0 || entry & PHYSICAL_ADDRESS_MASK != root_physical {
            continue;
        }
        if entry & LARGE_PAGE != 0
            || entry & WRITABLE == 0
            || entry & USER_ACCESSIBLE != 0
            || entry & NO_EXECUTE == 0
            || entry & PROTECTION_KEY_FIELD_MASK != 0
            || found.is_some()
        {
            return Err(PagingError::WxAuditFailed);
        }
        found = Some(index as u16);
    }
    found.ok_or(PagingError::WxAuditFailed)
}

fn validate_shared_kernel_half(
    active_root_pointer: *const u64,
    target_root_pointer: *const u64,
    active_root_physical: u64,
    target_root_physical: u64,
    active_recursive_index: u16,
    target_recursive_index: u16,
) -> Result<(), PagingError> {
    let active_index = usize::from(active_recursive_index);
    let target_index = usize::from(target_recursive_index);
    if !(LOWER_HALF_PML4_ENTRIES..PML4_ENTRY_COUNT).contains(&active_index)
        || !(LOWER_HALF_PML4_ENTRIES..PML4_ENTRY_COUNT).contains(&target_index)
        || active_index == target_index
    {
        return Err(PagingError::WxAuditFailed);
    }

    // Validate special slots before omitting them from the ordinary shared-entry
    // comparison. Each root must self-reference at its own slot, and the other
    // root's reserved recursive slot must be exactly empty.
    let slots = SharedRecursiveSlotEntries {
        // SAFETY: both roots have been validated as complete PML4 frames.
        active_self_entry: unsafe { ptr::read_volatile(active_root_pointer.add(active_index)) },
        // SAFETY: both indices have been range-checked above.
        active_target_slot: unsafe { ptr::read_volatile(active_root_pointer.add(target_index)) },
        // SAFETY: both indices have been range-checked above.
        target_active_slot: unsafe { ptr::read_volatile(target_root_pointer.add(active_index)) },
        // SAFETY: both indices have been range-checked above.
        target_self_entry: unsafe { ptr::read_volatile(target_root_pointer.add(target_index)) },
    };
    if !shared_recursive_slots_are_valid(
        active_root_physical,
        target_root_physical,
        active_recursive_index,
        target_recursive_index,
        slots,
    ) {
        return Err(PagingError::WxAuditFailed);
    }

    for index in LOWER_HALF_PML4_ENTRIES..PML4_ENTRY_COUNT {
        if index == active_index || index == target_index {
            continue;
        }
        // SAFETY: both root pointers refer to complete validated PML4 frames.
        let active_entry = unsafe { ptr::read_volatile(active_root_pointer.add(index)) };
        // SAFETY: same as above for the target root.
        let target_entry = unsafe { ptr::read_volatile(target_root_pointer.add(index)) };
        if active_entry != target_entry {
            return Err(PagingError::WxAuditFailed);
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuditRootRange {
    All,
    LowerHalf,
}

// Store audit scratch in BSS rather than the constrained bootstrap/kernel stack.
// The lease prevents re-entrant or concurrent walkers from observing each other's
// entries; this OS currently requires single-CPU, maskable-interrupts-disabled use.
// Table-path inventory has a separate fixed capacity and fails the audit closed if
// it fills; it catches a table frame reached through two different virtual paths.
static WX_AUDIT_RECURSIVE_FRAMES_BUSY: AtomicBool = AtomicBool::new(false);
static mut WX_AUDIT_RECURSIVE_FRAMES: [u64; MAX_WX_AUDIT_RECURSIVE_FRAMES] =
    [0; MAX_WX_AUDIT_RECURSIVE_FRAMES];
static mut WX_AUDIT_RECURSIVE_VIRTUALS: [u64; MAX_WX_AUDIT_RECURSIVE_FRAMES] =
    [0; MAX_WX_AUDIT_RECURSIVE_FRAMES];
static mut WX_AUDIT_VISITED_TABLES: [u64; MAX_WX_AUDIT_TABLE_PATHS] = [0; MAX_WX_AUDIT_TABLE_PATHS];

/// Physical frames whose writable recursive aliases must be checked after the
/// complete ordinary leaf inventory has been collected. Shared page-table frames
/// are deduplicated because another root's recursive alias has the same physical
/// extent and effective W/NX rights once shared PML4 entries are validated equal.
struct RecursiveAliasSet {
    count: usize,
    visited_table_count: usize,
}

impl RecursiveAliasSet {
    fn new() -> Result<Self, PagingError> {
        WX_AUDIT_RECURSIVE_FRAMES_BUSY
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| PagingError::WxAuditFailed)?;
        Ok(Self {
            count: 0,
            visited_table_count: 0,
        })
    }

    /// Records every table in the declared walk, not only tables with writable
    /// recursive aliases. A duplicate physical frame is an unsupported shared or
    /// cyclic table path and therefore makes the audit incomplete.
    fn visit_table(&mut self, table_physical: u64) -> Result<(), PagingError> {
        // SAFETY: the audit lease is held for this object's lifetime and the
        // count is bounded by the fixed table-path buffer.
        let table_frames = core::ptr::addr_of!(WX_AUDIT_VISITED_TABLES).cast::<u64>();
        // SAFETY: only initialized entries below visited_table_count are exposed.
        let visited =
            unsafe { core::slice::from_raw_parts(table_frames, self.visited_table_count) };
        if !frame_wx_audit_table_path_is_unique(visited, table_physical, MAX_WX_AUDIT_TABLE_PATHS) {
            return Err(PagingError::WxAuditFailed);
        }
        // SAFETY: the exclusive audit lease is held and capacity was checked above.
        unsafe {
            ptr::write(
                core::ptr::addr_of_mut!(WX_AUDIT_VISITED_TABLES)
                    .cast::<u64>()
                    .add(self.visited_table_count),
                table_physical,
            );
        }
        self.visited_table_count += 1;
        Ok(())
    }

    fn observe(
        &mut self,
        physical_frame: u64,
        recursive_virtual_address: u64,
        effective_writable: bool,
    ) -> Result<(), PagingError> {
        if !is_canonical_4level(recursive_virtual_address)
            || recursive_virtual_address & (PAGE_SIZE - 1) != 0
        {
            return Err(PagingError::WxAuditFailed);
        }
        if !effective_writable {
            return Ok(());
        }

        // SAFETY: the atomic lease grants this audit exclusive use of the fixed
        // BSS buffer. The function is called only under the kernel's documented
        // single-CPU, maskable-interrupts-disabled inspection contract.
        let frames = core::ptr::addr_of_mut!(WX_AUDIT_RECURSIVE_FRAMES).cast::<u64>();
        for index in 0..self.count {
            // SAFETY: index is strictly below count, which is only increased after
            // writing a slot below MAX_WX_AUDIT_RECURSIVE_FRAMES.
            if unsafe { ptr::read(frames.add(index)) } == physical_frame {
                return Ok(());
            }
        }
        if self.count == MAX_WX_AUDIT_RECURSIVE_FRAMES {
            return Err(PagingError::WxAuditFailed);
        }
        // SAFETY: the exclusive lease is held and count is below the fixed capacity.
        unsafe {
            ptr::write(frames.add(self.count), physical_frame);
            ptr::write(
                core::ptr::addr_of_mut!(WX_AUDIT_RECURSIVE_VIRTUALS)
                    .cast::<u64>()
                    .add(self.count),
                recursive_virtual_address,
            );
        }
        self.count += 1;
        Ok(())
    }

    fn check_conflicts<const CAPACITY: usize>(
        &self,
        audit: &mut FrameWxAudit<CAPACITY>,
    ) -> Result<(), PagingError> {
        // SAFETY: this set still owns the exclusive lease; all indices are below count.
        let frames = core::ptr::addr_of!(WX_AUDIT_RECURSIVE_FRAMES).cast::<u64>();
        let virtuals = core::ptr::addr_of!(WX_AUDIT_RECURSIVE_VIRTUALS).cast::<u64>();
        for index in 0..self.count {
            // SAFETY: index is below the successfully populated candidate count.
            let physical_frame = unsafe { ptr::read(frames.add(index)) };
            // SAFETY: the same index was populated with the validated recursive VA.
            let virtual_address = unsafe { ptr::read(virtuals.add(index)) };
            audit
                .observe_alias(
                    virtual_address,
                    physical_frame,
                    PAGE_SIZE,
                    FrameWxPermissions::new(true, false),
                )
                .map_err(|_| PagingError::WxAuditFailed)?;
        }
        Ok(())
    }
}

impl Drop for RecursiveAliasSet {
    fn drop(&mut self) {
        WX_AUDIT_RECURSIVE_FRAMES_BUSY.store(false, Ordering::Release);
    }
}

/// Walks a bounded page-table subtree and optionally records ordinary leaves or
/// the writable/NX recursive alias of each reachable page-table frame.
#[allow(clippy::too_many_arguments)]
fn audit_wx_table<const CAPACITY: usize>(
    boot_info: &BootInfo,
    active_recursive_index: u16,
    physical_address_bits: u8,
    audit_root_physical: u64,
    audit_root_recursive_index: u16,
    table_physical: u64,
    level: u8,
    virtual_prefix: u64,
    ancestors_writable: bool,
    ancestors_executable: bool,
    root_range: AuditRootRange,
    record_leaf_mappings: bool,
    recursive_view_index: Option<u16>,
    recursive_aliases: &mut RecursiveAliasSet,
    visited_path: &mut [u64; 4],
    depth: usize,
    table_budget: &mut FrameWxAuditTableBudget<MAX_WX_AUDIT_TABLES>,
    audit: &mut FrameWxAudit<CAPACITY>,
) -> Result<(), PagingError> {
    if !(1..=4).contains(&level)
        || depth >= visited_path.len()
        || visited_path[..depth].contains(&table_physical)
    {
        return Err(PagingError::WxAuditFailed);
    }
    recursive_aliases.visit_table(table_physical)?;
    table_budget
        .visit()
        .map_err(|_| PagingError::WxAuditFailed)?;
    visited_path[depth] = table_physical;

    if let Some(view_index) = recursive_view_index {
        // The root self-reference is required to be supervisor-only, writable,
        // and NX. Ancestor permissions on the ordinary path remain effective
        // for aliases to lower-level tables. The virtual alias is validated now,
        // but physical conflicts are checked after all ordinary leaves are known.
        let view_virtual = recursive_table_page_virtual_address(
            view_index,
            if level == 4 { 0 } else { virtual_prefix },
            level,
        )
        .ok_or(PagingError::WxAuditFailed)?;
        recursive_aliases.observe(table_physical, view_virtual, ancestors_writable)?;
    }

    // The active root is read through its checked recursive alias. For an
    // inactive root, only its root frame and ownership-registered private
    // lower-half tables may be read through a validated physical-offset alias.
    let target_virtual_address = if level == 4 { 0 } else { virtual_prefix };
    let mut editor = KernelPageTableEditor::new_for_readonly_audit(
        boot_info,
        target_virtual_address,
        active_recursive_index,
    )
    .map_err(|_| PagingError::WxAuditFailed)?;
    let table_pointer = editor
        .audit_table_pointer_for_root(audit_root_physical, table_physical, level, virtual_prefix)
        .ok_or(PagingError::WxAuditFailed)?;

    let (first_entry, end_entry) = if level != 4 {
        (0, PML4_ENTRY_COUNT)
    } else {
        match root_range {
            AuditRootRange::All => (0, PML4_ENTRY_COUNT),
            AuditRootRange::LowerHalf => (0, LOWER_HALF_PML4_ENTRIES),
        }
    };
    for index in first_entry..end_entry {
        // Each root's recursive slot is omitted: recursive page-table views are
        // a separate source that must not be confused with ordinary leaf maps.
        if level == 4 && index == usize::from(audit_root_recursive_index) {
            continue;
        }
        // SAFETY: the table-pointer helper validated the complete table frame;
        // index is below both the selected entry bound and the PML4 entry count.
        let entry = unsafe { ptr::read_volatile(table_pointer.add(index)) };
        // Non-present entries may carry OS-defined software metadata.
        // Ignore their other bits rather than treating them as malformed mappings.
        if entry & PRESENT == 0 {
            continue;
        }
        let large_page = level > 1 && entry & LARGE_PAGE != 0;
        if level == 4 && large_page {
            return Err(PagingError::WxAuditFailed);
        }
        if level > 1 && !large_page && entry & PROTECTION_KEY_FIELD_MASK != 0 {
            return Err(PagingError::WxAuditFailed);
        }

        let raw_physical = entry & PHYSICAL_ADDRESS_MASK;
        if raw_physical >= (1u64 << physical_address_bits) {
            return Err(PagingError::WxAuditFailed);
        }
        let writable = ancestors_writable && entry & WRITABLE != 0;
        let executable = ancestors_executable && entry & NO_EXECUTE == 0;
        let shift = 12 + (9 * (level - 1));
        let virtual_start = if level == 4 {
            let prefix = (index as u64) << 39;
            if index >= LOWER_HALF_PML4_ENTRIES {
                prefix | 0xffff_0000_0000_0000
            } else {
                prefix
            }
        } else {
            virtual_prefix | ((index as u64) << shift)
        };

        if level == 1 || large_page {
            let page_size = if large_page { 1u64 << shift } else { PAGE_SIZE };
            if large_page && raw_physical & ((page_size - 1) & !(1 << 12)) != 0 {
                return Err(PagingError::WxAuditFailed);
            }
            let physical_start = raw_physical & !(page_size - 1);
            if record_leaf_mappings {
                audit
                    .record_alias(
                        virtual_start,
                        physical_start,
                        page_size,
                        FrameWxPermissions::new(writable, executable),
                    )
                    .map_err(|_| PagingError::WxAuditFailed)?;
            }
            continue;
        }

        let child_physical = raw_physical;
        if child_physical == 0 || child_physical & (PAGE_SIZE - 1) != 0 {
            return Err(PagingError::WxAuditFailed);
        }
        audit_wx_table(
            boot_info,
            active_recursive_index,
            physical_address_bits,
            audit_root_physical,
            audit_root_recursive_index,
            child_physical,
            level - 1,
            virtual_start,
            writable,
            executable,
            AuditRootRange::All,
            record_leaf_mappings,
            recursive_view_index,
            recursive_aliases,
            visited_path,
            depth + 1,
            table_budget,
            audit,
        )?;
    }
    Ok(())
}
