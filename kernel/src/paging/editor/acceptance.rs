use super::*;

/// Failure from kernel-backed inactive address-space teardown.
///
/// A user-page mutation failure retains its partial result and the remaining
/// registry entries so a caller can decide whether to retry or fail-stop without
/// losing ownership of frames already removed. Do not free, reactivate, or reuse
/// the root merely because this error is returned.
#[derive(Debug)]
pub enum InactiveAddressSpaceTeardownError<const CAPACITY: usize> {
    Kernel(PagingError),
    UserPages(UserPageTeardownFailure<CAPACITY>),
}

impl<const CAPACITY: usize> From<PagingError> for InactiveAddressSpaceTeardownError<CAPACITY> {
    fn from(error: PagingError) -> Self {
        Self::Kernel(error)
    }
}

/// Tears down every registered user page in one inactive root, then reclaims
/// its private lower-half intermediate tables bottom-up.
///
/// The whole private tree is preflighted before the first destructive update.
/// Returned data frames are zeroed again before allocator reuse. The caller must
/// release the PML4 root separately after this succeeds.
pub fn teardown_inactive_user_address_space<const CAPACITY: usize>(
    boot_info: &BootInfo,
    root: &AddressSpaceRoot,
    active_root: &ActiveAddressSpaceRoot,
    registry: &mut UserPageMappingRegistry<ZeroedFrame, CAPACITY>,
) -> Result<(), InactiveAddressSpaceTeardownError<CAPACITY>> {
    let mut release_table_frame = crate::memory::free_frame;
    teardown_inactive_user_address_space_with_table_release(
        boot_info,
        root,
        active_root,
        registry,
        &mut release_table_frame,
    )
}

pub fn teardown_inactive_user_address_space_with_table_release<const CAPACITY: usize, E>(
    boot_info: &BootInfo,
    root: &AddressSpaceRoot,
    active_root: &ActiveAddressSpaceRoot,
    registry: &mut UserPageMappingRegistry<ZeroedFrame, CAPACITY>,
    release_table_frame: &mut impl FnMut(Frame) -> Result<(), (E, Frame)>,
) -> Result<(), InactiveAddressSpaceTeardownError<CAPACITY>> {
    let mut editor = KernelInactiveAddressSpaceEditor::new(boot_info, root, active_root)?;
    preflight_private_user_tree(root.physical_address(), registry, &mut editor)?;

    let mut teardown = match unmap_all_user_data_pages(root, registry, &mut editor) {
        Ok(result) => result,
        // Preserve the error value so its partial result retains every frame
        // token already detached and invalidated by the batch operation.
        Err(failure) => return Err(InactiveAddressSpaceTeardownError::UserPages(failure)),
    };

    let mut initializer =
        unsafe { KernelUserFrameInitializer::new(boot_info, active_root.recursive_index()) };
    let completed = teardown.completed_pages();
    for index in 0..completed {
        let frame = teardown
            .take_frame(index)
            .ok_or(PagingError::UserPageTeardownFailed)?;
        let zeroed = initialize_user_frame(frame, &mut initializer)
            .unwrap_or_else(|(_error, _frame)| panic!("could not re-zero a detached user frame"));
        if let Err((_error, _frame)) = crate::memory::free_frame(zeroed.into_frame()) {
            panic!("allocator failed to release a re-zeroed user frame");
        }
    }
    if registry.available_slots() != CAPACITY {
        return Err(InactiveAddressSpaceTeardownError::Kernel(
            PagingError::UserPageTeardownFailed,
        ));
    }

    reclaim_private_user_tables(root.physical_address(), &mut editor, release_table_frame)?;
    reclaim_pending_detached_private_tables(
        root.physical_address(),
        &mut editor,
        release_table_frame,
    )?;

    // Do not release the PML4 or allow its physical address to be reused while
    // the registry still holds private table ownership records for this root.
    // This detects orphaned table tokens left behind by an earlier partial
    // teardown or a structural mismatch that was not reachable from the tree.
    let remaining_private_tables = TABLE_FRAMES
        .lock()
        .published_count_for_root(root.physical_address())
        .map_err(|_| PagingError::InactivePageTableOwnershipViolation)?;
    if remaining_private_tables != 0 {
        return Err(InactiveAddressSpaceTeardownError::Kernel(
            PagingError::InactivePageTableOwnershipViolation,
        ));
    }

    Ok(())
}

/// Returns whether a detached table token remains registered for a root.
///
/// Used by the normal-boot failure-injection smoke test to prove that a failed
/// allocator release leaves the frame pending and non-reusable.
pub fn has_pending_detached_private_table(root_physical: u64) -> bool {
    TABLE_FRAMES
        .lock()
        .detached_table_for_root(root_physical, 0)
        .is_some()
}

/// Kernel implementation of the unsafe zero-before-publication contract.
///
/// The recursive PML4 index must describe the current CR3 root. It may be the
/// bootloader-provided index before activation or the private index selected for
/// an activated kernel root. The operation is single-CPU and requires maskable
/// interrupts to remain disabled, as enforced by the page-table editor.
pub struct KernelUserFrameInitializer<'a> {
    boot_info: &'a BootInfo,
    recursive_index: u16,
}

impl<'a> KernelUserFrameInitializer<'a> {
    /// Creates an initializer bound to BootInfo and the currently active root's
    /// recursive self-map slot.
    ///
    /// # Safety
    ///
    /// recursive_index must be the valid self-referential PML4 slot of the
    /// current CR3 root, and that root must remain active for the entire call.
    /// The caller must run under the kernel's documented single-CPU,
    /// maskable-interrupts-disabled contract. The implementation verifies the
    /// slot's entry and the full physical-memory-offset translation before use.
    pub unsafe fn new(boot_info: &'a BootInfo, recursive_index: u16) -> Self {
        Self {
            boot_info,
            recursive_index,
        }
    }
}

// SAFETY: zero_frame verifies allocator ownership, excludes active/page-table
// frames, validates the full supervisor-writable/NX alias through the active
// page tables, and verifies all 4096 bytes after writing. Interrupts must remain
// disabled and the current root must not change, as required by the constructor.
unsafe impl UserFrameInitializer for KernelUserFrameInitializer<'_> {
    fn zero_frame(&mut self, frame: &Frame) -> Result<(), UserFrameInitializationError> {
        let physical_address = frame.physical_address();
        let root_physical = active_root_table_physical();
        if physical_address == root_physical
            || !crate::memory::is_frame_allocated(physical_address).unwrap_or(false)
            || registered_table_frame(physical_address)
            || unpublished_table_frame(physical_address)
            || is_address_space_root_frame(physical_address)
        {
            return Err(UserFrameInitializationError::InitializationFailed);
        }

        let physical_memory_offset = match self.boot_info.physical_memory_offset {
            Optional::Some(offset) => offset,
            Optional::None => return Err(UserFrameInitializationError::InitializationFailed),
        };
        let Some(alias_virtual_address) = physical_memory_offset.checked_add(physical_address)
        else {
            return Err(UserFrameInitializationError::InitializationFailed);
        };
        let mut editor = match KernelPageTableEditor::new_with_recursive_index(
            self.boot_info,
            alias_virtual_address,
            self.recursive_index,
        ) {
            Ok(editor) => editor,
            Err(_) => return Err(UserFrameInitializationError::InitializationFailed),
        };
        if !editor.is_usable_frame(physical_address)
            || editor.is_table_frame(physical_address)
            || !editor.is_frame_allocated(physical_address)
        {
            return Err(UserFrameInitializationError::InitializationFailed);
        }
        let Some(alias) = editor.offset_alias(physical_address) else {
            return Err(UserFrameInitializationError::InitializationFailed);
        };
        if alias as usize & (PAGE_SIZE as usize - 1) != 0 {
            return Err(UserFrameInitializationError::InitializationFailed);
        }

        // SAFETY: offset_alias proved that all 4096 bytes resolve to this exact,
        // allocated Usable frame through a writable, supervisor-only, NX mapping.
        // Ownership is retained by the caller's Frame token and interrupts are
        // disabled, so this frame cannot be published concurrently in this model.
        unsafe { ptr::write_bytes(alias, 0, PAGE_SIZE as usize) };

        let entries = alias.cast::<u64>();
        for index in 0..(PAGE_SIZE as usize / size_of::<u64>()) {
            // SAFETY: the full page was validated through the same alias above.
            if unsafe { ptr::read_volatile(entries.add(index)) } != 0 {
                return Err(UserFrameInitializationError::InitializationFailed);
            }
        }
        Ok(())
    }
}

/// Exercise the kernel-backed user-frame initializer on an allocated, dirty
/// frame using the bootloader-provided recursive mapping. Dedicated acceptance
/// images call this before any CR3 switch; normal boot uses
/// `verify_user_frame_zeroing_test_with_recursive_index` after activation.
/// This validates the initialization/token gate, not live Ring-3 publication
/// or process isolation.
#[cfg(any(
    feature = "test-exception",
    feature = "test-general-protection",
    feature = "test-page-fault",
    feature = "test-double-fault",
    feature = "test-ist",
    feature = "test-supervisor-write-protection",
    feature = "test-nx-protection",
    feature = "test-vm-transitions"
))]
pub fn verify_user_frame_zeroing_test(boot_info: &BootInfo) -> Result<(), PagingError> {
    let recursive_index = match boot_info.recursive_index {
        Optional::Some(index) if is_safe_recursive_mapping_index(index) => index,
        _ => return Err(PagingError::InvalidRecursiveIndex),
    };
    verify_user_frame_zeroing_test_with_recursive_index(boot_info, recursive_index)
}

/// Runs the user-frame zeroing acceptance test against the supplied active
/// root's recursive self-map. The explicit index is used after CR3 activation,
/// when the bootloader's original recursive index is no longer authoritative.
pub fn verify_user_frame_zeroing_test_with_recursive_index(
    boot_info: &BootInfo,
    recursive_index: u16,
) -> Result<(), PagingError> {
    if !is_safe_recursive_mapping_index(recursive_index) {
        return Err(PagingError::InvalidRecursiveIndex);
    }
    crate::interrupts::write_hex(
        b"ONE OS USER FRAME ZERO TEST RECURSIVE INDEX: ",
        u64::from(recursive_index),
    );

    let frame = crate::memory::allocate_frame().map_err(|_| PagingError::FrameAllocationFailed)?;
    let physical_address = frame.physical_address();
    let physical_memory_offset = match boot_info.physical_memory_offset {
        Optional::Some(offset) => offset,
        _ => {
            let _ = release_data_frame(frame);
            return Err(PagingError::PhysicalMemoryOffsetUnavailable);
        }
    };
    let Some(alias_virtual_address) = physical_memory_offset.checked_add(physical_address) else {
        let _ = release_data_frame(frame);
        return Err(PagingError::PhysicalMemoryOffsetUnavailable);
    };
    let mut editor = match KernelPageTableEditor::new_with_recursive_index(
        boot_info,
        alias_virtual_address,
        recursive_index,
    ) {
        Ok(editor) => editor,
        Err(error) => {
            let _ = release_data_frame(frame);
            return Err(error);
        }
    };
    if !editor.is_usable_frame(physical_address)
        || editor.is_table_frame(physical_address)
        || !editor.is_frame_allocated(physical_address)
    {
        let _ = release_data_frame(frame);
        return Err(PagingError::UserFrameInitializationFailed);
    }
    let Some(alias) = editor.offset_alias(physical_address) else {
        let _ = release_data_frame(frame);
        return Err(PagingError::UserFrameInitializationFailed);
    };

    // Dirty every word, then require the concrete kernel initializer to clear
    // and verify every word before it can return a ZeroedFrame token.
    let words = alias.cast::<u64>();
    for index in 0..(PAGE_SIZE as usize / size_of::<u64>()) {
        let dirty_value = 0xa5a5_5a5a_f0f0_0f0f_u64 ^ index as u64;
        // SAFETY: the checked alias spans this complete allocated data frame.
        unsafe { ptr::write_volatile(words.add(index), dirty_value) };
    }
    crate::interrupts::write_hex(b"ONE OS USER FRAME ZERO TEST DIRTY: ", physical_address);

    // SAFETY: recursive_index was supplied by the active-root owner (or
    // validated from BootInfo before the bootloader-root transition test).
    let mut initializer = unsafe { KernelUserFrameInitializer::new(boot_info, recursive_index) };
    match initialize_user_frame(frame, &mut initializer) {
        Ok(zeroed) => {
            if zeroed.physical_address() != physical_address {
                let _ = release_data_frame(zeroed.into_frame());
                return Err(PagingError::UserFrameInitializationFailed);
            }
            for index in 0..(PAGE_SIZE as usize / size_of::<u64>()) {
                // SAFETY: the initializer validated this exact alias and the
                // test retains the frame's ownership token until verification ends.
                if unsafe { ptr::read_volatile(words.add(index)) } != 0 {
                    let _ = release_data_frame(zeroed.into_frame());
                    return Err(PagingError::UserFrameInitializationFailed);
                }
            }
            crate::interrupts::write_hex(
                b"ONE OS USER FRAME ZERO TEST VERIFIED: ",
                zeroed.physical_address(),
            );
            release_data_frame(zeroed.into_frame())?;
            crate::serial_write(b"ONE OS USER FRAME ZERO TEST PASS\n");
            Ok(())
        }
        Err((_error, frame)) => {
            let _ = release_data_frame(frame);
            Err(PagingError::UserFrameInitializationFailed)
        }
    }
}

pub fn verify_mapping_smoke_test(boot_info: &BootInfo) -> Result<(), PagingError> {
    // The caller has already initialized and smoke-tested the physical allocator.
    let data_frame =
        crate::memory::allocate_frame().map_err(|_| PagingError::FrameAllocationFailed)?;
    let data_physical = data_frame.physical_address();
    let recursive_index = match boot_info.recursive_index {
        Optional::Some(index) if is_safe_recursive_mapping_index(index) => index,
        Optional::Some(_) => {
            let _ = release_data_frame(data_frame);
            return Err(PagingError::InvalidRecursiveIndex);
        }
        Optional::None => {
            let _ = release_data_frame(data_frame);
            return Err(PagingError::RecursiveMappingUnavailable);
        }
    };
    let root_table_physical = active_root_table_physical();
    let permissions = PagePermissions::new(true, false, false);

    let physical_memory_offset = match boot_info.physical_memory_offset {
        Optional::Some(offset) => offset,
        Optional::None => {
            let _ = release_data_frame(data_frame);
            return Err(PagingError::PhysicalMemoryOffsetUnavailable);
        }
    };

    let highest_physical_end = boot_info
        .memory_regions
        .iter()
        .map(|region| region.end)
        .max()
        .unwrap_or(0)
        .max(1u64 << 32);
    let Some(physical_mapping_end) = physical_memory_offset.checked_add(highest_physical_end)
    else {
        let _ = release_data_frame(data_frame);
        return Err(PagingError::PhysicalMemoryOffsetUnavailable);
    };

    // Probe one address at the base of each high-half PML4 slot. This avoids
    // repeatedly retrying the same 2 MiB leaf when a candidate conflicts with
    // a large page, and skips both the recursive slot and the bootloader's
    // physical-memory-offset range before attempting to mutate page tables.
    for candidate_pml4_index in FIRST_CANDIDATE_PML4_INDEX..512 {
        if candidate_pml4_index == recursive_index {
            continue;
        }
        let raw_candidate = u64::from(candidate_pml4_index) << 39;
        let candidate = raw_candidate | 0xffff_0000_0000_0000;
        if candidate >= physical_memory_offset && candidate < physical_mapping_end {
            continue;
        }
        let mut editor = match KernelPageTableEditor::new(boot_info, candidate) {
            Ok(editor) => editor,
            Err(error) => {
                let _ = release_data_frame(data_frame);
                return Err(error);
            }
        };
        // SAFETY: data_frame remains owned through the map/access/unmap smoke
        // cycle and is released only after this mapping has been removed.
        match unsafe {
            map_supervisor_4k(
                root_table_physical,
                candidate,
                data_physical,
                permissions,
                &mut editor,
            )
        } {
            Ok(()) => {
                invalidate_local_tlb(candidate);
                // SAFETY: map_supervisor_4k installed a writable, supervisor-only mapping to
                // the allocated frame and the new translation has been invalidated.
                unsafe {
                    ptr::write_volatile(candidate as *mut u64, MAPPING_SMOKE_SENTINEL);
                }
                // SAFETY: the same validated mapping is immediately read back.
                let observed = unsafe { ptr::read_volatile(candidate as *const u64) };
                let atomic_entry_update_correctly = if let (Some(table_physical), Some(index)) = (
                    editor.reachable_table_physical(1),
                    virtual_index(candidate, 1),
                ) {
                    editor.verify_atomic_entry_compare_exchange(table_physical, index, 1)
                } else {
                    false
                };
                let translation =
                    translate_with_editor(&mut editor, root_table_physical, candidate);
                let mapped_correctly = atomic_entry_update_correctly
                    && observed == MAPPING_SMOKE_SENTINEL
                    && translation.is_ok_and(|result| {
                        result.physical_address == data_physical
                            && result.page_size == PAGE_SIZE
                            && result.writable
                            && !result.user_accessible
                            && !result.executable
                    });
                let unmapped = unmap_4k(root_table_physical, candidate, &mut editor);
                if unmapped.is_err() {
                    // Never return a data frame to the allocator while it may
                    // still be reachable through a live page-table entry.
                    return Err(PagingError::MappingSmokeMismatch);
                }
                invalidate_local_tlb(candidate);
                let unmapped_page = unmapped.expect("checked successful unmap");
                let unmapped_translation =
                    translate_with_editor(&mut editor, root_table_physical, candidate);
                let removed_correctly = unmapped_page.physical_address == data_physical
                    && unmapped_page.permissions == permissions
                    && matches!(unmapped_translation, Err(PageTableError::NotPresent { .. }));
                let release_result = release_data_frame(data_frame);
                if release_result.is_err() || !mapped_correctly || !removed_correctly {
                    return Err(PagingError::MappingSmokeMismatch);
                }
                return Ok(());
            }
            Err(error) if error.is_retryable_for_mapping_candidate() => {
                // map_supervisor_4k reports these failures during its read-only preflight,
                // before allocating a table or writing a page-table entry.
                continue;
            }
            Err(error) => {
                let _ = release_data_frame(data_frame);
                return Err(PagingError::MappingMutation(error));
            }
        }
    }

    let _ = release_data_frame(data_frame);
    Err(PagingError::NoUnusedVirtualAddress)
}

/// Restricts the physical-memory-offset aliases for every validated executable PT_LOAD page.
///
/// This must run while the bootloader root and its recursive index are active, before
/// constructing the private kernel root. The upper-half/direct-map page tables are
/// shared into later roots. Executable extents are derived from the validated ELF
/// program headers and page-table translations, never from a VA == PA assumption.
pub fn enforce_kernel_executable_alias_wx(boot_info: &BootInfo) -> Result<usize, PagingError> {
    let recursive_index = match boot_info.recursive_index {
        Optional::Some(index) if is_safe_recursive_mapping_index(index) => index,
        Optional::Some(_) => return Err(PagingError::InvalidRecursiveIndex),
        Optional::None => return Err(PagingError::RecursiveMappingUnavailable),
    };
    let regions: &[MemoryRegion] = &boot_info.memory_regions;
    let root_table_physical = active_root_table_physical();
    if root_table_physical == 0
        || root_table_physical & (PAGE_SIZE - 1) != 0
        || !is_bootloader_owned_page(regions, root_table_physical)
        || !validate_recursive_mapping_entry(recursive_index, root_table_physical)
    {
        return Err(PagingError::InvalidRootTable);
    }

    let physical_memory_offset = match boot_info.physical_memory_offset {
        Optional::Some(offset) => offset,
        Optional::None => return Err(PagingError::PhysicalMemoryOffsetUnavailable),
    };
    let physical_address_bits = (__cpuid(CPUID_PHYSICAL_ADDRESS_WIDTH).eax & 0xff) as u8;
    if !(32..=52).contains(&physical_address_bits) {
        return Err(PagingError::InvalidPhysicalAddressWidth {
            bits: physical_address_bits,
        });
    }

    let mut elf_header = [0u8; ELF64_HEADER_SIZE];
    read_kernel_elf_bytes(
        boot_info,
        0,
        &mut elf_header,
        root_table_physical,
        recursive_index,
        regions,
    )?;
    let (program_header_offset, program_header_size) =
        elf64_program_header_table_range(&elf_header, boot_info.kernel_len)
            .map_err(|_| PagingError::InvalidKernelElf)?;
    let mut program_header_buffer = [0u8; MAX_ELF64_PROGRAM_HEADERS * ELF64_PROGRAM_HEADER_SIZE];
    let program_headers = &mut program_header_buffer[..program_header_size];
    read_kernel_elf_bytes(
        boot_info,
        program_header_offset,
        program_headers,
        root_table_physical,
        recursive_index,
        regions,
    )?;
    let load_image = parse_elf64_load_segments(&elf_header, program_headers, boot_info.kernel_len)
        .map_err(|_| PagingError::InvalidKernelElf)?;

    let mut executable_pages_checked = 0usize;
    for segment in load_image.load_segments() {
        if !segment.executable() || segment.memory_size == 0 {
            continue;
        }
        // A writable/executable PT_LOAD page cannot be repaired by downgrading
        // only the direct-map alias; reject it rather than claiming W^X success.
        if segment.writable() {
            return Err(PagingError::InvalidKernelCodeMapping);
        }
        let load_start = boot_info
            .kernel_image_offset
            .checked_add(segment.virtual_address)
            .ok_or(PagingError::InvalidKernelLoadMapping)?;
        let load_end = load_start
            .checked_add(segment.memory_size)
            .filter(|end| *end > load_start)
            .ok_or(PagingError::InvalidKernelLoadMapping)?;
        if !canonical_range_stays_in_one_half(load_start, load_end) {
            return Err(PagingError::InvalidKernelLoadMapping);
        }

        let first_page = load_start & !(PAGE_SIZE - 1);
        let last_page = (load_end - 1) & !(PAGE_SIZE - 1);
        let mut virtual_page = first_page;
        loop {
            let translation = translate_virtual_address(
                virtual_page,
                root_table_physical,
                recursive_index,
                regions,
            )
            .map_err(|_| PagingError::InvalidKernelLoadMapping)?;
            if translation.page_size != PAGE_SIZE
                || translation.physical_address & (PAGE_SIZE - 1) != 0
                || !is_kernel_backed_page(regions, translation.physical_address)
                || translation.user_accessible
                || translation.writable
                || !translation.executable
            {
                return Err(PagingError::InvalidKernelLoadMapping);
            }

            let direct_alias = physical_memory_offset
                .checked_add(translation.physical_address)
                .filter(|address| {
                    is_canonical_4level(*address) && (*address & (PAGE_SIZE - 1)) == 0
                })
                .ok_or(PagingError::PhysicalMemoryOffsetUnavailable)?;
            restrict_physical_offset_alias_read_only_nx(
                boot_info,
                root_table_physical,
                direct_alias,
                translation.physical_address,
            )?;

            // Verify the effective permissions through a fresh page-table walk
            // for every executable PT_LOAD page, not just the single CPU-fault
            // sample exercised by the dedicated acceptance profile.
            let mut verify_editor = KernelPageTableEditor::new(boot_info, direct_alias)?;
            let verified =
                translate_with_editor(&mut verify_editor, root_table_physical, direct_alias)
                    .map_err(PagingError::Translation)?;
            if verified.physical_address != translation.physical_address
                || verified.page_size != PAGE_SIZE
                || verified.writable
                || verified.user_accessible
                || verified.executable
            {
                return Err(PagingError::WxAuditFailed);
            }

            executable_pages_checked = executable_pages_checked
                .checked_add(1)
                .ok_or(PagingError::InvalidKernelLoadMapping)?;

            if virtual_page == last_page {
                break;
            }
            virtual_page = virtual_page
                .checked_add(PAGE_SIZE)
                .ok_or(PagingError::InvalidKernelLoadMapping)?;
        }
    }

    if executable_pages_checked == 0 {
        return Err(PagingError::InvalidKernelLoadMapping);
    }
    Ok(executable_pages_checked)
}

/// Returns the physical-offset alias of a supervisor-only executable kernel
/// mapping for the dedicated W^X CPU-enforcement test. The helper checks the
/// live root, mapping permissions, and physical backing; it does not independently
/// prove ELF PT_LOAD membership. The current caller passes a known kernel function
/// address, and this helper never assumes VA == PA.
#[cfg(feature = "test-wx-runtime-audit")]
pub fn kernel_executable_direct_alias_for_test(
    boot_info: &BootInfo,
    executable_virtual_address: u64,
    recursive_index: u16,
) -> Result<u64, PagingError> {
    let regions: &[MemoryRegion] = &boot_info.memory_regions;
    let root_table_physical = active_root_table_physical();
    if !is_canonical_4level(executable_virtual_address)
        || !is_safe_recursive_mapping_index(recursive_index)
        || !validate_recursive_mapping_entry(recursive_index, root_table_physical)
    {
        return Err(PagingError::InvalidRecursiveMapping);
    }

    // Page-table editors take a page-aligned target address. Keep the caller's
    // code pointer only as a page selector; the permission check applies to the
    // full executable leaf that contains it.
    let executable_virtual_page = executable_virtual_address & !(PAGE_SIZE - 1);

    // The active root is kernel-owned and may contain page-table frames in
    // Usable regions, so use the checked kernel editor rather than the boot-only
    // translator, which deliberately accepts only Bootloader-owned table frames.
    let mut executable_editor = KernelPageTableEditor::new_with_recursive_index(
        boot_info,
        executable_virtual_page,
        recursive_index,
    )?;
    let executable = translate_with_editor(
        &mut executable_editor,
        root_table_physical,
        executable_virtual_page,
    )
    .map_err(PagingError::Translation)?;
    if executable.page_size != PAGE_SIZE
        || executable.writable
        || executable.user_accessible
        || !executable.executable
    {
        return Err(PagingError::InvalidKernelCodeMapping);
    }
    let physical_page = executable.physical_address & !(PAGE_SIZE - 1);
    if !is_kernel_backed_page(regions, physical_page) {
        return Err(PagingError::InvalidKernelLoadMapping);
    }

    let physical_memory_offset = match boot_info.physical_memory_offset {
        Optional::Some(offset) => offset,
        Optional::None => return Err(PagingError::PhysicalMemoryOffsetUnavailable),
    };
    let direct_alias = physical_memory_offset
        .checked_add(physical_page)
        .filter(|address| is_canonical_4level(*address) && (*address & (PAGE_SIZE - 1)) == 0)
        .ok_or(PagingError::PhysicalMemoryOffsetUnavailable)?;
    let mut alias_editor =
        KernelPageTableEditor::new_with_recursive_index(boot_info, direct_alias, recursive_index)?;
    let alias = translate_with_editor(&mut alias_editor, root_table_physical, direct_alias)
        .map_err(PagingError::Translation)?;
    if alias.page_size != PAGE_SIZE
        || alias.physical_address != physical_page
        || alias.writable
        || alias.user_accessible
        || alias.executable
    {
        return Err(PagingError::WxAuditFailed);
    }
    Ok(direct_alias)
}

#[cfg(feature = "test-wx-runtime-audit")]
const WX_SIBLING_PRE_TRANSITION_SENTINEL: u64 = 0x4f4e_455f_5758_5052;
#[cfg(feature = "test-wx-runtime-audit")]
const WX_SIBLING_ALIAS_WRITE_SENTINEL: u64 = 0x4f4e_455f_5758_414c;
#[cfg(feature = "test-wx-runtime-audit")]
const WX_SIBLING_DIRECT_WRITE_SENTINEL: u64 = 0x4f4e_455f_5758_444d;

/// Keeps two allocator-owned Usable frames that share one original large direct-map
/// leaf and the same 2 MiB physical subregion. This provides a controlled test layout
/// even when the bootloader has reserved every unused page beside the loaded kernel.
#[cfg(feature = "test-wx-runtime-audit")]
pub struct WxSiblingRegressionTest {
    executable_frame: Option<Frame>,
    sibling_frame: Option<Frame>,
    pub executable_physical_page: u64,
    pub sibling_physical_page: u64,
    pub original_large_page_size: u64,
    executable_virtual_address: Option<u64>,
}

/// Forms overlapping adjacent-frame candidates without skipping allocation positions.
#[cfg(feature = "test-wx-runtime-audit")]
fn take_adjacent_wx_frame_pair<T>(previous: &mut Option<T>, current: T) -> Option<(T, T)> {
    match previous.take() {
        Some(previous) => Some((previous, current)),
        None => {
            *previous = Some(current);
            None
        }
    }
}

/// Finds an owned pair in a real writable large-page direct-map leaf.
///
/// The physical location of PT_LOAD segments is chosen by the bootloader and must not
/// be treated as a placement guarantee. Instead, allocate both test frames from memory
/// explicitly reported as Usable, and retain their allocator tokens for the lifetime
/// of the test. The test executable page is mapped RX separately before its physical
/// offset alias is restricted to RO+NX.
#[cfg(feature = "test-wx-runtime-audit")]
pub fn verify_wx_sibling_large_page_precondition(
    boot_info: &BootInfo,
) -> Result<WxSiblingRegressionTest, PagingError> {
    let recursive_index = match boot_info.recursive_index {
        Optional::Some(index) if is_safe_recursive_mapping_index(index) => index,
        Optional::Some(_) => return Err(PagingError::InvalidRecursiveIndex),
        Optional::None => return Err(PagingError::RecursiveMappingUnavailable),
    };
    let root_table_physical = active_root_table_physical();
    if root_table_physical == 0
        || !validate_recursive_mapping_entry(recursive_index, root_table_physical)
    {
        return Err(PagingError::InvalidRecursiveMapping);
    }
    let physical_memory_offset = match boot_info.physical_memory_offset {
        Optional::Some(offset) => offset,
        Optional::None => return Err(PagingError::PhysicalMemoryOffsetUnavailable),
    };

    // Search every frame that was free at entry, rather than stopping at an
    // arbitrary physical range. Keep a one-frame sliding window so an eligible
    // pair is found regardless of whether its two frames fall on odd/even
    // allocation positions. Rejected frames are freed without rewinding next_hint.
    let scan_budget =
        crate::memory::free_frame_count().map_err(|_| PagingError::FrameAllocationFailed)?;
    if scan_budget < 2 {
        crate::serial_write(b"ONE OS W^X PRECONDITION NO USABLE LARGE-PAGE SIBLING PAIR FOUND\n");
        return Err(PagingError::WxSiblingFrameUnavailable);
    }
    // Include one extra allocation to test the wraparound pair between the final
    // free frame and the first one in the allocator's cyclic search order.
    let scan_attempts = scan_budget
        .checked_add(1)
        .ok_or(PagingError::FrameAllocationFailed)?;
    let mut previous_frame: Option<Frame> = None;
    // Cache eligibility by aligned virtual 2 MiB region, not physical region:
    // the physical-memory offset need not be 2 MiB aligned, and one physical
    // region can straddle two independently mapped virtual large-page leaves.
    // Within one aligned virtual 2 MiB region, a 2 MiB/1 GiB leaf covers every
    // candidate; a 4 KiB page-table subtree cannot contain a large leaf.
    let mut checked_region: Option<(u64, Option<u64>)> = None;

    for _ in 0..scan_attempts {
        let current_frame = match crate::memory::allocate_frame() {
            Ok(frame) => frame,
            Err(_) => {
                if let Some(frame) = previous_frame.take() {
                    release_data_frame_preserving_hint(frame);
                }
                return Err(PagingError::FrameAllocationFailed);
            }
        };
        let Some((executable_frame, current_frame)) =
            take_adjacent_wx_frame_pair(&mut previous_frame, current_frame)
        else {
            continue;
        };

        let executable_physical_page = executable_frame.physical_address();
        let sibling_physical_page = current_frame.physical_address();
        let same_2m_region = executable_physical_page != sibling_physical_page
            && executable_physical_page & !((1u64 << 21) - 1)
                == sibling_physical_page & !((1u64 << 21) - 1);

        if same_2m_region {
            let region_start = executable_physical_page & !((1u64 << 21) - 1);
            let direct_aliases = (|| -> Result<(u64, u64), PagingError> {
                let executable_direct_alias = physical_memory_offset
                    .checked_add(executable_physical_page)
                    .filter(|address| {
                        is_canonical_4level(*address) && (*address & (PAGE_SIZE - 1)) == 0
                    })
                    .ok_or(PagingError::PhysicalMemoryOffsetUnavailable)?;
                let sibling_direct_alias = physical_memory_offset
                    .checked_add(sibling_physical_page)
                    .filter(|address| {
                        is_canonical_4level(*address) && (*address & (PAGE_SIZE - 1)) == 0
                    })
                    .ok_or(PagingError::PhysicalMemoryOffsetUnavailable)?;
                Ok((executable_direct_alias, sibling_direct_alias))
            })();
            let (executable_direct_alias, sibling_direct_alias) = match direct_aliases {
                Ok(aliases) => aliases,
                Err(error) => {
                    release_data_frame_preserving_hint(executable_frame);
                    release_data_frame_preserving_hint(current_frame);
                    return Err(error);
                }
            };
            let virtual_region_start = executable_direct_alias & !((1u64 << 21) - 1);

            let large_page_size = match checked_region {
                Some((checked_start, page_size)) if checked_start == virtual_region_start => {
                    page_size
                }
                _ => {
                    let candidate = (|| -> Result<Option<u64>, PagingError> {
                        let mut editor = KernelPageTableEditor::new_with_recursive_index(
                            boot_info,
                            executable_direct_alias,
                            recursive_index,
                        )?;
                        let alias = translate_with_editor(
                            &mut editor,
                            root_table_physical,
                            executable_direct_alias,
                        )
                        .map_err(PagingError::Translation)?;

                        if (alias.page_size != (1u64 << 21) && alias.page_size != (1u64 << 30))
                            || alias.physical_address != executable_physical_page
                            || !alias.writable
                            || alias.user_accessible
                            || alias.executable
                            || executable_direct_alias & !(alias.page_size - 1)
                                != sibling_direct_alias & !(alias.page_size - 1)
                        {
                            return Ok(None);
                        }
                        Ok(Some(alias.page_size))
                    })();

                    match candidate {
                        Ok(page_size) => {
                            checked_region = Some((virtual_region_start, page_size));
                            page_size
                        }
                        Err(error) => {
                            release_data_frame_preserving_hint(executable_frame);
                            release_data_frame_preserving_hint(current_frame);
                            return Err(error);
                        }
                    }
                }
            };

            if let Some(original_page_size) = large_page_size {
                // A full large-page leaf covers both addresses. Verify that the
                // aliases really share that leaf before accepting the owned pair.
                if executable_direct_alias & !(original_page_size - 1)
                    == sibling_direct_alias & !(original_page_size - 1)
                {
                    // SAFETY: the direct-map alias belongs to an allocator-owned
                    // Usable frame and was checked as writable, supervisor-only, NX.
                    // Seed a single RET byte before installing the separate RX alias.
                    unsafe {
                        ptr::write_volatile(executable_direct_alias as *mut u8, 0xc3);
                        ptr::write_volatile(
                            sibling_direct_alias as *mut u64,
                            WX_SIBLING_PRE_TRANSITION_SENTINEL,
                        );
                    }
                    return Ok(WxSiblingRegressionTest {
                        executable_frame: Some(executable_frame),
                        sibling_frame: Some(current_frame),
                        executable_physical_page,
                        sibling_physical_page,
                        original_large_page_size: original_page_size,
                        executable_virtual_address: None,
                    });
                }
            }
        }

        // Advance by one allocation, not two: the current frame becomes the
        // previous candidate so overlapping pairs are checked on the next pass.
        release_data_frame_preserving_hint(executable_frame);
        previous_frame = Some(current_frame);
    }

    if let Some(frame) = previous_frame.take() {
        release_data_frame_preserving_hint(frame);
    }

    crate::serial_write(b"ONE OS W^X PRECONDITION NO USABLE LARGE-PAGE SIBLING PAIR FOUND\n");
    Err(PagingError::WxSiblingFrameUnavailable)
}

/// Maps the owned test executable page as supervisor RX and ensures its direct-map
/// alias is RO+NX. If the kernel PT_LOAD transition already split this same 2 MiB
/// region, this verifies that the sibling remained writable; otherwise it invokes
/// the same guarded direct-map restriction primitive to exercise the demotion path.
#[cfg(feature = "test-wx-runtime-audit")]
pub fn apply_wx_sibling_test_transition(
    boot_info: &BootInfo,
    test: &mut WxSiblingRegressionTest,
) -> Result<(), PagingError> {
    let recursive_index = match boot_info.recursive_index {
        Optional::Some(index) if is_safe_recursive_mapping_index(index) => index,
        Optional::Some(_) => return Err(PagingError::InvalidRecursiveIndex),
        Optional::None => return Err(PagingError::RecursiveMappingUnavailable),
    };
    let root_table_physical = active_root_table_physical();
    if !validate_recursive_mapping_entry(recursive_index, root_table_physical)
        || test.executable_frame.as_ref().map(Frame::physical_address)
            != Some(test.executable_physical_page)
        || test.sibling_frame.as_ref().map(Frame::physical_address)
            != Some(test.sibling_physical_page)
        || test.original_large_page_size != (1u64 << 21)
            && test.original_large_page_size != (1u64 << 30)
        || test.executable_physical_page & !((1u64 << 21) - 1)
            != test.sibling_physical_page & !((1u64 << 21) - 1)
    {
        return Err(PagingError::WxSiblingFrameUnavailable);
    }
    let physical_memory_offset = match boot_info.physical_memory_offset {
        Optional::Some(offset) => offset,
        Optional::None => return Err(PagingError::PhysicalMemoryOffsetUnavailable),
    };
    let executable_direct_alias = physical_memory_offset
        .checked_add(test.executable_physical_page)
        .filter(|address| is_canonical_4level(*address) && (*address & (PAGE_SIZE - 1)) == 0)
        .ok_or(PagingError::PhysicalMemoryOffsetUnavailable)?;

    // The precondition is checked before the PT_LOAD transition. An original
    // 1 GiB leaf may now be a 2 MiB child if PT_LOAD demoted a different child,
    // or a 4 KiB leaf if PT_LOAD touched this same physical 2 MiB region.
    let mut direct_editor = KernelPageTableEditor::new_with_recursive_index(
        boot_info,
        executable_direct_alias,
        recursive_index,
    )?;
    let direct_before = translate_with_editor(
        &mut direct_editor,
        root_table_physical,
        executable_direct_alias,
    )
    .map_err(PagingError::Translation)?;
    let valid_demotion_progress = oneos_core::is_valid_large_page_demotion_progress(
        test.original_large_page_size,
        direct_before.page_size,
    );
    let direct_mapping_is_writable_supervisor_nx =
        direct_before.writable && !direct_before.user_accessible && !direct_before.executable;
    if direct_before.physical_address != test.executable_physical_page
        || !valid_demotion_progress
        || !direct_mapping_is_writable_supervisor_nx
    {
        return Err(PagingError::LargePageDemotionFailed);
    }

    // Restrict the owned test frame's physical-offset alias before publishing any
    // executable alias. This avoids a transient W+X alias even with interrupts off.
    // If PT_LOAD already demoted this exact 2 MiB child, this changes the frame's
    // writable 4 KiB alias to RO+NX; otherwise the helper performs the remaining
    // 1 GiB-to-2 MiB or 2 MiB-to-4 KiB demotion required for this test frame.
    restrict_physical_offset_alias_read_only_nx(
        boot_info,
        root_table_physical,
        executable_direct_alias,
        test.executable_physical_page,
    )?;

    let highest_physical_end = boot_info
        .memory_regions
        .iter()
        .map(|region| region.end)
        .max()
        .unwrap_or(0)
        .max(1u64 << 32);
    let physical_mapping_end = physical_memory_offset
        .checked_add(highest_physical_end)
        .ok_or(PagingError::PhysicalMemoryOffsetUnavailable)?;
    let mut mapped_virtual_address = None;
    for candidate_pml4_index in FIRST_CANDIDATE_PML4_INDEX..512 {
        if candidate_pml4_index == recursive_index {
            continue;
        }
        let raw_candidate = u64::from(candidate_pml4_index) << 39;
        let candidate = raw_candidate | 0xffff_0000_0000_0000;
        if candidate >= physical_memory_offset && candidate < physical_mapping_end {
            continue;
        }
        let mut editor = match KernelPageTableEditor::new_with_recursive_index(
            boot_info,
            candidate,
            recursive_index,
        ) {
            Ok(editor) => editor,
            Err(error) => return Err(error),
        };
        // This per-editor permission is available only in the dedicated regression
        // image and only after verifying this frame's direct-map alias is RO+NX.
        #[cfg(feature = "test-wx-runtime-audit")]
        editor.allow_controlled_wx_test_executable_frame(test.executable_physical_page)?;
        // SAFETY: the owned executable test frame remains allocated for the test's
        // lifetime. The mapping is supervisor-only and deliberately not writable.
        match unsafe {
            map_supervisor_4k(
                root_table_physical,
                candidate,
                test.executable_physical_page,
                PagePermissions::new(false, false, true),
                &mut editor,
            )
        } {
            Ok(()) => {
                invalidate_local_tlb(candidate);
                let mut verify_editor = KernelPageTableEditor::new_with_recursive_index(
                    boot_info,
                    candidate,
                    recursive_index,
                )?;
                let mapped =
                    translate_with_editor(&mut verify_editor, root_table_physical, candidate)
                        .map_err(PagingError::Translation)?;
                if mapped.physical_address != test.executable_physical_page
                    || mapped.page_size != PAGE_SIZE
                    || mapped.writable
                    || mapped.user_accessible
                    || !mapped.executable
                {
                    return Err(PagingError::InvalidKernelCodeMapping);
                }
                mapped_virtual_address = Some(candidate);
                break;
            }
            Err(error) if error.is_retryable_for_mapping_candidate() => continue,
            Err(error) => return Err(PagingError::MappingMutation(error)),
        }
    }
    let executable_virtual_address =
        mapped_virtual_address.ok_or(PagingError::NoUnusedVirtualAddress)?;
    test.executable_virtual_address = Some(executable_virtual_address);

    // Verify the actual effective permissions on both aliases after the change.
    let mut executable_alias_editor = KernelPageTableEditor::new_with_recursive_index(
        boot_info,
        executable_virtual_address,
        recursive_index,
    )?;
    let executable_alias = translate_with_editor(
        &mut executable_alias_editor,
        root_table_physical,
        executable_virtual_address,
    )
    .map_err(PagingError::Translation)?;
    let mut direct_alias_editor = KernelPageTableEditor::new_with_recursive_index(
        boot_info,
        executable_direct_alias,
        recursive_index,
    )?;
    let direct_alias = translate_with_editor(
        &mut direct_alias_editor,
        root_table_physical,
        executable_direct_alias,
    )
    .map_err(PagingError::Translation)?;
    let sibling_direct_alias = physical_memory_offset
        .checked_add(test.sibling_physical_page)
        .filter(|address| is_canonical_4level(*address) && (*address & (PAGE_SIZE - 1)) == 0)
        .ok_or(PagingError::PhysicalMemoryOffsetUnavailable)?;
    let mut sibling_alias_editor = KernelPageTableEditor::new_with_recursive_index(
        boot_info,
        sibling_direct_alias,
        recursive_index,
    )?;
    let sibling_alias = translate_with_editor(
        &mut sibling_alias_editor,
        root_table_physical,
        sibling_direct_alias,
    )
    .map_err(PagingError::Translation)?;
    if executable_alias.physical_address != test.executable_physical_page
        || executable_alias.page_size != PAGE_SIZE
        || executable_alias.writable
        || executable_alias.user_accessible
        || !executable_alias.executable
        || direct_alias.physical_address != test.executable_physical_page
        || direct_alias.page_size != PAGE_SIZE
        || direct_alias.writable
        || direct_alias.user_accessible
        || direct_alias.executable
        || sibling_alias.physical_address != test.sibling_physical_page
        || sibling_alias.page_size != PAGE_SIZE
        || !sibling_alias.writable
        || sibling_alias.user_accessible
        || sibling_alias.executable
    {
        return Err(PagingError::LargePageDemotionFailed);
    }
    Ok(())
}

/// Verifies that the controlled RX test frame's direct-map alias is read-only/NX
/// while the writable data sibling remains writable/NX after large-page demotion.
#[cfg(feature = "test-wx-runtime-audit")]
pub fn verify_wx_sibling_test_after_transition(
    boot_info: &BootInfo,
    test: &mut WxSiblingRegressionTest,
    recursive_index: u16,
) -> Result<(), PagingError> {
    if test.executable_frame.as_ref().map(Frame::physical_address)
        != Some(test.executable_physical_page)
        || test.sibling_frame.as_ref().map(Frame::physical_address)
            != Some(test.sibling_physical_page)
        || test.executable_physical_page & !((1u64 << 21) - 1)
            != test.sibling_physical_page & !((1u64 << 21) - 1)
    {
        return Err(PagingError::WxSiblingFrameUnavailable);
    }
    let executable_virtual_address = test
        .executable_virtual_address
        .ok_or(PagingError::InvalidKernelCodeMapping)?;
    let root_table_physical = active_root_table_physical();
    if !validate_recursive_mapping_entry(recursive_index, root_table_physical) {
        return Err(PagingError::InvalidRecursiveMapping);
    }
    let physical_memory_offset = match boot_info.physical_memory_offset {
        Optional::Some(offset) => offset,
        Optional::None => return Err(PagingError::PhysicalMemoryOffsetUnavailable),
    };
    let executable_direct_alias = physical_memory_offset
        .checked_add(test.executable_physical_page)
        .filter(|address| is_canonical_4level(*address) && (*address & (PAGE_SIZE - 1)) == 0)
        .ok_or(PagingError::PhysicalMemoryOffsetUnavailable)?;
    let sibling_direct_alias = physical_memory_offset
        .checked_add(test.sibling_physical_page)
        .filter(|address| is_canonical_4level(*address) && (*address & (PAGE_SIZE - 1)) == 0)
        .ok_or(PagingError::PhysicalMemoryOffsetUnavailable)?;

    let mut executable_editor = KernelPageTableEditor::new_with_recursive_index(
        boot_info,
        executable_virtual_address,
        recursive_index,
    )?;
    let executable_alias = translate_with_editor(
        &mut executable_editor,
        root_table_physical,
        executable_virtual_address,
    )
    .map_err(PagingError::Translation)?;
    let mut direct_editor = KernelPageTableEditor::new_with_recursive_index(
        boot_info,
        executable_direct_alias,
        recursive_index,
    )?;
    let direct_alias = translate_with_editor(
        &mut direct_editor,
        root_table_physical,
        executable_direct_alias,
    )
    .map_err(PagingError::Translation)?;
    let mut sibling_editor = KernelPageTableEditor::new_with_recursive_index(
        boot_info,
        sibling_direct_alias,
        recursive_index,
    )?;
    let sibling_alias = translate_with_editor(
        &mut sibling_editor,
        root_table_physical,
        sibling_direct_alias,
    )
    .map_err(PagingError::Translation)?;
    if executable_alias.physical_address != test.executable_physical_page
        || executable_alias.page_size != PAGE_SIZE
        || executable_alias.writable
        || executable_alias.user_accessible
        || !executable_alias.executable
        || direct_alias.physical_address != test.executable_physical_page
        || direct_alias.page_size != PAGE_SIZE
        || direct_alias.writable
        || direct_alias.user_accessible
        || direct_alias.executable
        || sibling_alias.physical_address != test.sibling_physical_page
        || sibling_alias.page_size != PAGE_SIZE
        || !sibling_alias.writable
        || sibling_alias.user_accessible
        || sibling_alias.executable
    {
        return Err(PagingError::LargePageDemotionFailed);
    }

    // Map the sibling frame through a second, independent virtual address.
    // The direct map and this test alias must see the same physical contents in both
    // write directions, including the value seeded before the large-page transition.
    let highest_physical_end = boot_info
        .memory_regions
        .iter()
        .map(|region| region.end)
        .max()
        .unwrap_or(0)
        .max(1u64 << 32);
    let physical_mapping_end = physical_memory_offset
        .checked_add(highest_physical_end)
        .ok_or(PagingError::PhysicalMemoryOffsetUnavailable)?;
    let mut sibling_virtual_address = None;
    for candidate_pml4_index in FIRST_CANDIDATE_PML4_INDEX..512 {
        if candidate_pml4_index == recursive_index {
            continue;
        }
        let raw_candidate = u64::from(candidate_pml4_index) << 39;
        let candidate = raw_candidate | 0xffff_0000_0000_0000;
        if candidate >= physical_memory_offset && candidate < physical_mapping_end {
            continue;
        }
        let mut editor =
            KernelPageTableEditor::new_with_recursive_index(boot_info, candidate, recursive_index)?;
        // SAFETY: the sibling frame remains allocator-owned. This additional alias
        // is supervisor-only, writable, NX, and does not grant executable access.
        match unsafe {
            map_supervisor_4k(
                root_table_physical,
                candidate,
                test.sibling_physical_page,
                PagePermissions::new(true, false, false),
                &mut editor,
            )
        } {
            Ok(()) => {
                invalidate_local_tlb(candidate);
                sibling_virtual_address = Some(candidate);
                break;
            }
            Err(error) if error.is_retryable_for_mapping_candidate() => continue,
            Err(error) => return Err(PagingError::MappingMutation(error)),
        }
    }
    let sibling_virtual_address =
        sibling_virtual_address.ok_or(PagingError::NoUnusedVirtualAddress)?;

    let alias_check = (|| -> Result<(), PagingError> {
        let mut alias_editor = KernelPageTableEditor::new_with_recursive_index(
            boot_info,
            sibling_virtual_address,
            recursive_index,
        )?;
        let alias = translate_with_editor(
            &mut alias_editor,
            root_table_physical,
            sibling_virtual_address,
        )
        .map_err(PagingError::Translation)?;
        if alias.physical_address != test.sibling_physical_page
            || alias.page_size != PAGE_SIZE
            || !alias.writable
            || alias.user_accessible
            || alias.executable
        {
            return Err(PagingError::LargePageDemotionFailed);
        }

        // SAFETY: the additional alias is a validated writable mapping of the
        // retained sibling frame. This value was written before the transition.
        let before_transition =
            unsafe { ptr::read_volatile(sibling_virtual_address as *const u64) };
        if before_transition != WX_SIBLING_PRE_TRANSITION_SENTINEL {
            return Err(PagingError::LargePageDemotionFailed);
        }

        // SAFETY: the mapped alias is writable and addresses the retained frame.
        unsafe {
            ptr::write_volatile(
                sibling_virtual_address as *mut u64,
                WX_SIBLING_ALIAS_WRITE_SENTINEL,
            );
        }
        // SAFETY: this reads the same frame through the separately validated direct map.
        let through_direct_map = unsafe { ptr::read_volatile(sibling_direct_alias as *const u64) };
        if through_direct_map != WX_SIBLING_ALIAS_WRITE_SENTINEL {
            return Err(PagingError::LargePageDemotionFailed);
        }

        // SAFETY: the direct-map leaf was verified writable, supervisor-only, NX.
        unsafe {
            ptr::write_volatile(
                sibling_direct_alias as *mut u64,
                WX_SIBLING_DIRECT_WRITE_SENTINEL,
            );
        }
        // SAFETY: independently read the write through the additional virtual alias.
        let through_test_alias =
            unsafe { ptr::read_volatile(sibling_virtual_address as *const u64) };
        if through_test_alias != WX_SIBLING_DIRECT_WRITE_SENTINEL {
            return Err(PagingError::LargePageDemotionFailed);
        }
        Ok(())
    })();

    // Never release the data frame while its additional alias is still present.
    let mut cleanup_editor = KernelPageTableEditor::new_with_recursive_index(
        boot_info,
        sibling_virtual_address,
        recursive_index,
    )?;
    let unmapped = unmap_4k(
        root_table_physical,
        sibling_virtual_address,
        &mut cleanup_editor,
    )
    .map_err(PagingError::MappingMutation)?;
    invalidate_local_tlb(sibling_virtual_address);
    let mut verify_unmap_editor = KernelPageTableEditor::new_with_recursive_index(
        boot_info,
        sibling_virtual_address,
        recursive_index,
    )?;
    let after_unmap = translate_with_editor(
        &mut verify_unmap_editor,
        root_table_physical,
        sibling_virtual_address,
    );
    let removed_correctly = unmapped.physical_address == test.sibling_physical_page
        && unmapped.permissions == PagePermissions::new(true, false, false)
        && matches!(after_unmap, Err(PageTableError::NotPresent { .. }));
    if !removed_correctly {
        return Err(PagingError::LargePageDemotionFailed);
    }
    alias_check?;

    // The sibling's independent alias is removed and its TLB entry invalidated.
    // Its physical-offset alias remains writable/NX; the RX test frame stays owned.
    let sibling_frame = test
        .sibling_frame
        .take()
        .ok_or(PagingError::WxSiblingFrameUnavailable)?;
    release_data_frame(sibling_frame)?;
    Ok(())
}

/// Demotes a physical-offset leaf as needed, then removes write access using
/// break-before-make so a stale writable TLB translation cannot survive the
/// permission transition. It preserves the physical frame, cache/PAT/global and
/// A/D state, and republishes the leaf as read-only + NX.
fn restrict_physical_offset_alias_read_only_nx(
    boot_info: &BootInfo,
    root_table_physical: u64,
    virtual_address: u64,
    expected_physical_page: u64,
) -> Result<(), PagingError> {
    if !is_canonical_4level(virtual_address)
        || virtual_address & (PAGE_SIZE - 1) != 0
        || expected_physical_page & (PAGE_SIZE - 1) != 0
        || active_root_table_physical() != root_table_physical
    {
        return Err(PagingError::LargePageDemotionFailed);
    }

    let mut demotions = 0usize;
    loop {
        let mut editor = KernelPageTableEditor::new(boot_info, virtual_address)?;
        let translation = translate_with_editor(&mut editor, root_table_physical, virtual_address)
            .map_err(PagingError::Translation)?;
        if translation.physical_address != expected_physical_page || translation.user_accessible {
            return Err(PagingError::WxAuditFailed);
        }
        if translation.page_size == PAGE_SIZE {
            break;
        }
        if demotions >= 2
            || (translation.page_size != (1u64 << 21) && translation.page_size != (1u64 << 30))
        {
            return Err(PagingError::LargePageDemotionFailed);
        }
        let receipt = demote_large_page_for_address(boot_info, virtual_address)?
            .ok_or(PagingError::LargePageDemotionFailed)?;
        let receipt_end = receipt
            .physical_start
            .checked_add(receipt.virtual_length)
            .ok_or(PagingError::LargePageDemotionFailed)?;
        if receipt.virtual_length != translation.page_size
            || expected_physical_page < receipt.physical_start
            || expected_physical_page >= receipt_end
        {
            return Err(PagingError::LargePageDemotionFailed);
        }
        demotions += 1;
    }

    let mut editor = KernelPageTableEditor::new(boot_info, virtual_address)?;
    let (leaf_table_physical, leaf_index, leaf_entry) = {
        let mut table_physical = root_table_physical;
        let mut level = 4u8;
        loop {
            let index = virtual_index(virtual_address, level).ok_or(PagingError::WxAuditFailed)?;
            let entry = editor
                .read_entry(table_physical, index, level)
                .ok_or(PagingError::WxAuditFailed)?;
            if entry & PRESENT == 0 || (level == 4 && entry & LARGE_PAGE != 0) {
                return Err(PagingError::WxAuditFailed);
            }
            if level == 1 {
                break (table_physical, index, entry);
            }
            if entry & LARGE_PAGE != 0 {
                return Err(PagingError::LargePageDemotionFailed);
            }
            table_physical = entry & PHYSICAL_ADDRESS_MASK;
            if !valid_physical_page(table_physical, editor.physical_address_bits) {
                return Err(PagingError::WxAuditFailed);
            }
            level = level.checked_sub(1).ok_or(PagingError::WxAuditFailed)?;
        }
    };

    if leaf_entry & PHYSICAL_ADDRESS_MASK != expected_physical_page
        || leaf_entry & PRESENT == 0
        || leaf_entry & USER_ACCESSIBLE != 0
    {
        return Err(PagingError::WxAuditFailed);
    }
    // Even if the PTE already advertises RO+NX, repeat the break-before-make
    // sequence so a stale writable TLB entry cannot be mistaken for enforcement.
    const ACCESSED_DIRTY_MASK: u64 = (1 << 5) | (1 << 6);
    // First clear Present atomically. Retry only if the hardware monotonically
    // sets A/D; any other mutation fails before the entry is made non-present.
    compare_exchange_entry_with_ad_retry(
        leaf_entry,
        ATOMIC_ENTRY_CAS_MAX_ATTEMPTS,
        |expected| expected & !PRESENT,
        |expected, replacement| {
            editor
                .compare_exchange_entry(leaf_table_physical, leaf_index, 1, expected, replacement)
                .unwrap_or(Err(expected))
        },
    )
    .map_err(|_| PagingError::WxAuditFailed)?;

    // Once Present is cleared, any inability to complete the transition must
    // fail-stop: never return with a partially unpublished direct-map leaf.
    if crate::address_space::switch_address_space_flush_local_tlb(root_table_physical).is_err() {
        panic!("W^X direct-map transition could not flush the retired writable translation");
    }
    let cleared = editor
        .read_entry(leaf_table_physical, leaf_index, 1)
        .unwrap_or_else(|| panic!("W^X direct-map leaf became inaccessible after invalidation"));
    if cleared & PRESENT != 0
        || cleared & !(PRESENT | ACCESSED_DIRTY_MASK)
            != leaf_entry & !(PRESENT | ACCESSED_DIRTY_MASK)
        || (cleared & ACCESSED_DIRTY_MASK & leaf_entry) != (leaf_entry & ACCESSED_DIRTY_MASK)
    {
        panic!("W^X direct-map leaf changed unexpectedly after invalidation");
    }

    let replacement = (cleared | PRESENT) & !WRITABLE | NO_EXECUTE;
    editor.write_entry(leaf_table_physical, leaf_index, 1, replacement);
    if crate::address_space::switch_address_space_flush_local_tlb(root_table_physical).is_err() {
        panic!("W^X direct-map transition could not flush the republished read-only translation");
    }
    let final_entry = editor
        .read_entry(leaf_table_physical, leaf_index, 1)
        .unwrap_or_else(|| panic!("W^X direct-map leaf became inaccessible after publication"));
    if final_entry & PRESENT == 0
        || final_entry & PHYSICAL_ADDRESS_MASK != expected_physical_page
        || final_entry & WRITABLE != 0
        || final_entry & NO_EXECUTE == 0
        || final_entry & USER_ACCESSIBLE != 0
    {
        panic!("W^X direct-map leaf did not retain the expected read-only/NX mapping");
    }
    Ok(())
}

/// Exercises the live large-page demotion adapter against a real
/// physical-memory-offset mapping. The smoke test insists the selected frame
/// starts inside a large leaf, demotes 1 GiB -> 2 MiB -> 4 KiB as required, then
/// verifies the physical translation and effective permissions are preserved.
pub fn verify_large_page_demotion_smoke_test(boot_info: &BootInfo) -> Result<bool, PagingError> {
    let data_frame =
        crate::memory::allocate_frame().map_err(|_| PagingError::FrameAllocationFailed)?;
    let data_physical = data_frame.physical_address();

    let test_result = (|| {
        let physical_memory_offset = match boot_info.physical_memory_offset {
            Optional::Some(offset) => offset,
            Optional::None => return Err(PagingError::PhysicalMemoryOffsetUnavailable),
        };
        let virtual_address = physical_memory_offset
            .checked_add(data_physical)
            .filter(|address| is_canonical_4level(*address) && (*address & (PAGE_SIZE - 1)) == 0)
            .ok_or(PagingError::PhysicalMemoryOffsetUnavailable)?;
        let root_table_physical = active_root_table_physical();
        let mut editor = KernelPageTableEditor::new(boot_info, virtual_address)?;
        let initial = translate_with_editor(&mut editor, root_table_physical, virtual_address)
            .map_err(PagingError::Translation)?;
        if initial.physical_address != data_physical
            || !initial.writable
            || initial.user_accessible
            || initial.executable
            || initial.page_size < PAGE_SIZE
        {
            return Err(PagingError::LargePageDemotionFailed);
        }

        // A bootloader may already have split this direct-map area. Do not fail
        // a valid boot or claim to have tested demotion when no large leaf exists.
        if initial.page_size == PAGE_SIZE {
            return Ok(false);
        }

        let expected_permissions = (
            initial.writable,
            initial.user_accessible,
            initial.executable,
        );
        let mut current = initial;
        let mut completed_demotions = 0usize;
        while current.page_size > PAGE_SIZE && completed_demotions < 2 {
            let expected_physical_start = current
                .physical_address
                .checked_sub(virtual_address & (current.page_size - 1))
                .ok_or(PagingError::LargePageDemotionFailed)?;
            let receipt = demote_large_page_for_address(boot_info, virtual_address)?
                .ok_or(PagingError::LargePageDemotionFailed)?;
            if receipt.virtual_length != current.page_size
                || receipt.physical_start != expected_physical_start
            {
                return Err(PagingError::LargePageDemotionFailed);
            }
            completed_demotions += 1;

            let mut check_editor = KernelPageTableEditor::new(boot_info, virtual_address)?;
            current =
                translate_with_editor(&mut check_editor, root_table_physical, virtual_address)
                    .map_err(PagingError::Translation)?;
            if current.physical_address != data_physical
                || (
                    current.writable,
                    current.user_accessible,
                    current.executable,
                ) != expected_permissions
                || current.page_size >= receipt.virtual_length
            {
                return Err(PagingError::LargePageDemotionFailed);
            }
        }
        if completed_demotions == 0 || current.page_size != PAGE_SIZE {
            return Err(PagingError::LargePageDemotionFailed);
        }

        let mut access_editor = KernelPageTableEditor::new(boot_info, virtual_address)?;
        let alias = access_editor
            .offset_alias(data_physical)
            .ok_or(PagingError::LargePageDemotionFailed)?;
        const DEMOTION_SMOKE_SENTINEL: u64 = 0x4445_4d4f_5445_5631;
        // SAFETY: the owned data frame still has a validated writable,
        // supervisor-only, NX direct-map alias and remains allocated.
        unsafe { ptr::write_volatile(alias.cast::<u64>(), DEMOTION_SMOKE_SENTINEL) };
        // SAFETY: the same checked alias is read immediately after the write.
        let observed = unsafe { ptr::read_volatile(alias.cast::<u64>()) };
        if observed != DEMOTION_SMOKE_SENTINEL {
            return Err(PagingError::LargePageDemotionFailed);
        }
        Ok(true)
    })();

    let release_result = release_data_frame(data_frame);
    if release_result.is_err() {
        return Err(PagingError::FrameReleaseFailed);
    }
    test_result
}

/// Holds the owned data frame and target VA for one dedicated QEMU protection test.
/// The frame token deliberately remains alive for as long as the mapping is used.
#[cfg(any(
    feature = "test-supervisor-write-protection",
    feature = "test-nx-protection"
))]
pub struct ProtectionTestMapping {
    pub virtual_address: u64,
    pub physical_address: u64,
    _frame: Frame,
}

#[cfg(any(
    feature = "test-supervisor-write-protection",
    feature = "test-nx-protection"
))]
struct ProtectionTestFrameGuard<'a> {
    boot_info: &'a BootInfo,
    frame: Option<Frame>,
    mapped_virtual_address: Option<u64>,
}

#[cfg(any(
    feature = "test-supervisor-write-protection",
    feature = "test-nx-protection"
))]
impl<'a> ProtectionTestFrameGuard<'a> {
    fn new(boot_info: &'a BootInfo, frame: Frame) -> Self {
        Self {
            boot_info,
            frame: Some(frame),
            mapped_virtual_address: None,
        }
    }

    fn physical_address(&self) -> u64 {
        self.frame
            .as_ref()
            .expect("protection test guard owns a frame")
            .physical_address()
    }

    fn mark_mapped(&mut self, virtual_address: u64) {
        self.mapped_virtual_address = Some(virtual_address);
    }

    fn into_frame(mut self) -> Frame {
        self.mapped_virtual_address = None;
        self.frame
            .take()
            .expect("protection test guard owns a frame")
    }
}

#[cfg(any(
    feature = "test-supervisor-write-protection",
    feature = "test-nx-protection"
))]
impl Drop for ProtectionTestFrameGuard<'_> {
    fn drop(&mut self) {
        let Some(frame) = self.frame.take() else {
            return;
        };

        if let Some(virtual_address) = self.mapped_virtual_address {
            let root = active_root_table_physical();
            let Ok(mut editor) = KernelPageTableEditor::new(self.boot_info, virtual_address) else {
                // Keep the allocator's ownership bit set if safe unmapping cannot
                // be proven; a leaked frame is safer than a dangling live mapping.
                let _unreleased_frame = frame;
                return;
            };
            match unmap_4k(root, virtual_address, &mut editor) {
                Ok(unmapped) => {
                    // unmap_4k has cleared the leaf entry. Flush the stale
                    // translation before checking identity or deciding whether
                    // the frame can be returned to the allocator.
                    invalidate_local_tlb(virtual_address);
                    if unmapped.physical_address == frame.physical_address() {
                        if let Err((_error, _frame)) = crate::memory::free_frame(frame) {
                            // Keep the frame allocated on release failure; never panic
                            // while cleaning up a failed test setup.
                        }
                    } else {
                        // The mapping was removed, but the returned frame identity
                        // is unexpected. Do not recycle the frame we still own.
                        let _unreleased_frame = frame;
                    }
                }
                Err(_) => {
                    // Do not recycle a frame while its mapping state is uncertain.
                    let _unreleased_frame = frame;
                }
            }
        } else if let Err((_error, _frame)) = crate::memory::free_frame(frame) {
            // The frame remains allocated if the allocator rejects release.
        }
    }
}

#[cfg(any(
    feature = "test-supervisor-write-protection",
    feature = "test-nx-protection"
))]
#[derive(Clone, Copy)]
enum ProtectionTestPayload {
    Sentinel,
    Ud2,
}

#[cfg(feature = "test-supervisor-write-protection")]
/// Prepare a supervisor-readable, supervisor-read-only mapping whose attempted
/// supervisor write must raise a protection-violation page fault.
pub fn install_supervisor_write_protection_test(
    boot_info: &BootInfo,
) -> Result<ProtectionTestMapping, PagingError> {
    prepare_protection_test_mapping(
        boot_info,
        // The sentinel is data: keep its leaf NX so the persistent writable
        // physical-memory alias cannot create a frame-wide W+X combination.
        PagePermissions::new(false, false, false),
        ProtectionTestPayload::Sentinel,
    )
}

#[cfg(feature = "test-nx-protection")]
/// Prepare a supervisor-readable, supervisor-read-only, NX mapping containing
/// UD2. A successful instruction fetch would therefore fail the test with #UD.
pub fn install_nx_execution_protection_test(
    boot_info: &BootInfo,
) -> Result<ProtectionTestMapping, PagingError> {
    prepare_protection_test_mapping(
        boot_info,
        PagePermissions::new(false, false, false),
        ProtectionTestPayload::Ud2,
    )
}

#[cfg(any(
    feature = "test-supervisor-write-protection",
    feature = "test-nx-protection"
))]
fn prepare_protection_test_mapping(
    boot_info: &BootInfo,
    protected_permissions: PagePermissions,
    payload: ProtectionTestPayload,
) -> Result<ProtectionTestMapping, PagingError> {
    let frame = crate::memory::allocate_frame().map_err(|_| PagingError::FrameAllocationFailed)?;
    let mut frame_guard = ProtectionTestFrameGuard::new(boot_info, frame);
    let physical_address = frame_guard.physical_address();
    let recursive_index = match boot_info.recursive_index {
        Optional::Some(index) if is_safe_recursive_mapping_index(index) => index,
        Optional::Some(_) => {
            return Err(PagingError::InvalidRecursiveIndex);
        }
        Optional::None => {
            return Err(PagingError::RecursiveMappingUnavailable);
        }
    };
    let physical_memory_offset = match boot_info.physical_memory_offset {
        Optional::Some(offset) => offset,
        Optional::None => {
            return Err(PagingError::PhysicalMemoryOffsetUnavailable);
        }
    };
    let highest_physical_end = boot_info
        .memory_regions
        .iter()
        .map(|region| region.end)
        .max()
        .unwrap_or(0)
        .max(1u64 << 32);
    let Some(physical_mapping_end) = physical_memory_offset.checked_add(highest_physical_end)
    else {
        return Err(PagingError::PhysicalMemoryOffsetUnavailable);
    };
    let root_table_physical = active_root_table_physical();

    for candidate_pml4_index in FIRST_CANDIDATE_PML4_INDEX..512 {
        if candidate_pml4_index == recursive_index {
            continue;
        }
        let raw_candidate = u64::from(candidate_pml4_index) << 39;
        let candidate = raw_candidate | 0xffff_0000_0000_0000;
        if candidate >= physical_memory_offset && candidate < physical_mapping_end {
            continue;
        }

        let mut editor = match KernelPageTableEditor::new(boot_info, candidate) {
            Ok(editor) => editor,
            Err(error) => return Err(error),
        };

        // Initialize the owned Usable data frame through the checked physical-
        // memory-offset alias. This avoids a temporary VA mapping and unmap, so
        // a candidate that fails map_supervisor_4k's read-only preflight leaves the page-table
        // tree untouched and can safely be skipped.
        let direct_alias = editor
            .offset_alias(physical_address)
            .ok_or(PagingError::PhysicalMemoryOffsetUnavailable)?;
        // SAFETY: offset_alias verifies that this Usable frame is mapped to the
        // expected physical page and that the alias permits supervisor writes.
        unsafe {
            match payload {
                ProtectionTestPayload::Sentinel => {
                    ptr::write_volatile(direct_alias.cast::<u64>(), MAPPING_SMOKE_SENTINEL);
                }
                ProtectionTestPayload::Ud2 => {
                    // x86 UD2 encoding is 0x0f, 0x0b in little-endian order.
                    ptr::write_volatile(direct_alias.cast::<u16>(), 0x0b0f);
                }
            }
        }

        // SAFETY: frame_guard retains the frame token until the test mapping is
        // explicitly unmapped and the frame is released by the guard.
        match unsafe {
            map_supervisor_4k(
                root_table_physical,
                candidate,
                physical_address,
                protected_permissions,
                &mut editor,
            )
        } {
            Ok(()) => frame_guard.mark_mapped(candidate),
            Err(error) if error.is_retryable_for_mapping_candidate() => continue,
            Err(error) => return Err(PagingError::MappingMutation(error)),
        }
        invalidate_local_tlb(candidate);

        let entries = read_active_leaf_path(&mut editor, root_table_physical, candidate)?;
        let ancestor_permissions_valid = entries[..3]
            .iter()
            .all(|entry| entry & PRESENT != 0 && entry & WRITABLE != 0 && entry & NO_EXECUTE == 0);
        let leaf = entries[3];
        let leaf_permissions_valid = leaf & PRESENT != 0
            && leaf & PHYSICAL_ADDRESS_MASK == physical_address
            && leaf & WRITABLE == 0
            && leaf & USER_ACCESSIBLE == 0
            && (leaf & NO_EXECUTE != 0) == !protected_permissions.executable;
        let cr0: u64;
        // SAFETY: reading CR0 is valid in privileged x86_64 kernel execution.
        unsafe {
            asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        }
        if !ancestor_permissions_valid || !leaf_permissions_valid || cr0 & CR0_WP == 0 {
            return Err(PagingError::MappingSmokeMismatch);
        }

        let mapped_value_valid = match payload {
            // SAFETY: reads are allowed through the present supervisor read-only mapping.
            ProtectionTestPayload::Sentinel => unsafe {
                ptr::read_volatile(candidate as *const u64) == MAPPING_SMOKE_SENTINEL
            },
            // Data reads remain legal on NX pages; only instruction fetch is denied.
            ProtectionTestPayload::Ud2 => unsafe {
                ptr::read_volatile(candidate as *const u16) == 0x0b0f
            },
        };
        let translation = translate_with_editor(&mut editor, root_table_physical, candidate);
        let effective_permissions_valid = translation.is_ok_and(|result| {
            result.physical_address == physical_address
                && result.page_size == PAGE_SIZE
                && !result.writable
                && !result.user_accessible
                && result.executable == protected_permissions.executable
        });
        if !mapped_value_valid || !effective_permissions_valid {
            return Err(PagingError::MappingSmokeMismatch);
        }

        return Ok(ProtectionTestMapping {
            virtual_address: candidate,
            physical_address,
            _frame: frame_guard.into_frame(),
        });
    }

    Err(PagingError::NoUnusedVirtualAddress)
}

#[cfg(any(
    feature = "test-supervisor-write-protection",
    feature = "test-nx-protection"
))]
fn read_active_leaf_path(
    editor: &mut KernelPageTableEditor<'_>,
    root_table_physical: u64,
    virtual_address: u64,
) -> Result<[u64; 4], PagingError> {
    let mut entries = [0u64; 4];
    let mut table_physical = root_table_physical;
    for (position, level) in [4u8, 3, 2, 1].into_iter().enumerate() {
        let index =
            virtual_index(virtual_address, level).ok_or(PagingError::MappingSmokeMismatch)?;
        let entry = editor
            .read_entry(table_physical, index, level)
            .ok_or(PagingError::MappingSmokeMismatch)?;
        if entry & PRESENT == 0 || (level > 1 && entry & LARGE_PAGE != 0) {
            return Err(PagingError::MappingSmokeMismatch);
        }
        entries[position] = entry;
        if level > 1 {
            table_physical = entry & PHYSICAL_ADDRESS_MASK;
            if !valid_physical_page(table_physical, editor.physical_address_bits())
                || !editor.is_table_frame(table_physical)
            {
                return Err(PagingError::MappingSmokeMismatch);
            }
        }
    }
    Ok(entries)
}

#[cfg(feature = "test-vm-transitions")]
const TRANSITION_FIRST_SENTINEL: u64 = 0x4f4e_455f_564d_4131;
#[cfg(feature = "test-vm-transitions")]
const TRANSITION_SECOND_SENTINEL: u64 = 0x4f4e_455f_564d_4232;

#[cfg(feature = "test-vm-transitions")]
#[derive(Clone, Copy, Eq, PartialEq)]
enum TransitionTestState {
    Unmapped,
    FirstMapped,
    UnmappedAfterFirst,
    SecondMapped,
    UnmappedAfterSecond,
}

/// Releases a test frame unless setup transfers its ownership into the test context.
#[cfg(feature = "test-vm-transitions")]
struct TransitionTestFrameGuard(Option<Frame>);

#[cfg(feature = "test-vm-transitions")]
impl TransitionTestFrameGuard {
    fn new(frame: Frame) -> Self {
        Self(Some(frame))
    }

    fn physical_address(&self) -> u64 {
        self.0
            .as_ref()
            .expect("guard owns a frame")
            .physical_address()
    }

    fn into_frame(mut self) -> Frame {
        self.0.take().expect("guard owns a frame")
    }

    fn disarm(mut self) {
        // Used only if allocator uniqueness is violated and the address appears twice.
        // Do not attempt to return two tokens that alias the same physical frame.
        let _ = self.0.take();
    }
}

#[cfg(feature = "test-vm-transitions")]
impl Drop for TransitionTestFrameGuard {
    fn drop(&mut self) {
        if let Some(frame) = self.0.take() {
            if let Err((_error, _frame)) = crate::memory::free_frame(frame) {
                // Do not panic while handling a test setup error. On cleanup failure,
                // the allocator still regards the frame as allocated, so it is safer
                // to leave that capacity unavailable than risk a double release.
            }
        }
    }
}

/// Owns both data frames for the dedicated active map/unmap/remap QEMU case.
/// The same virtual address is first mapped to one frame and then to a distinct
/// frame so stale TLB translations are observable as stale payload data.
#[cfg(feature = "test-vm-transitions")]
pub struct MappingTransitionTest {
    pub virtual_address: u64,
    pub first_physical_address: u64,
    pub second_physical_address: u64,
    first_frame: Frame,
    second_frame: Frame,
    state: TransitionTestState,
}

#[cfg(feature = "test-vm-transitions")]
pub fn prepare_mapping_transition_test(
    boot_info: &BootInfo,
) -> Result<MappingTransitionTest, PagingError> {
    let first_frame = TransitionTestFrameGuard::new(
        crate::memory::allocate_frame().map_err(|_| PagingError::FrameAllocationFailed)?,
    );
    let second_frame = TransitionTestFrameGuard::new(
        crate::memory::allocate_frame().map_err(|_| PagingError::FrameAllocationFailed)?,
    );
    let first_physical_address = first_frame.physical_address();
    let second_physical_address = second_frame.physical_address();
    if first_physical_address == second_physical_address {
        // A duplicate address violates allocator uniqueness. Release only one
        // token so this failure path cannot attempt a duplicate free.
        second_frame.disarm();
        return Err(PagingError::MappingSmokeMismatch);
    }

    let recursive_index = match boot_info.recursive_index {
        Optional::Some(index) if is_safe_recursive_mapping_index(index) => index,
        Optional::Some(_) => return Err(PagingError::InvalidRecursiveIndex),
        Optional::None => return Err(PagingError::RecursiveMappingUnavailable),
    };
    let physical_memory_offset = match boot_info.physical_memory_offset {
        Optional::Some(offset) => offset,
        Optional::None => return Err(PagingError::PhysicalMemoryOffsetUnavailable),
    };
    let highest_physical_end = boot_info
        .memory_regions
        .iter()
        .map(|region| region.end)
        .max()
        .unwrap_or(0)
        .max(1u64 << 32);
    let Some(physical_mapping_end) = physical_memory_offset.checked_add(highest_physical_end)
    else {
        return Err(PagingError::PhysicalMemoryOffsetUnavailable);
    };
    let root_table_physical = active_root_table_physical();

    // Select a canonical high-half VA whose translation is currently absent.
    // Exclude the recursive PML4 slot and the complete bootloader direct-map
    // range before any page-table mutation is attempted.
    for candidate_pml4_index in FIRST_CANDIDATE_PML4_INDEX..512 {
        if candidate_pml4_index == recursive_index {
            continue;
        }
        let raw_candidate = u64::from(candidate_pml4_index) << 39;
        let candidate = raw_candidate | 0xffff_0000_0000_0000;
        if candidate >= physical_memory_offset && candidate < physical_mapping_end {
            continue;
        }
        let Ok(mut editor) = KernelPageTableEditor::new(boot_info, candidate) else {
            return Err(PagingError::MappingSmokeMismatch);
        };
        match translate_with_editor(&mut editor, root_table_physical, candidate) {
            Err(PageTableError::NotPresent { .. }) => {
                return Ok(MappingTransitionTest {
                    virtual_address: candidate,
                    first_physical_address,
                    second_physical_address,
                    first_frame: first_frame.into_frame(),
                    second_frame: second_frame.into_frame(),
                    state: TransitionTestState::Unmapped,
                });
            }
            // A recursive alias may be unavailable for this candidate without
            // implying that the active page tables are malformed. Keep searching.
            Err(error) if error.is_retryable_for_mapping_candidate() => continue,
            // Structural translation errors must never be treated as an empty slot.
            Err(error) => return Err(PagingError::Translation(error)),
            Ok(_) => {}
        }
    }

    Err(PagingError::NoUnusedVirtualAddress)
}

#[cfg(feature = "test-vm-transitions")]
impl MappingTransitionTest {
    pub fn map_first(&mut self, boot_info: &BootInfo) -> Result<(), PagingError> {
        if self.state != TransitionTestState::Unmapped {
            return Err(PagingError::MappingSmokeMismatch);
        }
        self.map_frame(boot_info, self.first_physical_address)?;
        self.state = TransitionTestState::FirstMapped;
        Ok(())
    }

    pub fn verify_first(&mut self, boot_info: &BootInfo) -> Result<(), PagingError> {
        if self.state != TransitionTestState::FirstMapped {
            return Err(PagingError::MappingSmokeMismatch);
        }
        // SAFETY: map_first installed a writable supervisor-only mapping to the
        // owned first frame and invalidated the target VA in the local TLB.
        unsafe {
            ptr::write_volatile(self.virtual_address as *mut u64, TRANSITION_FIRST_SENTINEL);
        }
        let observed = unsafe { ptr::read_volatile(self.virtual_address as *const u64) };
        if observed != TRANSITION_FIRST_SENTINEL {
            return Err(PagingError::MappingSmokeMismatch);
        }
        self.verify_translation(boot_info, self.first_physical_address)
    }

    pub fn unmap_first(&mut self, boot_info: &BootInfo) -> Result<(), PagingError> {
        if self.state != TransitionTestState::FirstMapped {
            return Err(PagingError::MappingSmokeMismatch);
        }
        self.unmap_frame(boot_info, self.first_physical_address)?;
        self.state = TransitionTestState::UnmappedAfterFirst;
        Ok(())
    }

    pub fn map_second(&mut self, boot_info: &BootInfo) -> Result<(), PagingError> {
        if self.state != TransitionTestState::UnmappedAfterFirst {
            return Err(PagingError::MappingSmokeMismatch);
        }
        let root_table_physical = active_root_table_physical();
        let mut editor = KernelPageTableEditor::new(boot_info, self.virtual_address)?;
        let direct_alias = editor
            .offset_alias(self.second_physical_address)
            .ok_or(PagingError::PhysicalMemoryOffsetUnavailable)?;
        // Initialize the second frame through its checked direct-map alias
        // before remapping the same VA. If INVLPG is missing after remap, the
        // stale translation still reads the first frame's different sentinel.
        unsafe {
            ptr::write_volatile(direct_alias.cast::<u64>(), TRANSITION_SECOND_SENTINEL);
        }
        // SAFETY: MappingTransitionTest retains both frame tokens until after
        // the corresponding mappings are removed and the test is finished.
        unsafe {
            map_supervisor_4k(
                root_table_physical,
                self.virtual_address,
                self.second_physical_address,
                PagePermissions::new(true, false, false),
                &mut editor,
            )
        }
        .map_err(PagingError::MappingMutation)?;
        invalidate_local_tlb(self.virtual_address);
        self.state = TransitionTestState::SecondMapped;
        Ok(())
    }

    pub fn verify_second(&mut self, boot_info: &BootInfo) -> Result<(), PagingError> {
        if self.state != TransitionTestState::SecondMapped {
            return Err(PagingError::MappingSmokeMismatch);
        }
        // Do not write through the test VA before checking: the preloaded second
        // sentinel detects stale TLB translations to the first physical frame.
        let observed = unsafe { ptr::read_volatile(self.virtual_address as *const u64) };
        if observed != TRANSITION_SECOND_SENTINEL {
            return Err(PagingError::MappingSmokeMismatch);
        }
        self.verify_translation(boot_info, self.second_physical_address)
    }

    pub fn unmap_second(&mut self, boot_info: &BootInfo) -> Result<(), PagingError> {
        if self.state != TransitionTestState::SecondMapped {
            return Err(PagingError::MappingSmokeMismatch);
        }
        self.unmap_frame(boot_info, self.second_physical_address)?;
        self.state = TransitionTestState::UnmappedAfterSecond;
        Ok(())
    }

    pub fn finish(self) -> Result<(), PagingError> {
        if self.state != TransitionTestState::UnmappedAfterSecond {
            return Err(PagingError::MappingSmokeMismatch);
        }
        release_data_frame(self.first_frame)?;
        release_data_frame(self.second_frame)
    }

    fn map_frame(
        &mut self,
        boot_info: &BootInfo,
        physical_address: u64,
    ) -> Result<(), PagingError> {
        let root_table_physical = active_root_table_physical();
        let mut editor = KernelPageTableEditor::new(boot_info, self.virtual_address)?;
        // SAFETY: MappingTransitionTest retains the frame token until the
        // corresponding mapping is removed and the test is finished.
        unsafe {
            map_supervisor_4k(
                root_table_physical,
                self.virtual_address,
                physical_address,
                PagePermissions::new(true, false, false),
                &mut editor,
            )
        }
        .map_err(PagingError::MappingMutation)?;
        invalidate_local_tlb(self.virtual_address);
        Ok(())
    }

    fn unmap_frame(
        &mut self,
        boot_info: &BootInfo,
        physical_address: u64,
    ) -> Result<(), PagingError> {
        let root_table_physical = active_root_table_physical();
        let mut editor = KernelPageTableEditor::new(boot_info, self.virtual_address)?;
        let removed = unmap_4k(root_table_physical, self.virtual_address, &mut editor)
            .map_err(PagingError::MappingMutation)?;
        invalidate_local_tlb(self.virtual_address);
        if removed.physical_address != physical_address
            || removed.permissions != PagePermissions::new(true, false, false)
            || !matches!(
                translate_with_editor(&mut editor, root_table_physical, self.virtual_address),
                Err(PageTableError::NotPresent { .. })
            )
        {
            return Err(PagingError::MappingSmokeMismatch);
        }
        Ok(())
    }

    fn verify_translation(
        &mut self,
        boot_info: &BootInfo,
        expected_physical_address: u64,
    ) -> Result<(), PagingError> {
        let root_table_physical = active_root_table_physical();
        let mut editor = KernelPageTableEditor::new(boot_info, self.virtual_address)?;
        let translation =
            translate_with_editor(&mut editor, root_table_physical, self.virtual_address)
                .map_err(PagingError::Translation)?;
        if translation.physical_address != expected_physical_address
            || translation.page_size != PAGE_SIZE
            || !translation.writable
            || translation.user_accessible
            || translation.executable
        {
            return Err(PagingError::MappingSmokeMismatch);
        }
        Ok(())
    }
}

fn release_data_frame(frame: Frame) -> Result<(), PagingError> {
    match crate::memory::free_frame(frame) {
        Ok(()) => Ok(()),
        Err((_error, _frame)) => Err(PagingError::FrameReleaseFailed),
    }
}

/// Releases a rejected W^X scan candidate without rewinding the allocator hint.
#[cfg(feature = "test-wx-runtime-audit")]
fn release_data_frame_preserving_hint(frame: Frame) {
    match crate::memory::free_frame_preserving_hint(frame) {
        Ok(()) => {}
        Err((error, frame)) => {
            // A failed free returns ownership of the still-allocated frame. This
            // test has no ownership registry to retain that token for a retry, so
            // stop immediately while the token is still live instead of continuing
            // the scan and silently stranding it.
            let physical_address = frame.physical_address();
            crate::serial_write(error.message());
            panic!(
                "failed to release W^X scan frame {:#x}; halting with frame token retained",
                physical_address
            );
        }
    }
}
