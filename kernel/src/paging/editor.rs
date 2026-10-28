use super::*;

mod acceptance;
mod wx_audit;

/// Establish CPU controls required before interpreting or changing leaf permissions.
///
/// NX is mandatory for this milestone: the kernel fails closed if the processor
/// does not advertise NX or the extended physical-address-width leaf.
pub fn initialize_paging_controls() -> Result<(), PagingError> {
    // SAFETY: CPUID is available at the x86_64 kernel privilege level.
    let maximum_extended_leaf = __cpuid(0x8000_0000).eax;
    validate_extended_cpuid_leaf(maximum_extended_leaf, CPUID_PHYSICAL_ADDRESS_WIDTH)
        .map_err(map_paging_precondition_error)?;
    // SAFETY: the maximum extended CPUID leaf was checked above.
    let features = __cpuid(CPUID_EXTENDED_FEATURES);
    // SAFETY: the extended physical-address-width CPUID leaf was checked above.
    let physical_address_bits = (__cpuid(CPUID_PHYSICAL_ADDRESS_WIDTH).eax & 0xff) as u8;
    validate_paging_cpu_capabilities(features.edx, physical_address_bits)
        .map_err(map_paging_precondition_error)?;

    let mut cr0: u64;
    // SAFETY: reading and writing CR0 is valid in privileged kernel execution.
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        cr0 |= CR0_WP;
        asm!("mov cr0, {}", in(reg) cr0, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
    }
    if cr0 & CR0_WP == 0 {
        return Err(PagingError::SupervisorWriteProtectionDisabled);
    }

    let mut low: u32;
    let mut high: u32;
    // SAFETY: EFER is the architectural extended-feature-enable MSR.
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") EFER_MSR,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags)
        );
    }
    let mut efer = (u64::from(high) << 32) | u64::from(low);
    if efer & EFER_NXE == 0 {
        efer |= EFER_NXE;
        low = efer as u32;
        high = (efer >> 32) as u32;
        // SAFETY: CPUID confirmed NX support; only the EFER.NXE bit is changed.
        unsafe {
            asm!(
                "wrmsr",
                in("ecx") EFER_MSR,
                in("eax") low,
                in("edx") high,
                options(nomem, nostack, preserves_flags)
            );
            asm!(
                "rdmsr",
                in("ecx") EFER_MSR,
                out("eax") low,
                out("edx") high,
                options(nomem, nostack, preserves_flags)
            );
        }
        efer = (u64::from(high) << 32) | u64::from(low);
    }
    validate_efer_nx_enable(efer).map_err(map_paging_precondition_error)?;

    Ok(())
}

struct TableFrameRegistry {
    held: AtomicBool,
    registry: core::cell::UnsafeCell<PageTableFrameRegistry<Frame, TABLE_FRAME_CAPACITY>>,
}

// SAFETY: every access to the UnsafeCell is through a TableFrameRegistryGuard.
// The non-blocking atomic guard serializes registry operations. Page-table tree
// mutation additionally remains a single-CPU, maskable-interrupts-disabled
// operation; disabling interrupts alone is not an SMP synchronization protocol.
unsafe impl Sync for TableFrameRegistry {}

struct TableFrameRegistryGuard<'a> {
    owner: &'a TableFrameRegistry,
}

impl core::ops::Deref for TableFrameRegistryGuard<'_> {
    type Target = PageTableFrameRegistry<Frame, TABLE_FRAME_CAPACITY>;

    fn deref(&self) -> &Self::Target {
        // SAFETY: this guard owns the registry's atomic access token.
        unsafe { &*self.owner.registry.get() }
    }
}

impl core::ops::DerefMut for TableFrameRegistryGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: this guard owns the registry's exclusive atomic access token.
        unsafe { &mut *self.owner.registry.get() }
    }
}

impl Drop for TableFrameRegistryGuard<'_> {
    fn drop(&mut self) {
        self.owner.held.store(false, Ordering::Release);
    }
}

impl TableFrameRegistry {
    const fn new() -> Self {
        Self {
            held: AtomicBool::new(false),
            registry: core::cell::UnsafeCell::new(PageTableFrameRegistry::new()),
        }
    }

    fn lock(&self) -> TableFrameRegistryGuard<'_> {
        if self
            .held
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // Never continue after losing exclusive registry access. This is a
            // deliberate fail-stop; a spin here could deadlock an NMI/interrupt.
            panic!("concurrent page-table frame registry access");
        }
        TableFrameRegistryGuard { owner: self }
    }
}

static TABLE_FRAMES: TableFrameRegistry = TableFrameRegistry::new();

struct KernelWxAliasRegistry {
    held: AtomicBool,
    registry: core::cell::UnsafeCell<Option<FrameWxRegistry<WX_ALIAS_REGISTRY_CAPACITY>>>,
}

// SAFETY: every access to the optional registry is protected by this non-blocking
// guard. Page-table mutations remain single-CPU with maskable interrupts disabled;
// this lock is not an SMP synchronization protocol.
unsafe impl Sync for KernelWxAliasRegistry {}

struct KernelWxAliasRegistryGuard<'a> {
    owner: &'a KernelWxAliasRegistry,
}

impl core::ops::Deref for KernelWxAliasRegistryGuard<'_> {
    type Target = Option<FrameWxRegistry<WX_ALIAS_REGISTRY_CAPACITY>>;

    fn deref(&self) -> &Self::Target {
        // SAFETY: the guard owns the registry access token.
        unsafe { &*self.owner.registry.get() }
    }
}

impl core::ops::DerefMut for KernelWxAliasRegistryGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: the guard owns the exclusive registry access token.
        unsafe { &mut *self.owner.registry.get() }
    }
}

impl Drop for KernelWxAliasRegistryGuard<'_> {
    fn drop(&mut self) {
        self.owner.held.store(false, Ordering::Release);
    }
}

impl KernelWxAliasRegistry {
    const fn new() -> Self {
        Self {
            held: AtomicBool::new(false),
            registry: core::cell::UnsafeCell::new(None),
        }
    }

    fn lock(&self) -> KernelWxAliasRegistryGuard<'_> {
        if self
            .held
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            panic!("concurrent kernel W^X alias registry access");
        }
        KernelWxAliasRegistryGuard { owner: self }
    }
}

static KERNEL_WX_ALIASES: KernelWxAliasRegistry = KernelWxAliasRegistry::new();

fn with_kernel_wx_registry<T>(
    physical_address_bits: u8,
    operation: impl FnOnce(&mut FrameWxRegistry<WX_ALIAS_REGISTRY_CAPACITY>) -> Result<T, FrameWxError>,
) -> Result<T, FrameWxError> {
    let mut guard = KERNEL_WX_ALIASES.lock();
    if guard.is_none() {
        *guard = Some(FrameWxRegistry::new(physical_address_bits)?);
    }
    let registry = guard
        .as_mut()
        .expect("W^X registry initialization must produce a value");
    if registry.physical_address_bits() != physical_address_bits {
        return Err(FrameWxError::InvalidPhysicalAddressWidth);
    }
    operation(registry)
}

fn reserve_kernel_wx_alias(
    root: u64,
    virtual_address: u64,
    physical_address: u64,
    permissions: PagePermissions,
    physical_address_bits: u8,
) -> Result<(), PageTableMutationError> {
    with_kernel_wx_registry(physical_address_bits, |registry| {
        registry
            .reserve_alias_range(
                root,
                virtual_address,
                physical_address,
                PAGE_SIZE,
                FrameWxPermissions::new(permissions.writable, permissions.executable),
            )
            .map(|_| ())
    })
    .map_err(|_| PageTableMutationError::WxAliasRegistryFailure)
}

fn commit_kernel_wx_alias(root: u64, virtual_address: u64, physical_address_bits: u8) {
    if with_kernel_wx_registry(physical_address_bits, |registry| {
        registry.commit_alias_at(root, virtual_address)
    })
    .is_err()
    {
        panic!("published mapping has no matching W^X reservation");
    }
}

fn begin_kernel_wx_alias_removal(
    root: u64,
    virtual_address: u64,
    physical_address: u64,
    permissions: PagePermissions,
    physical_address_bits: u8,
) -> Result<(), PageTableMutationError> {
    with_kernel_wx_registry(physical_address_bits, |registry| {
        registry.begin_removal_for_alias(
            root,
            virtual_address,
            physical_address,
            PAGE_SIZE,
            FrameWxPermissions::new(permissions.writable, permissions.executable),
        )
    })
    .map_err(|_| PageTableMutationError::WxAliasRegistryFailure)
}

fn complete_kernel_wx_alias_removal(root: u64, virtual_address: u64, physical_address_bits: u8) {
    if with_kernel_wx_registry(physical_address_bits, |registry| {
        registry.complete_removal_at(root, virtual_address)
    })
    .is_err()
    {
        panic!("detached mapping has no matching retiring W^X alias");
    }
}

// Address-space roots are page tables too, but their ownership is held by
// AddressSpaceRoot/ActiveAddressSpaceRoot rather than TABLE_FRAMES. Track every
// live kernel-created root frame so leaf mapping and user-frame zeroing reject
// roots that are not the current CR3 or the editor's immediate target.
//
// Zero is never a valid root physical address and is used as the empty marker.
// The kernel runs single-CPU with maskable interrupts disabled during these
// operations; atomics keep the individual slot operations race-free if that
// contract is later tightened.
static ADDRESS_SPACE_ROOT_FRAMES: [AtomicU64; ADDRESS_SPACE_ROOT_CAPACITY] =
    [const { AtomicU64::new(0) }; ADDRESS_SPACE_ROOT_CAPACITY];

/// Records one live kernel-created address-space root frame.
///
/// Returns false when the registry is full. Duplicate registration is
/// idempotent so a caller that already owns a root can safely revalidate it.
pub fn register_address_space_root(physical_address: u64) -> bool {
    if physical_address == 0 || physical_address & (PAGE_SIZE - 1) != 0 {
        return false;
    }
    for slot in ADDRESS_SPACE_ROOT_FRAMES.iter() {
        if slot.load(Ordering::Acquire) == physical_address {
            return true;
        }
    }
    for slot in ADDRESS_SPACE_ROOT_FRAMES.iter() {
        if slot
            .compare_exchange(0, physical_address, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return true;
        }
    }
    false
}

/// Removes exactly one live-root registry entry for dedicated CR3 guard fault-injection tests.
/// This deliberately bypasses the production unregister policy and must never be compiled
/// into normal kernel images.
#[cfg(any(
    feature = "test-cr3-switch-guard",
    feature = "test-cr3-activation-guard"
))]
pub fn remove_address_space_root_registration_for_cr3_test(physical_address: u64) -> bool {
    if physical_address == 0 || physical_address & (PAGE_SIZE - 1) != 0 {
        return false;
    }

    let mut matching_slot = None;
    for (index, slot) in ADDRESS_SPACE_ROOT_FRAMES.iter().enumerate() {
        if slot.load(Ordering::Acquire) == physical_address
            && matching_slot.replace(index).is_some()
        {
            return false;
        }
    }
    let Some(index) = matching_slot else {
        return false;
    };
    ADDRESS_SPACE_ROOT_FRAMES[index]
        .compare_exchange(physical_address, 0, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

/// Ensures a released root frame is absent from the registry.
///
/// A root may be removed only after its frame is no longer allocator-owned and
/// is not the current CR3. This prevents a live, still-activatable root from
/// being silently removed from the W^X audit's authoritative lifecycle set.
/// Missing or duplicate entries, an active root, and allocator/query uncertainty
/// fail closed so cleanup cannot silently shrink the audit's declared root set.
pub fn unregister_address_space_root(physical_address: u64) -> bool {
    if physical_address == 0
        || physical_address & (PAGE_SIZE - 1) != 0
        || physical_address == active_root_table_physical()
        || !matches!(
            crate::memory::is_frame_allocated(physical_address),
            Ok(false)
        )
    {
        return false;
    }

    let mut matching_slot = None;
    for (index, slot) in ADDRESS_SPACE_ROOT_FRAMES.iter().enumerate() {
        if slot.load(Ordering::Acquire) == physical_address
            && matching_slot.replace(index).is_some()
        {
            return false;
        }
    }

    let Some(index) = matching_slot else {
        return false;
    };
    ADDRESS_SPACE_ROOT_FRAMES[index]
        .compare_exchange(physical_address, 0, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

/// Returns whether this frame is a live kernel-created address-space root.
fn is_address_space_root_frame(physical_address: u64) -> bool {
    physical_address != 0
        && ADDRESS_SPACE_ROOT_FRAMES
            .iter()
            .any(|slot| slot.load(Ordering::Acquire) == physical_address)
}

/// Returns true only when exactly one registry slot names this root frame.
///
/// Activation must reject duplicate entries even though ordinary ownership
/// checks treat any matching entry as a root, so a duplicated root is never
/// accidentally treated as reclaimable data.
pub fn is_uniquely_registered_address_space_root(physical_address: u64) -> bool {
    if physical_address == 0 || physical_address & (PAGE_SIZE - 1) != 0 {
        return false;
    }

    let mut found = false;
    for slot in ADDRESS_SPACE_ROOT_FRAMES.iter() {
        let matches = slot.load(Ordering::Acquire) == physical_address;
        if matches && found {
            return false;
        }
        found |= matches;
    }
    found
}

fn reserve_table_frame_slot() -> Option<usize> {
    // SAFETY: this mutation is only used in the single-core, interrupts-disabled
    // bootstrap mapping path, before SMP is introduced.
    TABLE_FRAMES.lock().reserve_slot()
}

fn clear_reserved_table_frame_slot(index: usize) {
    // SAFETY: registry mutations are serialized by the single-core,
    // interrupts-disabled bootstrap precondition.
    if TABLE_FRAMES.lock().cancel_reservation(index).is_err() {
        panic!("page-table frame registry reservation invariant violated");
    }
}

fn install_table_frame(index: usize, frame: Frame) {
    // SAFETY: registry mutations are serialized by the single-core,
    // interrupts-disabled bootstrap precondition.
    if let Err((_error, _frame)) = TABLE_FRAMES.lock().install_reserved(index, frame) {
        panic!("page-table frame registry reservation invariant violated");
    }
}

fn registered_table_frame(physical_address: u64) -> bool {
    // SAFETY: the registry is read only under the same single-core bootstrap
    // contract as its mutations.
    TABLE_FRAMES.lock().contains(physical_address)
}

/// Returns whether a physical frame is registered as an already-published page table.
///
/// Active-root walkers may encounter these frames after a large-page demotion,
/// even though the firmware memory map still classifies the backing pages as Usable.
pub fn registered_published_page_table_frame(physical_address: u64) -> bool {
    TABLE_FRAMES
        .lock()
        .contains_published_unowned(physical_address)
}

fn unpublished_table_frame(physical_address: u64) -> bool {
    // SAFETY: the registry is read only under the same single-core bootstrap
    // contract as its mutations.
    TABLE_FRAMES.lock().contains_unpublished(physical_address)
}

fn mark_table_frame_published(physical_address: u64) {
    // SAFETY: registry mutations are serialized by the single-core,
    // interrupts-disabled bootstrap precondition. Bootloader-owned frames are
    // not in this registry, so their expected lookup miss is intentionally ignored.
    let _ = TABLE_FRAMES.lock().mark_published(physical_address);
}

fn mark_table_frame_published_for_root(root_physical: u64, physical_address: u64, table_level: u8) {
    // SAFETY: registry mutations are serialized by the single-core,
    // interrupts-disabled bootstrap precondition. The caller has just published
    // this table at the indicated level in the root's private lower-half tree.
    match unsafe {
        TABLE_FRAMES
            .lock()
            .mark_published_for_root(root_physical, physical_address, table_level)
    } {
        Ok(()) => {}
        Err(FrameRegistryError::FrameNotFound) => {
            panic!("private lower-half page table is missing from the frame registry")
        }
        Err(
            FrameRegistryError::InvalidOwnerRoot
            | FrameRegistryError::PublishedOwnerMismatch
            | FrameRegistryError::NotPublished
            | FrameRegistryError::NotDetached
            | FrameRegistryError::InvalidReservation
            | FrameRegistryError::DuplicateFrameAddress
            | FrameRegistryError::PublishedFrame,
        ) => panic!("private page-table root ownership invariant violated"),
    }
}

fn release_registered_table_frame(physical_address: u64) {
    // SAFETY: registry mutations are serialized by the single-core,
    // interrupts-disabled bootstrap precondition.
    let frame = match TABLE_FRAMES.lock().take_unpublished(physical_address) {
        Ok(frame) => frame,
        Err(FrameRegistryError::PublishedFrame) => {
            panic!("attempted to release a published page-table frame")
        }
        Err(FrameRegistryError::FrameNotFound) => {
            panic!("attempted to release an unregistered page-table frame")
        }
        Err(
            FrameRegistryError::InvalidReservation
            | FrameRegistryError::DuplicateFrameAddress
            | FrameRegistryError::InvalidOwnerRoot
            | FrameRegistryError::PublishedOwnerMismatch
            | FrameRegistryError::NotPublished
            | FrameRegistryError::NotDetached,
        ) => {
            panic!("page-table frame registry state is invalid")
        }
    };
    if let Err((_error, _frame)) = crate::memory::free_frame(frame) {
        panic!("physical allocator rejected an owned page-table frame");
    }
}

struct KernelPageTableEditor<'a> {
    regions: &'a [MemoryRegion],
    physical_memory_offset: u64,
    root_table_physical: u64,
    recursive_index: u16,
    target_virtual_address: u64,
    physical_address_bits: u8,
    #[cfg(feature = "test-wx-runtime-audit")]
    wx_test_executable_frame: Option<u64>,
}

impl<'a> KernelPageTableEditor<'a> {
    fn new(boot_info: &'a BootInfo, target_virtual_address: u64) -> Result<Self, PagingError> {
        let recursive_index = match boot_info.recursive_index {
            Optional::Some(index) if is_safe_recursive_mapping_index(index) => index,
            Optional::Some(_) => return Err(PagingError::InvalidRecursiveIndex),
            Optional::None => return Err(PagingError::RecursiveMappingUnavailable),
        };
        Self::new_with_recursive_index(boot_info, target_virtual_address, recursive_index)
    }

    /// Constructs an editor for the currently active root and its known recursive slot.
    ///
    /// This is used when a newly activated root uses a private recursive index
    /// rather than the original bootloader index. The supplied index is checked
    /// against the root's self-reference before any subsequent page-table walk.
    fn new_with_recursive_index(
        boot_info: &'a BootInfo,
        target_virtual_address: u64,
        recursive_index: u16,
    ) -> Result<Self, PagingError> {
        Self::new_with_recursive_index_mode(
            boot_info,
            target_virtual_address,
            recursive_index,
            true,
        )
    }

    /// Constructs an editor handle for a read-only audit without requiring R/W
    /// permission on the recursive mapping. The mutation constructor above keeps
    /// the stricter writable-alias invariant.
    fn new_for_readonly_audit(
        boot_info: &'a BootInfo,
        target_virtual_address: u64,
        recursive_index: u16,
    ) -> Result<Self, PagingError> {
        Self::new_with_recursive_index_mode(
            boot_info,
            target_virtual_address,
            recursive_index,
            false,
        )
    }

    fn new_with_recursive_index_mode(
        boot_info: &'a BootInfo,
        target_virtual_address: u64,
        recursive_index: u16,
        require_writable_recursive_mapping: bool,
    ) -> Result<Self, PagingError> {
        let flags: u64;
        // SAFETY: PUSHFQ reads the current flags register; no flags are changed.
        unsafe {
            asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
        }
        if flags & (1 << 9) != 0 {
            return Err(PagingError::InterruptsEnabled);
        }
        if !is_canonical_4level(target_virtual_address)
            || target_virtual_address & (PAGE_SIZE - 1) != 0
        {
            return Err(PagingError::MappingSmokeMismatch);
        }
        if !is_safe_recursive_mapping_index(recursive_index) {
            return Err(PagingError::InvalidRecursiveIndex);
        }
        let physical_memory_offset = match boot_info.physical_memory_offset {
            Optional::Some(offset) => offset,
            Optional::None => return Err(PagingError::PhysicalMemoryOffsetUnavailable),
        };
        let root_table_physical = active_root_table_physical();

        // The original boot root is bootloader-owned; a later kernel root is
        // allocator-owned and remains allocated while CR3 references it.
        let root_is_bootloader_owned =
            is_bootloader_owned_page(&boot_info.memory_regions, root_table_physical);
        let root_is_allocator_owned =
            crate::memory::is_frame_allocated(root_table_physical).unwrap_or(false);
        // SAFETY: active_root_table_physical reads CR3. The page is not dereferenced
        // until its alignment, full-frame ownership, and recursive self-reference
        // have been checked below.
        if root_table_physical == 0
            || root_table_physical & (PAGE_SIZE - 1) != 0
            || (!root_is_bootloader_owned && !root_is_allocator_owned)
        {
            return Err(PagingError::InvalidRootTable);
        }

        // SAFETY: the maximum extended leaf and NX support were checked during
        // initialize_paging_controls; read the width from the same CPU.
        let physical_address_bits = (__cpuid(CPUID_PHYSICAL_ADDRESS_WIDTH).eax & 0xff) as u8;
        if !valid_physical_page(root_table_physical, physical_address_bits) {
            return Err(PagingError::InvalidRootTable);
        }
        let recursive_mapping_valid = if require_writable_recursive_mapping {
            // Mapping mutations require a writable recursive alias. Keep this
            // invariant unchanged for every existing editor call site.
            validate_editor_recursive_mapping_entry(
                recursive_index,
                root_table_physical,
                root_is_allocator_owned,
            )
        } else {
            // Auditing only reads page-table entries. Require a valid supervisor
            // self-reference and NX, but do not confuse R/W=0 with unreadability.
            validate_readonly_recursive_mapping_entry(recursive_index, root_table_physical)
        };
        if !recursive_mapping_valid {
            return Err(PagingError::InvalidRecursiveMapping);
        }

        let cr0: u64;
        unsafe {
            asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        }
        if cr0 & CR0_WP == 0 {
            return Err(PagingError::SupervisorWriteProtectionDisabled);
        }
        let mut efer_low: u32;
        let mut efer_high: u32;
        unsafe {
            asm!(
                "rdmsr",
                in("ecx") EFER_MSR,
                out("eax") efer_low,
                out("edx") efer_high,
                options(nomem, nostack, preserves_flags)
            );
        }
        if ((u64::from(efer_high) << 32) | u64::from(efer_low)) & EFER_NXE == 0 {
            return Err(PagingError::UnsupportedNx);
        }

        Ok(Self {
            regions: &boot_info.memory_regions,
            physical_memory_offset,
            root_table_physical,
            recursive_index,
            target_virtual_address,
            physical_address_bits,
            #[cfg(feature = "test-wx-runtime-audit")]
            wx_test_executable_frame: None,
        })
    }

    fn is_usable_frame(&self, physical_address: u64) -> bool {
        physical_page_is_in_allowed_region(physical_address, self.regions.len(), |index| {
            let region = self.regions[index];
            (
                region.start,
                region.end,
                matches!(region.kind, MemoryRegionKind::Usable),
            )
        })
    }

    fn is_table_frame(&self, physical_address: u64) -> bool {
        is_bootloader_owned_page(self.regions, physical_address)
            || registered_table_frame(physical_address)
            || (physical_address == self.root_table_physical
                && crate::memory::is_frame_allocated(physical_address).unwrap_or(false))
    }

    fn offset_alias(&mut self, physical_address: u64) -> Option<*mut u8> {
        if !valid_physical_page(physical_address, self.physical_address_bits)
            || !self.is_usable_frame(physical_address)
        {
            return None;
        }
        let address = self.physical_memory_offset.checked_add(physical_address)?;
        let last_byte = address.checked_add(PAGE_SIZE - 1)?;
        if address & (PAGE_SIZE - 1) != 0
            || !is_canonical_4level(address)
            || !is_canonical_4level(last_byte)
        {
            return None;
        }
        // Prove that the physical-memory offset actually maps this complete
        // Usable frame to the expected physical page and permits supervisor
        // writes before zeroing an unpublished page-table frame.
        let translation = translate_with_editor(self, self.root_table_physical, address).ok()?;
        if translation.physical_address != physical_address
            || !translation.writable
            || translation.user_accessible
            || translation.executable
        {
            return None;
        }
        let pointer = usize::try_from(address).ok()? as *mut u8;
        Some(pointer)
    }

    fn reachable_table_physical(&self, wanted_level: u8) -> Option<u64> {
        if !(1..=4).contains(&wanted_level)
            || !valid_physical_page(self.root_table_physical, self.physical_address_bits)
            || !self.is_table_frame(self.root_table_physical)
        {
            return None;
        }

        // Check the recursive self-reference first. Its R/W bit is part of the
        // effective write permission for every recursive alias.
        let root_alias = recursive_table_page_virtual_address(
            self.recursive_index,
            self.target_virtual_address,
            4,
        )?;
        let recursive_entry_pointer =
            entry_pointer_from_page(root_alias, usize::from(self.recursive_index))?;
        // SAFETY: the bootloader contract supplied this recursive index, and
        // the root frame was validated as Bootloader-owned above.
        let recursive_entry = unsafe { ptr::read_volatile(recursive_entry_pointer) };
        if !recursive_entry_matches_root(recursive_entry, self.root_table_physical)
            || recursive_entry & WRITABLE == 0
        {
            return None;
        }

        let mut current_physical = self.root_table_physical;
        let mut visited = [0u64; 4];
        visited[0] = current_physical;
        for current_level in (wanted_level + 1..=4).rev() {
            let table_alias = recursive_table_page_virtual_address(
                self.recursive_index,
                self.target_virtual_address,
                current_level,
            )?;
            let index = virtual_index(self.target_virtual_address, current_level)?;
            let pointer = entry_pointer_from_page(table_alias, index)?;
            // SAFETY: every ancestor entry is read through the validated recursive
            // alias. Recursive and target-path write permissions are checked below.
            let entry = unsafe { ptr::read_volatile(pointer) };
            if entry & PRESENT == 0 || entry & WRITABLE == 0 || entry & LARGE_PAGE != 0 {
                return None;
            }
            let next_physical = entry & PHYSICAL_ADDRESS_MASK;
            if !valid_physical_page(next_physical, self.physical_address_bits)
                || !self.is_table_frame(next_physical)
                || visited[..(5 - current_level) as usize].contains(&next_physical)
            {
                return None;
            }
            visited[(4 - current_level) as usize + 1] = next_physical;
            current_physical = next_physical;
        }
        Some(current_physical)
    }

    /// Read-only variant of reachable_table_physical for the alias audit.
    ///
    /// It checks the same canonical path, present bits, frame addresses, table
    /// ownership, and cycle constraints but deliberately does not require R/W.
    /// x86 permits supervisor reads through read-only paging entries.
    fn reachable_table_physical_readonly(&self, wanted_level: u8) -> Option<u64> {
        if !(1..=4).contains(&wanted_level)
            || !valid_physical_page(self.root_table_physical, self.physical_address_bits)
            || !self.is_table_frame(self.root_table_physical)
        {
            return None;
        }

        let recursive_entry = read_recursive_mapping_entry(self.recursive_index)?;
        if !recursive_entry_matches_root(recursive_entry, self.root_table_physical)
            || recursive_entry & USER_ACCESSIBLE != 0
            || recursive_entry & NO_EXECUTE == 0
            || recursive_entry & PROTECTION_KEY_FIELD_MASK != 0
        {
            return None;
        }

        let mut current_physical = self.root_table_physical;
        let mut visited = [0u64; 4];
        visited[0] = current_physical;
        for current_level in (wanted_level + 1..=4).rev() {
            let table_alias = recursive_table_page_virtual_address(
                self.recursive_index,
                self.target_virtual_address,
                current_level,
            )?;
            let index = virtual_index(self.target_virtual_address, current_level)?;
            let pointer = entry_pointer_from_page(table_alias, index)?;
            // SAFETY: the recursive alias index and root frame were validated;
            // the target path is read only and each table page is checked below.
            let entry = unsafe { ptr::read_volatile(pointer) };
            if entry & PRESENT == 0
                || entry & LARGE_PAGE != 0
                || entry & PROTECTION_KEY_FIELD_MASK != 0
            {
                return None;
            }
            let next_physical = entry & PHYSICAL_ADDRESS_MASK;
            if !valid_physical_page(next_physical, self.physical_address_bits)
                || !self.is_table_frame(next_physical)
                || visited[..(5 - current_level) as usize].contains(&next_physical)
            {
                return None;
            }
            visited[(4 - current_level) as usize + 1] = next_physical;
            current_physical = next_physical;
        }
        Some(current_physical)
    }

    /// Performs a strong atomic update of one validated page-table entry.
    ///
    /// This RMW allows the caller to observe hardware Accessed/Dirty changes
    /// instead of racing them with a read-then-write sequence. It does not
    /// invalidate translations or make a multi-entry page-table transaction
    /// safe by itself. Callers must retain the editor's single-CPU,
    /// interrupts-disabled, PCID-disabled mutation preconditions.
    fn compare_exchange_entry(
        &mut self,
        table_physical: u64,
        index: usize,
        level: u8,
        expected: u64,
        replacement: u64,
    ) -> Option<Result<(), u64>> {
        let (pointer, reachable) = self.entry_pointer(table_physical, index, level)?;
        // SAFETY: entry_pointer validates a naturally aligned pointer to one
        // page-table entry. AtomicU64::compare_exchange compiles to an x86_64
        // locked compare-exchange, so hardware-updated A/D bits cause a failed
        // comparison instead of being silently overwritten by this RMW.
        let result = {
            let atomic_entry = unsafe { AtomicU64::from_ptr(pointer) };
            atomic_entry
                .compare_exchange(expected, replacement, Ordering::AcqRel, Ordering::Acquire)
                .map(|_| ())
        };
        if result.is_ok() && reachable {
            self.mark_reachable_table_frames();
        }
        Some(result)
    }

    /// Smoke-checks the atomic entry primitive without changing the entry.
    ///
    /// The retry policy is shared with host-testable logic. This verifies the
    /// concrete editor's CAS path, but does not prove large-page break-before-make
    /// ordering or TLB/page-walk quiescence.
    fn verify_atomic_entry_compare_exchange(
        &mut self,
        table_physical: u64,
        index: usize,
        level: u8,
    ) -> bool {
        let Some(initial) = self.read_entry(table_physical, index, level) else {
            return false;
        };
        compare_exchange_entry_with_ad_retry(
            initial,
            ATOMIC_ENTRY_CAS_MAX_ATTEMPTS,
            |expected| expected,
            |expected, replacement| {
                self.compare_exchange_entry(table_physical, index, level, expected, replacement)
                    .unwrap_or(Err(expected))
            },
        )
        .is_ok()
    }

    fn entry_pointer(
        &mut self,
        table_physical: u64,
        index: usize,
        level: u8,
    ) -> Option<(*mut u64, bool)> {
        if index >= 512
            || !(1..=4).contains(&level)
            || !valid_physical_page(table_physical, self.physical_address_bits)
        {
            return None;
        }
        if self.reachable_table_physical(level) == Some(table_physical) {
            let table_alias = recursive_table_page_virtual_address(
                self.recursive_index,
                self.target_virtual_address,
                level,
            )?;
            return Some((entry_pointer_from_page(table_alias, index)?, true));
        }

        // The offset path is permitted only for a newly allocated, unpublished
        // table frame retained by this editor's ownership registry.
        if !unpublished_table_frame(table_physical) {
            return None;
        }
        let page = self.offset_alias(table_physical)?;
        let address = (page as usize).checked_add(index.checked_mul(size_of::<u64>())?)?;
        let pointer = address as *mut u64;
        if pointer as usize & (size_of::<u64>() - 1) != 0 {
            return None;
        }
        Some((pointer, false))
    }

    /// Returns a pointer to the first entry in one verified reachable table.
    ///
    /// The W^X audit reads all 512 entries through this pointer. Validating the
    /// recursive path once per table avoids re-walking every ancestor for every
    /// entry, while the caller remains read-only and checks the index bound.
    fn audit_table_pointer(&self, table_physical: u64, level: u8) -> Option<*const u64> {
        if !(1..=4).contains(&level)
            || !valid_physical_page(table_physical, self.physical_address_bits)
            || self.reachable_table_physical_readonly(level) != Some(table_physical)
        {
            return None;
        }
        let table_alias = recursive_table_page_virtual_address(
            self.recursive_index,
            self.target_virtual_address,
            level,
        )?;
        Some(entry_pointer_from_page(table_alias, 0)?.cast_const())
    }

    /// Returns a validated read-only pointer to a table owned by the audit root.
    ///
    /// Active-root tables are reached only through the recursive alias. Inactive
    /// roots are accessed through the physical-memory offset only when the root
    /// is registered and allocated, or a private lower-half table has a matching
    /// root-and-level ownership record.
    fn audit_table_pointer_for_root(
        &mut self,
        audit_root_physical: u64,
        table_physical: u64,
        level: u8,
        virtual_prefix: u64,
    ) -> Option<*const u64> {
        if audit_root_physical == self.root_table_physical {
            return self.audit_table_pointer(table_physical, level);
        }
        if !(1..=4).contains(&level)
            || !valid_physical_page(table_physical, self.physical_address_bits)
        {
            return None;
        }

        if level == 4 {
            if table_physical != audit_root_physical
                || !is_address_space_root_frame(audit_root_physical)
                || !matches!(
                    crate::memory::is_frame_allocated(audit_root_physical),
                    Ok(true)
                )
            {
                return None;
            }
        } else if virtual_prefix >= 0x0000_8000_0000_0000
            || TABLE_FRAMES
                .lock()
                .published_table_level_for_root(audit_root_physical, table_physical)
                != Some(level)
        {
            // This walker deliberately audits only the inactive root's private
            // lower half. Shared kernel-half tables are read through the active
            // recursive mapping after their PML4 entries were compared.
            return None;
        }

        let alias = self.offset_alias(table_physical)?;
        if alias as usize & (size_of::<u64>() - 1) != 0 {
            return None;
        }
        Some(alias.cast::<u64>().cast_const())
    }

    fn mark_reachable_table_frames(&self) {
        // The root publication makes each staged table reachable. Record all
        // allocator-owned frames on this virtual path, not just the first child.
        // The lower canonical half is private to this address-space root, so its
        // table frames must carry root ownership before inactive-root teardown
        // can safely distinguish them from shared kernel-half tables.
        for level in 1..=3 {
            if let Some(physical_address) = self.reachable_table_physical(level) {
                if self.target_virtual_address < USER_VIRTUAL_ADDRESS_LIMIT {
                    mark_table_frame_published_for_root(
                        self.root_table_physical,
                        physical_address,
                        level,
                    );
                } else {
                    mark_table_frame_published(physical_address);
                }
            }
        }
    }
}

#[cfg(feature = "test-wx-runtime-audit")]
impl KernelPageTableEditor<'_> {
    /// Temporarily allow one test-owned frame to receive an RX alias after its
    /// physical-offset alias has been proven RO+NX. Ordinary executable mappings
    /// remain denied by the PageTableEditor implementation.
    fn allow_controlled_wx_test_executable_frame(
        &mut self,
        physical_page: u64,
    ) -> Result<(), PagingError> {
        if physical_page == 0
            || physical_page & (PAGE_SIZE - 1) != 0
            || !self.is_usable_frame(physical_page)
            || !PageTableEditor::is_frame_allocated(self, physical_page)
            || PageTableEditor::is_page_table_or_reserved_frame(self, physical_page)
            || is_address_space_root_frame(physical_page)
        {
            return Err(PagingError::WxSiblingFrameUnavailable);
        }

        let direct_alias = self
            .physical_memory_offset
            .checked_add(physical_page)
            .filter(|address| is_canonical_4level(*address) && (*address & (PAGE_SIZE - 1)) == 0)
            .ok_or(PagingError::PhysicalMemoryOffsetUnavailable)?;
        let root_table_physical = self.root_table_physical;
        let direct_mapping = translate_with_editor(self, root_table_physical, direct_alias)
            .map_err(PagingError::Translation)?;
        if direct_mapping.physical_address != physical_page
            || direct_mapping.page_size != PAGE_SIZE
            || direct_mapping.writable
            || direct_mapping.user_accessible
            || direct_mapping.executable
        {
            return Err(PagingError::LargePageDemotionFailed);
        }

        self.wx_test_executable_frame = Some(physical_page);
        Ok(())
    }
}

impl PageTableEditor for KernelPageTableEditor<'_> {
    fn physical_address_bits(&self) -> u8 {
        self.physical_address_bits
    }

    fn is_page_table_or_reserved_frame(&self, physical_address: u64) -> bool {
        // Only ordinary allocator-owned frames may be mapped as data. Permanent
        // bootstrap reservations are marked allocated in the allocator bitmap,
        // but intentionally have no releasable Frame token; reject them separately.
        // If the reservation side metadata cannot be queried, fail closed.
        !self.is_usable_frame(physical_address)
            || self.is_table_frame(physical_address)
            || is_address_space_root_frame(physical_address)
            || crate::memory::is_permanently_reserved(physical_address).unwrap_or(true)
    }

    fn is_frame_allocated(&self, physical_address: u64) -> bool {
        // map_supervisor_4k runs with maskable interrupts disabled under the current
        // single-CPU contract. If the allocator cannot be queried (for example,
        // because it is unavailable or busy), reject the mapping.
        crate::memory::is_frame_allocated(physical_address).unwrap_or(false)
    }

    fn executable_mapping_allowed(&self, _physical_address: u64) -> bool {
        // Normal executable mappings remain fail-closed while arbitrary writable
        // aliases are not fully tracked and controlled.
        #[cfg(feature = "test-wx-runtime-audit")]
        if self.wx_test_executable_frame == Some(_physical_address) {
            // This single test-owned frame is admitted only after the test helper
            // has revalidated its physical-offset alias as RO+NX and 4 KiB.
            return true;
        }
        false
    }

    fn reserve_wx_alias(
        &mut self,
        root: u64,
        virtual_address: u64,
        physical_address: u64,
        permissions: PagePermissions,
    ) -> Result<(), PageTableMutationError> {
        if root != self.root_table_physical || root != active_root_table_physical() {
            return Err(PageTableMutationError::WxAliasRegistryFailure);
        }
        reserve_kernel_wx_alias(
            root,
            virtual_address,
            physical_address,
            permissions,
            self.physical_address_bits,
        )
    }

    fn commit_wx_alias(&mut self, root: u64, virtual_address: u64) {
        if root != self.root_table_physical || root != active_root_table_physical() {
            panic!("active W^X alias committed against an unexpected root");
        }
        commit_kernel_wx_alias(root, virtual_address, self.physical_address_bits);
    }

    fn begin_wx_alias_removal(
        &mut self,
        root: u64,
        virtual_address: u64,
        physical_address: u64,
        permissions: PagePermissions,
    ) -> Result<(), PageTableMutationError> {
        if root != self.root_table_physical || root != active_root_table_physical() {
            return Err(PageTableMutationError::WxAliasRegistryFailure);
        }
        begin_kernel_wx_alias_removal(
            root,
            virtual_address,
            physical_address,
            permissions,
            self.physical_address_bits,
        )
    }

    fn complete_wx_alias_removal(&mut self, root: u64, virtual_address: u64) {
        if root != self.root_table_physical || root != active_root_table_physical() {
            panic!("active W^X alias removal used against an unexpected root");
        }
        // The PTE has already been cleared; invalidate before releasing the alias.
        invalidate_local_tlb(virtual_address);
        complete_kernel_wx_alias_removal(root, virtual_address, self.physical_address_bits);
    }

    fn read_entry(&mut self, table_physical: u64, index: usize, level: u8) -> Option<u64> {
        let (pointer, _reachable) = self.entry_pointer(table_physical, index, level)?;
        // SAFETY: entry_pointer validated the alias and alignment. Reachable
        // tables have writable ancestors; unlinked tables are owned Usable frames
        // accessed through the checked physical-memory offset.
        Some(unsafe { ptr::read_volatile(pointer) })
    }

    fn write_entry(&mut self, table_physical: u64, index: usize, level: u8, value: u64) {
        let Some((pointer, reachable)) = self.entry_pointer(table_physical, index, level) else {
            crate::interrupts::write_hex(b"PAGE-TABLE WRITE PREFLIGHT TABLE: ", table_physical);
            crate::interrupts::write_hex(b"PAGE-TABLE WRITE PREFLIGHT INDEX: ", index as u64);
            crate::interrupts::write_hex(b"PAGE-TABLE WRITE PREFLIGHT LEVEL: ", level as u64);
            crate::interrupts::write_hex(
                b"PAGE-TABLE WRITE PREFLIGHT TARGET VA: ",
                self.target_virtual_address,
            );
            crate::interrupts::write_hex(
                b"PAGE-TABLE WRITE PREFLIGHT UNPUBLISHED: ",
                u64::from(unpublished_table_frame(table_physical)),
            );
            crate::interrupts::write_hex(
                b"PAGE-TABLE WRITE PREFLIGHT USABLE: ",
                u64::from(self.is_usable_frame(table_physical)),
            );
            crate::interrupts::write_hex(
                b"PAGE-TABLE WRITE PREFLIGHT REACHABLE MATCH: ",
                u64::from(self.reachable_table_physical(level) == Some(table_physical)),
            );
            panic!("page-table write destination failed preflight");
        };
        // SAFETY: every existing destination is validated as writable during the
        // walk; newly allocated frames were validated and zeroed before allocation
        // returned. A fault here violates the editor contract and fail-stops.
        unsafe { ptr::write_volatile(pointer, value) };
        if reachable {
            self.mark_reachable_table_frames();
        }
    }

    fn allocate_table(&mut self) -> Option<u64> {
        // Reserve ownership metadata before taking a physical frame, so registry
        // exhaustion cannot consume or leak an allocator frame.
        let slot = reserve_table_frame_slot()?;
        let frame = match crate::memory::allocate_frame() {
            Ok(frame) => frame,
            Err(_) => {
                clear_reserved_table_frame_slot(slot);
                return None;
            }
        };
        let physical_address = frame.physical_address();
        if !valid_physical_page(physical_address, self.physical_address_bits)
            || !self.is_usable_frame(physical_address)
        {
            clear_reserved_table_frame_slot(slot);
            if let Err((_error, _frame)) = crate::memory::free_frame(frame) {
                panic!("physical allocator rejected an invalid table frame");
            }
            return None;
        }
        let Some(alias) = self.offset_alias(physical_address) else {
            clear_reserved_table_frame_slot(slot);
            if let Err((_error, _frame)) = crate::memory::free_frame(frame) {
                panic!("physical allocator rejected an inaccessible table frame");
            }
            return None;
        };

        install_table_frame(slot, frame);
        // SAFETY: the full frame lies within one Usable region and its canonical,
        // aligned physical-memory-offset alias was checked. Clearing it before
        // publication gives the hardware an initialized page table.
        #[cfg(feature = "test-vm-transitions")]
        crate::interrupts::write_hex(b"ONE OS VM TABLE FRAME ALLOCATED: ", physical_address);
        unsafe { ptr::write_bytes(alias, 0, PAGE_SIZE as usize) };
        #[cfg(feature = "test-vm-transitions")]
        {
            let entries = alias.cast::<u64>();
            for index in 0..((PAGE_SIZE as usize) / size_of::<u64>()) {
                // SAFETY: alias was validated to map this aligned, owned, unpublished
                // frame as supervisor-writable. The frame has not yet been published
                // through any parent entry, and the volatile read verifies each slot
                // after zeroing via the same checked physical-memory-offset alias.
                if unsafe { ptr::read_volatile(entries.add(index)) } != 0 {
                    crate::serial_write(
                        b"ONE OS VM TEST FAILED: table frame not zero before publication\n",
                    );
                    release_registered_table_frame(physical_address);
                    return None;
                }
            }
            // Include the physical frame address so the QEMU validator can
            // pair every successful 512-entry verification with one allocation.
            // This is emitted before map_supervisor_4k can publish the parent entry.
            crate::interrupts::write_hex(
                b"ONE OS VM TABLE PREPUBLICATION ZERO VERIFIED: ",
                physical_address,
            );
        }
        Some(physical_address)
    }

    fn free_table(&mut self, physical_address: u64) {
        release_registered_table_frame(physical_address);
    }
}

/// Page-table editor bound to one initialized, inactive address-space root.
///
/// Unlike `KernelPageTableEditor`, this editor accesses only
/// the supplied root and table frames that the ownership registry records as
/// private to that root (plus table frames staged by the current mapping call).
/// Every table access still passes through the active root's checked
/// physical-memory-offset alias.
///
/// The root must never be active while this editor is alive. A root that was
/// previously active is eligible only after `switch_address_space`
/// has switched away with PCID rejected and the required local/global TLB flush
/// completed. New roots have no cached translations. Consequently, the
/// root-aware invalidation hook below can prove that no target-root translation
/// remains rather than issuing an `INVLPG` against the wrong CR3.
struct KernelInactiveAddressSpaceEditor<'a> {
    boot_info: &'a BootInfo,
    regions: &'a [MemoryRegion],
    physical_memory_offset: u64,
    active_root_physical: u64,
    active_recursive_index: u16,
    target_root_physical: u64,
    physical_address_bits: u8,
    staged_frames: [Option<u64>; 3],
}

impl<'a> KernelInactiveAddressSpaceEditor<'a> {
    fn new(
        boot_info: &'a BootInfo,
        root: &AddressSpaceRoot,
        active_root: &ActiveAddressSpaceRoot,
    ) -> Result<Self, PagingError> {
        let flags: u64;
        // SAFETY: reading RFLAGS does not change interrupt state.
        unsafe {
            asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
        }
        if flags & (1 << 9) != 0 {
            return Err(PagingError::InterruptsEnabled);
        }

        let active_root_physical = active_root.physical_address();
        let target_root_physical = root.physical_address();
        if !root.is_initialized()
            || target_root_physical == active_root_physical
            || active_root_table_physical() != active_root_physical
            || root.physical_address_bits() != active_root.physical_address_bits()
        {
            return Err(PagingError::InactiveAddressSpaceInvalid);
        }

        let active_recursive_index = active_root.recursive_index();
        let target_recursive_index = root
            .recursive_index()
            .ok_or(PagingError::InactiveAddressSpaceInvalid)?;
        if !is_safe_recursive_mapping_index(active_recursive_index)
            || !(LOWER_HALF_PML4_ENTRIES..PML4_ENTRY_COUNT)
                .contains(&(target_recursive_index as usize))
        {
            return Err(PagingError::InvalidRecursiveIndex);
        }

        let cr4: u64;
        // SAFETY: CR4 is readable from the privileged kernel context.
        unsafe {
            asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        }
        if cr4 & CR4_LA57 != 0 {
            return Err(PagingError::UnsupportedFiveLevelPaging);
        }
        if cr4 & (1 << 17) != 0 {
            return Err(PagingError::PcidUnsupported);
        }

        let physical_address_bits = (__cpuid(CPUID_PHYSICAL_ADDRESS_WIDTH).eax & 0xff) as u8;
        if !(32..=52).contains(&physical_address_bits)
            || physical_address_bits != root.physical_address_bits()
            || physical_address_bits != active_root.physical_address_bits()
        {
            return Err(PagingError::InvalidPhysicalAddressWidth {
                bits: physical_address_bits,
            });
        }

        let physical_memory_offset = match boot_info.physical_memory_offset {
            Optional::Some(offset) => offset,
            Optional::None => return Err(PagingError::PhysicalMemoryOffsetUnavailable),
        };

        let editor = Self {
            boot_info,
            regions: &boot_info.memory_regions,
            physical_memory_offset,
            active_root_physical,
            active_recursive_index,
            target_root_physical,
            physical_address_bits,
            staged_frames: [None; 3],
        };

        let root_pointer = editor
            .table_pointer(target_root_physical, 4)
            .ok_or(PagingError::InactivePageTableUnavailable)?;
        // SAFETY: table_pointer validated the full target root frame as an
        // allocator-owned Usable frame and verified its exact writable,
        // supervisor-only, NX physical-memory-offset translation.
        let recursive_entry =
            unsafe { ptr::read_volatile(root_pointer.add(usize::from(target_recursive_index))) };
        if !recursive_entry_is_valid_kernel_root(recursive_entry, target_root_physical) {
            return Err(PagingError::InactiveAddressSpaceInvalid);
        }

        Ok(editor)
    }

    fn is_usable_frame(&self, physical_address: u64) -> bool {
        physical_page_is_in_allowed_region(physical_address, self.regions.len(), |index| {
            let region = self.regions[index];
            (
                region.start,
                region.end,
                matches!(region.kind, MemoryRegionKind::Usable),
            )
        })
    }

    fn is_staged_table(&self, physical_address: u64) -> bool {
        self.staged_frames.contains(&Some(physical_address))
    }

    fn remove_staged_table(&mut self, physical_address: u64) -> bool {
        if let Some(slot) = self
            .staged_frames
            .iter_mut()
            .find(|slot| **slot == Some(physical_address))
        {
            *slot = None;
            true
        } else {
            false
        }
    }

    fn track_staged_table(&mut self, physical_address: u64) -> bool {
        if let Some(slot) = self.staged_frames.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(physical_address);
            true
        } else {
            false
        }
    }

    fn is_private_table(&self, physical_address: u64, table_level: u8) -> bool {
        // SAFETY: registry reads and writes share the single-CPU,
        // interrupts-disabled mutation contract.
        TABLE_FRAMES
            .lock()
            .published_table_level_for_root(self.target_root_physical, physical_address)
            == Some(table_level)
    }

    /// Obtains a validated writable supervisor-only NX alias for one allocated
    /// physical frame. The active root's page tables are used to prove the alias
    /// resolves to the complete expected frame before a pointer is returned.
    fn active_offset_alias(&self, physical_address: u64) -> Option<*mut u8> {
        if !valid_physical_page(physical_address, self.physical_address_bits)
            || !self.is_usable_frame(physical_address)
            || !matches!(
                crate::memory::is_frame_allocated(physical_address),
                Ok(true)
            )
        {
            return None;
        }

        let alias = self.physical_memory_offset.checked_add(physical_address)?;
        if alias & (PAGE_SIZE - 1) != 0 || !is_canonical_4level(alias) {
            return None;
        }

        let mut active_editor = KernelPageTableEditor::new_with_recursive_index(
            self.boot_info,
            alias,
            self.active_recursive_index,
        )
        .ok()?;
        active_editor.offset_alias(physical_address)
    }

    fn table_pointer(&self, table_physical: u64, table_level: u8) -> Option<*mut u64> {
        if !valid_physical_page(table_physical, self.physical_address_bits)
            || !self.is_usable_frame(table_physical)
            || !matches!(crate::memory::is_frame_allocated(table_physical), Ok(true))
        {
            return None;
        }

        let table_is_target_root = table_physical == self.target_root_physical && table_level == 4;
        if !table_is_target_root
            && !self.is_private_table(table_physical, table_level)
            && !self.is_staged_table(table_physical)
        {
            return None;
        }

        let alias = self.active_offset_alias(table_physical)?;
        if alias as usize & (size_of::<u64>() - 1) != 0 {
            return None;
        }
        Some(alias.cast::<u64>())
    }

    fn publish_staged_subtree(&mut self, table_physical: u64, table_level: u8) {
        if !(1..=3).contains(&table_level) || !self.is_staged_table(table_physical) {
            panic!("attempted to publish an untracked private page-table frame");
        }

        // SAFETY: this subtree is being linked only beneath the target
        // root's private lower-half PML4 entry, and each child was allocated by
        // this editor, zeroed before publication, and reached through that tree.
        if unsafe {
            TABLE_FRAMES
                .lock()
                .mark_published_for_root(self.target_root_physical, table_physical, table_level)
                .is_err()
        } {
            panic!("private page-table root ownership invariant violated");
        }
        if !self.remove_staged_table(table_physical) {
            panic!("published page-table frame was not staged by this editor");
        }

        if table_level == 1 {
            return;
        }

        let table = self
            .table_pointer(table_physical, table_level)
            .unwrap_or_else(|| panic!("published private table is not accessible"));
        for index in 0..PML4_ENTRY_COUNT {
            // SAFETY: table_pointer validated this complete table frame.
            let entry = unsafe { ptr::read_volatile(table.add(index)) };
            if entry == 0 {
                continue;
            }
            if entry & PRESENT == 0
                || entry & LARGE_PAGE != 0
                || entry & PROTECTION_KEY_FIELD_MASK != 0
            {
                panic!("staged private page-table subtree is malformed");
            }
            let child = entry & PHYSICAL_ADDRESS_MASK;
            self.publish_staged_subtree(child, table_level - 1);
        }
    }

    fn validate_private_child(
        &self,
        physical_address: u64,
        expected_table_level: u8,
        visited: &[u64; TABLE_FRAME_CAPACITY],
        visited_count: usize,
    ) -> Result<(), PagingError> {
        if physical_address == 0
            || physical_address == self.target_root_physical
            || !valid_physical_page(physical_address, self.physical_address_bits)
            || !self.is_private_table(physical_address, expected_table_level)
        {
            return Err(PagingError::InactivePageTableOwnershipViolation);
        }
        if visited[..visited_count].contains(&physical_address) {
            return Err(PagingError::InactivePageTableMalformed);
        }
        if visited_count >= TABLE_FRAME_CAPACITY {
            return Err(PagingError::PrivatePageTableCapacityExceeded);
        }
        Ok(())
    }
}

impl PageTableEditor for KernelInactiveAddressSpaceEditor<'_> {
    fn physical_address_bits(&self) -> u8 {
        self.physical_address_bits
    }

    fn is_page_table_or_reserved_frame(&self, physical_address: u64) -> bool {
        !self.is_usable_frame(physical_address)
            || registered_table_frame(physical_address)
            || physical_address == self.active_root_physical
            || physical_address == self.target_root_physical
            || is_address_space_root_frame(physical_address)
    }

    fn is_frame_allocated(&self, physical_address: u64) -> bool {
        matches!(
            crate::memory::is_frame_allocated(physical_address),
            Ok(true)
        )
    }

    fn executable_mapping_allowed(&self, _physical_address: u64) -> bool {
        // No alias-wide executable publication is implemented yet.
        false
    }

    fn reserve_wx_alias(
        &mut self,
        root: u64,
        virtual_address: u64,
        physical_address: u64,
        permissions: PagePermissions,
    ) -> Result<(), PageTableMutationError> {
        if root != self.target_root_physical
            || active_root_table_physical() != self.active_root_physical
            || root == self.active_root_physical
        {
            return Err(PageTableMutationError::WxAliasRegistryFailure);
        }
        reserve_kernel_wx_alias(
            root,
            virtual_address,
            physical_address,
            permissions,
            self.physical_address_bits,
        )
    }

    fn commit_wx_alias(&mut self, root: u64, virtual_address: u64) {
        if root != self.target_root_physical
            || active_root_table_physical() != self.active_root_physical
            || root == self.active_root_physical
        {
            panic!("inactive W^X alias committed against an unexpected root");
        }
        commit_kernel_wx_alias(root, virtual_address, self.physical_address_bits);
    }

    fn begin_wx_alias_removal(
        &mut self,
        root: u64,
        virtual_address: u64,
        physical_address: u64,
        permissions: PagePermissions,
    ) -> Result<(), PageTableMutationError> {
        if root != self.target_root_physical
            || active_root_table_physical() != self.active_root_physical
            || root == self.active_root_physical
        {
            return Err(PageTableMutationError::WxAliasRegistryFailure);
        }
        begin_kernel_wx_alias_removal(
            root,
            virtual_address,
            physical_address,
            permissions,
            self.physical_address_bits,
        )
    }

    fn complete_wx_alias_removal(&mut self, root: u64, virtual_address: u64) {
        if root != self.target_root_physical
            || active_root_table_physical() != self.active_root_physical
            || root == self.active_root_physical
        {
            panic!("inactive W^X alias removal used against an unexpected root");
        }
        // The target is inactive. PCID is disabled and address-space switching
        // flushes non-global translations before the inactive root can be reused.
        complete_kernel_wx_alias_removal(root, virtual_address, self.physical_address_bits);
    }

    fn read_entry(&mut self, table_physical: u64, index: usize, level: u8) -> Option<u64> {
        if index >= PML4_ENTRY_COUNT || !(1..=4).contains(&level) {
            return None;
        }
        let table = self.table_pointer(table_physical, level)?;
        // SAFETY: table_pointer validated ownership and the complete checked
        // supervisor-writable alias for this physical table frame.
        Some(unsafe { ptr::read_volatile(table.add(index)) })
    }

    fn write_entry(&mut self, table_physical: u64, index: usize, level: u8, value: u64) {
        if index >= PML4_ENTRY_COUNT || !(1..=4).contains(&level) {
            panic!("invalid inactive page-table write index or level");
        }
        let is_reachable_parent = (table_physical == self.target_root_physical && level == 4)
            || self.is_private_table(table_physical, level);
        let table = self
            .table_pointer(table_physical, level)
            .unwrap_or_else(|| panic!("inactive page-table write destination failed preflight"));
        // SAFETY: all existing paths were validated before mutation; staged
        // table frames are private, allocated, zeroed, and accessed through the
        // checked physical-memory offset.
        unsafe { ptr::write_volatile(table.add(index), value) };

        // map_4k stages missing child tables, fills their entries, and then
        // publishes one top-level parent. Only that final link transitions the
        // staged subtree into root-owned state.
        if is_reachable_parent && level > 1 && value & PRESENT != 0 {
            let child = value & PHYSICAL_ADDRESS_MASK;
            if self.is_staged_table(child) {
                self.publish_staged_subtree(child, level - 1);
            }
        }
    }

    fn allocate_table(&mut self) -> Option<u64> {
        let slot = reserve_table_frame_slot()?;
        let frame = match crate::memory::allocate_frame() {
            Ok(frame) => frame,
            Err(_) => {
                clear_reserved_table_frame_slot(slot);
                return None;
            }
        };
        let physical_address = frame.physical_address();
        if !valid_physical_page(physical_address, self.physical_address_bits)
            || !self.is_usable_frame(physical_address)
        {
            clear_reserved_table_frame_slot(slot);
            if let Err((_error, _frame)) = crate::memory::free_frame(frame) {
                panic!("physical allocator rejected an invalid inactive table frame");
            }
            return None;
        }
        install_table_frame(slot, frame);
        if !self.track_staged_table(physical_address) {
            release_registered_table_frame(physical_address);
            return None;
        }
        let Some(alias) = self.active_offset_alias(physical_address) else {
            self.remove_staged_table(physical_address);
            release_registered_table_frame(physical_address);
            return None;
        };
        // SAFETY: the exact complete frame is allocated, Usable, staged and
        // writable through its validated supervisor-only NX offset alias.
        unsafe { ptr::write_bytes(alias, 0, PAGE_SIZE as usize) };
        Some(physical_address)
    }

    fn free_table(&mut self, physical_address: u64) {
        if !self.remove_staged_table(physical_address) {
            panic!("attempted to roll back a page-table frame not staged by this editor");
        }
        release_registered_table_frame(physical_address);
    }
}

/// Active-root adapter that binds the host-testable large-page transaction
/// to the kernel editor's checked recursive aliases, frame registry, atomic entry
/// update, and validated local all-TLB flush.
struct KernelLargePageDemotionEditor<'editor, 'boot> {
    editor: &'editor mut KernelPageTableEditor<'boot>,
    root_table_physical: u64,
    parent_table_physical: u64,
    parent_index: usize,
    source_level: u8,
    virtual_base: u64,
    allocated_table: Option<u64>,
    publication_reserved: bool,
    parent_pointer_published: bool,
    committed: bool,
}

impl<'editor, 'boot> KernelLargePageDemotionEditor<'editor, 'boot> {
    fn new(
        editor: &'editor mut KernelPageTableEditor<'boot>,
        parent_table_physical: u64,
        parent_index: usize,
        source_level: u8,
        virtual_base: u64,
    ) -> Result<Self, PagingError> {
        let root_table_physical = editor.root_table_physical;
        if root_table_physical != active_root_table_physical()
            || virtual_base < 0xffff_8000_0000_0000
            || !(2..=3).contains(&source_level)
            || parent_index >= PML4_ENTRY_COUNT
            || editor.reachable_table_physical(source_level) != Some(parent_table_physical)
            || virtual_base & ((1u64 << (12 + 9 * (source_level - 1))) - 1) != 0
        {
            return Err(PagingError::LargePageDemotionFailed);
        }
        Ok(Self {
            editor,
            root_table_physical,
            parent_table_physical,
            parent_index,
            source_level,
            virtual_base,
            allocated_table: None,
            publication_reserved: false,
            parent_pointer_published: false,
            committed: false,
        })
    }

    fn expected_range_length(&self) -> u64 {
        1u64 << (12 + 9 * (self.source_level - 1))
    }
}

impl LargePageDemotionEditor for KernelLargePageDemotionEditor<'_, '_> {
    fn physical_address_bits(&self) -> u8 {
        self.editor.physical_address_bits
    }

    fn read_entry(&mut self, table_physical: u64, index: usize, level: u8) -> Option<u64> {
        PageTableEditor::read_entry(self.editor, table_physical, index, level)
    }

    fn write_entry(&mut self, table_physical: u64, index: usize, level: u8, value: u64) {
        let is_final_parent_publication = table_physical == self.parent_table_physical
            && index == self.parent_index
            && level == self.source_level
            && value & PRESENT != 0
            && value & LARGE_PAGE == 0;
        if is_final_parent_publication {
            let child_table_physical = value & PHYSICAL_ADDRESS_MASK;
            if !self.publication_reserved
                || self.parent_pointer_published
                || self.allocated_table != Some(child_table_physical)
                || self.committed
            {
                panic!("large-page demotion parent publication violated its reservation");
            }
            let (pointer, reachable) = self
                .editor
                .entry_pointer(table_physical, index, level)
                .unwrap_or_else(|| panic!("large-page demotion parent became inaccessible"));
            if !reachable {
                panic!("large-page demotion parent was not reachable before publication");
            }
            // SAFETY: the transaction validated this parent entry before clearing
            // Present. It is now non-present, the full range has been flushed, and
            // the staged child table is fully initialized and still unpublished.
            // Bypass the generic write hook so ownership is committed only after
            // the transaction has actually installed this pointer.
            unsafe { ptr::write_volatile(pointer, value) };
            self.parent_pointer_published = true;
            return;
        }

        PageTableEditor::write_entry(self.editor, table_physical, index, level, value);
    }

    fn compare_exchange_entry(
        &mut self,
        table_physical: u64,
        index: usize,
        level: u8,
        expected: u64,
        replacement: u64,
    ) -> Result<(), u64> {
        self.editor
            .compare_exchange_entry(table_physical, index, level, expected, replacement)
            .unwrap_or(Err(expected))
    }

    fn allocate_table(&mut self) -> Option<u64> {
        if self.allocated_table.is_some() || self.committed {
            return None;
        }
        let child_table_physical = PageTableEditor::allocate_table(self.editor)?;
        self.allocated_table = Some(child_table_physical);
        Some(child_table_physical)
    }

    fn reserve_table_publication(
        &mut self,
        root_table_physical: u64,
        child_table_physical: u64,
        child_level: u8,
    ) -> bool {
        if root_table_physical != self.root_table_physical
            || root_table_physical != active_root_table_physical()
            || self.allocated_table != Some(child_table_physical)
            || child_level + 1 != self.source_level
            || self.publication_reserved
            || self.parent_pointer_published
            || self.committed
            || !unpublished_table_frame(child_table_physical)
            || self.editor.reachable_table_physical(self.source_level)
                != Some(self.parent_table_physical)
        {
            return false;
        }
        // allocate_table has already reserved and installed the owned Frame token
        // in TABLE_FRAMES before returning the zeroed frame. This reservation pins
        // that exact unpublished token to this parent/level transaction.
        self.publication_reserved = true;
        true
    }

    fn commit_table_publication(
        &mut self,
        root_table_physical: u64,
        child_table_physical: u64,
        child_level: u8,
    ) {
        if root_table_physical != self.root_table_physical
            || root_table_physical != active_root_table_physical()
            || self.allocated_table != Some(child_table_physical)
            || child_level + 1 != self.source_level
            || !self.publication_reserved
            || !self.parent_pointer_published
            || self.committed
            || !unpublished_table_frame(child_table_physical)
        {
            panic!("large-page demotion ownership commit violated its reservation");
        }

        if TABLE_FRAMES
            .lock()
            .mark_published(child_table_physical)
            .is_err()
        {
            panic!("large-page demotion could not commit page-table frame ownership");
        }
        self.publication_reserved = false;
        self.committed = true;
        // Reconcile all now-reachable tables after the child pointer is published.
        // This includes the new child level and remains idempotent with the explicit
        // registration above.
        self.editor.mark_reachable_table_frames();
    }

    fn release_unpublished_table(&mut self, child_table_physical: u64) {
        if self.allocated_table != Some(child_table_physical)
            || self.committed
            || self.parent_pointer_published
            || !unpublished_table_frame(child_table_physical)
        {
            panic!("large-page demotion attempted to release a foreign or published frame");
        }
        PageTableEditor::free_table(self.editor, child_table_physical);
        self.allocated_table = None;
        self.publication_reserved = false;
    }

    fn invalidate_local_range(&mut self, virtual_start: u64, length: u64) {
        if self.root_table_physical != active_root_table_physical()
            || self.editor.root_table_physical != self.root_table_physical
            || virtual_start != self.virtual_base
            || length != self.expected_range_length()
            || virtual_start & (length - 1) != 0
            || !is_canonical_4level(virtual_start)
            || !is_canonical_4level(virtual_start.saturating_add(length - 1))
        {
            panic!("large-page demotion requested an invalid TLB invalidation range");
        }
        // This validated helper disables PGE, reloads the same active CR3 with
        // PCID rejected, then restores CR4. Failure after Present was cleared is
        // an invariant violation, so fail-stop rather than return with ambiguity.
        if crate::address_space::switch_address_space_flush_local_tlb(self.root_table_physical)
            .is_err()
        {
            panic!("large-page demotion could not flush the complete local TLB range");
        }
    }
}

/// Demotes one large leaf covering `virtual_address`, if its current walk
/// encounters a 1 GiB or 2 MiB mapping. All table access remains rooted in the
/// active editor and is validated before the transaction mutates a parent entry.
fn demote_large_page_for_address(
    boot_info: &BootInfo,
    virtual_address: u64,
) -> Result<Option<LargePageDemotionReceipt>, PagingError> {
    if !is_canonical_4level(virtual_address) || virtual_address & (PAGE_SIZE - 1) != 0 {
        return Err(PagingError::LargePageDemotionFailed);
    }
    let mut editor = KernelPageTableEditor::new(boot_info, virtual_address)?;
    let root_table_physical = editor.root_table_physical;
    if root_table_physical != active_root_table_physical() {
        return Err(PagingError::LargePageDemotionFailed);
    }

    let mut table_physical = root_table_physical;
    for table_level in (1..=4).rev() {
        let index = virtual_index(virtual_address, table_level)
            .ok_or(PagingError::LargePageDemotionFailed)?;
        let entry = PageTableEditor::read_entry(&mut editor, table_physical, index, table_level)
            .ok_or(PagingError::LargePageDemotionFailed)?;
        if entry & PRESENT == 0 || (entry & PROTECTION_KEY_FIELD_MASK != 0 && table_level > 1) {
            return Err(PagingError::LargePageDemotionFailed);
        }
        if table_level == 4 && entry & LARGE_PAGE != 0 {
            return Err(PagingError::LargePageDemotionFailed);
        }
        if (table_level == 2 || table_level == 3) && entry & LARGE_PAGE != 0 {
            let page_size = 1u64 << (12 + 9 * (table_level - 1));
            let virtual_base = virtual_address & !(page_size - 1);
            let mut transaction_editor = KernelLargePageDemotionEditor::new(
                &mut editor,
                table_physical,
                index,
                table_level,
                virtual_base,
            )?;
            let receipt = demote_large_page(
                &mut transaction_editor,
                root_table_physical,
                table_physical,
                table_level,
                index,
                virtual_base,
            )
            .map_err(|_| PagingError::LargePageDemotionFailed)?;
            return Ok(Some(receipt));
        }
        if table_level == 1 {
            return Ok(None);
        }
        if !valid_physical_page(entry & PHYSICAL_ADDRESS_MASK, editor.physical_address_bits) {
            return Err(PagingError::LargePageDemotionFailed);
        }
        table_physical = entry & PHYSICAL_ADDRESS_MASK;
    }
    Err(PagingError::LargePageDemotionFailed)
}

impl UserAddressSpaceEditor for KernelInactiveAddressSpaceEditor<'_> {
    fn invalidate_translation(&mut self, root_table_physical: u64, virtual_address: u64) {
        if root_table_physical != self.target_root_physical
            || active_root_table_physical() != self.active_root_physical
            || self.active_root_physical == self.target_root_physical
            || virtual_address >= USER_VIRTUAL_ADDRESS_LIMIT
            || virtual_address & (PAGE_SIZE - 1) != 0
        {
            panic!("inactive-root TLB invalidation precondition was violated");
        }

        // The target root is provably inactive. A never-activated root has no
        // cached translations; a formerly active root can become AddressSpaceRoot
        // only after switch_address_space completed the CR4.PGE-clear / CR3-write
        // / CR4-restore sequence with PCID disabled. INVLPG under active_root would
        // flush the wrong address space and is intentionally not treated as proof.
    }
}

fn preflight_private_user_tree<const CAPACITY: usize>(
    root_physical: u64,
    registry: &UserPageMappingRegistry<ZeroedFrame, CAPACITY>,
    editor: &mut KernelInactiveAddressSpaceEditor<'_>,
) -> Result<(), PagingError> {
    if registry.root_physical_address() != root_physical {
        return Err(PagingError::InactivePageTableOwnershipViolation);
    }
    if registry.has_reserved_mappings() {
        return Err(PagingError::InactivePageTableMalformed);
    }

    let mut visited = [0u64; TABLE_FRAME_CAPACITY];
    let mut visited_count = 0usize;
    for pml4_index in 0..LOWER_HALF_PML4_ENTRIES {
        let entry = editor
            .read_entry(root_physical, pml4_index, 4)
            .ok_or(PagingError::InactivePageTableUnavailable)?;
        if entry == 0 {
            continue;
        }
        if entry & PRESENT == 0
            || entry & LARGE_PAGE != 0
            || entry & PROTECTION_KEY_FIELD_MASK != 0
            || entry & WRITABLE == 0
            || entry & USER_ACCESSIBLE == 0
        {
            return Err(PagingError::InactivePageTableMalformed);
        }
        let pdpt_physical = entry & PHYSICAL_ADDRESS_MASK;
        editor.validate_private_child(pdpt_physical, 3, &visited, visited_count)?;
        visited[visited_count] = pdpt_physical;
        visited_count += 1;
        preflight_private_pdpt(
            root_physical,
            pdpt_physical,
            (pml4_index as u64) << 39,
            registry,
            editor,
            &mut visited,
            &mut visited_count,
        )?;
    }

    // Walk ownership metadata in the opposite direction too: every published
    // non-detached table owned by this root must be reachable from the root.
    // Detached tokens are the explicit exception: a previous allocator-release
    // failure leaves those frames in the root-scoped retry list.
    let mut owned_table_ordinal = 0usize;
    loop {
        let owned_table = TABLE_FRAMES
            .lock()
            .root_owned_table_at(root_physical, owned_table_ordinal);
        let Some((table_physical, table_level, published, detached)) = owned_table else {
            break;
        };
        owned_table_ordinal += 1;

        if !published || table_level.is_none() {
            return Err(PagingError::InactivePageTableOwnershipViolation);
        }
        if !detached && !visited[..visited_count].contains(&table_physical) {
            return Err(PagingError::InactivePageTableOwnershipViolation);
        }
    }

    // Walk the mapping registry in the opposite direction as well: every token
    // retained for a mapped VA must still have a present PTE that resolves to
    // its exact physical frame. This catches deleted/missing PTEs that a tree-only
    // walk cannot see.
    for slot_index in 0..CAPACITY {
        let Some((virtual_address, expected_physical)) = registry.mapped_entry_at(slot_index)
        else {
            continue;
        };
        if virtual_address == 0
            || virtual_address >= USER_VIRTUAL_ADDRESS_LIMIT
            || virtual_address & (PAGE_SIZE - 1) != 0
        {
            return Err(PagingError::InactivePageTableMalformed);
        }

        let mut level = 4u8;
        let translation =
            translate_4level(virtual_address, root_physical, |table_physical, index| {
                let current_level = level;
                level = level.saturating_sub(1);
                editor.read_entry(table_physical, index, current_level)
            })
            .map_err(|_| PagingError::InactivePageTableMalformed)?;
        if translation.page_size != PAGE_SIZE || translation.physical_address != expected_physical {
            return Err(PagingError::InactivePageTableOwnershipViolation);
        }
        if !translation.writable || !translation.user_accessible || translation.executable {
            return Err(PagingError::InactivePageTableMalformed);
        }
    }

    Ok(())
}

fn preflight_private_pdpt<const CAPACITY: usize>(
    root_physical: u64,
    pdpt_physical: u64,
    virtual_prefix: u64,
    registry: &UserPageMappingRegistry<ZeroedFrame, CAPACITY>,
    editor: &mut KernelInactiveAddressSpaceEditor<'_>,
    visited: &mut [u64; TABLE_FRAME_CAPACITY],
    visited_count: &mut usize,
) -> Result<(), PagingError> {
    for pdpt_index in 0..PML4_ENTRY_COUNT {
        let entry = editor
            .read_entry(pdpt_physical, pdpt_index, 3)
            .ok_or(PagingError::InactivePageTableUnavailable)?;
        if entry == 0 {
            continue;
        }
        if entry & PRESENT == 0
            || entry & LARGE_PAGE != 0
            || entry & PROTECTION_KEY_FIELD_MASK != 0
            || entry & WRITABLE == 0
            || entry & USER_ACCESSIBLE == 0
        {
            return Err(PagingError::InactivePageTableMalformed);
        }
        let pd_physical = entry & PHYSICAL_ADDRESS_MASK;
        editor.validate_private_child(pd_physical, 2, visited, *visited_count)?;
        visited[*visited_count] = pd_physical;
        *visited_count += 1;
        preflight_private_pd(
            root_physical,
            pd_physical,
            virtual_prefix | ((pdpt_index as u64) << 30),
            registry,
            editor,
            visited,
            visited_count,
        )?;
    }
    Ok(())
}

fn preflight_private_pd<const CAPACITY: usize>(
    root_physical: u64,
    pd_physical: u64,
    virtual_prefix: u64,
    registry: &UserPageMappingRegistry<ZeroedFrame, CAPACITY>,
    editor: &mut KernelInactiveAddressSpaceEditor<'_>,
    visited: &mut [u64; TABLE_FRAME_CAPACITY],
    visited_count: &mut usize,
) -> Result<(), PagingError> {
    for pd_index in 0..PML4_ENTRY_COUNT {
        let entry = editor
            .read_entry(pd_physical, pd_index, 2)
            .ok_or(PagingError::InactivePageTableUnavailable)?;
        if entry == 0 {
            continue;
        }
        if entry & PRESENT == 0
            || entry & LARGE_PAGE != 0
            || entry & PROTECTION_KEY_FIELD_MASK != 0
            || entry & WRITABLE == 0
            || entry & USER_ACCESSIBLE == 0
        {
            return Err(PagingError::InactivePageTableMalformed);
        }
        let pt_physical = entry & PHYSICAL_ADDRESS_MASK;
        editor.validate_private_child(pt_physical, 1, visited, *visited_count)?;
        visited[*visited_count] = pt_physical;
        *visited_count += 1;
        preflight_private_pt(
            root_physical,
            pt_physical,
            virtual_prefix | ((pd_index as u64) << 21),
            registry,
            editor,
        )?;
    }
    Ok(())
}

fn preflight_private_pt<const CAPACITY: usize>(
    root_physical: u64,
    pt_physical: u64,
    virtual_prefix: u64,
    registry: &UserPageMappingRegistry<ZeroedFrame, CAPACITY>,
    editor: &mut KernelInactiveAddressSpaceEditor<'_>,
) -> Result<(), PagingError> {
    for pt_index in 0..PML4_ENTRY_COUNT {
        let entry = editor
            .read_entry(pt_physical, pt_index, 1)
            .ok_or(PagingError::InactivePageTableUnavailable)?;
        if entry == 0 {
            continue;
        }
        if entry & PRESENT == 0
            || entry & WRITABLE == 0
            || entry & USER_ACCESSIBLE == 0
            || entry & PROTECTION_KEY_FIELD_MASK != 0
        {
            return Err(PagingError::InactivePageTableMalformed);
        }
        let leaf_physical = entry & PHYSICAL_ADDRESS_MASK;
        if !valid_physical_page(leaf_physical, editor.physical_address_bits())
            || !editor.is_frame_allocated(leaf_physical)
            || editor.is_page_table_or_reserved_frame(leaf_physical)
        {
            return Err(PagingError::InactivePageTableOwnershipViolation);
        }

        let virtual_address = virtual_prefix | ((pt_index as u64) << 12);
        if virtual_address == 0 || virtual_address >= USER_VIRTUAL_ADDRESS_LIMIT {
            return Err(PagingError::InactivePageTableMalformed);
        }
        let expected_physical = registry
            .mapped_physical_address(virtual_address)
            .ok_or(PagingError::UnregisteredUserPage)?;
        if leaf_physical != expected_physical
            || leaf_physical == root_physical
            || leaf_physical == editor.active_root_physical
            || leaf_physical == editor.target_root_physical
        {
            return Err(PagingError::InactivePageTableOwnershipViolation);
        }

        let mut level = 4u8;
        let translation =
            translate_4level(virtual_address, root_physical, |table_physical, index| {
                let current_level = level;
                level = level.saturating_sub(1);
                editor.read_entry(table_physical, index, current_level)
            })
            .map_err(PagingError::Translation)?;
        if translation.page_size != PAGE_SIZE || translation.physical_address != expected_physical {
            return Err(PagingError::InactivePageTableOwnershipViolation);
        }
        if !translation.writable || !translation.user_accessible || translation.executable {
            return Err(PagingError::InactivePageTableMalformed);
        }
    }
    Ok(())
}

fn verify_private_table_empty(
    table_physical: u64,
    table_level: u8,
    editor: &mut KernelInactiveAddressSpaceEditor<'_>,
) -> Result<(), PagingError> {
    for index in 0..PML4_ENTRY_COUNT {
        let entry = editor
            .read_entry(table_physical, index, table_level)
            .ok_or(PagingError::InactivePageTableUnavailable)?;
        if entry != 0 {
            return Err(PagingError::InactivePageTableMalformed);
        }
    }
    Ok(())
}

fn release_pending_detached_private_table<E>(
    table_physical: u64,
    table_level: u8,
    editor: &mut KernelInactiveAddressSpaceEditor<'_>,
    release_table_frame: &mut impl FnMut(Frame) -> Result<(), (E, Frame)>,
) -> Result<(), PagingError> {
    // A previously attempted release may have left this frame detached and
    // registry-owned. It is no longer accepted by table_pointer(), so validate
    // its exact physical-memory-offset alias directly before retrying release.
    let alias = editor
        .active_offset_alias(table_physical)
        .ok_or(PagingError::InactivePageTableUnavailable)?;
    let entries = alias.cast::<u64>();
    for index in 0..PML4_ENTRY_COUNT {
        // SAFETY: active_offset_alias validates a writable alias to the entire
        // allocated 4 KiB frame. Every word must remain zero while detached.
        if unsafe { ptr::read_volatile(entries.add(index)) } != 0 {
            return Err(PagingError::PageTableFrameReleaseFailed);
        }
    }

    // SAFETY: the frame was marked detached only after its parent entry was
    // cleared, the table was emptied, and the inactive-root/TLB contract held.
    // The registry transaction restores the ownership record if free_frame
    // returns the token on failure, so a later teardown can retry it.
    match unsafe {
        TABLE_FRAMES.lock().release_published_for_root_with(
            editor.target_root_physical,
            table_physical,
            table_level,
            release_table_frame,
        )
    } {
        Ok(()) => Ok(()),
        Err(PublishedFrameReleaseError::Registry(_))
        | Err(PublishedFrameReleaseError::Release(_)) => {
            Err(PagingError::PageTableFrameReleaseFailed)
        }
        Err(PublishedFrameReleaseError::Restore { error, token }) => {
            // Restoration failure is an invariant violation. The Frame token
            // has no Drop-based allocator behavior, so leaving this branch only
            // halts the kernel; it cannot make the still-allocated frame reusable.
            let _stranded_frame_physical = token.physical_address();
            panic!(
                "failed to restore detached page-table ownership after free failure: {:?}",
                error
            );
        }
    }
}

fn release_detached_private_table<E>(
    table_physical: u64,
    table_level: u8,
    editor: &mut KernelInactiveAddressSpaceEditor<'_>,
    release_table_frame: &mut impl FnMut(Frame) -> Result<(), (E, Frame)>,
) -> Result<(), PagingError> {
    let pointer = editor
        .table_pointer(table_physical, table_level)
        .ok_or(PagingError::InactivePageTableUnavailable)?;
    verify_private_table_empty(table_physical, table_level, editor)?;

    // The parent entry was cleared before this function was entered; the table
    // is empty and the target root is inactive under the validated TLB contract.
    // SAFETY: table_pointer proves this is a writable alias to the exact,
    // exclusively owned, root-private table frame. No parent/root can reach it.
    unsafe { ptr::write_bytes(pointer.cast::<u8>(), 0, PAGE_SIZE as usize) };
    for index in 0..PML4_ENTRY_COUNT {
        // SAFETY: pointer still names the complete detached 4 KiB table frame.
        if unsafe { ptr::read_volatile(pointer.add(index)) } != 0 {
            return Err(PagingError::PageTableFrameReleaseFailed);
        }
    }

    // SAFETY: the parent entry is already clear, the table is empty, and the
    // target root is inactive with the required translation flush completed.
    unsafe {
        TABLE_FRAMES.lock().mark_published_table_detached_for_root(
            editor.target_root_physical,
            table_physical,
            table_level,
        )
    }
    .map_err(|_| PagingError::PageTableFrameReleaseFailed)?;

    release_pending_detached_private_table(table_physical, table_level, editor, release_table_frame)
}

fn reclaim_pending_detached_private_tables<E>(
    root_physical: u64,
    editor: &mut KernelInactiveAddressSpaceEditor<'_>,
    release_table_frame: &mut impl FnMut(Frame) -> Result<(), (E, Frame)>,
) -> Result<(), PagingError> {
    loop {
        // A release failure restores the token as detached. On a subsequent
        // teardown attempt there is no parent entry to rediscover it, so consume
        // this root-scoped pending list before deciding the root is reclaimable.
        let pending = TABLE_FRAMES
            .lock()
            .detached_table_for_root(root_physical, 0);
        let Some((physical_address, table_level)) = pending else {
            return Ok(());
        };
        release_pending_detached_private_table(
            physical_address,
            table_level,
            editor,
            release_table_frame,
        )?;
    }
}

fn reclaim_private_pd<E>(
    pd_physical: u64,
    editor: &mut KernelInactiveAddressSpaceEditor<'_>,
    release_table_frame: &mut impl FnMut(Frame) -> Result<(), (E, Frame)>,
) -> Result<(), PagingError> {
    for pd_index in 0..PML4_ENTRY_COUNT {
        let entry = editor
            .read_entry(pd_physical, pd_index, 2)
            .ok_or(PagingError::InactivePageTableUnavailable)?;
        if entry == 0 {
            continue;
        }
        if entry & PRESENT == 0 || entry & LARGE_PAGE != 0 || entry & PROTECTION_KEY_FIELD_MASK != 0
        {
            return Err(PagingError::InactivePageTableMalformed);
        }
        let pt_physical = entry & PHYSICAL_ADDRESS_MASK;
        if !editor.is_private_table(pt_physical, 1) {
            return Err(PagingError::InactivePageTableOwnershipViolation);
        }
        verify_private_table_empty(pt_physical, 1, editor)?;
        editor.write_entry(pd_physical, pd_index, 2, 0);
        release_detached_private_table(pt_physical, 1, editor, release_table_frame)?;
    }
    verify_private_table_empty(pd_physical, 2, editor)
}

fn reclaim_private_pdpt<E>(
    pdpt_physical: u64,
    editor: &mut KernelInactiveAddressSpaceEditor<'_>,
    release_table_frame: &mut impl FnMut(Frame) -> Result<(), (E, Frame)>,
) -> Result<(), PagingError> {
    for pdpt_index in 0..PML4_ENTRY_COUNT {
        let entry = editor
            .read_entry(pdpt_physical, pdpt_index, 3)
            .ok_or(PagingError::InactivePageTableUnavailable)?;
        if entry == 0 {
            continue;
        }
        if entry & PRESENT == 0 || entry & LARGE_PAGE != 0 || entry & PROTECTION_KEY_FIELD_MASK != 0
        {
            return Err(PagingError::InactivePageTableMalformed);
        }
        let pd_physical = entry & PHYSICAL_ADDRESS_MASK;
        if !editor.is_private_table(pd_physical, 2) {
            return Err(PagingError::InactivePageTableOwnershipViolation);
        }
        reclaim_private_pd(pd_physical, editor, release_table_frame)?;
        editor.write_entry(pdpt_physical, pdpt_index, 3, 0);
        release_detached_private_table(pd_physical, 2, editor, release_table_frame)?;
    }
    verify_private_table_empty(pdpt_physical, 3, editor)
}

fn reclaim_private_user_tables<E>(
    root_physical: u64,
    editor: &mut KernelInactiveAddressSpaceEditor<'_>,
    release_table_frame: &mut impl FnMut(Frame) -> Result<(), (E, Frame)>,
) -> Result<(), PagingError> {
    for pml4_index in 0..LOWER_HALF_PML4_ENTRIES {
        let entry = editor
            .read_entry(root_physical, pml4_index, 4)
            .ok_or(PagingError::InactivePageTableUnavailable)?;
        if entry == 0 {
            continue;
        }
        if entry & PRESENT == 0 || entry & LARGE_PAGE != 0 || entry & PROTECTION_KEY_FIELD_MASK != 0
        {
            return Err(PagingError::InactivePageTableMalformed);
        }
        let pdpt_physical = entry & PHYSICAL_ADDRESS_MASK;
        if !editor.is_private_table(pdpt_physical, 3) {
            return Err(PagingError::InactivePageTableOwnershipViolation);
        }
        reclaim_private_pdpt(pdpt_physical, editor, release_table_frame)?;
        editor.write_entry(root_physical, pml4_index, 4, 0);
        release_detached_private_table(pdpt_physical, 3, editor, release_table_frame)?;
    }
    Ok(())
}

fn initialize_user_frame_or_release_on_error<E>(
    frame: Frame,
    initializer: &mut impl UserFrameInitializer,
    release_frame: &mut impl FnMut(Frame) -> Result<(), (E, Frame)>,
) -> Result<ZeroedFrame, PagingError> {
    match initialize_user_frame(frame, initializer) {
        Ok(zeroed) => Ok(zeroed),
        Err((_initialization_error, frame)) => match release_frame(frame) {
            Ok(()) => Err(PagingError::UserFrameInitializationFailed),
            Err((_release_error, frame)) => {
                // A failed release must not permit reuse of a frame whose token
                // is no longer tracked by a caller. Fail-stop while retaining it
                // as allocated in the physical allocator.
                let _unreleased_frame_physical = frame.physical_address();
                panic!(
                    "allocator failed to release a frame after user-frame initialization failure"
                );
            }
        },
    }
}

/// Exercises the initializer-failure path and verifies that the exact returned
/// frame token reaches the allocator-release callback instead of being dropped.
pub fn verify_user_frame_initialization_failure_releases_frame_for_smoke() -> Result<(), PagingError>
{
    let frame = crate::memory::allocate_frame().map_err(|_| PagingError::FrameAllocationFailed)?;
    let expected_physical = frame.physical_address();
    let mut initializer = FailingUserFrameInitializer;
    let mut released_physical = None;
    let mut release_frame = |frame: Frame| {
        released_physical = Some(frame.physical_address());
        crate::memory::free_frame(frame)
    };

    let result =
        initialize_user_frame_or_release_on_error(frame, &mut initializer, &mut release_frame);
    drop(release_frame);
    if !matches!(result, Err(PagingError::UserFrameInitializationFailed))
        || released_physical != Some(expected_physical)
    {
        return Err(PagingError::UserFrameInitializationFailed);
    }
    Ok(())
}

/// Allocates, zeroes, and maps one test user-data page into an inactive root.
///
/// This helper is used by the normal-boot lifecycle smoke test. The returned
/// registry retains the frame token until the root has switched away and
/// teardown removes its mapping. It does not enter Ring 3.
pub fn map_test_user_page_for_teardown(
    boot_info: &BootInfo,
    root: &AddressSpaceRoot,
    active_root: &ActiveAddressSpaceRoot,
) -> Result<(UserPageMappingRegistry<ZeroedFrame, 1>, u64), PagingError> {
    let mut editor = KernelInactiveAddressSpaceEditor::new(boot_info, root, active_root)?;
    let frame = crate::memory::allocate_frame().map_err(|_| PagingError::FrameAllocationFailed)?;
    let data_frame_physical = frame.physical_address();
    // SAFETY: the initializer is bound to the current active root and the caller
    // keeps interrupts disabled and the active root stable for this operation.
    let mut initializer =
        unsafe { KernelUserFrameInitializer::new(boot_info, active_root.recursive_index()) };
    let mut release_frame = crate::memory::free_frame;
    let zeroed =
        initialize_user_frame_or_release_on_error(frame, &mut initializer, &mut release_frame)?;

    let mut registry = UserPageMappingRegistry::new(root);
    if let Err((error, zeroed)) =
        map_user_data_page(root, 0x4000, zeroed, &mut registry, &mut editor)
    {
        if let Err((_error, _frame)) = crate::memory::free_frame(zeroed.into_frame()) {
            panic!("allocator failed to release a zeroed, unpublished user frame");
        }
        return Err(PagingError::UserPageMapping(error));
    }
    Ok((registry, data_frame_physical))
}

/// Validates an inactive root's complete lower-half user page-table tree before
/// the CR3 switch path is allowed to activate it.
///
/// This is a read-only preflight. It requires every present lower-half leaf to be
/// represented by the matching registry and rejects foreign or shared private
/// tables, malformed entries, cycles, unsupported large pages, and capacity
/// exhaustion. The caller must serialize this check with all root mutations.
pub fn validate_inactive_user_address_space<const CAPACITY: usize>(
    boot_info: &BootInfo,
    root: &AddressSpaceRoot,
    active_root: &ActiveAddressSpaceRoot,
    registry: &UserPageMappingRegistry<ZeroedFrame, CAPACITY>,
) -> Result<(), PagingError> {
    let mut editor = KernelInactiveAddressSpaceEditor::new(boot_info, root, active_root)?;
    preflight_private_user_tree(root.physical_address(), registry, &mut editor)
}

/// Exercises preflight rejection of representative corrupted page-table states
/// on the real kernel alias, restoring every entry before returning.
pub fn verify_teardown_corruption_preflight_for_smoke<const CAPACITY: usize>(
    boot_info: &BootInfo,
    root: &AddressSpaceRoot,
    active_root: &ActiveAddressSpaceRoot,
    registry: &UserPageMappingRegistry<ZeroedFrame, CAPACITY>,
    foreign_root_physical: u64,
    foreign_data_physical: u64,
) -> Result<(), PagingError> {
    const TEST_VA: u64 = 0x4000;
    let mut editor = KernelInactiveAddressSpaceEditor::new(boot_info, root, active_root)?;
    // The editor-level predicate must fail closed for every live address-space
    // root, not only for the mapping editor's immediate target. This is checked
    // independently of the teardown preflight, which also validates leaf ownership.
    if !editor.is_page_table_or_reserved_frame(root.physical_address())
        || !editor.is_page_table_or_reserved_frame(active_root.physical_address())
        || !editor.is_page_table_or_reserved_frame(foreign_root_physical)
    {
        return Err(PagingError::InactivePageTableOwnershipViolation);
    }
    verify_user_frame_initialization_failure_releases_frame_for_smoke()?;
    let root_physical = root.physical_address();
    let pml4_index = ((TEST_VA >> 39) & 0x1ff) as usize;
    let pdpt_index = ((TEST_VA >> 30) & 0x1ff) as usize;
    let pd_index = ((TEST_VA >> 21) & 0x1ff) as usize;
    let pt_index = ((TEST_VA >> 12) & 0x1ff) as usize;

    let root_entry = editor
        .read_entry(root_physical, pml4_index, 4)
        .filter(|entry| *entry != 0)
        .ok_or(PagingError::InactivePageTableMalformed)?;
    let pdpt_physical = root_entry & PHYSICAL_ADDRESS_MASK;
    let pdpt_entry = editor
        .read_entry(pdpt_physical, pdpt_index, 3)
        .filter(|entry| *entry != 0)
        .ok_or(PagingError::InactivePageTableMalformed)?;
    let pd_physical = pdpt_entry & PHYSICAL_ADDRESS_MASK;
    let pd_entry = editor
        .read_entry(pd_physical, pd_index, 2)
        .filter(|entry| *entry != 0)
        .ok_or(PagingError::InactivePageTableMalformed)?;
    let pt_physical = pd_entry & PHYSICAL_ADDRESS_MASK;
    let leaf_entry = editor
        .read_entry(pt_physical, pt_index, 1)
        .filter(|entry| *entry != 0)
        .ok_or(PagingError::InactivePageTableMalformed)?;

    macro_rules! expect_rejected {
        ($table:expr, $level:expr, $index:expr, $original:expr, $bad:expr, $expected:expr) => {{
            editor.write_entry($table, $index, $level, $bad);
            let observed = preflight_private_user_tree(root_physical, registry, &mut editor);
            editor.write_entry($table, $index, $level, $original);
            if observed != Err($expected)
                || editor.read_entry($table, $index, $level) != Some($original)
            {
                return Err(PagingError::InactivePageTableMalformed);
            }
        }};
    }

    // Root self-cycle / foreign table target: ownership preflight must reject it.
    expect_rejected!(
        root_physical,
        4,
        pml4_index,
        root_entry,
        (root_entry & !PHYSICAL_ADDRESS_MASK) | root_physical,
        PagingError::InactivePageTableOwnershipViolation
    );
    // A large-page flag at an intermediate level must be rejected before walking.
    expect_rejected!(
        root_physical,
        4,
        pml4_index,
        root_entry,
        root_entry | LARGE_PAGE,
        PagingError::InactivePageTableMalformed
    );
    // A non-present but non-zero leaf is malformed and must not start teardown.
    expect_rejected!(
        pt_physical,
        1,
        pt_index,
        leaf_entry,
        leaf_entry & !PRESENT,
        PagingError::InactivePageTableMalformed
    );
    // Pointing a user leaf at an owned page-table frame must fail as reserved.
    expect_rejected!(
        pt_physical,
        1,
        pt_index,
        leaf_entry,
        (leaf_entry & !PHYSICAL_ADDRESS_MASK) | pt_physical,
        PagingError::InactivePageTableOwnershipViolation
    );
    // A valid, allocated data frame owned by another address space must not
    // satisfy this root's mapping merely because it is a user-usable frame.
    expect_rejected!(
        pt_physical,
        1,
        pt_index,
        leaf_entry,
        (leaf_entry & !PHYSICAL_ADDRESS_MASK) | foreign_data_physical,
        PagingError::InactivePageTableOwnershipViolation
    );
    // Reject the target's own PML4 and another root's PML4 as user data frames.
    expect_rejected!(
        pt_physical,
        1,
        pt_index,
        leaf_entry,
        (leaf_entry & !PHYSICAL_ADDRESS_MASK) | root_physical,
        PagingError::InactivePageTableOwnershipViolation
    );
    expect_rejected!(
        pt_physical,
        1,
        pt_index,
        leaf_entry,
        (leaf_entry & !PHYSICAL_ADDRESS_MASK) | foreign_root_physical,
        PagingError::InactivePageTableOwnershipViolation
    );
    // Delete a registered mapping's PTE. The tree walk alone skips zero entries;
    // the registry-to-PTE pass must detect the now-missing translation.
    expect_rejected!(
        pt_physical,
        1,
        pt_index,
        leaf_entry,
        0,
        PagingError::InactivePageTableMalformed
    );

    // Register an allocated but unreachable table frame to prove reverse
    // ownership validation rejects an orphan before teardown can mutate the tree.
    let orphan_table_physical = editor
        .allocate_table()
        .ok_or(PagingError::FrameAllocationFailed)?;
    // SAFETY: the orphan is an exclusively allocated, zeroed table frame. This
    // injected bad state exists only to test that preflight rejects it.
    if unsafe {
        TABLE_FRAMES
            .lock()
            .mark_published_for_root(root_physical, orphan_table_physical, 1)
    }
    .is_err()
    {
        editor.free_table(orphan_table_physical);
        return Err(PagingError::InactivePageTableOwnershipViolation);
    }
    let orphan_rejected = matches!(
        preflight_private_user_tree(root_physical, registry, &mut editor),
        Err(PagingError::InactivePageTableOwnershipViolation)
    );

    // Restore a valid detached-pending state so the allocated test frame can be
    // reclaimed by the same production release transaction used by teardown.
    // SAFETY: this injected frame has no parent entry, is zeroed and unreachable.
    unsafe {
        TABLE_FRAMES.lock().mark_published_table_detached_for_root(
            root_physical,
            orphan_table_physical,
            1,
        )
    }
    .map_err(|_| PagingError::InactivePageTableOwnershipViolation)?;
    if !editor.remove_staged_table(orphan_table_physical) {
        return Err(PagingError::InactivePageTableOwnershipViolation);
    }
    let mut release_table_frame = crate::memory::free_frame;
    release_pending_detached_private_table(
        orphan_table_physical,
        1,
        &mut editor,
        &mut release_table_frame,
    )?;
    if !orphan_rejected {
        return Err(PagingError::InactivePageTableMalformed);
    }

    if !registry.is_mapped(TEST_VA)
        || preflight_private_user_tree(root_physical, registry, &mut editor).is_err()
    {
        return Err(PagingError::InactivePageTableMalformed);
    }
    Ok(())
}

struct FailingUserFrameInitializer;

// SAFETY: this test initializer always fails and never claims that any frame is
// zeroed, so initialize_user_frame cannot create an invalid ZeroedFrame token.
unsafe impl UserFrameInitializer for FailingUserFrameInitializer {
    fn zero_frame(&mut self, _frame: &Frame) -> Result<(), UserFrameInitializationError> {
        Err(UserFrameInitializationError::InitializationFailed)
    }
}

fn active_root_table_physical() -> u64 {
    let cr3: u64;
    // SAFETY: CR3 is readable in privileged x86_64 kernel execution.
    unsafe {
        asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    }
    cr3 & PHYSICAL_ADDRESS_MASK
}

fn valid_physical_page(address: u64, bits: u8) -> bool {
    if !(32..=52).contains(&bits) || address == 0 || address & (PAGE_SIZE - 1) != 0 {
        return false;
    }
    let mask = ((1u64 << bits) - 1) & PHYSICAL_ADDRESS_MASK;
    address & !mask == 0
}

fn virtual_index(virtual_address: u64, level: u8) -> Option<usize> {
    if !(1..=4).contains(&level) {
        return None;
    }
    let shift = 12 + u32::from(level - 1) * 9;
    Some(((virtual_address >> shift) & 0x1ff) as usize)
}

fn entry_pointer_from_page(table_virtual_address: u64, index: usize) -> Option<*mut u64> {
    if index >= 512
        || !is_canonical_4level(table_virtual_address)
        || table_virtual_address & (PAGE_SIZE - 1) != 0
    {
        return None;
    }
    let offset = u64::try_from(index)
        .ok()?
        .checked_mul(size_of::<u64>() as u64)?;
    let address = table_virtual_address.checked_add(offset)?;
    let end = address.checked_add(size_of::<u64>() as u64 - 1)?;
    if !is_canonical_4level(address) || !is_canonical_4level(end) || address & 7 != 0 {
        return None;
    }
    Some(usize::try_from(address).ok()? as *mut u64)
}

fn translate_with_editor(
    editor: &mut KernelPageTableEditor<'_>,
    root_table_physical: u64,
    virtual_address: u64,
) -> Result<PageTranslation, PageTableError> {
    // entry_pointer() derives recursive aliases from editor.target_virtual_address.
    // That context must describe the address being translated, not the unrelated
    // mapping candidate the editor was originally created for. Restore the prior
    // target afterwards so a caller can continue its existing map/unmap operation.
    let previous_target = editor.target_virtual_address;
    editor.target_virtual_address = virtual_address;
    let mut level = 4u8;
    let result = translate_4level(virtual_address, root_table_physical, |table, index| {
        let current_level = level;
        level = level.saturating_sub(1);
        editor.read_entry(table, index, current_level)
    });
    editor.target_virtual_address = previous_target;
    result
}

fn invalidate_local_tlb(virtual_address: u64) {
    // SAFETY: INVLPG is available in the current x86_64 kernel and operates on
    // the target virtual address in the local CPU's translation cache.
    unsafe {
        asm!(
            "invlpg [{}]",
            in(reg) virtual_address,
            options(nostack, preserves_flags)
        );
    }
}

pub use acceptance::{
    enforce_kernel_executable_alias_wx, has_pending_detached_private_table,
    teardown_inactive_user_address_space, teardown_inactive_user_address_space_with_table_release,
    verify_large_page_demotion_smoke_test, verify_mapping_smoke_test,
    verify_user_frame_zeroing_test_with_recursive_index, InactiveAddressSpaceTeardownError,
    KernelUserFrameInitializer,
};
pub use wx_audit::audit_registered_wx_roots;

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
pub use acceptance::verify_user_frame_zeroing_test;

#[cfg(feature = "test-wx-runtime-audit")]
pub use acceptance::{
    apply_wx_sibling_test_transition, kernel_executable_direct_alias_for_test,
    verify_live_root_registry_unregistration_rejected_for_smoke,
    verify_wx_audit_cross_root_alias_for_smoke, verify_wx_sibling_large_page_precondition,
    verify_wx_sibling_test_after_transition, WxSiblingRegressionTest,
};

#[cfg(any(
    feature = "test-supervisor-write-protection",
    feature = "test-nx-protection"
))]
pub use acceptance::ProtectionTestMapping;

#[cfg(feature = "test-supervisor-write-protection")]
pub use acceptance::install_supervisor_write_protection_test;

#[cfg(feature = "test-nx-protection")]
pub use acceptance::install_nx_execution_protection_test;

#[cfg(feature = "test-vm-transitions")]
pub use acceptance::{prepare_mapping_transition_test, MappingTransitionTest};
