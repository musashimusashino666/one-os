//! Fixed-capacity ownership registry for page-table frames.
//!
//! The registry reserves metadata capacity before a physical frame is allocated,
//! retains the non-Copy token until the frame is released, and refuses to release
//! a published page-table frame until the caller proves it detached and records
//! that state.
//!
//! This type does not provide internal synchronization. Mutating methods require
//! exclusive `&mut` access, and callers that place it behind interior mutability
//! must serialize *all* reads and writes themselves. In the kernel, the wrapper
//! uses a non-blocking atomic access guard for registry state; page-table tree
//! mutation additionally requires the documented single-CPU, interrupts-disabled
//! contract. Neither contract alone implements remote TLB shootdowns or makes
//! the page-table tree safe for concurrent SMP mutation.

/// The ownership token for a physical frame tracked by a frame registry.
pub trait FrameToken {
    /// Physical base address of the frame represented by this token.
    fn frame_address(&self) -> u64;
}

impl FrameToken for crate::Frame {
    fn frame_address(&self) -> u64 {
        self.physical_address()
    }
}

/// The state error returned by the fixed-capacity page-table frame registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameRegistryError {
    /// The requested slot is not reserved.
    InvalidReservation,
    /// A frame with the same physical base is already owned by the registry.
    DuplicateFrameAddress,
    /// No owned frame has the requested physical base address.
    FrameNotFound,
    /// A published table frame must not be released through this registry.
    PublishedFrame,
    /// The supplied owner root is zero, unaligned, or otherwise invalid.
    InvalidOwnerRoot,
    /// The frame is published for a different root/level or has no private owner.
    PublishedOwnerMismatch,
    /// The frame is not currently published.
    NotPublished,
    /// The frame has not been marked detached before release.
    NotDetached,
}

/// Error returned by a root-scoped page-table frame release transaction.
pub enum PublishedFrameReleaseError<E, T> {
    /// The registry did not contain the expected detached root-owned frame.
    Registry(FrameRegistryError),
    /// The allocator refused to release the frame; the token has been restored.
    Release(E),
    /// Restoration violated a registry invariant; the caller still owns this token.
    Restore { error: FrameRegistryError, token: T },
}

/// Fixed-capacity storage for reserved and owned page-table frame tokens.
///
/// A reservation consumes metadata capacity before allocation. `install_reserved`
/// transfers a non-Copy ownership token into the slot. Published frames remain
/// owned, but cannot be released through `take_unpublished`.
///
/// This registry is intentionally unsynchronized. Every mutation requires
/// exclusive access, and any kernel wrapper using `UnsafeCell` must establish
/// exclusion for reads as well as writes before dereferencing the cell.
pub struct PageTableFrameRegistry<T: FrameToken, const CAPACITY: usize> {
    slots: [FrameSlot<T>; CAPACITY],
}

enum FrameSlot<T> {
    Empty,
    Reserved,
    Owned {
        token: T,
        published: bool,
        owner_root_physical: Option<u64>,
        owner_table_level: Option<u8>,
        detached: bool,
    },
}

impl<T: FrameToken, const CAPACITY: usize> PageTableFrameRegistry<T, CAPACITY> {
    /// Creates an empty registry without allocating.
    pub const fn new() -> Self {
        Self {
            slots: [const { FrameSlot::Empty }; CAPACITY],
        }
    }

    /// Reserves one metadata slot before the caller allocates a physical frame.
    ///
    /// Returns None when the registry is full. In that case, the allocation
    /// callback must not be called and the registry remains unchanged.
    pub fn reserve_slot(&mut self) -> Option<usize> {
        let index = self
            .slots
            .iter()
            .position(|slot| matches!(slot, FrameSlot::Empty))?;
        self.slots[index] = FrameSlot::Reserved;
        Some(index)
    }

    /// Cancels a reservation after allocation fails or frame validation rejects it.
    pub fn cancel_reservation(&mut self, index: usize) -> Result<(), FrameRegistryError> {
        match self.slots.get_mut(index) {
            Some(slot @ FrameSlot::Reserved) => {
                *slot = FrameSlot::Empty;
                Ok(())
            }
            _ => Err(FrameRegistryError::InvalidReservation),
        }
    }

    /// Installs an owned frame token into a previously reserved slot.
    ///
    /// On error, returns the original token so that the caller can release it
    /// through the allocator that issued it instead of dropping ownership.
    pub fn install_reserved(
        &mut self,
        index: usize,
        token: T,
    ) -> Result<(), (FrameRegistryError, T)> {
        if !matches!(self.slots.get(index), Some(FrameSlot::Reserved)) {
            return Err((FrameRegistryError::InvalidReservation, token));
        }
        if self.slots.iter().any(|slot| {
            matches!(slot, FrameSlot::Owned { token: owned, .. } if owned.frame_address() == token.frame_address())
        }) {
            return Err((FrameRegistryError::DuplicateFrameAddress, token));
        }

        self.slots[index] = FrameSlot::Owned {
            token,
            published: false,
            owner_root_physical: None,
            owner_table_level: None,
            detached: false,
        };
        Ok(())
    }

    /// Returns whether the registry owns a token for the physical frame.
    pub fn contains(&self, physical_address: u64) -> bool {
        self.slots.iter().any(|slot| {
            matches!(
                slot,
                FrameSlot::Owned { token, .. } if token.frame_address() == physical_address
            )
        })
    }

    /// Returns whether the physical frame is owned but not yet published.
    pub fn contains_unpublished(&self, physical_address: u64) -> bool {
        self.slots.iter().any(|slot| {
            matches!(
                slot,
                FrameSlot::Owned {
                    token,
                    published: false,
                    ..
                } if token.frame_address() == physical_address
            )
        })
    }

    /// Returns whether a frame is published for shared/kernel-half use rather than
    /// assigned to a private address-space root. This is intentionally stricter than
    /// `contains() && !contains_unpublished()`: a detached or private-root-owned
    /// table must not be accepted by a shared-root page-table walk.
    pub fn contains_published_unowned(&self, physical_address: u64) -> bool {
        self.slots.iter().any(|slot| {
            matches!(
                slot,
                FrameSlot::Owned {
                    token,
                    published: true,
                    owner_root_physical: None,
                    owner_table_level: None,
                    detached: false,
                } if token.frame_address() == physical_address
            )
        })
    }

    /// Marks a frame as published when the registry cannot establish a private
    /// address-space owner. Such a frame remains non-releasable through
    /// `take_unpublished`; it cannot be reclaimed by the root-scoped API.
    pub fn mark_published(&mut self, physical_address: u64) -> Result<(), FrameRegistryError> {
        for slot in &mut self.slots {
            if let FrameSlot::Owned {
                token, published, ..
            } = slot
            {
                if token.frame_address() == physical_address {
                    *published = true;
                    return Ok(());
                }
            }
        }
        Err(FrameRegistryError::FrameNotFound)
    }

    /// Marks a page-table frame as published in one private address-space tree.
    ///
    /// Calling this repeatedly for the same (root, frame, level) is idempotent.
    /// A frame already published without an owner, or owned by another root or
    /// paging level, is rejected instead of being silently adopted.
    ///
    /// # Safety
    ///
    /// The caller must have established that the frame is an exclusively owned,
    /// allocator-issued page-table frame and is being published only beneath the
    /// supplied root's private lower-half mapping tree. The frame must not be
    /// shared with another root or reachable through an unrelated page-table
    /// tree at `table_level`. The registry records this assertion; it does not
    /// verify reachability or the actual hardware table depth.
    #[allow(unsafe_code)]
    pub unsafe fn mark_published_for_root(
        &mut self,
        root_physical: u64,
        physical_address: u64,
        table_level: u8,
    ) -> Result<(), FrameRegistryError> {
        if root_physical == 0
            || root_physical & (crate::PAGE_SIZE - 1) != 0
            || !(1..=3).contains(&table_level)
        {
            return Err(FrameRegistryError::InvalidOwnerRoot);
        }

        for slot in &mut self.slots {
            if let FrameSlot::Owned {
                token,
                published,
                owner_root_physical,
                owner_table_level,
                detached,
                ..
            } = slot
            {
                if token.frame_address() != physical_address {
                    continue;
                }

                if *published {
                    return if *owner_root_physical == Some(root_physical)
                        && *owner_table_level == Some(table_level)
                        && !*detached
                    {
                        Ok(())
                    } else {
                        Err(FrameRegistryError::PublishedOwnerMismatch)
                    };
                }

                *published = true;
                *owner_root_physical = Some(root_physical);
                *owner_table_level = Some(table_level);
                *detached = false;
                return Ok(());
            }
        }

        Err(FrameRegistryError::FrameNotFound)
    }

    /// Counts published page-table frames whose private owner is this root.
    ///
    /// Teardown uses this after walking and reclaiming the reachable private
    /// tree. A non-zero count means that root-owned table tokens remain tracked
    /// (for example after an earlier partial failure), so the root must not be
    /// released and its physical address reused as a new ownership identity.
    pub fn published_count_for_root(
        &self,
        root_physical: u64,
    ) -> Result<usize, FrameRegistryError> {
        if root_physical == 0 || root_physical & (crate::PAGE_SIZE - 1) != 0 {
            return Err(FrameRegistryError::InvalidOwnerRoot);
        }

        Ok(self
            .slots
            .iter()
            .filter(|slot| {
                matches!(
                    slot,
                    FrameSlot::Owned {
                        published: true,
                        owner_root_physical: Some(owner),
                        ..
                    } if *owner == root_physical
                )
            })
            .count())
    }

    /// Returns a root-owned page-table token by zero-based registry order.
    ///
    /// The snapshot deliberately includes inconsistent publication or level
    /// metadata so teardown preflight can fail closed instead of silently
    /// skipping a token whose ownership record is malformed.
    ///
    /// The tuple contains (physical address, table level, published, detached).
    pub fn root_owned_table_at(
        &self,
        root_physical: u64,
        ordinal: usize,
    ) -> Option<(u64, Option<u8>, bool, bool)> {
        if root_physical == 0 || root_physical & (crate::PAGE_SIZE - 1) != 0 {
            return None;
        }

        self.slots
            .iter()
            .filter_map(|slot| match slot {
                FrameSlot::Owned {
                    token,
                    published,
                    owner_root_physical: Some(owner),
                    owner_table_level,
                    detached,
                    ..
                } if *owner == root_physical => Some((
                    token.frame_address(),
                    *owner_table_level,
                    *published,
                    *detached,
                )),
                _ => None,
            })
            .nth(ordinal)
    }

    /// Returns the paging level recorded for a root-private table frame.
    pub fn published_table_level_for_root(
        &self,
        root_physical: u64,
        physical_address: u64,
    ) -> Option<u8> {
        if root_physical == 0 || root_physical & (crate::PAGE_SIZE - 1) != 0 {
            return None;
        }

        self.slots.iter().find_map(|slot| match slot {
            FrameSlot::Owned {
                token,
                published: true,
                owner_root_physical: Some(owner),
                owner_table_level: Some(level),
                detached: false,
                ..
            } if token.frame_address() == physical_address && *owner == root_physical => {
                Some(*level)
            }
            _ => None,
        })
    }

    /// Returns whether a published frame is recorded as private to this root.
    pub fn contains_published_for_root(&self, root_physical: u64, physical_address: u64) -> bool {
        if root_physical == 0 || root_physical & (crate::PAGE_SIZE - 1) != 0 {
            return false;
        }

        self.slots.iter().any(|slot| {
            matches!(
                slot,
                FrameSlot::Owned {
                    token,
                    published: true,
                    owner_root_physical: Some(owner),
                    ..
                } if token.frame_address() == physical_address && *owner == root_physical
            )
        })
    }

    /// Marks a root-private published table as detached and safe to release.
    ///
    /// # Safety
    ///
    /// The caller must have cleared the table's only parent entry, proved the
    /// table is empty and unreachable from every root, and completed the required
    /// inactive-root/TLB transition. This function records that proof; it does
    /// not inspect hardware page-table reachability.
    #[allow(unsafe_code)]
    pub unsafe fn mark_published_table_detached_for_root(
        &mut self,
        root_physical: u64,
        physical_address: u64,
        table_level: u8,
    ) -> Result<(), FrameRegistryError> {
        if root_physical == 0
            || root_physical & (crate::PAGE_SIZE - 1) != 0
            || !(1..=3).contains(&table_level)
        {
            return Err(FrameRegistryError::InvalidOwnerRoot);
        }

        let Some(slot) = self.slots.iter_mut().find(|slot| {
            matches!(
                slot,
                FrameSlot::Owned { token, .. } if token.frame_address() == physical_address
            )
        }) else {
            return Err(FrameRegistryError::FrameNotFound);
        };

        match slot {
            FrameSlot::Owned {
                published: true,
                owner_root_physical: Some(owner),
                owner_table_level: Some(level),
                detached,
                ..
            } if *owner == root_physical && *level == table_level && !*detached => {
                *detached = true;
                Ok(())
            }
            FrameSlot::Owned {
                published: true,
                owner_root_physical: Some(owner),
                owner_table_level: Some(level),
                detached: true,
                ..
            } if *owner == root_physical && *level == table_level => {
                Err(FrameRegistryError::PublishedOwnerMismatch)
            }
            FrameSlot::Owned {
                published: false, ..
            } => Err(FrameRegistryError::NotPublished),
            _ => Err(FrameRegistryError::PublishedOwnerMismatch),
        }
    }

    /// Returns the physical address and paging level of the nth detached table
    /// awaiting release for this root.
    ///
    /// This includes detached tokens restored after allocator release failure,
    /// allowing a later teardown retry to reclaim them without a live parent entry.
    pub fn detached_table_for_root(&self, root_physical: u64, ordinal: usize) -> Option<(u64, u8)> {
        if root_physical == 0 || root_physical & (crate::PAGE_SIZE - 1) != 0 {
            return None;
        }

        self.slots
            .iter()
            .filter_map(|slot| match slot {
                FrameSlot::Owned {
                    token,
                    published: true,
                    owner_root_physical: Some(owner),
                    owner_table_level: Some(level),
                    detached: true,
                    ..
                } if *owner == root_physical => Some((token.frame_address(), *level)),
                _ => None,
            })
            .nth(ordinal)
    }

    /// Restores a detached table token after the physical allocator refused to
    /// release it. The token remains owned by the registry and is eligible for
    /// a later retry even though its parent entry is already clear.
    ///
    /// # Safety
    ///
    /// token must be the allocator-issued token previously removed from this
    /// registry for this exact root and table level after detachment. The caller
    /// must not use this API to adopt an unrelated frame.
    #[allow(unsafe_code)]
    pub unsafe fn restore_detached_published_for_root(
        &mut self,
        token: T,
        root_physical: u64,
        table_level: u8,
    ) -> Result<(), (FrameRegistryError, T)> {
        if root_physical == 0
            || root_physical & (crate::PAGE_SIZE - 1) != 0
            || !(1..=3).contains(&table_level)
        {
            return Err((FrameRegistryError::InvalidOwnerRoot, token));
        }

        if self.slots.iter().any(|slot| {
            matches!(
                slot,
                FrameSlot::Owned { token: existing, .. }
                    if existing.frame_address() == token.frame_address()
            )
        }) {
            return Err((FrameRegistryError::DuplicateFrameAddress, token));
        }

        let Some(index) = self
            .slots
            .iter()
            .position(|slot| matches!(slot, FrameSlot::Empty))
        else {
            return Err((FrameRegistryError::InvalidReservation, token));
        };

        self.slots[index] = FrameSlot::Owned {
            token,
            published: true,
            owner_root_physical: Some(root_physical),
            owner_table_level: Some(table_level),
            detached: true,
        };
        Ok(())
    }

    /// Returns and removes a published page-table frame recorded as private to
    /// the supplied root.
    ///
    /// # Safety
    ///
    /// The caller must have proved that the frame is detached from every parent
    /// entry, is unreachable from every address-space root, and cannot be used by
    /// any stale translation or recursive alias. The registry records ownership;
    /// it does not itself prove page-table reachability or TLB completion.
    #[allow(unsafe_code)]
    pub unsafe fn take_published_for_root(
        &mut self,
        root_physical: u64,
        physical_address: u64,
        table_level: u8,
    ) -> Result<T, FrameRegistryError> {
        if root_physical == 0
            || root_physical & (crate::PAGE_SIZE - 1) != 0
            || !(1..=3).contains(&table_level)
        {
            return Err(FrameRegistryError::InvalidOwnerRoot);
        }

        let Some(index) = self.slots.iter().position(|slot| {
            matches!(
                slot,
                FrameSlot::Owned { token, .. } if token.frame_address() == physical_address
            )
        }) else {
            return Err(FrameRegistryError::FrameNotFound);
        };

        match &self.slots[index] {
            FrameSlot::Owned {
                published: true,
                owner_root_physical: Some(owner),
                owner_table_level: Some(level),
                detached: true,
                ..
            } if *owner == root_physical && *level == table_level => {}
            FrameSlot::Owned {
                published: true,
                owner_root_physical: Some(owner),
                owner_table_level: Some(level),
                detached: false,
                ..
            } if *owner == root_physical && *level == table_level => {
                return Err(FrameRegistryError::NotDetached)
            }
            FrameSlot::Owned {
                published: true, ..
            } => return Err(FrameRegistryError::PublishedOwnerMismatch),
            FrameSlot::Owned {
                published: false, ..
            } => return Err(FrameRegistryError::NotPublished),
            FrameSlot::Empty | FrameSlot::Reserved => {
                return Err(FrameRegistryError::FrameNotFound);
            }
        }

        let slot = core::mem::replace(&mut self.slots[index], FrameSlot::Empty);
        match slot {
            FrameSlot::Owned {
                token,
                published: true,
                owner_root_physical: Some(owner),
                owner_table_level: Some(level),
                detached: true,
            } if owner == root_physical && level == table_level => Ok(token),
            other => {
                // Restore unexpected state rather than dropping a non-Copy
                // ownership token on an invariant failure.
                self.slots[index] = other;
                Err(FrameRegistryError::PublishedOwnerMismatch)
            }
        }
    }

    /// Releases one detached table through a fallible allocator operation.
    ///
    /// If the allocator rejects the token and returns it, this method restores
    /// the root/level/detached registry record before returning the allocator
    /// error. A subsequent teardown can discover and retry the detached frame.
    ///
    /// # Safety
    ///
    /// The frame must already be marked detached because its parent entry is
    /// clear, the frame is empty and unreachable from every root, and the
    /// required inactive-root/TLB transition is complete. The release callback
    /// must return the original token on failure rather than dropping it.
    #[allow(unsafe_code)]
    pub unsafe fn release_published_for_root_with<E>(
        &mut self,
        root_physical: u64,
        physical_address: u64,
        table_level: u8,
        release: impl FnOnce(T) -> Result<(), (E, T)>,
    ) -> Result<(), PublishedFrameReleaseError<E, T>> {
        // SAFETY: the caller's contract above establishes detachment and TLB safety.
        let token =
            unsafe { self.take_published_for_root(root_physical, physical_address, table_level) }
                .map_err(PublishedFrameReleaseError::Registry)?;

        match release(token) {
            Ok(()) => Ok(()),
            Err((error, token)) => {
                // SAFETY: release returned the exact token taken above, and no
                // other registry operation can adopt it while this transaction
                // is serialized by the caller.
                match unsafe {
                    self.restore_detached_published_for_root(token, root_physical, table_level)
                } {
                    Ok(()) => Err(PublishedFrameReleaseError::Release(error)),
                    Err((restore_error, token)) => Err(PublishedFrameReleaseError::Restore {
                        error: restore_error,
                        token,
                    }),
                }
            }
        }
    }

    /// Removes and returns an unpublished token, freeing its registry slot.
    ///
    /// Published frames are deliberately retained; callers must not use unmap
    /// as a reason to free page-table frames that can still be reached by a
    /// recursive alias or by another mapping.
    pub fn take_unpublished(&mut self, physical_address: u64) -> Result<T, FrameRegistryError> {
        let Some(index) = self.slots.iter().position(|slot| {
            matches!(
                slot,
                FrameSlot::Owned { token, .. } if token.frame_address() == physical_address
            )
        }) else {
            return Err(FrameRegistryError::FrameNotFound);
        };

        match &self.slots[index] {
            FrameSlot::Owned {
                published: true, ..
            } => return Err(FrameRegistryError::PublishedFrame),
            FrameSlot::Owned {
                published: false, ..
            } => {}
            FrameSlot::Empty | FrameSlot::Reserved => {
                return Err(FrameRegistryError::FrameNotFound);
            }
        }

        let slot = core::mem::replace(&mut self.slots[index], FrameSlot::Empty);
        match slot {
            FrameSlot::Owned {
                token,
                published: false,
                ..
            } => Ok(token),
            FrameSlot::Owned {
                published: true, ..
            } => Err(FrameRegistryError::PublishedFrame),
            FrameSlot::Empty | FrameSlot::Reserved => Err(FrameRegistryError::FrameNotFound),
        }
    }

    /// Number of unused metadata slots.
    pub fn available_slots(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| matches!(slot, FrameSlot::Empty))
            .count()
    }
}

impl<T: FrameToken, const CAPACITY: usize> Default for PageTableFrameRegistry<T, CAPACITY> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{FrameRegistryError, FrameToken, PageTableFrameRegistry};

    #[derive(Debug, Eq, PartialEq)]
    struct TestFrame {
        address: u64,
        token_id: u64,
    }

    impl TestFrame {
        fn new(address: u64, token_id: u64) -> Self {
            Self { address, token_id }
        }
    }

    impl FrameToken for TestFrame {
        fn frame_address(&self) -> u64 {
            self.address
        }
    }

    #[test]
    #[allow(unsafe_code)]
    fn root_owned_table_enumeration_includes_detached_pending_tokens() {
        let mut registry = PageTableFrameRegistry::<TestFrame, 2>::new();
        let first = registry.reserve_slot().unwrap();
        registry
            .install_reserved(first, TestFrame::new(0x8000, 1))
            .unwrap();
        let second = registry.reserve_slot().unwrap();
        registry
            .install_reserved(second, TestFrame::new(0x9000, 2))
            .unwrap();

        // SAFETY: this test models two allocator-owned private tables below one
        // root. The detached second token is deliberately pending release.
        unsafe { registry.mark_published_for_root(0x1000, 0x8000, 2) }.unwrap();
        unsafe { registry.mark_published_for_root(0x1000, 0x9000, 1) }.unwrap();
        unsafe { registry.mark_published_table_detached_for_root(0x1000, 0x9000, 1) }.unwrap();

        assert_eq!(
            registry.root_owned_table_at(0x1000, 0),
            Some((0x8000, Some(2), true, false))
        );
        assert_eq!(
            registry.root_owned_table_at(0x1000, 1),
            Some((0x9000, Some(1), true, true))
        );
        assert_eq!(registry.root_owned_table_at(0x1000, 2), None);
        assert_eq!(registry.root_owned_table_at(0, 0), None);
    }

    #[test]
    fn reservation_precedes_allocation_and_full_registry_fails_closed() {
        let mut registry = PageTableFrameRegistry::<TestFrame, 2>::new();
        let first = registry.reserve_slot().unwrap();
        registry
            .install_reserved(first, TestFrame::new(0x1000, 1))
            .unwrap();
        let second = registry.reserve_slot().unwrap();
        registry
            .install_reserved(second, TestFrame::new(0x2000, 2))
            .unwrap();

        let mut allocation_calls = 0;
        let attempted = registry.reserve_slot().map(|slot| {
            allocation_calls += 1;
            (slot, TestFrame::new(0x3000, 3))
        });

        assert!(attempted.is_none());
        assert_eq!(allocation_calls, 0);
        assert_eq!(registry.available_slots(), 0);
        assert!(registry.contains(0x1000));
        assert!(registry.contains(0x2000));
        assert!(!registry.contains(0x3000));
    }

    #[test]
    fn token_is_retained_until_unpublished_frame_is_taken_exactly_once() {
        let mut registry = PageTableFrameRegistry::<TestFrame, 1>::new();
        let slot = registry.reserve_slot().unwrap();
        registry
            .install_reserved(slot, TestFrame::new(0x4000, 77))
            .unwrap();

        assert!(registry.contains(0x4000));
        assert!(registry.contains_unpublished(0x4000));
        assert_eq!(
            registry.take_unpublished(0x4000).unwrap(),
            TestFrame::new(0x4000, 77)
        );
        assert!(!registry.contains(0x4000));
        assert_eq!(registry.available_slots(), 1);
        assert_eq!(
            registry.take_unpublished(0x4000),
            Err(FrameRegistryError::FrameNotFound)
        );
    }

    #[test]
    fn published_frames_remain_owned_and_cannot_be_released() {
        let mut registry = PageTableFrameRegistry::<TestFrame, 1>::new();
        let slot = registry.reserve_slot().unwrap();
        registry
            .install_reserved(slot, TestFrame::new(0x8000, 9))
            .unwrap();

        registry.mark_published(0x8000).unwrap();
        assert!(registry.contains(0x8000));
        assert!(!registry.contains_unpublished(0x8000));
        assert!(registry.contains_published_unowned(0x8000));
        assert_eq!(
            registry.take_unpublished(0x8000),
            Err(FrameRegistryError::PublishedFrame)
        );
        assert!(registry.contains(0x8000));
        assert_eq!(registry.available_slots(), 0);
    }

    #[test]
    fn duplicate_addresses_and_invalid_reservations_return_the_token() {
        let mut registry = PageTableFrameRegistry::<TestFrame, 2>::new();
        let slot = registry.reserve_slot().unwrap();
        registry
            .install_reserved(slot, TestFrame::new(0x9000, 10))
            .unwrap();
        let second = registry.reserve_slot().unwrap();

        let error = registry
            .install_reserved(second, TestFrame::new(0x9000, 11))
            .unwrap_err();
        assert_eq!(error.0, FrameRegistryError::DuplicateFrameAddress);
        assert_eq!(error.1, TestFrame::new(0x9000, 11));
        registry.cancel_reservation(second).unwrap();

        let error = registry
            .install_reserved(second, TestFrame::new(0xa000, 12))
            .unwrap_err();
        assert_eq!(error.0, FrameRegistryError::InvalidReservation);
        assert_eq!(error.1, TestFrame::new(0xa000, 12));
        assert!(registry.contains(0x9000));
        assert_eq!(registry.available_slots(), 1);
    }

    #[test]
    fn foreign_addresses_do_not_change_registry_state() {
        let mut registry = PageTableFrameRegistry::<TestFrame, 1>::new();
        let slot = registry.reserve_slot().unwrap();
        registry
            .install_reserved(slot, TestFrame::new(0xb000, 13))
            .unwrap();

        assert_eq!(
            registry.take_unpublished(0xc000),
            Err(FrameRegistryError::FrameNotFound)
        );
        assert_eq!(
            registry.mark_published(0xc000),
            Err(FrameRegistryError::FrameNotFound)
        );
        assert!(registry.contains(0xb000));
        assert_eq!(registry.available_slots(), 0);
    }

    #[test]
    #[allow(unsafe_code)]
    fn published_private_tables_can_only_be_taken_for_their_recorded_root() {
        let mut registry = PageTableFrameRegistry::<TestFrame, 1>::new();
        let slot = registry.reserve_slot().unwrap();
        registry
            .install_reserved(slot, TestFrame::new(0x8000, 91))
            .unwrap();

        assert_eq!(
            // SAFETY: the zero root is expected to be rejected before ownership changes.
            unsafe { registry.mark_published_for_root(0, 0x8000, 2) },
            Err(FrameRegistryError::InvalidOwnerRoot)
        );
        // SAFETY: this test models publication under one exclusive private root.
        unsafe { registry.mark_published_for_root(0x1000, 0x8000, 2) }.unwrap();
        assert!(registry.contains_published_for_root(0x1000, 0x8000));
        assert!(!registry.contains_published_unowned(0x8000));
        assert_eq!(registry.published_count_for_root(0x1000), Ok(1));
        assert!(!registry.contains_published_for_root(0x2000, 0x8000));
        assert!(!registry.contains_published_for_root(0, 0x8000));
        assert_eq!(
            // SAFETY: the registry must reject adopting a frame owned by a different root.
            unsafe { registry.mark_published_for_root(0x2000, 0x8000, 2) },
            Err(FrameRegistryError::PublishedOwnerMismatch)
        );
        assert_eq!(
            // SAFETY: the registry must reject changing the recorded paging level.
            unsafe { registry.mark_published_for_root(0x1000, 0x8000, 1) },
            Err(FrameRegistryError::PublishedOwnerMismatch)
        );
        assert_eq!(
            // SAFETY: a wrong-level release must be rejected before token removal.
            unsafe { registry.take_published_for_root(0x1000, 0x8000, 1) },
            Err(FrameRegistryError::PublishedOwnerMismatch)
        );
        assert_eq!(
            // SAFETY: correct owner/level alone is insufficient before detachment.
            unsafe { registry.take_published_for_root(0x1000, 0x8000, 2) },
            Err(FrameRegistryError::NotDetached)
        );
        assert!(registry.contains(0x8000));
        assert_eq!(
            registry.take_unpublished(0x8000),
            Err(FrameRegistryError::PublishedFrame)
        );

        // SAFETY: this unit test models the caller's external proof that the
        // frame has been detached and is unreachable before releasing the token.
        assert_eq!(
            registry.published_table_level_for_root(0x1000, 0x8000),
            Some(2)
        );
        assert_eq!(
            registry.published_table_level_for_root(0x2000, 0x8000),
            None
        );
        assert_eq!(
            // SAFETY: the test models the caller's proof that the table was detached.
            unsafe { registry.mark_published_table_detached_for_root(0x1000, 0x8000, 2) },
            Ok(())
        );
        assert_eq!(
            registry.detached_table_for_root(0x1000, 0),
            Some((0x8000, 2))
        );
        let frame = unsafe { registry.take_published_for_root(0x1000, 0x8000, 2) }.unwrap();
        assert_eq!(frame, TestFrame::new(0x8000, 91));
        assert!(!registry.contains(0x8000));
        assert_eq!(registry.published_count_for_root(0x1000), Ok(0));
        assert_eq!(registry.available_slots(), 1);
    }

    fn injected_free_frame_failure<T>(token: T) -> Result<(), ((), T)> {
        Err(((), token))
    }

    #[test]
    #[allow(unsafe_code)]
    fn detached_table_token_is_restored_after_injected_release_failure_and_can_be_retried() {
        let mut registry = PageTableFrameRegistry::<TestFrame, 1>::new();
        let slot = registry.reserve_slot().unwrap();
        registry
            .install_reserved(slot, TestFrame::new(0xA000, 93))
            .unwrap();
        // SAFETY: this test models publication beneath one exclusive root.
        unsafe { registry.mark_published_for_root(0x3000, 0xA000, 1) }.unwrap();
        // SAFETY: model the parent entry being cleared, the table verified
        // empty, and the target root being inactive.
        unsafe { registry.mark_published_table_detached_for_root(0x3000, 0xA000, 1) }.unwrap();

        // Inject the same fallible release contract used by free_frame().
        // The production registry transaction must restore the original token.
        let first = unsafe {
            registry.release_published_for_root_with(
                0x3000,
                0xA000,
                1,
                injected_free_frame_failure::<TestFrame>,
            )
        };
        assert!(matches!(
            first,
            Err(super::PublishedFrameReleaseError::Release(()))
        ));
        assert!(registry.contains(0xA000));
        assert_eq!(registry.published_count_for_root(0x3000), Ok(1));
        assert_eq!(
            registry.detached_table_for_root(0x3000, 0),
            Some((0xA000, 1))
        );
        assert_eq!(registry.available_slots(), 0);

        // A detached token still cannot be adopted or released using a different
        // root identity or paging level while the original root awaits retry.
        let wrong_root = unsafe {
            registry.release_published_for_root_with(
                0x5000,
                0xA000,
                1,
                injected_free_frame_failure::<TestFrame>,
            )
        };
        assert!(matches!(
            wrong_root,
            Err(super::PublishedFrameReleaseError::Registry(
                FrameRegistryError::PublishedOwnerMismatch
            ))
        ));
        let wrong_level = unsafe {
            registry.release_published_for_root_with(
                0x3000,
                0xA000,
                2,
                injected_free_frame_failure::<TestFrame>,
            )
        };
        assert!(matches!(
            wrong_level,
            Err(super::PublishedFrameReleaseError::Registry(
                FrameRegistryError::PublishedOwnerMismatch
            ))
        ));
        assert!(registry.contains(0xA000));
        assert_eq!(registry.published_count_for_root(0x3000), Ok(1));
        assert_eq!(
            registry.detached_table_for_root(0x3000, 0),
            Some((0xA000, 1))
        );
        assert_eq!(registry.available_slots(), 0);

        // Retry the same root-owned detached frame with a successful allocator.
        let second = unsafe {
            registry.release_published_for_root_with(0x3000, 0xA000, 1, |token| {
                assert_eq!(token, TestFrame::new(0xA000, 93));
                Ok::<(), ((), TestFrame)>(())
            })
        };
        assert!(second.is_ok());
        assert!(!registry.contains(0xA000));
        assert_eq!(registry.published_count_for_root(0x3000), Ok(0));
        assert_eq!(registry.available_slots(), 1);
    }

    #[test]
    #[allow(unsafe_code)]
    fn published_frames_without_root_ownership_cannot_be_adopted_or_released() {
        let mut registry = PageTableFrameRegistry::<TestFrame, 1>::new();
        let slot = registry.reserve_slot().unwrap();
        registry
            .install_reserved(slot, TestFrame::new(0x9000, 92))
            .unwrap();
        registry.mark_published(0x9000).unwrap();

        assert_eq!(
            // SAFETY: a generically published frame must not be adopted as private.
            unsafe { registry.mark_published_for_root(0x1000, 0x9000, 1) },
            Err(FrameRegistryError::PublishedOwnerMismatch)
        );
        assert_eq!(
            // SAFETY: no release proof is needed because the operation is
            // expected to reject the frame and leave registry ownership intact.
            unsafe { registry.take_published_for_root(0x1000, 0x9000, 1) },
            Err(FrameRegistryError::PublishedOwnerMismatch)
        );
        assert!(registry.contains(0x9000));
    }

    #[test]
    fn registry_capacity_is_reusable_after_cancellation_and_release() {
        let mut registry = PageTableFrameRegistry::<TestFrame, 1>::new();
        let slot = registry.reserve_slot().unwrap();
        assert_eq!(registry.reserve_slot(), None);
        registry.cancel_reservation(slot).unwrap();

        let slot = registry.reserve_slot().unwrap();
        registry
            .install_reserved(slot, TestFrame::new(0xd000, 14))
            .unwrap();
        registry.take_unpublished(0xd000).unwrap();

        assert_eq!(registry.available_slots(), 1);
        let reused = registry.reserve_slot().unwrap();
        assert_eq!(reused, slot);
    }
}
