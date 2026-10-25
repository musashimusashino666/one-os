//! Fixed-capacity ownership registry for page-table frames.
//!
//! The registry reserves metadata capacity before a physical frame is allocated,
//! retains the non-Copy token until the frame is released, and refuses to release
//! a published page-table frame. Synchronization is the caller's responsibility.

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
    /// The frame is published for a different root or has no recorded private owner.
    PublishedOwnerMismatch,
    /// The frame is not currently published.
    NotPublished,
}

/// Fixed-capacity storage for reserved and owned page-table frame tokens.
///
/// A reservation consumes metadata capacity before allocation. install_reserved
/// transfers a non-Copy ownership token into the slot. Published frames remain
/// owned, but cannot be released through take_unpublished.
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
    /// Calling this repeatedly for the same (root, frame) is idempotent. A frame
    /// already published without an owner, or owned by another root, is rejected
    /// instead of being silently adopted.
    ///
    /// # Safety
    ///
    /// The caller must have established that the frame is an exclusively owned,
    /// allocator-issued page-table frame and is being published only beneath the
    /// supplied root's private lower-half mapping tree. The frame must not be
    /// shared with another root or reachable through an unrelated page-table
    /// tree. The registry records this assertion; it does not verify reachability.
    #[allow(unsafe_code)]
    pub unsafe fn mark_published_for_root(
        &mut self,
        root_physical: u64,
        physical_address: u64,
    ) -> Result<(), FrameRegistryError> {
        if root_physical == 0 || root_physical & (crate::PAGE_SIZE - 1) != 0 {
            return Err(FrameRegistryError::InvalidOwnerRoot);
        }

        for slot in &mut self.slots {
            if let FrameSlot::Owned {
                token,
                published,
                owner_root_physical,
            } = slot
            {
                if token.frame_address() != physical_address {
                    continue;
                }

                if *published {
                    return if *owner_root_physical == Some(root_physical) {
                        Ok(())
                    } else {
                        Err(FrameRegistryError::PublishedOwnerMismatch)
                    };
                }

                *published = true;
                *owner_root_physical = Some(root_physical);
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
                } if token.frame_address() == physical_address && *owner == root_physical
            )
        })
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
    ) -> Result<T, FrameRegistryError> {
        if root_physical == 0 || root_physical & (crate::PAGE_SIZE - 1) != 0 {
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
                ..
            } if *owner == root_physical => {}
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
            } if owner == root_physical => Ok(token),
            other => {
                // Restore unexpected state rather than dropping a non-Copy
                // ownership token on an invariant failure.
                self.slots[index] = other;
                Err(FrameRegistryError::PublishedOwnerMismatch)
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
            unsafe { registry.mark_published_for_root(0, 0x8000) },
            Err(FrameRegistryError::InvalidOwnerRoot)
        );
        // SAFETY: this test models publication under one exclusive private root.
        unsafe { registry.mark_published_for_root(0x1000, 0x8000) }.unwrap();
        assert!(registry.contains_published_for_root(0x1000, 0x8000));
        assert_eq!(registry.published_count_for_root(0x1000), Ok(1));
        assert!(!registry.contains_published_for_root(0x2000, 0x8000));
        assert!(!registry.contains_published_for_root(0, 0x8000));
        assert_eq!(
            // SAFETY: the registry must reject adopting a frame owned by a different root.
            unsafe { registry.mark_published_for_root(0x2000, 0x8000) },
            Err(FrameRegistryError::PublishedOwnerMismatch)
        );
        assert_eq!(
            registry.take_unpublished(0x8000),
            Err(FrameRegistryError::PublishedFrame)
        );

        // SAFETY: this unit test models the caller's external proof that the
        // frame has been detached and is unreachable before releasing the token.
        let frame = unsafe { registry.take_published_for_root(0x1000, 0x8000) }.unwrap();
        assert_eq!(frame, TestFrame::new(0x8000, 91));
        assert!(!registry.contains(0x8000));
        assert_eq!(registry.published_count_for_root(0x1000), Ok(0));
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
            unsafe { registry.mark_published_for_root(0x1000, 0x9000) },
            Err(FrameRegistryError::PublishedOwnerMismatch)
        );
        assert_eq!(
            // SAFETY: no release proof is needed because the operation is
            // expected to reject the frame and leave registry ownership intact.
            unsafe { registry.take_published_for_root(0x1000, 0x9000) },
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
