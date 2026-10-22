#![no_std]
#![forbid(unsafe_code)]

//! Small, testable security primitives for ONE OS.
//!
//! This crate models authorization decisions. It does not enforce access at a
//! hardware or process boundary by itself; the kernel must implement that
//! enforcement before these types can be relied on for system security.

/// Stable identifier for a resource managed by an authority.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ObjectId(u64);

impl ObjectId {
    /// Creates an identifier for a resource.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the numeric identifier.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Rights which can be granted over a resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rights(u8);

impl Rights {
    const ALL_BITS: u8 = Self::READ.0 | Self::WRITE.0 | Self::EXECUTE.0;

    /// Read a resource.
    pub const READ: Self = Self(1 << 0);
    /// Modify a resource.
    pub const WRITE: Self = Self(1 << 1);
    /// Execute a resource.
    pub const EXECUTE: Self = Self(1 << 2);
    /// No permissions.
    pub const NONE: Self = Self(0);

    /// Creates rights from a bit field, rejecting unknown bits.
    pub const fn from_bits(bits: u8) -> Option<Self> {
        if bits & !Self::ALL_BITS == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    /// Returns the underlying permission bits.
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Returns true when no rights are set.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns true when every right in the other set is present.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Returns the union of two sets of rights.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// An authorization token.
///
/// Fields are private so callers cannot create arbitrary capabilities through
/// safe Rust. A future kernel must still validate tokens at protected
/// operations and must not trust user-provided memory as a token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capability {
    object: ObjectId,
    rights: Rights,
    generation: u64,
}

impl Capability {
    /// The object this capability refers to.
    pub const fn object(self) -> ObjectId {
        self.object
    }

    /// Rights carried by this capability.
    pub const fn rights(self) -> Rights {
        self.rights
    }
}

/// The reason an authorization request was denied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessError {
    /// A capability cannot be issued with no permissions.
    EmptyRights,
    /// The authority's generation counter can no longer advance safely.
    AuthorityExhausted,
    /// The capability belongs to an earlier generation and was revoked.
    Revoked,
    /// The capability is for a different object.
    WrongObject,
    /// The capability does not contain all requested permissions.
    InsufficientRights,
}

/// Issues and checks capabilities within one revocation domain.
///
/// revoke_all invalidates every capability issued by this authority. This
/// simple generation scheme is intentionally coarse-grained; per-object
/// revocation and delegation can be considered after kernel enforcement exists.
#[derive(Debug)]
pub struct Authority {
    generation: u64,
    exhausted: bool,
}

impl Authority {
    /// Creates a new authority.
    pub const fn new() -> Self {
        Self {
            generation: 1,
            exhausted: false,
        }
    }

    /// Issues a capability for an object with exactly the supplied rights.
    pub fn grant(
        &self,
        object: ObjectId,
        rights: Rights,
    ) -> Result<Capability, AccessError> {
        if self.exhausted {
            return Err(AccessError::AuthorityExhausted);
        }
        if rights.is_empty() {
            return Err(AccessError::EmptyRights);
        }

        Ok(Capability {
            object,
            rights,
            generation: self.generation,
        })
    }

    /// Checks that a capability is current and authorizes the requested action.
    pub fn authorize(
        &self,
        capability: &Capability,
        object: ObjectId,
        required: Rights,
    ) -> Result<(), AccessError> {
        if self.exhausted {
            return Err(AccessError::AuthorityExhausted);
        }
        if capability.generation != self.generation {
            return Err(AccessError::Revoked);
        }
        if capability.object != object {
            return Err(AccessError::WrongObject);
        }
        if required.is_empty() || !capability.rights.contains(required) {
            return Err(AccessError::InsufficientRights);
        }

        Ok(())
    }

    /// Invalidates all currently issued capabilities.
    ///
    /// If the generation counter is exhausted, the authority fails closed:
    /// it can neither issue nor validate any capability.
    pub fn revoke_all(&mut self) {
        match self.generation.checked_add(1) {
            Some(next) => self.generation = next,
            None => self.exhausted = true,
        }
    }
}

impl Default for Authority {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{AccessError, Authority, ObjectId, Rights};

    const FILE: ObjectId = ObjectId::new(7);
    const OTHER_FILE: ObjectId = ObjectId::new(8);

    #[test]
    fn grants_and_authorizes_requested_right() {
        let authority = Authority::new();
        let capability = authority.grant(FILE, Rights::READ).unwrap();

        assert_eq!(authority.authorize(&capability, FILE, Rights::READ), Ok(()));
    }

    #[test]
    fn denies_rights_not_granted() {
        let authority = Authority::new();
        let capability = authority.grant(FILE, Rights::READ).unwrap();

        assert_eq!(
            authority.authorize(&capability, FILE, Rights::WRITE),
            Err(AccessError::InsufficientRights)
        );
    }

    #[test]
    fn denies_access_to_another_object() {
        let authority = Authority::new();
        let capability = authority.grant(FILE, Rights::READ).unwrap();

        assert_eq!(
            authority.authorize(&capability, OTHER_FILE, Rights::READ),
            Err(AccessError::WrongObject)
        );
    }

    #[test]
    fn denies_empty_grants_and_empty_requests() {
        let authority = Authority::new();

        assert_eq!(
            authority.grant(FILE, Rights::NONE),
            Err(AccessError::EmptyRights)
        );

        let capability = authority.grant(FILE, Rights::READ).unwrap();
        assert_eq!(
            authority.authorize(&capability, FILE, Rights::NONE),
            Err(AccessError::InsufficientRights)
        );
    }

    #[test]
    fn revocation_invalidates_existing_capabilities() {
        let mut authority = Authority::new();
        let capability = authority.grant(FILE, Rights::READ).unwrap();

        authority.revoke_all();

        assert_eq!(
            authority.authorize(&capability, FILE, Rights::READ),
            Err(AccessError::Revoked)
        );
    }

    #[test]
    fn rejects_unknown_rights_bits() {
        assert_eq!(Rights::from_bits(0b1000_0000), None);
        assert_eq!(Rights::from_bits(Rights::READ.bits()), Some(Rights::READ));
    }

    #[test]
    fn supports_combined_rights() {
        let authority = Authority::new();
        let rights = Rights::READ.union(Rights::WRITE);
        let capability = authority.grant(FILE, rights).unwrap();

        assert_eq!(
            authority.authorize(&capability, FILE, Rights::READ.union(Rights::WRITE)),
            Ok(())
        );
    }
}
