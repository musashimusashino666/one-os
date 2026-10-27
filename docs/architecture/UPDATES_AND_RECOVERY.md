# Updates and Recovery Architecture

## Status

This is a target architecture, not an implemented update system.

## Required design

1. **Provenance:** updates identify the publisher, version, target platform, dependencies, and cryptographic integrity metadata.
2. **Authorization:** only an explicitly trusted update authority can authorize installation. Verification policy must be independent of untrusted package metadata.
3. **Atomicity:** interrupted installation must leave a known bootable state or enter a defined recovery path.
4. **Rollback control:** recovery may restore a known-good image, but must not silently permit downgrade to a version with a known security defect.
5. **Key lifecycle:** signing-key rotation, compromise response, recovery keys, and unavailable-key behavior must be specified.
6. **Auditability:** report the installed version, verification result, and recovery action without leaking secrets.
7. **User control:** updates explain consequences, preserve user data, and provide a predictable way to inspect and recover from failure.

## Acceptance requirements

Before a release claim, demonstrate valid-signature installation, invalid-signature rejection, tampered payload rejection, interrupted update recovery at each destructive phase, downgrade-policy enforcement, unavailable-network behavior, and data preservation. Failure injection must be reproducible.

## Current limitations

Authenticated boot, signed software updates, downgrade protection, persistent storage, data-at-rest encryption, and a production recovery workflow are not implemented. Do not imply otherwise in project status or marketing claims.
