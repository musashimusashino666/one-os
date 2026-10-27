# Security Model

## Security objective

ONE OS aims to protect confidentiality, integrity, and availability of user data and system state through small privileged code, kernel-enforced authority, isolated components, verified updates, and predictable recovery.

These are design goals. The current bootstrap does not yet implement the complete security model.

## Assets

- User documents, credentials, secrets, and cryptographic keys.
- Process memory, service state, and IPC messages.
- Kernel code, page tables, physical-frame ownership, and boot artifacts.
- System configuration, update metadata, and recovery state.
- Permission grants, activity records, and user-defined policy.

## Threats to address

The target model includes malicious or compromised applications and services, malformed input, cross-process access attempts, confused-deputy behavior, stale or forged capabilities, update interruption, rollback to vulnerable software, and unauthorized access to devices or network resources.

Initially out of scope: physical possession attacks, compromised firmware, malicious hardware, and comprehensive side-channel resistance. Those exclusions must be revisited before high-assurance claims.

## Trust boundaries

1. **Boot chain to kernel:** validate inputs and CPU preconditions; future releases need authenticated boot provenance.
2. **Kernel to user process:** enforce address-space isolation and validated entry/return; this boundary is not yet complete.
3. **Process to process:** enforce resource access through kernel-controlled capabilities and IPC contracts; currently incomplete.
4. **Service to device/network/storage:** mediate access through explicit rights and constrained interfaces; not yet implemented.
5. **Application/AI client to user authority:** delegated actions must be scoped and visible. A model or UI must not be able to mint kernel authority.
6. **Update system to running system:** verify provenance, preserve recoverability, and prevent unauthorized downgrade; not yet implemented.

## Required properties

- **Default deny:** missing, stale, malformed, or unrecognized authority is rejected.
- **Kernel enforcement:** authorization is checked at the protected operation, not only at API construction or user-interface time.
- **Isolation:** one process cannot read or modify another process's private state without an explicit permitted transfer.
- **Memory protection:** writable and executable aliases for a physical frame must not coexist where the platform contract forbids it. Partial audit coverage must be reported as incomplete.
- **Safe lifetime:** page-table roots and data frames are not reused before all relevant mappings and translations are quiescent.
- **Fail-closed audit:** capacity exhaustion, unknown roots, malformed entries, and unsupported mappings cannot produce a clean success result.
- **Revocation:** authority revocation has defined effects on in-flight work, cached rights, and associated mappings.
- **Recoverability:** failure and rollback do not silently expose secrets or downgrade security.

## Current controls and limits

The kernel currently has selected boot-mapping validation, a fixed-capacity physical-frame allocator, guarded page-table mutation, a read-only W^X audit over declared scope, and QEMU checks for selected supervisor protection, NX, TLB transitions, and direct-map permission changes. The guest test profile is single-vCPU QEMU.

Executable aliases derived from validated kernel ELF PT_LOAD pages are transitioned to read-only/NX in the physical-memory-offset mapping; audit runs have checks for zero conflicts in a declared scope. This does **not** establish global frame-wide W^X across every possible alias, root, future mapping, or unregistered mapping. Arbitrary executable mapping publication remains gated. See open Issues [#26](https://github.com/musashimusashino666/one-os/issues/26) and [#46](https://github.com/musashimusashino666/one-os/issues/46).

The current capability model is host-testable reference logic. Kernel-enforced capabilities, Ring 3 entry/return, complete process isolation, SMP synchronization, authenticated boot, signed updates, data-at-rest encryption, and a production recovery system are not implemented.

## Security claim standard

Every security statement must state:

- Protected asset and threat addressed.
- Enforcement mechanism and trusted components.
- Scope of roots, mappings, devices, or operations covered.
- Platform assumptions and synchronization model.
- Positive and negative test evidence on a specific revision.
- Known exclusions and outstanding issues.

A successful build, CI run, audit summary, or QEMU smoke test proves only the behavior covered by that test. It does not constitute certification or general proof of security.
