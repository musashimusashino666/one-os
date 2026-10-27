# Process Isolation and Capability Specification

## Purpose

This document defines the intended security boundary for user processes and the requirements that must hold before ONE OS may claim process isolation. The requirements below are target contracts; they are not a statement that the full boundary exists today.

## Process isolation

Each process must have an independently controlled address space. A process MUST NOT read or modify another process's private memory, kernel page tables, privileged kernel mappings, or resource state except through an explicitly authorized interface.

The kernel must validate the entire user virtual range, access mode, owner address space, and physical-frame ownership for every protected mapping or copy. User-provided pointers and handles are data, not proof of authority.

## User-mode entry and return

Before user execution is enabled, the kernel must validate:

- User and kernel code/data selectors and privilege levels.
- User instruction pointer and user stack ranges.
- Kernel entry stack and transition state.
- Register state and return frame.
- Exception and fault recovery behavior.
- The active address-space root and its mapping invariants.

Tests must demonstrate rejection of malformed entry state and controlled recovery from user faults. A CPL 0 test that switches roots is not a Ring 3 test.

## Capability semantics

A capability represents authority over a defined resource and set of operations. A usable capability design must specify:

- Resource identity and ownership.
- Explicit rights and whether rights can be attenuated.
- Authority provenance and who may delegate it.
- Lifetime, revocation, stale-handle behavior, and transfer semantics.
- Validation points at every protected operation.
- Error behavior for missing, malformed, forged, or revoked authority.

Capability identifiers that are process-local must not be accepted as globally unique proof of identity. Authority imported from untrusted processes requires a kernel-controlled transfer or verification protocol.

The current oneos-core capability types are a host-testable reference authorization model. They are not a hardware or process enforcement boundary.

## IPC and resource transfer

Before IPC is considered secure, its contract must define message framing, length limits, caller identity, authority transfer, resource ownership, cancellation, timeout semantics, errors, and behavior during process death. Malformed and oversized messages must fail without corrupting ownership state or disclosing unrelated memory.

A service API or UI permission prompt does not enforce these rules by itself.

## Address-space lifecycle

A root must have distinct states such as initialized/inactive and hardware-active. A root or frame MUST NOT be reclaimed while active or while stale translations may still reference it.

Teardown must preflight the private page-table tree and registry ownership before destructive changes, remove mappings, complete the required invalidation/switch contract, zero user-data frames before allocator reuse, reclaim private tables in a safe order, and preserve pending ownership after partial failure. A partially failed teardown must not release the root or lose frame tokens.

## Current implementation status

The kernel has host-testable primitives for mapping and ownership transitions. Kernel-created roots, selected CPL 0 switching and inactive-root teardown scenarios, zero-before-publication initialization, and related failure paths have QEMU smoke coverage. This does not establish independent Ring 3 execution, end-to-end process isolation, kernel-enforced capability checks, production IPC, a scheduler, or SMP safety.

Track the remaining work in [Issue #23](https://github.com/musashimusashino666/one-os/issues/23), [Issue #24](https://github.com/musashimusashino666/one-os/issues/24), and [Issue #25](https://github.com/musashimusashino666/one-os/issues/25).

## Required adversarial tests

- Cross-process read and write attempts against private frames.
- Forged, stale, attenuated, transferred, and revoked capabilities.
- Invalid user pointers, canonical-address boundaries, and partial-range overflow.
- Invalid selectors, registers, stack, instruction pointer, and return frame.
- Stale TLB mappings and frame reuse after unmap or teardown.
- Allocation, registry-capacity, and mapping-publication failures.
- Process exit during IPC and resource transfer.
- No user-visible mapping before initialization and ownership validation succeed.

The isolation milestone is incomplete until the relevant tests execute through the real kernel enforcement path and fail closed on the exact reviewed revision.
