# Process Isolation and Capability Specification

## Purpose

This document defines the intended security boundary for user processes and the
requirements that must hold before ONE OS may claim process isolation. The requirements
below are target contracts; they are not a statement that the full boundary exists
today.

## Process isolation

Each process must have an independently controlled address space. A process MUST NOT
read or modify another process's private memory, kernel page tables, privileged kernel
mappings, or resource state except through an explicitly authorized interface.

The kernel must validate the entire user virtual range, access mode, owner address
space, and physical-frame ownership for every protected mapping or copy. User-provided
pointers and handles are data, not proof of authority.

## User-mode entry and return

Before user execution is enabled, the kernel must validate:

- User and kernel code/data selectors and privilege levels.
- User instruction pointer and user stack ranges.
- Kernel entry stack and transition state.
- Register state and return frame.
- Exception and fault recovery behavior.
- The active address-space root and its mapping invariants.

Tests must demonstrate rejection of malformed entry state and controlled recovery from
user faults. A CPL 0 test that switches roots is not a Ring 3 test.

## Capability semantics

A capability represents authority over a defined resource and set of operations. A
usable capability design must specify:

- Resource identity and ownership.
- Explicit rights and whether rights can be attenuated.
- Authority provenance and who may delegate it.
- Lifetime, revocation, stale-handle behavior, and transfer semantics.
- Validation points at every protected operation.
- Error behavior for missing, malformed, forged, or revoked authority.

Capability identifiers that are process-local must not be accepted as globally unique
proof of identity. Authority imported from untrusted processes requires a
kernel-controlled transfer or verification protocol.

The current oneos-core capability types are a host-testable reference authorization
model. They are not a hardware or process enforcement boundary.

## Service compromise and confused-deputy resistance

The kernel is the mandatory reference monitor for protected operations. A policy service
may recommend allow/deny, present the owner's request, or broker IPC, but its own
assertion cannot authorize an operation. For every protected operation, the kernel MUST
validate kernel-owned authority state, the authenticated calling principal, the
resource, the requested right, the grant's scope/lifetime, and its revocation state.

Services MUST NOT be able to mint new authority, widen a received capability,
impersonate another principal by supplying an identity field, or turn the kernel into a
confused deputy. Delegation can only attenuate an existing valid grant unless a new
grant is established through the documented owner-authorized path. Restarted services
and local caches are not authoritative for revocation or grant validity.

This contract contains a compromised service to the rights actually delegated to it; it
does not claim that a compromised service will behave correctly within its own scope.
Its capabilities must therefore be narrow, attributable, and revocable. If a service is
designed to issue unrestricted grants or bypass kernel authorization, it is part of the
enforcement TCB and violates the target architecture described
in the [Security Model](../architecture/SECURITY_MODEL.md).

### Required adversarial acceptance tests

The real kernel protected-operation path (not a host-only model) MUST demonstrate:

- A malicious broker/service without a capability is denied cross-process reads/writes
  and protected resource operations.
- Forged, foreign, stale, revoked, or widened capabilities are rejected, including
  attempts to add rights or extend lifetime/scope.
- A broker cannot impersonate a caller or confuse the kernel by supplying a different
  principal/object identity in request data.
- A delegated capability permits only the granted resource and operations; further
  delegation is limited to an attenuated subset.
- Revocation prevents subsequent protected operations even if a service retains a copied
  handle, cached allow decision, or pre-restart state.
- A compromised broker cannot bypass a kernel denial by asking another service to act as
  a deputy without independently valid authority.
- A service restart, crash, or missing policy state fails closed for protected
  operations; it never restores authority from an untrusted cache.
- Valid in-scope requests still follow the documented policy, and audit attribution
  identifies both the caller and the service exercising its own authority.

Each negative case MUST assert an explicit denial/fault result and verify no protected
state was changed. Record candidate SHA, test profile, exact case/marker, and logs. The
service-compromise guarantee remains unverified until these tests pass in the integrated
kernel path.

## IPC and resource transfer

Before IPC is considered secure, its contract must define message framing, length
limits, caller identity, authority transfer, resource ownership, cancellation, timeout
semantics, errors, and behavior during process death. Malformed and oversized messages
must fail without corrupting ownership state or disclosing unrelated memory.

A service API or UI permission prompt does not enforce these rules by itself.

## Address-space lifecycle

A root must have distinct states such as initialized/inactive and hardware-active. A
root or frame MUST NOT be reclaimed while active or while stale translations may still
reference it.

Teardown must preflight the private page-table tree and registry ownership before
destructive changes, remove mappings, complete the required invalidation/switch
contract, zero user-data frames before allocator reuse, reclaim private tables in a safe
order, and preserve pending ownership after partial failure. A partially failed teardown
must not release the root or lose frame tokens.

## Current implementation status

The kernel has host-testable primitives for mapping and ownership transitions.
Kernel-created roots, selected CPL 0 switching and inactive-root teardown scenarios,
zero-before-publication initialization, and related failure paths have QEMU smoke
coverage. This does not establish independent Ring 3 execution, end-to-end process
isolation, kernel-enforced capability checks, production IPC, a scheduler, or SMP
safety.

Track the remaining work in
[Issue #23](https://github.com/musashimusashino666/one-os/issues/23),
[Issue #24](https://github.com/musashimusashino666/one-os/issues/24), and
[Issue #25](https://github.com/musashimusashino666/one-os/issues/25).

## Required adversarial tests

- Cross-process read and write attempts against private frames.
- Forged, stale, attenuated, transferred, and revoked capabilities.
- Invalid user pointers, canonical-address boundaries, and partial-range overflow.
- Invalid selectors, registers, stack, instruction pointer, and return frame.
- Stale TLB mappings and frame reuse after unmap or teardown.
- Allocation, registry-capacity, and mapping-publication failures.
- Process exit during IPC and resource transfer.
- Compromised broker/service attempts to forge, widen, replay, or use revoked authority
  and to act as a confused deputy (see the service-compromise acceptance contract
  above).
- No user-visible mapping before initialization and ownership validation succeed.

The isolation milestone is incomplete until the relevant tests execute through the real
kernel enforcement path and fail closed on the exact reviewed revision.
