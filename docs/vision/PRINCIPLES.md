# Design Principles

These principles are constraints on architecture, code, interface behavior, and project
claims. They are intended to resolve design disagreements consistently.

The long-term definition and target design—including the seven quality dimensions and
the PC, mobile, server, and embedded/edge scope—are specified in
[World-Class OS: Definition and Design](WORLD_CLASS_OS.md).
This document
supplies the normative principles that constrain implementation; it does not change the
status of any feature.

## P1. Least authority by default

Every component begins with no authority beyond what is required to start. Additional
access is granted explicitly, scoped to a resource and operation, and revocable.
Security-critical checks MUST be enforced by a trusted component, not only by
application libraries or UI conventions.

## P2. The kernel is the enforcement boundary

A capability type, permission dialog, manifest, or service policy is not a security
boundary unless a kernel-controlled operation validates it. Authority provenance must
not be forgeable by an untrusted caller. Invalid, stale, malformed, or ambiguous
authority fails closed.

## P3. Small trusted computing base

Privileged code MUST be minimized and its responsibilities documented. Drivers,
filesystems, network services, UI, and policy engines SHOULD run outside the kernel
where the required isolation model permits. Any exception requires a documented threat
and engineering rationale.

## P4. Memory safety and explicit unsafe contracts

Use memory-safe language and abstractions where practical. Every unsafe boundary MUST
state preconditions, ownership, lifetime, synchronization assumptions, and failure
behavior. Tests should target violated preconditions, not only happy paths.

## P5. Deny executable publication until the full contract exists

Executable permissions require physical-alias accounting, validated transitions, and
correct TLB invalidation. A clean partial audit is not proof of global W^X. Unsupported
mapping states and incomplete inventories MUST not be reported as success.

## P6. Ownership before mutation; quiescence before reuse

Memory and resource ownership must be explicit. For page-table changes, reservation,
publication, invalidation, detachment, and reclamation are distinct phases. A frame MUST
NOT be reused while any active root, hardware walk, or stale translation could still
reference it.

## P7. Failure must be bounded and recoverable

Capacity exhaustion, malformed input, failed allocation, interrupted transitions, and
incomplete audits must have defined outcomes. Do not silently truncate security-relevant
inventories. Where rollback cannot restore a known-safe state, fail-stop while retaining
ownership rather than continue with uncertain state.

## P8. Evidence defines completion

A feature is complete only when its acceptance criteria pass on the exact candidate
revision. Host tests, compilation, smoke tests, and hardware-level integration prove
different things and must be described separately. Claims MUST match the tested scope.

## P9. User agency is a system property

Data access, networking, background execution, device access, and AI actions SHOULD be
discoverable, scoped, and revocable. Consent must be specific to the action and context;
a single broad approval must not become unbounded future authority.

## P10. Compatibility is explicit

Native, sandboxed, virtualized, and compatibility execution paths have different
security and performance properties. Each path must declare its boundary and
limitations; compatibility MUST NOT silently bypass the permission model.

## P11. Recoverability is designed in

Updates, configuration changes, storage transitions, and key management need a recovery
story before they are treated as production-ready. Rollback policy must account for
downgrade attacks and known-vulnerable versions.

## P12. Prefer simple, auditable mechanisms

Prefer small mechanisms with explicit invariants over flexible abstractions that are
difficult to reason about. Complexity is justified only when it produces a measurable
benefit that cannot be achieved more simply.

## Applying the principles

When a change conflicts with a principle, the author must either change the design or
add an ADR that explains the conflict, threat-model impact, alternatives considered,
tests required, and conditions for revisiting the exception. An ADR records a decision;
it does not waive a security acceptance test.
