# ONE OS Vision

## Product definition

The canonical product definition, quality dimensions, and target platform scope are
maintained in [World-Class OS](WORLD_CLASS_OS.md).
This Vision explains the user problem and the assumptions that must
be validated.

## Product thesis

People should not need to grant software broad, invisible, or permanent authority simply
to use a computer. The operating system should make important authority boundaries
enforceable, understandable, observable, and revocable. A buggy or compromised
non-kernel service must not gain authority beyond its explicit grants or cross into
unrelated protected components. This guarantee is about containment: a compromised
service may still misuse the rights explicitly delegated to it and may deny service, so
grants must be narrow, attributable, revocable, and tested. An ordinary service or
broker must never be an unchecked alternative to kernel enforcement. Update interruption
and automation/AI actions must remain subject to the same rules.

ONE OS treats security, owner control, recoverability, usability, and compatibility as
one system-design problem. A permission screen without enforcement is not a security
boundary; a secure mechanism that users cannot understand or operate is not a complete
product; and a recovery plan that can silently reinstall a vulnerable version is not a
safe recovery plan.

## Intended users and initial validation cohort

- **Long-term product audience:** people and organizations using PCs and workstations,
  smartphones and mobile devices, servers, and embedded/edge devices who need dependable
  control over software, data, devices, networks, and background activity.
- **Initial validation cohort:** technically capable individual users, independent
  developers, and researchers who value inspectability and can help expose flaws in the
  authority, isolation, and recovery model. The initial cohort is deliberately narrower
  than the long-term four-domain platform scope.
- **Product assumption to validate:** a coherent combination of enforceable least
  authority, clear owner controls, and tested recovery is valuable enough to justify any
  compatibility, setup, or performance trade-offs. User research and comparison against
  established alternatives must test this assumption; it must not be treated as fact.

The initial cohort is a development and validation choice, not a statement that the
eventual system should remain expert-only. User-facing controls must be understandable
without requiring users to reason about page tables, capabilities, or kernel internals.

## The core jobs ONE OS must do well

A mature ONE OS should let its owner:

1. **Run software with bounded authority.** A program receives only the resources and
   operations it needs. Enforcement occurs at a trusted boundary and is not bypassable
   by relying on a UI, manifest, or library convention.
2. **Understand and change access.** The owner can determine which program or service
   has access to a resource, what it can do, and how to revoke that access. Revocation
   semantics, including queued and background work, are explicit.
3. **Inspect consequential activity.** Access to sensitive resources, network use,
   device activity, and delegated automation are discoverable in proportion to their
   risk, without an unbounded or misleading audit log.
4. **Survive failure without surrendering control.** Crashes, allocation failures,
   interrupted updates, and connectivity loss lead to documented, testable states. Data
   integrity and recovery take priority over silently continuing in an uncertain state.
5. **Choose a suitable software path.** Native, sandboxed, virtualized, and
   compatibility paths disclose their security and performance properties. Compatibility
   is never allowed to silently bypass the authority model.
6. **Use automation and AI under the same rules.** Delegated actions are scoped,
   attributable, limited in time or purpose where appropriate, inspectable, and
   revocable. AI is not a privileged exception to the security model.

## Strategic differentiation hypotheses

ONE OS will investigate four linked bets. They are hypotheses to validate, not claims of
uniqueness or superiority over existing operating systems.

### End-to-end authority lifecycle

**Intended distinction:** Grant, enforce, inspect, attenuate, and revoke authority
through one coherent model.

**Evidence required:** Adversarial tests for unauthorized access, forged/stale grants,
and revocation; user studies showing owners can correctly predict and change access.

### Automation is not exempt

**Intended distinction:** AI and background agents use the same bounded authority model
as other software.

**Evidence required:** Tests showing delegated actions cannot exceed scope and
revocation prevents subsequent protected operations; usability and comprehension
studies.

### Recovery is a first-class security property

**Intended distinction:** Updates and critical transitions have provenance, interruption
handling, anti-rollback policy, and a known-safe recovery path.

**Evidence required:** Failure-injection results across update transitions, integrity
checks, and tests against downgrade to known-vulnerable versions.

### Guarantees are bounded and inspectable

**Intended distinction:** Each security, privacy, compatibility, and performance claim
names its scope, assumptions, exclusions, and reproducible evidence.

**Evidence required:** Traceability from requirement to test/report, reproducible
evaluation, and review of claims against actual evidence.

No hypothesis is validated by documentation alone. Comparative work must name the
alternative systems, workload, hardware, configuration, and method. ONE OS must not
imply that competitors lack a capability merely because the project intends to implement
it differently.

## Design constraints

The normative implementation constraints are maintained in
[Principles](PRINCIPLES.md). The product definition is in
[World-Class OS](WORLD_CLASS_OS.md), and measurable acceptance and
release gates are in [Success Criteria](SUCCESS_CRITERIA.md).

## Non-goals and rejected shortcuts

The following are not valid shortcuts to the product goal:

- Claiming current production readiness, security certification, universal
  compatibility, zero vulnerabilities, perfect privacy, or superior performance without
  evidence.
- Treating Rust, a sandbox label, a capability data type, a permission dialog, or one
  passing QEMU test as proof of a complete security boundary.
- Optimizing one benchmark before its workload and baseline are representative and
  reproducible.
- Putting every driver, filesystem, service, UI, and policy engine into the kernel just
  to simplify early integration.
- Granting broad ambient authority to preserve compatibility without making the boundary
  and trade-off explicit.
- Giving AI or background services implicit or unrevocable privilege.
- Starting with SMP, unrestricted executable mappings, or general untrusted user
  execution before their authority, synchronization, and lifetime contracts have
  adversarial acceptance tests.

The early project is not yet a drop-in desktop replacement, mobile OS, real-time OS, or
universal application-compatibility layer. These are scope boundaries for sequencing,
not permanent prohibitions; any expansion requires explicit product rationale and
testable acceptance criteria.

## Decision rule

When goals conflict, prioritize in this order unless an Architecture Decision Record
(ADR) explains and justifies an exception:

1. Prevent unauthorized access and preserve integrity.
2. Preserve recoverability and ownership of data/resources.
3. Keep authority explicit, bounded, observable, and revocable.
4. Keep the trusted computing base and critical paths understandable.
5. Preserve usability, accessibility, and practical portability within those gates.
6. Optimize performance using representative measurements.

A performance or compatibility trade-off must be documented and measured, not assumed.
An ADR records the rationale; it does not waive a required acceptance test.

## Current project boundary

The current implementation is a bootstrap-stage x86_64 Rust research kernel centered on
BIOS/QEMU validation. The project has selected memory-management and protection paths,
but does not yet provide complete Ring 3 process isolation, kernel-enforced process
capabilities, a usable integrated system, authenticated boot, signed updates, or
resilient recovery. Current implementation limits are recorded in
[Implementation Status](../project/IMPLEMENTATION_STATUS.md), and the ordered
technical dependencies are recorded in the [Roadmap](../project/ROADMAP.md).

## How progress is judged

The [Success Criteria](SUCCESS_CRITERIA.md) define required evidence
and release gates. The [Design Principles](PRINCIPLES.md) constrain implementation
decisions. The [Implementation Status](../project/IMPLEMENTATION_STATUS.md)
states what has actually been demonstrated. These sources must remain
aligned: an aspiration is not a specification, a specification is not an implementation,
and an implementation is not verified until the required evidence passes on the exact
candidate.
