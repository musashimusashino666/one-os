# ADR-0001: Keep Executable Mapping Publication Fail-Closed

- **Status:** Accepted
- **Date:** 2026-10-27
- **Scope:** kernel page-table permissions and physical-frame aliases

## Context

A leaf mapping that is non-writable and executable does not by itself establish W^X. The same physical frame may remain writable through a direct-map, recursive, inherited, or other address-space alias. Large-page leaves can overlap a smaller range, and effective rights depend on ancestor entries. A bounded audit can miss mappings if its root inventory or mapping-source inventory is incomplete.

## Decision

ONE OS keeps arbitrary executable mapping publication restricted until the full alias inventory and permission-transition contract are demonstrated for the declared platform. Validated executable kernel PT_LOAD pages may be transitioned through the narrowly scoped boot path, but a successful bounded audit is not treated as a global W^X guarantee.

Any future relaxation must establish:
- Complete, explicitly sealed inventory of every activatable root and relevant mapping source.
- Effective permission calculation through every ancestor entry.
- Physical extent overlap detection across every supported page size.
- Direct-map, recursive-table, inherited, and managed aliases.
- Transactional W-to-X/X-to-W transitions with correct local or remote TLB handling for the supported execution model.
- Fail-closed behavior for missing roots, malformed entries, capacity exhaustion, and unsupported structures.
- Adversarial tests on the exact candidate revision.

## Consequences

This decision restricts functionality while correctness work is incomplete. It also makes the gap explicit and testable. Executable mapping convenience is not a reason to weaken the memory-safety boundary.

## Revisit when

Issue #26 and Issue #46 acceptance criteria pass and the current Issue #49 state is reconciled against merged work. Record the evidence and any remaining platform limits before changing this decision.
