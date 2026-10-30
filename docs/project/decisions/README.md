# Architecture Decision Records

This directory records durable decisions about architecture,
security boundaries, and long-lived system contracts.

## Accepted decisions

- [ADR-0001](ADR-0001-executable-publication.md)
  Executable mapping publication remains fail-closed.
- [ADR-0002](ADR-0002-single-cpu-paging-contract.md)
  Page-table mutation remains single-CPU until synchronization exists.
- [ADR-0003](ADR-0003-capability-microkernel-platform.md)
  Capability-oriented microkernel is the long-term platform target.

## When to create an ADR

Create an ADR when a change materially affects:

- Kernel/user-space boundaries or the trusted computing base.
- Capability authority, isolation, or revocation.
- Public interfaces, IPC, or resource ownership.
- Supported hardware profiles or execution contracts.
- Long-term architecture or a difficult-to-reverse choice.

Routine implementation details do not need an ADR.

## Decision workflow

1. Create the next sequential `ADR-NNNN-short-title.md`.
2. Describe context, constraints, and the problem.
3. Compare viable alternatives and their trade-offs.
4. State the decision and required safeguards.
5. Record consequences and conditions for revisiting it.
6. Link affected specifications, tests, and issues.
7. Update this index in the same pull request.

Use [ADR_TEMPLATE.md](ADR_TEMPLATE.md).

## Status lifecycle

- **Proposed:** under discussion; not an implementation mandate.
- **Accepted:** selected direction; implementation may still be incomplete.
- **Rejected:** considered and not selected.
- **Superseded:** replaced by a later ADR.
- **Deprecated:** no longer recommended, with the reason recorded.

Do not silently rewrite an accepted decision.
Supersede it with a new ADR that explains the change.
