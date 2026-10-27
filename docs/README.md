# Documentation Map

This directory is the authoritative documentation set for ONE OS. Documents describe either the intended product, normative contracts, verification evidence, or project execution. They must not silently mix those categories.

## Start here

1. [Vision](vision/VISION.md) — what ONE OS is trying to become and what “world-class” means in evidence-based terms.
2. [Principles](vision/PRINCIPLES.md) — rules that constrain design and implementation.
3. [Success criteria](vision/SUCCESS_CRITERIA.md) — outcomes and evidence needed to evaluate progress.
4. [Architecture overview](architecture/OVERVIEW.md) — target system layers and current boundaries.
5. [Security model](architecture/SECURITY_MODEL.md) — assets, threats, assumptions, controls, and explicit limits.
6. [Implementation status](project/IMPLEMENTATION_STATUS.md) — what exists now, what has been tested, and what has not been proved.
7. [Roadmap](project/ROADMAP.md) — ordered milestones and exit criteria.

## By purpose

- **Vision:** `vision/VISION.md`, `vision/PRINCIPLES.md`, `vision/SUCCESS_CRITERIA.md`
- **Architecture:** `architecture/OVERVIEW.md`, `architecture/SECURITY_MODEL.md`, `architecture/USER_EXPERIENCE.md`, `architecture/UPDATES_AND_RECOVERY.md`
- **Normative specifications:** `specs/BOOT_AND_MEMORY.md`, `specs/VIRTUAL_MEMORY_ACCEPTANCE.md`, `specs/ADDRESS_SPACE_LIFECYCLE.md`, `specs/PROCESS_AND_CAPABILITIES.md`, `specs/RING3_ISOLATION_ACCEPTANCE.md`
- **Engineering and evidence:** `engineering/DEVELOPMENT.md`, `engineering/VERIFICATION.md`
- **Execution and decisions:** `project/ROADMAP.md`, `project/IMPLEMENTATION_STATUS.md`, `project/decisions/`

## Rules for authoritative documentation

- Vision documents state intended outcomes; they do not assert that those outcomes already exist.
- Specifications state required behavior and invariants. An implementation is not compliant merely because the code compiles.
- Implementation status must be supported by current source, tests, and the exact CI result or explicitly marked unverified.
- A security claim must name its scope, assumptions, evidence, and known exclusions.
- A design decision that changes a security boundary, interface contract, or long-term architecture must be recorded as an ADR.
- Avoid duplicating detailed facts. Link to the source of truth instead.
- When behavior changes, update the relevant specification, verification evidence, and status in the same change.
- Remove superseded documentation rather than maintaining competing sources of truth.

Use RFC 2119-style words consistently: **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** express normative strength. A MUST-level requirement needs a testable acceptance condition or a documented reason why it cannot yet be tested.
