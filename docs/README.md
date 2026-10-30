# Documentation

This directory contains the authoritative project documentation.
Use this index to find the specification or evidence you need.
Avoid duplicate summaries: each fact has one canonical home.

## Product definition

- [World-class OS definition](vision/WORLD_CLASS_OS.md):
  product target, quality dimensions, and platform scope.
- [Vision](vision/VISION.md): purpose, user needs, and hypotheses.
- [Principles](vision/PRINCIPLES.md): architectural constraints.
- [Success criteria](vision/SUCCESS_CRITERIA.md):
  measurable requirements, release gates, and traceability.

## Architecture and contracts

- [Architecture overview](architecture/OVERVIEW.md)
- [Security model](architecture/SECURITY_MODEL.md)
- [User experience](architecture/USER_EXPERIENCE.md)
- [Updates and recovery](architecture/UPDATES_AND_RECOVERY.md)
- [Normative specifications](specs/):
  boot, memory, address spaces, process authority, and acceptance.

Specifications define required behavior.
A design target is not proof of implementation.

## Engineering

- [Development guide](engineering/DEVELOPMENT.md):
  toolchain, build, and local workflows.
- [Verification strategy](engineering/VERIFICATION.md):
  tests, CI contract, evidence scope, and exclusions.
- [Contributing guide](../CONTRIBUTING.md):
  change and review policy.
- [Security reporting policy](../SECURITY.md):
  vulnerability disclosure route and current limitations.

## Project execution

- [Implementation status](project/IMPLEMENTATION_STATUS.md):
  what exists and what has been verified.
- [Roadmap](project/ROADMAP.md):
  milestones, dependencies, and exit criteria.
- [Architecture decisions](project/decisions/README.md):
  accepted ADRs and the decision template.

## Documentation rules

1. Keep one canonical source for each requirement or claim.
2. Keep Markdown prose and table rows within 88 characters.
Prefer headings and lists over wide tables.
Exempt fenced code, inline code that cannot be split,
and unbreakable URLs only.
3. Vision describes intent; specifications define contracts.
4. Implementation status cites source and exact verification evidence.
5. Security claims state assumptions, scope, and exclusions.
6. Update specifications and tests in the same change as behavior.
7. Record durable architecture changes as ADRs.
8. Remove obsolete documents instead of preserving redirect pages.

Use RFC 2119 terms consistently:
**MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY**.
Every MUST-level requirement needs a testable acceptance condition
or a documented reason why it cannot yet be tested.
