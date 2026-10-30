# Contributing to ONE OS

## Before changing code

Read the relevant source documents:

- [Product definition](docs/vision/WORLD_CLASS_OS.md)
- [Architecture](docs/architecture/OVERVIEW.md)
- [Security model](docs/architecture/SECURITY_MODEL.md)
- [Relevant specification](docs/specs/)
- [Success criteria](docs/vision/SUCCESS_CRITERIA.md)
- [Implementation status](docs/project/IMPLEMENTATION_STATUS.md)
- [Roadmap](docs/project/ROADMAP.md)

The repository is a bootstrap-stage research kernel.
Do not describe a target design as an implemented capability.

## Scope and branches

- Keep each pull request focused on one coherent change.
- Link the relevant issue and state the invariant being changed.
- Avoid unrelated refactors in security-sensitive changes.
- Do not weaken a fail-closed path to make a test pass.
- Use a descriptive branch such as `fix/<scope>`,
  `feat/<scope>`, or `docs/<scope>`.

## Security-sensitive changes

Changes to memory, address spaces, authority, IPC,
or resource lifetime must include:

- The affected trust boundary and threat assumptions.
- The invariant and permitted state transitions.
- Denied-operation and malformed-input tests.
- Failure, rollback, ownership, and lifetime analysis.
- Exact evidence scope and exclusions.
- Updated specifications and verification documentation.
- An ADR when a durable architectural decision changes.

Do not infer global security from a bounded host test or QEMU run.

## Validation

Follow the [Development Guide](docs/engineering/DEVELOPMENT.md)
for toolchain setup and local validation commands.

The required PR-context CI check must pass on the latest PR HEAD.
A manual or older workflow run is not a substitute.
Report every check that was not run.

## Pull requests

Use the [pull request template](.github/pull_request_template.md).
Describe alternatives, tests, negative cases, and residual risk.
Review the complete diff and resolve all review comments.
Do not merge while required CI is pending or failing.
Use squash or rebase to preserve the active linear-history rule.

## Issue organization

Priority prefixes have distinct meanings:

- **P0:** product-thesis validation and user research.
  This may proceed in parallel with engineering work.
- **P1:** current milestone blocker or safety/security gate.
- **P2:** important prerequisite, governance, or strategic follow-on.

Parent issues track milestones; child issues define deliverables.
Close a parent only after child acceptance criteria pass.
Use #88 for the GitHub label and milestone taxonomy.

## Documentation

Keep one authoritative source for each claim.
Keep Markdown prose and table rows within 88 characters.
Prefer headings and lists over wide tables.
Exempt fenced code, inline code that cannot be split,
and unbreakable URLs only.
Update specifications and verification when behavior changes.
Update implementation status when source or evidence changes.
Update roadmap when milestone scope or dependencies change.
Update Success Criteria when product requirements or release
gates change. Record architectural decisions as ADRs.
