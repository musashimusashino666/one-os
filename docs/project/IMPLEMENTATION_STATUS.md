# Implementation Status

**Snapshot:** 2026-10-30
**Reviewed main:** `f1d80da6a7db7d87749fd0f31a666878775d36d1`

This document records observed implementation.
It does not guarantee broader security properties.

## Status matrix

### Foundations

- **Rust workspace and BIOS tooling — Verified for scope**
  Core crate, kernel, and xtask build paths exist.
- **Physical memory — Partial**
  Fixed-capacity frame allocator and host tests.
- **Boot mapping inspection — Partial**
  Selected mappings and ELF segments are checked.
- **Page-table mutation — Partial**
  Guarded 4 KiB paths and selected ownership/TLB checks.

### Memory protection

- **Large-page handling — Verified for scope**
  Demotion and sibling-preservation QEMU cases exist.
- **Direct-map W^X transition — Partial**
  Validated executable PT_LOAD aliases are preflighted and transitioned.
- **W^X alias audit — Verified for declared scope**
  Bounded active/registered-root audit and cross-root conflict test.
- **Global frame-wide W^X — Blocked**
  Complete boot-map coverage and transactional enforcement remain open.
- **CR3 write-site control — Verified for scope**
  Source, optimized assembly, and normal linked BIOS ELF checks.

### Process and platform

- **Address-space lifecycle — Partial**
  CPL 0 root switching and selected teardown paths are tested.
- **User-page initialization — Partial**
  Kernel zeroing adapter and selected QEMU checks exist.
- **Ring 3 process isolation — Not established**
  No complete user entry/return and isolation boundary.
- **Capability enforcement — Not established**
  oneos-core is a host-testable reference model.
- **IPC and scheduler — Not established**
  No usable integrated subsystem.
- **Storage, network, and drivers — Not established**
  No integrated user-facing system.
- **Permission UI and AI delegation — Not established**
  Design target only.
- **Secure boot and signed updates — Not established**
  No production integrity or recovery path.
- **SMP and remote TLB shootdown — Not established**
  Current paging contract is single-CPU.

## Verified implementation slices

### Memory and paging

- Fixed-capacity physical frame allocation.
- Selected boot mapping inspection.
- Guarded 4 KiB mapping and unmapping.
- Supervisor-write and NX protection checks.
- Large-page demotion and sibling permission checks.
- Direct-map permission transition for validated executable
  `PT_LOAD` pages.
- Bounded W^X audit over the active and registered roots.
- Cross-root writable/executable alias conflict injection.
- Exact PTE restoration and clean follow-up audit.
- Root admission, activation, and cleanup rejection tests.

These are bounded results.
They do not establish global frame-wide W^X.

### CR3 write-site control

- PR #73 adds source-level writer inventory and deny rules.
- PR #73 checks the reviewed optimized assembly path.
- PR #76 inspects the final linked ELF from the normal BIOS image.
- The linked image must contain exactly three reviewed CR3 writes.

The linked-ELF check does not inspect every feature-specific
QEMU test image. It is not a whole-program or boot-mapping proof.

### Process and authority

- CPL 0 address-space root lifecycle paths exist.
- Selected switching, zeroing, teardown, and reclamation paths
  have bounded tests.
- The capability model exists in the host-testable core crate.

These are prerequisites only.
They do not constitute Ring 3 isolation or kernel-enforced authority.

## Open work

### Product validation

- [#83](https://github.com/musashimusashino666/one-os/issues/83):
  validate the initial product thesis and comparators.

### Memory protection

- [#26](https://github.com/musashimusashino666/one-os/issues/26):
  parent memory-protection gate.
- [#46](https://github.com/musashimusashino666/one-os/issues/46):
  authoritative physical-alias inventory.
- [#80](https://github.com/musashimusashino666/one-os/issues/80):
  complete boot-mapping classification.
- [#81](https://github.com/musashimusashino666/one-os/issues/81):
  transactional frame-wide W^X enforcement.

### Process isolation and authority

- [#23](https://github.com/musashimusashino666/one-os/issues/23):
  safe user-page initialization and publication.
- [#24](https://github.com/musashimusashino666/one-os/issues/24):
  parent process-isolation milestone.
- [#77](https://github.com/musashimusashino666/one-os/issues/77):
  Ring 3 and independent address spaces.
- [#78](https://github.com/musashimusashino666/one-os/issues/78):
  kernel-enforced capabilities.
- [#87](https://github.com/musashimusashino666/one-os/issues/87):
  normative IPC specification.
- [#79](https://github.com/musashimusashino666/one-os/issues/79):
  kernel IPC implementation.

### Concurrency and release

- [#25](https://github.com/musashimusashino666/one-os/issues/25):
  SMP, preemption, and remote TLB shootdown.
- [#84](https://github.com/musashimusashino666/one-os/issues/84):
  production integrity and release readiness.

### Project governance

- [#85](https://github.com/musashimusashino666/one-os/issues/85):
  private vulnerability reporting and response policy.
- [#86](https://github.com/musashimusashino666/one-os/issues/86):
  automated documentation integrity checks.
- [#88](https://github.com/musashimusashino666/one-os/issues/88):
  issue labels and milestone taxonomy.
- [#89](https://github.com/musashimusashino666/one-os/issues/89):
  maintainability review for large implementation modules.

## Verification evidence

The latest relevant PR-context CI run checked on main is:

- PR #75, run [#41022642740][ci75]:
  passed on PR HEAD
  `8eb7af0883da710da04433cbc861938009497a9b`.
- PR #76, run [#41019578318][ci76]:
  passed on PR HEAD
  `c7b785dce8cf1b8681cf491147249c45beea9c90`.

PR #75 is documentation-only and includes the project definition
and ADR-0003 integration. PR #76 adds the linked-ELF CR3 check.

CI and QEMU evidence applies only to the tested revisions and
declared emulator profile. The current main commit is recorded
above; this snapshot does not claim a new run on this documentation PR.

## Explicit limitations

- Global frame-wide W^X is incomplete.
- Boot mapping classification is not exhaustive.
- Ring 3 process isolation is incomplete.
- Capability rights are not fully enforced by the kernel.
- IPC and a usable scheduler are not integrated.
- SMP and remote TLB shootdown are unsupported.
- Physical hardware validation is not established.
- Machine Check behavior is not validated.
- No independent human security sign-off is claimed.
- No production-readiness or certification claim is made.

[ci75]: https://github.com/musashimusashino666/one-os/actions/runs/41022642740
[ci76]: https://github.com/musashimusashino666/one-os/actions/runs/41019578318
