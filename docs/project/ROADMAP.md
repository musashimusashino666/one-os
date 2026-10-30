# Roadmap

## Planning rules

A milestone is complete only when its acceptance evidence passes
on the exact reviewed candidate.

A design document is not an implementation.
A passing test proves only its declared scope.

The canonical product target is defined in
[World-Class OS](../vision/WORLD_CLASS_OS.md).
The current implementation is tracked in
[Implementation Status](IMPLEMENTATION_STATUS.md).
Product requirements and non-compensating release gates are in
[Success Criteria](../vision/SUCCESS_CRITERIA.md).

## Long-term platform scope

ONE OS targets a shared platform across:

- PC and workstation.
- Smartphone and mobile.
- Server.
- Embedded and edge.

The current x86_64 BIOS/QEMU kernel is the first research target.
It does not establish support for the other profiles.

Each profile requires its own hardware matrix, tests,
performance baselines, and support statement.

## P0 — Validate the product thesis

**Status: Not established.**

Tracked by [#83](https://github.com/musashimusashino666/one-os/issues/83).

- Validate the initial user cohort and core workflows.
- Compare relevant operating systems on equivalent tasks.
- Define the initial usable PC scope and explicit non-goals.
- Establish usability and performance measurement methods.
- Record results, assumptions, and design changes.

**Exit:** documented user research, target workflows,
named comparators, and a versioned product scope.

Product research can proceed in parallel with engineering.
It does not relax security acceptance gates.

## M0 — Repository and boot foundation

**Status: Verified for the current QEMU profile.**

- Rust workspace and pinned toolchain.
- BIOS image build tooling.
- Memory-map validation.
- Basic exception and serial diagnostics.
- Repeatable CI and QEMU boot checks.

**Exit:** required checks pass and three independent QEMU boots
reach the expected markers.

This does not imply production readiness.

## M1 — Memory and kernel virtual memory

**Status: Partial. This is the current technical priority.**

### Implemented slices

- Fixed-capacity physical frame allocator.
- Selected boot mapping inspection.
- Guarded 4 KiB map and unmap operations.
- Supervisor-write and NX checks.
- Large-page demotion and sibling preservation.
- Direct-map transition for validated executable PT_LOAD pages.
- Bounded W^X audit over active and registered roots.
- Cross-root conflict injection and PTE restoration.
- CR3 source, assembly, and linked-ELF checks.

### Blocking work

1. [#46](https://github.com/musashimusashino666/one-os/issues/46)
   — prove authoritative root and alias inventory.
2. [#80](https://github.com/musashimusashino666/one-os/issues/80)
   — classify all required boot mappings and ELF translations.
3. [#81](https://github.com/musashimusashino666/one-os/issues/81)
   — implement transactional frame-wide W^X enforcement.
4. [#26](https://github.com/musashimusashino666/one-os/issues/26)
   — parent acceptance gate.

### Exit criteria

- Every required boot mapping is classified.
- Every root and mapping source in scope is accounted for.
- 4 KiB, 2 MiB, and 1 GiB overlaps are checked.
- W^X transitions preserve ownership and TLB ordering.
- Failure injection proves safe rollback.
- Arbitrary executable publication remains denied
  until the complete gate passes.

A clean bounded audit is not a global W^X proof.

## M2 — Process isolation and kernel authority

**Status: Not complete.**

Work is split into focused issues:

- [#23](https://github.com/musashimusashino666/one-os/issues/23)
  — initialize and publish user pages safely.
- [#77](https://github.com/musashimusashino666/one-os/issues/77)
  — Ring 3 entry and independent address spaces.
- [#78](https://github.com/musashimusashino666/one-os/issues/78)
  — kernel-enforced capabilities.
- [#87](https://github.com/musashimusashino666/one-os/issues/87)
  — specify the IPC ABI and transfer contract.
- [#79](https://github.com/musashimusashino666/one-os/issues/79)
  — implement IPC against the accepted specification.
- [#24](https://github.com/musashimusashino666/one-os/issues/24)
  — parent process-isolation milestone.

### Exit criteria

- Validated Ring 3 entry, return, and fault recovery.
- Independent process address spaces.
- Kernel-enforced and revocable authority.
- Defined IPC identity and resource ownership.
- Adversarial cross-process and forged-capability tests.
- Safe teardown and frame reclamation.

Do not treat CPL 0 root-switch tests as process isolation.

## Concurrency gate

[#25](https://github.com/musashimusashino666/one-os/issues/25)
tracks SMP, preemption, and remote TLB shootdown.

Keep SMP and preemption disabled until lock ordering,
root lifetime, frame reuse, and remote invalidation are specified
and verified.

## M3 — Minimum usable PC system

**Status: Not started as an integrated system.**

Candidate components:

- Storage and filesystem.
- Driver and device-management model.
- Networking.
- Service manager and process supervision.
- Shell and application execution.
- Tested update and recovery flow.

Do not expand the feature surface before M2 is accepted.
Validate the actual user workflows through P0 first.

## M4 — Owner-controlled user environment

**Status: Target design.**

- Understandable permission controls.
- Network, device, and background-activity visibility.
- Revocation and audit views.
- Accessible interaction.
- AI and automation using the normal authority model.

A permission UI is not a security boundary by itself.

## M5 — Release hardening and portability

**Status: Not started.**

Tracked by [#84](https://github.com/musashimusashino666/one-os/issues/84).

- Authenticated boot and signing-key lifecycle.
- Signed updates and anti-rollback.
- Interruption-safe recovery.
- Persistent-data protection.
- Fuzzing and independent security review.
- Physical-hardware validation.
- AArch64 and profile-specific ports.
- Published support matrix and comparative benchmarks.
- Release, support, and rollback policy.

No platform is supported by inference from another profile.

## Cross-cutting project governance

These tasks support every milestone:

- [#85](https://github.com/musashimusashino666/one-os/issues/85)
  — private vulnerability reporting and response policy.
- [#86](https://github.com/musashimusashino666/one-os/issues/86)
  — documentation integrity checks in CI.
- [#88](https://github.com/musashimusashino666/one-os/issues/88)
  — issue labels and milestone taxonomy.
- [#89](https://github.com/musashimusashino666/one-os/issues/89)
  — safe refactoring of large paging and CI modules.

## Execution order

1. Validate P0 product assumptions in parallel through #83.
2. Complete M1 gates #46, #80, and #81 under #26.
3. Complete #23 and Ring 3 isolation in #77.
4. Enforce kernel authority through #78.
5. Specify IPC in #87, then implement it in #79.
6. Complete #25 before enabling concurrency.
7. Build M3 only after M2 and user-workflow evidence.
8. Build M4 and M5 behind their acceptance gates.

Documentation, host-testable algorithms, CI quality,
and product research may proceed in parallel.
Security gates must not be bypassed to accelerate later milestones.
