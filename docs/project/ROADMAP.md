# Roadmap

## Planning rules

Milestones are completed by acceptance evidence, not by the presence of code or documentation. Dependencies that protect security boundaries block later milestones even when unrelated features could be prototyped in parallel.

## M0 — Repository and boot foundation

**Status: established for the current QEMU profile.**

Scope: Rust workspace, build tooling, serial diagnostics, memory-map validation, basic exception diagnostics, and repeatable CI boot checks.

Exit evidence: pinned toolchain builds the BIOS image; required host checks pass; three independent QEMU boots reach the expected markers and reject panic, missing-marker, and invalid-map cases. This milestone does not imply production readiness.

## M1 — Memory and kernel virtual-memory foundation

**Status: partially complete.**

Implemented slices include a fixed-capacity physical-frame allocator, selected boot mapping inspection, a new kernel root, guarded 4 KiB mapping operations, selected supervisor/NX protections, local TLB transition tests, large-page demotion integration, and direct-map permission transitions for validated executable kernel pages.

Blocking work:
- Complete declared-root and mapping-source inventory for frame-wide W^X.
- Ensure partial coverage, unknown roots, malformed structures, and capacity exhaustion cannot report success.
- Verify every physical overlap across supported page sizes, recursive aliases, direct-map aliases, and inherited mappings in scope.
- Reconcile open [Issue #49](https://github.com/musashimusashino666/one-os/issues/49) against merged implementation PRs #50 and #52; update or close it only after its acceptance criteria are rechecked against current main.
- Close [Issue #26](https://github.com/musashimusashino666/one-os/issues/26) and [Issue #46](https://github.com/musashimusashino666/one-os/issues/46) only when their stated criteria pass on the exact candidate.

Exit gate: all supported mapping sources and roots are explicitly accounted for, all relevant W/X physical overlaps are detected and prevented, transitions and failure paths are tested, and the documented audit scope is complete. Executable publication remains restricted until that gate passes.

## M2 — Process isolation and kernel-enforced authority

**Status: not complete.**

Existing root creation, CPL 0 switching/teardown, and frame-zeroing smoke paths are prerequisites, not a process boundary.

Required work:
- Validated Ring 3 entry/return and fault recovery.
- Independent process address spaces with kernel-enforced access checks.
- Kernel-controlled capability provenance, operation checks, attenuation, and revocation.
- IPC framing and resource-transfer semantics.
- Adversarial cross-process memory, forged/stale grant, and teardown/TLB tests.
- Defined lifecycle and failure handling for all process resources.

Exit gate: negative tests prove that one process cannot access another's private memory or protected resources without authority; all root and frame lifetimes remain safe during failure and teardown.

## M3 — Minimum usable system

**Status: not started as an integrated system.**

Candidate scope: persistent storage, driver model, networking, isolated service manager, process supervision, basic system shell, and a small set of useful applications. Each service must have an explicit privilege boundary and recovery behavior. Do not expand into a large feature surface before M2 is demonstrated.

## M4 — Owner-controlled, resilient user environment

**Status: target design.**

Implement understandable permission workflows, observability for network/background/device activity, accessible user interaction, and constrained AI/automation delegation. UI consent is useful only when backed by enforceable kernel or trusted-service policy.

## M5 — Release hardening and portability

**Status: not started.**

Required before a release claim: authenticated boot, signed and recoverable updates, downgrade policy, persistent-data protection, fuzzing and independent security review, supported hardware/software matrix, documented performance and usability measurements, and an explicit release/rollback process.

## Sequencing rule

Do not enable SMP, unrestricted executable mappings, or general untrusted user execution before their resource-lifetime and permission contracts have adversarial acceptance tests. Work on documentation, tooling, and host-testable algorithms can proceed in parallel without relaxing these gates.
