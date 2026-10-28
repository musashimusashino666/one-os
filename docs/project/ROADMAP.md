# Roadmap

## Planning rules

Milestones are completed by acceptance evidence, not by the presence of code or documentation. Dependencies that protect security boundaries block later milestones even when unrelated features could be prototyped in parallel.

The product definition in [Vision](../vision/VISION.md) is a set of hypotheses until validated with users and comparative evidence. Keep user/product validation distinct from kernel implementation status; do not claim product-market fit or superiority based on technical progress alone.

## P0 — Validate the product thesis

**Status: definition documented; validation not yet demonstrated.** This work can proceed in parallel with kernel milestones, but M3's integrated product scope should not be treated as committed until its user and security prerequisites are satisfied.

Required work:
- Test the initial target-cohort assumption with representative users; identify the highest-value workflows and where users misunderstand or cannot control authority.
- Compare relevant existing systems and execution approaches against the same named workflows. Record the threat model and configuration; do not assume that ONE OS is unique or superior.
- Prioritize an initial usable-system scope and explicitly defer features that do not advance the core promise of enforceable, understandable, revocable authority and safe recovery.
- Define task-study and performance-baseline methods before collecting results. Keep numeric targets marked TBD until their baseline and rationale are recorded.
- Record the resulting scope, unresolved assumptions, trade-offs, and decisions in maintained project documentation; create an ADR where a decision changes long-lived architecture or a security boundary.

Exit evidence: a published, privacy-preserving research summary; a target-user and core-workflow definition supported by that evidence; a versioned initial product scope with explicit non-goals; and an evaluation plan with named comparators, methods, and unresolved assumptions. If evidence contradicts the current thesis, revise the vision rather than forcing the findings to fit it.

## M0 — Repository and boot foundation

**Status: established for the current QEMU profile.**

Scope: Rust workspace, build tooling, serial diagnostics, memory-map validation, basic exception diagnostics, and repeatable CI boot checks.

Exit evidence: pinned toolchain builds the BIOS image; required host checks pass; three independent QEMU boots reach the expected markers and reject panic, missing-marker, and invalid-map cases. This milestone does not imply production readiness.

## M1 — Memory and kernel virtual-memory foundation

**Status: partially complete.**

Implemented slices include a fixed-capacity physical-frame allocator, selected boot mapping inspection, a new kernel root, guarded 4 KiB mapping operations, selected supervisor/NX protections, local TLB transition tests, large-page demotion integration, and direct-map permission transitions for validated executable kernel pages. A dedicated QEMU acceptance path also verifies that a writable alias introduced in an inactive root is detected against a controlled RX alias in the active root, then confirms the original mapping can be restored and the audit returns clean. This remains evidence for the explicitly declared roots, not proof that the root registry or all boot mapping sources are globally exhaustive. The registry cleanup path now refuses to unregister active or still-allocated roots, with a QEMU regression check that the rejected operation leaves the root in the audited set. A second test-only fault injection removes an allocated inactive target from the registry and calls the shared admission guard directly to verify rejection; it does not invoke the CR3-switch functions. The registry is restored before the follow-up audit. Separate QEMU profiles now fault-inject missing registration and exercise the real runtime switch and initial activation paths, requiring rejection before CR3 changes plus the corresponding registry/allocator cleanup invariants. PR #71 further requires roots to be allocator-owned and not permanently reserved at registration and activation, and adds fault-injection tests that mutate reservation metadata after registration: the actual CR3-switch path must reject the target before changing CR3, while the W^X audit must fail before dereferencing the affected root and pass a complete clean re-audit after the injected bit is removed. The coverage tracker also rejects source-accounting attempts until the root inventory is sealed and every declared root walk completes; source flags remain contingent on their source-specific validation stages. The relevant PR #71 CI run passed on its HEAD; see [the implementation status evidence snapshot](IMPLEMENTATION_STATUS.md) for the tested SHA/tree relationship.

Blocking work:
- Complete and independently validate the authoritative inventory of every root the kernel can activate and every mapping source that can create a physical alias.
- Keep duplicate/cyclic page-table paths, unknown roots, malformed structures, root-snapshot changes, and range/table/recursive/path budget exhaustion fail-closed; the bounded audit must never treat partial coverage as clean.
- Verify every physical overlap across supported page sizes, recursive aliases, direct-map aliases, and inherited mappings in scope; report both coverage completeness and conflict status separately.
- Complete the broader Issue #26 boot-mapping inventory and unexpected/missing mapping rejection; the current PT_LOAD/stack/BootInfo checks are bounded and do not independently prove every bootloader mapping is expected.
- Close [Issue #26](https://github.com/musashimusashino666/one-os/issues/26) and [Issue #46](https://github.com/musashimusashino666/one-os/issues/46) only when their stated criteria pass on the exact candidate.

The bounded x86 direct-map W^X transition risk review in [closed Issue #49](https://github.com/musashimusashino666/one-os/issues/49) was recorded against the reviewed main revision and closed with explicit residual-risk acceptance. That decision does not complete this milestone: independent human sign-off and physical-hardware validation were not performed, and the broader inventory work in Issues #26 and #46 remains open.

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

Candidate scope: persistent storage, driver model, networking, isolated service manager, process supervision, basic system shell, and a small set of useful applications. Each service must have an explicit privilege boundary and recovery behavior. Do not expand into a large feature surface before M2 is demonstrated. Final MVP scope must also satisfy the P0 product-validation exit evidence; this list is a candidate scope, not a commitment to build every listed component.

## M4 — Owner-controlled, resilient user environment

**Status: target design.**

Implement understandable permission workflows, observability for network/background/device activity, accessible user interaction, and constrained AI/automation delegation. UI consent is useful only when backed by enforceable kernel or trusted-service policy.

## M5 — Release hardening and portability

**Status: not started.**

Required before a release claim: authenticated boot, signed and recoverable updates, downgrade policy, persistent-data protection, fuzzing and independent security review, supported hardware/software matrix, documented performance and usability measurements, and an explicit release/rollback process.

## Sequencing rule

Do not enable SMP, unrestricted executable mappings, or general untrusted user execution before their resource-lifetime and permission contracts have adversarial acceptance tests. Work on documentation, tooling, product validation, and host-testable algorithms can proceed in parallel without relaxing these gates.
