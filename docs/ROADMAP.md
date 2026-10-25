# ONE OS Roadmap

Work is milestone-driven. A milestone is complete only when its acceptance criteria are reproducibly demonstrated; writing code alone is not sufficient.

## M0 — Repository and kernel bootstrap

- [x] Rust workspace and formatting/CI baseline.
- [x] x86_64 kernel entry point and COM1 diagnostics.
- [x] Host-testable no_std capability reference model.
- [x] BIOS disk-image build tool.
- [x] Architecture, security, development, and roadmap documents.
- [x] Verify three independent QEMU boot attempts through CI.
- [x] Test the serial-log validator against panic output, missing completion markers, invalid-map markers, and unexpected QEMU exit statuses.

Exit criteria: three independent QEMU invocations emit the expected startup markers; output is captured for each attempt, and panic, missing completion markers, or unexpected exit statuses fail clearly.

## M1 — CPU and memory foundations

- [x] Structurally validate BootInfo memory-map ranges and reject empty, inverted, or overlapping regions.
- [x] Define initial memory-region ownership and implement a fixed-capacity 4 KiB bitmap physical-frame allocator; host tests cover kernel-image overlap rejection, invalid ranges/maps, usable-region/frame capacity exhaustion, reserved-region exclusion, alignment, exhaustion, release/reuse, and foreign tokens.
- [x] Enable the bootloader recursive page-table mapping and inspect the active four-level page tables read-only; check sampled translations for kernel code, the active stack, and BootInfo without claiming segment-by-segment ELF mapping verification.
- [x] Set up and test kernel virtual-memory mappings, including map/unmap operations and permission enforcement.
- [x] Add host-testable 4 KiB map/unmap mutation primitives with W^X policy and allocation-failure rollback tests.
- [x] Connect an active-kernel editor, establish CR0.WP/EFER.NXE, and run a normal-boot map/access/unmap smoke cycle.
- [x] Run the dedicated QEMU supervisor-write-protection, NX-instruction-fetch, and map/unmap/remap transition/TLB tests as part of the reviewed implementation's required CI acceptance suite. Each subsequent change must pass the same suite on its exact PR candidate; see the [CI workflow runs](https://github.com/musashimusashino666/one-os/actions/workflows/ci.yml).
- [x] Complete the active-kernel mapping/protection acceptance suite: the concrete editor's physical-memory-offset alias and zero-before-publication path are asserted by the transition-test image, while registry rollback and CPU-precondition logic are host-tested. Keep the required CI suite green for every reviewed PR candidate. Follow the [kernel VM integration contract](VM_INTEGRATION_PLAN.md) for page-table access, frame-token ownership, CPU paging state, TLB invalidation, and acceptance criteria.
- [x] Establish exception handlers and diagnostic fault output, including QEMU tests for invalid opcode, general protection, and page-fault/CR2 reporting (verified in CI Run #120 at `892b9268c9a6774229189c60557be4d0d22bf541`).
- [x] Configure a TSS/IST stack for double-fault diagnostics and verify it with controlled QEMU fault injection (verified by CI Run #149 at `c2ba82663f8fcca40b396b61e6f764434d38abd7`).
- [x] Build the kernel as position-independent code at a fixed upper-half base, constrain bootloader-created dynamic mappings to the upper half, validate execution-critical addresses, and activate a verified supervisor-only kernel root during the normal QEMU boot smoke test. This is not yet process isolation or ring-3 execution.
- Keep unsafe code small and document safety invariants.

Exit criteria: allocator, ownership-registry, registry-backed mutation rollback, and CPU-precondition tests pass; reserved and unknown regions are never allocated; insufficient metadata fails closed; invalid maps fail closed; controlled CPU exception injection produces expected vector/error-code/CR2 diagnostics without a false boot-completion marker; read-only page-table walks complete their documented structural and sampled-address checks for essential bootstrap addresses without claiming exact ELF PT_LOAD correspondence; and all dedicated QEMU mapping/protection cases pass on the exact reviewed commit.

## M2 — Isolation and IPC

- [x] Prevent the normal CR3 activation path from returning an active root through the releasable inactive-root type; retain it as `ActiveAddressSpaceRoot`.
- [x] Require a `ZeroedFrame` token for the safe host-testable user-data mapping API and test zeroing/failure ownership contracts.
- [x] Implement and QEMU-test a kernel-backed user-frame zeroing adapter using a validated supervisor-only writable alias. PR #27 verifies the dirty frame is fully zeroed and that the returned `ZeroedFrame` names that exact physical frame. This does not publish a user page or prove process isolation.
- [x] Define the implementation contract and adversarial acceptance plan in [ISOLATION_PLAN.md](ISOLATION_PLAN.md). This document specifies the required invariants and test criteria; it does not mean the isolation features are implemented.
- [x] Add host-testable address-space-root construction/validation and an ownership-carrying active-to-inactive root transition API. Demotion rejects an observed CR3 root that still names the root being demoted; the unsafe caller must independently guarantee a real switch and completed TLB invalidation.
- [ ] Integrate and QEMU-test runtime address-space switching and teardown in the kernel. Remove user mappings and lower-level page tables transactionally, validate CR3/CR4 state, and complete required TLB invalidation before any frame reuse. Fail closed if the switch result is uncertain.

  The runtime-switch implementation slice adds a normal-boot A -> B -> A smoke test for two owned roots containing only shared supervisor-only kernel mappings. It verifies each target CR3 readback, each root's private recursive index, CPU paging preconditions, and the explicit CR4.PGE-clear / CR3-write / CR4-restore sequence. The temporary root is released only after switching away and completing the second local TLB transition. This is not user-process switching, user-page teardown, lower-level table reclamation, Ring 3 isolation, or SMP support; keep the overall item open until those requirements are implemented and tested.
- [ ] Implement a kernel-controlled ring 3 entry/return path with validated registers, selectors, user stack, and a kernel entry stack.
- [ ] Create independent user address spaces while keeping any required shared kernel mappings supervisor-only; prevent user access to page tables and recursive aliases.
- [ ] Add adversarial QEMU tests proving user code cannot read, write, or execute kernel-only memory or another process's private frames, including same-virtual-address/different-frame cases. Explicitly test ring-3 instruction fetch from a present supervisor-only executable page (require #PF vector 14, CR2 and saved RIP equal to the target VA, exact error code `0x15`) and instruction fetch of code mapped only in another process (require exact non-present instruction-fetch fault `0x14`). For both cases, the #PF handler must validate the user exception frame and redirect RIP to a validated user-mode recovery stub; that stub must re-enter the kernel through a dedicated DPL-3 test interrupt using the TSS kernel entry stack. Only the second, validated kernel entry may emit the unique marker and trigger the required `isa-debug-exit` status. See the fault recovery protocol in [ISOLATION_PLAN.md](ISOLATION_PLAN.md).
- [ ] Verify effective U/S, R/W, NX, CR0.WP, EFER.NXE, and address-space-switch/TLB behavior, and enforce physical-frame-wide W^X across all aliases: reject writable and executable aliases of the same frame in either mapping order and across address spaces; account for kernel/direct-map aliases and overlapping large-page mappings; allow write-to-execute transitions only after every writable alias is removed or downgraded and required TLB invalidation completes; keep the existing M1 suite green on the exact PR head.
- [ ] Implement a minimal scheduler and thread lifecycle only after the entry/exit and isolation acceptance tests pass.
- [ ] Define IPC message framing, length and memory-ownership validation, sender/receiver identity, and failure behavior.
- [ ] Introduce kernel-enforced capability checks at every protected operation; do not trust user-supplied IDs or serialized capability data as proof of authority.
- [ ] Test denial, revocation, invalid pointers, malformed messages, teardown, and cross-process isolation.

Exit criteria: **M2 is complete only when every M2 implementation item above passes on the exact reviewed commit; I1–I3 isolation success alone is not sufficient.** A controlled ring-3 execution and return path succeeds; adversarial tests show that processes cannot read, write, or execute kernel-only memory or one another's private resources, including the dedicated supervisor-only and cross-process instruction-fetch denial cases with validated user-mode recovery stubs and a second, normal kernel entry; address-space changes and teardown prevent stale-TLB access and premature frame reuse; and invalid state/resource exhaustion fail closed without partial publication or foreign-frame release. A minimal scheduler and thread lifecycle must operate on validated kernel-owned contexts. IPC must be exercised between isolated participants with framing, lengths, sender/receiver identity, memory ownership, cancellation, malformed-message, invalid-pointer, and failure semantics tested. Kernel-enforced capability checks must guard every protected operation, with test evidence for insufficient rights, wrong principals, forged/modified/foreign/stale tokens, revocation, and resource lifetime across IPC/teardown. The full M1 regression suite and all M2 isolation, scheduler/IPC, and capability acceptance tests must pass. I1–I3 may be reported separately as the initial user-space isolation phase, but M2 stays incomplete until I4 and I5 also pass. Passing QEMU tests demonstrate only the declared scenarios under the tested single-CPU environment, not SMP safety or production readiness. See the [user-space isolation plan](ISOLATION_PLAN.md).

## M3 — Storage and recovery

- Add an initial read-only or minimal writable filesystem path.
- Define filesystem error semantics and integrity checks.
- Implement snapshots or transactional updates where appropriate.
- Add independent backup and restore tests.

Exit criteria: power-loss simulation and fault injection preserve documented filesystem invariants.

## M4 — Device and network services

- Establish a driver model with user-space isolation where practical.
- Add a minimal set of tested virtual and physical devices.
- Implement a bounded networking stack and permission policy.
- Fuzz parsers and protocol boundaries.

Exit criteria: supported-device matrix and protocol test results are published.

## M5 — Developer and application platform

- Define the native system ABI and compatibility policy.
- Add a secure package format and signed repository metadata.
- Prototype sandboxed portable applications.
- Provide SDK documentation and end-to-end examples.

Exit criteria: third parties can build, sign, install, update, and uninstall a sample app with scoped rights.

## M6 — UI, accessibility, and AI services

- Build an accessible shell and window/input abstraction.
- Implement settings and user-facing permission controls.
- Expose controlled APIs to local and remote AI models.
- Require approval for sensitive or irreversible operations.
- Audit all AI-initiated side effects.

Exit criteria: usability tests, permission tests, and AI-action audit tests pass.

## M7 — Performance, hardware, and independent review

- Publish repeatable benchmarks against defined reference systems.
- Optimize only after profiling representative workloads.
- Add architecture support based on demand and test capacity.
- Conduct external security review and vulnerability response exercises.

Exit criteria: public reports disclose hardware, workload, build, limitations, and outstanding risks.

## Prioritization rule

Security boundaries, bootability, and reproducibility take precedence over features. A smaller, verified capability is more valuable than a broad subsystem whose behavior cannot be tested.
