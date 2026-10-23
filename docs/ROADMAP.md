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
- Keep unsafe code small and document safety invariants.

Exit criteria: allocator, ownership-registry, registry-backed mutation rollback, and CPU-precondition tests pass; reserved and unknown regions are never allocated; insufficient metadata fails closed; invalid maps fail closed; controlled CPU exception injection produces expected vector/error-code/CR2 diagnostics without a false boot-completion marker; read-only page-table walks complete their documented structural and sampled-address checks for essential bootstrap addresses without claiming exact ELF PT_LOAD correspondence; and all dedicated QEMU mapping/protection cases pass on the exact reviewed commit.

## M2 — Isolation and IPC

- [x] Define the implementation contract and adversarial acceptance plan in [ISOLATION_PLAN.md](ISOLATION_PLAN.md). This document specifies the required invariants and test criteria; it does not mean the isolation features are implemented.
- [ ] Add host-testable address-space construction, validation, switching, and teardown primitives that preserve frame ownership and fail-closed rollback.
- [ ] Implement a kernel-controlled ring 3 entry/return path with validated registers, selectors, user stack, and a kernel entry stack.
- [ ] Create independent user address spaces while keeping any required shared kernel mappings supervisor-only; prevent user access to page tables and recursive aliases.
- [ ] Add adversarial QEMU tests proving user code cannot access kernel-only memory or another process's private frames, including same-virtual-address/different-frame cases.
- [ ] Test physical-frame-wide W^X: reject writable and executable aliases of the same frame in either mapping order, within one address space and across address spaces; verify kernel/direct-map and overlapping large-page aliases, and verify write-to-execute transitions only after writable aliases are removed and TLB invalidation completes.
- [ ] Verify effective U/S, R/W, NX, CR0.WP, EFER.NXE, and address-space-switch/TLB behavior; enforce physical-frame-wide W^X across all aliases, address spaces, kernel/direct-map aliases, and large-page overlaps; keep the existing M1 suite green on the exact PR head.
- [ ] Implement a minimal scheduler and thread lifecycle only after the entry/exit and isolation acceptance tests pass.
- [ ] Define IPC message framing, length and memory-ownership validation, sender/receiver identity, and failure behavior.
- [ ] Introduce kernel-enforced capability checks at every protected operation; do not trust user-supplied IDs or serialized capability data as proof of authority.
- [ ] Test denial, revocation, invalid pointers, malformed messages, teardown, and cross-process isolation.

Exit criteria: a controlled user-mode execution and return path succeeds; adversarial tests demonstrate that a process cannot read or modify kernel-only memory or another process's private resources; address-space changes and teardown do not permit stale-TLB access or premature frame reuse; invalid state and resource exhaustion fail closed without publishing partial mappings or freeing foreign frames; and the complete documented acceptance suite passes on the exact reviewed commit. Passing QEMU tests demonstrate only the declared scenarios under the tested single-CPU environment, not SMP safety or production readiness. See the [user-space isolation plan](ISOLATION_PLAN.md).

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
