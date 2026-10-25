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
- [x] Enable the bootloader recursive page-table mapping and inspect the active four-level page tables read-only; parse the bounded ELF64 PT_LOAD table and validate every segment page's translation, physical backing region, effective U/S, R/W, and NX flags (including GNU_RELRO write-protection), and p_offset correspondence for read-only file-backed pages except a partial BSS-tail page. This does not audit every boot mapping or establish global W^X.
- [x] Set up and test kernel virtual-memory mappings, including map/unmap operations and permission enforcement.
- [x] Add host-testable 4 KiB map/unmap mutation primitives with W^X policy and allocation-failure rollback tests.
- [x] Connect an active-kernel editor, establish CR0.WP/EFER.NXE, and run a normal-boot map/access/unmap smoke cycle.
- [x] Run the dedicated QEMU supervisor-write-protection, NX-instruction-fetch, and map/unmap/remap transition/TLB tests as part of the reviewed implementation's required CI acceptance suite. Each subsequent change must pass the same suite on its exact PR candidate; see the [CI workflow runs](https://github.com/musashimusashino666/one-os/actions/workflows/ci.yml).
- [x] Complete the active-kernel mapping/protection acceptance suite: the concrete editor's physical-memory-offset alias and zero-before-publication path are asserted by the transition-test image, while registry rollback and CPU-precondition logic are host-tested. Keep the required CI suite green for every reviewed PR candidate. Follow the [kernel VM integration contract](VM_INTEGRATION_PLAN.md) for page-table access, frame-token ownership, CPU paging state, TLB invalidation, and acceptance criteria.
- [x] Establish exception handlers and diagnostic fault output, including QEMU tests for invalid opcode, general protection, and page-fault/CR2 reporting (verified in CI Run #120 at `892b9268c9a6774229189c60557be4d0d22bf541`).
- [x] Configure a TSS/IST stack for double-fault diagnostics and verify it with controlled QEMU fault injection (verified by CI Run #149 at `c2ba82663f8fcca40b396b61e6f764434d38abd7`).
- [x] Build the kernel as position-independent code at a fixed upper-half base, constrain bootloader-created dynamic mappings to the upper half, validate execution-critical addresses, and activate a verified supervisor-only kernel root during the normal QEMU boot smoke test. This is not yet process isolation or ring-3 execution.
- Keep unsafe code small and document safety invariants.

Exit criteria: allocator, ownership-registry, registry-backed mutation rollback, and CPU-precondition tests pass; reserved and unknown regions are never allocated; insufficient metadata fails closed; invalid maps fail closed; controlled CPU exception injection produces expected vector/error-code/CR2 diagnostics without a false boot-completion marker; read-only page-table walks complete their structural checks, all PT_LOAD pages satisfy the documented translation and permission checks, and all dedicated QEMU mapping/protection cases pass on the exact reviewed commit; this still does not claim complete boot-mapping or alias-wide W^X coverage.

## M2 — Isolation and IPC

- [x] Prevent the normal CR3 activation path from returning an active root through the releasable inactive-root type; retain it as `ActiveAddressSpaceRoot`.
- [x] Require a `ZeroedFrame` token for the safe host-testable user-data mapping API and test zeroing/failure ownership contracts.
- [x] Implement and QEMU-test a kernel-backed user-frame zeroing adapter using a validated supervisor-only writable alias. PR #27 verifies the dirty frame is fully zeroed and that the returned `ZeroedFrame` names that exact physical frame. This does not publish a user page or prove process isolation.
- [x] Define the implementation contract and adversarial acceptance plan in [ISOLATION_PLAN.md](ISOLATION_PLAN.md). This document specifies the required invariants and test criteria; it does not mean the isolation features are implemented.
- [x] Add host-testable address-space-root construction/validation and an ownership-carrying active-to-inactive root transition API. Demotion rejects an observed CR3 root that still names the root being demoted; the unsafe caller must independently guarantee a real switch and completed TLB invalidation.
- [x] Integrate and QEMU-test runtime address-space switching and inactive-root teardown in the kernel under the documented single-CPU, maskable-interrupts-disabled contract. The implementation preflights the private lower-half tree and mapping registry in both directions, unmaps registered user pages, re-zeroes data frames before allocator reuse, reclaims root/level-owned intermediate tables bottom-up, retries detached-table release failures, and refuses to release a root while private table ownership tokens remain.

  PR #31's normal-boot QEMU path exercises A -> B -> A switching at CPL 0 with distinct data frames for the same virtual address, rejection of representative corrupted page-table states, and one-shot table-release failure/retry. The PR description records the required CI suite passing for reviewed HEAD `7ad7cf5853560710eb92fcae03b611a8a6db2060` ([CI run #40171726440](https://github.com/musashimusashino666/one-os/actions/runs/40171726440)). This closes the inactive-root teardown implementation slice only; it does not establish Ring 3 entry/return, process isolation, kernel-enforced capabilities, alias-wide W^X, SMP, or remote TLB shootdowns. See [ADDRESS_SPACE_TEARDOWN_PLAN.md](ADDRESS_SPACE_TEARDOWN_PLAN.md).

- [ ] Implement a kernel-controlled ring 3 entry/return path with validated registers, selectors, user stack, and a kernel entry stack.
- [ ] Create independent user address spaces while keeping any required shared kernel mappings supervisor-only; prevent user access to page tables and recursive aliases.
- [ ] Add adversarial QEMU tests proving user code cannot read, write, or execute kernel-only memory or another process's private frames, including same-virtual-address/different-frame cases. Explicitly test ring-3 instruction fetch from a present supervisor-only executable page (require #PF vector 14, CR2 and saved RIP equal to the target VA, exact error code `0x15`) and instruction fetch of code mapped only in another process (require exact non-present instruction-fetch fault `0x14`). For both cases, the #PF handler must validate the user exception frame and redirect RIP to a validated user-mode recovery stub; that stub must re-enter the kernel through a dedicated DPL-3 test interrupt using the TSS kernel entry stack. Only the second, validated kernel entry may emit the unique marker and trigger the required `isa-debug-exit` status. See the fault recovery protocol in [ISOLATION_PLAN.md](ISOLATION_PLAN.md).
- [ ] Verify effective U/S, R/W, NX, CR0.WP, EFER.NXE, and address-space-switch/TLB behavior, and enforce physical-frame-wide W^X across all aliases: reject writable and executable aliases of the same frame in either mapping order and across address spaces; account for kernel/direct-map aliases and overlapping large-page mappings; allow write-to-execute transitions only after every writable alias is removed or downgraded and required TLB invalidation completes; keep the existing M1 suite green on the exact PR head.

  Implementation note: the bounded ELF64 PT_LOAD audit now validates every page in each load segment and cross-checks read-only file-backed pages against p_offset-derived physical frames (with an explicit exception for a partial page copied to zero BSS). This is a boot-mapping verification slice, not completion of Issue #26. The fixed-capacity `FrameWxRegistry` still is not connected to concrete kernel mapping paths and cannot discover boot/direct-map aliases by itself. All writable/executable aliases—including physical-memory-offset, shared roots, and 2 MiB/1 GiB overlaps—must be inventoried and transitioned transactionally before the kernel may authorize executable publication; the kernel continues to fail closed.
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
