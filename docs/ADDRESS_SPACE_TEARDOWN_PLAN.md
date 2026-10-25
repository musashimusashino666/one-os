# Kernel-Backed Inactive Address-Space Teardown

## Status

Implemented on `main` by [PR #31](https://github.com/musashimusashino666/one-os/pull/31). The kernel now has a `KernelInactiveAddressSpaceEditor` bound to one initialized, inactive root; it accesses owned frames through a validated active-root physical-memory-offset alias and validates the lower-half tree against root/level-scoped table ownership records.

The normal-boot QEMU lifecycle path switches between independent roots that map the same user virtual address to distinct frames, rejects representative ownership/tree corruption before mutation, switches away before teardown, removes registered user pages, re-zeroes returned data frames, reclaims private intermediate tables bottom-up, and verifies the peer mapping is unchanged. A one-shot allocator-release failure verifies that a detached table token remains registered and can be reclaimed on retry. These checks exercise CPL 0 mapping management; they do not enter Ring 3 or prove process isolation.

The PR description records the full required CI suite passing for reviewed HEAD `7ad7cf5853560710eb92fcae03b611a8a6db2060` ([CI run #40171726440](https://github.com/musashimusashino666/one-os/actions/runs/40171726440)). Treat this as evidence for the configured tests only, not as proof of all corruption states, all hardware behavior, or production security.

Roadmap M2 remains incomplete until Ring 3 entry/return, adversarial process-isolation tests, frame-wide W^X, kernel-enforced capability checks, scheduler/IPC acceptance criteria, and the other documented requirements are satisfied. SMP and remote TLB shootdowns remain out of scope for this single-CPU implementation.

## Implemented scope

PR #31 implements a kernel-controlled teardown path for one initialized, inactive address-space root under the existing single-CPU, maskable-interrupts-disabled model. It:

- connect `UserAddressSpaceEditor` to a concrete kernel editor bound to one inactive `AddressSpaceRoot`;
- safely access existing page-table frames in that root, not only the current CR3 recursive mapping or unpublished table frames;
- remove every registry-owned user data leaf through `unmap_all_user_data_pages`;
- reclaim only private, detached intermediate tables owned by the target address space;
- release the PML4 root only after every user mapping and private child table has been detached and its ownership reconciled;
- fail closed and retain any ownership token whose release or structural state is uncertain.

Out of scope: Ring 3 entry/return, scheduling, IPC, capability enforcement, SMP, preemption, remote TLB shootdowns, and system-wide W^X.

## Required invariants

### Address-space state

1. The target root must be initialized, allocator-owned, and inactive before teardown starts.
2. The target root must not alias the active CR3 root. Recheck hardware CR3 immediately before destructive operations.
3. The target's private recursive PML4 index must resolve to its own root frame and have supervisor-only, writable, non-executable permissions.
4. The caller must serialize teardown against mapping, allocation/freeing, root activation, and any other page-table mutation.
5. Keep maskable interrupts disabled for the whole operation until a stronger synchronization protocol is implemented.

### Table access and ownership

1. Bind the editor to exactly one target root; do not accept arbitrary table addresses merely because they are canonical or allocator-allocated.
2. Before dereferencing a table frame, validate alignment, CPU physical-address width, full-frame region coverage, allocator ownership, and table-frame registry state.
3. For tables not reachable through the active root's recursive mapping, use only a validated supervisor-only, writable, NX physical-memory-offset alias. Walk the active root to prove the complete alias maps the exact expected physical frame.
4. The target root's lower canonical half is private. Every present intermediate entry must point to an owned page-table frame and must not create cycles, recursive aliases, large-page overlaps, or shared private tables.
5. Validate user data mappings in both directions: every present user PTE must point to the exact physical frame retained by the same root's mapping registry, and every registry entry must resolve to a present PTE with that same physical frame and expected permissions. A mere virtual-address registration match is insufficient.
5. Never free bootloader-owned tables, kernel-half shared tables, the active root, or a frame whose registry state is ambiguous.
6. A published intermediate table may be released only after every parent reference to it has been removed, no root can reach it, and the required local/global TLB invalidation contract is satisfied.

### TLB and frame lifetime

1. The target root must be inactive. The CR3-switch path must have rejected PCID and completed its documented global/non-global flush sequence before a formerly active root becomes eligible for teardown.
2. A local `INVLPG` under a different CR3 is not proof that a stale translation for the inactive target root was invalidated. Document and test the inactive-root precondition instead.
3. Each leaf mapping must be removed and ownership retained until the teardown contract proves no stale translation can access the former frame.
4. Do not return a removed data frame to the allocator until its leaf is cleared, the inactive-root/TLB precondition is satisfied, and the mapping registry no longer owns it.
5. Every user data frame removed from a process must be re-zeroed through `UserFrameInitializer` before it can be published to any later user mapping.

### Failure semantics

1. Preflight all registry mappings and the private table tree before the first destructive update.
2. A detected preflight error must not change a PTE, registry entry, or frame ownership.
3. If a hardware/editor operation fails after mutation starts, return explicit partial progress and preserve every returned frame token. Keep unprocessed mappings and table ownership recoverable for a retry or fail-stop recovery.
4. Do not free the root or any intermediate table after uncertain CR3 state, failed parent detachment, failed table verification, or uncertain TLB state.
5. Prefer a deliberate leak over releasing a frame that may still be referenced.

## Implementation record

1. Add a concrete inactive-root editor in the kernel. Its root identity and recursive index are fixed at construction and revalidated before destructive mutation.
2. Add an ownership-aware lower-half table walker that preflights the complete private subtree. Reject malformed entries, user leaf mappings not represented in the matching registry, aliases/cycles, large-page entries, unowned tables, and table-count exhaustion.
3. Connect the kernel editor to `unmap_all_user_data_pages`; preserve the core API's preflight and partial-progress semantics.
4. Detach child tables bottom-up only after confirming each subtree is empty. Extend the frame registry with an explicitly unsafe or otherwise tightly scoped transition for releasing a formerly published table, and document the proof obligations at the kernel call site.
5. Zero and verify table frames before relinquishing them where required by the kernel's reuse policy. Release each frame only through the allocator that issued its token.
6. Add a kernel-backed test image that constructs two independent inactive roots with distinct user frames, tears one down, and verifies the other remains unchanged.
7. Add failpoint coverage for bad registered translations, foreign/unregistered child tables, allocation/registry exhaustion, mid-teardown failure, and release failure.
8. Keep all existing M1 QEMU acceptance tests green on the same candidate commit.

## Regression and acceptance checklist

The items below are the regression contract for future changes to this subsystem. PR #31 added the described host and QEMU coverage, and its reviewed HEAD passed the documented CI suite. Keep the overall M2 milestone open: this checklist does not establish Ring 3 isolation, frame-wide W^X, SMP safety, or production readiness.

- `cargo fmt --all -- --check`
- `cargo test --locked -p oneos-core`
- all existing Clippy, bare-metal kernel check/build, CR3 assembly validation, normal boot, exception, IST, supervisor-write, NX, and VM-transition CI checks
- QEMU success case: create a private user mapping, switch away, tear it down, and prove that the frame is not reused before teardown completes
- QEMU isolation case: roots A and B use the same virtual address for different physical frames; tearing down A must not modify B's mapping or data
- QEMU dirty-frame case: write a non-zero pattern through A, tear down A, reuse the physical frame for B only after full zero initialization, and verify every byte/word seen by B is zero
- preflight failure: inject a root self-reference, an intermediate large-page flag, a non-present leaf, and a user leaf pointing at a registered page-table frame; prove each is rejected, restored, and followed by a successful read-only preflight
- bidirectional user-map ownership: inject another address space's allocated data frame and target/foreign PML4 frames into a registered user PTE, and delete a registered PTE; each mutation must be rejected before root activation or teardown, with the entry restored and a later valid preflight succeeding
- reverse registry validation: a present PTE must match the frame token for its VA, and every registry token must have a present translation at the expected VA; neither extra PTEs nor stale registry-only mappings may pass preflight
- bottom-up reclamation: verify private intermediate tables are released exactly once after becoming unreachable, while shared kernel tables and the active root remain allocated
- release failure/retry: fail the first intermediate-table release after parent detachment, verify the detached token remains root-owned and pending, retry through the production allocator, then release the root only after no root-owned table token remains
- partial failure: all returned data/table ownership tokens remain visible and no unprocessed mapping is falsely marked complete
- malformed state: invalid root, active target root, invalid recursive entry, malformed/non-present entry encodings, cycles, and large-page conflicts fail closed
- all success markers are emitted only after the relevant kernel-side assertions; timeout, panic, wrong QEMU exit status, missing/duplicate marker, or ordinary bootstrap-completion output must fail the validator.

## Non-goals and reporting

Passing these tests demonstrates only the stated single-CPU QEMU cases. It does not establish SMP safety, remote TLB shootdown correctness, Ring 3 process isolation, kernel-enforced capabilities, complete alias-wide W^X, production security, or physical-hardware correctness.

Keep the overall M2 milestone open until user entry/return, adversarial process-isolation tests, scheduler/IPC, and kernel-enforced capability checks meet their own acceptance criteria.
