# Address-Space Lifecycle Contract

## Status

The kernel includes root construction/activation primitives and selected CPL 0 switching and inactive-root teardown smoke paths. This is not a complete Ring 3 process-isolation boundary. Current mutation is single-CPU and requires maskable interrupts to remain disabled; PCID and SMP synchronization are not supported.

## Root states and ownership

An address-space root must have explicit lifecycle state. An initialized inactive root and a hardware-active root are not interchangeable handles. Once CR3 activation has succeeded and been verified, the active handle must not expose a frame token that could make the root reusable while hardware is using it.

A root's private recursive PML4 slot must be validated and retained with the root. Shared upper-half kernel entries must match the active kernel root and remain supervisor-only. Private lower-half entries and intermediate tables require root-and-level-scoped ownership records.

Do not drop or reconstruct ownership tokens from physical addresses. Physical identity alone is not authorization to release a frame.

## Construction requirements

Before publishing a root:
- Validate the source and destination roots, CPU paging state, recursive slot, and all copied/shared entries.
- Preflight all upper-half mappings and verify that execution-critical code, stack, BootInfo, metadata, and exception state are available in the target kernel half.
- Clear or initialize all private lower-half entries in the unlinked destination.
- Keep user mappings absent until the target root and mapping metadata are validated.
- Make every required intermediate table accessible, initialized, and registered before linking it into the tree.
- Leave the old root and registry unchanged if construction fails.
- Never activate a root whose kernel entry, stack, IDT/TSS, BootInfo access, or required mapping set has not been validated.

## Switching requirements

A switch must validate the source/target lifecycle states, root physical address, recursive slot, relevant CPU state, and shared kernel mappings. Every kernel-created target root must have exactly one live-root registry entry, remain allocator-owned, and not be permanently reserved immediately before activation; both allocator and reservation queries must succeed, otherwise the switch is refused. The W^X audit revalidates the same ownership/reservation invariant for every registered root before dereferencing its page tables. Activation must read back CR3 and fail closed if the observed root differs from the requested root.

The supported baseline has one CPU and maskable interrupts disabled. The design must explicitly handle CR3/TLB semantics and cannot assume PCID or a future SMP policy. Root switching tests must demonstrate that two address spaces can map the same user VA to distinct frames, that writes remain private to the selected mapping, and that switching back does not expose stale translations from the other root.

A CPL 0 switch smoke test is not evidence of Ring 3 execution, user-entry validation, or process isolation.

## Teardown transaction

Teardown applies only to a root that is verified inactive. Before the first destructive update:
1. Validate root identity and ownership.
2. Walk and preflight the entire private lower-half tree against the root/level ownership registry.
3. Validate all registered user mappings and ensure no unexpected or unaccounted table is reachable.
4. Establish that the active root is different and that the root cannot be concurrently activated under the current execution model.

Then:
1. Remove registered user mappings using the supported editor.
2. Complete the required TLB/root-switch contract before reusing any data or table frame.
3. Preserve partial-result ownership if an unmap operation fails. Do not discard detached tokens or release the root on error.
4. Zero every detached user-data frame before returning it to the allocator.
5. Reclaim owned private intermediate tables bottom-up after proving that each table is detached and unreachable.
6. Retain a pending ownership record if allocator release fails; allow a controlled retry.
7. Verify no private table ownership entries remain for the root.
8. Release the root frame only after teardown succeeds and the root is proven inactive.

An inconsistency, unknown frame, registry mismatch, or uncertain TLB/lifetime state must fail closed. Do not continue after Present is cleared if the hierarchy cannot be restored to a known-safe state.

## Required tests

- Invalid root, wrong lifecycle state, reused root, malformed recursive slot, or mismatched shared upper-half entry is rejected before mutation.
- Cross-root mapping of the same VA to different physical frames preserves isolation on A → B → A switching.
- Invalid/duplicate/foreign table ownership records prevent teardown before destructive changes.
- An unexpected private table or orphan ownership token prevents root release.
- A one-shot allocator-release failure preserves the detached frame token as pending and prevents reuse; retry can reclaim it.
- Detached user data is re-zeroed before allocator reuse.
- Teardown removes user mappings and reclaims private intermediate tables bottom-up.
- The peer address space remains unchanged throughout teardown.
- Allocation, preflight, unmap, zeroing, and release failure paths retain every still-live ownership token and never release a foreign/active frame.
- Existing VM, W^X, protection, and TLB tests remain green on the same candidate.
- Tests explicitly state that this lifecycle acceptance runs at CPL 0 and does not establish Ring 3 isolation or SMP safety.

## Relationship to global W^X

A complete address-space lifecycle is a prerequisite for complete root inventory and alias accounting, but does not itself prove global W^X. Every activatable root and every relevant physical alias source must be included in the W^X audit contract.
