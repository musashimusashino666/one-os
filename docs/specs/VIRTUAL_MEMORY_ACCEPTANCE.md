# Virtual-Memory Integration and Acceptance Contract

## Status

The current kernel has a guarded page-table editor and selected QEMU acceptance paths. This document defines the implementation contract and required evidence. It does not claim that the kernel is a general-purpose virtual-memory manager or that global frame-wide W^X is complete.

Current assumptions: x86_64, four-level paging, one CPU, maskable interrupts disabled during mutation, PCID disabled, and the declared QEMU test profile in [Verification Strategy](../engineering/VERIFICATION.md).

## Safe access to page tables

A physical address alone is not enough to derive a recursive-map virtual address. For an already reachable table, resolve its alias using the recursive index, target virtual address, and current table level. Check canonicality, alignment, valid level/index, checked multiplication and addition, expected CR3 root, and the child physical frame actually found by the walk.

Reject malformed entries, absent/unavailable tables, repeated physical frames, cyclic walks, and any mismatch between expected and observed table identity. A recursive alias resolves tables already reachable through the selected path; it does not make an unlinked frame reachable.

An unpublished page-table frame may be accessed through the physical-memory offset only when it has been allocated from a validated Usable region, the offset exists, every address calculation is checked, and the complete page is contained in the allowed range. Never use this mechanism as a generic way to dereference Bootloader-owned or unknown physical frames.

The concrete editor must preflight every write destination before the first page-table entry changes: frame identity and ownership, level/index, target table-page alias, alignment, arithmetic, and effective writable access. All fallible validation, allocation, and ownership reservation must finish before publication. After successful preflight, an unexpected store fault must fail-stop; it must not report success or continue with a partially changed hierarchy.

## Frame ownership and publication

- Reserve ownership-registry capacity before physical-frame allocation.
- If the registry is full, reject before taking a frame.
- If allocation fails after a reservation, release the empty reservation.
- Retain the non-Copy ownership token for every allocated table frame for its entire published lifetime.
- Initialize every unlinked child table before making it reachable.
- If any pre-publication step fails, release each unpublished allocation exactly once and leave the prior page-table tree unchanged.
- Published table frames remain registered until a reviewed detach/invalidation/reclaim transaction completes.
- Reject duplicate, unknown, foreign, stale, or already-published release tokens; never release a data frame merely because a leaf was unmapped.
- The existing 4 KiB unmap primitive may retain empty intermediate tables. Reclamation requires a separate reachability and ownership proof.

## CPU and permission preconditions

Before relying on the page-table contract, verify the required CPUID leaves and physical-address width, NX support, CR0.WP, EFER.NXE, and the expected paging mode. The current root activation contract also requires CR0.PG, CR0.WP, EFER.NXE, CR4.LA57=0, CR4.PCIDE=0, and RFLAGS.IF=0. Fail before mutation if a required precondition is absent or inconsistent.

Effective permissions must be computed across every ancestor and leaf entry:
- Writable requires the writable bit through the full walk.
- User accessibility requires U/S permission through the full walk; a supervisor-only leaf remains supervisor-only.
- Executability requires NX=0 across the full walk.
- Never widen ancestor permissions as a shortcut to satisfy a mapping request.
- New lower-half intermediate entries may be user-accessible only under the process-address-space policy. Shared upper-half kernel entries must remain supervisor-only.

The kernel stack, BootInfo, memory-region metadata, and exception stacks have explicit ownership and permission requirements. Static IST stacks are not guard-page protected unless guard mappings are implemented and tested.

## TLB and transaction ordering

Every successful map, unmap, permission downgrade, root switch, or large-page transition must perform the architecture-appropriate invalidation before code depends on the new translation or a potentially referenced frame is reused. Installing a previously absent mapping must account for cached non-present translations. Local invalidation is not an SMP protocol.

Large-page demotion must preserve physical offsets and unrelated permissions/cache/PAT attributes, reserve child-table ownership before publication, use A/D-aware compare-exchange for hardware-updated entries, perform break-before-make, invalidate the full affected local range, and fail-stop if Present is cleared and a safe replacement cannot be committed. Never publish a partly initialized child table.

## W^X policy

A clean bounded audit is not proof of global W^X. A complete audit must explicitly enumerate the activatable roots and relevant mapping sources, calculate effective permissions, compare physical extents including 4 KiB/2 MiB/1 GiB overlaps, and account for direct-map, recursive-table, inherited, and managed aliases.

The current declared-scope implementation captures the active root and registered live kernel-created roots, walks the active tree and each inactive root's private lower half, verifies shared upper-half entries, and checks writable recursive aliases against the full ordinary-leaf inventory. Within the bounded walker, a table frame may be visited only once; cycles or a duplicate table frame reachable through another path invalidate the audit. The table-path inventory is capped at 2,048 frames, the table-visit budget at 16,384, and the W/X-range inventory at 128 entries. Any limit or structural error is an incomplete audit, not a clean result. These mechanisms do not independently prove that the root registry is authoritative beyond the current kernel lifecycle contract, nor do they prove that every bootloader-created mapping matches an expected map.

Arbitrary new executable mappings remain denied until complete alias accounting and the permission-transition contract are proven. The boot path currently transitions aliases for validated executable ELF PT_LOAD pages to read-only/NX and verifies selected properties; Issues [#26](https://github.com/musashimusashino666/one-os/issues/26) and [#46](https://github.com/musashimusashino666/one-os/issues/46) remain the authority for global coverage.

## Host acceptance tests

The core and editor tests must include:
- Recursive alias resolution for each level and multiple VAs, canonical boundaries, invalid indices/levels, alignment, and arithmetic overflow.
- Registry full-capacity behavior before allocation; token retention and exactly-once release; duplicate/foreign release rejection and slot reuse.
- Allocation failure at each intermediate-table depth, with unchanged root entries and reverse-order release of unlinked frames.
- Zeroed table pages before publication.
- Unmap returning the detached leaf physical address/permissions without freeing or registering the leaf frame as a table.
- NX/physical-width/CPUID/CR0.WP/EFER.NXE precondition validation, including unsupported-state cases.
- Malformed large-page alignment/reserved bits and PAT/permission preservation during demotion.
- A/D-bit monotonic update, hardware A/D changes, unexpected entry mutations, and bounded CAS retry exhaustion.
- W^X detection on same-frame aliases and large-page physical overlap, including budget exhaustion with a distinct incomplete-audit result.

## QEMU acceptance tests

Keep fault-injection images separate from the normal BIOS image. The normal page-fault handler remains fail-stop; recoverable faults are allowed only in dedicated tests with a narrowly armed expected-fault state.

Required current acceptance paths include:
- Three independent normal boots with exact startup and bootstrap-completion markers.
- Supervisor write to a read-only page: verify the expected present/write/supervisor fault code `0x3` in the declared profile.
- NX instruction fetch: verify the expected fault code `0x11` in the dedicated image.
- Not-present-to-present and unmap-to-remap transitions using controlled recovery; validate the target VA, access type, exact fault metadata, unique event count, translation, and immediate post-change access.
- Map/access/unmap operations, W^X rejection, and proof that ancestor permissions are not widened.
- Root activation and selected root-switch/teardown checks under the single-CPU contract.
- Live large-page demotion with mapping access, permission preservation, sibling-frame writability, and local invalidation checks.
- Direct-map permission change for validated executable kernel pages and a read-only runtime W^X audit over its explicitly declared scope.
- Serial validator tests for panic, missing or duplicate markers, invalid-map markers, unexpected exit status, timeout, incomplete audit, and unexpected completion markers.

Never make the normal kernel page-fault path generally recoverable merely to support a test. Each expected fault must match the armed phase and complete expected context; any unexpected/nested/mismatched fault must fail-stop.

## Reporting gate

Record the exact candidate SHA, CI run, guest profile, required test outcomes, and any artifacts or limitations. A successful build, host test, normal boot, or bounded audit alone does not complete the virtual-memory milestone.
