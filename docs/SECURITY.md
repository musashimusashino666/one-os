# Security Coverage Entry Point

This file is a short entry point for the memory-protection coverage required by Issues [#26](https://github.com/musashimusashino666/one-os/issues/26) and [#46](https://github.com/musashimusashino666/one-os/issues/46). The normative threat model and detailed limits remain in [Security Model](architecture/SECURITY_MODEL.md) and [Virtual-Memory Acceptance](specs/VIRTUAL_MEMORY_ACCEPTANCE.md).

## Current W^X audit scope

The read-only audit captures the active page-table root and registered live kernel-created roots, reports the physical address and completion status of each declared root, walks the active tree and private lower halves, verifies shared upper-half entries, and accounts for writable recursive-table aliases against the completed ordinary leaf inventory. Effective R/W, U/S, and NX permissions are folded across every ancestor and leaf. The expected physical-memory-offset mapping is checked contiguously and offset-correctly from physical address zero through the page-rounded greater of 4 GiB and the highest boot memory-map end; executable direct-map leaves are rejected.

The audit is bounded: the writable/executable range inventory is capped at 128 records, table visits at 16,384, and recursive-alias and duplicate-table-path inventories at 2,048 entries each. Duplicate/cyclic table paths, malformed leaves, direct-map gaps or translation mismatches, an invalid root snapshot, and capacity exhaustion fail closed. Source-coverage flags are accepted only after the root inventory is sealed and every declared root is audited; premature accounting or accounting after a prior failure permanently fails the scope. This ordering guard does not replace source-specific validation. A complete result means the declared walk completed; it is not, by itself, proof of a conflict-free system or coverage of roots/sources outside the declared lifecycle contract.

The dedicated `test-wx-runtime-audit` QEMU path injects a writable/NX alias in a registered inactive root for the same physical page as a controlled active-root RX mapping. It requires the read-only all-root audit to report the cross-root conflict, restores the exact original PTE, and requires a follow-up audit to be complete and conflict-free. It also attempts to unregister both the active root and a still-allocated inactive root; both removals must be rejected and the inactive root must remain present in a complete audit. Separately, the CR3 transition path now refuses to activate a target root unless it is uniquely registered and allocator-owned. The QEMU profile also injects a missing registry entry for an allocated inactive target, verifies that the shared activation guard rejects it before CR3 changes, restores the entry, and then requires the existing complete audit. These checks harden lifecycle invariants for the declared kernel/QEMU scenario; they do not independently prove that every possible root or mapping source is enumerable.

## Remaining security boundary

- Arbitrary executable mapping publication remains denied.
- The audit does not yet prove every bootloader-created mapping category is expected or implement transactional W^X enforcement across every possible alias/source.
- Page-table mutation and local TLB handling assume one CPU, maskable interrupts disabled, and PCID disabled. SMP and remote TLB shootdown/root-lifetime synchronization are unsupported.
- QEMU/CI evidence is tied to an exact candidate revision and is not hardware certification or an independent security review.

See [Roadmap](project/ROADMAP.md) for remaining blockers and the source documents above for the full threat model.
