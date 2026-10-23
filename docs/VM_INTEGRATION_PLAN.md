# Kernel Virtual-Memory Integration Plan

## Status

This document defines the implementation contract and acceptance tests for integrating
the host-testable page-table mutation primitives into the active x86_64 kernel. It is
a plan, not evidence that kernel-enforced memory protection exists. M1 remains open
until the integration and QEMU acceptance tests pass.

## Current baseline

- `oneos-core` provides host-testable `map_4k` and `unmap_4k` operations through
  `PageTableEditor`.
- The mutation helpers validate four-level canonical addresses, alignment, physical
  address width, ancestor permissions, and large-page conflicts; enforce W^X at the
  leaf; and roll back intermediate-table allocations on allocation failure.
- `kernel/src/paging.rs` currently inspects existing bootloader mappings read-only.
  It does not invoke the mutation helpers.
- `kernel/src/memory.rs` allocates physical frames from bootloader-designated Usable
  memory. A returned `Frame` is an owned, non-`Copy` token; its physical address
  alone is not the ownership token.
- The kernel currently checks `CR0.WP` during inspection. The mapping integration must
  separately establish the `EFER.NXE` precondition before relying on NX entries.
- The existing QEMU tests validate boot and selected exception diagnostics; they do
  not yet validate map/unmap against the active page tables.

## Goals

1. Use the existing tested mutation algorithms instead of duplicating paging logic in
   the kernel.
2. Add a concrete kernel `PageTableEditor` whose reads and writes are valid for the
   physical table frames and paging levels it receives.
3. Preserve unique ownership of newly allocated page-table frames for as long as the
   tables remain reachable.
4. Establish and check CPU-state, physical-address-width, synchronization, and TLB
   invalidation requirements at the kernel boundary.
5. Validate successful mapping and unmapping, translation and permission outcomes,
   and fail-closed behavior with reproducible host and QEMU tests.

## Required design decisions and invariants

### Page-table access

- Use the bootloader-provided recursive mapping to access page-table frames that are
  already reachable through the active page-table hierarchy, with the existing
  canonical-address, index, alignment, and ownership checks.
- Newly allocated table frames must be zero-filled before they are published into a
  parent entry. Because these frames come from the frame allocator's Usable regions,
  any use of the bootloader-provided physical-memory offset must follow that API's
  accessibility contract, check arithmetic for overflow, and never be generalized to
  Bootloader-owned or unknown frames.
- Do not assume a physical address can be dereferenced as a virtual address.
- Keep the editor's access logic in one implementation and document the safety
  invariants for each unsafe pointer operation.

### Frame ownership and lifetime

- Preserve each page-table allocation's `Frame` token. Do not discard the token after
  reading its physical address: dropping it leaks the allocation by design and loses
  the ability to release it correctly.
- The editor must keep tokens for successfully published intermediate tables in an
  ownership registry or equivalent structure. `free_table` must release only a frame
  owned by that editor and must return an error, or fail closed, for unknown frames.
- Failed, unpublished allocations must be released exactly once. A failed operation
  must not leave published entries pointing to a frame that has been returned to the
  allocator.
- Distinguish page-table frames from mapped data frames. `unmap_4k` clearing a leaf
  must not automatically free the mapped physical frame unless the caller can prove
  that the mapping owns that frame.
- The current `unmap_4k` primitive intentionally retains empty intermediate tables.
  Document this capacity cost. Reclaiming empty tables requires a separately reviewed
  ownership and reachability procedure; do not free a table still referenced elsewhere.

### CPU state, physical addresses, and permissions

- Query the active CPU's supported physical-address width and pass the validated
  value to `PageTableEditor::physical_address_bits`; reject unsupported or
  inconsistent results rather than assuming 52 physical-address bits.
- Establish and verify `CR0.WP` before treating read-only mappings as protection
  against supervisor writes.
- Establish and verify `EFER.NXE` before installing mappings whose NX bit is set.
  If a required CPU feature is unavailable, fail closed before changing active tables.
- Retain the existing W^X policy. Never widen existing ancestor permissions to make a
  requested mapping succeed.
- Serialize page-table mutations. The bootstrap currently has a single CPU with
  maskable interrupts disabled; encode that as an explicit temporary precondition
  rather than pretending it provides SMP safety. Before SMP, add cross-CPU coordination
  and shootdowns.
- Invalidate the local TLB as required after changes, especially unmaps and permission
  changes. Document that local invalidation is not sufficient for future shared
  address spaces on multiple CPUs.
- Do not treat a successful page-table entry write as proof that the CPU is enforcing
  the intended permissions; test the hardware-visible behavior.

## Suggested implementation sequence

1. Add a kernel-side editor abstraction and write down its table-address translation,
   allocation, zeroing, token-retention, and error-handling contracts.
2. Add read/write support for entries through the recursive mapping and a checked
   implementation for `MAXPHYADDR`.
3. Add owned page-table frame allocation with rollback on all pre-publication failures.
4. Establish and verify `CR0.WP` and `EFER.NXE`; fail before mutation if either
   required precondition is missing.
5. Integrate `map_4k` / `unmap_4k` without changing the algorithm's tested semantics.
6. Add a dedicated QEMU memory test image. Keep fault-injection code out of the normal
   BIOS image.
7. Run the full CI workflow on the exact final PR head and document observed results
   and limitations.

## Acceptance tests

### Host tests

- Preserve and run every existing `oneos-core` test.
- Test the concrete editor's ownership registry and lifecycle using a test backend:
  fresh frames are zero-filled, tokens are retained after successful publication,
  failed allocations are returned exactly once, and foreign/double releases fail
  closed.
- Test that no leaf-data frame is freed merely because its mapping was removed.
- Test that invalid CPU capability data or a missing required control-state precondition
  prevents mutation.

### QEMU integration tests

Use dedicated test images and serial-log validators. A normal boot must remain a
separate path and must still pass the existing repeated-boot and exception checks.

- Map one allocated data frame into a reserved, previously unmapped canonical virtual
  address; verify the translation, page offset, and effective permissions.
- Write and read a sentinel only through a deliberately writable, non-executable test
  mapping, then unmap it and verify that the virtual address is no longer mapped.
- Verify W^X rejection and that no existing ancestor permissions are widened.
- In a dedicated fault-injection image, attempt a supervisor-mode write through a
  read-only mapping and require a page-fault diagnostic with the expected fault
  address. The test must not emit the normal bootstrap-completion marker.
- Verify allocation/translation failures halt or return through the documented error
  path without publishing dangling entries or incorrectly freeing owned frames.
- Validate TLB invalidation behavior for the tested unmap/permission-change cases.
- Run formatting, all core tests, Clippy with warnings denied, kernel checks, image
  creation, the serial-log unit tests, repeated normal boots, exception tests, and the
  new memory-specific QEMU tests.

## Exit criteria

M1 may be marked complete only after the active-kernel integration and dedicated QEMU
mapping/protection tests pass on the exact reviewed commit. Host-side algorithm tests
alone, compilation alone, or successful normal boots do not satisfy this milestone.
Document any still-unimplemented reclaim policy, SMP requirement, or untested hardware
behavior without weakening the acceptance criteria.
