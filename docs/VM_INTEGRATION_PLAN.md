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

### Page-table access and recursive mapping address resolution

A physical page-table frame address alone is not enough to derive its recursive-map
virtual address. The editor must receive enough path context to identify the table
being accessed. Do not leave this as implicit, mutable out-of-band state.

- Each `map_4k` / `unmap_4k` operation is for one target virtual address. Extend the
  editor callback contract to carry that target virtual address and the current table
  level (or pass an equivalent validated access-path value). Update host test backends
  if the `PageTableEditor` trait is changed.
- For a table already reachable through the active four-level page-table hierarchy,
  derive its recursive alias with
  `recursive_table_page_virtual_address(recursive_index, target_virtual_address, level)`.
  This helper computes the virtual address of the paging-structure page at the given
  level from the target VA's path; it does not reverse-map an arbitrary physical address.
- Derive the entry pointer by checked addition of `entry_index * size_of::<u64>()`
  to that table-page virtual address. Check multiplication/addition overflow, canonical
  form, alignment, valid level/index, and the recursive index before dereferencing.
  The PML4 frame must match CR3. At lower levels, the walker follows entries selected
  by the target VA and passes the child physical frame it just read; reject malformed
  entries, unavailable tables, and repeated physical frames rather than continuing with
  a mismatched or cyclic walk.
- The recursive alias only resolves tables already reachable via the path. A newly
  allocated table frame is not reachable through the recursive mapping until linked
  into a parent entry. Access such unpublished frames through the bootloader-provided
  physical-memory offset only when the frame came from the Usable-only allocator, the
  offset is present, all address arithmetic is checked, and the complete frame is in
  the approved region. Never use that alias as a general-purpose way to access
  Bootloader-owned or unknown frames.
- If the editor cannot establish a safe virtual alias for the exact table it was asked
  to access, it must fail closed before publishing a new mapping. Do not assume a
  physical address can be dereferenced as a virtual address.
- Keep the editor's access logic in one implementation and document the safety
  invariants for each unsafe pointer operation.

### Frame ownership, registry capacity, and publication

- Preserve each page-table allocation's `Frame` token. Do not discard the token after
  reading its physical address: dropping it leaks the allocation by design and loses
  the ability to release it correctly.
- The ownership registry must have an explicit capacity and a checked reservation
  path. Before allocating a table frame, reserve a registry slot. If no slot is
  available, return allocation failure without taking a physical frame. If frame
  allocation fails after a slot was reserved, release that empty reservation.
  Store the returned `Frame` token and physical address in the reserved slot before
  returning the physical address from `allocate_table`.
- `allocate_table` must fail closed when either registry capacity or physical frame
  capacity is exhausted. Never return a physical table frame to the core primitive
  unless the editor already retains its ownership token.
- The core primitive allocates all missing intermediate tables before starting its
  page-table writes. If a later allocation/registration fails, every earlier
  unpublished allocation must be released exactly once and the page-table tree must
  remain byte-for-byte unchanged. A registry-capacity failure is the same class of
  pre-publication failure as a physical allocation failure.
- Before active-kernel integration, ensure that newly created intermediate tables are
  fully initialized before they become reachable. Prefer staging all new table
  contents in unlinked frames and publishing the highest missing parent entry only
  after every fallible operation has completed. If the core primitive's publication
  order is changed to support this, retain its existing host-test guarantees for
  rollback, W^X, permissions, and recursive-reference rejection.
- On successful mapping, keep the tokens for published intermediate tables in the
  registry for their full reachable lifetime. On rollback, remove the matching
  unpublished registry entry and free its token exactly once. If an operation requests
  an unknown, duplicate, or already-published frame through the rollback-only
  `free_table` path, do not free it; treat this as an invariant violation and fail
  closed. If the trait is made fallible, propagate and test that error instead.
- The current `PageTableEditor::free_table` callback returns no result. If that
  signature is retained, the concrete editor must fail-stop on an invalid release
  request rather than silently releasing a foreign frame. Consider a fallible
  signature if recovery from editor-internal inconsistencies is required.
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

1. Extend the editor contract with explicit target-VA/table-level path context so the
   recursive alias is derived deterministically, rather than guessed from a physical
   address.
2. Implement checked recursive-alias addressing for reachable tables and a separate,
   checked physical-memory-offset path for freshly allocated, still-unpublished Usable
   frames.
3. Implement registry-slot reservation and Frame-token retention before returning each
   newly allocated table frame; ensure registry exhaustion rolls back without mutation.
4. Stage new intermediate-table contents before publishing the highest missing parent
   entry. Keep the commit/publish portion free of fallible allocation or validation work.
5. Establish and verify `CR0.WP` and `EFER.NXE`; fail before mutation if a required
   precondition is missing. Integrate `map_4k` / `unmap_4k` without weakening tested
   core semantics.
6. Add dedicated QEMU memory test images. Keep fault-injection code out of the normal
   BIOS image.
7. Run the full CI workflow on the exact final PR head and document observed results
   and limitations.

## Acceptance tests

### Host tests

- Preserve and run every existing `oneos-core` test.
- Test the recursive-alias helper with each page-table level and multiple target VAs,
  including canonical boundaries, invalid indices/levels, checked entry-offset
  arithmetic, and alignment requirements.
- Test the concrete editor's ownership registry and lifecycle using a test backend:
  fresh frames are zero-filled, tokens are retained before publication, failed
  allocations are returned exactly once, and foreign/double releases fail closed.
- Test registry exhaustion when no slot is available before allocation and when
  capacity is insufficient for a mapping requiring multiple intermediate tables.
  The failure must leave all pre-existing table entries unchanged, remove all
  reservations, and return every physical frame acquired by that operation exactly
  once. Include allocation/free counters or equivalent ownership assertions.
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
