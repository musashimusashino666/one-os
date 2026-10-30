# Boot and Physical Memory Specification

## Purpose and scope

This specification records the current bootstrap and paging contract, then names the gaps that must be closed before it can be treated as a general memory-management design. It applies to the current x86_64, four-level paging, BIOS/QEMU implementation.

## Boot input validation

- BootInfo and the bootloader memory map are untrusted structured inputs to be validated before use.
- Memory-map entries with empty, inverted, overflowing, or overlapping ranges are rejected.
- Physical addresses and virtual addresses are checked for alignment, canonicality, and supported physical-address width before page-table access.
- Any backing metadata used for a memory read must be validated for its mapping, permissions, and ownership before dereferencing it.
- The kernel's first read through the bootloader-reported recursive PML4 slot relies on the bootloader API contract. That assumption must remain explicit; the kernel cannot prove the first alias safe before using it.

## Physical-frame allocator

Current rules:

- Only regions reported as Usable by the bootloader are candidates for allocation. Bootloader-owned and unknown firmware regions remain reserved.
- Region bounds are rounded inward to full 4 KiB frames; physical frame zero is excluded.
- Allocator initialization fails closed if validated ranges or fixed metadata capacity are insufficient.
- The current bitmap supports up to 16 GiB aggregate usable memory across at most 256 usable regions.
- Loaded kernel PT_LOAD frames discovered within usable regions, plus validated Usable-backed bootstrap metadata and stack frames, are reserved before allocation can return them.
- Ownership tokens identify managed frames. Foreign or stale tokens must be rejected.

These fixed capacities are implementation limits, not permanent architectural requirements. A change to them needs tests for exact boundaries and exhaustion.

## Kernel image and boot mapping checks

The inspector validates every 4 KiB page intersecting each bounded ELF64 PT_LOAD memory range for translation, physical backing, effective user/supervisor, writable, and NX permissions. It handles GNU_RELRO and verifies p_offset-derived physical correspondence for read-only file-backed pages, excluding the documented partial BSS-tail case.

The active stack, BootInfo, and the separately backed memory-region array are checked page by page for writable, supervisor-only, NX mappings and valid backing ownership. Usable-backed frames discovered by these checks are reserved.

These checks do not inventory every boot mapping or every physical alias. Their success must not be described as global memory integrity.

## Page-table mutation contract

- The current mutation model is single CPU with maskable interrupts disabled.
- Mutation preconditions include the expected active root, validated table ownership, canonical/aligned virtual addresses, supported physical addresses, legal parent permissions, and correct frame tokens.
- Mapping publication, removal, invalidation, ownership retirement, and frame release are separate phases.
- TLB invalidation must complete before resources that may still be referenced are reclaimed.
- The current editor is limited; it is not a general-purpose virtual memory manager.
- Empty intermediate table reclamation during every ordinary single-page unmap, SMP synchronization, remote TLB shootdown, PCID support, and general address-space concurrency are not established.

## W^X and executable mappings

The intended rule is that a physical frame must not be effectively writable through one alias and executable through another, within the declared security model.

Current implementation derives executable physical pages from validated ELF PT_LOAD translations and changes their physical-memory-offset aliases to read-only/NX before activating the private kernel root. Large-page demotion, break-before-make, local invalidation, and selected QEMU access checks are present. The read-only audit is bounded to declared roots and sources; zero observed conflicts is not proof of global completeness. The executable-alias transition path now preflights every executable PT_LOAD page and its physical-memory-offset translation before changing the first alias, preventing a late missing or malformed translation from leaving only a prefix transitioned. This is a preflight-ordering guarantee, not an atomic transaction over all alias sources or rollback guarantee after a mutation-stage failure, and it does not classify every unexpected bootloader mapping.

Arbitrary new executable mappings remain gated. Global frame-wide alias coverage is still open in [Issue #26](https://github.com/musashimusashino666/one-os/issues/26) and [Issue #46](https://github.com/musashimusashino666/one-os/issues/46).

## Acceptance requirements for extensions

Any memory-management change must add or update:

1. Host tests for malformed input, overflow, boundary and capacity conditions.
2. Ownership tests for foreign, stale, duplicate, and retained tokens.
3. Failure-injection tests proving no premature publication or release.
4. QEMU tests for actual page-table behavior and exact fault metadata where relevant.
5. TLB and alias tests covering every supported page size and root in scope.
6. Documentation of assumptions, audit coverage, and unimplemented cases.

A successful compilation is not sufficient acceptance evidence.
