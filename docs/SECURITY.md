# Security Model and Current Limitations

## Security goals

ONE OS aims to reduce the amount of code that must be trusted, enforce least authority, isolate failures, preserve data confidentiality and integrity, and support auditable recovery.

## Preliminary threat model

Assets to protect:

- user documents and secrets;
- authentication material and cryptographic keys;
- process memory and service state;
- system integrity and update provenance;
- device access, network permissions, and audit records.

Threats in scope for future implementation:

- a malicious or compromised application;
- a compromised user-space service;
- malformed files and protocol input;
- accidental or malicious cross-process access;
- interrupted updates and storage failures;
- unauthorized downgrade or tampering with boot artifacts.

Out of scope for the initial prototype: physical attacks, compromised firmware, malicious hardware, and side-channel resistance. These must be revisited before any production or high-assurance claim.

## Required controls (not yet complete)

1. Memory-safe implementation for privileged components where practical.
2. Address-space isolation and a controlled user/kernel transition.
3. Kernel-enforced capabilities checked at each protected operation.
4. Authenticated boot and signed software updates.
5. Least-privilege service manifests and explicit device permission.
6. Secure key storage, data-at-rest encryption, and tested key recovery.
7. Fuzzing, sanitizers where applicable, static analysis, code review, and independent security testing.
8. Audit logs that do not leak secrets and have a documented retention policy.
9. A tested rollback strategy that does not permit booting known-vulnerable images without an explicit recovery policy.

## Physical memory ownership

The initial frame allocator treats only bootloader memory-map entries marked Usable as allocatable. Bootloader and unknown firmware region kinds are reserved. Regions are rounded inward to 4 KiB frames, physical frame zero is excluded, allocator initialization validates ranges and fails closed when its fixed metadata capacity is insufficient. The static bitmap supports up to 16 GiB of aggregate usable RAM across 256 usable regions.

The allocator tracks physical-frame ownership. The kernel now uses a guarded page-table editor for limited active-kernel map/unmap operations and the associated acceptance tests, but it does not yet provide a general-purpose data-page mapping service or independent user-process address spaces. The kernel requests the bootloader's recursive page-table mapping and the read-only inspector reads existing paging entries through that mapping. It does not use `physical_memory_offset` to dereference Bootloader-owned frames, because bootloader_api documents that only `Usable` frames are safe to access through the physical-memory alias. The inspector parses the bounded ELF64 PT_LOAD table from a checked read-only, supervisor-only, NX kernel load mapping; each metadata page must translate to its exact Bootloader-owned physical ELF backing page before bytes are read. It walks every page in every PT_LOAD memory range, requires a 4 KiB translation backed by a Bootloader- or Usable-owned physical page, checks effective U/S, R/W, and NX permissions against PT_LOAD flags while accounting for the bootloader's post-relocation GNU_RELRO write-protection, and verifies exact p_offset-to-physical correspondence for read-only file-backed pages except a partial final page copied while zeroing BSS. Writable segments may be copied by the bootloader while processing relocations, so their exact source-frame correspondence is not asserted. The inspector separately checks page-offset preservation and expected page-table-derived U/S, R/W, and NX permissions for a sampled kernel-code address, active stack pointer, and BootInfo pointer; it separately requires CR0.WP to be set before treating R/W=0 as supervisor-write protection. The inspector additionally validates every 4 KiB page intersecting the active stack and BootInfo object as writable, supervisor-only, NX mappings. Every backing page must be fully contained in a Bootloader- or Usable-owned region, and Usable-backed pages are permanently reserved before the first allocator allocation. The Bootloader-owned-region check applies to each page-table page before a volatile read, including the CR3 root. Before walking other entries, the kernel also reads the recursive PML4 entry through the reported recursive mapping and checks that it is present, not a large-page entry, and points to the CR3 frame. That first read relies on the bootloader_api contract that the reported recursive index maps the active PML4 frame to itself; it cannot independently prove the recursive virtual address safe before performing the read; it does not assert that stack or BootInfo leaf mappings point into Bootloader-owned memory. The inspector rejects malformed/truncated ELF headers, oversized program-header tables, W+X load segments, invalid file/memory ranges, overlapping PT_LOAD virtual ranges, and missing or unexpected PT_LOAD page mappings. It does not inventory every non-PT_LOAD boot mapping, audit every alias of every physical frame, or prove global W^X. Before any allocator allocation is allowed, each PT_LOAD page backed by a Usable region is permanently reserved in the allocator bitmap. Such reservations issue no releasable Frame token; repeated physical aliases are idempotent, and reservation is rejected after any allocation attempt. Bootloader-owned frames remain excluded by the memory map. These checks are bootstrap diagnostics, not proof of full mapping completeness or system-wide memory protection. The read-only inspector does not write page-table entries or change mapping permissions; the separate guarded editor performs limited kernel mapping mutations under its documented single-CPU/interrupt-disabled preconditions. A returned physical address must not be dereferenced as allocated data until a valid mapping and initialization policy has been established for that use. The global API is serialized by a non-blocking lock; Busy means the caller must retry from a context where retry is safe. This bootstrap allocator is not yet a process-isolation boundary and does not establish production-grade memory safety.

## Review follow-up: root lifetime and user-frame initialization

The kernel's successful supervisor-root activation path returns an
`ActiveAddressSpaceRoot` handle. It does not expose the physical-frame ownership
token. The type now provides an unsafe `into_inactive_after_switch` transition
that rejects a CR3 readback which still names the root being demoted. Its safety
contract requires the caller to have completed the actual switch and all required
TLB invalidation; the API cannot prove those hardware conditions itself. The
transition itself does not unmap user pages or reclaim lower-level tables;
those operations are performed by the separate inactive-root teardown path.
Dropping the active handle still leaks the frame allocation rather than recycling
a frame that hardware may use. Runtime address-space switching and inactive-root
teardown are implemented under the existing single-CPU, maskable-interrupts-disabled
contract. Ring 3 entry, live process teardown, SMP synchronization, and remote TLB
shootdowns are not implemented. The kernel also tracks live address-space root
frames separately from ordinary page-table frames so mapping and user-frame
zeroing paths reject roots even when they are not the current CR3 root.

The raw `map_4k` primitive is crate-private and is not exported from `oneos-core`;
external callers cannot request user-accessible leaf mappings by supplying arbitrary
physical addresses and permission flags. Public user-data mappings go through the
`ZeroedFrame` API. The public supervisor-only mapper is an unsafe operation: the
caller must retain the frame token and keep the physical frame allocated for the
entire lifetime of the mapping. Releasing a mapped frame could otherwise let the
allocator reuse it as a page table beneath a stale writable alias.

The safe `oneos-core` user-data mapping helper now accepts only `ZeroedFrame`.
`initialize_user_frame` produces that token only after the supplied initializer
reports that the complete frame has been zeroed; on failure, the original frame
token is returned. The host-side tests exercise a dirty frame payload and the
failure path. The kernel now has a `KernelUserFrameInitializer` candidate that
validates the active root's recursive self-map and exact supervisor-writable,
NX physical-memory-offset alias, then clears and reads back the full frame. The
VM-transition QEMU acceptance image exercises this kernel implementation with a
dirty allocated frame and verifies that the returned token identifies the same
physical frame. This remains a pre-publication check: user-frame mappings are not
yet wired into live user processes, and the candidate must pass the exact-head CI
suite before the roadmap prerequisite can be considered complete.

The unmap API now returns a raw Frame rather than a ZeroedFrame, since user mode
may write to the page before it is unmapped. Reassignment to any address space must
run initialize_user_frame again. UserFrameInitializer is an unsafe trait, making
correct zeroing an explicit obligation of reviewed trusted code; a safe implementer
can no longer return success without acknowledging that contract. The active-root
constructor is also unsafe so safe code cannot forge the hardware-active state.

The remaining review findings are tracked in
[`SECURITY_REVIEW_2026-10-24.md](SECURITY_REVIEW_2026-10-24.md). In particular,
process isolation and kernel-enforced capabilities are not implemented; page-table
mutation remains single-CPU with maskable interrupts disabled; remote TLB shootdowns
and frame-wide W^X are not implemented; the boot-mapping inspector validates each PT_LOAD page but does not enumerate every non-PT_LOAD mapping or physical-frame alias.

## CR3 activation and exception-entry state

The supervisor kernel-root activation path re-reads CPU state before preparing the switch and fails closed unless paging is enabled, CR0.WP and EFER.NXE are set, CR4.LA57 and CR4.PCIDE are clear, and maskable interrupts are disabled. These conditions are checked at the activation call rather than inferred solely from earlier initialization. The interrupt/TSS initialization path is one-shot, validates the active RSP against the bootloader's kernel-stack interval, sets TSS.RSP0 to that stack's aligned top, and routes double fault, NMI, and machine-check entries to separate IST stacks.

The emergency stacks currently have no unmapped guard pages, and the NMI/machine-check handlers remain fail-stop diagnostics rather than full recovery mechanisms. This bootstrap work does not establish ring-3 execution, general privilege-transition safety, preemption safety, or SMP safety. Before enabling user mode or external interrupts, add guard-page-backed stacks and end-to-end tests for entry frames, stack bounds, and state restoration.

## Page-table mutation and physical-frame permissions

The host-testable `map_4k` primitive rejects leaf targets that the editor identifies
as page-table or reserved frames, and separately rejects the supplied root frame. It
also requires the exact target frame to be currently allocated according to the editor's
allocation-state query; a free frame inside a `Usable` region is rejected. The kernel
editor checks the global allocator bitmap under its lock and fails closed if the state
cannot be read. These checks protect the mapping engine itself rather than assuming
every caller obeys the allocator contract.

The check-to-publication guarantee currently relies on the mutation path running on the
single CPU with maskable interrupts disabled. Allocation-state inspection does not prove
which caller owns a frame token and is not an SMP ownership protocol. Before enabling
preemption or SMP address-space mutation, retain ownership tokens for mapped data frames
and synchronize token lifetime, mapping publication, unmapping, and remote TLB shootdowns.

The physical-memory-offset alias used to initialize a frame is validated against the
expected physical address and must be writable, supervisor-only, and non-executable.
The supervisor-write-protection sentinel is data and is mapped NX. New executable
mappings through the kernel editor currently fail closed because the persistent
writable physical-memory alias cannot yet be removed or downgraded with complete
reverse-alias accounting. The host-testable `FrameWxRegistry` now provides bounded
range-overlap checks, pending reservations, publication state, and a retirement phase
that continues to block conflicting permissions until the caller confirms TLB
invalidation. The registry is not yet wired into the kernel mapping paths and does not
discover existing aliases automatically. This does **not** establish frame-wide W^X
for all existing boot mappings; executable user pages remain unsupported until every
writable alias (including kernel/direct-map and large-page aliases) can be accounted
for and permission transitions are synchronized with TLB invalidation.

## Capability reference model

The crates/oneos-core crate currently models an object ID, a set of rights, a generation-stamped capability, and revocation by generation change. Unit tests verify basic authorization decisions.

This model is **not a security boundary** by itself. Safe Rust visibility rules do not protect against arbitrary kernel memory corruption, unsafe code, a malicious caller with direct memory access, or a faulty kernel integration. Do not use it to protect real data until the kernel establishes and enforces the necessary isolation.

Authority IDs are allocated by a process-local static counter. Independent processes start their counters independently, so numeric IDs may collide. The current model is strictly for in-process testing and must not be used to authenticate imported or serialized capabilities across process boundaries. Before process isolation or IPC can rely on capabilities, the kernel must manage authority identity in protected state and verify token provenance and rights at every protected operation.

## Security reporting

Do not publish exploit details for an unpatched vulnerability, and do not include credentials, personal data, or production secrets in public issues.

Preferred channel: [GitHub private vulnerability reporting for this repository](https://github.com/musashimusashino666/one-os/security/advisories/new). If the page does not offer a private submission form, do not post vulnerability details publicly; contact the repository maintainer through a private contact method listed on their GitHub profile and request a private disclosure channel.

## Release gate

No release should be described as production-ready or secure solely because CI passes. A release requires a documented threat-model review, test results, reproducible build information, independent review of privileged code, and a tested recovery process.
