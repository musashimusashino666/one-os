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

The allocator tracks physical-frame ownership. The kernel now uses a guarded page-table editor for limited active-kernel map/unmap operations and the associated acceptance tests, but it does not yet provide a general-purpose data-page mapping service or independent user-process address spaces. The kernel requests the bootloader's recursive page-table mapping and the read-only inspector reads existing paging entries through that mapping. It does not use `physical_memory_offset` to dereference Bootloader-owned frames, because bootloader_api documents that only `Usable` frames are safe to access through the physical-memory alias. The inspector checks that one sampled kernel-code virtual address lies within BootInfo's virtual kernel-image range and that its translated physical address falls within the in-memory ELF backing interval reported by BootInfo. This interval check does not establish segment-specific virtual-to-physical correspondence. The inspector checks page-offset preservation and expected page-table-derived U/S, R/W, and NX permissions for the sampled kernel-code address, active stack pointer, and BootInfo pointer; it separately requires CR0.WP to be set before treating R/W=0 as supervisor-write protection. These leaf-mapping checks do not validate stack or BootInfo physical-memory-region ownership. The Bootloader-owned-region check applies to each page-table page before a volatile read, including the CR3 root. Before walking other entries, the kernel also reads the recursive PML4 entry through the reported recursive mapping and checks that it is present, not a large-page entry, and points to the CR3 frame. That first read relies on the bootloader_api contract that the reported recursive index maps the active PML4 frame to itself; it cannot independently prove the recursive virtual address safe before performing the read; it does not assert that stack or BootInfo leaf mappings point into Bootloader-owned memory. The inspector does not parse ELF PT_LOAD headers or compare p_offset, p_vaddr, p_filesz, and p_memsz against observed translations, and it does not inspect every mapping. These checks are bootstrap diagnostics, not a proof of exact mapping correctness, mapping completeness, or system-wide memory protection. The read-only inspector does not write page-table entries or change mapping permissions; the separate guarded editor performs limited kernel mapping mutations under its documented single-CPU/interrupt-disabled preconditions. A returned physical address must not be dereferenced as allocated data until a valid mapping and initialization policy has been established for that use. The global API is serialized by a non-blocking lock; Busy means the caller must retry from a context where retry is safe. This bootstrap allocator is not yet a process-isolation boundary and does not establish production-grade memory safety.

## Review follow-up: root lifetime and user-frame initialization

The kernel's successful supervisor-root activation path returns an
`ActiveAddressSpaceRoot` handle. Unlike the inactive-root handle, it does not
expose the physical-frame ownership token or a conversion back to the releasable
inactive type. Dropping the active handle leaks the frame allocation rather than
making an active page-table frame available for reuse. This is API-level protection,
not a full address-space lifecycle: callers must still retain the active handle, and
teardown/switching has not been implemented.

The safe `oneos-core` user-data mapping helper now accepts only `ZeroedFrame`.
`initialize_user_frame` produces that token only after the supplied initializer
reports that the complete frame has been zeroed; on failure, the original frame
token is returned. The host-side tests exercise a dirty frame payload and the
failure path. A production kernel-backed initializer and its integration with the
user-address-space editor are still outstanding, so this is not evidence that live
user-process pages are currently being exposed safely.

The remaining review findings are tracked in
[`SECURITY_REVIEW_2026-10-24.md](SECURITY_REVIEW_2026-10-24.md). In particular,
process isolation and kernel-enforced capabilities are not implemented; page-table
mutation remains single-CPU with maskable interrupts disabled; remote TLB shootdowns
and frame-wide W^X are not implemented; and boot-mapping checks remain sampled rather
than a complete ELF-segment mapping proof.

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
reverse-alias accounting. This does **not** establish frame-wide W^X for all existing
boot mappings; executable user pages remain unsupported until every writable alias
(including kernel/direct-map and large-page aliases) can be accounted for and
permission transitions are synchronized with TLB invalidation.

## Capability reference model

The crates/oneos-core crate currently models an object ID, a set of rights, a generation-stamped capability, and revocation by generation change. Unit tests verify basic authorization decisions.

This model is **not a security boundary** by itself. Safe Rust visibility rules do not protect against arbitrary kernel memory corruption, unsafe code, a malicious caller with direct memory access, or a faulty kernel integration. Do not use it to protect real data until the kernel establishes and enforces the necessary isolation.

Authority IDs are allocated by a process-local static counter. Independent processes start their counters independently, so numeric IDs may collide. The current model is strictly for in-process testing and must not be used to authenticate imported or serialized capabilities across process boundaries. Before process isolation or IPC can rely on capabilities, the kernel must manage authority identity in protected state and verify token provenance and rights at every protected operation.

## Security reporting

Do not publish exploit details for an unpatched vulnerability, and do not include credentials, personal data, or production secrets in public issues.

Preferred channel: [GitHub private vulnerability reporting for this repository](https://github.com/musashimusashino666/one-os/security/advisories/new). If the page does not offer a private submission form, do not post vulnerability details publicly; contact the repository maintainer through a private contact method listed on their GitHub profile and request a private disclosure channel.

## Release gate

No release should be described as production-ready or secure solely because CI passes. A release requires a documented threat-model review, test results, reproducible build information, independent review of privileged code, and a tested recovery process.
