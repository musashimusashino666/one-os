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

This allocator currently tracks ownership state; it does not map or clear allocated data frames. The kernel requests the bootloader's recursive page-table mapping and reads current paging entries through that mapping. It does not use `physical_memory_offset` to dereference Bootloader-owned frames, because bootloader_api documents that only `Usable` frames are safe to access through the physical-memory alias. The inspector checks that one sampled kernel-code virtual address lies within BootInfo's virtual kernel-image range and that its translated physical address falls within the in-memory ELF backing interval reported by BootInfo. This interval check does not establish segment-specific virtual-to-physical correspondence. The inspector checks page-offset preservation and expected page-table-derived U/S, R/W, and NX permissions for the sampled kernel-code address, active stack pointer, and BootInfo pointer; it separately requires CR0.WP to be set before treating R/W=0 as supervisor-write protection. These leaf-mapping checks do not validate stack or BootInfo physical-memory-region ownership. The Bootloader-owned-region check applies to each page-table page before a volatile read, including the CR3 root. Before walking other entries, the kernel also reads the recursive PML4 entry through the reported recursive mapping and checks that it is present, not a large-page entry, and points to the CR3 frame. That first read relies on the bootloader_api contract that the reported recursive index maps the active PML4 frame to itself; it cannot independently prove the recursive virtual address safe before performing the read; it does not assert that stack or BootInfo leaf mappings point into Bootloader-owned memory. The inspector does not parse ELF PT_LOAD headers or compare p_offset, p_vaddr, p_filesz, and p_memsz against observed translations, and it does not inspect every mapping. These checks are bootstrap diagnostics, not a proof of exact mapping correctness, mapping completeness, or system-wide memory protection. The code does not write page-table entries or change mapping permissions. A returned physical address must not be dereferenced as allocated data until a later virtual-memory layer establishes a valid mapping and initialization policy. The global API is serialized by a non-blocking lock; Busy means the caller must retry from a context where retry is safe. This bootstrap allocator is not yet a process-isolation boundary and does not establish production-grade memory safety.

## Capability reference model

The crates/oneos-core crate currently models an object ID, a set of rights, a generation-stamped capability, and revocation by generation change. Unit tests verify basic authorization decisions.

This model is **not a security boundary** by itself. Safe Rust visibility rules do not protect against arbitrary kernel memory corruption, unsafe code, a malicious caller with direct memory access, or a faulty kernel integration. Do not use it to protect real data until the kernel establishes and enforces the necessary isolation.

Authority IDs are allocated by a process-local static counter. Independent processes start their counters independently, so numeric IDs may collide. The current model is strictly for in-process testing and must not be used to authenticate imported or serialized capabilities across process boundaries. Before process isolation or IPC can rely on capabilities, the kernel must manage authority identity in protected state and verify token provenance and rights at every protected operation.

## Security reporting

Do not publish exploit details for an unpatched vulnerability, and do not include credentials, personal data, or production secrets in public issues.

Preferred channel: [GitHub private vulnerability reporting for this repository](https://github.com/musashimusashino666/one-os/security/advisories/new). If the page does not offer a private submission form, do not post vulnerability details publicly; contact the repository maintainer through a private contact method listed on their GitHub profile and request a private disclosure channel.

## Release gate

No release should be described as production-ready or secure solely because CI passes. A release requires a documented threat-model review, test results, reproducible build information, independent review of privileged code, and a tested recovery process.
