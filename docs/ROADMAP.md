# Roadmap Entry Point

The authoritative milestone sequence is maintained in [Project Roadmap](project/ROADMAP.md). This file provides the requested top-level entry point without duplicating its detailed planning records.

## Current memory-security gate

The bounded W^X inventory slice in [Issue #46](https://github.com/musashimusashino666/one-os/issues/46) is being implemented as read-only audit logic: declared roots are reported individually, supported leaf extents and effective permissions are checked, the direct-map interval is verified, and malformed/incomplete scope fails closed. Arbitrary executable mapping publication remains denied.

[Issue #26](https://github.com/musashimusashino666/one-os/issues/26) remains a blocking parent gate. It requires complete verification of the required boot mapping set (including ELF PT_LOAD correspondence and rejection of unexpected/missing mappings) and transactional frame-wide W^X enforcement across all aliases and mapping sources. A clean declared-scope inventory, a successful build, or QEMU acceptance alone does not demonstrate that parent issue complete.

The current kernel contract is single CPU with maskable interrupts disabled and PCID disabled during page-table mutation; SMP, remote TLB shootdown, and general root-lifetime synchronization remain unimplemented. Close these issues only when each stated criterion has evidence on the exact reviewed, CI-green candidate. See [Implementation Status](project/IMPLEMENTATION_STATUS.md), [Security Model](architecture/SECURITY_MODEL.md), and [Virtual-Memory Acceptance](specs/VIRTUAL_MEMORY_ACCEPTANCE.md).
