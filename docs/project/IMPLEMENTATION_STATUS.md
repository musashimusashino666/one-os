# Implementation Status

**Snapshot date:** 2026-10-28  
**Reviewed main commit:** `927d7daacb4c6e2dcbf6a5e837034532f2680400`  
**Purpose:** describe observed implementation status, not guarantee a current CI result.

Update this document when main changes in a material way. “Implemented” means code exists; “verified” means the stated test path demonstrated the behavior; neither word implies a broader security guarantee.

## Status matrix

| Area | Status | Evidence and boundary |
| --- | --- | --- |
| Rust workspace and BIOS image tooling | Implemented | Workspace contains oneos-core, bare-metal kernel, and oneos-xtask. |
| Memory map and physical frame allocator | Implemented with fixed limits | Host tests and bootstrap checks exist. Capacity is bounded; only eligible Usable regions are allocatable. |
| Selected boot mapping inspection | Implemented, bounded | ELF PT_LOAD, selected metadata, permissions, and ownership are checked. Not every boot mapping or alias is covered. |
| Kernel virtual-memory mutation | Implemented for limited paths | Guarded 4 KiB map/unmap and related ownership/TLB checks; not a general VM subsystem. |
| Selected protection and TLB tests | Acceptance paths implemented | QEMU profiles cover supervisor-write protection, NX, mapping transitions, large-page demotion, direct-map permission transitions, and a QMP-injected asynchronous NMI during the verified non-present transition window. These are scoped emulator tests, not physical-hardware or Machine Check validation. |
| Bounded x86 W^X transition risk review | Closed with residual risks recorded | [Issue #49](https://github.com/musashimusashino666/one-os/issues/49) was closed on 2026-10-28 after an AI-assisted review against the exact reviewed main revision and explicit maintainer residual-risk acceptance. No independent human sign-off or physical-hardware validation was performed. This is not a global W^X guarantee. |
| W^X | Partial; global guarantee incomplete | Direct-map aliases for validated executable PT_LOAD pages are transitioned to RO/NX and bounded audits exist. Complete frame-wide root/alias inventory remains open under [#26](https://github.com/musashimusashino666/one-os/issues/26) and [#46](https://github.com/musashimusashino666/one-os/issues/46). |
| Address-space lifecycle | Partial | CPL 0 root switch, selected user-data mapping, teardown/re-zero/reclaim scenarios are smoke-tested. This is not Ring 3 process isolation. |
| Capability model | Reference model only | oneos-core is host-testable; rights are not yet enforced as a complete process boundary by the kernel. |
| Ring 3 user execution | Not implemented as a complete path | No validated end-to-end user entry/return and isolation acceptance suite. |
| Scheduler and IPC | Not implemented as a usable subsystem | Contracts and implementation remain roadmap work. |
| Storage, networking, drivers, service manager | Not implemented as integrated services | Not a daily-use operating system. |
| User-facing permission controls and AI delegation | Design target only | No integrated shell/desktop and no complete owner-control UX. |
| Authenticated boot and signed updates/recovery | Not implemented | Must precede any corresponding product security claim. |
| SMP and remote TLB shootdown | Not implemented | Current paging mutation contract assumes one CPU and maskable interrupts disabled. |

## Outstanding work items

- [Issue #26](https://github.com/musashimusashino666/one-os/issues/26): complete frame-wide W^X and boot-mapping verification.
- [Issue #46](https://github.com/musashimusashino666/one-os/issues/46): inventory all declared physical aliases before enforcing frame-wide W^X.
- [Issue #23](https://github.com/musashimusashino666/one-os/issues/23): gate live user-page publication on lifecycle and isolation tests.
- [Issue #24](https://github.com/musashimusashino666/one-os/issues/24): process address-space isolation and kernel-enforced capabilities.
- [Issue #25](https://github.com/musashimusashino666/one-os/issues/25): SMP/preemption synchronization and remote TLB shootdown protocol.

Issue #49 is a completed, bounded architecture-risk review, not an open implementation milestone. Its closure does not close #26 or #46, establish system-wide W^X, or validate Machine Check behavior or physical hardware.

## Evidence policy

This snapshot is based on source, issue, and documentation inspection. It does not claim that this documentation update itself ran the full CI suite. The QMP-injected NMI acceptance test passed in CI run [#991](https://github.com/musashimusashino666/one-os/actions/runs/40610402449) for PR #62's exact HEAD; the recorded merge into main preserves that tested tree. The test is QEMU evidence, not physical-hardware evidence. Before merging code or declaring a milestone complete, check the required CI result for the exact candidate SHA and inspect the relevant test artifacts.
