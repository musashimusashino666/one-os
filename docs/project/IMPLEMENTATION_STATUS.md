# Implementation Status

**Snapshot date:** 2026-10-28  
**Reviewed main commit:** `d9b130e84da910da5057f71d924d277573b81bde`  
**Purpose:** describe observed implementation status, not guarantee a current CI result.

Update this document when main changes in a material way. “Implemented” means code exists; “verified” means the stated test path demonstrated the behavior; neither word implies a broader security guarantee.

## Status matrix

| Area | Status | Evidence and boundary |
| --- | --- | --- |
| Rust workspace and BIOS image tooling | Implemented | Workspace contains oneos-core, bare-metal kernel, and oneos-xtask. |
| Memory map and physical frame allocator | Implemented with fixed limits | Host tests and bootstrap checks exist. Capacity is bounded; only eligible Usable regions are allocatable. |
| Selected boot mapping inspection | Implemented, bounded | ELF PT_LOAD, selected metadata, permissions, and ownership are checked. Not every boot mapping or alias is covered. |
| Kernel virtual-memory mutation | Implemented for limited paths | Guarded 4 KiB map/unmap and related ownership/TLB checks; not a general VM subsystem. |
| Selected protection and TLB tests | Acceptance paths implemented | QEMU profiles cover supervisor-write protection, NX, mapping transitions, large-page demotion, direct-map permission transitions, a QMP-injected asynchronous NMI during the verified non-present transition window, rejection of live-root unregistration, rejection of missing/duplicate root registration, rejection of allocator-unowned and permanently reserved roots at admission, real CR3-switch rejection when reservation metadata becomes inconsistent after registration, W^X-audit rejection of the same inconsistent root state, cross-root W^X conflict injection, PTE/reservation-state restoration, and a clean follow-up audit. These are scoped emulator tests, not physical-hardware, Machine Check, or system-wide security certification. |
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

This snapshot was reconciled against the source tree, PR metadata, open issues, and GitHub Actions records on 2026-10-28. The latest relevant evidence reviewed here is PR #71: its required CI run [#40657289751](https://github.com/musashimusashino666/one-os/actions/runs/40657289751) passed on PR HEAD `b948771fb862fc6327d8c28a29925a49648c6658`. The merged main commit `d9b130e84da910da5057f71d924d277573b81bde` has the same Git tree (`f12c189c8478f43ae50be55754f08e48c6d06112`) as that tested HEAD, although the commit SHAs differ. This is QEMU/CI evidence for the tested source tree, not physical-hardware evidence or proof of global W^X. This documentation change has not itself run the CI suite; require CI for the exact new PR HEAD and inspect the relevant logs before merging.
