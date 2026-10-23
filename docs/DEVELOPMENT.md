# Development Guide

## Prerequisites

- Nightly Rust, selected by rust-toolchain.toml.
- rustfmt, clippy, llvm-tools-preview, rust-src, and the x86_64-unknown-none target. The toolchain file requests these components and target.
- QEMU with the x86_64 system emulator. On Debian/Ubuntu, install the qemu-system-x86 package.
- Git.
- Python 3 (used to read Cargo's reported target directory for the QEMU command).

## Checks

Run these from the repository root:

    cargo fmt --all -- --check
    cargo test --locked -p oneos-core
    cargo clippy --locked -p oneos-core --all-targets -- -D warnings
    cargo check --locked -p one-os-kernel --target x86_64-unknown-none

## CI and merge protection

The CI workflow runs in the pull-request context when a PR is opened, reopened,
marked ready for review, or updated with a new head commit (`synchronize`). The
required check name is `Format, test, lint, and boot`; keep it synchronized with
the active GitHub ruleset if the job is renamed. `workflow_dispatch` is useful
for diagnosis, but a run for an older SHA or a non-PR event does not validate the
current PR head.

GitHub's active `Protect main` ruleset is the authoritative merge gate; comments
in a workflow file cannot enforce repository settings. It must require the
`Format, test, lint, and boot` check and keep the branch up to date with `main`.
Review threads should be resolved; if approving reviews are configured, stale
approvals should be dismissed after new commits. Avoid bypass actors where possible.

**Single-maintainer policy:** the ruleset currently requires `0` approving reviews.
Keep this at `0` while no independent reviewer is available. A requirement of one
approval would prevent the sole PR author from approving their own change and can
block all merges. Continue to review the diff deliberately and require a successful
PR-context check on the exact latest HEAD before merging. Revisit the approval
threshold only after an independent reviewer is available; do not present native
review approval as enforced while its count is zero.

## Build a BIOS image

Run:

    cargo run --locked -p oneos-xtask -- image

The build tool compiles one-os-kernel for x86_64-unknown-none, discovers the actual kernel executable from Cargo's compiler-artifact JSON, then uses the bootloader crate to create one-os-bios.img inside Cargo's reported target directory. It honors CARGO_TARGET_DIR; for example, use CARGO_TARGET_DIR=/tmp/one-os-target cargo run --locked -p oneos-xtask -- image to place outputs elsewhere. The bootloader builder needs the nightly toolchain, LLVM tools, and Rust sources so it can build its boot stages. This is a BIOS image; UEFI support is not configured yet.

## Run in QEMU

Run:

    IMAGE_DIR="$(cargo metadata --locked --format-version 1 --no-deps | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')"
    qemu-system-x86_64 -drive format=raw,file="$IMAGE_DIR/one-os-bios.img" -serial stdio -display none -no-reboot -no-shutdown

Expected serial output includes:

    ONE OS kernel booted
    ONE OS FRAME ALLOCATOR READY
    ONE OS PAGE TABLE INSPECTION READY
    ONE OS VM MAPPING SMOKE TEST READY
    Usable physical frames: 0x...
    Usable physical regions: 0x...
    Architecture: x86_64
    Milestone: serial bootstrap
    Memory map: structurally validated
    ONE OS BOOTSTRAP COMPLETE

For the dedicated memory-acceptance images, CI additionally builds and runs:
`image-test-supervisor-write-protection`, `image-test-nx-protection`, and
`image-test-vm-transitions`. The protected-write case requires the exact page-fault
error code `0x3`; NX instruction fetch requires `0x11`; transition reads require
two exact non-present faults (`0x0`) at their expected RIPs and CR2. These cases use
QEMU's `isa-debug-exit` and separate validators, and their serial logs are uploaded
as the `one-os-qemu-serial-logs` CI artifact. The required suite is designed to run on the exact PR candidate. Check the [CI workflow runs](https://github.com/musashimusashino666/one-os/actions/workflows/ci.yml) for the revision-specific result; a successful result for an older commit is not evidence that a newer commit has passed.

The kernel rejects empty, inverted, or overlapping memory-map ranges before initializing the physical-frame allocator. The allocator admits only regions marked Usable, excludes physical frame zero, and performs an allocation/free smoke test before the ready marker. It fails closed if the fixed metadata cannot cover the usable map (16 GiB aggregate usable memory or 256 regions). The kernel now performs a real active-page-table smoke cycle during bootstrap: it selects an unused canonical virtual page, maps an owned data frame as writable/supervisor-only/NX, writes and reads a sentinel through that virtual address, unmaps it, invalidates the local TLB, and verifies that translation reports the page as not present. Newly allocated page-table frames are zeroed through the checked physical-memory offset before publication and retain their non-Copy Frame ownership tokens while reachable. This is limited active-kernel mapping support, not general-purpose virtual-memory management or process isolation. M1's acceptance suite includes this boot smoke cycle plus the dedicated QEMU tests for recoverable not-present transitions, supervisor write-protection, NX instruction-fetch protection, and map/unmap/remap TLB behavior. The kernel then deliberately halts. Stop the virtual machine with Ctrl-C. A successful build does not prove that the image boots, which is why CI captures serial output and requires the startup, allocator-ready, page-table-inspection, mapping-smoke, and completion markers while rejecting failure, panic, and invalid-map markers.

## Automated boot smoke test

GitHub Actions builds a BIOS disk image, then performs three independent QEMU invocations against that image. Each attempt captures serial output and requires all five success markers, in order: kernel startup, physical-frame allocator readiness, page-table inspection readiness, active mapping smoke-test readiness, and bootstrap completion. The validator also rejects allocator, paging, mapping-mutation, invalid-memory-map, panic, and unexpected exception failure markers, as well as unexpected QEMU exit statuses. A timeout after the expected markers is normal because the bootstrap kernel deliberately halts without powering down. This smoke test checks boot integration, not OS completeness or security. CI installs the required toolchain components explicitly before building the image and imposes a job timeout to prevent hung runs.

## Read-only page-table inspection

The normal BIOS image requests a recursive page-table mapping from the bootloader. In bootloader_api v0.11.17, the bootloader contract is that the `recursive_index` reported in BootInfo names a PML4 entry that maps the active PML4 frame to itself. Before walking other entries, the kernel reads that recursive entry through the mapping and checks that it is present, does not set the PML4-reserved large-page bit, and references the CR3 PML4 frame. This initial read still relies on the bootloader contract being sufficient to make the recursive virtual address accessible; it is a consistency check, not a fault-proof independent probe. Before the bootstrap-completion marker, the kernel reads CR3/CR4, rejects five-level paging, and walks the current four-level page tables through the recursive mapping without modifying them. It checks that the sampled kernel-code translation falls within the physical ELF backing interval reported by BootInfo, verifies page-size offset preservation, and checks page-table permission bits for the sampled kernel-code address, active stack pointer, and BootInfo pointer. It does not validate the physical memory-map ownership of the stack or BootInfo leaf mappings. The kernel uses `kernel_len` only to bound the in-memory ELF backing interval; it does not treat `kernel_image_offset + kernel_len` as the loaded virtual image's end, because ELF segment layout and zero-filled memory can make those lengths differ. CR0.WP must be set before R/W=0 is treated as supervisor write protection. It deliberately does not read Bootloader-owned page-table frames through `physical_memory_offset`, which bootloader_api documents as safe only for Usable frames. The serial output must include:

    ONE OS FRAME ALLOCATOR READY
    ONE OS PAGE TABLE INSPECTION READY
    ONE OS BOOTSTRAP COMPLETE

The host-side tests for oneos-core exercise 4 KiB, 2 MiB, and 1 GiB translations, canonical-address boundaries, absent entries, unavailable table pages, invalid roots, and malformed large-page alignment bits. This is an inspection-only milestone: it does not allocate page-table frames, create or remove mappings, enforce page permissions, or establish process isolation.

## Host-testable page-table mutation

The oneos-core crate provides callback-driven map_4k and unmap_4k primitives for
4 KiB pages in four-level x86_64 page tables. Host tests cover address validation,
W^X rejection, effective permissions, mapping conflicts, large-page conflicts,
and rollback of newly allocated table frames when allocation fails.

The core primitives are connected to the active kernel page tables through the
guarded editor in kernel/src/paging.rs. The callback implementation must make
table reads and writes safe, return distinct zero-filled table frames, and
retain ownership of frames committed to page-table use. The caller must perform
TLB invalidation, serialize mutations, ensure EFER.NXE is enabled before using
NX permissions, and manage the lifetime of allocated page-table frames. When
read-only mappings must block supervisor-mode writes, the caller must also
ensure CR0.WP is enabled on every CPU that can execute with these page tables.
The primitives cannot inspect or enable either CR0.WP or EFER.NXE themselves.
When integrating them into the kernel, paging initialization must explicitly
establish and verify these CPU-control preconditions before relying on read-only
or non-executable mappings, and retain them on every CPU that can use the tables.
Both map and unmap reject repeated physical table frames encountered during a
walk, failing closed on recursive/cyclic references rather than treating them
as ordinary paging levels. Unmap clears the leaf entry but does not reclaim
now-empty intermediate tables. The active kernel integration is exercised by
specific QEMU protection and mapping-transition cases; those results do not
establish generalized process isolation or SMP-safe page-table management.

The PageTableEditor contract must report the active processor's MAXPHYADDR,
typically CPUID.80000008H:EAX[7:0]. Root, leaf, and intermediate-table physical
addresses are checked against this width (the supported contract is 32 through
52 bits), rather than assuming all processors implement 52 physical bits.
Bits 58:52 are software-available/ignored fields in long-mode paging entries,
and bits 62:59 are accepted as leaf protection-key fields; neither range is
mistaken for a physical address. The caller must still configure CPU paging
features consistently with the entries being used.

## Exception diagnostics test

The kernel disables maskable interrupts at entry and masks both 8259 PIC data ports before serial or IDT setup. This bootstrap never executes `sti`; external interrupt routing is not yet configured. `cli` does not mask NMI or machine-check events. The bootstrap installs a TSS with IST1 pointing to a dedicated double-fault stack; the double-fault IDT gate selects IST1. Other exception handlers continue to use the active stack. The dedicated `image-test-double-fault` image sets RSP to a non-canonical value before raising #UD, testing that exception delivery escalates to #DF and reaches the handler on IST1.

The fault-injection BIOS images are enabled only for dedicated tests, never for the normal kernel image:

    cargo run --locked -p oneos-xtask -- image-test-exception
    cargo run --locked -p oneos-xtask -- image-test-general-protection
    cargo run --locked -p oneos-xtask -- image-test-page-fault
    cargo run --locked -p oneos-xtask -- image-test-double-fault

CI executes all four images in QEMU. It verifies that the invalid-opcode test reports vector 6, a direct assembly data load from a non-canonical address reports #GP (vector 13) with error code 0, and a direct assembly load from an unmapped canonical address reports #PF (vector 14), an error code, and the expected CR2 address. Each case must halt after the exception, must not enter the Rust panic handler, and must not emit the bootstrap-completion marker. QEMU will remain running after each handler halts; stop local runs with Ctrl-C.

The normal serial-log validator separately rejects any `ONE OS EXCEPTION` diagnostic marker, even if the bootstrap-completion marker was already printed.

## Contribution rules

- Keep pull requests narrowly scoped and describe observable behavior.
- Add tests for each new authorization, state-transition, parser, or recovery behavior.
- Do not add a security claim without an associated test or review artifact.
- Document every new use of unsafe and its safety invariant.
- Avoid adding dependencies to privileged kernel code without a clear need and review.
- Include exact commands and results when reporting validation.


### Page-table ownership registry validation

The core crate exposes a fixed-capacity page-table frame ownership registry used by the kernel editor. Host tests cover reservation before allocation, capacity exhaustion without allocation, ownership-token retention, exactly-once release of unpublished frames, retention of published frames, duplicate-address rejection, invalid or foreign releases, slot reuse, rollback, and leaf-unmap ownership. Host-testable paging-precondition validators cover extended CPUID leaf availability, NX support, physical-address width, CR0.WP, and EFER.NXE. Required QEMU cases exercise the concrete editor's checked physical-memory-offset alias and zero-before-publication behavior. The latest revision-specific result is available in the [CI workflow runs](https://github.com/musashimusashino666/one-os/actions/workflows/ci.yml); any subsequent change must pass the required check on its exact PR candidate.
