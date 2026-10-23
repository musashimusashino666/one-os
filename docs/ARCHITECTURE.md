# ONE OS Architecture

## Status

This document describes the intended architecture, not a claim that each subsystem already exists. The current bootstrap kernel initializes COM1, disables maskable interrupts, masks the legacy PIC, installs an x86_64 IDT with fail-stop diagnostic handlers, structurally validates BootInfo memory-map ranges, initializes and smoke-tests a fixed-capacity physical-frame allocator, prints a completion marker, and halts. CI Run #120 passed on commit `892b9268c9a6774229189c60557be4d0d22bf541`: three independent normal QEMU boots and controlled #UD, #GP, and #PF/CR2 fault-injection checks all passed, including vector/error-code/CR2 and halt-marker validation. This verifies the controlled cases in the CI QEMU environment, not hardware-wide exception robustness. Before `interrupts::init()` loads the new IDT, the kernel temporarily relies on the bootloader-provided IDTR and descriptors; `cli` does not suppress synchronous exceptions, NMI, or machine-check events, so diagnostics are not guaranteed during this early window. The double-fault gate uses a dedicated TSS/IST stack configured during bootstrap; other exception handlers still use the active stack. CI includes a controlled invalid-stack fault-injection case to verify double-fault diagnostics, but this does not establish general hardware-wide exception robustness. The capability crate is a standalone reference model and is not wired into kernel enforcement. The core crate also contains callback-driven, host-testable 4 KiB map/unmap mutation primitives with W^X policy and allocation rollback; these are not yet connected to the active kernel page tables and do not provide hardware-enforced memory protection. The mutation interface obtains the physical-address width through its PageTableEditor contract and preserves software-available and leaf protection-key attribute bits instead of treating all high non-address bits as reserved. The map/unmap walks reject repeated physical table frames to fail closed on recursive/cyclic page-table references. Callers that rely on read-only mappings for supervisor write protection must ensure CR0.WP remains enabled on every CPU using these tables; the mutation primitives document but do not enforce that CPU-state precondition. Kernel integration must establish and verify CR0.WP and EFER.NXE before relying on read-only and non-executable mappings, respectively.

## Target architecture

The first development target is x86_64 under a virtual machine. Additional architectures should be introduced only after interfaces are stable and tested.

### 1. Hardware and boot boundary

The bootloader establishes the initial CPU state and passes a BootInfo structure to the kernel. The kernel now structurally validates the memory-map entries before reporting bootstrap completion: the map must be non-empty, each half-open range must have start < end, and no two ranges may overlap. The kernel now feeds the validated map into a fixed-capacity physical-frame allocator. Only regions explicitly tagged Usable are eligible; Bootloader and unknown region kinds remain reserved, physical frame zero is excluded, and ranges are rounded inward to complete 4 KiB frames. The allocator uses one bit per eligible frame and opaque, non-Copy frame tokens so a token cannot be safely duplicated or returned to a different allocator. Its boot-time metadata is statically reserved in the kernel image and supports up to 16 GiB of aggregate usable RAM across 256 usable regions; exceeding either bound fails closed. This stage does not validate the backing pointer used by bootloader_api, validate every other BootInfo address field, or map/zero/access the allocated frames. The bootstrap requests the bootloader-provided recursive page-table mapping and walks the active four-level tables read-only. It checks that one sampled kernel-code translation falls within the physical ELF backing interval reported by BootInfo, preserves page offsets, and has the expected page-table permission bits for the sampled kernel-code address, active stack pointer, and BootInfo pointer; the inspector also requires CR0.WP to be set before treating R/W=0 as supervisor write protection. It does not validate the physical memory-map ownership of the stack or BootInfo leaf mappings. Every page-table page read, including the CR3 root, must be fully contained in a Bootloader-owned region. Before the walk, the kernel checks the reported recursive PML4 entry for a present self-reference to the CR3 frame and rejects a large-page bit at that level. This value check relies on the bootloader API contract to make the first recursive read accessible; it is not an independent way to probe a broken recursive mapping. The inspector does not parse ELF PT_LOAD program headers or compare segment-specific p_offset, p_vaddr, p_filesz, and p_memsz values against observed translations; the interval check therefore does not prove exact virtual-to-physical correspondence. These sampled checks do not prove that all mappings are correct or complete, or that memory protection is enforced system-wide. The inspector does not use the physical-memory alias to access Bootloader-owned frames and does not create or remove mappings; full kernel virtual-memory management remains unimplemented.

### 2. Physical-frame allocation

The bootstrap allocator owns only frames represented by Usable memory-map entries. All other memory kinds are excluded, region endpoints are aligned inward to 4 KiB boundaries, and physical frame zero is never returned. A fixed-capacity bitmap avoids allocator recursion and heap dependencies during bootstrap. The kernel serializes access with a non-blocking lock; callers receive a Busy error rather than spinning if another context owns the allocator. Allocation returns a physical address token only: it does not imply that the frame is mapped, cleared, or safe to dereference. The current metadata capacity is 16 GiB of aggregate usable RAM and 256 usable segments; overflow is a boot failure, not a reason to allocate from reserved memory. The metadata limit can be removed after virtual-memory support allows the allocator to manage its own backing storage.

### 3. Minimal trusted kernel

The long-term design favors a microkernel-style trusted computing base. Initial responsibilities are expected to include:

- CPU and exception/interrupt fundamentals;
- address-space and memory-region control;
- thread lifecycle and scheduling;
- secure inter-process communication (IPC);
- capability validation at protected operations;
- controlled transitions between user mode and kernel mode.

File systems, networking, most device drivers, policy, and the service manager should run as isolated services where practical. Real-time and high-throughput paths may require measured, explicitly reviewed exceptions.

### 4. Authority and IPC

A resource is represented by an object identifier. A capability grants a limited set of rights over that object. The kernel must check capabilities at each privileged operation and must not trust a token copied from user memory without validating its provenance and ownership.

The current oneos-core crate demonstrates only grant/check/revoke semantics within one authority. It does not provide kernel isolation, protected memory, IPC, delegation, or protection against malicious unsafe code. These features must not be inferred from its unit tests.

### 5. System services

Planned services include storage, networking, device management, cryptographic key handling, identity, updates, software installation, logging, and UI composition. Each service should have a narrow API and an explicit rights manifest.

### 6. Application runtimes

The intended long-term model has three paths:

- native ABI for low-overhead, platform-specific applications;
- sandboxed portable modules, potentially WebAssembly-based;
- compatibility environments or virtual machines for legacy applications.

Compatibility is measured per application and version. It is not assumed to be universal.

### 7. User experience and AI

The UI should adapt to desktop, mobile, and server contexts while preserving coherent navigation and accessibility. AI-enabled actions must use the same authority checks as other clients, run with scoped permissions, and require confirmation for high-impact or irreversible operations.

### 8. Updates and recovery

A mature implementation should verify signed artifacts, support staged activation, maintain a known-good recovery path, prevent unauthorized rollback to vulnerable releases, and test restoration from independent backups. Those features are not yet implemented.

## Design constraints

- Keep privileged code small and auditable.
- Prefer memory-safe Rust; isolate and review unavoidable unsafe code.
- Avoid hidden ambient authority.
- Make denial the default when rights are missing or state is inconsistent.
- Test recovery, not just the happy path.
- Report benchmarks with hardware, build profile, workload, and repetitions.
- Document compatibility gaps and current limitations openly.

## Decision records

- Initial architecture: x86_64 bare-metal bootstrap, Rust workspace, host-testable no_std core.
- Kernel shape: microkernel-style separation is the target, but it must be validated against measured performance, driver support, and maintainability before claiming superiority.
