# ONE OS Architecture

## Status

This document describes the intended architecture, not a claim that each subsystem already exists. The current bootstrap kernel initializes COM1, disables maskable interrupts, masks the legacy PIC, installs an x86_64 IDT with fail-stop diagnostic handlers, structurally validates BootInfo memory-map ranges, prints a completion marker, and halts. CI Run #120 passed on commit `892b9268c9a6774229189c60557be4d0d22bf541`: three independent normal QEMU boots and controlled #UD, #GP, and #PF/CR2 fault-injection checks all passed, including vector/error-code/CR2 and halt-marker validation. This verifies the controlled cases in the CI QEMU environment, not hardware-wide exception robustness. Before `interrupts::init()` loads the new IDT, the kernel temporarily relies on the bootloader-provided IDTR and descriptors; `cli` does not suppress synchronous exceptions, NMI, or machine-check events, so diagnostics are not guaranteed during this early window. The handlers still use the active stack, so a dedicated IST stack for reliable double-fault diagnosis is not implemented. The capability crate is a standalone reference model and is not wired into kernel enforcement.

## Target architecture

The first development target is x86_64 under a virtual machine. Additional architectures should be introduced only after interfaces are stable and tested.

### 1. Hardware and boot boundary

The bootloader establishes the initial CPU state and passes a BootInfo structure to the kernel. The kernel now structurally validates the memory-map entries before reporting bootstrap completion: the map must be non-empty, each half-open range must have start < end, and no two ranges may overlap. This does not yet validate the backing pointer used by bootloader_api, classify usable memory for allocation, establish memory ownership, or validate the other BootInfo address fields. The physical page allocator and virtual-memory setup remain unimplemented.

### 2. Minimal trusted kernel

The long-term design favors a microkernel-style trusted computing base. Initial responsibilities are expected to include:

- CPU and exception/interrupt fundamentals;
- address-space and memory-region control;
- thread lifecycle and scheduling;
- secure inter-process communication (IPC);
- capability validation at protected operations;
- controlled transitions between user mode and kernel mode.

File systems, networking, most device drivers, policy, and the service manager should run as isolated services where practical. Real-time and high-throughput paths may require measured, explicitly reviewed exceptions.

### 3. Authority and IPC

A resource is represented by an object identifier. A capability grants a limited set of rights over that object. The kernel must check capabilities at each privileged operation and must not trust a token copied from user memory without validating its provenance and ownership.

The current oneos-core crate demonstrates only grant/check/revoke semantics within one authority. It does not provide kernel isolation, protected memory, IPC, delegation, or protection against malicious unsafe code. These features must not be inferred from its unit tests.

### 4. System services

Planned services include storage, networking, device management, cryptographic key handling, identity, updates, software installation, logging, and UI composition. Each service should have a narrow API and an explicit rights manifest.

### 5. Application runtimes

The intended long-term model has three paths:

- native ABI for low-overhead, platform-specific applications;
- sandboxed portable modules, potentially WebAssembly-based;
- compatibility environments or virtual machines for legacy applications.

Compatibility is measured per application and version. It is not assumed to be universal.

### 6. User experience and AI

The UI should adapt to desktop, mobile, and server contexts while preserving coherent navigation and accessibility. AI-enabled actions must use the same authority checks as other clients, run with scoped permissions, and require confirmation for high-impact or irreversible operations.

### 7. Updates and recovery

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
