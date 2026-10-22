# ONE OS Architecture

## Status

This document describes the intended architecture, not a claim that each subsystem already exists. The current executable kernel milestone is an x86_64 entry point with COM1 serial output and a halt loop. The capability crate is a standalone reference model and is not wired into kernel enforcement.

## Target architecture

The first development target is x86_64 under a virtual machine. Additional architectures should be introduced only after interfaces are stable and tested.

### 1. Hardware and boot boundary

The bootloader establishes the initial CPU state and passes a BootInfo structure to the kernel. The kernel must validate every boot-provided address and memory region before use. Boot information is not yet consumed beyond accepting the entry-point parameter.

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
