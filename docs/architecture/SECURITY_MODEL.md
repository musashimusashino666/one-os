# Security Model

## Security objective

ONE OS aims to protect confidentiality, integrity, and availability of user data and
system state through small privileged code, kernel-enforced authority, isolated
components, verified updates, and predictable recovery.

These are design goals. The current bootstrap does not yet implement the complete
security model.

## Assets

- User documents, credentials, secrets, and cryptographic keys.
- Process memory, service state, and IPC messages.
- Kernel code, page tables, physical-frame ownership, and boot artifacts.
- System configuration, update metadata, and recovery state.
- Permission grants, activity records, and user-defined policy.

## Threats to address

The target model includes malicious or compromised applications and services, malformed
input, cross-process access attempts, confused-deputy behavior, stale or forged
capabilities, update interruption, rollback to vulnerable software, and unauthorized
access to devices or network resources.

Initially out of scope: physical possession attacks, compromised firmware, malicious
hardware, and comprehensive side-channel resistance. Those exclusions must be revisited
before high-assurance claims.

## Trust assumptions and enforcement TCB

ONE OS includes malicious and compromised non-kernel applications, daemons, brokers, and
services in its threat model. The target architecture therefore does **not** delegate
final authorization enforcement to a general-purpose “trusted service.”

- **Mandatory enforcement TCB:** the relevant CPU/MMU and hardware behavior, the kernel
  reference monitor, and the boot path that establishes the running kernel's integrity.
  Production claims require authenticated boot and integrity evidence; those controls
  are not implemented in the current bootstrap.
- **Authority source:** grants must originate from kernel-owned policy or an explicit
  owner-approved grant through a documented trusted consent path. The exact components
  relied upon to authenticate owner intent must be named in the release threat model. A
  service's statement that a request is allowed is not, by itself, a grant.
- **Service containment:** a non-kernel service can broker a request and can use rights
  explicitly delegated to it. It MUST NOT mint authority, widen rights, impersonate the
  caller, override a kernel denial, or authorize a protected operation by presenting
  only its own policy result. The kernel checks the authenticated principal and
  kernel-owned authority state at each protected operation.
- **Compromise consequence:** a compromised service may misuse the capabilities actually
  delegated to that service, corrupt its own state, or deny service. It must not be able
  to exceed those rights or cross into unrelated protected processes/resources.
  Preventing misuse within a service's own granted scope requires narrower grants,
  revocation, confirmation policy, and auditability; it is not implied by containment
  alone.
- **Disallowed delegation:** any architecture in which a service must be trusted to
  bypass kernel checks, mint unrestricted capabilities, or make an unchallengeable allow
  decision is a different threat model. That service becomes part of the enforcement
  TCB; compromise of it invalidates the related security claim and blocks release claims
  for that scope. This is not the target ONE OS architecture.

The trust model assumes the kernel, CPU/MMU, and declared platform base are not
themselves already compromised. Malicious hardware, compromised firmware, and
comprehensive side-channel attacks remain excluded as stated below; they must not be
silently treated as covered by the service-compromise guarantee.

## Trust boundaries

1. **Boot chain to kernel:** validate inputs and CPU preconditions; future releases need
   authenticated boot provenance.
2. **Kernel to user process:** enforce address-space isolation and validated
   entry/return; this boundary is not yet complete.
3. **Process to process:** enforce resource access through kernel-controlled
   capabilities and IPC contracts; currently incomplete.
4. **Service to device/network/storage:** mediate access through explicit rights and
   constrained interfaces; the kernel remains the final enforcement point even when a
   broker or driver service participates. These service boundaries are not yet
   implemented.
5. **Application/AI client to user authority:** delegated actions must be scoped and
   visible. A model or UI must not be able to mint kernel authority.
6. **Update system to running system:** verify provenance, preserve recoverability, and
   prevent unauthorized downgrade; not yet implemented.

## Required properties

- **Default deny:** missing, stale, malformed, or unrecognized authority is rejected.
- **Kernel enforcement:** authorization is checked at the protected operation, not only
  at API construction or user-interface time. A non-kernel policy/broker service cannot
  substitute its own allow decision for kernel-owned authority.
- **Isolation:** one process cannot read or modify another process's private state
  without an explicit permitted transfer.
- **Memory protection:** writable and executable aliases for a physical frame must not
  coexist where the platform contract forbids it. Partial audit coverage must be
  reported as incomplete.
- **Safe lifetime:** page-table roots and data frames are not reused before all relevant
  mappings and translations are quiescent.
- **Fail-closed audit:** capacity exhaustion, unknown roots, malformed entries, and
  unsupported mappings cannot produce a clean success result.
- **Revocation:** authority revocation has defined effects on in-flight work, cached
  rights, and associated mappings.
- **Recoverability:** failure and rollback do not silently expose secrets or downgrade
  security.

## Current controls and limits

The kernel currently has selected boot-mapping validation, a fixed-capacity
physical-frame allocator, guarded page-table mutation, a read-only W^X audit over
declared scope, and QEMU checks for selected supervisor protection, NX, TLB transitions,
and direct-map permission changes. The guest test profile is single-vCPU QEMU.

Executable aliases derived from validated kernel ELF PT_LOAD pages are transitioned to
read-only/NX in the physical-memory-offset mapping; audit runs have checks for zero
conflicts in a declared scope. This does **not** establish global frame-wide W^X across
every possible alias, root, future mapping, or unregistered mapping. Arbitrary
executable mapping publication remains gated.
See open Issues [#26](https://github.com/musashimusashino666/one-os/issues/26)
and [#46](https://github.com/musashimusashino666/one-os/issues/46).

The declared-scope W^X audit walks the active root and every registered live
kernel-created root captured in a stable single-CPU snapshot. It computes effective R/W,
U/S, and NX rights through every ancestor and leaf; any high-half mapping that is
effectively user-accessible fails the audit. It walks the active root's complete tree,
validates shared upper-half PML4 entries in inactive roots, and walks each inactive
root's private lower half. Recursive table aliases are checked separately against the
completed W/X leaf inventory.

The active root's physical-memory-offset mapping is also checked as a complete interval
from physical address zero through the greater of 4 GiB and the highest boot memory-map
end (page-rounded). Each byte in that interval must have a present, contiguous,
offset-correct, non-executable translation, including read-only/NX leaves omitted from
the W/X range inventory. Shared upper-half entries in inactive roots must match the
active root. Repeated page-table frames, malformed entries, root-set changes, a
missing/mis-translated/executable direct-map range, or exhaustion of the fixed
range/table/recursive-alias/table-path budgets fail closed. The table-path inventory is
capped at 2,048 frames; these implementation bounds and the registered-root lifecycle
contract do not prove that every possible root or platform mapping source is enumerable.
Audit coverage means the declared walk completed; it does not mean the inventory is
conflict-free, and neither state is a global W^X proof outside that declared scope.

The current capability model is host-testable reference logic. Kernel-enforced
capabilities, Ring 3 entry/return, complete process isolation, SMP synchronization,
authenticated boot, signed updates, data-at-rest encryption, and a production recovery
system are not implemented. Consequently, the service-compromise boundary described
above is a target contract, not a demonstrated current guarantee.

## Security claim standard

Every security statement must state:

- Protected asset and threat addressed.
- Enforcement mechanism and trusted components.
- Scope of roots, mappings, devices, or operations covered.
- Platform assumptions and synchronization model.
- Positive and negative test evidence on a specific revision.
- Known exclusions and outstanding issues.

A successful build, CI run, audit summary, or QEMU smoke test proves only the behavior
covered by that test. It does not constitute certification or general proof of security.
