# ONE OS Vision

## One-sentence definition

**ONE OS is an operating system designed to give people secure, understandable, and revocable control over their digital environment, without sacrificing practical usability, resilience, or software choice.**

ONE OS is a research and engineering project pursuing that definition from a small trusted foundation. “World-class” is an ambition to be earned with comparative evidence, not a claim implied by the project name or design intent.

## The problem to solve

Modern computing asks people to trust large, opaque systems while offering limited visibility into what software can access, what background actions occur, how decisions are made, and how failures can be recovered from. Security settings, application boundaries, updates, and user experience are often treated as separate concerns.

ONE OS treats them as one system-design problem: the machine should protect its owner, explain meaningful authority, make consequential actions controllable, and recover predictably when components fail.

## The intended outcome

A mature ONE OS should let a person:

- Run applications with only the permissions they need, and understand and revoke those permissions.
- Keep one application or service from reading or modifying another's private state without explicit, kernel-enforced authority.
- Inspect consequential system activity without needing to trust undocumented conventions.
- Install updates with provenance checks, detect interrupted or failed updates, and recover without silently returning to a known-vulnerable state.
- Choose among native, sandboxed, and compatibility execution paths with clearly documented trade-offs.
- Use assistive and AI-driven features without granting them invisible or unlimited authority.
- Retain useful control when a component crashes, an update fails, or connectivity disappears.

These are target outcomes. The current bootstrap kernel does not yet implement the complete user-facing system described here.

## Design pillars

1. **Security by construction:** keep privileged code small, validate boundaries, default to denial, and enforce authority in the kernel.
2. **Owner control:** access, network activity, background work, and AI-initiated actions should be visible, scoped, and revocable.
3. **Resilience:** failure states, update interruption, rollback, and recovery are designed and tested rather than left to convention.
4. **Practical compatibility:** portability is a set of explicit execution contracts, not an unqualified promise that every application will run.
5. **Understandability:** system behavior and security guarantees should be explainable to both users and engineers.
6. **Evidence over marketing:** performance, privacy, security, accessibility, and compatibility claims require reproducible tests or measurements.

## What ONE OS is not

- It is not currently a daily-use, production, or security-certified operating system.
- It is not “secure” merely because Rust is used or because one QEMU test passes.
- It is not a promise of universal application compatibility, zero vulnerabilities, perfect privacy, or superior performance without measurements.
- It is not a plan to put every service, driver, interface, and policy into the kernel. The trusted computing base should remain small.
- It is not an excuse to hide uncertainty behind broad terms such as “AI-native” or “next-generation.”

## Decision rule

When goals conflict, prioritize in this order unless an ADR records a justified exception:

1. Prevent unauthorized access and preserve integrity.
2. Preserve recoverability and ownership of data/resources.
3. Keep authority explicit and revokeable.
4. Keep the trusted computing base and critical paths understandable.
5. Preserve usability, accessibility, and practical portability.
6. Optimize performance using measurement.

This ordering is a starting policy and should be revised only through an explicit, reasoned design decision.

## How progress is judged

The [success criteria](SUCCESS_CRITERIA.md) define the evidence needed to assess security, usability, resilience, compatibility, performance, and engineering quality. The [implementation status](../project/IMPLEMENTATION_STATUS.md) states what has actually been demonstrated today.
