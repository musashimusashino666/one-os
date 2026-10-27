# Success Criteria

“World-class” is an engineering target that must be evaluated across several dimensions. This document defines what to measure, not a claim that the criteria have already been met.

## Evaluation dimensions

| Dimension | Required evidence | Current status |
| --- | --- | --- |
| Isolation and authority | Adversarial tests show that unauthorized cross-process access, forged authority, stale grants, and revoked rights are rejected by kernel-enforced checks. | Not yet demonstrated; Ring 3 isolation and kernel-enforced capabilities are incomplete. |
| Memory protection | Complete alias coverage, fail-closed audit behavior, W^X transition tests, and TLB/lifetime tests across every supported mapping size and root. | Partial; bounded QEMU scenarios exist, while global frame-wide W^X remains open. |
| Boot and recovery | Reproducible boot, integrity/provenance checks, interrupted-update recovery, and downgrade policy tests. | Bootstrap only; authenticated boot and resilient updates are not implemented. |
| Privacy and owner control | Permission scopes, revocation, inspectable activity, and tests that prove background/AI actions respect user authority. | Design goal; user-facing control system is not implemented. |
| Reliability | Failure injection for allocation, storage, updates, and service crashes; recovery success rates are measured. | Limited kernel and QEMU fault-path tests only. |
| Compatibility | Published execution-path matrix and repeatable compatibility suite over named application and hardware sets. | Not yet established. |
| Performance | Reproducible benchmarks on named hardware, with baselines, variance, methodology, and workload descriptions. | No comparative performance claim established. |
| Usability and accessibility | Task-completion, error-recovery, accessibility, and comprehension studies with published methods. | Not yet established. |
| Engineering quality | Reproducible builds, required CI, traceability from requirement to tests, review records, and maintained documentation. | CI and design documentation exist; overall process remains under development. |

## Rules for quantitative targets

A number becomes a project target only when its methodology is defined. For every numeric target, record:

- What is measured and why it matters.
- Workload, hardware, software revision, and environment.
- Baseline and comparison set.
- Collection method, sample count, variance, and failure conditions.
- Threshold and rationale.
- Test or report that reproduces the result.

Do not invent performance, compatibility, reliability, or security scores to make the project appear mature. If a credible baseline is unavailable, mark the target as **TBD** and schedule the work required to define it.

## Release gates

No production or security-readiness claim may be made until the relevant gates are met:

1. Independent address spaces and user-mode entry/return have adversarial acceptance tests.
2. Kernel-enforced capability checks are exercised on protected operations.
3. Physical memory alias coverage and executable permission transitions are complete for the declared platform.
4. Boot integrity, signed updates, downgrade resistance, data protection, and recovery policies are implemented and tested.
5. Failure and fuzz testing cover untrusted boundaries.
6. Supported hardware, software, and compatibility limits are published.
7. Usability, accessibility, and performance claims cite reproducible evidence.
8. The exact release candidate passes its full validation suite and receives an independent review appropriate to the risk.

Passing one gate does not imply that the other gates are satisfied.
