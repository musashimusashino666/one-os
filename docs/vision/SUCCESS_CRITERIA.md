# Success Criteria

“World-class” is a target to evaluate, not a current status. This document defines acceptance contracts and the evidence needed to evaluate them. It does not assert that any unfinished criterion has passed.

## Evaluation rules

1. **Declare scope first.** Every result names the candidate revision, hardware/profile, configuration, threat model, supported workloads, and exclusions.
2. **Separate hard gates from comparative goals.** Isolation, integrity, authority enforcement, and safe recovery are pass/fail gates. A strong performance or usability score cannot compensate for a failed hard gate.
3. **Define thresholds before collecting results.** Do not choose a threshold after seeing results. When a credible baseline is unavailable, record the target as TBD and create the baseline study; do not invent a number.
4. **Test the enforcement path.** Model-only or host-only tests are valuable but do not prove that the kernel enforces a rule in the live system. Evidence must state which layer it exercises.
5. **Preserve negative evidence.** Failed tests, incomplete inventories, missing measurements, test exclusions, and known issues remain visible in the report.
6. **Re-run on the exact candidate.** A criterion is satisfied only by reproducible evidence from the candidate revision under review. A prior commit's green CI does not transfer to a new candidate.
7. **Report dimensions separately.** Do not collapse security, recovery, accessibility, compatibility, and performance into a single average that hides a critical failure.

## Evaluation scorecard

| ID / dimension | Acceptance contract | Required evidence / measurement | Current status |
| --- | --- | --- | --- |
| SC-01 — Process isolation and authority | Every declared unauthorized cross-process read/write and protected operation is denied. Valid authority succeeds only within its resource, operation, and scope. Forged, replayed, stale, or revoked authority is rejected. | Adversarial tests through the kernel's real protected operations; positive and negative cases; teardown and revocation tests; independent review of the boundary. | **Not met.** Ring 3 isolation and complete kernel-enforced capabilities are incomplete. |
| SC-02 — Memory protection | For the declared platform and supported mapping forms, no physical frame is simultaneously writable and executable through any accounted alias. Incomplete or unknown inventory and capacity exhaustion fail closed. Transitions preserve TLB and frame-lifetime invariants. | Complete declared-root/alias inventory; tests for every supported page size and mapping source; alias-based W^X tests; stale-translation, unmap, remap, teardown, and failure-path tests. | **Partial.** Selected QEMU paths exist; frame-wide W^X and full alias/root coverage remain incomplete. |
| SC-03 — Boot and update integrity | Boot and update artifacts have verifiable provenance. Invalid, unsigned, tampered, or policy-disallowed downgraded versions do not become active. | Chain-of-trust tests; signature and integrity negative tests; anti-rollback tests; exact-version policy tests; documented key lifecycle and failure behavior. | **Not met.** Authenticated boot and signed-update policy are not implemented. |
| SC-04 — Recovery and data integrity | At each declared update/configuration transition, interruption leads either to a previously verified usable state or to a documented safe recovery mode. Committed data is not silently corrupted or discarded. | Failure injection at every transition point; checksums/integrity verification; recovery tests with disconnected network and unavailable optional services; data-loss and recovery outcomes reported. | **Not met.** No integrated transactional update/recovery system exists. |
| SC-05 — Owner control and privacy | Sensitive operations are authorized by a kernel or explicitly trusted enforcement service, not by UI convention alone. Grants identify resource, operation, scope, and revocation behavior. Protected activity is inspectable; revocation blocks future protected operations, including background/delegated work. | End-to-end tests from grant through enforcement, event inspection, and revocation; tests for hidden ambient access, queued actions, service restart, and AI delegation; publish log exclusions and retention rules. | **Design target.** Integrated user-facing controls and enforcement are not implemented. |
| SC-06 — Reliability and fault containment | Every fault in the declared injection matrix ends in a documented safe outcome: successful recovery, a bounded error, isolation of the failed component, or an explicit fail-stop. No path silently reports success after partial completion. | Failure-injection matrix for allocation, malformed input, IPC, storage, services, and updates; repeated test runs; report fault detection, recovery outcomes, and unrecovered failures. | **Limited.** Kernel/bootstrap fault paths exist; service, storage, and update-level evidence does not. |
| SC-07 — Compatibility | Supported hardware, applications, formats, and execution modes are explicitly listed. Each compatibility claim passes a repeatable test case; exceptions and security trade-offs are documented. | Versioned hardware/software matrix; named applications and workflows; results for native, sandboxed, virtualized, or compatibility modes; reproducible regression suite. | **Not established.** No published compatibility matrix or integrated application environment exists. |
| SC-08 — Performance and resource use | Performance claims are tied to named workloads and relevant baselines, with methodology and variance. Security-critical behavior is not disabled or weakened to achieve a target. | Same hardware and workload where feasible; pinned build/configuration; warm-up and sample method; median and tail latency where relevant, throughput, memory/CPU cost, variance, and baseline comparison. | **Not established.** No comparative performance claim or benchmark protocol exists. Numeric targets are TBD. |
| SC-09 — Usability and accessibility | Representative users can complete core tasks—grant least privilege, inspect access, revoke it, and recover from a documented failure—with an understandable mental model and accessible interaction paths. | Published task definitions; participant/cohort description; task completion, error/recovery rate, time, and comprehension results; tests using declared assistive-technology and input profiles. Set acceptance thresholds before the study. | **Not established.** No integrated UI or user-study evidence exists. |
| SC-10 — Engineering quality and traceability | Every MUST-level contract has a testable acceptance condition or a documented reason it cannot yet be tested. A release candidate is reproducible and required checks are green on its exact revision. Claims match the implemented and tested scope. | Requirement-to-test/evidence traceability; pinned toolchain and build instructions; required CI and artifact review; current issue/exception list; documentation and independent-review records. | **Partial.** CI and design documents exist; end-to-end traceability and review process remain under development. |

## How comparative claims are evaluated

For a claim such as “best-in-class,” “more secure,” “easier to use,” or “faster,” publish an evaluation plan before collecting results. It must state:

- The precise claim and the user outcome it represents.
- At least one relevant workload and the target-user profile.
- The alternative systems/configurations used as comparators and why they are fair comparisons.
- Hardware, software versions, configuration, test method, sample count, variance, and exclusions.
- The threshold or decision rule and its rationale.
- Reproduction steps, results, failures, and limitations.

For broad “best-in-class” claims, compare against at least two relevant alternatives when a fair comparison is possible. If no fair comparator exists, narrow the claim to a measurable property and explain the limitation. Security comparisons must use equivalent threat models and disclose different default configurations; benchmark results from unlike workloads are not comparable.

Do not treat a passing test suite as proof of zero vulnerabilities. Tests establish evidence for declared cases and assumptions. The report must state residual risk and untested areas.

## Release gates

The following gates are non-compensating. They block production/security-readiness claims even if other dimensions perform well.

1. **Isolation and authority:** independent address spaces, validated user-mode entry/return, and adversarial kernel-enforced capability tests pass.
2. **Memory protection:** declared roots and physical aliases are fully accounted for; supported W/X transitions and failure paths pass; unknown or incomplete state fails closed.
3. **Integrity and recovery:** authenticated boot, signed updates, downgrade resistance, key policy, interruption recovery, and persistent-data protection are implemented and tested.
4. **Untrusted-boundary robustness:** fuzzing and failure injection cover the declared critical input and resource boundaries; security-critical unresolved findings are triaged and dispositioned through review.
5. **Product scope:** supported hardware, software, execution paths, known limitations, and recovery procedures are published.
6. **Owner control:** protected access, auditability, and revocation work end-to-end through trusted enforcement; representative users can complete core control tasks.
7. **Usability and performance evidence:** claims are supported by published, repeatable task studies and benchmarks using thresholds set in advance.
8. **Candidate integrity:** the exact release candidate passes its required validation suite, all exceptions are documented, and an independent review appropriate to the risk is complete.

A project milestone may complete without satisfying the production gates, but its status and public claims must remain limited to the evidence actually available.

## Quantitative target policy

Do not invent numerical goals solely to create a sense of precision. Introduce a numeric threshold only when its measurement method and rationale are recorded. Every target should include:

- **Metric:** what is measured and why it matters to the target user.
- **Workload and environment:** hardware, software revision, configuration, and workload.
- **Baseline:** the reference result and why it is suitable.
- **Method:** instrumentation, sample count, warm-up, variance, and failure handling.
- **Threshold:** acceptance value and rationale, set before evaluation.
- **Owner and follow-up:** the work needed to establish or revisit the threshold.

Where evidence is not yet available, write **TBD — baseline required**, identify the baseline study as work, and do not use the missing metric as a success claim.

## Status vocabulary

- **Not established:** there is no adequate implementation/evidence yet.
- **Partial:** some bounded paths are implemented or tested, but the full declared contract is not met.
- **Verified for scope:** required evidence passed for a named scope and exact candidate; this is not a universal guarantee.
- **Blocked:** a known prerequisite or unresolved issue prevents acceptance.

Update the scorecard when implementation or evidence materially changes. Keep [Implementation Status](../project/IMPLEMENTATION_STATUS.md) focused on what exists today and use the [Roadmap](../project/ROADMAP.md) for sequencing and milestone dependencies.
