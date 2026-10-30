# Success Criteria

“World-class” is a target to evaluate, not a current status. This document defines
acceptance contracts and the evidence needed to evaluate them. It does not assert that
any unfinished criterion has passed.

## Evaluation rules

1. **Declare scope first.** Every result names the candidate revision, hardware/profile,
   configuration, threat model, supported workloads, and exclusions.
2. **Separate hard gates from comparative goals.** Isolation, integrity, authority
   enforcement, and safe recovery are pass/fail gates. A strong performance or usability
   score cannot compensate for a failed hard gate.
3. **Define thresholds before collecting results.** Do not choose a threshold after
   seeing results. When a credible baseline is unavailable, record the target as TBD and
   create the baseline study; do not invent a number.
4. **Test the enforcement path.** Model-only or host-only tests are valuable but do not
   prove that the kernel enforces a rule in the live system. Evidence must state which
   layer it exercises.
5. **Preserve negative evidence.** Failed tests, incomplete inventories, missing
   measurements, test exclusions, and known issues remain visible in the report.
6. **Re-run on the exact candidate.** A criterion is satisfied only by reproducible
   evidence from the candidate revision under review. A prior commit's green CI does not
   transfer to a new candidate.
7. **Report dimensions separately.** Do not collapse security, recovery, accessibility,
   compatibility, and performance into a single average that hides a critical failure.
8. **Use the canonical strategic model without weakening detailed gates.**
   [World-Class OS: Definition and Design](WORLD_CLASS_OS.md) defines
   seven weighted quality dimensions. Their weights summarize comparative value; this
   scorecard's acceptance contracts and the release gates below remain authoritative.

## Evaluation scorecard

Each criterion has an acceptance contract, required evidence, and a conservative current
status.

### SC-01 — Process isolation and authority

**Acceptance contract:** Every unauthorized cross-process read/write and protected
operation is denied. Valid authority succeeds only within its resource, operation, and
scope. Forged, replayed, stale, or revoked authority is rejected.

**Required evidence:** Adversarial tests through real kernel protected operations;
positive and negative cases; teardown and revocation tests; independent review of the
boundary.

**Current status:** Not established. Ring 3 isolation and complete kernel-enforced
capabilities are incomplete.

### SC-02 — Memory protection

**Acceptance contract:** For the declared platform and supported mapping forms, no
physical frame is simultaneously writable and executable through any accounted alias.
Incomplete or unknown inventory and capacity exhaustion fail closed. Transitions
preserve TLB and frame-lifetime invariants.

**Required evidence:** Complete declared-root and alias inventory; tests for every
supported page size and mapping source; alias-based W^X tests; stale-translation, unmap,
remap, teardown, and failure-path tests.

**Current status:** Partial. Selected QEMU paths exist; frame-wide W^X and full
alias/root coverage remain incomplete.

### SC-03 — Boot and update integrity

**Acceptance contract:** Boot and update artifacts have verifiable provenance. Invalid,
unsigned, tampered, or policy-disallowed downgraded versions do not become active.

**Required evidence:** Chain-of-trust tests; signature and integrity negative tests;
anti-rollback tests; exact-version policy tests; documented key lifecycle and failure
behavior.

**Current status:** Not established. Authenticated boot and signed-update policy are not
implemented.

### SC-04 — Recovery and data integrity

**Acceptance contract:** At each declared update/configuration transition, interruption
leads either to a previously verified usable state or to a documented safe recovery
mode. Committed data is not silently corrupted or discarded.

**Required evidence:** Failure injection at every transition; checksums and integrity
verification; recovery tests with disconnected network and unavailable optional
services; reported data-loss and recovery outcomes.

**Current status:** Not established. No integrated transactional update/recovery system
exists.

### SC-05 — Owner control and privacy

**Acceptance contract:** The kernel is the mandatory reference monitor for every
protected operation. A service may broker requests or evaluate policy, but its allow
decision is not authority. The kernel checks the authenticated caller and kernel-owned
grant/capability state. A compromised service cannot mint, widen, impersonate, or bypass
authority. It may still misuse rights explicitly delegated to itself. Grants identify
resource, operation, scope, and revocation behavior.

**Required evidence:** End-to-end real-kernel tests for
grant/enforcement/inspection/revocation; compromised-broker tests for forged or widened
rights, caller impersonation, cross-process access, stale/revoked grants, restart and
stale caches, and denial of service. Verify that a service remains limited to its own
delegated rights. Host-only tests do not satisfy this criterion.

**Current status:** Not established. Integrated user-facing controls and kernel-enforced
process authority are not implemented.

### SC-06 — Reliability and fault containment

**Acceptance contract:** Every fault in the declared injection matrix ends in a
documented safe outcome: successful recovery, a bounded error, isolation of the failed
component, or an explicit fail-stop. No path silently reports success after partial
completion.

**Required evidence:** Failure-injection matrix for allocation, malformed input, IPC,
storage, services, and updates; repeated runs; detection, recovery, and
unrecovered-failure results.

**Current status:** Partial. Kernel/bootstrap fault paths exist; service, storage, and
update-level evidence does not.

### SC-07 — Compatibility

**Acceptance contract:** Supported hardware, applications, formats, and execution modes
are explicitly listed. Each compatibility claim passes a repeatable test; exceptions and
security trade-offs are documented.

**Required evidence:** Versioned hardware/software matrix; named applications and
workflows; results for native, sandboxed, virtualized, or compatibility modes;
repeatable regression suite.

**Current status:** Not established. No published compatibility matrix or integrated
application environment exists.

### SC-08 — Performance and resource use

**Acceptance contract:** Performance claims use named workloads and relevant baselines,
with methodology and variance. Security-critical behavior is not disabled or weakened to
achieve a target.

**Required evidence:** Same hardware and workload where feasible; pinned
build/configuration; warm-up and sample method; median and tail latency where relevant;
throughput, memory/CPU cost, variance, and baseline comparison.

**Current status:** Not established. No comparative performance claim or benchmark
protocol exists. Numeric targets are TBD.

### SC-09 — Usability and accessibility

**Acceptance contract:** Representative users can complete core tasks—grant least
privilege, inspect access, revoke it, and recover from a documented failure—with an
understandable mental model and accessible interaction paths.

**Required evidence:** Published task definitions and cohort; task completion,
error/recovery rate, time, and comprehension; tests using declared assistive-technology
and input profiles. Set acceptance thresholds before the study.

**Current status:** Not established. No integrated UI or user-study evidence exists.

### SC-10 — Engineering quality and traceability

**Acceptance contract:** Every MUST-level contract has a testable acceptance condition
or a documented reason it cannot yet be tested. A release candidate is reproducible and
required checks are green on its exact revision. Claims match the implemented and tested
scope.

**Required evidence:** Requirement-to-test/evidence traceability; pinned toolchain and
build instructions; required CI and artifact review; current issue/exception list;
documentation and independent-review records.

**Current status:** Partial. CI and design documents exist; end-to-end traceability and
review process remain in progress.

### SC-11 — Ecosystem and social/economic value

**Acceptance contract:** The declared product scope provides a practical path for users
and developers to obtain, create, maintain, and use software, with transparent support,
reasonable total cost of ownership, accessible interaction, localization, and meaningful
software choice.

**Required evidence:** Supported software/developer workflows; developer task studies;
total-cost model and assumptions; localization and accessibility coverage;
support/maintenance policy; documented distribution and provenance model.

**Current status:** Not established. No integrated software ecosystem, product cost
model, or representative developer/ user evidence exists.

### SC-12 — Adaptability and evolution

**Acceptance contract:** The OS can adopt declared new hardware, architectures, and
capabilities without silently breaking supported public contracts or weakening security
and recovery requirements. Support and deprecation lifecycles are explicit.

**Required evidence:** Cross-architecture acceptance suites; API/ABI compatibility
tests; upgrade and migration tests; documented deprecation policy; supported-platform
matrix and long-term maintenance evidence.

**Current status:** Not established. Multi-architecture portability, stable public API
lifecycle, and long-term support evidence are not established.

## Traceability to design, specifications, and roadmap

This map identifies the authoritative principles, contracts, and evidence route for each
scorecard dimension. A linked specification does not mean its contract is implemented or
that its evidence has passed.

### SC-01 — Process isolation and authority

- **Principles:** [P1](PRINCIPLES.md), [P2](PRINCIPLES.md), [P8](PRINCIPLES.md).
- **Contracts:** [Process and Capabilities](../specs/PROCESS_AND_CAPABILITIES.md),
  [Ring 3 Isolation Acceptance](../specs/RING3_ISOLATION_ACCEPTANCE.md),
  [Security Model](../architecture/SECURITY_MODEL.md).
- **Evidence route:** M2 in [Project Roadmap](../project/ROADMAP.md);
  real-kernel adversarial tests in
  [Verification Strategy](../engineering/VERIFICATION.md).

### SC-02 — Memory protection

- **Principles:** [P5](PRINCIPLES.md), [P6](PRINCIPLES.md),
  [P7](PRINCIPLES.md), [P8](PRINCIPLES.md).
- **Contracts:** [Virtual-Memory Acceptance](../specs/VIRTUAL_MEMORY_ACCEPTANCE.md),
  [Address-Space Lifecycle](../specs/ADDRESS_SPACE_LIFECYCLE.md).
- **Evidence route:** M1 and M2 in [Project Roadmap](../project/ROADMAP.md);
  Host/QEMU evidence and exact-candidate reporting.

### SC-03 and SC-04 — Boot, update, and recovery integrity

- **Principles:** [P7](PRINCIPLES.md), [P11](PRINCIPLES.md).
- **Contracts:** [Updates and Recovery](../architecture/UPDATES_AND_RECOVERY.md),
  [Security Model](../architecture/SECURITY_MODEL.md).
- **Evidence route:** M5 in [Project Roadmap](../project/ROADMAP.md);
  signature, anti-rollback, and
  interruption/failure-injection evidence, which is not yet implemented.

### SC-05 — Owner control and privacy

- **Principles:** [P1](PRINCIPLES.md), [P2](PRINCIPLES.md), [P9](PRINCIPLES.md).
- **Contracts:** [User Experience](../architecture/USER_EXPERIENCE.md),
  [Security Model](../architecture/SECURITY_MODEL.md),
  [Process and Capabilities](../specs/PROCESS_AND_CAPABILITIES.md).
- **Evidence route:** M2 enforcement and M4 user environment in
  [Project Roadmap](../project/ROADMAP.md); end-to-end grant/inspect/revoke tests.

### SC-06 — Reliability and fault containment

- **Principles:** [P7](PRINCIPLES.md), [P8](PRINCIPLES.md).
- **Contracts:** [Development Guide](../engineering/DEVELOPMENT.md),
  [Verification Strategy](../engineering/VERIFICATION.md),
  and relevant subsystem acceptance specifications.
- **Evidence route:** milestone exit criteria, declared failure-injection matrix, and
  recovery/fail-stop outcomes.

### SC-07 — Compatibility

- **Principles:** [P10](PRINCIPLES.md).
- **Contracts:** [Architecture Overview](../architecture/OVERVIEW.md),
  [User Experience](../architecture/USER_EXPERIENCE.md).
- **Evidence route:** M3 and M5 in [Project Roadmap](../project/ROADMAP.md);
  published hardware/application matrix and
  regression suite.

### SC-08 — Performance and resource use

- **Principles:** [P8](PRINCIPLES.md), [P12](PRINCIPLES.md).
- **Contracts:** comparative-claim and quantitative-target policies in this scorecard;
  [Development Guide](../engineering/DEVELOPMENT.md).
- **Evidence route:** M5 in [Project Roadmap](../project/ROADMAP.md);
  baseline and benchmark protocol before numeric claims.

### SC-09 — Usability and accessibility

- **Principles:** [P8](PRINCIPLES.md), [P9](PRINCIPLES.md).
- **Contracts:** [User Experience](../architecture/USER_EXPERIENCE.md).
- **Evidence route:** M4 in [Project Roadmap](../project/ROADMAP.md);
  representative task study and named input/assistive profiles.

### SC-10 — Engineering quality and traceability

- **Principles:** [P8](PRINCIPLES.md).
- **Contracts:** [Documentation Map](../README.md),
  [Development Guide](../engineering/DEVELOPMENT.md),
  [Verification Strategy](../engineering/VERIFICATION.md).
- **Evidence route:** all milestones; required checks and evidence must identify the
  exact candidate revision.

### SC-11 — Ecosystem and social/economic value

- **Principles:** [P9](PRINCIPLES.md), [P10](PRINCIPLES.md), [P12](PRINCIPLES.md).
- **Contracts:** [World-Class OS](WORLD_CLASS_OS.md),
  [User Experience](../architecture/USER_EXPERIENCE.md),
  [Architecture Overview](../architecture/OVERVIEW.md).
- **Evidence route:** P0 product validation, M3 minimum usable system, M4 owner
  environment, and M5 release/portability; developer/user studies and cost/support
  model.

### SC-12 — Adaptability and evolution

- **Principles:** [P8](PRINCIPLES.md), [P10](PRINCIPLES.md),
  [P11](PRINCIPLES.md), [P12](PRINCIPLES.md).
- **Contracts:** [World-Class OS](WORLD_CLASS_OS.md),
  [Architecture Overview](../architecture/OVERVIEW.md),
  [Updates and Recovery](../architecture/UPDATES_AND_RECOVERY.md).
- **Evidence route:** M5 cross-architecture and API/ABI compatibility
  work in [Project Roadmap](../project/ROADMAP.md).


When a code change alters a contract, update the normative specification and the
relevant acceptance test in the same change.
Update [Implementation Status](../project/IMPLEMENTATION_STATUS.md)
only when source or verification
evidence materially changes. Keep this scorecard's statuses conservative until the exact
evidence exists.

## How comparative claims are evaluated

For a claim such as “best-in-class,” “more secure,” “easier to use,” or “faster,”
publish an evaluation plan before collecting results. It must state:

- The precise claim and the user outcome it represents.
- At least one relevant workload and the target-user profile.
- The alternative systems/configurations used as comparators and why they are fair
  comparisons.
- Hardware, software versions, configuration, test method, sample count, variance, and
  exclusions.
- The threshold or decision rule and its rationale.
- Reproduction steps, results, failures, and limitations.

For broad “best-in-class” claims, compare against at least two relevant alternatives
when a fair comparison is possible. If no fair comparator exists, narrow the claim to a
measurable property and explain the limitation. Security comparisons must use equivalent
threat models and disclose different default configurations; benchmark results from
unlike workloads are not comparable.

Do not treat a passing test suite as proof of zero vulnerabilities. Tests establish
evidence for declared cases and assumptions. The report must state residual risk and
untested areas.

## Release gates

The following gates are non-compensating. They block production/security-readiness
claims even if other dimensions perform well.

1. **Isolation and authority:** independent address spaces, validated user-mode
   entry/return, and adversarial kernel-enforced capability tests pass.
2. **Memory protection:** declared roots and physical aliases are fully accounted for;
   supported W/X transitions and failure paths pass; unknown or incomplete state fails
   closed.
3. **Integrity and recovery:** authenticated boot, signed updates, downgrade resistance,
   key policy, interruption recovery, and persistent-data protection are implemented and
   tested.
4. **Untrusted-boundary robustness:** fuzzing and failure injection cover declared
   critical input/resource boundaries. All Critical security findings are fixed, and the
   relevant regression plus acceptance suite passes on the exact release candidate.
   Findings that could violate a hard security gate block release regardless of their
   current triage state.
5. **Product scope:** supported hardware, software, execution paths, known limitations,
   and recovery procedures are published.
6. **Owner control:** protected access, auditability, and revocation work end-to-end
   through the kernel-enforced reference monitor. A service may broker or recommend an
   action, but its own allow decision cannot grant rights or override a kernel denial;
   representative users can complete core control tasks.
7. **Usability and performance evidence:** claims are supported by published, repeatable
   task studies and benchmarks using thresholds set in advance.
8. **Candidate integrity:** the exact release candidate passes its required validation
   suite, all exceptions are documented, and an independent review appropriate to the
   risk is complete.

A project milestone may complete without satisfying the production gates, but its status
and public claims must remain limited to the evidence actually available.

## Security finding severity and release exceptions

Use the following severity rules for release decisions. A project issue's workflow state
(open, triaged, assigned, or in review) does not determine whether it blocks release.

- **Critical — unconditional release blocker.** A demonstrated or credible path to
  violate a hard security gate is Critical. Examples include unauthorized cross-process
  access, kernel-privilege or capability-authority escalation, bypass of required
  memory-protection invariants, or bypass of boot/update authenticity or anti-rollback
  controls. A Critical finding MUST be fixed. The fix, a regression test that reproduces
  the failure, and the applicable adversarial acceptance suite MUST pass on the exact
  release-candidate SHA. A review, mitigation note, or risk acceptance MUST NOT waive a
  Critical finding.
- **High — blocking when a hard gate may be affected.** Any High finding with a
  plausible path to violate a hard gate, or whose impact cannot be bounded with
  evidence, blocks release and must be treated as Critical for release-decision purposes
  until disproven. Severity uncertainty at a security boundary is not grounds to
  downgrade a finding.
- **High — narrowly exception-eligible only outside hard gates.** A High finding may be
  accepted temporarily only if evidence demonstrates that it does not violate any
  release gate. The exception record MUST state: the finding and severity rationale;
  affected components, configurations, and threat preconditions; demonstrated impact and
  residual risk; compensating controls and their test evidence; affected users and any
  required disclosure; a named remediation owner and deadline; an expiry/review date;
  and rollback/disable criteria. Approval requires both the release maintainer and an
  independent security reviewer. If an independent reviewer is unavailable, the
  exception MUST NOT be approved. The exception cannot waive a required acceptance test
  or make a failed hard gate pass.
- **Other findings.** Medium/Low findings must still be recorded and dispositioned
  according to project policy; their existence does not automatically block release, but
  any evidence that changes severity or shows a hard-gate violation must reopen the
  release decision.

Before release, publish a finding disposition summary for the exact candidate: all
Critical findings closed and re-tested; each open High finding either closed or
accompanied by a valid, unexpired exception; no gate-affecting exception; and required
independent review completed. An unresolved Critical finding or a failed security
acceptance test means **NO RELEASE**.

## Quantitative target policy

Do not invent numerical goals solely to create a sense of precision. Introduce a numeric
threshold only when its measurement method and rationale are recorded. Every target
should include:

- **Metric:** what is measured and why it matters to the target user.
- **Workload and environment:** hardware, software revision, configuration, and
  workload.
- **Baseline:** the reference result and why it is suitable.
- **Method:** instrumentation, sample count, warm-up, variance, and failure handling.
- **Threshold:** acceptance value and rationale, set before evaluation.
- **Owner and follow-up:** the work needed to establish or revisit the threshold.

Where evidence is not yet available, write **TBD — baseline required**, identify the
baseline study as work, and do not use the missing metric as a success claim.

## Status vocabulary

- **Not established:** there is no adequate implementation/evidence yet.
- **Partial:** some bounded paths are implemented or tested, but the full declared
  contract is not met.
- **Verified for scope:** required evidence passed for a named scope and exact
  candidate; this is not a universal guarantee.
- **Blocked:** a known prerequisite or unresolved issue prevents acceptance.

Use only these four labels in the scorecard's **Current status** column. Explanatory
sentences may describe details, but synonyms such as “not met,” “limited,” or “design
target” MUST NOT be used as alternate status labels.

Update the scorecard when implementation or evidence materially changes.
Keep [Implementation Status](../project/IMPLEMENTATION_STATUS.md)
focused on what exists today and use the
[Roadmap](../project/ROADMAP.md) for sequencing and milestone dependencies.
