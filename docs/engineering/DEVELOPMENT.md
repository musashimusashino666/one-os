# Development Guide

## Toolchain

The repository pins a nightly Rust toolchain in `rust-toolchain.toml` and requests rustfmt, Clippy, LLVM tools, Rust sources, and the `x86_64-unknown-none` target. QEMU and Python 3 are also required for the complete local acceptance flow.

Use the exact pinned toolchain when reproducing CI. Do not substitute an arbitrary nightly and treat differing results as equivalent.

## Fast checks

Run from the repository root:

~~~sh
cargo fmt --all -- --check
cargo test --locked -p oneos-core
cargo clippy --locked -p oneos-core --all-targets -- -D warnings
cargo clippy --locked -p one-os-kernel --target x86_64-unknown-none -- -D warnings
cargo clippy --locked -p oneos-xtask --all-targets -- -D warnings
cargo check --locked -p one-os-kernel --target x86_64-unknown-none
~~~

## Build a BIOS image

~~~sh
cargo run --locked -p oneos-xtask -- image
~~~

The tool builds the bare-metal kernel and creates `one-os-bios.img` inside Cargo's reported target directory. It must respect `CARGO_TARGET_DIR` and Cargo configuration. Python 3 is used to resolve the actual output path for the QEMU command.

## Run QEMU

~~~sh
IMAGE_DIR="$(cargo metadata --locked --format-version 1 --no-deps | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')"
qemu-system-x86_64   -machine pc-i440fx-8.2,accel=tcg   -cpu qemu64,+nx -smp 1 -m 128M   -drive format=raw,file="$IMAGE_DIR/one-os-bios.img"   -serial stdio -display none -no-reboot -no-shutdown
~~~

The guest profile is intentionally fixed to one CPU and a declared CPU model. The normal guest keeps running after the bootstrap completion marker; stop it with Ctrl-C. This is a diagnostic bootstrap, not a daily-use OS.

## W^X audit changes

The W^X inventory is read-only. The normal boot path may fail-stop when the audit reports a conflict, but the audit itself does not repair mappings or authorize arbitrary executable publication. A complete declared-scope result requires a stable inventory of the active root plus all registered live kernel-created roots, full walks of supported private trees, validation of shared upper-half entries, and recursive table-alias checks after the ordinary leaf inventory is complete. The root-registry cleanup API refuses to remove a current-CR3 root or any frame still marked allocated; cleanup uncertainty fails closed. The dedicated QEMU W^X profile checks this invariant, but it is not independent proof that all activatable roots have been registered.

Effective W/U/S and NX permissions are intersected through every ancestor entry. A high-half mapping that is effectively user-accessible is rejected; a lower-half mapping with U/S set below a supervisor-only ancestor remains effectively supervisor-only. The active root's physical-memory-offset mapping must be present and offset-correct from physical address zero through the greater of 4 GiB and the highest boot memory-map end (page-rounded), with no gaps and no executable direct-map leaf. This check observes every leaf, including read-only/NX leaves that do not consume W/X inventory entries. The walk is bounded: 128 stored W/X ranges, 16,384 table visits, and 2,048 recursive-alias and duplicate-table-path records. Capacity exhaustion, duplicate table frames on different paths, cycles, malformed entries, or root-snapshot changes must return an audit error; none may be logged as a clean audit. Keep these limits explicit when changing them, and test exact boundary and over-capacity cases. Host tests should cover both insertion orders for cross-page-size W/X overlaps. QEMU evidence must name the exact PR HEAD and guest profile. The dedicated `test-wx-runtime-audit` image also removes an allocated inactive target from the live-root registry under test-only fault injection and calls the shared admission guard directly to verify rejection. This probe does not execute either CR3-switch function; registration is restored before auditing. It creates a deliberate writable alias in an inactive root for the controlled RX frame in the active root, requires the audit to detect the physical conflict, restores the exact PTE, and requires a clean follow-up audit. This is QEMU evidence for the declared roots and test scenario only. A successful bounded audit is not a system-wide W^X proof, and SMP/remote TLB shootdown remains unsupported.

## Pull request workflow

- Use a focused branch and a bounded change.
- Update specification and verification documentation alongside behavior changes.
- Run the fast checks before pushing.
- Require the CI run triggered by the current PR head; a manual run on an older SHA is not evidence for the new head.
- Review the full diff, including generated or moved files, and resolve review comments.
- Do not merge memory-management or security changes solely because host tests pass.
- Keep main protected by the repository's active ruleset and required CI status. Documentation in YAML is not a substitute for the actual GitHub ruleset.

## Change report

A nontrivial PR should state: the invariant changed, alternatives considered, files and APIs affected, validation commands and results, failure cases tested, known gaps, and whether any acceptance test was not run.
