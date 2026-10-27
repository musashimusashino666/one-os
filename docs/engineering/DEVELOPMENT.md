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
