# Development Guide

This guide owns the local toolchain and command reference.
The acceptance contract and security-specific test coverage
belong in the [Verification Strategy](VERIFICATION.md)
and the relevant normative specifications.

## Requirements

- The Rust toolchain pinned in `rust-toolchain.toml`.
- The requested rustfmt, Clippy, LLVM tools, Rust sources,
  and `x86_64-unknown-none` target.
- QEMU system emulation for x86_64.
- Python 3 for CI validators and QEMU log checks.

Use the exact pinned toolchain when reproducing CI.
An arbitrary nightly is not an equivalent test environment.

## Fast checks

Run from the repository root:

```sh
cargo fmt --all -- --check
cargo test --locked -p oneos-core
cargo clippy --locked -p oneos-core --all-targets -- -D warnings
cargo clippy --locked -p one-os-kernel --target x86_64-unknown-none -- -D warnings
cargo clippy --locked -p oneos-xtask --all-targets -- -D warnings
cargo check --locked -p one-os-kernel --target x86_64-unknown-none
```

## Documentation integrity

Run the deterministic documentation checks from the repository root:

```sh
python3 -m unittest discover -s tools/ci -p 'test_check_docs.py'
python3 tools/ci/check_docs.py --root .
```

The validator checks repository-relative Markdown links and heading anchors,
the canonical README navigation, and the 88-character line policy. It does
not access external URLs or modify documentation. Fenced and indented code
blocks are excluded, but raw HTML block content remains subject to the line
limit. Inline code and unbreakable URLs are atomic only when the remaining
prose fits; wide Markdown table rows are never exempt.

## Build a BIOS image

```sh
cargo run --locked -p oneos-xtask -- image
```

The tool prints the actual kernel ELF and image output paths.
Honor the reported path and any configured `CARGO_TARGET_DIR`.

## Run the normal QEMU profile

Resolve Cargo's target directory:

```sh
IMAGE_DIR="$(cargo metadata --locked --format-version 1 --no-deps |
  python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')"
```

Run the declared one-vCPU guest profile:

```sh
qemu-system-x86_64 \
  -machine pc-i440fx-8.2,accel=tcg \
  -cpu qemu64,+nx -smp 1 -m 128M \
  -drive format=raw,file="$IMAGE_DIR/one-os-bios.img" \
  -serial stdio -display none -no-reboot -no-shutdown
```

The normal guest continues running after its bootstrap marker.
Stop it with Ctrl-C. This is a diagnostic bootstrap,
not a daily-use operating system.

## Specialized acceptance profiles

Use the exact profile commands and expected markers in
the [Verification Strategy](VERIFICATION.md).
Keep fault-injection images separate from the normal BIOS image.
Do not interpret a bounded Host or QEMU test as a global security proof.

## Pull request workflow

- Keep changes focused and link the relevant issue.
- Update normative specifications when contracts change.
- Update verification when test coverage or evidence changes.
- Run the fast checks before pushing.
- Require CI to pass on the latest PR HEAD.
- Review the complete diff and resolve review comments.
- Do not merge security changes based only on host tests.

The active GitHub ruleset is authoritative.
YAML comments do not configure repository protection.

## Change report

For a nontrivial change, report:

- The invariant changed and alternatives considered.
- Interfaces, ownership, and lifetime affected.
- Commands run and their exact results.
- Negative cases and failure paths tested.
- Known gaps and checks not run.
