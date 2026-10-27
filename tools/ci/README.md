# CI validation tools

This directory contains host-side validators and their Python regression tests used by the GitHub Actions workflow. These scripts validate emitted CR3-switch assembly and QEMU serial diagnostics; they are tooling, not part of the kernel runtime.

Run the regression suite from the repository root:

```sh
python3 -m unittest discover -s tools/ci -p 'test_*.py'
```

The CI workflow also runs the CR3 assembly validator against optimized kernel assembly and invokes the QEMU validators against the corresponding serial logs.
