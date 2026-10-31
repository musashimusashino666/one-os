# CI validation tools

This directory contains host-side validators and their Python regression tests used by
the GitHub Actions workflow. These scripts validate emitted CR3-switch assembly and QEMU
serial diagnostics; they are tooling, not part of the kernel runtime.

Run the regression suite from the repository root:

```sh
python3 -m unittest discover -s tools/ci -p 'test_*.py'
```

The CI workflow also runs the CR3 assembly validator against optimized kernel assembly
and invokes the QEMU validators against the corresponding serial
logs. The dedicated `run_qemu_nmi_wx_transition.py`
runner waits for the guest's verified-non-present PTE marker, injects a real NMI through
QMP, and requires the IST2 terminal pass marker plus the expected
`isa-debug-exit` status.

## Documentation integrity validator

Run the focused documentation checks from the repository root:

```sh
python3 -m unittest discover -s tools/ci -p 'test_check_docs.py'
python3 tools/ci/check_docs.py --root .
```

The checker validates local Markdown links and heading fragments, required
README navigation, and the 88-character line policy. It does not contact
external websites or rewrite files. Fenced and indented code blocks are
excluded. Raw HTML block content remains subject to the line limit. Inline
code and unbreakable URLs are atomic only when the remaining prose fits. Wide
table rows receive no exemption.
