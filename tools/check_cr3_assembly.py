#!/usr/bin/env python3
"""Check optimized x86_64 assembly for the kernel CR3/PGE switch sequence."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

FUNCTION_NAME = "activate_supervisor_kernel_root"
TYPE_RE = re.compile(r"^\s*\.type\s+([^,\s]+)\s*,\s*@function\b")
FUNCTION_END_RE = re.compile(r"^\s*\.Lfunc_end\d+\s*:")
SIZE_RE_TEMPLATE = r"^\s*\.size\s+{}\s*,"
INSTRUCTION_RE = re.compile(r"^\s*([a-zA-Z][a-zA-Z0-9.]*)\s+(.+?)\s*$")


def activation_function_bodies(assembly: str) -> list[tuple[str, list[str]]]:
    """Return the emitted function body or bodies for the activation routine."""
    lines = assembly.splitlines()
    found: list[tuple[str, list[str]]] = []

    for index, line in enumerate(lines):
        match = TYPE_RE.match(line)
        if not match:
            continue
        symbol = match.group(1)
        if FUNCTION_NAME not in symbol:
            continue

        label_re = re.compile(r"^\s*" + re.escape(symbol) + r"\s*:\s*$")
        label_index = next(
            (i for i in range(index + 1, len(lines)) if label_re.match(lines[i])),
            None,
        )
        if label_index is None:
            continue

        size_re = re.compile(SIZE_RE_TEMPLATE.format(re.escape(symbol)))
        end_index = next(
            (
                i
                for i in range(label_index + 1, len(lines))
                if FUNCTION_END_RE.match(lines[i]) or size_re.match(lines[i])
            ),
            len(lines),
        )
        found.append((symbol, lines[label_index + 1 : end_index]))

    return found


def _instruction(raw_line: str) -> tuple[str, list[str]] | None:
    """Parse a simple emitted instruction, accepting AT&T and Intel operand order."""
    line = raw_line.split("#", 1)[0].strip()
    if not line or line.startswith(".") or line.endswith(":"):
        return None
    match = INSTRUCTION_RE.match(line)
    if not match:
        return None
    return match.group(1).lower(), [part.strip() for part in match.group(2).split(",")]


def _att_syntax(operands: list[str]) -> bool:
    return any("%" in part for part in operands)


def _register_name(operand: str) -> str:
    return operand.strip().lstrip("%").lower()


def _writes_control_register(raw_line: str, register: str) -> bool:
    parsed = _instruction(raw_line)
    if parsed is None:
        return False
    mnemonic, operands = parsed
    if not mnemonic.startswith("mov") or not operands:
        return False
    destination = operands[-1] if _att_syntax(operands) else operands[0]
    return _register_name(destination) == register


def _control_register_write_source(raw_line: str, register: str) -> str | None:
    parsed = _instruction(raw_line)
    if parsed is None:
        return None
    mnemonic, operands = parsed
    if not mnemonic.startswith("mov") or not operands:
        return None
    destination = operands[-1] if _att_syntax(operands) else operands[0]
    if _register_name(destination) != register or len(operands) < 2:
        return None
    source = operands[0] if _att_syntax(operands) else operands[-1]
    return _register_name(source)


def _control_register_read_destination(raw_line: str, register: str) -> str | None:
    parsed = _instruction(raw_line)
    if parsed is None:
        return None
    mnemonic, operands = parsed
    if not mnemonic.startswith("mov") or len(operands) < 2:
        return None
    if _att_syntax(operands):
        source, destination = operands[0], operands[-1]
    else:
        destination, source = operands[0], operands[-1]
    if _register_name(source) != register:
        return None
    return _register_name(destination)


def _pge_clear_destination(raw_line: str) -> str | None:
    """Return the register modified by an instruction that clears CR4.PGE bit 7."""
    parsed = _instruction(raw_line)
    if parsed is None:
        return None
    mnemonic, operands = parsed
    joined = ", ".join(operands).lower()

    clears_pge = False
    if re.fullmatch(r"and(?:b|w|l|q)?", mnemonic):
        clears_pge = bool(
            re.search(r"(?<![\w])(?:\$)?-129(?!\d)", joined)
            or re.search(r"0x0*ffffffffffffff7f\b", joined)
            or re.search(r"18446744073709551487\b", joined)
        )
    elif re.fullmatch(r"btr(?:b|w|l|q)?", mnemonic):
        clears_pge = bool(re.search(r"(?:\$)?7\b", joined))

    if not clears_pge or not operands:
        return None
    # AND and BTR modify their destination in both supported assembly dialects.
    destination = operands[-1] if _att_syntax(operands) else operands[0]
    if destination.startswith("$") or destination.lstrip("%").lower().startswith("cr"):
        return None
    return _register_name(destination)


def validate_function_body(body: list[str]) -> tuple[bool, str]:
    """Require a data-flow-consistent PGE clear -> CR3 write -> PGE restore sequence."""
    cr4_writes = [
        index for index, line in enumerate(body) if _writes_control_register(line, "cr4")
    ]
    cr3_writes = [
        index for index, line in enumerate(body) if _writes_control_register(line, "cr3")
    ]

    if len(cr4_writes) < 2:
        return False, f"expected CR4 writes for PGE disable/restore; found {len(cr4_writes)}"
    if not cr3_writes:
        return False, "no actual CR3 write instruction found in activation routine"

    first_cr4_write = cr4_writes[0]
    last_cr4_write = cr4_writes[-1]
    disabled_value = _control_register_write_source(body[first_cr4_write], "cr4")
    restored_value = _control_register_write_source(body[last_cr4_write], "cr4")

    if disabled_value is None or not any(
        _pge_clear_destination(line) == disabled_value for line in body[:first_cr4_write]
    ):
        return False, "PGE bit 7 is not cleared in the register written to CR4"
    if not any(first_cr4_write < index < last_cr4_write for index in cr3_writes):
        return False, "CR3 write is not ordered between the PGE disable and restore writes"

    if restored_value is None or restored_value == disabled_value:
        return False, "PGE restore does not use a separate saved CR4 value"
    if not any(
        _control_register_read_destination(line, "cr4") == restored_value
        for line in body[:first_cr4_write]
    ):
        return False, "PGE restore value is not loaded from the pre-switch CR4 value"

    return True, "optimized activation assembly validates PGE clear -> CR3 write -> PGE restore"


def validate_cr3_asm_memory_order(source: str) -> tuple[bool, str]:
    """Ensure the CR3 inline asm retains the compiler memory clobber."""
    match = re.search(
        r'asm!\s*\(\s*"mov\s+cr3\s*,\s*\{\}"(?P<body>.*?)\);',
        source,
        flags=re.DOTALL,
    )
    if match is None:
        return False, "could not locate the CR3 asm block in address_space.rs"

    body = match.group("body")
    if re.search(r"\bnomem\b", body):
        return False, "CR3 inline asm must not specify nomem"
    if not re.search(r"\bin\(reg\)\s+root_physical\b", body):
        return False, "CR3 inline asm no longer uses the validated root_physical operand"
    return True, "CR3 inline asm preserves the compiler memory-ordering boundary"


def validate_assembly_directory(assembly_dir: Path) -> tuple[bool, list[str]]:
    paths = sorted(assembly_dir.rglob("*.s"))
    if not paths:
        return False, [f"no .s assembly files found under {assembly_dir}"]

    matches: list[tuple[Path, str, list[str]]] = []
    errors: list[str] = []
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as error:
            errors.append(f"cannot read {path}: {error}")
            continue
        matches.extend((path, symbol, body) for symbol, body in activation_function_bodies(text))

    if not matches:
        return False, errors + [
            f"could not find optimized {FUNCTION_NAME} function in any .s file under {assembly_dir}"
        ]

    for path, symbol, body in matches:
        valid, message = validate_function_body(body)
        if not valid:
            errors.append(f"{path}: {symbol}: {message}")
        else:
            print(f"PASS: {path}: {symbol}: {message}")

    return not errors, errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assembly-dir", required=True, type=Path, help="directory containing optimized .s files")
    parser.add_argument("--source", required=True, type=Path, help="address_space.rs source path")
    args = parser.parse_args()

    valid, messages = validate_assembly_directory(args.assembly_dir)
    if not valid:
        for message in messages:
            print(f"FAIL: {message}", file=sys.stderr)
        return 1
    for message in messages:
        print(f"NOTE: {message}")

    try:
        source = args.source.read_text(encoding="utf-8")
    except OSError as error:
        print(f"FAIL: cannot read {args.source}: {error}", file=sys.stderr)
        return 1

    valid, message = validate_cr3_asm_memory_order(source)
    if not valid:
        print(f"FAIL: {args.source}: {message}", file=sys.stderr)
        return 1
    print(f"PASS: {args.source}: {message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
