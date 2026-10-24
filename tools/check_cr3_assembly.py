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
GPR_RE = re.compile(
    r"^(?:r(?:ax|bx|cx|dx|si|di|bp|sp)|r\d+[dwb]?|"
    r"e(?:ax|bx|cx|dx|si|di|bp|sp)|[abcd][lhx]|[sd]il|bpl|spl)$",
    re.IGNORECASE,
)


def activation_function_bodies(assembly: str) -> list[tuple[str, list[str]]]:
    """Return emitted function bodies for the activation routine."""
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
    """Parse a simple emitted instruction, accepting ATT and Intel operand order."""
    line = raw_line.split("#", 1)[0].strip()
    if not line or line.startswith(".") or line.endswith(":"):
        return None
    match = INSTRUCTION_RE.match(line)
    if not match:
        return None
    return match.group(1).lower(), [part.strip() for part in match.group(2).split(",")]


def _att_syntax(operands: list[str]) -> bool:
    return any("%" in part for part in operands)


def _operand_register(operand: str) -> str | None:
    name = operand.strip().lstrip("%").lower()
    if GPR_RE.fullmatch(name):
        return name
    return None


def _register_name(operand: str) -> str:
    return operand.strip().lstrip("%").lower()


def _source_destination(operands: list[str]) -> tuple[str, str] | None:
    if len(operands) < 2:
        return None
    if _att_syntax(operands):
        return operands[0], operands[-1]
    return operands[-1], operands[0]


def _destination(operands: list[str]) -> str | None:
    if not operands:
        return None
    return operands[-1] if _att_syntax(operands) else operands[0]


def _control_register_write_source(raw_line: str, register: str) -> str | None:
    parsed = _instruction(raw_line)
    if parsed is None:
        return None
    mnemonic, operands = parsed
    if not mnemonic.startswith("mov"):
        return None
    pair = _source_destination(operands)
    if pair is None:
        return None
    source, destination = pair
    if _register_name(destination) != register:
        return None
    return _register_name(source)


def _pge_clear_destination(raw_line: str) -> str | None:
    """Return the GPR modified by an AND/BTR that clears CR4.PGE bit 7."""
    parsed = _instruction(raw_line)
    if parsed is None:
        return None
    mnemonic, operands = parsed

    clears_pge = False
    if re.fullmatch(r"and(?:b|w|l|q)?", mnemonic):
        # Compilers may combine adjacent facts. In this routine, PCIDE was
        # already proven clear, so LLVM can combine !CR4_PGE and !CR4_PCIDE
        # into a single immediate such as -131201. Accept any parsed AND
        # immediate whose bit 7 is zero, not only the literal -129.
        for operand in operands:
            token = operand.strip().lstrip("$")
            try:
                mask = int(token, 0)
            except ValueError:
                continue
            if mask & (1 << 7) == 0:
                clears_pge = True
                break
    elif re.fullmatch(r"btr(?:b|w|l|q)?", mnemonic):
        clears_pge = bool(re.search(r"(?:\$)?7\b", ", ".join(operands)))

    if not clears_pge:
        return None
    destination = _destination(operands)
    if destination is None:
        return None
    return _operand_register(destination)


def _clobbered_gpr(raw_line: str) -> str | None:
    """Return a destination register for common compiler-emitted write instructions."""
    parsed = _instruction(raw_line)
    if parsed is None:
        return None
    mnemonic, operands = parsed
    if mnemonic.startswith(("cmp", "test", "j", "call", "ret", "push", "nop", "ud2")):
        return None
    if mnemonic.startswith(("mov", "and", "or", "xor", "add", "sub", "shl", "shr",
                            "sar", "sal", "rol", "ror", "not", "neg", "inc", "dec",
                            "lea", "imul", "bts", "btc", "btr", "xchg", "pop")):
        target = _destination(operands)
        if target is None:
            return None
        return _operand_register(target)
    return None


def validate_function_body(body: list[str]) -> tuple[bool, str]:
    """Track values through register moves and verify PGE clear -> CR3 -> restore."""
    # Register taints move with ordinary GPR-to-GPR MOVs, matching LLVM register
    # allocation even when it inserts a copy between an AND/BTR and MOV CR4.
    # original_cr4 marks the value captured before the switch; pge_cleared marks
    # a derived value with CR4.PGE bit 7 cleared.
    taint: dict[str, str] = {}
    pge_disable_index: int | None = None
    cr3_write_indices: list[int] = []
    pge_restore_index: int | None = None
    first_cr4_write_index: int | None = None
    saw_pge_clear = False

    for index, line in enumerate(body):
        parsed = _instruction(line)
        if parsed is None:
            continue
        mnemonic, operands = parsed

        clear_destination = _pge_clear_destination(line)
        if clear_destination is not None:
            taint[clear_destination] = "pge_cleared"
            saw_pge_clear = True
            continue

        pair = _source_destination(operands) if mnemonic.startswith("mov") else None
        if pair is not None:
            source, destination = pair
            source_reg = _operand_register(source)
            destination_reg = _operand_register(destination)

            if _is_control_register(destination, "cr4") and source_reg:
                if first_cr4_write_index is None:
                    first_cr4_write_index = index
                source_taint = taint.get(source_reg)
                if source_taint == "pge_cleared" and pge_disable_index is None:
                    pge_disable_index = index
                elif source_taint == "original_cr4":
                    pge_restore_index = index
                continue

            if _is_control_register(destination, "cr3"):
                if source_reg is not None:
                    cr3_write_indices.append(index)
                continue

            if _is_control_register(source, "cr4") and destination_reg:
                # A CR4 read prior to the first CR4 write captures the original value.
                if first_cr4_write_index is None and pge_disable_index is None:
                    taint[destination_reg] = "original_cr4"
                else:
                    taint.pop(destination_reg, None)
                continue

            if source_reg and destination_reg:
                source_taint = taint.get(source_reg)
                if source_taint:
                    taint[destination_reg] = source_taint
                else:
                    taint.pop(destination_reg, None)
                continue

            if destination_reg:
                taint.pop(destination_reg, None)
            continue

        # Do not carry a taint through later instructions that overwrite its register.
        clobbered = _clobbered_gpr(line)
        if clobbered:
            taint.pop(clobbered, None)

    if first_cr4_write_index is None or pge_disable_index is None:
        if not saw_pge_clear:
            return False, "no instruction clearing CR4.PGE bit 7 was found"
        return False, "PGE-cleared value did not reach a CR4 write"
    if not cr3_write_indices:
        return False, "no actual CR3 write instruction found in activation routine"
    if pge_restore_index is None:
        return False, "original pre-switch CR4 value was not restored"
    # The optimizer can lay out the PGE-disabled path after a fast path that
    # writes CR3 directly when PGE is already clear. Require a CR3 write on the
    # disable/restore path, rather than incorrectly requiring the first textual
    # CR3 instruction in the function to be on that path.
    if not any(pge_disable_index < index < pge_restore_index for index in cr3_write_indices):
        return False, "required order is PGE disable -> CR3 write -> PGE restore"

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

    block = match.group("body")
    if re.search(r"\bnomem\b", block):
        return False, "CR3 inline asm must not specify nomem"
    if not re.search(r"\bin\(reg\)\s+root_physical\b", block):
        return False, "CR3 inline asm no longer uses the validated root_physical operand"
    return True, "CR3 inline asm preserves the compiler memory-ordering boundary"


def validate_cr4_asm_pge_order(source: str) -> tuple[bool, str]:
    """Ensure source-level CR4 writes disable PGE then restore the original CR4."""
    blocks = re.findall(
        r'asm!\s*\(\s*"mov\s+cr4\s*,\s*\{\}"(?P<body>.*?)\);',
        source,
        flags=re.DOTALL,
    )
    if len(blocks) < 2:
        return False, "expected separate CR4 asm blocks for PGE disable and restore"
    if not re.search(r"\bin\(reg\)\s+cr4_without_pge\b", blocks[0]):
        return False, "first CR4 write must use the PGE-cleared cr4_without_pge value"
    if not re.search(r"cr4_without_pge\s*=\s*cr4\s*&\s*!CR4_PGE\b", source):
        return False, "cr4_without_pge must be derived from cr4 with CR4_PGE cleared"
    if not re.search(r"\bin\(reg\)\s+cr4\b", blocks[1]):
        return False, "second CR4 write must restore the original cr4 value"
    return True, "source CR4 writes disable PGE and restore the original CR4 value"


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
            errors.append(f"{path}: {symbol}: {message}\n--- activation function body ---\n" + "\n".join(body) + "\n--- end activation function body ---")
        else:
            print(f"PASS: {path}: {symbol}: {message}")
            for index, line in enumerate(body):
                if re.search(r"\bcr[34]\b", line) or _pge_clear_destination(line) is not None:
                    print(f"ASM[{index:04d}]: {line.strip()}")

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

    valid, message = validate_cr4_asm_pge_order(source)
    if not valid:
        print(f"FAIL: {args.source}: {message}", file=sys.stderr)
        return 1
    print(f"PASS: {args.source}: {message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
