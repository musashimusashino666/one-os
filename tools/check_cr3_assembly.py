#!/usr/bin/env python3
"""Check optimized x86_64 assembly for the kernel CR3/PGE switch sequence."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

FUNCTION_NAMES = ("activate_supervisor_kernel_root", "switch_address_space")
FUNCTION_NAME = "activate_supervisor_kernel_root"
TYPE_RE = re.compile(r"^\s*\.type\s+([^,\s]+)\s*,\s*@function\b")
FUNCTION_END_RE = re.compile(r"^\s*\.Lfunc_end\d+\s*:")
SIZE_RE_TEMPLATE = r"^\s*\.size\s+{}\s*,"
INSTRUCTION_RE = re.compile(r"^\s*([a-zA-Z][a-zA-Z0-9.]*)(?:\s+(.+?))?\s*$")
GPR_RE = re.compile(
    r"^(?:r(?:ax|bx|cx|dx|si|di|bp|sp)|r\d+[dwb]?|"
    r"e(?:ax|bx|cx|dx|si|di|bp|sp)|[abcd][lhx]|[sd]il|bpl|spl)$",
    re.IGNORECASE,
)


def activation_function_bodies(assembly: str) -> list[tuple[str, list[str]]]:
    """Return emitted function bodies for all CR3-switch routines."""
    lines = assembly.splitlines()
    found: list[tuple[str, list[str]]] = []

    for index, line in enumerate(lines):
        match = TYPE_RE.match(line)
        if not match:
            continue
        symbol = match.group(1)
        if not any(function_name in symbol for function_name in FUNCTION_NAMES):
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
    operands = match.group(2)
    return match.group(1).lower(), (
        [part.strip() for part in operands.split(",")] if operands is not None else []
    )


def _att_syntax(operands: list[str]) -> bool:
    return any("%" in part for part in operands)


def _operand_register(operand: str) -> str | None:
    name = operand.strip().lstrip("%").lower()
    if not GPR_RE.fullmatch(name):
        return None

    aliases = {
        "eax": "rax", "ax": "rax", "al": "rax", "ah": "rax",
        "ebx": "rbx", "bx": "rbx", "bl": "rbx", "bh": "rbx",
        "ecx": "rcx", "cx": "rcx", "cl": "rcx", "ch": "rcx",
        "edx": "rdx", "dx": "rdx", "dl": "rdx", "dh": "rdx",
        "esi": "rsi", "si": "rsi", "sil": "rsi",
        "edi": "rdi", "di": "rdi", "dil": "rdi",
        "ebp": "rbp", "bp": "rbp", "bpl": "rbp",
        "esp": "rsp", "sp": "rsp", "spl": "rsp",
    }
    if name in aliases:
        return aliases[name]
    match = re.fullmatch(r"(r\d+)[dwb]?", name)
    if match:
        return match.group(1)
    return name


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


def _is_control_register(operand: str, register: str) -> bool:
    """Return whether an operand names the specified x86 control register."""
    return _register_name(operand) == register


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
    """Return a register only for a CR4-derived AND/BTR that safely clears PGE."""
    parsed = _instruction(raw_line)
    if parsed is None:
        return None
    mnemonic, operands = parsed
    if len(operands) != 2:
        return None

    destination = _destination(operands)
    if destination is None:
        return None
    destination_register = _operand_register(destination)
    if destination_register is None:
        return None

    # CR4 is read into a 64-bit GPR. A 32-bit AND would zero-extend its result,
    # destroying bits 32..63; require a 64-bit destination operation instead.
    raw_destination = destination.strip().lstrip("%").lower()
    gpr64 = {
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
        *(f"r{i}" for i in range(8, 16)),
    }
    source_operand = operands[0] if _att_syntax(operands) else operands[1]

    if re.fullmatch(r"and(?:q)?", mnemonic):
        if raw_destination not in gpr64:
            return None
        token = source_operand.strip().lstrip("$")
        try:
            immediate = int(token, 0)
        except ValueError:
            return None

        # x86-64 AND r/m64, imm32 sign-extends its immediate. Verify against
        # the effective 64-bit mask. Only PGE (bit 7), LA57 (bit 12), and PCIDE
        # (bit 17) may be cleared: the latter two are checked clear immediately
        # before this path by validate_kernel_root_activation_state().
        if not -(1 << 31) <= immediate < (1 << 31):
            return None
        mask64 = immediate & ((1 << 64) - 1)
        cleared_bits = (~mask64) & ((1 << 64) - 1)
        permitted_clears = (1 << 7) | (1 << 12) | (1 << 17)
        if cleared_bits & (1 << 7) == 0:
            return None
        if cleared_bits & ~permitted_clears:
            return None
        return destination_register

    if re.fullmatch(r"btr(?:q|w)?", mnemonic):
        # BTR changes only the selected bit. BTR r32 is deliberately rejected
        # because writing the 32-bit register clears the upper 32 GPR bits.
        if mnemonic.endswith("w"):
            word_destinations = {
                "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
            }
            if raw_destination not in word_destinations and not re.fullmatch(r"r\d+w", raw_destination):
                return None
        elif raw_destination not in gpr64:
            return None
        try:
            bit_index = int(source_operand.strip().lstrip("$"), 0)
        except ValueError:
            return None
        if bit_index != 7:
            return None
        return destination_register

    return None

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
    """Require every reachable CR3 write to be bracketed by PGE disable/restore."""
    instructions: list[tuple[str, str, list[str]]] = []
    labels: dict[str, int] = {}
    for raw_line in body:
        stripped = raw_line.split("#", 1)[0].strip()
        if not stripped:
            continue
        if stripped.endswith(":"):
            labels[stripped[:-1].strip()] = len(instructions)
            continue
        parsed = _instruction(raw_line)
        if parsed is not None:
            mnemonic, operands = parsed
            instructions.append((raw_line, mnemonic, operands))

    if not instructions:
        return False, "activation routine contains no instructions"

    # Build the CFG and analyze both edges of each conditional branch. This is
    # deliberately conservative: any reachable CR3 write must satisfy the
    # protocol, even if another path through the function is safe.
    successors: list[list[int]] = [[] for _ in instructions]
    for index, (_, mnemonic, operands) in enumerate(instructions):
        fallthrough = index + 1 if index + 1 < len(instructions) else None
        target = labels.get(operands[-1].strip()) if mnemonic.startswith("j") and operands else None
        if mnemonic.startswith("jmp"):
            if target is not None:
                successors[index].append(target)
        elif mnemonic.startswith("j"):
            if target is not None:
                successors[index].append(target)
            if fallthrough is not None and fallthrough not in successors[index]:
                successors[index].append(fallthrough)
        elif mnemonic.startswith(("ret", "iret", "ud2", "hlt")):
            continue
        elif fallthrough is not None:
            successors[index].append(fallthrough)

    registers = [
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
        *(f"r{i}" for i in range(8, 16)),
    ]
    reg_index = {name: index for index, name in enumerate(registers)}
    NONE = "-"
    ORIGINAL = "original_cr4"
    CLEARED = "pge_cleared"

    # Protocol stage:
    #   0 = no verified CR4.PGE-clear write
    #   1 = PGE-cleared CR4 has been written; CR3 write is now permitted
    #   2 = CR3 was written; original CR4 must be restored before any exit
    #   3 = original CR4 was restored; completed switch
    def instruction_transfer(
        index: int, tags: tuple[str, ...], stage: int
    ) -> tuple[tuple[str, ...], int]:
        raw_line, mnemonic, operands = instructions[index]
        state = list(tags)

        if mnemonic.startswith("call"):
            # SysV x86-64 caller-saved registers are not preserved by calls.
            for name in ("rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"):
                state[reg_index[name]] = NONE
            return tuple(state), stage

        if mnemonic == "cpuid":
            for name in ("rax", "rbx", "rcx", "rdx"):
                state[reg_index[name]] = NONE
            return tuple(state), stage

        if mnemonic == "rdmsr":
            state[reg_index["rax"]] = NONE
            state[reg_index["rdx"]] = NONE
            return tuple(state), stage

        clear_destination = _pge_clear_destination(raw_line)
        if clear_destination is not None:
            slot = reg_index.get(clear_destination)
            if slot is not None and state[slot] in (ORIGINAL, CLEARED):
                state[slot] = CLEARED
            elif slot is not None:
                state[slot] = NONE
            return tuple(state), stage

        pair = _source_destination(operands) if mnemonic.startswith("mov") else None
        if pair is not None:
            source, destination = pair
            source_register = _operand_register(source)
            destination_register = _operand_register(destination)

            if _is_control_register(destination, "cr4"):
                source_tag = state[reg_index[source_register]] if source_register in reg_index else NONE
                if source_tag == CLEARED and stage in (0, 4):
                    stage = 1
                elif source_tag == ORIGINAL and stage == 1:
                    # Restoring CR4 before CR3 can re-enable PGE on the path.
                    # That path may still return an error safely, but a later
                    # CR3 write on it must not be accepted.
                    stage = 4
                elif source_tag == ORIGINAL and stage == 2:
                    stage = 3
                return tuple(state), stage

            if _is_control_register(destination, "cr3"):
                # The caller checks this edge before transfer; retain this
                # transition only for a path already proven to have PGE clear.
                if source_register in reg_index and stage == 1:
                    stage = 2
                return tuple(state), stage

            if _is_control_register(source, "cr4") and destination_register in reg_index:
                state[reg_index[destination_register]] = ORIGINAL
                return tuple(state), stage

            if destination_register in reg_index:
                destination_slot = reg_index[destination_register]
                state[destination_slot] = (
                    state[reg_index[source_register]]
                    if source_register in reg_index
                    else NONE
                )
            return tuple(state), stage

        clobbered = _clobbered_gpr(raw_line)
        if clobbered in reg_index:
            state[reg_index[clobbered]] = NONE
        if mnemonic.startswith("set") and operands:
            destination = _destination(operands)
            register = _operand_register(destination) if destination else None
            if register in reg_index:
                state[reg_index[register]] = NONE
        if mnemonic.startswith("xchg"):
            for operand in operands:
                register = _operand_register(operand)
                if register in reg_index:
                    state[reg_index[register]] = NONE
        return tuple(state), stage

    saw_clear_instruction = any(
        _pge_clear_destination(raw_line) is not None
        for raw_line, _, _ in instructions
    )
    saw_clear_write = False
    saw_cr3_write = False
    saw_restore_write = False
    saw_completed_switch = False
    unsafe_cr3_path: str | None = None
    incomplete_exit: tuple[int, str] | None = None

    from collections import deque

    initial_tags = tuple(NONE for _ in registers)
    pending = deque([(0, initial_tags, 0)])
    visited: set[tuple[int, tuple[str, ...], int]] = set()
    state_limit = max(100_000, len(instructions) * 4096)

    while pending:
        index, tags, stage = pending.popleft()
        key = (index, tags, stage)
        if key in visited:
            continue
        visited.add(key)
        if len(visited) > state_limit:
            return False, "control-flow path analysis exceeded its state limit"

        raw_line, mnemonic, operands = instructions[index]
        pair = _source_destination(operands) if mnemonic.startswith("mov") else None

        # Reject each unsafe CR3 edge immediately. Do not return success merely
        # because some other path completed the protocol.
        if pair is not None:
            source, destination = pair
            source_register = _operand_register(source)
            source_tag = tags[reg_index[source_register]] if source_register in reg_index else NONE
            if _is_control_register(destination, "cr3"):
                saw_cr3_write = True
                if source_register not in reg_index:
                    unsafe_cr3_path = (
                        f"unrecognized CR3 source at instruction {index}: {raw_line.strip()}"
                    )
                elif stage != 1 and unsafe_cr3_path is None:
                    unsafe_cr3_path = (
                        "reachable CR3 write is not dominated by a PGE-cleared CR4 write "
                        f"(stage={stage}, instruction {index}: {raw_line.strip()})"
                    )
            elif _is_control_register(destination, "cr4") and source_register in reg_index:
                if source_tag == CLEARED:
                    saw_clear_write = True
                elif source_tag == ORIGINAL:
                    saw_restore_write = True

        next_tags, next_stage = instruction_transfer(index, tags, stage)

        # A terminal instruction or a block that falls out of the function
        # cannot leave PGE disabled or CR4 unrestored after a CR3 write.
        is_terminal = mnemonic.startswith(("ret", "iret", "ud2", "hlt")) or not successors[index]
        if is_terminal:
            if next_stage in (1, 2) and incomplete_exit is None:
                incomplete_exit = (
                    next_stage,
                    f"instruction {index}: {raw_line.strip()}",
                )
            if next_stage == 3:
                saw_completed_switch = True
        for successor in successors[index]:
            pending.append((successor, next_tags, next_stage))

    if not saw_clear_instruction:
        return False, "no instruction clearing CR4.PGE bit 7 was found"
    if not saw_clear_write:
        return False, "PGE-cleared value did not reach a CR4 write"
    if not saw_cr3_write:
        return False, "no actual CR3 write instruction found in activation routine"
    if unsafe_cr3_path is not None:
        return False, unsafe_cr3_path
    if incomplete_exit is not None:
        stage, location = incomplete_exit
        if stage == 2:
            return False, (
                "original pre-switch CR4 value was not restored on every CR3-switch exit "
                f"({location})"
            )
        return False, f"CR4.PGE disable path exited before completing CR3 switch ({location})"
    if not saw_restore_write or not saw_completed_switch:
        return False, "original pre-switch CR4 value was not restored on every CR3-switch exit"
    return True, "all reachable CR3 writes are bracketed by PGE disable and original CR4 restore"

def _asm_blocks_writing_control_register(
    source: str, register: str
) -> list[str]:
    """Find asm! blocks whose string templates write the named control register.

    Match the instruction independently of its operand placeholder style, so
    both positional ("mov cr3, {}") and named ("mov cr3, {root}") operands are
    checked. Rust's asm! templates are string literals; the macro body is
    captured separately so options and operands can be validated as a whole.
    """
    macro_pattern = re.compile(r"\basm!\s*\((?P<body>.*?)\);", re.DOTALL)
    string_pattern = re.compile(r'"((?:\\.|[^"\\])*)"')
    instruction_pattern = re.compile(
        rf"\bmov(?:q)?\s+{re.escape(register)}\s*,", re.IGNORECASE
    )
    blocks: list[str] = []
    for match in macro_pattern.finditer(source):
        body = match.group("body")
        templates = string_pattern.findall(body)
        if any(instruction_pattern.search(template) for template in templates):
            blocks.append(body)
    return blocks


def _split_top_level_commas(source: str) -> list[str]:
    """Split a Rust macro argument list without splitting nested expressions."""
    parts: list[str] = []
    start = 0
    depth = 0
    for index, character in enumerate(source):
        if character in "([{":
            depth += 1
        elif character in ")]}":
            depth -= 1
        elif character == "," and depth == 0:
            parts.append(source[start:index].strip())
            start = index + 1
    parts.append(source[start:].strip())
    return parts


def _asm_operand_bindings(
    block: str,
) -> tuple[list[tuple[str, str | None, str | None]], dict[str, tuple[str, str | None, str | None]]] | None:
    """Map Rust asm! operand names and positions to their declared input values.

    Each operand tuple is (kind, register class, expression). Unsupported operand
    declarations are rejected conservatively so they cannot shift positional
    placeholders past an operand the checker did not understand.
    """
    string_pattern = re.compile(r'"((?:\\.|[^"\\])*)"')
    body = string_pattern.sub(" ", block)
    body = re.sub(r"//[^\n]*", "", body)
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.DOTALL)
    positional: list[tuple[str, str | None, str | None]] = []
    named: dict[str, tuple[str, str | None, str | None]] = {}

    operand_pattern = re.compile(
        r"(?:(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*)?"
        r"(?P<kind>inlateout|lateout|inout|in|out|const|sym)\b(?P<tail>.*)",
        re.DOTALL,
    )
    register_operand_pattern = re.compile(
        r"\s*\(\s*(?P<register_class>[^()]+?)\s*\)\s*"
        r"(?P<expression>.+?)\s*",
        re.DOTALL,
    )

    for argument in _split_top_level_commas(body):
        if not argument or re.match(r"^(?:options|clobber_abi)\s*\(", argument):
            continue
        match = operand_pattern.fullmatch(argument)
        if match is None:
            return None

        kind = match.group("kind")
        tail = match.group("tail")
        register_class: str | None = None
        expression: str | None = None
        if kind in {"in", "out", "inout", "lateout", "inlateout"}:
            register_match = register_operand_pattern.fullmatch(tail)
            if register_match is not None:
                register_class = register_match.group("register_class").strip()
                expression = register_match.group("expression").strip()
        else:
            expression = tail.strip() or None

        operand = (kind, register_class, expression)
        name = match.group("name")
        if name is None:
            positional.append(operand)
        elif name in named:
            return None
        else:
            named[name] = operand

    return positional, named


def _template_placeholders(
    template: str, first_positional_index: int
) -> tuple[list[tuple[int, int, str, int | None]], int]:
    """Return placeholder spans, keys and positional indexes in template order.

    Anonymous placeholders consume positional operands in order of appearance.
    Named placeholders resolve by name and do not consume a positional index.
    Explicit numeric placeholders refer directly to their indexed operand.
    Escaped braces are ignored.
    """
    placeholders: list[tuple[int, int, str, int | None]] = []
    next_positional_index = first_positional_index
    index = 0

    while index < len(template):
        if template.startswith(("{{", "}}"), index):
            index += 2
            continue
        if template[index] != "{":
            index += 1
            continue

        closing = template.find("}", index + 1)
        if closing < 0:
            index += 1
            continue

        key = template[index + 1 : closing].split(":", 1)[0]
        if key == "":
            placeholders.append((index, closing + 1, key, next_positional_index))
            next_positional_index += 1
        elif re.fullmatch(r"\d+|[A-Za-z_][A-Za-z0-9_]*", key):
            placeholders.append((index, closing + 1, key, None))
        index = closing + 1

    return placeholders, next_positional_index


def _cr3_template_sources(
    block: str,
) -> list[tuple[str, str | None, int | None]]:
    """Return each CR3 source token and its exact template-placeholder binding."""
    string_pattern = re.compile(r'"((?:\\.|[^"\\])*)"')
    sources: list[tuple[str, str | None, int | None]] = []
    next_positional_index = 0

    for template in string_pattern.findall(block):
        placeholders, next_positional_index = _template_placeholders(
            template, next_positional_index
        )
        line_offset = 0
        for line in template.splitlines(keepends=True):
            match = re.search(
                r"\bmov(?:q)?\s+cr3\s*,\s*([^\s,;]+)",
                line,
                re.IGNORECASE,
            )
            if match is not None:
                token_start = line_offset + match.start(1)
                token_end = line_offset + match.end(1)
                placeholder = next(
                    (
                        item
                        for item in placeholders
                        if item[0] == token_start and item[1] == token_end
                    ),
                    None,
                )
                if placeholder is None:
                    sources.append((match.group(1), None, None))
                else:
                    _, _, key, positional_index = placeholder
                    sources.append((match.group(1), key, positional_index))
            line_offset += len(line)

    return sources


def _cr3_source_is_validated_root(
    block: str,
    placeholder_key: str | None,
    positional_index: int | None,
) -> bool:
    """Require the CR3 placeholder to bind directly to in(reg) root_physical."""
    if placeholder_key is None:
        return False

    parsed = _asm_operand_bindings(block)
    if parsed is None:
        return False
    positional, named = parsed

    if placeholder_key == "":
        if positional_index is None:
            return False
        operand = (
            positional[positional_index]
            if positional_index < len(positional)
            else None
        )
    elif placeholder_key.isdigit():
        position = int(placeholder_key)
        operand = positional[position] if position < len(positional) else None
    else:
        operand = named.get(placeholder_key)

    return operand == ("in", "reg", "root_physical")


def validate_cr3_asm_memory_order(source: str) -> tuple[bool, str]:
    """Ensure CR3 asm preserves memory order and writes the validated root input."""
    blocks = _asm_blocks_writing_control_register(source, "cr3")
    if not blocks:
        return False, "could not locate any asm! block writing CR3 in address_space.rs"

    for index, block in enumerate(blocks, start=1):
        if re.search(r"\bnomem\b", block):
            return False, f"CR3 inline asm block {index} must not specify nomem"

        sources = _cr3_template_sources(block)
        if not sources:
            return False, f"CR3 inline asm block {index} has no parseable CR3 source operand"
        for source_token, placeholder_key, positional_index in sources:
            if not _cr3_source_is_validated_root(
                block, placeholder_key, positional_index
            ):
                return False, (
                    f"CR3 inline asm block {index} writes CR3 from {source_token!r}; "
                    "the template operand must bind directly to in(reg) root_physical"
                )
    return True, f"all {len(blocks)} CR3 asm blocks preserve compiler ordering and use the validated root"


def validate_cr4_asm_pge_order(source: str) -> tuple[bool, str]:
    """Ensure every source-level CR3 switch clears PGE and restores original CR4."""
    blocks = _asm_blocks_writing_control_register(source, "cr4")
    if len(blocks) < 2 or len(blocks) % 2 != 0:
        return False, "expected paired CR4 asm blocks for every PGE-clear/restore sequence"
    if not re.search(r"cr4_without_pge\s*=\s*cr4\s*&\s*!CR4_PGE\b", source):
        return False, "cr4_without_pge must be derived from cr4 with CR4_PGE cleared"

    for pair_index in range(0, len(blocks), 2):
        disable_block = blocks[pair_index]
        restore_block = blocks[pair_index + 1]
        switch_number = pair_index // 2 + 1
        if not re.search(r"\bin\(\s*reg\s*\)\s+cr4_without_pge\b", disable_block):
            return False, (
                f"CR3 switch sequence {switch_number} must first write the "
                "PGE-cleared cr4_without_pge value"
            )
        if not re.search(r"\bin\(\s*reg\s*\)\s+cr4\b", restore_block):
            return False, (
                f"CR3 switch sequence {switch_number} must restore the original cr4 value"
            )
    return True, f"all {len(blocks) // 2} source CR3 switch sequences clear PGE and restore original CR4"


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
            f"could not find optimized CR3-switch functions {FUNCTION_NAMES!r} "
            f"in any .s file under {assembly_dir}"
        ]

    found_functions = {
        function_name
        for _path, symbol, _body in matches
        for function_name in FUNCTION_NAMES
        if function_name in symbol
    }
    missing_functions = sorted(set(FUNCTION_NAMES) - found_functions)
    if missing_functions:
        errors.append(
            "optimized assembly did not contain required CR3-switch functions: "
            + ", ".join(missing_functions)
        )

    for path, symbol, body in matches:
        valid, message = validate_function_body(body)
        if not valid:
            errors.append(f"{path}: {symbol}: {message}\n--- CR3-switch function body ---\n" + "\n".join(body) + "\n--- end CR3-switch function body ---")
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
