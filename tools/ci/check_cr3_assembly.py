#!/usr/bin/env python3
"""Check optimized x86_64 assembly for the kernel CR3/PGE switch sequence."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from rust_lexer import (
    mask_rust_comments_and_literals,
    rust_macro_invocations,
    rust_string_literals,
)

FUNCTION_NAMES = ("activate_supervisor_kernel_root", "switch_address_space")
FUNCTION_NAME = "activate_supervisor_kernel_root"
TYPE_RE = re.compile(r"^\s*\.type\s+([^,\s]+)\s*,\s*@function\b")
FUNCTION_END_RE = re.compile(r"^\s*\.Lfunc_end\d+\s*:")
SIZE_RE_TEMPLATE = r"^\s*\.size\s+{}\s*,"
INSTRUCTION_RE = re.compile(r"^\s*([a-zA-Z][a-zA-Z0-9.]*)(?:\s+(.+?))?\s*$")
LOOP_BRANCHES = {"loop", "loope", "loopz", "loopne", "loopnz"}
GPR_RE = re.compile(
    r"^(?:r(?:ax|bx|cx|dx|si|di|bp|sp)|r\d+[dwb]?|"
    r"e(?:ax|bx|cx|dx|si|di|bp|sp)|(?:si|di|bp|sp)|[abcd][lhx]|[sd]il|bpl|spl)$",
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


def _is_64_bit_gpr(operand: str) -> bool:
    """Return whether an operand is a full-width x86-64 general-purpose register."""
    name = _register_name(operand)
    return name in {
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
        *(f"r{i}" for i in range(8, 16)),
    }


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

    # Build the CFG for every supported direct branch. LOOP/LOOPE/LOOPNE
    # have a taken edge and a fallthrough edge just like conditional jumps;
    # treating them as ordinary instructions would hide paths that bypass
    # the PGE-clear write. Unknown/out-of-function branch targets fail closed.
    successors: list[list[int]] = [[] for _ in instructions]
    for index, (_, mnemonic, operands) in enumerate(instructions):
        fallthrough = index + 1 if index + 1 < len(instructions) else None
        is_loop_branch = mnemonic in LOOP_BRANCHES
        is_conditional_jump = mnemonic.startswith("j") and not mnemonic.startswith("jmp")
        is_unconditional_jump = mnemonic.startswith("jmp")
        target = (
            labels.get(operands[-1].strip())
            if (is_loop_branch or is_conditional_jump or is_unconditional_jump) and operands
            else None
        )
        if is_unconditional_jump:
            if target is None:
                return False, f"unresolved or non-local jump target at instruction {index}: {instructions[index][0].strip()}"
            successors[index].append(target)
        elif is_loop_branch or is_conditional_jump:
            if target is None:
                return False, f"unresolved or non-local conditional branch target at instruction {index}: {instructions[index][0].strip()}"
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

        if mnemonic in LOOP_BRANCHES:
            # LOOP-family instructions implicitly decrement RCX.
            state[reg_index["rcx"]] = NONE
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

        if mnemonic.startswith("xchg") and len(operands) == 2:
            # Only a full-width exchange preserves the tracked 64-bit values.
            # Partial-width XCHG changes the register contents; xchgl also
            # zero-extends both destinations, so invalidate provenance instead.
            left = _operand_register(operands[0])
            right = _operand_register(operands[1])
            left_slot = reg_index.get(left) if left is not None else None
            right_slot = reg_index.get(right) if right is not None else None
            full_width_gpr_exchange = (
                mnemonic in ("xchg", "xchgq")
                and _is_64_bit_gpr(operands[0])
                and _is_64_bit_gpr(operands[1])
            )
            if (
                full_width_gpr_exchange
                and left_slot is not None
                and right_slot is not None
            ):
                state[left_slot], state[right_slot] = state[right_slot], state[left_slot]
            else:
                for slot in (left_slot, right_slot):
                    if slot is not None:
                        state[slot] = NONE
            return tuple(state), stage

        clobbered = _clobbered_gpr(raw_line)
        if clobbered in reg_index:
            state[reg_index[clobbered]] = NONE
        if mnemonic.startswith("set") and operands:
            destination = _destination(operands)
            register = _operand_register(destination) if destination else None
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
    unsafe_call_path: str | None = None
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

        # A call is an interprocedural CR4 side-effect boundary. Do not permit
        # it while an original CR4 snapshot is live or while the PGE/CR3
        # transition is incomplete; callees are not part of this local CFG.
        if mnemonic.startswith("call") and (
            stage in (1, 2, 4)
            or (stage == 0 and (ORIGINAL in tags or CLEARED in tags))
        ) and unsafe_call_path is None:
            unsafe_call_path = (
                "call is not permitted while CR4 provenance or the "
                f"PGE/CR3 transition is active (stage={stage}, instruction {index}: "
                f"{raw_line.strip()})"
            )

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
    if unsafe_call_path is not None:
        return False, unsafe_call_path
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
    """Find asm! blocks writing a control register using comment-aware tokens.

    Match the instruction independently of its operand placeholder style, so
    both positional ("mov cr3, {}") and named ("mov cr3, {root}") operands are
    checked. Rust's asm! templates are string literals; the macro body is
    captured separately so options and operands can be validated as a whole.
    """
    instruction_pattern = re.compile(
        rf"\bmov(?:q)?\s+{re.escape(register)}\s*,", re.IGNORECASE
    )
    blocks: list[str] = []
    for invocation in rust_macro_invocations(source, {"asm"}):
        if invocation.closing is None:
            continue
        body = source[invocation.opening + 1 : invocation.closing]
        templates = [literal.value for literal in rust_string_literals(body)]
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
    body = mask_rust_comments_and_literals(block)
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
    sources: list[tuple[str, str | None, int | None]] = []
    next_positional_index = 0

    for literal in rust_string_literals(block):
        template = literal.value
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


def _cr3_source_is_validated_active_reload(
    source: str,
    block: str,
    placeholder_key: str | None,
    positional_index: int | None,
) -> bool:
    """Allow only a checked reload of the exact active CR3 in the local-TLB flush.

    Root-switch writes must still bind directly to root_physical. The only
    exception is the break-before-make flush, which must read CR3, compare its
    physical root against expected_root_physical, and reload that same raw value
    (including any architecturally meaningful low CR3 bits).
    """
    marker = "pub(super) fn switch_address_space_flush_local_tlb("
    start = source.find(marker)
    if start < 0:
        return False
    end_match = re.search(
        r"\n\s*/// Performs the validated hardware CR3 transition\.",
        source[start:],
    )
    if end_match is None:
        return False
    end = start + end_match.start()
    helper = source[start:end]

    # There must be one and only one CR3 write in this helper, and the candidate
    # asm block must physically occur within its source span. This prevents the
    # exception from weakening validation of an unrelated root switch.
    helper_writes = _asm_blocks_writing_control_register(helper, "cr3")
    write_offset = helper.find(block)
    if len(helper_writes) != 1 or write_offset < 0 or source.find(block, start, end) < 0:
        return False

    # The active-root comparison must guard the CR3 write, not merely appear
    # somewhere in the function after the hardware state has already changed.
    pre_write = _rust_code_without_literals_or_comments(helper[:write_offset])
    function_body_open = pre_write.find("{")
    if function_body_open < 0:
        return False
    pre_write_body = pre_write[function_body_open + 1 :]
    if not _if_guard_unconditionally_returns(
        pre_write_body,
        r"cr3\s*&\s*PHYSICAL_ADDRESS_MASK\s*!=\s*expected_root_physical",
    ):
        return False

    if not re.search(r"let\s+cr3\s*:\s*u64\s*;", helper):
        return False
    if not re.search(
        r'asm!\s*\(\s*"mov\s*\{\}\s*,\s*cr3"\s*,\s*out\s*\(\s*reg\s*\)\s*cr3',
        helper,
        re.DOTALL,
    ):
        return False
    if not re.search(
        r"validate_kernel_root_activation_state\s*\(\s*cr0\s*,\s*cr4\s*,\s*efer\s*,\s*rflags\s*\)",
        helper,
    ):
        return False
    if not re.search(
        r"cr3\s*&\s*PHYSICAL_ADDRESS_MASK\s*!=\s*expected_root_physical",
        helper,
    ):
        return False

    parsed = _asm_operand_bindings(block)
    if parsed is None or placeholder_key is None:
        return False
    positional, named = parsed
    if placeholder_key == "":
        if positional_index is None or positional_index >= len(positional):
            return False
        operand = positional[positional_index]
    elif placeholder_key.isdigit():
        position = int(placeholder_key)
        operand = positional[position] if position < len(positional) else None
    else:
        operand = named.get(placeholder_key)
    return operand == ("in", "reg", "cr3")


def _rust_code_without_literals_or_comments(source: str) -> str:
    """Mask Rust comments/literals through the shared comment-aware lexer."""
    return mask_rust_comments_and_literals(source)


def _asm_blocks_writing_control_register_with_locations(
    source: str, register: str
) -> list[tuple[str, int]]:
    """Find asm! blocks writing a control register and retain source offsets."""
    instruction_patterns = (
        re.compile(rf"\bmov(?:q)?\s+{re.escape(register)}\s*,", re.IGNORECASE),
        re.compile(rf"\bmov(?:q)?\s+[^,\n]+,\s*%{re.escape(register)}\b", re.IGNORECASE),
    )
    blocks: list[tuple[str, int]] = []
    for invocation in rust_macro_invocations(source, {"asm"}):
        if invocation.closing is None:
            continue
        body = source[invocation.opening + 1 : invocation.closing]
        templates = [literal.value for literal in rust_string_literals(body)]
        candidates = [*templates, "".join(templates)]
        if any(pattern.search(template) for template in candidates for pattern in instruction_patterns):
            blocks.append((body, invocation.start))
    return blocks


def _normalize_rust_identifier(identifier: str) -> str:
    """Normalize a Rust raw identifier while preserving ordinary identifiers."""
    return identifier[2:] if identifier.startswith("r#") else identifier


def _rust_function_body_spans(source: str) -> list[tuple[str, int, int]]:
    """Return function names and balanced body spans in comment/literal-masked Rust."""
    code = _rust_code_without_literals_or_comments(source)
    pattern = re.compile(r"\bfn\s+(?P<name>(?:r#)?[A-Za-z_][A-Za-z0-9_]*)\b")
    spans: list[tuple[str, int, int]] = []

    for match in pattern.finditer(code):
        cursor = match.end()
        parentheses = brackets = angles = 0
        body_start: int | None = None
        while cursor < len(code):
            character = code[cursor]
            if character == "(":
                parentheses += 1
            elif character == ")":
                parentheses = max(0, parentheses - 1)
            elif character == "[":
                brackets += 1
            elif character == "]":
                brackets = max(0, brackets - 1)
            elif character == "<":
                angles += 1
            elif character == ">" and (cursor == 0 or code[cursor - 1] != "-"):
                angles = max(0, angles - 1)
            elif character == "{" and parentheses == 0 and brackets == 0 and angles == 0:
                body_start = cursor
                break
            elif character == ";" and parentheses == 0 and brackets == 0 and angles == 0:
                break
            cursor += 1

        if body_start is None:
            continue

        depth = 1
        cursor = body_start + 1
        while cursor < len(code) and depth:
            if code[cursor] == "{":
                depth += 1
            elif code[cursor] == "}":
                depth -= 1
            cursor += 1
        if depth:
            continue
        spans.append(
            (_normalize_rust_identifier(match.group("name")), body_start, cursor - 1)
        )

    return spans

def _brace_depth_at(source: str, offset: int) -> int:
    """Return structural Rust brace depth in already-masked source before offset."""
    depth = 0
    for character in source[:offset]:
        if character == "{":
            depth += 1
        elif character == "}":
            depth = max(0, depth - 1)
    return depth

def _result_call_has_error_handling(code: str, call_start: int) -> bool:
    """Require a Result-returning call to propagate or explicitly return its error.

    Supported forms are a direct `?`, an `if let Err(error) = call { ... }`
    with `return Err(error)`, or a local result binding that is checked by an
    `if let Err(error) = binding { ... return Err(...); }` block before CR3.
    """
    opening = code.find("(", call_start)
    if opening < 0:
        return False

    depth = 0
    closing = None
    for index in range(opening, len(code)):
        if code[index] == "(":
            depth += 1
        elif code[index] == ")":
            depth -= 1
            if depth == 0:
                closing = index
                break
    if closing is None:
        return False

    suffix = code[closing + 1:]
    if re.match(r"\s*(?:\.\s*map_err\s*\([^;]*\))?\s*\?\s*;", suffix):
        return True

    # Explicit handling where the Result is inspected directly in the condition.
    error_binding = re.search(
        r"\bif\s+let\s+Err\s*\(\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\)\s*=\s*$",
        code[:call_start],
    )
    if error_binding is not None:
        block_start = closing + 1
        while block_start < len(code) and code[block_start].isspace():
            block_start += 1
        if block_start >= len(code) or code[block_start] != "{":
            return False
        block_end = _balanced_block_end(code, block_start)
        if block_end is None:
            return False
        body = code[block_start + 1:block_end]
        return_match = re.search(
            rf"\breturn\s+Err\s*\(\s*{re.escape(error_binding.group('name'))}\s*\)\s*;",
            body,
        )
        return return_match is not None and _brace_depth_at(body, return_match.start()) == 0

    # Explicit handling where the Result is first bound to a local variable.
    result_binding = re.search(
        r"\blet\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*$",
        code[:call_start],
    )
    if result_binding is None:
        return False
    semicolon = re.match(r"\s*;", suffix)
    if semicolon is None:
        return False
    remainder = suffix[semicolon.end():]
    error_check = re.search(
        rf"\bif\s+let\s+Err\s*\(\s*(?P<error>[A-Za-z_][A-Za-z0-9_]*)\s*\)\s*=\s*"
        rf"{re.escape(result_binding.group('name'))}\s*\{{",
        remainder,
    )
    if error_check is None:
        return False
    block_start = error_check.end() - 1
    block_end = _balanced_block_end(remainder, block_start)
    if block_end is None:
        return False
    body = remainder[block_start + 1:block_end]
    return_match = re.search(r"\breturn\s+Err\s*\(", body)
    return return_match is not None and _brace_depth_at(body, return_match.start()) == 0

def _balanced_block_end(code: str, opening: int) -> int | None:
    """Return the closing brace offset for a block in comment/literal-masked Rust."""
    if opening >= len(code) or code[opening] != "{":
        return None
    depth = 0
    for index in range(opening, len(code)):
        if code[index] == "{":
            depth += 1
        elif code[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return None

def _rust_if_condition_blocks(source: str) -> list[tuple[str, str]]:
    """Return condition/body pairs for Rust if blocks in masked Rust source."""
    blocks: list[tuple[str, str]] = []
    for match in re.finditer(r"\bif\b", source):
        condition_start = match.end()
        parentheses = brackets = 0
        body_start: int | None = None
        for cursor in range(condition_start, len(source)):
            character = source[cursor]
            if character == "(":
                parentheses += 1
            elif character == ")":
                parentheses = max(0, parentheses - 1)
            elif character == "[":
                brackets += 1
            elif character == "]":
                brackets = max(0, brackets - 1)
            elif character == "{" and parentheses == 0 and brackets == 0:
                body_start = cursor
                break
            elif character == ";" and parentheses == 0 and brackets == 0:
                break

        if body_start is None:
            continue
        body_end = _balanced_block_end(source, body_start)
        if body_end is None:
            continue
        blocks.append(
            (
                source[condition_start:body_start],
                source[body_start + 1:body_end],
            )
        )
    return blocks


def _if_guard_unconditionally_returns_err(
    source: str, condition_pattern: str
) -> bool:
    """Require a matching if condition to reject through a top-level return Err."""
    matching_bodies = [
        body
        for condition, body in _rust_if_condition_blocks(source)
        if re.search(condition_pattern, condition)
    ]
    if len(matching_bodies) != 1:
        return False

    body = matching_bodies[0]
    return_match = re.match(r"\s*return\s+Err\s*\(", body)
    if return_match is None:
        return False

    opening = body.find("(", return_match.start(), return_match.end())
    depth = 0
    closing: int | None = None
    for index in range(opening, len(body)):
        if body[index] == "(":
            depth += 1
        elif body[index] == ")":
            depth -= 1
            if depth == 0:
                closing = index
                break
    if closing is None:
        return False
    return body[closing + 1:].lstrip().startswith(";")



def _if_guard_unconditionally_returns(
    source: str, condition_pattern: str
) -> bool:
    """Require a unique top-level if guard that immediately returns."""
    matching_bodies: list[str] = []
    for match in re.finditer(r"\bif\b", source):
        # A nested guard can be skipped entirely on another path. The checked
        # active-root predicate must therefore be a direct function-level guard.
        if _brace_depth_at(source, match.start()) != 0:
            continue
        cursor = match.end()
        parentheses = brackets = 0
        body_start: int | None = None
        while cursor < len(source):
            character = source[cursor]
            if character == "(":
                parentheses += 1
            elif character == ")":
                parentheses = max(0, parentheses - 1)
            elif character == "[":
                brackets += 1
            elif character == "]":
                brackets = max(0, brackets - 1)
            elif character == "{" and parentheses == 0 and brackets == 0:
                body_start = cursor
                break
            elif character == ";" and parentheses == 0 and brackets == 0:
                break
            cursor += 1
        if body_start is None:
            continue
        condition = source[match.end():body_start]
        if not re.search(condition_pattern, condition):
            continue
        body_end = _balanced_block_end(source, body_start)
        if body_end is None:
            continue
        matching_bodies.append(source[body_start + 1:body_end])

    if len(matching_bodies) != 1:
        return False
    return re.match(r"\s*return\b", matching_bodies[0]) is not None


def validate_cr3_writer_contract(source: str) -> tuple[bool, str]:
    """Pin the three CR3 writes to their reviewed functions and root provenance."""
    expected_roles = {
        "switch_address_space_flush_local_tlb": "checked active-root reload",
        "switch_address_space": "validated target-root switch",
        "activate_supervisor_kernel_root": "initialized registered-root activation",
    }
    code = _rust_code_without_literals_or_comments(source)
    spans = _rust_function_body_spans(source)
    spans_by_name: dict[str, list[tuple[int, int]]] = {}
    for name, body_start, body_end in spans:
        if name in expected_roles:
            spans_by_name.setdefault(name, []).append((body_start, body_end))

    errors: list[str] = []
    signature_contracts = (
        (
            r"\bfn\s+switch_address_space_flush_local_tlb\s*\(\s*"
            r"expected_root_physical\s*:\s*u64\s*,?\s*\)",
            "switch_address_space_flush_local_tlb must accept only the expected "
            "physical root value for its checked active-root reload",
        ),
        (
            r"\bfn\s+switch_address_space\s*\(\s*current\s*:\s*"
            r"ActiveAddressSpaceRoot\s*,\s*next\s*:\s*AddressSpaceRoot\s*,",
            "switch_address_space must receive active and owned address-space root handles",
        ),
        (
            r"\bfn\s+activate_supervisor_kernel_root\s*\(\s*"
            r"boot_info\s*:\s*&\s*BootInfo\s*,?\s*\)",
            "activate_supervisor_kernel_root must retain the reviewed BootInfo-only entry point",
        ),
    )
    for pattern, diagnostic in signature_contracts:
        if re.search(pattern, code) is None:
            errors.append(diagnostic)

    for name in expected_roles:
        if len(spans_by_name.get(name, [])) != 1:
            errors.append(
                f"expected exactly one reviewed CR3 writer function {name!r}; "
                "refusing an incomplete CR3-writer contract"
            )

    writers = _asm_blocks_writing_control_register_with_locations(source, "cr3")
    if len(writers) != len(expected_roles):
        errors.append(
            f"expected exactly {len(expected_roles)} CR3-writing asm blocks, found "
            f"{len(writers)}; refusing an incomplete CR3-writer contract"
        )

    writes_by_function: dict[str, list[tuple[str, int]]] = {
        name: [] for name in expected_roles
    }
    for block, start in writers:
        owners = [
            (name, body_start, body_end)
            for name, body_start, body_end in spans
            if body_start < start < body_end
        ]
        if not owners:
            line = code.count("\n", 0, start) + 1
            errors.append(
                f"line {line}: CR3 write is outside the reviewed writer functions; "
                "refusing an incomplete CR3-writer contract"
            )
            continue
        # Use the innermost function when source contains a nested function item.
        name, body_start, body_end = min(
            owners, key=lambda owner: owner[2] - owner[1]
        )
        if name not in expected_roles:
            line = code.count("\n", 0, start) + 1
            errors.append(
                f"line {line}: CR3 write belongs to unreviewed function {name!r}; "
                "refusing an incomplete CR3-writer contract"
            )
            continue
        writes_by_function[name].append((block, start))

    for name, role in expected_roles.items():
        function_writes = writes_by_function[name]
        if len(function_writes) != 1:
            errors.append(
                f"reviewed function {name!r} ({role}) must contain exactly one "
                f"CR3 write, found {len(function_writes)}"
            )
            continue

        block, write_start = function_writes[0]
        body_start, body_end = spans_by_name[name][0]
        function_code = code[body_start + 1 : body_end]
        write_offset = write_start - body_start - 1
        prefix = function_code[:write_offset]
        if _brace_depth_at(function_code, write_offset) != 1:
            errors.append(
                f"reviewed function {name!r} CR3 write is not in its direct unsafe block"
            )

        sources = _cr3_template_sources(block)
        if not sources:
            errors.append(
                f"reviewed function {name!r} has an unparseable CR3 source operand"
            )
            continue

        if name == "switch_address_space_flush_local_tlb":
            if re.search(r"\blet\s+(?:mut\s+)?expected_root_physical\b", function_code):
                errors.append(
                    "switch_address_space_flush_local_tlb must not shadow its "
                    "expected_root_physical parameter"
                )
            cr3_declarations = list(
                re.finditer(r"\blet\b[^;]*\bcr3\b[^;]*;", function_code)
            )
            if len(cr3_declarations) != 1 or re.fullmatch(
                r"\s*let\s+cr3\s*:\s*u64\s*;",
                cr3_declarations[0].group(0) if cr3_declarations else "",
            ) is None:
                errors.append(
                    "switch_address_space_flush_local_tlb must reload the CR3 value "
                    "read from the hardware, without shadowing it"
                )
            for _source_token, placeholder_key, positional_index in sources:
                if not _cr3_source_is_validated_active_reload(
                    source, block, placeholder_key, positional_index
                ):
                    errors.append(
                        "switch_address_space_flush_local_tlb must reload the "
                        "currently active CR3 only after validating it against "
                        "expected_root_physical"
                    )
                    break

            state_validation_pattern = r"validate_kernel_root_activation_state\s*\("
            state_validation_matches = list(
                re.finditer(state_validation_pattern, prefix)
            )
            if len(state_validation_matches) != 1:
                errors.append(
                    "switch_address_space_flush_local_tlb must validate kernel "
                    "root activation state exactly once before its CR3 write"
                )
            elif _brace_depth_at(prefix, state_validation_matches[0].start()) != 0:
                errors.append(
                    "switch_address_space_flush_local_tlb must perform kernel "
                    "root activation state validation directly before its CR3 write"
                )
            elif not _result_call_has_error_handling(
                prefix, state_validation_matches[0].start()
            ):
                errors.append(
                    "switch_address_space_flush_local_tlb must propagate or "
                    "explicitly handle errors from validate_kernel_root_activation_state "
                    "before its CR3 write"
                )
            continue

        for source_token, placeholder_key, positional_index in sources:
            if not _cr3_source_is_validated_root(
                block, placeholder_key, positional_index
            ):
                errors.append(
                    f"reviewed function {name!r} writes CR3 from {source_token!r}; "
                    "its operand must bind directly to the reviewed root_physical"
                )
                break

        let_binding_pattern = re.compile(
            r"\blet\s+(?P<binding>[^=;]+?)\s*="
        )
        declarations = [
            match
            for match in let_binding_pattern.finditer(function_code)
            if re.search(r"\broot_physical\b", match.group("binding"))
        ]
        if len(declarations) != 1:
            errors.append(
                f"reviewed function {name!r} must have exactly one root_physical "
                "binding with no shadowed or reassigned source"
            )
            continue

        if name == "switch_address_space":
            binding_pattern = re.compile(
                r"\blet\s+root_physical\s*=\s*next\s*\.\s*"
                r"physical_address\s*\(\s*\)\s*;"
            )
            if re.search(r"\blet\s+(?:mut\s+)?next\b", function_code):
                errors.append(
                    "switch_address_space must use its validated next-root handle "
                    "without shadowing the next parameter"
                )
            current_binding = re.compile(
                r"\blet\s+current_physical\s*=\s*current\s*\.\s*"
                r"physical_address\s*\(\s*\)\s*;"
            )
            current_bindings = [
                match
                for match in let_binding_pattern.finditer(function_code)
                if re.search(r"\bcurrent_physical\b", match.group("binding"))
            ]
            if len(current_bindings) != 1 or current_binding.search(prefix) is None:
                errors.append(
                    "switch_address_space must derive current_physical exactly once "
                    "from the current root handle"
                )
            required_guard_rejections = (
                (
                    "target-root initialization",
                    r"!\s*next\s*\.\s*is_initialized\s*\(\s*\)",
                ),
                (
                    "target root differs from current root",
                    r"root_physical\s*==\s*current_physical",
                ),
                (
                    "target physical-address width",
                    r"next\s*\.\s*physical_address_bits\s*\(\s*\)\s*!=\s*physical_address_bits",
                ),
                (
                    "hardware active root matches the current handle",
                    r"active_root_table_physical\s*\(\s*\)\s*!=\s*current_physical",
                ),
            )
            for guard_name, guard_pattern in required_guard_rejections:
                if not _if_guard_unconditionally_returns_err(function_code, guard_pattern):
                    errors.append(
                        f"switch_address_space guard for {guard_name} must have "
                        "an unconditional return Err(...) rejection"
                    )

            ordered_contract = (
                r"validate_runtime_root_context\s*\(\s*boot_info\s*,\s*&\s*current\s*\)",
                current_binding.pattern,
                binding_pattern.pattern,
                r"validate_registered_root_for_activation\s*\(\s*root_physical\s*\)",
                r"!\s*next\s*\.\s*is_initialized\s*\(\s*\)",
                r"root_physical\s*==\s*current_physical",
                r"next\s*\.\s*physical_address_bits\s*\(\s*\)\s*!=\s*physical_address_bits",
                r"active_root_table_physical\s*\(\s*\)\s*!=\s*current_physical",
                r"verify_initialized_entries\s*\(\s*&\s*mut\s+editor\s*,\s*"
                r"root_physical\s*,\s*current_physical\s*,",
            )
            result_contracts = (
                (
                    r"validate_runtime_root_context\s*\(\s*boot_info\s*,\s*&\s*current\s*\)",
                    "validate_runtime_root_context",
                ),
                (
                    r"validate_registered_root_for_activation\s*\(\s*root_physical\s*\)",
                    "validate_registered_root_for_activation",
                ),
                (
                    r"verify_initialized_entries\s*\(\s*&\s*mut\s+editor\s*,\s*"
                    r"root_physical\s*,\s*current_physical\s*,",
                    "verify_initialized_entries",
                ),
            )
        else:
            binding_pattern = re.compile(
                r"\blet\s+root_physical\s*=\s*root\s*\.\s*"
                r"physical_address\s*\(\s*\)\s*;"
            )
            root_handle_bindings = [
                match
                for match in let_binding_pattern.finditer(function_code)
                if re.fullmatch(r"(?:mut\s+)?root", match.group("binding").strip())
            ]
            if (
                len(root_handle_bindings) != 1
                or root_handle_bindings[0].group("binding").strip() != "mut root"
            ):
                errors.append(
                    "activate_supervisor_kernel_root must use one owned mutable "
                    "AddressSpaceRoot handle without shadowing it"
                )
            ordered_contract = (
                r"let\s+frame\s*=\s*super\s*::\s*memory\s*::\s*allocate_frame\s*\(\s*\)",
                r"let\s+mut\s+root\s*=\s*match\s+AddressSpaceRoot\s*::\s*"
                r"try_from_frame\s*\(\s*frame\s*,\s*physical_address_bits\s*\)",
                binding_pattern.pattern,
                r"register_address_space_root\s*\(\s*root_physical\s*\)",
                r"root\s*\.\s*initialize_from_kernel_root\s*\(",
                r"verify_initialized_entries\s*\(\s*&\s*mut\s+editor\s*,\s*"
                r"root_physical\s*,\s*kernel_root_physical\s*,",
                r"validate_registered_root_for_activation\s*\(\s*root_physical\s*\)",
            )
            result_contracts = (
                (
                    r"root\s*\.\s*initialize_from_kernel_root\s*\(",
                    "AddressSpaceRoot::initialize_from_kernel_root",
                ),
                (
                    r"verify_initialized_entries\s*\(\s*&\s*mut\s+editor\s*,\s*"
                    r"root_physical\s*,\s*kernel_root_physical\s*,",
                    "verify_initialized_entries",
                ),
                (
                    r"validate_registered_root_for_activation\s*\(\s*root_physical\s*\)",
                    "validate_registered_root_for_activation",
                ),
            )

        for call_pattern, call_name in result_contracts:
            for call_match in re.finditer(call_pattern, prefix):
                if not _result_call_has_error_handling(prefix, call_match.start()):
                    errors.append(
                        f"reviewed function {name!r} must propagate or explicitly "
                        f"handle errors from {call_name} before its CR3 write"
                    )
                    break

        binding = binding_pattern.search(prefix)
        if binding is None:
            errors.append(
                f"reviewed function {name!r} must derive root_physical directly "
                "from its validated root handle before writing CR3"
            )
            continue

        previous_end = -1
        for contract_pattern in ordered_contract:
            match = re.search(contract_pattern, prefix)
            if (
                match is None
                or match.start() < previous_end
                or _brace_depth_at(prefix, match.start()) != 0
            ):
                errors.append(
                    f"reviewed function {name!r} is missing, nested, or has reordered "
                    f"root-validation step {contract_pattern!r} before its CR3 write"
                )
                break
            previous_end = match.end()

    if errors:
        return False, "; ".join(errors)
    return True, (
        "the three CR3 writes are pinned to the reviewed flush, switch, and "
        "initial-activation functions with explicit root-provenance checks"
    )

def validate_cr3_asm_memory_order(source: str) -> tuple[bool, str]:
    """Ensure CR3 asm preserves ordering and writes a validated root value."""
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
            valid_root = _cr3_source_is_validated_root(
                block, placeholder_key, positional_index
            )
            valid_local_reload = _cr3_source_is_validated_active_reload(
                source, block, placeholder_key, positional_index
            )
            if not (valid_root or valid_local_reload):
                return False, (
                    f"CR3 inline asm block {index} writes CR3 from {source_token!r}; "
                    "the template operand must bind directly to in(reg) root_physical, "
                    "or to the checked active CR3 in switch_address_space_flush_local_tlb"
                )
    return True, (
        f"all {len(blocks)} CR3 asm blocks preserve compiler ordering and use "
        "a validated root or checked active-root reload"
    )


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

    valid, message = validate_cr3_writer_contract(source)
    if not valid:
        print(f"FAIL: {args.source}: {message}", file=sys.stderr)
        return 1
    print(f"PASS: {args.source}: {message}")

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
