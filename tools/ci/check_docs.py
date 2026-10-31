#!/usr/bin/env python3
"""Validate local Markdown links, anchors, navigation, and line lengths."""

from __future__ import annotations

import argparse
from bisect import bisect_right
from html import unescape
from html.parser import HTMLParser
import posixpath
import re
import string
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

from github_slugger_data import GITHUB_SLUG_REMOVAL_RE

DEFAULT_MAX_LINE_LENGTH = 88
CHARACTER_REFERENCE_RE = re.compile(
    r"(\\*)(&(?:[A-Za-z][A-Za-z0-9]*|#[0-9]{1,7}|#[xX][0-9A-Fa-f]{1,6});)"
)
BACKTICK = chr(96)
IGNORED_DIRS = {".git", "target", "vendor", "node_modules"}

REQUIRED_LINKS = {
    "README.md": (
        "docs/README.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "docs/project/IMPLEMENTATION_STATUS.md",
        "docs/engineering/DEVELOPMENT.md",
        "docs/engineering/VERIFICATION.md",
        "LICENSE-MIT",
        "LICENSE-APACHE",
    ),
    "docs/README.md": (
        "vision/WORLD_CLASS_OS.md",
        "vision/VISION.md",
        "vision/PRINCIPLES.md",
        "vision/SUCCESS_CRITERIA.md",
        "architecture/OVERVIEW.md",
        "architecture/SECURITY_MODEL.md",
        "architecture/USER_EXPERIENCE.md",
        "architecture/UPDATES_AND_RECOVERY.md",
        "specs/",
        "engineering/DEVELOPMENT.md",
        "engineering/VERIFICATION.md",
        "../CONTRIBUTING.md",
        "../SECURITY.md",
        "project/IMPLEMENTATION_STATUS.md",
        "project/ROADMAP.md",
        "project/decisions/README.md",
    ),
}


class DocProblem:
    def __init__(self, path: str, line: int, message: str) -> None:
        self.path = path
        self.line = line
        self.message = message

    def __str__(self) -> str:
        location = f"{self.path}:{self.line}" if self.line else self.path
        return f"{location}: {self.message}"


def _is_escaped(text: str, index: int) -> bool:
    backslashes = 0
    index -= 1
    while index >= 0 and text[index] == "\\":
        backslashes += 1
        index -= 1
    return backslashes % 2 == 1


def _blockquote_content(line: str, max_depth: int | None = None) -> tuple[str, int]:
    """Remove blockquote prefixes, optionally stopping at a container depth."""
    offset = 0
    depth = 0
    while offset < len(line) and (max_depth is None or depth < max_depth):
        cursor = offset
        spaces = 0
        while cursor < len(line) and line[cursor] == " " and spaces < 4:
            cursor += 1
            spaces += 1
        if spaces > 3 or cursor >= len(line) or line[cursor] != ">":
            break
        depth += 1
        offset = cursor + 1
        if offset < len(line) and line[offset] in " \t":
            offset += 1
    return line[offset:], depth


def _container_content(
    line: str,
    list_stacks: dict[int, list[int]],
    max_quote_depth: int | None = None,
    allow_list_marker: bool = True,
) -> tuple[str, int, tuple[int, ...], bool]:
    """Strip blockquote/list container prefixes from one Markdown line.

    List indentation is tracked independently per blockquote depth. This is
    intentionally a small block-container parser for the syntax the validator
    needs; it does not attempt to render or rewrite Markdown.
    """
    content, quote_depth = _blockquote_content(line.rstrip("\r\n"), max_quote_depth)
    stack = list_stacks.setdefault(quote_depth, [])

    # Blank lines may separate a list item from its fenced block, so they do
    # not terminate the active list context.
    if not content.strip():
        return content, quote_depth, tuple(stack), False

    leading = len(content) - len(content.lstrip(" "))
    while stack and leading < stack[-1]:
        stack.pop()

    consumed = 0
    for content_indent in stack:
        required = content_indent - consumed
        if leading >= content_indent:
            content = content[required:]
            consumed = content_indent
        else:
            break

    opened_list_item = False
    if allow_list_marker:
        marker = re.match(
            r"^( {0,3})([*+-]|[0-9]{1,9}[.)])(?=[ \t]|$)([ \t]+)?",
            content,
        )
        if marker:
            marker_indent = len(marker.group(1))
            marker_width = len(marker.group(2))
            padding = marker.group(3) or ""
            # CommonMark treats five or more following spaces as one
            # separating space; the remainder stays part of the content.
            padding_used = len(padding) if 1 <= len(padding) <= 4 else (1 if padding else 0)
            absolute_marker_indent = consumed + marker_indent
            stack.append(absolute_marker_indent + marker_width + padding_used)
            content = content[marker.end() - len(padding) + padding_used:]
            opened_list_item = True

    return content, quote_depth, tuple(stack), opened_list_item


def _html_block_start(content: str, previous_blank: bool) -> tuple[str, str | None] | None:
    """Return the CommonMark HTML-block kind and its terminator."""
    stripped = content.lstrip(" ")
    if len(content) - len(stripped) > 3:
        return None

    if re.match(r"^<(?:pre|script|style|textarea)(?=[ \t>]|$)", stripped, re.IGNORECASE):
        return "terminator", r"</(?:pre|script|style|textarea)\s*>"
    if stripped.startswith("<!--"):
        return "terminator", "-->"
    if stripped.startswith("<?"):
        return "terminator", "?>"
    if stripped.startswith("<![CDATA["):
        return "terminator", "]]>"
    if re.match(r"^<![A-Z]", stripped):
        return "terminator", ">"

    block_tags = (
        "address|article|aside|base|basefont|blockquote|body|caption|center|col|"
        "colgroup|dd|details|dialog|dir|div|dl|dt|fieldset|figcaption|figure|"
        "footer|form|frame|frameset|h1|h2|h3|h4|h5|h6|head|header|hr|html|"
        "iframe|legend|li|link|main|menu|menuitem|nav|noframes|ol|"
        "optgroup|option|p|param|search|section|summary|table|tbody|td|"
        "tfoot|th|thead|title|tr|track|ul"
    )
    if re.match(rf"^</?(?:{block_tags})(?=[ \t/>])", stripped, re.IGNORECASE):
        return "blank", None

    complete_tag = re.compile(
        r"^</?[A-Za-z][A-Za-z0-9-]*(?:[ \t]+[^<>]*?)?[ \t]*/?>[ \t]*$"
    )
    if previous_blank and complete_tag.fullmatch(stripped):
        return "blank", None
    return None


def _markdown_block_regions(lines: list[str]) -> tuple[set[int], set[int]]:
    """Return fenced-code and raw-HTML block line indexes.

    The recognizer covers the seven CommonMark HTML block classes and tracks
    inline HTML comments so apparent fences inside comments are not Markdown
    code fences. Block parsing takes precedence over inline syntax.
    """
    text = "".join(lines)
    inline_ranges = _inline_code_ranges(text) if "<!--" in text and BACKTICK in text else []
    range_index = 0

    def is_inline_code(position: int) -> bool:
        nonlocal range_index
        while range_index < len(inline_ranges) and inline_ranges[range_index][1] <= position:
            range_index += 1
        return (
            range_index < len(inline_ranges)
            and inline_ranges[range_index][0] <= position < inline_ranges[range_index][1]
        )

    fenced: set[int] = set()
    html_lines: set[int] = set()
    list_stacks: dict[int, list[int]] = {}
    marker: str | None = None
    marker_length = 0
    fence_quote_depth = 0
    fence_list_context: tuple[int, ...] = ()
    html_kind: str | None = None
    html_terminator: str | None = None
    html_quote_depth = 0
    html_list_context: tuple[int, ...] = ()
    comment_open = False
    previous_blank = True
    line_offset = 0

    for index, line in enumerate(lines):
        raw_line = line.rstrip("\r\n")

        if marker is not None:
            container_line, quote_depth, list_context, _ = _container_content(
                line,
                list_stacks,
                max_quote_depth=fence_quote_depth,
                allow_list_marker=False,
            )
            if (
                quote_depth < fence_quote_depth
                or list_context[:len(fence_list_context)] != fence_list_context
            ):
                marker = None
                marker_length = 0
                fence_quote_depth = 0
                fence_list_context = ()
            else:
                fenced.add(index)
                close = re.match(
                    rf" {{0,3}}{re.escape(marker)}{{{marker_length},}}[ \t]*$",
                    container_line,
                )
                if close:
                    marker = None
                    marker_length = 0
                    fence_quote_depth = 0
                    fence_list_context = ()
                previous_blank = False
                line_offset += len(line)
                continue

        if html_kind is not None:
            container_line, quote_depth, list_context, _ = _container_content(
                line,
                list_stacks,
                max_quote_depth=html_quote_depth,
                allow_list_marker=False,
            )
            if (
                quote_depth < html_quote_depth
                or list_context[:len(html_list_context)] != html_list_context
            ):
                html_kind = None
                html_terminator = None
                html_quote_depth = 0
                html_list_context = ()
            else:
                if html_kind == "blank" and not container_line.strip():
                    html_kind = None
                    html_terminator = None
                    html_quote_depth = 0
                    html_list_context = ()
                    previous_blank = True
                    line_offset += len(line)
                    continue

                html_lines.add(index)
                if html_terminator and (
                    re.search(html_terminator, container_line, re.IGNORECASE)
                    if html_terminator.startswith("</")
                    else html_terminator in container_line
                ):
                    html_kind = None
                    html_terminator = None
                    html_quote_depth = 0
                    html_list_context = ()
                previous_blank = False
                line_offset += len(line)
                continue

        container_line, quote_depth, list_context, _ = _container_content(
            line, list_stacks
        )

        if comment_open:
            closing = container_line.find("-->")
            if closing < 0:
                previous_blank = False
                line_offset += len(line)
                continue
            comment_open = False
            # The comment occupied the start of this line. A fence or block
            # cannot begin after its closing delimiter on the same line.
            previous_blank = False
            line_offset += len(line)
            continue

        stripped = container_line.lstrip(" ")
        indent = len(container_line) - len(stripped)
        fence_match = (
            re.match(rf"({re.escape(BACKTICK)}{{3,}}|~{{3,}})(.*)$", stripped)
            if indent <= 3
            else None
        )
        if fence_match:
            candidate = fence_match.group(1)
            info = fence_match.group(2)
            if candidate[0] != BACKTICK or BACKTICK not in info:
                marker = candidate[0]
                marker_length = len(candidate)
                fence_quote_depth = quote_depth
                fence_list_context = list_context
                fenced.add(index)
                previous_blank = False
                line_offset += len(line)
                continue

        html_start = _html_block_start(container_line, previous_blank)
        if html_start is not None:
            kind, terminator = html_start
            html_lines.add(index)
            if kind == "blank":
                html_kind = kind
                html_terminator = None
                html_quote_depth = quote_depth
                html_list_context = list_context
            else:
                end_found = (
                    re.search(terminator, container_line, re.IGNORECASE) is not None
                    if terminator.startswith("</")
                    else terminator in container_line
                )
                if not end_found:
                    html_kind = kind
                    html_terminator = terminator
                    html_quote_depth = quote_depth
                    html_list_context = list_context
            previous_blank = False
            line_offset += len(line)
            continue

        # Track inline comments as well as block comments. Backticks inside an
        # inline code span do not start an HTML comment.
        search_from = 0
        content_offset = raw_line.find(container_line)
        if content_offset < 0:
            content_offset = max(0, len(raw_line) - len(container_line))
        while True:
            opening = container_line.find("<!--", search_from)
            if opening < 0:
                break
            absolute_opening = line_offset + content_offset + opening
            if _is_escaped(raw_line, content_offset + opening) or is_inline_code(absolute_opening):
                search_from = opening + 4
                continue
            closing = container_line.find("-->", opening + 4)
            if closing < 0:
                comment_open = True
                break
            search_from = closing + 3

        previous_blank = not container_line.strip()
        line_offset += len(line)

    return fenced, html_lines


def _fenced_code_lines(lines: list[str]) -> set[int]:
    """Return zero-based fenced-code lines, including list/blockquote containers."""
    return _markdown_block_regions(lines)[0]


def _html_block_lines(lines: list[str]) -> set[int]:
    """Return zero-based lines belonging to CommonMark raw HTML blocks."""
    return _markdown_block_regions(lines)[1]


def _mask_html_blocks_and_comments(text: str) -> str:
    """Mask raw HTML blocks/comments while preserving offsets and newlines."""
    lines = text.splitlines(keepends=True)
    fenced, html_lines = _markdown_block_regions(lines)
    ignored = fenced | html_lines
    ignored |= _indented_code_lines(lines, ignored)
    output = list(text)

    offset = 0
    for index, line in enumerate(lines):
        if index in html_lines:
            for position in range(offset, offset + len(line)):
                if output[position] not in "\r\n":
                    output[position] = " "
        offset += len(line)

    inline_ranges = _document_inline_code_ranges(text, ignored)
    range_index = 0
    in_comment = False
    offset = 0

    for line_number, line in enumerate(lines):
        if line_number in ignored:
            offset += len(line)
            continue

        position = 0
        while position < len(line):
            absolute = offset + position
            while range_index < len(inline_ranges) and inline_ranges[range_index][1] <= absolute:
                range_index += 1
            inside_code = (
                range_index < len(inline_ranges)
                and inline_ranges[range_index][0] <= absolute < inline_ranges[range_index][1]
            )

            if in_comment:
                if line.startswith("-->", position):
                    for index in range(position, position + 3):
                        if output[absolute + index - position] not in "\r\n":
                            output[absolute + index - position] = " "
                    position += 3
                    in_comment = False
                else:
                    if output[absolute] not in "\r\n":
                        output[absolute] = " "
                    position += 1
                continue

            if (
                not inside_code
                and line.startswith("<!--", position)
                and not _is_escaped(line, position)
            ):
                in_comment = True
                for index in range(position, position + 4):
                    if output[offset + index] not in "\r\n":
                        output[offset + index] = " "
                position += 4
                continue

            position += 1

        offset += len(line)

    return "".join(output)

def _inline_code_ranges(text: str) -> list[tuple[int, int]]:
    """Find matched inline-code spans in linear time.

    Delimiter runs are indexed once by length. A matching run closes the
    earliest opener of that length; runs inside a matched span are skipped,
    as required by Markdown code-span parsing.
    """
    runs: list[tuple[int, int, int]] = []
    index = 0
    backslash_count = 0

    while index < len(text):
        char = text[index]
        if char == "\\":
            backslash_count += 1
            index += 1
            continue
        if char != BACKTICK:
            backslash_count = 0
            index += 1
            continue
        if backslash_count % 2:
            # An escaped backtick is not part of a delimiter run. Any
            # following adjacent backticks are considered independently.
            backslash_count = 0
            index += 1
            continue

        start = index
        while index < len(text) and text[index] == BACKTICK:
            index += 1
        runs.append((start, index, index - start))
        backslash_count = 0

    next_same: list[int | None] = [None] * len(runs)
    next_by_length: dict[int, int] = {}
    for run_index in range(len(runs) - 1, -1, -1):
        run_length = runs[run_index][2]
        next_same[run_index] = next_by_length.get(run_length)
        next_by_length[run_length] = run_index

    ranges: list[tuple[int, int]] = []
    run_index = 0
    while run_index < len(runs):
        closing_index = next_same[run_index]
        if closing_index is None:
            run_index += 1
            continue
        ranges.append((runs[run_index][0], runs[closing_index][1]))
        run_index = closing_index + 1

    return ranges

def _leading_indent_columns(line: str) -> int:
    """Return leading indentation columns with CommonMark tab stops."""
    columns = 0
    for char in line:
        if char == " ":
            columns += 1
        elif char == "\t":
            columns += 4 - (columns % 4)
        else:
            break
    return columns


def _indented_code_lines(
    lines: list[str], excluded_lines: set[int] | None = None
) -> set[int]:
    """Identify CommonMark indented code blocks outside other block types."""
    excluded = set(excluded_lines or ())
    list_stacks: dict[int, list[int]] = {}
    code_lines: set[int] = set()
    previous_blank = True
    previous_context: tuple[int, tuple[int, ...]] | None = None
    previous_block_ended = False
    in_code_block = False
    atx_pattern = re.compile(r"^ {0,3}#{1,6}(?:[ \t]+|$)")
    thematic_pattern = re.compile(
        r"^ {0,3}(?:(?:[*][ \t]*){3,}|(?:-[ \t]*){3,}|(?:_[ \t]*){3,})$"
    )

    for index, raw_line in enumerate(lines):
        if index in excluded:
            in_code_block = False
            previous_blank = True
            previous_block_ended = True
            previous_context = None
            continue
        content, quote_depth, list_context, opened = _container_content(
            raw_line, list_stacks
        )
        if not content.strip():
            previous_blank = True
            continue
        context = (quote_depth, list_context)
        indent = _leading_indent_columns(content)
        starts_indented_code = indent >= 4 and (
            previous_blank or previous_context != context
            or previous_block_ended or opened or in_code_block
        )
        if starts_indented_code:
            code_lines.add(index)
            in_code_block = True
            previous_block_ended = False
        else:
            in_code_block = False
            previous_block_ended = bool(
                atx_pattern.match(content)
                or thematic_pattern.fullmatch(content)
                or re.match(r"^ {0,3}(?:=+|-+)[ \t]*$", content)
            )
        previous_blank = False
        previous_context = context
    return code_lines


def _is_lazy_continuation(
    content: str,
    quote_depth: int,
    list_context: tuple[int, ...],
    opened: bool,
    previous_context: tuple[int, tuple[int, ...]] | None,
    previous_paragraph: bool,
) -> bool:
    """Return whether an unmarked line lazily continues the prior paragraph."""
    if (
        previous_context is None
        or not previous_paragraph
        or opened
        or not content.strip()
    ):
        return False

    previous_quote_depth, previous_list_context = previous_context
    omitted_quote = (
        quote_depth < previous_quote_depth
        and previous_list_context[:len(list_context)] == list_context
    )
    omitted_list = (
        quote_depth == previous_quote_depth
        and len(list_context) < len(previous_list_context)
        and previous_list_context[:len(list_context)] == list_context
    )
    if not (omitted_quote or omitted_list):
        return False

    # Lazy continuation is limited to paragraph text. Block starts that can
    # interrupt a paragraph, plus indented code, must retain their own context.
    if _leading_indent_columns(content) >= 4:
        return False
    if re.match(r"^ {0,3}#{1,6}(?:[ \t]|$)", content):
        return False
    if re.fullmatch(r"^ {0,3}(?:=+|-+)[ \t]*$", content):
        return False
    if re.fullmatch(
        r"^ {0,3}(?:(?:[*][ \t]*){3,}|(?:-[ \t]*){3,}|(?:_[ \t]*){3,})$",
        content,
    ):
        return False
    return True


def _is_paragraph_content(content: str) -> bool:
    """Return whether a normalized line can keep a paragraph open."""
    if not content.strip():
        return False
    if re.match(r"^ {0,3}#{1,6}(?:[ \t]|$)", content):
        return False
    if re.fullmatch(r"^ {0,3}(?:=+|-+)[ \t]*$", content):
        return False
    if re.fullmatch(
        r"^ {0,3}(?:(?:[*][ \t]*){3,}|(?:-[ \t]*){3,}|(?:_[ \t]*){3,})$",
        content,
    ):
        return False
    return True


def _effective_container_context(
    content: str,
    quote_depth: int,
    list_context: tuple[int, ...],
    opened: bool,
    previous_context: tuple[int, tuple[int, ...]] | None,
    previous_paragraph: bool,
) -> tuple[int, tuple[int, ...]]:
    """Return the effective container context, including paragraph laziness."""
    if previous_context is not None and _is_lazy_continuation(
        content,
        quote_depth,
        list_context,
        opened,
        previous_context,
        previous_paragraph,
    ):
        return previous_context
    return quote_depth, list_context


def _document_inline_code_ranges(
    text: str, blocked_lines: set[int] | None = None
) -> list[tuple[int, int]]:
    """Find inline-code spans without crossing Markdown block boundaries.

    A supplied blocked-line set is complete and was computed from the original
    Markdown. Do not infer indentation from a later masked representation:
    inline HTML tags replaced with spaces must not turn visible text into an
    apparent indented code block.
    """
    lines = text.splitlines(keepends=True)
    if blocked_lines is None:
        fenced, html_blocks = _markdown_block_regions(lines)
        excluded = fenced | html_blocks
        excluded |= _indented_code_lines(lines, excluded)
    else:
        excluded = set(blocked_lines)

    ranges: list[tuple[int, int]] = []
    offset = 0
    segment_start: int | None = None
    segment_parts: list[str] = []
    previous_context: tuple[int, tuple[int, ...]] | None = None
    previous_paragraph = False
    list_stacks: dict[int, list[int]] = {}
    atx_pattern = re.compile(r"^ {0,3}#{1,6}(?:[ \t]+|$)")
    setext_pattern = re.compile(r"^ {0,3}(?:=+|-+)[ \t]*$")
    thematic_pattern = re.compile(
        r"^ {0,3}(?:(?:[*][ \t]*){3,}|(?:-[ \t]*){3,}|(?:_[ \t]*){3,})$"
    )

    def flush() -> None:
        nonlocal segment_start, segment_parts
        if segment_start is not None:
            segment = "".join(segment_parts)
            ranges.extend(
                (segment_start + start, segment_start + end)
                for start, end in _inline_code_ranges(segment)
            )
        segment_start = None
        segment_parts = []

    for line_index, line in enumerate(lines):
        if line_index in excluded:
            flush()
            previous_context = None
            previous_paragraph = False
            offset += len(line)
            continue
        content, quote_depth, list_context, opened = _container_content(
            line, list_stacks
        )
        if not content.strip():
            flush()
            previous_context = None
            previous_paragraph = False
            offset += len(line)
            continue
        context = _effective_container_context(
            content,
            quote_depth,
            list_context,
            opened,
            previous_context,
            previous_paragraph,
        )
        is_atx = atx_pattern.match(content) is not None
        is_setext = setext_pattern.fullmatch(content) is not None
        is_thematic = thematic_pattern.fullmatch(content) is not None
        if is_atx:
            flush()
            segment_start = offset
            segment_parts = [line]
            flush()
            previous_context = None
            previous_paragraph = False
        elif is_setext or is_thematic:
            flush()
            previous_context = None
            previous_paragraph = False
        else:
            if opened or (
                previous_context is not None and context != previous_context
            ):
                flush()
            if segment_start is None:
                segment_start = offset
            segment_parts.append(line)
            previous_context = context
            previous_paragraph = _is_paragraph_content(content)
        offset += len(line)
    flush()
    return ranges

def _line_inline_code_ranges(text: str, fenced_lines: set[int]) -> dict[int, list[tuple[int, int]]]:
    """Map inline-code intersections to per-line offsets for line-length checks."""
    lines = text.splitlines(keepends=True)
    ranges = _document_inline_code_ranges(text, fenced_lines)
    result: dict[int, list[tuple[int, int]]] = {}
    line_start = 0
    range_index = 0

    for line_number, line in enumerate(lines):
        content_end = line_start + len(line.rstrip("\r\n"))
        current: list[tuple[int, int]] = []
        while range_index < len(ranges) and ranges[range_index][1] <= line_start:
            range_index += 1
        scan = range_index
        while scan < len(ranges) and ranges[scan][0] < content_end:
            start, end = ranges[scan]
            left = max(start, line_start) - line_start
            right = min(end, content_end) - line_start
            if right > left:
                current.append((left, right))
            scan += 1
        if current:
            result[line_number] = current
        line_start += len(line)

    return result


def _split_gfm_table_cells(
    line: str, *, containers_normalized: bool = False
) -> tuple[list[str], int] | None:
    """Split a GFM table row, returning cells and its blockquote depth.

    Callers that parse a sequence of block-container lines can pass normalized
    content so list and blockquote prefixes are removed consistently first.
    """
    if containers_normalized:
        content = line.rstrip("\r\n")
        quote_depth = 0
    else:
        content, quote_depth = _blockquote_content(line.rstrip("\r\n"))
    separators = [
        index for index, char in enumerate(content)
        if char == "|" and not _is_escaped(content, index)
    ]
    if not separators:
        return None

    cells: list[str] = []
    start = 0
    for separator in separators:
        cells.append(content[start:separator].strip())
        start = separator + 1
    cells.append(content[start:].strip())

    # GFM permits both optional leading and trailing pipes.
    if content[:separators[0]].strip() == "":
        cells.pop(0)
    if content[separators[-1] + 1:].strip() == "":
        cells.pop()
    return cells, quote_depth


def _markdown_table_lines(lines: list[str], fenced_lines: set[int]) -> set[int]:
    """Identify GFM table headers, delimiters, and contiguous body rows.

    A table is recognized from the header/delimiter pair, not from a count of
    leading/trailing pipe characters. This includes two-column tables written
    without either optional edge pipe. All rows are normalized through one
    shared container parser so list and nested blockquote indentation remains
    associated with the complete table.
    """
    normalized_lines: list[str] = []
    contexts: list[tuple[int, tuple[int, ...]] | None] = []
    list_stacks: dict[int, list[int]] = {}
    for line_index, line in enumerate(lines):
        if line_index in fenced_lines:
            normalized_lines.append("")
            contexts.append(None)
            continue
        content, quote_depth, list_context, _ = _container_content(
            line, list_stacks
        )
        normalized_lines.append(content)
        contexts.append((quote_depth, list_context))

    table_lines: set[int] = set()
    index = 0
    delimiter_cell = re.compile(r":?-{3,}:?$")

    while index + 1 < len(lines):
        if contexts[index] is None or contexts[index + 1] is None:
            index += 1
            continue
        header = _split_gfm_table_cells(
            normalized_lines[index], containers_normalized=True
        )
        delimiter = _split_gfm_table_cells(
            normalized_lines[index + 1], containers_normalized=True
        )
        if header is None or delimiter is None:
            index += 1
            continue

        header_cells, _ = header
        delimiter_cells, _ = delimiter
        header_context = contexts[index]
        if (
            header_context != contexts[index + 1]
            or not header_cells
            or len(header_cells) != len(delimiter_cells)
            or not all(delimiter_cell.fullmatch(cell) for cell in delimiter_cells)
        ):
            index += 1
            continue

        table_lines.update((index, index + 1))
        row = index + 2
        while row < len(lines) and contexts[row] is not None:
            candidate = _split_gfm_table_cells(
                normalized_lines[row], containers_normalized=True
            )
            if candidate is None or contexts[row] != header_context:
                break
            table_lines.add(row)
            row += 1
        index = row

    return table_lines


def _line_length_is_exempt(
    line: str,
    max_line_length: int = DEFAULT_MAX_LINE_LENGTH,
    code_ranges: list[tuple[int, int]] | None = None,
    is_table_row: bool = False,
) -> bool:
    """Allow atomic inline-code/URL spans only when residual prose fits."""
    if is_table_row:
        return False  # GFM table rows must always obey the line-length limit.

    candidate_code_spans = code_ranges if code_ranges is not None else _inline_code_ranges(line)
    spans: list[tuple[int, int]] = []
    for start, end in candidate_code_spans:
        code_text = line[start:end]
        content_start = 0
        while content_start < len(code_text) and code_text[content_start] == BACKTICK:
            content_start += 1
        content_end = len(code_text)
        while content_end > content_start and code_text[content_end - 1] == BACKTICK:
            content_end -= 1
        # Spaces/tabs in a code span make it breakable under the documented
        # policy; only a single unbroken code token is treated as atomic.
        if not any(char.isspace() for char in code_text[content_start:content_end]):
            spans.append((start, end))
    spans.extend((match.start(), match.end()) for match in re.finditer(r"https?://\S+", line))
    if not spans:
        return False

    merged: list[list[int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])

    reduced_length = len(line) - sum(end - start - 1 for start, end in merged)
    return reduced_length <= max_line_length

def _mask_inline_code(
    text: str, blocked_lines: set[int] | None = None
) -> str:
    """Mask fenced, indented, and inline code while preserving offsets."""
    lines = text.splitlines(keepends=True)
    if blocked_lines is None:
        fenced, html_blocks = _markdown_block_regions(lines)
        blocked = fenced | html_blocks
        blocked |= _indented_code_lines(lines, blocked)
    else:
        # Callers passing blocked_lines have already parsed container/code
        # context from the original source before any offset-preserving masks.
        blocked = set(blocked_lines)
    output = list(text)
    offset = 0
    for line_number, line in enumerate(lines):
        if line_number in blocked:
            for index in range(offset, offset + len(line)):
                if output[index] not in "\r\n":
                    output[index] = " "
        offset += len(line)
    for start, end in _document_inline_code_ranges(text, blocked):
        for index in range(start, end):
            if output[index] not in "\r\n":
                output[index] = " "
    return "".join(output)

def _matching_bracket_pairs(
    text: str, boundary_offsets: set[int] | None = None
) -> dict[int, int]:
    """Pair nested square brackets without crossing supplied block boundaries."""
    stack: list[int] = []
    pairs: dict[int, int] = {}
    boundaries = boundary_offsets or set()
    for index, char in enumerate(text):
        if index in boundaries:
            stack.clear()
        if char not in "[]" or _is_escaped(text, index):
            continue
        if char == "[":
            stack.append(index)
        elif stack:
            pairs[stack.pop()] = index
    return pairs


def _parse_link_title(text: str, start: int) -> tuple[int | None, str | None]:
    """Parse one CommonMark link title beginning at start."""
    if start >= len(text):
        return None, "link title is missing"
    opener = text[start]
    if opener in {"\"", "'"}:
        index = start + 1
        while index < len(text):
            if _is_escaped(text, index):
                index += 1
                continue
            if text[index] == opener:
                return index + 1, None
            index += 1
        return None, "link title is not closed"
    if opener == "(":
        depth = 1
        index = start + 1
        while index < len(text):
            if _is_escaped(text, index):
                index += 1
                continue
            if text[index] == "(":
                depth += 1
            elif text[index] == ")":
                depth -= 1
                if depth == 0:
                    return index + 1, None
            index += 1
        return None, "parenthesized link title is not closed"
    return None, "link title must be quoted or parenthesized"


def _parse_destination_suffix(
    text: str, index: int, closing_delimiter: str | None
) -> tuple[int | None, str | None]:
    """Parse an optional title after a destination and validate its terminator."""
    initial = index
    while index < len(text) and text[index].isspace():
        index += 1
    had_separator = index > initial

    if index >= len(text):
        if closing_delimiter is None:
            return index, None
        return None, "link destination is not closed"

    if closing_delimiter is not None and text[index] == closing_delimiter:
        return index + 1, None
    if not had_separator:
        return index, "unexpected characters after link destination"

    title_end, error = _parse_link_title(text, index)
    if error is not None:
        # Resume at the malformed title so later independent links remain
        # visible to the scanner instead of being discarded with the error.
        return index, error
    assert title_end is not None
    index = title_end
    while index < len(text) and text[index].isspace():
        index += 1

    if closing_delimiter is None:
        if index == len(text):
            return index, None
        return index, "unexpected text after link title"
    if index < len(text) and text[index] == closing_delimiter:
        return index + 1, None
    return index, "unexpected text after link title"


def _parse_inline_destination(
    text: str, open_paren: int
) -> tuple[str | None, int, str | None]:
    """Parse an inline-link destination and optional CommonMark title."""
    index = open_paren + 1
    while index < len(text) and text[index].isspace():
        index += 1
    if index >= len(text):
        return None, len(text), "link destination is not closed"
    if text[index] == ")":
        return "", index + 1, None

    if text[index] == "<":
        start = index + 1
        index = start
        while index < len(text):
            char = text[index]
            if char in "\r\n":
                return None, index, "line break in angle-bracket link destination"
            if char == "<" and not _is_escaped(text, index):
                return None, index, "unescaped '<' in angle-bracket link destination"
            if char == ">" and not _is_escaped(text, index):
                target = text[start:index]
                end, error = _parse_destination_suffix(text, index + 1, ")")
                if error is not None:
                    return None, len(text) if end is None else end, error
                assert end is not None
                return target, end, None
            index += 1
        return None, len(text), "link has an unterminated angle-bracket destination"

    start = index
    depth = 0
    while index < len(text):
        char = text[index]
        if _is_escaped(text, index):
            index += 1
            continue
        if char.isspace():
            if depth:
                return None, index, "whitespace in unbracketed link destination"
            target = text[start:index]
            end, error = _parse_destination_suffix(text, index, ")")
            if error is not None:
                return None, len(text) if end is None else end, error
            assert end is not None
            return target, end, None
        if char == "(":
            depth += 1
        elif char == ")":
            if depth == 0:
                return text[start:index], index + 1, None
            depth -= 1
        index += 1

    return None, len(text), "link destination is not closed"


def _parse_reference_destination(text: str) -> tuple[str | None, str | None]:
    """Parse a reference-definition destination and optional CommonMark title."""
    index = 0
    while index < len(text) and text[index] in " \t":
        index += 1
    if index >= len(text):
        return None, "link reference definition has no destination"

    if text[index] == "<":
        start = index + 1
        index = start
        while index < len(text):
            char = text[index]
            if char in "\r\n":
                return None, "line break in angle-bracket link destination"
            if char == "<" and not _is_escaped(text, index):
                return None, "unescaped '<' in angle-bracket link destination"
            if char == ">" and not _is_escaped(text, index):
                target = text[start:index]
                _, error = _parse_destination_suffix(text, index + 1, None)
                return (target, None) if error is None else (None, error)
            index += 1
        return None, "unterminated angle-bracket reference destination"

    start = index
    depth = 0
    while index < len(text):
        char = text[index]
        if _is_escaped(text, index):
            index += 1
            continue
        if char.isspace():
            if depth:
                return None, "whitespace in unbracketed reference destination"
            target = text[start:index]
            _, error = _parse_destination_suffix(text, index, None)
            return (target, None) if error is None else (None, error)
        if char == "(":
            depth += 1
        elif char == ")":
            if depth == 0:
                return None, "unbalanced ')' in reference destination"
            depth -= 1
        index += 1
    if depth:
        return None, "unbalanced '(' in reference destination"
    return text[start:index], None


def _decode_commonmark_character_references(text: str) -> str:
    """Decode only semicolon-terminated CommonMark character references."""
    def decode_reference(match: re.Match[str]) -> str:
        backslashes, reference = match.groups()
        if len(backslashes) % 2:
            # An odd backslash run escapes the ampersand itself.
            return match.group(0)
        return backslashes + unescape(reference)

    return CHARACTER_REFERENCE_RE.sub(decode_reference, text)


def _unescape_destination(target: str) -> str:
    """Decode CommonMark character references and backslash escapes."""
    target = _decode_commonmark_character_references(target)
    output: list[str] = []
    index = 0
    while index < len(target):
        if (
            target[index] == "\\"
            and index + 1 < len(target)
            and target[index + 1] in string.punctuation
        ):
            output.append(target[index + 1])
            index += 2
        else:
            output.append(target[index])
            index += 1
    return "".join(output)

def _normalize_reference_label(label: str) -> str:
    label = re.sub(r"\\([\x21-\x2f\x3a-\x40\x5b-\x60\x7b-\x7e])", r"\1", label)
    return " ".join(label.casefold().split())



def _mask_inline_html_tags(text: str) -> str:
    """Mask inline HTML tags so Markdown syntax in attributes is not parsed."""
    lines = text.splitlines(keepends=True)
    line_offsets = [0]
    for line in lines:
        line_offsets.append(line_offsets[-1] + len(line))
    output = list(text)

    # Normalize block containers once so reference definitions and their
    # continuation lines are evaluated in the same quote/list context.
    container_lines: list[str] = []
    container_contexts: list[tuple[int, tuple[int, ...], bool]] = []
    list_stacks: dict[int, list[int]] = {}
    for line in lines:
        content, quote_depth, list_context, opened = _container_content(
            line, list_stacks
        )
        container_lines.append(content)
        container_contexts.append((quote_depth, list_context, opened))

    # Angle-bracket destinations are legal in inline links and reference
    # definitions. HTMLParser can mistake some of them for start tags, so
    # protect those spans before masking actual HTML markup.
    protected_angles: set[int] = set()
    bracket_pairs = _matching_bracket_pairs(text)

    def protect_angle_destination(start: int) -> None:
        if start >= len(text) or text[start] != "<":
            return
        index = start + 1
        while index < len(text) and text[index] not in "\r\n":
            if text[index] == ">" and not _is_escaped(text, index):
                protected_angles.add(start)
                return
            index += 1

    for opening, closing in bracket_pairs.items():
        suffix = closing + 1
        if suffix >= len(text):
            continue
        if text[suffix] == "(":
            cursor = suffix + 1
            while cursor < len(text) and text[cursor].isspace():
                cursor += 1
            protect_angle_destination(cursor)
        elif text[suffix] == ":":
            line_index = bisect_right(line_offsets, opening) - 1
            line_start = line_offsets[line_index]
            prefix = text[line_start:opening]
            # Permit a reference definition after ordinary blockquote/list
            # container markers, but not in the middle of a paragraph.
            while prefix:
                quote = re.match(r"^ {0,3}>[ \t]?", prefix)
                item = re.match(r"^ {0,3}(?:[-+*]|[0-9]{1,9}[.)])[ \t]+", prefix)
                marker = quote or item
                if marker is None:
                    break
                prefix = prefix[marker.end():]
            if not prefix.strip():
                cursor = suffix + 1
                while cursor < len(text) and text[cursor] in " \t":
                    cursor += 1

                definition_line_end = (
                    line_start + len(lines[line_index].rstrip("\r\n"))
                )
                if cursor < definition_line_end:
                    # Destination follows the colon on this line.
                    protect_angle_destination(cursor)
                elif cursor == definition_line_end and line_index + 1 < len(lines):
                    # CommonMark also permits the destination to start on
                    # the immediately following continuation line. Require
                    # the same block-container context and indentation rule
                    # used by reference extraction before protecting it.
                    next_index = line_index + 1
                    candidate = container_lines[next_index]
                    candidate_context = container_contexts[next_index]
                    base_context = container_contexts[line_index]
                    indentation = len(candidate) - len(candidate.lstrip(" \t"))
                    if (
                        candidate.strip()
                        and candidate_context[:2] == base_context[:2]
                        and not candidate_context[2]
                        and indentation <= 3
                    ):
                        raw_candidate = lines[next_index].rstrip("\r\n")
                        candidate_start = (
                            line_offsets[next_index]
                            + len(raw_candidate)
                            - len(candidate)
                            + indentation
                        )
                        protect_angle_destination(candidate_start)

    def tag_end(start: int) -> int:
        quote: str | None = None
        index = start + 1
        while index < len(text):
            char = text[index]
            if quote is not None:
                if char == quote:
                    quote = None
            elif char in {"'", '"'}:
                quote = char
            elif char == ">":
                return index + 1
            index += 1
        return start + 1

    inline_html_tag = re.compile(
        r"</?[A-Za-z][A-Za-z0-9-]*"
        r"(?:[ \t\n]+[A-Za-z_:][A-Za-z0-9_.:-]*"
        r"(?:[ \t\n]*=[ \t\n]*(?:\"[^\"]*\"|'[^']*'|[^\s\"'=<>\x60]+))?)*"
        r"[ \t\n]*/?>",
        re.DOTALL,
    )

    class InlineTagMasker(HTMLParser):
        def _mask_current_tag(self, *, validate_tag: bool = True) -> None:
            line, column = self.getpos()
            if line < 1 or line > len(lines):
                return
            start = line_offsets[line - 1] + column
            if (
                start >= len(text)
                or text[start] != "<"
                or _is_escaped(text, start)
                or start in protected_angles
            ):
                return
            end = tag_end(start)
            if validate_tag and not inline_html_tag.fullmatch(text[start:end]):
                # HTMLParser is permissive and can tokenize a Markdown
                # angle-bracket destination as a start tag. Mask only a
                # complete inline HTML tag.
                return
            for position in range(start, end):
                if output[position] not in "\r\n":
                    output[position] = " "

        def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
            self._mask_current_tag()

        def handle_endtag(self, tag: str) -> None:
            self._mask_current_tag()

        def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
            self._mask_current_tag()

        def handle_decl(self, decl: str) -> None:
            self._mask_current_tag(validate_tag=False)

        def handle_pi(self, data: str) -> None:
            self._mask_current_tag(validate_tag=False)

        def unknown_decl(self, data: str) -> None:
            self._mask_current_tag(validate_tag=False)

    parser = InlineTagMasker(convert_charrefs=False)
    parser.feed(text)
    parser.close()
    return "".join(output)


def _strip_inline_html_tags(text: str) -> str:
    """Remove recognized inline HTML markup while preserving text like '<3>'."""
    lines = text.splitlines(keepends=True)
    line_offsets = [0]
    for line in lines:
        line_offsets.append(line_offsets[-1] + len(line))

    spans: list[tuple[int, int]] = []

    def tag_end(start: int) -> int:
        quote: str | None = None
        index = start + 1
        while index < len(text):
            char = text[index]
            if quote is not None:
                if char == quote:
                    quote = None
            elif char in {"'", '"'}:
                quote = char
            elif char == ">":
                return index + 1
            index += 1
        return start + 1

    class InlineTagStripper(HTMLParser):
        def _record_current_markup(self, tag_name: str | None = None) -> None:
            if (
                tag_name is not None
                and re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*", tag_name) is None
            ):
                return
            line, column = self.getpos()
            if line < 1 or line > len(lines):
                return
            start = line_offsets[line - 1] + column
            if start >= len(text) or text[start] != "<" or _is_escaped(text, start):
                return

            if text.startswith("<!--", start):
                closing = text.find("-->", start + 4)
                end = closing + 3 if closing >= 0 else start + 1
            elif text.startswith("<?", start):
                closing = text.find("?>", start + 2)
                end = closing + 2 if closing >= 0 else start + 1
            else:
                end = tag_end(start)
            if end > start + 1:
                spans.append((start, end))

        def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
            self._record_current_markup(tag)

        def handle_endtag(self, tag: str) -> None:
            self._record_current_markup(tag)

        def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
            self._record_current_markup(tag)

        def handle_comment(self, data: str) -> None:
            self._record_current_markup()

        def handle_decl(self, decl: str) -> None:
            self._record_current_markup()

        def handle_pi(self, data: str) -> None:
            self._record_current_markup()

        def unknown_decl(self, data: str) -> None:
            self._record_current_markup()

    parser = InlineTagStripper(convert_charrefs=False)
    parser.feed(text)
    parser.close()
    for start, end in sorted(set(spans), reverse=True):
        text = text[:start] + text[end:]
    return text


def _extract_links(
    text: str,
    path: str,
    image_targets: list[tuple[str, int]] | None = None,
) -> tuple[list[tuple[str, int]], list[DocProblem]]:
    """Extract inline/reference links while respecting Markdown containers.

    Reference definitions may be placed in blockquotes or list items, and
    their destination may begin on the following line. Definitions are kept
    separate from use sites and use CommonMark's first-definition-wins rule.
    When supplied, image_targets receives image destinations separately from
    clickable links so images can be validated without satisfying navigation.
    """
    original_lines = text.splitlines(keepends=True)
    fenced, html_blocks = _markdown_block_regions(original_lines)
    markdown_ignored_blocks = fenced | html_blocks
    markdown_ignored_blocks |= _indented_code_lines(original_lines, markdown_ignored_blocks)
    html_masked = _mask_html_blocks_and_comments(text)
    html_tags_masked = _mask_inline_html_tags(html_masked)
    masked = _mask_inline_code(html_tags_masked, markdown_ignored_blocks)
    masked_lines = masked.splitlines(keepends=True)

    links: list[tuple[str, int]] = []
    problems: list[DocProblem] = []
    definitions: dict[str, tuple[str | None, int]] = {}
    definition_lines: set[int] = set()

    list_stacks: dict[int, list[int]] = {}
    normalized_lines: list[str] = []
    contexts: list[tuple[int, tuple[int, ...], bool]] = []
    for index, line in enumerate(masked_lines):
        if index in markdown_ignored_blocks:
            normalized_lines.append("")
            contexts.append((0, (), False))
            continue
        content, quote_depth, list_context, opened = _container_content(
            line, list_stacks
        )
        normalized_lines.append(content)
        contexts.append((quote_depth, list_context, opened))

    atx_heading = re.compile(r"^ {0,3}#{1,6}(?:[ \t]|$)")
    setext_underline = re.compile(r"^ {0,3}(?:=+|-+)[ \t]*$")
    thematic_break = re.compile(
        r"^ {0,3}(?:(?:[*][ \t]*){3,}|(?:-[ \t]*){3,}|(?:_[ \t]*){3,})$"
    )

    normalized_content = "\n".join(normalized_lines)
    line_offsets = [0]
    for normalized_line in normalized_lines:
        line_offsets.append(line_offsets[-1] + len(normalized_line) + 1)

    table_lines = _markdown_table_lines(original_lines, markdown_ignored_blocks)
    reference_boundaries: set[int] = set()
    reference_offset = 0
    previous_context: tuple[int, tuple[int, ...]] | None = None
    previous_paragraph = False
    for line_index, normalized_line in enumerate(normalized_lines):
        quote_depth, list_context, opened = contexts[line_index]
        ignored_or_table = (
            line_index in markdown_ignored_blocks or line_index in table_lines
        )
        effective_context = _effective_container_context(
            normalized_line,
            quote_depth,
            list_context,
            opened,
            previous_context,
            previous_paragraph,
        )
        block_start = (
            ignored_or_table
            or not normalized_line.strip()
            or atx_heading.match(normalized_line) is not None
            or setext_underline.fullmatch(normalized_line) is not None
            or thematic_break.fullmatch(normalized_line) is not None
            or opened
        )
        if previous_context is not None and effective_context != previous_context:
            block_start = True
        if block_start:
            reference_boundaries.add(reference_offset)
        reference_offset += len(normalized_line) + 1
        paragraph_line = (
            not ignored_or_table and _is_paragraph_content(normalized_line)
        )
        if paragraph_line:
            previous_context = effective_context
            previous_paragraph = True
        else:
            previous_context = None
            previous_paragraph = False

    reference_pairs = _matching_bracket_pairs(
        normalized_content, reference_boundaries
    )

    def reference_continuation_allowed(
        candidate_index: int, base_context: tuple[int, tuple[int, ...], bool]
    ) -> bool:
        if candidate_index >= len(normalized_lines) or candidate_index in markdown_ignored_blocks:
            return False
        candidate = normalized_lines[candidate_index]
        candidate_context = contexts[candidate_index]
        if (
            not candidate.strip()
            or candidate_context[:2] != base_context[:2]
            or candidate_context[2]
        ):
            return False
        indentation = len(candidate) - len(candidate.lstrip(" \t"))
        if indentation > 3:
            return False
        return True

    for index, line in enumerate(normalized_lines):
        if index in markdown_ignored_blocks:
            continue
        opening = re.match(r"^ {0,3}\[", line)
        if opening is None:
            continue

        open_offset = line_offsets[index] + opening.end() - 1
        close_offset = reference_pairs.get(open_offset)
        if close_offset is None or close_offset + 1 >= len(normalized_content):
            continue
        if normalized_content[close_offset + 1] != ":":
            continue

        label_text = normalized_content[open_offset + 1:close_offset]
        if not label_text.strip() or len(label_text) > 999:
            continue
        # Reference labels cannot contain unescaped opening brackets. Escaped
        # closing brackets remain part of the label rather than ending it.
        if any(
            char == "[" and not _is_escaped(label_text, position)
            for position, char in enumerate(label_text)
        ):
            continue

        label_end_line = index
        while (
            label_end_line + 1 < len(normalized_lines)
            and line_offsets[label_end_line + 1] <= close_offset
        ):
            label_end_line += 1
        base_context = contexts[index]
        if any(
            candidate in markdown_ignored_blocks
            or not normalized_lines[candidate].strip()
            or contexts[candidate][:2] != base_context[:2]
            or (candidate > index and contexts[candidate][2])
            for candidate in range(index, label_end_line + 1)
        ):
            continue

        line_number = index + 1
        if index > 0:
            previous = index - 1
            previous_line = normalized_lines[previous]
            previous_quote, previous_lists, _ = contexts[previous]
            current_quote, current_lists, opened_item = contexts[index]
            starts_new_block = (
                previous in markdown_ignored_blocks
                or previous in definition_lines
                or not previous_line.strip()
                or (previous_quote, previous_lists) != (current_quote, current_lists)
                or atx_heading.match(previous_line) is not None
                or setext_underline.fullmatch(previous_line) is not None
                or thematic_break.fullmatch(previous_line) is not None
            )
            if not (opened_item or starts_new_block):
                # A reference definition cannot interrupt an open paragraph.
                continue

        label = _normalize_reference_label(label_text)
        if not label:
            continue

        label_line_end = line_offsets[label_end_line] + len(
            normalized_lines[label_end_line]
        )
        payload = normalized_content[close_offset + 2:label_line_end].strip()
        consumed_lines = set(range(index, label_end_line + 1))
        destination_line = label_end_line

        if not payload:
            next_index = destination_line + 1
            if not reference_continuation_allowed(next_index, base_context):
                payload = ""
            else:
                payload = normalized_lines[next_index].strip()
                consumed_lines.add(next_index)
                destination_line = next_index

        if payload:
            target, destination_error = _parse_reference_destination(payload)
        else:
            target, destination_error = (
                None,
                "link reference definition has no destination",
            )

        def title_can_start(candidate_index: int) -> bool:
            if not reference_continuation_allowed(candidate_index, base_context):
                return False
            candidate = normalized_lines[candidate_index].lstrip(" \t")
            return candidate.startswith(('"', "'", "("))

        next_index = destination_line + 1
        if destination_error is None and title_can_start(next_index):
            payload += "\n" + normalized_lines[next_index].strip()
            consumed_lines.add(next_index)
            destination_line = next_index
            target, destination_error = _parse_reference_destination(payload)

        while destination_error in {
            "link title is not closed",
            "parenthesized link title is not closed",
        }:
            next_index = destination_line + 1
            if not reference_continuation_allowed(next_index, base_context):
                break
            payload += "\n" + normalized_lines[next_index].strip()
            consumed_lines.add(next_index)
            destination_line = next_index
            target, destination_error = _parse_reference_destination(payload)

        definition_lines.update(consumed_lines)
        if destination_error is not None or target is None:
            detail = destination_error or "missing destination"
            problems.append(
                DocProblem(
                    path,
                    line_number,
                    f"malformed Markdown reference definition '[{label}]': {detail}",
                )
            )
            continue

        if label in definitions:
            first_line = definitions[label][1]
            problems.append(
                DocProblem(
                    path,
                    line_number,
                    f"duplicate Markdown reference definition '{label}'; "
                    f"first definition on line {first_line} is used",
                )
            )
            continue

        definitions[label] = (_unescape_destination(target), line_number)

    # Remove complete definition blocks from link-use scanning, preserving
    # offsets and line numbers for actual reference use sites.
    scannable_lines: list[str] = []
    for line_index, line in enumerate(masked_lines):
        if line_index in definition_lines:
            scannable_lines.append(
                "".join(
                    "\n" if char == "\n" else "\r" if char == "\r" else " "
                    for char in line
                )
            )
        else:
            scannable_lines.append(line)
    content = "".join(scannable_lines)

    # Inline bracket pairing must not bridge Markdown block boundaries. Soft
    # line breaks inside a paragraph remain available to multiline link labels.
    table_lines = _markdown_table_lines(original_lines, markdown_ignored_blocks)
    block_boundaries: set[int] = set()
    offset = 0
    previous_context: tuple[int, tuple[int, ...]] | None = None
    previous_paragraph = False
    atx_start = re.compile(r"^ {0,3}#{1,6}(?:[ \t]|$)")
    thematic_break = re.compile(r"^ {0,3}(?:(?:[*][ \t]*){3,}|(?:-[ \t]*){3,}|(?:_[ \t]*){3,})$")
    setext_underline = re.compile(r"^ {0,3}(?:=+|-+)[ \t]*$")
    for line_index, line in enumerate(scannable_lines):
        normalized_line = normalized_lines[line_index]
        quote_depth, list_context, opened = contexts[line_index]
        ignored_or_table = (
            line_index in markdown_ignored_blocks
            or line_index in definition_lines
            or line_index in table_lines
        )
        effective_context = _effective_container_context(
            normalized_line,
            quote_depth,
            list_context,
            opened,
            previous_context,
            previous_paragraph,
        )
        block_start = (
            ignored_or_table
            or not normalized_line.strip()
            or atx_start.match(normalized_line) is not None
            or thematic_break.fullmatch(normalized_line) is not None
            or setext_underline.fullmatch(normalized_line) is not None
            or opened
        )
        if previous_context is not None and effective_context != previous_context:
            block_start = True
        if block_start:
            block_boundaries.add(offset)
        offset += len(line)
        paragraph_line = (
            not ignored_or_table and _is_paragraph_content(normalized_line)
        )
        if paragraph_line:
            previous_context = effective_context
            previous_paragraph = True
        else:
            previous_context = None
            previous_paragraph = False

    bracket_pairs = _matching_bracket_pairs(content, block_boundaries)
    index = 0
    line_number = 1

    def advance_to(next_index: int) -> None:
        nonlocal index, line_number
        line_number += content.count("\n", index, next_index)
        index = next_index

    def collect_target(target: str, source_line: int, is_image: bool) -> None:
        if is_image:
            if image_targets is not None:
                image_targets.append((target, source_line))
            return
        links.append((target, source_line))

    def collect_nested_images(
        label_start: int, label_end: int, outer_index: int
    ) -> None:
        """Collect image links nested inside an enclosing link's label."""
        cursor = label_start
        while cursor < label_end:
            if (
                content[cursor] != "!"
                or _is_escaped(content, cursor)
                or cursor + 1 >= label_end
                or content[cursor + 1] != "["
            ):
                cursor += 1
                continue

            image_open = cursor + 1
            image_close = bracket_pairs.get(image_open)
            if image_close is None or image_close >= label_end:
                cursor += 1
                continue

            suffix = image_close + 1
            image_line = line_number + content.count("\n", outer_index, cursor)
            if suffix < label_end and content[suffix] == "(":
                target, image_end, error = _parse_inline_destination(content, suffix)
                if error:
                    problems.append(DocProblem(path, image_line, error))
                elif target is not None:
                    collect_target(_unescape_destination(target), image_line, True)
                cursor = max(image_end, suffix + 1)
                continue

            reference_label: str | None = None
            reference_end = suffix
            if suffix < label_end and content[suffix] == "[":
                close_reference = bracket_pairs.get(suffix)
                if close_reference is not None and close_reference < label_end:
                    explicit_label = content[suffix + 1:close_reference]
                    reference_label = (
                        explicit_label
                        if explicit_label
                        else content[image_open + 1:image_close]
                    )
                    reference_end = close_reference + 1
            else:
                candidate = _normalize_reference_label(
                    content[image_open + 1:image_close]
                )
                if candidate in definitions:
                    reference_label = content[image_open + 1:image_close]

            if reference_label is not None:
                definition = definitions.get(
                    _normalize_reference_label(reference_label)
                )
                if definition is None:
                    problems.append(
                        DocProblem(
                            path,
                            image_line,
                            f"undefined Markdown reference: [{reference_label}]",
                        )
                    )
                elif definition[0] is not None:
                    collect_target(definition[0], image_line, True)
                cursor = reference_end
            else:
                cursor = image_close + 1

    while index < len(content):
        if content[index] != "[" or _is_escaped(content, index):
            advance_to(index + 1)
            continue

        close_bracket = bracket_pairs.get(index)
        if close_bracket is None:
            advance_to(index + 1)
            continue

        visible_label = content[index + 1:close_bracket]
        next_index = close_bracket + 1
        is_image = (
            index > 0
            and content[index - 1] == "!"
            and not _is_escaped(content, index - 1)
        )

        if next_index < len(content) and content[next_index] == "(":
            if image_targets is not None and not is_image:
                collect_nested_images(index + 1, close_bracket, index)
            target, end, error = _parse_inline_destination(content, next_index)
            if error:
                problems.append(DocProblem(path, line_number, error))
            elif target is not None:
                collect_target(_unescape_destination(target), line_number, is_image)
            advance_to(max(end, next_index + 1))
            continue

        reference_label: str | None = None
        end = close_bracket + 1
        if next_index < len(content) and content[next_index] == "[":
            close_reference = bracket_pairs.get(next_index)
            if close_reference is not None:
                explicit_label = content[next_index + 1:close_reference]
                reference_label = explicit_label if explicit_label else visible_label
                end = close_reference + 1
        else:
            candidate = _normalize_reference_label(visible_label)
            if candidate in definitions:
                reference_label = visible_label

        if reference_label is not None:
            if image_targets is not None and not is_image:
                collect_nested_images(index + 1, close_bracket, index)
            normalized = _normalize_reference_label(reference_label)
            definition = definitions.get(normalized)
            if definition is None:
                problems.append(
                    DocProblem(
                        path,
                        line_number,
                        f"undefined Markdown reference: [{reference_label}]",
                    )
                )
            elif definition[0] is not None:
                collect_target(definition[0], line_number, is_image)
            advance_to(end)
            continue

        advance_to(close_bracket + 1)

    return links, problems

def _strip_heading_link_destinations(heading: str) -> str:
    """Remove inline/reference link destinations while retaining visible labels.

    The shared bracket matcher and inline destination parser handle nested
    brackets and balanced parentheses in destinations.
    """
    bracket_pairs = _matching_bracket_pairs(heading)
    removals: list[tuple[int, int]] = []
    for _, closing in bracket_pairs.items():
        suffix = closing + 1
        if suffix < len(heading) and heading[suffix] == "(":
            _, end, error = _parse_inline_destination(heading, suffix)
            if error is None:
                removals.append((suffix, end))
        elif suffix < len(heading) and heading[suffix] == "[":
            reference_close = bracket_pairs.get(suffix)
            if reference_close is not None:
                removals.append((suffix, reference_close + 1))

    for start, end in sorted(removals, reverse=True):
        heading = heading[:start] + heading[end:]
    return heading


def _strip_heading_markup(heading: str) -> str:
    # Protect code-span contents from HTML character-reference decoding:
    # CommonMark leaves entities literal inside code spans.
    code_tokens: list[tuple[str, str]] = []
    for start, end in reversed(_inline_code_ranges(heading)):
        delimiter_length = 0
        while start + delimiter_length < end and heading[start + delimiter_length] == BACKTICK:
            delimiter_length += 1
        token = f"\ue000{len(code_tokens)}\ue001"
        code_text = heading[start + delimiter_length:end - delimiter_length]
        code_tokens.append((token, code_text))
        heading = heading[:start] + token + heading[end:]
    heading = _strip_heading_link_destinations(heading)
    heading = _strip_inline_html_tags(heading)
    heading = re.sub(r"\\([\\*_{}\[\]()#+\-.!_>])", r"\1", heading).replace("\\" + BACKTICK, BACKTICK)
    heading = re.sub(r"(?<!\w)(__|_)(?=\S)(.+?)(?<=\S)\1(?!\w)", r"\2", heading)
    heading = _decode_commonmark_character_references(heading)
    for token, code_text in reversed(code_tokens):
        heading = heading.replace(token, code_text)
    return heading.strip()

def _slugify_heading(heading: str) -> str:
    """Generate a GitHub-compatible heading slug before duplicate handling."""
    heading = _strip_heading_markup(heading).lower().replace(" ", "-")
    return GITHUB_SLUG_REMOVAL_RE.sub("", heading)

def _html_anchor_targets(text: str) -> set[str]:
    """Collect HTML id anchors and legacy a[name] anchors outside code."""
    lines = text.splitlines(keepends=True)
    fenced, html_blocks = _markdown_block_regions(lines)
    code_blocks = fenced | _indented_code_lines(lines, fenced | html_blocks)
    output = list(text)

    offset = 0
    for index, line in enumerate(lines):
        if index in code_blocks:
            for position in range(offset, offset + len(line)):
                if output[position] not in "\r\n":
                    output[position] = " "
        offset += len(line)

    for start, end in _document_inline_code_ranges(text, code_blocks | html_blocks):
        for position in range(start, end):
            if output[position] not in "\r\n":
                output[position] = " "

    class AnchorCollector(HTMLParser):
        def __init__(self) -> None:
            super().__init__(convert_charrefs=True)
            self.targets: set[str] = set()

        def _record(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
            tag_name = tag.lower()
            for attribute, value in attrs:
                attribute_name = attribute.lower()
                if value and (
                    attribute_name == "id"
                    or (tag_name == "a" and attribute_name == "name")
                ):
                    self.targets.add(value)

        def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
            self._record(tag, attrs)

        def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
            self._record(tag, attrs)

    parser = AnchorCollector()
    parser.feed("".join(output))
    parser.close()
    return parser.targets

def _markdown_anchors(text: str) -> set[str]:
    raw_lines = text.splitlines(keepends=True)
    fenced, html_blocks = _markdown_block_regions(raw_lines)
    indented = _indented_code_lines(raw_lines, fenced | html_blocks)
    ignored = fenced | html_blocks | indented
    html_masked = _mask_html_blocks_and_comments(text)
    lines = html_masked.splitlines()
    for index in ignored:
        lines[index] = ""

    list_stacks: dict[int, list[int]] = {}
    normalized: list[str] = []
    contexts: list[tuple[int, tuple[int, ...]]] = []
    opened_items: list[bool] = []
    previous_context: tuple[int, tuple[int, ...]] | None = None
    previous_paragraph = False
    for index, line in enumerate(lines):
        if index in ignored:
            normalized.append("")
            contexts.append((0, ()))
            opened_items.append(False)
            previous_context = None
            previous_paragraph = False
            continue
        content, quote_depth, list_context, opened = _container_content(
            line, list_stacks
        )
        effective_context = _effective_container_context(
            content,
            quote_depth,
            list_context,
            opened,
            previous_context,
            previous_paragraph,
        )
        normalized.append(content)
        contexts.append(effective_context)
        opened_items.append(opened)
        if _is_paragraph_content(content):
            previous_context = effective_context
            previous_paragraph = True
        else:
            previous_context = None
            previous_paragraph = False

    anchors: set[str] = _html_anchor_targets(text)
    atx_pattern = re.compile(r"^ {0,3}#{1,6}[ \t]+(.+?)[ \t]*#*[ \t]*$")
    underline_pattern = re.compile(r"^ {0,3}(?:=+|-+)[ \t]*$")
    thematic_pattern = re.compile(
        r"^ {0,3}(?:(?:[*][ \t]*){3,}|(?:-[ \t]*){3,}|(?:_[ \t]*){3,})$"
    )

    headings: list[tuple[int, str]] = []
    for index, line in enumerate(normalized):
        if index in ignored:
            continue
        atx = atx_pattern.match(line)
        if atx:
            headings.append((index, atx.group(1)))
            continue

        if not underline_pattern.fullmatch(line) or index == 0:
            continue
        previous = index - 1
        if (
            previous in ignored
            or not normalized[previous].strip()
            or contexts[previous] != contexts[index]
        ):
            continue

        start = previous
        while start > 0:
            if opened_items[start]:
                break
            candidate = start - 1
            candidate_line = normalized[candidate]
            if (
                candidate in ignored
                or not candidate_line.strip()
                or contexts[candidate] != contexts[previous]
                or atx_pattern.match(candidate_line)
                or underline_pattern.fullmatch(candidate_line)
                or thematic_pattern.fullmatch(candidate_line)
            ):
                break
            if opened_items[candidate]:
                start = candidate
                break
            start = candidate

        heading = " ".join(
            part.strip() for part in normalized[start:index] if part.strip()
        )
        if heading:
            headings.append((start, heading))

    # Slug collision suffixes follow source order, regardless of whether the
    # heading uses ATX or Setext syntax.
    occurrences: dict[str, int] = {}
    for _, heading in sorted(headings, key=lambda entry: entry[0]):
        base = _slugify_heading(heading)
        slug = base
        while slug in occurrences:
            occurrences[base] = occurrences.get(base, 0) + 1
            slug = f"{base}-{occurrences[base]}"
        occurrences[slug] = 0
        anchors.add(slug)

    return anchors

def _resolve_target(source: str, target: str) -> tuple[str | None, str | None, bool]:
    """Return (repository-relative path, fragment, external)."""
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc or target.startswith("//"):
        return None, None, True

    path = unquote(parsed.path)
    fragment = unquote(parsed.fragment) if parsed.fragment else None
    if not path:
        resolved = source
    elif path.startswith("/"):
        resolved = posixpath.normpath(path.lstrip("/"))
    else:
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(source), path))

    if resolved == ".":
        resolved = ""
    if resolved == ".." or resolved.startswith("../") or resolved.startswith("/"):
        return None, fragment, False
    return resolved, fragment, False


def validate_repository(root: Path, max_line_length: int = DEFAULT_MAX_LINE_LENGTH) -> list[DocProblem]:
    root = root.resolve()
    markdown_files = sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
        and path.suffix.lower() in {".md", ".markdown"}
        and not any(part in IGNORED_DIRS for part in path.relative_to(root).parts)
    )
    relative_files = {path.relative_to(root).as_posix(): path for path in markdown_files}
    file_contents: dict[str, str] = {}
    problems: list[DocProblem] = []
    discovered_links: dict[str, list[str]] = {}

    for relative, path in relative_files.items():
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as error:
            problems.append(DocProblem(relative, 0, f"Markdown is not valid UTF-8: {error}"))
            continue
        file_contents[relative] = content
        lines = content.splitlines(keepends=True)
        fenced, html_blocks = _markdown_block_regions(lines)
        markdown_ignored_blocks = fenced | html_blocks
        indented_code = _indented_code_lines(lines, markdown_ignored_blocks)
        markdown_ignored_blocks |= indented_code
        # Raw HTML blocks are ignored by Markdown link/anchor parsing, but
        # their content is still documentation text subject to the line limit.
        line_length_ignored = fenced | indented_code
        table_lines = _markdown_table_lines(lines, markdown_ignored_blocks)
        inline_code_by_line = _line_inline_code_ranges(content, markdown_ignored_blocks)
        for index, raw_line in enumerate(lines):
            line = raw_line.rstrip("\r\n")
            if index in line_length_ignored or len(line) <= max_line_length:
                continue
            # Inline code spans can cross line boundaries in CommonMark.
            # Table rows are never exempt, regardless of optional edge pipes.
            if not _line_length_is_exempt(
                line,
                max_line_length,
                inline_code_by_line.get(index, []),
                is_table_row=index in table_lines,
            ):
                problems.append(
                    DocProblem(
                        relative,
                        index + 1,
                        f"line is {len(line)} characters (limit {max_line_length})",
                    )
                )

        image_targets: list[tuple[str, int]] = []
        links, parse_problems = _extract_links(
            content, relative, image_targets=image_targets
        )
        problems.extend(parse_problems)
        discovered_links[relative] = []
        typed_targets = (
            [(target, line_number, False) for target, line_number in links]
            + [(target, line_number, True) for target, line_number in image_targets]
        )
        for target, line_number, is_image in typed_targets:
            try:
                resolved, fragment, external = _resolve_target(relative, target)
            except ValueError as error:
                problems.append(
                    DocProblem(relative, line_number, f"malformed link URL: {error}")
                )
                continue
            if external:
                continue  # External websites are intentionally not checked.
            if resolved is None:
                problems.append(DocProblem(relative, line_number, f"link escapes repository root: {target}"))
                continue

            target_path = root / resolved if resolved else root
            try:
                target_path.resolve().relative_to(root)
            except ValueError:
                problems.append(DocProblem(relative, line_number, f"link escapes repository root: {target}"))
                continue
            if not target_path.exists():
                problems.append(DocProblem(relative, line_number, f"missing internal link target: {target}"))
                continue
            if not target_path.is_file() and not target_path.is_dir():
                problems.append(DocProblem(relative, line_number, f"unsupported link target: {target}"))
                continue
            if not is_image:
                discovered_links[relative].append(resolved)

            if fragment and not is_image:
                anchor_file = target_path
                if target_path.is_dir():
                    readme = target_path / "README.md"
                    if not readme.is_file():
                        problems.append(
                            DocProblem(relative, line_number, f"directory has no README.md for fragment: {target}")
                        )
                        continue
                    anchor_file = readme
                if not anchor_file.is_file() or anchor_file.suffix.lower() not in {".md", ".markdown"}:
                    problems.append(
                        DocProblem(relative, line_number, f"fragment target is not a Markdown file: {target}")
                    )
                    continue
                anchor_relative = anchor_file.relative_to(root).as_posix()
                anchor_text = file_contents.get(anchor_relative)
                if anchor_text is None:
                    try:
                        anchor_text = anchor_file.read_text(encoding="utf-8")
                        file_contents[anchor_relative] = anchor_text
                    except UnicodeDecodeError:
                        anchor_text = ""
                if fragment not in _markdown_anchors(anchor_text):
                    problems.append(
                        DocProblem(relative, line_number, f"missing heading anchor '#{fragment}' in {resolved or '.'}")
                    )

    # Required navigation is checked independently of whether a link target happens to exist.
    for source, required_targets in REQUIRED_LINKS.items():
        if source not in relative_files:
            problems.append(DocProblem(source, 0, "required canonical entry point is missing"))
            continue
        actual = set(discovered_links.get(source, []))
        for required in required_targets:
            resolved, _, external = _resolve_target(source, required)
            if external or resolved is None:
                continue
            required_path = root / resolved
            if not required_path.exists():
                problems.append(DocProblem(source, 0, f"required target does not exist: {required}"))
            elif resolved not in actual:
                problems.append(DocProblem(source, 0, f"required navigation link is missing: {required}"))

    return sorted(problems, key=lambda problem: (problem.path, problem.line, problem.message))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="repository root (default: current directory)")
    parser.add_argument("--max-line-length", type=int, default=DEFAULT_MAX_LINE_LENGTH)
    args = parser.parse_args(argv)

    if args.max_line_length <= 0:
        parser.error("--max-line-length must be positive")
    if not args.root.is_dir():
        parser.error(f"repository root is not a directory: {args.root}")

    problems = validate_repository(args.root, args.max_line_length)
    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        print(f"documentation validation failed: {len(problems)} problem(s)", file=sys.stderr)
        return 1

    print(f"documentation validation passed ({args.max_line_length}-character limit; no external URL checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
