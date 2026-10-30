#!/usr/bin/env python3
"""Validate local Markdown links, anchors, navigation, and line lengths."""

from __future__ import annotations

import argparse
import posixpath
import re
import sys
import unicodedata
from pathlib import Path
from urllib.parse import unquote, urlsplit

DEFAULT_MAX_LINE_LENGTH = 88
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


def _blockquote_content(line: str) -> tuple[str, int]:
    """Remove consecutive blockquote prefixes and return the nesting depth."""
    offset = 0
    depth = 0
    while offset < len(line):
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


def _fenced_code_lines(lines: list[str]) -> set[int]:
    """Return zero-based lines inside fenced blocks, including blockquotes."""
    fenced: set[int] = set()
    marker: str | None = None
    marker_length = 0
    quote_depth = 0

    for index, line in enumerate(lines):
        container_line, current_quote_depth = _blockquote_content(line)

        if marker is not None and current_quote_depth < quote_depth:
            # The enclosing blockquote ended; its fenced block cannot consume
            # subsequent text outside that container.
            marker = None
            marker_length = 0
            quote_depth = 0

        stripped = container_line.lstrip(" ")
        indent = len(container_line) - len(stripped)
        match = (
            re.match(rf"({re.escape(BACKTICK)}{{3,}}|~{{3,}})(.*)$", stripped)
            if indent <= 3
            else None
        )

        if marker is not None:
            fenced.add(index)
            close = re.match(
                rf" {{0,3}}{re.escape(marker)}{{{marker_length},}}[ \t]*$",
                container_line,
            )
            if close and current_quote_depth >= quote_depth:
                marker = None
                marker_length = 0
                quote_depth = 0
            continue

        if match:
            candidate = match.group(1)
            info = match.group(2)
            if candidate[0] != BACKTICK or BACKTICK not in info:
                marker = candidate[0]
                marker_length = len(candidate)
                quote_depth = current_quote_depth
                fenced.add(index)

    return fenced


def _inline_code_ranges(text: str) -> list[tuple[int, int]]:
    """Find matched inline-code spans across the complete text."""
    ranges: list[tuple[int, int]] = []
    index = 0
    while index < len(text):
        if text[index] != BACKTICK or _is_escaped(text, index):
            index += 1
            continue

        run_end = index + 1
        while run_end < len(text) and text[run_end] == BACKTICK:
            run_end += 1
        run_length = run_end - index

        search = run_end
        closing: tuple[int, int] | None = None
        while search < len(text):
            candidate = text.find(BACKTICK, search)
            if candidate < 0:
                break
            if _is_escaped(text, candidate):
                search = candidate + 1
                continue
            candidate_end = candidate + 1
            while candidate_end < len(text) and text[candidate_end] == BACKTICK:
                candidate_end += 1
            if candidate_end - candidate == run_length:
                closing = (candidate, candidate_end)
                break
            search = candidate_end

        if closing is None:
            index = run_end
            continue
        ranges.append((index, closing[1]))
        index = closing[1]
    return ranges


def _document_inline_code_ranges(
    text: str, fenced_lines: set[int] | None = None
) -> list[tuple[int, int]]:
    """Find inline-code spans in contiguous non-fenced document sections."""
    lines = text.splitlines(keepends=True)
    fenced = fenced_lines if fenced_lines is not None else _fenced_code_lines(lines)
    ranges: list[tuple[int, int]] = []
    offset = 0
    segment_start: int | None = None
    segment_parts: list[str] = []

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

    for index, line in enumerate(lines):
        if index in fenced:
            flush()
        else:
            if segment_start is None:
                segment_start = offset
            segment_parts.append(line)
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


def _line_length_is_exempt(
    line: str,
    max_line_length: int = DEFAULT_MAX_LINE_LENGTH,
    code_ranges: list[tuple[int, int]] | None = None,
) -> bool:
    """Allow atomic inline-code/URL spans only when residual prose fits."""
    if line.count("|") >= 2:
        return False  # Wide Markdown table rows must be rewritten, not exempted.

    spans = list(code_ranges) if code_ranges is not None else _inline_code_ranges(line)
    spans.extend((match.start(), match.end()) for match in re.finditer(r"https?://\S+", line))
    if not spans:
        return False

    merged: list[list[int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])

    reduced = line
    for start, end in reversed(merged):
        reduced = reduced[:start] + "x" + reduced[end:]
    return len(reduced) <= max_line_length


def _mask_inline_code(text: str) -> str:
    """Mask fenced and inline code while preserving offsets and newlines."""
    lines = text.splitlines(keepends=True)
    fenced = _fenced_code_lines(lines)
    output = list(text)
    offset = 0

    for line_number, line in enumerate(lines):
        if line_number in fenced:
            for index in range(offset, offset + len(line)):
                if output[index] not in "\r\n":
                    output[index] = " "
        offset += len(line)

    for start, end in _document_inline_code_ranges(text, fenced):
        for index in range(start, end):
            if output[index] not in "\r\n":
                output[index] = " "

    return "".join(output)

def _find_closing_bracket(text: str, start: int) -> int | None:
    depth = 0
    index = start
    while index < len(text):
        char = text[index]
        if _is_escaped(text, index):
            index += 1
            continue
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def _parse_inline_destination(text: str, open_paren: int) -> tuple[str | None, int, str | None]:
    """Parse a Markdown inline destination and return (target, end, error)."""
    index = open_paren + 1
    while index < len(text) and text[index].isspace():
        index += 1
    if index >= len(text):
        return None, len(text), "link destination is not closed"
    if text[index] == ")":
        return None, index + 1, "link destination is empty"

    if text[index] == "<":
        start = index + 1
        index = start
        while index < len(text):
            if text[index] == ">" and not _is_escaped(text, index):
                target = text[start:index]
                index += 1
                while index < len(text) and text[index].isspace():
                    index += 1
                if index < len(text) and text[index] == ")":
                    return target, index + 1, None
                # An optional Markdown title may follow an angle-bracket destination.
                title_depth = 0
                while index < len(text):
                    title_char = text[index]
                    if not _is_escaped(text, index):
                        if title_char == "(":
                            title_depth += 1
                        elif title_char == ")":
                            if title_depth == 0:
                                return target, index + 1, None
                            title_depth -= 1
                    index += 1
                return target, len(text), "link destination is not closed"
            index += 1
        return None, len(text), "link has an unterminated angle-bracket destination"

    start = index
    depth = 0
    while index < len(text):
        char = text[index]
        if _is_escaped(text, index):
            index += 1
            continue
        if char == "(" and not _is_escaped(text, index):
            depth += 1
        elif char == ")":
            if depth == 0:
                target = text[start:index]
                if not target:
                    return None, index + 1, "link destination is empty"
                return target, index + 1, None
            depth -= 1
        elif char.isspace() and depth == 0:
            target = text[start:index]
            while index < len(text) and text[index].isspace():
                index += 1
            # The rest is an optional title; require the final outer ')'.
            title_depth = 0
            while index < len(text):
                title_char = text[index]
                if not _is_escaped(text, index):
                    if title_char == "(":
                        title_depth += 1
                    elif title_char == ")":
                        if title_depth == 0:
                            return target, index + 1, None
                        title_depth -= 1
                index += 1
            return None, len(text), "link destination is not closed"
        index += 1
    return None, len(text), "link destination is not closed"


def _unescape_destination(target: str) -> str:
    return re.sub(r"\\([\\*{}\[\]()#+\-.!_>])", r"\1", target).replace("\\" + BACKTICK, BACKTICK)


def _normalize_reference_label(label: str) -> str:
    label = re.sub(r"\\([\x21-\x2f\x3a-\x40\x5b-\x60\x7b-\x7e])", r"\1", label)
    return " ".join(label.casefold().split())


def _extract_links(text: str, path: str) -> tuple[list[tuple[str, int]], list[DocProblem]]:
    """Extract links actually used in the document and validate reference labels.

    Reference definitions are kept separately from use sites: an unused
    definition is not a navigation link and cannot satisfy required entry-point
    checks. Duplicate definitions follow CommonMark's first-definition-wins rule.
    """
    masked = _mask_inline_code(text)
    links: list[tuple[str, int]] = []
    problems: list[DocProblem] = []
    definitions: dict[str, tuple[str, int]] = {}
    definition_lines: set[int] = set()

    for line_number, line in enumerate(masked.splitlines(), 1):
        match = re.match(r"^ {0,3}\[([^\]]+)\]:[ \t]*(.*)$", line)
        if not match:
            continue

        definition_lines.add(line_number)
        label = _normalize_reference_label(match.group(1))
        destination_text = match.group(2).strip()
        target: str | None = None

        if destination_text.startswith("<"):
            closing = next(
                (
                    index
                    for index in range(1, len(destination_text))
                    if destination_text[index] == ">" and not _is_escaped(destination_text, index)
                ),
                None,
            )
            if closing is not None:
                target = destination_text[1:closing]
        elif destination_text:
            target_match = re.match(r"(\S+)", destination_text)
            if target_match:
                target = target_match.group(1)

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

        if target is None or target == "":
            problems.append(DocProblem(path, line_number, f"malformed Markdown reference definition: [{label}]"))
            definitions[label] = ("", line_number)
            continue

        definitions[label] = (_unescape_destination(target), line_number)

    # Remove definition lines from link-use scanning, retaining offsets/newlines.
    scannable_lines = masked.splitlines(keepends=True)
    scannable: list[str] = []
    for line_number, line in enumerate(scannable_lines, 1):
        if line_number in definition_lines:
            scannable.append("".join("\n" if char == "\n" else "\r" if char == "\r" else " " for char in line))
        else:
            scannable.append(line)
    content = "".join(scannable)

    index = 0
    while index < len(content):
        if content[index] != "[" or _is_escaped(content, index):
            index += 1
            continue

        close_bracket = _find_closing_bracket(content, index)
        if close_bracket is None:
            index += 1
            continue

        visible_label = content[index + 1:close_bracket]
        next_index = close_bracket + 1
        line_number = content.count("\n", 0, index) + 1

        if next_index < len(content) and content[next_index] == "(":
            target, end, error = _parse_inline_destination(content, next_index)
            if error:
                problems.append(DocProblem(path, line_number, error))
            elif target is not None:
                links.append((_unescape_destination(target), line_number))
            index = max(end, next_index + 1)
            continue

        reference_label: str | None = None
        end = close_bracket + 1
        if next_index < len(content) and content[next_index] == "[":
            close_reference = _find_closing_bracket(content, next_index)
            if close_reference is not None:
                explicit_label = content[next_index + 1:close_reference]
                reference_label = explicit_label if explicit_label else visible_label
                end = close_reference + 1
        else:
            # CommonMark shortcut reference: [label] when a definition exists.
            candidate = _normalize_reference_label(visible_label)
            if candidate in definitions:
                reference_label = visible_label

        if reference_label is not None:
            normalized = _normalize_reference_label(reference_label)
            definition = definitions.get(normalized)
            if definition is None:
                problems.append(
                    DocProblem(path, line_number, f"undefined Markdown reference: [{reference_label}]")
                )
            elif definition[0]:
                links.append((definition[0], line_number))
            index = end
            continue

        index = close_bracket + 1

    return links, problems

def _strip_heading_markup(heading: str) -> str:
    heading = re.sub(re.escape(BACKTICK) + r"+([^" + re.escape(BACKTICK) + r"]*?)" + re.escape(BACKTICK) + r"+", r"\1", heading)
    heading = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", heading)
    heading = re.sub(r"!?\[([^\]]*)\]\[[^]]*\]", r"\1", heading)
    heading = re.sub(r"<[^>]+>", "", heading)
    heading = re.sub(r"\\([\\*_{}\[\]()#+\-.!_>])", r"\1", heading).replace("\\" + BACKTICK, BACKTICK)
    heading = heading.replace("*", "").replace("_", "").replace("~", "")
    return heading.strip()


def _slugify_heading(heading: str) -> str:
    heading = _strip_heading_markup(heading).lower()
    output: list[str] = []
    for char in heading:
        category = unicodedata.category(char)
        if char.isspace():
            output.append("-")
        elif category.startswith("P") and char != "-":
            continue
        else:
            output.append(char)
    slug = "".join(output)
    slug = re.sub(r"-+", "-", slug).strip("-")
    return slug


def _markdown_anchors(text: str) -> set[str]:
    lines = text.splitlines()
    fenced = _fenced_code_lines(lines)
    anchors: set[str] = set()
    counts: dict[str, int] = {}

    for index, line in enumerate(lines):
        if index in fenced:
            continue
        explicit_ids = re.findall(r"<a\s+[^>]*?id\s*=\s*[\"']([^\"']+)[\"']", line, re.IGNORECASE)
        anchors.update(explicit_ids)

        atx = re.match(r"^ {0,3}(#{1,6})\s+(.+?)\s*#*\s*$", line)
        if atx:
            heading = atx.group(2)
        elif index + 1 < len(lines) and index + 1 not in fenced:
            underline = re.match(r"^ {0,3}(=+|-+)\s*$", lines[index + 1])
            heading = line.strip() if underline and line.strip() else None
        else:
            heading = None

        if heading:
            base = _slugify_heading(heading)
            count = counts.get(base, 0)
            slug = base if count == 0 else f"{base}-{count}"
            counts[base] = count + 1
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
        for path in root.rglob("*.md")
        if not any(part in IGNORED_DIRS for part in path.relative_to(root).parts)
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
        fenced = _fenced_code_lines(lines)
        inline_code_by_line = _line_inline_code_ranges(content, fenced)
        for index, raw_line in enumerate(lines):
            line = raw_line.rstrip("\r\n")
            if index in fenced or len(line) <= max_line_length:
                continue
            # Inline code spans can cross line boundaries in CommonMark.
            if not _line_length_is_exempt(
                line, max_line_length, inline_code_by_line.get(index, [])
            ):
                problems.append(
                    DocProblem(
                        relative,
                        index + 1,
                        f"line is {len(line)} characters (limit {max_line_length})",
                    )
                )

        links, parse_problems = _extract_links(content, relative)
        problems.extend(parse_problems)
        discovered_links[relative] = []
        for target, line_number in links:
            resolved, fragment, external = _resolve_target(relative, target)
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
            discovered_links[relative].append(resolved)

            if fragment:
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
