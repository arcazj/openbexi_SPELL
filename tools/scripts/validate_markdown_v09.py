#!/usr/bin/env python3
"""Render and validate every tracked Markdown document with the locked preview engine."""

from __future__ import annotations

import argparse
import html
import importlib.metadata
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

from markdown_it import MarkdownIt
from markdown_it.token import Token


ROOT = Path(__file__).resolve().parents[1]
MAX_MARKDOWN_BYTES = 4 * 1024 * 1024
MAX_MARKDOWN_FILES = 512
TABLE_DELIMITER = re.compile(
    r"^\s*\|?\s*:?-{3,}:?\s*(?:\|\s*:?-{3,}:?\s*)+\|?\s*$"
)
DANGEROUS_HTML = re.compile(
    r"<\s*/?\s*(?:script|style|iframe|object|embed|form|input|button|textarea)\b",
    re.IGNORECASE,
)
WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")
EXPLICIT_HTML_ID = re.compile(
    r"\bid\s*=\s*(?:\"([^\"]+)\"|'([^']+)'|([^\s>]+))", re.IGNORECASE
)
GITHUB_SLUG_PUNCTUATION = re.compile(r"[^\w\- ]", re.UNICODE)


class MarkdownValidationError(ValueError):
    """Raised when tracked Markdown cannot be rendered as a bounded preview."""


@dataclass(frozen=True)
class MarkdownReport:
    files: int
    links: int
    tables: int


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise MarkdownValidationError(message)


def _git_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for key in (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_REPLACE_REF_BASE",
    ):
        environment.pop(key, None)
    environment.update(
        {
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "LC_ALL": "C",
            "LANG": "C",
        }
    )
    return environment


def _qualification_export_markdown(root: Path) -> tuple[str, ...]:
    declared = os.environ.get("SPELL_QUALIFICATION_SOURCE_ROOT")
    try:
        source_root = root.resolve(strict=True)
        declared_root = Path(declared).resolve(strict=True) if declared else None
    except OSError as exc:
        raise MarkdownValidationError("qualification source root is invalid") from exc
    _require(
        declared_root == source_root and not (source_root / ".git").exists(),
        "cannot enumerate tracked Markdown",
    )

    paths: list[str] = []
    for directory, names, files in os.walk(source_root, topdown=True, followlinks=False):
        current = Path(directory)
        safe_names: list[str] = []
        for name in sorted(names):
            child = current / name
            _require(
                not _is_link_or_reparse(child),
                f"qualification export contains an unsafe directory: {child.relative_to(source_root).as_posix()}",
            )
            safe_names.append(name)
        names[:] = safe_names
        for name in sorted(files):
            path = current / name
            if path.suffix != ".md":
                continue
            _require(
                not _is_link_or_reparse(path),
                f"tracked Markdown is unsafe: {path.relative_to(source_root).as_posix()}",
            )
            paths.append(path.relative_to(source_root).as_posix())
            _require(
                len(paths) <= MAX_MARKDOWN_FILES,
                "tracked Markdown inventory exceeds the bounded file count",
            )
    return tuple(sorted(paths))


def tracked_markdown(root: Path) -> tuple[str, ...]:
    try:
        completed = subprocess.run(
            [
                "git",
                "-c",
                "core.quotepath=false",
                "ls-files",
                "-z",
                "--",
                "*.md",
            ],
            cwd=root,
            env=_git_environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except FileNotFoundError:
        return _qualification_export_markdown(root)
    if completed.returncode != 0:
        return _qualification_export_markdown(root)
    entries = completed.stdout.split(b"\0")
    if entries and entries[-1] == b"":
        entries.pop()
    try:
        paths = tuple(item.decode("utf-8") for item in entries)
    except UnicodeDecodeError as exc:
        raise MarkdownValidationError("tracked Markdown path is not UTF-8") from exc
    _require(paths == tuple(sorted(set(paths))), "tracked Markdown inventory differs")
    _require(
        len(paths) <= MAX_MARKDOWN_FILES,
        "tracked Markdown inventory exceeds the bounded file count",
    )
    for relative in paths:
        pure = PurePosixPath(relative)
        _require(
            bool(pure.parts)
            and not pure.is_absolute()
            and ".." not in pure.parts
            and pure.suffix == ".md",
            f"tracked Markdown path is unsafe: {relative}",
        )
    return paths


def _is_link_or_reparse(path: Path) -> bool:
    metadata = path.lstat()
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _tokens(tokens: list[Token]) -> list[Token]:
    flattened: list[Token] = []
    for token in tokens:
        flattened.append(token)
        if token.children:
            flattened.extend(_tokens(token.children))
    return flattened


def _comments_are_closed(source: str) -> bool:
    cursor = 0
    while True:
        start = source.find("<!--", cursor)
        if start < 0:
            return True
        end = source.find("-->", start + 4)
        if end < 0:
            return False
        cursor = end + 3


def _github_heading_anchors(source: str) -> set[str]:
    engine = preview_engine()
    tokens = engine.parse(source)
    anchors: set[str] = set()
    occurrences: dict[str, int] = {}
    for index, token in enumerate(tokens[:-1]):
        if token.type != "heading_open" or tokens[index + 1].type != "inline":
            continue
        label = tokens[index + 1].content
        label = re.sub(r"<[^>]*>", "", label)
        label = re.sub(r"[`*_~]", "", label)
        base = GITHUB_SLUG_PUNCTUATION.sub("", html.unescape(label).strip().lower())
        base = re.sub(r"\s", "-", base)
        suffix = occurrences.get(base, 0)
        occurrences[base] = suffix + 1
        anchors.add(base if suffix == 0 else f"{base}-{suffix}")
    for match in EXPLICIT_HTML_ID.finditer(source):
        anchors.add(html.unescape(next(value for value in match.groups() if value)))
    return anchors


def _validate_fragment(candidate: Path, target: str, fragment: str) -> None:
    if not fragment or candidate.suffix.lower() not in {".md", ".markdown"}:
        return
    try:
        source = candidate.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise MarkdownValidationError(
            f"Markdown link fragment target is not UTF-8: {target}"
        ) from exc
    decoded = unquote(fragment)
    _require("\0" not in decoded, f"Markdown link fragment contains NUL: {target}")
    _require(
        decoded in _github_heading_anchors(source),
        f"Markdown link fragment is missing: {target}",
    )


def _validate_local_target(root: Path, document: Path, target: str) -> None:
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc:
        return
    decoded = unquote(parsed.path) if parsed.path else ""
    _require("\0" not in decoded, f"Markdown link contains NUL: {target}")
    _require(
        not decoded.startswith(("/", "\\")) and WINDOWS_DRIVE.match(decoded) is None,
        f"Markdown link uses an absolute local path: {target}",
    )
    pure = PurePosixPath(decoded.replace("\\", "/"))
    candidate = document if not pure.parts else document.parent.joinpath(*pure.parts)
    _require(candidate.exists(), f"Markdown link target is missing: {target}")
    _require(not _is_link_or_reparse(candidate), f"Markdown link target is unsafe: {target}")
    try:
        candidate = candidate.resolve()
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise MarkdownValidationError(f"Markdown link escapes the repository: {target}") from exc
    _validate_fragment(candidate, target, parsed.fragment)


def preview_engine() -> MarkdownIt:
    return MarkdownIt("commonmark", {"html": True}).enable(
        ("table", "strikethrough")
    )


def validate_markdown(root: Path = ROOT) -> MarkdownReport:
    source_root = root.resolve()
    engine = preview_engine()
    file_count = 0
    link_count = 0
    table_count = 0
    for relative in tracked_markdown(source_root):
        path = source_root / relative
        _require(path.is_file(), f"tracked Markdown is missing: {relative}")
        _require(not _is_link_or_reparse(path), f"tracked Markdown is unsafe: {relative}")
        raw = path.read_bytes()
        _require(0 < len(raw) <= MAX_MARKDOWN_BYTES, f"tracked Markdown size is invalid: {relative}")
        _require(not raw.startswith(b"\xef\xbb\xbf"), f"tracked Markdown has a UTF-8 BOM: {relative}")
        try:
            source = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise MarkdownValidationError(f"tracked Markdown is not strict UTF-8: {relative}") from exc
        _require("\0" not in source, f"tracked Markdown contains NUL: {relative}")
        _require(_comments_are_closed(source), f"Markdown HTML comments are unbalanced: {relative}")
        _require(
            DANGEROUS_HTML.search(source) is None,
            f"Markdown contains unsafe preview HTML: {relative}",
        )

        parsed = engine.parse(source)
        rendered = engine.render(source)
        _require(bool(rendered.strip()), f"Markdown preview is blank: {relative}")
        flat = _tokens(parsed)
        observed_tables = sum(token.type == "table_open" for token in flat)
        expected_tables = sum(
            TABLE_DELIMITER.fullmatch(line) is not None for line in source.splitlines()
        )
        _require(
            observed_tables == expected_tables,
            f"GFM table did not render exactly: {relative}",
        )
        for token in flat:
            if token.type == "link_open":
                href = token.attrGet("href")
                _require(href is not None, f"Markdown link has no target: {relative}")
                _validate_local_target(source_root, path, href)
                link_count += 1
            elif token.type == "image":
                src = token.attrGet("src")
                _require(src is not None, f"Markdown image has no source: {relative}")
                _validate_local_target(source_root, path, src)
                link_count += 1
        file_count += 1
        table_count += observed_tables
    _require(file_count > 0, "tracked Markdown inventory is empty")
    return MarkdownReport(files=file_count, links=link_count, tables=table_count)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    try:
        report = validate_markdown(args.root)
    except (MarkdownValidationError, OSError) as exc:
        print(f"markdown_preview=FAIL error={exc}")
        return 1
    print(
        "markdown_preview=PASS "
        f"files={report.files} links={report.links} tables={report.tables} "
        f"engine=markdown-it-py-{importlib.metadata.version('markdown-it-py')} "
        "profile=commonmark+gfm-table-strikethrough"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
