"""Build the controlled SPELL GUI User Manual PDF from Markdown source."""

from __future__ import annotations

import argparse
import hashlib
import html
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

try:
    import fitz
    import markdown
except ImportError as exc:  # pragma: no cover - environment bootstrap
    raise SystemExit(
        "Install web/tools/requirements.txt before rendering the manual"
    ) from exc


TOOLS_DIR = Path(__file__).resolve().parent
WEB_DIR = TOOLS_DIR.parent
DEFAULT_SOURCE = WEB_DIR / "SPELL_GUI_USER_MANUAL.md"
DEFAULT_OUTPUT = WEB_DIR / "SPELL_GUI_USER_MANUAL-0.1.0-draft.1.pdf"
PRINT_CSS = WEB_DIR / "assets" / "gui-manual-print.css"
NODE_PRINTER = TOOLS_DIR / "print_gui_user_manual.cjs"


def build_html(source: Path) -> str:
    lines = source.read_text(encoding="utf-8").splitlines()
    if not lines or not lines[0].startswith("# "):
        raise ValueError("manual source must begin with one H1 title")

    title = lines[0].removeprefix("# ").strip()
    converter = markdown.Markdown(
        extensions=["tables", "toc", "fenced_code"],
        extension_configs={"toc": {"toc_depth": "2-4", "permalink": False}},
    )
    body = converter.convert("\n".join(lines[1:]))
    toc = converter.toc.replace('<div class="toc">', "").rsplit("</div>", 1)[0]
    base_uri = source.parent.resolve().as_uri() + "/"
    css_uri = PRINT_CSS.resolve().as_uri()

    cover = f"""<section class="cover">
  <div>
    <div class="cover-kicker">Next-Generation SPELL Documentation</div>
    <h1>{html.escape(title)}</h1>
    <div class="cover-rule"></div>
    <p class="cover-subtitle">Mission-control-quality web interface guidance for Controllers, Monitoring users, procedure developers, reviewers, and support teams.</p>
    <div class="draft-banner">Draft concept manual - no operational authorization</div>
  </div>
  <dl class="cover-meta">
    <dt>Manual version</dt><dd>0.1.0-draft.1</dd>
    <dt>Specification</dt><dd>Next-Generation SPELL Design Specification 0.1.0-draft.1</dd>
    <dt>Prepared</dt><dd>2026-07-18</dd>
    <dt>AI assistance</dt><dd>ChatGPT 5.6 SOL (project-declared)</dd>
    <dt>Product build</dt><dd>Not assigned</dd>
    <dt>Authority</dt><dd>DOC-011; human review and approval pending</dd>
  </dl>
</section>"""

    contents = f'<section class="contents"><h2>Contents</h2>{toc}</section>'
    note = (
        '<div class="publication-note">This PDF is generated from the controlled '
        "Markdown source. Concept wireframes describe intended information and "
        "workflow relationships; they are not evidence of implemented or accepted "
        "product behavior.</div>"
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<base href="{base_uri}">
<title>{html.escape(title)} - 0.1.0-draft.1</title>
<meta name="author" content="OpenBEXI SPELL Project">
<meta name="description" content="Draft next-generation SPELL web GUI user manual">
<link rel="stylesheet" href="{css_uri}">
</head>
<body>
{cover}
{contents}
{note}
<main id="manual">{body}</main>
</body>
</html>"""


def normalize_outline_and_metadata(pdf: Path) -> None:
    document = fitz.open(pdf)
    outline = document.get_toc()
    for entry in outline:
        value = entry[1]
        midpoint = len(value) // 2
        if len(value) % 2 == 0 and value[:midpoint] == value[midpoint:]:
            entry[1] = value[:midpoint]
    if outline:
        outline[0][1] = "Next-Generation SPELL Web GUI User Manual"
    document.set_toc(outline)

    metadata = document.metadata
    metadata.update(
        {
            "title": "Next-Generation SPELL Web GUI User Manual - 0.1.0-draft.1",
            "author": "OpenBEXI SPELL Project",
            "subject": "Draft next-generation SPELL web GUI user manual; DOC-011",
            "keywords": (
                "SPELL, mission operations, web interface, controller handover, "
                "procedure development"
            ),
        }
    )
    document.set_metadata(metadata)

    temporary = pdf.with_suffix(".normalized.pdf")
    document.save(temporary, garbage=3, deflate=True)
    document.close()
    os.replace(temporary, pdf)


def validate_pdf(pdf: Path) -> tuple[int, str]:
    document = fitz.open(pdf)
    pages = document.page_count
    text_chars = sum(len(page.get_text()) for page in document)
    images = sum(len(page.get_images(full=True)) for page in document)
    outline = document.get_toc()
    metadata = document.metadata
    unsafe_links = []
    internal_links = 0
    for page_number, page in enumerate(document, start=1):
        for link in page.get_links():
            uri = str(link.get("uri") or "")
            file_target = str(link.get("file") or "")
            if link.get("kind") in (fitz.LINK_GOTO, fitz.LINK_NAMED):
                internal_links += 1
            if (
                link.get("kind") == fitz.LINK_LAUNCH
                or uri.lower().startswith("file:")
                or file_target
            ):
                unsafe_links.append(page_number)
    document.close()

    raw = pdf.read_bytes()
    failures = []
    if pages < 2:
        failures.append("expected a multi-page PDF")
    if text_chars < 50_000:
        failures.append("selectable text is incomplete")
    if images != 4:
        failures.append(f"expected 4 concept figures, found {images}")
    if len(outline) < 80:
        failures.append("document outline is incomplete")
    if internal_links < 80:
        failures.append("linked contents navigation is incomplete")
    if metadata.get("author") != "OpenBEXI SPELL Project":
        failures.append("PDF author metadata is missing")
    if unsafe_links:
        pages_with_links = ", ".join(str(value) for value in sorted(set(unsafe_links)))
        failures.append(
            f"PDF contains non-portable file or launch links on pages {pages_with_links}"
        )
    if b"/StructTreeRoot" not in raw or b"/Marked true" not in raw:
        failures.append("tagged PDF structure is missing")
    if failures:
        raise RuntimeError("; ".join(failures))
    return pages, hashlib.sha256(raw).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--node", default=os.environ.get("NODE", "node"))
    parser.add_argument("--keep-html", type=Path)
    args = parser.parse_args()

    source = args.source.resolve()
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if not PRINT_CSS.is_file() or not NODE_PRINTER.is_file():
        raise SystemExit("manual print assets are incomplete")
    node = shutil.which(args.node) or args.node

    rendered = build_html(source)
    with tempfile.TemporaryDirectory(prefix="spell-gui-manual-") as temp_dir:
        html_path = Path(temp_dir) / "SPELL_GUI_USER_MANUAL.html"
        html_path.write_bytes(rendered.replace("\r\n", "\n").encode("utf-8"))
        subprocess.run(
            [node, str(NODE_PRINTER), str(html_path), str(output)],
            check=True,
        )
        if args.keep_html:
            args.keep_html.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(html_path, args.keep_html)

    normalize_outline_and_metadata(output)
    pages, digest = validate_pdf(output)
    print(f"Rendered {output}")
    print(f"Pages: {pages}")
    print(f"SHA-256: {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
