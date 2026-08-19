"""Side-effect-free source fingerprint shared by qualification and packaging."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


FINGERPRINT_TREES = (
    "backend",
    "frontend",
    "procedures",
    "proxy",
    "scripts",
    "security",
)
FINGERPRINT_FILES = (".dockerignore", "compose.yaml", "pyproject.toml")
FINGERPRINT_EXCLUDED_PARTS = {
    "__pycache__",
    ".pytest_cache",
    ".vite",
    "coverage",
    "dist",
    "node_modules",
    "playwright-report",
    "test-results",
}


def source_fingerprint_inputs(root: Path) -> list[Path]:
    source_root = root.resolve()
    paths: list[Path] = []
    for relative_tree in FINGERPRINT_TREES:
        tree = source_root / relative_tree
        if not tree.is_dir():
            raise FileNotFoundError(
                f"required qualification fingerprint tree is missing: {relative_tree}"
            )
        for path in tree.rglob("*"):
            relative = path.relative_to(source_root)
            if FINGERPRINT_EXCLUDED_PARTS.intersection(relative.parts):
                continue
            if path.is_symlink():
                raise ValueError(f"fingerprint input must not be a symlink: {relative.as_posix()}")
            if path.is_file():
                paths.append(path)
    for relative_file in FINGERPRINT_FILES:
        path = source_root / relative_file
        if not path.is_file() or path.is_symlink():
            raise FileNotFoundError(
                f"required qualification fingerprint file is missing: {relative_file}"
            )
        paths.append(path)
    return sorted(set(paths), key=lambda path: path.relative_to(source_root).as_posix())


def source_fingerprint(root: Path) -> str:
    source_root = root.resolve()
    digest = hashlib.sha256()
    for path in source_fingerprint_inputs(source_root):
        digest.update(path.relative_to(source_root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    print(source_fingerprint(args.root.resolve()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
