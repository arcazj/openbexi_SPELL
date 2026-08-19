#!/usr/bin/env python3
"""Build or verify the deterministic SPELL v0.10 source package."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from scripts.release_v10 import (
    PACKAGE_PATH,
    PRODUCT_VERSION,
    QUALIFICATION_PATH,
    RELEASE_MANIFEST_PATH,
    RELEASE_TAG,
    ROOT,
    SIDECAR_PATH,
    ReleaseV10Error,
    archive_bytes,
    assert_clean_worktree,
    git_commit,
    git_tree,
    package_content_manifest,
    package_files,
    sha256_bytes,
    sha256_file,
)
from scripts.validate_release_evidence_v10 import (
    validate_release_evidence_v10,
    validate_qualification,
)


def build(root: Path = ROOT, *, verify: bool = False) -> dict:
    root = root.resolve()
    assert_clean_worktree(root)
    qualification = validate_qualification(root)
    paths_before = package_files(root)
    first = archive_bytes(root, paths_before)
    paths_after = package_files(root)
    second = archive_bytes(root, paths_after)
    if [path.relative_to(root) for path in paths_before] != [path.relative_to(root) for path in paths_after]:
        raise ReleaseV10Error("v0.10 package input inventory changed during build")
    if first != second:
        raise ReleaseV10Error("v0.10 package builds are not byte-identical")
    package_digest = sha256_bytes(first)
    sidecar = f"{package_digest}  {PACKAGE_PATH.name}\n".encode("ascii")
    published = None
    if verify:
        published = json.loads((root / RELEASE_MANIFEST_PATH).read_text(encoding="utf-8"))
        package_input_commit = published["package_input_commit"]
        package_input_tree = published["package_input_tree"]
    else:
        package_input_commit = git_commit(root)
        package_input_tree = git_tree(root)
    manifest = {
        "schema_version": "spell.v10.release-manifest/1",
        "product_version": PRODUCT_VERSION,
        "release_tag": RELEASE_TAG,
        "qualification_sha256": sha256_file(root / QUALIFICATION_PATH),
        "qualified_commit": qualification["qualified_commit"],
        "source_fingerprint_sha256": qualification["source_fingerprint_sha256"],
        "package_input_commit": package_input_commit,
        "package_input_tree": package_input_tree,
        "package_path": PACKAGE_PATH.as_posix(),
        "package_sha256": package_digest,
        "sidecar_path": SIDECAR_PATH.as_posix(),
        "sidecar_sha256": sha256_bytes(sidecar),
        "file_count": len(paths_before),
        "content_manifest_sha256": package_content_manifest(root, paths_before),
        "reproducible_builds": 2,
        "legacy_documentation_packaged": False,
        "v11_packaged": False,
        "decision": "PASS",
    }
    package_path = root / PACKAGE_PATH
    sidecar_path = root / SIDECAR_PATH
    manifest_path = root / RELEASE_MANIFEST_PATH
    if verify:
        if package_path.read_bytes() != first or sidecar_path.read_bytes() != sidecar:
            raise ReleaseV10Error("published v0.10 package bytes differ from rebuild")
        assert published is not None
        if published != manifest:
            raise ReleaseV10Error("published v0.10 release manifest differs from rebuild")
        validate_release_evidence_v10(root, require_package=True)
        return manifest
    package_path.parent.mkdir(parents=True, exist_ok=True)
    package_path.write_bytes(first)
    sidecar_path.write_bytes(sidecar)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true")
    arguments = parser.parse_args()
    try:
        manifest = build(verify=arguments.verify)
    except (OSError, json.JSONDecodeError, ReleaseV10Error) as exc:
        print(f"v0.10-reproducible-package=FAIL reason={exc}")
        return 1
    print(
        "v0.10-reproducible-package=PASS "
        f"sha256={manifest['package_sha256']} files={manifest['file_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
