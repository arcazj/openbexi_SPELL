"""Build the active release twice in each of two independent Git worktrees."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile

from scripts.release_next import (
    ARTIFACT, MINOR, PACKAGE, ROOT, fingerprint, git, require, sha,
    validate_qualification, write_json,
)


def main() -> None:
    require(not git("status", "--porcelain"), "reproducibility requires a clean evidence commit")
    qualification = validate_qualification()
    revision, source_fingerprint = git("rev-parse", "HEAD"), fingerprint()
    evidence_root = ROOT / ".qualification" / f"v{MINOR}"
    evidence_root.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix="reproducibility-", dir=evidence_root)).resolve()
    require(staging.is_relative_to(evidence_root.resolve()), "export destination escaped workspace")
    products = []
    for label in ("export-a", "export-b"):
        export = staging / label
        subprocess.run(["git", "worktree", "add", "--detach", str(export), revision], cwd=ROOT, check=True)
        subprocess.run([
            sys.executable, "-I", "-c",
            "import runpy,sys; sys.path.insert(0,sys.argv.pop(1)); runpy.run_module('scripts.release_next',run_name='__main__')",
            str(export), "build",
        ], cwd=export, check=True)
        manifest_bytes = (export / ARTIFACT / "release-manifest.json").read_bytes()
        manifest = json.loads(manifest_bytes)
        package = (export / PACKAGE).read_bytes()
        require(manifest["repeated_builds"] == 2 and manifest["package_sha256"] == sha(package), "export did not reproduce")
        require(manifest["source_fingerprint"] == source_fingerprint, "export source differs")
        products.append((package, manifest_bytes, (export / (str(PACKAGE) + ".sha256")).read_bytes()))
    require(products[0] == products[1], "independent export package or manifest differs")
    require(not git("status", "--porcelain") and git("rev-parse", "HEAD") == revision
            and fingerprint() == source_fingerprint, "root changed during exports")
    package, manifest, sidecar = products[0]
    (ROOT / PACKAGE).write_bytes(package)
    (ROOT / ARTIFACT / "release-manifest.json").write_bytes(manifest)
    (ROOT / (str(PACKAGE) + ".sha256")).write_bytes(sidecar)
    write_json(ROOT / ARTIFACT / "reproducibility.json", {
        "schema_version": f"spell.v{MINOR}.reproducibility/1", "decision": "PASS",
        "source_commit": qualification["source_commit"], "source_fingerprint": source_fingerprint,
        "independent_exports": 2, "builds_per_export": 2,
        "package_sha256_results": [sha(item[0]) for item in products for _ in range(2)],
        "export_method": "independent detached Git worktrees of the clean evidence commit",
    })
    print(f"Four package builds matched: {sha(package)}")


if __name__ == "__main__":
    main()
