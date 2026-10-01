"""Record and independently verify the v0.11.1 documentation-only release."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = Path("artifacts/v0.11.1")
TAG = "v0.11.1"
PRODUCT_PATHS = ("backend", "frontend", "spell", "driver_host", "contracts",
                 "proxy", "procedures", "compose.yaml", "pyproject.toml")


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_cases(path: Path) -> list[str]:
    cases = list(ET.parse(path).getroot().iter("testcase"))
    identities = sorted(case.attrib["classname"] + "::" + case.attrib["name"] for case in cases)
    if len(cases) != 18 or len(set(identities)) != 18:
        raise ValueError("documentation test inventory differs")
    if any(any(case.find(status) is not None for status in ("failure", "error", "skipped")) for case in cases):
        raise ValueError("documentation qualification did not pass without skips")
    return identities


def check_product() -> None:
    if git("diff", "--name-only", "v0.11.0", "--", *PRODUCT_PATHS):
        raise ValueError("documentation release changed the accepted runtime")


def validate(require_tag: bool = False) -> dict:
    check_product()
    data = json.loads((ROOT / ARTIFACT / "qualification.json").read_text(encoding="utf-8"))
    if data["schema"] != "spell.documentation-release/1" or data["release"] != TAG:
        raise ValueError("release identity differs")
    if data["runtime_tag"] != "v0.11.0" or data["runtime_commit"] != git("rev-parse", "v0.11.0^{commit}"):
        raise ValueError("runtime predecessor differs")
    git("merge-base", "--is-ancestor", data["source_commit"], "HEAD")
    if git("rev-parse", data["source_commit"] + "^{tree}") != data["source_tree"]:
        raise ValueError("qualified source tree differs")
    changed = git("diff", "--name-only", data["source_commit"], "HEAD").splitlines()
    if any(not name.startswith(ARTIFACT.as_posix() + "/") for name in changed):
        raise ValueError("source changed after qualification")
    for name, expected in data["evidence_sha256"].items():
        path = ROOT / ARTIFACT / name
        if path.parent != ROOT / ARTIFACT or digest(path) != expected:
            raise ValueError("qualification evidence hash differs")
    if check_cases(ROOT / ARTIFACT / "documentation.xml") != data["tests"]:
        raise ValueError("qualified test identities differ")
    if require_tag:
        if git("cat-file", "-t", TAG) != "tag" or git("rev-parse", TAG + "^{commit}") != git("rev-parse", "HEAD"):
            raise ValueError("annotated release tag differs")
        if git("for-each-ref", "--format=%(contents)", "refs/tags/" + TAG) != tag_message():
            raise ValueError("annotated release message differs")
    return data


def tag_message() -> str:
    return (
        "SPELL v0.11.1 documentation maintenance\n\n"
        "Decision: ACCEPTED for documentation maintenance only\n"
        "Runtime predecessor: v0.11.0\n"
        "Qualification SHA-256: " + digest(ROOT / ARTIFACT / "qualification.json") + "\n"
        "Operational authorization: None"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", type=Path)
    parser.add_argument("--require-tag", action="store_true")
    parser.add_argument("--tag-message", action="store_true")
    args = parser.parse_args()
    if args.record:
        if git("status", "--porcelain"):
            raise ValueError("freeze clean committed source before qualification")
        check_product()
        identities = check_cases(args.record / "documentation.xml")
        destination = ROOT / ARTIFACT
        destination.mkdir(parents=True, exist_ok=True)
        for name in ("documentation.xml", "restoration.json"):
            (destination / name).write_bytes((args.record / name).read_bytes())
        data = {"schema": "spell.documentation-release/1", "release": TAG,
                "runtime_tag": "v0.11.0", "runtime_commit": git("rev-parse", "v0.11.0^{commit}"),
                "source_commit": git("rev-parse", "HEAD"), "source_tree": git("rev-parse", "HEAD^{tree}"),
                "tests": identities, "evidence_sha256": {name: digest(destination / name) for name in ("documentation.xml", "restoration.json")}}
        (destination / "qualification.json").write_bytes(
            (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8")
        )
    else:
        validate(args.require_tag)
        print(tag_message() if args.tag_message else "v0.11.1 documentation release: PASS")


if __name__ == "__main__":
    main()
