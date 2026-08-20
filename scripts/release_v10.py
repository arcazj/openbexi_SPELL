"""Shared fail-closed release controls for SPELL v0.10."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import tarfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = Path("contracts/v10/release_policy.json")
QUALIFICATION_PATH = Path("artifacts/v0.10/release-qualification.json")
RELEASE_MANIFEST_PATH = Path("artifacts/v0.10/release-manifest.json")
PACKAGE_PATH = Path("artifacts/v0.10/openbexi-spell-v0.10.0.tar.gz")
SIDECAR_PATH = Path(str(PACKAGE_PATH) + ".sha256")
PRODUCT_VERSION = "0.10.0"
RELEASE_TAG = "v0.10.0"

EXPECTED_GATES = {
    "backend_v10": {"tests": 443, "skipped": 1},
    "backend_full": {"tests": 1366, "skipped": 19},
    "backend_postgresql": {"tests": 16, "skipped": 0},
    "backend_compose": {"tests": 3, "skipped": 0},
    "frontend_unit": {"tests": 112, "skipped": 0},
    "release_tooling": {"minimum_tests": 8, "skipped": 0},
    "documentation": {"minimum_tests": 1, "skipped": 0},
}
GATE_COMMANDS = {
    "backend_v10": "python -m pytest <seven v0.10 backend test modules> --junitxml=<capture>",
    "backend_full": "python -m pytest backend/tests --junitxml=<capture>",
    "backend_postgresql": "python -m pytest <16 PostgreSQL-selected node IDs> --junitxml=<capture>",
    "backend_compose": "python -m pytest <three Docker-Compose-selected node IDs> --junitxml=<capture>",
    "frontend_unit": "npm test -- --run --reporter=junit --outputFile=<capture>",
    "release_tooling": "python -m pytest scripts/tests/test_release_v10.py --junitxml=<capture>",
    "documentation": "python -m pytest <documentation validation tests> --junitxml=<capture>",
}

ALLOWED_V10_ARTIFACTS = {
    "artifacts/v0.10/reference-examples.json",
    "artifacts/v0.10/browser-e2e/results/.last-run.json",
    QUALIFICATION_PATH.as_posix(),
}
FORBIDDEN_SOURCE_MARKERS = (
    re.compile(rb"v0\.11", re.IGNORECASE),
    re.compile(rb"0\.11\.0"),
    re.compile(rb"contracts[/\\]v11", re.IGNORECASE),
    re.compile(rb"ir_v11", re.IGNORECASE),
    re.compile(rb"telecommand_v11", re.IGNORECASE),
)
SECRET_PATH_NAMES = {
    ".env",
    "credentials.json",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "secrets.json",
}
SECRET_SUFFIXES = {".jks", ".key", ".p12", ".pem", ".pfx"}


class ReleaseV10Error(ValueError):
    """Raised when a v0.10 release invariant is not satisfied."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def _git(root: Path, *arguments: str, text: bool = True) -> str | bytes:
    result = subprocess.run(
        ["git", *arguments],
        cwd=root,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=60,
    )
    if result.returncode != 0:
        raise ReleaseV10Error(
            f"git {' '.join(arguments)} failed: "
            f"{result.stderr.decode('utf-8', errors='replace').strip()}"
        )
    return result.stdout.decode("utf-8").strip() if text else result.stdout


def git_commit(root: Path) -> str:
    return str(_git(root, "rev-parse", "HEAD"))


def git_tree(root: Path, revision: str = "HEAD") -> str:
    return str(_git(root, "rev-parse", f"{revision}^{{tree}}"))


def assert_clean_worktree(root: Path) -> None:
    status = str(_git(root, "status", "--porcelain", "--untracked-files=all"))
    if status:
        raise ReleaseV10Error("v0.10 release operation requires a clean worktree")


def _assert_ancestor(root: Path, ancestor: str, descendant: str = "HEAD") -> None:
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", ancestor, descendant],
        cwd=root,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=60,
    )
    if result.returncode != 0:
        raise ReleaseV10Error(f"required commit is not an ancestor: {ancestor}")


def load_policy(root: Path = ROOT) -> dict:
    path = root / POLICY_PATH
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseV10Error("v0.10 release policy is missing or invalid") from exc
    expected_keys = {
        "schema_version",
        "product_version",
        "release_tag",
        "candidate_commit",
        "scope",
        "operational_authorization",
        "reference_inputs",
        "release_evidence",
        "package_policy",
    }
    if set(policy) != expected_keys:
        raise ReleaseV10Error("v0.10 release policy fields differ from the contract")
    if (
        policy["schema_version"] != "spell.v10.release-policy/1"
        or policy["product_version"] != PRODUCT_VERSION
        or policy["release_tag"] != RELEASE_TAG
        or policy["scope"] != "bounded-language-reference-adapter"
        or policy["operational_authorization"] is not False
    ):
        raise ReleaseV10Error("v0.10 release policy identity differs")
    return policy


def _validate_hash_inventory(root: Path, rows: list[dict], label: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for row in rows:
        if set(row) != {"path", "sha256", "role"}:
            raise ReleaseV10Error(f"{label} inventory row has unexpected fields")
        relative = row["path"]
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise ReleaseV10Error(f"required {label} file is missing or unsafe: {relative}")
        digest = sha256_file(path)
        if digest != row["sha256"]:
            raise ReleaseV10Error(f"required {label} hash differs: {relative}")
        if relative in result:
            raise ReleaseV10Error(f"duplicate {label} path: {relative}")
        result[relative] = digest
    return result


def _tracked_paths(root: Path) -> list[str]:
    raw = _git(root, "ls-files", "-z", text=False)
    assert isinstance(raw, bytes)
    return sorted(part.decode("utf-8") for part in raw.split(b"\0") if part)


def _validate_reference_inputs(root: Path, policy: dict) -> dict[str, str]:
    declared = _validate_hash_inventory(root, policy["reference_inputs"], "reference")
    actual = {
        path.relative_to(root).as_posix()
        for path in (root / "SPELL_DOCUMENTATION").rglob("*")
        if path.is_file()
    }
    if actual != set(declared):
        extra = sorted(actual - set(declared))
        missing = sorted(set(declared) - actual)
        raise ReleaseV10Error(
            f"SPELL_DOCUMENTATION inventory differs; extra={extra}, missing={missing}"
        )
    return declared


def _validate_product_identity(root: Path, tracked: list[str]) -> None:
    required_paths = {
        "backend/ir_v10.py",
        "backend/reference_examples_v10.py",
        "contracts/v10/language_reference_example_matrix.json",
        "contracts/v10/language_reference_variant_matrix.json",
        "procedures/language_reference_244.spell.py",
        "scripts/generate_reference_runner_v10.py",
        "scripts/qualify_reference_examples_v10.py",
    }
    if not required_paths.issubset(tracked):
        raise ReleaseV10Error("required v0.10 product paths are missing")
    forbidden_paths = [
        path
        for path in tracked
        if path.startswith(("contracts/v11/", "artifacts/v0.11/"))
        or re.search(r"(^|/)[^/]*_v11(?:\.|/|$)", path, re.IGNORECASE)
    ]
    if forbidden_paths:
        raise ReleaseV10Error(f"v0.11 paths entered v0.10: {forbidden_paths}")

    identity_files = {
        "backend/version.py": 'PRODUCT_VERSION = "0.10.0"',
        "backend/__init__.py": '__version__ = "0.10.0"',
        "frontend/package.json": '"version": "0.10.0"',
        "frontend/package-lock.json": '"version": "0.10.0"',
        "pyproject.toml": 'version = "0.10.0"',
    }
    for relative, marker in identity_files.items():
        if marker not in (root / relative).read_text(encoding="utf-8"):
            raise ReleaseV10Error(f"v0.10 identity marker is missing: {relative}")

    procedures = sorted(path.name for path in (root / "procedures").glob("*.spell.py"))
    if procedures != ["language_reference_244.spell.py"]:
        raise ReleaseV10Error(f"v0.10 procedure catalog differs: {procedures}")

    source_paths = [
        path
        for path in tracked
        if path.startswith(("backend/", "frontend/src/", "procedures/", "contracts/"))
        and Path(path).suffix.casefold() in {".py", ".ts", ".tsx", ".json"}
        and path != POLICY_PATH.as_posix()
    ]
    source_paths.extend(["pyproject.toml", "frontend/package.json"])
    for relative in sorted(set(source_paths)):
        data = (root / relative).read_bytes()
        if any(pattern.search(data) for pattern in FORBIDDEN_SOURCE_MARKERS):
            raise ReleaseV10Error(f"v0.11 source marker entered v0.10: {relative}")


def _validate_reference_evidence(root: Path) -> None:
    example_matrix = json.loads(
        (root / "contracts/v10/language_reference_example_matrix.json").read_text(
            encoding="utf-8"
        )
    )
    variant_matrix = json.loads(
        (root / "contracts/v10/language_reference_variant_matrix.json").read_text(
            encoding="utf-8"
        )
    )
    evidence = json.loads(
        (root / "artifacts/v0.10/reference-examples.json").read_text(encoding="utf-8")
    )
    if example_matrix.get("example_count") != 195 or len(example_matrix.get("examples", [])) != 195:
        raise ReleaseV10Error("v0.10 example matrix is not exactly 195 entries")
    if (
        variant_matrix.get("example_count") != 195
        or variant_matrix.get("variant_count") != 257
        or variant_matrix.get("multiple_variant_example_count") != 46
    ):
        raise ReleaseV10Error("v0.10 variant matrix totals differ")
    if evidence.get("summary") != {
        "failed": 0,
        "passed": 195,
        "skipped": 0,
        "total": 195,
        "unresolved": 0,
        "xfailed": 0,
    }:
        raise ReleaseV10Error("v0.10 example qualification summary differs")
    if evidence.get("variant_summary") != {
        "failed": 0,
        "multiple_variant_examples": 46,
        "passed": 257,
        "total": 257,
        "unproved": 0,
    }:
        raise ReleaseV10Error("v0.10 variant qualification summary differs")
    results = evidence.get("results")
    if not isinstance(results, list) or [row.get("example_number") for row in results] != list(range(1, 196)):
        raise ReleaseV10Error("v0.10 qualification identities are not exactly 1..195")
    if any(row.get("status") != "PASS" for row in results):
        raise ReleaseV10Error("v0.10 qualification contains a non-PASS result")

    last_run = json.loads(
        (root / "artifacts/v0.10/browser-e2e/results/.last-run.json").read_text(
            encoding="utf-8"
        )
    )
    if last_run != {"status": "passed", "failedTests": []}:
        raise ReleaseV10Error("v0.10 browser run did not finish with PASS")
    browser_json = sorted(
        (root / "artifacts/v0.10/browser-e2e/results").glob(
            "*/language-reference-example-195-*-evidence.json"
        )
    )
    if len(browser_json) != 2:
        raise ReleaseV10Error("v0.10 requires exactly two canonical browser events")
    for path in browser_json:
        event = json.loads(path.read_text(encoding="utf-8"))
        payload = event.get("payload", {})
        if (
            event.get("event_type") != "procedure.reference_example_completed"
            or payload.get("example_number") != 195
            or payload.get("status") != "PASS"
            or payload.get("passed") is not True
        ):
            raise ReleaseV10Error(f"browser evidence differs: {path.relative_to(root)}")


def validate_repository(root: Path = ROOT) -> dict[str, object]:
    root = root.resolve()
    policy = load_policy(root)
    tracked = _tracked_paths(root)
    _assert_ancestor(root, policy["candidate_commit"])
    references = _validate_reference_inputs(root, policy)
    evidence = _validate_hash_inventory(root, policy["release_evidence"], "evidence")
    _validate_product_identity(root, tracked)
    _validate_reference_evidence(root)
    return {
        "candidate_commit": policy["candidate_commit"],
        "reference_hashes": references,
        "evidence_hashes": evidence,
    }


def _is_reparse_or_link(path: Path) -> bool:
    metadata = path.lstat()
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def package_files(root: Path = ROOT) -> list[Path]:
    root = root.resolve()
    policy = load_policy(root)["package_policy"]
    prefixes = tuple(policy["exclude_prefixes"])
    suffixes = {suffix.casefold() for suffix in policy["exclude_suffixes"]}
    forbidden = tuple(policy["forbidden_release_prefixes"])
    paths: list[Path] = []
    for relative in _tracked_paths(root):
        normalized = relative.replace("\\", "/")
        if normalized.startswith(forbidden):
            raise ReleaseV10Error(f"forbidden release path is tracked: {normalized}")
        if normalized.startswith(prefixes) or "/.qualification/" in f"/{normalized}":
            continue
        if Path(normalized).suffix.casefold() in suffixes:
            continue
        if normalized in {
            PACKAGE_PATH.as_posix(),
            SIDECAR_PATH.as_posix(),
            RELEASE_MANIFEST_PATH.as_posix(),
        }:
            continue
        if normalized.startswith("artifacts/"):
            if normalized.startswith("artifacts/v0.10/browser-e2e/results/"):
                if not normalized.endswith(".json"):
                    continue
            elif normalized not in ALLOWED_V10_ARTIFACTS:
                continue
        path = root / normalized
        if not path.is_file() or _is_reparse_or_link(path):
            raise ReleaseV10Error(f"package input is missing or unsafe: {normalized}")
        lowered_name = path.name.casefold()
        if lowered_name in SECRET_PATH_NAMES or path.suffix.casefold() in SECRET_SUFFIXES:
            raise ReleaseV10Error(f"secret-bearing path cannot enter package: {normalized}")
        paths.append(path)
    return sorted(paths, key=lambda path: path.relative_to(root).as_posix())


def source_files(root: Path = ROOT) -> list[Path]:
    excluded = {QUALIFICATION_PATH.as_posix()}
    return [
        path
        for path in package_files(root)
        if path.relative_to(root.resolve()).as_posix() not in excluded
    ]


def source_fingerprint(root: Path = ROOT) -> str:
    root = root.resolve()
    digest = hashlib.sha256()
    for path in source_files(root):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        data_hash = bytes.fromhex(sha256_file(path))
        digest.update(data_hash)
    return digest.hexdigest()


def parse_junit(path: Path) -> dict[str, int | float]:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        raise ReleaseV10Error(f"JUnit capture is missing or invalid: {path}") from exc
    cases = list(root.iter("testcase"))
    if not cases:
        raise ReleaseV10Error(f"JUnit capture contains no tests: {path}")
    failures = sum(case.find("failure") is not None for case in cases)
    errors = sum(case.find("error") is not None for case in cases)
    skipped = sum(case.find("skipped") is not None for case in cases)
    duration = sum(float(case.attrib.get("time", "0") or "0") for case in cases)
    return {
        "tests": len(cases),
        "passed": len(cases) - failures - errors - skipped,
        "failures": failures,
        "errors": errors,
        "skipped": skipped,
        "duration_seconds": round(duration, 6),
    }


def validate_gate_results(gates: dict[str, dict]) -> None:
    if set(gates) != set(EXPECTED_GATES):
        raise ReleaseV10Error("qualification gate inventory differs")
    for gate_id, expected in EXPECTED_GATES.items():
        result = gates[gate_id]
        if set(result) != {
            "tests",
            "passed",
            "failures",
            "errors",
            "skipped",
            "duration_seconds",
        }:
            raise ReleaseV10Error(f"qualification gate fields differ: {gate_id}")
        if result["failures"] != 0 or result["errors"] != 0:
            raise ReleaseV10Error(f"qualification gate failed: {gate_id}")
        if result["skipped"] != expected["skipped"]:
            raise ReleaseV10Error(f"qualification skip count differs: {gate_id}")
        if "tests" in expected and result["tests"] != expected["tests"]:
            raise ReleaseV10Error(f"qualification test count differs: {gate_id}")
        if result["tests"] < expected.get("minimum_tests", 0):
            raise ReleaseV10Error(f"qualification test count is too small: {gate_id}")
        if result["passed"] + result["failures"] + result["errors"] + result["skipped"] != result["tests"]:
            raise ReleaseV10Error(f"qualification totals are inconsistent: {gate_id}")
    if gates["backend_postgresql"]["passed"] != 16 or gates["backend_compose"]["passed"] != 3:
        raise ReleaseV10Error("environment-selected backend skips are not fully resolved")


def archive_bytes(root: Path, paths: Iterable[Path]) -> bytes:
    root = root.resolve()
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for path in paths:
            relative = path.relative_to(root).as_posix()
            data = path.read_bytes()
            info = tarfile.TarInfo(relative)
            info.size = len(data)
            info.mode = 0o755 if relative.startswith("scripts/") else 0o644
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(data))
    compressed = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=compressed, mtime=0) as output:
        output.write(raw.getvalue())
    return compressed.getvalue()


def package_content_manifest(root: Path, paths: Iterable[Path]) -> str:
    root = root.resolve()
    lines = [
        f"{sha256_file(path)}  {path.relative_to(root).as_posix()}\n"
        for path in paths
    ]
    return sha256_bytes("".join(lines).encode("utf-8"))
