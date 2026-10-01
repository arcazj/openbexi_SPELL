"""Source-bound v0.12 qualification, deterministic packaging, and tag validation.

Run tests from clean committed source. The recorder retains raw evidence;
validation recomputes its hashes, test identities, skips, and package bytes.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import math
import subprocess
import tarfile
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = Path("artifacts/v0.12")
TAG = "v0.12.0"
POLICY = Path("contracts/v12/release_policy.json")
PACKAGE = ARTIFACT / "openbexi-spell-v0.12.0.tar.gz"
PREDECESSOR = "v0.11.1"


class ReleaseError(ValueError):
    pass


def require(value: bool, message: str) -> None:
    if not value:
        raise ReleaseError(message)


def git(*args: str, binary: bool = False):
    value = subprocess.check_output(["git", *args], cwd=ROOT)
    return value if binary else value.decode("utf-8").strip()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((json.dumps(data, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8"))


def policy() -> dict:
    data = json.loads((ROOT / POLICY).read_bytes())
    require(data["release_tag"] == TAG and data["product_version"] == "0.12.0", "policy identity differs")
    require(data["scope"] == "SYNTHETIC_REPLAY_ONLY" and data["legacy_system_qualified"] is False, "scope differs")
    require(data["operational_authorization"] is False, "policy authority differs")
    require(git("rev-parse", PREDECESSOR + "^{commit}") == data["predecessor_commit"], "predecessor differs")
    git("merge-base", "--is-ancestor", data["predecessor_commit"], "HEAD")
    for row in data["reference_inputs"]:
        require(sha((ROOT / row["path"]).read_bytes()) == row["sha256"], "mandatory source hash differs")
    return data


def package_names() -> list[str]:
    result = []
    for name in git("ls-files", "-z").split("\0"):
        if not name or name.startswith(("artifacts/", "SPELL_DOCUMENTATION/", "tools/", ".qualification/")):
            continue
        path = Path(name)
        if path.suffix.lower() in {".pdf", ".zip", ".pyc", ".pyo"}:
            continue
        if name.startswith("NEW_SPELL_DOCUMENTATION_GENERATED_BY_AI/web/assets/"):
            continue
        require(path.name not in {".env", "credentials.json", "secrets.json"}, "secret path in package")
        require(path.suffix.lower() not in {".key", ".pem", ".pfx", ".p12"}, "private material in package")
        require((ROOT / path).is_file() and not (ROOT / path).is_symlink(), "unsafe package input")
        result.append(name)
    return sorted(result)


def fingerprint() -> str:
    return sha(json.dumps({name: sha((ROOT / name).read_bytes()) for name in package_names()}, sort_keys=True).encode())


def junit(path: Path) -> dict:
    cases = list(ET.parse(path).getroot().iter("testcase"))
    require(bool(cases), "empty test capture")
    identities, skipped = [], []
    for case in cases:
        identity = case.attrib.get("classname", "") + "::" + case.attrib["name"]
        require(identity not in identities, "duplicate test identity")
        identities.append(identity)
        require(case.find("failure") is None and case.find("error") is None, "test capture contains failure")
        duration = float(case.attrib.get("time", "0"))
        require(math.isfinite(duration) and duration >= 0, "invalid test duration")
        if case.find("skipped") is not None:
            skipped.append(identity)
    return {"tests": len(cases), "passed": len(cases) - len(skipped),
            "identities": sorted(identities), "skipped": sorted(skipped)}


def verify_captures(directory: Path, config: dict) -> dict:
    gates = {}
    for gate, expected in config["gates"].items():
        result = junit(directory / (gate + ".xml"))
        require(result["tests"] == expected["tests"], f"test count differs: {gate}")
        require(result["identities"] == expected["identities"], f"exact test catalog differs: {gate}")
        require(result["skipped"] == expected["skipped"], f"skip identities differ: {gate}")
        gates[gate] = result
    # Every environment-selected SQLite skip must execute elsewhere.
    resolved = set(gates["postgresql"]["identities"]) - set(gates["postgresql"]["skipped"])
    resolved |= set(gates["compose"]["identities"])
    require(set(gates["sqlite"]["skipped"]) <= resolved, "unresolved environment skip")
    report = json.loads((directory / "replay.json").read_bytes())
    require(report["decision"] == "PASS" and report["soak_seconds"] >= 60 and report["repetitions"] >= 100,
            "replay soak failed")
    require(report["comparison"]["counts"] == {"EQUIVALENT": 5, "DIFFERENT": 0, "INDETERMINATE": 3, "UNSUPPORTED": 1},
            "replay oracle differs")
    audit = json.loads((directory / "python-audit.json").read_bytes())
    require(not any(row.get("vulns") for row in audit["dependencies"]), "Python advisories remain")
    audit = json.loads((directory / "npm-audit.json").read_bytes())
    require(audit["metadata"]["vulnerabilities"]["total"] == 0, "Node advisories remain")
    supply = json.loads((directory / "supply-chain.json").read_bytes())
    require(set(supply["images"]) == {"backend", "driver", "frontend", "proxy"}, "SBOM inventory differs")
    require(len({row["image_id"] for row in supply["images"].values()}) == 4, "image identities are not distinct")
    for component, row in supply["images"].items():
        require(row["high"] == 0 and row["critical"] == 0, "image vulnerability gate failed")
        sbom = json.loads((directory / f"{component}.cdx.json").read_bytes())
        require(sbom.get("bomFormat") == "CycloneDX" and len(sbom.get("components", [])) > 0, "invalid SBOM")
        require(sbom["metadata"]["component"]["version"] == row["image_id"], "SBOM image identity differs")
        require(sha((directory / f"{component}.cdx.json").read_bytes()) == row["sbom_sha256"], "SBOM hash differs")
        scan_path = directory / f"{component}.sarif.json"
        require(sha(scan_path.read_bytes()) == row["scan_sha256"], "image scan hash differs")
        scan = json.loads(scan_path.read_bytes())
        rules = scan["runs"][0]["tool"]["driver"]["rules"]
        require(not any(float(rule["properties"].get("security-severity", "0")) >= 7 for rule in rules), "Critical/High advisory remains")
        disposition = row["lower_severity_disposition"]
        require(disposition["advisories"] == [rule["id"] for rule in rules] and disposition["review_by"] == "2026-10-30", "advisory disposition differs")
    probe = json.loads((directory / "image-probe.json").read_bytes())
    require(probe["decision"] == "PASS", "image probes failed")
    require(all(probe["images"][name]["image_id"] == row["image_id"] for name, row in supply["images"].items()), "probed/scanned images differ")
    require(all(probe["services"][service]["image_id"] == supply["images"][name]["image_id"] for service, name in
                (("backend", "backend"), ("spell-driver", "driver"), ("proxy", "proxy"))), "running/scanned images differ")
    validation = json.loads((directory / "sbom-validation.json").read_bytes())
    require(set(validation["schemas"]) == set(supply["images"]) and validation["negative_tamper_rejected"] is True,
            "strict SBOM schema proof differs")
    examples = json.loads((directory / "reference-examples.json").read_bytes())
    require(examples["variant_summary"]["passed"] == 257 and examples["variant_summary"]["failed"] == 0, "inherited variants failed")
    commands = json.loads((directory / "commands.json").read_bytes())
    require(all(row["returncode"] == 0 for row in commands["commands"]), "qualification command failed")
    require({row["gate"] for row in commands["commands"]} >= set(config["gates"]) | {"frontend-build", "image-probe", "reference-generators", "replay"},
            "qualification command inventory incomplete")
    require(all(row["source_commit"] == commands["source_commit"] for row in commands["commands"]), "command source differs")
    return gates


def record(captures: Path) -> None:
    require(not git("status", "--porcelain"), "qualification requires clean committed source")
    config = policy()
    gates = verify_captures(captures, config)
    commands = json.loads((captures / "commands.json").read_bytes())
    require(commands["source_commit"] == git("rev-parse", "HEAD"), "capture source differs")
    publication = ROOT / ARTIFACT
    require(not publication.exists(), "canonical evidence already exists")
    staging = Path(tempfile.mkdtemp(prefix="v12-publication-", dir=ROOT / ".qualification"))
    destination = staging / "evidence"
    destination.mkdir(parents=True, exist_ok=True)
    evidence = {}
    names = {gate + ".xml" for gate in config["gates"]} | {
        "replay.json", "python-audit.json", "npm-audit.json", "supply-chain.json", "commands.json",
        "backend.cdx.json", "driver.cdx.json", "frontend.cdx.json", "proxy.cdx.json",
        "backend.sarif.json", "driver.sarif.json", "frontend.sarif.json", "proxy.sarif.json",
        "image-probe.json", "reference-examples.json", "sbom-validation.json"}
    browser = [path for path in (captures / "browser").rglob("*") if path.is_file() and path.suffix in {".png", ".json"}]
    require(sum(path.suffix == ".png" for path in browser) == 4, "browser screenshot inventory differs")
    names |= {path.relative_to(captures).as_posix() for path in browser}
    for name in sorted(names):
        raw = (captures / name).read_bytes()
        (destination / name).parent.mkdir(parents=True, exist_ok=True)
        (destination / name).write_bytes(raw)
        evidence[name] = sha(raw)
    write_json(staging / "qualification.json", {
        "schema_version": "spell.v12.qualification/1", "product_version": "0.12.0",
        "scope": "SYNTHETIC_REPLAY_ONLY", "source_commit": git("rev-parse", "HEAD"),
        "source_tree": git("rev-parse", "HEAD^{tree}"), "source_fingerprint": fingerprint(),
        "predecessor_commit": config["predecessor_commit"], "gates": gates,
        "evidence_sha256": evidence, "accepted_exceptions": [], "operational_authorization": False,
    })
    publication.parent.mkdir(parents=True, exist_ok=True)
    staging.replace(publication)


def validate_qualification() -> dict:
    config = policy()
    data = json.loads((ROOT / ARTIFACT / "qualification.json").read_bytes())
    require(data["schema_version"] == "spell.v12.qualification/1" and data["product_version"] == "0.12.0", "qualification identity differs")
    require(data["accepted_exceptions"] == [] and data["operational_authorization"] is False, "decision differs")
    require(data["scope"] == "SYNTHETIC_REPLAY_ONLY" and data["predecessor_commit"] == config["predecessor_commit"], "qualification scope differs")
    require(data["source_fingerprint"] == fingerprint(), "qualified source differs")
    require(data["source_tree"] == git("rev-parse", data["source_commit"] + "^{tree}"), "qualified tree differs")
    git("merge-base", "--is-ancestor", data["source_commit"], "HEAD")
    directory = ROOT / ARTIFACT / "evidence"
    files = {path.relative_to(directory).as_posix() for path in directory.rglob("*") if path.is_file()}
    require(files == set(data["evidence_sha256"]), "unbound or missing evidence file")
    commands = json.loads((directory / "commands.json").read_bytes())
    require(commands["source_commit"] == data["source_commit"], "command/qualification source differs")
    for name, digest in data["evidence_sha256"].items():
        require(not Path(name).is_absolute() and ".." not in Path(name).parts and sha((directory / name).read_bytes()) == digest, "evidence hash differs")
    require(verify_captures(directory, config) == data["gates"], "recomputed gates differ")
    return data


def archive() -> bytes:
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode="w", format=tarfile.PAX_FORMAT) as target:
            for name in package_names():
                data = (ROOT / name).read_bytes()
                info = tarfile.TarInfo(name)
                info.size, info.mode, info.mtime = len(data), 0o644, 0
                target.addfile(info, io.BytesIO(data))
    return output.getvalue()


def build() -> None:
    require(not git("status", "--porcelain"), "packaging requires clean committed source")
    qualification = validate_qualification()
    first, second = archive(), archive()
    require(first == second, "package did not reproduce")
    (ROOT / PACKAGE).write_bytes(first)
    (ROOT / (str(PACKAGE) + ".sha256")).write_bytes((sha(first) + "  " + PACKAGE.name + "\n").encode())
    write_json(ROOT / ARTIFACT / "release-manifest.json", {
        "schema_version": "spell.v12.release-manifest/1", "release_tag": TAG,
        "source_commit": qualification["source_commit"], "package_sha256": sha(first),
        "qualification_sha256": sha((ROOT / ARTIFACT / "qualification.json").read_bytes()),
        "source_fingerprint": qualification["source_fingerprint"], "file_count": len(package_names()),
        "repeated_builds": 2, "scope": "SYNTHETIC_REPLAY_ONLY"})


def tag_message() -> str:
    manifest = json.loads((ROOT / ARTIFACT / "release-manifest.json").read_bytes())
    return (f"SPELL {TAG}\n\nDecision: ACCEPTED\nScope: SYNTHETIC_REPLAY_ONLY\n"
            f"Qualified source: {manifest['source_commit']}\nPackage SHA-256: {manifest['package_sha256']}\n"
            f"Qualification SHA-256: {manifest['qualification_sha256']}\n"
            "Accepted exceptions: None\nReal legacy-system qualification: Not claimed\nOperational authorization: None\n")


def validate(require_tag: bool = False) -> None:
    require(not git("status", "--porcelain"), "validation requires clean committed source")
    data = validate_qualification()
    manifest = json.loads((ROOT / ARTIFACT / "release-manifest.json").read_bytes())
    package = archive()
    require(package == (ROOT / PACKAGE).read_bytes(), "package differs from rebuild")
    require(sha(package) == manifest["package_sha256"], "package digest differs")
    require(manifest["qualification_sha256"] == sha((ROOT / ARTIFACT / "qualification.json").read_bytes()), "qualification binding differs")
    require(manifest["source_commit"] == data["source_commit"] and manifest["source_fingerprint"] == fingerprint(), "release source differs")
    require((ROOT / (str(PACKAGE) + ".sha256")).read_bytes() == (sha(package) + "  " + PACKAGE.name + "\n").encode(), "sidecar differs")
    if require_tag:
        require(git("cat-file", "-t", TAG) == "tag", "release tag is not annotated")
        require(git("rev-parse", TAG + "^{commit}") == git("rev-parse", "HEAD"), "release tag targets different source")
        require(git("for-each-ref", "--format=%(contents)", "refs/tags/" + TAG) == tag_message().strip(), "tag message differs")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("fingerprint", "record", "build", "validate", "tag-message"))
    parser.add_argument("--captures", type=Path)
    parser.add_argument("--require-tag", action="store_true")
    args = parser.parse_args()
    if args.action == "fingerprint": print(fingerprint())
    elif args.action == "record": record(args.captures)
    elif args.action == "build": build()
    elif args.action == "validate": validate(args.require_tag); print("v0.12 release: PASS")
    else: print(tag_message(), end="")


if __name__ == "__main__":
    main()
