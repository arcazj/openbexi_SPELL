"""Narrow applicability resolution for two independently reviewed GCC advisories.

This does not suppress scanner output or accept vulnerable runtime code.
Header absence resolves only the pb_ds advisory for the three listed Debian
runtime packages. Aligned-new overflow requires the separate exact-binary POSIX
proof. Neither review covers arbitrary GCC binaries or other vulnerabilities.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess

ADVISORY = "CVE-2026-102010"
UPSTREAM = "aaa8351f4d2e636f9680a1f0a8ebc2f0a60611e6"
PURL = "pkg:deb/debian/gcc-14@14.2.0-19?os_distro=trixie&os_name=debian&os_version=13"
PACKAGES = {name: "14.2.0-19" for name in ("gcc-14-base:amd64", "libgcc-s1:amd64", "libstdc++6:amd64")}
LOCATIONS = {"/usr/lib/x86_64-linux-gnu/libgcc_s.so.1", "/usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.33",
             "/usr/share/doc/gcc-14-base/copyright", "/var/lib/dpkg/status"}


def inspect_runtime():
    """Run inside the immutable image, retaining complete GCC package files."""
    packages, files = {}, {}
    for package in PACKAGES:
        packages[package] = subprocess.check_output(
            ["dpkg-query", "-W", "-f=${Version}", package], text=True).strip()
        for name in subprocess.check_output(["dpkg-query", "-L", package], text=True).splitlines():
            path = Path(name)
            if path.is_file():
                files[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    headers = sorted(str(p) for root in (Path("/usr/include"), Path("/usr/local/include"))
                     for p in root.rglob("*") if "pb_ds" in p.parts)
    return {"packages": packages, "files": files, "pb_ds_headers": headers}


def resolve(scan: dict, probe: dict) -> list[dict]:
    """Fail closed for every High finding outside this exact component review."""
    run = scan["runs"][0]
    resolutions = []
    for rule in run["tool"]["driver"]["rules"]:
        if float(rule["properties"].get("security-severity", "0")) < 7:
            continue
        if rule["id"] == "CVE-2026-95619":
            from scripts.gcc_aligned_new_applicability import resolve_rule
            results = [r for r in run["results"] if r["ruleId"] == rule["id"]]
            resolutions.append(resolve_rule(rule, results, probe))
            continue
        assert rule["id"] == ADVISORY, "unresolved Critical/High advisory"
        assert rule["properties"]["purls"] == [PURL], "unreviewed affected package"
        evidence = probe["gcc_header_applicability"]
        assert evidence["packages"] == PACKAGES, "unreviewed GCC runtime version"
        assert evidence["pb_ds_headers"] == [], "affected template headers present"
        files = evidence["files"]
        assert LOCATIONS - {"/var/lib/dpkg/status"} <= set(files), "missing runtime file inventory"
        assert all("pb_ds" not in path and "/include/" not in path for path in files), "GCC development files present"
        assert all(len(value) == 64 and set(value) <= set("0123456789abcdef") for value in files.values()), "invalid file hash"
        results = [r for r in run["results"] if r["ruleId"] == ADVISORY]
        assert len(results) == 1, "unreviewed finding multiplicity"
        locations = {p["physicalLocation"]["artifactLocation"]["uri"] for p in results[0]["locations"]}
        assert locations == LOCATIONS, "finding includes unreviewed files"
        resolutions.append({"advisory": ADVISORY, "status": "NOT_AFFECTED", "justification": "vulnerable_code_not_present",
                            "upstream_fix": UPSTREAM, "affected_package": PURL,
                            "evidence_sha256": hashlib.sha256(json.dumps(evidence, sort_keys=True).encode()).hexdigest()})
    return resolutions


if __name__ == "__main__":
    print(json.dumps(inspect_runtime(), sort_keys=True))
