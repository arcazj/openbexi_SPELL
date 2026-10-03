"""Reject broadened applicability claims and altered exact-binary proof."""
from copy import deepcopy

import pytest

from scripts import gcc_aligned_new_applicability as aligned
from scripts import gcc_header_applicability as header


def _inputs():
    rules = [{"id": advisory, "properties": {"security-severity": "7.7", "purls": [aligned.PURL]}}
             for advisory in (header.ADVISORY, aligned.ADVISORY)]
    results = [{"ruleId": rule["id"], "locations": [
        {"physicalLocation": {"artifactLocation": {"uri": path}}} for path in sorted(aligned.LOCATIONS)]}
        for rule in rules]
    scan = {"runs": [{"tool": {"driver": {"rules": rules}}, "results": results}]}
    files = {path: "a" * 64 for path in header.LOCATIONS - {"/var/lib/dpkg/status"}}
    files[aligned.LIBRARY] = aligned.LIBRARY_SHA256
    probe = {"gcc_aligned_new_applicability": aligned.expected_evidence(),
             "gcc_header_applicability": {"packages": dict(header.PACKAGES), "files": files, "pb_ds_headers": []}}
    return scan, probe


def test_exact_posix_proof_resolves_both_advisories_without_changing_raw_scan():
    scan, probe = _inputs()
    original = deepcopy(scan)
    resolutions = header.resolve(scan, probe)
    assert scan == original
    assert [r["advisory"] for r in resolutions] == [header.ADVISORY, aligned.ADVISORY]
    assert all(r["status"] == "NOT_AFFECTED" and r["justification"] == "vulnerable_code_not_present"
               for r in resolutions)
    assert resolutions[-1]["reviewed_library_sha256"] == aligned.LIBRARY_SHA256
    assert resolutions[-1]["upstream_fix"] == aligned.UPSTREAM


@pytest.mark.parametrize("mutation", [
    "advisory", "package", "package-extra", "location", "duplicate-location", "extra-finding",
    "version", "architecture", "library", "library-hash", "inventory-hash", "inventory-version",
    "allocator", "call", "plt", "got", "relocation", "function-hash", "c11-import", "loaded-code",
    "loader-override", "overflow-allocation", "array-overflow-allocation", "missing-boundary",
    "boundary-value", "missing-control", "control-failed", "boolean-as-number", "extra-proof",
])
def test_applicability_fails_closed_for_tampered_scope_binary_or_behavior(mutation):
    scan, probe = _inputs()
    run = scan["runs"][0]
    rule = run["tool"]["driver"]["rules"][-1]
    result = run["results"][-1]
    evidence = probe["gcc_aligned_new_applicability"]
    if mutation == "advisory": rule["id"] = "CVE-unreviewed"
    elif mutation == "package": rule["properties"]["purls"] = ["pkg:deb/debian/gcc-15@15.2.0"]
    elif mutation == "package-extra": rule["properties"]["purls"].append("pkg:generic/other@1")
    elif mutation == "location": result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = "/tmp/other.so"
    elif mutation == "duplicate-location": result["locations"].append(deepcopy(result["locations"][0]))
    elif mutation == "extra-finding": run["results"].append(deepcopy(result))
    elif mutation == "version": evidence["version"] = "14.2.0-20"
    elif mutation == "architecture": evidence["architecture"] = "aarch64"
    elif mutation == "library": evidence["library"] = "/tmp/libstdc++.so.6.0.33"
    elif mutation == "library-hash": evidence["library_sha256"] = "b" * 64
    elif mutation == "inventory-hash": probe["gcc_header_applicability"]["files"][aligned.LIBRARY] = "b" * 64
    elif mutation == "inventory-version": probe["gcc_header_applicability"]["packages"]["libstdc++6:amd64"] = "14.2.0-20"
    elif mutation == "allocator": evidence["binary"]["allocator"] = "aligned_alloc"
    elif mutation == "call": evidence["binary"]["call_address"] += 1
    elif mutation == "plt": evidence["binary"]["plt_address"] += 1
    elif mutation == "got": evidence["binary"]["got_address"] += 1
    elif mutation == "relocation": evidence["binary"]["relocation_type"] = "R_X86_64_GLOB_DAT"
    elif mutation == "function-hash": evidence["binary"]["functions"][aligned.SYMBOL][2] = "b" * 64
    elif mutation == "c11-import": evidence["binary"]["c11_aligned_alloc_import"] = True
    elif mutation == "loaded-code": evidence["loaded_code_matches_file"] = False
    elif mutation == "loader-override": evidence["loader_overrides"] = {"LD_PRELOAD": "/tmp/allocator.so"}
    elif mutation == "overflow-allocation": evidence["overflow_cases"][0]["scalar_null"] = False
    elif mutation == "array-overflow-allocation": evidence["overflow_cases"][-1]["array_null"] = False
    elif mutation == "missing-boundary": evidence["overflow_cases"].pop()
    elif mutation == "boundary-value": evidence["overflow_cases"][0]["size"] = 100
    elif mutation == "missing-control": evidence["controls"].pop()
    elif mutation == "control-failed": evidence["controls"][0]["array_aligned_write_free"] = False
    elif mutation == "boolean-as-number": evidence["loaded_code_matches_file"] = 1
    else: evidence["unreviewed"] = "field"
    with pytest.raises(AssertionError):
        header.resolve(scan, probe)


@pytest.mark.parametrize("data", [b"", b"not an ELF", b"\x7fELF\x02\x01\x01" + b"\0" * 256])
def test_unreviewed_elf_bytes_rejected_before_parsing_or_loading(data):
    with pytest.raises(AssertionError, match="unreviewed libstdc"):
        aligned.inspect_binary(data)
