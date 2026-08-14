from __future__ import annotations

import copy
import hashlib
import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from scripts import build_reproducible_v05 as release


def test_v05_archive_bytes_are_deterministic_and_normalized(tmp_path: Path) -> None:
    source = tmp_path / "scripts" / "probe.py"
    source.parent.mkdir()
    source.write_text("print('bounded')\n", encoding="ascii")

    first = release._archive_bytes(tmp_path, [source])
    second = release._archive_bytes(tmp_path, [source])

    assert first == second
    assert hashlib.sha256(first).hexdigest() == hashlib.sha256(second).hexdigest()


@pytest.mark.parametrize(
    "relative",
    [
        "artifacts/v0.4/gate-1.json",
        "legacy.zip",
        "runtime.sqlite",
        "secrets/value.json",
        "client.key",
    ],
)
def test_v05_package_rejects_forbidden_paths(relative: str) -> None:
    with pytest.raises(ValueError):
        release._validate_path(Path(relative))


def test_v05_package_rejects_private_key_bytes(tmp_path: Path) -> None:
    source = tmp_path / "scripts" / "probe.txt"
    source.parent.mkdir()
    source.write_bytes(b"-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n")

    with pytest.raises(ValueError, match="secret material"):
        release._archive_bytes(tmp_path, [source])


def test_v05_scanner_literal_contract_matches_every_live_source_file() -> None:
    for relative, literals in release.SECRET_SCANNER_LITERAL_CONTRACT.items():
        raw = (release.ROOT / relative).read_bytes()
        assert all(raw.count(literal) == 1 for literal in literals)
        release._validate_bytes(Path(relative), raw)


@pytest.mark.parametrize(
    "relative",
    sorted(release.SECRET_SCANNER_LITERAL_CONTRACT),
)
def test_v05_scanner_literal_contract_rejects_path_and_byte_mutations(
    relative: str,
) -> None:
    raw = (release.ROOT / relative).read_bytes()
    literal = release.SECRET_SCANNER_LITERAL_CONTRACT[relative][0]
    mutated_literal = literal[:-1] + b" " + literal[-1:]

    with pytest.raises(ValueError, match="literal contract differs"):
        release._validate_bytes(
            Path(relative), raw.replace(literal, mutated_literal, 1)
        )
    with pytest.raises(ValueError, match="secret material"):
        release._validate_bytes(Path("scripts/unapproved-scanner.py"), literal)
    with pytest.raises(ValueError, match="secret material"):
        release._validate_bytes(
            Path(relative),
            raw
            + b"\n"
            + release.PEM_PRIVATE_KEY_BEGIN
            + b"\nreal-payload\n-----END PRIVATE KEY-----\n",
        )


def test_v05_package_scans_canonical_candidate_canaries_structurally() -> None:
    for relative in (
        release.WORK_PACKAGE_MANIFEST,
        "artifacts/v0.5/work-package/tests/tooling.xml",
    ):
        path = release.ROOT / relative
        release._validate_bytes(Path(relative), path.read_bytes())


def test_v05_package_rejects_duplicate_or_mislocated_evidence_canaries() -> None:
    from scripts.validate_candidate_evidence_v05 import TOOLING_SYNTHETIC_NODES

    manifest_path = release.ROOT / release.WORK_PACKAGE_MANIFEST
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["suites"]["tooling"]["collected_nodes"].append(
        TOOLING_SYNTHETIC_NODES[0]
    )
    with pytest.raises(ValueError, match="synthetic tooling node"):
        release._validate_bytes(
            Path(release.WORK_PACKAGE_MANIFEST),
            json.dumps(manifest, separators=(",", ":")).encode("utf-8"),
        )

    tooling_relative = "artifacts/v0.5/work-package/tests/tooling.xml"
    tooling_raw = (release.ROOT / tooling_relative).read_bytes()
    root = ET.fromstring(tooling_raw)
    duplicated = False
    for parent in root.iter():
        for child in list(parent):
            expected_name = TOOLING_SYNTHETIC_NODES[0].rsplit("::", 1)[1]
            if child.tag == "testcase" and child.get("name") == expected_name:
                parent.append(copy.deepcopy(child))
                duplicated = True
                break
        if duplicated:
            break
    assert duplicated
    with pytest.raises(ValueError, match="exactly once"):
        release._validate_bytes(Path(tooling_relative), ET.tostring(root))
    with pytest.raises(ValueError, match="secret material"):
        release._validate_bytes(
            Path("artifacts/v0.5/final/tests/not-tooling.xml"), tooling_raw
        )


def test_current_v05_product_package_fingerprint_is_constructible() -> None:
    digest = release.product_package_sha256_v05(release.ROOT)
    assert len(digest) == 64
    assert set(digest) <= set("0123456789abcdef")
