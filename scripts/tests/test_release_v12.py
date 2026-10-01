from __future__ import annotations

import gzip
import io
import tarfile
from pathlib import Path

import pytest

from scripts import release_v12 as release


def test_junit_retains_exact_identities_and_skips(tmp_path: Path) -> None:
    path = tmp_path / "tests.xml"
    path.write_text('<testsuite><testcase classname="a" name="b" time="0.1"/><testcase classname="a" name="c"><skipped/></testcase></testsuite>')
    assert release.junit(path) == {"tests": 2, "passed": 1, "identities": ["a::b", "a::c"], "skipped": ["a::c"]}


@pytest.mark.parametrize("cases", [
    '', '<testcase name="bad"><failure/></testcase>', '<testcase name="bad"><error/></testcase>',
    '<testcase name="same"/><testcase name="same"/>', '<testcase name="bad" time="NaN"/>',
    '<testcase name="bad" time="Infinity"/>', '<testcase name="bad" time="-1"/>',
])
def test_junit_rejects_invalid_or_failing_evidence(tmp_path: Path, cases: str) -> None:
    path = tmp_path / "tests.xml"
    path.write_text('<testsuite>' + cases + '</testsuite>')
    with pytest.raises(release.ReleaseError):
        release.junit(path)


def test_package_retains_product_images_but_excludes_captures_and_manuals(tmp_path: Path, monkeypatch) -> None:
    names = ['frontend/src/logo.png', 'backend/app.py', 'artifacts/v0.12/screenshot.png',
             'SPELL_DOCUMENTATION/manual.pdf', 'legacy.zip', 'module.pyc']
    for name in names:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'product')
    monkeypatch.setattr(release, 'ROOT', tmp_path)
    monkeypatch.setattr(release, 'git', lambda *args: '\0'.join(names))
    assert release.package_names() == ['backend/app.py', 'frontend/src/logo.png']
    first = release.archive()
    assert first == release.archive()
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(first))) as archive:
        assert archive.getnames() == release.package_names()


@pytest.mark.parametrize("name", [".env", "backend/private.key", "credentials.json"])
def test_secret_paths_fail_packaging(tmp_path: Path, monkeypatch, name: str) -> None:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"synthetic-canary")
    monkeypatch.setattr(release, 'ROOT', tmp_path)
    monkeypatch.setattr(release, 'git', lambda *args: name)
    with pytest.raises(release.ReleaseError):
        release.package_names()


def test_json_evidence_has_canonical_lf_bytes(tmp_path: Path) -> None:
    path = tmp_path / "evidence.json"
    release.write_json(path, {"result": "PASS"})
    assert b'\r' not in path.read_bytes()
    assert path.read_bytes().endswith(b'\n')
