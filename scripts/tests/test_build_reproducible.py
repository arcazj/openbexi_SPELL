from __future__ import annotations

import json
import hashlib
import tarfile
import tempfile
import unittest
from pathlib import Path

from scripts import build_reproducible
from scripts.compose_qualification import compose_reports
from scripts.tests.test_compose_qualification import passing_reports


DIRECTORY_INPUTS = {
    "backend",
    "procedures",
    "proxy",
    "frontend",
    "scripts",
    "security",
    "artifacts/sbom",
    "artifacts/v0.3",
}


class ReleaseEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        for name in build_reproducible.INCLUDE:
            path = self.root / name
            if name in DIRECTORY_INPUTS:
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f"test input: {name}\n", encoding="utf-8")
        (self.root / "backend/app.py").write_text("VERSION = 'test'\n", encoding="utf-8")
        (self.root / "scripts/qualify_v03.py").write_text("# qualifier\n", encoding="utf-8")
        (self.root / "scripts/qualify_browser_stream_server.py").write_text(
            "# browser qualifier\n", encoding="utf-8"
        )
        (self.root / "scripts/source_fingerprint.py").write_text(
            "# shared fingerprint implementation\n", encoding="utf-8"
        )
        (self.root / "frontend/scripts").mkdir(parents=True, exist_ok=True)
        (self.root / "frontend/scripts/qualify-browser-stream.mjs").write_text(
            "// browser measurement harness\n", encoding="utf-8"
        )
        (self.root / "frontend/product.png").write_bytes(b"product asset")
        self._write_sboms()
        self._write_passing_evidence()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write(self, name: str, value: dict) -> None:
        path = self.root / build_reproducible.QUALIFICATION_REPORTS[name]
        path.write_text(json.dumps(value), encoding="utf-8")

    def _write_sboms(
        self,
        *,
        fingerprint: str | None = None,
        component_overrides: dict[str, set[str]] | None = None,
        image_binding: str | None = None,
    ) -> None:
        directory = self.root / build_reproducible.SBOM_DIRECTORY
        fingerprint = fingerprint or build_reproducible.source_fingerprint(self.root)
        component_overrides = component_overrides or {}
        lines = []
        for name in build_reproducible.SBOM_FILES:
            path = directory / name
            component_names = component_overrides.get(
                name, build_reproducible.SBOM_REQUIRED_COMPONENTS[name]
            )
            path.write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "specVersion": "1.5",
                        "version": 1,
                        "metadata": {
                            "component": {
                                "type": "container",
                                "name": build_reproducible.SBOM_SUBJECTS[name],
                                "version": "sha256:" + "b" * 64,
                            },
                            "properties": [
                                {
                                    "name": build_reproducible.SBOM_SOURCE_FINGERPRINT_PROPERTY,
                                    "value": fingerprint,
                                },
                                {
                                    "name": build_reproducible.SBOM_IMAGE_ID_PROPERTY,
                                    "value": image_binding or "sha256:" + "b" * 64,
                                },
                            ],
                        },
                        "components": [
                            {"type": "library", "name": component_name}
                            for component_name in sorted(component_names)
                        ],
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {name}")
        (directory / "SHA256SUMS").write_text(
            "\n".join(lines) + "\n", encoding="ascii"
        )

    def _write_passing_evidence(self) -> None:
        fingerprint = build_reproducible.source_fingerprint(self.root)
        quick, soak, browser = passing_reports()
        for report in (quick, soak, browser):
            report["source"] = {"fingerprint_sha256": fingerprint}
        sources = {
            name: build_reproducible.QUALIFICATION_REPORTS[name].name
            for name in ("quick", "soak", "browser")
        }
        composed = compose_reports(quick, soak, browser, sources)
        for name, report in (
            ("quick", quick),
            ("soak", soak),
            ("browser", browser),
            ("composed", composed),
        ):
            self._write(name, report)

    def test_accepts_consistent_evidence_for_current_source(self) -> None:
        expected = build_reproducible.source_fingerprint(self.root)
        self.assertEqual(build_reproducible.validate_qualification(self.root), expected)

    def test_rejects_missing_and_stale_evidence(self) -> None:
        browser = self.root / build_reproducible.QUALIFICATION_REPORTS["browser"]
        browser.unlink()
        with self.assertRaisesRegex(FileNotFoundError, "browser-stream"):
            build_reproducible.validate_qualification(self.root)

        self._write_passing_evidence()
        (self.root / "frontend/App.tsx").write_text(
            "export const changed = true;\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(ValueError, "current source"):
            build_reproducible.validate_qualification(self.root)

    def test_rejects_inconsistent_composed_evidence(self) -> None:
        path = self.root / build_reproducible.QUALIFICATION_REPORTS["composed"]
        report = json.loads(path.read_text(encoding="utf-8"))
        report["gates"]["event_replay"] = {"passed": True, "altered": True}
        path.write_text(json.dumps(report), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "do not match"):
            build_reproducible.validate_qualification(self.root)

    def test_rejects_semantically_invalid_evidence_with_passing_flags(self) -> None:
        quick_path = self.root / build_reproducible.QUALIFICATION_REPORTS["quick"]
        composed_path = self.root / build_reproducible.QUALIFICATION_REPORTS["composed"]
        quick = json.loads(quick_path.read_text(encoding="utf-8"))
        composed = json.loads(composed_path.read_text(encoding="utf-8"))
        quick["gates"]["rest_mutations"]["primary_p95_ms"] = 251.0
        composed["gates"]["rest_mutations"] = quick["gates"]["rest_mutations"]
        quick_path.write_text(json.dumps(quick), encoding="utf-8")
        composed_path.write_text(json.dumps(composed), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "REST p95 exceeds threshold"):
            build_reproducible.validate_qualification(self.root)

    def test_frontend_qualification_change_invalidates_evidence(self) -> None:
        harness = self.root / "frontend/scripts/qualify-browser-stream.mjs"
        harness.write_text("// changed measurement harness\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "current source"):
            build_reproducible.validate_qualification(self.root)

    def test_packaged_frontend_asset_change_invalidates_evidence(self) -> None:
        asset = self.root / "frontend/product.png"
        asset.write_bytes(b"changed product asset")
        with self.assertRaisesRegex(ValueError, "current source"):
            build_reproducible.validate_qualification(self.root)

    def test_rejects_missing_or_checksum_mismatched_sbom(self) -> None:
        frontend = (
            self.root / build_reproducible.SBOM_DIRECTORY / "frontend.cdx.json"
        )
        frontend.unlink()
        with self.assertRaisesRegex(FileNotFoundError, "frontend.cdx.json"):
            build_reproducible.validate_sboms(self.root)

        self._write_sboms()
        frontend.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "populated CycloneDX|checksum"):
            build_reproducible.validate_sboms(self.root)

    def test_rejects_sbom_without_required_components_or_current_source_binding(self) -> None:
        self._write_sboms(
            component_overrides={"frontend.cdx.json": {"react"}}
        )
        with self.assertRaisesRegex(ValueError, "missing required components"):
            build_reproducible.validate_sboms(self.root)

        self._write_sboms(fingerprint="0" * 64)
        with self.assertRaisesRegex(ValueError, "source fingerprint is stale"):
            build_reproducible.validate_sboms(self.root)

        self._write_sboms(image_binding="sha256:" + "c" * 64)
        with self.assertRaisesRegex(ValueError, "image identity is invalid"):
            build_reproducible.validate_sboms(self.root)

    def test_rejects_ambiguous_duplicate_keys_in_evidence(self) -> None:
        quick = self.root / build_reproducible.QUALIFICATION_REPORTS["quick"]
        quick.write_text(
            '{"product_version":"0.3.0","product_version":"0.3.0"}\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "unambiguous JSON"):
            build_reproducible.validate_qualification(self.root)

    def test_archive_contains_all_reports_and_no_png(self) -> None:
        (self.root / "artifacts/v0.3/evidence.png").write_bytes(b"not an image")
        (self.root / "artifacts/v0.3/unapproved-debug.json").write_text(
            "{}\n", encoding="utf-8"
        )
        (self.root / "artifacts/sbom/scanner.log").write_text(
            "not release evidence\n", encoding="utf-8"
        )
        output = self.root / "release.tar.gz"
        build_reproducible.build(self.root, output)
        with tarfile.open(output, mode="r:gz") as archive:
            names = set(archive.getnames())
        for report in build_reproducible.QUALIFICATION_REPORTS.values():
            self.assertIn(report.as_posix(), names)
        self.assertNotIn("artifacts/v0.3/evidence.png", names)
        self.assertNotIn("artifacts/v0.3/unapproved-debug.json", names)
        self.assertNotIn("artifacts/sbom/scanner.log", names)
        self.assertIn("frontend/product.png", names)

    def test_archive_bytes_are_reproducible(self) -> None:
        first = self.root / "first.tar.gz"
        second = self.root / "second.tar.gz"
        self.assertEqual(
            build_reproducible.build(self.root, first),
            build_reproducible.build(self.root, second),
        )
        self.assertEqual(first.read_bytes(), second.read_bytes())


if __name__ == "__main__":
    unittest.main()
