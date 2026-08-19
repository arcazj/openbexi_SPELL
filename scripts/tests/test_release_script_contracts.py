from __future__ import annotations

import unittest
from pathlib import Path


class ReleaseScriptContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(__file__).resolve().parents[2]

    def test_gate_invalidates_canonical_outputs_before_building(self) -> None:
        script = (self.root / "scripts/build_v03.ps1").read_text(encoding="utf-8")
        invalidation = script.index(
            "Remove-CanonicalReleaseOutputs"
        )
        preflight = script.index('foreach ($command in @("docker", "node", "npm", "npx"))')
        first_build = script.index("docker compose build --pull=false")
        self.assertLess(invalidation, preflight)
        self.assertLess(invalidation, first_build)
        self.assertIn(
            "Remove-Item -LiteralPath $canonicalOutput -Force",
            script[invalidation:first_build],
        )
        self.assertIn("$releasePublished = $true", script)
        self.assertLess(
            script.index("Move-Item -Force $temporarySidecar $releaseSidecar"),
            script.index("$releasePublished = $true"),
        )
        self.assertIn(
            "if (-not $releasePublished) {\n    Remove-CanonicalReleaseOutputs",
            script,
        )
        self.assertIn(
            "GetDirectoryName($canonicalOutputFull) -cne $artifactDirectoryFull",
            script[invalidation:first_build],
        )

    def test_qualification_publishes_only_after_complete_staging(self) -> None:
        script = (self.root / "scripts/qualify_release.ps1").read_text(
            encoding="utf-8"
        )
        staging = script.index(".qualification-staging-$stageId")
        composition = script.index("Qualification evidence composition failed")
        source_check = script.index(
            "Source changed while qualification evidence was being measured"
        )
        publication = script.index(
            "Move-Item -LiteralPath (Join-Path $staging $name)"
        )
        self.assertLess(staging, composition)
        self.assertLess(composition, source_check)
        self.assertLess(source_check, publication)
        self.assertIn("Restore-PreviousEvidence", script[publication:])
        self.assertEqual(script.count("Restore-PreviousEvidence"), 2)
        self.assertIn("$backupComplete = $false", script)
        self.assertIn("$backupComplete = $true", script)
        self.assertIn("$publicationStarted = $true", script)
        self.assertIn("$publicationComplete = $true", script)
        self.assertIn(
            "if ($backupComplete -and $publicationStarted -and -not $publicationComplete)",
            script[publication:],
        )
        self.assertIn("Copy-Item -LiteralPath $published", script)
        self.assertIn("Remove-Item -LiteralPath $staging -Recurse -Force", script)

    def test_release_scripts_do_not_use_host_bind_mounts(self) -> None:
        for name in (
            "audit_supply_chain.ps1",
            "generate_sbom.ps1",
            "qualify_release.ps1",
            "qualify_browser_stream.ps1",
        ):
            script = (self.root / "scripts" / name).read_text(encoding="utf-8")
            self.assertNotIn(' -v "', script, name)
            self.assertNotIn("--mount", script, name)
            self.assertNotIn("type=bind", script, name)

    def test_release_images_are_consumed_by_captured_id(self) -> None:
        gate = (self.root / "scripts/build_v03.ps1").read_text(encoding="utf-8")
        self.assertIn('"openbexi_spell-package-input:$packageRunId"', gate)
        self.assertIn(
            'docker image inspect $packageInputTag --format "{{.Id}}"', gate
        )
        self.assertNotIn("docker run --rm --network none --entrypoint python $packageInputTag", gate)
        self.assertIn("openbexi_spell-package-current-input:$packageRunId", gate)
        self.assertIn(
            "Package input changed while release artifacts were being built", gate
        )

        sbom = (self.root / "scripts/generate_sbom.ps1").read_text(encoding="utf-8")
        self.assertIn("openbexi_spell-backend-sbom-input:$stageId", sbom)
        self.assertIn("docker sbom $entry.Value.Image", sbom)
        self.assertIn("openbexi:scanned-image-id", sbom)
        self.assertEqual(sbom.count("--provenance=false"), 3)
        self.assertIn(
            '$normalized.Replace("`r`n", "`n").Replace("`r", "`n")', sbom
        )

    def test_qualification_image_uses_pinned_independent_base(self) -> None:
        dockerfile = (self.root / "scripts/qualification.Dockerfile").read_text(
            encoding="utf-8"
        )
        self.assertIn("FROM python:3.13-slim@sha256:", dockerfile)
        self.assertNotIn("FROM openbexi_spell-backend", dockerfile)
        self.assertIn("pip install --require-hashes", dockerfile)

    def test_browser_production_waits_for_server_subscription_readiness(self) -> None:
        harness = (
            self.root / "frontend/scripts/qualify-browser-stream.mjs"
        ).read_text(encoding="utf-8")
        keepalive = harness.index('message.event_type === "stream.keepalive"')
        readiness = harness.index("subscriptionsReady.every(Boolean)")
        production = harness.index('fetch(`${baseUrl}/qualification/start`')
        self.assertLess(keepalive, readiness)
        self.assertLess(readiness, production)
        self.assertIn("subscription_ready_at_ms", harness)


if __name__ == "__main__":
    unittest.main()
