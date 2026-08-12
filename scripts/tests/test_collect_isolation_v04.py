from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
COLLECTOR = ROOT / "scripts/collect_isolation_v04.ps1"


def _source() -> str:
    return COLLECTOR.read_text(encoding="utf-8")


def test_isolation_collector_is_source_and_exact_image_bound() -> None:
    source = _source()

    assert "ExpectedSourceFingerprint" in source
    assert "scripts/source_fingerprint_v04.py" in source
    assert source.count("containerSourceBefore") >= 2
    assert source.count("containerSourceAfter") >= 2
    assert "QualificationImageId" in source
    assert "DriverImageId" in source
    assert "PkiImageId" in source
    assert "runtime-created-from-exact-prebuilt-images" in source
    assert "docker build" not in source.lower()


def test_isolation_collector_proves_static_and_created_runtime_controls() -> None:
    source = _source()

    assert "test_compose_statically_isolates_and_hardens_the_driver" in source
    assert '"create", "--no-build", "--pull", "never"' in source
    assert '"up", "--detach", "--no-build", "--pull", "never", "--wait"' in source
    for runtime_field in (
        "ReadonlyRootfs",
        "CapDrop",
        "CapAdd",
        "SecurityOpt",
        "PidsLimit",
        "Memory",
        "NanoCpus",
        "StopTimeout",
        "Tmpfs",
        "PortBindings",
        "PublishAllPorts",
        "NetworkMode",
    ):
        assert runtime_field in source
    assert "runtime-single-internal-network-boundary" in source
    assert "runtime-filesystem-and-database-boundaries" in source


def test_isolation_collector_owns_and_verifies_only_exact_resources() -> None:
    source = _source()

    assert 'resourceLabelName = "spell.v04.isolation.run"' in source
    assert '"com.docker.compose.project=$($script:project)"' in source
    assert '"down", "--volumes", "--remove-orphans"' in source
    assert 'Get-MatchingIds $resource $label' in source
    assert 'if ($Resource -ceq "container") { $arguments += "--all" }' in source
    assert "exact-labelled-resource-and-process-cleanup-verified" in source
    assert "StartedUtcTicks" in source
    assert "$startedTicks -ne $identity.StartedUtcTicks" in source
    assert "Stop-Process -Name" not in source
    assert "Get-Process docker" not in source


def test_isolation_collector_emits_the_qualifier_contract_after_cleanup() -> None:
    source = _source()

    cleanup = source.index('Add-PassedAssertion "exact-labelled-resource-and-process-cleanup-verified"')
    result = source.index("$result = [ordered]@{")
    assert cleanup < result
    assert "test_id = $TestId" in source[result:]
    assert "source_fingerprint_sha256 = $ExpectedSourceFingerprint" in source[result:]
    assert "assertions = @($assertions)" in source[result:]
    assert "metrics = $metrics" in source[result:]
    assert "ConvertTo-Json -Compress -Depth 12" in source[result:]
