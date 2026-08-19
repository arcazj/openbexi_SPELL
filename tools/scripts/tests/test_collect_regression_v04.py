from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts import collect_regression_v04 as regression


SOURCE = "a" * 64
LEGACY_SOURCE = "b" * 64


def _integrity(count: int) -> dict[str, object]:
    return {
        "exact": True,
        "received_count": count,
        "expected_count": count,
        "duplicate_count": 0,
        "missing_count": 0,
        "unexpected_count": 0,
    }


def _legacy_quick() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "product_version": "0.4.0",
        "profile": "quick",
        "overall_pass": True,
        "acceptance_complete": False,
        "source": {"fingerprint_sha256": LEGACY_SOURCE},
        "gates": {
            "rest_mutations": {
                "test_id": "V03-PERF-001",
                "passed": True,
                "primary_mutations": 100,
                "primary_p95_ms": 2.0,
                "idempotent_retries": 100,
                "status_codes": [202],
                "retry_status_codes": [202],
                "retry_identity_mismatches": 0,
                "unique_command_ids": 100,
                "stored_command_count": 100,
                "durable_command_states": {"completed": 100},
                "workers_drained": True,
            },
            "event_replay": {
                "test_id": "V03-PERF-002",
                "passed": True,
                "event_count": 10_000,
                "replay_seconds": 0.2,
                "payloads_exact": True,
                "sequence_integrity": _integrity(10_000),
            },
            "eventhub_fanout": {
                "test_id": "V03-PERF-003A",
                "passed": True,
                "target_events_per_second": 100.0,
                "target_duration_seconds": 60.0,
                "event_count_excluding_sentinel": 6_001,
                "production_elapsed_seconds": 60.0,
                "measured_duration_seconds": 60.0,
                "achieved_events_per_second": 100.0167,
                "schedule_p95_ms": 2.0,
                "schedule_max_ms": 5.0,
                "clients": 2,
                "producer_errors": [],
                "client_queue_overflowed": [False, False],
                "persisted_sequence_integrity": _integrity(6_002),
                "reader_results": [
                    {"error": None, "sequence_integrity": _integrity(6_002)},
                    {"error": None, "sequence_integrity": _integrity(6_002)},
                ],
            },
        },
    }


def _legacy_soak(duration: float = 600.0) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "product_version": "0.4.0",
        "profile": "soak",
        "overall_pass": True,
        "acceptance_complete": False,
        "source": {"fingerprint_sha256": LEGACY_SOURCE},
        "gates": {
            "soak": {
                "test_id": "V03-PERF-004",
                "passed": True,
                "target_events_per_second": 20.0,
                "target_duration_seconds": duration,
                "event_count": 12_001,
                "production_elapsed_seconds": 600.0,
                "measured_duration_seconds": 600.0,
                "achieved_events_per_second": 20.0017,
                "schedule_p95_ms": 2.0,
                "schedule_max_ms": 5.0,
                "producer_errors": [],
                "control_failures": [],
                "sequence_integrity": _integrity(12_001),
                "memory_measurement": {
                    "post_warmup_growth_mib": 1.0,
                    "post_warmup_slope_mib_per_minute": 0.1,
                },
            }
        },
    }


def _legacy_browser() -> dict[str, object]:
    reader = {
        "error": None,
        "sentinel_received": True,
        "data_event_count": 6_001,
        "subscription_ready_at_ms": 500.0,
        "first_data_at_ms": 1_000.0,
        "last_data_at_ms": 61_000.0,
        "sentinel_at_ms": 61_001.0,
        "delivery_elapsed_seconds": 60.0,
        "achieved_events_per_second": 100.0167,
        "sequence_integrity": _integrity(6_002),
    }
    return {
        "schema_version": "1.0",
        "product_version": "0.3.0",
        "profile": "browser-stream",
        "test_id": "V03-PERF-003",
        "passed": True,
        "overall_pass": True,
        "acceptance_complete": False,
        "source": {"fingerprint_sha256": LEGACY_SOURCE},
        "target_events_per_second": 100.0,
        "target_duration_seconds": 60.0,
        "event_count_excluding_sentinel": 6_001,
        "producer": {
            "state": "finished",
            "errors": [],
            "produced_event_count": 6_001,
            "production_elapsed_seconds": 60.0,
            "elapsed_seconds": 60.0,
            "achieved_events_per_second": 100.0167,
            "schedule_p95_ms": 2.0,
            "schedule_max_ms": 5.0,
            "persisted_sequence_integrity": _integrity(6_002),
        },
        "reader_results": [dict(reader), dict(reader)],
    }


def _fake_inventory() -> dict[str, object]:
    value: dict[str, object] = {
        "tag": regression.ACCEPTED_TAG,
        "commit": regression.ACCEPTED_COMMIT,
        "python": {
            "backend/tests/test_procedure_parser.py": [
                "backend/tests/test_procedure_parser.py::test_parser"
            ],
            "backend/tests/test_worker_expressions.py": [
                "backend/tests/test_worker_expressions.py::test_worker"
            ],
            "backend/tests/test_api_execution.py": [
                "backend/tests/test_api_execution.py::test_websocket",
                "backend/tests/test_api_execution.py::test_unsigned_identity",
                "backend/tests/test_api_execution.py::test_crash_recovery",
            ],
            "backend/tests/test_auth.py": [
                "backend/tests/test_auth.py::test_signature"
            ],
            "scripts/tests/test_release_script_contracts.py": [
                "scripts/tests/test_release_script_contracts.py::Contract::test_audit"
            ],
            "scripts/tests/test_build_reproducible.py": [
                "scripts/tests/test_build_reproducible.py::Build::test_sbom"
            ],
        },
        "frontend_unit": {"frontend/src/store.test.ts": ["keeps state"]},
        "browser": {
            "frontend/e2e/auth.spec.ts": ["requires access"],
            "frontend/e2e/console.spec.ts": ["shows console"],
            "frontend/e2e/integration.spec.ts": ["recovers workflow"],
        },
        "accessibility_files": [
            "frontend/e2e/auth.spec.ts",
            "frontend/e2e/console.spec.ts",
            "frontend/e2e/integration.spec.ts",
        ],
        "accessibility_analysis_counts": {
            "frontend/e2e/auth.spec.ts": 1,
            "frontend/e2e/console.spec.ts": 1,
            "frontend/e2e/integration.spec.ts": 1,
        },
        "defaults": {"SPELL_ALLOW_LOCAL_DEV_TOKEN": "Constant(value='false')"},
    }
    value["sha256"] = hashlib.sha256(regression._canonical_json(value)).hexdigest()
    return value


def _junit(nodes: list[str], *, skipped: set[str] | None = None) -> bytes:
    skipped = skipped or set()
    cases = []
    for node in nodes:
        parts = node.split("::")
        module = parts[0][:-3].replace("/", ".")
        classname = ".".join((module, *parts[1:-1]))
        child = '<skipped message="postgresql only" />' if node in skipped else ""
        cases.append(
            f'<testcase classname="{classname}" name="{parts[-1]}">{child}</testcase>'
        )
    return ("<testsuites><testsuite>" + "".join(cases) + "</testsuite></testsuites>").encode()


def _browser_junit(titles: list[str]) -> bytes:
    cases = "".join(
        f'<testcase classname="browser" name="{title}" />' for title in titles
    )
    return f"<testsuites><testsuite>{cases}</testsuite></testsuites>".encode()


@pytest.fixture
def accepted_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "source"
    defaults = [
        f'SPELL_FAKE_DEFAULT_{index:02d} = os.getenv("SPELL_FAKE_DEFAULT_{index:02d}", "value-{index:02d}")'
        for index in range(12)
    ]
    sources = {
        "backend/auth.py": "import os\n" + "\n".join(defaults[:6]) + "\n",
        "backend/config.py": "import os\n" + "\n".join(defaults[6:]) + "\n",
        "backend/tests/test_backend.py": "\n".join(
            f"def test_backend_{index:02d}():\n    pass\n" for index in range(72)
        ),
        "scripts/tests/test_tooling.py": "\n".join(
            f"def test_tooling_{index:02d}():\n    pass\n" for index in range(26)
        ),
        "frontend/src/store.test.ts": "\n".join(
            f'test("unit {index:02d}", () => {{}});' for index in range(13)
        ),
        "frontend/e2e/auth.spec.ts": (
            'import AxeBuilder from "@axe-core/playwright";\n'
            + "\n".join(
                f'test("auth {index:02d}", async () => {{ await new AxeBuilder().analyze(); }});'
                for index in range(3)
            )
        ),
        "frontend/e2e/console.spec.ts": (
            'import AxeBuilder from "@axe-core/playwright";\n'
            + "\n".join(
                f'test("console {index:02d}", async () => {{ await new AxeBuilder().analyze(); }});'
                for index in range(3)
            )
        ),
        "frontend/e2e/integration.spec.ts": (
            'import AxeBuilder from "@axe-core/playwright";\n'
            + "\n".join(
                f'test("integration {index:02d}", async () => {{ await new AxeBuilder().analyze(); }});'
                for index in range(2)
            )
        ),
    }
    for relative in ("backend/auth.py", "backend/config.py"):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(sources[relative], encoding="utf-8")

    listed_paths = sorted(
        relative
        for relative in sources
        if relative.startswith(("backend/tests/", "scripts/tests/", "frontend/src/", "frontend/e2e/"))
    )

    def fake_git(request_root: Path, *arguments: str) -> bytes:
        assert request_root == root
        if arguments == ("rev-parse", f"{regression.ACCEPTED_TAG}^{{commit}}"):
            return f"{regression.ACCEPTED_COMMIT}\n".encode("ascii")
        if arguments and arguments[0] == "ls-tree":
            return ("\n".join(listed_paths) + "\n").encode("utf-8")
        if len(arguments) == 2 and arguments[0] == "show":
            prefix = f"{regression.ACCEPTED_COMMIT}:"
            assert arguments[1].startswith(prefix)
            return sources[arguments[1][len(prefix) :]].encode("utf-8")
        raise AssertionError(f"unexpected fake Git arguments: {arguments!r}")

    monkeypatch.setattr(regression, "_git", fake_git)
    return root


def _write_full_capture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    inventory = _fake_inventory()
    monkeypatch.setattr(regression, "source_fingerprint_v04", lambda _: SOURCE)
    monkeypatch.setattr(regression, "source_fingerprint", lambda _: LEGACY_SOURCE)
    monkeypatch.setattr(regression, "accepted_inventory", lambda _: inventory)
    monkeypatch.setattr(regression, "changed_defaults", lambda _root, _inventory: [])
    for relative, count in inventory["accessibility_analysis_counts"].items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("AxeBuilder\n" + ".analyze()\n" * count, encoding="utf-8")
    capture = (
        tmp_path
        / "artifacts"
        / "v0.4"
        / ".qualification"
        / "runtime-captures"
        / SOURCE
        / "regression"
    )
    (capture / "logs").mkdir(parents=True)
    (capture / "screenshots").mkdir()
    (capture / "frontend-dist" / "assets").mkdir(parents=True)
    (capture / "frontend-dist" / "index.html").write_text("<main>SPELL</main>", encoding="utf-8")
    (capture / "frontend-dist" / "assets" / "app.js").write_text("export {};", encoding="utf-8")

    python = inventory["python"]
    backend_nodes = [
        node for path, nodes in python.items() if path.startswith("backend/") for node in nodes
    ]
    tooling_nodes = [
        node for path, nodes in python.items() if path.startswith("scripts/") for node in nodes
    ]
    (capture / "backend-sqlite.xml").write_bytes(_junit(backend_nodes))
    (capture / "backend-postgresql.xml").write_bytes(_junit(backend_nodes))
    (capture / "tooling.xml").write_bytes(_junit(tooling_nodes))
    (capture / "browser-mocked.xml").write_bytes(
        _browser_junit(["requires access", "shows console"])
    )
    (capture / "browser-real.xml").write_bytes(_browser_junit(["recovers workflow"]))
    (capture / "frontend-unit.json").write_text(
        json.dumps(
            {
                "success": True,
                "numFailedTestSuites": 0,
                "numFailedTests": 0,
                "numPendingTestSuites": 0,
                "numPendingTests": 0,
                "numTodoTests": 0,
                "numTotalTests": 1,
                "numPassedTests": 1,
                "testResults": [
                    {"assertionResults": [{"status": "passed", "title": "keeps state"}]}
                ],
            }
        ),
        encoding="utf-8",
    )
    for name, value in (
        ("legacy-quick.json", _legacy_quick()),
        ("legacy-soak.json", _legacy_soak()),
        ("legacy-browser-stream.json", _legacy_browser()),
    ):
        (capture / name).write_text(json.dumps(value), encoding="utf-8")

    png = b"\x89PNG\r\n\x1a\nsynthetic"
    screenshots = {}
    for name in regression.REQUIRED_SCREENSHOTS:
        path = capture / "screenshots" / name
        path.write_bytes(png)
        screenshots[name] = hashlib.sha256(png).hexdigest()

    commands = {}
    for command_id in regression.REQUIRED_COMMANDS:
        stdout = capture / "logs" / f"{command_id}.stdout.log"
        stderr = capture / "logs" / f"{command_id}.stderr.log"
        stdout.write_bytes(b"")
        stderr.write_bytes(b"")
        commands[command_id] = {
            "return_code": 0,
            "stdout_path": f"logs/{command_id}.stdout.log",
            "stdout_sha256": hashlib.sha256(b"").hexdigest(),
            "stderr_path": f"logs/{command_id}.stderr.log",
            "stderr_sha256": hashlib.sha256(b"").hexdigest(),
        }

    captures = {
        name: hashlib.sha256((capture / name).read_bytes()).hexdigest()
        for name in regression.REQUIRED_CAPTURES
    }
    build_count, build_sha = regression._tree_digest(capture / "frontend-dist")
    manifest = {
        "schema_version": regression.REPORT_SCHEMA,
        "product_version": regression.PRODUCT_VERSION,
        "scope_profile": regression.SCOPE_PROFILE,
        "source_fingerprint_before_sha256": SOURCE,
        "source_fingerprint_after_sha256": SOURCE,
        "qualification_image_id": "sha256:" + "c" * 64,
        "accepted_baseline": {
            "tag": regression.ACCEPTED_TAG,
            "commit": regression.ACCEPTED_COMMIT,
            "inventory_sha256": inventory["sha256"],
        },
        "runtime": {
            "qualification_python": "Python 3.13.5",
            "node": "v24.0.0",
            "playwright": "1.61.1",
            "chromium": "140.0",
            "docker_server_platform": "linux/amd64",
            "short_lived_browser_token_discarded": True,
            "isolated_runtime_resources_torn_down": True,
        },
        "commands": commands,
        "captures": captures,
        "screenshots": screenshots,
        "frontend_build": {"file_count": build_count, "sha256": build_sha},
        "proxy_artifact_validated": True,
    }
    (capture / "run.json").write_text(json.dumps(manifest), encoding="utf-8")
    return capture


def test_accepted_tag_inventory_is_complete_and_defaults_are_unchanged(
    accepted_tree: Path,
) -> None:
    inventory = regression.accepted_inventory(accepted_tree)
    assert inventory["commit"] == regression.ACCEPTED_COMMIT
    assert sum(len(nodes) for nodes in inventory["python"].values()) == 98
    assert sum(len(titles) for titles in inventory["frontend_unit"].values()) == 13
    assert sum(len(titles) for titles in inventory["browser"].values()) == 8
    assert len(inventory["defaults"]) == 12
    assert regression.changed_defaults(accepted_tree, inventory) == []


def test_full_source_bound_capture_emits_regression_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    capture = _write_full_capture(tmp_path, monkeypatch)
    result = regression.validate_capture(tmp_path, capture)
    assert result["test_id"] == "V04-REG-001"
    assert result["source_fingerprint_sha256"] == SOURCE
    assert result["metrics"]["v03_suite_count"] == len(regression.SUITE_NAMES)
    assert result["metrics"]["v03_suite_failure_count"] == 0
    assert result["metrics"]["v03_changed_default_count"] == 0


def test_capture_rejects_stale_source_and_forbidden_reference(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    capture = _write_full_capture(tmp_path, monkeypatch)
    manifest_path = capture / "run.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["source_fingerprint_after_sha256"] = "d" * 64
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(regression.RegressionCollectorError, match="source binding is stale"):
        regression.validate_capture(tmp_path, capture)

    manifest["source_fingerprint_after_sha256"] = SOURCE
    manifest["accepted_baseline"]["inventory_sha256"] = "d" * 64
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(regression.RegressionCollectorError, match="inventory binding differs"):
        regression.validate_capture(tmp_path, capture)

    manifest["accepted_baseline"]["inventory_sha256"] = _fake_inventory()["sha256"]
    manifest["runtime"]["node"] = "artifacts\\v0.3\\forbidden"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(regression.RegressionCollectorError, match="forbidden retained evidence"):
        regression.validate_capture(tmp_path, capture)


def test_incomplete_junit_and_short_soak_fail_closed(tmp_path: Path) -> None:
    node = "backend/tests/test_auth.py::test_signature"
    path = tmp_path / "suite.xml"
    path.write_bytes(_junit([]))
    with pytest.raises(regression.RegressionCollectorError, match="no testcases"):
        regression._load_junit(path, "suite")

    path.write_bytes(_junit([node], skipped={node}))
    cases = regression._load_junit(path, "suite")
    with pytest.raises(regression.RegressionCollectorError, match="skipped a required"):
        regression._validate_python_inventory(
            {"backend/tests/test_auth.py": [node]},
            cases,
            "suite",
            allow_postgresql_skip=True,
        )

    with pytest.raises(regression.RegressionCollectorError, match="soak target differs"):
        regression._validate_legacy_soak(_legacy_soak(599.0), LEGACY_SOURCE)


def test_default_inventory_detects_an_inherited_change(tmp_path: Path) -> None:
    backend = tmp_path / "backend"
    backend.mkdir()
    (backend / "auth.py").write_text(
        'import os\nvalue = os.getenv("SPELL_ALLOW_LOCAL_DEV_TOKEN", "true")\n',
        encoding="utf-8",
    )
    (backend / "config.py").write_text("", encoding="utf-8")
    inventory = {
        "defaults": {"SPELL_ALLOW_LOCAL_DEV_TOKEN": "Constant(value='false')"}
    }
    assert regression.changed_defaults(tmp_path, inventory) == [
        "SPELL_ALLOW_LOCAL_DEV_TOKEN"
    ]


def test_default_inventory_serializes_empty_ast_fields_explicitly() -> None:
    defaults = regression._getenv_defaults(
        "backend/config.py",
        'import os\nvalue = os.getenv("DATABASE_URL", factory())\n',
    )

    assert defaults == {
        "DATABASE_URL": "Call(func=Name(id='factory', ctx=Load()), args=[], keywords=[])"
    }


def test_legacy_screenshot_paths_are_overrideable_without_changing_defaults() -> None:
    root = Path(__file__).resolve().parents[2]
    auth = (root / "frontend/e2e/auth.spec.ts").read_text(encoding="utf-8")
    integration = (root / "frontend/e2e/integration.spec.ts").read_text(encoding="utf-8")
    config = (root / "frontend/playwright.config.ts").read_text(encoding="utf-8")
    orchestrator = (root / "scripts/qualify_regression_v04.ps1").read_text(encoding="utf-8")
    for source in (auth, integration):
        assert "SPELL_E2E_ARTIFACT_DIRECTORY" in source
        assert '?? "../artifacts/v0.3"' in source
    assert "SPELL_E2E_OUTPUT_DIRECTORY" in config
    assert "SPELL_E2E_PREVIEW_PORT" in config
    assert FORBIDDEN_LITERAL not in orchestrator.replace("\\", "/").lower()
    assert 'foreach ($profile in @("quick", "soak"))' in orchestrator
    assert '"--$profile"' in orchestrator
    assert "--soak-duration-seconds" not in orchestrator
    assert orchestrator.index("$composeStarted = $true") < orchestrator.index(
        'Invoke-RecordedCommand "postgres-prepare"'
    )
    assert '"down", "--rmi", "local", "-v", "--remove-orphans"' in orchestrator
    for query in (
        'containers = @("ps", "-aq"',
        'networks = @("network", "ls"',
        'volumes = @("volume", "ls"',
        'images = @("image", "ls"',
    ):
        assert query in orchestrator
    assert orchestrator.count('"label=com.docker.compose.project=$project"') == 4
    assert orchestrator.count('"com.docker.compose.project=$project"') >= 4
    assert "isolated_runtime_resources_torn_down = $resourcesTornDown" in orchestrator
    assert "docker volume create --label" in orchestrator
    assert "target=/qualification-output,readonly" in orchestrator
    assert 'Invoke-DockerCleanupCommand @("volume", "rm", "-f", $name)' in orchestrator
    assert '$ErrorActionPreference = "Continue"' in orchestrator
    assert "if ($inspection.ExitCode -eq 0)" in orchestrator


def test_recorded_regression_commands_do_not_fail_on_native_stderr_progress() -> None:
    root = Path(__file__).resolve().parents[2]
    orchestrator = (root / "scripts/qualify_regression_v04.ps1").read_text(
        encoding="utf-8"
    )
    start = orchestrator.index("function Invoke-RecordedCommand")
    end = orchestrator.index("function New-QualificationContainer")
    recorder = orchestrator[start:end]

    assert "$savedPreference = $ErrorActionPreference" in recorder
    assert '$ErrorActionPreference = "Continue"' in recorder
    assert "$ErrorActionPreference = $savedPreference" in recorder
    assert "& $Action 1> $stdoutPath 2> $stderrPath" in recorder


def test_legacy_v03_qualifier_does_not_create_the_app_during_spawn_import() -> None:
    root = Path(__file__).resolve().parents[2]
    qualifier = (root / "scripts/qualify_v03.py").read_text(encoding="utf-8")
    import_line = "from backend.app import create_app"
    main_guard = 'if __name__ == "__main__"'

    assert import_line in qualifier
    assert qualifier.index(import_line) > qualifier.index("def main(")
    assert qualifier.index(import_line) < qualifier.index(main_guard)


FORBIDDEN_LITERAL = "artifacts" + "/v0.3"
