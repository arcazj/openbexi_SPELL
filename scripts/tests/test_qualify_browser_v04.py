from __future__ import annotations

import hashlib
import json
import re
import struct
from pathlib import Path

import pytest

from scripts import qualify_browser_v04 as browser
from scripts.qualify_browser_v04 import (
    BrowserQualificationError,
    EXPECTED_FIXTURE,
    FAULT_OBSERVATION_SCHEMA,
    OBSERVATION_SCHEMA,
    PROVENANCE_DIRECTORY,
    PROVENANCE_SCHEMA,
    STORAGE_PATH,
    TEST_IDS,
    load_fault_observations,
    load_observations,
    publish_browser_provenance_v04,
    result_for,
    validate_browser_provenance_v04,
    validate_observation_binding,
    write_storage_inventory,
)
from scripts.validate_release_evidence_v04 import SCOPE_PROFILE


SOURCE = "a" * 64
RUN_ID = "b" * 32


def _png(width: int, height: int) -> bytes:
    return b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + b"IHDR" + struct.pack(">II", width, height)


def _write_observation(root: Path, project: str, source: str = SOURCE) -> Path:
    viewport = {"width": 412, "height": 839} if project == "mobile" else {"width": 1280, "height": 720}
    screenshot = root / "artifacts" / "v0.4" / f"driver-projection-{project}.png"
    screenshot.parent.mkdir(parents=True, exist_ok=True)
    screenshot_bytes = _png(viewport["width"], viewport["height"])
    screenshot.write_bytes(screenshot_bytes)
    observation = {
        "schema_version": OBSERVATION_SCHEMA,
        "scope_profile": SCOPE_PROFILE,
        "run_id": RUN_ID,
        "source_fingerprint_sha256": source,
        "project": project,
        "source_test": "frontend/e2e/driver-projection-real.spec.ts",
        "runtime": {
            "node_version": "v24.13.0",
            "npm_version": "11.6.2",
            "node_executable_path": "C:/Program Files/nodejs/node.exe",
            "node_executable_sha256": "1" * 64,
            "playwright_version": "1.61.1",
            "browser_name": "chromium",
            "browser_version": "149.0.7827.55",
            "browser_executable_path": "C:/browser/chrome.exe",
            "browser_executable_sha256": "2" * 64,
            "project": "mobile" if project == "mobile" else "chromium",
            "command_profile": (
                "driver-projection-real:mobile"
                if project == "mobile"
                else "driver-projection-real:chromium"
            ),
            "stack_image_ids": {
                component: f"sha256:{str(index) * 64}"
                for index, component in enumerate(
                    ("backend", "driver", "pki_init", "postgres", "proxy", "qualification"),
                    start=1,
                )
            },
        },
        "fixture": EXPECTED_FIXTURE,
        "viewport": viewport,
        "accessibility": {
            "axe_critical_finding_count": 0,
            "axe_serious_finding_count": 0,
            "document_width": viewport["width"],
            "overflow_failure_count": 0,
            "viewport_width": viewport["width"],
        },
        "interaction": {"keyboard_failure_count": 0, "mutation_control_count": 0},
        "storage": {
            "inspected_key_count": 1,
            "inspected_value_count": 1,
            "service_secret_canary_match_count": 0,
            "removed_ephemeral_auth_token_count": 1,
            "local_storage": [],
            "session_storage": [],
        },
        "network": {
            "requests": [
                "http://127.0.0.1:18084/api/v1/drivers",
                "http://127.0.0.1:18084/api/v1/driver-contexts",
                "http://127.0.0.1:18084/api/v1/driver-bindings",
                "http://127.0.0.1:18084/api/v1/driver-operations/operation-1",
            ],
            "websockets": [
                "ws://127.0.0.1:18084/api/v1/driver-events/ws",
            ],
        },
        "screenshot": {
            "path": f"artifacts/v0.4/driver-projection-{project}.png",
            "sha256": hashlib.sha256(screenshot_bytes).hexdigest(),
        },
    }
    destination = root / "artifacts" / "v0.4" / "browser" / f"{project}.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(observation), encoding="utf-8")
    return destination


def _write_fault_observation(root: Path, project: str, source: str = SOURCE) -> Path:
    destination = root / "artifacts" / "v0.4" / "browser" / f"faults-{project}.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(
            {
                "schema_version": FAULT_OBSERVATION_SCHEMA,
                "scope_profile": SCOPE_PROFILE,
                "run_id": RUN_ID,
                "source_fingerprint_sha256": source,
                "project": project,
                "source_test": "frontend/e2e/driver-projection.spec.ts",
                "runtime": {
                    "node_version": "v24.13.0",
                    "npm_version": "11.6.2",
                    "node_executable_path": "C:/Program Files/nodejs/node.exe",
                    "node_executable_sha256": "1" * 64,
                    "playwright_version": "1.61.1",
                    "browser_name": "chromium",
                    "browser_version": "149.0.7827.55",
                    "browser_executable_path": "C:/browser/chrome.exe",
                    "browser_executable_sha256": "2" * 64,
                    "project": "mobile" if project == "mobile" else "chromium",
                    "command_profile": (
                        "driver-projection-fault:mobile"
                        if project == "mobile"
                        else "driver-projection-fault:chromium"
                    ),
                    "stack_image_ids": {
                        component: f"sha256:{str(index) * 64}"
                        for index, component in enumerate(
                            ("backend", "driver", "pki_init", "postgres", "proxy", "qualification"),
                            start=1,
                        )
                    },
                },
                "states": {
                    "degraded": True,
                    "disconnected": True,
                    "failed": True,
                    "stale": True,
                    "uncertain": True,
                    "unsupported": True,
                },
                "non_color_cue_count": 6,
                "mutation_control_count": 0,
            }
        ),
        encoding="utf-8",
    )
    return destination


def test_browser_observations_support_all_real_projection_collectors(tmp_path: Path) -> None:
    directory = tmp_path / "artifacts" / "v0.4" / "browser"
    for project in ("desktop", "mobile"):
        _write_observation(tmp_path, project)
        _write_fault_observation(tmp_path, project)

    observations = load_observations(tmp_path, directory, SOURCE)
    assert set(observations) == {"desktop", "mobile"}
    inventory_path = write_storage_inventory(tmp_path, SOURCE, observations)
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    assert inventory["source_fingerprint_sha256"] == SOURCE
    assert [item["project"] for item in inventory["projects"]] == ["desktop", "mobile"]
    fault_observations = load_fault_observations(directory, SOURCE)
    run_id, runtime, images = validate_observation_binding(observations, fault_observations)
    assert run_id == RUN_ID
    assert runtime["node_version"] == "v24.13.0"
    assert images["qualification"] == "sha256:" + "6" * 64
    for test_id in TEST_IDS:
        selected = fault_observations if test_id == "V04-UI-002" else observations
        result = result_for(test_id, SOURCE, selected)
        assert result["test_id"] == test_id
        assert result["source_fingerprint_sha256"] == SOURCE
        assert result["assertions"]
        assert all(item["passed"] is True for item in result["assertions"])
    assert result_for("V04-UI-003", SOURCE, observations)["metrics"] == {
        "desktop_viewport_count": 1,
        "mobile_viewport_count": 1,
        "screenshot_count": 2,
        "runtime_identity_count": 2,
        "stack_image_identity_count": 6,
        "axe_serious_finding_count": 0,
        "axe_critical_finding_count": 0,
        "keyboard_failure_count": 0,
        "overflow_failure_count": 0,
    }


@pytest.mark.parametrize(
    ("value", "expected"),
    (
        ("C:/Program Files/nodejs/node.exe", "C:/Program Files/nodejs/node.exe"),
        (r"C:\Program Files\nodejs\node.exe", "C:/Program Files/nodejs/node.exe"),
        ("/usr/bin/node", "/usr/bin/node"),
    ),
)
def test_absolute_runtime_paths_are_validated_independently_of_host_os(
    value: str,
    expected: str,
) -> None:
    assert browser._absolute_path(value, "runtime path") == expected


@pytest.mark.parametrize("value", ("node.exe", "tools/node.exe", "C:node.exe"))
def test_relative_runtime_paths_are_rejected(value: str) -> None:
    with pytest.raises(BrowserQualificationError, match="must be absolute"):
        browser._absolute_path(value, "runtime path")


def test_browser_observation_rejects_stale_or_non_loopback_evidence(tmp_path: Path) -> None:
    directory = tmp_path / "artifacts" / "v0.4" / "browser"
    desktop = _write_observation(tmp_path, "desktop")
    _write_observation(tmp_path, "mobile")

    with pytest.raises(BrowserQualificationError, match="fingerprint is stale"):
        load_observations(tmp_path, directory, "b" * 64)

    value = json.loads(desktop.read_text(encoding="utf-8"))
    value["network"]["requests"][0] = "https://example.com/api/v1/drivers"
    desktop.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(BrowserQualificationError, match="non-loopback"):
        load_observations(tmp_path, directory, SOURCE)


def test_browser_observation_requires_driver_websocket(tmp_path: Path) -> None:
    directory = tmp_path / "artifacts" / "v0.4" / "browser"
    desktop = _write_observation(tmp_path, "desktop")
    _write_observation(tmp_path, "mobile")

    value = json.loads(desktop.read_text(encoding="utf-8"))
    value["network"]["websockets"] = ["ws://127.0.0.1:18084/api/v1/ws"]
    desktop.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(BrowserQualificationError, match="driver downstream WebSocket"):
        load_observations(tmp_path, directory, SOURCE)


def test_browser_observation_rejects_mixed_run_and_tool_identity(tmp_path: Path) -> None:
    directory = tmp_path / "artifacts" / "v0.4" / "browser"
    for project in ("desktop", "mobile"):
        _write_observation(tmp_path, project)
        _write_fault_observation(tmp_path, project)
    desktop_fault = directory / "faults-desktop.json"
    value = json.loads(desktop_fault.read_text(encoding="utf-8"))
    value["run_id"] = "c" * 32
    desktop_fault.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(BrowserQualificationError, match="one run"):
        validate_observation_binding(
            load_observations(tmp_path, directory, SOURCE),
            load_fault_observations(directory, SOURCE),
        )

    value["run_id"] = RUN_ID
    value["runtime"]["browser_executable_sha256"] = "f" * 64
    desktop_fault.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(BrowserQualificationError, match="one tool identity"):
        validate_observation_binding(
            load_observations(tmp_path, directory, SOURCE),
            load_fault_observations(directory, SOURCE),
        )


def _prepare_publish_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    for relative in ("compose.yaml", "frontend/package-lock.json", "frontend/playwright.config.ts"):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"synthetic {relative}\n", encoding="utf-8")
    for project in ("desktop", "mobile"):
        _write_observation(tmp_path, project)
        _write_fault_observation(tmp_path, project)
        screenshot = tmp_path / "artifacts" / "v0.4" / f"driver-projection-{project}.png"
        (tmp_path / "artifacts" / "v0.4" / "browser" / screenshot.name).write_bytes(
            screenshot.read_bytes()
        )
        screenshot.unlink()

    program_files = tmp_path / "Program Files"
    local_app_data = tmp_path / "LocalAppData"
    monkeypatch.setenv("ProgramFiles", str(program_files))
    monkeypatch.setenv("LocalAppData", str(local_app_data))
    tool_inputs = {
        "docker_cli": (program_files, "Docker/Docker/resources/bin/docker.exe", b"docker-cli"),
        "docker_compose": (
            program_files,
            "Docker/Docker/resources/cli-plugins/docker-compose.exe",
            b"docker-compose",
        ),
        "python": (
            local_app_data,
            "OpenBEXI/release-toolchain/python-3.13.14-embed-amd64/python.exe",
            b"python",
        ),
    }
    executable_paths: dict[str, Path] = {}
    tools: list[dict[str, str]] = []
    for key, (base, relative, data) in tool_inputs.items():
        path = base.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        executable_paths[key] = path
        entry: dict[str, str] = {
            "name": {"docker_cli": "docker-cli", "docker_compose": "docker-compose"}.get(key, key),
            "base_directory": "ProgramFiles" if base == program_files else "LocalAppData",
            "relative_path": relative,
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        if key == "python":
            entry.update(
                {
                    "archive_relative_path": "OpenBEXI/release-toolchain/python.zip",
                    "archive_sha256": "9" * 64,
                    "archive_url": "https://example.invalid/python.zip",
                }
            )
        tools.append(entry)
    lock = {
        "schema_version": "spell.v04.release-toolchain/1",
        "host_platform": "windows-amd64-docker-desktop",
        "tools": tools,
        "versions": {
            "docker_cli": "29.7.2",
            "docker_compose": "v5.3.1",
            "host_python": "3.13.14",
        },
    }
    lock_path = tmp_path / "scripts" / "release-toolchain-v04.json"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    monkeypatch.setattr(browser, "source_fingerprint_v04", lambda _: SOURCE)
    return executable_paths


def _publish(tmp_path: Path, executable_paths: dict[str, Path], *, replace: bool = False) -> dict[str, object]:
    return publish_browser_provenance_v04(
        tmp_path,
        tmp_path / "artifacts" / "v0.4" / "browser",
        run_id=RUN_ID,
        started_at_utc="2026-07-19T12:00:00.000Z",
        finished_at_utc="2026-07-19T12:01:00.000Z",
        executable_paths=executable_paths,
        replace=replace,
    )


def test_browser_provenance_publication_is_exact_and_tamper_evident(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable_paths = _prepare_publish_root(tmp_path, monkeypatch)
    binding = _publish(tmp_path, executable_paths)
    assert binding["browser_provenance_schema_version"] == PROVENANCE_SCHEMA
    assert binding["browser_run_id"] == RUN_ID
    assert {path.name for path in (tmp_path / PROVENANCE_DIRECTORY).iterdir()} == {
        "desktop.json",
        "faults-desktop.json",
        "faults-mobile.json",
        "manifest.json",
        "mobile.json",
    }
    assert validate_browser_provenance_v04(tmp_path, SOURCE) == binding
    result = result_for(
        "V04-UI-001",
        SOURCE,
        load_observations(tmp_path, tmp_path / PROVENANCE_DIRECTORY, SOURCE),
        binding,
    )
    assert result["metrics"]["browser_manifest_sha256"] == binding["browser_manifest_sha256"]

    desktop = tmp_path / PROVENANCE_DIRECTORY / "desktop.json"
    original = desktop.read_bytes()
    desktop.write_bytes(original + b" ")
    with pytest.raises(BrowserQualificationError, match="artifact manifest differs"):
        validate_browser_provenance_v04(tmp_path, SOURCE)
    desktop.write_bytes(original)
    extra = tmp_path / PROVENANCE_DIRECTORY / "extra.json"
    extra.write_text("{}\n", encoding="utf-8")
    with pytest.raises(BrowserQualificationError, match="exact file set"):
        validate_browser_provenance_v04(tmp_path, SOURCE)


def test_browser_provenance_replace_rolls_back_both_destinations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable_paths = _prepare_publish_root(tmp_path, monkeypatch)
    _publish(tmp_path, executable_paths)
    provenance_before = {
        path.name: path.read_bytes() for path in (tmp_path / PROVENANCE_DIRECTORY).iterdir()
    }
    storage_before = (tmp_path / STORAGE_PATH).read_bytes()
    screenshots_before = {
        project: (tmp_path / "artifacts" / "v0.4" / f"driver-projection-{project}.png").read_bytes()
        for project in ("desktop", "mobile")
    }

    monkeypatch.setattr(
        browser,
        "validate_browser_provenance_v04",
        lambda *_: (_ for _ in ()).throw(BrowserQualificationError("forced validation failure")),
    )
    with pytest.raises(BrowserQualificationError, match="forced validation failure"):
        _publish(tmp_path, executable_paths, replace=True)
    assert {
        path.name: path.read_bytes() for path in (tmp_path / PROVENANCE_DIRECTORY).iterdir()
    } == provenance_before
    assert (tmp_path / STORAGE_PATH).read_bytes() == storage_before
    assert {
        project: (tmp_path / "artifacts" / "v0.4" / f"driver-projection-{project}.png").read_bytes()
        for project in ("desktop", "mobile")
    } == screenshots_before


def test_real_browser_runner_tears_down_partial_compose_start_and_restores_state() -> None:
    root = Path(__file__).resolve().parents[2]
    runner = (root / "scripts/qualify_browser_real_v04.ps1").read_text(encoding="utf-8")

    touched = runner.index("$composeTouched = $true")
    compose_up = runner.index("up -d --build --wait")
    captured_failure = runner.index("$failure = $_")
    cleanup_guard = runner.index(
        "if (-not $runtimeCleanupComplete -and $composeTouched -and $script:BrowserComposeExecutable)"
    )
    compose_down = runner.index(
        '"down", "--rmi", "local", "-v", "--remove-orphans"', cleanup_guard
    )
    qualification_remove = runner.index(
        'Invoke-DockerCleanupCommand @("image", "rm", $qualificationTag)', cleanup_guard
    )
    residual_check = runner.index("try { Assert-NoProjectResources }")
    restore_environment = runner.index('foreach ($name in $environmentNames)', cleanup_guard)
    restore_location = runner.index("Pop-Location", restore_environment)
    combined_failure = runner.index('"$($failure.Exception.Message); $cleanupMessage"')
    deferred_throw = runner.index("if ($failure) { throw $failure }")
    deferred_output = runner.index("Write-Output $resultJson")

    assert touched < compose_up < captured_failure < cleanup_guard
    assert "if ($started)" not in runner
    assert "Write-Error \"browser qualification Compose teardown failed\"" not in runner
    assert cleanup_guard < compose_down < qualification_remove < residual_check
    assert residual_check < restore_environment < restore_location < combined_failure
    assert combined_failure < deferred_throw < deferred_output
    assert '$ErrorActionPreference = "Continue"' in runner
    assert '--label "com.docker.compose.project=$project"' in runner
    assert 'images = @("image", "ls", "-q"' in runner
    assert '"image", "inspect", $qualificationTag' in runner
    toolchain_assertion = runner.index('assert_release_toolchain_v04.ps1')
    locked_build = runner.index('& $script:BrowserDockerExecutable build')
    locked_compose = runner.index('& $script:BrowserComposeExecutable -p $project', locked_build)
    capture_binding = runner.index('$env:SPELL_BROWSER_CAPTURE_DIRECTORY = $captureDirectory')
    publication = runner.index('--publish-provenance')
    result_assembly = runner.index('$resultJson = [ordered]@{')
    assert toolchain_assertion < locked_build < locked_compose
    assert capture_binding < compose_up < publication < result_assembly
    assert "docker compose" not in runner
    assert re.search(r"(?m)^\s*docker\s", runner) is None
    assert '--docker-executable $script:BrowserDockerExecutable' in runner
    assert '--compose-executable $script:BrowserComposeExecutable' in runner
    assert '--python-executable $PythonExecutable' in runner
    assert runner.index("$runtimeCleanupComplete = $true") < publication
