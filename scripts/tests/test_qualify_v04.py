from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

from scripts import qualify_v04
from scripts.validate_release_evidence_v04 import EXPECTED_TEST_IDS, GATE_TEST_IDS


SOURCE = "a" * 64


def _python_json_command(payload: dict[str, object], return_code: int = 0) -> tuple[str, ...]:
    program = (
        "import json,sys; "
        f"print(json.dumps({payload!r}, sort_keys=True)); "
        f"raise SystemExit({return_code})"
    )
    return (sys.executable, "-c", program)


def _perf_001_payload(**overrides: object) -> dict[str, object]:
    metrics: dict[str, object] = {
        "sample_count": 1_000,
        "duration_seconds": 10.0,
        "achieved_rate_per_second": 100.0,
        "p95_ms": 40.0,
        "max_ms": 100.0,
        "error_count": 0,
    }
    metrics.update(overrides)
    return {
        "test_id": "V04-PERF-001",
        "source_fingerprint_sha256": SOURCE,
        "assertions": [{"id": "measured-health-budget", "passed": True}],
        "metrics": metrics,
    }


def _linux_process_state(pid: int) -> str | None:
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except (FileNotFoundError, OSError):
        return None
    closing_parenthesis = stat.rfind(")")
    fields = stat[closing_parenthesis + 2 :].split() if closing_parenthesis >= 0 else []
    return fields[0] if fields else None


def _process_is_running(pid: int) -> bool:
    if os.name == "nt":
        result = subprocess.run(
            ("tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
        )
        return result.returncode == 0 and f'"{pid}"' in result.stdout
    if sys.platform.startswith("linux"):
        state = _linux_process_state(pid)
        return state is not None and state != "Z"
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _force_stop_test_process(pid: int) -> None:
    if not _process_is_running(pid):
        return
    if os.name == "nt":
        subprocess.run(
            ("taskkill", "/PID", str(pid), "/T", "/F"),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    else:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def _wait_until_not_running(pid: int, timeout_seconds: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    while _process_is_running(pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not _process_is_running(pid)


def test_recipe_catalog_covers_exact_gate_allocation() -> None:
    assert set(qualify_v04.RECIPES) == set(EXPECTED_TEST_IDS)
    assert len(qualify_v04.RECIPES) == 74
    assert set().union(*GATE_TEST_IDS.values()) == set(EXPECTED_TEST_IDS)
    plan = qualify_v04._plan()
    planned_ids = {
        entry["test_id"]
        for entries in plan["gates"].values()
        for entry in entries
    }
    assert planned_ids == set(EXPECTED_TEST_IDS)
    assert plan["collector_required_count"] > 0


def test_timed_out_command_terminates_its_child_process_tree(tmp_path: Path) -> None:
    child_pid_path = tmp_path / "child.pid"
    parent_program = (
        "import pathlib,subprocess,sys,time; "
        "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
        "pathlib.Path(sys.argv[1]).write_text(str(child.pid),encoding='ascii'); "
        "time.sleep(60)"
    )

    with pytest.raises(qualify_v04.QualificationError, match="command timed out"):
        qualify_v04._run_command(
            (sys.executable, "-c", parent_program, str(child_pid_path)),
            tmp_path,
            2.0,
        )

    assert child_pid_path.is_file()
    child_pid = int(child_pid_path.read_text(encoding="ascii"))
    try:
        _wait_until_not_running(child_pid)
    finally:
        _force_stop_test_process(child_pid)


def test_completed_command_terminates_its_background_child(tmp_path: Path) -> None:
    child_pid_path = tmp_path / "background-child.pid"
    parent_program = (
        "import pathlib,subprocess,sys; "
        "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],"
        "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
        "pathlib.Path(sys.argv[1]).write_text(str(child.pid),encoding='ascii')"
    )

    result, _, _ = qualify_v04._run_command(
        (sys.executable, "-c", parent_program, str(child_pid_path)),
        tmp_path,
        10.0,
    )

    assert result.returncode == 0
    assert child_pid_path.is_file()
    child_pid = int(child_pid_path.read_text(encoding="ascii"))
    try:
        _wait_until_not_running(child_pid)
    finally:
        _force_stop_test_process(child_pid)


@pytest.mark.skipif(os.name == "nt", reason="exercises POSIX process-group cleanup")
def test_posix_cleanup_kills_group_after_its_leader_has_exited(tmp_path: Path) -> None:
    child_pid_path = tmp_path / "orphaned-group-child.pid"
    parent_program = (
        "import pathlib,subprocess,sys; "
        "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
        "pathlib.Path(sys.argv[1]).write_text(str(child.pid),encoding='ascii')"
    )
    process = subprocess.Popen(
        (sys.executable, "-c", parent_program, str(child_pid_path)),
        cwd=tmp_path,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    assert process.wait(timeout=5.0) == 0
    child_pid = int(child_pid_path.read_text(encoding="ascii"))
    try:
        assert _process_is_running(child_pid)
        qualify_v04._terminate_process_tree(process)
        _wait_until_not_running(child_pid)
    finally:
        _force_stop_test_process(child_pid)


def test_timeout_cleanup_does_not_terminate_an_unrelated_process(tmp_path: Path) -> None:
    sentinel_kwargs: dict[str, object] = {}
    if os.name == "nt":
        sentinel_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        sentinel_kwargs["start_new_session"] = True
    sentinel = subprocess.Popen(
        (sys.executable, "-c", "import time; time.sleep(60)"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        **sentinel_kwargs,
    )
    try:
        with pytest.raises(qualify_v04.QualificationError, match="command timed out"):
            qualify_v04._run_command(
                (sys.executable, "-c", "import time; time.sleep(60)"),
                tmp_path,
                0.2,
            )
        assert sentinel.poll() is None
    finally:
        _force_stop_test_process(sentinel.pid)
        sentinel.wait(timeout=5.0)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="requires Linux procfs")
def test_linux_process_group_verification_ignores_zombies_but_detects_live_members() -> None:
    live = subprocess.Popen(
        (sys.executable, "-c", "import time; time.sleep(60)"),
        start_new_session=True,
    )
    try:
        assert qualify_v04._posix_process_group_has_live_members(live.pid)
        assert _process_is_running(live.pid)
    finally:
        _force_stop_test_process(live.pid)
        live.wait(timeout=5.0)

    zombie = subprocess.Popen(
        (sys.executable, "-c", "pass"),
        start_new_session=True,
    )
    try:
        deadline = time.monotonic() + 5.0
        while _linux_process_state(zombie.pid) != "Z" and time.monotonic() < deadline:
            time.sleep(0.05)
        assert _linux_process_state(zombie.pid) == "Z"
        assert not qualify_v04._posix_process_group_has_live_members(zombie.pid)
        assert not _process_is_running(zombie.pid)
    finally:
        zombie.wait(timeout=5.0)


def test_structured_collector_records_only_a_real_source_bound_pass(tmp_path: Path) -> None:
    command = qualify_v04.CommandSpec(
        _python_json_command(_perf_001_payload()),
        "collector-passed",
        structured=True,
    )
    with mock.patch.object(qualify_v04, "source_fingerprint_v04", return_value=SOURCE):
        path = qualify_v04.execute_test(
            tmp_path,
            "V04-PERF-001",
            (command,),
            timeout_seconds=10.0,
            replace=False,
        )

    evidence = json.loads(path.read_text(encoding="utf-8"))
    assert evidence["executed"] is True
    assert evidence["passed"] is True
    assert evidence["source"]["fingerprint_sha256"] == SOURCE
    assert evidence["commands"][0]["return_code"] == 0
    assert evidence["commands"][0]["stdout_sha256"] != "0" * 64
    assert evidence["metrics"]["sample_count"] == 1_000


@pytest.mark.parametrize(
    ("payload", "return_code", "message"),
    [
        (_perf_001_payload(), 7, "failed rc=7"),
        (
            {**_perf_001_payload(), "source_fingerprint_sha256": "b" * 64},
            0,
            "stale source fingerprint",
        ),
        (_perf_001_payload(p95_ms=50.1), 0, "exceeds 50 ms"),
        (
            {**_perf_001_payload(), "assertions": [{"id": "budget", "passed": False}]},
            0,
            "did not pass",
        ),
    ],
)
def test_failed_stale_or_semantically_invalid_collector_emits_nothing(
    tmp_path: Path,
    payload: dict[str, object],
    return_code: int,
    message: str,
) -> None:
    command = qualify_v04.CommandSpec(
        _python_json_command(payload, return_code),
        "collector-passed",
        structured=True,
    )
    with mock.patch.object(qualify_v04, "source_fingerprint_v04", return_value=SOURCE):
        with pytest.raises(qualify_v04.QualificationError, match=message):
            qualify_v04.execute_test(
                tmp_path,
                "V04-PERF-001",
                (command,),
                timeout_seconds=10.0,
                replace=False,
            )
    assert not qualify_v04._record_path(tmp_path, SOURCE, "V04-PERF-001").exists()


def test_targeted_pytest_skip_is_not_accepted_as_a_pass(tmp_path: Path) -> None:
    command = qualify_v04.CommandSpec(
        (sys.executable, "-c", "print('1 passed, 1 skipped in 0.01s')"),
        "pytest-passed",
        require_pytest_pass=True,
    )
    with mock.patch.object(qualify_v04, "source_fingerprint_v04", return_value=SOURCE):
        with pytest.raises(qualify_v04.QualificationError, match="passed=1 skipped=1"):
            qualify_v04.execute_test(
                tmp_path,
                "V04-DOC-001",
                (command,),
                timeout_seconds=10.0,
                replace=False,
            )
    assert not qualify_v04._record_path(tmp_path, SOURCE, "V04-DOC-001").exists()


def test_collector_argv_rejects_credential_like_material() -> None:
    with pytest.raises(qualify_v04.QualificationError, match="credential-like"):
        qualify_v04._safe_argv(("tool", "--token=not-for-evidence"))


def test_collector_map_is_typed_and_rejects_unknown_ids(tmp_path: Path) -> None:
    path = tmp_path / "collectors.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": qualify_v04.COLLECTOR_MAP_SCHEMA_VERSION,
                "collectors": {"V04-PERF-001": ["harness", "--json"]},
            }
        ),
        encoding="utf-8",
    )
    assert qualify_v04._load_collector_map(path) == {
        "V04-PERF-001": ("harness", "--json")
    }

    path.write_text(
        json.dumps(
            {
                "schema_version": qualify_v04.COLLECTOR_MAP_SCHEMA_VERSION,
                "collectors": {"V04-NOT-REAL": ["harness"]},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(qualify_v04.QualificationError, match="unknown ID"):
        qualify_v04._load_collector_map(path)

    path.write_text(
        '{"schema_version":"spell.v04.collector-map/1",'
        '"schema_version":"spell.v04.collector-map/1","collectors":{}}',
        encoding="utf-8",
    )
    with pytest.raises(qualify_v04.QualificationError, match="duplicate object key"):
        qualify_v04._load_collector_map(path)


def test_publish_fails_closed_when_any_of_74_records_is_missing(tmp_path: Path) -> None:
    with mock.patch.object(qualify_v04, "source_fingerprint_v04", return_value=SOURCE):
        with pytest.raises(qualify_v04.QualificationError, match="incomplete staged evidence"):
            qualify_v04.publish(tmp_path, replace=False)
    assert not (tmp_path / qualify_v04.TEST_EVIDENCE_DIRECTORY).exists()


def test_gate_report_binds_exact_record_bytes_and_assertion_count() -> None:
    gate_id = "V04-GATE-4"
    records: dict[str, dict[str, object]] = {}
    evidence_bytes: dict[str, bytes] = {}
    for test_id in GATE_TEST_IDS[gate_id]:
        records[test_id] = {
            "assertions": [
                {"id": f"{test_id}-one", "passed": True},
                {"id": f"{test_id}-two", "passed": True},
            ],
            "metrics": {},
        }
        evidence_bytes[test_id] = f"evidence:{test_id}\n".encode("ascii")
    report = qualify_v04._gate_report(gate_id, SOURCE, evidence_bytes, records)
    assert {item["test_id"] for item in report["tests"]} == set(GATE_TEST_IDS[gate_id])
    assert all(item["assertions"]["total"] == 2 for item in report["tests"])
    assert all(len(item["evidence_sha256"]) == 64 for item in report["tests"])
    assert report["overall_pass"] is True
    assert report["acceptance_complete"] is False


def test_run_reports_missing_environment_collector_as_a_blocker(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    result = qualify_v04.main(
        [
            "--root",
            str(tmp_path),
            "run",
            "--test-id",
            "V04-PERF-004",
        ]
    )
    output = json.loads(capsys.readouterr().out)
    assert result == 2
    assert output["staged_test_ids"] == []
    assert "V04-PERF-004" in output["blocked"]


def test_collector_map_can_replace_a_builtin_for_a_composed_environment(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    collector_map = tmp_path / "collectors.json"
    collector_map.write_text(
        json.dumps(
            {
                "schema_version": qualify_v04.COLLECTOR_MAP_SCHEMA_VERSION,
                "collectors": {"V04-DOC-001": ["composed-harness", "--json"]},
            }
        ),
        encoding="utf-8",
    )
    with mock.patch.object(qualify_v04, "execute_test") as execute:
        result = qualify_v04.main(
            [
                "--root",
                str(tmp_path),
                "run",
                "--test-id",
                "V04-DOC-001",
                "--collector-map",
                str(collector_map),
            ]
        )
    output = json.loads(capsys.readouterr().out)
    assert result == 0
    assert output["staged_test_ids"] == ["V04-DOC-001"]
    specs = execute.call_args.args[2]
    assert specs[0].argv == ("composed-harness", "--json")
    assert specs[0].structured is True
