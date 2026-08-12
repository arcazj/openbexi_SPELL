#!/usr/bin/env python3
"""Validate and emit the source-bound V04-REG-001 regression result.

The live orchestrator writes raw results beneath the v0.4 qualification capture
root. This collector independently inventories the accepted v0.3 tag, validates
every raw result, and emits only the small structured payload consumed by the
v0.4 qualification runner.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import inspect
import json
import math
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Sequence


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.source_fingerprint import source_fingerprint
from scripts.source_fingerprint_v04 import source_fingerprint_v04


REPORT_SCHEMA = "spell.v04.regression-run/1"
PRODUCT_VERSION = "0.4.0"
SCOPE_PROFILE = "LOCAL_SYNTHETIC_NON_CUI_SIMULATOR"
ACCEPTED_TAG = "v0.3.0"
ACCEPTED_COMMIT = "7bccbb4eb096b22d0d1f2f765d5172f6dde244f1"
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_XML_BYTES = 32 * 1024 * 1024
MAX_GIT_BLOB_BYTES = 4 * 1024 * 1024
MAX_LOG_BYTES = 32 * 1024 * 1024
MAX_SCREENSHOT_BYTES = 16 * 1024 * 1024
MAX_BUILD_FILE_BYTES = 64 * 1024 * 1024
MAX_BUILD_BYTES = 512 * 1024 * 1024
SHA256_RE = re.compile(r"[0-9a-f]{64}")
IMAGE_ID_RE = re.compile(r"sha256:[0-9a-f]{64}")
FORBIDDEN_EVIDENCE_FRAGMENT = "artifacts" + "/v0.3"

REQUIRED_CAPTURES = {
    "backend-sqlite.xml",
    "backend-postgresql.xml",
    "tooling.xml",
    "frontend-unit.json",
    "browser-mocked.xml",
    "browser-real.xml",
    "legacy-quick.json",
    "legacy-soak.json",
    "legacy-browser-stream.json",
}
REQUIRED_SCREENSHOTS = {
    "desktop-as-run-report.png",
    "desktop-v03-validation.png",
    "mobile-recovered-prompt.png",
    "session-access.png",
}
REQUIRED_COMMANDS = {
    "qualification-image-build",
    "qualification-runtime",
    "backend-sqlite",
    "postgres-prepare",
    "backend-postgresql",
    "tooling",
    "frontend-install",
    "frontend-unit",
    "frontend-build",
    "compose-runtime",
    "proxy-artifact",
    "browser-mocked",
    "browser-real",
    "legacy-quick",
    "legacy-soak",
    "legacy-browser-stream",
}

SUITE_NAMES = (
    "accepted-tag-inventory",
    "sqlite-backend",
    "postgresql-backend",
    "parser",
    "worker",
    "rest-websocket",
    "authentication",
    "isolation",
    "recovery",
    "frontend-unit",
    "frontend-build",
    "browser-mocked",
    "browser-real",
    "accessibility",
    "legacy-quick-performance",
    "legacy-ten-minute-soak",
    "legacy-browser-stream",
    "audit-tooling",
    "sbom-tooling",
    "reproducibility-tooling",
    "proxy-artifact",
    "unchanged-defaults",
)


class RegressionCollectorError(RuntimeError):
    pass


@dataclass(frozen=True)
class TestCase:
    classname: str
    name: str
    status: str
    skip_message: str


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RegressionCollectorError(message)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise RegressionCollectorError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _load_json(path: Path, label: str) -> dict[str, Any]:
    _regular_file(path, label)
    data = path.read_bytes()
    _require(0 < len(data) <= MAX_JSON_BYTES, f"{label} has an invalid size")
    try:
        value = json.loads(data, object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RegressionCollectorError(f"{label} is invalid JSON") from exc
    _require(isinstance(value, dict), f"{label} must be an object")
    _reject_forbidden(value, label)
    return value


def _reject_forbidden(value: Any, label: str) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            _reject_forbidden(key, label)
            _reject_forbidden(item, label)
    elif isinstance(value, list):
        for item in value:
            _reject_forbidden(item, label)
    elif isinstance(value, str):
        normalized = value.replace("\\", "/").casefold()
        _require(
            FORBIDDEN_EVIDENCE_FRAGMENT not in normalized,
            f"{label} references forbidden retained evidence",
        )


def _regular_file(path: Path, label: str) -> None:
    _require(path.is_file() and not path.is_symlink(), f"{label} is not a regular file")


def _relative_capture(capture_root: Path, relative: str, label: str) -> Path:
    pure = PurePosixPath(relative)
    _require(
        not pure.is_absolute() and pure.parts and ".." not in pure.parts,
        f"{label} has an unsafe capture path",
    )
    candidate = capture_root.joinpath(*pure.parts)
    resolved_root = capture_root.resolve()
    try:
        candidate.resolve().relative_to(resolved_root)
    except ValueError as exc:
        raise RegressionCollectorError(f"{label} escapes the capture root") from exc
    return candidate


def _git(root: Path, *arguments: str) -> bytes:
    try:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RegressionCollectorError("accepted-tag inventory requires local Git metadata") from exc
    _require(completed.returncode == 0, "accepted-tag Git inventory command failed")
    _require(len(completed.stdout) <= MAX_GIT_BLOB_BYTES, "accepted-tag Git output is too large")
    return completed.stdout


def _tag_blob(root: Path, path: str) -> str:
    data = _git(root, "show", f"{ACCEPTED_COMMIT}:{path}")
    _require(b"\0" not in data, f"accepted-tag source is not text: {path}")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RegressionCollectorError(f"accepted-tag source is not UTF-8: {path}") from exc


def _python_nodes(path: str, source: str) -> list[str]:
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        raise RegressionCollectorError(f"cannot parse accepted Python test: {path}") from exc
    nodes: list[str] = []

    def visit(body: Sequence[ast.stmt], parents: tuple[str, ...]) -> None:
        for item in body:
            if isinstance(item, ast.ClassDef):
                visit(item.body, (*parents, item.name))
            elif isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name.startswith(
                "test_"
            ):
                nodes.append("::".join((path, *parents, item.name)))

    visit(tree.body, ())
    return sorted(nodes)


TITLE_PATTERN = re.compile(r"\b(?:it|test)\s*\(\s*([\"'])([^\r\n\"']+)\1")


def _typescript_titles(source: str) -> list[str]:
    return sorted({match.group(2) for match in TITLE_PATTERN.finditer(source)})


def _stable_ast_dump(node: ast.AST) -> str:
    options: dict[str, Any] = {
        "annotate_fields": True,
        "include_attributes": False,
    }
    if "show_empty" in inspect.signature(ast.dump).parameters:
        options["show_empty"] = True
    return ast.dump(node, **options)


def _getenv_defaults(path: str, source: str) -> dict[str, str]:
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        raise RegressionCollectorError(f"cannot parse defaults source: {path}") from exc
    defaults: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or len(node.args) < 2:
            continue
        function = node.func
        if not (
            isinstance(function, ast.Attribute)
            and function.attr == "getenv"
            and isinstance(function.value, ast.Name)
            and function.value.id == "os"
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            continue
        key = node.args[0].value
        value = _stable_ast_dump(node.args[1])
        prior = defaults.setdefault(key, value)
        _require(prior == value, f"default is ambiguous in {path}: {key}")
    return defaults


def accepted_inventory(root: Path) -> dict[str, Any]:
    peeled = _git(root, "rev-parse", f"{ACCEPTED_TAG}^{{commit}}").decode("ascii").strip()
    _require(peeled == ACCEPTED_COMMIT, "accepted v0.3 tag does not resolve to the approved commit")
    listing = _git(
        root,
        "ls-tree",
        "-r",
        "--name-only",
        ACCEPTED_COMMIT,
        "--",
        "backend/tests",
        "scripts/tests",
        "frontend/src",
        "frontend/e2e",
    ).decode("utf-8")
    paths = sorted(line for line in listing.splitlines() if line)
    python_paths = [
        path
        for path in paths
        if path.startswith(("backend/tests/", "scripts/tests/"))
        and Path(path).name.startswith("test_")
        and path.endswith(".py")
    ]
    unit_paths = [path for path in paths if re.search(r"\.test\.tsx?$", path)]
    browser_paths = [path for path in paths if path.startswith("frontend/e2e/") and path.endswith(".spec.ts")]
    _require(python_paths and unit_paths and browser_paths, "accepted-tag test inventory is incomplete")

    python: dict[str, list[str]] = {}
    for path in python_paths:
        nodes = _python_nodes(path, _tag_blob(root, path))
        _require(nodes, f"accepted Python test file has no test nodes: {path}")
        python[path] = nodes
    frontend_unit: dict[str, list[str]] = {}
    for path in unit_paths:
        titles = _typescript_titles(_tag_blob(root, path))
        _require(titles, f"accepted frontend unit test file has no tests: {path}")
        frontend_unit[path] = titles
    browser: dict[str, list[str]] = {}
    accessibility_files: list[str] = []
    accessibility_analysis_counts: dict[str, int] = {}
    for path in browser_paths:
        source = _tag_blob(root, path)
        titles = _typescript_titles(source)
        _require(titles, f"accepted browser test file has no tests: {path}")
        browser[path] = titles
        if "AxeBuilder" in source and ".analyze()" in source:
            accessibility_files.append(path)
            accessibility_analysis_counts[path] = source.count(".analyze()")

    baseline_defaults: dict[str, str] = {}
    for path in ("backend/auth.py", "backend/config.py"):
        baseline_defaults.update(_getenv_defaults(path, _tag_blob(root, path)))
    _require(len(baseline_defaults) >= 10, "accepted default inventory is unexpectedly small")
    inventory = {
        "tag": ACCEPTED_TAG,
        "commit": ACCEPTED_COMMIT,
        "python": python,
        "frontend_unit": frontend_unit,
        "browser": browser,
        "accessibility_files": sorted(accessibility_files),
        "accessibility_analysis_counts": dict(sorted(accessibility_analysis_counts.items())),
        "defaults": dict(sorted(baseline_defaults.items())),
    }
    return {**inventory, "sha256": _sha256_bytes(_canonical_json(inventory))}


def changed_defaults(root: Path, inventory: dict[str, Any]) -> list[str]:
    current: dict[str, str] = {}
    for relative in ("backend/auth.py", "backend/config.py"):
        path = root / relative
        _regular_file(path, relative)
        current.update(_getenv_defaults(relative, path.read_text(encoding="utf-8")))
    baseline = inventory["defaults"]
    return sorted(key for key, value in baseline.items() if current.get(key) != value)


def _load_junit(path: Path, label: str) -> list[TestCase]:
    _regular_file(path, label)
    data = path.read_bytes()
    _require(0 < len(data) <= MAX_XML_BYTES, f"{label} has an invalid size")
    lowered = data.lower()
    _require(b"<!doctype" not in lowered and b"<!entity" not in lowered, f"{label} has unsafe XML")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise RegressionCollectorError(f"{label} is invalid JUnit XML") from exc
    for suite in root.iter("testsuite"):
        for key in ("failures", "errors"):
            reported = suite.get(key)
            if reported is not None:
                _require(reported.isdigit() and int(reported) == 0, f"{label} reports {key}")
        direct_cases = suite.findall("testcase")
        reported_tests = suite.get("tests")
        if reported_tests is not None and direct_cases:
            _require(
                reported_tests.isdigit() and int(reported_tests) == len(direct_cases),
                f"{label} testcase aggregate differs",
            )
    cases: list[TestCase] = []
    for value in root.iter("testcase"):
        name = value.get("name", "")
        classname = value.get("classname", "")
        _require(bool(name), f"{label} contains an unnamed testcase")
        failure = value.find("failure") is not None or value.find("error") is not None
        skipped = value.find("skipped")
        status = "failed" if failure else "skipped" if skipped is not None else "passed"
        cases.append(
            TestCase(
                classname=classname,
                name=name,
                status=status,
                skip_message=(skipped.get("message", "") if skipped is not None else ""),
            )
        )
    _require(cases, f"{label} contains no testcases")
    _require(not any(item.status == "failed" for item in cases), f"{label} contains a failure")
    return cases


def _node_covered(node: str, cases: Sequence[TestCase]) -> tuple[bool, str]:
    parts = node.split("::")
    path = parts[0]
    function = parts[-1]
    module = path[:-3].replace("/", ".")
    for case in cases:
        if case.name != function and not case.name.startswith(function + "["):
            continue
        normalized_class = case.classname.replace("\\", "/").replace("/", ".")
        if module in normalized_class or normalized_class.endswith(module.split(".")[-1]):
            return True, case.status
    return False, "missing"


def _validate_python_inventory(
    expected: dict[str, list[str]],
    cases: Sequence[TestCase],
    label: str,
    *,
    allow_postgresql_skip: bool,
) -> int:
    observed = 0
    for nodes in expected.values():
        for node in nodes:
            covered, status = _node_covered(node, cases)
            _require(covered, f"{label} omitted accepted test: {node}")
            if status == "skipped":
                _require(
                    allow_postgresql_skip and "postgresql" in node.casefold(),
                    f"{label} skipped a required accepted test: {node}",
                )
            else:
                _require(status == "passed", f"{label} did not pass accepted test: {node}")
            observed += 1
    for case in cases:
        if case.status == "skipped":
            _require(
                allow_postgresql_skip and "postgresql" in case.name.casefold(),
                f"{label} contains an unexpected skip: {case.name}",
            )
    return observed


def _validate_browser_titles(
    expected: dict[str, list[str]], cases: Sequence[TestCase], label: str
) -> int:
    _require(not any(item.status == "skipped" for item in cases), f"{label} contains a skipped test")
    observed = 0
    for titles in expected.values():
        for title in titles:
            matches = [case for case in cases if title in case.name and case.status == "passed"]
            _require(matches, f"{label} omitted accepted browser test: {title}")
            observed += 1
    return observed


def _validate_frontend_unit(report: dict[str, Any], inventory: dict[str, Any]) -> int:
    _require(report.get("success") is True, "frontend unit suite did not pass")
    for key in (
        "numFailedTestSuites",
        "numFailedTests",
        "numPendingTestSuites",
        "numPendingTests",
        "numTodoTests",
    ):
        _require(report.get(key) == 0, f"frontend unit report {key} must be zero")
    results = report.get("testResults")
    _require(isinstance(results, list) and results, "frontend unit report has no suites")
    passed_titles: set[str] = set()
    assertion_count = 0
    for suite in results:
        _require(isinstance(suite, dict), "frontend unit suite result must be an object")
        assertions = suite.get("assertionResults")
        _require(isinstance(assertions, list), "frontend unit assertions are missing")
        for assertion in assertions:
            _require(
                isinstance(assertion, dict) and assertion.get("status") == "passed",
                "frontend unit report contains a non-passing assertion",
            )
            title = assertion.get("title")
            if isinstance(title, str):
                passed_titles.add(title)
            assertion_count += 1
    _require(
        report.get("numTotalTests") == assertion_count
        and report.get("numPassedTests") == assertion_count,
        "frontend unit aggregate counts differ",
    )
    expected_titles = {
        title for titles in inventory["frontend_unit"].values() for title in titles
    }
    missing = sorted(expected_titles - passed_titles)
    _require(not missing, f"frontend unit suite omitted accepted tests: {missing!r}")
    return len(expected_titles)


def _integer(mapping: dict[str, Any], key: str, label: str) -> int:
    value = mapping.get(key)
    _require(isinstance(value, int) and not isinstance(value, bool), f"{label}.{key} is not an integer")
    return value


def _number(mapping: dict[str, Any], key: str, label: str) -> float:
    value = mapping.get(key)
    _require(
        isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value),
        f"{label}.{key} is not a finite number",
    )
    return float(value)


def _mapping(value: Any, label: str) -> dict[str, Any]:
    _require(isinstance(value, dict), f"{label} must be an object")
    return value


def _integrity(value: Any, label: str, expected_count: int) -> None:
    item = _mapping(value, label)
    _require(item.get("exact") is True, f"{label} is not exact")
    _require(_integer(item, "received_count", label) == expected_count, f"{label} received count differs")
    _require(_integer(item, "expected_count", label) == expected_count, f"{label} expected count differs")
    for key in ("duplicate_count", "missing_count", "unexpected_count"):
        _require(_integer(item, key, label) == 0, f"{label}.{key} must be zero")


def _timing(
    gate: dict[str, Any],
    label: str,
    count_key: str,
    minimum_count: int,
    target_rate: float,
    target_duration: float,
) -> int:
    count = _integer(gate, count_key, label)
    production = _number(gate, "production_elapsed_seconds", label)
    measured = _number(gate, "measured_duration_seconds", label)
    achieved = _number(gate, "achieved_events_per_second", label)
    _require(count >= minimum_count and production > 0, f"{label} workload is below threshold")
    _require(achieved >= target_rate and abs(achieved - count / production) <= 0.01, f"{label} rate differs")
    for duration in (production, measured):
        _require(target_duration * 0.999 <= duration <= target_duration + 1.0, f"{label} duration differs")
    _require(0 <= _number(gate, "schedule_p95_ms", label) <= 250, f"{label} p95 differs")
    _require(0 <= _number(gate, "schedule_max_ms", label) <= 1000, f"{label} max differs")
    return count


def _component(report: dict[str, Any], profile: str, gates: set[str], label: str) -> dict[str, Any]:
    _require(report.get("schema_version") == "1.0", f"{label} schema differs")
    _require(report.get("product_version") == PRODUCT_VERSION, f"{label} product version differs")
    _require(report.get("profile") == profile, f"{label} profile differs")
    _require(report.get("overall_pass") is True, f"{label} did not pass")
    _require(report.get("acceptance_complete") is False, f"{label} claims acceptance")
    value = _mapping(report.get("gates"), f"{label}.gates")
    _require(set(value) == gates, f"{label} gate set differs")
    return value


def _source(report: dict[str, Any], expected: str, label: str) -> None:
    value = _mapping(report.get("source"), f"{label}.source")
    _require(value.get("fingerprint_sha256") == expected, f"{label} source fingerprint is stale")


def _gate(gates: dict[str, Any], name: str, test_id: str, label: str) -> dict[str, Any]:
    value = _mapping(gates.get(name), label)
    _require(value.get("test_id") == test_id and value.get("passed") is True, f"{label} failed")
    return value


def _validate_legacy_quick(report: dict[str, Any], expected_source: str) -> None:
    gates = _component(report, "quick", {"rest_mutations", "event_replay", "eventhub_fanout"}, "legacy quick")
    _source(report, expected_source, "legacy quick")
    rest = _gate(gates, "rest_mutations", "V03-PERF-001", "legacy quick REST")
    primary = _integer(rest, "primary_mutations", "legacy quick REST")
    _require(primary >= 100 and 0 <= _number(rest, "primary_p95_ms", "legacy quick REST") <= 250, "legacy REST budget differs")
    _require(rest.get("status_codes") == [202] and rest.get("retry_status_codes") == [202], "legacy REST statuses differ")
    _require(_integer(rest, "idempotent_retries", "legacy quick REST") == primary, "legacy retry count differs")
    _require(_integer(rest, "retry_identity_mismatches", "legacy quick REST") == 0, "legacy retry identity differs")
    _require(_integer(rest, "unique_command_ids", "legacy quick REST") == primary, "legacy command IDs differ")
    _require(_integer(rest, "stored_command_count", "legacy quick REST") == primary, "legacy stored count differs")
    _require(rest.get("durable_command_states") == {"completed": primary} and rest.get("workers_drained") is True, "legacy REST settlement differs")

    replay = _gate(gates, "event_replay", "V03-PERF-002", "legacy quick replay")
    replay_count = _integer(replay, "event_count", "legacy quick replay")
    _require(replay_count >= 10_000 and 0 <= _number(replay, "replay_seconds", "legacy quick replay") <= 3, "legacy replay budget differs")
    _require(replay.get("payloads_exact") is True, "legacy replay payload differs")
    _integrity(replay.get("sequence_integrity"), "legacy replay integrity", replay_count)

    stream = _gate(gates, "eventhub_fanout", "V03-PERF-003A", "legacy quick fanout")
    rate = _number(stream, "target_events_per_second", "legacy quick fanout")
    duration = _number(stream, "target_duration_seconds", "legacy quick fanout")
    _require(rate >= 100 and duration >= 60, "legacy fanout target differs")
    event_count = _timing(stream, "legacy quick fanout", "event_count_excluding_sentinel", 6001, rate, duration)
    clients = _integer(stream, "clients", "legacy quick fanout")
    _require(clients >= 2 and stream.get("producer_errors") == [], "legacy fanout producer differs")
    overflow = stream.get("client_queue_overflowed")
    _require(isinstance(overflow, list) and len(overflow) == clients and all(item is False for item in overflow), "legacy fanout overflowed")
    _integrity(stream.get("persisted_sequence_integrity"), "legacy fanout persisted integrity", event_count + 1)
    readers = stream.get("reader_results")
    _require(isinstance(readers, list) and len(readers) == clients, "legacy fanout readers differ")
    for index, reader in enumerate(readers):
        item = _mapping(reader, f"legacy fanout reader {index}")
        _require(item.get("error") is None, f"legacy fanout reader {index} failed")
        _integrity(item.get("sequence_integrity"), f"legacy fanout reader {index} integrity", event_count + 1)


def _validate_legacy_soak(report: dict[str, Any], expected_source: str) -> None:
    gates = _component(report, "soak", {"soak"}, "legacy soak")
    _source(report, expected_source, "legacy soak")
    soak = _gate(gates, "soak", "V03-PERF-004", "legacy soak")
    rate = _number(soak, "target_events_per_second", "legacy soak")
    duration = _number(soak, "target_duration_seconds", "legacy soak")
    _require(rate >= 20 and duration >= 600, "legacy soak target differs")
    count = _timing(soak, "legacy soak", "event_count", 12_001, rate, duration)
    _require(soak.get("producer_errors") == [] and soak.get("control_failures") == [], "legacy soak errors are present")
    _integrity(soak.get("sequence_integrity"), "legacy soak integrity", count)
    memory = _mapping(soak.get("memory_measurement"), "legacy soak memory")
    _require(_number(memory, "post_warmup_growth_mib", "legacy soak memory") <= 32, "legacy soak memory growth differs")
    _require(_number(memory, "post_warmup_slope_mib_per_minute", "legacy soak memory") <= 2, "legacy soak memory slope differs")


def _validate_legacy_browser(report: dict[str, Any], expected_source: str) -> None:
    label = "legacy browser stream"
    _require(report.get("schema_version") == "1.0", f"{label} schema differs")
    _require(report.get("product_version") == "0.3.0", f"{label} product marker differs")
    _require(report.get("profile") == "browser-stream" and report.get("test_id") == "V03-PERF-003", f"{label} identity differs")
    _require(report.get("passed") is True and report.get("overall_pass") is True, f"{label} failed")
    _require(report.get("acceptance_complete") is False, f"{label} claims acceptance")
    _source(report, expected_source, label)
    rate = _number(report, "target_events_per_second", label)
    duration = _number(report, "target_duration_seconds", label)
    _require(rate >= 100 and duration >= 60, f"{label} target differs")
    event_count = _integer(report, "event_count_excluding_sentinel", label)
    producer = _mapping(report.get("producer"), f"{label}.producer")
    _require(producer.get("state") == "finished" and producer.get("errors") == [], f"{label} producer failed")
    timing = dict(producer)
    timing["event_count_excluding_sentinel"] = event_count
    timing["measured_duration_seconds"] = producer.get("elapsed_seconds")
    _timing(timing, f"{label}.producer", "event_count_excluding_sentinel", 6001, rate, duration)
    _require(_integer(producer, "produced_event_count", f"{label}.producer") == event_count, f"{label} producer count differs")
    _integrity(producer.get("persisted_sequence_integrity"), f"{label} persisted integrity", event_count + 1)
    readers = report.get("reader_results")
    _require(isinstance(readers, list) and len(readers) >= 2, f"{label} readers are missing")
    for index, reader in enumerate(readers):
        item = _mapping(reader, f"{label}.reader[{index}]")
        _require(item.get("error") is None and item.get("sentinel_received") is True, f"{label} reader failed")
        _require(_integer(item, "data_event_count", f"{label}.reader[{index}]") == event_count, f"{label} reader count differs")
        ready_ms = _number(item, "subscription_ready_at_ms", f"{label}.reader[{index}]")
        first_ms = _number(item, "first_data_at_ms", f"{label}.reader[{index}]")
        last_ms = _number(item, "last_data_at_ms", f"{label}.reader[{index}]")
        sentinel_ms = _number(item, "sentinel_at_ms", f"{label}.reader[{index}]")
        elapsed = _number(item, "delivery_elapsed_seconds", f"{label}.reader[{index}]")
        achieved = _number(item, "achieved_events_per_second", f"{label}.reader[{index}]")
        _require(
            ready_ms <= first_ms
            and sentinel_ms >= last_ms
            and abs(elapsed - (last_ms - first_ms) / 1000) <= 0.001,
            f"{label} reader boundaries differ",
        )
        _require(
            duration * 0.999 <= elapsed <= duration + 1
            and achieved >= rate
            and abs(achieved - event_count / elapsed) <= 0.01,
            f"{label} reader timing differs",
        )
        _integrity(item.get("sequence_integrity"), f"{label}.reader[{index}] integrity", event_count + 1)


def _tree_digest(path: Path) -> tuple[int, str]:
    _require(path.is_dir() and not path.is_symlink(), "frontend build capture is missing")
    files: list[Path] = []
    for item in sorted(path.rglob("*")):
        _require(not item.is_symlink(), "frontend build capture contains a symlink")
        if item.is_file():
            files.append(item)
    _require(files and (path / "index.html") in files, "frontend build capture is incomplete")
    digest = hashlib.sha256()
    total_bytes = 0
    for item in files:
        size = item.stat().st_size
        _require(0 < size <= MAX_BUILD_FILE_BYTES, "frontend build capture has an invalid file size")
        total_bytes += size
        _require(total_bytes <= MAX_BUILD_BYTES, "frontend build capture is too large")
        relative = item.relative_to(path).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(item.read_bytes()).digest())
    return len(files), digest.hexdigest()


def _category_inventory(inventory: dict[str, Any]) -> dict[str, list[str]]:
    backend_nodes = [
        node
        for path, nodes in inventory["python"].items()
        if path.startswith("backend/tests/")
        for node in nodes
    ]
    script_nodes = [
        node
        for path, nodes in inventory["python"].items()
        if path.startswith("scripts/tests/")
        for node in nodes
    ]
    categories = {
        "parser": [node for node in backend_nodes if "test_procedure_parser.py" in node],
        "worker": [node for node in backend_nodes if "test_worker_expressions.py" in node or "test_v03_execution.py" in node],
        "rest-websocket": [node for node in backend_nodes if "test_api_execution.py" in node],
        "authentication": [node for node in backend_nodes if "test_auth.py" in node],
        "isolation": [node for node in backend_nodes if any(word in node.casefold() for word in ("unsigned", "spoof", "signature", "issuer", "claim_policy"))],
        "recovery": [node for node in backend_nodes if any(word in node.casefold() for word in ("recover", "crash", "restart", "watchdog", "shutdown", "persistence_failure", "terminal_transition"))],
        "audit-tooling": [node for node in script_nodes if "test_release_script_contracts.py" in node],
        "sbom-tooling": [node for node in script_nodes if "sbom" in node.casefold() or "test_build_reproducible.py" in node],
        "reproducibility-tooling": [node for node in script_nodes if "test_build_reproducible.py" in node],
    }
    for name, nodes in categories.items():
        _require(nodes, f"accepted-tag category inventory is empty: {name}")
    return categories


def validate_capture(root: Path, capture_root: Path) -> dict[str, Any]:
    root = root.resolve()
    source = source_fingerprint_v04(root)
    expected_capture = (
        root
        / "artifacts"
        / "v0.4"
        / ".qualification"
        / "runtime-captures"
        / source
        / "regression"
    ).resolve()
    _require(capture_root.resolve() == expected_capture, "regression capture root is not canonical for this source")
    _require(capture_root.is_dir() and not capture_root.is_symlink(), "regression capture root is missing")
    manifest_path = capture_root / "run.json"
    manifest = _load_json(manifest_path, "regression run manifest")
    manifest_sha256 = _sha256_bytes(manifest_path.read_bytes())
    _require(manifest.get("schema_version") == REPORT_SCHEMA, "regression run schema differs")
    _require(manifest.get("product_version") == PRODUCT_VERSION, "regression product version differs")
    _require(manifest.get("scope_profile") == SCOPE_PROFILE, "regression scope differs")
    _require(
        manifest.get("source_fingerprint_before_sha256") == source
        and manifest.get("source_fingerprint_after_sha256") == source,
        "regression run source binding is stale",
    )
    _require(IMAGE_ID_RE.fullmatch(str(manifest.get("qualification_image_id", ""))) is not None, "qualification image ID is invalid")

    inventory = accepted_inventory(root)
    accepted = _mapping(manifest.get("accepted_baseline"), "accepted baseline")
    _require(accepted == {"tag": ACCEPTED_TAG, "commit": ACCEPTED_COMMIT, "inventory_sha256": inventory["sha256"]}, "accepted baseline inventory binding differs")
    defaults_changed = changed_defaults(root, inventory)
    _require(not defaults_changed, f"accepted defaults changed: {defaults_changed!r}")

    captures = _mapping(manifest.get("captures"), "capture checksum manifest")
    _require(set(captures) == REQUIRED_CAPTURES, "regression capture set is incomplete")
    for relative, digest in captures.items():
        _require(SHA256_RE.fullmatch(str(digest)) is not None, f"capture digest is invalid: {relative}")
        path = _relative_capture(capture_root, relative, relative)
        _regular_file(path, relative)
        data = path.read_bytes()
        _require(_sha256_bytes(data) == digest, f"capture checksum differs: {relative}")
        _require(FORBIDDEN_EVIDENCE_FRAGMENT.encode("ascii") not in data.replace(b"\\", b"/").lower(), f"capture cites forbidden retained evidence: {relative}")

    commands = _mapping(manifest.get("commands"), "regression commands")
    _require(set(commands) == REQUIRED_COMMANDS, "regression command accounting is incomplete")
    for command_id, record_value in commands.items():
        record = _mapping(record_value, f"command {command_id}")
        _require(record.get("return_code") == 0, f"command failed: {command_id}")
        for stream in ("stdout", "stderr"):
            relative = record.get(f"{stream}_path")
            digest = record.get(f"{stream}_sha256")
            _require(isinstance(relative, str) and SHA256_RE.fullmatch(str(digest)) is not None, f"command stream record is invalid: {command_id}")
            path = _relative_capture(capture_root, relative, f"{command_id} {stream}")
            _regular_file(path, f"{command_id} {stream}")
            _require(path.stat().st_size <= MAX_LOG_BYTES, f"command output is too large: {command_id}")
            data = path.read_bytes()
            _require(_sha256_bytes(data) == digest, f"command stream checksum differs: {command_id}")
            _require(FORBIDDEN_EVIDENCE_FRAGMENT.encode("ascii") not in data.replace(b"\\", b"/").lower(), f"command output cites forbidden retained evidence: {command_id}")

    screenshots = _mapping(manifest.get("screenshots"), "screenshot manifest")
    _require(set(screenshots) == REQUIRED_SCREENSHOTS, "legacy browser screenshot set is incomplete")
    for name, digest in screenshots.items():
        _require(SHA256_RE.fullmatch(str(digest)) is not None, f"screenshot digest is invalid: {name}")
        path = _relative_capture(capture_root, f"screenshots/{name}", name)
        _regular_file(path, name)
        _require(8 < path.stat().st_size <= MAX_SCREENSHOT_BYTES, f"screenshot size is invalid: {name}")
        data = path.read_bytes()
        _require(data.startswith(b"\x89PNG\r\n\x1a\n") and _sha256_bytes(data) == digest, f"screenshot is invalid: {name}")

    build = _mapping(manifest.get("frontend_build"), "frontend build manifest")
    build_count, build_digest = _tree_digest(capture_root / "frontend-dist")
    _require(build.get("file_count") == build_count and build.get("sha256") == build_digest, "frontend build capture differs")

    python_inventory: dict[str, list[str]] = inventory["python"]
    backend_inventory = {path: nodes for path, nodes in python_inventory.items() if path.startswith("backend/tests/")}
    tooling_inventory = {path: nodes for path, nodes in python_inventory.items() if path.startswith("scripts/tests/")}
    sqlite_cases = _load_junit(capture_root / "backend-sqlite.xml", "SQLite JUnit")
    postgres_cases = _load_junit(capture_root / "backend-postgresql.xml", "PostgreSQL JUnit")
    tooling_cases = _load_junit(capture_root / "tooling.xml", "tooling JUnit")
    sqlite_count = _validate_python_inventory(backend_inventory, sqlite_cases, "SQLite suite", allow_postgresql_skip=True)
    postgres_count = _validate_python_inventory(backend_inventory, postgres_cases, "PostgreSQL suite", allow_postgresql_skip=False)
    tooling_count = _validate_python_inventory(tooling_inventory, tooling_cases, "tooling suite", allow_postgresql_skip=False)

    unit_count = _validate_frontend_unit(_load_json(capture_root / "frontend-unit.json", "frontend unit report"), inventory)
    mocked_cases = _load_junit(capture_root / "browser-mocked.xml", "mocked browser JUnit")
    real_cases = _load_junit(capture_root / "browser-real.xml", "real browser JUnit")
    mocked_inventory = {path: titles for path, titles in inventory["browser"].items() if path.endswith(("auth.spec.ts", "console.spec.ts"))}
    real_inventory = {path: titles for path, titles in inventory["browser"].items() if path.endswith("integration.spec.ts")}
    _require(len(mocked_inventory) == 2 and len(real_inventory) == 1, "accepted browser inventory shape differs")
    mocked_count = _validate_browser_titles(mocked_inventory, mocked_cases, "mocked browser suite")
    real_count = _validate_browser_titles(real_inventory, real_cases, "real browser suite")
    _require(set(inventory["accessibility_files"]) == set(inventory["browser"]), "accepted accessibility inventory is incomplete")
    for relative, accepted_count in inventory["accessibility_analysis_counts"].items():
        current_source = (root / relative).read_text(encoding="utf-8")
        _require(
            "AxeBuilder" in current_source
            and current_source.count(".analyze()") >= accepted_count,
            f"current browser suite weakened accepted accessibility coverage: {relative}",
        )

    legacy_source = source_fingerprint(root)
    _validate_legacy_quick(_load_json(capture_root / "legacy-quick.json", "legacy quick report"), legacy_source)
    _validate_legacy_soak(_load_json(capture_root / "legacy-soak.json", "legacy soak report"), legacy_source)
    _validate_legacy_browser(_load_json(capture_root / "legacy-browser-stream.json", "legacy browser report"), legacy_source)

    categories = _category_inventory(inventory)
    runtime = _mapping(manifest.get("runtime"), "regression runtime")
    for key in (
        "qualification_python",
        "node",
        "playwright",
        "chromium",
        "docker_server_platform",
    ):
        _require(isinstance(runtime.get(key), str) and runtime[key], f"regression runtime {key} is missing")
    _require(
        re.fullmatch(r"Python 3\.13\.\d+", runtime["qualification_python"]) is not None,
        "qualification image Python runtime is not 3.13.x",
    )
    _require(runtime.get("short_lived_browser_token_discarded") is True, "browser token disposal was not recorded")
    _require(runtime.get("isolated_runtime_resources_torn_down") is True, "isolated runtime teardown was not verified")
    _require(manifest.get("proxy_artifact_validated") is True, "proxy artifact validation is missing")

    total_python = sum(len(nodes) for nodes in python_inventory.values())
    total_browser = sum(len(titles) for titles in inventory["browser"].values())
    metrics = {
        "v03_suite_count": len(SUITE_NAMES),
        "v03_suite_failure_count": 0,
        "v03_changed_default_count": 0,
        "accepted_tag_python_test_count": total_python,
        "accepted_tag_frontend_unit_test_count": unit_count,
        "accepted_tag_browser_test_count": total_browser,
        "sqlite_accounted_test_count": sqlite_count,
        "postgresql_accounted_test_count": postgres_count,
        "tooling_accounted_test_count": tooling_count,
        "mocked_browser_accounted_test_count": mocked_count,
        "real_browser_accounted_test_count": real_count,
        "accepted_default_count": len(inventory["defaults"]),
        "accepted_inventory_sha256": inventory["sha256"],
        "regression_run_manifest_sha256": manifest_sha256,
        "legacy_source_fingerprint_sha256": legacy_source,
        "qualification_image_id": manifest["qualification_image_id"],
        "capture_file_count": len(REQUIRED_CAPTURES),
        "screenshot_count": len(REQUIRED_SCREENSHOTS),
        "frontend_build_file_count": build_count,
        "frontend_build_sha256": build_digest,
        "semantic_category_count": len(categories),
    }
    return {
        "test_id": "V04-REG-001",
        "source_fingerprint_sha256": source,
        "assertions": [
            *({"id": name, "passed": True} for name in SUITE_NAMES),
            {"id": "source-bound-captures-checksummed", "passed": True},
            {"id": "isolated-runtime-resources-torn-down", "passed": True},
        ],
        "metrics": metrics,
    }


def _write_inventory(root: Path, output: Path) -> None:
    value = accepted_inventory(root)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(_canonical_json(value) + b"\n")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--capture-root", type=Path)
    parser.add_argument("--inventory-output", type=Path)
    parser.add_argument("--tree-root", type=Path)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if args.inventory_output is not None:
        _write_inventory(root, args.inventory_output)
        return 0
    if args.tree_root is not None:
        count, digest = _tree_digest(args.tree_root.resolve())
        print(_canonical_json({"file_count": count, "sha256": digest}).decode("ascii"))
        return 0
    source = source_fingerprint_v04(root)
    capture_root = args.capture_root or (
        root
        / "artifacts"
        / "v0.4"
        / ".qualification"
        / "runtime-captures"
        / source
        / "regression"
    )
    result = validate_capture(root, capture_root)
    print(_canonical_json(result).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
