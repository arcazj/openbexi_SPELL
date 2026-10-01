from __future__ import annotations

import ast
import copy
import json
from pathlib import Path

import pytest

from backend.legacy_observation_v12 import MAX_CAPTURE_BYTES, ReplayError, ReplaySource, compare, load_sources

ROOT = Path(__file__).resolve().parents[2]


def capture() -> dict:
    return json.loads((ROOT / "contracts/v12/reference_capture.json").read_text(encoding="utf-8"))


def source(value: dict | None = None) -> ReplaySource:
    return ReplaySource.from_bytes(json.dumps(capture() if value is None else value).encode())


def test_golden_report_uses_independent_oracle_and_exposes_limits() -> None:
    sources = load_sources()
    report = compare(sources["reference"], sources["simulator"])
    assert report["counts"] == {"EQUIVALENT": 5, "DIFFERENT": 0, "INDETERMINATE": 3, "UNSUPPORTED": 1}
    assert not report["legacy_system_qualified"]
    assert report["reference"]["digest"] != report["simulator"]["digest"]
    assert report["scope"] == "SYNTHETIC_REPLAY_ONLY"


def test_current_and_next_samples_distinguish_raw_engineering_and_clock() -> None:
    replay = source()
    assert replay.get_tm("TEMP")["value"] == {"type": "FINITE_DOUBLE", "value": 20.1}
    assert replay.get_tm("TEMP", value_format="RAW")["value"] == {"type": "UINT64", "value": "201"}
    first = replay.get_tm("TEMP", replay.cursor(0))
    assert first["value"]["value"] == 20.0
    assert first["sample"]["sequence"] == "1"
    assert replay.get_tm("TEMP", first["sample"]["cursor"])["sample"]["sequence"] == "7"
    assert replay.get_tm("TEMP", replay.cursor(7))["outcome"] == "NOT_AVAILABLE"
    assert replay.get_tm("COUNTER")["value"]["value"] == "18446744073709551615"


@pytest.mark.parametrize("item,outcome", [("STALE", "STALE"), ("UNKNOWN", "INDETERMINATE"),
    ("OPAQUE", "UNSUPPORTED"), ("MISSING", "NOT_AVAILABLE"), ("absent", "NOT_FOUND")])
def test_unusable_samples_do_not_yield_a_procedure_value(item: str, outcome: str) -> None:
    result = source().get_tm(item)
    assert result["outcome"] == outcome
    assert result["value"] is None


def test_snapshot_is_immutable_and_replay_is_lossless_and_paginated() -> None:
    replay = source()
    snapshot = replay.snapshot()
    snapshot["items"][0]["eng"]["value"] = -999.0
    assert replay.get_tm("TEMP")["value"]["value"] == 20.1
    cursor = replay.cursor(0)
    sequences = []
    while True:
        page = replay.replay(cursor, 2)
        sequences.extend(item["sequence"] for item in page["items"])
        cursor = page["cursor"]
        if not page["has_more"]:
            break
    assert sequences == [str(i) for i in range(1, 8)]
    assert cursor == replay.snapshot()["cursor"]


def test_gap_requires_snapshot_and_does_not_advance_cursor() -> None:
    value = capture()
    del value["samples"][2]
    replay = source(value)
    cursor = replay.cursor(2)
    page = replay.replay(cursor)
    assert page["outcome"] == "GAP"
    assert page["items"] == [] and page["cursor"] == cursor and page["snapshot_required"]
    assert replay.get_tm("TEMP", cursor)["outcome"] == "GAP"
    assert replay.replay(replay.snapshot()["cursor"])["outcome"] == "OK"


def test_disconnect_is_explicit_and_switching_source_restores_simulator() -> None:
    value = capture()
    value["connected"] = False
    replay = source(value)
    assert replay.get_tm("TEMP")["outcome"] == "DISCONNECTED"
    assert replay.read("resources", "DECODER")["outcome"] == "DISCONNECTED"
    assert replay.replay(replay.cursor(0))["outcome"] == "DISCONNECTED"
    assert compare(replay, source())["counts"]["EQUIVALENT"] == 0
    disconnected = compare(replay, replay)
    assert len(disconnected["rows"]) == 9
    assert disconnected["counts"] == {"EQUIVALENT": 0, "DIFFERENT": 0, "INDETERMINATE": 8, "UNSUPPORTED": 1}
    assert load_sources()["simulator"].get_tm("TEMP")["outcome"] == "OK"


def test_cursor_binds_capture_content_source_and_epoch() -> None:
    original = source()
    for key, value in [("epoch", "recording-2"), ("source_id", "other-source"), ("clock_ns", "11000000000")]:
        changed = capture()
        changed[key] = value
        with pytest.raises(ReplayError, match="STALE_SOURCE"):
            source(changed).replay(original.cursor(0))
    with pytest.raises(ReplayError, match="FUTURE_CURSOR"):
        original.replay(original.cursor(8))


@pytest.mark.parametrize("cursor", ["", "x", "x:y:z:-1", "x:y:z:01", "x:y:z:18446744073709551616", "x" * 221])
def test_invalid_cursor_is_rejected(cursor: str) -> None:
    with pytest.raises(ReplayError):
        source().replay(cursor)


@pytest.mark.parametrize("limit", [0, -1, 257, True, 1.0, "1"])
def test_pagination_is_bounded(limit) -> None:
    replay = source()
    with pytest.raises(ReplayError, match="INVALID_PAGE_SIZE"):
        replay.replay(replay.cursor(0), limit)


@pytest.mark.parametrize("payload", [b"", b"\xff", b"{", b'{"x":1,"x":2}', b'{"x":NaN}',
    b'{"x":"\\ud800"}', b"[" * 2000 + b"]" * 2000, b" " * (MAX_CAPTURE_BYTES + 1)])
def test_invalid_capture_is_rejected_without_echo(payload: bytes) -> None:
    with pytest.raises(ReplayError) as error:
        ReplaySource.from_bytes(payload)
    assert len(str(error.value)) < 50


@pytest.mark.parametrize("mutation", [
    lambda c: c.update(endpoint="https://not-permitted.invalid"),
    lambda c: c.update(reference_version="2.6.10"),
    lambda c: c.update(provenance="LIVE_GCS"),
    lambda c: c.update(connected=1),
    lambda c: c["catalog"].append(copy.deepcopy(c["catalog"][0])),
    lambda c: c["samples"][1].update(sequence="1"),
    lambda c: c["samples"][0].update(time_ns="10000000001"),
    lambda c: c["samples"][0].update(item_id="absent"),
    lambda c: c["samples"][0].update(valid="true"),
    lambda c: c["samples"][0].update(quality="unspecified"),
    lambda c: c["samples"][0]["raw"].update(value="18446744073709551616"),
    lambda c: c["samples"][0]["raw"].update(value=200),
    lambda c: c["samples"][0]["raw"].update(type="INT64"),
    lambda c: c["samples"][5].update(raw={"untrusted": "opaque"}),
    lambda c: c["limits"]["TEMP"]["lower"].update(value=100.0),
    lambda c: c["resources"].update(DECODER={"type": "BOOLEAN", "value": 1}),
])
def test_malformed_or_ambiguous_legacy_data_fails_closed(mutation) -> None:
    value = capture()
    mutation(value)
    with pytest.raises(ReplayError):
        source(value)


@pytest.mark.parametrize("field,value", [("eng", {"type": "FINITE_DOUBLE", "value": 99.0}),
    ("raw", {"type": "UINT64", "value": "999"}), ("time_ns", "9999999999")])
def test_comparison_detects_changed_golden_values(field, value) -> None:
    changed = capture()
    changed["samples"][-1][field] = value
    report = compare(source(), source(changed))
    row = next(row for row in report["rows"] if row["item_id"] == "TEMP" and row["category"] == "telemetry")
    assert row["classification"] == "DIFFERENT" and field in row["differences"]


def test_comparison_detects_units_resources_limits_and_missing_catalog_entries() -> None:
    changed = capture()
    changed["catalog"][0]["unit"] = "K"
    changed["resources"]["DECODER"]["value"] = "SIMULATOR-B"
    changed["limits"]["TEMP"]["upper"]["value"] = 80.0
    changed["catalog"].pop()
    report = compare(source(), source(changed))
    assert report["counts"]["DIFFERENT"] == 3
    assert report["counts"]["UNSUPPORTED"] == 2


def test_read_methods_never_expose_mutation_or_network_authority() -> None:
    replay = source()
    assert replay.read("resources", "DECODER")["value"]["value"] == "SIMULATOR-A"
    assert replay.read("limits", "TEMP")["value"]["upper"]["value"] == 40.0
    assert replay.read("resources", "absent")["outcome"] == "NOT_FOUND"
    with pytest.raises(ReplayError, match="UNSUPPORTED_SERVICE"):
        replay.read("commands", "TEMP")
    assert not any(hasattr(replay, method) for method in ("send", "inject", "set_resource", "set_limits", "connect"))
    tree = ast.parse((ROOT / "backend/legacy_observation_v12.py").read_text(encoding="utf-8"))
    imports = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    imports |= {name.name for node in ast.walk(tree) if isinstance(node, ast.Import) for name in node.names}
    assert not (imports & {"socket", "subprocess", "requests", "httpx", "urllib", "grpc"})


def test_api_requires_identity_and_supports_viewers(client, viewer_headers) -> None:
    prefix = "/api/v1/legacy-observation"
    paths = ["/sources", "/comparison", "/reference/catalog", "/reference/snapshot",
             "/reference/telemetry/TEMP", "/reference/resources/DECODER", "/reference/limits/TEMP"]
    for path in paths:
        assert client.get(prefix + path).status_code == 401
        assert client.get(prefix + path, headers=viewer_headers).status_code == 200
        for method in ("post", "put", "patch", "delete"):
            assert getattr(client, method)(prefix + path, headers=viewer_headers).status_code == 405
    assert client.get(prefix + "/unknown/snapshot", headers=viewer_headers).status_code == 404
    assert client.get(prefix + "/reference/commands/TEMP", headers=viewer_headers).status_code == 422


def test_api_replay_and_simulator_fallback_are_read_only(client, viewer_headers) -> None:
    prefix = "/api/v1/legacy-observation"
    snapshot = client.get(prefix + "/reference/snapshot", headers=viewer_headers).json()
    page = client.get(prefix + "/reference/replay", params={"after": snapshot["cursor"]}, headers=viewer_headers)
    assert page.status_code == 200 and page.json()["items"] == []
    assert client.get(prefix + "/simulator/snapshot", headers=viewer_headers).json()["source"]["source_id"] == "simulator-oracle"
    assert client.get(prefix + "/simulator/replay", params={"after": snapshot["cursor"]}, headers=viewer_headers).status_code == 409
    assert client.get(prefix + "/reference/replay", params={"after": snapshot["cursor"], "limit": 257}, headers=viewer_headers).status_code == 422
    assert client.get(prefix + "/reference/telemetry/TEMP", params={"value_format": "EXECUTE"}, headers=viewer_headers).status_code == 422
