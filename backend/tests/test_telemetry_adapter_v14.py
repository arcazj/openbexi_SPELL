from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import copy
import json
from pathlib import Path
import time

import pytest
from pydantic import ValidationError

from backend.legacy_observation_v12 import ReplayError, ReplaySource, load_sources
from backend.telemetry_adapter import TMQuery, compare_tm, get_tm, profile

ROOT = Path(__file__).resolve().parents[2]
PREFIX = "/api/v1/telemetry-adapter"


def capture():
    return json.loads((ROOT / "contracts/v12/reference_capture.json").read_bytes())


def source(value=None):
    return ReplaySource.from_bytes(json.dumps(capture() if value is None else value).encode())


def test_profile_has_exact_read_only_capability_and_no_remote_route(client, viewer_headers):
    assert client.get(PREFIX + "/profile").status_code == 401
    response = client.get(PREFIX + "/profile", headers=viewer_headers)
    assert response.status_code == 200
    assert response.json() == profile()
    assert profile()["mutability"] == "READ_ONLY"
    assert profile()["methods"] == ["GetTM", "Catalog", "Compare"]
    assert not profile()["operational_authorization"]
    assert "endpoint" not in profile()


@pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
def test_mutation_methods_are_absent(client, operator_headers, method):
    assert getattr(client, method)(PREFIX + "/reference/items/TEMP", headers=operator_headers).status_code == 405


def test_current_extended_and_raw_contract_preserves_uint64_and_refresh():
    replay = source()
    eng = get_tm(replay, "TEMP", TMQuery(extended=True))
    assert eng["value"] == {"type": "FINITE_DOUBLE", "value": 20.1}
    assert eng["sample"]["raw"]["value"] == "201"
    assert eng["sample"]["quality"] == "GOOD"
    assert eng["source"]["live"] is False
    assert eng["effect_certainty"] == "NO_MUTATION"
    eng["sample"]["raw"]["value"] = "tampered"
    assert get_tm(replay, "TEMP", TMQuery(value_format="RAW"))["value"]["value"] == "201"
    assert get_tm(replay, "COUNTER", TMQuery())["value"]["value"] == "18446744073709551615"
    assert get_tm(replay, "TEMP", TMQuery())["sample"] is None


@pytest.mark.parametrize("timeout,outcome", [(1999, "TIMEOUT"), (2000, "OK"), (60000, "OK")])
def test_next_sample_timeout_is_recorded_logical_time(timeout, outcome):
    replay = source()
    result = get_tm(replay, "TEMP", TMQuery(wait=True, after=replay.cursor(1), timeout_ms=timeout, extended=True))
    assert result["outcome"] == outcome
    if outcome == "OK":
        assert result["sample"]["sequence"] == "7"
    else:
        assert result["value"] is None and result["sample"] is None


def test_initial_and_exhausted_cursor_have_explicit_bounded_results():
    replay = source()
    result = get_tm(replay, "TEMP", TMQuery(wait=True, after=replay.cursor(0), timeout_ms=8000))
    assert result["value"]["value"] == 20.0
    assert get_tm(replay, "TEMP", TMQuery(wait=True, after=replay.cursor(7)))["outcome"] == "TIMEOUT"
    assert get_tm(replay, "MISSING", TMQuery(wait=True, after=replay.cursor(0)))["outcome"] == "TIMEOUT"
    assert get_tm(replay, "STALE", TMQuery(wait=True, after=replay.cursor(3)))["outcome"] == "TIME_REGRESSION"


@pytest.mark.parametrize("item,outcome", [("STALE", "STALE"), ("UNKNOWN", "INDETERMINATE"),
    ("MISSING", "NOT_AVAILABLE"), ("OPAQUE", "UNSUPPORTED"), ("absent", "NOT_FOUND")])
def test_non_good_observations_never_supply_values(item, outcome):
    result = get_tm(source(), item, TMQuery(extended=True))
    assert result["outcome"] == outcome and result["value"] is None
    if result["sample"]:
        assert result["sample"]["raw"] is None and result["sample"]["eng"] is None


@pytest.mark.parametrize("modifier", [{"wait": True}, {"after": "cursor"}, {"timeout_ms": 1},
    {"value_format": "HEX"}, {"extended": "invalid"}, {"Wait": True}, {"endpoint": "http://invalid"},
    {"wait": True, "after": "cursor", "timeout_ms": -1}, {"wait": True, "after": "cursor", "timeout_ms": 60001}])
def test_unsupported_or_ambiguous_modifiers_fail_closed(modifier):
    with pytest.raises(ValidationError):
        TMQuery(**modifier)


@pytest.mark.parametrize("modifier", ["value_format=HEX", "Timeout=3", "timeout_ms=1", "wait=true", "endpoint=x",
                                       "value_format=RAW&value_format=ENG"])
def test_rest_modifier_rejection(client, viewer_headers, modifier):
    response = client.get(PREFIX + "/reference/items/TEMP?" + modifier, headers=viewer_headers)
    assert response.status_code == 422, response.text


def test_source_epoch_digest_future_and_malformed_cursors_fail():
    replay = source()
    other = load_sources()["simulator"]
    for cursor in (other.cursor(1), replay.cursor(1000), "malformed", replay.cursor(1).replace("recording-1", "other")):
        with pytest.raises(ReplayError):
            get_tm(replay, "TEMP", TMQuery(wait=True, after=cursor))


def test_disconnect_gap_and_bad_quality_are_explicit_and_never_compared_as_success():
    good = source()
    for mode, outcome in (("disconnected", "DISCONNECTED"), ("gap", "GAP"), ("bad", "INDETERMINATE")):
        value = capture()
        if mode == "disconnected":
            value["connected"] = False
        elif mode == "gap":
            value["samples"].pop(1)
        else:
            value["samples"][-1]["quality"] = "BAD"
        bad = source(value)
        result = get_tm(bad, "TEMP", TMQuery(wait=mode == "gap", after=bad.cursor(0) if mode == "gap" else None))
        assert result["outcome"] == outcome and result["value"] is None
        if mode != "gap":
            assert compare_tm(good, bad, "TEMP")["classification"] == "INDETERMINATE"


def test_comparison_retains_both_full_traces_and_detects_field_difference():
    sources = load_sources()
    report = compare_tm(sources["reference"], sources["simulator"], "TEMP")
    assert report["classification"] == "EQUIVALENT"
    assert report["reference"]["source"]["digest"] != report["simulator"]["source"]["digest"]
    value = capture()
    value["samples"][-1]["eng"]["value"] = 99.0
    report = compare_tm(source(), source(value), "TEMP")
    assert report["classification"] == "DIFFERENT" and report["differences"] == ["eng"]
    assert compare_tm(source(), source(), "OPAQUE")["classification"] == "UNSUPPORTED"
    assert compare_tm(source(), source(), "MISSING")["classification"] == "INDETERMINATE"


def test_api_catalog_snapshot_and_explicit_fallback_are_source_bound(client, viewer_headers):
    results = []
    for name in ("reference", "simulator"):
        catalog = client.get(f"{PREFIX}/{name}/catalog", headers=viewer_headers).json()
        response = client.get(f"{PREFIX}/{name}/items/TEMP", params={"wait": True, "after": catalog["initial_cursor"], "extended": True}, headers=viewer_headers)
        assert response.status_code == 200, response.text
        assert response.json()["value"]["value"] == {"reference": 20.0, "simulator": 20.1}[name]
        results.append(response.json()["source"]["digest"])
    assert results[0] != results[1]
    assert client.get(PREFIX + "/unknown/items/TEMP", headers=viewer_headers).status_code == 404
    assert client.get(PREFIX + "/comparison/TEMP", headers=viewer_headers).json()["classification"] == "EQUIVALENT"
    assert client.get(PREFIX + "/comparison/TEMP?unknown=true", headers=viewer_headers).status_code == 422


def test_bounded_parallel_load_has_no_shared_cursor_or_source_mutation():
    replay = source()
    before = replay.snapshot()
    start = time.monotonic()
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: get_tm(replay, "TEMP", TMQuery(wait=True, after=replay.cursor(1), extended=True)), range(128)))
    assert time.monotonic() - start < 30
    assert all(value["outcome"] == "OK" and value["sample"]["sequence"] == "7" for value in results)
    assert replay.snapshot() == before


def test_page_boundaries_do_not_hide_a_gap_before_a_next_sample():
    value = capture()
    row = copy.deepcopy(value["samples"][1])
    value["samples"] = [{**row, "sequence": str(index), "time_ns": "8000000000"} for index in range(1, 258)]
    value["samples"].append({**capture()["samples"][-1], "sequence": "259"})
    replay = source(value)
    assert get_tm(replay, "TEMP", TMQuery(wait=True, after=replay.cursor(0)))["outcome"] == "GAP"
