from __future__ import annotations

import json
import sys
import types
from datetime import datetime, timedelta, timezone

import pytest


sys.modules.setdefault("grpc", types.ModuleType("grpc"))

from scripts import runtime_fault_probe_v04 as probe


class FakeResponse:
    status = 200

    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, _limit: int) -> bytes:
        return self.payload


def test_projection_observation_uses_internal_fixed_url_and_never_returns_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "test-token-that-must-not-be-returned"
    captured: dict[str, object] = {}

    def urlopen(request, timeout: float):
        captured["url"] = request.full_url
        captured["headers"] = dict(request.header_items())
        captured["timeout"] = timeout
        return FakeResponse(
            {
                "items": [
                    {
                        "id": "local-synthetic-simulator",
                        "state": "READY",
                        "credential_epoch": 2,
                        "last_observed_at": "2026-07-19T21:30:01+00:00",
                        "stale": False,
                        "staleness": "OBSERVED",
                    }
                ]
            }
        )

    monkeypatch.setattr(probe.urllib.request, "urlopen", urlopen)

    result = probe._projection_observation(token)

    assert captured["url"] == probe.DRIVER_PROJECTION_URL
    assert captured["timeout"] == 2
    assert captured["headers"]["Host"] == "127.0.0.1"
    assert captured["headers"]["Authorization"] == f"Bearer {token}"
    assert result["http_status"] == 200
    assert result["credential_epoch"] == 2
    assert token not in json.dumps(result)


def test_projection_recovery_requires_a_strictly_newer_observation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline = datetime(2026, 7, 19, 21, 30, tzinfo=timezone.utc)
    outcomes = iter(
        (
            {"http_status": 500, "response_bytes": 21},
            {
                "http_status": 200,
                "last_observed_at": baseline.isoformat(),
            },
            {
                "http_status": 200,
                "last_observed_at": (baseline + timedelta(seconds=1)).isoformat(),
                "driver_state": "READY",
            },
        )
    )
    monkeypatch.setenv("SPELL_API_BEARER_TOKEN", "not-reported")
    monkeypatch.setattr(probe, "_projection_observation", lambda _token: next(outcomes))
    monkeypatch.setattr(probe.time, "sleep", lambda _seconds: None)

    result = probe.api_projection(
        timeout_seconds=1,
        expected_status=200,
        must_advance_from=baseline.isoformat(),
    )

    assert result["observation_advanced"] is True
    assert result["driver_state"] == "READY"
    assert "not-reported" not in json.dumps(result)


def test_projection_probe_fails_closed_without_bearer_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SPELL_API_BEARER_TOKEN", raising=False)

    with pytest.raises(ValueError, match="SPELL_API_BEARER_TOKEN is required"):
        probe.api_projection(
            timeout_seconds=1,
            expected_status=200,
            must_advance_from=None,
        )
