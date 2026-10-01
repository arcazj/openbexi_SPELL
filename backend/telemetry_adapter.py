"""A bounded GetTM capability over immutable local synthetic observations."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .legacy_observation_v12 import MAX_PAGE, ReplayError, ReplaySource

PROFILE = "LOCAL_SYNTHETIC_TELEMETRY_ADAPTER"


class ComparisonQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")
    value_format: Literal["RAW", "ENG"] = "ENG"


class TMQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")
    value_format: Literal["RAW", "ENG"] = "ENG"
    wait: bool = False
    after: str | None = Field(None, min_length=1, max_length=220)
    timeout_ms: int | None = Field(None, ge=0, le=60_000)
    extended: bool = False

    @model_validator(mode="after")
    def check_wait(self):
        if self.wait and self.after is None:
            raise ValueError("Wait requires a source-bound cursor")
        if not self.wait and (self.after is not None or self.timeout_ms is not None):
            raise ValueError("Cursor and Timeout require Wait")
        return self


def profile() -> dict:
    value = json.loads((Path(__file__).resolve().parents[1] / "contracts/v14/telemetry_profile.json").read_bytes())
    if value["profile"] != PROFILE or value["methods"] != ["GetTM", "Catalog", "Compare"]:
        raise RuntimeError("telemetry profile differs")
    return value


def _origin_time(source: ReplaySource, after: str) -> tuple[str, int]:
    # Public replay validates identity, digest, epoch, future positions and gaps.
    check = source.replay(after, MAX_PAGE)
    if check["outcome"] != "OK":
        return check["outcome"], 0
    if after == source.cursor(0):
        return "OK", 0
    cursor = source.cursor(0)
    while True:
        page = source.replay(cursor, MAX_PAGE)
        if page["outcome"] != "OK":
            return page["outcome"], 0
        for item in page["items"]:
            if item["cursor"] == after:
                return "OK", int(item["time_ns"])
        if not page["has_more"]:
            raise ReplayError("INVALID_CURSOR")
        cursor = page["cursor"]


def get_tm(source: ReplaySource, item_id: str, query: TMQuery) -> dict:
    result = source.get_tm(item_id, query.after if query.wait else None, query.value_format)
    if query.wait:
        origin_outcome, origin_ns = _origin_time(source, query.after)
        if origin_outcome != "OK":
            result = {"outcome": origin_outcome, "value": None}
        elif result["outcome"] == "NOT_AVAILABLE":
            result = {"outcome": "TIMEOUT", "value": None}
        elif "sample" in result:
            elapsed_ns = int(result["sample"]["time_ns"]) - origin_ns
            budget_ns = (60_000 if query.timeout_ms is None else query.timeout_ms) * 1_000_000
            if elapsed_ns < 0:
                result = {"outcome": "TIME_REGRESSION", "value": None}
            elif elapsed_ns > budget_ns:
                result = {"outcome": "TIMEOUT", "value": None}
    sample = result.get("sample") if query.extended else None
    if sample is not None and result["outcome"] != "OK":
        sample = {**sample, "raw": None, "eng": None}
    return {"profile": PROFILE, "source": source.identity(), "item_id": item_id,
            "outcome": result["outcome"], "value": result["value"], "sample": sample,
            "cursor": result.get("sample", {}).get("cursor", query.after),
            "modifiers": query.model_dump(), "effect_certainty": "NO_MUTATION",
            "legacy_system_qualified": False}


def compare_tm(reference: ReplaySource, simulator: ReplaySource, item_id: str,
               value_format: Literal["RAW", "ENG"] = "ENG") -> dict:
    query = TMQuery(value_format=value_format, extended=True)
    left, right = get_tm(reference, item_id, query), get_tm(simulator, item_id, query)
    outcomes = {left["outcome"], right["outcome"]}
    differences = []
    if outcomes & {"UNSUPPORTED", "NOT_FOUND"}:
        classification = "UNSUPPORTED"
    elif outcomes != {"OK"}:
        classification = "INDETERMINATE"
    else:
        differences = [field for field in ("raw", "eng", "unit", "time_ns", "validity", "quality")
                       if left["sample"][field] != right["sample"][field]]
        classification = "DIFFERENT" if differences else "EQUIVALENT"
    return {"profile": PROFILE, "item_id": item_id, "classification": classification,
            "differences": differences, "reference": left, "simulator": right,
            "legacy_system_qualified": False, "effect_certainty": "NO_MUTATION"}
