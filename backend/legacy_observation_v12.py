"""Bounded, immutable read-only translation of offline SPELL observation captures.

The bundled captures are independently authored synthetic reference fixtures.
This module has no network, command, credential, or executable legacy interface.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .condition_engine import TypedScalar

SCHEMA = "spell.legacy-observation-capture/1"
MAX_CAPTURE_BYTES = 1_048_576
MAX_ITEMS = 128
MAX_SAMPLES = 4096
MAX_PAGE = 256
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_DECIMAL = re.compile(r"(?:0|[1-9][0-9]{0,19})\Z")
_TYPES = {"BOOLEAN", "INT64", "UINT64", "FINITE_DOUBLE", "STRING", "BYTES"}
_ROOT = Path(__file__).resolve().parents[1] / "contracts" / "v12"


class ReplayError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _require(condition: bool, code: str = "INVALID_CAPTURE") -> None:
    if not condition:
        raise ReplayError(code)


def _keys(value: Any, required: set[str]) -> None:
    _require(type(value) is dict and set(value) == required)


def _name(value: Any) -> str:
    _require(type(value) is str and _NAME.fullmatch(value) is not None)
    return value


def _number(value: Any, maximum: int = 2**64 - 1) -> int:
    _require(type(value) is str and _DECIMAL.fullmatch(value) is not None)
    result = int(value)
    _require(result <= maximum)
    return result


def _scalar(value: Any, kind: str | None = None) -> dict[str, Any]:
    try:
        scalar = TypedScalar.from_dict(value)
        result = scalar.as_dict()
    except (TypeError, ValueError, OverflowError, UnicodeError) as exc:
        raise ReplayError("INVALID_SCALAR") from exc
    _require(kind is None or result["type"] == kind, "TYPE_MISMATCH")
    return result


def _pairs(pairs: list[tuple[str, Any]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        _require(key not in result, "DUPLICATE_FIELD")
        result[key] = value
    return result


def _decode(data: bytes) -> dict:
    _require(type(data) is bytes and 0 < len(data) <= MAX_CAPTURE_BYTES, "CAPTURE_BOUNDS")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ReplayError("INVALID_NUMBER")))
        # Validate UTF-8 scalar strings and finite JSON, including unsupported payloads.
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
        _require(len(encoded) <= MAX_CAPTURE_BYTES, "CAPTURE_BOUNDS")
    except (UnicodeError, ValueError, RecursionError, OverflowError) as exc:
        if isinstance(exc, ReplayError):
            raise
        raise ReplayError("INVALID_CAPTURE") from exc
    return value


@dataclass(frozen=True)
class ReplaySource:
    """Canonical bytes are the only retained state; callers cannot mutate the source."""

    _canonical: bytes
    digest: str

    @classmethod
    def from_bytes(cls, data: bytes) -> "ReplaySource":
        capture = _decode(data)
        _keys(capture, {"schema_version", "reference_version", "source_id", "epoch",
                        "provenance", "clock_ns", "connected", "catalog", "samples",
                        "resources", "limits"})
        _require(capture["schema_version"] == SCHEMA, "UNSUPPORTED_SCHEMA")
        _require(capture["reference_version"] == "2.4.4", "UNSUPPORTED_REFERENCE")
        _require(capture["provenance"] == "INDEPENDENT_SYNTHETIC_FIXTURE", "UNQUALIFIED_SOURCE")
        _name(capture["source_id"])
        _name(capture["epoch"])
        clock = _number(capture["clock_ns"], 2**63 - 1)
        _require(type(capture["connected"]) is bool)
        catalog = capture["catalog"]
        _require(type(catalog) is list and 0 < len(catalog) <= MAX_ITEMS, "CATALOG_BOUNDS")
        by_id = {}
        for entry in catalog:
            _keys(entry, {"item_id", "raw_type", "eng_type", "unit", "max_age_ns"})
            item_id = _name(entry["item_id"])
            _require(item_id not in by_id, "DUPLICATE_ITEM")
            _name(entry["raw_type"])
            _name(entry["eng_type"])
            _require(type(entry["unit"]) is str and len(entry["unit"].encode("utf-8")) <= 64)
            _number(entry["max_age_ns"], 2**63 - 1)
            by_id[item_id] = entry
        samples = capture["samples"]
        _require(type(samples) is list and len(samples) <= MAX_SAMPLES, "SAMPLE_BOUNDS")
        previous = 0
        times: dict[str, int] = {}
        for sample in samples:
            _keys(sample, {"sequence", "item_id", "time_ns", "raw", "eng", "valid", "quality"})
            item_id = _name(sample["item_id"])
            _require(item_id in by_id, "UNKNOWN_ITEM")
            sequence = _number(sample["sequence"])
            time = _number(sample["time_ns"], 2**63 - 1)
            _require(sequence > previous and times.get(item_id, 0) <= time <= clock, "INVALID_ORDER")
            previous = sequence
            times[item_id] = time
            _require(sample["valid"] is None or type(sample["valid"]) is bool)
            _require(type(sample["quality"]) is str and sample["quality"] in {"GOOD", "BAD", "SUSPECT", "UNKNOWN"})
            for field in ("raw", "eng"):
                kind = by_id[item_id][field + "_type"]
                if kind in _TYPES:
                    sample[field] = _scalar(sample[field], kind)
                else:
                    # Unsupported legacy encodings carry no ambiguous value across the boundary.
                    _require(sample[field] is None, "UNSUPPORTED_PAYLOAD")
        resources = capture["resources"]
        _require(type(resources) is dict and len(resources) <= MAX_ITEMS, "RESOURCE_BOUNDS")
        for name, value in resources.items():
            _name(name)
            resources[name] = _scalar(value)
        limits = capture["limits"]
        _require(type(limits) is dict and len(limits) <= MAX_ITEMS, "LIMIT_BOUNDS")
        for item_id, definition in limits.items():
            _require(item_id in by_id, "UNKNOWN_ITEM")
            _keys(definition, {"enabled", "lower", "upper"})
            _require(type(definition["enabled"]) is bool)
            kind = by_id[item_id]["eng_type"]
            _require(kind in {"INT64", "UINT64", "FINITE_DOUBLE"}, "UNSUPPORTED_LIMIT")
            definition["lower"] = _scalar(definition["lower"], kind)
            definition["upper"] = _scalar(definition["upper"], kind)
            lower = TypedScalar.from_dict(definition["lower"]).value
            upper = TypedScalar.from_dict(definition["upper"]).value
            _require(lower <= upper, "INVALID_LIMIT_ORDER")
        canonical = json.dumps(capture, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
        return cls(canonical, hashlib.sha256(canonical).hexdigest())

    def _capture(self) -> dict:
        return json.loads(self._canonical)

    def identity(self) -> dict:
        capture = self._capture()
        return {key: capture[key] for key in ("source_id", "epoch", "reference_version", "provenance")} | {
            "digest": self.digest, "mutability": "READ_ONLY", "live": False,
            "clock": "RECORDED_LOGICAL_TIME", "clock_ns": capture["clock_ns"],
        }

    def catalog(self) -> dict:
        return {"source": self.identity(), "items": self._capture()["catalog"]}

    def cursor(self, sequence: int) -> str:
        capture = self._capture()
        return f"{capture['source_id']}:{capture['epoch']}:{self.digest}:{sequence}"

    def _sequence(self, cursor: str) -> int:
        _require(type(cursor) is str and len(cursor) <= 220, "INVALID_CURSOR")
        fields = cursor.split(":")
        _require(len(fields) == 4, "INVALID_CURSOR")
        try:
            sequence = _number(fields[3])
        except ReplayError as exc:
            raise ReplayError("INVALID_CURSOR") from exc
        _require(cursor == self.cursor(sequence), "STALE_SOURCE")
        return sequence

    def _sample(self, sample: dict, now: int | None = None, capture: dict | None = None) -> dict:
        capture = self._capture() if capture is None else capture
        entry = next(item for item in capture["catalog"] if item["item_id"] == sample["item_id"])
        now = int(capture["clock_ns"]) if now is None else now
        validity = "UNKNOWN" if sample["valid"] is None else "VALID" if sample["valid"] else "INVALID"
        outcome = "OK"
        if entry["raw_type"] not in _TYPES or entry["eng_type"] not in _TYPES:
            outcome = "UNSUPPORTED"
        elif not capture["connected"]:
            outcome = "DISCONNECTED"
        elif validity != "VALID" or sample["quality"] != "GOOD":
            outcome = "INDETERMINATE"
        elif now - int(sample["time_ns"]) > int(entry["max_age_ns"]):
            outcome = "STALE"
        return {key: sample[key] for key in ("item_id", "sequence", "time_ns", "raw", "eng", "quality")} | {
            "validity": validity, "unit": entry["unit"], "outcome": outcome,
            "cursor": f"{capture['source_id']}:{capture['epoch']}:{self.digest}:{sample['sequence']}",
        }

    def snapshot(self) -> dict:
        capture = self._capture()
        latest = {sample["item_id"]: sample for sample in capture["samples"]}
        items = [self._sample(latest[entry["item_id"]], capture=capture) if entry["item_id"] in latest else {
            "item_id": entry["item_id"], "outcome": "NOT_AVAILABLE", "raw": None,
            "eng": None, "unit": entry["unit"], "validity": "UNKNOWN", "quality": "UNKNOWN",
        } for entry in capture["catalog"]]
        sequence = int(capture["samples"][-1]["sequence"]) if capture["samples"] else 0
        return {"source": self.identity(), "connected": capture["connected"],
                "items": items, "cursor": self.cursor(sequence),
                "resources": capture["resources"] if capture["connected"] else {},
                "limits": capture["limits"] if capture["connected"] else {}}

    def replay(self, after: str, limit: int = 64) -> dict:
        _require(type(limit) is int and 1 <= limit <= MAX_PAGE, "INVALID_PAGE_SIZE")
        sequence = self._sequence(after)
        capture = self._capture()
        last = int(capture["samples"][-1]["sequence"]) if capture["samples"] else 0
        _require(sequence <= last, "FUTURE_CURSOR")
        rows = [row for row in capture["samples"] if int(row["sequence"]) > sequence][:limit]
        outcome = "OK" if capture["connected"] else "DISCONNECTED"
        if any(int(row["sequence"]) != sequence + index + 1 for index, row in enumerate(rows)):
            outcome = "GAP"
        if outcome != "OK":
            return {"source": self.identity(), "outcome": outcome, "items": [],
                    "cursor": after, "snapshot_required": True, "has_more": False}
        # Replay samples are judged at their acquisition clock, not at the capture's final clock.
        cursor = self.cursor(int(rows[-1]["sequence"])) if rows else after
        return {"source": self.identity(), "outcome": outcome,
                "items": [self._sample(row, int(row["time_ns"]), capture) for row in rows],
                "cursor": cursor, "snapshot_required": False,
                "has_more": bool(rows and int(rows[-1]["sequence"]) < last)}

    def get_tm(self, item_id: str, after: str | None = None, value_format: str = "ENG") -> dict:
        _name(item_id)
        _require(value_format in {"RAW", "ENG"}, "UNSUPPORTED_FORMAT")
        capture = self._capture()
        if item_id not in {item["item_id"] for item in capture["catalog"]}:
            return {"outcome": "NOT_FOUND", "value": None}
        if after is None:
            candidates = [item for item in self.snapshot()["items"] if item["item_id"] == item_id]
        else:
            # Traverse every page so a gap on another item cannot be silently crossed.
            candidates = []
            cursor = after
            while True:
                page = self.replay(cursor, MAX_PAGE)
                if page["outcome"] != "OK":
                    return {"outcome": page["outcome"], "value": None}
                candidates = [item for item in page["items"] if item["item_id"] == item_id]
                if candidates or not page["has_more"]:
                    break
                cursor = page["cursor"]
        if not candidates:
            return {"outcome": "NOT_AVAILABLE", "value": None}
        item = candidates[0]
        return {"outcome": item["outcome"], "value": item[value_format.lower()] if item["outcome"] == "OK" else None,
                "sample": item}

    def read(self, category: str, item_id: str) -> dict:
        _name(item_id)
        _require(category in {"resources", "limits"}, "UNSUPPORTED_SERVICE")
        capture = self._capture()
        if not capture["connected"]:
            return {"outcome": "DISCONNECTED", "value": None}
        value = capture[category].get(item_id)
        return {"outcome": "OK" if value is not None else "NOT_FOUND", "value": value}


def compare(reference: ReplaySource, simulator: ReplaySource) -> dict:
    """Compare independently supplied typed snapshots; bad evidence cannot pass."""
    left, right = reference.snapshot(), simulator.snapshot()
    rows = []
    first = {item["item_id"]: item for item in left["items"]}
    second = {item["item_id"]: item for item in right["items"]}
    for item_id in sorted(first.keys() | second.keys()):
        a, b = first.get(item_id), second.get(item_id)
        classification, differences = "EQUIVALENT", []
        if a is None or b is None:
            classification = "UNSUPPORTED"
        elif "UNSUPPORTED" in {a["outcome"], b["outcome"]}:
            classification = "UNSUPPORTED"
        elif a["outcome"] != "OK" or b["outcome"] != "OK":
            classification = "INDETERMINATE"
        else:
            differences = [field for field in ("raw", "eng", "unit", "time_ns", "validity", "quality") if a.get(field) != b.get(field)]
            if differences:
                classification = "DIFFERENT"
        rows.append({"category": "telemetry", "item_id": item_id,
                     "classification": classification, "differences": differences})
    for category in ("resources", "limits"):
        known = reference._capture()[category].keys() | simulator._capture()[category].keys()
        for item_id in sorted(known):
            a, b = left[category].get(item_id), right[category].get(item_id)
            classification = "INDETERMINATE" if not left["connected"] or not right["connected"] else (
                "UNSUPPORTED" if a is None or b is None else "EQUIVALENT" if a == b else "DIFFERENT")
            rows.append({"category": category, "item_id": item_id, "classification": classification,
                         "differences": ["value"] if classification == "DIFFERENT" else []})
    return {"schema_version": "spell.v12.compatibility-report/1", "reference": reference.identity(),
            "simulator": simulator.identity(), "scope": "SYNTHETIC_REPLAY_ONLY",
            "legacy_system_qualified": False, "rows": rows,
            "counts": {key: sum(row["classification"] == key for row in rows) for key in
                       ("EQUIVALENT", "DIFFERENT", "INDETERMINATE", "UNSUPPORTED")}}


def load_sources() -> dict[str, ReplaySource]:
    manifest = json.loads((_ROOT / "replay_manifest.json").read_text(encoding="utf-8"))
    result = {}
    for name in ("reference", "simulator"):
        path = _ROOT / (name + "_capture.json")
        with path.open("rb") as stream:
            raw = stream.read(MAX_CAPTURE_BYTES + 1)
        _require(hashlib.sha256(raw).hexdigest() == manifest["captures"][name], "CAPTURE_DIGEST_MISMATCH")
        result[name] = ReplaySource.from_bytes(raw)
    return result
