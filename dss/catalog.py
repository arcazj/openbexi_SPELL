"""One immutable satellite definition shared by DSS, CMD and TLM."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path

DATABASE_PATH = Path(__file__).resolve().parents[1] / "contracts/dss/satellite_database.json"


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate satellite database field")
        result[key] = value
    return result


@dataclass(frozen=True)
class SatelliteDatabase:
    revision: str
    digest: str
    commands: tuple[dict, ...]
    telemetry: tuple[dict, ...]
    material: dict

    @classmethod
    def load(cls, path: Path = DATABASE_PATH) -> "SatelliteDatabase":
        raw = path.read_bytes()
        if not 1 <= len(raw) <= 262144:
            raise ValueError("satellite database size is outside bounds")
        data = json.loads(raw, object_pairs_hook=_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite database value")))
        if (data["schema_version"] != "openbexi.dss.satellite-database/1"
                or data["satellite_id"] != "GENERIC" or data["simulator_only"] is not True):
            raise ValueError("satellite database identity differs")
        commands, telemetry = data["commands"], data["telemetry"]
        for rows, name, code in ((commands, "name", "command_code"), (telemetry, "item_id", "item_code")):
            if (not 1 <= len(rows) <= 128 or len({r[name] for r in rows}) != len(rows)
                    or len({r[code] for r in rows}) != len(rows)
                    or any(type(r[code]) is not int or not 1 <= r[code] <= 65535 for r in rows)):
                raise ValueError("satellite database definitions are ambiguous")
        if data["packet_apids"] != {"tc":100,"tm":101,"ack":102}:
            raise ValueError("packet APID definitions differ")
        return cls(data["revision"], hashlib.sha256(raw).hexdigest(), tuple(commands), tuple(telemetry), data)

    def command(self, name: str) -> dict:
        for row in self.commands:
            if row["name"] == name:
                return row
        raise ValueError("command is not in the GENERIC satellite database")

    def item(self, name: str) -> dict:
        for row in self.telemetry:
            if row["item_id"] == name:
                return row
        raise ValueError("telemetry item is not in the GENERIC satellite database")


def load_database() -> dict:
    return json.loads(DATABASE_PATH.read_bytes())


_DATABASE = SatelliteDatabase.load()
DATABASE_REVISION, DATABASE_DIGEST = _DATABASE.revision, _DATABASE.digest
TELEMETRY_ITEMS = tuple(dict(row, catalog_digest=(DATABASE_DIGEST if row["logical_catalog_digest"] == "DATABASE"
    else row["logical_catalog_digest"])) for row in _DATABASE.telemetry)


def validate_command(name: str, arguments: list) -> None:
    definition = _DATABASE.command(name)
    if type(arguments) is not list or len(arguments) > 16:
        raise ValueError("command arguments are outside bounds")
    expected = {row["name"]: row for row in definition["arguments"]}
    seen = set()
    for argument in arguments:
        if (type(argument) is not dict or set(argument) != {"name", "value", "value_type", "value_format", "radix", "encoded"}
                or argument.get("name") not in expected or argument["name"] in seen):
            raise ValueError("unknown or duplicate command argument")
        seen.add(argument["name"])
        item, value = expected[argument["name"]], argument.get("value")
        kind = item["value_type"]
        if argument.get("value_type") != kind:
            raise ValueError("argument type differs from satellite database")
        valid = ((kind == "FLOAT" and type(value) in {int,float} and math.isfinite(value))
            or (kind == "LONG" and type(value) is int and -(1<<63) <= value < (1<<63))
            or (kind == "BOOLEAN" and type(value) is bool)
            or (kind == "STRING" and type(value) is str and len(value) <= 256))
        if not valid: raise ValueError("argument value differs from database type/bounds")
        if kind in {"LONG","FLOAT"} and not item["minimum"] <= value <= item["maximum"]:
            raise ValueError("argument value exceeds database range")
        if item["allowed_values"] and value not in item["allowed_values"]:
            raise ValueError("argument value is not a database enumeration")
        if argument["value_format"] not in item["allowed_formats"]:
            raise ValueError("argument format differs from satellite database")
        radix = argument["radix"]
        if radix not in {"DEC", "HEX", "OCT", "BIN"} or (kind != "LONG" and radix != "DEC"):
            raise ValueError("argument radix differs from database type")
        if kind == "LONG" and radix != "DEC":
            encoded = {"HEX": lambda: f"0x{value:X}", "OCT": lambda: f"0o{value:o}", "BIN": lambda: f"0b{value:b}"}[radix]()
        elif kind == "FLOAT": encoded = format(value, ".17g")
        elif kind == "BOOLEAN": encoded = "true" if value else "false"
        else: encoded = str(value)
        if type(argument["encoded"]) is not str or argument["encoded"] != encoded:
            raise ValueError("argument encoding differs from typed value")
    if any(row["required"] and row["name"] not in seen for row in expected.values()):
        raise ValueError("required command argument is missing")
