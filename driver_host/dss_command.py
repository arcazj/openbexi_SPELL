"""Actual CCSDS Cortex transport with a durable no-resend driver journal."""
from __future__ import annotations

import hashlib
import json
import socket
import re
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Callable

from dss.packets import ACK_APID, decode_packet, encode_tc, recv_packet
from dss.catalog import validate_command
from .dss_config import DssConfig

STAGES = frozenset({"TRANSPORT", "LOADING", "RELEASE", "ACKNOWLEDGEMENT", "ONBOARD_EXECUTION", "VERIFICATION"})
OUTCOMES = {"TRANSPORT": {"ACCEPTED", "REJECTED", "UNCERTAIN"}, "LOADING": {"LOADED", "FAILED", "UNCERTAIN"}, "RELEASE": {"RELEASED", "FAILED", "UNCERTAIN"}, "ACKNOWLEDGEMENT": {"ACKNOWLEDGED", "NACKED", "TIMED_OUT", "UNCERTAIN"}, "ONBOARD_EXECUTION": {"SUCCEEDED", "FAILED", "UNCERTAIN"}, "VERIFICATION": {"PASSED", "FAILED", "INDETERMINATE"}}
CORRELATIONS = ("database_revision", "database_digest", "satellite_id", "satellite_epoch", "scenario_id", "operation_id", "procedure_id", "execution_id", "plan_id", "element_id", "stage", "command_name", "command_digest")


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


class DssUnavailable(RuntimeError):
    """Bounded error; callers must never replace it with a nominal outcome."""


class DssCommandDriver:
    def __init__(self, config: DssConfig, *, connect: Callable[..., Any] = socket.create_connection):
        self.config = config
        self._connect = connect
        self._lock = threading.RLock()
        config.journal_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(config.journal_path, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute("CREATE TABLE IF NOT EXISTS command_stage (identity TEXT PRIMARY KEY, request_hash TEXT NOT NULL, request BLOB NOT NULL, ack BLOB, dispatched_ns INTEGER NOT NULL, elapsed_ns INTEGER, state TEXT NOT NULL)")
        self._db.commit()

    def perform(self, body: dict[str, Any]) -> dict[str, Any]:
        # Codec and immutable shared database validate all fields before intent.
        validate_command(body["command_name"], body["arguments"])
        if (any(type(body.get(name)) is not str or not 1 <= len(body[name]) <= 256 for name in CORRELATIONS)
            or body.get("schema_version") != "openbexi.dss.tc/1"
            or re.fullmatch(r"[0-9a-f]{64}", body["command_digest"]) is None):
            raise ValueError("DSS command correlations are invalid")
        raw = encode_tc(body)
        if len(raw) > 60_000 or body.get("stage") not in STAGES:
            raise ValueError("DSS command exceeds the bounded transport profile")
        identity = hashlib.sha256(canonical([body[name] for name in ("satellite_epoch", "operation_id", "plan_id", "element_id", "stage")])).hexdigest()
        request_hash = hashlib.sha256(raw).hexdigest()
        with self._lock:
            prior = self._db.execute("SELECT request_hash,ack,state,elapsed_ns FROM command_stage WHERE identity=?", (identity,)).fetchone()
            if prior:
                if prior[0] != request_hash:
                    raise ValueError("DSS command identity conflicts with its durable intent")
                if prior[2] != "SETTLED" or prior[1] is None:
                    raise DssUnavailable("DSS command dispatch is unresolved; resend is forbidden")
                return self._result(raw, bytes(prior[1]), int(prior[3] or 0))
            self._db.execute("INSERT INTO command_stage VALUES(?,?,?,NULL,?,NULL,'DISPATCHED')", (identity, request_hash, raw, time.time_ns()))
            self._db.commit()
        started = time.monotonic_ns()
        try:
            with self._connect((self.config.cortex_host, self.config.cortex_port), timeout=self.config.timeout_seconds) as peer:
                peer.settimeout(self.config.timeout_seconds)
                peer.sendall(raw)
                ack_raw = recv_packet(peer)
            if len(ack_raw) > 60_000:
                raise ValueError("DSS acknowledgement exceeds the RPC bound")
            packet = decode_packet(ack_raw)
            ack = packet.body
            if packet.packet_type != 0 or packet.apid != ACK_APID:
                raise ValueError("DSS acknowledgement packet type differs")
            if any(ack.get(name) != body.get(name) for name in CORRELATIONS):
                raise ValueError("DSS acknowledgement correlation differs")
            if ack.get("schema_version") != "openbexi.dss.ack/1":
                raise ValueError("DSS acknowledgement profile differs")
            if (type(ack.get("outcome")) is not str or ack["outcome"] not in OUTCOMES[body["stage"]]
                or any(type(ack.get(name)) is not int or not 0 <= ack[name] < 2**63 for name in ("state_revision", "tm_sequence", "ack_sequence"))):
                raise ValueError("DSS acknowledgement stage or revision is invalid")
            if packet.sequence != ack["ack_sequence"] & 0x3fff:
                raise ValueError("DSS acknowledgement sequence differs")
            elapsed = time.monotonic_ns() - started
            with self._lock:
                self._db.execute("UPDATE command_stage SET ack=?,elapsed_ns=?,state='SETTLED' WHERE identity=? AND state='DISPATCHED'", (ack_raw, elapsed, identity))
                self._db.commit()
            return self._result(raw, ack_raw, elapsed)
        except (OSError, ValueError, TimeoutError) as exc:
            # The durable DISPATCHED record intentionally survives every ambiguity.
            raise DssUnavailable("DSS command acknowledgement is unavailable or invalid") from exc

    @staticmethod
    def _result(raw: bytes, ack: bytes, elapsed_ns: int) -> dict[str, Any]:
        return {"acknowledgement_packet": ack, "command_packet_sha256": hashlib.sha256(raw).hexdigest(), "acknowledgement_packet_sha256": hashlib.sha256(ack).hexdigest(), "elapsed_ns": elapsed_ns}

    def close(self) -> None:
        with self._lock:
            self._db.close()
