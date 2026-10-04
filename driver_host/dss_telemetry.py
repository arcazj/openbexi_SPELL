"""Kafka binary telemetry consumer and restart-safe packet provenance ledger."""
from __future__ import annotations

import asyncio
import hashlib
import json
import math
import re
import sqlite3
import threading
import time
from typing import Any

from dss.packets import ACK_APID, TM_APID, decode_packet
from .dss_command import canonical, DssUnavailable
from .dss_config import DssConfig
from .observation import (CATALOG_ITEMS, CATALOG_DIGEST, CatalogItem, ClockReading, ClockSource, Gap, ObservationCode, ObservationFailure, Quality, ScalarKind, ScalarValue, TelemetrySample, Validity)

SOURCE_ID = "dss-GENERIC"
CLOCK_PROVENANCE = "dss-dynamics-clock"
TM_TOPIC = "openbexi.GENERIC.tm"
ACK_TOPIC = "openbexi.GENERIC.ack"
# Logical live NEXT retention is separate from the complete packet proof ledger.
NEXT_WINDOW_PACKETS = 8


class DssTelemetryDriver:
    source_id = SOURCE_ID
    catalog_digest = CATALOG_DIGEST
    def __init__(self, config: DssConfig):
        self.config = config
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._connected = False
        self._error = "NOT_STARTED"
        config.journal_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(config.journal_path, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute("CREATE TABLE IF NOT EXISTS dss_packet (id INTEGER PRIMARY KEY, topic TEXT NOT NULL, partition_id INTEGER NOT NULL, offset_id INTEGER NOT NULL, packet BLOB NOT NULL, packet_hash TEXT NOT NULL, body TEXT NOT NULL, epoch TEXT NOT NULL, sequence_id INTEGER NOT NULL, operation_id TEXT NOT NULL, received_ns INTEGER NOT NULL, UNIQUE(topic,partition_id,offset_id))")
        self._db.execute("CREATE INDEX IF NOT EXISTS dss_packet_epoch ON dss_packet(epoch,sequence_id)")
        # The topic/partition/offset uniqueness index otherwise makes SQLite
        # sort every retained packet body for each current-value read.
        self._db.execute("CREATE INDEX IF NOT EXISTS dss_packet_topic_latest ON dss_packet(topic,id)")
        self._db.execute("CREATE INDEX IF NOT EXISTS dss_packet_topic_cursor ON dss_packet(topic,epoch,sequence_id)")
        self._db.execute("CREATE INDEX IF NOT EXISTS dss_packet_hash ON dss_packet(packet_hash)")
        self._db.commit()

    def ingest(self, topic: str, partition: int, offset: int, raw: bytes) -> None:
        if topic not in {TM_TOPIC, ACK_TOPIC} or type(partition) is not int or partition < 0 or type(offset) is not int or offset < 0:
            raise ValueError("DSS Kafka provenance is invalid")
        if type(raw) is not bytes or not 6 <= len(raw) <= 60_000:
            raise ValueError("DSS Kafka packet size is invalid")
        packet = decode_packet(raw)
        body = packet.body
        expected_schema = "openbexi.dss.tm/1" if topic == TM_TOPIC else "openbexi.dss.ack/1"
        if (packet.packet_type != 0 or packet.apid != (TM_APID if topic == TM_TOPIC else ACK_APID)
                or body.get("schema_version") != expected_schema or body.get("satellite_id") != "GENERIC"):
            raise ValueError("DSS packet topic/profile differs")
        from dss.catalog import DATABASE_REVISION, DATABASE_DIGEST
        if body.get("database_revision") != DATABASE_REVISION or body.get("database_digest") != DATABASE_DIGEST:
            raise ValueError("DSS packet database identity differs")
        epoch, sequence = body.get("satellite_epoch"), body.get("tm_sequence")
        if type(epoch) is not str or re.fullmatch(r"epoch-[0-9a-f]{64}", epoch) is None or type(sequence) is not int or not 0 <= sequence < 2**63:
            raise ValueError("DSS packet cursor is invalid")
        primary_sequence = sequence if topic == TM_TOPIC else body.get("ack_sequence")
        if type(primary_sequence) is not int or not 0 <= primary_sequence < 2**63 or packet.sequence != primary_sequence & 0x3fff:
            raise ValueError("DSS primary sequence differs from its payload")
        if topic == TM_TOPIC:
            self._validate_items(body)
        digest = hashlib.sha256(raw).hexdigest()
        with self._lock:
            prior = self._db.execute("SELECT packet_hash FROM dss_packet WHERE topic=? AND partition_id=? AND offset_id=?", (topic, partition, offset)).fetchone()
            if prior:
                if prior[0] != digest:
                    raise ValueError("DSS Kafka offset was reused with different bytes")
                return
            if topic == TM_TOPIC:
                prior_sequence = self._db.execute("SELECT packet_hash FROM dss_packet WHERE topic=? AND epoch=? AND sequence_id=?", (topic, epoch, sequence)).fetchone()
                if prior_sequence is not None and prior_sequence[0] != digest:
                    raise ValueError("DSS telemetry sequence was reused with different packet bytes")
                latest_sequence = self._db.execute("SELECT MAX(sequence_id) FROM dss_packet WHERE topic=? AND epoch=?", (topic, epoch)).fetchone()[0]
                if latest_sequence is not None and sequence < latest_sequence:
                    raise ValueError("DSS telemetry sequence moved backwards")
            self._db.execute("INSERT INTO dss_packet(topic,partition_id,offset_id,packet,packet_hash,body,epoch,sequence_id,operation_id,received_ns) VALUES(?,?,?,?,?,?,?,?,?,?)", (topic, partition, offset, raw, digest, canonical(body).decode("ascii"), epoch, sequence, body.get("operation_id", ""), time.time_ns()))
            self._db.commit()

    @staticmethod
    def _validate_items(body: dict[str, Any]) -> None:
        from dss.catalog import TELEMETRY_ITEMS
        definitions = {item["item_id"]: item for item in TELEMETRY_ITEMS}
        if type(body.get("items")) is not list or len(body["items"]) > len(definitions):
            raise ValueError("DSS telemetry item list is invalid")
        if (body.get("source_id") != SOURCE_ID or body.get("clock_provenance") != CLOCK_PROVENANCE
            or type(body.get("clock_uncertainty_ns")) is not int or not 0 <= body["clock_uncertainty_ns"] <= 60_000_000_000
            or type(body.get("state_revision")) is not int or body["state_revision"] < 0):
            raise ValueError("DSS telemetry source/clock identity is invalid")
        driver_uncertainty = body.get("driver_time_uncertainty_ns", body["clock_uncertainty_ns"])
        if type(driver_uncertainty) is not int or not 0 <= driver_uncertainty <= 60_000_000_000:
            raise ValueError("DSS driver time uncertainty is invalid")
        if "running" in body and type(body["running"]) is not bool:
            raise ValueError("DSS dynamics running flag is invalid")
        seen = set()
        for item in body["items"]:
            definition = definitions.get(item.get("item_id")) if type(item) is dict else None
            if definition is None or item["item_id"] in seen:
                raise ValueError("DSS telemetry item is unknown or duplicated")
            seen.add(item["item_id"])
            for key in ("item_code", "catalog_digest", "qualified_name", "unit", "description"):
                if type(item.get(key)) is not type(definition[key]) or item.get(key) != definition[key]:
                    raise ValueError("DSS telemetry metadata differs from shared database")
            for field, kind in (("raw", definition["raw_type"]), ("engineering", definition["engineering_type"])):
                scalar = item.get(field)
                if type(scalar) is not dict or set(scalar) != {"type", "value"} or scalar["type"] != kind:
                    raise ValueError("DSS telemetry scalar type differs")
                value = scalar["value"]
                valid = ((kind == "BOOLEAN" and type(value) is bool)
                    or (kind == "UINT64" and type(value) is int and 0 <= value < 2**64)
                    or (kind == "INT64" and type(value) is int and -(2**63) <= value < 2**63)
                    or (kind == "FINITE_DOUBLE" and type(value) is float and math.isfinite(value))
                    or (kind == "STRING" and type(value) is str and len(value.encode("utf-8")) <= 4096))
                if not valid:
                    raise ValueError("DSS telemetry scalar value differs")
            expected = (float(item["raw"]["value"] * definition["engineering_scale"])
                        if definition["engineering_type"] == "FINITE_DOUBLE" else item["raw"]["value"])
            if type(item["engineering"]["value"]) is not type(expected) or item["engineering"]["value"] != expected:
                raise ValueError("DSS telemetry raw/engineering conversion differs")
            Validity(item["validity"])
            Quality(item["quality"])

    def _latest(self, *, require_fresh: bool = True) -> dict[str, Any]:
        with self._lock:
            row = self._db.execute("SELECT body,received_ns FROM dss_packet WHERE topic=? ORDER BY id DESC LIMIT 1", (TM_TOPIC,)).fetchone()
        if row is None or (require_fresh and time.time_ns() - row[1] > self.config.stale_seconds * 1e9):
            raise DssUnavailable("DSS telemetry is unavailable or stale")
        body = json.loads(row[0])
        acquired = body.get("acquired_at_unix_ns")
        if type(acquired) is not int or acquired <= 0 or (require_fresh and not 0 <= time.time_ns() - acquired <= self.config.stale_seconds * 1e9):
            raise DssUnavailable("DSS telemetry acquisition time is stale or invalid")
        return body

    def health(self, *, require_fresh: bool = True) -> dict[str, Any]:
        if require_fresh and self._thread is not None and not self._connected:
            raise DssUnavailable("DSS Kafka subscription is unavailable")
        body = self._latest(require_fresh=require_fresh)
        return {key: body[key] for key in ("database_revision", "database_digest", "satellite_id", "satellite_epoch", "scenario_id", "state_revision", "tm_sequence", "simulation_time_ns", "clock_epoch_unix_ns", "dynamics_tick")}

    def evidence(self, epoch: str, sequence: int = 0, operation_id: str = "", packet_sha256: str = "") -> list[dict[str, Any]]:
        if packet_sha256 and re.fullmatch(r"[0-9a-f]{64}", packet_sha256) is None:
            raise ValueError("DSS evidence digest selector is invalid")
        predicates, parameters = ["epoch=?"], [epoch]
        for field, value in (("sequence_id", sequence), ("operation_id", operation_id), ("packet_hash", packet_sha256)):
            if value:
                predicates.append(field + "=?")
                parameters.append(value)
        with self._lock:
            rows = self._db.execute("SELECT packet,packet_hash,topic,partition_id,offset_id,received_ns FROM dss_packet WHERE "
                + " AND ".join(predicates) + " ORDER BY id DESC LIMIT 16", parameters).fetchall()
        # A response remains below the driver RPC message bound.
        output, total = [], 0
        for row in rows:
            total += len(row[0]) + 512
            if total > 60_000:
                break
            output.append(dict(zip(("packet", "packet_sha256", "topic", "partition", "offset", "received_unix_ns"), row)))
        return output

    @staticmethod
    def _epoch(body: dict[str, Any]) -> str:
        return body["satellite_epoch"]

    def get_time(self) -> ClockReading:
        try:
            body = self._latest()
        except DssUnavailable as exc:
            raise ObservationFailure(ObservationCode.NOT_AVAILABLE, "DSS clock telemetry is unavailable") from exc
        return self._clock_reading(body)

    @staticmethod
    def _clock_reading(body: dict[str, Any]) -> ClockReading:
        stamp = body["acquired_at_unix_ns"]
        return ClockReading(body["clock_epoch_unix_ns"] + body["simulation_time_ns"], stamp,
            ClockSource.SIMULATOR, CLOCK_PROVENANCE,
            body.get("driver_time_uncertainty_ns", body["clock_uncertainty_ns"]))

    def clock_evidence(self) -> tuple[ClockReading, bytes]:
        body = self._latest()
        with self._lock:
            row = self._db.execute("SELECT packet FROM dss_packet WHERE topic=? AND epoch=? AND sequence_id=? LIMIT 1",
                (TM_TOPIC, body["satellite_epoch"], body["tm_sequence"])).fetchone()
        if row is None:
            raise DssUnavailable("DSS clock packet evidence is unavailable")
        return self._clock_reading(body), bytes(row[0])

    @staticmethod
    def _sample(item_id: str, body: dict[str, Any]) -> TelemetrySample:
        from dss.catalog import TELEMETRY_ITEMS
        metadata = next((item for item in TELEMETRY_ITEMS if item["item_id"] == item_id), None)
        if metadata is None:
            raise ObservationFailure(ObservationCode.NOT_FOUND, "DSS telemetry item is not in the selected logical catalog")
        definition = CatalogItem(item_id, metadata["qualified_name"], ScalarKind(metadata["raw_type"]), ScalarKind(metadata["engineering_type"]), metadata["unit"], metadata["description"])
        item = next((value for value in body["items"] if value["item_id"] == item_id), None)
        if item is None:
            raise ObservationFailure(ObservationCode.NOT_AVAILABLE, "DSS telemetry item is absent")
        epoch, sequence = DssTelemetryDriver._epoch(body), body["tm_sequence"]
        sample_id = hashlib.sha256(canonical({"item_id": item_id, "source_epoch": epoch, "source_id": SOURCE_ID, "source_sequence": str(sequence)})).hexdigest()
        quality, reason = Quality(item["quality"]), item.get("quality_reason", "dss-decoded-kafka")
        if body.get("freshness_policy_revision") != "v07-r1":
            quality, reason = Quality.UNKNOWN, "DSS_POLICY_REVISION_MISMATCH"
        elif body.get("synchronization_state") != "COMPLETE":
            quality, reason = Quality.UNKNOWN, "DSS_SOURCE_GAP"
        return TelemetrySample(sample_id, definition, epoch, sequence,
            ScalarValue(definition.raw_type, item["raw"]["value"]), ScalarValue(definition.engineering_type, item["engineering"]["value"]),
            body["acquired_at_unix_ns"], CLOCK_PROVENANCE, body["clock_uncertainty_ns"],
            Validity(item["validity"]), quality, reason)

    @staticmethod
    def catalog_digest_for(item_id: str) -> str:
        from dss.catalog import TELEMETRY_ITEMS
        return next(item["catalog_digest"] for item in TELEMETRY_ITEMS if item["item_id"] == item_id)

    async def current(self, item_id: str) -> TelemetrySample:
        try:
            return self._sample(item_id, self._latest(require_fresh=False))
        except DssUnavailable as exc:
            raise ObservationFailure(ObservationCode.NOT_AVAILABLE, "DSS telemetry is unavailable") from exc

    async def next(self, item_id: str, source_epoch: str, after_sequence: int, deadline_unix_ns: int) -> TelemetrySample:
        while time.time_ns() < deadline_unix_ns:
            try:
                latest = self._latest(require_fresh=False)
                if self._epoch(latest) != source_epoch:
                    raise ObservationFailure(ObservationCode.STALE_GENERATION, "DSS satellite epoch changed; CURRENT resynchronization is required")
                first_live = max(1, latest["tm_sequence"] - NEXT_WINDOW_PACKETS + 1)
                if after_sequence + 1 < first_live:
                    raise ObservationFailure(ObservationCode.GAP,
                        "DSS cursor precedes the bounded live NEXT window; CURRENT resynchronization is required",
                        gap=Gap(source_epoch, first_live, latest["tm_sequence"]))
                with self._lock:
                    row = self._db.execute("SELECT body FROM dss_packet WHERE topic=? AND epoch=? AND sequence_id>? ORDER BY sequence_id LIMIT 1", (TM_TOPIC, latest["satellite_epoch"], after_sequence)).fetchone()
                if row:
                    body = json.loads(row[0])
                    if body["tm_sequence"] != after_sequence + 1:
                        raise ObservationFailure(ObservationCode.GAP, "DSS Kafka telemetry sequence gap", gap=Gap(source_epoch, body["tm_sequence"], latest["tm_sequence"]))
                    return self._sample(item_id, body)
            except DssUnavailable:
                pass
            await asyncio.sleep(0.025)
        raise ObservationFailure(ObservationCode.DEADLINE_EXCEEDED, "DSS telemetry NEXT deadline elapsed")

    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(target=self._consume, name="dss-kafka-telemetry", daemon=True)
            self._thread.start()

    def _consume(self) -> None:
        from kafka import KafkaConsumer, TopicPartition, OffsetAndMetadata
        while not self._stop.is_set():
            consumer = None
            try:
                consumer = KafkaConsumer(TM_TOPIC, ACK_TOPIC, bootstrap_servers=self.config.kafka_bootstrap,
                    group_id="openbexi-spell-dss-driver", enable_auto_commit=False, auto_offset_reset="earliest",
                    consumer_timeout_ms=500, request_timeout_ms=10_000, session_timeout_ms=6_000,
                    max_partition_fetch_bytes=1_048_576)
                self._connected = True
                while not self._stop.is_set():
                    for message in consumer:
                        self.ingest(message.topic, message.partition, message.offset, bytes(message.value))
                        consumer.commit({TopicPartition(message.topic, message.partition): OffsetAndMetadata(message.offset + 1, "")})
                        if self._stop.is_set():
                            break
                self._error = "STOPPED"
            except Exception:
                self._connected = False
                self._error = "KAFKA_OR_PACKET_UNAVAILABLE"
                self._stop.wait(0.5)
            finally:
                if consumer is not None:
                    consumer.close()

    def close(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=12)
        with self._lock:
            self._db.close()
