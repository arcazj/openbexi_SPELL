"""Bounded local DSS transports over one durable satellite engine.

The outbox is at-least-once across a process crash. Consumers deduplicate the
immutable epoch/sequence identity; a Kafka receipt never re-executes a TC.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import math
import os
import signal
import socket
import socketserver
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .catalog import SatelliteDatabase, canonical, validate_command
from .engine import DssConflict, DssEngine
from .packets import decode_tc, decode_tm, encode_tc, encode_tm, recv_packet

LOG = logging.getLogger("dss")
MAX_BODY = 65_536
MAX_RESPONSE = 16 * 1024 * 1024
TOPICS = frozenset({"openbexi.GENERIC.tm", "openbexi.GENERIC.ack"})


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _constant(_value: str) -> None:
    raise ValueError("nonfinite JSON value")


class DssRuntime:
    def __init__(self, engine: DssEngine, *, bootstrap_servers: str,
                 test_control: bool = False, tick_seconds: float = 1.0,
                 allowed_origins: frozenset[str] = frozenset({"http://127.0.0.1:8080", "http://localhost:8080"})):
        if type(tick_seconds) not in {int, float} or not 0.02 <= tick_seconds <= 5:
            raise ValueError("tick interval outside bounds")
        self.engine = engine
        self.database = SatelliteDatabase.load()
        model_tick_ns = self.database.material["dynamics"]["tick_ns"]
        interval_ns = round(tick_seconds * 1_000_000_000)
        if type(model_tick_ns) is not int or model_tick_ns <= 0 or interval_ns % model_tick_ns:
            raise ValueError("publication cadence must contain complete model ticks")
        self.ticks_per_frame = interval_ns // model_tick_ns
        if not 1 <= self.ticks_per_frame <= 1000:
            raise ValueError("publication cadence exceeds model bounds")
        self.bootstrap_servers = bootstrap_servers
        self.test_control = test_control
        self.tick_seconds = tick_seconds
        self.allowed_origins = allowed_origins
        self.stop_event = threading.Event()
        self.threads: list[threading.Thread] = []
        self.publisher_ready = False
        self.last_publish_ns: int | None = None
        self.publisher_error: str | None = None
        self.runtime_error: str | None = None
        # Reset must not overlap a TCP command; engine methods own state locking.
        self.admission_lock = threading.Lock()
        self.tc_address = ("127.0.0.1", 3080)

    def start(self) -> None:
        self.threads = [threading.Thread(target=self._tick_loop, name="dss-tick", daemon=True),
                        threading.Thread(target=self._publish_loop, name="dss-publish", daemon=True)]
        for thread in self.threads:
            thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        for thread in self.threads:
            thread.join(timeout=12)

    def health(self) -> dict[str, Any]:
        alive = len(self.threads) == 2 and all(thread.is_alive() for thread in self.threads)
        outbox = self.engine.outbox_status()
        error = self.runtime_error or ("DSS_OUTBOX_BACKPRESSURE" if outbox["backpressure"] else self.publisher_error)
        return {"status": "ready" if alive and self.publisher_ready and not error else "unavailable",
                "publisher": "connected" if self.publisher_ready else "unavailable",
                "last_publish_ns": self.last_publish_ns,
                "outbox": outbox, "error_code": error,
                "automatic_interval_ns": round(self.tick_seconds * 1_000_000_000),
                "physics_ticks_per_frame": self.ticks_per_frame}

    def _tick_loop(self) -> None:
        try:
            while not self.stop_event.wait(self.tick_seconds):
                self.engine.advance(ticks=self.ticks_per_frame)
        except Exception:
            self.runtime_error = "DSS_TICK_FAILED"
            LOG.error("DSS_TICK_FAILED")

    def publish_pending(self, producer: Any) -> int:
        """Mark only broker-confirmed bytes. Network calls never hold engine locks."""
        count = 0
        for record in self.engine.pending_packets(limit=128):
            if self.stop_event.is_set():
                break
            if record["topic"] not in TOPICS or type(record["packet"]) is not bytes:
                raise ValueError("invalid outbox record")
            key = str(record["epoch"]).encode("ascii")
            producer.send(record["topic"], key=key, value=record["packet"]).get(timeout=5)
            self.engine.mark_published(record["id"])
            self.last_publish_ns = time.time_ns()
            count += 1
        return count

    def _publish_loop(self) -> None:
        from kafka import KafkaProducer
        from kafka.admin import KafkaAdminClient

        producer = None
        admin = None
        next_probe = 0.0
        while not self.stop_event.is_set():
            try:
                if producer is None:
                    producer = KafkaProducer(
                        bootstrap_servers=self.bootstrap_servers, client_id="openbexi-generic-dss",
                        enable_idempotence=True, acks="all", retries=5,
                        max_in_flight_requests_per_connection=1,
                        max_block_ms=5000, request_timeout_ms=5000,
                        delivery_timeout_ms=10000, bootstrap_timeout_ms=3000,
                        receive_message_max_bytes=131072, max_request_size=131072,
                        linger_ms=0,
                    )
                    admin = KafkaAdminClient(bootstrap_servers=self.bootstrap_servers,
                                             client_id="openbexi-dss-health", request_timeout_ms=5000,
                                             bootstrap_timeout_ms=3000, receive_message_max_bytes=131072)
                    next_probe = 0.0
                self.publish_pending(producer)
                if time.monotonic() >= next_probe:
                    if not admin.describe_cluster().get("brokers"):
                        raise ValueError("Kafka broker metadata unavailable")
                    next_probe = time.monotonic() + 5
                self.publisher_ready = True
                self.publisher_error = None
                self.stop_event.wait(0.05)
            except Exception:
                # Never log credentials, broker objects, packet values or arbitrary errors.
                self.publisher_ready = False
                self.publisher_error = "DSS_KAFKA_UNAVAILABLE"
                if producer is not None:
                    try:
                        producer.close(timeout=1)
                    except Exception:
                        pass
                if admin is not None:
                    try:
                        admin.close()
                    except Exception:
                        pass
                producer = None
                admin = None
                self.stop_event.wait(1)
        if producer is not None:
            producer.close(timeout=2)
        if admin is not None:
            admin.close()

    def catalog(self) -> dict[str, Any]:
        return {"satellite_id": "GENERIC", "database_revision": self.database.revision,
                "database_digest": self.database.digest, "commands": list(self.database.commands),
                "telemetry": list(self.database.telemetry)}

    def execute_ui_command(self, request: dict[str, Any]) -> dict[str, Any]:
        """A local operator command uses the same binary TC ingress as SPELL."""
        required = {"operation_id", "command_name", "arguments", "expected_epoch", "expected_revision", "confirmed"}
        if set(request) != required or request["confirmed"] is not True:
            raise ValueError("explicit complete command confirmation required")
        operation = request["operation_id"]
        if type(operation) is not str or str(uuid.UUID(operation, version=4)) != operation:
            raise ValueError("canonical command UUID required")
        definition = self.database.command(request["command_name"])
        if definition.get("role") == "REFERENCE_ADAPTATION":
            raise ValueError("reference adaptation is not a UI command")
        arguments = []
        if type(request["arguments"]) is not list or len(request["arguments"]) > 16:
            raise ValueError("bounded typed arguments required")
        for argument in request["arguments"]:
            if type(argument) is not dict or set(argument) != {"name", "value", "value_type", "value_format"}:
                raise ValueError("typed UI argument fields differ")
            value, kind = argument["value"], argument["value_type"]
            if kind == "FLOAT":
                if type(value) not in {float, int}:
                    raise ValueError("finite numeric argument required")
                try:
                    value = float(value)
                except (OverflowError, ValueError) as exc:
                    raise ValueError("finite numeric argument required") from exc
                if not math.isfinite(value):
                    raise ValueError("finite numeric argument required")
                encoded = format(value, ".17g")
            elif kind == "BOOLEAN":
                encoded = "true" if value is True else "false"
            else:
                encoded = str(value)
            arguments.append({**argument, "value": value, "radix": "DEC", "encoded": encoded})
        validate_command(request["command_name"], arguments)
        state = self.engine.state()
        if state["running"]:
            raise DssConflict("pause before reviewing a UI command")
        if (type(request["expected_revision"]) is not int or state["epoch"] != request["expected_epoch"]
                or state["revision"] != request["expected_revision"]):
            raise DssConflict("DSS command state changed")
        digest = hashlib.sha256(canonical({"command_name": request["command_name"], "arguments": arguments,
                                          "database_digest": state["database_digest"]})).hexdigest()
        base = {"schema_version": "openbexi.dss.tc/1", "satellite_id": state["satellite_id"],
                "database_revision": state["database_revision"], "database_digest": state["database_digest"],
                "satellite_epoch": state["epoch"], "scenario_id": state["scenario_id"],
                "operation_id": operation, "procedure_id": "DSS_UI", "execution_id": f"dss-ui-{operation}",
                "plan_id": f"dss-ui-{operation}", "element_id": "command-1",
                "command_name": request["command_name"], "arguments": arguments, "command_digest": digest}
        result: dict[str, Any] = {"operation_id": operation, "command_name": request["command_name"],
                                  "outcome": "UNCERTAIN", "receipts": []}
        stages = (("TRANSPORT", "ACCEPTED"), ("LOADING", "LOADED"), ("RELEASE", "RELEASED"),
                  ("ACKNOWLEDGEMENT", "ACKNOWLEDGED"), ("ONBOARD_EXECUTION", "SUCCEEDED"))
        try:
            with socket.create_connection(self.tc_address, timeout=2) as connection:
                connection.settimeout(3)
                for sequence, (stage, outcome) in enumerate(stages):
                    body = {**base, "stage": stage}
                    if stage == "TRANSPORT":
                        body["expected_revision"] = request["expected_revision"]
                    connection.sendall(encode_tc(body, sequence=sequence))
                    answer = decode_tm(recv_packet(connection))
                    if (answer.get("schema_version") != "openbexi.dss.ack/1"
                            or any(answer.get(key) != value for key, value in base.items()
                                   if key not in {"schema_version", "arguments"})
                            or answer.get("stage") != stage):
                        raise ValueError("acknowledgement binding differs")
                    result["receipts"].append(answer)
                    if answer.get("outcome") != outcome:
                        result["outcome"] = "UNCERTAIN" if answer.get("outcome") in {"MISSING", "UNCERTAIN", "INDETERMINATE"} else "REJECTED"
                        return result
                result["outcome"] = "SUCCEEDED"
        except (OSError, ValueError, EOFError):
            # The byte send may have changed the satellite. Do not repeat it.
            result["outcome"] = "UNCERTAIN"
        return result


class BoundedThreads(socketserver.ThreadingMixIn):
    daemon_threads = False
    block_on_close = True
    allow_reuse_address = True

    def __init__(self, *args: Any, max_connections: int = 16, **kwargs: Any):
        self.slots = threading.BoundedSemaphore(max_connections)
        super().__init__(*args, **kwargs)

    def process_request(self, request: socket.socket, client_address: Any) -> None:
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request: socket.socket, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, _request: Any, _client_address: Any) -> None:
        LOG.warning("DSS_REQUEST_FAILED")


class TcServer(BoundedThreads, socketserver.TCPServer):
    def __init__(self, address: tuple[str, int], runtime: DssRuntime):
        self.runtime = runtime
        super().__init__(address, TcHandler)


class TcHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(5)
        runtime = self.server.runtime
        # Bounded session lifetime; clients may reconnect without resending a command.
        for _ in range(64):
            if runtime.stop_event.is_set():
                return
            try:
                raw = recv_packet(self.request)
                body = decode_tc(raw)
                with runtime.admission_lock:
                    answer = runtime.engine.process_tc(body, raw)
                    fault = runtime.engine.consume_transport_fault(body, answer)
                if fault["drop_ack"]:
                    return
                if fault["delay_ms"] and runtime.stop_event.wait(fault["delay_ms"] / 1000):
                    return
                packet = encode_tm(answer, sequence=answer["ack_sequence"] & 0x3fff, ack=True)
                self.request.sendall(packet)
            except (OSError, ValueError, EOFError):
                return


class ApiServer(BoundedThreads, HTTPServer):
    def __init__(self, address: tuple[str, int], runtime: DssRuntime):
        self.runtime = runtime
        super().__init__(address, ApiHandler, max_connections=4)


class ApiHandler(BaseHTTPRequestHandler):
    server_version = "OpenBEXI-DSS"
    sys_version = ""
    protocol_version = "HTTP/1.0"

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, _format: str, *_args: Any) -> None:
        pass

    def _reply(self, status: int, value: Any) -> None:
        raw = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("utf-8")
        if len(raw) > MAX_RESPONSE:
            status, raw = 413, b'{"error_code":"DSS_RESPONSE_BOUNDS"}'
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(raw)

    def _error(self, status: int, code: str) -> None:
        self._reply(status, {"error_code": code})

    def do_GET(self) -> None:
        runtime = self.server.runtime
        route = urlsplit(self.path)
        try:
            if route.path == "/healthz":
                health = runtime.health()
                self._reply(200 if health["status"] == "ready" else 503, health)
            elif route.path == "/api/v1/state":
                self._reply(200, {**runtime.engine.state(), "transport": runtime.health()})
            elif route.path == "/api/v1/catalog":
                self._reply(200, runtime.catalog())
            elif route.path == "/api/v1/telemetry":
                self._reply(200, runtime.engine.telemetry())
            elif route.path == "/api/v1/evidence":
                params = parse_qs(route.query, strict_parsing=True, max_num_fields=4)
                if set(params) - {"scenario_id", "offset", "limit", "expected_revision"} or any(len(value) != 1 for value in params.values()):
                    raise ValueError("evidence query fields differ")
                scenario = params.get("scenario_id", [])
                if len(scenario) != 1 or not 1 <= len(scenario[0]) <= 160:
                    raise ValueError("scenario required")
                def integer(name: str, default: int) -> int:
                    value = params.get(name, [str(default)])[0]
                    if not value.isascii() or not value.isdigit() or len(value) > 10:
                        raise ValueError("evidence cursor is invalid")
                    return int(value)
                revision = integer("expected_revision", 0) if "expected_revision" in params else None
                self._reply(200, runtime.engine.evidence_page(scenario[0], offset=integer("offset", 0),
                                                               limit=integer("limit", 32), expected_revision=revision))
            else:
                self._error(404, "DSS_ROUTE_NOT_FOUND")
        except DssConflict:
            self._error(409, "DSS_STATE_CONFLICT")
        except (ValueError, TypeError, KeyError):
            self._error(400, "DSS_REQUEST_INVALID")

    def do_POST(self) -> None:
        runtime = self.server.runtime
        origin = self.headers.get("Origin")
        if origin is not None and origin not in runtime.allowed_origins:
            self._error(403, "DSS_ORIGIN_DENIED")
            return
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            self._error(415, "DSS_JSON_REQUIRED")
            return
        if self.headers.get("Transfer-Encoding") is not None:
            self._error(400, "DSS_REQUEST_INVALID")
            return
        try:
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1 or not lengths[0].isdigit():
                raise ValueError("length required")
            length = int(lengths[0])
            if not 2 <= length <= MAX_BODY:
                self._error(413, "DSS_REQUEST_BOUNDS")
                return
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError("truncated request")
            body = json.loads(raw, object_pairs_hook=_object, parse_constant=_constant)
            if type(body) is not dict:
                raise ValueError("object required")
            route = urlsplit(self.path)
            if route.query:
                raise ValueError("query unsupported")
            if route.path == "/api/v1/control":
                if set(body) - {"action", "expected_epoch", "expected_revision", "ticks"}:
                    raise ValueError("unknown field")
                if body.get("action") not in ("PAUSE", "RESUME", "STEP"):
                    raise ValueError("unknown action")
                state = runtime.engine.control(body["action"], expected_epoch=body["expected_epoch"],
                                               expected_revision=body["expected_revision"], ticks=body.get("ticks", 1))
            elif route.path == "/api/v1/commands":
                state = runtime.execute_ui_command(body)
            elif route.path == "/api/v1/scenarios/reset":
                if not runtime.test_control:
                    self._error(403, "DSS_TEST_CONTROL_DISABLED")
                    return
                if set(body) - {"scenario_id", "initial_state", "faults", "expected_epoch", "retirement_token"}:
                    raise ValueError("unknown field")
                if not body.get("expected_epoch"):
                    raise ValueError("epoch required")
                with runtime.admission_lock:
                    state = runtime.engine.reset(**body)
            else:
                self._error(404, "DSS_ROUTE_NOT_FOUND")
                return
            self._reply(200, state)
        except DssConflict:
            self._error(409, "DSS_STATE_CONFLICT")
        except (ValueError, TypeError, KeyError, RecursionError, OverflowError) as exc:
            code = str(getattr(exc, "code", "DSS_REQUEST_INVALID"))
            # Only closed engine codes, never arbitrary exception text.
            if not code.startswith("DSS_") or not code.replace("_", "").isalnum():
                code = "DSS_REQUEST_INVALID"
            self._error(409 if any(part in code for part in ("FENCE", "CONFLICT", "BUSY", "EPOCH", "REVISION")) else 400, code)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", default=os.environ.get("DSS_STATE_PATH", "/var/lib/dss/satellite.sqlite"))
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--tc-port", type=int, default=3080)
    parser.add_argument("--http-port", type=int, default=8081)
    args = parser.parse_args()
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
    origin_port = os.environ.get("DSS_LOCAL_PORT", "8080")
    if not origin_port.isdigit() or not 1 <= int(origin_port) <= 65535:
        raise ValueError("invalid local ingress port")
    runtime = DssRuntime(DssEngine(args.database),
                         bootstrap_servers=os.environ.get("DSS_KAFKA_BOOTSTRAP_SERVERS", "kafka:9092"),
                         test_control=os.environ.get("DSS_TEST_CONTROL_ENABLED", "false").lower() == "true",
                         allowed_origins=frozenset({f"http://127.0.0.1:{origin_port}", f"http://localhost:{origin_port}"}))
    tcp, http = TcServer((args.listen, args.tc_port), runtime), ApiServer((args.listen, args.http_port), runtime)
    runtime.tc_address = ("127.0.0.1", args.tc_port)
    threads = [threading.Thread(target=server.serve_forever, name=name, daemon=True)
               for server, name in ((tcp, "dss-tcp"), (http, "dss-http"))]
    for signal_id in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signal_id, lambda *_: runtime.stop_event.set())
    runtime.start()
    for thread in threads:
        thread.start()
    try:
        runtime.stop_event.wait()
    finally:
        for server in (tcp, http):
            server.shutdown()
            server.server_close()
        runtime.stop()
        for thread in threads:
            thread.join(timeout=2)
        runtime.engine.close()


if __name__ == "__main__":
    main()
