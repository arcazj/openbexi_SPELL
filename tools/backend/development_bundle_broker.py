"""Fail-closed broker for two independent network-isolated bundle builders."""

from __future__ import annotations

import base64
import hashlib
import secrets
import threading
import time
from pathlib import Path
from typing import Any, Mapping

from .development_bundle_builder import (
    BundleBuildResult,
    BundleBuilder,
    canonical_request_bytes,
)
from .development_bundle_protocol import (
    atomic_protocol_write,
    protocol_inventory,
    read_protocol_file,
    require_protocol_directory,
)
from .development_bundle_provenance import toolchain_descriptor, toolchain_digest
from .development_domain import (
    DevelopmentConflictError,
    DevelopmentCorruptionError,
    DevelopmentError,
    canonical_json_bytes,
    require_digest,
    strict_json_bytes,
)


PROTOCOL_SCHEMA = "spell.bundle-build-protocol/1"
RESPONSE_SCHEMA = "spell.bundle-build-response/1"
READY_SCHEMA = "spell.bundle-builder-ready/1"
WORKER_IDS = ("builder-a", "builder-b")


class DualContainerBundleBroker(BundleBuilder):
    def __init__(
        self,
        *,
        request_directory: Path,
        response_directories: Mapping[str, Path],
        timeout_seconds: float = 30.0,
        poll_seconds: float = 0.05,
    ) -> None:
        if set(response_directories) != set(WORKER_IDS):
            raise ValueError("exactly builder-a and builder-b response directories are required")
        if not (0.1 <= timeout_seconds <= 120.0):
            raise ValueError("bundle builder timeout must be between 0.1 and 120 seconds")
        if not (0.005 <= poll_seconds <= 1.0):
            raise ValueError("bundle builder poll interval is invalid")
        self.request_directory = require_protocol_directory(
            request_directory, "bundle request directory"
        )
        self.response_directories = {
            worker: require_protocol_directory(path, f"{worker} response directory")
            for worker, path in sorted(response_directories.items())
        }
        identities = {
            (path.lstat().st_dev, path.lstat().st_ino)
            for path in (self.request_directory, *self.response_directories.values())
        }
        if len(identities) != 3:
            raise ValueError("bundle protocol directories must be distinct")
        self.timeout_seconds = timeout_seconds
        self.poll_seconds = poll_seconds
        self._lock = threading.Lock()

    def _assert_ready(self) -> None:
        expected_digest = toolchain_digest()
        for worker, directory in self.response_directories.items():
            marker = directory / "ready.json"
            if not marker.exists():
                raise DevelopmentConflictError(
                    "bundle builder is not ready",
                    code="BUILDER_UNAVAILABLE",
                    current={"worker_id": worker},
                )
            raw = read_protocol_file(
                marker, label=f"{worker} readiness marker"
            )
            value = strict_json_bytes(raw, f"{worker} readiness marker")
            if canonical_json_bytes(value) != raw or value != {
                "schema_version": READY_SCHEMA,
                "toolchain_digest": expected_digest,
                "worker_id": worker,
            }:
                raise DevelopmentConflictError(
                    "bundle builder readiness differs",
                    code="BUILDER_UNAVAILABLE",
                )

    @staticmethod
    def _parse_response(
        raw: bytes,
        *,
        expires_at_epoch_ms: int,
        worker_id: str,
        request_id: str,
        request_sha256: str,
    ) -> BundleBuildResult:
        value = strict_json_bytes(raw, f"{worker_id} bundle response")
        if type(value) is not dict or canonical_json_bytes(value) != raw:
            raise DevelopmentCorruptionError("bundle worker response is not canonical")
        common = {
            "expires_at_epoch_ms",
            "request_id",
            "request_sha256",
            "schema_version",
            "status",
            "worker_id",
        }
        if (
            value.get("schema_version") != RESPONSE_SCHEMA
            or value.get("worker_id") != worker_id
            or value.get("request_id") != request_id
            or value.get("request_sha256") != request_sha256
            or value.get("expires_at_epoch_ms") != expires_at_epoch_ms
        ):
            raise DevelopmentCorruptionError("bundle worker response identity differs")
        if value.get("status") == "ERROR":
            if set(value) != common | {"error_code"} or type(value["error_code"]) is not str:
                raise DevelopmentCorruptionError("bundle worker failure response differs")
            raise DevelopmentConflictError(
                "isolated bundle builder rejected the request",
                code="BUILDER_FAILED",
                current={"worker_id": worker_id, "error_code": value["error_code"][:80]},
            )
        success_fields = common | {
            "bundle_bytes",
            "bundle_sha256",
            "manifest_without_digest",
            "procedure_ids",
            "toolchain_descriptor",
            "toolchain_digest",
        }
        if value.get("status") != "OK" or set(value) != success_fields:
            raise DevelopmentCorruptionError("bundle worker success response differs")
        try:
            bundle_bytes = base64.b64decode(value["bundle_bytes"], validate=True)
        except (TypeError, ValueError) as exc:
            raise DevelopmentCorruptionError("bundle worker bytes are invalid") from exc
        bundle_digest = require_digest(value["bundle_sha256"], "bundle_sha256")
        if hashlib.sha256(bundle_bytes).hexdigest() != bundle_digest:
            raise DevelopmentCorruptionError("bundle worker byte digest differs")
        descriptor = value["toolchain_descriptor"]
        if type(descriptor) is not dict or descriptor != toolchain_descriptor():
            raise DevelopmentCorruptionError("bundle worker toolchain descriptor differs")
        descriptor_digest = require_digest(value["toolchain_digest"], "toolchain_digest")
        if (
            hashlib.sha256(canonical_json_bytes(descriptor)).hexdigest()
            != descriptor_digest
            or descriptor_digest != toolchain_digest()
        ):
            raise DevelopmentCorruptionError("bundle worker toolchain digest differs")
        manifest = value["manifest_without_digest"]
        procedure_ids = value["procedure_ids"]
        if type(manifest) is not dict or type(procedure_ids) is not list:
            raise DevelopmentCorruptionError("bundle worker result shape differs")
        if not procedure_ids or len(procedure_ids) > 1024 or any(
            type(item) is not str or not item or len(item.encode("utf-8")) > 200
            for item in procedure_ids
        ):
            raise DevelopmentCorruptionError("bundle worker procedure identities differ")
        return BundleBuildResult(
            bundle_bytes=bundle_bytes,
            manifest_without_digest=manifest,
            procedure_ids=tuple(procedure_ids),
            toolchain_descriptor=descriptor,
            toolchain_digest=descriptor_digest,
        )

    def build(self, request: Mapping[str, Any]) -> BundleBuildResult:
        request_raw = canonical_request_bytes(request)
        request_sha256 = hashlib.sha256(request_raw).hexdigest()
        request_id = secrets.token_hex(16)
        request_path = self.request_directory / f"{request_id}.request.json"
        response_paths = {
            worker: directory / f"{request_id}.response.json"
            for worker, directory in self.response_directories.items()
        }
        with self._lock:
            self._assert_ready()
            protocol_inventory(self.request_directory, "bundle request directory")
            for worker, directory in self.response_directories.items():
                protocol_inventory(directory, f"{worker} response directory")
            now_ms = int(time.time() * 1000)
            envelope = {
                "created_at_epoch_ms": now_ms,
                "expires_at_epoch_ms": now_ms + int(self.timeout_seconds * 1000),
                "request": dict(request),
                "request_id": request_id,
                "request_sha256": request_sha256,
                "schema_version": PROTOCOL_SCHEMA,
            }
            envelope_raw = canonical_json_bytes(envelope)
            deadline = time.monotonic() + self.timeout_seconds
            try:
                atomic_protocol_write(
                    request_path, envelope_raw, label="bundle build request"
                )
                responses: dict[str, BundleBuildResult] = {}

                def reject_timeout() -> None:
                    missing = sorted(set(WORKER_IDS) - set(responses))
                    raise DevelopmentConflictError(
                        "independent bundle builders did not respond before the deadline",
                        code="BUILDER_UNAVAILABLE",
                        current={"missing_workers": missing},
                    )

                while len(responses) != len(WORKER_IDS):
                    if time.monotonic() >= deadline:
                        reject_timeout()
                    for worker in WORKER_IDS:
                        if worker in responses or not response_paths[worker].exists():
                            continue
                        if time.monotonic() >= deadline:
                            reject_timeout()
                        raw = read_protocol_file(
                            response_paths[worker], label=f"{worker} bundle response"
                        )
                        parsed = self._parse_response(
                            raw,
                            expires_at_epoch_ms=envelope["expires_at_epoch_ms"],
                            worker_id=worker,
                            request_id=request_id,
                            request_sha256=request_sha256,
                        )
                        if time.monotonic() >= deadline:
                            reject_timeout()
                        responses[worker] = parsed
                    if len(responses) == len(WORKER_IDS):
                        break
                    if time.monotonic() >= deadline:
                        reject_timeout()
                    time.sleep(self.poll_seconds)
                first = responses[WORKER_IDS[0]]
                second = responses[WORKER_IDS[1]]
                if first != second:
                    raise DevelopmentCorruptionError(
                        "independent isolated bundle builds differ"
                    )
                return first
            finally:
                request_path.unlink(missing_ok=True)
                for path in response_paths.values():
                    path.unlink(missing_ok=True)


__all__ = [
    "DualContainerBundleBroker",
    "PROTOCOL_SCHEMA",
    "READY_SCHEMA",
    "RESPONSE_SCHEMA",
    "WORKER_IDS",
]
