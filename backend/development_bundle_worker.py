"""Network-independent worker process for deterministic v0.9 bundle builds."""

from __future__ import annotations

import argparse
import base64
import errno
import hashlib
import os
import re
import time
from pathlib import Path
from typing import Any

from .development_bundle_broker import (
    PROTOCOL_SCHEMA,
    READY_SCHEMA,
    RESPONSE_SCHEMA,
    WORKER_IDS,
)
from .development_bundle_builder import build_request_payload, canonical_request_bytes
from .development_bundle_protocol import (
    atomic_protocol_write,
    protocol_inventory,
    read_protocol_file,
    require_protocol_directory,
)
from .development_bundle_provenance import toolchain_digest
from .development_domain import (
    DevelopmentCorruptionError,
    DevelopmentError,
    canonical_json_bytes,
    strict_json_bytes,
)


_REQUEST_NAME = re.compile(r"([0-9a-f]{32})\.request\.json")


def _configuration() -> tuple[str, Path, Path, float]:
    worker_id = os.environ.get("SPELL_BUNDLE_BUILDER_WORKER_ID", "")
    if worker_id not in WORKER_IDS:
        raise RuntimeError("bundle builder worker identity is invalid")
    request_value = os.environ.get("SPELL_BUNDLE_REQUEST_DIR", "")
    response_value = os.environ.get("SPELL_BUNDLE_RESPONSE_DIR", "")
    if not request_value or not response_value:
        raise RuntimeError("bundle builder protocol directories are required")
    request_directory = require_protocol_directory(
        Path(request_value), "bundle request directory"
    )
    response_directory = require_protocol_directory(
        Path(response_value), "bundle response directory"
    )
    if (
        request_directory.lstat().st_dev,
        request_directory.lstat().st_ino,
    ) == (
        response_directory.lstat().st_dev,
        response_directory.lstat().st_ino,
    ):
        raise RuntimeError("bundle worker request and response directories must differ")
    try:
        poll_seconds = float(os.environ.get("SPELL_BUNDLE_BUILDER_POLL_SECONDS", "0.05"))
    except ValueError as exc:
        raise RuntimeError("bundle builder poll interval is invalid") from exc
    if not 0.005 <= poll_seconds <= 1.0:
        raise RuntimeError("bundle builder poll interval is invalid")
    return worker_id, request_directory, response_directory, poll_seconds


def _ready_value(worker_id: str) -> dict[str, Any]:
    return {
        "schema_version": READY_SCHEMA,
        "toolchain_digest": toolchain_digest(),
        "worker_id": worker_id,
    }


def _parse_request(
    raw: bytes, filename_request_id: str
) -> tuple[dict[str, Any], str, int]:
    envelope = strict_json_bytes(raw, "bundle build protocol request")
    required = {
        "created_at_epoch_ms",
        "expires_at_epoch_ms",
        "request",
        "request_id",
        "request_sha256",
        "schema_version",
    }
    if type(envelope) is not dict or set(envelope) != required:
        raise DevelopmentError("bundle build protocol request fields differ")
    if canonical_json_bytes(envelope) != raw:
        raise DevelopmentError("bundle build protocol request is not canonical")
    if (
        envelope["schema_version"] != PROTOCOL_SCHEMA
        or envelope["request_id"] != filename_request_id
    ):
        raise DevelopmentError("bundle build protocol request identity differs")
    created = envelope["created_at_epoch_ms"]
    expires = envelope["expires_at_epoch_ms"]
    if (
        type(created) is not int
        or type(expires) is not int
        or expires < created
        or expires - created > 120_000
        or int(time.time() * 1000) > expires
    ):
        raise DevelopmentError("bundle build protocol request deadline is invalid")
    request = envelope["request"]
    if type(request) is not dict:
        raise DevelopmentError("bundle build protocol payload is invalid")
    request_digest = hashlib.sha256(canonical_request_bytes(request)).hexdigest()
    if envelope["request_sha256"] != request_digest:
        raise DevelopmentError("bundle build protocol request digest differs")
    return request, request_digest, expires


def _response(
    *,
    worker_id: str,
    expires_at_epoch_ms: int,
    request_id: str,
    request_sha256: str,
    request: dict[str, Any],
) -> dict[str, Any]:
    common = {
        "expires_at_epoch_ms": expires_at_epoch_ms,
        "request_id": request_id,
        "request_sha256": request_sha256,
        "schema_version": RESPONSE_SCHEMA,
        "status": "OK",
        "worker_id": worker_id,
    }
    try:
        result = build_request_payload(request)
    except Exception as exc:
        code = exc.code if isinstance(exc, DevelopmentError) else "BUILDER_INTERNAL_FAILURE"
        return {**common, "error_code": str(code)[:80], "status": "ERROR"}
    return {
        **common,
        "bundle_bytes": base64.b64encode(result.bundle_bytes).decode("ascii"),
        "bundle_sha256": hashlib.sha256(result.bundle_bytes).hexdigest(),
        "manifest_without_digest": result.manifest_without_digest,
        "procedure_ids": list(result.procedure_ids),
        "toolchain_descriptor": result.toolchain_descriptor,
        "toolchain_digest": result.toolchain_digest,
    }


def _write_ready(worker_id: str, response_directory: Path) -> None:
    atomic_protocol_write(
        response_directory / "ready.json",
        canonical_json_bytes(_ready_value(worker_id)),
        label="bundle builder readiness marker",
        replace=True,
    )


def _remove_expired_orphans(
    worker_id: str, request_directory: Path, response_directory: Path
) -> None:
    now_ms = int(time.time() * 1000)
    for path in protocol_inventory(response_directory, "bundle response directory"):
        if path.name == "ready.json" or path.name.startswith("."):
            continue
        match = re.fullmatch(r"([0-9a-f]{32})\.response\.json", path.name)
        if match is None:
            raise RuntimeError("bundle response directory contains an unknown entry")
        request_id = match.group(1)
        if (request_directory / f"{request_id}.request.json").exists():
            continue
        try:
            raw = read_protocol_file(path, label="orphaned bundle builder response")
        except DevelopmentCorruptionError as exc:
            if (
                isinstance(exc.__cause__, OSError)
                and exc.__cause__.errno == errno.ENOENT
            ):
                continue
            raise
        value = strict_json_bytes(raw, "orphaned bundle builder response")
        if (
            type(value) is not dict
            or canonical_json_bytes(value) != raw
            or value.get("schema_version") != RESPONSE_SCHEMA
            or value.get("worker_id") != worker_id
            or value.get("request_id") != request_id
            or type(value.get("expires_at_epoch_ms")) is not int
        ):
            raise RuntimeError("orphaned bundle builder response is invalid")
        if value["expires_at_epoch_ms"] <= now_ms:
            path.unlink(missing_ok=True)


def healthcheck() -> int:
    try:
        worker_id, _, response_directory, _ = _configuration()
        raw = read_protocol_file(
            response_directory / "ready.json", label="bundle builder readiness marker"
        )
        if strict_json_bytes(raw, "bundle builder readiness marker") != _ready_value(
            worker_id
        ):
            return 1
        return 0
    except Exception:
        return 1


def process_pending_once(
    worker_id: str, request_directory: Path, response_directory: Path
) -> bool:
    _remove_expired_orphans(worker_id, request_directory, response_directory)
    entries = protocol_inventory(request_directory, "bundle request directory")
    handled = False
    for path in entries:
        match = _REQUEST_NAME.fullmatch(path.name)
        if match is None:
            if path.name.startswith(".") and path.name.endswith(".tmp"):
                continue
            raise RuntimeError("bundle request directory contains an unknown entry")
        request_id = match.group(1)
        response_path = response_directory / f"{request_id}.response.json"
        if response_path.exists():
            continue
        raw = read_protocol_file(path, label="bundle build protocol request")
        try:
            request, request_sha256, expires_at_epoch_ms = _parse_request(
                raw, request_id
            )
            value = _response(
                worker_id=worker_id,
                expires_at_epoch_ms=expires_at_epoch_ms,
                request_id=request_id,
                request_sha256=request_sha256,
                request=request,
            )
        except Exception as exc:
            value = {
                "error_code": (
                    exc.code
                    if isinstance(exc, DevelopmentError)
                    else "INVALID_PROTOCOL_REQUEST"
                ),
                "expires_at_epoch_ms": int(time.time() * 1000),
                "request_id": request_id,
                "request_sha256": hashlib.sha256(raw).hexdigest(),
                "schema_version": RESPONSE_SCHEMA,
                "status": "ERROR",
                "worker_id": worker_id,
            }
        # The broker removes the request first on timeout. A late worker must
        # not deliberately publish into an already-abandoned exchange.
        if (
            path.exists()
            and type(value.get("expires_at_epoch_ms")) is int
            and int(time.time() * 1000) <= value["expires_at_epoch_ms"]
        ):
            atomic_protocol_write(
                response_path,
                canonical_json_bytes(value),
                label="bundle builder response",
            )
            # Broker cleanup can remove the request after the pre-publish check
            # but before the atomic rename. The late publisher owns cleanup in
            # that ordering; all other orderings are covered by broker cleanup.
            if not path.exists():
                response_path.unlink(missing_ok=True)
        handled = True
    return handled


def run() -> None:
    worker_id, request_directory, response_directory, poll_seconds = _configuration()
    _write_ready(worker_id, response_directory)
    while True:
        if not process_pending_once(worker_id, request_directory, response_directory):
            time.sleep(poll_seconds)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--healthcheck", action="store_true")
    options = parser.parse_args()
    if options.healthcheck:
        return healthcheck()
    run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["healthcheck", "main", "process_pending_once", "run"]
