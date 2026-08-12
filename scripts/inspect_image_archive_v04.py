#!/usr/bin/env python3
"""Inspect every regular file in every layer of one Docker image-save archive."""

from __future__ import annotations

import argparse
import json
import re
import tarfile
from pathlib import Path, PurePosixPath
from typing import BinaryIO


LEGACY_LAYER_PATTERN = re.compile(r"[0-9a-f]{64}/layer\.tar\Z")
OCI_LAYER_PATTERN = re.compile(r"blobs/sha256/[0-9a-f]{64}\Z")
ARCHIVE_PATTERN = re.compile(r"\.(?:zip|7z|rar|tar|tgz|gz|bz2|xz)\Z")
JOURNAL_PATTERN = re.compile(r"\.(?:db|journal|sqlite|sqlite3|wal|shm)\Z")
SECRET_SUFFIX_PATTERN = re.compile(r"\.(?:key|pem|p12|pfx|jks)\Z")
MANUAL_PATTERN = re.compile(r"manual.*\.(?:txt|md|html|json)\Z")
PRIVATE_KEY_BLOCK = re.compile(
    br"-----BEGIN (?:(?:RSA|EC|OPENSSH) )?PRIVATE KEY-----\r?\n"
    br"(?:[A-Za-z0-9+/=]{16,}\r?\n)+"
    br"-----END (?:(?:RSA|EC|OPENSSH) )?PRIVATE KEY-----"
)
AWS_ACCESS_KEY = re.compile(b"A" + b"KIA[0-9A-Z]{16}")
PRODUCT_PREFIXES = (
    "/app/",
    "/src/frontend/",
    "/usr/share/nginx/html/",
    "/run/spell-driver",
    "/etc/spell-driver/",
    "/var/lib/spell-driver/",
)
EXACT_JOURNALS = {
    "canonical-audit.jsonl",
    "driver-journal.bin",
    "operation-evidence.json",
}
EXACT_SECRETS = {
    ".env",
    "credentials.json",
    "secrets.json",
    "id_rsa",
    "id_ed25519",
}


def _safe_member_name(value: str, label: str) -> str:
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError(f"unsafe {label} path")
    return path.as_posix().lstrip("./")


def _read_json_member(archive: tarfile.TarFile, name: str) -> object:
    members = [member for member in archive.getmembers() if member.name == name]
    if len(members) != 1 or not members[0].isfile():
        raise ValueError(f"image archive {name} cardinality differs")
    stream = archive.extractfile(members[0])
    if stream is None:
        raise ValueError(f"image archive {name} is unreadable")
    return json.load(stream)


def _config_matches(config_name: object, expected_image_id: str) -> bool:
    digest = expected_image_id.removeprefix("sha256:")
    return config_name in {f"{digest}.json", f"blobs/sha256/{digest}"}


def _is_layer_member_name(layer_name: object) -> bool:
    if not isinstance(layer_name, str):
        return False
    return (
        LEGACY_LAYER_PATTERN.fullmatch(layer_name) is not None
        or OCI_LAYER_PATTERN.fullmatch(layer_name) is not None
    )


def _scan_layer(stream: BinaryIO, metrics: dict[str, int]) -> None:
    with tarfile.open(fileobj=stream, mode="r:*") as layer:
        for member in layer:
            if not member.isfile():
                continue
            relative = _safe_member_name(member.name, "layer member")
            metrics["scanned_file_count"] += 1
            absolute = "/" + relative.casefold()
            file_name = PurePosixPath(relative).name.casefold()
            is_product = absolute.startswith(PRODUCT_PREFIXES)
            if "/grpc_tools/" in absolute or absolute.endswith(
                "/generate_driver_contract.py"
            ):
                metrics["runtime_generator_count"] += 1
            if is_product:
                if file_name.endswith(".pdf"):
                    metrics["pdf_file_count"] += 1
                if ARCHIVE_PATTERN.search(file_name):
                    metrics["legacy_archive_count"] += 1
                if JOURNAL_PATTERN.search(file_name) or file_name in EXACT_JOURNALS:
                    metrics["runtime_journal_count"] += 1
                if SECRET_SUFFIX_PATTERN.search(file_name) or file_name in EXACT_SECRETS:
                    metrics["secret_file_count"] += 1
                if MANUAL_PATTERN.search(file_name):
                    metrics["manual_text_file_count"] += 1
            if member.size <= 16 * 1024 * 1024:
                member_stream = layer.extractfile(member)
                if member_stream is None:
                    raise ValueError("regular layer member is unreadable")
                content = member_stream.read()
                if PRIVATE_KEY_BLOCK.search(content) or (
                    _looks_like_text(content) and AWS_ACCESS_KEY.search(content)
                ):
                    metrics["secret_file_count"] += 1


def _looks_like_text(content: bytes) -> bool:
    if not content:
        return True
    sample = content[:4096]
    if b"\x00" in sample:
        return False
    printable = sum(
        byte in b"\t\n\r" or 32 <= byte <= 126
        for byte in sample
    )
    return printable / len(sample) >= 0.9


def inspect_archive(path: Path, expected_image_id: str) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("image-save archive must be a regular file")
    metrics = {
        "scanned_file_count": 0,
        "secret_file_count": 0,
        "pdf_file_count": 0,
        "manual_text_file_count": 0,
        "legacy_archive_count": 0,
        "runtime_journal_count": 0,
        "runtime_generator_count": 0,
        "scanned_layer_count": 0,
        "layer_scan_failure_count": 0,
    }
    with tarfile.open(path, mode="r:*") as archive:
        manifest = _read_json_member(archive, "manifest.json")
        if not isinstance(manifest, list) or len(manifest) != 1:
            raise ValueError("image-save manifest cardinality differs")
        record = manifest[0]
        if not isinstance(record, dict):
            raise ValueError("image-save manifest entry is malformed")
        config_name = record.get("Config")
        layers = record.get("Layers")
        if (
            not _config_matches(config_name, expected_image_id)
            or not isinstance(layers, list)
            or not layers
        ):
            raise ValueError("image-save manifest identity or layer set differs")
        layer_members = {member.name: member for member in archive.getmembers()}
        if len(set(layers)) != len(layers):
            raise ValueError("image-save manifest repeats a layer")
        for layer_name in layers:
            if not _is_layer_member_name(layer_name):
                raise ValueError("image-save layer path is invalid")
            member = layer_members.get(layer_name)
            if member is None or not member.isfile():
                raise ValueError("image-save layer is absent or not regular")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("image-save layer is unreadable")
            _scan_layer(stream, metrics)
            metrics["scanned_layer_count"] += 1
    return {
        "schema_version": "spell.v04.image-layer-inspection/1",
        "image_id": expected_image_id,
        **metrics,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--image-id", required=True)
    args = parser.parse_args()
    if re.fullmatch(r"sha256:[0-9a-f]{64}", args.image_id) is None:
        parser.error("--image-id must be an exact sha256 image ID")
    result = inspect_archive(args.archive.resolve(), args.image_id)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
