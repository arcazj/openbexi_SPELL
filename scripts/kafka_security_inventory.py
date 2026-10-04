"""Verify installed Kafka security dependencies against the source-bound lock."""
from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath

LOCK_PATH = "/usr/local/share/openbexi/kafka_dependency_lock.json"


def verify_inventory(lock_bytes, *, hashes, sizes, installed_apks, jar_files):
    lock = json.loads(lock_bytes)
    jars = [r for r in lock["artifacts"] if r["kind"] == "MAVEN"]
    apks = [r for r in lock["artifacts"] if r["kind"] == "APK"]
    expected_hashes = {LOCK_PATH: hashlib.sha256(lock_bytes).hexdigest()}
    expected_sizes = {}
    names = set(jar_files)
    for row in jars:
        path = "/opt/kafka/libs/" + row["url"].rsplit("/", 1)[-1]
        expected_hashes[path] = row["sha256"]
        expected_sizes[path] = row["size"]
        family = {p for p in names if PurePosixPath(p).name.startswith(row["name"] + "-")}
        if family != {path}:
            raise ValueError("Kafka classpath has an absent, duplicate or old patched library")
    expected_apks = {r["name"] + "-" + r["version"] for r in apks}
    if hashes != expected_hashes or sizes != expected_sizes or set(installed_apks) != expected_apks:
        raise ValueError("Kafka installed dependency bytes, size or package version differ")
    return {"lock_sha256": expected_hashes[LOCK_PATH], "jar_sha256": {p:h for p,h in expected_hashes.items() if p != LOCK_PATH},
            "jar_sizes": expected_sizes, "installed_apks": sorted(expected_apks), "decision": "PASS"}
