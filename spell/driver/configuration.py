"""Canonical non-secret configuration fingerprints for the v0.4 driver boundary."""

from __future__ import annotations

import hashlib
import json
from typing import Mapping


def canonical_configuration_digest(material: Mapping[str, object]) -> str:
    encoded = json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def context_binding_digest(
    *,
    server_profile_id: str,
    driver_host_generation: str,
    host_profile_digest: str,
    schema_version: str,
    context_profile_id: str,
    synthetic_context_label: str,
) -> str:
    return canonical_configuration_digest(
        {
            "context_profile_id": context_profile_id,
            "host_profile_digest": host_profile_digest,
            "parent_driver_host_generation": driver_host_generation,
            "schema_version": schema_version,
            "server_profile_id": server_profile_id,
            "synthetic_context_label": synthetic_context_label,
        }
    )


def execution_attachment_digest(
    *,
    server_profile_id: str,
    driver_host_generation: str,
    host_profile_digest: str,
    context_id: str,
    context_generation: str,
    context_binding_digest: str,
    execution_id: str,
    schema_version: str,
    attachment_profile_id: str,
    synthetic_execution_label: str,
) -> str:
    return canonical_configuration_digest(
        {
            "attachment_profile_id": attachment_profile_id,
            "context_binding_digest": context_binding_digest,
            "context_generation": context_generation,
            "context_id": context_id,
            "execution_id": execution_id,
            "host_profile_digest": host_profile_digest,
            "parent_driver_host_generation": driver_host_generation,
            "schema_version": schema_version,
            "server_profile_id": server_profile_id,
            "synthetic_execution_label": synthetic_execution_label,
        }
    )
