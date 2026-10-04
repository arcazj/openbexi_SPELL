"""Explicit local DSS transport configuration; disabled preserves the legacy profile."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class DssConfig:
    enabled: bool = False
    cortex_host: str = "dss"
    cortex_port: int = 3080
    kafka_bootstrap: str = "kafka:9092"
    journal_path: Path = Path("/var/lib/spell-driver/dss-state.sqlite3")
    timeout_seconds: float = 3.0
    stale_seconds: float = 5.0

    def __post_init__(self) -> None:
        if type(self.enabled) is not bool:
            raise ValueError("DSS enabled must be boolean")
        if self.cortex_host != "dss" or self.cortex_port != 3080:
            raise ValueError("DSS transport must use the fixed internal Cortex endpoint")
        if self.kafka_bootstrap != "kafka:9092":
            raise ValueError("DSS telemetry must use the fixed internal Kafka endpoint")
        if not 0 < self.timeout_seconds <= 10 or not 0 < self.stale_seconds <= 60:
            raise ValueError("DSS transport bounds are invalid")

    @classmethod
    def from_environment(cls) -> "DssConfig":
        enabled = os.getenv("SPELL_DSS_ENABLED", "false").lower()
        if enabled not in {"true", "false"}:
            raise ValueError("SPELL_DSS_ENABLED must be true or false")
        return cls(
            enabled=enabled == "true",
            cortex_host=os.getenv("SPELL_DSS_CORTEX_HOST", "dss"),
            cortex_port=int(os.getenv("SPELL_DSS_CORTEX_PORT", "3080")),
            kafka_bootstrap=os.getenv("SPELL_DSS_KAFKA_BOOTSTRAP", "kafka:9092"),
        )
