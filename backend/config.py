from __future__ import annotations

import math
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    database_url: str
    procedures_dir: Path
    websocket_replay_limit: int
    websocket_queue_size: int
    websocket_keepalive_seconds: float
    command_ack_timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        if self.websocket_replay_limit <= 0:
            raise ValueError("SPELL_WS_REPLAY_LIMIT must be a positive integer")
        if self.websocket_queue_size <= 0:
            raise ValueError("SPELL_WS_QUEUE_SIZE must be a positive integer")
        if (
            not math.isfinite(self.websocket_keepalive_seconds)
            or self.websocket_keepalive_seconds <= 0
        ):
            raise ValueError("SPELL_WS_KEEPALIVE_SECONDS must be a positive finite number")
        if (
            not math.isfinite(self.command_ack_timeout_seconds)
            or self.command_ack_timeout_seconds <= 0
        ):
            raise ValueError(
                "SPELL_COMMAND_ACK_TIMEOUT_SECONDS must be a positive finite number"
            )

    @classmethod
    def from_env(cls) -> "Settings":
        root = Path(__file__).resolve().parents[1]
        return cls(
            database_url=os.getenv(
                "DATABASE_URL", f"sqlite:///{(root / 'var' / 'spell_v02.db').as_posix()}"
            ),
            procedures_dir=Path(os.getenv("SPELL_PROCEDURES_DIR", root / "procedures")),
            websocket_replay_limit=int(os.getenv("SPELL_WS_REPLAY_LIMIT", "1000")),
            websocket_queue_size=int(os.getenv("SPELL_WS_QUEUE_SIZE", "256")),
            websocket_keepalive_seconds=float(os.getenv("SPELL_WS_KEEPALIVE_SECONDS", "5")),
            command_ack_timeout_seconds=float(
                os.getenv("SPELL_COMMAND_ACK_TIMEOUT_SECONDS", "5")
            ),
        )
