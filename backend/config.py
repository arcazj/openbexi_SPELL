from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    database_url: str
    procedures_dir: Path
    dev_auth_token: str
    websocket_replay_limit: int
    websocket_queue_size: int
    websocket_keepalive_seconds: float

    @classmethod
    def from_env(cls) -> "Settings":
        root = Path(__file__).resolve().parents[1]
        return cls(
            database_url=os.getenv(
                "DATABASE_URL", f"sqlite:///{(root / 'var' / 'spell_v02.db').as_posix()}"
            ),
            procedures_dir=Path(os.getenv("SPELL_PROCEDURES_DIR", root / "procedures")),
            dev_auth_token=os.getenv("SPELL_DEV_AUTH_TOKEN", "spell-dev-token"),
            websocket_replay_limit=int(os.getenv("SPELL_WS_REPLAY_LIMIT", "1000")),
            websocket_queue_size=int(os.getenv("SPELL_WS_QUEUE_SIZE", "256")),
            websocket_keepalive_seconds=float(os.getenv("SPELL_WS_KEEPALIVE_SECONDS", "5")),
        )
