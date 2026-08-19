from __future__ import annotations

import math
import os
from dataclasses import dataclass
from pathlib import Path


DRIVER_TARGET = "spell-driver:50051"
DRIVER_CA_PATH = Path("/run/spell-driver-client/ca.crt")
DRIVER_CLIENT_CERT_PATH = Path("/run/spell-driver-client/client.crt")
DRIVER_CLIENT_KEY_PATH = Path("/run/spell-driver-client/client.key")


def _strict_bool(name: str, value: str) -> bool:
    normalized = value.strip().lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    raise ValueError(f"{name} must be true or false")


@dataclass(frozen=True)
class Settings:
    database_url: str
    procedures_dir: Path
    websocket_replay_limit: int
    websocket_queue_size: int
    websocket_keepalive_seconds: float
    command_ack_timeout_seconds: float = 5.0
    driver_enabled: bool = False
    driver_target: str = DRIVER_TARGET
    driver_ca_path: Path = DRIVER_CA_PATH
    driver_client_cert_path: Path = DRIVER_CLIENT_CERT_PATH
    driver_client_key_path: Path = DRIVER_CLIENT_KEY_PATH
    driver_rpc_timeout_seconds: float = 2.0
    driver_poll_seconds: float = 1.0
    driver_stale_after_seconds: float = 5.0
    observation_poll_seconds: float = 0.2
    observation_freshness_sweep_seconds: float = 0.5
    data_dir: Path | None = None
    v0007_backup_directory: Path | None = None
    bundle_request_directory: Path | None = None
    bundle_response_a_directory: Path | None = None
    bundle_response_b_directory: Path | None = None
    bundle_build_timeout_seconds: float = 30.0

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
        if self.driver_target != DRIVER_TARGET:
            raise ValueError("the v0.4 driver target must be the bundled simulator service")
        for name, value in (
            ("SPELL_DRIVER_RPC_TIMEOUT_SECONDS", self.driver_rpc_timeout_seconds),
            ("SPELL_DRIVER_POLL_SECONDS", self.driver_poll_seconds),
            ("SPELL_DRIVER_STALE_AFTER_SECONDS", self.driver_stale_after_seconds),
        ):
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be a positive finite number")
        if self.driver_stale_after_seconds <= self.driver_poll_seconds:
            raise ValueError(
                "SPELL_DRIVER_STALE_AFTER_SECONDS must exceed SPELL_DRIVER_POLL_SECONDS"
            )
        for name, value in (
            ("SPELL_OBSERVATION_POLL_SECONDS", self.observation_poll_seconds),
            (
                "SPELL_OBSERVATION_FRESHNESS_SWEEP_SECONDS",
                self.observation_freshness_sweep_seconds,
            ),
        ):
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be a positive finite number")
        if self.driver_enabled:
            fixed_paths = (
                (self.driver_ca_path, DRIVER_CA_PATH),
                (self.driver_client_cert_path, DRIVER_CLIENT_CERT_PATH),
                (self.driver_client_key_path, DRIVER_CLIENT_KEY_PATH),
            )
            if any(actual != expected for actual, expected in fixed_paths):
                raise ValueError("driver credential paths must use the fixed service mount")
        if self.data_dir is not None:
            data_dir = self.data_dir.resolve(strict=False)
            procedures_dir = self.procedures_dir.resolve(strict=False)
            if (
                data_dir == procedures_dir
                or procedures_dir in data_dir.parents
                or data_dir in procedures_dir.parents
            ):
                raise ValueError("SPELL_DATA_DIR must be separate from executable procedures")
        if (
            self.v0007_backup_directory is not None
            and not self.v0007_backup_directory.is_absolute()
        ):
            raise ValueError("SPELL_V0007_BACKUP_DIR must be an absolute path")
        builder_directories = (
            self.bundle_request_directory,
            self.bundle_response_a_directory,
            self.bundle_response_b_directory,
        )
        if any(item is not None for item in builder_directories):
            if any(item is None for item in builder_directories):
                raise ValueError("all three bundle builder directories are required")
            concrete = tuple(item for item in builder_directories if item is not None)
            if any(not item.is_absolute() for item in concrete):
                raise ValueError("bundle builder directories must be absolute paths")
            normalized = tuple(item.resolve(strict=False) for item in concrete)
            if len(set(normalized)) != 3 or any(
                left in right.parents or right in left.parents
                for index, left in enumerate(normalized)
                for right in normalized[index + 1 :]
            ):
                raise ValueError("bundle builder directories must be separate")
        if (
            not math.isfinite(self.bundle_build_timeout_seconds)
            or not 0.1 <= self.bundle_build_timeout_seconds <= 120.0
        ):
            raise ValueError(
                "SPELL_BUNDLE_BUILD_TIMEOUT_SECONDS must be between 0.1 and 120"
            )

    @property
    def resolved_data_dir(self) -> Path:
        if self.data_dir is not None:
            return self.data_dir.resolve(strict=False)
        if self.database_url.startswith("sqlite:///"):
            database_path = Path(self.database_url.removeprefix("sqlite:///"))
            return database_path.resolve(strict=False).parent / "spell-data"
        return Path(__file__).resolve().parents[1] / "var" / "spell-data"

    @property
    def bundle_builder_configured(self) -> bool:
        return self.bundle_request_directory is not None

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
            driver_enabled=_strict_bool(
                "SPELL_DRIVER_ENABLED", os.getenv("SPELL_DRIVER_ENABLED", "false")
            ),
            driver_target=DRIVER_TARGET,
            driver_ca_path=DRIVER_CA_PATH,
            driver_client_cert_path=DRIVER_CLIENT_CERT_PATH,
            driver_client_key_path=DRIVER_CLIENT_KEY_PATH,
            driver_rpc_timeout_seconds=float(
                os.getenv("SPELL_DRIVER_RPC_TIMEOUT_SECONDS", "2")
            ),
            driver_poll_seconds=float(os.getenv("SPELL_DRIVER_POLL_SECONDS", "1")),
            driver_stale_after_seconds=float(
                os.getenv("SPELL_DRIVER_STALE_AFTER_SECONDS", "5")
            ),
            observation_poll_seconds=float(
                os.getenv("SPELL_OBSERVATION_POLL_SECONDS", "0.2")
            ),
            observation_freshness_sweep_seconds=float(
                os.getenv("SPELL_OBSERVATION_FRESHNESS_SWEEP_SECONDS", "0.5")
            ),
            data_dir=Path(os.getenv("SPELL_DATA_DIR", root / "var" / "spell-data")),
            v0007_backup_directory=(
                Path(value)
                if (value := os.getenv("SPELL_V0007_BACKUP_DIR"))
                else None
            ),
            bundle_request_directory=(
                Path(value)
                if (value := os.getenv("SPELL_BUNDLE_REQUEST_DIR"))
                else None
            ),
            bundle_response_a_directory=(
                Path(value)
                if (value := os.getenv("SPELL_BUNDLE_RESPONSE_A_DIR"))
                else None
            ),
            bundle_response_b_directory=(
                Path(value)
                if (value := os.getenv("SPELL_BUNDLE_RESPONSE_B_DIR"))
                else None
            ),
            bundle_build_timeout_seconds=float(
                os.getenv("SPELL_BUNDLE_BUILD_TIMEOUT_SECONDS", "30")
            ),
        )
