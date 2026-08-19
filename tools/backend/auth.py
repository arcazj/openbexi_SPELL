"""Strict JWT authentication primitives for the SPELL control plane.

This module intentionally has no FastAPI dependency. HTTP adapters must derive
identity exclusively from ``authenticate_bearer`` and must not consult client-
supplied actor or role headers.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any, Iterable


ALLOWED_ROLES = frozenset({"viewer", "operator", "admin"})
JWT_ALGORITHM = "HS256"


class AuthenticationError(ValueError):
    """Raised when a credential cannot be authenticated."""


class AuthorizationError(PermissionError):
    """Raised when an authenticated subject lacks a required role."""


@dataclass(frozen=True)
class AuthConfig:
    issuer: str
    audience: str
    signing_secret: bytes
    clock_skew_seconds: int = 30
    max_token_lifetime_seconds: int = 900
    allow_local_dev_issuance: bool = False

    def __post_init__(self) -> None:
        if not self.issuer or not self.audience:
            raise ValueError("JWT issuer and audience are required")
        if len(self.signing_secret) < 32:
            raise ValueError("JWT HS256 signing secret must contain at least 32 bytes")
        if self.clock_skew_seconds < 0 or self.max_token_lifetime_seconds < 1:
            raise ValueError("JWT time limits are invalid")

    @classmethod
    def from_env(cls) -> "AuthConfig":
        secret = os.getenv("SPELL_JWT_HS256_SECRET", "")
        return cls(
            issuer=os.getenv("SPELL_JWT_ISSUER", "openbexi-spell-local"),
            audience=os.getenv("SPELL_JWT_AUDIENCE", "openbexi-spell-api"),
            signing_secret=secret.encode("utf-8"),
            clock_skew_seconds=int(os.getenv("SPELL_JWT_CLOCK_SKEW_SECONDS", "30")),
            max_token_lifetime_seconds=int(os.getenv("SPELL_JWT_MAX_LIFETIME_SECONDS", "900")),
            allow_local_dev_issuance=os.getenv("SPELL_ALLOW_LOCAL_DEV_TOKEN", "false").lower()
            == "true",
        )


@dataclass(frozen=True)
class Identity:
    subject: str
    role: str
    issuer: str
    audience: str
    expires_at: int
    issued_at: int
    token_id: str


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    if not value or any(
        character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        for character in value
    ):
        raise AuthenticationError("malformed JWT segment")
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, UnicodeError) as exc:
        raise AuthenticationError("invalid JWT base64 encoding") from exc
    if _b64url_encode(decoded) != value:
        raise AuthenticationError("non-canonical JWT base64 encoding")
    return decoded


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AuthenticationError(f"duplicate JWT field: {key}")
        result[key] = value
    return result


def _decode_object(segment: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            _b64url_decode(segment),
            object_pairs_hook=_unique_json_object,
        )
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise AuthenticationError(f"invalid JWT {label}") from exc
    if not isinstance(value, dict):
        raise AuthenticationError(f"JWT {label} must be an object")
    return value


def _integer_claim(payload: dict[str, Any], name: str, required: bool = True) -> int | None:
    value = payload.get(name)
    if value is None and not required:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise AuthenticationError(f"JWT {name} claim must be an integer")
    return value


def encode_token(config: AuthConfig, claims: dict[str, Any]) -> str:
    header = {"alg": JWT_ALGORITHM, "typ": "JWT"}
    header_segment = _b64url_encode(
        json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    payload_segment = _b64url_encode(
        json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
    signature = hmac.new(config.signing_secret, signing_input, hashlib.sha256).digest()
    return f"{header_segment}.{payload_segment}.{_b64url_encode(signature)}"


def decode_token(config: AuthConfig, token: str, now: int | None = None) -> Identity:
    parts = token.split(".")
    if len(parts) != 3:
        raise AuthenticationError("JWT must contain exactly three segments")
    header_segment, payload_segment, signature_segment = parts
    header = _decode_object(header_segment, "header")
    if header != {"alg": JWT_ALGORITHM, "typ": "JWT"}:
        raise AuthenticationError("JWT header must specify only HS256 and JWT")

    signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
    expected = hmac.new(config.signing_secret, signing_input, hashlib.sha256).digest()
    supplied = _b64url_decode(signature_segment)
    if not hmac.compare_digest(expected, supplied):
        raise AuthenticationError("invalid JWT signature")

    payload = _decode_object(payload_segment, "payload")
    issuer = payload.get("iss")
    if issuer != config.issuer:
        raise AuthenticationError("invalid JWT issuer")
    audience_claim = payload.get("aud")
    audiences = [audience_claim] if isinstance(audience_claim, str) else audience_claim
    if not isinstance(audiences, list) or config.audience not in audiences or not all(
        isinstance(item, str) for item in audiences
    ):
        raise AuthenticationError("invalid JWT audience")

    subject = payload.get("sub")
    role = payload.get("role")
    token_id = payload.get("jti")
    if not isinstance(subject, str) or not subject.strip():
        raise AuthenticationError("JWT subject is required")
    if role not in ALLOWED_ROLES:
        raise AuthenticationError("JWT role is invalid")
    if not isinstance(token_id, str) or not token_id:
        raise AuthenticationError("JWT token identifier is required")

    current = int(time.time()) if now is None else now
    expires_at = _integer_claim(payload, "exp")
    issued_at = _integer_claim(payload, "iat")
    not_before = _integer_claim(payload, "nbf", required=False)
    assert expires_at is not None and issued_at is not None
    if expires_at <= current - config.clock_skew_seconds:
        raise AuthenticationError("JWT has expired")
    if issued_at > current + config.clock_skew_seconds:
        raise AuthenticationError("JWT was issued in the future")
    if not_before is not None and not_before > current + config.clock_skew_seconds:
        raise AuthenticationError("JWT is not active")
    if expires_at <= issued_at:
        raise AuthenticationError("JWT expiry must follow issuance")
    if expires_at - issued_at > config.max_token_lifetime_seconds:
        raise AuthenticationError("JWT lifetime exceeds policy")

    return Identity(
        subject=subject,
        role=role,
        issuer=issuer,
        audience=config.audience,
        expires_at=expires_at,
        issued_at=issued_at,
        token_id=token_id,
    )


def authenticate_bearer(
    authorization: str | None,
    config: AuthConfig,
    now: int | None = None,
) -> Identity:
    if not authorization or not authorization.startswith("Bearer "):
        raise AuthenticationError("Bearer authorization is required")
    token = authorization.removeprefix("Bearer ")
    if not token or " " in token:
        raise AuthenticationError("Bearer authorization is malformed")
    return decode_token(config, token, now=now)


def require_any_role(identity: Identity, allowed_roles: Iterable[str]) -> Identity:
    allowed = frozenset(allowed_roles)
    if not allowed or not allowed <= ALLOWED_ROLES:
        raise ValueError("role policy contains an unsupported role")
    if identity.role not in allowed:
        raise AuthorizationError("authenticated role is not authorized")
    return identity


def issue_local_dev_token(
    config: AuthConfig,
    subject: str,
    role: str,
    peer_host: str,
    lifetime_seconds: int = 300,
    now: int | None = None,
) -> str:
    """Issue a short-lived token only under an explicit loopback-only policy."""

    if not config.allow_local_dev_issuance:
        raise AuthorizationError("local development token issuance is disabled")
    try:
        if not ipaddress.ip_address(peer_host).is_loopback:
            raise AuthorizationError("development tokens may be issued only from loopback")
    except ValueError as exc:
        raise AuthorizationError("development token peer must be a loopback IP address") from exc
    if not subject.strip() or role not in ALLOWED_ROLES:
        raise ValueError("development token subject or role is invalid")
    if lifetime_seconds < 1 or lifetime_seconds > config.max_token_lifetime_seconds:
        raise ValueError("development token lifetime exceeds policy")
    issued_at = int(time.time()) if now is None else now
    return encode_token(
        config,
        {
            "iss": config.issuer,
            "aud": config.audience,
            "sub": subject,
            "role": role,
            "iat": issued_at,
            "nbf": issued_at,
            "exp": issued_at + lifetime_seconds,
            "jti": str(uuid.uuid4()),
        },
    )
