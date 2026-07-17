from __future__ import annotations

import pytest

from backend.auth import (
    AuthConfig,
    AuthenticationError,
    AuthorizationError,
    authenticate_bearer,
    decode_token,
    encode_token,
    issue_local_dev_token,
    require_any_role,
)


NOW = 1_800_000_000


@pytest.fixture
def config() -> AuthConfig:
    return AuthConfig(
        issuer="https://issuer.invalid/spell-local",
        audience="openbexi-spell-api",
        signing_secret=b"test-only-secret-with-at-least-32-bytes",
        clock_skew_seconds=5,
        max_token_lifetime_seconds=600,
        allow_local_dev_issuance=True,
    )


def claims(**overrides):
    value = {
        "iss": "https://issuer.invalid/spell-local",
        "aud": "openbexi-spell-api",
        "sub": "operator.alice",
        "role": "operator",
        "iat": NOW,
        "nbf": NOW,
        "exp": NOW + 300,
        "jti": "test-token-id",
    }
    value.update(overrides)
    return value


def test_valid_signed_bearer_derives_server_identity(config: AuthConfig) -> None:
    token = encode_token(config, claims())
    identity = authenticate_bearer(f"Bearer {token}", config, now=NOW + 1)
    assert identity.subject == "operator.alice"
    assert identity.role == "operator"
    assert require_any_role(identity, {"operator", "admin"}) is identity


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"iss": "wrong"}, "issuer"),
        ({"aud": "wrong"}, "audience"),
        ({"sub": ""}, "subject"),
        ({"role": "owner"}, "role"),
        ({"exp": NOW - 10}, "expired"),
        ({"iat": NOW + 10}, "future"),
        ({"nbf": NOW + 10}, "active"),
        ({"exp": NOW + 601}, "lifetime"),
    ],
)
def test_claim_policy_is_strict(config: AuthConfig, overrides, message: str) -> None:
    with pytest.raises(AuthenticationError, match=message):
        decode_token(config, encode_token(config, claims(**overrides)), now=NOW)


def test_signature_tampering_and_algorithm_confusion_are_rejected(config: AuthConfig) -> None:
    token = encode_token(config, claims())
    header, payload, signature = token.split(".")
    with pytest.raises(AuthenticationError, match="signature"):
        decode_token(config, f"{header}.{payload}.{signature[:-1]}A", now=NOW)
    with pytest.raises(AuthenticationError, match="malformed JWT segment"):
        decode_token(config, f"{header}.{payload}.{signature}!", now=NOW)

    none_header = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
    with pytest.raises(AuthenticationError, match="HS256"):
        decode_token(config, f"{none_header}.{payload}.", now=NOW)


def test_role_is_never_taken_from_spoofable_headers(config: AuthConfig) -> None:
    token = encode_token(config, claims(role="viewer", sub="viewer.bob"))
    spoofed_headers = {"X-Dev-Actor": "admin.mallory", "X-Dev-Role": "admin"}
    identity = authenticate_bearer(f"Bearer {token}", config, now=NOW)
    assert spoofed_headers["X-Dev-Role"] != identity.role
    with pytest.raises(AuthorizationError):
        require_any_role(identity, {"admin"})


def test_local_issuer_requires_explicit_enablement_and_loopback(config: AuthConfig) -> None:
    token = issue_local_dev_token(
        config,
        subject="local.operator",
        role="operator",
        peer_host="127.0.0.1",
        now=NOW,
    )
    assert decode_token(config, token, now=NOW).subject == "local.operator"
    with pytest.raises(AuthorizationError, match="loopback"):
        issue_local_dev_token(config, "local.operator", "operator", "192.0.2.10", now=NOW)

    disabled = AuthConfig(
        issuer=config.issuer,
        audience=config.audience,
        signing_secret=config.signing_secret,
        allow_local_dev_issuance=False,
    )
    with pytest.raises(AuthorizationError, match="disabled"):
        issue_local_dev_token(disabled, "local.operator", "operator", "127.0.0.1", now=NOW)
