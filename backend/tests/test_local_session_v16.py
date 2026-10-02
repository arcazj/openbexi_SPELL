from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.auth import AuthenticationError, decode_token
from backend.config import Settings
from backend.local_session import COOKIE_NAME, COOKIE_AUDIENCE_SUFFIX, install_local_session_api

ORIGIN = "http://127.0.0.1:8080"
HEADERS = {
    "Origin": ORIGIN, "Sec-Fetch-Site": "same-origin",
    "X-Spell-Local-Session": "bootstrap-v16",
    "X-Spell-Local-Ingress": "loopback-proxy-v16",
    "Content-Type": "application/json",
}


@pytest.fixture
def settings(tmp_path: Path):
    return Settings(database_url="sqlite://", procedures_dir=tmp_path,
                    websocket_replay_limit=10, websocket_queue_size=10,
                    websocket_keepalive_seconds=1, local_session_enabled=True)


@pytest.fixture
def local_client(settings, auth_config):
    app = FastAPI()
    install_local_session_api(app, settings, lambda: replace(auth_config, allow_local_dev_issuance=False))
    with TestClient(app, base_url=ORIGIN) as client:
        yield client


def bootstrap(client, headers=None, body="{}", path="/api/v1/local-session"):
    return client.post(path, headers=HEADERS if headers is None else headers, content=body)


def test_bootstrap_finite_operator_only_without_development_issuer(local_client, auth_config):
    response = bootstrap(local_client, {**HEADERS, "X-Spell-Role": "admin", "X-Spell-Actor": "spoof"})
    assert response.status_code == 200
    data = response.json()
    identity = decode_token(auth_config, data["access_token"])
    assert identity.role == data["role"] == "operator"
    assert identity.subject.startswith("local.simulator.")
    assert identity.subject != "spoof"
    assert identity.expires_at - identity.issued_at == 300
    assert data["mode"] == "simulator-only" and data["operational_use"] is False
    assert data["expires_at"] == identity.expires_at
    assert response.headers["cache-control"] == "no-store"
    cookie = response.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie and "Max-Age=900" in cookie
    assert "Path=/api/v1/local-session" in cookie
    with pytest.raises(AuthenticationError, match="audience"):
        decode_token(auth_config, local_client.cookies.get(COOKIE_NAME))


def test_cookie_retains_subject_across_reload_and_renewal(local_client, auth_config):
    first = decode_token(auth_config, bootstrap(local_client).json()["access_token"])
    renewed = decode_token(auth_config, bootstrap(local_client).json()["access_token"])
    assert first.subject == renewed.subject and first.token_id != renewed.token_id


@pytest.mark.parametrize("cookie", ["tampered.payload.signature", "expired"])
def test_untrusted_or_expired_cookie_never_selects_actor(local_client, auth_config, monkeypatch, cookie):
    from backend import local_session
    first = decode_token(auth_config, bootstrap(local_client).json()["access_token"])
    if cookie == "expired":
        monkeypatch.setattr(local_session.time, "time", lambda: first.issued_at + 901)
    else:
        local_client.cookies.clear()
        local_client.cookies.set(COOKIE_NAME, cookie)
    data = bootstrap(local_client).json()
    fresh = decode_token(auth_config, data["access_token"], now=data["expires_at"] - 1)
    assert fresh.role == "operator" and fresh.subject != first.subject


@pytest.mark.parametrize("name,value", [
    ("Origin", None), ("Origin", "http://evil.invalid:8080"),
    ("Origin", "http://127.0.0.1:8081"), ("Origin", "null"),
    ("Origin", "http://127.0.0.1.evil.invalid:8080"),
    ("Sec-Fetch-Site", None), ("Sec-Fetch-Site", "cross-site"),
    ("Sec-Fetch-Site", "same-site"), ("X-Spell-Local-Session", None),
    ("X-Spell-Local-Ingress", None), ("Content-Type", "text/plain"),
    ("Host", "evil.invalid:8080"), ("Host", "localhost:8080"),
])
def test_bootstrap_rejects_cross_origin_or_missing_boundary(local_client, name, value):
    headers = dict(HEADERS)
    if value is None:
        headers.pop(name)
    else:
        headers[name] = value
    response = bootstrap(local_client, headers)
    assert response.status_code == 403
    assert "access_token" not in response.json() and "set-cookie" not in response.headers


@pytest.mark.parametrize("body", ['{"role":"admin"}', '[]', 'null', '', '{} ' * 20])
def test_bootstrap_has_no_identity_or_arbitrary_input(local_client, body):
    assert bootstrap(local_client, body=body).status_code == 400


def test_bootstrap_rejects_query_and_duplicate_origin(local_client):
    assert bootstrap(local_client, path="/api/v1/local-session?role=admin").status_code == 403
    headers = list(HEADERS.items()) + [("Origin", ORIGIN)]
    assert bootstrap(local_client, headers).status_code == 403
    assert local_client.get("/api/v1/local-session", headers=HEADERS).status_code == 405


def test_default_backend_disables_bootstrap_and_preserves_auth(client):
    assert client.post("/api/v1/local-session", headers=HEADERS, json={}).status_code == 404
    assert client.get("/api/v1/procedures").status_code == 401


def test_issued_operator_has_existing_api_permissions_not_admin(local_client, client):
    token = bootstrap(local_client).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}", "X-Spell-Session-Id": "browser-session",
               "X-Spell-Client-Instance-Key-Id": "browser-client"}
    assert client.get("/api/v1/procedures", headers=headers).status_code == 200
    response = client.put("/api/v1/contexts/simulator/settings", headers=headers, json={
        "settings": {"PROMPT_WARNING_DELAY": 1}, "expected_revision": 1, "idempotency_key": "local-forbidden",
        "reason": "Cannot elevate local operator",
    })
    assert response.status_code == 403


def test_smaller_configured_token_lifetime_is_respected(settings, auth_config):
    auth = replace(auth_config, max_token_lifetime_seconds=60)
    app = FastAPI()
    install_local_session_api(app, settings, lambda: auth)
    with TestClient(app, base_url=ORIGIN) as client:
        response = bootstrap(client)
        identity = decode_token(auth, response.json()["access_token"])
        assert identity.expires_at - identity.issued_at == 60
        cookie_config = replace(auth, audience=auth.audience + COOKIE_AUDIENCE_SUFFIX)
        cookie = decode_token(cookie_config, client.cookies.get(COOKIE_NAME))
        assert cookie.expires_at - cookie.issued_at == 60


def test_local_settings_are_explicit_and_fail_closed(monkeypatch, settings):
    monkeypatch.delenv("SPELL_LOCAL_SESSION_ENABLED", raising=False)
    assert Settings.from_env().local_session_enabled is False
    monkeypatch.setenv("SPELL_LOCAL_SESSION_ENABLED", "yes")
    with pytest.raises(ValueError, match="true or false"):
        Settings.from_env()
    with pytest.raises(ValueError, match="65535"):
        replace(settings, local_session_port=65536)
