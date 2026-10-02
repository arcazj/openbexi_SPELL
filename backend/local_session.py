"""Finite operator bootstrap for the explicitly enabled loopback simulator.

The reverse proxy is the sole published ingress and overwrites the marker on
this exact route. The marker is not an identity credential: Origin, Host,
Fetch Metadata and the custom JSON request header are independently required.
The browser cookie uses a separate audience and cannot authorize API calls.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import replace
from typing import Callable

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .auth import AuthConfig, AuthenticationError, decode_token, encode_token
from .config import Settings


SESSION_PATH = "/api/v1/local-session"
COOKIE_NAME = "spell_local_simulator"
COOKIE_AUDIENCE_SUFFIX = ":local-session:v16"
INGRESS_MARKER = "loopback-proxy-v16"
ACCESS_LIFETIME_SECONDS = 300
COOKIE_LIFETIME_SECONDS = 900
SUBJECT_PREFIX = "local.simulator."


def _response(payload: dict, status: int = 200) -> JSONResponse:
    return JSONResponse(payload, status_code=status, headers={
        "Cache-Control": "no-store", "Pragma": "no-cache",
        "Vary": "Origin", "X-Content-Type-Options": "nosniff",
    })


def install_local_session_api(
    app: FastAPI, settings: Settings, get_auth_config: Callable[[], AuthConfig],
) -> None:
    @app.post(SESSION_PATH)
    async def local_session(request: Request) -> JSONResponse:
        if not settings.local_session_enabled:
            return _response({"detail": "Local simulator connection is disabled"}, 404)

        origins = {
            f"http://127.0.0.1:{settings.local_session_port}",
            f"http://localhost:{settings.local_session_port}",
        }
        origin = request.headers.get("origin", "")
        required = {
            "origin": origin,
            "host": origin.removeprefix("http://"),
            "sec-fetch-site": "same-origin",
            "x-spell-local-session": "bootstrap-v16",
            "x-spell-local-ingress": INGRESS_MARKER,
            "content-type": "application/json",
        }
        if (
            origin not in origins or request.url.query
            or any(request.headers.getlist(name) != [value] for name, value in required.items())
        ):
            return _response({"detail": "Local simulator connection rejected"}, 403)
        body = b""
        async for chunk in request.stream():
            body += chunk
            if len(body) > 32:
                return _response({"detail": "Local simulator request must be empty JSON"}, 400)
        try:
            if json.loads(body) != {}:
                raise ValueError
        except (ValueError, UnicodeError):
            return _response({"detail": "Local simulator request must be empty JSON"}, 400)

        auth = get_auth_config()
        # Cookie validation has no grace: an expired identity starts a new session.
        cookie_auth = replace(auth, audience=auth.audience + COOKIE_AUDIENCE_SUFFIX,
                              clock_skew_seconds=0)
        now = int(time.time())
        subject = SUBJECT_PREFIX + str(uuid.uuid4())
        cookie = request.cookies.get(COOKIE_NAME)
        if cookie:
            try:
                identity = decode_token(cookie_auth, cookie, now=now)
                if identity.role != "operator" or not identity.subject.startswith(SUBJECT_PREFIX):
                    raise AuthenticationError("invalid local identity")
                uuid.UUID(identity.subject.removeprefix(SUBJECT_PREFIX))
                subject = identity.subject
            except (AuthenticationError, ValueError):
                # Never use unverified cookie claims, even to select the subject.
                # Expiry/rotation is normal: replace it with a fresh local identity.
                pass

        def issue(config: AuthConfig, lifetime: int) -> str:
            return encode_token(config, {
                "iss": config.issuer, "aud": config.audience,
                "sub": subject, "role": "operator", "iat": now, "nbf": now,
                "exp": now + lifetime, "jti": str(uuid.uuid4()),
            })

        lifetime = min(ACCESS_LIFETIME_SECONDS, auth.max_token_lifetime_seconds)
        cookie_lifetime = min(COOKIE_LIFETIME_SECONDS, auth.max_token_lifetime_seconds)
        response = _response({
            "access_token": issue(auth, lifetime), "token_type": "Bearer",
            "expires_at": now + lifetime, "role": "operator",
            "mode": "simulator-only", "operational_use": False,
        })
        response.set_cookie(
            COOKIE_NAME, issue(cookie_auth, cookie_lifetime), max_age=cookie_lifetime,
            path=SESSION_PATH, httponly=True, samesite="strict", secure=False,
        )
        return response
