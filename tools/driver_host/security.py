"""Fail-closed per-RPC authorization for the local mTLS driver boundary."""

from __future__ import annotations

import logging
from collections import Counter, defaultdict
from typing import Any, Iterable

import grpc

from .config import HostConfig
from .certificates import certificate_fingerprint


CONTRACT_MAJOR_METADATA = "x-spell-contract-major"
CREDENTIAL_EPOCH_METADATA = "x-spell-credential-epoch"
EXPECTED_CONTRACT_MAJOR = "1"
LOGGER = logging.getLogger("spell.driver.security")


def _decoded(values: Iterable[bytes]) -> tuple[str, ...]:
    try:
        return tuple(value.decode("utf-8", "strict") for value in values)
    except UnicodeDecodeError as exc:
        raise ValueError("peer identity is not valid UTF-8") from exc


class DriverAuthorizationInterceptor(grpc.aio.ServerInterceptor):
    """Require the approved role, epoch, and contract major before dispatch."""

    def __init__(self, config: HostConfig) -> None:
        self._expected_san = config.expected_client_san
        self._expected_common_name = config.expected_client_common_name
        self._expected_epoch = str(config.credential_epoch)
        self._revoked = frozenset(config.revoked_client_fingerprints)
        self.audit_counts: Counter[str] = Counter()

    async def _deny(
        self,
        context: grpc.aio.ServicerContext,
        reason: str,
        code: grpc.StatusCode,
        message: str,
    ) -> None:
        self.audit_counts[reason] += 1
        LOGGER.warning("driver RPC authorization rejected reason=%s", reason)
        await context.abort(code, message)

    async def _authorize(
        self, context: grpc.aio.ServicerContext, metadata: Any
    ) -> None:
        grouped: dict[str, list[str]] = defaultdict(list)
        for item in metadata:
            if item.key in {CONTRACT_MAJOR_METADATA, CREDENTIAL_EPOCH_METADATA}:
                grouped[item.key].append(item.value)
        if grouped[CONTRACT_MAJOR_METADATA] != [EXPECTED_CONTRACT_MAJOR]:
            await self._deny(
                context,
                "contract_major_rejected",
                grpc.StatusCode.FAILED_PRECONDITION,
                "driver contract major metadata is missing or unsupported",
            )
        if grouped[CREDENTIAL_EPOCH_METADATA] != [self._expected_epoch]:
            await self._deny(
                context,
                "credential_epoch_rejected",
                grpc.StatusCode.UNAUTHENTICATED,
                "driver credential epoch is missing or stale",
            )

        auth = context.auth_context()
        if _decoded(auth.get("transport_security_type", ())) not in {
            ("ssl",),
            ("tls",),
        }:
            await self._deny(
                context,
                "transport_rejected",
                grpc.StatusCode.UNAUTHENTICATED,
                "mutual TLS authentication is required",
            )
        try:
            sans = _decoded(auth.get("x509_subject_alternative_name", ()))
            common_names = _decoded(auth.get("x509_common_name", ()))
        except ValueError:
            await self._deny(
                context,
                "peer_identity_rejected",
                grpc.StatusCode.PERMISSION_DENIED,
                "peer service identity is invalid",
            )
        if sans != (self._expected_san,) or common_names != (
            self._expected_common_name,
        ):
            await self._deny(
                context,
                "peer_role_rejected",
                grpc.StatusCode.PERMISSION_DENIED,
                "peer certificate is not authorized for the driver gateway role",
            )

        peer_certificates = tuple(auth.get("x509_pem_cert", ()))
        if len(peer_certificates) != 1:
            await self._deny(
                context,
                "peer_certificate_missing",
                grpc.StatusCode.UNAUTHENTICATED,
                "peer leaf certificate evidence is unavailable",
            )
        try:
            fingerprint = certificate_fingerprint(peer_certificates[0])
        except ValueError:
            await self._deny(
                context,
                "peer_certificate_invalid",
                grpc.StatusCode.UNAUTHENTICATED,
                "peer leaf certificate evidence is invalid",
            )
        if fingerprint in self._revoked:
            await self._deny(
                context,
                "peer_certificate_revoked",
                grpc.StatusCode.PERMISSION_DENIED,
                "peer certificate is revoked",
            )
        self.audit_counts["authorized"] += 1

    async def intercept_service(self, continuation: Any, handler_call_details: Any) -> Any:
        handler = await continuation(handler_call_details)
        if handler is None or handler.unary_unary is None:
            self.audit_counts["unknown_rpc"] += 1
            LOGGER.warning("driver RPC authorization rejected reason=unknown_rpc")
            return handler

        async def authorized_unary_unary(request: Any, context: Any) -> Any:
            await self._authorize(context, handler_call_details.invocation_metadata)
            return await handler.unary_unary(request, context)

        return grpc.unary_unary_rpc_method_handler(
            authorized_unary_unary,
            request_deserializer=handler.request_deserializer,
            response_serializer=handler.response_serializer,
        )
