"""Local test-only CA issuance with physically split client/server outputs."""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Sequence

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .config import (
    DEFAULT_CLIENT_COMMON_NAME,
    DEFAULT_CLIENT_SAN,
    DEFAULT_SERVER_NAME,
)
from .certificates import certificate_fingerprint


CLIENT_FILES = frozenset({"ca.crt", "client.crt", "client.key"})
SERVER_FILES = frozenset({"ca.crt", "server.crt", "server.key"})
MAX_CREDENTIAL_BYTES = 65_536


@dataclass(frozen=True)
class PkiBundle:
    ca_certificate: bytes
    client_certificate: bytes
    client_private_key: bytes
    server_certificate: bytes
    server_private_key: bytes

    @property
    def client_fingerprint(self) -> str:
        return certificate_fingerprint(self.client_certificate)

    @property
    def server_fingerprint(self) -> str:
        return certificate_fingerprint(self.server_certificate)


def _name(common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OpenBEXI SPELL local test"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def _private_key_bytes(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _certificate_bytes(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.PEM)


def generate_bundle(
    *,
    now: Optional[datetime] = None,
    client_common_name: str = DEFAULT_CLIENT_COMMON_NAME,
    client_san: str = DEFAULT_CLIENT_SAN,
    server_name: str = DEFAULT_SERVER_NAME,
    client_not_before: Optional[datetime] = None,
    client_not_after: Optional[datetime] = None,
) -> PkiBundle:
    """Issue one ephemeral local CA and narrowly scoped client/server leaves."""

    observed = now or datetime.now(timezone.utc)
    if observed.tzinfo is None:
        raise ValueError("PKI clock must be timezone-aware")
    observed = observed.astimezone(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = _name("openbexi-spell-local-test-ca")
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(observed - timedelta(minutes=5))
        .not_valid_after(observed + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
        .sign(ca_key, hashes.SHA256())
    )

    def issue_leaf(
        common_name: str,
        san: x509.GeneralName,
        eku: x509.ObjectIdentifier,
        not_before: datetime,
        not_after: datetime,
    ) -> tuple[bytes, bytes]:
        if not_after <= not_before:
            raise ValueError("leaf certificate validity interval is empty")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(_name(common_name))
            .issuer_name(ca_certificate.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage([eku]), critical=True)
            .add_extension(x509.SubjectAlternativeName([san]), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        return _certificate_bytes(certificate), _private_key_bytes(key)

    client_certificate, client_key = issue_leaf(
        client_common_name,
        x509.UniformResourceIdentifier(client_san),
        ExtendedKeyUsageOID.CLIENT_AUTH,
        client_not_before or observed - timedelta(minutes=5),
        client_not_after or observed + timedelta(days=7),
    )
    server_certificate, server_key = issue_leaf(
        server_name,
        x509.DNSName(server_name),
        ExtendedKeyUsageOID.SERVER_AUTH,
        observed - timedelta(minutes=5),
        observed + timedelta(days=7),
    )
    return PkiBundle(
        ca_certificate=_certificate_bytes(ca_certificate),
        client_certificate=client_certificate,
        client_private_key=client_key,
        server_certificate=server_certificate,
        server_private_key=server_key,
    )


def _prepare_directory(path: Path, expected: frozenset[str], force: bool) -> None:
    if path.is_symlink():
        raise ValueError("credential output directory must not be a symlink")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not path.is_dir():
        raise ValueError("credential output path must be a directory")
    present = {entry.name for entry in path.iterdir()}
    if present.difference(expected):
        raise ValueError("credential output directory contains unexpected files")
    if present and not force:
        raise FileExistsError("credential output directory is not empty")
    for name in present:
        candidate = path / name
        if candidate.is_symlink() or not candidate.is_file():
            raise ValueError("credential output contains a non-regular entry")
        candidate.unlink()
    path.chmod(0o700)


def _write_private(path: Path, content: bytes, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(descriptor)
    path.chmod(mode)


def _certificate_time(certificate: x509.Certificate, name: str) -> datetime:
    aware = getattr(certificate, f"{name}_utc", None)
    if aware is not None:
        return aware
    return getattr(certificate, name).replace(tzinfo=timezone.utc)


def _read_existing_file(
    directory: Path,
    name: str,
    *,
    mode: int,
    uid: int,
    gid: int,
) -> bytes:
    candidate = directory / name
    if candidate.is_symlink() or not candidate.is_file():
        raise ValueError("existing credential bundle contains a non-regular entry")
    metadata = candidate.stat()
    if metadata.st_uid != uid or metadata.st_gid != gid:
        raise ValueError("existing credential bundle ownership is invalid")
    if metadata.st_mode & 0o777 != mode:
        raise ValueError("existing credential bundle mode is invalid")
    if metadata.st_size < 1 or metadata.st_size > MAX_CREDENTIAL_BYTES:
        raise ValueError("existing credential bundle file size is invalid")
    return candidate.read_bytes()


def _validate_leaf(
    certificate: x509.Certificate,
    private_key: rsa.RSAPrivateKey,
    ca_certificate: x509.Certificate,
    *,
    extended_usage: x509.ObjectIdentifier,
    san_type: type[x509.GeneralName],
    san_value: str,
    common_name: str,
    now: datetime,
) -> None:
    if certificate.issuer != ca_certificate.subject:
        raise ValueError("existing leaf certificate has the wrong issuer")
    ca_public_key = ca_certificate.public_key()
    if not isinstance(ca_public_key, rsa.RSAPublicKey):
        raise ValueError("existing CA key type is unsupported")
    ca_public_key.verify(
        certificate.signature,
        certificate.tbs_certificate_bytes,
        padding.PKCS1v15(),
        certificate.signature_hash_algorithm,
    )
    certificate_public = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_public = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if certificate_public != private_public:
        raise ValueError("existing certificate and private key do not match")
    usages = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    if set(usages) != {extended_usage}:
        raise ValueError("existing leaf certificate usage is invalid")
    names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    if names.get_values_for_type(san_type) != [san_value]:
        raise ValueError("existing leaf certificate subject alternative name is invalid")
    common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if [item.value for item in common_names] != [common_name]:
        raise ValueError("existing leaf certificate common name is invalid")
    if not _certificate_time(certificate, "not_valid_before") <= now:
        raise ValueError("existing leaf certificate is not yet valid")
    if _certificate_time(certificate, "not_valid_after") <= now:
        raise ValueError("existing leaf certificate is expired")


def existing_split_bundle_fingerprints(
    client_directory: str | Path,
    server_directory: str | Path,
    *,
    client_uid: int,
    client_gid: int,
    server_uid: int,
    server_gid: int,
    now: Optional[datetime] = None,
) -> Optional[tuple[str, str]]:
    """Return fingerprints for a complete reusable bundle, or None when empty."""

    client_path = Path(client_directory)
    server_path = Path(server_directory)
    if client_path.is_symlink() or server_path.is_symlink():
        raise ValueError("credential output directory must not be a symlink")
    client_resolved = client_path.resolve()
    server_resolved = server_path.resolve()
    if (
        client_resolved == server_resolved
        or client_resolved in server_resolved.parents
        or server_resolved in client_resolved.parents
    ):
        raise ValueError("client and server credential directories must be disjoint")
    if not client_path.exists() and not server_path.exists():
        return None
    if not client_path.is_dir() or not server_path.is_dir():
        raise ValueError("credential output paths must both be directories")
    client_entries = {entry.name for entry in client_path.iterdir()}
    server_entries = {entry.name for entry in server_path.iterdir()}
    if not client_entries and not server_entries:
        return None
    for path, uid, gid in (
        (client_path, client_uid, client_gid),
        (server_path, server_uid, server_gid),
    ):
        metadata = path.stat()
        if metadata.st_uid != uid or metadata.st_gid != gid:
            raise ValueError("existing credential directory ownership is invalid")
        if metadata.st_mode & 0o777 != 0o700:
            raise ValueError("existing credential directory mode is invalid")
    if client_entries != CLIENT_FILES or server_entries != SERVER_FILES:
        raise ValueError("existing credential bundle is incomplete")

    client_values = {
        name: _read_existing_file(
            client_path,
            name,
            mode=0o400 if name == "client.key" else 0o644,
            uid=client_uid,
            gid=client_gid,
        )
        for name in CLIENT_FILES
    }
    server_values = {
        name: _read_existing_file(
            server_path,
            name,
            mode=0o600 if name == "server.key" else 0o644,
            uid=server_uid,
            gid=server_gid,
        )
        for name in SERVER_FILES
    }
    if client_values["ca.crt"] != server_values["ca.crt"]:
        raise ValueError("existing client and server bundles use different CAs")

    try:
        ca_certificate = x509.load_pem_x509_certificate(client_values["ca.crt"])
        client_certificate = x509.load_pem_x509_certificate(client_values["client.crt"])
        server_certificate = x509.load_pem_x509_certificate(server_values["server.crt"])
        client_key = serialization.load_pem_private_key(
            client_values["client.key"], password=None
        )
        server_key = serialization.load_pem_private_key(
            server_values["server.key"], password=None
        )
        if not isinstance(client_key, rsa.RSAPrivateKey) or not isinstance(
            server_key, rsa.RSAPrivateKey
        ):
            raise ValueError("existing private key type is unsupported")
        basic = ca_certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        if not basic.ca or basic.path_length != 0:
            raise ValueError("existing CA constraints are invalid")
        ca_public_key = ca_certificate.public_key()
        if not isinstance(ca_public_key, rsa.RSAPublicKey):
            raise ValueError("existing CA key type is unsupported")
        ca_public_key.verify(
            ca_certificate.signature,
            ca_certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            ca_certificate.signature_hash_algorithm,
        )
        observed = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        if not _certificate_time(ca_certificate, "not_valid_before") <= observed:
            raise ValueError("existing CA certificate is not yet valid")
        if _certificate_time(ca_certificate, "not_valid_after") <= observed:
            raise ValueError("existing CA certificate is expired")
        _validate_leaf(
            client_certificate,
            client_key,
            ca_certificate,
            extended_usage=ExtendedKeyUsageOID.CLIENT_AUTH,
            san_type=x509.UniformResourceIdentifier,
            san_value=DEFAULT_CLIENT_SAN,
            common_name=DEFAULT_CLIENT_COMMON_NAME,
            now=observed,
        )
        _validate_leaf(
            server_certificate,
            server_key,
            ca_certificate,
            extended_usage=ExtendedKeyUsageOID.SERVER_AUTH,
            san_type=x509.DNSName,
            san_value=DEFAULT_SERVER_NAME,
            common_name=DEFAULT_SERVER_NAME,
            now=observed,
        )
    except (
        InvalidSignature,
        TypeError,
        UnsupportedAlgorithm,
        ValueError,
        x509.ExtensionNotFound,
    ) as exc:
        raise ValueError("existing credential bundle failed validation") from exc
    return (
        certificate_fingerprint(client_values["client.crt"]),
        certificate_fingerprint(server_values["server.crt"]),
    )


def _set_owner(path: Path, uid: Optional[int], gid: Optional[int]) -> None:
    if uid is None or gid is None:
        return
    if uid < 0 or gid < 0:
        raise ValueError("credential UID and GID must be nonnegative")
    os.chown(path, uid, gid)


def write_split_bundle(
    bundle: PkiBundle,
    client_directory: str | Path,
    server_directory: str | Path,
    *,
    client_uid: Optional[int] = None,
    client_gid: Optional[int] = None,
    server_uid: Optional[int] = None,
    server_gid: Optional[int] = None,
    force: bool = False,
) -> None:
    client_input = Path(client_directory)
    server_input = Path(server_directory)
    if client_input.is_symlink() or server_input.is_symlink():
        raise ValueError("credential output directory must not be a symlink")
    client_path = client_input.resolve()
    server_path = server_input.resolve()
    if (
        client_path == server_path
        or client_path in server_path.parents
        or server_path in client_path.parents
    ):
        raise ValueError("client and server credential directories must be disjoint")
    _prepare_directory(client_path, CLIENT_FILES, force)
    _prepare_directory(server_path, SERVER_FILES, force)
    client_values = {
        "ca.crt": (bundle.ca_certificate, 0o644),
        "client.crt": (bundle.client_certificate, 0o644),
        "client.key": (bundle.client_private_key, 0o400),
    }
    server_values = {
        "ca.crt": (bundle.ca_certificate, 0o644),
        "server.crt": (bundle.server_certificate, 0o644),
        "server.key": (bundle.server_private_key, 0o600),
    }
    for name, (content, mode) in client_values.items():
        destination = client_path / name
        _write_private(destination, content, mode)
        _set_owner(destination, client_uid, client_gid)
    for name, (content, mode) in server_values.items():
        destination = server_path / name
        _write_private(destination, content, mode)
        _set_owner(destination, server_uid, server_gid)
    _set_owner(client_path, client_uid, client_gid)
    _set_owner(server_path, server_uid, server_gid)


def _environment_integer(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="issue split local v0.4 mTLS material")
    parser.add_argument("--client-dir", required=True)
    parser.add_argument("--server-dir", required=True)
    parser.add_argument(
        "--client-uid",
        type=int,
        default=_environment_integer("SPELL_DRIVER_CLIENT_UID", 10001),
    )
    parser.add_argument(
        "--client-gid",
        type=int,
        default=_environment_integer("SPELL_DRIVER_CLIENT_GID", 10001),
    )
    parser.add_argument(
        "--server-uid",
        type=int,
        default=_environment_integer("SPELL_DRIVER_SERVER_UID", 10002),
    )
    parser.add_argument(
        "--server-gid",
        type=int,
        default=_environment_integer("SPELL_DRIVER_SERVER_GID", 10002),
    )
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    fingerprints = None
    if not args.force:
        fingerprints = existing_split_bundle_fingerprints(
            args.client_dir,
            args.server_dir,
            client_uid=args.client_uid,
            client_gid=args.client_gid,
            server_uid=args.server_uid,
            server_gid=args.server_gid,
        )
    if fingerprints is None:
        bundle = generate_bundle()
        write_split_bundle(
            bundle,
            args.client_dir,
            args.server_dir,
            client_uid=args.client_uid,
            client_gid=args.client_gid,
            server_uid=args.server_uid,
            server_gid=args.server_gid,
            force=args.force,
        )
        fingerprints = (bundle.client_fingerprint, bundle.server_fingerprint)
    json.dump(
        {
            "client_fingerprint": fingerprints[0],
            "server_fingerprint": fingerprints[1],
        },
        sys.stdout,
        sort_keys=True,
    )
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
