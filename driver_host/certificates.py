"""Small certificate helpers shared by runtime authorization and PKI init."""

from __future__ import annotations

import hashlib
import ssl


def certificate_fingerprint(pem_certificate: bytes) -> str:
    """Return the lowercase SHA-256 fingerprint of one PEM certificate's DER."""

    try:
        der = ssl.PEM_cert_to_DER_cert(pem_certificate.decode("ascii"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("peer certificate is not valid PEM") from exc
    return hashlib.sha256(der).hexdigest()
