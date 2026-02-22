"""TLS/SSL certificate inspection module."""

from __future__ import annotations

import hashlib
import logging
import socket
import ssl
from urllib.parse import urlparse

from ssi.models.investigation import SSLInfo
from ssi.osint import with_retries

logger = logging.getLogger(__name__)


def _extract_host_port(url: str) -> tuple[str, int]:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = parsed.hostname or url
    port = parsed.port or 443
    return host, port


@with_retries(max_retries=2, backoff_seconds=1.0, retryable_exceptions=(socket.timeout, ConnectionError, OSError))
def inspect_ssl(url: str) -> SSLInfo:
    """Connect to *url* and extract TLS certificate details.

    Args:
        url: Full URL or bare domain.

    Returns:
        Populated ``SSLInfo``.
    """
    host, port = _extract_host_port(url)
    logger.info("SSL inspection for %s:%d", host, port)

    ctx = ssl.create_default_context()
    info = SSLInfo()

    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                der_cert = ssock.getpeercert(binary_form=True)

                if cert:
                    info.subject = _format_dn(cert.get("subject", ()))
                    info.issuer = _format_dn(cert.get("issuer", ()))
                    info.serial_number = str(cert.get("serialNumber", ""))
                    info.not_before = cert.get("notBefore", "")
                    info.not_after = cert.get("notAfter", "")
                    info.san = [v for _, v in cert.get("subjectAltName", ())]
                    info.is_valid = True

                if der_cert:
                    info.fingerprint_sha256 = hashlib.sha256(der_cert).hexdigest()

                # Check self-signed: issuer == subject
                if info.issuer and info.subject and info.issuer == info.subject:
                    info.is_self_signed = True

    except ssl.SSLCertVerificationError as e:
        logger.warning("SSL verification failed for %s: %s", host, e)
        info.is_valid = False
    except Exception as e:
        logger.warning("SSL connection failed for %s: %s", host, e)

    return info


def _format_dn(dn_tuples: tuple) -> str:
    """Flatten an SSL distinguished name tuple into a readable string."""
    parts = []
    for rdn in dn_tuples:
        for attr, val in rdn:
            parts.append(f"{attr}={val}")
    return ", ".join(parts)
