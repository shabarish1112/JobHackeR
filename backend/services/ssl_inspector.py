"""TLS certificate inspection with SSRF-aware address validation."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from datetime import datetime, timezone


class UnsafeAddressError(ValueError):
    """Raised when a hostname resolves to a non-public address."""


class SSLInspector:
    """Perform a certificate-validated TLS handshake without shelling out."""

    async def inspect(self, host: str, port: int = 443) -> dict:
        return await asyncio.to_thread(self._inspect_sync, host, port)

    @staticmethod
    def _validate_public_resolution(host: str, port: int) -> None:
        if not 1 <= port <= 65535:
            raise UnsafeAddressError("Invalid network port.")
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        if not addresses:
            raise UnsafeAddressError("Host did not resolve to an address.")
        for item in addresses:
            ip = ipaddress.ip_address(item[4][0])
            if any((ip.is_private, ip.is_loopback, ip.is_link_local, ip.is_multicast, ip.is_reserved, ip.is_unspecified)):
                raise UnsafeAddressError("Host resolves to a private or reserved address.")

    def _inspect_sync(self, host: str, port: int) -> dict:
        context = ssl.create_default_context()
        try:
            self._validate_public_resolution(host, port)
            with socket.create_connection((host, port), timeout=5) as raw:
                with context.wrap_socket(raw, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    expires = ssl.cert_time_to_seconds(cert["notAfter"]) if cert.get("notAfter") else None
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    subject = dict(x[0] for x in cert.get("subject", []))
                    return {
                        "valid": True,
                        "tls_version": tls.version(),
                        "issuer": issuer.get("organizationName") or issuer.get("commonName"),
                        "subject": subject.get("commonName"),
                        "expires_at": datetime.fromtimestamp(expires, timezone.utc).isoformat() if expires else None,
                        "error": None,
                        "source": "Live TLS handshake",
                    }
        except Exception as exc:
            return {
                "valid": False,
                "tls_version": None,
                "issuer": None,
                "subject": None,
                "expires_at": None,
                "error": str(exc),
                "source": "Live TLS handshake",
            }
