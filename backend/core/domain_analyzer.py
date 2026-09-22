"""Pure URL/domain parsing and deterministic risk analysis."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from rapidfuzz.distance import Levenshtein


class DomainAnalysisError(ValueError):
    """Raised when a supplied URL is malformed or unsafe to inspect."""


class DomainAnalyzer:
    """Parse a web URL and expose safe, deterministic domain signals."""

    ALLOWED_SCHEMES = {"http", "https"}
    SUSPICIOUS_TOKENS = {"login", "verify", "secure", "update", "payment", "wallet", "hr", "career"}

    def __init__(self, url: str) -> None:
        if not url or not isinstance(url, str):
            raise DomainAnalysisError("URL must be a non-empty string.")

        raw = url.strip()
        candidate = raw if "://" in raw else f"https://{raw}"
        parsed = urlparse(candidate)
        scheme = parsed.scheme.lower()
        if scheme not in self.ALLOWED_SCHEMES:
            raise DomainAnalysisError("Only HTTP and HTTPS URLs are supported.")
        if parsed.username or parsed.password:
            raise DomainAnalysisError("URLs containing embedded credentials are not accepted.")

        host = (parsed.hostname or "").strip(".").lower()
        if not host:
            raise DomainAnalysisError(f"Unable to extract a domain from '{url}'.")

        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            self.is_ip_address = False
        else:
            self.is_ip_address = True
            if self._is_non_public_ip(ip):
                raise DomainAnalysisError("Private, loopback or reserved IP addresses cannot be inspected.")

        self.original_url = raw
        self.normalized_url = parsed.geturl()
        self.host = host
        self.port = parsed.port
        self.domain = self._registrable_domain(host)

    @staticmethod
    def _is_non_public_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        return any((ip.is_private, ip.is_loopback, ip.is_link_local, ip.is_multicast, ip.is_reserved, ip.is_unspecified))

    @staticmethod
    def _registrable_domain(host: str) -> str:
        labels = host.split(".")
        if len(labels) <= 2:
            return host
        if len(labels) >= 3 and labels[-2:] in (["co", "uk"], ["com", "au"], ["co", "in"], ["com", "br"]):
            return ".".join(labels[-3:])
        return ".".join(labels[-2:])

    def parse_domain(self) -> str:
        """Return the best-effort registrable domain without network I/O."""
        return self.domain

    def is_https(self) -> bool:
        """Return whether the submitted URL uses HTTPS."""
        return urlparse(self.normalized_url).scheme.lower() == "https"

    def lexical_flags(self, known_domains: set[str] | None = None) -> list[str]:
        """Return explainable URL/domain signals; no external calls are made."""
        flags: list[str] = []
        if self.is_ip_address:
            flags.append("URL uses an IP address instead of a registered domain")
        if not self.is_https():
            flags.append("URL is not using HTTPS")
        if "xn--" in self.host:
            flags.append("Punycode/IDN hostname detected")
        if len(self.host) > 45:
            flags.append("Unusually long hostname")
        if self.host.count(".") >= 3:
            flags.append("Deeply nested subdomain structure")

        hits = sorted(self.SUSPICIOUS_TOKENS.intersection(set(re.split(r"[^a-z0-9]+", self.host))))
        if len(hits) >= 2:
            flags.append(f"Multiple sensitive hostname keywords: {', '.join(hits)}")

        if known_domains:
            target = self.domain
            for legit in known_domains:
                candidate = legit.lower().strip()
                if target == candidate:
                    continue
                if Levenshtein.distance(target, candidate) <= 2:
                    flags.append(f"Possible typosquatting of {legit}")
                    break
        return flags
