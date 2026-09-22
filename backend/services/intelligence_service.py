"""Orchestrates external intelligence providers behind a small interface."""

from __future__ import annotations
from dataclasses import dataclass, asdict
from .rdap_client import RDAPClient
from .ssl_inspector import SSLInspector
from .reputation_client import ReputationClient
from .search_client import PublicSearchClient


@dataclass(frozen=True)
class IntelligenceReport:
    domain: str
    domain_age_days: int | None
    created_at: str | None
    registrar: str | None
    ssl_valid: bool | None
    ssl_issuer: str | None
    ssl_expires_at: str | None
    ssl_error: str | None
    reputation_status: str
    reputation_provider: str | None
    reputation_detail: str | None
    sources: list[str]
    lookup_errors: list[str]

    @classmethod
    def empty(cls, domain: str = "") -> "IntelligenceReport":
        """Create an explicit no-network intelligence result."""
        return cls(
            domain=domain, domain_age_days=None, created_at=None, registrar=None,
            ssl_valid=None, ssl_issuer=None, ssl_expires_at=None, ssl_error=None,
            reputation_status="unknown", reputation_provider=None, reputation_detail=None,
            sources=[], lookup_errors=[],
        )

    def to_dict(self) -> dict:
        return asdict(self)


class IntelligenceService:
    def __init__(self, rdap: RDAPClient, ssl: SSLInspector, reputation: ReputationClient, search: PublicSearchClient | None = None) -> None:
        self.rdap = rdap
        self.ssl = ssl
        self.reputation = reputation
        self.search = search or PublicSearchClient()

    async def inspect(self, domain: str, host: str) -> IntelligenceReport:
        import asyncio
        rdap_task = asyncio.create_task(self.rdap.lookup(domain))
        ssl_task = asyncio.create_task(self.ssl.inspect(host))
        rep_task = asyncio.create_task(self.reputation.lookup(domain))
        results = await asyncio.gather(rdap_task, ssl_task, rep_task, return_exceptions=True)

        rdap, tls, rep = results
        errors: list[str] = []
        if isinstance(rdap, Exception):
            errors.append(f"RDAP lookup: {rdap}")
            rdap = {}
        if isinstance(tls, Exception):
            errors.append(f"TLS lookup: {tls}")
            tls = {}
        if isinstance(rep, Exception):
            errors.append(f"Reputation lookup: {rep}")
            rep = {}

        sources = []
        for item in (rdap, tls, rep):
            if isinstance(item, dict) and item.get("source"):
                sources.append(item["source"])
            elif isinstance(item, dict) and item.get("provider"):
                sources.append(item["provider"])

        return IntelligenceReport(
            domain=domain,
            domain_age_days=rdap.get("domain_age_days"),
            created_at=rdap.get("created_at"),
            registrar=rdap.get("registrar"),
            ssl_valid=tls.get("valid"),
            ssl_issuer=tls.get("issuer"),
            ssl_expires_at=tls.get("expires_at"),
            ssl_error=tls.get("error"),
            reputation_status=rep.get("status", "unknown"),
            reputation_provider=rep.get("provider"),
            reputation_detail=rep.get("detail"),
            sources=sources,
            lookup_errors=errors,
        )


    async def discover_company(self, company_name: str) -> list[dict]:
        """Discover candidate domains from a public search engine.

        Returned domains are candidates only and must be independently verified.
        """
        return await self.search.find_candidate_domains(company_name)
