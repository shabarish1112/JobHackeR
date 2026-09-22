"""Lightweight public web-search adapter for company-name discovery.

This adapter is intentionally treated as discovery, not proof of ownership.
Search engines can change markup or rate-limit automated clients.
"""
from __future__ import annotations
from urllib.parse import quote, urlparse
import re
import httpx


class PublicSearchClient:
    async def find_candidate_domains(self, company_name: str, limit: int = 5) -> list[dict]:
        query = f"{company_name} official website careers"
        url = f"https://html.duckduckgo.com/html/?q={quote(query)}"
        try:
            async with httpx.AsyncClient(timeout=7.0, headers={"User-Agent": "Job-Hacker/2.0"}) as client:
                response = await client.get(url)
                response.raise_for_status()
            links = re.findall(r'(?:nuddg|uddg)=([^"&]+)', response.text)
            seen = set()
            results = []
            from urllib.parse import unquote
            for raw in links:
                target = unquote(raw)
                host = (urlparse(target).hostname or "").lower()
                if not host or host in seen or host.endswith("duckduckgo.com"):
                    continue
                seen.add(host)
                results.append({"url": target, "domain": host, "source": "DuckDuckGo public search result"})
                if len(results) >= limit:
                    break
            return results
        except Exception as exc:
            return [{"error": str(exc), "source": "DuckDuckGo public search result"}]
