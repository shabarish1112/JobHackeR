"""Optional reputation adapters.

The application remains useful without API keys. When configured, these adapters
add provider-backed reputation evidence rather than pretending static heuristics
are live intelligence.
"""

from __future__ import annotations
import os
import httpx


class ReputationClient:
    def __init__(self) -> None:
        self.google_key = os.getenv("GOOGLE_SAFE_BROWSING_KEY")

    async def lookup(self, domain: str) -> dict:
        if not self.google_key:
            return {
                "status": "not_configured",
                "provider": "Google Safe Browsing",
                "detail": "Set GOOGLE_SAFE_BROWSING_KEY to enable live Safe Browsing checks.",
            }

        url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.google_key}"
        body = {
            "client": {"clientId": "job-hacker", "clientVersion": "2.0.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": f"https://{domain}/"}],
            },
        }
        try:
            async with httpx.AsyncClient(timeout=7.0) as client:
                response = await client.post(url, json=body)
                response.raise_for_status()
                matches = response.json().get("matches", [])
            return {
                "status": "malicious" if matches else "clean",
                "provider": "Google Safe Browsing",
                "detail": f"{len(matches)} threat match(es) returned." if matches else "No threat match returned.",
                "matches": matches,
            }
        except Exception as exc:
            return {"status": "error", "provider": "Google Safe Browsing", "detail": str(exc)}
