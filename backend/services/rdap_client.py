"""Public RDAP client for domain registration intelligence."""
from __future__ import annotations
from datetime import datetime, timezone
import httpx


class RDAPClient:
    async def lookup(self, domain: str) -> dict:
        async with httpx.AsyncClient(timeout=7.0, follow_redirects=True) as client:
            response = await client.get(f"https://rdap.org/domain/{domain}")
            response.raise_for_status()
            payload = response.json()
        created = self._event(payload, "registration")
        age_days = max(0, (datetime.now(timezone.utc) - created).days) if created else None
        registrar = None
        for entity in payload.get("entities", []):
            if "registrar" in entity.get("roles", []):
                registrar = self._entity_name(entity)
                break
        return {
            "domain": domain,
            "created_at": created.isoformat() if created else None,
            "domain_age_days": age_days,
            "registrar": registrar,
            "status": payload.get("status", []),
            "source": "RDAP (public registration data)",
        }

    @staticmethod
    def _event(payload: dict, action: str):
        for event in payload.get("events", []):
            if event.get("eventAction") == action and event.get("eventDate"):
                try:
                    return datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
                except ValueError:
                    return None
        return None

    @staticmethod
    def _entity_name(entity: dict) -> str | None:
        for item in entity.get("vcardArray", [None, []])[1]:
            if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                return str(item[3])
        return entity.get("handle")
