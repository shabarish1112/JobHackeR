from datetime import datetime, timezone

from backend.services.rdap_client import RDAPClient
from backend.services.reputation_client import ReputationClient
from backend.services.report_service import ReportService
from backend.services.ssl_inspector import SSLInspector


def test_rdap_event_parser_handles_iso_dates():
    client = RDAPClient()
    payload = {"events": [{"eventAction": "registration", "eventDate": "2020-01-02T03:04:05Z"}]}
    result = client._event(payload, "registration")
    assert result == datetime(2020, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def test_rdap_event_parser_handles_invalid_dates():
    assert RDAPClient._event({"events": [{"eventAction": "registration", "eventDate": "bad"}]}, "registration") is None


def test_rdap_entity_name_prefers_vcard_full_name():
    entity = {"vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]], "handle": "R1"}
    assert RDAPClient._entity_name(entity) == "Example Registrar"


def test_report_service_always_includes_india_guidance():
    report = ReportService().for_context(high_risk=False, has_payment_request=False)
    assert report[0]["country"] == "India"
    assert report[0]["helpline"] == "1930"


def test_report_service_adds_global_guidance_for_high_risk():
    report = ReportService().for_context(high_risk=True, has_payment_request=False)
    assert len(report) == 2
    assert report[1]["country"] == "Global"


def test_reputation_client_without_key_is_explicitly_unconfigured(monkeypatch):
    monkeypatch.delenv("GOOGLE_SAFE_BROWSING_KEY", raising=False)
    client = ReputationClient()
    # The public API is async; this branch is deterministic and requires no network.
    import asyncio
    result = asyncio.run(client.lookup("example.com"))
    assert result["status"] == "not_configured"
    assert result["provider"] == "Google Safe Browsing"


def test_ssl_inspector_rejects_invalid_port():
    result = SSLInspector()._inspect_sync("example.com", 70000)
    assert result["valid"] is False
    assert "Invalid network port" in result["error"]

class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class FakeAsyncClient:
    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def get(self, url):
        return FakeResponse({
            "events": [{"eventAction": "registration", "eventDate": "2020-01-02T03:04:05Z"}],
            "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Test Registrar"]]]}],
            "status": ["active"],
        })

    async def post(self, url, json):
        return FakeResponse({"matches": [{"threatType": "SOCIAL_ENGINEERING"}]})


def test_rdap_lookup_builds_registration_report(monkeypatch):
    import backend.services.rdap_client as module
    monkeypatch.setattr(module.httpx, "AsyncClient", FakeAsyncClient)
    import asyncio
    result = asyncio.run(RDAPClient().lookup("example.com"))
    assert result["registrar"] == "Test Registrar"
    assert result["domain_age_days"] >= 0
    assert result["source"].startswith("RDAP")


def test_reputation_client_returns_malicious_when_provider_matches(monkeypatch):
    import backend.services.reputation_client as module
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_KEY", "test-key")
    monkeypatch.setattr(module.httpx, "AsyncClient", FakeAsyncClient)
    import asyncio
    result = asyncio.run(ReputationClient().lookup("example.com"))
    assert result["status"] == "malicious"
    assert result["matches"]


def test_ssl_inspector_blocks_private_resolution(monkeypatch):
    import backend.services.ssl_inspector as module
    monkeypatch.setattr(module.socket, "getaddrinfo", lambda *args, **kwargs: [(0, 0, 0, "", ("127.0.0.1", 443))])
    result = SSLInspector()._inspect_sync("internal.example", 443)
    assert result["valid"] is False
    assert "private or reserved" in result["error"]


def test_intelligence_service_combines_provider_results():
    import asyncio
    from backend.services.intelligence_service import IntelligenceService

    class Provider:
        async def lookup(self, domain):
            return {"domain_age_days": 12, "created_at": "2020-01-01T00:00:00+00:00", "registrar": "R", "source": "RDAP"}

    class TLS:
        async def inspect(self, host):
            return {"valid": True, "issuer": "CA", "expires_at": "2030-01-01T00:00:00+00:00", "source": "TLS"}

    class Rep:
        async def lookup(self, domain):
            return {"status": "clean", "provider": "Provider", "detail": "No match"}

    result = asyncio.run(IntelligenceService(Provider(), TLS(), Rep()).inspect("example.com", "example.com"))
    assert result.domain_age_days == 12
    assert result.ssl_valid is True
    assert result.reputation_status == "clean"
    assert result.sources == ["RDAP", "TLS", "Provider"]


def test_intelligence_service_converts_provider_errors_to_lookup_errors():
    import asyncio
    from backend.services.intelligence_service import IntelligenceService

    class Broken:
        async def lookup(self, domain):
            raise RuntimeError("provider unavailable")

    class TLS:
        async def inspect(self, host):
            return {"valid": True, "source": "TLS"}

    class Rep:
        async def lookup(self, domain):
            return {"status": "unknown"}

    result = asyncio.run(IntelligenceService(Broken(), TLS(), Rep()).inspect("example.com", "example.com"))
    assert result.domain_age_days is None
    assert any("provider unavailable" in error for error in result.lookup_errors)


def test_search_client_parses_public_result_links(monkeypatch):
    import backend.services.search_client as module
    import asyncio

    class SearchClient(FakeAsyncClient):
        async def get(self, url):
            return FakeResponse({"html": "unused"})

    class Response:
        text = '<a href="/l/?uddg=https%3A%2F%2Fexample.com%2Fcareers">x</a><a href="/l/?uddg=https%3A%2F%2Fexample.org">y</a>'
        def raise_for_status(self):
            return None

    class Client:
        def __init__(self, *args, **kwargs): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
        async def get(self, url): return Response()

    monkeypatch.setattr(module.httpx, "AsyncClient", Client)
    result = asyncio.run(module.PublicSearchClient().find_candidate_domains("Example"))
    assert [item["domain"] for item in result] == ["example.com", "example.org"]
