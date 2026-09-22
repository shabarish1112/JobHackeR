from types import SimpleNamespace

from fastapi.testclient import TestClient

from backend.api import routes
from backend.main import app
from backend.services.intelligence_service import IntelligenceReport


client = TestClient(app)


def test_health_has_security_headers():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"


def test_inspect_rejects_empty_payload():
    response = client.post("/api/v1/inspect", json={})
    assert response.status_code == 400
    assert "Provide offer text" in response.json()["detail"]


def test_inspect_returns_explainable_text_result(monkeypatch):
    monkeypatch.setattr(
        routes._intelligence,
        "inspect",
        lambda domain, host: _async_result(
            IntelligenceReport(
                domain=domain,
                domain_age_days=500,
                created_at=None,
                registrar="Example Registrar",
                ssl_valid=True,
                ssl_issuer="Example CA",
                ssl_expires_at=None,
                ssl_error=None,
                reputation_status="clean",
                reputation_provider="Test Provider",
                reputation_detail="No match",
                sources=["test"],
                lookup_errors=[],
            )
        ),
    )

    response = client.post(
        "/api/v1/inspect",
        json={"company_url": "https://example.com", "offer_text": "URGENT pay a refundable deposit"},
    )
    assert response.status_code == 200
    data = response.json()
    assert 0 <= data["threat_score"] <= 100
    assert data["risk_level"] in {"low", "medium", "high"}
    assert data["red_flags"]
    assert data["score_signals"]
    assert data["intelligence"]["registrar"] == "Example Registrar"
    assert data["reporting"]


def test_inspect_rejects_private_target():
    response = client.post("/api/v1/inspect", json={"company_url": "https://127.0.0.1"})
    assert response.status_code == 400
    assert "Private" in response.json()["detail"]


def test_company_search_delegates_to_search_adapter(monkeypatch):
    async def fake_search(name):
        return [{"domain": "example.com", "url": "https://example.com", "source": "test"}]

    monkeypatch.setattr(routes._search, "find_candidate_domains", fake_search)
    response = client.get("/api/v1/company-search", params={"name": "Example"})
    assert response.status_code == 200
    assert response.json()["candidates"][0]["domain"] == "example.com"


def _async_result(value):
    async def inner():
        return value

    return inner()


def test_inspect_with_document_text_uses_document_content():
    response = client.post("/api/v1/inspect", json={"document_text": "Send your password immediately"})
    assert response.status_code == 200
    assert any("Sensitive information request" == signal["name"] for signal in response.json()["score_signals"])


def test_company_search_rejects_short_names():
    response = client.get("/api/v1/company-search", params={"name": "a"})
    assert response.status_code == 422


def test_inspect_pdf_extracts_and_scores_offer(monkeypatch):
    from io import BytesIO
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import A4

    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    pdf.drawString(50, 780, "Company: Acme Technologies")
    pdf.drawString(50, 760, "Email: hr@acme.example")
    pdf.drawString(50, 740, "Visit https://example.com/careers")
    pdf.drawString(50, 720, "Pay an application fee immediately and send your password")
    pdf.save()

    monkeypatch.setattr(
        routes._intelligence,
        "inspect",
        lambda domain, host: _async_result(IntelligenceReport.empty(domain))
    )

    response = client.post(
        "/api/v1/inspect-pdf",
        files={"file": ("offer.pdf", buffer.getvalue(), "application/pdf")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["document"]["pages"] == 1
    assert "hr@acme.example" in data["document"]["emails"]
    assert data["document"]["urls"]
    assert data["risk_level"] == "high"
    assert any(item["category"] == "Document" for item in data["evidence"])
    assert any(item["category"] == "Fraud signal" for item in data["evidence"])
