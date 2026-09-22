"""HTTP API routes. Business logic is delegated to application services."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, File, HTTPException, Query, UploadFile, status

from .schemas import InspectionRequest, InspectionResponse
from ..core.domain_analyzer import DomainAnalysisError, DomainAnalyzer
from ..core.text_heuristics import TextHeuristicsAnalyzer
from ..core.threat_scorer import ThreatScorer
from ..services.document_extractor import DocumentExtractionError, extract_pdf
from ..services.intelligence_service import IntelligenceReport, IntelligenceService
from ..services.rdap_client import RDAPClient
from ..services.reputation_client import ReputationClient
from ..services.report_service import ReportService
from ..services.search_client import PublicSearchClient
from ..services.ssl_inspector import SSLInspector

router = APIRouter(prefix="/api/v1", tags=["inspection"])

_intelligence = IntelligenceService(RDAPClient(), SSLInspector(), ReputationClient())
_scorer = ThreatScorer()
_reporter = ReportService()
_search = PublicSearchClient()


def _evidence_trail(*, document: dict | None, company_url: str | None, intelligence: IntelligenceReport, discovered: list[dict], text_signals) -> list[dict]:
    evidence: list[dict] = []
    if document:
        evidence.append({
            "category": "Document",
            "status": "observed",
            "source": document.get("filename", "Uploaded PDF"),
            "finding": f"Extracted {document.get('pages', 0)} page(s), {document.get('text_characters', 0)} text characters, {len(document.get('emails', []))} email(s), {len(document.get('urls', []))} URL(s).",
            "why_it_matters": "These are facts found directly inside the uploaded offer letter; they are not independent proof of authenticity.",
        })
    if company_url:
        evidence.append({
            "category": "Domain registration",
            "status": "available" if intelligence.created_at or intelligence.domain_age_days is not None else "unavailable",
            "source": "RDAP",
            "finding": f"{intelligence.domain or 'Domain'} registered {intelligence.domain_age_days} days ago" if intelligence.domain_age_days is not None else "Registration age was not returned.",
            "why_it_matters": "Registration data can support the existence of a domain, but it does not establish that the recruiter or offer is genuine.",
        })
        evidence.append({
            "category": "TLS certificate",
            "status": "valid" if intelligence.ssl_valid is True else "failed" if intelligence.ssl_valid is False else "not_checked",
            "source": "TLS handshake",
            "finding": intelligence.ssl_issuer or intelligence.ssl_error or "Certificate status was not returned.",
            "why_it_matters": "A valid certificate protects the connection; it does not prove that the site belongs to the claimed employer.",
        })
        evidence.append({
            "category": "Reputation",
            "status": intelligence.reputation_status,
            "source": intelligence.reputation_provider or "Configured reputation provider",
            "finding": intelligence.reputation_detail or "No provider detail returned.",
            "why_it_matters": "Reputation results are an external signal. Unknown/unavailable is not evidence of safety.",
        })
    if discovered:
        candidate_domains = {str(item.get("domain", "")).lower() for item in discovered}
        observed_domain = intelligence.domain.lower() if intelligence.domain else ""
        matches = observed_domain and observed_domain in candidate_domains
        evidence.append({
            "category": "Company identity cross-check",
            "status": "candidate_matches" if matches else "candidates_found",
            "source": "Public search",
            "finding": (
                f"The inspected domain {observed_domain} appears among {len(discovered)} public-search candidate(s)."
                if matches else f"Found {len(discovered)} candidate domain(s) for the supplied company name."
            ),
            "why_it_matters": "Search candidates can help compare the letter's domain with public company presence; they are candidates, not proof of ownership.",
        })
    if text_signals.financial_traps:
        evidence.append({
            "category": "Fraud signal",
            "status": "flagged",
            "source": "Offer letter text",
            "finding": ", ".join(text_signals.financial_traps),
            "why_it_matters": "The document explicitly contains payment-related language that can indicate recruitment fraud.",
        })
    if text_signals.credential_requests:
        evidence.append({
            "category": "Fraud signal",
            "status": "flagged",
            "source": "Offer letter text",
            "finding": ", ".join(text_signals.credential_requests),
            "why_it_matters": "Requests for passwords, OTPs, PINs or banking/identity credentials are high-risk signals.",
        })
    return evidence



async def _run_inspection(*, offer_text: str | None, company_url: str | None, company_name: str | None, document: dict | None = None) -> InspectionResponse:
    if not any((offer_text, company_url, company_name)):
        raise HTTPException(status_code=400, detail="Provide offer text, a company URL, or document text.")

    text_signals = TextHeuristicsAnalyzer(offer_text or "").analyze()
    domain_flags: list[str] = []
    intelligence: IntelligenceReport | None = None
    discovered: list[dict] = []

    if company_url:
        try:
            analyzer = DomainAnalyzer(company_url)
            domain_flags = analyzer.lexical_flags()
            intelligence_task = _intelligence.inspect(analyzer.domain, analyzer.host)
            if company_name:
                intelligence, discovered = await asyncio.gather(
                    intelligence_task, _intelligence.discover_company(company_name)
                )
            else:
                intelligence = await intelligence_task
        except DomainAnalysisError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    elif company_name:
        discovered = await _intelligence.discover_company(company_name)
        first = next((item for item in discovered if item.get("domain") and "." in item["domain"]), None)
        if first:
            try:
                analyzer = DomainAnalyzer(first["url"])
                domain_flags = analyzer.lexical_flags()
                intelligence = await _intelligence.inspect(analyzer.domain, analyzer.host)
            except DomainAnalysisError:
                pass

    intelligence = intelligence or IntelligenceReport.empty()
    result = _scorer.score(domain_flags=domain_flags, text_signals=text_signals, intelligence=intelligence)
    flags = [signal.evidence for signal in result.signals]

    recommendations = [
        "Verify the employer using a contact method found independently on its official website.",
        "Never pay a recruitment, equipment, registration or refundable-deposit fee to secure a job.",
    ]
    if result.risk_level == "high":
        recommendations.insert(0, "Pause the interaction. Do not send money, OTPs, passwords, identity documents or banking credentials.")
    elif result.risk_level == "medium":
        recommendations.insert(0, "Treat the offer as unverified until the employer, recruiter identity and job posting are independently confirmed.")

    reports = _reporter.for_context(
        high_risk=result.risk_level == "high",
        has_payment_request=bool(text_signals.financial_traps),
    )
    evidence = _evidence_trail(document=document, company_url=company_url, intelligence=intelligence, discovered=discovered, text_signals=text_signals)

    return InspectionResponse(
        threat_score=result.score,
        risk_level=result.risk_level,
        red_flags=flags,
        actionable_recommendations=recommendations,
        score_signals=[signal.__dict__ for signal in result.signals],
        intelligence=intelligence.to_dict(),
        reporting=reports,
        company_search_results=discovered,
        document=document,
        evidence=evidence,
    )


@router.get("/company-search")
async def company_search(name: str = Query(min_length=2, max_length=200)) -> dict:
    """Return public-search candidates for a company name; candidates are not proof of ownership."""
    normalized = name.strip()
    if len(normalized) < 2:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Company name is too short.")
    return {"query": normalized, "candidates": await _search.find_candidate_domains(normalized)}


@router.post("/inspect", response_model=InspectionResponse)
async def inspect(request: InspectionRequest) -> InspectionResponse:
    """Inspect supplied recruitment content and return explainable evidence."""
    return await _run_inspection(
        offer_text=request.offer_text or request.document_text,
        company_url=str(request.company_url) if request.company_url else None,
        company_name=request.company_name,
    )


@router.post("/inspect-pdf", response_model=InspectionResponse)
async def inspect_pdf(file: UploadFile = File(...), company_name: str | None = Query(default=None, max_length=200)) -> InspectionResponse:
    """Extract a recruitment PDF and inspect its content plus any discovered web evidence."""
    filename = file.filename or "offer-letter.pdf"
    if not filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF offer letters are supported.")
    content = await file.read()
    try:
        document = extract_pdf(content, filename)
    except DocumentExtractionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Prefer a URL embedded in the document, otherwise use the optional company name.
    company_url = document.urls[0] if document.urls else None
    selected_company = company_name.strip() if company_name and company_name.strip() else document.company_name
    return await _run_inspection(
        offer_text="\n\n".join(item["text"] for item in document.page_text),
        company_url=company_url,
        company_name=selected_company,
        document=document.to_dict(),
    )
