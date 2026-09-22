import pytest
from backend.core.domain_analyzer import DomainAnalyzer
from backend.core.text_heuristics import TextHeuristicsAnalyzer
from backend.core.threat_scorer import ThreatScorer


def test_domain_flags():
    a = DomainAnalyzer("http://legitcorp.co")
    assert "URL is not using HTTPS" in a.lexical_flags()


def test_text_signals():
    s = TextHeuristicsAnalyzer("URGENT. Pay a refundable deposit and send OTP to recruiter@gmail.com").analyze()
    assert s.urgency
    assert s.financial_traps
    assert s.credential_requests
    assert s.free_email_addresses


def test_score_bounds():
    intelligence = type("I", (), {"domain_age_days": 10, "ssl_valid": False, "ssl_error": "bad", "reputation_status": "malicious"})()
    result = ThreatScorer().score(
        domain_flags=["Possible typosquatting of legitcorp.com"],
        text_signals=TextHeuristicsAnalyzer("urgent pay before sending password").analyze(),
        intelligence=intelligence,
    )
    assert 0 <= result.score <= 100
    assert result.risk_level == "high"
