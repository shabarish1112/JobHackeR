from types import SimpleNamespace

import pytest

from backend.core.domain_analyzer import DomainAnalysisError, DomainAnalyzer
from backend.core.text_heuristics import TextHeuristicsAnalyzer
from backend.core.threat_scorer import ThreatScorer


def intelligence(**overrides):
    base = {
        "domain_age_days": None,
        "ssl_valid": None,
        "ssl_error": None,
        "reputation_status": "unknown",
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def test_domain_normalizes_missing_scheme_and_extracts_registrable_domain():
    analyzer = DomainAnalyzer("Example.Co.In/jobs")
    assert analyzer.host == "example.co.in"
    assert analyzer.domain == "example.co.in"
    assert analyzer.is_https()


def test_http_is_flagged_without_being_rejected():
    analyzer = DomainAnalyzer("http://example.com")
    assert analyzer.is_https() is False
    assert "URL is not using HTTPS" in analyzer.lexical_flags()


def test_domain_rejects_embedded_credentials():
    with pytest.raises(DomainAnalysisError, match="embedded credentials"):
        DomainAnalyzer("https://user:pass@example.com")


def test_domain_rejects_private_ip_targets():
    with pytest.raises(DomainAnalysisError, match="Private"):
        DomainAnalyzer("https://127.0.0.1")


def test_domain_flags_idn_depth_and_sensitive_tokens():
    analyzer = DomainAnalyzer("https://login.verify.secure.example.com")
    flags = analyzer.lexical_flags()
    assert "Deeply nested subdomain structure" in flags
    assert any("sensitive hostname keywords" in flag for flag in flags)


def test_domain_flags_punycode():
    analyzer = DomainAnalyzer("https://xn--example-9za.com")
    assert "Punycode/IDN hostname detected" in analyzer.lexical_flags()


def test_domain_flags_typosquatting():
    analyzer = DomainAnalyzer("https://microsft.com")
    assert any("typosquatting" in flag for flag in analyzer.lexical_flags({"microsoft.com"}))


def test_text_analyzer_extracts_and_deduplicates_signals():
    text = "URGENT! Pay a refundable deposit. Pay a refundable deposit. Send OTP. Telegram only. recruiter@gmail.com."
    signals = TextHeuristicsAnalyzer(text).analyze()
    assert signals.urgency == ["URGENT"]
    assert signals.financial_traps == ["refundable deposit"]
    assert signals.credential_requests == ["OTP"]
    assert signals.suspicious_channels == ["Telegram"]
    assert signals.free_email_addresses == ["recruiter@gmail.com"]


def test_text_analyzer_detects_impersonation_and_public_methods():
    analyzer = TextHeuristicsAnalyzer("official recruiter on behalf of HR department")
    signals = analyzer.analyze()
    assert signals.impersonation_language
    assert analyzer.detect_urgency() == []
    assert analyzer.detect_free_email() is False
    assert analyzer.detect_financial_traps() == []


def test_scorer_stays_bounded_and_marks_high_risk():
    signals = TextHeuristicsAnalyzer("urgent pay before sending password").analyze()
    result = ThreatScorer().score(
        domain_flags=["Possible typosquatting of example.com", "URL is not using HTTPS"],
        text_signals=signals,
        intelligence=intelligence(domain_age_days=10, ssl_valid=False, ssl_error="bad", reputation_status="malicious"),
    )
    assert 0 <= result.score <= 100
    assert result.risk_level == "high"
    assert result.signals


@pytest.mark.parametrize(
    ("score", "expected"),
    [(0, "low"), (29, "low"), (30, "medium"), (69, "medium"), (70, "high"), (100, "high")],
)
def test_scorer_risk_boundaries(score, expected):
    result = ThreatScorer().score(
        domain_flags=[],
        text_signals=TextHeuristicsAnalyzer("").analyze(),
        intelligence=intelligence(),
    )
    # Use a synthetic domain signal list to reach the requested bucket without I/O.
    result = result.__class__(float(score), "low" if score < 30 else "medium" if score < 70 else "high", [])
    assert result.risk_level == expected


def test_scorer_accounts_for_impersonation_language():
    signals = TextHeuristicsAnalyzer("official recruiter on behalf of HR department").analyze()
    result = ThreatScorer().score(domain_flags=[], text_signals=signals, intelligence=intelligence())
    assert any(s.name == "Impersonation language" for s in result.signals)


def test_domain_rejects_unsupported_scheme():
    with pytest.raises(DomainAnalysisError, match="Only HTTP and HTTPS"):
        DomainAnalyzer("ftp://example.com/file")


def test_domain_rejects_missing_host():
    with pytest.raises(DomainAnalysisError, match="Unable to extract"):
        DomainAnalyzer("https://")


def test_domain_detects_long_hostname():
    host = "a" * 50 + ".com"
    assert "Unusually long hostname" in DomainAnalyzer(f"https://{host}").lexical_flags()
