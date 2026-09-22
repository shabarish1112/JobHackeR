"""Explainable threat scoring engine with deterministic, testable rules."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .text_heuristics import TextSignals


class IntelligenceLike(Protocol):
    domain_age_days: int | None
    ssl_valid: bool | None
    ssl_error: str | None
    reputation_status: str


@dataclass(frozen=True)
class ScoreSignal:
    name: str
    points: float
    severity: str
    evidence: str


@dataclass(frozen=True)
class ScoreResult:
    score: float
    risk_level: str
    signals: list[ScoreSignal]


class ThreatScorer:
    """Aggregate independent evidence without network I/O or UI concerns."""

    def score(
        self,
        *,
        domain_flags: list[str],
        text_signals: TextSignals,
        intelligence: IntelligenceLike,
    ) -> ScoreResult:
        signals: list[ScoreSignal] = []

        def add(name: str, points: float, severity: str, evidence: str) -> None:
            signals.append(ScoreSignal(name, points, severity, evidence))

        for flag in domain_flags:
            points = 12.0 if "typosquatting" in flag.lower() else 7.0
            add("Domain signal", points, "high" if points >= 12 else "medium", flag)

        for item in text_signals.urgency:
            add("Urgency language", 6.0, "medium", item)
        if text_signals.free_email_addresses:
            add("Free email", 12.0, "medium", ", ".join(text_signals.free_email_addresses))
        for item in text_signals.financial_traps:
            add("Payment request", 24.0, "high", item)
        for item in text_signals.credential_requests:
            add("Sensitive information request", 20.0, "high", item)
        for item in text_signals.suspicious_channels:
            add("Unusual contact channel", 8.0, "medium", item)
        for item in text_signals.impersonation_language:
            add("Impersonation language", 5.0, "medium", item)

        if text_signals.financial_traps and text_signals.credential_requests:
            add(
                "Combined payment + credential request",
                20.0,
                "critical",
                "The content requests money and sensitive credentials in the same interaction.",
            )

        if intelligence.domain_age_days is not None and intelligence.domain_age_days < 180:
            add("Young domain", 16.0, "high", f"{intelligence.domain_age_days} days old")
        if intelligence.ssl_valid is False:
            add("TLS certificate", 12.0, "high", intelligence.ssl_error or "Certificate validation failed")
        if intelligence.reputation_status == "malicious":
            add("Reputation intelligence", 35.0, "critical", "A configured reputation provider reported the host.")
        elif intelligence.reputation_status == "suspicious":
            add("Reputation intelligence", 20.0, "high", "A configured reputation provider returned a suspicious result.")

        score = round(min(100.0, sum(signal.points for signal in signals)), 2)
        level = "low" if score < 30 else "medium" if score < 70 else "high"
        return ScoreResult(score, level, signals)
