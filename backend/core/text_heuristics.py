"""Deterministic text signals for recruitment/phishing language."""

from __future__ import annotations
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class TextSignals:
    urgency: list[str]
    financial_traps: list[str]
    credential_requests: list[str]
    free_email_addresses: list[str]
    suspicious_channels: list[str]
    impersonation_language: list[str]


class TextHeuristicsAnalyzer:
    """Extract explainable, non-ML signals from offer-letter text."""

    PATTERNS = {
        "urgency": re.compile(r"\b(urgent|immediately|asap|act now|within \d+ hours?|last chance|today only)\b", re.I),
        "financial": re.compile(r"\b(application fee|processing fee|equipment fee|refundable deposit|security deposit|advance payment|pay before|registration fee|training fee|crypto(?:currency)? payment)\b", re.I),
        "credentials": re.compile(r"\b(password|otp|one[- ]time password|cvv|pin|netbanking|bank account|aadhaar|pan card|passport|login credentials)\b", re.I),
        "free_email": re.compile(r"\b[A-Z0-9._%+-]+@(gmail|yahoo|outlook|hotmail|protonmail|icloud)\.[A-Z]{2,}\b", re.I),
        "channels": re.compile(r"\b(telegram|whatsapp only|signal|personal whatsapp|dm me)\b", re.I),
        "impersonation": re.compile(r"\b(on behalf of|official recruiter|human resources department|hr department|talent acquisition)\b", re.I),
    }

    def __init__(self, text: str) -> None:
        if not isinstance(text, str):
            raise ValueError("Text must be a string.")
        self.text = text

    @staticmethod
    def _unique_matches(pattern: re.Pattern[str], text: str) -> list[str]:
        seen: list[str] = []
        for match in pattern.finditer(text):
            value = match.group(0).strip()
            if value.lower() not in {x.lower() for x in seen}:
                seen.append(value)
        return seen

    def analyze(self) -> TextSignals:
        return TextSignals(
            urgency=self._unique_matches(self.PATTERNS["urgency"], self.text),
            financial_traps=self._unique_matches(self.PATTERNS["financial"], self.text),
            credential_requests=self._unique_matches(self.PATTERNS["credentials"], self.text),
            free_email_addresses=self._unique_matches(self.PATTERNS["free_email"], self.text),
            suspicious_channels=self._unique_matches(self.PATTERNS["channels"], self.text),
            impersonation_language=self._unique_matches(self.PATTERNS["impersonation"], self.text),
        )

    def detect_urgency(self) -> list[str]:
        return self.analyze().urgency

    def detect_free_email(self) -> bool:
        return bool(self.analyze().free_email_addresses)

    def detect_financial_traps(self) -> list[str]:
        return self.analyze().financial_traps
