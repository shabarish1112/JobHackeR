"""Threat-context reporting guidance. This is guidance, not an emergency service."""

from __future__ import annotations


class ReportService:
    INDIA = {
        "country": "India",
        "primary": "National Cyber Crime Reporting Portal",
        "url": "https://cybercrime.gov.in/",
        "helpline": "1930",
        "note": "For financial cyber fraud in India, contact 1930 promptly and file/complete the complaint through the National Cyber Crime Reporting Portal.",
    }

    def for_context(self, high_risk: bool, has_payment_request: bool) -> list[dict]:
        items = [self.INDIA]
        if high_risk or has_payment_request:
            items.append({
                "country": "Global",
                "primary": "Contact your local cybercrime/law-enforcement authority",
                "url": None,
                "helpline": None,
                "note": "If you are outside India, use the cybercrime reporting service or law-enforcement channel for your country. Preserve the URL, emails, phone numbers, payment records and screenshots.",
            })
        return items
