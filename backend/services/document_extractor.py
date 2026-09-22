"""Secure extraction of useful evidence from recruitment PDFs."""

from __future__ import annotations

import io
import re
from dataclasses import asdict, dataclass
from typing import Any

from pypdf import PdfReader


MAX_PDF_BYTES = 12 * 1024 * 1024
MAX_PAGES = 40
MAX_TEXT_CHARS = 100_000

URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", re.I)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d[\d\s().-]{8,}\d)(?!\d)")
MONEY_RE = re.compile(r"(?:₹|INR|USD|\$|EUR|€|GBP|£)\s?[\d,]+(?:\.\d{1,2})?(?:\s?(?:per\s+month|per\s+annum|monthly|annual|year|month|LPA))?", re.I)
DATE_RE = re.compile(r"\b(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[/-]\d{1,2}[/-]\d{1,2}|(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{1,2},?\s+\d{4})\b", re.I)


@dataclass(frozen=True)
class ExtractedDocument:
    filename: str
    pages: int
    text_characters: int
    metadata: dict[str, str]
    urls: list[str]
    domains: list[str]
    emails: list[str]
    phone_numbers: list[str]
    money_mentions: list[str]
    dates: list[str]
    company_name: str | None
    page_text: list[dict[str, Any]]
    extraction_warnings: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class DocumentExtractionError(ValueError):
    """Raised when a PDF cannot be safely inspected."""


def _unique(values: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        cleaned = value.strip().rstrip(".,;:)")
        key = cleaned.lower()
        if cleaned and key not in seen:
            seen.add(key)
            result.append(cleaned)
    return result


def _company_from_text(text: str) -> str | None:
    patterns = [
        r"(?:employer|company|organization|organisation|employer name)\s*(?:name)?\s*[:\-]\s*([^\n]{2,100})",
        r"(?:offered by|offer from|on behalf of)\s+([A-Z][^\n,.]{1,90})",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.I)
        if match:
            value = re.sub(r"\s+", " ", match.group(1)).strip(" .,-")
            if 2 <= len(value) <= 100:
                return value
    return None


def extract_pdf(content: bytes, filename: str) -> ExtractedDocument:
    if not content:
        raise DocumentExtractionError("The uploaded PDF is empty.")
    if len(content) > MAX_PDF_BYTES:
        raise DocumentExtractionError("PDF is too large. Maximum supported size is 12 MB.")
    if not content.startswith(b"%PDF"):
        raise DocumentExtractionError("The uploaded file is not a valid PDF document.")

    try:
        reader = PdfReader(io.BytesIO(content), strict=False)
    except Exception as exc:  # pypdf exposes several parser exception types
        raise DocumentExtractionError(f"The PDF could not be parsed: {exc}") from exc

    if len(reader.pages) > MAX_PAGES:
        raise DocumentExtractionError(f"PDF has {len(reader.pages)} pages. Maximum supported is {MAX_PAGES} pages.")

    warnings: list[str] = []
    page_text: list[dict[str, Any]] = []
    all_text_parts: list[str] = []
    for index, page in enumerate(reader.pages, start=1):
        try:
            text = page.extract_text() or ""
        except Exception as exc:
            text = ""
            warnings.append(f"Page {index}: text extraction failed ({type(exc).__name__}).")
        text = text[:MAX_TEXT_CHARS]
        all_text_parts.append(text)
        page_text.append({"page": index, "characters": len(text), "text": text})

    text = "\n\n".join(all_text_parts)[:MAX_TEXT_CHARS]
    # Some PDFs use a private glyph instead of a line break when text is extracted.
    text = text.replace("■", "\n").replace("\u2028", "\n")
    if not text.strip():
        warnings.append("No selectable text was found. This may be a scanned/image-only PDF; OCR is required for full text extraction.")

    urls = _unique(URL_RE.findall(text))
    domains: list[str] = []
    for url in urls:
        match = re.match(r"https?://([^/:?#]+)", url, re.I)
        if match:
            domains.append(match.group(1).lower())

    raw_metadata = reader.metadata or {}
    metadata = {}
    for key, value in raw_metadata.items():
        if value is not None:
            metadata[str(key).lstrip("/")] = str(value)[:500]

    return ExtractedDocument(
        filename=filename,
        pages=len(reader.pages),
        text_characters=len(text),
        metadata=metadata,
        urls=urls,
        domains=_unique(domains),
        emails=_unique(EMAIL_RE.findall(text)),
        phone_numbers=_unique(PHONE_RE.findall(text)),
        money_mentions=_unique(MONEY_RE.findall(text)),
        dates=_unique(DATE_RE.findall(text)),
        company_name=_company_from_text(text),
        page_text=page_text,
        extraction_warnings=warnings,
    )
