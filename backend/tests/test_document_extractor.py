from io import BytesIO

from pypdf import PdfWriter

from backend.services.document_extractor import DocumentExtractionError, extract_pdf


def _pdf_with_text(text: str) -> bytes:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import A4
    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    pdf.drawString(50, 780, text)
    pdf.save()
    return buffer.getvalue()


def test_pdf_extractor_extracts_recruitment_facts():
    content = _pdf_with_text(
        "Offer Letter\nCompany: Acme Technologies\nEmail: hr@acme.example\n"
        "Visit https://acme.example/careers\nSalary INR 80,000 per month\n"
        "Pay an application fee immediately."
    )
    result = extract_pdf(content, "offer.pdf")
    assert result.pages == 1
    assert "hr@acme.example" in result.emails
    assert "https://acme.example/careers" in result.urls
    assert result.company_name == "Acme Technologies"
    assert result.money_mentions


def test_pdf_extractor_rejects_non_pdf():
    try:
        extract_pdf(b"not a pdf", "offer.pdf")
    except DocumentExtractionError as exc:
        assert "valid PDF" in str(exc)
    else:
        raise AssertionError("Expected invalid PDF to be rejected")
