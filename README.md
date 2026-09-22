# JobHacker 2.2 — Fake Offer Letter & Phishing Inspector

JobHacker is a focused recruitment-fraud inspection tool. The product is intentionally a **single-page, simple interface**: a user can upload an offer-letter PDF or paste a recruiter message, then receive an explainable evidence report.

## What the current version does

- **PDF offer-letter upload** with drag-and-drop support, 12 MB limit and safe parsing.
- Extracts selectable PDF text plus useful recruitment facts: company name patterns, email addresses, URLs/domains, phone numbers, money mentions, dates, page count and PDF metadata.
- Detects common recruitment-fraud signals: urgency, payment/fee requests, credential requests, unusual contact channels, free-mail addresses and impersonation language.
- Automatically inspects the first URL found in an uploaded PDF when present.
- Cross-checks a supplied/detected company name against public-search candidates when available.
- Checks domain registration/RDAP, TLS certificate state and optional reputation intelligence.
- Shows an **evidence trail** separating facts found inside the document from independent web evidence.
- Provides practical next steps and India reporting guidance where applicable.
- Uses deterministic, explainable scoring rather than pretending that a model can prove legitimacy with certainty.
- Responsive on desktop and mobile, with light/dark theme support and a presentation-focused light theme.

## Important limitation

A PDF extraction result is only as complete as the PDF's accessible content. Text-based PDFs are fully inspected for the supported fields. If a PDF is scanned/image-only, the product warns that OCR is required rather than silently pretending it extracted text it could not read.

Likewise, a registered domain, valid TLS certificate, search result, or clean reputation result is **supporting evidence, not proof that the recruiter or offer is genuine**. A suspicious finding is evidence of risk, not a legal determination of fraud.

## Run locally

From the project root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r backend/requirements.txt
python start.py
```

Open:

```text
http://localhost:8000
```

The launcher serves the frontend on port `3000` and FastAPI on port `8000`.

### Phone on the same Wi-Fi

The launcher binds both services to `0.0.0.0`. It prints your LAN URL. For example:

```text
http://192.168.1.15:3000
```

Open that URL on a phone connected to the same Wi-Fi. If Windows Firewall blocks it, allow Python on the Private network.

## Optional reputation intelligence

RDAP and TLS inspection work without an API key when outbound internet access is available.

For Google Safe Browsing, configure:

```powershell
$env:GOOGLE_SAFE_BROWSING_KEY="your-key"
python start.py
```

If no key is configured, the UI reports the provider as unconfigured instead of inventing a result.

## API endpoints

### Text inspection

```text
POST /api/v1/inspect
```

Accepts JSON containing `offer_text`, `company_url` and/or `company_name`.

### PDF inspection

```text
POST /api/v1/inspect-pdf
```

Accepts multipart form data with a `file` field and an optional `company_name` query parameter.

The response includes:

- `threat_score`
- `risk_level`
- `red_flags`
- `score_signals`
- `intelligence`
- `document`
- `evidence`
- `actionable_recommendations`
- `reporting`

## Architecture

```text
frontend/
  index.html              Single-page inspection UI
  styles.css              Minimal responsive visual system
  app.js                  Upload, inspection and evidence rendering
  assets/

backend/
  api/
    routes.py             HTTP boundary and inspection orchestration
    schemas.py            Typed request/response contracts
  core/
    domain_analyzer.py    URL/domain safety and lexical analysis
    text_heuristics.py    Explainable recruitment-fraud signals
    threat_scorer.py      Deterministic risk scoring
  services/
    document_extractor.py Secure PDF extraction and entity discovery
    rdap_client.py        Domain registration intelligence
    ssl_inspector.py      Certificate/TLS inspection
    reputation_client.py  Optional reputation provider
    intelligence_service.py Parallel external intelligence orchestration
    report_service.py     Reporting guidance
    search_client.py      Public company/domain search
```

## Quality gate

The current suite contains **52 automated tests** and the latest local run reached **91.04% total backend coverage**.

```bash
pytest -q
pytest --cov=backend --cov-report=term-missing -q
```

GitHub Actions is configured under `.github/workflows/quality.yml` to run the tests and enforce the coverage floor.

## Security hardening

- Private, loopback, link-local, multicast and reserved IP targets are rejected before network inspection.
- URLs with embedded credentials and unsupported schemes are rejected.
- PDF uploads are limited to 12 MB and 40 pages.
- Non-PDF uploads are rejected before parsing.
- Request text has explicit size limits and typed validation.
- Browser security headers are added to API responses.
- CORS origins can be restricted with `JOBHACKER_CORS_ORIGINS`.

## Accessibility

- Explicit labels for every form control.
- Keyboard-accessible PDF dropzone.
- Skip link and live result/error regions.
- Visible keyboard focus states.
- Reduced-motion support.
- Responsive controls designed for touch screens.
