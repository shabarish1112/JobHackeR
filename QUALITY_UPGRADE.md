# JobHacker 2.0 — Quality Upgrade

## Product/UI

- Removed the multi-page/navigation experience and consolidated the product into one inspection workflow.
- Reduced decorative UI and moved attention to the PDF upload, paste box, analysis action and evidence report.
- Added a drag-and-drop PDF offer-letter workflow.
- Added mobile-friendly controls and preserved light/dark theme support.
- Results now distinguish extracted document facts, fraud signals and independent web evidence.

## PDF intelligence

Added `backend/services/document_extractor.py` using `pypdf` with:

- file-size and page-count limits;
- PDF signature validation;
- selectable-text extraction;
- page-level extraction details;
- PDF metadata;
- URLs/domains;
- email addresses;
- phone numbers;
- money/salary mentions;
- date mentions;
- simple company-name extraction;
- scanned/image-only warning.

The frontend calls `POST /api/v1/inspect-pdf` and automatically uses the first discovered URL for live domain inspection.

## Evidence model

The result includes an `evidence` trail that labels each finding by source and explains why it matters. It explicitly avoids treating domain registration, TLS, search results or reputation data as absolute proof of legitimacy.

## Scoring

The scoring engine was tightened for combinations of payment and sensitive-credential requests because the combination is materially more concerning than either signal alone.

## Tests

The project now has **52 passing tests** and the latest local coverage run reached **91.04% total backend coverage**.

Coverage command:

```bash
pytest --cov=backend --cov-report=term-missing -q
```

## 2.2 final product verification
- Single-origin application: frontend + API on one port (`8000`).
- 52 automated tests pass.
- Root `/` returns the JobHacker single-page UI.
- `/health` remains available for connectivity checks.
- API requests use the same origin by default, eliminating localhost/LAN API mismatch on phones.
- Light theme was redesigned for stronger contrast, hierarchy and presentation quality.
