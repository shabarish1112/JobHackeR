# JobHacker 2.2 — Final Single-Origin UI Refresh

## Product direction
The application is intentionally one page and one website. The user lands directly on the inspection workflow; there is no second frontend site and no separate frontend port.

## UX changes
- PDF upload is the primary action and the first thing users see.
- Text-message inspection remains available as a compact alternative.
- Company name and URL are tucked into an optional context disclosure instead of competing with the upload action.
- Removed the side privacy panel and unnecessary secondary page/navigation concepts.
- Added a compact four-step trust strip: Extract → Detect → Verify → Explain.
- Results remain on the same page and scroll into view after analysis.
- Light theme uses a clean warm-white surface system, restrained green accent, stronger borders and softer shadows for presentation clarity.
- Dark theme retains the high-contrast inspection-console aesthetic.
- Mobile controls use full-width touch targets and stacked content.

## Architecture
FastAPI serves `/`, `/index.html`, CSS, JavaScript, PWA assets and `/api/v1/*` from the same origin on port `8000`. `start.py` launches only Uvicorn.
