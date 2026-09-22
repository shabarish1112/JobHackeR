from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INDEX = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
APP = (ROOT / "frontend" / "app.js").read_text(encoding="utf-8")
CSS = (ROOT / "frontend" / "styles.css").read_text(encoding="utf-8")


def test_competition_title_is_present():
    assert "Fake Offer Letter & Phishing Inspector" in INDEX


def test_accessible_form_labels_match_controls():
    assert 'label for="url"' in INDEX
    assert 'label for="company"' in INDEX
    assert 'label for="text"' in INDEX
    assert 'for="pdf-file"' in INDEX


def test_single_page_contract_has_no_secondary_navigation_routes():
    assert 'href="#/how-it-works"' not in INDEX
    assert 'href="#/mission"' not in INDEX
    assert 'Drop your offer letter PDF here' in INDEX


def test_accessibility_contract_has_skip_link_and_live_regions():
    assert 'class="skip-link"' in INDEX
    assert 'aria-live="polite"' in INDEX
    assert 'role="alert"' in INDEX


def test_mobile_api_fallback_and_request_timeout_exist():
    assert "localApiFallback" in APP
    assert "AbortController" in APP
    assert "30000" in APP
    assert "/api/v1/inspect-pdf" in APP


def test_reduced_motion_and_focus_styles_exist():
    assert "prefers-reduced-motion:reduce" in CSS
    assert "focus-visible" in CSS
