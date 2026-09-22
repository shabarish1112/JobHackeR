const THEME_KEY = "jobhacker-theme";
const themeToggle = document.getElementById("theme-toggle");
const themeMeta = document.getElementById("theme-color");
const app = document.getElementById("inspector");

function applyTheme(theme) {
  const light = theme === "light";
  document.documentElement.classList.toggle("light", light);
  if (themeMeta) themeMeta.setAttribute("content", light ? "#f6f7f5" : "#080909");
  if (themeToggle) {
    themeToggle.querySelector(".theme-icon").textContent = light ? "☾" : "☀";
    themeToggle.querySelector(".theme-label").textContent = light ? "DARK" : "LIGHT";
    themeToggle.setAttribute("aria-label", light ? "Switch to dark theme" : "Switch to light theme");
  }
  localStorage.setItem(THEME_KEY, theme);
}

const savedTheme = localStorage.getItem(THEME_KEY);
const systemLight = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches;
applyTheme(savedTheme || (systemLight ? "light" : "dark"));
themeToggle?.addEventListener("click", () => applyTheme(document.documentElement.classList.contains("light") ? "dark" : "light"));

function localApiFallback() {
  // Production and local launcher both use one origin. Keeping this helper
  // makes the frontend safe to open from a static file during development.
  if (window.location.protocol === "http:" || window.location.protocol === "https:") {
    return window.location.origin;
  }
  return "http://127.0.0.1:8000";
}
const API = (window.JOB_HACKER_API || localApiFallback()).replace(/\/$/, "");

const fileInput = document.getElementById("pdf-file");
const dropzone = document.getElementById("dropzone");
const fileName = document.getElementById("file-name");
let selectedFile = null;

const escapeHtml = (value = "") => String(value).replace(/[&<>"']/g, c => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
}[c]));

function setFile(file) {
  if (!file) return;
  if (file.type !== "application/pdf" && !file.name.toLowerCase().endsWith(".pdf")) {
    showError("Please choose a PDF offer letter.");
    return;
  }
  if (file.size > 12 * 1024 * 1024) {
    showError("That PDF is larger than 12 MB. Please choose a smaller file.");
    return;
  }
  selectedFile = file;
  fileName.textContent = `Selected: ${file.name} · ${(file.size / 1024 / 1024).toFixed(1)} MB`;
  dropzone.classList.add("selected");
  document.getElementById("text").value = "";
  document.getElementById("error").innerHTML = "";
}

fileInput?.addEventListener("change", e => setFile(e.target.files?.[0]));
dropzone?.addEventListener("keydown", e => {
  if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fileInput.click(); }
});
["dragenter", "dragover"].forEach(type => dropzone?.addEventListener(type, e => { e.preventDefault(); dropzone.classList.add("dragging"); }));
["dragleave", "drop"].forEach(type => dropzone?.addEventListener(type, e => { e.preventDefault(); dropzone.classList.remove("dragging"); }));
dropzone?.addEventListener("drop", e => setFile(e.dataTransfer?.files?.[0]));

document.getElementById("text")?.addEventListener("input", () => {
  if (document.getElementById("text").value.trim()) {
    selectedFile = null;
    fileInput.value = "";
    fileName.textContent = "";
    dropzone.classList.remove("selected");
  }
});

function showError(message) {
  document.getElementById("error").innerHTML = `<div class="error">${escapeHtml(message)}</div>`;
}

async function inspect() {
  const button = document.getElementById("inspect");
  const error = document.getElementById("error");
  const offerText = document.getElementById("text").value.trim();
  const companyUrl = document.getElementById("url").value.trim();
  const companyName = document.getElementById("company").value.trim();

  if (!selectedFile && !offerText && !companyUrl && !companyName) {
    showError("Upload the offer letter PDF or add the message/URL you want to inspect.");
    return;
  }

  button.disabled = true;
  button.innerHTML = "ANALYSING <span class=\"spinner\"></span>";
  error.innerHTML = "";
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 30000);

  try {
    let res;
    if (selectedFile) {
      const form = new FormData();
      form.append("file", selectedFile);
      if (companyName) form.append("company_name", companyName);
      res = await fetch(`${API}/api/v1/inspect-pdf`, { method: "POST", body: form, signal: controller.signal });
    } else {
      res = await fetch(`${API}/api/v1/inspect`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        body: JSON.stringify({ offer_text: offerText || null, company_url: companyUrl || null, company_name: companyName || null }),
        signal: controller.signal
      });
    }
    const data = await res.json().catch(() => ({ detail: "The inspection service returned an invalid response." }));
    if (!res.ok) throw new Error(data.detail || "Inspection failed");
    renderResult(data);
    document.getElementById("result")?.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (e) {
    showError(e.name === "AbortError" ? "Analysis timed out. Check the API connection and try again." : (e.message || "Inspection failed."));
  } finally {
    clearTimeout(timeout);
    button.disabled = false;
    button.innerHTML = "ANALYSE OFFER <span>→</span>";
  }
}

document.getElementById("inspect")?.addEventListener("click", inspect);

document.getElementById("url")?.addEventListener("input", e => {
  const value = e.target.value.trim();
  if (value && selectedFile) {
    // Keep the uploaded PDF as the primary source; the URL is still visible as context.
  }
});

function statusClass(status) {
  const value = String(status || "").toLowerCase();
  if (["valid", "clean", "available", "observed", "candidate_matches"].includes(value)) return "positive";
  if (["failed", "malicious", "flagged"].includes(value)) return "negative";
  return "neutral";
}

function renderResult(d) {
  const level = String(d.risk_level || "unknown");
  const intelligence = d.intelligence || {};
  const doc = d.document;
  const evidence = d.evidence || [];
  const extracted = doc ? `
    <section class="result-card">
      <div class="result-heading"><div><span class="step-label">02</span><h2>What the PDF contains</h2></div><span class="quiet">EXTRACTED FACTS</span></div>
      <div class="fact-grid">
        <div><small>File</small><b>${escapeHtml(doc.filename || "Offer letter")}</b></div>
        <div><small>Pages</small><b>${escapeHtml(doc.pages ?? "—")}</b></div>
        <div><small>Email addresses</small><b>${escapeHtml(doc.emails?.length ?? 0)}</b></div>
        <div><small>URLs found</small><b>${escapeHtml(doc.urls?.length ?? 0)}</b></div>
        <div><small>Phone numbers</small><b>${escapeHtml(doc.phone_numbers?.length ?? 0)}</b></div>
        <div><small>Money mentions</small><b>${escapeHtml(doc.money_mentions?.length ?? 0)}</b></div>
      </div>
      <div class="extracted-list">
        ${renderExtracted("Company detected", doc.company_name)}
        ${renderExtracted("Emails", doc.emails?.join(", "))}
        ${renderExtracted("URLs", doc.urls?.join(" · "))}
        ${renderExtracted("Money", doc.money_mentions?.join(" · "))}
        ${renderExtracted("Dates", doc.dates?.join(" · "))}
      </div>
      ${doc.extraction_warnings?.length ? `<div class="warning">${doc.extraction_warnings.map(escapeHtml).join(" ")}</div>` : ""}
    </section>` : "";

  const redFlags = (d.red_flags || []).length
    ? d.red_flags.map(x => `<li>${escapeHtml(x)}</li>`).join("")
    : `<li class="good">No configured red-flag rule fired.</li>`;

  document.getElementById("result").innerHTML = `
    <div class="result-top">
      <div>
        <span class="eyebrow">ANALYSIS COMPLETE</span>
        <h2>Here is what the evidence says.</h2>
      </div>
      <div class="risk ${escapeHtml(level)}"><b>${escapeHtml(Number(d.threat_score).toFixed(0))}</b><span>/100 risk</span><strong>${escapeHtml(level.toUpperCase())}</strong></div>
    </div>

    <div class="result-grid">
      <section class="result-card findings">
        <div class="result-heading"><div><span class="step-label">03</span><h2>Fraud signals</h2></div><span class="quiet">RULE-BASED EVIDENCE</span></div>
        <ul>${redFlags}</ul>
        <div class="signal-count">${escapeHtml(d.score_signals?.length || 0)} signal(s) contributed to the risk score.</div>
      </section>
      <section class="result-card">
        <div class="result-heading"><div><span class="step-label">04</span><h2>Independent checks</h2></div><span class="quiet">PUBLIC INTELLIGENCE</span></div>
        <div class="fact-grid compact">
          <div><small>Domain age</small><b>${escapeHtml(intelligence.domain_age_days == null ? "Not returned" : `${intelligence.domain_age_days} days`)}</b></div>
          <div><small>Registrar</small><b>${escapeHtml(intelligence.registrar || "Not returned")}</b></div>
          <div><small>TLS</small><b class="${intelligence.ssl_valid === true ? "ok" : intelligence.ssl_valid === false ? "bad" : ""}">${intelligence.ssl_valid === true ? "Valid" : intelligence.ssl_valid === false ? "Failed" : "Not checked"}</b></div>
          <div><small>Reputation</small><b>${escapeHtml(intelligence.reputation_status || "Unknown")}</b></div>
        </div>
        <p class="microcopy">These checks can support or contradict details in the letter. A registered domain or valid TLS certificate is <b>not proof that the recruiter is genuine.</b></p>
      </section>
    </div>

    ${extracted}

    <section class="result-card evidence-card">
      <div class="result-heading"><div><span class="step-label">05</span><h2>Evidence trail</h2></div><span class="quiet">WHY EACH FINDING MATTERS</span></div>
      <div class="evidence-list">${evidence.length ? evidence.map(renderEvidence).join("") : `<p class="empty">No external evidence was requested. The result is based on the supplied text.</p>`}</div>
    </section>

    <section class="result-card next-card">
      <div class="result-heading"><div><span class="step-label">06</span><h2>What to do next</h2></div></div>
      <ul class="actions-list">${(d.actionable_recommendations || []).map(x => `<li>${escapeHtml(x)}</li>`).join("")}</ul>
      ${(d.reporting || []).map(r => `<div class="report"><b>${escapeHtml(r.primary)}</b><p>${escapeHtml(r.note)}</p>${r.helpline ? `<b>Helpline: ${escapeHtml(r.helpline)}</b>` : ""}${r.url ? `<a target="_blank" rel="noopener" href="${escapeHtml(r.url)}">Open reporting portal ↗</a>` : ""}</div>`).join("")}
    </section>
  `;
}

function renderExtracted(label, value) {
  if (!value) return "";
  return `<div class="extracted-row"><small>${escapeHtml(label)}</small><span>${escapeHtml(value)}</span></div>`;
}

function renderEvidence(item) {
  return `<article class="evidence-item"><div class="evidence-meta"><span class="evidence-status ${statusClass(item.status)}">${escapeHtml(item.status || "observed")}</span><span>${escapeHtml(item.category || "Evidence")}</span><span>Source: ${escapeHtml(item.source || "—")}</span></div><b>${escapeHtml(item.finding || "No finding returned.")}</b><p>${escapeHtml(item.why_it_matters || "")}</p></article>`;
}

if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => navigator.serviceWorker.register("./sw.js").catch(() => {}));
}
