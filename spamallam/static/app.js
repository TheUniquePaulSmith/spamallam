/* Admin UI behaviors: passkey login/enrollment, add-passkey, provider test. */
"use strict";

async function postJSON(url, body) {
  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(data.detail || `HTTP ${resp.status}`);
  return data;
}

function showError(id, err) {
  const el = document.getElementById(id);
  if (el) { el.textContent = String(err.message || err); el.hidden = false; }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

/* ---- login ---- */
const loginBtn = document.getElementById("login-btn");
if (loginBtn) {
  loginBtn.addEventListener("click", async () => {
    try {
      const { options, sealed } = await postJSON("/api/auth/options");
      const cred = await navigator.credentials.get(prepareRequestOptions(options));
      const result = await postJSON("/api/auth/verify", {
        sealed, credential: credentialToJSON(cred),
      });
      window.location = result.redirect || "/";
    } catch (err) { showError("login-error", err); }
  });
}

/* ---- setup / enrollment ---- */
const setupForm = document.getElementById("setup-form");
if (setupForm) {
  setupForm.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const token = setupForm.dataset.token;
    const username = document.getElementById("setup-username").value.trim();
    const display = (document.getElementById("setup-display") || {}).value || "";
    const label = (document.getElementById("setup-label") || {}).value || "first passkey";
    try {
      const { options, sealed, username: resolved } =
        await postJSON("/api/setup/options", { token, username });
      const cred = await navigator.credentials.create(prepareCreationOptions(options));
      const result = await postJSON("/api/setup/verify", {
        token, username: resolved, display, label, sealed,
        credential: credentialToJSON(cred),
      });
      window.location = result.redirect || "/";
    } catch (err) { showError("setup-error", err); }
  });
}

/* ---- add passkey (users page) ---- */
const addPasskeyBtn = document.getElementById("add-passkey-btn");
if (addPasskeyBtn) {
  addPasskeyBtn.addEventListener("click", async () => {
    const label = (document.getElementById("passkey-label") || {}).value || "passkey";
    try {
      const { options, sealed } = await postJSON("/api/passkey/options");
      const cred = await navigator.credentials.create(prepareCreationOptions(options));
      await postJSON("/api/passkey/verify", {
        sealed, label, credential: credentialToJSON(cred),
      });
      window.location.reload();
    } catch (err) { showError("passkey-error", err); }
  });
}

/* ---- provider: fetch available models ---- */
const fetchModelsBtn = document.getElementById("fetch-models-btn");
if (fetchModelsBtn) {
  fetchModelsBtn.addEventListener("click", async () => {
    const status = document.getElementById("fetch-models-status");
    const datalist = document.getElementById("model-list");
    const ptype = document.getElementById("ptype").value;
    const base_url = document.getElementById("base-url-input").value;
    const api_key = document.getElementById("api-key-input").value;
    status.textContent = "Fetching…";
    fetchModelsBtn.disabled = true;
    try {
      const { models } = await postJSON("/api/provider/models", { ptype, base_url, api_key });
      datalist.innerHTML = "";
      for (const m of models) {
        const opt = document.createElement("option");
        opt.value = m;
        datalist.appendChild(opt);
      }
      status.textContent = models.length
        ? `${models.length} models found — pick from the Model field's suggestions`
        : "Provider returned no models";
    } catch (err) {
      status.textContent = "Fetch failed: " + (err.message || err);
    } finally {
      fetchModelsBtn.disabled = false;
    }
  });
}

/* ---- provider test: formatted rendering (+ raw JSON toggle) ---- */
function verdictBadgeClass(v) {
  if (v === "HAM") return "ok";
  if (v === "SPAM") return "warn";
  return "error"; // PHISHING, MALICIOUS
}

function renderTestEvent(ev, i) {
  const kind = ev.kind;
  let summary = `#${i} ${kind}`;
  let body = "";
  if (kind === "ai_request") {
    summary += ` — tools offered: ${(ev.tools || []).join(", ") || "(none)"}`;
    body = `<p><strong>System prompt</strong></p><pre class="log">${escapeHtml(ev.system || "")}</pre>` +
           `<p><strong>User message</strong></p><pre class="log">${escapeHtml(ev.user || "")}</pre>`;
  } else if (kind === "ai_response") {
    const calls = ev.tool_calls || [];
    summary += ` (iteration ${ev.iteration}) — ` +
      (calls.length ? `${calls.length} tool call(s): ${calls.map((c) => c.name).join(", ")}` : "final answer");
    if (ev.usage && ev.usage.total_tokens) summary += ` · ${ev.usage.total_tokens} tokens`;
    if (ev.text) body += `<p><strong>Response text</strong></p><pre class="log">${escapeHtml(ev.text)}</pre>`;
    if (calls.length) {
      body += `<p><strong>Tool calls requested</strong></p><pre class="log">${escapeHtml(JSON.stringify(calls, null, 2))}</pre>`;
    }
    if (ev.usage) body += `<p class="muted small">Usage: ${escapeHtml(JSON.stringify(ev.usage))}</p>`;
  } else if (kind === "tool_call") {
    summary += `: ${ev.tool}`;
    body = `<p><strong>Arguments</strong></p><pre class="log">${escapeHtml(JSON.stringify(ev.arguments, null, 2))}</pre>` +
           `<p><strong>Result</strong></p><pre class="log">${escapeHtml(JSON.stringify(ev.result, null, 2))}</pre>`;
  } else {
    body = `<pre class="log">${escapeHtml(JSON.stringify(ev, null, 2))}</pre>`;
  }
  return `<details class="card trace"><summary>${escapeHtml(summary)}</summary>${body}</details>`;
}

function renderProviderTest(result) {
  const parts = [];

  const ping = result.ping || {};
  parts.push('<div class="card">');
  parts.push(`<p><strong>Provider:</strong> <span class="mono">${escapeHtml(result.provider || "")}</span></p>`);
  if (ping.ok) {
    parts.push(`<p><strong>Connectivity:</strong> <span class="ok">OK</span>` +
      (ping.endpoint ? ` — <span class="mono small">${escapeHtml(ping.endpoint)}</span>` : "") + `</p>`);
    if (ping.models_visible && ping.models_visible.length) {
      parts.push(`<p><strong>Models visible:</strong> ` +
        ping.models_visible.map((m) => `<span class="badge">${escapeHtml(m)}</span>`).join(" ") + `</p>`);
    }
    if (typeof ping.configured_model_listed === "boolean") {
      parts.push(`<p><strong>Configured model listed:</strong> ` +
        (ping.configured_model_listed ? `<span class="ok">yes</span>` : `<span class="warn">no</span>`) + `</p>`);
    }
    if (ping.model) {
      parts.push(`<p><strong>Model confirmed by provider:</strong> <span class="mono">${escapeHtml(ping.model)}</span></p>`);
    }
  } else {
    parts.push(`<p><strong>Connectivity:</strong> <span class="error">FAILED</span></p>` +
      `<pre class="log">${escapeHtml(ping.error || "")}</pre>`);
  }
  parts.push("</div>");

  const analysis = result.analysis;
  if (analysis) {
    if (analysis.ok) {
      parts.push(`<div class="card">
        <p class="big"><span class="badge ${verdictBadgeClass(analysis.verdict)}">${escapeHtml(analysis.verdict)}</span>
           ${Math.round((analysis.confidence || 0) * 100)}% confidence</p>
        <p><strong>Category:</strong> ${escapeHtml(analysis.category || "(none)")}</p>
        <p><strong>Reason:</strong> ${escapeHtml(analysis.reason || "")}</p>
        <p><strong>Tools used:</strong> ${
          (analysis.tools_used && analysis.tools_used.length)
            ? analysis.tools_used.map((t) => `<span class="badge">${escapeHtml(t)}</span>`).join(" ")
            : '<span class="muted">none</span>'
        }</p>
      </div>`);
    } else {
      parts.push(`<div class="card"><p><strong>Analysis:</strong> <span class="error">FAILED</span></p>` +
        `<pre class="log">${escapeHtml(analysis.error || "")}</pre></div>`);
    }
    const events = analysis.events || [];
    if (events.length) {
      parts.push("<h3>Technical exchange</h3>");
      events.forEach((ev, i) => parts.push(renderTestEvent(ev, i)));
    }
  }
  return parts.join("\n");
}

const testBtn = document.getElementById("test-btn");
if (testBtn) {
  testBtn.addEventListener("click", async () => {
    const wrap = document.getElementById("test-result");
    const summary = document.getElementById("test-summary");
    const out = document.getElementById("test-output");
    wrap.hidden = false;
    summary.innerHTML = '<p class="muted">Running test (connectivity check + sample e-mail analysis)…</p>';
    out.textContent = "";
    testBtn.disabled = true;
    try {
      const result = await postJSON("/api/provider/test");
      summary.innerHTML = renderProviderTest(result);
      out.textContent = JSON.stringify(result, null, 2);
    } catch (err) {
      summary.innerHTML = `<p class="error">Test failed: ${escapeHtml(err.message || String(err))}</p>`;
    } finally {
      testBtn.disabled = false;
    }
  });
}

const testToggleRaw = document.getElementById("test-toggle-raw");
if (testToggleRaw) {
  testToggleRaw.addEventListener("click", () => {
    const out = document.getElementById("test-output");
    out.hidden = !out.hidden;
    testToggleRaw.textContent = out.hidden ? "Show raw JSON" : "Hide raw JSON";
  });
}

/* ---- test message (full pipeline: overrides -> AI -> rspamd) ---- */
const testMessageBtn = document.getElementById("test-message-btn");
if (testMessageBtn) {
  testMessageBtn.addEventListener("click", async () => {
    const form = document.getElementById("test-message-form");
    const out = document.getElementById("test-message-output");
    const summary = document.getElementById("test-message-summary");
    out.hidden = false;
    out.textContent = "Running message through the pipeline (AI + rspamd)…";
    summary.hidden = true;
    testMessageBtn.disabled = true;
    try {
      const resp = await fetch("/api/test/message", { method: "POST", body: new FormData(form) });
      const result = await resp.json();
      if (!resp.ok) throw new Error(result.detail || `HTTP ${resp.status}`);
      out.textContent = JSON.stringify(result, null, 2);
      const v = result.verdict || {};
      document.getElementById("tm-action").textContent = (result.action || "").toUpperCase();
      document.getElementById("tm-reason").textContent = result.reason || "(none)";
      document.getElementById("tm-ai-verdict").textContent =
        `${v.ai_verdict || "?"} (${Math.round((v.ai_confidence || 0) * 100)}% confidence) — ${v.ai_reason || ""}`;
      document.getElementById("tm-rspamd-action").textContent = v.rspamd_action || "";
      document.getElementById("tm-rspamd-score").textContent = v.rspamd_score;
      summary.hidden = false;
    } catch (err) {
      out.textContent = "Test failed: " + (err.message || err);
    } finally {
      testMessageBtn.disabled = false;
    }
  });
}
