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

function showToast(message, type) {
  const container = document.getElementById("toast-container");
  if (!container) return;
  const el = document.createElement("div");
  el.className = "toast" + (type === "error" ? " error" : "");
  el.textContent = message;
  container.appendChild(el);
  requestAnimationFrame(() => el.classList.add("show"));
  const dismiss = () => { el.classList.remove("show"); setTimeout(() => el.remove(), 200); };
  const timer = setTimeout(dismiss, 4000);
  el.addEventListener("click", () => { clearTimeout(timer); dismiss(); });
}

function setButtonBusy(btn, busy, label) {
  if (!btn) return;
  if (busy) {
    if (btn.dataset.originalHtml === undefined) btn.dataset.originalHtml = btn.innerHTML;
    btn.disabled = true;
    btn.classList.add("busy");
    btn.innerHTML = `<span class="spinner" aria-hidden="true"></span>${escapeHtml(label || "Working…")}`;
  } else {
    btn.disabled = false;
    btn.classList.remove("busy");
    if (btn.dataset.originalHtml !== undefined) {
      btn.innerHTML = btn.dataset.originalHtml;
      delete btn.dataset.originalHtml;
    }
  }
}

/* ---- flash message from redirect (server-rendered form saves) ---- */
(function flashFromQuery() {
  const params = new URLSearchParams(location.search);
  const flash = params.get("flash");
  if (flash === "saved") showToast(params.get("msg") || "Saved.", "success");
  else if (flash === "error") showToast(params.get("msg") || "Something went wrong.", "error");
  if (flash !== null) {
    params.delete("flash"); params.delete("msg");
    const qs = params.toString();
    history.replaceState(null, "", location.pathname + (qs ? "?" + qs : "") + location.hash);
  }
})();

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
    setButtonBusy(addPasskeyBtn, true, "Adding…");
    try {
      const { options, sealed } = await postJSON("/api/passkey/options");
      const cred = await navigator.credentials.create(prepareCreationOptions(options));
      await postJSON("/api/passkey/verify", {
        sealed, label, credential: credentialToJSON(cred),
      });
      const params = new URLSearchParams(location.search);
      params.set("flash", "saved");
      params.set("msg", "Passkey added.");
      window.location.href = location.pathname + "?" + params.toString();
    } catch (err) {
      showError("passkey-error", err);
      setButtonBusy(addPasskeyBtn, false);
    }
  });
}

/* ---- provider: encrypted-secret fields (keep/clear/replace) ---- */
const SECRET_SENTINEL = "__SA_SECRET_UNCHANGED__";
function wireSecretField(inputId, changedId) {
  const input = document.getElementById(inputId);
  const changed = document.getElementById(changedId);
  if (!input || !changed) return;
  input.addEventListener("input", () => {
    changed.value = (input.value !== SECRET_SENTINEL) ? "1" : "0";
  });
}
wireSecretField("api-key-input", "api-key-changed");
wireSecretField("pfx-password-input", "pfx-password-changed");

/* ---- provider: PFX "remove certificate" checkbox disables the password field ---- */
const mtlsClearCheckbox = document.getElementById("mtls-clear");
const pfxPasswordInputEl = document.getElementById("pfx-password-input");
if (mtlsClearCheckbox && pfxPasswordInputEl) {
  const syncPfxPasswordDisabled = () => { pfxPasswordInputEl.disabled = mtlsClearCheckbox.checked; };
  mtlsClearCheckbox.addEventListener("change", syncPfxPasswordDisabled);
  syncPfxPasswordDisabled();
}

/* ---- provider: fetch available models ---- */
const fetchModelsBtn = document.getElementById("fetch-models-btn");
if (fetchModelsBtn) {
  fetchModelsBtn.addEventListener("click", async () => {
    const status = document.getElementById("fetch-models-status");
    const datalist = document.getElementById("model-list");
    const ptype = document.getElementById("ptype").value;
    const base_url = document.getElementById("base-url-input").value;
    const apiKeyRaw = document.getElementById("api-key-input").value;
    const api_key = apiKeyRaw === SECRET_SENTINEL ? "" : apiKeyRaw;
    status.textContent = "Fetching…";
    setButtonBusy(fetchModelsBtn, true, "Fetching…");
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
      showToast("Fetch failed: " + (err.message || err), "error");
    } finally {
      setButtonBusy(fetchModelsBtn, false);
    }
  });
}

/* ---- provider test: formatted rendering (+ raw JSON toggle) ---- */
function verdictBadgeClass(v) {
  if (v === "HAM") return "ok";
  if (v === "SPAM") return "warn";
  if (v === "PHISHING" || v === "MALICIOUS") return "error";
  return ""; // SKIPPED, ERROR, unknown — neutral, not alarming (full-pipeline-only states)
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
  } else if (kind === "rspamd") {
    const nsym = ev.symbols ? Object.keys(ev.symbols).length : 0;
    summary += ` — action: ${ev.action}, score: ${ev.score} (${nsym} symbol(s) — see the rspamd symbols table above)`;
  } else if (kind === "rspamd_error" || kind === "ai_error") {
    summary += `: ${ev.error || ""}`;
  } else if (kind === "ai_skipped") {
    summary += `: ${ev.reason || ""}`;
  } else if (kind === "whitelist" || kind === "blocklist") {
    summary += `: rule=${ev.rule || ""}`;
  } else if (kind === "headers_stripped") {
    summary += `: ${ev.count} header(s) removed (spoofed X-SpamAllam-*/X-Spam-* on inbound)`;
    body = `<pre class="log">${escapeHtml((ev.headers || []).join("\n"))}</pre>`;
  } else {
    body = `<pre class="log">${escapeHtml(JSON.stringify(ev, null, 2))}</pre>`;
  }
  return `<details class="card trace"><summary>${escapeHtml(summary)}</summary>${body}</details>`;
}

function renderSymbolsTable(symbols) {
  const rows = Object.entries(symbols || {})
    .map(([name, score]) => {
      const ref = (typeof RSPAMD_SYMBOLS !== "undefined" && RSPAMD_SYMBOLS[name]) || null;
      return { name, score: Number(score) || 0, group: ref ? ref.group : "", description: ref ? ref.description : "" };
    })
    .sort((a, b) => Math.abs(b.score) - Math.abs(a.score));
  const trs = rows.map((r) => `<tr>
      <td class="mono">${escapeHtml(r.name)}</td>
      <td>${r.group ? `<span class="badge">${escapeHtml(r.group)}</span>` : '<span class="muted">—</span>'}</td>
      <td class="${r.score > 0 ? "warn" : (r.score < 0 ? "ok" : "muted")}">${r.score.toFixed(2)}</td>
      <td>${r.description ? escapeHtml(r.description) : '<span class="muted">no reference available</span>'}</td>
    </tr>`).join("");
  return `<div class="card">
    <h3>rspamd symbols</h3>
    <p class="muted small">Sorted by impact (largest |score| first). Positive scores push toward spam/reject,
       negative scores push toward ham. Descriptions and modules come from rspamd's default configuration and
       may not reflect local score overrides in this deployment.</p>
    <table>
      <tr><th>Symbol</th><th>Module</th><th>Score</th><th>Meaning</th></tr>
      ${trs || '<tr><td colspan="4" class="muted">no symbols fired</td></tr>'}
    </table>
  </div>`;
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
    setButtonBusy(testBtn, true, "Running test…");
    try {
      const result = await postJSON("/api/provider/test");
      summary.innerHTML = renderProviderTest(result);
      out.textContent = JSON.stringify(result, null, 2);
    } catch (err) {
      summary.innerHTML = `<p class="error">Test failed: ${escapeHtml(err.message || String(err))}</p>`;
    } finally {
      setButtonBusy(testBtn, false);
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

/* ---- test message: formatted rendering (+ raw JSON toggle) ---- */
function actionBadgeClass(action) {
  if (action === "drop") return "error";
  if (action === "tempfail") return "warn";
  return "ok"; // deliver
}

function renderMessageTest(result) {
  const parts = [];
  const v = result.verdict || {};

  parts.push(`<div class="card">
    <p class="big"><span class="badge ${actionBadgeClass(result.action)}">${escapeHtml((result.action || "").toUpperCase())}</span></p>
    ${result.reason ? `<p><strong>Reason:</strong> ${escapeHtml(result.reason)}</p>` : ""}
  </div>`);

  parts.push(`<div class="card">
    <h3>AI analysis</h3>
    ${v.ai_verdict === "SKIPPED" ? `<p class="muted">AI analysis is disabled globally — enable it on the
        <a href="/settings/ai">AI settings</a> page to get a verdict here. rspamd scoring below still applies.</p>` : `
    <p><span class="badge ${verdictBadgeClass(v.ai_verdict)}">${escapeHtml(v.ai_verdict || "?")}</span>
       ${Math.round((v.ai_confidence || 0) * 100)}% confidence</p>
    ${v.ai_category ? `<p><strong>Category:</strong> ${escapeHtml(v.ai_category)}</p>` : ""}
    ${v.ai_reason ? `<p><strong>Reason:</strong> ${escapeHtml(v.ai_reason)}</p>` : ""}
    ${v.whitelisted ? `<p><strong>Whitelisted:</strong> ${escapeHtml(v.whitelisted)}</p>` : ""}
    ${v.model ? `<p><strong>Model:</strong> <span class="mono">${escapeHtml(v.model)}</span></p>` : ""}
    ${(v.labels && v.labels.length) ? `<p><strong>Classification:</strong> ${
      v.labels.map((l) => `<span class="badge">${escapeHtml(l)}</span>`).join(" ")
    }</p>` : ""}
    <p><strong>Tools used:</strong> ${
      (v.tools_used && v.tools_used.length)
        ? v.tools_used.map((t) => `<span class="badge">${escapeHtml(t)}</span>`).join(" ")
        : '<span class="muted">none</span>'
    }</p>`}
  </div>`);

  parts.push(`<div class="card">
    <h3>rspamd</h3>
    <p><strong>Action:</strong> ${escapeHtml(v.rspamd_action || "(none)")}
       &nbsp; <strong>Score:</strong> ${v.rspamd_score}</p>
    <p class="muted small">This deployment's thresholds (rspamd/local.d/actions.conf):
       greylist &ge; 4, add header (tag as spam) &ge; 6, reject &ge; 15.</p>
  </div>`);

  const rspamdEvent = (result.events || []).find((e) => e.kind === "rspamd");
  if (rspamdEvent && rspamdEvent.symbols) {
    parts.push(renderSymbolsTable(rspamdEvent.symbols));
  }

  const events = result.events || [];
  if (events.length) {
    parts.push("<h3>Full technical trace</h3>");
    events.forEach((ev, i) => parts.push(renderTestEvent(ev, i)));
  }

  return parts.join("\n");
}

const testMessageBtn = document.getElementById("test-message-btn");
if (testMessageBtn) {
  testMessageBtn.addEventListener("click", async () => {
    const form = document.getElementById("test-message-form");
    const wrap = document.getElementById("test-message-result");
    const summary = document.getElementById("test-message-summary");
    const out = document.getElementById("test-message-output");
    wrap.hidden = false;
    summary.innerHTML = '<p class="muted">Running message through the pipeline (overrides → AI → rspamd)…</p>';
    out.textContent = "";
    setButtonBusy(testMessageBtn, true, "Running…");
    try {
      const resp = await fetch("/api/test/message", { method: "POST", body: new FormData(form) });
      const result = await resp.json();
      if (!resp.ok) throw new Error(result.detail || `HTTP ${resp.status}`);
      summary.innerHTML = renderMessageTest(result);
      out.textContent = JSON.stringify(result, null, 2);
    } catch (err) {
      summary.innerHTML = `<p class="error">Test failed: ${escapeHtml(err.message || String(err))}</p>`;
    } finally {
      setButtonBusy(testMessageBtn, false);
    }
  });
}

const testMessageToggleRaw = document.getElementById("test-message-toggle-raw");
if (testMessageToggleRaw) {
  testMessageToggleRaw.addEventListener("click", () => {
    const out = document.getElementById("test-message-output");
    out.hidden = !out.hidden;
    testMessageToggleRaw.textContent = out.hidden ? "Show raw JSON" : "Hide raw JSON";
  });
}
