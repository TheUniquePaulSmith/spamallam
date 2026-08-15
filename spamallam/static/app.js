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

/* ---- provider test ---- */
const testBtn = document.getElementById("test-btn");
if (testBtn) {
  testBtn.addEventListener("click", async () => {
    const out = document.getElementById("test-output");
    out.hidden = false;
    out.textContent = "Running test (connectivity check + sample e-mail analysis)…";
    testBtn.disabled = true;
    try {
      const result = await postJSON("/api/provider/test");
      out.textContent = JSON.stringify(result, null, 2);
    } catch (err) {
      out.textContent = "Test failed: " + (err.message || err);
    } finally {
      testBtn.disabled = false;
    }
  });
}
