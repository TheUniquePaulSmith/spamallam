# Quarantine

Every message SpamAllam **drops** (silent discard: AI verdict
`MALICIOUS`/`PHISHING` at or above the drop threshold, or an rspamd `reject`) is
also copied to a quarantine so a human can recover a false positive.

## What is stored, and where

- `/data/quarantine/<YYYY-MM-DD>/<trace-id>.enc` — the raw message
  (anti-spoof headers already removed, SpamAllam's own `X-SpamAllam-*` headers
  **not** yet added), encrypted with **AES-256-GCM** via `SECRETS_KEY` (the same
  `SecretsBox` used for API keys). The `/data` volume and its backups never hold
  quarantined mail in the clear.
- `/data/quarantine/<YYYY-MM-DD>/<trace-id>.json` — plaintext metadata only
  (envelope from/to, subject, verdict, drop reason, size, status). No body.

Day-partitioned like the trace log, so retention pruning is a directory walk.

## Retention

`quarantine.retention_days` (Quarantine page → *Quarantine settings*, admin
only; default **90**) is independent of `logging.retention_days`. Once a day is
older than the window the whole directory — metadata and ciphertext — is deleted
by the daily retention loop. Set `quarantine.enabled` off to stop quarantining
new drops (the existing attachment-stripped log copy under `/data/logs/raw/` is
unaffected).

## Actions

| Action | Effect |
| --- | --- |
| **Preview** | Renders the message HTML inside a `sandbox`ed, same-origin iframe with a `default-src 'none'` CSP. An allowlist sanitizer drops `<script>`/`<style>`/handlers and rewrites every remote `<img>`/resource reference, so previewing cannot run script or load a tracking pixel. `cid:` parts are not loaded; inline `data:` images are kept. |
| **Release** | Prepends `X-SpamAllam-Released: by <user>; …` and re-injects to postfix `:10025` — the post-filter port, so there is **no** re-analysis and no rspamd milter. Delivered to the original envelope recipients. Optionally adds the sender's domain to `overrides.whitelist_domains` so future mail isn't re-dropped. The entry becomes a `released` tombstone and its ciphertext is deleted. |
| **Permanently delete** | Same tombstone treatment (`deleted`), ciphertext removed immediately. |

Every action is written to the admin audit log.

## Who sees what — per-user address ownership

- **Admins** see and act on every quarantined message.
- **Non-admin users** are assigned one or more owned e-mail addresses by an
  admin — on the invite form, or later on the Users page. A non-admin sees only
  quarantined mail whose envelope recipient normalizes to one of their
  addresses, and can release/delete only those. Matching is case-insensitive and
  plus-addressing–aware (`paul+news@example.com` matches an owner of
  `paul@example.com`).
- A non-admin's admin-UI surface is limited to **Quarantine**, their own
  **per-recipient Context**, and **their own passkeys**. Everything else is
  admin-only.
