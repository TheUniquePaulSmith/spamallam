#!/bin/sh
# SpamAllam rspamd entrypoint: render env-dependent config, then run rspamd.
set -eu

TEMPLATES=/etc/rspamd/templates

log() { echo "[rspamd-entrypoint] $*"; }

# ---------------------------------------------------------------------------
# Controller password (hashed, never stored in plaintext config)
# ---------------------------------------------------------------------------
PASSWORD_HASH=$(rspamadm pw -p "$RSPAMD_PASSWORD")
export PASSWORD_HASH
envsubst '${PASSWORD_HASH}' \
  < "$TEMPLATES/worker-controller.inc.tmpl" \
  > /etc/rspamd/local.d/worker-controller.inc

# ---------------------------------------------------------------------------
# Antivirus: ClamAV always; VirusTotal only when an API key is provided
# ---------------------------------------------------------------------------
if [ -n "${VT_API_KEY:-}" ]; then
  export VT_API_KEY
  envsubst '${VT_API_KEY}' \
    < "$TEMPLATES/antivirus-virustotal.conf.tmpl" > /tmp/vt.conf
  VT_BLOCK=$(cat /tmp/vt.conf); rm -f /tmp/vt.conf
else
  VT_BLOCK="# VirusTotal disabled (no VT_API_KEY provided)"
  log "VirusTotal rule disabled: VT_API_KEY not set"
fi
export VT_BLOCK
envsubst '${VT_BLOCK}' \
  < "$TEMPLATES/antivirus.conf.tmpl" \
  > /etc/rspamd/local.d/antivirus.conf

# ---------------------------------------------------------------------------
# spamallam plugin config (consumed by rspamd.local.lua)
# ---------------------------------------------------------------------------
cat > /etc/rspamd/spamallam.config.lua <<EOF
-- generated at container start; do not edit
return {
  hmac_key = "${HEADER_HMAC_KEY}",
  spam_weight = ${SPAMALLAM_SPAM_WEIGHT:-6.0},
  phish_weight = ${SPAMALLAM_PHISH_WEIGHT:-8.0},
  malicious_weight = ${SPAMALLAM_MALICIOUS_WEIGHT:-12.0},
  ham_weight = ${SPAMALLAM_HAM_WEIGHT:--3.0},
  -- reject signatures older than this many seconds (replay window)
  max_age = 3600,
}
EOF
chmod 640 /etc/rspamd/spamallam.config.lua

# rspamd runs as _rspamd (Ubuntu image) — make its dirs writable
RSPAMD_USER=$(getent passwd _rspamd >/dev/null 2>&1 && echo _rspamd || echo rspamd)
chown -R "$RSPAMD_USER":"$RSPAMD_USER" /var/lib/rspamd
chgrp "$RSPAMD_USER" /etc/rspamd/spamallam.config.lua

log "starting rspamd as $RSPAMD_USER"
exec rspamd -f -u "$RSPAMD_USER" -g "$RSPAMD_USER"
