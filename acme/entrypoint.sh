#!/bin/sh
# SpamAllam acme.sh container: issues/renews LetsEncrypt certs via DNS-01 and
# installs them into the shared /certs volume (this is the ONLY writer; postfix
# and spamallam mount /certs read-only and hot-reload when files change).
set -u

log() { echo "[acme] $*"; }

if [ -z "${ACME_DNS_PROVIDER:-}" ]; then
  log "ACME_DNS_PROVIDER not set — certificate issuance disabled."
  log "postfix/spamallam will use their self-signed fallbacks until configured."
  exec sleep infinity
fi

ACME="/usr/local/bin/acme.sh"
DOMAINS=$(echo "${ACME_DOMAINS}" | tr ',' ' ')

"$ACME" --set-default-ca --server "${ACME_SERVER:-letsencrypt}"
if [ -n "${ACME_EMAIL:-}" ]; then
  "$ACME" --register-account -m "$ACME_EMAIL" >/dev/null 2>&1 || true
fi

for domain in $DOMAINS; do
  [ -z "$domain" ] && continue
  outdir="/certs/${domain}"
  mkdir -p "$outdir"

  if ! "$ACME" --list | grep -q "^${domain}"; then
    log "issuing certificate for ${domain} via ${ACME_DNS_PROVIDER}"
    "$ACME" --issue --dns "$ACME_DNS_PROVIDER" -d "$domain" --keylength ec-256 \
      || { log "ERROR: issuance failed for ${domain} (check DNS provider credentials)"; continue; }
  fi

  # --install-cert records itself in acme.sh config, so renewals re-install
  # automatically; consumers watch the files, so no reload command is needed.
  "$ACME" --install-cert -d "$domain" --ecc \
    --key-file "${outdir}/key.pem" \
    --fullchain-file "${outdir}/fullchain.pem" \
    --reloadcmd "true" \
    || log "ERROR: install-cert failed for ${domain}"

  # readable by spamallam (uid 1000); postfix reads as root (CAP_DAC_OVERRIDE)
  chown 1000:1000 "${outdir}/key.pem" "${outdir}/fullchain.pem" 2>/dev/null || true
  chmod 600 "${outdir}/key.pem" 2>/dev/null || true
  chmod 644 "${outdir}/fullchain.pem" 2>/dev/null || true
done

log "startup issuance complete; entering renew daemon (crond)"
exec crond -n -s -m off
