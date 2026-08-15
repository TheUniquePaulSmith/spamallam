#!/bin/sh
# SpamAllam postfix entrypoint: render config from env, manage TLS certs,
# watch for cert rotation, run postfix in the foreground.
set -eu

TEMPLATES=/etc/postfix/templates
CERT_NAME="${TLS_CERT_NAME:-$MAIL_HOSTNAME}"
ACME_CERT_DIR="/certs/${CERT_NAME}"
SELF_SIGNED_DIR=/etc/postfix/tls-selfsigned

log() { echo "[entrypoint] $*"; }

# ---------------------------------------------------------------------------
# Derived variables
# ---------------------------------------------------------------------------
# mydomain = hostname minus its first label (mail.example.com -> example.com)
MAIL_DOMAIN="${MAIL_HOSTNAME#*.}"
# comma list -> space list for relay_domains
MAIL_DOMAINS_SPACED=$(echo "$MAIL_DOMAINS" | tr ',' ' ')

# ---------------------------------------------------------------------------
# Recipient validation modes: domain (default) | list | verify
# ---------------------------------------------------------------------------
RECIPIENT_VALIDATION_EXTRA=""
RELAY_RECIPIENT_MAPS_LINE=""
case "${RECIPIENT_VALIDATION:-domain}" in
  domain)
    ;;  # relay_domains + reject_unauth_destination is the whole policy
  list)
    if [ -z "${RELAY_RECIPIENTS:-}" ]; then
      log "FATAL: RECIPIENT_VALIDATION=list but RELAY_RECIPIENTS is empty"; exit 1
    fi
    : > /etc/postfix/relay_recipients
    for addr in $(echo "$RELAY_RECIPIENTS" | tr ',' ' '); do
      echo "$addr OK" >> /etc/postfix/relay_recipients
    done
    postmap /etc/postfix/relay_recipients
    RELAY_RECIPIENT_MAPS_LINE="relay_recipient_maps = hash:/etc/postfix/relay_recipients"
    ;;
  verify)
    RECIPIENT_VALIDATION_EXTRA=",
    reject_unverified_recipient"
    ;;
  *)
    log "FATAL: unknown RECIPIENT_VALIDATION '${RECIPIENT_VALIDATION}'"; exit 1
    ;;
esac

# ---------------------------------------------------------------------------
# TLS certificates: prefer acme-issued certs from the shared volume; fall back
# to a locally generated self-signed pair so the gateway always starts.
# ---------------------------------------------------------------------------
pick_certs() {
  if [ -s "${ACME_CERT_DIR}/fullchain.pem" ] && [ -s "${ACME_CERT_DIR}/key.pem" ]; then
    TLS_CERT_FILE="${ACME_CERT_DIR}/fullchain.pem"
    TLS_KEY_FILE="${ACME_CERT_DIR}/key.pem"
  else
    if [ ! -s "${SELF_SIGNED_DIR}/fullchain.pem" ]; then
      log "no acme certificate at ${ACME_CERT_DIR}; generating self-signed fallback"
      mkdir -p "$SELF_SIGNED_DIR"
      openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -subj "/CN=${MAIL_HOSTNAME}" \
        -keyout "${SELF_SIGNED_DIR}/key.pem" \
        -out "${SELF_SIGNED_DIR}/fullchain.pem" >/dev/null 2>&1
      chmod 600 "${SELF_SIGNED_DIR}/key.pem"
    fi
    TLS_CERT_FILE="${SELF_SIGNED_DIR}/fullchain.pem"
    TLS_KEY_FILE="${SELF_SIGNED_DIR}/key.pem"
  fi
  log "using TLS cert: ${TLS_CERT_FILE}"
}
pick_certs

# ---------------------------------------------------------------------------
# Optional STARTTLS-enforced listener on :2587
# ---------------------------------------------------------------------------
if [ "${ENABLE_STARTTLS_PORT:-true}" = "true" ]; then
  STARTTLS_LISTENER='# ---- Inbound STARTTLS-enforced :2587 ---------------------------------------
2587      inet  n       -       n       -       -       smtpd
    -o syslog_name=postfix/starttls
    -o smtpd_tls_security_level=encrypt
    -o content_filter=spamallam:[spamallam]:10026'
else
  STARTTLS_LISTENER='# STARTTLS listener disabled (ENABLE_STARTTLS_PORT != true)'
fi

# ---------------------------------------------------------------------------
# Render config (envsubst with an explicit allowlist so postfix $vars survive)
# ---------------------------------------------------------------------------
export MAIL_HOSTNAME MAIL_DOMAIN MAIL_DOMAINS_SPACED MAILSERVER_HOST \
       MAILSERVER_PORT DOCKER_SUBNET MESSAGE_SIZE_LIMIT JUNK_COMMAND_LIMIT \
       SMTPD_CLIENT_CONNECTION_COUNT_LIMIT SMTPD_CLIENT_CONNECTION_RATE_LIMIT \
       POSTSCREEN_DNSBL_SITES POSTSCREEN_DNSBL_THRESHOLD \
       TLS_CERT_FILE TLS_KEY_FILE \
       RECIPIENT_VALIDATION_EXTRA RELAY_RECIPIENT_MAPS_LINE STARTTLS_LISTENER

MAIN_VARS='${MAIL_HOSTNAME} ${MAIL_DOMAIN} ${MAIL_DOMAINS_SPACED} ${MAILSERVER_HOST} ${MAILSERVER_PORT} ${DOCKER_SUBNET} ${MESSAGE_SIZE_LIMIT} ${JUNK_COMMAND_LIMIT} ${SMTPD_CLIENT_CONNECTION_COUNT_LIMIT} ${SMTPD_CLIENT_CONNECTION_RATE_LIMIT} ${POSTSCREEN_DNSBL_SITES} ${POSTSCREEN_DNSBL_THRESHOLD} ${TLS_CERT_FILE} ${TLS_KEY_FILE} ${RECIPIENT_VALIDATION_EXTRA} ${RELAY_RECIPIENT_MAPS_LINE}'
MASTER_VARS='${STARTTLS_LISTENER}'

envsubst "$MAIN_VARS"   < "$TEMPLATES/main.cf.tmpl"   > /etc/postfix/main.cf
envsubst "$MASTER_VARS" < "$TEMPLATES/master.cf.tmpl" > /etc/postfix/master.cf

# spool dir ownership can drift on a fresh named volume
/usr/sbin/postfix set-permissions >/dev/null 2>&1 || true
postfix check || { log "postfix check failed"; exit 1; }

# ---------------------------------------------------------------------------
# Cert-rotation watcher: acme container rotates files in the shared volume;
# we re-render (paths may flip from self-signed to acme) and reload postfix.
# ---------------------------------------------------------------------------
cert_stamp() {
  cat "${ACME_CERT_DIR}/fullchain.pem" 2>/dev/null | sha256sum | cut -d' ' -f1
}
(
  last=$(cert_stamp)
  while sleep 60; do
    cur=$(cert_stamp)
    if [ "$cur" != "$last" ]; then
      last="$cur"
      log "certificate change detected; re-rendering and reloading postfix"
      pick_certs
      export TLS_CERT_FILE TLS_KEY_FILE
      envsubst "$MAIN_VARS" < "$TEMPLATES/main.cf.tmpl" > /etc/postfix/main.cf
      postfix reload || true
    fi
  done
) &

log "starting postfix (hostname=${MAIL_HOSTNAME}, relay_domains=${MAIL_DOMAINS_SPACED}, relayhost=[${MAILSERVER_HOST}]:${MAILSERVER_PORT})"
exec /usr/sbin/postfix start-fg
