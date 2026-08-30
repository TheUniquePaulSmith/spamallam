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
# Route inbound-reply traffic out via the macvlan gateway (mailwan), not
# whatever network Docker happens to pick as the default route. Without this,
# replies to a connection that arrived on POSTFIX_MACVLAN_IP can leave via a
# different interface/gateway than they arrived on — the asymmetric routing
# that let an external sender's traffic appear to originate inside
# mynetworks in the first place (see docs/SECURITY.md). Requires NET_ADMIN.
# Interface name is looked up by IP rather than assumed (e.g. "eth1") since
# Docker's interface-to-network assignment order isn't something this stack
# controls.
# ---------------------------------------------------------------------------
MACVLAN_IFACE=$(ip -4 -o addr show | awk -v ip="$POSTFIX_MACVLAN_IP" '$4 ~ ("^" ip "/") {print $2; exit}')
if [ -z "$MACVLAN_IFACE" ]; then
  log "FATAL: no interface holds POSTFIX_MACVLAN_IP (${POSTFIX_MACVLAN_IP}); check the mailwan network"
  exit 1
fi
ip route replace default via "$MACVLAN_GATEWAY" dev "$MACVLAN_IFACE"
# Assert, don't assume: `set -eu` catches a command that fails, not one that
# succeeds with the wrong result. postfix now has two non-internal networks
# (mailwan + delivernet), so a default route on the wrong one is exactly the
# asymmetric-routing/open-relay condition this whole design exists to prevent.
ACTUAL_DEFAULT=$(ip -4 route show default | head -n 1)
case "$ACTUAL_DEFAULT" in
  *"via $MACVLAN_GATEWAY dev $MACVLAN_IFACE"*) ;;
  *)
    log "FATAL: default route is '${ACTUAL_DEFAULT}', expected via ${MACVLAN_GATEWAY} dev ${MACVLAN_IFACE}"
    exit 1
    ;;
esac
log "default route -> ${MACVLAN_GATEWAY} dev ${MACVLAN_IFACE}"

# The re-injection listener binds this address explicitly, and postfix master
# would fail with "bind: Cannot assign requested address" -- which `postfix
# check` does not catch -- if filternet were missing or renumbered.
if ! ip -4 -o addr show | awk -v ip="$FILTER_POSTFIX_IP" '$4 ~ ("^" ip "/") {found=1} END {exit !found}'; then
  log "FATAL: no interface holds FILTER_POSTFIX_IP (${FILTER_POSTFIX_IP}); check the filternet network"
  exit 1
fi

# ---------------------------------------------------------------------------
# Derived variables
# ---------------------------------------------------------------------------
# mydomain = hostname minus its first label (mail.example.com -> example.com)
MAIL_DOMAIN="${MAIL_HOSTNAME#*.}"
# comma list -> space list for relay_domains
MAIL_DOMAINS_SPACED=$(echo "$MAIL_DOMAINS" | tr ',' ' ')

# Trusted for re-injection: the spamallam container, and nothing else unless the
# operator deliberately widens it. NOT the delivery network -- see main.cf.tmpl.
POSTFIX_MYNETWORKS="${FILTER_SPAMALLAM_IP}/32"
if [ -n "${MYNETWORKS_EXTRA:-}" ]; then
  POSTFIX_MYNETWORKS="${POSTFIX_MYNETWORKS} ${MYNETWORKS_EXTRA}"
  log "WARNING: MYNETWORKS_EXTRA widens re-injection trust to: ${MYNETWORKS_EXTRA}"
fi
log "mynetworks -> 127.0.0.0/8 [::1]/128 ${POSTFIX_MYNETWORKS}"

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
  # Double-quoted on purpose: envsubst does not recurse into the values it
  # substitutes, so ${POSTFIX_MACVLAN_IP}/${FILTER_SPAMALLAM_IP} have to be
  # expanded by the shell here or they reach master.cf as literal text and
  # postfix refuses to start. Nothing else in this block contains a '$'.
  STARTTLS_LISTENER="# ---- Inbound STARTTLS-enforced :2587 ---------------------------------------
${POSTFIX_MACVLAN_IP}:2587      inet  n       -       n       -       -       smtpd
    -o syslog_name=postfix/starttls
    -o smtpd_tls_security_level=encrypt
    -o content_filter=spamallam:[${FILTER_SPAMALLAM_IP}]:10026"
else
  STARTTLS_LISTENER='# STARTTLS listener disabled (ENABLE_STARTTLS_PORT != true)'
fi

# ---------------------------------------------------------------------------
# Render config (envsubst with an explicit allowlist so postfix $vars survive)
# ---------------------------------------------------------------------------
# DOCKER_SUBNET is deliberately NOT exported here any more: the delivery network
# must not be substitutable into mynetworks. POSTFIX_MYNETWORKS replaces it.
export MAIL_HOSTNAME MAIL_DOMAIN MAIL_DOMAINS_SPACED MAILSERVER_HOST \
       MAILSERVER_PORT POSTFIX_MYNETWORKS MESSAGE_SIZE_LIMIT JUNK_COMMAND_LIMIT \
       SMTPD_CLIENT_CONNECTION_COUNT_LIMIT SMTPD_CLIENT_CONNECTION_RATE_LIMIT \
       POSTSCREEN_DNSBL_SITES POSTSCREEN_DNSBL_THRESHOLD \
       TLS_CERT_FILE TLS_KEY_FILE \
       POSTFIX_MACVLAN_IP FILTER_POSTFIX_IP FILTER_SPAMALLAM_IP \
       RECIPIENT_VALIDATION_EXTRA RELAY_RECIPIENT_MAPS_LINE STARTTLS_LISTENER

MAIN_VARS='${MAIL_HOSTNAME} ${MAIL_DOMAIN} ${MAIL_DOMAINS_SPACED} ${MAILSERVER_HOST} ${MAILSERVER_PORT} ${POSTFIX_MYNETWORKS} ${MESSAGE_SIZE_LIMIT} ${JUNK_COMMAND_LIMIT} ${SMTPD_CLIENT_CONNECTION_COUNT_LIMIT} ${SMTPD_CLIENT_CONNECTION_RATE_LIMIT} ${POSTSCREEN_DNSBL_SITES} ${POSTSCREEN_DNSBL_THRESHOLD} ${TLS_CERT_FILE} ${TLS_KEY_FILE} ${RECIPIENT_VALIDATION_EXTRA} ${RELAY_RECIPIENT_MAPS_LINE}'
MASTER_VARS='${STARTTLS_LISTENER} ${POSTFIX_MACVLAN_IP} ${FILTER_POSTFIX_IP} ${FILTER_SPAMALLAM_IP}'

envsubst "$MAIN_VARS"   < "$TEMPLATES/main.cf.tmpl"   > /etc/postfix/main.cf
envsubst "$MASTER_VARS" < "$TEMPLATES/master.cf.tmpl" > /etc/postfix/master.cf

# Edge header strip (see header_checks in main.cf.tmpl). Mirrors the trust-
# granting half of _STRIP_RE in spamallam/app/pipeline/headers.py.
cat > /etc/postfix/header_checks <<'EOF'
/^X-SpamAllam-Signature:/  IGNORE
EOF

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
