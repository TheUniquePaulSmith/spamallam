# SpamAllam security model

## Threat model

SpamAllam assumes the internet-facing SMTP listener is under constant attack
(scanners, spam cannons, exploit attempts against the MTA) and that any single
container may eventually be compromised. Goals, in order:

1. Never be an open relay or a backscatter source.
2. Keep the internal mail server unreachable except through the filtered path.
3. Keep verdict headers unforgeable by senders.
4. Keep secrets (API keys, mTLS material) off disk in plaintext and out of
   sibling containers.
5. Keep the AI from being weaponized (link activation, over-blocking).

## Inbound SMTP surface (postfix)

- Relay policy: `permit_mynetworks, reject_unauth_destination` with
  `mynetworks` = loopback + the stack's fixed docker subnet only. Mail is
  accepted solely *for* `MAIL_DOMAINS`.
- **Direct-LAN exposure, not port-publish NAT**: postfix is dual-homed onto a
  macvlan network (`mailwan`) and reached at its own `POSTFIX_MACVLAN_IP`,
  instead of via Docker's normal `ports:` publish path. This isn't cosmetic —
  some Docker hosts (Synology Container Manager included) rewrite an inbound
  connection's source IP to the docker bridge gateway address before the
  container ever sees it. That address falls *inside* `mynetworks`, which
  turns the first line of every restriction list above
  (`permit_mynetworks`) into an unconditional pass for any internet sender,
  i.e. an open relay that `reject_unauth_destination` never gets a chance to
  enforce. macvlan means postfix sees the real client IP on every connection,
  so `mynetworks` can only ever match genuinely internal traffic.
- **Default-route fixup**: replies to an inbound macvlan connection must leave
  via the macvlan gateway, or they're routed out the internal bridge instead —
  reintroducing the exact asymmetric-routing condition macvlan exists to
  avoid. Older Docker Engine/Compose builds have no declarative way to pin
  this (no `gw_priority` schema support, no `network connect --gw-priority`
  CLI), so `postfix/entrypoint.sh` sets the default route explicitly at
  startup via `ip route replace`, using a targeted `NET_ADMIN` grant — the one
  exception to "no network capabilities" below. It runs once, before postfix
  starts, is not used by postfix itself, and its only effect is that one
  route replacement.
- postscreen with weighted DNSBLs drops bots before a smtpd process is spent.
- `reject_unauth_pipelining`, FQDN + resolvable HELO required, strict RFC821
  envelopes, VRFY disabled, junk-command limit (default 50), per-client
  connection count/rate caps, message size cap.
- No SASL/submission anywhere: the :2587 listener enforces STARTTLS but is
  still receive-only. Outbound mail is not this system's job.
- Unknown recipients are rejected at SMTP time (`domain`/`list`/`verify`
  modes); DROP verdicts are silent discards; `notify_classes` is empty and
  bounce lifetime short — no backscatter.
- Container: unprivileged ports only, `cap_drop: ALL` plus only the setuid/file
  caps postfix's privilege-separated design needs and the one `NET_ADMIN`
  grant described above, `no-new-privileges`.

### DNSBL lookups can get blocked by a handful of big public resolvers

postscreen's weighted DNSBL checks (`POSTSCREEN_DNSBL_SITES`) query
`zen.spamhaus.org` from whatever resolver the postfix container ends up
with — normally Docker's embedded resolver, forwarding to whatever DNS the
docker host itself uses. Spamhaus specifically fingerprints and blocks free
DNSBL-zone queries from a short list of massive, anonymously-shared anycast
resolvers — Google `8.8.8.8`, Cloudflare `1.1.1.1`, Quad9, OpenDNS and
similar — because millions of unrelated users share the same querying IP,
making per-user abuse impossible to attribute. It does *not* generally
target ordinary ISP-provided resolvers, which are shared only among that
ISP's own customers. If your resolver is one of the blocked ones, Spamhaus
returns `127.255.255.254` ("query via public/open resolver") for every
lookup instead of a real answer, and postscreen scores that return code like
a genuine listing — rejecting legitimate senders. Observed in practice: a
Gmail MX hard-rejected with `550 5.7.1 ... blocked using zen.spamhaus.org`,
while a different Gmail IP passed minutes later because postscreen already
had a cached verdict for it and skipped a fresh lookup. This isn't a spam
signal; it's Spamhaus refusing free service to that resolver.

Quick check for whether your current resolver is affected — Spamhaus keeps a
standing positive-control test entry (`127.0.0.2` should always be listed):

```bash
dig +short 2.0.0.127.zen.spamhaus.org @<resolver-ip>
```

`127.0.0.2` back means that resolver is fine for this. `127.255.255.254`
means it's blocked (directly, or because it's silently forwarding to one of
the big public services above).

**Fix**: register for Spamhaus's free DQS (Data Query Service) and swap in
your personalized zone, which isn't subject to the public-resolver
restriction regardless of which DNS server the query transits:

```
POSTSCREEN_DNSBL_SITES=<your-dqs-key>.zen.dq.spamhaus.net*3 bl.spamcop.net*2
```

Pointing the container at a resolver that isn't one of the blocked ones —
your ISP's own resolver, a router/UDM/Pi-hole, or any recursive resolver you
run yourself — also works and needs no registration. Uncomment and edit the
`dns:` block already present (commented out) on the postfix service in
`docker-compose.yml`:

```yaml
  postfix:
    ...
    dns:
      - 173.44.120.52   # your resolver's IP
```

This is Compose's own `dns:` service key, applied at container-creation
time — it reconfigures what postfix's embedded Docker resolver forwards
*external* (non-container) queries to, while `/etc/resolv.conf` inside the
container keeps pointing at `127.0.0.11` either way, so container-name
resolution (the `spamallam` name postfix's `content_filter` targets, per
`postfix/templates/master.cf.tmpl`) stays intact. Confirmed by comparing
`docker run --network spamallam_mailnet ... cat /etc/resolv.conf` with and
without `--dns` on a throwaway container: identical output (`nameserver
127.0.0.11`) both times.

This is deliberately a direct `docker-compose.yml` edit, not an env var like
everything else in this stack. Two earlier attempts at an env-var-driven
version both broke the *default* (no-override) deployment path in different
ways, both caught via `docker compose config` against a real `.env` before
shipping:

- Rewriting `/etc/resolv.conf` from inside the running container (a
  `POSTFIX_DNS_SERVERS` var applied at runtime in `postfix/entrypoint.sh`)
  discards the `nameserver 127.0.0.11` line entirely, breaking `spamallam`
  resolution and hard-bouncing every relayed message (`5.4.4 Name does not
  resolve`) — regardless of whether the var was set.
- Applying it via Compose's `dns:` key with `${POSTFIX_DNS_SERVER:-default}`
  interpolation: Compose substitutes into an already-typed YAML scalar
  rather than raw text, so there's no default expression that renders as a
  true empty list when the var is unset — both an empty string and a literal
  `"[]"` default ended up wrapped into a one-element list containing an
  invalid entry (`[""]` / `["[]"]`), which breaks container creation for
  every deployment that leaves the var unset, not just ones that set it.

A direct, always-valid, commented-out-by-default block in the tracked
`docker-compose.yml` sidesteps both failure modes entirely.

## Header trust chain

- On receipt, spamallam strips every inbound `X-SpamAllam-*`, `X-Spam-*`,
  `X-Spamd-*` header (folded continuations included) and logs the spoof
  attempt.
- The headers spamallam adds are signed: HMAC-SHA256 over
  `v1\n{ts}\n{verdict}\n{confidence}\n{category}\n{whitelisted}` with the
  shared `HEADER_HMAC_KEY`. The rspamd Lua plugin recomputes the HMAC
  (constant-time compare, ±1 h replay window) and refuses to score unverified
  headers (`SPAMALLAM_SIG_INVALID` instead).
- Downstream (MailPlus rules) can therefore trust `X-SpamAllam-*` only because
  the internet-facing edge strips them first; if you re-architect the mail
  path, preserve that property.
- This trust chain holds regardless of the admin-configurable AI/rspamd
  pipeline order (`ai.pipeline_order`, see AI settings). In "rspamd first"
  mode, rspamd scores the message *before* the `X-SpamAllam-*` headers exist
  for that pass, so it simply never sees them — the Lua plugin already
  handles a missing verdict header gracefully (bails out with no
  `SPAMALLAM_*` symbols added, no error), so no plugin change was needed.
  This is a scoring-coverage trade-off, not a trust-chain weakening.

## Admin interface

- HTTPS only, on an internal/LAN bind — **never** port-forward it.
- Authentication is exclusively FIDO2 WebAuthn passkeys (phishing-resistant,
  origin-bound); there are no passwords to phish, stuff, or brute-force.
  Bootstrap and invites use single-use, 24-hour, hashed-at-rest tokens.
- Sessions: signed cookies, `Secure`/`HttpOnly`/`SameSite=Strict`, 12 h TTL.
  Every state-changing POST requires a per-user CSRF token. HSTS, CSP
  (`default-src 'self'`), no-sniff, deny-frame headers on every response.
- Authorization: only admins mutate settings/users, and only admins can view
  `/logs` (including raw dropped-message downloads), `/logs/audit`, and
  `/logs/blocks` — those pages expose full mail content and AI prompt/response
  text, not just settings, so non-admin invited users cannot see them.
- Every mutation lands in an append-only audit log (who, when, what,
  old → new) with secret values redacted at write time.

## Secrets at rest

- All sensitive values (LLM API keys, PFX file + password, VirusTotal, UniFi
  and search API keys) are stored as AES-256-GCM ciphertext under a key derived
  from `SECRETS_KEY`, which exists only in the container environment / Docker
  secret — never in the /data volume. Volume backups are safe to store.
- The mTLS PFX is decrypted only when a provider call needs it; the PEM
  material touches only a memory-backed tmpfs for the milliseconds an
  `SSLContext` needs to load it, then is unlinked.
- The UI is write-only for secrets (set/replace/clear), traces redact them,
  and the audit log records only *that* they changed.
- **Honest limit**: an attacker with code execution inside the running
  spamallam process can read decrypted secrets from memory. No design in which
  the app can use a secret unattended avoids that; the protection targets the
  disk, backups, and sibling containers.

## AI-specific safeguards

- **No link activation**: neither web tool will ever fetch a URL that appears
  in the analyzed message (exact URL *and* same-host matches are refused) —
  only URLs from search results or known brand domains.
- **No SSRF against internal services**: `web_fetch` resolves its target
  before fetching and refuses private/loopback/link-local/multicast/reserved
  addresses (same class of check `ip_lookup`/`ip_ownership` already apply),
  so a prompt-injection payload cannot induce the model into fetching an
  internal service (rspamd, redis, cloud metadata endpoints, etc.).
- **Over-blocking**: unifi_block refuses shared-mail-provider IPs and private
  ranges, caps CIDR rollup at /24, defaults to suggest-only, and audit-logs
  every attempt.
- **Prompt injection**: the message body is data inside a clearly delimited
  JSON block; tools return structured JSON; the model cannot cause actions
  beyond the enabled tools, and the block tool's guardrails are enforced in
  code, not in the prompt.
- **Availability**: analyses are concurrency-bounded with a hard per-message
  timeout; provider outages follow the configured failure mode (fail-open by
  default) and rspamd outages always fail open — an attacker cannot turn the
  filter into a mail-loss denial of service.

## Container hardening summary

| Service | user | caps | rootfs |
|---|---|---|---|
| postfix | root→postfix (priv-sep) | CHOWN, DAC_OVERRIDE, FOWNER, KILL, SETGID, SETUID, NET_ADMIN | rw (spool) |
| spamallam | uid 1000 | none | read-only + /data + tmpfs |
| rspamd | root→_rspamd | CHOWN, DAC_OVERRIDE, FOWNER, SETGID, SETUID | rw |
| redis / clamav | image defaults | none added | rw (data volumes) |
| acme | root | CHOWN, DAC_OVERRIDE, FOWNER, SETGID, SETUID | rw |

All services: `no-new-privileges: true`, on the internal `mailnet` bridge; only
postfix is additionally dual-homed onto the direct-LAN `mailwan` macvlan
network (see above) — every other service's ports, if published at all, stay
loopback/LAN-only. The certs volume is writable by acme alone. No container
mounts docker.sock.

## Residual risks / operator notes

- The macvlan fix depends on postfix's default route actually going out via
  `MACVLAN_GATEWAY`, so replies to an inbound connection leave via the same
  gateway they arrived on. `postfix/entrypoint.sh` sets this explicitly with
  `ip route replace` at startup (see above) rather than relying on Docker's
  own default-gateway selection, since neither this stack's target Compose
  versions nor older Engine releases (no `gw_priority` schema support, no
  `network connect --gw-priority`) offer a declarative way to pin it. If that
  entrypoint step ever fails silently or gets bypassed (e.g. a custom
  entrypoint override), verify with `docker exec spamallam-postfix ip route`
  after every deploy — a wrong default route silently reopens the
  asymmetric-routing/relay issue this network was added to fix. See "Verify
  the macvlan default route" in [SYNOLOGY.md](SYNOLOGY.md).
- **macvlan can't reach its own host**: if `MAILSERVER_HOST` runs on the same
  physical machine as this stack (the reference Synology/MailPlus deployment),
  it must NOT be set to that host's real LAN IP — Linux's macvlan driver
  cannot route between a macvlan child (postfix, on `mailwan`) and the host
  that owns the parent interface, full stop, regardless of subnet/routing
  config. Mail is accepted, scanned, and reinjected normally right up until
  this last hop, then queues forever as `Host is unreachable` — nothing about
  it fails loudly earlier. Use the `mailnet` docker bridge gateway IP instead;
  see the `MAILSERVER_HOST` guidance in [SYNOLOGY.md](SYNOLOGY.md).
- **MailPlus hostname collision**: postfix's built-in relay-loop guard bounces
  (`mail for <host> loops back to myself`) if `MAILSERVER_HOST`'s own
  EHLO/HELO response matches `MAIL_HOSTNAME` — common on the reference
  deployment if MailPlus was the direct port-25 answerer under that hostname
  before this stack existed. Same failure signature as the macvlan issue
  above (accepted/scanned/reinjected, then bounced at the last hop), different
  cause. Give MailPlus its own distinct hostname; see "Give MailPlus a
  different hostname" in [SYNOLOGY.md](SYNOLOGY.md).
- rspamd's controller UI (:11334) is password-protected but plain HTTP — keep
  it loopback/LAN and treat the password as low-value.
- `verify` recipient mode probes the internal server; keep it in `domain` mode
  if your mail server rate-limits probes.
- The UniFi tool uses `verify=false` toward the controller (self-signed UniFi
  certs); the API key is the actual trust anchor there. Pin a proper cert on
  the console if this bothers you.
- GeoIP quality depends on the GeoLite2 database you mount and refresh.
