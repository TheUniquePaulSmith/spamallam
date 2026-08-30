# Deploying SpamAllam on a Synology NAS (with MailPlus)

This guide covers the reference deployment: the whole stack running on the same
Synology that hosts MailPlus, deployed through Portainer (or Container Manager),
with **no privileged ports** anywhere.

## 1. Port plan

The stack never binds a port below 1024, so it coexists with DSM services.
postfix is the one exception to "reached via the docker host": it's dual-homed
onto a macvlan network (`mailwan`) and gets its own LAN IP
(`POSTFIX_MACVLAN_IP`) so inbound connections arrive with their real source
IP instead of being NAT-rewritten by Docker's port-publish path — see
[SECURITY.md](SECURITY.md) for why that matters (a rewritten source IP can
fall inside `mynetworks` and turn `permit_mynetworks` into an open relay).

| Port | Owner | Reachable at | Purpose |
|---|---|---|---|
| 2525 | spamallam-postfix | `POSTFIX_MACVLAN_IP` (WAN :25 forwarded here) | inbound SMTP |
| 2587 | spamallam-postfix | `POSTFIX_MACVLAN_IP` (WAN :587 forwarded here, optional) | inbound STARTTLS-enforced |
| 2526 (example) | MailPlus | NAS LAN IP | internal delivery port (`MAILSERVER_PORT`) |
| 8443 | spamallam admin UI | docker host, loopback/LAN only | admin UI |
| 11334 | rspamd web UI | docker host, loopback/LAN only | rspamd controller |

### Set up the macvlan network

Set in `.env`:

- `MACVLAN_PARENT` — the NIC this stack's mail traffic actually uses (check
  with `ip -o link show` over SSH, or DSM Network Center).
- `MACVLAN_SUBNET` / `MACVLAN_GATEWAY` — the LAN/VLAN postfix's address lives
  on.
- `POSTFIX_MACVLAN_IP` — a free address on that subnet you pick yourself
  (Docker's macvlan IPAM assigns it statically from `docker-compose.yml`; it
  does not request a lease from your router's DHCP server). Exclude it from
  DSM's/your router's DHCP pool, or reserve it, so nothing else is ever handed
  the same address.

### Verify the macvlan default route (required, every deploy)

postfix's outbound default route must go via `MACVLAN_GATEWAY`, or replies to
an inbound connection leave via a different gateway than they arrived on —
the exact asymmetric-routing condition that let mxtoolbox report an open
relay in the first place. Docker itself doesn't offer a reliable way to pin
this on older Engine/Compose: neither the Compose `gw_priority` schema field
nor the `docker network connect --gw-priority` CLI flag exist prior to fairly
recent releases (Compose rejects the former outright at validation:
`Additional property gw_priority is not allowed`; check yours with
`docker network connect --help`). So `postfix/entrypoint.sh` sets the route
itself at container startup with `ip route replace default via
$MACVLAN_GATEWAY dev <iface>` (the container is granted `NET_ADMIN` for
exactly this, see `docker-compose.yml`) — Docker's own default-gateway
selection is never relied on.

Confirm it took effect after every deploy:

```bash
docker exec spamallam-postfix ip route
```

The `default` line must go via `MACVLAN_GATEWAY` (your mail LAN's router), not
the `delivernet` bridge gateway (`DOCKER_SUBNET`'s `.1`). It should always be
correct — the entrypoint fails the container outright (check `docker logs
spamallam-postfix`) if it can't find an interface holding
`POSTFIX_MACVLAN_IP`. A wrong-but-running result would mean something
replaced or skipped the entrypoint (e.g. a custom `command:`/`entrypoint:`
override).

### Move MailPlus off :25

MailPlus Server → **Service** → **SMTP**: change the SMTP port from 25 to your
chosen internal port (e.g. **2526**), and set `MAILSERVER_PORT=2526` in `.env`.
MailPlus keeps handling **outbound** mail itself — SpamAllam is inbound-only
by design.

**`MAILSERVER_HOST` — read this before setting it**: if MailPlus runs on this
*same* Synology (the reference deployment this guide covers), do **not** set
it to the NAS's real LAN IP. Linux's macvlan driver cannot route between a
macvlan child (postfix, on `mailwan`) and the physical host that owns the
parent interface — even though they're on the same subnet, the kernel blocks
it. Mail queues up as `Host is unreachable` and never gets delivered; it will
look like everything is working (accepted, scanned, reinjected) right up
until this last hop. Use the `delivernet` docker bridge gateway IP instead — that
path never touches the macvlan interface, so it isn't affected:

```bash
docker network inspect spamallam_delivernet --format '{{(index .IPAM.Config 0).Gateway}}'
docker exec spamallam-postfix nc -zv -w5 <that-gateway-ip> <MAILSERVER_PORT>
```

If the `nc` check succeeds (it will, unless MailPlus is bound to a specific
interface rather than all of them), set `MAILSERVER_HOST` to that gateway IP
— typically `172.28.0.1` for the default `DOCKER_SUBNET`.

> If MailPlus is on a genuinely different physical host, its normal LAN IP is
> correct as-is — this restriction only applies when it's the same box.

### Give MailPlus a different hostname than `MAIL_HOSTNAME`

Postfix refuses to relay to a server whose EHLO/HELO response hostname
matches its own `$myhostname` (`MAIL_HOSTNAME`) — a built-in, non-configurable
loop guard, since a match normally means "this relay hop points back at
myself." Before this stack existed, MailPlus was likely the thing directly
answering port 25 under your public mail hostname (e.g.
`mail.fractalengine.com`), and that identity often survives the port move
unless changed explicitly. The symptom is mail accepted, scanned, and
reinjected successfully, then bounced at the very last hop:

```
warning: host <MAILSERVER_HOST>:<port> greeted me with my own hostname <MAIL_HOSTNAME>
status=bounced (mail for <MAILSERVER_HOST>:<port> loops back to myself)
```

Fix: **MailPlus Server → General → Hostname (FQDN)** — set it to anything
*other* than `MAIL_HOSTNAME`, e.g. `mail-internal.<yourdomain>`. It only needs
to be unique for this internal EHLO handshake between postfix and MailPlus on
the private mail network — it doesn't need to resolve publicly or match any
DNS record. After changing it, flush any mail stuck from before the fix:

```bash
docker exec spamallam-postfix postqueue -f
docker exec spamallam-postfix mailq
```

### Trust the gateway as an internal relay

Because the relay hop targets the `delivernet` bridge gateway rather than going
out via `mailwan`, MailPlus sees the connection arrive from **postfix's own
address on the `delivernet` bridge** — i.e. from within `DOCKER_SUBNET` (default
`172.28.0.0/24`), the same as it would with plain bridge networking and no
macvlan involved. It is *not* `POSTFIX_MACVLAN_IP`.

MailPlus must accept mail for your domains from `DOCKER_SUBNET`:

- Add `DOCKER_SUBNET` to MailPlus's allow list so the NAS/docker source is
  never greylisted/rate-limited/re-authenticated — see "MailPlus's own
  SPF/DKIM/ARC checks will always fail for relayed mail" below for the exact
  steps.
- MailPlus Server → **Service** → SMTP: no authentication is needed for mail
  addressed *to* your served domains; verify a test mail is accepted.
- Since rspamd runs in this stack, disable MailPlus's own spam/rspamd engine
  (MailPlus Server → **Security** → Spam) to avoid double-scoring, or keep it —
  double-scanning is safe, just redundant.

### MailPlus's own SPF/DKIM/ARC checks will always fail for relayed mail

If MailPlus performs its own inbound SPF/DKIM/DMARC/anti-spoofing validation
(**Mail Delivery → Security** tab — not the outbound-signing toggle of the
same name), it re-runs those checks against the connection it actually
sees — from spamallam-postfix on `DOCKER_SUBNET`, not the sender's real MTA.
Two distinct effects, both expected and neither fixable by tweaking the setup
further:

- **SPF always softfails/fails.** SPF validates the *immediately connecting*
  IP against the envelope-from domain's SPF record. That connecting IP is now
  your internal relay, which no sender's SPF record will ever authorize — this
  happens for every relayed message from every SPF-publishing domain,
  regardless of whether the original sender was legitimate. rspamd already
  did the real check against the true origin (see `R_SPF_ALLOW` /
  `DMARC_POLICY_ALLOW` in `X-Spamd-Result`).
- **ARC/DKIM reject on any message spamallam body-rewrites.** The
  classification footer and SPAM banner (`app/pipeline/body.py`) intentionally
  modify the body after the original sender signed it, so the original
  DKIM/ARC body hash genuinely no longer matches — this isn't a
  misconfiguration, it's a cryptographically correct "fail" for bytes that
  were legitimately altered downstream of the signature. You cannot have both
  MailPlus-side ARC validation passing *and* body-rewrite features (footer
  tags, banners) enabled for the same message.

**Fix**: MailPlus Server → **Mail Delivery** → **Security** →
**Block/Allow List** → **Allow list** tab → **Create** → give it a name (e.g.
`Spamallam`) and set **Rule** to `DOCKER_SUBNET` in CIDR form (default
`172.28.0.0/24`) → **OK**, then **OK** on the Block/Allow List dialog. The
allow list takes precedence over the block list, and — per Synology's own
help text on that dialog — this is also where the checks in "Trust the
gateway as an internal relay" above (greylisting/rate-limiting exemptions)
get applied, so one entry covers both. Authentication trust belongs upstream,
at spamallam/rspamd, which signs its verdict into `X-SpamAllam-*`/
`X-Spamd-Result` before this hop — see
[SECURITY.md](SECURITY.md#header-trust-chain).

## 2. Deploy with Portainer

1. Portainer → Stacks → **Add stack** → Repository (point at this git repo) or
   paste `docker-compose.yml`.
2. Add the environment variables from `.env.example` in the stack's *Environment
   variables* section (Portainer substitutes them like compose does).
3. Deploy. First ClamAV start downloads signatures (several minutes); postfix
   and spamallam are usable immediately.
4. `docker logs spamallam-app` → open the printed `/setup?token=…` URL from a
   LAN browser to enroll the first admin passkey.

To reach the admin UI from your LAN set `ADMIN_BIND=<NAS-LAN-IP>:8443` in the
stack environment (default is loopback only).

## 3. Folder rules from verdict headers

Every delivered message carries:

| Header | Meaning |
|---|---|
| `X-Spam-Flag: YES` | rspamd total score crossed the add-header threshold |
| `X-Spam-Status: Yes/No, score=… required=…` | score summary |
| `X-Spamd-Result: …` | full symbol list |
| `X-SpamAllam-Verdict: HAM/SPAM/PHISHING/MALICIOUS/SKIPPED/ERROR` | AI verdict |
| `X-SpamAllam-Category: …` | AI category (e.g. "timeshare offer") |
| `X-SpamAllam-Whitelisted: yes; rule=…` | admin override applied |

MailPlus (webmail) supports per-user filter rules on custom headers:
**MailPlus → Settings → Message filter rules → Create**, condition type
*Header* — e.g. `X-Spam-Flag` *contains* `YES` → move to **Junk**, or
`X-SpamAllam-Category` *contains* `newsletter` → move to a Newsletters folder.
Because the headers are added before delivery, server-side rules apply to every
client (IMAP/mobile included).

> High-confidence PHISHING/MALICIOUS never reaches a mailbox at all — it is
> silently dropped at the gateway and visible in the admin UI's message log.

## 4. Certificates

The `acme` container issues via DNS-01 (`ACME_DNS_PROVIDER`, e.g. `dns_cf` for
Cloudflare or `dns_synology_dsm`). It is independent of DSM's own certificate
handling — no interaction with DSM's LetsEncrypt. If you leave it unconfigured,
self-signed certificates keep the stack functional (fine for testing; replace
before going live, since sending servers see the cert on STARTTLS).

## 5. Updating

```bash
git pull
SPAMALLAM_VERSION="$(git describe --tags --always --dirty)" docker compose build --pull
docker compose up -d
```

`SPAMALLAM_VERSION` stamps the git tag (or short commit hash) into the image;
it shows in the admin UI footer. Omit it and the footer falls back to the
packaged version from `pyproject.toml`.

State (config, users, logs, bayes data, certs) lives in named volumes and
survives rebuilds. Back up the `spamallam-data` volume — with `SECRETS_KEY`
kept separately, its config files contain no plaintext secrets.

### Upgrading across the network-segmentation change

The release that split `mailnet` into `filternet`/`delivernet`/`scannet`/
`acmenet` needs one extra step, because `delivernet` takes over
`DOCKER_SUBNET` (which is what keeps `MAILSERVER_HOST` working unchanged) while
the old network still holds it:

```
failed to create network spamallam_delivernet: Error response from daemon:
Pool overlaps with other one on this address space
```

`mailnet` is gone from `docker-compose.yml`, so `down` does not always remove
it. Delete it explicitly, then bring the stack up:

```bash
docker compose down --remove-orphans && docker network rm spamallam_mailnet && docker compose up -d --build
```

Never add `-v` to that `down`: the postfix spool is a named volume, and queued
mail lives in it. That release also requires a new `REDIS_PASSWORD` in `.env`,
and `SECRETS_KEY`/`HEADER_HMAC_KEY` of at least 32 characters — the containers
refuse to start otherwise. See the README's Upgrading section.
