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
the `mailnet` bridge gateway (`DOCKER_SUBNET`'s `.1`). It should always be
correct — the entrypoint fails the container outright (check `docker logs
spamallam-postfix`) if it can't find an interface holding
`POSTFIX_MACVLAN_IP`. A wrong-but-running result would mean something
replaced or skipped the entrypoint (e.g. a custom `command:`/`entrypoint:`
override) — mail may still flow either way (postscreen/DNSBL and the relay
hop to `MAILSERVER_HOST` work regardless, since `MAILSERVER_HOST` is
on-link), so this won't fail loudly on its own; don't skip the check.

### Move MailPlus off :25

MailPlus Server → **Service** → **SMTP**: change the SMTP port from 25 to your
chosen internal port (e.g. **2526**), and set `MAILSERVER_HOST` to the NAS LAN IP
and `MAILSERVER_PORT=2526` in `.env`. MailPlus keeps handling **outbound** mail
itself — SpamAllam is inbound-only by design.

> If MailPlus is on a different host, just point `MAILSERVER_HOST/PORT` there;
> nothing else changes.

### Trust the gateway as an internal relay

Now that postfix's outbound relay hop rides the macvlan network's default
route (see above), MailPlus sees the relay connection arriving **from
`POSTFIX_MACVLAN_IP`** directly — not from the docker bridge subnet or a
NAS-NATed address as with plain bridge networking. If `MAILSERVER_HOST` is on
the same `MACVLAN_SUBNET` as postfix (as it is when MailPlus and
`POSTFIX_MACVLAN_IP` both live on a dedicated mail VLAN), this connection is
on-link — no gateway hop, no NAT.

MailPlus must accept mail for your domains from `POSTFIX_MACVLAN_IP`:

- MailPlus Server → **Security** → make sure the NAS/docker source is not
  greylisted/rate-limited.
- MailPlus Server → **Service** → SMTP: no authentication is needed for mail
  addressed *to* your served domains; verify a test mail is accepted.
- Since rspamd runs in this stack, disable MailPlus's own spam/rspamd engine
  (MailPlus Server → **Security** → Spam) to avoid double-scoring, or keep it —
  double-scanning is safe, just redundant.

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
docker compose build --pull
docker compose up -d
```

State (config, users, logs, bayes data, certs) lives in named volumes and
survives rebuilds. Back up the `spamallam-data` volume — with `SECRETS_KEY`
kept separately, its config files contain no plaintext secrets.
