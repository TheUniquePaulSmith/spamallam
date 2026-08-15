# Deploying SpamAllam on a Synology NAS (with MailPlus)

This guide covers the reference deployment: the whole stack running on the same
Synology that hosts MailPlus, deployed through Portainer (or Container Manager),
with **no privileged ports** anywhere.

## 1. Port plan

The stack never binds a port below 1024, so it coexists with DSM services:

| Port | Owner | Purpose |
|---|---|---|
| 2525 | spamallam-postfix | inbound SMTP (WAN :25 forwarded here) |
| 2587 | spamallam-postfix | inbound STARTTLS-enforced (WAN :587 forwarded here, optional) |
| 2526 (example) | MailPlus | internal delivery port (`MAILSERVER_PORT`) |
| 8443 | spamallam admin UI | loopback/LAN only |
| 11334 | rspamd web UI | loopback/LAN only |

### Move MailPlus off :25

MailPlus Server → **Service** → **SMTP**: change the SMTP port from 25 to your
chosen internal port (e.g. **2526**), and set `MAILSERVER_HOST` to the NAS LAN IP
and `MAILSERVER_PORT=2526` in `.env`. MailPlus keeps handling **outbound** mail
itself — SpamAllam is inbound-only by design.

> If MailPlus is on a different host, just point `MAILSERVER_HOST/PORT` there;
> nothing else changes.

### Trust the gateway as an internal relay

MailPlus must accept mail for your domains from the docker subnet
(default `172.28.0.0/24`, i.e. the NAS itself when using bridge networking —
connections will appear to come from the NAS/docker bridge IP):

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
