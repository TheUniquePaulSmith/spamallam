# UniFi integration

Two touch points: the **port forwards** that deliver SMTP to the stack, and the
optional **network-block tool** the AI can use against confirmed-malicious
sources.

## 1. Port forwarding (required)

UniFi Network → Settings → **Port Forwarding**:

| Name | WAN port | Forward IP | Forward port |
|---|---|---|---|
| smtp-inbound | 25 | `POSTFIX_MACVLAN_IP` (from `.env`) | 2525 |
| smtp-starttls (optional) | 587 | `POSTFIX_MACVLAN_IP` | 2587 |

Forward to postfix's own macvlan address, **not** the docker host / NAS IP.
postfix is dual-homed onto a dedicated mail LAN (`mailwan` in
`docker-compose.yml`) specifically so it gets a real, un-NATed IP here —
forwarding to the NAS IP instead would route through Docker's port-publish
path again and reintroduce the source-IP-rewrite/open-relay issue this setup
avoids (see [SECURITY.md](SECURITY.md)).

If your mail LAN (`MACVLAN_SUBNET`) is its own VLAN, also confirm UniFi's
inter-VLAN/firewall rules let WAN-forwarded traffic reach it, and that the
gateway you set as `MACVLAN_GATEWAY` gives that VLAN normal outbound routing
(postfix's DNSBL lookups and its relay hop to `MAILSERVER_HOST` both egress
via this network — see the `gw_priority` note in `docker-compose.yml`).

Do **not** forward 8443 (admin UI) or 11334 (rspamd UI) — those are LAN-only.

## 2. Network-block tool (optional)

When enabled (Admin UI → Tools → `unifi_block`), the AI may request that a
confirmed-malicious SMTP source be added to a named UniFi address group /
Network List, which you reference from a firewall rule that drops inbound SMTP.

### Setup

1. **API key**: UniFi console → Settings → Control Plane → **Integrations** →
   Create API key. Paste it into Admin UI → Tools → unifi_block (stored
   encrypted).
2. **URL**: your console, e.g. `https://192.168.1.1`. **Site**: `default`
   unless you renamed it.
3. Deploy once in `suggest` policy: the tool only *records* recommendations
   (Admin UI → Logs → Blocks). Create the group on first use or let `auto`
   policy create it: an address group named `spamallam-blocked`
   (`UNIFI_NETWORK_LIST`).
4. Create the firewall rule yourself (one time): Security → Firewall rules →
   WAN In (or your zone-based equivalent) → **Block**, source =
   `spamallam-blocked` group, destination port = your forwarded SMTP ports.
5. When you trust the behavior, switch the policy to `auto`.

### Guardrails (built in, not configurable off)

- IPs whose rDNS matches a **shared mail provider** (SendGrid, Amazon SES,
  Mailchimp/Mandrill, Azure Communication Services, Microsoft 365, Google,
  Mailgun, Postmark, SparkPost, Brevo, Zoho, Proton) are **always refused** —
  blocking them would break unrelated legitimate mail. Handle those senders by
  content classification and domain whitelisting instead.
- CIDR rollup is capped at `max_prefix` (default /24) — the AI can never
  request a /8.
- IPv4 public space only; private/reserved ranges refused.
- Every attempt (suggested / executed / refused) is written to the block log
  and the admin audit log.

### API compatibility note

The tool talks to the classic Network REST endpoint
(`…/proxy/network/api/s/<site>/rest/firewallgroup`) with an `X-API-KEY` header,
falling back to the non-UniFi-OS path automatically. Recent UniFi Network
releases accept console API keys on these endpoints; if yours does not (older
controllers), leave the tool in `suggest` mode and apply blocks by hand from
the Blocks page.
