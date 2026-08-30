# Firewall and traffic model

Docker-level segmentation (see [SECURITY.md](SECURITY.md)) is only half the
boundary. It controls which containers can reach each other; it cannot control
what a compromised container can reach on your LAN, and it cannot stop anything
from talking to the Docker host itself. Those parts need rules on your gateway
and on the host.

This document is the full traffic model — every flow the stack makes, which
boundary it crosses, and whether a firewall can even see it — followed by the
rules worth applying. [UNIFI.md](UNIFI.md) covers the port-forwards you need for
mail to work at all; this covers everything you should *deny*.

---

## 1. The one rule that matters most

If you read nothing else:

> **Restrict `MAILSERVER_PORT` on the Docker host so that only postfix's
> `delivernet` address can connect to it.**

After the network segmentation, `rspamd`, `redis`, `clamav` and `acme` can no
longer reach postfix's re-injection listener. But `scannet` is not an internal
network — those containers have internet egress, and traffic they send to
`172.28.0.1` (the `delivernet` gateway) is routed to the Docker host, which owns
that address. If your mail server is listening there, a compromised scanner can
deliver to it directly, skipping the gateway entirely.

Docker networking cannot close that. Only a host firewall rule can.

---

## 2. Why postfix is the only container a network firewall can see

postfix is on a **macvlan** network, so it has a real IP and MAC on your mail
LAN. Your gateway sees it as a device and VLAN/firewall rules apply to it
normally.

Every other container is behind a Docker **bridge**. Its traffic leaves the host
NAT'd to the host's own IP, so:

- your gateway cannot distinguish rspamd's traffic from the NAS's own traffic;
- a rule targeting "the rspamd container" on your gateway will silently match
  nothing;
- inbound rules cannot reach those containers at all unless a port is published.

So: **gateway rules constrain postfix and the LAN. Everything else is
constrained by Docker network membership (§4) and host rules (§6).** Writing
gateway rules for the other containers feels productive and accomplishes
nothing — don't.

---

## 3. Traffic inventory

### 3.1 WAN → gateway → mail LAN

| Flow | Destination | Port | Firewallable | Notes |
|---|---|---|---|---|
| Inbound SMTP | `POSTFIX_MACVLAN_IP` | 2525 | **Yes** | WAN :25 forwarded here |
| Inbound submission | `POSTFIX_MACVLAN_IP` | 2587 | **Yes** | WAN :587, optional; STARTTLS enforced |

Nothing else should ever be forwarded from WAN. In particular **never** forward
10025, 10026, 8443 or 11334.

### 3.2 postfix egress

| Flow | Destination | Port | Firewallable | Notes |
|---|---|---|---|---|
| DNSBL / DNS | `POSTFIX_DNS_SERVER` | 53 | **Yes** | postscreen's Spamhaus/SpamCop lookups |
| Outbound SMTP replies | internet | ephemeral | **Yes** | via `MACVLAN_GATEWAY` (the pinned default route) |
| Delivery to mail server | `MAILSERVER_HOST` | `MAILSERVER_PORT` | Host-only | over `delivernet`, not the LAN |

### 3.3 Inside Docker

None of these cross a network boundary your gateway can see. They are governed
entirely by network membership.

| Flow | Network | Port | Who can reach it |
|---|---|---|---|
| postfix → spamallam (content filter) | `filternet` | 10026 | postfix only (bound to `FILTER_SPAMALLAM_IP`) |
| spamallam → postfix (re-injection) | `filternet` | 10025 | spamallam only (bound to `FILTER_POSTFIX_IP`, `mynetworks` is its /32) |
| spamallam → rspamd | `scannet` | 11333 | spamallam, redis, clamav |
| spamallam → redis (tool cache, DB 1) | `scannet` | 6379 | password-protected |
| rspamd → redis (bayes/fuzzy, DB 0) | `scannet` | 6379 | password-protected |
| rspamd → clamav | `scannet` | 3310 | — |

### 3.4 Container egress to the internet

Useful as a detection baseline: anything outside this list is worth alerting on.

| Container | Legitimate egress |
|---|---|
| postfix | DNS/DNSBL, outbound SMTP |
| spamallam | the configured LLM provider only |
| rspamd | DNS/RBLs, `fuzzy.rspamd.com:11445`, VirusTotal (if enabled) |
| clamav | freshclam signature updates |
| acme | the ACME server and your DNS provider's API |
| **redis** | **none whatsoever** |

`redis` is the clearest signal in the stack: it has no legitimate reason to
send a single packet to the internet. If it does, something is wrong.

### 3.5 Host-published ports

| Service | Default bind | Notes |
|---|---|---|
| spamallam admin UI | `127.0.0.1:8443` (`ADMIN_BIND`) | HTTPS, passkey-only |
| rspamd controller | `127.0.0.1:11334` (`RSPAMD_UI_BIND`) | **plain HTTP** |

Both default to loopback. Prefer reaching them over VPN or an SSH tunnel
(`ssh -L 8443:127.0.0.1:8443 nas`) rather than widening the bind — especially
the rspamd controller, whose password would cross your LAN in cleartext.

---

## 4. Gateway (UniFi) rules

Port-forwards are in [UNIFI.md](UNIFI.md). These are the denies.

1. **Allow WAN → `POSTFIX_MACVLAN_IP` on 2525 (and 2587) only.** Explicitly deny
   everything else to that address. It is a real LAN device with a real IP;
   without this, any future forward you add to that host is reachable.
2. **Deny LAN → `POSTFIX_MACVLAN_IP` except from your admin workstation.**
   Nothing on your LAN needs to talk to the gateway MTA.
3. **Isolate `MACVLAN_SUBNET` from your other VLANs.** It should reach the
   internet and nothing else internal. This is the containment boundary if
   postfix itself is ever compromised.
4. **Constrain postfix's egress** to DNS (53) and SMTP (25/465/587) rather than
   "any". A mail gateway has no reason to open arbitrary outbound connections.
5. **Never forward 10025, 10026, 8443 or 11334 from WAN.** 10025 in particular
   is the unfiltered path to your mailboxes.

---

## 5. Verifying the segmentation

Run after any change to the networks. The first two must **fail** — that is the
whole point of the change.

```bash
docker run --rm --network spamallam_scannet nicolaka/netshoot nc -zv -w3 172.28.1.2 10025
```

```bash
docker run --rm --network spamallam_scannet nicolaka/netshoot nc -zv -w3 172.28.1.3 10026
```

(Use a throwaway container: `redis:7-alpine` has neither `nc` nor bash's
`/dev/tcp`, so `docker exec spamallam-redis` cannot test this.)

Then confirm the listeners are bound where they should be:

```bash
docker exec spamallam-postfix ss -lnt
```

Expect 10025 on `FILTER_POSTFIX_IP` **only**, and 2525/2587 on
`POSTFIX_MACVLAN_IP` **only**. And confirm the trust boundary:

```bash
docker exec spamallam-postfix postconf mynetworks
```

Expect `127.0.0.0/8 [::1]/128 172.28.1.3/32` — a single host, not a subnet.

Finally, from outside, confirm only the mail ports answer:

```bash
nmap -Pn -p 25,587,2525,2587,8443,10025,10026,11334 <your-wan-ip>
```

---

## 6. Docker host rules

### 6.1 Restrict the mail server's port (the important one)

Allow only postfix's `delivernet` address to reach `MAILSERVER_PORT`. Find it
with:

```bash
docker inspect spamallam-postfix --format '{{(index .NetworkSettings.Networks "spamallam_delivernet").IPAddress}}'
```

On a Synology (or any Linux host), with that address as `<postfix-ip>` and the
bridge interface as `<br-iface>` (from `ip -o addr show | grep 172.28.0.1`):

```bash
sudo iptables -I INPUT -i <br-iface> -p tcp --dport 2526 ! -s <postfix-ip> -j DROP
```

Persist it the way your distribution expects; on DSM, a boot-up Task Scheduler
task is the usual route. Verify it works from a container that should be
refused:

```bash
docker run --rm --network spamallam_scannet nicolaka/netshoot nc -zv -w3 172.28.0.1 2526
```

**This is a different control from the MailPlus allow list** described in
[SYNOLOGY.md](SYNOLOGY.md). The allow list says *who MailPlus will relay for*;
the firewall says *who may connect at all*. The allow list is still scoped to
`DOCKER_SUBNET`, which is correct — postfix's source address is in that subnet.
The firewall half can and should be narrowed to the single address.

### 6.2 Keep the admin ports on loopback

Leave `ADMIN_BIND` and `RSPAMD_UI_BIND` at their `127.0.0.1` defaults. If you
must reach them from elsewhere, use a VPN or an SSH tunnel.

---

## 7. What this does and does not protect against

**Does:**

- Stops a compromised scanner container from injecting mail into your internal
  server (§6.1 plus the network segmentation).
- Stops the re-injection listener from existing anywhere it could be
  port-forwarded to the internet.
- Limits the blast radius of a postfix compromise to one isolated VLAN.
- Gives you an egress baseline where unexpected traffic is a real signal (§3.4).

**Does not:**

- Authenticate the re-injection channel. These rules reduce *who can reach* it;
  they do not make it prove who it is. Anything that legitimately reaches
  postfix:10025 is still trusted completely. Cryptographic authentication
  (mTLS between spamallam and postfix) is the next tier and is not implemented.
- Protect against compromise of the Docker host itself. The host owns every
  bridge gateway and can reach everything; that is explicitly out of scope in
  the threat model.
- Help if `MYNETWORKS_EXTRA` is set carelessly. Anything listed there can
  deliver unfiltered mail to your internal server. Add single addresses, never
  subnets.
