"""UniFi network-blocking integration.

Adds a rolled-up CIDR for a confirmed-malicious SMTP source to a named UniFi
"Network List" / firewall address group, which the admin references from a
firewall rule that drops inbound SMTP.

Guardrails (defense against over-blocking):
  * NEVER blocks an IP whose rDNS matches a known shared mail provider
    (SendGrid, SES, Mailchimp, ACS, ...) — that would break legitimate mail
    from unrelated senders. Domain whitelisting is the right lever there.
  * CIDR rollup is capped (default /24 max, i.e. never wider).
  * IPv4 only; private/reserved ranges refused.
  * Default policy is "suggest": the block is recorded for admin review in the
    admin UI, nothing is pushed to UniFi until policy is set to "auto".
  * Every attempt — suggested, executed or refused — is audit-logged.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import time
from typing import Any

import httpx

from ..config import ENV
from ..store.audit import record as audit_record
from ..store.files import append_jsonl
from ..store.secrets import SecretsBox
from . import providers_db


def _suggestions_path():
    return ENV.data_dir / "logs" / "block-suggestions.jsonl"


def rollup(ip: str, prefix: int, max_prefix: int) -> str:
    """Roll an IPv4 address up to `prefix`, never wider than `max_prefix`."""
    prefix = max(prefix, max_prefix)  # numerically larger prefix = narrower net
    net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
    return str(net)


async def unifi_block(args: dict[str, Any], cfg: dict[str, Any], box: SecretsBox) -> dict[str, Any]:
    ucfg = cfg["tools"]["unifi_block"]
    ip = str(args.get("ip", "")).strip()
    reason = str(args.get("reason", "")).strip()[:300]
    requested_prefix = int(args.get("prefix", 32))

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"error": f"invalid IP {ip!r}"}
    if addr.version != 4:
        return {"refused": True, "reason": "IPv6 blocking not supported; refusing"}
    if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast:
        return {"refused": True, "reason": "refusing to block private/reserved address space"}

    # Guardrail: shared mail providers are never blockable
    hostname = await asyncio.get_running_loop().run_in_executor(
        None, lambda: _safe_rdns(ip)
    )
    shared = providers_db.match_hostname(hostname)
    if shared:
        audit_record("spamallam-ai", "unifi_block.refused",
                     {"ip": ip, "shared_provider": shared, "reason": reason})
        return {
            "refused": True,
            "ip": ip,
            "reverse_dns": hostname,
            "shared_provider": shared,
            "reason": (f"{shared['name']} is a shared mail provider — blocking its IPs "
                       "would break unrelated legitimate mail. Use domain-level "
                       "classification/whitelisting instead."),
        }

    max_prefix = int(ucfg.get("max_prefix", 24))
    cidr = rollup(ip, requested_prefix, max_prefix)

    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "ip": ip,
        "cidr": cidr,
        "reverse_dns": hostname,
        "reason": reason,
        "policy": ucfg.get("policy", "suggest"),
    }

    if ucfg.get("policy", "suggest") != "auto":
        entry["status"] = "suggested"
        append_jsonl(_suggestions_path(), json.dumps(entry, ensure_ascii=False))
        audit_record("spamallam-ai", "unifi_block.suggested", entry)
        return {
            "status": "suggested",
            "cidr": cidr,
            "note": ("policy is 'suggest' — block recorded for admin review in the "
                     "admin UI; nothing was pushed to UniFi"),
        }

    try:
        result = await push_block(cfg, box, cidr)
    except Exception as exc:  # noqa: BLE001
        entry["status"] = "error"
        entry["error"] = str(exc)
        append_jsonl(_suggestions_path(), json.dumps(entry, ensure_ascii=False))
        audit_record("spamallam-ai", "unifi_block.error", entry)
        return {"error": f"UniFi API call failed: {exc}", "cidr": cidr}

    entry["status"] = "blocked"
    append_jsonl(_suggestions_path(), json.dumps(entry, ensure_ascii=False))
    audit_record("spamallam-ai", "unifi_block.executed", entry)
    return {"status": "blocked", "cidr": cidr, "unifi": result}


def _safe_rdns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""


async def push_block(cfg: dict[str, Any], box: SecretsBox, cidr: str) -> dict[str, Any]:
    """Append `cidr` to the configured UniFi firewall address group.

    Uses the classic Network REST endpoint (/rest/firewallgroup) with an
    UniFi OS API key — see docs/UNIFI.md for version notes and setup.
    """
    ucfg = cfg["tools"]["unifi_block"]
    base = (ucfg.get("url") or "").rstrip("/")
    if not base:
        raise RuntimeError("UniFi URL not configured")
    api_key = box.decrypt_str(ucfg["api_key"]) if SecretsBox.is_encrypted(ucfg.get("api_key")) else ""
    if not api_key:
        raise RuntimeError("UniFi API key not configured")
    site = ucfg.get("site", "default")
    group_name = ucfg.get("network_list", "spamallam-blocked")

    headers = {"X-API-KEY": api_key, "Accept": "application/json"}
    async with httpx.AsyncClient(timeout=20, verify=False, headers=headers) as client:
        # UniFi OS consoles use the /proxy/network prefix; bare controllers do not.
        for prefix in ("/proxy/network", ""):
            list_url = f"{base}{prefix}/api/s/{site}/rest/firewallgroup"
            resp = await client.get(list_url)
            if resp.status_code == 404:
                continue
            resp.raise_for_status()
            groups = resp.json().get("data", [])
            group = next((g for g in groups if g.get("name") == group_name), None)
            if group is None:
                create = await client.post(list_url, json={
                    "name": group_name,
                    "group_type": "address-group",
                    "group_members": [cidr],
                })
                create.raise_for_status()
                return {"created_group": group_name, "members": [cidr]}
            members = list(dict.fromkeys([*(group.get("group_members") or []), cidr]))
            update = await client.put(f"{list_url}/{group['_id']}", json={
                **group, "group_members": members,
            })
            update.raise_for_status()
            return {"group": group_name, "members": members}
    raise RuntimeError("firewallgroup endpoint not found — check UniFi URL/version (docs/UNIFI.md)")


def read_suggestions(limit: int = 200) -> list[dict]:
    try:
        lines = _suggestions_path().read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return []
    out = []
    for line in lines[-limit:]:
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return list(reversed(out))
