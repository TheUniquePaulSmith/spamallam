"""Tool registry: definitions offered to the LLM + dispatch, honoring per-tool
enable/disable switches from the admin UI."""
from __future__ import annotations

from typing import Any

from ..store.secrets import SecretsBox
from . import netinfo, providers_db, unifi, webtools

_DEFINITIONS: dict[str, dict[str, Any]] = {
    "ip_lookup": {
        "description": ("Look up an IP address: reverse DNS, GeoIP country/city/ASN, RIR "
                        "registry ownership, and whether it belongs to a known shared mail "
                        "provider. Use on the connecting client IP and Received-chain hops."),
        "parameters": {
            "type": "object",
            "properties": {"ip": {"type": "string", "description": "IPv4/IPv6 address"}},
            "required": ["ip"],
        },
    },
    "domain_age": {
        "description": ("RDAP (WHOIS) lookup of a domain's registration date, age in days and "
                        "registrar. Newly registered sender domains are a strong spam/phishing "
                        "signal."),
        "parameters": {
            "type": "object",
            "properties": {"domain": {"type": "string"}},
            "required": ["domain"],
        },
    },
    "ip_ownership": {
        "description": ("Regional Internet Registry (RDAP) ownership lookup: WHO owns and "
                        "operates an IP address or every IP a hostname resolves to — owning "
                        "organization, registration country, RIR and netblock. Uses DNS and "
                        "registry queries ONLY (never contacts the target host), so it is safe "
                        "on hostnames from message links/images. Use it to correlate sending "
                        "IP vs sender-domain hosting vs link/image hosting: e.g. mail carried "
                        "by SendGrid whose links resolve to an unrelated foreign-registered "
                        "network is a masquerade indicator."),
        "parameters": {
            "type": "object",
            "properties": {"target": {"type": "string",
                                      "description": "IP address or hostname to attribute"}},
            "required": ["target"],
        },
    },
    "dns_verify": {
        "description": ("Fetch MX, SPF and DMARC records for a domain, and optionally check "
                        "whether the sender domain aligns with a claimed brand's domain "
                        "(impersonation check, e.g. mail claiming to be OpenSea.io)."),
        "parameters": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "sender domain to inspect"},
                "claimed_brand_domain": {
                    "type": "string",
                    "description": "official domain of the brand the mail claims to be from (optional)",
                },
            },
            "required": ["domain"],
        },
    },
    "web_search": {
        "description": ("Search the web to validate a sender, brand or claim (e.g. 'is "
                        "example-corp.com a real company'). Returns titles/URLs/snippets only. "
                        "Never fetches URLs from the analyzed message."),
        "parameters": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
    "web_fetch": {
        "description": ("Fetch one page found via web_search or a well-known brand domain, to "
                        "validate sender legitimacy. REFUSES any URL that appears in the "
                        "analyzed message body (activation-link protection)."),
        "parameters": {
            "type": "object",
            "properties": {"url": {"type": "string", "description": "http(s) URL to fetch"}},
            "required": ["url"],
        },
    },
    "shared_provider_check": {
        "description": ("Determine whether the message was sent through a shared bulk-mail "
                        "provider (SendGrid, Amazon SES, Mailchimp, Azure Communication "
                        "Services, ...). Detects legitimate-infrastructure masquerading: a "
                        "trusted provider carrying an impersonation attack."),
        "parameters": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "connecting client IP (optional)"},
                "domain": {"type": "string", "description": "sender/return-path domain (optional)"},
            },
        },
    },
    "unifi_block": {
        "description": ("Request a network-level block of a confirmed-malicious SMTP source at "
                        "the UniFi gateway. Provide the attacking IP, an optional CIDR prefix "
                        "to roll up (never wider than the configured cap), and a reason. "
                        "Refuses shared-mail-provider IPs. Depending on policy the block is "
                        "either executed or recorded as a suggestion for the admin."),
        "parameters": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "attacking IPv4 address"},
                "prefix": {"type": "integer", "description": "CIDR prefix to roll up to (default 32)"},
                "reason": {"type": "string", "description": "why this source should be blocked"},
            },
            "required": ["ip", "reason"],
        },
    },
}


def tool_definitions(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for name, definition in _DEFINITIONS.items():
        if cfg["tools"].get(name, {}).get("enabled"):
            out.append({"name": name, **definition})
    return out


async def _shared_provider_check(args: dict[str, Any], summary: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    ip = str(args.get("ip", "")).strip()
    domain = str(args.get("domain", "")).strip()
    if ip:
        hostname = await netinfo.rdns_cached(ip)
        out["ip"] = ip
        out["reverse_dns"] = hostname or "(none)"
        out["ip_provider"] = providers_db.match_hostname(hostname)
    if domain:
        out["domain"] = domain
        out["domain_provider"] = providers_db.match_domain(domain)
    chain_hits = providers_db.match_text("\n".join(summary.get("received_chain", [])))
    if chain_hits:
        out["received_chain_providers"] = chain_hits

    detected = out.get("ip_provider") or out.get("domain_provider") or (chain_hits[0] if chain_hits else None)
    if detected:
        out["detected"] = detected
        out["never_ip_block"] = True
        out["analysis_note"] = (
            f"Message rode {detected['name']} infrastructure. If the claimed brand/sender does "
            "not plausibly use this provider, treat as a masqueraded attack via shared "
            "infrastructure — classify by content, weigh spam-ward, do NOT IP-block."
        )
    else:
        out["detected"] = None
        out["analysis_note"] = "No shared mail provider detected; sender appears to use its own infrastructure."
    return out


async def execute(
    name: str,
    arguments: dict[str, Any],
    cfg: dict[str, Any],
    box: SecretsBox,
    summary: dict[str, Any],
) -> dict[str, Any]:
    if not cfg["tools"].get(name, {}).get("enabled"):
        return {"error": f"tool {name!r} is disabled by the administrator"}

    if name == "ip_lookup":
        return await netinfo.ip_lookup(arguments, cfg)
    if name == "ip_ownership":
        return await netinfo.ip_ownership(arguments, cfg)
    if name == "domain_age":
        return await netinfo.domain_age(arguments, cfg)
    if name == "dns_verify":
        return await netinfo.dns_verify(arguments, cfg)
    if name == "web_search":
        return await webtools.web_search(arguments, cfg, box)
    if name == "web_fetch":
        return await webtools.web_fetch(arguments, cfg, summary)
    if name == "shared_provider_check":
        return await _shared_provider_check(arguments, summary)
    if name == "unifi_block":
        return await unifi.unifi_block(arguments, cfg, box)
    return {"error": f"unknown tool {name!r}"}
