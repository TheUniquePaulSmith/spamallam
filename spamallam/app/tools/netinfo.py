"""Network-evidence tools: ip_lookup (GeoIP + rDNS), domain_age (RDAP),
dns_verify (MX/SPF/DMARC + brand alignment)."""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from datetime import datetime, timezone
from typing import Any

import httpx

from . import providers_db

# ---------------------------------------------------------------------------
# ip_lookup
# ---------------------------------------------------------------------------


def _rdns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""


async def ip_lookup(args: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
    ip = str(args.get("ip", "")).strip()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"error": f"invalid IP address {ip!r}"}
    if addr.is_private or addr.is_loopback:
        return {"ip": ip, "note": "private/loopback address — internal hop, not the internet sender"}

    loop = asyncio.get_running_loop()
    hostname = await loop.run_in_executor(None, _rdns, ip)

    out: dict[str, Any] = {"ip": ip, "reverse_dns": hostname or "(none)"}

    geo_path = cfg["tools"]["ip_lookup"].get("geoip_db_path") or ""
    if not geo_path:
        from ..config import ENV
        geo_path = ENV.geoip_db_path
    try:
        import maxminddb

        with maxminddb.open_database(geo_path) as db:
            rec = db.get(ip) or {}
        country = (rec.get("country") or {}).get("iso_code", "")
        out["country"] = country or "unknown"
        out["city"] = ((rec.get("city") or {}).get("names") or {}).get("en", "")
        if isinstance(rec.get("autonomous_system_organization"), str):
            out["asn_org"] = rec["autonomous_system_organization"]
        if cfg["tools"]["ip_lookup"].get("non_us_note") and country and country != "US":
            out["note"] = f"origin country {country} is outside the US — weigh spam-ward per policy"
    except FileNotFoundError:
        out["geoip"] = f"GeoIP database not found at {geo_path}; rDNS evidence only"
    except Exception as exc:  # noqa: BLE001
        out["geoip"] = f"GeoIP lookup failed: {exc}"

    shared = providers_db.match_hostname(hostname)
    if shared:
        out["shared_mail_provider"] = shared
    return out


# ---------------------------------------------------------------------------
# domain_age (RDAP — the modern WHOIS)
# ---------------------------------------------------------------------------


async def domain_age(args: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
    domain = str(args.get("domain", "")).strip().lower().rstrip(".")
    if not domain or "/" in domain or " " in domain:
        return {"error": f"invalid domain {domain!r}"}

    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            resp = await client.get(f"https://rdap.org/domain/{domain}")
        if resp.status_code == 404:
            return {"domain": domain, "registered": False,
                    "note": "domain not found in RDAP — possibly unregistered or brand-new"}
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:  # noqa: BLE001
        return {"domain": domain, "error": f"RDAP lookup failed: {exc}"}

    registration = None
    for event in data.get("events", []):
        if event.get("eventAction") == "registration":
            registration = event.get("eventDate")
            break

    out: dict[str, Any] = {
        "domain": domain,
        "registered": True,
        "registration_date": registration or "unknown",
        "registrar": next(
            (e.get("vcardArray", [None, []])[1][1][3]
             for e in data.get("entities", [])
             if "registrar" in (e.get("roles") or []) and e.get("vcardArray")),
            "unknown",
        ),
        "statuses": data.get("status", []),
    }
    if registration:
        try:
            reg_dt = datetime.fromisoformat(registration.replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - reg_dt).days
            out["age_days"] = age_days
            young = int(cfg["tools"]["domain_age"].get("young_domain_days", 90))
            if age_days <= young:
                out["note"] = (f"domain registered only {age_days} days ago "
                               f"(<= {young}) — strong spam/phishing signal")
        except ValueError:
            pass
    return out


# ---------------------------------------------------------------------------
# dns_verify
# ---------------------------------------------------------------------------


async def _txt_records(resolver, name: str) -> list[str]:
    try:
        answers = await resolver.resolve(name, "TXT")
        return ["".join(s.decode() for s in r.strings) for r in answers]
    except Exception:  # noqa: BLE001
        return []


async def dns_verify(args: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
    import dns.asyncresolver

    domain = str(args.get("domain", "")).strip().lower().rstrip(".")
    claimed_brand = str(args.get("claimed_brand_domain", "")).strip().lower().rstrip(".")
    if not domain:
        return {"error": "domain is required"}

    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 10

    out: dict[str, Any] = {"domain": domain}
    try:
        mx = await resolver.resolve(domain, "MX")
        out["mx"] = sorted(str(r.exchange).rstrip(".") for r in mx)
    except Exception as exc:  # noqa: BLE001
        out["mx"] = []
        out["mx_error"] = str(exc)

    txt = await _txt_records(resolver, domain)
    out["spf"] = next((t for t in txt if t.lower().startswith("v=spf1")), "(none)")
    dmarc_txt = await _txt_records(resolver, f"_dmarc.{domain}")
    out["dmarc"] = next((t for t in dmarc_txt if t.lower().startswith("v=dmarc1")), "(none)")

    shared_hits = providers_db.match_text(out["spf"])
    if shared_hits:
        out["spf_shared_providers"] = shared_hits

    if claimed_brand:
        aligned = domain == claimed_brand or domain.endswith("." + claimed_brand)
        out["brand_alignment"] = {
            "claimed_brand_domain": claimed_brand,
            "sender_domain": domain,
            "aligned": aligned,
        }
        if not aligned:
            out["brand_alignment"]["note"] = (
                "sender domain does NOT belong to the claimed brand — "
                "classic impersonation indicator"
            )
    return out
