"""Network-evidence tools: ip_lookup (GeoIP + rDNS + RIR registry), domain_age
(RDAP), dns_verify (MX/SPF/DMARC + brand alignment), ip_ownership (RIR
correlation of arbitrary IPs/hostnames)."""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

import httpx

from . import providers_db

# ---------------------------------------------------------------------------
# Regional Internet Registry (RIR) lookups via RDAP
# rdap.org redirects each IP to its authoritative registry, which tells us WHO
# owns/operates the address space (org, registration country, netblock).
# ---------------------------------------------------------------------------

_RIR_BY_HOST = {
    "arin.net": "ARIN (North America)",
    "ripe.net": "RIPE NCC (Europe / Middle East / Central Asia)",
    "apnic.net": "APNIC (Asia-Pacific)",
    "lacnic.net": "LACNIC (Latin America / Caribbean)",
    "afrinic.net": "AFRINIC (Africa)",
}


def _rir_from_host(host: str) -> str:
    for suffix, name in _RIR_BY_HOST.items():
        if host == suffix or host.endswith("." + suffix):
            return name
    return host or "unknown"


def _vcard_fn(entity: dict[str, Any]) -> str:
    try:
        for entry in entity.get("vcardArray", [None, []])[1]:
            if entry[0] == "fn":
                return str(entry[3])
    except (IndexError, TypeError):
        pass
    return ""


def parse_rdap_ip(data: dict[str, Any], final_host: str) -> dict[str, Any]:
    """Reduce an RDAP IP-network response to the ownership facts the model needs."""
    org = ""
    for entity in data.get("entities", []) or []:
        roles = entity.get("roles") or []
        if "registrant" in roles or "owner" in roles:
            org = _vcard_fn(entity)
            if org:
                break
    if not org:  # some RIRs only attach admin/tech contacts
        for entity in data.get("entities", []) or []:
            org = _vcard_fn(entity)
            if org:
                break

    cidrs = [
        f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}"
        for c in (data.get("cidr0_cidrs") or [])
        if c.get("length") is not None
    ]
    out: dict[str, Any] = {
        "rir": _rir_from_host(final_host),
        "network_name": data.get("name", ""),
        "handle": data.get("handle", ""),
        "registration_country": data.get("country", "") or "unknown",
        "organization": org or "unknown",
    }
    if cidrs:
        out["netblock"] = cidrs
    elif data.get("startAddress"):
        out["netblock"] = [f"{data.get('startAddress')} - {data.get('endAddress')}"]
    return out


async def _rdap_ip(client: httpx.AsyncClient, ip: str) -> dict[str, Any]:
    last_exc: Exception | None = None
    for attempt in range(2):  # rdap.org bootstrap redirects occasionally flake
        try:
            resp = await client.get(f"https://rdap.org/ip/{ip}")
            resp.raise_for_status()
            return parse_rdap_ip(resp.json(), urlsplit(str(resp.url)).hostname or "")
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            if attempt == 0:
                await asyncio.sleep(1)
    return {"error": f"RDAP registry lookup failed: {type(last_exc).__name__}: {last_exc}"}

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
        out["geoip"] = f"GeoIP lookup failed: {type(exc).__name__}: {exc}"

    async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
        out["registry"] = await _rdap_ip(client, ip)

    shared = providers_db.match_hostname(hostname)
    if shared:
        out["shared_mail_provider"] = shared
    return out


# ---------------------------------------------------------------------------
# ip_ownership — RIR correlation for arbitrary IPs / hostnames
# ---------------------------------------------------------------------------


async def _resolve_ips(hostname: str, limit: int) -> list[str]:
    import dns.asyncresolver

    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 10
    ips: list[str] = []
    for rtype in ("A", "AAAA"):
        try:
            answers = await resolver.resolve(hostname, rtype)
            ips.extend(str(r) for r in answers)
        except Exception:  # noqa: BLE001
            continue
    # de-duplicate, preserve order
    seen: set[str] = set()
    return [ip for ip in ips if not (ip in seen or seen.add(ip))][:limit]


async def ip_ownership(args: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
    """Who owns/operates an IP (or every IP a hostname resolves to), per the
    Regional Internet Registries. DNS + RDAP only — never contacts the target,
    so it is safe to use on hostnames taken from message links or images."""
    target = str(args.get("target", "")).strip().lower().rstrip(".")
    if not target or "/" in target or " " in target:
        return {"error": f"invalid target {target!r} (expect an IP address or hostname)"}

    max_ips = int(cfg["tools"].get("ip_ownership", {}).get("max_ips", 4))
    out: dict[str, Any] = {"target": target}

    try:
        ipaddress.ip_address(target)
        ips = [target]
    except ValueError:
        ips = await _resolve_ips(target, max_ips)
        out["resolved_ips"] = ips
        if not ips:
            out["note"] = "hostname did not resolve — dead or DNS-blocked infrastructure"
            return out

    ownership: list[dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
        for ip in ips:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback:
                ownership.append({"ip": ip, "note": "private/loopback — not internet-routable"})
                continue
            entry = {"ip": ip, **await _rdap_ip(client, ip)}
            hostname = await asyncio.get_running_loop().run_in_executor(None, _rdns, ip)
            if hostname:
                entry["reverse_dns"] = hostname
                shared = providers_db.match_hostname(hostname)
                if shared:
                    entry["shared_mail_provider"] = shared
            ownership.append(entry)

    out["ownership"] = ownership
    countries = {e.get("registration_country") for e in ownership
                 if e.get("registration_country") not in (None, "", "unknown")}
    if countries:
        out["registration_countries"] = sorted(countries)
    out["analysis_note"] = (
        "Compare WHO operates each piece of infrastructure: sending IP vs sender domain "
        "vs link/image hosts. A trusted carrier (e.g. SendGrid) delivering content hosted "
        "in an unrelated or high-risk registry/org is a masquerade indicator."
    )
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
        return {"domain": domain, "error": f"RDAP lookup failed: {type(exc).__name__}: {exc}"}

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
