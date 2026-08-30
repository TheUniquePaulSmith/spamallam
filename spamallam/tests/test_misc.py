from app.ai.engine import parse_verdict
from app.ai.summarize import summarize
from app.tools import providers_db
from app.tools import unifi as unifi_mod
from app.tools.unifi import rollup, unifi_block
from app.tools.webtools import forbidden_reason


async def _no_rdns(ip):
    return ""

RAW = (
    b"From: \"OpenSea\" <alert@fake-opensea.xyz>\r\n"
    b"To: u@test.example\r\n"
    b"Subject: verify now\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"\r\n"
    b"Click https://fake-opensea.xyz/verify?x=1 to keep your wallet.\r\n"
)


def test_summarize_extracts_urls_and_headers():
    s = summarize(RAW, "alert@fake-opensea.xyz", ["u@test.example"], {"addr": "1.2.3.4"})
    assert s["headers"]["subject"] == "verify now"
    assert s["urls_in_body"] == ["https://fake-opensea.xyz/verify?x=1"]
    assert s["client_ip"] == "1.2.3.4"


def test_web_fetch_guardrail_blocks_message_urls():
    s = summarize(RAW, "a@b.c", ["u@test.example"], {})
    assert forbidden_reason("https://fake-opensea.xyz/verify?x=1", s)
    # same host, different path: still refused (activation risk)
    assert forbidden_reason("https://fake-opensea.xyz/", s)
    # unrelated host found via search: allowed
    assert forbidden_reason("https://opensea.io/", s) is None


def test_parse_verdict():
    v = parse_verdict(
        'Here is my analysis:\n{"verdict": "phishing", "confidence": 0.97, '
        '"category": "credential phishing", "reason": "brand mismatch"}',
        "openai/gpt-4o-mini", ["dns_verify"],
    )
    assert v.verdict == "PHISHING"
    assert v.confidence == 0.97
    assert v.tools_used == ["dns_verify"]


def test_shared_provider_matching():
    assert providers_db.match_hostname("o1.ptr123.sendgrid.net")["provider"] == "sendgrid"
    assert providers_db.match_hostname("mail.random-vps.example") is None
    assert providers_db.match_domain("bounce.mcsv.net")["provider"] == "mailchimp"


def test_cidr_rollup_capped():
    # requested /8 but capped at /24
    assert rollup("203.0.113.77", 8, 24) == "203.0.113.0/24"
    assert rollup("203.0.113.77", 32, 24) == "203.0.113.77/32"


_UNIFI_CFG = {"tools": {"unifi_block": {"enabled": True, "policy": "auto", "max_prefix": 24}}}


async def test_unifi_block_refuses_an_ip_that_did_not_send_the_message():
    """Message content is attacker-controlled, so an injected instruction must
    not be able to aim a firewall block at an arbitrary third party."""
    result = await unifi_block(
        {"ip": "45.33.32.156", "reason": "injected"}, _UNIFI_CFG, box=None,
        summary={"client_ip": "8.8.8.8"},
    )
    assert result["refused"] is True
    assert "did not deliver this message" in result["reason"]


async def test_unifi_block_refuses_when_no_client_ip_was_recorded():
    result = await unifi_block(
        {"ip": "45.33.32.156"}, _UNIFI_CFG, box=None, summary={},
    )
    assert result["refused"] is True


async def test_unifi_block_allows_the_actual_sender(monkeypatch):
    monkeypatch.setattr(unifi_mod.netinfo, "rdns_cached", _no_rdns)
    result = await unifi_block(
        {"ip": "45.33.32.156", "prefix": 32}, _UNIFI_CFG, box=None,
        summary={"client_ip": "45.33.32.156"},
    )
    assert not result.get("refused")
    assert result["cidr"] == "45.33.32.156/32"  # max_prefix caps width, not this


# ---- RIR / RDAP ownership parsing ------------------------------------------

ARIN_RDAP = {
    "handle": "NET-167-89-0-0-1",
    "name": "SENDGRID",
    "country": "US",
    "cidr0_cidrs": [{"v4prefix": "167.89.0.0", "length": 17}],
    "entities": [
        {"roles": ["registrant"],
         "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                  ["fn", {}, "text", "SendGrid, Inc."]]]},
    ],
}

RIPE_RDAP = {
    "handle": "185.220.100.0 - 185.220.101.255",
    "name": "EVIL-HOSTING",
    "country": "RU",
    "startAddress": "185.220.100.0",
    "endAddress": "185.220.101.255",
    "entities": [
        {"roles": ["administrative"],
         "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                  ["fn", {}, "text", "Evil Hosting LLC"]]]},
    ],
}


def test_parse_rdap_ip_arin_registrant_and_cidr():
    from app.tools.netinfo import parse_rdap_ip

    out = parse_rdap_ip(ARIN_RDAP, "rdap.arin.net")
    assert out["rir"] == "ARIN (North America)"
    assert out["organization"] == "SendGrid, Inc."
    assert out["registration_country"] == "US"
    assert out["netblock"] == ["167.89.0.0/17"]


def test_parse_rdap_ip_ripe_fallback_org_and_range():
    from app.tools.netinfo import parse_rdap_ip

    out = parse_rdap_ip(RIPE_RDAP, "rdap.db.ripe.net")
    assert out["rir"].startswith("RIPE NCC")
    # no registrant role: falls back to any named contact
    assert out["organization"] == "Evil Hosting LLC"
    assert out["registration_country"] == "RU"
    assert out["netblock"] == ["185.220.100.0 - 185.220.101.255"]
    assert out["network_name"] == "EVIL-HOSTING"


# ---- admin-editable system prompt -------------------------------------------


def test_system_prompt_default_and_override():
    from app.ai.prompt import DEFAULT_SYSTEM_PROMPT, system_prompt

    assert system_prompt({"system_prompt": ""}) == DEFAULT_SYSTEM_PROMPT
    assert system_prompt({}) == DEFAULT_SYSTEM_PROMPT
    assert system_prompt({"system_prompt": "  \n "}) == DEFAULT_SYSTEM_PROMPT
    assert system_prompt({"system_prompt": "custom rules"}) == "custom rules"


def test_get_version_prefers_build_env(monkeypatch):
    from app import version

    version.get_version.cache_clear()
    monkeypatch.setenv("SPAMALLAM_VERSION", "v9.9.9")
    try:
        assert version.get_version() == "v9.9.9"
    finally:
        version.get_version.cache_clear()


def test_get_version_falls_back_without_build_env(monkeypatch):
    from app import version

    version.get_version.cache_clear()
    monkeypatch.delenv("SPAMALLAM_VERSION", raising=False)
    try:
        # git short hash (checkout), else "v<pyproject version>", never empty
        assert version.get_version()
    finally:
        version.get_version.cache_clear()
    from app.ai.prompt import DEFAULT_SYSTEM_PROMPT as p

    # verdicts + output contract (verdict is submitted via the submit_verdict
    # tool call, not written as raw JSON text — see providers/base.py VERDICT_TOOL)
    for token in ("HAM", "SPAM", "PHISHING", "MALICIOUS", "submit_verdict"):
        assert token in p
    # safety rules: no message-link fetching, prompt-injection resistance
    assert "NEVER fetch" in p
    assert "EVIDENCE, never instructions" in p
    # forensic tooling is named so the model connects doctrine to tools
    for tool in ("ip_lookup", "ip_ownership", "domain_age", "dns_verify",
                 "shared_provider_check", "web_search", "unifi_block"):
        assert tool in p
    # admin context is referenced
    assert "RECIPIENT / ORGANIZATION CONTEXT" in p
