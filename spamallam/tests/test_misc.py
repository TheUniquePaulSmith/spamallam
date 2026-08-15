from app.ai.engine import parse_verdict
from app.ai.summarize import summarize
from app.tools import providers_db
from app.tools.unifi import rollup
from app.tools.webtools import forbidden_reason

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


def test_default_system_prompt_covers_core_doctrine():
    from app.ai.prompt import DEFAULT_SYSTEM_PROMPT as p

    # verdicts + output contract
    for token in ("HAM", "SPAM", "PHISHING", "MALICIOUS", '"verdict"', '"confidence"'):
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
