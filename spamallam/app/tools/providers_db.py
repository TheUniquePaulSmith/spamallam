"""Shared bulk-mail provider knowledge base.

Used two ways:
  1. shared_provider_check tool — tells the model whether the message rode a
     legitimate shared provider (and could be a masqueraded attack).
  2. unifi_block guardrail — IPs belonging to these providers are NEVER
     blockable; blocking SendGrid/SES/Mailchimp egress would break unrelated
     legitimate mail. Domain whitelisting is the correct lever instead.
"""
from __future__ import annotations

from typing import Any

# provider key -> (display name, rDNS suffixes, SPF/domain markers)
SHARED_PROVIDERS: dict[str, dict[str, Any]] = {
    "sendgrid":   {"name": "Twilio SendGrid",
                   "rdns": [".sendgrid.net", ".sendgrid.com"],
                   "domains": ["sendgrid.net", "sendgrid.com"]},
    "amazon_ses": {"name": "Amazon SES",
                   "rdns": [".amazonses.com", ".smtp-out.amazonses.com", ".ses.amazonaws.com"],
                   "domains": ["amazonses.com"]},
    "mailchimp":  {"name": "Mailchimp / Mandrill",
                   "rdns": [".mcsv.net", ".mcdlv.net", ".rsgsv.net", ".mandrillapp.com"],
                   "domains": ["mcsv.net", "mcdlv.net", "rsgsv.net", "mandrillapp.com", "mailchimp.com"]},
    "acs":        {"name": "Azure Communication Services",
                   "rdns": [".azurecomm.net", ".acssend.net"],
                   "domains": ["azurecomm.net", "acssend.net"]},
    "microsoft":  {"name": "Microsoft 365 / Outlook",
                   "rdns": [".outbound.protection.outlook.com", ".outlook.com"],
                   "domains": ["protection.outlook.com", "outlook.com"]},
    "google":     {"name": "Google Workspace / Gmail",
                   "rdns": [".google.com", ".googlemail.com", ".smtp-out.gmail.com"],
                   "domains": ["google.com", "googlemail.com", "gmail.com"]},
    "mailgun":    {"name": "Mailgun",
                   "rdns": [".mailgun.net", ".mailgun.org", ".mailgun.info"],
                   "domains": ["mailgun.org", "mailgun.net", "mailgun.info"]},
    "postmark":   {"name": "Postmark",
                   "rdns": [".mtasv.net"],
                   "domains": ["mtasv.net", "postmarkapp.com"]},
    "sparkpost":  {"name": "SparkPost",
                   "rdns": [".sparkpostmail.com", ".spmta.com"],
                   "domains": ["sparkpostmail.com", "spmta.com"]},
    "brevo":      {"name": "Brevo (Sendinblue)",
                   "rdns": [".sendinblue.com", ".brevosend.com"],
                   "domains": ["sendinblue.com", "brevosend.com"]},
    "zoho":       {"name": "Zoho Mail",
                   "rdns": [".zoho.com", ".zohomail.com"],
                   "domains": ["zoho.com", "zohomail.com"]},
    "proton":     {"name": "Proton Mail",
                   "rdns": [".protonmail.ch"],
                   "domains": ["protonmail.ch", "proton.me"]},
}


def match_hostname(hostname: str) -> dict[str, str] | None:
    """Match an rDNS hostname against known provider suffixes."""
    host = (hostname or "").lower().rstrip(".")
    if not host:
        return None
    for key, info in SHARED_PROVIDERS.items():
        for suffix in info["rdns"]:
            if host.endswith(suffix) or host == suffix.lstrip("."):
                return {"provider": key, "name": info["name"], "matched": suffix}
    return None


def match_domain(domain: str) -> dict[str, str] | None:
    dom = (domain or "").lower().strip(".")
    if not dom:
        return None
    for key, info in SHARED_PROVIDERS.items():
        for candidate in info["domains"]:
            if dom == candidate or dom.endswith("." + candidate):
                return {"provider": key, "name": info["name"], "matched": candidate}
    return None


def match_text(text: str) -> list[dict[str, str]]:
    """Find provider markers anywhere in a blob (Received chain, SPF record...)."""
    hits: list[dict[str, str]] = []
    low = (text or "").lower()
    for key, info in SHARED_PROVIDERS.items():
        for candidate in info["domains"]:
            if candidate in low:
                hits.append({"provider": key, "name": info["name"], "matched": candidate})
                break
    return hits
