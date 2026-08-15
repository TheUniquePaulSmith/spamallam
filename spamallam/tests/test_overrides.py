from app.pipeline import overrides as ovr

OVERRIDES = {
    "whitelist_domains": ["github.com"],
    "whitelist_recipients": ["press@test.example"],
    "blocklist_domains": ["bad.example"],
}


def test_whitelist_domain_matches_subdomain_and_display_name():
    hit = ovr.check_whitelist(OVERRIDES, "bounce@mailer.github.com", "", ["u@test.example"])
    assert hit == "domain:github.com"
    hit = ovr.check_whitelist(
        OVERRIDES, "other@x.example", '"GitHub" <noreply@github.com>', ["u@test.example"]
    )
    assert hit == "domain:github.com"


def test_whitelist_recipient_plus_addressing():
    hit = ovr.check_whitelist(OVERRIDES, "a@b.c", "", ["press+campaign@test.example"])
    assert hit == "recipient:press@test.example"


def test_no_lookalike_match():
    assert ovr.check_whitelist(OVERRIDES, "a@notgithub.com", "", ["u@test.example"]) is None
    assert ovr.check_whitelist(OVERRIDES, "a@github.com.evil.tld", "", ["u@test.example"]) is None


def test_blocklist():
    assert ovr.check_blocklist(OVERRIDES, "x@bad.example", "") == "domain:bad.example"
    assert ovr.check_blocklist(OVERRIDES, "x@good.example", "") is None
