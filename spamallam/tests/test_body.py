import email
import email.policy

from app.pipeline import body
from app.pipeline.headers import SpamallamVerdict
from app.pipeline.rspamd_client import RspamdResult
from app.store.settings import DEFAULTS


def _html_body(raw: bytes) -> str:
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    return msg.get_content()

RAW_HTML = (
    b"From: sender@example.com\r\n"
    b"Content-Type: text/html\r\n"
    b"\r\n"
    b"<html><body><p>hi</p></body></html>\r\n"
)

CLEAN_RSPAMD = RspamdResult(ok=True, action="no action", score=0.0, required_score=15.0)


def _cfg(**marking_overrides):
    marking = {**DEFAULTS["marking"], **marking_overrides}
    return {"marking": marking, "classification": {**DEFAULTS["classification"], "enabled": True,
                                                     "placement": "footer"}}


class _NullTrace:
    def event(self, *a, **k):
        pass


def test_default_footer_template_renders_tags():
    verdict = SpamallamVerdict(verdict="HAM", labels=["newsletter"])
    out = body.rewrite(RAW_HTML, verdict, CLEAN_RSPAMD, _cfg(), _NullTrace())
    html = _html_body(out)
    assert "[[spamallam:newsletter]]" in html
    assert "SpamAllam:" in html


def test_custom_footer_template_used():
    verdict = SpamallamVerdict(verdict="HAM", labels=["marketing"])
    cfg = _cfg(footer_template='<div class="custom">{tags}</div>')
    out = body.rewrite(RAW_HTML, verdict, CLEAN_RSPAMD, cfg, _NullTrace())
    html = _html_body(out)
    assert '<div class="custom">[[spamallam:marketing]]</div>' in html


def test_no_labels_skips_footer():
    verdict = SpamallamVerdict(verdict="HAM", labels=[])
    out = body.rewrite(RAW_HTML, verdict, CLEAN_RSPAMD, _cfg(), _NullTrace())
    assert out == RAW_HTML


def test_marking_trigger_on_rspamd_spam():
    verdict = SpamallamVerdict(verdict="HAM")  # AI disagrees / didn't flag it
    spammy_rspamd = RspamdResult(ok=True, action="add header", score=8.0, required_score=15.0)
    cfg = _cfg(enabled=True, trigger_on_rspamd_spam=True)

    out = body.rewrite(RAW_HTML, verdict, spammy_rspamd, cfg, _NullTrace())
    html = _html_body(out)
    assert "SpamAllam flagged this message as SPAM" in html
    assert "rspamd scored this message 8.0/15.0" in html

    cfg_off = _cfg(enabled=True, trigger_on_rspamd_spam=False)
    out_off = body.rewrite(RAW_HTML, verdict, spammy_rspamd, cfg_off, _NullTrace())
    assert out_off == RAW_HTML


def test_marking_trigger_on_rspamd_spam_ignores_hard_reject():
    """Reject-tier mail never reaches body.rewrite() in the real pipeline
    (it's dropped first) -- but if it somehow did, the rspamd-driven trigger
    should still only fire for the spam-ish-not-reject middle tier."""
    verdict = SpamallamVerdict(verdict="HAM")
    rejected = RspamdResult(ok=True, action="reject", score=30.0, required_score=15.0)
    cfg = _cfg(enabled=True, trigger_on_rspamd_spam=True)
    out = body.rewrite(RAW_HTML, verdict, rejected, cfg, _NullTrace())
    assert out == RAW_HTML
