import email
import email.policy

from app.pipeline import body
from app.pipeline.headers import SpamallamVerdict
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


def _cfg(**marking_overrides):
    marking = {**DEFAULTS["marking"], **marking_overrides}
    return {"marking": marking, "classification": {**DEFAULTS["classification"], "enabled": True,
                                                     "placement": "footer"}}


class _NullTrace:
    def event(self, *a, **k):
        pass


def test_default_footer_template_renders_tags():
    verdict = SpamallamVerdict(verdict="HAM", labels=["newsletter"])
    out = body.rewrite(RAW_HTML, verdict, _cfg(), _NullTrace())
    html = _html_body(out)
    assert "[[spamallam:newsletter]]" in html
    assert "SpamAllam:" in html


def test_custom_footer_template_used():
    verdict = SpamallamVerdict(verdict="HAM", labels=["marketing"])
    cfg = _cfg(footer_template='<div class="custom">{tags}</div>')
    out = body.rewrite(RAW_HTML, verdict, cfg, _NullTrace())
    html = _html_body(out)
    assert '<div class="custom">[[spamallam:marketing]]</div>' in html


def test_no_labels_skips_footer():
    verdict = SpamallamVerdict(verdict="HAM", labels=[])
    out = body.rewrite(RAW_HTML, verdict, _cfg(), _NullTrace())
    assert out == RAW_HTML
