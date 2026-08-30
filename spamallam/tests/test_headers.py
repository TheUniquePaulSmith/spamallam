import hashlib
import hmac as hmac_mod

from app.pipeline import headers as hdr

RAW = (
    b"From: alice@example.com\r\n"
    b"X-Spam-Flag: YES\r\n"
    b"X-SpamAllam-Verdict: HAM\r\n"
    b"X-SpamAllam-Signature: v=1; ts=1; sig=deadbeef\r\n"
    b"Subject: hello\r\n"
    b"X-Spamd-Result: default: False\r\n"
    b"\tcontinuation line\r\n"
    b"\r\n"
    b"body stays byte-exact \xff\xfe\r\n"
)


def test_strip_removes_spoofed_headers_and_preserves_body():
    cleaned, removed = hdr.strip_spam_headers(RAW)
    assert len(removed) == 5  # 4 headers + 1 continuation
    assert b"X-SpamAllam" not in cleaned
    assert b"X-Spam-Flag" not in cleaned
    assert b"X-Spamd-Result" not in cleaned
    assert b"From: alice@example.com" in cleaned
    assert b"Subject: hello" in cleaned
    assert cleaned.endswith(b"\r\n\r\nbody stays byte-exact \xff\xfe\r\n")


def test_strip_noop_when_clean():
    raw = b"From: a@b.c\r\nSubject: x\r\n\r\nbody\r\n"
    cleaned, removed = hdr.strip_spam_headers(raw)
    assert cleaned == raw
    assert removed == []


def test_strip_catches_headers_smuggled_via_mixed_line_endings():
    """A bare LF inside an otherwise-CRLF header block must not hide a header.

    Splitting the block on one separator leaves the smuggled line embedded in
    its predecessor, where the ^-anchored strip pattern never sees it -- and
    everything downstream (rspamd's Lua plugin, MailPlus rules) trusts that
    inbound X-SpamAllam-* headers cannot survive this function.
    """
    raw = (
        b"From: alice@example.com\r\n"
        b"Subject: hello\n"
        b"X-SpamAllam-Whitelisted: yes; rule=domain:evil.example\r\n"
        b"X-SpamAllam-Signature: v=1; ts=1; sig=deadbeef\r\n"
        b"To: bob@example.com\r\n"
        b"\r\n"
        b"body\r\n"
    )
    cleaned, removed = hdr.strip_spam_headers(raw)
    assert b"X-SpamAllam" not in cleaned
    assert len(removed) == 2
    assert b"From: alice@example.com" in cleaned
    assert b"Subject: hello" in cleaned
    assert b"To: bob@example.com" in cleaned
    assert cleaned.endswith(b"\r\n\r\nbody\r\n")


def test_strip_is_byte_exact_for_clean_mixed_ending_messages():
    """DKIM signatures cover these bytes: a message with nothing to strip must
    come back unchanged even when its line endings are inconsistent."""
    for raw in (
        b"From: a@b.c\nSubject: x\n\nbody\n",
        b"From: a@b.c\r\nSubject: x\nTo: d@e.f\r\n\r\nbody\r\n",
    ):
        cleaned, removed = hdr.strip_spam_headers(raw)
        assert cleaned == raw
        assert removed == []


def test_strip_handles_first_and_last_header_removal():
    raw = b"X-Spam-Flag: YES\r\nFrom: a@b.c\r\nX-Spamd-Result: junk\r\n\r\nbody\r\n"
    cleaned, removed = hdr.strip_spam_headers(raw)
    assert cleaned == b"From: a@b.c\r\n\r\nbody\r\n"
    assert len(removed) == 2


def test_signature_matches_reference_hmac():
    verdict = hdr.SpamallamVerdict(
        verdict="phishing", confidence=0.97, category="credential phishing",
        whitelisted="",
    )
    key = b"k"
    signed = hdr.sign(verdict, key, ts=1723750000)
    assert signed.startswith("v=1; ts=1723750000; sig=")
    sig = signed.split("sig=")[1]
    # canonical string contract shared with rspamd/lua/rspamd.local.lua
    canonical = b"v1\n1723750000\nPHISHING\n0.97\ncredential phishing\n"
    expected = hmac_mod.new(key, canonical, hashlib.sha256).hexdigest()
    assert sig == expected


def test_prepend_headers_keeps_crlf_style():
    raw = b"From: a@b.c\r\n\r\nbody\r\n"
    out = hdr.prepend_headers(raw, [("X-SpamAllam-Verdict", "HAM")])
    assert out.startswith(b"X-SpamAllam-Verdict: HAM\r\nFrom: a@b.c")
    assert out.endswith(b"\r\n\r\nbody\r\n")


def test_build_headers_folds_and_clamps():
    verdict = hdr.SpamallamVerdict(verdict="SPAM", confidence=7.5,
                                   category="a\r\ninjected", reason="r")
    built = dict(hdr.build_spamallam_headers(verdict, b"k"))
    assert built["X-SpamAllam-Confidence"] == "1.00"
    assert "\n" not in built["X-SpamAllam-Category"]
