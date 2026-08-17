"""MIME-aware body rewriting: SPAM warning banner, plaintext->HTML conversion,
remote-image breaking, and a classification footer.

This is deliberately the one place in the pipeline that parses and
reserializes a message -- headers.py works on raw bytes precisely to avoid
that (re-folding/re-encoding risk). It only runs when marking/classification
settings actually require it for this verdict, and it fails open: any error
here (malformed MIME, unexpected structure, anything) falls back to
delivering the original, untouched raw bytes. A cosmetic feature must never
be able to block or corrupt mail delivery.
"""
from __future__ import annotations

import email
import email.policy
import html as html_mod
import re
from html.parser import HTMLParser
from typing import Any

from .headers import SpamallamVerdict

# S/MIME and PGP/MIME: touching the body would corrupt the signature/ciphertext.
_SKIP_CONTENT_TYPES = {"multipart/signed", "multipart/encrypted"}

_REMOTE_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_BODY_OPEN_RE = re.compile(r"(?i)<body[^>]*>")
_BODY_CLOSE_RE = re.compile(r"(?i)</body>")


class _ImageBreaker(HTMLParser):
    """Rewrites remote (http/https) <img src=...> and legacy background=...
    attributes to an inert placeholder. Leaves cid:/data: URIs untouched --
    those are embedded content, not remote fetches, so they aren't trackers.
    CSS background-image: url(...) is intentionally out of scope (rare as a
    tracking vector; rewriting arbitrary CSS safely needs a real CSS parser).
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self._out: list[str] = []

    def _rewrite_attrs(self, tag: str, attrs: list[tuple[str, str | None]]) -> list[tuple[str, str | None]]:
        out = []
        for name, value in attrs:
            lname = name.lower()
            if value is not None and _REMOTE_URL_RE.match(value) and (
                (tag.lower() == "img" and lname == "src") or lname == "background"
            ):
                value = "about:blank"
            out.append((name, value))
        return out

    @staticmethod
    def _attr_str(attrs: list[tuple[str, str | None]]) -> str:
        parts = []
        for name, value in attrs:
            if value is None:
                parts.append(f" {name}")
            else:
                parts.append(f' {name}="{html_mod.escape(value, quote=True)}"')
        return "".join(parts)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._out.append(f"<{tag}{self._attr_str(self._rewrite_attrs(tag, attrs))}>")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._out.append(f"<{tag}{self._attr_str(self._rewrite_attrs(tag, attrs))} />")

    def handle_endtag(self, tag: str) -> None:
        self._out.append(f"</{tag}>")

    def handle_data(self, data: str) -> None:
        self._out.append(data)

    def handle_comment(self, data: str) -> None:
        self._out.append(f"<!--{data}-->")

    def handle_decl(self, decl: str) -> None:
        self._out.append(f"<!{decl}>")

    def handle_entityref(self, name: str) -> None:
        self._out.append(f"&{name};")

    def handle_charref(self, name: str) -> None:
        self._out.append(f"&#{name};")

    def result(self) -> str:
        return "".join(self._out)


def _break_images(markup: str) -> str:
    parser = _ImageBreaker()
    try:
        parser.feed(markup)
        parser.close()
        return parser.result()
    except Exception:  # noqa: BLE001 -- malformed HTML: leave it as-is rather than mangling it
        return markup


def _insert_after_body_open(markup: str, snippet: str) -> str:
    match = _BODY_OPEN_RE.search(markup)
    if match:
        return markup[:match.end()] + snippet + markup[match.end():]
    return snippet + markup


def _insert_before_body_close(markup: str, snippet: str) -> str:
    match = _BODY_CLOSE_RE.search(markup)
    if match:
        return markup[:match.start()] + snippet + markup[match.start():]
    return markup + snippet


def _render_banner(template: str, verdict: SpamallamVerdict) -> str:
    return template.format(
        verdict=verdict.verdict,
        confidence=f"{verdict.confidence:.0%}",
        category=html_mod.escape(verdict.category or "-"),
        reason=html_mod.escape(verdict.reason or "-"),
        model=html_mod.escape(verdict.model or "-"),
    )


def _plaintext_banner(verdict: SpamallamVerdict) -> str:
    return (
        f"=== SpamAllam flagged this message as {verdict.verdict} ===\n"
        f"Category: {verdict.category or '-'}\n"
        f"Confidence: {verdict.confidence:.0%}\n"
        f"Reason: {verdict.reason or '-'}\n"
        + "=" * 40 + "\n\n"
    )


def label_tag(label_key: str) -> str:
    """The exact literal string a mail client's keyword/content filter should
    match on for a given label (e.g. Synology MailPlus's rule builder only
    offers From/To/Subject/Keyword/Size -- no header matching -- so this
    bracketed, low-collision tag in the body is the actual integration point,
    not the X-SpamAllam-Labels header)."""
    return f"[[spamallam:{label_key}]]"


def _classification_footer_html(labels: list[str], template: str) -> str:
    tags = " ".join(label_tag(l) for l in labels)
    return template.format(tags=html_mod.escape(tags))


def _classification_footer_text(labels: list[str]) -> str:
    tags = " ".join(label_tag(l) for l in labels)
    return f"\n\n-- \nSpamAllam: {tags}"


def _wants_marking(verdict: SpamallamVerdict, marking_cfg: dict[str, Any]) -> bool:
    if not marking_cfg.get("enabled"):
        return False
    triggers = {v.upper() for v in marking_cfg.get("trigger_verdicts", [])}
    return verdict.verdict.upper() in triggers


def _wants_images_broken(verdict: SpamallamVerdict, marking_cfg: dict[str, Any]) -> bool:
    scope = (marking_cfg.get("break_images") or {}).get("scope", "off")
    if scope == "all_mail":
        return True
    if scope == "spam_only":
        return _wants_marking(verdict, marking_cfg)
    return False


def _wants_classification_footer(classification_cfg: dict[str, Any]) -> bool:
    return bool(classification_cfg.get("enabled")) and classification_cfg.get("placement", "header") in ("footer", "both")


def rewrite(raw: bytes, verdict: SpamallamVerdict, cfg: dict[str, Any], trace: Any) -> bytes:
    """Insert a SPAM warning banner, convert plaintext to HTML when needed,
    break remote images, and append a classification footer -- all
    admin-configurable via cfg["marking"] / cfg["classification"]. Fails
    open: any error, or nothing to do, returns `raw` unchanged."""
    marking_cfg = cfg.get("marking", {})
    classification_cfg = cfg.get("classification", {})

    do_mark = _wants_marking(verdict, marking_cfg)
    do_images = _wants_images_broken(verdict, marking_cfg)
    do_footer = _wants_classification_footer(classification_cfg) and bool(verdict.labels)

    if not (do_mark or do_images or do_footer):
        return raw

    try:
        return _rewrite(raw, verdict, marking_cfg, do_mark, do_images, do_footer)
    except Exception as exc:  # noqa: BLE001 -- cosmetic feature must never break delivery
        trace.event("body_rewrite_error", error=f"{type(exc).__name__}: {exc}")
        return raw


def _rewrite(raw: bytes, verdict: SpamallamVerdict, marking_cfg: dict[str, Any],
             do_mark: bool, do_images: bool, do_footer: bool) -> bytes:
    msg = email.message_from_bytes(raw, policy=email.policy.default)

    if msg.get_content_type() in _SKIP_CONTENT_TYPES:
        return raw

    banner_html = _render_banner(marking_cfg.get("banner_template", ""), verdict) if do_mark else ""
    footer_html = (
        _classification_footer_html(verdict.labels, marking_cfg.get("footer_template", ""))
        if do_footer else ""
    )
    convert_plaintext = bool(marking_cfg.get("convert_plaintext_to_html", True))
    touched = False

    for part in msg.walk():
        if part.is_multipart():
            continue
        if part.get_filename() or part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            content = part.get_content()
        except Exception:  # noqa: BLE001 -- undecodable part, leave it alone
            continue
        if not isinstance(content, str):
            continue

        if ctype == "text/html":
            new_content = content
            if do_mark:
                new_content = _insert_after_body_open(new_content, banner_html)
            if do_images:
                new_content = _break_images(new_content)
            if do_footer:
                new_content = _insert_before_body_close(new_content, footer_html)
            if new_content != content:
                part.set_content(new_content, subtype="html")
                touched = True
        else:  # text/plain
            if do_mark and convert_plaintext:
                new_html = f"<html><body>{banner_html}<pre>{html_mod.escape(content)}</pre>"
                if do_footer:
                    new_html += footer_html
                new_html += "</body></html>"
                part.set_content(new_html, subtype="html")
                touched = True
            else:
                new_content = content
                if do_mark:
                    new_content = _plaintext_banner(verdict) + new_content
                if do_footer:
                    new_content = new_content + _classification_footer_text(verdict.labels)
                if new_content != content:
                    part.set_content(new_content)
                    touched = True

    if not touched:
        return raw
    return msg.as_bytes(policy=email.policy.SMTP)
