"""Safe rendering of an untrusted quarantined message for the admin preview.

`body._ImageBreaker` only neutralizes remote <img>/background attributes -- it
leaves scripts, styles, event handlers and other active content intact, so it is
not safe for actually *rendering* attacker-controlled HTML in the admin origin.

This module is an allowlist sanitizer (stdlib html.parser only -- no new
dependency): unknown/dangerous tags are dropped, script/style/link/etc. are
dropped with their contents, every on* handler is removed, and any remote
resource reference (http/https <img src>, srcset, background, CSS url(...)) is
stripped so previewing a message cannot phone home or load a tracking pixel.

Defense in depth: the preview route also serves this inside a
`<iframe sandbox>` (no allow-scripts) with a `default-src 'none'` CSP, so even a
sanitizer miss cannot execute script or fetch a remote URL.
"""
from __future__ import annotations

import email
import email.policy
import html as html_mod
import re
from html.parser import HTMLParser

# 1x1 fully transparent GIF -- what a blocked remote image / tracking pixel
# collapses to.
_BLOCKED_IMG = (
    "data:image/gif;base64,"
    "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"
)

_REMOTE_URL_RE = re.compile(r"^\s*(?:https?:)?//", re.IGNORECASE)
_DANGEROUS_SCHEME_RE = re.compile(r"^\s*(?:javascript|vbscript|data:text/html|file):", re.IGNORECASE)
_DATA_IMAGE_RE = re.compile(r"^\s*data:image/(?:png|gif|jpeg|jpg|webp|bmp|svg\+xml);", re.IGNORECASE)
_HAS_REMOTE_IMG_RE = re.compile(
    r"""(?:<img\b[^>]*\bsrc\s*=\s*["']?\s*(?:https?:)?//)"""
    r"""|(?:\bbackground\s*=\s*["']?\s*(?:https?:)?//)""",
    re.IGNORECASE,
)

# Dropped together with everything they contain.
_DROP_TREE = {
    "script", "style", "head", "title", "noscript", "template", "iframe",
    "frame", "frameset", "object", "embed", "applet", "form", "svg", "math",
    "canvas", "audio", "video", "map", "area",
}
# Dropped (void / no end tag) -- emit nothing, keep parsing siblings.
_DROP_VOID = {"link", "meta", "base", "param", "source", "track"}

# Everything we're willing to emit. Anything else: tag dropped, text kept.
_ALLOWED_TAGS = {
    "a", "abbr", "acronym", "address", "article", "aside", "b", "big",
    "blockquote", "br", "caption", "center", "cite", "code", "col", "colgroup",
    "dd", "del", "dfn", "div", "dl", "dt", "em", "fieldset", "figcaption",
    "figure", "font", "footer", "h1", "h2", "h3", "h4", "h5", "h6", "header",
    "hr", "i", "img", "ins", "kbd", "label", "legend", "li", "main", "mark",
    "nav", "ol", "p", "pre", "q", "s", "samp", "section", "small", "span",
    "strike", "strong", "sub", "sup", "table", "tbody", "td", "tfoot", "th",
    "thead", "time", "tr", "tt", "u", "ul", "var", "wbr",
}
_VOID_TAGS = {"br", "hr", "img", "col", "wbr"}

# Per-tag attribute allowlist (plus the globals below). Values are still
# scheme-checked for url-bearing names.
_ATTRS: dict[str, set[str]] = {
    "a": {"href", "name", "target", "title"},
    "img": {"src", "alt", "width", "height", "title"},
    "font": {"color", "face", "size"},
    "td": {"colspan", "rowspan", "align", "valign", "width", "height", "nowrap", "bgcolor"},
    "th": {"colspan", "rowspan", "align", "valign", "width", "height", "nowrap", "bgcolor"},
    "table": {"border", "cellpadding", "cellspacing", "width", "align", "bgcolor", "summary"},
    "col": {"span", "width", "align"},
    "colgroup": {"span", "width", "align"},
    "tr": {"align", "valign", "bgcolor"},
    "tbody": {"align", "valign"},
    "thead": {"align", "valign"},
    "tfoot": {"align", "valign"},
    "ol": {"start", "type"},
}
_GLOBAL_ATTRS = {"dir", "lang", "title", "align", "class", "id", "colspan", "rowspan"}
_URL_ATTRS = {"href", "src", "cite", "action", "background", "longdesc"}
# Never emitted, whatever the tag.
_DROP_ATTRS = {"style", "srcset", "background", "ping", "formaction", "dynsrc",
               "lowsrc", "data", "usemap", "sizes"}

_STYLE_BAD_RE = re.compile(r"url\s*\(|expression\s*\(|@import|javascript:|/\*", re.IGNORECASE)


def _clean_style(value: str) -> str:
    """Keep inert declarations (colours, spacing, fonts); drop any that could
    fetch a remote resource or run script."""
    keep = [d.strip() for d in value.split(";") if d.strip() and not _STYLE_BAD_RE.search(d)]
    return "; ".join(keep)


class _Sanitizer(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self._out: list[str] = []
        self._skip: list[str] = []  # stack of open _DROP_TREE tags

    # -- helpers -----------------------------------------------------------
    def _emit(self, s: str) -> None:
        if not self._skip:
            self._out.append(s)

    def _clean_attrs(self, tag: str, attrs: list[tuple[str, str | None]]) -> str:
        allowed = _ATTRS.get(tag, set()) | _GLOBAL_ATTRS
        parts: list[str] = []
        for name, value in attrs:
            lname = name.lower()
            if lname.startswith("on") or lname in _DROP_ATTRS:
                if lname == "style" and value:
                    cleaned = _clean_style(value)
                    if cleaned:
                        parts.append(f' style="{html_mod.escape(cleaned, quote=True)}"')
                continue
            if lname not in allowed:
                continue
            if value is None:
                parts.append(f" {lname}")
                continue
            if lname in _URL_ATTRS:
                value = self._clean_url(tag, lname, value)
                if value is None:
                    continue
            parts.append(f' {lname}="{html_mod.escape(value, quote=True)}"')
        return "".join(parts)

    @staticmethod
    def _clean_url(tag: str, attr: str, value: str) -> str | None:
        v = value.strip()
        if _DANGEROUS_SCHEME_RE.match(v):
            return None
        if tag == "img" and attr == "src":
            if _DATA_IMAGE_RE.match(v):
                return v
            # remote image, cid: part we don't load, or anything else -> blocked
            return _BLOCKED_IMG
        if v.lower().startswith("cid:"):
            return None
        if _REMOTE_URL_RE.match(v) and attr not in ("href",):
            return None  # remote non-link resource reference
        return v

    # -- parser callbacks -----------------------------------------------------
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag in _DROP_TREE:
            self._skip.append(tag)
            return
        if tag in _DROP_VOID or self._skip:
            return
        if tag not in _ALLOWED_TAGS:
            return  # drop the tag, keep its text content
        slash = " /" if tag in _VOID_TAGS else ""
        self._emit(f"<{tag}{self._clean_attrs(tag, attrs)}{slash}>")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag in _DROP_TREE or tag in _DROP_VOID or self._skip:
            return
        if tag not in _ALLOWED_TAGS:
            return
        self._emit(f"<{tag}{self._clean_attrs(tag, attrs)} />")

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if self._skip:
            if tag == self._skip[-1]:
                self._skip.pop()
            return
        if tag in _ALLOWED_TAGS and tag not in _VOID_TAGS:
            self._emit(f"</{tag}>")

    def handle_data(self, data: str) -> None:
        self._emit(html_mod.escape(data, quote=False))

    def handle_entityref(self, name: str) -> None:
        self._emit(f"&{name};")

    def handle_charref(self, name: str) -> None:
        self._emit(f"&#{name};")

    # comments (incl. IE conditional comments) and declarations: dropped.
    def handle_comment(self, data: str) -> None:  # noqa: D401
        pass

    def handle_decl(self, decl: str) -> None:
        pass

    def result(self) -> str:
        return "".join(self._out)


def sanitize_email_html(markup: str) -> str:
    """Allowlist-sanitize a message's HTML body. Fails closed: on any parser
    error the whole thing is returned as escaped preformatted text."""
    try:
        p = _Sanitizer()
        p.feed(markup)
        p.close()
        return p.result()
    except Exception:  # noqa: BLE001 -- unparsable/hostile: show it as inert text
        return f'<pre class="qtn-text">{html_mod.escape(markup)}</pre>'


def _first_parts(msg: email.message.Message) -> tuple[str | None, str | None]:
    text_part: str | None = None
    html_part: str | None = None
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
        except Exception:  # noqa: BLE001
            continue
        if not isinstance(content, str):
            continue
        if ctype == "text/plain" and text_part is None:
            text_part = content
        elif ctype == "text/html" and html_part is None:
            html_part = content
    return text_part, html_part


def sanitize_email(raw: bytes) -> dict[str, object]:
    """Parse a raw .eml and return safe-to-render pieces for the preview page:
    {subject, from, to, date, html, had_remote_images, text_only}."""
    try:
        msg = email.message_from_bytes(raw, policy=email.policy.default)
    except Exception:  # noqa: BLE001
        return {
            "subject": "(unparseable message)", "from": "", "to": "", "date": "",
            "html": f'<pre class="qtn-text">{html_mod.escape(raw.decode("utf-8", "replace"))}</pre>',
            "had_remote_images": False, "text_only": True,
        }

    text_part, html_part = _first_parts(msg)
    if html_part is not None:
        had_remote = bool(_HAS_REMOTE_IMG_RE.search(html_part))
        body_html = sanitize_email_html(html_part)
        text_only = False
    elif text_part is not None:
        had_remote = False
        body_html = f'<pre class="qtn-text">{html_mod.escape(text_part)}</pre>'
        text_only = True
    else:
        had_remote = False
        body_html = ('<p class="qtn-note">This message has no text/plain or '
                     'text/html part (attachments/binary only).</p>')
        text_only = True

    return {
        "subject": str(msg.get("Subject", "")),
        "from": str(msg.get("From", "")),
        "to": str(msg.get("To", "")),
        "date": str(msg.get("Date", "")),
        "html": body_html,
        "had_remote_images": had_remote,
        "text_only": text_only,
    }


def preview_document(raw: bytes) -> str:
    """A complete standalone HTML document for the sandboxed preview iframe."""
    p = sanitize_email(raw)
    esc = lambda s: html_mod.escape(str(s), quote=True)  # noqa: E731
    note = ""
    if p["had_remote_images"]:
        note = ('<p class="qtn-note">Remote images and tracking pixels have been '
                'blocked in this preview.</p>')
    return f"""<!doctype html>
<html><head><meta charset="utf-8">
<style>
  body {{ font: 14px/1.5 -apple-system, Segoe UI, Roboto, Arial, sans-serif;
         margin: 0; padding: 16px; color: #111; background: #fff; }}
  .qtn-hdr {{ border-bottom: 1px solid #ddd; margin-bottom: 12px; padding-bottom: 8px;
             font-size: 13px; color: #333; }}
  .qtn-hdr b {{ display: inline-block; min-width: 64px; color: #666; font-weight: 600; }}
  .qtn-note {{ background: #fff8e1; border: 1px solid #ffe082; color: #7b5e00;
             padding: 6px 10px; border-radius: 4px; font-size: 12px; margin: 8px 0; }}
  .qtn-text {{ white-space: pre-wrap; word-break: break-word; font: inherit; }}
  img {{ max-width: 100%; height: auto; }}
  table {{ max-width: 100%; }}
</style></head>
<body>
  <div class="qtn-hdr">
    <div><b>From</b> {esc(p['from'])}</div>
    <div><b>To</b> {esc(p['to'])}</div>
    <div><b>Date</b> {esc(p['date'])}</div>
    <div><b>Subject</b> {esc(p['subject'])}</div>
  </div>
  {note}
  {p['html']}
</body></html>"""
