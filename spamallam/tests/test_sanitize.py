from app.pipeline import sanitize


def test_strips_active_content():
    html = (
        '<html><head><style>body{background:url(http://x/y)}</style></head>'
        '<body><script>steal()</script>'
        '<p onclick="evil()" onmouseover="x">hi <b>there</b></p>'
        '<a href="javascript:evil()">x</a>'
        '<a href="https://ok.example/read">link</a></body></html>'
    )
    out = sanitize.sanitize_email_html(html)
    assert "<script" not in out
    assert "steal()" not in out
    assert "<style" not in out
    assert "onclick" not in out and "onmouseover" not in out
    assert "javascript:" not in out
    assert "<b>there</b>" in out
    assert 'href="https://ok.example/read"' in out  # links are kept


def test_remote_image_blocked_data_image_kept():
    html = (
        '<img src="http://tracker.example/pixel.gif" width="1" height="1">'
        '<img src="data:image/png;base64,iVBORw0KGgo=">'
    )
    out = sanitize.sanitize_email_html(html)
    assert "tracker.example" not in out
    assert "data:image/gif;base64," in out          # blocked-image placeholder
    assert "data:image/png;base64,iVBORw0KGgo=" in out


def test_malformed_or_unclosed_stays_inert():
    # unclosed <script>: everything after it is suppressed, nothing executable leaks
    out = sanitize.sanitize_email_html("<div><script>=1 still going")
    assert "<script" not in out.lower()
    assert "still going" not in out

    # genuinely broken markup must not raise and must not emit raw tags
    out2 = sanitize.sanitize_email_html("<b><<< <img src=x onerror=alert(1)>")
    assert "onerror" not in out2
    assert "alert(1)" not in out2


def test_sanitize_email_detects_remote_and_wraps_plaintext():
    html_msg = (
        b"Subject: hi\r\nContent-Type: text/html\r\n\r\n"
        b'<body><img src="https://a/b.png"></body>'
    )
    d = sanitize.sanitize_email(html_msg)
    assert d["had_remote_images"] is True
    assert d["text_only"] is False

    text_msg = b"Subject: hi\r\nContent-Type: text/plain\r\n\r\n<not a tag> & stuff\r\n"
    d = sanitize.sanitize_email(text_msg)
    assert d["text_only"] is True
    assert "&lt;not a tag&gt;" in d["html"]

    doc = sanitize.preview_document(html_msg)
    assert doc.startswith("<!doctype html>")
    assert "Remote images and tracking pixels have been blocked" in doc


def test_control_characters_cannot_hide_a_dangerous_scheme():
    """HTMLParser resolves character references before the sanitizer sees the
    value, and browsers strip TAB/CR/LF from URLs -- so "jav&#9;ascript:" would
    run unless those characters are removed before the scheme is checked."""
    for payload in (
        '<a href="jav&#9;ascript:alert(1)">x</a>',
        '<a href="jav&#10;ascript:alert(1)">x</a>',
        '<a href="&#32;javascript:alert(1)">x</a>',
    ):
        out = sanitize.sanitize_email_html(payload)
        assert "javascript" not in out.lower()
        assert "alert(1)" not in out


def test_css_escapes_and_image_set_cannot_fetch_remote_content():
    """A backslash is a CSS ident escape, so "\75 rl(...)" tokenizes as url();
    image-set() fetches remote content with no literal "url(" substring."""
    for payload in (
        r'<p style="background:\75 rl(https://evil/x)">y</p>',
        r'<p style="background:\000075rl(https://evil/x)">y</p>',
        '<p style="background-image:image-set(https://evil/x.png 1x)">y</p>',
        '<p style="background:cross-fade(url(https://evil/x.png))">y</p>',
    ):
        assert "evil" not in sanitize.sanitize_email_html(payload)

    # inert declarations still survive
    assert "color:#333" in sanitize.sanitize_email_html('<p style="color:#333">y</p>')


def test_links_never_get_a_new_browsing_context():
    out = sanitize.sanitize_email_html('<a href="https://ok.example" target="_blank">z</a>')
    assert "target" not in out
    assert 'href="https://ok.example"' in out
