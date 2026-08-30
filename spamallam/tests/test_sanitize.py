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
