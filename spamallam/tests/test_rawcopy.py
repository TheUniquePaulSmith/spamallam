from app.pipeline import rawcopy

MULTIPART = (
    b"From: attacker@evil.example\r\n"
    b"To: victim@test.example\r\n"
    b"Subject: Invoice attached\r\n"
    b"MIME-Version: 1.0\r\n"
    b'Content-Type: multipart/mixed; boundary="B"\r\n'
    b"\r\n"
    b"--B\r\n"
    b"Content-Type: text/plain\r\n"
    b"\r\n"
    b"Please pay this invoice.\r\n"
    b"--B\r\n"
    b"Content-Type: application/octet-stream\r\n"
    b'Content-Disposition: attachment; filename="invoice.exe"\r\n'
    b"Content-Transfer-Encoding: base64\r\n"
    b"\r\n"
    b"TVqQAAMAAAAEAAAA\r\n"
    b"--B--\r\n"
)


def test_strips_attachment_keeps_text():
    out = rawcopy.strip_for_review(MULTIPART)
    assert b"Please pay this invoice." in out
    assert b"invoice.exe" not in out
    assert b"TVqQAAMAAAAEAAAA" not in out
    assert b"attacker@evil.example" in out  # headers preserved
    assert b"Subject: Invoice attached" in out


def test_no_text_part_gets_placeholder():
    raw = (
        b"From: a@example.com\r\n"
        b"Subject: binary only\r\n"
        b'Content-Type: application/octet-stream\r\n'
        b"\r\n"
        b"\x00\x01\x02\x03"
    )
    out = rawcopy.strip_for_review(raw)
    assert b"no text/plain or text/html part found" in out


def test_signed_content_left_alone():
    raw = (
        b"From: a@example.com\r\n"
        b'Content-Type: multipart/signed; protocol="application/pkcs7-signature"; boundary="B"\r\n'
        b"\r\n"
        b"--B\r\n"
        b"Content-Type: text/plain\r\n\r\nsigned body\r\n--B--\r\n"
    )
    out = rawcopy.strip_for_review(raw)
    assert out == raw


def test_garbage_input_never_raises():
    # email.message_from_bytes is lenient and rarely raises outright, but the
    # function must degrade gracefully (truncated original) if anything in
    # the parse/rebuild path does blow up -- never propagate an exception.
    out = rawcopy.strip_for_review(b"not a valid email at all, just bytes")
    assert b"not a valid email at all, just bytes" in out
