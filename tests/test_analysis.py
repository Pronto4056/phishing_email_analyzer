import json
from email.message import EmailMessage
import pytest
from phishing_analyzer.parser import parse_email, AnalysisError
from phishing_analyzer.report import analyze


def email(body="Hello", *, html=False, headers=""):
    return ("From: Support <support@example.org>\r\nTo: person@example.net\r\n"
            "Subject: Sample\r\n" + headers +
            ("Content-Type: text/html; charset=utf-8" if html else "Content-Type: text/plain; charset=utf-8") +
            "\r\n\r\n" + body).encode()


def report(raw):
    return analyze(raw, "sample.eml")["report"]


def ids(raw):
    return [f["rule_id"] for f in report(raw)["findings"]]


def test_benign_and_export_privacy():
    r = analyze(email("PRIVATE_BODY_MARKER"), "sample.eml")
    assert r["report"]["score"] == 0
    assert r["report"]["rating"] == "Low observed concern"
    assert r["preview"]["text"] == "PRIVATE_BODY_MARKER"
    assert "PRIVATE_BODY_MARKER" not in json.dumps(r["report"])
    assert len(r["report"]["sha256"]) == 64
    assert "safety is not established" in r["report"]["summary"]


def test_reply_to_mismatch_and_duplicate_sender():
    assert ids(email(headers="Reply-To: help@other.example\r\n")) == ["SENDER-01"]
    r = report(email(headers="From: other@evil.example\r\nReply-To: help@other.example\r\n"))
    assert not r["findings"]
    assert r["completeness"] == "partial"
    assert len(r["headers"]["from"]) == 2
    assert r["rating"] is None


@pytest.mark.parametrize("body, expected", [
    ('<a href="https://evil.example">https://example.org</a>', ["LINK-01"]),
    ('<a href="https://evil.example">Click here</a>', []),
    ('<a href="https://example.org@evil.example">https://example.org</a>', ["LINK-01"]),
    ('<a href="https://EXAMPLE.org./a">https://example.org</a>', []),
    ('http://192.0.2.1/a', ["LINK-02"]),
    ('http://[2001:db8::1]:80/a', ["LINK-02"]),
    ('https://xn--bcher-kva.example/a', ["LINK-03"]),
    ('https://bücher.example/a', ["LINK-03"]),
])
def test_links(body, expected):
    assert ids(email(body, html=True)) == expected


def test_repeated_findings_score_once_and_auth_untrusted():
    body = '<a href="https://evil.example">https://example.org</a>' * 3
    raw = email(body, html=True, headers="Reply-To: help@other.example\r\nAuthentication-Results: forged.example; spf=pass; dkim=pass; dmarc=pass\r\n")
    r = report(raw)
    assert r["score"] == 4
    assert r["rating"] == "High observed concern"
    assert len(r["links"]) == 1
    assert len(r["links"][0]["occurrences"]) == 3
    assert r["authentication"][0]["verified"] is False
    assert r == report(raw)


@pytest.mark.parametrize("filename, ctype, expected", [
    ("invoice.pdf.exe", "application/octet-stream", ["ATTACH-01"]),
    ("invoice.pdf", "text/plain", ["ATTACH-02"]),
    ("invoice.pdf", "application/octet-stream", []),
    ("invoice.pdf", "application/pdf", []),
])
def test_attachments(filename, ctype, expected):
    m = EmailMessage(); m["From"] = "person@example.org"; m.set_content("Hello")
    main, sub = ctype.split("/")
    m.add_attachment(b"SYNTHETIC", maintype=main, subtype=sub, filename=filename)
    r = report(m.as_bytes())
    assert [f["rule_id"] for f in r["findings"]] == expected
    assert r["attachments"][0]["size"] == 9


def test_encoded_headers_plain_multipart_and_attached_email():
    m = EmailMessage(); m["From"] = "person@example.org"; m["Subject"] = "Résumé"
    m.set_content("Hello https://example.org")
    m.add_alternative('<p>Hello</p><img src="https://evil.example/pixel"><script>oops</script>', subtype="html")
    child = EmailMessage(); child["From"] = "other@example.org"; child.set_content("http://192.0.2.9")
    m.add_attachment(child)
    p = parse_email(m.as_bytes())
    assert p["headers"]["subject"][0]["value"] == "Résumé"
    assert len(p["links"]) == 1
    assert "oops" not in p["text"]
    assert len(p["attachments"]) == 1


@pytest.mark.parametrize("raw", [b"", b"ordinary text without headers", b"garbage: value\n\nbody"])
def test_invalid_email(raw):
    with pytest.raises(AnalysisError):
        parse_email(raw)


def test_malformed_partial_and_header_only():
    assert report(b"Subject: Only\r\n\r\n")["completeness"] == "complete"
    r = report(b"Subject: Broken\nContent-Type: multipart/mixed; boundary=x\n\nno boundary")
    assert r["completeness"] == "partial"
    assert r["score"] is None


def test_text_link_limits_and_preview():
    r = analyze(email("A" * 20001), "sample.eml")
    assert r["report"]["completeness"] == "complete"
    assert len(r["preview"]["text"]) == 20000
    assert r["preview"]["truncated"]
    assert report(email("A" * (1024 * 1024 + 1)))["score"] is None
    assert report(email(" ".join(f"https://example.org/{i}" for i in range(201))))["score"] is None


def multipart(count):
    m = EmailMessage(); m["From"] = "person@example.org"; m.make_mixed()
    for _ in range(count):
        c = EmailMessage(); c.set_content("hi"); m.attach(c)
    return m.as_bytes()


def test_part_limit():
    assert parse_email(multipart(199))["completeness"] == "complete"
    with pytest.raises(AnalysisError):
        parse_email(multipart(200))


def test_raw_limit():
    prefix = b"Subject: Test\n\n"
    assert parse_email(prefix + b" " * (5 * 1024 * 1024 - len(prefix)))["completeness"] == "partial"
    with pytest.raises(AnalysisError):
        parse_email(prefix + b" " * (5 * 1024 * 1024 + 1 - len(prefix)))


@pytest.mark.parametrize("body,headers,score,rating", [
    ("http://192.0.2.1", "", 1, "Low observed concern"),
    ("http://192.0.2.1", "Reply-To: person@other.example\r\n", 2, "Medium observed concern"),
    ('<a href="https://evil.example">https://example.org</a>', "", 3, "Medium observed concern"),
])
def test_score_boundaries(body, headers, score, rating):
    r = report(email(body, html=True, headers=headers))
    assert (r["score"], r["rating"]) == (score, rating)


def test_duplicate_href_preserves_first_and_marks_partial():
    r = report(email('<a href="https://evil.example" href="https://bank.example">https://bank.example</a>', html=True))
    assert r["links"][0]["host"] == "evil.example"
    assert r["completeness"] == "partial"
    assert r["score"] is None
    assert [f["rule_id"] for f in r["findings"]] == ["LINK-01"]


def test_duplicate_mime_headers_are_partial():
    r = report(b'From: person@example.org\nContent-Type: text/plain\nContent-Type: text/html\n\n<a href="https://evil.example">https://bank.example</a>')
    assert r["completeness"] == "partial"
    assert r["score"] is None
    assert any("duplicate Content-Type" in w for w in r["warnings"])


def test_missing_href_is_usable_partial():
    r = report(email('<a href>Help</a>', html=True))
    assert r["completeness"] == "partial"
    assert not r["links"]


def test_defective_address_not_scored():
    r = report(b'From: <sender@example.org\nReply-To: other@elsewhere.example\n\nhello')
    assert not r["findings"]
    assert r["score"] is None


def nested(levels):
    inner = EmailMessage(); inner["From"] = "person@example.org"; inner.set_content("hello")
    for _ in range(levels-1):
        parent = EmailMessage(); parent["From"] = "person@example.org"; parent.make_mixed(); parent.attach(inner); inner = parent
    return inner.as_bytes()


def test_nesting_boundaries():
    assert parse_email(nested(20))["completeness"] == "complete"
    with pytest.raises(AnalysisError):
        parse_email(nested(21))


def test_missing_attachment_type_and_decoded_limit(monkeypatch):
    raw = b'From: person@example.org\nContent-Disposition: attachment; filename="invoice.pdf"\n\nSYNTHETIC'
    assert not report(raw)["findings"]
    from phishing_analyzer import config
    monkeypatch.setattr(config, "DECODED_LIMIT", 8)
    with pytest.raises(AnalysisError):
        parse_email(raw)


def test_analysis_makes_no_socket_calls(monkeypatch):
    import socket
    def forbidden(*args, **kwargs):
        raise AssertionError("Analysis attempted network access")
    monkeypatch.setattr(socket, "socket", forbidden)
    assert report(email("https://example.org"))["score"] == 0


def test_malformed_content_type_has_no_overall_rating():
    r = report(b"From: sender@example.org\nContent-Type: !!!\n\nhello")
    assert r["completeness"] == "partial"
    assert r["score"] is None
