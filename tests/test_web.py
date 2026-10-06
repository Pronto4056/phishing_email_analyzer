import json
import sys
from urllib.parse import quote
import pytest
from phishing_analyzer.web import create_app
from phishing_analyzer.worker import execute, run_worker
from phishing_analyzer.parser import AnalysisError

RAW = b"From: support@example.org\r\nSubject: LOCAL_SECRET\r\n\r\nHello"


@pytest.fixture
def client():
    app = create_app({"TESTING": True})
    return app.test_client()


def token(client):
    client.get("/", base_url="http://127.0.0.1:5000")
    with client.session_transaction(base_url="http://127.0.0.1:5000") as s:
        return s["csrf"]


def post(client, raw=RAW, **headers):
    h = {"X-CSRF-Token": token(client), "X-Email-Filename": quote("sample.eml"), "Origin": "http://127.0.0.1:5000"}
    h.update(headers)
    return client.post("/api/analyze", data=raw, content_type="application/octet-stream", headers=h, base_url="http://127.0.0.1:5000")


def test_actual_worker():
    assert run_worker(RAW, "sample.eml")["report"]["score"] == 0
    with pytest.raises(AnalysisError):
        run_worker(b"no headers", "sample.eml")


@pytest.mark.parametrize("script,timeout,limit", [
    ("import time;time.sleep(30)", .1, 1024),
    ("import sys;sys.stdout.buffer.write(b'x'*100000)", 3, 1024),
    ("raise SystemExit(1)", 3, 1024),
    ("print('not json')", 3, 1024),
])
def test_worker_failure(script, timeout, limit):
    with pytest.raises(AnalysisError) as e:
        execute([sys.executable, "-c", script], b"", timeout, limit)
    assert e.value.status == 503


def test_upload_and_headers(client):
    r = post(client)
    assert r.status_code == 200
    assert r.json["report"]["filename"] == "sample.eml"
    assert r.json["preview"]["text"] == "Hello"
    assert r.headers["Cache-Control"] == "no-store"
    assert "object-src 'none'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["Referrer-Policy"] == "no-referrer"


@pytest.mark.parametrize("headers", [
    {"X-CSRF-Token": "wrong"}, {"Origin": "https://evil.example"},
    {"Sec-Fetch-Site": "cross-site"}, {"X-Email-Filename": "%ZZ"},
    {"X-Email-Filename": "x" * 256}, {"X-Email-Filename": "file.txt"},
])
def test_bad_headers(client, headers):
    assert post(client, **headers).status_code in {400, 403}


def test_wrong_host_and_missing_csrf(client):
    assert client.get("/", base_url="http://evil.example").status_code == 403
    assert client.post("/api/analyze", data=RAW, content_type="application/octet-stream", base_url="http://127.0.0.1:5000").status_code == 403


def test_validation_and_size_boundary(client):
    assert post(client, b"").status_code == 400
    assert post(client, b"not an email").status_code == 422
    prefix = b"Subject: size\r\n\r\n"
    assert post(client, prefix + b"a" * (5*1024*1024 - len(prefix))).status_code == 200
    assert post(client, prefix + b"a" * (5*1024*1024 + 1 - len(prefix))).status_code == 413
    t = token(client)
    assert client.post("/api/analyze", data=RAW, content_type="multipart/form-data", headers={"X-CSRF-Token": t}, base_url="http://127.0.0.1:5000").status_code == 400


def test_sample_allowlist_and_busy(client):
    t = token(client)
    h = {"X-CSRF-Token": t}
    assert client.post("/api/sample/benign", headers=h, base_url="http://127.0.0.1:5000").status_code == 200
    assert client.post("/api/sample/unknown", headers=h, base_url="http://127.0.0.1:5000").status_code == 404
    gate = client.application.extensions["analysis_gate"]
    gate.acquire()
    try:
        assert post(client).status_code == 503
    finally:
        gate.release()


def test_private_data_not_logged_or_written(client, tmp_path, caplog, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert post(client).status_code == 200
    assert not list(tmp_path.iterdir())
    assert "LOCAL_SECRET" not in caplog.text


def test_filename_basename_and_expired_token(client):
    assert post(client, **{"X-Email-Filename": quote("../../sample.eml")}).json["report"]["filename"] == "sample.eml"
    with client.session_transaction(base_url="http://127.0.0.1:5000") as s:
        s["issued"] = 0
    assert client.post("/api/analyze", data=RAW, content_type="application/octet-stream", headers={"X-CSRF-Token": "old"}, base_url="http://127.0.0.1:5000").status_code == 403


def test_non_ascii_token_rejected_without_server_error(client):
    assert post(client, **{"X-CSRF-Token": "é"}).status_code == 403
