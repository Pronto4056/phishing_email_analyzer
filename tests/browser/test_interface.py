"""Real browser acceptance checks against the actual loopback server."""
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from urllib.request import urlopen
import pytest
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2]
ORIGIN = "http://127.0.0.1:5000"


@pytest.fixture(scope="module")
def browser_page():
    env = dict(os.environ, PYTHONPATH=str(ROOT / "src"), PYTHONDONTWRITEBYTECODE="1")
    server = subprocess.Popen([sys.executable, "-B", "-m", "phishing_analyzer"], cwd=ROOT, env=env,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    try:
        for _ in range(50):
            if server.poll() is not None:
                pytest.fail("Local server failed to start; check whether port 5000 is already occupied.")
            try:
                with urlopen(ORIGIN, timeout=.3) as r:
                    if r.status == 200:
                        break
            except OSError:
                time.sleep(.1)
        else:
            pytest.fail("Local server did not become ready.")
        with sync_playwright() as p:
            browser = p.chromium.launch(channel="msedge", headless=True)
            page = browser.new_page(viewport={"width": 1440, "height": 1050}, accept_downloads=True)
            yield page
            browser.close()
    finally:
        server.terminate(); server.wait(timeout=10)


def test_sample_flow_export_and_security(browser_page):
    page = browser_page
    requests, errors = [], []
    page.on("request", lambda r: requests.append(r.url))
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(ORIGIN)
    page.get_by_label("Choose a sample").select_option("suspicious")
    page.get_by_role("button", name="Analyze email", exact=True).click()
    page.get_by_text("High observed concern", exact=True).wait_for()
    assert page.get_by_text("SENDER-01", exact=True).count() == 1
    assert page.get_by_text("LINK-01", exact=True).count() == 1
    assert page.evaluate("window.EMAIL_SCRIPT_EXECUTED") is None
    assert all(u.startswith(ORIGIN + "/") or u == ORIGIN for u in requests)
    assert not errors
    assert page.locator("#report a").count() == 0
    shots = ROOT / "evidence" / "screenshots"; shots.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(shots / "desktop-report.png"), full_page=True)
    with page.expect_download() as d:
        page.get_by_role("button", name="Download JSON", exact=True).click()
    data = json.loads(Path(d.value.path()).read_text())
    assert data["score"] == 4
    assert "preview" not in data and "text" not in data
    assert [x["rule_id"] for x in data["findings"]] == ["SENDER-01", "LINK-01"]
    page.get_by_role("button", name="Analyze another email", exact=True).click()
    assert page.locator("#report").is_hidden()


def test_upload_filename_partial_clear_mobile(browser_page):
    page = browser_page; page.goto(ORIGIN)
    raw = (ROOT / "src/phishing_analyzer/samples/suspicious.eml").read_bytes()
    page.get_by_label("Upload a saved email").set_input_files({"name": '<img src=x onerror=alert(1)>.eml', "mimeType": "application/octet-stream", "buffer": raw})
    page.get_by_role("button", name="Analyze email", exact=True).click()
    page.get_by_text("High observed concern", exact=True).wait_for()
    assert page.locator("#report img").count() == 0
    page.get_by_role("button", name="Analyze another email", exact=True).click()
    page.get_by_label("Choose a sample").select_option("partial")
    page.get_by_role("button", name="Analyze email", exact=True).click()
    page.get_by_text("Incomplete analysis", exact=True).wait_for()
    assert page.get_by_text("High observed concern", exact=True).count() == 0
    page.set_viewport_size({"width": 390, "height": 844})
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    page.screenshot(path=str(ROOT / "evidence/screenshots/mobile-report.png"), full_page=True)
    page.get_by_role("button", name="Analyze another email", exact=True).click()
    page.get_by_label("Upload a saved email").set_input_files({"name": "bad.eml", "mimeType": "application/octet-stream", "buffer": b"not an email"})
    page.get_by_role("button", name="Analyze email", exact=True).click()
    page.get_by_role("status").get_by_text("No recognized email headers were found.", exact=True).wait_for()
    assert page.locator("#report").is_hidden()
    page.get_by_role("button", name="Analyze email", exact=True).focus()
    assert page.get_by_role("button", name="Analyze email", exact=True).evaluate("el => el === document.activeElement")
