"""Loopback interface with raw-byte uploads and no analysis storage."""
import re
import secrets
import threading
import time
from datetime import timedelta
from pathlib import Path
from urllib.parse import unquote
from flask import Flask, jsonify, render_template, request, session
from werkzeug.exceptions import RequestEntityTooLarge
from .config import RAW_LIMIT
from .parser import AnalysisError
from .worker import run_worker

SAMPLES = {"benign": "benign.eml", "suspicious": "suspicious.eml", "attachment": "attachment.eml", "partial": "partial.eml"}
ORIGIN = "http://127.0.0.1:5000"


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(SECRET_KEY=secrets.token_hex(32), MAX_CONTENT_LENGTH=RAW_LIMIT,
                      SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
                      PERMANENT_SESSION_LIFETIME=timedelta(hours=1), SESSION_COOKIE_SECURE=False)
    if test_config:
        app.config.update(test_config)
    gate = threading.Lock()
    app.extensions["analysis_gate"] = gate

    @app.before_request
    def protect():
        if request.host != "127.0.0.1:5000":
            return jsonify(error="Open the app at http://127.0.0.1:5000."), 403
        if request.method == "POST":
            expected = session.get("csrf", "")
            supplied = request.headers.get("X-CSRF-Token", "")
            issued = session.get("issued", 0)
            if not expected or not supplied.isascii() or not secrets.compare_digest(expected, supplied) or time.time() - issued > 3600:
                return jsonify(error="Your analysis session expired. Refresh the page and try again."), 403
            if request.headers.get("Origin", ORIGIN) != ORIGIN or request.headers.get("Sec-Fetch-Site") == "cross-site":
                return jsonify(error="Cross-site analysis requests are blocked."), 403

    @app.after_request
    def headers(response):
        response.headers.update({
            "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        })
        return response

    @app.errorhandler(AnalysisError)
    def analysis_error(e):
        return jsonify(error=str(e)), e.status

    @app.errorhandler(RequestEntityTooLarge)
    def too_large(e):
        return jsonify(error="Email exceeds the 5 MiB limit."), 413

    @app.errorhandler(404)
    def missing(e):
        return jsonify(error="This sample or page does not exist."), 404

    @app.get("/")
    def index():
        session["csrf"] = secrets.token_hex(32)
        session["issued"] = time.time()
        session.permanent = True
        return render_template("index.html", csrf=session["csrf"])

    def process(raw, filename):
        if not raw:
            raise AnalysisError("Choose a non-empty email file.", 400)
        if not gate.acquire(blocking=False):
            raise AnalysisError("Another email is being analyzed. Please try again shortly.", 503)
        try:
            return jsonify(run_worker(raw, filename))
        finally:
            gate.release()

    @app.post("/api/analyze")
    def upload():
        if request.mimetype != "application/octet-stream":
            raise AnalysisError("Upload a saved .eml file using the upload control.", 400)
        metadata = request.headers.get("X-Email-Filename", "")
        if not metadata or len(metadata) > 3060 or re.search(r"%(?![a-fA-F0-9]{2})", metadata):
            raise AnalysisError("The email filename is missing or invalid.", 400)
        try:
            filename = unquote(metadata, errors="strict")
        except UnicodeError:
            raise AnalysisError("The email filename is invalid.", 400) from None
        if len(filename) > 255 or any(ord(c) < 32 or ord(c) == 127 for c in filename):
            raise AnalysisError("The email filename is too long or invalid.", 400)
        filename = filename.replace("\\", "/").rsplit("/", 1)[-1]
        if not filename.lower().endswith(".eml"):
            raise AnalysisError("Choose a saved email with the .eml extension.", 400)
        return process(request.get_data(cache=False), filename)

    @app.post("/api/sample/<sample_id>")
    def sample(sample_id):
        if sample_id not in SAMPLES:
            return jsonify(error="This sample does not exist."), 404
        filename = SAMPLES[sample_id]
        raw = (Path(__file__).parent / "samples" / filename).read_bytes()
        return process(raw, filename)

    return app
