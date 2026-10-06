import hashlib
from .parser import parse_email
from .rules import evaluate
from . import config

LIMITATIONS = [
    "Heuristic triage priority, not a phishing probability or safe/unsafe verdict.",
    "Authentication headers are unverified and may be forged. No DNS or cryptographic checks are performed.",
    "No link visits, reputation checks, attachment execution, archive extraction, or malware scanning.",
    "Full-hostname comparison can flag legitimate service domains and subdomains.",
    "Input and runtime limits are enforced, but the parsing subprocess is not a hard RAM sandbox.",
]


def analyze(raw, filename):
    email = parse_email(raw)
    findings = evaluate(email)
    complete = email["completeness"] == "complete"
    score = sum(f["weight"] for f in findings) if complete else None
    rating = ("Low observed concern" if score <= 1 else "Medium observed concern" if score <= 3 else "High observed concern") if complete else None
    summary = ("Analysis incomplete; no overall rating is available." if not complete else
               "No configured indicators found; safety is not established." if score == 0 else
               "Review the evidence and context before deciding the next triage action.")
    r = {"schema_version": config.SCHEMA_VERSION, "ruleset_version": config.RULESET_VERSION,
         "filename": filename, "sha256": hashlib.sha256(raw).hexdigest(), "completeness": email["completeness"],
         "warnings": email["warnings"], "headers": email["headers"], "links": email["links"],
         "attachments": email["attachments"], "authentication": email["authentication"], "findings": findings,
         "score": score, "rating": rating, "summary": summary, "empty_body": email["empty_body"], "limitations": LIMITATIONS}
    return {"report": r, "preview": {"text": email["text"][:config.PREVIEW_LIMIT], "truncated": len(email["text"]) > config.PREVIEW_LIMIT}}
