"""Transparent heuristic rules. Scores are triage priorities, not probabilities."""
import ipaddress
from pathlib import PurePath

RULES = {
    "SENDER-01": ("Sender / reply-to domain mismatch", 1, "Replies go to a different full domain. Legitimate support services can do this.", "Confirm the reply destination through a known contact channel."),
    "LINK-01": ("Displayed link differs from destination", 3, "The visible hostname does not match the actual link host.", "Review the destination as text; do not open the link to verify it."),
    "LINK-02": ("IP address destination", 1, "The link uses an IP literal rather than a domain. This can be legitimate.", "Check whether this destination is expected in the email's context."),
    "LINK-03": ("Internationalized domain", 1, "Unicode/punycode domains may be legitimate or visually misleading.", "Compare the ASCII hostname with the expected organization domain."),
    "ATTACH-01": ("Executable or script attachment", 3, "The final filename extension can identify an executable or script; contents are not scanned.", "Do not execute the attachment. Escalate through your normal security process."),
    "ATTACH-02": ("Attachment type / extension mismatch", 1, "A declared type conflicts with the supported filename mapping; headers can be wrong.", "Confirm the expected file type without opening or executing the attachment."),
}
RISKY = {".exe", ".com", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".hta", ".msi"}
TYPES = {".pdf": "application/pdf", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".txt": "text/plain"}


def evaluate(email):
    hits = {}
    def add(rule, ref, value):
        hits.setdefault(rule, []).append({"reference": ref, "observed": value})
    domains = email["domains"]
    if domains.get("from") and domains.get("reply-to") and domains["from"] != domains["reply-to"]:
        add("SENDER-01", "header:reply-to:0", f"From: {domains['from']} | Reply-To: {domains['reply-to']}")
    for link in email["links"]:
        for occ in link["occurrences"]:
            if occ["claimed_host"] and occ["claimed_host"] != link["host"]:
                add("LINK-01", link["id"], f"Displayed: {occ['claimed_host']} | Actual: {link['host']}")
        try:
            ipaddress.ip_address(link["host"])
            add("LINK-02", link["id"], link["host"])
        except ValueError:
            pass
        if any(label.startswith("xn--") for label in link["host"].split(".")):
            add("LINK-03", link["id"], link["host"])
    for a in email["attachments"]:
        suffix = PurePath(a["filename"]).suffix.lower()
        if suffix in RISKY:
            add("ATTACH-01", a["id"], a["filename"])
        declared = a.get("declared_content_type")
        if suffix in TYPES and declared and declared != "application/octet-stream" and declared != TYPES[suffix]:
            add("ATTACH-02", a["id"], f"{a['filename']}: {declared}")
    findings = []
    for rid, (title, weight, explanation, action) in RULES.items():
        if rid in hits:
            findings.append({"rule_id": rid, "title": title, "category": rid.split("-")[0].lower(),
                             "weight": weight, "explanation": explanation, "recommendation": action, "evidence": hits[rid]})
    return findings
