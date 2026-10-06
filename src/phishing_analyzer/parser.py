"""Bounded MIME observations; never render HTML or open attachments."""
import re
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from . import config
from .links import TextHTMLParser, URL_PATTERN, url_host, claimed_host, normalize_host


class AnalysisError(ValueError):
    def __init__(self, message, status=422):
        super().__init__(message)
        self.status = status


def parse_email(raw):
    if not raw:
        raise AnalysisError("Choose a non-empty email file.", 400)
    if len(raw) > config.RAW_LIMIT:
        raise AnalysisError("Email exceeds the 5 MiB limit.", 413)
    try:
        root = BytesParser(policy=policy.default).parsebytes(raw)
        if not any(root.get_all(h) for h in ("From", "To", "Subject", "Date", "Message-ID", "MIME-Version", "Content-Type")):
            raise AnalysisError("No recognized email headers were found.")
        return _observe(root)
    except AnalysisError:
        raise
    except (ValueError, UnicodeError, RecursionError, IndexError):
        raise AnalysisError("Email structure could not be parsed safely.") from None


def _observe(root):
    warnings = []
    headers = {}
    domains = {}
    for name in ("From", "Reply-To", "To", "Subject", "Date", "Message-ID"):
        values = root.get_all(name, [])
        key = name.lower()
        headers[key] = [{"id": f"header:{key}:{i}", "value": str(v)} for i, v in enumerate(values)]
        if name in {"From", "Reply-To"}:
            addresses = getaddresses([str(v) for v in values])
            domain = None
            if len(values) == 1 and len(addresses) == 1 and not getattr(values[0], "defects", ()):
                addr = addresses[0][1]
                if addr.count("@") == 1 and addr.split("@")[0] and not re.search(r"\s", addr):
                    domain = normalize_host(addr.split("@")[1])
            if values and domain is None:
                warnings.append(f"{name} is ambiguous or malformed; domain comparison skipped.")
            domains[key] = domain
        for v in values:
            if getattr(v, "defects", ()):
                warnings.append(f"{name} contains header parsing defects.")
    auth = []
    for i, v in enumerate(root.get_all("Authentication-Results", [])):
        raw_value = str(v)
        outcomes = [{"method": m.lower(), "result": result.lower()} for m, result in
                    re.findall(r"(?:^|;)\s*(spf|dkim|dmarc)\s*=\s*([a-z]+)\b", raw_value, re.I)]
        auth.append({"id": f"header:authentication-results:{i}", "authserv_id": raw_value.split(";", 1)[0].strip(),
                     "outcomes": outcomes, "raw": raw_value, "verified": False})
    attachments, links, text_parts = [], {}, []
    stack = [(root, "part:0", 1)]
    parts = decoded_total = text_bytes = 0
    while stack:
        part, pid, depth = stack.pop()
        parts += 1
        if parts > config.PART_LIMIT or depth > config.DEPTH_LIMIT:
            raise AnalysisError("Email exceeds MIME part or nesting limits.")
        if part.defects:
            warnings.append(f"{pid}: MIME parsing defects ({', '.join(type(d).__name__ for d in part.defects)}).")
        for header in ("Content-Type", "Content-Transfer-Encoding", "Content-Disposition"):
            if len(part.get_all(header, [])) > 1:
                warnings.append(f"{pid}: duplicate {header} headers make MIME interpretation ambiguous.")
            for value in part.get_all(header, []):
                if getattr(value, "defects", ()):
                    warnings.append(f"{pid}: malformed {header} header makes MIME interpretation incomplete.")
        ctype = part.get_content_type()
        filename = part.get_filename()
        is_attachment = part.get_content_disposition() == "attachment" or filename is not None or ctype == "message/rfc822"
        if is_attachment and ctype == "message/rfc822":
            attachments.append({"id": pid, "filename": filename or "Attached email", "content_type": ctype,
                                "declared_content_type": ctype, "size": None, "note": "Nested message not analyzed; decoded size unavailable."})
            continue
        if part.is_multipart() and not is_attachment:
            payload = part.get_payload()
            for i in reversed(range(len(payload))):
                stack.append((payload[i], f"{pid}.{i}", depth + 1))
            continue
        payload = part.get_payload(decode=True)
        if payload is None:
            warnings.append(f"{pid}: Unsupported multipart attachment or decoding.")
            continue
        decoded_total += len(payload)
        if decoded_total > config.DECODED_LIMIT:
            raise AnalysisError("Decoded email exceeds the payload limit.")
        if part.defects:
            warnings.append(f"{pid}: Payload decoding defects.")
        if is_attachment:
            attachments.append({"id": pid, "filename": filename or "Unnamed attachment", "content_type": ctype,
                                "declared_content_type": ctype if part.get("Content-Type") is not None else None, "size": len(payload)})
            continue
        if ctype not in {"text/plain", "text/html"}:
            warnings.append(f"{pid}: Unsupported body type {ctype}; not inspected.")
            continue
        remaining = max(0, config.TEXT_LIMIT - text_bytes)
        if len(payload) > remaining:
            warnings.append("Text inspection limit reached; content was not fully analyzed.")
            payload = payload[:remaining]
        text_bytes += len(payload)
        charset = part.get_content_charset() or "utf-8"
        try:
            text = payload.decode(charset, errors="strict")
        except (LookupError, UnicodeError):
            text = payload.decode("utf-8", errors="replace")
            warnings.append(f"{pid}: Unknown charset or invalid text encoding; replacement decoding used.")
        candidates = []
        if ctype == "text/html":
            html = TextHTMLParser(); html.feed(text); html.close()
            text, anchors = html.result()
            warnings.extend(f"{pid}: {w}" for w in html.warnings)
            candidates.extend((destination, visible, "anchor") for destination, visible in anchors)
            # Text inside an anchor is its displayed label, not another destination.
            residual = text
            for _, visible in anchors:
                residual = residual.replace(visible, "", 1) if visible else residual
            candidates.extend((m.group().rstrip(".,;)"), "", "text") for m in URL_PATTERN.finditer(residual))
        else:
            candidates.extend((m.group().rstrip(".,;)"), "", "text") for m in URL_PATTERN.finditer(text))
        text_parts.append(text.strip())
        for destination, visible, source in candidates:
            host = url_host(destination)
            if not host:
                if destination.lower().startswith(("http:", "https:")):
                    warnings.append(f"{pid}: Malformed HTTP(S) destination could not be evaluated.")
                continue
            if destination not in links:
                if len(links) >= config.LINK_LIMIT:
                    warnings.append("Link limit reached; destinations were not fully analyzed.")
                    continue
                links[destination] = {"id": f"link:{len(links)}", "url": destination, "host": host, "occurrences": []}
            links[destination]["occurrences"].append({"part_id": pid, "display": visible, "claimed_host": claimed_host(visible), "source": source})
    text = "\n\n".join(p for p in text_parts if p)
    return {"headers": headers, "domains": domains, "authentication": auth, "attachments": attachments,
            "links": list(links.values()), "text": text, "warnings": list(dict.fromkeys(warnings)),
            "completeness": "partial" if warnings else "complete", "empty_body": not bool(text)}
