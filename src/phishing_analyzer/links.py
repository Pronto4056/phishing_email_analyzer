"""URL observations without resolving or fetching destinations."""
import ipaddress
import re
from html.parser import HTMLParser
from urllib.parse import urlsplit

URL_PATTERN = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)


def normalize_host(value):
    try:
        host = value.lower().removesuffix(".")
        try:
            return str(ipaddress.ip_address(host))
        except ValueError:
            host = host.encode("idna").decode("ascii")
            if not re.fullmatch(r"[a-z0-9.-]+", host):
                return None
            if any(not part or len(part) > 63 or part.startswith("-") or part.endswith("-") for part in host.split(".")):
                return None
            return host if len(host) <= 253 else None
    except (UnicodeError, AttributeError):
        return None


def url_host(value):
    try:
        p = urlsplit(value)
        if p.scheme.lower() not in {"http", "https"} or not p.hostname:
            return None
        _ = p.port
        return normalize_host(p.hostname)
    except (ValueError, UnicodeError):
        return None


def claimed_host(text):
    value = text.strip()
    if re.match(r"https?://", value, re.I) and not re.search(r"\s", value):
        return url_host(value)
    if re.fullmatch(r"[^\s/:@]+\.[^\s/:@]+", value):
        return normalize_host(value)
    return None


class TextHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text = []
        self.anchors = []
        self.anchor = None
        self.skip = 0
        self.warnings = []

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style"}:
            self.skip += 1
        if self.skip:
            return
        if tag == "a":
            hrefs = [value for name, value in attrs if name == "href"]
            if len(hrefs) > 1:
                self.warnings.append("Duplicate href attributes are ambiguous; the first destination was retained.")
            if hrefs and hrefs[0] is None:
                self.warnings.append("An anchor has an empty href attribute; destination analysis was skipped.")
            self.anchor = [(hrefs[0] or "") if hrefs else "", []]
        if tag in {"p", "div", "br", "li"}:
            self.text.append("\n")

    def handle_endtag(self, tag):
        if tag in {"script", "style"}:
            self.skip = max(0, self.skip - 1)
            return
        if self.skip:
            return
        if tag == "a" and self.anchor:
            self.anchors.append((self.anchor[0], "".join(self.anchor[1])))
            self.anchor = None

    def handle_data(self, data):
        if not self.skip:
            self.text.append(data)
            if self.anchor:
                self.anchor[1].append(data)

    def result(self):
        if self.anchor:
            self.anchors.append((self.anchor[0], "".join(self.anchor[1])))
            self.anchor = None
        return "".join(self.text).strip(), self.anchors
