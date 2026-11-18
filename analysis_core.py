
"""Offline email parsing and deterministic triage."""
import ipaddress
import re
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from urllib.parse import urlsplit

MAX_BYTES = 1024 * 1024
MAX_PARTS = 100
URL = re.compile(r"""https?://[^\s<>"']+""", re.I)
HEADER = re.compile(r"^[!-9;-~]+:")
CLAIMS = ("From", "Reply-To", "Subject")


class InputError(ValueError):
    pass


@dataclass(frozen=True)
class Link:
    visible: str
    destination: str


@dataclass(frozen=True)
class Email:
    headers: dict[str, str]
    domains: dict[str, str]
    body: str
    links: tuple[Link, ...]


@dataclass(frozen=True)
class Finding:
    title: str
    observed: str
    reason: str
    points: int


class BodyHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text = []
        self.links = []
        self.unanchored = []
        self.href = None
        self.label = []
        self.hidden = None

    def handle_starttag(self, tag, attrs):
        if self.hidden:
            return
        if tag in {"script", "style", "template", "head"}:
            self.hidden = tag
        elif tag == "a":
            self.handle_endtag("a")
            self.href = next((value for name, value in attrs if name == "href"), None) or ""
            self.label = []
            self.unanchored.append(" ")
        elif tag in {"p", "br", "div", "li", "tr"}:
            self.text.append("\n")
            self.unanchored.append(" ")

    def handle_endtag(self, tag):
        if self.hidden:
            if tag == self.hidden:
                self.hidden = None
            return
        if tag == "a" and self.href is not None:
            if self.href:
                self.links.append(Link("".join(self.label).strip(), self.href.strip()))
            self.href = None

    def handle_data(self, data):
        if not self.hidden:
            self.text.append(data)
            if self.href is not None:
                self.label.append(data)
            else:
                self.unanchored.append(data)


def parse(raw: bytes, filename: str | None = None) -> Email:
    if filename is not None and not filename.lower().endswith(".eml"):
        raise InputError("Upload an .eml file or paste the email as text.")
    if len(raw) > MAX_BYTES:
        raise InputError("Input exceeds 1 MiB. Export a smaller .eml or paste its relevant text.")
    if not raw.strip():
        raise InputError("Enter email text or choose a non-empty .eml file.")
    if b"\x00" in raw:
        raise InputError("Input contains binary data. Export an .eml or paste readable text.")

    try:
        if filename is None and not HEADER.match(raw.decode("utf-8")):
            return Email({}, {}, raw.decode("utf-8"), tuple(text_links(raw.decode("utf-8"))))
        message = BytesParser(policy=policy.default).parsebytes(raw)
        headers, domains = {}, {}
        for name in CLAIMS:
            values = message.get_all(name, [])
            if values:
                headers[name] = " | ".join(map(str, values)).strip()
            if name != "Subject" and len(values) == 1:
                claim = values[0]
                if not claim.defects and len(claim.addresses) == 1:
                    address = claim.addresses[0]
                    if address.username and address.domain:
                        domains[name] = address.domain.casefold().rstrip(".")

        bodies, links = [], []
        for index, part in enumerate(message.walk(), start=1):
            if index > MAX_PARTS:
                raise InputError("Email exceeds 100 MIME parts. Paste the relevant email text.")
            if part.defects:
                raise InputError("Malformed MIME. Re-export the original .eml or paste its text.")
        for part in body_parts(message):
            encoding = str(part.get("Content-Transfer-Encoding", "7bit")).strip().lower()
            if encoding not in {"7bit", "8bit", "binary", "quoted-printable", "base64"}:
                raise InputError("Unsupported MIME transfer encoding. Re-export the .eml or paste its text.")
            content = part.get_content(errors="strict")
            if part.defects:
                raise InputError("Malformed MIME encoding. Re-export the .eml or paste its text.")
            if part.get_content_subtype() == "html":
                html = BodyHTML()
                html.feed(content)
                html.close()
                html.handle_endtag("a")
                bodies.append("".join(html.text))
                links.extend(html.links)
                links.extend(text_links("".join(html.unanchored)))
            else:
                bodies.append(content)
                links.extend(text_links(content))
        body = "\n".join(bodies).strip()
        if not body and not links:
            raise InputError("No readable body found. Use an .eml with a text or HTML body, or paste its text.")
        return Email(headers, domains, body, tuple(dict.fromkeys(links)))
    except (UnicodeError, LookupError, RecursionError, ValueError, IndexError, AssertionError) as exc:
        if isinstance(exc, InputError):
            raise
        raise InputError("Email could not be decoded. Re-export the .eml or paste readable text.") from exc


def body_parts(part):
    if part.get_content_disposition() == "attachment" or part.get_filename():
        return
    if part.get_content_maintype() == "multipart":
        for child in part.iter_parts():
            yield from body_parts(child)
    elif part.get_content_type() in {"text/plain", "text/html"}:
        yield part


def text_links(body):
    for match in URL.finditer(body):
        url = match.group().rstrip(".,;!?)")
        yield Link(url, url)


def hostname(url):
    try:
        return (urlsplit(url).hostname or "").encode("idna").decode().lower().rstrip(".")
    except (UnicodeError, ValueError):
        return ""


def unusual(url):
    reasons = []
    try:
        parsed = urlsplit(url)
        host = hostname(url)
        port = parsed.port
    except ValueError:
        return ["the URL cannot be parsed"]
    if parsed.scheme not in {"http", "https"} or not host:
        reasons.append("the destination is relative, malformed, or uses a non-web scheme")
    if parsed.username is not None:
        reasons.append("userinfo appears before the destination host")
    if port is not None and port != {"http": 80, "https": 443}.get(parsed.scheme):
        reasons.append("the port differs from the scheme default")
    if any(label.startswith("xn--") for label in host.split(".")):
        reasons.append("the host contains an internationalized domain label")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        reasons.append("the host is an IP address")
    return reasons


URGENCY = re.compile(r"\b(?:urgent|immediately|right now|today|within \d+ hours?)\b", re.I)
REQUEST = re.compile(
    r"\b(?:enter|provide|confirm|verify|send|submit|share|reset|pay|wire|transfer|update)\b"
    r"[^\n.!?]{0,55}\b(?:password|credentials|passcode|payment|invoice|funds|money|bank details)\b",
    re.I,
)


def assess(email):
    findings = []
    sender, reply = (email.domains.get(name) for name in CLAIMS[:2])
    if sender and reply and sender != reply:
        findings.append(Finding("Sender / Reply-To mismatch", f"From: {sender}\nReply-To: {reply}",
                                "Replies would go to a different claimed domain.", 3))
    for link in email.links:
        visible = URL.fullmatch(link.visible)
        if visible and visible.group() != link.destination:
            findings.append(Finding("Visible URL / destination mismatch",
                                    f"Visible: {link.visible}\nDestination: {link.destination}",
                                    "The URL shown in the message differs from the actual destination.", 4))
        reasons = unusual(link.destination)
        if reasons:
            findings.append(Finding("Unusual URL structure", link.destination,
                                    "Flagged because " + ", and ".join(reasons) + ".", 2))
    content = email.headers.get("Subject", "") + "\n" + email.body
    urgency, request = URGENCY.search(content), REQUEST.search(content)
    if urgency and request:
        findings.append(Finding("Urgent credential or payment request",
                                f"Urgency: {urgency.group()}\nRequest: {request.group()}",
                                "The email combines time pressure with a sensitive request.", 3))
    unknown = [name for name in CLAIMS if not email.headers.get(name)]
    uncertain = [name for name in CLAIMS[:2] if email.headers.get(name) and name not in email.domains]
    # Cap repeats by finding type so repeated links cannot inflate the score.
    points = sum({finding.title: finding.points for finding in findings}.values())
    level = "High" if points >= 6 else "Review" if points or unknown or uncertain else "Low"
    return level, points, findings, unknown, uncertain


def report(email, assessment, model_score=None):
    def inert(value):
        # Indented Markdown code keeps arbitrary input inert, including HTML and URLs.
        return "\n".join("    " + line for line in str(value).splitlines())

    level, points, findings, unknown, uncertain = assessment
    sections = ["# PhishGuard AI triage report",
                f"**{level}** ({points} rule points). Header values are unverified email claims.",
                "## Claimed headers\n\n" + inert("\n".join(
                    f"{name}: {email.headers.get(name) or 'Unknown'}" for name in CLAIMS)),
                "## Uncertainty\n\nMissing: " + (", ".join(unknown) or "None") +
                ". Unusable address claims: " + (", ".join(uncertain) or "None") + ".",
                "## Local model\n\n" + ("Unknown" if model_score is None else f"{model_score:.1%}") +
                " · TF-IDF and logistic regression trained on synthetic email text.",
                "## Rule evidence"]
    for item in findings:
        sections.append(f"### {item.title} (+{item.points})\n\n{item.reason}\n\n{inert(item.observed)}")
    if not findings:
        sections.append("No configured rule fired.")
    return "\n\n".join(sections) + "\n"
