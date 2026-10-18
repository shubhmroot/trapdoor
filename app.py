"""Trapdoor: evidence-first phishing investigation demo."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import html
import hmac
import json
import os
import re
import unicodedata
import urllib.error
import urllib.request
from difflib import SequenceMatcher
from email.parser import Parser
from email.policy import default as email_policy
from email.utils import getaddresses
from urllib.parse import parse_qsl, unquote, urlsplit

from flask import Flask, jsonify, render_template, request

try:
    from dotenv import load_dotenv
except ImportError:  # Environment variables still work when python-dotenv is unavailable.
    load_dotenv = None

if load_dotenv:
    load_dotenv()

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024
TINYFISH_FETCH_ENDPOINT = "https://api.fetch.tinyfish.ai"
TINYFISH_MAX_URLS = 3
TINYFISH_TEXT_LIMIT = 1200


@app.before_request
def require_netlify_proxy_for_hosted_api():
    """Keep the public Render API from bypassing Netlify's rate-limited proxy."""
    proxy_token = os.getenv("TRAPDOOR_PROXY_TOKEN", "").strip()
    if proxy_token and request.path.startswith("/api/") and request.path != "/api/health":
        supplied = request.headers.get("Authorization", "")
        expected = f"Bearer {proxy_token}"
        if not hmac.compare_digest(supplied, expected):
            return jsonify({"error": "Use Trapdoor's public website to access this API."}), 403

BRANDS = {
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com"},
    "google": {"google.com"},
    "gmail": {"gmail.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.in"},
}

URL_RE = re.compile(
    r"(?i)(?:\b(?:https?|ftp)://[^\s<>\"']+|(?<!:)//[^\s<>\"']+|\bwww\.[^\s<>\"']+|"
    r"\b(?:data|javascript|file):[^\s<>\"']+)"
)
_QUOTED_LOCAL = r'"(?:\\.|[^"\\])*"'
_ATOM_LOCAL = r"[^\s()<>\[\]:;,\"@]+"
_DOMAIN = r"[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+"
EMAIL_RE = re.compile(rf"(?i)({_QUOTED_LOCAL}|{_ATOM_LOCAL})@({_DOMAIN}|\[[0-9a-f:.]+\])")

URGENT_RE = re.compile(r"\b(urgent|immediately|within\s+\d+\s+hours?|today|suspended|blocked|limited time|act now|final notice)\b", re.I)
CREDENTIAL_RE = re.compile(r"\b(enter (?:your )?password|provide (?:your )?password|confirm (?:your )?password|verify your account|sign in|login|credentials|one[- ]time code|otp|card number|ssn|social security)\b", re.I)
THREAT_RE = re.compile(r"\b(account (?:will be|has been) (?:closed|blocked|suspended)|legal action|will be terminated|unusual activity)\b", re.I)
PAYMENT_RE = re.compile(r"\b(payment|invoice|refund|wire transfer|gift card|crypto(?:currency)?)\b", re.I)

SUSPICIOUS_HOST_WORDS = {
    "account", "alert", "bank", "blocked", "card", "free", "gift", "helpdesk",
    "invoice", "login", "password", "prize", "renewal", "restore", "secure",
    "session", "suspended", "update", "verify", "winner", "phish", "evil",
}
SUSPICIOUS_EMAIL_WORDS = SUSPICIOUS_HOST_WORDS | {"lottery", "urgent", "payroll", "support", "billing", "hr", "portal", "vendor"}
SAFE_RESERVED_EMAIL_ROOTS = {"example.com", "example.org", "example.net"}
FREE_MAIL_DOMAINS = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "protonmail.com", "icloud.com", "aol.com"}
SHORTENER_HOSTS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "is.gd", "ow.ly", "buff.ly",
    "rebrand.ly", "cutt.ly", "short.example",
}
REDIRECT_PARAMS = {"url", "u", "redirect", "next", "dest", "destination", "target", "continue", "return", "returnto"}

_UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})|\\U([0-9a-fA-F]{8})")
_INVISIBLE_RE = re.compile(r"[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180e\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]")
_BIDI_CONTROL_RE = re.compile(r"[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")
_UNICODE_SLASHES = "\u2044\u2215\u29f8\uff0f"
_CONFUSABLES = str.maketrans({
    "а": "a", "Α": "a", "α": "a", "е": "e", "Ε": "e", "ε": "e",
    "о": "o", "Ο": "o", "ο": "o", "р": "p", "Ρ": "p", "ρ": "p",
    "с": "c", "ϲ": "c", "х": "x", "Χ": "x", "χ": "x", "у": "y",
    "і": "i", "Ι": "i", "ι": "i", "ј": "j", "Ј": "j", "ѕ": "s",
    "κ": "k", "Κ": "k", "τ": "t", "Τ": "t", "υ": "y", "ν": "v",
    "μ": "m", "ӏ": "l", "ⅼ": "l", "０": "0", "１": "1",
})


def _decode_unicode_escapes(value: str) -> str:
    def replace(match: re.Match) -> str:
        codepoint = int(match.group(1) or match.group(2), 16)
        try:
            return chr(codepoint)
        except ValueError:
            return match.group(0)
    return _UNICODE_ESCAPE_RE.sub(replace, value)


def _confusable_skeleton(value: str) -> str:
    value = _decode_unicode_escapes(value).casefold().translate(_CONFUSABLES)
    value = value.replace("rn", "m")
    return value


def _decode_idn_host(host: str) -> str:
    decoded = []
    for label in host.split("."):
        if label.lower().startswith("xn--"):
            try:
                decoded.append(label.encode("ascii").decode("idna"))
                continue
            except (UnicodeError, ValueError):
                pass
        decoded.append(label)
    return ".".join(decoded)


def _script_family(character: str) -> str | None:
    name = unicodedata.name(character, "")
    if "LATIN" in name:
        return "LATIN"
    if "CYRILLIC" in name:
        return "CYRILLIC"
    if "GREEK" in name:
        return "GREEK"
    return None


def _mixed_latin_greek_cyrillic(value: str) -> bool:
    scripts = {_script_family(char) for char in value if _script_family(char)}
    return "LATIN" in scripts and bool(scripts & {"GREEK", "CYRILLIC"})


def _finding(rule: str, severity: str, title: str, evidence: str, source: str, weight: int) -> dict:
    return {"rule": rule, "severity": severity, "title": title, "evidence": evidence, "source": source, "weight": weight}


def extract_urls(text: str) -> list[str]:
    found = URL_RE.findall(text)
    return [item.rstrip(".,!?;:)") for item in found][:20]


def normalized_url(value: str) -> str:
    candidate = html.unescape(_decode_unicode_escapes(value.strip()))
    if candidate.lower().startswith("www."):
        return "http://" + candidate
    if candidate.startswith("//"):
        return "https:" + candidate
    return candidate


def host_parts(value: str) -> tuple[str | None, str | None, str | None]:
    try:
        parsed = urlsplit(normalized_url(value))
        host = (parsed.hostname or "").rstrip(".").lower()
        if not host:
            return None, parsed.scheme.lower() or None, None
        labels = host.split(".")
        registrable = ".".join(labels[-2:]) if len(labels) >= 2 else host
        return host, parsed.scheme.lower() or None, registrable
    except ValueError:
        return None, None, None


def _tinyfish_safe_url(value: str) -> str | None:
    """Return a URL safe to submit to TinyFish, or None for ambiguous/local targets."""
    candidate = normalized_url(value)
    if "\\" in candidate or any(ord(char) < 32 for char in candidate):
        return None
    try:
        parsed = urlsplit(candidate)
        host = (parsed.hostname or "").rstrip(".").lower()
        port = parsed.port
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not host:
        return None
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        return None
    if port not in {None, 80, 443}:
        return None
    if host.endswith((".localhost", ".local", ".test", ".example", ".invalid")):
        return None
    if host in {"example.com", "example.org", "example.net"}:
        return None
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            # Reject malformed IDNs and labels before handing the URL to a remote fetcher.
            ascii_host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return None
        labels = ascii_host.split(".")
        if "." not in ascii_host or any(
            not label or len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
            for label in labels
        ):
            return None
    else:
        if not address.is_global:
            return None
    return candidate


def _tinyfish_api_key() -> str:
    key = os.getenv("TINYFISH_API_KEY", "").strip()
    if key.lower() in {"your_tinyfish_api_key_here", "replace_me", "changeme"}:
        return ""
    return key


def _tinyfish_fetch(urls: list[str]) -> dict:
    """Fetch URLs through TinyFish; only URL strings are sent, never the pasted message."""
    api_key = _tinyfish_api_key()
    if not api_key:
        return {
            "status": "not_configured",
            "provider": "TinyFish",
            "detail": "TinyFish is not configured. Set TINYFISH_API_KEY in the app environment and restart Trapdoor.",
            "pages": [],
        }
    if not urls:
        return {
            "status": "skipped",
            "provider": "TinyFish",
            "detail": "No public HTTP or HTTPS URL was eligible for a live fetch. Local-only, reserved, ambiguous, and non-web addresses are skipped.",
            "pages": [],
        }

    request_body = json.dumps({
        "urls": urls,
        "format": "markdown",
        "ttl": 0,
        "per_url_timeout_ms": 30000,
        "purpose": "Read-only phishing investigation: inspect the visible page title, final URL, and page text. Do not click, sign in, submit forms, or download files.",
    }).encode("utf-8")
    api_request = urllib.request.Request(
        TINYFISH_FETCH_ENDPOINT,
        data=request_body,
        headers={"X-API-Key": api_key, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(api_request, timeout=40) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError, UnicodeError, json.JSONDecodeError):
        return {
            "status": "unavailable",
            "provider": "TinyFish",
            "detail": "TinyFish could not complete the live page check. The local rule findings are still available; this failure is not a safe result.",
            "pages": [],
        }

    results_by_url = {}
    for page in payload.get("results", []) if isinstance(payload, dict) else []:
        if isinstance(page, dict):
            results_by_url[str(page.get("url", ""))] = page
    errors_by_url = {}
    for error in payload.get("errors", []) if isinstance(payload, dict) else []:
        if isinstance(error, dict):
            errors_by_url[str(error.get("url", ""))] = error

    pages = []
    failed = 0
    for url in urls:
        item = results_by_url.get(url)
        if item:
            text_value = item.get("text", "")
            if not isinstance(text_value, str):
                text_value = json.dumps(text_value, ensure_ascii=False)
            pages.append({
                "status": "checked",
                "url": str(item.get("url") or url),
                "final_url": str(item.get("final_url") or item.get("url") or url),
                "title": str(item.get("title") or "Page title unavailable")[:240],
                "description": str(item.get("description") or "")[:400],
                "text_excerpt": re.sub(r"\s+", " ", text_value).strip()[:TINYFISH_TEXT_LIMIT],
            })
        else:
            failed += 1
            error = errors_by_url.get(url, {})
            pages.append({
                "status": "unavailable",
                "url": url,
                "detail": str(error.get("error") or error.get("code") or "TinyFish could not fetch this page.")[:240],
            })

    checked = sum(page["status"] == "checked" for page in pages)
    status = "checked" if checked else "unavailable"
    if failed and checked:
        detail = f"TinyFish fetched {checked} page(s); {failed} URL(s) could not be fetched."
    elif checked:
        detail = f"TinyFish fetched {checked} live page(s). Review the returned title, final URL, and excerpt as additional evidence."
    else:
        detail = "TinyFish could not fetch these pages. The failure is unknown, not a clean bill of health."
    return {"status": status, "provider": "TinyFish", "detail": detail, "pages": pages}


def _add_tinyfish_findings(report: dict, inspection: dict) -> None:
    """Add only concrete live-page signals, then refresh the report's decision fields."""
    additions = []
    for page in inspection.get("pages", []):
        if page.get("status") != "checked":
            continue
        requested_host = host_parts(page.get("url", ""))[0]
        final_host = host_parts(page.get("final_url", ""))[0]
        if requested_host and final_host and _registrable_host(requested_host) != _registrable_host(final_host):
            additions.append(_finding(
                "TINYFISH_CROSS_SITE_REDIRECT", "medium", "The live page ended on a different registered site",
                f"TinyFish fetched {requested_host} and reported the final page at {final_host}. Cross-site redirects can be legitimate, but verify the final destination before signing in or paying.",
                "TinyFish live page check", 18,
            ))

        title = page.get("title", "")
        title_skeleton = _confusable_skeleton(title)
        action_in_title = bool(re.search(r"(?i)\b(sign\s*in|log\s*in|account|password|verify|security)\b", title))
        if action_in_title:
            for brand, official_domains in BRANDS.items():
                if brand in title_skeleton and final_host and not _is_official_brand_domain(final_host, official_domains):
                    additions.append(_finding(
                        "TINYFISH_BRAND_LOGIN_TITLE", "high", f"The live page title pairs {brand.title()} with an account action on another domain",
                        f"TinyFish returned the page title {title!r} at {final_host}. A brand and sign-in or account title on a nonofficial domain needs independent verification.",
                        "TinyFish live page check", 38,
                    ))
                    break

    present = {finding["rule"] for finding in report["findings"]}
    for item in additions:
        if item["rule"] not in present:
            report["findings"].append(item)
            present.add(item["rule"])
    score = min(100, sum(item["weight"] for item in report["findings"]))
    if score >= 75:
        verdict, label = "CRITICAL_RISK", "Strong danger signals"
    elif score >= 50:
        verdict, label = "HIGH_RISK", "High risk signals"
    elif score >= 25:
        verdict, label = "MEDIUM_RISK", "Review these risk signals"
    elif score > 0:
        verdict, label = "LOW_RISK", "Caution signal found"
    else:
        verdict, label = "NO_SIGNALS_FOUND", "No obvious signals found"
    action, action_label = _next_step(score, report["emails"], report["urls"])
    report.update({"verdict": verdict, "label": label, "action_label": action_label,
                   "recommended_action": action, "risk_score": score})
    report["recommendations"] = [action]
    if score >= 25:
        report["recommendations"].append("Contact the organization using a phone number or website you already trust, not details in this message.")
    elif score > 0:
        report["recommendations"].append("A low-level warning can be benign; confirm the destination before entering credentials or paying.")
    else:
        report["recommendations"].append("Before signing in or paying, check that the address bar shows the exact site you meant to visit.")
    if score >= 50:
        report["recommendations"].append("If you already shared a password or code, change it through the official service and contact its support team.")
    if not report["findings"]:
        report["summary"] = "TinyFish fetched the live page and no obvious warning patterns matched the URL or returned page title. If you expected this link and the final address matches the site you intended, it is reasonable to open; review the page details below."
    elif verdict in {"HIGH_RISK", "CRITICAL_RISK"}:
        report["summary"] = "Strong warning patterns appeared in the local rules or live page evidence. Do not use the link; verify through a trusted channel."
    elif verdict == "MEDIUM_RISK":
        report["summary"] = "Suspicious patterns appeared in the local rules or live page evidence. Hold off on signing in, paying, downloading, or sharing codes until you verify the destination."
    else:
        report["summary"] = "Warning patterns appeared in the local rules or live page evidence. Review the evidence; a single caution signal can also occur on a legitimate site."


def _ip_address(host: str) -> tuple[str | None, bool]:
    """Return standard or browser-style IPv4 notation and whether it was obfuscated."""
    try:
        return str(ipaddress.ip_address(host)), False
    except ValueError:
        pass

    labels = host.split(".")
    try:
        if len(labels) == 1 and (labels[0].isdecimal() or labels[0].lower().startswith("0x")):
            number = int(labels[0], 0) if labels[0].lower().startswith("0x") else int(labels[0], 10)
            if 0 <= number <= 0xFFFFFFFF:
                return str(ipaddress.IPv4Address(number)), True
        if len(labels) == 4 and all(part.isdecimal() or part.lower().startswith("0x") for part in labels):
            octets = []
            for part in labels:
                if part.lower().startswith("0x"):
                    octets.append(int(part, 16))
                elif len(part) > 1 and part.startswith("0") and all(char in "01234567" for char in part):
                    octets.append(int(part, 8))
                else:
                    octets.append(int(part, 10))
            if all(0 <= octet <= 255 for octet in octets):
                return ".".join(str(octet) for octet in octets), True
    except (ValueError, ipaddress.AddressValueError):
        pass
    return None, False


def _is_internal_host(host: str) -> bool:
    if host.lower() == "localhost" or host.lower().endswith(".localhost") or host.lower().endswith(".local"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    private_networks = (
        ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"), ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("fc00::/7"), ipaddress.ip_network("fe80::/10"),
        ipaddress.ip_network("::1/128"),
    )
    return any(address.version == network.version and address in network for network in private_networks)


def _is_official_brand_domain(host: str, official_domains: set[str]) -> bool:
    return any(host == domain or host.endswith("." + domain) for domain in official_domains)


def _brand_mentioned(host: str) -> str | None:
    labels = [label for label in re.split(r"[.-]", host.lower()) if label]
    for brand, official_domains in BRANDS.items():
        if _is_official_brand_domain(host, official_domains):
            continue
        for label in labels:
            normalized = _confusable_skeleton(label).translate(str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s"}))
            if brand in label or brand in normalized or (
                len(normalized) >= max(5, len(brand) - 1) and SequenceMatcher(None, normalized, brand).ratio() >= 0.8
            ):
                return brand
    return None


def _host_terms(host: str) -> set[str]:
    return {part for part in re.split(r"[^a-z0-9]+", host.lower()) if part}


def _decoded_redirect(value: str) -> str:
    decoded = value
    for _ in range(3):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    if not re.match(r"(?i)^(?:https?:)?//", decoded.strip()):
        try:
            compact = re.sub(r"\s+", "", decoded)
            padding = "=" * ((4 - len(compact) % 4) % 4)
            unpacked = base64.urlsafe_b64decode(compact + padding).decode("utf-8", "ignore")
            if re.match(r"(?i)^(?:https?:)?//", unpacked.strip()):
                decoded = unpacked
        except (binascii.Error, ValueError):
            pass
    return decoded


def _registrable_host(host: str) -> str:
    labels = host.lower().rstrip(".").split(".")
    public_suffixes = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "com.br", "com.cn", "com.sg", "co.in", "firm.in", "net.in", "org.in", "co.jp"}
    if len(labels) >= 3 and ".".join(labels[-2:]) in public_suffixes:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host.lower()


def _redirect_findings(url: str, parsed) -> list[dict]:
    findings = []
    oauth_context = "/oauth2/authorize" in parsed.path.lower()
    outer_host = (parsed.hostname or "").lower()
    seen_destinations = set()
    pending = [(key, value, 0) for key, value in parse_qsl(parsed.query, keep_blank_values=True)]
    while pending:
        key, value, depth = pending.pop(0)
        key_lower = key.lower().replace("_", "")
        decoded = _decoded_redirect(value)
        nested_candidate = decoded.strip()
        try:
            nested = urlsplit(nested_candidate if not nested_candidate.startswith("//") else "https:" + nested_candidate)
        except ValueError:
            continue
        has_destination = bool(nested.scheme in {"http", "https"} and nested.netloc)
        if key_lower in REDIRECT_PARAMS or key_lower in {"redirecturi", "redirecturl"}:
            if has_destination and not (key_lower == "redirecturi" and oauth_context):
                destination_host = (nested.hostname or "").lower()
                same_site = bool(destination_host and outer_host and _registrable_host(destination_host) == _registrable_host(outer_host))
                if not same_site and destination_host not in seen_destinations:
                    seen_destinations.add(destination_host)
                    findings.append(_finding(
                        "NESTED_REDIRECT_DESTINATION", "high", "The URL carries another destination",
                        f"The “{key}” parameter reveals a second destination ({destination_host}). Verify that destination before trusting the outer site.",
                        "URL query", 55,
                    ))
                if depth < 3:
                    pending.extend((next_key, next_value, depth + 1) for next_key, next_value in parse_qsl(nested.query, keep_blank_values=True))
                if findings:
                    break
        elif depth < 3:
            # Allow a wrapped base64 URL to expose its own redirect parameters.
            if nested.query:
                pending.extend((next_key, next_value, depth + 1) for next_key, next_value in parse_qsl(nested.query, keep_blank_values=True))
    return findings


def analyze_url(url: str) -> list[dict]:
    findings: list[dict] = []
    decoded_input = html.unescape(_decode_unicode_escapes(url.strip()))
    candidate = normalized_url(url)
    if _INVISIBLE_RE.search(decoded_input):
        controls = sorted({f"U+{ord(match.group(0)):04X}" for match in _INVISIBLE_RE.finditer(decoded_input)})
        findings.append(_finding(
            "INVISIBLE_OR_BIDI_UNICODE", "high", "The URL contains invisible or direction-changing Unicode",
            f"The input contains hidden formatting characters ({', '.join(controls)}). These can disguise text; inspect the address in plain text.",
            "Unicode rendering", 58,
        ))
    if any(char in decoded_input for char in _UNICODE_SLASHES):
        findings.append(_finding(
            "UNICODE_DELIMITER_CONFUSION", "high", "A look-alike slash may disguise the URL structure",
            "The URL contains a Unicode slash-like character that is not the normal ASCII slash. Browsers and readers may display or interpret it differently.",
            "Unicode rendering", 52,
        ))
    if "\\" in decoded_input and re.search(r"(?i)^https?://[^/?#]*\\", decoded_input):
        findings.append(_finding(
            "BACKSLASH_AUTHORITY_CONFUSION", "high", "A backslash makes the apparent host ambiguous",
            "Browsers may treat a backslash like a slash in special-scheme URLs, while other parsers may not. Verify the actual host before opening it.",
            "URL parsing", 48,
        ))
    candidate = _INVISIBLE_RE.sub("", candidate)
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return [_finding("MALFORMED_URL", "medium", "The URL could not be parsed", "Its structure is malformed, so the destination cannot be assessed reliably.", "URL structure", 18)]

    scheme = parsed.scheme.lower()
    if scheme in {"data", "javascript", "file", "vbscript"}:
        return [_finding(
            "ACTIVE_OR_EMBEDDED_CONTENT_URI", "high", "This is not a normal website link",
            f"The link uses the {scheme}: scheme, which can open embedded content or a local resource instead of a normal HTTPS website.",
            "URL scheme", 78,
        )]

    host = (parsed.hostname or "").rstrip(".").lower()
    if not host:
        return findings

    raw_host = host
    decoded_host = unquote(host).lower()
    display_host = _decode_idn_host(decoded_host)
    if _mixed_latin_greek_cyrillic(display_host):
        findings.append(_finding(
            "MIXED_SCRIPT_HOSTNAME", "high", "The hostname mixes Latin with look-alike characters from another script",
            f"The hostname {display_host} mixes scripts. Its look-alike form is {_confusable_skeleton(display_host)}; compare it with the organization’s exact known domain.",
            "Unicode rendering", 42,
        ))
    ip, obfuscated_ip = _ip_address(decoded_host)
    internal_host = _is_internal_host(ip or decoded_host)
    if ip and not internal_host:
        findings.append(_finding(
            "IP_ADDRESS_HOST", "medium", "The link uses an IP address",
            f"The hostname resolves syntactically to {ip}, rather than using a named domain.", "URL structure", 22,
        ))
        if obfuscated_ip:
            findings.append(_finding(
                "OBFUSCATED_IP_HOST", "high", "The IP address is written in an unusual numeric form",
                f"The hostname {raw_host} can be interpreted as {ip}. Numeric variants can hide the true destination.",
                "URL structure", 48,
            ))

    if scheme == "http" and not internal_host:
        findings.append(_finding(
            "NO_HTTPS", "low", "The link does not use HTTPS",
            "The URL begins with http://. Encryption alone cannot establish trust, but its absence is a caution signal.",
            "URL structure", 6,
        ))

    userinfo = parsed.netloc.rsplit("@", 1)[0] if "@" in parsed.netloc else ""
    ftp_credentials = scheme == "ftp" and ":" in userinfo and host.startswith("ftp.")
    credentialed_ftp_host = ":" in userinfo and host.startswith("ftp.")
    if "@" in parsed.netloc and not (ftp_credentials or credentialed_ftp_host):
        findings.append(_finding(
            "AT_SIGN_IN_AUTHORITY", "high", "The URL contains an @ sign in its authority",
            "Text before @ can look like a trusted site name while the browser connects to the host after it.",
            "URL structure", 42,
        ))

    if "xn--" in raw_host or any("%" in part for part in raw_host.split(".")):
        findings.append(_finding(
            "ENCODED_OR_PUNYCODE_HOST", "medium", "The hostname contains encoded or internationalized text",
            "Punycode or percent-encoded hostname characters can make a destination harder to read. This is a review signal, not proof of deception.",
            "URL structure", 12,
        ))

    if decoded_host != raw_host and "%" in raw_host:
        findings.append(_finding(
            "PERCENT_ENCODED_HOSTNAME", "high", "Encoded characters change the hostname when decoded",
            f"The raw hostname {raw_host} decodes to {decoded_host}. The visible and parsed forms may not be read the same way; do not trust it until the exact destination is clear.",
            "URL parsing", 48,
        ))

    brand = _brand_mentioned(display_host)
    if brand:
        spoofed_label = next((
            label for label in display_host.split(".")
            if brand in _confusable_skeleton(label).translate(str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s"}))
            and brand not in label
        ), None)
        findings.append(_finding(
            "BRAND_NAME_IN_DOMAIN", "high", f"The hostname mentions {brand.title()} outside its official domain",
            f"The actual hostname is {decoded_host}; a brand name inside a hostname does not make that domain official.",
            "Hostname comparison", 40,
        ))
        brand_lure_terms = _host_terms(decoded_host) & {
            "account", "billing", "delivery", "help", "login", "order", "payment",
            "renewal", "secure", "service", "support", "verify",
        }
        if brand_lure_terms:
            findings.append(_finding(
                "BRAND_WITH_ACTION_LURE", "high", f"The nonofficial {brand.title()}-like domain also asks for an account action",
                f"The hostname is not an official {brand.title()} domain and combines the brand name with {', '.join(sorted(brand_lure_terms)[:4])}. Treat the destination as suspicious.",
                "Hostname comparison", 22,
            ))
        if spoofed_label:
            findings.append(_finding(
                "BRAND_HOMOGRAPH_DOMAIN", "high", f"A hostname label imitates {brand.title()}",
                f"The label {spoofed_label!r} resembles {brand}. Similar-looking characters or letter pairs can hide a different domain.",
                "Hostname comparison", 52,
            ))

    terms = _host_terms(decoded_host) & SUSPICIOUS_HOST_WORDS
    strong_terms = terms & {"bank", "blocked", "free", "gift", "phish", "prize", "suspended", "verify", "winner", "evil"}
    if len(terms) >= 2 or (terms and strong_terms):
        examples = ", ".join(sorted(terms)[:5])
        weight = min(32, 18 + max(0, len(terms) - 1) * 6)
        findings.append(_finding(
            "SUSPICIOUS_HOST_WORDS", "medium", "The hostname combines account or lure language",
            f"The hostname includes these terms: {examples}. Check whether the organization actually owns this domain.",
            "Hostname wording", weight,
        ))

    lure_words = terms & {"account", "free", "gift", "prize", "winner", "lottery", "bank", "suspended", "blocked", "verify", "restore", "login"}
    if len(lure_words) >= 2:
        findings.append(_finding(
            "COMBINED_HOST_LURE", "high", "The hostname combines multiple phishing-style lure or account terms",
            f"The host combines {', '.join(sorted(lure_words)[:5])}. Verify the exact registered domain through a known route.",
            "Hostname wording", 42,
        ))

    if decoded_host in SHORTENER_HOSTS or decoded_host.split(".")[0] == "short":
        findings.append(_finding(
            "SHORTENER_OR_HIDDEN_DESTINATION", "medium", "The link may hide its final destination",
            f"The hostname {decoded_host} is a short-link style address; the final page is not visible in this URL alone.",
            "URL structure", 18,
        ))

    if len(decoded_host.split(".")) >= 7:
        findings.append(_finding(
            "EXCESSIVE_SUBDOMAINS", "medium", "The hostname has an unusually long chain of subdomains",
            f"The hostname has {len(decoded_host.split('.'))} labels. Long hostnames can hide the registered domain in truncated views; read from the right-hand end.",
            "URL structure", 24,
        ))

    try:
        port = parsed.port
    except ValueError:
        port = -1
    if not internal_host and port not in (None, 80 if scheme == "http" else 443 if scheme == "https" else None):
        findings.append(_finding(
            "NONSTANDARD_WEB_PORT", "medium", "The website link uses a nonstandard port",
            f"The URL specifies port {port if port is not None else 'invalid'}, which is unusual for normal web browsing.",
            "URL structure", 16,
        ))

    if re.search(r"\.(?:pdf|docx?|xlsx?|pptx?|jpg|png|iso|lnk)\.(?:html?|exe|js|scr|iso|lnk)(?:$|[;?#])", parsed.path, re.I):
        findings.append(_finding(
            "DOUBLE_FILE_EXTENSION", "high", "The file name uses a misleading double extension",
            f"The path ends in {parsed.path.rsplit('/', 1)[-1]}, where a document-like extension is followed by an active file extension.",
            "URL path", 48,
        ))

    if re.search(r"\.(?:exe|scr|lnk|iso|js)(?:$|[;?#])", parsed.path, re.I):
        findings.append(_finding(
            "EXECUTABLE_OR_SHORTCUT_FILE", "high", "The link ends in an executable, script, disk image, or shortcut",
            f"The path ends in {parsed.path.rsplit('/', 1)[-1]}. Treat unexpected executable files as unsafe until verified.",
            "URL path", 52,
        ))

    if decoded_host.startswith("sites.") and re.search(r"/forms?/|viewform", parsed.path, re.I):
        findings.append(_finding(
            "PUBLIC_FORM_HOSTING", "low", "The link points to a hosted form",
            "Public form platforms can be used for legitimate surveys and for credential collection. Verify the form owner and what it requests.",
            "URL path", 12,
        ))

    path_terms = _host_terms(unquote(parsed.path)) & {"account", "auth", "login", "password", "restore", "secure", "signin", "update", "verify"}
    if len(path_terms) >= 2 or (ip and path_terms):
        findings.append(_finding(
            "CREDENTIAL_HARVESTING_PATH", "medium", "The URL path points toward account access or recovery",
            f"The path includes these terms: {', '.join(sorted(path_terms))}. A login or recovery path is only a concern when the destination is unexpected; verify the hostname first.",
            "URL path", 24,
        ))

    if "@" in parsed.path:
        findings.append(_finding(
            "AT_SIGN_IN_PATH", "low", "The URL path contains an at sign",
            "This is different from an @ sign before the hostname. It does not change the destination by itself, but it makes the path unusual and worth checking.",
            "URL path", 10,
        ))

    if parsed.fragment and re.search(r"(?i)(?:https?://|www\.)", parsed.fragment):
        embedded = extract_urls(parsed.fragment)
        embedded_host = host_parts(embedded[0])[0] if embedded else None
        if embedded_host and embedded_host != host:
            findings.append(_finding(
                "URL_HIDDEN_IN_FRAGMENT", "medium", "The URL fragment contains a second web address",
                f"The actual destination is {host}, while the part after # contains {embedded_host}. A fragment does not change the destination, but can disguise it in copied text.",
                "URL parsing", 28,
            ))

    if parsed.query.startswith(".") and re.search(r"(?i)\.[a-z]{2,}/", parsed.query):
        findings.append(_finding(
            "QUERY_DELIMITER_CONFUSION", "medium", "Text that resembles a hostname appears after the query delimiter",
            "The question mark ends the hostname. The domain-like text after it is query data, not the site you will visit; check the hostname shown before the question mark.",
            "URL parsing", 22,
        ))

    findings.extend(_redirect_findings(candidate, parsed))
    return findings


def _email_matches(text: str) -> list[dict]:
    text = _decode_unicode_escapes(text)
    found = []
    occupied: list[tuple[int, int]] = []
    matches = list(EMAIL_RE.finditer(text))
    # Prefer a quoted local part as one address instead of extracting an email embedded inside it.
    for match in sorted(matches, key=lambda item: (item.start(), -(item.end() - item.start()))):
        span = match.span()
        if any(span[0] < end and span[1] > start for start, end in occupied):
            continue
        local, domain = match.groups()
        value = f"{local}@{domain}".strip(".,;:<> ")
        found.append({"value": value, "local": local, "domain": domain.lower().rstrip(".")})
        occupied.append(span)
    return found


def _reserved_safe_email_domain(domain: str) -> bool:
    return any(domain == root or domain.endswith("." + root) for root in SAFE_RESERVED_EMAIL_ROOTS)


def _is_free_mail_domain(domain: str) -> bool:
    return any(domain == root or domain.endswith("." + root) for root in FREE_MAIL_DOMAINS)


def _analyze_email_address(address: dict) -> list[dict]:
    local = address["local"]
    domain = address["domain"]
    findings = []
    if _reserved_safe_email_domain(domain):
        return findings

    if domain.startswith("[") and domain.endswith("]"):
        findings.append(_finding(
            "IP_LITERAL_EMAIL_DOMAIN", "high", "The sender address uses an IP-literal domain",
            f"The sender domain is written as {domain} instead of a normal mail domain. Verify the sender through another channel.",
            "Email address", 52,
        ))

    if _mixed_latin_greek_cyrillic(local):
        findings.append(_finding(
            "MIXED_SCRIPT_EMAIL_NAME", "high", "The sender name mixes Latin with look-alike characters",
            f"The local part {local} mixes writing systems; its approximate look-alike form is {_confusable_skeleton(local)}.",
            "Email address", 52,
        ))

    if "xn--" in domain:
        findings.append(_finding(
            "PUNYCODE_EMAIL_DOMAIN", "low", "The sender domain uses an internationalized label",
            f"The domain {domain} decodes to {_decode_idn_host(domain)}. Internationalized domains can be legitimate; compare its spelling with the exact sender domain you expect.",
            "Email address", 14,
        ))

    display_domain = _decode_idn_host(domain)
    if _mixed_latin_greek_cyrillic(display_domain):
        findings.append(_finding(
            "MIXED_SCRIPT_EMAIL_DOMAIN", "high", "The sender domain mixes Latin with look-alike characters",
            f"The rendered domain {display_domain} mixes writing systems; compare it with the exact domain you expect.",
            "Email address", 42,
        ))
    brand = _brand_mentioned(display_domain)
    if brand:
        findings.append(_finding(
            "BRAND_NAME_IN_EMAIL_DOMAIN", "high", f"The sender domain mentions {brand.title()} outside its official domain",
            f"The address uses {domain}, which is not one of the recognized official {brand.title()} domains.",
            "Email address", 40,
        ))
        spoofed_label = next((
            label for label in display_domain.split(".")
            if brand in _confusable_skeleton(label).translate(str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s"}))
            and brand not in label
        ), None)
        if spoofed_label:
            findings.append(_finding(
                "EMAIL_BRAND_HOMOGRAPH", "high", f"A sender-domain label imitates {brand.title()}",
                f"The rendered label {spoofed_label!r} resembles {brand}. Verify the actual domain before replying or paying.",
                "Email address", 52,
            ))

    domain_terms = _host_terms(domain)
    suspicious = domain_terms & SUSPICIOUS_EMAIL_WORDS
    if len(suspicious) >= 2 or suspicious & {"free", "gift", "lottery", "phish", "prize", "urgent", "verify", "winner", "evil", "payroll"}:
        examples = ", ".join(sorted(suspicious)[:5])
        findings.append(_finding(
            "SUSPICIOUS_EMAIL_DOMAIN_WORDS", "medium", "The sender domain uses lure or account-warning language",
            f"The domain includes these terms: {examples}. Confirm it belongs to the claimed organization.",
            "Email address", min(32, 22 + max(0, len(suspicious) - 2) * 5),
        ))

    if re.search(r"\.(?:com|org|net|co)\.[a-z0-9-]+\.[a-z]{2,}$", domain):
        findings.append(_finding(
            "DOMAIN_EMBEDDED_BEFORE_REAL_SUFFIX", "high", "The address places a company-like domain inside another domain",
            f"In {domain}, the apparent company domain is followed by additional hostname labels; the sender is controlled by the final domain suffix.",
            "Email address", 35,
        ))

    local_lower = local.lower()
    local_skeleton = _confusable_skeleton(local_lower)
    if any(brand in local_skeleton for brand in BRANDS) and not any(_is_official_brand_domain(domain, official) for official in BRANDS.values()):
        findings.append(_finding(
            "BRAND_STUFFED_EMAIL_LOCAL_PART", "high", "The sender name contains a brand-like address string",
            f"The local part {local} contains a brand name, but the sending domain is {domain}. The displayed name does not establish who controls the account.",
            "Email address", 52,
        ))
    if "%" in local:
        findings.append(_finding(
            "PERCENT_ROUTING_EMAIL", "medium", "The sender uses percent-routing syntax",
            f"The local part {local} contains a legacy percent-routing marker that can confuse address readers.",
            "Email address", 40,
        ))
    if local_lower.startswith('"') and "@" in local:
        findings.append(_finding(
            "QUOTED_ADDRESS_IN_LOCAL_PART", "high", "A second address is embedded inside the sender name",
            f"The quoted local part {local} contains an @ sign and can visually resemble a different sender address; the actual domain is {domain}.",
            "Email address", 52,
        ))
    if re.search(r"\d{5,}$", local_lower):
        findings.append(_finding(
            "NUMBERED_BULK_SENDER", "low", "The sender name has a long numeric suffix",
            f"The local part {local} ends with a long number. This can occur in automated mail, but is also common in throwaway sender names.",
            "Email address", 10,
        ))

    lure_local = _host_terms(local_lower) & {"winner", "lottery", "urgent", "alert", "verify", "prize", "payroll"}
    if lure_local:
        findings.append(_finding(
            "LURE_WORDS_IN_SENDER", "medium", "The sender name uses urgency or prize language",
            f"The address name includes: {', '.join(sorted(lure_local))}.", "Email address", 18,
        ))
    if lure_local and suspicious:
        findings.append(_finding(
            "COMBINED_EMAIL_LURE", "high", "The sender name and domain both contain lure or warning language",
            f"The sender name includes {', '.join(sorted(lure_local))}; the domain includes {', '.join(sorted(suspicious)[:4])}. Treat the sender as unverified.",
            "Email address", 32,
        ))

    if local_lower.startswith("\"") and ("@" in local or "<" in local) and any(brand in local_lower for brand in BRANDS):
        findings.append(_finding(
            "SPOOFED_DISPLAY_NAME_IN_LOCAL_PART", "high", "A brand-like display name is embedded in the address",
            f"The quoted local part {local} contains display-name or address syntax; the actual sender domain is {domain}.",
            "Email address", 30,
        ))

    role = re.split(r"[.+_-]", local_lower)[0]
    free_mail_lookalike = domain_terms & {"gmail", "yahoo", "outlook", "hotmail", "protonmail", "icloud", "aol"}
    if role in {"ceo", "cfo", "payroll", "finance", "accounts"} and free_mail_lookalike and not _is_free_mail_domain(domain):
        findings.append(_finding(
            "EXECUTIVE_NAME_FREE_MAIL_LOOKALIKE", "high", "An executive-style sender uses a free-mail lookalike domain",
            f"The sender name suggests {role}, and {domain} contains a free-mail brand label without being that provider’s official domain.",
            "Email address", 32,
        ))
    if role in {"ceo", "cfo", "payroll", "finance", "accounts"} and domain.endswith(".co"):
        findings.append(_finding(
            "POSSIBLE_EXECUTIVE_TLD_SWAP", "low", "A sensitive sender uses a .co domain that could be confused with .com",
            f"The sender is {local}@{domain}. A .co domain can be legitimate, and this address alone cannot prove a one-letter swap. Compare it with the exact company domain you already know before sending money or sensitive information.",
            "Email address", 20,
        ))

    if "relay" in domain_terms or "disposable" in domain_terms or "tempmail" in domain_terms:
        findings.append(_finding(
            "RELAY_OR_DISPOSABLE_EMAIL_DOMAIN", "medium", "The sender domain looks like a relay or disposable-mail service",
            f"The domain {domain} includes a relay or disposable-mail label. Verify the sender using a known channel.",
            "Email address", 18,
        ))
    if re.search(r"(?i)\b(payments?|billing|payroll|finance|accounts)\b", local) and domain_terms & {"vendor", "portal", "invoice", "supplier"}:
        findings.append(_finding(
            "PAYMENT_ROLE_VENDOR_DOMAIN", "medium", "A payment-related sender uses a vendor-portal style domain",
            f"The local part {local} suggests payment or finance, while {domain} looks like a vendor or portal domain. This can be legitimate; confirm new payees and account details by phone.",
            "Email address", 22,
        ))
    return findings


def _header_values(text: str) -> dict[str, str]:
    try:
        message = Parser(policy=email_policy).parsestr(text)
    except (ValueError, TypeError):
        return {}
    return {name.lower(): str(message.get(name, "")) for name in ("from", "reply-to", "return-path", "authentication-results", "received-spf", "subject") if message.get(name)}


def analyze_email(text: str) -> tuple[list[dict], list[dict]]:
    addresses = _email_matches(URL_RE.sub(" ", text))
    findings = []
    for address in addresses:
        findings.extend(_analyze_email_address(address))

    headers = _header_values(text)
    from_addresses = _email_matches(headers.get("from", ""))
    reply_addresses = _email_matches(headers.get("reply-to", ""))
    return_addresses = _email_matches(headers.get("return-path", ""))
    for display_name, sender_value in getaddresses([headers.get("from", "")]):
        sender = _email_matches(sender_value)
        brand_in_display = next((brand for brand in BRANDS if brand in _confusable_skeleton(display_name)), None)
        if brand_in_display and sender and not _is_official_brand_domain(sender[0]["domain"], BRANDS[brand]):
            findings.append(_finding(
                "DISPLAY_NAME_DOMAIN_MISMATCH", "high", "The display name claims a brand the sender domain does not match",
                f"The display name says {display_name!r}, but the address uses {sender[0]['domain']}. Display names can be chosen freely; verify the actual address.",
                "Email headers", 42,
            ))
        if sender and _is_free_mail_domain(sender[0]["domain"]) and re.search(r"(?i)\b(ceo|cfo|chief executive|chief financial|payroll|finance director)\b", display_name):
            findings.append(_finding(
                "EXECUTIVE_DISPLAY_NAME_FREE_MAIL", "high", "An executive-style display name uses a free-mail account",
                f"The display name {display_name!r} claims an executive or finance role, while the sender is {sender[0]['domain']}. Verify the person through a known work contact.",
                "Email headers", 42,
            ))
    display_re = re.compile(r'(?is)(?:"([^"\r\n]{1,100})"|([^<>\r\n]{1,100}?))\s*<\s*([^<>\s]+@[^<>\s]+)\s*>')
    for match in display_re.finditer(_decode_unicode_escapes(text)):
        display_name = (match.group(1) or match.group(2) or "").strip()
        sender = _email_matches(match.group(3))
        brand_in_display = next((brand for brand in BRANDS if brand in _confusable_skeleton(display_name)), None)
        if brand_in_display and sender and not _is_official_brand_domain(sender[0]["domain"], BRANDS[brand_in_display]):
            if not any(item["rule"] == "DISPLAY_NAME_DOMAIN_MISMATCH" for item in findings):
                findings.append(_finding(
                    "DISPLAY_NAME_DOMAIN_MISMATCH", "high", "The display name claims a brand the sender domain does not match",
                    f"The display name says {display_name!r}, but the address uses {sender[0]['domain']}. Display names can be chosen freely; verify the actual address.",
                    "Email address", 52,
                ))
        if sender and _is_free_mail_domain(sender[0]["domain"]) and re.search(r"(?i)\b(ceo|cfo|chief executive|chief financial|payroll|finance director)\b", display_name):
            if not any(item["rule"] == "EXECUTIVE_DISPLAY_NAME_FREE_MAIL" for item in findings):
                findings.append(_finding(
                    "EXECUTIVE_DISPLAY_NAME_FREE_MAIL", "high", "An executive-style display name uses a free-mail account",
                    f"The display name {display_name!r} claims an executive or finance role, while the sender is {sender[0]['domain']}. Verify the person through a known work contact.",
                    "Email address", 42,
                ))
    if from_addresses and reply_addresses:
        from_domain = from_addresses[0]["domain"]
        reply_domain = reply_addresses[0]["domain"]
        if from_domain != reply_domain:
            findings.append(_finding(
                "REPLY_TO_DOMAIN_MISMATCH", "high", "The Reply-To domain differs from the sender domain",
                f"From uses {from_domain}, while Reply-To sends replies to {reply_domain}. A mismatch can be legitimate, but verify the sender before responding.",
                "Email headers", 42,
            ))

    if from_addresses and return_addresses:
        from_domain = from_addresses[0]["domain"]
        return_domain = return_addresses[0]["domain"]
        if from_domain != return_domain:
            findings.append(_finding(
                "RETURN_PATH_DOMAIN_MISMATCH", "low", "The delivery return path differs from the visible sender",
                f"From uses {from_domain}, while Return-Path uses {return_domain}. Mailing services and forwarding can cause this; treat it as context, not proof of phishing.",
                "Email headers", 10,
            ))

    auth = " ".join(headers.get(name, "") for name in ("authentication-results", "received-spf")).lower()
    failed = {method for method in ("spf", "dkim", "dmarc") if re.search(rf"\b{method}\s*=\s*fail\b", auth)}
    passed = {method for method in ("spf", "dkim", "dmarc") if re.search(rf"\b{method}\s*=\s*pass\b", auth)}
    failures = sorted(failed)
    dmarc_pass = "dmarc" in passed
    severe_auth_failure = not dmarc_pass and ("dmarc" in failed or ("spf" in failed and "dkim" in failed))
    if not dmarc_pass and (severe_auth_failure or (failed and not ("dkim" in passed and failed == {"spf"}))):
        findings.append(_finding(
            "EMAIL_AUTHENTICATION_FAILURE", "high", "The email authentication checks failed",
            f"The headers report failed {', '.join(failures)} checks. Authentication failures need investigation alongside the sender and message content.",
            "Email headers", 52,
        ))
    return findings, addresses


def analyze_markup(text: str) -> list[dict]:
    findings = []
    anchor_re = re.compile(r"(?is)<a\b[^>]*\bhref\s*=\s*(['\"])(.*?)\1[^>]*>(.*?)</a\s*>")
    for match in anchor_re.finditer(text):
        href = html.unescape(match.group(2)).strip()
        visible = re.sub(r"(?is)<[^>]+>", " ", match.group(3))
        visible = html.unescape(visible).strip()
        visible_urls = extract_urls(visible)
        if not visible_urls:
            continue
        visible_host = host_parts(visible_urls[0])[0]
        href_host = host_parts(href)[0]
        if visible_host and href_host and visible_host != href_host:
            findings.append(_finding(
                "LINK_TEXT_HREF_MISMATCH", "high", "The link text shows a different destination from its target",
                f"The visible link says {visible_host}, but the embedded target is {href_host}. Check the target before clicking.",
                "Message markup", 52,
            ))
    if re.search(r"(?is)<(?:form\b|input\b[^>]*(?:password|email)|script\b|iframe\b)|\bon(?:load|click)\s*=", text):
        findings.append(_finding(
            "ACTIVE_HTML_CONTENT", "high", "The pasted content contains active HTML or a form",
            "HTML forms, scripts, frames, or event handlers can create interactive content. This text-only checker cannot safely render or fully inspect that page.",
            "Message markup", 48,
        ))
    for match in re.finditer(r"(?i)(?:base64,)?([A-Za-z0-9+/]{80,}={0,2})", text):
        candidate = match.group(1)
        try:
            decoded = base64.b64decode(candidate + "=" * ((4 - len(candidate) % 4) % 4), validate=False).decode("utf-8", "ignore")
        except (binascii.Error, ValueError):
            continue
        if re.search(r"(?is)<(?:html|form|input|script)\b|password|sign\s*in", decoded):
            findings.append(_finding(
                "ENCODED_ACTIVE_HTML", "high", "An encoded payload contains login-like HTML or script content",
                "A base64-like block decodes to HTML, a form, a script, or password-related text. Do not open or execute the attachment; inspect it in a safe analysis environment.",
                "Encoded message content", 52,
            ))
            break
    return findings


def _next_step(score: int, emails: list[dict], urls: list[dict]) -> tuple[str, str]:
    if score >= 75:
        return "Avoid this. Do not open the link, reply, download the file, or share information; verify through a contact method you already trust.", "Avoid — strong warning signs"
    if score >= 50:
        return "Do not use this link or reply address. Open the service’s known app or type its website address yourself.", "High risk — do not use it"
    if score >= 25:
        return "This looks suspicious. Do not sign in, pay, download, or share a code from it until you verify the exact destination or sender.", "Suspicious — verify first"
    if score > 0:
        return "One caution signal appeared. It may be legitimate, but check the exact destination or sender before entering a password, payment details, or a code.", "Caution — check before sharing details"
    if urls:
        return "No obvious red flags were found in this URL. If it is the site you meant to visit and you expected the link, it is reasonable to open. Check the address before signing in.", "No obvious red flags — likely okay if expected"
    if emails:
        return "No obvious warning signs were found in this address or pasted message. If you expected it, it is reasonable to read; confirm the sender before replying or paying.", "No obvious red flags — likely okay to read"
    return "No obvious warning signs were found in the pasted text. If you expected it, it is reasonable to continue; check the sender or address before sharing sensitive details.", "No obvious red flags — likely okay if expected"


def _message_content(text: str) -> str:
    headers = _header_values(text)
    if not headers:
        return text
    parts = re.split(r"\r?\n\s*\r?\n", text, maxsplit=1)
    subject = headers.get("subject", "")
    body = parts[1] if len(parts) == 2 else ""
    return f"{subject}\n{body}"


def analyze_message(text: str) -> list[dict]:
    findings: list[dict] = []
    for pattern, rule, severity, title, evidence_prefix, source, weight in (
        (URGENT_RE, "URGENT_LANGUAGE", "medium", "The message creates time pressure", "It includes", "Message content", 10),
        (CREDENTIAL_RE, "CREDENTIAL_REQUEST", "high", "The message refers to account access or sensitive information", "It includes", "Message content", 18),
        (THREAT_RE, "THREAT_OR_CONSEQUENCE", "medium", "The message threatens a consequence", "It includes", "Message content", 10),
        (PAYMENT_RE, "PAYMENT_CONTEXT", "low", "The message discusses money or payment", "It includes", "Message content", 5),
    ):
        match = pattern.search(text)
        if match:
            findings.append(_finding(rule, severity, title, f"{evidence_prefix} “{match.group(0)}”. This can be a warning sign; verify the request independently.", source, weight))
    if re.search(r"(?i)\b(bank details|bank account|payment details|invoice account)\b.{0,45}\b(changed|change|updated|new|replace|different)\b|\b(changed|change|updated|new|replace|different)\b.{0,45}\b(bank details|bank account|payment details|invoice account)\b", text):
        findings.append(_finding(
            "PAYMENT_DESTINATION_CHANGE", "high", "The message asks you to use changed payment details",
            "Requests to change bank or payment details are a common business-email-compromise pattern. Confirm the change by calling a known contact at a number you already have.",
            "Message content", 52,
        ))
    if re.search(r"(?i)\b(first contact|first time|new vendor|new supplier|new bank account)\b", text) and re.search(r"(?i)\b(gift cards?|wire transfer|bank details|payment|invoice)\b", text) and URGENT_RE.search(text):
        findings.append(_finding(
            "FIRST_CONTACT_URGENT_PAYMENT", "high", "A first-contact request combines urgency with a payment action",
            "The message combines a new contact or vendor, time pressure, and payment language. Verify the person and payment details through a separate trusted channel.",
            "Message content", 42,
        ))
    return findings


def analyze(text: str, input_type: str = "auto") -> dict:
    clean = text.strip()
    urls = extract_urls(clean)
    email_findings, emails = analyze_email(clean)
    message_text = _message_content(clean)
    message_text = URL_RE.sub(" ", message_text)
    message_text = EMAIL_RE.sub(" ", message_text)

    findings = email_findings + analyze_markup(clean)
    if re.search(r"(?i)\b[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+\([^()\r\n]{1,40}\)@[A-Z0-9.-]+\.[A-Z]{2,}\b", clean):
        findings.append(_finding(
            "RFC_COMMENT_EMAIL_SYNTAX", "low", "The sender address contains an unusual comment segment",
            "Comments can appear in standards-compliant email syntax, but they can also make an address harder to read. Inspect the parsed address before replying.",
            "Email address", 8,
        ))
    if input_type != "url":
        findings.extend(analyze_message(message_text))
    for url in urls:
        findings.extend(analyze_url(url))

    seen = set()
    unique = []
    for finding in findings:
        if finding["rule"] not in seen:
            seen.add(finding["rule"])
            unique.append(finding)
    score = min(100, sum(item["weight"] for item in unique))
    if score >= 75:
        verdict, label = "CRITICAL_RISK", "Strong danger signals"
    elif score >= 50:
        verdict, label = "HIGH_RISK", "High risk signals"
    elif score >= 25:
        verdict, label = "MEDIUM_RISK", "Review these risk signals"
    elif score > 0:
        verdict, label = "LOW_RISK", "Caution signal found"
    else:
        verdict, label = "NO_SIGNALS_FOUND", "No obvious signals found"

    if not unique:
        summary = "No obvious warning signs were found in the text you pasted. If you expected it and the sender or domain matches what you intended, it is reasonable to continue. This scan did not inspect the live page or check reputation."
    elif verdict in {"HIGH_RISK", "CRITICAL_RISK"}:
        summary = "Strong warning patterns appeared. Do not use the link, reply address, or attachment; verify through a trusted channel."
    elif verdict == "MEDIUM_RISK":
        summary = "Suspicious patterns appeared. Hold off on signing in, paying, downloading, or sharing codes until you verify the sender or destination."
    else:
        summary = "Warning patterns appeared. Review the evidence; a single caution signal can also occur on legitimate links or emails."

    action, action_label = _next_step(score, emails, urls)
    recommendations = [action]
    if score >= 25:
        recommendations.append("Contact the organization using a phone number or website you already trust, not details in this message.")
    elif score > 0:
        recommendations.append("A low-level warning can be benign; confirm the destination before entering credentials or paying.")
    else:
        recommendations.append("Before signing in or paying, check that the address bar shows the exact site you meant to visit.")
    if score >= 50:
        recommendations.append("If you already shared a password or code, change it through the official service and contact its support team.")
    coverage_notes = [
        "Signal points are matched-rule counts, not a probability or a guarantee of safety.",
        "It cannot resolve a link, check domain age or reputation, detect later content swaps, or inspect QR images and attachments you did not paste as text.",
    ]
    return {
        "verdict": verdict,
        "label": label,
        "action_label": action_label,
        "recommended_action": action,
        "risk_score": score,
        "score_type": "heuristic",
        "summary": summary,
        "findings": unique,
        "urls": [{"value": url, "host": host_parts(url)[0]} for url in urls],
        "emails": [{"value": email["value"], "domain": email["domain"]} for email in emails],
        "reputation": {"status": "not_checked", "detail": "No external reputation provider is configured; this result uses explainable local checks only."},
        "live_inspection": {"status": "not_requested", "provider": "TinyFish", "detail": "Live page inspection was not requested.", "pages": []},
        "recommendations": recommendations,
        "coverage_notes": coverage_notes,
        "input_type": input_type,
        "analyzed_length": len(clean),
    }


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "service": "Trapdoor", "version": "0.5.0",
                    "tinyfish_configured": bool(_tinyfish_api_key())})


@app.post("/api/analyze")
def analyze_api():
    payload = request.get_json(silent=True) or {}
    text = payload.get("text", "")
    input_type = payload.get("input_type", "auto")
    if not isinstance(text, str):
        return jsonify({"error": "Text must be a string."}), 400
    if not text.strip():
        return jsonify({"error": "Paste a URL, email, or text message to investigate."}), 400
    if len(text) > 20000:
        return jsonify({"error": "Input is too long. Please keep it under 20,000 characters."}), 413
    if input_type not in {"auto", "url", "email", "sms"}:
        return jsonify({"error": "Choose URL, email, SMS, or automatic detection."}), 400
    report = analyze(text, input_type)
    if payload.get("tinyfish_enabled") is True:
        safe_urls = []
        for item in report["urls"]:
            safe_url = _tinyfish_safe_url(item["value"])
            if safe_url and safe_url not in safe_urls:
                safe_urls.append(safe_url)
        inspection = _tinyfish_fetch(safe_urls[:TINYFISH_MAX_URLS])
        if len(safe_urls) > TINYFISH_MAX_URLS:
            inspection["detail"] += f" Only the first {TINYFISH_MAX_URLS} eligible URLs were checked."
        report["live_inspection"] = inspection
        if inspection["status"] == "checked":
            _add_tinyfish_findings(report, inspection)
    return jsonify(report)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

