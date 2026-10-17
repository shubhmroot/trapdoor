"""Trapdoor: evidence-first phishing investigation demo."""

from __future__ import annotations

import ipaddress
import re
from difflib import SequenceMatcher
from urllib.parse import urlsplit

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024

BRANDS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com"],
    "google": ["google.com", "gmail.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.in"],
    "bank": [],
}

URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"']+")
URGENT_RE = re.compile(r"\b(urgent|immediately|within\s+\d+\s+hours?|today|suspended|blocked|limited time|act now|final notice)\b", re.I)
CREDENTIAL_RE = re.compile(r"\b(password|verify your account|sign in|login|credentials|one[- ]time code|otp|card number|ssn|social security)\b", re.I)
THREAT_RE = re.compile(r"\b(account (?:will be|has been) (?:closed|blocked|suspended)|legal action|will be terminated|unusual activity)\b", re.I)
PAYMENT_RE = re.compile(r"\b(payment|invoice|refund|wire transfer|gift card|crypto(?:currency)?)\b", re.I)


def extract_urls(text: str) -> list[str]:
    found = URL_RE.findall(text)
    return [item.rstrip(".,!?;:)") for item in found][:10]


def normalized_url(value: str) -> str:
    candidate = value.strip()
    if candidate.lower().startswith("www."):
        candidate = "http://" + candidate
    return candidate


def host_parts(value: str) -> tuple[str | None, str | None, str | None]:
    try:
        parsed = urlsplit(normalized_url(value))
        host = (parsed.hostname or "").rstrip(".").lower()
        if not host:
            return None, parsed.scheme.lower() or None, None
        try:
            ipaddress.ip_address(host)
            registrable = host
        except ValueError:
            labels = host.split(".")
            registrable = ".".join(labels[-2:]) if len(labels) >= 2 else host
        return host, parsed.scheme.lower() or None, registrable
    except ValueError:
        return None, None, None


def analyze_url(url: str) -> list[dict]:
    findings: list[dict] = []
    host, scheme, registrable = host_parts(url)
    if not host:
        return findings

    try:
        ipaddress.ip_address(host)
        findings.append({"rule": "IP_ADDRESS_HOST", "severity": "medium", "title": "The link uses an IP address", "evidence": f"The hostname is {host}, rather than a named domain.", "source": "URL structure", "weight": 15})
    except ValueError:
        pass

    if scheme == "http":
        findings.append({"rule": "NO_HTTPS", "severity": "low", "title": "The link does not use HTTPS", "evidence": "The URL begins with http://. Encryption alone cannot establish trust, but its absence is a useful caution signal.", "source": "URL structure", "weight": 5})

    if "@" in urlsplit(normalized_url(url)).netloc:
        findings.append({"rule": "AT_SIGN_IN_AUTHORITY", "severity": "high", "title": "The URL contains an @ sign in its authority", "evidence": "Text before @ can look like a trusted site name while the browser connects to the host after it.", "source": "URL structure", "weight": 20})

    if host.count("-") >= 2 or len(host) > 45:
        findings.append({"rule": "UNUSUAL_HOSTNAME", "severity": "low", "title": "The hostname has an unusual shape", "evidence": f"The hostname {host} is unusually long or contains several hyphens.", "source": "URL structure", "weight": 8})

    if re.search(r"%[0-9a-f]{2}", url, re.I) or "xn--" in host:
        findings.append({"rule": "ENCODED_OR_PUNYCODE", "severity": "medium", "title": "The URL contains encoded or internationalized text", "evidence": "Encoded characters or a punycode label can make a destination harder to read. This is a review signal, not proof of deception.", "source": "URL structure", "weight": 12})

    host_labels = [label for label in re.split(r"[.-]", host) if label]
    for brand, official_domains in BRANDS.items():
        if not official_domains or any(host == domain or host.endswith("." + domain) for domain in official_domains):
            continue
        brand_match = brand in host.replace("-", "").replace(".", "")
        near_match = any(
            len(label) >= 4 and SequenceMatcher(None, label, brand).ratio() >= 0.8
            for label in host_labels
        )
        if brand_match or near_match:
            findings.append({"rule": "BRAND_NAME_IN_DOMAIN", "severity": "high", "title": f"The hostname mentions {brand.title()} outside its official domain", "evidence": f"The registrable domain is {registrable}; a brand name in a hostname does not make that domain official.", "source": "Hostname comparison", "weight": 25})
            break
    return findings


def analyze_message(text: str) -> list[dict]:
    findings: list[dict] = []
    if URGENT_RE.search(text):
        match = URGENT_RE.search(text)
        findings.append({"rule": "URGENT_LANGUAGE", "severity": "medium", "title": "The message creates time pressure", "evidence": f"It includes the phrase “{match.group(0)}”. Urgency can pressure people to act before checking.", "source": "Message content", "weight": 10})
    if CREDENTIAL_RE.search(text):
        match = CREDENTIAL_RE.search(text)
        findings.append({"rule": "CREDENTIAL_REQUEST", "severity": "high", "title": "The message refers to account access or sensitive information", "evidence": f"It includes “{match.group(0)}”. A request to verify credentials or share a code deserves independent verification.", "source": "Message content", "weight": 18})
    if THREAT_RE.search(text):
        match = THREAT_RE.search(text)
        findings.append({"rule": "THREAT_OR_CONSEQUENCE", "severity": "medium", "title": "The message threatens a consequence", "evidence": f"It includes “{match.group(0)}”. Threats can be used to prompt a rushed response.", "source": "Message content", "weight": 10})
    if PAYMENT_RE.search(text):
        match = PAYMENT_RE.search(text)
        findings.append({"rule": "PAYMENT_CONTEXT", "severity": "low", "title": "The message discusses money or payment", "evidence": f"It includes “{match.group(0)}”. Payment context is worth checking against a known contact or account.", "source": "Message content", "weight": 5})
    return findings


def analyze(text: str, input_type: str = "auto") -> dict:
    clean = text.strip()
    urls = extract_urls(clean)
    findings = analyze_message(clean)
    for url in urls:
        findings.extend(analyze_url(url))

    seen = set()
    unique = []
    for finding in findings:
        if finding["rule"] not in seen:
            seen.add(finding["rule"])
            unique.append(finding)
    score = min(100, sum(item["weight"] for item in unique))
    if score >= 40:
        verdict, label = "HIGH_RISK", "High risk signals"
    elif score >= 20:
        verdict, label = "MEDIUM_RISK", "Some risk signals"
    elif score > 0:
        verdict, label = "LOW_RISK", "A few caution signals"
    elif urls:
        verdict, label = "NO_SIGNALS_FOUND", "No obvious signals found"
    else:
        verdict, label = "NO_SIGNALS_FOUND", "No obvious signals found"

    if not findings:
        summary = "The checks in this demo did not find a known warning pattern. That does not confirm the content is safe."
    elif verdict == "HIGH_RISK":
        summary = "Several warning patterns appeared. Pause and verify through a trusted channel before taking action."
    else:
        summary = "Some warning patterns appeared. Review each finding and verify the sender or destination independently."

    recommendations = ["Do not enter passwords, payment details, or one-time codes from this message.", "Contact the organization using a phone number or website you already trust.", "If you already shared information, change the affected password and contact the relevant provider."]
    return {
        "verdict": verdict,
        "label": label,
        "risk_score": score,
        "score_type": "heuristic",
        "summary": summary,
        "findings": unique,
        "urls": [{"value": url, "host": host_parts(url)[0]} for url in urls],
        "reputation": {"status": "not_checked", "detail": "No external reputation provider is configured in this demo."},
        "recommendations": recommendations,
        "input_type": input_type,
        "analyzed_length": len(clean),
    }


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "service": "Trapdoor", "version": "0.1.0"})


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
    return jsonify(analyze(text, input_type))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

