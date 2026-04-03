#!/usr/bin/env python3
"""
AI Phishing Detector
=====================
Detects phishing attempts by analyzing URLs, email headers, email body
content, and extracted links. Uses heuristic scoring, pattern matching,
and domain reputation checks to assign a phishing risk score.

Author: Egwu Donatus Achema
Usage:
    python ai_phishing_detector.py --url "http://paypa1-secure.com/login"
    python ai_phishing_detector.py --email sample.eml --report report.html
    python ai_phishing_detector.py --list urls.txt --report report.html
    python ai_phishing_detector.py --demo --report report.html
"""

import argparse
import email
import email.policy
import json
import re
import socket
import ssl
import sys
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime
from email.header import decode_header
from html.parser import HTMLParser
from pathlib import Path
from typing import Optional

# ── ANSI Colours ───────────────────────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    BLUE   = "\033[94m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

# ── Phishing Keywords ──────────────────────────────────────────────────────────
PHISHING_KEYWORDS = [
    "verify your account", "confirm your identity", "update your information",
    "suspended account", "unusual activity", "click here immediately",
    "your account will be closed", "verify now", "login immediately",
    "security alert", "unauthorized access", "reset your password",
    "confirm your email", "billing information", "payment failed",
    "account compromised", "act now", "urgent action required",
    "limited time offer", "winner", "you have been selected",
    "congratulations", "claim your prize", "free gift",
    "your paypal", "your apple id", "your amazon account",
    "dear customer", "dear user", "dear account holder",
]

URGENCY_KEYWORDS = [
    "urgent", "immediately", "act now", "expires", "limited",
    "warning", "alert", "attention", "important", "critical",
    "last chance", "final notice", "deadline", "suspend",
]

SENSITIVE_KEYWORDS = [
    "password", "credit card", "social security", "ssn", "bank account",
    "routing number", "pin", "cvv", "date of birth", "passport",
    "driver license", "login credentials", "username",
]

# ── Suspicious URL Patterns ────────────────────────────────────────────────────
SUSPICIOUS_TLD = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
    ".online", ".site", ".website", ".space", ".fun", ".icu",
    ".buzz", ".monster", ".rest",
}

BRAND_KEYWORDS = [
    "paypal", "apple", "amazon", "google", "microsoft", "facebook",
    "netflix", "instagram", "twitter", "linkedin", "dropbox",
    "chase", "wellsfargo", "bankofamerica", "citibank", "hsbc",
    "ebay", "walmart", "fedex", "ups", "dhl", "usps",
]

IP_IN_URL_RE      = re.compile(r"https?://(\d{1,3}\.){3}\d{1,3}")
SUBDOMAIN_RE      = re.compile(r"https?://([^/]+)")
URL_RE            = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
AT_IN_URL_RE      = re.compile(r"https?://[^@]*@")
HOMOGLYPH_RE      = re.compile(r"[а-яёА-ЯЁ\u00e0-\u024f]")  # Cyrillic/Latin lookalikes
DOUBLE_DASH_RE    = re.compile(r"--")
LONG_SUBDOMAIN_RE = re.compile(r"([a-z0-9-]+\.){4,}")

# ── Known phishing/malicious domain fragments ──────────────────────────────────
MALICIOUS_FRAGMENTS = [
    "secure-login", "account-verify", "update-billing", "signin-",
    "verify-", "login-secure", "account-suspended", "unlock-account",
    "confirm-email", "secure-update", "-login", "webscr",
    "cmd=_login", "ebayisapi", "banking-secure",
]

# ── Trusted domains (whitelist) ───────────────────────────────────────────────
TRUSTED_DOMAINS = {
    "google.com", "gmail.com", "microsoft.com", "outlook.com",
    "apple.com", "amazon.com", "paypal.com", "facebook.com",
    "twitter.com", "linkedin.com", "github.com", "stackoverflow.com",
    "wikipedia.org", "youtube.com", "instagram.com",
}

# ── Demo data ─────────────────────────────────────────────────────────────────
DEMO_URLS = [
    "http://paypa1-secure-login.tk/account/verify",
    "https://192.168.1.100/apple-id/reset",
    "http://amazon-account-suspended.xyz/update/billing",
    "https://www.google.com",
    "http://secure-bankofamerica-login.com/signin",
    "https://github.com/Don-cybertech",
    "http://netflix-billing-update.top/payment",
    "https://microsoft-account-verify.ml/login",
]

DEMO_EMAIL = """From: "PayPal Security" <security@paypa1-support.tk>
To: victim@gmail.com
Subject: URGENT: Your PayPal Account Has Been Suspended
Date: Thu, 01 Apr 2026 09:00:00 +0000
Reply-To: noreply@paypa1-support.tk
Message-ID: <fake123@paypa1-support.tk>

Dear Customer,

We have detected unusual activity on your PayPal account. Your account has been
temporarily suspended due to unauthorized access attempts.

You must verify your account immediately or it will be permanently closed within
24 hours.

Click here immediately to restore access:
http://paypa1-secure-login.tk/account/verify?user=victim@gmail.com

Please confirm your identity by providing:
- Your password
- Credit card number
- Date of birth

Act now. This is your final notice.

PayPal Security Team
"""


# ══════════════════════════════════════════════════════════════════════════════
class PhishingIndicator:
    """A single phishing indicator with score contribution."""

    def __init__(self, category: str, description: str,
                 score: int, severity: str):
        self.category    = category
        self.description = description
        self.score       = score
        self.severity    = severity

    def to_dict(self):
        return vars(self)


# ══════════════════════════════════════════════════════════════════════════════
class PhishingResult:
    """Result of a phishing analysis."""

    THRESHOLDS = {
        "SAFE":       (0,  20),
        "SUSPICIOUS": (21, 50),
        "LIKELY":     (51, 75),
        "PHISHING":   (76, 100),
    }

    def __init__(self, target: str, target_type: str):
        self.target      = target
        self.target_type = target_type
        self.indicators: list[PhishingIndicator] = []
        self.raw_score   = 0
        self.verdict     = "SAFE"
        self.ts          = datetime.now().isoformat(timespec="seconds")

    def add(self, indicator: PhishingIndicator):
        self.indicators.append(indicator)
        self.raw_score = min(100, self.raw_score + indicator.score)

    def finalize(self):
        for verdict, (low, high) in self.THRESHOLDS.items():
            if low <= self.raw_score <= high:
                self.verdict = verdict
                break

    @property
    def verdict_colour(self):
        return {
            "SAFE":       C.GREEN,
            "SUSPICIOUS": C.YELLOW,
            "LIKELY":     C.YELLOW,
            "PHISHING":   C.RED,
        }.get(self.verdict, C.RESET)

    def __str__(self):
        col = self.verdict_colour
        lines = [
            f"\n{C.BOLD}{C.CYAN}{'─'*60}{C.RESET}",
            f"{C.BOLD}Target  : {self.target[:80]}{C.RESET}",
            f"{C.BOLD}Type    : {self.target_type}{C.RESET}",
            f"{col}{C.BOLD}Verdict : {self.verdict} (Score: {self.raw_score}/100){C.RESET}",
        ]
        if self.indicators:
            lines.append(f"\n{C.BOLD}Indicators:{C.RESET}")
            for ind in self.indicators:
                sev_col = {
                    "HIGH": C.RED, "MEDIUM": C.YELLOW, "LOW": C.CYAN
                }.get(ind.severity, C.RESET)
                lines.append(
                    f"  {sev_col}[{ind.severity}]{C.RESET} "
                    f"{ind.category}: {ind.description} (+{ind.score})"
                )
        return "\n".join(lines)

    def to_dict(self):
        return {
            "target": self.target,
            "target_type": self.target_type,
            "verdict": self.verdict,
            "score": self.raw_score,
            "ts": self.ts,
            "indicators": [i.to_dict() for i in self.indicators],
        }


# ══════════════════════════════════════════════════════════════════════════════
class URLAnalyzer:
    """Analyzes a URL for phishing indicators."""

    def analyze(self, url: str) -> PhishingResult:
        result = PhishingResult(url, "URL")
        url_lower = url.lower()

        # 1. IP address in URL
        if IP_IN_URL_RE.match(url):
            result.add(PhishingIndicator(
                "URL Structure", "IP address used instead of domain name",
                25, "HIGH"
            ))

        # 2. Suspicious TLD
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower().split(":")[0]
            for tld in SUSPICIOUS_TLD:
                if domain.endswith(tld):
                    result.add(PhishingIndicator(
                        "Suspicious TLD", f"Domain uses high-risk TLD: {tld}",
                        20, "HIGH"
                    ))
                    break
        except Exception:
            pass

        # 3. Brand name in subdomain (not in main domain)
        try:
            parts = domain.split(".")
            if len(parts) >= 3:
                subdomain = ".".join(parts[:-2])
                for brand in BRAND_KEYWORDS:
                    if brand in subdomain:
                        result.add(PhishingIndicator(
                            "Brand Impersonation",
                            f"Brand name '{brand}' found in subdomain",
                            30, "HIGH"
                        ))
                        break
        except Exception:
            pass

        # 4. Brand name in domain but not trusted
        try:
            root_domain = ".".join(domain.split(".")[-2:])
            for brand in BRAND_KEYWORDS:
                if brand in domain and root_domain not in TRUSTED_DOMAINS:
                    result.add(PhishingIndicator(
                        "Brand Impersonation",
                        f"Brand name '{brand}' in untrusted domain",
                        25, "HIGH"
                    ))
                    break
        except Exception:
            pass

        # 5. @ symbol in URL
        if AT_IN_URL_RE.search(url):
            result.add(PhishingIndicator(
                "URL Obfuscation", "@ symbol in URL used to hide real destination",
                20, "HIGH"
            ))

        # 6. Homoglyph / lookalike characters
        if HOMOGLYPH_RE.search(url):
            result.add(PhishingIndicator(
                "Homoglyph Attack", "Unicode lookalike characters detected in URL",
                25, "HIGH"
            ))

        # 7. Excessive subdomains
        if LONG_SUBDOMAIN_RE.search(domain if 'domain' in dir() else url):
            result.add(PhishingIndicator(
                "URL Structure", "Excessive subdomains — common phishing tactic",
                15, "MEDIUM"
            ))

        # 8. Double dash in domain
        if DOUBLE_DASH_RE.search(url_lower):
            result.add(PhishingIndicator(
                "URL Structure", "Double dash in URL — common phishing pattern",
                10, "MEDIUM"
            ))

        # 9. Malicious URL fragments
        for fragment in MALICIOUS_FRAGMENTS:
            if fragment in url_lower:
                result.add(PhishingIndicator(
                    "Malicious Pattern",
                    f"Known phishing URL pattern: '{fragment}'",
                    20, "HIGH"
                ))
                break

        # 10. URL length
        if len(url) > 100:
            result.add(PhishingIndicator(
                "URL Structure", f"Unusually long URL ({len(url)} chars)",
                10, "MEDIUM"
            ))

        # 11. HTTP (no SSL)
        if url.startswith("http://"):
            result.add(PhishingIndicator(
                "No HTTPS", "URL uses unencrypted HTTP",
                10, "MEDIUM"
            ))

        # 12. Trusted domain — reduce score
        try:
            root = ".".join(domain.split(".")[-2:])
            if root in TRUSTED_DOMAINS:
                result.raw_score = max(0, result.raw_score - 30)
                result.add(PhishingIndicator(
                    "Trusted Domain", f"{root} is a known trusted domain",
                    -30, "LOW"
                ))
        except Exception:
            pass

        result.finalize()
        return result


# ══════════════════════════════════════════════════════════════════════════════
class EmailAnalyzer:
    """Analyzes an email message for phishing indicators."""

    def __init__(self):
        self.url_analyzer = URLAnalyzer()

    def analyze_text(self, raw_email: str) -> PhishingResult:
        """Analyze raw email text."""
        try:
            msg = email.message_from_string(
                raw_email, policy=email.policy.default
            )
        except Exception:
            msg = email.message_from_string(raw_email)

        subject = self._decode_header(msg.get("Subject", ""))
        sender  = msg.get("From", "")
        reply_to = msg.get("Reply-To", "")
        msg_id  = msg.get("Message-ID", "")

        result = PhishingResult(
            f"Email: {subject[:60]}", "Email"
        )

        # ── Header Analysis ───────────────────────────────────────────────────

        # 1. Sender domain vs Reply-To domain mismatch
        sender_domain   = self._extract_domain(sender)
        reply_to_domain = self._extract_domain(reply_to)
        if reply_to and sender_domain and reply_to_domain:
            if sender_domain != reply_to_domain:
                result.add(PhishingIndicator(
                    "Header Spoofing",
                    f"Sender domain ({sender_domain}) differs from "
                    f"Reply-To ({reply_to_domain})",
                    25, "HIGH"
                ))

        # 2. Suspicious sender domain
        if sender_domain:
            for tld in SUSPICIOUS_TLD:
                if sender_domain.endswith(tld):
                    result.add(PhishingIndicator(
                        "Suspicious Sender",
                        f"Sender uses high-risk TLD: {sender_domain}",
                        20, "HIGH"
                    ))
                    break

        # 3. Brand impersonation in sender name but not domain
        sender_lower = sender.lower()
        for brand in BRAND_KEYWORDS:
            if brand in sender_lower and sender_domain:
                root = ".".join(sender_domain.split(".")[-2:])
                if root not in TRUSTED_DOMAINS and brand not in sender_domain:
                    result.add(PhishingIndicator(
                        "Sender Impersonation",
                        f"Claims to be '{brand}' but domain is '{sender_domain}'",
                        30, "HIGH"
                    ))
                    break

        # 4. Urgency in subject
        subject_lower = subject.lower()
        urgency_found = [k for k in URGENCY_KEYWORDS if k in subject_lower]
        if urgency_found:
            result.add(PhishingIndicator(
                "Urgency Tactics",
                f"Urgency keywords in subject: {', '.join(urgency_found[:3])}",
                15, "MEDIUM"
            ))

        # 5. Phishing keywords in subject
        for kw in PHISHING_KEYWORDS:
            if kw in subject_lower:
                result.add(PhishingIndicator(
                    "Phishing Subject",
                    f"Known phishing phrase in subject: '{kw}'",
                    15, "MEDIUM"
                ))
                break

        # ── Body Analysis ─────────────────────────────────────────────────────
        body = self._get_body(msg)
        body_lower = body.lower()

        # 6. Phishing keywords in body
        found_kw = [kw for kw in PHISHING_KEYWORDS if kw in body_lower]
        if found_kw:
            result.add(PhishingIndicator(
                "Phishing Content",
                f"Phishing phrases detected: {', '.join(found_kw[:3])}",
                20, "HIGH"
            ))

        # 7. Urgency keywords in body
        found_urgency = [k for k in URGENCY_KEYWORDS if k in body_lower]
        if len(found_urgency) >= 3:
            result.add(PhishingIndicator(
                "Urgency Tactics",
                f"Multiple urgency keywords: {', '.join(found_urgency[:4])}",
                15, "MEDIUM"
            ))

        # 8. Sensitive data requests
        found_sensitive = [k for k in SENSITIVE_KEYWORDS if k in body_lower]
        if found_sensitive:
            result.add(PhishingIndicator(
                "Sensitive Data Request",
                f"Requests sensitive info: {', '.join(found_sensitive[:3])}",
                25, "HIGH"
            ))

        # 9. Generic greeting
        generic = ["dear customer", "dear user", "dear account holder",
                   "dear member", "hello user"]
        for g in generic:
            if g in body_lower:
                result.add(PhishingIndicator(
                    "Generic Greeting",
                    f"Impersonal greeting detected: '{g}'",
                    10, "MEDIUM"
                ))
                break

        # 10. URL analysis on links in body
        urls = URL_RE.findall(body)
        suspicious_urls = 0
        for url in urls[:10]:  # Limit to first 10 URLs
            url_result = self.url_analyzer.analyze(url)
            if url_result.verdict in ("PHISHING", "LIKELY"):
                suspicious_urls += 1
                result.add(PhishingIndicator(
                    "Suspicious Link",
                    f"Phishing URL in body: {url[:70]}",
                    20, "HIGH"
                ))

        # 11. Link/text mismatch (display text differs from href)
        mismatches = self._find_link_mismatches(body)
        if mismatches:
            result.add(PhishingIndicator(
                "Link Mismatch",
                f"Display text doesn't match URL destination",
                20, "HIGH"
            ))

        result.finalize()
        return result

    def analyze_file(self, path: str) -> PhishingResult:
        try:
            raw = Path(path).read_text(encoding="utf-8", errors="replace")
            return self.analyze_text(raw)
        except Exception as e:
            r = PhishingResult(path, "Email")
            r.add(PhishingIndicator("Error", str(e), 0, "LOW"))
            r.finalize()
            return r

    def _decode_header(self, value: str) -> str:
        try:
            parts = decode_header(value)
            decoded = []
            for part, enc in parts:
                if isinstance(part, bytes):
                    decoded.append(part.decode(enc or "utf-8", errors="replace"))
                else:
                    decoded.append(str(part))
            return " ".join(decoded)
        except Exception:
            return value

    def _extract_domain(self, address: str) -> str:
        m = re.search(r"@([\w.-]+)", address)
        return m.group(1).lower() if m else ""

    def _get_body(self, msg) -> str:
        body = ""
        try:
            if msg.is_multipart():
                for part in msg.walk():
                    ct = part.get_content_type()
                    if ct in ("text/plain", "text/html"):
                        body += part.get_payload(decode=True).decode(
                            errors="replace"
                        )
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    body = payload.decode(errors="replace")
                else:
                    body = str(msg.get_payload())
        except Exception:
            body = str(msg.get_payload() or "")
        return body

    def _find_link_mismatches(self, body: str) -> list:
        pattern = re.compile(
            r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>',
            re.IGNORECASE
        )
        mismatches = []
        for href, text in pattern.findall(body):
            text = text.strip().lower()
            href = href.strip().lower()
            if text.startswith("http") and text != href:
                mismatches.append((text, href))
        return mismatches


# ══════════════════════════════════════════════════════════════════════════════
class ReportGenerator:
    """Generates a dark-themed HTML phishing detection report."""

    VERDICT_COLOURS = {
        "SAFE":       "#2ecc71",
        "SUSPICIOUS": "#e67e22",
        "LIKELY":     "#e67e22",
        "PHISHING":   "#e74c3c",
    }

    SEVERITY_COLOURS = {
        "HIGH":   "#e74c3c",
        "MEDIUM": "#e67e22",
        "LOW":    "#2ecc71",
    }

    def generate(self, results: list[PhishingResult], path: str):
        counts = {"SAFE": 0, "SUSPICIOUS": 0, "LIKELY": 0, "PHISHING": 0}
        for r in results:
            counts[r.verdict] = counts.get(r.verdict, 0) + 1

        badges = ""
        for verdict, col in self.VERDICT_COLOURS.items():
            badges += (
                f"<div class='badge' style='border-color:{col}'>"
                f"<span style='color:{col}'>{verdict}</span>"
                f"<strong>{counts.get(verdict, 0)}</strong></div>"
            )

        rows = ""
        for r in results:
            col = self.VERDICT_COLOURS.get(r.verdict, "#fff")
            indicator_list = "".join(
                f"<li><span style='color:{self.SEVERITY_COLOURS.get(i.severity,'#fff')}'>"
                f"[{i.severity}]</span> {i.category}: {i.description} "
                f"<em>(+{i.score})</em></li>"
                for i in r.indicators if i.score > 0
            )
            rows += f"""
            <tr>
              <td style='word-break:break-all;max-width:200px'>{r.target[:80]}</td>
              <td>{r.target_type}</td>
              <td style='color:{col};font-weight:bold'>{r.verdict}</td>
              <td style='color:{col};font-weight:bold'>{r.raw_score}/100</td>
              <td><ul style='padding-left:1rem;font-size:.8em'>{indicator_list}</ul></td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang='en'>
<head>
  <meta charset='utf-8'>
  <title>Phishing Detection Report</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:2rem}}
    h1{{color:#58a6ff;margin-bottom:.5rem}}
    .meta{{color:#8b949e;font-size:.85em;margin-bottom:1.5rem}}
    .summary{{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:2rem}}
    .badge{{border:1px solid;border-radius:8px;padding:.5rem 1.2rem;
            display:flex;flex-direction:column;align-items:center;min-width:110px}}
    .badge span{{font-size:.75em}}
    .badge strong{{font-size:1.6em}}
    table{{width:100%;border-collapse:collapse;font-size:.82em}}
    th{{background:#161b22;color:#58a6ff;padding:.6rem .5rem;text-align:left}}
    td{{padding:.5rem;border-bottom:1px solid #21262d;vertical-align:top}}
    tr:hover{{background:#161b22}}
    ul{{list-style:disc;margin:.3rem 0}}
    li{{margin:.2rem 0;line-height:1.4}}
  </style>
</head>
<body>
  <h1>AI Phishing Detection Report</h1>
  <div class='meta'>
    Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")} |
    Total Analyzed: {len(results)} |
    Phishing Detected: {counts.get("PHISHING", 0)}
  </div>
  <div class='summary'>{badges}</div>
  <table>
    <thead><tr>
      <th>Target</th><th>Type</th><th>Verdict</th>
      <th>Score</th><th>Indicators</th>
    </tr></thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>"""

        Path(path).write_text(html, encoding="utf-8")
        print(f"{C.GREEN}[+] Report saved → {path}{C.RESET}")


# ══════════════════════════════════════════════════════════════════════════════
def print_banner():
    print(f"""{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════╗
║          AI Phishing Detector v1.0           ║
║          Author: Egwu Donatus Achema         ║
╚══════════════════════════════════════════════╝
{C.RESET}""")

def print_summary(results: list[PhishingResult]):
    total    = len(results)
    phishing = len([r for r in results if r.verdict == "PHISHING"])
    likely   = len([r for r in results if r.verdict == "LIKELY"])
    susp     = len([r for r in results if r.verdict == "SUSPICIOUS"])
    safe     = len([r for r in results if r.verdict == "SAFE"])

    print(f"\n{C.BOLD}{'═'*60}{C.RESET}")
    print(f"{C.BOLD}  ANALYSIS COMPLETE{C.RESET}")
    print(f"{'═'*60}")
    print(f"  Total Analyzed : {total}")
    print(f"  {C.RED}Phishing       : {phishing}{C.RESET}")
    print(f"  {C.YELLOW}Likely         : {likely}{C.RESET}")
    print(f"  {C.YELLOW}Suspicious     : {susp}{C.RESET}")
    print(f"  {C.GREEN}Safe           : {safe}{C.RESET}")
    print(f"{'═'*60}\n")

def parse_args():
    p = argparse.ArgumentParser(
        description="AI Phishing Detector — URL, Email, and Link Analysis"
    )
    p.add_argument("--url",    help="Single URL to analyze")
    p.add_argument("--email",  help="Path to .eml email file")
    p.add_argument("--list",   help="Text file with one URL per line")
    p.add_argument("--demo",   action="store_true",
                   help="Run demo analysis on built-in phishing samples")
    p.add_argument("--report", metavar="HTML",
                   help="Save HTML report to this file")
    return p.parse_args()


# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    args = parse_args()
    print_banner()

    if not any([args.url, args.email, args.list, args.demo]):
        print(f"{C.RED}[!] Specify --url, --email, --list, or --demo.{C.RESET}")
        print(f"{C.YELLOW}    Use --help for usage.{C.RESET}")
        sys.exit(1)

    url_analyzer   = URLAnalyzer()
    email_analyzer = EmailAnalyzer()
    results: list[PhishingResult] = []

    # Single URL
    if args.url:
        print(f"{C.CYAN}[*] Analyzing URL...{C.RESET}")
        r = url_analyzer.analyze(args.url)
        results.append(r)
        print(r)

    # Email file
    if args.email:
        print(f"{C.CYAN}[*] Analyzing email: {args.email}{C.RESET}")
        r = email_analyzer.analyze_file(args.email)
        results.append(r)
        print(r)

    # URL list file
    if args.list:
        print(f"{C.CYAN}[*] Analyzing URLs from {args.list}...{C.RESET}")
        try:
            urls = Path(args.list).read_text(encoding="utf-8").splitlines()
            urls = [u.strip() for u in urls if u.strip() and not u.startswith("#")]
            for url in urls:
                r = url_analyzer.analyze(url)
                results.append(r)
                print(r)
        except Exception as e:
            print(f"{C.RED}[!] Cannot read file: {e}{C.RESET}")

    # Demo mode
    if args.demo:
        print(f"{C.CYAN}[*] Running demo analysis...{C.RESET}")
        print(f"\n{C.BOLD}--- URL Analysis ---{C.RESET}")
        for url in DEMO_URLS:
            r = url_analyzer.analyze(url)
            results.append(r)
            print(r)

        print(f"\n{C.BOLD}--- Email Analysis ---{C.RESET}")
        r = email_analyzer.analyze_text(DEMO_EMAIL)
        results.append(r)
        print(r)

    print_summary(results)

    if args.report:
        ReportGenerator().generate(results, args.report)
    else:
        print(f"{C.YELLOW}[!] Tip: Add --report report.html to save an HTML report.{C.RESET}")
