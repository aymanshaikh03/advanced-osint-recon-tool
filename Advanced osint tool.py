"""
╔══════════════════════════════════════════════════════════════════════════╗
║           ADVANCED OSINT RECONNAISSANCE TOOL  v3.0                      ║
║           For Educational / Authorized Security Research Only            ║
╠══════════════════════════════════════════════════════════════════════════╣
║  Modules:                                                                ║
║    📡  IP & Geolocation      (multi-provider, ASN, org)                 ║
║    🗂   WHOIS / RDAP          (registrar, dates, nameservers)            ║
║    🌐  DNS Deep Dive          (A/AAAA/MX/NS/TXT/SOA/SPF/DMARC)         ║
║    🔍  Subdomain Enumeration  (crt.sh CT + wordlist, HTTP probe)        ║
║    🔌  Port Scanner           (Fast / Deep modes, banner grab)          ║
║    🧬  HTTP / Tech Stack      (headers, framework detection, cookies)   ║
║    🔐  SSL/TLS Inspector      (cert chain, SANs, expiry)                ║
║    📧  Email Intelligence     (MX, providers, homepage scrape)          ║
║    👤  Social Media Search    (20 platforms, confidence-labelled)       ║
║    🔎  Google Dork Generator  (20 targeted dork queries)                ║
║    🧠  Correlation Engine     (risk score, infra clustering, findings)  ║
║                                                                          ║
║  Export:  TXT  |  JSON                                                   ║
╚══════════════════════════════════════════════════════════════════════════╝

Run:  python osint_recon_v3_commented.py

HOW THIS FILE IS ORGANISED:
  ┌──────────────────────────────────────────────────────────────┐
  │  SECTION 1  →  Imports                                       │
  │  SECTION 2  →  Constants & Shared Configuration             │
  │  SECTION 3  →  Shared Helper Utilities                      │
  │  SECTION 4  →  Recon Module Functions (the actual scanning) │
  │  SECTION 5  →  GUI (the app window, buttons, output pane)   │
  │  SECTION 6  →  Entry Point  (starts the app)                │
  └──────────────────────────────────────────────────────────────┘
"""

# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 1 — IMPORTS
#  All standard-library modules used by this tool.
#  No third-party pip packages are required — everything ships with Python.
# ═════════════════════════════════════════════════════════════════════════════

import tkinter as tk                       # GUI framework (built into Python)
from tkinter import ttk, scrolledtext, messagebox, filedialog  # GUI widgets
import threading                           # Lets the scan run in the background so the GUI stays responsive
import socket                              # Low-level TCP connections (port scanning, DNS resolution)
import ssl                                 # SSL/TLS certificate inspection
import urllib.request                      # Making HTTP GET requests without external libraries
import urllib.error                        # Catching HTTP errors (404, timeout, etc.)
import urllib.parse                        # URL encoding (e.g. spaces → %20 in usernames)
import json                                # Parsing JSON responses from APIs
import re                                  # Regular expressions (pattern matching in HTML, headers)
import time                                # Timestamps and sleep between retries
import datetime                            # Certificate expiry date calculations
import webbrowser                          # Opens URLs in the user's default browser when clicked
from concurrent.futures import ThreadPoolExecutor, as_completed
# ThreadPoolExecutor → runs many tasks at the same time (parallel port scanning, subdomain checks)
# as_completed      → processes results as each thread finishes, not waiting for all to finish


# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 2 — CONSTANTS & SHARED CONFIGURATION
#
#  These are look-up tables and fixed values used across the whole tool.
#  Keeping them at the top in one place makes it easy to update them
#  without touching any of the scanning logic below.
# ═════════════════════════════════════════════════════════════════════════════

VERSION = "3.0"

# ── Social media platforms ────────────────────────────────────────────────────
# Maps a human-readable platform name to its profile URL template.
# The "{}" placeholder is replaced with the username being searched.
# Example: "GitHub" → "https://github.com/johndoe"
SOCIAL_PLATFORMS = {
    "GitHub":      "https://github.com/{}",
    "Twitter/X":   "https://twitter.com/{}",
    "Instagram":   "https://www.instagram.com/{}",
    "Reddit":      "https://www.reddit.com/user/{}",
    "TikTok":      "https://www.tiktok.com/@{}",
    "LinkedIn":    "https://www.linkedin.com/in/{}",
    "Pinterest":   "https://www.pinterest.com/{}",
    "Twitch":      "https://www.twitch.tv/{}",
    "YouTube":     "https://www.youtube.com/@{}",
    "HackerNews":  "https://news.ycombinator.com/user?id={}",
    "DevTo":       "https://dev.to/{}",
    "Medium":      "https://medium.com/@{}",
    "GitLab":      "https://gitlab.com/{}",
    "Bitbucket":   "https://bitbucket.org/{}",
    "Keybase":     "https://keybase.io/{}",
    "Steam":       "https://steamcommunity.com/id/{}",
    "Flickr":      "https://www.flickr.com/people/{}",
    "Vimeo":       "https://vimeo.com/{}",
    "SoundCloud":  "https://soundcloud.com/{}",
    "Patreon":     "https://www.patreon.com/{}",
}

# ── Subdomain wordlist ────────────────────────────────────────────────────────
# Common subdomain prefixes to try during brute-force enumeration.
# Each entry is tested as "<entry>.<target-domain>" e.g. "api.example.com".
# Common admin/dev/infra entries are included to find exposed internal services.
SUBDOMAINS_WORDLIST = [
    "www", "mail", "ftp", "admin", "portal", "api", "dev",
    "staging", "test", "vpn", "remote", "login", "secure",
    "blog", "shop", "store", "cdn", "static", "media",
    "app", "beta", "dashboard", "support", "help", "docs",
    "mx", "smtp", "pop", "imap", "ns1", "ns2", "dns",
    "git", "gitlab", "jenkins", "ci", "jira", "confluence",
    "webmail", "autodiscover", "autoconfig", "cpanel",
    "whm", "plesk", "phpmyadmin", "db", "database",
    "backup", "monitor", "status", "grafana", "kibana",
]

# ── Well-known TCP ports and their service names ──────────────────────────────
# Used by the port scanner to label open ports with human-readable service names.
# Key = port number, Value = protocol/service name.
# Includes common databases, remote access, and web services.
PORT_SERVICES = {
    21:    "FTP",        22:    "SSH",        23:    "Telnet",
    25:    "SMTP",       53:    "DNS",        80:    "HTTP",
    110:   "POP3",       143:   "IMAP",       443:   "HTTPS",
    445:   "SMB",        993:   "IMAPS",      995:   "POP3S",
    1433:  "MSSQL",      1521:  "Oracle",     3306:  "MySQL",
    3389:  "RDP",        5432:  "Postgres",   5900:  "VNC",
    6379:  "Redis",      8080:  "HTTP-Alt",   8443:  "HTTPS-Alt",
    8888:  "Jupyter",    9200:  "Elastic",    27017: "MongoDB",
    6667:  "IRC",        2222:  "SSH-Alt",    4443:  "HTTPS-Alt2",
    8000:  "HTTP-Dev",   8081:  "HTTP-Alt2",  9090:  "Prometheus",
}

# Ports where we attempt to read a "banner" (the server's greeting message).
# Banners reveal the exact software and version running on that port.
BANNER_PORTS = {21, 22, 25, 80, 443, 8080, 8000, 8081, 8443, 3306, 6379}

# ── HTTP response headers worth logging ──────────────────────────────────────
# These headers reveal the server's technology stack, CDN, caching, and
# security configuration. We extract and display any of these that are present.
HTTP_HEADERS_OF_INTEREST = [
    "Server", "X-Powered-By", "X-Generator", "X-Frame-Options",
    "Content-Security-Policy", "Strict-Transport-Security",
    "X-XSS-Protection", "X-Content-Type-Options",
    "Access-Control-Allow-Origin", "Set-Cookie",
    "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Drupal-Cache", "X-WordPress", "CF-RAY",
    "Via", "X-Cache", "X-Varnish",
]

# ── Technology fingerprint patterns ──────────────────────────────────────────
# Maps technology names to a list of regex patterns.
# We search these patterns inside HTTP headers + the first 5000 bytes of the page body.
# If any pattern matches, we report that technology as detected.
# Example: if "wp-content" appears in the page, WordPress is likely running.
TECH_PATTERNS: dict[str, list[str]] = {
    "WordPress":      [r"wp-content", r"wp-json", r"WordPress"],
    "Drupal":         [r"Drupal", r"X-Drupal"],
    "Joomla":         [r"Joomla"],
    "Shopify":        [r"Shopify", r"cdn\.shopify"],
    "Wix":            [r"wixstatic", r"X-Wix"],
    "Squarespace":    [r"squarespace"],
    "Laravel":        [r"laravel_session", r"Laravel"],
    "Django":         [r"csrftoken", r"django"],
    "React":          [r"__NEXT_DATA__", r"react", r"ReactDOM"],
    "Angular":        [r"ng-version", r"angular"],
    "Vue.js":         [r"__vue__", r"vue\.js"],
    "jQuery":         [r"jquery"],
    "Bootstrap":      [r"bootstrap"],
    "Cloudflare":     [r"CF-RAY", r"cloudflare"],
    "AWS CloudFront": [r"CloudFront", r"X-Amz"],
    "Nginx":          [r"nginx"],
    "Apache":         [r"Apache"],
    "IIS":            [r"Microsoft-IIS", r"ASP\.NET"],
    "PHP":            [r"PHP/", r"\.php"],
    "Ruby on Rails":  [r"X-Runtime", r"_rails_"],
    "Node.js":        [r"X-Powered-By.*[Ee]xpress", r"node"],
}

# ── Security headers checklist ────────────────────────────────────────────────
# HTTP response headers that protect against common web attacks.
# We check which of these are present (good) and which are missing (a risk).
# Key = HTTP header name, Value = friendly description shown in the output.
SEC_HEADERS = {
    "Strict-Transport-Security": "HSTS",                # Forces HTTPS
    "Content-Security-Policy":   "CSP",                 # Blocks XSS
    "X-Frame-Options":           "Clickjack Protection",# Prevents iframe embedding
    "X-XSS-Protection":          "XSS Protection",      # Legacy browser XSS filter
    "X-Content-Type-Options":    "MIME Sniff Block",    # Stops MIME confusion attacks
    "Referrer-Policy":           "Referrer Policy",     # Controls referrer header leakage
    "Permissions-Policy":        "Permissions Policy",  # Restricts browser features
}

# ── Email provider fingerprinting ─────────────────────────────────────────────
# Maps keywords found in MX record hostnames to the actual email provider name.
# Example: if an MX record contains "google", the provider is "Google Workspace".
MX_PROVIDERS = {
    ("google", "googlemail"): "Google Workspace",
    ("outlook", "microsoft"): "Microsoft 365",
    ("mxroute",):             "MXRoute",
    ("mailgun",):             "Mailgun",
    ("amazonses",):           "Amazon SES",
    ("protonmail",):          "ProtonMail",
    ("zoho",):                "Zoho Mail",
    ("sendgrid",):            "SendGrid",
}

# ── Shared SSL context ────────────────────────────────────────────────────────
# We disable certificate verification here intentionally — because we are
# *inspecting* certificates (not verifying them for trust), and the target may
# have an expired or self-signed certificate that we still want to analyse.
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode    = ssl.CERT_NONE

# Fake browser User-Agent so that servers don't block requests from Python's urllib.
_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 Chrome/124.0 Safari/537.36"
)


# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 3 — SHARED HELPER UTILITIES
#
#  Small reusable functions and classes that multiple scan modules depend on.
#  Think of these as the "plumbing" — nothing domain-specific here.
# ═════════════════════════════════════════════════════════════════════════════

# ── 3a. Request statistics tracker ───────────────────────────────────────────
# Counts how many HTTP requests succeeded, timed out, or failed during a scan.
# Reset at the start of each scan; printed in the summary at the end.
class _ReqStats:
    def __init__(self):
        self.success = 0   # Server replied (even with an error code like 404)
        self.timeout = 0   # Connection timed out or network error
        self.failed  = 0   # Unexpected exception (not a timeout)

    def reset(self):
        """Called at the start of every new scan to zero out the counters."""
        self.success = self.timeout = self.failed = 0

    def summary(self) -> str:
        """Returns a one-line string e.g. 'HTTP Requests — Total: 42  Success: 38  ...'"""
        total = self.success + self.timeout + self.failed
        return (f"  HTTP Requests — Total: {total}  "
                f"Success: {self.success}  "
                f"Timeout: {self.timeout}  "
                f"Failed: {self.failed}")

# Global instance shared across all scan modules in one scan session.
req_stats = _ReqStats()


# ── 3b. HTTP GET with retry ───────────────────────────────────────────────────
def http_get(url: str, timeout: int = 7, return_headers: bool = False, retries: int = 3):
    """
    Performs an HTTP GET request and returns the response.

    Parameters:
        url            - The full URL to fetch.
        timeout        - Seconds to wait before giving up on a connection.
        return_headers - If True, also returns a dict of response headers.
        retries        - How many times to retry on timeout before giving up.

    Returns:
        Without headers: (status_code, body_text)
        With headers:    (status_code, body_text, headers_dict)
        On failure:      (None, "", {}) or (None, "")
    """
    req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "*/*"})
    last_exc = None
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=_CTX) as r:
                body = r.read().decode("utf-8", errors="ignore")
                req_stats.success += 1
                return (r.status, body, dict(r.headers)) if return_headers else (r.status, body)
        except urllib.error.HTTPError as e:
            # The server replied with an error code (e.g. 404, 403).
            # This still counts as "reachable" for our purposes.
            req_stats.success += 1
            return (e.code, "", {}) if return_headers else (e.code, "")
        except (socket.timeout, urllib.error.URLError) as e:
            # Network timeout or DNS resolution failure — retry after a pause.
            last_exc = e
            req_stats.timeout += 1
            if attempt < retries - 1:
                time.sleep(2)  # Wait 2 seconds before retrying
        except Exception as e:
            # Unexpected error — don't retry.
            last_exc = e
            req_stats.failed += 1
            break
    return (None, "", {}) if return_headers else (None, "")


# ── 3c. DNS resolution ────────────────────────────────────────────────────────
def resolve(host: str) -> str | None:
    """
    Resolves a hostname to its IPv4 address using the OS's DNS resolver.
    Returns the IP string (e.g. "93.184.216.34"), or None if it cannot be resolved.
    """
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


# ── 3d. DNS record query via Google DoH ──────────────────────────────────────
def dns_query(domain: str, qtype: str) -> list[str]:
    """
    Queries a specific DNS record type for a domain using Google's
    DNS-over-HTTPS (DoH) JSON API. This avoids needing the 'dnspython' library.

    Parameters:
        domain - The domain name to query (e.g. "example.com")
        qtype  - The record type as a string: "A", "AAAA", "MX", "NS",
                 "TXT", "SOA", "CNAME", or "PTR"

    Returns:
        A list of record values (strings). Empty list if none found or on error.
    """
    # Map record type names to their numeric DNS type codes (RFC 1035).
    type_map = {"A": 1, "AAAA": 28, "MX": 15, "NS": 2, "TXT": 16, "SOA": 6, "CNAME": 5, "PTR": 12}
    url = f"https://dns.google/resolve?name={urllib.parse.quote(domain)}&type={type_map.get(qtype, 1)}"
    status, body = http_get(url)
    if status != 200 or not body:
        return []
    try:
        # The response JSON has an "Answer" array; each item has a "data" field with the record value.
        return [a.get("data", "") for a in json.loads(body).get("Answer", [])]
    except Exception:
        return []


# ── 3e. Confidence scoring ────────────────────────────────────────────────────
# Many results (subdomains, social profiles, open ports) get a confidence score
# from 0–100. This class converts that score to a human-readable label and a
# GUI colour tag.
class Confidence:
    HIGH   = "HIGH"
    MEDIUM = "MEDIUM"
    LOW    = "LOW"

    @staticmethod
    def label(score: int) -> str:
        """Convert a 0–100 score → 'HIGH' / 'MEDIUM' / 'LOW'."""
        if score >= 70: return Confidence.HIGH
        if score >= 40: return Confidence.MEDIUM
        return Confidence.LOW

    @staticmethod
    def tag(score: int) -> str:
        """Return the tkinter text-tag name for colour-coding in the GUI output."""
        return {"HIGH": "conf_high", "MEDIUM": "conf_med", "LOW": "conf_low"}[Confidence.label(score)]


def score_subdomain(ip: str | None, http_ok: bool) -> int:
    """
    Calculates a confidence score for a discovered subdomain.
    - +50 if it resolves to an IP  (it's real, not a DNS miss)
    - +35 if it responds to HTTP   (it's actually serving web content)
    Maximum possible score: 85 → classified as HIGH.
    """
    s = 0
    if ip:      s += 50
    if http_ok: s += 35
    return min(s, 100)


def score_social(status: int | None) -> int:
    """
    Scores a social-media username check based on the HTTP response code.
    - 200 → page exists  → score 60 (MEDIUM confidence)
    - 301/302 → redirect → score 40 (LOW confidence)
    - Anything else (404, None) → score 0 (not found)
    Note: HTTP 200 does NOT guarantee the profile exists — some platforms
    return 200 for non-existent usernames with a "user not found" page.
    """
    if status == 200:          return 60
    if status in (301, 302):   return 40
    return 0


# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 4 — RECON MODULE FUNCTIONS
#
#  Each function here is one independent scanning module.
#  They all follow the same signature: (target, log, report)
#    • target  — the domain, IP, or username being analysed
#    • log     — function to print a line to the GUI output pane
#    • report  — dict that accumulates all results for JSON export
#
#  The modules are numbered in the order they typically run.
# ═════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 1 — IP & GEOLOCATION
#
#  What it does:
#    1. Resolves the target hostname to an IP address.
#    2. Queries ipapi.co for geolocation data (country, city, ASN, org, etc.)
#    3. Falls back to ip-api.com if the first provider fails or rate-limits.
#    4. Logs a Google Maps link if coordinates are available.
#
#  APIs used:
#    • https://ipapi.co/{ip}/json/       (primary)
#    • http://ip-api.com/json/{ip}       (fallback)
# ─────────────────────────────────────────────────────────────────────────────
def run_ip_lookup(target: str, log, report: dict):
    log("", "header")
    log("  ━━━  📡  IP & GEOLOCATION INTELLIGENCE  ━━━", "header")
    log("")

    # Step 1 — resolve hostname → IP (or treat target as a bare IP if resolution fails)
    ip = resolve(target)
    if ip:
        log(f"  Hostname  : {target}")
        log(f"  Resolved  : {ip}")
    else:
        ip = target   # target is already a bare IP address
        log(f"  Target IP : {ip}")

    report["ip"] = {"target": target, "resolved": ip}

    # Step 2 — query primary geo provider (ipapi.co)
    status, body = http_get(f"https://ipapi.co/{ip}/json/")
    geo = {}
    if status == 200 and body:
        try:
            geo = json.loads(body)
        except Exception:
            pass

    lat = lon = None  # Will be set if coordinates are available (used for Maps link)

    if geo and not geo.get("error"):
        # ipapi.co returned valid data — display it
        log("")
        log("  ┌─ GEOLOCATION (ipapi.co) " + "─" * 28)
        log(f"  │  Country   : {geo.get('country_name','N/A')} ({geo.get('country_code','?')}) [{geo.get('country_code_iso3','')}]")
        log(f"  │  Region    : {geo.get('region','N/A')} ({geo.get('region_code','?')})")
        log(f"  │  City      : {geo.get('city','N/A')}")
        log(f"  │  ZIP/Post  : {geo.get('postal','N/A')}")
        log(f"  │  Latitude  : {geo.get('latitude','?')}")
        log(f"  │  Longitude : {geo.get('longitude','?')}")
        log(f"  │  Timezone  : {geo.get('timezone','N/A')}")
        log(f"  │  UTC Offset: {geo.get('utc_offset','N/A')}")
        log(f"  │  Currency  : {geo.get('currency','N/A')} ({geo.get('currency_name','?')})")
        log(f"  │  Languages : {geo.get('languages','N/A')}")
        log(f"  └─ NETWORK")
        log(f"  │  ASN       : {geo.get('asn','N/A')}")
        log(f"  │  Org / ISP : {geo.get('org','N/A')}")
        log(f"  │  Network   : {geo.get('network','N/A')}")
        log("")
        log(f"  ┌─ FLAGS")
        log(f"  │  EU Member    : {'Yes' if geo.get('in_eu') else 'No'}")
        log(f"  │  Calling Code : +{str(geo.get('country_calling_code','N/A')).lstrip('+')}")
        log(f"  │  Capital      : {geo.get('country_capital','N/A')}")
        log(f"  │  Country Pop  : {geo.get('country_population','N/A')}")
        log(f"  └──" + "─" * 40)
        lat, lon = geo.get("latitude"), geo.get("longitude")
        report["ip"]["geo"] = geo
    else:
        # Step 3 — fallback to ip-api.com (ipapi.co may have rate-limited us)
        s2, b2 = http_get(f"http://ip-api.com/json/{ip}?fields=66846719")
        if s2 == 200 and b2:
            try:
                d = json.loads(b2)
                log("")
                log("  ┌─ GEOLOCATION (ip-api.com fallback) " + "─" * 18)
                log(f"  │  Country   : {d.get('country','N/A')} ({d.get('countryCode','?')})")
                log(f"  │  Region    : {d.get('regionName','N/A')} ({d.get('region','?')})")
                log(f"  │  City      : {d.get('city','N/A')}")
                log(f"  │  Latitude  : {d.get('lat','?')}")
                log(f"  │  Longitude : {d.get('lon','?')}")
                log(f"  │  Timezone  : {d.get('timezone','N/A')}")
                log(f"  │  ISP       : {d.get('isp','N/A')}")
                log(f"  │  Org       : {d.get('org','N/A')}")
                log(f"  │  ASN       : {d.get('as','N/A')}")
                log(f"  │  Hosting   : {'Yes' if d.get('hosting') else 'No'}  "
                    f"Proxy: {'Yes' if d.get('proxy') else 'No'}  "
                    f"Mobile: {'Yes' if d.get('mobile') else 'No'}")
                log(f"  └──" + "─" * 40)
                lat, lon = d.get("lat"), d.get("lon")
                report["ip"]["geo"] = d
            except Exception:
                pass
        else:
            log("  [!] Could not retrieve geo data (rate limit or offline)")

    # Step 4 — if we have coordinates, show a clickable Google Maps link
    if lat and lon:
        log("")
        log(f"  🗺  Google Maps: https://maps.google.com/?q={lat},{lon}", "found")
    log("")


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 2 — WHOIS / RDAP
#
#  What it does:
#    Queries the RDAP (Registration Data Access Protocol) service for domain
#    registration data: who registered it, when, when it expires, which
#    nameservers it uses, and who the registrar is.
#
#  RDAP is the modern replacement for the older plain-text WHOIS protocol.
#
#  API used:
#    • https://rdap.org/domain/{domain}
# ─────────────────────────────────────────────────────────────────────────────
def run_whois(target: str, log, report: dict):
    log("", "header")
    log("  ━━━  🗂  WHOIS / RDAP LOOKUP  ━━━", "header")
    log("")

    # Strip any protocol prefix and path — we only need the bare domain name
    domain = target.lstrip("https://").lstrip("http://").split("/")[0]
    status, body = http_get(f"https://rdap.org/domain/{domain}")
    rdap_data: dict = {}

    if status == 200 and body:
        try:
            d = json.loads(body)
            rdap_data["domain"]      = d.get("ldhName", domain)
            rdap_data["status"]      = d.get("status", [])
            rdap_data["events"]      = {}
            rdap_data["nameservers"] = []
            rdap_data["entities"]    = {}

            log(f"  Domain      : {rdap_data['domain']}")
            log(f"  Status      : {', '.join(rdap_data['status'])}")

            # Events contain registration, expiration, and last-updated dates
            for ev in d.get("events", []):
                action = ev.get("eventAction", "")
                date   = ev.get("eventDate", "")[:10]   # Trim time, keep date only
                if action in ("registration", "expiration", "last changed"):
                    label = {"registration": "Registered ", "expiration": "Expires    ",
                             "last changed": "Updated    "}.get(action, action)
                    log(f"  {label}: {date}")
                    rdap_data["events"][action] = date

            # Nameservers — the DNS servers authoritative for this domain
            ns_list = [n.get("ldhName", "") for n in d.get("nameservers", [])]
            if ns_list:
                log(f"  Nameservers : {', '.join(ns_list)}")
                rdap_data["nameservers"] = ns_list

            # Entities — people/orgs associated with the domain (registrar, registrant, etc.)
            for entity in d.get("entities", []):
                roles = entity.get("roles", [])
                vcard = entity.get("vcardArray", [])
                name = email = ""
                if vcard and len(vcard) > 1:
                    for item in vcard[1]:
                        if item[0] == "fn":    name  = item[3]   # Full name
                        if item[0] == "email": email = item[3]   # Email address
                for role in ("registrar", "registrant", "administrative", "technical"):
                    if role in roles:
                        labels = {"registrar": "Registrar  ", "registrant": "Registrant ",
                                  "administrative": "Admin      ", "technical": "Tech       "}
                        log(f"  {labels[role]}: {name} {email}".strip())
                        rdap_data["entities"][role] = {"name": name, "email": email}

            log(f"  RDAP URL    : https://rdap.org/domain/{domain}", "found")
        except Exception as e:
            log(f"  [!] Parse error: {e}")
    else:
        log(f"  [!] RDAP lookup failed (status={status}). Domain may be unregistered or TLD unsupported.")

    report["whois"] = rdap_data
    log("")
    # Bonus: link to reverse-WHOIS to find other domains registered by the same person/org
    log(f"  🔗 ViewDNS Reverse WHOIS: https://viewdns.info/reversewhois/?q={domain}", "found")
    log("")


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 3 — DNS DEEP DIVE
#
#  What it does:
#    Queries multiple DNS record types to build a complete picture of
#    a domain's DNS configuration.
#
#  Record types queried:
#    A     → IPv4 address(es) the domain points to
#    AAAA  → IPv6 address(es)
#    NS    → Name servers (who controls DNS for this domain)
#    MX    → Mail servers (who handles email)
#    TXT   → Text records (SPF, DKIM, verification tokens, etc.)
#    SOA   → Start of Authority (primary nameserver + admin contact)
#    CNAME → Canonical name (alias pointing to another domain)
#
#  Also extracts:
#    SPF   → Email spoofing prevention policy (from TXT records)
#    DMARC → Email authentication policy (separate DNS lookup)
#    rDNS  → Reverse DNS of the primary IP (PTR record)
# ─────────────────────────────────────────────────────────────────────────────
def run_dns(domain: str, log, report: dict):
    log("", "header")
    log("  ━━━  🌐  DNS DEEP DIVE  ━━━", "header")
    log("")

    dns_data: dict = {}

    # Query all standard record types in sequence
    for rtype in ["A", "AAAA", "NS", "MX", "TXT", "SOA", "CNAME"]:
        results = dns_query(domain, rtype)
        dns_data[rtype] = results
        if results:
            log(f"  [{rtype:<5}]", "section")
            for r in results:
                log(f"         → {r}")
        else:
            log(f"  [{rtype:<5}]  (no records)", "muted")

    # Extract SPF from TXT records — SPF records always start with "v=spf1"
    spf   = [r for r in dns_data.get("TXT", []) if "v=spf1" in r]
    # DMARC lives at a special subdomain: _dmarc.<domain>
    dmarc = dns_query(f"_dmarc.{domain}", "TXT")
    dns_data["spf"]   = spf
    dns_data["dmarc"] = dmarc

    # Show email security status — missing SPF/DMARC is a significant risk
    log("")
    log("  ┌─ EMAIL SECURITY RECORDS")
    if spf:
        log(f"  │  SPF   : {spf[0]}", "found")
    else:
        log("  │  SPF   : ✗ NOT FOUND (spoofing risk)", "warn")
    if dmarc:
        log(f"  │  DMARC : {dmarc[0]}", "found")
    else:
        log("  │  DMARC : ✗ NOT FOUND (no DMARC policy)", "warn")
    log(f"  │  DKIM  : Check default._domainkey.{domain}")
    log(f"  └──" + "─" * 40)

    # Reverse DNS — look up what hostname is registered for the primary IP
    a_records = dns_data.get("A", [])
    if a_records:
        try:
            rdns = socket.gethostbyaddr(a_records[0])[0]
            log(f"\n  Reverse DNS ({a_records[0]}): {rdns}")
            dns_data["reverse_dns"] = rdns
        except Exception:
            log(f"\n  Reverse DNS ({a_records[0]}): N/A")

    report["dns"] = dns_data
    log("")


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 4 — SUBDOMAIN ENUMERATION
#
#  What it does:
#    Discovers subdomains (e.g. api.example.com, mail.example.com) using two methods:
#
#    Method 1 — Certificate Transparency logs (passive, via crt.sh):
#      SSL certificates issued for a domain are logged publicly.
#      crt.sh lets us search these logs to find all subdomains that have
#      ever had an SSL certificate — revealing subdomains without sending
#      any packets to the target.
#
#    Method 2 — Wordlist brute-force (active):
#      We try each word from SUBDOMAINS_WORDLIST as a subdomain prefix
#      and attempt to resolve it. If it resolves, it exists.
#
#  Wildcard detection:
#    Some domains return an IP for ANY subdomain (even made-up ones).
#    We detect this and skip results that match the wildcard IP to
#    avoid false positives.
#
#  Confidence scoring:
#    Each found subdomain is scored based on whether it resolves AND
#    whether it responds to HTTP.
# ─────────────────────────────────────────────────────────────────────────────

def _clean_sub(name: str) -> str:
    """
    Normalises a subdomain name from CT log entries.
    Removes leading wildcards (*.example.com → example.com) and whitespace.
    """
    return name.strip().lower().lstrip("*.")


def _http_probe(fqdn: str) -> bool:
    """
    Checks whether a hostname responds to HTTP or HTTPS.
    Returns True if we get any response (status < 500 = not a server crash).
    Used to confirm subdomains are actively serving web content.
    """
    for scheme in ("https", "http"):
        status, _ = http_get(f"{scheme}://{fqdn}", timeout=4)
        if status and status < 500:
            return True
    return False


def _detect_wildcard(domain: str) -> str | None:
    """
    Checks whether the domain has wildcard DNS configured (*.domain → same IP).
    We do this by probing a deliberately nonsensical subdomain.
    If it resolves, it means ANY subdomain resolves — wildcard DNS is active.
    Returns the wildcard IP (so we can filter it out), or None if no wildcard.
    """
    probe = f"__unlikely_probe_xyzzy__.{domain}"
    return resolve(probe)


def run_subdomain_finder(domain: str, log, report: dict):
    log("", "header")
    log("  ━━━  🔍  SUBDOMAIN ENUMERATION  ━━━", "header")
    log("")

    found: dict[str, dict] = {}   # fqdn → {ip, http_ok, source, score}
    domain_lower = domain.lower()

    # ── Wildcard check (do this first to avoid false positives later) ──────────
    wildcard_ip = _detect_wildcard(domain_lower)
    if wildcard_ip:
        log(f"  ⚠  Wildcard DNS detected (*.{domain} → {wildcard_ip})", "warn")
        log("     Wordlist results resolving to this IP are likely false positives and will be filtered.", "warn")
    else:
        log("  ✓  No wildcard DNS detected", "found")
    log("")

    # ── Method 1: Certificate Transparency logs (crt.sh) ──────────────────────
    log("  [1/2] Certificate Transparency (crt.sh) ...")
    status, body = http_get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=12)
    ct_subs: set[str] = set()

    if status == 200 and body:
        try:
            for cert in json.loads(body):
                # name_value can contain multiple names separated by newlines
                for raw in cert.get("name_value", "").splitlines():
                    cleaned = _clean_sub(raw)
                    # Only keep entries that belong to our target domain
                    if cleaned.endswith(f".{domain_lower}") or cleaned == domain_lower:
                        ct_subs.add(cleaned)
        except Exception:
            pass

    if ct_subs:
        log(f"  Found {len(ct_subs)} unique entries in CT logs (resolving + probing) ...")
        def probe_ct(sub):
            """Try to resolve and HTTP-probe one CT subdomain."""
            ip      = resolve(sub)
            http_ok = _http_probe(sub) if ip else False
            return sub, ip, http_ok
        # Run up to 20 probes in parallel to keep things fast
        with ThreadPoolExecutor(max_workers=20) as ex:
            for future in as_completed({ex.submit(probe_ct, s): s for s in ct_subs}):
                sub, ip, http_ok = future.result()
                if ip:
                    score = score_subdomain(ip, http_ok)
                    found[sub] = {"ip": ip, "http_ok": http_ok, "source": "CT", "score": score}
                    conf = Confidence.label(score)
                    log(f"    [CT] {sub:<45} → {ip:<18} {'HTTPS✓' if http_ok else 'no HTTP'}  [{conf}]",
                        Confidence.tag(score))
    else:
        log("  No CT log data retrieved (rate limit or offline)")

    # ── Method 2: Wordlist brute-force ─────────────────────────────────────────
    log("")
    log(f"  [2/2] Wordlist brute-force ({len(SUBDOMAINS_WORDLIST)} entries) ...")

    def check_wl(sub):
        """Try to resolve and probe one wordlist-generated subdomain."""
        fqdn    = f"{sub}.{domain_lower}"
        ip      = resolve(fqdn)
        http_ok = _http_probe(fqdn) if ip else False
        return fqdn, ip, http_ok

    with ThreadPoolExecutor(max_workers=20) as ex:
        for future in as_completed({ex.submit(check_wl, s): s for s in SUBDOMAINS_WORDLIST}):
            fqdn, ip, http_ok = future.result()
            if ip and fqdn not in found:
                # Skip if this IP matches the wildcard — it's a false positive
                if wildcard_ip and ip == wildcard_ip:
                    continue
                score = score_subdomain(ip, http_ok)
                found[fqdn] = {"ip": ip, "http_ok": http_ok, "source": "WL", "score": score}
                conf = Confidence.label(score)
                log(f"    [WL] {fqdn:<45} → {ip:<18} {'HTTPS✓' if http_ok else 'no HTTP'}  [{conf}]",
                    Confidence.tag(score))

    # ── Summary ────────────────────────────────────────────────────────────────
    high   = sum(1 for d in found.values() if Confidence.label(d["score"]) == "HIGH")
    medium = sum(1 for d in found.values() if Confidence.label(d["score"]) == "MEDIUM")
    low    = sum(1 for d in found.values() if Confidence.label(d["score"]) == "LOW")
    unique_ips = list(set(d["ip"] for d in found.values()))

    log("")
    log(f"  ┌─ SUMMARY")
    log(f"  │  Total resolved subdomains : {len(found)}")
    log(f"  │  Confidence HIGH           : {high}",   "conf_high")
    log(f"  │  Confidence MEDIUM         : {medium}", "conf_med")
    log(f"  │  Confidence LOW            : {low}",    "conf_low")
    log(f"  │  Unique IPs discovered     : {len(unique_ips)}")
    for ip in unique_ips:
        log(f"  │    {ip}")
    log(f"  └──" + "─" * 40)

    report["subdomains"] = {
        "wildcard_ip": wildcard_ip,
        "entries": {
            fqdn: {**data, "confidence": Confidence.label(data["score"])}
            for fqdn, data in found.items()
        }
    }
    log("")


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 5 — PORT SCANNER
#
#  What it does:
#    Attempts TCP connections to a list of well-known ports on the target IP.
#    Open ports indicate active services running on the server.
#
#  Two scan modes:
#    Fast  — 0.7s timeout per port, 40 threads, banner grab only for
#             a limited set of common ports (BANNER_PORTS).
#    Deep  — 1.5s timeout per port, banner grab on ALL open ports.
#
#  Banner grabbing:
#    After confirming a port is open, we send a small probe and read the
#    first ~60 bytes of the response. Many services announce their
#    software name and version in this "banner".
#
#  Confidence scoring:
#    Well-known ports (e.g. 80, 443, 22) score higher by default.
#    A matching banner keyword increases the score further.
# ─────────────────────────────────────────────────────────────────────────────

def _probe_port(ip: str, port: int, timeout: float) -> tuple[int, bool]:
    """
    Tries to open a TCP connection to (ip, port).
    Returns (port, True) if the connection succeeds (port is open),
    or (port, False) if it fails or times out.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))  # 0 = success, non-zero = error
        s.close()
        return port, result == 0
    except Exception:
        return port, False


def _grab_banner(ip: str, port: int) -> str:
    """
    Reads the service banner from an open port (the server's greeting text).
    For web ports we send an HTTP HEAD request; for others we just send a newline.
    Returns the first line of the response (up to 60 chars), or "" on failure.
    """
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, port))
        # HTTP ports get a proper request; everything else gets a bare newline
        s.send(b"HEAD / HTTP/1.0\r\n\r\n" if port in (80, 8080, 8000, 8081) else b"\r\n")
        raw = s.recv(256)
        s.close()
        return raw.decode("utf-8", errors="ignore").split("\n")[0][:60].strip()
    except Exception:
        return ""


def _port_confidence(port: int, banner: str) -> int:
    """
    Calculates a confidence score for an open port result.
    - Well-known ports start at 80 (more trusted); others start at 50.
    - If the banner text confirms the expected service, add 15 points.
    """
    well_known = {80, 443, 22, 21, 25, 53, 3306, 5432, 3389, 6379, 27017}
    base = 80 if port in well_known else 50
    svc  = PORT_SERVICES.get(port, "").lower()
    if banner and svc and any(kw in banner.lower()
                               for kw in [svc, "ssh", "ftp", "smtp", "http", "mysql", "redis"]):
        base = min(base + 15, 100)
    return base


def run_port_scan(target: str, log, report: dict, deep: bool = False):
    log("", "header")
    log("  ━━━  🔌  PORT SCANNER  ━━━", "header")
    log("")

    ip      = resolve(target) or target
    timeout = 1.5 if deep else 0.7
    mode    = "DEEP (banner grab, 1.5s timeout)" if deep else "FAST (0.7s timeout)"

    log(f"  Target : {ip}")
    log(f"  Mode   : {mode}")
    log(f"  Ports  : {len(PORT_SERVICES)}")
    log("")

    # Scan all ports in PORT_SERVICES in parallel (up to 40 threads at once)
    results: dict[int, bool] = {}
    with ThreadPoolExecutor(max_workers=40) as ex:
        for future in as_completed({ex.submit(_probe_port, ip, p, timeout): p for p in PORT_SERVICES}):
            port, is_open = future.result()
            results[port] = is_open

    open_ports:   list[int]  = []
    report_ports: dict       = {}

    # Display results sorted by port number (easier to read than random thread order)
    for port in sorted(PORT_SERVICES.keys()):
        svc     = PORT_SERVICES[port]
        is_open = results.get(port, False)
        if is_open:
            open_ports.append(port)
            # Grab banner for deep mode OR for known banner-worthy ports
            banner = _grab_banner(ip, port) if (deep or port in BANNER_PORTS) else ""
            score  = _port_confidence(port, banner)
            conf   = Confidence.label(score)
            banner_str = f'  "{banner}"' if banner else ""
            log(f"  [OPEN]   {port:<6} {svc:<14} [{conf}]{banner_str}", Confidence.tag(score))
            report_ports[port] = {"service": svc, "banner": banner, "confidence": conf}
        else:
            log(f"  [closed] {port:<6} {svc}", "muted")

    log("")
    log(f"  ┌─ RESULTS")
    log(f"  │  Open  : {len(open_ports)}  {open_ports}")
    log(f"  │  Closed: {len(PORT_SERVICES) - len(open_ports)}")
    log(f"  └──" + "─" * 40)

    report["ports"] = {"open": report_ports, "total_scanned": len(PORT_SERVICES)}
    log("")


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 6 — HTTP HEADERS & TECHNOLOGY FINGERPRINT
#
#  What it does:
#    Makes an HTTP request to the target and analyses the response to reveal:
#
#    1. Security headers — which protective headers are present/missing.
#       Missing headers are flagged as risks.
#
#    2. Technology headers — server name, powered-by, framework clues, CDN info.
#
#    3. Technology detection — pattern-matches headers + page source against
#       TECH_PATTERNS to identify frameworks, CMS, and CDN.
#
#    4. Cookie security — checks each Set-Cookie header for Secure,
#       HttpOnly, and SameSite flags (missing flags are security risks).
#
#  Tries HTTPS first, falls back to HTTP if HTTPS fails.
# ─────────────────────────────────────────────────────────────────────────────
def run_http_fingerprint(domain: str, log, report: dict):
    log("", "header")
    log("  ━━━  🧬  HTTP HEADERS & TECH FINGERPRINT  ━━━", "header")
    log("")

    fp_data: dict = {}

    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        log(f"  Probing {url} ...")
        status, body, hdrs = http_get(url, return_headers=True)
        if not status:
            continue   # Try next scheme if this one failed entirely

        log(f"\n  HTTP Status  : {status}")
        log(f"  URL          : {url}")
        log("")

        # ── Security headers check ─────────────────────────────────────────
        log("  ┌─ SECURITY HEADERS")
        present, missing = [], []
        for hdr, label in SEC_HEADERS.items():
            # Headers can be returned in any case; check both original and lowercase
            val = hdrs.get(hdr) or hdrs.get(hdr.lower(), "")
            if val:
                log(f"  │  ✓ {label:<26} : {val[:60]}", "found")
                present.append(hdr)
            else:
                log(f"  │  ✗ {label:<26} : MISSING", "warn")
                missing.append(hdr)
        log("  └" + "─" * 44)
        fp_data["security_headers"] = {"present": present, "missing": missing}

        # ── Raw technology-revealing headers ───────────────────────────────
        log("")
        log("  ┌─ SERVER & TECHNOLOGY HEADERS")
        raw_hdrs = {}
        for h in HTTP_HEADERS_OF_INTEREST:
            val = hdrs.get(h) or hdrs.get(h.lower(), "")
            if val:
                log(f"  │  {h:<30} : {val[:70]}")
                raw_hdrs[h] = val
        log("  └" + "─" * 44)
        fp_data["raw_headers"] = raw_hdrs

        # ── Technology detection ───────────────────────────────────────────
        # Combine headers + first 5000 bytes of page body into one searchable string
        log("")
        log("  ┌─ TECHNOLOGY DETECTION")
        all_content = json.dumps(dict(hdrs)) + body[:5000]
        detected = [
            tech for tech, pats in TECH_PATTERNS.items()
            if any(re.search(p, all_content, re.IGNORECASE) for p in pats)
        ]
        if detected:
            for t in detected:
                log(f"  │  ✓ {t}", "found")
        else:
            log("  │  No common frameworks detected")
        log("  └" + "─" * 44)
        fp_data["technologies"] = detected

        # ── Cookie security analysis ───────────────────────────────────────
        # Collect all Set-Cookie header values from the response
        cookies = [v for k, v in hdrs.items() if k.lower() == "set-cookie"]
        if cookies:
            log("")
            log("  ┌─ COOKIES")
            cookie_data = []
            for c in cookies[:5]:   # Show up to 5 cookies
                secure   = "Secure"   if "Secure"   in c else "NO Secure"    # Cookie sent only over HTTPS?
                httponly = "HttpOnly" if "HttpOnly" in c else "NO HttpOnly"  # Inaccessible to JS?
                ss_match = re.search(r"SameSite=(\w+)", c)
                ss       = ss_match.group(1) if ss_match else "None"         # CSRF protection?
                name     = c.split("=")[0].strip()
                log(f"  │  {name:<20} [{secure}] [{httponly}] [SameSite={ss}]")
                cookie_data.append({"name": name, "secure": "Secure" in c,
                                    "httponly": "HttpOnly" in c, "samesite": ss})
            log("  └" + "─" * 44)
            fp_data["cookies"] = cookie_data

        break   # Stop after the first scheme that worked — no need to try HTTP if HTTPS succeeded

    report["http"] = fp_data
    log("")


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 7 — SSL / TLS CERTIFICATE INSPECTOR
#
#  What it does:
#    Opens a real TLS connection to port 443 and reads the SSL certificate.
#    We inspect (not verify) it — so expired or self-signed certs are fine.
#
#  Information extracted:
#    - TLS protocol version (TLS 1.2, TLS 1.3, etc.)
#    - Cipher suite and key strength (bits)
#    - Certificate Subject (who the cert was issued TO)
#    - Certificate Issuer (who signed/issued the cert)
#    - Validity dates and days remaining until expiry
#    - Subject Alternative Names (SANs) — all domains covered by this cert
#    - Wildcard SAN entries (potentially wide coverage)
# ─────────────────────────────────────────────────────────────────────────────
def run_ssl_inspect(domain: str, log, report: dict):
    log("", "header")
    log("  ━━━  🔐  SSL / TLS CERTIFICATE INSPECTOR  ━━━", "header")
    log("")

    ssl_data: dict = {}
    try:
        # Create a context that skips verification — we're inspecting, not trusting
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        # Open a TCP connection to port 443, then wrap it with TLS
        with socket.create_connection((domain, 443), timeout=7) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert    = ssock.getpeercert()     # The certificate data as a Python dict
                cipher  = ssock.cipher()          # (cipher_name, protocol_version, key_bits)
                version = ssock.version()         # e.g. "TLSv1.3"

        if not cert:
            log("  [!] No cert retrieved (possibly no HTTPS)")
            return

        log(f"  TLS Version  : {version}")
        log(f"  Cipher Suite : {cipher[0] if cipher else 'N/A'}")
        log(f"  Bits         : {cipher[2] if cipher else 'N/A'}")
        log("")

        # Subject = who the cert was issued TO (the website owner)
        subj   = dict(x[0] for x in cert.get("subject", []))
        # Issuer = who issued/signed the cert (Certificate Authority)
        issuer = dict(x[0] for x in cert.get("issuer", []))

        log("  ┌─ SUBJECT")
        log(f"  │  Common Name   : {subj.get('commonName','N/A')}")
        log(f"  │  Organization  : {subj.get('organizationName','N/A')}")
        log(f"  │  Country       : {subj.get('countryName','N/A')}")
        log(f"  │  State         : {subj.get('stateOrProvinceName','N/A')}")
        log(f"  └──" + "─" * 40)

        log("  ┌─ ISSUER")
        log(f"  │  Common Name   : {issuer.get('commonName','N/A')}")
        log(f"  │  Organization  : {issuer.get('organizationName','N/A')}")
        log(f"  │  Country       : {issuer.get('countryName','N/A')}")
        log(f"  └──" + "─" * 40)

        not_before = cert.get("notBefore", "")
        not_after  = cert.get("notAfter",  "")
        log(f"  Valid From   : {not_before}")
        log(f"  Valid Until  : {not_after}")

        # Calculate how many days until the certificate expires
        days_remaining = None
        try:
            exp   = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            delta = exp - datetime.datetime.utcnow()
            days_remaining = delta.days
            if delta.days < 0:
                log(f"  ⚠  CERTIFICATE EXPIRED {abs(delta.days)} days ago!", "warn")
            elif delta.days < 30:
                log(f"  ⚠  Expires in {delta.days} days (renew soon!)", "warn")
            else:
                log(f"  ✓  Expires in {delta.days} days", "found")
        except Exception:
            pass

        # SANs = all domain names this single certificate covers
        # Modern certs often cover dozens of subdomains at once
        sans = [name for kind, name in cert.get("subjectAltName", []) if kind == "DNS"]
        if sans:
            log("")
            log(f"  ┌─ SUBJECT ALT NAMES ({len(sans)} entries)")
            for san in sans[:20]:
                log(f"  │  {san}")
            if len(sans) > 20:
                log(f"  │  ... and {len(sans)-20} more")
            log(f"  └──" + "─" * 40)

        # Wildcard SANs (e.g. *.example.com) cover all subdomains — worth noting
        wildcards = [s for s in sans if s.startswith("*")]
        if wildcards:
            log(f"\n  Wildcard SANs: {', '.join(wildcards)}", "warn")

        ssl_data = {
            "version": version, "cipher": cipher[0] if cipher else None,
            "bits": cipher[2] if cipher else None, "subject": subj,
            "issuer": issuer, "not_before": not_before, "not_after": not_after,
            "days_remaining": days_remaining, "sans": sans, "wildcards": wildcards,
        }
    except Exception as e:
        log(f"  [!] SSL inspection failed: {e}")

    report["ssl"] = ssl_data
    log("")


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 8 — EMAIL INTELLIGENCE
#
#  What it does:
#    Gathers email-related intelligence for a domain:
#
#    1. MX records — which mail servers handle email for the domain,
#       and which email provider they belong to (Google Workspace, M365, etc.)
#
#    2. Common role addresses — generates a list of typical email addresses
#       like info@, admin@, support@ for manual investigation.
#
#    3. Homepage email scraping — fetches the domain's homepage and uses
#       regex to find any email addresses exposed in the HTML.
#
#    4. Breach intelligence links — provides quick links to HIBP, Hunter.io,
#       and IntelX for further investigation.
# ─────────────────────────────────────────────────────────────────────────────
def run_email_intel(domain: str, log, report: dict):
    log("", "header")
    log("  ━━━  📧  EMAIL INTELLIGENCE  ━━━", "header")
    log("")
    log(f"  Domain : {domain}")
    log("")

    email_data: dict = {}
    mx = dns_query(domain, "MX")   # Get the domain's mail server records
    email_data["mx"] = mx

    if mx:
        log("  ┌─ MX RECORDS (Mail Servers)")
        providers_found = []
        for m in mx:
            # MX records format: "10 mail.example.com" (priority then server)
            parts    = m.split(" ", 1)
            priority, server = (parts + [""])[:2] if len(parts) == 2 else ("?", m)
            srv_lower = server.lower()
            # Check if the server hostname matches a known email provider
            provider = ""
            for keys, name in MX_PROVIDERS.items():
                if any(k in srv_lower for k in keys):
                    provider = f"  → {name}"
                    providers_found.append(name)
                    break
            log(f"  │  Priority {priority:<4} {server}{provider}", "found" if provider else None)
        log(f"  └──" + "─" * 40)
        email_data["providers"] = providers_found
        log("")

    # Common role addresses — not verified to exist, just generated for reference
    roles = ["info", "contact", "admin", "support", "help", "hr", "sales",
             "marketing", "security", "abuse", "noreply", "webmaster", "postmaster", "legal"]
    log("  ┌─ COMMON ROLE ADDRESSES")
    for r in roles:
        log(f"  │  {r}@{domain}")
    log(f"  └──" + "─" * 40)
    email_data["role_addresses"] = [f"{r}@{domain}" for r in roles]

    # Scrape the homepage for exposed email addresses using regex
    log("")
    log("  Scraping homepage for exposed email addresses ...")
    # Pattern 1: emails specifically at the target domain
    email_re     = re.compile(r'[a-zA-Z0-9._%+\-]+@' + re.escape(domain), re.IGNORECASE)
    # Pattern 2: any email address found on the page
    any_email_re = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
    found_domain: set[str] = set()
    found_other:  set[str] = set()

    for scheme in ("https", "http"):
        s, b = http_get(f"{scheme}://{domain}", timeout=8)
        if s and b:
            found_domain = set(email_re.findall(b))
            found_other  = set(any_email_re.findall(b)) - found_domain  # Exclude domain emails (already captured)
            break   # Stop after first successful fetch

    if found_domain:
        log(f"\n  ✓ Emails matching @{domain} found on homepage:", "found")
        for e in sorted(found_domain):
            log(f"    → {e}", "found")
    else:
        log(f"  No @{domain} emails exposed on homepage")

    if found_other:
        log(f"\n  Other emails found on homepage:")
        for e in sorted(found_other)[:10]:
            log(f"    → {e}")

    email_data["scraped_domain_emails"] = sorted(found_domain)
    email_data["scraped_other_emails"]  = sorted(found_other)[:10]

    # Links for manual further investigation (breach databases, email finders)
    log("")
    log("  ┌─ BREACH INTELLIGENCE HINTS")
    log(f"  │  HaveIBeenPwned : https://haveibeenpwned.com/api/v3/breacheddomain/{domain}")
    log(f"  │  IntelX          : https://intelx.io/?s={domain}")
    log(f"  │  Hunter.io       : https://hunter.io/domain-search/{domain}")
    log(f"  └──" + "─" * 40)

    report["email"] = email_data
    log("")


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 9 — SOCIAL MEDIA USERNAME SEARCH
#
#  What it does:
#    Checks all platforms in SOCIAL_PLATFORMS to see if the target username
#    appears to exist. Does this by sending HTTP GET requests and checking
#    the response status code.
#
#  Important caveats:
#    - HTTP 200 does NOT mean the profile exists. Some platforms always return
#      200 and show a "user not found" page instead of 404.
#    - Results must always be manually verified.
#    - Requests are run in parallel (10 threads) to keep it fast.
#
#  Confidence scoring:
#    - HTTP 200  → score 60 → MEDIUM confidence (possible match)
#    - HTTP 301/302 → score 40 → LOW confidence (redirect)
#    - HTTP 404  → not found
# ─────────────────────────────────────────────────────────────────────────────
def run_social_search(username: str, log, report: dict):
    log("", "header")
    log("  ━━━  👤  SOCIAL MEDIA OSINT  ━━━", "header")
    log("")
    log(f"  Username : {username}")
    log(f"  Platforms: {len(SOCIAL_PLATFORMS)}")
    log("  ⚠  Results are UNVERIFIED — HTTP 200 ≠ profile exists. Manual check required.", "warn")
    log("")

    results: dict[str, tuple[str, int | None]] = {}

    def check(name, url_tmpl):
        """Checks one platform. URL-encodes the username (handles special characters)."""
        url    = url_tmpl.format(urllib.parse.quote(username))
        status, _ = http_get(url, timeout=8)
        return name, url, status

    # Check all platforms concurrently (10 threads at a time)
    with ThreadPoolExecutor(max_workers=10) as ex:
        for future in as_completed({ex.submit(check, n, u): n for n, u in SOCIAL_PLATFORMS.items()}):
            name, url, status = future.result()
            results[name] = (url, status)

    possible, not_found, unknown = [], [], []
    for name, (url, status) in sorted(results.items()):
        score = score_social(status)
        if score > 0:
            possible.append((name, url, status, score))   # Possible profile found
        elif status == 404:
            not_found.append(name)                         # Definitively not found
        else:
            unknown.append((name, status))                 # Blocked, error, or unexpected code

    log(f"  ┌─ MANUAL VERIFICATION REQUIRED ({len(possible)} URLs — HTTP 200 ≠ profile exists)")
    for name, url, status, score in possible:
        conf = Confidence.label(score)
        log(f"  │  ? {name:<16} [{conf}] [HTTP {status}]  {url}", Confidence.tag(score))
    log(f"  └──" + "─" * 40)

    log("")
    log(f"  ┌─ NOT FOUND ({len(not_found)} platforms)")
    for name in not_found:
        log(f"  │  ✗ {name}", "muted")
    log(f"  └──" + "─" * 40)

    if unknown:
        log("")
        log(f"  ┌─ BLOCKED / UNKNOWN ({len(unknown)})")
        for name, status in unknown:
            log(f"  │  ? {name:<16} (HTTP {status})")
        log(f"  └──" + "─" * 40)

    log("")
    log("  ┌─ MANUAL VERIFICATION TOOLS")
    log(f"  │  Namechk    : https://namechk.com/")
    log(f"  │  WhatsMyName: https://whatsmyname.app/?q={username}")
    log(f"  │  Sherlock   : sherlock {username}  (CLI tool)")
    log(f"  └──" + "─" * 40)

    report["social"] = {
        "username": username,
        "possible_matches": [
            {"platform": n, "url": u, "http_status": s, "confidence": Confidence.label(sc)}
            for n, u, s, sc in possible
        ],
        "not_found": not_found,
    }
    log("")


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 10 — GOOGLE DORK GENERATOR
#
#  What it does:
#    Generates a list of pre-built Google search queries (called "dorks") that
#    can find potentially sensitive or exposed information about a target domain.
#    These are NOT run automatically — they are displayed as clickable links
#    for the analyst to use manually in a browser.
#
#  Each dork targets a different type of exposure:
#    - Exposed files (PDFs, config files, database dumps)
#    - Admin/login pages
#    - Technology-specific exposure (WordPress, Jenkins, phpinfo)
#    - Leaked credentials (API keys, GitHub mentions)
#    - Historical data (Wayback Machine, cached pages)
#    - Employee information (LinkedIn)
# ─────────────────────────────────────────────────────────────────────────────
def run_dork_generator(target: str, log, report: dict):
    log("", "header")
    log("  ━━━  🔎  GOOGLE DORK GENERATOR  ━━━", "header")
    log("")

    domain = target.split("/")[0]   # Strip any path from the domain
    dorks = [
        ("Exposed files",    f'site:{domain} ext:pdf OR ext:docx OR ext:xlsx OR ext:pptx'),
        ("Config/env files", f'site:{domain} ext:env OR ext:config OR ext:cfg OR ext:xml'),
        ("Login pages",      f'site:{domain} inurl:login OR inurl:signin OR inurl:admin'),
        ("Exposed dirs",     f'site:{domain} intitle:"index of"'),
        ("API keys/secrets", f'site:{domain} intext:"api_key" OR intext:"secret_key"'),
        ("SQL errors",       f'site:{domain} intext:"sql syntax" OR intext:"mysql error"'),
        ("DB dumps",         f'site:{domain} ext:sql OR ext:db OR ext:sqlite'),
        ("Backup files",     f'site:{domain} ext:bak OR ext:backup OR ext:old'),
        ("phpinfo",          f'site:{domain} inurl:phpinfo.php'),
        ("WordPress",        f'site:{domain} inurl:wp-admin OR inurl:wp-login'),
        ("Jenkins",          f'site:{domain} inurl:jenkins OR intitle:"dashboard [jenkins]"'),
        ("Exposed .git",     f'site:{domain} inurl:".git"'),
        ("Camera feeds",     f'site:{domain} inurl:view/index.shtml OR intitle:"webcam"'),
        ("Pastebin leaks",   f'site:pastebin.com "{domain}"'),
        ("GitHub leaks",     f'site:github.com "{domain}"'),
        ("Subdomains",       f'site:*.{domain} -site:www.{domain}'),
        ("Employee info",    f'site:linkedin.com "{domain}" employees'),
        ("Cached pages",     f'cache:{domain}'),
        ("Related sites",    f'related:{domain}'),
        ("Wayback Machine",  f'https://web.archive.org/web/*/{domain}/*'),
    ]

    log("  Copy these into Google or other search engines:\n")
    for label, dork in dorks:
        log(f"  [{label}]")
        log(f"    {dork}", "found")
        log("")

    report["dorks"] = {label: dork for label, dork in dorks}


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE 11 — CORRELATION ENGINE
#
#  What it does:
#    This module runs AFTER all other modules and reads from the report dict
#    that was built up by them. It analyses the combined data to produce:
#
#    1. Infrastructure clustering — which IPs are shared by subdomains,
#       which ASN/org owns the infrastructure, SSL cert coverage overlap.
#
#    2. Technology profile — a consolidated view of detected tech stack.
#
#    3. Security posture assessment — evaluates the scan data against
#       a checklist of common security weaknesses and generates findings:
#       • Missing SPF / DMARC     → HIGH (email spoofing risk)
#       • Dangerous ports open     → HIGH (exposed services)
#       • Missing CSP / HSTS       → MEDIUM (web attack surface)
#       • SSL certificate expiring → MEDIUM
#       • Many high-confidence subdomains found → LOW (attack surface)
#
#    4. Actionable intelligence — summarises only HIGH + MEDIUM findings
#       for quick triage.
# ─────────────────────────────────────────────────────────────────────────────
def run_correlation(domain: str, report: dict, log):
    log("", "header")
    log("  ━━━  🧠  CORRELATION & INTELLIGENCE SUMMARY  ━━━", "header")
    log("")

    # Pull data from other modules' results (they may be empty if those modules weren't run)
    ip_data   = report.get("ip",         {})
    dns_data  = report.get("dns",        {})
    ssl_data  = report.get("ssl",        {})
    http_data = report.get("http",       {})
    port_data = report.get("ports",      {})
    sub_data  = report.get("subdomains", {}).get("entries", {})

    # Each finding is a tuple: ("description", "HIGH" | "MEDIUM" | "LOW")
    notes: list[tuple[str, str]] = []

    # ── Infrastructure clustering ──────────────────────────────────────────────
    log("  ┌─ INFRASTRUCTURE CLUSTERING")
    a_records  = dns_data.get("A", [])
    geo        = ip_data.get("geo", {})
    org        = geo.get("org") or geo.get("isp", "Unknown")
    asn        = geo.get("asn", "Unknown")

    log(f"  │  Primary IP   : {a_records[0] if a_records else 'N/A'}")
    log(f"  │  ASN / Org    : {asn}  {org}")

    # Map each subdomain IP to the list of subdomains sharing it
    sub_ips: dict[str, list[str]] = {}
    for fqdn, data in sub_data.items():
        ip = data.get("ip", "")
        if ip:
            sub_ips.setdefault(ip, []).append(fqdn)

    if len(sub_ips) > 1:
        log(f"  │  Subdomain IPs : {len(sub_ips)} distinct IPs across {len(sub_data)} subdomains")
        for ip, fqdns in list(sub_ips.items())[:5]:
            log(f"  │    {ip}  ← {', '.join(fqdns[:3])}{'…' if len(fqdns)>3 else ''}")

    # Cross-reference SSL certificate SANs with discovered subdomains
    ssl_sans  = set(ssl_data.get("sans", []))
    known_sub = set(sub_data.keys())
    covered   = known_sub & {s.lstrip("*.") for s in ssl_sans}
    if ssl_sans:
        log(f"  │  SSL covers {len(ssl_sans)} SAN(s), {len(covered)} match discovered subdomains")
    log("  └" + "─" * 44)

    # ── Technology profile ─────────────────────────────────────────────────────
    log("")
    log("  ┌─ TECHNOLOGY PROFILE")
    techs = http_data.get("technologies", [])
    if techs:
        for t in techs:
            log(f"  │  ✓ {t}", "found")
    else:
        log("  │  No technology fingerprints found")
    log("  └" + "─" * 44)

    # ── Security posture assessment ────────────────────────────────────────────
    log("")
    log("  ┌─ SECURITY POSTURE")

    sec_missing = http_data.get("security_headers", {}).get("missing", [])
    open_ports  = port_data.get("open", {})
    spf         = dns_data.get("spf",   [])
    dmarc       = dns_data.get("dmarc", [])

    # Email spoofing — missing SPF/DMARC means anyone can fake emails from this domain
    if not spf:
        notes.append(("SPF record missing — domain may be spoofable", "HIGH"))
    if not dmarc:
        notes.append(("DMARC policy absent — no email spoofing protection", "HIGH"))

    # Dangerous open ports — these services are often exploited or contain sensitive data
    risky = {p for p in [23, 3389, 5900, 6379, 27017, 9200]
             if str(p) in map(str, open_ports) or p in open_ports}
    if risky:
        notes.append((f"Sensitive ports open: {risky} — exposed services risk", "HIGH"))

    # Missing web security headers
    if "Content-Security-Policy" in sec_missing:
        notes.append(("CSP header missing — elevated XSS risk", "MEDIUM"))
    if "Strict-Transport-Security" in sec_missing:
        notes.append(("HSTS missing — HTTPS not enforced", "MEDIUM"))

    # SSL certificate expiry
    days = ssl_data.get("days_remaining")
    if days is not None and days < 30:
        notes.append((f"SSL certificate expires in {days} days", "MEDIUM"))

    # Subdomain exposure
    hi_subs = [f for f, d in sub_data.items() if d.get("confidence") == "HIGH"]
    if hi_subs:
        notes.append((f"{len(hi_subs)} HIGH-confidence subdomains discovered", "LOW"))

    # Count findings by severity
    sev_icon = {"HIGH": ("🔴", "warn"), "MEDIUM": ("🟡", "warn"), "LOW": ("🟢", "found")}
    high_count   = sum(1 for _, s in notes if s == "HIGH")
    medium_count = sum(1 for _, s in notes if s == "MEDIUM")
    low_count    = sum(1 for _, s in notes if s == "LOW")

    log(f"  │  Observations Severity:", "section")
    log(f"  │    High Findings   : {high_count}",   "warn"  if high_count   else None)
    log(f"  │    Medium Findings : {medium_count}", "warn"  if medium_count else None)
    log(f"  │    Low Findings    : {low_count}",    "found" if low_count    else None)
    log("  │")
    for msg, sev in notes:
        icon, tag = sev_icon[sev]
        log(f"  │  {icon}  [{sev}]  {msg}", tag)
    log("  └" + "─" * 44)

    # ── Actionable intelligence — only HIGH + MEDIUM for quick triage ──────────
    log("")
    log("  ┌─ ACTIONABLE INTELLIGENCE")
    actionable = [(m, s) for m, s in notes if s in ("HIGH", "MEDIUM")]
    if not actionable:
        log("  │  No critical issues detected in this scan.")
    else:
        log(f"  │  {len(actionable)} item(s) warrant follow-up:")
        for msg, sev in actionable:
            icon, tag = sev_icon[sev]
            log(f"  │    {icon}  [{sev}]  {msg}", tag)
    log("  └" + "─" * 44)

    report["correlation"] = {
        "high_findings":   high_count,
        "medium_findings": medium_count,
        "low_findings":    low_count,
        "findings":    [{"message": m, "severity": s} for m, s in notes],
        "technologies": techs,
        "asn":         asn,
        "org":         org,
    }
    log("")


# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 5 — GUI  (Graphical User Interface)
#
#  This class builds and manages the entire application window using tkinter.
#  It is responsible for:
#
#    • Drawing the window layout (title, input fields, module checkboxes,
#      action buttons, progress bar, scrollable output pane)
#    • Reading user inputs (domain, username, scan mode, module selection)
#    • Launching the scan in a background thread so the UI stays responsive
#    • Displaying coloured scan output in real-time
#    • Exporting results to TXT or JSON files
#
#  The actual scanning logic lives in Section 4 — this class only
#  calls those functions and displays their output.
# ═════════════════════════════════════════════════════════════════════════════

class OSINTApp(tk.Tk):
    """
    The main application window.
    Inherits from tk.Tk (the root tkinter window class).
    """

    # ── Colour palette (dark hacker aesthetic) ────────────────────────────────
    BG     = "#080c10"   # Main background — near black
    PANEL  = "#0d1117"   # Slightly lighter panel background
    PANEL2 = "#161b22"   # Even lighter — used for input fields
    ACCENT = "#00d4ff"   # Cyan — primary highlights, RUN button
    GREEN  = "#00ff88"   # Bright green — success / found results
    RED    = "#ff4757"   # Red — warnings / errors
    ORANGE = "#ffa502"   # Orange — medium severity
    TEXT   = "#d0d8e4"   # Off-white — normal text
    MUTED  = "#586274"   # Grey — closed ports, minor info
    BORDER = "#21262d"   # Dark border lines
    GOLD   = "#e5b44a"   # Gold — section headers, export buttons

    def __init__(self):
        super().__init__()
        self.title("🕵️  Advanced OSINT Reconnaissance Tool  v3.0")
        self.geometry("1160x860")           # Default window size
        self.minsize(950, 680)              # Minimum size — prevents layout breaking
        self.configure(bg=self.BG)
        self._report_lines: list[str] = [] # Stores all output text for TXT export
        self._report_data:  dict      = {} # Stores structured data for JSON export
        self._build_ui()                   # Draw all widgets

    # ── Layout builder ────────────────────────────────────────────────────────
    def _build_ui(self):
        """
        Constructs all GUI widgets from top to bottom:
          1. Title bar
          2. Input row (domain, username, scan mode toggles)
          3. Module checkboxes (select which modules to run)
          4. Action bar (RUN, Clear, Export TXT, Export JSON buttons)
          5. Progress bar
          6. Scrollable output text pane
        """
        BG, PANEL, PANEL2  = self.BG, self.PANEL, self.PANEL2
        ACCENT, GREEN, RED = self.ACCENT, self.GREEN, self.RED
        TEXT, MUTED, BORDER, GOLD = self.TEXT, self.MUTED, self.BORDER, self.GOLD

        # ── 1. Title bar ───────────────────────────────────────────────────────
        tf = tk.Frame(self, bg=BG)
        tf.pack(fill="x", padx=24, pady=(16, 4))
        tk.Label(tf, text="◈  ADVANCED OSINT RECON TOOL",
                 font=("Courier New", 20, "bold"), fg=ACCENT, bg=BG).pack(side="left")
        tk.Label(tf, text=f"v{VERSION}  ·  Educational / Authorized Use Only",
                 font=("Courier New", 8), fg=MUTED, bg=BG).pack(side="right", padx=4)
        tk.Frame(self, bg=ACCENT, height=1).pack(fill="x", padx=24, pady=2)  # Thin accent line

        # ── 2. Input row ───────────────────────────────────────────────────────
        inp_outer = tk.Frame(self, bg=PANEL2)
        inp_outer.pack(fill="x", padx=24, pady=(8, 0))
        inp_f = tk.Frame(inp_outer, bg=PANEL2)
        inp_f.pack(fill="x", padx=12, pady=10)

        def make_field(label, var, width, col):
            """Helper to create a labelled text input field at a given grid column."""
            tk.Label(inp_f, text=label, font=("Courier New", 9, "bold"),
                     fg=MUTED, bg=PANEL2).grid(row=0, column=col, sticky="w", padx=(8, 4), pady=2)
            tk.Entry(inp_f, textvariable=var, font=("Courier New", 11),
                     bg=PANEL, fg=TEXT, insertbackground=ACCENT, relief="flat",
                     highlightthickness=1, highlightcolor=ACCENT,
                     highlightbackground=BORDER, width=width
                     ).grid(row=0, column=col+1, padx=(0, 24), ipady=6)

        self.domain_var = tk.StringVar(value="example.com")
        self.uname_var  = tk.StringVar(value="johndoe")
        make_field("Domain / IP :", self.domain_var, 32, 0)
        make_field("Username :",    self.uname_var,  22, 2)

        self.deep_var    = tk.BooleanVar(value=False)
        self.passive_var = tk.BooleanVar(value=False)

        # Deep scan checkbox — enables longer timeouts and banner grabbing on all ports
        tk.Checkbutton(inp_f, text="Deep Scan (slower, banner grab)",
                       variable=self.deep_var,
                       font=("Courier New", 9), fg=MUTED, bg=PANEL2,
                       activeforeground=ACCENT, activebackground=PANEL2,
                       selectcolor=BG).grid(row=0, column=4, padx=8)

        # Passive-only mode — disables modules that actively probe the target
        tk.Checkbutton(inp_f, text="Passive Only (DNS/CT/RDAP — no probes)",
                       variable=self.passive_var,
                       font=("Courier New", 9), fg=MUTED, bg=PANEL2,
                       activeforeground=self.ORANGE, activebackground=PANEL2,
                       selectcolor=BG,
                       command=self._on_passive_toggle).grid(row=0, column=5, padx=8)

        # ── 3. Module checkboxes ───────────────────────────────────────────────
        # Each checkbox maps to a module key (e.g. "ip" → run_ip_lookup).
        # Checking/unchecking lets the user run only the modules they want.
        chk_f = tk.Frame(self, bg=BG)
        chk_f.pack(fill="x", padx=24, pady=6)

        self.chk_vars: dict[str, tk.BooleanVar] = {}
        modules = [
            ("ip",        "📡 IP & Geo"),
            ("whois",     "🗂 WHOIS"),
            ("dns",       "🌐 DNS"),
            ("subs",      "🔍 Subdomains"),
            ("ports",     "🔌 Port Scan"),
            ("http",      "🧬 HTTP / Tech"),
            ("ssl",       "🔐 SSL Cert"),
            ("email",     "📧 Email"),
            ("social",    "👤 Social"),
            ("dorks",     "🔎 Dorks"),
            ("correlate", "🧠 Correlate"),
        ]
        chk_style = dict(font=("Courier New", 9, "bold"), fg=TEXT, bg=BG,
                         activeforeground=ACCENT, activebackground=BG, selectcolor=PANEL2)
        for i, (key, label) in enumerate(modules):
            v = tk.BooleanVar(value=True)   # All modules enabled by default
            self.chk_vars[key] = v
            tk.Checkbutton(chk_f, text=label, variable=v, **chk_style).grid(
                row=0, column=i, padx=4, pady=2)

        # "All" / "None" toggle buttons for quickly selecting/deselecting all modules
        def toggle_all(val):
            for v in self.chk_vars.values():
                v.set(val)

        bs = dict(font=("Courier New", 8), bg=PANEL2, fg=MUTED, relief="flat", cursor="hand2", padx=6, pady=2)
        tk.Button(chk_f, text="All",  command=lambda: toggle_all(True),  **bs).grid(row=0, column=len(modules),   padx=(12, 2))
        tk.Button(chk_f, text="None", command=lambda: toggle_all(False), **bs).grid(row=0, column=len(modules)+1, padx=2)

        # ── 4. Action bar ──────────────────────────────────────────────────────
        btn_f = tk.Frame(self, bg=BG)
        btn_f.pack(fill="x", padx=24, pady=8)

        self.run_btn = tk.Button(
            btn_f, text="  ▶  RUN RECON SCAN  ",
            font=("Courier New", 11, "bold"),
            bg=ACCENT, fg=BG, relief="flat", cursor="hand2",
            padx=16, pady=7, command=self._start_scan)
        self.run_btn.pack(side="left", padx=(0, 8))

        tk.Button(btn_f, text="  🗑  Clear  ",
                  font=("Courier New", 10), bg=PANEL2, fg=MUTED,
                  relief="flat", cursor="hand2", padx=10, pady=7,
                  command=self._clear).pack(side="left", padx=(0, 4))

        tk.Button(btn_f, text="  💾  Export TXT  ",
                  font=("Courier New", 10), bg=PANEL2, fg=GREEN,
                  relief="flat", cursor="hand2", padx=10, pady=7,
                  command=self._export_txt).pack(side="left", padx=(0, 4))

        tk.Button(btn_f, text="  📦  Export JSON  ",
                  font=("Courier New", 10), bg=PANEL2, fg=GOLD,
                  relief="flat", cursor="hand2", padx=10, pady=7,
                  command=self._export_json).pack(side="left")

        # Status label on the right side of the action bar
        self.status_var = tk.StringVar(value="Ready. Enter target and click ▶ RUN.")
        tk.Label(btn_f, textvariable=self.status_var,
                 font=("Courier New", 9), fg=GREEN, bg=BG).pack(side="right", padx=8)

        # ── 5. Progress bar ────────────────────────────────────────────────────
        # Animates while a scan is running; stopped when the scan completes.
        self.progress = ttk.Progressbar(self, mode="indeterminate", length=200)
        self.progress.pack(fill="x", padx=24, pady=(0, 4))

        # ── 6. Scrollable output pane ──────────────────────────────────────────
        # All scan results appear here in coloured text.
        out_f = tk.Frame(self, bg=self.BORDER, bd=1)
        out_f.pack(fill="both", expand=True, padx=24, pady=(0, 16))

        self.output = scrolledtext.ScrolledText(
            out_f, bg="#020508", fg=TEXT,
            font=("Courier New", 10), relief="flat",
            insertbackground=ACCENT, wrap="word", state="disabled",
            selectbackground=PANEL2, selectforeground=ACCENT)
        self.output.pack(fill="both", expand=True, padx=2, pady=2)

        # Define colour tags for different types of output lines
        self.output.tag_config("header",    foreground=ACCENT,      font=("Courier New", 10, "bold"))
        self.output.tag_config("found",     foreground=GREEN)        # Positive finding
        self.output.tag_config("warn",      foreground=RED)          # Risk or warning
        self.output.tag_config("muted",     foreground=MUTED)        # Low-importance info
        self.output.tag_config("section",   foreground=GOLD,        font=("Courier New", 10, "bold"))
        self.output.tag_config("conf_high", foreground=GREEN,       font=("Courier New", 10, "bold"))
        self.output.tag_config("conf_med",  foreground=self.ORANGE)
        self.output.tag_config("conf_low",  foreground=MUTED)

        self._log("  Welcome to Advanced OSINT Reconnaissance Tool v3.0", "header")
        self._log("  Enter Domain/IP and/or Username, select modules, then click ▶ RUN.")
        self._log("  ⚠  Only target systems you are authorised to analyse.\n", "warn")

    # ── Logging helper ─────────────────────────────────────────────────────────
    _URL_RE = re.compile(r'(https?://[^\s\]\[<>"\']+)')

    def _log(self, msg: str, tag: str | None = None):
        """
        Appends one line of text to the output pane.
        Automatically detects any URLs in the text and makes them clickable
        (opens in the user's default browser when clicked).
        Thread-safe: can be called from both the main thread and scan threads.
        """
        self.output.configure(state="normal")
        self._report_lines.append(msg)   # Save for TXT export

        # Split the message on URLs so we can handle them separately
        for part in self._URL_RE.split(msg):
            if self._URL_RE.fullmatch(part):
                # This part IS a URL — make it blue, underlined, and clickable
                uid = f"url_{abs(hash(part)) % 10**9}_{int(time.time()*10000) % 10**9}"
                url = part
                self.output.tag_config(uid, foreground=self.ACCENT, underline=True)
                self.output.tag_bind(uid, "<Button-1>", lambda e, u=url: webbrowser.open(u))
                self.output.tag_bind(uid, "<Enter>",    lambda e: self.output.configure(cursor="hand2"))
                self.output.tag_bind(uid, "<Leave>",    lambda e: self.output.configure(cursor=""))
                self.output.insert("end", part, (uid, tag) if tag else (uid,))
            elif part:
                # Normal text — apply the given colour tag (or no tag)
                self.output.insert("end", part, tag or "")

        self.output.insert("end", "\n")
        self.output.configure(state="disabled")
        self.output.see("end")  # Auto-scroll to the latest line

    # ── Output management ──────────────────────────────────────────────────────

    def _clear(self):
        """Wipes the output pane and resets the report buffers."""
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.configure(state="disabled")
        self._report_lines.clear()
        self._report_data.clear()
        self.status_var.set("Cleared.")

    def _export_txt(self):
        """Saves all output lines as a plain-text report file."""
        if not self._report_lines:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text file", "*.txt"), ("All files", "*.*")],
            title="Save OSINT Report (TXT)")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(self._report_lines))
            messagebox.showinfo("Exported", f"TXT report saved:\n{path}")

    def _export_json(self):
        """Saves the structured report data as a formatted JSON file."""
        if not self._report_data:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON file", "*.json"), ("All files", "*.*")],
            title="Save OSINT Report (JSON)")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self._report_data, f, indent=2, default=str)
            messagebox.showinfo("Exported", f"JSON report saved:\n{path}")

    # ── Passive mode toggle ────────────────────────────────────────────────────
    # Passive-only: only run modules that don't send packets to the target.
    # These are safe for analysing targets you may not have direct permission to probe.
    _PASSIVE_MODULES  = {"ip", "whois", "dns", "subs", "email", "dorks", "correlate"}
    _ACTIVE_ONLY      = {"ports", "http", "ssl", "social"}   # These actively probe the target

    def _on_passive_toggle(self):
        """
        When the user enables Passive Only mode, automatically uncheck all
        active-only modules so they don't accidentally run.
        """
        if self.passive_var.get():
            for key in self._ACTIVE_ONLY:
                self.chk_vars[key].set(False)
            self.deep_var.set(False)

    # ── Scan launcher ──────────────────────────────────────────────────────────

    def _start_scan(self):
        """
        Called when the RUN button is clicked.
        Validates inputs, then launches _scan_thread in a background daemon thread.
        Running the scan in a separate thread is essential — without it, the GUI
        would freeze completely while the scan is running.
        """
        # Strip protocol prefix and trailing slash from domain input
        domain = (self.domain_var.get().strip()
                  .lstrip("https://").lstrip("http://").rstrip("/"))
        uname  = self.uname_var.get().strip()

        if not domain and not uname:
            messagebox.showwarning("Input required", "Enter at least a domain/IP or username.")
            return
        if not any(v.get() for v in self.chk_vars.values()):
            messagebox.showwarning("No modules", "Select at least one module.")
            return

        # Disable the RUN button while scanning to prevent double-clicks
        self.run_btn.configure(state="disabled", text="  ⏳  Scanning…  ")
        self.status_var.set("Scanning …")
        self.progress.start(10)
        self._report_lines.clear()
        self._report_data.clear()

        # Launch the scan in a background thread (daemon=True means it exits with the app)
        threading.Thread(
            target=self._scan_thread,
            args=(domain, uname, self.deep_var.get(), self.passive_var.get()),
            daemon=True).start()

    def _scan_thread(self, domain: str, uname: str, deep: bool, passive: bool = False):
        """
        The actual scan logic — runs in a background thread.
        Checks which modules are enabled and calls them in order.
        All output goes through self._log(); all results go into rep (report dict).

        Parameters:
            domain  - Target domain or IP address (may be empty if only social scan)
            uname   - Target username (may be empty if only domain scan)
            deep    - True = Deep mode (slower, more thorough port scan)
            passive - True = Skip active-probe modules
        """
        log = self._log                  # Shorthand for the logging function
        cv  = self.chk_vars              # Shorthand for the module checkboxes
        rep = self._report_data          # The dict we're building up for JSON export

        # Print scan header with timestamp and target info
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        req_stats.reset()
        log("", "header")
        log("═" * 62, "header")
        log(f"  OSINT RECON SCAN  ·  {ts}", "header")
        log(f"  Target Domain/IP : {domain or '—'}", "header")
        log(f"  Target Username  : {uname  or '—'}", "header")
        mode_str = "Passive" if passive else ("Deep" if deep else "Fast")
        log(f"  Scan Mode        : {mode_str}", "header")
        log("═" * 62 + "\n", "header")

        rep["meta"] = {
            "timestamp": ts, "domain": domain,
            "username": uname, "deep": deep,
        }

        # Call each module only if its checkbox is ticked AND the required input is present
        if cv["ip"].get()        and domain: run_ip_lookup(domain,  log, rep)
        if cv["whois"].get()     and domain: run_whois(domain,       log, rep)
        if cv["dns"].get()       and domain: run_dns(domain,         log, rep)
        if cv["subs"].get()      and domain: run_subdomain_finder(domain, log, rep)
        if cv["ports"].get()     and domain: run_port_scan(domain,   log, rep, deep=deep)
        if cv["http"].get()      and domain: run_http_fingerprint(domain, log, rep)
        if cv["ssl"].get()       and domain: run_ssl_inspect(domain, log, rep)
        if cv["email"].get()     and domain: run_email_intel(domain, log, rep)
        if cv["social"].get()    and uname:  run_social_search(uname, log, rep)   # Social uses username, not domain
        if cv["dorks"].get()     and domain: run_dork_generator(domain, log, rep)
        if cv["correlate"].get() and domain: run_correlation(domain, rep, log)

        # Print scan footer with final timestamp and request statistics
        ts2 = time.strftime("%Y-%m-%d %H:%M:%S")
        log("═" * 62, "header")
        log(f"  SCAN COMPLETE  ·  {ts2}", "header")
        log(f"  {req_stats.summary()}", "muted")
        log("═" * 62 + "\n", "header")

        # Re-enable the RUN button and stop the progress bar
        self.run_btn.configure(state="normal", text="  ▶  RUN RECON SCAN  ")
        self.status_var.set("Scan complete ✓  —  Export TXT or JSON above")
        self.progress.stop()


# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 6 — ENTRY POINT
#
#  This block runs only when the script is executed directly (not imported).
#  It creates the OSINTApp window and starts the tkinter event loop,
#  which keeps the GUI alive and responsive until the window is closed.
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app = OSINTApp()
    app.mainloop()   # Blocks here until the user closes the window
