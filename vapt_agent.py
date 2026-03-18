#!/usr/bin/env python3
"""
VAPT AI Agent - Automated Vulnerability Assessment & Penetration Testing
Performs: port scanning, tech/package detection, CVE lookups, upgrade guidance
"""

import asyncio
import json
import re
import socket
import ssl
import subprocess
import sys
import urllib.request
import urllib.error
from datetime import datetime
from typing import Optional
import anthropic

# ── Anthropic client ──────────────────────────────────────────────────────────
client = anthropic.Anthropic()

# ── Tool definitions ──────────────────────────────────────────────────────────
TOOLS = [
    {
        "name": "scan_ports",
        "description": (
            "Scan common TCP ports on a target host to discover open services. "
            "Returns a list of open ports with service banners where available."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Target hostname or IP"},
                "ports": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "List of ports to scan. Defaults to common web ports.",
                },
            },
            "required": ["host"],
        },
    },
    {
        "name": "grab_banner",
        "description": "Grab HTTP/HTTPS response headers and server banner from a URL to identify web server software and version.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Full URL (http:// or https://)"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "detect_technologies",
        "description": "Detect web technologies, frameworks, CMS, and JavaScript libraries used by a website by analysing HTTP response headers and page content.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Full URL of the target website"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "check_ssl_tls",
        "description": "Inspect the SSL/TLS certificate and configuration of a host: expiry date, issuer, protocol versions, and basic misconfigs.",
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Hostname (no https://)"},
                "port": {"type": "integer", "description": "Port, default 443"},
            },
            "required": ["host"],
        },
    },
    {
        "name": "check_security_headers",
        "description": "Check HTTP security headers (CSP, HSTS, X-Frame-Options, etc.) and flag missing or misconfigured ones.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Full URL of the target website"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "lookup_cve",
        "description": "Search the NVD (National Vulnerability Database) for known CVEs affecting a specific technology/package and version.",
        "input_schema": {
            "type": "object",
            "properties": {
                "keyword": {"type": "string", "description": "Technology name, e.g. 'Apache 2.4.49'"},
                "max_results": {"type": "integer", "description": "Max CVEs to return, default 5"},
            },
            "required": ["keyword"],
        },
    },
    {
        "name": "generate_upgrade_steps",
        "description": "Generate step-by-step upgrade/remediation instructions for a given technology or package vulnerability.",
        "input_schema": {
            "type": "object",
            "properties": {
                "technology": {"type": "string", "description": "Technology name and current version"},
                "vulnerability": {"type": "string", "description": "Brief description of the vulnerability"},
                "target_version": {"type": "string", "description": "Safe/recommended version if known"},
            },
            "required": ["technology", "vulnerability"],
        },
    },
    {
        "name": "scan_js_libraries",
        "description": (
            "Deep-scan a webpage for ALL JavaScript libraries and frameworks, extract their versions, "
            "and check each against a known-vulnerable version database. Returns each library with: "
            "detected version, latest safe version, whether it is vulnerable, known CVEs, and severity."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Full URL of the target webpage"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "audit_http_headers",
        "description": (
            "Comprehensive audit of ALL HTTP response headers: checks for missing security headers, "
            "misconfigured values, information-leaking headers, and cookie security flags. "
            "Returns per-header severity, current value, recommended value, and exact remediation config "
            "for Apache, Nginx, and IIS."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Full URL of the target website"},
            },
            "required": ["url"],
        },
    },
]


# ── Tool implementations ──────────────────────────────────────────────────────

def scan_ports(host: str, ports: Optional[list] = None) -> dict:
    """TCP connect scan on specified ports."""
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                 3306, 3389, 5432, 6379, 8080, 8443, 8888, 27017]

    open_ports = []
    closed_ports = []

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            result = sock.connect_ex((host, port))
            if result == 0:
                banner = ""
                try:
                    if port in (80, 8080, 8888):
                        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = sock.recv(512).decode(errors="ignore").split("\r\n")[0]
                    else:
                        sock.settimeout(0.5)
                        banner = sock.recv(256).decode(errors="ignore").strip()[:120]
                except Exception:
                    pass
                service = _common_service(port)
                open_ports.append({"port": port, "service": service, "banner": banner})
            else:
                closed_ports.append(port)
            sock.close()
        except Exception as e:
            closed_ports.append(port)

    return {
        "host": host,
        "open_ports": open_ports,
        "total_scanned": len(ports),
        "open_count": len(open_ports),
    }


def _common_service(port: int) -> str:
    services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
        8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt", 27017: "MongoDB",
    }
    return services.get(port, "Unknown")


def grab_banner(url: str) -> dict:
    """Fetch HTTP headers to identify server software."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "VAPTAgent/1.0"})
        with urllib.request.urlopen(req, timeout=8, context=ctx if url.startswith("https") else None) as resp:
            headers = dict(resp.headers)
            return {
                "url": url,
                "status_code": resp.status,
                "server": headers.get("Server", "Not disclosed"),
                "x_powered_by": headers.get("X-Powered-By", ""),
                "via": headers.get("Via", ""),
                "headers": {k: v for k, v in headers.items()},
            }
    except Exception as e:
        return {"url": url, "error": str(e)}


def detect_technologies(url: str) -> dict:
    """Detect CMS, frameworks, and JS libs from headers and page source."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    technologies = []
    versions = {}

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 VAPTAgent/1.0"})
        with urllib.request.urlopen(req, timeout=10, context=ctx if url.startswith("https") else None) as resp:
            headers = dict(resp.headers)
            body = resp.read(65536).decode(errors="ignore")

        # Server
        server = headers.get("Server", "")
        if server:
            technologies.append({"name": server, "category": "Web Server"})

        # Powered-by
        xpb = headers.get("X-Powered-By", "")
        if xpb:
            technologies.append({"name": xpb, "category": "Framework/Runtime"})

        # WordPress
        if "wp-content" in body or "wp-includes" in body:
            v = re.search(r'WordPress (\d+\.\d+[\.\d]*)', body)
            ver = v.group(1) if v else "unknown"
            technologies.append({"name": f"WordPress {ver}", "category": "CMS", "version": ver})

        # Drupal
        if "Drupal" in body or "/sites/default/" in body:
            technologies.append({"name": "Drupal", "category": "CMS"})

        # Joomla
        if "/components/com_" in body:
            technologies.append({"name": "Joomla", "category": "CMS"})

        # React
        if "react" in body.lower() and ("__REACT" in body or "data-reactroot" in body):
            technologies.append({"name": "React", "category": "JS Framework"})

        # jQuery
        jq = re.search(r'jquery[.\-/](\d+\.\d+[\.\d]*)', body, re.I)
        if jq:
            technologies.append({"name": f"jQuery {jq.group(1)}", "category": "JS Library", "version": jq.group(1)})

        # Bootstrap
        bs = re.search(r'bootstrap[.\-/](\d+\.\d+[\.\d]*)', body, re.I)
        if bs:
            technologies.append({"name": f"Bootstrap {bs.group(1)}", "category": "CSS Framework", "version": bs.group(1)})

        # Angular
        if "ng-version=" in body or "__ngContext__" in body:
            nv = re.search(r'ng-version="([\d.]+)"', body)
            technologies.append({"name": f"Angular {nv.group(1) if nv else ''}", "category": "JS Framework"})

        # Vue
        if "__vue_app__" in body or "vue.min.js" in body.lower():
            technologies.append({"name": "Vue.js", "category": "JS Framework"})

        # PHP
        php = re.search(r'PHP/([\d.]+)', server + xpb)
        if php:
            technologies.append({"name": f"PHP {php.group(1)}", "category": "Runtime", "version": php.group(1)})

        # Nginx / Apache version parse
        for webserver in ["nginx", "Apache"]:
            m = re.search(rf'{webserver}/([\d.]+)', server, re.I)
            if m:
                versions[webserver] = m.group(1)

        return {"url": url, "technologies": technologies, "raw_server": server, "versions": versions}

    except Exception as e:
        return {"url": url, "error": str(e), "technologies": []}


def check_ssl_tls(host: str, port: int = 443) -> dict:
    """Check SSL/TLS certificate details."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher = ssock.cipher()

        issues = []
        not_after = cert.get("notAfter", "")
        expiry = None
        if not_after:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.utcnow()).days
            if days_left < 0:
                issues.append(f"CRITICAL: Certificate EXPIRED {abs(days_left)} days ago")
            elif days_left < 30:
                issues.append(f"WARNING: Certificate expires in {days_left} days")

        if protocol in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            issues.append(f"CRITICAL: Weak protocol in use: {protocol}")

        return {
            "host": host,
            "port": port,
            "protocol": protocol,
            "cipher": cipher[0] if cipher else "Unknown",
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "subject": dict(x[0] for x in cert.get("subject", [])),
            "expires": str(expiry) if expiry else not_after,
            "san": [v for _, v in cert.get("subjectAltName", [])],
            "issues": issues,
        }
    except Exception as e:
        return {"host": host, "port": port, "error": str(e)}


def check_security_headers(url: str) -> dict:
    """Audit HTTP security headers."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    REQUIRED = {
        "Strict-Transport-Security": "Protects against downgrade attacks (HSTS)",
        "Content-Security-Policy": "Mitigates XSS and data injection attacks",
        "X-Content-Type-Options": "Prevents MIME sniffing",
        "X-Frame-Options": "Prevents clickjacking",
        "Referrer-Policy": "Controls referrer information",
        "Permissions-Policy": "Controls browser features",
    }

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "VAPTAgent/1.0"})
        with urllib.request.urlopen(req, timeout=8, context=ctx if url.startswith("https") else None) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}

        present, missing = [], []
        for header, desc in REQUIRED.items():
            if header.lower() in headers:
                present.append({"header": header, "value": headers[header.lower()]})
            else:
                missing.append({"header": header, "description": desc, "severity": "Medium"})

        # Flag dangerous headers
        warnings = []
        if "server" in headers and headers["server"] not in ("", "cloudflare"):
            warnings.append(f"Server header discloses version: {headers['server']}")
        if "x-powered-by" in headers:
            warnings.append(f"X-Powered-By discloses technology: {headers['x-powered-by']}")

        return {
            "url": url,
            "present_headers": present,
            "missing_headers": missing,
            "warnings": warnings,
            "score": f"{len(present)}/{len(REQUIRED)}",
        }
    except Exception as e:
        return {"url": url, "error": str(e)}


def lookup_cve(keyword: str, max_results: int = 5) -> dict:
    """Query NVD API for CVEs matching a keyword."""
    encoded = urllib.parse.quote(keyword) if hasattr(urllib, "parse") else keyword.replace(" ", "%20")
    api_url = (
        f"https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?keywordSearch={encoded}&resultsPerPage={max_results}"
    )
    try:
        import urllib.parse
        encoded = urllib.parse.quote(keyword)
        api_url = (
            f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?keywordSearch={encoded}&resultsPerPage={max_results}"
        )
        req = urllib.request.Request(api_url, headers={"User-Agent": "VAPTAgent/1.0"})
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = json.loads(resp.read())

        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                "No description"
            )
            metrics = cve.get("metrics", {})
            cvss_score = None
            severity = "UNKNOWN"
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    m = metrics[key][0].get("cvssData", {})
                    cvss_score = m.get("baseScore")
                    severity = m.get("baseSeverity", "UNKNOWN")
                    break
            cves.append({
                "id": cve_id,
                "description": desc[:300],
                "cvss_score": cvss_score,
                "severity": severity,
                "published": cve.get("published", "")[:10],
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })

        return {"keyword": keyword, "total_found": data.get("totalResults", 0), "cves": cves}
    except Exception as e:
        return {"keyword": keyword, "error": str(e), "cves": []}


def generate_upgrade_steps(technology: str, vulnerability: str, target_version: str = "") -> dict:
    """Return remediation steps (structured, not AI-generated here — AI agent will elaborate)."""
    steps_map = {
        "wordpress": [
            "1. Backup your database and files: `wp db export backup.sql && tar -czf backup.tgz wp-content/`",
            "2. Update via WP-CLI: `wp core update` or Dashboard → Updates",
            "3. Update all plugins: `wp plugin update --all`",
            "4. Update all themes: `wp theme update --all`",
            "5. Verify site integrity after update",
        ],
        "apache": [
            "1. Check current version: `apache2 -v` or `httpd -v`",
            "2. Ubuntu/Debian: `sudo apt update && sudo apt upgrade apache2`",
            "3. RHEL/CentOS: `sudo yum update httpd`",
            "4. Restart: `sudo systemctl restart apache2`",
            "5. Confirm version: `apache2 -v`",
        ],
        "nginx": [
            "1. Ubuntu/Debian: `sudo apt update && sudo apt upgrade nginx`",
            "2. RHEL/CentOS: `sudo yum update nginx`",
            "3. Restart: `sudo systemctl restart nginx`",
        ],
        "jquery": [
            "1. Replace CDN link: <script src=\"https://code.jquery.com/jquery-3.7.1.min.js\">",
            "2. Or update via npm: `npm update jquery`",
            "3. Test all JS functionality after upgrade",
        ],
        "php": [
            "1. Ubuntu: `sudo add-apt-repository ppa:ondrej/php && sudo apt update && sudo apt install php8.3`",
            "2. Update php.ini settings as needed",
            "3. Restart web server",
        ],
        "ssl": [
            "1. Renew certificate: `sudo certbot renew` (Let's Encrypt)",
            "2. Disable TLS 1.0/1.1 in nginx: `ssl_protocols TLSv1.2 TLSv1.3;`",
            "3. Test with: `openssl s_client -connect host:443`",
        ],
    }

    tech_lower = technology.lower()
    steps = []
    for key, val in steps_map.items():
        if key in tech_lower:
            steps = val
            break

    if not steps:
        steps = [
            f"1. Identify the current version of {technology}",
            f"2. Review the official changelog/security advisories for {technology}",
            f"3. Update to {target_version or 'the latest stable version'} following the vendor guide",
            "4. Test functionality in a staging environment before production",
            "5. Monitor logs after update for any regressions",
        ]

    return {
        "technology": technology,
        "vulnerability": vulnerability,
        "recommended_version": target_version or "Latest stable",
        "steps": steps,
    }


# ── Known-vulnerable JS library database ─────────────────────────────────────
# Format: library_key → { "safe_from": "version", "cves": [...], "severity": str }
JS_VULN_DB = {
    "jquery": [
        {"affected_below": "1.9.0",  "severity": "HIGH",     "cve": "CVE-2011-4969",  "issue": "XSS via location.hash"},
        {"affected_below": "3.0.0",  "severity": "MEDIUM",   "cve": "CVE-2015-9251",  "issue": "XSS via cross-domain Ajax"},
        {"affected_below": "3.4.0",  "severity": "MEDIUM",   "cve": "CVE-2019-11358", "issue": "Prototype Pollution"},
        {"affected_below": "3.5.0",  "severity": "MEDIUM",   "cve": "CVE-2020-11022", "issue": "XSS via HTML parsing"},
        {"affected_below": "3.5.0",  "severity": "MEDIUM",   "cve": "CVE-2020-11023", "issue": "XSS in .html() method"},
        {"affected_below": "3.7.1",  "severity": "INFO",     "cve": "",               "issue": "Not latest stable (3.7.1)"},
    ],
    "jquery-ui": [
        {"affected_below": "1.13.0", "severity": "HIGH",     "cve": "CVE-2021-41182", "issue": "XSS in Datepicker"},
        {"affected_below": "1.13.0", "severity": "HIGH",     "cve": "CVE-2021-41183", "issue": "XSS via location.hash"},
        {"affected_below": "1.13.0", "severity": "HIGH",     "cve": "CVE-2021-41184", "issue": "XSS in closeText option"},
        {"affected_below": "1.13.2", "severity": "MEDIUM",   "cve": "CVE-2022-31160", "issue": "XSS in checkboxradio widget"},
    ],
    "bootstrap": [
        {"affected_below": "3.4.0",  "severity": "HIGH",     "cve": "CVE-2018-14040", "issue": "XSS in collapse data-parent"},
        {"affected_below": "3.4.0",  "severity": "HIGH",     "cve": "CVE-2018-14041", "issue": "XSS via data-target"},
        {"affected_below": "3.4.1",  "severity": "HIGH",     "cve": "CVE-2019-8331",  "issue": "XSS in tooltip/popover"},
        {"affected_below": "4.3.1",  "severity": "HIGH",     "cve": "CVE-2019-8331",  "issue": "XSS in tooltip/popover"},
        {"affected_below": "5.3.3",  "severity": "INFO",     "cve": "",               "issue": "Not latest stable (5.3.3)"},
    ],
    "lodash": [
        {"affected_below": "4.17.11","severity": "HIGH",     "cve": "CVE-2018-16487", "issue": "Prototype Pollution"},
        {"affected_below": "4.17.12","severity": "HIGH",     "cve": "CVE-2019-1010266","issue": "ReDoS"},
        {"affected_below": "4.17.19","severity": "CRITICAL", "cve": "CVE-2020-8203",  "issue": "Prototype Pollution via zipObjectDeep"},
        {"affected_below": "4.17.21","severity": "HIGH",     "cve": "CVE-2021-23337", "issue": "Command Injection via template"},
    ],
    "moment": [
        {"affected_below": "2.19.3", "severity": "HIGH",     "cve": "CVE-2017-18214", "issue": "ReDoS"},
        {"affected_below": "2.29.2", "severity": "HIGH",     "cve": "CVE-2022-24785", "issue": "Path Traversal"},
        {"affected_below": "2.29.4", "severity": "HIGH",     "cve": "CVE-2022-31129", "issue": "ReDoS via long strings"},
    ],
    "angularjs": [
        {"affected_below": "1.8.0",  "severity": "HIGH",     "cve": "CVE-2019-14863", "issue": "Prototype Pollution"},
        {"affected_below": "1.8.3",  "severity": "CRITICAL", "cve": "CVE-2023-26118", "issue": "ReDoS in $sanitize"},
        {"affected_below": "1.8.3",  "severity": "CRITICAL", "cve": "CVE-2023-26117", "issue": "ReDoS via \\.* pattern"},
        {"affected_below": "1.8.3",  "severity": "HIGH",     "cve": "CVE-2022-25844", "issue": "ReDoS in $$sanitize"},
    ],
    "vue": [
        {"affected_below": "2.6.13", "severity": "MEDIUM",   "cve": "CVE-2021-22956", "issue": "XSS via SSR"},
        {"affected_below": "3.2.47", "severity": "INFO",     "cve": "",               "issue": "Not latest stable (3.4.x)"},
    ],
    "react": [
        {"affected_below": "16.0.0", "severity": "HIGH",     "cve": "CVE-2018-6341",  "issue": "XSS via SSR data"},
        {"affected_below": "18.3.1", "severity": "INFO",     "cve": "",               "issue": "Not latest stable (18.3.1)"},
    ],
    "axios": [
        {"affected_below": "0.21.1", "severity": "HIGH",     "cve": "CVE-2020-28168", "issue": "SSRF via relative URLs"},
        {"affected_below": "1.6.0",  "severity": "CRITICAL", "cve": "CVE-2023-45857", "issue": "CSRF token exposure"},
    ],
    "underscore": [
        {"affected_below": "1.12.1", "severity": "HIGH",     "cve": "CVE-2021-23358", "issue": "Arbitrary code execution via template"},
    ],
    "handlebars": [
        {"affected_below": "4.5.3",  "severity": "CRITICAL", "cve": "CVE-2019-19919", "issue": "Prototype Pollution RCE"},
        {"affected_below": "4.7.7",  "severity": "HIGH",     "cve": "CVE-2021-23369", "issue": "RCE via template injection"},
    ],
    "highlight.js": [
        {"affected_below": "10.4.1", "severity": "HIGH",     "cve": "CVE-2021-23346", "issue": "ReDoS"},
    ],
    "marked": [
        {"affected_below": "4.0.10", "severity": "HIGH",     "cve": "CVE-2022-21681", "issue": "ReDoS"},
        {"affected_below": "4.0.10", "severity": "HIGH",     "cve": "CVE-2022-21680", "issue": "ReDoS via heading"},
    ],
    "dompurify": [
        {"affected_below": "2.4.0",  "severity": "HIGH",     "cve": "CVE-2022-25887", "issue": "Bypass via mXSS"},
        {"affected_below": "3.1.6",  "severity": "INFO",     "cve": "",               "issue": "Not latest stable (3.1.6)"},
    ],
}

# Latest safe versions (for reporting)
JS_LATEST = {
    "jquery": "3.7.1", "jquery-ui": "1.13.2", "bootstrap": "5.3.3",
    "lodash": "4.17.21", "moment": "2.29.4", "angularjs": "1.8.3",
    "vue": "3.4.21", "react": "18.3.1", "axios": "1.6.8",
    "underscore": "1.13.6", "handlebars": "4.7.8", "highlight.js": "11.9.0",
    "marked": "12.0.0", "dompurify": "3.1.6",
}


def _version_tuple(v: str):
    """Convert version string to comparable tuple."""
    try:
        return tuple(int(x) for x in re.sub(r"[^0-9.]", "", v).split("."))
    except Exception:
        return (0,)


def _is_vulnerable(detected_ver: str, affected_below: str) -> bool:
    return _version_tuple(detected_ver) < _version_tuple(affected_below)


def scan_js_libraries(url: str) -> dict:
    """Fetch page source and deeply fingerprint all JS libraries + check against vuln DB."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Extended patterns: (library_key, display_name, regex_list)
    PATTERNS = [
        ("jquery",       "jQuery",        [r'jquery[.\-/](\d+\.\d+[\.\d]*)', r'jQuery v(\d+\.\d+[\.\d]*)', r"jquery.*?['\"](\d+\.\d+[\.\d]*)['\"]"]),
        ("jquery-ui",    "jQuery UI",     [r'jquery[.\-/]ui[.\-/](\d+\.\d+[\.\d]*)', r'jQuery UI - v(\d+\.\d+[\.\d]*)']),
        ("bootstrap",    "Bootstrap",     [r'bootstrap[.\-/](\d+\.\d+[\.\d]*)', r'Bootstrap v(\d+\.\d+[\.\d]*)']),
        ("lodash",       "Lodash",        [r'lodash[.\-/](\d+\.\d+[\.\d]*)', r"lodash.*?['\"](\d+\.\d+[\.\d]*)['\"]"]),
        ("moment",       "Moment.js",     [r'moment[.\-/](\d+\.\d+[\.\d]*)', r'moment\.js.*?v(\d+\.\d+[\.\d]*)']),
        ("angularjs",    "AngularJS",     [r'angular[.\-/](\d+\.\d+[\.\d]*)', r'AngularJS v(\d+\.\d+[\.\d]*)', r'ng-version=["\'](\d+\.\d+[\.\d]*)']),
        ("vue",          "Vue.js",        [r'vue[.\-/](\d+\.\d+[\.\d]*)', r'Vue\.version\s*=\s*["\'](\d+\.\d+[\.\d]*)']),
        ("react",        "React",         [r'react[.\-/](\d+\.\d+[\.\d]*)', r'React\.version.*?(\d+\.\d+[\.\d]*)']),
        ("axios",        "Axios",         [r'axios[.\-/](\d+\.\d+[\.\d]*)']),
        ("underscore",   "Underscore.js", [r'underscore[.\-/](\d+\.\d+[\.\d]*)', r'Underscore\.js (\d+\.\d+[\.\d]*)']),
        ("handlebars",   "Handlebars",    [r'handlebars[.\-/](\d+\.\d+[\.\d]*)', r'Handlebars\.VERSION.*?(\d+\.\d+[\.\d]*)']),
        ("highlight.js", "Highlight.js",  [r'highlight[.\-/](\d+\.\d+[\.\d]*)']),
        ("marked",       "Marked",        [r'marked[.\-/](\d+\.\d+[\.\d]*)']),
        ("dompurify",    "DOMPurify",     [r'dompurify[.\-/](\d+\.\d+[\.\d]*)', r'DOMPurify\.version.*?(\d+\.\d+[\.\d]*)']),
    ]

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 VAPTAgent/1.0"})
        with urllib.request.urlopen(req, timeout=12, context=ctx if url.startswith("https") else None) as resp:
            body = resp.read(131072).decode(errors="ignore")

        # Also collect all <script src="..."> URLs for version extraction
        script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.I)

        detected = []
        for lib_key, display_name, regexes in PATTERNS:
            version = None
            # Search page body
            for pattern in regexes:
                m = re.search(pattern, body, re.I)
                if m:
                    version = m.group(1)
                    break
            # Search script src URLs
            if not version:
                for src in script_srcs:
                    for pattern in regexes:
                        m = re.search(pattern, src, re.I)
                        if m:
                            version = m.group(1)
                            break
                    if version:
                        break

            if not version:
                continue

            # Check vuln DB
            vulns = []
            highest_severity = "INFO"
            sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
            for entry in JS_VULN_DB.get(lib_key, []):
                if _is_vulnerable(version, entry["affected_below"]):
                    vulns.append({
                        "cve": entry["cve"],
                        "issue": entry["issue"],
                        "severity": entry["severity"],
                        "fixed_in": entry["affected_below"],
                    })
                    if sev_rank.get(entry["severity"], 0) > sev_rank.get(highest_severity, 0):
                        highest_severity = entry["severity"]

            detected.append({
                "library": display_name,
                "key": lib_key,
                "detected_version": version,
                "latest_safe_version": JS_LATEST.get(lib_key, "Check npm"),
                "is_vulnerable": len(vulns) > 0,
                "vulnerability_count": len(vulns),
                "highest_severity": highest_severity if vulns else "OK",
                "vulnerabilities": vulns,
                "upgrade_command": _js_upgrade_cmd(lib_key, JS_LATEST.get(lib_key, "")),
            })

        # Summary stats
        vuln_count   = sum(1 for d in detected if d["is_vulnerable"])
        critical_libs = [d["library"] for d in detected if d["highest_severity"] == "CRITICAL"]
        high_libs     = [d["library"] for d in detected if d["highest_severity"] == "HIGH"]

        return {
            "url": url,
            "libraries_found": len(detected),
            "vulnerable_libraries": vuln_count,
            "critical": critical_libs,
            "high": high_libs,
            "script_src_urls": script_srcs[:20],
            "libraries": detected,
        }

    except Exception as e:
        return {"url": url, "error": str(e), "libraries": []}


def _js_upgrade_cmd(lib_key: str, latest: str) -> str:
    cmd_map = {
        "jquery":      f"Replace CDN: <script src=\"https://code.jquery.com/jquery-{latest}.min.js\"> OR: npm update jquery",
        "jquery-ui":   f"npm update jquery-ui  OR download from https://jqueryui.com/",
        "bootstrap":   f"npm update bootstrap  OR CDN: https://getbootstrap.com/docs/5.3/getting-started/download/",
        "lodash":      f"npm update lodash",
        "moment":      f"npm update moment  (consider migrating to date-fns or Luxon)",
        "angularjs":   f"npm update angular  OR consider migrating to Angular 17+",
        "vue":         f"npm update vue",
        "react":       f"npm update react react-dom",
        "axios":       f"npm update axios",
        "underscore":  f"npm update underscore",
        "handlebars":  f"npm update handlebars",
        "highlight.js":f"npm update highlight.js",
        "marked":      f"npm update marked",
        "dompurify":   f"npm update dompurify",
    }
    return cmd_map.get(lib_key, f"npm update {lib_key}")


# ── HTTP Header audit ─────────────────────────────────────────────────────────

# Full header policy: name → {severity, description, recommended, apache_conf, nginx_conf, iis_conf, bad_patterns}
HEADER_POLICY = {
    # ── Missing = bad ──────────────────────────────────────────────────────────
    "Strict-Transport-Security": {
        "must_be_present": True,
        "severity_if_missing": "HIGH",
        "description": "Forces browsers to use HTTPS. Missing allows downgrade attacks.",
        "recommended_value": "max-age=31536000; includeSubDomains; preload",
        "apache": 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
        "nginx":  'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
        "iis":    '<add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains; preload"/>',
        "owasp":  "A02:2021 – Cryptographic Failures",
    },
    "Content-Security-Policy": {
        "must_be_present": True,
        "severity_if_missing": "HIGH",
        "description": "Prevents XSS and data injection. Missing allows arbitrary script execution.",
        "recommended_value": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none';",
        "apache": "Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; ...\"",
        "nginx":  "add_header Content-Security-Policy \"default-src 'self'; script-src 'self';\" always;",
        "iis":    "<add name=\"Content-Security-Policy\" value=\"default-src 'self';\"/>",
        "owasp":  "A03:2021 – Injection",
    },
    "X-Content-Type-Options": {
        "must_be_present": True,
        "severity_if_missing": "MEDIUM",
        "recommended_value": "nosniff",
        "description": "Prevents MIME-type sniffing. Missing allows content-type confusion attacks.",
        "apache": 'Header always set X-Content-Type-Options "nosniff"',
        "nginx":  'add_header X-Content-Type-Options "nosniff" always;',
        "iis":    '<add name="X-Content-Type-Options" value="nosniff"/>',
        "owasp":  "A05:2021 – Security Misconfiguration",
    },
    "X-Frame-Options": {
        "must_be_present": True,
        "severity_if_missing": "MEDIUM",
        "recommended_value": "DENY",
        "description": "Prevents clickjacking. Prefer CSP frame-ancestors over this legacy header.",
        "apache": 'Header always set X-Frame-Options "DENY"',
        "nginx":  'add_header X-Frame-Options "DENY" always;',
        "iis":    '<add name="X-Frame-Options" value="DENY"/>',
        "owasp":  "A05:2021 – Security Misconfiguration",
    },
    "Referrer-Policy": {
        "must_be_present": True,
        "severity_if_missing": "LOW",
        "recommended_value": "strict-origin-when-cross-origin",
        "description": "Controls referrer information leakage in navigation requests.",
        "apache": 'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
        "nginx":  'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
        "iis":    '<add name="Referrer-Policy" value="strict-origin-when-cross-origin"/>',
        "owasp":  "A01:2021 – Broken Access Control",
    },
    "Permissions-Policy": {
        "must_be_present": True,
        "severity_if_missing": "LOW",
        "recommended_value": "camera=(), microphone=(), geolocation=(), payment=()",
        "description": "Restricts browser feature access. Prevents feature abuse.",
        "apache": 'Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"',
        "nginx":  'add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;',
        "iis":    '<add name="Permissions-Policy" value="camera=(), microphone=(), geolocation=()"/>',
        "owasp":  "A05:2021 – Security Misconfiguration",
    },
    "Cross-Origin-Opener-Policy": {
        "must_be_present": True,
        "severity_if_missing": "LOW",
        "recommended_value": "same-origin",
        "description": "Isolates browsing context, mitigates Spectre attacks.",
        "apache": 'Header always set Cross-Origin-Opener-Policy "same-origin"',
        "nginx":  'add_header Cross-Origin-Opener-Policy "same-origin" always;',
        "iis":    '<add name="Cross-Origin-Opener-Policy" value="same-origin"/>',
        "owasp":  "A05:2021 – Security Misconfiguration",
    },
    "Cross-Origin-Resource-Policy": {
        "must_be_present": True,
        "severity_if_missing": "LOW",
        "recommended_value": "same-origin",
        "description": "Prevents other origins from reading responses (protects against Spectre).",
        "apache": 'Header always set Cross-Origin-Resource-Policy "same-origin"',
        "nginx":  'add_header Cross-Origin-Resource-Policy "same-origin" always;',
        "iis":    '<add name="Cross-Origin-Resource-Policy" value="same-origin"/>',
        "owasp":  "A05:2021 – Security Misconfiguration",
    },
    # ── Should be REMOVED / minimised ─────────────────────────────────────────
    "Server": {
        "must_be_absent": True,
        "severity_if_present_with_version": "MEDIUM",
        "description": "Exposes web server name and version — aids targeted attacks.",
        "recommended_value": "Remove or set to generic value (e.g. 'webserver')",
        "apache": "ServerTokens Prod\nServerSignature Off",
        "nginx":  "server_tokens off;",
        "iis":    "Remove via UrlScan or RequestFiltering",
        "owasp":  "A05:2021 – Security Misconfiguration",
    },
    "X-Powered-By": {
        "must_be_absent": True,
        "severity_if_present_with_version": "LOW",
        "description": "Reveals backend technology (PHP, ASP.NET, Express). Remove it.",
        "recommended_value": "Remove entirely",
        "apache": "Header unset X-Powered-By\nHeader always unset X-Powered-By",
        "nginx":  "fastcgi_hide_header X-Powered-By;  # or proxy_hide_header",
        "iis":    'Remove via web.config: <remove name="X-Powered-By"/>',
        "owasp":  "A05:2021 – Security Misconfiguration",
    },
    "X-AspNet-Version": {
        "must_be_absent": True,
        "severity_if_present_with_version": "LOW",
        "description": "Exposes ASP.NET version. Remove via enableVersionHeader='false'.",
        "recommended_value": "Remove entirely",
        "apache": "N/A",
        "nginx":  "N/A",
        "iis":    '<httpRuntime enableVersionHeader="false"/>',
        "owasp":  "A05:2021 – Security Misconfiguration",
    },
    # ── Cookie checks ──────────────────────────────────────────────────────────
    "Set-Cookie": {
        "check_flags": True,
        "required_flags": ["HttpOnly", "Secure", "SameSite"],
        "severity": "HIGH",
        "description": "Session cookies missing HttpOnly/Secure/SameSite flags enable session hijacking.",
        "recommended_value": "Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict",
        "apache": 'Header always edit Set-Cookie ^(.*)$ "$1; HttpOnly; Secure; SameSite=Strict"',
        "nginx":  "proxy_cookie_flags ~ httponly secure samesite=strict;",
        "iis":    "Configure via system.web/httpCookies requireSSL='true' httpOnlyCookies='true'",
        "owasp":  "A02:2021 – Cryptographic Failures",
    },
}

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "OK": -1}


def audit_http_headers(url: str) -> dict:
    """Full HTTP header security audit with remediation configs."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "VAPTAgent/1.0"})
        with urllib.request.urlopen(req, timeout=10, context=ctx if url.startswith("https") else None) as resp:
            raw_headers = dict(resp.headers)
            status = resp.status

        headers_lower = {k.lower(): v for k, v in raw_headers.items()}
        findings = []
        score = 0
        max_score = 0

        for header_name, policy in HEADER_POLICY.items():
            h_lower = header_name.lower()
            present = h_lower in headers_lower
            current_value = headers_lower.get(h_lower, "")

            # ── Must be present ────────────────────────────────────────────────
            if policy.get("must_be_present"):
                max_score += 1
                if present:
                    score += 1
                    # Check value quality for CSP
                    value_issues = []
                    if header_name == "Content-Security-Policy":
                        if "unsafe-inline" in current_value and "script-src" not in current_value:
                            value_issues.append("'unsafe-inline' in default-src weakens CSP")
                        if "unsafe-eval" in current_value:
                            value_issues.append("'unsafe-eval' allows dynamic code execution")
                        if "*" in current_value:
                            value_issues.append("Wildcard (*) in CSP defeats its purpose")
                    if header_name == "Strict-Transport-Security":
                        m = re.search(r'max-age=(\d+)', current_value)
                        if m and int(m.group(1)) < 15552000:
                            value_issues.append("max-age < 180 days is too short")
                        if "includeSubDomains" not in current_value:
                            value_issues.append("includeSubDomains missing — subdomains unprotected")

                    findings.append({
                        "header": header_name,
                        "status": "PRESENT" if not value_issues else "MISCONFIGURED",
                        "severity": "OK" if not value_issues else "MEDIUM",
                        "current_value": current_value,
                        "recommended_value": policy["recommended_value"],
                        "value_issues": value_issues,
                        "apache_config": policy.get("apache", ""),
                        "nginx_config": policy.get("nginx", ""),
                        "iis_config": policy.get("iis", ""),
                        "owasp_ref": policy.get("owasp", ""),
                        "description": policy.get("description", ""),
                    })
                else:
                    findings.append({
                        "header": header_name,
                        "status": "MISSING",
                        "severity": policy["severity_if_missing"],
                        "current_value": None,
                        "recommended_value": policy["recommended_value"],
                        "value_issues": [],
                        "apache_config": policy.get("apache", ""),
                        "nginx_config": policy.get("nginx", ""),
                        "iis_config": policy.get("iis", ""),
                        "owasp_ref": policy.get("owasp", ""),
                        "description": policy.get("description", ""),
                    })

            # ── Must be absent / minimal ──────────────────────────────────────
            elif policy.get("must_be_absent") and present:
                # Check if value contains a version number
                has_version = bool(re.search(r'\d+\.\d+', current_value))
                severity = policy["severity_if_present_with_version"] if has_version else "INFO"
                findings.append({
                    "header": header_name,
                    "status": "INFORMATION_LEAKAGE",
                    "severity": severity,
                    "current_value": current_value,
                    "recommended_value": policy["recommended_value"],
                    "value_issues": ["Discloses technology/version — assists attackers in fingerprinting"],
                    "apache_config": policy.get("apache", ""),
                    "nginx_config": policy.get("nginx", ""),
                    "iis_config": policy.get("iis", ""),
                    "owasp_ref": policy.get("owasp", ""),
                    "description": policy.get("description", ""),
                })

            # ── Cookie flag checks ────────────────────────────────────────────
            elif policy.get("check_flags") and present:
                missing_flags = [f for f in policy["required_flags"] if f.lower() not in current_value.lower()]
                if missing_flags:
                    findings.append({
                        "header": header_name,
                        "status": "INSECURE_COOKIE",
                        "severity": policy["severity"],
                        "current_value": current_value,
                        "recommended_value": policy["recommended_value"],
                        "value_issues": [f"Missing cookie flag(s): {', '.join(missing_flags)}"],
                        "apache_config": policy.get("apache", ""),
                        "nginx_config": policy.get("nginx", ""),
                        "iis_config": policy.get("iis", ""),
                        "owasp_ref": policy.get("owasp", ""),
                        "description": policy.get("description", ""),
                    })

        # Count by severity
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            s = f["severity"]
            if s in sev_counts:
                sev_counts[s] += 1

        grade_pct = int((score / max_score) * 100) if max_score else 0
        if grade_pct >= 90:   grade = "A"
        elif grade_pct >= 75: grade = "B"
        elif grade_pct >= 60: grade = "C"
        elif grade_pct >= 40: grade = "D"
        else:                  grade = "F"

        return {
            "url": url,
            "http_status": status,
            "score": f"{score}/{max_score}",
            "grade": grade,
            "severity_summary": sev_counts,
            "total_findings": len(findings),
            "findings": findings,
        }

    except Exception as e:
        return {"url": url, "error": str(e), "findings": []}


# ── Tool dispatcher ───────────────────────────────────────────────────────────

def run_tool(name: str, inputs: dict) -> str:
    dispatch = {
        "scan_ports": scan_ports,
        "grab_banner": grab_banner,
        "detect_technologies": detect_technologies,
        "check_ssl_tls": check_ssl_tls,
        "check_security_headers": check_security_headers,
        "lookup_cve": lookup_cve,
        "generate_upgrade_steps": generate_upgrade_steps,
        "scan_js_libraries": scan_js_libraries,
        "audit_http_headers": audit_http_headers,
    }
    fn = dispatch.get(name)
    if fn is None:
        return json.dumps({"error": f"Unknown tool: {name}"})
    result = fn(**inputs)
    return json.dumps(result, default=str, indent=2)


# ── Agent loop ────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are an expert cybersecurity AI agent specialising in Web Application
Vulnerability Assessment and Penetration Testing (VAPT).

Your workflow for a target URL/host:
1. Parse the host and URL from the user input.
2. Scan open ports (scan_ports).
3. Grab HTTP banner (grab_banner).
4. Detect technologies and versions (detect_technologies).
5. Check SSL/TLS certificate (check_ssl_tls).
6. Run the DEEP JavaScript library scan (scan_js_libraries) — this checks all JS libs
   against a built-in known-vulnerable version database and returns CVE details.
7. Run the COMPREHENSIVE HTTP header audit (audit_http_headers) — this checks all
   security headers, cookie flags, information-leaking headers, and returns exact
   Apache/Nginx/IIS remediation config snippets.
8. For EVERY detected technology with a version, look up known CVEs (lookup_cve).
9. For each vulnerability found OR outdated version, generate upgrade steps (generate_upgrade_steps).
10. Produce a structured VAPT report with:
    - Executive Summary (overall risk rating: Critical / High / Medium / Low)
    - Open Ports & Services
    - Detected Technologies
    - SSL/TLS Findings
    - JavaScript Library Audit (vulnerable libs, CVEs, severity, upgrade commands)
    - HTTP Security Header Audit (grade, missing/misconfigured headers, exact config fixes)
    - CVE / Vulnerability Findings (with CVSS scores)
    - Remediation Plan (prioritised by severity)
    - Overall risk score

For the HTTP Header section, always include the exact recommended header values AND the
server-specific configuration snippets (Apache / Nginx / IIS) from the audit results.

For the JS Library section, list every vulnerable library with its CVE IDs, severity,
current version, safe version, and the exact upgrade command.

Be thorough. Use all tools. Always provide actionable remediation steps."""


def run_vapt_agent(target: str):
    print(f"\n{'='*60}")
    print(f"  VAPT AI Agent  |  Target: {target}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    messages = [{"role": "user", "content": f"Perform a full VAPT assessment on: {target}"}]

    step = 0
    while True:
        step += 1
        print(f"[Agent] Thinking... (step {step})")

        response = client.messages.create(
            model="claude-opus-4-5",
            max_tokens=8192,
            system=SYSTEM_PROMPT,
            tools=TOOLS,
            messages=messages,
        )

        # Append assistant response
        messages.append({"role": "assistant", "content": response.content})

        if response.stop_reason == "end_turn":
            # Final answer
            for block in response.content:
                if hasattr(block, "text"):
                    print("\n" + "="*60)
                    print("  VAPT REPORT")
                    print("="*60)
                    print(block.text)
            break

        if response.stop_reason == "tool_use":
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    print(f"  → Running tool: {block.name}({json.dumps(block.input)[:80]}...)")
                    output = run_tool(block.name, block.input)
                    # Print a brief preview
                    preview = output[:200].replace("\n", " ")
                    print(f"    ✓ Result preview: {preview}...")
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": output,
                    })

            messages.append({"role": "user", "content": tool_results})
        else:
            print(f"[Agent] Unexpected stop reason: {response.stop_reason}")
            break

    print(f"\n[Agent] Assessment complete. Steps taken: {step}")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python vapt_agent.py <target-url-or-host>")
        print("Example: python vapt_agent.py https://example.com")
        sys.exit(1)

    target = sys.argv[1]
    run_vapt_agent(target)