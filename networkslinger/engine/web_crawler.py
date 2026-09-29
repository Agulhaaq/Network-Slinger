"""
Deep HTTP/HTTPS Web Scrawler, Technology Stack Fingerprinter & SSL Certificate Auditor.
"""

import asyncio
from datetime import datetime, timezone
import re
import socket
import ssl
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
import httpx

from ..models import DiscoveredEndpoint, SSLCertInfo, WebCrawlResult


COMMON_PROBE_PATHS = [
    ("/robots.txt", "Robots Policy File", False),
    ("/admin", "Administrative Portal", True),
    ("/login", "Login Authentication Gateway", False),
    ("/api", "API Base Endpoint", False),
    ("/docs", "API Documentation (Swagger/FastAPI)", True),
    ("/swagger", "Swagger API Documentation", True),
    ("/metrics", "Prometheus/System Metrics", True),
    ("/phpmyadmin", "phpMyAdmin Database Manager", True),
    ("/wp-login.php", "WordPress Admin Login", True),
    ("/.env", "Environment Variables File (CRITICAL EXPOSURE)", True),
    ("/.git/HEAD", "Git Repository Metadata (CRITICAL EXPOSURE)", True),
]


def extract_ssl_cert(ip: str, port: int, timeout: float = 2.0) -> Optional[SSLCertInfo]:
    """Inspects SSL/TLS certificate details using python's ssl and cryptography."""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                if not der_cert:
                    return None

                from cryptography import x509
                from cryptography.hazmat.backends import default_backend

                cert = x509.load_der_x509_certificate(der_cert, default_backend())

                subject = cert.subject.rfc4514_string()
                issuer = cert.issuer.rfc4514_string()

                # Extract CN if present
                for attr in cert.subject:
                    if attr.oid == x509.NameOID.COMMON_NAME:
                        subject = attr.value
                        break

                for attr in cert.issuer:
                    if attr.oid == x509.NameOID.COMMON_NAME:
                        issuer = attr.value
                        break

                not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=timezone.utc)
                not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)

                now = datetime.now(timezone.utc)
                days_left = (not_after - now).days
                is_expired = days_left < 0
                is_self_signed = cert.issuer == cert.subject

                # Subject Alternative Names (SANs)
                sans = []
                try:
                    san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    sans = [str(n.value) for n in san_ext.value]
                except Exception:
                    pass

                return SSLCertInfo(
                    subject=str(subject),
                    issuer=str(issuer),
                    valid_from=not_before,
                    valid_to=not_after,
                    days_left=days_left,
                    is_expired=is_expired,
                    is_self_signed=is_self_signed,
                    san_list=sans[:15],
                    signature_algorithm=cert.signature_algorithm_oid._name if hasattr(cert, "signature_algorithm_oid") else ""
                )
    except Exception:
        pass
    return None


def detect_technologies(headers: Dict[str, str], html_content: str) -> List[str]:
    """Identifies technologies, frameworks, and web servers from headers and HTML."""
    tech: Set[str] = set()
    server = headers.get("server", "").lower()
    powered_by = headers.get("x-powered-by", "").lower()
    lower_html = html_content.lower()

    # Web Servers
    if "nginx" in server:
        tech.add("Nginx")
    elif "apache" in server:
        tech.add("Apache HTTPD")
    elif "iis" in server or "microsoft-iis" in server:
        tech.add("Microsoft IIS")
    elif "caddy" in server:
        tech.add("Caddy Server")
    elif "cloudflare" in server:
        tech.add("Cloudflare Proxy")
    elif "openresty" in server:
        tech.add("OpenResty")
    elif "lighttpd" in server:
        tech.add("Lighttpd")
    elif "werkzeug" in server:
        tech.add("Python Werkzeug / Flask")
    elif "uvicorn" in server:
        tech.add("Python Uvicorn / FastAPI")

    # Backend frameworks
    if "php" in powered_by or ".php" in lower_html:
        tech.add("PHP")
    if "express" in powered_by:
        tech.add("Express.js / Node.js")
    if "asp.net" in powered_by:
        tech.add("ASP.NET")
    if "django" in lower_html or "csrfmiddlewaretoken" in lower_html:
        tech.add("Django")
    if "rails" in lower_html or "phusion passenger" in server:
        tech.add("Ruby on Rails")

    # CMS & Network Panels
    if "wp-content" in lower_html or "wordpress" in lower_html:
        tech.add("WordPress CMS")
    if "openwrt" in lower_html or "luci" in lower_html:
        tech.add("OpenWrt / LuCI Router WebUI")
    if "pi-hole" in lower_html or "pihole" in lower_html:
        tech.add("Pi-hole DNS")
    if "synology" in lower_html or "diskstation" in lower_html:
        tech.add("Synology DSM")
    if "proxmox" in lower_html:
        tech.add("Proxmox VE")
    if "grafana" in lower_html:
        tech.add("Grafana")
    if "mikrotik" in lower_html or "routeros" in lower_html:
        tech.add("MikroTik RouterOS WebFig")
    if "tp-link" in lower_html:
        tech.add("TP-Link Web Console")
    if "asus" in lower_html and "router" in lower_html:
        tech.add("ASUS Router WebUI")

    # Frontend Frameworks
    if "react" in lower_html or "__next" in lower_html or "data-reactroot" in lower_html:
        tech.add("React / Next.js")
    if "vue" in lower_html or "data-v-" in lower_html or "__nuxt" in lower_html:
        tech.add("Vue.js / Nuxt")
    if "bootstrap" in lower_html:
        tech.add("Bootstrap")
    if "tailwind" in lower_html:
        tech.add("Tailwind CSS")

    return sorted(list(tech))


def analyze_security_headers(headers: Dict[str, str]) -> List[str]:
    """Identifies missing recommended HTTP security headers."""
    missing = []
    norm_headers = {k.lower(): v for k, v in headers.items()}

    if "strict-transport-security" not in norm_headers:
        missing.append("Strict-Transport-Security (HSTS)")
    if "content-security-policy" not in norm_headers:
        missing.append("Content-Security-Policy (CSP)")
    if "x-frame-options" not in norm_headers:
        missing.append("X-Frame-Options (Clickjacking Protection)")
    if "x-content-type-options" not in norm_headers:
        missing.append("X-Content-Type-Options (MIME Sniffing Protection)")
    if "referrer-policy" not in norm_headers:
        missing.append("Referrer-Policy")

    return missing


async def crawl_web_service(
    ip: str,
    port: int,
    deep_crawl: bool = False,
    timeout: float = 3.0
) -> Optional[WebCrawlResult]:
    """
    Crawls an HTTP or HTTPS service running on `ip:port`.
    Extracts headers, title, tech stack, SSL certificate, links, and sensitive endpoints.
    """
    is_https = port in (443, 8443)
    urls_to_try = []

    if is_https:
        urls_to_try = [f"https://{ip}:{port}"]
    elif port in (80, 8080, 3000, 5000, 8000, 8888, 9000):
        urls_to_try = [f"http://{ip}:{port}"]
    else:
        # Unknown port: probe HTTP first, fallback to HTTPS
        urls_to_try = [f"http://{ip}:{port}", f"https://{ip}:{port}"]

    ssl_info: Optional[SSLCertInfo] = None
    if is_https or port == 443 or port == 8443:
        loop = asyncio.get_running_loop()
        ssl_info = await loop.run_in_executor(None, extract_ssl_cert, ip, port)

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        timeout=timeout,
        headers={"User-Agent": "NetworkSlinger/1.0 (+https://github.com/networkslinger)"}
    ) as client:
        resp = None
        chosen_url = None

        for test_url in urls_to_try:
            try:
                resp = await client.get(test_url)
                chosen_url = str(resp.url)
                if test_url.startswith("https://") and not ssl_info:
                    loop = asyncio.get_running_loop()
                    ssl_info = await loop.run_in_executor(None, extract_ssl_cert, ip, port)
                break
            except Exception:
                continue

        if not resp:
            return None

        # Extract Title and Links
        html = resp.text
        title = ""
        links: List[str] = []
        try:
            soup = BeautifulSoup(html, "html.parser")
            if soup.title and soup.title.string:
                title = soup.title.string.strip()

            # Scrape links for deeper mapping
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"]
                if href.startswith("/") or href.startswith(chosen_url):
                    full_link = urljoin(chosen_url, href)
                    if full_link not in links and len(links) < 20:
                        links.append(full_link)
        except Exception:
            pass

        # Convert headers
        clean_headers = {k: v for k, v in resp.headers.items()}
        tech = detect_technologies(clean_headers, html)
        missing_sec = analyze_security_headers(clean_headers)

        discovered_endpoints: List[DiscoveredEndpoint] = []

        # Probe sensitive paths if requested or standard scan
        if deep_crawl:
            probe_tasks = []
            for path, desc, is_sens in COMMON_PROBE_PATHS:
                target_url = urljoin(chosen_url, path)
                probe_tasks.append(_probe_path(client, target_url, desc, is_sens))

            probed = await asyncio.gather(*probe_tasks, return_exceptions=True)
            for item in probed:
                if isinstance(item, DiscoveredEndpoint):
                    discovered_endpoints.append(item)

        return WebCrawlResult(
            url=chosen_url or f"http://{ip}:{port}",
            port=port,
            is_https=chosen_url.startswith("https://") if chosen_url else is_https,
            status_code=resp.status_code,
            title=title[:100],
            server=clean_headers.get("server", ""),
            powered_by=clean_headers.get("x-powered-by", ""),
            tech_stack=tech,
            ssl_info=ssl_info,
            headers=clean_headers,
            missing_security_headers=missing_sec,
            discovered_endpoints=discovered_endpoints,
            links_found=links
        )


async def _probe_path(client: httpx.AsyncClient, url: str, description: str, is_sensitive: bool) -> Optional[DiscoveredEndpoint]:
    """Probes a single endpoint (e.g. /robots.txt, /.env) to see if it responds with valid content."""
    try:
        r = await client.get(url, timeout=1.5)
        # Check for genuine found endpoints (not soft 404s or 500s)
        if r.status_code in (200, 301, 302, 401, 403):
            # Special check for /.env and /.git: make sure it's not a generic HTML 404 page
            if "/.env" in url and ("<html" in r.text.lower() or "<body" in r.text.lower()):
                return None
            if "/.git" in url and ("<html" in r.text.lower() or "<body" in r.text.lower()):
                return None

            title = ""
            if "text/html" in r.headers.get("content-type", ""):
                try:
                    soup = BeautifulSoup(r.text[:2000], "html.parser")
                    if soup.title and soup.title.string:
                        title = soup.title.string.strip()
                except Exception:
                    pass

            return DiscoveredEndpoint(
                url=url,
                status_code=r.status_code,
                title=title[:60],
                content_type=r.headers.get("content-type", "").split(";")[0],
                is_sensitive=is_sensitive,
                description=description
            )
    except Exception:
        pass
    return None
