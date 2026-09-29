"""
Security auditor and vulnerability heuristic analyzer.
Evaluates discovered ports, banners, web endpoints, and SSL certificates to calculate risk scores.
"""

from typing import List, Tuple
from ..models import HostResult, RiskLevel, SecurityFinding


def audit_host(host: HostResult) -> Tuple[int, RiskLevel, List[SecurityFinding]]:
    """
    Audits an individual discovered host and returns:
    (risk_score: 0-100, overall_risk_level, findings_list)
    """
    findings: List[SecurityFinding] = []
    score = 0

    open_port_nums = {p.port for p in host.open_ports}

    # 1. Check for unencrypted Telnet
    if 23 in open_port_nums:
        findings.append(SecurityFinding(
            title="Unencrypted Telnet Service Exposed",
            severity=RiskLevel.HIGH,
            description="Telnet (port 23) transmits all keystrokes, credentials, and session data in cleartext.",
            port=23,
            remediation="Disable the Telnet daemon and replace with SSH (Secure Shell) on port 22."
        ))
        score += 25

    # 2. Check for plain Docker Socket (Port 2375)
    if 2375 in open_port_nums:
        findings.append(SecurityFinding(
            title="Exposed Docker Daemon API (No TLS)",
            severity=RiskLevel.CRITICAL,
            description="Docker socket on TCP 2375 allows unauthenticated root remote code execution on the host system.",
            port=2375,
            remediation="Bind Docker socket to localhost (127.0.0.1) or enforce mutual TLS authentication on port 2376."
        ))
        score += 45

    # 3. Check for Redis exposures
    for p in host.open_ports:
        if p.port == 6379:
            if "Unauthenticated" in p.banner or p.details.get("unauthenticated"):
                findings.append(SecurityFinding(
                    title="Unauthenticated Redis Database",
                    severity=RiskLevel.CRITICAL,
                    description="The Redis server does not require authentication; anyone on the network can read/write data or execute commands.",
                    port=6379,
                    remediation="Configure 'requirepass' in redis.conf and bind Redis strictly to 127.0.0.1."
                ))
                score += 45
            else:
                findings.append(SecurityFinding(
                    title="Exposed Redis Port",
                    severity=RiskLevel.MEDIUM,
                    description="Redis database port 6379 is accessible over the network.",
                    port=6379,
                    remediation="Restrict access using firewall rules or ACLs to authorized application servers only."
                ))
                score += 10

    # 4. Check FTP anonymous access
    for p in host.open_ports:
        if p.port in (21, 2121):
            if p.details.get("anonymous_allowed"):
                findings.append(SecurityFinding(
                    title="FTP Anonymous Login Enabled",
                    severity=RiskLevel.HIGH,
                    description="The FTP server permits unauthenticated anonymous logins.",
                    port=p.port,
                    remediation="Disable anonymous FTP login in the server configuration unless intentionally public."
                ))
                score += 25

    # 5. Check Database exposures (MySQL, PostgreSQL, MongoDB, MSSQL)
    db_ports = {3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB", 1433: "MSSQL"}
    for port, db_name in db_ports.items():
        if port in open_port_nums:
            findings.append(SecurityFinding(
                title=f"Direct {db_name} Database Exposure",
                severity=RiskLevel.MEDIUM,
                description=f"{db_name} port {port} is directly listening on the network interface.",
                port=port,
                remediation="Ensure database is protected behind a firewall and requires strong authentication."
            ))
            score += 15

    # 6. Audit Web Services & SSL Certificates
    for web in host.web_services:
        # SSL Check
        if web.ssl_info:
            if web.ssl_info.is_expired:
                findings.append(SecurityFinding(
                    title="Expired SSL/TLS Certificate",
                    severity=RiskLevel.HIGH,
                    description=f"SSL certificate for {web.url} expired on {web.ssl_info.valid_to}.",
                    port=web.port,
                    remediation="Renew the SSL/TLS certificate immediately with an authorized Certificate Authority."
                ))
                score += 25
            elif web.ssl_info.days_left is not None and web.ssl_info.days_left < 14:
                findings.append(SecurityFinding(
                    title="SSL Certificate Expiring Soon",
                    severity=RiskLevel.LOW,
                    description=f"Certificate for {web.url} will expire in {web.ssl_info.days_left} days.",
                    port=web.port,
                    remediation="Schedule automated certificate renewal."
                ))
                score += 5

            if web.ssl_info.is_self_signed:
                findings.append(SecurityFinding(
                    title="Self-Signed SSL Certificate",
                    severity=RiskLevel.LOW,
                    description=f"The certificate on port {web.port} is self-signed, causing browser trust warnings.",
                    port=web.port,
                    remediation="Deploy a trusted certificate from Let's Encrypt or your enterprise PKI."
                ))
                score += 5

        # Sensitive Endpoints discovered
        for ep in web.discovered_endpoints:
            if ".env" in ep.url and ep.status_code == 200:
                findings.append(SecurityFinding(
                    title="CRITICAL: Exposed .env Configuration File",
                    severity=RiskLevel.CRITICAL,
                    description=f"Environment credentials file accessible at {ep.url}.",
                    port=web.port,
                    remediation="Block access to dotfiles (.env, .git) in web server config immediately."
                ))
                score += 50
            elif ".git" in ep.url and ep.status_code == 200:
                findings.append(SecurityFinding(
                    title="CRITICAL: Exposed .git Version Control Metadata",
                    severity=RiskLevel.CRITICAL,
                    description=f"Git repository files accessible at {ep.url}, allowing full source code extraction.",
                    port=web.port,
                    remediation="Deny public access to .git directories via web server configuration."
                ))
                score += 45
            elif "phpmyadmin" in ep.url.lower():
                findings.append(SecurityFinding(
                    title="Exposed phpMyAdmin Administration Portal",
                    severity=RiskLevel.MEDIUM,
                    description=f"phpMyAdmin database management panel detected at {ep.url}.",
                    port=web.port,
                    remediation="Restrict access to phpMyAdmin by IP whitelist or VPN."
                ))
                score += 15

        # Missing Security Headers (if HTTPS)
        if web.is_https and "Strict-Transport-Security (HSTS)" in web.missing_security_headers:
            findings.append(SecurityFinding(
                title=f"Missing HSTS Header ({web.url})",
                severity=RiskLevel.LOW,
                description="HTTP Strict Transport Security (HSTS) header is missing, allowing potential SSL-stripping attacks.",
                port=web.port,
                remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to response headers."
            ))
            score += 3

    # Calculate overall risk level
    final_score = min(100, score)
    if final_score >= 70:
        level = RiskLevel.CRITICAL
    elif final_score >= 40:
        level = RiskLevel.HIGH
    elif final_score >= 20:
        level = RiskLevel.MEDIUM
    elif final_score > 0:
        level = RiskLevel.LOW
    else:
        level = RiskLevel.INFO

    return final_score, level, findings
