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

    # 1. Unencrypted Telnet
    if 23 in open_port_nums:
        findings.append(SecurityFinding(
            title="Unencrypted Telnet Service Exposed",
            severity=RiskLevel.HIGH,
            description="Telnet (port 23) transmits all keystrokes, credentials, and session data in cleartext.",
            port=23,
            remediation="Disable Telnet and replace with SSH (port 22)."
        ))
        score += 25

    # 2. Unencrypted Docker daemon
    if 2375 in open_port_nums:
        findings.append(SecurityFinding(
            title="Exposed Docker Daemon API (No TLS)",
            severity=RiskLevel.CRITICAL,
            description="Docker socket on TCP 2375 allows unauthenticated root remote code execution on the host.",
            port=2375,
            remediation="Bind Docker to localhost only or enforce mutual TLS on port 2376."
        ))
        score += 45

    # 3. Redis — use the details flag set by banner_grabber (more reliable than string parsing)
    for p in host.open_ports:
        if p.port == 6379:
            if p.details.get("unauthenticated"):
                findings.append(SecurityFinding(
                    title="Unauthenticated Redis Database",
                    severity=RiskLevel.CRITICAL,
                    description="Redis server has no authentication; anyone on the network can read/write or execute commands.",
                    port=6379,
                    remediation="Set 'requirepass' in redis.conf and bind Redis to 127.0.0.1."
                ))
                score += 45
            else:
                findings.append(SecurityFinding(
                    title="Redis Port Exposed to Network",
                    severity=RiskLevel.MEDIUM,
                    description="Redis database port 6379 is reachable over the network.",
                    port=6379,
                    remediation="Restrict access via firewall rules to authorized servers only."
                ))
                score += 10

    # 4. FTP anonymous access
    for p in host.open_ports:
        if p.port in (21, 2121):
            if p.details.get("anonymous_allowed"):
                findings.append(SecurityFinding(
                    title="FTP Anonymous Login Enabled",
                    severity=RiskLevel.HIGH,
                    description="The FTP server permits unauthenticated anonymous logins.",
                    port=p.port,
                    remediation="Disable anonymous FTP access in server configuration."
                ))
                score += 25

    # 5. Direct database exposure (MySQL, PostgreSQL, MongoDB, MSSQL, Oracle)
    db_ports = {
        3306: "MySQL",
        5432: "PostgreSQL",
        27017: "MongoDB",
        1433: "MSSQL",
        1521: "Oracle DB"
    }
    for port, db_name in db_ports.items():
        if port in open_port_nums:
            findings.append(SecurityFinding(
                title=f"Direct {db_name} Database Port Exposed",
                severity=RiskLevel.MEDIUM,
                description=f"{db_name} port {port} is listening directly on the network interface.",
                port=port,
                remediation=f"Firewall {port}/tcp to application servers only and verify authentication is required."
            ))
            score += 15

    # 6. VNC exposed
    if 5900 in open_port_nums:
        findings.append(SecurityFinding(
            title="VNC Remote Desktop Exposed",
            severity=RiskLevel.HIGH,
            description="VNC graphical remote desktop (port 5900) is accessible on the network. Often has weak or no authentication.",
            port=5900,
            remediation="Restrict VNC to localhost and tunnel through SSH. Enforce VNC password authentication."
        ))
        score += 20

    # 7. SNMP exposed
    for snmp_port in (161, 162):
        if snmp_port in open_port_nums:
            findings.append(SecurityFinding(
                title="SNMP Port Exposed",
                severity=RiskLevel.MEDIUM,
                description=f"SNMP port {snmp_port} is reachable. Default community strings ('public'/'private') may allow device enumeration.",
                port=snmp_port,
                remediation="Change SNMP community strings, restrict by ACL, or upgrade to SNMPv3 with authentication."
            ))
            score += 10

    # 8. Memcached exposed (no authentication by design)
    if 11211 in open_port_nums:
        findings.append(SecurityFinding(
            title="Memcached Cache Server Exposed",
            severity=RiskLevel.HIGH,
            description="Memcached (port 11211) has no authentication — anyone on the network can read cached data.",
            port=11211,
            remediation="Bind Memcached strictly to 127.0.0.1 and firewall port 11211."
        ))
        score += 20

    # 9. Elasticsearch exposed
    if 9200 in open_port_nums:
        findings.append(SecurityFinding(
            title="Elasticsearch API Exposed",
            severity=RiskLevel.MEDIUM,
            description="Elasticsearch REST API (port 9200) is accessible. Older versions had no auth by default.",
            port=9200,
            remediation="Enable Elasticsearch security features (X-Pack) and restrict port 9200 by firewall."
        ))
        score += 15

    # 10. RDP exposed to the network
    if 3389 in open_port_nums:
        findings.append(SecurityFinding(
            title="RDP Remote Desktop Exposed to Network",
            severity=RiskLevel.LOW,
            description="RDP (port 3389) is accessible. Frequently targeted by brute-force and ransomware campaigns.",
            port=3389,
            remediation="Place RDP behind a VPN or use Network Level Authentication (NLA). Restrict to known IPs."
        ))
        score += 8

    # 11. SMB / NetBIOS exposed
    if 445 in open_port_nums:
        findings.append(SecurityFinding(
            title="SMB File Sharing Exposed",
            severity=RiskLevel.MEDIUM,
            description="SMB (port 445) is accessible. Ensure the system is patched against EternalBlue (MS17-010) and related exploits.",
            port=445,
            remediation="Apply all Windows security patches, disable SMBv1, and firewall port 445 from untrusted networks."
        ))
        score += 12

    # 12. Audit Web Services & SSL Certificates
    for web in host.web_services:
        if web.ssl_info:
            if web.ssl_info.is_expired:
                findings.append(SecurityFinding(
                    title="Expired SSL/TLS Certificate",
                    severity=RiskLevel.HIGH,
                    description=f"SSL certificate for {web.url} expired on {web.ssl_info.valid_to}.",
                    port=web.port,
                    remediation="Renew the SSL/TLS certificate immediately."
                ))
                score += 25
            elif web.ssl_info.days_left is not None and web.ssl_info.days_left < 14:
                findings.append(SecurityFinding(
                    title="SSL Certificate Expiring Soon",
                    severity=RiskLevel.LOW,
                    description=f"Certificate for {web.url} expires in {web.ssl_info.days_left} days.",
                    port=web.port,
                    remediation="Schedule automated certificate renewal before expiry."
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

        # Sensitive endpoints discovered
        for ep in web.discovered_endpoints:
            ep_url_lower = ep.url.lower()
            if ".env" in ep_url_lower and ep.status_code == 200:
                findings.append(SecurityFinding(
                    title="CRITICAL: Exposed .env Configuration File",
                    severity=RiskLevel.CRITICAL,
                    description=f"Environment credentials file accessible at {ep.url}.",
                    port=web.port,
                    remediation="Block access to dotfiles (.env, .git) in web server config immediately."
                ))
                score += 50
            elif ".git" in ep_url_lower and ep.status_code == 200:
                findings.append(SecurityFinding(
                    title="CRITICAL: Exposed .git Version Control Metadata",
                    severity=RiskLevel.CRITICAL,
                    description=f"Git repository files accessible at {ep.url}, allowing full source code extraction.",
                    port=web.port,
                    remediation="Deny public access to .git directories via web server configuration."
                ))
                score += 45
            elif "phpmyadmin" in ep_url_lower and ep.status_code in (200, 301, 302):
                findings.append(SecurityFinding(
                    title="Exposed phpMyAdmin Administration Portal",
                    severity=RiskLevel.MEDIUM,
                    description=f"phpMyAdmin database management panel detected at {ep.url}.",
                    port=web.port,
                    remediation="Restrict access to phpMyAdmin by IP allowlist or VPN."
                ))
                score += 15

        # Missing HSTS header on HTTPS services
        if web.is_https and "Strict-Transport-Security (HSTS)" in web.missing_security_headers:
            findings.append(SecurityFinding(
                title=f"Missing HSTS Header ({web.url})",
                severity=RiskLevel.LOW,
                description="HTTP Strict Transport Security (HSTS) header is absent, enabling SSL-stripping attacks.",
                port=web.port,
                remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to response headers."
            ))
            score += 3

    # Calculate overall risk level from accumulated score
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
