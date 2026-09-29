"""
High-speed asynchronous TCP port scanner and service identifier.
"""

import asyncio
import socket
from typing import Dict, List, Optional, Set
from ..models import PortProfile, PortResult, RiskLevel


# Service definitions for common ports
KNOWN_SERVICES: Dict[int, str] = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    68: "dhcp",
    69: "tftp",
    80: "http",
    88: "kerberos",
    110: "pop3",
    111: "rpcbind",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    162: "snmptrap",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    514: "syslog",
    587: "submission",
    636: "ldaps",
    873: "rsync",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1194: "openvpn",
    1433: "mssql",
    1521: "oracle",
    1723: "pptp",
    1883: "mqtt",
    2049: "nfs",
    2375: "docker-plain",
    2376: "docker-tls",
    3000: "http-dev",
    3128: "squid-proxy",
    3306: "mysql",
    3389: "rdp",
    4443: "https-alt",
    5000: "http-alt / upnp",
    5060: "sip",
    5353: "mdns",
    5432: "postgresql",
    5672: "rabbitmq",
    5900: "vnc",
    5985: "winrm-http",
    5986: "winrm-https",
    6379: "redis",
    6443: "kubernetes-api",
    8000: "http-alt",
    8008: "http-alt",
    8080: "http-proxy",
    8081: "http-alt",
    8443: "https-alt",
    8888: "http-alt",
    9000: "portainer / sonar",
    9090: "prometheus",
    9100: "node-exporter",
    9200: "elasticsearch",
    9418: "git",
    11211: "memcached",
    27017: "mongodb",
}

# Top 25 Ports (Fast Profile)
FAST_PORTS: List[int] = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
    993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 27017
]

# Top 100 Ports (Standard Profile)
STANDARD_PORTS: List[int] = sorted(list(set(FAST_PORTS + [
    20, 69, 88, 111, 137, 138, 161, 389, 465, 514, 587, 636, 873, 1025, 1080, 1194,
    1723, 1883, 2049, 2121, 2222, 2375, 2376, 3000, 3128, 4443, 5000, 5001, 5060,
    5222, 5353, 5672, 5985, 5986, 6000, 6443, 6667, 7000, 7070, 7443, 8000, 8008,
    8081, 8088, 8181, 8282, 8444, 8500, 8880, 9000, 9042, 9090, 9092, 9100, 9200,
    9300, 9418, 9999, 10000, 11211, 16379, 20000, 25565, 27018, 50000, 50070
])))

# Extended Ports (Top 1000 most common ports in security scans)
EXTENDED_PORTS: List[int] = sorted(list(set(STANDARD_PORTS + list(range(1, 1025)))))


def parse_port_spec(spec: str, profile: PortProfile = PortProfile.STANDARD) -> List[int]:
    """Parses user port specification string or returns profile presets."""
    if profile == PortProfile.FAST:
        return FAST_PORTS
    elif profile == PortProfile.EXTENDED:
        return EXTENDED_PORTS
    elif profile == PortProfile.STANDARD and not spec:
        return STANDARD_PORTS

    if not spec:
        return STANDARD_PORTS

    ports: Set[int] = set()
    parts = spec.split(",")
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                s = max(1, int(start.strip()))
                e = min(65535, int(end.strip()))
                ports.update(range(s, e + 1))
            except Exception:
                pass
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except Exception:
                pass

    return sorted(list(ports)) if ports else STANDARD_PORTS


async def check_port(
    ip: str,
    port: int,
    semaphore: asyncio.Semaphore,
    timeout: float = 1.0
) -> Optional[PortResult]:
    """Asynchronously checks if a single TCP port is open."""
    async with semaphore:
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            service = KNOWN_SERVICES.get(port, "unknown")
            risk = RiskLevel.INFO
            reason = ""

            # Preliminary risk hints
            if port == 23:
                risk = RiskLevel.HIGH
                reason = "Telnet protocol transmits all credentials in cleartext"
            elif port == 21:
                risk = RiskLevel.MEDIUM
                reason = "FTP is unencrypted; check for anonymous access"
            elif port in (6379, 27017, 11211):
                risk = RiskLevel.HIGH
                reason = f"NoSQL/Cache port ({service}) exposed to network"
            elif port == 2375:
                risk = RiskLevel.CRITICAL
                reason = "Unencrypted Docker daemon socket allows root remote execution"

            return PortResult(
                port=port,
                protocol="tcp",
                state="open",
                service=service,
                risk_level=risk,
                risk_reason=reason
            )
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None


async def scan_host_ports(
    ip: str,
    ports: List[int],
    concurrency: int = 150,
    timeout: float = 1.0,
    progress_callback = None
) -> List[PortResult]:
    """Scans a list of TCP ports for a given IP with concurrency limit."""
    semaphore = asyncio.Semaphore(concurrency)
    open_ports: List[PortResult] = []

    async def scan_single(p):
        res = await check_port(ip, p, semaphore, timeout)
        if progress_callback:
            progress_callback(ip, p, res is not None)
        return res

    tasks = [scan_single(p) for p in ports]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in results:
        if isinstance(r, PortResult):
            open_ports.append(r)

    return sorted(open_ports, key=lambda x: x.port)
