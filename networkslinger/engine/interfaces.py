"""
Local network interfaces and CIDR target calculation utilities.
"""

import ipaddress
import platform
import re
import socket
import subprocess
from typing import Dict, List, Optional, Tuple
import psutil


class InterfaceInfo:
    def __init__(self, name: str, ip: str, netmask: str, mac: Optional[str] = None):
        self.name = name
        self.ip = ip
        self.netmask = netmask
        self.mac = mac
        try:
            self.network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
            self.cidr = str(self.network)
        except Exception:
            self.network = None
            self.cidr = f"{ip}/32"

    def to_dict(self) -> Dict[str, str]:
        return {
            "name": self.name,
            "ip": self.ip,
            "netmask": self.netmask,
            "cidr": self.cidr,
            "mac": self.mac or ""
        }


def get_default_gateway() -> Optional[str]:
    """Finds the default gateway IP address on Windows or Linux."""
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output("route print 0.0.0.0", shell=True, text=True, stderr=subprocess.DEVNULL)
            for line in output.splitlines():
                parts = line.strip().split()
                if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    gateway_ip = parts[2]
                    # Verify it's a valid IPv4
                    socket.inet_aton(gateway_ip)
                    return gateway_ip
        else:
            output = subprocess.check_output("ip route", shell=True, text=True, stderr=subprocess.DEVNULL)
            match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", output)
            if match:
                return match.group(1)
    except Exception:
        pass
    return None


def get_active_interfaces() -> List[InterfaceInfo]:
    """
    Returns a list of all active network interfaces having a valid IPv4 address.
    Filters out loopback (127.0.0.1) and APIPA (169.254.x.x) if better interfaces exist.
    """
    interfaces: List[InterfaceInfo] = []
    addrs = psutil.net_if_addrs()

    for iface_name, addr_list in addrs.items():
        ipv4_addr = None
        netmask = None
        mac_addr = None

        for addr in addr_list:
            if addr.family == socket.AF_INET:
                ipv4_addr = addr.address
                netmask = addr.netmask or "255.255.255.0"
            elif addr.family == psutil.AF_LINK or (hasattr(socket, "AF_PACKET") and addr.family == socket.AF_PACKET):
                mac_addr = addr.address

        if ipv4_addr and ipv4_addr != "127.0.0.1":
            interfaces.append(InterfaceInfo(name=iface_name, ip=ipv4_addr, netmask=netmask, mac=mac_addr))

    # Prioritize non-APIPA interfaces (169.254.x.x is link-local fallback)
    non_apipa = [i for i in interfaces if not i.ip.startswith("169.254.")]
    return non_apipa if non_apipa else interfaces


def get_primary_interface() -> Optional[InterfaceInfo]:
    """Returns the most likely primary local network interface (e.g. connected to Wi-Fi or Ethernet LAN)."""
    active = get_active_interfaces()
    if not active:
        return None

    gateway = get_default_gateway()
    if gateway:
        # Check which interface contains the gateway in its subnet
        for iface in active:
            if iface.network and ipaddress.IPv4Address(gateway) in iface.network:
                return iface

    # Otherwise return the first valid private LAN interface (192.168.x, 10.x, 172.16-31.x)
    for iface in active:
        if iface.ip.startswith(("192.168.", "10.", "172.")):
            return iface

    return active[0]


def parse_targets(target_strings: List[str]) -> List[str]:
    """
    Parses a list of target specifications:
    - CIDR: '192.168.1.0/24'
    - Range: '192.168.1.1-192.168.1.25'
    - Hostname / IP: '192.168.1.1', 'example.com'
    Returns a deduplicated list of IP addresses to scan.
    """
    resolved_ips: List[str] = []
    seen = set()

    for item in target_strings:
        item = item.strip()
        if not item:
            continue

        # Handle IP Range: '192.168.1.1-192.168.1.50' or '192.168.1.1-50'
        if "-" in item and not "/" in item:
            parts = item.split("-")
            if len(parts) == 2:
                start_str, end_str = parts[0].strip(), parts[1].strip()
                try:
                    start_ip = ipaddress.IPv4Address(start_str)
                    if "." in end_str:
                        end_ip = ipaddress.IPv4Address(end_str)
                    else:
                        # e.g., '192.168.1.1-50'
                        octets = start_str.split(".")
                        octets[-1] = end_str
                        end_ip = ipaddress.IPv4Address(".".join(octets))

                    cur = int(start_ip)
                    end = int(end_ip)
                    for ip_int in range(cur, min(end + 1, cur + 1024)):
                        ip_str = str(ipaddress.IPv4Address(ip_int))
                        if ip_str not in seen:
                            seen.add(ip_str)
                            resolved_ips.append(ip_str)
                    continue
                except Exception:
                    pass

        # Handle CIDR: e.g. '192.168.1.0/24'
        if "/" in item:
            try:
                net = ipaddress.IPv4Network(item, strict=False)
                # Cap maximum hosts to prevent runaway loops (max 1024 hosts per range)
                for host in list(net.hosts())[:1024]:
                    ip_str = str(host)
                    if ip_str not in seen:
                        seen.add(ip_str)
                        resolved_ips.append(ip_str)
                continue
            except Exception:
                pass

        # Handle Single Host / IP
        try:
            ip_obj = ipaddress.IPv4Address(item)
            ip_str = str(ip_obj)
            if ip_str not in seen:
                seen.add(ip_str)
                resolved_ips.append(ip_str)
        except Exception:
            # Domain or Hostname
            try:
                addr = socket.gethostbyname(item)
                if addr not in seen:
                    seen.add(addr)
                    resolved_ips.append(addr)
            except Exception:
                pass

    return resolved_ips
