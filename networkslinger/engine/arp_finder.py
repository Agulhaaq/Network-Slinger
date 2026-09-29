"""
Hardware MAC address resolution using Windows SendARP and system ARP cache fallback.
"""

import asyncio
import ctypes
import platform
import re
import socket
import struct
import subprocess
from typing import Dict, Optional


def resolve_mac_windows(ip: str) -> Optional[str]:
    """Resolves MAC address on Windows using SendARP from Iphlpapi.dll."""
    try:
        dest_ip = struct.unpack('<I', socket.inet_aton(ip))[0]
        mac_buf = (ctypes.c_byte * 6)()
        mac_len = ctypes.c_ulong(6)
        res = ctypes.windll.Iphlpapi.SendARP(dest_ip, 0, ctypes.byref(mac_buf), ctypes.byref(mac_len))
        if res == 0:
            mac_bytes = bytearray(mac_buf)
            # Check if not all zeros
            if any(b != 0 for b in mac_bytes):
                return ':'.join(f'{b & 0xff:02X}' for b in mac_bytes)
    except Exception:
        pass
    return None


def get_arp_cache() -> Dict[str, str]:
    """Reads the operating system's ARP table as fallback."""
    table = {}
    try:
        cmd = "arp -a"
        output = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)
        # Matches IP followed by MAC address (XX-XX-XX-XX-XX-XX or XX:XX:XX:XX:XX:XX)
        pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})")
        for match in pattern.finditer(output):
            ip, mac = match.groups()
            formatted_mac = mac.replace("-", ":").upper()
            if formatted_mac != "FF:FF:FF:FF:FF:FF" and not formatted_mac.startswith("01:00:5E"):
                table[ip] = formatted_mac
    except Exception:
        pass
    return table


_cached_arp_table: Optional[Dict[str, str]] = None


def resolve_mac(ip: str) -> Optional[str]:
    """
    Resolves the MAC address for an IPv4 address.
    Tries Windows SendARP first, then cached ARP table.
    """
    global _cached_arp_table
    if platform.system() == "Windows":
        mac = resolve_mac_windows(ip)
        if mac:
            return mac

    if _cached_arp_table is None:
        _cached_arp_table = get_arp_cache()

    return _cached_arp_table.get(ip)


async def async_resolve_mac(ip: str) -> Optional[str]:
    """Asynchronously resolves the MAC address in a thread pool."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, resolve_mac, ip)
