"""
High-speed asynchronous host discovery and device type classification.
"""

import asyncio
import socket
import time
from typing import Callable, List, Optional
from ..models import DeviceType, HostResult
from .arp_finder import async_resolve_mac
from .interfaces import get_default_gateway
from .oui_database import lookup_vendor


FAST_PING_PORTS = [80, 443, 22, 135, 445, 8080, 53, 3389]


async def probe_ip_alive(
    ip: str,
    gateway_ip: Optional[str] = None,
    timeout: float = 0.8
) -> Optional[HostResult]:
    """
    Probes an IP to see if it is responsive via ARP (local LAN) or fast TCP probe.
    Returns HostResult if alive, None otherwise.
    """
    start_time = time.perf_counter()

    # 1. ARP Resolution (Instantaneous physical check on local segment)
    mac = await async_resolve_mac(ip)
    is_alive = mac is not None

    # 2. Fast TCP SYN/Connect ping across common ports
    if not is_alive:
        for port in FAST_PING_PORTS:
            try:
                conn = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(conn, timeout=timeout)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                is_alive = True
                break
            except Exception:
                continue

    if not is_alive:
        return None

    latency = (time.perf_counter() - start_time) * 1000.0

    # 3. Vendor identification
    vendor = lookup_vendor(mac) if mac else "Unknown Vendor"

    # 4. Reverse DNS lookup
    hostname = ""
    try:
        loop = asyncio.get_running_loop()
        h_info = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
        hostname = h_info[0]
    except Exception:
        pass

    # 5. Classify initial device type
    dev_type = DeviceType.UNKNOWN
    if gateway_ip and ip == gateway_ip:
        dev_type = DeviceType.GATEWAY
    elif any(k in vendor.lower() for k in ("espressif", "tuya", "philips", "roku", "sonos", "amazon", "google")):
        dev_type = DeviceType.IOT
    elif any(k in vendor.lower() for k in ("canon", "epson", "brother", "xerox", "lexmark", "hp")):
        dev_type = DeviceType.PRINTER
    elif any(k in vendor.lower() for k in ("cisco", "netgear", "tp-link", "ubiquiti", "mikrotik", "asus")):
        dev_type = DeviceType.GATEWAY

    return HostResult(
        ip=ip,
        mac_address=mac,
        vendor=vendor,
        hostname=hostname,
        device_type=dev_type,
        is_alive=True,
        latency_ms=round(latency, 2)
    )


async def discover_hosts(
    ips: List[str],
    concurrency: int = 100,
    timeout: float = 0.8,
    progress_callback: Optional[Callable[[str, bool], None]] = None
) -> List[HostResult]:
    """Scans a list of target IPs concurrently to identify live hosts."""
    gateway_ip = get_default_gateway()
    semaphore = asyncio.Semaphore(concurrency)
    live_hosts: List[HostResult] = []

    async def check_host(ip: str):
        async with semaphore:
            host = await probe_ip_alive(ip, gateway_ip=gateway_ip, timeout=timeout)
            if progress_callback:
                progress_callback(ip, host is not None)
            return host

    tasks = [check_host(ip) for ip in ips]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for res in results:
        if isinstance(res, HostResult):
            live_hosts.append(res)

    # Sort numerically by IP octets
    def ip_sort_key(h: HostResult):
        try:
            return [int(x) for x in h.ip.split(".")]
        except Exception:
            return [0, 0, 0, 0]

    return sorted(live_hosts, key=ip_sort_key)
