"""
Multicast Service Discovery (SSDP / UPnP).
Discovers smart TVs, routers, gateways, media servers, and IoT devices with detailed metadata.
"""

import asyncio
import re
import socket
from typing import Dict, Optional
import httpx
from bs4 import BeautifulSoup
from ..models import SSDPDeviceInfo


SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900
SSDP_MX = 2

SSDP_SEARCH_MSG = (
    "M-SEARCH * HTTP/1.1\r\n"
    f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
    'MAN: "ssdp:discover"\r\n'
    f"MX: {SSDP_MX}\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
).encode("utf-8")


class SSDPDiscoveryProtocol(asyncio.DatagramProtocol):
    def __init__(self, on_device_found):
        self.on_device_found = on_device_found
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        try:
            text = data.decode("utf-8", errors="ignore")
            headers = {}
            for line in text.split("\r\n"):
                if ":" in line:
                    key, val = line.split(":", 1)
                    headers[key.strip().upper()] = val.strip()

            ip = addr[0]
            location = headers.get("LOCATION", "")
            server = headers.get("SERVER", "")
            st = headers.get("ST", "")

            self.on_device_found(ip, location, server, st)
        except Exception:
            pass

    def error_received(self, exc):
        pass


async def fetch_ssdp_descriptor(url: str, timeout: float = 2.0) -> Optional[Dict[str, str]]:
    """Fetches UPnP root description XML from the LOCATION URL and extracts device details."""
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")
                device = soup.find("device")
                if device:
                    def get_text(tag_name):
                        t = device.find(tag_name)
                        return t.get_text().strip() if t else ""

                    return {
                        "friendly_name": get_text("friendlyname"),
                        "manufacturer": get_text("manufacturer"),
                        "model_name": get_text("modelname"),
                        "model_number": get_text("modelnumber"),
                        "presentation_url": get_text("presentationurl"),
                        "device_type": get_text("devicetype"),
                    }
    except Exception:
        pass
    return None


class SSDPCrawler:
    def __init__(self, listen_duration: float = 2.5):
        self.listen_duration = listen_duration
        self.discovered_raw: Dict[str, Dict[str, str]] = {}

    def _handle_found(self, ip: str, location: str, server: str, st: str):
        if ip not in self.discovered_raw or location:
            self.discovered_raw[ip] = {
                "ip": ip,
                "location": location,
                "server": server,
                "st": st,
            }

    async def discover(self) -> Dict[str, SSDPDeviceInfo]:
        """Runs SSDP multicast discovery and resolves device descriptors."""
        loop = asyncio.get_running_loop()
        results: Dict[str, SSDPDeviceInfo] = {}

        try:
            # Create UDP socket bound to 0.0.0.0
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setblocking(False)

            transport, protocol = await loop.create_datagram_endpoint(
                lambda: SSDPDiscoveryProtocol(self._handle_found),
                sock=sock
            )

            # Send multicast M-SEARCH packet
            try:
                transport.sendto(SSDP_SEARCH_MSG, (SSDP_ADDR, SSDP_PORT))
            except Exception:
                pass

            # Listen for responses
            await asyncio.sleep(self.listen_duration)
            transport.close()

            # Now fetch XML descriptions concurrently
            async def resolve_device(ip: str, raw: dict):
                info = SSDPDeviceInfo(
                    location=raw.get("location", ""),
                    server=raw.get("server", ""),
                    device_type=raw.get("st", ""),
                )
                loc = raw.get("location")
                if loc and (loc.startswith("http://") or loc.startswith("https://")):
                    desc = await fetch_ssdp_descriptor(loc)
                    if desc:
                        info.friendly_name = desc.get("friendly_name", "")
                        info.manufacturer = desc.get("manufacturer", "")
                        info.model_name = desc.get("model_name", "")
                        info.model_number = desc.get("model_number", "")
                        info.presentation_url = desc.get("presentation_url", "")
                        if desc.get("device_type"):
                            info.device_type = desc.get("device_type")
                return ip, info

            tasks = [resolve_device(ip, raw) for ip, raw in self.discovered_raw.items()]
            if tasks:
                resolved = await asyncio.gather(*tasks, return_exceptions=True)
                for item in resolved:
                    if isinstance(item, tuple):
                        results[item[0]] = item[1]

        except Exception:
            pass

        return results
