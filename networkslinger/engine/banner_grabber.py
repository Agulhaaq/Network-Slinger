"""
Asynchronous service banner grabber and protocol prober.
Extracts service versions, configurations, and detects unauthenticated exposures.
"""

import asyncio
import re
from typing import Dict, Optional, Tuple


async def grab_ssh_banner(ip: str, port: int, timeout: float = 1.5) -> Tuple[str, Dict]:
    details = {}
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout)
            banner = line.decode("utf-8", errors="ignore").strip()
            if "SSH" in banner:
                details["protocol"] = "SSH"
                details["raw_banner"] = banner
                return banner, details
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except Exception:
        pass
    return "", details


async def grab_ftp_banner(ip: str, port: int, timeout: float = 1.5) -> Tuple[str, Dict]:
    details = {"anonymous_allowed": False}
    banner = ""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout)
            banner = line.decode("utf-8", errors="ignore").strip()

            # Check anonymous login
            writer.write(b"USER anonymous\r\n")
            await writer.drain()
            user_resp = await asyncio.wait_for(reader.readline(), timeout=timeout)
            user_str = user_resp.decode("utf-8", errors="ignore")
            if "331" in user_str:
                writer.write(b"PASS guest@slinger.local\r\n")
                await writer.drain()
                pass_resp = await asyncio.wait_for(reader.readline(), timeout=timeout)
                if "230" in pass_resp.decode("utf-8", errors="ignore"):
                    details["anonymous_allowed"] = True

            writer.write(b"QUIT\r\n")
            await writer.drain()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except Exception:
        pass
    return banner, details


async def grab_smtp_banner(ip: str, port: int, timeout: float = 1.5) -> Tuple[str, Dict]:
    details = {}
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout)
            banner = line.decode("utf-8", errors="ignore").strip()
            return banner, details
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except Exception:
        pass
    return "", details


async def probe_redis(ip: str, port: int, timeout: float = 1.5) -> Tuple[str, Dict]:
    details = {"unauthenticated": False}
    banner = ""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        try:
            writer.write(b"PING\r\n")
            await writer.drain()
            resp = await asyncio.wait_for(reader.readline(), timeout=timeout)
            resp_str = resp.decode("utf-8", errors="ignore").strip()
            if "+PONG" in resp_str:
                details["unauthenticated"] = True
                banner = "Redis (Unauthenticated Access!)"
                # Try to grab server info for version
                writer.write(b"INFO server\r\n")
                await writer.drain()
                try:
                    info_data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
                    match = re.search(
                        r"redis_version:([0-9\.]+)",
                        info_data.decode("utf-8", errors="ignore")
                    )
                    if match:
                        banner = f"Redis {match.group(1)} (Unauthenticated Access!)"
                except Exception:
                    pass
            elif "NOAUTH" in resp_str:
                banner = "Redis (Authentication Required)"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except Exception:
        pass
    return banner, details


async def probe_mysql(ip: str, port: int, timeout: float = 1.5) -> Tuple[str, Dict]:
    details = {}
    banner = ""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        try:
            data = await asyncio.wait_for(reader.read(256), timeout=timeout)
            if len(data) > 5:
                # MySQL initial handshake packet:
                # [3-byte packet length][1-byte seq][1-byte proto version][null-term version]
                proto_version = data[4]
                null_pos = data.find(b"\x00", 5)
                if null_pos != -1:
                    version_str = data[5:null_pos].decode("utf-8", errors="ignore")
                    banner = f"MySQL/MariaDB {version_str} (Proto v{proto_version})"
                    details["version"] = version_str
                    details["protocol_version"] = proto_version
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except Exception:
        pass
    return banner, details


async def probe_generic(ip: str, port: int, timeout: float = 1.0) -> Tuple[str, Dict]:
    """Generic banner grab for unspecified ports — listens for greeting, then probes."""
    details = {}
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        try:
            # First listen for passive greeting
            try:
                line = await asyncio.wait_for(reader.read(256), timeout=0.6)
                if line:
                    return line.decode("utf-8", errors="ignore").strip()[:120], details
            except asyncio.TimeoutError:
                pass

            # Send probe if no passive banner
            writer.write(b"\r\n\r\n")
            await writer.drain()
            try:
                line = await asyncio.wait_for(reader.read(256), timeout=0.6)
                if line:
                    return line.decode("utf-8", errors="ignore").strip()[:120], details
            except asyncio.TimeoutError:
                pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except Exception:
        pass
    return "", details


async def grab_banner_for_port(
    ip: str,
    port: int,
    service: str,
    timeout: float = 1.5
) -> Tuple[str, Dict]:
    """Dispatches appropriate banner prober based on port and recognized service."""
    if port in (22, 2222) or service == "ssh":
        return await grab_ssh_banner(ip, port, timeout)
    elif port in (21, 2121) or service == "ftp":
        return await grab_ftp_banner(ip, port, timeout)
    elif port in (25, 465, 587) or service in ("smtp", "smtps", "submission"):
        return await grab_smtp_banner(ip, port, timeout)
    elif port == 6379 or service == "redis":
        return await probe_redis(ip, port, timeout)
    elif port == 3306 or service == "mysql":
        return await probe_mysql(ip, port, timeout)
    elif port in (80, 443, 8080, 8443, 8888, 3000, 5000, 8000, 9000):
        # Web services handled by web_crawler — skip here
        return "", {}
    else:
        return await probe_generic(ip, port, timeout=1.0)
