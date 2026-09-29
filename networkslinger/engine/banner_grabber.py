"""
Asynchronous service banner grabber and protocol prober.
Extracts service versions, configurations, and detects unauthenticated exposures (e.g. open Redis, anonymous FTP).
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
        line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        banner = line.decode("utf-8", errors="ignore").strip()
        writer.close()
        await writer.wait_closed()
        if "SSH" in banner:
            details["protocol"] = "SSH"
            details["raw_banner"] = banner
            return banner, details
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
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass
    return banner, details


async def grab_smtp_banner(ip: str, port: int, timeout: float = 1.5) -> Tuple[str, Dict]:
    details = {}
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        banner = line.decode("utf-8", errors="ignore").strip()
        writer.close()
        await writer.wait_closed()
        return banner, details
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
        writer.write(b"PING\r\n")
        await writer.drain()
        resp = await asyncio.wait_for(reader.readline(), timeout=timeout)
        resp_str = resp.decode("utf-8", errors="ignore").strip()
        if "+PONG" in resp_str:
            details["unauthenticated"] = True
            banner = "Redis (Unauthenticated Access!)"
            # Attempt to grab server info
            writer.write(b"INFO server\r\n")
            await writer.drain()
            info_data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            match = re.search(r"redis_version:([0-9\.]+)", info_data.decode("utf-8", errors="ignore"))
            if match:
                banner = f"Redis {match.group(1)} (Unauthenticated Access!)"
        elif "NOAUTH" in resp_str:
            banner = "Redis (Authentication Required)"

        writer.close()
        await writer.wait_closed()
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
        data = await asyncio.wait_for(reader.read(256), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        if len(data) > 5:
            # MySQL initial handshake packet format:
            # [packet length: 3][packet number: 1][protocol version: 1][server version: null-terminated string]
            proto_version = data[4]
            null_pos = data.find(b"\x00", 5)
            if null_pos != -1:
                version_str = data[5:null_pos].decode("utf-8", errors="ignore")
                banner = f"MySQL/MariaDB {version_str} (Proto v{proto_version})"
                details["version"] = version_str
                details["protocol_version"] = proto_version
    except Exception:
        pass
    return banner, details


async def probe_generic(ip: str, port: int, timeout: float = 1.0) -> Tuple[str, Dict]:
    """Generic banner grab for unspecified ports."""
    details = {}
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        # First listen for passive greeting
        try:
            line = await asyncio.wait_for(reader.read(256), timeout=0.6)
            if line:
                banner = line.decode("utf-8", errors="ignore").strip()
                writer.close()
                await writer.wait_closed()
                return banner[:120], details
        except asyncio.TimeoutError:
            pass

        # Send probe if no passive banner
        writer.write(b"\r\n\r\n")
        await writer.drain()
        line = await asyncio.wait_for(reader.read(256), timeout=0.6)
        writer.close()
        await writer.wait_closed()
        if line:
            return line.decode("utf-8", errors="ignore").strip()[:120], details
    except Exception:
        pass
    return "", details


async def grab_banner_for_port(ip: str, port: int, service: str, timeout: float = 1.5) -> Tuple[str, Dict]:
    """Dispatches appropriate banner prober based on port and recognized service."""
    if port in (22, 2222) or service == "ssh":
        return await grab_ssh_banner(ip, port, timeout)
    elif port in (21, 2121) or service == "ftp":
        return await grab_ftp_banner(ip, port, timeout)
    elif port in (25, 465, 587) or service in ("smtp", "smtps"):
        return await grab_smtp_banner(ip, port, timeout)
    elif port == 6379 or service == "redis":
        return await probe_redis(ip, port, timeout)
    elif port == 3306 or service == "mysql":
        return await probe_mysql(ip, port, timeout)
    elif port in (80, 443, 8080, 8443, 8888, 3000, 5000):
        # Web services handled by web_crawler
        return "", {}
    else:
        return await probe_generic(ip, port, timeout=1.0)
