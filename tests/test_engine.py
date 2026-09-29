"""
Unit and integration tests for Network Slinger engine.
"""

import asyncio
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from networkslinger.models import PortProfile
from networkslinger.engine import (
    get_active_interfaces,
    get_default_gateway,
    lookup_vendor,
    parse_targets,
    parse_port_spec,
    resolve_mac,
    probe_ip_alive,
)


def test_interfaces_and_gateway():
    ifaces = get_active_interfaces()
    assert len(ifaces) > 0, "Should detect at least one active network interface"
    print(f"[PASS] Detected {len(ifaces)} interfaces: {[i.name + ' (' + i.ip + ')' for i in ifaces]}")

    gw = get_default_gateway()
    print(f"[PASS] Default gateway resolved: {gw}")


def test_oui_lookup():
    assert "Apple" in lookup_vendor("00:03:93:00:00:00")
    assert "TP-Link" in lookup_vendor("D4:1A:D1:00:00:00")
    assert "Raspberry Pi" in lookup_vendor("B8:27:EB:00:00:00")
    assert "Espressif" in lookup_vendor("24:6F:28:00:00:00")
    print("[PASS] MAC OUI Vendor lookup working properly")


def test_target_parsing():
    ips = parse_targets(["192.168.1.1", "192.168.1.10-192.168.1.15"])
    assert len(ips) == 7
    assert "192.168.1.1" in ips
    assert "192.168.1.15" in ips
    print(f"[PASS] Target parser resolved {len(ips)} IPs correctly")


def test_port_specs():
    fast = parse_port_spec("", PortProfile.FAST)
    assert 80 in fast and 443 in fast and 22 in fast
    custom = parse_port_spec("80,443,8000-8005", PortProfile.CUSTOM)
    assert len(custom) == 8
    print(f"[PASS] Port spec parser resolved {len(custom)} custom ports")


async def async_host_probe():
    # Test localhost alive check
    host = await probe_ip_alive("127.0.0.1")
    assert host is not None
    assert host.is_alive
    print(f"[PASS] Localhost probe successful: {host.ip}, latency: {host.latency_ms}ms")


if __name__ == "__main__":
    test_interfaces_and_gateway()
    test_oui_lookup()
    test_target_parsing()
    test_port_specs()
    asyncio.run(async_host_probe())
    print("\nALL BASIC ENGINE TESTS PASSED!")
