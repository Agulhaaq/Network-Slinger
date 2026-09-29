"""
Network Slinger - Advanced Network Crawler, Topology Mapper & Service Auditor.
"""

__version__ = "1.0.0"
__author__ = "Antigravity Engineering"

from .models import (
    HostResult,
    PortResult,
    ScanConfig,
    ScanProgress,
    ScanReport,
    WebCrawlResult,
)

__all__ = [
    "ScanConfig",
    "ScanReport",
    "ScanProgress",
    "HostResult",
    "PortResult",
    "WebCrawlResult",
]
