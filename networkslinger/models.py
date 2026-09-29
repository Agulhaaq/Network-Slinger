"""
Pydantic data models for Network Slinger.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DeviceType(str, Enum):
    GATEWAY = "Gateway / Router"
    SERVER = "Server"
    WORKSTATION = "Workstation / PC"
    IOT = "IoT / Smart Device"
    PRINTER = "Network Printer"
    MOBILE = "Mobile Device"
    UNKNOWN = "Unknown Host"


class PortProfile(str, Enum):
    PING_ONLY = "ping_only"
    FAST = "fast"          # Top 25 ports
    STANDARD = "standard"  # Top 100 ports
    EXTENDED = "extended"  # Top 1000 ports
    CUSTOM = "custom"


class SSLCertInfo(BaseModel):
    subject: str = ""
    issuer: str = ""
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None
    days_left: Optional[int] = None
    is_expired: bool = False
    is_self_signed: bool = False
    san_list: List[str] = Field(default_factory=list)
    signature_algorithm: str = ""


class DiscoveredEndpoint(BaseModel):
    url: str
    status_code: int
    title: str = ""
    content_type: str = ""
    is_sensitive: bool = False
    description: str = ""


class WebCrawlResult(BaseModel):
    url: str
    port: int
    is_https: bool
    status_code: int = 0
    title: str = ""
    server: str = ""
    powered_by: str = ""
    tech_stack: List[str] = Field(default_factory=list)
    ssl_info: Optional[SSLCertInfo] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    missing_security_headers: List[str] = Field(default_factory=list)
    discovered_endpoints: List[DiscoveredEndpoint] = Field(default_factory=list)
    links_found: List[str] = Field(default_factory=list)
    favicon_hash: Optional[str] = None


class PortResult(BaseModel):
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = "unknown"
    banner: str = ""
    details: Dict[str, Any] = Field(default_factory=dict)
    risk_level: RiskLevel = RiskLevel.INFO
    risk_reason: str = ""


class SecurityFinding(BaseModel):
    title: str
    severity: RiskLevel
    description: str
    port: Optional[int] = None
    remediation: str = ""


class SSDPDeviceInfo(BaseModel):
    friendly_name: str = ""
    manufacturer: str = ""
    model_name: str = ""
    model_number: str = ""
    presentation_url: str = ""
    device_type: str = ""
    location: str = ""
    server: str = ""


class HostResult(BaseModel):
    ip: str
    mac_address: Optional[str] = None
    vendor: str = "Unknown Vendor"
    hostname: str = ""
    device_type: DeviceType = DeviceType.UNKNOWN
    is_alive: bool = True
    latency_ms: float = 0.0
    open_ports: List[PortResult] = Field(default_factory=list)
    web_services: List[WebCrawlResult] = Field(default_factory=list)
    ssdp_info: Optional[SSDPDeviceInfo] = None
    netbios_name: Optional[str] = None
    mdns_services: List[str] = Field(default_factory=list)
    security_findings: List[SecurityFinding] = Field(default_factory=list)
    risk_score: int = 0  # 0 to 100
    risk_level: RiskLevel = RiskLevel.INFO
    os_hint: str = ""
    last_seen: datetime = Field(default_factory=datetime.now)


class TopologyNode(BaseModel):
    id: str
    label: str
    group: str
    ip: str = ""
    device_type: str = ""
    risk_level: str = "INFO"
    details: Dict[str, Any] = Field(default_factory=dict)


class TopologyEdge(BaseModel):
    source: str
    target: str
    label: str = ""
    edge_type: str = "connected"


class TopologyGraph(BaseModel):
    nodes: List[TopologyNode] = Field(default_factory=list)
    edges: List[TopologyEdge] = Field(default_factory=list)


class ScanConfig(BaseModel):
    targets: List[str] = Field(default_factory=list)
    port_profile: PortProfile = PortProfile.STANDARD
    custom_ports: str = ""
    concurrency: int = 200
    timeout: float = 1.0
    crawl_web: bool = True
    deep_web_crawl: bool = False
    enable_multicast: bool = True
    include_localhost: bool = False


class ScanProgress(BaseModel):
    scan_id: str
    stage: str
    percent: float = 0.0
    current_target: str = ""
    hosts_discovered: int = 0
    hosts_total: int = 0
    ports_scanned: int = 0
    ports_total: int = 0
    message: str = ""
    is_complete: bool = False
    error: Optional[str] = None


class ScanSummary(BaseModel):
    total_hosts_scanned: int = 0
    live_hosts_found: int = 0
    total_open_ports: int = 0
    total_web_services: int = 0
    critical_risks: int = 0
    high_risks: int = 0
    medium_risks: int = 0
    low_risks: int = 0


class ScanReport(BaseModel):
    scan_id: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    duration_seconds: float = 0.0
    config: ScanConfig
    summary: ScanSummary = Field(default_factory=ScanSummary)
    hosts: List[HostResult] = Field(default_factory=list)
    topology: TopologyGraph = Field(default_factory=TopologyGraph)
