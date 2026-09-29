"""
Master Network Crawler & Reconnaissance Orchestrator.
Coordinates host discovery, port scanning, banner grabbing, web scrawling, SSDP, and vulnerability auditing.
"""

import asyncio
from datetime import datetime
import time
from typing import Callable, Dict, List, Optional
import uuid

from ..models import (
    DeviceType,
    HostResult,
    PortProfile,
    PortResult,
    RiskLevel,
    ScanConfig,
    ScanProgress,
    ScanReport,
    ScanSummary,
    TopologyEdge,
    TopologyGraph,
    TopologyNode,
    WebCrawlResult,
)
from .banner_grabber import grab_banner_for_port
from .host_discovery import discover_hosts
from .interfaces import get_default_gateway, get_primary_interface, parse_targets
from .multicast_ssdp import SSDPCrawler
from .port_scanner import parse_port_spec, scan_host_ports
from .security_auditor import audit_host
from .web_crawler import crawl_web_service


WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000, 9090, 8081}


class NetworkSlingerCrawler:
    def __init__(self, config: Optional[ScanConfig] = None):
        self.config = config or ScanConfig()
        self.scan_id = str(uuid.uuid4())[:8]
        self.progress = ScanProgress(
            scan_id=self.scan_id,
            stage="Idle",
            percent=0.0,
            message="Ready to scrawl"
        )
        self.progress_subscribers: List[Callable[[ScanProgress], None]] = []

    def register_progress_callback(self, cb: Callable[[ScanProgress], None]):
        self.progress_subscribers.append(cb)

    def _notify_progress(self, stage: str, percent: float, msg: str, **kwargs):
        self.progress.stage = stage
        self.progress.percent = round(percent, 1)
        self.progress.message = msg
        for k, v in kwargs.items():
            if hasattr(self.progress, k):
                setattr(self.progress, k, v)
        for cb in self.progress_subscribers:
            try:
                cb(self.progress)
            except Exception:
                pass

    async def execute_crawl(self) -> ScanReport:
        """Executes the complete end-to-end network scrawl."""
        start_time = time.perf_counter()
        started_dt = datetime.now()

        # Step 1: Target Resolution
        self._notify_progress("Target Resolution", 5.0, "Resolving network targets...")
        target_ips: List[str] = []

        if not self.config.targets:
            primary_iface = get_primary_interface()
            if primary_iface:
                target_str = primary_iface.cidr
                self.config.targets = [target_str]
                target_ips = parse_targets([target_str])
            else:
                target_ips = ["127.0.0.1"]
        else:
            target_ips = parse_targets(self.config.targets)

        if not target_ips:
            target_ips = ["127.0.0.1"]

        self._notify_progress(
            "Host Discovery",
            10.0,
            f"Probing {len(target_ips)} target IP addresses...",
            hosts_total=len(target_ips)
        )

        # Step 2: Concurrent SSDP discovery if enabled
        ssdp_devices = {}
        ssdp_task = None
        if self.config.enable_multicast:
            ssdp_task = asyncio.create_task(SSDPCrawler(listen_duration=2.0).discover())

        # Step 3: Host Discovery
        discovered_count = 0

        def on_host_probe(ip: str, is_alive: bool):
            nonlocal discovered_count
            if is_alive:
                discovered_count += 1
            self.progress.hosts_discovered = discovered_count
            self.progress.current_target = ip

        live_hosts = await discover_hosts(
            target_ips,
            concurrency=self.config.concurrency,
            timeout=self.config.timeout,
            progress_callback=on_host_probe
        )

        # Await SSDP discovery if running
        if ssdp_task:
            try:
                ssdp_devices = await ssdp_task
            except Exception:
                pass

        self._notify_progress(
            "Port Scanning",
            30.0,
            f"Found {len(live_hosts)} active hosts. Commencing service scans...",
            hosts_discovered=len(live_hosts)
        )

        # Step 4: Port & Service Crawl for each live host
        target_ports = parse_port_spec(self.config.custom_ports, self.config.port_profile)
        total_ports_to_scan = len(live_hosts) * len(target_ports)
        scanned_ports_counter = 0

        async def scan_single_host(host: HostResult):
            nonlocal scanned_ports_counter

            # Attach SSDP if found
            if host.ip in ssdp_devices:
                host.ssdp_info = ssdp_devices[host.ip]
                if host.ssdp_info.friendly_name and not host.hostname:
                    host.hostname = host.ssdp_info.friendly_name
                if host.ssdp_info.device_type:
                    host.device_type = DeviceType.IOT

            # Scan Ports
            def on_port_check(ip, port, is_open):
                nonlocal scanned_ports_counter
                scanned_ports_counter += 1
                if total_ports_to_scan > 0:
                    pct = 30.0 + (scanned_ports_counter / total_ports_to_scan) * 45.0
                    self._notify_progress(
                        "Port Scanning",
                        pct,
                        f"Scanning {host.ip}:{port}...",
                        ports_scanned=scanned_ports_counter,
                        ports_total=total_ports_to_scan
                    )

            open_ports = await scan_host_ports(
                host.ip,
                target_ports,
                concurrency=min(self.config.concurrency, 60),
                timeout=self.config.timeout,
                progress_callback=on_port_check
            )

            # Deep Banner Probing
            for p in open_ports:
                banner, details = await grab_banner_for_port(host.ip, p.port, p.service)
                if banner:
                    p.banner = banner
                if details:
                    p.details = details

            host.open_ports = open_ports

            # Web Service Crawling
            if self.config.crawl_web:
                web_ports_found = [p.port for p in open_ports if p.port in WEB_PORTS or "http" in p.service]
                for wp in web_ports_found:
                    crawl_res = await crawl_web_service(
                        host.ip,
                        wp,
                        deep_crawl=self.config.deep_web_crawl,
                        timeout=3.0
                    )
                    if crawl_res:
                        host.web_services.append(crawl_res)
                        # Set hostname from page title if still empty
                        if crawl_res.title and not host.hostname:
                            host.hostname = crawl_res.title[:30]

            # Heuristic Device Type Refinement
            port_set = {p.port for p in open_ports}
            if 3389 in port_set or (135 in port_set and 445 in port_set):
                host.device_type = DeviceType.WORKSTATION
            elif any(p in port_set for p in (3306, 5432, 27017, 6379, 22)) and host.device_type == DeviceType.UNKNOWN:
                host.device_type = DeviceType.SERVER
            elif 80 in port_set and 443 in port_set and host.device_type == DeviceType.UNKNOWN:
                host.device_type = DeviceType.SERVER

            # Security Audit
            risk_score, risk_lvl, findings = audit_host(host)
            host.risk_score = risk_score
            host.risk_level = risk_lvl
            host.security_findings = findings

            return host

        # Run host deep scanning concurrently
        host_tasks = [scan_single_host(h) for h in live_hosts]
        completed_hosts = await asyncio.gather(*host_tasks)

        self._notify_progress("Topology Building", 90.0, "Constructing network topology graph...")

        # Step 5: Build Topology Graph
        gateway_ip = get_default_gateway()
        topology = self._build_topology_graph(completed_hosts, gateway_ip)

        # Step 6: Summary Statistics
        summary = ScanSummary(
            total_hosts_scanned=len(target_ips),
            live_hosts_found=len(completed_hosts),
            total_open_ports=sum(len(h.open_ports) for h in completed_hosts),
            total_web_services=sum(len(h.web_services) for h in completed_hosts),
            critical_risks=sum(1 for h in completed_hosts if h.risk_level == RiskLevel.CRITICAL),
            high_risks=sum(1 for h in completed_hosts if h.risk_level == RiskLevel.HIGH),
            medium_risks=sum(1 for h in completed_hosts if h.risk_level == RiskLevel.MEDIUM),
            low_risks=sum(1 for h in completed_hosts if h.risk_level == RiskLevel.LOW),
        )

        duration = time.perf_counter() - start_time
        finished_dt = datetime.now()

        report = ScanReport(
            scan_id=self.scan_id,
            started_at=started_dt,
            finished_at=finished_dt,
            duration_seconds=round(duration, 2),
            config=self.config,
            summary=summary,
            hosts=completed_hosts,
            topology=topology
        )

        self._notify_progress(
            "Complete",
            100.0,
            f"Scrawl completed in {report.duration_seconds}s. Found {summary.live_hosts_found} live hosts with {summary.total_open_ports} open ports.",
            is_complete=True
        )

        return report

    def _build_topology_graph(self, hosts: List[HostResult], gateway_ip: Optional[str]) -> TopologyGraph:
        """Constructs an interactive Node-Edge network topology graph."""
        nodes: List[TopologyNode] = []
        edges: List[TopologyEdge] = []

        # Central Subnet / Gateway Hub
        hub_id = "gateway_hub"
        nodes.append(TopologyNode(
            id=hub_id,
            label=f"Gateway ({gateway_ip})" if gateway_ip else "Network Gateway Hub",
            group="gateway",
            ip=gateway_ip or "0.0.0.0",
            device_type=DeviceType.GATEWAY.value,
            risk_level="INFO",
            details={"gateway_ip": gateway_ip or "Unknown"}
        ))

        for host in hosts:
            node_id = f"host_{host.ip}"
            label = host.hostname if host.hostname else host.ip
            if host.vendor and host.vendor != "Unknown Vendor":
                label += f"\n({host.vendor[:15]})"

            nodes.append(TopologyNode(
                id=node_id,
                label=label,
                group=host.device_type.value.lower().replace(" ", "_"),
                ip=host.ip,
                device_type=host.device_type.value,
                risk_level=host.risk_level.value,
                details={
                    "mac": host.mac_address or "N/A",
                    "vendor": host.vendor,
                    "ports_count": len(host.open_ports),
                    "risk_score": host.risk_score,
                    "findings_count": len(host.security_findings)
                }
            ))

            # Connect Host to Gateway Hub
            edges.append(TopologyEdge(
                source=hub_id,
                target=node_id,
                label=f"{host.latency_ms}ms" if host.latency_ms > 0 else "",
                edge_type="network_link"
            ))

            # Sub-nodes for Open Web Services or Critical Ports
            for web in host.web_services:
                service_id = f"svc_{host.ip}_{web.port}"
                nodes.append(TopologyNode(
                    id=service_id,
                    label=f":{web.port} {web.server or 'HTTP'}",
                    group="service_web",
                    ip=host.ip,
                    device_type="Web Service",
                    risk_level="INFO",
                    details={"url": web.url, "title": web.title}
                ))
                edges.append(TopologyEdge(
                    source=node_id,
                    target=service_id,
                    label=str(web.port),
                    edge_type="service_port"
                ))

        return TopologyGraph(nodes=nodes, edges=edges)
