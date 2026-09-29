"""
Network Slinger - Command Line Interface (CLI).
Rich interactive terminal UI with colored tables, live progress bars, and ASCII banners.
"""

import argparse
import asyncio
from datetime import datetime
import json
import os
import sys
from typing import List, Optional

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from .engine import (
    NetworkSlingerCrawler,
    get_active_interfaces,
    get_default_gateway,
    get_primary_interface,
    parse_port_spec,
    parse_targets,
)
from .models import HostResult, PortProfile, RiskLevel, ScanConfig, ScanReport


console = Console(safe_box=True)

BANNER_ART = """[bold cyan]
  _   _      _                      _      ____  _ _
 | \\ | | ___| |___      _____  _ __| | __ / ___|| (_)_ __   __ _  ___ _ __
 |  \\| |/ _ \\ __\\ \\ /\\ / / _ \\| '__| |/ / \\___ \\| | | '_ \\ / _` |/ _ \\ '__|
 | |\\  |  __/ |_ \\ V  V / (_) | |  |   <   ___) | | | | | | (_| |  __/ |
 |_| \\_|\\___|\\__| \\_/\\_/ \\___/|_|  |_|\\_\\ |____/|_|_|_| |_|\\__, |\\___|_|
                                                           |___/
[/bold cyan]
[dim cyan]         Next-Gen Async Network Crawler, Banner Recon & Topology Auditor[/dim cyan]
"""


def print_banner():
    console.print(BANNER_ART)


def get_risk_style(level: RiskLevel) -> str:
    if level == RiskLevel.CRITICAL:
        return "bold red"
    elif level == RiskLevel.HIGH:
        return "bold orange3"
    elif level == RiskLevel.MEDIUM:
        return "bold yellow"
    elif level == RiskLevel.LOW:
        return "bold green"
    return "dim white"


def display_interfaces():
    """Prints detected local network interfaces and gateways."""
    ifaces = get_active_interfaces()
    gw = get_default_gateway()

    table = Table(title="Local Network Interfaces", box=box.ROUNDED, header_style="bold magenta")
    table.add_column("Interface Name", style="cyan")
    table.add_column("IP Address", style="bold green")
    table.add_column("Subnet Mask", style="dim")
    table.add_column("Calculated CIDR", style="bold yellow")
    table.add_column("MAC Address", style="dim")

    for i in ifaces:
        table.add_row(i.name, i.ip, i.netmask, i.cidr, i.mac or "N/A")

    console.print(table)
    if gw:
        console.print(f"[bold cyan]Default Gateway:[/bold cyan] [bold green]{gw}[/bold green]\n")


def display_hosts_table(hosts: List[HostResult]):
    """Renders the discovered hosts table."""
    table = Table(title="Discovered Network Hosts", box=box.ROUNDED, header_style="bold cyan")
    table.add_column("IP Address", style="bold green", no_wrap=True)
    table.add_column("MAC Address", style="dim")
    table.add_column("Hardware Vendor", style="cyan")
    table.add_column("Hostname / Name", style="white")
    table.add_column("Type", style="magenta")
    table.add_column("Open Ports", style="yellow")
    table.add_column("Risk Score", justify="center")

    for h in hosts:
        ports_str = ", ".join(f"{p.port}/{p.service}" for p in h.open_ports[:5])
        if len(h.open_ports) > 5:
            ports_str += f" (+{len(h.open_ports) - 5} more)"
        if not ports_str:
            ports_str = "[dim]None[/dim]"

        risk_styled = f"[{get_risk_style(h.risk_level)}]{h.risk_score} ({h.risk_level.value})[/{get_risk_style(h.risk_level)}]"

        table.add_row(
            h.ip,
            h.mac_address or "N/A",
            h.vendor[:20],
            (h.hostname or h.ssdp_info.friendly_name if h.ssdp_info else "")[:25] or "[dim]-[/dim]",
            h.device_type.value,
            ports_str,
            risk_styled
        )

    console.print(table)


def display_web_services(hosts: List[HostResult]):
    """Renders discovered web services and tech stacks."""
    web_services = []
    for h in hosts:
        for w in h.web_services:
            web_services.append((h, w))

    if not web_services:
        return

    table = Table(title="Crawled Web Services & Applications", box=box.ROUNDED, header_style="bold green")
    table.add_column("Target URL", style="bold cyan")
    table.add_column("HTTP", style="dim", justify="center")
    table.add_column("Page Title", style="white")
    table.add_column("Server & Tech Stack", style="magenta")
    table.add_column("SSL Cert", style="yellow")
    table.add_column("Discovered Routes", style="dim")

    for h, w in web_services:
        tech_str = ", ".join(w.tech_stack[:4])
        if w.server and w.server not in tech_str:
            tech_str = f"{w.server}; {tech_str}" if tech_str else w.server

        ssl_str = "[dim]N/A[/dim]"
        if w.ssl_info:
            days = w.ssl_info.days_left
            if w.ssl_info.is_expired:
                ssl_str = "[bold red]EXPIRED[/bold red]"
            elif days is not None:
                ssl_str = f"[green]{days}d left[/green]"

        routes_str = f"{len(w.discovered_endpoints)} sensitive" if w.discovered_endpoints else f"{len(w.links_found)} links"

        table.add_row(
            w.url,
            str(w.status_code),
            (w.title or "[dim]No Title[/dim]")[:30],
            tech_str or "[dim]Unknown[/dim]",
            ssl_str,
            routes_str
        )

    console.print(table)


def display_security_findings(hosts: List[HostResult]):
    """Renders security audit findings table."""
    all_findings = []
    for h in hosts:
        for f in h.security_findings:
            all_findings.append((h.ip, f))

    if not all_findings:
        console.print(Panel("[bold green][+] No significant security anomalies detected.[/bold green]", title="Security Audit"))
        return

    table = Table(title="Security & Vulnerability Findings", box=box.ROUNDED, header_style="bold red")
    table.add_column("Host IP", style="bold cyan")
    table.add_column("Severity", justify="center")
    table.add_column("Finding", style="white")
    table.add_column("Remediation Guidance", style="dim")

    for ip, f in all_findings:
        sev_style = get_risk_style(f.severity)
        table.add_row(
            ip,
            f"[{sev_style}]{f.severity.value}[/{sev_style}]",
            f.title,
            f.remediation[:60] + "..." if len(f.remediation) > 60 else f.remediation
        )

    console.print(table)


async def run_cli_crawl(args) -> ScanReport:
    """Runs crawl orchestrator from CLI arguments."""
    targets = [args.target] if args.target else []
    port_profile = PortProfile(args.ports) if args.ports in [p.value for p in PortProfile] else PortProfile.STANDARD
    custom_ports = args.custom_ports or ""

    config = ScanConfig(
        targets=targets,
        port_profile=port_profile,
        custom_ports=custom_ports,
        concurrency=args.concurrency,
        crawl_web=not args.no_web,
        deep_web_crawl=args.deep,
        enable_multicast=not args.no_multicast,
        timeout=args.timeout
    )

    crawler = NetworkSlingerCrawler(config)

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.fields[stage]}:[/bold cyan] {task.description}"),
        BarColumn(),
        TextColumn("[bold yellow]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        transient=True
    ) as progress:
        task_id = progress.add_task("Initializing...", total=100, stage="Init")

        def on_progress(p):
            progress.update(
                task_id,
                completed=p.percent,
                stage=p.stage,
                description=p.message[:50]
            )

        crawler.register_progress_callback(on_progress)
        report = await crawler.execute_crawl()

    # Display Tables
    console.print(f"\n[bold green][+] Scrawl Finished in {report.duration_seconds}s[/bold green]")
    display_hosts_table(report.hosts)
    display_web_services(report.hosts)
    display_security_findings(report.hosts)

    # Export Report if requested
    if args.output:
        save_report(report, args.output, args.format)

    return report


def save_report(report: ScanReport, output_path: str, fmt: str = "json"):
    """Saves scan report to disk in JSON, HTML or CSV."""
    if fmt == "html" or output_path.endswith(".html"):
        from .web.reporter import generate_html_report
        html_content = generate_html_report(report)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        console.print(f"[bold green]Report saved to standalone HTML:[/bold green] {output_path}")
    elif fmt == "csv" or output_path.endswith(".csv"):
        import csv
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["IP", "MAC", "Vendor", "Hostname", "Device Type", "Open Ports", "Risk Score", "Risk Level"])
            for h in report.hosts:
                ports = ";".join(str(p.port) for p in h.open_ports)
                writer.writerow([h.ip, h.mac_address or "", h.vendor, h.hostname, h.device_type.value, ports, h.risk_score, h.risk_level.value])
        console.print(f"[bold green]Report saved to CSV:[/bold green] {output_path}")
    else:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report.model_dump_json(indent=2))
        console.print(f"[bold green]Report saved to JSON:[/bold green] {output_path}")


def main():
    parser = argparse.ArgumentParser(
        prog="networkslinger",
        description="Network Slinger - Advanced Network Crawler, Reconnaissance & Topology Auditor"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Command: crawl / scan
    scan_p = subparsers.add_parser("crawl", aliases=["scan"], help="Crawl and scan network targets")
    scan_p.add_argument("-t", "--target", type=str, help="Target CIDR, IP or range (e.g. 192.168.1.0/24). If omitted, auto-detects local LAN.")
    scan_p.add_argument("-p", "--ports", choices=["fast", "standard", "extended", "custom"], default="standard", help="Port scanning profile")
    scan_p.add_argument("--custom-ports", type=str, default="", help="Custom ports (e.g. '80,443,8000-8080')")
    scan_p.add_argument("-c", "--concurrency", type=int, default=150, help="Max concurrent connections (default 150)")
    scan_p.add_argument("--timeout", type=float, default=1.0, help="Connection timeout in seconds")
    scan_p.add_argument("--no-web", action="store_true", help="Skip HTTP/HTTPS web crawling")
    scan_p.add_argument("--deep", action="store_true", help="Enable deep web path probes (/.env, /.git, /admin)")
    scan_p.add_argument("--no-multicast", action="store_true", help="Disable SSDP multicast discovery")
    scan_p.add_argument("-o", "--output", type=str, help="Save report to file path")
    scan_p.add_argument("--format", choices=["json", "csv", "html"], default="json", help="Report export format")

    # Command: discover
    subparsers.add_parser("discover", help="Quick host discovery on local subnet")

    # Command: app / gui (Native Desktop App)
    app_p = subparsers.add_parser("app", aliases=["gui"], help="Launch single-instance native desktop GUI window")
    app_p.add_argument("--host", type=str, default="127.0.0.1", help="Host (default 127.0.0.1)")
    app_p.add_argument("--port", type=int, default=8000, help="Port (default 8000)")
    app_p.add_argument("--browser", action="store_true", help="Launch in default browser instead of native window")

    # Command: web
    web_p = subparsers.add_parser("web", help="Launch the Web Dashboard (single-instance)")
    web_p.add_argument("--host", type=str, default="127.0.0.1", help="Web console host (default 127.0.0.1)")
    web_p.add_argument("--port", type=int, default=8000, help="Web console port (default 8000)")
    web_p.add_argument("--native", action="store_true", help="Launch in native desktop window")
    web_p.add_argument("--server-only", action="store_true", help="Run Uvicorn server in foreground without browser/window")

    # Command: ifaces
    subparsers.add_parser("ifaces", help="List detected network interfaces and gateway")

    args = parser.parse_args()

    print_banner()

    if args.command in ("crawl", "scan"):
        asyncio.run(run_cli_crawl(args))
    elif args.command == "discover":
        args.ports = "fast"
        args.custom_ports = ""
        args.target = None
        args.concurrency = 150
        args.timeout = 0.8
        args.no_web = True
        args.deep = False
        args.no_multicast = False
        args.output = None
        args.format = "json"
        asyncio.run(run_cli_crawl(args))
    elif args.command == "ifaces":
        display_interfaces()
    elif args.command in ("app", "gui"):
        from .single_instance import run_one_time_instance
        run_one_time_instance(host=args.host, port=args.port, native_window=not args.browser)
    elif args.command == "web":
        if getattr(args, "server_only", False):
            from .web.server import launch_web_server
            launch_web_server(host=args.host, port=args.port)
        else:
            from .single_instance import run_one_time_instance
            run_one_time_instance(host=args.host, port=args.port, native_window=args.native)
    else:
        # Default: launch the single-instance local desktop application
        console.print("[bold green][+] Launching Network Slinger Local Desktop Application...[/bold green]")
        from .single_instance import run_one_time_instance
        run_one_time_instance(host="127.0.0.1", port=8000, native_window=True)


if __name__ == "__main__":
    main()
