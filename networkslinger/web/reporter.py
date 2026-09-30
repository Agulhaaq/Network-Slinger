"""
Standalone HTML audit report generator for Network Slinger.
Produces clean, professional monochrome reports. 100% offline — zero external dependencies.
"""

from datetime import datetime
import json
from ..models import ScanReport, RiskLevel


def generate_html_report(report: ScanReport) -> str:
    """Generates a standalone, offline-safe professional HTML audit report."""
    started_str = report.started_at.strftime("%Y-%m-%d %H:%M:%S")
    targets_str = ", ".join(report.config.targets) if report.config.targets else "Auto-detected LAN"
    total_alerts = (report.summary.critical_risks or 0) + (report.summary.high_risks or 0)

    # Build host rows
    host_rows = ""
    for h in report.hosts:
        port_chips = "".join(
            f'<span style="font-family:monospace;font-size:10px;padding:2px 6px;background:#1a1a1a;border:1px solid #2d2d2d;border-radius:4px;color:#aaa;margin-right:3px;">{p.port}/{p.service}</span>'
            for p in h.open_ports[:8]
        )
        if len(h.open_ports) > 8:
            port_chips += f'<span style="font-size:10px;color:#555;">+{len(h.open_ports)-8}</span>'
        mac = h.mac_address or "—"
        host_rows += f"""
        <tr>
            <td style="font-family:monospace;font-size:13px;font-weight:700;color:#f0f0f0;">{h.ip}</td>
            <td style="font-size:11px;color:#888;">{h.hostname or "—"}</td>
            <td>
                <div style="font-size:11px;color:#999;">{h.vendor or "Unknown"}</div>
                <div style="font-family:monospace;font-size:10px;color:#555;">{mac}</div>
            </td>
            <td><span style="font-size:9px;font-weight:800;letter-spacing:1px;text-transform:uppercase;border:1px solid #333;border-radius:4px;padding:2px 7px;color:#888;">{h.device_type.value if hasattr(h.device_type,'value') else h.device_type}</span></td>
            <td>{port_chips or '<span style="color:#444;font-size:11px;">None</span>'}</td>
            <td style="font-family:monospace;font-size:11px;color:#aaa;">{f"{h.latency_ms:.1f}ms" if h.latency_ms else "—"}</td>
            <td style="font-size:10px;font-weight:800;letter-spacing:1px;text-transform:uppercase;color:#777;">{h.risk_level.value if hasattr(h.risk_level,'value') else h.risk_level}</td>
        </tr>"""

    # Build findings rows
    findings_html = ""
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_findings = []
    for h in report.hosts:
        for f in h.security_findings:
            all_findings.append((h, f))
    all_findings.sort(key=lambda x: sev_order.get(x[1].severity.value if hasattr(x[1].severity, "value") else x[1].severity, 4))

    for h, f in all_findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        hi = sev in ("CRITICAL", "HIGH")
        findings_html += f"""
        <div style="background:#111;border:1px solid #222;border-radius:10px;padding:16px 20px;margin-bottom:10px;display:grid;grid-template-columns:auto 1fr auto;gap:16px;align-items:start;">
            <span style="font-size:9px;font-weight:800;letter-spacing:1.5px;text-transform:uppercase;border:1px solid {'#666' if hi else '#333'};border-radius:4px;padding:3px 9px;color:{'#f0f0f0' if hi else '#777'};white-space:nowrap;margin-top:2px;">{sev}</span>
            <div>
                <div style="font-size:13px;font-weight:700;color:#f0f0f0;">{f.title}</div>
                <div style="font-size:11px;color:#666;margin-top:5px;line-height:1.5;">{f.description}</div>
                {f'<div style="font-size:11px;font-weight:700;color:#555;margin-top:8px;">{f.remediation}</div>' if f.remediation else ""}
            </div>
            <div style="font-family:monospace;font-size:11px;color:#555;white-space:nowrap;">{h.ip}{f":{f.port}" if f.port else ""}</div>
        </div>"""

    # Web services
    web_html = ""
    for h in report.hosts:
        for w in h.web_services:
            techs = "".join(f'<span style="font-family:monospace;font-size:10px;padding:2px 6px;background:#1a1a1a;border:1px solid #2d2d2d;border-radius:4px;color:#888;margin-right:3px;">{t}</span>' for t in (w.tech_stack or []))
            ssl_str = "—"
            if w.ssl_info:
                ssl_str = f"Expired ({w.ssl_info.days_left}d)" if w.ssl_info.is_expired else f"Valid ({w.ssl_info.days_left or '?'}d left)"
            elif w.is_https:
                ssl_str = "Present"
            web_html += f"""
            <div style="background:#111;border:1px solid #222;border-radius:10px;padding:16px 20px;margin-bottom:10px;">
                <div style="font-family:monospace;font-size:13px;font-weight:700;color:#f0f0f0;">{w.url}</div>
                <div style="font-size:11px;color:#666;margin-top:5px;">{w.title or "No title"} &bull; {w.server or "Unknown server"} &bull; HTTP {w.status_code}</div>
                {f'<div style="margin-top:10px;">{techs}</div>' if techs else ""}
                <div style="font-size:10px;font-weight:700;color:#555;margin-top:8px;letter-spacing:0.5px;text-transform:uppercase;">SSL: {ssl_str}</div>
            </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Slinger — Audit Report {report.scan_id}</title>
    <!-- 100% Offline Report — Zero External Dependencies -->
    <style>
        *, *::before, *::after {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background: #080808;
            color: #f0f0f0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Helvetica Neue", Arial, sans-serif;
            font-size: 13px;
            line-height: 1.45;
            padding: 40px 32px;
            -webkit-font-smoothing: antialiased;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h2 {{
            font-size: 10px;
            font-weight: 800;
            letter-spacing: 2px;
            text-transform: uppercase;
            color: #555;
            margin: 40px 0 16px;
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        h2::after {{ content: ""; flex: 1; height: 1px; background: #1e1e1e; }}
        table {{ width: 100%; border-collapse: collapse; }}
        thead th {{
            padding: 10px 14px;
            text-align: left;
            font-size: 9px;
            font-weight: 800;
            letter-spacing: 1.5px;
            text-transform: uppercase;
            color: #444;
            border-bottom: 1px solid #1e1e1e;
            background: #0e0e0e;
        }}
        tbody tr {{ border-bottom: 1px solid #151515; }}
        tbody tr:hover {{ background: #0e0e0e; }}
        tbody td {{ padding: 13px 14px; vertical-align: middle; }}
        ::-webkit-scrollbar {{ width: 5px; }} 
        ::-webkit-scrollbar-thumb {{ background: #333; border-radius:3px; }}
    </style>
</head>
<body>
<div class="container">

    <!-- Header -->
    <div style="border-bottom: 1px solid #1e1e1e; padding-bottom: 28px; margin-bottom: 32px; display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:16px;">
        <div>
            <div style="font-size:14px;font-weight:900;letter-spacing:2px;text-transform:uppercase;color:#f0f0f0;">Network Slinger</div>
            <div style="font-size:11px;color:#555;margin-top:6px;letter-spacing:0.5px;">Audit Report &bull; Scan ID: {report.scan_id} &bull; {started_str} &bull; {report.duration_seconds}s</div>
        </div>
        <span style="background:#fff;color:#000;font-family:monospace;font-size:10px;font-weight:800;padding:6px 16px;border-radius:6px;text-transform:uppercase;">{targets_str}</span>
    </div>

    <!-- Summary stats -->
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:40px;">
        <div style="background:#111;border:1px solid #1e1e1e;border-radius:10px;padding:20px;">
            <div style="font-family:monospace;font-size:36px;font-weight:700;color:#f0f0f0;line-height:1;">{report.summary.live_hosts_found}</div>
            <div style="font-size:9px;font-weight:800;letter-spacing:2px;text-transform:uppercase;color:#555;margin-top:8px;">Live Targets</div>
        </div>
        <div style="background:#111;border:1px solid #1e1e1e;border-radius:10px;padding:20px;">
            <div style="font-family:monospace;font-size:36px;font-weight:700;color:#f0f0f0;line-height:1;">{report.summary.total_open_ports}</div>
            <div style="font-size:9px;font-weight:800;letter-spacing:2px;text-transform:uppercase;color:#555;margin-top:8px;">Open Ports</div>
        </div>
        <div style="background:#111;border:1px solid #1e1e1e;border-radius:10px;padding:20px;">
            <div style="font-family:monospace;font-size:36px;font-weight:700;color:#f0f0f0;line-height:1;">{report.summary.total_web_services}</div>
            <div style="font-size:9px;font-weight:800;letter-spacing:2px;text-transform:uppercase;color:#555;margin-top:8px;">Web Services</div>
        </div>
        <div style="background:#111;border:1px solid #1e1e1e;border-radius:10px;padding:20px;">
            <div style="font-family:monospace;font-size:36px;font-weight:700;color:#f0f0f0;line-height:1;">{total_alerts}</div>
            <div style="font-size:9px;font-weight:800;letter-spacing:2px;text-transform:uppercase;color:#555;margin-top:8px;">Risk Alerts</div>
        </div>
    </div>

    <!-- Discovered Assets -->
    <h2>Discovered Assets</h2>
    <div style="overflow-x:auto;">
    <table>
        <thead>
            <tr>
                <th>IP Address</th>
                <th>Hostname</th>
                <th>Vendor / MAC</th>
                <th>Type</th>
                <th>Open Ports</th>
                <th>RTT</th>
                <th>Risk</th>
            </tr>
        </thead>
        <tbody>
            {host_rows or '<tr><td colspan="7" style="text-align:center;padding:30px;color:#444;">No hosts discovered.</td></tr>'}
        </tbody>
    </table>
    </div>

    <!-- Web Services -->
    <h2>Web Services &amp; Applications</h2>
    {web_html or '<div style="color:#444;font-size:12px;padding:16px 0;">No web services identified.</div>'}

    <!-- Security Audit -->
    <h2>Security Audit Findings</h2>
    {findings_html or '<div style="color:#444;font-size:12px;padding:16px 0;">No vulnerabilities recorded. All targets compliant.</div>'}

    <!-- Raw JSON -->
    <h2>Raw Telemetry</h2>
    <pre style="background:#050505;border:1px solid #1a1a1a;border-radius:10px;padding:20px;overflow-x:auto;font-family:monospace;font-size:10px;color:#555;line-height:1.65;">{json.dumps(json.loads(report.model_dump_json()), indent=2)}</pre>

    <div style="margin-top:40px;padding-top:20px;border-top:1px solid #1a1a1a;font-size:10px;color:#333;letter-spacing:1px;text-transform:uppercase;">
        Network Slinger &bull; Local Reconnaissance Engine &bull; {started_str}
    </div>

</div>
</body>
</html>"""
    return html
