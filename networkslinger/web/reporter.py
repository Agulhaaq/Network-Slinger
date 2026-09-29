"""
HTML and JSON report generator for Network Slinger.
Produces standalone, self-contained interactive HTML audit reports.
"""

from datetime import datetime
import json
from ..models import ScanReport


def generate_html_report(report: ScanReport) -> str:
    """Generates a standalone, beautiful HTML report containing all scan findings and data."""
    hosts_json = report.model_dump_json(indent=2)
    started_str = report.started_at.strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Slinger Audit Report - {report.scan_id}</title>
    <style>
        :root {{
            --bg-primary: #0a0e17;
            --bg-secondary: #121826;
            --bg-card: #182234;
            --accent-cyan: #00f0ff;
            --accent-green: #00ff88;
            --accent-yellow: #ffcc00;
            --accent-orange: #ff7700;
            --accent-red: #ff3366;
            --text-main: #e2e8f0;
            --text-dim: #94a3b8;
            --border-color: #24324a;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background: var(--bg-primary);
            color: var(--text-main);
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            padding: 30px 20px;
            line-height: 1.5;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 25px 30px;
            margin-bottom: 25px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 8px 24px rgba(0,0,0,0.4);
        }}
        .logo-area h1 {{
            font-size: 26px;
            color: var(--accent-cyan);
            letter-spacing: 1px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .logo-area p {{ color: var(--text-dim); font-size: 14px; margin-top: 4px; }}
        .badge {{
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .badge-critical {{ background: rgba(255,51,102,0.2); color: var(--accent-red); border: 1px solid var(--accent-red); }}
        .badge-high {{ background: rgba(255,119,0,0.2); color: var(--accent-orange); border: 1px solid var(--accent-orange); }}
        .badge-medium {{ background: rgba(255,204,0,0.2); color: var(--accent-yellow); border: 1px solid var(--accent-yellow); }}
        .badge-low {{ background: rgba(0,255,136,0.2); color: var(--accent-green); border: 1px solid var(--accent-green); }}
        .badge-info {{ background: rgba(0,240,255,0.2); color: var(--accent-cyan); border: 1px solid var(--accent-cyan); }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }}
        .stat-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 20px;
            text-align: center;
        }}
        .stat-card .val {{ font-size: 32px; font-weight: 800; color: var(--accent-cyan); }}
        .stat-card .lbl {{ font-size: 13px; color: var(--text-dim); text-transform: uppercase; margin-top: 5px; }}

        .section {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 25px;
        }}
        .section h2 {{ font-size: 20px; margin-bottom: 18px; color: #fff; border-bottom: 1px solid var(--border-color); padding-bottom: 10px; }}

        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid var(--border-color); }}
        th {{ background: var(--bg-card); color: var(--accent-cyan); font-size: 13px; font-weight: 600; text-transform: uppercase; }}
        td {{ font-size: 14px; }}
        tr:hover {{ background: rgba(255,255,255,0.02); }}

        .port-pill {{
            display: inline-block;
            background: rgba(0,240,255,0.1);
            color: var(--accent-cyan);
            border: 1px solid rgba(0,240,255,0.3);
            border-radius: 6px;
            padding: 2px 8px;
            font-size: 12px;
            margin: 2px;
        }}
        .tech-pill {{
            display: inline-block;
            background: rgba(255,204,0,0.1);
            color: var(--accent-yellow);
            border-radius: 6px;
            padding: 2px 8px;
            font-size: 12px;
            margin: 2px;
        }}
        pre {{
            background: #000;
            padding: 15px;
            border-radius: 8px;
            overflow-x: auto;
            color: #00ff88;
            font-family: monospace;
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo-area">
                <h1>⚡ NETWORK SLINGER</h1>
                <p>Scan ID: {report.scan_id} &bull; Started: {started_str} &bull; Duration: {report.duration_seconds}s</p>
            </div>
            <div>
                <span class="badge badge-info">Targets: {", ".join(report.config.targets)}</span>
            </div>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="val">{report.summary.live_hosts_found}</div>
                <div class="lbl">Live Hosts Found</div>
            </div>
            <div class="stat-card">
                <div class="val" style="color: var(--accent-green);">{report.summary.total_open_ports}</div>
                <div class="lbl">Open Ports</div>
            </div>
            <div class="stat-card">
                <div class="val" style="color: var(--accent-yellow);">{report.summary.total_web_services}</div>
                <div class="lbl">Web Services</div>
            </div>
            <div class="stat-card">
                <div class="val" style="color: var(--accent-red);">{report.summary.critical_risks + report.summary.high_risks}</div>
                <div class="lbl">High / Critical Risks</div>
            </div>
        </div>

        <div class="section">
            <h2>Discovered Hosts & Hardware Inventory</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>MAC / Vendor</th>
                        <th>Device Name</th>
                        <th>Classification</th>
                        <th>Open Ports</th>
                        <th>Risk Score</th>
                    </tr>
                </thead>
                <tbody>
    """

    for h in report.hosts:
        ports_html = "".join(f'<span class="port-pill">{p.port}/{p.service}</span>' for p in h.open_ports) or "<span style='color: #64748b;'>None</span>"
        risk_cls = "badge-info"
        if h.risk_level.value == "CRITICAL":
            risk_cls = "badge-critical"
        elif h.risk_level.value == "HIGH":
            risk_cls = "badge-high"
        elif h.risk_level.value == "MEDIUM":
            risk_cls = "badge-medium"
        elif h.risk_level.value == "LOW":
            risk_cls = "badge-low"

        html += f"""
                    <tr>
                        <td><strong>{h.ip}</strong></td>
                        <td>{h.mac_address or 'N/A'}<br><small style="color: var(--accent-cyan);">{h.vendor}</small></td>
                        <td>{h.hostname or (h.ssdp_info.friendly_name if h.ssdp_info else 'N/A')}</td>
                        <td>{h.device_type.value}</td>
                        <td>{ports_html}</td>
                        <td><span class="badge {risk_cls}">{h.risk_score} ({h.risk_level.value})</span></td>
                    </tr>
        """

    html += """
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>Crawled Web Services & Technologies</h2>
            <table>
                <thead>
                    <tr>
                        <th>URL</th>
                        <th>Status</th>
                        <th>Title</th>
                        <th>Server / Technologies</th>
                        <th>SSL Certificate</th>
                    </tr>
                </thead>
                <tbody>
    """

    web_count = 0
    for h in report.hosts:
        for w in h.web_services:
            web_count += 1
            tech_html = "".join(f'<span class="tech-pill">{t}</span>' for t in w.tech_stack)
            if w.server:
                tech_html = f"<code>{w.server}</code> " + tech_html

            ssl_html = "N/A"
            if w.ssl_info:
                if w.ssl_info.is_expired:
                    ssl_html = "<span class='badge badge-critical'>EXPIRED</span>"
                elif w.ssl_info.days_left is not None:
                    ssl_html = f"<span class='badge badge-low'>{w.ssl_info.days_left}d left</span>"

            html += f"""
                    <tr>
                        <td><a href="{w.url}" target="_blank" style="color: var(--accent-cyan); text-decoration: none;">{w.url}</a></td>
                        <td><span class="badge badge-info">{w.status_code}</span></td>
                        <td>{w.title or '<span style="color: #64748b;">No Title</span>'}</td>
                        <td>{tech_html or '<span style="color: #64748b;">Unknown</span>'}</td>
                        <td>{ssl_html}</td>
                    </tr>
            """

    if web_count == 0:
        html += "<tr><td colspan='5' style='text-align:center; color: #64748b;'>No web applications discovered during this scan.</td></tr>"

    html += """
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>Security & Risk Audit Findings</h2>
            <table>
                <thead>
                    <tr>
                        <th>Host IP</th>
                        <th>Severity</th>
                        <th>Vulnerability / Finding</th>
                        <th>Remediation Advice</th>
                    </tr>
                </thead>
                <tbody>
    """

    finding_count = 0
    for h in report.hosts:
        for f in h.security_findings:
            finding_count += 1
            sev_cls = "badge-info"
            if f.severity.value == "CRITICAL":
                sev_cls = "badge-critical"
            elif f.severity.value == "HIGH":
                sev_cls = "badge-high"
            elif f.severity.value == "MEDIUM":
                sev_cls = "badge-medium"
            elif f.severity.value == "LOW":
                sev_cls = "badge-low"

            html += f"""
                    <tr>
                        <td><strong>{h.ip}</strong></td>
                        <td><span class="badge {sev_cls}">{f.severity.value}</span></td>
                        <td><strong>{f.title}</strong><br><small style="color: var(--text-dim);">{f.description}</small></td>
                        <td style="color: var(--accent-green);">{f.remediation}</td>
                    </tr>
            """

    if finding_count == 0:
        html += "<tr><td colspan='4' style='text-align:center; color: var(--accent-green);'>✓ No security risks or anomalies identified.</td></tr>"

    html += f"""
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>Raw Scan JSON Data</h2>
            <pre><code>{hosts_json}</code></pre>
        </div>
    </div>
</body>
</html>
    """
    return html
