"""
High-Contrast Monochrome HTML and JSON report generator for Network Slinger.
Produces standalone, self-contained interactive HTML audit reports.
"""

from datetime import datetime
import json
from ..models import ScanReport


def generate_html_report(report: ScanReport) -> str:
    """Generates a standalone, high-contrast monochrome HTML report."""
    hosts_json = report.model_dump_json(indent=2)
    started_str = report.started_at.strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NETWORK SLINGER -- AUDIT REPORT {report.scan_id}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800;900&family=JetBrains+Mono:wght@500;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg: #000000;
            --surface: #0e0e0e;
            --card-light: #ffffff;
            --card-light-text: #000000;
            --border: #222222;
            --text-high: #ffffff;
            --text-muted: #777777;
            --font-sans: 'Plus Jakarta Sans', -apple-system, sans-serif;
            --font-mono: 'JetBrains Mono', monospace;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background: var(--bg);
            color: var(--text-high);
            font-family: var(--font-sans);
            padding: 40px 24px;
            line-height: 1.5;
            -webkit-font-smoothing: antialiased;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        
        header {{
            border-bottom: 1px solid var(--border);
            padding-bottom: 24px;
            margin-bottom: 32px;
            display: flex;
            justify-content: space-between;
            align-items: baseline;
            flex-wrap: wrap;
            gap: 16px;
        }}
        .logo-area h1 {{
            font-size: 22px;
            font-weight: 900;
            letter-spacing: 1.5px;
            text-transform: uppercase;
        }}
        .logo-area p {{
            color: var(--text-muted);
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 1px;
            text-transform: uppercase;
            margin-top: 4px;
        }}
        .target-pill {{
            background: #ffffff;
            color: #000000;
            font-family: var(--font-mono);
            font-size: 11px;
            font-weight: 800;
            padding: 6px 16px;
            border-radius: 40px;
            text-transform: uppercase;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 36px;
        }}
        .stat-card {{
            background: #111111;
            border: 1px solid var(--border);
            border-radius: 20px;
            padding: 24px;
        }}
        .stat-card .val {{
            font-family: var(--font-mono);
            font-size: 38px;
            font-weight: 800;
            color: #ffffff;
            line-height: 1;
        }}
        .stat-card .lbl {{
            font-size: 11px;
            font-weight: 800;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 8px;
        }}

        .section-header {{
            font-size: 14px;
            font-weight: 900;
            letter-spacing: 1.5px;
            text-transform: uppercase;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .section-header::after {{
            content: "";
            flex: 1;
            height: 1px;
            background: var(--border);
        }}

        .device-card {{
            background: #ffffff;
            color: #000000;
            border-radius: 20px;
            padding: 22px 26px;
            margin-bottom: 14px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .device-ip {{
            font-family: var(--font-mono);
            font-size: 16px;
            font-weight: 800;
        }}
        .device-meta {{
            font-size: 12px;
            color: #555555;
            font-weight: 600;
            margin-top: 2px;
        }}
        .ports-wrap {{
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
            margin-top: 8px;
        }}
        .chip {{
            background: #000000;
            color: #ffffff;
            font-family: var(--font-mono);
            font-size: 10px;
            font-weight: 700;
            padding: 3px 8px;
            border-radius: 6px;
        }}
        .chip-outline {{
            background: transparent;
            color: #000000;
            border: 1px solid #000000;
            font-size: 10px;
            font-weight: 800;
            padding: 2px 7px;
            border-radius: 20px;
            text-transform: uppercase;
        }}

        pre {{
            background: #090909;
            border: 1px solid var(--border);
            padding: 20px;
            border-radius: 16px;
            overflow-x: auto;
            color: #aaaaaa;
            font-family: var(--font-mono);
            font-size: 11px;
            line-height: 1.6;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo-area">
                <h1>NETWORK SLINGER -- AUDIT REPORT</h1>
                <p>SCAN ID: {report.scan_id} &bull; TIMESTAMP: {started_str} &bull; DURATION: {report.duration_seconds}S</p>
            </div>
            <div>
                <span class="target-pill">TARGET: {", ".join(report.config.targets)}</span>
            </div>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="val">{report.summary.live_hosts_found}</div>
                <div class="lbl">DISCOVERED TARGETS</div>
            </div>
            <div class="stat-card">
                <div class="val">{report.summary.total_open_ports}</div>
                <div class="lbl">ACTIVE PORTS</div>
            </div>
            <div class="stat-card">
                <div class="val">{report.summary.total_web_services}</div>
                <div class="lbl">WEB APPLICATIONS</div>
            </div>
            <div class="stat-card">
                <div class="val">{report.summary.critical_risks + report.summary.high_risks}</div>
                <div class="lbl">SECURITY ALERTS</div>
            </div>
        </div>

        <div class="section-header">DISCOVERED ASSETS --</div>
        <div style="margin-bottom: 36px;">
    """

    for h in report.hosts:
        ports_html = "".join(f'<span class="chip">{p.port}/{p.service}</span>' for p in h.open_ports) or "<span style='color: #888;'>NO OPEN PORTS</span>"
        html += f"""
            <div class="device-card">
                <div>
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <span class="device-ip">{h.ip}</span>
                        <span class="chip-outline">{h.device_type.value}</span>
                    </div>
                    <div class="device-meta">{h.vendor} &bull; {h.hostname or (h.ssdp_info.friendly_name if h.ssdp_info else 'UNNAMED HOST')} &bull; MAC: {h.mac_address or 'N/A'}</div>
                    <div class="ports-wrap">{ports_html}</div>
                </div>
                <div style="text-align: right;">
                    <div style="font-family: var(--font-mono); font-size: 15px; font-weight: 800;">{h.latency_ms} MS</div>
                    <div style="font-size: 11px; font-weight: 800; color: #555; text-transform: uppercase; margin-top: 4px;">RISK SCORE: {h.risk_score}</div>
                </div>
            </div>
        """

    html += """
        </div>
        <div class="section-header">WEB SERVICES & APPS --</div>
        <div style="margin-bottom: 36px;">
    """

    web_count = 0
    for h in report.hosts:
        for w in h.web_services:
            web_count += 1
            tech_html = "".join(f'<span class="chip">{t}</span>' for t in w.tech_stack)
            html += f"""
                <div class="device-card">
                    <div>
                        <div style="display: flex; align-items: center; gap: 10px;">
                            <span class="device-ip">{w.url}</span>
                            <span class="chip-outline">HTTP {w.status_code}</span>
                        </div>
                        <div class="device-meta">{w.title or 'UNTITLED APPLICATION'} &bull; SERVER: {w.server or 'UNKNOWN'}</div>
                        <div class="ports-wrap">{tech_html}</div>
                    </div>
                    <div style="text-align: right;">
                        <div style="font-size: 11px; font-weight: 800; text-transform: uppercase;">SSL: {'EXPIRED' if w.ssl_info and w.ssl_info.is_expired else ('VALID' if w.ssl_info else 'N/A')}</div>
                    </div>
                </div>
            """

    if web_count == 0:
        html += "<div style='color: #666; font-size: 12px; padding: 20px 0;'>NO WEB SERVICES IDENTIFIED.</div>"

    html += """
        </div>
        <div class="section-header">SECURITY ANOMALIES & AUDIT --</div>
        <div style="margin-bottom: 36px;">
    """

    finding_count = 0
    for h in report.hosts:
        for f in h.security_findings:
            finding_count += 1
            html += f"""
                <div class="device-card" style="border-left: 8px solid #000000;">
                    <div>
                        <div style="display: flex; align-items: center; gap: 10px;">
                            <span class="device-ip">{h.ip}</span>
                            <span class="chip-outline">{f.severity.value}</span>
                        </div>
                        <div style="font-size: 13px; font-weight: 800; margin-top: 4px;">{f.title}</div>
                        <div style="font-size: 12px; color: #555555; margin-top: 4px;">{f.description}</div>
                        <div style="font-size: 12px; font-weight: 700; margin-top: 6px; color: #000000;">REMEDIATION: {f.remediation}</div>
                    </div>
                </div>
            """

    if finding_count == 0:
        html += "<div style='color: #666; font-size: 12px; padding: 20px 0;'>NO VULNERABILITIES RECORDED. ALL TARGETS COMPLIANT.</div>"

    html += f"""
        </div>
        <div class="section-header">RAW AUDIT TELEMETRY --</div>
        <pre>{hosts_json}</pre>
    </div>
</body>
</html>
    """
    return html
