# ⚡ Network Slinger (Network Scrawler)
> **High-Performance Asynchronous Network Crawler, Deep Service Reconnaissance, Banner Grabbing & Interactive Topology Auditor.**

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Modern%20Async-009688.svg)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 🧭 Overview

**Network Slinger** is a next-generation network reconnaissance and crawling engine engineered for cybersecurity engineers, devops teams, and system administrators. It combines zero-dependency hardware-level host discovery, asynchronous multi-port scanning, deep protocol banner grabbing, headless HTTP/HTTPS web application scrawling, SSDP/UPnP multicast reconnaissance, and automated vulnerability heuristic auditing.

It features both a **Rich Terminal CLI** with live streaming progress bars and formatted tables, and a **Real-Time Interactive Cyber Web Console** with force-directed network topology mapping powered by WebSockets.

---

## 🌟 Key Features

### 1. ⚡ High-Speed Host Discovery Engine
- **Windows Hardware ARP Acceleration**: Uses Windows Native `SendARP` API via `ctypes` for instantaneous (<1ms) physical host alive resolution with zero raw-packet drivers needed.
- **Cross-Platform Fallback**: System ARP table caching (`/proc/net/arp` and `arp -a`) + multi-port async TCP Connect ping.
- **Embedded OUI Database**: Offline database mapping MAC address prefixes to over 200 hardware manufacturers (Apple, Cisco, TP-Link, Intel, Espressif, Raspberry Pi, Ubiquiti, Samsung, etc.).
- **Automatic Subnet & Gateway Detection**: Reads active IPv4 network interfaces and calculates the exact CIDR range (e.g. `192.168.1.0/24`) and default gateway without manual configuration.

### 2. 🔌 Asynchronous Port Scanner & Banner Prober
- **Preset Scanning Profiles**:
  - `fast`: Top 25 critical ports
  - `standard`: Top 100 most common services
  - `extended`: Top 1,000 ports
  - `custom`: e.g. `80,443,8000-8080,3000`
- **Protocol Banner Grabbers**:
  - **SSH**: Captures OpenSSH/Dropbear server banners and OS fingerprints.
  - **FTP**: Grabs 220 greetings and automatically performs anonymous login audit.
  - **SMTP**: Grabs mail transfer agent greetings.
  - **Redis**: Actively probes for unauthenticated database instances (`PING` / `INFO`).
  - **MySQL / MariaDB**: Handshake packet parser extracting server version and auth plugins.
  - **Docker / RTSP / Databases**: Identifies exposed daemons and camera streams.

### 3. 🌐 Headless HTTP/HTTPS Web Application Scrawler
- **Technology Stack Identification**: Detects web servers (Nginx, Apache, IIS, Caddy, Lighttpd), backends (PHP, Express, Django, ASP.NET), CMS/management panels (WordPress, OpenWrt/LuCI, Pi-hole, Synology DSM, Proxmox VE, Grafana, MikroTik), and frontend frameworks (React, Vue, Bootstrap, Tailwind).
- **SSL/TLS Certificate Inspection**: Parses Subject, Issuer, Validity window, Days left until expiration, Self-signed certificates, and Subject Alternative Names (SANs).
- **Sensitive Path Prober**: Scrawls for exposed `.env` files, `.git` metadata, administration gateways (`/admin`, `/wp-login.php`, `/phpmyadmin`), and API documentation (`/swagger`, `/docs`).
- **HTTP Security Header Audit**: Flags missing HSTS, CSP, X-Frame-Options (Clickjacking), and MIME protection headers.

### 4. 📡 Multicast & Ambient Discovery
- **SSDP / UPnP Multicast Crawler**: Transmits `M-SEARCH` multicast queries to `239.255.255.250:1900`, captures responses from smart TVs, media centers, routers, and IoT hubs, and parses their XML device descriptors (Friendly Name, Manufacturer, Model).

### 5. 🛡️ Automated Vulnerability & Risk Scoring
- Calculates a weighted **Risk Score (0–100)** and risk severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) for every host with actionable remediation guidance:
  - **Critical**: Unauthenticated Redis/MongoDB, unencrypted Docker daemon API on port 2375, exposed `.env` or `.git` directories.
  - **High**: Cleartext Telnet on port 23, anonymous FTP write access, expired SSL certificates.
  - **Medium**: Self-signed SSL certificates, exposed admin panels, unencrypted databases on public interfaces.
  - **Low**: Missing HSTS or Clickjacking headers, SSL certificates expiring soon.

### 6. 100% Fully Local & Offline Operation
- **Zero External Dependencies / No CDNs**: All scripts, styling, and graphing libraries (`vis-network.min.js`) are locally vendored within the application package. Zero requests to external CDNs or Google Fonts.
- **Embedded Offline Hardware Vendor Database**: Resolves MAC prefixes completely offline using local IEEE definitions.
- **Self-Contained Offline Export Reports**: Exported HTML audit reports render completely offline without contacting external networks.

### 7. Single-Instance Architecture & Native Desktop Window
- **One-Time Instance Guarantee**: Enforced via Windows Named Mutex (`Global\NetworkSlinger_SingleInstance_App`) and cross-platform PID lockfiles.
- **Automated Duplicate Prevention**: Launching a second time automatically brings the active window to the foreground or opens the active browser tab without port collisions or crashes.
- **Native Desktop GUI**: Run as a native standalone window via `pywebview` (`python run.py app` or double-clicking `NetworkSlinger.bat`).
- **High-Contrast Neo-Minimalist Dashboard**: Monochrome high-contrast design (black, white, quiet charcoal) inspired by Eline Ye with radial latency tick dials and physical pill switches.

---

## 🚀 Quick Start & Installation

### 1. Windows Application Installation (Full Setup)

Network Slinger compiles and installs as a standalone native Windows desktop application with Windows Start Menu integration and Programs registration.

**Option A: Double-Click Setup**
Double-click:
```powershell
Setup.bat
```

**Option B: PowerShell Installer**
```powershell
powershell -ExecutionPolicy Bypass -File install.ps1
```

* **Installed Path**: `%LOCALAPPDATA%\Programs\NetworkSlinger\NetworkSlinger.exe`
* **Start Menu**: Available in the Windows Start Menu as **Network Slinger**.
* **Windows Settings**: Registered under Windows Settings > Apps with an uninstaller.

---

### 2. Build Standalone Executable from Source

You can build the binary distribution anytime using PyInstaller:
```powershell
pyinstaller NetworkSlinger.spec --noconfirm
```
The standalone binary and local assets will be output to `dist\NetworkSlinger\NetworkSlinger.exe`.

---

### 3. Developer / Python Execution

If running directly from source code:
```powershell
python -m pip install -e .
python run.py
```

---

## 💻 CLI Usage

### 1. View Local Interfaces & Gateway
```powershell
python run.py ifaces
```

### 2. Quick Auto-Discovery on Local Subnet
Automatically detects your primary network interface (e.g. `192.168.1.0/24`) and scans active hosts:
```powershell
python run.py discover
```

### 3. Full Network Crawl
```powershell
# Crawl local subnet with standard 100 ports and web scraping
python run.py crawl

# Crawl a specific CIDR or IP range
python run.py crawl --target 192.168.1.0/24 --ports standard

# Fast scan on a single IP with custom ports
python run.py crawl --target 192.168.1.1 --ports fast

# Deep web scrawl probing for /.env, /.git, and admin panels
python run.py crawl --target 192.168.1.0/24 --deep --output report.html --format html
```

### 4. CLI Arguments Reference

| Argument | Flag | Default | Description |
| :--- | :--- | :--- | :--- |
| `--target` | `-t` | Auto LAN | CIDR (`192.168.1.0/24`), range (`192.168.1.1-50`), or IP |
| `--ports` | `-p` | `standard` | Port profile: `fast` (25), `standard` (100), `extended` (1000), `custom` |
| `--custom-ports` | | `""` | Custom comma-separated ports or ranges (`80,443,8000-8080`) |
| `--concurrency` | `-c` | `150` | Maximum simultaneous async socket connections |
| `--timeout` | | `1.0` | Socket connection timeout in seconds |
| `--no-web` | | `False` | Disable HTTP/HTTPS web application crawler |
| `--deep` | | `False` | Enable deep sensitive endpoint probes (`/.env`, `/.git`, `/admin`) |
| `--no-multicast` | | `False` | Disable SSDP / UPnP multicast discovery |
| `--output` | `-o` | `None` | Save output report to file path |
| `--format` | | `json` | Report output format: `json`, `csv`, `html` |

---

## 🌐 Web Console & Dashboard

Launch the web console with:
```powershell
python run.py web
# or specify host/port
python run.py web --host 127.0.0.1 --port 8000
```
Open **[http://127.0.0.1:8000](http://127.0.0.1:8000)** in your browser to access:
- **Radar & Scrawler Panel**: Configure targets, toggle deep crawl, watch real-time animated radar and streaming terminal logs.
- **Topology Graph**: Drag, zoom, and explore the network node hierarchy.
- **Host Inventory**: Searchable device list with hardware vendors, latency, and open ports.
- **Web Applications Showcase**: Live cards with page titles, server banners, tech tags, and SSL certificates.
- **Security Audit**: Actionable vulnerability findings and remediation guide.
- **Export Center**: Download self-contained HTML, JSON, or CSV audit reports.

---

## 🐍 Programmatic Python API

You can easily integrate Network Slinger into your own Python automation scripts:

```python
import asyncio
from networkslinger.engine import NetworkSlingerCrawler
from networkslinger.models import ScanConfig, PortProfile

async def main():
    config = ScanConfig(
        targets=["192.168.1.1"],
        port_profile=PortProfile.FAST,
        crawl_web=True,
        deep_web_crawl=False
    )
    
    crawler = NetworkSlingerCrawler(config)
    report = await crawler.execute_crawl()
    
    print(f"Discovered {len(report.hosts)} host(s) in {report.duration_seconds}s")
    for host in report.hosts:
        print(f"Host: {host.ip} ({host.vendor}) - Risk: {host.risk_level.value}")
        for port in host.open_ports:
            print(f"  Port {port.port}/{port.service} - {port.banner}")

if __name__ == "__main__":
    asyncio.run(main())
```

---

## 🧪 Testing

Run the included automated integration test suite:
```powershell
python tests/test_engine.py
```

---

## 🔒 Security & Ethical Notice

Network Slinger is designed exclusively for authorized network auditing, asset management, and defensive vulnerability assessments. Always obtain proper written authorization before scanning networks that you do not own or manage.
