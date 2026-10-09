# Port-Scanner
This is mini port scanner cretaed using nmap reference
# Port Scanner and Mitigation System

A Python-based cybersecurity mini project for identifying open TCP ports, detecting exposed network services, analyzing service banners, and recommending security mitigation measures.

## Project Overview

Port scanning is a network reconnaissance technique used to identify accessible ports and services on a target system. This project implements an asynchronous TCP port scanner with optional Nmap integration and service-specific mitigation recommendations.

The project is intended for educational purposes and authorized network security assessments.

## Features

* Asynchronous TCP port scanning
* Configurable target host and port ranges
* Basic service identification using port numbers and banners
* Optional Nmap service and version detection
* JSON, CSV, and TXT result exports
* Timestamped scan results
* Security hardening recommendations for detected services
* Console output with colored status messages
* Connection timeout and concurrency controls

## Technology Stack

* **Language:** Python 3
* **Networking:** Python `asyncio` and socket streams
* **Service detection:** Banner analysis
* **Optional scanner integration:** Nmap
* **Output formats:** JSON, CSV, TXT
* **Operating systems:** Linux, macOS, and Windows, subject to environment and Nmap availability

## Repository Structure

```text
port-scanner/
├── README.md
├── dynamic_scanner.py
├── requirements.txt
├── .gitignore
├── LICENSE
├── docs/
│   └── project-notes.md
├── results/
└── screenshots/
```

## Prerequisites

* Python 3.9 or newer
* Nmap, if using optional Nmap integration
* Permission to scan the target system

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/port-scanner-mitigation-system.git
cd port-scanner
```

Create and activate a virtual environment:

```bash
python -m venv .venv
```

Windows:

```powershell
.venv\Scripts\Activate.ps1
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Install dependencies, if required:

```bash
pip install -r requirements.txt
```

## Usage

Display command-line options:

```bash
python dynamic_scanner.py --help
```

Scan an authorized host over a small port range:

```bash
python dynamic_scanner.py --target 127.0.0.1 --ports 1-1024
```

Scan selected ports:

```bash
python dynamic_scanner.py --target 127.0.0.1 --ports 22,80,443
```

Save results as JSON:

```bash
python dynamic_scanner.py --target 127.0.0.1 --ports 1-1024 --out results/scan.json
```

Save results as CSV:

```bash
python dynamic_scanner.py --target 127.0.0.1 --ports 1-1024 --out results/scan.csv
```

Use Nmap integration:

```bash
python dynamic_scanner.py --target 127.0.0.1 --ports 1-1024 --nmap
```

Use a conservative concurrency and timeout setting when testing unfamiliar lab environments.

## Mitigation Recommendations

The scanner provides recommendations based on identified services. Examples include:

| Service          | Example recommendation                                          |
| ---------------- | --------------------------------------------------------------- |
| SSH              | Use key-based authentication and restrict access                |
| FTP              | Prefer SFTP or FTPS and disable anonymous access                |
| Telnet           | Disable Telnet and use SSH                                      |
| HTTP/HTTPS       | Patch the web server and use secure TLS configuration           |
| MySQL            | Restrict database access to trusted networks                    |
| Redis            | Require authentication and restrict network exposure            |
| SMB              | Disable SMBv1 and restrict access                               |
| Unknown services | Identify the listening process and disable unnecessary services |

These are general recommendations. Verify the configuration and business requirements before making changes.

## Limitations

* The primary scanner uses TCP connection attempts.
* A failed connection is not definitive proof that a port is closed; a firewall or timeout may affect the result.
* Banner-based service identification is heuristic and may be incomplete.
* UDP, SYN, FIN, NULL, and XMAS scanning should not be described as implemented unless corresponding code is added and tested.
* Automatic firewall blocking and real-time IDS/IPS monitoring require additional implementation beyond the scanner functions.

## Ethical and Legal Use

Only scan systems you own or have explicit authorization to assess. Begin with localhost or a dedicated cybersecurity lab. Do not scan public or third-party systems without permission.

## Academic Project

**Project title:** Port Scanner and Mitigation System

**Department:** CSE (Cyber Security)

**Academic year:** 2025–2026

Refer to the accompanying academic project report for the original project description, objectives, implementation discussion, and results.

## Future Enhancements

* Integrate live network traffic monitoring
* Add scan detection based on source IP and connection frequency
* Add SIEM-compatible logging
* Improve service identification
* Develop a dashboard for scan results
* Add configurable defensive integrations with explicit operator approval

