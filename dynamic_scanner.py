
#!/usr/bin/env python3
"""
Port Scanner and Mitigation System

Defensive asynchronous TCP port scanner with optional Nmap integration.

Features:
- Asynchronous TCP connect scanning
- Banner grabbing and basic service identification
- Optional Nmap service/version detection
- JSON, CSV and TXT output
- Security mitigation suggestions

LEGAL: Only scan systems you own or have explicit authorization to test.
"""

import argparse
import asyncio
import csv
import ipaddress
import json
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

DEFAULT_PORTS = "1-65535"
CONCURRENCY = 500
TIMEOUT = 1.5
RATE_DELAY = 0.0
PROBE_READ_BYTES = 2048
BANNER_SNIPPET_MAX = 200

COMMON_PORT_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    135: "msrpc",
    139: "netbios",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    587: "smtp-submission",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    2375: "docker",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}

MITIGATIONS = {
    "ssh": [
        "Use SSH keys and disable password login where practical.",
        "Restrict access to trusted IP addresses or a VPN.",
        "Keep the SSH server and operating system updated.",
    ],
    "ftp": [
        "Avoid transmitting credentials over unencrypted FTP.",
        "Prefer SFTP or another secure file-transfer method.",
        "Restrict access and disable the service if unnecessary.",
    ],
    "telnet": [
        "Replace Telnet with SSH.",
        "Disable Telnet if it is not required.",
    ],
    "smtp": [
        "Configure authentication and prevent unauthorized open relay.",
        "Use secure transport and keep the mail server updated.",
    ],
    "dns": [
        "Restrict zone transfers to authorized systems.",
        "Review recursion settings and keep DNS software updated.",
    ],
    "http": [
        "Keep the web server and application updated.",
        "Use HTTPS when the service handles sensitive information.",
        "Remove unnecessary applications and default pages.",
    ],
    "https": [
        "Maintain valid certificates and modern TLS settings.",
        "Keep the web server and its dependencies updated.",
    ],
    "mysql": [
        "Restrict database access to trusted hosts.",
        "Use strong authentication and least-privilege accounts.",
        "Avoid exposing the database directly to the internet.",
    ],
    "postgresql": [
        "Restrict network access to trusted clients.",
        "Use strong authentication and least-privilege accounts.",
        "Keep PostgreSQL updated.",
    ],
    "redis": [
        "Avoid exposing Redis publicly.",
        "Restrict access with firewall rules and authentication.",
        "Keep Redis updated and use protected network interfaces.",
    ],
    "smb": [
        "Restrict SMB to trusted networks.",
        "Disable obsolete SMB protocol versions.",
        "Keep file-sharing systems patched.",
    ],
    "vnc": [
        "Restrict remote desktop access to trusted networks.",
        "Use secure tunneling or VPN access.",
        "Use strong authentication and updated software.",
    ],
    "ldap": [
        "Restrict directory access to authorized systems.",
        "Use encrypted LDAP connections where appropriate.",
        "Review permissions and authentication policies.",
    ],
    "snmp": [
        "Restrict SNMP access to management systems.",
        "Prefer SNMPv3 with authentication and encryption.",
        "Change default community strings if present.",
    ],
    "rdp": [
        "Restrict RDP to trusted networks or a VPN.",
        "Require strong authentication and keep systems updated.",
        "Enable appropriate account lockout and access policies.",
    ],
    "unknown": [
        "Identify the application listening on this port.",
        "Confirm that the service is required.",
        "Restrict access and update the service if necessary.",
    ],
}


# ---------------------------------------------------------
# General helpers
# ---------------------------------------------------------

def now_utc() -> str:
    """Return the current UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def validate_target(target: str) -> str:
    """
    Validate an IP address or hostname.

    Hostnames are permitted; this function does not resolve them.
    """
    target = target.strip()

    if not target:
        raise ValueError("Target cannot be empty.")

    if any(char.isspace() for char in target):
        raise ValueError("Target must not contain whitespace.")

    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    if len(target) > 253:
        raise ValueError("Hostname is too long.")

    hostname = target.rstrip(".")

    if not hostname:
        raise ValueError("Invalid hostname.")

    labels = hostname.split(".")

    for label in labels:
        if (
            not label
            or len(label) > 63
            or not re.fullmatch(
                r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?",
                label,
            )
        ):
            raise ValueError("Enter a valid IP address or hostname.")

    return hostname


def parse_ports(port_spec: str) -> list[int]:
    """
    Parse ports such as:
        22
        22,80,443
        1-1000
        22,80,8000-8100
    """
    ports = set()

    for item in port_spec.split(","):
        item = item.strip()

        if not item:
            raise ValueError("Empty port entry.")

        if "-" in item:
            parts = item.split("-")

            if len(parts) != 2:
                raise ValueError(f"Invalid port range: {item}")

            try:
                start, end = map(int, parts)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid port range: {item}"
                ) from exc

            if not (1 <= start <= end <= 65535):
                raise ValueError(f"Port range out of bounds: {item}")

            ports.update(range(start, end + 1))

        else:
            try:
                port = int(item)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid port number: {item}"
                ) from exc

            if not 1 <= port <= 65535:
                raise ValueError(f"Port out of bounds: {port}")

            ports.add(port)

    if not ports:
        raise ValueError("At least one port is required.")

    return sorted(ports)


# ---------------------------------------------------------
# Banner grabbing and service identification
# ---------------------------------------------------------

async def grab_banner(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> str:
    """Attempt to read a short service banner."""
    data = b""

    try:
        data = await asyncio.wait_for(
            reader.read(PROBE_READ_BYTES),
            timeout=0.5,
        )
    except (asyncio.TimeoutError, OSError):
        pass

    if not data:
        try:
            writer.write(b"\r\n")
            await writer.drain()

            data = await asyncio.wait_for(
                reader.read(PROBE_READ_BYTES),
                timeout=0.5,
            )
        except (asyncio.TimeoutError, OSError):
            pass

    text = data.decode("utf-8", errors="replace")
    text = "".join(
        char if char.isprintable() or char in "\r\n\t" else " "
        for char in text
    )

    return text.strip()[:BANNER_SNIPPET_MAX]


def detect_service_and_version(
    port: int,
    banner: str,
) -> tuple[str, str]:
    """Estimate the service and version from port and banner."""
    service = COMMON_PORT_SERVICES.get(port, "unknown")
    version = ""

    if banner:
        first_line = banner.splitlines()[0].strip()

        ssh_match = re.search(r"SSH-[\w.\-]+", first_line, re.I)
        if ssh_match:
            service = "ssh"
            version = ssh_match.group(0)

        elif first_line.upper().startswith("HTTP/"):
            service = "https" if port in (443, 8443) else "http"
            version = first_line

        elif first_line.upper().startswith("220"):
            if port == 21:
                service = "ftp"
            elif port in (25, 587, 465):
                service = "smtp"
            version = first_line

        elif first_line.upper().startswith("REDIS"):
            service = "redis"
            version = first_line

        elif first_line:
            version = first_line[:BANNER_SNIPPET_MAX]

    return service, version


async def probe_with_existing_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> str:
    """Read a banner from an already established connection."""
    return await grab_banner(reader, writer)


# ---------------------------------------------------------
# TCP scanning
# ---------------------------------------------------------

async def scan_port(
    target: str,
    port: int,
    semaphore: asyncio.Semaphore,
    timeout: float,
    rate_delay: float,
) -> Optional[dict]:
    """Try to establish a TCP connection to one port."""
    async with semaphore:
        if rate_delay > 0:
            await asyncio.sleep(rate_delay)

        writer = None

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=timeout,
            )

            banner = await probe_with_existing_connection(
                reader,
                writer,
            )

            service, version = detect_service_and_version(
                port,
                banner,
            )

            return {
                "host": target,
                "port": port,
                "status": "open",
                "service": service,
                "version": version,
                "banner": banner,
                "timestamp": now_utc(),
            }

        except (asyncio.TimeoutError, OSError, ValueError):
            return None

        finally:
            if writer is not None:
                writer.close()

                try:
                    await writer.wait_closed()
                except OSError:
                    pass


async def async_scan(
    target: str,
    ports: list[int],
    concurrency: int = CONCURRENCY,
    timeout: float = TIMEOUT,
    rate_delay: float = RATE_DELAY,
) -> list[dict]:
    """Scan the requested TCP ports asynchronously."""
    semaphore = asyncio.Semaphore(concurrency)

    tasks = [
        scan_port(
            target,
            port,
            semaphore,
            timeout,
            rate_delay,
        )
        for port in ports
    ]

    results = await asyncio.gather(*tasks)

    return sorted(
        [result for result in results if result is not None],
        key=lambda result: result["port"],
    )


# ---------------------------------------------------------
# Optional Nmap integration
# ---------------------------------------------------------

def run_nmap_and_parse(
    target: str,
    ports: list[int],
    timeout: float,
) -> list[dict]:
    """Run Nmap service detection and parse its XML output."""
    if not shutil.which("nmap"):
        print(
            "Warning: Nmap was not found. Skipping Nmap integration.",
            file=sys.stderr,
        )
        return []

    port_spec = ",".join(map(str, ports))

    command = [
        "nmap",
        "-sT",
        "-sV",
        "-Pn",
        "-p",
        port_spec,
        "-oX",
        "-",
        target,
    ]

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=max(timeout * len(ports), 60),
            check=False,
        )

        if completed.returncode not in (0,):
            print(
                "Warning: Nmap returned a non-zero exit status.",
                file=sys.stderr,
            )

        if not completed.stdout.strip():
            return []

        root = ET.fromstring(completed.stdout)
        results = []

        for host in root.findall("host"):
            address_element = host.find("address")
            host_address = (
                address_element.get("addr")
                if address_element is not None
                else target
            )

            for port_element in host.findall(".//port"):
                state_element = port_element.find("state")
                service_element = port_element.find("service")

                if (
                    state_element is None
                    or state_element.get("state") != "open"
                ):
                    continue

                port_id = int(port_element.get("portid", "0"))

                service = COMMON_PORT_SERVICES.get(
                    port_id,
                    "unknown",
                )
                version = ""

                if service_element is not None:
                    service = service_element.get("name", service)
                    product = service_element.get("product", "")
                    version_text = service_element.get("version", "")
                    extra = service_element.get("extrainfo", "")

                    version = " ".join(
                        part for part in (
                            product,
                            version_text,
                            extra,
                        ) if part
                    ).strip()

                results.append({
                    "host": host_address,
                    "port": port_id,
                    "status": "open",
                    "service": service,
                    "version": version,
                    "banner": "",
                    "timestamp": now_utc(),
                })

        return results

    except (
        OSError,
        subprocess.TimeoutExpired,
        ET.ParseError,
    ) as exc:
        print(f"Warning: Nmap integration failed: {exc}", file=sys.stderr)
        return []


def merge_nmap(
    scan_results: list[dict],
    nmap_results: list[dict],
) -> list[dict]:
    """Merge Nmap service details into TCP scan results."""
    merged = {
        (item["host"], item["port"]): dict(item)
        for item in scan_results
    }

    for item in nmap_results:
        key = (item["host"], item["port"])

        if key in merged:
            if item.get("service") and item["service"] != "unknown":
                merged[key]["service"] = item["service"]

            if item.get("version"):
                merged[key]["version"] = item["version"]
        else:
            merged[key] = dict(item)

    return sorted(
        merged.values(),
        key=lambda item: (item["host"], item["port"]),
    )


# ---------------------------------------------------------
# Output and mitigation suggestions
# ---------------------------------------------------------

def save_results(
    results: list[dict],
    output_path: str,
) -> None:
    """Save results to JSON, CSV or TXT based on file extension."""
    path = Path(output_path)
    extension = path.suffix.lower()

    fields = [
        "host",
        "port",
        "status",
        "service",
        "version",
        "timestamp",
    ]

    try:
        path.parent.mkdir(parents=True, exist_ok=True)

        if extension == ".json":
            with path.open("w", encoding="utf-8") as file:
                json.dump(results, file, indent=4)

        elif extension == ".csv":
            with path.open(
                "w",
                newline="",
                encoding="utf-8",
            ) as file:
                writer = csv.DictWriter(
                    file,
                    fieldnames=fields,
                    extrasaction="ignore",
                )
                writer.writeheader()
                writer.writerows(results)

        elif extension == ".txt":
            with path.open("w", encoding="utf-8") as file:
                file.write(
                    "host,port,status,service,version,timestamp\n"
                )

                for item in results:
                    values = [
                        str(item.get(field, "")).replace("\n", " ")
                        for field in fields
                    ]
                    file.write(", ".join(values) + "\n")

        else:
            raise ValueError(
                "Output extension must be .json, .csv or .txt"
            )

        print(f"Results saved to: {path}")

    except OSError as exc:
        print(f"Error saving results: {exc}", file=sys.stderr)


def print_mitigations(results: list[dict]) -> None:
    """Print mitigation suggestions for detected open services."""
    if not results:
        print("\nNo open TCP ports were detected.")
        return

    print("\nMitigation suggestions")
    print("=" * 60)

    services = sorted({
        item.get("service", "unknown").lower()
        for item in results
    })

    for service in services:
        suggestions = MITIGATIONS.get(
            service,
            MITIGATIONS["unknown"],
        )

        print(f"\nService: {service}")

        for suggestion in suggestions:
            print(f"  - {suggestion}")


def print_results(results: list[dict]) -> None:
    """Display only open ports in the console."""
    print("\nOpen TCP ports")
    print("=" * 80)

    if not results:
        print("No open TCP ports detected.")
        return

    print(
        f"{'HOST':<25} {'PORT':<8} {'SERVICE':<20} "
        f"{'VERSION'}"
    )
    print("-" * 80)

    for item in results:
        print(
            f"{item['host']:<25} "
            f"{item['port']:<8} "
            f"{item['service']:<20} "
            f"{item.get('version', '')}"
        )


# ---------------------------------------------------------
# Command-line interface
# ---------------------------------------------------------

def cli() -> argparse.Namespace:
    """Define and parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Port Scanner and Mitigation System"
    )

    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="Target IP address or hostname you are authorized to scan",
    )

    parser.add_argument(
        "-p",
        "--ports",
        default=DEFAULT_PORTS,
        help="Ports, comma-separated ports or ranges (default: 1-65535)",
    )

    parser.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=CONCURRENCY,
        help=f"Maximum concurrent connections (default: {CONCURRENCY})",
    )

    parser.add_argument(
        "-to",
        "--timeout",
        type=float,
        default=TIMEOUT,
        help=f"Connection timeout in seconds (default: {TIMEOUT})",
    )

    parser.add_argument(
        "-r",
        "--rate-delay",
        type=float,
        default=RATE_DELAY,
        help="Delay in seconds before each connection attempt",
    )

    parser.add_argument(
        "--nmap",
        action="store_true",
        help="Use Nmap for additional service/version detection",
    )

    parser.add_argument(
        "-o",
        "--out",
        help="Output file (.json, .csv or .txt)",
    )

    args = parser.parse_args()

    if args.concurrency < 1:
        parser.error("Concurrency must be at least 1.")

    if args.timeout <= 0:
        parser.error("Timeout must be greater than 0.")

    if args.rate_delay < 0:
        parser.error("Rate delay cannot be negative.")

    if args.out:
        if Path(args.out).suffix.lower() not in (
            ".json",
            ".csv",
            ".txt",
        ):
            parser.error("Output file must end in .json, .csv or .txt.")

    return args


async def main_scan(args: argparse.Namespace) -> int:
    """Validate input, scan ports and display results."""
    try:
        target = validate_target(args.target)
        ports = parse_ports(args.ports)

    except ValueError as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2

    print(f"Target: {target}")
    print(f"Ports to scan: {len(ports)}")
    print(f"Concurrency: {args.concurrency}")
    print(f"Timeout: {args.timeout} seconds")

    print(
        "\nReminder: scan only systems you own "
        "or are explicitly authorized to test."
    )

    results = await async_scan(
        target=target,
        ports=ports,
        concurrency=args.concurrency,
        timeout=args.timeout,
        rate_delay=args.rate_delay,
    )

    if args.nmap:
        print("\nRunning optional Nmap service detection...")
        nmap_results = run_nmap_and_parse(
            target,
            ports,
            args.timeout,
        )
        results = merge_nmap(results, nmap_results)

    print_results(results)
    print_mitigations(results)

    if args.out:
        save_results(results, args.out)

    return 0


def main() -> int:
    """Program entry point."""
    args = cli()

    try:
        return asyncio.run(main_scan(args))
    except KeyboardInterrupt:
        print("\nScan interrupted by user.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
