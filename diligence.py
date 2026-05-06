#!/usr/bin/env python3
"""
Diligence - autorisierte Heimnetz-Inventarisierung mit Nmap.

Erzeugt Nmap-XML, CSV, JSON und einen HTML-Tabellenreport.
"""

import argparse
import csv
import datetime as dt
import html
import ipaddress
import json
import logging
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

APP_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG = APP_DIR / "config.json"
PROFILE_COMMANDS = {
    "discovery": ["-sn"],
    "common": ["-sV", "--top-ports"],
    "ports": ["-sV", "-p"],
}
ALLOWED_TIMING = {"T0", "T1", "T2", "T3", "T4", "T5"}
PRIVATE_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::1/128"),
)


def configure_console() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def load_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Config nicht gefunden: {path}")
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def setup_logging(config: dict[str, Any]) -> logging.Logger:
    log_file = resolve_app_path(config["paths"]["log_file"])
    log_file.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("Diligence")
    logger.handlers.clear()
    logger.setLevel(getattr(logging, config["logging"].get("level", "INFO").upper(), logging.INFO))

    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    console_handler = logging.StreamHandler()
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger


def resolve_app_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else APP_DIR / path


def is_private_target(target: str) -> bool:
    try:
        network = ipaddress.ip_network(target, strict=False)
        return any(network.subnet_of(private) or network.overlaps(private) for private in PRIVATE_NETS)
    except ValueError:
        try:
            address = ipaddress.ip_address(target)
            return any(address in private for private in PRIVATE_NETS)
        except ValueError:
            return False


def require_authorized_target(target: str, allow_public: bool) -> None:
    if allow_public or is_private_target(target):
        return
    raise ValueError(
        "Ziel wirkt nicht wie ein privates Heimnetz. "
        "Nutze nur autorisierte Ziele oder setze allow_public_targets bewusst auf true."
    )


def build_nmap_command(config: dict[str, Any], xml_path: Path) -> list[str]:
    scan_config = config["scan"]
    profile = scan_config.get("profile", "common")
    target = scan_config["target"]
    timing = scan_config.get("timing", "T3")
    if timing not in ALLOWED_TIMING:
        raise ValueError(f"Ungueltiger Timing-Wert: {timing}")

    command = ["nmap", f"-{timing}", "-oX", str(xml_path)]

    if profile == "discovery":
        command.extend(PROFILE_COMMANDS["discovery"])
    elif profile == "common":
        top_ports = int(scan_config.get("top_ports", 100))
        if top_ports < 1 or top_ports > 1000:
            raise ValueError("top_ports muss zwischen 1 und 1000 liegen")
        command.extend(PROFILE_COMMANDS["common"])
        command.append(str(top_ports))
    elif profile == "ports":
        ports = str(scan_config.get("ports", "22,80,443,445,3389"))
        command.extend(PROFILE_COMMANDS["ports"])
        command.append(ports)
    else:
        raise ValueError(f"Unbekanntes Scan-Profil: {profile}")

    command.append(target)
    return command


def run_nmap(command: list[str], logger: logging.Logger) -> None:
    if shutil.which("nmap") is None:
        raise RuntimeError("Nmap wurde nicht gefunden. Bitte Nmap installieren und PATH neu laden.")

    logger.info("Starte Nmap: %s", " ".join(command))
    result = subprocess.run(command, cwd=APP_DIR, text=True, capture_output=True, check=False)
    if result.stdout:
        logger.info(result.stdout.strip())
    if result.stderr:
        logger.warning(result.stderr.strip())
    if result.returncode != 0:
        raise RuntimeError(f"Nmap fehlgeschlagen (Exit Code {result.returncode})")


def parse_nmap_xml(xml_path: Path) -> list[dict[str, str]]:
    tree = ET.parse(xml_path)
    root = tree.getroot()
    rows: list[dict[str, str]] = []

    for host in root.findall("host"):
        status = host.find("status")
        state = status.get("state", "") if status is not None else ""
        addresses = host.findall("address")
        ip_address = next((a.get("addr", "") for a in addresses if a.get("addrtype") in {"ipv4", "ipv6"}), "")
        mac_address = next((a.get("addr", "") for a in addresses if a.get("addrtype") == "mac"), "")
        vendor = next((a.get("vendor", "") for a in addresses if a.get("addrtype") == "mac"), "")
        hostname = ""
        hostname_node = host.find("hostnames/hostname")
        if hostname_node is not None:
            hostname = hostname_node.get("name", "")

        ports = host.findall("ports/port")
        if not ports:
            rows.append(make_row(ip_address, hostname, mac_address, vendor, state))
            continue

        for port in ports:
            port_state = port.find("state")
            service = port.find("service")
            rows.append(make_row(
                ip_address,
                hostname,
                mac_address,
                vendor,
                state,
                port.get("protocol", ""),
                port.get("portid", ""),
                port_state.get("state", "") if port_state is not None else "",
                service.get("name", "") if service is not None else "",
                service.get("product", "") if service is not None else "",
                service.get("version", "") if service is not None else "",
            ))
    return rows


def make_row(
    ip_address: str,
    hostname: str,
    mac_address: str,
    vendor: str,
    host_state: str,
    protocol: str = "",
    port: str = "",
    port_state: str = "",
    service: str = "",
    product: str = "",
    version: str = "",
) -> dict[str, str]:
    return {
        "ip": ip_address,
        "hostname": hostname,
        "mac": mac_address,
        "vendor": vendor,
        "host_state": host_state,
        "protocol": protocol,
        "port": port,
        "port_state": port_state,
        "service": service,
        "product": product,
        "version": version,
    }


def write_csv(rows: list[dict[str, str]], path: Path) -> None:
    fields = list(make_row("", "", "", "", "").keys())
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def write_json(rows: list[dict[str, str]], path: Path) -> None:
    with path.open("w", encoding="utf-8") as handle:
        json.dump(rows, handle, indent=2, ensure_ascii=False)


def write_html(rows: list[dict[str, str]], path: Path, target: str, created_at: str) -> None:
    headers = ["IP", "Hostname", "MAC", "Hersteller", "Host", "Proto", "Port", "Port-Status", "Dienst", "Produkt", "Version"]
    keys = list(make_row("", "", "", "", "").keys())
    body = "\n".join(
        "<tr>" + "".join(f"<td>{html.escape(row.get(key, ''))}</td>" for key in keys) + "</tr>"
        for row in rows
    )
    document = f"""<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Diligence Report</title>
  <style>
    body {{ font-family: Segoe UI, Arial, sans-serif; margin: 32px; color: #202124; background: #f7f9fb; }}
    h1 {{ margin: 0 0 8px; font-size: 28px; }}
    .meta {{ margin-bottom: 24px; color: #5f6368; }}
    table {{ width: 100%; border-collapse: collapse; background: white; border: 1px solid #dfe3e8; }}
    th, td {{ padding: 10px 12px; border-bottom: 1px solid #edf0f2; text-align: left; font-size: 14px; }}
    th {{ background: #eef3f7; font-weight: 600; position: sticky; top: 0; }}
    tr:hover {{ background: #f4f8fb; }}
  </style>
</head>
<body>
  <h1>Diligence Network Report</h1>
  <div class="meta">Ziel: {html.escape(target)} | Erstellt: {html.escape(created_at)} | Eintraege: {len(rows)}</div>
  <table>
    <thead><tr>{"".join(f"<th>{html.escape(header)}</th>" for header in headers)}</tr></thead>
    <tbody>{body}</tbody>
  </table>
</body>
</html>
"""
    path.write_text(document, encoding="utf-8")


def create_reports(config: dict[str, Any], rows: list[dict[str, str]], report_dir: Path, stamp: str) -> dict[str, Path]:
    target = config["scan"]["target"]
    created_at = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    paths = {
        "csv": report_dir / f"diligence_{stamp}.csv",
        "json": report_dir / f"diligence_{stamp}.json",
        "html": report_dir / f"diligence_{stamp}.html",
    }
    write_csv(rows, paths["csv"])
    write_json(rows, paths["json"])
    write_html(rows, paths["html"], target, created_at)
    return paths


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Diligence Heimnetz-Inventarisierung mit Nmap")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG), help="Pfad zur config.json")
    parser.add_argument("--target", help="Zielnetz, z. B. 192.168.178.0/24")
    parser.add_argument("--profile", choices=sorted(PROFILE_COMMANDS), help="Scan-Profil")
    parser.add_argument("--allow-public", action="store_true", help="Oeffentliche Ziele erlauben, wenn autorisiert")
    parser.add_argument("--parse-only", help="Vorhandene Nmap-XML parsen, ohne neuen Scan")
    return parser.parse_args()


def main() -> int:
    configure_console()
    args = parse_args()
    config = load_config(Path(args.config))
    if args.target:
        config["scan"]["target"] = args.target
    if args.profile:
        config["scan"]["profile"] = args.profile
    if args.allow_public:
        config["scan"]["allow_public_targets"] = True

    logger = setup_logging(config)
    target = config["scan"]["target"]
    require_authorized_target(target, bool(config["scan"].get("allow_public_targets", False)))

    report_dir = resolve_app_path(config["paths"]["report_dir"])
    report_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    xml_path = Path(args.parse_only) if args.parse_only else report_dir / f"diligence_{stamp}.xml"

    if not args.parse_only:
        command = build_nmap_command(config, xml_path)
        run_nmap(command, logger)

    rows = parse_nmap_xml(xml_path)
    reports = create_reports(config, rows, report_dir, stamp)
    logger.info("Report erstellt: %s", reports["html"])
    logger.info("CSV: %s", reports["csv"])
    logger.info("JSON: %s", reports["json"])
    print()
    print(f"Gefundene Tabelleneintraege: {len(rows)}")
    print(f"HTML-Report: {reports['html']}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"Fehler: {exc}", file=sys.stderr)
        raise SystemExit(1)
