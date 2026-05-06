#!/usr/bin/env python3
"""
Diligence Integration - Nutze Nmap Suite Tools direkt in diligence.py.
"""

import logging
from pathlib import Path
from typing import Any, Optional

from nmap_suite import verify_nmap_suite, find_nmap_tool
from ping_scanner import NpingScanner
from scan_comparison import ScanComparator, create_comparison_report
from network_tools import PortProber


def get_nmap_suite_status(logger: logging.Logger) -> dict[str, bool]:
    """Ermittle Verfügbarkeit aller Nmap-Suite-Tools."""
    status = verify_nmap_suite()
    
    for tool, available in status.items():
        symbol = "✓" if available else "✗"
        logger.debug(f"[{symbol}] {tool}")
    
    return status


def run_post_scan_nping(
    config: dict[str, Any],
    discovered_ips: list[str],
    logger: logging.Logger,
) -> Optional[dict[str, bool]]:
    """
    Führe Nping nach dem Nmap-Scan aus.
    
    Args:
        config: Diligence-Konfiguration
        discovered_ips: Liste der von Nmap entdeckten IPs
        logger: Logger-Instanz
    
    Returns:
        Nping-Ergebnisse oder None
    """
    nping_config = config.get("nping", {})
    if not nping_config.get("enabled", False):
        return None
    
    if not discovered_ips:
        logger.info("Keine IPs für Nping verfügbar")
        return None
    
    logger.info(f"Starte Nping für {len(discovered_ips)} Hosts...")
    
    try:
        scanner = NpingScanner(logger)
        if not scanner.is_available():
            logger.warning("Nping nicht verfügbar")
            return None
        
        results = scanner.ping_hosts(
            discovered_ips,
            count=nping_config.get("ping_count", 3),
            timeout_ms=nping_config.get("timeout_ms", 5000),
        )
        
        reachable = sum(1 for r in results.values() if r)
        logger.info(f"Nping abgeschlossen: {reachable}/{len(results)} erreichbar")
        
        return results
    except Exception as exc:
        logger.error(f"Nping Fehler: {exc}")
        return None


def run_post_scan_ncat_probe(
    config: dict[str, Any],
    discovered_hosts: list[dict[str, str]],
    logger: logging.Logger,
) -> Optional[dict]:
    """
    Probe offene Ports mit Ncat nach dem Nmap-Scan.
    
    Args:
        config: Diligence-Konfiguration
        discovered_hosts: Liste der gefundenen Hosts mit Ports
        logger: Logger-Instanz
    
    Returns:
        Probe-Ergebnisse oder None
    """
    ncat_config = config.get("ncat", {})
    if not ncat_config.get("probe_discovered_ports", False):
        return None
    
    if not discovered_hosts:
        logger.info("Keine Hosts für Ncat-Probe verfügbar")
        return None
    
    logger.info(f"Starte Ncat Port-Probe für {len(discovered_hosts)} Hosts...")
    
    try:
        prober = PortProber(logger)
        results = {}
        
        for host in discovered_hosts[:5]:  # Max 5 Hosts
            ip = host.get("ip")
            if not ip:
                continue
            
            ports = [int(p) for p in host.get("ports", [])[:5]]  # Max 5 Ports
            if ports:
                probe_results = prober.probe_ports(
                    ip,
                    ports,
                    timeout_seconds=ncat_config.get("port_probe_timeout", 5),
                )
                results[ip] = probe_results
        
        logger.info(f"Ncat-Probe abgeschlossen für {len(results)} Hosts")
        return results
    except Exception as exc:
        logger.error(f"Ncat Fehler: {exc}")
        return None


def run_comparison_with_previous(
    config: dict[str, Any],
    new_xml: Path,
    report_dir: Path,
    logger: logging.Logger,
) -> Optional[Path]:
    """
    Vergleiche neuen Scan mit dem vorherigen.
    
    Args:
        config: Diligence-Konfiguration
        new_xml: Pfad zur neuen XML-Datei
        report_dir: Report-Verzeichnis
        logger: Logger-Instanz
    
    Returns:
        Pfad zum Vergleichs-Report oder None
    """
    ndiff_config = config.get("ndiff", {})
    if not ndiff_config.get("auto_compare_with_last", False):
        return None
    
    # Finde vorherigen Scan
    xml_files = sorted(report_dir.glob("diligence_*.xml"))
    if len(xml_files) < 2:
        logger.debug("Nicht genug Scans für Vergleich")
        return None
    
    old_xml = xml_files[-2]  # Zweitletzter Scan
    
    logger.info(f"Vergleiche mit vorherigem Scan: {old_xml.name}")
    
    try:
        comparator = ScanComparator(logger)
        if not comparator.is_available():
            logger.warning("Ndiff nicht verfügbar")
            return None
        
        # Erstelle Report
        stamp = new_xml.stem.split("_", 1)[1]
        comparison_path = report_dir / f"diligence_{stamp}_comparison.md"
        
        create_comparison_report(old_xml, new_xml, comparison_path, logger)
        return comparison_path
    except Exception as exc:
        logger.error(f"Ndiff Fehler: {exc}")
        return None


def extract_discovered_ips(rows: list[dict[str, str]]) -> list[str]:
    """Extrahiere eindeutige IPs aus Scan-Ergebnissen."""
    ips = set()
    for row in rows:
        if row.get("ip") and row.get("host_state") == "up":
            ips.add(row["ip"])
    return sorted(ips)


def extract_discovered_hosts(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    """Extrahiere Hosts mit offenen Ports."""
    hosts_dict = {}
    
    for row in rows:
        ip = row.get("ip")
        if not ip or row.get("host_state") != "up":
            continue
        
        if ip not in hosts_dict:
            hosts_dict[ip] = {
                "ip": ip,
                "hostname": row.get("hostname", ""),
                "mac": row.get("mac", ""),
                "ports": [],
            }
        
        if row.get("port") and row.get("port_state") == "open":
            hosts_dict[ip]["ports"].append(row["port"])
    
    return list(hosts_dict.values())


# ===== Beispiel-Integration in diligence.py =====

INTEGRATION_EXAMPLE = """
# In diligence.py main() hinzufügen:

from diligence_integration import (
    get_nmap_suite_status,
    run_post_scan_nping,
    run_post_scan_ncat_probe,
    run_comparison_with_previous,
    extract_discovered_ips,
)

# Nach dem Scan
rows = parse_nmap_xml(xml_path)
reports = create_reports(config, rows, report_dir, stamp)

# ===== Neue Suite-Features =====

# 1. Nmap Suite Status
suite_status = get_nmap_suite_status(logger)
logger.debug(f"Nmap Suite Tools: {suite_status}")

# 2. Post-Scan Nping
discovered_ips = extract_discovered_ips(rows)
ping_results = run_post_scan_nping(config, discovered_ips, logger)
if ping_results:
    logger.info(f"Nping: {sum(1 for r in ping_results.values() if r)} Hosts erreichbar")

# 3. Post-Scan Ncat Probe
discovered_hosts = extract_discovered_hosts(rows)
probe_results = run_post_scan_ncat_probe(config, discovered_hosts, logger)
if probe_results:
    logger.info(f"Ncat: {len(probe_results)} Hosts geprobt")

# 4. Scan-Vergleich
comparison_report = run_comparison_with_previous(config, xml_path, report_dir, logger)
if comparison_report:
    logger.info(f"Vergleich: {comparison_report}")
"""
