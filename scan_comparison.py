#!/usr/bin/env python3
"""
Ndiff Integration - Vergleich von Nmap-Scans.
Erkennt Veränderungen im Netzwerk zwischen zwei Scans.
"""

import json
import logging
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Optional

from nmap_suite import find_nmap_tool, run_nmap_tool


class ScanComparator:
    """Vergleicht zwei Nmap-Scan-Ergebnisse."""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.ndiff_exe = find_nmap_tool("ndiff")
    
    def is_available(self) -> bool:
        """Prüfe ob Ndiff verfügbar ist."""
        return self.ndiff_exe is not None
    
    def compare_xml_scans(
        self,
        old_xml: Path,
        new_xml: Path,
        output_format: str = "text",
    ) -> Optional[str]:
        """
        Vergleiche zwei XML-Scan-Dateien.
        
        Args:
            old_xml: Pfad zur älteren XML-Datei
            new_xml: Pfad zur neueren XML-Datei
            output_format: "text" oder "html"
        
        Returns:
            Vergleichsergebnis als String
        """
        if not self.is_available():
            raise RuntimeError("Ndiff nicht gefunden")
        
        if not old_xml.exists() or not new_xml.exists():
            raise FileNotFoundError("Eine oder beide XML-Dateien existieren nicht")
        
        try:
            if output_format == "html":
                args = ["--html", str(old_xml), str(new_xml)]
            else:
                args = [str(old_xml), str(new_xml)]
            
            result = run_nmap_tool("ndiff", args, timeout_seconds=30, capture_output=True)
            
            if result.returncode in (0, 1):  # 0 = identisch, 1 = unterschiede
                return result.stdout
            else:
                self.logger.error(f"Ndiff Fehler: {result.stderr}")
                return None
        except Exception as exc:
            self.logger.error(f"Scan-Vergleich Fehler: {exc}")
            return None
    
    def parse_scan_differences(
        self,
        old_xml: Path,
        new_xml: Path,
    ) -> dict[str, Any]:
        """
        Parse die Unterschiede zwischen zwei Scans strukturiert.
        
        Returns:
            dict mit:
            - new_hosts: Neue Hosts
            - gone_hosts: Entfernte Hosts
            - changed_hosts: Geänderte Hosts
            - new_ports: Neue offene Ports
            - closed_ports: Geschlossene Ports
        """
        old_hosts = self._parse_hosts_from_xml(old_xml)
        new_hosts = self._parse_hosts_from_xml(new_xml)
        
        old_ips = set(old_hosts.keys())
        new_ips = set(new_hosts.keys())
        
        differences = {
            "new_hosts": list(new_ips - old_ips),
            "gone_hosts": list(old_ips - new_ips),
            "changed_hosts": {},
            "new_ports": {},
            "closed_ports": {},
        }
        
        # Vergleiche gemeinsame Hosts
        for ip in old_ips & new_ips:
            old_data = old_hosts[ip]
            new_data = new_hosts[ip]
            
            old_ports = set(old_data.get("ports", []))
            new_ports = set(new_data.get("ports", []))
            
            if old_ports != new_ports:
                differences["changed_hosts"][ip] = {
                    "new_ports": list(new_ports - old_ports),
                    "closed_ports": list(old_ports - new_ports),
                }
                
                if ip not in differences["new_ports"]:
                    differences["new_ports"][ip] = []
                differences["new_ports"][ip].extend(new_ports - old_ports)
                
                if ip not in differences["closed_ports"]:
                    differences["closed_ports"][ip] = []
                differences["closed_ports"][ip].extend(old_ports - new_ports)
        
        return differences
    
    def _parse_hosts_from_xml(self, xml_path: Path) -> dict[str, dict[str, Any]]:
        """Parse Hosts und Ports aus XML."""
        hosts = {}
        
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            
            for host in root.findall("host"):
                status = host.find("status")
                if status is not None and status.get("state") == "up":
                    addresses = host.findall("address")
                    ip = next(
                        (a.get("addr", "") for a in addresses if a.get("addrtype") in {"ipv4", "ipv6"}),
                        None,
                    )
                    
                    if ip:
                        ports = []
                        for port in host.findall("ports/port"):
                            port_state = port.find("state")
                            if port_state is not None and port_state.get("state") == "open":
                                port_id = port.get("portid")
                                ports.append(port_id)
                        
                        hosts[ip] = {"ports": ports}
        except Exception as exc:
            self.logger.error(f"XML-Parse Fehler: {exc}")
        
        return hosts


def create_comparison_report(
    old_xml: Path,
    new_xml: Path,
    output_path: Path,
    logger: logging.Logger,
) -> None:
    """
    Erstelle einen Scan-Vergleich-Report.
    
    Args:
        old_xml: Pfad zur älteren XML-Datei
        new_xml: Pfad zur neueren XML-Datei
        output_path: Pfad für den Report (MD)
        logger: Logger-Instanz
    """
    comparator = ScanComparator(logger)
    differences = comparator.parse_scan_differences(old_xml, new_xml)
    
    content = [
        "# Netzwerk-Scan Vergleich",
        "",
        f"- Alt: {old_xml.name}",
        f"- Neu: {new_xml.name}",
        "",
    ]
    
    # Neue Hosts
    if differences["new_hosts"]:
        content.append("## Neue Hosts")
        content.append("")
        for ip in sorted(differences["new_hosts"]):
            content.append(f"- {ip}")
        content.append("")
    
    # Entfernte Hosts
    if differences["gone_hosts"]:
        content.append("## Entfernte Hosts")
        content.append("")
        for ip in sorted(differences["gone_hosts"]):
            content.append(f"- {ip}")
        content.append("")
    
    # Geänderte Hosts
    if differences["changed_hosts"]:
        content.append("## Geänderte Hosts")
        content.append("")
        for ip, changes in sorted(differences["changed_hosts"].items()):
            content.append(f"### {ip}")
            content.append("")
            
            if changes.get("new_ports"):
                content.append("**Neue Ports:**")
                for port in sorted(changes["new_ports"]):
                    content.append(f"- {port}")
                content.append("")
            
            if changes.get("closed_ports"):
                content.append("**Geschlossene Ports:**")
                for port in sorted(changes["closed_ports"]):
                    content.append(f"- {port}")
                content.append("")
    
    # Summary
    if not any([differences["new_hosts"], differences["gone_hosts"], differences["changed_hosts"]]):
        content.append("✓ Keine Unterschiede gefunden.")
    else:
        content.append("## Zusammenfassung")
        content.append("")
        content.append(f"- Neue Hosts: {len(differences['new_hosts'])}")
        content.append(f"- Entfernte Hosts: {len(differences['gone_hosts'])}")
        content.append(f"- Geänderte Hosts: {len(differences['changed_hosts'])}")
        content.append("")
    
    output_path.write_text("\n".join(content), encoding="utf-8")
    logger.info(f"Vergleichs-Report erstellt: {output_path}")


def export_comparison_json(
    differences: dict[str, Any],
    output_path: Path,
) -> None:
    """Exportiere Vergleichsergebnisse als JSON."""
    output_path.write_text(json.dumps(differences, indent=2, ensure_ascii=False), encoding="utf-8")
