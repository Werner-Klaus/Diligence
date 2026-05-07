#!/usr/bin/env python3
"""
Nping Integration - Echtzeit Ping und Erreichbarkeitsprüfungen.
Schnelle Multitarget-Erreichbarkeitsprüfungen.
"""

import logging
import subprocess
from pathlib import Path
from typing import Any, Optional

from nmap_suite import find_nmap_tool, run_nmap_tool


class NpingScanner:
    """Führt Nping-Scans durch."""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.nping_exe = find_nmap_tool("nping")
    
    def is_available(self) -> bool:
        """Prüfe ob Nping verfügbar ist."""
        return self.nping_exe is not None
    
    def ping_hosts(
        self,
        targets: list[str],
        count: int = 3,
        timeout_ms: int = 5000,
    ) -> dict[str, bool]:
        """
        Ping mehrere Hosts gleichzeitig.
        
        Args:
            targets: Liste von IP-Adressen/Hostnamen
            count: Anzahl der Ping-Pakete pro Host
            timeout_ms: Timeout pro Host in Millisekunden
        
        Returns:
            dict mit Host -> erreichbar (True/False)
        """
        if not self.is_available():
            raise RuntimeError("Nping nicht gefunden")
        
        results = {}
        for target in targets:
            results[target] = self._ping_single(target, count, timeout_ms)
        
        return results
    
    def _ping_single(
        self,
        target: str,
        count: int,
        timeout_ms: int,
    ) -> bool:
        """Ping einen einzelnen Host."""
        try:
            args = [
                "--icmp",
                f"--count={count}",
                f"--delay={timeout_ms // 1000}s",
                target,
            ]
            
            result = run_nmap_tool("nping", args, timeout_seconds=30, capture_output=True)
            
            # Nping gibt 0 zurück wenn mindestens ein Echo zurückkommt
            if result.returncode == 0:
                self.logger.debug(f"Nping {target}: erreichbar")
                return True
            else:
                self.logger.debug(f"Nping {target}: nicht erreichbar")
                return False
        except Exception as exc:
            self.logger.warning(f"Nping Fehler für {target}: {exc}")
            return False
    
    def tcp_syn_probe(
        self,
        target: str,
        ports: list[int],
        timeout_seconds: int = 10,
    ) -> dict[int, bool]:
        """
        TCP-SYN-Probe auf mehrere Ports.
        
        Args:
            target: Ziel-IP oder Hostname
            ports: Liste von Port-Nummern
            timeout_seconds: Timeout für den Scan
        
        Returns:
            dict mit port -> erreichbar (True/False)
        """
        if not self.is_available():
            raise RuntimeError("Nping nicht gefunden")
        
        results = {}
        port_string = ",".join(str(p) for p in ports)
        
        try:
            args = [
                "--tcp",
                f"--dest-port={port_string}",
                "--flags=syn",
                "--count=1",
                target,
            ]
            
            result = run_nmap_tool("nping", args, timeout_seconds=timeout_seconds, capture_output=True)
            
            # Parse Nping-Ausgabe
            for port in ports:
                results[port] = self._check_port_response(result.stdout, port)
            
            return results
        except Exception as exc:
            self.logger.error(f"TCP-Probe Fehler: {exc}")
            return {port: False for port in ports}
    
    def _check_port_response(self, output: str, port: int) -> bool:
        """Prüfe ob Port in Nping-Ausgabe geöffnet ist."""
        # Vereinfachte Heuristik: Suche nach positiven Responses
        return "Sent" in output and f"({port})" in output
    
    def udp_probe(
        self,
        target: str,
        ports: list[int],
        timeout_seconds: int = 10,
    ) -> dict[int, bool]:
        """UDP-Probe auf mehrere Ports."""
        if not self.is_available():
            raise RuntimeError("Nping nicht gefunden")
        
        results = {}
        
        try:
            for port in ports:
                args = [
                    "--udp",
                    f"--dest-port={port}",
                    "--count=1",
                    target,
                ]
                
                result = run_nmap_tool("nping", args, timeout_seconds=timeout_seconds, capture_output=True)
                results[port] = result.returncode == 0
            
            return results
        except Exception as exc:
            self.logger.error(f"UDP-Probe Fehler: {exc}")
            return {port: False for port in ports}


def create_ping_report(
    ping_results: dict[str, bool],
    output_path: Path,
) -> None:
    """
    Erstelle einen Ping-Report.
    
    Args:
        ping_results: dict mit host -> erreichbar
        output_path: Pfad für den Report
    """
    reachable = [h for h, r in ping_results.items() if r]
    unreachable = [h for h, r in ping_results.items() if not r]
    
    content = [
        "# Nping Erreichbarkeitsbericht",
        "",
        f"- Gesamte Hosts: {len(ping_results)}",
        f"- Erreichbar: {len(reachable)}",
        f"- Nicht erreichbar: {len(unreachable)}",
        "",
        "## Bewertung",
        "",
    ]
    if not ping_results:
        content.append("- Keine Hosts getestet.")
    elif reachable and not unreachable:
        content.append("- Alle getesteten Hosts sind erreichbar. Das ist fuer bekannte Heimnetzgeraete normal.")
    elif reachable:
        content.append("- Einige Hosts sind erreichbar, andere nicht. Nicht erreichbar bedeutet nicht automatisch offline; Firewalls koennen Ping blockieren.")
    else:
        content.append("- Keine Hosts per Nping erreichbar. Pruefe Zielnetz, VPN, Firewall und Netzwerkprofil.")
    content.extend([
        "",
        "## Erreichbare Hosts",
        "",
    ])
    
    if reachable:
        for host in sorted(reachable):
            content.append(f"- {host}")
    else:
        content.append("Keine")
    
    content.extend(["", "## Nicht erreichbare Hosts", ""])
    
    if unreachable:
        for host in sorted(unreachable):
            content.append(f"- {host}")
    else:
        content.append("Keine")
    
    output_path.write_text("\n".join(content), encoding="utf-8")
