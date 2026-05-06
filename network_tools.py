#!/usr/bin/env python3
"""
Ncat Integration - Netzwerkverbindungen und Datenübertragung.
Für Debugging, Traffic-Analyse und Netzwerk-Tests.
"""

import logging
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable, Optional

from nmap_suite import find_nmap_tool, run_nmap_tool


class NetworkCat:
    """Ncat Network Connection Tool."""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.ncat_exe = find_nmap_tool("ncat")
    
    def is_available(self) -> bool:
        """Prüfe ob Ncat verfügbar ist."""
        return self.ncat_exe is not None
    
    def test_port_connectivity(
        self,
        host: str,
        port: int,
        timeout_seconds: int = 5,
    ) -> bool:
        """
        Teste Konnektivität zu einem Port mit Ncat.
        
        Args:
            host: Ziel-Host/IP
            port: Port-Nummer
            timeout_seconds: Verbindungs-Timeout
        
        Returns:
            True wenn Verbindung erfolgreich, False sonst
        """
        if not self.is_available():
            raise RuntimeError("Ncat nicht gefunden")
        
        try:
            args = [
                f"--max-conns=1",
                f"--recv-timeout={timeout_seconds * 1000}",
                f"--send-timeout={timeout_seconds * 1000}",
                host,
                str(port),
            ]
            
            result = run_nmap_tool("ncat", args, timeout_seconds=timeout_seconds + 5, capture_output=True)
            
            # Ncat gibt 0 zurück bei erfolgreichem Connect
            success = result.returncode == 0
            self.logger.debug(f"Ncat {host}:{port} {'erfolgreich' if success else 'fehlgeschlagen'}")
            return success
        except Exception as exc:
            self.logger.warning(f"Ncat Fehler für {host}:{port}: {exc}")
            return False
    
    def probe_service_banner(
        self,
        host: str,
        port: int,
        timeout_seconds: int = 5,
    ) -> Optional[str]:
        """
        Lese Service-Banner von einem Port.
        
        Args:
            host: Ziel-Host/IP
            port: Port-Nummer
            timeout_seconds: Timeout in Sekunden
        
        Returns:
            Banner/Response oder None
        """
        if not self.is_available():
            raise RuntimeError("Ncat nicht gefunden")
        
        try:
            args = [
                f"--recv-timeout={timeout_seconds * 1000}",
                host,
                str(port),
            ]
            
            result = run_nmap_tool("ncat", args, timeout_seconds=timeout_seconds + 5, capture_output=True)
            
            if result.stdout:
                banner = result.stdout.strip()[:200]  # Max 200 chars
                self.logger.debug(f"Banner {host}:{port}: {banner}")
                return banner
            
            return None
        except Exception as exc:
            self.logger.debug(f"Banner-Probe Fehler: {exc}")
            return None
    
    def send_data_and_receive(
        self,
        host: str,
        port: int,
        data: str,
        timeout_seconds: int = 5,
    ) -> Optional[str]:
        """
        Sende Daten und empfange Response.
        
        Args:
            host: Ziel-Host/IP
            port: Port-Nummer
            data: Zu sendende Daten
            timeout_seconds: Timeout in Sekunden
        
        Returns:
            Antwort oder None
        """
        if not self.is_available():
            raise RuntimeError("Ncat nicht gefunden")
        
        try:
            args = [
                f"--recv-timeout={timeout_seconds * 1000}",
                host,
                str(port),
            ]
            
            result = subprocess.run(
                [self.ncat_exe] + args,
                input=data,
                capture_output=True,
                text=True,
                timeout=timeout_seconds + 5,
            )
            
            if result.stdout:
                return result.stdout.strip()
            
            return None
        except Exception as exc:
            self.logger.warning(f"Data-Probe Fehler: {exc}")
            return None
    
    def listen_on_port(
        self,
        port: int,
        duration_seconds: int = 30,
        on_connection: Optional[Callable[[str], None]] = None,
    ) -> list[str]:
        """
        Höre auf einem Port und erfasse eingehende Verbindungen.
        
        Args:
            port: Port zum Abhören
            duration_seconds: Wie lange abhören
            on_connection: Callback für neue Verbindungen
        
        Returns:
            Liste der empfangenen Daten
        """
        if not self.is_available():
            raise RuntimeError("Ncat nicht gefunden")
        
        collected_data = []
        
        try:
            args = [
                "-l",
                f"--max-conns=10",
                str(port),
            ]
            
            process = subprocess.Popen(
                [self.ncat_exe] + args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            
            start_time = time.time()
            
            while time.time() - start_time < duration_seconds:
                if process.poll() is not None:
                    break
                
                try:
                    line = process.stdout.readline()
                    if line:
                        collected_data.append(line.strip())
                        if on_connection:
                            on_connection(line.strip())
                except Exception:
                    pass
                
                time.sleep(0.1)
            
            process.terminate()
            process.wait(timeout=5)
            
        except Exception as exc:
            self.logger.error(f"Listen Fehler: {exc}")
        
        return collected_data


class PortProber:
    """Batch-Probe mehrerer Ports mit Ncat."""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.ncat = NetworkCat(logger)
    
    def probe_ports(
        self,
        host: str,
        ports: list[int],
        timeout_seconds: int = 5,
    ) -> dict[int, dict[str, any]]:
        """
        Probe mehrere Ports gleichzeitig.
        
        Returns:
            dict mit port -> {connected: bool, banner: str}
        """
        results = {}
        
        for port in ports:
            result = {
                "connected": False,
                "banner": None,
            }
            
            try:
                if self.ncat.test_port_connectivity(host, port, timeout_seconds):
                    result["connected"] = True
                    banner = self.ncat.probe_service_banner(host, port, timeout_seconds)
                    result["banner"] = banner
            except Exception as exc:
                self.logger.warning(f"Probe Fehler Port {port}: {exc}")
            
            results[port] = result
        
        return results


def create_port_probe_report(
    host: str,
    probe_results: dict[int, dict[str, any]],
    output_path: Path,
) -> None:
    """Erstelle einen Port-Probe-Report."""
    connected = [p for p, r in probe_results.items() if r["connected"]]
    
    content = [
        "# Ncat Port-Probe Bericht",
        "",
        f"- Host: {host}",
        f"- Getestete Ports: {len(probe_results)}",
        f"- Erreichbar: {len(connected)}",
        "",
        "## Port-Details",
        "",
    ]
    
    for port in sorted(probe_results.keys()):
        result = probe_results[port]
        status = "✓ Offen" if result["connected"] else "✗ Geschlossen"
        banner = result.get("banner", "-")
        
        content.append(f"### Port {port}")
        content.append(f"- Status: {status}")
        if banner:
            content.append(f"- Banner: `{banner[:100]}`")
        content.append("")
    
    output_path.write_text("\n".join(content), encoding="utf-8")
