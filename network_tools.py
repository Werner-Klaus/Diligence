#!/usr/bin/env python3
"""
Ncat/Nmap Integration fuer Netzwerkverbindungen und Port-Probes.
"""

import logging
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable, Optional

from nmap_suite import find_nmap_tool, run_nmap_tool


class NetworkCat:
    """Ncat Network Connection Tool."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.ncat_exe = find_nmap_tool("ncat")

    def is_available(self) -> bool:
        """Pruefe ob Ncat verfuegbar ist."""
        return self.ncat_exe is not None

    def test_port_connectivity(
        self,
        host: str,
        port: int,
        timeout_seconds: int = 5,
    ) -> bool:
        """Teste TCP-Konnektivitaet zu einem Port mit Ncat."""
        if not self.is_available():
            raise RuntimeError("Ncat nicht gefunden")

        try:
            args = [
                "-z",
                "-w",
                f"{max(timeout_seconds, 1)}s",
                host,
                str(port),
            ]

            result = run_nmap_tool("ncat", args, timeout_seconds=timeout_seconds + 5, capture_output=True)
            success = result.returncode == 0
            self.logger.debug(f"Ncat {host}:{port} {'erfolgreich' if success else 'fehlgeschlagen'}")
            return success
        except Exception as exc:
            self.logger.warning(f"Ncat Fehler fuer {host}:{port}: {exc}")
            return False

    def probe_service_banner(
        self,
        host: str,
        port: int,
        timeout_seconds: int = 5,
    ) -> Optional[str]:
        """Lese ein Service-Banner von einem Port, falls der Dienst eines sendet."""
        if not self.is_available():
            raise RuntimeError("Ncat nicht gefunden")

        try:
            args = [
                "--recv-only",
                "-w",
                f"{max(timeout_seconds, 1)}s",
                host,
                str(port),
            ]

            result = run_nmap_tool("ncat", args, timeout_seconds=timeout_seconds + 5, capture_output=True)

            if result.stdout:
                banner = result.stdout.strip()[:200]
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
        """Sende Daten und empfange eine Antwort."""
        if not self.is_available():
            raise RuntimeError("Ncat nicht gefunden")

        try:
            args = [
                "-w",
                f"{max(timeout_seconds, 1)}s",
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
        """Hoere auf einem Port und erfasse eingehende Verbindungen."""
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
                    line = process.stdout.readline() if process.stdout else ""
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
    """Batch-Probe mehrerer Ports mit Nmap-Status und Ncat-Banner."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.ncat = NetworkCat(logger)
        self.nmap_exe = find_nmap_tool("nmap")

    def scan_ports_with_nmap(
        self,
        host: str,
        ports: list[int],
        timeout_seconds: int = 5,
    ) -> dict[int, dict[str, Any]]:
        """Ermittle Portstatus mit Nmap, damit filtered/closed sichtbar bleibt."""
        if not self.nmap_exe:
            raise RuntimeError("Nmap nicht gefunden")

        port_string = ",".join(str(port) for port in ports)
        command = [
            self.nmap_exe,
            "-sT",
            "--max-retries",
            "1",
            "--initial-rtt-timeout",
            "500ms",
            "--max-rtt-timeout",
            f"{max(timeout_seconds, 1)}s",
            "-p",
            port_string,
            "-oX",
            "-",
            host,
        ]
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=max(timeout_seconds * len(ports) + 10, 20),
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip() or f"Nmap Exit Code {result.returncode}")

        parsed: dict[int, dict[str, Any]] = {
            port: {
                "connected": False,
                "state": "unknown",
                "reason": "",
                "service": "",
                "banner": None,
            }
            for port in ports
        }
        root = ET.fromstring(result.stdout)
        for port_node in root.findall("host/ports/port"):
            port_id = int(port_node.get("portid", "0"))
            state_node = port_node.find("state")
            service_node = port_node.find("service")
            state = state_node.get("state", "") if state_node is not None else "unknown"
            parsed[port_id] = {
                "connected": state == "open",
                "state": state,
                "reason": state_node.get("reason", "") if state_node is not None else "",
                "service": service_node.get("name", "") if service_node is not None else "",
                "banner": None,
            }
        return parsed

    def probe_ports(
        self,
        host: str,
        ports: list[int],
        timeout_seconds: int = 5,
    ) -> dict[int, dict[str, Any]]:
        """Probe mehrere Ports und bewahre den genauen Portstatus."""
        results = {}
        for port in ports:
            result = {
                "connected": False,
                "state": "closed_or_filtered",
                "reason": "tcp-connect-failed",
                "service": "",
                "banner": None,
            }
            try:
                if self.ncat.test_port_connectivity(host, port, timeout_seconds):
                    result["connected"] = True
                    result["state"] = "open"
                    result["reason"] = "tcp-connect"
                    result["banner"] = self.ncat.probe_service_banner(host, port, timeout_seconds)
            except Exception as exc:
                self.logger.warning(f"Probe Fehler Port {port}: {exc}")
            results[port] = result

        return results


def create_port_probe_report(
    host: str,
    probe_results: dict[int, dict[str, Any]],
    output_path: Path,
) -> None:
    """Erstelle einen Port-Probe-Report."""
    connected = [p for p, r in probe_results.items() if r["connected"]]

    content = [
        "# Port-Probe Bericht",
        "",
        f"- Host: {host}",
        f"- Getestete Ports: {len(probe_results)}",
        f"- Offen: {len(connected)}",
        "",
        "## Port-Details",
        "",
    ]

    for port in sorted(probe_results.keys()):
        result = probe_results[port]
        state = result.get("state", "open" if result["connected"] else "unknown")
        reason = result.get("reason", "")
        service = result.get("service", "")
        banner = result.get("banner")

        content.append(f"### Port {port}")
        content.append(f"- Status: {'OPEN' if result['connected'] else state.upper()}")
        if reason:
            content.append(f"- Grund: {reason}")
        if service:
            content.append(f"- Service: {service}")
        if banner:
            content.append(f"- Banner: `{banner[:100]}`")
        content.append("")

    output_path.write_text("\n".join(content), encoding="utf-8")
