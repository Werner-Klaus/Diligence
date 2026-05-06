#!/usr/bin/env python3
"""
Nmap Scripts (NSE) Integration - Tiefere Service-Analyse.
FÃ¼hrt spezialisierte Nmap-Scripts fÃ¼r verschiedene Services aus.
"""

import json
import logging
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Optional

from nmap_suite import find_nmap_tool


# Vordefinierte Script-Profile fÃ¼r hÃ¤ufige Anwendungen
SCRIPT_PROFILES = {
    "home-services": {
        "description": "Sichere NSE-Analyse typischer Heimnetz-Dienste",
        "ports": [22, 53, 80, 139, 443, 445, 515, 631, 9100, 5000, 5357, "49152-49156"],
        "scripts": [
            "ssh-hostkey",
            "ssh-auth-methods",
            "http-title",
            "http-server-header",
            "http-headers",
            "ssl-cert",
            "ssl-enum-ciphers",
            "smb-protocols",
            "smb-os-discovery",
            "smb-security-mode",
            "dns-nsid",
        ],
    },
    "smb-basic": {
        "description": "SMB Basis-Analyse (Protokolle, OS, Security Mode)",
        "ports": [139, 445],
        "scripts": [
            "smb-protocols",
            "smb-os-discovery",
            "smb-security-mode",
        ],
    },
    "smb": {
        "description": "SMB/Windows Ressourcen-Analyse",
        "ports": [139, 445],
        "scripts": [
            "smb-protocols",
            "smb-os-discovery",
            "smb-security-mode",
            "smb-enum-shares",
            "smb-enum-users",
        ],
    },
    "smb-vuln": {
        "description": "SMB Sicherheitsluecken-Checks",
        "ports": [445],
        "scripts": [
            "smb-vuln-ms17-010",
            "smb-vuln-ms10-054",
            "smb-vuln-ms10-061",
        ],
    },
    "ssh": {
        "description": "SSH Security-Analyse",
        "ports": [22],
        "scripts": [
            "ssh-hostkey",
            "ssh-auth-methods",
            "ssh2-enum-algos",
            "ssh-rsa-key-exchange",
        ],
    },
    "http": {
        "description": "HTTP/HTTPS Web-Service-Analyse",
        "ports": [80, 443, 8080, 8443],
        "scripts": [
            "http-title",
            "http-version",
            "http-server-header",
            "http-headers",
            "http-robots.txt",
            "ssl-cert",
            "ssl-enum-ciphers",
            "https-redirect",
        ],
    },
    "dns": {
        "description": "DNS Service-Analyse",
        "ports": [53],
        "scripts": [
            "dns-nsid",
            "dns-cache-snoop",
            "dns-zone-transfer",
            "dns-recursion",
        ],
    },
    "ftp": {
        "description": "FTP Service-Analyse",
        "ports": [21],
        "scripts": [
            "ftp-anon",
            "ftp-bounce",
            "ftp-proftpd-backdoor",
            "ftp-vsftpd-backdoor",
        ],
    },
    "rdp": {
        "description": "RDP/Remote Desktop-Analyse",
        "ports": [3389],
        "scripts": [
            "rdp-enum-encryption",
            "rdp-ntlm-info",
            "ms-sql-info",
        ],
    },
    "mysql": {
        "description": "MySQL Database-Analyse",
        "ports": [3306],
        "scripts": [
            "mysql-info",
            "mysql-empty-password",
            "mysql-audit",
        ],
    },
    "mssql": {
        "description": "MSSQL Server-Analyse",
        "ports": [1433],
        "scripts": [
            "ms-sql-info",
            "ms-sql-empty-password",
            "ms-sql-dac",
        ],
    },
    "snmp": {
        "description": "SNMP Service-Analyse",
        "ports": [161],
        "scripts": [
            "snmp-info",
            "snmp-interfaces",
            "snmp-processes",
            "snmp-sysdescr",
        ],
    },
    "vulnerabilities": {
        "description": "Allgemeine SicherheitslÃ¼cken-PrÃ¼fung",
        "ports": [],
        "scripts": [
            "vulners",
            "vulscan",
            "ssl-cert-intaddr",
            "ssl-dh-params",
        ],
    },
}


class NmapScriptRunner:
    """FÃ¼hrt Nmap-Scripts (NSE) aus."""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.nmap_exe = find_nmap_tool("nmap")
    
    def is_available(self) -> bool:
        """PrÃ¼fe ob Nmap verfÃ¼gbar ist."""
        return self.nmap_exe is not None
    
    def get_available_scripts(self) -> list[str]:
        """
        Liste verfÃ¼gbare Nmap-Scripts auf.
        
        Returns:
            Liste der installierten Scripts
        """
        if not self.is_available():
            return []
        
        try:
            result = subprocess.run(
                [self.nmap_exe, "--script-help"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            # Einfache Heuristik: ZÃ¤hle Script-Zeilen
            scripts = [line.strip() for line in result.stdout.split("\n") if line.strip().startswith("smb-")]
            return scripts[:10]  # Top 10
        except Exception:
            return []
    
    def run_script_profile(
        self,
        host: str,
        profile: str,
        output_format: str = "xml",
    ) -> Optional[str]:
        """
        FÃ¼hre ein vordefiniertes Script-Profil aus.
        
        Args:
            host: Ziel-Host/IP
            profile: Profil-Name (smb, ssh, http, etc.)
            output_format: "xml" oder "text"
        
        Returns:
            Output oder None
        """
        if profile not in SCRIPT_PROFILES:
            self.logger.error(f"Unbekanntes Profil: {profile}")
            return None
        
        if not self.is_available():
            raise RuntimeError("Nmap nicht gefunden")
        
        profile_config = SCRIPT_PROFILES[profile]
        scripts = ",".join(profile_config["scripts"])
        ports = profile_config.get("ports", [])
        
        port_arg = ",".join(str(p) for p in ports) if ports else "1-65535"
        
        try:
            self.logger.info(f"Starte {profile} Script-Profil auf {host}")
            
            if output_format == "xml":
                output_file = f"nmap_scripts_{profile}_{host.replace('/', '_')}.xml"
                args = [
                    self.nmap_exe,
                    "-sV",
                    "-p",
                    port_arg,
                    f"--script={scripts}",
                    "-oX",
                    output_file,
                    host,
                ]
            else:
                args = [
                    self.nmap_exe,
                    "-sV",
                    "-p",
                    port_arg,
                    f"--script={scripts}",
                    host,
                ]
            
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=600,
            )
            
            self.logger.info(f"{profile} Profile abgeschlossen")
            return result.stdout if output_format == "text" else output_file
        except Exception as exc:
            self.logger.error(f"Script Fehler: {exc}")
            return None
    
    def run_custom_scripts(
        self,
        host: str,
        scripts: list[str],
        ports: list[int | str],
        timeout_seconds: int = 300,
        skip_host_discovery: bool = False,
    ) -> dict[str, Any]:
        """
        FÃ¼hre Custom Scripts auf spezifischen Ports aus.
        
        Args:
            host: Ziel-Host
            scripts: Liste von Script-Namen
            ports: Liste von Port-Nummern
            timeout_seconds: Timeout
        
        Returns:
            dict mit Script-Ergebnissen
        """
        if not self.is_available():
            raise RuntimeError("Nmap nicht gefunden")
        
        results = {}
        script_string = ",".join(scripts)
        port_string = ",".join(str(p) for p in ports) if ports else "1-65535"
        
        try:
            self.logger.info(f"FÃ¼hre {len(scripts)} Scripts auf {host}:{port_string} aus")
            
            args = [
                self.nmap_exe,
                "-sT",
                "-sV",
                "-p",
                port_string,
                f"--script={script_string}",
                "-oX",
                "-",  # XML zu stdout
            ]
            if skip_host_discovery:
                args.append("-Pn")
            args.append(host)
            
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )

            if result.returncode != 0:
                self.logger.warning(f"Nmap Script Exit Code: {result.returncode}")
                return {
                    "error": result.stderr.strip() or result.stdout.strip(),
                    "returncode": result.returncode,
                }
            
            # Parse XML Output
            if result.stdout:
                try:
                    root = ET.fromstring(result.stdout)
                    results = self._parse_script_output(root, scripts)
                except Exception as exc:
                    self.logger.warning(f"XML Parse Fehler: {exc}")
                    results = {"raw_output": result.stdout}
            
            return results
        except Exception as exc:
            self.logger.error(f"Custom Scripts Fehler: {exc}")
            return {}

    def find_hosts_with_open_ports(
        self,
        target: str,
        ports: list[int | str],
        timeout_seconds: int = 180,
        skip_host_discovery: bool = False,
    ) -> list[dict[str, Any]]:
        """Finde Hosts im Zielbereich mit offenen Ports."""
        if not self.is_available():
            raise RuntimeError("Nmap nicht gefunden")

        port_string = ",".join(str(p) for p in ports)
        args = [
            self.nmap_exe,
            "-sT",
            "-p",
            port_string,
            "--open",
            "-oX",
            "-",
        ]
        if skip_host_discovery:
            args.append("-Pn")
        args.append(target)

        self.logger.info(f"Suche offene Ports {port_string} in {target}")
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip() or f"Nmap Exit Code {result.returncode}")

        root = ET.fromstring(result.stdout)
        hosts: list[dict[str, Any]] = []
        for host in root.findall("host"):
            addresses = host.findall("address")
            ip = next((a.get("addr", "") for a in addresses if a.get("addrtype") in {"ipv4", "ipv6"}), "")
            mac = next((a.get("addr", "") for a in addresses if a.get("addrtype") == "mac"), "")
            vendor = next((a.get("vendor", "") for a in addresses if a.get("addrtype") == "mac"), "")
            open_ports: list[str] = []
            for port in host.findall("ports/port"):
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    open_ports.append(port.get("portid", ""))
            if ip and open_ports:
                hosts.append({
                    "ip": ip,
                    "mac": mac,
                    "vendor": vendor,
                    "open_ports": open_ports,
                })
        return hosts
    
    def _parse_script_output(self, root: ET.Element, scripts: list[str]) -> dict[str, Any]:
        """Parse Nmap Script XML Output."""
        results: dict[str, Any] = {
            "host": {},
            "ports": {},
            "scripts": {},
        }
        
        for host in root.findall("host"):
            status = host.find("status")
            if status is not None:
                results["host"]["state"] = status.get("state", "")

            for address in host.findall("address"):
                if address.get("addrtype") in {"ipv4", "ipv6"}:
                    results["host"]["ip"] = address.get("addr", "")
                elif address.get("addrtype") == "mac":
                    results["host"]["mac"] = address.get("addr", "")
                    results["host"]["vendor"] = address.get("vendor", "")

            for port in host.findall("ports/port"):
                port_id = port.get("portid", "?")
                port_state = port.find("state")
                service = port.find("service")
                results["ports"][port_id] = {
                    "protocol": port.get("protocol", ""),
                    "state": port_state.get("state", "") if port_state is not None else "",
                    "service": service.get("name", "") if service is not None else "",
                    "product": service.get("product", "") if service is not None else "",
                    "version": service.get("version", "") if service is not None else "",
                }
                
                for script in port.findall("script"):
                    script_name = script.get("id", "unknown")
                    output = script.get("output", "")
                    
                    if script_name not in results["scripts"]:
                        results["scripts"][script_name] = {}
                    
                    results["scripts"][script_name][port_id] = output.strip()
        
        return results
    
    def smb_analysis(
        self,
        host: str,
        ports: Optional[list[int | str]] = None,
        scripts: Optional[list[str]] = None,
        timeout_seconds: int = 180,
        skip_host_discovery: bool = False,
    ) -> dict[str, Any]:
        """
        Spezialisierte SMB-Analyse.

        Returns:
            dict mit SMB-Informationen
        """
        self.logger.info(f"Starte SMB-Analyse fuer {host}")
        selected_scripts = scripts or SCRIPT_PROFILES["smb-basic"]["scripts"]
        selected_ports = ports or SCRIPT_PROFILES["smb-basic"]["ports"]
        results = self.run_custom_scripts(
            host,
            selected_scripts,
            selected_ports,
            timeout_seconds=timeout_seconds,
            skip_host_discovery=skip_host_discovery,
        )
        return summarize_smb_results(host, selected_ports, selected_scripts, results)

    def ssl_analysis(self, host: str, port: int = 443, timeout_seconds: int = 120) -> dict[str, Any]:
        """
        Spezialisierte SSL/TLS-Analyse.
        
        Returns:
            dict mit SSL-Informationen
        """
        self.logger.info(f"Starte SSL-Analyse fuer {host}:{port}")
        
        try:
            args = [
                self.nmap_exe,
                "-sT",
                "-p",
                str(port),
                "--script=ssl-cert,ssl-enum-ciphers,ssl-dh-params",
                "-oX",
                "-",
                host,
            ]
            
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )

            if result.returncode != 0:
                error = result.stderr.strip() or result.stdout.strip() or f"Nmap Exit Code {result.returncode}"
                return {
                    "error": error,
                    "output": result.stdout,
                    "stderr": result.stderr,
                    "port": port,
                }
            
            return {
                "output": result.stdout,
                "port": port,
            }
        except Exception as exc:
            self.logger.error(f"SSL-Analyse Fehler: {exc}")
            return {"error": str(exc)}
    
    def service_fingerprint(self, host: str, port: int) -> dict[str, Any]:
        """
        Service-Fingerprinting fÃ¼r einen Port.
        
        Returns:
            dict mit Service-Details
        """
        self.logger.info(f"Fingerprint {host}:{port}")
        
        try:
            args = [
                self.nmap_exe,
                "-p",
                str(port),
                "--script=service-*",
                "-sV",
                "-oX",
                "-",
                host,
            ]
            
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=120,
            )
            
            return {"fingerprint": result.stdout}
        except Exception as exc:
            self.logger.error(f"Fingerprint Fehler: {exc}")
            return {"error": str(exc)}


def create_script_analysis_report(
    host: str,
    profile: str,
    script_results: dict[str, Any],
    output_path: Path,
) -> None:
    """Erstelle einen Script-Analyse-Report."""
    profile_config = SCRIPT_PROFILES.get(profile, {})
    description = profile_config.get("description", profile)
    
    content = [
        f"# Nmap Script Analyse - {profile.upper()}",
        "",
        f"- Host: {host}",
        f"- Profil: {description}",
        f"- Zeitstempel: {Path(output_path).stem}",
        "",
        "## Ergebnisse",
        "",
    ]
    
    scripts = script_results.get("scripts", script_results) if isinstance(script_results, dict) else {}

    if not scripts:
        content.append("Keine Ergebnisse gefunden.")
    else:
        for script, results in scripts.items():
            content.append(f"### {script}")
            content.append("")
            
            if isinstance(results, dict):
                for port, output in results.items():
                    content.append(f"**Port {port}:**")
                    content.append(f"```")
                    content.append(output[:500])  # Max 500 chars
                    if len(output) > 500:
                        content.append("... (gekÃ¼rzt)")
                    content.append("```")
                    content.append("")
            else:
                content.append(f"{results}")
            
            content.append("")
    
    output_path.write_text("\n".join(content), encoding="utf-8")


def summarize_smb_results(
    host: str,
    ports: list[int | str],
    scripts: list[str],
    script_results: dict[str, Any],
) -> dict[str, Any]:
    """Extrahiere lesbare SMB-Kernaussagen aus NSE-Ergebnissen."""
    outputs = script_results.get("scripts", {}) if isinstance(script_results, dict) else {}
    combined = "\n".join(
        output
        for per_port in outputs.values()
        if isinstance(per_port, dict)
        for output in per_port.values()
        if output
    )

    summary = {
        "host": host,
        "ports": [str(port) for port in ports],
        "scripts": scripts,
        "protocols": [],
        "os": "-",
        "computer_name": "-",
        "domain": "-",
        "shares": [],
        "users": [],
        "raw_results": script_results,
    }
    if isinstance(script_results, dict) and script_results.get("error"):
        summary["error"] = script_results["error"]
        summary["returncode"] = script_results.get("returncode")

    for line in combined.splitlines():
        clean = line.strip()
        lower = clean.lower()
        if not clean:
            continue
        if "smbv" in lower or "smb 2" in lower or "smb 3" in lower:
            summary["protocols"].append(clean)
        elif lower.startswith("os:"):
            summary["os"] = clean.split(":", 1)[1].strip()
        elif lower.startswith("computer name:"):
            summary["computer_name"] = clean.split(":", 1)[1].strip()
        elif lower.startswith("domain name:") or lower.startswith("workgroup:"):
            summary["domain"] = clean.split(":", 1)[1].strip()
        elif "anonymous access" in lower or "share:" in lower:
            summary["shares"].append(clean.lstrip("|_ ").strip())
        elif "user:" in lower:
            summary["users"].append(clean.lstrip("|_ ").strip())

    return summary


def create_smb_report(smb_data: dict[str, Any], output_path: Path) -> None:
    """Schreibe einen kompakten SMB-Markdown-Report."""
    content = [
        "# SMB Analyse",
        "",
        f"- Host: {smb_data.get('host', '-')}",
        f"- Ports: {', '.join(smb_data.get('ports', []))}",
        f"- OS: {smb_data.get('os', '-')}",
        f"- Computer Name: {smb_data.get('computer_name', '-')}",
        f"- Domain/Workgroup: {smb_data.get('domain', '-')}",
        f"- Scripts: {', '.join(smb_data.get('scripts', []))}",
        "",
        "## Protokolle",
        "",
    ]

    if smb_data.get("error"):
        content.extend(["## Fehler", "", str(smb_data["error"]), ""])

    protocols = smb_data.get("protocols", [])
    content.extend([f"- {item}" for item in protocols] if protocols else ["Keine Protokoll-Details gefunden."])
    content.extend(["", "## Shares", ""])

    shares = smb_data.get("shares", [])
    content.extend([f"- {item}" for item in shares] if shares else ["Keine Share-Details gefunden."])
    content.extend(["", "## Benutzer", ""])

    users = smb_data.get("users", [])
    content.extend([f"- {item}" for item in users] if users else ["Keine Benutzer-Details gefunden."])

    output_path.write_text("\n".join(content).rstrip() + "\n", encoding="utf-8")

