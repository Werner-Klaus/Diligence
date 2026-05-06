#!/usr/bin/env python3
"""
Nmap Suite Tools Integration für Diligence.
Nping, Ndiff, Ncat, und weitere Nmap-Werkzeuge.
"""

import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional


NMAP_SUITE_TOOLS = {
    "nmap": "Hauptscanning-Tool",
    "nping": "Echtzeit Ping / Erreichbarkeitsprüfung",
    "ndiff": "Scan-Vergleich für zeitliche Änderungen",
    "ncat": "Netzwerkverbindungs- und Datentransfer-Tool",
}


def find_nmap_tool(tool_name: str) -> Optional[str]:
    """Suche nach einem Nmap-Suite-Tool im System."""
    # Versuche im PATH
    found = shutil.which(tool_name)
    if found:
        return found
    
    # Windows-spezifische Pfade
    common_paths = [
        Path(f"C:\\Program Files (x86)\\Nmap\\{tool_name}.exe"),
        Path(f"C:\\Program Files\\Nmap\\{tool_name}.exe"),
    ]
    
    for candidate in common_paths:
        if candidate.exists():
            return str(candidate)
    
    return None


def verify_nmap_suite() -> dict[str, bool]:
    """Prüfe Verfügbarkeit aller Nmap-Suite-Tools."""
    results = {}
    for tool in NMAP_SUITE_TOOLS.keys():
        results[tool] = find_nmap_tool(tool) is not None
    return results


def get_tool_version(tool_name: str) -> Optional[str]:
    """Ermittle die Version eines Nmap-Suite-Tools."""
    tool_path = find_nmap_tool(tool_name)
    if not tool_path:
        return None
    
    try:
        result = subprocess.run(
            [tool_path, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.split("\n")[0] if result.stdout else None
    except Exception:
        return None


def run_nmap_tool(
    tool_name: str,
    args: list[str],
    timeout_seconds: int = 300,
    capture_output: bool = False,
) -> subprocess.CompletedProcess:
    """
    Führe ein Nmap-Suite-Tool aus.
    
    Args:
        tool_name: Name des Tools (nmap, nping, ndiff, ncat)
        args: Argumente für das Tool
        timeout_seconds: Timeout in Sekunden
        capture_output: Erfasse stdout/stderr
    
    Returns:
        subprocess.CompletedProcess
    """
    tool_path = find_nmap_tool(tool_name)
    if not tool_path:
        raise RuntimeError(f"{tool_name} nicht gefunden. Installiere die Nmap Suite.")
    
    command = [tool_path] + args
    kwargs = {
        "timeout": timeout_seconds,
        "check": False,
    }
    
    if capture_output:
        kwargs["capture_output"] = True
        kwargs["text"] = True
    
    return subprocess.run(command, **kwargs)


if __name__ == "__main__":
    print("=== Nmap Suite Tools Verfügbarkeit ===\n")
    status = verify_nmap_suite()
    for tool, available in status.items():
        symbol = "✓" if available else "✗"
        version = get_tool_version(tool) if available else "-"
        print(f"[{symbol}] {tool:10} {NMAP_SUITE_TOOLS[tool]:40} {version}")
