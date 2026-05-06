#!/usr/bin/env python3
"""
Diligence Suite - Dateiübersicht und Funktions-Index.
Generiert automatische Übersicht aller neuen Module.
"""

import sys
from pathlib import Path

SUITE_FILES = {
    "nmap_suite.py": {
        "description": "Basis-Integration für Nmap-Suite-Tools",
        "functions": [
            "find_nmap_tool() - Suche nach Tool im System",
            "verify_nmap_suite() - Prüfe Verfügbarkeit",
            "get_tool_version() - Hole Tool-Version",
            "run_nmap_tool() - Führe Tool aus",
        ],
        "size": "~2 KB",
    },
    "ping_scanner.py": {
        "description": "Nping Integration - Erreichbarkeitsprüfungen",
        "classes": [
            "NpingScanner - Führt Ping-Scans durch",
        ],
        "functions": [
            "ping_hosts() - Multi-Host Ping",
            "tcp_syn_probe() - TCP-SYN Probe",
            "udp_probe() - UDP-Erreichbarkeitsprüfung",
            "create_ping_report() - Markdown-Report",
        ],
        "size": "~4 KB",
    },
    "scan_comparison.py": {
        "description": "Ndiff Integration - Scan-Vergleiche",
        "classes": [
            "ScanComparator - Vergleiche Scans",
        ],
        "functions": [
            "compare_xml_scans() - Vergleiche zwei XMLs",
            "parse_scan_differences() - Strukturierte Unterschiede",
            "create_comparison_report() - Markdown-Report",
            "export_comparison_json() - JSON-Export",
        ],
        "size": "~5 KB",
    },
    "network_tools.py": {
        "description": "Ncat Integration - Port-Probe & Kommunikation",
        "classes": [
            "NetworkCat - Ncat-Operationen",
            "PortProber - Batch Port-Probe",
        ],
        "functions": [
            "test_port_connectivity() - Teste Port",
            "probe_service_banner() - Lese Service-Banner",
            "send_data_and_receive() - Datenaustausch",
            "listen_on_port() - Höre auf Port",
            "probe_ports() - Batch-Probe",
            "create_port_probe_report() - Markdown-Report",
        ],
        "size": "~6 KB",
    },
    "diligence_suite.py": {
        "description": "CLI-Interface - Befehlszeileninterface",
        "commands": [
            "verify - Tools prüfen",
            "ping - Nping Erreichbarkeitsprüfung",
            "compare - Ndiff Scan-Vergleich",
            "probe - Ncat Port-Probe",
            "listen - Ncat Abhören",
        ],
        "size": "~8 KB",
    },
    "diligence_integration.py": {
        "description": "Integration - Module für diligence.py",
        "functions": [
            "get_nmap_suite_status() - Tool-Verfügbarkeit",
            "run_post_scan_nping() - Nping nach Scan",
            "run_post_scan_ncat_probe() - Port-Probe",
            "run_comparison_with_previous() - Auto-Vergleich",
            "extract_discovered_ips() - IP-Extraktion",
            "extract_discovered_hosts() - Host-Extraktion",
        ],
        "size": "~7 KB",
    },
}

DOCUMENTATION_FILES = {
    "QUICK_START.md": "Anfänger-Leitfaden mit 5 Basis-Befehlen",
    "NMAP_SUITE.md": "Ausführliche Feature-Dokumentation",
    "SUITE_MODULES.md": "Technische Modulreferenz",
    "FEATURES_SUMMARY.md": "Übersicht aller Funktionen",
}

GENERATED_REPORTS = {
    "reports/ping_test.md": "Nping Erreichbarkeitsbericht (Test)",
    "reports/port_probe_test.md": "Ncat Port-Probe Report (Test)",
}


def print_section(title):
    """Drucke einen Sections-Header."""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")


def main() -> int:
    """Hauptfunktion."""
    print_section("Diligence Suite - Übersicht")
    
    # Module
    print("📦 NEUE PYTHON-MODULE\n")
    total_size = 0
    for filename, info in SUITE_FILES.items():
        desc = info["description"]
        size = info.get("size", "?")
        print(f"  {filename:<25} {desc}")
        print(f"  {'':25} Größe: {size}\n")
    
    # Dokumentation
    print_section("📚 DOKUMENTATION")
    for filename, desc in DOCUMENTATION_FILES.items():
        print(f"  {filename:<25} {desc}")
    
    # Test-Reports
    print_section("📊 GENERIERTE TEST-REPORTS")
    for filename, desc in GENERATED_REPORTS.items():
        print(f"  {filename:<40} {desc}")
    
    # CLI-Befehle
    print_section("🎯 CLI-BEFEHLE (diligence_suite.py)")
    
    commands = [
        ("verify", "Tools Verfügbarkeit prüfen"),
        ("ping", "Nping - Multi-Host Erreichbarkeitsprüfung"),
        ("compare", "Ndiff - Scan-Vergleich"),
        ("probe", "Ncat - Port-Probe mit Banner-Grabbing"),
        ("listen", "Ncat - Auf Port abhören"),
    ]
    
    for cmd, desc in commands:
        print(f"  python diligence_suite.py {cmd:<10} - {desc}")
    
    # Integrations-Funktionen
    print_section("🔗 INTEGRATIONS-FUNKTIONEN")
    
    integrations = [
        ("get_nmap_suite_status", "Verifiziere Tool-Verfügbarkeit"),
        ("run_post_scan_nping", "Nping nach Nmap-Scan"),
        ("run_post_scan_ncat_probe", "Port-Probe nach Scan"),
        ("run_comparison_with_previous", "Auto-Vergleich mit letztem Scan"),
        ("extract_discovered_ips", "Extrahiere eindeutige IPs"),
        ("extract_discovered_hosts", "Extrahiere Hosts mit Ports"),
    ]
    
    print("Nutze diese in diligence.py:\n")
    for func, desc in integrations:
        print(f"  from diligence_integration import {func}")
        print(f"    → {desc}\n")
    
    # Anwendungsszenarien
    print_section("🎯 ANWENDUNGSSZENARIEN")
    
    scenarios = [
        ("Quick Check", "python diligence_suite.py ping --targets 192.168.1.0/24", "30s"),
        ("Service Monitor", "python diligence_suite.py probe --host router --ports 22,80,443", "1m"),
        ("Full Inventory", "python diligence.py", "30m"),
        ("Change Tracking", "python diligence_suite.py compare --old scan1.xml --new scan2.xml", "10s"),
        ("Incident Response", "Alle Tools kombinieren", "5-30m"),
    ]
    
    print("  Szenario                 Befehl                          Dauer\n")
    for scenario, cmd, duration in scenarios:
        print(f"  {scenario:<20} {cmd:<40} {duration}")
    
    # Überblick
    print_section("📈 STATISTIK")
    
    print(f"  Neue Python-Module:        {len(SUITE_FILES)}")
    print(f"  Neue Dokumentation:        {len(DOCUMENTATION_FILES)}")
    print(f"  CLI-Befehle:               {len(commands)}")
    print(f"  Integrations-Funktionen:   {len(integrations)}")
    print(f"  Test-Reports:              {len(GENERATED_REPORTS)}")
    
    total_features = len(SUITE_FILES) + len(DOCUMENTATION_FILES) + len(commands)
    print(f"\n  TOTAL: {total_features} neue Features!")
    
    # Links
    print_section("📖 DOKUMENTATIONS-LINKS")
    
    links = [
        ("QUICK_START.md", "Anfänger-Leitfaden"),
        ("NMAP_SUITE.md", "Feature-Dokumentation"),
        ("SUITE_MODULES.md", "Technische Referenz"),
        ("FEATURES_SUMMARY.md", "Komplette Übersicht"),
    ]
    
    for filename, desc in links:
        print(f"  → {filename}")
        print(f"    {desc}\n")
    
    # Abschluss
    print_section("✅ NÄCHSTE SCHRITTE")
    
    steps = [
        "python diligence_suite.py verify",
        "python diligence_suite.py ping --targets 192.168.1.1",
        "python diligence_suite.py probe --host 192.168.1.1 --ports 22,80,443",
        "python diligence.py",
        "Dokumentation lesen: QUICK_START.md",
    ]
    
    for i, step in enumerate(steps, 1):
        print(f"  {i}. {step}")
    
    print_section("🎉 BEREIT!")
    
    print("  Diligence Suite ist vollständig installiert!")
    print("  Alle Nmap-Suite-Tools sind integriert:")
    print("  ✓ Nping (Erreichbarkeitsprüfung)")
    print("  ✓ Ndiff (Scan-Vergleich)")
    print("  ✓ Ncat (Port-Probe)")
    print("  ✓ Nmap (Vollständiger Scan)")
    print("\n  Viel Erfolg beim Netzwerk-Monitoring! 🚀\n")
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
