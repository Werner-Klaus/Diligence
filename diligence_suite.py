#!/usr/bin/env python3
"""
Diligence Suite - Erweiterte Nmap-Integration.
Nmap, Nping, Ndiff, Ncat in einer Anwendung.
"""

import argparse
import datetime as dt
import json
import logging
import sys
from pathlib import Path

from nmap_suite import verify_nmap_suite
from ping_scanner import NpingScanner, create_ping_report
from scan_comparison import ScanComparator, create_comparison_report, export_comparison_json
from network_tools import NetworkCat, PortProber, create_port_probe_report
from nmap_scripts import NmapScriptRunner, SCRIPT_PROFILES, create_script_analysis_report, create_smb_report


APP_DIR = Path(__file__).resolve().parent


def setup_logging(log_level: str = "INFO") -> logging.Logger:
    """Konfiguriere Logging."""
    logger = logging.getLogger("DiligenceSuite")
    logger.handlers.clear()
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    return logger


def safe_name(value: str) -> str:
    """Dateiname aus Host/IP erzeugen."""
    return value.replace("\\", "_").replace("/", "_").replace(":", "_").replace(" ", "_")


def cmd_verify_tools(args: argparse.Namespace) -> int:
    """Verifiziere verfÃ¼gbare Tools."""
    logger = setup_logging()
    
    print("\n=== Nmap Suite Tools VerfÃ¼gbarkeit ===\n")
    status = verify_nmap_suite()
    
    for tool, available in status.items():
        symbol = "âœ“" if available else "âœ—"
        print(f"[{symbol}] {tool}")
    
    available_count = sum(1 for v in status.values() if v)
    print(f"\nVerfÃ¼gbar: {available_count}/{len(status)}")
    
    return 0


def cmd_ping(args: argparse.Namespace) -> int:
    """FÃ¼hre Nping-Scans durch."""
    logger = setup_logging(args.log_level)
    
    if not args.targets:
        print("Fehler: --targets erforderlich", file=sys.stderr)
        return 1
    
    targets = args.targets.split(",")
    
    print(f"\nPinge {len(targets)} Host(s)...")
    
    scanner = NpingScanner(logger)
    if not scanner.is_available():
        print("Fehler: Nping nicht verfÃ¼gbar", file=sys.stderr)
        return 1
    
    results = scanner.ping_hosts(targets, count=args.count)
    
    # Ausgabe
    reachable = [t for t, r in results.items() if r]
    unreachable = [t for t, r in results.items() if not r]
    
    print(f"\nErgebnisse:")
    print(f"  Erreichbar: {len(reachable)}")
    print(f"  Nicht erreichbar: {len(unreachable)}")
    
    # Report speichern
    if args.output:
        report_path = Path(args.output)
        create_ping_report(results, report_path)
        logger.info(f"Ping-Report gespeichert: {report_path}")
    
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    """Vergleiche zwei Scan-Dateien."""
    logger = setup_logging(args.log_level)
    
    old_path = Path(args.old)
    new_path = Path(args.new)
    
    if not old_path.exists() or not new_path.exists():
        print("Fehler: Eine oder beide XML-Dateien nicht gefunden", file=sys.stderr)
        return 1
    
    print(f"\nVergleiche Scans:")
    print(f"  Alt: {old_path.name}")
    print(f"  Neu: {new_path.name}")
    
    comparator = ScanComparator(logger)
    if not comparator.is_available():
        print("Fehler: Ndiff nicht verfÃ¼gbar", file=sys.stderr)
        return 1
    
    differences = comparator.parse_scan_differences(old_path, new_path)
    
    print(f"\nUnterschiede:")
    print(f"  Neue Hosts: {len(differences['new_hosts'])}")
    print(f"  Entfernte Hosts: {len(differences['gone_hosts'])}")
    print(f"  GeÃ¤nderte Hosts: {len(differences['changed_hosts'])}")
    
    # Reports speichern
    if args.output:
        report_path = Path(args.output)
        create_comparison_report(old_path, new_path, report_path, logger)
        
        json_path = report_path.with_name(report_path.stem + ".json")
        export_comparison_json(differences, json_path)
        logger.info(f"Vergleichs-Reports gespeichert")
    
    return 0


def cmd_probe(args: argparse.Namespace) -> int:
    """Probe Ports mit Ncat."""
    logger = setup_logging(args.log_level)
    
    if not args.host or not args.ports:
        print("Fehler: --host und --ports erforderlich", file=sys.stderr)
        return 1
    
    ports = [int(p.strip()) for p in args.ports.split(",")]
    
    print(f"\nProbe {len(ports)} Port(s) auf {args.host}...")
    
    prober = PortProber(logger)
    results = prober.probe_ports(args.host, ports, args.timeout)
    
    connected = [p for p, r in results.items() if r["connected"]]
    print(f"\nErgebnisse:")
    print(f"  Erreichbare Ports: {len(connected)}")
    
    for port in sorted(results.keys()):
        if results[port]["connected"]:
            banner = results[port].get("banner", "")
            banner_info = f" ({banner[:40]})" if banner else ""
            print(f"    {port}/{banner_info}")
    
    # Report speichern
    if args.output:
        report_path = Path(args.output)
        create_port_probe_report(args.host, results, report_path)
        logger.info(f"Port-Probe-Report gespeichert: {report_path}")
    
    return 0


def cmd_listen(args: argparse.Namespace) -> int:
    """HÃ¶re auf eingehende Verbindungen."""
    logger = setup_logging(args.log_level)
    
    print(f"\nHÃ¶re auf Port {args.port} ({args.duration} Sekunden)...")
    
    ncat = NetworkCat(logger)
    if not ncat.is_available():
        print("Fehler: Ncat nicht verfÃ¼gbar", file=sys.stderr)
        return 1
    
    connections = ncat.listen_on_port(args.port, args.duration)
    
    print(f"\nVerbindungen erfasst: {len(connections)}")
    for i, conn in enumerate(connections[:10], 1):
        print(f"  {i}. {conn[:80]}")
    
    return 0


def cmd_scripts(args: argparse.Namespace) -> int:
    """Fuehre Nmap-Script-Profile aus."""
    logger = setup_logging(args.log_level)

    if not args.host or not args.profile:
        print("Fehler: --host und --profile erforderlich", file=sys.stderr)
        return 1

    if args.profile not in SCRIPT_PROFILES:
        print(f"Fehler: Unbekanntes Profil: {args.profile}", file=sys.stderr)
        print(f"Verfuegbare Profile: {', '.join(SCRIPT_PROFILES.keys())}", file=sys.stderr)
        return 1

    profile_config = SCRIPT_PROFILES[args.profile]
    ports = [int(p.strip()) for p in args.ports.split(",")] if args.ports else profile_config.get("ports", [])
    print(f"\nStarte {args.profile} Script-Profil...")
    print(f"Beschreibung: {profile_config['description']}")
    print(f"Scripts: {len(profile_config['scripts'])}")
    print(f"Ports: {','.join(str(p) for p in ports) if ports else 'alle'}")

    runner = NmapScriptRunner(logger)
    if not runner.is_available():
        print("Fehler: Nmap nicht verfuegbar", file=sys.stderr)
        return 1

    try:
        results = runner.run_custom_scripts(
            args.host,
            profile_config["scripts"],
            ports,
            timeout_seconds=args.timeout,
            skip_host_discovery=args.skip_host_discovery,
        )

        print(f"\nScript-Profil abgeschlossen!")
        script_results = results.get("scripts", results) if isinstance(results, dict) else {}
        print(f"Ergebnisse: {len(script_results)} Scripts")

        for script_name in list(script_results.keys())[:5]:
            print(f"  - {script_name}")

        if args.output:
            report_path = Path(args.output)
            create_script_analysis_report(args.host, args.profile, results, report_path)
            logger.info(f"Script-Report gespeichert: {report_path}")

        return 0
    except Exception as exc:
        print(f"Fehler: {exc}", file=sys.stderr)
        return 1


def cmd_smb(args: argparse.Namespace) -> int:
    """Spezialisierte SMB-Analyse."""
    logger = setup_logging(args.log_level)

    if not args.host:
        print("Fehler: --host erforderlich", file=sys.stderr)
        return 1

    print(f"\nStarte SMB-Analyse fuer {args.host}:{args.port}...")

    runner = NmapScriptRunner(logger)
    if not runner.is_available():
        print("Fehler: Nmap nicht verfuegbar", file=sys.stderr)
        return 1

    try:
        profile = SCRIPT_PROFILES["smb"] if args.deep else SCRIPT_PROFILES["smb-basic"]
        scripts = [s.strip() for s in args.scripts.split(",")] if args.scripts else profile["scripts"]
        smb_data = runner.smb_analysis(
            args.host,
            port=args.port,
            scripts=scripts,
            timeout_seconds=args.timeout,
            skip_host_discovery=args.skip_host_discovery,
        )

        print(f"\nSMB-Analyse Ergebnisse:")
        print(f"  Port: {smb_data.get('port', '-')}")
        print(f"  OS: {smb_data.get('os', '-')}")
        print(f"  Computer: {smb_data.get('computer_name', '-')}")
        print(f"  Domain: {smb_data.get('domain', '-')}")
        print(f"  Protokolle: {len(smb_data.get('protocols', []))}")
        print(f"  Shares: {len(smb_data.get('shares', []))}")
        print(f"  Users: {len(smb_data.get('users', []))}")

        if smb_data.get('protocols'):
            print("\n  Protokolle:")
            for protocol in smb_data['protocols'][:5]:
                print(f"    - {protocol}")

        if smb_data.get('shares'):
            print("\n  Shares:")
            for share in smb_data['shares'][:5]:
                print(f"    - {share}")

        stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = Path(args.output) if args.output else APP_DIR / "reports" / f"smb_{safe_name(args.host)}_{stamp}.md"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if output_path.suffix.lower() == ".json":
            output_path.write_text(json.dumps(smb_data, indent=2, ensure_ascii=False), encoding="utf-8")
        else:
            create_smb_report(smb_data, output_path)
        logger.info(f"SMB-Report gespeichert: {output_path}")

        return 0
    except Exception as exc:
        print(f"Fehler: {exc}", file=sys.stderr)
        return 1

def cmd_ssl(args: argparse.Namespace) -> int:
    """Spezialisierte SSL/TLS-Analyse."""
    logger = setup_logging(args.log_level)
    
    if not args.host:
        print("Fehler: --host erforderlich", file=sys.stderr)
        return 1
    
    port = args.port or 443
    print(f"\nStarte SSL-Analyse fÃ¼r {args.host}:{port}...")
    
    runner = NmapScriptRunner(logger)
    if not runner.is_available():
        print("Fehler: Nmap nicht verfÃ¼gbar", file=sys.stderr)
        return 1
    
    try:
        ssl_data = runner.ssl_analysis(args.host, port)
        
        print(f"\nSSL-Analyse Ergebnisse:")
        if "error" in ssl_data:
            print(f"  Fehler: {ssl_data['error']}")
        else:
            print(f"  Port: {ssl_data.get('port', '?')}")
            output = ssl_data.get('output', '')
            lines = output.split('\n')[:10]
            for line in lines:
                if line.strip():
                    print(f"  {line[:80]}")
        
        if args.output:
            output_path = Path(args.output)
            output_path.write_text(ssl_data.get('output', ''), encoding="utf-8")
            logger.info(f"SSL-Report gespeichert: {output_path}")
        
        return 0
    except Exception as exc:
        print(f"Fehler: {exc}", file=sys.stderr)
        return 1


def main() -> int:
    """Hauptfunktion."""
    parser = argparse.ArgumentParser(
        description="Diligence Suite - Erweiterte Nmap-Integration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Beispiele:
  python diligence_suite.py verify                  # Tools prÃ¼fen
  python diligence_suite.py ping --targets 192.168.1.1,192.168.1.2
  python diligence_suite.py compare --old scan1.xml --new scan2.xml
  python diligence_suite.py probe --host 192.168.1.1 --ports 22,80,443
  python diligence_suite.py listen --port 5000 --duration 30
  python diligence_suite.py scripts --host 192.168.178.20 --profile smb-basic
  python diligence_suite.py smb --host 192.168.178.20
  python diligence_suite.py smb --host 192.168.178.20 --deep
  python diligence_suite.py ssl --host 192.168.1.1
        """,
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Befehl")
    
    # verify
    subparsers.add_parser("verify", help="Verifiziere verfÃ¼gbare Tools")
    
    # ping
    ping_parser = subparsers.add_parser("ping", help="Nping - Hosts pingen")
    ping_parser.add_argument("--targets", required=True, help="Komma-separierte Host-Liste")
    ping_parser.add_argument("--count", type=int, default=3, help="Ping-Versuche pro Host")
    ping_parser.add_argument("--output", help="Pfad fÃ¼r Ping-Report")
    ping_parser.add_argument("--log-level", default="INFO", help="Log-Level")
    
    # compare
    compare_parser = subparsers.add_parser("compare", help="Ndiff - Scans vergleichen")
    compare_parser.add_argument("--old", required=True, help="Alte XML-Datei")
    compare_parser.add_argument("--new", required=True, help="Neue XML-Datei")
    compare_parser.add_argument("--output", help="Pfad fÃ¼r Vergleich-Report")
    compare_parser.add_argument("--log-level", default="INFO", help="Log-Level")
    
    # probe
    probe_parser = subparsers.add_parser("probe", help="Ncat - Ports proben")
    probe_parser.add_argument("--host", required=True, help="Ziel-Host")
    probe_parser.add_argument("--ports", required=True, help="Komma-separierte Port-Liste")
    probe_parser.add_argument("--timeout", type=int, default=5, help="Timeout pro Port")
    probe_parser.add_argument("--output", help="Pfad fÃ¼r Port-Probe-Report")
    probe_parser.add_argument("--log-level", default="INFO", help="Log-Level")
    
    # listen
    listen_parser = subparsers.add_parser("listen", help="Ncat - Auf Port abhÃ¶ren")
    listen_parser.add_argument("--port", type=int, required=True, help="Port zum AbhÃ¶ren")
    listen_parser.add_argument("--duration", type=int, default=30, help="AbhÃ¶r-Dauer in Sekunden")
    listen_parser.add_argument("--log-level", default="INFO", help="Log-Level")
    
    # scripts
    scripts_parser = subparsers.add_parser("scripts", help="Nmap Scripts - Service-Analyse")
    scripts_parser.add_argument("--host", required=True, help="Ziel-Host")
    scripts_parser.add_argument("--profile", required=True, choices=sorted(SCRIPT_PROFILES.keys()), help="Script-Profil")
    scripts_parser.add_argument("--ports", help="Komma-separierte Portliste, ueberschreibt Profil-Ports")
    scripts_parser.add_argument("--timeout", type=int, default=300, help="Timeout in Sekunden")
    scripts_parser.add_argument("--skip-host-discovery", action="store_true", help="Nmap -Pn setzen")
    scripts_parser.add_argument("--output", help="Pfad fÃ¼r Script-Report")
    scripts_parser.add_argument("--log-level", default="INFO", help="Log-Level")
    
    # smb
    smb_parser = subparsers.add_parser("smb", help="SMB/Windows Analyse")
    smb_parser.add_argument("--host", required=True, help="Ziel-Host")
    smb_parser.add_argument("--port", type=int, default=445, help="SMB-Port (default: 445)")
    smb_parser.add_argument("--deep", action="store_true", help="Zusaetzlich Shares/Users abfragen")
    smb_parser.add_argument("--scripts", help="Komma-separierte NSE-Scripts, ueberschreibt basic/deep")
    smb_parser.add_argument("--timeout", type=int, default=180, help="Timeout in Sekunden")
    smb_parser.add_argument("--skip-host-discovery", action="store_true", help="Nmap -Pn setzen")
    smb_parser.add_argument("--output", help="Pfad fÃ¼r SMB-Report")
    smb_parser.add_argument("--log-level", default="INFO", help="Log-Level")
    
    # ssl
    ssl_parser = subparsers.add_parser("ssl", help="SSL/TLS Analyse")
    ssl_parser.add_argument("--host", required=True, help="Ziel-Host")
    ssl_parser.add_argument("--port", type=int, help="HTTPS Port (default: 443)")
    ssl_parser.add_argument("--output", help="Pfad fÃ¼r SSL-Report")
    ssl_parser.add_argument("--log-level", default="INFO", help="Log-Level")
    
    args = parser.parse_args()
    
    # Command-Dispatcher
    commands = {
        "verify": cmd_verify_tools,
        "ping": cmd_ping,
        "compare": cmd_compare,
        "probe": cmd_probe,
        "listen": cmd_listen,
        "scripts": cmd_scripts,
        "smb": cmd_smb,
        "ssl": cmd_ssl,
    }
    
    if not args.command:
        parser.print_help()
        return 0
    
    cmd_func = commands.get(args.command)
    if not cmd_func:
        print(f"Unbekannter Befehl: {args.command}", file=sys.stderr)
        return 1
    
    return cmd_func(args)


if __name__ == "__main__":
    raise SystemExit(main())

