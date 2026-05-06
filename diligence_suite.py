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


def parse_port_list(value: str) -> list[int | str]:
    """Komma-Portliste parsen; Ranges wie 49152-49156 bleiben erhalten."""
    ports: list[int | str] = []
    for item in value.split(","):
        part = item.strip()
        if not part:
            continue
        ports.append(part if "-" in part else int(part))
    return ports


def default_report_path(command: str, filename: str) -> Path:
    """Erzeuge einen Reportpfad im passenden Unterordner."""
    path = APP_DIR / "reports" / command / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def selected_report_path(output: str | None, command: str, filename: str) -> Path:
    """Nutze --output oder den Default-Unterordner fuer ein Kommando."""
    path = Path(output) if output else default_report_path(command, filename)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def cmd_verify_tools(args: argparse.Namespace) -> int:
    """Verifiziere verfuegbare Tools."""
    logger = setup_logging()
    
    print("\n=== Nmap Suite Tools Verfuegbarkeit ===\n")
    status = verify_nmap_suite()
    
    for tool, available in status.items():
        symbol = "OK" if available else "NO"
        print(f"[{symbol}] {tool}")
    
    available_count = sum(1 for v in status.values() if v)
    print(f"\nVerfuegbar: {available_count}/{len(status)}")
    
    return 0


def cmd_ping(args: argparse.Namespace) -> int:
    """Fuehre Nping-Scans durch."""
    logger = setup_logging(args.log_level)
    
    if not args.targets:
        print("Fehler: --targets erforderlich", file=sys.stderr)
        return 1
    
    targets = args.targets.split(",")
    
    print(f"\nPinge {len(targets)} Host(s)...")
    
    scanner = NpingScanner(logger)
    if not scanner.is_available():
        print("Fehler: Nping nicht verfuegbar", file=sys.stderr)
        return 1
    
    results = scanner.ping_hosts(targets, count=args.count)
    
    # Ausgabe
    reachable = [t for t, r in results.items() if r]
    unreachable = [t for t, r in results.items() if not r]
    
    print(f"\nErgebnisse:")
    print(f"  Erreichbar: {len(reachable)}")
    print(f"  Nicht erreichbar: {len(unreachable)}")
    
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = selected_report_path(args.output, "ping", f"ping_{stamp}.md")
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
        print("Fehler: Ndiff nicht verfuegbar", file=sys.stderr)
        return 1
    
    differences = comparator.parse_scan_differences(old_path, new_path)
    
    print(f"\nUnterschiede:")
    print(f"  Neue Hosts: {len(differences['new_hosts'])}")
    print(f"  Entfernte Hosts: {len(differences['gone_hosts'])}")
    print(f"  Geaenderte Hosts: {len(differences['changed_hosts'])}")
    
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = selected_report_path(args.output, "compare", f"compare_{stamp}.md")
    create_comparison_report(old_path, new_path, report_path, logger)

    json_path = report_path.with_name(report_path.stem + ".json")
    export_comparison_json(differences, json_path)
    logger.info(f"Vergleichs-Reports gespeichert: {report_path}, {json_path}")
    
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
    
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = selected_report_path(args.output, "probe", f"probe_{safe_name(args.host)}_{stamp}.md")
    create_port_probe_report(args.host, results, report_path)
    logger.info(f"Port-Probe-Report gespeichert: {report_path}")
    
    return 0


def cmd_listen(args: argparse.Namespace) -> int:
    """Hoere auf eingehende Verbindungen."""
    logger = setup_logging(args.log_level)
    
    print(f"\nHoere auf Port {args.port} ({args.duration} Sekunden)...")
    
    ncat = NetworkCat(logger)
    if not ncat.is_available():
        print("Fehler: Ncat nicht verfuegbar", file=sys.stderr)
        return 1
    
    connections = ncat.listen_on_port(args.port, args.duration)
    
    print(f"\nVerbindungen erfasst: {len(connections)}")
    for i, conn in enumerate(connections[:10], 1):
        print(f"  {i}. {conn[:80]}")

    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = selected_report_path(args.output, "listen", f"listen_{args.port}_{stamp}.md")
    content = [
        "# Ncat Listen Report",
        "",
        f"- Port: {args.port}",
        f"- Dauer: {args.duration} Sekunden",
        f"- Verbindungen: {len(connections)}",
        "",
        "## Daten",
        "",
    ]
    content.extend([f"{index}. `{conn[:160]}`" for index, conn in enumerate(connections, 1)] or ["Keine Verbindungen erfasst."])
    report_path.write_text("\n".join(content) + "\n", encoding="utf-8")
    logger.info(f"Listen-Report gespeichert: {report_path}")
    
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
    ports = parse_port_list(args.ports) if args.ports else profile_config.get("ports", [])
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

        stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = selected_report_path(
            args.output,
            "scripts",
            f"scripts_{args.profile}_{safe_name(args.host)}_{stamp}.md",
        )
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

    ports = parse_port_list(args.ports)
    print(f"\nStarte SMB-Analyse fuer {args.host}:{','.join(str(port) for port in ports)}...")

    runner = NmapScriptRunner(logger)
    if not runner.is_available():
        print("Fehler: Nmap nicht verfuegbar", file=sys.stderr)
        return 1

    try:
        profile = SCRIPT_PROFILES["smb"] if args.deep else SCRIPT_PROFILES["smb-basic"]
        scripts = [s.strip() for s in args.scripts.split(",")] if args.scripts else profile["scripts"]
        smb_data = runner.smb_analysis(
            args.host,
            ports=ports,
            scripts=scripts,
            timeout_seconds=args.timeout,
            skip_host_discovery=args.skip_host_discovery,
        )

        print(f"\nSMB-Analyse Ergebnisse:")
        print(f"  Ports: {', '.join(smb_data.get('ports', []))}")
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
        suffix = ".json" if args.output and Path(args.output).suffix.lower() == ".json" else ".md"
        output_path = selected_report_path(args.output, "smb", f"smb_{safe_name(args.host)}_{stamp}{suffix}")
        if output_path.suffix.lower() == ".json":
            output_path.write_text(json.dumps(smb_data, indent=2, ensure_ascii=False), encoding="utf-8")
        else:
            create_smb_report(smb_data, output_path)
        logger.info(f"SMB-Report gespeichert: {output_path}")

        return 0
    except Exception as exc:
        print(f"Fehler: {exc}", file=sys.stderr)
        return 1


def create_smb_sweep_report(target: str, hosts: list[dict], analyses: list[dict], output_path: Path) -> None:
    """Schreibe einen kompakten SMB-Sweep-Report."""
    content = [
        "# SMB Sweep",
        "",
        f"- Ziel: {target}",
        f"- Hosts mit offenen SMB-Ports: {len(hosts)}",
        "",
        "## Treffer",
        "",
    ]
    if not hosts:
        content.append("Keine Hosts mit offenen SMB-Ports gefunden.")
    else:
        content.extend([
            "| IP | MAC | Hersteller | Offene Ports |",
            "| --- | --- | --- | --- |",
        ])
        for host in hosts:
            content.append(
                f"| {host.get('ip', '-')} | {host.get('mac', '-') or '-'} | "
                f"{host.get('vendor', '-') or '-'} | {', '.join(host.get('open_ports', []))} |"
            )

    content.extend(["", "## SMB-Details", ""])
    for data in analyses:
        content.extend([
            f"### {data.get('host', '-')}",
            "",
            f"- Ports: {', '.join(data.get('ports', []))}",
            f"- OS: {data.get('os', '-')}",
            f"- Computer Name: {data.get('computer_name', '-')}",
            f"- Domain/Workgroup: {data.get('domain', '-')}",
            f"- Scripts: {', '.join(data.get('scripts', []))}",
            "",
            "#### Protokolle",
            "",
        ])
        protocols = data.get("protocols", [])
        content.extend([f"- {item}" for item in protocols] if protocols else ["Keine Protokoll-Details gefunden."])
        if data.get("error"):
            content.extend(["", "#### Fehler", "", str(data["error"])])
        content.append("")

    output_path.write_text("\n".join(content).rstrip() + "\n", encoding="utf-8")


def cmd_smb_sweep(args: argparse.Namespace) -> int:
    """SMB-Analyse fuer alle Hosts mit offenen SMB-Ports in einem Zielnetz."""
    logger = setup_logging(args.log_level)
    ports = parse_port_list(args.ports)
    runner = NmapScriptRunner(logger)
    if not runner.is_available():
        print("Fehler: Nmap nicht verfuegbar", file=sys.stderr)
        return 1

    print(f"\nSuche SMB-Hosts in {args.target} auf Ports {','.join(str(port) for port in ports)}...")
    try:
        hosts = runner.find_hosts_with_open_ports(
            args.target,
            ports,
            timeout_seconds=args.discovery_timeout,
            skip_host_discovery=args.skip_host_discovery,
        )
        print(f"Gefunden: {len(hosts)} Host(s) mit offenen SMB-Ports")

        profile = SCRIPT_PROFILES["smb"] if args.deep else SCRIPT_PROFILES["smb-basic"]
        scripts = [s.strip() for s in args.scripts.split(",")] if args.scripts else profile["scripts"]
        analyses = []
        for index, host in enumerate(hosts, 1):
            ip = host["ip"]
            print(f"  [{index}/{len(hosts)}] SMB-Analyse: {ip}")
            analyses.append(runner.smb_analysis(
                ip,
                ports=ports,
                scripts=scripts,
                timeout_seconds=args.timeout,
                skip_host_discovery=args.skip_host_discovery,
            ))

        stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        suffix = ".json" if args.output and Path(args.output).suffix.lower() == ".json" else ".md"
        output_path = selected_report_path(args.output, "smb_sweep", f"smb_sweep_{safe_name(args.target)}_{stamp}{suffix}")
        if output_path.suffix.lower() == ".json":
            output_path.write_text(json.dumps({"target": args.target, "hosts": hosts, "analyses": analyses}, indent=2, ensure_ascii=False), encoding="utf-8")
        else:
            create_smb_sweep_report(args.target, hosts, analyses, output_path)
        logger.info(f"SMB-Sweep-Report gespeichert: {output_path}")
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
    print(f"\nStarte SSL-Analyse fuer {args.host}:{port}...")
    
    runner = NmapScriptRunner(logger)
    if not runner.is_available():
        print("Fehler: Nmap nicht verfuegbar", file=sys.stderr)
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
        
        stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = selected_report_path(args.output, "ssl", f"ssl_{safe_name(args.host)}_{port}_{stamp}.txt")
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
  python diligence_suite.py verify                  # Tools pruefen
  python diligence_suite.py ping --targets 192.168.1.1,192.168.1.2
  python diligence_suite.py compare --old scan1.xml --new scan2.xml
  python diligence_suite.py probe --host 192.168.1.1 --ports 22,80,443
  python diligence_suite.py listen --port 5000 --duration 30
  python diligence_suite.py scripts --host 192.168.178.20 --profile home-services
  python diligence_suite.py scripts --host 192.168.178.20 --profile smb-basic
  python diligence_suite.py smb --host 192.168.178.20
  python diligence_suite.py smb-sweep --target 192.168.178.0/24
  python diligence_suite.py smb --host 192.168.178.20 --deep
  python diligence_suite.py ssl --host 192.168.1.1
        """,
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Befehl")
    
    # verify
    subparsers.add_parser("verify", help="Verifiziere verfuegbare Tools")
    
    # ping
    ping_parser = subparsers.add_parser("ping", help="Nping - Hosts pingen")
    ping_parser.add_argument("--targets", required=True, help="Komma-separierte Host-Liste")
    ping_parser.add_argument("--count", type=int, default=3, help="Ping-Versuche pro Host")
    ping_parser.add_argument("--output", help="Pfad fuer Ping-Report")
    ping_parser.add_argument("--log-level", default="INFO", help="Log-Level")
    
    # compare
    compare_parser = subparsers.add_parser("compare", help="Ndiff - Scans vergleichen")
    compare_parser.add_argument("--old", required=True, help="Alte XML-Datei")
    compare_parser.add_argument("--new", required=True, help="Neue XML-Datei")
    compare_parser.add_argument("--output", help="Pfad fuer Vergleich-Report")
    compare_parser.add_argument("--log-level", default="INFO", help="Log-Level")
    
    # probe
    probe_parser = subparsers.add_parser("probe", help="Ncat - Ports proben")
    probe_parser.add_argument("--host", required=True, help="Ziel-Host")
    probe_parser.add_argument("--ports", required=True, help="Komma-separierte Port-Liste")
    probe_parser.add_argument("--timeout", type=int, default=5, help="Timeout pro Port")
    probe_parser.add_argument("--output", help="Pfad fuer Port-Probe-Report")
    probe_parser.add_argument("--log-level", default="INFO", help="Log-Level")
    
    # listen
    listen_parser = subparsers.add_parser("listen", help="Ncat - Auf Port abhoeren")
    listen_parser.add_argument("--port", type=int, required=True, help="Port zum Abhoeren")
    listen_parser.add_argument("--duration", type=int, default=30, help="Abhoer-Dauer in Sekunden")
    listen_parser.add_argument("--output", help="Pfad fuer Listen-Report")
    listen_parser.add_argument("--log-level", default="INFO", help="Log-Level")
    
    # scripts
    scripts_parser = subparsers.add_parser("scripts", help="Nmap Scripts - Service-Analyse")
    scripts_parser.add_argument("--host", required=True, help="Ziel-Host")
    scripts_parser.add_argument("--profile", required=True, choices=sorted(SCRIPT_PROFILES.keys()), help="Script-Profil")
    scripts_parser.add_argument("--ports", help="Komma-separierte Portliste, Ranges erlaubt, ueberschreibt Profil-Ports")
    scripts_parser.add_argument("--timeout", type=int, default=300, help="Timeout in Sekunden")
    scripts_parser.add_argument("--skip-host-discovery", action="store_true", help="Nmap -Pn setzen")
    scripts_parser.add_argument("--output", help="Pfad fuer Script-Report")
    scripts_parser.add_argument("--log-level", default="INFO", help="Log-Level")
    
    # smb
    smb_parser = subparsers.add_parser("smb", help="SMB/Windows Analyse")
    smb_parser.add_argument("--host", required=True, help="Ziel-Host")
    smb_parser.add_argument("--ports", default="139,445", help="Komma-separierte SMB-Portliste (default: 139,445)")
    smb_parser.add_argument("--deep", action="store_true", help="Zusaetzlich Shares/Users abfragen")
    smb_parser.add_argument("--scripts", help="Komma-separierte NSE-Scripts, ueberschreibt basic/deep")
    smb_parser.add_argument("--timeout", type=int, default=180, help="Timeout in Sekunden")
    smb_parser.add_argument("--skip-host-discovery", action="store_true", help="Nmap -Pn setzen")
    smb_parser.add_argument("--output", help="Pfad fuer SMB-Report")
    smb_parser.add_argument("--log-level", default="INFO", help="Log-Level")

    # smb-sweep
    smb_sweep_parser = subparsers.add_parser("smb-sweep", help="SMB-Analyse fuer alle SMB-Hosts im Zielnetz")
    smb_sweep_parser.add_argument("--target", required=True, help="Zielnetz oder Host, z. B. 192.168.178.0/24")
    smb_sweep_parser.add_argument("--ports", default="139,445", help="Komma-separierte SMB-Portliste (default: 139,445)")
    smb_sweep_parser.add_argument("--deep", action="store_true", help="Zusaetzlich Shares/Users abfragen")
    smb_sweep_parser.add_argument("--scripts", help="Komma-separierte NSE-Scripts, ueberschreibt basic/deep")
    smb_sweep_parser.add_argument("--timeout", type=int, default=180, help="Timeout pro SMB-Host in Sekunden")
    smb_sweep_parser.add_argument("--discovery-timeout", type=int, default=300, help="Timeout fuer SMB-Hostsuche in Sekunden")
    smb_sweep_parser.add_argument("--skip-host-discovery", action="store_true", help="Nmap -Pn setzen")
    smb_sweep_parser.add_argument("--output", help="Pfad fuer SMB-Sweep-Report")
    smb_sweep_parser.add_argument("--log-level", default="INFO", help="Log-Level")
    
    # ssl
    ssl_parser = subparsers.add_parser("ssl", help="SSL/TLS Analyse")
    ssl_parser.add_argument("--host", required=True, help="Ziel-Host")
    ssl_parser.add_argument("--port", type=int, help="HTTPS Port (default: 443)")
    ssl_parser.add_argument("--output", help="Pfad fuer SSL-Report")
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
        "smb-sweep": cmd_smb_sweep,
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

