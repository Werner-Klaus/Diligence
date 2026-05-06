# Diligence Suite - Neue Funktionen

Diligence wurde um erweiterte Nmap-Suite-Funktionen erweitert. Diese Dokumentation erklärt die neuen Module und deren Verwendung.

## Neue Module

### 1. **nmap_suite.py** - Basis-Integration
- Findet Nmap-Suite-Tools im System
- Verifiziert Verfügbarkeit (nmap, nping, ndiff, ncat)
- Stellt Tool-Launcher bereit

```python
from nmap_suite import verify_nmap_suite, find_nmap_tool, run_nmap_tool

# Tools prüfen
status = verify_nmap_suite()
# {'nmap': True, 'nping': True, 'ndiff': True, 'ncat': True}

# Tool ausführen
run_nmap_tool("nping", ["--icmp", "192.168.1.1"])
```

### 2. **ping_scanner.py** - Nping Integration
- Schnelle Erreichbarkeitsprüfungen (ICMP/TCP/UDP)
- Multi-Target Batch-Ping
- Port-spezifische Probes

**Klassen:**
- `NpingScanner` - Führt Ping-Scans durch
- Methoden: `ping_hosts()`, `tcp_syn_probe()`, `udp_probe()`

**Verwendung:**
```python
from ping_scanner import NpingScanner

scanner = NpingScanner(logger)
results = scanner.ping_hosts(["192.168.1.1", "192.168.1.2"])
# {'192.168.1.1': True, '192.168.1.2': False}
```

### 3. **scan_comparison.py** - Ndiff Integration
- Vergleicht zwei Nmap-Scan-Ergebnisse
- Identifiziert neue/entfernte Hosts
- Trackt Port-Änderungen

**Klassen:**
- `ScanComparator` - Scan-Vergleich

**Verwendung:**
```python
from scan_comparison import ScanComparator

comparator = ScanComparator(logger)
diff = comparator.parse_scan_differences(old_xml, new_xml)
# {'new_hosts': [...], 'gone_hosts': [...], 'changed_hosts': {...}}
```

### 4. **network_tools.py** - Ncat Integration
- Port-Erreichbarkeitsprüfung
- Service-Banner Grabbing
- Datenaustausch mit Remote-Diensten
- Verbindungs-Abhören

**Klassen:**
- `NetworkCat` - Ncat-Operationen
- `PortProber` - Batch Port-Probe

**Verwendung:**
```python
from network_tools import PortProber

prober = PortProber(logger)
results = prober.probe_ports("192.168.1.1", [22, 80, 443])
# {22: {'connected': True, 'banner': 'SSH-2.0-...'}, ...}
```

### 5. **diligence_suite.py** - CLI Interface
Standalone-Befehlszeileninterface für alle Suite-Tools.

**Befehle:**
```bash
python diligence_suite.py verify              # Tools prüfen
python diligence_suite.py ping ...            # Nping
python diligence_suite.py compare ...         # Ndiff
python diligence_suite.py probe ...           # Ncat Port-Probe
python diligence_suite.py listen ...          # Ncat Abhören
```

### 6. **diligence_integration.py** - Integration in Hauptanwendung
Funktionen zur Integration der Suite-Tools in die Hauptdatei `diligence.py`.

**Funktionen:**
- `get_nmap_suite_status()` - Tool-Verfügbarkeit
- `run_post_scan_nping()` - Nping nach Scan
- `run_post_scan_ncat_probe()` - Port-Probe
- `run_comparison_with_previous()` - Auto-Vergleich
- `extract_discovered_ips()` - IP-Extraktion
- `extract_discovered_hosts()` - Host-Extraktion

## Verwendungsszenarien

### Szenario 1: Pre-Scan Schnellprüfung
```powershell
# Welche Hosts sind online?
python diligence_suite.py ping --targets 192.168.178.0/24 --count 1 --output reports/online.md

# Dann vollständigen Scan durchführen
python diligence.py
```

### Szenario 2: Service-Monitoring
```powershell
# Wichtige Services täglich prüfen
python diligence_suite.py probe --host router --ports 22,80,443,9100 --output reports/services_today.md

# Mit gestern vergleichen
type reports/services_yesterday.md | compare with reports/services_today.md
```

### Szenario 3: Netzwerk-Trend-Analyse
```powershell
# Scans durchführen im Abstand von Tagen
python diligence.py  # Tag 1
# ... Tage warten ...
python diligence.py  # Tag 7

# Unterschiede analyse
python diligence_suite.py compare `
  --old reports/diligence_tag1.xml `
  --new reports/diligence_tag7.xml `
  --output reports/netzwerk_changes.md
```

### Szenario 4: Sicherheit-Incident Response
```powershell
# 1. Schnell Status erfassen
python diligence_suite.py ping --targets 192.168.0.0/16

# 2. Verdächtige Hosts auf Service-Banner prüfen
python diligence_suite.py probe --host verdächtig --ports 1-100

# 3. Mit Baseline vergleichen
python diligence_suite.py compare --old baseline.xml --new incident.xml
```

## Konfiguration

### config.json - Neue Sektionen

```json
{
  "nping": {
    "enabled": true,
    "auto_ping_discovered_hosts": false,
    "ping_count": 3,
    "timeout_ms": 5000
  },
  "ndiff": {
    "enabled": true,
    "auto_compare_with_last": false,
    "keep_comparison_reports": true
  },
  "ncat": {
    "enabled": true,
    "port_probe_timeout": 5,
    "banner_grab_enabled": true,
    "probe_discovered_ports": false
  }
}
```

## Workflow-Integration

### Manuelle Integration in diligence.py

```python
# Am Ende von main() hinzufügen:
from diligence_integration import (
    run_post_scan_nping,
    run_post_scan_ncat_probe,
    run_comparison_with_previous,
    extract_discovered_ips,
)

# Nach create_reports()
discovered_ips = extract_discovered_ips(rows)
ping_results = run_post_scan_nping(config, discovered_ips, logger)

if config.get("ncat", {}).get("probe_discovered_ports"):
    discovered_hosts = extract_discovered_hosts(rows)
    probe_results = run_post_scan_ncat_probe(config, discovered_hosts, logger)

if config.get("ndiff", {}).get("auto_compare_with_last"):
    comparison = run_comparison_with_previous(config, xml_path, report_dir, logger)
```

## Performance-Übersicht

| Tool | Zweck | Geschwindigkeit | Genauigkeit |
|------|-------|-----------------|------------|
| **Nping** | Erreichbarkeit | ⚡⚡⚡ | 95% |
| **Ncat** | Port-Probe | ⚡⚡ | 98% |
| **Nmap** | Vollscan | ⚡ | 99% |
| **Ndiff** | Vergleich | ⚡⚡⚡ | 100% |

## Fehlerbehandlung

### Tools nicht gefunden?
```powershell
python diligence_suite.py verify
# Zeigt welche Tools fehlen

python bootstrap.py --yes
python validate.py --install
```

### Import-Fehler?
```powershell
# Stelle sicher alle Module im Verzeichnis sind:
ls *.py | where {$_ -match "nmap_suite|ping_scanner|scan_comparison|network_tools|diligence_suite|diligence_integration"}
```

## Ausgabe-Formate

Alle Tools generieren:

| Format | Dateiendung | Verwendung |
|--------|-------------|-----------|
| Markdown | .md | Dokumentation, Sharing, Git |
| JSON | .json | Automatisierung, APIs |
| Console | (stdout) | Schnelle Übersicht |
| HTML | .html | Browser-Ansicht (nur Nmap) |

## Dateien-Übersicht

```
Diligence/
├── nmap_suite.py              # Basis-Tools
├── ping_scanner.py            # Nping-Modul
├── scan_comparison.py         # Ndiff-Modul
├── network_tools.py           # Ncat-Modul
├── diligence_suite.py         # CLI-Interface
├── diligence_integration.py   # Integration für diligence.py
├── diligence.py               # (Original, unverändert)
└── NMAP_SUITE.md              # Detaillierte Anleitung
```

## Lizenzen

- **Nmap Suite**: GPL (https://nmap.org)
- **Diligence**: MIT License
- **Diligence Suite**: MIT License

## Tipps & Tricks

### Automatisierte Tagesüberwachung
```powershell
# task-scheduler:
# Täglich um 06:00 Uhr:
cd C:\Users\leonh\_github\Diligence && python diligence.py
```

### Integration mit anderen Tools
```powershell
# Ergebnisse als CSV exportieren
python diligence_suite.py probe --host router --ports 22,80,443 | Export-Csv -Path report.csv
```

### Batch-Verarbeitung
```python
# Alle XML-Dateien vergleichen
for i in range(len(xml_files)-1):
    comparator.compare_xml_scans(xml_files[i], xml_files[i+1])
```

---

**Hinweis:** Nutze diese Tools nur auf autorisierten Netzwerken! Vorsicht bei UDP-Scans und Port 0-1024, da diese Admin-Rechte brauchen.

## SMB/NSE Beispiele

```powershell
python diligence_suite.py smb --host 192.168.178.20
python diligence_suite.py smb --host 192.168.178.20 --deep
python diligence_suite.py scripts --host 192.168.178.20 --profile smb-basic
python diligence_suite.py scripts --host 192.168.178.20 --profile smb-vuln
```
