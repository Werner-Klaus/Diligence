# Diligence Suite - Erweiterte Nmap-Integration

Erweitert Diligence um zusätzliche Funktionen der Nmap-Suite: **Nping**, **Ndiff**, und **Ncat**.

## Features

### Nping - Echtzeit Ping & Erreichbarkeitsprüfungen

Schnelle Multi-Target-Erreichbarkeitsprüfungen mit verschiedenen Protokollen.

```powershell
python diligence_suite.py ping --targets 192.168.1.1,192.168.1.2,192.168.1.3 --count 3 --output reports/ping_results.md
```

**Funktionen:**
- ICMP Echo Requests (Ping)
- TCP-SYN Probe auf mehrere Ports
- UDP-Probe für Dienste
- Batch-Erreichbarkeitstest

**Output:**
- Markdown-Report mit Erreichbarkeitsstatus
- Schnelle Prüfung vor vollständigem Nmap-Scan

### Ndiff - Scan-Vergleich & Trend-Analyse

Vergleiche zwei Nmap-Scan-Ergebnisse und erkenne zeitliche Veränderungen.

```powershell
python diligence_suite.py compare --old reports/diligence_20260506_181223.xml `
                                  --new reports/diligence_20260506_234111.xml `
                                  --output reports/comparison_result.md
```

**Funktionen:**
- Neue Hosts identifizieren
- Entfernte Hosts erkennen
- Port-Änderungen tracken
- Trend-Analyse für Netzwerk-Sicherheit
- JSON-Export für Automatisierung

**Output:**
- Markdown-Vergleichsbericht
- JSON mit strukturierten Änderungen
- Geeignet für Monitoring-Systeme

### Ncat - Port-Probe & Datenaustausch

Teste Port-Erreichbarkeit und kommuniziere mit Netzwerk-Diensten.

```powershell
# Port-Probe mit Banner-Grabbing
python diligence_suite.py probe --host 192.168.1.1 --ports 22,80,443,3389,5900 `
                                 --timeout 5 --output reports/port_probe.md

# Auf Port abhören
python diligence_suite.py listen --port 5000 --duration 30
```

**Funktionen:**
- Port-Erreichbarkeitsprüfung
- Service-Banner Grabbing
- Datenaustausch mit Remote-Diensten
- Verbindungs-Debugging
- Firewall-Test

**Output:**
- Detaillierter Port-Status-Report
- Banner-Informationen
- Response-Zeiten

## Tool-Übersicht

```
┌─────────────────────────────────────────────────────────────┐
│                    Diligence Suite                           │
├─────────────────────────────────────────────────────────────┤
│ Nmap     │ Vollständiger Netzwerk-Scan                       │
│ Nping    │ Schnelle Erreichbarkeitsprüfungen                 │
│ Ndiff    │ Scan-Vergleiche & Trend-Analyse                  │
│ Ncat     │ Port-Probe & Service-Kommunikation                │
└─────────────────────────────────────────────────────────────┘
```

## Verwendungsbeispiele

### 1. Pre-Scan Erreichbarkeitsprüfung

```powershell
# Schnell prüfen, welche Hosts online sind
python diligence_suite.py ping --targets 192.168.178.0/24 `
                                --output reports/online_hosts.md
```

### 2. Netzwerk-Monitoring mit Vergleich

```powershell
# Ersten Scan durchführen
python diligence.py

# Nach Zeit erneut scannen
# ... Zeit verstreichen lassen ...
python diligence.py

# Unterschiede analysieren
python diligence_suite.py compare --old reports/scan_alt.xml `
                                  --new reports/scan_neu.xml `
                                  --output reports/netzwerk_changes.md
```

### 3. Service-Verfügbarkeit testen

```powershell
# Wichtige Services prüfen
python diligence_suite.py probe --host router.local `
                                 --ports 22,80,443,9100 `
                                 --output reports/service_status.md
```

### 4. Netzwerk-Debugging

```powershell
# Port aktivität erfassen
python diligence_suite.py listen --port 8080 --duration 60
```

## Konfiguration

Erweiterte Optionen in `config.json`:

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

## Tool-Verfügbarkeit prüfen

```powershell
python diligence_suite.py verify
```

Output:
```
[✓] nmap
[✓] nping
[✓] ndiff
[✓] ncat
```

## Integrationsworkflows

### Automatisierte Netzwerk-Überwachung

```powershell
# 1. Täglich scannen
python diligence.py

# 2. Mit gestrigem Scan vergleichen
python diligence_suite.py compare --old reports/scan_yesterday.xml `
                                  --new reports/scan_today.xml

# 3. Service-Status prüfen
python diligence_suite.py probe --host kritischer_server --ports 22,80,443
```

### Notfall-Incident Response

```powershell
# 1. Schnell alle Hosts pingen
python diligence_suite.py ping --targets 192.168.0.0/16

# 2. Verdächtige Ports proben
python diligence_suite.py probe --host verdächtiger_host --ports 1-1024

# 3. Mit letztem Baseline-Scan vergleichen
python diligence_suite.py compare --old reports/baseline.xml --new reports/incident.xml
```

## Performance-Tipps

| Tool | Beste Verwendung | Geschwindigkeit |
|------|-----------------|-----------------|
| Nping | Schnelle Erreichbarkeitsprüfung | ⚡⚡⚡ Sehr schnell |
| Ncat | Port-Probe einzelner Services | ⚡⚡ Schnell |
| Nmap | Vollständiger Netzwerk-Scan | ⚡ Langsam |
| Ndiff | Vergleich existierender Scans | ⚡⚡⚡ Sehr schnell |

## Ausgabe-Formate

Alle Tools generieren:
- **Markdown Reports** (.md) - Für Dokumentation und Sharing
- **JSON Export** - Für Automatisierung und Scripts
- **Console Output** - Für schnelle Übersicht

## Fehlerbehandlung

```powershell
# Tool nicht gefunden?
python diligence_suite.py verify

# Nmap Suite neu installieren
python bootstrap.py --yes
python validate.py --install
```

## Lizenzen & Credits

- **Nmap Suite**: https://nmap.org - GPL License
- **Diligence**: Heimnetz-Inventarisierung

---

**Hinweis:** Nutze diese Tools nur auf autorisierten Netzwerken!

## SMB/NSE-Analyse

```powershell
# SMB-Protokolle, OS-Discovery und Security Mode auf Port 445
python diligence_suite.py smb --host 192.168.178.20

# Entspricht in etwa:
# nmap --script smb-protocols,smb-os-discovery,smb-security-mode -p 445 192.168.178.20

# Tiefere SMB-Inventarisierung mit Shares/Users
python diligence_suite.py smb --host 192.168.178.20 --deep --output reports/smb_deep_192.168.178.20.md

# Explizites Script-Profil
python diligence_suite.py scripts --host 192.168.178.20 --profile smb-basic --output reports/smb_basic.md
```

Profile:
- `smb-basic`: `smb-protocols`, `smb-os-discovery`, `smb-security-mode`
- `smb`: `smb-basic` plus `smb-enum-shares`, `smb-enum-users`
- `smb-vuln`: getrennte SMB-Schwachstellenchecks
