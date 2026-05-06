# Diligence

Diligence inventarisiert ein autorisiertes Heimnetz mit Nmap und erzeugt daraus
saubere Reports als HTML, CSV und JSON.

## Voraussetzungen

- Python 3.10 oder neuer
- Nmap installiert und im PATH verfuegbar
- Ein Zielnetz, das dir gehoert oder fuer das du eine klare Scan-Erlaubnis hast

## Schnellstart

```powershell
cd Diligence
Copy-Item config.example.json config.json
python validate.py
python diligence.py
```

Die Reports landen im Ordner `reports/`.

## Dependencies fuer Tests automatisch installieren

Diligence nutzt keine externen Python-Pakete. Fuer echte Scans wird aber Nmap
benoetigt. Unter Windows kann der Test-Bootstrap Nmap per `winget` installieren:

```powershell
python bootstrap.py --yes
python validate.py
```

Alternativ kann die Validierung den Bootstrap direkt starten:

```powershell
python validate.py --install
python launcher.py --install-deps
python diligence.py --install-deps
```

Nach einer Nmap-Installation muss das Terminal manchmal neu geoeffnet werden,
damit der aktualisierte PATH sichtbar ist.

## Konfiguration

```json
{
  "scan": {
    "target": "192.168.178.0/24",
    "profile": "common",
    "allow_public_targets": false,
    "timing": "T3",
    "top_ports": 100
  }
}
```

Profile:

- `discovery`: Host-Erkennung ohne Portscan (`nmap -sn`)
- `common`: Versionsscan gegen die haeufigsten Ports
- `ports`: Versionsscan gegen eine explizite Portliste aus `scan.ports`

## CLI-Beispiele

```powershell
python diligence.py --target 192.168.178.0/24 --profile discovery
python diligence.py --target 192.168.178.0/24 --profile common
python diligence.py --parse-only .\reports\diligence_20260506_120000.xml
```

Oeffentliche Zielbereiche sind absichtlich blockiert, solange
`allow_public_targets` nicht bewusst aktiviert wird.
