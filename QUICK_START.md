# 🚀 Diligence Suite - Quick Start Guide

## Installation (2 Minuten)

```powershell
cd C:\Users\leonh\_github\Diligence
python bootstrap.py --yes
python validate.py --install
```

## 5 Basis-Befehle

### 1️⃣ Tools Prüfen
```powershell
python diligence_suite.py verify
```
**Zeigt:** Welche Tools verfügbar sind
**Output:**
```
[✓] nmap
[✓] nping  
[✓] ndiff
[✓] ncat
Verfügbar: 4/4
```

### 2️⃣ Schnelle Ping-Prüfung (30 Sekunden)
```powershell
python diligence_suite.py ping --targets 192.168.1.1
```
**Zeigt:** Ob Host online ist
**Gut für:** Vor dem großen Scan
**Output:** `Erreichbar: 1 | Nicht erreichbar: 0`

### 3️⃣ Port-Probe (1-2 Minuten)
```powershell
python diligence_suite.py probe --host 192.168.1.1 --ports 22,80,443
```
**Zeigt:** Welche Ports offen sind
**Gut für:** Service-Verfügbarkeit prüfen
**Output:** Details zu jedem Port

### 4️⃣ Vollständiger Nmap-Scan (10-30 Minuten)
```powershell
python diligence.py
```
**Zeigt:** Komplette Netzwerk-Inventur
**Gut für:** Regelmäßige Überwachung
**Output:** Mehrere Report-Formate

### 5️⃣ Scan-Vergleich (10 Sekunden)
```powershell
python diligence_suite.py compare --old reports/scan_old.xml --new reports/scan_new.xml
```
**Zeigt:** Unterschiede zwischen Scans
**Gut für:** Trend-Analyse, Change-Tracking
**Output:** Neue/gelöschte Hosts und Ports

---

## 📊 Welches Tool wann nutzen?

| Situation | Tool | Befehl | Dauer |
|-----------|------|--------|-------|
| **Schnell prüfen ob Netzwerk online** | Nping | `ping` | 10s |
| **Prüfen ob wichtiger Service läuft** | Ncat | `probe` | 20s |
| **Tägliche komplette Inventur** | Nmap | `diligence.py` | 30m |
| **Unterschiede seit letztem Scan** | Ndiff | `compare` | 5s |
| **Nach Sicherheits-Incident** | Alle | alle kombinieren | 5-30m |

---

## 🎯 Häufige Aufgaben

### A) Täglich den Netzwerk-Status checken
```powershell
# Montag früh
python diligence_suite.py ping --targets 192.168.0.0/24 --output reports/monday.md

# Freitag früh
python diligence_suite.py ping --targets 192.168.0.0/24 --output reports/friday.md

# Unterschiede checken
python diligence_suite.py compare --old reports/monday.xml --new reports/friday.xml
```

### B) Notfall: Vermuteter Sicherheitsvorfall
```powershell
# 1. Schnell alles pingen
python diligence_suite.py ping --targets 192.168.0.0/16

# 2. Verdächtige Ports proben
python diligence_suite.py probe --host verdächtiger_host --ports 1-100

# 3. Mit Baseline vergleichen
python diligence_suite.py compare --old baseline.xml --new incident.xml

# 4. Detaillierter Scan
python diligence.py
```

### C) Wichtige Services überwachen
```powershell
# Router, Server, Drucker, NAS prüfen
python diligence_suite.py probe --host router.local --ports 22,80,443,9100 --output reports/critical.md

# Diese Datei täglich als Report ansehen
type reports/critical.md
```

### D) Report-Archiv durchsuchen
```powershell
# Alle Reports heute
ls reports/diligence_20260506*.xml

# Älteste und neueste vergleichen
python diligence_suite.py compare --old reports/diligence_20260506_171556.xml --new reports/diligence_20260506_234136.xml
```

---

## 📈 Report-Formate

Jeder Befehl erzeugt **Markdown (.md)** Reports:

### Ping-Report (`ping_test.md`)
```markdown
# Nping Erreichbarkeitsbericht

- Gesamte Hosts: 1
- Erreichbar: 1
- Nicht erreichbar: 0

## Erreichbare Hosts
- 192.168.178.1
```

### Port-Probe Report (`port_probe_test.md`)
```markdown
# Ncat Port-Probe Bericht

- Host: 192.168.178.1
- Getestete Ports: 4
- Erreichbar: 0

## Port-Details
### Port 22
- Status: ✗ Geschlossen
```

### Vergleichs-Report (`scan_comparison.md`)
```markdown
# Netzwerk-Scan Vergleich

## Neue Hosts
- 192.168.1.100

## Entfernte Hosts
- 192.168.1.50

## Geänderte Hosts
### 192.168.1.1
**Neue Ports:** 8080/tcp
**Geschlossene Ports:** 5000/tcp
```

---

## ⚡ Performance-Matrix

```
Aktion                      Zeit      Genauigkeit
─────────────────────────────────────────────────
Einzelnen Host pingen       ~1s       95%
4 Ports proben              ~5s       98%
10 Hosts pingen             ~10s      95%
Scans vergleichen           <1s       100%
Vollständiger Nmap-Scan     15-60m    99%
```

---

## 🔍 Tipps & Tricks

### Tipp 1: Offline erste prüfen
```powershell
# Nicht jeden Host voll scannen, sondern erst Erreichbarkeit prüfen
python diligence_suite.py ping --targets 192.168.0.0/24 --output online_hosts.md
```

### Tipp 2: Automatisiert vergleichen
```powershell
# Nach jedem Scan automatisch mit letztem vergleichen
python diligence.py
# ... Scan speichert neue .xml Datei ...
python diligence_suite.py compare --old old.xml --new new.xml  
```

### Tipp 3: CSV für Excel
```powershell
# Nmap erzeugt auch CSV-Reports automatisch
type reports/diligence_*.csv | Get-Content | convertfrom-csv | export-excel
```

### Tipp 4: JSON für APIs
```powershell
# Ergebnisse als JSON speichern für externe Tools
python diligence_suite.py compare ... > reports/data.json
# Dann in anderen Tools/Scripts verwenden
```

---

## 🛑 Fehler beheben

| Fehler | Lösung |
|--------|--------|
| `nping nicht gefunden` | `python validate.py --install` |
| `Permission denied` | Admin-Terminal starten |
| `XML nicht gefunden` | `ls reports/*.xml` prüfen |
| `Python nicht gefunden` | Python zur PATH hinzufügen |
| `Keine Hosts gefunden` | `ping 192.168.0.0/24` statt einzelne IPs |

---

## 📚 Weitere Hilfe

Detailliert: [NMAP_SUITE.md](NMAP_SUITE.md)
Module: [SUITE_MODULES.md](SUITE_MODULES.md)  
Features: [FEATURES_SUMMARY.md](FEATURES_SUMMARY.md)

---

## ✅ Checkliste für Anfänger

- [ ] `python diligence_suite.py verify` ausgeführt
- [ ] Alle 4 Tools ✓ markiert?
- [ ] `python diligence_suite.py ping --targets 192.168.1.1` getestet
- [ ] Report in `reports/` Ordner gefunden?
- [ ] `python diligence.py` einmal durchlaufen lassen
- [ ] `python diligence_suite.py compare` mit 2 XMLs getestet

Wenn alles ✓: **Gratulieren! Du bist bereit!**

---

**Viel Erfolg beim Netzwerk-Monitoring! 🎯**

## SMB genauer pruefen

```powershell
# Protokolle und Betriebssystem-Infos auf Port 445
python diligence_suite.py smb --host 192.168.178.20

# Zusaetzlich Shares/Users abfragen
python diligence_suite.py smb --host 192.168.178.20 --deep --output reports/smb_deep_192.168.178.20.md
```
