#!/usr/bin/env python3
"""Validierungscheck fuer Diligence."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
REQUIRED_KEYS = [
    "scan.target",
    "scan.profile",
    "scan.allow_public_targets",
    "scan.timing",
    "paths.report_dir",
    "paths.log_file",
    "logging.level",
]
ALLOWED_PROFILES = {"discovery", "common", "ports"}
ALLOWED_TIMING = {"T0", "T1", "T2", "T3", "T4", "T5"}


def get_nested(data: dict, dotkey: str):
    for key in dotkey.split("."):
        if not isinstance(data, dict) or key not in data:
            return None
        data = data[key]
    return data


def main() -> int:
    install = "--install" in sys.argv
    config_file = APP_DIR / "config.json"
    if not config_file.exists():
        print("config.json nicht gefunden.")
        print("Erstelle sie mit: Copy-Item config.example.json config.json")
        return 1

    with config_file.open("r", encoding="utf-8") as handle:
        config = json.load(handle)

    missing = [key for key in REQUIRED_KEYS if get_nested(config, key) is None]
    if missing:
        print("Fehlende Pflichtschluessel:")
        for key in missing:
            print(f"  - {key}")
        return 1

    if config["scan"]["profile"] not in ALLOWED_PROFILES:
        print("Ungueltiges Scan-Profil:", config["scan"]["profile"])
        return 1

    if config["scan"]["timing"] not in ALLOWED_TIMING:
        print("Ungueltiger Timing-Wert:", config["scan"]["timing"])
        return 1

    if shutil.which("nmap") is None:
        if install:
            result = subprocess.run([sys.executable, "bootstrap.py", "--yes"], cwd=APP_DIR, check=False)
            if result.returncode == 0 or shutil.which("nmap") is not None:
                print("Nmap-Dependency installiert.")
                print("Diligence-Validierung erfolgreich.")
                return 0

        print("Nmap wurde nicht im PATH gefunden.")
        print("Installiere Nmap von https://nmap.org/download.html und oeffne das Terminal danach neu.")
        print("Oder automatisch fuer Tests: python validate.py --install")
        return 1

    print("Diligence-Validierung erfolgreich.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
