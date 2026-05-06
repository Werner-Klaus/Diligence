#!/usr/bin/env python3
"""Dependency-Bootstrap fuer Diligence."""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
NMAP_WINGET_ID = "Insecure.Nmap"
COMMON_NMAP_PATHS = [
    Path(r"C:\Program Files (x86)\Nmap\nmap.exe"),
    Path(r"C:\Program Files\Nmap\nmap.exe"),
]


def run(command: list[str]) -> int:
    print("Fuehre aus:", " ".join(command), flush=True)
    return subprocess.run(command, cwd=APP_DIR, check=False).returncode


def nmap_path() -> str | None:
    found = shutil.which("nmap")
    if found:
        return found

    for candidate in COMMON_NMAP_PATHS:
        if candidate.exists():
            return str(candidate)

    return None


def install_python_requirements() -> bool:
    requirements = APP_DIR / "requirements.txt"
    if not requirements.exists():
        print("requirements.txt nicht gefunden, ueberspringe Python-Pakete.")
        return True

    installable = [
        line.strip()
        for line in requirements.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not installable:
        print("Keine Python-Pakete in requirements.txt definiert.")
        return True

    command = [sys.executable, "-m", "pip", "install", "-r", str(requirements)]
    return run(command) == 0


def install_nmap(assume_yes: bool) -> bool:
    existing = nmap_path()
    if existing:
        print(f"Nmap bereits vorhanden: {existing}")
        return True

    if shutil.which("winget") is None:
        print("winget wurde nicht gefunden.")
        print("Installiere Nmap manuell von https://nmap.org/download.html")
        return False

    if not assume_yes:
        answer = input("Nmap per winget installieren? [j/N] ").strip().lower()
        if answer not in {"j", "ja", "y", "yes"}:
            print("Installation abgebrochen.")
            return False

    command = [
        "winget",
        "install",
        "--id",
        NMAP_WINGET_ID,
        "-e",
        "--accept-package-agreements",
        "--accept-source-agreements",
    ]
    if run(command) != 0:
        print("winget-Installation fehlgeschlagen.")
        return False

    installed = nmap_path()
    if installed:
        print(f"Nmap installiert: {installed}")
        print("Falls nmap im aktuellen Terminal noch nicht gefunden wird, Terminal neu oeffnen.")
        return True

    print("Nmap-Installation abgeschlossen, aber nmap ist im aktuellen PATH noch nicht sichtbar.")
    print("Terminal neu oeffnen und validate.py erneut starten.")
    return False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Installiert Diligence-Testdependencies")
    parser.add_argument("--yes", action="store_true", help="Installation ohne Rueckfrage starten")
    parser.add_argument("--skip-nmap", action="store_true", help="Nmap-Installation ueberspringen")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    ok = install_python_requirements()
    if not args.skip_nmap:
        ok = install_nmap(args.yes) and ok
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
