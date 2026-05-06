#!/usr/bin/env python3
"""Diligence Launcher mit Vorcheck."""

import subprocess
import sys
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent


def main() -> int:
    print("Diligence - Heimnetz-Inventarisierung")
    print()
    validate_command = [sys.executable, "validate.py"]
    if "--install-deps" in sys.argv:
        validate_command.append("--install")

    validate = subprocess.run(validate_command, cwd=APP_DIR, check=False)
    if validate.returncode != 0:
        input("Druecke Enter zum Schliessen...")
        return validate.returncode

    run = subprocess.run([sys.executable, "diligence.py"], cwd=APP_DIR, check=False)
    input("Druecke Enter zum Schliessen...")
    return run.returncode


if __name__ == "__main__":
    raise SystemExit(main())
