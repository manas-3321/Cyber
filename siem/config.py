"""Central configuration and small path / IO helpers for the mini-SIEM.

The project deliberately uses only the Python standard library so that the
whole lab can be reproduced on an air-gapped analyst workstation.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

DATA_DIR = ROOT / "data"
LOG_DIR = DATA_DIR / "logs"
ASSETS_FILE = DATA_DIR / "assets.csv"
INTEL_FILE = DATA_DIR / "threat_intel" / "indicators.csv"

DETECTIONS_DIR = ROOT / "detections"
RULES_FILE = DETECTIONS_DIR / "rules.json"
ALLOWLIST_FILE = DETECTIONS_DIR / "allowlists.json"
BASELINE_FILE = DETECTIONS_DIR / "baseline_processes.json"

OUTPUT_DIR = ROOT / "output"
INCIDENT_DIR = OUTPUT_DIR / "incidents"
DASHBOARD_FILE = OUTPUT_DIR / "dashboard.html"

# The log bundle is a seven day capture.  Syslog style sources (auth.log,
# squid) carry no year, so the ingest layer pins them to this year.
LAB_YEAR = 2026
LAB_TIMEZONE = "UTC"

# Internal address space used by the simulated enterprise.
INTERNAL_NETWORKS = ("10.10.0.0/16", "10.20.0.0/16", "172.16.0.0/12", "192.168.0.0/16")

# Labels used consistently across alerts, cases, reports and dashboards.
SEVERITIES = ("Low", "Medium", "High", "Critical")
SEVERITY_ORDER = {name: idx for idx, name in enumerate(SEVERITIES)}

# Analysts that own cases in the simulated SOC (TheHive users).
ANALYSTS = ("analyst.l1", "analyst.l2", "ir.lead")


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def parse_ts(value: str) -> datetime:
    """Parse an ISO-8601 timestamp and always return an aware UTC datetime."""
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def iso(dt: datetime) -> str:
    dt = dt.astimezone(timezone.utc).replace(microsecond=0)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path: Path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=False)
        fh.write("\n")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def ensure_output_dirs() -> None:
    for path in (OUTPUT_DIR, INCIDENT_DIR):
        os.makedirs(path, exist_ok=True)
