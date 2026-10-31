"""Risk-based severity scoring and prioritisation.

A raw rule severity is only the starting point.  The score adds business
context so the SOC can allocate analysts to what actually matters:

    score = base_severity
          + asset criticality
          + threat-intelligence confidence
          + volume / corroboration
          - low-confidence (behavioural) penalty

Scores are clamped to 0-100 and mapped back to the four severity levels used
by the incident process: Low < 45 <= Medium < 70 <= High < 90 <= Critical.
"""
from __future__ import annotations

from typing import List, Optional, Tuple

from .assets import AssetInventory

BASE = {"Low": 25, "Medium": 45, "High": 70, "Critical": 90}
ASSET_BONUS = {"Critical": 10, "High": 6, "Medium": 3, "Low": 0}
INTEL_BONUS = {"critical": 16, "high": 12, "medium": 6, "low": 3}


def severity_from_score(score: float) -> str:
    if score >= 90:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 45:
        return "Medium"
    return "Low"


def score_alert(alert: dict, inventory: AssetInventory) -> dict:
    breakdown = {}
    base = BASE.get(alert.get("base_severity", "Medium"), 45)
    breakdown["base_rule_severity"] = base

    entity = alert.get("entity", {})
    host = entity.get("host.name")
    ip = entity.get("host.ip") or entity.get("source.ip")
    asset = inventory.by_host(host) or inventory.by_ip(host)
    if asset is None and ip and inventory.is_internal(ip):
        asset = inventory.by_ip(ip)
    if asset is None and entity.get("user.name"):
        # User-centric alerts (e.g. off-hours share access) are attributed to
        # the user's primary device, then to the host seen in the telemetry.
        asset = inventory.by_owner(entity["user.name"])
        if asset is None:
            for observed_host in alert.get("observables", {}).get("hosts", []):
                asset = inventory.by_host(observed_host)
                if asset:
                    break
    if asset is None and entity.get("email.recipient"):
        asset = inventory.by_owner(str(entity["email.recipient"]).split("@")[0])
    criticality = asset.criticality if asset else "Medium"
    asset_bonus = ASSET_BONUS.get(criticality, 3)
    breakdown["asset_criticality"] = asset_bonus
    breakdown["asset"] = asset.hostname if asset else (host or ip or "unknown")

    intel_bonus = 0
    best_intel = None
    for match in alert.get("intel", []):
        bonus = INTEL_BONUS.get(str(match.get("confidence", "")).lower(), 0)
        if bonus > intel_bonus:
            intel_bonus = bonus
            best_intel = match
    breakdown["threat_intel"] = intel_bonus

    volume_bonus = min(6, int(alert.get("event_count", 1) // 10)) if alert.get("type") != "anomaly" else 4
    breakdown["volume_corroboration"] = volume_bonus

    confidence_penalty = 0
    if float(alert.get("confidence", 0.7)) < 0.65:
        confidence_penalty = -8
    breakdown["confidence_penalty"] = confidence_penalty

    score = max(0, min(100, base + asset_bonus + intel_bonus + volume_bonus + confidence_penalty))
    alert["risk_score"] = score
    alert["severity"] = severity_from_score(score)
    alert["score_breakdown"] = breakdown
    if asset:
        alert["asset"] = asset.as_dict()
    alert["intel_high_confidence"] = bool(best_intel)
    return alert


def prioritise(severity: str) -> str:
    return {"Critical": "P1", "High": "P2", "Medium": "P3", "Low": "P4"}.get(severity, "P4")


def score_incident(alerts: List[dict]) -> Tuple[int, str]:
    """Incident risk = strongest alert plus a bounded corroboration bonus."""
    if not alerts:
        return 0, "Low"
    strongest = max(alert["risk_score"] for alert in alerts)
    distinct_rules = len({alert["rule_id"] for alert in alerts})
    bonus = min(8, max(0, distinct_rules - 1) * 2)
    score = min(100, strongest + bonus)
    return score, severity_from_score(score)
