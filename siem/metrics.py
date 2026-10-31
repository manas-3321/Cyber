"""SOC metrics: detection performance, coverage, trend and tuning impact.

Every figure in the dashboard and in the evidence pack is derived here so the
numbers cannot drift between artefacts.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from statistics import mean, median
from typing import Iterable, List

from . import config
from .incidents import TACTIC_ORDER


def _safe_mean(values: Iterable[float]) -> float:
    values = [v for v in values if v is not None]
    return round(mean(values), 1) if values else 0.0


def _safe_median(values: Iterable[float]) -> float:
    values = [v for v in values if v is not None]
    return round(median(values), 1) if values else 0.0


def compute(
    events: List[dict],
    ingest_stats: List[dict],
    alerts: List[dict],
    suppressed: List[dict],
    incidents: List[dict],
    anomaly_baselines: dict,
    rule_pack: dict,
    intel_count: int,
) -> dict:
    by_day = Counter(event["ts"][:10] for event in events)
    incident_by_day = Counter(incident["first_seen"][:10] for incident in incidents)

    all_candidates = alerts + suppressed
    by_severity = Counter(alert["severity"] for alert in alerts)
    by_type = Counter(alert["incident_type"] for alert in alerts)
    by_rule = Counter(alert["rule_id"] for alert in alerts)

    rule_names = {rule["id"]: rule["name"] for rule in rule_pack.get("rules", [])}
    for rule in rule_pack.get("anomaly_rules", []):
        rule_names[rule["id"]] = rule["name"]

    rule_coverage = []
    for rule in rule_pack.get("rules", []) + rule_pack.get("anomaly_rules", []):
        count = by_rule.get(rule["id"], 0)
        suppressed_for_rule = sum(1 for alert in suppressed if alert["rule_id"] == rule["id"])
        rule_coverage.append(
            {
                "rule_id": rule["id"],
                "name": rule["name"],
                "type": rule.get("type", "anomaly"),
                "severity": rule.get("severity"),
                "incident_type": rule.get("incident_type"),
                "tactics": sorted({m["tactic"] for m in rule.get("mitre", [])}),
                "techniques": sorted({m["id"] for m in rule.get("mitre", [])}),
                "alerts": count,
                "suppressed": suppressed_for_rule,
                "triggered": count + suppressed_for_rule > 0,
            }
        )

    techniques_defined = {m["id"] for rule in rule_pack.get("rules", []) for m in rule.get("mitre", [])}
    techniques_defined |= {m["id"] for rule in rule_pack.get("anomaly_rules", []) for m in rule.get("mitre", [])}
    techniques_detected = {
        m["id"]
        for alert in alerts
        for m in alert.get("mitre", [])
    }
    tactics_detected = {m["tactic"] for alert in alerts for m in alert.get("mitre", [])}

    mttd = [incident["mttd_minutes"] for incident in incidents]
    mtta = [incident["mtta_minutes"] for incident in incidents]
    mttr = [incident["mttr_minutes"] for incident in incidents]

    intel_hits = Counter()
    for alert in alerts:
        for match in alert.get("intel", []):
            intel_hits[(match.get("value"), match.get("threat_type"))] += 1

    suppress_reasons = Counter()
    for alert in suppressed:
        entry = alert.get("suppression") or {}
        suppress_reasons[(entry.get("id"), entry.get("reason"))] += 1

    parse_rates = [row.get("parse_rate", 0) for row in ingest_stats]
    total_lines = sum(row.get("raw_lines", 0) for row in ingest_stats)

    incidents_by_type = Counter(incident["type"] for incident in incidents)
    incidents_by_severity = Counter(incident["severity"] for incident in incidents)
    campaigns = [incident["incident_id"] for incident in incidents if incident.get("campaign")]

    return {
        "generated_at": config.iso(datetime.now(tz=config.timezone.utc)),
        "window": {
            "start": events[0]["ts"] if events else None,
            "end": events[-1]["ts"] if events else None,
        },
        "events": {
            "total": len(events),
            "raw_lines": total_lines,
            "by_source": dict(Counter(event["source"] for event in events)),
            "by_category": dict(Counter(event["event.category"] for event in events)),
            "by_day": dict(sorted(by_day.items())),
            "ingest_files": ingest_stats,
            "mean_parse_rate": round(_safe_mean(parse_rates), 1),
        },
        "detections": {
            "candidate_alerts": len(all_candidates),
            "actionable_alerts": len(alerts),
            "suppressed_alerts": len(suppressed),
            "suppression_rate": round(len(suppressed) / len(all_candidates) * 100, 1) if all_candidates else 0.0,
            "by_severity": {severity: by_severity.get(severity, 0) for severity in config.SEVERITIES},
            "by_type": dict(by_type.most_common()),
            "by_rule": dict(by_rule.most_common()),
            "top_rules": [
                {"rule_id": rule_id, "name": rule_names.get(rule_id, rule_id), "alerts": count}
                for rule_id, count in by_rule.most_common(10)
            ],
            "alerts_per_day": round(len(alerts) / max(1, len(by_day)), 1),
        },
        "incidents": {
            "total": len(incidents),
            "by_severity": {severity: incidents_by_severity.get(severity, 0) for severity in config.SEVERITIES},
            "by_type": dict(incidents_by_type.most_common()),
            "by_day": dict(sorted(incident_by_day.items())),
            "campaigns": campaigns,
            "mttd_minutes": {"mean": _safe_mean(mttd), "median": _safe_median(mttd), "max": max(mttd) if mttd else 0},
            "mtta_minutes": {"mean": _safe_mean(mtta), "median": _safe_median(mtta), "max": max(mtta) if mtta else 0},
            "mttr_minutes": {"mean": _safe_mean(mttr), "median": _safe_median(mttr), "max": max(mttr) if mttr else 0},
            "mttr_hours": {"mean": round(_safe_mean(mttr) / 60, 1), "median": round(_safe_median(mttr) / 60, 1)},
            "per_severity": {
                severity: _count_incidents(incidents, severity) for severity in config.SEVERITIES
            },
        },
        "coverage": {
            "rules_defined": len(rule_coverage),
            "rules_triggered": sum(1 for rule in rule_coverage if rule["triggered"]),
            "rule_utilisation_pct": round(
                sum(1 for rule in rule_coverage if rule["triggered"]) / len(rule_coverage) * 100, 1
            ) if rule_coverage else 0.0,
            "techniques_defined": len(techniques_defined),
            "techniques_detected": len(techniques_detected),
            "techniques_missed": sorted(techniques_defined - techniques_detected),
            "tactics_detected": [t for t in TACTIC_ORDER if t in tactics_detected],
            "rule_detail": sorted(rule_coverage, key=lambda r: (-r["alerts"], r["rule_id"])),
        },
        "threat_intel": {
            "indicators": intel_count,
            "matched_indicators": len(intel_hits),
            "top_matches": [
                {"indicator": value, "threat_type": threat_type, "alerts": count}
                for (value, threat_type), count in intel_hits.most_common(10)
            ],
        },
        "tuning": {
            "suppressed": len(suppressed),
            "by_reason": [
                {"allowlist": key[0], "reason": key[1], "alerts": count}
                for key, count in suppress_reasons.most_common()
            ],
            "anomaly_models": anomaly_baselines,
            "noise_reduction_pct": round(len(suppressed) / len(all_candidates) * 100, 1) if all_candidates else 0.0,
        },
    }


def _count_incidents(incidents: List[dict], severity: str) -> int:
    return sum(1 for incident in incidents if incident["severity"] == severity)
