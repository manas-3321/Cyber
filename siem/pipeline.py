"""End-to-end pipeline: ingest -> detect -> score -> correlate -> report."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import List, Optional

from . import (
    anomaly,
    assets,
    config,
    dashboard,
    incidents as incident_mod,
    ingest,
    intel as intel_mod,
    metrics as metrics_mod,
    report,
    rules as rules_mod,
    scoring,
    suppress,
)


def _assign_alert_ids(alerts: List[dict]) -> None:
    ordered = sorted(alerts, key=lambda a: (a["detected_at"], a["rule_id"], a["group_key"]))
    for index, alert in enumerate(ordered, start=1):
        alert["alert_id"] = f"ALT-2026-{index:04d}"


def run(
    data_path: Optional[Path] = None,
    output_dir: Optional[Path] = None,
    write_events: bool = True,
) -> dict:
    output_dir = Path(output_dir) if output_dir else config.OUTPUT_DIR
    incident_dir = output_dir / "incidents"
    visuals_dir = output_dir / "visuals"
    for path in (output_dir, incident_dir, visuals_dir):
        path.mkdir(parents=True, exist_ok=True)
    # Remove reports from earlier runs so numbering never goes stale.
    for stale in list(incident_dir.glob("INC-*.md")) + list(visuals_dir.glob("*.svg")):
        stale.unlink()

    # 1. Context: asset inventory, threat intelligence, detection content.
    inventory = assets.load_inventory()
    intel = intel_mod.load_feed()
    rule_pack = config.load_json(config.RULES_FILE)
    allowlists = config.load_json(config.ALLOWLIST_FILE)["allowlists"]
    baseline_processes = config.load_json(config.BASELINE_FILE)["processes"]

    # 2. Ingest + normalise + enrich.
    ingest_result = ingest.ingest(data_path)
    events = ingest.enrich_events(ingest_result["events"], inventory, intel)

    # 3. Correlate.
    engine = rules_mod.RuleEngine(rule_pack, {"allowlists": allowlists})
    detections = engine.evaluate(events)
    anomaly_result = anomaly.detect(events, rule_pack.get("anomaly_rules", []), baseline_processes)

    candidates: List[dict] = detections["alerts"] + anomaly_result["alerts"]

    # 4. Risk-score with business context, then apply the tuning layer.
    for alert in candidates:
        scoring.score_alert(alert, inventory)
        suppress.apply(alert, allowlists)

    _assign_alert_ids(candidates)
    alerts = [alert for alert in candidates if not alert["suppressed"]]
    suppressed = [alert for alert in candidates if alert["suppressed"]]

    # 5. Case management.
    incidents = incident_mod.build_incidents(alerts, inventory)

    # 6. Metrics.
    metrics = metrics_mod.compute(
        events=events,
        ingest_stats=ingest_result["stats"],
        alerts=alerts,
        suppressed=suppressed,
        incidents=incidents,
        anomaly_baselines=anomaly_result["baselines"],
        rule_pack=rule_pack,
        intel_count=len(intel),
    )

    # 7. Artefacts.
    if write_events:
        with open(output_dir / "events.jsonl", "w", encoding="utf-8") as fh:
            for event in events:
                fh.write(json.dumps(event, separators=(",", ":")) + "\n")

    config.write_json(output_dir / "alerts.json", alerts)
    config.write_json(output_dir / "suppressed_alerts.json", suppressed)
    config.write_json(output_dir / "metrics.json", metrics)
    config.write_json(output_dir / "ingest_stats.json", {
        "files": ingest_result["stats"],
        "errors": ingest_result["errors"],
        "totals": {
            "raw_lines": sum(row["raw_lines"] for row in ingest_result["stats"]),
            "events": len(events),
            "by_source": dict(Counter(event["source"] for event in events)),
        },
    })
    config.write_json(output_dir / "anomaly_baselines.json", anomaly_result["baselines"])
    config.write_json(output_dir / "thehive_cases.json", incident_mod.to_thehive(incidents))

    for incident in incidents:
        config.write_text(incident_dir / f"{incident['incident_id']}.md", report.render_incident(incident))
    config.write_text(incident_dir / "INDEX.md", report.render_index(incidents, metrics))
    config.write_text(output_dir / "EXECUTIVE_SUMMARY.md", report.render_executive_summary(metrics, incidents))

    # 8. Dashboard + standalone chart artefacts.
    artefacts = dashboard.build_dashboard(
        metrics, incidents, alerts, suppressed, [ioc.as_dict() for ioc in intel.indicators])
    for name, content in artefacts.items():
        target = output_dir / name if name == "dashboard.html" else visuals_dir / name
        target.parent.mkdir(parents=True, exist_ok=True)
        config.write_text(target, content)

    manifest = {
        "generated_at": config.iso(config.now_utc()),
        "capture_window": metrics["window"],
        "events": len(events),
        "alerts": len(alerts),
        "suppressed": len(suppressed),
        "incidents": len(incidents),
        "artefacts": sorted(
            str(path.relative_to(output_dir))
            for path in output_dir.rglob("*") if path.is_file()
        ),
    }
    config.write_json(output_dir / "run_manifest.json", manifest)

    return {
        "events": events,
        "alerts": alerts,
        "suppressed": suppressed,
        "incidents": incidents,
        "metrics": metrics,
        "manifest": manifest,
    }


def print_summary(result: dict) -> None:
    metrics = result["metrics"]
    print("=" * 78)
    print(" Security Incident Detection and Analysis — pipeline complete")
    print("=" * 78)
    print(f" capture window   : {metrics['window']['start']} -> {metrics['window']['end']}")
    print(f" events ingested  : {metrics['events']['total']:,} "
          f"({', '.join(f'{k}={v}' for k, v in metrics['events']['by_source'].items())})")
    print(f" alerts           : {metrics['detections']['actionable_alerts']} actionable, "
          f"{metrics['detections']['suppressed_alerts']} suppressed by tuning")
    print(f" incidents        : {metrics['incidents']['total']} "
          f"({metrics['incidents']['by_severity']['Critical']} critical, "
          f"{metrics['incidents']['by_severity']['High']} high, "
          f"{metrics['incidents']['by_severity']['Medium']} medium, "
          f"{metrics['incidents']['by_severity']['Low']} low)")
    print(f" MTTD / MTTA / MTTR: {metrics['incidents']['mttd_minutes']['mean']} min / "
          f"{metrics['incidents']['mtta_minutes']['mean']} min / "
          f"{metrics['incidents']['mttr_hours']['mean']} h")
    print(f" ATT&CK coverage   : {metrics['coverage']['techniques_detected']}/"
          f"{metrics['coverage']['techniques_defined']} techniques, "
          f"{metrics['coverage']['rules_triggered']}/{metrics['coverage']['rules_defined']} rules exercised")
    print("-" * 78)
    for incident in result["incidents"]:
        print(f" {incident['incident_id']}  {incident['severity']:<8} {incident['priority']:<3} "
              f"score={incident['risk_score']:<3} {incident['title']}")
    print("-" * 78)
    print(f" dashboard: {config.OUTPUT_DIR.relative_to(config.ROOT)}/dashboard.html")
    print(f" cases    : {config.INCIDENT_DIR.relative_to(config.ROOT)}/")
