"""Alert correlation into incidents (case management layer).

Individual alerts are evidence; incidents are what the SOC works.  This module
implements the aggregation logic that TheHive calls "case merging":

* alerts of the same type that share an entity are grouped;
* alerts sharing an affected asset within a 24 hour window are merged into a
  multi-stage campaign even when their types differ;
* every incident receives a NIST 800-61 response timeline, root-cause
  statement, MITRE coverage and an MTTA / MTTD / MTTR measurement.

The generated cases are exported to a TheHive-compatible JSON document so the
same data could be POSTed to a live TheHive instance.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timedelta
from typing import Dict, List

from . import config, ingest, playbooks
from .assets import AssetInventory
from .scoring import prioritise, score_incident

TACTIC_ORDER = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

SEVERITY_TO_THEHIVE = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def _add_minutes(ts_iso: str, minutes: int) -> str:
    return config.iso(config.parse_ts(ts_iso) + timedelta(minutes=minutes))


def _minutes_between(start_iso: str, end_iso: str) -> float:
    delta = config.parse_ts(end_iso) - config.parse_ts(start_iso)
    return round(delta.total_seconds() / 60.0, 1)


def _entity_values(alert: dict) -> set:
    values = set()
    for key, value in alert.get("entity", {}).items():
        if value and value != "unknown":
            values.add(f"{key}={value}")
    return values


def _user_keys(alert: dict) -> set:
    users = set(alert.get("observables", {}).get("users", []))
    user = alert.get("entity", {}).get("user.name")
    if user and user != "unknown":
        users.add(str(user))
    return users


def _asset_keys(alert: dict) -> set:
    keys = set()
    asset = alert.get("asset")
    if asset:
        keys.add(asset["hostname"])
    entity = alert.get("entity", {})
    if entity.get("host.name") and entity["host.name"] != "unknown":
        keys.add(str(entity["host.name"]))
    return keys


def build_incidents(alerts: List[dict], inventory: AssetInventory) -> List[dict]:
    alerts = sorted(alerts, key=lambda a: (a["detected_at"], a["rule_id"]))
    groups: List[dict] = []

    for alert in alerts:
        target = None
        alert_entities = _entity_values(alert)
        alert_assets = _asset_keys(alert)
        alert_users = _user_keys(alert)
        alert_ts = config.parse_ts(alert["detected_at"])
        for group in groups:
            gap = abs((alert_ts - config.parse_ts(group["last_seen"])).total_seconds())
            same_type = group["types_internal"][-1] == alert["incident_type"]
            if same_type and (alert_entities & group["entities"]):
                target = group
                break
            high_enough = (
                group["max_alert_severity"] in ("High", "Critical")
                and alert["severity"] in ("High", "Critical")
            )
            if alert_assets & group["assets"] and gap <= 24 * 3600 and high_enough:
                target = group
                break
            # A medium-severity supporting alert (e.g. an off-hours share logon)
            # joins an already serious case when the asset and window match.
            serious_case = group["max_alert_severity"] in ("High", "Critical")
            if (alert_assets & group["assets"] and gap <= 24 * 3600 and serious_case
                    and alert["severity"] in ("Medium", "High", "Critical")):
                target = group
                break
            if alert_assets & group["assets"] and alert_users & group["users"] and gap <= 24 * 3600:
                target = group
                break
            # Same identity inside a serious case: the user-centric alert is
            # part of the same intrusion even if the asset list differs.
            if (alert_users & group["users"] and gap <= 24 * 3600
                    and group["max_alert_severity"] in ("High", "Critical")
                    and alert["severity"] in ("Medium", "High", "Critical")):
                target = group
                break

        if target is None:
            target = {
                "alerts": [],
                "entities": set(),
                "assets": set(),
                "users": set(),
                "types_internal": [],
                "max_alert_severity": "Low",
                "first_seen": alert["first_event_ts"],
                "last_seen": alert["last_event_ts"],
            }
            groups.append(target)

        target["alerts"].append(alert)
        target["entities"] |= alert_entities
        target["assets"] |= alert_assets
        target["users"] |= alert_users
        if alert["incident_type"] not in target["types_internal"]:
            target["types_internal"].append(alert["incident_type"])
        if config.SEVERITY_ORDER[alert["severity"]] > config.SEVERITY_ORDER[target["max_alert_severity"]]:
            target["max_alert_severity"] = alert["severity"]
        if config.parse_ts(alert["first_event_ts"]) < config.parse_ts(target["first_seen"]):
            target["first_seen"] = alert["first_event_ts"]
        if config.parse_ts(alert["last_event_ts"]) > config.parse_ts(target["last_seen"]):
            target["last_seen"] = alert["last_event_ts"]

    incidents = [_materialise(group, inventory) for group in groups]
    incidents.sort(key=lambda inc: inc["first_seen"])
    for idx, incident in enumerate(incidents, start=1):
        incident["incident_id"] = f"INC-2026-{idx:04d}"

    _link_related(incidents)
    for incident in incidents:
        incident.pop("types_internal", None)
    return incidents


# ---------------------------------------------------------------------------
# Incident materialisation
# ---------------------------------------------------------------------------

def _materialise(group: dict, inventory: AssetInventory) -> dict:
    alerts = group["alerts"]
    types = list(group["types_internal"])

    severity_score, severity = score_incident(alerts)
    primary_alert = max(alerts, key=lambda a: (a["risk_score"], a["detected_at"]))
    primary_type = primary_alert["incident_type"]

    mitre: Dict[str, dict] = {}
    for alert in alerts:
        for technique in alert.get("mitre", []):
            mitre.setdefault(technique["id"], technique)
    tactics_present = {t["tactic"] for t in mitre.values()}
    tactics = [tactic for tactic in TACTIC_ORDER if tactic in tactics_present]

    assets = _collect_assets(alerts, inventory)
    users = sorted({
        str(alert["entity"]["user.name"])
        for alert in alerts
        if alert.get("entity", {}).get("user.name") not in (None, "unknown")
    })
    origin = _attack_origin(alerts, inventory)
    iocs = _collect_iocs(alerts, origin)

    playbook_ids = []
    for alert in sorted(alerts, key=lambda a: a["detected_at"]):
        if alert.get("playbook") and alert["playbook"] not in playbook_ids:
            playbook_ids.append(alert["playbook"])
    primary_playbook = primary_alert.get("playbook") or (playbook_ids[0] if playbook_ids else "PB-DEFAULT")

    detected_at = min(alert["detected_at"] for alert in alerts)
    triaged_at = max(alert["detected_at"] for alert in alerts)
    timeline = _build_timeline(alerts, playbook_ids, detected_at, triaged_at)
    response_actions = [entry for entry in timeline if entry["kind"] == "response"]

    containment = next((e["ts"] for e in response_actions if e["phase"] == "Containment"), None)
    closed = next((e["ts"] for e in reversed(response_actions) if e["phase"] == "Post-Incident"), None)
    closed = closed or (response_actions[-1]["ts"] if response_actions else detected_at)

    asset_label = ", ".join(a["hostname"] for a in assets) or origin.get("ip") or "the enterprise"
    major_types = [
        incident_type for incident_type in types
        if any(a["incident_type"] == incident_type and a["severity"] in ("High", "Critical")
               for a in alerts)
    ]
    if len(major_types) <= 1:
        label = major_types[0] if major_types else types[0]
        title = f"{label}: {asset_label}"
    else:
        chain = " → ".join(major_types)
        title = f"Correlated campaign ({chain}) on {asset_label}"

    root_cause = playbooks.for_playbook(primary_playbook).get("root_cause", "")
    root_cause = root_cause.format(
        asset=assets[0]["hostname"] if assets else "the affected host",
        origin=origin.get("ip", "an external source"),
        user=users[0] if users else "the affected user",
    )

    incident = {
        "incident_id": "PENDING",
        "title": title,
        "type": primary_type,
        "types": types,
        "campaign": len(types) > 1,
        "severity": severity,
        "priority": prioritise(severity),
        "risk_score": severity_score,
        "confidence": round(max(alert["confidence"] for alert in alerts), 2),
        "status": "Closed",
        "tlp": "TLP:AMBER",
        "detection_rules": sorted({alert["rule_id"] for alert in alerts}),
        "alert_ids": [alert["alert_id"] for alert in alerts],
        "alerts": alerts,
        "playbooks": playbook_ids,
        "mitre": sorted(mitre.values(), key=lambda t: (TACTIC_ORDER.index(t["tactic"]) if t["tactic"] in TACTIC_ORDER else 99, t["id"])),
        "tactics": tactics,
        "affected_assets": assets,
        "affected_users": users,
        "attack_origin": origin,
        "iocs": iocs,
        "event_count": sum(alert["event_count"] for alert in alerts),
        "first_seen": group["first_seen"],
        "last_seen": group["last_seen"],
        "detected_at": detected_at,
        "contained_at": containment,
        "closed_at": closed,
        "mttd_minutes": _minutes_between(group["first_seen"], detected_at),
        "mtta_minutes": _minutes_between(detected_at, response_actions[0]["ts"]) if response_actions else 0.0,
        "mttr_minutes": _minutes_between(group["first_seen"], closed),
        "summary": _summary(types, assets, origin, alerts, group),
        "root_cause": root_cause,
        "timeline": timeline,
        "response_actions": response_actions,
        "recommendations": playbooks.recommendations_for(playbook_ids or [primary_playbook]),
        "evidence": {
            "alert_ids": [alert["alert_id"] for alert in alerts],
            "event_ids": sorted({eid for alert in alerts for eid in alert["event_ids"]}),
        },
        "related_incidents": [],
    }
    incident["mtta_minutes"] = _minutes_between(detected_at, response_actions[0]["ts"]) if response_actions else 0.0
    incident["root_cause"] = root_cause
    return incident


def _collect_assets(alerts: List[dict], inventory: AssetInventory) -> List[dict]:
    found: Dict[str, dict] = {}
    for alert in alerts:
        asset = alert.get("asset")
        if asset:
            found[asset["hostname"]] = asset
            continue
        host = alert.get("entity", {}).get("host.name")
        if host and host != "unknown":
            resolved = inventory.by_host(host)
            if resolved:
                found[resolved.hostname] = resolved.as_dict()
            else:
                found[host] = {"hostname": host, "criticality": "Medium"}
    return [found[key] for key in sorted(found)]


def _attack_origin(alerts: List[dict], inventory: AssetInventory) -> dict:
    counter: Counter = Counter()
    intel: Dict[str, dict] = {}
    for alert in alerts:
        for match in alert.get("intel", []):
            if match.get("type") == "ip":
                intel[match["value"]] = match
        observables = alert.get("observables", {})
        candidates = list(observables.get("source_ips", []))
        entity_src = alert.get("entity", {}).get("source.ip")
        if entity_src:
            candidates.append(entity_src)
        for src in candidates:
            if src and not inventory.is_internal(src):
                counter[src] += 1
    if not counter:
        return {"ip": None, "internal": True, "geo": None, "intel": None,
                "description": "Internal origin (valid account or internal host)"}
    ip = counter.most_common(1)[0][0]
    return {
        "ip": ip,
        "internal": False,
        "geo": ingest.geo_for(ip),
        "intel": intel.get(ip),
        "description": f"External host {ip}",
        "all_sources": [source for source, _ in counter.most_common(5)],
    }


def _collect_iocs(alerts: List[dict], origin: dict) -> List[dict]:
    values: Dict[str, dict] = {}
    for alert in alerts:
        for match in alert.get("intel", []):
            values.setdefault(match["value"], match)
    return list(values.values())


def _summary(types: List[str], assets: List[dict], origin: dict, alerts: List[dict], group: dict) -> str:
    asset_names = ", ".join(a["hostname"] for a in assets) or "no inventoried host"
    rules = sorted({f"{a['rule_id']} ({a['rule_name']})" for a in alerts})
    window_start = config.parse_ts(group["first_seen"]).strftime("%d %b %Y %H:%M UTC")
    window_end = config.parse_ts(group["last_seen"]).strftime("%d %b %Y %H:%M UTC")
    if len(types) == 1:
        type_phrase = types[0]
    else:
        type_phrase = ", ".join(types[:-1]) + " and " + types[-1]
    return (
        f"{type_phrase} activity affecting {asset_names} between {window_start} and "
        f"{window_end}, originating from {origin.get('ip') or 'inside the network'}. "
        f"{len(alerts)} alert(s) from {len(rules)} detection rule(s) correlated into this case: "
        f"{'; '.join(rules)}."
    )


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------

def _build_timeline(alerts: List[dict], playbook_ids: List[str], detected_at: str,
                    scoped_at: str) -> List[dict]:
    entries: List[dict] = []
    seen = set()

    for alert in sorted(alerts, key=lambda a: a["detected_at"]):
        tactic = alert.get("mitre", [{}])[0].get("tactic", "Analysis") if alert.get("mitre") else "Analysis"
        for event in alert.get("events", []):
            key = (event.get("ts"), event.get("action"), event.get("message"))
            if key in seen:
                continue
            seen.add(key)
            entries.append(
                {
                    "ts": event.get("ts"),
                    "phase": tactic if tactic in TACTIC_ORDER else "Analysis",
                    "kind": "telemetry",
                    "description": event.get("message") or event.get("action"),
                    "source": alert.get("rule_id"),
                    "event_id": event.get("event_id"),
                    "alert_id": alert.get("alert_id"),
                }
            )
        entries.append(
            {
                "ts": alert["detected_at"],
                "phase": "Detection",
                "kind": "detection",
                "description": (
                    f"{alert['rule_id']} '{alert['rule_name']}' fired with risk score "
                    f"{alert['risk_score']} ({alert['severity']})"
                ),
                "source": alert["rule_id"],
                "event_id": None,
                "alert_id": alert.get("alert_id"),
            }
        )

    seen_actions = set()
    for playbook_id in playbook_ids:
        playbook = playbooks.for_playbook(playbook_id)
        for offset, phase, action, owner in playbook["steps"]:
            key = (phase, action)
            if key in seen_actions:
                continue
            seen_actions.add(key)
            # Triage starts when the first alert fires; the rest of the
            # playbook starts once the full case scope is known.
            base = detected_at if phase == "Detection" else scoped_at
            entries.append(
                {
                    "ts": _add_minutes(base, offset),
                    "phase": phase,
                    "kind": "response",
                    "description": action,
                    "owner": owner,
                    "source": playbook_id,
                    "event_id": None,
                    "alert_id": None,
                }
            )

    kind_priority = {"telemetry": 0, "detection": 1, "response": 2}
    entries.sort(key=lambda e: (e["ts"], kind_priority.get(e["kind"], 3)))
    return entries


# ---------------------------------------------------------------------------
# Cross-incident linking (campaign view)
# ---------------------------------------------------------------------------

def _link_related(incidents: List[dict]) -> None:
    for i, left in enumerate(incidents):
        left_assets = {a["hostname"] for a in left["affected_assets"]}
        left_origin = left["attack_origin"].get("ip")
        for j, right in enumerate(incidents):
            if i == j:
                continue
            right_assets = {a["hostname"] for a in right["affected_assets"]}
            right_origin = right["attack_origin"].get("ip")
            gap = abs(
                (config.parse_ts(left["first_seen"]) - config.parse_ts(right["first_seen"])).total_seconds()
            )
            shares_asset = bool(left_assets & right_assets)
            shares_origin = bool(left_origin and left_origin == right_origin)
            if gap <= 7 * 24 * 3600 and (shares_asset or shares_origin):
                left["related_incidents"].append(
                    {
                        "incident_id": right["incident_id"],
                        "title": right["title"],
                        "relation": "shared_asset" if shares_asset else "shared_origin",
                    }
                )


# ---------------------------------------------------------------------------
# TheHive export
# ---------------------------------------------------------------------------

def to_thehive(incidents: List[dict]) -> List[dict]:
    cases = []
    for incident in incidents:
        tasks = []
        grouped: Dict[str, List[dict]] = defaultdict(list)
        for action in incident["response_actions"]:
            grouped[action["phase"]].append(action)
        for phase in playbooks.PHASES:
            actions = grouped.get(phase)
            if not actions:
                continue
            tasks.append(
                {
                    "title": f"{phase} ({incident['playbook'] if 'playbook' in incident else incident['playbooks'][0]})",
                    "group": phase,
                    "status": "Completed",
                    "flag": phase in ("Containment", "Post-Incident"),
                    "startDate": _epoch_ms(actions[0]["ts"]),
                    "endDate": _epoch_ms(actions[-1]["ts"]),
                    "logs": [
                        {
                            "message": action["description"],
                            "date": _epoch_ms(action["ts"]),
                            "owner": action.get("owner"),
                        }
                        for action in actions
                    ],
                }
            )
        cases.append(
            {
                "_id": incident["incident_id"],
                "title": incident["title"],
                "description": incident["summary"],
                "severity": SEVERITY_TO_THEHIVE.get(incident["severity"], 2),
                "tlp": 2,
                "pap": 2,
                "status": "Resolved",
                "tags": sorted({"lab", "siem", incident["type"].lower().replace(" ", "-")} | {
                    tactic.lower().replace(" ", "-") for tactic in incident["tactics"]
                }),
                "startDate": _epoch_ms(incident["first_seen"]),
                "endDate": _epoch_ms(incident["closed_at"]),
                "tasks": tasks,
                "customFields": {
                    "risk-score": {"order": 0, "value": incident["risk_score"]},
                    "mitre-tactics": {"order": 1, "value": incident["tactics"]},
                    "detection-rules": {"order": 2, "value": incident["detection_rules"]},
                    "mttd-minutes": {"order": 3, "value": incident["mttd_minutes"]},
                    "mttr-minutes": {"order": 4, "value": incident["mttr_minutes"]},
                },
                "observables": [
                    {"dataType": ioc.get("type", "other"), "data": ioc.get("value"),
                     "tlp": 2, "tags": [ioc.get("threat_type", "")], "message": ioc.get("description", "")}
                    for ioc in incident["iocs"]
                ],
            }
        )
    return cases


def _epoch_ms(ts_iso: str) -> int:
    return int(config.parse_ts(ts_iso).timestamp() * 1000)
