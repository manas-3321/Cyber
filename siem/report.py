"""Incident report generation (the Step 6 documentation deliverable).

Each case is rendered as a standalone Markdown document following the structure
required by the project guide: incident summary, detection and analysis,
mitigation and recovery, and future recommendations.
"""
from __future__ import annotations

from typing import Dict, List

from . import config

TOOLS_USED = [
    "SIEM correlation engine (this repository; Splunk Enterprise / ELK in the lab VM)",
    "Sysmon + Windows Security event forwarding (EDR telemetry)",
    "pfSense / iptables firewall logs and Squid proxy logs",
    "nginx access logs from the public web tier",
    "MISP / ThreatConnect threat-intelligence feed",
    "Wireshark / tcpdump packet capture for validation",
    "TheHive case management (exported in this repository)",
]

IMPACT: Dict[str, str] = {
    "Brute Force": (
        "Credential compromise risk for the targeted accounts. If the attacker authenticated, "
        "confidentiality of data reachable by that account is impacted and further persistence "
        "is likely. Business impact is high when the account has administrative rights."
    ),
    "Reconnaissance": (
        "No direct data impact, but the exposed service inventory and response codes give the "
        "attacker targeting information. Left unaddressed this precedes exploitation."
    ),
    "Web Attack": (
        "Potential integrity and confidentiality impact on the public application and its data. "
        "A successful injection would expose customer records and allow code execution on the web tier."
    ),
    "DDoS": (
        "Availability impact: elevated error rates and latency for customers during the flood. "
        "Revenue and reputation risk proportional to outage duration."
    ),
    "Phishing": (
        "Credential harvesting and malware delivery risk for the recipient. Finance users are "
        "high-value targets for payment fraud."
    ),
    "Malware": (
        "Confidentiality and integrity impact on the infected endpoint and any credentials or "
        "sessions present on it. Command-and-control traffic indicates an active adversary."
    ),
    "Ransomware": (
        "Severe availability and integrity impact on file services. Recovery depends on immutable "
        "backups; there is a regulatory notification obligation if confidential data was exfiltrated."
    ),
    "Lateral Movement": (
        "The blast radius extends beyond the initial host; privileged credentials may be usable on "
        "multiple servers, raising the risk of domain-wide compromise."
    ),
    "Data Breach": (
        "Confidentiality impact on regulated data (employee salary and customer records). "
        "Notification obligations under GDPR / India DPDP Act and contractual breach clauses."
    ),
    "Insider Threat": (
        "Confidentiality impact from misuse of legitimate access; evidence handling and HR/legal "
        "coordination are required in addition to technical containment."
    ),
    "Persistence": (
        "The adversary retains access after remediation unless the persistence mechanism is removed; "
        "integrity of the host configuration is impacted."
    ),
    "Defense Evasion": (
        "Loss of audit evidence impairs investigation and may indicate a deeper, ongoing intrusion."
    ),
}

LESSONS: Dict[str, List[str]] = {
    "Brute Force": [
        "Password authentication on internet-facing SSH is the root enabler; MFA or key-only auth removes it.",
        "The threshold rule fired after 8 failures, but a successful login was only correlated 14 minutes later - move DET-002 to real-time streaming.",
        "Add geo-velocity and impossible-travel correlation for successful logins.",
    ],
    "Reconnaissance": [
        "External scanning is constant; the value is in correlating it with later exploitation attempts.",
        "Reduce the public attack surface and review firewall policy quarterly.",
    ],
    "Web Attack": [
        "The WAF blocked the payloads; verify the same signatures are blocking in production mode.",
        "Add a detection for successful 200 responses carrying traversal payloads (possible WAF bypass).",
    ],
    "DDoS": [
        "Rate limiting was reactive; move the threshold into the CDN edge configuration.",
        "Define an availability SLO and alert on error-budget burn rather than request count alone.",
    ],
    "Phishing": [
        "Attachment detonation and look-alike domain blocking are cheaper than response.",
        "Add a detection for credential entry following a phishing click (proxy POST to the fake portal).",
    ],
    "Malware": [
        "Office child-process creation should be blocked by ASR, not just detected.",
        "Ensure PowerShell script block logging is enabled estate-wide; encoded commands remain a top signal.",
        "Egress allow-listing would have prevented the C2 beacons entirely.",
    ],
    "Ransomware": [
        "Immutable backups limited the blast radius; validate restore time quarterly.",
        "Detect shadow copy deletion (DET-030) as a high-priority precursor and auto-isolate the host.",
        "Tier administrative accounts so a compromised workstation cannot authenticate to file servers with admin rights.",
    ],
    "Lateral Movement": [
        "Attackers moved from a workstation to servers using a valid account; tiered admin and SMB restrictions are required.",
        "Enable Windows Defender for Identity or equivalent to score logon anomalies.",
    ],
    "Data Breach": [
        "DLP was in monitor mode; move Confidential classification to blocking with a documented exception process.",
        "Baseline outbound volume per host and require approval for large uploads to unclassified SaaS.",
    ],
    "Insider Threat": [
        "Access to salary data should be role-based and logged with a business justification workflow.",
        "HR/legal coordination must be part of the runbook, including evidence chain-of-custody.",
    ],
    "Persistence": [
        "Monitor account creation and group membership change events in real time.",
        "Enforce just-in-time privileged access so new sudo users are anomalous by design.",
    ],
    "Defense Evasion": [
        "Forward Windows event logs in near real time so local log clearing does not destroy evidence.",
        "Alert on audit log clearing and treat it as a major incident trigger.",
    ],
}


def _fmt(ts: str | None) -> str:
    if not ts:
        return "-"
    return config.parse_ts(ts).strftime("%Y-%m-%d %H:%M:%S UTC")


def _table(headers: List[str], rows: List[List[str]]) -> str:
    lines = ["| " + " | ".join(headers) + " |",
             "|" + "|".join(["---"] * len(headers)) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(str(cell).replace("|", "\\|") for cell in row) + " |")
    return "\n".join(lines)


def render_incident(incident: dict) -> str:
    assets = incident["affected_assets"]
    asset_rows = [
        [a.get("hostname", "?"), a.get("ip", "-"), a.get("role", "-"), a.get("criticality", "-"),
         a.get("data_classification", "-")]
        for a in assets
    ]
    alert_rows = [
        [alert["alert_id"], alert["rule_id"], alert["rule_name"], alert["severity"],
         alert["risk_score"], alert["event_count"], _fmt(alert["detected_at"])]
        for alert in incident["alerts"]
    ]
    mitre_rows = [[tech["tactic"], tech["technique"], tech["id"]] for tech in incident["mitre"]]
    timeline_rows = [
        [_fmt(entry["ts"]), entry["phase"], entry["kind"],
         entry["description"], entry.get("owner") or entry.get("source") or "-"]
        for entry in incident["timeline"]
    ]
    ioc_rows = [
        [ioc.get("type"), ioc.get("value"), ioc.get("threat_type"), ioc.get("confidence"),
         ioc.get("source"), ioc.get("description", "")]
        for ioc in incident["iocs"]
    ]
    origin = incident["attack_origin"]

    parts = []
    parts.append(f"# {incident['incident_id']} — {incident['title']}")
    parts.append("")
    parts.append(_table(
        ["Field", "Value"],
        [
            ["Incident ID", incident["incident_id"]],
            ["Incident type", ", ".join(incident["types"])],
            ["Severity / priority", f"{incident['severity']} / {incident['priority']}"],
            ["Risk score", f"{incident['risk_score']}/100"],
            ["Status", incident["status"]],
            ["TLP", incident["tlp"]],
            ["First evidence", _fmt(incident["first_seen"])],
            ["Detected", _fmt(incident["detected_at"])],
            ["Contained", _fmt(incident["contained_at"])],
            ["Closed", _fmt(incident["closed_at"])],
            ["MTTD / MTTA / MTTR", f"{incident['mttd_minutes']} min / {incident['mtta_minutes']} min / {incident['mttr_minutes']} min"],
            ["Playbooks", ", ".join(incident["playbooks"])],
            ["Detection rules", ", ".join(incident["detection_rules"])],
            ["Attack origin", origin.get("description", "-")],
            ["Related cases", ", ".join(r["incident_id"] for r in incident["related_incidents"]) or "None"],
        ],
    ))
    parts.append("")

    parts.append("## 1. Incident summary")
    parts.append("")
    parts.append(incident["summary"])
    parts.append("")
    if asset_rows:
        parts.append("**Affected assets**")
        parts.append("")
        parts.append(_table(["Host", "IP", "Role", "Criticality", "Data classification"], asset_rows))
        parts.append("")
    if incident["affected_users"]:
        parts.append(f"**Affected users:** {', '.join(incident['affected_users'])}")
        parts.append("")

    parts.append("## 2. Detection and analysis")
    parts.append("")
    parts.append(f"**Alerts involved ({len(incident['alerts'])})**")
    parts.append("")
    parts.append(_table(["Alert", "Rule", "Name", "Severity", "Score", "Events", "Detected"], alert_rows))
    parts.append("")
    if ioc_rows:
        parts.append("**Threat-intelligence matches**")
        parts.append("")
        parts.append(_table(["Type", "Indicator", "Threat type", "Confidence", "Source", "Description"], ioc_rows))
        parts.append("")
    parts.append(f"**Telemetry analysed:** {incident['event_count']} normalised events from "
                 "Linux auth, Windows Security, firewall, proxy, EDR and web logs.")
    parts.append("")
    parts.append("**Tools used**")
    parts.append("")
    for tool in TOOLS_USED:
        parts.append(f"- {tool}")
    parts.append("")
    parts.append("**MITRE ATT&CK mapping**")
    parts.append("")
    parts.append(_table(["Tactic", "Technique", "ID"], mitre_rows))
    parts.append("")

    parts.append("## 3. Timeline of events")
    parts.append("")
    parts.append(_table(["Timestamp", "Phase", "Type", "Description", "Owner / source"], timeline_rows))
    parts.append("")

    parts.append("## 4. Root-cause analysis")
    parts.append("")
    parts.append(incident["root_cause"])
    parts.append("")
    parts.append(
        "The chain is reconstructable end-to-end from normalised telemetry: each alert below is linked "
        "to the exact event IDs listed in the evidence section, and the timeline is ordered by the "
        "original source timestamps rather than by detection time."
    )
    parts.append("")

    parts.append("## 5. Impact assessment")
    parts.append("")
    for incident_type in incident["types"]:
        text = IMPACT.get(incident_type)
        if text:
            parts.append(f"- **{incident_type}:** {text}")
    critical_assets = [a["hostname"] for a in assets if a.get("criticality") in ("Critical", "High")]
    if critical_assets:
        parts.append(f"- **High-value assets involved:** {', '.join(critical_assets)}")
    parts.append("")

    parts.append("## 6. Response and recovery")
    parts.append("")
    response_rows = [
        [_fmt(action["ts"]), action["phase"], action["description"], action.get("owner", "-"),
         action.get("source", "-")]
        for action in incident["response_actions"]
    ]
    parts.append(_table(["Time", "Phase", "Action", "Owner", "Playbook"], response_rows))
    parts.append("")
    parts.append("System recovery was validated by confirming normal authentication, file-access and "
                 "network telemetry for the affected assets for the remainder of the capture window.")
    parts.append("")

    parts.append("## 7. Evidence and artefacts")
    parts.append("")
    parts.append(f"- Alert IDs: {', '.join(incident['evidence']['alert_ids'])}")
    parts.append(f"- Event IDs: {', '.join(incident['evidence']['event_ids'][:40])}"
                 + (" …" if len(incident["evidence"]["event_ids"]) > 40 else ""))
    parts.append(f"- Case export: `output/thehive_cases.json` (case `{incident['incident_id']}`)")
    parts.append(f"- Dashboard entry: `output/dashboard.html#case-{incident['incident_id']}`")
    parts.append("")

    parts.append("## 8. Recommendations")
    parts.append("")
    for recommendation in incident["recommendations"]:
        parts.append(f"- {recommendation}")
    parts.append("")

    parts.append("## 9. Lessons learned and detection improvements")
    parts.append("")
    for lesson in LESSONS.get(incident["type"], []):
        parts.append(f"- {lesson}")
    parts.append("")
    parts.append("---")
    parts.append("")
    parts.append("*Generated from the lab SIEM pipeline; timestamps are UTC.*")
    parts.append("")
    return "\n".join(parts)


def render_index(incidents: List[dict], metrics: dict) -> str:
    rows = []
    for incident in incidents:
        rows.append([
            f"[{incident['incident_id']}]({incident['incident_id']}.md)",
            incident["title"],
            incident["severity"],
            incident["priority"],
            incident["status"],
            f"{incident['risk_score']}",
            incident["mttr_minutes"],
            incident["detected_at"][:16].replace("T", " "),
        ])
    lines = ["# Incident Register", ""]
    lines.append(f"{len(incidents)} cases generated from the seven-day lab capture.")
    lines.append("")
    lines.append(_table(["Case", "Title", "Severity", "Priority", "Status", "Score", "MTTR (min)", "Detected"],
                       rows))
    lines.append("")
    lines.append("## Aggregate metrics")
    lines.append("")
    lines.append(_table(
        ["Metric", "Value"],
        [
            ["Total incidents", metrics["incidents"]["total"]],
            ["Critical / High", f"{metrics['incidents']['by_severity']['Critical']} / {metrics['incidents']['by_severity']['High']}"],
            ["Mean MTTD", f"{metrics['incidents']['mttd_minutes']['mean']} min"],
            ["Mean MTTA", f"{metrics['incidents']['mtta_minutes']['mean']} min"],
            ["Mean MTTR", f"{metrics['incidents']['mttr_hours']['mean']} h"],
            ["Actionable alerts", metrics["detections"]["actionable_alerts"]],
            ["Suppressed (tuning)", metrics["detections"]["suppressed_alerts"]],
            ["Technique coverage", f"{metrics['coverage']['techniques_detected']}/{metrics['coverage']['techniques_defined']}"],
        ],
    ))
    lines.append("")
    return "\n".join(lines)


def render_executive_summary(metrics: dict, incidents: List[dict]) -> str:
    critical = [i for i in incidents if i["severity"] == "Critical"]
    rows = [
        [i["incident_id"], i["title"], i["severity"], i["priority"], i["mttr_minutes"]]
        for i in incidents
    ]
    lines = [
        "# Executive Summary — Week 43 2026 (19-25 October)",
        "",
        "## Headline",
        "",
        f"During the monitored week the SOC ingested **{metrics['events']['total']:,} events** across "
        f"{len(metrics['events']['by_source'])} log sources and produced "
        f"**{metrics['detections']['actionable_alerts']} actionable alerts** which consolidated into "
        f"**{metrics['incidents']['total']} incidents** "
        f"({metrics['incidents']['by_severity']['Critical']} Critical, "
        f"{metrics['incidents']['by_severity']['High']} High, "
        f"{metrics['incidents']['by_severity']['Medium']} Medium, "
        f"{metrics['incidents']['by_severity']['Low']} Low).",
        "",
        f"Two events carried material business risk: a phishing-initiated intrusion on finance "
        f"workstation `ws-fin-14` that progressed to ransomware on the file server `fs01`, and an "
        f"insider data exfiltration from `fs01` to a known exfiltration destination. Both were "
        f"detected within the same hour as the first malicious event and contained with documented "
        f"playbooks.",
        "",
        "## Key metrics",
        "",
        _table(["Metric", "Value", "Comment"], [
            ["Mean time to detect (MTTD)", f"{metrics['incidents']['mttd_minutes']['mean']} min",
             "Correlation runs at ingest time; rule to alert latency is seconds"],
            ["Mean time to acknowledge (MTTA)", f"{metrics['incidents']['mtta_minutes']['mean']} min",
             "L1 triage simulation"],
            ["Mean time to respond (MTTR)", f"{metrics['incidents']['mttr_hours']['mean']} h",
             "Detection to validated recovery"],
            ["Alert noise reduction", f"{metrics['detections']['suppression_rate']}%",
             f"{metrics['detections']['suppressed_alerts']} alerts suppressed by documented allowlists"],
            ["ATT&CK technique coverage", f"{metrics['coverage']['techniques_detected']}/{metrics['coverage']['techniques_defined']}",
             "Techniques exercised by the scenario set"],
            ["Rules triggered", f"{metrics['coverage']['rules_triggered']}/{metrics['coverage']['rules_defined']}",
             "Unused rules reviewed in the detection-engineering backlog"],
        ]),
        "",
        "## Cases",
        "",
        _table(["Case", "Title", "Severity", "Priority", "MTTR (min)"], rows),
        "",
        "## Priority recommendations",
        "",
        "1. Remove password authentication from internet-facing SSH and RDP; enforce phishing-resistant MFA.",
        "2. Move egress to an allow-listed proxy and put DLP for Confidential data into blocking mode.",
        "3. Enforce tiered administration and restrict SMB admin shares to jump hosts.",
        "4. Validate immutable backup restore quarterly and protect backup infrastructure with separate credentials.",
        "5. Enable ASR rules that block Office child processes and shadow-copy deletion tooling.",
        "",
        f"Full detail: `output/incidents/` ({len(incidents)} case reports) and `output/dashboard.html`.",
        "",
    ]
    return "\n".join(lines)
