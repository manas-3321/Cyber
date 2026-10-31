"""Static HTML dashboard generation.

Output is a single self-contained file (no CDN, no build step) so it can be
opened from disk, attached as evidence, or served by ``python -m siem serve``.
"""
from __future__ import annotations

import html
import json
from collections import Counter
from typing import Dict, List

from . import charts, config
from .incidents import TACTIC_ORDER

CSS = """
:root {
  --bg: #0b1120; --panel: #111a2e; --panel-2: #16213a; --border: #23304d;
  --text: #e6edf7; --muted: #93a4c0; --accent: #4d8dff;
  --critical: #ef4444; --high: #f97316; --medium: #eab308; --low: #22c55e;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font-family: ui-sans-serif, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  font-size: 14px; line-height: 1.5; }
header { padding: 28px 32px 18px; border-bottom: 1px solid var(--border);
  background: linear-gradient(120deg, #0b1120 0%, #12203a 60%, #0b1120 100%); }
header h1 { margin: 0; font-size: 22px; letter-spacing: 0.2px; }
header p { margin: 6px 0 0; color: var(--muted); }
.badge { display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 11px;
  font-weight: 600; letter-spacing: 0.4px; text-transform: uppercase; }
.sev-Critical { background: rgba(239,68,68,0.16); color: var(--critical); border: 1px solid rgba(239,68,68,0.45); }
.sev-High { background: rgba(249,115,22,0.16); color: var(--high); border: 1px solid rgba(249,115,22,0.45); }
.sev-Medium { background: rgba(234,179,8,0.16); color: var(--medium); border: 1px solid rgba(234,179,8,0.45); }
.sev-Low { background: rgba(34,197,94,0.16); color: var(--low); border: 1px solid rgba(34,197,94,0.45); }
nav { display: flex; gap: 4px; padding: 0 32px; border-bottom: 1px solid var(--border);
  background: var(--panel); position: sticky; top: 0; z-index: 5; overflow-x: auto; }
nav button { background: none; border: none; color: var(--muted); padding: 12px 16px; cursor: pointer;
  font-size: 13px; font-weight: 600; border-bottom: 2px solid transparent; white-space: nowrap; }
nav button:hover { color: var(--text); }
nav button.active { color: var(--text); border-bottom-color: var(--accent); }
main { padding: 24px 32px 64px; max-width: 1440px; }
section { display: none; }
section.active { display: block; }
.grid { display: grid; gap: 16px; }
.kpis { grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); margin-bottom: 22px; }
.card { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 16px 18px; }
.kpi .label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.6px; }
.kpi .value { font-size: 30px; font-weight: 700; margin-top: 6px; }
.kpi .sub { color: var(--muted); font-size: 12px; margin-top: 4px; }
.charts { grid-template-columns: repeat(auto-fit, minmax(430px, 1fr)); margin-bottom: 20px; }
.chart { background: #fff; border-radius: 12px; padding: 8px; overflow-x: auto; }
h2 { font-size: 16px; margin: 26px 0 12px; }
h3 { font-size: 14px; margin: 0 0 8px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
th { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; }
tbody tr:hover { background: rgba(77,141,255,0.06); }
.table-wrap { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; overflow: auto; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
.muted { color: var(--muted); }
.controls { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin-bottom: 12px; }
.controls input { background: var(--panel-2); border: 1px solid var(--border); color: var(--text);
  border-radius: 8px; padding: 8px 12px; min-width: 260px; }
.chip { background: var(--panel-2); border: 1px solid var(--border); color: var(--muted);
  border-radius: 999px; padding: 6px 12px; cursor: pointer; font-size: 12px; }
.chip.active { color: #fff; border-color: var(--accent); background: rgba(77,141,255,0.18); }
details.case { background: var(--panel); border: 1px solid var(--border); border-radius: 12px;
  padding: 14px 18px; margin-bottom: 12px; }
details.case summary { cursor: pointer; list-style: none; display: flex; gap: 12px;
  align-items: center; flex-wrap: wrap; }
details.case summary::-webkit-details-marker { display: none; }
details.case[open] summary { margin-bottom: 14px; }
.case-title { font-weight: 600; font-size: 14px; }
.case-meta { color: var(--muted); font-size: 12px; }
.kv { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 8px 18px;
  margin: 10px 0 16px; font-size: 13px; }
.kv div span { color: var(--muted); display: block; font-size: 11px; text-transform: uppercase;
  letter-spacing: 0.5px; }
.timeline { border-left: 2px solid var(--border); margin: 10px 0 4px 6px; padding-left: 14px; }
.timeline .item { margin-bottom: 10px; font-size: 13px; }
.timeline .ts { color: var(--muted); font-size: 11px; font-family: ui-monospace, monospace; }
.tag { font-size: 11px; padding: 1px 7px; border-radius: 5px; background: var(--panel-2);
  border: 1px solid var(--border); color: var(--muted); margin-right: 4px; }
footer { padding: 20px 32px; border-top: 1px solid var(--border); color: var(--muted); font-size: 12px; }
"""

JS = """
const buttons = document.querySelectorAll('nav button');
function showSection(target) {
  buttons.forEach(b => b.classList.toggle('active', b.dataset.target === target));
  document.querySelectorAll('section').forEach(s => s.classList.toggle('active', s.id === target));
  window.scrollTo({ top: 0, behavior: 'smooth' });
}
buttons.forEach(btn => btn.addEventListener('click', () => showSection(btn.dataset.target)));
document.querySelectorAll('a[href^="#case-"]').forEach(link => link.addEventListener('click', event => {
  event.preventDefault();
  showSection('incidents');
  const card = document.querySelector(link.getAttribute('href'));
  if (card) { card.open = true; card.scrollIntoView({ behavior: 'smooth' }); }
}));
const search = document.getElementById('alert-search');
const chips = document.querySelectorAll('.chip[data-sev]');
let activeSeverity = 'all';
function applyFilters() {
  const term = (search?.value || '').toLowerCase();
  document.querySelectorAll('#alert-rows tr').forEach(row => {
    const sev = row.dataset.severity;
    const text = row.dataset.text.toLowerCase();
    const sevOk = activeSeverity === 'all' || sev === activeSeverity;
    row.style.display = (sevOk && text.includes(term)) ? '' : 'none';
  });
}
chips.forEach(chip => chip.addEventListener('click', () => {
  chips.forEach(c => c.classList.remove('active'));
  chip.classList.add('active');
  activeSeverity = chip.dataset.sev;
  applyFilters();
}));
if (search) search.addEventListener('input', applyFilters);
"""


def _e(value) -> str:
    return html.escape(str(value if value is not None else ""))


def _sev(value: str) -> str:
    return f'<span class="badge sev-{_e(value)}">{_e(value)}</span>'


def _table(headers: List[str], rows: List[List[str]], table_id: str = "") -> str:
    id_attr = f' id="{table_id}"' if table_id else ""
    head = "".join(f"<th>{_e(header)}</th>" for header in headers)
    body = []
    for row in rows:
        body.append("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>")
    return (f'<div class="table-wrap"><table{id_attr}><thead><tr>{head}</tr></thead>'
            f'<tbody>{"".join(body)}</tbody></table></div>')


def _fmt_ts(ts: str | None) -> str:
    if not ts:
        return "-"
    return config.parse_ts(ts).strftime("%d %b %H:%M:%S")


def _kpi(label: str, value, sub: str = "") -> str:
    return (f'<div class="card kpi"><div class="label">{_e(label)}</div>'
            f'<div class="value">{_e(value)}</div><div class="sub">{_e(sub)}</div></div>')


def build_dashboard(metrics: dict, incidents: List[dict], alerts: List[dict],
                    suppressed: List[dict], intel_indicators: List[dict]) -> Dict[str, str]:
    """Return {filename: content} for the dashboard and the standalone charts."""
    visuals: Dict[str, str] = {}

    events_by_day = metrics["events"]["by_day"]
    events_line = charts.line_chart(
        [(label[5:], value) for label, value in events_by_day.items()],
        "Event volume per day (all sources)", y_label="events", color="#4d8dff")
    visuals["events-per-day.svg"] = events_line

    severity_counts = metrics["detections"]["by_severity"]
    severity_bar = charts.stacked_bar(
        [(severity, severity_counts[severity]) for severity in config.SEVERITIES],
        "Alerts by severity",
        colors=[charts.SEVERITY_COLORS[s] for s in config.SEVERITIES])
    visuals["alerts-by-severity.svg"] = severity_bar

    type_counts = metrics["incidents"]["by_type"]
    type_bar = charts.h_bar_chart(
        [(key, value) for key, value in type_counts.items()],
        "Incidents by type", width=560, label_width=170)
    visuals["incidents-by-type.svg"] = type_bar

    top_rules = [(item["name"], item["alerts"]) for item in metrics["detections"]["top_rules"][:8]]
    rules_bar = charts.h_bar_chart(top_rules, "Alerts by detection rule", width=640, label_width=250)
    visuals["top-detection-rules.svg"] = rules_bar

    tactic_counts = Counter()
    for alert in alerts:
        for technique in alert.get("mitre", []):
            tactic_counts[technique["tactic"]] += 1
    tactic_items = [(tactic, tactic_counts.get(tactic, 0)) for tactic in TACTIC_ORDER]
    tactics_bar = charts.h_bar_chart(tactic_items, "ATT&CK tactic coverage (alerts)",
                                     width=560, label_width=170, colors=["#7c3aed"] * len(tactic_items))
    visuals["mitre-tactics.svg"] = tactics_bar

    # -- KPI cards -------------------------------------------------------
    kpis = "".join([
        _kpi("Events ingested", f"{metrics['events']['total']:,}",
             f"{len(metrics['events']['by_source'])} sources · {metrics['events']['mean_parse_rate']}% parse rate"),
        _kpi("Actionable alerts", metrics["detections"]["actionable_alerts"],
             f"{metrics['detections']['suppressed_alerts']} suppressed by tuning"),
        _kpi("Incidents", metrics["incidents"]["total"],
             f"{metrics['incidents']['by_severity']['Critical']} critical · "
             f"{metrics['incidents']['by_severity']['High']} high"),
        _kpi("Mean MTTD", f"{metrics['incidents']['mttd_minutes']['mean']} min",
             "first malicious event → alert"),
        _kpi("Mean MTTR", f"{metrics['incidents']['mttr_hours']['mean']} h",
             "first event → validated recovery"),
        _kpi("ATT&CK coverage",
             f"{metrics['coverage']['techniques_detected']}/{metrics['coverage']['techniques_defined']}",
             "techniques exercised"),
    ])

    # -- overview tables -------------------------------------------------
    overview_rows = []
    for incident in incidents:
        overview_rows.append([
            f'<a href="#case-{_e(incident["incident_id"])}">{_e(incident["incident_id"])}</a>',
            _e(incident["title"]),
            _sev(incident["severity"]),
            _e(incident["priority"]),
            _e(incident["risk_score"]),
            _e(len(incident["alerts"])),
            _e(_fmt_ts(incident["detected_at"])),
            _e(f"{incident['mttr_minutes']} min"),
        ])
    overview_table = _table(
        ["Case", "Title", "Severity", "Priority", "Risk", "Alerts", "Detected", "MTTR"],
        overview_rows)

    # -- incident cards --------------------------------------------------
    case_cards = []
    for incident in incidents:
        asset_tags = "".join(
            f'<span class="tag">{_e(asset["hostname"])} · {_e(asset.get("criticality", "-"))}</span>'
            for asset in incident["affected_assets"])
        mitre_tags = "".join(
            f'<span class="tag">{_e(tech["id"])} {_e(tech["technique"])}</span>'
            for tech in incident["mitre"])
        alert_rows = []
        for alert in incident["alerts"]:
            alert_rows.append([
                f'<span class="mono">{_e(alert["alert_id"])}</span>',
                _e(alert["rule_id"]),
                _e(alert["rule_name"]),
                _sev(alert["severity"]),
                _e(alert["risk_score"]),
                _e(alert["event_count"]),
                _e(_fmt_ts(alert["detected_at"])),
            ])
        alert_table = _table(["Alert", "Rule", "Name", "Severity", "Score", "Events", "Detected"],
                             alert_rows)
        timeline_items = "".join(
            f'<div class="item"><div class="ts">{_e(entry["ts"].replace("T", " ").replace("Z", " UTC"))}'
            f' · {_e(entry["phase"])} · {_e(entry["kind"])}</div>{_e(entry["description"])}</div>'
            for entry in incident["timeline"][:40]
        )
        recommendations = "".join(f"<li>{_e(item)}</li>" for item in incident["recommendations"])
        case_cards.append(f"""
<details class="case" id="case-{_e(incident['incident_id'])}">
  <summary>
    <span class="case-title">{_e(incident['incident_id'])} — {_e(incident['title'])}</span>
    {_sev(incident['severity'])}
    <span class="badge" style="background:var(--panel-2);color:var(--muted);border:1px solid var(--border)">{_e(incident['priority'])}</span>
    <span class="case-meta">risk {_e(incident['risk_score'])}/100 · {_e(incident['status'])} · MTTR {_e(incident['mttr_minutes'])} min</span>
  </summary>
  <div class="kv">
    <div><span>Type</span>{_e(', '.join(incident['types']))}</div>
    <div><span>Affected assets</span>{asset_tags or '-'}</div>
    <div><span>Users</span>{_e(', '.join(incident['affected_users']) or '-')}</div>
    <div><span>Attack origin</span>{_e(incident['attack_origin'].get('description', '-'))}</div>
    <div><span>Detected</span>{_e(_fmt_ts(incident['detected_at']))}</div>
    <div><span>Contained</span>{_e(_fmt_ts(incident['contained_at']))}</div>
  </div>
  <h3>Summary</h3>
  <p>{_e(incident['summary'])}</p>
  <h3>Root cause</h3>
  <p>{_e(incident['root_cause'])}</p>
  <h3>MITRE ATT&amp;CK</h3>
  <p>{mitre_tags or '—'}</p>
  <h3>Alerts</h3>
  {alert_table}
  <h3 style="margin-top:16px">Timeline</h3>
  <div class="timeline">{timeline_items}</div>
  <h3>Recommendations</h3>
  <ul>{recommendations}</ul>
  <p class="muted"><a href="incidents/{_e(incident['incident_id'])}.md">Full incident report (Markdown)</a></p>
</details>""")

    # -- alert table -----------------------------------------------------
    alert_rows_html = []
    for alert in sorted(alerts, key=lambda a: a["detected_at"], reverse=True):
        text = " ".join([
            alert["alert_id"], alert["rule_id"], alert["rule_name"], alert["incident_type"],
            json.dumps(alert["entity"]), alert.get("summary", ""),
        ]).lower()
        alert_rows_html.append(
            f'<tr data-severity="{_e(alert["severity"])}" data-text="{_e(text)}">'
            f'<td class="mono">{_e(alert["alert_id"])}</td>'
            f'<td>{_sev(alert["severity"])}</td>'
            f'<td>{_e(alert["rule_id"])}<div class="muted" style="font-size:11px">{_e(alert["rule_name"])}</div></td>'
            f'<td>{_e(alert["incident_type"])}</td>'
            f'<td class="mono">{_e(json.dumps(alert["entity"]))}</td>'
            f'<td>{_e(alert["risk_score"])}</td>'
            f'<td>{_e(alert["event_count"])}</td>'
            f'<td class="muted" style="max-width:420px">{_e(alert.get("summary", ""))}</td>'
            f'<td class="mono">{_e(_fmt_ts(alert["detected_at"]))}</td></tr>'
        )
    chip_html = '<button class="chip active" data-sev="all">All</button>' + "".join(
        f'<button class="chip" data-sev="{_e(severity)}">{_e(severity)}</button>'
        for severity in config.SEVERITIES)

    # -- coverage / intel / quality --------------------------------------
    coverage_rows = []
    for rule in metrics["coverage"]["rule_detail"]:
        coverage_rows.append([
            f'<span class="mono">{_e(rule["rule_id"])}</span>',
            _e(rule["name"]),
            _e(rule["type"]),
            _sev(rule["severity"] or "Medium"),
            _e(rule["incident_type"]),
            _e(", ".join(rule["techniques"])),
            _e(rule["alerts"]),
            _e(rule["suppressed"]),
            "✅" if rule["triggered"] else "—",
        ])
    coverage_table = _table(
        ["Rule", "Name", "Type", "Severity", "Incident type", "ATT&CK", "Alerts", "Suppressed", "Exercised"],
        coverage_rows)

    intel_rows = [
        [_e(ioc["type"]), f'<span class="mono">{_e(ioc["value"])}</span>', _e(ioc["threat_type"]),
         _e(ioc["confidence"]), _e(ioc["source"]), _e(ioc["first_seen"]), _e(ioc["description"])]
        for ioc in intel_indicators
    ]
    intel_table = _table(["Type", "Indicator", "Threat type", "Confidence", "Feed", "First seen", "Description"],
                         intel_rows)

    ingest_rows = [
        [f'<span class="mono">{_e(row["file"])}</span>', _e(row["parser"]), _e(row["raw_lines"]),
         _e(row["events"]), _e(f'{row["parse_rate"]}%')]
        for row in metrics["events"]["ingest_files"]
    ]
    ingest_table = _table(["Log file", "Parser", "Raw lines", "Events", "Parse rate"], ingest_rows)

    suppression_rows = [
        [_e(item["allowlist"]), _e(item["reason"]), _e(item["alerts"])]
        for item in metrics["tuning"]["by_reason"]
    ] or [["—", "No alerts were suppressed in this capture window", "0"]]
    suppression_table = _table(["Allowlist", "Justification", "Alerts suppressed"], suppression_rows)

    anomaly_rows = []
    for feature, payload in metrics["tuning"]["anomaly_models"].items():
        if feature == "first_seen_process":
            anomaly_rows.append([
                _e(feature), _e("novelty"), _e(payload.get("hosts_observed")),
                _e(", ".join(f"{host}: {', '.join(values)}"
                             for host, values in payload.get("novel_processes", {}).items()) or "none"),
            ])
        else:
            groups = payload.get("groups", {})
            anomaly_rows.append([
                _e(feature), _e("robust z-score"), _e(len(groups)),
                _e("; ".join(f"{host}: median {group.get('median_bytes') or group.get('median_failures')}"
                             f" (basis {group.get('basis')})" for host, group in groups.items()) or "n/a"),
            ])
    anomaly_table = _table(["Feature", "Method", "Groups", "Baseline"], anomaly_rows)

    window = metrics["window"]
    generated = metrics["generated_at"].replace("T", " ").replace("Z", " UTC")

    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SOC Dashboard — Security Incident Detection and Analysis</title>
<style>{CSS}</style>
</head>
<body>
<header>
  <h1>SOC Detection &amp; Response Dashboard</h1>
  <p>Security Incident Detection and Analysis lab · capture window
     {_e(window['start'][:10])} → {_e(window['end'][:10])} · generated {_e(generated)}</p>
  <p><span class="tag">SIEM correlation</span><span class="tag">Threat intelligence</span>
     <span class="tag">Anomaly detection</span><span class="tag">TheHive cases</span>
     <span class="tag">{_e(metrics['events']['total'])} events</span></p>
</header>
<nav>
  <button class="active" data-target="overview">Overview</button>
  <button data-target="incidents">Incidents</button>
  <button data-target="alerts">Alerts</button>
  <button data-target="coverage">Detection coverage</button>
  <button data-target="intel">Threat intelligence</button>
  <button data-target="quality">Data quality &amp; tuning</button>
</nav>
<main>
  <section id="overview" class="active">
    <div class="grid kpis">{kpis}</div>
    <div class="grid charts">
      <div class="chart">{events_line}</div>
      <div class="chart">{severity_bar}</div>
      <div class="chart">{type_bar}</div>
      <div class="chart">{rules_bar}</div>
    </div>
    <h2>Incident register</h2>
    {overview_table}
    <h2>ATT&amp;CK tactic coverage</h2>
    <div class="chart" style="max-width:600px">{tactics_bar}</div>
  </section>

  <section id="incidents">
    <h2>Cases ({len(incidents)})</h2>
    {''.join(case_cards)}
  </section>

  <section id="alerts">
    <h2>Alerts ({len(alerts)})</h2>
    <div class="controls">
      {chip_html}
      <input id="alert-search" type="search" placeholder="Search rule, entity, indicator…">
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Alert</th><th>Severity</th><th>Rule</th><th>Type</th><th>Entity</th>
        <th>Risk</th><th>Events</th><th>Summary</th><th>Detected</th></tr></thead>
        <tbody id="alert-rows">{''.join(alert_rows_html)}</tbody>
      </table>
    </div>
    <h2>Suppressed alerts (tuning evidence)</h2>
    {suppression_table}
  </section>

  <section id="coverage">
    <h2>Detection rule coverage</h2>
    <p class="muted">{metrics['coverage']['rules_triggered']} of {metrics['coverage']['rules_defined']}
    rules were exercised by the scenario set
    ({metrics['coverage']['rule_utilisation_pct']}%). Techniques detected:
    {metrics['coverage']['techniques_detected']} of {metrics['coverage']['techniques_defined']}.</p>
    {coverage_table}
    <h2>Unused or partially covered techniques</h2>
    <p class="muted">{_e(', '.join(metrics['coverage']['techniques_missed']) or 'None')}</p>
  </section>

  <section id="intel">
    <h2>Threat-intelligence feed ({len(intel_indicators)} indicators)</h2>
    {intel_table}
    <h2>Indicators that produced alerts</h2>
    {_table(["Indicator", "Threat type", "Alerts"],
            [[_e(item["indicator"]), _e(item["threat_type"]), _e(item["alerts"])]
             for item in metrics["threat_intel"]["top_matches"]])}
  </section>

  <section id="quality">
    <h2>Log ingestion</h2>
    {ingest_table}
    <h2>Anomaly model baselines</h2>
    {anomaly_table}
    <h2>Suppression governance</h2>
    {suppression_table}
    <p class="muted">Allowlists are stored in <span class="mono">detections/allowlists.json</span>
    with owner, change ticket and expiry date for every exception.</p>
  </section>
</main>
<footer>
  Generated by the lab SIEM pipeline · all timestamps UTC · data is synthetic and contains no real
  personal or customer information.
</footer>
<script>{JS}</script>
</body>
</html>
"""
    visuals["dashboard.html"] = page
    return visuals
