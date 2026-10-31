# 00 — How to use this project

Everything below works from a clean checkout with **Python 3.10+ only** — no pip
install, no SIEM licence, no internet.

---

## 1. Sixty-second tour

```bash
cd Cyber

python3 -m siem generate   # 1. build the seven-day log capture (data/logs)
python3 -m siem run        # 2. detect, score, correlate, report (output/)
python3 -m siem serve      # 3. open http://localhost:8000
```

`serve` prints `dashboard available at http://0.0.0.0:8000/`. Open it, then:

| Tab | What to do there |
|---|---|
| **Overview** | Read the six KPIs, then scroll to the incident register. Start here. |
| **Incidents** | Expand a case. `INC-2026-0006` is the flagship: phishing → malware → lateral movement → ransomware. |
| **Alerts** | Click the **Critical** chip, or search `203.0.113.44` / `fs01` / `data-share-cloud.net`. |
| **Detection coverage** | Which of the 29 rules fired, which were suppressed, ATT&CK techniques per rule. |
| **Threat intelligence** | The IOC feed and which indicators produced alerts. |
| **Data quality & tuning** | Per-file parse rates, anomaly baselines, allowlist justifications. |

Equivalent one-liners if you prefer `make`:

```bash
make all     # generate + run + test
make serve   # dashboard only (use --refresh via: python3 -m siem serve --refresh)
make test    # 42 tests
make clean   # remove output/ and data/logs, start over
```

---

## 2. What just got created

| Path | What it is | How to read it |
|---|---|---|
| `output/dashboard.html` | Self-contained SOC dashboard (no CDN needed) | Browser, or `python3 -m siem serve` |
| `output/incidents/INC-2026-000X.md` | One 9-section report per case | `cat` or any Markdown viewer |
| `output/incidents/INDEX.md` | Case register + aggregate metrics | Markdown |
| `output/EXECUTIVE_SUMMARY.md` | One-page CISO view | Markdown |
| `output/metrics.json` | Every number in the reports | `jq` / Python |
| `output/alerts.json` | 34 alerts with entities, scores, event IDs | `jq` |
| `output/suppressed_alerts.json` | The 3 tuned-out alerts + justification | `jq` |
| `output/thehive_cases.json` | TheHive-compatible cases, tasks, observables | Import into TheHive |
| `output/ingest_stats.json` | Raw lines vs parsed events vs parse rate | `jq` |
| `output/visuals/*.svg` | Five standalone charts (screenshot-friendly) | Browser / GitHub |
| `output/events.jsonl` | All 1,092 normalised events | `head`, `grep` |
| `data/logs/**` | The raw capture in native formats | `head`, your SIEM |

---

## 3. Reading a case report

Open one:

```bash
sed -n '1,80p' output/incidents/INC-2026-0006.md
```

Sections, in order, and what to look for:

1. **Header table** — type, severity/priority, risk score, MTTD/MTTA/MTTR, playbooks.
2. **Incident summary** — one paragraph plus affected assets with criticality and data classification.
3. **Detection and analysis** — every alert, the IOC matches, tools used, ATT&CK mapping.
4. **Timeline** — telemetry, detections and response actions in one ordered table.
5. **Root cause** — why it was possible, in plain language.
6. **Impact assessment** — per incident type, with high-value assets called out.
7. **Response and recovery** — who did what, when, under which playbook.
8. **Evidence** — alert IDs and event IDs you can grep in `events.jsonl`.
9. **Recommendations / lessons learned** — feeds the 30/60/90-day roadmap in `docs/08`.

Follow evidence by event ID:

```bash
grep -m3 'EVT-000431' output/events.jsonl | jq .
```

---

## 4. Everyday analyst queries (jq)

```bash
# Critical alerts, newest first
jq -r '.[] | select(.severity=="Critical") | [.alert_id,.rule_id,.incident_type,.risk_score,.summary] | @tsv' \
   output/alerts.json

# What did a specific IP do?
jq -r '.[] | select(.observables.source_ips[]? == "203.0.113.44") | "\(.alert_id) \(.rule_id) \(.summary)"' \
   output/alerts.json

# Alert volume per rule
jq -r '.[] | .rule_id' output/alerts.json | sort | uniq -c | sort -rn

# Why was something suppressed?
jq -r '.[] | "\(.alert_id) \(.rule_id) -> \(.suppression.id): \(.suppression.reason)"' \
   output/suppressed_alerts.json

# Current SOC KPIs
jq '{events: .events.total, alerts: .detections.actionable_alerts,
     incidents: .incidents.by_severity, mttd: .incidents.mttd_minutes.mean,
     mttr_h: .incidents.mttr_hours.mean}' output/metrics.json
```

---

## 5. Change something (the interesting part)

### 5.1 Add a detection rule

1. Append to the `rules` array in `detections/rules.json`:

```json
{
  "id": "DET-050",
  "name": "SSH login from an unusual country",
  "description": "Successful SSH login from a geolocation never seen for this host in the last 30 days.",
  "type": "match",
  "severity": "High",
  "confidence": 0.7,
  "incident_type": "Brute Force",
  "playbook": "PB-BRUTE-FORCE",
  "mitre": [{"id": "T1078", "tactic": "Defense Evasion", "technique": "Valid Accounts"}],
  "match": {
    "event.action": ["ssh_login_success"],
    "source.internal": [false],
    "source.geo.country": ["Russia"]
  },
  "group_by": ["source.ip", "host.name"],
  "window_seconds": 3600,
  "false_positive_notes": "Travelling staff; confirm with the user directory."
}
```

2. Run and confirm:

```bash
python3 -m siem run | head -20
python3 -m unittest tests.test_detection -v      # coverage test may need the new rule added
```

Rules are data, not code — no Python changes, no restart of anything.

### 5.2 Tune a false positive (the right way)

Add to `detections/allowlists.json` — never delete a rule because it is noisy:

```json
{
  "id": "AL-005",
  "rule_ids": ["DET-034"],
  "match": {"user.name": ["j.patel"]},
  "reason": "Finance month-end close runs 20:00-23:00 UTC; approved by the finance controller.",
  "owner": "finance-ops",
  "ticket": "CHG-2026-0781",
  "expires": "2027-01-31"
}
```

Every suppression needs an **owner, ticket and expiry**, and suppressed alerts stay in
`output/suppressed_alerts.json` — tuning is auditable by design.

### 5.3 Change how severity is calculated

`siem/scoring.py` is ~100 lines: `BASE`, `ASSET_BONUS`, `INTEL_BONUS`, the confidence
penalty and `severity_from_score()`. Editing those constants re-prioritises every case;
`python3 -m unittest` verifies the bounded-score and priority invariants afterwards.

### 5.4 Add or change an attack scenario

`scenarios/generator.py` holds one function per scenario (`scenario_phishing_malware`,
`scenario_ransomware`, …). Add your events there, then regenerate:

```bash
python3 -m siem generate && python3 -m siem run
```

The generator writes each line in the source's native format, so you can also point the
parsers at real exports by dropping files into `data/logs/<source>/`.

### 5.5 Work on a different capture window

Date helpers live at the top of `scenarios/generator.py` (`START`). Shift `START`, and
the seven-day window (including the business-hours and off-hours logic) moves with it.
Remember to update the capture-window text in `README.md` and `docs/07` if you publish it.

---

## 6. Use the detection content in a real SIEM

| You have | Use |
|---|---|
| Splunk | Paste searches from `detections/splunk/searches.spl`; create lookups from `data/threat_intel/indicators.csv` and `data/assets.csv`; save as correlation searches on a 5-minute schedule. |
| Elastic Security | Recreate rules from `detections/elastic/kql.md` (threshold + EQL sequence); ingest via `filebeat` using `docs/02` §4.1. |
| Sigma-compatible (Sentinel, Chronicle, Sumo) | `sigma convert -t <backend> detections/sigma/*.yml` |
| Suricata / Snort | Copy `detections/suricata/local.rules` to `/etc/suricata/rules/` and reload. |
| TheHive | Import `output/thehive_cases.json` (see `docs/02` §6 for the API sketch). |

The lab JSON pack stays the source of truth; the other formats are translations for
deployment.

---

## 7. Validate and submit

```bash
python3 -m unittest discover -s tests -v      # 42 tests: parsing, every rule, scoring,
                                              # correlation, response, reporting, determinism
python3 -m compileall -q siem scenarios tests  # syntax check
```

Evidence checklist for the assignment is in
[`docs/09-validation-and-evidence.md`](09-validation-and-evidence.md) §3 — every brief
deliverable mapped to a file you can screenshot or attach.

Screenshots: open the dashboard tabs (Overview, Incidents expanded, Alerts filtered to
Critical, Detection coverage, Threat intelligence, Data quality) and capture each; the
five committed SVGs in `output/visuals/` are the same visuals if you cannot run a browser.

---

## 8. Troubleshooting

| Symptom | Fix |
|---|---|
| `Address already in use` on port 8000 | `python3 -m siem serve --port 8010`, or kill the old process |
| Dashboard looks empty | Run `python3 -m siem run` first; `serve --refresh` does both |
| Stale incident numbers (`INC-0013` with 8 cases) | The pipeline clears old reports automatically — make sure you are on the latest code and re-run |
| `No parser for …` in `ingest_stats.json` | Files must sit in `data/logs/<auth|windows|firewall|proxy|edr|web|mail>/` |
| Tests fail after editing a rule | Expected: the coverage test asserts every rule in the pack fires. Add a scenario, or mark the rule as intentionally unexercised. |
| Want a clean slate | `make clean` then `make all` |

---

## 9. Where to read next

| If you want… | Read |
|---|---|
| The design and data flow | [01-architecture.md](01-architecture.md) |
| To rebuild the real VirtualBox lab | [02-lab-environment.md](02-lab-environment.md) |
| To understand the parsers | [03-log-sources-and-ingestion.md](03-log-sources-and-ingestion.md) |
| To write better rules | [04-detection-engineering.md](04-detection-engineering.md) |
| To run an incident end-to-end | [05-incident-response.md](05-incident-response.md) |
| The business conclusions | [08-findings-and-recommendations.md](08-findings-and-recommendations.md) |
| Every scenario and its detections | [11-attack-scenarios.md](11-attack-scenarios.md) |
