# 09 — Validation and evidence

## 1. Test strategy

| Layer | What is verified | Test file |
|---|---|---|
| Parsing | Each of the seven sources parses, fields normalised, timestamps sorted, IDs unique | `tests/test_ingest.py` |
| Enrichment | Asset criticality, identity→asset mapping, internal/external, geo, IOC matching, off-hours | `tests/test_ingest.py` |
| Detection | Every rule fires on the attacking scenario, thresholds behave, sequences require both steps | `tests/test_detection.py` |
| Tuning | Scanner, backup and service-account alerts are suppressed with the right allowlist | `tests/test_detection.py` |
| Anomaly | Volume anomaly flags the insider host, novelty flags the dropped binaries | `tests/test_detection.py` |
| Scoring | Asset criticality raises risk, intel escalates severity, scores bounded 0–100 | `tests/test_detection.py` |
| Correlation | Phishing → ransomware merges into one campaign; priorities match severities | `tests/test_detection.py` |
| Response | Timeline ordered, containment never before last detection, MTTR ≥ MTTD | `tests/test_detection.py` |
| Reporting | Case reports contain all required sections; dashboard, visuals and TheHive export exist | `tests/test_detection.py` |
| Determinism | Two runs produce identical alerts and incident counts | `tests/test_detection.py` |

Run everything:

```bash
python3 -m unittest discover -s tests -v
```

Expected: **42 tests, OK**.

## 2. Reproduction steps

```bash
# 1. Rebuild the seven-day capture (deterministic, seed 20261031)
python3 -m siem generate

# 2. Run the SIEM pipeline
python3 -m siem run

# 3. Review the dashboard
python3 -m siem serve --port 8000

# 4. Read the cases
ls output/incidents/ && cat output/incidents/INC-2026-0006.md
```

## 3. Evidence index

| Deliverable (project brief) | File | How to verify |
|---|---|---|
| Configured security environment | `docs/02-lab-environment.md` | VM table, forwarding configs, Suricata, TheHive |
| SIEM dashboard | `output/dashboard.html` | Open in a browser or `python3 -m siem serve` |
| Dashboard screenshots | `output/visuals/*.svg` + this doc §4 | Five standalone SVG charts |
| Alert screenshots | Dashboard → Alerts tab; `output/alerts.json` | 34 alerts with entity, score, summary, event IDs |
| Log ingestion evidence | `output/ingest_stats.json`, `data/logs/manifest.json` | Per-file raw lines, events, parse rate |
| Incident analysis reports | `output/incidents/*.md` | Eight 9-section reports |
| Incident documentation | `output/incidents/INDEX.md`, `output/EXECUTIVE_SUMMARY.md` | Register and executive view |
| Visualisation outputs | `output/visuals/`, dashboard charts | Severity, volume, type, rules, ATT&CK |
| Case management | `output/thehive_cases.json` | TheHive-compatible cases, tasks, observables |
| Detection content | `detections/` | JSON pack + Sigma + SPL + KQL + Suricata |

## 4. Dashboard evidence

The dashboard is a single self-contained HTML file. To capture screenshots for a
submission:

1. `python3 -m siem serve --port 8000`
2. open `http://localhost:8000/`
3. capture each tab: **Overview** (KPIs + charts), **Incidents** (expanded case),
   **Alerts** (filtered to Critical), **Detection coverage**, **Threat intelligence**,
   **Data quality & tuning**.

The five SVG charts below are the same visuals and are committed so the evidence pack
is complete without a browser:

| Chart | File |
|---|---|
| Event volume per day | `output/visuals/events-per-day.svg` |
| Alerts by severity | `output/visuals/alerts-by-severity.svg` |
| Incidents by type | `output/visuals/incidents-by-type.svg` |
| Alerts by detection rule | `output/visuals/top-detection-rules.svg` |
| ATT&CK tactic coverage | `output/visuals/mitre-tactics.svg` |

## 5. Validation against the project guide

| Brief requirement | Implementation | Status |
|---|---|---|
| Continuous monitoring of network, endpoint, auth, system/app logs | 7 sources, 1,092 events | ✅ |
| Unauthorised access attempts | DET-001, DET-002, DET-003, DET-013 | ✅ |
| Malware behaviour detection | DET-021…027, DET-030/031/032 | ✅ |
| Data exfiltration indicators | DET-037, DET-038, ANO-001 | ✅ |
| Lateral movement activity | DET-033 | ✅ |
| Severity levels Low/Medium/High/Critical | `siem/scoring.py`, 4/2/2/0 incidents | ✅ |
| Incident types (malware, phishing, DDoS, insider, brute force, breach) | All present as primary or contributing types | ✅ |
| Reduced response time for critical threats | P1 targets, MTTA 2 min | ✅ |
| Reduce false positives | 3 governed suppressions, 0 residual FPs | ✅ |
| Fine-tune correlation rules | `detections/rules.json` + tests | ✅ |
| Behavioural and signature detection | 26 signature/correlation + 3 anomaly models | ✅ |
| SIEM correlation rules | JSON pack + SPL + KQL + Sigma | ✅ |
| IDS/IPS alerts | Suricata rule set | ✅ |
| Anomaly detection models | Robust z-score + novelty | ✅ |
| Recurring attack patterns / trend analysis | `docs/08` §3, `output/metrics.json` | ✅ |
| Asset and business impact | Asset inventory + `docs/08` §4 | ✅ |
| Attack vector and risk exposure | `docs/08` §3 | ✅ |
| Detection/response/audit documentation | Case reports §1–§9 | ✅ |
| Patch/policy/firewall/training/segmentation/zero trust recommendations | `docs/08` §5 | ✅ |

## 6. Limitations and honest gaps

| Gap | Why it exists | How it would be closed |
|---|---|---|
| No real VM screenshots | The environment is simulated in-repo | Build the VMs from `docs/02`, capture Splunk screenshots |
| MTTA/MTTR modelled, not observed | No live SOC | Instrument TheHive task timestamps in a pilot |
| No PCAP evidence | Binary capture is out of scope | Run `tcpdump` during Kali scenarios and attach |
| Small statistical baseline | Seven-day capture | Six months of telemetry, seasonal models |
| No TLS inspection | Encrypted uploads are volume-only | Add proxy TLS break-and-inspect in the lab |
| No cloud identity logs | Scope limited to on-prem | Add M365/Azure AD sign-in ingestion |
