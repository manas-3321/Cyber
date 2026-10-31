# Executive Summary — Week 43 2026 (19-25 October)

## Headline

During the monitored week the SOC ingested **1,092 events** across 7 log sources and produced **34 actionable alerts** which consolidated into **8 incidents** (4 Critical, 2 High, 2 Medium, 0 Low).

Two events carried material business risk: a phishing-initiated intrusion on finance workstation `ws-fin-14` that progressed to ransomware on the file server `fs01`, and an insider data exfiltration from `fs01` to a known exfiltration destination. Both were detected within the same hour as the first malicious event and contained with documented playbooks.

## Key metrics

| Metric | Value | Comment |
|---|---|---|
| Mean time to detect (MTTD) | 3.3 min | Correlation runs at ingest time; rule to alert latency is seconds |
| Mean time to acknowledge (MTTA) | 2.0 min | L1 triage simulation |
| Mean time to respond (MTTR) | 7.6 h | Detection to validated recovery |
| Alert noise reduction | 8.1% | 3 alerts suppressed by documented allowlists |
| ATT&CK technique coverage | 27/27 | Techniques exercised by the scenario set |
| Rules triggered | 29/29 | Unused rules reviewed in the detection-engineering backlog |

## Cases

| Case | Title | Severity | Priority | MTTR (min) |
|---|---|---|---|---|
| INC-2026-0001 | DDoS: 203.0.113.199 | High | P2 | 124.5 |
| INC-2026-0002 | Brute Force: 203.0.113.120 | Medium | P3 | 244.6 |
| INC-2026-0003 | Reconnaissance: 198.51.100.23 | Medium | P3 | 60.6 |
| INC-2026-0004 | Web Attack: 198.51.100.23 | High | P2 | 301.1 |
| INC-2026-0005 | Correlated campaign (Brute Force → Persistence → Malware) on web-srv-02.corp.local | Critical | P1 | 381.0 |
| INC-2026-0006 | Correlated campaign (Phishing → Malware → Lateral Movement → Ransomware → Defense Evasion) on fs01.corp.local, ws-fin-14.corp.local | Critical | P1 | 1528.0 |
| INC-2026-0007 | Data Breach: ws-hr-07.corp.local | Critical | P1 | 750.0 |
| INC-2026-0008 | Brute Force: jump-01.corp.local | Critical | P1 | 251.0 |

## Priority recommendations

1. Remove password authentication from internet-facing SSH and RDP; enforce phishing-resistant MFA.
2. Move egress to an allow-listed proxy and put DLP for Confidential data into blocking mode.
3. Enforce tiered administration and restrict SMB admin shares to jump hosts.
4. Validate immutable backup restore quarterly and protect backup infrastructure with separate credentials.
5. Enable ASR rules that block Office child processes and shadow-copy deletion tooling.

Full detail: `output/incidents/` (8 case reports) and `output/dashboard.html`.
