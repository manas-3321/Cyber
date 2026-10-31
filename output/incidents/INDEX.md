# Incident Register

8 cases generated from the seven-day lab capture.

| Case | Title | Severity | Priority | Status | Score | MTTR (min) | Detected |
|---|---|---|---|---|---|---|---|
| [INC-2026-0001](INC-2026-0001.md) | DDoS: 203.0.113.199 | High | P2 | Closed | 85 | 124.5 | 2026-10-20 14:04 |
| [INC-2026-0002](INC-2026-0002.md) | Brute Force: 203.0.113.120 | Medium | P3 | Closed | 52 | 244.6 | 2026-10-20 15:04 |
| [INC-2026-0003](INC-2026-0003.md) | Reconnaissance: 198.51.100.23 | Medium | P3 | Closed | 62 | 60.6 | 2026-10-21 01:40 |
| [INC-2026-0004](INC-2026-0004.md) | Web Attack: 198.51.100.23 | High | P2 | Closed | 85 | 301.1 | 2026-10-21 02:06 |
| [INC-2026-0005](INC-2026-0005.md) | Correlated campaign (Brute Force → Persistence → Malware) on web-srv-02.corp.local | Critical | P1 | Closed | 100 | 381.0 | 2026-10-22 03:07 |
| [INC-2026-0006](INC-2026-0006.md) | Correlated campaign (Phishing → Malware → Lateral Movement → Ransomware → Defense Evasion) on fs01.corp.local, ws-fin-14.corp.local | Critical | P1 | Closed | 100 | 1528.0 | 2026-10-23 09:12 |
| [INC-2026-0007](INC-2026-0007.md) | Data Breach: ws-hr-07.corp.local | Critical | P1 | Closed | 100 | 750.0 | 2026-10-25 00:45 |
| [INC-2026-0008](INC-2026-0008.md) | Brute Force: jump-01.corp.local | Critical | P1 | Closed | 91 | 251.0 | 2026-10-25 04:09 |

## Aggregate metrics

| Metric | Value |
|---|---|
| Total incidents | 8 |
| Critical / High | 4 / 2 |
| Mean MTTD | 3.3 min |
| Mean MTTA | 2.0 min |
| Mean MTTR | 7.6 h |
| Actionable alerts | 34 |
| Suppressed (tuning) | 3 |
| Technique coverage | 27/27 |
