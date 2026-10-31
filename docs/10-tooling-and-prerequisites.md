# 10 — Tooling and prerequisites

## 1. Infrastructure

| Requirement | Minimum | Why |
|---|---|---|
| RAM | 12 GB (16 GB recommended) | pfSense + SIEM + 3–4 VMs running simultaneously |
| CPU | Intel i7 / Ryzen 7 with VT-x / AMD-V | Virtualisation; Sysmon + Splunk are CPU-hungry |
| Storage | SSD, 120 GB free | VM disks and log retention |
| Network | Host-only + NAT adapters | Isolated attack range with internet for updates |
| Host OS | Windows 10/11, Ubuntu 22.04, macOS | VirtualBox 7.x supported |

## 2. Required software

| Tool | Version | Role in this project |
|---|---|---|
| Oracle VirtualBox | 7.0+ | Hypervisor |
| Kali Linux | 2024.x | Attack simulation (Hydra, Nmap, sqlmap, Metasploit) |
| Ubuntu Server | 22.04 LTS | Web, database, SIEM, scanner, case management |
| Windows Server | 2022 | Domain controller, file server, RDP bastion |
| Windows 11 | 23H2+ | Endpoints |
| Splunk Enterprise **or** ELK Stack | 9.x / 8.x | SIEM platform (the lab pipeline mirrors their semantics) |
| Sysmon + SwiftOnSecurity config | 15.x | Endpoint telemetry |
| pfSense | 2.7 | Firewall, DNS, Squid proxy |
| Suricata | 7.x | IDS/IPS alerts |
| Wireshark / tcpdump | 4.x / 4.99 | Packet validation |
| MISP | 2.4 | Threat-intelligence platform |
| TheHive | 4.x | Case management |
| Cortex | 3.x | Observable analysis |
| Nessus or OpenVAS | latest | Vulnerability scanning (authorised) |
| ServiceNow (or Jira) | — | Change and incident records |

Optional but useful: Velociraptor (DFIR), Atomic Red Team (safe technique simulation),
YARA (file scanning), Volatility 3 (memory forensics).

## 3. This repository's requirements

| Requirement | Notes |
|---|---|
| Python 3.10+ | Standard library only — no pip install needed |
| `git` | Optional, for versioning the detection content |
| Modern browser | To view `output/dashboard.html` |

Everything else is generated: no database, no message queue, no container runtime.

## 4. Skills checklist

| Area | Specific capability |
|---|---|
| Security fundamentals | CIA triad, least privilege, defence in depth, risk scoring |
| Networking | TCP/IP, DNS, HTTP/HTTPS, SMB, proxies, firewalls, NAT |
| Operating systems | Linux syslog/auth.log, Windows event log/Sysmon, file permissions |
| SIEM | Log ingestion, field extraction, correlation, dashboards, alert tuning |
| Detection engineering | Sigma/SPL/KQL, thresholds vs sequences, false-positive analysis |
| Threat intelligence | IOC types, feeds, confidence, ageing, STIX/TAXII |
| Incident response | NIST SP 800-61, evidence handling, containment decisions, comms |
| MITRE ATT&CK | Tactics vs techniques, mapping detections to behaviour |
| Scripting | Python data structures, regex, JSON, basic statistics |

## 5. Build checklist (in order)

1. Install VirtualBox and enable VT-x in BIOS.
2. Create the host-only networks (`10.10.0.0/24`, `10.10.2.0/24`, `10.10.5.0/24`, `10.10.4.0/24`).
3. Deploy pfSense with a WAN NAT adapter and the LAN adapters; configure firewall rules
   (DMZ inbound 80/443 only, corporate default deny, security segment allowlisted).
4. Deploy `siem-01`, install Splunk Enterprise or Elastic, verify the web UI.
5. Deploy Windows VMs, promote `dc01`, create the lab users and file shares, install
   Sysmon and the forwarding agent.
6. Deploy Ubuntu VMs, configure `rsyslog` forwarding, nginx, PostgreSQL, Squid.
7. Deploy MISP, TheHive and Cortex; configure feeds and API keys.
8. Deploy the false-positive controls: Nessus scanner and the backup job.
9. Sanity-check ingestion: run a failed SSH login and confirm it arrives in the SIEM.
10. Snapshot every VM.
11. Execute the scenarios in [11-attack-scenarios.md](11-attack-scenarios.md) from Kali.
12. Collect evidence (dashboards, alerts, PCAP) and write the case reports.

## 6. Cost and licensing

| Component | Licence |
|---|---|
| VirtualBox, Kali, Ubuntu, pfSense, Suricata, Wireshark, Sysmon | Free / open source |
| Splunk Enterprise | Free trial (500 MB/day) — sufficient for the lab |
| Elastic Stack | Free basic tier |
| TheHive / Cortex / MISP | Free / open source |
| Nessus Essentials | Free for 16 IPs |
| Windows Server / 11 | Evaluation images (180 days) |

A cloud alternative: one 16 GB VM hosting nested virtualisation, or a hybrid where the
SIEM runs in the cloud and logs are shipped over a VPN — but the isolated local lab is
cheaper and safer for attack simulation.
