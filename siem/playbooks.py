"""Incident-response playbooks (NIST SP 800-61 phases) and root-cause text.

The response steps are simulated analyst actions with realistic offsets from
detection time.  In a production deployment these would be TheHive tasks and
ServiceNow change records; ``output/thehive_cases.json`` exports them in a
shape that maps directly onto TheHive's case/task API.
"""
from __future__ import annotations

from typing import Dict, List

PHASES = ("Detection", "Analysis", "Containment", "Eradication", "Recovery", "Post-Incident")

_COMMON_RECOMMENDATIONS = [
    "Enforce phishing-resistant MFA on all remote access paths (VPN, SSH, RDP, webmail).",
    "Segment server, workstation and OT networks; restrict east-west SMB and RDP to jump hosts.",
    "Reduce detection latency by streaming endpoint and firewall telemetry with < 5 minute delay.",
    "Run a quarterly tabletop exercise against this playbook and update contact trees.",
    "Track mean time to detect/respond as a SOC KPI and review monthly with the CISO.",
]

PLAYBOOKS: Dict[str, Dict] = {
    "PB-BRUTE-FORCE": {
        "name": "Credential attack / account compromise",
        "steps": [
            (2, "Detection", "L1 triages alert, confirms source IP reputation and target accounts", "analyst.l1"),
            (4, "Analysis", "Pivot on source IP across auth, VPN and web logs for success after failure", "analyst.l1"),
            (9, "Containment", "Block source IP/range at perimeter firewall and WAF", "analyst.l2"),
            (14, "Containment", "Disable or force-reset compromised accounts; revoke active sessions and tokens", "analyst.l2"),
            (21, "Analysis", "Hunt for persistence: new accounts, authorized_keys, cron jobs, sudoers edits", "ir.lead"),
            (45, "Eradication", "Remove attacker persistence and rotate host credentials / SSH keys", "ir.lead"),
            (75, "Recovery", "Restore service, enable MFA on the exposed service, monitor for 72 hours", "it-ops"),
            (240, "Post-Incident", "Document lessons learned, close case in TheHive, update detection thresholds", "ir.lead"),
        ],
        "root_cause": (
            "Internet-exposed SSH on {asset} accepted password authentication. Attackers at {origin} "
            "guessed valid credentials, authenticated successfully and escalated privileges with sudo. "
            "The absence of MFA and of source-IP rate limiting allowed the brute force to succeed."
        ),
        "recommendations": [
            "Disable password-based SSH in favour of keys or short-lived certificates; add fail2ban/CrowdSec.",
            "Alert on successful authentication from any IP with prior failures (rule DET-002).",
            "Move internet-facing administration behind a VPN or zero-trust access proxy.",
        ],
    },
    "PB-RECON": {
        "name": "External reconnaissance",
        "steps": [
            (2, "Detection", "Validate scan volume against authorised scanner inventory", "analyst.l1"),
            (6, "Analysis", "Check whether any probe received a 200/302 or application error", "analyst.l1"),
            (12, "Containment", "Apply perimeter block for the scanning IP for 24 hours", "analyst.l2"),
            (60, "Post-Incident", "Confirm exposure inventory matches the firewall policy and close", "ir.lead"),
        ],
        "root_cause": (
            "Externally initiated service discovery against {asset} reached the firewall from {origin}. "
            "The scan was blocked by default-deny policy; no successful exploitation was observed."
        ),
        "recommendations": [
            "Reduce the public attack surface to required ports only; review quarterly.",
            "Enable geo/IP reputation blocking at the edge for known scanner ranges.",
            "Feed scanner IPs into the allowlist review to keep noise low for authorised tests.",
        ],
    },
    "PB-WEB-ATTACK": {
        "name": "Web application exploitation attempt",
        "steps": [
            (2, "Detection", "L1 confirms malicious payloads in request paths and response codes", "analyst.l1"),
            (5, "Analysis", "Extract payloads, user-agents and check for successful exploitation or shell upload", "analyst.l2"),
            (10, "Containment", "Enable WAF blocking rules and rate limiting for the attacking IP", "analyst.l2"),
            (30, "Analysis", "Review application logs and file integrity for webshells or data access", "ir.lead"),
            (90, "Eradication", "Patch the vulnerable component and re-run vulnerability scan", "cloud-eng"),
            (180, "Recovery", "Validate application integrity and monitor for 48 hours", "cloud-eng"),
            (300, "Post-Incident", "Update WAF virtual patches and close the case", "ir.lead"),
        ],
        "root_cause": (
            "Exploitation attempts against the public web tier ({asset}) from {origin} matched known "
            "injection and path-traversal signatures. The WAF and application input validation "
            "rejected the payloads; no evidence of successful exploitation was found."
        ),
        "recommendations": [
            "Add virtual patching for the attempted CVE classes in the WAF.",
            "Adopt a secure SDLC gate with SAST/DAST before release.",
        ],
    },
    "PB-DDOS": {
        "name": "Denial of service",
        "steps": [
            (2, "Detection", "Confirm request-rate anomaly and error-rate impact on the web tier", "analyst.l1"),
            (3, "Containment", "Enable CDN/WAF rate limiting and challenge suspicious clients", "analyst.l2"),
            (8, "Containment", "Scrub traffic at the edge; block the dominant source ASN", "cloud-eng"),
            (25, "Recovery", "Verify latency and error budget recovered; scale web tier if required", "cloud-eng"),
            (120, "Post-Incident", "Tune volumetric thresholds and document the traffic pattern", "ir.lead"),
        ],
        "root_cause": (
            "A single external source ({origin}) generated an HTTP request flood against {asset}, "
            "exhausting application worker capacity. Edge rate limiting was not enabled before the event."
        ),
        "recommendations": [
            "Keep always-on L7 rate limiting and bot management at the CDN.",
            "Define a DDoS runbook with pre-agreed scrubbing capacity and contact tree.",
        ],
    },
    "PB-PHISHING": {
        "name": "Phishing campaign",
        "steps": [
            (2, "Detection", "L1 confirms sender infrastructure against threat intelligence", "analyst.l1"),
            (6, "Containment", "Purge matching messages from all mailboxes and block sender domain", "analyst.l2"),
            (15, "Analysis", "Identify recipients who clicked or opened attachments; check for credential entry", "analyst.l2"),
            (30, "Containment", "Reset credentials and revoke sessions for users who submitted credentials", "analyst.l2"),
            (90, "Analysis", "Hunt for follow-on endpoint activity from opened attachments", "ir.lead"),
            (180, "Post-Incident", "Run targeted awareness comms and update mail filters", "ir.lead"),
        ],
        "root_cause": (
            "A phishing message from the look-alike domain in the threat-intelligence feed was delivered "
            "to {user} on {asset}. The attachment executed after the user enabled content, which is how the "
            "subsequent PowerShell execution chain obtained a foothold."
        ),
        "recommendations": [
            "Enable Safe Links / attachment detonation and block newly registered domains.",
            "Mandate phishing-resistant MFA so harvested credentials are not replayable.",
            "Run quarterly phishing simulations with reporting metrics per department.",
        ],
    },
    "PB-MALWARE": {
        "name": "Malware / command and control",
        "steps": [
            (2, "Detection", "L1 validates process tree, hash reputation and network beaconing", "analyst.l1"),
            (5, "Containment", "Network-isolate {asset} through EDR isolation policy", "analyst.l2"),
            (10, "Containment", "Block C2 IP/domain at proxy, DNS and perimeter firewall", "analyst.l2"),
            (20, "Analysis", "Collect volatile evidence: process tree, autoruns, scheduled tasks, memory", "ir.lead"),
            (40, "Analysis", "Scope credential exposure; reset accounts that authenticated on the host", "ir.lead"),
            (90, "Eradication", "Remove malware, persistence and re-image the endpoint", "it-ops"),
            (180, "Recovery", "Restore user data, re-enable network access, monitor for 72 hours", "it-ops"),
            (360, "Post-Incident", "YARA/Sigma coverage review, lessons learned, case closure", "ir.lead"),
        ],
        "root_cause": (
            "Macro-enabled Office document delivered by phishing executed an encoded PowerShell "
            "downloader on {asset}. The payload contacted known malicious infrastructure and established "
            "persistence through registry run keys and a scheduled task before credential access."
        ),
        "recommendations": [
            "Block Office child-process creation via ASR rules (Win32/Office / PowerShell).",
            "Enforce PowerShell script block logging and AMSI telemetry to the SIEM.",
            "Drive EDR coverage to 100% of endpoints with tamper protection enabled.",
        ],
    },
    "PB-C2": {
        "name": "Command and control beaconing",
        "steps": [
            (2, "Detection", "Validate beacon interval and destination against the IOC feed", "analyst.l1"),
            (5, "Containment", "Block destination at DNS, proxy and firewall egress rules", "analyst.l2"),
            (12, "Containment", "Isolate the beaconing host and capture memory", "analyst.l2"),
            (30, "Analysis", "Hunt all hosts for the same destination and JA3/URI pattern", "ir.lead"),
            (120, "Eradication", "Rebuild host and rotate credentials used on it", "it-ops"),
            (240, "Post-Incident", "Add IOC to blocking feeds and update detection content", "ir.lead"),
        ],
        "root_cause": (
            "Endpoint {asset} established periodic encrypted sessions to IOC-listed infrastructure "
            "({origin}). Egress filtering allowed direct outbound 443 to arbitrary destinations."
        ),
        "recommendations": [
            "Restrict egress to an approved destination list through an authenticated proxy.",
            "Detect beaconing via connection-interval analysis rather than static IOCs only.",
        ],
    },
    "PB-RANSOMWARE": {
        "name": "Ransomware / destructive attack",
        "steps": [
            (2, "Detection", "Declare major incident; notify IR lead and CISO on-call", "analyst.l1"),
            (3, "Containment", "Disable network ports on affected segments and isolate {asset}", "analyst.l2"),
            (8, "Containment", "Disable compromised accounts and revoke Kerberos tickets", "analyst.l2"),
            (15, "Analysis", "Determine patient-zero, encryption scope and backup integrity", "ir.lead"),
            (45, "Eradication", "Rebuild affected servers from known-good images", "it-ops"),
            (120, "Recovery", "Restore data from immutable backups in a validated sequence", "it-ops"),
            (480, "Post-Incident", "Forensic report, regulator/legal assessment, resilience improvements", "ir.lead"),
        ],
        "root_cause": (
            "Privileged lateral movement from a previously compromised workstation reached {asset}. "
            "The attacker deleted volume shadow copies and encrypted file shares at scale. Immutable "
            "backups limited the data loss but recovery required a full restore."
        ),
        "recommendations": [
            "Enforce immutable, offline backups and test restores quarterly.",
            "Block shadow-copy deletion tooling and protect backup infrastructure with separate credentials.",
            "Apply least privilege to service accounts and restrict SMB admin shares.",
        ],
    },
    "PB-DATA-BREACH": {
        "name": "Data exfiltration / breach",
        "steps": [
            (2, "Detection", "Confirm volume anomaly and destination classification with intel", "analyst.l1"),
            (4, "Containment", "Block destination and isolate the source host", "analyst.l2"),
            (10, "Containment", "Suspend the account and preserve proxy/firewall evidence", "analyst.l2"),
            (20, "Analysis", "Determine data classification and volume transferred; legal notification trigger", "ir.lead"),
            (60, "Analysis", "Interview business owner and review DLP policy gaps", "ir.lead"),
            (180, "Recovery", "Restore normal access with enhanced monitoring after HR/legal sign-off", "it-ops"),
            (720, "Post-Incident", "Regulatory assessment (GDPR/DPDP), DLP tuning, case closure", "ir.lead"),
        ],
        "root_cause": (
            "A large volume of data left {asset} for an external destination listed as an exfiltration "
            "endpoint. Egress filtering permitted arbitrary HTTPS uploads and DLP was not in blocking mode."
        ),
        "recommendations": [
            "Move DLP from monitor to block for Confidential/Restricted data leaving the estate.",
            "Baseline normal outbound volume per host and alert on deviation (rule ANO-001).",
            "Apply least privilege to file shares holding salary, customer and M&A data.",
        ],
    },
    "PB-INSIDER": {
        "name": "Insider threat",
        "steps": [
            (2, "Detection", "L1 validates after-hours access pattern against HR/joiner data", "analyst.l1"),
            (10, "Analysis", "Review share access, volume moved and business justification", "analyst.l2"),
            (30, "Containment", "Coordinate with HR/legal; restrict share access pending investigation", "ir.lead"),
            (120, "Analysis", "Preserve evidence chain-of-custody for potential disciplinary action", "ir.lead"),
            (480, "Post-Incident", "Policy update, user awareness, access recertification", "ir.lead"),
        ],
        "root_cause": (
            "Valid credentials for {user} accessed Confidential data on {asset} outside business hours "
            "without an approved change. Excessive share permissions and absent DLP controls allowed "
            "bulk collection."
        ),
        "recommendations": [
            "Run quarterly entitlement reviews on Confidential shares.",
            "Alert on after-hours access to Restricted data assets (rule DET-034).",
        ],
    },
    "PB-LATERAL-MOVEMENT": {
        "name": "Lateral movement",
        "steps": [
            (2, "Detection", "Validate the source host is not a management server or backup job", "analyst.l1"),
            (6, "Containment", "Isolate the source workstation and restrict admin shares", "analyst.l2"),
            (15, "Analysis", "Enumerate all remote logons and services created from the source host", "ir.lead"),
            (60, "Eradication", "Reset credentials used in the network logons and rebuild the source host", "it-ops"),
            (180, "Post-Incident", "Tier admin accounts, enable Protected Users group, close case", "ir.lead"),
        ],
        "root_cause": (
            "A single internal source authenticated to multiple servers with network logons, indicating "
            "re-use of harvested credentials or automated admin-share tooling."
        ),
        "recommendations": [
            "Implement tiered administration with separate credentials per tier.",
            "Disable SMBv1, restrict admin shares, and monitor service creation on servers.",
        ],
    },
    "PB-DEFAULT": {
        "name": "Generic incident handling",
        "steps": [
            (2, "Detection", "L1 triage and enrichment", "analyst.l1"),
            (15, "Analysis", "Scope affected assets and accounts", "analyst.l2"),
            (45, "Containment", "Apply containment appropriate to the incident type", "analyst.l2"),
            (120, "Eradication", "Remove root cause and validate", "it-ops"),
            (240, "Recovery", "Restore normal operations and monitor", "it-ops"),
            (480, "Post-Incident", "Document and close", "ir.lead"),
        ],
        "root_cause": "Root cause determined during triage of the correlated alerts on {asset}.",
        "recommendations": [],
    },
}


def for_playbook(playbook_id: str | None) -> Dict:
    return PLAYBOOKS.get(playbook_id or "PB-DEFAULT", PLAYBOOKS["PB-DEFAULT"])


def recommendations_for(playbooks: List[str]) -> List[str]:
    seen = []
    for playbook_id in playbooks:
        for item in for_playbook(playbook_id).get("recommendations", []):
            if item not in seen:
                seen.append(item)
    for item in _COMMON_RECOMMENDATIONS:
        if item not in seen:
            seen.append(item)
    return seen
