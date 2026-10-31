"""Log ingestion: native log formats -> one normalised event schema.

Six heterogeneous sources are parsed here, mirroring a real Splunk/ELK
deployment where every sourcetype needs its own field extraction:

===========================  =========================================
source directory             native format
===========================  =========================================
``auth/``                    Linux ``/var/log/auth.log`` (syslog)
``windows/``                 Windows Security event export (CSV)
``firewall/``                pfSense / iptables export (CSV)
``proxy/``                   Squid access log
``edr/``                     Sysmon / EDR telemetry (JSON lines)
``web/``                     nginx combined access log
``mail/``                    Secure email gateway (JSON lines)
===========================  =========================================

Every event is flattened onto dotted ECS-style keys (``source.ip``,
``event.action`` ...) which keeps the correlation engine and the JSON output
simple while staying familiar to analysts trained on Elastic Common Schema.
"""
from __future__ import annotations

import csv
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Iterable, List

from . import config
from .assets import AssetInventory
from .intel import ThreatIntel

# ---------------------------------------------------------------------------
# Event construction
# ---------------------------------------------------------------------------

CORE_FIELDS = {
    "ts",
    "source",
    "event_id",
    "event.category",
    "event.action",
    "event.outcome",
    "event.off_hours",
    "event.severity",
    "host.name",
    "host.ip",
    "host.criticality",
    "user.name",
    "source.ip",
    "source.port",
    "destination.ip",
    "destination.port",
    "network.transport",
    "network.bytes",
    "network.direction",
    "process.name",
    "process.command_line",
    "process.parent_name",
    "file.path",
    "file.hash_sha256",
    "dns.question.name",
    "url.full",
    "http.status",
    "http.method",
    "email.sender",
    "email.recipient",
    "email.subject",
    "email.attachment",
    "message",
    "raw",
    "intel.hit",
    "intel.matches",
}


def make_event(
    ts: datetime,
    source: str,
    category: str,
    action: str,
    outcome: str = "unknown",
    **fields,
) -> dict:
    event = {
        "ts": config.iso(ts),
        "source": source,
        "event.category": category,
        "event.action": action,
        "event.outcome": outcome,
        "event.off_hours": is_off_hours(ts),
    }
    for key, value in fields.items():
        if value is None or value == "":
            continue
        event[key] = value
    return event


def is_off_hours(ts: datetime) -> bool:
    """Business hours are Mon-Fri 08:00-19:00 UTC in this lab."""
    if ts.weekday() >= 5:
        return True
    return ts.hour < 8 or ts.hour >= 19


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[A-Za-z0-9_./-]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$"
)
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}

SSH_FAIL_RE = re.compile(
    r"(?:Failed password|Failed publickey|Invalid user|error: maximum authentication attempts exceeded) "
    r"(?:for (?:invalid user )?)?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)(?: port (?P<port>\d+))?"
)
SSH_OK_RE = re.compile(
    r"Accepted (?P<method>password|publickey) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
)
SUDO_RE = re.compile(r"^(?P<user>\S+) : .*USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.*)$")
USERADD_RE = re.compile(r"new user: name=(?P<user>[^,]+)")
USERMOD_RE = re.compile(r"add '(?P<user>[^']+)' to group '(?P<group>[^']+)'")

OFFSET_MINUTES = 0


def parse_auth_log(path: Path) -> List[dict]:
    events: List[dict] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        match = SYSLOG_RE.match(line)
        if not match:
            continue
        ts = datetime(
            config.LAB_YEAR,
            MONTHS[match.group("mon")],
            int(match.group("day")),
            *[int(x) for x in match.group("time").split(":")],
        )
        host = match.group("host")
        proc = match.group("proc")
        msg = match.group("msg")

        if proc.startswith("sshd"):
            ok = SSH_OK_RE.search(msg)
            if ok:
                events.append(
                    make_event(
                        ts, "auth", "authentication", "ssh_login_success", "success",
                        **{"host.name": host, "user.name": ok.group("user"),
                           "source.ip": ok.group("ip"), "source.port": int(ok.group("port")),
                           "network.transport": "tcp", "destination.port": 22,
                           "message": msg, "raw": line},
                    )
                )
                continue
            failed = SSH_FAIL_RE.search(msg)
            if failed:
                events.append(
                    make_event(
                        ts, "auth", "authentication", "ssh_login_failed", "failure",
                        **{"host.name": host, "user.name": failed.group("user"),
                           "source.ip": failed.group("ip"),
                           "source.port": int(failed.group("port") or 0) or None,
                           "network.transport": "tcp", "destination.port": 22,
                           "message": msg, "raw": line},
                    )
                )
                continue

        if proc == "sudo":
            sudo = SUDO_RE.search(msg)
            if sudo:
                events.append(
                    make_event(
                        ts, "auth", "process", "sudo_command", "success",
                        **{"host.name": host, "user.name": sudo.group("user"),
                           "process.name": "sudo",
                           "process.command_line": sudo.group("cmd").strip(),
                           "message": msg, "raw": line},
                    )
                )
                continue

        if proc.startswith("useradd"):
            new_user = USERADD_RE.search(msg)
            if new_user:
                events.append(
                    make_event(
                        ts, "auth", "iam", "account_created", "success",
                        **{"host.name": host, "user.name": new_user.group("user").strip(),
                           "message": msg, "raw": line},
                    )
                )
                continue

        if proc == "CRON":
            cron = re.search(r"\((?:root|\S+)\) CMD \((?P<cmd>.*)\)", msg)
            if cron:
                events.append(
                    make_event(
                        ts, "auth", "process", "cron_job", "unknown",
                        **{"host.name": host, "user.name": "root",
                           "process.name": "cron",
                           "process.command_line": cron.group("cmd"),
                           "message": msg, "raw": line},
                    )
                )
                continue

        if proc.startswith("usermod"):
            group = USERMOD_RE.search(msg)
            if group:
                events.append(
                    make_event(
                        ts, "auth", "iam", "group_membership_added", "success",
                        **{"host.name": host, "user.name": group.group("user"),
                           "group.name": group.group("group"),
                           "message": msg, "raw": line},
                    )
                )
    return events


WINDOWS_ACTIONS = {
    "4624": ("authentication", "windows_logon_success", "success"),
    "4625": ("authentication", "windows_logon_failed", "failure"),
    "4634": ("authentication", "windows_logoff", "success"),
    "4648": ("authentication", "windows_explicit_credential_logon", "success"),
    "4672": ("iam", "windows_special_privileges_assigned", "success"),
    "4688": ("process", "process_created", "success"),
    "4720": ("iam", "account_created", "success"),
    "4726": ("iam", "account_deleted", "success"),
    "4740": ("iam", "account_locked", "success"),
    "7045": ("process", "service_installed", "success"),
    "1102": ("configuration", "audit_log_cleared", "success"),
}


def parse_windows_security(path: Path) -> List[dict]:
    events: List[dict] = []
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            event_id = str(row.get("EventID", "")).strip()
            category, action, outcome = WINDOWS_ACTIONS.get(
                event_id, ("unknown", f"windows_event_{event_id}", "unknown")
            )
            ts = config.parse_ts(row["TimeCreated"])
            user = (row.get("TargetUserName") or row.get("SubjectUserName") or "").strip()
            if "\\" in user:
                user = user.split("\\", 1)[1]
            if user.endswith("$"):
                continue
            fields = {
                "host.name": row.get("Computer", "").strip(),
                "user.name": user or None,
                "source.ip": (row.get("IpAddress") or "").strip() or None,
                "logon.type": (row.get("LogonType") or "").strip() or None,
                "process.name": (row.get("ProcessName") or row.get("ServiceName") or "").strip() or None,
                "process.command_line": (row.get("CommandLine") or row.get("ImagePath") or "").strip() or None,
                "event.code": event_id,
                "message": row.get("Message", "").strip() or f"Windows event {event_id}",
                "raw": json.dumps(row, separators=(",", ":")),
            }
            events.append(make_event(ts, "windows", category, action, outcome, **fields))
    return events


def parse_firewall_csv(path: Path) -> List[dict]:
    events: List[dict] = []
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            ts = config.parse_ts(row["timestamp"])
            action_raw = row["action"].strip().lower()
            action = "firewall_allow" if action_raw in ("allow", "pass", "accept") else "firewall_deny"
            events.append(
                make_event(
                    ts, "firewall", "network", action,
                    "success" if action == "firewall_allow" else "failure",
                    **{
                        "observer.name": row.get("host", "").strip() or None,
                        "source.ip": row["src_ip"].strip(),
                        "destination.ip": row["dst_ip"].strip(),
                        "destination.port": int(row["dst_port"]) if row.get("dst_port") else None,
                        "network.transport": row.get("protocol", "tcp").strip().lower(),
                        "network.bytes": int(row["bytes"]) if row.get("bytes") else None,
                        "rule.name": row.get("rule", "").strip() or None,
                        "interface.name": row.get("interface", "").strip() or None,
                        "message": f"{action_raw} {row.get('protocol', '')} "
                                   f"{row['src_ip']}->{row['dst_ip']}:{row.get('dst_port', '')} "
                                   f"rule={row.get('rule', '')}",
                        "raw": json.dumps(row, separators=(",", ":")),
                    },
                )
            )
    return events


SQUID_RE = re.compile(
    r"^(?P<ts>\d+\.\d+)\s+(?P<lat>\d+)\s+(?P<client>\S+)\s+(?P<code>[A-Z_]+)/(?P<status>\d+)\s+"
    r"(?P<bytes>\d+)\s+(?P<method>[A-Z]+)\s+(?P<url>\S+)\s+(?P<user>\S+)\s+(?P<peer>\S+)\s+(?P<mime>\S+)"
)


def parse_squid(path: Path) -> List[dict]:
    events: List[dict] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = SQUID_RE.match(line)
        if not match:
            continue
        ts = datetime.fromtimestamp(float(match.group("ts")), tz=timezone.utc)
        denied = "DENIED" in match.group("code")
        events.append(
            make_event(
                ts, "proxy", "web", "proxy_denied" if denied else "http_request",
                "failure" if denied else "success",
                **{
                    "source.ip": match.group("client"),
                    "url.full": match.group("url"),
                    "dns.question.name": _host_of(match.group("url")),
                    "http.method": match.group("method"),
                    "http.status": int(match.group("status")),
                    "network.bytes": int(match.group("bytes")),
                    "network.direction": "outbound",
                    "user.name": None if match.group("user") == "-" else match.group("user"),
                    "message": f"{match.group('method')} {match.group('url')} -> {match.group('status')}",
                    "raw": line,
                },
            )
        )
    return events


SYSMON_ACTIONS = {
    1: ("process", "process_created", "success"),
    3: ("network", "network_connection", "success"),
    10: ("process", "process_access", "success"),
    11: ("file", "file_created", "success"),
    12: ("registry", "registry_object_created", "success"),
    13: ("registry", "registry_value_set", "success"),
    22: ("network", "dns_query", "success"),
}


def parse_sysmon(path: Path) -> List[dict]:
    events: List[dict] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        record_id = int(record.get("EventID", 0))
        category, action, outcome = SYSMON_ACTIONS.get(
            record_id, ("unknown", f"sysmon_event_{record_id}", "unknown")
        )
        ts = config.parse_ts(record["UtcTime"])
        user = record.get("User") or ""
        if "\\" in user:
            user = user.split("\\", 1)[1]
        hashes = {}
        for part in (record.get("Hashes") or "").split(","):
            if "=" in part:
                algo, value = part.split("=", 1)
                hashes[algo.upper()] = value
        fields = {
            "host.name": record.get("Computer", "").strip(),
            "user.name": user or None,
            "process.name": _basename(record.get("Image")),
            "process.path": record.get("Image"),
            "process.command_line": record.get("CommandLine"),
            "process.parent_name": _basename(record.get("ParentImage")),
            "process.parent_command_line": record.get("ParentCommandLine"),
            "process.guid": record.get("ProcessGuid"),
            "source.ip": record.get("SourceIp") or None,
            "destination.ip": record.get("DestinationIp") or None,
            "destination.port": _int_or_none(record.get("DestinationPort")),
            "network.transport": (record.get("Protocol") or "").lower() or None,
            "file.path": record.get("TargetFilename"),
            "file.hash_sha256": hashes.get("SHA256"),
            "registry.key": record.get("TargetObject"),
            "registry.value": record.get("Details"),
            "dns.question.name": record.get("QueryName"),
            "process.target_name": _basename(record.get("TargetImage")),
            "process.access_mask": record.get("GrantedAccess"),
            "event.code": str(record_id),
            "message": _sysmon_message(record_id, record),
            "raw": line,
        }
        events.append(make_event(ts, "edr", category, action, outcome, **fields))
    return events


NGINX_RE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+) '
    r'HTTP/[0-9.]+" (?P<status>\d{3}) (?P<bytes>\d+) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"'
)


def parse_nginx(path: Path) -> List[dict]:
    events: List[dict] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = NGINX_RE.match(line)
        if not match:
            continue
        ts = datetime.strptime(match.group("ts"), "%d/%b/%Y:%H:%M:%S %z")
        status = int(match.group("status"))
        path_value = match.group("path")
        events.append(
            make_event(
                ts, "web", "web", "http_request",
                "success" if status < 400 else "failure",
                **{
                    "host.name": "web-srv-02",
                    "source.ip": match.group("ip"),
                    "url.full": path_value,
                    "url.path": path_value.split("?", 1)[0],
                    "http.method": match.group("method"),
                    "http.status": status,
                    "http.user_agent": match.group("ua"),
                    "network.bytes": int(match.group("bytes")),
                    "network.direction": "inbound",
                    "message": f'{match.group("method")} {path_value} -> {status}',
                    "raw": line,
                },
            )
        )
    return events


def parse_mail(path: Path) -> List[dict]:
    events: List[dict] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        ts = config.parse_ts(record["timestamp"])
        verdict = record.get("verdict", "delivered").lower()
        events.append(
            make_event(
                ts, "mail", "email", "email_delivered" if verdict == "delivered" else f"email_{verdict}",
                "success" if verdict == "delivered" else "failure",
                **{
                    "email.sender": record.get("from"),
                    "email.recipient": record.get("to"),
                    "email.subject": record.get("subject"),
                    "email.attachment": record.get("attachment"),
                    "file.hash_sha256": record.get("attachment_sha256"),
                    "url.full": (record.get("urls") or [None])[0],
                    "dns.question.name": record.get("sender_domain"),
                    "source.ip": record.get("src_ip"),
                    "message": f"mail {record.get('subject')} from {record.get('from')} "
                               f"verdict={verdict}",
                    "raw": line,
                },
            )
        )
    return events


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _basename(value) -> str | None:
    if not value:
        return None
    return str(value).replace("/", "\\").split("\\")[-1]


def _int_or_none(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _host_of(url: str) -> str | None:
    text = url.split("://", 1)[-1]
    host = text.split("/", 1)[0].split(":", 1)[0]
    return host.lower() or None


def _sysmon_message(record_id: int, record: dict) -> str:
    if record_id == 1:
        return f"process created {_basename(record.get('Image'))}"
    if record_id == 3:
        return f"network connection to {record.get('DestinationIp')}:{record.get('DestinationPort')}"
    if record_id == 10:
        return f"process access to {_basename(record.get('TargetImage'))}"
    if record_id == 11:
        return f"file created {record.get('TargetFilename')}"
    if record_id == 22:
        return f"dns query {record.get('QueryName')}"
    return f"sysmon event {record_id}"


PARSER_MAP: Dict[str, Callable[[Path], List[dict]]] = {
    "auth": parse_auth_log,
    "windows": parse_windows_security,
    "firewall": parse_firewall_csv,
    "proxy": parse_squid,
    "edr": parse_sysmon,
    "web": parse_nginx,
    "mail": parse_mail,
}


# ---------------------------------------------------------------------------
# Enrichment
# ---------------------------------------------------------------------------

# Documentation ranges carry a stable fake geography in this lab.
GEO = {
    "203.0.113.": ("Netherlands", "Amsterdam", "AS64500 EXAMPLE-NL"),
    "198.51.100.": ("Russia", "Moscow", "AS64501 EXAMPLE-RU"),
    "192.0.2.": ("United States", "Ashburn", "AS64502 EXAMPLE-US"),
}


def geo_for(ip: str) -> dict:
    """Public geo lookup used by the case layer for attack-origin enrichment."""
    return _geo(ip)


def _geo(ip: str) -> dict:
    for prefix, (country, city, asn) in GEO.items():
        if ip.startswith(prefix):
            return {"country": country, "city": city, "asn": asn}
    return {"country": "Unknown", "city": "Unknown", "asn": "Unknown"}


def enrich_events(
    events: Iterable[dict],
    inventory: AssetInventory,
    intel: ThreatIntel,
) -> List[dict]:
    enriched = []
    for event in events:
        asset = inventory.for_event(event)
        if asset is None and event.get("email.recipient"):
            local_part = str(event["email.recipient"]).split("@")[0]
            asset = inventory.by_owner(local_part)
        if event.get("source") == "firewall":
            # Attribute network flows to the internal endpoint, not the firewall.
            src = event.get("source.ip")
            dst = event.get("destination.ip")
            if src and inventory.is_internal(src):
                asset = inventory.by_ip(src)
            elif dst and inventory.is_internal(dst):
                asset = inventory.by_ip(dst)
        elif asset is None and event.get("source.ip") and inventory.is_internal(event["source.ip"]):
            asset = inventory.by_ip(event["source.ip"])
        if asset:
            if event.get("source") == "firewall" or not event.get("host.name"):
                event["host.name"] = asset.hostname
            event.setdefault("host.ip", asset.ip)
            event["host.criticality"] = asset.criticality
            event["host.role"] = asset.role
            event["host.data_classification"] = asset.data_classification
        else:
            event.setdefault("host.criticality", "Medium")

        src = event.get("source.ip")
        dst = event.get("destination.ip")
        if src:
            event["source.internal"] = inventory.is_internal(src)
            if not event["source.internal"]:
                event["source.geo"] = _geo(src)
        if dst:
            event["destination.internal"] = inventory.is_internal(dst)

        hits = intel.match_event(event)
        if hits:
            event["intel.hit"] = True
            event["intel.matches"] = [hit.as_dict() for hit in hits]
            event["intel.threat_type"] = hits[0].threat_type
            event["intel.confidence"] = hits[0].confidence
        else:
            event["intel.hit"] = False
        enriched.append(event)

    enriched.sort(key=lambda e: (e["ts"], e.get("source", "")))
    for idx, event in enumerate(enriched, start=1):
        event["event_id"] = f"EVT-{idx:06d}"
    return enriched


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def discover(path: Path) -> List[Path]:
    if path.is_file():
        return [path]
    files = [p for p in sorted(path.rglob("*")) if p.is_file() and p.suffix in (".log", ".csv", ".jsonl")]
    return files


def ingest(path: Path | None = None) -> dict:
    """Parse every log file under ``path`` and return events + ingest stats."""
    log_path = Path(path) if path else config.LOG_DIR
    events: List[dict] = []
    stats: List[dict] = []
    errors: List[str] = []
    for file_path in discover(log_path):
        parser_name = file_path.parent.name if file_path.parent != log_path else file_path.stem
        parser = PARSER_MAP.get(parser_name)
        if parser is None:
            errors.append(f"no parser for {file_path}")
            continue
        parsed = parser(file_path)
        raw_lines = sum(1 for line in file_path.read_text(errors="replace").splitlines() if line.strip())
        if file_path.suffix == ".csv" and raw_lines:
            raw_lines -= 1  # header row
        stats.append(
            {
                "file": str(file_path.relative_to(config.ROOT)),
                "parser": parser_name,
                "raw_lines": raw_lines,
                "events": len(parsed),
                "parse_rate": round(len(parsed) / raw_lines * 100, 1) if raw_lines else 0.0,
            }
        )
        events.extend(parsed)
    return {"events": events, "stats": stats, "errors": errors}


def source_breakdown(events: Iterable[dict]) -> Counter:
    return Counter(event["source"] for event in events)
