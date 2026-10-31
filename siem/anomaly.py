"""Statistical anomaly detection (the "ML / behavioural" half of the SIEM).

Three lightweight models are implemented with the standard library:

``outbound_bytes_per_host_hour``
    Robust z-score over hourly outbound byte counts per host.  Median + MAD are
    used so that the very outlier we are hunting does not inflate the baseline
    (a known weakness of mean / standard deviation).
``auth_failures_per_source_ip_hour``
    Robust z-score over hourly failed-authentication counts per source IP.
``first_seen_process``
    Novelty model: a process executing on a host that is absent from the
    approved software baseline and has never been observed on that host.
"""
from __future__ import annotations

from collections import defaultdict
from statistics import median
from typing import Dict, Iterable, List, Tuple

from . import config

MAD_TO_SIGMA = 1.4826


def _hour_bucket(ts_iso: str) -> str:
    dt = config.parse_ts(ts_iso)
    return dt.strftime("%Y-%m-%dT%H")


def _median(values: List[float]) -> float:
    return float(median(values)) if values else 0.0


def robust_stats(values: List[float]) -> Tuple[float, float]:
    """Return (median, robust sigma) using the median absolute deviation."""
    if not values:
        return 0.0, 1.0
    med = _median(values)
    deviations = [abs(v - med) for v in values]
    mad = _median(deviations)
    sigma = MAD_TO_SIGMA * mad
    if sigma <= 0:
        # Degenerate distribution: fall back to a small relative scale so that
        # a single novel observation is not reported as infinitely anomalous.
        sigma = max(1.0, abs(med) * 0.05)
    return med, sigma


def _alert(
    rule: dict,
    entity: dict,
    group_key: str,
    ts: str,
    summary: str,
    extra: dict,
    event_ids: List[str],
    events: List[dict],
) -> dict:
    return {
        "rule_id": rule["id"],
        "rule_name": rule["name"],
        "description": rule.get("description", ""),
        "type": "anomaly",
        "feature": rule.get("feature"),
        "method": rule.get("method"),
        "base_severity": rule.get("severity", "Medium"),
        "confidence": rule.get("confidence", 0.6),
        "incident_type": rule.get("incident_type", "Unclassified"),
        "playbook": rule.get("playbook"),
        "mitre": rule.get("mitre", []),
        "entity": entity,
        "group_key": group_key,
        "first_event_ts": ts,
        "last_event_ts": ts,
        "detected_at": ts,
        "event_count": len(event_ids),
        "event_ids": event_ids[:50],
        "events": [
            {"event_id": e.get("event_id"), "ts": e.get("ts"),
             "action": e.get("event.action"), "message": e.get("message")}
            for e in events[:20]
        ],
        "intel": _intel_from_events(events),
        "suppressed": False,
        "suppression": None,
        "summary": summary,
        "false_positive_notes": rule.get("false_positive_notes", ""),
        "observables": {
            "source_ips": sorted({e.get("source.ip") for e in events if e.get("source.ip")}),
            "destination_ips": sorted({e.get("destination.ip") for e in events if e.get("destination.ip")}),
            "domains": sorted({e.get("dns.question.name") for e in events if e.get("dns.question.name")}),
            "users": sorted({e.get("user.name") for e in events if e.get("user.name")}),
            "hosts": sorted({e.get("host.name") for e in events if e.get("host.name")}),
            "files": [],
        },
        **extra,
    }


def detect(
    events: List[dict],
    anomaly_rules: List[dict],
    baseline_processes: Iterable[str],
) -> dict:
    alerts: List[dict] = []
    baselines: Dict[str, dict] = {}

    baseline_set = {p.casefold() for p in baseline_processes}

    for rule in anomaly_rules:
        feature = rule.get("feature")
        if feature == "outbound_bytes_per_host_hour":
            feature_alerts, baseline = _outbound_bytes(rule, events)
        elif feature == "auth_failures_per_source_ip_hour":
            feature_alerts, baseline = _auth_failures(rule, events)
        elif feature == "first_seen_process":
            feature_alerts, baseline = _first_seen_process(rule, events, baseline_set)
        else:  # pragma: no cover - defensive
            continue
        alerts.extend(feature_alerts)
        baselines[feature] = baseline

    return {"alerts": alerts, "baselines": baselines}


# ---------------------------------------------------------------------------
# Feature: outbound bytes per host per hour
# ---------------------------------------------------------------------------

def _outbound_bytes(rule: dict, events: List[dict]) -> Tuple[List[dict], dict]:
    buckets: Dict[Tuple[str, str], float] = defaultdict(float)
    bucket_events: Dict[Tuple[str, str], List[dict]] = defaultdict(list)

    for event in events:
        if event.get("source") not in ("firewall", "proxy"):
            continue
        if not event.get("destination.ip") or event.get("destination.internal"):
            continue
        host = event.get("host.name")
        if not host:
            continue
        bytes_value = event.get("network.bytes") or 0
        try:
            bytes_value = float(bytes_value)
        except (TypeError, ValueError):
            continue
        if bytes_value <= 0:
            continue
        key = (host, _hour_bucket(event["ts"]))
        buckets[key] += bytes_value
        bucket_events[key].append(event)

    per_host: Dict[str, List[float]] = defaultdict(list)
    for (host, _bucket), total in buckets.items():
        per_host[host].append(total)

    global_values = [v for values in per_host.values() for v in values]
    global_median, global_sigma = robust_stats(global_values)
    threshold = float(rule.get("threshold", 5.0))
    min_value = float(rule.get("min_value", 0))

    alerts: List[dict] = []
    host_baseline = {}
    for host, values in per_host.items():
        if len(values) >= 3:
            med, sigma = robust_stats(values)
            basis = "host"
        else:
            peers = [v for other, vals in per_host.items() if other != host for v in vals]
            med, sigma = robust_stats(peers) if peers else (global_median, global_sigma)
            basis = "environment"
        host_baseline[host] = {
            "buckets": len(values),
            "median_bytes": round(med, 2),
            "sigma_bytes": round(sigma, 2),
            "basis": basis,
        }
        for (bucket_host, bucket), total in buckets.items():
            if bucket_host != host:
                continue
            if total < min_value:
                continue
            score = (total - med) / sigma if sigma else 0.0
            if score < threshold:
                continue
            events_in_bucket = sorted(bucket_events[(host, bucket)], key=lambda e: e["ts"])
            alerts.append(
                _alert(
                    rule,
                    {"host.name": host},
                    host,
                    events_in_bucket[-1]["ts"],
                    f"Outbound volume anomaly on {host}: {_human_bytes(total)} in {bucket}:00 "
                    f"versus median {_human_bytes(med)} (robust z={score:.1f})",
                    {
                        "observed_value": round(total, 2),
                        "observed_human": _human_bytes(total),
                        "baseline_median": round(med, 2),
                        "baseline_sigma": round(sigma, 2),
                        "baseline_basis": basis,
                        "anomaly_score": round(score, 2),
                        "bucket": bucket,
                    },
                    [e.get("event_id") for e in events_in_bucket],
                    events_in_bucket,
                )
            )

    return alerts, {
        "feature": "outbound_bytes_per_host_hour",
        "groups": host_baseline,
        "global_median_bytes": round(global_median, 2),
        "global_sigma_bytes": round(global_sigma, 2),
        "buckets_evaluated": len(buckets),
    }


# ---------------------------------------------------------------------------
# Feature: failed authentications per source IP per hour
# ---------------------------------------------------------------------------

def _auth_failures(rule: dict, events: List[dict]) -> Tuple[List[dict], dict]:
    failure_actions = {"ssh_login_failed", "windows_logon_failed"}
    buckets: Dict[Tuple[str, str], List[dict]] = defaultdict(list)
    for event in events:
        if event.get("event.action") not in failure_actions:
            continue
        src = event.get("source.ip")
        if not src:
            continue
        buckets[(src, _hour_bucket(event["ts"]))].append(event)

    per_source: Dict[str, List[float]] = defaultdict(list)
    for (src, _bucket), evts in buckets.items():
        per_source[src].append(float(len(evts)))

    global_values = [v for values in per_source.values() for v in values]
    global_median, global_sigma = robust_stats(global_values)
    threshold = float(rule.get("threshold", 4.0))
    min_value = float(rule.get("min_value", 5))

    alerts: List[dict] = []
    source_baseline = {}
    for src, values in per_source.items():
        if len(values) >= 3:
            med, sigma = robust_stats(values)
            basis = "source"
        else:
            peers = [v for other, vals in per_source.items() if other != src for v in vals]
            med, sigma = robust_stats(peers) if peers else (global_median, global_sigma)
            basis = "environment"
        source_baseline[src] = {
            "buckets": len(values),
            "median_failures": round(med, 2),
            "sigma": round(sigma, 2),
            "basis": basis,
        }
        for (bucket_src, bucket), evts in buckets.items():
            if bucket_src != src:
                continue
            observed = float(len(evts))
            if observed < min_value:
                continue
            score = (observed - med) / sigma if sigma else 0.0
            if score < threshold:
                continue
            evts = sorted(evts, key=lambda e: e["ts"])
            hosts = sorted({e.get("host.name", "unknown") for e in evts})
            alerts.append(
                _alert(
                    rule,
                    {"source.ip": src},
                    src,
                    evts[-1]["ts"],
                    f"Authentication failure spike from {src}: {int(observed)} failures in "
                    f"{bucket}:00 versus median {med:.0f} (robust z={score:.1f}) against "
                    f"{', '.join(hosts)}",
                    {
                        "observed_value": observed,
                        "baseline_median": round(med, 2),
                        "baseline_sigma": round(sigma, 2),
                        "baseline_basis": basis,
                        "anomaly_score": round(score, 2),
                        "bucket": bucket,
                        "affected_hosts": hosts,
                    },
                    [e.get("event_id") for e in evts],
                    evts,
                )
            )

    return alerts, {
        "feature": "auth_failures_per_source_ip_hour",
        "groups": source_baseline,
        "global_median_failures": round(global_median, 2),
        "global_sigma": round(global_sigma, 2),
        "buckets_evaluated": len(buckets),
    }


# ---------------------------------------------------------------------------
# Feature: first-seen process on endpoint
# ---------------------------------------------------------------------------

def _first_seen_process(rule: dict, events: List[dict], baseline: set) -> Tuple[List[dict], dict]:
    seen: Dict[str, set] = defaultdict(set)
    alerts: List[dict] = []
    novel_by_host: Dict[str, set] = defaultdict(set)

    for event in sorted(events, key=lambda e: e["ts"]):
        if event.get("event.action") != "process_created":
            continue
        host = event.get("host.name")
        process = (event.get("process.name") or "").strip()
        if not host or not process:
            continue
        key = process.casefold()
        first_time = key not in seen[host]
        seen[host].add(key)
        if not first_time:
            continue
        if key in baseline:
            continue
        novel_by_host[host].add(process)
        alerts.append(
            _alert(
                rule,
                {"host.name": host, "process.name": process},
                f"{host}|{process}",
                event["ts"],
                f"Novel process '{process}' executed on {host} for the first time in the "
                f"observed period (not in approved software baseline)",
                {
                    "observed_value": process,
                    "baseline_basis": "software-baseline",
                    "anomaly_score": None,
                    "command_line": event.get("process.command_line"),
                    "user": event.get("user.name"),
                },
                [event.get("event_id")],
                [event],
            )
        )

    return alerts, {
        "feature": "first_seen_process",
        "hosts_observed": len(seen),
        "baseline_size": len(baseline),
        "novel_processes": {host: sorted(values) for host, values in novel_by_host.items()},
    }


def _intel_from_events(events: List[dict]) -> List[dict]:
    seen = {}
    for event in events:
        for match in event.get("intel.matches", []) or []:
            seen.setdefault(match["value"], match)
    return list(seen.values())


def _human_bytes(value: float) -> str:
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(size) < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"
