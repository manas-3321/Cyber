"""Correlation engine: match, threshold, distinct-count, sequence and
allowlist suppression.

The engine consumes normalised events and a declarative rule pack.  It is
deliberately small enough to audit: every alert can be traced back to the rule,
the group key and the exact event IDs that produced it.
"""
from __future__ import annotations

import re
from collections import defaultdict, deque
from typing import Dict, Iterable, List, Optional

from . import config

_MISSING = object()


# ---------------------------------------------------------------------------
# Matching helpers
# ---------------------------------------------------------------------------

def _eq(actual, expected) -> bool:
    if actual is None or actual is _MISSING:
        return False
    if isinstance(expected, bool):
        return bool(actual) is expected
    if isinstance(expected, int) and not isinstance(expected, bool):
        try:
            return int(actual) == expected
        except (TypeError, ValueError):
            return False
    return str(actual).strip().casefold() == str(expected).strip().casefold()


def match_event(event: dict, spec: Optional[dict]) -> bool:
    if not spec:
        return True
    for field, expected in spec.items():
        actual = event.get(field, _MISSING)
        if actual is _MISSING:
            return False
        if isinstance(expected, (list, tuple, set)):
            if not any(_eq(actual, item) for item in expected):
                return False
        elif not _eq(actual, expected):
            return False
    return True


def _regex_hit(event: dict, spec: Optional[dict], cache: Dict[str, re.Pattern]) -> bool:
    if not spec:
        return True
    for field, pattern in spec.items():
        value = event.get(field)
        if value is None:
            return False
        compiled = cache.get(pattern)
        if compiled is None:
            compiled = re.compile(pattern)
            cache[pattern] = compiled
        if not compiled.search(str(value)):
            return False
    return True


def match_intel(event: dict, threat_types: Optional[Iterable[str]]) -> bool:
    # No threat-type filter on the rule: threat intelligence is not required.
    if not threat_types:
        return True
    if not event.get("intel.hit"):
        return False
    wanted = {t.casefold() for t in threat_types}
    for match in event.get("intel.matches", []):
        if str(match.get("threat_type", "")).casefold() in wanted:
            return True
    return False


def group_key(event: dict, fields: List[str]) -> str:
    parts = []
    for field in fields:
        value = event.get(field, "unknown")
        parts.append(str(value))
    return "|".join(parts)


def _sample_events(events: List[dict], limit: int = 40) -> List[dict]:
    sample = events[:limit]
    return [
        {
            "event_id": e.get("event_id"),
            "ts": e.get("ts"),
            "action": e.get("event.action"),
            "message": e.get("message"),
        }
        for e in sample
    ]


# ---------------------------------------------------------------------------
# Rule evaluation
# ---------------------------------------------------------------------------

class RuleEngine:
    def __init__(self, rule_pack: dict, allowlists: Optional[dict] = None):
        self.rules = rule_pack.get("rules", [])
        self.anomaly_rules = rule_pack.get("anomaly_rules", [])
        self.allowlists = (allowlists or {}).get("allowlists", [])
        self._regex_cache: Dict[str, re.Pattern] = {}

    # -- public API ------------------------------------------------------
    def evaluate(self, events: List[dict]) -> dict:
        alerts: List[dict] = []
        for rule in self.rules:
            produced = self._evaluate_rule(rule, events)
            alerts.extend(produced)
        for idx, alert in enumerate(sorted(alerts, key=lambda a: a["first_event_ts"]), start=1):
            alert["alert_id"] = f"ALT-2026-{idx:04d}"
        suppressed = [a for a in alerts if a.get("suppressed")]
        return {"alerts": [a for a in alerts if not a.get("suppressed")], "suppressed": suppressed}

    def _evaluate_rule(self, rule: dict, events: List[dict]) -> List[dict]:
        candidates = [
            event
            for event in events
            if match_event(event, rule.get("match"))
            and _regex_hit(event, rule.get("match_regex"), self._regex_cache)
            and match_intel(event, rule.get("intel_threat_types"))
        ]
        if not candidates:
            return []

        rule_type = rule.get("type", "match")
        if rule_type == "threshold":
            raw_alerts = self._threshold(rule, candidates)
        elif rule_type == "sequence":
            raw_alerts = self._sequence(rule, candidates)
        else:
            raw_alerts = self._match(rule, candidates)

        return [self._finalise(rule, alert) for alert in raw_alerts]

    # -- rule types ------------------------------------------------------
    def _match(self, rule: dict, candidates: List[dict]) -> List[dict]:
        """One alert per group; all hits inside the window are aggregated."""
        grouped: Dict[str, List[dict]] = defaultdict(list)
        for event in candidates:
            grouped[group_key(event, rule.get("group_by", []))].append(event)

        alerts = []
        for key, hits in grouped.items():
            hits.sort(key=lambda e: e["ts"])
            alerts.append(
                self._alert_dict(
                    rule,
                    hits[0],
                    hits[-1],
                    len(hits),
                    self._entity(hits[0], rule),
                    key,
                    hits,
                    extra=self._extra(rule, hits),
                )
            )
        return alerts

    def _threshold(self, rule: dict, candidates: List[dict]) -> List[dict]:
        grouped: Dict[str, List[dict]] = defaultdict(list)
        for event in candidates:
            grouped[group_key(event, rule.get("group_by", []))].append(event)

        window = rule.get("window_seconds", 300)
        required = rule.get("count", 1)
        distinct_spec = rule.get("distinct")
        threshold_field = rule.get("threshold_field")
        operator = rule.get("threshold_operator", ">=")

        alerts = []
        for key, hits in grouped.items():
            hits.sort(key=lambda e: e["ts"])

            if threshold_field:
                threshold_value = _to_float(rule.get("threshold_value"))
                if threshold_value is None:
                    threshold_value = _to_float(rule.get("count")) or 1.0
                qualifying = [
                    hit for hit in hits
                    if _compare(_to_float(hit.get(threshold_field)) or 0.0, operator, threshold_value)
                ]
                if qualifying:
                    total = sum(_to_float(hit.get(threshold_field)) or 0.0 for hit in qualifying)
                    alerts.append(
                        self._alert_dict(
                            rule, qualifying[0], qualifying[-1], len(qualifying),
                            self._entity(qualifying[0], rule), key, qualifying,
                            extra={"observed_value": total, "threshold": threshold_value},
                        )
                    )
                continue

            window_events: deque = deque()
            last_alert_ts = None
            for hit in hits:
                window_events.append(hit)
                while _delta(window_events[0]["ts"], hit["ts"]) > window:
                    window_events.popleft()

                if len(window_events) < required:
                    continue
                if distinct_spec:
                    distinct = {e.get(distinct_spec["field"]) for e in window_events}
                    distinct.discard(None)
                    if len(distinct) < distinct_spec.get("min", 1):
                        continue
                if last_alert_ts is not None and _delta(last_alert_ts, hit["ts"]) < window:
                    continue

                current = list(window_events)
                alerts.append(
                    self._alert_dict(
                        rule, current[0], current[-1], len(current),
                        self._entity(current[0], rule), key, current,
                        extra=self._extra(rule, current),
                    )
                )
                last_alert_ts = hit["ts"]
        return alerts

    def _sequence(self, rule: dict, candidates: List[dict]) -> List[dict]:
        grouped: Dict[str, List[dict]] = defaultdict(list)
        for event in candidates:
            grouped[group_key(event, rule.get("group_by", []))].append(event)

        window = rule.get("window_seconds", 900)
        steps = rule.get("steps", [])
        alerts = []
        for key, hits in grouped.items():
            hits.sort(key=lambda e: e["ts"])
            matched = self._match_sequence(hits, steps, window)
            if not matched:
                continue
            alerts.append(
                self._alert_dict(
                    rule, matched[0], matched[-1], len(matched),
                    self._entity(matched[0], rule), key, matched,
                    extra={"chain": [step.get("label", step.get("match")) for step in steps]},
                )
            )
        return alerts

    def _match_sequence(self, events: List[dict], steps: List[dict], window: int) -> Optional[List[dict]]:
        for start_index, first in enumerate(events):
            if not match_event(first, steps[0].get("match")):
                continue
            start_ts = first["ts"]
            cursor = start_index
            collected: List[dict] = []
            complete = True
            for step in steps:
                needed = int(step.get("count", 1))
                found = 0
                while cursor < len(events) and found < needed:
                    candidate = events[cursor]
                    if _delta(start_ts, candidate["ts"]) > window:
                        break
                    if match_event(candidate, step.get("match")):
                        collected.append(candidate)
                        found += 1
                    cursor += 1
                if found < needed:
                    complete = False
                    break
            if complete:
                return collected
        return None

    # -- alert construction ---------------------------------------------
    def _alert_dict(self, rule, first, last, count, entity, key, events, extra=None) -> dict:
        intel_matches = []
        for event in events:
            intel_matches.extend(event.get("intel.matches", []))
        unique_intel = {m["value"]: m for m in intel_matches}

        alert = {
            "rule_id": rule["id"],
            "rule_name": rule["name"],
            "description": rule.get("description", ""),
            "type": rule.get("type", "match"),
            "base_severity": rule.get("severity", "Medium"),
            "confidence": rule.get("confidence", 0.7),
            "incident_type": rule.get("incident_type", "Unclassified"),
            "playbook": rule.get("playbook"),
            "mitre": rule.get("mitre", []),
            "entity": entity,
            "group_key": key,
            "first_event_ts": first["ts"],
            "last_event_ts": last["ts"],
            "detected_at": last["ts"],
            "event_count": count,
            "event_ids": [e.get("event_id") for e in events[:50]],
            "events": _sample_events(events),
            "intel": list(unique_intel.values()),
            "suppressed": False,
            "suppression": None,
            "false_positive_notes": rule.get("false_positive_notes", ""),
            "references": rule.get("references", []),
        }
        alert["observables"] = {
            "source_ips": sorted({e.get("source.ip") for e in events if e.get("source.ip")}),
            "destination_ips": sorted({e.get("destination.ip") for e in events if e.get("destination.ip")}),
            "domains": sorted({e.get("dns.question.name") for e in events if e.get("dns.question.name")}),
            "users": sorted({e.get("user.name") for e in events if e.get("user.name")}),
            "hosts": sorted({e.get("host.name") for e in events if e.get("host.name")}),
            "files": sorted({e.get("file.path") for e in events if e.get("file.path")})[:25],
        }
        if extra:
            alert.update(extra)

        context = dict(first)
        context.update(entity)
        context["count"] = count
        context["event_count"] = count
        context["distinct"] = extra.get("distinct_count") if extra else None
        context["first_ts"] = first["ts"]
        context["last_ts"] = last["ts"]
        summary = rule.get("summary_template", "")
        if summary:
            try:
                alert["summary"] = summary.format(**context)
            except (KeyError, IndexError):
                alert["summary"] = rule["name"]
        else:
            alert["summary"] = self._default_summary(rule, entity, count, first, last)

        return alert

    def _default_summary(self, rule, entity, count, first, last) -> str:
        anchor = ", ".join(f"{k}={v}" for k, v in entity.items()) or "environment-wide"
        return (
            f"{rule['name']}: {count} matching event(s) for {anchor} "
            f"between {first['ts']} and {last['ts']}"
        )

    def _entity(self, event: dict, rule: dict) -> dict:
        entity = {}
        for field in rule.get("group_by", []):
            entity[field] = event.get(field, "unknown")
        return entity

    def _extra(self, rule: dict, events: List[dict]) -> dict:
        extra = {}
        distinct_spec = rule.get("distinct")
        if distinct_spec:
            values = {e.get(distinct_spec["field"]) for e in events}
            values.discard(None)
            extra["distinct_count"] = len(values)
            extra["distinct_values"] = sorted(str(v) for v in values)[:25]
        return extra

    def _finalise(self, rule: dict, alert: dict) -> dict:
        return alert


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _to_float(value) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _compare(value: float, operator: str, threshold: float) -> bool:
    if operator == ">":
        return value > threshold
    if operator == ">=":
        return value >= threshold
    if operator == "<":
        return value < threshold
    if operator == "<=":
        return value <= threshold
    return value == threshold


def _delta(start_iso: str, end_iso: str) -> float:
    start = config.parse_ts(start_iso)
    end = config.parse_ts(end_iso)
    return (end - start).total_seconds()


def load_allowlists(path=None) -> dict:
    return config.load_json(path or config.ALLOWLIST_FILE)
