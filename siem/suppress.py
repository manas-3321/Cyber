"""Allowlist / suppression layer.

Suppression is applied centrally so that every alert producer (correlation
rules, anomaly models) is subject to exactly the same tuning governance.
"""
from __future__ import annotations

from typing import List, Optional

from .rules import match_event


def _host_variants(value: str) -> set:
    text = str(value).strip().lower()
    return {text, text.split(".")[0]}


def _entry_matches(spec: dict, context: dict) -> bool:
    for key, expected in spec.items():
        actual = context.get(key)
        if actual is None:
            return False
        values = expected if isinstance(expected, (list, tuple, set)) else [expected]
        if key == "host.name":
            actual_variants = _host_variants(actual)
            if not any(_host_variants(item) & actual_variants for item in values):
                return False
        elif not match_event(context, {key: expected}):
            return False
    return True


def find_suppression(alert: dict, allowlists: List[dict]) -> Optional[dict]:
    context = dict(alert.get("entity", {}))
    for event in alert.get("events", [])[:1]:
        for key, value in event.items():
            context.setdefault(key, value)
    # Backfill fields that the alert inherited from the first raw event.
    for key in ("source.ip", "host.name", "user.name", "destination.ip"):
        if key not in context and key in alert.get("entity", {}):
            context[key] = alert["entity"][key]

    for entry in allowlists:
        if alert["rule_id"] not in entry.get("rule_ids", []):
            continue
        spec = entry.get("match", {})
        if spec and _entry_matches(spec, context):
            return {
                "id": entry["id"],
                "reason": entry.get("reason", ""),
                "owner": entry.get("owner"),
                "ticket": entry.get("ticket"),
                "expires": entry.get("expires"),
            }
    return None


def apply(alert: dict, allowlists: List[dict]) -> dict:
    suppression = find_suppression(alert, allowlists)
    if suppression:
        alert["suppressed"] = True
        alert["suppression"] = suppression
    else:
        alert["suppressed"] = False
        alert["suppression"] = None
    return alert
