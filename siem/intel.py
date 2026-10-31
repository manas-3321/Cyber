"""Threat-intelligence feed handling.

The lab feed mirrors the fields an analyst would get from MISP / ThreatConnect
/ Anomali and is intentionally stored as CSV so it can be replaced with a live
STIX/TAXII pull without touching the detection engine.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
from typing import Dict, Iterable, List

from . import config


@dataclass
class Indicator:
    type: str
    value: str
    threat_type: str
    confidence: str
    source: str
    first_seen: str
    last_seen: str
    tags: str
    description: str

    def as_dict(self) -> dict:
        return {
            "type": self.type,
            "value": self.value,
            "threat_type": self.threat_type,
            "confidence": self.confidence,
            "source": self.source,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "tags": self.tags,
            "description": self.description,
        }


class ThreatIntel:
    """In-memory IOC index with exact-match lookup per indicator type."""

    def __init__(self, indicators: Iterable[Indicator]):
        self.indicators = list(indicators)
        self._index: Dict[str, Dict[str, Indicator]] = {}
        for ind in self.indicators:
            self._index.setdefault(ind.type, {})[ind.value.lower()] = ind

    def __len__(self) -> int:
        return len(self.indicators)

    def lookup(self, ioc_type: str, value) -> Indicator | None:
        if not value:
            return None
        return self._index.get(ioc_type, {}).get(str(value).strip().lower())

    def match_event(self, event: dict) -> List[Indicator]:
        """Return every IOC that appears anywhere in a normalised event."""
        candidates = []
        for key, ioc_type in (
            ("source.ip", "ip"),
            ("destination.ip", "ip"),
            ("host.ip", "ip"),
            ("dns.question.name", "domain"),
            ("url.full", "domain"),
            ("file.hash_sha256", "sha256"),
            ("email.sender", "domain"),
        ):
            value = event.get(key)
            if not value:
                continue
            if ioc_type == "domain":
                value = _domain_of(str(value))
            hit = self.lookup(ioc_type, value)
            if hit:
                candidates.append(hit)
        for value in event.get("file.hashes", []) or []:
            hit = self.lookup("sha256", value)
            if hit:
                candidates.append(hit)
        return candidates


def _domain_of(value: str) -> str:
    text = value.strip().lower()
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0]
    if ":" in text:
        text = text.split(":", 1)[0]
    parts = text.split(".")
    if len(parts) > 2:
        # Keep the registrable part (co.uk style suffixes are out of scope here).
        return ".".join(parts[-2:])
    return text


def load_feed(path=None) -> ThreatIntel:
    path = path or config.INTEL_FILE
    indicators = []
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            indicators.append(
                Indicator(
                    type=row["type"].strip(),
                    value=row["value"].strip(),
                    threat_type=row["threat_type"].strip(),
                    confidence=row["confidence"].strip(),
                    source=row["source"].strip(),
                    first_seen=row["first_seen"].strip(),
                    last_seen=row["last_seen"].strip(),
                    tags=row.get("tags", "").strip(),
                    description=row.get("description", "").strip(),
                )
            )
    return ThreatIntel(indicators)
