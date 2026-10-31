"""Asset inventory and business-context enrichment.

Detection severity is not only a property of the rule: an identical alert on a
tier-0 domain controller outranks the same alert on a developer laptop.  This
module loads the asset register used by the risk scoring model.
"""
from __future__ import annotations

import csv
import ipaddress
from dataclasses import dataclass, field
from typing import Dict, Iterable, Optional

from . import config


@dataclass
class Asset:
    hostname: str
    ip: str
    os: str
    role: str
    owner: str
    business_unit: str
    criticality: str
    environment: str
    data_classification: str
    notes: str = ""
    tags: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "ip": self.ip,
            "role": self.role,
            "criticality": self.criticality,
            "business_unit": self.business_unit,
            "environment": self.environment,
            "data_classification": self.data_classification,
        }


class AssetInventory:
    def __init__(self, assets: Iterable[Asset]):
        self.assets = list(assets)
        self._by_ip: Dict[str, Asset] = {a.ip: a for a in self.assets}
        self._by_host: Dict[str, Asset] = {}
        self._by_owner: Dict[str, Asset] = {}
        for asset in self.assets:
            self._by_host[asset.hostname.lower()] = asset
            self._by_host[asset.hostname.lower().split(".")[0]] = asset
            owner = asset.owner.strip().lower()
            if owner and not owner.startswith(("it-", "user ", "soc", "secops", "dba", "cloud-eng", "eng-")):
                self._by_owner.setdefault(owner, asset)
                if "." in owner:
                    self._by_owner.setdefault(owner.split(".")[0], asset)
        self._networks = [ipaddress.ip_network(n) for n in config.INTERNAL_NETWORKS]

    # -- lookups ---------------------------------------------------------
    def by_ip(self, ip: Optional[str]) -> Optional[Asset]:
        if not ip:
            return None
        return self._by_ip.get(ip)

    def by_host(self, host: Optional[str]) -> Optional[Asset]:
        if not host:
            return None
        key = host.lower()
        if key in self._by_host:
            return self._by_host[key]
        short = key.split(".")[0]
        return self._by_host.get(short)

    def by_owner(self, login: Optional[str]) -> Optional[Asset]:
        if not login:
            return None
        key = str(login).strip().lower()
        return self._by_owner.get(key) or self._by_owner.get(key.split("@")[0])

    def for_event(self, event: dict) -> Optional[Asset]:
        return (
            self.by_host(event.get("host.name"))
            or self.by_ip(event.get("host.ip"))
        )

    def is_internal(self, ip: Optional[str]) -> bool:
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._networks)

    def criticality_of(self, host: Optional[str] = None, ip: Optional[str] = None) -> str:
        asset = self.by_host(host) or self.by_ip(ip)
        return asset.criticality if asset else "Medium"

    def sensitive_assets(self) -> list:
        return [a for a in self.assets if a.data_classification in ("Confidential", "Restricted")]


def load_inventory(path=None) -> AssetInventory:
    path = path or config.ASSETS_FILE
    assets = []
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            assets.append(
                Asset(
                    hostname=row["hostname"].strip(),
                    ip=row["ip"].strip(),
                    os=row["os"].strip(),
                    role=row["role"].strip(),
                    owner=row["owner"].strip(),
                    business_unit=row["business_unit"].strip(),
                    criticality=row["criticality"].strip(),
                    environment=row["environment"].strip(),
                    data_classification=row["data_classification"].strip(),
                    notes=row.get("notes", "").strip(),
                )
            )
    return AssetInventory(assets)
