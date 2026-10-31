"""Ingestion and normalisation tests."""
from __future__ import annotations

import unittest
from collections import Counter

from siem import assets, config, ingest, intel

INVENTORY = assets.load_inventory()
FEED = intel.load_feed()
RESULT = ingest.ingest()
EVENTS = ingest.enrich_events(RESULT["events"], INVENTORY, FEED)


class IngestTests(unittest.TestCase):
    def test_every_source_is_parsed(self):
        sources = Counter(event["source"] for event in EVENTS)
        for expected in ("auth", "windows", "firewall", "proxy", "edr", "web", "mail"):
            self.assertGreater(sources[expected], 0, f"no events parsed for {expected}")

    def test_parse_rate_is_high(self):
        for row in RESULT["stats"]:
            self.assertGreaterEqual(row["parse_rate"], 95.0, f"low parse rate for {row['file']}")

    def test_events_are_time_sorted_and_identified(self):
        timestamps = [event["ts"] for event in EVENTS]
        self.assertEqual(timestamps, sorted(timestamps))
        self.assertEqual(EVENTS[0]["event_id"], "EVT-000001")
        self.assertEqual(len({event["event_id"] for event in EVENTS}), len(EVENTS))

    def test_linux_auth_failure_normalised(self):
        event = next(e for e in EVENTS if e["event.action"] == "ssh_login_failed")
        self.assertEqual(event["event.category"], "authentication")
        self.assertEqual(event["event.outcome"], "failure")
        self.assertEqual(event["destination.port"], 22)
        self.assertIn("source.ip", event)
        self.assertIn("user.name", event)

    def test_windows_security_event_normalised(self):
        logon = next(e for e in EVENTS if e["event.action"] == "windows_logon_success")
        self.assertEqual(logon["source"], "windows")
        self.assertIn("host.name", logon)
        self.assertIn("host.criticality", logon)

    def test_firewall_flow_attributed_to_endpoint_not_firewall(self):
        flow = next(e for e in EVENTS if e["source"] == "firewall" and e.get("destination.internal"))
        self.assertEqual(flow["observer.name"], "fw-core-01")
        self.assertNotEqual(flow["host.name"], "fw-core-01")

    def test_asset_enrichment_assigns_criticality(self):
        fs_event = next(e for e in EVENTS if e.get("host.name") == "fs01.corp.local")
        self.assertEqual(fs_event["host.criticality"], "Critical")
        self.assertEqual(fs_event["host.data_classification"], "Confidential")

    def test_proxy_events_are_attributed_to_client_asset(self):
        exfil = next(e for e in EVENTS if e.get("url.full") == "https://data-share-cloud.net/upload")
        self.assertEqual(exfil["host.name"], "ws-hr-07.corp.local")

    def test_threat_intel_matching(self):
        hits = [e for e in EVENTS if e.get("intel.hit")]
        self.assertTrue(hits)
        values = {match["value"] for event in hits for match in event["intel.matches"]}
        self.assertIn("203.0.113.44", values)
        self.assertIn("data-share-cloud.net", values)
        self.assertIn("secure-auth-portal.com", values)

    def test_off_hours_flag(self):
        exfil = next(e for e in EVENTS if e.get("url.full") == "https://data-share-cloud.net/upload")
        self.assertTrue(exfil["event.off_hours"])
        business_hours = next(
            e for e in EVENTS
            if e["source"] == "windows" and e["event.action"] == "windows_logon_success"
            and e["ts"][11:13] == "08"
        )
        self.assertFalse(business_hours["event.off_hours"])

    def test_internal_external_classification(self):
        external = next(e for e in EVENTS if e["source"] == "web")
        self.assertFalse(external["source.internal"])
        self.assertIn("source.geo", external)

    def test_no_event_lost_between_raw_and_parsed(self):
        raw = sum(row["raw_lines"] for row in RESULT["stats"])
        self.assertGreaterEqual(raw, len(EVENTS))
        self.assertLessEqual(abs(raw - len(EVENTS)), 5, "unexpected number of unparsed lines")


if __name__ == "__main__":
    unittest.main()
