"""Detection, scoring, correlation and reporting tests."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from siem import config, pipeline


class PipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.out = Path(cls._tmp.name) / "output"
        cls.result = pipeline.run(output_dir=cls.out)
        cls.alerts = cls.result["alerts"]
        cls.suppressed = cls.result["suppressed"]
        cls.incidents = cls.result["incidents"]
        cls.metrics = cls.result["metrics"]

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    # -- helper ----------------------------------------------------------
    def rules_fired(self):
        return {alert["rule_id"] for alert in self.alerts}

    def alerts_for(self, rule_id):
        return [alert for alert in self.alerts if alert["rule_id"] == rule_id]

    # -- rule coverage ---------------------------------------------------
    def test_all_scenario_rules_fire(self):
        expected = {
            "DET-001", "DET-002", "DET-003", "DET-010", "DET-011", "DET-012", "DET-013",
            "DET-020", "DET-021", "DET-022", "DET-023", "DET-024", "DET-025", "DET-026",
            "DET-027", "DET-030", "DET-031", "DET-032", "DET-033", "DET-034", "DET-035",
            "DET-036", "DET-037", "DET-038", "DET-039", "DET-040",
            "ANO-001", "ANO-002", "ANO-003",
        }
        self.assertEqual(expected - self.rules_fired(), set())

    def test_every_rule_in_the_pack_was_exercised(self):
        self.assertEqual(self.metrics["coverage"]["rules_triggered"],
                         self.metrics["coverage"]["rules_defined"])

    # -- brute force -----------------------------------------------------
    def test_ssh_brute_force_threshold_and_realert_suppression(self):
        alerts = self.alerts_for("DET-001")
        self.assertEqual(len(alerts), 1, "sliding window should emit one alert per burst")
        alert = alerts[0]
        self.assertEqual(alert["entity"]["source.ip"], "203.0.113.44")
        self.assertEqual(alert["event_count"], 8)
        self.assertEqual(alert["severity"], "High")

    def test_success_after_failure_sequence_is_critical(self):
        alert = self.alerts_for("DET-002")[0]
        self.assertEqual(alert["type"], "sequence")
        self.assertEqual(alert["severity"], "Critical")
        self.assertEqual(alert["event_count"], 6)
        self.assertIn("chain", alert)

    def test_benign_admin_typos_do_not_alert(self):
        for alert in self.alerts:
            if alert["rule_id"] in ("DET-001", "DET-003"):
                self.assertNotEqual(alert["entity"].get("source.ip"), "10.10.0.50")

    # -- reconnaissance / web -------------------------------------------
    def test_port_scan_requires_distinct_ports(self):
        alert = self.alerts_for("DET-010")[0]
        self.assertGreaterEqual(alert["distinct_count"], 10)
        self.assertEqual(alert["entity"]["source.ip"], "198.51.100.23")

    def test_web_exploitation_signatures(self):
        alert = self.alerts_for("DET-011")[0]
        self.assertGreaterEqual(alert["event_count"], 6)

    def test_http_flood_threshold(self):
        alert = self.alerts_for("DET-012")[0]
        self.assertEqual(alert["event_count"], 300)

    def test_credential_stuffing(self):
        alert = self.alerts_for("DET-013")[0]
        self.assertEqual(alert["severity"], "Medium")

    # -- endpoint --------------------------------------------------------
    def test_office_child_process_and_encoded_powershell(self):
        parent = self.alerts_for("DET-021")[0]
        encoded = self.alerts_for("DET-022")[0]
        self.assertEqual(parent["entity"]["host.name"], "ws-fin-14.corp.local")
        self.assertEqual(parent["severity"], "Critical")
        self.assertGreaterEqual(encoded["risk_score"], 70)

    def test_ransomware_chain(self):
        self.assertEqual(self.alerts_for("DET-030")[0]["severity"], "Critical")
        mass = self.alerts_for("DET-031")[0]
        self.assertGreaterEqual(mass["event_count"], 100)
        self.assertEqual(self.alerts_for("DET-039")[0]["event_count"], 1)

    def test_lateral_movement_requires_three_hosts(self):
        alert = self.alerts_for("DET-033")[0]
        self.assertGreaterEqual(alert["distinct_count"], 3)

    # -- tuning ----------------------------------------------------------
    def test_scanner_is_suppressed(self):
        suppressed = {(a["rule_id"], a["suppression"]["id"]) for a in self.suppressed}
        self.assertIn(("DET-010", "AL-001"), suppressed)
        self.assertFalse(any(a["rule_id"] == "DET-010" and a["entity"].get("source.ip") == "10.10.5.20"
                             for a in self.alerts))

    def test_backup_volume_anomaly_is_suppressed(self):
        suppressed_ids = {a["suppression"]["id"] for a in self.suppressed}
        self.assertIn("AL-002", suppressed_ids)
        self.assertFalse(any(a["entity"].get("host.name", "").startswith("backup-01")
                             for a in self.alerts))

    def test_service_account_share_access_is_suppressed(self):
        suppressed = {(a["rule_id"], a["suppression"]["id"]) for a in self.suppressed}
        self.assertIn(("DET-034", "AL-003"), suppressed)

    # -- anomaly ---------------------------------------------------------
    def test_outbound_volume_anomaly_flags_insider_exfiltration(self):
        alerts = self.alerts_for("ANO-001")
        hosts = {alert["entity"]["host.name"] for alert in alerts}
        self.assertIn("ws-hr-07.corp.local", hosts)
        alert = next(a for a in alerts if a["entity"]["host.name"] == "ws-hr-07.corp.local")
        self.assertGreater(alert["anomaly_score"], 5)
        self.assertGreater(alert["observed_value"], alert["baseline_median"])

    def test_first_seen_process_detects_malware_binaries(self):
        processes = {a["entity"].get("process.name") for a in self.alerts_for("ANO-003")}
        self.assertIn("invoice_2026.exe", processes)
        self.assertIn("svc.exe", processes)

    def test_auth_anomaly_fires_on_low_and_slow_brute_force(self):
        alerts = self.alerts_for("ANO-002")
        self.assertTrue(alerts)
        self.assertTrue(all(alert["anomaly_score"] >= 4 for alert in alerts))

    # -- scoring ---------------------------------------------------------
    def test_asset_criticality_raises_risk(self):
        from siem import assets, scoring

        inventory = assets.load_inventory()
        base_alert = {
            "rule_id": "TEST-001", "rule_name": "test", "base_severity": "High",
            "confidence": 0.9, "type": "match", "event_count": 1, "intel": [],
        }
        critical = scoring.score_alert(
            {**base_alert, "entity": {"host.name": "fs01.corp.local"}}, inventory)
        low = scoring.score_alert(
            {**base_alert, "entity": {"host.name": "ws-dev-03.corp.local"}}, inventory)
        self.assertGreater(critical["risk_score"], low["risk_score"])
        self.assertEqual(critical["score_breakdown"]["asset_criticality"], 10)
        self.assertEqual(low["score_breakdown"]["asset_criticality"], 0)

    def test_threat_intel_escalates_severity(self):
        c2 = self.alerts_for("DET-026")[0]
        self.assertEqual(c2["severity"], "Critical")
        self.assertGreater(c2["score_breakdown"]["threat_intel"], 0)
        self.assertTrue(c2["intel"])

    def test_scores_are_bounded(self):
        for alert in self.alerts:
            self.assertGreaterEqual(alert["risk_score"], 0)
            self.assertLessEqual(alert["risk_score"], 100)
            self.assertIn(alert["severity"], config.SEVERITIES)

    # -- incidents -------------------------------------------------------
    def test_incident_count_and_priorities(self):
        self.assertGreaterEqual(len(self.incidents), 8)
        for incident in self.incidents:
            self.assertIn(incident["priority"], ("P1", "P2", "P3", "P4"))
            self.assertEqual(incident["priority"][1], str(4 - config.SEVERITY_ORDER[incident["severity"]]))

    def test_phishing_and_ransomware_correlate_into_one_campaign(self):
        campaigns = [i for i in self.incidents if i["campaign"]]
        self.assertTrue(campaigns)
        campaign = next(i for i in campaigns if "Ransomware" in i["types"])
        rule_ids = set(campaign["detection_rules"])
        self.assertIn("DET-020", rule_ids)
        self.assertIn("DET-030", rule_ids)
        self.assertIn("DET-031", rule_ids)
        self.assertIn("Ransomware", campaign["types"])
        self.assertIn("Phishing", campaign["types"])
        self.assertEqual(campaign["severity"], "Critical")

    def test_incident_timeline_is_ordered_and_has_response(self):
        for incident in self.incidents:
            timestamps = [entry["ts"] for entry in incident["timeline"]]
            self.assertEqual(timestamps, sorted(timestamps))
            self.assertTrue(incident["response_actions"])
            phases = {action["phase"] for action in incident["response_actions"]}
            self.assertIn("Containment", phases)
            self.assertIn("Post-Incident", phases)

    def test_containment_never_precedes_the_last_detection(self):
        for incident in self.incidents:
            last_detection = max(alert["detected_at"] for alert in incident["alerts"])
            self.assertGreaterEqual(incident["contained_at"], last_detection)

    def test_mttr_is_measured(self):
        for incident in self.incidents:
            self.assertGreaterEqual(incident["mttd_minutes"], 0)
            self.assertGreater(incident["mttr_minutes"], 0)
            self.assertGreaterEqual(incident["mttr_minutes"], incident["mttd_minutes"])

    def test_related_cases_are_linked(self):
        self.assertTrue(any(i["related_incidents"] for i in self.incidents))

    # -- reporting -------------------------------------------------------
    def test_reports_and_dashboard_are_written(self):
        case_file = self.out / "incidents" / f"{self.incidents[0]['incident_id']}.md"
        self.assertTrue(case_file.exists())
        text = case_file.read_text()
        for heading in ("Incident summary", "Detection and analysis", "Timeline of events",
                        "Root-cause analysis", "Impact assessment", "Response and recovery",
                        "Recommendations"):
            self.assertIn(heading, text)
        dashboard = (self.out / "dashboard.html").read_text()
        self.assertIn("SOC Detection", dashboard)
        self.assertIn("INC-2026-0001", dashboard)
        self.assertTrue((self.out / "visuals" / "events-per-day.svg").exists())
        self.assertTrue((self.out / "thehive_cases.json").exists())
        self.assertTrue((self.out / "metrics.json").exists())

    def test_thehive_export_shape(self):
        import json

        cases = json.loads((self.out / "thehive_cases.json").read_text())
        self.assertEqual(len(cases), len(self.incidents))
        first = cases[0]
        for key in ("_id", "title", "severity", "status", "tasks", "customFields"):
            self.assertIn(key, first)
        self.assertGreater(first["severity"], 0)

    # -- determinism -----------------------------------------------------
    def test_pipeline_is_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            second = pipeline.run(output_dir=Path(tmp) / "output", write_events=False)
        fingerprint = [(a["rule_id"], tuple(sorted(a["entity"].items())))
                       for a in self.alerts]
        second_fingerprint = [(a["rule_id"], tuple(sorted(a["entity"].items())))
                              for a in second["alerts"]]
        self.assertEqual(fingerprint, second_fingerprint)
        self.assertEqual(len(self.incidents), len(second["incidents"]))


if __name__ == "__main__":
    unittest.main()
