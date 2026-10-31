# Detection content

| File | Format | Purpose |
|---|---|---|
| `rules.json` | Lab JSON rule pack | Reference implementation, executed by `siem/rules.py` and `siem/anomaly.py` |
| `allowlists.json` | JSON | Governed suppressions (owner, ticket, expiry, reason) |
| `baseline_processes.json` | JSON | Approved software baseline for the novelty model |
| `sigma/*.yml` | Sigma | Vendor-neutral detection rules |
| `splunk/searches.spl` | Splunk SPL | Correlation searches with lookups and thresholds |
| `elastic/kql.md` | KQL / EQL | Kibana detection rules and an EQL sequence |
| `suricata/local.rules` | Suricata | Network-layer IDS rules |

## Rule pack schema

```jsonc
{
  "id": "DET-001",
  "name": "SSH brute force against Linux host",
  "description": "…why this matters…",
  "type": "match | threshold | sequence",
  "severity": "Low | Medium | High | Critical",
  "confidence": 0.85,
  "incident_type": "Brute Force",
  "playbook": "PB-BRUTE-FORCE",
  "mitre": [{"id": "T1110.001", "tactic": "Credential Access", "technique": "Brute Force: Password Guessing"}],
  "match": {"event.action": ["ssh_login_failed"]},      // field → value or list
  "match_regex": {"process.command_line": "(?i)-enc\\s"},// optional
  "intel_threat_types": ["Malware"],                    // optional intel filter
  "group_by": ["source.ip", "host.name"],
  "count": 8,                                           // threshold
  "window_seconds": 900,
  "distinct": {"field": "destination.port", "min": 10},  // optional cardinality
  "threshold_field": "network.bytes",                    // optional numeric field
  "threshold_value": 500000000,
  "steps": [{"match": {}, "count": 5, "label": "…"}],     // sequence only
  "false_positive_notes": "…",
  "references": ["…"]
}
```

Matching semantics:

* values are compared case-insensitively; booleans and integers compare by type;
* every key in `match` must match (AND); list values are OR;
* `match_regex` is an unanchored (`search`) regular expression on the field text;
* `intel_threat_types` requires an IOC match of that threat type;
* threshold rules use a sliding window with a cooldown of one window to avoid alert
  storms; `distinct` adds a cardinality requirement.

## Validation

```bash
python3 -m unittest tests.test_detection -v
```

New rules must include: a triggering scenario, a benign control, false-positive notes,
an ATT&CK mapping and a playbook link.
