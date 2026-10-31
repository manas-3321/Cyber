# Elastic / Kibana (KQL + EQL) equivalents

Elastic Security uses EQL for sequences and KQL for threshold-style hunting.
These queries run against the ECS-compatible indices the lab ships
(`logs-*`) and mirror the JSON rule pack.

## DET-001 — SSH brute force

```kql
event.category: "authentication" and event.action: "ssh_login_failed"
```

Threshold configuration in a detection rule: **8 events** per **15 minutes**
grouped by `source.ip` and `host.name`.

## DET-002 — Successful login after failures (EQL sequence)

```eql
sequence by source.ip with maxspan=30m
  [ authentication where event.action == "ssh_login_failed" ] with runs=5
  [ authentication where event.action == "ssh_login_success" ]
```

## DET-003 — Windows logon failure burst

```kql
event.code: "4625" and event.action: "windows_logon_failed"
```

Threshold: 10 events / 10 minutes grouped by `source.ip` and `host.name`.

## DET-010 — Port scan

```kql
event.category: "network" and event.action: "firewall_deny"
```

Threshold: 20 events / 5 minutes with a **cardinality** check on
`destination.port` ≥ 10, grouped by `source.ip`.

## DET-011 — Web exploitation attempt

```kql
event.category: "web" and url.path: (
  *"../"* or *"%2e%2e"* or *"union select"* or *"<script"* or *"/etc/passwd"* or *"${jndi:"*
)
```

## DET-012 — HTTP flood

```kql
event.category: "web" and event.action: "http_request" and source.ip: *
```

Threshold: 300 events / 5 minutes grouped by `source.ip`.

## DET-021 / DET-022 — Office spawns PowerShell / encoded command

```kql
process.name: ("powershell.exe" or "pwsh.exe" or "cmd.exe") and
process.parent.name: ("WINWORD.EXE" or "EXCEL.EXE" or "OUTLOOK.EXE")
```

```kql
process.name: "powershell.exe" and
process.command_line: (*"-enc"* or *"-nop"* or *"FromBase64String"* or *"DownloadString"* or *"IEX"*)
```

## DET-023 — LSASS access

```kql
event.action: "process_access" and process.target.name: "lsass.exe"
```

## DET-026 — C2 infrastructure

```kql
event.category: "network" and threat.indicator.type: "ip" and
threat.indicator.name: ("192.0.2.77" or "203.0.113.44")
```

In production this is a **threat-intel indicator match rule** backed by the
`threat.indicator-*` index populated from MISP.

## DET-030 — Shadow copy deletion

```kql
process.command_line: (*"vssadmin"* and *"delete"* and *"shadows"*) or
process.command_line: (*"shadowcopy"* and *"delete"*)
```

## DET-031 — Mass file encryption

```kql
event.category: "file" and event.action: "file_created" and file.extension: "locked"
```

Threshold: 100 events / 10 minutes grouped by `host.name`.

## DET-033 — SMB lateral movement

```kql
event.code: "4624" and winlog.event_data.LogonType: ("3" or "8")
```

Threshold: 3 events / 10 minutes with cardinality on `host.name` ≥ 3, grouped
by `source.ip`.

## DET-038 — Upload to exfiltration destination

```kql
event.category: "web" and http.request.method: ("POST" or "PUT") and
url.domain: "data-share-cloud.net"
```

## ANO-001 — Outbound volume anomaly

ML job: `rare` / `high_distinct_count` on `destination.ip` combined with a
population analysis of `network.bytes` per `host.name` per hour. The lab uses
median + MAD robust z-scoring; the Elastic equivalent is a
`high_mean(destination.ip)` or `metric` anomaly detector on `sum(network.bytes)`.
