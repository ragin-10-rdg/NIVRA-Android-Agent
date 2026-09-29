# NIVRA Wazuh Alert Catalog

Every alert that can appear on the dashboard from `nivra_rules.xml`, with
its severity level and dashboard tier. Rules `100100` and `100130` are
**not** listed -- they're level 0 correlation-only gates (see comments in
`nivra_rules.xml`) and never produce a dashboard alert themselves.

## Dashboard tiers

| Tier | Level range | Meaning |
|---|---|---|
| 🟢 Low | 0-6 | Minor/routine, authorized events |
| 🟡 Medium | 7-11 | Integrity warnings, first-time-seen behavior |
| 🟠 High | 12-14 | High-importance, correlated attack-pattern matches |
| 🔴 Critical | 15-16 | Confirmed severe attacks, near-zero false-positive chance |

Critical is intentionally reserved for exact threat-intel IOC matches on
the single most severe category (ransomware) -- everything else, even an
exact C2/phishing/malware IOC match, tops out at High. This keeps
Critical meaningful: if it fires, it should mean "act now," not "this
happened often."

## All alerting rules

| Rule ID | Level | Tier | Trigger | Description template |
|---|---|---|---|---|
| 100101 | 5 | 🟢 Low | Single failed device-unlock attempt | `NIVRA: Failed device unlock attempt on $(device.device_id).` |
| 100110 | 5 | 🟢 Low | Approved-baseline app installed | `NIVRA: New (approved-baseline) application installed on $(device.device_id): $(details.package_name).` |
| 100150 | 3 | 🟢 Low | Heartbeat received | `NIVRA: Heartbeat received from $(device.device_id).` |
| 100160 | 6 | 🟢 Low | Outdated security patch level (not current/previous year) | `NIVRA: Device $(device.device_id) reporting an outdated security patch level ($(details.security_patch)).` |
| 100120 | 8 | 🟡 Medium | Security-configuration drift | `NIVRA: Security-configuration drift detected on $(device.device_id): $(details.drifted_fields).` |
| 100111 | 9 | 🟡 Medium | Unexpected (non-baseline) app installed | `NIVRA: UNEXPECTED application installed on managed device $(device.device_id): $(details.package_name) (not on approved baseline).` |
| 100136 | 10 | 🟡 Medium | Resolved a known malware-distribution hostname | `NIVRA: $(details.package_name) on $(device.device_id) resolved a known malware-distribution hostname: $(details.hostname) (threat intel: nivra_malware_domains).` |
| 100131 | 11 | 🟡 Medium | Resolved a known phishing hostname | `NIVRA: $(details.package_name) on $(device.device_id) resolved a known phishing hostname: $(details.hostname) (threat intel: nivra_phishing_domains).` |
| 100102 | 12 | 🟠 High | 5+ failed unlock attempts in 5 minutes | `NIVRA: 5+ failed unlock attempts on $(device.device_id) within 5 minutes -- possible brute-force / lost-or-stolen device.` |
| 100132 | 12 | 🟠 High | Connected to a known C2 IP | `NIVRA: $(details.package_name) on $(device.device_id) connected to a known C2 IP $(details.ip_address):$(details.port) (threat intel: nivra_c2_ips).` |
| 100133 | 12 | 🟠 High | Resolved a known C2 hostname | `NIVRA: $(details.package_name) on $(device.device_id) resolved a known C2 hostname: $(details.hostname) (threat intel: nivra_c2_domains).` |
| 100140 | 12 | 🟠 High | ADB / administrative activity (confirmed ADB shell session) | `NIVRA: ADB or administrative security activity detected on $(device.device_id).` |
| 100151 | 12 | 🟠 High | No heartbeat within expected window (agent may be offline/disabled/tampered) | `NIVRA: Device $(device.device_id) has not sent a heartbeat within the expected window -- agent may be offline, disabled, or the device compromised/tampered with.` |
| 100134 | 15 | 🔴 Critical | Connected to a known ransomware-affiliated IP | `NIVRA: $(details.package_name) on $(device.device_id) connected to a known ransomware-affiliated IP $(details.ip_address):$(details.port) (threat intel: nivra_ransomware_ips).` |
| 100135 | 15 | 🔴 Critical | Resolved a known ransomware-affiliated hostname | `NIVRA: $(details.package_name) on $(device.device_id) resolved a known ransomware-affiliated hostname: $(details.hostname) (threat intel: nivra_ransomware_domains).` |

## Why each rule sits where it does

- **Low (100101, 100110, 100150, 100160):** routine telemetry or a single
  low-signal event (one failed unlock could just be a typo; heartbeats and
  approved installs are expected, healthy activity).
- **Medium (100111, 100120, 100131, 100136):** something worth a SOC
  analyst's attention but not yet a confirmed attack -- a first-time
  install off the approved list, config drift, or contact with a
  known-bad domain in a lower-severity category (phishing lure, generic
  malware distribution infrastructure).
- **High (100102, 100132, 100133, 100140, 100151):** a confirmed,
  OS-level or correlated signal rather than a heuristic -- 5+ failures in
  5 minutes, active C2 contact, an actual ADB shell session
  (`SecurityLogCollector.kt` tags this `Severity.HIGH` at the source,
  it's not inferred), or sustained heartbeat silence. Still ambiguous
  enough (dead battery, flaky network, shared/legitimate infra, or
  legitimate developer ADB use) that Critical would overstate it.
- **Critical (100134, 100135):** an exact match against a specifically
  ransomware-affiliated IOC. This is the one category where "the
  indicator is real and current" (per `wazuh-integration/threat-intel/
  README.md`'s freshness caveats) converts directly to "this device may
  be about to be encrypted" -- the closest thing this ruleset has to a
  near-zero-false-positive, drop-everything signal.

## Rules that exist but never alert

| Rule ID | Level | Role |
|---|---|---|
| 100100 | 0 | Base gate: any NIVRA JSON event (matches `decoded_as=json` + `schema_version`). All other rules chain off this via `if_sid`. |
| 100130 | 0 | NETWORK_EVENT gate: matches every outbound connect/DNS event, but only exists so 100131-100136 below can check it against threat-intel lists. Plain network activity alone is not alert-worthy (see `nivra_rules.xml` comment -- this is why NETWORK_EVENT used to be >95% of alert volume before this rule was demoted from level 3 to level 0). |
