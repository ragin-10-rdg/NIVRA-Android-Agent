# Mapping `iocs.csv` categories to Wazuh alerts

This describes how each of the six IOC categories in this dataset could be
turned into a Wazuh detection, against NIVRA's existing Android agent
event schema (`event.type`, `details.*` -- see
`wazuh-integration/rules/nivra_rules.xml`).

**This is a detection/intelligence mapping, not a blocking mechanism.** A
match against one of these IOCs should raise a Wazuh alert for an analyst
to triage -- nothing here should auto-block a device, app, or connection.

| Category | Wazuh alert concept | NIVRA event source | IOC types used |
|---|---|---|---|
| malware | Known-malicious hash/domain/URL detection | `APPLICATION_INSTALL`, `NETWORK_EVENT` | hash, domain, url |
| phishing | Suspicious domain/URL detection | `NETWORK_EVENT` (DNS lookups) | domain, url |
| c2 | Outbound connection to known C2 infrastructure | `NETWORK_EVENT` (connect) | ip, domain |
| scanning | Repeated connection attempts / reconnaissance | `NETWORK_EVENT` (connect, high-frequency) | ip |
| brute-force | Repeated authentication failures | `SECURITY_LOG` (`details.subtype=failed_unlock`) | ip (source-side correlation only -- see caveat below) |
| ransomware | Ransomware-associated IOC/domain/hash detection | `NETWORK_EVENT`, `APPLICATION_INSTALL` | ip, domain, hash |

## Per-category detail

### malware -> hash/domain/URL detection
NIVRA's `APPLICATION_INSTALL` event (rule `100110`/`100111` in
`nivra_rules.xml`) currently reports `details.package_name` but **not** an
APK hash, so this dataset's `hash`-type malware IOCs (from MalwareBazaar/
ThreatFox) can't be matched against NIVRA telemetry today -- that would
require a new on-device collector that hashes the installed APK. The
`domain`/`url` malware IOCs (payload-delivery infrastructure) *can* be
matched today against `NETWORK_EVENT`'s `details.hostname` field.

### phishing -> suspicious domain/URL detection
Match `details.hostname` (DNS-type `NETWORK_EVENT`) or `details.ip_address`
against this dataset's `phishing` URLs' host component. This is exactly
what the existing placeholder rule `100131` does structurally -- this
dataset is the real data that placeholder pattern was a stand-in for.

### c2 -> outbound connection to known C2 IOC
Match `details.ip_address` (connect-type `NETWORK_EVENT`) against this
dataset's `c2` IPs, or `details.hostname` against `c2` domains. This is
what rule `100132` (restricted IP) already targets -- see "Wiring this in"
below.

### scanning -> repeated connection attempts / reconnaissance
This dataset's `scanning` entries (Blocklist.de `apache.txt`/`bots.txt`)
are IPs *reported as scanners/attackers*, not IPs NIVRA devices scan from.
Practically, this category is more useful as an **inbound-reputation
list** for a future NIVRA feature (e.g. flagging when a device receives
connections from one of these IPs) than for outbound matching -- NIVRA's
current `NETWORK_EVENT` only captures the device's own outbound activity
via `ConnectEvent`/`DnsEvent`. Document this as a known scope gap rather
than force a match that isn't meaningful yet.

### brute-force -> repeated authentication failures
NIVRA already detects this natively and independently of any external IOC
list: rule `100101` (single failed unlock) and `100102` (5+ within 5
minutes -- brute-force threshold) fire directly off `details.subtype` and
`details.success` in NIVRA's own `SECURITY_LOG` event, which has nothing
to do with IP reputation (a device's own lock screen has no source IP).
This dataset's `brute-force` **IPs** (Blocklist.de `ssh.txt`/
`bruteforcelogin.txt`) are a different thing -- hosts known for attacking
*other* systems via SSH/web-login -- and would only become relevant to
NIVRA if a monitored device's own network activity connects *to* one of
them (i.e. treat these as a `c2`-style outbound-connection blocklist, not
as a way to detect brute-force *against* the device).

### ransomware -> ransomware-related IOC/domain/hash detection
Same mechanics as `malware` and `c2` (this dataset's ransomware rows are
already typed as `ip`, `domain`, or `hash`) -- match `details.ip_address`/
`details.hostname` against `NETWORK_EVENT`, flagged with a higher rule
level than generic `malware`/`c2` matches given the severity of a
confirmed ransomware C2 contact.

## Wiring this in: CDB lists, not inline regex

`nivra_rules.xml` rules `100131`/`100132` currently use inline `pcre2`
placeholder patterns (a handful of example strings) precisely because
they were never given a real list to check against. With 269 real IOCs,
inline regex alternation doesn't scale -- Wazuh's built-in mechanism for
this is a **CDB list** (`<list>` rule field), a flat `key:value` file the
manager loads into memory for O(1) lookups.

Example: generate a CDB list of just this dataset's `c2` IPs from
`iocs.csv` --

```bash
awk -F, '$4=="c2" && $2=="ip" {print $3":"}' iocs.csv > /var/ossec/etc/lists/nivra_c2_ips
```

(CDB list format is `key:value`, value may be empty -- `ip:` is enough for
a membership check.) Then reference it in a rule:

```xml
<rule id="100132" level="10">
  <if_sid>100130</if_sid>
  <list field="details.ip_address" lookup="match_key">etc/lists/nivra_c2_ips</list>
  <description>NIVRA: $(details.package_name) on $(device.device_id) connected to a known C2 IP $(details.ip_address) (threat intel: nivra_c2_ips).</description>
  <group>network_activity,threat_intel,restricted_destination,</group>
</rule>
```

The same pattern applies per-category: one CDB list per (category, IOC
type) pair generated from `iocs.csv`, one rule per list. This keeps the
threat-intel data itself out of the rule XML entirely, so refreshing the
dataset later never requires touching `nivra_rules.xml`.

**This wiring is done.** The CDB lists live in `wazuh-integration/lists/`
(generated by `build_cdb_lists.py`, one file per category/type pair used
by a rule) and `nivra_rules.xml` rules `100131`-`100136` reference them:

| Rule | Category | IOC type | List file | Level |
|---|---|---|---|---|
| 100131 | phishing | domain (from url host) | `nivra_phishing_domains` | 9 |
| 100132 | c2 | ip | `nivra_c2_ips` | 10 |
| 100133 | c2 | domain | `nivra_c2_domains` | 10 |
| 100134 | ransomware | ip | `nivra_ransomware_ips` | 13 |
| 100135 | ransomware | domain | `nivra_ransomware_domains` | 13 |
| 100136 | malware | domain | `nivra_malware_domains` | 8 |

Verified live via `wazuh-logtest` against real values from each list
(one hit per rule, plus a clean control against rule `100130`/level 0
producing no alert) on 2026-09-29. Regenerating `iocs.csv` later requires
re-running `build_cdb_lists.py`, re-syncing the six list files to
`E:\NIVRA-Wazuh\wazuh-docker\single-node\nivra-receiver\wazuh-ruleset\lists\`,
and recreating the `wazuh.manager` container (`docker compose up -d
wazuh.manager` -- a plain `restart` does not re-attach new/changed bind
mounts) -- same persistence caveat as `nivra_rules.xml`/`nivra_decoder.xml`
described in this repo's Wazuh memory notes.
