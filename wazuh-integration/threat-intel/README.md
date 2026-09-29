# NIVRA Wazuh IOC Threat-Intelligence Dataset

A curated set of **real, publicly reported indicators of compromise (IOCs)**
for use in a Wazuh SOC laboratory. Every value in `iocs.csv` / `iocs.json`
was copied from a live public threat-intelligence feed on the collection
date below -- nothing in this dataset was invented.

- **Collected:** 2026-09-29 (UTC), from each source's live "recent" export
- **Total IOCs:** 269 (unique)
- **Files:** `iocs.csv`, `iocs.json` (identical records, two formats),
  this `README.md`, and `wazuh_ioc_mapping.md`

## Category counts

| Category    | Count | Target | Notes |
|-------------|------:|-------:|-------|
| malware     | 50 | 50 | met |
| phishing    | 50 | 50 | met |
| c2          | 50 | 50 | met |
| scanning    | 50 | 50 | met |
| brute-force | 50 | 50 | met |
| ransomware  | 19 | 50 | **shortfall -- see below** |
| **Total**   | **269** | 300 | |

### Why ransomware fell short of 50

abuse.ch's ThreatFox/URLhaus/MalwareBazaar "recent" feeds are dominated by
commodity infostealers, RATs, loaders, and generic C2 frameworks (Cobalt
Strike, AsyncRAT, Vidar, etc.) -- very little of what's currently flowing
through them is *identifiably* ransomware-specific infrastructure or
payloads. Rather than guess (rule #10 of this task's source rules:
"if an IOC cannot be confidently categorized, exclude it rather than
guessing"), this dataset only labels an entry `ransomware` when the
source's own malware-family/tag field contains an unambiguous ransomware
brand name (e.g. `RansomHub`, `WannaCryptor`/`WannaCry`, `Akira`). That
strict rule matched 31 raw candidates across all three abuse.ch feeds;
after removing duplicates (several `RansomHub` C2 reports pointed at the
same underlying IP), 19 unique IOCs remained. A generic loader or Cobalt
Strike beacon *might* belong to a ransomware affiliate in reality, but the
feed data alone doesn't say so -- including it as `ransomware` would be
exactly the kind of unjustified labeling this dataset is required to
avoid.

## Sources used

| Source | IOCs contributed | Feed used |
|---|---:|---|
| ThreatFox (abuse.ch) | 85 | `https://threatfox.abuse.ch/export/json/recent/` |
| Blocklist.de | 100 | `lists/ssh.txt`, `lists/bruteforcelogin.txt`, `lists/apache.txt`, `lists/bots.txt` |
| OpenPhish | 50 | community feed (`feed.txt`) |
| MalwareBazaar (abuse.ch) | 19 | `https://bazaar.abuse.ch/export/csv/recent/` |
| URLhaus (abuse.ch) | 15 | `https://urlhaus.abuse.ch/downloads/csv_recent/` |

**AbuseIPDB was not used.** Its blacklist/bulk endpoints require a
registered API key, which was not available in this environment. Its role
(community-reported abusive IPs) is covered here by Blocklist.de, which
publishes the same class of data (fail2ban-style abuse reports) as open,
unauthenticated text lists.

## Methodology / disclosed normalizations

No IOC value was altered in a way that changes what it identifies. The
following formatting-only transformations were applied and are disclosed
here for transparency:

1. **ThreatFox `ip:port` splitting.** ThreatFox reports C2 indicators as a
   combined `ip:port` string (e.g. `104.143.204.78:8443`). Since this
   dataset's `ioc_type=ip` field is schema-typed to hold a bare IP address,
   the port was stripped (`104.143.204.78`). The IP itself is unchanged.
2. **Date truncation.** Sources provide full UTC timestamps
   (`2026-09-29 13:05:08`); this dataset keeps only the date portion
   (`2026-09-29`) to match the `first_seen`/`last_seen` schema.
3. **Snapshot-only sources (Blocklist.de, OpenPhish).** These two sources
   publish a live list with no per-entry historical date. `first_seen` is
   set to this dataset's collection date (the date we actually observed
   the entry in the source's list); `last_seen` is `null` per the task's
   fallback rule, since the source provides no distinct second timestamp.
4. **Confidence defaults for sources with no native score.** ThreatFox
   publishes a genuine `confidence_level` (0-100) and it is used as-is.
   The other four sources don't score individual entries, so a fixed,
   disclosed default was applied per source instead of fabricating a
   precise-looking number:
   - URLhaus: 75
   - MalwareBazaar: 70
   - Blocklist.de: 65
   - OpenPhish: 80

   These defaults reflect each source's general curation model (URLhaus/
   MalwareBazaar are abuse.ch-verified submissions; Blocklist.de is
   unverified community fail2ban reports; OpenPhish is a curated
   commercial-grade feed) -- they are **not** a per-IOC reputation score
   from the source itself.
5. **Ransomware classification** uses a keyword match (see above) against
   each source's own malware-family/tag field -- never against the IOC
   value itself.

## Quality control performed

- **269 / 269 unique** -- zero duplicate `(ioc_type, ioc)` pairs in the
  final dataset (checked by construction with a global dedup set across
  all sources and categories).
- **31 duplicates removed** during dataset construction (mostly repeated
  ThreatFox C2 reports resolving to the same IP/domain across different
  report IDs).
- **0 entries rejected for invalid format** -- every `ip` validated via
  Python's `ipaddress` module, every `domain` against an RFC-1035-shaped
  hostname pattern, every `url` for a valid `http(s)://` scheme + host,
  every `hash` for a correctly-lengthed hex string (32/40/64 chars ->
  md5/sha1/sha256).
- Every record has a non-empty `source` and a `category` from the exact
  six allowed values.
- `iocs.csv` and `iocs.json` contain the same 269 records (both generated
  from one in-memory list, then serialized twice).
- Records are sorted by `category`, then `ioc`, in both files.

## Purpose and intended workflow

```
Threat Intelligence Feed
        |
IOC Dataset  (this dataset)
        |
IOC Normalization
        |
Wazuh Custom Rules
        |
Wazuh Manager
        |
Wazuh Dashboard
        |
IOC Detection Alert
```

See `wazuh_ioc_mapping.md` for how each category maps to a concrete Wazuh
detection rule against NIVRA's Android agent event schema.

**This dataset does not automatically block anything.** It is a
detection/intelligence dataset only -- matching an event against one of
these IOCs should produce a Wazuh alert for a human analyst to triage, not
trigger an automated block.

## Warning

> This dataset contains threat-intelligence indicators collected from
> public sources. An IOC may become inactive, be reassigned, or be
> incorrectly reported. The dataset is intended for cybersecurity
> research, SOC monitoring, and Wazuh laboratory testing. It should not be
> used as the sole basis for blocking or attributing activity.

Every record carries its own `source` and `first_seen`/`last_seen` dates
precisely so that an analyst can judge freshness for themselves -- an old
`first_seen` with no recent `last_seen` confirmation (`null`) is weaker
evidence than an IOC both first- and last-seen on the collection date.
