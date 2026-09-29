#!/usr/bin/env python3
"""Generate Wazuh CDB list files from ../threat-intel/iocs.csv for the
categories/types that map to NIVRA's actual NETWORK_EVENT telemetry
(outbound ip/hostname). Run from this directory (wazuh-integration/lists/).
Format: one `key:` per line (empty value -- membership-only lookup).

After regenerating, re-sync these six files to
E:\\NIVRA-Wazuh\\wazuh-docker\\single-node\\nivra-receiver\\wazuh-ruleset\\lists\\
and recreate the wazuh.manager container (`docker compose up -d
wazuh.manager` -- a plain `restart` does not re-attach bind mounts)."""
import csv
from urllib.parse import urlparse

OUT_DIR = "."
IOCS_CSV = "../threat-intel/iocs.csv"

rows = list(csv.DictReader(open(IOCS_CSV, encoding="utf-8")))

def write_list(name, values):
    values = sorted(set(values))
    with open(f"{OUT_DIR}/{name}", "w", newline="\n", encoding="utf-8") as f:
        for v in values:
            f.write(f"{v}:\n")
    print(name, len(values))

write_list("nivra_c2_ips", [r["ioc"] for r in rows if r["category"] == "c2" and r["ioc_type"] == "ip"])
write_list("nivra_c2_domains", [r["ioc"] for r in rows if r["category"] == "c2" and r["ioc_type"] == "domain"])
write_list("nivra_ransomware_ips", [r["ioc"] for r in rows if r["category"] == "ransomware" and r["ioc_type"] == "ip"])
write_list("nivra_ransomware_domains", [r["ioc"] for r in rows if r["category"] == "ransomware" and r["ioc_type"] == "domain"])
write_list("nivra_malware_domains", [r["ioc"] for r in rows if r["category"] == "malware" and r["ioc_type"] == "domain"])

phishing_domains = []
for r in rows:
    if r["category"] == "phishing" and r["ioc_type"] == "url":
        host = urlparse(r["ioc"]).netloc
        if host:
            phishing_domains.append(host)
write_list("nivra_phishing_domains", phishing_domains)
