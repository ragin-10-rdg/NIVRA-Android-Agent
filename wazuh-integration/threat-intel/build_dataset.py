#!/usr/bin/env python3
"""Build the NIVRA Wazuh IOC threat-intel dataset from real abuse.ch /
blocklist.de / OpenPhish feed exports already downloaded into this
directory. No IOC values are invented -- every value here is copied
verbatim (aside from documented, disclosed normalizations) from the raw
feed files.
"""
import csv
import ipaddress
import json
import re
from urllib.parse import urlparse

RANSOM_PAT = re.compile(
    r"(ransom|lockbit|conti|revil|sodinokibi|blackcat|alphv|hive|akira|royal|"
    r"clop|cl0p|ryuk|maze|netwalker|darkside|babuk|avaddon|phobos|makop|"
    r"medusa|black ?basta|rhysida|8base|lockergoga|wannacry|wannacryptor|"
    r"notpetya|gandcrab|dharma|ragnar|nefilim|egregor|snatch|mespinoza|pysa|"
    r"qilin|blacksuit|cactus|hunters international)",
    re.IGNORECASE,
)

COLLECTION_DATE = "2026-09-29"  # date these feeds were fetched, UTC

# provenance-transparent default confidence for sources with no native score
DEFAULT_CONF = {
    "URLhaus": 75,
    "MalwareBazaar": 70,
    "Blocklist.de": 65,
    "OpenPhish": 80,
}

seen_iocs = set()
records = []  # each: dict without ioc_id yet


def dt_date(s):
    if not s:
        return None
    return s.split(" ")[0].split("T")[0]


def valid_ip(v):
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def valid_domain(v):
    return bool(DOMAIN_RE.match(v))


def valid_url(v):
    try:
        p = urlparse(v)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False


HASH_RE = {32: "md5", 40: "sha1", 64: "sha256"}


def valid_hash(v):
    if not re.fullmatch(r"[A-Fa-f0-9]+", v):
        return False
    return len(v) in HASH_RE


def add(ioc_type, ioc, category, threat, malware_family, confidence, source,
        first_seen, last_seen):
    ioc = ioc.strip()
    if not ioc:
        return "invalid"
    if ioc_type == "ip" and not valid_ip(ioc):
        return "invalid"
    if ioc_type == "domain" and not valid_domain(ioc):
        return "invalid"
    if ioc_type == "url" and not valid_url(ioc):
        return "invalid"
    if ioc_type == "hash" and not valid_hash(ioc):
        return "invalid"
    key = (ioc_type, ioc.lower())
    if key in seen_iocs:
        return "dup"
    seen_iocs.add(key)
    records.append({
        "ioc_type": ioc_type,
        "ioc": ioc,
        "category": category,
        "threat": threat,
        "malware_family": malware_family or "Unknown",
        "confidence": int(confidence),
        "source": source,
        "first_seen": first_seen,
        "last_seen": last_seen if last_seen else None,
        "enabled": True,
    })
    return "ok"


dup_count = 0
invalid_count = 0


def counted_add(*a, **kw):
    global dup_count, invalid_count
    result = add(*a, **kw)
    if result == "dup":
        dup_count += 1
    elif result == "invalid":
        invalid_count += 1
    return result == "ok"


# ---------------------------------------------------------------- ThreatFox
tf = json.load(open("threatfox_recent.json", encoding="utf-8"))
tf_entries = [v[0] for v in tf.values()]

tf_ransom, tf_c2, tf_malware = [], [], []
for e in tf_entries:
    name_blob = " ".join(filter(None, [e.get("malware_printable"), e.get("malware"), e.get("tags") or ""]))
    is_ransom = bool(RANSOM_PAT.search(name_blob))
    bucket = tf_ransom if is_ransom else (tf_c2 if e["threat_type"] == "botnet_cc" else tf_malware)
    if e["threat_type"] in ("botnet_cc", "payload", "payload_delivery"):
        bucket.append(e)

# sort by confidence desc then recency for a reasonable/diverse top slice
for lst in (tf_ransom, tf_c2, tf_malware):
    lst.sort(key=lambda e: (-e.get("confidence_level", 0), e.get("first_seen_utc", "")), reverse=False)


def tf_to_ioc(e):
    t = e["ioc_type"]
    val = e["ioc_value"]
    if t == "ip:port":
        return "ip", val.rsplit(":", 1)[0]
    if t in ("md5_hash", "sha1_hash", "sha256_hash"):
        return "hash", val
    return t, val  # domain / url as-is


# ransomware bucket first (scarce -- give it first claim)
for e in tf_ransom:
    ioc_type, val = tf_to_ioc(e)
    threat = "command_and_control" if e["threat_type"] == "botnet_cc" else "ransomware_infrastructure"
    counted_add(ioc_type, val, "ransomware", threat, e.get("malware_printable"),
                e.get("confidence_level", 50), "ThreatFox",
                dt_date(e.get("first_seen_utc")), dt_date(e.get("last_seen_utc")))

TARGET = 50
c2_added = 0
for e in tf_c2:
    if c2_added >= TARGET:
        break
    ioc_type, val = tf_to_ioc(e)
    if counted_add(ioc_type, val, "c2", "command_and_control", e.get("malware_printable"),
                    e.get("confidence_level", 50), "ThreatFox",
                    dt_date(e.get("first_seen_utc")), dt_date(e.get("last_seen_utc"))):
        c2_added += 1

malware_added = 0
for e in tf_malware:
    if malware_added >= 20:  # leave room for URLhaus + MalwareBazaar diversity
        break
    ioc_type, val = tf_to_ioc(e)
    if counted_add(ioc_type, val, "malware", "payload_delivery", e.get("malware_printable"),
                   e.get("confidence_level", 50), "ThreatFox",
                   dt_date(e.get("first_seen_utc")), dt_date(e.get("last_seen_utc"))):
        malware_added += 1

# ---------------------------------------------------------------- URLhaus
with open("urlhaus_recent.csv", encoding="utf-8") as f:
    lines = [l for l in f if not l.startswith("#")]
uh_rows = list(csv.reader(lines))
uh_added = 0
for row in uh_rows:
    if uh_added >= 15:
        break
    if len(row) < 9:
        continue
    _id, dateadded, url, status, last_online, threat, tags, link, reporter = row[:9]
    is_ransom = bool(RANSOM_PAT.search(tags or ""))
    family = "Unknown"
    if tags and tags != "None":
        # first tag token that looks like a family name, else Unknown
        family = tags.split(",")[0].strip() or "Unknown"
    cat = "ransomware" if is_ransom else "malware"
    before = len(records)
    counted_add("url", url, cat, "payload_delivery", family,
                DEFAULT_CONF["URLhaus"], "URLhaus", dt_date(dateadded), dt_date(last_online))
    if len(records) > before and not is_ransom:
        uh_added += 1

# ---------------------------------------------------------------- MalwareBazaar
with open("malwarebazaar_recent.csv", encoding="utf-8") as f:
    lines = [l for l in f if not l.startswith("#")]
mb_rows = list(csv.reader(lines, skipinitialspace=True))
mb_added = 0
for row in mb_rows:
    if len(row) < 9:
        continue
    first_seen, sha256, md5, sha1, reporter, fname, ftype, mime, signature = row[:9]
    signature = signature.strip()
    if signature == "n/a" or not signature:
        signature = "Unknown"
    is_ransom = bool(RANSOM_PAT.search(signature))
    cat = "ransomware" if is_ransom else "malware"
    if not is_ransom and mb_added >= 15:
        continue
    before = len(records)
    counted_add("hash", sha256, cat, "payload_delivery" if cat == "malware" else "ransomware_infrastructure",
                signature, DEFAULT_CONF["MalwareBazaar"], "MalwareBazaar", dt_date(first_seen), None)
    if len(records) > before and not is_ransom:
        mb_added += 1

# ---------------------------------------------------------------- OpenPhish
with open("openphish_feed.txt", encoding="utf-8") as f:
    ph_urls = [l.strip() for l in f if l.strip()]
ph_added = 0
for url in ph_urls:
    if ph_added >= 50:
        break
    before = len(records)
    counted_add("url", url, "phishing", "phishing", "Unknown",
                DEFAULT_CONF["OpenPhish"], "OpenPhish", COLLECTION_DATE, None)
    if len(records) > before:
        ph_added += 1

# ---------------------------------------------------------------- Blocklist.de
def load_ips(path):
    with open(path, encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip()]

ssh_ips = load_ips("blocklist_ssh.txt")
bfl_ips = load_ips("blocklist_bruteforcelogin.txt")
apache_ips = load_ips("blocklist_apache.txt")
bots_ips = load_ips("blocklist_bots.txt")

def add_ip_batch(ips, n, category, threat):
    added = 0
    for ip in ips:
        if added >= n:
            break
        before = len(records)
        counted_add("ip", ip, category, threat, "Unknown",
                    DEFAULT_CONF["Blocklist.de"], "Blocklist.de", COLLECTION_DATE, None)
        if len(records) > before:
            added += 1
    return added

add_ip_batch(ssh_ips, 30, "brute-force", "ssh_bruteforce")
add_ip_batch(bfl_ips, 20, "brute-force", "login_bruteforce")
add_ip_batch(apache_ips, 25, "scanning", "web_scanning")
add_ip_batch(bots_ips, 25, "scanning", "web_scanning")

# ---------------------------------------------------------------- finalize
records.sort(key=lambda r: (r["category"], r["ioc"]))
for i, r in enumerate(records, start=1):
    r["ioc_id"] = f"IOC-{i:04d}"

# reorder keys per schema
FIELDS = ["ioc_id", "ioc_type", "ioc", "category", "threat", "malware_family",
          "confidence", "source", "first_seen", "last_seen", "enabled"]
final = [{k: r[k] for k in FIELDS} for r in records]

with open("iocs.json", "w", encoding="utf-8") as f:
    json.dump(final, f, indent=2)

with open("iocs.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(FIELDS)
    for r in final:
        row = [r[k] for k in FIELDS]
        row = ["" if v is None else ("true" if v is True else ("false" if v is False else v)) for v in row]
        w.writerow(row)

from collections import Counter
cat_counts = Counter(r["category"] for r in final)
src_counts = Counter(r["source"] for r in final)

print("TOTAL", len(final))
print("BY_CATEGORY", dict(cat_counts))
print("BY_SOURCE", dict(src_counts))
print("DUPLICATES_REMOVED", dup_count)
print("INVALID_REJECTED", invalid_count)
