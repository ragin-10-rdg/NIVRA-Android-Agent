#!/usr/bin/env python3
"""
NIVRA offline watchdog.

Wazuh's rule engine alerts on event *presence*, not absence -- there's no
built-in "alert if X doesn't happen" primitive. This script closes that gap
for the agent-offline use case: run it on a schedule (cron, every 5-10
minutes) on the Wazuh Manager/Indexer host.

For each device that has ever sent a heartbeat, it queries the Wazuh
Indexer (OpenSearch) for the most recent HEARTBEAT event. If none exists
within OFFLINE_THRESHOLD_SECONDS, it writes a synthetic AGENT_OFFLINE event
into the same JSON Lines file the receiver writes to -- so it flows through
the *same* decoder/rule pipeline as every other NIVRA event (rule 100151
in nivra_rules.xml), rather than needing a separate alerting mechanism.

Setup:
  pip install opensearch-py
  crontab -e
    */5 * * * * /usr/bin/python3 /opt/nivra/nivra_offline_watchdog.py

Configure OPENSEARCH_* below (or via environment variables) for your
Wazuh Indexer deployment.
"""

import json
import os
from datetime import datetime, timezone

try:
    from opensearchpy import OpenSearch
except ImportError:
    OpenSearch = None  # Script still runs in --dry-run/test mode without the dependency.

OPENSEARCH_HOST = os.environ.get("NIVRA_INDEXER_HOST", "localhost")
OPENSEARCH_PORT = int(os.environ.get("NIVRA_INDEXER_PORT", "9200"))
OPENSEARCH_USER = os.environ.get("NIVRA_INDEXER_USER", "admin")
OPENSEARCH_PASS = os.environ.get("NIVRA_INDEXER_PASS", "")
ALERTS_INDEX_PATTERN = os.environ.get("NIVRA_ALERTS_INDEX", "wazuh-alerts-*")

OFFLINE_THRESHOLD_SECONDS = int(os.environ.get("NIVRA_OFFLINE_THRESHOLD_SECONDS", str(30 * 60)))  # 30 min default
LOOKBACK_HOURS = 72  # how far back to search for "devices we know about"

OUTPUT_LOG_FILE = "/var/log/nivra/nivra-events.json"
STATE_FILE = "/var/log/nivra/watchdog_state.json"  # tracks devices already marked offline, to avoid alert spam


def get_client():
    if OpenSearch is None:
        raise RuntimeError("opensearch-py not installed; run `pip install opensearch-py`")
    return OpenSearch(
        hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
        http_auth=(OPENSEARCH_USER, OPENSEARCH_PASS),
        use_ssl=True,
        verify_certs=False,  # set True + provide ca_certs in a real deployment
    )


def known_devices(client) -> set:
    """Devices that have sent at least one event in the lookback window."""
    query = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": f"now-{LOOKBACK_HOURS}h"}}},
        "aggs": {"devices": {"terms": {"field": "data.device.device_id.keyword", "size": 1000}}},
    }
    resp = client.search(index=ALERTS_INDEX_PATTERN, body=query)
    buckets = resp.get("aggregations", {}).get("devices", {}).get("buckets", [])
    return {b["key"] for b in buckets}


def last_heartbeat_time(client, device_id: str):
    query = {
        "size": 1,
        "sort": [{"@timestamp": "desc"}],
        "query": {
            "bool": {
                "must": [
                    {"term": {"data.event.type.keyword": "HEARTBEAT"}},
                    {"term": {"data.device.device_id.keyword": device_id}},
                ]
            }
        },
    }
    resp = client.search(index=ALERTS_INDEX_PATTERN, body=query)
    hits = resp.get("hits", {}).get("hits", [])
    if not hits:
        return None
    return datetime.fromisoformat(hits[0]["_source"]["@timestamp"].replace("Z", "+00:00"))


def load_state() -> dict:
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_state(state: dict):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f)


def write_offline_event(device_id: str):
    event = {
        "schema_version": "1.0",
        "event_id": f"watchdog-{device_id}-{int(datetime.now(timezone.utc).timestamp())}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "device": {"device_id": device_id, "android_version": "unknown", "security_patch": "unknown"},
        "agent": {"name": "NIVRA Offline Watchdog", "version": "0.2.0-prototype"},
        "event": {"type": "AGENT_OFFLINE", "severity": "HIGH"},
        "data": {"threshold_seconds": OFFLINE_THRESHOLD_SECONDS},
    }
    os.makedirs(os.path.dirname(OUTPUT_LOG_FILE), exist_ok=True)
    with open(OUTPUT_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def main():
    client = get_client()
    state = load_state()
    now = datetime.now(timezone.utc)

    for device_id in known_devices(client):
        last_seen = last_heartbeat_time(client, device_id)
        seconds_since = (now - last_seen).total_seconds() if last_seen else float("inf")

        if seconds_since > OFFLINE_THRESHOLD_SECONDS:
            if not state.get(device_id, {}).get("offline_alert_sent"):
                write_offline_event(device_id)
                state[device_id] = {"offline_alert_sent": True, "last_alert_at": now.isoformat()}
                print(f"[watchdog] {device_id} offline for {int(seconds_since)}s -- alert written")
        else:
            if state.get(device_id, {}).get("offline_alert_sent"):
                print(f"[watchdog] {device_id} back online")
            state[device_id] = {"offline_alert_sent": False}

    save_state(state)


if __name__ == "__main__":
    main()
