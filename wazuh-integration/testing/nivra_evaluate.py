#!/usr/bin/env python3
"""
NIVRA evaluation script.

Cross-references the scenario log produced by run_scenarios.sh against a
Wazuh alerts export (JSON Lines, e.g. from `/var/ossec/logs/alerts/alerts.json`
or a Wazuh Indexer export) to compute:

  - Detection accuracy: fraction of triggered scenarios that produced a
    matching alert within the expected time window.
  - False-positive rate: fraction of alerts in the same window that don't
    correspond to any triggered scenario (a rough proxy -- a full FP study
    would run over a longer baseline period with no injected scenarios).
  - Collection success rate / delivery reliability: read directly from the
    on-device Metrics screen (Settings) or the METRICS event type; this
    script only handles the detection-side metrics that need Wazuh's view.

Usage:
  python3 nivra_evaluate.py --scenarios scenario_log.jsonl --alerts alerts_export.jsonl

Expected scenario -> rule-id mapping is defined in SCENARIO_RULE_MAP below;
adjust if you changed rule IDs in nivra_rules.xml.
"""

import argparse
import json
from datetime import datetime, timedelta

SCENARIO_RULE_MAP = {
    "failed_unlock": [100101, 100102],
    "unexpected_app_install": [100110, 100111],
    "config_drift": [100120],
    "suspicious_network": [100130, 100131],
    "agent_offline": [100151],
    "adb_activity": [100140],
}

MATCH_WINDOW_MINUTES = 15


def parse_jsonl(path):
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def evaluate(scenarios, alerts):
    detected = 0
    results = []

    matched_alert_indices = set()

    for scenario in scenarios:
        name = scenario["scenario"]
        triggered_at = parse_time(scenario["triggered_at"])
        expected_rule_ids = SCENARIO_RULE_MAP.get(name, [])
        window_end = triggered_at + timedelta(minutes=MATCH_WINDOW_MINUTES)

        match = None
        for idx, alert in enumerate(alerts):
            rule_id = int(alert.get("rule", {}).get("id", -1))
            alert_time = parse_time(alert.get("timestamp", alert.get("@timestamp", "1970-01-01T00:00:00Z")))
            if rule_id in expected_rule_ids and triggered_at <= alert_time <= window_end:
                match = alert
                matched_alert_indices.add(idx)
                break

        detected_flag = match is not None
        if detected_flag:
            detected += 1

        results.append({
            "scenario": name,
            "triggered_at": scenario["triggered_at"],
            "detected": detected_flag,
            "matched_rule_id": match.get("rule", {}).get("id") if match else None,
        })

    total_scenarios = len(scenarios)
    detection_accuracy_pct = (detected / total_scenarios * 100) if total_scenarios else 0.0

    unmatched_alerts = [a for i, a in enumerate(alerts) if i not in matched_alert_indices]
    nivra_unmatched = [a for a in unmatched_alerts if str(a.get("rule", {}).get("id", "")).startswith("1001")]
    total_nivra_alerts = len([a for a in alerts if str(a.get("rule", {}).get("id", "")).startswith("1001")])
    false_positive_rate_pct = (len(nivra_unmatched) / total_nivra_alerts * 100) if total_nivra_alerts else 0.0

    return {
        "total_scenarios": total_scenarios,
        "detected": detected,
        "detection_accuracy_pct": round(detection_accuracy_pct, 1),
        "total_nivra_alerts": total_nivra_alerts,
        "unmatched_nivra_alerts": len(nivra_unmatched),
        "false_positive_rate_pct": round(false_positive_rate_pct, 1),
        "per_scenario": results,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenarios", required=True)
    parser.add_argument("--alerts", required=True)
    args = parser.parse_args()

    scenarios = parse_jsonl(args.scenarios)
    alerts = parse_jsonl(args.alerts)
    report = evaluate(scenarios, alerts)

    print(json.dumps(report, indent=2))
    print()
    print(f"Detection accuracy: {report['detection_accuracy_pct']}% "
          f"(target: >=90%, proposal success metric)")
    print(f"False-positive rate: {report['false_positive_rate_pct']}% "
          f"(target: <=10%, proposal success metric)")
