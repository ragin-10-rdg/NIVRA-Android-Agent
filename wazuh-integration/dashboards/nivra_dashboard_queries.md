# NIVRA Wazuh Dashboard — sample visualizations

Import these as OpenSearch Dashboards (Wazuh Dashboard) saved searches /
visualizations against the `wazuh-alerts-*` index pattern. Field names
assume the nested JSON schema is flattened by JSON_Decoder as
`data.device.device_id`, `data.event.type`, `data.event.severity`, etc.

## 1. Alerts by device (table)
Aggregation: Terms on `data.device.device_id.keyword`, metric: Count.

## 2. Events by type over time (line chart)
X-axis: Date histogram on `@timestamp`.
Split series: Terms on `data.event.type.keyword`.

## 3. Severity distribution (pie chart)
Aggregation: Terms on `data.event.severity.keyword`.

## 4. Application inventory drift (data table)
Filter: `data.event.type: "APPLICATION_INSTALL" AND data.data.approved: false`
Columns: `data.device.device_id`, `data.data.package_name`, `@timestamp`.

## 5. Agent-offline status (metric + table)
Filter: `data.event.type: "AGENT_OFFLINE"`
Shows any device the watchdog (wazuh-integration/watchdog/) has flagged.

## 6. Security-configuration drift (data table)
Filter: `data.event.type: "SECURITY_CONFIGURATION" AND data.event.severity: "MEDIUM"`
Columns: `data.device.device_id`, `data.data.drifted_fields`, `@timestamp`.

## 7. Failed unlock attempts (line chart, brute-force detection)
Filter: `rule.id: (100101 OR 100102)`
X-axis: Date histogram, split by `data.device.device_id.keyword`.

## Success-metric queries (for the evaluation writeup)

**Detection accuracy / false-positive rate**: computed by
`wazuh-integration/testing/nivra_evaluate.py` against a scenario log +
an alerts export from this same index pattern (Stack Management -> Saved
Objects -> Export, or the `_search` API against `wazuh-alerts-*`).

**Collection success rate / delivery reliability**: read directly from the
device's own persisted counters (Settings screen shows a summary; the raw
counters live in the on-device `metrics_counters` Room table) since these
describe the device-to-receiver leg, not something visible from the
Wazuh side alone.
