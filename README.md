# NIVRA — Native Intelligence & Vulnerability Response Agent

A native Kotlin Android security telemetry agent running as a Device
Owner/DPC on a controlled Android Enterprise device. It collects only
supported security telemetry, normalizes it into a common event schema,
securely transmits events to a Wazuh-compatible ingestion path, and uses
custom Wazuh decoders/rules to generate centralized security alerts. It
ships with a native Android UI (Jetpack Compose, launchable from the App
Drawer) so a researcher can see agent/device/security/Wazuh status without
touching the Wazuh Dashboard.

**This is not**: an antivirus, an EDR, an MDM replacement, a surveillance
application, a root application, or a packet-capture tool. See "Explicitly
excluded data" below for the enforced technical constraints.

## Repository layout

```
NIVRA/
├── app/                                     Android Studio module (Kotlin)
│   └── src/main/kotlin/com/nivra/agent/
│       ├── NivraApplication.kt              Schedules the WorkManager heartbeat
│       ├── ui/                              Jetpack Compose screens (App Drawer-launchable)
│       │   ├── MainActivity.kt              Nav host + bottom navigation
│       │   ├── DashboardScreen.kt           Screen 1: overview + success metrics
│       │   ├── DeviceScreen.kt              Screen 2: device identity/patch
│       │   ├── ApplicationsScreen.kt        Screen 3: inventory + baseline badge
│       │   ├── SecurityScreen.kt            Screen 4: config status + capability honesty
│       │   ├── EventsScreen.kt              Screen 5: recent normalized event feed
│       │   ├── WazuhConnectionScreen.kt     Screen 6: transport status (no secrets shown)
│       │   ├── SettingsScreen.kt            Screen 7: server/heartbeat/log-level config
│       │   ├── AgentViewModel.kt            The only UI <-> AgentManager bridge
│       │   └── theme/                       Material3 theme
│       ├── agent/
│       │   ├── AgentManager.kt              Single coordination point; exposes StateFlow<AgentStatus>
│       │   ├── AgentService.kt              Foreground service driving the collection loops
│       │   ├── HeartbeatManager.kt          WorkManager CoroutineWorker (survives process death)
│       │   └── BootReceiver.kt              Reboot recovery
│       ├── collectors/
│       │   ├── DeviceCollector.kt
│       │   ├── ApplicationCollector.kt      Persisted baseline diff (survives reboot)
│       │   ├── SecurityConfigCollector.kt   Baseline-diffed drift detection
│       │   ├── SecurityLogCollector.kt      Capability-checked SecurityLog polling
│       │   └── NetworkCollector.kt          Event-driven (DPC callback), not polled
│       ├── dpc/
│       │   └── NivraDeviceAdminReceiver.kt  Device Owner entry point + log callbacks
│       ├── models/                          SecurityEvent (UUID/UTC/state), AgentStatus, etc.
│       ├── normalization/
│       │   └── EventNormalizer.kt           Attaches device context + data-minimization filter
│       ├── transport/
│       │   ├── WazuhTransport.kt            Ingestion-mechanism facade (see below)
│       │   ├── ApiClient.kt                 HTTPS + retry/backoff
│       │   └── TlsManager.kt                Platform CA trust, no accept-all shortcut
│       ├── storage/
│       │   ├── EventDatabase.kt             Room: queued events, known packages, metrics counters
│       │   ├── EventQueue.kt                PENDING -> SENDING -> SENT/FAILED lifecycle
│       │   ├── MetricsRecorder.kt           Backs the 4 success metrics
│       │   └── Preferences.kt               EncryptedSharedPreferences; no hardcoded secrets
│       ├── baseline/
│       │   ├── ApplicationBaseline.kt       Defines "unexpected application"
│       │   └── SecurityConfigBaseline.kt    Defines "configuration drift"
│       └── utils/
│           ├── DeviceIdentity.kt            Non-reversible device ID (SHA-256 of ANDROID_ID)
│           ├── CapabilityChecker.kt         Detects capability availability before use
│           ├── Logger.kt                    Leveled logging with sensitive-field redaction
│           └── Constants.kt
│   └── src/test/                            Pure-JVM unit tests (schema, baseline diff, filter)
│   └── src/androidTest/                     Instrumented tests (real Context/DPM)
├── wazuh-integration/
│   ├── decoders/nivra_decoder.xml           Parses the nested JSON schema
│   ├── rules/nivra_rules.xml                Rules for all 6 scenarios + offline watchdog hook
│   ├── receiver/nivra_receiver.py           Authenticated HTTPS -> JSON-Lines bridge
│   ├── watchdog/nivra_offline_watchdog.py   Closes Wazuh's presence-only alerting gap
│   ├── testing/run_scenarios.sh             Drives all 6 controlled test scenarios via adb
│   ├── testing/nivra_evaluate.py            Computes detection accuracy / false-positive rate
│   └── dashboards/nivra_dashboard_queries.md Sample OpenSearch/Wazuh Dashboard visualizations
└── provisioning/
    └── qr_provisioning_payload.json         Zero-touch/QR Device Owner enrollment payload
```

## The one architectural decision made explicit: Android -> Wazuh ingestion

The native `wazuh-agent` daemon can't run on Android without root, so this
project uses a **custom HTTPS ingestion endpoint**
(`wazuh-integration/receiver/nivra_receiver.py`) that bridges authenticated
JSON POSTs into a JSON-Lines file monitored by Wazuh's own `<localfile>`
log-collector module — a supported, documented Wazuh integration pattern.
Syslog-only transport was considered and rejected because it loses
request/response semantics (an HTTP 4xx on a malformed event, a clean
success/failure signal for the delivery-reliability metric). This decision
lives in code comments at the top of `WazuhTransport.kt` — validate it
against your actual Wazuh deployment before treating it as final.

## Event schema

Every event follows one schema (`models/SecurityEvent.kt`):

```json
{
  "schema_version": "1.0",
  "event_id": "1e2d3c4b-...",
  "timestamp": "2026-08-22T19:42:31Z",
  "device": {"device_id": "nivra-...", "android_version": "15", "security_patch": "2026-08-01"},
  "agent": {"name": "NIVRA Android Security Agent", "version": "0.2.0-prototype"},
  "event": {"type": "APPLICATION_INSTALL", "severity": "MEDIUM"},
  "data": {"package_name": "com.example.test", "approved": false}
}
```

`event_id` (UUID) lets Wazuh and the local queue distinguish a retried
delivery from a genuinely new event. Timestamps are always UTC/ISO-8601.
Every queued event carries a state: `PENDING -> SENDING -> SENT | FAILED`
(`storage/EventDatabase.kt`), which is what makes reliability testing and
the collection/delivery success metrics computable rather than asserted.

## Capability detection

`utils/CapabilityChecker.kt` checks whether SecurityLog, network logging,
and Device Owner status are actually available/authorized *before* a
collector relies on them, rather than assuming Android will always provide
them. Unavailable capabilities are logged and surfaced on the Security
screen as "Limited / Unavailable" with a reason, not silently omitted —
this is what "the implementation should not assume an API will provide
everything you want" means in code.

## Setting up the dev/test environment

1. **Android Studio**: open the `NIVRA/` root. It will offer to generate
   `gradle/wrapper/gradle-wrapper.jar` on first sync (this repo ships the
   wrapper properties/scripts but not the binary jar).
2. **Test device**: factory-reset an Android 14–16 device with Android
   Enterprise support, no Google account added yet.
3. **Provision as Device Owner**, either:
   - adb (dev/test): `adb install app-debug.apk && adb shell dpm set-device-owner com.nivra.agent/.dpc.NivraDeviceAdminReceiver`
   - QR/zero-touch (fleet): encode `provisioning/qr_provisioning_payload.json`
     into a QR code, tap the setup welcome screen 6 times, scan it.
4. **Wazuh Manager**: stand up Wazuh Manager + Indexer + Dashboard (Docker
   Compose, per the proposal's infra choice).
5. **Receiver**: generate a per-device token (`openssl rand -hex 32`), add
   its SHA-256 to `wazuh-integration/receiver/enrolled_devices.json` (copy
   from the `.example.json`), then run `nivra_receiver.py --cert ... --key ...`
   on/near the manager host. Enter the host/port/token in the app's
   Settings screen (or via the QR payload's admin extras bundle).
6. **Decoders/rules**: copy the two XML files into
   `/var/ossec/etc/decoders/` and `/var/ossec/etc/rules/`, restart
   `wazuh-manager`.
7. Add the `<localfile>` stanza (see `nivra_receiver.py` docstring) to
   `ossec.conf`.
8. **Offline watchdog**: `pip install opensearch-py`, configure the
   `NIVRA_INDEXER_*` environment variables, and cron
   `nivra_offline_watchdog.py` every 5–10 minutes.

## Testing and evaluation

```
wazuh-integration/testing/run_scenarios.sh scenario_log.jsonl path/to/test.apk
# ... exercise the device, then export Wazuh alerts for the same window ...
python3 wazuh-integration/testing/nivra_evaluate.py \
    --scenarios scenario_log.jsonl --alerts alerts_export.jsonl
```

This computes detection accuracy and false-positive rate against the
proposal's targets (≥90% and ≤10% respectively). Collection success rate
and delivery reliability are read directly from the device's own
persisted counters (visible on the Dashboard screen; backed by
`storage/MetricsRecorder.kt`), since they describe the device-to-receiver
leg rather than something visible from the Wazuh side.

Run unit tests: `./gradlew test` (schema serialization, baseline diff
logic, data-minimization filter — no Android runtime needed).
Run instrumented tests: `./gradlew connectedAndroidTest` (requires a
connected device/emulator; SecurityLog/network-logging-specific behavior
additionally requires Device Owner provisioning).

## Explicitly excluded data (enforced, not just documented)

`EventNormalizer` runs a data-minimization filter over every event's data
map and drops any field matching an excluded pattern (password, SMS/message
content, contacts, keystrokes, file/photo content, location, packet
payloads) even if a collector accidentally included one — see
`DataMinimizationFilterTest.kt`. The Android manifest requests no runtime
permissions for any of these categories in the first place. Network
telemetry is connection metadata only (host/IP/port/package), since that's
all Android's network-logging API exposes.

## Explicit non-goals

Per project scope: no rooting, no Magisk, no exploiting Android
vulnerabilities, no bypassing permissions, no reading messages/SMS/photos/
files, no keystroke capture, no full packet capture, no antivirus/EDR/MDM
feature creep, no hardcoded secrets, no disabling Android security
protections to make telemetry easier to collect.

## Known simplifications / next steps

- `nivra_receiver.py`'s enrolled-devices store is a flat JSON file —
  fine for a handful of prototype devices, replace with a real datastore
  for a larger fleet.
- The offline watchdog's OpenSearch query aggregation size (1000 devices)
  and lookback window (72h) are prototype defaults; tune per deployment.
- Rule 100131's suspicious-hostname pattern is a placeholder — replace
  with a real threat-intel feed during detection engineering.
- `gradle-wrapper.jar` (binary) isn't included; Android Studio generates it
  automatically on first project sync.
- TLS in `TlsManager` trusts the platform CA store plus an optional single
  pinned cert; a larger deployment may want full certificate pinning per
  environment rather than a single optional override.
