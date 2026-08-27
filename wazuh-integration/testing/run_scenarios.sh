#!/usr/bin/env bash
# NIVRA scenario test harness.
#
# Drives each of the six controlled test scenarios from the proposal's
# Testing and Evaluation section against a connected, provisioned test
# device, logging what was done and when so nivra_evaluate.py can later
# cross-reference against the Wazuh alerts export and compute detection
# accuracy / false-positive rate.
#
# Usage: ./run_scenarios.sh /path/to/scenario_log.jsonl
# Requires: adb connected to exactly one provisioned Device Owner test device.

set -euo pipefail
LOG_FILE="${1:-scenario_log.jsonl}"
UNEXPECTED_APK="${2:-}"  # path to a harmless test APK for scenario 2

log_event() {
  local scenario="$1"
  local description="$2"
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "{\"scenario\":\"$scenario\",\"triggered_at\":\"$ts\",\"description\":\"$description\"}" >> "$LOG_FILE"
  echo "[$ts] $scenario: $description"
}

echo "NIVRA scenario harness -- logging to $LOG_FILE"
echo

# Scenario 1: repeated failed unlock attempts
echo "--- Scenario 1: Failed unlock attempts ---"
adb shell input keyevent KEYCODE_WAKEUP
for i in 1 2 3 4 5; do
  adb shell input text "0000"
  adb shell input keyevent KEYCODE_ENTER
  sleep 1
done
log_event "failed_unlock" "Sent 5 incorrect PIN attempts"
echo

# Scenario 2: unexpected application installation
echo "--- Scenario 2: Unexpected application installation ---"
if [[ -n "$UNEXPECTED_APK" ]]; then
  adb install -r "$UNEXPECTED_APK"
  log_event "unexpected_app_install" "Installed $UNEXPECTED_APK (not on approved baseline)"
else
  echo "Skipped: no APK path provided as \$2."
fi
echo

# Scenario 3: security-configuration drift
echo "--- Scenario 3: Security-configuration drift (enable ADB debugging setting) ---"
adb shell settings put global development_settings_enabled 1
log_event "config_drift" "Enabled developer options via settings put global"
echo

# Scenario 4: suspicious network activity
echo "--- Scenario 4: Suspicious network activity ---"
adb shell am start -a android.intent.action.VIEW -d "http://example-suspicious-test.tk" || true
log_event "suspicious_network" "Triggered a request to a .tk test domain via VIEW intent"
echo

# Scenario 5: agent-offline detection
echo "--- Scenario 5: Agent-offline detection ---"
echo "Manual step: disable Wi-Fi/mobile data on the device now, wait past"
echo "NIVRA_OFFLINE_THRESHOLD_SECONDS, then re-enable connectivity."
log_event "agent_offline" "Manual connectivity interruption -- see harness output for timing"
echo

# Scenario 6: ADB shell activity
echo "--- Scenario 6: ADB administrative activity ---"
adb shell echo "nivra-test-adb-activity"
log_event "adb_activity" "Executed an interactive adb shell command"
echo

# Revert scenario 3's change so the device returns to baseline.
adb shell settings put global development_settings_enabled 0

echo "Done. Scenario timestamps written to $LOG_FILE."
echo "Next: export Wazuh alerts for this window and run nivra_evaluate.py."
