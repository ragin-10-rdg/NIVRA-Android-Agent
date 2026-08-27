package com.nivra.agent.models

enum class EventType {
    DEVICE_INFO,
    APPLICATION_INVENTORY,
    APPLICATION_INSTALL,
    APPLICATION_UNINSTALL,
    SECURITY_CONFIGURATION,
    SECURITY_LOG,
    NETWORK_EVENT,
    HEARTBEAT,
    PATCH_STATUS,
    ADMIN_ACTIVITY,
    METRICS,
    // Emitted server-side by the watchdog (wazuh-integration/watchdog/), never
    // by the on-device agent.
    AGENT_OFFLINE
}

enum class Severity { INFO, LOW, MEDIUM, HIGH }
