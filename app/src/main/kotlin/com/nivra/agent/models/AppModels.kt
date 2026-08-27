package com.nivra.agent.models

/** Snapshot of device identity/state, used by both collectors and the UI Device screen. */
data class DeviceInfo(
    val deviceId: String,
    val manufacturer: String,
    val model: String,
    val androidRelease: String,
    val sdkInt: Int,
    val securityPatch: String,
    val encryptionStatus: String,
    val isDeviceOwner: Boolean
)

/** Application inventory entry, used by both collectors and the UI Applications screen. */
data class ApplicationInfo(
    val packageName: String,
    val versionName: String?,
    val isSystemApp: Boolean,
    val installerPackage: String?,
    val firstInstallTime: Long,
    val lastUpdateTime: Long,
    val approved: Boolean
)

/** Availability of a given telemetry capability on this device/Android version. */
enum class CapabilityStatus { AVAILABLE, UNAVAILABLE, UNKNOWN }

data class CapabilityInfo(
    val name: String,
    val status: CapabilityStatus,
    val reason: String? = null
)

/** Connection state to the Wazuh-side receiver, surfaced on the Wazuh Connection screen. */
enum class ConnectionStatus { CONNECTED, DEGRADED, DISCONNECTED, UNKNOWN }

/**
 * Aggregate, observable agent status. AgentManager exposes this as a
 * StateFlow; every UI screen reads from it rather than talking to
 * collectors/transport directly (UI is a view into the agent, not the agent).
 */
data class AgentStatus(
    val isDeviceOwner: Boolean = false,
    val isRunning: Boolean = false,
    val agentVersion: String = SecurityEvent.AGENT_VERSION,
    val device: DeviceInfo? = null,
    val capabilities: List<CapabilityInfo> = emptyList(),
    val connectionStatus: ConnectionStatus = ConnectionStatus.UNKNOWN,
    val wazuhServer: String = "",
    val eventsCollected: Long = 0,
    val eventsSent: Long = 0,
    val eventsPending: Long = 0,
    val eventsFailed: Long = 0,
    val lastHeartbeatEpochMs: Long? = null,
    val lastSuccessfulDeliveryEpochMs: Long? = null,
    val recentEvents: List<SecurityEvent> = emptyList(),
    val applications: List<ApplicationInfo> = emptyList(),
    val securityEventCount24h: Long = 0,
    val collectionSuccessRatePct: Double = 100.0,
    val deliveryReliabilityPct: Double = 100.0
)
