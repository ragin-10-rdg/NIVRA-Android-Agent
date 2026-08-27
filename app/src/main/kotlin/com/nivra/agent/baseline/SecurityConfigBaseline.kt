package com.nivra.agent.baseline

/**
 * Expected ("secure") state for the configuration fields NIVRA monitors.
 * SecurityConfigCollector compares its snapshot against this to decide
 * whether a SECURITY_CONFIGURATION event represents drift, per the spec's
 * "expected state vs current state -> changed?" requirement.
 */
data class SecurityConfigSnapshot(
    val adbEnabled: Boolean,
    val developerOptionsEnabled: Boolean,
    val unknownSourcesEnabled: Boolean,
    val securityLoggingEnabled: Boolean,
    val networkLoggingEnabled: Boolean
)

object SecurityConfigBaseline {

    /** The expected, secure configuration for a managed NIVRA device. */
    val expected = SecurityConfigSnapshot(
        adbEnabled = false,
        developerOptionsEnabled = false,
        unknownSourcesEnabled = false,
        securityLoggingEnabled = true,
        networkLoggingEnabled = true
    )

    /** Returns the list of field names that differ from the expected baseline. */
    fun diff(current: SecurityConfigSnapshot): List<String> {
        val drifted = mutableListOf<String>()
        if (current.adbEnabled != expected.adbEnabled) drifted += "adb_enabled"
        if (current.developerOptionsEnabled != expected.developerOptionsEnabled) drifted += "developer_options_enabled"
        if (current.unknownSourcesEnabled != expected.unknownSourcesEnabled) drifted += "unknown_sources_enabled"
        if (current.securityLoggingEnabled != expected.securityLoggingEnabled) drifted += "security_logging_enabled"
        if (current.networkLoggingEnabled != expected.networkLoggingEnabled) drifted += "network_logging_enabled"
        return drifted
    }
}
