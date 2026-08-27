package com.nivra.agent.collectors

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.provider.Settings
import com.nivra.agent.baseline.SecurityConfigBaseline
import com.nivra.agent.baseline.SecurityConfigSnapshot
import com.nivra.agent.dpc.NivraDeviceAdminReceiver
import com.nivra.agent.models.EventType
import com.nivra.agent.models.SecurityEvent
import com.nivra.agent.models.Severity
import com.nivra.agent.normalization.EventNormalizer
import com.nivra.agent.storage.MetricsRecorder

class SecurityConfigCollector(private val context: Context) {

    private val normalizer = EventNormalizer(context)
    private val metrics = MetricsRecorder(context)

    fun snapshot(): SecurityConfigSnapshot {
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val admin = NivraDeviceAdminReceiver.componentName(context)
        val resolver = context.contentResolver

        val adbEnabled = Settings.Global.getInt(resolver, Settings.Global.ADB_ENABLED, 0) == 1
        val devOptionsEnabled = Settings.Global.getInt(
            resolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0
        ) == 1
        val unknownSourcesEnabled = try {
            Settings.Secure.getInt(resolver, Settings.Secure.INSTALL_NON_MARKET_APPS, 0) == 1
        } catch (e: Settings.SettingNotFoundException) {
            false
        }

        val securityLoggingEnabled = try {
            dpm.isSecurityLoggingEnabled(admin)
        } catch (e: SecurityException) {
            false
        }
        val networkLoggingEnabled = try {
            dpm.isNetworkLoggingEnabled(admin)
        } catch (e: SecurityException) {
            false
        }

        return SecurityConfigSnapshot(
            adbEnabled = adbEnabled,
            developerOptionsEnabled = devOptionsEnabled,
            unknownSourcesEnabled = unknownSourcesEnabled,
            securityLoggingEnabled = securityLoggingEnabled,
            networkLoggingEnabled = networkLoggingEnabled
        )
    }

    /** Emits a SECURITY_CONFIGURATION event only when it differs from the baseline. */
    suspend fun collectIfDrifted(): SecurityEvent? {
        metrics.recordCollectionAttempt(EventType.SECURITY_CONFIGURATION.name)
        val current = snapshot()
        val drifted = SecurityConfigBaseline.diff(current)
        if (drifted.isEmpty()) return null

        val data = mapOf(
            "adb_enabled" to current.adbEnabled,
            "developer_options_enabled" to current.developerOptionsEnabled,
            "unknown_sources_enabled" to current.unknownSourcesEnabled,
            "security_logging_enabled" to current.securityLoggingEnabled,
            "network_logging_enabled" to current.networkLoggingEnabled,
            "drifted_fields" to drifted
        )

        return normalizer.normalize(EventType.SECURITY_CONFIGURATION, Severity.MEDIUM, data)
    }

    /** Periodic full snapshot regardless of drift, for the Security screen and audit trail. */
    suspend fun collectSnapshotEvent(): SecurityEvent {
        val current = snapshot()
        val drifted = SecurityConfigBaseline.diff(current)
        val data = mapOf(
            "adb_enabled" to current.adbEnabled,
            "developer_options_enabled" to current.developerOptionsEnabled,
            "unknown_sources_enabled" to current.unknownSourcesEnabled,
            "security_logging_enabled" to current.securityLoggingEnabled,
            "network_logging_enabled" to current.networkLoggingEnabled,
            "drifted_fields" to drifted
        )
        val severity = if (drifted.isEmpty()) Severity.INFO else Severity.MEDIUM
        return normalizer.normalize(EventType.SECURITY_CONFIGURATION, severity, data)
    }
}
