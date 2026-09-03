package com.nivra.agent.collectors

import android.app.admin.DevicePolicyManager
import android.app.admin.SecurityLog
import android.content.Context
import com.nivra.agent.dpc.NivraDeviceAdminReceiver
import com.nivra.agent.models.EventType
import com.nivra.agent.models.SecurityEvent
import com.nivra.agent.models.Severity
import com.nivra.agent.normalization.EventNormalizer
import com.nivra.agent.storage.MetricsRecorder
import com.nivra.agent.utils.CapabilityChecker
import com.nivra.agent.utils.Logger
import com.nivra.agent.models.CapabilityStatus

/**
 * Pulls SecurityLog entries via the Device Owner API. Per the capability-
 * detection requirement, this checks availability first, logs and reports
 * the limitation rather than silently doing nothing, and keeps working for
 * every other collector if this one is unavailable on a given build.
 */
class SecurityLogCollector(private val context: Context) {

    private val normalizer = EventNormalizer(context)
    private val metrics = MetricsRecorder(context)

    suspend fun collect(): List<SecurityEvent> {
        val capability = CapabilityChecker.securityLogCapability(context)
        if (capability.status != CapabilityStatus.AVAILABLE) {
            // Not counted as a collection attempt: an unavailable capability
            // is an expected, gracefully-handled state (see CapabilityChecker),
            // not a collection failure -- counting it as an "attempt" would
            // permanently drag down the collection-success-rate metric on any
            // device that simply isn't Device Owner / logging-enabled.
            Logger.w("SecurityLog unavailable: ${capability.reason}")
            metrics.recordCollectionUnavailable(EventType.SECURITY_LOG.name)
            return emptyList()
        }
        metrics.recordCollectionAttempt(EventType.SECURITY_LOG.name)

        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val admin = NivraDeviceAdminReceiver.componentName(context)

        val rawEvents: List<SecurityLog.SecurityEvent> = try {
            dpm.retrieveSecurityLogs(admin) ?: return emptyList()
        } catch (e: SecurityException) {
            Logger.e("retrieveSecurityLogs failed", e)
            return emptyList()
        }

        return rawEvents.mapNotNull { toSecurityEvent(it) }
    }

    private fun toSecurityEvent(event: SecurityLog.SecurityEvent): SecurityEvent? {
        val timestamp = java.time.Instant.ofEpochMilli(event.timeNanos / 1_000_000L)

        return when (event.tag) {
            SecurityLog.TAG_KEYGUARD_DISMISS_AUTH_ATTEMPT -> {
                @Suppress("UNCHECKED_CAST")
                val data = event.data as? Array<Any> ?: arrayOf()
                val success = (data.getOrNull(0) as? Int) == 1
                val method = data.getOrNull(1)?.toString()

                normalizer.normalize(
                    EventType.SECURITY_LOG,
                    severity = if (success) Severity.INFO else Severity.MEDIUM,
                    data = mapOf("subtype" to "failed_unlock", "success" to success, "method" to method),
                    timestamp = timestamp
                )
            }

            SecurityLog.TAG_ADB_SHELL_INTERACTIVE,
            SecurityLog.TAG_ADB_SHELL_CMD -> {
                normalizer.normalize(
                    EventType.ADMIN_ACTIVITY,
                    severity = Severity.HIGH,
                    data = mapOf("subtype" to "adb"),
                    timestamp = timestamp
                )
            }

            SecurityLog.TAG_APP_PROCESS_START -> {
                @Suppress("UNCHECKED_CAST")
                val data = event.data as? Array<Any> ?: arrayOf()
                normalizer.normalize(
                    EventType.SECURITY_LOG,
                    severity = Severity.LOW,
                    data = mapOf("subtype" to "process_start", "process" to data.getOrNull(0)?.toString()),
                    timestamp = timestamp
                )
            }

            else -> null // Outside the defined telemetry scope.
        }
    }
}
