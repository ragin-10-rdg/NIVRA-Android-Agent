package com.nivra.agent.collectors

import android.app.admin.ConnectEvent
import android.app.admin.DevicePolicyManager
import android.app.admin.DnsEvent
import android.app.admin.NetworkEvent
import android.content.Context
import com.nivra.agent.dpc.NivraDeviceAdminReceiver
import com.nivra.agent.models.CapabilityStatus
import com.nivra.agent.models.EventType
import com.nivra.agent.models.SecurityEvent
import com.nivra.agent.models.Severity
import com.nivra.agent.normalization.EventNormalizer
import com.nivra.agent.storage.MetricsRecorder
import com.nivra.agent.utils.CapabilityChecker
import com.nivra.agent.utils.Logger
import java.time.Instant

/**
 * Retrieves an Android Enterprise network-logging batch (DNS + TCP connect
 * metadata only -- never packet payloads, which this API doesn't expose in
 * the first place). Called from NivraDeviceAdminReceiver.onNetworkLogsAvailable
 * with the batchToken the platform provides; this class does not poll.
 */
class NetworkCollector(private val context: Context) {

    private val normalizer = EventNormalizer(context)
    private val metrics = MetricsRecorder(context)

    suspend fun collectBatch(batchToken: Long): List<SecurityEvent> {
        metrics.recordCollectionAttempt(EventType.NETWORK_EVENT.name)
        val capability = CapabilityChecker.networkLoggingCapability(context)
        if (capability.status != CapabilityStatus.AVAILABLE) {
            Logger.w("Network logging unavailable: ${capability.reason}")
            metrics.recordCollectionUnavailable(EventType.NETWORK_EVENT.name)
            return emptyList()
        }

        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val admin = NivraDeviceAdminReceiver.componentName(context)

        val events: List<NetworkEvent> = try {
            dpm.retrieveNetworkLogs(admin, batchToken) ?: return emptyList()
        } catch (e: SecurityException) {
            Logger.e("retrieveNetworkLogs failed", e)
            return emptyList()
        }

        return events.map { event ->
            val data: Map<String, Any?> = when (event) {
                is DnsEvent -> mapOf(
                    "type" to "dns",
                    "hostname" to event.hostname,
                    "package_name" to event.packageName,
                    "ip_addresses" to event.inetAddresses.map { it.hostAddress }
                )
                is ConnectEvent -> mapOf(
                    "type" to "connect",
                    "ip_address" to event.inetAddress.hostAddress,
                    "port" to event.port,
                    "package_name" to event.packageName
                )
                else -> mapOf("type" to "unknown")
            }

            normalizer.normalize(
                EventType.NETWORK_EVENT,
                severity = Severity.INFO, // Escalated server-side by Wazuh rules
                                           // for suspicious destinations.
                data = data,
                timestamp = Instant.ofEpochMilli(event.timestamp)
            )
        }
    }
}
