package com.nivra.agent.normalization

import android.content.Context
import android.os.Build
import com.nivra.agent.models.EventType
import com.nivra.agent.models.SecurityEvent
import com.nivra.agent.models.Severity
import com.nivra.agent.utils.DeviceIdentity
import com.nivra.agent.utils.Logger
import java.time.Instant

/**
 * Every collector builds its event through this normalizer rather than
 * constructing SecurityEvent directly. Two things happen here, always:
 *
 *  1. Device/agent context (device_id, android_version, security_patch) is
 *     attached consistently, so collectors don't each reimplement it.
 *  2. The data-minimization filter runs over the event's data map and drops
 *     (rather than transmits) any field whose key matches an excluded
 *     category, even if a collector accidentally included one. This is the
 *     "technical constraint, not just documentation" version of the
 *     proposal's Legal/Ethical exclusion list.
 */
class EventNormalizer(private val context: Context) {

    private val excludedKeyPatterns = listOf(
        "password", "passwd", "pin_code", "message_body", "sms_body", "sms_content",
        "contact_", "keystroke", "file_content", "photo", "image_data", "location",
        "latitude", "longitude", "packet_payload", "call_log"
    )

    fun normalize(
        eventType: EventType,
        severity: Severity,
        data: Map<String, Any?>,
        timestamp: Instant = Instant.now()
    ): SecurityEvent {
        val filtered = filterExcludedFields(data)

        return SecurityEvent(
            timestampUtc = timestamp,
            deviceId = DeviceIdentity.get(context),
            androidVersion = Build.VERSION.RELEASE ?: "unknown",
            securityPatch = Build.VERSION.SECURITY_PATCH ?: "unknown",
            eventType = eventType,
            severity = severity,
            data = filtered
        )
    }

    private fun filterExcludedFields(data: Map<String, Any?>): Map<String, Any?> {
        val result = mutableMapOf<String, Any?>()
        for ((key, value) in data) {
            val lower = key.lowercase()
            if (excludedKeyPatterns.any { lower.contains(it) }) {
                Logger.w("Dropped field '$key' at normalization: matches excluded-data pattern")
                continue
            }
            result[key] = filterNestedValue(value)
        }
        return result
    }

    /**
     * Recurses into nested maps/lists so exclusion isn't limited to the
     * top-level data map -- e.g. APPLICATION_INVENTORY's "applications"
     * list of per-app maps gets the same field-name filtering as any
     * top-level field.
     */
    @Suppress("UNCHECKED_CAST")
    private fun filterNestedValue(value: Any?): Any? = when (value) {
        is Map<*, *> -> filterExcludedFields(value as Map<String, Any?>)
        is List<*> -> value.map { filterNestedValue(it) }
        else -> value
    }
}
