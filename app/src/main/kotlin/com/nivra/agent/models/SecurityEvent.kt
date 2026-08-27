package com.nivra.agent.models

import org.json.JSONArray
import org.json.JSONObject
import java.time.Instant
import java.util.UUID

/**
 * The one predictable event schema every collector normalizes into.
 * Matches the schema in the technical spec:
 *
 * {
 *   "schema_version": "1.0",
 *   "event_id": "uuid",
 *   "timestamp": "2026-08-22T19:42:31Z",
 *   "device": { "device_id": ..., "android_version": ..., "security_patch": ... },
 *   "agent": { "name": ..., "version": ... },
 *   "event": { "type": ..., "severity": ... },
 *   "data": { ... }
 * }
 *
 * event_id lets Wazuh (and our own reliability metrics) distinguish a retried
 * delivery of the same event from a genuinely new one.
 */
data class SecurityEvent(
    val eventId: String = UUID.randomUUID().toString(),
    val timestampUtc: Instant = Instant.now(),
    val deviceId: String,
    val androidVersion: String,
    val securityPatch: String,
    val eventType: EventType,
    val severity: Severity,
    val data: Map<String, Any?>,
    var state: EventState = EventState.PENDING
) {
    companion object {
        const val SCHEMA_VERSION = "1.0"
        const val AGENT_NAME = "NIVRA Android Security Agent"
        const val AGENT_VERSION = "0.2.0-prototype"
    }

    fun toJson(): JSONObject {
        val root = JSONObject()
        root.put("schema_version", SCHEMA_VERSION)
        root.put("event_id", eventId)
        root.put("timestamp", timestampUtc.toString()) // ISO-8601 UTC, e.g. 2026-08-22T19:42:31Z

        val device = JSONObject()
        device.put("device_id", deviceId)
        device.put("android_version", androidVersion)
        device.put("security_patch", securityPatch)
        root.put("device", device)

        val agent = JSONObject()
        agent.put("name", AGENT_NAME)
        agent.put("version", AGENT_VERSION)
        root.put("agent", agent)

        val eventObj = JSONObject()
        eventObj.put("type", eventType.name)
        eventObj.put("severity", severity.name)
        root.put("event", eventObj)

        root.put("data", mapToJson(data))
        return root
    }

    private fun mapToJson(map: Map<String, Any?>): JSONObject {
        val obj = JSONObject()
        for ((k, v) in map) {
            obj.put(k, valueToJson(v))
        }
        return obj
    }

    @Suppress("UNCHECKED_CAST")
    private fun valueToJson(v: Any?): Any = when (v) {
        null -> JSONObject.NULL
        is Map<*, *> -> mapToJson(v as Map<String, Any?>)
        is List<*> -> JSONArray(v.map { valueToJson(it) })
        else -> v
    }
}
