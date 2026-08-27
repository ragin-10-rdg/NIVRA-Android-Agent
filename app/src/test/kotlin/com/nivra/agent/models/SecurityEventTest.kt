package com.nivra.agent.models

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.time.Instant

/**
 * Pure-JVM unit test (no Android runtime needed) verifying the wire schema
 * stays stable -- the Wazuh decoder in wazuh-integration/decoders/ depends
 * on these exact field names and nesting.
 */
class SecurityEventTest {

    @Test
    fun `toJson produces the documented nested schema`() {
        val event = SecurityEvent(
            eventId = "test-uuid-1234",
            timestampUtc = Instant.parse("2026-08-22T19:42:31Z"),
            deviceId = "nivra-abcdef0123456789",
            androidVersion = "15",
            securityPatch = "2026-08-01",
            eventType = EventType.APPLICATION_INSTALL,
            severity = Severity.MEDIUM,
            data = mapOf("package_name" to "com.example.test", "approved" to false)
        )

        val json = event.toJson()

        assertEquals("1.0", json.getString("schema_version"))
        assertEquals("test-uuid-1234", json.getString("event_id"))
        assertEquals("2026-08-22T19:42:31Z", json.getString("timestamp"))

        val device = json.getJSONObject("device")
        assertEquals("nivra-abcdef0123456789", device.getString("device_id"))
        assertEquals("15", device.getString("android_version"))
        assertEquals("2026-08-01", device.getString("security_patch"))

        val agent = json.getJSONObject("agent")
        assertEquals(SecurityEvent.AGENT_NAME, agent.getString("name"))
        assertEquals(SecurityEvent.AGENT_VERSION, agent.getString("version"))

        val eventObj = json.getJSONObject("event")
        assertEquals("APPLICATION_INSTALL", eventObj.getString("type"))
        assertEquals("MEDIUM", eventObj.getString("severity"))

        val data = json.getJSONObject("data")
        assertEquals("com.example.test", data.getString("package_name"))
        assertFalse(data.getBoolean("approved"))
    }

    @Test
    fun `nested maps and lists serialize correctly`() {
        val event = SecurityEvent(
            deviceId = "d1",
            androidVersion = "15",
            securityPatch = "2026-08-01",
            eventType = EventType.APPLICATION_INVENTORY,
            severity = Severity.INFO,
            data = mapOf(
                "app_count" to 2,
                "applications" to listOf(
                    mapOf("package_name" to "com.a", "approved" to true),
                    mapOf("package_name" to "com.b", "approved" to false)
                )
            )
        )

        val data = event.toJson().getJSONObject("data")
        assertEquals(2, data.getInt("app_count"))
        val apps = data.getJSONArray("applications")
        assertEquals(2, apps.length())
        assertEquals("com.a", (apps.get(0) as JSONObject).getString("package_name"))
    }

    @Test
    fun `null values become JSON null rather than being dropped`() {
        val event = SecurityEvent(
            deviceId = "d1",
            androidVersion = "15",
            securityPatch = "2026-08-01",
            eventType = EventType.NETWORK_EVENT,
            severity = Severity.INFO,
            data = mapOf("hostname" to null, "port" to 443)
        )

        val data = event.toJson().getJSONObject("data")
        assertTrue(data.isNull("hostname"))
        assertEquals(443, data.getInt("port"))
    }

    @Test
    fun `each event gets a unique id by default`() {
        val e1 = SecurityEvent(deviceId = "d", androidVersion = "15", securityPatch = "p",
            eventType = EventType.HEARTBEAT, severity = Severity.INFO, data = emptyMap())
        val e2 = SecurityEvent(deviceId = "d", androidVersion = "15", securityPatch = "p",
            eventType = EventType.HEARTBEAT, severity = Severity.INFO, data = emptyMap())

        assertNotEquals(e1.eventId, e2.eventId)
    }
}
