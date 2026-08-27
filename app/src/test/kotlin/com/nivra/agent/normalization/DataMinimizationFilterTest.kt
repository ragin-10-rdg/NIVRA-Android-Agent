package com.nivra.agent.normalization

import org.junit.Assert.*
import org.junit.Test

/**
 * EventNormalizer.normalize() requires an Android Context (for device_id /
 * Build fields), so it's exercised in androidTest. This test isolates the
 * pure excluded-field-matching logic by duplicating the same pattern list
 * and matching rule used in EventNormalizer, so the security guarantee
 * (excluded fields never reach the wire) can be pinned down without a full
 * Android runtime. If EventNormalizer's excludedKeyPatterns changes, update
 * this list to match.
 */
class DataMinimizationFilterTest {

    private val excludedKeyPatterns = listOf(
        "password", "passwd", "pin_code", "message_body", "sms_body", "sms_content",
        "contact_", "keystroke", "file_content", "photo", "image_data", "location",
        "latitude", "longitude", "packet_payload", "call_log"
    )

    private fun filter(data: Map<String, Any?>): Map<String, Any?> =
        data.filterKeys { key -> excludedKeyPatterns.none { key.lowercase().contains(it) } }

    @Test
    fun `password fields are dropped`() {
        val result = filter(mapOf("username" to "bob", "password" to "hunter2"))
        assertTrue(result.containsKey("username"))
        assertFalse(result.containsKey("password"))
    }

    @Test
    fun `sms and message content is dropped`() {
        val result = filter(mapOf("sender" to "+1555", "sms_body" to "secret", "message_body" to "secret2"))
        assertTrue(result.containsKey("sender"))
        assertFalse(result.containsKey("sms_body"))
        assertFalse(result.containsKey("message_body"))
    }

    @Test
    fun `location fields are dropped`() {
        val result = filter(mapOf("latitude" to 1.0, "longitude" to 2.0, "device_id" to "d1"))
        assertTrue(result.containsKey("device_id"))
        assertFalse(result.containsKey("latitude"))
        assertFalse(result.containsKey("longitude"))
    }

    @Test
    fun `legitimate telemetry fields pass through unchanged`() {
        val input = mapOf("package_name" to "com.example.app", "port" to 443, "hostname" to "example.com")
        assertEquals(input, filter(input))
    }
}
