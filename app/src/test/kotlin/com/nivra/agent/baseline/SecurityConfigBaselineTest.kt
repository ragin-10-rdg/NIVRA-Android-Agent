package com.nivra.agent.baseline

import org.junit.Assert.*
import org.junit.Test

class SecurityConfigBaselineTest {

    @Test
    fun `matching baseline produces no drift`() {
        val current = SecurityConfigBaseline.expected.copy()
        assertTrue(SecurityConfigBaseline.diff(current).isEmpty())
    }

    @Test
    fun `adb enabled is flagged as drift`() {
        val current = SecurityConfigBaseline.expected.copy(adbEnabled = true)
        val drifted = SecurityConfigBaseline.diff(current)
        assertEquals(listOf("adb_enabled"), drifted)
    }

    @Test
    fun `multiple simultaneous drifts are all reported`() {
        val current = SecurityConfigBaseline.expected.copy(
            adbEnabled = true,
            developerOptionsEnabled = true,
            securityLoggingEnabled = false
        )
        val drifted = SecurityConfigBaseline.diff(current)
        assertEquals(3, drifted.size)
        assertTrue(drifted.contains("adb_enabled"))
        assertTrue(drifted.contains("developer_options_enabled"))
        assertTrue(drifted.contains("security_logging_enabled"))
    }

    @Test
    fun `unknown sources enabled is flagged as drift`() {
        val current = SecurityConfigBaseline.expected.copy(unknownSourcesEnabled = true)
        assertEquals(listOf("unknown_sources_enabled"), SecurityConfigBaseline.diff(current))
    }
}
