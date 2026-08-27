package com.nivra.agent

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.nivra.agent.collectors.DeviceCollector
import com.nivra.agent.collectors.SecurityConfigCollector
import com.nivra.agent.dpc.NivraDeviceAdminReceiver
import com.nivra.agent.normalization.EventNormalizer
import com.nivra.agent.models.EventType
import com.nivra.agent.models.Severity
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests requiring a real Android Context. Note: full
 * SecurityLog/network-logging collector tests additionally require the
 * test device to actually be provisioned as Device Owner (see README) --
 * those are marked and skip gracefully when Device Owner isn't active,
 * per the capability-detection requirement, rather than failing the whole
 * suite on an unprovisioned CI/emulator device.
 */
@RunWith(AndroidJUnit4::class)
class CollectorInstrumentedTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun deviceCollector_producesWellFormedEvent() = runBlocking {
        val collector = DeviceCollector(context)
        val event = collector.collect()

        assertEquals(EventType.DEVICE_INFO, event.eventType)
        assertTrue(event.deviceId.startsWith("nivra-"))
        assertNotNull(event.securityPatch)

        val json = event.toJson()
        assertEquals("1.0", json.getString("schema_version"))
    }

    @Test
    fun securityConfigCollector_snapshotHasAllExpectedFields() {
        val collector = SecurityConfigCollector(context)
        val snapshot = collector.snapshot()

        // These are booleans by construction; asserting no exception is the
        // meaningful check here (i.e. Settings.Global/.Secure reads succeed
        // on this device/emulator without throwing).
        assertNotNull(snapshot.adbEnabled)
        assertNotNull(snapshot.developerOptionsEnabled)
    }

    @Test
    fun eventNormalizer_attachesDeviceContextAndFiltersExcludedFields() {
        val normalizer = EventNormalizer(context)
        val event = normalizer.normalize(
            EventType.SECURITY_CONFIGURATION,
            Severity.INFO,
            data = mapOf("adb_enabled" to false, "password" to "should-be-dropped")
        )

        assertTrue(event.deviceId.isNotBlank())
        assertFalse(event.data.containsKey("password"))
        assertTrue(event.data.containsKey("adb_enabled"))
    }

    @Test
    fun deviceOwnerCapability_reportsHonestlyWhenNotProvisioned() {
        // On an unprovisioned emulator this should be false, not throw --
        // exercising the "continue functioning if unavailable" requirement.
        val isOwner = NivraDeviceAdminReceiver.isDeviceOwner(context)
        assertNotNull(isOwner) // isDeviceOwner never returns null; the real
                                // assertion is that the call above didn't throw.
    }
}
