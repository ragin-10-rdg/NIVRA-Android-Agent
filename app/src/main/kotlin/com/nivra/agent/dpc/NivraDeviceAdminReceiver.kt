package com.nivra.agent.dpc

import android.app.admin.DeviceAdminReceiver
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import com.nivra.agent.agent.AgentService
import com.nivra.agent.collectors.NetworkCollector
import com.nivra.agent.storage.EventQueue
import com.nivra.agent.utils.Logger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * NIVRA's Device Policy Controller receiver.
 *
 * Provision as Device Owner on a freshly factory-reset test device with no
 * accounts configured:
 *
 *   adb shell dpm set-device-owner com.nivra.agent/.dpc.NivraDeviceAdminReceiver
 *
 * or via the zero-touch/QR flow described in /provisioning for fleet
 * deployment. Once granted, this component enables SecurityLog and Android
 * Enterprise network logging and starts the agent.
 */
class NivraDeviceAdminReceiver : DeviceAdminReceiver() {

    companion object {
        private const val TAG = "NivraDPC"

        fun componentName(context: Context): ComponentName =
            ComponentName(context, NivraDeviceAdminReceiver::class.java)

        fun isDeviceOwner(context: Context): Boolean {
            val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
            return dpm.isDeviceOwnerApp(context.packageName)
        }
    }

    override fun onEnabled(context: Context, intent: Intent) {
        super.onEnabled(context, intent)
        Logger.i("Device admin enabled")
        activateTelemetryPolicies(context)
    }

    override fun onProfileProvisioningComplete(context: Context, intent: Intent) {
        super.onProfileProvisioningComplete(context, intent)
        Logger.i("Provisioning complete")
        applyProvisioningExtras(context, intent)
        activateTelemetryPolicies(context)
    }

    /**
     * Reads the optional admin extras bundle from QR/zero-touch provisioning
     * (see /provisioning/qr_provisioning_payload.json) and seeds Preferences
     * with it, so a fleet-deployed device doesn't need a manual Settings
     * visit before it can reach the Wazuh receiver.
     */
    private fun applyProvisioningExtras(context: Context, intent: Intent) {
        val bundle = intent.getParcelableExtra<android.os.PersistableBundle>(
            DevicePolicyManager.EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE
        ) ?: return

        val prefs = com.nivra.agent.storage.Preferences(context)
        bundle.getString("wazuh_host")?.let { prefs.wazuhHost = it }
        bundle.getString("wazuh_port")?.toIntOrNull()?.let { prefs.wazuhPort = it }
        bundle.getString("enrollment_token")?.let { prefs.enrollmentToken = it }
        Logger.i("Applied provisioning extras from QR/zero-touch payload")
    }

    /**
     * Called by the platform whenever a batch of network logs becomes
     * available. A BroadcastReceiver callback must not block or do
     * long-running work on the main thread, so we take a goAsync() wakelock
     * and finish it once the batch has been queued.
     */
    override fun onNetworkLogsAvailable(
        context: Context,
        intent: Intent,
        batchToken: Long,
        networkLogsCount: Int
    ) {
        super.onNetworkLogsAvailable(context, intent, batchToken, networkLogsCount)
        val pendingResult = goAsync()
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val collector = NetworkCollector(context)
                val events = collector.collectBatch(batchToken)
                val queue = EventQueue(context)
                events.forEach { queue.enqueue(it) }
                Logger.i("Queued ${events.size} network events from batch $batchToken")
            } catch (e: Exception) {
                Logger.e("Failed to process network log batch", e)
            } finally {
                pendingResult.finish()
            }
        }
    }

    override fun onSecurityLogsAvailable(context: Context, intent: Intent) {
        super.onSecurityLogsAvailable(context, intent)
        val pendingResult = goAsync()
        CoroutineScope(Dispatchers.IO).launch {
            try {
                AgentService.pollSecurityLogsNow(context)
            } finally {
                pendingResult.finish()
            }
        }
    }

    private fun activateTelemetryPolicies(context: Context) {
        if (!isDeviceOwner(context)) {
            Logger.w("Not Device Owner yet; skipping policy activation")
            return
        }

        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val admin = componentName(context)

        try {
            dpm.setSecurityLoggingEnabled(admin, true)
            dpm.setNetworkLoggingEnabled(admin, true)
            Logger.i("Security logging and network logging enabled")
        } catch (e: SecurityException) {
            Logger.e("Failed to enable logging policies", e)
        }

        AgentService.start(context)
    }
}
