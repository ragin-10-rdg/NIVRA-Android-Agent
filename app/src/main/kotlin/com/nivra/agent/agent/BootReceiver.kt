package com.nivra.agent.agent

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.nivra.agent.dpc.NivraDeviceAdminReceiver

/**
 * Reboot recovery: Boot -> Agent initializes -> Device Owner verified ->
 * AgentService starts -> collectors/heartbeat resume automatically via
 * AgentManager.attach().
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED &&
            NivraDeviceAdminReceiver.isDeviceOwner(context)
        ) {
            AgentService.start(context)
        }
    }
}
