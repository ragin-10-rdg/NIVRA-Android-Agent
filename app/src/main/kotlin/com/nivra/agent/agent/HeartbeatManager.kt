package com.nivra.agent.agent

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters

/**
 * Battery-friendly heartbeat + queue-drain job, scheduled via WorkManager
 * (see NivraApplication) rather than a busy loop. This runs even if the
 * foreground service has been killed by the system, so a heartbeat gap on
 * the Wazuh side reliably means "agent genuinely offline," not "foreground
 * service got reaped."
 */
class HeartbeatManager(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        return try {
            AgentManager.attach(applicationContext)
            AgentManager.sendHeartbeat()
            AgentManager.drainQueue()
            Result.success()
        } catch (e: Exception) {
            Result.retry()
        }
    }
}
