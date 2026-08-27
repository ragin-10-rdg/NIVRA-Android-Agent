package com.nivra.agent.agent

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.nivra.agent.storage.Preferences
import com.nivra.agent.utils.Logger
import kotlinx.coroutines.*

/**
 * Long-running foreground service coordinating the parallel telemetry
 * loops. Runs as a visible foreground service (required for reliable
 * background execution on modern Android) with a persistent low-priority
 * notification -- NIVRA runs transparently, never hidden from the device
 * user, consistent with the project's "not a surveillance application"
 * scope.
 *
 * The UI (MainActivity/Compose screens) never talks to this service or the
 * collectors directly -- it only observes AgentManager.status. This
 * service's only job is to drive AgentManager's collection methods on a
 * schedule and keep it initialized while the process is alive.
 */
class AgentService : Service() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    companion object {
        private const val CHANNEL_ID = "nivra_telemetry"
        private const val NOTIFICATION_ID = 1001

        fun start(context: Context) {
            val intent = Intent(context, AgentService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, AgentService::class.java))
        }

        /** Invoked from the DPC's onSecurityLogsAvailable callback. */
        suspend fun pollSecurityLogsNow(context: Context) {
            AgentManager.attach(context)
            AgentManager.pollSecurityLogs()
        }
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification())

        scope.launch {
            AgentManager.attach(applicationContext)
            val prefs = Preferences(applicationContext)
            if (!prefs.agentEnabled) {
                Logger.i("Agent disabled via Settings; service idle")
                return@launch
            }
            runCollectionLoops(prefs)
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private suspend fun runCollectionLoops(prefs: Preferences) = coroutineScope {
        launch { loopEvery(60 * 60_000L) { AgentManager.collectDeviceInfo() } }
        launch { loopEvery(30 * 60_000L) { AgentManager.collectAppInventory() } }
        launch { loopEvery(15 * 60_000L) { AgentManager.collectSecurityConfig() } }
        launch { loopEvery(10 * 60_000L) { AgentManager.pollSecurityLogs() } }
        launch { loopEvery(60_000L) { AgentManager.drainQueue() } }
        launch { loopEvery(5 * 60_000L) { AgentManager.refreshStatus() } }
        // Network events arrive via the DPC's onNetworkLogsAvailable
        // callback (event-driven, not a poll loop) -- see NivraDeviceAdminReceiver.
    }

    private suspend fun loopEvery(intervalMs: Long, block: suspend () -> Unit) {
        while (currentCoroutineContext().isActive) {
            try {
                block()
            } catch (e: Exception) {
                Logger.e("Collection loop iteration failed", e)
            }
            delay(intervalMs)
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID, "NIVRA Security Monitoring", NotificationManager.IMPORTANCE_MIN
            )
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun buildNotification(): Notification =
        NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("NIVRA Security Agent")
            .setContentText("Monitoring device security telemetry")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .build()

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }
}
