package com.nivra.agent

import android.app.Application
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import com.nivra.agent.agent.HeartbeatManager
import com.nivra.agent.storage.Preferences
import com.nivra.agent.utils.Logger
import java.util.concurrent.TimeUnit
import coil.ImageLoader
import coil.ImageLoaderFactory
import coil.decode.SvgDecoder

class NivraApplication : Application(), ImageLoaderFactory {

    override fun newImageLoader(): ImageLoader {
        return ImageLoader.Builder(this)
            .components {
                add(SvgDecoder.Factory())
            }
            .build()
    }

    override fun onCreate() {
        super.onCreate()
        Logger.minLevel = try {
            Logger.Level.valueOf(Preferences(this).logLevel)
        } catch (e: IllegalArgumentException) {
            Logger.Level.INFO
        }
        scheduleHeartbeat()
    }

    /**
     * WorkManager, not an infinite loop, is what survives process death and
     * doze/battery-optimization restrictions. 15 minutes is WorkManager's
     * minimum period for PeriodicWorkRequest; the foreground service's own
     * in-process heartbeat loop (see AgentService) can run more frequently
     * while the process is alive.
     */
    private fun scheduleHeartbeat() {
        val constraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED)
            .build()

        val request = PeriodicWorkRequestBuilder<HeartbeatManager>(15, TimeUnit.MINUTES)
            .setConstraints(constraints)
            .build()

        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
            "nivra_heartbeat",
            ExistingPeriodicWorkPolicy.KEEP,
            request
        )
    }
}
