package com.nivra.agent.utils

import android.content.Context
import android.provider.Settings
import java.security.MessageDigest

/**
 * Derives a stable, project-specific device identifier (e.g.
 * "nivra-a1b2c3d4e5f6a7b8") without touching hardware identifiers like IMEI
 * or serial number, which would require additional runtime permissions and
 * are exactly the kind of identifier the spec says to avoid using casually.
 */
object DeviceIdentity {
    private var cached: String? = null

    fun get(context: Context): String {
        cached?.let { return it }

        val androidId = Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
            ?: "unknown"
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(androidId.toByteArray())
            .joinToString("") { "%02x".format(it) }

        val id = "nivra-${digest.take(16)}"
        cached = id
        return id
    }
}
