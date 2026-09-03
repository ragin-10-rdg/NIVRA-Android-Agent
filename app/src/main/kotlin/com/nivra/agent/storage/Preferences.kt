package com.nivra.agent.storage

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * All configuration that would otherwise be hardcoded (Wazuh server host,
 * port, TLS toggle, enrollment/auth token, heartbeat interval, log level,
 * application/security-config baselines) lives here, encrypted at rest via
 * Jetpack Security. Nothing here ships in source control or APK resources.
 *
 * For the prototype, values are set once from the Settings screen during
 * enrollment; a production fleet deployment would instead populate these
 * from a provisioning payload (see /provisioning) or an EMM console.
 */
class Preferences(context: Context) {

    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val prefs = EncryptedSharedPreferences.create(
        context,
        "nivra_secure_prefs",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    var wazuhHost: String
        get() = prefs.getString(KEY_HOST, "") ?: ""
        set(value) = prefs.edit().putString(KEY_HOST, value).apply()

    var wazuhPort: Int
        get() = prefs.getInt(KEY_PORT, 8443)
        set(value) = prefs.edit().putInt(KEY_PORT, value).apply()

    var tlsEnabled: Boolean
        get() = prefs.getBoolean(KEY_TLS, true)
        set(value) = prefs.edit().putBoolean(KEY_TLS, value).apply()

    /** Bearer token issued at enrollment time; never logged, never hardcoded. */
    var enrollmentToken: String
        get() = prefs.getString(KEY_TOKEN, "") ?: ""
        set(value) = prefs.edit().putString(KEY_TOKEN, value).apply()

    /**
     * Optional PEM-encoded certificate to pin (in addition to the platform
     * CA store) for the prototype's self-signed/private-CA Wazuh receiver.
     * See TlsManager -- blank means "platform CA store only".
     */
    var pinnedCertPem: String
        get() = prefs.getString(KEY_PINNED_CERT, "") ?: ""
        set(value) = prefs.edit().putString(KEY_PINNED_CERT, value).apply()

    var heartbeatIntervalSeconds: Int
        get() = prefs.getInt(KEY_HEARTBEAT_INTERVAL, 900) // 15 min default; spec's 30s
                                                            // example is too aggressive
                                                            // for a battery-friendly
                                                            // WorkManager schedule.
        set(value) = prefs.edit().putInt(KEY_HEARTBEAT_INTERVAL, value.coerceAtLeast(60)).apply()

    var agentEnabled: Boolean
        get() = prefs.getBoolean(KEY_AGENT_ENABLED, true)
        set(value) = prefs.edit().putBoolean(KEY_AGENT_ENABLED, value).apply()

    var logLevel: String
        get() = prefs.getString(KEY_LOG_LEVEL, "INFO") ?: "INFO"
        set(value) = prefs.edit().putString(KEY_LOG_LEVEL, value).apply()

    /** Comma-separated approved-package baseline for the "unexpected app" use case. */
    var approvedPackagesCsv: String
        get() = prefs.getString(KEY_APPROVED_PACKAGES, defaultBaseline()) ?: defaultBaseline()
        set(value) = prefs.edit().putString(KEY_APPROVED_PACKAGES, value).apply()

    fun approvedPackages(): Set<String> =
        approvedPackagesCsv.split(",").map { it.trim() }.filter { it.isNotEmpty() }.toSet()

    fun wazuhIngestUrl(): String {
        val scheme = if (tlsEnabled) "https" else "http"
        return "$scheme://$wazuhHost:$wazuhPort/nivra/ingest"
    }

    private fun defaultBaseline(): String =
        // A sensible starting baseline of common preinstalled/system packages;
        // update via Settings once the test device's real inventory is known.
        "com.android.chrome,com.google.android.youtube,com.android.settings,com.android.systemui"

    companion object {
        private const val KEY_HOST = "wazuh_host"
        private const val KEY_PORT = "wazuh_port"
        private const val KEY_TLS = "tls_enabled"
        private const val KEY_TOKEN = "enrollment_token"
        private const val KEY_PINNED_CERT = "pinned_cert_pem"
        private const val KEY_HEARTBEAT_INTERVAL = "heartbeat_interval_seconds"
        private const val KEY_AGENT_ENABLED = "agent_enabled"
        private const val KEY_LOG_LEVEL = "log_level"
        private const val KEY_APPROVED_PACKAGES = "approved_packages"
    }
}
