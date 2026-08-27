package com.nivra.agent.utils

import android.util.Log

/**
 * Thin wrapper over Log so log level and sensitive-field filtering are
 * enforced in one place. Never logs values under these keys, even if a
 * caller passes them in by mistake (defense in depth on top of the
 * collectors already never reading this data).
 */
object Logger {
    private const val TAG = "NIVRA"
    private val REDACTED_KEYS = setOf(
        "password", "token", "auth", "authorization", "secret", "key",
        "message", "sms", "contact", "keystroke", "file_content"
    )

    enum class Level { DEBUG, INFO, WARN, ERROR }

    var minLevel: Level = Level.INFO

    fun d(msg: String) = log(Level.DEBUG, msg)
    fun i(msg: String) = log(Level.INFO, msg)
    fun w(msg: String) = log(Level.WARN, msg)
    fun e(msg: String, throwable: Throwable? = null) {
        if (Level.ERROR.ordinal >= minLevel.ordinal) {
            Log.e(TAG, redact(msg), throwable)
        }
    }

    private fun log(level: Level, msg: String) {
        if (level.ordinal < minLevel.ordinal) return
        val redacted = redact(msg)
        when (level) {
            Level.DEBUG -> Log.d(TAG, redacted)
            Level.INFO -> Log.i(TAG, redacted)
            Level.WARN -> Log.w(TAG, redacted)
            Level.ERROR -> Log.e(TAG, redacted)
        }
    }

    private fun redact(msg: String): String {
        var out = msg
        for (key in REDACTED_KEYS) {
            val regex = Regex("(?i)($key\\s*[:=]\\s*)([^,}\\s]+)")
            out = regex.replace(out) { m -> "${m.groupValues[1]}[REDACTED]" }
        }
        return out
    }
}
