package com.nivra.agent.transport

import com.nivra.agent.utils.Logger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import kotlin.math.min
import kotlin.math.pow

data class ApiResponse(val statusCode: Int, val body: String)

/**
 * Minimal HTTPS client: POSTs JSON, enforces TLS via TlsManager, applies a
 * bearer token, and retries with exponential backoff on transient failures
 * (network errors / 5xx). 4xx responses (bad request, auth failure) are not
 * retried, since retrying a rejected/malformed event won't help.
 */
class ApiClient(
    private val connectTimeoutMs: Int = 8_000,
    private val readTimeoutMs: Int = 8_000,
    private val maxRetries: Int = 3
) {

    suspend fun postJson(
        url: String,
        jsonBody: String,
        bearerToken: String?,
        tlsEnabled: Boolean,
        pinnedCertPem: String? = null
    ): ApiResponse? {
        var attempt = 0
        while (attempt <= maxRetries) {
            val result = attemptPost(url, jsonBody, bearerToken, tlsEnabled, pinnedCertPem)
            if (result != null) {
                if (result.statusCode in 200..299) return result
                if (result.statusCode in 400..499) {
                    Logger.w("Non-retryable response ${result.statusCode} from receiver")
                    return result
                }
            }
            attempt++
            if (attempt <= maxRetries) {
                // delay() (not Thread.sleep) so a cancelled drain suspends
                // out immediately instead of blocking the dispatcher thread
                // through the full backoff window.
                val backoffMs = (500.0 * 2.0.pow(attempt.toDouble())).toLong()
                delay(min(backoffMs, 8_000))
            }
        }
        return null
    }

    private suspend fun attemptPost(
        url: String,
        jsonBody: String,
        bearerToken: String?,
        tlsEnabled: Boolean,
        pinnedCertPem: String?
    ): ApiResponse? = withContext(Dispatchers.IO) {
        var connection: HttpURLConnection? = null
        try {
            val parsed = URL(url)
            connection = parsed.openConnection() as HttpURLConnection
            if (tlsEnabled && connection is HttpsURLConnection) {
                TlsManager.applyTo(connection, pinnedCertPem)
            }
            connection.requestMethod = "POST"
            connection.connectTimeout = connectTimeoutMs
            connection.readTimeout = readTimeoutMs
            connection.doOutput = true
            connection.setRequestProperty("Content-Type", "application/json")
            if (!bearerToken.isNullOrBlank()) {
                connection.setRequestProperty("Authorization", "Bearer $bearerToken")
            }

            OutputStreamWriter(connection.outputStream, Charsets.UTF_8).use { it.write(jsonBody) }

            val code = connection.responseCode
            val stream = if (code in 200..299) connection.inputStream else connection.errorStream
            val body = stream?.bufferedReader()?.use { it.readText() } ?: ""
            ApiResponse(code, body)
        } catch (e: Exception) {
            Logger.w("Transport error: ${e.javaClass.simpleName}")
            null
        } finally {
            connection?.disconnect()
        }
    }
}
