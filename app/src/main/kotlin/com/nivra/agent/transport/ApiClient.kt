package com.nivra.agent.transport

import com.nivra.agent.utils.Logger
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

    fun postJson(url: String, jsonBody: String, bearerToken: String?, tlsEnabled: Boolean): ApiResponse? {
        var attempt = 0
        while (attempt <= maxRetries) {
            val result = attemptPost(url, jsonBody, bearerToken, tlsEnabled)
            if (result != null) {
                if (result.statusCode in 200..299) return result
                if (result.statusCode in 400..499) {
                    Logger.w("Non-retryable response ${result.statusCode} from receiver")
                    return result
                }
            }
            attempt++
            if (attempt <= maxRetries) {
                val backoffMs = (500.0 * 2.0.pow(attempt.toDouble())).toLong()
                Thread.sleep(min(backoffMs, 8_000))
            }
        }
        return null
    }

    private fun attemptPost(url: String, jsonBody: String, bearerToken: String?, tlsEnabled: Boolean): ApiResponse? {
        var connection: HttpURLConnection? = null
        return try {
            val parsed = URL(url)
            connection = parsed.openConnection() as HttpURLConnection
            if (tlsEnabled && connection is HttpsURLConnection) {
                TlsManager.applyTo(connection)
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
