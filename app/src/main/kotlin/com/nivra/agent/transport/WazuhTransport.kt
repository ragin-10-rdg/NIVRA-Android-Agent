package com.nivra.agent.transport

import android.content.Context
import com.nivra.agent.storage.Preferences

/**
 * Delivers a single normalized event to the Wazuh-side ingestion path.
 *
 * INGESTION MECHANISM (decided, not left for Claude/implementer to invent):
 * this agent uses a custom HTTPS ingestion endpoint
 * (wazuh-integration/receiver/nivra_receiver.py) rather than the native
 * Wazuh agent-manager registration protocol. Reasoning, so it's on record:
 *
 *  - The native Wazuh agent protocol expects the *actual* wazuh-agent
 *    daemon (C/C++, registered via `manage_agents` + agent.conf key),
 *    which doesn't run on Android and can't be side-loaded without root.
 *  - Syslog-only transport would work but loses the ability to do request/
 *    response (e.g. returning 4xx on a malformed event, or an eventual
 *    ack), which we want for the delivery-reliability metric.
 *  - A small HTTPS receiver that writes JSON Lines into a file monitored
 *    by Wazuh's <localfile> module is a supported, documented Wazuh
 *    integration pattern and keeps the Android side to a plain HTTPS POST.
 *
 * This should be validated experimentally against your actual Wazuh
 * deployment before being treated as final -- see README "Ingestion
 * mechanism" section.
 */
class WazuhTransport(context: Context) {

    private val prefs = Preferences(context)
    private val client = ApiClient()

    suspend fun send(payloadJson: String): Boolean {
        val response = client.postJson(
            url = prefs.wazuhIngestUrl(),
            jsonBody = payloadJson,
            bearerToken = prefs.enrollmentToken.ifBlank { null },
            tlsEnabled = prefs.tlsEnabled,
            pinnedCertPem = prefs.pinnedCertPem.ifBlank { null }
        )
        return response != null && response.statusCode in 200..299
    }
}
