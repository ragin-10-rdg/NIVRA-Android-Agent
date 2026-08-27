package com.nivra.agent.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.nivra.agent.models.AgentStatus

@Composable
fun WazuhConnectionScreen(status: AgentStatus, onForceSend: () -> Unit) {
    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        SectionCard("Wazuh Connection") {
            StatusRow("Status", status.connectionStatus.name, connectionColor(status.connectionStatus))
            StatusRow("Server", status.wazuhServer.ifBlank { "Not configured" })
            StatusRow("Last successful event", formatEpochMs(status.lastSuccessfulDeliveryEpochMs))
            StatusRow("Events sent", status.eventsSent.toString())
            StatusRow("Pending", status.eventsPending.toString())
            StatusRow("Failed", status.eventsFailed.toString())
        }

        Text(
            "The enrollment token and TLS configuration are not shown here. " +
                "Configure the server address and credentials from Settings.",
            style = MaterialTheme.typography.bodySmall
        )

        Spacer(modifier = Modifier.height(16.dp))
        Button(onClick = onForceSend) { Text("Send queued events now") }
    }
}
