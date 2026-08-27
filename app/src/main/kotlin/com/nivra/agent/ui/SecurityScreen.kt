package com.nivra.agent.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.nivra.agent.models.AgentStatus
import com.nivra.agent.models.CapabilityStatus

@Composable
fun SecurityScreen(status: AgentStatus) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
    ) {
        SectionCard("Security Status") {
            StatusRow("Security patch", status.device?.securityPatch ?: "Unknown")
            StatusRow("Device Owner", if (status.isDeviceOwner) "ENABLED" else "DISABLED")
            StatusRow("Agent", if (status.isRunning) "RUNNING" else "STOPPED")
            StatusRow("Wazuh Connection", status.connectionStatus.name, connectionColor(status.connectionStatus))
            StatusRow("Security events (24h)", status.securityEventCount24h.toString())
        }

        SectionCard("Telemetry Capabilities") {
            Text(
                "Honest reporting: capabilities not supported or not yet " +
                    "authorized on this device are shown as Limited/Unavailable " +
                    "rather than silently omitted.",
                style = MaterialTheme.typography.bodySmall
            )
            Spacer(modifier = Modifier.height(8.dp))
            status.capabilities.forEach { capability ->
                StatusRow(
                    capability.name.replace('_', ' ').replaceFirstChar { it.uppercase() },
                    when (capability.status) {
                        CapabilityStatus.AVAILABLE -> "Available"
                        CapabilityStatus.UNAVAILABLE -> "Limited / Unavailable"
                        CapabilityStatus.UNKNOWN -> "Unknown"
                    },
                    capabilityColor(capability.status)
                )
                capability.reason?.let {
                    Text("  Reason: $it", style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}
