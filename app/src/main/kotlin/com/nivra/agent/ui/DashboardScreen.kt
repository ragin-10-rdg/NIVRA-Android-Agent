package com.nivra.agent.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.nivra.agent.models.AgentStatus
import com.nivra.agent.models.ConnectionStatus
import com.nivra.agent.ui.theme.StatusGood

@Composable
fun DashboardScreen(status: AgentStatus, onRefresh: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
    ) {
        NivraLogo(modifier = Modifier.padding(vertical = 24.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = androidx.compose.ui.Alignment.CenterVertically
        ) {
            Text(
                if (status.isRunning) "● AGENT ONLINE" else "○ AGENT OFFLINE",
                color = if (status.isRunning) StatusGood else MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.Bold
            )
            TextButton(onClick = onRefresh) { 
                Text("REFRESH DATA", style = MaterialTheme.typography.labelLarge) 
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        SectionCard("Status") {
            StatusRow("Device Status", if (status.eventsFailed > 5) "AT RISK" else "SECURE")
            StatusRow(
                "Wazuh Connection",
                status.connectionStatus.name,
                connectionColor(status.connectionStatus)
            )
            StatusRow("Device Owner", if (status.isDeviceOwner) "ENABLED" else "NOT PROVISIONED")
        }

        SectionCard("Security Patch") {
            StatusRow("Patch level", status.device?.securityPatch ?: "Unknown")
        }

        SectionCard("Events") {
            StatusRow("Collected", status.eventsCollected.toString())
            StatusRow("Sent", status.eventsSent.toString())
            StatusRow("Pending", status.eventsPending.toString())
            StatusRow("Failed", status.eventsFailed.toString())
        }

        SectionCard("Success Metrics") {
            StatusRow("Collection success rate", "%.1f%%".format(status.collectionSuccessRatePct))
            StatusRow("Delivery reliability", "%.1f%%".format(status.deliveryReliabilityPct))
        }

        SectionCard("Heartbeat") {
            StatusRow("Last heartbeat", formatEpochMs(status.lastHeartbeatEpochMs))
            StatusRow("Last successful delivery", formatEpochMs(status.lastSuccessfulDeliveryEpochMs))
        }

        if (!status.isDeviceOwner) {
            SectionCard("Provisioning required") {
                Text(
                    "This device is not yet provisioned as Device Owner. " +
                        "Telemetry collection is limited until provisioning completes. " +
                        "See the README for the adb dpm set-device-owner command or the " +
                        "QR/zero-touch enrollment flow.",
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }
    }
}
