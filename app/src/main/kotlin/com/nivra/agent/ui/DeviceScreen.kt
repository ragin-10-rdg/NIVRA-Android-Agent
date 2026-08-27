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
import com.nivra.agent.models.SecurityEvent

@Composable
fun DeviceScreen(status: AgentStatus) {
    val device = status.device

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
    ) {
        SectionCard("Device Information") {
            StatusRow("Manufacturer", device?.manufacturer ?: "Unknown")
            StatusRow("Model", device?.model ?: "Unknown")
            StatusRow("Android version", device?.androidRelease ?: "Unknown")
            StatusRow("API level", device?.sdkInt?.toString() ?: "Unknown")
            StatusRow("Security patch", device?.securityPatch ?: "Unknown")
            StatusRow("Encryption", device?.encryptionStatus ?: "Unknown")
            StatusRow("Device Owner", if (device?.isDeviceOwner == true) "ENABLED" else "DISABLED")
        }

        SectionCard("Agent") {
            StatusRow("Agent version", SecurityEvent.AGENT_VERSION)
            StatusRow("Project device ID", device?.deviceId ?: "Unknown")
        }

        Text(
            "The device identifier above is derived on-device (SHA-256 of ANDROID_ID) " +
                "rather than a hardware identifier like IMEI or serial number.",
            style = MaterialTheme.typography.bodySmall
        )
    }
}
