package com.nivra.agent.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.nivra.agent.storage.Preferences

/**
 * Deliberately does not expose the enrollment token in plaintext once set,
 * and does not offer any control that would disable Android security
 * protections (e.g. no toggle for "allow unknown sources") -- consistent
 * with "don't allow the user to disable security protections in a way that
 * undermines the research design."
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    prefs: Preferences,
    onSave: (host: String, port: Int, tls: Boolean, heartbeatSeconds: Int, agentEnabled: Boolean, logLevel: String) -> Unit
) {
    var host by remember { mutableStateOf(prefs.wazuhHost) }
    var portText by remember { mutableStateOf(prefs.wazuhPort.toString()) }
    var tls by remember { mutableStateOf(prefs.tlsEnabled) }
    var heartbeatText by remember { mutableStateOf(prefs.heartbeatIntervalSeconds.toString()) }
    var agentEnabled by remember { mutableStateOf(prefs.agentEnabled) }
    var logLevel by remember { mutableStateOf(prefs.logLevel) }
    var tokenInput by remember { mutableStateOf("") }
    var saved by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
    ) {
        SectionCard("Agent") {
            Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                Switch(checked = agentEnabled, onCheckedChange = { agentEnabled = it })
                Spacer(modifier = Modifier.width(8.dp))
                Text("Agent Enabled")
            }
        }

        SectionCard("Wazuh Server") {
            OutlinedTextField(
                value = host, onValueChange = { host = it },
                label = { Text("Server host") }, modifier = Modifier.fillMaxWidth()
            )
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(
                value = portText, onValueChange = { portText = it.filter { c -> c.isDigit() } },
                label = { Text("Port") }, modifier = Modifier.fillMaxWidth()
            )
            Spacer(modifier = Modifier.height(8.dp))
            Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                Switch(checked = tls, onCheckedChange = { tls = it })
                Spacer(modifier = Modifier.width(8.dp))
                Text("TLS Enabled")
            }
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(
                value = tokenInput, onValueChange = { tokenInput = it },
                label = { Text("Enrollment token (leave blank to keep current)") },
                visualTransformation = androidx.compose.ui.text.input.PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth()
            )
        }

        SectionCard("Heartbeat & Logging") {
            OutlinedTextField(
                value = heartbeatText, onValueChange = { heartbeatText = it.filter { c -> c.isDigit() } },
                label = { Text("Heartbeat interval (seconds, min 60)") }, modifier = Modifier.fillMaxWidth()
            )
            Spacer(modifier = Modifier.height(8.dp))
            var expanded by remember { mutableStateOf(false) }
            ExposedDropdownMenuBox(expanded = expanded, onExpandedChange = { expanded = it }) {
                OutlinedTextField(
                    value = logLevel, onValueChange = {}, readOnly = true,
                    label = { Text("Log level") }, modifier = Modifier.menuAnchor().fillMaxWidth()
                )
                ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
                    listOf("DEBUG", "INFO", "WARN", "ERROR").forEach { level ->
                        DropdownMenuItem(text = { Text(level) }, onClick = { logLevel = level; expanded = false })
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))
        Button(onClick = {
            if (tokenInput.isNotBlank()) prefs.enrollmentToken = tokenInput
            onSave(
                host,
                portText.toIntOrNull() ?: 8443,
                tls,
                heartbeatText.toIntOrNull() ?: 900,
                agentEnabled,
                logLevel
            )
            saved = true
        }) {
            Text("Save")
        }
        if (saved) {
            Spacer(modifier = Modifier.height(8.dp))
            Text("Settings saved.", style = MaterialTheme.typography.bodySmall)
        }
    }
}
