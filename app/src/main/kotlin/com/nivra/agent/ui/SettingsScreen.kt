package com.nivra.agent.ui

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.nivra.agent.dpc.NivraDeviceAdminReceiver
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
    var certInput by remember { mutableStateOf("") }
    var certConfigured by remember { mutableStateOf(prefs.pinnedCertPem.isNotBlank()) }
    var saved by remember { mutableStateOf(false) }

    val context = LocalContext.current
    val isDebugBuild = (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
    var deviceOwnerEnabled by remember { mutableStateOf(NivraDeviceAdminReceiver.isDeviceOwner(context)) }
    var showRemoveAdminConfirm by remember { mutableStateOf(false) }
    var adminRemoved by remember { mutableStateOf(false) }

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
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(
                value = certInput, onValueChange = { certInput = it },
                label = { Text("Pinned certificate PEM, optional (leave blank to keep current)") },
                minLines = 3,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                if (certConfigured) "A pinned certificate is currently configured."
                else "No pinned certificate configured -- platform CA store only.",
                style = MaterialTheme.typography.bodySmall
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

        if (isDebugBuild) {
            SectionCard("Device Admin (debug builds only)") {
                Text(
                    "Device Owner: " + if (deviceOwnerEnabled) "ENABLED" else "DISABLED",
                    style = MaterialTheme.typography.bodyMedium
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    "Removing device admin stops SecurityLog/network-log collection " +
                        "until the app is re-provisioned (adb shell dpm set-device-owner " +
                        "com.nivra.agent/.dpc.NivraDeviceAdminReceiver). Use this only to " +
                        "unblock reinstalling from Android Studio during development -- a " +
                        "Device Owner process can't otherwise be force-stopped.",
                    style = MaterialTheme.typography.bodySmall
                )
                Spacer(modifier = Modifier.height(8.dp))
                Button(
                    onClick = { showRemoveAdminConfirm = true },
                    enabled = deviceOwnerEnabled
                ) {
                    Text("Remove Device Admin")
                }
                if (adminRemoved) {
                    Spacer(modifier = Modifier.height(4.dp))
                    Text("Device admin removed.", style = MaterialTheme.typography.bodySmall)
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))
        Button(onClick = {
            if (tokenInput.isNotBlank()) prefs.enrollmentToken = tokenInput
            if (certInput.isNotBlank()) {
                prefs.pinnedCertPem = certInput
                certConfigured = true
            }
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

    if (showRemoveAdminConfirm) {
        AlertDialog(
            onDismissRequest = { showRemoveAdminConfirm = false },
            title = { Text("Remove device admin?") },
            text = {
                Text(
                    "This relinquishes Device Owner and deactivates the admin. " +
                        "SecurityLog and network-log collection stop until you re-run " +
                        "'adb shell dpm set-device-owner ...' on a clean profile."
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
                    val admin = NivraDeviceAdminReceiver.componentName(context)
                    try {
                        if (dpm.isDeviceOwnerApp(context.packageName)) {
                            dpm.clearDeviceOwnerApp(context.packageName)
                        }
                        dpm.removeActiveAdmin(admin)
                    } catch (e: SecurityException) {
                        // Best effort; nothing more we can do from inside the app.
                    }
                    deviceOwnerEnabled = NivraDeviceAdminReceiver.isDeviceOwner(context)
                    adminRemoved = true
                    showRemoveAdminConfirm = false
                }) {
                    Text("Remove")
                }
            },
            dismissButton = {
                TextButton(onClick = { showRemoveAdminConfirm = false }) {
                    Text("Cancel")
                }
            }
        )
    }
}
