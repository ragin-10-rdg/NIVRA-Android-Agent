package com.nivra.agent.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.nivra.agent.models.AgentStatus
import com.nivra.agent.ui.theme.StatusGood
import com.nivra.agent.ui.theme.StatusWarn

@Composable
fun ApplicationsScreen(status: AgentStatus) {
    val apps = status.applications.sortedByDescending { !it.approved }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Text("Installed Applications (${apps.size})", style = MaterialTheme.typography.titleMedium)
        Text(
            "${apps.count { !it.approved }} not on the approved baseline",
            style = MaterialTheme.typography.bodySmall,
            color = if (apps.any { !it.approved }) StatusWarn else StatusGood
        )
        Spacer(modifier = Modifier.height(8.dp))

        LazyColumn {
            items(apps) { app ->
                Card(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text(app.packageName, fontWeight = FontWeight.SemiBold)
                            Text(
                                if (app.approved) "Approved" else "⚠ Unexpected",
                                color = if (app.approved) StatusGood else StatusWarn,
                                style = MaterialTheme.typography.labelMedium
                            )
                        }
                        Text("Version: ${app.versionName ?: "n/a"}", style = MaterialTheme.typography.bodySmall)
                        Text(
                            "Installer: ${app.installerPackage ?: "unknown"}${if (app.isSystemApp) " (system)" else ""}",
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
            }
        }
    }
}
