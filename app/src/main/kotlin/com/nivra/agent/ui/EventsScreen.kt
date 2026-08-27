package com.nivra.agent.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.nivra.agent.models.AgentStatus
import com.nivra.agent.models.Severity
import com.nivra.agent.ui.theme.StatusBad
import com.nivra.agent.ui.theme.StatusGood
import com.nivra.agent.ui.theme.StatusUnknown
import com.nivra.agent.ui.theme.StatusWarn
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun EventsScreen(status: AgentStatus) {
    val timeFormat = remember { SimpleDateFormat("HH:mm", Locale.getDefault()) }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Text("Recent Security Events", style = MaterialTheme.typography.titleMedium)
        Spacer(modifier = Modifier.height(8.dp))

        if (status.recentEvents.isEmpty()) {
            Text("No events collected yet.", style = MaterialTheme.typography.bodyMedium)
        }

        LazyColumn {
            items(status.recentEvents) { event ->
                Card(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(12.dp),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column {
                            Text(
                                event.eventType.name.replace('_', ' '),
                                fontWeight = FontWeight.SemiBold
                            )
                            Text(timeFormat.format(Date(event.timestampUtc.toEpochMilli())), style = MaterialTheme.typography.bodySmall)
                        }
                        Text(event.severity.name, color = severityColor(event.severity))
                    }
                }
            }
        }
    }
}

private fun severityColor(severity: Severity) = when (severity) {
    Severity.INFO -> StatusUnknown
    Severity.LOW -> StatusGood
    Severity.MEDIUM -> StatusWarn
    Severity.HIGH -> StatusBad
}
