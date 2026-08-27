package com.nivra.agent.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.background
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.nivra.agent.models.CapabilityStatus
import com.nivra.agent.models.ConnectionStatus
import com.nivra.agent.ui.theme.StatusBad
import com.nivra.agent.ui.theme.StatusGood
import com.nivra.agent.ui.theme.StatusUnknown
import com.nivra.agent.ui.theme.StatusWarn
import androidx.compose.ui.graphics.Color
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import com.nivra.agent.R
import androidx.compose.ui.Alignment
import androidx.compose.ui.unit.sp

import coil.compose.AsyncImage
import androidx.compose.ui.layout.ContentScale

@Composable
fun NivraLogo(modifier: Modifier = Modifier) {
    AsyncImage(
        model = "file:///android_asset/NIVRA_white_transparent.png",
        contentDescription = "NIVRA Logo",
        modifier = modifier
            .fillMaxWidth()
            .height(120.dp),
        contentScale = ContentScale.Fit
    )
}

@Composable
fun SectionCard(title: String, content: @Composable ColumnScope.() -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        border = androidx.compose.foundation.BorderStroke(1.dp, MaterialTheme.colorScheme.primary.copy(alpha = 0.2f))
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                title.uppercase(),
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.primary
            )
            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp), thickness = 0.5.dp, color = MaterialTheme.colorScheme.primary.copy(alpha = 0.1f))
            content()
        }
    }
}

@Composable
fun StatusRow(label: String, value: String, dotColor: Color? = null) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium)
        Row(verticalAlignment = Alignment.CenterVertically) {
            dotColor?.let {
                Box(modifier = Modifier.size(8.dp).clip(CircleShape).background(it))
                Spacer(modifier = Modifier.width(6.dp))
            }
            Text(value, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
        }
    }
}

fun connectionColor(status: ConnectionStatus): Color = when (status) {
    ConnectionStatus.CONNECTED -> StatusGood
    ConnectionStatus.DEGRADED -> StatusWarn
    ConnectionStatus.DISCONNECTED -> StatusBad
    ConnectionStatus.UNKNOWN -> StatusUnknown
}

fun capabilityColor(status: CapabilityStatus): Color = when (status) {
    CapabilityStatus.AVAILABLE -> StatusGood
    CapabilityStatus.UNAVAILABLE -> StatusWarn
    CapabilityStatus.UNKNOWN -> StatusUnknown
}

fun formatEpochMs(epochMs: Long?): String {
    if (epochMs == null) return "Never"
    return SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date(epochMs))
}
