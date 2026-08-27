package com.nivra.agent.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val DarkColors = darkColorScheme(
    primary = NivraPrimary,
    secondary = NivraSecondary,
    background = NivraBackground,
    surface = NivraSurface,
    onBackground = Color.White,
    onSurface = NivraOnSurface,
    onSurfaceVariant = NivraOnSurfaceSecondary
)

private val LightColors = lightColorScheme(
    primary = NivraPrimary,
    secondary = NivraSecondary
)

@Composable
fun NivraTheme(darkTheme: Boolean = true, content: @Composable () -> Unit) {
    val colors = if (darkTheme) DarkColors else LightColors
    MaterialTheme(colorScheme = colors, content = content)
}
