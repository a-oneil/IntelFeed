package com.example.intelfeed.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val IntelFeedDarkColorScheme = darkColorScheme(
    primary = CyberBlue,
    onPrimary = SlateDark900,
    primaryContainer = CyberBlueDim,
    onPrimaryContainer = TextPrimary,
    
    secondary = CyberGreen,
    onSecondary = SlateDark900,
    secondaryContainer = CyberGreenDim,
    onSecondaryContainer = TextPrimary,
    
    tertiary = CyberAmber,
    onTertiary = SlateDark900,
    
    background = SlateDark900,
    onBackground = TextPrimary,
    
    surface = SlateDark800,
    onSurface = TextPrimary,
    surfaceVariant = SlateDark700,
    onSurfaceVariant = TextSecondary,
    
    outline = SlateDark600,
    outlineVariant = SlateDark500,
    
    error = CyberRed,
    onError = Color.White
)

@Composable
fun IntelFeedTheme(
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = IntelFeedDarkColorScheme,
        typography = Typography,
        content = content
    )
}
