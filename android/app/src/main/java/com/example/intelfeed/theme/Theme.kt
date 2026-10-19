package com.example.intelfeed.theme

import android.app.Activity
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

@Composable
fun IntelFeedTheme(
    content: @Composable () -> Unit
) {
    // Observe ThemeEngine.variables so MaterialTheme recomposes whenever the server theme or schema updates
    val isLight = ThemeEngine.isLightTheme
    val onPrimary = ThemeEngine.color("accent-fg", ThemeEngine.contrastTextColor(CyberBlue))
    val onSecondary = ThemeEngine.contrastTextColor(CyberGreen)
    val onTertiary = ThemeEngine.contrastTextColor(CyberAmber)
    val onError = ThemeEngine.contrastTextColor(CyberRed)

    val colorScheme = if (isLight) {
        lightColorScheme(
            primary = CyberBlue,
            onPrimary = onPrimary,
            primaryContainer = CyberBlueDim,
            onPrimaryContainer = ThemeEngine.contrastTextColor(CyberBlueDim),
            secondary = CyberGreen,
            onSecondary = onSecondary,
            secondaryContainer = CyberGreenDim,
            onSecondaryContainer = TextPrimary,
            tertiary = CyberAmber,
            onTertiary = onTertiary,
            background = SlateDark900,
            onBackground = TextPrimary,
            surface = SlateDark800,
            onSurface = TextPrimary,
            surfaceVariant = SlateDark700,
            onSurfaceVariant = TextSecondary,
            outline = SlateDark600,
            outlineVariant = SlateDark500,
            error = CyberRed,
            onError = onError
        )
    } else {
        darkColorScheme(
            primary = CyberBlue,
            onPrimary = onPrimary,
            primaryContainer = CyberBlueDim,
            onPrimaryContainer = TextPrimary,
            secondary = CyberGreen,
            onSecondary = onSecondary,
            secondaryContainer = CyberGreenDim,
            onSecondaryContainer = TextPrimary,
            tertiary = CyberAmber,
            onTertiary = onTertiary,
            background = SlateDark900,
            onBackground = TextPrimary,
            surface = SlateDark800,
            onSurface = TextPrimary,
            surfaceVariant = SlateDark700,
            onSurfaceVariant = TextSecondary,
            outline = SlateDark600,
            outlineVariant = SlateDark500,
            error = CyberRed,
            onError = onError
        )
    }

    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as? Activity)?.window ?: return@SideEffect
            WindowCompat.getInsetsController(window, view).apply {
                isAppearanceLightStatusBars = isLight
                isAppearanceLightNavigationBars = isLight
            }
        }
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography,
        content = content
    )
}
