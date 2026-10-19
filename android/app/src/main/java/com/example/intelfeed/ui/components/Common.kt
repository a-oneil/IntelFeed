package com.example.intelfeed.ui.components

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CloudOff
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.intelfeed.data.model.EntityType
import com.example.intelfeed.util.Clipboard
import com.example.intelfeed.theme.CyberAmber
import com.example.intelfeed.theme.CyberBlue
import com.example.intelfeed.theme.CyberCyan
import com.example.intelfeed.theme.CyberGreen
import com.example.intelfeed.theme.CyberOrange
import com.example.intelfeed.theme.CyberPurple
import com.example.intelfeed.theme.CyberRed
import com.example.intelfeed.theme.SlateDark600
import com.example.intelfeed.theme.SlateDark700
import com.example.intelfeed.theme.SlateDark900
import com.example.intelfeed.theme.TextMuted
import com.example.intelfeed.theme.TextPrimary
import com.example.intelfeed.theme.TextSecondary
import com.example.intelfeed.theme.ThemeEngine
import com.example.intelfeed.ui.entity.Badge
import com.example.intelfeed.ui.entity.ProfileChip
import com.example.intelfeed.ui.entity.Tone
import kotlinx.coroutines.delay

fun Tone.color(): Color = when (this) {
    Tone.NEUTRAL -> TextSecondary
    Tone.INFO -> ThemeEngine.severityColor("info")
    Tone.SUCCESS -> ThemeEngine.severityColor("low")
    Tone.WARNING -> ThemeEngine.severityColor("medium")
    Tone.DANGER -> ThemeEngine.severityColor("high")
    Tone.CRITICAL -> ThemeEngine.severityColor("critical")
    Tone.ACCENT -> ThemeEngine.domainAccentColor("dash")
}

fun Badge.color(): Color =
    if (ruleFormat != null) ThemeEngine.ruleFormatColor(ruleFormat) else tone.color()

fun ProfileChip.color(): Color =
    ref?.type?.color() ?: colorKey?.let { ThemeEngine.entityColor(it) } ?: tone.color()

/**
 * The workbench's entity colours (`--entity-*` from `/api/themes/schema`), driven by the server so
 * entity types look identical across web and mobile.
 */
fun EntityType.color(): Color = ThemeEngine.entityColor(this)


/** Small rounded label. Tappable when [onClick] is set (then at least 32dp tall for touch). */
@OptIn(ExperimentalFoundationApi::class)
@Composable
fun Pill(
    label: String,
    color: Color,
    modifier: Modifier = Modifier,
    monospace: Boolean = false,
    leadingIcon: ImageVector? = null,
    filled: Boolean = false,
    fgColor: Color? = null,
    onClick: (() -> Unit)? = null,
    onLongClick: (() -> Unit)? = null
) {
    val clickModifier = when {
        onClick != null && onLongClick != null -> Modifier.combinedClickable(onClick = onClick, onLongClick = onLongClick)
        onClick != null -> Modifier.clickable(onClick = onClick)
        onLongClick != null -> Modifier.combinedClickable(onClick = {}, onLongClick = onLongClick)
        else -> Modifier
    }
    val textColor = if (filled) (fgColor ?: ThemeEngine.contrastTextColor(color)) else color
    Surface(
        color = if (filled) color else color.copy(alpha = 0.15f),
        shape = RoundedCornerShape(6.dp),
        modifier = modifier.then(clickModifier)
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = if (onClick != null) 6.dp else 3.dp)
        ) {
            if (leadingIcon != null) {
                Icon(leadingIcon, contentDescription = null, tint = textColor, modifier = Modifier.size(13.dp))
                Spacer(Modifier.width(4.dp))
            }
            Text(
                text = label,
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold,
                color = textColor,
                fontFamily = if (monospace) FontFamily.Monospace else FontFamily.Default,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}


@Composable
fun SectionHeader(text: String, modifier: Modifier = Modifier, trailing: @Composable (() -> Unit)? = null) {
    Row(
        modifier = modifier.fillMaxWidth().padding(top = 20.dp, bottom = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = text,
            fontSize = 13.sp,
            fontWeight = FontWeight.Bold,
            color = TextSecondary,
            modifier = Modifier.weight(1f).semantics { heading() }
        )
        trailing?.invoke()
    }
}

@Composable
fun EmptyState(
    icon: ImageVector,
    title: String,
    message: String,
    modifier: Modifier = Modifier,
    iconTint: Color = SlateDark600,
    actionLabel: String? = null,
    onAction: (() -> Unit)? = null
) {
    Box(modifier = modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(icon, contentDescription = null, tint = iconTint, modifier = Modifier.size(52.dp))
            Spacer(Modifier.height(12.dp))
            Text(title, fontSize = 17.sp, fontWeight = FontWeight.Bold, color = TextPrimary, textAlign = TextAlign.Center)
            Spacer(Modifier.height(6.dp))
            Text(message, fontSize = 14.sp, color = TextMuted, textAlign = TextAlign.Center, lineHeight = 20.sp)
            if (actionLabel != null && onAction != null) {
                Spacer(Modifier.height(16.dp))
                OutlinedButton(onClick = onAction) { Text(actionLabel) }
            }
        }
    }
}

@Composable
fun ErrorState(message: String, onRetry: (() -> Unit)?, modifier: Modifier = Modifier) {
    EmptyState(
        icon = Icons.Default.CloudOff,
        title = "Couldn't load this",
        message = message,
        iconTint = CyberAmber,
        actionLabel = if (onRetry != null) "Try again" else null,
        onAction = onRetry,
        modifier = modifier
    )
}

@Composable
fun LoadingBox(modifier: Modifier = Modifier, color: Color = CyberBlue) {
    Box(modifier = modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        CircularProgressIndicator(color = color, strokeWidth = 2.dp)
    }
}

/**
 * A loading state for requests that can be slow (some searches and unread lists take 8–10 s on
 * the server). After a few seconds it says so, so the app doesn't look stuck.
 */
@Composable
fun SlowLoadingState(message: String, modifier: Modifier = Modifier) {
    var slow by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        delay(3_000)
        slow = true
    }
    Column(modifier = modifier.fillMaxWidth().padding(top = 96.dp, start = 32.dp, end = 32.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        CircularProgressIndicator(color = CyberBlue, strokeWidth = 2.dp, modifier = Modifier.size(28.dp))
        Spacer(Modifier.height(14.dp))
        Text(message, fontSize = 14.sp, color = TextSecondary, textAlign = TextAlign.Center)
        if (slow) {
            Spacer(Modifier.height(6.dp))
            Text("The server is taking a moment. Hang on…", fontSize = 13.sp, color = TextMuted, textAlign = TextAlign.Center)
        }
    }
}

@Composable
fun InlineLoading(modifier: Modifier = Modifier, color: Color = CyberBlue) {
    Box(modifier = modifier.fillMaxWidth().padding(16.dp), contentAlignment = Alignment.Center) {
        CircularProgressIndicator(modifier = Modifier.size(22.dp), color = color, strokeWidth = 2.dp)
    }
}

/** A full-width "Load more" button for lists that don't auto-page. */
@Composable
fun LoadMoreButton(label: String, loading: Boolean, onClick: () -> Unit, modifier: Modifier = Modifier) {
    Box(modifier = modifier.fillMaxWidth().padding(vertical = 8.dp), contentAlignment = Alignment.Center) {
        if (loading) CircularProgressIndicator(modifier = Modifier.size(22.dp), color = CyberBlue, strokeWidth = 2.dp)
        else OutlinedButton(onClick = onClick) { Text(label) }
    }
}

@Composable
fun PrimaryButton(text: String, onClick: () -> Unit, modifier: Modifier = Modifier, icon: ImageVector? = null, enabled: Boolean = true) {
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = modifier,
        colors = ButtonDefaults.buttonColors(
            containerColor = CyberBlue,
            contentColor = ThemeEngine.color("accent-fg", ThemeEngine.contrastTextColor(CyberBlue))
        )
    ) {
        if (icon != null) {
            Icon(icon, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(8.dp))
        }
        Text(text, fontWeight = FontWeight.Bold)
    }
}


/** Two-column label/value row for profile facts. Long-press to copy value. */
@OptIn(ExperimentalFoundationApi::class)
@Composable
fun FactRow(label: String, value: String) {
    val context = LocalContext.current
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(4.dp))
            .combinedClickable(
                onClick = {},
                onLongClick = { Clipboard.copy(context, label, value) }
            )
            .padding(vertical = 5.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text(label, fontSize = 13.sp, color = TextMuted, modifier = Modifier.width(128.dp))
        Text(value, fontSize = 13.sp, color = TextPrimary, modifier = Modifier.weight(1f))
    }
}

/** Divider-ish spacer used between cards in scrolling screens. */
@Composable
fun CardSurface(modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    Surface(color = SlateDark700.copy(alpha = 0.55f), shape = RoundedCornerShape(12.dp), modifier = modifier.fillMaxWidth()) {
        content()
    }
}
