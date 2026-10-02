package com.example.intelfeed.ui.reader

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.automirrored.filled.VolumeUp
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.intelfeed.theme.CyberBlue
import com.example.intelfeed.theme.SlateDark700
import com.example.intelfeed.theme.SlateDark800
import com.example.intelfeed.theme.TextMuted
import com.example.intelfeed.theme.TextPrimary
import com.example.intelfeed.theme.TextSecondary

private val SPEECH_RATES = listOf(
    0.85f to "0.85x  ·  Relaxed",
    1.0f to "1.0x  ·  Normal (Recommended)",
    1.15f to "1.15x  ·  Brisk",
    1.3f to "1.3x  ·  Fast"
)

@Composable
fun VoiceSettingsDialog(
    currentRate: Float,
    onSelectRate: (Float) -> Unit,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.AutoMirrored.Filled.VolumeUp, contentDescription = null, tint = CyberBlue, modifier = Modifier.size(24.dp))
                Spacer(Modifier.width(10.dp))
                Text("Read aloud voice & speed", fontSize = 18.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
            }
        },
        text = {
            Column {
                Text(
                    text = "IntelFeed automatically selects high-definition neural voices on your device and smooths technical text for natural speech.",
                    fontSize = 13.sp,
                    color = TextMuted,
                    lineHeight = 18.sp
                )

                Spacer(Modifier.height(14.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Speed, contentDescription = null, tint = TextSecondary, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("Reading speed", fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = TextSecondary)
                }
                Spacer(Modifier.height(6.dp))

                SPEECH_RATES.forEach { (rate, label) ->
                    val isSelected = kotlin.math.abs(currentRate - rate) < 0.05f
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(8.dp))
                            .selectable(selected = isSelected, onClick = { onSelectRate(rate) }, role = Role.RadioButton)
                            .padding(vertical = 6.dp, horizontal = 4.dp)
                    ) {
                        RadioButton(selected = isSelected, onClick = null)
                        Spacer(Modifier.width(10.dp))
                        Text(label, fontSize = 14.sp, color = if (isSelected) TextPrimary else TextSecondary)
                    }
                }

                Spacer(Modifier.height(14.dp))
                HorizontalDivider(color = SlateDark700)
                Spacer(Modifier.height(12.dp))

                Surface(
                    color = SlateDark800,
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(10.dp))
                        .clickable { ArticleSpeaker.openSystemTtsSettings(context) }
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.padding(12.dp)
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("System Voice Models", fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = TextPrimary)
                            Text(
                                "Install or change Google's natural studio voices in Android settings",
                                fontSize = 12.sp,
                                color = TextMuted
                            )
                        }
                        Spacer(Modifier.width(8.dp))
                        Icon(Icons.AutoMirrored.Filled.OpenInNew, contentDescription = null, tint = CyberBlue, modifier = Modifier.size(18.dp))
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text("Done", color = CyberBlue)
            }
        }
    )
}
