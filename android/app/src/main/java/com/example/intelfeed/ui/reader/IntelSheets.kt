package com.example.intelfeed.ui.reader

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import coil.compose.AsyncImage
import com.example.intelfeed.data.model.EntityType
import com.example.intelfeed.data.model.GlossaryTerm
import com.example.intelfeed.theme.SlateDark800
import com.example.intelfeed.theme.TextMuted
import com.example.intelfeed.theme.TextPrimary
import com.example.intelfeed.theme.TextSecondary
import com.example.intelfeed.ui.components.Pill
import com.example.intelfeed.ui.components.color
import com.example.intelfeed.ui.entity.severityTone
import java.util.Locale

/**
 * The web reader's entity popover as a bottom sheet: type (plus KEV and severity for a CVE), the
 * phrase from the article, key facts, description, lookup links, and Profile / Search / Copy.
 * The web's Enrich and "Wrong?" actions change shared server data and aren't offered here.
 */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun EntityPreviewSheet(
    preview: EntityPreview,
    onProfile: () -> Unit,
    onSearch: () -> Unit,
    onCopy: () -> Unit,
    onLink: (String) -> Unit,
    onDismiss: () -> Unit
) {
    val color = preview.type.color()
    ModalBottomSheet(onDismissRequest = onDismiss, containerColor = SlateDark800) {
        Column(
            Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .navigationBarsPadding()
                .padding(horizontal = 20.dp)
                .padding(bottom = 16.dp)
        ) {
            FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Pill(preview.type.label, color, filled = true)
                if (preview.kev) Pill("KEV", Color(0xFFDC2626), filled = true)
                preview.severity?.takeIf { it.isNotBlank() }?.let { Pill(it.lowercase(Locale.US), severityTone(it).color()) }
            }
            Spacer(Modifier.height(10.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                preview.imageUrl?.let {
                    AsyncImage(
                        model = it,
                        contentDescription = null,
                        contentScale = ContentScale.Crop,
                        modifier = Modifier.size(40.dp).clip(RoundedCornerShape(6.dp))
                    )
                    Spacer(Modifier.width(10.dp))
                }
                SelectionContainer {
                    Text(
                        preview.value,
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold,
                        color = TextPrimary,
                        fontFamily = if (preview.type == EntityType.OBSERVABLE || preview.type == EntityType.CVE) FontFamily.Monospace else null
                    )
                }
            }
            if (!preview.name.equals(preview.value, ignoreCase = true)) {
                Text(preview.name, fontSize = 13.sp, color = TextMuted)
            }
            if (preview.facts.isNotEmpty() || preview.description != null) {
                Spacer(Modifier.height(12.dp))
                preview.facts.forEach { (label, value) -> FactLine(label, value) }
                preview.description?.let {
                    Spacer(Modifier.height(6.dp))
                    Text("Description", fontSize = 11.sp, color = TextMuted, fontWeight = FontWeight.SemiBold)
                    Text(it, fontSize = 13.sp, color = TextSecondary, lineHeight = 18.sp)
                }
            }
            if (preview.artifacts.isNotEmpty()) {
                Spacer(Modifier.height(10.dp))
                Text("Detection artifacts", fontSize = 11.sp, color = TextMuted, fontWeight = FontWeight.SemiBold)
                preview.artifacts.forEach { (label, value) -> FactLine(label, value) }
            }
            if (preview.links.isNotEmpty()) {
                Spacer(Modifier.height(12.dp))
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    preview.links.take(4).forEach { link ->
                        Pill(link.label, TextSecondary, leadingIcon = Icons.AutoMirrored.Filled.OpenInNew, onClick = { onLink(link.url) })
                    }
                }
            }
            Spacer(Modifier.height(16.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                OutlinedButton(onClick = onProfile, modifier = Modifier.weight(1f)) {
                    Icon(Icons.Default.Person, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("Profile")
                }
                OutlinedButton(onClick = onSearch, modifier = Modifier.weight(1f)) {
                    Icon(Icons.Default.Search, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("Search")
                }
                OutlinedButton(onClick = onCopy, modifier = Modifier.weight(1f)) {
                    Icon(Icons.Default.ContentCopy, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("Copy")
                }
            }
        }
    }
}

// The web's colours for glossary categories (NIST CSF functions).
private fun glossaryCategoryColor(category: String): Color = when (category.lowercase()) {
    "govern" -> Color(0xFF6366F1)
    "identify" -> Color(0xFF3B82F6)
    "protect" -> Color(0xFF22C55E)
    "detect" -> Color(0xFFF59E0B)
    "respond" -> Color(0xFFEF4444)
    "recover" -> Color(0xFF8B5CF6)
    else -> Color(0xFF6B7280)
}

/**
 * The web's glossary tooltip: term, category and maturity, description, up to five technologies,
 * and "Search articles" (the term and its other spellings, OR-ed).
 */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun GlossarySheet(
    term: GlossaryTerm,
    onSearchArticles: () -> Unit,
    onLink: (String) -> Unit,
    onDismiss: () -> Unit
) {
    ModalBottomSheet(onDismissRequest = onDismiss, containerColor = SlateDark800) {
        Column(
            Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .navigationBarsPadding()
                .padding(horizontal = 20.dp)
                .padding(bottom = 16.dp)
        ) {
            Text("Glossary", fontSize = 11.sp, color = TextMuted, fontWeight = FontWeight.SemiBold)
            Text(term.name, fontSize = 20.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
            Spacer(Modifier.height(8.dp))
            FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                if (term.category.isNotBlank()) Pill(term.category.uppercase(Locale.US), glossaryCategoryColor(term.category), filled = true)
                term.maturity?.takeIf { it.isNotBlank() }?.let { Pill(it, TextSecondary) }
            }
            term.description?.takeIf { it.isNotBlank() }?.let {
                Spacer(Modifier.height(10.dp))
                Text(it, fontSize = 14.sp, color = TextSecondary, lineHeight = 20.sp)
            }
            val tech = term.technologies.filter { it.name.isNotBlank() }.take(5)
            if (tech.isNotEmpty()) {
                Spacer(Modifier.height(10.dp))
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    tech.forEach { t ->
                        val url = t.url?.takeIf { it.isNotBlank() }
                        Pill(t.name, TextSecondary, leadingIcon = url?.let { Icons.AutoMirrored.Filled.OpenInNew }, onClick = url?.let { { onLink(it) } })
                    }
                }
            }
            Spacer(Modifier.height(16.dp))
            OutlinedButton(onClick = onSearchArticles, modifier = Modifier.fillMaxWidth()) {
                Icon(Icons.Default.Search, contentDescription = null, modifier = Modifier.size(16.dp))
                Spacer(Modifier.width(6.dp))
                Text("Search articles")
            }
        }
    }
}

/** The web's glossary search: the term and its search terms, each quoted, OR-ed. */
fun glossarySearchQuery(term: GlossaryTerm): String =
    (listOf(term.name) + term.searchTerms).filter { it.isNotBlank() }.joinToString(" OR ") { "\"${it.replace("\"", "")}\"" }

@Composable
private fun FactLine(label: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 3.dp)) {
        Text(label, fontSize = 12.sp, color = TextMuted, modifier = Modifier.width(110.dp))
        Text(value, fontSize = 13.sp, color = TextPrimary, modifier = Modifier.weight(1f))
    }
}
