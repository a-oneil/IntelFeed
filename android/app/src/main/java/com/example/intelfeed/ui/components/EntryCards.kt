package com.example.intelfeed.ui.components

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.clickable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.CallSplit
import androidx.compose.material.icons.filled.AutoStories
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.DoneAll
import androidx.compose.material.icons.filled.Bookmark
import androidx.compose.material.icons.filled.BookmarkBorder
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.RadioButtonUnchecked
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.StarBorder
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import com.example.intelfeed.data.model.DailySummary
import com.example.intelfeed.ui.entity.EntityRef
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import coil.compose.AsyncImage
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.intelfeed.data.model.EntityType
import com.example.intelfeed.data.model.EntryIntelCounts
import com.example.intelfeed.data.model.EntryItem
import com.example.intelfeed.data.model.Signal
import com.example.intelfeed.data.model.StoryThread
import com.example.intelfeed.theme.CyberAmber
import com.example.intelfeed.theme.CyberBlue
import com.example.intelfeed.theme.CyberGreen
import com.example.intelfeed.theme.CyberOrange
import com.example.intelfeed.theme.CyberPurple
import com.example.intelfeed.theme.CyberRed
import com.example.intelfeed.theme.SlateDark700
import com.example.intelfeed.theme.SlateDark800
import com.example.intelfeed.theme.SlateDark900
import com.example.intelfeed.theme.TextMuted
import com.example.intelfeed.theme.TextPrimary
import com.example.intelfeed.theme.TextSecondary
import com.example.intelfeed.util.DateUtils
import com.example.intelfeed.util.HtmlText
import java.util.Locale
import com.example.intelfeed.ui.reader.ReaderFontSize
import com.example.intelfeed.util.MarkdownText
import com.example.intelfeed.data.model.DayIntel
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.foundation.layout.widthIn
import androidx.compose.ui.draw.drawBehind
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.horizontalScroll

/** One item in a card's overflow menu. */
data class CardAction(val label: String, val icon: ImageVector? = null, val onClick: () -> Unit)

/**
 * Priority score colour bands. Scores run 0–10, ranked against the last 30 days (9 ≈ top 5%,
 * 10 = top 1%), and the Radar threshold sits around 8. Red and orange match the web app's
 * high/medium bands (frontend/src/utils/signalBand.ts).
 */
fun scoreColor(score: Double): Color = when {
    score >= 9.5 -> CyberRed
    score >= 8.5 -> CyberOrange
    score >= 7 -> CyberAmber
    else -> CyberBlue
}

fun signalFamilyColor(family: String?): Color = when (family?.lowercase()) {
    "novelty" -> CyberPurple
    "coverage" -> CyberBlue
    "severity" -> CyberRed
    "interest" -> CyberGreen
    "content" -> CyberAmber
    else -> TextSecondary
}

/** Readable names for the signal engine's types; unknown ones are humanized ("novel_entity" -> "Novel entity"). */
fun signalLabel(type: String): String = when (type) {
    "pir_match" -> "PIR match"
    "kev_added" -> "Added to KEV"
    "epss_jump" -> "EPSS jump"
    "epss_high" -> "High EPSS"
    "critical_cvss" -> "Critical CVSS"
    "weaponized_poc" -> "Weaponized PoC"
    "feed_echo" -> "Re-report"
    else -> type.replace('_', ' ').replaceFirstChar { it.titlecase(Locale.US) }
}

@Composable
fun ScoreBadge(score: Double, modifier: Modifier = Modifier) {
    val color = scoreColor(score)
    Surface(color = color.copy(alpha = 0.16f), shape = RoundedCornerShape(6.dp), modifier = modifier) {
        Text(
            text = "◆ " + String.format(Locale.US, "%.1f", score),
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            color = color,
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
        )
    }
}

@Composable
private fun SignalLine(signal: Signal) {
    Row(verticalAlignment = Alignment.Top, modifier = Modifier.padding(top = 3.dp)) {
        Box(
            modifier = Modifier
                .padding(top = 6.dp)
                .size(6.dp)
                .background(signalFamilyColor(signal.family ?: familyOf(signal.type)), CircleShape)
        )
        Spacer(Modifier.width(6.dp))
        Text(
            text = signal.explanation.ifBlank { signalLabel(signal.type) },
            fontSize = 12.sp,
            color = TextSecondary,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
    }
}

/** List items only carry the signal type; the family comes from the engine's fixed grouping. */
fun familyOf(type: String): String? = when (type) {
    "novel_entity", "entity_resurgence", "new_pairing", "scoop" -> "novelty"
    "source_convergence", "under_reported", "feed_echo" -> "coverage"
    "kev_added", "epss_jump", "epss_high", "weaponized_poc", "critical_cvss" -> "severity"
    "pir_match", "correlation_event", "watchlist" -> "interest"
    "detection_content", "research_depth" -> "content"
    else -> null
}

/**
 * An article row. Tap opens it; long-press starts multi-select when [onLongClick] is set. In
 * [selectionMode] a tap toggles selection instead.
 */
@OptIn(ExperimentalFoundationApi::class, ExperimentalLayoutApi::class)
@Composable
fun EntryCard(
    entry: EntryItem,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    onLongClick: (() -> Unit)? = null,
    selectionMode: Boolean = false,
    selected: Boolean = false,
    compact: Boolean = false,
    // The web list's intel badges for this article (POST /api/entries/intel-counts), if loaded.
    intel: EntryIntelCounts? = null,
    // Tapping a tag runs a search for it; null leaves tags as plain labels.
    onTagClick: ((String) -> Unit)? = null,
    onToggleStar: (() -> Unit)? = null,
    onToggleBookmark: (() -> Unit)? = null,
    menuActions: List<CardAction> = emptyList()
) {
    val borderColor = if (selected) CyberBlue else Color.Transparent
    Surface(
        color = if (selected) CyberBlue.copy(alpha = 0.12f) else SlateDark800,
        shape = RoundedCornerShape(12.dp),
        modifier = modifier
            .fillMaxWidth()
            .border(1.5.dp, borderColor, RoundedCornerShape(12.dp))
            .clip(RoundedCornerShape(12.dp))
            .combinedClickable(
                onClick = onClick,
                onLongClick = onLongClick,
                onLongClickLabel = if (onLongClick != null) "Select" else null
            )
            .semantics {
                stateDescription = buildString {
                    append(if (entry.isRead) "Read" else "Unread")
                    if (entry.isStarred) append(", starred")
                    if (entry.isBookmarked) append(", bookmarked")
                    if (selectionMode) append(if (selected) ", selected" else ", not selected")
                }
            }
    ) {
        Column(
            modifier = Modifier
                .padding(start = 14.dp, end = 6.dp, top = 12.dp, bottom = if (compact) 12.dp else 4.dp)
                .alpha(if (entry.isEcho && entry.isRead) 0.7f else 1f)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(end = 8.dp)) {
                if (selectionMode) {
                    Icon(
                        imageVector = if (selected) Icons.Filled.CheckCircle else Icons.Filled.RadioButtonUnchecked,
                        contentDescription = null,
                        tint = if (selected) CyberBlue else TextMuted,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(Modifier.width(8.dp))
                } else if (!entry.isRead) {
                    Box(Modifier.size(8.dp).background(CyberBlue, CircleShape))
                    Spacer(Modifier.width(7.dp))
                }
                val source = entry.feedTitle?.takeIf { it.isNotBlank() }
                if (source != null) {
                    Text(
                        text = source,
                        fontSize = 12.sp,
                        color = TextSecondary,
                        fontWeight = FontWeight.Medium,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f, fill = false)
                    )
                }
                if (entry.isEcho) {
                    Spacer(Modifier.width(6.dp))
                    Pill("Re-report", TextMuted)
                }
                Spacer(Modifier.weight(1f))
                entry.priorityScore?.takeIf { it > 0 }?.let {
                    ScoreBadge(it)
                    Spacer(Modifier.width(8.dp))
                }
                Text(DateUtils.formatRelativeTime(entry.publishedAt), fontSize = 12.sp, color = TextMuted, maxLines = 1)
            }

            Spacer(Modifier.height(6.dp))
            Text(
                text = entry.displayTitle,
                fontSize = 15.sp,
                fontWeight = if (!entry.isRead) FontWeight.Bold else FontWeight.Medium,
                color = if (!entry.isRead) TextPrimary else TextSecondary,
                maxLines = if (compact) 2 else 3,
                overflow = TextOverflow.Ellipsis,
                lineHeight = 20.sp,
                modifier = Modifier.padding(end = 8.dp)
            )

            if (!compact && !entry.summary.isNullOrBlank()) {
                val snippet = remember(entry.summary) { HtmlText.toSnippet(entry.summary) }
                if (snippet.isNotBlank()) {
                    Spacer(Modifier.height(4.dp))
                    Text(
                        text = snippet,
                        fontSize = 13.sp,
                        color = TextMuted,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                        lineHeight = 18.sp,
                        modifier = Modifier.padding(end = 8.dp)
                    )
                }
            }

            // The web shows the intel line in compact rows too.
            if (intel != null) IntelCueRow(intel)

            if (!compact && entry.topSignals.isNotEmpty()) {
                Spacer(Modifier.height(4.dp))
                entry.topSignals.take(2).forEach { SignalLine(it) }
            }

            if (!compact && entry.tags.isNotEmpty()) {
                Spacer(Modifier.height(6.dp))
                FlowRow(horizontalArrangement = Arrangement.spacedBy(4.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    entry.tags.take(4).forEach { tag ->
                        Pill("#${tag.name}", tagColor(tag.color), onClick = onTagClick?.let { { it(tag.name) } })
                    }
                }
            }

            if (!compact && !selectionMode && (onToggleStar != null || onToggleBookmark != null || menuActions.isNotEmpty())) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    val minutes = DateUtils.readingMinutes(entry.wordCount)
                    val author = entry.author?.takeIf { it.isNotBlank() && it.length < 40 }
                    Text(
                        text = listOfNotNull(author, minutes?.let { "$it min read" }).joinToString(" · "),
                        fontSize = 12.sp,
                        color = TextMuted,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f)
                    )
                    if (onToggleBookmark != null) {
                        IconButton(onClick = onToggleBookmark) {
                            Icon(
                                imageVector = if (entry.isBookmarked) Icons.Filled.Bookmark else Icons.Filled.BookmarkBorder,
                                contentDescription = if (entry.isBookmarked) "Remove bookmark" else "Bookmark",
                                tint = if (entry.isBookmarked) CyberBlue else TextMuted,
                                modifier = Modifier.size(20.dp)
                            )
                        }
                    }
                    if (onToggleStar != null) {
                        IconButton(onClick = onToggleStar) {
                            Icon(
                                imageVector = if (entry.isStarred) Icons.Filled.Star else Icons.Filled.StarBorder,
                                contentDescription = if (entry.isStarred) "Unstar" else "Star",
                                tint = if (entry.isStarred) CyberAmber else TextMuted,
                                modifier = Modifier.size(20.dp)
                            )
                        }
                    }
                    if (menuActions.isNotEmpty()) {
                        var open by remember { mutableStateOf(false) }
                        Box {
                            IconButton(onClick = { open = true }) {
                                Icon(Icons.Filled.MoreVert, contentDescription = "More actions", tint = TextMuted, modifier = Modifier.size(20.dp))
                            }
                            DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
                                menuActions.forEach { action ->
                                    DropdownMenuItem(
                                        text = { Text(action.label) },
                                        leadingIcon = action.icon?.let { { Icon(it, contentDescription = null) } },
                                        onClick = { open = false; action.onClick() }
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/** How a cue is drawn, following the web's intel-line chip classes. */
enum class CueStyle { NORMAL, HIGH, STRONG, DASHED, DASHED_ITALIC }

/**
 * One small cue on a card ("Qilin +1", "2 PIR", "3 TTPs", "KEV opportunity"); [description] is
 * read by screen readers. [pirs] is set on the PIR cue, which opens the matched requirements.
 */
data class IntelCue(
    val text: String,
    val color: Color,
    val description: String,
    val style: CueStyle = CueStyle.NORMAL,
    val pirs: List<com.example.intelfeed.data.model.PirMatch> = emptyList()
)

// The web's --entity-pir, #dc2626 (critical CVE, KEV opportunity) and --warning.
private val PirColor = Color(0xFF06B6D4)
private val CriticalRed = Color(0xFFDC2626)
private val WarningColor = Color(0xFFD29922)

/** The web's PIR categories, in its order, with its --pir-* colours. */
val PIR_CATEGORIES = listOf(
    "tactical" to Color(0xFFEF4444),
    "operational" to Color(0xFFF97316),
    "technical" to Color(0xFF06B6D4),
    "strategic" to Color(0xFF8B5CF6)
)

/**
 * The web list's intel line (IntelBadges), in its order: notes; the lead actor or malware (+ how
 * many more) and the PIR matches; then TTPs, CVEs (stronger when the worst is high or critical)
 * and rules; then the detection opportunity: "KEV opportunity" / "high-risk opportunity" when a
 * KEV or high-risk CVE has no rule, else "detection opportunity" or "telemetry gap".
 */
fun intelCues(c: EntryIntelCounts): List<IntelCue> = buildList {
    if (c.notes > 0) add(IntelCue(if (c.notes == 1) "1 note" else "${c.notes} notes", TextSecondary, "${c.notes} analyst note${if (c.notes == 1) "" else "s"}"))
    val lead = c.actors.firstOrNull() ?: c.malware.firstOrNull()
    if (lead != null) {
        // The web adds the two counts (actor_count, malware_count) and shows the rest as +N.
        val all = (c.actorCount.takeIf { it > 0 } ?: c.actors.size) + (c.malwareCount.takeIf { it > 0 } ?: c.malware.size)
        val color = if (c.actors.isNotEmpty()) EntityType.THREAT_ACTOR.color() else EntityType.MALWARE.color()
        val kind = if (c.actors.isNotEmpty()) "Threat actor" else "Malware"
        add(IntelCue(if (all > 1) "$lead +${all - 1}" else lead, color, "$kind: " + (c.actors + c.malware).joinToString(", ")))
    }
    if (c.pirMatches.isNotEmpty()) {
        add(IntelCue("${c.pirMatches.size} PIR", PirColor,
            "Matches ${c.pirMatches.size} of your standing intelligence requirements: " + c.pirMatches.joinToString(", ") { it.title },
            pirs = c.pirMatches))
    }
    if (c.ttps > 0) add(IntelCue("${c.ttps} ${if (c.ttps == 1) "TTP" else "TTPs"}", EntityType.TTP.color(), "${c.ttps} MITRE ATT&CK technique${if (c.ttps == 1) "" else "s"}"))
    if (c.cves > 0) {
        val severity = c.cveMaxSeverity?.lowercase()
        val (color, style) = when (severity) {
            "critical" -> CriticalRed to CueStyle.STRONG
            "high" -> EntityType.CVE.color() to CueStyle.HIGH
            else -> EntityType.CVE.color() to CueStyle.NORMAL
        }
        add(IntelCue("${c.cves} ${if (c.cves == 1) "CVE" else "CVEs"}", color,
            "${c.cves} CVE${if (c.cves == 1) "" else "s"} referenced" + (severity?.let { ", worst severity $it" } ?: ""), style))
    }
    if (c.rules > 0) add(IntelCue("${c.rules} ${if (c.rules == 1) "Rule" else "Rules"}", EntityType.RULE.color(), "${c.rules} detection rule${if (c.rules == 1) "" else "s"}"))
    val opportunity = c.detectionOpportunity ?: if (c.hasDetectionGap) "actionable_gap" else null
    when {
        c.hasDetectionGap && c.hasHighRiskCve && c.hasKevCve ->
            add(IntelCue("KEV opportunity", CriticalRed, "CISA KEV CVE (actively exploited) with no detection rules", CueStyle.STRONG))
        c.hasDetectionGap && c.hasHighRiskCve ->
            add(IntelCue("high-risk opportunity", WarningColor, "High-risk CVE with no detection rules", CueStyle.STRONG))
        opportunity == "actionable_gap" ->
            add(IntelCue("detection opportunity", WarningColor, "No detection rule exists for the observed TTPs or CVEs", CueStyle.DASHED))
        opportunity == "telemetry_gap" ->
            add(IntelCue("telemetry gap", TextSecondary, "Library rules exist, but their data sources aren't in your telemetry", CueStyle.DASHED_ITALIC))
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun IntelCueRow(counts: EntryIntelCounts) {
    val cues = remember(counts) { intelCues(counts) }
    if (cues.isEmpty()) return
    var pirSheet by remember { mutableStateOf<List<com.example.intelfeed.data.model.PirMatch>?>(null) }
    FlowRow(
        horizontalArrangement = Arrangement.spacedBy(6.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
        modifier = Modifier.padding(top = 6.dp, end = 8.dp)
    ) {
        cues.forEach { cue ->
            val onClick: (() -> Unit)? = if (cue.pirs.isNotEmpty()) ({ pirSheet = cue.pirs }) else null
            IntelCueChip(cue, onClick)
        }
    }
    pirSheet?.let { PirMatchesSheet(it, onDismiss = { pirSheet = null }) }
}

@Composable
private fun IntelCueChip(cue: IntelCue, onClick: (() -> Unit)?) {
    val c = cue.color
    val (bg, border) = when (cue.style) {
        CueStyle.NORMAL -> 0.12f to 0.30f
        CueStyle.HIGH -> 0.18f to 0.45f
        CueStyle.STRONG -> if (c == CriticalRed) 0.22f to 0.58f else 0.20f to 0.55f
        CueStyle.DASHED, CueStyle.DASHED_ITALIC -> 0f to 0.5f
    }
    // The web mixes the chip colour into the secondary text colour; strong and dashed chips use it pure.
    val textColor = when (cue.style) {
        CueStyle.NORMAL, CueStyle.HIGH -> androidx.compose.ui.graphics.lerp(c, TextSecondary, 0.45f)
        CueStyle.STRONG -> androidx.compose.ui.graphics.lerp(c, TextSecondary, 0.3f)
        else -> c
    }
    val shape = RoundedCornerShape(6.dp)
    val dashed = cue.style == CueStyle.DASHED || cue.style == CueStyle.DASHED_ITALIC
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .heightIn(min = 22.dp)
            .clip(shape)
            .background(c.copy(alpha = bg), shape)
            .then(
                if (dashed) Modifier.drawBehind {
                    drawRoundRect(
                        color = c.copy(alpha = border),
                        cornerRadius = androidx.compose.ui.geometry.CornerRadius(6.dp.toPx()),
                        style = androidx.compose.ui.graphics.drawscope.Stroke(
                            width = 1.dp.toPx(),
                            pathEffect = androidx.compose.ui.graphics.PathEffect.dashPathEffect(floatArrayOf(4.dp.toPx(), 3.dp.toPx()))
                        )
                    )
                } else Modifier.border(1.dp, c.copy(alpha = border), shape)
            )
            .then(if (onClick != null) Modifier.clickable(onClickLabel = "Show matched requirements", onClick = onClick) else Modifier)
            .semantics { contentDescription = cue.description }
            .padding(horizontal = 7.dp, vertical = 2.dp)
    ) {
        Text(
            cue.text,
            fontSize = 11.sp,
            color = textColor,
            fontWeight = if (cue.style == CueStyle.STRONG) FontWeight.SemiBold else FontWeight.Medium,
            fontStyle = if (cue.style == CueStyle.DASHED_ITALIC) androidx.compose.ui.text.font.FontStyle.Italic else null,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.widthIn(max = 180.dp)
        )
        if (cue.pirs.isNotEmpty()) {
            Spacer(Modifier.width(5.dp))
            PirCategoryBar(cue.pirs)
            Text(" ▾", fontSize = 10.sp, color = textColor)
        }
    }
}

/** The PIR chip's small bar: one segment per category, as wide as its share of the matches. */
@Composable
private fun PirCategoryBar(pirs: List<com.example.intelfeed.data.model.PirMatch>) {
    Row(Modifier.width(40.dp).height(5.dp).clip(RoundedCornerShape(2.dp)), horizontalArrangement = Arrangement.spacedBy(1.dp)) {
        PIR_CATEGORIES.forEach { (category, color) ->
            val n = pirs.count { it.category.equals(category, ignoreCase = true) }
            if (n > 0) Box(Modifier.weight(n.toFloat()).fillMaxHeight().background(color))
        }
    }
}

/**
 * The web's PIR popover: the matched requirements by category, each with why it matched; tapping
 * one searches `pir:"<title>"`. Uses [LocalIntelNavigation] for the search and the requirements page.
 */
@OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)
@Composable
fun PirMatchesSheet(pirs: List<com.example.intelfeed.data.model.PirMatch>, onDismiss: () -> Unit) {
    val nav = LocalIntelNavigation.current
    androidx.compose.material3.ModalBottomSheet(onDismissRequest = onDismiss, containerColor = SlateDark800) {
        Column(
            Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .navigationBarsPadding()
                .padding(horizontal = 20.dp)
                .padding(bottom = 16.dp)
        ) {
            Text("Matches ${pirs.size} of your standing intelligence requirements", fontSize = 15.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
            val known = PIR_CATEGORIES.map { it.first }
            val groups = PIR_CATEGORIES.map { (cat, color) -> Triple(cat, color, pirs.filter { it.category.equals(cat, ignoreCase = true) }) } +
                Triple("other", TextSecondary, pirs.filter { p -> known.none { it.equals(p.category, ignoreCase = true) } })
            groups.filter { it.third.isNotEmpty() }.forEach { (cat, color, items) ->
                Spacer(Modifier.height(12.dp))
                Text(cat.uppercase(Locale.US), fontSize = 11.sp, fontWeight = FontWeight.Bold, color = color)
                items.forEach { p ->
                    Column(
                        Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(8.dp))
                            .clickable { onDismiss(); nav.searchQuery("pir:\"${p.title.replace("\"", "")}\"") }
                            .padding(vertical = 8.dp)
                    ) {
                        Text(p.title, fontSize = 14.sp, color = TextPrimary, fontWeight = FontWeight.Medium)
                        p.matchedOn?.takeIf { it.isNotBlank() }?.let { on ->
                            val how = when (p.matchType) { "entity" -> "entity"; "manual" -> "manual"; else -> "keyword" }
                            Text(listOfNotNull("$how: $on", p.relevance?.let { "$it relevance" }).joinToString(" · "), fontSize = 12.sp, color = TextMuted)
                        }
                    }
                }
            }
            Spacer(Modifier.height(10.dp))
            Text(
                "Requirements are yours to edit →",
                fontSize = 13.sp,
                color = CyberBlue,
                modifier = Modifier.clip(RoundedCornerShape(6.dp)).clickable { onDismiss(); nav.openRequirements() }.padding(vertical = 8.dp)
            )
        }
    }
}

/** App-level navigation the list cards' intel sheets need; provided in MainNavigation. */
class IntelNavigation(val searchQuery: (String) -> Unit = {}, val openRequirements: () -> Unit = {})

val LocalIntelNavigation = androidx.compose.runtime.staticCompositionLocalOf { IntelNavigation() }

/**
 * A magazine/grid card for the 2-column feed view. Displays article thumbnail if available,
 * score badge, source, title, snippet, tags, and quick-action bar.
 */
@OptIn(ExperimentalFoundationApi::class, ExperimentalLayoutApi::class)
@Composable
fun EntryGridCard(
    entry: EntryItem,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    intel: EntryIntelCounts? = null,
    onLongClick: (() -> Unit)? = null,
    selectionMode: Boolean = false,
    selected: Boolean = false,
    onTagClick: ((String) -> Unit)? = null,
    onToggleStar: (() -> Unit)? = null,
    onToggleBookmark: (() -> Unit)? = null,
    menuActions: List<CardAction> = emptyList()
) {
    val borderColor = if (selected) CyberBlue else SlateDark700.copy(alpha = 0.6f)
    val hasImage = !entry.imageUrl.isNullOrBlank()

    Surface(
        color = if (selected) CyberBlue.copy(alpha = 0.12f) else SlateDark800,
        shape = RoundedCornerShape(12.dp),
        modifier = modifier
            .fillMaxWidth()
            .border(if (selected) 2.dp else 1.dp, borderColor, RoundedCornerShape(12.dp))
            .clip(RoundedCornerShape(12.dp))
            .combinedClickable(
                onClick = onClick,
                onLongClick = onLongClick,
                onLongClickLabel = if (onLongClick != null) "Select" else null
            )
            .semantics {
                stateDescription = buildString {
                    append(if (entry.isRead) "Read" else "Unread")
                    if (entry.isStarred) append(", starred")
                    if (entry.isBookmarked) append(", bookmarked")
                    if (selectionMode) append(if (selected) ", selected" else ", not selected")
                }
            }
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .alpha(if (entry.isEcho && entry.isRead) 0.7f else 1f)
        ) {
            // Hero Thumbnail or Subtle Gradient Header
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(if (hasImage) 110.dp else 36.dp)
                    .background(
                        Brush.verticalGradient(
                            listOf(
                                SlateDark700.copy(alpha = 0.7f),
                                SlateDark800
                            )
                        )
                    )
            ) {
                if (hasImage) {
                    AsyncImage(
                        model = entry.imageUrl,
                        contentDescription = null,
                        contentScale = ContentScale.Crop,
                        modifier = Modifier
                            .fillMaxSize()
                            .clip(RoundedCornerShape(topStart = 12.dp, topEnd = 12.dp))
                    )
                    // Scrim gradient over image bottom
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .background(
                                Brush.verticalGradient(
                                    listOf(Color.Transparent, Color.Black.copy(alpha = 0.6f))
                                )
                            )
                    )
                }

                // Top badges row (selection checkbox, unread dot, priority score)
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 8.dp, vertical = 6.dp)
                        .align(Alignment.TopStart),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    if (selectionMode) {
                        Surface(
                            color = SlateDark900.copy(alpha = 0.85f),
                            shape = CircleShape,
                            modifier = Modifier.size(24.dp)
                        ) {
                            Box(contentAlignment = Alignment.Center) {
                                Icon(
                                    imageVector = if (selected) Icons.Filled.CheckCircle else Icons.Filled.RadioButtonUnchecked,
                                    contentDescription = null,
                                    tint = if (selected) CyberBlue else TextMuted,
                                    modifier = Modifier.size(18.dp)
                                )
                            }
                        }
                    } else if (!entry.isRead) {
                        Box(
                            Modifier
                                .size(8.dp)
                                .background(CyberBlue, CircleShape)
                        )
                    }

                    Spacer(Modifier.weight(1f))

                    entry.priorityScore?.takeIf { it > 0 }?.let {
                        ScoreBadge(it)
                    }
                }

                // If image exists, display source & relative time over the bottom scrim
                if (hasImage) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 8.dp, vertical = 6.dp)
                            .align(Alignment.BottomStart),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        val source = entry.feedTitle?.takeIf { it.isNotBlank() }
                        if (source != null) {
                            Text(
                                text = source,
                                fontSize = 11.sp,
                                color = TextPrimary,
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                                modifier = Modifier.weight(1f, fill = false)
                            )
                        }
                        Spacer(Modifier.weight(1f))
                        Text(
                            DateUtils.formatRelativeTime(entry.publishedAt),
                            fontSize = 11.sp,
                            color = TextMuted,
                            maxLines = 1
                        )
                    }
                }
            }

            // Card Body Content
            Column(modifier = Modifier.padding(start = 10.dp, end = 10.dp, top = 8.dp, bottom = 4.dp)) {
                // When there is no image, show source and relative time here
                if (!hasImage) {
                    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
                        val source = entry.feedTitle?.takeIf { it.isNotBlank() }
                        if (source != null) {
                            Text(
                                text = source,
                                fontSize = 11.sp,
                                color = CyberBlue,
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                                modifier = Modifier.weight(1f, fill = false)
                            )
                        }
                        Spacer(Modifier.weight(1f))
                        Text(
                            DateUtils.formatRelativeTime(entry.publishedAt),
                            fontSize = 11.sp,
                            color = TextMuted,
                            maxLines = 1
                        )
                    }
                    Spacer(Modifier.height(4.dp))
                }

                // Title
                Text(
                    text = entry.displayTitle,
                    fontSize = 13.5.sp,
                    fontWeight = if (!entry.isRead) FontWeight.Bold else FontWeight.Medium,
                    color = if (!entry.isRead) TextPrimary else TextSecondary,
                    maxLines = 3,
                    overflow = TextOverflow.Ellipsis,
                    lineHeight = 18.sp
                )

                // Snippet
                if (!entry.summary.isNullOrBlank()) {
                    val snippet = remember(entry.summary) { HtmlText.toSnippet(entry.summary) }
                    if (snippet.isNotBlank()) {
                        Spacer(Modifier.height(4.dp))
                        Text(
                            text = snippet,
                            fontSize = 11.5.sp,
                            color = TextMuted,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis,
                            lineHeight = 15.sp
                        )
                    }
                }

                // The web's magazine cards carry the same intel line as its list rows.
                if (intel != null) IntelCueRow(intel)

                // Tags
                if (entry.tags.isNotEmpty()) {
                    Spacer(Modifier.height(6.dp))
                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(4.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        entry.tags.take(2).forEach { tag ->
                            Pill("#${tag.name}", tagColor(tag.color), onClick = onTagClick?.let { { it(tag.name) } })
                        }
                    }
                }

                // Card Footer Action Row
                if (!selectionMode) {
                    Spacer(Modifier.height(4.dp))
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        if (onToggleStar != null) {
                            IconButton(onClick = onToggleStar, modifier = Modifier.size(32.dp)) {
                                Icon(
                                    imageVector = if (entry.isStarred) Icons.Filled.Star else Icons.Filled.StarBorder,
                                    contentDescription = if (entry.isStarred) "Unstar" else "Star",
                                    tint = if (entry.isStarred) CyberAmber else TextMuted,
                                    modifier = Modifier.size(18.dp)
                                )
                            }
                        }
                        if (onToggleBookmark != null) {
                            IconButton(onClick = onToggleBookmark, modifier = Modifier.size(32.dp)) {
                                Icon(
                                    imageVector = if (entry.isBookmarked) Icons.Filled.Bookmark else Icons.Filled.BookmarkBorder,
                                    contentDescription = if (entry.isBookmarked) "Remove bookmark" else "Bookmark",
                                    tint = if (entry.isBookmarked) CyberBlue else TextMuted,
                                    modifier = Modifier.size(18.dp)
                                )
                            }
                        }

                        Spacer(Modifier.weight(1f))

                        if (menuActions.isNotEmpty()) {
                            var open by remember { mutableStateOf(false) }
                            Box {
                                IconButton(onClick = { open = true }, modifier = Modifier.size(32.dp)) {
                                    Icon(
                                        Icons.Filled.MoreVert,
                                        contentDescription = "More actions",
                                        tint = TextMuted,
                                        modifier = Modifier.size(18.dp)
                                    )
                                }
                                DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
                                    menuActions.forEach { action ->
                                        DropdownMenuItem(
                                            text = { Text(action.label, fontSize = 13.sp) },
                                            leadingIcon = action.icon?.let { { Icon(it, contentDescription = null, modifier = Modifier.size(18.dp)) } },
                                            onClick = { open = false; action.onClick() }
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/** A Priority Queue story row: many outlets' coverage of one story, opened as a thread. */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun StoryCard(
    title: String,
    thread: StoryThread,
    score: Double?,
    onClick: () -> Unit,
    onEntityClick: (EntityType, String, String) -> Unit,
    modifier: Modifier = Modifier
) {
    Surface(
        color = SlateDark800,
        shape = RoundedCornerShape(12.dp),
        modifier = modifier
            .fillMaxWidth()
            .border(1.dp, CyberPurple.copy(alpha = 0.35f), RoundedCornerShape(12.dp))
            .clip(RoundedCornerShape(12.dp))
            .combinedClickable(onClick = onClick)
            .semantics { contentDescription = "Story: $title, ${thread.sourceCount} outlets, ${thread.unreadCount} unread" }
    ) {
        Column(Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Pill("Story", CyberPurple, leadingIcon = Icons.Filled.AutoStories)
                Spacer(Modifier.width(8.dp))
                Text(
                    text = "${thread.sourceCount} outlets · ${thread.unreadCount} unread",
                    fontSize = 12.sp,
                    color = TextSecondary,
                    modifier = Modifier.weight(1f)
                )
                score?.takeIf { it > 0 }?.let { ScoreBadge(it); Spacer(Modifier.width(8.dp)) }
                Text(DateUtils.formatRelativeTime(thread.lastSeen), fontSize = 12.sp, color = TextMuted)
            }
            Spacer(Modifier.height(8.dp))
            Text(
                text = title,
                fontSize = 15.sp,
                fontWeight = if (thread.unreadCount > 0) FontWeight.Bold else FontWeight.Medium,
                color = TextPrimary,
                maxLines = 3,
                overflow = TextOverflow.Ellipsis,
                lineHeight = 20.sp
            )
            if (!thread.summary.isNullOrBlank()) {
                Spacer(Modifier.height(4.dp))
                Text(thread.summary, fontSize = 13.sp, color = TextMuted, maxLines = 2, overflow = TextOverflow.Ellipsis)
            }
            val entities = thread.keyEntities.take(5)
            if (entities.isNotEmpty()) {
                Spacer(Modifier.height(8.dp))
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    entities.forEach { ke ->
                        val type = EntityType.fromKey(ke.entityType)
                        val id = ke.entityId
                        if (type != null && id != null) {
                            Pill(ke.label, type.color(), onClick = { onEntityClick(type, id, ke.label) })
                        } else {
                            Pill(ke.label, TextSecondary)
                        }
                    }
                }
            }
            Spacer(Modifier.height(8.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.AutoMirrored.Filled.CallSplit, contentDescription = null, tint = CyberPurple, modifier = Modifier.size(14.dp))
                Spacer(Modifier.width(4.dp))
                Text("Open the story to see every outlet's coverage", fontSize = 12.sp, color = CyberPurple)
            }
        }
    }
}

/** One chip under a day divider; [focus] is the list filter it applies (null: nothing to filter by). */
private data class DayChip(
    val kind: String,
    val name: String,
    val extra: String?,
    val color: Color,
    val focus: com.example.intelfeed.data.model.DayFocus?
)

/** The web shows at most this many chips per day. */
private const val MAX_DAY_CHIPS = 5

/**
 * The website's day chips, in its order: exploited count, newly tracked, technique, sector, CVE,
 * actor, malware, product, country (at most five). Each one filters the list to that day's
 * articles that mention it, like the web; tapping it again shows the whole list.
 */
private fun dayChips(intel: DayIntel, dayKey: String): List<DayChip> = buildList {
    fun times(count: Int) = if (count > 1) "×$count" else null
    fun focus(chip: String, label: String, vararg params: Pair<String, String?>): com.example.intelfeed.data.model.DayFocus? {
        if (params.any { it.second.isNullOrBlank() }) return null
        return com.example.intelfeed.data.model.DayFocus(dayKey, chip, label, params.associate { it.first to it.second!! })
    }
    intel.signals.activelyExploited.takeIf { it > 0 }?.let { n ->
        add(DayChip("", "$n actively exploited", null, CyberRed, focus("signal", "articles mentioning an actively-exploited CVE", "exploited_cves" to "true")))
    }
    intel.signals.new?.let { n ->
        val type = EntityType.fromKey(n.type)
        val kind = if (type == EntityType.MALWARE) "★ new malware" else "★ new actor"
        add(DayChip(kind, n.name, if (n.total > 1) "+${n.total - 1}" else null, CyberGreen,
            focus("new", "articles mentioning ${n.name}", "entity_type" to n.type, "entity_id" to n.id)))
    }
    intel.ttp?.let { t ->
        val label = listOfNotNull(t.techniqueId, t.name.takeIf { it.isNotBlank() }).joinToString(" ")
        add(DayChip("ttp", label, times(t.count), EntityType.TTP.color(),
            focus("ttp", "articles mentioning ${t.techniqueId ?: t.name}", "entity_type" to "ttp", "entity_id" to t.id)))
    }
    intel.sector?.let { add(DayChip("sector", it.name, times(it.count), TextSecondary, focus("sector", "articles targeting ${it.name}", "sector" to it.slug))) }
    intel.cve?.let { c ->
        add(DayChip(if (c.kev) "cve · kev" else "cve", c.name, c.cvssScore?.let { String.format(Locale.US, "%.1f", it) } ?: times(c.count),
            if (c.kev) CyberRed else EntityType.CVE.color(), focus("cve", "articles mentioning ${c.name}", "entity_type" to "cve", "entity_id" to c.id)))
    }
    listOf(
        Triple("threat_actor", "actor", intel.threatActor),
        Triple("malware", "malware", intel.malware),
        Triple("product", "product", intel.product),
        Triple("country", "country", intel.country)
    ).forEach { (type, kind, e) ->
        e ?: return@forEach
        add(DayChip(kind, e.name, times(e.count), EntityType.fromKey(type)?.color() ?: TextSecondary,
            focus(type, "articles mentioning ${e.name}", "entity_type" to type, "entity_id" to e.id)))
    }
}.filter { it.name.isNotBlank() }.take(MAX_DAY_CHIPS)

/**
 * Day divider for date-ordered lists: the day's most-mentioned entities (from the server's
 * day-intel, tap to open a profile) and the saved AI briefing, which only loads when asked for.
 * Reading a saved briefing doesn't generate anything or use AI tokens.
 */
@Composable
fun DayHeader(
    label: String,
    dayKey: String,
    dayIntel: DayIntel?,
    // False until the chips were fetched (a fetched day with nothing to show is true with a null dayIntel).
    dayIntelKnown: Boolean,
    onLoadDayIntel: () -> Unit,
    dailySummary: DailySummary?,
    summaryChecked: Boolean,
    summaryLoading: Boolean,
    summaryFailed: Boolean,
    onRequestSummary: () -> Unit,
    serverUrl: String?,
    onOpenLink: (String) -> Unit,
    // The day chip filtering the list, if any, and what tapping a chip does.
    activeFocus: com.example.intelfeed.data.model.DayFocus? = null,
    onDayFocus: (com.example.intelfeed.data.model.DayFocus) -> Unit = {},
    modifier: Modifier = Modifier,
    // Shown when the day has unread articles; the caller confirms before marking.
    onMarkDayRead: (() -> Unit)? = null
) {
    var expanded by rememberSaveable(dayKey) { mutableStateOf(false) }
    // Runs when the divider scrolls into view (off-screen days cost nothing), and again after a
    // refresh or scope change clears the day's data while the divider stays on screen.
    LaunchedEffect(dayKey, dayIntelKnown) { if (!dayIntelKnown) onLoadDayIntel() }

    val hasSummary = dailySummary?.summary?.isNotBlank() == true
    val noSummary = summaryChecked && !hasSummary

    Column(modifier = modifier.fillMaxWidth().padding(top = 12.dp, bottom = 4.dp)) {
        Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text(label, fontSize = 13.sp, fontWeight = FontWeight.Bold, color = TextSecondary)
            Spacer(Modifier.width(10.dp))
            Box(Modifier.weight(1f).height(1.dp).background(SlateDark700))
            if (onMarkDayRead != null) {
                IconButton(onClick = onMarkDayRead, modifier = Modifier.size(32.dp)) {
                    Icon(Icons.Default.DoneAll, contentDescription = "Mark $label as read", tint = TextMuted, modifier = Modifier.size(18.dp))
                }
            } else {
                Spacer(Modifier.width(8.dp))
            }
            val (chipText, chipColor) = when {
                summaryLoading -> "Loading…" to TextMuted
                summaryFailed -> "Retry briefing" to CyberAmber
                hasSummary -> (if (expanded) "Hide briefing" else "AI briefing") to CyberPurple
                noSummary -> "No briefing" to TextMuted
                else -> "AI briefing" to TextMuted
            }
            Surface(
                color = if (hasSummary) CyberPurple.copy(alpha = 0.16f) else SlateDark700.copy(alpha = 0.5f),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier
                    .clip(RoundedCornerShape(12.dp))
                    .clickable(enabled = !summaryLoading, onClickLabel = "AI briefing for $label") {
                        if (!summaryChecked) { onRequestSummary(); expanded = true } else expanded = !expanded
                    }
            ) {
                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)) {
                    Icon(Icons.Default.Bolt, contentDescription = null, tint = chipColor, modifier = Modifier.size(12.dp))
                    Spacer(Modifier.width(4.dp))
                    Text(chipText, fontSize = 11.sp, fontWeight = FontWeight.Medium, color = chipColor)
                }
            }
        }

        val chips = remember(dayIntel, dayKey) { dayIntel?.let { dayChips(it, dayKey) }.orEmpty() }
        if (chips.isNotEmpty()) {
            Spacer(Modifier.height(6.dp))
            Row(
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState())
            ) {
                chips.forEach { chip ->
                    val active = activeFocus != null && chip.focus != null && activeFocus.dayKey == chip.focus.dayKey && activeFocus.chip == chip.focus.chip
                    DayChipView(chip, active, onDayFocus)
                }
            }
        }

        if (expanded && (hasSummary || noSummary)) {
            Spacer(Modifier.height(8.dp))
            Surface(
                color = SlateDark800,
                shape = RoundedCornerShape(10.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, CyberPurple.copy(alpha = if (hasSummary) 0.4f else 0.15f)),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(Modifier.padding(12.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Bolt, contentDescription = null, tint = CyberPurple, modifier = Modifier.size(15.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("AI daily briefing", fontWeight = FontWeight.Bold, fontSize = 13.sp, color = CyberPurple)
                    }
                    Spacer(Modifier.height(6.dp))
                    if (dailySummary != null && hasSummary) {
                        val blocks = remember(dailySummary.summary, serverUrl) { MarkdownText.parse(dailySummary.summary.orEmpty(), serverUrl) }
                        ArticleContent(blocks = blocks, fontSize = ReaderFontSize.SMALL, onLinkClick = onOpenLink)
                        Spacer(Modifier.height(8.dp))
                        val generated = DateUtils.formatRelativeTime(dailySummary.generatedAt).takeIf { it.isNotBlank() }
                        Text(
                            listOfNotNull(generated?.let { "Generated $it" }, "saved on the server, so reading it uses no AI tokens").joinToString(" · "),
                            fontSize = 11.sp,
                            color = TextMuted
                        )
                    } else {
                        Text(
                            "No briefing has been generated for this day yet. Briefings are created on the IntelFeed website; the app only shows saved ones, so it never spends AI tokens.",
                            fontSize = 13.sp,
                            color = TextSecondary,
                            lineHeight = 18.sp
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun DayChipView(chip: DayChip, active: Boolean, onDayFocus: (com.example.intelfeed.data.model.DayFocus) -> Unit) {
    val focus = chip.focus
    Surface(
        color = chip.color.copy(alpha = if (active) 0.3f else 0.12f),
        shape = RoundedCornerShape(6.dp),
        modifier = Modifier
            .clip(RoundedCornerShape(6.dp))
            .then(if (active) Modifier.border(1.dp, chip.color, RoundedCornerShape(6.dp)) else Modifier)
            .then(
                if (focus != null) Modifier.clickable(
                    onClickLabel = if (active) "Show all articles again" else "Show only ${focus.label}",
                    onClick = { onDayFocus(focus) }
                ) else Modifier
            )
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(horizontal = 7.dp, vertical = 3.dp)) {
            if (chip.kind.isNotEmpty()) {
                Text(chip.kind, fontSize = 10.sp, color = chip.color.copy(alpha = 0.75f), maxLines = 1)
                Spacer(Modifier.width(4.dp))
            }
            Text(chip.name, fontSize = 12.sp, fontWeight = FontWeight.Medium, color = chip.color, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.widthIn(max = 220.dp))
            chip.extra?.let {
                Spacer(Modifier.width(4.dp))
                Text(it, fontSize = 10.sp, color = TextMuted, maxLines = 1)
            }
            if (active) {
                Spacer(Modifier.width(4.dp))
                Text("✕", fontSize = 10.sp, color = chip.color)
            }
        }
    }
}

/** Tag colours come from the server as hex strings (#8B5CF6). Colours too dark for the dark theme fall back to grey. */
fun tagColor(hex: String?): Color {
    val parsed = hex?.removePrefix("#")?.takeIf { it.length == 6 }?.toLongOrNull(16) ?: return CyberBlue
    val color = Color(0xFF000000 or parsed)
    val luminance = 0.299f * color.red + 0.587f * color.green + 0.114f * color.blue
    return if (luminance < 0.25f) TextSecondary else color
}
