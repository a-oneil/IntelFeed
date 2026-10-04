package com.example.intelfeed.ui.screens

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.intelfeed.data.model.EntityStory
import com.example.intelfeed.data.model.EntityType
import com.example.intelfeed.data.model.MentionsTimeseries
import com.example.intelfeed.data.model.TimelineEvent
import com.example.intelfeed.data.model.WhatsNewItem
import com.example.intelfeed.theme.CyberAmber
import com.example.intelfeed.theme.CyberPurple
import com.example.intelfeed.theme.CyberRed
import com.example.intelfeed.theme.SlateDark700
import com.example.intelfeed.theme.TextMuted
import com.example.intelfeed.theme.TextPrimary
import com.example.intelfeed.theme.TextSecondary
import com.example.intelfeed.ui.components.CardSurface
import com.example.intelfeed.ui.components.ErrorState
import com.example.intelfeed.ui.components.InlineLoading
import com.example.intelfeed.ui.components.LoadMoreButton
import com.example.intelfeed.ui.components.Pill
import com.example.intelfeed.ui.components.SectionHeader
import com.example.intelfeed.ui.components.color
import com.example.intelfeed.ui.entity.EntityRef
import com.example.intelfeed.ui.entity.TimelinePresentation
import com.example.intelfeed.ui.entity.TimelineUiState
import com.example.intelfeed.util.DateUtils
import java.text.NumberFormat
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.TimeZone

/**
 * The profile's Timeline tab, the phone version of the website profile's activity view: a mentions
 * chart with its trend, "What's new" signals, the stories the entity is part of, and key events
 * (new relationships and correlations) by day.
 */
internal fun LazyListScope.timelineTab(
    timeline: TimelineUiState,
    type: EntityType,
    onWindow: (String) -> Unit,
    onOpenEntry: (String, List<String>) -> Unit,
    onOpenEntity: (EntityRef) -> Unit,
    onOpenThread: (String, String?) -> Unit,
    onOpenLink: (String) -> Unit,
    onMoreEvents: () -> Unit,
    retry: () -> Unit
) {
    item(key = "t-mentions") { MentionsCard(timeline, type, onWindow) }

    if (timeline.whatsNew.isNotEmpty()) {
        item(key = "t-new-h") { SectionHeader("What's new", Modifier.padding(horizontal = 16.dp)) }
        val ids = timeline.whatsNew.map { it.entryId }.distinct()
        itemsIndexed(timeline.whatsNew, key = { i, _ -> "t-new:$i" }) { _, item ->
            WhatsNewRow(item, onClick = { onOpenEntry(item.entryId, ids) })
        }
    }

    if (timeline.stories.isNotEmpty()) {
        item(key = "t-stories-h") { SectionHeader("Stories", Modifier.padding(horizontal = 16.dp)) }
        itemsIndexed(timeline.stories, key = { _, s -> "t-story:" + s.slug }) { _, story ->
            StoryRow(story, onClick = { onOpenThread(story.slug, story.title) })
        }
    }

    item(key = "t-events-h") {
        SectionHeader(if (timeline.events.isNotEmpty()) "Key events · ${NumberFormat.getIntegerInstance(Locale.US).format(timeline.events.size)}" else "Key events", Modifier.padding(horizontal = 16.dp))
    }
    when {
        timeline.events.isEmpty() && timeline.loading -> item(key = "t-events-loading") { InlineLoading() }
        timeline.events.isEmpty() && timeline.eventsError != null -> item(key = "t-events-error") { ErrorState(timeline.eventsError, onRetry = retry) }
        timeline.events.isEmpty() -> item(key = "t-events-empty") {
            Text(
                "No new relationships or correlations recorded yet. Articles that mention it are on the Articles tab.",
                fontSize = 13.sp, color = TextMuted, modifier = Modifier.padding(horizontal = 16.dp)
            )
        }
        else -> {
            val shown = timeline.events.take(timeline.shownEvents)
            var lastDay: String? = null
            shown.forEachIndexed { i, event ->
                val day = DateUtils.localDayKey(event.date)
                if (day != lastDay) {
                    lastDay = day
                    item(key = "t-day:$i") {
                        Text(
                            DateUtils.dayLabel(event.date), fontSize = 12.sp, fontWeight = FontWeight.SemiBold, color = TextSecondary,
                            modifier = Modifier.padding(start = 16.dp, end = 16.dp, top = 10.dp, bottom = 2.dp)
                        )
                    }
                }
                item(key = "t-ev:$i") { EventRow(event, onOpenEntity, onOpenEntry, onOpenLink) }
            }
            if (timeline.events.size > shown.size) {
                item(key = "t-events-more") { LoadMoreButton("Show more events (${timeline.events.size - shown.size} left)", loading = false, onClick = onMoreEvents) }
            }
        }
    }
}

@Composable
private fun MentionsCard(timeline: TimelineUiState, type: EntityType, onWindow: (String) -> Unit) {
    val mentions = timeline.mentions
    CardSurface(modifier = Modifier.padding(horizontal = 16.dp, vertical = 10.dp)) {
        Column(Modifier.padding(14.dp)) {
            Text("Mentions", fontSize = 15.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
            Spacer(Modifier.height(2.dp))
            val windowLabel = TimelinePresentation.windowLabel(timeline.window)
            when {
                mentions == null && timeline.mentionsLoading -> InlineLoading()
                mentions == null -> Text(timeline.mentionsError ?: "Mentions aren't available for this profile.", fontSize = 13.sp, color = TextMuted)
                else -> {
                    val number = NumberFormat.getIntegerInstance(Locale.US)
                    val summary = buildList {
                        add("${number.format(mentions.total)} ${if (mentions.total == 1) "article" else "articles"} " + if (timeline.window == "all") "in total" else "in $windowLabel")
                        if (mentions.totalFeeds > 0) add("${number.format(mentions.totalFeeds)} ${if (mentions.totalFeeds == 1) "feed" else "feeds"}")
                    }.joinToString(" · ")
                    Text(summary, fontSize = 13.sp, color = TextSecondary)
                    TimelinePresentation.trendLine(mentions, windowLabel)?.let { trend ->
                        Text(trend.text, fontSize = 12.sp, color = if (trend.up) CyberAmber else TextMuted)
                    }
                    Spacer(Modifier.height(10.dp))
                    Column(Modifier.alpha(if (timeline.mentionsLoading) 0.4f else 1f)) { MentionsChart(mentions, type.color()) }
                }
            }
            Spacer(Modifier.height(8.dp))
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                TimelinePresentation.WINDOWS.forEach { (value, label) ->
                    FilterChip(
                        selected = timeline.window == value,
                        onClick = { onWindow(value) },
                        label = { Text(label, fontSize = 12.sp) },
                        colors = FilterChipDefaults.filterChipColors(selectedContainerColor = type.color().copy(alpha = 0.2f), selectedLabelColor = type.color())
                    )
                }
            }
        }
    }
}

@Composable
private fun MentionsChart(mentions: MentionsTimeseries, color: Color) {
    val points = mentions.points
    if (points.isEmpty() || mentions.total == 0) {
        Text("No mentions in this period.", fontSize = 13.sp, color = TextMuted)
        return
    }
    val max = points.maxOf { it.count }.coerceAtLeast(1)
    val peak = points.maxBy { it.count }
    val spansYears = points.first().date.take(4) != points.last().date.take(4)
    val description = "Mentions chart, ${mentions.total} articles. Peak ${peak.count} on ${chartDate(peak.date, spansYears)}."
    Canvas(Modifier.fillMaxWidth().height(64.dp).semantics { contentDescription = description }) {
        val slot = size.width / points.size
        val barWidth = (slot * 0.7f).coerceAtLeast(1f)
        points.forEachIndexed { i, p ->
            val h = if (p.count == 0) 1.5f else (p.count.toFloat() / max) * size.height
            drawRoundRect(
                color = if (p.count == 0) SlateDark700 else color,
                topLeft = Offset(i * slot + (slot - barWidth) / 2, size.height - h),
                size = Size(barWidth, h),
                cornerRadius = CornerRadius(barWidth / 4, barWidth / 4)
            )
        }
    }
    Spacer(Modifier.height(4.dp))
    Row(Modifier.fillMaxWidth()) {
        Text(chartDate(points.first().date, spansYears), fontSize = 11.sp, color = TextMuted)
        Spacer(Modifier.weight(1f))
        if (peak.count >= 3) Text("Peak ${peak.count} · ${chartDate(peak.date, spansYears)}", fontSize = 11.sp, color = TextMuted)
        Spacer(Modifier.weight(1f))
        Text(chartDate(points.last().date, spansYears), fontSize = 11.sp, color = TextMuted)
    }
}

/** "Aug 14", or "Aug 2025" when the chart spans years. Point dates are UTC days. */
private fun chartDate(date: String, withYear: Boolean): String {
    val parsed = DateUtils.parseDate(date) ?: return date.take(10)
    return SimpleDateFormat(if (withYear) "MMM yyyy" else "MMM d", Locale.US).apply { timeZone = TimeZone.getTimeZone("UTC") }.format(parsed)
}

@Composable
private fun WhatsNewRow(item: WhatsNewItem, onClick: () -> Unit) {
    CardSurface(modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp).clip(RoundedCornerShape(12.dp)).clickable(onClick = onClick)) {
        Column(Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Pill(TimelinePresentation.signalLabel(item.signalType), CyberPurple)
                Spacer(Modifier.width(8.dp))
                Text(DateUtils.formatRelativeTime(item.publishedAt), fontSize = 12.sp, color = TextMuted)
            }
            Spacer(Modifier.height(6.dp))
            Text(item.entryTitle ?: "Article", fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = TextPrimary, maxLines = 2, overflow = TextOverflow.Ellipsis)
            item.explanation?.takeIf { it.isNotBlank() }?.let {
                Spacer(Modifier.height(2.dp))
                Text(it, fontSize = 12.sp, color = TextSecondary, maxLines = 2, overflow = TextOverflow.Ellipsis)
            }
        }
    }
}

@Composable
private fun StoryRow(story: EntityStory, onClick: () -> Unit) {
    CardSurface(modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp).clip(RoundedCornerShape(12.dp)).clickable(onClick = onClick)) {
        Column(Modifier.padding(12.dp)) {
            Text(story.title.ifBlank { "Story" }, fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = TextPrimary, maxLines = 2, overflow = TextOverflow.Ellipsis)
            (story.latestBeat?.headline ?: story.summary)?.takeIf { it.isNotBlank() }?.let {
                Spacer(Modifier.height(2.dp))
                Text(it, fontSize = 12.sp, color = TextSecondary, maxLines = 2, overflow = TextOverflow.Ellipsis)
            }
            Spacer(Modifier.height(4.dp))
            val meta = listOfNotNull(
                "${story.entryCount} ${if (story.entryCount == 1) "article" else "articles"}",
                story.sourceCount.takeIf { it > 0 }?.let { "$it ${if (it == 1) "source" else "sources"}" },
                story.status?.takeIf { it.isNotBlank() },
                DateUtils.formatRelativeTime(story.lastSeen).takeIf { it.isNotBlank() }?.let { "updated ${if (it == "Just now" || it == "Yesterday") it.lowercase() else it}" }
            ).joinToString(" · ")
            Text(meta, fontSize = 12.sp, color = TextMuted)
        }
    }
}

@Composable
private fun EventRow(
    event: TimelineEvent,
    onOpenEntity: (EntityRef) -> Unit,
    onOpenEntry: (String, List<String>) -> Unit,
    onOpenLink: (String) -> Unit
) {
    val target = TimelinePresentation.eventTarget(event)
    val entryId = event.entryId
    val url = event.url?.takeIf { it.startsWith("http") }
    val onClick: (() -> Unit)? = when {
        target != null -> { { onOpenEntity(target) } }
        entryId != null -> { { onOpenEntry(entryId, listOf(entryId)) } }
        url != null -> { { onOpenLink(url) } }
        else -> null
    }
    val color = when {
        event.eventType == "correlation" && event.severity in setOf("high", "critical") -> CyberRed
        event.eventType == "correlation" -> CyberAmber
        target != null -> target.type.color()
        else -> TextSecondary
    }
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .then(if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier)
            .padding(horizontal = 16.dp, vertical = 8.dp)
    ) {
        Pill(TimelinePresentation.eventLabel(event), color)
        Spacer(Modifier.width(10.dp))
        Text(event.title, fontSize = 14.sp, color = TextPrimary, maxLines = 2, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
    }
}
