package com.example.intelfeed.ui.entity

import com.example.intelfeed.data.model.EntityType
import com.example.intelfeed.data.model.MentionsTimeseries
import com.example.intelfeed.data.model.TimelineEvent
import com.example.intelfeed.util.DateUtils
import java.util.Locale

/** Turns the profile timeline responses into what the Timeline tab lists. Plain Kotlin, unit-tested. */
object TimelinePresentation {

    /** Key events listed at a time; "Show more" adds another page. */
    const val PAGE = 40

    /** Chart windows offered on the phone (the website also has 24h and 60d). */
    val WINDOWS = listOf("7d" to "7 days", "30d" to "30 days", "90d" to "90 days", "all" to "All time")

    fun windowLabel(window: String): String = WINDOWS.firstOrNull { it.first == window }?.second?.lowercase(Locale.US) ?: window

    /**
     * The events worth listing, newest first: relationships, correlations and the like. Articles
     * are left out (the Articles tab lists them) and so are "Related to …" events, which the website
     * also leaves off its timeline.
     */
    fun keyEvents(events: List<TimelineEvent>): List<TimelineEvent> =
        events.filter { it.eventType != null && it.eventType != "article" && !it.date.isNullOrBlank() && !it.title.startsWith("Related to ") }
            .sortedByDescending { DateUtils.parseIsoMillis(it.date) }

    /** Short label for an event's pill: the relationship verb ("Uses", "Exploits"), or its type. */
    fun eventLabel(event: TimelineEvent): String = when (event.eventType) {
        "relationship" -> humanize(event.eventSubtype ?: "related")
        "correlation" -> "Correlation"
        else -> humanize(event.eventType ?: "event")
    }

    fun signalLabel(signalType: String?): String = when (signalType) {
        null, "" -> "Signal"
        "scoop" -> "Scoop"
        "new_pairing" -> "New pairing"
        else -> humanize(signalType)
    }

    /** The profile an event points to: "Uses malware “Click2Shell”" with its nav context opens Click2Shell. */
    fun eventTarget(event: TimelineEvent): EntityRef? {
        val context = event.navContext ?: return null
        val type = EntityType.fromKey(context.entityType) ?: return null
        val id = context.entityId?.takeIf { it.isNotBlank() } ?: return null
        val name = QUOTED.find(event.title)?.groupValues?.get(1)?.takeIf { it.isNotBlank() } ?: event.title
        return EntityRef(type, id, name)
    }

    /** Change against the previous window in percent, or null when there's nothing to compare with. */
    fun trendPercent(mentions: MentionsTimeseries): Int? {
        val previous = mentions.previousTotal ?: return null
        if (previous <= 0) return null
        return Math.round((mentions.total - previous) * 100.0 / previous).toInt()
    }

    /**
     * The trend line under the mentions summary, as the web profile words it: nothing when there's
     * no previous window, no change, or no mentions at all; "new" when the previous window had none.
     * [up] is null for "new" (always a rise), else the direction.
     */
    fun trendLine(mentions: MentionsTimeseries, windowLabel: String): Trend? {
        val previous = mentions.previousTotal ?: return null
        if (previous <= 0) {
            return if (mentions.total > 0) Trend(true, "↑ New: none in the previous $windowLabel") else null
        }
        val pct = trendPercent(mentions) ?: return null
        if (pct == 0) return null
        val size = if (kotlin.math.abs(pct) > 999) ">999" else kotlin.math.abs(pct).toString()
        return Trend(pct > 0, "${if (pct > 0) "↑" else "↓"} $size% vs the previous $windowLabel")
    }

    data class Trend(val up: Boolean, val text: String)

    private val QUOTED = Regex("[“\"]([^”\"]+)[”\"]")

    private fun humanize(raw: String): String = raw.replace('_', ' ').trim().replaceFirstChar { it.titlecase(Locale.US) }
}
