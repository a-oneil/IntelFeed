package com.example.intelfeed.data.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

// An entity profile's activity over time (the website profile's "Mentions" chart, event markers,
// "What's new" and stories). Shapes checked against the live server.

/** GET /api/entities/{type}/{id}/mentions-timeseries?window=7d|30d|90d|all */
@Serializable
data class MentionsTimeseries(
    val window: String? = null,
    // "hour", "day" or "week": what one point covers.
    val bucket: String = "day",
    @SerialName("total_feeds") val totalFeeds: Int = 0,
    // Articles in the window before this one, for a trend.
    @SerialName("previous_total") val previousTotal: Int? = null,
    val points: List<MentionPoint> = emptyList()
) {
    val total: Int get() = points.sumOf { it.count }
}

@Serializable
data class MentionPoint(
    // "yyyy-MM-dd" (or an ISO timestamp for hourly buckets).
    val date: String,
    val count: Int = 0,
    val feeds: Int = 0
)

/** GET /api/intelligence/timeline/{type}/{id}: every event, newest first (articles included). */
@Serializable
data class EntityTimeline(val events: List<TimelineEvent> = emptyList())

@Serializable
data class TimelineEvent(
    @SerialName("entry_id") val entryId: String? = null,
    val title: String = "",
    val url: String? = null,
    val date: String? = null,
    // "article", "relationship", "correlation", …
    @SerialName("event_type") val eventType: String? = null,
    val severity: String? = null,
    // For relationships the verb ("uses", "exploits", "targets"); for correlations the rule.
    @SerialName("event_subtype") val eventSubtype: String? = null,
    // The other entity, when the event is about one.
    @SerialName("nav_context") val navContext: TimelineNavContext? = null
)

@Serializable
data class TimelineNavContext(
    @SerialName("entity_type") val entityType: String? = null,
    @SerialName("entity_id") val entityId: String? = null
)

/** GET /api/engine/entities/{type}/{id}/whats-new?scoped=true → {items: […]} */
@Serializable
data class WhatsNewItem(
    @SerialName("entry_id") val entryId: String,
    @SerialName("entry_title") val entryTitle: String? = null,
    @SerialName("published_at") val publishedAt: String? = null,
    // "scoop", "new_pairing", …
    @SerialName("signal_type") val signalType: String? = null,
    val explanation: String? = null
)

/** GET /api/entities/{type}/{id}/story-threads?limit=&status=any → {items: […]} */
@Serializable
data class EntityStory(
    val slug: String,
    val title: String = "",
    val summary: String? = null,
    val status: String? = null,
    @SerialName("entry_count") val entryCount: Int = 0,
    @SerialName("source_count") val sourceCount: Int = 0,
    @SerialName("first_seen") val firstSeen: String? = null,
    @SerialName("last_seen") val lastSeen: String? = null,
    @SerialName("latest_beat") val latestBeat: StoryBeat? = null
)

@Serializable
data class StoryBeat(
    val headline: String? = null,
    @SerialName("occurred_at") val occurredAt: String? = null
)
