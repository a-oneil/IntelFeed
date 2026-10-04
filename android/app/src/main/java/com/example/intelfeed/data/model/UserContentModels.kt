package com.example.intelfeed.data.model

import com.example.intelfeed.util.HtmlText
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Article note (GET /api/notes/entry/{id}). The body lives in content_markdown / content_html; there
 * is no "content" field (the app used to read one, so notes showed up blank). Notes are visible to
 * everyone on the instance; only the author or an admin can edit or delete one.
 */
@Serializable
data class EntryNote(
    val id: String = "",
    @SerialName("entry_id") val entryId: String? = null,
    val title: String? = null,
    @SerialName("content_markdown") val contentMarkdown: String? = null,
    @SerialName("content_html") val contentHtml: String? = null,
    @SerialName("is_pinned") val isPinned: Boolean = false,
    @SerialName("created_by") val createdBy: String? = null,
    @SerialName("creator_username") val creatorUsername: String? = null,
    @SerialName("created_at") val createdAt: String? = null,
    @SerialName("updated_at") val updatedAt: String? = null
) {
    /** Readable body. The web editor stores HTML even in content_markdown. */
    val displayText: String
        get() {
            val html = contentHtml?.takeIf { it.isNotBlank() }
            if (html != null) return HtmlText.toPlainText(html)
            val markdown = contentMarkdown?.trim().orEmpty()
            return if (markdown.startsWith("<")) HtmlText.toPlainText(markdown) else markdown
        }
}

/** POST /api/notes/entry/{id} and PUT /api/notes/{id} (same body the web client sends). */
@Serializable
data class NoteRequest(
    val title: String,
    @SerialName("content_markdown") val contentMarkdown: String,
    @SerialName("is_pinned") val isPinned: Boolean = false
)

@Serializable
data class TagIdsRequest(
    @SerialName("tag_ids") val tagIds: List<String>
)

@Serializable
data class CreateTagRequest(
    val name: String,
    val color: String? = null
)

/** GET /api/intelligence/watchlist. mode is "watch" (boosts in the Priority Queue) or "mute" (suppressed). */
@Serializable
data class WatchlistItem(
    @SerialName("entity_type") val entityType: String,
    @SerialName("entity_id") val entityId: String,
    @SerialName("entity_name") val entityName: String? = null,
    val mode: String = "watch"
)

@Serializable
data class WatchlistRequest(
    @SerialName("entity_type") val entityType: String,
    @SerialName("entity_id") val entityId: String,
    val mode: String
)

/** PUT /api/engine/radar-feedback. verdict: 1 useful, -1 noise, 0 clears. */
@Serializable
data class RadarFeedbackRequest(
    @SerialName("entry_id") val entryId: String,
    val verdict: Int
)

/** POST /api/entries/{id}/share. url is a server-relative path such as /shared/<token>. */
@Serializable
data class ShareLink(
    val token: String? = null,
    val url: String? = null
)

/** GET /api/entries/daily-summary: a saved AI briefing (Markdown). Reading it never generates one. */
@Serializable
data class DailySummary(
    val summary: String? = null,
    val cached: Boolean = false,
    @SerialName("generated_at") val generatedAt: String? = null
)

/**
 * GET /api/entries/day-intel: the day's most-mentioned entity of each type, for the chips under a
 * day divider (the website's day header). Every field can be null on a quiet day.
 */
@Serializable
data class DayIntel(
    @SerialName("threat_actor") val threatActor: DayTopEntity? = null,
    val malware: DayTopEntity? = null,
    val cve: DayTopEntity? = null,
    val ttp: DayTopEntity? = null,
    val sector: DayTopEntity? = null,
    val product: DayTopEntity? = null,
    val country: DayTopEntity? = null,
    val signals: DaySignals = DaySignals()
)

/** [name] is the CVE id for a CVE; a technique also has [techniqueId]; a sector has a [slug] and no id. */
@Serializable
data class DayTopEntity(
    val id: String? = null,
    val name: String = "",
    val count: Int = 0,
    @SerialName("technique_id") val techniqueId: String? = null,
    @SerialName("cvss_score") val cvssScore: Double? = null,
    val severity: String? = null,
    val kev: Boolean = false,
    val slug: String? = null
)

@Serializable
data class DaySignals(
    @SerialName("actively_exploited") val activelyExploited: Int = 0,
    /** A threat actor or malware family IntelFeed tracked for the first time that day. */
    val new: DayNewEntity? = null
)

@Serializable
data class DayNewEntity(
    val type: String = "",
    val id: String? = null,
    val name: String = "",
    val total: Int = 1
)

/** GET /api/requirements item: a shared intelligence requirement (PIR). */
@Serializable
data class Requirement(
    val id: String,
    val title: String = "",
    val description: String? = null,
    // critical | high | medium | low
    val priority: String? = null,
    // active | fulfilled | expired | draft
    val status: String? = null,
    // strategic | operational | tactical | technical
    val category: String? = null,
    val keywords: List<String> = emptyList(),
    @SerialName("match_count") val matchCount: Int = 0,
    @SerialName("last_matched_at") val lastMatchedAt: String? = null,
    @SerialName("created_by") val createdBy: String? = null,
    @SerialName("auto_match") val autoMatch: Boolean = true
)

/** GET /api/requirements/{id}/matches item: one article that answered the requirement, and why. */
@Serializable
data class RequirementMatch(
    @SerialName("requirement_id") val requirementId: String? = null,
    @SerialName("entry_id") val entryId: String,
    @SerialName("match_type") val matchType: String? = null,
    @SerialName("matched_on") val matchedOn: String? = null,
    @SerialName("matched_at") val matchedAt: String? = null,
    val relevance: String? = null,
    @SerialName("entry_title") val entryTitle: String? = null,
    @SerialName("entry_url") val entryUrl: String? = null,
    @Serializable(with = FlexibleStringSerializer::class)
    @SerialName("entry_published_at") val entryPublishedAt: String? = null
)

/** POST /api/requirements, as the web's New Requirement form sends it (unset fields left out). */
@OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
@Serializable
data class CreateRequirementRequest(
    val title: String,
    val priority: String = "medium",
    val category: String = "operational",
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val description: String? = null,
    val keywords: List<String> = emptyList()
)

/**
 * A day chip's filter (the web's day "focus"): articles narrowed by [params] (e.g.
 * exploited_cves=true, entity_type/entity_id, sector). [chip] identifies the chip on day
 * [dayKey]; [label] reads "articles mentioning …" for the "Showing only …" bar. [window] is the
 * time range searched: the web only has DAY; the app defaults to the open view's range (Last 24
 * hours → 24h, This week → 7 days) and the bar lets you change it.
 */
data class DayFocus(
    val dayKey: String,
    val chip: String,
    val label: String,
    val params: Map<String, String>,
    val window: FocusWindow = FocusWindow.DAY
)

/** The day filter's time range. [hours] is null for DAY (the chip's own day) and ALL. */
enum class FocusWindow(val label: String, val hours: Long?) {
    DAY("That day", null),
    H24("24h", 24),
    D7("7 days", 24 * 7),
    D30("30 days", 24 * 30),
    ALL("All time", null)
}
