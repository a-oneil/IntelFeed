package com.example.intelfeed.data.model

import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.nullable
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull

// Response shapes in this package were checked against the live server on 2026-09-22 (see
// claude_changes.md). The server's docs are older than its responses in several places.

@Serializable
data class CursorPage<T>(
    val items: List<T> = emptyList(),
    @SerialName("next_cursor") val nextCursor: String? = null,
    @SerialName("has_more") val hasMore: Boolean = false,
    val total: Int? = null
)

/**
 * Reads a string or a number as a String. Search hits send `published_at` as epoch seconds
 * (e.g. 1790094767.0) while the entry endpoints send ISO strings.
 */
@OptIn(ExperimentalSerializationApi::class)
object FlexibleStringSerializer : KSerializer<String?> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("FlexibleString", PrimitiveKind.STRING).nullable

    override fun deserialize(decoder: Decoder): String? {
        if (decoder is JsonDecoder) {
            val element = decoder.decodeJsonElement()
            return if (element is JsonNull) null else (element as? JsonPrimitive)?.content
        }
        return decoder.decodeString()
    }

    override fun serialize(encoder: Encoder, value: String?) {
        if (value == null) encoder.encodeNull() else encoder.encodeString(value)
    }
}

/**
 * Tags arrive as objects ({"name", "color"}) from the entry endpoints but as bare strings
 * (["morning-brief"]) in search hits. Accepts both.
 */
object FlexibleTagListSerializer : KSerializer<List<TagEntity>> {
    private val delegate = ListSerializer(TagEntity.serializer())
    override val descriptor: SerialDescriptor = delegate.descriptor

    override fun deserialize(decoder: Decoder): List<TagEntity> {
        val jsonDecoder = decoder as? JsonDecoder ?: return delegate.deserialize(decoder)
        val array = jsonDecoder.decodeJsonElement() as? JsonArray ?: return emptyList()
        return array.mapNotNull { element ->
            when (element) {
                is JsonPrimitive -> element.contentOrNull?.takeIf { it.isNotBlank() }?.let { TagEntity(name = it) }
                is JsonObject -> runCatching { jsonDecoder.json.decodeFromJsonElement(TagEntity.serializer(), element) }.getOrNull()
                else -> null
            }
        }
    }

    override fun serialize(encoder: Encoder, value: List<TagEntity>) = delegate.serialize(encoder, value)
}

/** One explainable ranking signal. List items carry type + explanation; the detail adds family and weights. */
@Serializable
data class Signal(
    val type: String = "",
    val family: String? = null,
    val score: Double? = null,
    val weighted: Double? = null,
    val explanation: String = ""
)

@Serializable
data class EntryItem(
    val id: String = "",
    val title: String = "",
    val summary: String? = null,
    val url: String? = null,
    @Serializable(with = FlexibleStringSerializer::class)
    @SerialName("published_at") val publishedAt: String? = null,
    @SerialName("feed_id") val feedId: String? = null,
    @SerialName("feed_title") val feedTitle: String? = null,
    @SerialName("feed_type") val feedType: String? = null,
    val author: String? = null,
    @SerialName("content_type") val contentType: String? = null,
    @SerialName("is_read") val isRead: Boolean = false,
    @SerialName("is_starred") val isStarred: Boolean = false,
    @SerialName("is_bookmarked") val isBookmarked: Boolean = false,
    @Serializable(with = FlexibleStringSerializer::class)
    @SerialName("created_at") val createdAt: String? = null,
    @SerialName("priority_score") val priorityScore: Double? = null,
    @SerialName("image_url") val imageUrl: String? = null,
    @SerialName("translated_title") val translatedTitle: String? = null,
    @SerialName("word_count") val wordCount: Int? = null,
    @Serializable(with = FlexibleTagListSerializer::class)
    val tags: List<TagEntity> = emptyList(),
    // Top two ranking explanations; only set when the entry clears the Radar threshold.
    @SerialName("top_signals") val topSignals: List<Signal> = emptyList(),
    // A re-report of an earlier article; the web list de-emphasises these.
    @SerialName("is_echo") val isEcho: Boolean = false,
    // Client-side only: set on Priority Queue story rows (the id is then "thread:<slug>").
    @Transient val thread: StoryThread? = null
) {
    val isThread: Boolean get() = thread != null
    val displayTitle: String get() = translatedTitle?.takeIf { it.isNotBlank() } ?: title
}

/**
 * One entry's value from POST /api/entries/intel-counts (the web list's badges). Entries with
 * nothing extracted are absent from the response. Shape checked on the live server, 2026-09-23.
 */
@Serializable
data class EntryIntelCounts(
    val ttps: Int = 0,
    val cves: Int = 0,
    val rules: Int = 0,
    val notes: Int = 0,
    val total: Int = 0,
    @SerialName("has_detection_gap") val hasDetectionGap: Boolean = false,
    // e.g. "actionable_gap"; null when there's nothing to do.
    @SerialName("detection_opportunity") val detectionOpportunity: String? = null,
    @SerialName("has_high_risk_cve") val hasHighRiskCve: Boolean = false,
    @SerialName("has_kev_cve") val hasKevCve: Boolean = false,
    @SerialName("high_value") val highValue: Boolean = false,
    @SerialName("pir_matches") val pirMatches: List<PirMatch> = emptyList(),
    val actors: List<String> = emptyList(),
    @SerialName("actor_count") val actorCount: Int = 0,
    val malware: List<String> = emptyList(),
    @SerialName("malware_count") val malwareCount: Int = 0,
    // "critical", "high", "medium", "low" or null.
    @SerialName("cve_max_severity") val cveMaxSeverity: String? = null
)

/** A priority intelligence requirement the entry matched. */
@Serializable
data class PirMatch(
    val id: String? = null,
    val title: String = "",
    val priority: String? = null,
    val category: String? = null,
    @SerialName("match_type") val matchType: String? = null,
    @SerialName("matched_on") val matchedOn: String? = null,
    val relevance: String? = null
)

/** GET /api/entries/count: how many entries match the list filters (the web sidebar's counts). */
@Serializable
data class EntryCount(val total: Int = 0)

/** GET /api/entries/priority-unread-count: unread entries in the Priority Queue (story rows are counted separately). */
@Serializable
data class PriorityUnreadCount(@SerialName("unread_count") val unreadCount: Int = 0)

@Serializable
data class BulkActionRequest(
    @SerialName("entry_ids") val entryIds: List<String>,
    val action: String
)

@Serializable
data class MarkAllReadRequest(
    @SerialName("feed_id") val feedId: String? = null,
    @SerialName("category_id") val categoryId: String? = null,
    // A time window (the web's "mark this day read" sends the day's bounds). Left out when unset.
    @OptIn(ExperimentalSerializationApi::class) @EncodeDefault(EncodeDefault.Mode.NEVER)
    val since: String? = null,
    @OptIn(ExperimentalSerializationApi::class) @EncodeDefault(EncodeDefault.Mode.NEVER)
    val before: String? = null,
    // Only what the Priority Queue shows (the web sends this from its Priority Queue view).
    @OptIn(ExperimentalSerializationApi::class) @EncodeDefault(EncodeDefault.Mode.NEVER)
    @SerialName("radar_only") val radarOnly: Boolean? = null
)

@Serializable
data class PriorityQueueItem(
    val kind: String = "entry",
    val score: Double = 0.0,
    val entry: EntryItem? = null,
    val thread: StoryThread? = null,
    @SerialName("absorbed_entry_ids") val absorbedEntryIds: List<String> = emptyList()
)

@Serializable
data class PriorityQueueResponse(
    val items: List<PriorityQueueItem> = emptyList(),
    @SerialName("next_cursor") val nextCursor: String? = null,
    @SerialName("has_more") val hasMore: Boolean = false,
    @SerialName("radar_threshold") val radarThreshold: Double? = null
)

@Serializable
data class EchoOf(
    @SerialName("entry_id") val entryId: String,
    val title: String? = null,
    @SerialName("feed_title") val feedTitle: String? = null,
    @Serializable(with = FlexibleStringSerializer::class)
    @SerialName("published_at") val publishedAt: String? = null,
    val shared: Int = 0,
    val total: Int = 0
)

/**
 * GET /api/entries/{id}. The live server does NOT include extracted entities here (the older docs
 * say it does): they come from /api/entries/{id}/threat-actors, /malware, /cves, … (see [EntryIntel]).
 */
@Serializable
data class EntryDetail(
    val id: String,
    val title: String,
    val summary: String? = null,
    val url: String? = null,
    @Serializable(with = FlexibleStringSerializer::class)
    @SerialName("published_at") val publishedAt: String? = null,
    @SerialName("feed_id") val feedId: String? = null,
    @SerialName("feed_title") val feedTitle: String? = null,
    @SerialName("feed_type") val feedType: String? = null,
    val author: String? = null,
    @SerialName("content_html") val contentHtml: String? = null,
    @SerialName("content_text") val contentText: String? = null,
    @SerialName("is_read") val isRead: Boolean = false,
    @SerialName("is_starred") val isStarred: Boolean = false,
    @SerialName("is_bookmarked") val isBookmarked: Boolean = false,
    @SerialName("image_url") val imageUrl: String? = null,
    @SerialName("word_count") val wordCount: Int? = null,
    @SerialName("translated_title") val translatedTitle: String? = null,
    @SerialName("translated_html") val translatedHtml: String? = null,
    val media: List<EntryMedia> = emptyList(),
    @Serializable(with = FlexibleTagListSerializer::class)
    val tags: List<TagEntity> = emptyList(),
    @SerialName("priority_score") val priorityScore: Double? = null,
    @SerialName("top_signals") val topSignals: List<Signal> = emptyList(),
    // The full "Why" breakdown: every signal with its family and weighted contribution.
    @SerialName("priority_signals") val prioritySignals: List<Signal> = emptyList(),
    @SerialName("is_echo") val isEcho: Boolean = false,
    @SerialName("echo_of") val echoOf: EchoOf? = null
)

@Serializable
data class EntryMedia(
    val id: String? = null,
    val url: String? = null,
    @SerialName("media_type") val mediaType: String? = null,
    val title: String? = null
)

/** Entities linked to one entry, assembled from the per-type /api/entries/{id}/… endpoints. */
data class EntryIntel(
    val threatActors: List<ThreatActor> = emptyList(),
    val malware: List<Malware> = emptyList(),
    val cves: List<Cve> = emptyList(),
    val ttps: List<Ttp> = emptyList(),
    val countries: List<Country> = emptyList(),
    val tools: List<Tool> = emptyList(),
    val vendors: List<Vendor> = emptyList(),
    val products: List<Product> = emptyList(),
    val cwes: List<Cwe> = emptyList(),
    val mitigations: List<Mitigation> = emptyList(),
    val observables: List<ObservableItem> = emptyList()
) {
    val isEmpty: Boolean
        get() = count == 0
    val count: Int
        get() = threatActors.size + malware.size + cves.size + ttps.size + countries.size +
            tools.size + vendors.size + products.size + cwes.size + mitigations.size + observables.size
}

@Serializable
data class ThreatActorEntity(
    val id: String? = null,
    val name: String,
    val confidence: Double? = null
)

@Serializable
data class MalwareEntity(
    val id: String? = null,
    val name: String,
    val confidence: Double? = null
)

@Serializable
data class TagEntity(
    val id: String? = null,
    val name: String,
    val color: String? = null,
    @SerialName("entry_count") val entryCount: Int? = null
)

@Serializable
data class SimilarEntry(
    val id: String,
    val title: String = "",
    @SerialName("feed_title") val feedTitle: String? = null,
    @Serializable(with = FlexibleStringSerializer::class)
    @SerialName("published_at") val publishedAt: String? = null,
    val url: String? = null,
    val similarity: Double? = null,
    @SerialName("thread_slug") val threadSlug: String? = null,
    @SerialName("thread_title") val threadTitle: String? = null
)

@Serializable
data class SimilarEntriesResponse(
    val items: List<SimilarEntry> = emptyList(),
    val method: String? = null
)

@Serializable
data class Category(
    val id: String,
    val name: String,
    @SerialName("parent_id") val parentId: String? = null,
    val position: Int = 0,
    @SerialName("feed_count") val feedCount: Int = 0,
    @SerialName("created_at") val createdAt: String? = null,
    val children: List<Category> = emptyList()
)

@Serializable
data class FeedSource(
    val id: String,
    val title: String,
    val url: String,
    @SerialName("feed_type") val feedType: String? = null,
    @SerialName("site_url") val siteUrl: String? = null,
    @SerialName("icon_url") val iconUrl: String? = null,
    val description: String? = null,
    @SerialName("category_id") val categoryId: String? = null,
    @SerialName("unread_count") val unreadCount: Int = 0,
    @SerialName("is_active") val isActive: Boolean = true,
    @SerialName("is_muted") val isMuted: Boolean = false,
    @SerialName("last_fetched_at") val lastFetchedAt: String? = null,
    @SerialName("custom_title") val customTitle: String? = null,
    @SerialName("error_count") val errorCount: Int = 0,
    @SerialName("last_error") val lastError: String? = null,
    @SerialName("fetch_interval_minutes") val fetchIntervalMinutes: Int? = null,
    // How much intelligence is extracted from this feed's articles; see curationLabel.
    @SerialName("intel_extraction_mode") val intelExtractionMode: String? = null,
    @SerialName("auto_extract_on_ingest") val autoExtractOnIngest: Boolean = false
) {
    val displayTitle: String get() = customTitle ?: title

    /**
     * The web's curation label for the feed (its sidebar rail tooltip), from the extraction mode
     * and auto-extract flag, or null when extraction is off.
     */
    val curationLabel: String?
        get() {
            // Same rules as the web client: a missing mode counts as "selective".
            val mode = intelExtractionMode?.lowercase()?.takeIf { it.isNotBlank() } ?: "selective"
            return when {
                mode == "none" -> null
                mode == "manual" -> "Manual — only when triggered"
                (mode == "full" || mode == "selective") && !autoExtractOnIngest -> "Known entities only — match against existing database"
                mode == "full" -> "Full — extract all intelligence automatically"
                else -> "Selective — security-relevant articles only"
            }
        }

    /** "RSS", "GitHub repo", "Telegram"… */
    val typeLabel: String?
        get() = feedType?.takeIf { it.isNotBlank() }?.let { t ->
            when (t.lowercase()) {
                "rss", "atom", "json", "opml" -> t.uppercase()
                "github_repo" -> "GitHub repo"
                "web_scraper" -> "Web scraper"
                "youtube" -> "YouTube"
                else -> t.replace('_', ' ').replaceFirstChar { it.titlecase() }
            }
        }
}

@Serializable
data class IngestUrlRequest(val url: String)

@Serializable
data class IngestUrlResponse(
    val id: String? = null,
    val title: String? = null,
    val url: String? = null,
    val message: String? = null
)

/**
 * POST /api/feeds. Unset optional fields are left out of the JSON (the web client omits them too),
 * so the server applies its own defaults instead of receiving explicit nulls.
 */
@OptIn(ExperimentalSerializationApi::class)
@Serializable
data class CreateFeedRequest(
    val url: String,
    @EncodeDefault(EncodeDefault.Mode.NEVER)
    @SerialName("category_id") val categoryId: String? = null,
    @EncodeDefault(EncodeDefault.Mode.NEVER)
    val title: String? = null,
    @EncodeDefault(EncodeDefault.Mode.NEVER)
    @SerialName("fetch_interval_minutes") val fetchIntervalMinutes: Int? = null
)

/**
 * A feed found by POST /api/feeds/discover. The live web client reads one object
 * ({url, title, description, feed_type}); the older docs describe {"feeds": [{url, title, type}]}.
 * IntelFeedRepository.discoverFeeds accepts both.
 */
@Serializable
data class DiscoveredFeed(
    val url: String = "",
    val title: String? = null,
    val description: String? = null,
    @SerialName("feed_type") val feedType: String? = null,
    val type: String? = null
) {
    val typeLabel: String? get() = (feedType ?: type)?.takeIf { it.isNotBlank() }?.uppercase()
}
