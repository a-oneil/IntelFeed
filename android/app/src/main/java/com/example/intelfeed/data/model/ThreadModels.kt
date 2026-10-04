package com.example.intelfeed.data.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/** A story thread: one unfolding story folded from many outlets' articles. */
@Serializable
data class StoryThread(
    val id: String? = null,
    val slug: String? = null,
    val title: String? = null,
    val summary: String? = null,
    val status: String? = null,
    @SerialName("source_count") val sourceCount: Int = 0,
    @SerialName("unread_count") val unreadCount: Int = 0,
    @SerialName("entry_count") val entryCount: Int = 0,
    @SerialName("echo_count") val echoCount: Int = 0,
    @SerialName("new_since_opened") val newSinceOpened: Int = 0,
    @SerialName("first_seen") val firstSeen: String? = null,
    @SerialName("last_seen") val lastSeen: String? = null,
    @SerialName("top_score") val topScore: Double? = null,
    @SerialName("top_entry_id") val topEntryId: String? = null,
    @SerialName("key_entities") val keyEntities: List<ThreadKeyEntity> = emptyList(),
    @SerialName("entry_ids") val entryIds: List<String> = emptyList(),
    @SerialName("created_at") val createdAt: String? = null,
    @SerialName("updated_at") val updatedAt: String? = null
)

@Serializable
data class ThreadKeyEntity(
    @SerialName("entity_type") val entityType: String = "",
    @SerialName("entity_id") val entityId: String? = null,
    val label: String = "",
    val count: Int = 0
)

@Serializable
data class ThreadListResponse(
    val threads: List<StoryThread> = emptyList()
)

/** One wave of the story: what changed, with the article that carried it. */
@Serializable
data class ThreadBeat(
    val id: String? = null,
    val position: Int = 0,
    @SerialName("occurred_at") val occurredAt: String? = null,
    // e.g. first_disclosure
    val kind: String? = null,
    val headline: String? = null,
    val body: String? = null,
    @SerialName("lead_entry_id") val leadEntryId: String? = null,
    @SerialName("entry_ids") val entryIds: List<String> = emptyList(),
    @SerialName("is_ai") val isAi: Boolean = false
)

@Serializable
data class ThreadMember(
    @SerialName("entry_id") val entryId: String,
    val title: String = "",
    val url: String? = null,
    @Serializable(with = FlexibleStringSerializer::class)
    @SerialName("published_at") val publishedAt: String? = null,
    @SerialName("priority_score") val priorityScore: Double? = null,
    @SerialName("feed_title") val feedTitle: String? = null,
    val source: String? = null,
    // origin | beat | echo
    val role: String? = null,
    val similarity: Double? = null,
    @SerialName("duplicate_of_entry_id") val duplicateOfEntryId: String? = null,
    @SerialName("is_read") val isRead: Boolean = false
)

@Serializable
data class ThreadYield(
    val techniques: Int = 0,
    val cves: Int = 0,
    val products: Int = 0,
    val rules: Int = 0,
    @SerialName("echoes_folded") val echoesFolded: Int = 0
)

@Serializable
data class NearestThread(
    val slug: String,
    val title: String? = null,
    val status: String? = null,
    @SerialName("entry_count") val entryCount: Int = 0,
    val similarity: Double? = null
)

@Serializable
data class ThreadDetail(
    val id: String? = null,
    val slug: String,
    val title: String? = null,
    val summary: String? = null,
    val status: String? = null,
    @SerialName("source_count") val sourceCount: Int = 0,
    @SerialName("unread_count") val unreadCount: Int = 0,
    @SerialName("entry_count") val entryCount: Int = 0,
    @SerialName("echo_count") val echoCount: Int = 0,
    @SerialName("first_seen") val firstSeen: String? = null,
    @SerialName("last_seen") val lastSeen: String? = null,
    @SerialName("key_entities") val keyEntities: List<ThreadKeyEntity> = emptyList(),
    val beats: List<ThreadBeat> = emptyList(),
    val members: List<ThreadMember> = emptyList(),
    @SerialName("thread_yield") val threadYield: ThreadYield? = null,
    val nearest: List<NearestThread> = emptyList()
)
