package com.example.intelfeed.data.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class UnifiedSearchRequest(
    val q: String,
    val limit: Int = 20,
    val offset: Int = 0,
    // The web's values: up to 200 entities in all, with no practical cap per type (500). The app
    // asked for 25 per type, so a search matching 200 CVEs could only ever list 25 of them.
    @SerialName("entity_limit") val entityLimit: Int = 200,
    @SerialName("entity_group_limit") val entityGroupLimit: Int = 500
)

@Serializable
data class SearchEntriesResult(
    val hits: List<EntryItem> = emptyList(),
    @SerialName("estimatedTotalHits") val estimatedTotalHits: Int = 0
)

@Serializable
data class SearchEntitiesResult(
    val items: List<SearchEntityItem> = emptyList(),
    // Untrimmed per-type totals; items is capped at entity_group_limit per type.
    val counts: Map<String, Int> = emptyMap()
)

@Serializable
data class SearchEntityItem(
    val id: String = "",
    val name: String? = null,
    // Notes use title instead of name.
    val title: String? = null,
    @SerialName("cve_id") val cveId: String? = null,
    @SerialName("technique_id") val techniqueId: String? = null,
    val type: String? = null,
    @SerialName("entity_type") val entityType: String? = null,
    val description: String? = null,
    // "direct" (the query hit its name/alias/id) or "mention" (description, tag, rule body…).
    @SerialName("match_kind") val matchKind: String? = null,
    val aliases: List<String> = emptyList(),
    @SerialName("article_count") val articleCount: Int? = null,
    // Notes: "note" (on an article, or standalone) or "entity_note" (on an entity).
    @SerialName("note_source") val noteSource: String? = null,
    @SerialName("entry_id") val entryId: String? = null,
    @SerialName("entry_title") val entryTitle: String? = null,
    @SerialName("entity_id") val entityId: String? = null,
    @SerialName("entity_name") val entityName: String? = null
) {
    // For entity notes, entity_type is the note's subject, so "type" must win.
    val displayType: String get() = type ?: entityType ?: "entity"
    val displayName: String
        get() = name?.takeIf { it.isNotBlank() }
            ?: title?.takeIf { it.isNotBlank() }
            ?: cveId?.takeIf { it.isNotBlank() }
            ?: techniqueId?.takeIf { it.isNotBlank() }
            ?: entityName?.let { "Note on $it" }
            ?: id.takeIf { it.isNotBlank() }
            ?: "Untitled"
    val isNote: Boolean get() = displayType.equals("note", ignoreCase = true)
}

@Serializable
data class ParsedFilter(
    val field: String = "",
    val value: String = "",
    val exact: Boolean = false,
    val negated: Boolean = false,
    val raw: String = ""
)

@Serializable
data class UnifiedSearchResponse(
    val query: String = "",
    val entries: SearchEntriesResult = SearchEntriesResult(),
    val entities: SearchEntitiesResult = SearchEntitiesResult(),
    @SerialName("parsed_filters") val parsedFilters: List<ParsedFilter> = emptyList(),
    @SerialName("did_you_mean") val didYouMean: String? = null,
    @SerialName("unknown_fields") val unknownFields: List<String> = emptyList(),
    @SerialName("processingTimeMs") val processingTimeMs: Long? = null
)

/** GET /api/search/autocomplete: e.g. {type: "value", text: "Qilin", field: "threat_actor", insert: "threat_actor:Qilin"}. */
@Serializable
data class SearchSuggestion(
    val type: String? = null,
    val text: String = "",
    val field: String? = null,
    val insert: String? = null
)

@Serializable
data class SavedSearch(
    val id: String,
    val name: String = "",
    @SerialName("display_name") val displayName: String? = null,
    val query: String = "",
    @SerialName("unread_count") val unreadCount: Int? = null,
    @SerialName("total_count") val totalCount: Int? = null,
    // The web stores the search page's scope with the query ({"scope": "everything"|"workbench"|"feeds", …}).
    val filters: SavedSearchFilters? = null
) {
    val label: String get() = displayName?.takeIf { it.isNotBlank() } ?: name.ifBlank { query }
}

@Serializable
data class SavedSearchFilters(val scope: String? = null)

@Serializable
data class CreateSavedSearchRequest(
    val name: String,
    val query: String
)
