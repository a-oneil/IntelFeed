package com.example.intelfeed.data.network

import com.example.intelfeed.data.model.AttachEntryRequest
import com.example.intelfeed.data.model.AuthTokens
import com.example.intelfeed.data.model.BulkActionRequest
import com.example.intelfeed.data.model.Campaign
import com.example.intelfeed.data.model.CreateCampaignRequest
import com.example.intelfeed.data.model.Category
import com.example.intelfeed.data.model.Country
import com.example.intelfeed.data.model.CreateEntityNoteRequest
import com.example.intelfeed.data.model.CreateFeedRequest
import com.example.intelfeed.data.model.CreateSavedSearchRequest
import com.example.intelfeed.data.model.CreateTagRequest
import com.example.intelfeed.data.model.CursorPage
import com.example.intelfeed.data.model.Cve
import com.example.intelfeed.data.model.Cwe
import com.example.intelfeed.data.model.DetectionRule
import com.example.intelfeed.data.model.EntityNote
import com.example.intelfeed.data.model.EntityRelationship
import com.example.intelfeed.data.model.EntryDetail
import com.example.intelfeed.data.model.EntryItem
import com.example.intelfeed.data.model.EntryNote
import com.example.intelfeed.data.model.FeedSource
import com.example.intelfeed.data.model.IngestUrlRequest
import com.example.intelfeed.data.model.IngestUrlResponse
import com.example.intelfeed.data.model.LoginRequest
import com.example.intelfeed.data.model.LogoutRequest
import com.example.intelfeed.data.model.Malware
import com.example.intelfeed.data.model.ObservableItem
import com.example.intelfeed.data.model.MarkAllReadRequest
import com.example.intelfeed.data.model.Mitigation
import com.example.intelfeed.data.model.NoteRequest
import com.example.intelfeed.data.model.PriorityQueueResponse
import com.example.intelfeed.data.model.Product
import com.example.intelfeed.data.model.RadarFeedbackRequest
import com.example.intelfeed.data.model.RefreshTokenRequest
import com.example.intelfeed.data.model.SavedSearch
import com.example.intelfeed.data.model.SearchSuggestion
import com.example.intelfeed.data.model.ShareLink
import com.example.intelfeed.data.model.SimilarEntriesResponse
import com.example.intelfeed.data.model.TagEntity
import com.example.intelfeed.data.model.TagIdsRequest
import com.example.intelfeed.data.model.ThreadDetail
import com.example.intelfeed.data.model.ThreadListResponse
import com.example.intelfeed.data.model.ColorSchemaDto
import com.example.intelfeed.data.model.ThreatActor
import com.example.intelfeed.data.model.ThemeDto
import com.example.intelfeed.data.model.ThemePreferenceUpdateRequest
import com.example.intelfeed.data.model.ThemePreferenceUpdateResponse
import com.example.intelfeed.data.model.Tool
import com.example.intelfeed.data.model.Ttp
import com.example.intelfeed.data.model.UnifiedSearchRequest
import com.example.intelfeed.data.model.UnifiedSearchResponse
import com.example.intelfeed.data.model.UpdateEntityNoteRequest
import com.example.intelfeed.data.model.UserProfile
import com.example.intelfeed.data.model.Vendor
import com.example.intelfeed.data.model.WatchlistItem
import com.example.intelfeed.data.model.WatchlistRequest
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.Header
import retrofit2.http.POST
import retrofit2.http.PUT
import retrofit2.http.Path
import retrofit2.http.Query

interface IntelFeedApi {

    // Auth

    @POST("api/auth/login")
    suspend fun login(@Body request: LoginRequest): AuthTokens

    @POST("api/auth/refresh")
    suspend fun refresh(@Body request: RefreshTokenRequest): AuthTokens

    /** Revokes the given tokens server-side. Takes the Authorization header explicitly because local tokens are cleared first. */
    @POST("api/auth/logout")
    suspend fun logout(
        @Header("Authorization") authorization: String,
        @Body request: LogoutRequest
    ): Response<Unit>

    @GET("api/auth/me")
    suspend fun getMe(): UserProfile

    @PUT("api/themes/user/preferences")
    suspend fun updateThemePreference(@Body request: ThemePreferenceUpdateRequest): ThemePreferenceUpdateResponse

    // Themes & Color Schema

    @GET("api/themes")
    suspend fun getThemes(): List<ThemeDto>

    @GET("api/themes/default")
    suspend fun getDefaultTheme(): ThemeDto?

    @GET("api/themes/schema")
    suspend fun getColorSchema(): ColorSchemaDto


    // Entries

    @GET("api/entries")
    suspend fun getEntries(
        @Query("is_read") isRead: Boolean? = null,
        @Query("is_starred") isStarred: Boolean? = null,
        @Query("is_bookmarked") isBookmarked: Boolean? = null,
        @Query("feed_id") feedId: String? = null,
        @Query("category_id") categoryId: String? = null,
        @Query("campaign_id") campaignId: String? = null,
        @Query("since") since: String? = null,
        @Query("sort") sort: String? = "newest",
        @Query("limit") limit: Int = 30,
        @Query("cursor") cursor: String? = null,
        // Articles about entities on your watchlist (the web's "Watched" view).
        @Query("watched") watched: Boolean? = null,
        @Query("before") before: String? = null,
        // A day chip's filter (DayFocus.params): exploited_cves, entity_type + entity_id, or sector.
        @retrofit2.http.QueryMap focus: Map<String, String> = emptyMap()
    ): CursorPage<EntryItem>

    /** Counts entries matching the same filters as GET /api/entries. The web always sends dedup=true here. */
    @GET("api/entries/count")
    suspend fun countEntries(
        @Query("is_read") isRead: Boolean? = null,
        @Query("is_starred") isStarred: Boolean? = null,
        @Query("is_bookmarked") isBookmarked: Boolean? = null,
        @Query("watched") watched: Boolean? = null,
        @Query("since") since: String? = null,
        @Query("dedup") dedup: Boolean? = true
    ): com.example.intelfeed.data.model.EntryCount

    /**
     * Per-entry intelligence summary for list cards (the web's badges): body is a JSON array of up
     * to 100 entry ids; the response maps each id to its counts. Reads only.
     */
    @POST("api/entries/intel-counts")
    suspend fun getIntelCounts(@Body entryIds: List<String>): kotlinx.serialization.json.JsonElement

    // Intelligence requirements (PIRs): shared, server-side questions with keywords that every
    // incoming article is matched against. Shapes checked on the live server, 2026-09-23.

    /** Leak-site victim postings (the web's Ransomware tracker). Filters repeat: group=a&group=b. */
    @GET("api/ransomware/disclosures")
    suspend fun getRansomwareDisclosures(
        @Query("limit") limit: Int,
        @Query("offset") offset: Int,
        @Query("sort") sort: String,
        @Query("group") groups: List<String>,
        @Query("sector") sectors: List<String>,
        @Query("country") countries: List<String>,
        @Query("watched_only") watchedOnly: Boolean?,
        @Query("since") sinceDays: Int?,
        @Query("q") q: String?
    ): com.example.intelfeed.data.model.RansomwareDisclosurePage

    @GET("api/ransomware/stats")
    suspend fun getRansomwareStats(@Query("days") days: Int): com.example.intelfeed.data.model.RansomwareStats

    /** The profile's relationship graph (nodes and edges around one entity). */
    @GET("api/intelligence/graph/{type}/{id}")
    suspend fun getEntityGraph(@Path("type") type: String, @Path("id") id: String, @Query("depth") depth: Int = 1, @Query("window_days") windowDays: Int? = null): kotlinx.serialization.json.JsonElement

    /** The web Workbench's ATT&CK Matrix. [days] null = all time. */
    @GET("api/attack/matrix")
    suspend fun getAttackMatrix(@Query("domain") domain: String, @Query("days") days: Int?): com.example.intelfeed.data.model.AttackMatrix

    // ENTITY TIMELINE (profile "Timeline" tab)

    @GET("api/entities/{type}/{id}/mentions-timeseries")
    suspend fun getMentionsTimeseries(@Path("type") type: String, @Path("id") id: String, @Query("window") window: String): com.example.intelfeed.data.model.MentionsTimeseries

    @GET("api/intelligence/timeline/{type}/{id}")
    suspend fun getEntityTimeline(@Path("type") type: String, @Path("id") id: String): com.example.intelfeed.data.model.EntityTimeline

    @GET("api/engine/entities/{type}/{id}/whats-new")
    suspend fun getWhatsNew(@Path("type") type: String, @Path("id") id: String, @Query("scoped") scoped: Boolean = true): CursorPage<com.example.intelfeed.data.model.WhatsNewItem>

    @GET("api/entities/{type}/{id}/story-threads")
    suspend fun getEntityStories(@Path("type") type: String, @Path("id") id: String, @Query("limit") limit: Int = 10, @Query("status") status: String = "any"): CursorPage<com.example.intelfeed.data.model.EntityStory>

    @GET("api/requirements")
    suspend fun getRequirements(
        @Query("limit") limit: Int = 200,
        @Query("offset") offset: Int = 0
    ): CursorPage<com.example.intelfeed.data.model.Requirement>

    @GET("api/requirements/{id}/matches")
    suspend fun getRequirementMatches(
        @Path("id") id: String,
        @Query("limit") limit: Int = 20,
        @Query("offset") offset: Int = 0
    ): CursorPage<com.example.intelfeed.data.model.RequirementMatch>

    @GET("api/entries/priority-unread-count")
    suspend fun getPriorityUnreadCount(): com.example.intelfeed.data.model.PriorityUnreadCount

    @GET("api/entries/priority-queue")
    suspend fun getPriorityQueue(
        @Query("limit") limit: Int = 30,
        @Query("cursor") cursor: String? = null
    ): PriorityQueueResponse

    @GET("api/entries/{id}")
    suspend fun getEntryDetail(@Path("id") id: String): EntryDetail

    @PUT("api/entries/{id}/read")
    suspend fun markRead(@Path("id") id: String): Response<Unit>

    @PUT("api/entries/{id}/unread")
    suspend fun markUnread(@Path("id") id: String): Response<Unit>

    // The server has no /unstar or /unbookmark routes: /star and /bookmark toggle. The repository
    // sets star/bookmark state explicitly through bulkAction instead, so a stale local flag can't
    // flip it the wrong way. Kept for reference only.
    @PUT("api/entries/{id}/star")
    suspend fun toggleStar(@Path("id") id: String): Response<Unit>

    @PUT("api/entries/{id}/bookmark")
    suspend fun toggleBookmark(@Path("id") id: String): Response<Unit>

    /** Explicit, idempotent state change: action is read, unread, star, unstar, bookmark, unbookmark or hide. */
    @POST("api/entries/bulk-action")
    suspend fun bulkAction(@Body request: BulkActionRequest): Response<Unit>

    /** Null feed/category fields mean every unread entry for the user. */
    @POST("api/entries/mark-all-read")
    suspend fun markAllRead(@Body request: MarkAllReadRequest): Response<Unit>

    @GET("api/entries/{id}/similar")
    suspend fun getSimilarEntries(@Path("id") id: String): SimilarEntriesResponse

    /** Returns the existing public link or creates one. */
    @POST("api/entries/{id}/share")
    suspend fun createShareLink(@Path("id") id: String): ShareLink

    @POST("api/entries/ingest/url")
    suspend fun ingestUrl(@Body request: IngestUrlRequest): IngestUrlResponse

    /**
     * Cached AI briefing for one day (day_key YYYY-MM-DD). The body is JSON null when none exists,
     * which a DailySummary return type can't decode, so the repository parses this. GET never generates.
     */
    @GET("api/entries/daily-summary")
    suspend fun getDailySummary(
        @Query("day_key") dayKey: String,
        @Query("feed_id") feedId: String? = null,
        @Query("category_id") categoryId: String? = null,
        @Query("is_starred") isStarred: Boolean? = null,
        @Query("is_bookmarked") isBookmarked: Boolean? = null,
        @Query("dedup") dedup: Boolean? = true
    ): kotlinx.serialization.json.JsonElement

    /**
     * The day's top entity of each type for a day divider. [since]/[before] are the local day's
     * bounds as UTC ISO timestamps; the filters are the same ones the web sends for the list.
     */
    @GET("api/entries/day-intel")
    suspend fun getDayIntel(
        @Query("since") since: String,
        @Query("before") before: String,
        @Query("feed_id") feedId: String? = null,
        @Query("category_id") categoryId: String? = null,
        @Query("is_starred") isStarred: Boolean? = null,
        @Query("is_bookmarked") isBookmarked: Boolean? = null,
        @Query("dedup") dedup: Boolean? = true
    ): kotlinx.serialization.json.JsonElement

    @PUT("api/engine/radar-feedback")
    suspend fun sendRadarFeedback(@Body request: RadarFeedbackRequest): Response<Unit>

    // Entities linked to one entry. GET /api/entries/{id} does not include them.

    @GET("api/entries/{id}/threat-actors")
    suspend fun getEntryThreatActors(@Path("id") id: String): List<ThreatActor>

    @GET("api/entries/{id}/malware")
    suspend fun getEntryMalware(@Path("id") id: String): List<Malware>

    @GET("api/entries/{id}/cves")
    suspend fun getEntryCves(@Path("id") id: String): List<Cve>

    @GET("api/entries/{id}/ttps")
    suspend fun getEntryTtps(@Path("id") id: String): List<Ttp>

    @GET("api/entries/{id}/countries")
    suspend fun getEntryCountries(@Path("id") id: String): List<Country>

    @GET("api/entries/{id}/tools")
    suspend fun getEntryTools(@Path("id") id: String): List<Tool>

    @GET("api/entries/{id}/vendors")
    suspend fun getEntryVendors(@Path("id") id: String): List<Vendor>

    @GET("api/entries/{id}/products")
    suspend fun getEntryProducts(@Path("id") id: String): List<Product>

    // Also used by the web reader to mark names in the text. Read as JSON and decoded item by item
    // (IntelFeedRepository.decodeItems), so one odd row doesn't empty the whole list.

    @GET("api/entries/{id}/cwes")
    suspend fun getEntryCwes(@Path("id") id: String): kotlinx.serialization.json.JsonElement

    @GET("api/entries/{id}/mitigations")
    suspend fun getEntryMitigations(@Path("id") id: String): kotlinx.serialization.json.JsonElement

    /** {"items": [...]} (the web reads `.items`); a bare array is accepted too. */
    @GET("api/entries/{id}/observables")
    suspend fun getEntryObservables(@Path("id") id: String): kotlinx.serialization.json.JsonElement

    /** Glossary terms in the article. A POST, but it only reads (the web reader sends it for every article). */
    @POST("api/glossary/detect")
    suspend fun detectGlossary(@Body request: com.example.intelfeed.data.model.GlossaryDetectRequest): kotlinx.serialization.json.JsonElement

    // Story threads

    @GET("api/threads")
    suspend fun getThreads(
        @Query("status") status: String = "open",
        @Query("limit") limit: Int = 40
    ): ThreadListResponse

    @GET("api/threads/{slug}")
    suspend fun getThread(@Path("slug") slug: String): ThreadDetail

    /** Stamps the thread as seen; new_since_opened counts from here. Takes the thread id. */
    @POST("api/threads/{id}/open")
    suspend fun markThreadOpened(@Path("id") threadId: String): Response<Unit>

    // Notes on articles

    @GET("api/notes/entry/{entryId}")
    suspend fun getEntryNotes(@Path("entryId") entryId: String): List<EntryNote>

    @POST("api/notes/entry/{entryId}")
    suspend fun createEntryNote(@Path("entryId") entryId: String, @Body request: NoteRequest): EntryNote

    @PUT("api/notes/{id}")
    suspend fun updateNote(@Path("id") id: String, @Body request: NoteRequest): EntryNote

    @DELETE("api/notes/{id}")
    suspend fun deleteNote(@Path("id") id: String): Response<Unit>

    // Tags

    @GET("api/tags")
    suspend fun getTags(): List<TagEntity>

    @POST("api/tags")
    suspend fun createTag(@Body request: CreateTagRequest): TagEntity

    @GET("api/tags/entries/{entryId}")
    suspend fun getEntryTags(@Path("entryId") entryId: String): List<TagEntity>

    @POST("api/tags/entries/{entryId}")
    suspend fun addEntryTags(@Path("entryId") entryId: String, @Body request: TagIdsRequest): Response<Unit>

    @DELETE("api/tags/entries/{entryId}/{tagId}")
    suspend fun removeEntryTag(@Path("entryId") entryId: String, @Path("tagId") tagId: String): Response<Unit>

    @DELETE("api/tags/{tagId}")
    suspend fun deleteTag(@Path("tagId") tagId: String): Response<Unit>

    // Feeds & categories

    @GET("api/categories")
    suspend fun getCategories(): List<Category>

    @GET("api/feeds")
    suspend fun getFeeds(
        @Query("category_id") categoryId: String? = null,
        @Query("search") search: String? = null,
        @Query("limit") limit: Int = 1000,
        @Query("offset") offset: Int = 0
    ): CursorPage<FeedSource>

    @POST("api/feeds")
    suspend fun createFeed(@Body request: CreateFeedRequest): FeedSource

    /** Looks for a feed at a feed or website address. Read-only: nothing is subscribed. See DiscoveredFeed for the two response shapes. */
    @POST("api/feeds/discover")
    suspend fun discoverFeed(@Body request: IngestUrlRequest): kotlinx.serialization.json.JsonElement

    @POST("api/feeds/{id}/refresh")
    suspend fun refreshFeed(@Path("id") id: String): Response<Unit>

    // Workbench lists and entity detail. List responses are offset-paged with a total.

    @GET("api/threat-actors")
    suspend fun getThreatActors(
        @Query("search") search: String? = null,
        @Query("sort") sort: String? = "activity",
        @Query("limit") limit: Int = 30,
        @Query("offset") offset: Int = 0
    ): CursorPage<ThreatActor>

    @GET("api/threat-actors/{id}")
    suspend fun getThreatActor(@Path("id") id: String): ThreatActor

    @GET("api/malware")
    suspend fun getMalware(
        @Query("search") search: String? = null,
        @Query("limit") limit: Int = 30,
        @Query("offset") offset: Int = 0
    ): CursorPage<Malware>

    @GET("api/malware/{id}")
    suspend fun getMalwareDetail(@Path("id") id: String): Malware

    @GET("api/cves")
    suspend fun getCves(
        @Query("search") search: String? = null,
        @Query("limit") limit: Int = 30,
        @Query("offset") offset: Int = 0
    ): CursorPage<Cve>

    /** Takes the CVE identifier (e.g. CVE-2024-1234), not the row id. */
    @GET("api/cves/{cveId}")
    suspend fun getCveDetail(@Path("cveId") cveId: String): Cve

    @GET("api/cwes")
    suspend fun getCwes(
        @Query("search") search: String? = null,
        @Query("limit") limit: Int = 30,
        @Query("offset") offset: Int = 0
    ): CursorPage<Cwe>

    @GET("api/cwes/{cweId}")
    suspend fun getCweDetail(@Path("cweId") cweId: String): Cwe

    @GET("api/observables")
    suspend fun getObservables(
        @Query("search") search: String? = null,
        // The web's filter name for ipv4 / domain / url / sha256 …
        @Query("kind") kind: String? = null,
        @Query("limit") limit: Int = 30,
        @Query("offset") offset: Int = 0
    ): CursorPage<ObservableItem>

    @GET("api/observables/{id}")
    suspend fun getObservable(@Path("id") id: String): ObservableItem

    @GET("api/ttps")
    suspend fun getTtps(
        @Query("search") search: String? = null,
        @Query("limit") limit: Int = 30,
        @Query("offset") offset: Int = 0
    ): CursorPage<Ttp>

    /** There is no /api/ttps/{id}; the web client looks techniques up by ATT&CK id. */
    @GET("api/ttps/by-technique/{techniqueId}")
    suspend fun getTtpByTechnique(@Path("techniqueId") techniqueId: String): Ttp

    @GET("api/campaigns")
    suspend fun getCampaigns(
        @Query("search") search: String? = null,
        @Query("limit") limit: Int = 30,
        @Query("offset") offset: Int = 0
    ): CursorPage<Campaign>

    @GET("api/campaigns/{id}")
    suspend fun getCampaign(@Path("id") id: String): Campaign

    @POST("api/campaigns")
    suspend fun createCampaign(@Body request: CreateCampaignRequest): Campaign

    @POST("api/campaigns/{id}/entries")
    suspend fun attachEntryToCampaign(
        @Path("id") id: String,
        @Body request: AttachEntryRequest
    ): Response<Unit>

    /** Adds several articles in one request (the web's bulk "add to campaign"). */
    @POST("api/campaigns/{id}/entries/bulk")
    suspend fun attachEntriesToCampaign(
        @Path("id") id: String,
        @Body request: com.example.intelfeed.data.model.EntryIdsRequest
    ): Response<Unit>

    @DELETE("api/campaigns/{id}/entries/{entryId}")
    suspend fun detachEntryFromCampaign(
        @Path("id") id: String,
        @Path("entryId") entryId: String
    ): Response<Unit>

    @GET("api/campaigns/by-entry/{entryId}")
    suspend fun getCampaignsByEntry(
        @Path("entryId") entryId: String
    ): List<String>

    @GET("api/detection-rules")
    suspend fun getDetectionRules(
        @Query("search") search: String? = null,
        @Query("rule_type") ruleType: String? = null,
        @Query("limit") limit: Int = 30,
        @Query("offset") offset: Int = 0
    ): CursorPage<DetectionRule>

    @GET("api/detection-rules/{id}")
    suspend fun getDetectionRule(@Path("id") id: String): DetectionRule

    @GET("api/vendors")
    suspend fun getVendors(
        @Query("search") search: String? = null,
        @Query("limit") limit: Int = 30,
        @Query("offset") offset: Int = 0
    ): CursorPage<Vendor>

    @GET("api/vendors/{id}")
    suspend fun getVendor(@Path("id") id: String): Vendor

    @GET("api/products")
    suspend fun getProducts(
        @Query("search") search: String? = null,
        @Query("limit") limit: Int = 30,
        @Query("offset") offset: Int = 0
    ): CursorPage<Product>

    @GET("api/products/{id}")
    suspend fun getProduct(@Path("id") id: String): Product

    @GET("api/tools")
    suspend fun getTools(
        @Query("search") search: String? = null,
        @Query("limit") limit: Int = 30,
        @Query("offset") offset: Int = 0
    ): CursorPage<Tool>

    @GET("api/tools/{id}")
    suspend fun getTool(@Path("id") id: String): Tool

    @GET("api/countries")
    suspend fun getCountries(
        @Query("search") search: String? = null,
        @Query("limit") limit: Int = 30,
        @Query("offset") offset: Int = 0
    ): CursorPage<Country>

    @GET("api/countries/{id}")
    suspend fun getCountry(@Path("id") id: String): Country

    @GET("api/mitigations")
    suspend fun getMitigations(
        @Query("search") search: String? = null,
        @Query("limit") limit: Int = 30,
        @Query("offset") offset: Int = 0
    ): CursorPage<Mitigation>

    @GET("api/mitigations/{id}")
    suspend fun getMitigation(@Path("id") id: String): Mitigation

    // Relationships, entity notes, watchlist

    @GET("api/entity-relationships")
    suspend fun getRelationships(
        @Query("entity_type") entityType: String,
        @Query("entity_id") entityId: String,
        @Query("limit") limit: Int = 50,
        @Query("offset") offset: Int = 0
    ): CursorPage<EntityRelationship>

    @GET("api/entity-notes")
    suspend fun getEntityNotes(
        @Query("entity_type") entityType: String,
        @Query("entity_id") entityId: String,
        @Query("limit") limit: Int = 50
    ): CursorPage<EntityNote>

    @POST("api/entity-notes")
    suspend fun createEntityNote(@Body request: CreateEntityNoteRequest): EntityNote

    @PUT("api/entity-notes/{id}")
    suspend fun updateEntityNote(@Path("id") id: String, @Body request: UpdateEntityNoteRequest): EntityNote

    @DELETE("api/entity-notes/{id}")
    suspend fun deleteEntityNote(@Path("id") id: String): Response<Unit>

    @GET("api/intelligence/watchlist")
    suspend fun getWatchlist(): List<WatchlistItem>

    @PUT("api/intelligence/watchlist")
    suspend fun setWatchlistEntry(@Body request: WatchlistRequest): Response<Unit>

    @DELETE("api/intelligence/watchlist/{type}/{id}")
    suspend fun removeWatchlistEntry(@Path("type") entityType: String, @Path("id") entityId: String): Response<Unit>

    // Search

    @POST("api/search/unified")
    suspend fun searchUnified(@Body request: UnifiedSearchRequest): UnifiedSearchResponse

    @GET("api/search/autocomplete")
    suspend fun autocomplete(@Query("q") query: String): List<SearchSuggestion>

    @GET("api/saved-searches")
    suspend fun getSavedSearches(): List<SavedSearch>

    @POST("api/saved-searches")
    suspend fun createSavedSearch(@Body request: CreateSavedSearchRequest): SavedSearch

    @DELETE("api/saved-searches/{id}")
    suspend fun deleteSavedSearch(@Path("id") id: String): Response<Unit>
}
