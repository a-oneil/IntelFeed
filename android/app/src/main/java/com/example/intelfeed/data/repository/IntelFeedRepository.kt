package com.example.intelfeed.data.repository

import com.example.intelfeed.data.local.AuthPreferences
import com.example.intelfeed.data.model.AttachEntryRequest
import com.example.intelfeed.data.model.BulkActionRequest
import com.example.intelfeed.data.model.Campaign
import com.example.intelfeed.data.model.Category
import com.example.intelfeed.data.model.CreateCampaignRequest
import com.example.intelfeed.data.model.Country
import com.example.intelfeed.data.model.CreateEntityNoteRequest
import com.example.intelfeed.data.model.CreateFeedRequest
import com.example.intelfeed.data.model.CreateSavedSearchRequest
import com.example.intelfeed.data.model.CreateTagRequest
import com.example.intelfeed.data.model.CursorPage
import com.example.intelfeed.data.model.Cve
import com.example.intelfeed.data.model.Cwe
import com.example.intelfeed.data.model.DailySummary
import com.example.intelfeed.data.model.DayIntel
import com.example.intelfeed.data.model.DetectionRule
import com.example.intelfeed.data.model.DiscoveredFeed
import com.example.intelfeed.data.model.EntityNote
import com.example.intelfeed.data.model.EntityRelationship
import com.example.intelfeed.data.model.ObservableItem
import com.example.intelfeed.data.model.EntryDetail
import com.example.intelfeed.data.model.EntryIntel
import com.example.intelfeed.data.model.EntryIntelCounts
import com.example.intelfeed.data.model.EntryItem
import com.example.intelfeed.data.model.EntryNote
import com.example.intelfeed.data.model.FeedSource
import com.example.intelfeed.data.model.IngestUrlRequest
import com.example.intelfeed.data.model.IngestUrlResponse
import com.example.intelfeed.data.model.LoginRequest
import com.example.intelfeed.data.model.LogoutRequest
import com.example.intelfeed.data.model.Malware
import com.example.intelfeed.data.model.MarkAllReadRequest
import com.example.intelfeed.data.model.Mitigation
import com.example.intelfeed.data.model.NoteRequest
import com.example.intelfeed.data.model.Product
import com.example.intelfeed.data.model.RadarFeedbackRequest
import com.example.intelfeed.data.model.SavedSearch
import com.example.intelfeed.data.model.SearchSuggestion
import com.example.intelfeed.data.model.SimilarEntry
import com.example.intelfeed.data.model.TagEntity
import com.example.intelfeed.data.model.TagIdsRequest
import com.example.intelfeed.data.model.ThreadDetail
import com.example.intelfeed.data.model.ColorSchemaDto
import com.example.intelfeed.data.model.ThreatActor
import com.example.intelfeed.data.model.ThemeDto
import com.example.intelfeed.data.model.ThemePreferenceUpdateRequest
import com.example.intelfeed.data.model.Tool
import com.example.intelfeed.data.model.Ttp
import com.example.intelfeed.data.model.UnifiedSearchRequest
import com.example.intelfeed.data.model.UnifiedSearchResponse
import com.example.intelfeed.data.model.UpdateEntityNoteRequest
import com.example.intelfeed.data.model.UserProfile
import com.example.intelfeed.data.model.Vendor
import com.example.intelfeed.data.model.WatchlistItem
import com.example.intelfeed.data.model.WatchlistRequest

import com.example.intelfeed.data.network.ApiClient
import com.example.intelfeed.data.network.IntelFeedApi
import com.example.intelfeed.util.DateUtils
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import okhttp3.OkHttpClient
import retrofit2.HttpException
import retrofit2.Response
import android.util.Log
import com.example.intelfeed.BuildConfig
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import kotlin.coroutines.cancellation.CancellationException

enum class FeedFilter(val label: String) {
    PRIORITY_QUEUE("Priority Queue"),
    UNREAD("Unread"),
    LAST_24H("Last 24 hours"),
    THIS_WEEK("This week"),
    // Articles about entities you watch (GET /api/entries?watched=true), like the web's quick view.
    WATCHED("Watched"),
    ALL("All articles"),
    STARRED("Starred"),
    BOOKMARKED("Bookmarked")
}

/**
 * Unread counts for the quick views, as the web sidebar shows them. Null means unknown (not loaded
 * or the request failed); "All articles" has no count.
 */
data class ViewCounts(
    val priority: Int? = null,
    val unread: Int? = null,
    val last24h: Int? = null,
    val thisWeek: Int? = null,
    val watched: Int? = null,
    val starred: Int? = null,
    val bookmarked: Int? = null
) {
    fun forFilter(filter: FeedFilter): Int? = when (filter) {
        FeedFilter.PRIORITY_QUEUE -> priority
        FeedFilter.UNREAD -> unread
        FeedFilter.LAST_24H -> last24h
        FeedFilter.THIS_WEEK -> thisWeek
        FeedFilter.WATCHED -> watched
        FeedFilter.STARRED -> starred
        FeedFilter.BOOKMARKED -> bookmarked
        FeedFilter.ALL -> null
    }
}

/**
 * A change to an entry's read/star/bookmark flags. Every screen showing entries applies these, so a
 * star in the reader also shows in the feed list, search results and story threads. A failed request
 * is followed by the reverse update.
 */
data class EntryFlagUpdate(
    val id: String,
    val isRead: Boolean? = null,
    val isStarred: Boolean? = null,
    val isBookmarked: Boolean? = null,
    /** True only after the server accepted this change. */
    val confirmed: Boolean = false
)

/**
 * The list a day divider belongs to, sent with the day's chips and briefing so they describe the
 * same articles (the web sends the list's feed/folder/starred/bookmarked filters too).
 */
data class DayScope(
    val feedId: String? = null,
    val categoryId: String? = null,
    val starred: Boolean = false,
    val bookmarked: Boolean = false
)

/** One page of an offset-paged list: the items plus whether another page exists. */
data class OffsetPage<T>(val items: List<T>, val total: Int?, val hasMore: Boolean, val nextOffset: Int)

/**
 * The app's single source of server data. There is exactly one instance per process (see
 * IntelFeedApplication), so every ViewModel shares one OkHttp client and one token-refresh lock.
 */
class IntelFeedRepository(
    private val authPreferences: AuthPreferences
) {
    private val apiClient = ApiClient(authPreferences)

    // Built on first use and rebuilt when the stored server URL changes, so constructing the
    // repository never blocks the main thread on a DataStore read.
    @Volatile
    private var cachedApi: Pair<String, IntelFeedApi>? = null

    val isLoggedIn: Flow<Boolean> = authPreferences.isLoggedIn
    val serverUrl: Flow<String> = authPreferences.serverUrl
    val username: Flow<String?> = authPreferences.username

    private val _entryUpdates = MutableSharedFlow<EntryFlagUpdate>(extraBufferCapacity = 256)
    val entryUpdates: SharedFlow<EntryFlagUpdate> = _entryUpdates.asSharedFlow()
    // Keep rapid read/undo requests for one article in user order. A fixed set avoids retaining
    // one lock per article for the lifetime of the app.
    private val readMutationLocks = Array(64) { Mutex() }

    // The signed-in user (id + role decide who may edit a shared note). Null until loaded.
    private val _currentUser = MutableStateFlow<UserProfile?>(null)
    val currentUser: StateFlow<UserProfile?> = _currentUser.asStateFlow()

    private suspend fun getApi(): IntelFeedApi {
        val serverUrl = authPreferences.getServerUrl()
        cachedApi?.let { (url, api) -> if (url == serverUrl) return api }
        return apiClient.createApi(serverUrl).also { cachedApi = serverUrl to it }
    }

    suspend fun currentServerUrl(): String = authPreferences.getServerUrl()

    /** HTTP client for article images: sends the session token only to the IntelFeed server itself. */
    fun imageHttpClient(): OkHttpClient = apiClient.imageHttpClient()

    /**
     * Like runCatching, but lets coroutine cancellation propagate. The ViewModels cancel stale
     * loads; reporting that cancellation as a failure would show a bogus error.
     */
    private inline fun <T> apiCall(block: () -> T): Result<T> {
        return try {
            Result.success(block())
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            if (BuildConfig.DEBUG) {
                runCatching { Log.e("IntelFeedRepo", "apiCall error: ${e.message}", e) }
            }
            Result.failure(e)
        }
    }

    /** Endpoints returning Response<Unit> don't throw on 4xx/5xx; without this, failures looked like success. */
    private fun Response<*>.requireSuccess() {
        if (!isSuccessful) throw HttpException(this)
    }

    private fun <T> CursorPage<T>.toOffsetPage(offset: Int): OffsetPage<T> {
        val next = offset + items.size
        val more = total?.let { next < it } ?: (hasMore || items.isNotEmpty() && nextCursor != null)
        return OffsetPage(items, total, more && items.isNotEmpty(), next)
    }

    // AUTH

    /** [serverUrl] must be a valid http(s) URL (see ServerUrl.normalize); it is saved before signing in. */
    suspend fun login(serverUrl: String, username: String, password: String): Result<UserProfile> = apiCall {
        authPreferences.setServerUrl(serverUrl)
        val tokens = getApi().login(LoginRequest(username = username, password = password))
        // Not the previous session's user (a session that expired never went through logout()).
        _currentUser.value = null
        authPreferences.saveAuthTokens(
            accessToken = tokens.accessToken,
            refreshToken = tokens.refreshToken,
            username = username
        )
        loadCurrentUser().getOrElse { UserProfile(username = username, role = "analyst").also { _currentUser.value = it } }
    }

    // Saving the tokens starts the app's data load, which also asks for the user; with this, the
    // sign-in and that load share one GET /api/auth/me instead of sending two.
    private val currentUserLock = Mutex()

    /** The signed-in user, loaded once per session. */
    suspend fun loadCurrentUser(): Result<UserProfile> = currentUserLock.withLock {
        _currentUser.value?.let { return@withLock Result.success(it) }
        apiCall { getApi().getMe().also { _currentUser.value = it } }
    }

    /**
     * Clears the session locally first so the UI signs out right away, then asks the server to
     * revoke the tokens (best effort, 5 s cap). Without the revoke, the 7-day refresh token
     * stayed valid after logout.
     */
    suspend fun logout() {
        val accessToken = authPreferences.getAccessToken()
        val refreshToken = authPreferences.getRefreshToken()
        authPreferences.clear()
        _currentUser.value = null
        if (accessToken.isNullOrBlank()) return
        apiCall {
            withTimeoutOrNull(5_000) {
                getApi().logout("Bearer $accessToken", LogoutRequest(refreshToken = refreshToken))
            }
        }
    }

    // THEMES & COLOR SCHEMA

    suspend fun getThemes(): Result<List<ThemeDto>> = apiCall { getApi().getThemes() }

    suspend fun getDefaultTheme(): Result<ThemeDto?> = apiCall { getApi().getDefaultTheme() }

    suspend fun getColorSchema(): Result<ColorSchemaDto> = apiCall { getApi().getColorSchema() }

    suspend fun updateThemePreference(themeId: String?): Result<UserProfile?> = apiCall {
        val resp = getApi().updateThemePreference(
            ThemePreferenceUpdateRequest(
                themeId = themeId,
                clearTheme = themeId == null
            )
        )
        val updated = _currentUser.value?.copy(themeId = resp.themeId)
        _currentUser.value = updated
        updated
    }

    // FEED

    suspend fun getEntries(
        filter: FeedFilter,
        cursor: String? = null,
        feedId: String? = null,
        categoryId: String? = null,
        limit: Int = 30,
        // "Hide read" for date-ordered views; the Unread and Priority Queue views are unread anyway.
        hideRead: Boolean = false,
        // "newest" or "oldest". Doesn't apply to the ranked Priority Queue.
        sort: String = "newest",
        // A day chip's filter: that day's articles only, narrowed like the web's day focus.
        dayFocus: com.example.intelfeed.data.model.DayFocus? = null
    ): Result<CursorPage<EntryItem>> = apiCall {
        // The chip's day, when the filter is on that day (the web's behaviour).
        val focusBounds = dayFocus?.takeIf { it.window == com.example.intelfeed.data.model.FocusWindow.DAY }?.let { DateUtils.dayBounds(it.dayKey) }
        // The priority-queue endpoint can't filter by feed or category. A scoped Priority Queue
        // view uses that scope's unread entries (the closest equivalent) rather than silently
        // showing the unscoped queue under the category banner.
        if (filter == FeedFilter.PRIORITY_QUEUE && feedId == null && categoryId == null && dayFocus == null) {
            val pq = getApi().getPriorityQueue(limit = limit, cursor = cursor)
            val mappedItems = pq.items.mapNotNull { item ->
                when {
                    item.entry != null -> item.entry.copy(priorityScore = item.score)
                    item.thread != null -> {
                        // A story row: it opens the thread reader, not one of its articles.
                        val key = item.thread.slug ?: item.thread.id ?: return@mapNotNull null
                        EntryItem(
                            id = "thread:$key",
                            title = item.thread.title ?: "Story thread",
                            summary = item.thread.summary,
                            publishedAt = item.thread.lastSeen,
                            // The best unread article's 0–10 score, not the row's rank: the rank
                            // adds an outlet bonus that pins nearly every story at 10 (and would
                            // make every well-covered story send an alert).
                            priorityScore = item.thread.topScore ?: item.score,
                            isRead = item.thread.unreadCount == 0,
                            thread = item.thread
                        )
                    }
                    else -> null
                }
            }
            CursorPage(items = mappedItems, nextCursor = pq.nextCursor, hasMore = pq.hasMore)
        } else {
            getApi().getEntries(
                isRead = if (filter == FeedFilter.UNREAD || filter == FeedFilter.PRIORITY_QUEUE || hideRead) false else null,
                isStarred = if (filter == FeedFilter.STARRED) true else null,
                isBookmarked = if (filter == FeedFilter.BOOKMARKED) true else null,
                feedId = feedId,
                categoryId = categoryId,
                since = run {
                    val viewSince = when (filter) {
                        FeedFilter.LAST_24H -> isoTimestamp(System.currentTimeMillis() - 24 * HOUR_MS)
                        FeedFilter.THIS_WEEK -> isoTimestamp(System.currentTimeMillis() - 7 * 24 * HOUR_MS)
                        else -> null
                    }
                    // A chip filter with its own range replaces the view's range.
                    val window = dayFocus?.window
                    when (window) {
                        com.example.intelfeed.data.model.FocusWindow.H24, com.example.intelfeed.data.model.FocusWindow.D7,
                        com.example.intelfeed.data.model.FocusWindow.D30 ->
                            return@run isoTimestamp(System.currentTimeMillis() - (window.hours ?: 24) * HOUR_MS)
                        com.example.intelfeed.data.model.FocusWindow.ALL -> return@run null
                        else -> Unit
                    }
                    // As on the web: the day's start, unless the view's own window starts later.
                    val daySince = focusBounds?.first
                    when {
                        daySince == null -> viewSince
                        viewSince == null -> daySince
                        DateUtils.parseIsoMillis(daySince) > DateUtils.parseIsoMillis(viewSince) -> daySince
                        else -> viewSince
                    }
                },
                sort = if (sort == "oldest") "oldest" else "newest",
                limit = limit,
                cursor = cursor,
                watched = if (filter == FeedFilter.WATCHED) true else null,
                before = focusBounds?.second,
                focus = dayFocus?.params.orEmpty()
            )
        }
    }

    /**
     * The quick views' unread counts, fetched in parallel the way the web sidebar does: unread
     * entries per view (dedup=true, time windows rounded down to the hour), and for the Priority
     * Queue its unread count plus open stories that still have unread articles. A failed count is null.
     */
    suspend fun getViewCounts(): ViewCounts = coroutineScope {
        val api = getApi()
        val hour = System.currentTimeMillis() / HOUR_MS * HOUR_MS
        suspend fun count(isStarred: Boolean? = null, isBookmarked: Boolean? = null, watched: Boolean? = null, since: String? = null) =
            apiCall { api.countEntries(isRead = false, isStarred = isStarred, isBookmarked = isBookmarked, watched = watched, since = since).total }.getOrNull()
        val unread = async { count() }
        val day = async { count(since = isoTimestamp(hour - 24 * HOUR_MS)) }
        val week = async { count(since = isoTimestamp(hour - 7 * 24 * HOUR_MS)) }
        val watched = async { count(watched = true) }
        val starred = async { count(isStarred = true) }
        val bookmarked = async { count(isBookmarked = true) }
        // Both halves of the Priority Queue count start together; the stories request used to wait
        // for the entry count (up to ~2 s on the live server) before it was even sent.
        val priorityEntries = async { apiCall { api.getPriorityUnreadCount().unreadCount }.getOrNull() }
        val priorityStories = async { apiCall { api.getThreads(status = "open", limit = 40).threads.count { it.unreadCount > 0 } }.getOrDefault(0) }
        val priority = priorityEntries.await()?.let { it + priorityStories.await() }
        ViewCounts(priority, unread.await(), day.await(), week.await(), watched.await(), starred.await(), bookmarked.await())
    }


    /**
     * The web list's per-article intel badges, in batches of 100 ids like the web client. Entries
     * without anything extracted aren't in the map; a batch that fails is simply missing.
     */
    suspend fun getIntelCounts(ids: List<String>): Map<String, EntryIntelCounts> {
        val api = getApi()
        val out = mutableMapOf<String, EntryIntelCounts>()
        for (batch in ids.distinct().chunked(100)) {
            val element = apiCall { api.getIntelCounts(batch) }.getOrNull() as? JsonObject ?: continue
            element.forEach { (id, value) ->
                runCatching { apiClient.json.decodeFromJsonElement(EntryIntelCounts.serializer(), value) }.getOrNull()?.let { out[id] = it }
            }
        }
        return out
    }


    suspend fun getRansomwareDisclosures(
        offset: Int, sort: String, groups: List<String>, sectors: List<String>, countries: List<String>,
        watchedOnly: Boolean, sinceDays: Int?, q: String?
    ): Result<com.example.intelfeed.data.model.RansomwareDisclosurePage> = apiCall {
        getApi().getRansomwareDisclosures(60, offset, sort, groups, sectors, countries, if (watchedOnly) true else null, sinceDays, q?.trim()?.ifEmpty { null })
    }

    suspend fun getRansomwareStats(days: Int): Result<com.example.intelfeed.data.model.RansomwareStats> =
        apiCall { getApi().getRansomwareStats(days) }

    suspend fun getEntityGraph(type: String, id: String, windowDays: Int? = null): Result<com.example.intelfeed.data.model.EntityGraph> = apiCall {
        apiClient.json.decodeFromJsonElement(com.example.intelfeed.data.model.EntityGraph.serializer(), getApi().getEntityGraph(type, id, 1, windowDays))
    }

    suspend fun getAttackMatrix(domain: String, days: Int?): Result<com.example.intelfeed.data.model.AttackMatrix> =
        apiCall { getApi().getAttackMatrix(domain, days) }

    // ENTITY TIMELINE. [type] is the server's type name in these paths (see EntityType.timelinePath).

    suspend fun getMentionsTimeseries(type: String, id: String, window: String): Result<com.example.intelfeed.data.model.MentionsTimeseries> =
        apiCall { getApi().getMentionsTimeseries(type, id, window) }

    suspend fun getEntityTimeline(type: String, id: String): Result<List<com.example.intelfeed.data.model.TimelineEvent>> =
        apiCall { getApi().getEntityTimeline(type, id).events }

    suspend fun getWhatsNew(type: String, id: String): Result<List<com.example.intelfeed.data.model.WhatsNewItem>> =
        apiCall { getApi().getWhatsNew(type, id).items }

    suspend fun getEntityStories(type: String, id: String): Result<List<com.example.intelfeed.data.model.EntityStory>> =
        apiCall { getApi().getEntityStories(type, id).items }

    // INTELLIGENCE REQUIREMENTS (shared, server-side keyword matching)

    suspend fun getRequirements(): Result<List<com.example.intelfeed.data.model.Requirement>> = apiCall { getApi().getRequirements().items }

    suspend fun getRequirementMatches(id: String, offset: Int = 0): Result<OffsetPage<com.example.intelfeed.data.model.RequirementMatch>> =
        apiCall { getApi().getRequirementMatches(id, offset = offset).toOffsetPage(offset) }

    /** A requirement matching [keywords] for everyone on the server. */
    suspend fun createRequirement(title: String, keywords: List<String>, description: String? = null): Result<com.example.intelfeed.data.model.Requirement> =
        apiCall { getApi().createRequirement(com.example.intelfeed.data.model.CreateRequirementRequest(title = title, description = description, keywords = keywords)) }

    suspend fun getCategories(): Result<List<Category>> = apiCall { getApi().getCategories() }

    /** Every feed (the web client asks for 1000; the drawer used to stop at 100 of ~300). */
    suspend fun getFeeds(): Result<List<FeedSource>> = apiCall { getApi().getFeeds(limit = 1000).items }

    suspend fun createFeed(
        url: String,
        categoryId: String? = null,
        title: String? = null,
        fetchIntervalMinutes: Int? = null
    ): Result<FeedSource> = apiCall {
        getApi().createFeed(CreateFeedRequest(url = url, categoryId = categoryId, title = title, fetchIntervalMinutes = fetchIntervalMinutes))
    }

    /** Feeds found at [url] (a feed or a website address). Fails with NoSuchElementException when there are none. */
    suspend fun discoverFeeds(url: String): Result<List<DiscoveredFeed>> = apiCall {
        val found = parseDiscoveredFeeds(getApi().discoverFeed(IngestUrlRequest(url)), apiClient.json)
        if (found.isEmpty()) throw NoSuchElementException("No feed found at $url")
        found
    }

    // ENTRY STATE. Each change is broadcast before the request (optimistic) and reversed on failure.

    suspend fun setRead(id: String, read: Boolean): Result<Unit> =
        readMutationLocks[id.hashCode() and (readMutationLocks.size - 1)].withLock {
            changeFlags(listOf(id), EntryFlagUpdate(id, isRead = read), EntryFlagUpdate(id, isRead = !read)) {
                val response = if (read) getApi().markRead(id) else getApi().markUnread(id)
                response.requireSuccess()
            }
        }

    suspend fun setStarred(id: String, starred: Boolean): Result<Unit> =
        changeFlags(listOf(id), EntryFlagUpdate(id, isStarred = starred), EntryFlagUpdate(id, isStarred = !starred)) {
            getApi().bulkAction(BulkActionRequest(listOf(id), if (starred) "star" else "unstar")).requireSuccess()
        }

    suspend fun setBookmarked(id: String, bookmarked: Boolean): Result<Unit> =
        changeFlags(listOf(id), EntryFlagUpdate(id, isBookmarked = bookmarked), EntryFlagUpdate(id, isBookmarked = !bookmarked)) {
            getApi().bulkAction(BulkActionRequest(listOf(id), if (bookmarked) "bookmark" else "unbookmark")).requireSuccess()
        }

    /**
     * Applies one flag to many entries with POST /api/entries/bulk-action. [previous] holds each
     * entry's current value so a failure can restore it.
     */
    suspend fun bulkSet(action: BulkAction, previous: Map<String, Boolean>): Result<Unit> {
        val ids = previous.keys.toList()
        if (ids.isEmpty()) return Result.success(Unit)
        // emit, not tryEmit: tryEmit silently drops updates once the buffer (256) is full, so
        // marking a long selection read left part of it looking unread.
        ids.forEach { _entryUpdates.emit(action.update(it, action.value)) }
        val result = apiCall { getApi().bulkAction(BulkActionRequest(ids, action.serverAction)).requireSuccess() }
        if (result.isSuccess) ids.forEach { _entryUpdates.emit(action.update(it, action.value).copy(confirmed = true)) }
        else previous.forEach { (id, old) -> _entryUpdates.emit(action.update(id, old)) }
        return result
    }

    private suspend fun changeFlags(
        ids: List<String>,
        optimistic: EntryFlagUpdate,
        revert: EntryFlagUpdate,
        request: suspend () -> Unit
    ): Result<Unit> {
        _entryUpdates.emit(optimistic)
        val result = apiCall { request() }
        if (result.isSuccess) _entryUpdates.emit(optimistic.copy(confirmed = true))
        else if (ids.isNotEmpty()) _entryUpdates.emit(revert)
        return result
    }

    /**
     * Marks unread entries read, limited to [feedId] / [categoryId] when given; with neither, every
     * feed. [priorityOnly] limits it to the Priority Queue's articles (`radar_only`, as the web's
     * Priority Queue sends), so clearing the queue doesn't mark every other unread article read.
     */
    suspend fun markAllRead(feedId: String? = null, categoryId: String? = null, priorityOnly: Boolean = false): Result<Unit> = apiCall {
        val request = if (priorityOnly) MarkAllReadRequest(radarOnly = true) else MarkAllReadRequest(feedId = feedId, categoryId = categoryId)
        getApi().markAllRead(request).requireSuccess()
    }

    /** Marks every unread article published on the local day [dayKey] read, in the feed/folder if given (the web's day button). */
    suspend fun markDayRead(dayKey: String, feedId: String? = null, categoryId: String? = null): Result<Unit> = apiCall {
        val (since, before) = DateUtils.dayBounds(dayKey) ?: error("Bad day key $dayKey")
        getApi().markAllRead(MarkAllReadRequest(feedId = feedId, categoryId = categoryId, since = since, before = before)).requireSuccess()
    }

    // READER

    suspend fun getEntryDetail(id: String): Result<EntryDetail> = apiCall { getApi().getEntryDetail(id) }

    /**
     * Loads the entities linked to an entry from the per-type endpoints in parallel, the same ones
     * the web reader uses. A type that fails is left empty rather than failing the whole panel.
     */
    suspend fun getEntryIntel(id: String): EntryIntel = coroutineScope {
        val api = getApi()
        val actors = async { apiCall { api.getEntryThreatActors(id) }.getOrDefault(emptyList()) }
        val malware = async { apiCall { api.getEntryMalware(id) }.getOrDefault(emptyList()) }
        val cves = async { apiCall { api.getEntryCves(id) }.getOrDefault(emptyList()) }
        val ttps = async { apiCall { api.getEntryTtps(id) }.getOrDefault(emptyList()) }
        val countries = async { apiCall { api.getEntryCountries(id) }.getOrDefault(emptyList()) }
        val tools = async { apiCall { api.getEntryTools(id) }.getOrDefault(emptyList()) }
        val vendors = async { apiCall { api.getEntryVendors(id) }.getOrDefault(emptyList()) }
        val products = async { apiCall { api.getEntryProducts(id) }.getOrDefault(emptyList()) }
        val cwes = async { apiCall { decodeItems(api.getEntryCwes(id), Cwe.serializer()) }.getOrDefault(emptyList()) }
        val mitigations = async { apiCall { decodeItems(api.getEntryMitigations(id), Mitigation.serializer()) }.getOrDefault(emptyList()) }
        val observables = async { apiCall { decodeItems(api.getEntryObservables(id), ObservableItem.serializer()) }.getOrDefault(emptyList()) }
        EntryIntel(
            threatActors = actors.await(),
            malware = malware.await(),
            cves = cves.await(),
            ttps = ttps.await(),
            countries = countries.await(),
            tools = tools.await(),
            vendors = vendors.await(),
            products = products.await(),
            cwes = cwes.await(),
            mitigations = mitigations.await(),
            observables = observables.await()
        )
    }

    /** Glossary terms found in the article, as the web reader gets them. */
    suspend fun detectGlossary(entryId: String): Result<List<com.example.intelfeed.data.model.GlossaryMatch>> = apiCall {
        decodeItems(getApi().detectGlossary(com.example.intelfeed.data.model.GlossaryDetectRequest(entryId)), com.example.intelfeed.data.model.GlossaryMatch.serializer())
    }

    /**
     * Decodes a list response item by item, skipping items that don't fit [serializer]. Accepts a
     * bare array or an object holding one under "items" (or "matches"/"results").
     */
    private fun <T> decodeItems(element: kotlinx.serialization.json.JsonElement, serializer: kotlinx.serialization.KSerializer<T>): List<T> {
        val array = when (element) {
            is kotlinx.serialization.json.JsonArray -> element
            is JsonObject -> listOf("items", "matches", "results").firstNotNullOfOrNull { element[it] as? kotlinx.serialization.json.JsonArray }
            else -> null
        } ?: return emptyList()
        return array.mapNotNull { item -> runCatching { apiClient.json.decodeFromJsonElement(serializer, item) }.getOrNull() }
    }

    suspend fun getSimilarEntries(id: String): Result<List<SimilarEntry>> = apiCall {
        getApi().getSimilarEntries(id).items
    }

    /** Creates (or returns) the entry's public share link, as an absolute URL on the server. */
    suspend fun createShareLink(id: String): Result<String> = apiCall {
        val link = getApi().createShareLink(id)
        val path = link.url ?: link.token?.let { "/shared/$it" } ?: error("The server didn't return a link")
        if (path.startsWith("http")) path else currentServerUrl().trimEnd('/') + "/" + path.trimStart('/')
    }

    suspend fun sendRadarFeedback(entryId: String, verdict: Int): Result<Unit> = apiCall {
        getApi().sendRadarFeedback(RadarFeedbackRequest(entryId, verdict)).requireSuccess()
    }

    suspend fun ingestUrl(url: String): Result<IngestUrlResponse> = apiCall {
        getApi().ingestUrl(IngestUrlRequest(url))
    }

    /** The saved AI briefing for [dayKey] (local YYYY-MM-DD) in [scope], or null when there is none. Never generates one. */
    suspend fun getDailySummary(dayKey: String, scope: DayScope = DayScope()): Result<DailySummary?> = apiCall {
        val element = getApi().getDailySummary(
            dayKey, scope.feedId, scope.categoryId,
            isStarred = scope.starred.takeIf { it }, isBookmarked = scope.bookmarked.takeIf { it }
        )
        if (element is JsonNull) null else apiClient.json.decodeFromJsonElement(DailySummary.serializer(), element)
    }

    /** The day divider's topic chips for [dayKey] (local YYYY-MM-DD) in [scope]. Null on a day with no data. */
    suspend fun getDayIntel(dayKey: String, scope: DayScope = DayScope()): Result<DayIntel?> = apiCall {
        val (since, before) = DateUtils.dayBounds(dayKey) ?: error("Bad day key $dayKey")
        val element = getApi().getDayIntel(
            since, before, scope.feedId, scope.categoryId,
            isStarred = scope.starred.takeIf { it }, isBookmarked = scope.bookmarked.takeIf { it }
        )
        if (element !is JsonObject) null else apiClient.json.decodeFromJsonElement(DayIntel.serializer(), element)
    }

    // NOTES ON ARTICLES

    suspend fun getNotes(entryId: String): Result<List<EntryNote>> = apiCall {
        getApi().getEntryNotes(entryId).sortedWith(compareByDescending<EntryNote> { it.isPinned }.thenByDescending { it.updatedAt ?: it.createdAt })
    }

    suspend fun createNote(entryId: String, title: String, body: String, pinned: Boolean = false): Result<EntryNote> = apiCall {
        getApi().createEntryNote(entryId, NoteRequest(title = title, contentMarkdown = body, isPinned = pinned))
    }

    suspend fun updateNote(id: String, title: String, body: String, pinned: Boolean): Result<EntryNote> = apiCall {
        getApi().updateNote(id, NoteRequest(title = title, contentMarkdown = body, isPinned = pinned))
    }

    suspend fun deleteNote(id: String): Result<Unit> = apiCall { getApi().deleteNote(id).requireSuccess() }

    // TAGS

    suspend fun getTags(): Result<List<TagEntity>> = apiCall { getApi().getTags().sortedBy { it.name.lowercase() } }

    suspend fun getEntryTags(entryId: String): Result<List<TagEntity>> = apiCall { getApi().getEntryTags(entryId) }

    suspend fun createTag(name: String): Result<TagEntity> = apiCall { getApi().createTag(CreateTagRequest(name = name)) }

    suspend fun addEntryTag(entryId: String, tagId: String): Result<Unit> = apiCall {
        getApi().addEntryTags(entryId, TagIdsRequest(listOf(tagId))).requireSuccess()
    }

    suspend fun removeEntryTag(entryId: String, tagId: String): Result<Unit> = apiCall {
        getApi().removeEntryTag(entryId, tagId).requireSuccess()
    }

    suspend fun deleteTag(tagId: String): Result<Unit> = apiCall {
        getApi().deleteTag(tagId).requireSuccess()
    }

    // STORY THREADS

    suspend fun getThread(slug: String): Result<ThreadDetail> = apiCall { getApi().getThread(slug) }

    suspend fun markThreadOpened(threadId: String): Result<Unit> = apiCall {
        getApi().markThreadOpened(threadId).requireSuccess()
    }

    // WORKBENCH LISTS (offset-paged)

    suspend fun getThreatActors(search: String? = null, offset: Int = 0, limit: Int = PAGE): Result<OffsetPage<ThreatActor>> =
        apiCall { getApi().getThreatActors(search = search, offset = offset, limit = limit).toOffsetPage(offset) }

    suspend fun getMalware(search: String? = null, offset: Int = 0, limit: Int = PAGE): Result<OffsetPage<Malware>> =
        apiCall { getApi().getMalware(search = search, offset = offset, limit = limit).toOffsetPage(offset) }

    suspend fun getCves(search: String? = null, offset: Int = 0, limit: Int = PAGE): Result<OffsetPage<Cve>> =
        apiCall { getApi().getCves(search = search, offset = offset, limit = limit).toOffsetPage(offset) }

    suspend fun getTtps(search: String? = null, offset: Int = 0, limit: Int = PAGE): Result<OffsetPage<Ttp>> =
        apiCall { getApi().getTtps(search = search, offset = offset, limit = limit).toOffsetPage(offset) }

    suspend fun getCampaigns(search: String? = null, offset: Int = 0, limit: Int = PAGE): Result<OffsetPage<Campaign>> =
        apiCall { getApi().getCampaigns(search = search, offset = offset, limit = limit).toOffsetPage(offset) }

    suspend fun createCampaign(name: String, description: String? = null): Result<Campaign> =
        apiCall { getApi().createCampaign(CreateCampaignRequest(name = name.trim(), description = description?.trim())) }

    suspend fun attachEntryToCampaign(campaignId: String, entryId: String): Result<Unit> =
        apiCall { getApi().attachEntryToCampaign(campaignId, AttachEntryRequest(entryId)).requireSuccess() }

    /** One request for any number of articles (one article uses the single-entry route, like the web reader). */
    suspend fun attachEntriesToCampaign(campaignId: String, entryIds: List<String>): Result<Unit> = when (entryIds.size) {
        0 -> Result.success(Unit)
        1 -> attachEntryToCampaign(campaignId, entryIds.first())
        else -> apiCall {
            getApi().attachEntriesToCampaign(campaignId, com.example.intelfeed.data.model.EntryIdsRequest(entryIds.distinct())).requireSuccess()
        }
    }

    suspend fun detachEntryFromCampaign(campaignId: String, entryId: String): Result<Unit> =
        apiCall { getApi().detachEntryFromCampaign(campaignId, entryId).requireSuccess() }

    suspend fun getCampaignsByEntry(entryId: String): Result<List<String>> =
        apiCall { getApi().getCampaignsByEntry(entryId) }

    suspend fun getCampaignEntries(
        campaignId: String,
        isRead: Boolean? = null,
        limit: Int = 30,
        cursor: String? = null
    ): Result<CursorPage<EntryItem>> = apiCall {
        getApi().getEntries(
            campaignId = campaignId,
            isRead = isRead,
            limit = limit,
            cursor = cursor
        )
    }

    suspend fun getDetectionRules(search: String? = null, offset: Int = 0, limit: Int = PAGE): Result<OffsetPage<DetectionRule>> =
        apiCall { getApi().getDetectionRules(search = search, offset = offset, limit = limit).toOffsetPage(offset) }

    suspend fun getVendors(search: String? = null, offset: Int = 0, limit: Int = PAGE): Result<OffsetPage<Vendor>> =
        apiCall { getApi().getVendors(search = search, offset = offset, limit = limit).toOffsetPage(offset) }

    suspend fun getProducts(search: String? = null, offset: Int = 0, limit: Int = PAGE): Result<OffsetPage<Product>> =
        apiCall { getApi().getProducts(search = search, offset = offset, limit = limit).toOffsetPage(offset) }

    suspend fun getTools(search: String? = null, offset: Int = 0, limit: Int = PAGE): Result<OffsetPage<Tool>> =
        apiCall { getApi().getTools(search = search, offset = offset, limit = limit).toOffsetPage(offset) }

    suspend fun getCountries(search: String? = null, offset: Int = 0, limit: Int = PAGE): Result<OffsetPage<Country>> =
        apiCall { getApi().getCountries(search = search, offset = offset, limit = limit).toOffsetPage(offset) }

    suspend fun getMitigations(search: String? = null, offset: Int = 0, limit: Int = PAGE): Result<OffsetPage<Mitigation>> =
        apiCall { getApi().getMitigations(search = search, offset = offset, limit = limit).toOffsetPage(offset) }

    suspend fun getCwes(search: String? = null, offset: Int = 0, limit: Int = PAGE): Result<OffsetPage<Cwe>> =
        apiCall { getApi().getCwes(search = search, offset = offset, limit = limit).toOffsetPage(offset) }

    suspend fun getObservables(search: String? = null, offset: Int = 0, limit: Int = PAGE, kind: String? = null): Result<OffsetPage<ObservableItem>> =
        apiCall { getApi().getObservables(search = search, kind = kind, offset = offset, limit = limit).toOffsetPage(offset) }

    // ENTITY DETAIL

    suspend fun getThreatActor(id: String): Result<ThreatActor> = apiCall { getApi().getThreatActor(id) }
    suspend fun getMalwareDetail(id: String): Result<Malware> = apiCall { getApi().getMalwareDetail(id) }
    /** [cveId] is the identifier (CVE-2024-1234), which is what the detail route takes. */
    suspend fun getCveDetail(cveId: String): Result<Cve> = apiCall { getApi().getCveDetail(cveId) }
    suspend fun getCweDetail(cweId: String): Result<Cwe> = apiCall { getApi().getCweDetail(cweId) }
    suspend fun getObservable(id: String): Result<ObservableItem> = apiCall { getApi().getObservable(id) }
    suspend fun getTtpByTechnique(techniqueId: String): Result<Ttp> = apiCall { getApi().getTtpByTechnique(techniqueId) }
    suspend fun getCampaign(id: String): Result<Campaign> = apiCall { getApi().getCampaign(id) }
    suspend fun getDetectionRule(id: String): Result<DetectionRule> = apiCall { getApi().getDetectionRule(id) }
    suspend fun getVendor(id: String): Result<Vendor> = apiCall { getApi().getVendor(id) }
    suspend fun getProduct(id: String): Result<Product> = apiCall { getApi().getProduct(id) }
    suspend fun getTool(id: String): Result<Tool> = apiCall { getApi().getTool(id) }
    suspend fun getCountry(id: String): Result<Country> = apiCall { getApi().getCountry(id) }
    suspend fun getMitigation(id: String): Result<Mitigation> = apiCall { getApi().getMitigation(id) }

    suspend fun getRelationships(entityType: String, entityId: String, offset: Int = 0): Result<OffsetPage<EntityRelationship>> =
        apiCall { getApi().getRelationships(entityType, entityId, limit = 50, offset = offset).toOffsetPage(offset) }

    suspend fun getEntityNotes(entityType: String, entityId: String): Result<List<EntityNote>> =
        apiCall { getApi().getEntityNotes(entityType, entityId).items }

    suspend fun createEntityNote(entityType: String, entityId: String, title: String?, content: String): Result<EntityNote> =
        apiCall { getApi().createEntityNote(CreateEntityNoteRequest(entityType, entityId, title, content)) }

    suspend fun updateEntityNote(id: String, title: String?, content: String): Result<EntityNote> =
        apiCall { getApi().updateEntityNote(id, UpdateEntityNoteRequest(title, content)) }

    suspend fun deleteEntityNote(id: String): Result<Unit> = apiCall { getApi().deleteEntityNote(id).requireSuccess() }

    // WATCHLIST (per user)

    suspend fun getWatchlist(): Result<List<WatchlistItem>> = apiCall { getApi().getWatchlist() }

    /** [mode] is "watch", "mute", or null to remove the entity from both lists. */
    suspend fun setWatchMode(entityType: String, entityId: String, mode: String?): Result<Unit> = apiCall {
        if (mode == null) getApi().removeWatchlistEntry(entityType, entityId).requireSuccess()
        else getApi().setWatchlistEntry(WatchlistRequest(entityType, entityId, mode)).requireSuccess()
    }

    // SEARCH

    /**
     * Only the first page carries entity groups: later pages ("Load more") keep the entities from
     * page one, so they ask for the minimum instead of re-downloading up to 200 entities each time.
     */
    suspend fun searchUnified(query: String, offset: Int = 0, limit: Int = 20): Result<UnifiedSearchResponse> = apiCall {
        getApi().searchUnified(
            if (offset == 0) UnifiedSearchRequest(q = query, limit = limit, offset = offset)
            else UnifiedSearchRequest(q = query, limit = limit, offset = offset, entityLimit = 1, entityGroupLimit = 1)
        )
    }

    /** Articles for an entity profile: unified search with the type's field filter. Entities are skipped. */
    suspend fun searchEntries(query: String, offset: Int = 0, limit: Int = 20): Result<OffsetPage<EntryItem>> = apiCall {
        val res = getApi().searchUnified(
            UnifiedSearchRequest(q = query, limit = limit, offset = offset, entityLimit = 1, entityGroupLimit = 1)
        )
        val hits = res.entries.hits
        val total = res.entries.estimatedTotalHits
        OffsetPage(hits, total, hits.isNotEmpty() && offset + hits.size < total, offset + hits.size)
    }

    suspend fun autocomplete(query: String): Result<List<SearchSuggestion>> = apiCall { getApi().autocomplete(query) }

    suspend fun getSavedSearches(): Result<List<SavedSearch>> = apiCall { getApi().getSavedSearches() }

    suspend fun createSavedSearch(name: String, query: String): Result<SavedSearch> = apiCall {
        getApi().createSavedSearch(CreateSavedSearchRequest(name = name, query = query))
    }

    suspend fun deleteSavedSearch(id: String): Result<Unit> = apiCall { getApi().deleteSavedSearch(id).requireSuccess() }

    companion object {
        const val PAGE = 30
        private const val HOUR_MS = 60 * 60 * 1000L

        private fun isoTimestamp(millis: Long): String =
            SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US)
                .apply { timeZone = TimeZone.getTimeZone("UTC") }
                .format(Date(millis))
    }
}

/** Reads either discover response shape: one feed object, or {"feeds": [...]}. Entries without a URL are dropped. */
internal fun parseDiscoveredFeeds(element: JsonElement, json: Json): List<DiscoveredFeed> {
    val obj = element as? JsonObject ?: return emptyList()
    val list = (obj["feeds"] as? JsonArray)
        ?.mapNotNull { runCatching { json.decodeFromJsonElement(DiscoveredFeed.serializer(), it) }.getOrNull() }
        ?: listOfNotNull(runCatching { json.decodeFromJsonElement(DiscoveredFeed.serializer(), obj) }.getOrNull())
    return list.filter { it.url.isNotBlank() }.distinctBy { it.url }
}

/** Bulk actions from the feed's selection mode. [value] is the flag each selected entry ends up with. */
enum class BulkAction(val serverAction: String, val value: Boolean) {
    READ("read", true),
    UNREAD("unread", false),
    STAR("star", true),
    UNSTAR("unstar", false),
    BOOKMARK("bookmark", true),
    UNBOOKMARK("unbookmark", false);

    val opposite: BulkAction
        get() = when (this) {
            READ -> UNREAD
            UNREAD -> READ
            STAR -> UNSTAR
            UNSTAR -> STAR
            BOOKMARK -> UNBOOKMARK
            UNBOOKMARK -> BOOKMARK
        }

    fun update(id: String, flag: Boolean): EntryFlagUpdate = when (this) {
        READ, UNREAD -> EntryFlagUpdate(id, isRead = flag)
        STAR, UNSTAR -> EntryFlagUpdate(id, isStarred = flag)
        BOOKMARK, UNBOOKMARK -> EntryFlagUpdate(id, isBookmarked = flag)
    }
}
