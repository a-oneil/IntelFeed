package com.example.intelfeed.ui

import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.snapshots.SnapshotStateList
import androidx.compose.runtime.snapshotFlow
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.intelfeed.data.local.UserPreferences
import com.example.intelfeed.data.model.Category
import com.example.intelfeed.data.model.DayIntel
import com.example.intelfeed.data.model.DiscoveredFeed
import com.example.intelfeed.data.model.EntityType
import com.example.intelfeed.data.model.EntryItem
import com.example.intelfeed.data.model.EntryIntelCounts
import com.example.intelfeed.data.model.FeedSource
import com.example.intelfeed.data.model.SavedSearch
import com.example.intelfeed.data.model.SearchSuggestion
import com.example.intelfeed.data.model.ThemeDto
import com.example.intelfeed.data.model.UnifiedSearchResponse
import com.example.intelfeed.data.model.UserProfile
import com.example.intelfeed.data.model.WatchlistItem
import com.example.intelfeed.data.network.ServerUrl
import com.example.intelfeed.data.repository.BulkAction
import com.example.intelfeed.data.repository.DayScope
import com.example.intelfeed.data.repository.EntryFlagUpdate
import com.example.intelfeed.data.repository.FeedFilter
import com.example.intelfeed.data.repository.IntelFeedRepository
import com.example.intelfeed.data.repository.OffsetPage
import com.example.intelfeed.data.repository.ViewCounts
import com.example.intelfeed.theme.ThemeEngine
import com.example.intelfeed.ui.entity.Badge
import com.example.intelfeed.ui.entity.EntityRef
import com.example.intelfeed.ui.entity.Tone
import com.example.intelfeed.ui.entity.WorkbenchItem
import com.example.intelfeed.ui.entity.toWorkbenchItem
import com.example.intelfeed.ui.navigation.Route
import com.example.intelfeed.ui.navigation.RouteCodec

import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import retrofit2.HttpException

enum class AppTab { FEED, WORKBENCH, SEARCH }

/** Workbench lists. [type] is null for the Watchlist, which mixes types. */
enum class WorkbenchTab(val label: String, val type: EntityType?) {
    ACTORS("Threat actors", EntityType.THREAT_ACTOR),
    MALWARE("Malware", EntityType.MALWARE),
    CVES("Vulnerabilities", EntityType.CVE),
    TTPS("Techniques", EntityType.TTP),
    // A view, not a list (the web Workbench's ATT&CK Matrix).
    ATTACK_MATRIX("ATT&CK matrix", null),
    // The web Workbench's ransomware tracker (leak-site victims).
    RANSOMWARE("Ransomware", null),
    WEAKNESSES("Weaknesses", EntityType.WEAKNESS),
    OBSERVABLES("Observables", EntityType.OBSERVABLE),
    TOOLS("Tools", EntityType.TOOL),
    VENDORS("Vendors", EntityType.VENDOR),
    PRODUCTS("Products", EntityType.PRODUCT),
    COUNTRIES("Countries", EntityType.COUNTRY),
    RULES("Detection rules", EntityType.RULE),
    CAMPAIGNS("Campaigns", EntityType.CAMPAIGN),
    MITIGATIONS("Mitigations", EntityType.MITIGATION),
    WATCHLIST("Watchlist", null);

    /** Tabs that show their own view instead of a searchable list. */
    val isView: Boolean get() = this == ATTACK_MATRIX || this == RANSOMWARE
}

enum class SearchScope(val label: String) { EVERYTHING("Everything"), ARTICLES("Articles"), ENTITIES("Entities") }

data class IntelFeedUiState(
    // Session
    val isLoggedIn: Boolean = false,
    // False until the stored session has been read, so the login screen doesn't flash at startup.
    val sessionChecked: Boolean = false,
    val serverUrl: String = "",
    val username: String? = null,
    val currentUser: UserProfile? = null,
    val loginLoading: Boolean = false,
    val loginError: String? = null,

    val currentTab: AppTab = AppTab.FEED,

    // Feed
    val selectedFilter: FeedFilter = FeedFilter.PRIORITY_QUEUE,
    val entries: List<EntryItem> = emptyList(),
    val feedLoading: Boolean = false,
    val isRefreshing: Boolean = false,
    val nextCursor: String? = null,
    val hasMore: Boolean = false,
    val feedError: String? = null,
    // Bumped whenever the list is replaced by a different scope, so the screen scrolls to the top.
    val feedScrollToTop: Int = 0,
    val feedDensity: String = "expanded",
    val feedLayout: String = "list",
    // The web toolbar's "Hide Read" and sort, for date-ordered views (saved on the device).
    val feedHideRead: Boolean = false,
    val feedSort: String = "newest",
    // "Auto-read": articles scrolled past in the list are marked read (off by default).
    val feedAutoRead: Boolean = false,
    // Day dividers, keyed by local day "yyyy-MM-dd". A key present with a null value means
    // "checked, nothing there". Cleared when the list's scope changes or on pull-to-refresh.
    val dailySummaries: Map<String, com.example.intelfeed.data.model.DailySummary?> = emptyMap(),
    val dailySummaryLoading: Set<String> = emptySet(),
    val dailySummaryErrors: Set<String> = emptySet(),
    val dayIntel: Map<String, DayIntel?> = emptyMap(),
    // A day chip's filter on the list (the web's day focus); cleared when the feed, folder or view changes.
    val dayFocus: com.example.intelfeed.data.model.DayFocus? = null,
    // Multi-select (long-press an article). Empty = not selecting.
    val selectedIds: Set<String> = emptySet(),
    // Unread counts for the quick views (drawer badges, toolbar subtitle).
    val viewCounts: ViewCounts = ViewCounts(),
    // Per-article intel cues for list cards (PIR, actors, CVEs, techniques, detection gap), by entry id.
    val intelCounts: Map<String, EntryIntelCounts> = emptyMap(),
    // The article the reader last showed when it was walking the feed list: the list scrolls to it
    // on the way back if it's off screen (you may have swiped far from where you started).
    val feedFocusEntryId: String? = null,

    // Drawer
    val categories: List<Category> = emptyList(),
    val feeds: List<FeedSource> = emptyList(),
    val drawerLoading: Boolean = false,
    val drawerError: String? = null,
    val selectedCategoryId: String? = null,
    val selectedCategoryName: String? = null,
    val selectedFeedId: String? = null,
    val selectedFeedTitle: String? = null,

    // Workbench
    val selectedWorkbenchTab: WorkbenchTab = WorkbenchTab.ACTORS,
    val workbenchSearchQuery: String = "",
    val workbenchItems: List<WorkbenchItem> = emptyList(),
    val workbenchTotal: Int? = null,
    val workbenchHasMore: Boolean = false,
    val workbenchNextOffset: Int = 0,
    val workbenchLoading: Boolean = false,
    val workbenchLoadingMore: Boolean = false,
    val workbenchError: String? = null,

    // Search
    val searchQuery: String = "",
    val submittedQuery: String? = null,
    val searchScope: SearchScope = SearchScope.EVERYTHING,
    val searchLoading: Boolean = false,
    val searchError: String? = null,
    val searchResponse: UnifiedSearchResponse? = null,
    // Articles for the submitted query, grown by "load more".
    val searchEntries: List<EntryItem> = emptyList(),
    val searchEntriesTotal: Int = 0,
    val searchLoadingMore: Boolean = false,
    val searchSuggestions: List<SearchSuggestion> = emptyList(),
    val recentSearches: List<String> = emptyList(),
    // Tracked keywords (kept on this device): highlighted in articles and checked by the alerts.
    val trackedKeywords: List<String> = emptyList(),
    val savedSearches: List<SavedSearch> = emptyList(),

    // Themes & Color Schema
    val availableThemes: List<ThemeDto> = emptyList(),
    val activeThemeId: String? = null,
    val activeThemeName: String = "GitHub Dark",
    val activeThemeSource: String = "default"
) {
    val isSelecting: Boolean get() = selectedIds.isNotEmpty()
    val searchHasMore: Boolean get() = searchEntries.size < searchEntriesTotal
    val isAdmin: Boolean get() = currentUser?.role.equals("admin", ignoreCase = true)
}

class IntelFeedViewModel(
    val repository: IntelFeedRepository,
    val userPreferences: UserPreferences,
    val messenger: UiMessenger,
    // Keeps the back stack and the feed's view across Android stopping the process in the background.
    private val savedState: SavedStateHandle
) : ViewModel() {

    private val _uiState = MutableStateFlow(IntelFeedUiState())
    val uiState: StateFlow<IntelFeedUiState> = _uiState.asStateFlow()

    /** The navigation back stack, rendered by NavDisplay. Never empty: Home is always at the bottom. */
    val backStack: SnapshotStateList<Route> = mutableStateListOf(Route.Home)

    // One in-flight job per area. Starting a new load cancels the stale one, so a slow response
    // can't overwrite a newer one (e.g. the previous filter's page arriving last).
    private var feedJob: Job? = null
    private var drawerJob: Job? = null
    private var workbenchJob: Job? = null
    // Separate from workbenchJob: overwriting that reference left a debounced search running
    // uncancelled, so an older query's results could replace the newer one's.
    private var workbenchMoreJob: Job? = null
    // The tab and search the Workbench list on screen was loaded for.
    private var workbenchItemsKey: Pair<WorkbenchTab, String?>? = null
    private var searchJob: Job? = null
    private var suggestJob: Job? = null
    private var themeJob: Job? = null

    private var userInitiatedLogout = false

    private var countsJob: Job? = null
    private var countsLoadedAt = 0L
    // Entry ids whose intel cues were already requested this session.
    private val intelCountsRequested = mutableSetOf<String>()
    // Optimistic read updates stay in the list until the server confirms them. If the reader is
    // closed before confirmation, this set also keeps the card available for a failure rollback.
    private val pendingReadIds = mutableSetOf<String>()

    // Day dividers: bumped whenever the list's scope changes, so late responses are dropped.
    private var dayDataGeneration = 0
    private val dayIntelRequested = mutableSetOf<String>()

    init {
        // Before anything loads, so the first feed request uses the restored view.
        restoreSavedState()
        viewModelScope.launch {
            val cached = userPreferences.getCachedThemeState()
            ThemeEngine.restoreFromCache(cached)
            _uiState.update {
                it.copy(
                    activeThemeId = ThemeEngine.activeThemeId,
                    activeThemeName = ThemeEngine.activeThemeName,
                    activeThemeSource = ThemeEngine.activeThemeSource
                )
            }
        }
        viewModelScope.launch {
            snapshotFlow { backStack.toList() }.collect { routes -> RouteCodec.encode(routes)?.let { savedState[KEY_BACK_STACK] = it } }
        }
        viewModelScope.launch {
            _uiState.map { SavedView(it.currentTab, it.selectedFilter, it.selectedFeedId, it.selectedFeedTitle, it.selectedCategoryId, it.selectedCategoryName) }
                .distinctUntilChanged()
                .collect { v ->
                    savedState[KEY_TAB] = v.tab.name
                    savedState[KEY_FILTER] = v.filter.name
                    savedState[KEY_FEED_ID] = v.feedId
                    savedState[KEY_FEED_TITLE] = v.feedTitle
                    savedState[KEY_CATEGORY_ID] = v.categoryId
                    savedState[KEY_CATEGORY_NAME] = v.categoryName
                }
        }
        viewModelScope.launch {
            repository.serverUrl.collect { url -> _uiState.update { it.copy(serverUrl = url) } }
        }
        viewModelScope.launch {
            repository.username.collect { user -> _uiState.update { it.copy(username = user) } }
        }
        viewModelScope.launch {
            repository.currentUser.collect { user -> _uiState.update { it.copy(currentUser = user) } }
        }
        viewModelScope.launch {
            userPreferences.recentSearches.collect { recent -> _uiState.update { it.copy(recentSearches = recent) } }
        }
        viewModelScope.launch {
            userPreferences.trackedKeywords.collect { list -> _uiState.update { it.copy(trackedKeywords = list) } }
        }
        viewModelScope.launch {
            userPreferences.feedDensity.collect { density -> _uiState.update { it.copy(feedDensity = density) } }
        }
        viewModelScope.launch {
            userPreferences.feedLayout.collect { layout -> _uiState.update { it.copy(feedLayout = layout) } }
        }
        viewModelScope.launch {
            combine(userPreferences.feedHideRead, userPreferences.feedSort) { hide, sort -> hide to sort }.collect { (hide, sort) ->
                val before = _uiState.value
                _uiState.update { it.copy(feedHideRead = hide, feedSort = sort) }
                // A changed option reloads the list (not at startup, where the first load follows sign-in).
                if (before.isLoggedIn && (before.feedHideRead != hide || before.feedSort != sort)) {
                    // The web keeps a day filter when only the sort changes.
                    loadFeed(isRefresh = true, scopeChanged = true, keepDayFocus = true)
                }
            }
        }
        viewModelScope.launch {
            userPreferences.feedAutoRead.collect { on -> _uiState.update { it.copy(feedAutoRead = on) } }
        }
        viewModelScope.launch {
            repository.entryUpdates.collect(::applyEntryUpdate)
        }
        viewModelScope.launch {
            // isLoggedIn only emits on change, so token refreshes don't reload everything.
            repository.isLoggedIn.collect { loggedIn ->
                if (loggedIn) {
                    _uiState.update { it.copy(isLoggedIn = true, sessionChecked = true) }
                    loadFeed(isRefresh = true)
                    loadCategoriesAndFeeds()
                    // Also loads the saved searches (a separate call here sent the request twice).
                    loadViewCounts(force = true)
                    loadWorkbench()
                    syncThemesForSignedInUser()
                } else {
                    resetSession()
                    syncThemeForSignedOut()
                }
            }
        }
    }

    /**
     * Synchronizes the server's color schema (`/api/themes/schema`) and theme list (`/api/themes`)
     * with the signed-in user's preference (`user.themeId`) or the instance default (`isDefault`).
     */
    fun refreshThemes() {
        if (_uiState.value.isLoggedIn) {
            syncThemesForSignedInUser()
        } else {
            syncThemeForSignedOut()
        }
    }

    private fun syncThemesForSignedInUser() {
        themeJob?.cancel()
        themeJob = viewModelScope.launch {
            val cached = userPreferences.getCachedThemeState()
            val schemaDeferred = async { repository.getColorSchema() }
            val userDeferred = async { repository.loadCurrentUser() }
            val themesDeferred = async { repository.getThemes() }

            schemaDeferred.await().getOrNull()?.let { schema ->
                ThemeEngine.applyColorSchema(schema)
                userPreferences.saveCachedColorSchema(schema)
            }

            val user = userDeferred.await().getOrNull()
            val themes = themesDeferred.await().getOrNull().orEmpty()
            if (themes.isNotEmpty()) {
                val resolved = ThemeEngine.resolveSignedInTheme(themes, user, cached)
                if (resolved != null) {
                    ThemeEngine.applyThemeDto(resolved.theme, resolved.source)
                    userPreferences.saveCachedTheme(
                        themeId = resolved.theme.id,
                        themeName = resolved.theme.name,
                        variables = resolved.theme.variables,
                        source = resolved.source
                    )
                }
                _uiState.update {
                    it.copy(
                        availableThemes = themes,
                        activeThemeId = ThemeEngine.activeThemeId,
                        activeThemeName = ThemeEngine.activeThemeName,
                        activeThemeSource = ThemeEngine.activeThemeSource
                    )
                }
            }
        }
    }

    private fun syncThemeForSignedOut() {
        themeJob?.cancel()
        themeJob = viewModelScope.launch {
            val cached = userPreferences.getCachedThemeState()
            val schemaDeferred = async { repository.getColorSchema() }
            val defaultDeferred = async { repository.getDefaultTheme() }

            schemaDeferred.await().getOrNull()?.let { schema ->
                ThemeEngine.applyColorSchema(schema)
                userPreferences.saveCachedColorSchema(schema)
            }

            val publicDefault = defaultDeferred.await().getOrNull()
            if (publicDefault != null && ThemeEngine.shouldApplyPublicDefaultWhenSignedOut(publicDefault, cached)) {
                ThemeEngine.applyThemeDto(publicDefault, "default")
                userPreferences.saveCachedTheme(
                    themeId = publicDefault.id,
                    themeName = publicDefault.name,
                    variables = publicDefault.variables,
                    source = "default"
                )
                _uiState.update {
                    it.copy(
                        activeThemeId = ThemeEngine.activeThemeId,
                        activeThemeName = ThemeEngine.activeThemeName,
                        activeThemeSource = ThemeEngine.activeThemeSource
                    )
                }
            }
        }
    }

    /** Selects a theme in the mobile app and persists it to the user's server profile (`PUT /api/auth/me/theme`). */
    fun selectTheme(theme: ThemeDto) {
        ThemeEngine.applyThemeDto(theme, "user")
        _uiState.update {
            it.copy(
                activeThemeId = theme.id,
                activeThemeName = theme.name,
                activeThemeSource = "user"
            )
        }
        viewModelScope.launch {
            userPreferences.saveCachedTheme(
                themeId = theme.id,
                themeName = theme.name,
                variables = theme.variables,
                source = "user"
            )
            if (_uiState.value.isLoggedIn) {
                repository.updateThemePreference(theme.id).onFailure { e ->
                    messenger.show("Saved theme on device, but couldn't sync to server: ${ErrorText.describe(e)}")
                }
            }
        }
    }

    /** Clears the user's personal theme override and follows the server's instance default theme. */
    fun useDefaultTheme() {
        val themes = _uiState.value.availableThemes
        val defaultTheme = themes.find { it.isDefault } ?: themes.find { it.name == "GitHub Dark" } ?: themes.firstOrNull()
        if (defaultTheme != null) {
            ThemeEngine.applyThemeDto(defaultTheme, "default")
        } else {
            ThemeEngine.resetToDefault()
        }
        _uiState.update {
            it.copy(
                activeThemeId = ThemeEngine.activeThemeId,
                activeThemeName = ThemeEngine.activeThemeName,
                activeThemeSource = "default"
            )
        }
        viewModelScope.launch {
            if (defaultTheme != null) {
                userPreferences.saveCachedTheme(
                    themeId = defaultTheme.id,
                    themeName = defaultTheme.name,
                    variables = defaultTheme.variables,
                    source = "default"
                )
            } else {
                userPreferences.clearCachedTheme()
            }
            if (_uiState.value.isLoggedIn) {
                repository.updateThemePreference(null).onFailure { e ->
                    messenger.show("Couldn't reset theme preference on server: ${ErrorText.describe(e)}")
                }
            }
        }
    }

    /**
     * Brings back what the saved state holds after Android stopped the process: the open screens
     * and the feed's tab, view and feed or folder. The app used to reopen on the Priority Queue,
     * losing the article you were reading (e.g. after a while in the browser via "Open original").
     */
    private fun restoreSavedState() {
        savedState.get<String>(KEY_BACK_STACK)?.let(RouteCodec::decode)
            ?.takeIf { it.firstOrNull() == Route.Home }
            ?.let { routes ->
                backStack.clear()
                backStack.addAll(routes)
            }
        _uiState.update { s ->
            s.copy(
                currentTab = savedState.get<String>(KEY_TAB)?.let { name -> AppTab.entries.firstOrNull { it.name == name } } ?: s.currentTab,
                selectedFilter = savedState.get<String>(KEY_FILTER)?.let { name -> FeedFilter.entries.firstOrNull { it.name == name } } ?: s.selectedFilter,
                selectedFeedId = savedState[KEY_FEED_ID],
                selectedFeedTitle = savedState[KEY_FEED_TITLE],
                selectedCategoryId = savedState[KEY_CATEGORY_ID],
                selectedCategoryName = savedState[KEY_CATEGORY_NAME]
            )
        }
    }

    /**
     * Runs when the session ends: user logout, or the server rejecting the refresh token.
     * Clears everything loaded for the previous account, so a different user signing in next
     * doesn't see it.
     */
    private fun resetSession() {
        listOf(feedJob, drawerJob, workbenchJob, workbenchMoreJob, searchJob, suggestJob, countsJob, themeJob).forEach { it?.cancel() }
        countsLoadedAt = 0L
        dayDataGeneration++
        dayIntelRequested.clear()
        intelCountsRequested.clear()
        pendingReadIds.clear()
        val previous = _uiState.value
        val sessionExpired = previous.isLoggedIn && !userInitiatedLogout
        userInitiatedLogout = false
        // Device preferences survive sign-out. Their flows are distinctUntilChanged and don't emit
        // again, so dropping them here showed defaults (list layout, Hide Read off, no tracked
        // keywords) until the app restarted.
        _uiState.value = IntelFeedUiState(
            sessionChecked = true,
            serverUrl = previous.serverUrl,
            username = previous.username,
            recentSearches = previous.recentSearches,
            trackedKeywords = previous.trackedKeywords,
            feedDensity = previous.feedDensity,
            feedLayout = previous.feedLayout,
            feedHideRead = previous.feedHideRead,
            feedSort = previous.feedSort,
            feedAutoRead = previous.feedAutoRead,
            availableThemes = previous.availableThemes,
            activeThemeId = previous.activeThemeId,
            activeThemeName = previous.activeThemeName,
            activeThemeSource = previous.activeThemeSource,
            loginError = if (sessionExpired) "Your session has expired. Please sign in again." else previous.loginError
        )
        backStack.clear()
        backStack.add(Route.Home)
    }


    // NAVIGATION

    fun navigate(route: Route) {
        if (backStack.lastOrNull() == route) return
        backStack.add(route)
    }

    /** Replaces the top destination (reader next/previous), so Back returns to the list. */
    fun replaceTop(route: Route) {
        if (backStack.size <= 1) backStack.add(route) else backStack[backStack.lastIndex] = route
    }

    /** Returns false when there's nothing to pop (the system then closes the app). */
    fun goBack(): Boolean {
        if (backStack.size > 1) {
            val popped = backStack.removeAt(backStack.lastIndex)
            if (popped is Route.Reader) {
                purgeReadEntriesIfHiding()
            }
            return true
        }
        val state = _uiState.value
        return when {
            state.isSelecting -> { clearSelection(); true }
            state.currentTab != AppTab.FEED -> { setAppTab(AppTab.FEED); true }
            else -> false
        }
    }

    /** Opens an article, or a story thread for a Priority Queue story row. */
    fun openEntry(entry: EntryItem, contextIds: List<String>? = null) {
        val thread = entry.thread
        if (thread != null) {
            val slug = thread.slug ?: return
            navigate(Route.Thread(slug, thread.title))
        } else {
            val siblings = contextIds ?: _uiState.value.entries.filterNot { it.isThread }.map { it.id }
            navigate(Route.Reader(entry.id, siblings))
        }
    }

    /**
     * Opens one article. [contextIds] is the list Previous/Next walks; it defaults to just this
     * article. (Null means "the feed list", which only makes sense when opening from the feed: a
     * similar-coverage link or a notification used to let you swipe into unrelated feed articles.)
     */
    fun openEntry(id: String, contextIds: List<String>? = listOf(id)) = navigate(Route.Reader(id, contextIds))

    fun openEntity(ref: EntityRef) = navigate(Route.Entity(ref.type, ref.id, ref.name))

    fun openEntity(typeKey: String, idOrName: String, name: String? = null) {
        val type = EntityType.fromKey(typeKey)
        if (type == null) {
            messenger.show("Opening ${typeKey.replace('_', ' ')} results isn't supported in the app yet.")
            return
        }
        navigate(Route.Entity(type, idOrName, name))
    }

    fun openThread(slug: String, title: String? = null) = navigate(Route.Thread(slug, title))

    fun setFeedFocus(entryId: String) = _uiState.update { it.copy(feedFocusEntryId = entryId) }

    fun clearFeedFocus() = _uiState.update { it.copy(feedFocusEntryId = null) }

    fun setAppTab(tab: AppTab) {
        _uiState.update { it.copy(currentTab = tab, selectedIds = emptySet()) }
        if (tab == AppTab.FEED) {
            purgeReadEntriesIfHiding()
        }
        if (tab == AppTab.WORKBENCH && _uiState.value.workbenchItems.isEmpty() && !_uiState.value.workbenchLoading) {
            loadWorkbench()
        }
        if (tab == AppTab.SEARCH && _uiState.value.savedSearches.isEmpty()) loadSavedSearches()
    }

    // SESSION

    fun login(serverUrl: String, username: String, password: String) {
        if (username.isBlank() || password.isBlank()) {
            _uiState.update { it.copy(loginError = "Please enter both username and password") }
            return
        }
        // Validated here and only saved on sign-in. Saving on every keystroke let a partial
        // address like "https://" crash Retrofit, and the saved value crashed every launch after.
        val normalizedUrl = ServerUrl.normalize(serverUrl)
        if (normalizedUrl == null) {
            _uiState.update { it.copy(loginError = "Enter a valid server address, e.g. https://intelfeed.example.com") }
            return
        }
        if (_uiState.value.loginLoading) return

        viewModelScope.launch {
            _uiState.update { it.copy(loginLoading = true, loginError = null) }
            repository.login(normalizedUrl, username.trim(), password).fold(
                // Data loading starts from the isLoggedIn collector once the tokens are saved.
                onSuccess = { profile ->
                    _uiState.update { it.copy(loginLoading = false, username = profile.username ?: username.trim()) }
                },
                onFailure = { error ->
                    _uiState.update { it.copy(loginLoading = false, loginError = loginErrorMessage(error)) }
                }
            )
        }
    }

    private fun loginErrorMessage(error: Throwable): String = when {
        error is HttpException && error.code() == 401 -> "Invalid username or password."
        error is HttpException && error.code() == 429 -> "Too many sign-in attempts. Wait a few minutes and try again."
        else -> ErrorText.describe(error)
    }

    fun logout() {
        userInitiatedLogout = true
        // Clearing the tokens flips isLoggedIn, and resetSession() then clears the UI state.
        viewModelScope.launch { repository.logout() }
    }

    // FEED

    /** Switches the triage filter and clears any feed/category scope in one step (a single reload). */
    fun setFilter(filter: FeedFilter) {
        val state = _uiState.value
        if (state.selectedFilter == filter && state.selectedFeedId == null && state.selectedCategoryId == null) return
        _uiState.update {
            it.copy(
                selectedFilter = filter,
                selectedCategoryId = null,
                selectedCategoryName = null,
                selectedFeedId = null,
                selectedFeedTitle = null
            )
        }
        loadFeed(isRefresh = true, scopeChanged = true)
    }

    /**
     * Changes which articles of the open feed or folder are listed (all of them, or only unread),
     * keeping the scope. A feed opened from the drawer inherits the current view, which after launch
     * is the Priority Queue (unread only there), and the chips leave the feed, so a feed whose
     * articles were all read looked empty with no way to see them.
     */
    fun setScopedFilter(filter: FeedFilter) {
        if (_uiState.value.selectedFilter == filter) return
        _uiState.update { it.copy(selectedFilter = filter) }
        loadFeed(isRefresh = true, scopeChanged = true)
    }

    fun toggleFeedLayout() {
        val next = if (_uiState.value.feedLayout == "grid") "list" else "grid"
        viewModelScope.launch {
            userPreferences.setFeedLayout(next)
        }
    }

    fun setFeedAutoRead(enabled: Boolean) {
        viewModelScope.launch { userPreferences.setFeedAutoRead(enabled) }
        messenger.show(if (enabled) "Auto-read on: articles you scroll past are marked read" else "Auto-read off")
    }

    /**
     * Auto-read: the feed list reports articles the user scrolled off the top. They're marked
     * read in one request, quietly (the cards dim; no message for every scroll). Skipped while
     * selecting, where scrolling is for picking articles.
     */
    fun markScrolledPastRead(ids: Collection<String>) {
        val state = _uiState.value
        if (!state.feedAutoRead || state.isSelecting) return
        val targets = state.entries.filter { it.id in ids && !it.isRead && !it.isThread }
        if (targets.isEmpty()) return
        viewModelScope.launch {
            repository.bulkSet(BulkAction.READ, targets.associate { it.id to false })
                .onFailure { messenger.showError("mark scrolled-past articles read", it) }
        }
    }

    fun setFeedHideRead(hide: Boolean) {
        viewModelScope.launch { userPreferences.setFeedHideRead(hide) }
    }

    fun setFeedSort(sort: String) {
        viewModelScope.launch { userPreferences.setFeedSort(sort) }
    }

    fun setFeedLayout(layout: String) {
        viewModelScope.launch {
            userPreferences.setFeedLayout(layout)
        }
    }

    fun refreshFeed() {
        // Extraction can finish after an article first appears, so a refresh asks for cues again.
        intelCountsRequested.clear()
        resetDayData()
        loadFeed(isRefresh = true)
        loadCategoriesAndFeeds()
        loadViewCounts(force = true)
    }

    /**
     * Reloads the quick views' unread counts. Without [force] it's skipped when the counts are
     * under a minute old (the drawer asks every time it opens; they're eight requests).
     */
    fun loadViewCounts(force: Boolean = false) {
        if (!force && (countsJob?.isActive == true || System.currentTimeMillis() - countsLoadedAt < 60_000)) return
        countsJob?.cancel()
        countsJob = viewModelScope.launch {
            // Saved searches carry their own unread/total counts; refresh them with the views'.
            launch { repository.getSavedSearches().onSuccess { list -> _uiState.update { it.copy(savedSearches = list) } } }
            val counts = repository.getViewCounts()
            countsLoadedAt = System.currentTimeMillis()
            _uiState.update { it.copy(viewCounts = counts) }
        }
    }

    fun loadMoreEntries() {
        val state = _uiState.value
        if (!state.hasMore || state.nextCursor.isNullOrBlank()) return
        loadFeed(isRefresh = false)
    }

    /**
     * A refresh cancels whatever feed load is in flight. "Load more" is skipped while any load is
     * running, including a refresh, so a page fetched with an old cursor never lands on a new list.
     * When the scope changes, the old list and cursor are cleared right away.
     */
    private fun loadFeed(isRefresh: Boolean, scopeChanged: Boolean = false, keepDayFocus: Boolean = false) {
        if (isRefresh) {
            feedJob?.cancel()
        } else if (feedJob?.isActive == true) {
            return
        }

        if (scopeChanged) resetDayData()
        if (scopeChanged && !keepDayFocus) _uiState.update { it.copy(dayFocus = null) }
        val state = _uiState.value
        val cursor = if (isRefresh) null else state.nextCursor

        _uiState.update {
            val base = if (scopeChanged) {
                it.copy(entries = emptyList(), nextCursor = null, hasMore = false, selectedIds = emptySet(), feedScrollToTop = it.feedScrollToTop + 1)
            } else it
            base.copy(feedLoading = !isRefresh, isRefreshing = isRefresh, feedError = null)
        }

        feedJob = viewModelScope.launch {
            repository.getEntries(
                filter = state.selectedFilter,
                cursor = cursor,
                feedId = state.selectedFeedId,
                categoryId = state.selectedCategoryId,
                limit = 30,
                hideRead = state.feedHideRead,
                sort = state.feedSort,
                dayFocus = state.dayFocus
            ).fold(
                onSuccess = { page ->
                    loadIntelCounts(page.items)
                    _uiState.update { current ->
                        // distinctBy: LazyColumn crashes on duplicate keys, and a ranked queue can
                        // repeat an item across pages.
                        val updatedList = if (isRefresh) page.items.distinctBy { it.id }
                        else (current.entries + page.items).distinctBy { it.id }
                        current.copy(
                            entries = updatedList,
                            nextCursor = page.nextCursor,
                            hasMore = page.hasMore,
                            feedLoading = false,
                            isRefreshing = false,
                            selectedIds = if (current.selectedIds.isEmpty()) emptySet() else current.selectedIds.intersect(updatedList.map { it.id }.toSet())
                        )
                    }
                },
                onFailure = { error ->
                    _uiState.update {
                        it.copy(feedLoading = false, isRefreshing = false, feedError = ErrorText.describe(error))
                    }
                }
            )
        }
    }

    /** Fetches the intel cues for articles not asked about yet (one request per page, like the web). */
    private fun loadIntelCounts(entries: List<EntryItem>) {
        val ids = entries.filterNot { it.isThread }.map { it.id }.filter { intelCountsRequested.add(it) }
        if (ids.isEmpty()) return
        viewModelScope.launch {
            val counts = repository.getIntelCounts(ids)
            if (counts.isNotEmpty()) _uiState.update { it.copy(intelCounts = it.intelCounts + counts) }
        }
    }

    // DAY DIVIDERS (chips and AI briefings). Both describe the list on screen, so they're fetched
    // with its scope, and responses for a previous scope are dropped (dayDataGeneration).

    private fun currentDayScope(state: IntelFeedUiState = _uiState.value) = DayScope(
        feedId = state.selectedFeedId,
        categoryId = state.selectedCategoryId,
        starred = state.selectedFilter == FeedFilter.STARRED,
        bookmarked = state.selectedFilter == FeedFilter.BOOKMARKED
    )

    private fun resetDayData() {
        dayDataGeneration++
        dayIntelRequested.clear()
        _uiState.update {
            it.copy(dayIntel = emptyMap(), dailySummaries = emptyMap(), dailySummaryLoading = emptySet(), dailySummaryErrors = emptySet())
        }
    }

    /** The topic chips for a day divider ([dayKey] is the local "yyyy-MM-dd"). Fetched once per day and scope. */
    fun loadDayIntel(dayKey: String) {
        if (!dayIntelRequested.add(dayKey)) return
        val generation = dayDataGeneration
        val scope = currentDayScope()
        viewModelScope.launch {
            // A failure just leaves the divider without chips; they're a summary, not content.
            val intel = repository.getDayIntel(dayKey, scope).getOrNull()
            if (generation != dayDataGeneration) return@launch
            _uiState.update { it.copy(dayIntel = it.dayIntel + (dayKey to intel)) }
        }
    }

    /** The saved AI briefing for [dayKey] (local "yyyy-MM-dd"). Only reads; never generates one. */
    fun loadDailySummary(dayKey: String) {
        val state = _uiState.value
        if (state.dailySummaries.containsKey(dayKey) || dayKey in state.dailySummaryLoading) return
        val generation = dayDataGeneration
        val scope = currentDayScope(state)
        _uiState.update { it.copy(dailySummaryLoading = it.dailySummaryLoading + dayKey, dailySummaryErrors = it.dailySummaryErrors - dayKey) }
        viewModelScope.launch {
            val result = repository.getDailySummary(dayKey, scope)
            if (generation != dayDataGeneration) return@launch
            _uiState.update { st ->
                result.fold(
                    onSuccess = { summary ->
                        st.copy(dailySummaries = st.dailySummaries + (dayKey to summary), dailySummaryLoading = st.dailySummaryLoading - dayKey)
                    },
                    onFailure = {
                        st.copy(dailySummaryLoading = st.dailySummaryLoading - dayKey, dailySummaryErrors = st.dailySummaryErrors + dayKey)
                    }
                )
            }
        }
    }

    fun loadCategoriesAndFeeds() {
        drawerJob?.cancel()
        drawerJob = viewModelScope.launch {
            _uiState.update { it.copy(drawerLoading = true, drawerError = null) }
            // In parallel: the feed list (up to 1000 feeds) is slow, and it used to wait for the categories.
            val categoriesDeferred = async { repository.getCategories() }
            val feedsResult = repository.getFeeds()
            val categoriesResult = categoriesDeferred.await()
            val error = categoriesResult.exceptionOrNull() ?: feedsResult.exceptionOrNull()
            _uiState.update { state ->
                state.copy(
                    drawerLoading = false,
                    drawerError = error?.let { "Couldn't load your feeds. ${ErrorText.describe(it)}" },
                    categories = categoriesResult.getOrDefault(state.categories),
                    feeds = feedsResult.getOrDefault(state.feeds)
                )
            }
        }
    }

    fun selectCategory(id: String?, name: String?) {
        _uiState.update {
            it.copy(selectedCategoryId = id, selectedCategoryName = name, selectedFeedId = null, selectedFeedTitle = null)
        }
        loadFeed(isRefresh = true, scopeChanged = true)
    }

    fun selectFeed(id: String?, title: String?) {
        _uiState.update {
            it.copy(selectedFeedId = id, selectedFeedTitle = title, selectedCategoryId = null, selectedCategoryName = null)
        }
        loadFeed(isRefresh = true, scopeChanged = true)
    }

    fun clearFeedFilter() {
        _uiState.update {
            it.copy(selectedCategoryId = null, selectedCategoryName = null, selectedFeedId = null, selectedFeedTitle = null)
        }
        loadFeed(isRefresh = true, scopeChanged = true)
    }

    // ENTRY FLAGS. The repository broadcasts each change; applyEntryUpdate() updates every list.

    fun toggleRead(entry: EntryItem) = setRead(entry.id, !entry.isRead)

    fun setRead(id: String, read: Boolean) {
        viewModelScope.launch {
            repository.setRead(id, read).onFailure { messenger.showError("update read status", it) }
        }
    }

    fun toggleStar(entry: EntryItem) {
        viewModelScope.launch {
            repository.setStarred(entry.id, !entry.isStarred).onFailure { messenger.showError("update the star", it) }
        }
    }

    fun toggleBookmark(entry: EntryItem) {
        viewModelScope.launch {
            repository.setBookmarked(entry.id, !entry.isBookmarked).onFailure { messenger.showError("update the bookmark", it) }
        }
    }

    fun shouldHideRead(state: IntelFeedUiState = _uiState.value): Boolean {
        return state.selectedFilter == FeedFilter.UNREAD ||
            state.selectedFilter == FeedFilter.PRIORITY_QUEUE ||
            (state.feedHideRead && state.selectedFilter != FeedFilter.PRIORITY_QUEUE)
    }

    /** Removes read articles from the current list if the view is unread-only or hiding read. */
    fun purgeReadEntriesIfHiding() {
        val state = _uiState.value
        if (shouldHideRead(state)) {
            _uiState.update { current ->
                val remaining = current.entries.filterNot { it.isRead && !it.isThread && it.id !in pendingReadIds }
                current.copy(entries = remaining)
            }
        }
    }

    private fun applyEntryUpdate(update: EntryFlagUpdate) {
        if (update.isRead == true && !update.confirmed) pendingReadIds.add(update.id)
        // Only a read-state update settles a pending read; a confirmed star or bookmark must not.
        if (update.isRead == false || (update.isRead == true && update.confirmed)) pendingReadIds.remove(update.id)
        _uiState.update { state ->
            val before = state.entries.find { it.id == update.id } ?: state.searchEntries.find { it.id == update.id }
            // Keep the drawer's unread badges honest as articles are read.
            val feeds = if (update.isRead != null && before != null && before.feedId != null && before.isRead != update.isRead) {
                val delta = if (update.isRead) -1 else 1
                state.feeds.map { f -> if (f.id == before.feedId) f.copy(unreadCount = (f.unreadCount + delta).coerceAtLeast(0)) else f }
            } else state.feeds
            // The Unread count follows reads and unreads made in the app until the next reload.
            val counts = if (update.isRead != null && before != null && before.isRead != update.isRead && state.viewCounts.unread != null) {
                state.viewCounts.copy(unread = (state.viewCounts.unread + if (update.isRead) -1 else 1).coerceAtLeast(0))
            } else state.viewCounts
            val isReaderOpen = backStack.lastOrNull() is Route.Reader
            val hideRead = shouldHideRead(state)
            val updatedEntries = if (update.isRead == true && update.confirmed && hideRead && !isReaderOpen) {
                state.entries.filterNot { it.id == update.id && !it.isThread }
            } else {
                state.entries.map { if (it.id == update.id) it.applied(update) else it }
            }
            state.copy(
                entries = updatedEntries,
                searchEntries = state.searchEntries.map { if (it.id == update.id) it.applied(update) else it },
                feeds = feeds,
                viewCounts = counts
            )
        }
    }

    private fun EntryItem.applied(u: EntryFlagUpdate) = copy(
        isRead = u.isRead ?: isRead,
        isStarred = u.isStarred ?: isStarred,
        isBookmarked = u.isBookmarked ?: isBookmarked
    )

    /** Marks everything in the current feed/category scope read, or every feed when nothing is selected. */
    /** The unscoped Priority Queue (inside a feed or folder, that view is plain unread articles). */
    private fun IntelFeedUiState.isPriorityQueueList() =
        selectedFilter == FeedFilter.PRIORITY_QUEUE && selectedFeedId == null && selectedCategoryId == null

    fun markAllAsRead() {
        val state = _uiState.value
        _uiState.update { current -> current.copy(entries = current.entries.map { it.copy(isRead = true) }) }
        viewModelScope.launch {
            repository.markAllRead(
                feedId = state.selectedFeedId,
                categoryId = state.selectedCategoryId,
                priorityOnly = state.isPriorityQueueList()
            )
                .onSuccess { messenger.show("All caught up") }
                .onFailure { messenger.showError("mark everything as read", it) }
            // Reload either way so the list matches the server (this also undoes the optimistic update on failure).
            loadFeed(isRefresh = true)
            loadCategoriesAndFeeds()
            loadViewCounts(force = true)
        }
    }

    /**
     * Marks every unread article from one day read, like the web's day-divider button: the
     * current feed or folder if one is selected, otherwise all feeds. Then reloads the list.
     */
    fun markDayRead(dayKey: String, label: String) {
        val state = _uiState.value
        viewModelScope.launch {
            repository.markDayRead(dayKey, feedId = state.selectedFeedId, categoryId = state.selectedCategoryId)
                .onSuccess { messenger.show("Marked everything from $label as read") }
                .onFailure { messenger.showError("mark $label as read", it) }
            loadFeed(isRefresh = true)
            loadCategoriesAndFeeds()
            loadViewCounts(force = true)
        }
    }

    /** The web's Shift+M: marks every unread article above [entryId] in the list as read. */
    fun markAboveAsRead(entryId: String) {
        val entries = _uiState.value.entries
        val index = entries.indexOfFirst { it.id == entryId }
        if (index <= 0) return
        val targets = entries.take(index).filter { !it.isRead && !it.isThread }
        if (targets.isEmpty()) {
            messenger.show("Everything above is already read")
            return
        }
        runBulk(BulkAction.READ, targets)
    }

    // SELECTION

    fun toggleSelection(id: String) {
        _uiState.update { s ->
            s.copy(selectedIds = if (id in s.selectedIds) s.selectedIds - id else s.selectedIds + id)
        }
    }

    fun selectAll() {
        _uiState.update { s -> s.copy(selectedIds = s.entries.filterNot { it.isThread }.map { it.id }.toSet()) }
    }

    fun clearSelection() = _uiState.update { it.copy(selectedIds = emptySet()) }

    fun applyToSelection(action: BulkAction) {
        val state = _uiState.value
        val targets = state.entries.filter { it.id in state.selectedIds && !it.isThread }
        clearSelection()
        runBulk(action, targets)
    }

    private fun runBulk(action: BulkAction, targets: List<EntryItem>) {
        if (targets.isEmpty()) return
        val previous = targets.associate { e ->
            e.id to when (action) {
                BulkAction.READ, BulkAction.UNREAD -> e.isRead
                BulkAction.STAR, BulkAction.UNSTAR -> e.isStarred
                BulkAction.BOOKMARK, BulkAction.UNBOOKMARK -> e.isBookmarked
            }
        }
        viewModelScope.launch {
            repository.bulkSet(action, previous).fold(
                onSuccess = {
                    val noun = if (targets.size == 1) "1 article" else "${targets.size} articles"
                    val verb = when (action) {
                        BulkAction.READ -> "Marked $noun read"
                        BulkAction.UNREAD -> "Marked $noun unread"
                        BulkAction.STAR -> "Starred $noun"
                        BulkAction.UNSTAR -> "Unstarred $noun"
                        BulkAction.BOOKMARK -> "Bookmarked $noun"
                        BulkAction.UNBOOKMARK -> "Removed $noun from bookmarks"
                    }
                    messenger.show(verb, "Undo") { undoBulk(action, previous) }
                    loadViewCounts(force = true)
                },
                onFailure = { messenger.showError("update ${targets.size} articles", it) }
            )
        }
    }

    /**
     * Restores each entry's own previous value: only entries the action actually changed get the
     * opposite action, so undoing "mark 10 read" leaves the ones that were already read alone.
     */
    private fun undoBulk(action: BulkAction, previous: Map<String, Boolean>) {
        val changed = previous.filterValues { it != action.value }.mapValues { action.value }
        if (changed.isEmpty()) return
        viewModelScope.launch {
            repository.bulkSet(action.opposite, changed).fold(
                onSuccess = {
                    if (shouldHideRead() && action == BulkAction.READ) {
                        loadFeed(isRefresh = true)
                    }
                    loadViewCounts(force = true)
                },
                onFailure = { messenger.showError("undo", it) }
            )
        }
    }

    // WORKBENCH

    fun setWorkbenchTab(tab: WorkbenchTab) {
        if (_uiState.value.selectedWorkbenchTab == tab && _uiState.value.workbenchItems.isNotEmpty()) return
        _uiState.update { it.copy(selectedWorkbenchTab = tab, workbenchItems = emptyList(), workbenchTotal = null) }
        loadWorkbench()
    }

    fun setWorkbenchSearch(query: String) {
        _uiState.update { it.copy(workbenchSearchQuery = query) }
        loadWorkbench(debounceMs = 350)
    }

    fun loadWorkbench(debounceMs: Long = 0) {
        workbenchJob?.cancel()
        workbenchMoreJob?.cancel()
        workbenchJob = viewModelScope.launch {
            if (debounceMs > 0) delay(debounceMs)
            val tab = _uiState.value.selectedWorkbenchTab
            val query = _uiState.value.workbenchSearchQuery.trim().ifEmpty { null }
            _uiState.update { it.copy(workbenchLoading = true, workbenchLoadingMore = false, workbenchError = null) }
            fetchWorkbench(tab, query, 0).fold(
                onSuccess = { page ->
                    workbenchItemsKey = tab to query
                    _uiState.update {
                        it.copy(
                            workbenchItems = page.items.distinctBy { i -> i.ref.id },
                            workbenchTotal = page.total,
                            workbenchHasMore = page.hasMore,
                            workbenchNextOffset = page.nextOffset,
                            workbenchLoading = false
                        )
                    }
                },
                onFailure = { err ->
                    // The screen only shows the error when the list is empty. A failed refresh keeps
                    // the list and says so; a failed new search clears it, or the old, unfiltered
                    // list stayed under the new search text as if it were the result.
                    val sameList = workbenchItemsKey == (tab to query) && _uiState.value.workbenchItems.isNotEmpty()
                    _uiState.update {
                        if (sameList) it.copy(workbenchLoading = false, workbenchError = ErrorText.describe(err))
                        else it.copy(workbenchLoading = false, workbenchError = ErrorText.describe(err),
                            workbenchItems = emptyList(), workbenchTotal = null, workbenchHasMore = false)
                    }
                    if (sameList) messenger.showError("refresh the Workbench", err) { loadWorkbench() }
                }
            )
        }
    }

    fun loadMoreWorkbench() {
        val state = _uiState.value
        if (!state.workbenchHasMore || state.workbenchLoading || state.workbenchLoadingMore) return
        // A first page is still pending (e.g. a debounced search): its results replace the list.
        if (workbenchJob?.isActive == true) return
        val tab = state.selectedWorkbenchTab
        val query = state.workbenchSearchQuery.trim().ifEmpty { null }
        workbenchMoreJob = viewModelScope.launch {
            _uiState.update { it.copy(workbenchLoadingMore = true) }
            fetchWorkbench(tab, query, state.workbenchNextOffset).fold(
                onSuccess = { page ->
                    _uiState.update {
                        it.copy(
                            workbenchItems = (it.workbenchItems + page.items).distinctBy { i -> i.ref.id },
                            workbenchTotal = page.total ?: it.workbenchTotal,
                            workbenchHasMore = page.hasMore,
                            workbenchNextOffset = page.nextOffset,
                            workbenchLoadingMore = false
                        )
                    }
                },
                onFailure = { err ->
                    _uiState.update { it.copy(workbenchLoadingMore = false) }
                    messenger.showError("load more", err) { loadMoreWorkbench() }
                }
            )
        }
    }

    private suspend fun fetchWorkbench(tab: WorkbenchTab, query: String?, offset: Int): Result<OffsetPage<WorkbenchItem>> {
        fun <T> Result<OffsetPage<T>>.rows(map: (T) -> WorkbenchItem) =
            map { p -> OffsetPage(p.items.map(map), p.total, p.hasMore, p.nextOffset) }
        return when (tab) {
            WorkbenchTab.ACTORS -> repository.getThreatActors(query, offset).rows { it.toWorkbenchItem() }
            WorkbenchTab.MALWARE -> repository.getMalware(query, offset).rows { it.toWorkbenchItem() }
            WorkbenchTab.CVES -> repository.getCves(query, offset).rows { it.toWorkbenchItem() }
            WorkbenchTab.TTPS -> repository.getTtps(query, offset).rows { it.toWorkbenchItem() }
            WorkbenchTab.WEAKNESSES -> repository.getCwes(query, offset).rows { it.toWorkbenchItem() }
            WorkbenchTab.OBSERVABLES -> repository.getObservables(query, offset).rows { it.toWorkbenchItem() }
            WorkbenchTab.TOOLS -> repository.getTools(query, offset).rows { it.toWorkbenchItem() }
            WorkbenchTab.VENDORS -> repository.getVendors(query, offset).rows { it.toWorkbenchItem() }
            WorkbenchTab.PRODUCTS -> repository.getProducts(query, offset).rows { it.toWorkbenchItem() }
            WorkbenchTab.COUNTRIES -> repository.getCountries(query, offset).rows { it.toWorkbenchItem() }
            WorkbenchTab.RULES -> repository.getDetectionRules(query, offset).rows { it.toWorkbenchItem() }
            WorkbenchTab.CAMPAIGNS -> repository.getCampaigns(query, offset).rows { it.toWorkbenchItem() }
            WorkbenchTab.MITIGATIONS -> repository.getMitigations(query, offset).rows { it.toWorkbenchItem() }
            // Views load their own data (see WorkbenchScreen).
            WorkbenchTab.ATTACK_MATRIX, WorkbenchTab.RANSOMWARE -> Result.success(OffsetPage(emptyList(), 0, false, 0))
            WorkbenchTab.WATCHLIST -> repository.getWatchlist().map { list ->
                val rows = list.mapNotNull { it.toWorkbenchItem() }
                    .filter { query == null || it.title.contains(query, ignoreCase = true) }
                OffsetPage(rows, rows.size, false, rows.size)
            }
        }
    }

    private fun WatchlistItem.toWorkbenchItem(): WorkbenchItem? {
        val type = EntityType.fromKey(entityType) ?: return null
        val name = entityName ?: entityId
        return WorkbenchItem(
            ref = EntityRef(type, entityId, name),
            title = name,
            subtitle = type.label,
            badges = listOf(if (mode == "mute") Badge("Muted", Tone.NEUTRAL) else Badge("Watching", Tone.SUCCESS))
        )
    }

    // SEARCH

    fun setSearchQuery(query: String) {
        _uiState.update { it.copy(searchQuery = query) }
        suggestJob?.cancel()
        val lastToken = query.substringAfterLast(' ')
        if (lastToken.length < 2) {
            _uiState.update { it.copy(searchSuggestions = emptyList()) }
            return
        }
        suggestJob = viewModelScope.launch {
            delay(250)
            val suggestions = repository.autocomplete(query).getOrDefault(emptyList())
            _uiState.update { it.copy(searchSuggestions = suggestions.filter { s -> !s.insert.isNullOrBlank() || s.text.isNotBlank() }.take(6)) }
        }
    }

    /** Replaces the word being typed with the suggestion ("threat_actor:qil" -> "threat_actor:Qilin "). */
    fun applySuggestion(suggestion: SearchSuggestion) {
        val query = _uiState.value.searchQuery
        val insert = suggestion.insert ?: suggestion.text
        val prefix = query.substringBeforeLast(' ', "").let { if (it.isEmpty()) "" else "$it " }
        val newQuery = "$prefix${quoteIfNeeded(insert)} "
        _uiState.update { it.copy(searchQuery = newQuery, searchSuggestions = emptyList()) }
    }

    private fun quoteIfNeeded(insert: String): String {
        val field = insert.substringBefore(':', "")
        val value = insert.substringAfter(':', insert)
        return if (field.isNotEmpty() && value.contains(' ') && !value.startsWith("\"")) "$field:\"$value\"" else insert
    }

    fun setSearchScope(scope: SearchScope) = _uiState.update { it.copy(searchScope = scope) }

    fun searchUnified(query: String) {
        val trimmed = query.trim()
        if (trimmed.isBlank()) return
        suggestJob?.cancel()
        searchJob?.cancel()
        _uiState.update {
            it.copy(
                searchQuery = trimmed,
                submittedQuery = trimmed,
                searchLoading = true,
                searchError = null,
                searchSuggestions = emptyList(),
                searchEntries = emptyList(),
                searchEntriesTotal = 0
            )
        }
        viewModelScope.launch { userPreferences.addRecentSearch(trimmed) }
        searchJob = viewModelScope.launch {
            repository.searchUnified(trimmed).fold(
                onSuccess = { res ->
                    loadIntelCounts(res.entries.hits)
                    _uiState.update {
                        it.copy(
                            searchResponse = res,
                            searchEntries = res.entries.hits.distinctBy { e -> e.id },
                            searchEntriesTotal = res.entries.estimatedTotalHits,
                            searchLoading = false
                        )
                    }
                },
                onFailure = { err ->
                    _uiState.update { it.copy(searchLoading = false, searchError = ErrorText.describe(err)) }
                }
            )
        }
    }

    fun loadMoreSearchResults() {
        val state = _uiState.value
        val query = state.submittedQuery ?: return
        if (!state.searchHasMore || state.searchLoading || state.searchLoadingMore) return
        searchJob = viewModelScope.launch {
            _uiState.update { it.copy(searchLoadingMore = true) }
            repository.searchUnified(query, offset = state.searchEntries.size).fold(
                onSuccess = { res ->
                    loadIntelCounts(res.entries.hits)
                    _uiState.update {
                        val merged = (it.searchEntries + res.entries.hits).distinctBy { e -> e.id }
                        it.copy(
                            searchEntries = merged,
                            // Stop paging if the server returns nothing new.
                            searchEntriesTotal = if (merged.size == it.searchEntries.size) merged.size else res.entries.estimatedTotalHits,
                            searchLoadingMore = false
                        )
                    }
                },
                onFailure = { err ->
                    _uiState.update { it.copy(searchLoadingMore = false) }
                    messenger.showError("load more results", err) { loadMoreSearchResults() }
                }
            )
        }
    }

    fun clearSearch() {
        searchJob?.cancel()
        suggestJob?.cancel()
        _uiState.update {
            it.copy(searchQuery = "", submittedQuery = null, searchResponse = null, searchEntries = emptyList(),
                searchEntriesTotal = 0, searchError = null, searchLoading = false, searchSuggestions = emptyList())
        }
    }

    fun clearRecentSearches() {
        viewModelScope.launch { userPreferences.clearRecentSearches() }
    }

    fun loadSavedSearches() {
        viewModelScope.launch {
            repository.getSavedSearches().onSuccess { list -> _uiState.update { it.copy(savedSearches = list) } }
        }
    }

    fun saveCurrentSearch(name: String) {
        val query = _uiState.value.submittedQuery ?: return
        viewModelScope.launch {
            repository.createSavedSearch(name.ifBlank { query }, query).fold(
                onSuccess = { saved ->
                    _uiState.update { it.copy(savedSearches = listOf(saved) + it.savedSearches) }
                    messenger.show("Saved \"${saved.label}\"")
                },
                onFailure = { messenger.showError("save the search", it) }
            )
        }
    }

    // KEYWORDS (tracked on this device)

    /**
     * Tracks [keyword] on this device. With [alsoOnServer] it's also added as an intelligence
     * requirement (shared with everyone on the server, like the website's), unless one already
     * lists that keyword.
     */
    fun addKeyword(keyword: String, alsoOnServer: Boolean = false) {
        viewModelScope.launch {
            val clean = keyword.trim()
            if (clean.length < 2) {
                messenger.show("A keyword needs at least 2 characters")
                return@launch
            }
            val added = userPreferences.addTrackedKeyword(clean)
            if (!alsoOnServer) {
                if (added) messenger.show("Tracking \"$clean\". It's highlighted in articles, and new matches are notified if alerts are on.")
                else messenger.show("\"$clean\" is already tracked (or you've reached ${UserPreferences.MAX_KEYWORDS} keywords)")
                return@launch
            }
            val existing = repository.getRequirements().getOrNull()
                ?.firstOrNull { req -> req.keywords.any { it.equals(clean, ignoreCase = true) } }
            if (existing != null) {
                messenger.show("${if (added) "Tracking \"$clean\". " else ""}The server requirement \"${existing.title}\" already covers it.")
                return@launch
            }
            repository.createRequirement(title = clean, keywords = listOf(clean)).fold(
                onSuccess = { messenger.show(if (added) "Tracking \"$clean\" here and as a server requirement" else "Added \"$clean\" as a server requirement") },
                onFailure = { messenger.showError("add the server requirement", it) }
            )
        }
    }

    fun openRequirements() = navigate(Route.Requirements)

    fun removeKeyword(keyword: String) {
        viewModelScope.launch {
            userPreferences.removeTrackedKeyword(keyword)
            messenger.show("Stopped tracking \"$keyword\"", "Undo") { addKeyword(keyword) }
        }
    }

    /**
     * Articles containing [keyword] as a phrase, on the Search tab (from the drawer or a highlight
     * in an article). [newestFirst] is for a keyword alert: search is relevance-ordered by default,
     * which could put the new articles the alert was about below older ones.
     */
    fun searchKeyword(keyword: String, newestFirst: Boolean = false) {
        val clean = keyword.trim().replace("\"", "")
        if (clean.isEmpty()) return
        while (backStack.size > 1) backStack.removeAt(backStack.lastIndex)
        setAppTab(AppTab.SEARCH)
        _uiState.update { it.copy(searchScope = SearchScope.ARTICLES) }
        searchUnified(if (newestFirst) "\"$clean\" sort:newest" else "\"$clean\"")
    }

    /** Runs [query] as typed on the Search tab (articles), from the home screen. */
    fun searchQuery(query: String) {
        if (query.isBlank()) return
        while (backStack.size > 1) backStack.removeAt(backStack.lastIndex)
        setAppTab(AppTab.SEARCH)
        _uiState.update { it.copy(searchScope = SearchScope.ARTICLES) }
        searchUnified(query)
    }

    /**
     * Shows every article with a tag: goes back to the home screen and runs `tag:<name>` on the
     * Search tab (the web links tags to its search page the same way).
     */
    fun searchTag(name: String) {
        val clean = name.trim().removePrefix("#").replace("\"", "")
        if (clean.isEmpty()) return
        while (backStack.size > 1) backStack.removeAt(backStack.lastIndex)
        setAppTab(AppTab.SEARCH)
        _uiState.update { it.copy(searchScope = SearchScope.ARTICLES) }
        searchUnified(if (clean.any { it.isWhitespace() }) "tag:\"$clean\"" else "tag:$clean")
    }

    /**
     * A day chip was tapped: show only that day's matching articles, like the web; the same chip
     * again (or null) shows the whole list again. The day chips and briefings stay as they are.
     */
    fun setDayFocus(focus: com.example.intelfeed.data.model.DayFocus?) {
        val current = _uiState.value.dayFocus
        val next = if (focus != null && current?.dayKey == focus.dayKey && current.chip == focus.chip) null
            // Match the open view's range (the user's request): Last 24 hours → 24h, This week → 7 days.
            else focus?.copy(window = defaultFocusWindow(_uiState.value.selectedFilter))
        applyDayFocus(next)
    }

    /** Changes the time range of the current chip filter (the bar's picker). */
    fun setDayFocusWindow(window: com.example.intelfeed.data.model.FocusWindow) {
        val current = _uiState.value.dayFocus ?: return
        if (current.window == window) return
        applyDayFocus(current.copy(window = window))
    }

    private fun defaultFocusWindow(filter: FeedFilter) = when (filter) {
        FeedFilter.LAST_24H -> com.example.intelfeed.data.model.FocusWindow.H24
        FeedFilter.THIS_WEEK -> com.example.intelfeed.data.model.FocusWindow.D7
        else -> com.example.intelfeed.data.model.FocusWindow.DAY
    }

    private fun applyDayFocus(next: com.example.intelfeed.data.model.DayFocus?) {
        feedJob?.cancel()
        _uiState.update {
            it.copy(dayFocus = next, entries = emptyList(), nextCursor = null, hasMore = false, selectedIds = emptySet(), feedScrollToTop = it.feedScrollToTop + 1)
        }
        loadFeed(isRefresh = true)
    }

    /** Opens a saved search from the drawer like the web does: runs it on the Search tab, in its saved scope. */
    fun openSavedSearch(search: SavedSearch) {
        val scope = when (search.filters?.scope?.lowercase()) {
            "workbench" -> SearchScope.ENTITIES
            "feeds" -> SearchScope.ARTICLES
            else -> SearchScope.EVERYTHING
        }
        setAppTab(AppTab.SEARCH)
        _uiState.update { it.copy(searchScope = scope) }
        searchUnified(search.query)
    }

    fun deleteSavedSearch(search: SavedSearch) {
        // By id: the list is refreshed with new counts, so the item on screen may no longer be equal to [search].
        _uiState.update { it.copy(savedSearches = it.savedSearches.filterNot { s -> s.id == search.id }) }
        viewModelScope.launch {
            repository.deleteSavedSearch(search.id).onFailure {
                _uiState.update { s -> if (s.savedSearches.any { it.id == search.id }) s else s.copy(savedSearches = s.savedSearches + search) }
                messenger.showError("delete the saved search", it)
            }
        }
    }

    fun deleteTag(tagId: String, onComplete: (Boolean) -> Unit = {}) {
        viewModelScope.launch {
            repository.deleteTag(tagId).fold(
                onSuccess = {
                    messenger.show("Tag deleted")
                    onComplete(true)
                },
                onFailure = {
                    messenger.showError("delete the tag", it)
                    onComplete(false)
                }
            )
        }
    }

    // SHARE TARGET

    /** "Share to IntelFeed" from another app: ingests the page as an article. */
    fun ingestSharedUrl(url: String) {
        messenger.show("Adding to IntelFeed…")
        viewModelScope.launch {
            repository.ingestUrl(url).fold(
                onSuccess = { res ->
                    val id = res.id
                    val title = res.title?.takeIf { it.isNotBlank() } ?: "the article"
                    if (id != null) messenger.show("Added $title", "Open") { openEntry(id) }
                    else messenger.show(res.message ?: "Added $title")
                },
                onFailure = { messenger.showError("add that page", it) { ingestSharedUrl(url) } }
            )
        }
    }

    // ADD FEED (drawer). Subscribing and adding a single page are separate, explicit choices: a
    // failed subscription used to fall back to ingesting the URL as an article on the shared server.

    /** Looks for feeds at [url] without subscribing (POST /api/feeds/discover). */
    fun discoverFeeds(url: String, onResult: (Result<List<DiscoveredFeed>>) -> Unit) {
        viewModelScope.launch { onResult(repository.discoverFeeds(url)) }
    }

    fun subscribeToFeed(feed: DiscoveredFeed, categoryId: String?, fetchIntervalMinutes: Int?) {
        val label = feed.title?.takeIf { it.isNotBlank() } ?: feed.url
        messenger.show("Subscribing to $label…")
        viewModelScope.launch {
            repository.createFeed(feed.url, categoryId = categoryId, fetchIntervalMinutes = fetchIntervalMinutes).fold(
                onSuccess = { created ->
                    messenger.show("Subscribed to ${created.displayTitle}", "Open") { selectFeed(created.id, created.displayTitle) }
                    loadCategoriesAndFeeds()
                },
                onFailure = { err ->
                    val hint = if (err is HttpException && err.code() == 403) " Adding feeds may need an admin account." else ""
                    messenger.show("Couldn't subscribe to $label. ${ErrorText.describe(err)}$hint")
                }
            )
        }
    }

    /** The part of the UI state kept in the saved state. */
    private data class SavedView(
        val tab: AppTab,
        val filter: FeedFilter,
        val feedId: String?,
        val feedTitle: String?,
        val categoryId: String?,
        val categoryName: String?
    )

    private companion object {
        const val KEY_BACK_STACK = "back_stack"
        const val KEY_TAB = "tab"
        const val KEY_FILTER = "filter"
        const val KEY_FEED_ID = "feed_id"
        const val KEY_FEED_TITLE = "feed_title"
        const val KEY_CATEGORY_ID = "category_id"
        const val KEY_CATEGORY_NAME = "category_name"
    }
}
