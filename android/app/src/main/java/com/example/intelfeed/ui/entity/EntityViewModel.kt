package com.example.intelfeed.ui.entity

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.intelfeed.data.model.EntityNote
import com.example.intelfeed.data.model.EntityRelationship
import com.example.intelfeed.data.model.EntityType
import com.example.intelfeed.data.model.EntryItem
import com.example.intelfeed.data.model.UserProfile
import com.example.intelfeed.data.repository.IntelFeedRepository
import com.example.intelfeed.data.repository.OffsetPage
import com.example.intelfeed.ui.ErrorText
import com.example.intelfeed.ui.UiMessenger
import com.example.intelfeed.data.model.EntityStory
import com.example.intelfeed.data.model.MentionsTimeseries
import com.example.intelfeed.data.model.TimelineEvent
import com.example.intelfeed.data.model.WhatsNewItem
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.withContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/** A paged list section of the profile (articles, relationships). */
data class PagedSection<T>(
    val items: List<T> = emptyList(),
    val total: Int? = null,
    val loading: Boolean = false,
    val loaded: Boolean = false,
    val hasMore: Boolean = false,
    val nextOffset: Int = 0,
    val error: String? = null,
    // Cursor-paged sections (a campaign's articles) page with this instead of nextOffset.
    val nextCursor: String? = null
)

/** The Timeline tab: mentions chart, what's new, stories and key events. Loaded when the tab opens. */
data class TimelineUiState(
    val requested: Boolean = false,
    val loading: Boolean = false,
    val window: String = "90d",
    val mentions: MentionsTimeseries? = null,
    val mentionsLoading: Boolean = false,
    val mentionsError: String? = null,
    val whatsNew: List<WhatsNewItem> = emptyList(),
    val stories: List<EntityStory> = emptyList(),
    // Key events only (see TimelinePresentation.keyEvents), newest first.
    val events: List<TimelineEvent> = emptyList(),
    val eventsError: String? = null,
    val shownEvents: Int = TimelinePresentation.PAGE
)

data class EntityUiState(
    val profile: EntityProfile? = null,
    val loading: Boolean = true,
    val error: String? = null,
    val articles: PagedSection<EntryItem> = PagedSection(),
    val relationships: PagedSection<EntityRelationship> = PagedSection(),
    // The web's relationship graph (GET /api/intelligence/graph/{type}/{id}?depth=1).
    val graph: com.example.intelfeed.data.model.EntityGraph? = null,
    val graphLoading: Boolean = false,
    val graphError: String? = null,
    // Time window for the graph (window_days); null = all time.
    val graphWindowDays: Int? = null,
    val notes: List<EntityNote> = emptyList(),
    val notesLoaded: Boolean = false,
    val notesLoading: Boolean = false,
    val notesError: String? = null,
    /** "watch", "mute" or null. */
    val watchMode: String? = null,
    val watchBusy: Boolean = false,
    val currentUser: UserProfile? = null,
    val timeline: TimelineUiState = TimelineUiState()
) {
    fun canEdit(note: EntityNote): Boolean {
        val user = currentUser ?: return false
        return user.role.equals("admin", ignoreCase = true) || (note.createdBy != null && note.createdBy == user.id)
    }
}

/** One entity profile. Scoped to its back-stack entry, so profiles you pivot through keep their state. */
class EntityViewModel(
    private val type: EntityType,
    private val idOrName: String,
    private val name: String?,
    private val repository: IntelFeedRepository,
    private val messenger: UiMessenger
) : ViewModel() {

    private val _state = MutableStateFlow(EntityUiState())
    val state: StateFlow<EntityUiState> = _state.asStateFlow()

    private var articlesJob: Job? = null
    private var mentionsJob: Job? = null

    init {
        viewModelScope.launch { repository.currentUser.collect { u -> _state.update { it.copy(currentUser = u) } } }
        viewModelScope.launch {
            repository.entryUpdates.collect { u ->
                _state.update { s ->
                    s.copy(articles = s.articles.copy(items = s.articles.items.map { e ->
                        if (e.id != u.id) e else e.copy(
                            isRead = u.isRead ?: e.isRead,
                            isStarred = u.isStarred ?: e.isStarred,
                            isBookmarked = u.isBookmarked ?: e.isBookmarked
                        )
                    }))
                }
            }
        }
        load()
    }

    fun load() {
        _state.update { it.copy(loading = true, error = null) }
        viewModelScope.launch {
            resolveProfile().fold(
                onSuccess = { profile ->
                    _state.update { it.copy(profile = profile, loading = false) }
                    loadArticles(reset = true)
                    if (type.watchable) loadWatchMode(profile)
                },
                onFailure = { e ->
                    if (e is NoSuchElementException) {
                        // Graceful fallback: construct minimal profile so user can view articles & mentions
                        val fallback = fallbackProfile()
                        _state.update { it.copy(profile = fallback, loading = false, error = null) }
                        loadArticles(reset = true)
                    } else {
                        _state.update {
                            it.copy(loading = false, error = ErrorText.describe(e))
                        }
                    }
                }
            )
        }
    }

    private fun fallbackProfile(): EntityProfile {
        val displayName = name?.takeIf { it.isNotBlank() } ?: idOrName
        return EntityProfile(
            ref = EntityRef(type, idOrName, displayName),
            title = displayName,
            subtitle = type.label,
            description = "IntelFeed has no profile for this name yet. The Articles tab lists the reporting that mentions it.",
            searchName = displayName,
            placeholder = true
        )
    }

    /**
     * Fetches the detail by id. If there's no id (article pivots sometimes only carry a name) or
     * the fetch fails, searches by name but only accepts an exact name/alias/id match: the first
     * fuzzy hit could be the wrong actor.
     */
    private suspend fun resolveProfile(): Result<EntityProfile> {
        val key = idOrName.trim()
        val label = name ?: key
        suspend fun <T> resolve(
            fetch: suspend (String) -> Result<T>,
            search: suspend (String) -> Result<OffsetPage<T>>,
            matches: (T) -> Boolean,
            toProfile: (T) -> EntityProfile
        ): Result<EntityProfile> {
            fetch(key).getOrNull()?.let { return Result.success(toProfile(it)) }
            val found = search(label)
            found.exceptionOrNull()?.let { return Result.failure(it) }
            val match = found.getOrNull()?.items?.firstOrNull(matches) ?: return Result.failure(NoSuchElementException())
            return Result.success(toProfile(match))
        }
        fun same(a: String?) = a != null && (a.equals(key, ignoreCase = true) || a.equals(label, ignoreCase = true))
        return when (type) {
            EntityType.THREAT_ACTOR -> resolve({ repository.getThreatActor(it) }, { repository.getThreatActors(it) },
                { a -> same(a.id) || same(a.name) || a.aliases.any(::same) }, { it.toProfile() })
            EntityType.MALWARE -> resolve({ repository.getMalwareDetail(it) }, { repository.getMalware(it) },
                { m -> same(m.id) || same(m.name) || m.aliases.any(::same) }, { it.toProfile() })
            EntityType.CVE -> {
                // The detail route takes the CVE identifier; pivots may carry the row id plus the name.
                val cveId = listOf(key, label).firstOrNull { it.startsWith("CVE-", ignoreCase = true) }
                resolve({ repository.getCveDetail(cveId ?: it) }, { repository.getCves(cveId ?: it) },
                    { c -> same(c.id) || same(c.cveId) }, { it.toProfile() })
            }
            EntityType.TTP -> {
                val techniqueId = listOf(key, label).firstOrNull { TECHNIQUE_ID.matches(it) }
                resolve({ t -> if (techniqueId != null) repository.getTtpByTechnique(techniqueId.uppercase()) else Result.failure(NoSuchElementException(t)) },
                    { repository.getTtps(techniqueId ?: it) },
                    { t -> same(t.id) || same(t.techniqueId) || same(t.techniqueName) }, { it.toProfile() })
            }
            EntityType.TOOL -> resolve({ repository.getTool(it) }, { repository.getTools(it) },
                { t -> same(t.id) || same(t.name) || t.aliases.any(::same) }, { it.toProfile() })
            EntityType.VENDOR -> resolve({ repository.getVendor(it) }, { repository.getVendors(it) },
                { v -> same(v.id) || same(v.name) || v.aliases.any(::same) }, { it.toProfile() })
            EntityType.PRODUCT -> resolve({ repository.getProduct(it) }, { repository.getProducts(it) },
                { p -> same(p.id) || same(p.name) || p.aliases.any(::same) }, { it.toProfile() })
            EntityType.COUNTRY -> resolve({ repository.getCountry(it) }, { repository.getCountries(it) },
                { c -> same(c.id) || same(c.name) || same(c.isoCode) || c.aliases.any(::same) }, { it.toProfile() })
            EntityType.MITIGATION -> resolve({ repository.getMitigation(it) }, { repository.getMitigations(it) },
                { m -> same(m.id) || same(m.name) || same(m.mitreId) }, { it.toProfile() })
            EntityType.CAMPAIGN -> resolve({ repository.getCampaign(it) }, { repository.getCampaigns(it) },
                { c -> same(c.id) || same(c.name) }, { it.toProfile() })
            EntityType.WEAKNESS -> {
                val cweId = listOf(key, label).firstOrNull { it.startsWith("CWE-", ignoreCase = true) }
                resolve({ repository.getCweDetail(cweId ?: it) }, { repository.getCwes(cweId ?: it) },
                    { c -> same(c.id) || same(c.cweId) }, { it.toProfile() })
            }
            EntityType.OBSERVABLE -> resolve({ repository.getObservable(it) }, { repository.getObservables(it) },
                { o -> same(o.id) || same(o.value) }, { it.toProfile() })
            EntityType.RULE -> resolve({ repository.getDetectionRule(it) }, { repository.getDetectionRules(it) },
                { r -> same(r.id) || same(r.title) }, { it.toProfile() })
        }
    }

    // ARTICLES

    fun loadArticles(reset: Boolean = false) {
        val profile = _state.value.profile ?: return
        val section = _state.value.articles
        if (!reset && (!section.hasMore || section.loading)) return
        articlesJob?.cancel()

        if (type == EntityType.CAMPAIGN) {
            // GET /api/entries?campaign_id= is cursor-paged. It used to always fetch page 1 and
            // report the page size as the campaign's article count.
            val cursor = if (reset) null else section.nextCursor
            _state.update { it.copy(articles = it.articles.copy(loading = true, error = null)) }
            articlesJob = viewModelScope.launch {
                repository.getCampaignEntries(campaignId = profile.serverId, cursor = cursor).fold(
                    onSuccess = { page ->
                        _state.update { s ->
                            val items = if (reset) page.items else (s.articles.items + page.items).distinctBy { it.id }
                            val more = page.hasMore && !page.nextCursor.isNullOrBlank() && page.items.isNotEmpty()
                            s.copy(articles = PagedSection(items, page.total, false, true, more, 0, nextCursor = page.nextCursor))
                        }
                    },
                    onFailure = { e ->
                        _state.update { it.copy(articles = it.articles.copy(loading = false, loaded = true, error = ErrorText.describe(e))) }
                    }
                )
            }
            return
        }

        val query = type.articlesQuery(profile.searchName) ?: return
        val offset = if (reset) 0 else section.nextOffset
        _state.update { it.copy(articles = it.articles.copy(loading = true, error = null)) }
        articlesJob = viewModelScope.launch {
            repository.searchEntries(query, offset).fold(
                onSuccess = { page ->
                    _state.update { s ->
                        val items = if (reset) page.items else (s.articles.items + page.items).distinctBy { it.id }
                        s.copy(articles = PagedSection(items, page.total, false, true, page.hasMore, page.nextOffset))
                    }
                },
                onFailure = { e ->
                    _state.update { it.copy(articles = it.articles.copy(loading = false, loaded = true, error = ErrorText.describe(e))) }
                }
            )
        }
    }

    // RELATIONSHIPS (loaded when the tab first opens)

    fun loadRelationships(reset: Boolean = false) {
        val profile = _state.value.profile?.takeUnless { it.placeholder } ?: return
        if (reset || (_state.value.graph == null && !_state.value.graphLoading)) loadGraph(profile)
        val section = _state.value.relationships
        if (section.loading || (!reset && section.loaded && !section.hasMore)) return
        val offset = if (reset || !section.loaded) 0 else section.nextOffset
        _state.update { it.copy(relationships = it.relationships.copy(loading = true, error = null)) }
        viewModelScope.launch {
            repository.getRelationships(type.key, profile.serverId, offset).fold(
                onSuccess = { page ->
                    _state.update { s ->
                        val items = if (offset == 0) page.items else (s.relationships.items + page.items).distinctBy { it.id }
                        s.copy(relationships = PagedSection(items, page.total, false, true, page.hasMore, page.nextOffset))
                    }
                },
                onFailure = { e ->
                    _state.update { it.copy(relationships = it.relationships.copy(loading = false, loaded = true, error = ErrorText.describe(e))) }
                }
            )
        }
    }

    private var graphJob: Job? = null

    fun setGraphWindow(days: Int?) {
        val profile = _state.value.profile?.takeUnless { it.placeholder } ?: return
        if (days == _state.value.graphWindowDays) return
        _state.update { it.copy(graphWindowDays = days) }
        loadGraph(profile)
    }

    private fun loadGraph(profile: EntityProfile) {
        val path = type.timelinePath ?: return
        graphJob?.cancel()
        _state.update { it.copy(graphLoading = true, graphError = null) }
        graphJob = viewModelScope.launch {
            repository.getEntityGraph(path, profile.serverId, _state.value.graphWindowDays).fold(
                onSuccess = { g -> _state.update { it.copy(graph = g, graphLoading = false) } },
                onFailure = { e -> _state.update { it.copy(graphLoading = false, graphError = ErrorText.describe(e)) } }
            )
        }
    }

    // NOTES (shared across the instance)

    // TIMELINE

    private fun updateTimeline(change: (TimelineUiState) -> TimelineUiState) = _state.update { it.copy(timeline = change(it.timeline)) }

    /** Loads the Timeline tab once (or again with [force]): chart, what's new, stories and events, in parallel. */
    fun loadTimeline(force: Boolean = false) {
        val profile = _state.value.profile?.takeUnless { it.placeholder } ?: return
        val path = type.timelinePath ?: return
        val current = _state.value.timeline
        if (current.requested && !force) return
        updateTimeline { it.copy(requested = true, loading = true, eventsError = null) }
        loadMentions(current.window)
        val id = profile.serverId
        viewModelScope.launch {
            val whatsNew = async { repository.getWhatsNew(path, id) }
            val stories = async { repository.getEntityStories(path, id) }
            val events = async { repository.getEntityTimeline(path, id) }
            val eventsResult = events.await()
            // A busy actor has thousands of events; filter and sort them off the main thread.
            val keyEvents = eventsResult.getOrNull()?.let { withContext(Dispatchers.Default) { TimelinePresentation.keyEvents(it) } }
            val whatsNewItems = whatsNew.await().getOrDefault(emptyList())
            val storyItems = stories.await().getOrDefault(emptyList())
            updateTimeline {
                it.copy(
                    loading = false,
                    whatsNew = whatsNewItems,
                    stories = storyItems,
                    events = keyEvents ?: it.events,
                    eventsError = eventsResult.exceptionOrNull()?.let(ErrorText::describe),
                    shownEvents = TimelinePresentation.PAGE
                )
            }
        }
    }

    /** Switches the mentions chart to [window] ("7d", "30d", "90d", "all"). */
    fun setMentionsWindow(window: String) {
        val t = _state.value.timeline
        if (window == t.window && (t.mentions != null || t.mentionsLoading)) return
        loadMentions(window)
    }

    private fun loadMentions(window: String) {
        val profile = _state.value.profile?.takeUnless { it.placeholder } ?: return
        val path = type.timelinePath ?: return
        mentionsJob?.cancel()
        updateTimeline { it.copy(window = window, mentionsLoading = true, mentionsError = null) }
        mentionsJob = viewModelScope.launch {
            repository.getMentionsTimeseries(path, profile.serverId, window).fold(
                onSuccess = { m -> updateTimeline { it.copy(mentions = m, mentionsLoading = false) } },
                onFailure = { e -> updateTimeline { it.copy(mentionsLoading = false, mentionsError = ErrorText.describe(e)) } }
            )
        }
    }

    fun showMoreEvents() = updateTimeline { it.copy(shownEvents = it.shownEvents + TimelinePresentation.PAGE) }

    fun loadNotes(force: Boolean = false) {
        val profile = _state.value.profile?.takeUnless { it.placeholder } ?: return
        if (_state.value.notesLoading || (_state.value.notesLoaded && !force)) return
        _state.update { it.copy(notesLoading = true, notesError = null) }
        viewModelScope.launch {
            repository.getEntityNotes(type.key, profile.serverId).fold(
                onSuccess = { notes -> _state.update { it.copy(notes = notes, notesLoaded = true, notesLoading = false) } },
                onFailure = { e -> _state.update { it.copy(notesLoading = false, notesLoaded = true, notesError = ErrorText.describe(e)) } }
            )
        }
    }

    fun saveNote(existing: EntityNote?, title: String, content: String, onResult: (Boolean) -> Unit) {
        val profile = _state.value.profile?.takeUnless { it.placeholder } ?: return
        val body = content.trim()
        if (body.isEmpty()) return
        val cleanTitle = title.trim().ifEmpty { null }
        viewModelScope.launch {
            val result = if (existing == null) repository.createEntityNote(type.key, profile.serverId, cleanTitle, body)
            else repository.updateEntityNote(existing.id, cleanTitle, body)
            result.fold(
                onSuccess = { saved ->
                    _state.update { s -> s.copy(notes = listOf(saved) + s.notes.filterNot { it.id == saved.id }) }
                    messenger.show(if (existing == null) "Note added" else "Note updated")
                    onResult(true)
                },
                onFailure = {
                    messenger.showError(if (existing == null) "save the note" else "update the note", it)
                    onResult(false)
                }
            )
        }
    }

    fun deleteNote(note: EntityNote) {
        _state.update { it.copy(notes = it.notes.filterNot { n -> n.id == note.id }) }
        viewModelScope.launch {
            repository.deleteEntityNote(note.id).fold(
                onSuccess = { messenger.show("Note deleted") },
                onFailure = {
                    messenger.showError("delete the note", it)
                    loadNotes(force = true)
                }
            )
        }
    }

    // WATCH / MUTE (per user; steers only your own Priority Queue)

    private fun loadWatchMode(profile: EntityProfile) {
        viewModelScope.launch {
            repository.getWatchlist().onSuccess { list ->
                val mode = list.firstOrNull { it.entityType == type.key && it.entityId == profile.serverId }?.mode
                _state.update { it.copy(watchMode = mode) }
            }
        }
    }

    /** [mode] "watch" or "mute"; choosing the current mode again removes it. */
    fun setWatchMode(mode: String) {
        val profile = _state.value.profile?.takeUnless { it.placeholder } ?: return
        val previous = _state.value.watchMode
        val next = if (previous == mode) null else mode
        _state.update { it.copy(watchMode = next, watchBusy = true) }
        viewModelScope.launch {
            repository.setWatchMode(type.key, profile.serverId, next).fold(
                onSuccess = {
                    _state.update { it.copy(watchBusy = false) }
                    messenger.show(
                        when (next) {
                            "watch" -> "Watching ${profile.title}. Its articles get a boost in your Priority Queue."
                            "mute" -> "Muted ${profile.title}. Its articles are hidden from your Priority Queue."
                            else -> if (previous == "mute") "Unmuted ${profile.title}" else "Stopped watching ${profile.title}"
                        }
                    )
                },
                onFailure = {
                    _state.update { s -> s.copy(watchMode = previous, watchBusy = false) }
                    messenger.showError("update the watchlist", it)
                }
            )
        }
    }

    companion object {
        private val TECHNIQUE_ID = Regex("^[Tt]\\d{4}(\\.\\d{3})?$")
    }
}
