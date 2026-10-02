package com.example.intelfeed.ui.workbench

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.intelfeed.data.model.RansomwareDisclosure
import com.example.intelfeed.data.model.RansomwareStats
import com.example.intelfeed.data.repository.IntelFeedRepository
import com.example.intelfeed.ui.ErrorText
import com.example.intelfeed.ui.UiMessenger
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/** The web tracker's two views. */
enum class RansomwareView(val label: String) { LEAK_WATCH("Leak Watch"), LANDSCAPE("Landscape") }

/** Leak Watch filters, as the web's (days 3650 = all time). */
data class RansomwareFilters(
    val days: Int = 7,
    val q: String = "",
    val watchedOnly: Boolean = false,
    val groups: List<String> = emptyList(),
    val sectors: List<String> = emptyList(),
    val countries: List<String> = emptyList(),
    // "recent", "group" or "sector".
    val sort: String = "recent"
) {
    val facetCount: Int get() = groups.size + sectors.size + countries.size
    // The web asks for stats over the same window, capped at a year.
    val statsDays: Int get() = if (days >= ALL_DAYS) 365 else days

    companion object { const val ALL_DAYS = 3650 }
}

data class RansomwareState(
    val view: RansomwareView = RansomwareView.LEAK_WATCH,
    val filters: RansomwareFilters = RansomwareFilters(),
    val items: List<RansomwareDisclosure> = emptyList(),
    val total: Int = 0,
    val hasMore: Boolean = false,
    val loading: Boolean = true,
    val loadingMore: Boolean = false,
    val error: String? = null,
    // Stats for Leak Watch's cards and filter facets.
    val stats: RansomwareStats? = null,
    val landscapeDays: Int = 90,
    val landscape: RansomwareStats? = null,
    val landscapeLoading: Boolean = false,
    val landscapeError: String? = null,
    // Disclosures whose watch star is being changed.
    val watchBusy: Set<String> = emptySet()
)

class RansomwareViewModel(
    private val repository: IntelFeedRepository,
    private val messenger: UiMessenger
) : ViewModel() {
    private val _state = MutableStateFlow(RansomwareState())
    val state: StateFlow<RansomwareState> = _state.asStateFlow()

    private var listJob: Job? = null
    private var statsJob: Job? = null
    private var landscapeJob: Job? = null
    private var statsDaysLoaded: Int? = null
    private var started = false

    /** Loads the first time the tab is shown (the ViewModel lives as long as the Workbench). */
    fun ensureLoaded() {
        if (started) return
        started = true
        reloadList()
        loadStats()
    }

    fun refresh() {
        statsDaysLoaded = null
        reloadList()
        loadStats()
        if (_state.value.view == RansomwareView.LANDSCAPE) loadLandscape()
    }

    fun setView(view: RansomwareView) {
        _state.update { it.copy(view = view) }
        if (view == RansomwareView.LANDSCAPE && _state.value.landscape == null) loadLandscape()
    }

    fun updateFilters(change: (RansomwareFilters) -> RansomwareFilters, debounce: Boolean = false) {
        _state.update { it.copy(filters = change(it.filters)) }
        reloadList(debounce)
        loadStats()
    }

    fun toggleFacet(kind: String, value: String) = updateFilters({ f ->
        fun List<String>.flip() = if (value in this) this - value else this + value
        when (kind) {
            "group" -> f.copy(groups = f.groups.flip())
            "sector" -> f.copy(sectors = f.sectors.flip())
            else -> f.copy(countries = f.countries.flip())
        }
    })

    private fun reloadList(debounce: Boolean = false) {
        listJob?.cancel()
        _state.update { it.copy(loading = true, error = null) }
        listJob = viewModelScope.launch {
            if (debounce) delay(300)
            val f = _state.value.filters
            repository.getRansomwareDisclosures(0, f.sort, f.groups, f.sectors, f.countries, f.watchedOnly, f.days.takeIf { it < RansomwareFilters.ALL_DAYS }, f.q).fold(
                onSuccess = { page -> _state.update { it.copy(loading = false, items = page.items, total = page.total, hasMore = page.hasMore) } },
                onFailure = { e -> _state.update { it.copy(loading = false, error = ErrorText.describe(e)) } }
            )
        }
    }

    fun loadMore() {
        val s = _state.value
        if (!s.hasMore || s.loadingMore || s.loading) return
        _state.update { it.copy(loadingMore = true) }
        listJob = viewModelScope.launch {
            val f = s.filters
            repository.getRansomwareDisclosures(s.items.size, f.sort, f.groups, f.sectors, f.countries, f.watchedOnly, f.days.takeIf { it < RansomwareFilters.ALL_DAYS }, f.q).fold(
                onSuccess = { page ->
                    _state.update { it.copy(loadingMore = false, items = (it.items + page.items).distinctBy { d -> d.id }, total = page.total, hasMore = page.hasMore) }
                },
                onFailure = { e ->
                    _state.update { it.copy(loadingMore = false) }
                    messenger.showError("load more disclosures", e)
                }
            )
        }
    }

    private fun loadStats() {
        val days = _state.value.filters.statsDays
        if (days == statsDaysLoaded) return
        statsDaysLoaded = days
        statsJob?.cancel()
        statsJob = viewModelScope.launch {
            repository.getRansomwareStats(days).onSuccess { st -> _state.update { it.copy(stats = st) } }
                .onFailure { statsDaysLoaded = null }
        }
    }

    fun setLandscapeDays(days: Int) {
        if (days == _state.value.landscapeDays && _state.value.landscape != null) return
        _state.update { it.copy(landscapeDays = days) }
        loadLandscape()
    }

    private fun loadLandscape() {
        landscapeJob?.cancel()
        val days = _state.value.landscapeDays
        _state.update { it.copy(landscapeLoading = true, landscapeError = null) }
        landscapeJob = viewModelScope.launch {
            repository.getRansomwareStats(days).fold(
                onSuccess = { st -> _state.update { it.copy(landscapeLoading = false, landscape = st) } },
                onFailure = { e -> _state.update { it.copy(landscapeLoading = false, landscapeError = ErrorText.describe(e)) } }
            )
        }
    }

    /** Watches or unwatches the victim organisation (your own watchlist, entity type ransomware_victim), like the web's star. */
    fun toggleWatch(d: RansomwareDisclosure) {
        val victimId = d.victimId ?: return
        if (d.id in _state.value.watchBusy) return
        val next = !d.watched
        _state.update { s -> s.copy(watchBusy = s.watchBusy + d.id, items = s.items.map { if (it.victimId == victimId) it.copy(watched = next) else it }) }
        viewModelScope.launch {
            repository.setWatchMode("ransomware_victim", victimId, if (next) "watch" else null).fold(
                onSuccess = {
                    _state.update { it.copy(watchBusy = it.watchBusy - d.id) }
                    messenger.show(if (next) "Watching ${d.victimName}" else "Stopped watching ${d.victimName}")
                },
                onFailure = { e ->
                    _state.update { s -> s.copy(watchBusy = s.watchBusy - d.id, items = s.items.map { if (it.victimId == victimId) it.copy(watched = !next) else it }) }
                    messenger.showError("update the watchlist", e)
                }
            )
        }
    }
}
