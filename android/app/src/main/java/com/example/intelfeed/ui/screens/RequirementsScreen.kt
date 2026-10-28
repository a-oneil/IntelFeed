package com.example.intelfeed.ui.screens

import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.TrackChanges
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.example.intelfeed.LocalSnackbarHostState
import com.example.intelfeed.data.model.Requirement
import com.example.intelfeed.data.model.RequirementMatch
import com.example.intelfeed.data.repository.IntelFeedRepository
import com.example.intelfeed.theme.CyberAmber
import com.example.intelfeed.theme.CyberBlue
import com.example.intelfeed.theme.CyberRed
import com.example.intelfeed.theme.SlateDark900
import com.example.intelfeed.theme.TextMuted
import com.example.intelfeed.theme.TextPrimary
import com.example.intelfeed.theme.TextSecondary
import com.example.intelfeed.theme.ThemeEngine
import com.example.intelfeed.ui.ErrorText

import com.example.intelfeed.util.HtmlText
import com.example.intelfeed.ui.components.CardSurface
import com.example.intelfeed.ui.components.EmptyState
import com.example.intelfeed.ui.components.ErrorState
import com.example.intelfeed.ui.components.InlineLoading
import com.example.intelfeed.ui.components.Pill
import com.example.intelfeed.ui.components.SlowLoadingState
import com.example.intelfeed.util.DateUtils
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.util.Locale

data class RequirementsState(
    val requirements: List<Requirement> = emptyList(),
    val loading: Boolean = true,
    val refreshing: Boolean = false,
    val error: String? = null,
    val expanded: Set<String> = emptySet(),
    val matches: Map<String, List<RequirementMatch>> = emptyMap(),
    val matchesLoading: Set<String> = emptySet(),
    val matchesError: Map<String, String> = emptyMap()
)

/**
 * The server's intelligence requirements (GET /api/requirements): the web's keyword matching.
 * Read-only here; a requirement can be created from the drawer's "Track a keyword".
 */
class RequirementsViewModel(private val repository: IntelFeedRepository) : ViewModel() {
    private val _state = MutableStateFlow(RequirementsState())
    val state: StateFlow<RequirementsState> = _state.asStateFlow()

    init { load() }

    fun load(refresh: Boolean = false) {
        _state.update { it.copy(loading = !refresh, refreshing = refresh, error = null) }
        viewModelScope.launch {
            repository.getRequirements().fold(
                onSuccess = { list ->
                    _state.update { it.copy(requirements = sortRequirements(list), loading = false, refreshing = false, matches = if (refresh) emptyMap() else it.matches) }
                    // Reload the matches of anything still open after a refresh.
                    if (refresh) _state.value.expanded.forEach { loadMatches(it) }
                },
                onFailure = { e -> _state.update { it.copy(loading = false, refreshing = false, error = ErrorText.describe(e)) } }
            )
        }
    }

    fun toggle(id: String) {
        val open = id in _state.value.expanded
        _state.update { it.copy(expanded = if (open) it.expanded - id else it.expanded + id) }
        if (!open && !_state.value.matches.containsKey(id)) loadMatches(id)
    }

    private fun loadMatches(id: String) {
        if (id in _state.value.matchesLoading) return
        _state.update { it.copy(matchesLoading = it.matchesLoading + id, matchesError = it.matchesError - id) }
        viewModelScope.launch {
            repository.getRequirementMatches(id).fold(
                onSuccess = { page -> _state.update { it.copy(matches = it.matches + (id to page.items), matchesLoading = it.matchesLoading - id) } },
                onFailure = { e -> _state.update { it.copy(matchesLoading = it.matchesLoading - id, matchesError = it.matchesError + (id to ErrorText.describe(e))) } }
            )
        }
    }

    companion object {
        private val PRIORITY_ORDER = listOf("critical", "high", "medium", "low")

        /** Active first, then by priority, then by title. */
        fun sortRequirements(list: List<Requirement>): List<Requirement> = list.sortedWith(
            compareBy<Requirement> { if (it.status.equals("active", ignoreCase = true)) 0 else 1 }
                .thenBy { PRIORITY_ORDER.indexOf(it.priority?.lowercase()).let { i -> if (i < 0) 9 else i } }
                .thenBy { it.title.lowercase() }
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RequirementsScreen(
    viewModel: RequirementsViewModel,
    onBack: () -> Unit,
    onOpenEntry: (String, List<String>) -> Unit,
    onSearchKeyword: (String) -> Unit
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    Scaffold(
        topBar = {
            TopAppBar(
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back", tint = TextPrimary) } },
                title = {
                    Column {
                        Text("Intelligence requirements", fontSize = 18.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
                        Text("Shared on your server · every new article is matched against them", fontSize = 12.sp, color = TextMuted)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = SlateDark900)
            )
        },
        snackbarHost = { SnackbarHost(LocalSnackbarHostState.current) },
        containerColor = SlateDark900
    ) { padding ->
        PullToRefreshBox(isRefreshing = state.refreshing, onRefresh = { viewModel.load(refresh = true) }, modifier = Modifier.fillMaxSize().padding(padding)) {
            when {
                state.loading -> SlowLoadingState("Loading requirements…")
                state.error != null && state.requirements.isEmpty() -> ErrorState(state.error!!, onRetry = { viewModel.load() }, modifier = Modifier.fillMaxSize())
                state.requirements.isEmpty() -> EmptyState(Icons.Default.TrackChanges, "No requirements yet", "Requirements are created on the website, or from \"Track a keyword\" in the feeds drawer.")
                else -> LazyColumn(contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.fillMaxSize()) {
                    items(state.requirements, key = { it.id }, contentType = { "requirement_card" }) { req ->
                        RequirementCard(
                            requirement = req,
                            expanded = req.id in state.expanded,
                            matches = state.matches[req.id],
                            matchesLoading = req.id in state.matchesLoading,
                            matchesError = state.matchesError[req.id],
                            onToggle = { viewModel.toggle(req.id) },
                            onOpenEntry = onOpenEntry,
                            onSearchKeyword = onSearchKeyword
                        )
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun RequirementCard(
    requirement: Requirement,
    expanded: Boolean,
    matches: List<RequirementMatch>?,
    matchesLoading: Boolean,
    matchesError: String?,
    onToggle: () -> Unit,
    onOpenEntry: (String, List<String>) -> Unit,
    onSearchKeyword: (String) -> Unit
) {
    val priorityColor = ThemeEngine.severityColor(requirement.priority)
    CardSurface(modifier = Modifier.animateContentSize()) {
        Column(Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth().clip(RoundedCornerShape(8.dp)).clickable(onClickLabel = if (expanded) "Hide matches" else "Show matches", onClick = onToggle)) {
                Column(Modifier.weight(1f)) {
                    Text(HtmlText.toPlainText(requirement.title), fontSize = 15.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
                    Spacer(Modifier.height(4.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        requirement.priority?.let { Pill(it.replaceFirstChar { c -> c.titlecase(Locale.US) }, priorityColor); Spacer(Modifier.width(6.dp)) }
                        requirement.category?.takeIf { it.isNotBlank() }?.let { cat ->
                            Pill(cat.replaceFirstChar { c -> c.titlecase(Locale.US) }, ThemeEngine.pirCategoryColor(cat))
                            Spacer(Modifier.width(6.dp))
                        }
                        val status = requirement.status?.lowercase()
                        if (status != null && status != "active") { Pill(status, TextMuted); Spacer(Modifier.width(6.dp)) }
                        // "latest just now" / "latest 20m ago" / "latest Sep 3"
                        val last = DateUtils.formatRelativeTime(requirement.lastMatchedAt).takeIf { it.isNotBlank() }
                            ?.let { if (it == "Just now" || it == "Yesterday") it.lowercase() else it }
                        val count = String.format(Locale.US, "%,d %s", requirement.matchCount, if (requirement.matchCount == 1) "match" else "matches")
                        Text(
                            listOfNotNull(count, last?.let { "latest $it" }).joinToString(" · "),
                            fontSize = 12.sp, color = TextMuted, maxLines = 1, overflow = TextOverflow.Ellipsis
                        )
                    }
                }
                Icon(if (expanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore, contentDescription = null, tint = TextMuted)
            }

            requirement.description?.takeIf { it.isNotBlank() }?.let {
                Spacer(Modifier.height(6.dp))
                Text(HtmlText.toPlainText(it), fontSize = 13.sp, color = TextSecondary, maxLines = if (expanded) 6 else 2, overflow = TextOverflow.Ellipsis)
            }
            if (requirement.keywords.isNotEmpty()) {
                Spacer(Modifier.height(8.dp))
                val shown = if (expanded) requirement.keywords else requirement.keywords.take(8)
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    shown.forEach { kw ->
                        Pill(kw, CyberAmber, onClick = { onSearchKeyword(kw) })
                    }
                    if (!expanded && requirement.keywords.size > shown.size) Pill("+${requirement.keywords.size - shown.size} more", TextMuted, onClick = onToggle)
                }
            }
            if (expanded) {
                Spacer(Modifier.height(10.dp))
                Text("Recent matches", fontSize = 12.sp, fontWeight = FontWeight.SemiBold, color = TextSecondary)
                when {
                    matchesLoading && matches == null -> InlineLoading()
                    matchesError != null -> Text(matchesError, fontSize = 13.sp, color = CyberAmber)
                    matches.isNullOrEmpty() -> Text("No articles have matched yet.", fontSize = 13.sp, color = TextMuted)
                    else -> {
                        val ids = matches.map { it.entryId }
                        matches.forEach { m ->
                            Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(8.dp)).clickable { onOpenEntry(m.entryId, ids) }.padding(vertical = 8.dp)) {
                                Text(HtmlText.toPlainText(m.entryTitle ?: "Article"), fontSize = 14.sp, color = TextPrimary, maxLines = 2, overflow = TextOverflow.Ellipsis)
                                val why = listOfNotNull(
                                    m.matchType?.let { t -> m.matchedOn?.let { "$t: ${HtmlText.toPlainText(it)}" } },
                                    m.relevance?.let { "$it relevance" },
                                    DateUtils.formatRelativeTime(m.entryPublishedAt ?: m.matchedAt).takeIf { it.isNotBlank() }
                                ).joinToString(" · ")
                                if (why.isNotEmpty()) Text(why, fontSize = 12.sp, color = TextMuted)
                            }
                        }
                    }
                }
            }
        }
    }
}
