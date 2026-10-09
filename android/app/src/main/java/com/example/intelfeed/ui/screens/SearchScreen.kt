package com.example.intelfeed.ui.screens

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ManageSearch
import androidx.compose.material.icons.filled.BookmarkAdd
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Lightbulb
import androidx.compose.material.icons.automirrored.filled.Notes
import androidx.compose.material.icons.filled.SavedSearch
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.intelfeed.data.model.EntityType
import com.example.intelfeed.data.model.FeedSource
import com.example.intelfeed.util.SearchTokens
import com.example.intelfeed.data.model.SearchEntityItem
import com.example.intelfeed.theme.CyberAmber
import com.example.intelfeed.theme.CyberBlue
import com.example.intelfeed.theme.SlateDark600
import com.example.intelfeed.theme.SlateDark700
import com.example.intelfeed.theme.SlateDark800
import com.example.intelfeed.theme.SlateDark900
import com.example.intelfeed.theme.TextMuted
import com.example.intelfeed.theme.TextPrimary
import com.example.intelfeed.theme.TextSecondary
import com.example.intelfeed.ui.IntelFeedUiState
import com.example.intelfeed.ui.IntelFeedViewModel
import com.example.intelfeed.ui.i18n.LocalStrings
import com.example.intelfeed.ui.SearchScope
import com.example.intelfeed.ui.components.CardSurface
import com.example.intelfeed.ui.components.EmptyState
import com.example.intelfeed.ui.components.EntryCard
import com.example.intelfeed.ui.components.ErrorState
import com.example.intelfeed.ui.components.InlineLoading
import com.example.intelfeed.ui.components.Pill
import com.example.intelfeed.ui.components.SectionHeader
import com.example.intelfeed.ui.components.SlowLoadingState
import com.example.intelfeed.ui.components.color
import java.text.NumberFormat
import java.util.Locale

private val EXAMPLES = listOf(
    "threat_actor:APT29" to "Articles about one actor",
    "cve.kev:true cve.epss:>0.5" to "Known-exploited CVEs likely to be attacked",
    "is:unread signal:kev_added" to "Unread articles where a CVE joined KEV",
    "tag:to-rule is:unread" to "Tagged for rule work, not yet read",
    "ransomware date:>=2026-09-01" to "Keyword plus a date range",
    "note:phishing" to "Search analyst notes"
)

private fun fmt(n: Int): String = NumberFormat.getIntegerInstance(Locale.US).format(n)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SearchScreen(uiState: IntelFeedUiState, viewModel: IntelFeedViewModel, modifier: Modifier = Modifier) {
    val focusManager = LocalFocusManager.current
    var showSaveDialog by remember { mutableStateOf(false) }
    var showFilterSheet by remember { mutableStateOf(false) }
    val submit = { q: String -> focusManager.clearFocus(); viewModel.searchUnified(q) }

    if (showSaveDialog) {
        var name by rememberSaveable { mutableStateOf(uiState.submittedQuery.orEmpty()) }
        AlertDialog(
            onDismissRequest = { showSaveDialog = false },
            title = { Text("Save this search") },
            text = {
                Column {
                    Text("Saved searches are yours and also appear in the web app's sidebar.", fontSize = 13.sp, color = TextMuted)
                    Spacer(Modifier.height(12.dp))
                    OutlinedTextField(value = name, onValueChange = { name = it }, label = { Text("Name") }, singleLine = true)
                }
            },
            confirmButton = { TextButton(onClick = { viewModel.saveCurrentSearch(name); showSaveDialog = false }) { Text("Save") } },
            dismissButton = { TextButton(onClick = { showSaveDialog = false }) { Text("Cancel") } }
        )
    }

    if (showFilterSheet) {
        SearchFilterSheet(
            currentQuery = uiState.searchQuery,
            feeds = uiState.feeds,
            onDismiss = { showFilterSheet = false },
            onApply = { newQuery ->
                showFilterSheet = false
                viewModel.setSearchQuery(newQuery)
                submit(newQuery)
            }
        )
    }

    val strings = LocalStrings.current

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(strings.navSearch, fontSize = 18.sp, fontWeight = FontWeight.Bold, color = TextPrimary) },
                actions = {
                    if (uiState.submittedQuery != null && uiState.searchResponse != null) {
                        IconButton(onClick = { showSaveDialog = true }) { Icon(Icons.Default.BookmarkAdd, contentDescription = "Save this search", tint = TextSecondary) }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = SlateDark900)
            )
        },
        containerColor = SlateDark900
    ) { padding ->
        Column(modifier.fillMaxSize().padding(padding)) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                OutlinedTextField(
                    value = uiState.searchQuery,
                    onValueChange = { viewModel.setSearchQuery(it) },
                    modifier = Modifier.weight(1f),
                    placeholder = { Text(strings.searchPlaceholder, color = TextMuted) },
                    leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = TextSecondary) },
                    trailingIcon = if (uiState.searchQuery.isNotEmpty()) {
                        { IconButton(onClick = { viewModel.clearSearch() }) { Icon(Icons.Default.Close, contentDescription = "Clear search", tint = TextMuted) } }
                    } else null,
                    singleLine = true,
                    shape = RoundedCornerShape(10.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = CyberBlue,
                        unfocusedBorderColor = SlateDark700,
                        focusedContainerColor = SlateDark800,
                        unfocusedContainerColor = SlateDark800,
                        focusedTextColor = TextPrimary,
                        unfocusedTextColor = TextPrimary
                    ),
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                    keyboardActions = KeyboardActions(onSearch = { submit(uiState.searchQuery) })
                )
                Spacer(Modifier.width(8.dp))
                val hasFilters = hasActiveFilterTokens(uiState.searchQuery)
                Surface(
                    color = if (hasFilters) CyberBlue.copy(alpha = 0.2f) else SlateDark800,
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier
                        .size(52.dp)
                        .clip(RoundedCornerShape(10.dp))
                        .clickable { showFilterSheet = true }
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Icon(
                            imageVector = Icons.Default.Tune,
                            contentDescription = "Search filters",
                            tint = if (hasFilters) CyberBlue else TextSecondary
                        )
                    }
                }
            }

            // Autocomplete: field values such as threat_actor:Qilin.
            if (uiState.searchSuggestions.isNotEmpty() && uiState.searchQuery != uiState.submittedQuery) {
                Surface(color = SlateDark800, shape = RoundedCornerShape(10.dp), modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp)) {
                    Column {
                        uiState.searchSuggestions.forEachIndexed { i, s ->
                            if (i > 0) HorizontalDivider(color = SlateDark700)
                            Row(
                                modifier = Modifier.fillMaxWidth().clickable { viewModel.applySuggestion(s) }.padding(horizontal = 14.dp, vertical = 12.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(s.text, color = TextPrimary, fontSize = 14.sp, modifier = Modifier.weight(1f))
                                s.field?.let { Text(it.replace('_', ' '), color = TextMuted, fontSize = 12.sp) }
                            }
                        }
                    }
                }
            }

            when {
                uiState.submittedQuery == null -> SearchHome(uiState, viewModel, onRun = submit)
                uiState.searchLoading -> SlowLoadingState("Searching for ${uiState.submittedQuery}…")
                uiState.searchError != null -> ErrorState(uiState.searchError, onRetry = { submit(uiState.submittedQuery) }, modifier = Modifier.fillMaxSize())
                else -> SearchResults(uiState, viewModel, onRun = submit)
            }
        }
    }
}

@OptIn(ExperimentalFoundationApi::class, ExperimentalLayoutApi::class)
@Composable
private fun SearchHome(uiState: IntelFeedUiState, viewModel: IntelFeedViewModel, onRun: (String) -> Unit) {
    var searchToDelete by remember { mutableStateOf<com.example.intelfeed.data.model.SavedSearch?>(null) }
    val strings = LocalStrings.current
    LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp)) {
        if (uiState.recentSearches.isNotEmpty()) {
            item(key = "recent") {
                SectionHeader(strings.searchRecent, trailing = { TextButton(onClick = { viewModel.clearRecentSearches() }) { Text(strings.searchClear) } })
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    uiState.recentSearches.forEach { q -> Pill(q, TextSecondary, leadingIcon = Icons.Default.History, onClick = { onRun(q) }) }
                }
            }
        }
        if (uiState.savedSearches.isNotEmpty()) {
            item(key = "saved-header", contentType = "header") { SectionHeader("Saved searches") }
            items(uiState.savedSearches, key = { "saved:" + it.id }, contentType = { "saved_search" }) { saved ->
                CardSurface(
                    modifier = Modifier
                        .padding(vertical = 4.dp)
                        .clip(RoundedCornerShape(12.dp))
                        .combinedClickable(onClick = { viewModel.openSavedSearch(saved) }, onLongClick = { searchToDelete = saved })
                ) {
                    Row(Modifier.padding(start = 14.dp, end = 4.dp, top = 6.dp, bottom = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.SavedSearch, contentDescription = null, tint = CyberBlue, modifier = Modifier.size(20.dp))
                        Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f)) {
                            Text(saved.label, fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = TextPrimary, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            if (saved.query != saved.label) Text(saved.query, fontSize = 12.sp, color = TextMuted, fontFamily = FontFamily.Monospace, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        }
                        saved.unreadCount?.takeIf { it > 0 }?.let { Pill("${fmt(it)} unread", CyberBlue) }
                        IconButton(onClick = { searchToDelete = saved }) {
                            Icon(Icons.Default.Close, contentDescription = "Delete saved search ${saved.label}", tint = TextMuted, modifier = Modifier.size(18.dp))
                        }
                    }
                }
            }
        }
        item(key = "tips") {
            SectionHeader("Try a filter")
            Text("Search understands fields. Tap an example to run it.", fontSize = 13.sp, color = TextMuted)
            Spacer(Modifier.height(8.dp))
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                EXAMPLES.forEach { (query, what) ->
                    CardSurface(modifier = Modifier.clip(RoundedCornerShape(12.dp)).clickable { onRun(query) }) {
                        Row(Modifier.padding(horizontal = 14.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.Lightbulb, contentDescription = null, tint = CyberAmber, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(12.dp))
                            Column {
                                Text(query, fontFamily = FontFamily.Monospace, fontSize = 13.sp, color = TextPrimary)
                                Text(what, fontSize = 12.sp, color = TextMuted)
                            }
                        }
                    }
                }
            }
        }
    }
    searchToDelete?.let { saved ->
        AlertDialog(
            onDismissRequest = { searchToDelete = null },
            title = { Text("Delete saved search?") },
            text = { Text("\"${saved.label}\" is removed here and in the web app.") },
            confirmButton = { TextButton(onClick = { viewModel.deleteSavedSearch(saved); searchToDelete = null }) { Text("Delete") } },
            dismissButton = { TextButton(onClick = { searchToDelete = null }) { Text("Cancel") } }
        )
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun SearchResults(uiState: IntelFeedUiState, viewModel: IntelFeedViewModel, onRun: (String) -> Unit) {
    val response = uiState.searchResponse ?: return
    val listState = rememberLazyListState()
    val entityTotal = response.entities.counts.values.sum().takeIf { it > 0 } ?: response.entities.items.size
    val articleTotal = uiState.searchEntriesTotal
    val scope = uiState.searchScope

    val nearEnd by remember {
        derivedStateOf {
            val total = listState.layoutInfo.totalItemsCount
            val last = listState.layoutInfo.visibleItemsInfo.lastOrNull()?.index ?: 0
            total > 0 && last >= total - 3
        }
    }
    LaunchedEffect(nearEnd, uiState.searchEntries.size, scope) {
        if (nearEnd && scope != SearchScope.ENTITIES && uiState.searchHasMore) viewModel.loadMoreSearchResults()
    }
    // Only for a new query: the results are re-created when you come back from an article, and
    // scrolling to the top then lost your place.
    var scrolledForQuery by rememberSaveable { mutableStateOf(uiState.submittedQuery) }
    LaunchedEffect(uiState.submittedQuery) {
        if (uiState.submittedQuery != scrolledForQuery) {
            scrolledForQuery = uiState.submittedQuery
            listState.scrollToItem(0)
        }
    }

    val entityGroups = remember(response.entities.items) {
        response.entities.items.groupBy { it.displayType.lowercase() }.entries.sortedWith(
            compareByDescending<Map.Entry<String, List<SearchEntityItem>>> { e -> e.value.any { it.matchKind == "direct" } }
                .thenBy { e -> TYPE_ORDER.indexOf(e.key).let { if (it < 0) 99 else it } }
        )
    }

    LazyColumn(
        state = listState,
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(start = 16.dp, end = 16.dp, bottom = 24.dp)
    ) {
        item(key = "meta", contentType = "meta") {
            Column {
                response.didYouMean?.let { suggestion ->
                    Surface(color = CyberAmber.copy(alpha = 0.12f), shape = RoundedCornerShape(10.dp), modifier = Modifier.fillMaxWidth().padding(top = 6.dp).clip(RoundedCornerShape(10.dp)).clickable { onRun(suggestion) }) {
                        Text("Did you mean  $suggestion ?", color = CyberAmber, fontSize = 14.sp, modifier = Modifier.padding(12.dp))
                    }
                }
                if (response.parsedFilters.isNotEmpty()) {
                    Spacer(Modifier.height(8.dp))
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        response.parsedFilters.forEach { f ->
                            Pill((if (f.negated) "NOT " else "") + "${f.field.replace('_', ' ')}: ${f.value}", CyberBlue)
                        }
                    }
                }
                if (response.unknownFields.isNotEmpty()) {
                    Text("Not a search field, searched as text: " + response.unknownFields.joinToString(", "), fontSize = 12.sp, color = TextMuted, modifier = Modifier.padding(top = 6.dp))
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(vertical = 8.dp)) {
                    ScopeChip("Everything", scope == SearchScope.EVERYTHING) { viewModel.setSearchScope(SearchScope.EVERYTHING) }
                    ScopeChip("Articles · ${fmt(articleTotal)}", scope == SearchScope.ARTICLES) { viewModel.setSearchScope(SearchScope.ARTICLES) }
                    ScopeChip("Entities · ${fmt(entityTotal)}", scope == SearchScope.ENTITIES) { viewModel.setSearchScope(SearchScope.ENTITIES) }
                }
            }
        }

        if (articleTotal == 0 && response.entities.items.isEmpty()) {
            item(key = "none", contentType = "empty") {
                EmptyState(
                    Icons.AutoMirrored.Filled.ManageSearch,
                    "No results",
                    "Try fewer words, a different spelling, or a field such as threat_actor:, cve: or malware:."
                )
            }
            return@LazyColumn
        }

        if (scope != SearchScope.ARTICLES) entityResults(entityGroups, response.entities.counts, compact = scope == SearchScope.EVERYTHING, viewModel, onShowAll = { viewModel.setSearchScope(SearchScope.ENTITIES) })

        if (scope != SearchScope.ENTITIES && uiState.searchEntries.isNotEmpty()) {
            item(key = "articles-header", contentType = "header") { SectionHeader("Articles · ${fmt(articleTotal)}") }
            val ids = uiState.searchEntries.map { it.id }
            items(uiState.searchEntries, key = { "e:" + it.id }, contentType = { "search_entry" }) { entry ->
                EntryCard(
                    entry = entry,
                    intel = uiState.intelCounts[entry.id],
                    onTagClick = { tag -> viewModel.searchTag(tag) },
                    onClick = { viewModel.openEntry(entry.id, ids) },
                    onToggleStar = { viewModel.toggleStar(entry) },
                    onToggleBookmark = { viewModel.toggleBookmark(entry) },
                    modifier = Modifier.padding(vertical = 5.dp)
                )
            }
            if (uiState.searchLoadingMore) item(key = "more", contentType = "loading") { InlineLoading() }
        }
    }
}

@Composable
private fun ScopeChip(label: String, selected: Boolean, onClick: () -> Unit) {
    FilterChip(
        selected = selected,
        onClick = onClick,
        label = { Text(label, fontSize = 13.sp) },
        colors = FilterChipDefaults.filterChipColors(
            selectedContainerColor = CyberBlue,
            selectedLabelColor = SlateDark900,
            containerColor = SlateDark800,
            labelColor = TextSecondary
        ),
        border = FilterChipDefaults.filterChipBorder(enabled = true, selected = selected, borderColor = SlateDark600, selectedBorderColor = CyberBlue)
    )
}

private val TYPE_ORDER = listOf("threat_actor", "malware", "cve", "ttp", "tool", "vendor", "product", "country", "campaign", "rule", "detection_rule", "mitigation", "note")

private fun typeTitle(type: String): String = EntityType.fromKey(type)?.pluralLabel ?: when (type) {
    "note" -> "Notes"
    else -> type.replace('_', ' ').replaceFirstChar { it.titlecase(Locale.US) } + "s"
}

private fun LazyListScope.entityResults(
    groups: List<Map.Entry<String, List<SearchEntityItem>>>,
    counts: Map<String, Int>,
    compact: Boolean,
    viewModel: IntelFeedViewModel,
    onShowAll: () -> Unit
) {
    if (groups.isEmpty()) return
    groups.forEach { (type, list) ->
        val total = counts[type] ?: list.size
        val shown = if (compact) list.sortedByDescending { it.matchKind == "direct" }.take(4) else list
        item(key = "g:$type", contentType = "entity_header") {
            SectionHeader("${typeTitle(type)} · ${fmt(total)}", trailing = if (compact && total > shown.size) {
                { TextButton(onClick = onShowAll) { Text("Show more") } }
            } else null)
        }
        items(shown, key = { "ent:$type:${it.id}" }, contentType = { "search_entity" }) { entity -> SearchEntityRow(entity, viewModel) }
        if (!compact && total > list.size) {
            item(key = "g-more:$type", contentType = "entity_more") {
                Text("Showing ${list.size} of ${fmt(total)}. Narrow the search to see others.", fontSize = 12.sp, color = TextMuted, modifier = Modifier.padding(vertical = 4.dp))
            }
        }
    }
}

@Composable
private fun SearchEntityRow(entity: SearchEntityItem, viewModel: IntelFeedViewModel) {
    val type = EntityType.fromKey(entity.displayType)
    val color = type?.color() ?: if (entity.isNote) CyberAmber else CyberBlue
    CardSurface(
        modifier = Modifier.padding(vertical = 4.dp).clip(RoundedCornerShape(12.dp)).clickable {
            when {
                entity.isNote && entity.entryId != null -> viewModel.openEntry(entity.entryId)
                entity.isNote && entity.entityId != null && entity.entityType != null ->
                    viewModel.openEntity(entity.entityType, entity.entityId, entity.entityName)
                else -> viewModel.openEntity(entity.displayType, entity.id, entity.displayName)
            }
        }
    ) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            if (entity.isNote) {
                Icon(Icons.AutoMirrored.Filled.Notes, contentDescription = null, tint = color, modifier = Modifier.size(20.dp))
                Spacer(Modifier.width(10.dp))
            }
            Column(Modifier.weight(1f)) {
                Text(entity.displayName, fontSize = 15.sp, fontWeight = FontWeight.SemiBold, color = if (entity.isNote) TextPrimary else color, maxLines = 1, overflow = TextOverflow.Ellipsis)
                val sub = when {
                    entity.isNote && entity.entryTitle != null -> "On: ${entity.entryTitle}"
                    entity.isNote && entity.entityName != null -> "On: ${entity.entityName}"
                    entity.aliases.isNotEmpty() -> "aka " + entity.aliases.take(3).joinToString(", ")
                    else -> null
                }
                sub?.let { Text(it, fontSize = 12.sp, color = TextSecondary, maxLines = 1, overflow = TextOverflow.Ellipsis) }
                entity.description?.takeIf { it.isNotBlank() }?.let {
                    Text(it, fontSize = 12.sp, color = TextMuted, maxLines = 2, overflow = TextOverflow.Ellipsis)
                }
            }
            if (entity.matchKind == "mention") {
                Spacer(Modifier.width(8.dp))
                Text("mentions", fontSize = 11.sp, color = TextMuted)
            }
        }
    }
}

private val FILTER_PATTERNS = listOf(
    Regex("""date:>=\S+"""),
    Regex("""is:unread\b"""),
    Regex("""is:read\b"""),
    Regex("""is:starred\b"""),
    Regex("""is:bookmarked\b"""),
    Regex("""signal:kev_added\b"""),
    Regex("""cve\.epss:>0\.5\b"""),
    Regex("""(?<![\w.\-])is:noted\b""")
)

// Fields the sheet edits as lists of values (feeds, tags) or a single choice (sort).
private val SHEET_FIELDS = listOf("feed", "tag", "sort")

private fun hasActiveFilterTokens(query: String): Boolean {
    return FILTER_PATTERNS.any { it.containsMatchIn(query) } || SHEET_FIELDS.any { SearchTokens.values(query, it).isNotEmpty() }
}

/** The sheet's sort choices; [token] null = the server's default (relevance). */
private enum class SortChoice(val label: String, val token: String?) {
    RELEVANCE("Best match", null),
    NEWEST("Newest", "newest"),
    OLDEST("Oldest", "oldest"),
    // sort:radar orders by priority score; the server ignores free-text words with it.
    RADAR("Highest score", "radar")
}

private fun stripFilterTokens(query: String): String {
    var result = query
    for (pat in FILTER_PATTERNS) {
        result = pat.replace(result, "")
    }
    return result.trim().replace(Regex("""\s+"""), " ")
}

private enum class TimeRange(val label: String, val days: Int?) {
    ANY("Any time", null),
    DAY("Past 24h", 1),
    WEEK("Past 7d", 7),
    MONTH("Past 30d", 30),
    // A date:>= filter that isn't one of the presets (typed by hand or from a saved search). Kept as is.
    CUSTOM("Custom", null)
}

private val DATE_FILTER = Regex("""date:>=(\S+)""")

/** Local date [days] before today as yyyy-MM-dd. Calendar rather than java.time, which needs Android 8 (minSdk is 24). */
private fun daysAgo(days: Int): String {
    val cal = java.util.Calendar.getInstance().apply { add(java.util.Calendar.DAY_OF_YEAR, -days) }
    return java.text.SimpleDateFormat("yyyy-MM-dd", Locale.US).format(cal.time)
}

/** Which preset the query's date:>= filter matches, CUSTOM for another date, ANY when there's none. */
private fun timeRangeOf(query: String): Pair<TimeRange, String?> {
    val date = DATE_FILTER.find(query)?.groupValues?.get(1) ?: return TimeRange.ANY to null
    val preset = listOf(TimeRange.DAY, TimeRange.WEEK, TimeRange.MONTH).firstOrNull { daysAgo(it.days!!) == date }
    return (preset ?: TimeRange.CUSTOM) to date
}

private enum class ReadFilter(val label: String, val token: String?) {
    ALL("All", null),
    UNREAD("Unread only", "is:unread"),
    READ("Read only", "is:read")
}

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
private fun SearchFilterSheet(
    currentQuery: String,
    feeds: List<FeedSource>,
    onDismiss: () -> Unit,
    onApply: (String) -> Unit
) {
    // It used to read any date filter as "Past 7d", so Apply replaced a 1-day or custom range.
    val (initialTime, existingDate) = remember(currentQuery) { timeRangeOf(currentQuery) }
    var selectedTime by remember { mutableStateOf(initialTime) }
    var selectedRead by remember {
        mutableStateOf(
            when {
                currentQuery.contains("is:unread") -> ReadFilter.UNREAD
                currentQuery.contains("is:read") -> ReadFilter.READ
                else -> ReadFilter.ALL
            }
        )
    }
    var starred by remember { mutableStateOf(currentQuery.contains("is:starred")) }
    var bookmarked by remember { mutableStateOf(currentQuery.contains("is:bookmarked")) }
    var kevAdded by remember { mutableStateOf(currentQuery.contains("signal:kev_added")) }
    var highEpss by remember { mutableStateOf(currentQuery.contains("cve.epss:>0.5")) }
    var hasNotes by remember { mutableStateOf(Regex("""(?<![\w.\-])is:noted\b""").containsMatchIn(currentQuery)) }
    // A sort the sheet doesn't offer (typed by hand) is kept as it is.
    val existingSort = remember(currentQuery) { SearchTokens.values(currentQuery, "sort").firstOrNull() }
    var sortChoice by remember { mutableStateOf(SortChoice.entries.firstOrNull { it.token != null && it.token == existingSort?.lowercase() } ?: SortChoice.RELEVANCE) }
    val customSort = existingSort?.takeIf { s -> SortChoice.entries.none { it.token == s.lowercase() } }
    var keepCustomSort by remember { mutableStateOf(customSort != null) }
    val keptSort = customSort?.takeIf { keepCustomSort }
    var selectedFeeds by remember { mutableStateOf(SearchTokens.values(currentQuery, "feed")) }
    var feedInput by remember { mutableStateOf("") }
    var tagsText by remember { mutableStateOf(SearchTokens.values(currentQuery, "tag").joinToString(", ")) }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        containerColor = SlateDark800,
        dragHandle = {
            Surface(
                modifier = Modifier.padding(vertical = 10.dp),
                color = SlateDark600,
                shape = RoundedCornerShape(2.dp)
            ) {
                Box(Modifier.size(width = 36.dp, height = 4.dp))
            }
        }
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 8.dp)
                .verticalScroll(rememberScrollState())
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text("Search Filters", fontSize = 18.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
                TextButton(onClick = {
                    selectedTime = TimeRange.ANY
                    selectedRead = ReadFilter.ALL
                    starred = false
                    bookmarked = false
                    kevAdded = false
                    highEpss = false
                    hasNotes = false
                    sortChoice = SortChoice.RELEVANCE
                    keepCustomSort = false
                    selectedFeeds = emptyList()
                    tagsText = ""
                }) {
                    Text("Reset", color = CyberAmber)
                }
            }

            Spacer(Modifier.height(8.dp))
            Text("Time Window", fontSize = 13.sp, fontWeight = FontWeight.SemiBold, color = TextSecondary)
            Spacer(Modifier.height(6.dp))
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                TimeRange.entries.filter { it != TimeRange.CUSTOM || existingDate != null && initialTime == TimeRange.CUSTOM }.forEach { t ->
                    FilterChip(
                        selected = selectedTime == t,
                        onClick = { selectedTime = t },
                        label = { Text(if (t == TimeRange.CUSTOM) "Since $existingDate" else t.label) },
                        colors = FilterChipDefaults.filterChipColors(
                            selectedContainerColor = CyberBlue,
                            selectedLabelColor = SlateDark900,
                            containerColor = SlateDark700,
                            labelColor = TextSecondary
                        ),
                        border = FilterChipDefaults.filterChipBorder(
                            enabled = true,
                            selected = selectedTime == t,
                            borderColor = SlateDark600,
                            selectedBorderColor = CyberBlue
                        )
                    )
                }
            }

            Spacer(Modifier.height(14.dp))
            Text("Read Status", fontSize = 13.sp, fontWeight = FontWeight.SemiBold, color = TextSecondary)
            Spacer(Modifier.height(6.dp))
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                ReadFilter.entries.forEach { r ->
                    FilterChip(
                        selected = selectedRead == r,
                        onClick = { selectedRead = r },
                        label = { Text(r.label) },
                        colors = FilterChipDefaults.filterChipColors(
                            selectedContainerColor = CyberBlue,
                            selectedLabelColor = SlateDark900,
                            containerColor = SlateDark700,
                            labelColor = TextSecondary
                        ),
                        border = FilterChipDefaults.filterChipBorder(
                            enabled = true,
                            selected = selectedRead == r,
                            borderColor = SlateDark600,
                            selectedBorderColor = CyberBlue
                        )
                    )
                }
            }

            Spacer(Modifier.height(14.dp))
            Text("Flags", fontSize = 13.sp, fontWeight = FontWeight.SemiBold, color = TextSecondary)
            Spacer(Modifier.height(6.dp))
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                FilterChip(
                    selected = starred,
                    onClick = { starred = !starred },
                    label = { Text("Starred") },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = CyberAmber,
                        selectedLabelColor = SlateDark900,
                        containerColor = SlateDark700,
                        labelColor = TextSecondary
                    ),
                    border = FilterChipDefaults.filterChipBorder(
                        enabled = true,
                        selected = starred,
                        borderColor = SlateDark600,
                        selectedBorderColor = CyberAmber
                    )
                )
                FilterChip(
                    selected = bookmarked,
                    onClick = { bookmarked = !bookmarked },
                    label = { Text("Bookmarked") },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = CyberBlue,
                        selectedLabelColor = SlateDark900,
                        containerColor = SlateDark700,
                        labelColor = TextSecondary
                    ),
                    border = FilterChipDefaults.filterChipBorder(
                        enabled = true,
                        selected = bookmarked,
                        borderColor = SlateDark600,
                        selectedBorderColor = CyberBlue
                    )
                )
            }

            Spacer(Modifier.height(14.dp))
            Text("Signals & Severity", fontSize = 13.sp, fontWeight = FontWeight.SemiBold, color = TextSecondary)
            Spacer(Modifier.height(6.dp))
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                FilterChip(
                    selected = kevAdded,
                    onClick = { kevAdded = !kevAdded },
                    label = { Text("KEV Added") },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = CyberBlue,
                        selectedLabelColor = SlateDark900,
                        containerColor = SlateDark700,
                        labelColor = TextSecondary
                    ),
                    border = FilterChipDefaults.filterChipBorder(
                        enabled = true,
                        selected = kevAdded,
                        borderColor = SlateDark600,
                        selectedBorderColor = CyberBlue
                    )
                )
                FilterChip(
                    selected = highEpss,
                    onClick = { highEpss = !highEpss },
                    label = { Text("High EPSS (>0.5)") },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = CyberBlue,
                        selectedLabelColor = SlateDark900,
                        containerColor = SlateDark700,
                        labelColor = TextSecondary
                    ),
                    border = FilterChipDefaults.filterChipBorder(
                        enabled = true,
                        selected = highEpss,
                        borderColor = SlateDark600,
                        selectedBorderColor = CyberBlue
                    )
                )
            }

            Spacer(Modifier.height(14.dp))
            Text("Notes", fontSize = 13.sp, fontWeight = FontWeight.SemiBold, color = TextSecondary)
            Spacer(Modifier.height(6.dp))
            FilterChip(
                selected = hasNotes,
                onClick = { hasNotes = !hasNotes },
                label = { Text("Has analyst notes") },
                colors = FilterChipDefaults.filterChipColors(selectedContainerColor = CyberBlue, selectedLabelColor = SlateDark900, containerColor = SlateDark700, labelColor = TextSecondary),
                border = FilterChipDefaults.filterChipBorder(enabled = true, selected = hasNotes, borderColor = SlateDark600, selectedBorderColor = CyberBlue)
            )

            Spacer(Modifier.height(14.dp))
            Text("Sort", fontSize = 13.sp, fontWeight = FontWeight.SemiBold, color = TextSecondary)
            Spacer(Modifier.height(6.dp))
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                SortChoice.entries.forEach { choice ->
                    FilterChip(
                        selected = sortChoice == choice && keptSort == null,
                        onClick = { sortChoice = choice; keepCustomSort = false },
                        label = { Text(choice.label) },
                        colors = FilterChipDefaults.filterChipColors(selectedContainerColor = CyberBlue, selectedLabelColor = SlateDark900, containerColor = SlateDark700, labelColor = TextSecondary),
                        border = FilterChipDefaults.filterChipBorder(enabled = true, selected = sortChoice == choice && keptSort == null, borderColor = SlateDark600, selectedBorderColor = CyberBlue)
                    )
                }
            }
            if (sortChoice == SortChoice.RADAR) {
                Text("Orders by priority score; keywords in the query are ignored with this sort.", fontSize = 11.sp, color = TextMuted, modifier = Modifier.padding(top = 4.dp))
            }
            keptSort?.let { Text("Keeping sort:$it from your query.", fontSize = 11.sp, color = TextMuted, modifier = Modifier.padding(top = 4.dp)) }

            Spacer(Modifier.height(14.dp))
            Text("Feeds", fontSize = 13.sp, fontWeight = FontWeight.SemiBold, color = TextSecondary)
            Spacer(Modifier.height(6.dp))
            if (selectedFeeds.isNotEmpty()) {
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    selectedFeeds.forEach { name -> Pill("$name  ✕", CyberBlue, onClick = { selectedFeeds = selectedFeeds - name }) }
                }
                Spacer(Modifier.height(6.dp))
            }
            OutlinedTextField(
                value = feedInput,
                onValueChange = { feedInput = it },
                placeholder = { Text("Add a feed", color = TextMuted) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            val feedMatches = remember(feedInput, feeds, selectedFeeds) {
                if (feedInput.isBlank()) emptyList()
                else feeds.map { it.displayTitle }.distinct()
                    .filter { it.contains(feedInput.trim(), ignoreCase = true) && it !in selectedFeeds }
                    .sortedBy { it.lowercase() }.take(5)
            }
            feedMatches.forEach { name ->
                Text(
                    name,
                    color = TextPrimary,
                    fontSize = 14.sp,
                    modifier = Modifier.fillMaxWidth().clickable { selectedFeeds = selectedFeeds + name; feedInput = "" }.padding(vertical = 8.dp, horizontal = 4.dp)
                )
            }

            Spacer(Modifier.height(14.dp))
            Text("Tags", fontSize = 13.sp, fontWeight = FontWeight.SemiBold, color = TextSecondary)
            Spacer(Modifier.height(6.dp))
            OutlinedTextField(
                value = tagsText,
                onValueChange = { tagsText = it },
                placeholder = { Text("e.g. to-rule, morning-brief", color = TextMuted) },
                supportingText = { Text("Separate several tags with commas; an article needs all of them.") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(Modifier.height(24.dp))
            Button(
                onClick = {
                    val tokens = mutableListOf<String>()
                    when (selectedTime) {
                        TimeRange.DAY, TimeRange.WEEK, TimeRange.MONTH -> tokens.add("date:>=${daysAgo(selectedTime.days!!)}")
                        TimeRange.CUSTOM -> existingDate?.let { tokens.add("date:>=$it") }
                        TimeRange.ANY -> Unit
                    }
                    selectedRead.token?.let { tokens.add(it) }
                    if (starred) tokens.add("is:starred")
                    if (bookmarked) tokens.add("is:bookmarked")
                    if (kevAdded) tokens.add("signal:kev_added")
                    if (highEpss) tokens.add("cve.epss:>0.5")
                    if (hasNotes) tokens.add("is:noted")
                    when {
                        keptSort != null -> tokens.add(SearchTokens.token("sort", keptSort))
                        sortChoice.token != null -> tokens.add("sort:${sortChoice.token}")
                    }
                    selectedFeeds.forEach { tokens.add(SearchTokens.token("feed", it)) }
                    tagsText.split(',').map { it.trim().removePrefix("#") }.filter { it.isNotEmpty() }.distinct()
                        .forEach { tokens.add(SearchTokens.token("tag", it)) }

                    val clean = SHEET_FIELDS.fold(stripFilterTokens(currentQuery)) { q, field -> SearchTokens.remove(q, field) }
                    val result = (listOf(SearchTokens.closeOpenQuote(clean)) + tokens).filter { it.isNotBlank() }.joinToString(" ")
                    onApply(result)
                },
                modifier = Modifier.fillMaxWidth().height(48.dp),
                shape = RoundedCornerShape(10.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = CyberBlue,
                    contentColor = SlateDark900
                )
            ) {
                Text("Apply Filters", fontWeight = FontWeight.Bold, fontSize = 15.sp)
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}
