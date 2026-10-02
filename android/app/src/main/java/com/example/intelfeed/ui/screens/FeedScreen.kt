package com.example.intelfeed.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.GridItemSpan
import androidx.compose.foundation.lazy.grid.LazyGridState
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.lazy.grid.rememberLazyGridState
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.filled.AccountCircle
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Bookmark
import androidx.compose.material.icons.filled.BookmarkBorder
import androidx.compose.material.icons.filled.Campaign
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.DoneAll
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.GridView
import androidx.compose.material.icons.filled.MarkEmailRead
import androidx.compose.material.icons.filled.MarkEmailUnread
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.RssFeed
import androidx.compose.material.icons.filled.SelectAll
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.SwapVert
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material.icons.filled.StarBorder
import androidx.compose.material.icons.filled.VerticalAlignTop
import androidx.compose.material.icons.filled.ViewAgenda
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.SwipeToDismissBox
import androidx.compose.material3.SwipeToDismissBoxValue
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.material3.rememberSwipeToDismissBoxState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.intelfeed.LocalSnackbarHostState
import com.example.intelfeed.data.model.EntryItem
import com.example.intelfeed.data.model.FeedSource
import com.example.intelfeed.data.repository.BulkAction
import com.example.intelfeed.data.repository.FeedFilter
import com.example.intelfeed.theme.CyberAmber
import com.example.intelfeed.theme.CyberBlue
import com.example.intelfeed.theme.CyberGreen
import com.example.intelfeed.theme.CyberPurple
import com.example.intelfeed.theme.SlateDark600
import com.example.intelfeed.theme.SlateDark800
import com.example.intelfeed.theme.SlateDark900
import com.example.intelfeed.theme.TextMuted
import com.example.intelfeed.theme.TextPrimary
import com.example.intelfeed.theme.TextSecondary
import com.example.intelfeed.ui.IntelFeedUiState
import com.example.intelfeed.ui.IntelFeedViewModel
import com.example.intelfeed.ui.i18n.LocalStrings
import com.example.intelfeed.ui.i18n.localizedLabel
import com.example.intelfeed.ui.components.CampaignPickerSheet
import com.example.intelfeed.ui.components.CardAction
import com.example.intelfeed.ui.components.DayHeader
import com.example.intelfeed.ui.components.EmptyState
import com.example.intelfeed.ui.components.EntryCard
import com.example.intelfeed.ui.components.EntryGridCard
import com.example.intelfeed.ui.components.ErrorState
import com.example.intelfeed.ui.components.InlineLoading
import com.example.intelfeed.ui.components.SlowLoadingState
import com.example.intelfeed.ui.components.StoryCard
import com.example.intelfeed.ui.navigation.Route
import com.example.intelfeed.util.DateUtils
import com.example.intelfeed.util.ExternalLinks
import com.example.intelfeed.util.InAppLinks
import com.example.intelfeed.util.ShareSheet
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.first
import androidx.compose.runtime.snapshotFlow
import androidx.compose.runtime.rememberUpdatedState
import java.util.concurrent.atomic.AtomicBoolean
import androidx.compose.foundation.interaction.DragInteraction
import androidx.compose.foundation.interaction.InteractionSource
import java.text.NumberFormat

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FeedScreen(uiState: IntelFeedUiState, viewModel: IntelFeedViewModel, onOpenDrawer: () -> Unit) {
    val listState = rememberLazyListState()
    val gridState = rememberLazyGridState()
    val scope = rememberCoroutineScope()
    var showMarkAllDialog by remember { mutableStateOf(false) }
    var showCampaignPicker by remember { mutableStateOf(false) }
    var singleEntryForCampaign by remember { mutableStateOf<String?>(null) }

    // Page in more as the end of the list or grid comes into view.
    val nearEnd by remember(uiState.feedLayout) {
        derivedStateOf {
            if (uiState.feedLayout == "grid") {
                val total = gridState.layoutInfo.totalItemsCount
                val last = gridState.layoutInfo.visibleItemsInfo.lastOrNull()?.index ?: 0
                total > 0 && last >= total - 6
            } else {
                val total = listState.layoutInfo.totalItemsCount
                val last = listState.layoutInfo.visibleItemsInfo.lastOrNull()?.index ?: 0
                total > 0 && last >= total - 4
            }
        }
    }
    LaunchedEffect(nearEnd, uiState.entries.size, uiState.hasMore, uiState.feedLoading, uiState.feedError) {
        if ((nearEnd || uiState.entries.isEmpty()) && uiState.hasMore &&
            !uiState.feedLoading && !uiState.isRefreshing && uiState.feedError == null) {
            viewModel.loadMoreEntries()
        }
    }
    // A different filter/feed/category starts at the top. The handled value is saved because this
    // screen is re-created when you come back from an article: re-running the scroll then threw
    // away your place in the list.
    var handledScrollToTop by rememberSaveable { mutableIntStateOf(uiState.feedScrollToTop) }
    LaunchedEffect(uiState.feedScrollToTop) {
        if (uiState.feedScrollToTop != handledScrollToTop) {
            handledScrollToTop = uiState.feedScrollToTop
            if (uiState.feedLayout == "grid") gridState.scrollToItem(0)
            else listState.scrollToItem(0)
        }
    }

    val scopeName = uiState.selectedFeedTitle ?: uiState.selectedCategoryName
    if (showMarkAllDialog) {
        AlertDialog(
            onDismissRequest = { showMarkAllDialog = false },
            title = { Text("Mark all as read?") },
            text = {
                Text(
                    when {
                        scopeName != null -> "Every unread article in \"$scopeName\" will be marked as read."
                        uiState.selectedFilter == FeedFilter.PRIORITY_QUEUE ->
                            "Every article in the Priority Queue will be marked as read. Other unread articles stay unread."
                        else -> "Every unread article in all of your feeds will be marked as read. This can't be undone."
                    }
                )
            },
            confirmButton = { TextButton(onClick = { showMarkAllDialog = false; viewModel.markAllAsRead() }) { Text("Mark all read") } },
            dismissButton = { TextButton(onClick = { showMarkAllDialog = false }) { Text("Cancel") } }
        )
    }

    Scaffold(
        topBar = {
            if (uiState.isSelecting) {
                SelectionTopBar(
                    count = uiState.selectedIds.size,
                    onClose = { viewModel.clearSelection() },
                    onSelectAll = { viewModel.selectAll() },
                    onAction = { viewModel.applyToSelection(it) },
                    onAddToCampaign = { showCampaignPicker = true }
                )
            } else {
                val strings = LocalStrings.current
                FeedTopBar(
                    title = scopeName ?: uiState.selectedFilter.localizedLabel(strings),
                    subtitle = feedSubtitle(uiState),
                    isGrid = uiState.feedLayout == "grid",
                    listOptions = listOptionsFor(uiState),
                    hideRead = uiState.feedHideRead,
                    oldestFirst = uiState.feedSort == "oldest",
                    autoRead = uiState.feedAutoRead,
                    onToggleHideRead = { viewModel.setFeedHideRead(!uiState.feedHideRead) },
                    onToggleAutoRead = { viewModel.setFeedAutoRead(!uiState.feedAutoRead) },
                    onToggleSort = { viewModel.setFeedSort(if (uiState.feedSort == "oldest") "newest" else "oldest") },
                    onOpenDrawer = onOpenDrawer,
                    onToggleLayout = { viewModel.toggleFeedLayout() },
                    onMarkAllRead = { showMarkAllDialog = true },
                    onOpenSettings = { viewModel.navigate(Route.Settings) },
                    onScrollTop = {
                        scope.launch {
                            if (uiState.feedLayout == "grid") gridState.animateScrollToItem(0)
                            else listState.animateScrollToItem(0)
                        }
                    }
                )
            }
        },
        containerColor = SlateDark900
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            FilterChips(uiState, onSelect = { viewModel.setFilter(it) })
            if (scopeName != null) {
                ScopeBanner(
                    name = scopeName,
                    isFeed = uiState.selectedFeedTitle != null,
                    feed = uiState.selectedFeedId?.let { id -> uiState.feeds.firstOrNull { it.id == id } },
                    filter = uiState.selectedFilter,
                    // The chips leave the feed, so the banner switches between all and unread articles in it.
                    onToggleShowAll = {
                        viewModel.setScopedFilter(if (uiState.selectedFilter == FeedFilter.ALL) FeedFilter.UNREAD else FeedFilter.ALL)
                    },
                    onClear = { viewModel.clearFeedFilter() }
                )
            }
            uiState.dayFocus?.let { focus ->
                // The web's day-focus bar ("Showing only <label>", "Clear filter"), plus a range
                // picker: the chip's day, or 24h / 7 / 30 days / all time.
                Column(
                    Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 4.dp)
                        .background(CyberBlue.copy(alpha = 0.10f), RoundedCornerShape(8.dp))
                        .padding(start = 12.dp, bottom = 4.dp)
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        val range = when (focus.window) {
                            com.example.intelfeed.data.model.FocusWindow.DAY -> DateUtils.dayLabel(DateUtils.dayBounds(focus.dayKey)?.first)
                            com.example.intelfeed.data.model.FocusWindow.ALL -> "all time"
                            else -> "last ${focus.window.label}"
                        }
                        Text(
                            "Showing only ${focus.label}" + if (range.isNotBlank()) " · $range" else "",
                            fontSize = 13.sp,
                            color = TextPrimary,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f)
                        )
                        TextButton(onClick = { viewModel.setDayFocus(null) }) { Text("Clear filter") }
                    }
                    Row(
                        Modifier.horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        val dayName = DateUtils.dayLabel(DateUtils.dayBounds(focus.dayKey)?.first).ifBlank { "That day" }
                        com.example.intelfeed.data.model.FocusWindow.entries.forEach { w ->
                            FilterChip(
                                selected = focus.window == w,
                                onClick = { viewModel.setDayFocusWindow(w) },
                                label = { Text(if (w == com.example.intelfeed.data.model.FocusWindow.DAY) dayName else w.label, fontSize = 12.sp) }
                            )
                        }
                    }
                }
            }

            PullToRefreshBox(
                isRefreshing = uiState.isRefreshing,
                onRefresh = { viewModel.refreshFeed() },
                modifier = Modifier.fillMaxSize()
            ) {
                when {
                    // Scrollable like the empty state: a plain Box can't be pulled, so pull-to-refresh
                    // did nothing on the error screen (seen during a server outage, all requests 502).
                    uiState.entries.isEmpty() && uiState.feedError != null -> LazyColumn(Modifier.fillMaxSize()) {
                        item {
                            ErrorState(
                                message = uiState.feedError,
                                onRetry = { viewModel.refreshFeed() },
                                modifier = Modifier.fillParentMaxSize()
                            )
                        }
                    }
                    uiState.entries.isEmpty() && uiState.isRefreshing -> LazyColumn(Modifier.fillMaxSize()) {
                        item { SlowLoadingState("Loading ${scopeName ?: uiState.selectedFilter.label.lowercase()}…") }
                    }
                    uiState.entries.isEmpty() && !uiState.isRefreshing && !uiState.feedLoading -> LazyColumn(Modifier.fillMaxSize()) {
                        // A scrollable empty state, so pull-to-refresh still works.
                        item { FeedEmptyState(uiState, onShowAllInScope = { viewModel.setScopedFilter(FeedFilter.ALL) }) }
                    }
                    uiState.feedLayout == "grid" -> FeedGrid(
                        uiState = uiState,
                        viewModel = viewModel,
                        gridState = gridState,
                        onAddToCampaign = { singleEntryForCampaign = it }
                    )
                    else -> FeedList(
                        uiState = uiState,
                        viewModel = viewModel,
                        listState = listState,
                        onAddToCampaign = { singleEntryForCampaign = it }
                    )
                }
            }
        }
    }

    if (showCampaignPicker && uiState.selectedIds.isNotEmpty()) {
        val snackbarHostState = LocalSnackbarHostState.current
        CampaignPickerSheet(
            entryIds = uiState.selectedIds.toList(),
            repository = viewModel.repository,
            onDismiss = { showCampaignPicker = false },
            onSuccess = { campaignName, count ->
                viewModel.clearSelection()
                scope.launch {
                    snackbarHostState.showSnackbar("Added $count article${if (count == 1) "" else "s"} to $campaignName")
                }
            }
        )
    }

    if (singleEntryForCampaign != null) {
        val snackbarHostState = LocalSnackbarHostState.current
        val entryId = singleEntryForCampaign!!
        CampaignPickerSheet(
            entryIds = listOf(entryId),
            repository = viewModel.repository,
            onDismiss = { singleEntryForCampaign = null },
            onSuccess = { campaignName, _ ->
                singleEntryForCampaign = null
                scope.launch {
                    snackbarHostState.showSnackbar("Added article to $campaignName")
                }
            }
        )
    }
}

/** Which list options apply: the ranked Priority Queue has neither; Unread is unread already. */
private data class ListOptions(val hideRead: Boolean, val sort: Boolean)

private fun listOptionsFor(state: IntelFeedUiState): ListOptions {
    val scoped = state.selectedFeedId != null || state.selectedCategoryId != null
    return when {
        state.selectedFilter == FeedFilter.PRIORITY_QUEUE && !scoped -> ListOptions(hideRead = false, sort = false)
        // A scoped Priority Queue shows the scope's unread articles (see ScopeBanner).
        state.selectedFilter == FeedFilter.PRIORITY_QUEUE || state.selectedFilter == FeedFilter.UNREAD -> ListOptions(hideRead = false, sort = true)
        else -> ListOptions(hideRead = true, sort = true)
    }
}

private fun feedSubtitle(state: IntelFeedUiState): String? {
    if (state.entries.isEmpty()) return state.username?.let { "@$it" }
    val articles = state.entries.filterNot { it.isThread }
    val stories = state.entries.count { it.isThread }
    val more = if (state.hasMore) "+" else ""
    // The server's unread count for the whole view, when no feed or folder narrows it; otherwise
    // what's loaded so far.
    val scoped = state.selectedFeedId != null || state.selectedCategoryId != null
    val serverUnread = if (scoped) null else state.viewCounts.forFilter(state.selectedFilter)
    if (state.selectedFilter == FeedFilter.UNREAD && serverUnread != null) {
        return "${NumberFormat.getIntegerInstance().format(serverUnread)} unread"
    }
    val unread = serverUnread ?: articles.count { !it.isRead }
    val options = listOptionsFor(state)
    val hidingRead = options.hideRead && state.feedHideRead
    return buildList {
        if (stories > 0) add("$stories ${if (stories == 1) "story" else "stories"}")
        if (articles.isNotEmpty()) add("${articles.size}$more ${if (articles.size == 1) "article" else if (hidingRead) "unread" else "articles"}")
        if (!hidingRead && unread > 0 && state.selectedFilter != FeedFilter.UNREAD && state.selectedFilter != FeedFilter.PRIORITY_QUEUE) {
            add("${NumberFormat.getIntegerInstance().format(unread)} unread")
        }
        if (options.sort && state.feedSort == "oldest") add("oldest first")
    }.joinToString(" · ")
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun FeedTopBar(
    title: String,
    subtitle: String?,
    isGrid: Boolean,
    listOptions: ListOptions,
    hideRead: Boolean,
    oldestFirst: Boolean,
    autoRead: Boolean,
    onToggleHideRead: () -> Unit,
    onToggleAutoRead: () -> Unit,
    onToggleSort: () -> Unit,
    onOpenDrawer: () -> Unit,
    onToggleLayout: () -> Unit,
    onMarkAllRead: () -> Unit,
    onOpenSettings: () -> Unit,
    onScrollTop: () -> Unit
) {
    var menuOpen by remember { mutableStateOf(false) }
    TopAppBar(
        navigationIcon = {
            IconButton(onClick = onOpenDrawer) { Icon(Icons.Default.Menu, contentDescription = "Feeds and folders", tint = CyberBlue) }
        },
        title = {
            Column {
                Text(title, fontSize = 18.sp, fontWeight = FontWeight.Bold, color = TextPrimary, maxLines = 1, overflow = TextOverflow.Ellipsis)
                if (subtitle != null) Text(subtitle, fontSize = 12.sp, color = TextMuted, maxLines = 1)
            }
        },
        actions = {
            IconButton(onClick = onToggleLayout) {
                Icon(
                    imageVector = if (isGrid) Icons.Default.ViewAgenda else Icons.Default.GridView,
                    contentDescription = if (isGrid) "Switch to list view" else "Switch to grid view",
                    tint = if (isGrid) CyberBlue else TextSecondary
                )
            }
            IconButton(onClick = onMarkAllRead) { Icon(Icons.Default.DoneAll, contentDescription = "Mark all as read", tint = TextSecondary) }
            Box {
                IconButton(onClick = { menuOpen = true }) { Icon(Icons.Default.MoreVert, contentDescription = "More", tint = TextSecondary) }
                DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                    if (listOptions.hideRead) {
                        DropdownMenuItem(
                            text = { Text("Hide read articles") },
                            leadingIcon = { Icon(Icons.Default.VisibilityOff, null) },
                            trailingIcon = { Checkbox(checked = hideRead, onCheckedChange = null) },
                            onClick = { menuOpen = false; onToggleHideRead() }
                        )
                    }
                    DropdownMenuItem(
                        text = { Text("Auto-read on scroll") },
                        leadingIcon = { Icon(Icons.Default.MarkEmailRead, null) },
                        trailingIcon = { Checkbox(checked = autoRead, onCheckedChange = null) },
                        onClick = { menuOpen = false; onToggleAutoRead() }
                    )
                    if (listOptions.sort) {
                        DropdownMenuItem(
                            text = { Text(if (oldestFirst) "Show newest first" else "Show oldest first") },
                            leadingIcon = { Icon(Icons.Default.SwapVert, null) },
                            onClick = { menuOpen = false; onToggleSort() }
                        )
                    }
                    DropdownMenuItem(
                        text = { Text(if (isGrid) "Switch to list view" else "Switch to grid view") },
                        leadingIcon = { Icon(if (isGrid) Icons.Default.ViewAgenda else Icons.Default.GridView, null) },
                        onClick = { menuOpen = false; onToggleLayout() }
                    )
                    DropdownMenuItem(
                        text = { Text("Back to top") },
                        leadingIcon = { Icon(Icons.Default.VerticalAlignTop, null) },
                        onClick = { menuOpen = false; onScrollTop() }
                    )
                    DropdownMenuItem(
                        text = { Text("Account & settings") },
                        leadingIcon = { Icon(Icons.Default.AccountCircle, null) },
                        onClick = { menuOpen = false; onOpenSettings() }
                    )
                }
            }
        },
        colors = TopAppBarDefaults.topAppBarColors(containerColor = SlateDark900, titleContentColor = TextPrimary)
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SelectionTopBar(
    count: Int,
    onClose: () -> Unit,
    onSelectAll: () -> Unit,
    onAction: (BulkAction) -> Unit,
    onAddToCampaign: () -> Unit
) {
    var menuOpen by remember { mutableStateOf(false) }
    TopAppBar(
        navigationIcon = { IconButton(onClick = onClose) { Icon(Icons.Default.Close, contentDescription = "Cancel selection", tint = TextPrimary) } },
        title = { Text("$count selected", fontWeight = FontWeight.Bold) },
        actions = {
            IconButton(onClick = { onAction(BulkAction.READ) }) { Icon(Icons.Default.MarkEmailRead, contentDescription = "Mark read", tint = TextPrimary) }
            IconButton(onClick = { onAction(BulkAction.STAR) }) { Icon(Icons.Default.Star, contentDescription = "Star", tint = CyberAmber) }
            IconButton(onClick = { onAction(BulkAction.BOOKMARK) }) { Icon(Icons.Default.Bookmark, contentDescription = "Bookmark", tint = CyberBlue) }
            IconButton(onClick = onAddToCampaign) { Icon(Icons.Default.Campaign, contentDescription = "Add to campaign", tint = CyberPurple) }
            Box {
                IconButton(onClick = { menuOpen = true }) { Icon(Icons.Default.MoreVert, contentDescription = "More", tint = TextPrimary) }
                DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                    DropdownMenuItem(text = { Text("Select all") }, leadingIcon = { Icon(Icons.Default.SelectAll, null) }, onClick = { menuOpen = false; onSelectAll() })
                    DropdownMenuItem(text = { Text("Add to campaign") }, leadingIcon = { Icon(Icons.Default.Campaign, null, tint = CyberPurple) }, onClick = { menuOpen = false; onAddToCampaign() })
                    DropdownMenuItem(text = { Text("Mark unread") }, leadingIcon = { Icon(Icons.Default.MarkEmailUnread, null) }, onClick = { menuOpen = false; onAction(BulkAction.UNREAD) })
                    DropdownMenuItem(text = { Text("Remove star") }, leadingIcon = { Icon(Icons.Default.StarBorder, null) }, onClick = { menuOpen = false; onAction(BulkAction.UNSTAR) })
                    DropdownMenuItem(text = { Text("Remove bookmark") }, leadingIcon = { Icon(Icons.Default.BookmarkBorder, null) }, onClick = { menuOpen = false; onAction(BulkAction.UNBOOKMARK) })
                }
            }
        },
        colors = TopAppBarDefaults.topAppBarColors(containerColor = SlateDark800, titleContentColor = TextPrimary)
    )
}

@Composable
private fun FilterChips(uiState: IntelFeedUiState, onSelect: (FeedFilter) -> Unit) {
    val scoped = uiState.selectedFeedId != null || uiState.selectedCategoryId != null
    LazyRow(
        modifier = Modifier.fillMaxWidth(),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 4.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        items(FeedFilter.entries) { filter ->
            // With a feed/category open, the chip shows which view of that scope you're in, but
            // tapping one returns to all feeds (the drawer picks the scope).
            val isSelected = uiState.selectedFilter == filter && !scoped
            val strings = LocalStrings.current
            FilterChip(
                selected = isSelected,
                onClick = { onSelect(filter) },
                label = { Text(filter.localizedLabel(strings), fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Medium) },
                leadingIcon = when (filter) {
                    FeedFilter.PRIORITY_QUEUE -> { { Icon(Icons.Default.Bolt, null, Modifier.size(16.dp), tint = if (isSelected) SlateDark900 else CyberAmber) } }
                    FeedFilter.STARRED -> { { Icon(Icons.Default.Star, null, Modifier.size(16.dp), tint = if (isSelected) SlateDark900 else CyberAmber) } }
                    FeedFilter.BOOKMARKED -> { { Icon(Icons.Default.Bookmark, null, Modifier.size(16.dp), tint = if (isSelected) SlateDark900 else CyberBlue) } }
                    FeedFilter.WATCHED -> { { Icon(Icons.Default.Visibility, null, Modifier.size(16.dp), tint = if (isSelected) SlateDark900 else CyberGreen) } }
                    else -> null
                },
                colors = FilterChipDefaults.filterChipColors(
                    selectedContainerColor = CyberBlue,
                    selectedLabelColor = SlateDark900,
                    containerColor = SlateDark800,
                    labelColor = TextSecondary
                ),
                border = FilterChipDefaults.filterChipBorder(
                    enabled = true,
                    selected = isSelected,
                    borderColor = SlateDark600,
                    selectedBorderColor = CyberBlue
                )
            )
        }
    }
}

/** "every 30 min", "hourly", "every 6 h", "daily". */
private fun pollInterval(minutes: Int): String = when {
    minutes <= 0 -> "manually"
    minutes == 60 -> "hourly"
    minutes == 1440 -> "daily"
    minutes % 1440 == 0 -> "every ${minutes / 1440} days"
    minutes % 60 == 0 -> "every ${minutes / 60} h"
    else -> "every $minutes min"
}

/**
 * The feed or folder the list is narrowed to. For one feed it also shows what the web's single-feed
 * view shows: type, unread count, last fetch and polling cadence, its curation (extraction) mode,
 * and fetch errors.
 */
@Composable
private fun ScopeBanner(
    name: String,
    isFeed: Boolean,
    feed: FeedSource?,
    filter: FeedFilter,
    onToggleShowAll: () -> Unit,
    onClear: () -> Unit
) {
    Surface(
        color = CyberBlue.copy(alpha = 0.12f),
        shape = RoundedCornerShape(10.dp),
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(start = 12.dp)) {
            Icon(if (isFeed) Icons.Default.RssFeed else Icons.Default.Folder, contentDescription = null, tint = CyberBlue, modifier = Modifier.size(16.dp))
            Spacer(Modifier.width(8.dp))
            Column(Modifier.weight(1f).padding(vertical = 6.dp)) {
                Text(name, color = CyberBlue, fontSize = 13.sp, fontWeight = FontWeight.Bold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                // The Priority Queue can't be scoped server-side; say what's shown instead.
                Text(
                    when (filter) {
                        FeedFilter.PRIORITY_QUEUE -> "Unread articles, newest first"
                        FeedFilter.UNREAD -> "Unread articles"
                        else -> filter.label
                    },
                    color = TextMuted,
                    fontSize = 11.sp
                )
                if (feed != null) {
                    val health = listOfNotNull(
                        feed.typeLabel,
                        "${feed.unreadCount} unread",
                        DateUtils.formatRelativeTime(feed.lastFetchedAt).takeIf { it.isNotBlank() }?.let { rel ->
                            "fetched " + if (rel == "Just now" || rel == "Yesterday") rel.lowercase() else rel
                        },
                        feed.fetchIntervalMinutes?.let { "checked ${pollInterval(it)}" },
                        "muted".takeIf { feed.isMuted },
                        "paused".takeIf { !feed.isActive }
                    )
                    Text(health.joinToString(" · "), color = TextSecondary, fontSize = 11.sp, maxLines = 2, overflow = TextOverflow.Ellipsis)
                    feed.curationLabel?.let { Text(it, color = CyberPurple, fontSize = 11.sp, maxLines = 1, overflow = TextOverflow.Ellipsis) }
                    if (feed.errorCount > 0) {
                        Text(
                            "⚠ The last ${if (feed.errorCount == 1) "fetch" else "${feed.errorCount} fetches"} failed" +
                                (feed.lastError?.takeIf { it.isNotBlank() }?.let { ": ${it.take(160)}" } ?: ""),
                            color = CyberAmber,
                            fontSize = 11.sp,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }
            }
            TextButton(onClick = onToggleShowAll) {
                Text(if (filter == FeedFilter.ALL) "Unread only" else "Show all", fontSize = 12.sp, color = CyberBlue)
            }
            IconButton(onClick = onClear) { Icon(Icons.Default.Close, contentDescription = "Show all feeds", tint = CyberBlue, modifier = Modifier.size(18.dp)) }
        }
    }
}

@Composable
private fun FeedEmptyState(uiState: IntelFeedUiState, onShowAllInScope: () -> Unit) {
    val scopeName = uiState.selectedFeedTitle ?: uiState.selectedCategoryName
    // A feed or folder with the Priority Queue selected shows its unread articles (the queue can't
    // be narrowed on the server), so "nothing clears the priority threshold" would be wrong there.
    val filter = if (scopeName != null && uiState.selectedFilter == FeedFilter.PRIORITY_QUEUE) FeedFilter.UNREAD else uiState.selectedFilter
    val hidingRead = uiState.feedHideRead && listOptionsFor(uiState).hideRead
    val (title, message) = if (scopeName != null && filter == FeedFilter.UNREAD) {
        "All caught up" to "No unread articles in \"$scopeName\". Pull down to check for new ones."
    } else if (hidingRead) {
        "No unread articles here" to "Everything in this view is read. Turn off \"Hide read articles\" in the ⋮ menu to see them."
    } else when (filter) {
        FeedFilter.PRIORITY_QUEUE -> "Nothing urgent right now" to "No unread article clears the priority threshold. Pull down to check again, or browse Unread."
        FeedFilter.UNREAD -> "All caught up" to "You've read everything here. Pull down to check for new articles."
        FeedFilter.STARRED -> "No starred articles" to "Star an article to come back to it later today."
        FeedFilter.BOOKMARKED -> "No bookmarks yet" to "Bookmark articles you'll want to find again as reference."
        FeedFilter.LAST_24H, FeedFilter.THIS_WEEK -> "Nothing new" to "No articles arrived in this window."
        FeedFilter.WATCHED -> "Nothing from your watchlist" to "Watch an actor, malware family, CVE or other entity from its profile, and articles about it collect here."
        FeedFilter.ALL -> "No articles" to "Nothing matches this view yet."
    }
    // An unread-only feed or folder offers its read articles too.
    val showAll = scopeName != null && uiState.selectedFilter != FeedFilter.ALL
    EmptyState(
        icon = Icons.Default.CheckCircle,
        iconTint = CyberGreen,
        title = title,
        message = message,
        modifier = Modifier.padding(top = 48.dp),
        actionLabel = if (showAll) "Show all articles" else null,
        onAction = if (showAll) onShowAllInScope else null
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun FeedList(
    uiState: IntelFeedUiState,
    viewModel: IntelFeedViewModel,
    listState: androidx.compose.foundation.lazy.LazyListState,
    onAddToCampaign: (String) -> Unit
) {
    val context = LocalContext.current
    // Day dividers only make sense for date-ordered views; the Priority Queue is ranked.
    val showDays = uiState.selectedFilter != FeedFilter.PRIORITY_QUEUE ||
        uiState.selectedFeedId != null || uiState.selectedCategoryId != null
    val rows = remember(uiState.entries, showDays) {
        buildFeedRows(uiState.entries, showDays)
    }

    // Back from the reader: show the article it ended on if it's off screen.
    val focusId = uiState.feedFocusEntryId
    LaunchedEffect(focusId) {
        val id = focusId ?: return@LaunchedEffect
        snapshotFlow { listState.layoutInfo.totalItemsCount }.first { it > 0 }
        val info = listState.layoutInfo
        val fullyVisible = info.visibleItemsInfo.any {
            it.key == id && it.offset >= info.viewportStartOffset && it.offset + it.size <= info.viewportEndOffset
        }
        val index = rows.indexOfFirst { it is FeedRow.Item && it.entry.id == id }
        if (index >= 0 && !fullyVisible) listState.scrollToItem((index - 1).coerceAtLeast(0))
        viewModel.clearFeedFocus()
    }
    AutoReadOnScroll(
        enabled = uiState.feedAutoRead && !uiState.isSelecting,
        interactionSource = listState.interactionSource,
        firstVisibleIndex = { listState.firstVisibleItemIndex },
        isScrolling = { listState.isScrollInProgress },
        rows = rows,
        onScrolledPast = viewModel::markScrolledPastRead
    )

    LazyColumn(
        state = listState,
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 4.dp, bottom = 24.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        items(
            items = rows,
            key = { it.key },
            contentType = { row ->
                when (row) {
                    is FeedRow.Day -> "day_header"
                    is FeedRow.Item -> if (row.entry.isThread) "story_card" else "entry_card"
                }
            }
        ) { row ->
            when (row) {
                is FeedRow.Day -> DayRow(row, uiState, viewModel)
                is FeedRow.Item -> {
                    val entry = row.entry
                    val thread = entry.thread
                    if (thread != null) {
                        StoryCard(
                            title = entry.title,
                            thread = thread,
                            score = entry.priorityScore,
                            onClick = { viewModel.openEntry(entry) },
                            onEntityClick = { type, id, name -> viewModel.openEntity(type.key, id, name) }
                        )
                    } else {
                        val selected = entry.id in uiState.selectedIds
                        SwipeableEntry(
                            entry = entry,
                            enabled = !uiState.isSelecting,
                            onSwipeRead = { viewModel.toggleRead(entry) },
                            onSwipeStar = { viewModel.toggleStar(entry) }
                        ) {
                            EntryCard(
                                entry = entry,
                                compact = uiState.feedDensity == "compact",
                                intel = uiState.intelCounts[entry.id],
                                onTagClick = if (uiState.isSelecting) null else { tag -> viewModel.searchTag(tag) },
                                selectionMode = uiState.isSelecting,
                                selected = selected,
                                onClick = {
                                    if (uiState.isSelecting) viewModel.toggleSelection(entry.id) else viewModel.openEntry(entry)
                                },
                                onLongClick = { viewModel.toggleSelection(entry.id) },
                                onToggleStar = { viewModel.toggleStar(entry) },
                                onToggleBookmark = { viewModel.toggleBookmark(entry) },
                                menuActions = listOfNotNull(
                                    CardAction(if (entry.isRead) "Mark as unread" else "Mark as read",
                                        if (entry.isRead) Icons.Default.MarkEmailUnread else Icons.Default.MarkEmailRead) { viewModel.toggleRead(entry) },
                                    CardAction("Mark everything above as read", Icons.Default.DoneAll) { viewModel.markAboveAsRead(entry.id) },
                                    CardAction("Add to campaign", Icons.Default.Campaign) { onAddToCampaign(entry.id) },
                                    entry.url?.takeIf { it.isNotBlank() }?.let { url ->
                                        CardAction("Open original", Icons.AutoMirrored.Filled.OpenInNew) { ExternalLinks.openInBrowser(context, url) }
                                    },
                                    entry.url?.takeIf { it.isNotBlank() }?.let { url ->
                                        CardAction("Share link", Icons.Default.Share) { ShareSheet.shareText(context, "${entry.displayTitle}\n$url", entry.displayTitle) }
                                    }
                                )
                            )
                        }
                    }
                }
            }
        }

        if (uiState.feedLoading) item(key = "loading", contentType = "loading") { InlineLoading() }
        if (uiState.feedError != null && uiState.entries.isNotEmpty()) {
            item(key = "error", contentType = "error") {
                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth().padding(8.dp)) {
                    Text(uiState.feedError, color = CyberAmber, fontSize = 13.sp, modifier = Modifier.weight(1f))
                    TextButton(onClick = { viewModel.loadMoreEntries() }) { Text("Retry") }
                }
            }
        }
        if (!uiState.hasMore && !uiState.feedLoading && uiState.entries.isNotEmpty()) {
            item(key = "end", contentType = "end") {
                Text(
                    text = "That's everything in this view.",
                    color = TextMuted,
                    fontSize = 13.sp,
                    modifier = Modifier.fillMaxWidth().padding(vertical = 16.dp),
                    textAlign = androidx.compose.ui.text.style.TextAlign.Center
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun FeedGrid(
    uiState: IntelFeedUiState,
    viewModel: IntelFeedViewModel,
    gridState: LazyGridState,
    onAddToCampaign: (String) -> Unit
) {
    val context = LocalContext.current
    val showDays = uiState.selectedFilter != FeedFilter.PRIORITY_QUEUE ||
        uiState.selectedFeedId != null || uiState.selectedCategoryId != null
    val rows = remember(uiState.entries, showDays) {
        buildFeedRows(uiState.entries, showDays)
    }

    val focusId = uiState.feedFocusEntryId
    LaunchedEffect(focusId) {
        val id = focusId ?: return@LaunchedEffect
        snapshotFlow { gridState.layoutInfo.totalItemsCount }.first { it > 0 }
        val visible = gridState.layoutInfo.visibleItemsInfo.any { it.key == id }
        val index = rows.indexOfFirst { it is FeedRow.Item && it.entry.id == id }
        if (index >= 0 && !visible) gridState.scrollToItem(index)
        viewModel.clearFeedFocus()
    }
    AutoReadOnScroll(
        enabled = uiState.feedAutoRead && !uiState.isSelecting,
        interactionSource = gridState.interactionSource,
        firstVisibleIndex = { gridState.firstVisibleItemIndex },
        isScrolling = { gridState.isScrollInProgress },
        rows = rows,
        onScrolledPast = viewModel::markScrolledPastRead
    )

    LazyVerticalGrid(
        columns = GridCells.Adaptive(minSize = 160.dp),
        state = gridState,
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(start = 12.dp, end = 12.dp, top = 4.dp, bottom = 24.dp),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        items(
            items = rows,
            key = { it.key },
            contentType = { row ->
                when (row) {
                    is FeedRow.Day -> "day_header"
                    is FeedRow.Item -> if (row.entry.isThread) "story_card" else "entry_grid_card"
                }
            },
            span = { row ->
                when (row) {
                    is FeedRow.Day -> GridItemSpan(maxLineSpan)
                    is FeedRow.Item -> {
                        if (row.entry.isThread) GridItemSpan(maxLineSpan)
                        else GridItemSpan(1)
                    }
                }
            }
        ) { row ->
            when (row) {
                is FeedRow.Day -> DayRow(row, uiState, viewModel)
                is FeedRow.Item -> {
                    val entry = row.entry
                    val thread = entry.thread
                    if (thread != null) {
                        StoryCard(
                            title = entry.title,
                            thread = thread,
                            score = entry.priorityScore,
                            onClick = { viewModel.openEntry(entry) },
                            onEntityClick = { type, id, name -> viewModel.openEntity(type.key, id, name) }
                        )
                    } else {
                        val selected = entry.id in uiState.selectedIds
                        EntryGridCard(
                            entry = entry,
                            intel = uiState.intelCounts[entry.id],
                            selectionMode = uiState.isSelecting,
                            onTagClick = if (uiState.isSelecting) null else { tag -> viewModel.searchTag(tag) },
                            selected = selected,
                            onClick = {
                                if (uiState.isSelecting) viewModel.toggleSelection(entry.id)
                                else viewModel.openEntry(entry)
                            },
                            onLongClick = { viewModel.toggleSelection(entry.id) },
                            onToggleStar = { viewModel.toggleStar(entry) },
                            onToggleBookmark = { viewModel.toggleBookmark(entry) },
                            menuActions = listOfNotNull(
                                CardAction(
                                    if (entry.isRead) "Mark as unread" else "Mark as read",
                                    if (entry.isRead) Icons.Default.MarkEmailUnread else Icons.Default.MarkEmailRead
                                ) { viewModel.toggleRead(entry) },
                                CardAction("Mark everything above as read", Icons.Default.DoneAll) { viewModel.markAboveAsRead(entry.id) },
                                CardAction("Add to campaign", Icons.Default.Campaign) { onAddToCampaign(entry.id) },
                                entry.url?.takeIf { it.isNotBlank() }?.let { url ->
                                    CardAction("Open original", Icons.AutoMirrored.Filled.OpenInNew) { ExternalLinks.openInBrowser(context, url) }
                                },
                                entry.url?.takeIf { it.isNotBlank() }?.let { url ->
                                    CardAction("Share link", Icons.Default.Share) { ShareSheet.shareText(context, "${entry.displayTitle}\n$url", entry.displayTitle) }
                                }
                            )
                        )
                    }
                }
            }
        }

        if (uiState.feedLoading) item(key = "loading", span = { GridItemSpan(maxLineSpan) }, contentType = "loading") { InlineLoading() }
        if (uiState.feedError != null && uiState.entries.isNotEmpty()) {
            item(key = "error", span = { GridItemSpan(maxLineSpan) }, contentType = "error") {
                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth().padding(8.dp)) {
                    Text(uiState.feedError, color = CyberAmber, fontSize = 13.sp, modifier = Modifier.weight(1f))
                    TextButton(onClick = { viewModel.loadMoreEntries() }) { Text("Retry") }
                }
            }
        }
        if (!uiState.hasMore && !uiState.feedLoading && uiState.entries.isNotEmpty()) {
            item(key = "end", span = { GridItemSpan(maxLineSpan) }, contentType = "end") {
                Text(
                    text = "That's everything in this view.",
                    color = TextMuted,
                    fontSize = 13.sp,
                    modifier = Modifier.fillMaxWidth().padding(vertical = 16.dp),
                    textAlign = androidx.compose.ui.text.style.TextAlign.Center
                )
            }
        }
    }
}

/**
 * Auto-read (the web's toolbar toggle): reports the unread articles the user scrolls off the top
 * of the list or grid. Only movement that starts with the user's own drag counts (including the
 * fling after it), and only rows that were on screen and then passed: jumps made by the app
 * (back to top, returning from an article, a new filter) never mark anything. Articles are sent
 * in batches when the scroll stops, or every 25.
 */
@Composable
private fun AutoReadOnScroll(
    enabled: Boolean,
    interactionSource: InteractionSource,
    firstVisibleIndex: () -> Int,
    isScrolling: () -> Boolean,
    rows: List<FeedRow>,
    onScrolledPast: (List<String>) -> Unit
) {
    val currentRows by rememberUpdatedState(rows)
    val report by rememberUpdatedState(onScrolledPast)
    if (!enabled) return
    LaunchedEffect(interactionSource) {
        var userDriven = false
        val pending = LinkedHashSet<String>()
        fun flush() {
            if (pending.isNotEmpty()) {
                report(pending.toList())
                pending.clear()
            }
        }
        try {
            launch { interactionSource.interactions.collect { if (it is DragInteraction.Start) userDriven = true } }
            launch {
                snapshotFlow { isScrolling() }.collect { scrolling ->
                    if (!scrolling) {
                        userDriven = false
                        flush()
                    }
                }
            }
            var previous = firstVisibleIndex()
            snapshotFlow { firstVisibleIndex() }.collect { index ->
                if (userDriven && index > previous) {
                    val passed = currentRows.subList(previous.coerceAtMost(currentRows.size), index.coerceAtMost(currentRows.size))
                    passed.forEach { row -> if (row is FeedRow.Item && !row.entry.isRead && !row.entry.isThread) pending += row.entry.id }
                    if (pending.size >= 25) flush()
                }
                previous = index
            }
        } finally {
            flush()
        }
    }
}

private fun buildFeedRows(entries: List<EntryItem>, showDays: Boolean): List<FeedRow> {
    if (!showDays) return entries.map { FeedRow.Item(it) }
    return buildList {
        var lastDayKey: String? = null
        val usedKeys = mutableSetOf<String>()
        entries.forEach { entry ->
            val dayKey = DateUtils.localDayKey(entry.publishedAt)
            if (dayKey != null && dayKey != lastDayKey) {
                lastDayKey = dayKey
                // LazyColumn crashes on a repeated key; a day can only repeat if the list isn't date-ordered.
                var key = "day:$dayKey"
                var n = 1
                while (!usedKeys.add(key)) key = "day:$dayKey#${n++}"
                add(FeedRow.Day(DateUtils.dayLabel(entry.publishedAt), dayKey, key))
            }
            add(FeedRow.Item(entry))
        }
    }.let { rows ->
        // Each divider knows how many loaded articles under it are unread (for "mark day read").
        val unreadByKey = mutableMapOf<String, Int>()
        var current: String? = null
        rows.forEach { row ->
            when (row) {
                is FeedRow.Day -> current = row.key
                is FeedRow.Item -> if (!row.entry.isRead && !row.entry.isThread) current?.let { unreadByKey[it] = (unreadByKey[it] ?: 0) + 1 }
            }
        }
        rows.map { if (it is FeedRow.Day) it.copy(unread = unreadByKey[it.key] ?: 0) else it }
    }
}

/** A day divider with the day's topic chips and its saved AI briefing (list and grid share it). */
@Composable
private fun DayRow(row: FeedRow.Day, uiState: IntelFeedUiState, viewModel: IntelFeedViewModel) {
    val context = LocalContext.current
    val key = row.dayKey
    var confirmMarkDay by remember { mutableStateOf(false) }
    if (confirmMarkDay) {
        val scopeName = uiState.selectedFeedTitle ?: uiState.selectedCategoryName
        AlertDialog(
            onDismissRequest = { confirmMarkDay = false },
            title = { Text("Mark ${row.label} as read?") },
            text = {
                Text(
                    "Every unread article published on this day " +
                        (if (scopeName != null) "in \"$scopeName\"" else "in all of your feeds") +
                        " will be marked as read, including ones not loaded yet. This can't be undone."
                )
            },
            confirmButton = { TextButton(onClick = { confirmMarkDay = false; viewModel.markDayRead(key, row.label) }) { Text("Mark read") } },
            dismissButton = { TextButton(onClick = { confirmMarkDay = false }) { Text("Cancel") } }
        )
    }
    DayHeader(
        label = row.label,
        dayKey = key,
        dayIntel = uiState.dayIntel[key],
        dayIntelKnown = uiState.dayIntel.containsKey(key),
        onLoadDayIntel = { viewModel.loadDayIntel(key) },
        dailySummary = uiState.dailySummaries[key],
        summaryChecked = uiState.dailySummaries.containsKey(key),
        summaryLoading = key in uiState.dailySummaryLoading,
        summaryFailed = key in uiState.dailySummaryErrors,
        onRequestSummary = { viewModel.loadDailySummary(key) },
        serverUrl = uiState.serverUrl,
        onOpenLink = { url ->
            // Briefings link to articles as <server>/?entry=<id>: open those in the app.
            val entryId = InAppLinks.entryId(url, uiState.serverUrl)
            if (entryId != null) viewModel.openEntry(entryId) else ExternalLinks.openInBrowser(context, url)
        },
        activeFocus = uiState.dayFocus,
        onDayFocus = { focus -> viewModel.setDayFocus(focus) },
        onMarkDayRead = if (row.unread > 0) ({ confirmMarkDay = true }) else null
    )
}

private sealed interface FeedRow {
    val key: String

    data class Day(val label: String, val dayKey: String, override val key: String, val unread: Int = 0) : FeedRow

    data class Item(val entry: EntryItem) : FeedRow {
        override val key get() = entry.id
    }
}

/**
 * Swipe right to toggle read, swipe left to toggle the star. The row springs back after the
 * action instead of disappearing, so nothing leaves the list unexpectedly.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SwipeableEntry(
    entry: EntryItem,
    enabled: Boolean,
    onSwipeRead: () -> Unit,
    onSwipeStar: () -> Unit,
    content: @Composable () -> Unit
) {
    val state = rememberSwipeToDismissBoxState(positionalThreshold = { it * 0.35f })
    val scope = rememberCoroutineScope()
    // SwipeToDismissBox runs LaunchedEffect(settledValue, onDismiss) and calls onDismiss whenever the
    // row is settled in a swiped position. A new onDismiss on every recomposition restarted that
    // effect: the toggle re-rendered the card, onDismiss ran again while the row was still swiped,
    // and one swipe became a loop (star, unstar, star…: 328 requests in 10 seconds on the emulator).
    // So the callback is created once and reads the latest actions, and each swipe acts only once:
    // `acting` stays set until the row is back in place.
    val latestRead by rememberUpdatedState(onSwipeRead)
    val latestStar by rememberUpdatedState(onSwipeStar)
    val onDismiss = remember(state, scope) {
        val acting = AtomicBoolean(false)
        val callback: (SwipeToDismissBoxValue) -> Unit = { value ->
            if (value != SwipeToDismissBoxValue.Settled && acting.compareAndSet(false, true)) {
                if (value == SwipeToDismissBoxValue.StartToEnd) latestRead() else latestStar()
                scope.launch {
                    try {
                        state.reset()
                    } finally {
                        acting.set(false)
                    }
                }
            }
        }
        callback
    }
    SwipeToDismissBox(
        state = state,
        gesturesEnabled = enabled,
        onDismiss = onDismiss,
        backgroundContent = {
            val direction = state.dismissDirection
            val (color, icon, label, alignment) = when (direction) {
                SwipeToDismissBoxValue.StartToEnd -> SwipeVisual(
                    CyberBlue, if (entry.isRead) Icons.Default.MarkEmailUnread else Icons.Default.MarkEmailRead,
                    if (entry.isRead) "Mark unread" else "Mark read", Alignment.CenterStart
                )
                SwipeToDismissBoxValue.EndToStart -> SwipeVisual(
                    CyberAmber, if (entry.isStarred) Icons.Default.StarBorder else Icons.Default.Star,
                    if (entry.isStarred) "Unstar" else "Star", Alignment.CenterEnd
                )
                SwipeToDismissBoxValue.Settled -> SwipeVisual(Color.Transparent, null, "", Alignment.Center)
            }
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .clip(RoundedCornerShape(12.dp))
                    .background(color.copy(alpha = 0.25f))
                    .padding(horizontal = 20.dp),
                contentAlignment = alignment
            ) {
                if (icon != null) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(icon, contentDescription = null, tint = color)
                        Spacer(Modifier.width(8.dp))
                        Text(label, color = color, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                    }
                }
            }
        }
    ) {
        content()
    }
}

private data class SwipeVisual(
    val color: Color,
    val icon: androidx.compose.ui.graphics.vector.ImageVector?,
    val label: String,
    val alignment: Alignment
)
