package com.example.intelfeed.ui.screens

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Article
import androidx.compose.material.icons.automirrored.filled.VolumeOff
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Bookmark
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.DateRange
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.MarkEmailUnread
import androidx.compose.material.icons.automirrored.filled.Label
import androidx.compose.material.icons.filled.RssFeed
import androidx.compose.material.icons.filled.Schedule
import androidx.compose.material.icons.filled.SavedSearch
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.TrackChanges
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalDrawerSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.intelfeed.data.model.Category
import com.example.intelfeed.data.model.DiscoveredFeed
import com.example.intelfeed.data.model.SavedSearch
import com.example.intelfeed.ui.components.AddFeedDialog
import com.example.intelfeed.data.model.FeedSource
import com.example.intelfeed.data.repository.FeedFilter
import com.example.intelfeed.theme.CyberAmber
import com.example.intelfeed.theme.CyberBlue
import com.example.intelfeed.theme.CyberRed
import com.example.intelfeed.theme.SlateDark700
import com.example.intelfeed.theme.SlateDark800
import com.example.intelfeed.theme.SlateDark900
import com.example.intelfeed.theme.TextMuted
import com.example.intelfeed.theme.TextPrimary
import com.example.intelfeed.theme.TextSecondary
import com.example.intelfeed.ui.IntelFeedUiState
import com.example.intelfeed.ui.i18n.LocalStrings
import com.example.intelfeed.ui.i18n.localizedLabel

private const val UNCATEGORIZED = "__uncategorized__"
private const val MUTED = "__muted__"

/** One row of the flattened category tree. */
private sealed interface DrawerRow {
    val key: String

    data class CategoryRow(val category: Category, val depth: Int, val unread: Int, val feedCount: Int, val expanded: Boolean, val hasContent: Boolean) : DrawerRow {
        override val key get() = "c:${category.id}"
    }

    data class FeedRow(val feed: FeedSource, val depth: Int) : DrawerRow {
        override val key get() = "f:${feed.id}"
    }
}

@Composable
fun FeedDrawerSheet(
    uiState: IntelFeedUiState,
    onFilterSelect: (FeedFilter) -> Unit,
    onCategorySelect: (String, String) -> Unit,
    onFeedSelect: (String, String) -> Unit,
    onOpenSettings: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
    // Saved searches are listed (with their unread counts) when this is set.
    onOpenSavedSearch: ((SavedSearch) -> Unit)? = null,
    onDeleteSavedSearch: ((SavedSearch) -> Unit)? = null,
    // Tracked keywords: the section shows when onKeywordSearch is set.
    onKeywordSearch: ((String) -> Unit)? = null,
    onAddKeyword: (keyword: String, alsoOnServer: Boolean) -> Unit = { _, _ -> },
    onRemoveKeyword: (String) -> Unit = {},
    // The server's intelligence requirements (shared keyword matching). Row hidden when null.
    onOpenRequirements: (() -> Unit)? = null,
    // Add Feed. The button is hidden when onDiscoverFeeds is null.
    onDiscoverFeeds: ((url: String, onResult: (Result<List<DiscoveredFeed>>) -> Unit) -> Unit)? = null,
    onSubscribe: (feed: DiscoveredFeed, categoryId: String?, intervalMinutes: Int?) -> Unit = { _, _, _ -> },
    onAddArticle: (url: String) -> Unit = {}
) {
    var expanded by rememberSaveable { mutableStateOf(setOf<String>()) }
    var feedQuery by rememberSaveable { mutableStateOf("") }
    var showAddFeedDialog by rememberSaveable { mutableStateOf(false) }
    var showAddKeyword by rememberSaveable { mutableStateOf(false) }
    var keywordToRemove by rememberSaveable { mutableStateOf<String?>(null) }
    var searchToDelete by remember { mutableStateOf<SavedSearch?>(null) }
    val scoped = uiState.selectedCategoryId != null || uiState.selectedFeedId != null

    val activeFeeds = remember(uiState.feeds) { uiState.feeds.filter { !it.isMuted } }
    val mutedFeeds = remember(uiState.feeds) { uiState.feeds.filter { it.isMuted } }

    val feedsByCategory = remember(activeFeeds) { activeFeeds.groupBy { it.categoryId ?: UNCATEGORIZED } }
    val knownCategoryIds = remember(uiState.categories) {
        buildSet {
            fun collect(c: Category) { add(c.id); c.children.forEach(::collect) }
            uiState.categories.forEach(::collect)
        }
    }
    val uncategorized = remember(activeFeeds, knownCategoryIds) { activeFeeds.filter { it.categoryId == null || it.categoryId !in knownCategoryIds } }

    val rows: List<DrawerRow> = remember(uiState.categories, activeFeeds, mutedFeeds, expanded, feedQuery) {
        if (feedQuery.isNotBlank()) {
            uiState.feeds.filter { it.displayTitle.contains(feedQuery.trim(), ignoreCase = true) }
                .sortedBy { it.displayTitle.lowercase() }
                .map { DrawerRow.FeedRow(it, 0) }
        } else buildList<DrawerRow> {
            fun unreadIn(c: Category): Int = (feedsByCategory[c.id]?.sumOf { it.unreadCount } ?: 0) + c.children.sumOf { unreadIn(it) }
            fun feedsIn(c: Category): Int = (feedsByCategory[c.id]?.size ?: 0) + c.children.sumOf { feedsIn(it) }
            fun addCategory(c: Category, depth: Int) {
                val isOpen = c.id in expanded
                val own = feedsByCategory[c.id].orEmpty()
                add(DrawerRow.CategoryRow(c, depth, unreadIn(c), feedsIn(c).takeIf { it > 0 } ?: c.feedCount, isOpen, own.isNotEmpty() || c.children.isNotEmpty()))
                if (isOpen) {
                    c.children.sortedBy { it.position }.forEach { addCategory(it, depth + 1) }
                    own.sortedBy { it.displayTitle.lowercase() }.forEach { add(DrawerRow.FeedRow(it, depth + 1)) }
                }
            }
            uiState.categories.sortedBy { it.position }.forEach { addCategory(it, 0) }
            if (uncategorized.isNotEmpty()) {
                val isOpen = UNCATEGORIZED in expanded
                add(DrawerRow.CategoryRow(Category(UNCATEGORIZED, "Uncategorized"), 0, uncategorized.sumOf { it.unreadCount }, uncategorized.size, isOpen, true))
                if (isOpen) uncategorized.sortedBy { it.displayTitle.lowercase() }.forEach { add(DrawerRow.FeedRow(it, 1)) }
            }
            if (mutedFeeds.isNotEmpty()) {
                val isMutedOpen = MUTED in expanded
                add(DrawerRow.CategoryRow(Category(MUTED, "Muted Feeds"), 0, mutedFeeds.sumOf { it.unreadCount }, mutedFeeds.size, isMutedOpen, true))
                if (isMutedOpen) mutedFeeds.sortedBy { it.displayTitle.lowercase() }.forEach { add(DrawerRow.FeedRow(it, 1)) }
            }
        }
    }

    val strings = LocalStrings.current

    if (showAddKeyword) {
        var text by rememberSaveable { mutableStateOf("") }
        var alsoOnServer by rememberSaveable { mutableStateOf(false) }
        AlertDialog(
            onDismissRequest = { showAddKeyword = false },
            title = { Text(strings.drawerTrackKeyword) },
            text = {
                Column {
                    Text(
                        "A word or phrase to watch for. It's highlighted wherever it appears in an article, and if background alerts are on you're notified when a new article mentions it. Your keyword list is kept on this device.",
                        fontSize = 13.sp,
                        color = TextMuted
                    )
                    Spacer(Modifier.height(10.dp))
                    OutlinedTextField(value = text, onValueChange = { text = it }, singleLine = true, placeholder = { Text("e.g. device code phishing") }, modifier = Modifier.fillMaxWidth())
                    if (onOpenRequirements != null) {
                        // Opt-in: a requirement is shared with everyone on the server, so it's never created silently.
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.fillMaxWidth().padding(top = 8.dp).clip(RoundedCornerShape(8.dp))
                                .toggleable(value = alsoOnServer, role = Role.Checkbox, onValueChange = { alsoOnServer = it })
                        ) {
                            Checkbox(checked = alsoOnServer, onCheckedChange = null)
                            Spacer(Modifier.width(8.dp))
                            Column {
                                Text("Also add as a server requirement", fontSize = 14.sp, color = TextPrimary)
                                Text("Shared with everyone on your server; the server then tags every matching article, as on the website.", fontSize = 12.sp, color = TextMuted)
                            }
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(enabled = text.trim().length >= 2, onClick = { onAddKeyword(text, alsoOnServer); showAddKeyword = false }) { Text(strings.drawerTrack) }
            },
            dismissButton = { TextButton(onClick = { showAddKeyword = false }) { Text(strings.drawerCancel) } }
        )
    }
    keywordToRemove?.let { keyword ->
        AlertDialog(
            onDismissRequest = { keywordToRemove = null },
            title = { Text("Stop tracking \"$keyword\"?") },
            text = { Text("It won't be highlighted or notified any more.") },
            confirmButton = { TextButton(onClick = { onRemoveKeyword(keyword); keywordToRemove = null }) { Text("Stop tracking") } },
            dismissButton = { TextButton(onClick = { keywordToRemove = null }) { Text("Cancel") } }
        )
    }
    searchToDelete?.let { saved ->
        AlertDialog(
            onDismissRequest = { searchToDelete = null },
            title = { Text("Delete saved search?") },
            text = { Text("“${saved.label}” will be removed. Your articles won’t be affected.") },
            confirmButton = {
                TextButton(onClick = {
                    onDeleteSavedSearch?.invoke(saved)
                    searchToDelete = null
                }) { Text("Delete", color = CyberRed) }
            },
            dismissButton = { TextButton(onClick = { searchToDelete = null }) { Text("Cancel") } }
        )
    }

    if (showAddFeedDialog && onDiscoverFeeds != null) {
        AddFeedDialog(
            categories = uiState.categories,
            onDismiss = { showAddFeedDialog = false },
            onDiscover = onDiscoverFeeds,
            onSubscribe = onSubscribe,
            onAddArticle = onAddArticle
        )
    }

    ModalDrawerSheet(modifier = modifier.width(320.dp), drawerContainerColor = SlateDark900) {
        Column(Modifier.fillMaxSize()) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(start = 20.dp, end = 8.dp, top = 16.dp, bottom = 4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(Icons.Default.Shield, contentDescription = null, tint = CyberBlue, modifier = Modifier.size(24.dp))
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Text("IntelFeed", style = MaterialTheme.typography.titleMedium, color = TextPrimary, fontWeight = FontWeight.Bold)
                    uiState.username?.let { Text("@$it", fontSize = 12.sp, color = TextMuted) }
                }
                IconButton(onClick = onOpenSettings) { Icon(Icons.Default.Settings, contentDescription = strings.drawerAccountSettings, tint = TextSecondary) }
            }

            // "Find a feed" sits below the views, keywords and saved searches, so its results used to
            // appear under the keyboard. Typing scrolls the feed section to the top, and the list
            // stays above the keyboard.
            val listState = rememberLazyListState()
            LaunchedEffect(feedQuery.isNotBlank()) {
                if (feedQuery.isNotBlank()) listState.animateScrollToItem(1)
            }
            LazyColumn(state = listState, modifier = Modifier.weight(1f).imePadding().padding(horizontal = 12.dp)) {
                item {
                    SectionLabel(strings.drawerHeaderViews)
                    FeedFilter.entries.forEach { filter ->
                        DrawerItem(
                            icon = filterIcon(filter),
                            title = filter.localizedLabel(strings),
                            isSelected = uiState.selectedFilter == filter && !scoped,
                            count = uiState.viewCounts.forFilter(filter),
                            onClick = { onFilterSelect(filter) }
                        )
                    }
                    if (onKeywordSearch != null) {
                        HorizontalDivider(modifier = Modifier.padding(vertical = 10.dp), color = SlateDark700)
                        Row(
                            modifier = Modifier.fillMaxWidth().padding(end = 4.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            SectionLabel(strings.drawerHeaderKeywords)
                            TextButton(
                                onClick = { showAddKeyword = true },
                                contentPadding = androidx.compose.foundation.layout.PaddingValues(horizontal = 8.dp, vertical = 0.dp)
                            ) {
                                Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(16.dp), tint = CyberBlue)
                                Spacer(Modifier.width(4.dp))
                                Text(strings.drawerAdd, fontSize = 12.sp, color = CyberBlue)
                            }
                        }
                        if (uiState.trackedKeywords.isEmpty()) {
                            Text(
                                "Track words or phrases: they're highlighted in articles, and new matches can notify you.",
                                fontSize = 12.sp,
                                color = TextMuted,
                                modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp)
                            )
                        }
                        uiState.trackedKeywords.forEach { keyword ->
                            KeywordItem(keyword = keyword, onClick = { onKeywordSearch(keyword) }, onRemove = { keywordToRemove = keyword })
                        }
                        if (onOpenRequirements != null) {
                            DrawerItem(icon = Icons.Default.TrackChanges, title = strings.drawerServerRequirements, isSelected = false, onClick = onOpenRequirements)
                        }
                    }
                    if (uiState.savedSearches.isNotEmpty() && onOpenSavedSearch != null) {
                        HorizontalDivider(modifier = Modifier.padding(vertical = 10.dp), color = SlateDark700)
                        SectionLabel("SAVED SEARCHES")
                        uiState.savedSearches.forEach { saved ->
                            SavedSearchItem(
                                saved = saved,
                                onClick = { onOpenSavedSearch(saved) },
                                onDelete = if (onDeleteSavedSearch != null) { { searchToDelete = saved } } else null
                            )
                        }
                    }
                    HorizontalDivider(modifier = Modifier.padding(vertical = 10.dp), color = SlateDark700)
                }
                // Its own item (index 1), so typing a feed search can scroll it to the top.
                item(key = "feeds-header") {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(end = 4.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        SectionLabel(strings.drawerHeaderFoldersFeeds)
                        if (onDiscoverFeeds != null) {
                            TextButton(
                                onClick = { showAddFeedDialog = true },
                                contentPadding = androidx.compose.foundation.layout.PaddingValues(horizontal = 8.dp, vertical = 0.dp)
                            ) {
                                Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(16.dp), tint = CyberBlue)
                                Spacer(Modifier.width(4.dp))
                                Text(strings.drawerAdd, fontSize = 12.sp, color = CyberBlue)
                            }
                        }
                    }
                    OutlinedTextField(
                        value = feedQuery,
                        onValueChange = { feedQuery = it },
                        placeholder = { Text(strings.drawerFindFeed, color = TextMuted) },
                        leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = TextMuted) },
                        trailingIcon = if (feedQuery.isNotEmpty()) {
                            { IconButton(onClick = { feedQuery = "" }) { Icon(Icons.Default.Close, contentDescription = "Clear", tint = TextMuted) } }
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
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 4.dp, vertical = 4.dp)
                    )
                    if (uiState.drawerError != null) {
                        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(horizontal = 8.dp)) {
                            Text(uiState.drawerError, color = CyberAmber, fontSize = 12.sp, modifier = Modifier.weight(1f))
                            TextButton(onClick = onRetry) { Text("Retry") }
                        }
                    }
                    if (feedQuery.isNotBlank() && rows.isEmpty()) {
                        Text("No feed matches \"$feedQuery\"", color = TextMuted, fontSize = 13.sp, modifier = Modifier.padding(12.dp))
                    }
                }

                items(rows, key = { it.key }) { row ->
                    when (row) {
                        is DrawerRow.CategoryRow -> CategoryItem(
                            row = row,
                            isSelected = uiState.selectedCategoryId == row.category.id,
                            onSelect = { if (row.category.id != UNCATEGORIZED && row.category.id != MUTED) onCategorySelect(row.category.id, row.category.name) else expanded = expanded.toggle(row.category.id) },
                            onToggle = { expanded = expanded.toggle(row.category.id) }
                        )
                        is DrawerRow.FeedRow -> FeedItem(
                            feed = row.feed,
                            depth = row.depth,
                            isSelected = uiState.selectedFeedId == row.feed.id,
                            onClick = { onFeedSelect(row.feed.id, row.feed.displayTitle) }
                        )
                    }
                }
            }
        }
    }
}

private fun Set<String>.toggle(id: String) = if (id in this) this - id else this + id

private fun filterIcon(filter: FeedFilter): ImageVector = when (filter) {
    FeedFilter.PRIORITY_QUEUE -> Icons.Default.Bolt
    FeedFilter.UNREAD -> Icons.Default.MarkEmailUnread
    FeedFilter.LAST_24H -> Icons.Default.Schedule
    FeedFilter.THIS_WEEK -> Icons.Default.DateRange
    FeedFilter.WATCHED -> Icons.Default.Visibility
    FeedFilter.ALL -> Icons.AutoMirrored.Filled.Article
    FeedFilter.STARRED -> Icons.Default.Star
    FeedFilter.BOOKMARKED -> Icons.Default.Bookmark
}

@Composable
private fun SectionLabel(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.labelSmall,
        color = TextMuted,
        modifier = Modifier.padding(start = 12.dp, top = 8.dp, bottom = 6.dp)
    )
}

@Composable
private fun CategoryItem(row: DrawerRow.CategoryRow, isSelected: Boolean, onSelect: () -> Unit, onToggle: () -> Unit) {
    Surface(
        shape = RoundedCornerShape(8.dp),
        color = if (isSelected) CyberBlue.copy(alpha = 0.15f) else Color.Transparent,
        modifier = Modifier.fillMaxWidth().padding(start = (row.depth * 14).dp, top = 1.dp, bottom = 1.dp).clip(RoundedCornerShape(8.dp)).clickable(onClick = onSelect)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(start = 12.dp)) {
            val folderIcon = when {
                row.category.id == MUTED -> Icons.AutoMirrored.Filled.VolumeOff
                row.expanded -> Icons.Default.FolderOpen
                else -> Icons.Default.Folder
            }
            Icon(
                imageVector = folderIcon,
                contentDescription = null,
                tint = if (isSelected) CyberBlue else TextMuted,
                modifier = Modifier.size(18.dp)
            )
            Spacer(Modifier.width(10.dp))
            Text(
                text = row.category.name,
                style = MaterialTheme.typography.bodyMedium,
                color = if (isSelected) CyberBlue else TextPrimary,
                fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f)
            )
            UnreadCount(row.unread)
            if (row.hasContent) {
                IconButton(onClick = onToggle) {
                    Icon(
                        imageVector = if (row.expanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                        contentDescription = if (row.expanded) "Collapse ${row.category.name}" else "Show feeds in ${row.category.name}",
                        tint = TextMuted
                    )
                }
            } else {
                Spacer(Modifier.width(48.dp))
            }
        }
    }
}

@Composable
private fun FeedItem(feed: FeedSource, depth: Int, isSelected: Boolean, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(start = (depth * 14).dp)
            .clip(RoundedCornerShape(8.dp))
            .background(if (isSelected) CyberBlue.copy(alpha = 0.18f) else Color.Transparent)
            .clickable(onClick = onClick)
            .padding(horizontal = 12.dp, vertical = 11.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        val feedIcon = if (feed.isMuted) Icons.AutoMirrored.Filled.VolumeOff else Icons.Default.RssFeed
        Icon(
            feedIcon,
            contentDescription = null,
            tint = if (isSelected) CyberBlue else if (feed.isMuted) TextMuted.copy(alpha = 0.6f) else TextMuted,
            modifier = Modifier.size(15.dp)
        )
        Spacer(Modifier.width(10.dp))
        Text(
            text = feed.displayTitle,
            style = MaterialTheme.typography.bodySmall,
            color = when {
                isSelected -> CyberBlue
                feed.isMuted -> TextMuted
                else -> TextPrimary
            },
            fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.weight(1f)
        )
        if (feed.isMuted) {
            Text("(muted)", color = TextMuted, fontSize = 10.sp, modifier = Modifier.padding(horizontal = 4.dp))
        }
        if (feed.errorCount > 0) {
            Text(
                "⚠",
                color = CyberAmber,
                fontSize = 12.sp,
                modifier = Modifier.padding(horizontal = 4.dp).semantics { contentDescription = "Fetch errors" }
            )
        }
        UnreadCount(feed.unreadCount)
    }
}

@Composable
private fun UnreadCount(count: Int) {
    if (count <= 0) return
    Surface(color = CyberBlue.copy(alpha = 0.18f), shape = RoundedCornerShape(10.dp)) {
        Text(
            text = if (count > 999) "999+" else "$count",
            fontSize = 11.sp,
            color = CyberBlue,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(horizontal = 7.dp, vertical = 1.dp)
        )
    }
}

/** A tracked keyword: tap searches for it; the ✕ stops tracking it (after a confirmation). */
@Composable
private fun KeywordItem(keyword: String, onClick: () -> Unit, onRemove: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .clickable(onClickLabel = "Search for $keyword", onClick = onClick)
            .padding(start = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(Icons.AutoMirrored.Filled.Label, contentDescription = null, tint = CyberAmber, modifier = Modifier.size(18.dp))
        Spacer(Modifier.width(12.dp))
        Text(keyword, style = MaterialTheme.typography.bodyMedium, color = TextPrimary, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
        IconButton(onClick = onRemove) { Icon(Icons.Default.Close, contentDescription = "Stop tracking $keyword", tint = TextMuted, modifier = Modifier.size(18.dp)) }
    }
}

/** A saved search: opens it on the Search tab. The badge is its unread count; the total is shown beside the query. */
@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun SavedSearchItem(
    saved: SavedSearch,
    onClick: () -> Unit,
    onDelete: (() -> Unit)? = null
) {
    Surface(
        shape = RoundedCornerShape(8.dp),
        color = Color.Transparent,
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 1.dp)
            .clip(RoundedCornerShape(8.dp))
            .combinedClickable(
                onClickLabel = "Run saved search",
                onClick = onClick,
                onLongClick = onDelete
            )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 12.dp, end = 4.dp, top = 6.dp, bottom = 6.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(Icons.Default.SavedSearch, contentDescription = null, tint = TextMuted, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(saved.label, style = MaterialTheme.typography.bodyMedium, color = TextPrimary, maxLines = 1, overflow = TextOverflow.Ellipsis)
                val detail = listOfNotNull(
                    saved.query.takeIf { it != saved.label },
                    saved.totalCount?.let { if (it == 1) "1 article" else "$it articles" }
                ).joinToString(" · ")
                if (detail.isNotEmpty()) Text(detail, fontSize = 11.sp, color = TextMuted, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            UnreadCount(saved.unreadCount ?: 0)
            if (onDelete != null) {
                IconButton(onClick = onDelete) {
                    Icon(
                        Icons.Default.Close,
                        contentDescription = "Delete saved search ${saved.label}",
                        tint = TextMuted,
                        modifier = Modifier.size(18.dp)
                    )
                }
            }
        }
    }
}

/** A quick view. [count] is its unread count (the web sidebar's numbers); null hides the badge. */
@Composable
private fun DrawerItem(icon: ImageVector, title: String, isSelected: Boolean, count: Int? = null, onClick: () -> Unit) {
    Surface(
        shape = RoundedCornerShape(8.dp),
        color = if (isSelected) CyberBlue.copy(alpha = 0.15f) else Color.Transparent,
        modifier = Modifier.fillMaxWidth().padding(vertical = 1.dp).clip(RoundedCornerShape(8.dp)).clickable(onClick = onClick)
    ) {
        Row(modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.Start) {
            Icon(icon, contentDescription = null, tint = if (isSelected) CyberBlue else TextMuted, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(12.dp))
            Text(
                text = title,
                style = MaterialTheme.typography.bodyMedium,
                color = if (isSelected) CyberBlue else TextPrimary,
                fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal,
                modifier = Modifier.weight(1f)
            )
            if (count != null) UnreadCount(count)
        }
    }
}
