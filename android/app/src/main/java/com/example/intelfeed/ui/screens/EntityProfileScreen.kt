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
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Article
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Hub
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.automirrored.filled.Notes
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.PrimaryScrollableTabRow
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.intelfeed.LocalSnackbarHostState
import com.example.intelfeed.data.model.EntityNote
import com.example.intelfeed.data.model.EntityRelationship
import com.example.intelfeed.data.model.EntityType
import com.example.intelfeed.theme.CyberAmber
import com.example.intelfeed.theme.CyberBlue
import com.example.intelfeed.theme.CyberGreen
import com.example.intelfeed.theme.CyberRed
import com.example.intelfeed.theme.SlateDark600
import com.example.intelfeed.theme.SlateDark700
import com.example.intelfeed.theme.SlateDark800
import com.example.intelfeed.theme.SlateDark900
import com.example.intelfeed.theme.TextMuted
import com.example.intelfeed.theme.TextPrimary
import com.example.intelfeed.theme.TextSecondary
import com.example.intelfeed.ui.components.CardSurface
import com.example.intelfeed.ui.components.CodeBlock
import com.example.intelfeed.ui.components.EmptyState
import com.example.intelfeed.ui.components.EntryCard
import com.example.intelfeed.ui.components.ErrorState
import com.example.intelfeed.ui.components.FactRow
import com.example.intelfeed.ui.components.InlineLoading
import com.example.intelfeed.ui.components.LoadMoreButton
import com.example.intelfeed.ui.components.LoadingBox
import com.example.intelfeed.ui.components.Pill
import com.example.intelfeed.ui.components.SectionHeader
import com.example.intelfeed.ui.components.color
import com.example.intelfeed.ui.entity.EntityProfile
import com.example.intelfeed.ui.entity.EntityRef
import com.example.intelfeed.ui.entity.EntityUiState
import com.example.intelfeed.ui.entity.EntityViewModel
import com.example.intelfeed.util.Clipboard
import com.example.intelfeed.util.ExternalLinks
import java.text.NumberFormat
import java.util.Locale

private enum class ProfileTab(val label: String) { OVERVIEW("Overview"), TIMELINE("Timeline"), ARTICLES("Articles"), RELATIONSHIPS("Relationships"), NOTES("Notes") }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EntityProfileScreen(
    viewModel: EntityViewModel,
    type: EntityType,
    fallbackTitle: String,
    onBack: () -> Unit,
    onOpenEntry: (String, List<String>) -> Unit,
    onOpenEntity: (EntityRef) -> Unit,
    onOpenThread: (String, String?) -> Unit = { _, _ -> }
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val profile = state.profile
    var menuOpen by remember { mutableStateOf(false) }
    var tab by rememberSaveable { mutableStateOf(ProfileTab.OVERVIEW) }
    var editing by remember { mutableStateOf<EntityNoteDraft?>(null) }
    var noteToDelete by remember { mutableStateOf<EntityNote?>(null) }

    // A placeholder profile (no server record) only has the overview and the Articles search.
    val placeholder = profile?.placeholder == true
    val tabs = remember(type, placeholder) {
        buildList {
            add(ProfileTab.OVERVIEW)
            if (type.timelinePath != null && !placeholder) add(ProfileTab.TIMELINE)
            if (type.searchField != null) add(ProfileTab.ARTICLES)
            if (type != EntityType.RULE && !placeholder) { add(ProfileTab.RELATIONSHIPS); add(ProfileTab.NOTES) }
        }
    }
    LaunchedEffect(tab, profile) {
        when (tab) {
            ProfileTab.RELATIONSHIPS -> viewModel.loadRelationships()
            ProfileTab.NOTES -> viewModel.loadNotes()
            ProfileTab.TIMELINE -> viewModel.loadTimeline()
            else -> Unit
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back", tint = TextPrimary) } },
                title = {
                    Column {
                        Text(type.label.uppercase(Locale.US), fontSize = 11.sp, color = type.color(), fontWeight = FontWeight.Bold)
                        Text(profile?.title ?: fallbackTitle, fontSize = 17.sp, fontWeight = FontWeight.Bold, color = TextPrimary, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                },
                actions = {
                    if (profile != null) {
                        IconButton(onClick = { menuOpen = true }) { Icon(Icons.Default.MoreVert, contentDescription = "More", tint = TextSecondary) }
                        DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                            if (type.watchable && !profile.placeholder) {
                                DropdownMenuItem(
                                    text = { Text(if (state.watchMode == "mute") "Unmute" else "Mute in Priority Queue") },
                                    leadingIcon = { Icon(Icons.Default.VisibilityOff, null) },
                                    onClick = { menuOpen = false; viewModel.setWatchMode("mute") }
                                )
                            }
                            DropdownMenuItem(
                                text = { Text("Copy name") },
                                leadingIcon = { Icon(Icons.Default.ContentCopy, null) },
                                onClick = { menuOpen = false; Clipboard.copy(context, type.label, profile.title) }
                            )
                        }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = SlateDark900)
            )
        },
        snackbarHost = { SnackbarHost(LocalSnackbarHostState.current) },
        containerColor = SlateDark900
    ) { padding ->
        when {
            profile == null && state.loading -> LoadingBox(Modifier.padding(padding), color = type.color())
            profile == null -> ErrorState(state.error ?: "This profile couldn't be loaded.", onRetry = viewModel::load, modifier = Modifier.padding(padding).fillMaxSize())
            else -> LazyColumn(
                modifier = Modifier.fillMaxSize().padding(padding),
                contentPadding = PaddingValues(bottom = 32.dp)
            ) {
                item(key = "header") { ProfileHeader(profile, type, state, onWatch = { viewModel.setWatchMode(it) }) }
                if (tabs.size > 1) {
                    stickyHeader(key = "tabs") {
                        PrimaryScrollableTabRow(
                            selectedTabIndex = tabs.indexOf(tab).coerceAtLeast(0),
                            containerColor = SlateDark900,
                            contentColor = type.color(),
                            edgePadding = 12.dp,
                            divider = { HorizontalDivider(color = SlateDark700) }
                        ) {
                            tabs.forEach { t ->
                                val label = when (t) {
                                    ProfileTab.ARTICLES -> (state.articles.total ?: profile.articleCount.takeIf { it > 0 })?.let { "Articles · ${compact(it)}" } ?: t.label
                                    ProfileTab.NOTES -> if (state.notes.isNotEmpty()) "Notes · ${state.notes.size}" else t.label
                                    else -> t.label
                                }
                                Tab(selected = tab == t, onClick = { tab = t }, text = { Text(label, color = if (tab == t) type.color() else TextMuted) })
                            }
                        }
                    }
                }
                when (tab) {
                    ProfileTab.OVERVIEW -> overview(profile, onOpenEntity, onOpenSource = { id -> onOpenEntry(id, emptyList()) }, onLink = { ExternalLinks.openInBrowser(context, it) })
                    ProfileTab.TIMELINE -> timelineTab(
                        timeline = state.timeline,
                        type = type,
                        onWindow = viewModel::setMentionsWindow,
                        onOpenEntry = onOpenEntry,
                        onOpenEntity = onOpenEntity,
                        onOpenThread = onOpenThread,
                        onOpenLink = { ExternalLinks.openInBrowser(context, it) },
                        onMoreEvents = viewModel::showMoreEvents,
                        retry = { viewModel.loadTimeline(force = true) }
                    )
                    ProfileTab.ARTICLES -> articles(state, onOpenEntry, retry = { viewModel.loadArticles(reset = true) }, more = { viewModel.loadArticles() })
                    ProfileTab.RELATIONSHIPS -> relationships(
                        state, profile, onOpenEntity,
                        retry = { viewModel.loadRelationships(reset = true) },
                        more = { viewModel.loadRelationships() },
                        onGraphWindow = viewModel::setGraphWindow,
                        onOpenGraphNode = { node ->
                            val id = com.example.intelfeed.ui.entity.GraphLayout.entityId(node)
                            if (node.type == "entry") onOpenEntry(id, emptyList())
                            else EntityType.fromKey(node.type)?.let { onOpenEntity(EntityRef(it, id, node.label)) }
                        }
                    )
                    ProfileTab.NOTES -> notes(
                        state,
                        onAdd = { editing = EntityNoteDraft(null, "", "") },
                        onEdit = { editing = EntityNoteDraft(it, it.title.orEmpty(), it.content.orEmpty()) },
                        onDelete = { noteToDelete = it },
                        retry = { viewModel.loadNotes(force = true) }
                    )
                }
            }
        }
    }

    editing?.let { draft ->
        NoteEditor(
            heading = if (draft.existing == null) "New note on ${profile?.title ?: fallbackTitle}" else "Edit note",
            initialTitle = draft.title,
            initialBody = draft.body,
            initialPinned = false,
            showPin = false,
            hint = "Visible to everyone on your IntelFeed server.",
            onDismiss = { editing = null },
            onSave = { title, body, _, done ->
                viewModel.saveNote(draft.existing, title, body) { saved -> done(saved); if (saved) editing = null }
            }
        )
    }
    noteToDelete?.let { note ->
        AlertDialog(
            onDismissRequest = { noteToDelete = null },
            title = { Text("Delete this note?") },
            text = { Text("It's removed for everyone on the server.") },
            confirmButton = { TextButton(onClick = { viewModel.deleteNote(note); noteToDelete = null }) { Text("Delete", color = CyberRed) } },
            dismissButton = { TextButton(onClick = { noteToDelete = null }) { Text("Cancel") } }
        )
    }
}

private data class EntityNoteDraft(val existing: EntityNote?, val title: String, val body: String)

private fun compact(n: Int): String = NumberFormat.getIntegerInstance(Locale.US).format(n)

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ProfileHeader(profile: EntityProfile, type: EntityType, state: EntityUiState, onWatch: (String) -> Unit) {
    var expanded by rememberSaveable { mutableStateOf(false) }
    Column(Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
        Text(
            profile.title,
            fontSize = 24.sp,
            fontWeight = FontWeight.Bold,
            color = TextPrimary,
            fontFamily = if (profile.monospaceTitle) FontFamily.Monospace else FontFamily.Default
        )
        profile.subtitle?.let { Text(it, fontSize = 13.sp, color = TextMuted) }
        if (profile.badges.isNotEmpty()) {
            Spacer(Modifier.height(10.dp))
            FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                profile.badges.forEach { Pill(it.label, it.color()) }
            }
        }
        if (profile.aliases.isNotEmpty()) {
            Spacer(Modifier.height(10.dp))
            Text("Also known as " + profile.aliases.take(8).joinToString(", ") + if (profile.aliases.size > 8) " +${profile.aliases.size - 8}" else "",
                fontSize = 13.sp, color = TextSecondary)
        }
        profile.description?.takeIf { it.isNotBlank() }?.let { desc ->
            Spacer(Modifier.height(10.dp))
            Text(
                text = desc,
                fontSize = 15.sp,
                color = TextSecondary,
                lineHeight = 22.sp,
                maxLines = if (expanded) Int.MAX_VALUE else 5,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.animateContentSize().clickable { expanded = !expanded }
            )
            if (desc.length > 300) {
                TextButton(onClick = { expanded = !expanded }, contentPadding = PaddingValues(0.dp)) { Text(if (expanded) "Show less" else "Read more") }
            }
        }
        if (type.watchable && !profile.placeholder) {
            Spacer(Modifier.height(10.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                WatchChip(if (state.watchMode == "watch") "Watching" else "Watch", Icons.Default.Visibility, state.watchMode == "watch", CyberGreen, !state.watchBusy) { onWatch("watch") }
                WatchChip(if (state.watchMode == "mute") "Muted" else "Mute", Icons.Default.VisibilityOff, state.watchMode == "mute", CyberAmber, !state.watchBusy) { onWatch("mute") }
            }
            Text(
                when (state.watchMode) {
                    "watch" -> "Its articles get a boost in your Priority Queue."
                    "mute" -> "Its articles are hidden from your Priority Queue (not from search or feeds)."
                    else -> "Watch to boost its articles in your Priority Queue; mute to hide them. Only affects you."
                },
                fontSize = 12.sp,
                color = TextMuted,
                modifier = Modifier.padding(top = 4.dp)
            )
        }
        Spacer(Modifier.height(8.dp))
    }
}

@Composable
private fun WatchChip(label: String, icon: androidx.compose.ui.graphics.vector.ImageVector, selected: Boolean, color: androidx.compose.ui.graphics.Color, enabled: Boolean, onClick: () -> Unit) {
    FilterChip(
        selected = selected,
        enabled = enabled,
        onClick = onClick,
        label = { Text(label) },
        leadingIcon = { Icon(icon, contentDescription = null, modifier = Modifier.size(16.dp)) },
        colors = FilterChipDefaults.filterChipColors(
            selectedContainerColor = color.copy(alpha = 0.2f),
            selectedLabelColor = color,
            selectedLeadingIconColor = color,
            containerColor = SlateDark800,
            labelColor = TextSecondary,
            iconColor = TextSecondary
        ),
        border = FilterChipDefaults.filterChipBorder(enabled = enabled, selected = selected, borderColor = SlateDark600, selectedBorderColor = color)
    )
}

@OptIn(ExperimentalLayoutApi::class)
private fun LazyListScope.overview(
    profile: EntityProfile,
    onOpenEntity: (EntityRef) -> Unit,
    onOpenSource: (String) -> Unit,
    onLink: (String) -> Unit
) {
    item(key = "overview") {
        val context = LocalContext.current
        Column(Modifier.padding(horizontal = 16.dp)) {
            if (profile.facts.isNotEmpty()) {
                SectionHeader("Key facts")
                CardSurface {
                    Column(Modifier.padding(horizontal = 14.dp, vertical = 8.dp)) {
                        profile.facts.forEach { (label, value) -> FactRow(label, value) }
                    }
                }
            }
            profile.chipGroups.forEach { group ->
                SectionHeader(group.title)
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    group.chips.forEach { chip ->
                        val ref = chip.ref
                        Pill(
                            label = chip.label,
                            color = chip.color(),
                            onClick = ref?.let { { onOpenEntity(it) } },
                            onLongClick = { Clipboard.copy(context, group.title, chip.label) }
                        )
                    }
                }
            }

            if (profile.techniques.isNotEmpty()) {
                SectionHeader("ATT&CK techniques (${profile.techniques.size})")
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    profile.techniques.take(40).forEach { t ->
                        val id = t.techniqueId
                        CardSurface(modifier = Modifier.clip(RoundedCornerShape(12.dp)).then(
                            if (id != null) Modifier.clickable { onOpenEntity(EntityRef(EntityType.TTP, id, id)) } else Modifier
                        )) {
                            Row(Modifier.padding(horizontal = 12.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                                Text(id ?: "—", fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold, color = EntityType.TTP.color(), fontSize = 13.sp)
                                Spacer(Modifier.width(10.dp))
                                Column(Modifier.weight(1f)) {
                                    Text(t.techniqueName ?: "", fontSize = 14.sp, color = TextPrimary, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                    t.tactic?.let { Text(it.replace('-', ' '), fontSize = 12.sp, color = TextMuted) }
                                }
                                if (t.count > 1) Text("${t.count}×", fontSize = 12.sp, color = TextMuted)
                            }
                        }
                    }
                    if (profile.techniques.size > 40) Text("+${profile.techniques.size - 40} more", fontSize = 12.sp, color = TextMuted)
                }
            }
            profile.sections.forEach { (title, body) ->
                SectionHeader(title)
                Text(body, fontSize = 14.sp, color = TextSecondary, lineHeight = 21.sp)
            }
            profile.code?.let {
                SectionHeader("Rule")
                CodeBlock(it)
            }
            profile.sourceEntryId?.let { id ->
                Spacer(Modifier.height(12.dp))
                TextButton(onClick = { onOpenSource(id) }) {
                    Icon(Icons.AutoMirrored.Filled.Article, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("Open the article this rule came from")
                }
            }
            if (profile.links.isNotEmpty()) {
                SectionHeader("Look it up elsewhere")
                CardSurface {
                    Column {
                        profile.links.forEachIndexed { i, link ->
                            if (i > 0) HorizontalDivider(color = SlateDark600)
                            Row(
                                modifier = Modifier.fillMaxWidth().clickable { onLink(link.url) }.padding(horizontal = 14.dp, vertical = 14.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(link.label, fontSize = 14.sp, color = CyberBlue, modifier = Modifier.weight(1f))
                                Icon(Icons.AutoMirrored.Filled.OpenInNew, contentDescription = null, tint = TextMuted, modifier = Modifier.size(16.dp))
                            }
                        }
                    }
                }
            }
        }
    }
}

private fun LazyListScope.articles(
    state: EntityUiState,
    onOpenEntry: (String, List<String>) -> Unit,
    retry: () -> Unit,
    more: () -> Unit
) {
    val section = state.articles
    when {
        section.items.isEmpty() && section.loading -> item(key = "a-loading") { InlineLoading() }
        section.items.isEmpty() && section.error != null -> item(key = "a-error") { ErrorState(section.error, onRetry = retry) }
        section.items.isEmpty() && section.loaded -> item(key = "a-empty") {
            EmptyState(Icons.AutoMirrored.Filled.Article, "No articles found", "No article in the search index links to this entity yet.")
        }
        else -> {
            item(key = "a-count", contentType = "header") {
                section.total?.let { Text("${compact(it)} articles, newest first", fontSize = 12.sp, color = TextMuted, modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) }
            }
            val itemIds = section.items.map { it.id }
            items(section.items, key = { "a:" + it.id }, contentType = { "entity_article" }) { entry ->
                EntryCard(
                    entry = entry,
                    onClick = { onOpenEntry(entry.id, itemIds) },
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 5.dp)
                )
            }
            if (section.hasMore) item(key = "a-more", contentType = "more") { LoadMoreButton("Load more articles", section.loading, more) }
        }
    }
}

/** How a relationship reads from the other side: "APT29 uses X" seen from X is "used by APT29". */
private fun inverseVerb(verb: String): String = when (verb) {
    "uses" -> "used by"
    "exploits" -> "exploited by"
    "targets" -> "targeted by"
    "attributed_to" -> "attribution of"
    "variant_of" -> "has variant"
    "delivers" -> "delivered by"
    "drops" -> "dropped by"
    "hosts" -> "hosted by"
    else -> verb.replace('_', ' ')
}

private fun LazyListScope.relationships(
    state: EntityUiState,
    profile: EntityProfile,
    onOpenEntity: (EntityRef) -> Unit,
    retry: () -> Unit,
    more: () -> Unit,
    onGraphWindow: (Int?) -> Unit = {},
    onOpenGraphNode: (com.example.intelfeed.data.model.GraphNode) -> Unit = {}
) {
    val section = state.relationships
    // The web's relationship graph, above the list.
    if (profile.ref.type.timelinePath != null) item(key = "r-graph", contentType = "graph") {
        com.example.intelfeed.ui.entity.EntityGraphView(
            graph = state.graph,
            loading = state.graphLoading,
            error = state.graphError,
            windowDays = state.graphWindowDays,
            onWindow = onGraphWindow,
            onOpenNode = onOpenGraphNode,
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)
        )
    }
    when {
        section.items.isEmpty() && (section.loading || !section.loaded) -> item(key = "r-loading") { InlineLoading() }
        section.items.isEmpty() && section.error != null -> item(key = "r-error") { ErrorState(section.error, onRetry = retry) }
        section.items.isEmpty() -> item(key = "r-empty") {
            EmptyState(Icons.Default.Hub, "No relationships yet", "Relationships appear once articles or ATT&CK connect this entity to others.")
        }
        else -> {
            item(key = "r-intro", contentType = "intro") {
                Text(
                    "Built from articles that name both, plus MITRE ATT&CK. Tap one to open it.",
                    fontSize = 12.sp, color = TextMuted, modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)
                )
            }
            items(section.items, key = { "r:" + it.id }, contentType = { "relationship" }) { rel -> RelationshipRow(rel, profile, onOpenEntity) }
            if (section.hasMore) item(key = "r-more", contentType = "more") { LoadMoreButton("Load more", section.loading, more) }
        }
    }
}

@Composable
private fun RelationshipRow(rel: EntityRelationship, profile: EntityProfile, onOpenEntity: (EntityRef) -> Unit) {
    val outgoing = rel.sourceId == profile.serverId
    val otherType = EntityType.fromKey(if (outgoing) rel.targetType else rel.sourceType)
    val otherId = if (outgoing) rel.targetId else rel.sourceId
    val otherName = (if (outgoing) rel.targetName else rel.sourceName) ?: otherId
    val verb = if (outgoing) rel.relationshipType.replace('_', ' ') else inverseVerb(rel.relationshipType)
    CardSurface(
        modifier = Modifier
            .padding(horizontal = 16.dp, vertical = 4.dp)
            .clip(RoundedCornerShape(12.dp))
            .then(if (otherType != null) Modifier.clickable { onOpenEntity(EntityRef(otherType, otherId, otherName)) } else Modifier)
    ) {
        Column(Modifier.padding(12.dp)) {
            Text(verb, fontSize = 12.sp, color = TextMuted)
            Spacer(Modifier.height(2.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(otherName, fontSize = 15.sp, fontWeight = FontWeight.SemiBold, color = otherType?.color() ?: TextPrimary, modifier = Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis)
                otherType?.let { Text(it.label, fontSize = 11.sp, color = TextMuted) }
            }
            Spacer(Modifier.height(6.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                rel.confidence?.let {
                    Pill(it.replaceFirstChar { c -> c.titlecase(Locale.US) }, when (it) { "confirmed" -> CyberGreen; "probable" -> CyberBlue; else -> TextSecondary })
                }
                if (rel.evidenceEntryIds.isNotEmpty()) {
                    Pill("${rel.evidenceEntryIds.size} ${if (rel.evidenceEntryIds.size == 1) "source" else "sources"}", TextSecondary)
                }
                rel.source?.takeIf { it.startsWith("analyst") }?.let { Pill("Analyst", CyberAmber) }
            }
        }
    }
}

private fun LazyListScope.notes(
    state: EntityUiState,
    onAdd: () -> Unit,
    onEdit: (EntityNote) -> Unit,
    onDelete: (EntityNote) -> Unit,
    retry: () -> Unit
) {
    item(key = "n-add", contentType = "add_note") {
        Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            Text("Notes are visible to everyone on your server.", fontSize = 12.sp, color = TextMuted, modifier = Modifier.weight(1f))
            TextButton(onClick = onAdd) {
                Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(4.dp))
                Text("Add note")
            }
        }
    }
    when {
        state.notesLoading && state.notes.isEmpty() -> item(key = "n-loading") { InlineLoading() }
        state.notesError != null && state.notes.isEmpty() -> item(key = "n-error") { ErrorState(state.notesError, onRetry = retry) }
        state.notes.isEmpty() -> item(key = "n-empty") {
            EmptyState(Icons.AutoMirrored.Filled.Notes, "No notes yet", "Record what you know: attribution, context, detections, false positives.")
        }
        else -> items(state.notes, key = { "n:" + it.id }, contentType = { "entity_note" }) { note ->
            NoteCard(
                title = note.title,
                body = note.content.orEmpty(),
                author = note.username,
                time = note.updatedAt ?: note.createdAt,
                pinned = false,
                canEdit = state.canEdit(note),
                onEdit = { onEdit(note) },
                onDelete = { onDelete(note) },
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp)
            )
        }
    }
}
