package com.example.intelfeed.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.fillMaxHeight
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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.AutoStories
import androidx.compose.material.icons.filled.DoneAll
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.intelfeed.LocalSnackbarHostState
import com.example.intelfeed.data.model.EntityType
import com.example.intelfeed.data.model.ThreadBeat
import com.example.intelfeed.data.model.ThreadDetail
import com.example.intelfeed.data.model.ThreadMember
import com.example.intelfeed.theme.CyberBlue
import com.example.intelfeed.theme.CyberPurple
import com.example.intelfeed.theme.SlateDark700
import com.example.intelfeed.theme.SlateDark900
import com.example.intelfeed.theme.TextMuted
import com.example.intelfeed.theme.TextPrimary
import com.example.intelfeed.theme.TextSecondary
import com.example.intelfeed.ui.components.CardSurface
import com.example.intelfeed.ui.components.ErrorState
import com.example.intelfeed.ui.components.LoadingBox
import com.example.intelfeed.ui.components.Pill
import com.example.intelfeed.ui.components.ScoreBadge
import com.example.intelfeed.ui.components.SectionHeader
import com.example.intelfeed.ui.components.color
import com.example.intelfeed.ui.thread.ThreadViewModel
import com.example.intelfeed.util.DateUtils
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ThreadScreen(
    viewModel: ThreadViewModel,
    fallbackTitle: String?,
    onBack: () -> Unit,
    onOpenEntry: (String, List<String>) -> Unit,
    onOpenEntity: (EntityType, String, String) -> Unit,
    onOpenThread: (String, String?) -> Unit
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val detail = state.detail

    Scaffold(
        topBar = {
            TopAppBar(
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back", tint = TextPrimary) } },
                title = {
                    Column {
                        Text("STORY", fontSize = 11.sp, color = CyberPurple, fontWeight = FontWeight.Bold)
                        Text(detail?.title ?: fallbackTitle ?: "Story", fontSize = 16.sp, fontWeight = FontWeight.Bold, color = TextPrimary, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                },
                actions = {
                    if (detail != null && detail.members.any { !it.isRead }) {
                        IconButton(onClick = viewModel::markAllRead) { Icon(Icons.Default.DoneAll, contentDescription = "Mark the whole story read", tint = TextSecondary) }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = SlateDark900)
            )
        },
        snackbarHost = { SnackbarHost(LocalSnackbarHostState.current) },
        containerColor = SlateDark900
    ) { padding ->
        when {
            detail == null && state.loading -> LoadingBox(Modifier.padding(padding), color = CyberPurple)
            detail == null -> ErrorState(state.error ?: "This story couldn't be loaded.", onRetry = viewModel::load, modifier = Modifier.padding(padding).fillMaxSize())
            else -> ThreadBody(detail, Modifier.padding(padding), onOpenEntry, onOpenEntity, onOpenThread, onMarkAllRead = viewModel::markAllRead)
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ThreadBody(
    detail: ThreadDetail,
    modifier: Modifier,
    onOpenEntry: (String, List<String>) -> Unit,
    onOpenEntity: (EntityType, String, String) -> Unit,
    onOpenThread: (String, String?) -> Unit,
    onMarkAllRead: () -> Unit
) {
    // Newest coverage first; echoes (syndicated copies) last.
    val members = remember(detail.members) {
        detail.members.sortedWith(compareBy<ThreadMember> { it.role == "echo" }.thenByDescending { it.publishedAt ?: "" })
    }
    val memberIds = members.map { it.entryId }
    val titles = detail.members.associate { it.entryId to it.title }
    val unread = detail.members.count { !it.isRead }

    val sortedBeats = remember(detail.beats) { detail.beats.sortedBy { it.position } }

    LazyColumn(modifier = modifier.fillMaxSize(), contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp)) {
        item(key = "header") {
            Column {
                Text(detail.title ?: "Story", fontSize = 22.sp, fontWeight = FontWeight.Bold, color = TextPrimary, lineHeight = 28.sp)
                Spacer(Modifier.height(8.dp))
                Text(
                    listOfNotNull(
                        "${detail.sourceCount} outlets",
                        "${detail.members.size.coerceAtLeast(detail.entryCount)} articles",
                        if (unread > 0) "$unread unread" else "all read",
                        detail.lastSeen?.let { "updated ${DateUtils.formatRelativeTime(it)}" }
                    ).joinToString(" · "),
                    fontSize = 13.sp,
                    color = TextMuted
                )
                detail.summary?.takeIf { it.isNotBlank() }?.let {
                    Spacer(Modifier.height(10.dp))
                    Text(it, fontSize = 15.sp, color = TextSecondary, lineHeight = 22.sp)
                }
                if (detail.keyEntities.isNotEmpty()) {
                    SectionHeader("Key entities")
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        detail.keyEntities.take(16).forEach { ke ->
                            val type = EntityType.fromKey(ke.entityType)
                            val id = ke.entityId
                            if (type != null && id != null) Pill(ke.label, type.color(), onClick = { onOpenEntity(type, id, ke.label) })
                            else Pill(ke.label, TextSecondary)
                        }
                    }
                }
                detail.threadYield?.let { y ->
                    val parts = listOfNotNull(
                        y.cves.takeIf { it > 0 }?.let { "$it CVEs" },
                        y.techniques.takeIf { it > 0 }?.let { "$it techniques" },
                        y.products.takeIf { it > 0 }?.let { "$it products" },
                        y.rules.takeIf { it > 0 }?.let { "$it detection rules" },
                        y.echoesFolded.takeIf { it > 0 }?.let { "$it duplicate reports folded" }
                    )
                    if (parts.isNotEmpty()) {
                        Spacer(Modifier.height(10.dp))
                        Text("Across the coverage: " + parts.joinToString(", "), fontSize = 13.sp, color = TextMuted)
                    }
                }
            }
        }

        if (detail.beats.isNotEmpty()) {
            item(key = "beats-header", contentType = "header") { SectionHeader("What happened") }
            items(sortedBeats, key = { "beat:" + (it.id ?: it.position.toString()) }, contentType = { "beat" }) { beat ->
                BeatRow(beat, titles, onOpen = { id -> onOpenEntry(id, memberIds) })
            }
        }

        item(key = "coverage-header", contentType = "header") {
            SectionHeader("Coverage (${members.size})", trailing = {
                if (unread > 0) TextButton(onClick = onMarkAllRead) { Text("Mark all read") }
            })
        }
        items(members, key = { "m:" + it.entryId }, contentType = { "member" }) { member ->
            MemberRow(member, onClick = { onOpenEntry(member.entryId, memberIds) })
        }

        if (detail.nearest.isNotEmpty()) {
            item(key = "nearest-header", contentType = "header") { SectionHeader("Related stories") }
            items(detail.nearest, key = { "n:" + it.slug }, contentType = { "nearest" }) { near ->
                CardSurface(modifier = Modifier.padding(vertical = 4.dp).clip(RoundedCornerShape(12.dp)).clickable { onOpenThread(near.slug, near.title) }) {
                    Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.AutoStories, contentDescription = null, tint = CyberPurple, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(10.dp))
                        Column(Modifier.weight(1f)) {
                            Text(near.title ?: near.slug, fontSize = 14.sp, color = TextPrimary, maxLines = 2, overflow = TextOverflow.Ellipsis)
                            Text(
                                listOfNotNull("${near.entryCount} articles", near.status, near.similarity?.let { "${(it * 100).toInt()}% similar" }).joinToString(" · "),
                                fontSize = 12.sp, color = TextMuted
                            )
                        }
                    }
                }
            }
        }
        item(key = "end", contentType = "spacer") { Spacer(Modifier.height(24.dp)) }
    }
}

@Composable
private fun BeatRow(beat: ThreadBeat, titles: Map<String, String>, onOpen: (String) -> Unit) {
    Row(Modifier.fillMaxWidth().height(IntrinsicSize.Min).padding(vertical = 4.dp)) {
        // Timeline rail, as tall as the beat's text.
        Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.width(18.dp).fillMaxHeight()) {
            Box(Modifier.padding(top = 5.dp).size(10.dp).background(CyberPurple, CircleShape))
            Box(Modifier.width(2.dp).weight(1f).background(SlateDark700))
        }
        Spacer(Modifier.width(10.dp))
        Column(Modifier.weight(1f)) {
            Text(
                listOfNotNull(
                    beat.occurredAt?.let { DateUtils.dayLabel(it) },
                    beat.kind?.replace('_', ' ')?.replaceFirstChar { it.titlecase(Locale.US) }
                ).joinToString(" · "),
                fontSize = 12.sp,
                color = CyberPurple,
                fontWeight = FontWeight.SemiBold
            )
            beat.headline?.let { Text(it, fontSize = 15.sp, fontWeight = FontWeight.Bold, color = TextPrimary, lineHeight = 20.sp) }
            beat.body?.takeIf { it.isNotBlank() }?.let {
                Spacer(Modifier.height(4.dp))
                Text(it, fontSize = 14.sp, color = TextSecondary, lineHeight = 20.sp, maxLines = 6, overflow = TextOverflow.Ellipsis)
            }
            beat.leadEntryId?.let { id ->
                TextButton(onClick = { onOpen(id) }, contentPadding = PaddingValues(0.dp)) {
                    Text("Read: " + (titles[id] ?: "the lead article"), maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
            }
        }
    }
}

@Composable
private fun MemberRow(member: ThreadMember, onClick: () -> Unit) {
    CardSurface(modifier = Modifier.padding(vertical = 4.dp).clip(RoundedCornerShape(12.dp)).clickable(onClick = onClick)) {
        Column(Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (!member.isRead) {
                    Box(Modifier.size(8.dp).background(CyberBlue, CircleShape))
                    Spacer(Modifier.width(7.dp))
                }
                Text(
                    member.source ?: member.feedTitle ?: "",
                    fontSize = 12.sp, color = TextSecondary, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f)
                )
                when (member.role) {
                    "origin" -> Pill("First to report", CyberPurple)
                    "echo" -> Pill("Re-report", TextMuted)
                    else -> Unit
                }
                member.priorityScore?.takeIf { it > 0 }?.let { Spacer(Modifier.width(6.dp)); ScoreBadge(it) }
            }
            Spacer(Modifier.height(4.dp))
            Text(
                member.title,
                fontSize = 14.sp,
                fontWeight = if (member.isRead) FontWeight.Medium else FontWeight.Bold,
                color = if (member.isRead) TextSecondary else TextPrimary,
                maxLines = 3,
                overflow = TextOverflow.Ellipsis
            )
            Text(DateUtils.formatRelativeTime(member.publishedAt), fontSize = 12.sp, color = TextMuted)
        }
    }
}
