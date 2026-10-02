package com.example.intelfeed.ui.workbench

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.FilterList
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.StarBorder
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.drawText
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.intelfeed.data.model.EntityType
import com.example.intelfeed.data.model.RansomwareDisclosure
import com.example.intelfeed.data.model.RansomwareGroupStat
import com.example.intelfeed.data.model.RansomwarePoint
import com.example.intelfeed.data.model.RansomwareStats
import com.example.intelfeed.theme.SlateDark600
import com.example.intelfeed.theme.SlateDark700
import com.example.intelfeed.theme.SlateDark800
import com.example.intelfeed.theme.TextMuted
import com.example.intelfeed.theme.TextPrimary
import com.example.intelfeed.theme.TextSecondary
import com.example.intelfeed.ui.components.ErrorState
import com.example.intelfeed.ui.components.InlineLoading
import com.example.intelfeed.ui.components.LoadingBox
import com.example.intelfeed.ui.entity.EntityRef
import com.example.intelfeed.util.DateUtils
import com.example.intelfeed.util.ExternalLinks
import java.text.NumberFormat
import java.util.Locale
import kotlin.math.abs
import kotlin.math.roundToInt

// The web's --accent, --entity-victim, --success and --danger.
private val Accent = Color(0xFFF78166)
private val Victim = Color(0xFFE0555B)
// The web colours a rise in victims with --entity-victim and a fall with --success.
private val Up = Color(0xFFE0555B)
private val Down = Color(0xFF3FB950)

/** The web's group palette (--rgroup-*): the server sends a group key in group_color. */
fun ransomwareGroupColor(key: String?): Color {
    val k = key?.trim()?.lowercase()?.replace("cl0p", "clop")
    if (k != null && k.startsWith("#") && k.length == 7) k.drop(1).toLongOrNull(16)?.let { return Color(0xFF000000 or it) }
    return when (k) {
        "lockbit" -> Color(0xFFE05C2F)
        "clop" -> Color(0xFF12996A)
        "akira" -> Color(0xFF2A78D6)
        "qilin" -> Color(0xFFC2537F)
        "play" -> Color(0xFFB5820F)
        "ransomhub" -> Color(0xFF2F8F2F)
        else -> Color(0xFF8B94A3)
    }
}

private fun hoursSince(iso: String?): Double? =
    iso?.let { DateUtils.parseIsoMillis(it) }?.takeIf { it > 0 }?.let { (System.currentTimeMillis() - it) / 3_600_000.0 }

/** The web's "just now" / "5h ago" / "3d ago". */
fun ransomwareAgo(iso: String?): String {
    val h = hoursSince(iso) ?: return ""
    return when {
        h < 1 -> "just now"
        h < 24 -> "${h.toInt()}h ago"
        else -> "${(h / 24).toInt()}d ago"
    }
}

/** The web's day buckets for "Newest first". */
fun ransomwareBucket(iso: String?): String {
    val h = hoursSince(iso) ?: return "Earlier"
    return when {
        h < 24 -> "Today"
        h < 48 -> "Yesterday"
        h < 168 -> "This week"
        else -> "Earlier"
    }
}

private fun pct(v: Double): String = if (v % 1.0 == 0.0) abs(v).toInt().toString() else String.format(Locale.US, "%.1f", abs(v))

@Composable
private fun Trend(value: Double, up: Boolean, small: Boolean = false) {
    // Rising victim counts are bad news, so the web colours ▲ red.
    Text("${if (up) "▲" else "▼"} ${pct(value)}%", fontSize = if (small) 11.sp else 12.sp, color = if (up) Up else Down, fontWeight = FontWeight.SemiBold)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RansomwareTracker(vm: RansomwareViewModel, state: RansomwareState, onOpenEntity: (EntityRef) -> Unit) {
    LaunchedEffect(Unit) { vm.ensureLoaded() }
    val openGroup: (String, String?) -> Unit = { id, name -> onOpenEntity(EntityRef(EntityType.THREAT_ACTOR, id, name ?: id)) }
    Column(Modifier.fillMaxSize()) {
        SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 6.dp)) {
            RansomwareView.entries.forEachIndexed { i, v ->
                SegmentedButton(
                    selected = state.view == v,
                    onClick = { vm.setView(v) },
                    shape = SegmentedButtonDefaults.itemShape(i, RansomwareView.entries.size),
                    colors = SegmentedButtonDefaults.colors(activeContainerColor = Victim.copy(alpha = 0.25f), activeContentColor = TextPrimary, inactiveContainerColor = SlateDark800, inactiveContentColor = TextSecondary)
                ) { Text(v.label) }
            }
        }
        when (state.view) {
            RansomwareView.LEAK_WATCH -> LeakWatch(vm, state, openGroup)
            RansomwareView.LANDSCAPE -> Landscape(vm, state, openGroup)
        }
    }
}

// LEAK WATCH

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun LeakWatch(vm: RansomwareViewModel, state: RansomwareState, openGroup: (String, String?) -> Unit) {
    val f = state.filters
    var showFacets by remember { mutableStateOf(false) }
    var sortOpen by remember { mutableStateOf(false) }
    var expanded by remember { mutableStateOf<String?>(null) }
    var alertDismissed by remember { mutableStateOf(false) }
    val listState = rememberLazyListState()
    val nearEnd by remember { derivedStateOf { (listState.layoutInfo.visibleItemsInfo.lastOrNull()?.index ?: 0) >= listState.layoutInfo.totalItemsCount - 5 } }
    LaunchedEffect(nearEnd, state.items.size) { if (nearEnd) vm.loadMore() }

    Column(Modifier.fillMaxSize()) {
        OutlinedTextField(
            value = f.q,
            onValueChange = { q -> vm.updateFilters({ it.copy(q = q) }, debounce = true) },
            placeholder = { Text("Filter victims, groups, domains…", color = TextMuted) },
            leadingIcon = { Icon(Icons.Default.Search, null, tint = TextSecondary) },
            trailingIcon = if (f.q.isNotEmpty()) { { IconButton(onClick = { vm.updateFilters({ it.copy(q = "") }) }) { Icon(Icons.Default.Close, "Clear", tint = TextMuted) } } } else null,
            singleLine = true,
            shape = RoundedCornerShape(10.dp),
            colors = OutlinedTextFieldDefaults.colors(focusedContainerColor = SlateDark800, unfocusedContainerColor = SlateDark800, focusedTextColor = TextPrimary, unfocusedTextColor = TextPrimary, unfocusedBorderColor = SlateDark700, focusedBorderColor = Victim),
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp)
        )
        Row(
            Modifier.horizontalScroll(rememberScrollState()).padding(horizontal = 16.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            listOf(1 to "24h", 7 to "7d", 30 to "30d", RansomwareFilters.ALL_DAYS to "All").forEach { (d, l) ->
                TrackerChip(l, f.days == d) { vm.updateFilters({ it.copy(days = d) }) }
            }
            TrackerChip("Watched only", f.watchedOnly) { vm.updateFilters({ it.copy(watchedOnly = !it.watchedOnly) }) }
            TrackerChip(if (f.facetCount > 0) "Filters · ${f.facetCount}" else "Filters", f.facetCount > 0, icon = true) { showFacets = true }
            Box {
                TrackerChip(when (f.sort) { "group" -> "By group"; "sector" -> "By sector"; else -> "Newest first" }, false) { sortOpen = true }
                DropdownMenu(expanded = sortOpen, onDismissRequest = { sortOpen = false }) {
                    listOf("recent" to "Newest first", "group" to "By group", "sector" to "By sector").forEach { (v, l) ->
                        DropdownMenuItem(text = { Text(l) }, onClick = { sortOpen = false; vm.updateFilters({ it.copy(sort = v) }) })
                    }
                }
            }
        }
        when {
            state.loading && state.items.isEmpty() -> LoadingBox(color = Victim)
            state.error != null && state.items.isEmpty() -> ErrorState(state.error, onRetry = vm::refresh, modifier = Modifier.fillMaxSize())
            else -> LazyColumn(state = listState, contentPadding = PaddingValues(start = 16.dp, end = 16.dp, bottom = 24.dp), modifier = Modifier.fillMaxSize()) {
                state.stats?.let { st -> item(key = "kpis") { LeakWatchKpis(st, f.days) } }
                // The web's banner for a watched organisation that just appeared.
                val hit = state.items.firstOrNull { it.watched && it.isNew }
                if (hit != null && !alertDismissed) item(key = "alert") {
                    Row(
                        Modifier.fillMaxWidth().padding(top = 8.dp).background(Victim.copy(alpha = 0.12f), RoundedCornerShape(8.dp)).border(1.dp, Victim.copy(alpha = 0.5f), RoundedCornerShape(8.dp)).padding(start = 10.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text("WATCHLIST HIT", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = Color.White, modifier = Modifier.background(Victim, RoundedCornerShape(4.dp)).padding(horizontal = 5.dp, vertical = 2.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("${hit.victimName}, a watched organization, was posted to ${hit.groupName ?: "an unattributed group"}'s leak site ${ransomwareAgo(hit.postedAt)}.",
                            fontSize = 13.sp, color = TextPrimary, modifier = Modifier.weight(1f).padding(vertical = 8.dp))
                        IconButton(onClick = { alertDismissed = true }) { Icon(Icons.Default.Close, "Dismiss", tint = TextSecondary) }
                    }
                }
                item(key = "count") {
                    Text("${NumberFormat.getIntegerInstance(Locale.US).format(state.total)} disclosures", fontSize = 13.sp, color = TextSecondary, modifier = Modifier.padding(top = 10.dp, bottom = 4.dp))
                }
                if (state.items.isEmpty() && !state.loading) item(key = "empty") {
                    Text("No disclosures match these filters.", color = TextMuted, fontSize = 14.sp, modifier = Modifier.padding(vertical = 24.dp))
                }
                val rows: List<Any> = if (f.sort == "recent") buildList {
                    val counts = state.items.groupingBy { ransomwareBucket(it.postedAt) }.eachCount()
                    var last: String? = null
                    state.items.forEach { d ->
                        val b = ransomwareBucket(d.postedAt)
                        if (b != last) { add(b to (counts[b] ?: 0)); last = b }
                        add(d)
                    }
                } else state.items
                items(rows, key = { r -> if (r is RansomwareDisclosure) r.id else "div:" + (r as Pair<*, *>).first }) { r ->
                    if (r is RansomwareDisclosure) {
                        DisclosureRow(
                            d = r,
                            open = expanded == r.id,
                            busy = r.id in state.watchBusy,
                            onToggle = { expanded = if (expanded == r.id) null else r.id },
                            onWatch = { vm.toggleWatch(r) },
                            openGroup = openGroup
                        )
                    } else {
                        val (label, n) = r as Pair<*, *>
                        Row(Modifier.fillMaxWidth().padding(top = 12.dp, bottom = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                            Text(label.toString().uppercase(Locale.US), fontSize = 11.sp, fontWeight = FontWeight.Bold, color = TextMuted)
                            Spacer(Modifier.width(6.dp))
                            Text("$n", fontSize = 11.sp, color = TextMuted)
                        }
                    }
                }
                if (state.loadingMore) item(key = "more") { InlineLoading(color = Victim) }
            }
        }
    }
    if (showFacets) FacetSheet(vm, state, onDismiss = { showFacets = false })
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun LeakWatchKpis(st: RansomwareStats, days: Int) {
    val t = st.totals
    Row(Modifier.horizontalScroll(rememberScrollState()).padding(top = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Kpi("New victims · ${if (days >= RansomwareFilters.ALL_DAYS) "all" else "${days}d"}", NumberFormat.getIntegerInstance(Locale.US).format(t.victims)) {
            Row(verticalAlignment = Alignment.CenterVertically) { Trend(t.victimsWow, t.victimsWow >= 0); Text(" vs prior", fontSize = 11.sp, color = TextMuted) }
        }
        Kpi("Active groups", "${t.groupsActive}") { Text(st.groups.take(3).joinToString(", ") { it.name }, fontSize = 11.sp, color = TextMuted, maxLines = 1, overflow = TextOverflow.Ellipsis) }
        Kpi("Top sector hit", st.sectors.firstOrNull()?.label ?: "—", smallValue = true) { Text(st.sectors.firstOrNull()?.let { "${it.victims} victims" }.orEmpty(), fontSize = 11.sp, color = TextMuted) }
        Kpi("Watchlist hits", "${t.watchlistHits}", critical = true) { Text("watched orgs / sectors", fontSize = 11.sp, color = TextMuted) }
    }
}

@Composable
private fun Kpi(label: String, value: String, smallValue: Boolean = false, critical: Boolean = false, modifier: Modifier = Modifier.width(150.dp), sub: @Composable () -> Unit) {
    Column(
        modifier
            .background(if (critical) Victim.copy(alpha = 0.08f) else SlateDark800, RoundedCornerShape(10.dp))
            .border(1.dp, if (critical) Victim.copy(alpha = 0.4f) else SlateDark700, RoundedCornerShape(10.dp))
            .padding(10.dp)
    ) {
        Text(label, fontSize = 11.sp, color = TextMuted, maxLines = 1, overflow = TextOverflow.Ellipsis)
        Text(value, fontSize = if (smallValue) 15.sp else 22.sp, fontWeight = FontWeight.Bold, color = if (critical) Victim else TextPrimary, maxLines = 1, overflow = TextOverflow.Ellipsis)
        sub()
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun DisclosureRow(
    d: RansomwareDisclosure,
    open: Boolean,
    busy: Boolean,
    onToggle: () -> Unit,
    onWatch: () -> Unit,
    openGroup: (String, String?) -> Unit
) {
    val context = LocalContext.current
    Column(
        Modifier
            .fillMaxWidth()
            .padding(vertical = 3.dp)
            .clip(RoundedCornerShape(8.dp))
            .background(if (d.watched) Accent.copy(alpha = 0.06f) else SlateDark800)
            .border(1.dp, if (open) SlateDark600 else Color.Transparent, RoundedCornerShape(8.dp))
            .clickable(onClickLabel = if (open) "Hide details" else "Show details", onClick = onToggle)
            .padding(start = 10.dp, top = 8.dp, bottom = 8.dp)
    ) {
        Row(verticalAlignment = Alignment.Top) {
            Box(Modifier.padding(top = 6.dp).size(8.dp).background(if (d.isNew) Victim else SlateDark600, CircleShape))
            Spacer(Modifier.width(8.dp))
            Column(Modifier.weight(1f)) {
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(2.dp), itemVerticalAlignment = Alignment.CenterVertically) {
                    Text(d.victimName, fontSize = 15.sp, fontWeight = FontWeight.SemiBold, color = TextPrimary)
                    d.domain?.takeIf { it.isNotBlank() }?.let { Text(it, fontSize = 12.sp, fontFamily = FontFamily.Monospace, color = TextMuted) }
                    if (d.isNew) Tag("NEW", Victim)
                    if (d.watched) Tag("WATCHED", Accent)
                }
                Spacer(Modifier.height(4.dp))
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(4.dp), itemVerticalAlignment = Alignment.CenterVertically) {
                    val gid = d.groupId
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.clip(RoundedCornerShape(6.dp)).then(if (gid != null) Modifier.clickable(onClickLabel = "Open ${d.groupName} profile") { openGroup(gid, d.groupName) } else Modifier)
                            .padding(horizontal = 2.dp, vertical = 2.dp)
                    ) {
                        Box(Modifier.size(8.dp).background(ransomwareGroupColor(d.groupColor), CircleShape))
                        Spacer(Modifier.width(5.dp))
                        Text(d.groupName ?: "Unattributed", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = TextSecondary)
                    }
                    d.sectorLabel?.takeIf { it.isNotBlank() }?.let {
                        Text(it, fontSize = 11.sp, color = TextSecondary, maxLines = 1, overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.widthIn(max = 180.dp).border(1.dp, SlateDark600, RoundedCornerShape(10.dp)).padding(horizontal = 7.dp, vertical = 1.dp))
                    }
                    d.countryCode?.takeIf { it.isNotBlank() }?.let { Text(it, fontSize = 11.sp, fontFamily = FontFamily.Monospace, color = TextMuted) }
                }
            }
            Column(horizontalAlignment = Alignment.End) {
                Text(ransomwareAgo(d.postedAt), fontSize = 11.sp, color = TextMuted, modifier = Modifier.padding(end = 10.dp))
                if (d.victimId != null) WatchStar(d.watched, busy, d.victimName, onWatch)
            }
        }
        if (open) {
            Column(Modifier.padding(start = 16.dp, end = 10.dp, top = 8.dp)) {
                DetailLine("Data claimed", d.claimedData?.takeIf { it.isNotBlank() } ?: "—")
                DetailLine("First seen", ransomwareAgo(d.postedAt))
                d.publishedAt?.let { DetailLine("Publish deadline", DateUtils.parseDate(it)?.let { dt -> java.text.DateFormat.getDateInstance().format(dt) } ?: it) }
                d.source?.takeIf { it.isNotBlank() }?.let { DetailLine("Source", it) }
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), modifier = Modifier.padding(top = 6.dp)) {
                    d.groupId?.let { gid -> TextButton(onClick = { openGroup(gid, d.groupName) }) { Text("↳ Pivot to ${d.groupName ?: "group"} profile") } }
                    d.leakSiteUrl?.takeIf { it.isNotBlank() }?.let { url ->
                        TextButton(onClick = { ExternalLinks.openInBrowser(context, url) }) {
                            Icon(Icons.AutoMirrored.Filled.OpenInNew, null, Modifier.size(15.dp))
                            Spacer(Modifier.width(4.dp))
                            Text("Leak site post")
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun WatchStar(watched: Boolean, busy: Boolean, name: String, onClick: () -> Unit) {
    IconButton(onClick = onClick, enabled = !busy) {
        Icon(if (watched) Icons.Default.Star else Icons.Default.StarBorder, if (watched) "Unwatch $name" else "Watch $name",
            tint = if (watched) Accent else TextMuted, modifier = Modifier.size(20.dp))
    }
}

@Composable
private fun Tag(text: String, color: Color) {
    Text(text, fontSize = 9.sp, fontWeight = FontWeight.Bold, color = Color.White, modifier = Modifier.background(color, RoundedCornerShape(4.dp)).padding(horizontal = 4.dp, vertical = 1.dp))
}

@Composable
private fun DetailLine(label: String, value: String) {
    Row(Modifier.padding(vertical = 2.dp)) {
        Text(label, fontSize = 12.sp, color = TextMuted, modifier = Modifier.width(120.dp))
        Text(value, fontSize = 13.sp, color = TextPrimary, modifier = Modifier.weight(1f))
    }
}

@Composable
private fun TrackerChip(label: String, selected: Boolean, icon: Boolean = false, onClick: () -> Unit) {
    FilterChip(
        selected = selected,
        onClick = onClick,
        label = { Text(label, fontSize = 12.sp) },
        leadingIcon = if (icon) { { Icon(Icons.Default.FilterList, null, Modifier.size(16.dp)) } } else null,
        colors = FilterChipDefaults.filterChipColors(selectedContainerColor = Victim.copy(alpha = 0.25f), selectedLabelColor = TextPrimary, labelColor = TextSecondary, iconColor = TextSecondary)
    )
}

/** The web's left rail: group, sector and country facets with counts (multi-select). */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun FacetSheet(vm: RansomwareViewModel, state: RansomwareState, onDismiss: () -> Unit) {
    val st = state.stats
    val f = state.filters
    ModalBottomSheet(onDismissRequest = onDismiss, containerColor = SlateDark800) {
        Column(Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).navigationBarsPadding().padding(horizontal = 16.dp).padding(bottom = 16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Leak watch filters", fontSize = 18.sp, fontWeight = FontWeight.Bold, color = TextPrimary, modifier = Modifier.weight(1f))
                if (f.facetCount > 0) TextButton(onClick = { vm.updateFilters({ it.copy(groups = emptyList(), sectors = emptyList(), countries = emptyList()) }) }) { Text("Clear all") }
            }
            if (st == null) Text("Loading…", color = TextMuted)
            st?.let { s ->
                FacetGroup("Ransomware group", s.groups.map { Triple(it.name, it.name, it.victims) }, f.groups, colorOf = { name -> ransomwareGroupColor(s.groups.firstOrNull { it.name == name }?.color) }) { vm.toggleFacet("group", it) }
                FacetGroup("Sector", s.sectors.map { Triple(it.sector, it.label, it.victims) }, f.sectors) { vm.toggleFacet("sector", it) }
                FacetGroup("Country", s.countries.filter { !it.isoCode.isNullOrBlank() }.map { Triple(it.isoCode!!, "${it.name} (${it.isoCode})", it.victims) }, f.countries) { vm.toggleFacet("country", it) }
            }
        }
    }
}

@Composable
private fun FacetGroup(title: String, items: List<Triple<String, String, Int>>, selected: List<String>, colorOf: ((String) -> Color)? = null, onToggle: (String) -> Unit) {
    if (items.isEmpty()) return
    Text(title.uppercase(Locale.US), fontSize = 11.sp, fontWeight = FontWeight.Bold, color = TextMuted, modifier = Modifier.padding(top = 12.dp, bottom = 2.dp))
    items.forEach { (value, label, count) ->
        Row(
            Modifier.fillMaxWidth().clip(RoundedCornerShape(6.dp)).clickable { onToggle(value) }.padding(vertical = 2.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Checkbox(checked = value in selected, onCheckedChange = { onToggle(value) })
            colorOf?.let { Box(Modifier.size(8.dp).background(it(value), CircleShape)); Spacer(Modifier.width(6.dp)) }
            Text(label, fontSize = 14.sp, color = TextPrimary, modifier = Modifier.weight(1f))
            Text("$count", fontSize = 12.sp, color = TextMuted)
        }
    }
}

// LANDSCAPE

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun Landscape(vm: RansomwareViewModel, state: RansomwareState, openGroup: (String, String?) -> Unit) {
    Column(Modifier.fillMaxSize()) {
        Row(Modifier.padding(horizontal = 16.dp), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            listOf(30 to "30d", 90 to "90d", 365 to "1y").forEach { (d, l) -> TrackerChip(l, state.landscapeDays == d) { vm.setLandscapeDays(d) } }
        }
        val st = state.landscape
        when {
            st == null && state.landscapeLoading -> LoadingBox(color = Victim)
            st == null && state.landscapeError != null -> ErrorState(state.landscapeError, onRetry = { vm.setLandscapeDays(state.landscapeDays) }, modifier = Modifier.fillMaxSize())
            st == null -> Unit
            else -> Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 16.dp).padding(bottom = 24.dp)) {
                val days = state.landscapeDays
                val t = st.totals
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp), maxItemsInEachRow = 2, modifier = Modifier.padding(top = 8.dp)) {
                    val w = Modifier.weight(1f)
                    Kpi("Victims · ${days}d", NumberFormat.getIntegerInstance(Locale.US).format(t.victims), modifier = w) {
                        Row(verticalAlignment = Alignment.CenterVertically) { Trend(t.victimsWow, t.victimsWow >= 0); Text(" vs prior ${days}d", fontSize = 11.sp, color = TextMuted) }
                    }
                    Kpi("Most active group", st.mostActiveGroup?.name ?: "—", smallValue = true, modifier = w.then(groupClick(st.mostActiveGroup, openGroup))) {
                        Text(st.mostActiveGroup?.let { "${it.victims} victims · ${pct(it.share)}% share" } ?: "no data", fontSize = 11.sp, color = TextMuted)
                    }
                    Kpi("Fastest riser", st.fastestRiser?.name ?: "—", smallValue = true, modifier = w.then(groupClick(st.fastestRiser, openGroup))) {
                        Row(verticalAlignment = Alignment.CenterVertically) { st.fastestRiser?.let { Trend(it.wowTrend, it.trendUp) }; Text(" WoW volume", fontSize = 11.sp, color = TextMuted) }
                    }
                    Kpi("Sectors hit", "${t.sectorsHit}", modifier = w) {
                        Text(st.sectors.firstOrNull()?.let { "${it.label} leads (${pct(it.share)}%)" }.orEmpty(), fontSize = 11.sp, color = TextMuted, maxLines = 2)
                    }
                    Kpi("Watchlist exposure", "${t.watchlistHits}", critical = true, modifier = w) { Text("watched orgs / sectors hit", fontSize = 11.sp, color = TextMuted) }
                }
                ChartCard("Victim disclosures over time", "Weekly new-victim postings across all tracked leak sites") { WeeklyLine(st.timeseries) }
                ChartCard("Most active groups", "Victim count · share · week-over-week") {
                    val top = st.groups.firstOrNull()?.victims ?: 0
                    st.groups.forEach { g ->
                        BarRow(
                            label = g.name, dot = ransomwareGroupColor(g.color), fraction = if (top > 0) g.victims.toFloat() / top else 0f, fill = ransomwareGroupColor(g.color),
                            value = "${g.victims}", onClick = g.id?.let { id -> { openGroup(id, g.name) } }
                        ) { Trend(g.wowTrend, g.trendUp, small = true) }
                    }
                }
                ChartCard("Sectors targeted", "Share of disclosed victims by industry") {
                    val top = st.sectors.firstOrNull()?.victims ?: 0
                    st.sectors.forEach { s ->
                        BarRow(s.label, null, if (top > 0) s.victims.toFloat() / top else 0f, Accent.copy(alpha = 0.85f), "${s.victims}") { Text("${pct(s.share)}%", fontSize = 11.sp, color = TextMuted) }
                    }
                }
                ChartCard("Victims by country", "Where disclosed organizations are headquartered") {
                    if (st.countries.isEmpty()) Text("No country data.", fontSize = 13.sp, color = TextMuted)
                    val top = st.countries.firstOrNull()?.victims ?: 0
                    st.countries.forEach { c ->
                        BarRow(c.name + (c.isoCode?.let { " · $it" } ?: ""), null, if (top > 0) c.victims.toFloat() / top else 0f, Accent.copy(alpha = 0.28f), "${c.victims}") {}
                    }
                }
                ChartCard("Your watchlist exposure", "Watched entities against ${days}d disclosures") {
                    if (st.watchlistExposure.isEmpty()) Text("No watched groups, orgs, or sectors yet.", fontSize = 13.sp, color = TextMuted)
                    st.watchlistExposure.forEach { e ->
                        Row(Modifier.fillMaxWidth().padding(vertical = 5.dp), verticalAlignment = Alignment.CenterVertically) {
                            Text(if (e.hit) "🎯" else "○", fontSize = 14.sp, color = TextMuted, modifier = Modifier.width(26.dp))
                            Column(Modifier.weight(1f)) {
                                Text(e.name, fontSize = 14.sp, color = TextPrimary)
                                Text("${e.kind} · ${e.detail}", fontSize = 12.sp, color = TextMuted)
                            }
                            if (e.hit) Tag("HIT", Victim) else Text("CLEAR", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = Down)
                        }
                    }
                }
            }
        }
    }
}

private fun groupClick(g: RansomwareGroupStat?, openGroup: (String, String?) -> Unit): Modifier {
    val id = g?.id ?: return Modifier
    return Modifier.clip(RoundedCornerShape(10.dp)).clickable(onClickLabel = "Open ${g.name} profile") { openGroup(id, g.name) }
}

@Composable
private fun ChartCard(title: String, subtitle: String, content: @Composable () -> Unit) {
    Column(
        Modifier.fillMaxWidth().padding(top = 12.dp).background(SlateDark800, RoundedCornerShape(12.dp)).border(1.dp, SlateDark700, RoundedCornerShape(12.dp)).padding(14.dp)
    ) {
        Text(title, fontSize = 15.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
        Text(subtitle, fontSize = 12.sp, color = TextMuted)
        Spacer(Modifier.height(10.dp))
        content()
    }
}

@Composable
private fun BarRow(label: String, dot: Color?, fraction: Float, fill: Color, value: String, onClick: (() -> Unit)? = null, extra: @Composable () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(6.dp)).then(if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier).padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Row(Modifier.width(118.dp), verticalAlignment = Alignment.CenterVertically) {
            dot?.let { Box(Modifier.size(8.dp).background(it, CircleShape)); Spacer(Modifier.width(5.dp)) }
            Text(label, fontSize = 12.sp, color = TextSecondary, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
        Box(Modifier.weight(1f).height(10.dp).clip(RoundedCornerShape(5.dp)).background(SlateDark700)) {
            Box(Modifier.fillMaxWidth(fraction.coerceIn(0f, 1f)).fillMaxHeight().background(fill))
        }
        // Fixed widths so every bar ends at the same place.
        Text(value, fontSize = 12.sp, fontWeight = FontWeight.SemiBold, color = TextPrimary, textAlign = androidx.compose.ui.text.style.TextAlign.End, modifier = Modifier.width(44.dp))
        Spacer(Modifier.width(6.dp))
        Box(Modifier.width(60.dp)) { extra() }
    }
}

/**
 * The web's weekly line: area gradient in the accent colour, dashed average, y ticks at 0 / ⅓ / ⅔ /
 * max (max = 1.12 × the highest week), every other week labelled, the last point marked. Tap a
 * point to read it.
 */
@Composable
private fun WeeklyLine(points: List<RansomwarePoint>) {
    if (points.isEmpty()) {
        Text("No disclosures in this window.", fontSize = 13.sp, color = TextMuted)
        return
    }
    val measurer = rememberTextMeasurer()
    var selected by remember(points) { mutableStateOf<Int?>(null) }
    val axisStyle = TextStyle(fontSize = 10.sp, color = TextMuted)
    val max = (points.maxOf { it.count }.coerceAtLeast(1)) * 1.12f
    val avg = points.sumOf { it.count }.toFloat() / points.size
    val desc = "Weekly victim disclosures: " + points.joinToString(", ") { "${it.label} ${it.count}" }
    Column {
        Canvas(
            Modifier.fillMaxWidth().height(190.dp).semantics { contentDescription = desc }
                .pointerInput(points) {
                    detectTapGestures { pos ->
                        val left = 34.dp.toPx(); val right = size.width - 10.dp.toPx()
                        val i = if (points.size == 1) 0 else (((pos.x - left) / (right - left)) * (points.size - 1)).roundToInt().coerceIn(0, points.size - 1)
                        selected = if (selected == i) null else i
                    }
                }
        ) {
            val l = 34.dp.toPx(); val r = 10.dp.toPx(); val t = 10.dp.toPx(); val b = 22.dp.toPx()
            val iw = size.width - l - r; val ih = size.height - t - b
            fun x(i: Int) = l + if (points.size == 1) iw / 2 else iw * i / (points.size - 1)
            fun y(v: Float) = t + ih * (1 - v / max)
            listOf(0f, (max * 0.33f).roundToInt().toFloat(), (max * 0.66f).roundToInt().toFloat(), max.roundToInt().toFloat()).forEach { v ->
                drawLine(SlateDark700, Offset(l, y(v)), Offset(size.width - r, y(v)), 1.dp.toPx())
                val tl = measurer.measure(v.toInt().toString(), axisStyle)
                drawText(tl, topLeft = Offset(l - 6.dp.toPx() - tl.size.width, y(v) - tl.size.height / 2))
            }
            val line = Path().apply { points.forEachIndexed { i, p -> if (i == 0) moveTo(x(i), y(p.count.toFloat())) else lineTo(x(i), y(p.count.toFloat())) } }
            val area = Path().apply {
                moveTo(x(0), y(0f)); points.forEachIndexed { i, p -> lineTo(x(i), y(p.count.toFloat())) }; lineTo(x(points.lastIndex), y(0f)); close()
            }
            drawPath(area, Brush.verticalGradient(listOf(Accent.copy(alpha = 0.24f), Accent.copy(alpha = 0f)), startY = t, endY = t + ih))
            drawLine(TextMuted.copy(alpha = 0.7f), Offset(l, y(avg)), Offset(size.width - r, y(avg)), 1.5.dp.toPx(), pathEffect = PathEffect.dashPathEffect(floatArrayOf(4.dp.toPx(), 4.dp.toPx())))
            drawPath(line, Accent, style = Stroke(2.2.dp.toPx(), cap = androidx.compose.ui.graphics.StrokeCap.Round, join = androidx.compose.ui.graphics.StrokeJoin.Round))
            points.forEachIndexed { i, p ->
                if (i % 2 == 0 || i == points.lastIndex) {
                    val tl = measurer.measure(p.label, axisStyle)
                    val cx = (x(i) - tl.size.width / 2).coerceIn(0f, size.width - tl.size.width)
                    drawText(tl, topLeft = Offset(cx, size.height - tl.size.height))
                }
            }
            drawCircle(Accent, 4.2.dp.toPx(), Offset(x(points.lastIndex), y(points.last().count.toFloat())))
            selected?.let { i ->
                drawLine(TextSecondary, Offset(x(i), t), Offset(x(i), t + ih), 1.dp.toPx())
                drawCircle(Accent, 4.5.dp.toPx(), Offset(x(i), y(points[i].count.toFloat())))
            }
        }
        val sel = selected?.let { points.getOrNull(it) }
        Text(
            if (sel != null) "${sel.count} victims · ${sel.label}" else "Tap the chart to read a week · dashed line = average (${avg.roundToInt()})",
            fontSize = 12.sp, color = if (sel != null) TextPrimary else TextMuted
        )
    }
}
