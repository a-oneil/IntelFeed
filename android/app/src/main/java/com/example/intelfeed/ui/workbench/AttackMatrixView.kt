package com.example.intelfeed.ui.workbench

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.intelfeed.data.model.AttackMatrix
import com.example.intelfeed.data.model.AttackTechnique
import com.example.intelfeed.data.model.EntityType
import com.example.intelfeed.data.repository.IntelFeedRepository
import com.example.intelfeed.theme.SlateDark700
import com.example.intelfeed.theme.SlateDark800
import com.example.intelfeed.theme.SlateDark900
import com.example.intelfeed.theme.TextMuted
import com.example.intelfeed.theme.TextPrimary
import com.example.intelfeed.theme.TextSecondary
import com.example.intelfeed.ui.ErrorText
import com.example.intelfeed.ui.components.ErrorState
import com.example.intelfeed.ui.components.LoadingBox
import com.example.intelfeed.ui.components.color
import com.example.intelfeed.ui.entity.EntityRef
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlin.math.roundToInt
import kotlin.math.sqrt

/** The web matrix's layer modes: heat by article frequency, colour by rule coverage, or both. */
enum class MatrixLayer(val label: String) { HEAT("Feed heat"), COVERAGE("Coverage"), BOTH("Both") }

data class AttackMatrixState(
    val domain: String = "enterprise",
    // The web defaults to 30 days; null = all time.
    val days: Int? = 30,
    val layer: MatrixLayer = MatrixLayer.BOTH,
    val loading: Boolean = true,
    val error: String? = null,
    val matrix: AttackMatrix? = null,
    // Parent technique ids whose sub-techniques are shown.
    val expanded: Set<String> = emptySet()
)

class AttackMatrixViewModel(private val repository: IntelFeedRepository) : ViewModel() {
    private val _state = MutableStateFlow(AttackMatrixState())
    val state: StateFlow<AttackMatrixState> = _state.asStateFlow()
    private var job: Job? = null

    /** Loads the first time the tab is shown (the ViewModel lives as long as the Workbench). */
    fun ensureLoaded() {
        if (job == null) load()
    }

    fun load() {
        val s = _state.value
        job?.cancel()
        _state.update { it.copy(loading = true, error = null) }
        job = viewModelScope.launch {
            repository.getAttackMatrix(s.domain, s.days).fold(
                onSuccess = { m -> _state.update { it.copy(loading = false, matrix = m) } },
                onFailure = { e -> _state.update { it.copy(loading = false, error = ErrorText.describe(e)) } }
            )
        }
    }

    fun setDomain(domain: String) {
        if (domain == _state.value.domain) return
        _state.update { it.copy(domain = domain, matrix = null, expanded = emptySet()) }
        load()
    }

    fun setDays(days: Int?) {
        if (days == _state.value.days) return
        _state.update { it.copy(days = days) }
        load()
    }

    fun setLayer(layer: MatrixLayer) = _state.update { it.copy(layer = layer) }

    fun toggleExpanded(techniqueId: String) = _state.update {
        it.copy(expanded = if (techniqueId in it.expanded) it.expanded - techniqueId else it.expanded + techniqueId)
    }

    /** Expands every parent, or collapses all when they're all open (the web's "Expand subs"). */
    fun toggleAllSubs() = _state.update { s ->
        val parents = s.matrix?.tactics.orEmpty().flatMap { t -> t.techniques.filter { it.subtechniques.isNotEmpty() }.map { it.techniqueId } }.toSet()
        s.copy(expanded = if (parents.isNotEmpty() && s.expanded.containsAll(parents)) emptySet() else parents)
    }
}

// The web's --success, --warning and --danger.
private val Covered = Color(0xFF3FB950)
private val LibraryOnly = Color(0xFFD29922)
private val NoRule = Color(0xFFF85149)

private fun coverageColor(coverage: String) = when (coverage) {
    "covered" -> Covered
    "library_only" -> LibraryOnly
    else -> NoRule
}

private fun coverageLabel(coverage: String) = when (coverage) {
    "covered" -> "Covered"
    "library_only" -> "Missing telemetry"
    else -> "No rule"
}

/** The web's heat: 0 for none, else 15 % + 75 % × √(count / max). */
fun matrixHeat(count: Int, max: Int): Float =
    if (count <= 0 || max <= 0) 0f else minOf(1f, 0.15f + 0.75f * sqrt(count.toFloat() / max))

private data class MatrixTap(val tech: AttackTechnique, val tacticName: String)

/**
 * The web Workbench's ATT&CK Matrix: one column per tactic (scroll sideways), each technique
 * shaded by how often it appeared in the feeds and edged by rule coverage. Tap a technique to
 * open its profile, long-press for its numbers; parents with sub-techniques expand.
 */
@OptIn(ExperimentalLayoutApi::class, ExperimentalMaterial3Api::class)
@Composable
fun AttackMatrixView(vm: AttackMatrixViewModel, state: AttackMatrixState, onOpenEntity: (EntityRef) -> Unit) {
    var detail by remember { mutableStateOf<MatrixTap?>(null) }
    androidx.compose.runtime.LaunchedEffect(Unit) { vm.ensureLoaded() }
    val window = state.days?.let { "last $it days" } ?: "all time"
    Column(Modifier.fillMaxSize()) {
        Column(Modifier.padding(horizontal = 16.dp, vertical = 6.dp)) {
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
                listOf("enterprise" to "Enterprise", "mobile" to "Mobile", "ics" to "ICS").forEach { (v, l) ->
                    MatrixChip(l, state.domain == v) { vm.setDomain(v) }
                }
                Box(Modifier.width(1.dp).height(20.dp).background(SlateDark700))
                listOf<Pair<Int?, String>>(7 to "7d", 30 to "30d", 90 to "90d", null to "All").forEach { (v, l) ->
                    MatrixChip(l, state.days == v) { vm.setDays(v) }
                }
            }
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
                MatrixLayer.entries.forEach { MatrixChip(it.label, state.layer == it) { vm.setLayer(it) } }
                val parents = state.matrix?.tactics.orEmpty().flatMap { t -> t.techniques.filter { it.subtechniques.isNotEmpty() }.map { it.techniqueId } }
                if (parents.isNotEmpty()) {
                    TextButton(onClick = vm::toggleAllSubs) {
                        Text(if (state.expanded.containsAll(parents)) "Collapse subs" else "Expand subs", fontSize = 13.sp)
                    }
                }
            }
            state.matrix?.let { m ->
                FlowRow(horizontalArrangement = Arrangement.spacedBy(12.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Legend(Covered, "${m.coverageSummary.covered} covered")
                    Legend(LibraryOnly, "${m.coverageSummary.libraryOnly} missing telemetry")
                    Legend(NoRule, "${m.coverageSummary.noRule} no rule")
                }
                Text("${m.techniqueCount} techniques · heat = articles seen $window", fontSize = 12.sp, color = TextMuted)
            }
        }
        val m = state.matrix
        when {
            m == null && state.loading -> LoadingBox(color = EntityType.TTP.color())
            m == null && state.error != null -> ErrorState(state.error, onRetry = vm::load, modifier = Modifier.fillMaxSize())
            m == null -> Unit
            else -> Box(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
                Row(
                    Modifier.horizontalScroll(rememberScrollState()).padding(start = 12.dp, end = 12.dp, bottom = 24.dp),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    m.tactics.forEach { tactic ->
                        Column(Modifier.width(148.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Row(
                                Modifier.fillMaxWidth().background(SlateDark800, RoundedCornerShape(6.dp)).padding(horizontal = 8.dp, vertical = 6.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(tactic.name, fontSize = 12.sp, fontWeight = FontWeight.Bold, color = TextPrimary, modifier = Modifier.weight(1f), maxLines = 2)
                                Text("${tactic.techniques.size}", fontSize = 11.sp, color = TextMuted)
                            }
                            tactic.techniques.forEach { tech ->
                                val open = tech.techniqueId in state.expanded
                                MatrixCell(
                                    tech = tech,
                                    // Collapsed parents show their sub-techniques' articles too.
                                    count = if (open) tech.articleCount else tech.rollupArticleCount ?: tech.articleCount,
                                    max = m.maxArticleCount,
                                    layer = state.layer,
                                    sub = false,
                                    expanded = open,
                                    onToggle = { vm.toggleExpanded(tech.techniqueId) },
                                    onClick = { onOpenEntity(EntityRef(EntityType.TTP, tech.techniqueId, tech.techniqueId)) },
                                    onLongClick = { detail = MatrixTap(tech, tactic.name) }
                                )
                                if (open) tech.subtechniques.forEach { subTech ->
                                    MatrixCell(
                                        tech = subTech, count = subTech.articleCount, max = m.maxArticleCount, layer = state.layer,
                                        sub = true, expanded = false, onToggle = {},
                                        onClick = { onOpenEntity(EntityRef(EntityType.TTP, subTech.techniqueId, subTech.techniqueId)) },
                                        onLongClick = { detail = MatrixTap(subTech, tactic.name) }
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    detail?.let { d ->
        ModalBottomSheet(onDismissRequest = { detail = null }, containerColor = SlateDark800) {
            Column(Modifier.fillMaxWidth().navigationBarsPadding().padding(horizontal = 20.dp).padding(bottom = 16.dp)) {
                Text("${d.tech.techniqueId} — ${d.tech.name}", fontSize = 17.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
                Spacer(Modifier.height(8.dp))
                Text("Tactic: ${d.tacticName}", fontSize = 14.sp, color = TextSecondary)
                val rollup = d.tech.rollupArticleCount?.takeIf { it != d.tech.articleCount }?.let { " ($it incl. sub-techniques)" }.orEmpty()
                Text("Articles ($window): ${d.tech.articleCount}$rollup", fontSize = 14.sp, color = TextSecondary)
                Row {
                    Text("Rules: ${d.tech.ruleCount} — ", fontSize = 14.sp, color = TextSecondary)
                    Text(coverageLabel(d.tech.coverage), fontSize = 14.sp, color = coverageColor(d.tech.coverage), fontWeight = FontWeight.SemiBold)
                }
                if (d.tech.coverage == "library_only" && d.tech.missingDataSources.isNotEmpty()) {
                    Text("Missing telemetry: " + d.tech.missingDataSources.take(4).joinToString(", ") + if (d.tech.missingDataSources.size > 4) "…" else "",
                        fontSize = 14.sp, color = TextSecondary)
                }
                Spacer(Modifier.height(14.dp))
                OutlinedButton(onClick = {
                    detail = null
                    onOpenEntity(EntityRef(EntityType.TTP, d.tech.techniqueId, d.tech.techniqueId))
                }, modifier = Modifier.fillMaxWidth()) { Text("Open technique profile") }
            }
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun MatrixCell(
    tech: AttackTechnique,
    count: Int,
    max: Int,
    layer: MatrixLayer,
    sub: Boolean,
    expanded: Boolean,
    onToggle: () -> Unit,
    onClick: () -> Unit,
    onLongClick: () -> Unit
) {
    val ttp = EntityType.TTP.color()
    val cov = coverageColor(tech.coverage)
    val heat = matrixHeat(count, max)
    val fill = when (layer) {
        MatrixLayer.COVERAGE -> cov.copy(alpha = 0.16f)
        else -> if (heat > 0f) ttp.copy(alpha = heat) else SlateDark900
    }
    val edge = layer != MatrixLayer.HEAT
    val shape = RoundedCornerShape(4.dp)
    Column(
        Modifier
            .fillMaxWidth()
            .padding(start = if (sub) 10.dp else 0.dp)
            .heightIn(min = 44.dp)
            .clip(shape)
            .background(fill, shape)
            .drawBehind {
                drawRect(SlateDark700, style = androidx.compose.ui.graphics.drawscope.Stroke(1.dp.toPx()))
                if (edge) drawRect(cov, topLeft = Offset.Zero, size = Size(3.dp.toPx(), size.height))
            }
            .combinedClickable(onClick = onClick, onLongClick = onLongClick, onLongClickLabel = "Show details")
            .semantics {
                contentDescription = "${tech.techniqueId} ${tech.name}, $count articles, ${coverageLabel(tech.coverage)}"
            }
            .padding(start = if (edge) 8.dp else 6.dp, end = 4.dp, top = 4.dp, bottom = 5.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(tech.techniqueId, fontSize = 10.sp, fontFamily = FontFamily.Monospace, color = TextSecondary, modifier = Modifier.weight(1f))
            if (count > 0) Text("$count", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
            if (tech.subtechniques.isNotEmpty()) {
                Icon(
                    if (expanded) Icons.Default.ExpandMore else Icons.Default.ChevronRight,
                    contentDescription = if (expanded) "Collapse sub-techniques" else "Expand ${tech.subtechniques.size} sub-techniques",
                    tint = TextSecondary,
                    modifier = Modifier.size(20.dp).clip(RoundedCornerShape(4.dp)).combinedClickable(onClick = onToggle)
                )
            }
        }
        Text(tech.name, fontSize = 11.5.sp, color = TextPrimary, lineHeight = 14.sp, maxLines = 3, overflow = TextOverflow.Ellipsis)
    }
}

@Composable
private fun MatrixChip(label: String, selected: Boolean, onClick: () -> Unit) {
    FilterChip(
        selected = selected,
        onClick = onClick,
        label = { Text(label, fontSize = 12.sp) },
        colors = FilterChipDefaults.filterChipColors(selectedContainerColor = EntityType.TTP.color().copy(alpha = 0.25f), selectedLabelColor = TextPrimary, labelColor = TextSecondary)
    )
}

@Composable
private fun Legend(color: Color, text: String) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(10.dp).background(color, RoundedCornerShape(2.dp)))
        Spacer(Modifier.width(5.dp))
        Text(text, fontSize = 12.sp, color = TextSecondary)
    }
}

// Rounds a heat fraction to a percentage, for tests and accessibility text.
internal fun heatPercent(count: Int, max: Int) = (matrixHeat(count, max) * 100).roundToInt()
