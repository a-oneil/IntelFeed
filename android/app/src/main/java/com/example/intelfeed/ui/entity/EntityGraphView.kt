package com.example.intelfeed.ui.entity

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.drawText
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.intelfeed.data.model.EntityGraph
import com.example.intelfeed.data.model.EntityType
import com.example.intelfeed.data.model.GraphNode
import com.example.intelfeed.theme.SlateDark600
import com.example.intelfeed.theme.SlateDark700
import com.example.intelfeed.theme.SlateDark800
import com.example.intelfeed.theme.SlateDark900
import com.example.intelfeed.theme.TextMuted
import com.example.intelfeed.theme.TextPrimary
import com.example.intelfeed.theme.TextSecondary
import com.example.intelfeed.ui.components.InlineLoading
import com.example.intelfeed.ui.components.color
import kotlin.math.cos
import kotlin.math.hypot
import kotlin.math.sin

/** The web's node colour: the entity type's colour, grey for articles. */
private fun graphColor(type: String): Color = if (type == "entry") Color(0xFF6B7280) else EntityType.fromKey(type)?.color() ?: Color(0xFF6B7280)

private fun graphTypeLabel(type: String): String = if (type == "entry") "Articles" else EntityType.fromKey(type)?.pluralLabel ?: type

private fun cut(s: String, max: Int) = if (s.length <= max) s else s.take(max - 1) + "…"

/**
 * The web profile's relationship graph (Relationships tab): this entity in the middle, its linked
 * entities on a ring grouped by type (malware hexagons, techniques squares, CVEs triangles,
 * countries ringed circles), edges weighted by strength and dashed when only "possible". Tap a
 * node to open it, "+N" for more of that type; the legend hides types; the chips set the window.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun EntityGraphView(
    graph: EntityGraph?,
    loading: Boolean,
    error: String?,
    windowDays: Int?,
    onWindow: (Int?) -> Unit,
    onOpenNode: (GraphNode) -> Unit,
    modifier: Modifier = Modifier
) {
    var perType by remember(graph) { mutableIntStateOf(5) }
    var hidden by remember { mutableStateOf(emptySet<String>()) }
    val layout = remember(graph, perType, hidden) { graph?.let { GraphLayout.layout(it, perType, hidden) } }
    val measurer = rememberTextMeasurer()
    val labelStyle = TextStyle(fontSize = 10.sp, color = TextSecondary)
    val seedStyle = TextStyle(fontSize = 11.sp, color = TextPrimary, fontWeight = FontWeight.Bold)
    val sectorStyle = TextStyle(fontSize = 9.sp, color = TextMuted, fontWeight = FontWeight.Bold)

    Column(
        modifier.fillMaxWidth().background(SlateDark800, RoundedCornerShape(12.dp)).border(1.dp, SlateDark700, RoundedCornerShape(12.dp)).padding(12.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Relationship graph", fontSize = 14.sp, fontWeight = FontWeight.Bold, color = TextPrimary, modifier = Modifier.weight(1f))
            if (loading && graph != null) Text("Updating…", fontSize = 11.sp, color = TextMuted)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            listOf<Pair<Int?, String>>(null to "All time", 30 to "30d", 90 to "90d", 365 to "1y").forEach { (d, l) ->
                FilterChip(
                    selected = windowDays == d, onClick = { onWindow(d) }, label = { Text(l, fontSize = 12.sp) },
                    colors = FilterChipDefaults.filterChipColors(selectedContainerColor = SlateDark600, selectedLabelColor = TextPrimary, labelColor = TextSecondary)
                )
            }
        }
        when {
            graph == null && loading -> InlineLoading()
            graph == null && error != null -> Text(error, fontSize = 13.sp, color = TextMuted, modifier = Modifier.padding(vertical = 16.dp))
            layout == null || layout.placed.size <= 1 && hidden.isEmpty() -> Text("No linked entities in this window.", fontSize = 13.sp, color = TextMuted, modifier = Modifier.padding(vertical = 16.dp))
            else -> {
                val seed = layout.placed.first()
                val desc = "Relationship graph of ${seed.node.label}: " + layout.sectors.joinToString("; ") { "${it.total} ${graphTypeLabel(it.type)}" }
                // Units → pixels: the ring plus its nodes in units, then the widest label in pixels.
                val maxLabelPx = remember(layout) {
                    layout.placed.drop(1).maxOfOrNull { measurer.measure(cut(it.node.label, 16), labelStyle).size.width }?.toFloat() ?: 0f
                }
                val ringUnits = layout.ringRadius + 22f
                fun scaleFor(side: Float) = ((side / 2f - maxLabelPx - 4f) / ringUnits).coerceAtLeast(side / 2f / (ringUnits * 3f))
                // On a phone the web's node size overlaps its neighbours; keep a gap.
                val ringCount = (layout.placed.size - 1 + layout.overflow.size).coerceAtLeast(1)
                val maxR = (2 * Math.PI.toFloat() * layout.ringRadius / ringCount) * 0.38f
                Canvas(
                    Modifier.fillMaxWidth().aspectRatio(1f).clip(RoundedCornerShape(8.dp)).background(SlateDark900)
                        .semantics { contentDescription = desc }
                        .pointerInput(layout) {
                            detectTapGestures { pos ->
                                val scale = scaleFor(minOf(size.width, size.height).toFloat())
                                val cx = size.width / 2f; val cy = size.height / 2f
                                val ux = (pos.x - cx) / scale; val uy = (pos.y - cy) / scale
                                layout.overflow.firstOrNull { hypot(ux - it.x, uy - it.y) < 20f }?.let {
                                    perType = minOf(perType + 4, 20)
                                    return@detectTapGestures
                                }
                                layout.placed.filter { !it.seed }.minByOrNull { hypot(ux - it.x, uy - it.y) }
                                    ?.takeIf { hypot(ux - it.x, uy - it.y) < GraphLayout.nodeRadius(it.node) + 12f }
                                    ?.let { onOpenNode(it.node) }
                            }
                        }
                ) {
                    val scale = scaleFor(minOf(size.width, size.height))
                    val c = Offset(size.width / 2f, size.height / 2f)
                    fun p(x: Float, y: Float) = Offset(c.x + x * scale, c.y + y * scale)
                    // Ring guide.
                    drawCircle(SlateDark700, layout.ringRadius * scale, c, style = Stroke(1.dp.toPx(), pathEffect = PathEffect.dashPathEffect(floatArrayOf(3.dp.toPx(), 4.dp.toPx()))))
                    // Type labels just inside the ring, at the middle of each sector.
                    // Alternating distances, so neighbouring labels don't overlap.
                    layout.sectors.filter { it.end - it.start >= 0.45f }.forEachIndexed { i, s ->
                        val mid = (s.start + s.end) / 2
                        val r = layout.ringRadius * if (i % 2 == 0) 0.64f else 0.42f
                        val t = measurer.measure("${graphTypeLabel(s.type).uppercase()} ${s.total}", sectorStyle)
                        val at = p(r * cos(mid), r * sin(mid))
                        drawText(t, topLeft = Offset((at.x - t.size.width / 2).coerceIn(0f, size.width - t.size.width), (at.y - t.size.height / 2).coerceIn(0f, size.height - t.size.height)))
                    }
                    // Edges: width by strength, dashed when only "possible".
                    layout.edges.forEach { e ->
                        val a = layout.byId[e.source] ?: return@forEach
                        val b = layout.byId[e.target] ?: return@forEach
                        val touchesSeed = a.seed || b.seed
                        drawLine(
                            (if (touchesSeed) graphColor((if (a.seed) b else a).node.type) else SlateDark600).copy(alpha = if (touchesSeed) 0.45f else 0.25f),
                            p(a.x, a.y), p(b.x, b.y),
                            strokeWidth = ((0.8f + 2.2f * e.weight.toFloat().coerceIn(0f, 1f)) * scale).coerceAtLeast(1f),
                            pathEffect = if (e.confidence == "possible") PathEffect.dashPathEffect(floatArrayOf(5 * scale, 4 * scale)) else null
                        )
                    }
                    // Nodes and labels.
                    layout.placed.forEach { pl ->
                        val units = if (pl.seed) GraphLayout.nodeRadius(pl.node) + 4f else minOf(GraphLayout.nodeRadius(pl.node), maxR)
                        val r = units * scale
                        val at = p(pl.x, pl.y)
                        val color = graphColor(pl.node.type)
                        if (pl.seed) drawCircle(color.copy(alpha = 0.3f), r + 6 * scale, at, style = Stroke(2 * scale))
                        drawNodeShape(pl.node.type, at, r, color)
                        if (pl.seed) {
                            val t = measurer.measure(cut(pl.node.label, 22), seedStyle)
                            drawText(t, topLeft = Offset(at.x - t.size.width / 2, at.y + r + 8 * scale))
                        } else {
                            // Along the spoke, outward from the node (flipped on the left so it reads
                            // left to right), so neighbouring labels don't collide.
                            val t = measurer.measure(cut(pl.node.label, 16), labelStyle)
                            val d = kotlin.math.hypot(pl.x, pl.y) + units + 5f
                            val anchor = Offset(c.x + d * cos(pl.angle) * scale, c.y + d * sin(pl.angle) * scale)
                            val right = cos(pl.angle) >= 0
                            val deg = Math.toDegrees(pl.angle.toDouble()).toFloat() + if (right) 0f else 180f
                            rotate(deg, pivot = anchor) {
                                val left = if (right) anchor.x else anchor.x - t.size.width
                                drawText(t, topLeft = Offset(left, anchor.y - t.size.height / 2))
                            }
                        }
                    }
                    // "+N more" pills.
                    layout.overflow.forEach { o ->
                        val at = p(o.x, o.y)
                        val w = 32 * scale; val h = 18 * scale
                        drawRoundRect(SlateDark700, Offset(at.x - w / 2, at.y - h / 2), Size(w, h), CornerRadius(h / 2))
                        val t = measurer.measure("+${o.count}", TextStyle(fontSize = 10.sp, color = TextPrimary, fontWeight = FontWeight.Bold))
                        drawText(t, topLeft = Offset(at.x - t.size.width / 2, at.y - t.size.height / 2))
                    }
                }
                Spacer(Modifier.height(8.dp))
                Text("Tap a node to open it · tap +N to show more of a type · tap a type below to hide it", fontSize = 11.sp, color = TextMuted)
                Spacer(Modifier.height(6.dp))
                // The types on the ring (the seed's direct links), plus any hidden ones so they can come back.
                val allTypes = remember(graph) { graph?.let { GraphLayout.layout(it, Int.MAX_VALUE, emptySet()).sectors.associate { s -> s.type to s.total } }.orEmpty() }
                val types = allTypes
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    types.forEach { (type, count) ->
                        val off = type in hidden
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.clip(RoundedCornerShape(6.dp))
                                .clickable(onClickLabel = if (off) "Show ${graphTypeLabel(type)}" else "Hide ${graphTypeLabel(type)}") { hidden = if (off) hidden - type else hidden + type }
                                .padding(horizontal = 4.dp, vertical = 3.dp)
                        ) {
                            Box(Modifier.size(9.dp).background(graphColor(type).copy(alpha = if (off) 0.25f else 1f), CircleShape))
                            Spacer(Modifier.width(4.dp))
                            Text("${graphTypeLabel(type)} $count", fontSize = 11.sp, color = if (off) TextMuted.copy(alpha = 0.5f) else TextSecondary)
                        }
                    }
                }
            }
        }
    }
}

/** The web's shapes: malware hexagon, technique rounded square, CVE triangle, country ringed circle, article card, else a circle. */
private fun DrawScope.drawNodeShape(type: String, c: Offset, r: Float, color: Color) {
    fun polygon(sides: Int): Path = Path().apply {
        for (i in 0 until sides) {
            val a = -Math.PI / 2 + 2 * Math.PI * i / sides
            val pt = Offset(c.x + r * cos(a).toFloat(), c.y + r * sin(a).toFloat())
            if (i == 0) moveTo(pt.x, pt.y) else lineTo(pt.x, pt.y)
        }
        close()
    }
    when (type) {
        "malware" -> drawPath(polygon(6), color)
        "ttp" -> drawRoundRect(color, Offset(c.x - r * 0.8f, c.y - r * 0.8f), Size(r * 1.6f, r * 1.6f), CornerRadius(3.dp.toPx()))
        "cve" -> drawPath(polygon(3), color)
        "entry" -> drawRoundRect(color, Offset(c.x - r * 1.3f, c.y - r * 0.8f), Size(r * 2.6f, r * 1.6f), CornerRadius(4.dp.toPx()))
        "country" -> {
            drawCircle(color, r, c)
            drawCircle(color.copy(alpha = 0.4f), r + 3.dp.toPx() * 0.6f, c, style = Stroke(1.5.dp.toPx() * 0.6f))
        }
        else -> drawCircle(color, r, c)
    }
}
