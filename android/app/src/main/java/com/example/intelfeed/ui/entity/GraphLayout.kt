package com.example.intelfeed.ui.entity

import com.example.intelfeed.data.model.EntityGraph
import com.example.intelfeed.data.model.GraphEdge
import com.example.intelfeed.data.model.GraphNode
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.max
import kotlin.math.min
import kotlin.math.sin

/**
 * The web profile graph's radial layout (EntityGraph `re()`), first ring only: the entity in the
 * middle, its neighbours on a ring, grouped by type into sectors in the order the types first
 * appear, strongest links first, at most [perType] per type (the rest become a "+N" pill).
 * Sector widths follow each type's share, at least 0.25 rad, starting at the top (-π/2).
 * Coordinates are in abstract units around (0, 0); the view scales them to fit.
 */
object GraphLayout {

    data class Placed(val node: GraphNode, val x: Float, val y: Float, val angle: Float, val seed: Boolean)
    data class Sector(val type: String, val start: Float, val end: Float, val shown: Int, val total: Int)
    data class Overflow(val type: String, val count: Int, val x: Float, val y: Float, val angle: Float)

    data class Result(
        val placed: List<Placed>,
        val edges: List<GraphEdge>,
        val sectors: List<Sector>,
        val overflow: List<Overflow>,
        val ringRadius: Float
    ) {
        val byId: Map<String, Placed> = placed.associateBy { it.node.id }
    }

    // The web's per-node spacing (28 × ring spacing 1) and minimum ring (15 % of the view).
    private const val SPACING = 28f
    private const val MIN_SECTOR = 0.25f

    /** [size] is the web's view size (min of width and height) the minimum ring is based on. */
    fun layout(graph: EntityGraph, perType: Int, hiddenTypes: Set<String>, size: Float = 400f): Result {
        val seed = graph.nodes.firstOrNull() ?: return Result(emptyList(), emptyList(), emptyList(), emptyList(), 0f)
        val byId = graph.nodes.associateBy { it.id }
        // Strongest link per pair, and the seed's neighbours in the order the edges list them.
        val weights = HashMap<String, Double>()
        val neighbours = LinkedHashSet<String>()
        for (e in graph.edges) {
            val key = listOf(e.source, e.target).sorted().joinToString("|")
            if (e.weight > (weights[key] ?: 0.0)) weights[key] = e.weight
            if (e.source == seed.id) neighbours += e.target
            if (e.target == seed.id) neighbours += e.source
        }
        fun weight(id: String) = weights[listOf(seed.id, id).sorted().joinToString("|")] ?: 0.0

        val groups = LinkedHashMap<String, MutableList<GraphNode>>()
        for (id in neighbours) {
            val n = byId[id] ?: continue
            if (n.id == seed.id || n.type in hiddenTypes) continue
            groups.getOrPut(n.type) { mutableListOf() } += n
        }
        groups.values.forEach { list -> list.sortByDescending { weight(it.id) } }

        val placed = mutableListOf(Placed(seed, 0f, 0f, 0f, seed = true))
        val total = groups.values.sumOf { min(it.size, perType) }
        if (total == 0) return Result(placed, emptyList(), emptyList(), emptyList(), 0f)

        val arc = (2 * PI).toFloat()
        val startAt = (-PI / 2).toFloat()
        val radius = max(size * 0.15f, SPACING * total / arc)
        val sectors = mutableListOf<Sector>()
        val overflow = mutableListOf<Overflow>()
        var at = startAt
        for ((type, list) in groups) {
            val shown = list.take(perType)
            val width = max(shown.size.toFloat() / total * arc, MIN_SECTOR)
            shown.forEachIndexed { i, n ->
                val a = at + width * (i + 1) / (shown.size + 1)
                placed += Placed(n, radius * cos(a), radius * sin(a), a, seed = false)
            }
            if (list.size > shown.size) {
                val a = at + width - width * 0.05f
                overflow += Overflow(type, list.size - shown.size, radius * cos(a), radius * sin(a), a)
            }
            sectors += Sector(type, at, at + width, shown.size, list.size)
            at += width
        }
        // The minimum sector width can push the total past a full circle; squeeze back like the web.
        val used = at - startAt
        if (used > 0 && kotlin.math.abs(used - arc) > 0.01f) {
            val k = arc / used
            fun squeeze(a: Float) = startAt + (a - startAt) * k
            for (i in 1 until placed.size) {
                val p = placed[i]
                val a = squeeze(p.angle)
                placed[i] = p.copy(x = radius * cos(a), y = radius * sin(a), angle = a)
            }
            for (i in overflow.indices) {
                val o = overflow[i]
                val a = squeeze(o.angle)
                overflow[i] = o.copy(x = radius * cos(a), y = radius * sin(a), angle = a)
            }
            for (i in sectors.indices) sectors[i] = sectors[i].copy(start = squeeze(sectors[i].start), end = squeeze(sectors[i].end))
        }
        val visible = placed.map { it.node.id }.toSet()
        return Result(placed, graph.edges.filter { it.source in visible && it.target in visible }, sectors, overflow, radius)
    }

    /** The web's node radius: size × 2 + 4, kept to 6–16 (articles 4–12). */
    fun nodeRadius(node: GraphNode): Float =
        if (node.type == "entry") (node.size * 2 + 2).toFloat().coerceIn(4f, 12f) else (node.size * 2 + 4).toFloat().coerceIn(6f, 16f)

    /** "threat_actor-5a00…" → "5a00…". */
    fun entityId(node: GraphNode): String = node.id.removePrefix(node.type + "-")
}
