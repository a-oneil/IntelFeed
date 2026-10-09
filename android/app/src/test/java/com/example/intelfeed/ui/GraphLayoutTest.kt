package com.example.intelfeed.ui

import com.example.intelfeed.data.model.EntityGraph
import com.example.intelfeed.data.model.GraphEdge
import com.example.intelfeed.data.model.GraphNode
import com.example.intelfeed.ui.entity.GraphLayout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.math.hypot

class GraphLayoutTest {

    private val seed = GraphNode("threat_actor-q", "threat_actor", "Qilin", 100.0)
    private fun node(type: String, i: Int) = GraphNode("$type-$i", type, "$type $i", 80.0)

    private fun graph(): EntityGraph {
        val cves = (1..8).map { node("cve", it) }
        val tools = (1..2).map { node("tool", it) }
        val edges = cves.mapIndexed { i, n -> GraphEdge(seed.id, n.id, weight = i / 10.0) } +
            tools.map { GraphEdge(it.id, seed.id, weight = 0.5) } +
            GraphEdge(cves[0].id, tools[0].id, 0.3)
        return EntityGraph(listOf(seed) + cves + tools + node("cwe", 1), edges)
    }

    @Test
    fun ringHoldsTheStrongestPerTypeWithOverflow() {
        val r = GraphLayout.layout(graph(), perType = 5, hiddenTypes = emptySet())
        assertEquals(1 + 5 + 2, r.placed.size)
        // Strongest CVE links first (weights 0.7, 0.6, 0.5, 0.4, 0.3).
        assertEquals(listOf("cve-8", "cve-7", "cve-6", "cve-5", "cve-4"), r.placed.filter { it.node.type == "cve" }.map { it.node.id })
        assertEquals(3, r.overflow.single { it.type == "cve" }.count)
        // Everything on the ring is the same distance from the entity; the cwe isn't a direct link.
        r.placed.drop(1).forEach { assertEquals(r.ringRadius, hypot(it.x, it.y), 0.01f) }
        assertTrue(r.placed.none { it.node.type == "cwe" })
        assertEquals(listOf("cve", "tool"), r.sectors.map { it.type })
    }

    @Test
    fun hiddenTypesAndRadius() {
        val r = GraphLayout.layout(graph(), perType = 5, hiddenTypes = setOf("cve"))
        assertEquals(listOf("tool"), r.sectors.map { it.type })
        // Few nodes: the web's minimum ring, 15 % of the view.
        assertEquals(60f, r.ringRadius, 0.01f)
        assertEquals(16f, GraphLayout.nodeRadius(seed), 0f)
        assertEquals("q", GraphLayout.entityId(seed))
    }
}
