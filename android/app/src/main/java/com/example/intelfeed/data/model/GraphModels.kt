package com.example.intelfeed.data.model

import kotlinx.serialization.Serializable

/**
 * GET /api/intelligence/graph/{type}/{id}?depth=1 (window_days optional), the web profile's
 * relationship graph. Node ids are "<type>-<id>"; the first node is the entity itself. "entry"
 * nodes are articles.
 */
@Serializable
data class EntityGraph(val nodes: List<GraphNode> = emptyList(), val edges: List<GraphEdge> = emptyList())

@Serializable
data class GraphNode(val id: String, val type: String = "", val label: String = "", val size: Double = 1.0)

@Serializable
data class GraphEdge(
    val source: String,
    val target: String,
    val weight: Double = 1.0,
    // Relationship verb, e.g. "uses", "exploits".
    val label: String? = null,
    // "possible", "probable" or "confirmed"; the graph dashes "possible" links.
    val confidence: String? = null
)
