package com.example.intelfeed.ui.navigation

import com.example.intelfeed.data.model.EntityType
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json

/**
 * Destinations on the back stack (rendered by Navigation3's NavDisplay in Navigation.kt). Login is
 * not a route: it replaces the whole stack while signed out.
 */
@Serializable
sealed interface Route {
    /** The tabbed shell: Feed, Workbench, Search. */
    @Serializable
    data object Home : Route

    /**
     * An article. [contextIds] is the list it was opened from, for next/previous. Null means the
     * feed list, which is read live so paging keeps next/previous going.
     */
    @Serializable
    data class Reader(val entryId: String, val contextIds: List<String>? = null) : Route

    /** An entity profile. [idOrName] is a server id when known, otherwise a name to resolve. */
    @Serializable
    data class Entity(val type: EntityType, val idOrName: String, val name: String? = null) : Route

    /** A story thread, opened from a Priority Queue story row or a similar-article link. */
    @Serializable
    data class Thread(val slug: String, val title: String? = null) : Route

    @Serializable
    data object Settings : Route

    /** The server's intelligence requirements (shared keyword matching) and their matches. */
    @Serializable
    data object Requirements : Route
}

/**
 * The back stack as a string for the saved instance state, so the app comes back where it was after
 * Android stops its process in the background (it used to reopen on the Priority Queue). The class
 * discriminator isn't "type": Route.Entity has a property with that name.
 */
object RouteCodec {
    private val json = Json { classDiscriminator = "route"; ignoreUnknownKeys = true }
    private val serializer = ListSerializer(Route.serializer())

    /** Null if the stack can't be written; saving it must never crash the app. */
    fun encode(routes: List<Route>): String? = runCatching { json.encodeToString(serializer, routes) }.getOrNull()

    /** The routes in [encoded], or null if it can't be read (e.g. saved by a different version). */
    fun decode(encoded: String): List<Route>? = runCatching { json.decodeFromString(serializer, encoded) }.getOrNull()
}
