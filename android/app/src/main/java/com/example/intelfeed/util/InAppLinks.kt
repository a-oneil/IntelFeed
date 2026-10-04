package com.example.intelfeed.util

import okhttp3.HttpUrl.Companion.toHttpUrlOrNull

/** Recognises links to the IntelFeed web app that the Android app can open itself. */
object InAppLinks {

    private val ID = Regex("^[A-Za-z0-9-]{1,64}$")

    /**
     * The article id in a web-app link such as https://intelfeed.cc/?entry=<id> (the form the AI
     * briefings use), or null. Only links on the signed-in server ([serverUrl]) count, so a
     * look-alike host can't route into the app.
     */
    fun entryId(url: String, serverUrl: String?): String? {
        val link = url.trim().toHttpUrlOrNull() ?: return null
        val server = serverUrl?.toHttpUrlOrNull() ?: return null
        if (!link.scheme.equals(server.scheme, ignoreCase = true)) return null
        if (!link.host.equals(server.host, ignoreCase = true) || link.port != server.port) return null
        return link.queryParameter("entry")?.takeIf { ID.matches(it) }
    }
}
