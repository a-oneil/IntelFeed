package com.example.intelfeed.util

import okhttp3.HttpUrl.Companion.toHttpUrlOrNull

object WebUrl {

    /**
     * Cleans up a web address the user typed or pasted (a feed, a website, an article page):
     * trims it, adds https:// when no scheme is given, and returns null unless it's a valid
     * http(s) URL with a host. Unlike ServerUrl.normalize, the path and query are kept, because
     * feed addresses often depend on them (…/feed?format=rss).
     */
    fun normalize(raw: String): String? {
        val trimmed = raw.trim()
        if (trimmed.isEmpty() || trimmed.any { it.isWhitespace() }) return null
        val withScheme = when {
            "://" in trimmed -> trimmed
            trimmed.startsWith("http:", ignoreCase = true) || trimmed.startsWith("https:", ignoreCase = true) -> return null
            else -> "https://$trimmed"
        }
        val url = withScheme.toHttpUrlOrNull() ?: return null
        // A bare word ("feed") would become host "feed"; require a dotted name, an IPv6 address or localhost.
        val host = url.host
        if (host.isBlank() || ('.' !in host && ':' !in host && host != "localhost")) return null
        return url.toString()
    }
}
