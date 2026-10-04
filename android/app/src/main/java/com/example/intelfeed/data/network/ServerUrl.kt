package com.example.intelfeed.data.network

import okhttp3.HttpUrl.Companion.toHttpUrlOrNull

object ServerUrl {

    /**
     * Normalizes a user-entered instance address to an http(s) base URL without a trailing
     * slash, or returns null if it can't be used as a Retrofit base URL. A missing scheme
     * defaults to https. Callers must validate before persisting: Retrofit throws on an
     * invalid base URL, and a saved bad value would crash every launch.
     */
    fun normalize(raw: String): String? {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return null
        val withScheme = when {
            "://" in trimmed -> trimmed
            // A half-typed scheme ("https:/", "http:") would otherwise become host "https".
            trimmed.startsWith("http:", ignoreCase = true) || trimmed.startsWith("https:", ignoreCase = true) -> return null
            else -> "https://$trimmed"
        }
        val url = withScheme.toHttpUrlOrNull() ?: return null
        if (url.host.isBlank()) return null
        if (url.username.isNotEmpty() || url.password.isNotEmpty()) return null
        return url.newBuilder().query(null).fragment(null).build().toString().trimEnd('/')
    }

    /**
     * True when [raw] is a usable address the app would reach without TLS (http://): the password
     * and session tokens would then cross the network as plain text.
     */
    fun isCleartext(raw: String): Boolean = normalize(raw)?.startsWith("http://") == true
}
