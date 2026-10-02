package com.example.intelfeed.util

import androidx.core.text.HtmlCompat

/** Plain-text rendering of feed-supplied HTML (summaries and article bodies). */
object HtmlText {

    private val scriptOrStyleBlock = Regex("<(script|style)\\b[^>]*>[\\s\\S]*?</\\1\\s*>", RegexOption.IGNORE_CASE)
    private val listItemTag = Regex("<li\\b[^>]*>", RegexOption.IGNORE_CASE)
    private val whitespace = Regex("\\s+")

    private const val MAX_CACHE_ENTRIES = 512
    private const val MAX_CACHEABLE_LENGTH = 4096
    private val cacheLock = Any()
    private val plainTextCache = object : LinkedHashMap<String, String>(128, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, String>?): Boolean = size > MAX_CACHE_ENTRIES
    }
    private val snippetCache = object : LinkedHashMap<String, String>(128, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, String>?): Boolean = size > MAX_CACHE_ENTRIES
    }

    private val basicTagRegex = Regex("<[^>]*>")
    private val parameterRegex = Regex("<parameter\\b[^>]*>[\\s\\S]*?(</parameter>|$)", RegexOption.IGNORE_CASE)
    private val thoughtRegex = Regex("<(?:thought|reasoning|scratchpad)\\b[^>]*>[\\s\\S]*?(</(?:thought|reasoning|scratchpad)>|$)", RegexOption.IGNORE_CASE)
    private val descTagRegex = Regex("</?(?:new_)?description\\b[^>]*>", RegexOption.IGNORE_CASE)

    /** Basic unescape fallback for JVM unit tests or simple strings. */
    fun unescapeBasicHtml(text: String): String =
        text.replace(basicTagRegex, "")
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("&apos;", "'")
            .replace("&nbsp;", " ")
            .trim()

    /**
     * Strips backend LLM artifacts like </new_description>, <parameter name="reason">...</parameter>,
     * or reasoning/scratchpad tags that occasionally leak into entity descriptions from server prompts.
     */
    fun cleanAiArtifacts(text: String?): String? {
        if (text.isNullOrBlank()) return null
        val stripped = text
            .replace(parameterRegex, "")
            .replace(thoughtRegex, "")
            .replace(descTagRegex, "")
            .trim()
        if (stripped.isBlank()) return null
        return if (stripped.contains('&') || stripped.contains('<')) {
            toPlainText(stripped).trim().ifBlank { null }
        } else {
            stripped
        }
    }

    /** Keeps paragraph breaks and list bullets, and decodes every entity (numeric ones too) exactly once. */
    fun toPlainText(html: String): String {
        if (html.isEmpty()) return ""
        val canCache = html.length <= MAX_CACHEABLE_LENGTH
        if (canCache) {
            synchronized(cacheLock) {
                plainTextCache[html]?.let { return it }
            }
        }
        val prepared = html
            .replace(scriptOrStyleBlock, "") // fromHtml would otherwise render their contents as text
            .replace(listItemTag) { it.value + "• " }
        val result = try {
            HtmlCompat.fromHtml(prepared, HtmlCompat.FROM_HTML_MODE_LEGACY)
                .toString()
                .replace("￼", "") // placeholder character fromHtml inserts for <img>
                .trim()
        } catch (_: Exception) {
            unescapeBasicHtml(prepared)
        }
        if (canCache) {
            synchronized(cacheLock) {
                plainTextCache[html] = result
            }
        }
        return result
    }

    /**
     * Single-paragraph version for list cards with a couple of lines. A long value (some feeds put
     * the whole article in the summary) is cut before parsing: it used to be parsed in full, on the
     * main thread, every time its card came back into view, since long values aren't cached.
     */
    fun toSnippet(html: String): String {
        if (html.isEmpty()) return ""
        val source = if (html.length > MAX_CACHEABLE_LENGTH) cutForSnippet(html) else html
        synchronized(cacheLock) {
            snippetCache[source]?.let { return it }
        }
        val result = toPlainText(source).replace(whitespace, " ")
        synchronized(cacheLock) {
            snippetCache[source] = result
        }
        return result
    }

    private val unclosedScriptOrStyle = Regex("<(script|style)\\b(?![\\s\\S]*</\\1\\s*>)", RegexOption.IGNORE_CASE)

    /** The start of [html], far more than a card shows, cut so it doesn't end inside a tag or an unclosed script/style. */
    internal fun cutForSnippet(html: String): String {
        var cut = html.substring(0, MAX_CACHEABLE_LENGTH)
        val lastOpen = cut.lastIndexOf('<')
        if (lastOpen > cut.lastIndexOf('>')) cut = cut.substring(0, lastOpen)
        // fromHtml shows a script's or style's contents as text; its closing tag may have been cut off.
        unclosedScriptOrStyle.find(cut)?.let { cut = cut.substring(0, it.range.first) }
        return cut
    }

    internal fun clearCache() = synchronized(cacheLock) {
        plainTextCache.clear()
        snippetCache.clear()
    }
}
