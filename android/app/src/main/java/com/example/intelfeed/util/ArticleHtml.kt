package com.example.intelfeed.util

import org.jsoup.Jsoup
import org.jsoup.nodes.Element
import org.jsoup.nodes.Node
import org.jsoup.nodes.TextNode
import java.net.URI

/**
 * Turns feed-supplied article HTML into a small list of blocks the reader renders natively:
 * paragraphs and headings with bold/italic/code/link spans, list items, quotes, code blocks,
 * images and dividers. Scripts, styles, frames and forms are dropped. Nothing here executes or
 * trusts the HTML; links are only ever http(s) and are opened through ExternalLinks.
 *
 * Plain Kotlin with no Compose types, so it can be unit-tested on the JVM.
 */
object ArticleHtml {

    sealed interface Block

    enum class TextKind { BODY, H1, H2, H3, QUOTE, CAPTION }

    data class Paragraph(val text: RichText, val kind: TextKind = TextKind.BODY) : Block

    /** [marker] is "•", "◦" or "3."; empty for a second paragraph inside the same item. */
    data class ListItem(val text: RichText, val marker: String, val depth: Int) : Block

    /**
     * A code block. [breaks] are the text-node boundaries (see [RichText.breaks]); [marks] are the
     * ENTITY/GLOSSARY spans ArticleLinker adds (the web highlights names inside code too).
     */
    data class Code(val text: String, val breaks: List<Int> = emptyList(), val marks: List<Span> = emptyList()) : Block

    data class Image(val url: String, val alt: String?) : Block

    data object Divider : Block

    // ENTITY, GLOSSARY and KEYWORD are added by ArticleLinker, not by the HTML parser.
    enum class SpanKind { BOLD, ITALIC, CODE, LINK, STRIKE, UNDERLINE, MARK, ENTITY, KEYWORD, GLOSSARY }

    /**
     * [url] is set for LINK. For ENTITY, [entityType] (server key, e.g. "threat_actor"),
     * [entityId] and [entityName] say which entity the phrase is. For GLOSSARY, [glossaryId] is the term.
     */
    data class Span(
        val start: Int,
        val end: Int,
        val kind: SpanKind,
        val url: String? = null,
        val entityType: String? = null,
        val entityId: String? = null,
        val entityName: String? = null,
        val glossaryId: String? = null
    )

    /**
     * [breaks] are the offsets where one HTML text node ends and the next begins (e.g. at the edges
     * of a <b> or <a>). The web reader matches entity names one text node at a time, so a name split
     * across two nodes isn't marked there; ArticleLinker uses these to do the same.
     */
    data class RichText(val text: String, val spans: List<Span> = emptyList(), val breaks: List<Int> = emptyList())

    private val DROP = "script,style,noscript,iframe,svg,form,button,input,select,textarea,object,embed,template,canvas,audio,video"
    private val WHITESPACE = Regex("[\\s\\u00A0]+")
    private const val CELL_SEPARATOR = "  ·  "
    // Icon fonts put glyphs in the Private Use Area; they render as boxes (e.g. The Hacker News byline).
    private val PRIVATE_USE = Regex("[\\uE000-\\uF8FF]")

    /**
     * [articleUrl] resolves relative links and images. [serverUrl] resolves the server's own image
     * proxy paths (/api/proxy/image?...), which need the session token (see ApiClient.imageHttpClient).
     */
    fun parse(html: String, articleUrl: String?, serverUrl: String?): List<Block> {
        val doc = Jsoup.parseBodyFragment(html, articleUrl.orEmpty())
        doc.select(DROP).remove()
        val walker = Walker(articleUrl, serverUrl)
        walker.walkChildren(doc.body())
        walker.flush()
        return walker.blocks.cleanUp()
    }

    /** Collapses repeated dividers and drops a leading/trailing divider. */
    private fun List<Block>.cleanUp(): List<Block> {
        val out = ArrayList<Block>(size)
        for (b in this) {
            if (b is Divider && (out.isEmpty() || out.last() is Divider)) continue
            out += b
        }
        while (out.lastOrNull() is Divider) out.removeAt(out.lastIndex)
        return out
    }

    private class Walker(private val articleUrl: String?, private val serverUrl: String?) {
        val blocks = mutableListOf<Block>()
        private val text = StringBuilder()
        private val spans = mutableListOf<Span>()
        private val breaks = mutableListOf<Int>()
        private var kind = TextKind.BODY
        private var listMarker: String? = null
        private var listDepth = 0

        fun walkChildren(el: Element) {
            for (node in el.childNodes()) {
                when (node) {
                    is TextNode -> appendText(node.wholeText)
                    is Element -> handle(node)
                }
            }
        }

        private fun handle(el: Element) {
            when (el.normalName()) {
                "br" -> text.append('\n')
                "a" -> styled(el, SpanKind.LINK, linkUrl(el))
                "b", "strong" -> styled(el, SpanKind.BOLD)
                "i", "em", "cite", "dfn" -> styled(el, SpanKind.ITALIC)
                "code", "kbd", "samp", "tt" -> styled(el, SpanKind.CODE)
                "s", "strike", "del" -> styled(el, SpanKind.STRIKE)
                "u", "ins" -> styled(el, SpanKind.UNDERLINE)
                "mark" -> styled(el, SpanKind.MARK)
                "img" -> image(el)
                "picture" -> el.selectFirst("img")?.let { image(it) }
                "hr" -> { flush(); blocks += Divider }
                "pre" -> {
                    flush()
                    codeBlock(el)?.let { blocks += it }
                }
                "h1" -> heading(el, TextKind.H1)
                "h2" -> heading(el, TextKind.H2)
                "h3", "h4", "h5", "h6" -> heading(el, TextKind.H3)
                "blockquote" -> withKind(el, TextKind.QUOTE)
                "figcaption", "caption" -> withKind(el, TextKind.CAPTION)
                "ul", "ol" -> list(el)
                "li" -> listItem(el, "•") // stray li outside a list
                "table" -> table(el)
                "p", "div", "section", "article", "header", "footer", "main", "aside", "figure", "center",
                "details", "summary", "dl", "dt", "dd", "address", "nav" -> { flush(); walkChildren(el); flush() }
                else -> walkChildren(el) // span, font, sup, small, time… : inline, keep the text
            }
        }

        private fun styled(el: Element, spanKind: SpanKind, url: String? = null) {
            val start = text.length
            walkChildren(el)
            val end = text.length
            if (end > start && (spanKind != SpanKind.LINK || url != null)) spans += Span(start, end, spanKind, url)
        }

        private fun heading(el: Element, headingKind: TextKind) {
            flush()
            val previous = kind
            kind = headingKind
            walkChildren(el)
            flush()
            kind = previous
        }

        private fun withKind(el: Element, blockKind: TextKind) {
            flush()
            val previous = kind
            kind = blockKind
            walkChildren(el)
            flush()
            kind = previous
        }

        private fun list(el: Element) {
            flush()
            val ordered = el.normalName() == "ol"
            var index = el.attr("start").toIntOrNull() ?: 1
            listDepth++
            for (child in el.children()) {
                if (child.normalName() == "li") {
                    val marker = if (ordered) "${index++}." else if (listDepth > 1) "◦" else "•"
                    listItem(child, marker)
                } else {
                    handle(child)
                }
            }
            flush()
            listDepth--
        }

        private fun listItem(el: Element, marker: String) {
            flush()
            val previousMarker = listMarker
            listMarker = marker
            walkChildren(el)
            flush()
            listMarker = previousMarker
        }

        private fun table(el: Element) {
            flush()
            for (row in el.select("tr")) {
                val cells = row.children().filter { it.normalName() == "td" || it.normalName() == "th" }
                    .map { it.text().trim() }
                    .filter { it.isNotEmpty() }
                if (cells.isEmpty()) continue
                val line = cells.joinToString(CELL_SEPARATOR)
                // Each cell is its own text on the web, so a name can't be matched across cells.
                val breaks = cells.dropLast(1).runningFold(0) { at, cell -> at + cell.length + CELL_SEPARATOR.length }.drop(1)
                    .flatMap { next -> listOf(next - CELL_SEPARATOR.length, next) }
                val header = row.children().any { it.normalName() == "th" }
                blocks += Paragraph(RichText(line, if (header) listOf(Span(0, line.length, SpanKind.BOLD)) else emptyList(), breaks))
            }
        }

        /** A <pre> as a code block: its text (a <br> is a newline) and where its text nodes meet. */
        private fun codeBlock(el: Element): Code? {
            val sb = StringBuilder()
            val nodeStarts = mutableListOf<Int>()
            fun walk(node: Node) {
                when (node) {
                    is TextNode -> {
                        if (sb.isNotEmpty()) nodeStarts += sb.length
                        sb.append(node.wholeText)
                    }
                    is Element -> if (node.normalName() == "br") sb.append('\n') else node.childNodes().forEach(::walk)
                }
            }
            el.childNodes().forEach(::walk)
            val raw = sb.toString()
            val lead = raw.length - raw.trimStart('\n').length
            val code = raw.trim('\n').trimEnd()
            if (code.isBlank()) return null
            val breaks = nodeStarts.map { it - lead }.filter { it > 0 && it < code.length }.distinct()
            return Code(code, breaks)
        }

        private fun image(el: Element) {
            val w = el.attr("width").toIntOrNull()
            val h = el.attr("height").toIntOrNull()
            if ((w != null && w <= 2) || (h != null && h <= 2)) return // tracking pixel
            val raw = listOf(el.attr("src"), el.attr("data-src"), el.attr("srcset").substringBefore(' '))
                .firstOrNull { it.isNotBlank() } ?: return
            val url = resolveImage(raw) ?: return
            flush()
            blocks += Image(url, el.attr("alt").takeIf { it.isNotBlank() })
        }

        private fun resolveImage(src: String): String? {
            val s = src.trim()
            return when {
                s.startsWith("data:") -> null
                s.startsWith("//") -> "https:$s"
                s.startsWith("http://") || s.startsWith("https://") -> s
                s.startsWith("/api/") && serverUrl != null -> serverUrl.trimEnd('/') + s
                articleUrl != null -> runCatching { URI(articleUrl).resolve(s).toString() }.getOrNull()
                    ?.takeIf { it.startsWith("http://") || it.startsWith("https://") }
                else -> null
            }
        }

        private fun linkUrl(el: Element): String? {
            val href = el.attr("href").trim()
            if (href.isEmpty() || href.startsWith("#")) return null
            val abs = if (href.startsWith("http://") || href.startsWith("https://")) href else el.absUrl("href")
            return abs.takeIf { it.startsWith("http://") || it.startsWith("https://") }
        }

        private fun appendText(raw: String) {
            var t = raw.replace(PRIVATE_USE, "").replace(WHITESPACE, " ")
            if (t.isEmpty()) return
            val last = text.lastOrNull()
            if (t.startsWith(' ') && (last == null || last == ' ' || last == '\n')) t = t.trimStart()
            if (t.isEmpty()) return
            // Every text node after the first starts a new one (see RichText.breaks).
            if (text.isNotEmpty()) breaks += text.length
            text.append(t)
        }

        /** Emits the buffered inline text as a block (paragraph, heading or list item). */
        fun flush() {
            if (text.isEmpty()) return
            val full = text.toString()
            val lead = full.length - full.trimStart().length
            val trimmed = full.trim()
            text.setLength(0)
            val shifted = spans.mapNotNull { s ->
                val start = (s.start - lead).coerceIn(0, trimmed.length)
                val end = (s.end - lead).coerceIn(0, trimmed.length)
                if (end > start) s.copy(start = start, end = end) else null
            }
            spans.clear()
            val shiftedBreaks = breaks.map { it - lead }.filter { it > 0 && it < trimmed.length }.distinct()
            breaks.clear()
            if (trimmed.isEmpty()) return
            val rich = RichText(trimmed, shifted, shiftedBreaks)
            val marker = listMarker
            if (marker != null) {
                blocks += ListItem(rich, marker, listDepth.coerceAtLeast(1))
                listMarker = "" // later paragraphs in the same item continue without a bullet
            } else {
                blocks += Paragraph(rich, kind)
            }
        }
    }

    private val blocksCache = java.util.Collections.synchronizedMap(
        object : java.util.LinkedHashMap<String, List<Block>>(50, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, List<Block>>?): Boolean = size > 50
        }
    )

    private fun cacheKey(detail: com.example.intelfeed.data.model.EntryDetail, serverUrl: String?): String =
        "${detail.id}:${detail.contentHtml?.hashCode() ?: 0}:${detail.translatedHtml?.hashCode() ?: 0}:${detail.contentText?.hashCode() ?: 0}:${serverUrl.orEmpty()}"

    fun getCached(detail: com.example.intelfeed.data.model.EntryDetail, serverUrl: String?): List<Block>? =
        blocksCache[cacheKey(detail, serverUrl)]

    /** HTML when there is some, otherwise the plain text split into paragraphs, otherwise the summary. */
    fun parseBlocks(detail: com.example.intelfeed.data.model.EntryDetail, serverUrl: String?): List<Block> {
        val key = cacheKey(detail, serverUrl)
        blocksCache[key]?.let { return it }
        val blocks = parseBlocksUncached(detail, serverUrl)
        blocksCache[key] = blocks
        return blocks
    }

    private fun parseBlocksUncached(detail: com.example.intelfeed.data.model.EntryDetail, serverUrl: String?): List<Block> {
        val html = detail.translatedHtml?.takeIf { it.isNotBlank() } ?: detail.contentHtml?.takeIf { it.isNotBlank() }
        if (html != null) {
            val blocks = parse(html, detail.url, serverUrl)
            if (blocks.isNotEmpty()) return blocks
        }
        val text = detail.contentText?.trim()?.takeIf { it.isNotEmpty() }
        if (text != null) {
            return text.split(Regex("\\n\\s*\\n")).map { it.trim() }.filter { it.isNotEmpty() }
                .map { Paragraph(RichText(it)) }
        }
        return detail.summary?.takeIf { it.isNotBlank() }?.let { parse(it, detail.url, serverUrl) } ?: emptyList()
    }
}

