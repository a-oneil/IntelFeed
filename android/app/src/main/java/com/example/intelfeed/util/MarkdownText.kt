package com.example.intelfeed.util

import com.example.intelfeed.util.ArticleHtml.Block
import com.example.intelfeed.util.ArticleHtml.RichText
import com.example.intelfeed.util.ArticleHtml.Span
import com.example.intelfeed.util.ArticleHtml.SpanKind
import com.example.intelfeed.util.ArticleHtml.TextKind
import java.net.URI

/**
 * Turns the server's Markdown (AI day briefings) into the same blocks the article reader renders
 * (ArticleHtml / ArticleContent): headings, paragraphs, bullet and numbered lists, quotes, code
 * blocks, rules, and bold/italic/code/strike/link spans.
 *
 * Only a subset of Markdown is needed; anything unrecognised stays as plain text, so nothing is
 * lost. Links are kept only when they resolve to http(s); relative links ("/?entry=<id>") are
 * resolved against [baseUrl] (the IntelFeed server) so InAppLinks can open them in the app.
 *
 * Plain Kotlin with no Android types, so it can be unit-tested on the JVM.
 */
object MarkdownText {

    private val HEADING = Regex("^(#{1,6})\\s+(.*?)\\s*#*\\s*$")
    private val RULE = Regex("^(?:-{3,}|\\*{3,}|_{3,})$")
    private val LIST_ITEM = Regex("^(\\s*)([-*+]|\\d{1,3}[.)])\\s+(.*)$")
    private const val ESCAPABLE = "\\`*_{}[]()#+-.!~>|"

    fun parse(markdown: String, baseUrl: String? = null): List<Block> {
        val blocks = mutableListOf<Block>()
        val paragraph = mutableListOf<String>()
        val quote = mutableListOf<String>()
        var code: StringBuilder? = null
        // The list item being built: continuation lines are joined onto it.
        var itemText: StringBuilder? = null
        var itemMarker = ""
        var itemDepth = 1

        fun flushParagraph() {
            if (paragraph.isNotEmpty()) {
                blocks += ArticleHtml.Paragraph(inline(paragraph.joinToString(" "), baseUrl))
                paragraph.clear()
            }
        }
        fun flushQuote() {
            if (quote.isNotEmpty()) {
                blocks += ArticleHtml.Paragraph(inline(quote.joinToString(" "), baseUrl), TextKind.QUOTE)
                quote.clear()
            }
        }
        fun flushItem() {
            itemText?.let { blocks += ArticleHtml.ListItem(inline(it.toString(), baseUrl), itemMarker, itemDepth) }
            itemText = null
        }
        fun flushAll() { flushParagraph(); flushQuote(); flushItem() }

        for (rawLine in markdown.replace("\r\n", "\n").split('\n')) {
            val line = rawLine.trimEnd()
            val trimmed = line.trim()

            val codeBuffer = code
            if (codeBuffer != null) {
                if (trimmed.startsWith("```")) {
                    blocks += ArticleHtml.Code(codeBuffer.toString().trimEnd('\n'))
                    code = null
                } else {
                    codeBuffer.append(rawLine).append('\n')
                }
                continue
            }

            when {
                trimmed.startsWith("```") -> { flushAll(); code = StringBuilder() }
                trimmed.isEmpty() -> flushAll()
                HEADING.matches(trimmed) -> {
                    flushAll()
                    val m = HEADING.matchEntire(trimmed)!!
                    val kind = when (m.groupValues[1].length) { 1 -> TextKind.H1; 2 -> TextKind.H2; else -> TextKind.H3 }
                    blocks += ArticleHtml.Paragraph(inline(m.groupValues[2], baseUrl), kind)
                }
                RULE.matches(trimmed) -> { flushAll(); blocks += ArticleHtml.Divider }
                trimmed.startsWith(">") -> {
                    flushParagraph(); flushItem()
                    quote += trimmed.removePrefix(">").trim()
                }
                LIST_ITEM.matches(line) -> {
                    flushParagraph(); flushQuote(); flushItem()
                    val m = LIST_ITEM.matchEntire(line)!!
                    val indent = m.groupValues[1].replace("\t", "    ").length
                    itemDepth = (indent / 2 + 1).coerceAtMost(3)
                    val bullet = m.groupValues[2]
                    itemMarker = when {
                        bullet.first().isDigit() -> bullet.dropLast(1) + "."
                        itemDepth > 1 -> "◦"
                        else -> "•"
                    }
                    itemText = StringBuilder(m.groupValues[3])
                }
                itemText != null && rawLine.startsWith(" ") -> itemText!!.append(' ').append(trimmed)
                else -> {
                    flushQuote(); flushItem()
                    paragraph += trimmed
                }
            }
        }
        code?.let { blocks += ArticleHtml.Code(it.toString().trimEnd('\n')) }
        flushAll()
        return blocks
    }

    /** Inline Markdown: **bold**, __bold__, *italic*, _italic_, `code`, ~~strike~~, [text](url), \escapes. */
    fun inline(src: String, baseUrl: String? = null): RichText {
        val out = StringBuilder()
        val spans = mutableListOf<Span>()

        fun appendRich(rich: RichText, kind: SpanKind?, url: String? = null) {
            val start = out.length
            out.append(rich.text)
            rich.spans.forEach { spans += it.copy(start = it.start + start, end = it.end + start) }
            if (kind != null && out.length > start) spans += Span(start, out.length, kind, url)
        }

        var i = 0
        while (i < src.length) {
            val c = src[i]
            when {
                c == '\\' && i + 1 < src.length && src[i + 1] in ESCAPABLE -> { out.append(src[i + 1]); i += 2 }
                c == '`' -> {
                    val end = src.indexOf('`', i + 1)
                    if (end > i + 1) {
                        val start = out.length
                        out.append(src, i + 1, end)
                        spans += Span(start, out.length, SpanKind.CODE)
                        i = end + 1
                    } else { out.append(c); i++ }
                }
                src.startsWith("**", i) || src.startsWith("__", i) || src.startsWith("~~", i) -> {
                    val marker = src.substring(i, i + 2)
                    val end = src.indexOf(marker, i + 2)
                    if (end > i + 2) {
                        appendRich(inline(src.substring(i + 2, end), baseUrl), if (marker == "~~") SpanKind.STRIKE else SpanKind.BOLD)
                        i = end + 2
                    } else { out.append(marker); i += 2 }
                }
                (c == '*' || c == '_') && isEmphasisStart(src, i) -> {
                    val end = findEmphasisEnd(src, i)
                    if (end > 0) {
                        appendRich(inline(src.substring(i + 1, end), baseUrl), SpanKind.ITALIC)
                        i = end + 1
                    } else { out.append(c); i++ }
                }
                c == '[' -> {
                    val close = matchingBracket(src, i)
                    val hasUrl = close > i && close + 1 < src.length && src[close + 1] == '('
                    val urlEnd = if (hasUrl) src.indexOf(')', close + 2) else -1
                    if (urlEnd > 0) {
                        val label = inline(src.substring(i + 1, close), baseUrl)
                        val target = src.substring(close + 2, urlEnd).trim().substringBefore(' ').removeSurrounding("<", ">")
                        val url = resolve(target, baseUrl)
                        appendRich(label, if (url != null) SpanKind.LINK else null, url)
                        i = urlEnd + 1
                    } else { out.append(c); i++ }
                }
                else -> { out.append(c); i++ }
            }
        }
        return RichText(out.toString(), spans.filter { it.end > it.start })
    }

    // An underscore inside a word (snake_case, CVE_2024) isn't emphasis.
    private fun isEmphasisStart(src: String, i: Int): Boolean {
        val next = src.getOrNull(i + 1) ?: return false
        if (next.isWhitespace()) return false
        return src[i] == '*' || i == 0 || !src[i - 1].isLetterOrDigit()
    }

    private fun findEmphasisEnd(src: String, start: Int): Int {
        val marker = src[start]
        var j = src.indexOf(marker, start + 1)
        while (j > start + 1) {
            val closesWord = marker == '*' || j + 1 >= src.length || !src[j + 1].isLetterOrDigit()
            if (!src[j - 1].isWhitespace() && closesWord) return j
            j = src.indexOf(marker, j + 1)
        }
        return -1
    }

    private fun matchingBracket(src: String, open: Int): Int {
        var depth = 0
        for (j in open until src.length) {
            when (src[j]) {
                '[' -> depth++
                ']' -> { depth--; if (depth == 0) return j }
            }
        }
        return -1
    }

    private fun resolve(target: String, baseUrl: String?): String? {
        if (target.isEmpty()) return null
        if (target.startsWith("http://", ignoreCase = true) || target.startsWith("https://", ignoreCase = true)) return target
        if (baseUrl == null || target.startsWith("#")) return null
        return runCatching { URI(baseUrl.trimEnd('/') + "/").resolve(target).toString() }.getOrNull()
            ?.takeIf { it.startsWith("http://") || it.startsWith("https://") }
    }
}
