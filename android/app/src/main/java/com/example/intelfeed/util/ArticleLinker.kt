package com.example.intelfeed.util

import com.example.intelfeed.util.ArticleHtml.Block
import com.example.intelfeed.util.ArticleHtml.RichText
import com.example.intelfeed.util.ArticleHtml.Span
import com.example.intelfeed.util.ArticleHtml.SpanKind

/**
 * Marks phrases in parsed article text the way the web reader does, in the web's order:
 *
 * 1. GLOSSARY terms (the web's `glossary-term` spans): `\b` word boundaries, any case, longest
 *    phrase first.
 * 2. ENTITY names (the web's EntityHighlighter): `(?<!\w)name(?!\w)`, any case, longest first.
 *    Text already inside a glossary term is skipped. On the same phrase the entity listed last
 *    wins, as in the web's lookup map.
 * 3. KEYWORD phrases (the app's tracked keywords and matched requirement keywords; the web has no
 *    equivalent): whole words, not inside links, code or anything already marked.
 *
 * Like the web, glossary and entity matching runs one HTML text node at a time
 * ([RichText.breaks]), so a name split by markup isn't matched, while names inside links and
 * code are. `\w` is ASCII there (JavaScript regexes without the `u` flag), so it is here too.
 * Plain Kotlin, so it runs off the main thread and is unit-tested on the JVM.
 */
object ArticleLinker {

    /**
     * A phrase to mark. ENTITY terms carry the entity; GLOSSARY terms carry the term id in
     * [entityId]; KEYWORD terms carry nothing else.
     */
    data class Term(
        val text: String,
        val kind: SpanKind,
        val entityType: String? = null,
        val entityId: String? = null,
        val entityName: String? = null
    )

    // JavaScript's \w without the u flag.
    private const val W = "[A-Za-z0-9_]"
    private const val JS_WORD_BOUNDARY = "(?:(?<=$W)(?!$W)|(?<!$W)(?=$W))"

    // Keyword phrases are the app's own; they keep the earlier Unicode-aware whole-word rule.
    private const val KEYWORD_MIN_LENGTH = 2

    // Keyed by the source list's identity plus the terms. Each entry keeps the source list and the
    // terms and both are checked on a hit: an identity hash alone can collide, which would have
    // shown another article's highlights.
    private class CacheEntry(val source: List<Block>, val terms: List<Term>, val result: List<Block>)

    private val cache = java.util.Collections.synchronizedMap(
        object : java.util.LinkedHashMap<Long, CacheEntry>(50, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Long, CacheEntry>?): Boolean = size > 50
        }
    )

    private fun cacheKey(blocks: List<Block>, terms: List<Term>): Long =
        (System.identityHashCode(blocks).toLong() shl 32) xor (terms.hashCode().toLong() and 0xFFFFFFFFL)

    /** The annotated blocks if [annotate] already ran for these exact blocks and terms. */
    fun getCached(blocks: List<Block>, terms: List<Term>): List<Block>? {
        if (terms.isEmpty()) return blocks
        val entry = cache[cacheKey(blocks, terms)] ?: return null
        return if (entry.source === blocks && entry.terms == terms) entry.result else null
    }

    fun annotate(blocks: List<Block>, terms: List<Term>): List<Block> {
        if (terms.isEmpty()) return blocks
        getCached(blocks, terms)?.let { return it }
        val matcher = Matcher(terms)
        val result = if (matcher.isEmpty) blocks else blocks.map { block ->
            when (block) {
                is ArticleHtml.Paragraph -> block.copy(text = matcher.mark(block.text))
                is ArticleHtml.ListItem -> block.copy(text = matcher.mark(block.text))
                is ArticleHtml.Code -> {
                    val marked = matcher.mark(RichText(block.text, emptyList(), block.breaks), keywords = false)
                    if (marked.spans.isEmpty()) block else block.copy(marks = marked.spans)
                }
                else -> block
            }
        }
        cache[cacheKey(blocks, terms)] = CacheEntry(blocks, terms, result)
        return result
    }

    private class Matcher(terms: List<Term>) {
        private val glossary = terms.filter { it.kind == SpanKind.GLOSSARY && it.text.isNotEmpty() }
        private val entities = terms.filter { it.kind == SpanKind.ENTITY && it.text.isNotEmpty() }
        private val keywords = terms.filter { it.kind == SpanKind.KEYWORD }
            .map { it.copy(text = it.text.trim()) }
            .filter { it.text.length >= KEYWORD_MIN_LENGTH && it.text.any { c -> c.isLetterOrDigit() } }
            .distinctBy { it.text.lowercase() }

        // associateBy keeps the last term for a repeated phrase, like the web's Map.set loop.
        private val glossaryByText = glossary.associateBy { it.text.lowercase() }
        private val entityByText = entities.associateBy { it.text.lowercase() }
        private val keywordByText = keywords.associateBy { it.text.lowercase() }

        private val glossaryRegex = alternation(glossary)?.let { Regex("$JS_WORD_BOUNDARY(?:$it)$JS_WORD_BOUNDARY", RegexOption.IGNORE_CASE) }
        private val entityRegex = alternation(entities)?.let { Regex("(?<!$W)(?:$it)(?!$W)", RegexOption.IGNORE_CASE) }
        private val keywordRegex = alternation(keywords)?.let { Regex("(?<![\\p{L}\\p{N}_])(?:$it)(?![\\p{L}\\p{N}_])", RegexOption.IGNORE_CASE) }

        val isEmpty = glossaryRegex == null && entityRegex == null && keywordRegex == null

        /** Longest phrase first (stable, as the web sorts), each matched literally. */
        private fun alternation(list: List<Term>): String? =
            list.map { it.text }.distinct().sortedByDescending { it.length }
                .joinToString("|") { Regex.escape(it) }.ifEmpty { null }

        fun mark(rich: RichText, keywords: Boolean = true): RichText {
            val text = rich.text
            if (text.isEmpty()) return rich
            val added = mutableListOf<Span>()

            // 1. Glossary terms, one text node at a time.
            val glossaryRanges = mutableListOf<IntRange>()
            glossaryRegex?.let { regex ->
                forEachSegment(text, rich.breaks, emptyList()) { from, to ->
                    regex.findAll(text.substring(from, to)).forEach { m ->
                        val term = glossaryByText[m.value.lowercase()] ?: return@forEach
                        val start = from + m.range.first
                        val end = from + m.range.last + 1
                        added += Span(start, end, SpanKind.GLOSSARY, glossaryId = term.entityId, entityName = term.entityName)
                        glossaryRanges += start until end
                    }
                }
            }

            // 2. Entity names, in the text nodes left outside the glossary terms.
            val entityRanges = mutableListOf<IntRange>()
            entityRegex?.let { regex ->
                forEachSegment(text, rich.breaks, glossaryRanges) { from, to ->
                    regex.findAll(text.substring(from, to)).forEach { m ->
                        val term = entityByText[m.value.lowercase()] ?: return@forEach
                        val start = from + m.range.first
                        val end = from + m.range.last + 1
                        added += Span(start, end, SpanKind.ENTITY, entityType = term.entityType, entityId = term.entityId, entityName = term.entityName)
                        entityRanges += start until end
                    }
                }
            }

            // 3. The app's keyword highlights, anywhere not already marked, linked or code.
            if (keywords) keywordRegex?.let { regex ->
                val blocked = rich.spans.filter { it.kind == SpanKind.LINK || it.kind == SpanKind.CODE }.map { it.start until it.end } +
                    glossaryRanges + entityRanges
                regex.findAll(text).forEach { m ->
                    val start = m.range.first
                    val end = m.range.last + 1
                    if (blocked.any { start <= it.last && end > it.first }) return@forEach
                    if (keywordByText[m.value.lowercase()] == null) return@forEach
                    added += Span(start, end, SpanKind.KEYWORD)
                }
            }

            return if (added.isEmpty()) rich else rich.copy(spans = rich.spans + added)
        }

        /**
         * Calls [block] with each [from, to) stretch of [text] that is one text node: split at
         * [breaks] and at the edges of [skip], with the [skip] ranges themselves left out.
         */
        private inline fun forEachSegment(text: String, breaks: List<Int>, skip: List<IntRange>, block: (Int, Int) -> Unit) {
            val cuts = sortedSetOf(0, text.length)
            breaks.forEach { if (it in 1 until text.length) cuts += it }
            skip.forEach { cuts += it.first; cuts += it.last + 1 }
            var previous = -1
            for (cut in cuts) {
                if (previous >= 0 && cut > previous && skip.none { previous >= it.first && previous <= it.last }) {
                    block(previous, cut)
                }
                previous = cut
            }
        }
    }
}
