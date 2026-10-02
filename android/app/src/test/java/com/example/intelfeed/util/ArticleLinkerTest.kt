package com.example.intelfeed.util

import com.example.intelfeed.data.model.Cve
import com.example.intelfeed.data.model.EntryIntel
import com.example.intelfeed.data.model.GlossaryMatch
import com.example.intelfeed.data.model.GlossaryTerm
import com.example.intelfeed.data.model.Mitigation
import com.example.intelfeed.data.model.ObservableItem
import com.example.intelfeed.data.model.ThreatActor
import com.example.intelfeed.data.model.Ttp
import com.example.intelfeed.ui.reader.entityTerms
import com.example.intelfeed.ui.reader.glossaryTerms
import com.example.intelfeed.util.ArticleHtml.Paragraph
import com.example.intelfeed.util.ArticleHtml.RichText
import com.example.intelfeed.util.ArticleHtml.Span
import com.example.intelfeed.util.ArticleHtml.SpanKind
import com.example.intelfeed.util.ArticleLinker.Term
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The web reader's rules (EntityHighlighter and the glossary pass), checked on the app's linker. */
class ArticleLinkerTest {

    private fun entity(text: String, id: String = text) = Term(text, SpanKind.ENTITY, "threat_actor", id, text)
    private fun glossary(text: String, id: String = text) = Term(text, SpanKind.GLOSSARY, entityId = id, entityName = text)
    private fun marked(block: ArticleHtml.Block, vararg kinds: SpanKind = arrayOf(SpanKind.ENTITY, SpanKind.KEYWORD)): List<String> {
        val rich = (block as Paragraph).text
        return rich.spans.filter { it.kind in kinds }.sortedBy { it.start }.map { rich.text.substring(it.start, it.end) }
    }

    @Test
    fun marksWholeWordsInAnyCase() {
        val out = ArticleLinker.annotate(listOf(Paragraph(RichText("ShinyHunters hit Qilin; shinyhunters again. Not ShinyHuntersX."))), listOf(entity("ShinyHunters")))
        assertEquals(listOf("ShinyHunters", "shinyhunters"), marked(out.single()))
    }

    @Test
    fun longestPhraseWins() {
        val out = ArticleLinker.annotate(listOf(Paragraph(RichText("Nightmare Eclipse and Eclipse"))), listOf(entity("Eclipse", "e1"), entity("Nightmare Eclipse", "e2")))
        val spans = (out.single() as Paragraph).text.spans
        assertEquals(listOf("e2", "e1"), spans.sortedBy { it.start }.map { it.entityId })
    }

    @Test
    fun entityNamesInsideLinksAndCodeAreMarkedLikeTheWeb() {
        val text = "Qilin says see Qilin site and run qilin.exe"
        val rich = RichText(text, listOf(Span(15, 20, SpanKind.LINK, url = "https://x"), Span(34, 43, SpanKind.CODE)))
        val out = ArticleLinker.annotate(listOf(Paragraph(rich)), listOf(entity("Qilin")))
        assertEquals(listOf("Qilin", "Qilin", "qilin"), marked(out.single()))
    }

    @Test
    fun keywordsStayOutOfLinksAndCode() {
        val text = "ransom note, ransom site"
        val rich = RichText(text, listOf(Span(13, 24, SpanKind.LINK, url = "https://x")))
        val out = ArticleLinker.annotate(listOf(Paragraph(rich)), listOf(Term("ransom", SpanKind.KEYWORD)))
        assertEquals(listOf("ransom"), marked(out.single()))
        assertEquals(0, (out.single() as Paragraph).text.spans.single { it.kind == SpanKind.KEYWORD }.start)
    }

    @Test
    fun shortTermsAreMarkedAndTheLastOfADuplicateWins() {
        // The web has no minimum length and keeps the last entity for a repeated phrase.
        val out = ArticleLinker.annotate(listOf(Paragraph(RichText("US and APT28"))), listOf(entity("US"), entity("APT28", "a"), entity("apt28", "b")))
        val spans = (out.single() as Paragraph).text.spans.sortedBy { it.start }
        assertEquals(listOf("US", "b"), spans.map { it.entityId })
    }

    @Test
    fun specialCharactersAreMatchedLiterally() {
        val out = ArticleLinker.annotate(listOf(Paragraph(RichText("Uses C++ and T1059.001 but not T1059x001"))),
            listOf(Term("C++", SpanKind.KEYWORD), Term("T1059.001", SpanKind.ENTITY, "ttp", "T1059.001", "T1059.001")))
        assertEquals(listOf("C++", "T1059.001"), marked(out.single()))
    }

    @Test
    fun wordBoundaryIsAsciiLikeJavaScript() {
        // JavaScript's \w is [A-Za-z0-9_], so a name next to an accented or Cyrillic letter still matches.
        val out = ArticleLinker.annotate(listOf(Paragraph(RichText("éSandworm, Sandwormя, Sandworm_x"))), listOf(entity("Sandworm")))
        assertEquals(listOf("Sandworm", "Sandworm"), marked(out.single()))
    }

    @Test
    fun namesSplitAcrossTextNodesAreNotMatched() {
        // "<b>Lazarus</b> Group": two text nodes, so "Lazarus Group" can't match but "Lazarus" can.
        val rich = RichText("Lazarus Group struck", listOf(Span(0, 7, SpanKind.BOLD)), breaks = listOf(7))
        val out = ArticleLinker.annotate(listOf(Paragraph(rich)), listOf(entity("Lazarus Group", "lg"), entity("Lazarus", "l")))
        val spans = (out.single() as Paragraph).text.spans.filter { it.kind == SpanKind.ENTITY }
        assertEquals(listOf("l"), spans.map { it.entityId })
    }

    @Test
    fun glossaryTermsComeFirstAndEntitiesSkipThem() {
        val out = ArticleLinker.annotate(
            listOf(Paragraph(RichText("Ransomware groups like Akira use ransomware."))),
            listOf(glossary("ransomware", "g1"), entity("Akira"), entity("ransomware", "wrong"))
        )
        val p = out.single() as Paragraph
        assertEquals(listOf("Ransomware", "ransomware"), marked(p, SpanKind.GLOSSARY))
        assertEquals(listOf("Akira"), marked(p, SpanKind.ENTITY))
        assertTrue(p.text.spans.filter { it.kind == SpanKind.GLOSSARY }.all { it.glossaryId == "g1" })
    }

    @Test
    fun entityNextToAGlossaryTermStillMatchesInItsOwnNode() {
        // After the glossary span splits "zero-day Qilin", "Qilin" is its own text node.
        val out = ArticleLinker.annotate(listOf(Paragraph(RichText("a zero-day Qilin exploit"))), listOf(glossary("zero-day"), entity("Qilin")))
        assertEquals(listOf("Qilin"), marked(out.single(), SpanKind.ENTITY))
    }

    @Test
    fun codeBlocksGetMarks() {
        val block = ArticleHtml.Code("connect 203.0.113.9 then\nbeacon", breaks = emptyList())
        val out = ArticleLinker.annotate(listOf(block), listOf(Term("203.0.113.9", SpanKind.ENTITY, "observable", "o1", "203.0.113.9")))
        val code = out.single() as ArticleHtml.Code
        assertEquals(listOf("203.0.113.9"), code.marks.map { code.text.substring(it.start, it.end) })
    }

    @Test
    fun nothingToMarkReturnsTheSameBlocks() {
        val blocks = listOf(Paragraph(RichText("plain")))
        assertTrue(ArticleLinker.annotate(blocks, emptyList()) === blocks)
    }

    @Test
    fun cacheOnlyReturnsResultsForTheSameBlocksAndTerms() {
        val a = listOf(Paragraph(RichText("Qilin")))
        val b = listOf(Paragraph(RichText("Qilin")))
        val terms = listOf(entity("Qilin"))
        val first = ArticleLinker.annotate(a, terms)
        assertTrue(ArticleLinker.getCached(a, terms) === first)
        assertNull(ArticleLinker.getCached(b, terms))
        assertNull(ArticleLinker.getCached(a, listOf(entity("Akira"))))
    }

    @Test
    fun termsFollowTheWebOrderAndSources() {
        val intel = EntryIntel(
            threatActors = listOf(
                ThreatActor(id = "a1", name = "APT28", aliases = listOf("Fancy Bear"), matchedNames = listOf("Fancy Bear")),
                ThreatActor(id = "a2", name = "Sandworm", aliases = listOf("Voodoo Bear"))
            ),
            cves = listOf(Cve(id = "row1", cveId = "CVE-2026-1")),
            ttps = listOf(Ttp(id = "t", techniqueId = "T1059", techniqueName = "Command and Scripting Interpreter")),
            mitigations = listOf(Mitigation(id = "m1", name = "User Training", mitreId = "M1017")),
            observables = listOf(ObservableItem(id = "o1", value = "evil.com", surfaceForm = "evil[.]com"))
        )
        val terms = entityTerms(intel)
        assertEquals(
            listOf("CVE-2026-1", "T1059", "Command and Scripting Interpreter", "Fancy Bear", "Sandworm", "Voodoo Bear", "User Training", "M1017", "evil.com", "evil[.]com"),
            terms.map { it.text }
        )
        // CVEs and techniques open by their public ids.
        assertEquals("CVE-2026-1", terms.first().entityId)
    }

    @Test
    fun observablesAreSkippedAbove200() {
        val many = (1..201).map { ObservableItem(id = "o$it", value = "10.0.0.$it") }
        assertTrue(entityTerms(EntryIntel(observables = many)).isEmpty())
    }

    @Test
    fun glossaryTermsAreOrderedByNameLengthWithSearchTerms() {
        val terms = glossaryTerms(listOf(
            GlossaryMatch(GlossaryTerm(id = "1", name = "EDR", searchTerms = listOf("endpoint detection and response"))),
            GlossaryMatch(GlossaryTerm(id = "2", name = "Zero trust"))
        ))
        assertEquals(listOf("Zero trust", "EDR", "endpoint detection and response"), terms.map { it.text })
        assertEquals(listOf("2", "1", "1"), terms.map { it.entityId })
    }
}
