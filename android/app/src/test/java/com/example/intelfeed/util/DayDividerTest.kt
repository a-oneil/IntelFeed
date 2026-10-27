package com.example.intelfeed.util

import com.example.intelfeed.data.model.DayIntel
import com.example.intelfeed.data.network.ApiJson
import com.example.intelfeed.util.ArticleHtml.SpanKind
import com.example.intelfeed.util.ArticleHtml.TextKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.TimeZone

/** Day dividers: local day keys, the day's UTC bounds, the day-intel payload, and briefing Markdown. */
class DayDividerTest {

    private val newYork = TimeZone.getTimeZone("America/New_York")

    @Test
    fun dayKeyIsTheLocalDateNotTheUtcDate() {
        // 01:30 UTC on the 22nd is still the evening of the 21st in New York.
        assertEquals("2026-09-21", DateUtils.localDayKey("2026-09-22T01:30:00Z", newYork))
        assertEquals("2026-09-22", DateUtils.localDayKey("2026-09-22T01:30:00Z", TimeZone.getTimeZone("UTC")))
        assertNull(DateUtils.localDayKey(null, newYork))
    }

    @Test
    fun dayBoundsAreLocalMidnightToMidnightInUtc() {
        assertEquals(
            "2026-09-21T04:00:00.000Z" to "2026-09-22T03:59:59.999Z",
            DateUtils.dayBounds("2026-09-21", newYork)
        )
        assertEquals(
            "2026-09-21T00:00:00.000Z" to "2026-09-21T23:59:59.999Z",
            DateUtils.dayBounds("2026-09-21", TimeZone.getTimeZone("UTC"))
        )
        assertNull(DateUtils.dayBounds("21/09/2026", newYork))
    }

    @Test
    fun dayBoundsCoverA25HourDay() {
        // Clocks go back on 2026-11-01 in New York: that day is 25 hours long.
        assertEquals(
            "2026-11-01T04:00:00.000Z" to "2026-11-02T04:59:59.999Z",
            DateUtils.dayBounds("2026-11-01", newYork)
        )
    }

    @Test
    fun decodesTheLiveDayIntelPayload() {
        // GET /api/entries/day-intel on the live server, 2026-09-22.
        val json = """{"threat_actor":{"id":"e5049c67-51bf-4dc9-9a78-fb23d6a7bbd7","name":"ShinyHunters","count":14},
            "malware":{"id":"6047d10d-2e7a-4a98-9d73-e04af25c93bf","name":"TerminalFix","count":15},
            "cve":{"id":"866519e7-2822-4169-b485-42e7da3f6cb2","name":"CVE-2026-53266","count":4,"cvss_score":8.8,"severity":"HIGH","kev":true},
            "ttp":{"id":"d7b0d1d4-9a47-4349-9bfa-5a7c8a502f15","technique_id":"T1190","name":"Exploit Public-Facing Application","count":6},
            "sector":{"slug":"financial-services","name":"Financial Services","count":2},
            "product":{"id":"e75941e7-85c4-44b2-be62-a3dcc3ddf6ac","name":"Linux","count":131},
            "country":{"id":"632722b6-6de0-4cee-ada1-5f915ab74f66","name":"United States","count":29},
            "signals":{"actively_exploited":22,"new":null}}"""
        val intel = ApiJson.json.decodeFromString(DayIntel.serializer(), json)
        assertEquals("ShinyHunters", intel.threatActor?.name)
        assertEquals(true, intel.cve?.kev)
        assertEquals(8.8, intel.cve?.cvssScore)
        assertEquals("T1190", intel.ttp?.techniqueId)
        assertNull(intel.sector?.id)
        assertEquals(22, intel.signals.activelyExploited)
        assertNull(intel.signals.new)
    }

    @Test
    fun decodesAQuietDay() {
        val intel = ApiJson.json.decodeFromString(DayIntel.serializer(), """{"threat_actor":null,"signals":{"actively_exploited":0,"new":{"type":"malware","id":"m1","name":"NewFam","total":3}}}""")
        assertNull(intel.threatActor)
        assertEquals("NewFam", intel.signals.new?.name)
    }

    @Test
    fun briefingMarkdownBecomesBlocks() {
        val md = """
            ## TL;DR

            Three themes **converge** today, see [Mind the Gap](/?entry=cc568026-0b81-49ea-869c-a79c56351fee).

            ### Key Developments
            - First item with `CVE-2026-1`
            - Second item
              continues here
            1. Numbered

            > A quote
            ---
            ```
            code block
            ```
        """.trimIndent()
        val blocks = MarkdownText.parse(md, "https://intelfeed.example.com")
        val h2 = blocks[0] as ArticleHtml.Paragraph
        assertEquals(TextKind.H2, h2.kind)
        assertEquals("TL;DR", h2.text.text)

        val para = blocks[1] as ArticleHtml.Paragraph
        assertEquals("Three themes converge today, see Mind the Gap.", para.text.text)
        assertTrue(para.text.spans.any { it.kind == SpanKind.BOLD && para.text.text.substring(it.start, it.end) == "converge" })
        val link = para.text.spans.single { it.kind == SpanKind.LINK }
        assertEquals("https://intelfeed.example.com/?entry=cc568026-0b81-49ea-869c-a79c56351fee", link.url)
        assertEquals("Mind the Gap", para.text.text.substring(link.start, link.end))

        assertEquals(TextKind.H3, (blocks[2] as ArticleHtml.Paragraph).kind)
        val first = blocks[3] as ArticleHtml.ListItem
        assertEquals("•", first.marker)
        assertTrue(first.text.spans.any { it.kind == SpanKind.CODE })
        assertEquals("Second item continues here", (blocks[4] as ArticleHtml.ListItem).text.text)
        assertEquals("1.", (blocks[5] as ArticleHtml.ListItem).marker)
        assertEquals(TextKind.QUOTE, (blocks[6] as ArticleHtml.Paragraph).kind)
        assertEquals(ArticleHtml.Divider, blocks[7])
        assertEquals("code block", (blocks[8] as ArticleHtml.Code).text)
    }

    @Test
    fun markdownInlineEdgeCases() {
        // snake_case isn't italic; a lone asterisk stays; unsafe link schemes are dropped but the text kept.
        assertEquals("apt_group_29 and 5 * 3", MarkdownText.inline("apt_group_29 and 5 * 3").text)
        assertTrue(MarkdownText.inline("apt_group_29").spans.isEmpty())
        val js = MarkdownText.inline("[click](javascript:alert(1))", "https://intelfeed.example.com")
        assertTrue(js.spans.none { it.kind == SpanKind.LINK })
        val bold = MarkdownText.inline("**[Title](https://example.com/a)** and *it*")
        assertEquals("Title and it", bold.text)
        assertTrue(bold.spans.any { it.kind == SpanKind.LINK && it.url == "https://example.com/a" })
        assertTrue(bold.spans.any { it.kind == SpanKind.ITALIC })
    }

    @Test
    fun onlyEntryLinksOnTheSignedInServerOpenInTheApp() {
        val id = "cc568026-0b81-49ea-869c-a79c56351fee"
        assertEquals(id, InAppLinks.entryId("https://intelfeed.example.com/?entry=$id", "https://intelfeed.example.com"))
        assertNull(InAppLinks.entryId("https://intelfeed.example.com.evil.com/?entry=$id", "https://intelfeed.example.com"))
        assertNull(InAppLinks.entryId("https://example.com/?entry=$id", "https://intelfeed.example.com"))
        assertNull(InAppLinks.entryId("https://intelfeed.example.com/?entry=../../x", "https://intelfeed.example.com"))
        assertNull(InAppLinks.entryId("https://intelfeed.example.com/about", "https://intelfeed.example.com"))
    }
}
