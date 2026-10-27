package com.example.intelfeed.util

import com.example.intelfeed.util.ArticleHtml.Block
import com.example.intelfeed.util.ArticleHtml.Code
import com.example.intelfeed.util.ArticleHtml.Image
import com.example.intelfeed.util.ArticleHtml.ListItem
import com.example.intelfeed.util.ArticleHtml.Paragraph
import com.example.intelfeed.util.ArticleHtml.SpanKind
import com.example.intelfeed.util.ArticleHtml.TextKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ArticleHtmlTest {

    private fun parse(html: String, url: String? = "https://example.com/posts/1", server: String? = "https://intelfeed.example.com"): List<Block> =
        ArticleHtml.parse(html, url, server)

    @Test
    fun paragraphsHeadingsAndInlineStyles() {
        val blocks = parse("<h2>Summary</h2><p>Attackers used <strong>CVE-2026-1</strong> and <a href=\"/iocs\">these IOCs</a>.</p>")
        assertEquals(2, blocks.size)
        val heading = blocks[0] as Paragraph
        assertEquals(TextKind.H2, heading.kind)
        assertEquals("Summary", heading.text.text)
        val p = blocks[1] as Paragraph
        assertEquals("Attackers used CVE-2026-1 and these IOCs.", p.text.text)
        val bold = p.text.spans.single { it.kind == SpanKind.BOLD }
        assertEquals("CVE-2026-1", p.text.text.substring(bold.start, bold.end))
        val link = p.text.spans.single { it.kind == SpanKind.LINK }
        assertEquals("https://example.com/iocs", link.url)
        assertEquals("these IOCs", p.text.text.substring(link.start, link.end))
    }

    @Test
    fun scriptsStylesAndIconGlyphsAreDropped() {
        val blocks = parse("<script>alert(1)</script><style>p{}</style><p>Swati Khandelwal</p><iframe src=x></iframe>")
        assertEquals(listOf("Swati Khandelwal"), blocks.map { (it as Paragraph).text.text })
    }

    @Test
    fun codeBlocksKeepTheirLineBreaks() {
        val blocks = parse("<pre><code>rule x {\n  condition: true\n}</code></pre>")
        assertEquals("rule x {\n  condition: true\n}", (blocks.single() as Code).text)
    }

    @Test
    fun listsNestAndNumber() {
        val blocks = parse("<ol><li>First</li><li>Second<ul><li>Inner</li></ul></li></ol>")
        val items = blocks.filterIsInstance<ListItem>()
        assertEquals(listOf("1.", "2.", "◦"), items.map { it.marker })
        assertEquals(listOf(1, 1, 2), items.map { it.depth })
        assertEquals("Inner", items[2].text.text)
    }

    @Test
    fun imagesResolveAndTrackingPixelsAreSkipped() {
        val blocks = parse(
            "<img src=\"/api/proxy/image?url=x\"><img src=\"//cdn.example.com/a.png\"><img src=\"b.png\">" +
                "<img src=\"https://t.example.com/p.gif\" width=\"1\" height=\"1\"><img src=\"data:image/png;base64,AAA\">"
        )
        assertEquals(
            listOf("https://intelfeed.example.com/api/proxy/image?url=x", "https://cdn.example.com/a.png", "https://example.com/posts/b.png"),
            blocks.filterIsInstance<Image>().map { it.url }
        )
    }

    @Test
    fun unsafeLinksAreNotLinked() {
        val p = parse("<p><a href=\"javascript:alert(1)\">x</a> <a href=\"#top\">y</a></p>").single() as Paragraph
        assertTrue(p.text.spans.none { it.kind == SpanKind.LINK })
        assertEquals("x y", p.text.text)
    }

    @Test
    fun entitiesAreDecodedOnceAndWhitespaceCollapsed() {
        val p = parse("<p>AT&amp;T   &lt;script&gt;\n  tag</p>").single() as Paragraph
        assertEquals("AT&T <script> tag", p.text.text)
    }

    @Test
    fun textNodeBoundariesAreRecorded() {
        // "Attackers used " | "CVE-2026-1" | " and " | "these IOCs" | "."
        val p = parse("<p>Attackers used <strong>CVE-2026-1</strong> and <a href=\"https://x\">these IOCs</a>.</p>").single() as Paragraph
        assertEquals(listOf(15, 25, 30, 40), p.text.breaks)
    }

    @Test
    fun codeBlockRecordsItsTextNodes() {
        val code = parse("<pre><code><span>curl</span> http://evil.test</code></pre>").single() as Code
        assertEquals("curl http://evil.test", code.text)
        assertEquals(listOf(4), code.breaks)
    }
}
