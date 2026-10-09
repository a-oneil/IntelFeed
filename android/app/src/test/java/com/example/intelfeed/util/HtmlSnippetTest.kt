package com.example.intelfeed.util

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class HtmlSnippetTest {

    @Test
    fun longSummaryIsCutOutsideATag() {
        val cut = HtmlText.cutForSnippet("a".repeat(4090) + "<a href=\"https://example.com\">link</a>" + "b".repeat(5000))
        assertEquals("a".repeat(4090), cut)
    }

    @Test
    fun scriptWhoseClosingTagWasCutOffIsDropped() {
        assertEquals("<p>Intro</p>", HtmlText.cutForSnippet("<p>Intro</p><script>" + "x".repeat(5000) + "</script>"))
    }

    @Test
    fun closedScriptIsLeftForTheParserToRemove() {
        val cut = HtmlText.cutForSnippet("<style>p{}</style><p>" + "y".repeat(5000))
        assertTrue(cut.startsWith("<style>p{}</style><p>yyy"))
        assertEquals(4096, cut.length)
    }

    @Test
    fun cleanAiArtifactsStripsLeakedPromptTagsAndParameters() {
        val raw = "ShinyHunters is a cybercriminal group active since 2020.</new_description>\n<parameter name=\"reason\">Updated with recent breach info</parameter>"
        val cleaned = HtmlText.cleanAiArtifacts(raw)
        assertEquals("ShinyHunters is a cybercriminal group active since 2020.", cleaned)
    }

    @Test
    fun cleanAiArtifactsHandlesEnclosingTagsAndEntities() {
        val raw = "<new_description>Breach intelligence &amp; extortion broker.</new_description>"
        val cleaned = HtmlText.cleanAiArtifacts(raw)
        assertEquals("Breach intelligence & extortion broker.", cleaned)
    }

    @Test
    fun cleanAiArtifactsReturnsNullForEmptyOrOnlyArtifacts() {
        assertEquals(null, HtmlText.cleanAiArtifacts("<new_description></new_description>"))
        assertEquals(null, HtmlText.cleanAiArtifacts("<parameter name=\"foo\">bar</parameter>"))
        assertEquals(null, HtmlText.cleanAiArtifacts("   "))
    }
}
