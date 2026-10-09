package com.example.intelfeed.util

import org.junit.Assert.assertEquals
import org.junit.Test

class SearchTokensTest {

    @Test
    fun readsQuotedAndBareValues() {
        val q = """ransomware feed:"Dark Reading" feed:RSS tag:to-rule is:unread"""
        assertEquals(listOf("Dark Reading", "RSS"), SearchTokens.values(q, "feed"))
        assertEquals(listOf("to-rule"), SearchTokens.values(q, "tag"))
    }

    @Test
    fun removeKeepsEverythingElse() {
        val q = """ransomware feed:"Dark Reading" tag:a is:unread tag:b"""
        assertEquals("""ransomware feed:"Dark Reading" is:unread""", SearchTokens.remove(q, "tag"))
        assertEquals("ransomware tag:a is:unread tag:b", SearchTokens.remove(q, "feed"))
    }

    @Test
    fun negatedTokensAreLeftAlone() {
        val q = "apt -tag:noise NOT feed:Reddit tag:keep"
        assertEquals(listOf("keep"), SearchTokens.values(q, "tag"))
        assertEquals(emptyList<String>(), SearchTokens.values(q, "feed"))
        assertEquals("apt -tag:noise NOT feed:Reddit", SearchTokens.remove(q, "tag"))
    }

    @Test
    fun otherFieldsWithTheSameSuffixDontMatch() {
        // "rule.tag:" or "mytag:" aren't the tag field.
        assertEquals(emptyList<String>(), SearchTokens.values("rule.tag:x mytag:y", "tag"))
    }

    @Test
    fun tokensAreQuotedWhenNeeded() {
        assertEquals("feed:\"Dark Reading\"", SearchTokens.token("feed", "Dark Reading"))
        assertEquals("tag:to-rule", SearchTokens.token("tag", " to-rule "))
        assertEquals("feed:\"Bad Name\"", SearchTokens.token("feed", "Bad \"Name\""))
    }

    @Test
    fun unclosedQuoteIsClosedBeforeFiltersAreAppended() {
        assertEquals("\"ransomware\"", SearchTokens.closeOpenQuote("\"ransomware"))
        assertEquals("\"lock bit\" x", SearchTokens.closeOpenQuote("\"lock bit\" x"))
        assertEquals("plain", SearchTokens.closeOpenQuote("plain"))
    }
}
