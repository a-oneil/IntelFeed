package com.example.intelfeed.util

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class InAppLinksTest {

    private val serverUrl = "https://intelfeed.cc"

    @Test
    fun matchesValidEntryLink() {
        val link = "https://intelfeed.cc/?entry=abc-123-def"
        val entryId = InAppLinks.entryId(link, serverUrl)
        assertEquals("abc-123-def", entryId)
    }

    @Test
    fun rejectsHttpWhenServerIsHttps() {
        val link = "http://intelfeed.cc/?entry=abc-123-def"
        val entryId = InAppLinks.entryId(link, serverUrl)
        assertNull("Downgraded HTTP link must not be accepted for HTTPS server", entryId)
    }

    @Test
    fun rejectsMismatchedHost() {
        val link = "https://evil-intelfeed.cc/?entry=abc-123-def"
        val entryId = InAppLinks.entryId(link, serverUrl)
        assertNull(entryId)
    }

    @Test
    fun rejectsMismatchedPort() {
        val link = "https://intelfeed.cc:8443/?entry=abc-123-def"
        val entryId = InAppLinks.entryId(link, serverUrl)
        assertNull(entryId)
    }

    @Test
    fun rejectsInvalidEntryIdCharacters() {
        val link = "https://intelfeed.cc/?entry=abc%20123;DROP"
        val entryId = InAppLinks.entryId(link, serverUrl)
        assertNull(entryId)
    }

    @Test
    fun rejectsOversizedEntryId() {
        val link = "https://intelfeed.cc/?entry=" + "a".repeat(65)
        val entryId = InAppLinks.entryId(link, serverUrl)
        assertNull(entryId)
    }

    @Test
    fun returnsNullWhenNoEntryParam() {
        val link = "https://intelfeed.cc/search?q=test"
        val entryId = InAppLinks.entryId(link, serverUrl)
        assertNull(entryId)
    }

    @Test
    fun returnsNullWhenServerUrlIsNull() {
        val link = "https://intelfeed.cc/?entry=abc-123"
        val entryId = InAppLinks.entryId(link, null)
        assertNull(entryId)
    }
}
