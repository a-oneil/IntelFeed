package com.example.intelfeed.util

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ShareIntentSanitizerTest {

    @Test
    fun extractsValidHttpsUrl() {
        val text = "Check out this article: https://example.com/cyber/threat-report?id=123"
        val extracted = ShareIntentSanitizer.extractUrlFromText(text)
        assertEquals("https://example.com/cyber/threat-report?id=123", extracted)
    }

    @Test
    fun extractsValidHttpUrl() {
        val text = "Local test: http://192.168.1.50:8080/feed"
        val extracted = ShareIntentSanitizer.extractUrlFromText(text)
        assertEquals("http://192.168.1.50:8080/feed", extracted)
    }

    @Test
    fun stripsTrailingPunctuation() {
        val text = "Read here: https://example.com/post.html."
        val extracted = ShareIntentSanitizer.extractUrlFromText(text)
        assertEquals("https://example.com/post.html", extracted)
    }

    @Test
    fun rejectsUrlWithEmbeddedCredentials() {
        val text = "Phishing attempt: https://victim:secretpassword@evil.com/login"
        val extracted = ShareIntentSanitizer.extractUrlFromText(text)
        assertNull(extracted)
    }

    @Test
    fun rejectsNonHttpSchemes() {
        assertNull(ShareIntentSanitizer.sanitizeUrl("ftp://files.example.com/dump"))
        assertNull(ShareIntentSanitizer.sanitizeUrl("file:///data/local/tmp"))
        assertNull(ShareIntentSanitizer.sanitizeUrl("javascript:alert(1)"))
        assertNull(ShareIntentSanitizer.sanitizeUrl("content://media/external/images"))
    }

    @Test
    fun rejectsControlCharacters() {
        assertNull(ShareIntentSanitizer.sanitizeUrl("https://example.com/test\u0000injection"))
        assertNull(ShareIntentSanitizer.sanitizeUrl("https://example.com/test\r\ninjection"))
    }

    @Test
    fun rejectsOversizedUrls() {
        val longUrl = "https://example.com/" + "a".repeat(3000)
        assertNull(ShareIntentSanitizer.sanitizeUrl(longUrl))
    }

    @Test
    fun returnsNullForBlankOrInvalidInput() {
        assertNull(ShareIntentSanitizer.extractUrlFromText(""))
        assertNull(ShareIntentSanitizer.extractUrlFromText("   "))
        assertNull(ShareIntentSanitizer.extractUrlFromText("just plain text with no url"))
    }
}
