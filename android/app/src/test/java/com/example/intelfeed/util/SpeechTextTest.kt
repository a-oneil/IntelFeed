package com.example.intelfeed.util

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SpeechTextTest {

    @Test
    fun shortTextIsOneChunk() {
        assertEquals(listOf("Title.\n\nBody text."), SpeechText.chunk("Title.\n\nBody text."))
    }

    @Test
    fun emptyTextHasNoChunks() {
        assertTrue(SpeechText.chunk("  \n\n ").isEmpty())
    }

    @Test
    fun longArticleIsSplitUnderTheLimitWithoutLosingWords() {
        val paragraph = (1..60).joinToString(" ") { "Sentence number $it ends here." }
        val article = List(12) { paragraph }.joinToString("\n\n") // ~22,000 characters
        val chunks = SpeechText.chunk(article)
        assertTrue(chunks.size > 1)
        assertTrue(chunks.all { it.length <= SpeechText.MAX_CHUNK })
        val words = { s: String -> s.split(Regex("\\s+")).filter { it.isNotEmpty() } }
        assertEquals(words(article), chunks.flatMap(words))
    }

    @Test
    fun splitsAtSentenceEndsWhenAParagraphIsTooLong() {
        val text = "First sentence here. Second sentence here. Third one."
        val chunks = SpeechText.chunk(text, max = 25)
        assertEquals(listOf("First sentence here.", "Second sentence here.", "Third one."), chunks)
    }

    @Test
    fun aHugeWordIsCutToFit() {
        val chunks = SpeechText.chunk("a".repeat(25), max = 10)
        assertEquals(listOf(10, 10, 5), chunks.map { it.length })
    }

    @Test
    fun cleanForSpeechReplacesUrlsWithDomainMentions() {
        val input = "Read more at https://thehackernews.com/2026/09/cyber-threat.html and https://cdn.example.org/report."
        val output = SpeechText.cleanForSpeech(input)
        assertEquals("Read more at link to thehackernews.com and link to cdn.example.org.", output)
    }

    @Test
    fun cleanForSpeechOmitsLongHashes() {
        val md5 = "5d41402abc4b2a76b9719d911017c592"
        val sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        val input = "Sample hash is $md5 and secondary $sha256."
        val output = SpeechText.cleanForSpeech(input)
        assertEquals("Sample hash is [hash] and secondary [hash].", output)
    }

    @Test
    fun cleanForSpeechFormatsCveNaturally() {
        val input = "Vulnerability CVE-2024-38077 was patched."
        val output = SpeechText.cleanForSpeech(input)
        assertEquals("Vulnerability C-V-E 2024, 38077 was patched.", output)
    }

    @Test
    fun cleanForSpeechStripsMarkdownAndEnsuresHeadingPeriod() {
        val input = "## Threat Report\n\n**Warning**: Attackers used *spearphishing* to drop malware."
        val output = SpeechText.cleanForSpeech(input)
        assertEquals("Threat Report.\n\nWarning: Attackers used spearphishing to drop malware.", output)
    }
}

