package com.example.intelfeed.util

import com.example.intelfeed.data.model.EntryDetail
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class ArticleTranslatorTest {

    @Test
    fun languageDisplayNames() {
        assertEquals("Ukrainian", ArticleTranslator.languageDisplayName("uk"))
        assertEquals("Russian", ArticleTranslator.languageDisplayName("ru"))
        assertEquals("Chinese", ArticleTranslator.languageDisplayName("zh"))
        assertEquals("German", ArticleTranslator.languageDisplayName("de"))
        assertEquals("French", ArticleTranslator.languageDisplayName("fr"))
        assertEquals("Spanish", ArticleTranslator.languageDisplayName("es"))
        assertEquals("Japanese", ArticleTranslator.languageDisplayName("ja"))
        assertEquals("Unknown", ArticleTranslator.languageDisplayName("und"))
    }

    @Test
    fun supportedLanguagesIncludeStandardLanguages() {
        val all = com.google.mlkit.nl.translate.TranslateLanguage.getAllLanguages()
        org.junit.Assert.assertTrue(all.contains("en"))
        org.junit.Assert.assertTrue(all.contains("es"))
        org.junit.Assert.assertTrue(all.contains("uk"))
    }

    @Test
    fun translationCacheStoresAndRetrieves() {
        val entryId = "test-entry-123"
        assertNull(ArticleTranslator.getCached(entryId))

        val result = ArticleTranslator.TranslationResult(
            sourceLanguageCode = "uk",
            sourceLanguageName = "Ukrainian",
            translatedTitle = "Malware now has a board of directors",
            translatedBlocks = listOf(
                ArticleHtml.Paragraph(ArticleHtml.RichText("Cisco Talos discovered ClosedQuorum."))
            ),
            translatedText = "Malware now has a board of directors. Cisco Talos discovered ClosedQuorum."
        )

        ArticleTranslator.cacheTranslation(entryId, result)
        val cached = ArticleTranslator.getCached(entryId)
        assertNotNull(cached)
        assertEquals("Ukrainian", cached?.sourceLanguageName)
        assertEquals("Malware now has a board of directors", cached?.translatedTitle)
    }

    @Test
    fun parseBlocksFallsBackToPlainTextWhenNoHtml() {
        val detail = EntryDetail(
            id = "test-1",
            feedId = "f1",
            title = "Test Article",
            contentText = "Paragraph 1\n\nParagraph 2"
        )
        val blocks = ArticleHtml.parseBlocks(detail, null)
        assertEquals(2, blocks.size)
        assertEquals("Paragraph 1", (blocks[0] as ArticleHtml.Paragraph).text.text)
        assertEquals("Paragraph 2", (blocks[1] as ArticleHtml.Paragraph).text.text)
    }

    @Test
    fun getSupportedLanguagesReturnsSortedList() {
        val supported = ArticleTranslator.getSupportedLanguages()
        org.junit.Assert.assertTrue(supported.size >= 50)
        val english = supported.find { it.code == "en" }
        assertNotNull(english)
        assertEquals("English", english?.displayName)

        val spanish = supported.find { it.code == "es" }
        assertNotNull(spanish)
        assertEquals("Spanish", spanish?.displayName)
        org.junit.Assert.assertTrue(spanish?.nativeName?.contains("español", ignoreCase = true) == true)

        // Check list is sorted by displayName
        val displayNames = supported.map { it.displayName }
        assertEquals(displayNames.sorted(), displayNames)
    }

    @Test
    fun translationCacheSeparatesTargetLanguages() {
        val entryId = "entry-multi-lang"
        val resultEn = ArticleTranslator.TranslationResult(
            sourceLanguageCode = "uk",
            sourceLanguageName = "Ukrainian",
            targetLanguageCode = "en",
            targetLanguageName = "English",
            translatedTitle = "English Title",
            translatedBlocks = emptyList(),
            translatedText = "English Text"
        )
        val resultEs = ArticleTranslator.TranslationResult(
            sourceLanguageCode = "uk",
            sourceLanguageName = "Ukrainian",
            targetLanguageCode = "es",
            targetLanguageName = "Spanish",
            translatedTitle = "Título en Español",
            translatedBlocks = emptyList(),
            translatedText = "Texto en Español"
        )

        ArticleTranslator.cacheTranslation(entryId, "en", resultEn)
        ArticleTranslator.cacheTranslation(entryId, "es", resultEs)

        val cachedEn = ArticleTranslator.getCached(entryId, "en")
        val cachedEs = ArticleTranslator.getCached(entryId, "es")
        val cachedFr = ArticleTranslator.getCached(entryId, "fr")

        assertEquals("English Title", cachedEn?.translatedTitle)
        assertEquals("Título en Español", cachedEs?.translatedTitle)
        assertNull(cachedFr)
    }
}
