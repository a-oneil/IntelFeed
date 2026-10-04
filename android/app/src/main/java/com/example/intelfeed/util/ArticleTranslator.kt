package com.example.intelfeed.util

import com.google.android.gms.tasks.Task
import com.google.mlkit.common.model.DownloadConditions
import com.google.mlkit.nl.languageid.LanguageIdentification
import com.google.mlkit.nl.translate.TranslateLanguage
import com.google.mlkit.nl.translate.Translation
import com.google.mlkit.nl.translate.TranslatorOptions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import java.util.Locale
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

suspend fun <T> Task<T>.awaitTask(): T = suspendCancellableCoroutine { cont ->
    addOnSuccessListener { result ->
        if (cont.isActive) cont.resume(result)
    }
    addOnFailureListener { exception ->
        if (cont.isActive) cont.resumeWithException(exception)
    }
    addOnCanceledListener {
        if (cont.isActive) cont.cancel()
    }
}

object ArticleTranslator {

    data class TranslationResult(
        val sourceLanguageCode: String,
        val sourceLanguageName: String,
        val targetLanguageCode: String = TranslateLanguage.ENGLISH,
        val targetLanguageName: String = languageDisplayName(targetLanguageCode),
        val translatedTitle: String,
        val translatedBlocks: List<ArticleHtml.Block>,
        val translatedText: String
    )

    data class SupportedLanguage(
        val code: String,
        val displayName: String,
        val nativeName: String
    )

    private val cache = java.util.Collections.synchronizedMap(
        object : java.util.LinkedHashMap<String, TranslationResult>(50, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, TranslationResult>?): Boolean {
                return size > 50
            }
        }
    )

    fun getCached(entryId: String, targetLang: String = TranslateLanguage.ENGLISH): TranslationResult? {
        val targetCode = TranslateLanguage.fromLanguageTag(targetLang) ?: targetLang
        return cache["$entryId:$targetCode"] ?: if (targetCode == TranslateLanguage.ENGLISH) cache[entryId] else null
    }

    fun cacheTranslation(entryId: String, result: TranslationResult) {
        cache["$entryId:${result.targetLanguageCode}"] = result
    }

    fun cacheTranslation(entryId: String, targetLang: String, result: TranslationResult) {
        val targetCode = TranslateLanguage.fromLanguageTag(targetLang) ?: targetLang
        cache["$entryId:$targetCode"] = result
    }

    /**
     * Returns a sorted list of all languages supported by ML Kit on-device translation.
     */
    fun getSupportedLanguages(): List<SupportedLanguage> {
        return TranslateLanguage.getAllLanguages().map { code ->
            val locale = Locale.forLanguageTag(code)
            val englishName = languageDisplayName(code)
            val native = runCatching {
                locale.getDisplayName(locale).replaceFirstChar { if (it.isLowerCase()) it.titlecase(locale) else it.toString() }
            }.getOrNull()
            val label = if (native.isNullOrBlank() || native.equals(englishName, ignoreCase = true)) {
                englishName
            } else {
                "$englishName ($native)"
            }
            SupportedLanguage(
                code = code,
                displayName = englishName,
                nativeName = label
            )
        }.sortedBy { it.displayName }
    }

    /**
     * Identifies the language of the given text using ML Kit.
     * Returns BCP-47 tag, e.g. "uk", "ru", "zh", "en", or "und".
     */
    suspend fun identifyLanguage(text: String): String = withContext(Dispatchers.Default) {
        val sample = text.take(500)
        val identifier = LanguageIdentification.getClient()
        try {
            identifier.identifyLanguage(sample).awaitTask()
        } finally {
            identifier.close()
        }
    }

    fun languageDisplayName(code: String): String {
        return when (code.lowercase()) {
            "und" -> "Unknown"
            "zh" -> "Chinese"
            "uk" -> "Ukrainian"
            "ru" -> "Russian"
            "ja" -> "Japanese"
            "ko" -> "Korean"
            "de" -> "German"
            "fr" -> "French"
            "es" -> "Spanish"
            "it" -> "Italian"
            "pt" -> "Portuguese"
            "pl" -> "Polish"
            "ar" -> "Arabic"
            "fa" -> "Persian"
            "hi" -> "Hindi"
            "tr" -> "Turkish"
            "nl" -> "Dutch"
            "en" -> "English"
            else -> runCatching {
                Locale.forLanguageTag(code).getDisplayLanguage(Locale.ENGLISH).ifBlank { code.uppercase() }
            }.getOrDefault(code.uppercase())
        }
    }

    /**
     * Translates an article's title and blocks to the specified target language on-device. The
     * read-aloud text is built from the translated blocks.
     */
    suspend fun translateArticle(
        entryId: String,
        title: String,
        blocks: List<ArticleHtml.Block>,
        targetLang: String = TranslateLanguage.ENGLISH
    ): Result<TranslationResult> = withContext(Dispatchers.Default) {
        runCatching {
            val targetCode = TranslateLanguage.fromLanguageTag(targetLang)
                ?: error("Target language '${languageDisplayName(targetLang)}' ($targetLang) is not supported for on-device translation.")

            getCached(entryId, targetCode)?.let { return@runCatching it }

            // Sample text from title and first body blocks to identify language
            val sample = buildString {
                append(title).append("\n")
                blocks.take(3).forEach { block ->
                    when (block) {
                        is ArticleHtml.Paragraph -> append(block.text.text).append("\n")
                        is ArticleHtml.ListItem -> append(block.text.text).append("\n")
                        else -> {}
                    }
                }
            }

            val sourceLang = identifyLanguage(sample)
            if (sourceLang == "und") {
                error("Could not determine language of article.")
            }
            if (sourceLang == targetCode) {
                error("Article is already in ${languageDisplayName(targetCode)}.")
            }

            val mlKitSource = TranslateLanguage.fromLanguageTag(sourceLang)
                ?: error("Language '${languageDisplayName(sourceLang)}' ($sourceLang) is not supported for on-device translation.")

            val options = TranslatorOptions.Builder()
                .setSourceLanguage(mlKitSource)
                .setTargetLanguage(targetCode)
                .build()

            val translator = Translation.getClient(options)
            try {
                // Ensure model is downloaded
                val conditions = DownloadConditions.Builder().build()
                translator.downloadModelIfNeeded(conditions).awaitTask()

                // Translate title
                val translatedTitle = translator.translate(title).awaitTask()

                // Translate blocks while preserving formatting, images, code, and dividers
                val translatedBlocks = blocks.map { block ->
                    when (block) {
                        is ArticleHtml.Paragraph -> {
                            val translated = translator.translate(block.text.text).awaitTask()
                            ArticleHtml.Paragraph(ArticleHtml.RichText(translated), block.kind)
                        }
                        is ArticleHtml.ListItem -> {
                            val translated = translator.translate(block.text.text).awaitTask()
                            ArticleHtml.ListItem(ArticleHtml.RichText(translated), block.marker, block.depth)
                        }
                        is ArticleHtml.Code -> block // Preserve code blocks exactly
                        is ArticleHtml.Image -> block // Preserve images
                        is ArticleHtml.Divider -> block
                    }
                }

                // Text for read-aloud, built from the translated blocks. It used to translate the
                // article's contentText as well, which ran the whole article through the model twice.
                val translatedText = translatedBlocks.mapNotNull { block ->
                    when (block) {
                        is ArticleHtml.Paragraph -> block.text.text
                        is ArticleHtml.ListItem -> block.text.text
                        else -> null
                    }
                }.joinToString("\n\n")

                val result = TranslationResult(
                    sourceLanguageCode = sourceLang,
                    sourceLanguageName = languageDisplayName(sourceLang),
                    targetLanguageCode = targetCode,
                    targetLanguageName = languageDisplayName(targetCode),
                    translatedTitle = translatedTitle,
                    translatedBlocks = translatedBlocks,
                    translatedText = translatedText
                )

                cacheTranslation(entryId, targetCode, result)
                result
            } finally {
                translator.close()
            }
        }
    }
}
