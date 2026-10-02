package com.example.intelfeed.ui.reader

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.speech.tts.TextToSpeech
import android.speech.tts.UtteranceProgressListener
import android.speech.tts.Voice
import android.widget.Toast
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.example.intelfeed.util.SpeechText
import java.util.Locale

/**
 * Reads an article aloud with the system text-to-speech engine.
 *
 * - Automatically searches for and selects high-quality neural/natural voice models over legacy
 *   robotic screen-reader defaults.
 * - Cleans technical text (URLs, hashes, markdown, CVEs) with SpeechText for a natural cadence.
 * - Supports language targeting so foreign or translated articles use authentic native voices.
 * - Supports configurable speech rates.
 * - The engine is only started the first time the user taps Read aloud.
 * - Long text is queued in chunks: TextToSpeech rejects input over ~4000 characters.
 * - [isSpeaking] is Compose state, updated on the main thread.
 */
class ArticleSpeaker(context: Context) {

    private val appContext = context.applicationContext
    private val main = Handler(Looper.getMainLooper())
    private var tts: TextToSpeech? = null
    private var ready = false

    private data class PendingSpeech(
        val key: String,
        val text: String,
        val language: String?,
        val speechRate: Float
    )

    private var pending: PendingSpeech? = null
    private var lastUtteranceId: String? = null

    var isSpeaking by mutableStateOf(false)
        private set

    fun speak(
        key: String,
        text: String,
        language: String? = null,
        speechRate: Float = 1.0f
    ) {
        val engine = tts
        if (engine == null) {
            pending = PendingSpeech(key, text, language, speechRate)
            isSpeaking = true
            tts = TextToSpeech(appContext) { status -> main.post { onInit(status) } }
            return
        }
        if (!ready) {
            pending = PendingSpeech(key, text, language, speechRate)
            isSpeaking = true
            return
        }
        play(engine, key, text, language, speechRate)
    }

    fun stop() {
        pending = null
        lastUtteranceId = null
        tts?.stop()
        isSpeaking = false
    }

    fun shutdown() {
        stop()
        tts?.shutdown()
        tts = null
        ready = false
    }

    private fun onInit(status: Int) {
        val engine = tts ?: return
        if (status != TextToSpeech.SUCCESS) {
            isSpeaking = false
            pending = null
            Toast.makeText(appContext, "Text-to-speech isn't available on this device", Toast.LENGTH_SHORT).show()
            return
        }
        engine.setOnUtteranceProgressListener(object : UtteranceProgressListener() {
            override fun onStart(utteranceId: String?) {
                main.post { if (lastUtteranceId != null) isSpeaking = true }
            }

            override fun onDone(utteranceId: String?) {
                main.post { if (utteranceId != null && utteranceId == lastUtteranceId) isSpeaking = false }
            }

            @Deprecated("Deprecated in Java")
            override fun onError(utteranceId: String?) {
                main.post { isSpeaking = false }
            }

            override fun onError(utteranceId: String?, errorCode: Int) {
                main.post { isSpeaking = false }
            }
        })
        ready = true
        pending?.let { p ->
            pending = null
            play(engine, p.key, p.text, p.language, p.speechRate)
        }
    }

    private fun play(engine: TextToSpeech, key: String, text: String, language: String?, speechRate: Float) {
        val targetLocale = if (!language.isNullOrBlank()) {
            val parsed = Locale.forLanguageTag(language)
            if (parsed.language.isEmpty()) Locale.getDefault() else parsed
        } else {
            Locale.getDefault()
        }
        configureVoice(engine, targetLocale, speechRate)
        val cleaned = SpeechText.cleanForSpeech(text)
        queue(engine, key, cleaned)
    }

    private fun configureVoice(engine: TextToSpeech, targetLocale: Locale, speechRate: Float) {
        engine.setSpeechRate(speechRate.coerceIn(0.5f, 2.0f))
        engine.setPitch(1.0f)

        try {
            val allVoices = engine.voices
            if (!allVoices.isNullOrEmpty()) {
                val matching = allVoices.filter { voice ->
                    !voice.features.contains(TextToSpeech.Engine.KEY_FEATURE_NOT_INSTALLED) &&
                        voice.locale.language.equals(targetLocale.language, ignoreCase = true)
                }

                if (matching.isNotEmpty()) {
                    val countryMatches = matching.filter {
                        targetLocale.country.isEmpty() || it.locale.country.equals(targetLocale.country, ignoreCase = true)
                    }.ifEmpty { matching }

                    // Prefer higher quality (VERY_HIGH > HIGH > NORMAL) and neural/network/studio voices
                    val best = countryMatches.maxWithOrNull(
                        compareBy<Voice> { it.quality }
                            .thenBy { voice ->
                                val n = voice.name.lowercase()
                                when {
                                    n.contains("network") -> 3
                                    n.contains("neural") || n.contains("wavenet") || n.contains("studio") -> 2
                                    voice.quality >= Voice.QUALITY_HIGH -> 1
                                    else -> 0
                                }
                            }
                            .thenBy { if (!it.isNetworkConnectionRequired) 1 else 0 }
                    )

                    if (best != null) {
                        engine.voice = best
                        return
                    }
                }
            }
        } catch (_: Throwable) {
            // Some TTS engines don't support getVoices(); fallback to language
        }

        try {
            engine.language = targetLocale
        } catch (_: Throwable) {
            engine.language = Locale.getDefault()
        }
    }

    private fun queue(engine: TextToSpeech, key: String, text: String) {
        val max = minOf(SpeechText.MAX_CHUNK, TextToSpeech.getMaxSpeechInputLength() - 100)
        val chunks = SpeechText.chunk(text, max)
        if (chunks.isEmpty()) {
            isSpeaking = false
            return
        }
        engine.stop()
        lastUtteranceId = "article_${key}_${chunks.lastIndex}"
        isSpeaking = true
        chunks.forEachIndexed { index, chunk ->
            val id = "article_${key}_$index"
            val params = Bundle().apply { putString(TextToSpeech.Engine.KEY_PARAM_UTTERANCE_ID, id) }
            val mode = if (index == 0) TextToSpeech.QUEUE_FLUSH else TextToSpeech.QUEUE_ADD
            if (engine.speak(chunk, mode, params, id) == TextToSpeech.ERROR) {
                isSpeaking = false
                lastUtteranceId = null
                return
            }
        }
    }

    companion object {
        fun openSystemTtsSettings(context: Context) {
            try {
                val intent = Intent("com.android.settings.TTS_SETTINGS").apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK
                }
                context.startActivity(intent)
            } catch (_: Throwable) {
                try {
                    val intent = Intent(Settings.ACTION_SETTINGS).apply {
                        flags = Intent.FLAG_ACTIVITY_NEW_TASK
                    }
                    context.startActivity(intent)
                } catch (_: Throwable) {
                    Toast.makeText(context, "Could not open text-to-speech settings", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }
}

