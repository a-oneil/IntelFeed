package com.example.intelfeed.util

import android.content.Intent
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull

/** Validates and sanitizes incoming ACTION_SEND intents and web URLs shared into IntelFeed. Protects against URI permission bypass, oversized payloads, embedded credentials, and non-http(s) schemes. */
object ShareIntentSanitizer {

    private const val MAX_SHARE_TEXT_LENGTH = 4096
    private const val MAX_URL_LENGTH = 2048

    // Matches http/https URLs in shared text.
    private val URL_REGEX = Regex("https?://[^\\s\"'<>]+", RegexOption.IGNORE_CASE)

    /** Extracts and validates an HTTP or HTTPS link from an incoming [Intent]. Rejects intents carrying URI permission grant flags, bounds the text size, and rejects URLs containing control characters or embedded credentials (userInfo). */
    fun extractSafeUrl(intent: Intent?): String? {
        intent ?: return null
        if (intent.action != Intent.ACTION_SEND || intent.type != "text/plain") return null

        // 1. Refuse intents with URI permission grant flags, to prevent URI permission bypass or escalation.
        val uriPermissionFlags = Intent.FLAG_GRANT_READ_URI_PERMISSION or
                Intent.FLAG_GRANT_WRITE_URI_PERMISSION or
                Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION or
                Intent.FLAG_GRANT_PREFIX_URI_PERMISSION
        if ((intent.flags and uriPermissionFlags) != 0) {
            return null
        }

        // 2. Bound the incoming text length to avoid regex DoS or memory spikes.
        val rawText = try {
            intent.getStringExtra(Intent.EXTRA_TEXT)?.take(MAX_SHARE_TEXT_LENGTH)
        } catch (_: RuntimeException) {
            // Malformed extras from another app must not crash the exported activity.
            null
        } ?: return null
        return extractUrlFromText(rawText)
    }

    /** Extracts the first http(s) URL in [text], or null when that URL fails [sanitizeUrl]. */
    fun extractUrlFromText(text: String?): String? {
        if (text.isNullOrBlank()) return null
        val bounded = text.take(MAX_SHARE_TEXT_LENGTH)
        val match = URL_REGEX.find(bounded) ?: return null
        return sanitizeUrl(match.value)
    }

    /** Validates and normalizes the [candidate] URL. Requires an http/https scheme and a non-empty host, and rejects URLs with user credentials (userInfo, used in phishing) or control characters and whitespace. */
    fun sanitizeUrl(candidate: String?): String? {
        if (candidate.isNullOrBlank()) return null
        // Strip trailing punctuation often attached when sharing from messages or Markdown.
        val trimmed = candidate.trim().trimEnd('.', ',', ';', ':', ')', ']', '}')
        if (trimmed.length > MAX_URL_LENGTH) return null
        // Reject control characters, newlines, or whitespace.
        if (trimmed.any { it.isISOControl() || it.isWhitespace() }) return null

        val httpUrl = trimmed.toHttpUrlOrNull() ?: return null
        val scheme = httpUrl.scheme.lowercase()
        if (scheme != "http" && scheme != "https") return null
        // Reject user:password credentials in the URL to prevent credential leakage or phishing.
        if (httpUrl.username.isNotEmpty() || httpUrl.password.isNotEmpty()) return null
        if (httpUrl.host.isBlank()) return null

        return httpUrl.toString()
    }
}
