package com.example.intelfeed.util

object SpeechText {

    /** Android's TextToSpeech.getMaxSpeechInputLength() is 4000; stay under it. */
    const val MAX_CHUNK = 3_800

    private val SENTENCE_END = Regex("(?<=[.!?…])\\s+")

    private val URL_REGEX = Regex("https?://(?:www\\.)?([a-zA-Z0-9.-]+)(?:/[^\\s]*)?", RegexOption.IGNORE_CASE)
    private val HASH_REGEX = Regex("\\b[a-fA-F0-9]{32,64}\\b")
    private val CVE_REGEX = Regex("\\bCVE-(\\d{4})-(\\d+)\\b", RegexOption.IGNORE_CASE)
    private val CODE_BLOCK_REGEX = Regex("```[\\s\\S]*?```")
    private val INLINE_CODE_REGEX = Regex("`([^`]+)`")
    private val MARKDOWN_LINK_REGEX = Regex("\\[([^\\]]+)\\]\\([^)]+\\)")
    private val BOLD_ITALIC_REGEX = Regex("(\\*\\*|__|\\*|_)(.*?)\\1")
    private val HEADER_REGEX = Regex("(?m)^#{1,6}\\s+(.+)$")
    private val HR_REGEX = Regex("(?m)^[-*_]{3,}\\s*$")
    private val BULLET_REGEX = Regex("(?m)^\\s*[•\\-*]\\s+")

    /**
     * Cleans raw article text for natural-sounding speech:
     * - Replaces long URLs with friendly domain mentions ("link to domain.com")
     * - Omits 32- and 64-character hex hashes (MD5, SHA256) so the voice doesn't spell them out
     * - Formats CVE identifiers with natural cadence pauses ("C-V-E 2024, 38077")
     * - Strips markdown tokens and ensures headings end with a period for a breath pause
     * - Omits code blocks
     */
    fun cleanForSpeech(text: String): String {
        if (text.isBlank()) return ""
        return text
            .replace(CODE_BLOCK_REGEX, " [code snippet omitted] ")
            .replace(MARKDOWN_LINK_REGEX, "$1")
            .replace(URL_REGEX) { match ->
                val domain = match.groupValues[1].trimEnd('.', ',', '!', '?', ';', ':')
                val trailing = match.value.takeLastWhile { it in ".,!?;:" }
                " link to $domain$trailing "
            }
            .replace(HASH_REGEX, " [hash] ")
            .replace(CVE_REGEX, "C-V-E $1, $2")
            .replace(HEADER_REGEX) { match ->
                val title = match.groupValues[1].trim()
                if (title.endsWith(".") || title.endsWith("!") || title.endsWith("?")) title else "$title."
            }
            .replace(BOLD_ITALIC_REGEX, "$2")
            .replace(INLINE_CODE_REGEX, "$1")
            .replace(HR_REGEX, "")
            .replace(BULLET_REGEX, "")
            .replace(Regex("\\s+([.,!?;:])"), "$1")
            .replace(Regex("[ \\t]+"), " ")
            .replace(Regex("\\n{3,}"), "\n\n")
            .trim()
    }

    /**
     * Splits text into pieces TextToSpeech will accept. TextToSpeech.speak() rejects anything longer
     * than its limit (it returns ERROR and says nothing), so a long article has to be queued in
     * parts. Splits at paragraph breaks, then sentence ends, then spaces; never inside a word
     * unless a single "word" is longer than [max].
     */
    fun chunk(text: String, max: Int = MAX_CHUNK): List<String> {
        require(max > 0)
        val chunks = mutableListOf<String>()
        val current = StringBuilder()

        fun flush() {
            val piece = current.toString().trim()
            if (piece.isNotEmpty()) chunks += piece
            current.setLength(0)
        }

        fun append(piece: String, separator: String) {
            if (current.isNotEmpty() && current.length + separator.length + piece.length > max) flush()
            if (current.isNotEmpty()) current.append(separator)
            current.append(piece)
        }

        for (paragraph in text.split(Regex("\\n\\s*\\n")).map { it.trim() }.filter { it.isNotEmpty() }) {
            if (paragraph.length <= max) {
                append(paragraph, "\n\n")
                continue
            }
            for (sentence in paragraph.split(SENTENCE_END).filter { it.isNotBlank() }) {
                if (sentence.length <= max) {
                    append(sentence, " ")
                    continue
                }
                for (word in sentence.split(' ').filter { it.isNotEmpty() }) {
                    if (word.length <= max) append(word, " ")
                    else word.chunked(max).forEach { append(it, "") }
                }
            }
        }
        flush()
        return chunks
    }
}
