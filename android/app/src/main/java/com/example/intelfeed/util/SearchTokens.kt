package com.example.intelfeed.util

/**
 * Reads and rewrites `field:value` tokens in a search query (docs/query-language.md), for the
 * search filter sheet. Only positive tokens are handled: a negated one (`-tag:x`, `NOT feed:x`)
 * is left exactly as typed, so editing filters can never flip its meaning.
 */
object SearchTokens {

    private fun pattern(field: String) =
        Regex("""(?<![\w.\-])(?<!NOT )${Regex.escape(field)}:("([^"]*)"|(\S+))""")

    /** Every positive value of [field], unquoted, in order. */
    fun values(query: String, field: String): List<String> =
        pattern(field).findAll(query).map { m -> m.groupValues[2].ifEmpty { m.groupValues[3] } }.filter { it.isNotBlank() }.toList()

    /** The query without its positive [field] tokens, with spaces tidied. */
    fun remove(query: String, field: String): String =
        pattern(field).replace(query, "").trim().replace(Regex("""\s+"""), " ")

    /** `field:value`, quoted when the value has a space (the server stops a value at the first space). */
    fun token(field: String, value: String): String {
        val clean = value.trim().replace("\"", "")
        return if (clean.any { it.isWhitespace() }) "$field:\"$clean\"" else "$field:$clean"
    }

    /**
     * [query] with an unclosed quote closed. The filter sheet appends its tokens to the typed text,
     * and after an unclosed quote the server read them as part of the phrase ("ransomware
     * date:>=… is:starred"), so applying a filter found nothing.
     */
    fun closeOpenQuote(query: String): String = if (query.count { it == '"' } % 2 == 1) "$query\"" else query
}
