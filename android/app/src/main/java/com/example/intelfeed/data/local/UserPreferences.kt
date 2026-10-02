package com.example.intelfeed.data.local

import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.floatPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json

/**
 * Device-local reading preferences. Stored in the same DataStore file as the session (which is
 * excluded from backups), and deliberately kept on logout: they describe the device, not the account.
 */
class UserPreferences(private val context: Context) {

    companion object {
        private val KEY_APP_LANGUAGE = stringPreferencesKey("app_language")
        private val KEY_READER_TEXT_SIZE = stringPreferencesKey("reader_text_size")
        private val KEY_TTS_SPEECH_RATE = floatPreferencesKey("tts_speech_rate")
        private val KEY_RECENT_SEARCHES = stringPreferencesKey("recent_searches")
        private val KEY_AUTO_MARK_READ = booleanPreferencesKey("auto_mark_read")
        private val KEY_AUTO_TRANSLATE = booleanPreferencesKey("auto_translate_articles")
        private val KEY_TRANSLATE_TARGET_LANG = stringPreferencesKey("translate_target_lang")

        fun defaultTranslateLanguage(): String {
            val systemLang = java.util.Locale.getDefault().language.lowercase()
            return if (com.google.mlkit.nl.translate.TranslateLanguage.getAllLanguages().contains(systemLang)) systemLang else "en"
        }
        private val KEY_FEED_DENSITY = stringPreferencesKey("feed_density")
        private val KEY_FEED_LAYOUT = stringPreferencesKey("feed_layout")
        private val KEY_FEED_HIDE_READ = booleanPreferencesKey("feed_hide_read")
        private val KEY_FEED_AUTO_READ = booleanPreferencesKey("feed_auto_read")
        private val KEY_FEED_SORT = stringPreferencesKey("feed_sort")
        private val KEY_HIGHLIGHT_ENTITIES = booleanPreferencesKey("highlight_entities")
        private val KEY_TRACKED_KEYWORDS = stringPreferencesKey("tracked_keywords")
        // JSON {keyword: [entry ids already notified or seen]}, for keyword alerts.
        private val KEY_KEYWORD_SEEN = stringPreferencesKey("keyword_seen_ids")
        const val MAX_KEYWORDS = 50
        private const val MAX_SEEN_PER_KEYWORD = 200
        private val KEY_NOTIFICATIONS_ENABLED = booleanPreferencesKey("notifications_enabled")
        private val KEY_LAST_NOTIFICATION_SYNC_MS = longPreferencesKey("last_notification_sync_ms")
        // Campaign, saved-search and priority alerts already posted ("e:<entry id>", "t:<slug>:<time>").
        private val KEY_NOTIFIED_ALERTS = stringPreferencesKey("notified_alert_keys")
        private const val MAX_NOTIFIED_ALERTS = 500
        // "<server>|<username>" the alert state above belongs to (see claimAlertState).
        private val KEY_ALERT_STATE_OWNER = stringPreferencesKey("alert_state_owner")
        private const val RECENT_SEPARATOR = "\u001F"
        const val MAX_RECENT_SEARCHES = 8
    }

    /** Name of a ReaderFontSize value, or null for the default. */
    val readerTextSize: Flow<String?> = context.dataStore.data
        .map { it[KEY_READER_TEXT_SIZE] }
        .distinctUntilChanged()

    suspend fun setReaderTextSize(name: String) {
        context.dataStore.edit { it[KEY_READER_TEXT_SIZE] = name }
    }

    /** Read-aloud speech rate (e.g. 0.85f, 1.0f, 1.15f, 1.3f). Default is 1.0f. */
    val ttsSpeechRate: Flow<Float> = context.dataStore.data
        .map { it[KEY_TTS_SPEECH_RATE] ?: 1.0f }
        .distinctUntilChanged()

    suspend fun setTtsSpeechRate(rate: Float) {
        context.dataStore.edit { it[KEY_TTS_SPEECH_RATE] = rate }
    }

    /** Whether opening an article automatically marks it as read. Default is true. */
    val autoMarkRead: Flow<Boolean> = context.dataStore.data
        .map { it[KEY_AUTO_MARK_READ] ?: true }
        .distinctUntilChanged()

    suspend fun setAutoMarkRead(enabled: Boolean) {
        context.dataStore.edit { it[KEY_AUTO_MARK_READ] = enabled }
    }

    /** Whether foreign language articles are automatically translated to the user's language in the reader. Default false. */
    val autoTranslate: Flow<Boolean> = context.dataStore.data
        .map { it[KEY_AUTO_TRANSLATE] ?: false }
        .distinctUntilChanged()

    suspend fun setAutoTranslate(enabled: Boolean) {
        context.dataStore.edit { it[KEY_AUTO_TRANSLATE] = enabled }
    }

    /** Interface language code ("system", "en", "es", "fr", "de", "uk", "ru", "zh", "ja", "pt", "it"). Defaults to "system". */
    val appLanguage: Flow<String> = context.dataStore.data
        .map { it[KEY_APP_LANGUAGE] ?: "system" }
        .distinctUntilChanged()

    suspend fun setAppLanguage(code: String) {
        context.dataStore.edit { it[KEY_APP_LANGUAGE] = code }
    }

    /** Target language code for on-device article translation (e.g. "en", "es", "fr", "de"). Defaults to phone system language if supported, else "en". */
    val translateTargetLanguage: Flow<String> = context.dataStore.data
        .map { it[KEY_TRANSLATE_TARGET_LANG] ?: defaultTranslateLanguage() }
        .distinctUntilChanged()

    suspend fun setTranslateTargetLanguage(code: String) {
        context.dataStore.edit { it[KEY_TRANSLATE_TARGET_LANG] = code }
    }

    /** Feed card density: "expanded" (default, includes preview) or "compact" (title/metadata only). */
    val feedDensity: Flow<String> = context.dataStore.data
        .map { it[KEY_FEED_DENSITY] ?: "expanded" }
        .distinctUntilChanged()

    suspend fun setFeedDensity(density: String) {
        context.dataStore.edit { it[KEY_FEED_DENSITY] = density }
    }

    /** Feed layout style: "list" (vertical flow) or "grid" (multi-column magazine cards). */
    val feedLayout: Flow<String> = context.dataStore.data
        .map { it[KEY_FEED_LAYOUT] ?: "list" }
        .distinctUntilChanged()

    suspend fun setFeedLayout(layout: String) {
        context.dataStore.edit { it[KEY_FEED_LAYOUT] = layout }
    }

    /** The web's "Hide Read" toggle: date-ordered views show only unread articles. Default off. */
    val feedHideRead: Flow<Boolean> = context.dataStore.data
        .map { it[KEY_FEED_HIDE_READ] ?: false }
        .distinctUntilChanged()

    suspend fun setFeedHideRead(hide: Boolean) {
        context.dataStore.edit { it[KEY_FEED_HIDE_READ] = hide }
    }

    /**
     * The web toolbar's "Auto-read": articles scrolled off the top of the list are marked read.
     * Off by default on the phone, since a fling can pass many articles at once.
     */
    val feedAutoRead: Flow<Boolean> = context.dataStore.data
        .map { it[KEY_FEED_AUTO_READ] ?: false }
        .distinctUntilChanged()

    suspend fun setFeedAutoRead(enabled: Boolean) {
        context.dataStore.edit { it[KEY_FEED_AUTO_READ] = enabled }
    }

    /** "newest" (default) or "oldest": the order of date-ordered views (GET /api/entries?sort=). */
    val feedSort: Flow<String> = context.dataStore.data
        .map { if (it[KEY_FEED_SORT] == "oldest") "oldest" else "newest" }
        .distinctUntilChanged()

    suspend fun setFeedSort(sort: String) {
        context.dataStore.edit { it[KEY_FEED_SORT] = if (sort == "oldest") "oldest" else "newest" }
    }

    /** Mark linked entity names in article text (tap to open the profile), like the web reader. Default on. */
    val highlightEntities: Flow<Boolean> = context.dataStore.data
        .map { it[KEY_HIGHLIGHT_ENTITIES] ?: true }
        .distinctUntilChanged()

    suspend fun setHighlightEntities(enabled: Boolean) {
        context.dataStore.edit { it[KEY_HIGHLIGHT_ENTITIES] = enabled }
    }

    /**
     * The user's tracked keywords (phrases), kept on this device: highlighted in articles, listed
     * in the drawer, and checked by the background alerts. Oldest first.
     */
    val trackedKeywords: Flow<List<String>> = context.dataStore.data
        .map { prefs -> prefs[KEY_TRACKED_KEYWORDS]?.split(RECENT_SEPARATOR)?.filter { it.isNotBlank() } ?: emptyList() }
        .distinctUntilChanged()

    /** Adds [keyword] (trimmed, spaces collapsed) unless it's already tracked in any case. Returns false if not added. */
    suspend fun addTrackedKeyword(keyword: String): Boolean {
        val clean = keyword.trim().replace(Regex("\\s+"), " ").replace(RECENT_SEPARATOR, "")
        if (clean.length < 2 || clean.length > 100) return false
        var added = false
        context.dataStore.edit { prefs ->
            val current = prefs[KEY_TRACKED_KEYWORDS]?.split(RECENT_SEPARATOR)?.filter { it.isNotBlank() } ?: emptyList()
            if (current.size < MAX_KEYWORDS && current.none { it.equals(clean, ignoreCase = true) }) {
                prefs[KEY_TRACKED_KEYWORDS] = (current + clean).joinToString(RECENT_SEPARATOR)
                added = true
            }
        }
        return added
    }

    /** Stops tracking [keyword] and forgets its alert history, so tracking it again starts fresh. */
    suspend fun removeTrackedKeyword(keyword: String) {
        val serializer = MapSerializer(String.serializer(), ListSerializer(String.serializer()))
        context.dataStore.edit { prefs ->
            val current = prefs[KEY_TRACKED_KEYWORDS]?.split(RECENT_SEPARATOR)?.filter { it.isNotBlank() } ?: emptyList()
            prefs[KEY_TRACKED_KEYWORDS] = current.filterNot { it.equals(keyword, ignoreCase = true) }.joinToString(RECENT_SEPARATOR)
            prefs[KEY_KEYWORD_SEEN]?.let { raw ->
                val seen = runCatching { Json.decodeFromString(serializer, raw) }.getOrDefault(emptyMap())
                prefs[KEY_KEYWORD_SEEN] = Json.encodeToString(serializer, seen.filterKeys { !it.equals(keyword, ignoreCase = true) })
            }
        }
    }

    /** Entry ids already seen for each keyword by the background alerts. */
    suspend fun getKeywordSeenIds(): Map<String, List<String>> {
        val raw = context.dataStore.data.first()[KEY_KEYWORD_SEEN] ?: return emptyMap()
        return runCatching {
            Json.decodeFromString(MapSerializer(String.serializer(), ListSerializer(String.serializer())), raw)
        }.getOrDefault(emptyMap())
    }

    suspend fun setKeywordSeenIds(seen: Map<String, List<String>>) {
        val trimmed = seen.mapValues { (_, ids) -> ids.takeLast(MAX_SEEN_PER_KEYWORD) }
        context.dataStore.edit {
            it[KEY_KEYWORD_SEEN] = Json.encodeToString(MapSerializer(String.serializer(), ListSerializer(String.serializer())), trimmed)
        }
    }

    /** Most recent first. */
    val recentSearches: Flow<List<String>> = context.dataStore.data
        .map { prefs -> prefs[KEY_RECENT_SEARCHES]?.split(RECENT_SEPARATOR)?.filter { it.isNotBlank() } ?: emptyList() }
        .distinctUntilChanged()

    suspend fun addRecentSearch(query: String) {
        val q = query.trim().replace(RECENT_SEPARATOR, "").take(100)
        if (q.isEmpty()) return
        context.dataStore.edit { prefs ->
            val current = prefs[KEY_RECENT_SEARCHES]?.split(RECENT_SEPARATOR)?.filter { it.isNotBlank() } ?: emptyList()
            val updated = (listOf(q) + current.filterNot { it.equals(q, ignoreCase = true) }).take(MAX_RECENT_SEARCHES)
            prefs[KEY_RECENT_SEARCHES] = updated.joinToString(RECENT_SEPARATOR)
        }
    }

    suspend fun clearRecentSearches() {
        context.dataStore.edit { it.remove(KEY_RECENT_SEARCHES) }
    }

    /** Whether background notifications for campaigns, tracked keywords, and priority alerts are enabled. */
    val notificationsEnabled: Flow<Boolean> = context.dataStore.data
        .map { it[KEY_NOTIFICATIONS_ENABLED] ?: true }
        .distinctUntilChanged()

    suspend fun setNotificationsEnabled(enabled: Boolean) {
        context.dataStore.edit { it[KEY_NOTIFICATIONS_ENABLED] = enabled }
    }

    suspend fun getLastNotificationSyncMs(): Long {
        return context.dataStore.data.map { it[KEY_LAST_NOTIFICATION_SYNC_MS] ?: 0L }.first()
    }

    suspend fun setLastNotificationSyncMs(timestampMs: Long) {
        context.dataStore.edit { it[KEY_LAST_NOTIFICATION_SYNC_MS] = timestampMs }
    }

    /** Keys of background alerts already posted, so a later check never repeats one. */
    suspend fun getNotifiedAlertKeys(): Set<String> =
        context.dataStore.data.first()[KEY_NOTIFIED_ALERTS]?.split(RECENT_SEPARATOR)?.filterTo(HashSet()) { it.isNotBlank() } ?: emptySet()

    /** Records [keys] as posted, keeping the most recent [MAX_NOTIFIED_ALERTS]. */
    suspend fun addNotifiedAlertKeys(keys: Collection<String>) {
        if (keys.isEmpty()) return
        context.dataStore.edit { prefs ->
            val current = prefs[KEY_NOTIFIED_ALERTS]?.split(RECENT_SEPARATOR)?.filter { it.isNotBlank() } ?: emptyList()
            val added = keys.map { it.replace(RECENT_SEPARATOR, "") }
            prefs[KEY_NOTIFIED_ALERTS] = (current - added.toSet() + added).takeLast(MAX_NOTIFIED_ALERTS).joinToString(RECENT_SEPARATOR)
        }
    }

    /**
     * Ties the background alert state (keyword baselines, posted alerts, last check time) to
     * [owner], the signed-in server and user. When the owner changes, that state is dropped, so a
     * different account starts with fresh keyword baselines instead of alerting about every match.
     * State saved before owners were recorded is kept and adopted.
     */
    suspend fun claimAlertState(owner: String) {
        context.dataStore.edit { prefs ->
            val previous = prefs[KEY_ALERT_STATE_OWNER]
            if (previous != null && previous != owner) {
                prefs.remove(KEY_KEYWORD_SEEN)
                prefs.remove(KEY_NOTIFIED_ALERTS)
                prefs.remove(KEY_LAST_NOTIFICATION_SYNC_MS)
            }
            if (previous != owner) prefs[KEY_ALERT_STATE_OWNER] = owner
        }
    }
}
