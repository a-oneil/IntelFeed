package com.example.intelfeed.data.local

import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.floatPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import com.example.intelfeed.notifications.PriorityAlerts
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
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
        // Left by versions that tracked keywords on the device; claimAlertState removes them.
        private val LEGACY_KEYWORD_KEYS = listOf(stringPreferencesKey("tracked_keywords"), stringPreferencesKey("keyword_seen_ids"))
        private val KEY_NOTIFICATIONS_ENABLED = booleanPreferencesKey("notifications_enabled")
        private val KEY_LAST_NOTIFICATION_SYNC_MS = longPreferencesKey("last_notification_sync_ms")
        // Campaign, saved-search and priority alerts already posted ("e:<entry id>", "t:<story slug>").
        // A story records its articles too, so the cap leaves room for them.
        private val KEY_NOTIFIED_ALERTS = stringPreferencesKey("notified_alert_keys")
        private const val MAX_NOTIFIED_ALERTS = 3000
        // "<server>|<username>" the alert state above belongs to (see claimAlertState).
        private val KEY_ALERT_STATE_OWNER = stringPreferencesKey("alert_state_owner")
        // Lowest priority score that notifies (Settings), and the cut-off the queue was last
        // recorded at without alerting (see IntelNotificationWorker).
        private val KEY_PRIORITY_ALERT_SCORE = floatPreferencesKey("priority_alert_score")
        private val KEY_PRIORITY_ALERT_BASELINE = floatPreferencesKey("priority_alert_baseline")
        private val KEY_THEME_ID = stringPreferencesKey("theme_id")
        private val KEY_THEME_NAME = stringPreferencesKey("theme_name")
        private val KEY_THEME_SOURCE = stringPreferencesKey("theme_source")
        private val KEY_THEME_VARS = stringPreferencesKey("theme_vars")
        private val KEY_COLOR_SCHEMA = stringPreferencesKey("color_schema")
        private val themeJson = Json { ignoreUnknownKeys = true }
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

    /** Whether background notifications for campaigns, saved searches, and priority alerts are enabled. */
    val notificationsEnabled: Flow<Boolean> = context.dataStore.data
        .map { it[KEY_NOTIFICATIONS_ENABLED] ?: true }
        .distinctUntilChanged()

    suspend fun setNotificationsEnabled(enabled: Boolean) {
        context.dataStore.edit { it[KEY_NOTIFICATIONS_ENABLED] = enabled }
    }

    /** Unread Priority Queue items scoring at least this notify. Default 9.5 (the red band). */
    val priorityAlertScore: Flow<Double> = context.dataStore.data
        .map { PriorityAlerts.clampCutoff(it[KEY_PRIORITY_ALERT_SCORE]?.toDouble() ?: PriorityAlerts.DEFAULT_CUTOFF) }
        .distinctUntilChanged()

    suspend fun setPriorityAlertScore(score: Double) {
        context.dataStore.edit { it[KEY_PRIORITY_ALERT_SCORE] = PriorityAlerts.clampCutoff(score).toFloat() }
    }

    /** The cut-off the queue was last recorded at, or null before the first check. */
    suspend fun getPriorityAlertBaseline(): Double? =
        context.dataStore.data.first()[KEY_PRIORITY_ALERT_BASELINE]?.toDouble()

    suspend fun setPriorityAlertBaseline(cutoff: Double) {
        context.dataStore.edit { it[KEY_PRIORITY_ALERT_BASELINE] = cutoff.toFloat() }
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
     * Ties the background alert state (posted alerts, priority baseline, last check time) to
     * [owner], the signed-in server and user. When the owner changes, that state is dropped, so a
     * different account starts fresh. State saved before owners were recorded is kept and adopted.
     */
    suspend fun claimAlertState(owner: String) {
        context.dataStore.edit { prefs ->
            val previous = prefs[KEY_ALERT_STATE_OWNER]
            if (previous != null && previous != owner) {
                prefs.remove(KEY_NOTIFIED_ALERTS)
                prefs.remove(KEY_PRIORITY_ALERT_BASELINE)
                prefs.remove(KEY_LAST_NOTIFICATION_SYNC_MS)
            }
            if (previous != owner) prefs[KEY_ALERT_STATE_OWNER] = owner
            LEGACY_KEYWORD_KEYS.forEach { if (it in prefs) prefs.remove(it) }
        }
    }

    val cachedThemeState: Flow<CachedThemeState> = context.dataStore.data
        .map { prefs ->
            val varsRaw = prefs[KEY_THEME_VARS]
            val vars = if (!varsRaw.isNullOrBlank()) {
                runCatching {
                    themeJson.decodeFromString(MapSerializer(String.serializer(), String.serializer()), varsRaw)
                }.getOrDefault(emptyMap())
            } else {
                emptyMap()
            }
            val schemaRaw = prefs[KEY_COLOR_SCHEMA]
            val schema = if (!schemaRaw.isNullOrBlank()) {
                runCatching {
                    themeJson.decodeFromString(com.example.intelfeed.data.model.ColorSchemaDto.serializer(), schemaRaw)
                }.getOrNull()
            } else {
                null
            }
            CachedThemeState(
                themeId = prefs[KEY_THEME_ID],
                themeName = prefs[KEY_THEME_NAME],
                source = prefs[KEY_THEME_SOURCE],
                variables = vars,
                colorSchema = schema
            )
        }
        .distinctUntilChanged()

    suspend fun getCachedThemeState(): CachedThemeState = cachedThemeState.first()

    suspend fun saveCachedTheme(
        themeId: String,
        themeName: String,
        variables: Map<String, String>,
        source: String? = null
    ) {
        val varsJson = themeJson.encodeToString(MapSerializer(String.serializer(), String.serializer()), variables)
        context.dataStore.edit { prefs ->
            prefs[KEY_THEME_ID] = themeId
            prefs[KEY_THEME_NAME] = themeName
            prefs[KEY_THEME_VARS] = varsJson
            if (source != null) {
                prefs[KEY_THEME_SOURCE] = source
            }
        }
    }

    suspend fun clearCachedTheme() {
        context.dataStore.edit { prefs ->
            prefs.remove(KEY_THEME_ID)
            prefs.remove(KEY_THEME_NAME)
            prefs.remove(KEY_THEME_SOURCE)
            prefs.remove(KEY_THEME_VARS)
        }
    }

    suspend fun saveCachedColorSchema(schema: com.example.intelfeed.data.model.ColorSchemaDto) {
        val schemaJson = themeJson.encodeToString(com.example.intelfeed.data.model.ColorSchemaDto.serializer(), schema)
        context.dataStore.edit { prefs ->
            prefs[KEY_COLOR_SCHEMA] = schemaJson
        }
    }
}

data class CachedThemeState(
    val themeId: String? = null,
    val themeName: String? = null,
    val source: String? = null,
    val variables: Map<String, String> = emptyMap(),
    val colorSchema: com.example.intelfeed.data.model.ColorSchemaDto? = null
)

