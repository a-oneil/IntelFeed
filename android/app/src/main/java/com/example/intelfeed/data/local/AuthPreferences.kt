package com.example.intelfeed.data.local

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.example.intelfeed.data.network.ServerUrl
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

// One DataStore per file per process: UserPreferences reads and writes this same instance.
internal val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "intelfeed_prefs")

/**
 * The session: server address, username and the two tokens. The tokens are encrypted at rest with
 * [cipher] (a Keystore key, see TokenCipher); everything else is plain.
 */
class AuthPreferences(
    private val store: DataStore<Preferences>,
    private val cipher: TokenCipher = TokenCipher.androidKeystore()
) {
    constructor(context: Context, cipher: TokenCipher = TokenCipher.androidKeystore()) : this(context.dataStore, cipher)

    // Null until DataStore has been read. Using the public default before that
    // would send a self-hosted session's first request (and potentially its bearer token) there.
    @Volatile private var cachedServerUrl: String? = null
    @Volatile private var cachedAccessToken: String? = null
    @Volatile private var cacheLoaded = false
    private val sessionMutex = Mutex()

    // Decrypting goes through the Keystore (a binder call), and the auth interceptor reads the
    // token for every request, so the last stored value → plain text pair is cached.
    private class DecryptCache(private val cipher: TokenCipher) {
        @Volatile private var last: Pair<String, String?>? = null
        fun get(stored: String?): String? {
            stored ?: return null
            last?.let { (s, plain) -> if (s == stored) return plain }
            return cipher.decrypt(stored).also { last = stored to it }
        }
    }
    private val accessCache = DecryptCache(cipher)
    private val refreshCache = DecryptCache(cipher)

    companion object {
        val KEY_SERVER_URL = stringPreferencesKey("server_url")
        val KEY_ACCESS_TOKEN = stringPreferencesKey("access_token")
        val KEY_REFRESH_TOKEN = stringPreferencesKey("refresh_token")
        val KEY_USERNAME = stringPreferencesKey("username")
        // No built-in server: the address is entered on the login screen.
        const val DEFAULT_SERVER_URL = ""
    }

    // Every flow below is distinctUntilChanged: DataStore emits on any write (e.g. each token
    // refresh), and collectors of isLoggedIn reload the whole app on each emission.

    // Stored values are re-validated so an invalid URL saved by an older build reads as no address
    // (and the login screen) instead of crashing Retrofit at startup.
    val serverUrl: Flow<String> = store.data.map { prefs ->
        prefs[KEY_SERVER_URL]?.let(ServerUrl::normalize) ?: DEFAULT_SERVER_URL
    }.distinctUntilChanged()

    val accessToken: Flow<String?> = store.data.map { prefs ->
        accessCache.get(prefs[KEY_ACCESS_TOKEN])
    }.distinctUntilChanged()

    val refreshToken: Flow<String?> = store.data.map { prefs ->
        refreshCache.get(prefs[KEY_REFRESH_TOKEN])
    }.distinctUntilChanged()

    val username: Flow<String?> = store.data.map { prefs ->
        prefs[KEY_USERNAME]
    }.distinctUntilChanged()

    // A token that can no longer be decrypted (Keystore key gone), or no valid server address,
    // counts as signed out, so the login screen shows instead of every request failing.
    val isLoggedIn: Flow<Boolean> = store.data.map { prefs ->
        !accessCache.get(prefs[KEY_ACCESS_TOKEN]).isNullOrBlank() &&
            prefs[KEY_SERVER_URL]?.let(ServerUrl::normalize) != null
    }.distinctUntilChanged()

    private suspend fun ensureCacheLoaded() {
        if (cacheLoaded) return
        sessionMutex.withLock {
            if (!cacheLoaded) {
                val prefs = store.data.first()
                cachedServerUrl = prefs[KEY_SERVER_URL]?.let(ServerUrl::normalize) ?: DEFAULT_SERVER_URL
                cachedAccessToken = accessCache.get(prefs[KEY_ACCESS_TOKEN])
                cacheLoaded = true
            }
        }
    }

    fun getCachedServerUrl(): String? = cachedServerUrl

    fun getCachedAccessToken(): String? = cachedAccessToken

    suspend fun getServerUrl(): String {
        ensureCacheLoaded()
        return sessionMutex.withLock { requireNotNull(cachedServerUrl) }
    }

    suspend fun getAccessToken(): String? {
        ensureCacheLoaded()
        return sessionMutex.withLock { cachedAccessToken }
    }

    suspend fun getRefreshToken(): String? {
        return refreshToken.first()
    }

    /** Persists [url] after normalizing it; throws [IllegalArgumentException] if it isn't a valid http(s) URL. */
    suspend fun setServerUrl(url: String) {
        val cleanUrl = requireNotNull(ServerUrl.normalize(url)) { "Invalid server URL: $url" }
        ensureCacheLoaded()
        sessionMutex.withLock {
            store.edit { prefs -> prefs[KEY_SERVER_URL] = cleanUrl }
            cachedServerUrl = cleanUrl
        }
    }

    suspend fun saveAuthTokens(accessToken: String, refreshToken: String?, username: String?) {
        ensureCacheLoaded()
        val encryptedAccess = cipher.encrypt(accessToken)
        val encryptedRefresh = refreshToken?.let(cipher::encrypt)
        sessionMutex.withLock {
            store.edit { prefs ->
                prefs[KEY_ACCESS_TOKEN] = encryptedAccess
                if (encryptedRefresh != null) prefs[KEY_REFRESH_TOKEN] = encryptedRefresh
                else prefs.remove(KEY_REFRESH_TOKEN)
                if (username != null) prefs[KEY_USERNAME] = username
            }
            cachedAccessToken = accessToken
        }
    }

    /** A late refresh cannot restore a session after logout or replace a newer login. */
    suspend fun saveRefreshedTokens(expectedAccessToken: String, accessToken: String, refreshToken: String?): Boolean {
        ensureCacheLoaded()
        val encryptedAccess = cipher.encrypt(accessToken)
        val encryptedRefresh = refreshToken?.let(cipher::encrypt)
        return sessionMutex.withLock {
            if (cachedAccessToken != expectedAccessToken) return@withLock false
            store.edit { prefs ->
                prefs[KEY_ACCESS_TOKEN] = encryptedAccess
                if (encryptedRefresh != null) prefs[KEY_REFRESH_TOKEN] = encryptedRefresh
            }
            cachedAccessToken = accessToken
            true
        }
    }

    /**
     * Re-saves tokens written by a version before encryption, so an existing session is protected
     * without signing the user out. Does nothing if they're already encrypted or the Keystore
     * isn't available.
     */
    suspend fun encryptStoredTokens() {
        val current = store.data.first()
        val pending = listOf(KEY_ACCESS_TOKEN, KEY_REFRESH_TOKEN).mapNotNull { key ->
            // Pair(...), not `to`: DataStore's Preferences.Key has its own infix `to`.
            current[key]?.takeIf { it.isNotBlank() && !cipher.isEncrypted(it) }?.let { Pair(key, cipher.encrypt(it)) }
        }.filter { (_, value) -> cipher.isEncrypted(value) }
        if (pending.isEmpty()) return
        store.edit { prefs ->
            pending.forEach { (key, encrypted) ->
                // Only if nothing (e.g. a token refresh) replaced the value in the meantime.
                if (prefs[key] == current[key]) prefs[key] = encrypted
            }
        }
    }

    suspend fun clear() {
        ensureCacheLoaded()
        sessionMutex.withLock {
            clearLocked()
        }
    }

    /** An expired request must not sign out a newer session after a server or account switch. */
    suspend fun clearIfCurrentToken(expectedAccessToken: String): Boolean {
        ensureCacheLoaded()
        return sessionMutex.withLock {
            if (cachedAccessToken != expectedAccessToken) return@withLock false
            clearLocked()
            true
        }
    }

    private suspend fun clearLocked() {
        cachedAccessToken = null
        store.edit { prefs ->
            prefs.remove(KEY_ACCESS_TOKEN)
            prefs.remove(KEY_REFRESH_TOKEN)
            prefs.remove(KEY_USERNAME)
        }
    }
}
