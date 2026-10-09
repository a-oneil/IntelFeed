package com.example.intelfeed.data.network

import com.example.intelfeed.BuildConfig
import com.example.intelfeed.data.local.AuthPreferences
import com.example.intelfeed.data.model.RefreshTokenRequest
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.Dispatcher
import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.HttpException
import retrofit2.Retrofit
import retrofit2.converter.kotlinx.serialization.asConverterFactory
import java.util.concurrent.TimeUnit

/** The JSON settings every API call uses. Shared with tests so they decode exactly like the app. */
object ApiJson {
    val json = Json {
        // The server adds fields often; unknown ones are ignored rather than failing the response.
        ignoreUnknownKeys = true
        coerceInputValues = true
        isLenient = true
        encodeDefaults = true
    }
}

class ApiClient(private val authPreferences: AuthPreferences) {

    // Shared with the repository for payloads it decodes itself (e.g. endpoints that can return null).
    val json = ApiJson.json

    // The server rotates refresh tokens and blacklists the old one on use, so concurrent 401s
    // must share one refresh. Without this, the second refresh spends an already-used token,
    // fails, and logs the user out.
    private val refreshLock = Any()

    private val authInterceptor = Interceptor { chain ->
        val originalRequest = chain.request()
        // Sign-in must never carry a token from a previous session, especially when the user
        // changes servers. Logout carries its captured token explicitly after local sign-out.
        if (originalRequest.header("Authorization") != null ||
            originalRequest.url.encodedPath.endsWith("/api/auth/login")) {
            return@Interceptor chain.proceed(originalRequest)
        }
        // Only the signed-in server gets the token, even from an API instance built for an older address.
        val server = sessionServer()
        if (server == null || !originalRequest.url.isSameOrigin(server)) {
            return@Interceptor chain.proceed(originalRequest)
        }

        val accessToken = authPreferences.getCachedAccessToken() ?: runBlocking { authPreferences.getAccessToken() }
        if (accessToken.isNullOrBlank()) {
            return@Interceptor chain.proceed(originalRequest)
        }

        val response = chain.proceed(originalRequest.withBearer(accessToken))
        if (response.code != 401) {
            return@Interceptor response
        }

        // Only close the 401 once we know we're retrying; otherwise Retrofit still needs to read
        // its body (closing it early turned every 401 into an IllegalStateException("closed")).
        val newAccessToken = refreshAccessToken(staleAccessToken = accessToken)
            ?: return@Interceptor response
        response.close()
        chain.proceed(originalRequest.withBearer(newAccessToken))
    }

    /**
     * Returns a fresh access token, or null if the session couldn't be refreshed. Only an explicit
     * 401/403 from the refresh endpoint ends the session (matching the web client); network errors,
     * rate limiting (429) and 5xx keep the stored tokens so a later request can try again.
     */
    private fun refreshAccessToken(staleAccessToken: String): String? = synchronized(refreshLock) {
        val currentAccessToken = authPreferences.getCachedAccessToken() ?: runBlocking { authPreferences.getAccessToken() }
        if (currentAccessToken.isNullOrBlank()) return null // logged out while waiting for the lock
        if (currentAccessToken != staleAccessToken) return currentAccessToken // another request already refreshed

        val refreshToken = runBlocking { authPreferences.getRefreshToken() }
        if (refreshToken.isNullOrBlank()) return null

        try {
            val tokens = runBlocking {
                val serverUrl = authPreferences.getServerUrl()
                buildRetrofit(serverUrl, refreshHttpClient)
                    .create(IntelFeedApi::class.java)
                    .refresh(RefreshTokenRequest(refreshToken = refreshToken))
            }
            if (runBlocking {
                authPreferences.saveRefreshedTokens(
                    expectedAccessToken = staleAccessToken,
                    accessToken = tokens.accessToken,
                    refreshToken = tokens.refreshToken ?: refreshToken
                )
            }) tokens.accessToken else null
        } catch (e: HttpException) {
            if (e.code() == 401 || e.code() == 403) {
                runBlocking { authPreferences.clearIfCurrentToken(staleAccessToken) }
            }
            null
        } catch (e: Exception) {
            null
        }
    }

    // Has no auth interceptor, so a refresh can never recurse into another refresh.
    private val refreshHttpClient = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .build()

    private val okHttpClient = OkHttpClient.Builder()
        // OkHttp allows 5 concurrent requests per host by default. The app starts ~13 at once
        // (feed, folders, eight view counts, Workbench, saved searches) and some take 4–10 s on the
        // server, so the feed could wait behind the counts. The server speaks HTTP/2, so these all
        // share one connection anyway.
        .dispatcher(Dispatcher().apply { maxRequestsPerHost = 16 })
        .connectTimeout(20, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .addInterceptor(authInterceptor)
        .apply {
            // Request URLs include search terms and entity lookups; keep them out of release logcat.
            if (BuildConfig.DEBUG) {
                addInterceptor(HttpLoggingInterceptor().apply {
                    level = HttpLoggingInterceptor.Level.BASIC
                })
            }
        }
        .build()

    // The parsed server address, re-parsed only when the stored address changes.
    @Volatile private var parsedServer: Pair<String, HttpUrl>? = null

    private fun sessionServer(): HttpUrl? {
        val raw = authPreferences.getCachedServerUrl() ?: runBlocking { authPreferences.getServerUrl() }
        parsedServer?.let { (url, parsed) -> if (url == raw) return parsed }
        return raw.toHttpUrlOrNull()?.also { parsedServer = raw to it }
    }

    private fun HttpUrl.isSameOrigin(server: HttpUrl): Boolean =
        scheme == server.scheme && host.equals(server.host, ignoreCase = true) && port == server.port

    /**
     * Client for article images (Coil). The server serves feed images through an authenticated
     * proxy (/api/proxy/image), so requests to that proxy carry the access token. Other paths on
     * the server and third-party image hosts never receive it: article HTML comes from arbitrary
     * feeds, and an <img> pointing at another API path would otherwise make an authenticated GET.
     */
    // Built from the API client so both share one connection pool: proxied images
    // come from the IntelFeed server, and reusing the API's open HTTP/2 connection avoids a new
    // TLS handshake per image. The API client's interceptors (auth refresh, logging) are removed.
    fun imageHttpClient(): OkHttpClient = okHttpClient.newBuilder()
        .apply { interceptors().clear() }
        // Its own queue (default limits), so a screen full of images can't hold up API calls.
        .dispatcher(Dispatcher())
        .connectTimeout(20, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .addInterceptor { chain ->
            val request = chain.request()
            val server = authPreferences.getCachedServerUrl()?.let { sessionServer() }
            val isImageProxy = server != null && request.url.isSameOrigin(server) &&
                request.url.encodedPath.startsWith(server.encodedPath.trimEnd('/') + "/api/proxy/")
            val token = if (isImageProxy) authPreferences.getCachedAccessToken() else null
            chain.proceed(if (token.isNullOrBlank()) request else request.withBearer(token))
        }
        .build()

    /** [serverUrl] must already be validated (see [ServerUrl.normalize]); Retrofit throws on a bad base URL. */
    fun createApi(serverUrl: String): IntelFeedApi {
        return buildRetrofit(serverUrl, okHttpClient).create(IntelFeedApi::class.java)
    }

    private fun buildRetrofit(serverUrl: String, client: OkHttpClient): Retrofit {
        return Retrofit.Builder()
            .baseUrl(ensureTrailingSlash(serverUrl))
            .client(client)
            .addConverterFactory(json.asConverterFactory("application/json".toMediaType()))
            .build()
    }

    private fun Request.withBearer(token: String): Request {
        return newBuilder().header("Authorization", "Bearer $token").build()
    }

    private fun ensureTrailingSlash(url: String): String {
        return if (url.endsWith("/")) url else "$url/"
    }
}
