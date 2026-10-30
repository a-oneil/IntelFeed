package com.example.intelfeed.notifications

import com.example.intelfeed.BuildConfig
import com.example.intelfeed.data.network.ApiJson
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit

/** Finds the newest app release on GitHub and decides whether it is newer than the installed app. */
object AppUpdates {

    // CI publishes each version as a release tagged android-v<version> (.github/workflows/ci.yml).
    const val RELEASES_API = "https://api.github.com/repos/a-oneil/IntelFeed/releases?per_page=30"
    private const val TAG_PREFIX = "android-v"
    // Release pages only: a notification tap opens this in the browser.
    private const val RELEASE_PAGE_PREFIX = "https://github.com/"
    // CI writes "**IntelFeed for Android 1.7** (build 8)" at the top of the notes, then the merged
    // PR's title ("what changed"), then the download line.
    private val BUILD = Regex("""\(build (\d+)\)""")

    @Serializable
    data class GitHubRelease(
        @SerialName("tag_name") val tagName: String = "",
        val draft: Boolean = false,
        val prerelease: Boolean = false,
        val body: String? = null,
        @SerialName("html_url") val htmlUrl: String? = null
    )

    data class Release(val versionName: String, val versionCode: Int?, val url: String?, val summary: String? = null)

    // Its own client: nothing from the IntelFeed session (token, server address) goes to GitHub.
    private val client by lazy {
        OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(15, TimeUnit.SECONDS)
            .build()
    }

    /** The newest release, or null when GitHub can't be read (offline, rate-limited, repo not public). */
    suspend fun fetchLatest(url: String = RELEASES_API, http: OkHttpClient = client): Release? = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url(url)
            .header("Accept", "application/vnd.github+json")
            // GitHub asks API clients to name themselves.
            .header("User-Agent", "IntelFeed-Android/${BuildConfig.VERSION_NAME}")
            .build()
        runCatching {
            http.newCall(request).execute().use { resp ->
                if (!resp.isSuccessful) return@use null
                val body = resp.body?.string() ?: return@use null
                pickLatest(ApiJson.json.decodeFromString(ListSerializer(GitHubRelease.serializer()), body))
            }
        }.getOrNull()
    }

    /** The highest published android-v<version> release in [releases], or null. */
    fun pickLatest(releases: List<GitHubRelease>): Release? = releases
        .filter { !it.draft && !it.prerelease && it.tagName.startsWith(TAG_PREFIX) }
        .mapNotNull { r -> parse(r.tagName.removePrefix(TAG_PREFIX))?.let { r to it } }
        .maxWithOrNull { a, b -> compare(a.second, b.second) }
        ?.first
        ?.let { r ->
            Release(
                versionName = r.tagName.removePrefix(TAG_PREFIX),
                versionCode = r.body?.let { BUILD.find(it)?.groupValues?.get(1)?.toIntOrNull() },
                url = r.htmlUrl?.trim()?.takeIf { it.startsWith(RELEASE_PAGE_PREFIX) },
                summary = summaryOf(r.body)
            )
        }

    /** The "what changed" line CI puts under the heading, or null when the notes don't have one. */
    fun summaryOf(body: String?): String? {
        val lines = body?.lines()?.map { it.trim() }?.filter { it.isNotEmpty() } ?: return null
        if (lines.firstOrNull()?.startsWith("**IntelFeed for Android") != true) return null
        return lines.getOrNull(1)?.takeUnless { it.startsWith("Download ") || it.startsWith("Built from ") }?.take(200)
    }

    /** "1.10" -> [1, 10]; null when it isn't dotted numbers. */
    fun parse(version: String?): List<Int>? {
        val parts = version?.trim()?.split('.') ?: return null
        return parts.map { it.toIntOrNull() ?: return null }
    }

    private fun compare(a: List<Int>, b: List<Int>): Int {
        for (i in 0 until maxOf(a.size, b.size)) {
            val d = a.getOrElse(i) { 0 }.compareTo(b.getOrElse(i) { 0 })
            if (d != 0) return d
        }
        return 0
    }

    /**
     * True when [release] is newer than the installed [currentName] / [currentCode].
     * The build number decides when it is known (it always goes up); otherwise the version name.
     */
    fun isNewer(release: Release, currentName: String, currentCode: Int): Boolean {
        release.versionCode?.let { return it > currentCode }
        val current = parse(currentName) ?: return false
        val latest = parse(release.versionName) ?: return false
        return compare(latest, current) > 0
    }
}
