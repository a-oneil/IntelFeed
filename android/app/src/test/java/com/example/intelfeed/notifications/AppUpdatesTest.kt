package com.example.intelfeed.notifications

import com.example.intelfeed.notifications.AppUpdates.GitHubRelease
import com.example.intelfeed.notifications.AppUpdates.Release
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AppUpdatesTest {

    private fun release(tag: String, draft: Boolean = false, prerelease: Boolean = false, body: String? = "**IntelFeed for Android** (build 8)") =
        GitHubRelease(tagName = tag, draft = draft, prerelease = prerelease, body = body, htmlUrl = "https://github.com/a-oneil/IntelFeed/releases/tag/$tag")

    @Test fun picksTheHighestVersionNotTheFirstListed() {
        val latest = AppUpdates.pickLatest(listOf(release("android-v1.9"), release("android-v1.10"), release("android-v1.2")))
        assertEquals("1.10", latest?.versionName)
        assertEquals("https://github.com/a-oneil/IntelFeed/releases/tag/android-v1.10", latest?.url)
    }

    @Test fun skipsDraftsPrereleasesAndOtherTags() {
        val latest = AppUpdates.pickLatest(
            listOf(
                release("android-v2.0", draft = true),
                release("android-v1.9", prerelease = true),
                release("v3.0"),
                release("android-vnext"),
                release("android-v1.7")
            )
        )
        assertEquals("1.7", latest?.versionName)
        assertNull(AppUpdates.pickLatest(listOf(release("v3.0"))))
    }

    @Test fun readsTheBuildNumberFromTheNotes() {
        assertEquals(8, AppUpdates.pickLatest(listOf(release("android-v1.7")))?.versionCode)
        assertNull(AppUpdates.pickLatest(listOf(release("android-v1.7", body = "no build here")))?.versionCode)
    }

    @Test fun summaryIsTheWhatChangedLineFromCiNotes() {
        val notes = "**IntelFeed for Android 1.8** (build 9)\n\nnotify when a new app release is out\n\nDownload `IntelFeed.apk` below."
        assertEquals("notify when a new app release is out", AppUpdates.summaryOf(notes))
        assertNull(AppUpdates.summaryOf("**IntelFeed for Android 1.8** (build 9)\n\nDownload `IntelFeed.apk` below."))
        assertNull(AppUpdates.summaryOf("Hand-written notes"))
    }

    @Test fun onlyGithubHttpsLinksAreKept() {
        val evil = GitHubRelease(tagName = "android-v1.8", htmlUrl = "https://github.com.evil.example/x")
        assertNull(AppUpdates.pickLatest(listOf(evil))?.url)
    }

    @Test fun higherBuildNumberIsNewer() {
        assertTrue(AppUpdates.isNewer(Release("1.8", 9, null), "1.7", 8))
        assertFalse(AppUpdates.isNewer(Release("1.7", 8, null), "1.7", 8))
    }

    @Test fun versionNamesCompareAsNumbersNotText() {
        assertTrue(AppUpdates.isNewer(Release("1.10", null, null), "1.9", 9))
        assertFalse(AppUpdates.isNewer(Release("1.9", null, null), "1.10", 11))
        assertFalse(AppUpdates.isNewer(Release("1.7.0", null, null), "1.7", 8))
        assertTrue(AppUpdates.isNewer(Release("2", null, null), "1.7", 8))
    }

    @Test fun fetchDecodesGithubsListAndFailsQuietly() = runTest {
        val server = MockWebServer()
        server.enqueue(MockResponse().setBody("""[{"tag_name":"android-v1.8","draft":false,"prerelease":false,"body":"(build 9)","html_url":"https://github.com/a-oneil/IntelFeed/releases/tag/android-v1.8","assets":[]}]"""))
        server.enqueue(MockResponse().setResponseCode(404))
        server.start()
        try {
            val http = OkHttpClient()
            val url = server.url("/repos/a-oneil/IntelFeed/releases").toString()
            assertEquals(Release("1.8", 9, "https://github.com/a-oneil/IntelFeed/releases/tag/android-v1.8"), AppUpdates.fetchLatest(url, http))
            assertNull(AppUpdates.fetchLatest(url, http))
            val request = server.takeRequest()
            assertNull(request.getHeader("Authorization"))
            assertTrue(request.getHeader("User-Agent")!!.startsWith("IntelFeed-Android/"))
        } finally {
            server.shutdown()
        }
    }
}
