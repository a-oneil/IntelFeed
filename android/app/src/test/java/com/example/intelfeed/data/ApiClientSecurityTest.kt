package com.example.intelfeed.data

import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import com.example.intelfeed.data.local.AuthPreferences
import com.example.intelfeed.data.local.TokenCipher
import com.example.intelfeed.data.model.LoginRequest
import com.example.intelfeed.data.network.ApiClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.test.runTest
import okhttp3.Request
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class ApiClientSecurityTest {
    @get:Rule val temp = TemporaryFolder()
    private lateinit var scope: CoroutineScope
    private lateinit var auth: AuthPreferences
    private lateinit var server: MockWebServer

    @Before fun setUp() {
        scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val store = PreferenceDataStoreFactory.create(scope = scope) {
            temp.root.resolve("auth.preferences_pb")
        }
        auth = AuthPreferences(store, TokenCipher { null })
        server = MockWebServer().also { it.start() }
    }

    @After fun tearDown() {
        server.shutdown()
        scope.cancel()
    }

    @Test fun loginToAnotherServerDoesNotSendPreviousBearerToken() = runTest {
        auth.setServerUrl("https://previous.example")
        auth.saveAuthTokens("previous-secret", "refresh-secret", "previous-user")
        server.enqueue(MockResponse().setBody("""{"access_token":"new-secret"}"""))

        ApiClient(auth).createApi(server.url("/").toString())
            .login(LoginRequest("new-user", "password"))

        val request = server.takeRequest()
        assertEquals("/api/auth/login", request.path)
        assertNull(request.getHeader("Authorization"))
    }

    @Test fun apiSendsTokenOnlyToTheSignedInServer() = runTest {
        auth.setServerUrl(server.url("/").toString())
        auth.saveAuthTokens("secret", null, "user")
        server.enqueue(MockResponse().setResponseCode(204))
        ApiClient(auth).createApi(server.url("/").toString()).markRead("a")
        assertEquals("Bearer secret", server.takeRequest().getHeader("Authorization"))

        // An API instance still pointing at another address (the stored server changed) gets no token.
        auth.setServerUrl("https://other.example")
        server.enqueue(MockResponse().setResponseCode(204))
        ApiClient(auth).createApi(server.url("/").toString()).markRead("a")
        assertNull(server.takeRequest().getHeader("Authorization"))
    }

    @Test fun imageClientSendsTokenOnlyToTheImageProxy() = runTest {
        auth.setServerUrl(server.url("/").toString())
        auth.saveAuthTokens("secret", null, "user")
        val images = ApiClient(auth).imageHttpClient()
        fun fetch(path: String): String? {
            server.enqueue(MockResponse().setResponseCode(200))
            images.newCall(Request.Builder().url(server.url(path)).build()).execute().close()
            return server.takeRequest().getHeader("Authorization")
        }

        assertEquals("Bearer secret", fetch("/api/proxy/image?url=https%3A%2F%2Fexample.com%2Fa.png"))
        // Feed HTML can point an <img> at any server path; those must not become authenticated GETs.
        assertNull(fetch("/api/entries/abc/read"))
        assertNull(fetch("/api/auth/logout"))
    }
}
