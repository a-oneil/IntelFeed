package com.example.intelfeed.data

import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import com.example.intelfeed.data.local.AuthPreferences
import com.example.intelfeed.data.local.TokenCipher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class AuthPreferencesTest {
    @get:Rule val temp = TemporaryFolder()
    private lateinit var scope: CoroutineScope
    private lateinit var store: androidx.datastore.core.DataStore<Preferences>
    private lateinit var auth: AuthPreferences

    @Before fun setUp() {
        scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        store = PreferenceDataStoreFactory.create(scope = scope) {
            temp.root.resolve("auth.preferences_pb")
        }
        auth = AuthPreferences(store, TokenCipher { null })
    }

    @After fun tearDown() {
        scope.cancel()
    }

    @Test fun firstRequestUsesStoredServerInsteadOfPublicDefault() = runTest {
        store.edit { it[AuthPreferences.KEY_SERVER_URL] = "https://self-hosted.example" }
        assertEquals("https://self-hosted.example", auth.getServerUrl())
        assertEquals("https://self-hosted.example", auth.getCachedServerUrl())
    }

    @Test fun lateRefreshCannotRestoreLoggedOutSession() = runTest {
        auth.saveAuthTokens("old", "refresh-old", "user")
        auth.clear()

        assertFalse(auth.saveRefreshedTokens("old", "late", "refresh-late"))
        assertNull(auth.getAccessToken())
        assertNull(auth.getRefreshToken())
    }

    @Test fun staleRefreshFailureCannotClearNewLogin() = runTest {
        auth.saveAuthTokens("old", "refresh-old", "user")
        auth.saveAuthTokens("new", "refresh-new", "user")

        assertFalse(auth.clearIfCurrentToken("old"))
        assertEquals("new", auth.getAccessToken())
        assertEquals("refresh-new", auth.getRefreshToken())
        assertTrue(auth.saveRefreshedTokens("new", "newer", "refresh-newer"))
        assertEquals("newer", auth.getAccessToken())
    }

    @Test fun newLoginWithoutRefreshTokenDoesNotKeepPreviousAccountsToken() = runTest {
        auth.saveAuthTokens("old", "refresh-old", "old-user")
        auth.saveAuthTokens("new", null, "new-user")

        assertEquals("new", auth.getAccessToken())
        assertNull(auth.getRefreshToken())
    }
}
