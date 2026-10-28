package com.example.intelfeed

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.createSavedStateHandle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.intelfeed.data.model.EntityType
import com.example.intelfeed.notifications.IntelNotificationHelper
import com.example.intelfeed.theme.IntelFeedTheme
import com.example.intelfeed.ui.IntelFeedViewModel
import com.example.intelfeed.ui.entity.EntityRef
import com.example.intelfeed.util.InAppLinks
import com.example.intelfeed.util.ShareIntentSanitizer

class MainActivity : ComponentActivity() {

    // A web link shared to IntelFeed from another app, waiting for the user to confirm adding it.
    private var pendingSharedUrl by mutableStateOf<String?>(null)

    // Where a tapped notification should go, handled once the session is ready. Set from onCreate
    // (app started by the tap) and onNewIntent (app already open: the tap used to do nothing).
    private var pendingRoute by mutableStateOf<IntelNotificationHelper.Route?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Not after a configuration change or process restore: the same tap would be handled again.
        // A link still waiting for "Add article" comes back from the saved state instead (rotating
        // the screen used to dismiss the dialog and lose the link).
        if (savedInstanceState == null) {
            handleShareIntent(intent)
        } else {
            pendingSharedUrl = savedInstanceState.getString(STATE_SHARED_URL)
        }
        takeNotificationRoute()

        val app = application as IntelFeedApplication
        enableEdgeToEdge()
        setContent {
            val viewModel: IntelFeedViewModel = viewModel {
                IntelFeedViewModel(app.repository, app.userPreferences, app.messenger, createSavedStateHandle())
            }
            val uiState by viewModel.uiState.collectAsStateWithLifecycle()
            val appLanguage by app.userPreferences.appLanguage.collectAsStateWithLifecycle(initialValue = "system")
            val currentStrings = androidx.compose.runtime.remember(appLanguage) {
                com.example.intelfeed.ui.i18n.AppStrings.forLanguage(appLanguage)
            }

            val route = pendingRoute
            LaunchedEffect(route, uiState.isLoggedIn) {
                if (route != null && uiState.isLoggedIn) {
                    pendingRoute = null
                    if (app.pendingNotificationRoute === route) app.pendingNotificationRoute = null
                    when (route) {
                        is IntelNotificationHelper.Route.Entry -> viewModel.openEntry(route.id)
                        is IntelNotificationHelper.Route.Thread -> viewModel.openThread(route.slug, route.title)
                        is IntelNotificationHelper.Route.Campaign -> viewModel.openEntity(EntityRef(EntityType.CAMPAIGN, route.id, route.name ?: "Campaign"))
                    }
                }
            }

            IntelFeedTheme {
                androidx.compose.runtime.CompositionLocalProvider(com.example.intelfeed.ui.i18n.LocalStrings provides currentStrings) {
                    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                        MainNavigation(viewModel = viewModel, app = app)

                    val sharedUrl = pendingSharedUrl
                    // A link to an article on the signed-in IntelFeed server (…/?entry=<id>) opens
                    // that article instead of offering to add the page as a new one.
                    val sharedEntryId = sharedUrl?.let { InAppLinks.entryId(it, uiState.serverUrl) }
                    LaunchedEffect(sharedEntryId, uiState.isLoggedIn) {
                        if (sharedEntryId != null && uiState.isLoggedIn) {
                            pendingSharedUrl = null
                            viewModel.openEntry(sharedEntryId)
                        }
                    }
                    if (sharedUrl != null && sharedEntryId == null && uiState.isLoggedIn) {
                        AlertDialog(
                            onDismissRequest = { pendingSharedUrl = null },
                            title = { Text("Add to IntelFeed?") },
                            text = { Text("IntelFeed will fetch this page, add it as an article and run its intelligence extraction.\n\n$sharedUrl") },
                            confirmButton = {
                                TextButton(onClick = {
                                    pendingSharedUrl = null
                                    viewModel.ingestSharedUrl(sharedUrl)
                                }) { Text("Add article") }
                            },
                            dismissButton = { TextButton(onClick = { pendingSharedUrl = null }) { Text("Cancel") } }
                        )
                    }
                }
                }
            }
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        pendingSharedUrl?.let { outState.putString(STATE_SHARED_URL, it) }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleShareIntent(intent)
        takeNotificationRoute()
    }

    // The route stays in the application until it's handled, so a tap waiting for sign-in survives
    // the activity being re-created (e.g. rotating the sign-in screen).
    private fun takeNotificationRoute() {
        val app = application as IntelFeedApplication
        app.pendingNotificationRoute?.let { pendingRoute = it }
    }

    /** Picks the first safe http(s) link out of text shared from another app (browsers often add a title). */
    private fun handleShareIntent(intent: Intent?) {
        val safeUrl = ShareIntentSanitizer.extractSafeUrl(intent)
        if (safeUrl != null) {
            pendingSharedUrl = safeUrl
        }
        // Consume share extras so configuration changes or activity replays don't re-trigger
        intent?.removeExtra(Intent.EXTRA_TEXT)
        intent?.removeExtra(Intent.EXTRA_STREAM)
    }

    private companion object {
        // The shared link (already validated by ShareIntentSanitizer) waiting for confirmation.
        const val STATE_SHARED_URL = "pending_shared_url"
    }
}
