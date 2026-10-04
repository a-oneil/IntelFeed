package com.example.intelfeed

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Hub
import androidx.compose.material.icons.filled.RssFeed
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.DrawerValue
import androidx.compose.material3.Icon
import androidx.compose.material3.ModalNavigationDrawer
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.NavigationRailItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveableStateHolder
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.material3.rememberDrawerState
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalWindowInfo
import androidx.compose.ui.unit.dp
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.lifecycle.viewmodel.navigation3.rememberViewModelStoreNavEntryDecorator
import androidx.navigation3.runtime.NavEntry
import androidx.navigation3.runtime.rememberSaveableStateHolderNavEntryDecorator
import androidx.navigation3.ui.NavDisplay
import com.example.intelfeed.theme.CyberBlue
import com.example.intelfeed.theme.CyberPurple
import com.example.intelfeed.theme.SlateDark800
import com.example.intelfeed.theme.SlateDark900
import com.example.intelfeed.theme.TextMuted
import com.example.intelfeed.theme.TextPrimary
import com.example.intelfeed.ui.AppTab
import com.example.intelfeed.ui.i18n.AppStrings
import com.example.intelfeed.ui.i18n.LocalStrings
import com.example.intelfeed.ui.IntelFeedUiState
import com.example.intelfeed.ui.IntelFeedViewModel
import com.example.intelfeed.ui.entity.EntityViewModel
import com.example.intelfeed.ui.navigation.Route
import com.example.intelfeed.ui.reader.ReaderViewModel
import com.example.intelfeed.ui.screens.EntityProfileScreen
import com.example.intelfeed.ui.screens.EntryReaderScreen
import com.example.intelfeed.ui.screens.FeedDrawerSheet
import com.example.intelfeed.ui.screens.FeedScreen
import com.example.intelfeed.ui.screens.LoginScreen
import com.example.intelfeed.ui.screens.SearchScreen
import com.example.intelfeed.ui.screens.RequirementsScreen
import com.example.intelfeed.ui.screens.RequirementsViewModel
import com.example.intelfeed.ui.screens.SettingsScreen
import com.example.intelfeed.ui.screens.ThreadScreen
import com.example.intelfeed.ui.screens.WorkbenchScreen
import com.example.intelfeed.ui.thread.ThreadViewModel
import kotlinx.coroutines.launch

/** The app-wide snackbar host. Screens pass it to their Scaffold so messages appear above their bars. */
val LocalSnackbarHostState = staticCompositionLocalOf { SnackbarHostState() }

@Composable
fun MainNavigation(
    viewModel: IntelFeedViewModel,
    app: IntelFeedApplication,
    modifier: Modifier = Modifier
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()

    // Shows messages posted by any ViewModel. A new message replaces the current one.
    LaunchedEffect(Unit) {
        app.messenger.messages.collect { message ->
            scope.launch {
                snackbarHostState.currentSnackbarData?.dismiss()
                val result = snackbarHostState.showSnackbar(
                    message = message.text,
                    actionLabel = message.actionLabel,
                    withDismissAction = message.actionLabel != null,
                    duration = if (message.actionLabel != null) SnackbarDuration.Long else SnackbarDuration.Short
                )
                if (result == SnackbarResult.ActionPerformed) message.onAction?.invoke()
            }
        }
    }

    val intelNavigation = remember(viewModel) {
        com.example.intelfeed.ui.components.IntelNavigation(
            searchQuery = { query -> viewModel.searchQuery(query) },
            openRequirements = { viewModel.openRequirements() }
        )
    }
    CompositionLocalProvider(
        LocalSnackbarHostState provides snackbarHostState,
        com.example.intelfeed.ui.components.LocalIntelNavigation provides intelNavigation
    ) {
        when {
            // Blank until the stored session has been read, instead of flashing the login screen.
            !uiState.sessionChecked -> Box(modifier.fillMaxSize().background(SlateDark900))
            !uiState.isLoggedIn -> LoginScreen(
                uiState = uiState,
                onLogin = { serverUrl, username, password -> viewModel.login(serverUrl, username, password) }
            )
            else -> NavDisplay(
                backStack = viewModel.backStack,
                onBack = { viewModel.goBack() },
                modifier = modifier.fillMaxSize().background(SlateDark900),
                // Gives every back-stack entry its own saved state and ViewModelStore, so two open
                // articles (or profiles) each keep their own ViewModel.
                entryDecorators = listOf(
                    rememberSaveableStateHolderNavEntryDecorator(),
                    rememberViewModelStoreNavEntryDecorator()
                ),
                entryProvider = { route ->
                    when (route) {
                        Route.Home -> NavEntry(route) { HomeShell(viewModel, uiState) }
                        is Route.Reader -> NavEntry(route) {
                            // Next/previous walk the list the article was opened from; the feed list is
                            // read live so paging keeps it going.
                            val siblings = route.contextIds
                                ?: uiState.entries.filterNot { it.isThread }.map { it.id }
                            EntryReaderScreen(
                                app = app,
                                entryId = route.entryId,
                                siblingIds = siblings,
                                onBack = { viewModel.goBack() },
                                onNearListEnd = { viewModel.loadMoreEntries() },
                                onSettledEntry = { id -> viewModel.setFeedFocus(id) },
                                onSearchTag = { tag -> viewModel.searchTag(tag) },
                                onSearchKeyword = { keyword -> viewModel.searchKeyword(keyword) },
                                onSearchQuery = { query -> viewModel.searchQuery(query) },
                                onOpenEntry = { id -> viewModel.openEntry(id) },
                                onOpenEntity = { ref -> viewModel.openEntity(ref) },
                                onOpenThread = { slug, title -> viewModel.openThread(slug, title) }
                            )
                        }
                        is Route.Entity -> NavEntry(route) {
                            val entityVm = viewModel(key = "${route.type.key}:${route.idOrName}") {
                                EntityViewModel(route.type, route.idOrName, route.name, app.repository, app.messenger)
                            }
                            EntityProfileScreen(
                                viewModel = entityVm,
                                type = route.type,
                                fallbackTitle = route.name ?: route.idOrName,
                                onBack = { viewModel.goBack() },
                                onOpenEntry = { id, context -> viewModel.openEntry(id, context) },
                                onOpenEntity = { ref -> viewModel.openEntity(ref) },
                                onOpenThread = { slug, title -> viewModel.openThread(slug, title) }
                            )
                        }
                        is Route.Thread -> NavEntry(route) {
                            val threadVm = viewModel(key = route.slug) {
                                ThreadViewModel(route.slug, app.repository, app.messenger)
                            }
                            ThreadScreen(
                                viewModel = threadVm,
                                fallbackTitle = route.title,
                                onBack = { viewModel.goBack() },
                                onOpenEntry = { id, context -> viewModel.openEntry(id, context) },
                                onOpenEntity = { type, id, name -> viewModel.openEntity(type.key, id, name) },
                                onOpenThread = { slug, title -> viewModel.openThread(slug, title) }
                            )
                        }
                        Route.Requirements -> NavEntry(route) {
                            val requirementsVm = viewModel { RequirementsViewModel(app.repository) }
                            RequirementsScreen(
                                viewModel = requirementsVm,
                                trackedKeywords = uiState.trackedKeywords,
                                onBack = { viewModel.goBack() },
                                onOpenEntry = { id, context -> viewModel.openEntry(id, context) },
                                onSearchKeyword = { keyword -> viewModel.searchKeyword(keyword) }
                            )
                        }
                        Route.Settings -> NavEntry(route) {
                            SettingsScreen(
                                uiState = uiState,
                                repository = app.repository,
                                userPreferences = app.userPreferences,
                                onBack = { viewModel.goBack() },
                                onClearRecentSearches = { viewModel.clearRecentSearches() },
                                onLogout = {
                                    // Alerts name this account's articles; a tap after signing in
                                    // as someone else would open an article they may not have.
                                    androidx.core.app.NotificationManagerCompat.from(app).cancelAll()
                                    viewModel.logout()
                                }
                            )
                        }
                    }
                }
            )
        }
    }
}

/** The tabbed home screen: Feed, Workbench and Search share one bottom navigation bar (a side rail in landscape). */
@Composable
private fun HomeShell(viewModel: IntelFeedViewModel, uiState: IntelFeedUiState) {
    // The feeds drawer covers the whole screen, bottom bar included, so it lives here rather than
    // inside the Feed tab.
    val drawerState = rememberDrawerState(initialValue = DrawerValue.Closed)
    val scope = rememberCoroutineScope()
    val tabStates = rememberSaveableStateHolder()
    val closeDrawer: () -> Unit = { scope.launch { drawerState.close() } }

    BackHandler(enabled = drawerState.isOpen) { closeDrawer() }
    // Fresh unread counts for the drawer's views (skipped if they're under a minute old).
    LaunchedEffect(drawerState.isOpen) { if (drawerState.isOpen) viewModel.loadViewCounts() }
    // Back on Workbench/Search returns to the Feed; back while selecting clears the selection.
    BackHandler(enabled = !drawerState.isOpen && (uiState.currentTab != AppTab.FEED || uiState.isSelecting)) { viewModel.goBack() }

    ModalNavigationDrawer(
        drawerState = drawerState,
        gesturesEnabled = uiState.currentTab == AppTab.FEED && !uiState.isSelecting,
        drawerContent = {
            FeedDrawerSheet(
                uiState = uiState,
                onFilterSelect = { viewModel.setFilter(it); closeDrawer() },
                onCategorySelect = { id, name -> viewModel.selectCategory(id, name); closeDrawer() },
                onFeedSelect = { id, title -> viewModel.selectFeed(id, title); closeDrawer() },
                onOpenSettings = { closeDrawer(); viewModel.navigate(Route.Settings) },
                onRetry = { viewModel.loadCategoriesAndFeeds() },
                onOpenSavedSearch = { saved -> closeDrawer(); viewModel.openSavedSearch(saved) },
                onDeleteSavedSearch = { saved -> viewModel.deleteSavedSearch(saved) },
                onKeywordSearch = { keyword -> closeDrawer(); viewModel.searchKeyword(keyword) },
                onAddKeyword = { keyword, alsoOnServer -> viewModel.addKeyword(keyword, alsoOnServer) },
                onRemoveKeyword = { viewModel.removeKeyword(it) },
                onOpenRequirements = { closeDrawer(); viewModel.openRequirements() },
                onDiscoverFeeds = { url, onResult -> viewModel.discoverFeeds(url, onResult) },
                onSubscribe = { feed, catId, interval -> viewModel.subscribeToFeed(feed, catId, interval); closeDrawer() },
                onAddArticle = { url -> viewModel.ingestSharedUrl(url); closeDrawer() }
            )
        }
    ) {
    // A phone in landscape is only ~400 dp tall: the bottom bar plus each tab's top bar and chips
    // left about a sixth of the screen for the list. Short windows get a side rail instead.
    val shortWindow = isShortWindow()
    val showRail = shortWindow && !uiState.isSelecting
    val railInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Vertical + WindowInsetsSides.Start)
    val strings = LocalStrings.current
    Row(Modifier.fillMaxSize().background(SlateDark900)) {
    if (showRail) {
        NavigationRail(containerColor = SlateDark900, contentColor = TextPrimary, windowInsets = railInsets) {
            Spacer(Modifier.weight(1f))
            AppTab.entries.forEach { tab ->
                val (label, icon, accent) = tab.presentation(strings)
                NavigationRailItem(
                    selected = uiState.currentTab == tab,
                    onClick = { viewModel.setAppTab(tab) },
                    icon = { Icon(icon, contentDescription = null) },
                    label = { Text(label) },
                    colors = NavigationRailItemDefaults.colors(
                        selectedIconColor = accent,
                        selectedTextColor = accent,
                        unselectedIconColor = TextMuted,
                        unselectedTextColor = TextMuted,
                        indicatorColor = SlateDark800
                    )
                )
            }
            Spacer(Modifier.weight(1f))
        }
    }
    Scaffold(
        // The rail already covers the start-side insets (e.g. a camera cutout in landscape).
        modifier = Modifier.weight(1f).then(
            if (showRail) Modifier.consumeWindowInsets(WindowInsets.safeDrawing.only(WindowInsetsSides.Start)) else Modifier
        ),
        bottomBar = {
            if (!uiState.isSelecting && !shortWindow) {
                NavigationBar(containerColor = SlateDark900, contentColor = TextPrimary) {
                    AppTab.entries.forEach { tab ->
                        val (label, icon, accent) = tab.presentation(strings)
                        TabItem(uiState.currentTab == tab, label, icon, accent) { viewModel.setAppTab(tab) }
                    }
                }
            }
        },
        snackbarHost = { SnackbarHost(LocalSnackbarHostState.current) },
        containerColor = SlateDark900
    ) { innerPadding ->
        // Each tab has its own Scaffold. Apply and consume this one's padding so tab content ends
        // above the bottom bar instead of underneath it.
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .consumeWindowInsets(innerPadding)
        ) {
            // Each tab keeps its own saved state (scroll positions, open dialogs) while another tab
            // is shown; switching Feed → Search → Feed used to start the feed at the top again.
            tabStates.SaveableStateProvider(uiState.currentTab.name) {
                when (uiState.currentTab) {
                    AppTab.FEED -> FeedScreen(uiState = uiState, viewModel = viewModel, onOpenDrawer = { scope.launch { drawerState.open() } })
                    AppTab.WORKBENCH -> WorkbenchScreen(uiState = uiState, viewModel = viewModel)
                    AppTab.SEARCH -> SearchScreen(uiState = uiState, viewModel = viewModel)
                }
            }
        }
    }
    }
    }
}

/** Label, icon and accent colour for a home tab, shared by the bottom bar and the side rail. */
private fun AppTab.presentation(strings: AppStrings): Triple<String, ImageVector, androidx.compose.ui.graphics.Color> = when (this) {
    AppTab.FEED -> Triple(strings.navFeed, Icons.Default.RssFeed, CyberBlue)
    AppTab.WORKBENCH -> Triple(strings.navWorkbench, Icons.Default.Hub, CyberPurple)
    AppTab.SEARCH -> Triple(strings.navSearch, Icons.Default.Search, CyberBlue)
}

/** True when the window is under 480 dp tall (Material's compact height), e.g. a phone in landscape. */
@Composable
private fun isShortWindow(): Boolean {
    val heightPx = LocalWindowInfo.current.containerSize.height
    return heightPx > 0 && with(LocalDensity.current) { heightPx.toDp() } < 480.dp
}

@Composable
private fun androidx.compose.foundation.layout.RowScope.TabItem(
    selected: Boolean,
    label: String,
    icon: ImageVector,
    accent: androidx.compose.ui.graphics.Color,
    onClick: () -> Unit
) {
    NavigationBarItem(
        selected = selected,
        onClick = onClick,
        icon = { Icon(icon, contentDescription = null) },
        label = { Text(label) },
        colors = NavigationBarItemDefaults.colors(
            selectedIconColor = accent,
            selectedTextColor = accent,
            unselectedIconColor = TextMuted,
            unselectedTextColor = TextMuted,
            indicatorColor = SlateDark800
        )
    )
}
