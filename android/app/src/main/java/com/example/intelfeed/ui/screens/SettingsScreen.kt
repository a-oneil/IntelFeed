package com.example.intelfeed.ui.screens

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Logout
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.automirrored.filled.VolumeUp
import androidx.compose.material.icons.filled.AccountCircle
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.DeleteOutline
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material.icons.filled.SystemUpdate
import androidx.compose.material.icons.filled.Tag
import androidx.compose.material.icons.filled.Translate
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.filled.Palette
import com.example.intelfeed.data.model.ThemeDto
import com.example.intelfeed.theme.SlateDark700
import com.example.intelfeed.theme.ThemeEngine
import com.example.intelfeed.ui.i18n.AppLanguage
import com.example.intelfeed.ui.i18n.LocalStrings
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Slider
import androidx.compose.material3.SliderDefaults
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarResult
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.core.content.ContextCompat
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.intelfeed.BuildConfig
import com.example.intelfeed.LocalSnackbarHostState
import com.example.intelfeed.data.local.UserPreferences
import com.example.intelfeed.data.model.TagEntity
import com.example.intelfeed.data.repository.IntelFeedRepository
import com.example.intelfeed.notifications.AppUpdates
import com.example.intelfeed.notifications.IntelNotificationHelper
import com.example.intelfeed.notifications.PriorityAlerts
import com.example.intelfeed.theme.CyberAmber
import com.example.intelfeed.theme.CyberBlue
import com.example.intelfeed.theme.CyberPurple
import com.example.intelfeed.theme.CyberRed
import com.example.intelfeed.theme.SlateDark600
import com.example.intelfeed.theme.SlateDark800
import com.example.intelfeed.theme.SlateDark900
import com.example.intelfeed.theme.TextMuted
import com.example.intelfeed.theme.TextPrimary
import com.example.intelfeed.theme.TextSecondary
import com.example.intelfeed.ui.IntelFeedUiState
import com.example.intelfeed.ui.components.CardSurface
import com.example.intelfeed.ui.components.Pill
import com.example.intelfeed.ui.components.SectionHeader
import com.example.intelfeed.ui.components.tagColor
import com.example.intelfeed.ui.reader.ReaderFontSize
import com.example.intelfeed.ui.reader.VoiceSettingsDialog
import com.example.intelfeed.util.ArticleTranslator
import com.example.intelfeed.util.ExternalLinks
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    uiState: IntelFeedUiState,
    repository: IntelFeedRepository? = null,
    userPreferences: UserPreferences,
    onBack: () -> Unit,
    onClearRecentSearches: () -> Unit,
    onSelectTheme: (ThemeDto) -> Unit = {},
    onUseDefaultTheme: () -> Unit = {},
    onRefreshThemes: () -> Unit = {},
    onLogout: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val strings = LocalStrings.current
    val textSizeName by userPreferences.readerTextSize.collectAsStateWithLifecycle(initialValue = null)
    val textSize = ReaderFontSize.fromName(textSizeName)
    val notificationsEnabled by userPreferences.notificationsEnabled.collectAsStateWithLifecycle(initialValue = true)
    val priorityAlertScore by userPreferences.priorityAlertScore.collectAsStateWithLifecycle(initialValue = PriorityAlerts.DEFAULT_CUTOFF)
    val updateNoticesEnabled by userPreferences.updateNoticesEnabled.collectAsStateWithLifecycle(initialValue = true)
    var checkingForUpdate by remember { mutableStateOf(false) }
    val snackbarHostState = LocalSnackbarHostState.current
    val speechRate by userPreferences.ttsSpeechRate.collectAsStateWithLifecycle(initialValue = 1.0f)
    var confirmLogout by remember { mutableStateOf(false) }
    var showTagManager by remember { mutableStateOf(false) }
    var showLanguagePicker by remember { mutableStateOf(false) }
    var showAppLanguagePicker by remember { mutableStateOf(false) }
    var showThemePicker by remember { mutableStateOf(false) }
    var showVoiceSettings by remember { mutableStateOf(false) }

    // Whether Android lets the app post notifications at all (Android 13+ permission and the app's
    // system switch). Re-read when the screen resumes, since both can change in system settings.
    var systemAllowsAlerts by remember { mutableStateOf(IntelNotificationHelper.canPostNotifications(context)) }
    LifecycleResumeEffect(Unit) {
        systemAllowsAlerts = IntelNotificationHelper.canPostNotifications(context)
        onPauseOrDispose { }
    }
    var sendTestAfterGrant by remember { mutableStateOf(false) }
    // The permission prompt was opened by the update-notices switch, not the intel alerts one.
    var updatesAfterGrant by remember { mutableStateOf(false) }

    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        systemAllowsAlerts = IntelNotificationHelper.canPostNotifications(context)
        val sendTest = sendTestAfterGrant
        sendTestAfterGrant = false
        val forUpdates = updatesAfterGrant
        updatesAfterGrant = false
        scope.launch {
            if (forUpdates) userPreferences.setUpdateNoticesEnabled(isGranted)
            else userPreferences.setNotificationsEnabled(isGranted)
            when {
                !isGranted -> snackbarHostState.showSnackbar("Notifications aren't allowed. You can allow them in Android's app settings.")
                sendTest -> {
                    IntelNotificationHelper.sendTestNotification(context)
                    snackbarHostState.showSnackbar("Test alert sent to the status bar")
                }
            }
        }
    }
    val needsPermission = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
        ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
    val alertsOn = notificationsEnabled && systemAllowsAlerts
    val setAlerts: (Boolean) -> Unit = { next ->
        if (next && needsPermission) permissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        else scope.launch { userPreferences.setNotificationsEnabled(next) }
    }
    val updateNoticesOn = updateNoticesEnabled && systemAllowsAlerts
    val setUpdateNotices: (Boolean) -> Unit = { next ->
        if (next && needsPermission) {
            updatesAfterGrant = true
            permissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else scope.launch { userPreferences.setUpdateNoticesEnabled(next) }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back", tint = TextPrimary) } },
                title = { Text(strings.settingsTitle, fontWeight = FontWeight.Bold, color = TextPrimary) },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = SlateDark900)
            )
        },
        snackbarHost = { SnackbarHost(LocalSnackbarHostState.current) },
        containerColor = SlateDark900
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp)
        ) {
            SectionHeader(strings.settingsAccount)
            CardSurface {
                Column(Modifier.padding(16.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.AccountCircle, contentDescription = null, tint = CyberBlue, modifier = Modifier.size(40.dp))
                        Spacer(Modifier.width(12.dp))
                        Column {
                            Text(uiState.currentUser?.username ?: uiState.username ?: "Signed in", fontSize = 17.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
                            uiState.currentUser?.role?.let { Text(it.replaceFirstChar { c -> c.uppercase() }, fontSize = 13.sp, color = TextMuted) }
                        }
                    }
                    Spacer(Modifier.height(12.dp))
                    Text(strings.settingsServer, fontSize = 12.sp, color = TextMuted)
                    Text(uiState.serverUrl, fontSize = 14.sp, color = TextSecondary)
                }
            }
            SettingsRow(
                icon = Icons.AutoMirrored.Filled.OpenInNew,
                title = strings.settingsOpenWeb,
                subtitle = "Admin settings, feeds, automation and reports live in the web app.",
                onClick = { ExternalLinks.openInBrowser(context, uiState.serverUrl) }
            )

            SectionHeader(strings.settingsReading)

            val themeSubtitle = if (uiState.activeThemeSource == "default") {
                "${uiState.activeThemeName} (Instance default)"
            } else {
                uiState.activeThemeName
            }
            SettingsRow(
                icon = Icons.Default.Palette,
                title = "Theme",
                subtitle = themeSubtitle,
                onClick = {
                    onRefreshThemes()
                    showThemePicker = true
                },
                tint = CyberBlue
            )

            val appLangCode by userPreferences.appLanguage.collectAsStateWithLifecycle(initialValue = "system")
            val appLang = remember(appLangCode) { AppLanguage.fromCode(appLangCode) }
            SettingsRow(
                icon = Icons.Default.Language,
                title = strings.settingsAppLanguage,
                subtitle = appLang.getEffectiveName(),
                onClick = { showAppLanguagePicker = true },
                tint = CyberPurple
            )


            val autoMarkRead by userPreferences.autoMarkRead.collectAsStateWithLifecycle(initialValue = true)
            val feedDensity by userPreferences.feedDensity.collectAsStateWithLifecycle(initialValue = "expanded")
            val feedLayout by userPreferences.feedLayout.collectAsStateWithLifecycle(initialValue = "list")

            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { scope.launch { userPreferences.setAutoMarkRead(!autoMarkRead) } }
                    .padding(vertical = 10.dp)
            ) {
                Column(Modifier.weight(1f)) {
                    Text(strings.settingsAutoMarkRead, fontSize = 15.sp, color = TextPrimary)
                    Text(strings.settingsAutoMarkReadSub, fontSize = 12.sp, color = TextMuted)
                }
                Switch(
                    checked = autoMarkRead,
                    onCheckedChange = { scope.launch { userPreferences.setAutoMarkRead(it) } }
                )
            }

            val feedAutoRead by userPreferences.feedAutoRead.collectAsStateWithLifecycle(initialValue = false)
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { scope.launch { userPreferences.setFeedAutoRead(!feedAutoRead) } }
                    .padding(vertical = 10.dp)
            ) {
                Column(Modifier.weight(1f)) {
                    Text(strings.settingsAutoReadScroll, fontSize = 15.sp, color = TextPrimary)
                    Text(strings.settingsAutoReadScrollSub, fontSize = 12.sp, color = TextMuted)
                }
                Switch(
                    checked = feedAutoRead,
                    onCheckedChange = { scope.launch { userPreferences.setFeedAutoRead(it) } }
                )
            }

            val highlightEntities by userPreferences.highlightEntities.collectAsStateWithLifecycle(initialValue = true)
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { scope.launch { userPreferences.setHighlightEntities(!highlightEntities) } }
                    .padding(vertical = 10.dp)
            ) {
                Column(Modifier.weight(1f)) {
                    Text(strings.settingsHighlightEntities, fontSize = 15.sp, color = TextPrimary)
                    Text(strings.settingsHighlightEntitiesSub, fontSize = 12.sp, color = TextMuted)
                }
                Switch(checked = highlightEntities, onCheckedChange = { scope.launch { userPreferences.setHighlightEntities(it) } })
            }

            val targetLangCode by userPreferences.translateTargetLanguage.collectAsStateWithLifecycle(initialValue = UserPreferences.defaultTranslateLanguage())
            val targetLangName = remember(targetLangCode) { ArticleTranslator.languageDisplayName(targetLangCode) }
            SettingsRow(
                icon = Icons.Default.Translate,
                title = strings.settingsTranslationTarget,
                subtitle = "Translate articles into $targetLangName",
                onClick = { showLanguagePicker = true },
                tint = CyberBlue
            )

            val autoTranslate by userPreferences.autoTranslate.collectAsStateWithLifecycle(initialValue = false)
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { scope.launch { userPreferences.setAutoTranslate(!autoTranslate) } }
                    .padding(vertical = 10.dp)
            ) {
                Column(Modifier.weight(1f)) {
                    Text(strings.settingsAutoTranslate, fontSize = 15.sp, color = TextPrimary)
                    Text("Automatically translate foreign articles into $targetLangName on-device using ML Kit", fontSize = 12.sp, color = TextMuted)
                }
                Switch(
                    checked = autoTranslate,
                    onCheckedChange = { scope.launch { userPreferences.setAutoTranslate(it) } }
                )
            }

            SettingsRow(
                icon = Icons.AutoMirrored.Filled.VolumeUp,
                title = "Read aloud voice & speed",
                subtitle = "${speechRate}x speed · High-definition neural voices",
                onClick = { showVoiceSettings = true },
                tint = CyberBlue
            )

            Spacer(Modifier.height(8.dp))
            Text("Feed layout", fontSize = 14.sp, color = TextSecondary)
            listOf("list" to "List (standard vertical stream)", "grid" to "Grid (multi-column magazine cards)").forEach { (key, label) ->
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .fillMaxWidth()
                        .selectable(
                            selected = feedLayout == key,
                            role = Role.RadioButton,
                            onClick = { scope.launch { userPreferences.setFeedLayout(key) } }
                        )
                        .padding(vertical = 6.dp)
                ) {
                    RadioButton(selected = feedLayout == key, onClick = null)
                    Spacer(Modifier.width(12.dp))
                    Text(label, fontSize = 14.sp, color = TextPrimary)
                }
            }

            Spacer(Modifier.height(8.dp))
            Text("Feed card density", fontSize = 14.sp, color = TextSecondary)
            listOf("expanded" to "Expanded (with snippet preview)", "compact" to "Compact (high density, title only)").forEach { (key, label) ->
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .fillMaxWidth()
                        .selectable(
                            selected = feedDensity == key,
                            role = Role.RadioButton,
                            onClick = { scope.launch { userPreferences.setFeedDensity(key) } }
                        )
                        .padding(vertical = 6.dp)
                ) {
                    RadioButton(selected = feedDensity == key, onClick = null)
                    Spacer(Modifier.width(12.dp))
                    Text(label, fontSize = 14.sp, color = TextPrimary)
                }
            }

            Spacer(Modifier.height(8.dp))
            Text("Article text size", fontSize = 14.sp, color = TextSecondary)
            ReaderFontSize.entries.forEach { size ->
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .fillMaxWidth()
                        .selectable(
                            selected = size == textSize,
                            role = Role.RadioButton,
                            onClick = { scope.launch { userPreferences.setReaderTextSize(size.name) } }
                        )
                        .padding(vertical = 6.dp)
                ) {
                    RadioButton(selected = size == textSize, onClick = null)
                    Spacer(Modifier.width(12.dp))
                    Text(size.label, fontSize = size.size, color = TextPrimary)
                }
            }

            SectionHeader("Notifications & Alerts")
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { setAlerts(!alertsOn) }
                    .padding(vertical = 10.dp)
            ) {
                Column(Modifier.weight(1f)) {
                    Text("Background Intel Alerts", fontSize = 15.sp, color = TextPrimary)
                    Text(
                        when {
                            notificationsEnabled && !systemAllowsAlerts -> "Android isn't allowing IntelFeed notifications. Turn this on to allow them."
                            else -> "Checks every 15 minutes for new articles in your campaigns and saved searches, and for priority intel scoring ${formatCutoff(priorityAlertScore)} or higher"
                        },
                        fontSize = 12.sp,
                        color = if (notificationsEnabled && !systemAllowsAlerts) CyberAmber else TextMuted
                    )
                }
                Switch(checked = alertsOn, onCheckedChange = setAlerts)
            }

            // Saved when the drag ends, not on every step it passes.
            var cutoffDraft by remember(priorityAlertScore) { mutableStateOf(priorityAlertScore.toFloat()) }
            Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Priority alert score", fontSize = 15.sp, color = if (alertsOn) TextPrimary else TextMuted, modifier = Modifier.weight(1f))
                    Text(formatCutoff(cutoffDraft.toDouble()), fontSize = 15.sp, color = if (alertsOn) CyberPurple else TextMuted)
                }
                Text(
                    "Unread Priority Queue items scoring at least this notify you, once each. A story alerts once, however much it grows. Lowering it doesn't alert on items already waiting.",
                    fontSize = 12.sp,
                    color = TextMuted
                )
                Slider(
                    value = cutoffDraft,
                    onValueChange = { cutoffDraft = it },
                    onValueChangeFinished = { scope.launch { userPreferences.setPriorityAlertScore(cutoffDraft.toDouble()) } },
                    valueRange = PriorityAlerts.MIN_CUTOFF.toFloat()..PriorityAlerts.MAX_CUTOFF.toFloat(),
                    steps = ((PriorityAlerts.MAX_CUTOFF - PriorityAlerts.MIN_CUTOFF) / PriorityAlerts.CUTOFF_STEP).toInt() - 1,
                    enabled = alertsOn,
                    colors = SliderDefaults.colors(thumbColor = CyberPurple, activeTrackColor = CyberPurple)
                )
            }

            SettingsRow(
                icon = Icons.Default.Notifications,
                title = "Send test notification",
                subtitle = "Check that alerts appear in the status bar",
                tint = CyberPurple,
                onClick = {
                    when {
                        needsPermission -> {
                            sendTestAfterGrant = true
                            permissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                        }
                        !systemAllowsAlerts -> scope.launch { snackbarHostState.showSnackbar("Notifications are turned off for IntelFeed in Android's settings.") }
                        else -> {
                            IntelNotificationHelper.sendTestNotification(context)
                            scope.launch { snackbarHostState.showSnackbar("Test alert sent to the status bar") }
                        }
                    }
                }
            )

            SettingsRow(
                icon = Icons.Default.Sync,
                title = "Check for new intel now",
                subtitle = "Run the background alert check for tracked intelligence right away",
                onClick = {
                    IntelNotificationHelper.triggerImmediateSync(context)
                    scope.launch { snackbarHostState.showSnackbar("Background sync triggered") }
                }
            )

            SectionHeader("Search")
            SettingsRow(
                icon = Icons.Default.History,
                title = "Clear recent searches",
                subtitle = if (uiState.recentSearches.isEmpty()) "Nothing to clear" else "${uiState.recentSearches.size} saved on this device",
                onClick = onClearRecentSearches
            )

            if (repository != null) {
                SectionHeader("Tags")
                SettingsRow(
                    icon = Icons.Default.Tag,
                    title = "Manage server tags",
                    subtitle = "View and delete tags across your instance",
                    onClick = { showTagManager = true }
                )
            }

            SectionHeader("App updates")
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { setUpdateNotices(!updateNoticesOn) }
                    .padding(vertical = 10.dp)
            ) {
                Column(Modifier.weight(1f)) {
                    Text("New version notices", fontSize = 15.sp, color = TextPrimary)
                    Text(
                        if (updateNoticesEnabled && !systemAllowsAlerts) "Android isn't allowing IntelFeed notifications. Turn this on to allow them."
                        else "Once a day, notifies you when a new release of the app is out",
                        fontSize = 12.sp,
                        color = if (updateNoticesEnabled && !systemAllowsAlerts) CyberAmber else TextMuted
                    )
                }
                Switch(checked = updateNoticesOn, onCheckedChange = setUpdateNotices)
            }
            SettingsRow(
                icon = Icons.Default.SystemUpdate,
                title = "Check for an app update",
                subtitle = if (checkingForUpdate) "Checking…" else "You have ${BuildConfig.VERSION_NAME} (build ${BuildConfig.VERSION_CODE})",
                onClick = {
                    if (checkingForUpdate) return@SettingsRow
                    checkingForUpdate = true
                    scope.launch {
                        val release = AppUpdates.fetchLatest()
                        checkingForUpdate = false
                        when {
                            release == null -> snackbarHostState.showSnackbar("Couldn't check GitHub for releases.")
                            AppUpdates.isNewer(release, BuildConfig.VERSION_NAME, BuildConfig.VERSION_CODE) -> {
                                val url = release.url
                                val result = snackbarHostState.showSnackbar(
                                    "IntelFeed ${release.versionName} is available",
                                    actionLabel = if (url != null) "Open" else null,
                                    withDismissAction = true
                                )
                                if (result == SnackbarResult.ActionPerformed) ExternalLinks.openInBrowser(context, url)
                            }
                            else -> snackbarHostState.showSnackbar("You have the newest version.")
                        }
                    }
                }
            )

            HorizontalDivider(color = SlateDark600, modifier = Modifier.padding(vertical = 16.dp))
            SettingsRow(
                icon = Icons.AutoMirrored.Filled.Logout,
                title = "Sign out",
                subtitle = "Removes your session from this device and the server.",
                tint = CyberRed,
                onClick = { confirmLogout = true }
            )
            Spacer(Modifier.height(24.dp))
            Text("IntelFeed for Android ${BuildConfig.VERSION_NAME} (build ${BuildConfig.VERSION_CODE})", fontSize = 12.sp, color = TextMuted)
            Spacer(Modifier.height(32.dp))
        }
    }

    if (confirmLogout) {
        AlertDialog(
            onDismissRequest = { confirmLogout = false },
            title = { Text("Sign out?") },
            text = { Text("You'll need your password to sign in again.") },
            confirmButton = { TextButton(onClick = { confirmLogout = false; onLogout() }) { Text("Sign out", color = CyberRed) } },
            dismissButton = { TextButton(onClick = { confirmLogout = false }) { Text("Cancel") } }
        )
    }

    if (showTagManager && repository != null) {
        TagManagerSheet(
            repository = repository,
            onDismiss = { showTagManager = false }
        )
    }

    if (showLanguagePicker) {
        val currentTargetCode by userPreferences.translateTargetLanguage.collectAsStateWithLifecycle(initialValue = UserPreferences.defaultTranslateLanguage())
        LanguagePickerSheet(
            selectedCode = currentTargetCode,
            onSelect = { code ->
                scope.launch { userPreferences.setTranslateTargetLanguage(code) }
            },
            onDismiss = { showLanguagePicker = false }
        )
    }

    if (showAppLanguagePicker) {
        val currentAppLangCode by userPreferences.appLanguage.collectAsStateWithLifecycle(initialValue = "system")
        AppLanguagePickerSheet(
            selectedCode = currentAppLangCode,
            onSelect = { code ->
                scope.launch { userPreferences.setAppLanguage(code) }
                showAppLanguagePicker = false
            },
            onDismiss = { showAppLanguagePicker = false }
        )
    }

    if (showThemePicker) {
        ThemePickerSheet(
            themes = uiState.availableThemes,
            activeThemeId = uiState.activeThemeId,
            activeThemeSource = uiState.activeThemeSource,
            userThemeId = uiState.currentUser?.themeId,
            onSelectTheme = { theme ->
                onSelectTheme(theme)
                showThemePicker = false
            },
            onUseDefaultTheme = {
                onUseDefaultTheme()
                showThemePicker = false
            },
            onDismiss = { showThemePicker = false }
        )
    }

    if (showVoiceSettings) {
        VoiceSettingsDialog(
            currentRate = speechRate,
            onSelectRate = { scope.launch { userPreferences.setTtsSpeechRate(it) } },
            onDismiss = { showVoiceSettings = false }
        )
    }
}


@Composable
private fun SettingsRow(icon: ImageVector, title: String, subtitle: String?, onClick: () -> Unit, tint: androidx.compose.ui.graphics.Color = TextSecondary) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick).padding(vertical = 14.dp)
    ) {
        Icon(icon, contentDescription = null, tint = tint, modifier = Modifier.size(22.dp))
        Spacer(Modifier.width(16.dp))
        Column {
            Text(title, fontSize = 15.sp, color = if (tint == CyberRed) CyberRed else TextPrimary)
            subtitle?.let { Text(it, fontSize = 12.sp, color = TextMuted) }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun TagManagerSheet(
    repository: IntelFeedRepository,
    onDismiss: () -> Unit
) {
    val scope = rememberCoroutineScope()
    var tags by remember { mutableStateOf<List<TagEntity>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }
    var error by remember { mutableStateOf<String?>(null) }
    var searchQuery by remember { mutableStateOf("") }
    var tagToDelete by remember { mutableStateOf<TagEntity?>(null) }
    var isDeleting by remember { mutableStateOf(false) }

    fun refreshTags() {
        loading = true
        error = null
        scope.launch {
            repository.getTags().fold(
                onSuccess = { list ->
                    tags = list.sortedBy { it.name.lowercase() }
                    loading = false
                },
                onFailure = { err ->
                    error = err.message ?: "Failed to load tags"
                    loading = false
                }
            )
        }
    }

    LaunchedEffect(Unit) {
        refreshTags()
    }

    val filtered = remember(tags, searchQuery) {
        if (searchQuery.isBlank()) tags
        else tags.filter { it.name.contains(searchQuery.trim(), ignoreCase = true) }
    }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        containerColor = SlateDark800
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp)
                .imePadding()
                .navigationBarsPadding()
                .padding(bottom = 16.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(Modifier.weight(1f)) {
                    Text("Manage Server Tags", fontSize = 18.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
                    Text("Tags are shared across all articles on your server", fontSize = 12.sp, color = TextMuted)
                }
                IconButton(onClick = onDismiss) {
                    Icon(Icons.Default.Close, contentDescription = "Close", tint = TextSecondary)
                }
            }
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                placeholder = { Text("Filter tags…", color = TextMuted) },
                singleLine = true,
                leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = TextMuted) },
                trailingIcon = if (searchQuery.isNotEmpty()) {
                    { IconButton(onClick = { searchQuery = "" }) { Icon(Icons.Default.Close, contentDescription = "Clear") } }
                } else null,
                colors = OutlinedTextFieldDefaults.colors(
                    focusedTextColor = TextPrimary,
                    unfocusedTextColor = TextPrimary,
                    focusedBorderColor = CyberBlue
                ),
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(12.dp))

            when {
                loading -> {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(200.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        CircularProgressIndicator(color = CyberBlue)
                    }
                }
                error != null -> {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 32.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text(error ?: "Error loading tags", color = CyberRed, fontSize = 14.sp)
                        Spacer(Modifier.height(8.dp))
                        TextButton(onClick = { refreshTags() }) {
                            Text("Retry", color = CyberBlue)
                        }
                    }
                }
                tags.isEmpty() -> {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 32.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text("No tags found on the server", color = TextMuted, fontSize = 14.sp)
                    }
                }
                filtered.isEmpty() -> {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 32.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text("No tags match \"$searchQuery\"", color = TextMuted, fontSize = 14.sp)
                    }
                }
                else -> {
                    LazyColumn(
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(max = 400.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        items(filtered, key = { it.id ?: it.name }) { tag ->
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 6.dp)
                            ) {
                                Pill(
                                    label = "#${tag.name}",
                                    color = tagColor(tag.color)
                                )
                                Spacer(Modifier.width(10.dp))
                                val count = tag.entryCount ?: 0
                                Text(
                                    text = if (count == 1) "1 article" else "$count articles",
                                    fontSize = 13.sp,
                                    color = TextMuted,
                                    modifier = Modifier.weight(1f)
                                )
                                IconButton(
                                    onClick = { tagToDelete = tag },
                                    enabled = !isDeleting && tag.id != null
                                ) {
                                    Icon(
                                        Icons.Default.DeleteOutline,
                                        contentDescription = "Delete tag",
                                        tint = CyberRed
                                    )
                                }
                            }
                            HorizontalDivider(color = SlateDark600.copy(alpha = 0.5f))
                        }
                    }
                }
            }
        }
    }

    tagToDelete?.let { tag ->
        val count = tag.entryCount ?: 0
        val countText = if (count == 1) "1 article" else "$count articles"
        AlertDialog(
            onDismissRequest = { if (!isDeleting) tagToDelete = null },
            title = { Text("Delete tag \"#${tag.name}\"?") },
            text = {
                Text("This will permanently delete this tag from the server and remove it from $countText. This action cannot be undone.")
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        val id = tag.id ?: return@TextButton
                        isDeleting = true
                        scope.launch {
                            repository.deleteTag(id).fold(
                                onSuccess = {
                                    tags = tags.filterNot { it.id == id }
                                    tagToDelete = null
                                    isDeleting = false
                                },
                                onFailure = {
                                    tagToDelete = null
                                    isDeleting = false
                                }
                            )
                        }
                    },
                    enabled = !isDeleting
                ) {
                    Text(if (isDeleting) "Deleting…" else "Delete", color = CyberRed)
                }
            },
            dismissButton = {
                TextButton(
                    onClick = { tagToDelete = null },
                    enabled = !isDeleting
                ) {
                    Text("Cancel")
                }
            }
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun LanguagePickerSheet(
    selectedCode: String,
    onSelect: (String) -> Unit,
    onDismiss: () -> Unit
) {
    val languages = remember { ArticleTranslator.getSupportedLanguages() }
    var searchQuery by remember { mutableStateOf("") }
    val filteredLanguages = remember(languages, searchQuery) {
        if (searchQuery.isBlank()) languages
        else {
            val q = searchQuery.trim().lowercase()
            languages.filter {
                it.displayName.lowercase().contains(q) ||
                    it.nativeName.lowercase().contains(q) ||
                    it.code.lowercase().contains(q)
            }
        }
    }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        containerColor = SlateDark900,
        dragHandle = null
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(max = 600.dp)
                .navigationBarsPadding()
                .imePadding()
                .padding(horizontal = 20.dp, vertical = 16.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(Modifier.weight(1f)) {
                    Text("Translation Language", fontSize = 18.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
                    Text("Select target language for on-device translation", fontSize = 12.sp, color = TextMuted)
                }
                IconButton(onClick = onDismiss) {
                    Icon(Icons.Default.Close, contentDescription = "Close", tint = TextSecondary)
                }
            }
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                placeholder = { Text("Search languages…", color = TextMuted) },
                singleLine = true,
                leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = TextMuted) },
                trailingIcon = if (searchQuery.isNotEmpty()) {
                    { IconButton(onClick = { searchQuery = "" }) { Icon(Icons.Default.Close, contentDescription = "Clear") } }
                } else null,
                colors = OutlinedTextFieldDefaults.colors(
                    focusedTextColor = TextPrimary,
                    unfocusedTextColor = TextPrimary,
                    focusedBorderColor = CyberBlue
                ),
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(12.dp))

            LazyColumn(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f, fill = false)
            ) {
                items(filteredLanguages, key = { it.code }) { lang ->
                    val isSelected = lang.code.equals(selectedCode, ignoreCase = true)
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                onSelect(lang.code)
                                onDismiss()
                            }
                            .padding(vertical = 12.dp, horizontal = 4.dp)
                    ) {
                        RadioButton(
                            selected = isSelected,
                            onClick = null
                        )
                        Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f)) {
                            Text(
                                text = lang.nativeName,
                                fontSize = 15.sp,
                                fontWeight = if (isSelected) FontWeight.SemiBold else FontWeight.Normal,
                                color = if (isSelected) CyberBlue else TextPrimary
                            )
                        }
                        if (isSelected) {
                            Pill(label = "Selected", color = CyberBlue)
                        }
                    }
                    HorizontalDivider(color = SlateDark800)
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AppLanguagePickerSheet(
    selectedCode: String,
    onSelect: (String) -> Unit,
    onDismiss: () -> Unit
) {
    val languages = remember { AppLanguage.entries }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        containerColor = SlateDark900,
        dragHandle = null
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .navigationBarsPadding()
                .padding(horizontal = 20.dp, vertical = 16.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(Modifier.weight(1f)) {
                    Text("App language", fontSize = 18.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
                    Text("Display language for the app interface", fontSize = 12.sp, color = TextMuted)
                }
                IconButton(onClick = onDismiss) {
                    Icon(Icons.Default.Close, contentDescription = "Close", tint = TextSecondary)
                }
            }
            Spacer(Modifier.height(12.dp))

            LazyColumn(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f, fill = false)
            ) {
                items(languages, key = { it.code }) { lang ->
                    val isSelected = lang.code.equals(selectedCode, ignoreCase = true)
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                onSelect(lang.code)
                                onDismiss()
                            }
                            .padding(vertical = 12.dp, horizontal = 4.dp)
                    ) {
                        RadioButton(
                            selected = isSelected,
                            onClick = null
                        )
                        Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f)) {
                            Text(
                                text = lang.getEffectiveName(),
                                fontSize = 15.sp,
                                fontWeight = if (isSelected) FontWeight.SemiBold else FontWeight.Normal,
                                color = if (isSelected) CyberPurple else TextPrimary
                            )
                        }
                        if (isSelected) {
                            Pill(label = "Active", color = CyberPurple)
                        }
                    }
                    HorizontalDivider(color = SlateDark800)
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ThemePickerSheet(
    themes: List<ThemeDto>,
    activeThemeId: String?,
    activeThemeSource: String,
    userThemeId: String?,
    onSelectTheme: (ThemeDto) -> Unit,
    onUseDefaultTheme: () -> Unit,
    onDismiss: () -> Unit
) {
    val defaultTheme = themes.firstOrNull { it.isDefault }
    val followingDefault = userThemeId.isNullOrBlank() || activeThemeSource == "default"

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        containerColor = SlateDark900,
        dragHandle = null
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(max = 620.dp)
                .navigationBarsPadding()
                .imePadding()
                .padding(horizontal = 20.dp, vertical = 16.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(Modifier.weight(1f)) {
                    Text("Workbench Theme", fontSize = 18.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
                    Text(
                        "Synced with your IntelFeed account and instance palette",
                        fontSize = 12.sp,
                        color = TextMuted
                    )
                }
                IconButton(onClick = onDismiss) {
                    Icon(Icons.Default.Close, contentDescription = "Close", tint = TextSecondary)
                }
            }
            Spacer(Modifier.height(12.dp))

            LazyColumn(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f, fill = false)
            ) {
                item(key = "__instance_default__") {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable(onClick = onUseDefaultTheme)
                            .padding(vertical = 12.dp, horizontal = 4.dp)
                    ) {
                        RadioButton(
                            selected = followingDefault,
                            onClick = null
                        )
                        Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f)) {
                            Text(
                                text = "Follow Instance Default",
                                fontSize = 15.sp,
                                fontWeight = if (followingDefault) FontWeight.SemiBold else FontWeight.Normal,
                                color = if (followingDefault) CyberBlue else TextPrimary
                            )
                            Text(
                                text = defaultTheme?.let { "Currently ${it.name}" } ?: "Uses the instance's default theme",
                                fontSize = 12.sp,
                                color = TextMuted
                            )
                        }
                        if (defaultTheme != null) {
                            ThemeSwatches(variables = defaultTheme.variables)
                            Spacer(Modifier.width(8.dp))
                        }
                        if (followingDefault) {
                            Pill(label = "Default", color = CyberBlue)
                        }
                    }
                    HorizontalDivider(color = SlateDark800)
                }

                val builtInThemes = themes.filter { it.isBuiltIn }
                val customThemes = themes.filter { !it.isBuiltIn }

                if (builtInThemes.isNotEmpty()) {
                    item(key = "__header_builtin__") {
                        Text(
                            text = "BUILT-IN THEMES",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = TextMuted,
                            modifier = Modifier.padding(top = 12.dp, bottom = 4.dp, start = 4.dp)
                        )
                    }
                    items(builtInThemes, key = { it.id }) { theme ->
                        val isSelected = !followingDefault && activeThemeId == theme.id
                        ThemeOptionRow(
                            theme = theme,
                            isSelected = isSelected,
                            onClick = { onSelectTheme(theme) }
                        )
                    }
                }

                if (customThemes.isNotEmpty()) {
                    item(key = "__header_custom__") {
                        Text(
                            text = "CUSTOM INSTANCE THEMES",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = TextMuted,
                            modifier = Modifier.padding(top = 12.dp, bottom = 4.dp, start = 4.dp)
                        )
                    }
                    items(customThemes, key = { it.id }) { theme ->
                        val isSelected = !followingDefault && activeThemeId == theme.id
                        ThemeOptionRow(
                            theme = theme,
                            isSelected = isSelected,
                            onClick = { onSelectTheme(theme) }
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun ThemeOptionRow(
    theme: ThemeDto,
    isSelected: Boolean,
    onClick: () -> Unit
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(vertical = 12.dp, horizontal = 4.dp)
    ) {
        RadioButton(
            selected = isSelected,
            onClick = null
        )
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(
                    text = theme.name,
                    fontSize = 15.sp,
                    fontWeight = if (isSelected) FontWeight.SemiBold else FontWeight.Normal,
                    color = if (isSelected) CyberBlue else TextPrimary
                )
                if (theme.isDefault) {
                    Pill(label = "Instance Default", color = TextMuted)
                }
            }
            if (theme.description.isNotBlank()) {
                Text(
                    text = theme.description,
                    fontSize = 12.sp,
                    color = TextMuted
                )
            }
        }
        Spacer(Modifier.width(8.dp))
        ThemeSwatches(variables = theme.variables)
        if (isSelected) {
            Spacer(Modifier.width(8.dp))
            Pill(label = "Active", color = CyberBlue)
        }
    }
    HorizontalDivider(color = SlateDark800)
}

@Composable
private fun ThemeSwatches(variables: Map<String, String>) {
    val swatchCandidates = listOf(
        listOf("bg-primary", "--bg-primary", "--bg-base"),
        listOf("bg-secondary", "--bg-secondary", "--bg-elevated"),
        listOf("accent", "--accent", "--accent-primary"),
        listOf("text-primary", "--text-primary")
    )
    Row(
        horizontalArrangement = Arrangement.spacedBy(4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        swatchCandidates.forEach { candidates ->
            val raw = candidates.firstNotNullOfOrNull { variables[it] }
            val color = ThemeEngine.parseCssColor(raw, SlateDark800)
            Box(
                modifier = Modifier
                    .size(14.dp)
                    .background(color, RoundedCornerShape(4.dp))
                    .border(1.dp, SlateDark700, RoundedCornerShape(4.dp))
            )
        }
    }
}

/** A priority cut-off as the score badge shows it ("9.5"). */
private fun formatCutoff(score: Double): String = String.format(java.util.Locale.US, "%.1f", score)
