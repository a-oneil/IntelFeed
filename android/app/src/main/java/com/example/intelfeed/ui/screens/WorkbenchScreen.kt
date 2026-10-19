package com.example.intelfeed.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import kotlinx.coroutines.launch
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Hub
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.PrimaryScrollableTabRow
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.intelfeed.theme.CyberPurple
import com.example.intelfeed.theme.SlateDark700
import com.example.intelfeed.theme.SlateDark800
import com.example.intelfeed.theme.SlateDark900
import com.example.intelfeed.theme.TextMuted
import com.example.intelfeed.theme.TextPrimary
import com.example.intelfeed.theme.TextSecondary
import com.example.intelfeed.ui.IntelFeedUiState
import com.example.intelfeed.ui.IntelFeedViewModel
import com.example.intelfeed.ui.WorkbenchTab
import com.example.intelfeed.ui.i18n.LocalStrings
import com.example.intelfeed.ui.workbench.AttackMatrixView
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.intelfeed.ui.components.EmptyState
import com.example.intelfeed.ui.components.ErrorState
import com.example.intelfeed.ui.components.InlineLoading
import com.example.intelfeed.ui.components.LoadingBox
import com.example.intelfeed.ui.components.Pill
import com.example.intelfeed.ui.components.color
import com.example.intelfeed.ui.entity.WorkbenchItem
import com.example.intelfeed.ui.entity.articleCountLabel
import java.text.NumberFormat
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WorkbenchScreen(uiState: IntelFeedUiState, viewModel: IntelFeedViewModel, modifier: Modifier = Modifier) {
    val focusManager = LocalFocusManager.current
    val scope = rememberCoroutineScope()
    val tab = uiState.selectedWorkbenchTab
    val accent = tab.type?.color()
        ?: if (tab == WorkbenchTab.RANSOMWARE) com.example.intelfeed.theme.ThemeEngine.domainAccentColor("ops")
        else com.example.intelfeed.theme.ThemeEngine.domainAccentColor("dash")
    val listState = rememberLazyListState()

    var showCreateCampaignDialog by remember { mutableStateOf(false) }

    val nearEnd by remember {
        derivedStateOf {
            val total = listState.layoutInfo.totalItemsCount
            val last = listState.layoutInfo.visibleItemsInfo.lastOrNull()?.index ?: 0
            total > 0 && last >= total - 4
        }
    }
    LaunchedEffect(nearEnd, uiState.workbenchItems.size, uiState.workbenchHasMore) {
        if (nearEnd && uiState.workbenchHasMore) viewModel.loadMoreWorkbench()
    }
    // Only when the tab really changes: this screen is re-created when you come back from a
    // profile, and scrolling to the top then lost your place in the list.
    var scrolledForTab by rememberSaveable { mutableStateOf(tab) }
    LaunchedEffect(tab) {
        if (tab != scrolledForTab) {
            scrolledForTab = tab
            listState.scrollToItem(0)
        }
    }

    val strings = LocalStrings.current
    // Kept for the Workbench's lifetime so switching tabs doesn't reload the matrix.
    val matrixVm = androidx.lifecycle.viewmodel.compose.viewModel { com.example.intelfeed.ui.workbench.AttackMatrixViewModel(viewModel.repository) }
    val ransomwareVm = androidx.lifecycle.viewmodel.compose.viewModel { com.example.intelfeed.ui.workbench.RansomwareViewModel(viewModel.repository, viewModel.messenger) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(strings.navWorkbench, fontSize = 18.sp, fontWeight = FontWeight.Bold, color = TextPrimary) },
                actions = {
                    if (tab == WorkbenchTab.CAMPAIGNS) {
                        IconButton(onClick = { showCreateCampaignDialog = true }) {
                            Icon(Icons.Default.Add, contentDescription = "New Campaign", tint = CyberPurple)
                        }
                    }
                    IconButton(onClick = {
                        when (tab) {
                            WorkbenchTab.ATTACK_MATRIX -> matrixVm.load()
                            WorkbenchTab.RANSOMWARE -> ransomwareVm.refresh()
                            else -> viewModel.loadWorkbench()
                        }
                    }) { Icon(Icons.Default.Refresh, contentDescription = "Refresh", tint = TextSecondary) }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = SlateDark900)
            )
        },
        containerColor = SlateDark900
    ) { padding ->
        Column(modifier.fillMaxSize().padding(padding)) {
            val searchPlaceholder = when (tab) {
                WorkbenchTab.ACTORS -> strings.searchThreatActors
                WorkbenchTab.MALWARE -> strings.searchMalware
                WorkbenchTab.CVES -> strings.searchVulnerabilities
                WorkbenchTab.TTPS -> strings.searchTechniques
                else -> "Search ${tab.label.lowercase(Locale.US)}"
            }
            if (!tab.isView) {
                OutlinedTextField(
                    value = uiState.workbenchSearchQuery,
                    onValueChange = { viewModel.setWorkbenchSearch(it) },
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp),
                    placeholder = { Text(searchPlaceholder, color = TextMuted) },
                    leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = TextSecondary) },
                    trailingIcon = if (uiState.workbenchSearchQuery.isNotEmpty()) {
                        { IconButton(onClick = { viewModel.setWorkbenchSearch("") }) { Icon(Icons.Default.Close, contentDescription = "Clear search", tint = TextMuted) } }
                    } else null,
                    singleLine = true,
                    shape = RoundedCornerShape(10.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = accent,
                        unfocusedBorderColor = SlateDark700,
                        focusedContainerColor = SlateDark800,
                        unfocusedContainerColor = SlateDark800,
                        focusedTextColor = TextPrimary,
                        unfocusedTextColor = TextPrimary
                    ),
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                    keyboardActions = KeyboardActions(onSearch = { focusManager.clearFocus() })
                )
            }

            PrimaryScrollableTabRow(
                selectedTabIndex = tab.ordinal,
                containerColor = SlateDark900,
                contentColor = accent,
                edgePadding = 12.dp,
                divider = { HorizontalDivider(color = SlateDark700) }
            ) {
                WorkbenchTab.entries.forEach { t ->
                    val selected = t == tab
                    val tabLabel = when (t) {
                        WorkbenchTab.ACTORS -> strings.tabThreatActors
                        WorkbenchTab.MALWARE -> strings.tabMalware
                        WorkbenchTab.CVES -> strings.tabVulnerabilities
                        WorkbenchTab.TTPS -> strings.tabTechniques
                        else -> t.label
                    }
                     Tab(
                        selected = selected,
                        onClick = { viewModel.setWorkbenchTab(t) },
                        text = {
                            val tAccent = t.type?.color()
                                ?: if (t == WorkbenchTab.RANSOMWARE) com.example.intelfeed.theme.ThemeEngine.domainAccentColor("ops")
                                else com.example.intelfeed.theme.ThemeEngine.domainAccentColor("dash")
                            Text(
                                tabLabel,
                                fontWeight = if (selected) FontWeight.Bold else FontWeight.Medium,
                                color = if (selected) tAccent else TextMuted
                            )
                        }
                    )

                }
            }

            if (tab == WorkbenchTab.ATTACK_MATRIX) {
                val matrixState by matrixVm.state.collectAsStateWithLifecycle()
                AttackMatrixView(matrixVm, matrixState, onOpenEntity = { viewModel.openEntity(it) })
            } else if (tab == WorkbenchTab.RANSOMWARE) {
                val ransomwareState by ransomwareVm.state.collectAsStateWithLifecycle()
                com.example.intelfeed.ui.workbench.RansomwareTracker(ransomwareVm, ransomwareState, onOpenEntity = { viewModel.openEntity(it) })
            } else PullToRefreshBox(
                isRefreshing = uiState.workbenchLoading && uiState.workbenchItems.isNotEmpty(),
                onRefresh = { viewModel.loadWorkbench() },
                modifier = Modifier.fillMaxSize()
            ) {
                when {
                    uiState.workbenchLoading && uiState.workbenchItems.isEmpty() -> LoadingBox(color = accent)
                    uiState.workbenchError != null && uiState.workbenchItems.isEmpty() -> ErrorState(
                        uiState.workbenchError, onRetry = { viewModel.loadWorkbench() }, modifier = Modifier.fillMaxSize()
                    )
                    uiState.workbenchItems.isEmpty() -> LazyColumn(Modifier.fillMaxSize()) {
                        item {
                            if (tab == WorkbenchTab.WATCHLIST && uiState.workbenchSearchQuery.isBlank()) {
                                EmptyState(
                                    Icons.Default.Visibility,
                                    "You're not watching anything yet",
                                    "Open a threat actor, malware family, CVE, vendor or product and tap Watch. Its articles then get a boost in your Priority Queue."
                                )
                            } else {
                                EmptyState(
                                    Icons.Default.Hub,
                                    "No ${tab.label.lowercase(Locale.US)} found",
                                    if (uiState.workbenchSearchQuery.isNotBlank()) "Nothing matches \"${uiState.workbenchSearchQuery}\"." else "There's nothing here yet."
                                )
                            }
                        }
                    }
                    else -> {
                        val fmt = remember { NumberFormat.getIntegerInstance(Locale.US) }
                        LazyColumn(
                            state = listState,
                            modifier = Modifier.fillMaxSize(),
                            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 24.dp),
                            verticalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            item(key = "count", contentType = "count_header") {
                                val shown = uiState.workbenchItems.size
                                val total = uiState.workbenchTotal
                                Text(
                                    if (total != null && total > shown) "Showing ${fmt.format(shown)} of ${fmt.format(total)}" else "${fmt.format(shown)} ${if (shown == 1) "item" else "items"}",
                                    fontSize = 12.sp,
                                    color = TextMuted
                                )
                            }
                            items(uiState.workbenchItems, key = { it.ref.type.key + ":" + it.ref.id }, contentType = { "workbench_card" }) { item ->
                                WorkbenchCard(item, onClick = { viewModel.openEntity(item.ref) })
                            }
                            if (uiState.workbenchLoadingMore) item(key = "more", contentType = "loading") { InlineLoading(color = accent) }
                        }
                    }
                }
            }
        }
    }

    if (showCreateCampaignDialog) {
        var name by remember { mutableStateOf("") }
        var description by remember { mutableStateOf("") }
        var creating by remember { mutableStateOf(false) }
        var createError by remember { mutableStateOf<String?>(null) }

        AlertDialog(
            onDismissRequest = { if (!creating) showCreateCampaignDialog = false },
            containerColor = SlateDark900,
            title = { Text("New Campaign", color = TextPrimary, fontWeight = FontWeight.Bold) },
            text = {
                Column {
                    Text("Create a tracked investigation campaign.", fontSize = 13.sp, color = TextSecondary)
                    Spacer(Modifier.height(12.dp))
                    OutlinedTextField(
                        value = name,
                        onValueChange = { name = it },
                        placeholder = { Text("Campaign Name (e.g. Operation Sentinel)", fontSize = 13.sp, color = TextMuted) },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = CyberPurple,
                            unfocusedBorderColor = SlateDark700,
                            focusedTextColor = TextPrimary,
                            unfocusedTextColor = TextPrimary
                        )
                    )
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = description,
                        onValueChange = { description = it },
                        placeholder = { Text("Objective / Scope (optional)", fontSize = 13.sp, color = TextMuted) },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = CyberPurple,
                            unfocusedBorderColor = SlateDark700,
                            focusedTextColor = TextPrimary,
                            unfocusedTextColor = TextPrimary
                        )
                    )
                    if (createError != null) {
                        Spacer(Modifier.height(6.dp))
                        Text(createError!!, color = com.example.intelfeed.theme.CyberRed, fontSize = 12.sp)
                    }
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        val n = name.trim()
                        if (n.isBlank()) return@Button
                        creating = true
                        createError = null
                        scope.launch {
                            viewModel.repository.createCampaign(n, description.takeIf { it.isNotBlank() }).fold(
                                onSuccess = {
                                    creating = false
                                    showCreateCampaignDialog = false
                                    viewModel.loadWorkbench()
                                },
                                onFailure = { err ->
                                    creating = false
                                    createError = err.localizedMessage ?: "Failed to create campaign"
                                }
                            )
                        }
                    },
                    enabled = name.isNotBlank() && !creating,
                    colors = ButtonDefaults.buttonColors(containerColor = CyberPurple)
                ) {
                    if (creating) {
                        CircularProgressIndicator(modifier = Modifier.size(16.dp), color = TextPrimary, strokeWidth = 2.dp)
                    } else {
                        Text("Create", color = TextPrimary, fontWeight = FontWeight.Bold)
                    }
                }
            },
            dismissButton = {
                Button(
                    onClick = { showCreateCampaignDialog = false },
                    enabled = !creating,
                    colors = ButtonDefaults.buttonColors(containerColor = SlateDark800)
                ) {
                    Text("Cancel", color = TextSecondary)
                }
            }
        )
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun WorkbenchCard(item: WorkbenchItem, onClick: () -> Unit) {
    val typeColor = item.ref.type.color()
    Surface(
        color = SlateDark800,
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).clickable(onClick = onClick)
    ) {
        Column(Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = item.title,
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Bold,
                    color = if (item.monospaceTitle) typeColor else TextPrimary,
                    fontFamily = if (item.monospaceTitle) FontFamily.Monospace else FontFamily.Default,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f)
                )
                articleCountLabel(item.articleCount)?.let {
                    Spacer(Modifier.width(8.dp))
                    Text(it, fontSize = 12.sp, color = TextMuted)
                }
            }
            item.subtitle?.let {
                Spacer(Modifier.height(2.dp))
                Text(it, fontSize = 13.sp, color = TextSecondary, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            if (item.badges.isNotEmpty()) {
                Spacer(Modifier.height(8.dp))
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    item.badges.forEach { Pill(it.label, it.color()) }
                }
            }
            item.description?.takeIf { it.isNotBlank() }?.let {
                Spacer(Modifier.height(8.dp))
                Text(it, fontSize = 13.sp, color = TextMuted, maxLines = 2, overflow = TextOverflow.Ellipsis, lineHeight = 18.sp)
            }
        }
    }
}

