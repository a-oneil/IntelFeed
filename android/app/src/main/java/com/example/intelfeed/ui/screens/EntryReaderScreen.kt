package com.example.intelfeed.ui.screens

import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.ScrollState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.intelfeed.IntelFeedApplication
import kotlinx.coroutines.launch
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.AutoStories
import androidx.compose.material.icons.filled.Bookmark
import androidx.compose.material.icons.filled.BookmarkBorder
import androidx.compose.material.icons.filled.Campaign
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.DeleteOutline
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.FormatSize
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.MarkEmailRead
import androidx.compose.material.icons.filled.MarkEmailUnread
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.PushPin
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.automirrored.filled.Notes
import androidx.compose.material.icons.automirrored.filled.VolumeUp
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.StarBorder
import androidx.compose.material.icons.filled.ThumbDown
import androidx.compose.material.icons.filled.ThumbUp
import androidx.compose.material.icons.filled.Tag
import androidx.compose.material.icons.filled.Translate
import androidx.compose.material.icons.automirrored.filled.VolumeOff
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import com.example.intelfeed.util.HtmlText
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.intelfeed.ui.i18n.LocalStrings
import coil.compose.AsyncImage
import com.example.intelfeed.LocalSnackbarHostState
import com.example.intelfeed.data.model.Cve
import com.example.intelfeed.data.model.EntityType
import com.example.intelfeed.data.model.EntryDetail
import com.example.intelfeed.data.model.EntryIntel
import com.example.intelfeed.data.model.EntryNote
import com.example.intelfeed.data.model.Signal
import com.example.intelfeed.data.model.TagEntity
import com.example.intelfeed.theme.CyberAmber
import com.example.intelfeed.theme.CyberBlue
import com.example.intelfeed.theme.CyberCyan
import com.example.intelfeed.theme.CyberGreen
import com.example.intelfeed.theme.CyberPurple
import com.example.intelfeed.theme.CyberRed
import com.example.intelfeed.theme.SlateDark600
import com.example.intelfeed.theme.SlateDark700
import com.example.intelfeed.theme.SlateDark800
import com.example.intelfeed.theme.SlateDark900
import com.example.intelfeed.theme.TextMuted
import com.example.intelfeed.theme.TextPrimary
import com.example.intelfeed.theme.TextSecondary
import com.example.intelfeed.ui.components.ArticleContent
import com.example.intelfeed.ui.components.CampaignPickerSheet
import com.example.intelfeed.ui.components.CardSurface
import com.example.intelfeed.ui.components.ErrorState
import com.example.intelfeed.ui.components.LoadingBox
import com.example.intelfeed.ui.components.Pill
import com.example.intelfeed.ui.components.ScoreBadge
import com.example.intelfeed.ui.components.SectionHeader
import com.example.intelfeed.ui.components.color
import com.example.intelfeed.ui.components.familyOf
import com.example.intelfeed.ui.components.signalFamilyColor
import com.example.intelfeed.ui.components.signalLabel
import com.example.intelfeed.ui.components.tagColor
import com.example.intelfeed.ui.entity.EntityRef
import com.example.intelfeed.ui.entity.cvssTone
import com.example.intelfeed.ui.reader.ReaderFontSize
import com.example.intelfeed.ui.reader.ReaderUiState
import com.example.intelfeed.ui.reader.ArticleSpeaker
import com.example.intelfeed.ui.reader.entityTerms
import com.example.intelfeed.ui.reader.keywordTerms
import com.example.intelfeed.data.model.PirMatch
import com.example.intelfeed.util.ArticleLinker
import com.example.intelfeed.ui.reader.ReaderPages
import com.example.intelfeed.ui.reader.ReaderViewModel
import com.example.intelfeed.data.model.GlossaryTerm
import com.example.intelfeed.ui.reader.glossaryTerms
import com.example.intelfeed.ui.reader.glossarySearchQuery
import com.example.intelfeed.ui.reader.GlossarySheet
import com.example.intelfeed.ui.reader.EntityPreviewSheet
import com.example.intelfeed.ui.reader.EntityPreviews
import com.example.intelfeed.ui.reader.EntityPreview
import com.example.intelfeed.util.ArticleHtml
import com.example.intelfeed.ui.reader.VoiceSettingsDialog
import com.example.intelfeed.util.Clipboard
import com.example.intelfeed.util.DateUtils
import com.example.intelfeed.util.ExternalLinks
import com.example.intelfeed.util.ShareSheet
import androidx.compose.runtime.snapshotFlow
import androidx.compose.runtime.rememberUpdatedState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EntryReaderScreen(
    app: IntelFeedApplication,
    entryId: String,
    siblingIds: List<String>,
    onBack: () -> Unit,
    onNearListEnd: () -> Unit,
    onOpenEntry: (String) -> Unit,
    // The article the pager has settled on (so the list can show it when you go back).
    onSettledEntry: (String) -> Unit = {},
    // Tapping a tag searches for it.
    onSearchTag: (String) -> Unit = {},
    // Tapping a highlighted keyword searches for it.
    onSearchKeyword: (String) -> Unit = {},
    // Runs a search query as typed (the glossary sheet's "Search articles").
    onSearchQuery: (String) -> Unit = {},
    onOpenEntity: (EntityRef) -> Unit,
    onOpenThread: (String, String?) -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    val effectiveSiblingIds = remember(siblingIds, entryId) {
        if (siblingIds.contains(entryId)) {
            siblingIds.distinct()
        } else {
            (listOf(entryId) + siblingIds).distinct()
        }
    }
    val initialIndex = remember(entryId, effectiveSiblingIds) {
        effectiveSiblingIds.indexOf(entryId).coerceAtLeast(0)
    }
    val pagerState = rememberPagerState(initialPage = initialIndex) {
        effectiveSiblingIds.size
    }

    val pages: ReaderPages = viewModel { ReaderPages() }
    val activeEntryId = effectiveSiblingIds.getOrNull(pagerState.currentPage) ?: entryId
    val activeVm = readerViewModel(pages, activeEntryId, app)
    val activeState by activeVm.state.collectAsStateWithLifecycle()
    val detail = activeState.detail

    // The pager also composes the neighbouring pages (beyondViewportPageCount) so a swipe shows
    // text at once. Only the page it has settled on is marked read and loads its side panels;
    // otherwise opening one article marked the next and previous ones read too.
    val settledEntryId = effectiveSiblingIds.getOrNull(pagerState.settledPage) ?: entryId
    val settledVm = readerViewModel(pages, settledEntryId, app)
    LaunchedEffect(settledVm) {
        settledVm.activate()
        onSettledEntry(settledEntryId)
    }
    // Only articles within two pages of the one on screen keep their state (the pager composes
    // one page either side). Coming back further reloads the article.
    LaunchedEffect(pagerState.settledPage, effectiveSiblingIds) {
        val page = pagerState.settledPage
        val keep = (page - 2..page + 2).mapNotNullTo(HashSet()) { effectiveSiblingIds.getOrNull(it) }
        pages.retainOnly(keep + activeEntryId + settledEntryId)
    }

    val speechRate by app.userPreferences.ttsSpeechRate.collectAsStateWithLifecycle(initialValue = 1.0f)
    var showVoiceSettings by remember { mutableStateOf(false) }
    var showTextSize by remember { mutableStateOf(false) }
    var showTagPicker by remember { mutableStateOf(false) }
    var showCampaignPicker by remember { mutableStateOf(false) }
    var editingNote by remember { mutableStateOf<NoteDraft?>(null) }
    var menuOpen by remember { mutableStateOf(false) }
    var showFindInArticle by remember { mutableStateOf(false) }
    var findQuery by remember { mutableStateOf("") }
    val findFocusRequester = remember { FocusRequester() }
    val keyboardController = LocalSoftwareKeyboardController.current
    val strings = LocalStrings.current

    LaunchedEffect(showFindInArticle) {
        if (showFindInArticle) {
            delay(100)
            findFocusRequester.requestFocus()
            keyboardController?.show()
        }
    }
    // Find in article. Applied once typing pauses: each change re-styles every paragraph of the
    // article on the main thread.
    val appliedFind by produceState("", findQuery) {
        val query = findQuery.trim()
        if (query.isNotEmpty()) delay(250)
        value = query
    }
    // The paragraphs the find bar searches, as the reader shows them, so the count matches the
    // highlights (it used to count in contentText, which many articles don't have). Parsed off the
    // main thread once per article, only while the find bar is open.
    val findTexts by produceState<List<String>?>(null, showFindInArticle, detail?.id, activeState.translation, activeState.showOriginal) {
        val article = detail
        val translation = activeState.translation
        val showOriginal = activeState.showOriginal
        value = if (!showFindInArticle || article == null) null else withContext(Dispatchers.Default) {
            val blocks = if (translation != null && !showOriginal) {
                translation.translatedBlocks
            } else {
                ArticleHtml.parseBlocks(article, activeState.serverUrl)
            }
            blocks.mapNotNull { block ->
                when (block) {
                    is ArticleHtml.Paragraph -> block.text.text
                    is ArticleHtml.ListItem -> block.text.text
                    else -> null
                }
            }
        }
    }
    val findCount = remember(findTexts, appliedFind) {
        findTexts?.takeIf { appliedFind.isNotEmpty() }?.sumOf { countOccurrences(it, appliedFind) }
    }
    // Read aloud. The speech engine starts on the first tap, not on every article open.
    val speaker = remember { ArticleSpeaker(context) }
    DisposableEffect(speaker) { onDispose { speaker.shutdown() } }
    val isSpeaking = speaker.isSpeaking

    // Stop reading aloud when swiping to another article
    LaunchedEffect(pagerState.currentPage) {
        if (speaker.isSpeaking) speaker.stop()
    }

    val toggleSpeak = {
        if (speaker.isSpeaking) {
            speaker.stop()
        } else if (detail != null) {
            val translation = activeState.translation
            val showOriginal = activeState.showOriginal
            val lang = if (translation != null && !showOriginal) translation.targetLanguageCode else null
            val textToRead = buildString {
                val titleToRead = if (translation != null && !showOriginal) {
                    translation.translatedTitle
                } else {
                    detail.translatedTitle?.takeIf { it.isNotBlank() } ?: detail.title
                }
                append(titleToRead).append(".\n\n")
                if (!detail.author.isNullOrBlank()) append("By ").append(detail.author).append(".\n\n")
                val body = if (translation != null && !showOriginal) {
                    translation.translatedText
                } else {
                    detail.contentText?.takeIf { it.isNotBlank() } ?: HtmlText.toPlainText(detail.contentHtml.orEmpty())
                }
                append(body)
            }
            speaker.speak(detail.id, textToRead, language = lang, speechRate = speechRate)
        }
    }

    // When nearing the end of available articles, trigger loading more from the feed
    LaunchedEffect(pagerState.currentPage, effectiveSiblingIds.size) {
        if (pagerState.currentPage >= effectiveSiblingIds.size - 3) onNearListEnd()
    }

    Scaffold(
        topBar = {
            if (showFindInArticle) {
                TopAppBar(
                    navigationIcon = {
                        IconButton(onClick = { showFindInArticle = false; findQuery = ""; keyboardController?.hide() }) {
                            Icon(Icons.Default.Close, contentDescription = "Close search", tint = TextPrimary)
                        }
                    },
                    title = {
                        OutlinedTextField(
                            value = findQuery,
                            onValueChange = { findQuery = it },
                            placeholder = { Text("Find in article…", fontSize = 14.sp, color = TextMuted) },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth().height(52.dp).focusRequester(findFocusRequester),
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = CyberBlue,
                                unfocusedBorderColor = SlateDark600,
                                focusedTextColor = TextPrimary,
                                unfocusedTextColor = TextPrimary,
                                cursorColor = CyberBlue
                            )
                        )
                    },
                    actions = {
                        val count = findCount
                        if (count != null) {
                            Text(
                                text = if (count == 1) "1 match" else "$count matches",
                                fontSize = 12.sp,
                                color = if (count > 0) CyberAmber else TextMuted,
                                modifier = Modifier.padding(end = 12.dp)
                            )
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(containerColor = SlateDark900)
                )
            } else {
                TopAppBar(
                    navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back", tint = TextPrimary) } },
                    title = {
                        Text(
                            text = detail?.feedTitle ?: "Article",
                            fontSize = 15.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = TextSecondary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    },
                    actions = {
                        if (detail != null) {
                            IconButton(onClick = toggleSpeak) {
                                Icon(
                                    if (isSpeaking) Icons.AutoMirrored.Filled.VolumeOff else Icons.AutoMirrored.Filled.VolumeUp,
                                    contentDescription = if (isSpeaking) "Stop reading aloud" else "Read aloud",
                                    tint = if (isSpeaking) CyberGreen else TextSecondary
                                )
                            }
                            IconButton(onClick = { showFindInArticle = true }) {
                                Icon(Icons.Default.Search, contentDescription = "Find in article", tint = TextSecondary)
                            }
                            IconButton(onClick = activeVm::toggleBookmark) {
                                Icon(
                                    if (detail.isBookmarked) Icons.Default.Bookmark else Icons.Default.BookmarkBorder,
                                    contentDescription = if (detail.isBookmarked) "Remove bookmark" else "Bookmark",
                                    tint = if (detail.isBookmarked) CyberBlue else TextSecondary
                                )
                            }
                            IconButton(onClick = activeVm::toggleStar) {
                                Icon(
                                    if (detail.isStarred) Icons.Default.Star else Icons.Default.StarBorder,
                                    contentDescription = if (detail.isStarred) "Unstar" else "Star",
                                    tint = if (detail.isStarred) CyberAmber else TextSecondary
                                )
                            }
                            IconButton(onClick = {
                                if (activeState.translation != null) {
                                    activeVm.toggleShowOriginal()
                                } else {
                                    activeVm.translate()
                                }
                            }) {
                                if (activeState.isTranslating) {
                                    CircularProgressIndicator(
                                        modifier = Modifier.size(18.dp),
                                        strokeWidth = 2.dp,
                                        color = CyberBlue
                                    )
                                } else {
                                    val targetName = activeState.translation?.targetLanguageName ?: activeState.targetLanguageName
                                    Icon(
                                        Icons.Default.Translate,
                                        contentDescription = if (activeState.translation != null) {
                                            if (activeState.showOriginal) "Show $targetName translation" else "Show original"
                                        } else {
                                            "Translate to $targetName"
                                        },
                                        tint = if (activeState.translation != null && !activeState.showOriginal) CyberBlue else TextSecondary
                                    )
                                }
                            }
                            Box {
                                IconButton(onClick = { menuOpen = true }) { Icon(Icons.Default.MoreVert, contentDescription = "More", tint = TextSecondary) }
                                DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                                    if (activeState.translation != null) {
                                        val targetName = activeState.translation?.targetLanguageName ?: activeState.targetLanguageName
                                        DropdownMenuItem(
                                            text = { Text(if (activeState.showOriginal) strings.readerShowTranslation else strings.readerShowOriginal) },
                                            leadingIcon = { Icon(Icons.Default.Translate, null, tint = CyberBlue) },
                                            onClick = { menuOpen = false; activeVm.toggleShowOriginal() }
                                        )
                                    } else {
                                        DropdownMenuItem(
                                            text = { Text("${strings.readerTranslate} (${activeState.targetLanguageName})") },
                                            leadingIcon = { Icon(Icons.Default.Translate, null) },
                                            onClick = { menuOpen = false; activeVm.translate() }
                                        )
                                    }
                                    val url = detail.url?.takeIf { it.isNotBlank() }
                                    if (url != null) {
                                        DropdownMenuItem(text = { Text(strings.readerOpenOriginal) }, leadingIcon = { Icon(Icons.AutoMirrored.Filled.OpenInNew, null) },
                                            onClick = { menuOpen = false; ExternalLinks.openInBrowser(context, url) })
                                        DropdownMenuItem(text = { Text(strings.readerShareLink) }, leadingIcon = { Icon(Icons.Default.Share, null) },
                                            onClick = { menuOpen = false; ShareSheet.shareText(context, "${detail.title}\n$url", detail.title) })
                                        DropdownMenuItem(text = { Text(strings.readerCopyLink) }, leadingIcon = { Icon(Icons.Default.ContentCopy, null) },
                                            onClick = { menuOpen = false; Clipboard.copy(context, "Link", url) })
                                    }
                                    DropdownMenuItem(
                                        text = { Text(strings.readerExportMarkdown) },
                                        leadingIcon = { Icon(Icons.AutoMirrored.Filled.Notes, null) },
                                        onClick = {
                                            menuOpen = false
                                            val md = buildString {
                                                append("# ").append(detail.title).append("\n\n")
                                                append("**Source:** ").append(detail.feedTitle ?: "Unknown")
                                                append(" | **Published:** ").append(DateUtils.formatRelativeTime(detail.publishedAt)).append("\n")
                                                if (!detail.author.isNullOrBlank()) append("**Author:** ").append(detail.author).append("\n")
                                                if (!detail.url.isNullOrBlank()) append("**URL:** ").append(detail.url).append("\n")
                                                append("\n---\n\n")
                                                val body = detail.contentText?.takeIf { it.isNotBlank() } ?: HtmlText.toPlainText(detail.contentHtml.orEmpty())
                                                append(body)
                                            }
                                            Clipboard.copy(context, "Markdown Article", md)
                                            ShareSheet.shareText(context, md, "${detail.title}.md")
                                        }
                                    )
                                    DropdownMenuItem(
                                        text = { Text("Share IntelFeed page") },
                                        leadingIcon = { Icon(Icons.Default.Link, null) },
                                        onClick = {
                                            menuOpen = false
                                            // A public, read-only page on the server with the article and its extracted intel.
                                            activeVm.createShareLink { link -> ShareSheet.shareText(context, "${detail.title}\n$link", detail.title) }
                                        }
                                    )
                                    DropdownMenuItem(
                                        text = { Text(if (detail.isRead) strings.readerMarkUnread else strings.readerMarkRead) },
                                        leadingIcon = { Icon(if (detail.isRead) Icons.Default.MarkEmailUnread else Icons.Default.MarkEmailRead, null) },
                                        onClick = { menuOpen = false; activeVm.toggleRead() }
                                    )
                                    DropdownMenuItem(
                                        text = { Text("Add to campaign") },
                                        leadingIcon = { Icon(Icons.Default.Campaign, null, tint = CyberPurple) },
                                        onClick = { menuOpen = false; showCampaignPicker = true }
                                    )
                                    DropdownMenuItem(text = { Text("Text size") }, leadingIcon = { Icon(Icons.Default.FormatSize, null) },
                                        onClick = { menuOpen = false; showTextSize = true })
                                    DropdownMenuItem(
                                        text = { Text("Voice & speed settings") },
                                        leadingIcon = { Icon(Icons.AutoMirrored.Filled.VolumeUp, null) },
                                        onClick = { menuOpen = false; showVoiceSettings = true }
                                    )
                                }
                            }
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(containerColor = SlateDark900, titleContentColor = TextPrimary)
                )
            }
        },
        bottomBar = {
            if (effectiveSiblingIds.size > 1) {
                // A plain 56 dp bar: BottomAppBar is always 80 dp, which in landscape left about half
                // the screen for the article.
                Surface(color = SlateDark800) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.fillMaxWidth().navigationBarsPadding().height(56.dp).padding(horizontal = 8.dp)
                    ) {
                        TextButton(
                            onClick = {
                                if (pagerState.currentPage > 0) {
                                    scope.launch { pagerState.animateScrollToPage(pagerState.currentPage - 1) }
                                }
                            },
                            enabled = pagerState.currentPage > 0
                        ) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(6.dp))
                            Text("Previous")
                        }
                        Text(
                            text = "${pagerState.currentPage + 1} of ${effectiveSiblingIds.size}",
                            color = TextMuted,
                            fontSize = 13.sp,
                            modifier = Modifier.weight(1f),
                            textAlign = androidx.compose.ui.text.style.TextAlign.Center
                        )
                        TextButton(
                            onClick = {
                                if (pagerState.currentPage < effectiveSiblingIds.lastIndex) {
                                    scope.launch { pagerState.animateScrollToPage(pagerState.currentPage + 1) }
                                }
                            },
                            enabled = pagerState.currentPage < effectiveSiblingIds.lastIndex
                        ) {
                            Text("Next")
                            Spacer(Modifier.width(6.dp))
                            Icon(Icons.AutoMirrored.Filled.ArrowForward, contentDescription = null, modifier = Modifier.size(18.dp))
                        }
                    }
                }
            }
        },
        snackbarHost = { SnackbarHost(LocalSnackbarHostState.current) },
        containerColor = SlateDark900
    ) { padding ->
        HorizontalPager(
            state = pagerState,
            beyondViewportPageCount = 1,
            modifier = Modifier
                .padding(padding)
                .consumeWindowInsets(padding)
                .fillMaxSize()
        ) { page ->
            val pageEntryId = effectiveSiblingIds.getOrNull(page) ?: return@HorizontalPager
            val pageVm = readerViewModel(pages, pageEntryId, app)
            val pageState by pageVm.state.collectAsStateWithLifecycle()
            val pageDetail = pageState.detail

            when {
                pageDetail == null && pageState.loading -> LoadingBox(Modifier.fillMaxSize())
                pageDetail == null -> ErrorState(
                    message = pageState.error ?: "This article couldn't be loaded.",
                    onRetry = pageVm::load,
                    modifier = Modifier.fillMaxSize()
                )
                else -> ReaderBody(
                    state = pageState,
                    detail = pageDetail,
                    modifier = Modifier.fillMaxSize(),
                    initialScrollPosition = pageVm.scrollPosition,
                    onScrollPositionChanged = { pageVm.scrollPosition = it },
                    highlightQuery = if (showFindInArticle && appliedFind.isNotEmpty() && page == pagerState.currentPage) appliedFind else null,
                    onLink = { ExternalLinks.openInBrowser(context, it) },
                    onOpenEntry = onOpenEntry,
                    onOpenEntity = onOpenEntity,
                    onOpenThread = onOpenThread,
                    onVote = pageVm::vote,
                    onAddTag = { pageVm.loadAllTags(); showTagPicker = true },
                    onNewNote = { editingNote = NoteDraft(null, "", "", false) },
                    onEditNote = { note -> editingNote = NoteDraft(note, note.title.orEmpty(), note.displayText, note.isPinned) },
                    onDeleteNote = pageVm::deleteNote,
                    onRetryNotes = pageVm::retryNotes,
                    onToggleRead = pageVm::toggleRead,
                    onTagClick = onSearchTag,
                    onKeywordClick = onSearchKeyword,
                    onSearchQuery = onSearchQuery,
                    onToggleTranslation = pageVm::toggleShowOriginal
                )
            }
        }
    }

    if (showTextSize) {
        TextSizeDialog(current = activeState.fontSize, onSelect = { activeVm.setFontSize(it); showTextSize = false }, onDismiss = { showTextSize = false })
    }
    if (showVoiceSettings) {
        VoiceSettingsDialog(
            currentRate = speechRate,
            onSelectRate = { scope.launch { app.userPreferences.setTtsSpeechRate(it) } },
            onDismiss = { showVoiceSettings = false }
        )
    }
    if (showCampaignPicker && detail != null) {
        val snackbarHostState = LocalSnackbarHostState.current
        CampaignPickerSheet(
            entryIds = listOf(detail.id),
            repository = app.repository,
            onDismiss = { showCampaignPicker = false },
            onSuccess = { campaignName, _ ->
                scope.launch {
                    snackbarHostState.showSnackbar("Added to $campaignName")
                }
            }
        )
    }
    if (showTagPicker) {
        TagPickerSheet(
            state = activeState,
            onDismiss = { showTagPicker = false },
            onAdd = activeVm::addTag,
            onRemove = activeVm::removeTag,
            onCreate = activeVm::createAndAddTag,
            onDelete = activeVm::deleteTag
        )
    }
    editingNote?.let { draft ->
        NoteEditorSheet(
            draft = draft,
            onDismiss = { editingNote = null },
            onSave = { title, body, pinned, done ->
                activeVm.saveNote(draft.existing, title, body, pinned) { saved -> done(saved); if (saved) editingNote = null }
            }
        )
    }
}

private data class NoteDraft(val existing: EntryNote?, val title: String, val body: String, val pinned: Boolean)

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ReaderBody(
    state: ReaderUiState,
    detail: EntryDetail,
    modifier: Modifier,
    initialScrollPosition: Int = 0,
    onScrollPositionChanged: (Int) -> Unit = {},
    highlightQuery: String? = null,
    onLink: (String) -> Unit,
    onOpenEntry: (String) -> Unit,
    onOpenEntity: (EntityRef) -> Unit,
    onOpenThread: (String, String?) -> Unit,
    onVote: (Int) -> Unit,
    onAddTag: () -> Unit,
    onNewNote: () -> Unit,
    onEditNote: (EntryNote) -> Unit,
    onDeleteNote: (EntryNote) -> Unit,
    onRetryNotes: () -> Unit,
    onToggleRead: () -> Unit,
    onTagClick: (String) -> Unit,
    onKeywordClick: (String) -> Unit,
    onSearchQuery: (String) -> Unit = {},
    onToggleTranslation: () -> Unit = {}
) {
    val context = LocalContext.current
    // The web reader's popovers: a tapped entity name or glossary term.
    var entityPreview by remember { mutableStateOf<EntityPreview?>(null) }
    var glossaryTerm by remember { mutableStateOf<GlossaryTerm?>(null) }

    // Synchronously check memory cache for parsed blocks so returning to an article doesn't reset to loading
    val cachedBlocks = remember(detail.id, detail.contentHtml, state.serverUrl, state.translation, state.showOriginal) {
        if (state.translation != null && !state.showOriginal) {
            state.translation.translatedBlocks
        } else {
            ArticleHtml.getCached(detail, state.serverUrl)
        }
    }
    // Parsing a long article off the main thread keeps the open animation smooth.
    val blocks by produceState<List<ArticleHtml.Block>?>(
        initialValue = cachedBlocks,
        detail.id, detail.contentHtml, state.serverUrl, state.translation, state.showOriginal
    ) {
        if (cachedBlocks != null) {
            value = cachedBlocks
        } else {
            value = withContext(Dispatchers.Default) {
                if (state.translation != null && !state.showOriginal) {
                    state.translation.translatedBlocks
                } else {
                    ArticleHtml.parseBlocks(detail, state.serverUrl)
                }
            }
        }
    }

    // Entity names (and tracked keywords) marked in the text, computed off the main thread once
    // the linked intelligence has loaded; until then the plain text shows.
    val terms = remember(state.glossary, state.intel, state.highlightEntities, state.trackedKeywords, state.pirMatches) {
        // The web marks glossary terms first, then entity names outside them (the "Highlight
        // entities" setting only turns entities off); the app's keywords go last.
        glossaryTerms(state.glossary) +
            (if (state.highlightEntities) state.intel?.let(::entityTerms).orEmpty() else emptyList()) +
            keywordTerms(state.trackedKeywords, state.pirMatches)
    }
    val cachedLinked = remember(blocks, terms) {
        val base = blocks
        if (base == null || terms.isEmpty()) base else ArticleLinker.getCached(base, terms)
    }
    val linked by produceState<List<ArticleHtml.Block>?>(
        initialValue = cachedLinked,
        blocks, terms
    ) {
        val base = blocks
        if (cachedLinked != null) {
            value = cachedLinked
        } else {
            value = if (base == null || terms.isEmpty()) base else withContext(Dispatchers.Default) { ArticleLinker.annotate(base, terms) }
        }
    }
    val parsed = linked ?: blocks

    val restoreTarget = remember(detail.id) { initialScrollPosition }
    val scrollState = rememberSaveable(detail.id, saver = ScrollState.Saver) {
        ScrollState(initial = initialScrollPosition)
    }

    // Current values for the collector below; reading `parsed` directly captured the first
    // composition's value, so once the article was parsed, scrolling back to the top was never saved.
    val articleShown by rememberUpdatedState(parsed != null)
    val reportScroll by rememberUpdatedState(onScrollPositionChanged)
    LaunchedEffect(scrollState) {
        snapshotFlow { scrollState.value }
            .collect { pos ->
                // While the article is still loading the page is short and the position is clamped
                // to 0; don't overwrite the saved position with that.
                if (pos > 0 || articleShown) reportScroll(pos)
            }
    }

    LaunchedEffect(detail.id, parsed != null) {
        if (parsed != null && restoreTarget > 0 && scrollState.value < restoreTarget) {
            if (scrollState.maxValue < restoreTarget) {
                snapshotFlow { scrollState.maxValue }
                    .filter { it >= restoreTarget || it > 0 }
                    .first()
            }
            val target = restoreTarget.coerceAtMost(scrollState.maxValue)
            if (target > scrollState.value) {
                scrollState.scrollTo(target)
            }
        }
    }

    var noteToDelete by remember { mutableStateOf<EntryNote?>(null) }

    entityPreview?.let { preview ->
        EntityPreviewSheet(
            preview = preview,
            onProfile = {
                entityPreview = null
                onScrollPositionChanged(scrollState.value)
                onOpenEntity(EntityRef(preview.type, preview.id, preview.name))
            },
            onSearch = { entityPreview = null; onKeywordClick(preview.value) },
            onCopy = { entityPreview = null; Clipboard.copy(context, preview.type.label, preview.value) },
            onLink = onLink,
            onDismiss = { entityPreview = null }
        )
    }
    glossaryTerm?.let { term ->
        GlossarySheet(
            term = term,
            onSearchArticles = { glossaryTerm = null; onSearchQuery(glossarySearchQuery(term)) },
            onLink = onLink,
            onDismiss = { glossaryTerm = null }
        )
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(horizontal = 18.dp, vertical = 8.dp)
    ) {
        detail.echoOf?.let { echo ->
            Surface(
                color = SlateDark700,
                shape = RoundedCornerShape(10.dp),
                modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp).clip(RoundedCornerShape(10.dp)).clickable {
                    onScrollPositionChanged(scrollState.value)
                    onOpenEntry(echo.entryId)
                }
            ) {
                Column(Modifier.padding(12.dp)) {
                    Text("This is a re-report", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
                    Text(
                        text = "${echo.feedTitle ?: "Another source"} published it first" +
                            (if (echo.total > 0) " (they share ${echo.shared} of ${echo.total} entities)" else "") + ". Tap to read the original.",
                        fontSize = 13.sp,
                        color = TextSecondary
                    )
                }
            }
        }

        val titleText = if (state.translation != null && !state.showOriginal) {
            state.translation.translatedTitle
        } else {
            detail.translatedTitle ?: detail.title
        }
        Text(titleText, fontSize = 23.sp, fontWeight = FontWeight.Bold, color = TextPrimary, lineHeight = 30.sp)
        Spacer(Modifier.height(8.dp))
        val meta = listOfNotNull(
            detail.author?.takeIf { it.isNotBlank() }?.let { "By $it" },
            detail.publishedAt?.let { DateUtils.formatRelativeTime(it) }?.takeIf { it.isNotBlank() },
            DateUtils.readingMinutes(detail.wordCount)?.let { "$it min read" }
        )
        if (meta.isNotEmpty()) Text(meta.joinToString("  ·  "), fontSize = 13.sp, color = TextMuted)

        // Translation status banner / pill
        val tr = state.translation
        if (tr != null) {
            Spacer(Modifier.height(8.dp))
            Pill(
                label = if (state.showOriginal) "Show ${tr.targetLanguageName} translation" else "Translated from ${tr.sourceLanguageName} · Show original",
                color = CyberBlue,
                leadingIcon = Icons.Default.Translate,
                onClick = onToggleTranslation
            )
        } else if (state.isTranslating) {
            Spacer(Modifier.height(8.dp))
            Pill(
                label = "Translating to ${state.targetLanguageName} on-device…",
                color = CyberBlue,
                leadingIcon = Icons.Default.Translate
            )
        }

        // Tags
        Spacer(Modifier.height(10.dp))
        FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            // Read state, visible and one tap to reverse. Says so when opening the article marked
            // it read (Settings › Auto-mark as read on open).
            when {
                !detail.isRead -> Pill("Unread · mark read", CyberBlue, leadingIcon = Icons.Default.MarkEmailUnread, onClick = onToggleRead)
                state.autoMarkedRead -> Pill("Marked read on open · undo", TextSecondary, leadingIcon = Icons.Default.MarkEmailRead, onClick = onToggleRead)
                else -> Pill("Read · mark unread", TextSecondary, leadingIcon = Icons.Default.MarkEmailRead, onClick = onToggleRead)
            }
            state.tags.forEach { tag -> Pill("#${tag.name}", tagColor(tag.color), onClick = { onTagClick(tag.name) }) }
            Pill(if (state.tags.isEmpty()) "Add tag" else "Edit tags", TextSecondary, leadingIcon = Icons.Default.Tag, onClick = onAddTag)
        }

        // Why it's ranked
        val signals = detail.prioritySignals.ifEmpty { detail.topSignals }
        if (detail.priorityScore != null || signals.isNotEmpty()) {
            Spacer(Modifier.height(14.dp))
            WhyCard(score = detail.priorityScore, signals = signals, vote = state.radarVote, onVote = onVote)
        }

        if (state.pirMatches.isNotEmpty()) {
            Spacer(Modifier.height(14.dp))
            PirMatchesCard(state.pirMatches)
        }

        // Linked intelligence
        val intel = state.intel
        if (intel == null) {
            Spacer(Modifier.height(14.dp))
            Text("Loading linked intelligence…", fontSize = 12.sp, color = TextMuted)
        } else if (!intel.isEmpty) {
            Spacer(Modifier.height(14.dp))
            IntelPanel(intel) { ref ->
                onScrollPositionChanged(scrollState.value)
                onOpenEntity(ref)
            }
        }

        Spacer(Modifier.height(18.dp))
        HorizontalDivider(color = SlateDark700)
        Spacer(Modifier.height(16.dp))

        when {
            parsed == null -> Text("Loading article…", color = TextMuted, fontSize = 13.sp)
            parsed.isEmpty() -> Text("This article has no text. Open the original to read it.", color = TextMuted, fontSize = 14.sp)
            else -> {
                if (detail.imageUrl != null && parsed.none { it is ArticleHtml.Image }) {
                    AsyncImage(
                        model = detail.imageUrl,
                        contentDescription = null,
                        contentScale = ContentScale.FillWidth,
                        modifier = Modifier.fillMaxWidth().heightIn(max = 260.dp).clip(RoundedCornerShape(10.dp))
                    )
                    Spacer(Modifier.height(14.dp))
                }
                ArticleContent(
                    blocks = parsed,
                    fontSize = state.fontSize,
                    onLinkClick = onLink,
                    highlightQuery = highlightQuery,
                    onEntityClick = { mark ->
                        val type = EntityType.fromKey(mark.type)
                        val preview = type?.let { EntityPreviews.build(state.intel, it, mark.id, mark.name, mark.text) }
                        when {
                            preview != null -> entityPreview = preview
                            type != null -> {
                                onScrollPositionChanged(scrollState.value)
                                onOpenEntity(EntityRef(type, mark.id, mark.name))
                            }
                        }
                    },
                    onKeywordClick = onKeywordClick,
                    onGlossaryClick = { id -> glossaryTerm = state.glossary.firstOrNull { it.term.id == id }?.term }
                )
            }
        }


        detail.url?.takeIf { it.isNotBlank() }?.let { url ->
            Spacer(Modifier.height(20.dp))
            OutlinedButton(onClick = { ExternalLinks.openInBrowser(context, url) }, modifier = Modifier.fillMaxWidth()) {
                Icon(Icons.AutoMirrored.Filled.OpenInNew, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text("Read the original on ${hostOf(url)}")
            }
        }

        // Notes
        SectionHeader(
            text = "Notes" + if (state.notes.isNotEmpty()) " (${state.notes.size})" else "",
            modifier = Modifier.padding(top = 12.dp),
            trailing = {
                TextButton(onClick = onNewNote) {
                    Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("Add note")
                }
            }
        )
        when {
            state.notesLoading && state.notes.isEmpty() -> Text("Loading notes…", color = TextMuted, fontSize = 13.sp)
            state.notesError != null -> Row(verticalAlignment = Alignment.CenterVertically) {
                Text(state.notesError, color = CyberAmber, fontSize = 13.sp, modifier = Modifier.weight(1f))
                TextButton(onClick = onRetryNotes) { Text("Retry") }
            }
            state.notes.isEmpty() -> Text(
                "No notes yet. Notes are visible to everyone on your IntelFeed server.",
                color = TextMuted,
                fontSize = 13.sp
            )
            else -> Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                state.notes.forEach { note ->
                    NoteCard(
                        title = note.title,
                        body = note.displayText,
                        author = note.creatorUsername,
                        time = note.updatedAt ?: note.createdAt,
                        pinned = note.isPinned,
                        canEdit = state.canEdit(note),
                        onEdit = { onEditNote(note) },
                        onDelete = { noteToDelete = note }
                    )
                }
            }
        }

        // Similar coverage
        if (state.similar.isNotEmpty()) {
            SectionHeader("Similar coverage")
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                state.similar.forEach { item ->
                    CardSurface(modifier = Modifier.clip(RoundedCornerShape(12.dp)).clickable {
                        onScrollPositionChanged(scrollState.value)
                        onOpenEntry(item.id)
                    }) {
                        Column(Modifier.padding(12.dp)) {
                            Text(item.title, fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = TextPrimary, maxLines = 2, overflow = TextOverflow.Ellipsis)
                            Spacer(Modifier.height(4.dp))
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    listOfNotNull(item.feedTitle, DateUtils.formatRelativeTime(item.publishedAt).takeIf { it.isNotBlank() }).joinToString(" · "),
                                    fontSize = 12.sp, color = TextMuted, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f)
                                )
                                item.similarity?.let { Text("${(it * 100).toInt()}% similar", fontSize = 12.sp, color = CyberPurple) }
                            }
                            val slug = item.threadSlug
                            if (slug != null) {
                                Spacer(Modifier.height(6.dp))
                                Pill("Part of a story", CyberPurple, leadingIcon = Icons.Default.AutoStories, onClick = {
                                    onScrollPositionChanged(scrollState.value)
                                    onOpenThread(slug, item.threadTitle)
                                })
                            }
                        }
                    }

                }
            }
        }
        Spacer(Modifier.height(32.dp))
    }

    noteToDelete?.let { note ->
        AlertDialog(
            onDismissRequest = { noteToDelete = null },
            title = { Text("Delete this note?") },
            text = { Text("It's removed for everyone on the server.") },
            confirmButton = { TextButton(onClick = { onDeleteNote(note); noteToDelete = null }) { Text("Delete", color = CyberRed) } },
            dismissButton = { TextButton(onClick = { noteToDelete = null }) { Text("Cancel") } }
        )
    }
}

/** The ReaderViewModel for one article, kept in that article's own store (see ReaderPages). */
@Composable
private fun readerViewModel(pages: ReaderPages, entryId: String, app: IntelFeedApplication): ReaderViewModel =
    viewModel(viewModelStoreOwner = pages.owner(entryId), key = entryId) {
        ReaderViewModel(entryId, app.repository, app.userPreferences, app.messenger, pages.autoReadIds)
    }

private fun hostOf(url: String): String = runCatching { java.net.URI(url).host?.removePrefix("www.") }.getOrNull() ?: "the source"

private fun articleBlocks(detail: EntryDetail, serverUrl: String?): List<ArticleHtml.Block> =
    ArticleHtml.parseBlocks(detail, serverUrl)

@Composable
private fun WhyCard(score: Double?, signals: List<Signal>, vote: Int, onVote: (Int) -> Unit) {
    var expanded by rememberSaveable { mutableStateOf(false) }
    CardSurface(modifier = Modifier.animateContentSize()) {
        Column(Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth().clickable { expanded = !expanded }) {
                Text("Why this is ranked", fontSize = 14.sp, fontWeight = FontWeight.Bold, color = TextPrimary, modifier = Modifier.weight(1f))
                score?.let { ScoreBadge(it) }
            }
            val shown = if (expanded) signals else signals.take(2)
            if (shown.isEmpty()) {
                Text("No individual signals were recorded for this article.", fontSize = 13.sp, color = TextMuted, modifier = Modifier.padding(top = 6.dp))
            }
            val maxWeight = signals.mapNotNull { it.weighted }.maxOrNull()?.takeIf { it > 0 }
            shown.forEach { signal ->
                val family = signal.family ?: familyOf(signal.type)
                Column(Modifier.padding(top = 10.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Pill(signalLabel(signal.type), signalFamilyColor(family))
                        family?.let {
                            Spacer(Modifier.width(6.dp))
                            Text(it.replaceFirstChar { c -> c.titlecase(Locale.US) }, fontSize = 11.sp, color = TextMuted)
                        }
                        Spacer(Modifier.weight(1f))
                        signal.weighted?.let { Text("+" + String.format(Locale.US, "%.2f", it), fontSize = 11.sp, color = TextMuted) }
                    }
                    if (signal.explanation.isNotBlank()) {
                        Spacer(Modifier.height(4.dp))
                        Text(signal.explanation, fontSize = 13.sp, color = TextSecondary, lineHeight = 18.sp)
                    }
                    if (maxWeight != null && signal.weighted != null) {
                        Spacer(Modifier.height(4.dp))
                        Box(Modifier.fillMaxWidth().height(3.dp).clip(RoundedCornerShape(2.dp)).background(SlateDark600)) {
                            Box(Modifier.fillMaxWidth((signal.weighted / maxWeight).toFloat().coerceIn(0.05f, 1f)).height(3.dp).background(signalFamilyColor(family)))
                        }
                    }
                }
            }
            if (signals.size > 2) {
                TextButton(onClick = { expanded = !expanded }, modifier = Modifier.padding(top = 4.dp)) {
                    Text(if (expanded) "Show less" else "Show all ${signals.size} signals")
                }
            }
            HorizontalDivider(color = SlateDark600, modifier = Modifier.padding(vertical = 8.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Worth your attention?", fontSize = 13.sp, color = TextSecondary, modifier = Modifier.weight(1f))
                IconButton(onClick = { onVote(1) }) {
                    Icon(Icons.Default.ThumbUp, contentDescription = "Useful", tint = if (vote == 1) CyberGreen else TextMuted, modifier = Modifier.size(20.dp))
                }
                IconButton(onClick = { onVote(-1) }) {
                    Icon(Icons.Default.ThumbDown, contentDescription = "Noise", tint = if (vote == -1) CyberRed else TextMuted, modifier = Modifier.size(20.dp))
                }
            }
        }
    }
}

/** The web reader's "PIR Matches": which intelligence requirements this article answers, and why. */
@Composable
private fun PirMatchesCard(matches: List<PirMatch>) {
    CardSurface {
        Column(Modifier.padding(14.dp)) {
            Text("Matches your intelligence requirements", fontSize = 14.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
            matches.forEach { m ->
                Row(verticalAlignment = Alignment.Top, modifier = Modifier.padding(top = 8.dp)) {
                    val color = when (m.priority?.lowercase()) {
                        "critical" -> CyberRed
                        "high" -> CyberAmber
                        else -> CyberBlue
                    }
                    Pill(m.priority?.replaceFirstChar { it.titlecase(Locale.US) } ?: "PIR", color)
                    Spacer(Modifier.width(8.dp))
                    Column(Modifier.weight(1f)) {
                        Text(m.title, fontSize = 13.sp, color = TextPrimary, fontWeight = FontWeight.SemiBold)
                        val why = listOfNotNull(
                            m.matchType?.let { type -> m.matchedOn?.let { "$type: $it" } },
                            m.relevance?.let { "$it relevance" }
                        ).joinToString(" · ")
                        if (why.isNotEmpty()) Text(why, fontSize = 12.sp, color = TextMuted)
                    }
                }
            }
        }
    }
}

private data class IntelChip(val label: String, val ref: EntityRef, val color: Color)

private data class IntelGroup(val title: String, val type: EntityType, val chips: List<IntelChip>)

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun IntelPanel(intel: EntryIntel, onOpenEntity: (EntityRef) -> Unit) {
    val context = LocalContext.current
    val groups = remember(intel) {
        fun group(title: String, type: EntityType, chips: List<IntelChip>) = IntelGroup(title, type, chips)
        fun chip(type: EntityType, label: String, id: String, name: String, color: Color = type.color()) =
            IntelChip(label, EntityRef(type, id, name), color)
        // Known-exploited first, then by CVSS, so the CVEs that matter lead the list.
        val cves = intel.cves.sortedWith(compareByDescending<Cve> { it.isKev }.thenByDescending { it.cvssScore?.toDoubleOrNull() ?: 0.0 })
        listOf(
            group("Threat actors", EntityType.THREAT_ACTOR, intel.threatActors.map { chip(EntityType.THREAT_ACTOR, it.name, it.id, it.name) }),
            group("Malware", EntityType.MALWARE, intel.malware.map { chip(EntityType.MALWARE, it.name, it.id, it.name) }),
            group("Vulnerabilities", EntityType.CVE, cves.map { c ->
                val color = if (c.isKev) CyberRed else cvssTone(c.cvssScore?.toDoubleOrNull()).color()
                chip(EntityType.CVE, if (c.isKev) "${c.cveId} · KEV" else c.cveId, c.cveId, c.cveId, color)
            }),
            group("Techniques", EntityType.TTP, intel.ttps.map { t ->
                chip(EntityType.TTP, "${t.techniqueId} ${t.techniqueName.orEmpty()}".trim(), t.techniqueId, t.techniqueId)
            }),
            group("Tools", EntityType.TOOL, intel.tools.map { chip(EntityType.TOOL, it.name, it.id, it.name) }),
            group("Vendors", EntityType.VENDOR, intel.vendors.map { chip(EntityType.VENDOR, it.name, it.id, it.name) }),
            group("Products", EntityType.PRODUCT, intel.products.map { chip(EntityType.PRODUCT, it.name, it.id, it.name) }),
            group("Countries", EntityType.COUNTRY, intel.countries.map { c ->
                chip(EntityType.COUNTRY, if (c.role != null && c.role != "mentioned") "${c.name} · ${c.role}" else c.name, c.id, c.name)
            }),
            // Also fetched for the web reader's highlighting (GET /api/entries/{id}/cwes, /mitigations, /observables).
            group("Weaknesses", EntityType.WEAKNESS, intel.cwes.map { chip(EntityType.WEAKNESS, it.cweId, it.cweId, it.displayTitle) }),
            group("Mitigations", EntityType.MITIGATION, intel.mitigations.map { m ->
                chip(EntityType.MITIGATION, listOfNotNull(m.mitreId, m.name).joinToString(" "), m.id, m.name)
            }),
            group("Observables", EntityType.OBSERVABLE, intel.observables.map { chip(EntityType.OBSERVABLE, it.value, it.id, it.value) })
        ).filter { it.chips.isNotEmpty() }
    }
    CardSurface {
        Column(Modifier.padding(14.dp)) {
            Text("Linked intelligence", fontSize = 14.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
            Text("${intel.count} entities found in this article. Tap to view profile, long-press to copy.", fontSize = 12.sp, color = TextMuted)
            groups.forEach { group ->
                var showAll by rememberSaveable(group.title) { mutableStateOf(false) }
                val limit = 10
                Spacer(Modifier.height(10.dp))
                Text(group.title, fontSize = 12.sp, fontWeight = FontWeight.SemiBold, color = TextSecondary)
                Spacer(Modifier.height(6.dp))
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    val visible = if (showAll) group.chips else group.chips.take(limit)
                    visible.forEach { chip ->
                        Pill(
                            label = chip.label,
                            color = chip.color,
                            monospace = group.type in setOf(EntityType.CVE, EntityType.TTP, EntityType.WEAKNESS, EntityType.OBSERVABLE),
                            onClick = { onOpenEntity(chip.ref) },
                            onLongClick = {
                                val copyText = chip.ref.name.ifBlank { chip.ref.id }
                                Clipboard.copy(context, group.type.label, copyText)
                            }
                        )
                    }
                    if (group.chips.size > limit) {
                        Pill(if (showAll) "Show fewer" else "+${group.chips.size - limit} more", TextSecondary, onClick = { showAll = !showAll })
                    }
                }
            }
        }
    }
}

@Composable
fun NoteCard(
    title: String?,
    body: String,
    author: String?,
    time: String?,
    pinned: Boolean,
    canEdit: Boolean,
    onEdit: () -> Unit,
    onDelete: () -> Unit,
    modifier: Modifier = Modifier
) {
    CardSurface(modifier = modifier) {
        Column(Modifier.padding(start = 12.dp, top = 10.dp, bottom = 10.dp, end = 4.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (pinned) {
                    Icon(Icons.Default.PushPin, contentDescription = "Pinned", tint = CyberAmber, modifier = Modifier.size(14.dp))
                    Spacer(Modifier.width(4.dp))
                }
                Text(
                    text = title?.takeIf { it.isNotBlank() } ?: "Note",
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold,
                    color = TextPrimary,
                    modifier = Modifier.weight(1f),
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
                if (canEdit) {
                    IconButton(onClick = onEdit) { Icon(Icons.Default.Edit, contentDescription = "Edit note", tint = TextMuted, modifier = Modifier.size(18.dp)) }
                    IconButton(onClick = onDelete) { Icon(Icons.Default.DeleteOutline, contentDescription = "Delete note", tint = TextMuted, modifier = Modifier.size(18.dp)) }
                }
            }
            if (body.isNotBlank() && body != title) {
                Spacer(Modifier.height(4.dp))
                Text(body, fontSize = 14.sp, color = TextSecondary, lineHeight = 20.sp, modifier = Modifier.padding(end = 8.dp))
            }
            val meta = listOfNotNull(author?.let { "@$it" }, time?.let { DateUtils.formatRelativeTime(it) }?.takeIf { it.isNotBlank() })
            if (meta.isNotEmpty()) {
                Spacer(Modifier.height(6.dp))
                Text(meta.joinToString(" · "), fontSize = 12.sp, color = TextMuted)
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun NoteEditorSheet(
    draft: NoteDraft,
    onDismiss: () -> Unit,
    onSave: (title: String, body: String, pinned: Boolean, done: (Boolean) -> Unit) -> Unit
) {
    NoteEditor(
        heading = if (draft.existing == null) "New note" else "Edit note",
        initialTitle = draft.title,
        initialBody = draft.body,
        initialPinned = draft.pinned,
        showPin = true,
        hint = "Visible to everyone on your IntelFeed server.",
        onDismiss = onDismiss,
        onSave = onSave
    )
}

/** Bottom-sheet note editor shared by article notes and entity notes. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NoteEditor(
    heading: String,
    initialTitle: String,
    initialBody: String,
    initialPinned: Boolean,
    showPin: Boolean,
    hint: String,
    onDismiss: () -> Unit,
    onSave: (title: String, body: String, pinned: Boolean, done: (Boolean) -> Unit) -> Unit
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    var title by rememberSaveable { mutableStateOf(initialTitle) }
    var body by rememberSaveable { mutableStateOf(initialBody) }
    var pinned by rememberSaveable { mutableStateOf(initialPinned) }
    var saving by remember { mutableStateOf(false) }
    val fieldColors = OutlinedTextFieldDefaults.colors(
        focusedBorderColor = CyberCyan,
        unfocusedBorderColor = SlateDark600,
        focusedTextColor = TextPrimary,
        unfocusedTextColor = TextPrimary,
        cursorColor = CyberCyan
    )
    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = sheetState, containerColor = SlateDark800) {
        Column(Modifier.fillMaxWidth().padding(horizontal = 20.dp).imePadding().navigationBarsPadding().padding(bottom = 16.dp)) {
            Text(heading, fontSize = 18.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
            Text(hint, fontSize = 12.sp, color = TextMuted)
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = title,
                onValueChange = { title = it },
                label = { Text("Title (optional)") },
                singleLine = true,
                colors = fieldColors,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = body,
                onValueChange = { body = it },
                label = { Text("Note") },
                placeholder = { Text("Observations, IOCs, attribution, next steps…", color = TextMuted) },
                minLines = 5,
                colors = fieldColors,
                modifier = Modifier.fillMaxWidth()
            )
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(top = 8.dp)) {
                if (showPin) {
                    Switch(checked = pinned, onCheckedChange = { pinned = it })
                    Spacer(Modifier.width(8.dp))
                    Text("Pin to top", color = TextSecondary, fontSize = 14.sp, modifier = Modifier.weight(1f))
                } else {
                    Spacer(Modifier.weight(1f))
                }
                TextButton(onClick = onDismiss) { Text("Cancel") }
                Spacer(Modifier.width(4.dp))
                FilledTonalButton(
                    enabled = body.isNotBlank() && !saving,
                    onClick = {
                        saving = true
                        onSave(title, body, pinned) { saving = false }
                    }
                ) { Text(if (saving) "Saving…" else "Save") }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
private fun TagPickerSheet(
    state: ReaderUiState,
    onDismiss: () -> Unit,
    onAdd: (TagEntity) -> Unit,
    onRemove: (TagEntity) -> Unit,
    onCreate: (String) -> Unit,
    onDelete: (TagEntity) -> Unit
) {
    var query by rememberSaveable { mutableStateOf("") }
    var tagToDelete by remember { mutableStateOf<TagEntity?>(null) }
    val applied = state.tags.mapNotNull { it.id }.toSet()
    val matches = state.allTags.filter { query.isBlank() || it.name.contains(query.trim(), ignoreCase = true) }
    val exact = state.allTags.any { it.name.equals(query.trim(), ignoreCase = true) }
    ModalBottomSheet(onDismissRequest = onDismiss, containerColor = SlateDark800) {
        Column(Modifier.fillMaxWidth().padding(horizontal = 20.dp).imePadding().navigationBarsPadding().padding(bottom = 16.dp)) {
            Text("Tags", fontSize = 18.sp, fontWeight = FontWeight.Bold, color = TextPrimary)
            Text("Tags are shared across your IntelFeed server. Tap to add/remove, long-press to delete.", fontSize = 12.sp, color = TextMuted)
            Spacer(Modifier.height(10.dp))
            if (state.tags.isNotEmpty()) {
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    state.tags.forEach { tag -> Pill("#${tag.name}  ✕", tagColor(tag.color), onClick = { onRemove(tag) }) }
                }
                Spacer(Modifier.height(12.dp))
            }
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                placeholder = { Text("Find or create a tag", color = TextMuted) },
                singleLine = true,
                leadingIcon = { Icon(Icons.Default.Tag, contentDescription = null, tint = TextMuted) },
                trailingIcon = if (query.isNotEmpty()) { { IconButton(onClick = { query = "" }) { Icon(Icons.Default.Close, contentDescription = "Clear") } } } else null,
                colors = OutlinedTextFieldDefaults.colors(focusedTextColor = TextPrimary, unfocusedTextColor = TextPrimary, focusedBorderColor = CyberBlue),
                modifier = Modifier.fillMaxWidth()
            )
            if (query.isNotBlank() && !exact) {
                TextButton(onClick = { onCreate(query); query = "" }) {
                    Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("Create \"${query.trim().lowercase().replace(Regex("\\s+"), "-")}\"")
                }
            }
            Spacer(Modifier.height(8.dp))
            if (state.allTagsLoading) {
                Text("Loading tags…", color = TextMuted, fontSize = 13.sp)
            } else {
                Column(Modifier.heightIn(max = 320.dp).verticalScroll(rememberScrollState())) {
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        matches.filter { it.id !in applied }.forEach { tag ->
                            Pill(
                                label = "#${tag.name}" + (tag.entryCount?.let { " · $it" } ?: ""),
                                color = tagColor(tag.color),
                                onClick = { onAdd(tag) },
                                onLongClick = { tagToDelete = tag }
                            )
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
            onDismissRequest = { tagToDelete = null },
            title = { Text("Delete tag \"#${tag.name}\"?") },
            text = { Text("This will permanently delete this tag from the server and remove it from $countText. This action cannot be undone.") },
            confirmButton = {
                TextButton(onClick = {
                    val toDelete = tag
                    tagToDelete = null
                    onDelete(toDelete)
                }) {
                    Text("Delete", color = CyberRed)
                }
            },
            dismissButton = {
                TextButton(onClick = { tagToDelete = null }) {
                    Text("Cancel")
                }
            }
        )
    }
}

@Composable
private fun TextSizeDialog(current: ReaderFontSize, onSelect: (ReaderFontSize) -> Unit, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Text size") },
        text = {
            Column {
                ReaderFontSize.entries.forEach { size ->
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier
                            .fillMaxWidth()
                            .selectable(selected = size == current, onClick = { onSelect(size) }, role = Role.RadioButton)
                            .padding(vertical = 4.dp)
                    ) {
                        RadioButton(selected = size == current, onClick = null)
                        Spacer(Modifier.width(12.dp))
                        Text(size.label, fontSize = size.size)
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text("Done") } }
    )
}

private fun countOccurrences(text: String, query: String): Int {
    if (query.isBlank()) return 0
    var count = 0
    var index = text.indexOf(query, ignoreCase = true)
    while (index >= 0) {
        count++
        index = text.indexOf(query, index + query.length, ignoreCase = true)
    }
    return count
}
