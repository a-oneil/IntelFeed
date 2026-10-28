package com.example.intelfeed.ui.reader

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.intelfeed.data.local.UserPreferences
import com.example.intelfeed.data.model.EntryDetail
import com.example.intelfeed.data.model.EntryIntel
import com.example.intelfeed.data.model.EntryNote
import com.example.intelfeed.data.model.PirMatch
import com.example.intelfeed.data.model.SimilarEntry
import com.example.intelfeed.data.model.TagEntity
import com.example.intelfeed.data.model.UserProfile
import com.example.intelfeed.data.repository.IntelFeedRepository
import com.example.intelfeed.ui.ErrorText
import com.example.intelfeed.ui.UiMessenger
import com.example.intelfeed.util.ArticleHtml
import com.example.intelfeed.util.ArticleTranslator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class ReaderUiState(
    val detail: EntryDetail? = null,
    val loading: Boolean = true,
    val error: String? = null,
    val intel: EntryIntel? = null,
    // Glossary terms found in the article (POST /api/glossary/detect), underlined like on the web.
    val glossary: List<com.example.intelfeed.data.model.GlossaryMatch> = emptyList(),
    val notes: List<EntryNote> = emptyList(),
    val notesLoading: Boolean = false,
    val notesError: String? = null,
    val tags: List<TagEntity> = emptyList(),
    // Every tag on the instance, loaded when the tag picker opens.
    val allTags: List<TagEntity> = emptyList(),
    val allTagsLoading: Boolean = false,
    val similar: List<SimilarEntry> = emptyList(),
    // This session's Priority Queue feedback: 1 useful, -1 noise, 0 none.
    val radarVote: Int = 0,
    val currentUser: UserProfile? = null,
    val fontSize: ReaderFontSize = ReaderFontSize.MEDIUM,
    val serverUrl: String? = null,
    // True when opening the article marked it read (the "auto-mark as read" setting), so the
    // reader can say so and offer to undo it.
    val autoMarkedRead: Boolean = false,
    // Settings › Highlight entities in articles.
    val highlightEntities: Boolean = true,
    // Intelligence requirements this article matched (POST /api/entries/intel-counts), as on the web reader.
    val pirMatches: List<PirMatch> = emptyList(),
    // On-device neural translation state
    val translation: ArticleTranslator.TranslationResult? = null,
    val isTranslating: Boolean = false,
    val showOriginal: Boolean = false,
    val translationError: String? = null,
    val targetLanguage: String = "en",
    val targetLanguageName: String = "English"
) {
    /** Notes are shared across the instance; only the author or an admin may change one. */
    fun canEdit(note: EntryNote): Boolean {
        val user = currentUser ?: return false
        return user.role.equals("admin", ignoreCase = true) || (note.createdBy != null && note.createdBy == user.id)
    }
}

/**
 * One article. Scoped to its back-stack entry, so each open article keeps its own state.
 *
 * The reader pager builds a ViewModel for the article on screen and for its neighbours (so a swipe
 * shows text immediately). Creating one only loads the article itself. Marking it read and loading
 * the side panels (linked intelligence, notes, similar coverage) wait for [activate], which the
 * screen calls once the page is actually on screen.
 */
class ReaderViewModel(
    private val entryId: String,
    private val repository: IntelFeedRepository,
    private val userPreferences: UserPreferences,
    private val messenger: UiMessenger,
    // Articles already auto-marked read, shared by the reader's pages (ReaderPages.autoReadIds).
    private val autoReadIds: MutableSet<String> = HashSet()
) : ViewModel() {

    private val _state = MutableStateFlow(ReaderUiState())
    val state: StateFlow<ReaderUiState> = _state.asStateFlow()

    // Retains vertical scroll offset across navigation (e.g. tapping an entity profile and returning).
    var scrollPosition: Int = 0

    // True once the page has been on screen; the side panels then load and stay loaded.
    private var active = false
    private var panelsLoaded = false
    // Set once the user adds or removes a tag, so a slower tag load can't overwrite their change.
    private var tagsEdited = false

    init {
        viewModelScope.launch {
            repository.currentUser.collect { user -> _state.update { it.copy(currentUser = user) } }
        }
        viewModelScope.launch {
            userPreferences.highlightEntities.collect { on -> _state.update { it.copy(highlightEntities = on) } }
        }
        viewModelScope.launch {
            userPreferences.readerTextSize.collect { name ->
                _state.update { it.copy(fontSize = ReaderFontSize.fromName(name)) }
            }
        }
        viewModelScope.launch {
            userPreferences.translateTargetLanguage.collect { lang ->
                val name = ArticleTranslator.languageDisplayName(lang)
                _state.update { it.copy(targetLanguage = lang, targetLanguageName = name) }
            }
        }
        viewModelScope.launch {
            repository.entryUpdates.collect { u ->
                if (u.id != entryId) return@collect
                _state.update { s ->
                    s.copy(detail = s.detail?.let { d ->
                        d.copy(
                            isRead = u.isRead ?: d.isRead,
                            isStarred = u.isStarred ?: d.isStarred,
                            isBookmarked = u.isBookmarked ?: d.isBookmarked
                        )
                    })
                }
            }
        }
        // Suspending calls run before update {}: update retries its lambda when the state changed
        // meanwhile, which re-sent the request (the eight linked-intel calls went out twice).
        viewModelScope.launch {
            val url = repository.currentServerUrl()
            _state.update { it.copy(serverUrl = url) }
        }
        load()
    }

    fun load() {
        _state.update { it.copy(loading = true, error = null) }
        viewModelScope.launch {
            repository.getEntryDetail(entryId).fold(
                onSuccess = { detail ->
                    _state.update { it.copy(detail = detail, tags = detail.tags, loading = false) }
                    if (active) onVisible()
                },
                onFailure = { error ->
                    _state.update { it.copy(loading = false, error = ErrorText.describe(error)) }
                }
            )
        }
    }

    /** The page is on screen (settled in the pager). Safe to call repeatedly. */
    fun activate() {
        active = true
        if (_state.value.detail != null) onVisible()
    }

    private fun onVisible() {
        val detail = _state.value.detail ?: return
        // At most once per article while the reader is open (the page's ViewModel may be cleared
        // and re-created), so reading an article again after marking it unread by hand doesn't
        // flip it back.
        if (autoReadIds.add(entryId)) {
            if (!detail.isRead) {
                viewModelScope.launch {
                    if (userPreferences.autoMarkRead.first()) {
                        repository.setRead(entryId, true).onSuccess { _state.update { it.copy(autoMarkedRead = true) } }
                    }
                }
            }
        }
        if (panelsLoaded) return
        panelsLoaded = true
        viewModelScope.launch {
            val intel = repository.getEntryIntel(entryId)
            _state.update { it.copy(intel = intel) }
        }
        viewModelScope.launch {
            repository.detectGlossary(entryId).onSuccess { matches ->
                if (matches.isNotEmpty()) _state.update { it.copy(glossary = matches) }
            }
        }
        viewModelScope.launch { loadNotes() }
        viewModelScope.launch {
            val matches = repository.getIntelCounts(listOf(entryId))[entryId]?.pirMatches.orEmpty()
            if (matches.isNotEmpty()) _state.update { it.copy(pirMatches = matches) }
        }
        // The article's tags come from GET /api/tags/entries/{id}, as on the web. The detail's own
        // `tags` field can be empty for an article that has tags (seen on the live server), which
        // made the reader show "Add tag" on tagged articles.
        viewModelScope.launch {
            repository.getEntryTags(entryId).onSuccess { tags ->
                if (!tagsEdited) _state.update { it.copy(tags = tags) }
            }
        }
        viewModelScope.launch {
            repository.getSimilarEntries(entryId).onSuccess { list ->
                _state.update { it.copy(similar = list.filter { s -> s.id != entryId }.take(8)) }
            }
        }
        viewModelScope.launch {
            // Read the setting itself: the state's targetLanguage may not have been collected yet.
            val targetLang = userPreferences.translateTargetLanguage.first()
            ArticleTranslator.getCached(entryId, targetLang)?.let { cached ->
                _state.update { it.copy(translation = cached) }
            }
            if (userPreferences.autoTranslate.first() && _state.value.translation == null) {
                translate(silent = true)
            }
        }
    }

    fun translate(silent: Boolean = false) {
        val detail = _state.value.detail ?: return
        if (_state.value.isTranslating) return
        _state.update { it.copy(isTranslating = true, translationError = null) }
        viewModelScope.launch {
            val targetLang = userPreferences.translateTargetLanguage.first()
            val blocks = withContext(Dispatchers.Default) { ArticleHtml.parseBlocks(detail, _state.value.serverUrl) }
            ArticleTranslator.translateArticle(
                entryId = entryId,
                title = detail.title,
                blocks = blocks,
                targetLang = targetLang
            ).fold(
                onSuccess = { result ->
                    _state.update { it.copy(translation = result, isTranslating = false, showOriginal = false) }
                },
                onFailure = { error ->
                    val msg = error.message ?: "Translation failed"
                    _state.update {
                        it.copy(
                            isTranslating = false,
                            translationError = if (silent) null else msg
                        )
                    }
                    if (!silent) {
                        messenger.show(msg)
                    }
                }
            )
        }
    }

    fun toggleShowOriginal() {
        _state.update { it.copy(showOriginal = !it.showOriginal) }
    }

    // FLAGS (the repository broadcasts, and the collector above updates the detail)

    fun toggleRead() {
        val d = _state.value.detail ?: return
        _state.update { it.copy(autoMarkedRead = false) }
        viewModelScope.launch { repository.setRead(entryId, !d.isRead).onFailure { messenger.showError("update read status", it) } }
    }

    fun toggleStar() {
        val d = _state.value.detail ?: return
        viewModelScope.launch { repository.setStarred(entryId, !d.isStarred).onFailure { messenger.showError("update the star", it) } }
    }

    fun toggleBookmark() {
        val d = _state.value.detail ?: return
        viewModelScope.launch {
            repository.setBookmarked(entryId, !d.isBookmarked).onFailure { messenger.showError("update the bookmark", it) }
        }
    }

    fun setFontSize(size: ReaderFontSize) {
        _state.update { it.copy(fontSize = size) }
        viewModelScope.launch { userPreferences.setReaderTextSize(size.name) }
    }

    /** Priority Queue feedback. Tapping the active vote again clears it. */
    fun vote(verdict: Int) {
        val previous = _state.value.radarVote
        val next = if (previous == verdict) 0 else verdict
        _state.update { it.copy(radarVote = next) }
        viewModelScope.launch {
            repository.sendRadarFeedback(entryId, next).fold(
                onSuccess = { if (next != 0) messenger.show("Thanks — the ranking will learn from this") },
                onFailure = {
                    _state.update { s -> s.copy(radarVote = previous) }
                    messenger.showError("send feedback", it)
                }
            )
        }
    }

    fun createShareLink(onReady: (String) -> Unit) {
        viewModelScope.launch {
            repository.createShareLink(entryId).fold(
                onSuccess = onReady,
                onFailure = { messenger.showError("create a share link", it) }
            )
        }
    }

    // NOTES

    private suspend fun loadNotes() {
        _state.update { it.copy(notesLoading = true, notesError = null) }
        repository.getNotes(entryId).fold(
            onSuccess = { notes -> _state.update { it.copy(notes = notes, notesLoading = false) } },
            onFailure = { e -> _state.update { it.copy(notesLoading = false, notesError = "Couldn't load notes. ${ErrorText.describe(e)}") } }
        )
    }

    fun retryNotes() {
        viewModelScope.launch { loadNotes() }
    }

    /** [onResult] true = saved. The editor keeps the text on failure. */
    fun saveNote(existing: EntryNote?, title: String, body: String, pinned: Boolean, onResult: (Boolean) -> Unit) {
        val cleanBody = body.trim()
        if (cleanBody.isEmpty()) return
        // The server wants a title; derive one from the first line like a notes app would.
        val cleanTitle = title.trim().ifEmpty { cleanBody.lineSequence().first().take(60).trim().ifEmpty { "Untitled Note" } }
        viewModelScope.launch {
            val result = if (existing == null) repository.createNote(entryId, cleanTitle, cleanBody, pinned)
            else repository.updateNote(existing.id, cleanTitle, cleanBody, pinned)
            result.fold(
                onSuccess = { saved ->
                    _state.update { s ->
                        val others = s.notes.filterNot { it.id == saved.id }
                        s.copy(notes = (listOf(saved) + others).sortedByDescending { it.isPinned })
                    }
                    messenger.show(if (existing == null) "Note added" else "Note updated")
                    onResult(true)
                },
                onFailure = {
                    messenger.showError(if (existing == null) "save the note" else "update the note", it)
                    onResult(false)
                }
            )
        }
    }

    fun deleteNote(note: EntryNote) {
        _state.update { it.copy(notes = it.notes.filterNot { n -> n.id == note.id }) }
        viewModelScope.launch {
            repository.deleteNote(note.id).fold(
                onSuccess = { messenger.show("Note deleted") },
                onFailure = {
                    messenger.showError("delete the note", it)
                    loadNotes()
                }
            )
        }
    }

    // TAGS

    fun loadAllTags() {
        if (_state.value.allTags.isNotEmpty() || _state.value.allTagsLoading) return
        _state.update { it.copy(allTagsLoading = true) }
        viewModelScope.launch {
            repository.getTags().fold(
                onSuccess = { tags -> _state.update { it.copy(allTags = tags, allTagsLoading = false) } },
                onFailure = {
                    _state.update { s -> s.copy(allTagsLoading = false) }
                    messenger.showError("load tags", it)
                }
            )
        }
    }

    fun addTag(tag: TagEntity) {
        tagsEdited = true
        val id = tag.id ?: return
        if (_state.value.tags.any { it.id == id }) return
        _state.update { it.copy(tags = it.tags + tag) }
        viewModelScope.launch {
            repository.addEntryTag(entryId, id).onFailure {
                _state.update { s -> s.copy(tags = s.tags.filterNot { t -> t.id == id }) }
                messenger.showError("add the tag", it)
            }
        }
    }

    /** Tags are shared across the instance, so an existing tag with the same name is reused. */
    fun createAndAddTag(name: String) {
        val clean = name.trim().lowercase().replace(Regex("\\s+"), "-")
        if (clean.isEmpty()) return
        _state.value.allTags.firstOrNull { it.name.equals(clean, ignoreCase = true) }?.let { addTag(it); return }
        viewModelScope.launch {
            repository.createTag(clean).fold(
                onSuccess = { tag ->
                    _state.update { it.copy(allTags = (it.allTags + tag).sortedBy { t -> t.name.lowercase() }) }
                    addTag(tag)
                },
                onFailure = { messenger.showError("create the tag", it) }
            )
        }
    }

    fun removeTag(tag: TagEntity) {
        tagsEdited = true
        val id = tag.id ?: return
        _state.update { it.copy(tags = it.tags.filterNot { t -> t.id == id }) }
        viewModelScope.launch {
            repository.removeEntryTag(entryId, id).onFailure {
                _state.update { s -> s.copy(tags = s.tags + tag) }
                messenger.showError("remove the tag", it)
            }
        }
    }

    fun deleteTag(tag: TagEntity) {
        val id = tag.id ?: return
        _state.update {
            it.copy(
                tags = it.tags.filterNot { t -> t.id == id },
                allTags = it.allTags.filterNot { t -> t.id == id }
            )
        }
        viewModelScope.launch {
            repository.deleteTag(id).fold(
                onSuccess = { messenger.show("Deleted tag #${tag.name}") },
                onFailure = {
                    messenger.showError("delete the tag", it)
                    repository.getTags().onSuccess { tags -> _state.update { it.copy(allTags = tags) } }
                }
            )
        }
    }
}
