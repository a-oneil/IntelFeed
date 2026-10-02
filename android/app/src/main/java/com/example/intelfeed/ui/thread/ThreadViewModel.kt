package com.example.intelfeed.ui.thread

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.intelfeed.data.model.ThreadDetail
import com.example.intelfeed.data.repository.BulkAction
import com.example.intelfeed.data.repository.IntelFeedRepository
import com.example.intelfeed.ui.ErrorText
import com.example.intelfeed.ui.UiMessenger
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class ThreadUiState(
    val detail: ThreadDetail? = null,
    val loading: Boolean = true,
    val error: String? = null
)

/** A story thread: the spine of what changed, and every outlet's article folded under it. */
class ThreadViewModel(
    private val slug: String,
    private val repository: IntelFeedRepository,
    private val messenger: UiMessenger
) : ViewModel() {

    private val _state = MutableStateFlow(ThreadUiState())
    val state: StateFlow<ThreadUiState> = _state.asStateFlow()

    init {
        viewModelScope.launch {
            repository.entryUpdates.collect { u ->
                val read = u.isRead ?: return@collect
                _state.update { s ->
                    s.copy(detail = s.detail?.let { d ->
                        d.copy(members = d.members.map { m -> if (m.entryId == u.id) m.copy(isRead = read) else m })
                    })
                }
            }
        }
        load()
    }

    fun load() {
        _state.update { it.copy(loading = true, error = null) }
        viewModelScope.launch {
            repository.getThread(slug).fold(
                onSuccess = { detail ->
                    _state.update { it.copy(detail = detail, loading = false) }
                    // Same as the web reader: stamps the thread as seen, which resets "new since opened".
                    detail.id?.let { repository.markThreadOpened(it) }
                },
                onFailure = { e -> _state.update { it.copy(loading = false, error = ErrorText.describe(e)) } }
            )
        }
    }

    /** Marks every unread article in the story read, which drops it out of the Priority Queue. */
    fun markAllRead() {
        val members = _state.value.detail?.members ?: return
        val unread = members.filter { !it.isRead }
        if (unread.isEmpty()) return
        viewModelScope.launch {
            repository.bulkSet(BulkAction.READ, unread.associate { it.entryId to false }).fold(
                onSuccess = { messenger.show("Marked the story read") },
                onFailure = { messenger.showError("mark the story read", it) }
            )
        }
    }
}
