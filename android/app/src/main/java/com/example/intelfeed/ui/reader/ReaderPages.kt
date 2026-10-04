package com.example.intelfeed.ui.reader

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelStore
import androidx.lifecycle.ViewModelStoreOwner

/**
 * The reader pager's per-article state. Each article gets its own ViewModelStore, and only the
 * articles near the one on screen keep theirs (see [retainOnly]). All ReaderViewModels used to
 * share the reader's store, so swiping through a long list kept one for every article passed (the
 * full article, its panels and five live subscriptions) until the reader closed.
 *
 * Scoped to the reader's back-stack entry, so the kept pages survive a configuration change.
 */
class ReaderPages : ViewModel() {

    private val owners = HashMap<String, ViewModelStoreOwner>()

    /**
     * Articles already auto-marked read in this reader. Shared by its pages, so an article you
     * marked unread by hand isn't marked read again when you swipe back to it.
     */
    val autoReadIds: MutableSet<String> = HashSet()

    fun owner(entryId: String): ViewModelStoreOwner = owners.getOrPut(entryId) {
        val store = ViewModelStore()
        object : ViewModelStoreOwner {
            override val viewModelStore: ViewModelStore = store
        }
    }

    /** Clears the state of every article except [keep]. */
    fun retainOnly(keep: Set<String>) {
        val iterator = owners.entries.iterator()
        while (iterator.hasNext()) {
            val (id, owner) = iterator.next()
            if (id !in keep) {
                owner.viewModelStore.clear()
                iterator.remove()
            }
        }
    }

    override fun onCleared() {
        owners.values.forEach { it.viewModelStore.clear() }
        owners.clear()
    }
}
