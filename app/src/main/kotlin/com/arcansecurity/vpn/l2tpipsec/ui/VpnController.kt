package com.arcansecurity.vpn.l2tpipsec.ui

import android.content.Context
import com.arcansecurity.vpn.l2tpipsec.data.ProfileStoreState
import com.arcansecurity.vpn.l2tpipsec.data.SecretKind
import com.arcansecurity.vpn.l2tpipsec.data.VpnProfile
import com.arcansecurity.vpn.l2tpipsec.platform.AndroidLogger
import com.arcansecurity.vpn.l2tpipsec.platform.AppComponentsHolder
import com.arcansecurity.vpn.l2tpipsec.service.VpnStatusRepository
import com.arcansecurity.vpn.l2tpipsec.ui.profile.ProfileFormState
import com.arcansecurity.vpn.l2tpipsec.ui.profile.SecretIntent
import com.arcansecurity.vpn.l2tpipsec.ui.profile.applySecretCommit
import com.arcansecurity.vpn.l2tpipsec.ui.profile.commit
import com.arcansecurity.vpn.l2tpipsec.ui.profile.duplicateOf
import com.arcansecurity.vpn.l2tpipsec.ui.profile.newProfileId
import com.arcansecurity.vpn.l2tpipsec.ui.profile.newProfileName
import com.arcansecurity.vpn.l2tpipsec.ui.profile.toProfile
import com.arcansecurity.vpn.l2tpipsec.ui.profile.validate
import com.arcansecurity.vpn.l2tpipsec.ui.profile.wipe
import com.arcansecurity.vpn.l2tpipsec.ui.profile.withAllErrorsShown
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Where the single Activity currently is. */
sealed interface Route {
    /** Status, the connect button and a summary of the active profile. */
    data object Home : Route

    /** The list of saved profiles. */
    data object Profiles : Route

    /** The profile form. Which profile is being edited lives in [VpnController.editor]. */
    data object Editor : Route
}

/** The editor is asynchronous: opening it probes the vault, which is file and keystore work. */
sealed interface EditorState {
    data object Loading : EditorState
    data class Ready(val form: ProfileFormState) : EditorState
}

/**
 * State holder for the whole app: navigation, the profile being edited and the shared status and
 * log sources.
 *
 * It is a process singleton rather than a `ViewModel` on purpose — the tunnel outlives the Activity
 * by design, and the status the UI shows has to be correct the instant a recreated Activity
 * recomposes.
 *
 * **It holds no secret, and there is no code path by which it could.** The `SecretVault` it talks to
 * can only answer "is one set" and be handed a replacement; the characters of a replacement are
 * owned by the screen that collected them and arrive here only as an argument to [saveEditor],
 * which wipes them before it returns. `SecretReader`, the one interface that can read a secret back,
 * is never imported anywhere under `ui/`.
 *
 * Nothing in the constructor touches storage. Opening the encrypted store used to happen inline in
 * `MainActivity.onCreate`; here it is a coroutine, and [storeState] is [ProfileStoreState.LOADING]
 * until it finishes.
 */
class VpnController private constructor(private val appContext: Context) {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    /** The shared log sink; the Logs sheet renders its ring buffer. */
    val logger: AndroidLogger = AndroidLogger.shared

    /** Live tunnel state, published by the service. */
    val status: VpnStatusRepository = VpnStatusRepository

    private val _storeState = MutableStateFlow(ProfileStoreState.LOADING)
    private val _profiles = MutableStateFlow<List<VpnProfile>>(emptyList())
    private val _activeProfileId = MutableStateFlow<String?>(null)
    private val _usesEncryptedStorage = MutableStateFlow(true)
    private val _backStack = MutableStateFlow<List<Route>>(listOf(Route.Home))
    private val _editor = MutableStateFlow<EditorState?>(null)
    private val _message = MutableStateFlow<String?>(null)
    private val _saving = MutableStateFlow(false)

    /** [ProfileStoreState.LOADING] until the store has been opened off the main thread. */
    val storeState: StateFlow<ProfileStoreState> get() = _storeState.asStateFlow()

    val profiles: StateFlow<List<VpnProfile>> get() = _profiles.asStateFlow()

    val activeProfileId: StateFlow<String?> get() = _activeProfileId.asStateFlow()

    /** `false` when the keystore refused to encrypt the store; the UI warns about it. */
    val usesEncryptedStorage: StateFlow<Boolean> get() = _usesEncryptedStorage.asStateFlow()

    val backStack: StateFlow<List<Route>> get() = _backStack.asStateFlow()

    val editor: StateFlow<EditorState?> get() = _editor.asStateFlow()

    /** One-shot text for the snackbar. */
    val message: StateFlow<String?> get() = _message.asStateFlow()

    val saving: StateFlow<Boolean> get() = _saving.asStateFlow()

    val activeProfile: VpnProfile?
        get() = _profiles.value.firstOrNull { it.id == _activeProfileId.value }

    init {
        scope.launch {
            val components = AppComponentsHolder.get(appContext)
            launch { components.profiles.state.collect { _storeState.value = it } }
            launch { components.profiles.profiles.collect { _profiles.value = it } }
            launch { components.profiles.activeProfileId.collect { _activeProfileId.value = it } }
            launch {
                components.profiles.usesEncryptedStorage.collect { _usesEncryptedStorage.value = it }
            }
        }
    }

    // ---------------------------------------------------------------------------- navigation

    fun navigateTo(route: Route) {
        if (_backStack.value.lastOrNull() == route) return
        _backStack.value = _backStack.value + route
    }

    /** @return `false` when there is nothing left to pop, so the Activity should finish. */
    fun back(): Boolean {
        val stack = _backStack.value
        if (stack.size <= 1) return false
        if (stack.last() == Route.Editor) _editor.value = null
        _backStack.value = stack.dropLast(1)
        return true
    }

    // ---------------------------------------------------------------------------- the editor

    /**
     * Opens the form over [profileId], or over a brand new profile when it is `null`.
     *
     * The vault probe runs on [Dispatchers.IO]: `isSet` reads a keystore-backed file, and doing that
     * while the navigation animation is running is exactly the kind of main-thread I/O this rewrite
     * exists to remove.
     */
    fun openEditor(profileId: String?) {
        _editor.value = EditorState.Loading
        navigateTo(Route.Editor)
        scope.launch {
            val components = AppComponentsHolder.get(appContext)
            val existing = profileId?.let { id -> _profiles.value.firstOrNull { it.id == id } }
            val profile = existing ?: VpnProfile(
                id = newProfileId(),
                name = newProfileName(_profiles.value.map { it.name }),
            )
            val presence = withContext(Dispatchers.IO) {
                SecretKind.entries.associateWith { components.vault.isSet(profile.id, it) }
            }
            _editor.value = EditorState.Ready(
                ProfileFormState.of(
                    profile = profile,
                    presharedKeyStored = presence[SecretKind.PRESHARED_KEY] == true,
                    passwordStored = presence[SecretKind.PASSWORD] == true,
                    isNew = existing == null,
                ),
            )
        }
    }

    /** Replaces the form state. The only thing the screen may put in here is non-secret. */
    fun updateEditor(transform: (ProfileFormState) -> ProfileFormState) {
        val current = _editor.value as? EditorState.Ready ?: return
        _editor.value = EditorState.Ready(transform(current.form))
    }

    /**
     * Validates and saves the profile, then applies whatever the user decided about each secret.
     *
     * @param typedPresharedKey the characters the screen collected, or `null` when the field was
     *   never opened for typing. They are overwritten before this function returns; the caller must
     *   not keep a reference.
     */
    fun saveEditor(
        typedPresharedKey: CharArray?,
        typedPassword: CharArray?,
        onSaved: () -> Unit,
    ) {
        val current = _editor.value as? EditorState.Ready ?: return
        val validation = current.form.validate()
        if (!validation.isValid) {
            typedPresharedKey.wipe()
            typedPassword.wipe()
            _editor.value = EditorState.Ready(current.form.withAllErrorsShown())
            _message.value = validation.errors.first().message
            return
        }

        val profile = current.form.toProfile()
        _saving.value = true
        scope.launch {
            try {
                val components = AppComponentsHolder.get(appContext)
                withContext(Dispatchers.IO) {
                    components.profiles.upsert(profile)
                    applySecretCommit(
                        components.vault,
                        profile.id,
                        SecretKind.PRESHARED_KEY,
                        current.form.presharedKey.commit(),
                        typedPresharedKey,
                    )
                    applySecretCommit(
                        components.vault,
                        profile.id,
                        SecretKind.PASSWORD,
                        current.form.password.commit(),
                        typedPassword,
                    )
                    if (_activeProfileId.value == null) components.profiles.setActive(profile.id)
                }
                _editor.value = null
                _message.value = "Saved '${profile.name}'"
                onSaved()
            } catch (e: Exception) {
                _message.value = "Could not save the profile: ${e.message ?: e.javaClass.simpleName}"
            } finally {
                // Belt and braces: applySecretCommit already wipes what it was given, but a throw
                // before it is reached must not leave a key sitting in a live array.
                typedPresharedKey.wipe()
                typedPassword.wipe()
                _saving.value = false
            }
        }
    }

    /** Drops the edit session without writing anything. */
    fun cancelEditor() {
        _editor.value = null
        back()
    }

    // ---------------------------------------------------------------------------- the list

    fun setActive(id: String) {
        scope.launch {
            val components = AppComponentsHolder.get(appContext)
            withContext(Dispatchers.IO) { components.profiles.setActive(id) }
        }
    }

    /**
     * Copies a profile under a new name.
     *
     * The copy gets no secrets: they are filed under the original's id in a vault the UI cannot
     * read, so there is nothing to copy even in principle. The message says so.
     */
    fun duplicate(profile: VpnProfile) {
        scope.launch {
            val components = AppComponentsHolder.get(appContext)
            val copy = duplicateOf(profile, _profiles.value.map { it.name })
            withContext(Dispatchers.IO) { components.profiles.upsert(copy) }
            _message.value = "Copied to '${copy.name}'. Its pre-shared key and password must be entered again."
        }
    }

    /** Deletes the profile and everything the vault holds for it. */
    fun delete(profile: VpnProfile) {
        scope.launch {
            val components = AppComponentsHolder.get(appContext)
            withContext(Dispatchers.IO) {
                components.profiles.delete(profile.id)
                components.vault.clearAll(profile.id)
            }
            _message.value = "Deleted '${profile.name}'"
        }
    }

    // ---------------------------------------------------------------------------- connecting

    /**
     * Checks that the active profile could actually connect, then calls [onReady] on the main
     * thread so the Activity can run the `VpnService.prepare` dance.
     *
     * The service re-checks all of this on its own worker thread — it has to, since it can be
     * started by always-on VPN with no UI at all. This exists so that a missing pre-shared key is a
     * sentence on screen instead of a foreground service that starts and immediately fails.
     */
    fun requestConnect(onReady: () -> Unit) {
        scope.launch {
            val components = AppComponentsHolder.get(appContext)
            val profile = activeProfile
            if (profile == null) {
                _message.value = if (_profiles.value.isEmpty()) {
                    "Create a VPN profile first"
                } else {
                    "Choose which profile to connect to"
                }
                return@launch
            }
            val presence = withContext(Dispatchers.IO) {
                SecretKind.entries.associateWith { components.vault.isSet(profile.id, it) }
            }
            val form = ProfileFormState.of(
                profile = profile,
                presharedKeyStored = presence[SecretKind.PRESHARED_KEY] == true,
                passwordStored = presence[SecretKind.PASSWORD] == true,
            )
            val validation = form.validate()
            if (!validation.isValid) {
                _message.value = validation.errors.first().message
                openEditor(profile.id)
                return@launch
            }
            onReady()
        }
    }

    // ---------------------------------------------------------------------------- messages

    fun showMessage(text: String) {
        _message.value = text
    }

    fun consumeMessage() {
        _message.value = null
    }

    companion object {
        @Volatile
        private var instance: VpnController? = null

        fun get(context: Context): VpnController =
            instance ?: synchronized(this) {
                instance ?: VpnController(context.applicationContext).also { instance = it }
            }
    }
}
