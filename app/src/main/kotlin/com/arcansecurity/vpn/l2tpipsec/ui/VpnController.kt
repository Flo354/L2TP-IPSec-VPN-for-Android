package com.arcansecurity.vpn.l2tpipsec.ui

import android.content.Context
import com.arcansecurity.vpn.l2tpipsec.data.ProfileField
import com.arcansecurity.vpn.l2tpipsec.data.ProfileRepository
import com.arcansecurity.vpn.l2tpipsec.data.ValidationResult
import com.arcansecurity.vpn.l2tpipsec.data.VpnProfile
import com.arcansecurity.vpn.l2tpipsec.data.validate
import com.arcansecurity.vpn.l2tpipsec.platform.AndroidLogger
import com.arcansecurity.vpn.l2tpipsec.service.VpnStatusRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * State holder for the single screen: the profile being edited, which fields have been touched
 * (so inline errors only appear once they can be acted on) and the shared status/log sources.
 *
 * It is a process singleton rather than a `ViewModel` on purpose — the tunnel outlives the
 * Activity by design, and the draft profile should survive a rotation without a `SavedStateHandle`
 * dance for twenty fields.
 */
class VpnController private constructor(context: Context) {

    private val repository = ProfileRepository.get(context)

    /** The shared log sink; the Logs sheet renders its ring buffer. */
    val logger: AndroidLogger = AndroidLogger.shared

    /** Live tunnel state, published by the service. */
    val status: VpnStatusRepository = VpnStatusRepository

    /** `false` when the keystore refused to encrypt the store; the UI warns about it. */
    val usesEncryptedStorage: Boolean get() = repository.usesEncryptedStorage

    /** `true` when the saved profile could not be decrypted, so the form starts blank. */
    val profileWasUnreadable: StateFlow<Boolean> get() = repository.profileWasUnreadable

    private val _draft = MutableStateFlow(repository.profile.value)
    private val _touched = MutableStateFlow(emptySet<ProfileField>())
    private val _showAllErrors = MutableStateFlow(false)
    private val _advancedExpanded = MutableStateFlow(false)
    private val _message = MutableStateFlow<String?>(null)

    /** The profile as currently edited; not yet persisted. */
    val draft: StateFlow<VpnProfile> get() = _draft.asStateFlow()

    /** Fields the user has edited, plus everything once a connect attempt was refused. */
    val touched: StateFlow<Set<ProfileField>> get() = _touched.asStateFlow()

    val showAllErrors: StateFlow<Boolean> get() = _showAllErrors.asStateFlow()

    val advancedExpanded: StateFlow<Boolean> get() = _advancedExpanded.asStateFlow()

    /** One-shot text for the snackbar. */
    val message: StateFlow<String?> get() = _message.asStateFlow()

    val validation: ValidationResult get() = _draft.value.validate()

    /** Applies an edit and marks [field] as touched so its error may show. */
    fun edit(field: ProfileField?, transform: (VpnProfile) -> VpnProfile) {
        _draft.value = transform(_draft.value)
        if (field != null) {
            _touched.value = _touched.value + field
        }
    }

    fun toggleAdvanced() {
        _advancedExpanded.value = !_advancedExpanded.value
    }

    /** Writes the draft to the encrypted store. Called before every connect. */
    fun persist() {
        repository.save(_draft.value)
    }

    /**
     * Validates and persists ahead of a connection attempt.
     *
     * @return `true` when the profile is good enough to hand to the service.
     */
    fun prepareForConnect(): Boolean {
        val result = _draft.value.validate()
        if (!result.isValid) {
            _showAllErrors.value = true
            _message.value = result.errors.first().message
            return false
        }
        _showAllErrors.value = false
        persist()
        return true
    }

    fun showMessage(text: String) {
        _message.value = text
    }

    fun consumeMessage() {
        _message.value = null
    }

    /** Discards edits and reloads what is on disk. */
    fun revert() {
        repository.reload()
        _draft.value = repository.profile.value
        _touched.value = emptySet()
        _showAllErrors.value = false
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
