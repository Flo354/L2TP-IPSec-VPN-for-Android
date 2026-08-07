package com.arcansecurity.vpn.l2tpipsec.ui.profile

import com.arcansecurity.vpn.l2tpipsec.data.SecretKind
import com.arcansecurity.vpn.l2tpipsec.data.wipe
import com.arcansecurity.vpn.l2tpipsec.data.SecretVault

/**
 * The editing model for one stored secret.
 *
 * The rule this file exists to enforce: **a secret that has been saved can never be shown again.**
 * The vault has no read path for the UI at all — [SecretFieldModel.stored] is a boolean that came
 * from `SecretVault.isSet`, and nothing anywhere in `ui/` can turn it back into characters.
 *
 * The characters the user is *currently typing* are a different thing: they belong to the screen,
 * they are held by the composable that draws the field, and they never reach a state holder that
 * outlives it. What travels up to the form state is [SecretFieldModel.typedLength] — a length, so
 * the reducer and the validator can do their work without ever being handed the value.
 */

/** What the user has decided to do with one secret during an edit session. */
enum class SecretIntent {
    /** Untouched. Whatever the vault holds stays exactly as it is. */
    KEEP,

    /** The field is open for typing; a non-empty value will replace what is stored. */
    REPLACE,

    /** The user explicitly asked, and confirmed, that the stored secret be removed. */
    CLEAR,
}

/**
 * Everything the form needs in order to render and validate one secret field.
 *
 * Note what is absent: any way to obtain the stored value. [typedLength] is deliberately an `Int`
 * and not the text — see the file comment.
 */
data class SecretFieldModel(
    val kind: SecretKind,
    /** `SecretVault.isSet` for this profile and kind, sampled when the editor was opened. */
    val stored: Boolean,
    val intent: SecretIntent = SecretIntent.KEEP,
    /** How many characters the user has typed into the replacement field. Never the value. */
    val typedLength: Int = 0,
) {
    init {
        require(typedLength >= 0) { "typedLength cannot be negative" }
    }

    val typedIsEmpty: Boolean get() = typedLength == 0
}

/** What saving the profile should do to the vault for this field. */
sealed interface SecretCommit {
    /** Leave the vault alone. The one outcome that must never lose a secret. */
    data object Keep : SecretCommit

    /** Write the characters the screen is holding. */
    data object Store : SecretCommit

    /** Remove the stored secret. */
    data object Clear : SecretCommit
}

/**
 * Decides whether the user actually replaced this secret.
 *
 * The case that matters is `REPLACE` with nothing typed: the user tapped **Replace**, changed their
 * mind, and left the field empty. Treating that as "store an empty secret" — or worse, as a clear —
 * would silently destroy a working credential during an unrelated edit, which is exactly the bug
 * this whole design is here to prevent. It is [SecretCommit.Keep].
 */
fun SecretFieldModel.commit(): SecretCommit = when (intent) {
    SecretIntent.KEEP -> SecretCommit.Keep
    SecretIntent.CLEAR -> SecretCommit.Clear
    SecretIntent.REPLACE -> if (typedIsEmpty) SecretCommit.Keep else SecretCommit.Store
}

/**
 * Whether a secret will exist for this field once the profile is saved.
 *
 * This is what "a pre-shared key is required" is checked against, and it is satisfied by a stored
 * secret the UI cannot see. It is derived from [commit] rather than restated, so the validator and
 * the writer can never disagree about whether a secret is about to exist.
 */
val SecretFieldModel.isSatisfied: Boolean
    get() = when (commit()) {
        SecretCommit.Keep -> stored
        SecretCommit.Store -> true
        SecretCommit.Clear -> false
    }

/** Whether the field should be drawn as an editable text field rather than a saved placeholder. */
val SecretFieldModel.isEditable: Boolean
    get() = intent == SecretIntent.REPLACE || (intent == SecretIntent.KEEP && !stored)

/**
 * The placeholder drawn in place of a saved secret.
 *
 * A fixed string, not one bullet per character: the length of a pre-shared key is information, and
 * the UI does not know it anyway.
 */
const val STORED_SECRET_PLACEHOLDER: String = "••••••••"


/**
 * Carries out one field's [SecretCommit] against the vault, then scrubs [typed].
 *
 * This is the whole write path for secrets, so it is a free function over the `SecretVault`
 * interface rather than a private method on the state holder: it is the code most worth testing —
 * "editing a profile must never wipe a secret the user did not touch" is a property of exactly
 * these four lines — and a fake vault is all it takes.
 *
 * [typed] is wiped whatever the outcome, including the paths that never look at it.
 */
fun applySecretCommit(
    vault: SecretVault,
    profileId: String,
    kind: SecretKind,
    commit: SecretCommit,
    typed: CharArray?,
) {
    try {
        when (commit) {
            SecretCommit.Keep -> Unit
            SecretCommit.Clear -> vault.clear(profileId, kind)
            SecretCommit.Store ->
                // commit() only returns Store for a non-empty typed value, so a null here would be
                // the screen and the form state disagreeing. Refusing beats storing an empty secret
                // that would then fail authentication with no way to tell why.
                if (typed != null && typed.isNotEmpty()) vault.store(profileId, kind, typed)
        }
    } finally {
        typed?.wipe()
    }
}

private val SCRUB_VALUE: Char = Char(0)
