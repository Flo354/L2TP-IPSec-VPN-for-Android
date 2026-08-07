package com.arcansecurity.vpn.l2tpipsec.ui.profile

import com.arcansecurity.vpn.l2tpipsec.core.tunnel.IkeIdentityType
import com.arcansecurity.vpn.l2tpipsec.data.SecretKind
import com.arcansecurity.vpn.l2tpipsec.data.VpnProfile

/** Editable fields a validation error can be attached to. */
enum class ProfileField {
    NAME,
    SERVER,
    PRESHARED_KEY,
    USERNAME,
    PASSWORD,
    IDENTITY_VALUE,
    MTU,
    DNS_SERVERS,
    PPP_AUTH,
}

/** One human-readable problem, bound to the field that should show it inline. */
data class ValidationError(val field: ProfileField, val message: String)

/**
 * Outcome of [ProfileFormState.validate]. Messages are plain English rather than string resources
 * so that validation stays a pure-JVM concern and can be unit-tested without Android.
 */
data class ValidationResult(val errors: List<ValidationError> = emptyList()) {

    val isValid: Boolean get() = errors.isEmpty()

    /** The first message attached to [field], or `null` when the field is fine. */
    operator fun get(field: ProfileField): String? =
        errors.firstOrNull { it.field == field }?.message

    companion object {
        val VALID = ValidationResult()
    }
}

/**
 * Everything one profile-editing session holds, and nothing else.
 *
 * Two deliberate properties:
 *
 *  * **No secret is in here.** The two [SecretFieldModel]s carry a presence flag and a typed length;
 *    the characters live in the composable that draws the field and die with it. That is what makes
 *    "never put a secret in a saved-instance-state bundle" a structural fact rather than a habit.
 *  * **MTU is kept as text.** Parsing on every keystroke turned a half-deleted "14" into `14` and
 *    then into an error the user could not read past; the text is the truth while editing and
 *    [toProfile] does the conversion once.
 *
 * The whole class is free of Android types, so the reducer and the validator are unit-testable.
 */
data class ProfileFormState(
    val profile: VpnProfile,
    val mtuText: String,
    val presharedKey: SecretFieldModel,
    val password: SecretFieldModel,
    /** Fields the user has edited; an error only shows once it can be acted on. */
    val touched: Set<ProfileField> = emptySet(),
    /** Raised when a save was refused, so every problem becomes visible at once. */
    val showAllErrors: Boolean = false,
    /** `true` while creating a profile that has never been saved. */
    val isNew: Boolean = false,
    val advancedExpanded: Boolean = false,
) {
    /** The model for [kind], so callers can stay generic over the two secrets. */
    fun secret(kind: SecretKind): SecretFieldModel = when (kind) {
        SecretKind.PRESHARED_KEY -> presharedKey
        SecretKind.PASSWORD -> password
    }

    companion object {
        /** Opens a session over [profile], with the vault's answers for the two secrets. */
        fun of(
            profile: VpnProfile,
            presharedKeyStored: Boolean,
            passwordStored: Boolean,
            isNew: Boolean = false,
        ): ProfileFormState = ProfileFormState(
            profile = profile,
            mtuText = profile.mtu.toString(),
            presharedKey = SecretFieldModel(SecretKind.PRESHARED_KEY, stored = presharedKeyStored),
            password = SecretFieldModel(SecretKind.PASSWORD, stored = passwordStored),
            isNew = isNew,
        )
    }
}

// ------------------------------------------------------------------------------------- reduction

/** Applies an edit and marks [field] as touched so its error may show. */
fun ProfileFormState.edit(
    field: ProfileField?,
    transform: (VpnProfile) -> VpnProfile,
): ProfileFormState = copy(
    profile = transform(profile),
    touched = if (field == null) touched else touched + field,
)

/** MTU is edited as text; only digits are accepted so the keyboard cannot smuggle anything in. */
fun ProfileFormState.editMtu(text: String): ProfileFormState = copy(
    mtuText = text.filter(Char::isDigit).take(4),
    touched = touched + ProfileField.MTU,
)

/**
 * Records how many characters the user has typed into a secret field.
 *
 * The signature is the point: a caller *cannot* hand the value to the form state, because the
 * parameter is an `Int`.
 */
fun ProfileFormState.withTypedSecret(kind: SecretKind, length: Int): ProfileFormState =
    withSecret(kind) { it.copy(intent = SecretIntent.REPLACE, typedLength = length) }

/** Moves a secret field between saved / replacing / cleared. Typing resets when leaving REPLACE. */
fun ProfileFormState.withSecretIntent(kind: SecretKind, intent: SecretIntent): ProfileFormState =
    withSecret(kind) {
        it.copy(intent = intent, typedLength = if (intent == SecretIntent.REPLACE) it.typedLength else 0)
    }

private fun ProfileFormState.withSecret(
    kind: SecretKind,
    transform: (SecretFieldModel) -> SecretFieldModel,
): ProfileFormState {
    val field = if (kind == SecretKind.PRESHARED_KEY) ProfileField.PRESHARED_KEY else ProfileField.PASSWORD
    return when (kind) {
        SecretKind.PRESHARED_KEY -> copy(presharedKey = transform(presharedKey))
        SecretKind.PASSWORD -> copy(password = transform(password))
    }.copy(touched = touched + field)
}

/** Marks every field as touched; used when a save is refused. */
fun ProfileFormState.withAllErrorsShown(): ProfileFormState = copy(showAllErrors = true)

/** The profile as it should be persisted: trimmed, with the MTU text converted back to a number. */
fun ProfileFormState.toProfile(): VpnProfile = profile.copy(
    name = profile.name.trim().ifBlank { UNTITLED_PROFILE },
    server = profile.server.trim(),
    username = profile.username.trim(),
    identityValue = profile.identityValue.trim(),
    dnsServers = profile.dnsServers.trim(),
    mtu = mtuText.trim().toIntOrNull() ?: profile.mtu,
)

// ------------------------------------------------------------------------------------ validation

/**
 * Checks the form before it is saved or handed to the protocol stack.
 *
 * The rules mirror the `require` blocks inside `VpnConfig` so that the UI can explain the problem
 * next to the offending field instead of letting the constructor throw. The one that is not a
 * mirror is the pre-shared key: it is checked through [isSatisfied], i.e. against the vault's
 * `isSet`, so a profile whose key was saved months ago validates without the UI ever seeing it.
 */
fun ProfileFormState.validate(): ValidationResult {
    val errors = mutableListOf<ValidationError>()

    if (profile.name.isBlank()) {
        errors += ValidationError(ProfileField.NAME, "A profile name is required")
    }

    val host = profile.server.trim()
    when {
        host.isEmpty() ->
            errors += ValidationError(ProfileField.SERVER, "Server address is required")

        host.any { it.isWhitespace() } ->
            errors += ValidationError(ProfileField.SERVER, "Server address cannot contain spaces")

        !host.matches(HOST_PATTERN) ->
            errors += ValidationError(ProfileField.SERVER, "Not a valid host name or IP address")
    }

    if (!presharedKey.isSatisfied) {
        errors += ValidationError(ProfileField.PRESHARED_KEY, "A pre-shared key is required")
    }

    val mtu = mtuText.trim().toIntOrNull()
    if (mtu == null || mtu !in VpnProfile.MIN_MTU..VpnProfile.MAX_MTU) {
        errors += ValidationError(
            ProfileField.MTU,
            "MTU must be between ${VpnProfile.MIN_MTU} and ${VpnProfile.MAX_MTU}",
        )
    }

    if (profile.identityType != IkeIdentityType.AUTO_IPV4 && profile.identityValue.isBlank()) {
        errors += ValidationError(
            ProfileField.IDENTITY_VALUE,
            "An identity value is required for ${profile.identityType.name}",
        )
    }

    val badDns = profile.dnsServerList.firstOrNull { !it.matches(IP_LITERAL_PATTERN) }
    if (badDns != null) {
        errors += ValidationError(ProfileField.DNS_SERVERS, "'$badDns' is not an IP address")
    }

    if (profile.allowedPppAuth.isEmpty()) {
        errors += ValidationError(
            ProfileField.PPP_AUTH,
            "At least one PPP authentication protocol must be allowed",
        )
    }

    return ValidationResult(errors)
}

/** The error to draw under [field], or `null` while the user has not earned it yet. */
fun ProfileFormState.visibleError(result: ValidationResult, field: ProfileField): String? =
    result[field]?.takeIf { showAllErrors || field in touched }

/** Host names, IPv4 literals; deliberately permissive, the resolver has the final word. */
private val HOST_PATTERN = Regex("^[A-Za-z0-9._:\\[\\]-]+$")

/** Dotted-quad IPv4 or anything that looks like an IPv6 literal. */
private val IP_LITERAL_PATTERN = Regex(
    "^((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}" +
        "|[0-9A-Fa-f:]+:[0-9A-Fa-f:.]*)$",
)
