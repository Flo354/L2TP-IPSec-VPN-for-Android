package com.arcansecurity.vpn.l2tpipsec.data

import com.arcansecurity.vpn.l2tpipsec.core.tunnel.IkeIdentityType

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
 * Outcome of [VpnProfile.validate]. Messages are plain English rather than string resources so
 * that validation stays a pure-JVM concern and can be unit-tested without Android.
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
 * Checks the profile before it is handed to the protocol stack.
 *
 * The rules mirror the `require` blocks inside `VpnConfig` so that the UI can explain the problem
 * next to the offending field instead of letting the constructor throw.
 */
fun VpnProfile.validate(): ValidationResult {
    val errors = mutableListOf<ValidationError>()

    val host = server.trim()
    when {
        host.isEmpty() ->
            errors += ValidationError(ProfileField.SERVER, "Server address is required")

        host.any { it.isWhitespace() } ->
            errors += ValidationError(ProfileField.SERVER, "Server address cannot contain spaces")

        !host.matches(HOST_PATTERN) ->
            errors += ValidationError(ProfileField.SERVER, "Not a valid host name or IP address")
    }

    if (presharedKey.isEmpty()) {
        errors += ValidationError(ProfileField.PRESHARED_KEY, "Pre-shared key is required")
    }

    if (mtu !in VpnProfile.MIN_MTU..VpnProfile.MAX_MTU) {
        errors += ValidationError(
            ProfileField.MTU,
            "MTU must be between ${VpnProfile.MIN_MTU} and ${VpnProfile.MAX_MTU}",
        )
    }

    if (identityType != IkeIdentityType.AUTO_IPV4 && identityValue.isBlank()) {
        errors += ValidationError(
            ProfileField.IDENTITY_VALUE,
            "An identity value is required for ${identityType.name}",
        )
    }

    val badDns = dnsServerList.firstOrNull { !it.matches(IP_LITERAL_PATTERN) }
    if (badDns != null) {
        errors += ValidationError(ProfileField.DNS_SERVERS, "'$badDns' is not an IP address")
    }

    if (allowedPppAuth.isEmpty()) {
        errors += ValidationError(
            ProfileField.PPP_AUTH,
            "At least one PPP authentication protocol must be allowed",
        )
    }

    return ValidationResult(errors)
}

/** Host names, IPv4 literals; deliberately permissive, the resolver has the final word. */
private val HOST_PATTERN = Regex("^[A-Za-z0-9._:\\[\\]-]+$")

/** Dotted-quad IPv4 or anything that looks like an IPv6 literal. */
private val IP_LITERAL_PATTERN = Regex(
    "^((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}" +
        "|[0-9A-Fa-f:]+:[0-9A-Fa-f:.]*)$",
)
