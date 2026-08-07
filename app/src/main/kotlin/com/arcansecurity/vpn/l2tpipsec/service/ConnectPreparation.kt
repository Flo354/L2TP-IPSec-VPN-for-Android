package com.arcansecurity.vpn.l2tpipsec.service

import com.arcansecurity.vpn.l2tpipsec.core.tunnel.Phase1Proposal
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.Phase2Proposal
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.VpnConfig
import com.arcansecurity.vpn.l2tpipsec.data.VpnProfile
import com.arcansecurity.vpn.l2tpipsec.ui.profile.dnsServerList
import com.arcansecurity.vpn.l2tpipsec.ui.profile.localIdentity

/**
 * Turning a saved profile plus the secrets read out of the vault into a [VpnConfig].
 *
 * This is the *only* place in the app where a profile and its secrets are combined, and it runs on
 * the tunnel worker thread — never on the main looper, and never anywhere `ui/` can reach it.
 *
 * It is a plain function over plain values so the failure paths ("no profile selected", "no
 * pre-shared key") can be tested without a device, a keystore or a service.
 */
sealed interface ConnectPreparation {

    /** Everything was there; hand [config] to the protocol stack. */
    data class Ready(val config: VpnConfig) : ConnectPreparation

    /** Nothing can be attempted, and retrying will not help. [reason] is shown to the user. */
    data class Rejected(val reason: String) : ConnectPreparation
}

/**
 * Assembles the tunnel configuration.
 *
 * @param profile the active profile, or `null` when the store has none.
 * @param presharedKey what `SecretReader` returned for [com.arcansecurity.vpn.l2tpipsec.data.SecretKind.PRESHARED_KEY].
 * @param password what it returned for the PPP password; `null` is treated as an empty one, which
 *   is what a peer that authenticates on the pre-shared key alone expects.
 *
 * Neither array is wiped here — the caller owns them and clears them in its own `finally`, which is
 * the only arrangement that also covers the exception paths.
 */
fun prepareConnect(
    profile: VpnProfile?,
    presharedKey: CharArray?,
    password: CharArray?,
): ConnectPreparation {
    if (profile == null) {
        return ConnectPreparation.Rejected(
            "No VPN profile is selected. Create one and mark it active.",
        )
    }
    if (presharedKey == null || presharedKey.isEmpty()) {
        // Reads the same as the form's own message on purpose: the user should recognise it.
        return ConnectPreparation.Rejected("A pre-shared key is required")
    }

    return try {
        ConnectPreparation.Ready(
            VpnConfig(
                serverHost = profile.server.trim(),
                presharedKey = String(presharedKey),
                username = profile.username.trim(),
                password = password?.let { String(it) } ?: "",
                exchangeMode = profile.exchangeMode,
                localIdentity = profile.localIdentity(),
                phase1 = Phase1Proposal(
                    encryption = profile.phase1Encryption,
                    hash = profile.phase1Hash,
                    dhGroup = profile.phase1DhGroup,
                ),
                phase2 = Phase2Proposal(
                    encryption = profile.phase2Encryption,
                    integrity = profile.phase2Integrity,
                    pfsGroup = profile.phase2PfsGroup,
                ),
                forceUdpEncapsulation = profile.forceUdpEncapsulation,
                allowedPppAuth = profile.allowedPppAuth,
                mtu = profile.mtu,
                dnsOverride = profile.dnsServerList(),
                blockIpv6 = profile.blockIpv6,
                debugLogging = profile.debugLogging,
            ),
        )
    } catch (e: IllegalArgumentException) {
        // VpnConfig's own require() blocks. The form validates the same rules, so reaching this
        // means the profile was written by an older build or edited outside the app.
        ConnectPreparation.Rejected(e.message ?: "The profile is not valid")
    }
}

