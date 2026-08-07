package com.arcansecurity.vpn.l2tpipsec.ui.profile

import com.arcansecurity.vpn.l2tpipsec.core.tunnel.IkeIdentity
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.IkeIdentityType
import com.arcansecurity.vpn.l2tpipsec.data.VpnProfile

/**
 * The free-text fields of a [VpnProfile] turned into the shapes the protocol stack wants.
 *
 * These used to be computed properties on `VpnProfile` itself. They live here instead because the
 * profile is now owned by the data layer and should stay a plain record: both the form validator and
 * the service's connect path need exactly the same interpretation of "192.168.1.1, 9.9.9.9", and one
 * shared implementation is the only way they cannot drift apart.
 */

/** The DNS override field split into individual addresses; empty means "keep what IPCP offered". */
fun VpnProfile.dnsServerList(): List<String> =
    dnsServers.split(DNS_SEPARATORS).map { it.trim() }.filter { it.isNotEmpty() }

/** The ISAKMP identity, with the value cleared for the automatic type. */
fun VpnProfile.localIdentity(): IkeIdentity =
    if (identityType == IkeIdentityType.AUTO_IPV4) {
        IkeIdentity(IkeIdentityType.AUTO_IPV4, "")
    } else {
        IkeIdentity(identityType, identityValue.trim())
    }

private val DNS_SEPARATORS = Regex("[,;\\s]+")
