package com.arcansecurity.vpn.l2tpipsec.data

import com.arcansecurity.vpn.l2tpipsec.core.tunnel.IkeIdentityType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ProfileValidationTest {

    private val good = VpnProfile(
        id = "p1",
        name = "Home",
        server = "vpn.example.com",
        username = "alice",
        mtu = 1400,
        dnsServers = "192.168.1.1",
    )

    /** Everything the profile needs is present, and the vault holds the pre-shared key. */
    private val complete = SecretPresence(presharedKeySet = true, passwordSet = true)

    @Test
    fun `a complete profile is accepted`() {
        val result = good.validate(complete)
        assertTrue(result.errors.toString(), result.isValid)
    }

    @Test
    fun `a blank server is rejected`() {
        val result = good.copy(server = "   ").validate(complete)
        assertFalse(result.isValid)
        assertNotNull(result[ProfileField.SERVER])
    }

    /**
     * The rule that used to read the value. It now reads existence, which is the only thing the UI
     * can ask about a write-only store — and the only thing the rule ever needed.
     */
    @Test
    fun `a missing pre-shared key is rejected`() {
        val result = good.validate(complete.copy(presharedKeySet = false))
        assertFalse(result.isValid)
        assertNotNull(result[ProfileField.PRESHARED_KEY])
    }

    /** Plenty of concentrators are configured with no PPP password; `VpnConfig` allows it too. */
    @Test
    fun `a missing password is accepted`() {
        val result = good.validate(complete.copy(passwordSet = false))
        assertTrue(result.errors.toString(), result.isValid)
    }

    @Test
    fun `validation reads the vault rather than any stored value`() {
        val fixture = StoreFixture()

        assertFalse(good.validate(fixture.secrets).isValid)

        fixture.secrets.store(good.id, SecretKind.PRESHARED_KEY, "psk".toCharArray())

        assertTrue(good.validate(fixture.secrets).isValid)
    }

    @Test
    fun `an MTU below the floor is rejected`() {
        val result = good.copy(mtu = 575).validate(complete)
        assertFalse(result.isValid)
        assertNotNull(result[ProfileField.MTU])
    }

    @Test
    fun `an MTU above the ceiling is rejected`() {
        val result = good.copy(mtu = 1501).validate(complete)
        assertFalse(result.isValid)
        assertNotNull(result[ProfileField.MTU])
    }

    @Test
    fun `the MTU boundaries are inclusive`() {
        assertTrue(good.copy(mtu = 576).validate(complete).isValid)
        assertTrue(good.copy(mtu = 1500).validate(complete).isValid)
    }

    @Test
    fun `an explicit identity type requires a value`() {
        val missing = good.copy(identityType = IkeIdentityType.FQDN, identityValue = " ")
            .validate(complete)
        assertFalse(missing.isValid)
        assertNotNull(missing[ProfileField.IDENTITY_VALUE])

        val present = good.copy(
            identityType = IkeIdentityType.FQDN,
            identityValue = "client.example.com",
        ).validate(complete)
        assertTrue(present.isValid)
    }

    @Test
    fun `a DNS override that is not an IP address is rejected`() {
        val result = good.copy(dnsServers = "not-a-dns-server").validate(complete)
        assertFalse(result.isValid)
        assertNotNull(result[ProfileField.DNS_SERVERS])
    }

    @Test
    fun `dropping every PPP protocol is rejected`() {
        val result = good.copy(allowedPppAuth = emptyList()).validate(complete)
        assertFalse(result.isValid)
        assertNotNull(result[ProfileField.PPP_AUTH])
    }

    @Test
    fun `every problem is reported at once`() {
        val result = good.copy(server = "", mtu = 0).validate(SecretPresence.NONE)
        assertEquals(result.errors.toString(), 3, result.errors.size)
        assertNull(result[ProfileField.USERNAME])
    }
}
