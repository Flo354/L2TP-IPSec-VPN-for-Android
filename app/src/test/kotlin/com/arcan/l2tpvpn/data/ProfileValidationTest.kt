package com.arcan.l2tpvpn.data

import com.arcan.l2tpvpn.core.tunnel.IkeIdentityType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ProfileValidationTest {

    private val good = VpnProfile(
        name = "Home",
        server = "vpn.example.com",
        presharedKey = "psk",
        username = "alice",
        password = "hunter2",
        mtu = 1400,
        dnsServers = "192.168.1.1",
    )

    @Test
    fun `a complete profile is accepted`() {
        val result = good.validate()
        assertTrue(result.errors.toString(), result.isValid)
    }

    @Test
    fun `a blank server is rejected`() {
        val result = good.copy(server = "   ").validate()
        assertFalse(result.isValid)
        assertNotNull(result[ProfileField.SERVER])
    }

    @Test
    fun `a blank pre-shared key is rejected`() {
        val result = good.copy(presharedKey = "").validate()
        assertFalse(result.isValid)
        assertNotNull(result[ProfileField.PRESHARED_KEY])
    }

    @Test
    fun `an MTU below the floor is rejected`() {
        val result = good.copy(mtu = 575).validate()
        assertFalse(result.isValid)
        assertNotNull(result[ProfileField.MTU])
    }

    @Test
    fun `an MTU above the ceiling is rejected`() {
        val result = good.copy(mtu = 1501).validate()
        assertFalse(result.isValid)
        assertNotNull(result[ProfileField.MTU])
    }

    @Test
    fun `the MTU boundaries are inclusive`() {
        assertTrue(good.copy(mtu = 576).validate().isValid)
        assertTrue(good.copy(mtu = 1500).validate().isValid)
    }

    @Test
    fun `an explicit identity type requires a value`() {
        val missing = good.copy(identityType = IkeIdentityType.FQDN, identityValue = " ").validate()
        assertFalse(missing.isValid)
        assertNotNull(missing[ProfileField.IDENTITY_VALUE])

        val present = good.copy(
            identityType = IkeIdentityType.FQDN,
            identityValue = "client.example.com",
        ).validate()
        assertTrue(present.isValid)
    }

    @Test
    fun `a DNS override that is not an IP address is rejected`() {
        val result = good.copy(dnsServers = "not-a-dns-server").validate()
        assertFalse(result.isValid)
        assertNotNull(result[ProfileField.DNS_SERVERS])
    }

    @Test
    fun `dropping every PPP protocol is rejected`() {
        val result = good.copy(allowedPppAuth = emptyList()).validate()
        assertFalse(result.isValid)
        assertNotNull(result[ProfileField.PPP_AUTH])
    }

    @Test
    fun `every problem is reported at once`() {
        val result = good.copy(server = "", presharedKey = "", mtu = 0).validate()
        assertEquals(3, result.errors.size)
        assertNull(result[ProfileField.USERNAME])
    }
}
