package com.arcansecurity.vpn.l2tpipsec.ui.profile

import com.arcansecurity.vpn.l2tpipsec.core.tunnel.IkeIdentityType
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.PppAuthProtocol
import com.arcansecurity.vpn.l2tpipsec.data.SecretKind
import com.arcansecurity.vpn.l2tpipsec.data.VpnProfile
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ProfileFormStateTest {

    private fun form(
        profile: VpnProfile = VpnProfile(id = "p1", name = "Home", server = "vpn.example.com"),
        presharedKeyStored: Boolean = true,
        passwordStored: Boolean = true,
    ) = ProfileFormState.of(profile, presharedKeyStored, passwordStored)

    // ------------------------------------------------------------------------------- reduction

    @Test
    fun `editing a field marks it touched`() {
        val edited = form().edit(ProfileField.SERVER) { it.copy(server = "10.0.0.1") }
        assertEquals("10.0.0.1", edited.profile.server)
        assertTrue(ProfileField.SERVER in edited.touched)
    }

    @Test
    fun `an edit with no field leaves the touched set alone`() {
        val edited = form().edit(null) { it.copy(blockIpv6 = false) }
        assertEquals(false, edited.profile.blockIpv6)
        assertTrue(edited.touched.isEmpty())
    }

    @Test
    fun `the MTU field keeps digits only and is capped at four characters`() {
        assertEquals("1400", form().editMtu("1a4b0c0d9").mtuText)
        assertEquals("", form().editMtu("abc").mtuText)
    }

    /** Half-deleting the MTU has to be representable, or the field cannot be retyped. */
    @Test
    fun `the MTU field may be emptied while typing`() {
        val cleared = form().editMtu("")
        assertEquals("", cleared.mtuText)
        assertTrue(ProfileField.MTU in cleared.touched)
    }

    @Test
    fun `saving trims the text fields and converts the MTU back to a number`() {
        val saved = form(VpnProfile(id = "p1", name = "  Home  ", server = "  vpn.example.com  "))
            .edit(ProfileField.USERNAME) { it.copy(username = " alice ") }
            .editMtu("1380")
            .toProfile()
        assertEquals("Home", saved.name)
        assertEquals("vpn.example.com", saved.server)
        assertEquals("alice", saved.username)
        assertEquals(1380, saved.mtu)
    }

    @Test
    fun `a blank name is saved as the placeholder rather than empty`() {
        val saved = form(VpnProfile(id = "p1", name = "   ", server = "vpn.example.com")).toProfile()
        assertEquals(UNTITLED_PROFILE, saved.name)
    }

    // --------------------------------------------------------------------- secrets in the form

    /**
     * The form state can only ever be told *how many* characters were typed. If this signature ever
     * grows a `String`, the guarantee that no secret reaches a state holder goes with it.
     */
    @Test
    fun `typing a secret records a length and switches the field to replacing`() {
        val typed = form().withTypedSecret(SecretKind.PRESHARED_KEY, 9)
        assertEquals(9, typed.presharedKey.typedLength)
        assertEquals(SecretIntent.REPLACE, typed.presharedKey.intent)
        assertTrue(ProfileField.PRESHARED_KEY in typed.touched)
        // and the other one is untouched
        assertEquals(SecretIntent.KEEP, typed.password.intent)
    }

    @Test
    fun `leaving the replace state discards the typed length`() {
        val backToKeep = form()
            .withTypedSecret(SecretKind.PASSWORD, 6)
            .withSecretIntent(SecretKind.PASSWORD, SecretIntent.KEEP)
        assertEquals(0, backToKeep.password.typedLength)
        assertEquals(SecretIntent.KEEP, backToKeep.password.intent)
    }

    @Test
    fun `secret lookup by kind returns the matching field`() {
        val state = form().withTypedSecret(SecretKind.PASSWORD, 3)
        assertEquals(3, state.secret(SecretKind.PASSWORD).typedLength)
        assertEquals(0, state.secret(SecretKind.PRESHARED_KEY).typedLength)
    }

    // ------------------------------------------------------------------------------ validation

    @Test
    fun `a complete profile with stored secrets is valid`() {
        assertTrue(form().validate().isValid)
    }

    /** Requirement: the message must be satisfiable by a secret the UI cannot read. */
    @Test
    fun `a stored pre-shared key satisfies the requirement`() {
        val state = form(presharedKeyStored = true)
        assertNull(state.validate()[ProfileField.PRESHARED_KEY])
    }

    @Test
    fun `a missing pre-shared key is reported`() {
        val state = form(presharedKeyStored = false)
        assertEquals("A pre-shared key is required", state.validate()[ProfileField.PRESHARED_KEY])
    }

    @Test
    fun `typing a pre-shared key satisfies the requirement without storing anything yet`() {
        val state = form(presharedKeyStored = false)
            .withTypedSecret(SecretKind.PRESHARED_KEY, 20)
        assertNull(state.validate()[ProfileField.PRESHARED_KEY])
    }

    @Test
    fun `clearing the pre-shared key makes the profile invalid`() {
        val state = form(presharedKeyStored = true)
            .withSecretIntent(SecretKind.PRESHARED_KEY, SecretIntent.CLEAR)
        assertEquals("A pre-shared key is required", state.validate()[ProfileField.PRESHARED_KEY])
    }

    /** The password is optional: a peer can authenticate on the pre-shared key alone. */
    @Test
    fun `a missing password is not an error`() {
        assertTrue(form(passwordStored = false).validate().isValid)
    }

    @Test
    fun `a missing name is reported`() {
        val state = form(VpnProfile(id = "p1", name = "", server = "vpn.example.com"))
        assertEquals("A profile name is required", state.validate()[ProfileField.NAME])
    }

    @Test
    fun `a missing server is reported`() {
        val state = form(VpnProfile(id = "p1", name = "Home", server = ""))
        assertEquals("Server address is required", state.validate()[ProfileField.SERVER])
    }

    @Test
    fun `a server with spaces is reported`() {
        val state = form(VpnProfile(id = "p1", name = "Home", server = "vpn example com"))
        assertEquals("Server address cannot contain spaces", state.validate()[ProfileField.SERVER])
    }

    @Test
    fun `a server with illegal characters is reported`() {
        val state = form(VpnProfile(id = "p1", name = "Home", server = "vpn/example"))
        assertEquals("Not a valid host name or IP address", state.validate()[ProfileField.SERVER])
    }

    @Test
    fun `an unparseable MTU is reported`() {
        val state = form().editMtu("")
        assertEquals("MTU must be between 576 and 1500", state.validate()[ProfileField.MTU])
    }

    @Test
    fun `an out of range MTU is reported at both ends`() {
        assertEquals("MTU must be between 576 and 1500", form().editMtu("100").validate()[ProfileField.MTU])
        assertEquals("MTU must be between 576 and 1500", form().editMtu("9000").validate()[ProfileField.MTU])
        assertNull(form().editMtu("576").validate()[ProfileField.MTU])
        assertNull(form().editMtu("1500").validate()[ProfileField.MTU])
    }

    @Test
    fun `a non-automatic identity needs a value`() {
        val state = form(
            VpnProfile(
                id = "p1",
                name = "Home",
                server = "vpn.example.com",
                identityType = IkeIdentityType.FQDN,
                identityValue = "  ",
            ),
        )
        assertEquals(
            "An identity value is required for FQDN",
            state.validate()[ProfileField.IDENTITY_VALUE],
        )
    }

    @Test
    fun `the automatic identity needs no value`() {
        assertNull(form().validate()[ProfileField.IDENTITY_VALUE])
    }

    @Test
    fun `a bad DNS entry is named in the message`() {
        val state = form(
            VpnProfile(
                id = "p1",
                name = "Home",
                server = "vpn.example.com",
                dnsServers = "9.9.9.9, notanip",
            ),
        )
        assertEquals("'notanip' is not an IP address", state.validate()[ProfileField.DNS_SERVERS])
    }

    @Test
    fun `well formed DNS lists pass whatever separator was used`() {
        val state = form(
            VpnProfile(
                id = "p1",
                name = "Home",
                server = "vpn.example.com",
                dnsServers = "9.9.9.9, 192.168.1.1; 2001:db8::1",
            ),
        )
        assertNull(state.validate()[ProfileField.DNS_SERVERS])
        assertEquals(
            listOf("9.9.9.9", "192.168.1.1", "2001:db8::1"),
            state.profile.dnsServerList,
        )
    }

    @Test
    fun `an empty PPP auth set is reported`() {
        val state = form(
            VpnProfile(
                id = "p1",
                name = "Home",
                server = "vpn.example.com",
                allowedPppAuth = emptyList<PppAuthProtocol>(),
            ),
        )
        assertEquals(
            "At least one PPP authentication protocol must be allowed",
            state.validate()[ProfileField.PPP_AUTH],
        )
    }

    // ------------------------------------------------------------------------ error visibility

    @Test
    fun `an error stays hidden until its field has been touched`() {
        val state = form(VpnProfile(id = "p1", name = "Home", server = ""))
        assertNull(state.visibleError(state.validate(), ProfileField.SERVER))
    }

    @Test
    fun `an error shows once its field has been touched`() {
        val state = form(VpnProfile(id = "p1", name = "Home", server = "x"))
            .edit(ProfileField.SERVER) { it.copy(server = "") }
        assertEquals(
            "Server address is required",
            state.visibleError(state.validate(), ProfileField.SERVER),
        )
    }

    @Test
    fun `a refused save reveals every error at once`() {
        val state = form(VpnProfile(id = "p1", name = "", server = "")).withAllErrorsShown()
        val validation = state.validate()
        assertEquals("Server address is required", state.visibleError(validation, ProfileField.SERVER))
        assertEquals("A profile name is required", state.visibleError(validation, ProfileField.NAME))
    }

    @Test
    fun `a valid form shows no error even with everything revealed`() {
        val state = form().withAllErrorsShown()
        assertTrue(state.validate().isValid)
        assertFalse(state.showAllErrors && state.validate().errors.isNotEmpty())
    }
}
