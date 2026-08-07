package com.arcansecurity.vpn.l2tpipsec.ui.profile

import com.arcansecurity.vpn.l2tpipsec.data.VpnProfile
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ProfileListModelTest {

    private fun profile(id: String, name: String, server: String = "vpn.example.com") =
        VpnProfile(id = id, name = name, server = server)

    // ------------------------------------------------------------------------------- ordering

    @Test
    fun `profiles are ordered by name, ignoring case`() {
        val ordered = orderedForDisplay(
            listOf(
                profile("1", "zurich"),
                profile("2", "Amsterdam"),
                profile("3", "berlin"),
            ),
        )
        assertEquals(listOf("Amsterdam", "berlin", "zurich"), ordered.map { it.name })
    }

    /** Two identically named profiles must not swap places between recompositions. */
    @Test
    fun `identical names are broken by id so the order is stable`() {
        val a = profile("aaa", "Office")
        val b = profile("bbb", "Office")
        assertEquals(listOf("aaa", "bbb"), orderedForDisplay(listOf(b, a)).map { it.id })
        assertEquals(listOf("aaa", "bbb"), orderedForDisplay(listOf(a, b)).map { it.id })
    }

    /** The active profile is badged, not hoisted: a list that reorders under the finger misfires. */
    @Test
    fun `ordering does not depend on which profile is active`() {
        val profiles = listOf(profile("1", "zurich"), profile("2", "Amsterdam"))
        assertEquals(
            orderedForDisplay(profiles).map { it.id },
            orderedForDisplay(profiles.reversed()).map { it.id },
        )
    }

    @Test
    fun `a blank name sorts under its fallback rather than first`() {
        val ordered = orderedForDisplay(listOf(profile("1", "  "), profile("2", "Amsterdam")))
        assertEquals(listOf("Amsterdam", "vpn.example.com"), ordered.map { it.displayName })
    }

    @Test
    fun `an empty list orders to an empty list`() {
        assertEquals(emptyList<VpnProfile>(), orderedForDisplay(emptyList()))
    }

    // -------------------------------------------------------------------------- display names

    @Test
    fun `a blank name falls back to the server, which identifies the profile better`() {
        // The editor saves a blank name as UNTITLED_PROFILE, so this is the defensive path: a
        // profile that reached the list unnamed is still more recognisable by where it connects.
        assertEquals("vpn.example.com", profile("1", "   ").displayName)
    }

    @Test
    fun `a profile with neither a name nor a server falls back to the default name`() {
        assertEquals(VpnProfile.DEFAULT_NAME, profile("1", "  ", server = "").displayName)
    }

    @Test
    fun `a blank server is displayed as a prompt`() {
        assertEquals("No server set", profile("1", "Home", server = "").displayServer)
    }

    // ---------------------------------------------------------------------------- duplicating

    @Test
    fun `the first copy is suffixed`() {
        assertEquals("Home (copy)", duplicateNameFor("Home", listOf("Home")))
    }

    @Test
    fun `a taken copy name is numbered`() {
        assertEquals(
            "Home (copy 2)",
            duplicateNameFor("Home", listOf("Home", "Home (copy)")),
        )
        assertEquals(
            "Home (copy 3)",
            duplicateNameFor("Home", listOf("Home", "Home (copy)", "Home (copy 2)")),
        )
    }

    /** Copying a copy gives "Home (copy 2)", not "Home (copy) (copy)". */
    @Test
    fun `copying a copy does not pile up suffixes`() {
        assertEquals(
            "Home (copy 2)",
            duplicateNameFor("Home (copy)", listOf("Home", "Home (copy)")),
        )
    }

    @Test
    fun `a duplicate gets a fresh id and keeps every other setting`() {
        val original = profile("original", "Home").copy(mtu = 1380, blockIpv6 = false)
        val copy = duplicateOf(original, listOf("Home"))
        assertNotEquals(original.id, copy.id)
        assertEquals("Home (copy)", copy.name)
        assertEquals(1380, copy.mtu)
        assertEquals(false, copy.blockIpv6)
    }

    // --------------------------------------------------------------------------- naming a new

    @Test
    fun `the first profile gets the default name`() {
        assertEquals(VpnProfile.DEFAULT_NAME, newProfileName(emptyList()))
    }

    @Test
    fun `a second profile does not collide with the first`() {
        val taken = listOf(VpnProfile.DEFAULT_NAME)
        assertEquals("${VpnProfile.DEFAULT_NAME} 2", newProfileName(taken))
        assertEquals(
            "${VpnProfile.DEFAULT_NAME} 3",
            newProfileName(taken + "${VpnProfile.DEFAULT_NAME} 2"),
        )
    }

    @Test
    fun `new ids are unique`() {
        assertTrue(List(50) { VpnProfile.newId() }.toSet().size == 50)
    }
}
