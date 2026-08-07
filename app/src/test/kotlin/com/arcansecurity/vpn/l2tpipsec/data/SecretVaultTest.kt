package com.arcansecurity.vpn.l2tpipsec.data

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.Timeout

/**
 * The write-only credential store.
 *
 * The defect these tests exist for: the pre-shared key and the PPP password used to be plain
 * fields on the profile, so anything holding a profile could print them — and the generated
 * `toString` did.
 */
class SecretVaultTest {

    /** Every suspend path here can in principle wait on a lock; never let a bug hang the build. */
    @get:Rule
    val timeout: Timeout = Timeout.seconds(30)

    private val fixture = StoreFixture()
    private val vault get() = fixture.vault

    // ------------------------------------------------------------------ the write-only guarantee

    /**
     * The point of the whole exercise, checked structurally rather than by reading the source: a
     * type the UI holds must have no member that could hand back a secret. Adding a `fun get(…)`
     * or making [SecretVault] extend [SecretReader] fails right here.
     */
    @Test
    fun `SecretVault declares no method that can return a secret`() {
        val leaking = SecretVault::class.java.declaredMethods.filter { method ->
            method.returnType != Void.TYPE && method.returnType != Boolean::class.javaPrimitiveType
        }

        assertTrue(
            "SecretVault must expose nothing but Unit and Boolean, found: " +
                leaking.joinToString { "${it.name}: ${it.returnType.simpleName}" },
            leaking.isEmpty(),
        )
        assertTrue(
            "SecretVault must have no supertype that could smuggle a getter in: " +
                SecretVault::class.java.interfaces.joinToString { it.simpleName },
            SecretVault::class.java.interfaces.isEmpty(),
        )
        assertFalse(
            "SecretVault must not inherit the read path",
            SecretReader::class.java.isAssignableFrom(SecretVault::class.java),
        )
    }

    @Test
    fun `a stored secret is reachable through SecretReader and nowhere else`() {
        fixture.secrets.store("p1", SecretKind.PRESHARED_KEY, "s3cr3t-psk".toCharArray())
        fixture.flushSecrets()

        assertArrayEquals(
            "s3cr3t-psk".toCharArray(),
            fixture.reader.read("p1", SecretKind.PRESHARED_KEY),
        )
    }

    @Test
    fun `isSet reports presence per profile and per kind`() {
        fixture.secrets.store("p1", SecretKind.PRESHARED_KEY, "psk".toCharArray())

        assertTrue(vault.isSet("p1", SecretKind.PRESHARED_KEY))
        assertFalse(vault.isSet("p1", SecretKind.PASSWORD))
        assertFalse("another profile must not inherit it", vault.isSet("p2", SecretKind.PRESHARED_KEY))
    }

    @Test
    fun `two profiles keep separate credentials`() {
        fixture.secrets.store("p1", SecretKind.PASSWORD, "one".toCharArray())
        fixture.secrets.store("p2", SecretKind.PASSWORD, "two".toCharArray())
        fixture.flushSecrets()

        assertArrayEquals("one".toCharArray(), fixture.reader.read("p1", SecretKind.PASSWORD))
        assertArrayEquals("two".toCharArray(), fixture.reader.read("p2", SecretKind.PASSWORD))
    }

    @Test
    fun `clear forgets the secret on disk as well as in memory`() {
        fixture.secrets.store("p1", SecretKind.PASSWORD, "hunter2".toCharArray())
        fixture.flushSecrets()

        fixture.secrets.clear("p1", SecretKind.PASSWORD)
        fixture.flushSecrets()

        assertFalse(vault.isSet("p1", SecretKind.PASSWORD))
        assertNull(fixture.reader.read("p1", SecretKind.PASSWORD))
        assertTrue(
            "the row must be gone, not blanked: ${fixture.prefs.values.keys}",
            fixture.prefs.values.keys.none { it.startsWith("secret.") },
        )
    }

    @Test
    fun `clearAll forgets both kinds`() {
        fixture.secrets.store("p1", SecretKind.PRESHARED_KEY, "psk".toCharArray())
        fixture.secrets.store("p1", SecretKind.PASSWORD, "hunter2".toCharArray())
        fixture.flushSecrets()

        fixture.secrets.clearAll("p1")
        fixture.flushSecrets()

        assertFalse(vault.isSet("p1", SecretKind.PRESHARED_KEY))
        assertFalse(vault.isSet("p1", SecretKind.PASSWORD))
        assertNull(fixture.reader.read("p1", SecretKind.PRESHARED_KEY))
        assertNull(fixture.reader.read("p1", SecretKind.PASSWORD))
    }

    /** An emptied text field is the user removing the credential, not a no-op. */
    @Test
    fun `storing an empty secret clears it`() {
        fixture.secrets.store("p1", SecretKind.PASSWORD, "hunter2".toCharArray())
        fixture.flushSecrets()

        fixture.secrets.store("p1", SecretKind.PASSWORD, CharArray(0))
        fixture.flushSecrets()

        assertFalse(vault.isSet("p1", SecretKind.PASSWORD))
        assertNull(fixture.reader.read("p1", SecretKind.PASSWORD))
    }

    /** Callers are told to wipe what they read; that must not empty the store. */
    @Test
    fun `read hands out a copy the caller may wipe`() {
        fixture.secrets.store("p1", SecretKind.PRESHARED_KEY, "psk".toCharArray())
        fixture.flushSecrets()

        fixture.reader.read("p1", SecretKind.PRESHARED_KEY)!!.wipe()

        assertArrayEquals(
            "psk".toCharArray(),
            fixture.reader.read("p1", SecretKind.PRESHARED_KEY),
        )
    }

    /**
     * Same, for a value the store would not take, which therefore stays in the queue and is served
     * from there. The caller must not be able to blank the queue by wiping what it was handed.
     */
    @Test
    fun `read hands out a copy of a value that is only in memory`() {
        fixture.prefs.writesFail = true
        fixture.secrets.store("p1", SecretKind.PRESHARED_KEY, "psk".toCharArray())
        fixture.flushSecrets()

        fixture.reader.read("p1", SecretKind.PRESHARED_KEY)!!.wipe()

        assertArrayEquals(
            "psk".toCharArray(),
            fixture.reader.read("p1", SecretKind.PRESHARED_KEY),
        )
    }

    /** The caller keeps ownership of the array it passed in; the vault must have taken a copy. */
    @Test
    fun `wiping the array that was stored does not blank the stored secret`() {
        val typed = "psk".toCharArray()
        fixture.secrets.store("p1", SecretKind.PRESHARED_KEY, typed)
        typed.wipe()
        fixture.flushSecrets()

        assertArrayEquals(
            "psk".toCharArray(),
            fixture.reader.read("p1", SecretKind.PRESHARED_KEY),
        )
    }

    /**
     * `store` is called from a click handler and cannot suspend, so the write is queued. "Save the
     * profile, then connect" must not race that queue, and no caller should have to know it exists.
     */
    @Test
    fun `a secret is usable straight after store, with no flush from the caller`() {
        fixture.secrets.store("p1", SecretKind.PASSWORD, "hunter2".toCharArray())

        assertTrue(vault.isSet("p1", SecretKind.PASSWORD))
        assertArrayEquals(
            "hunter2".toCharArray(),
            fixture.reader.read("p1", SecretKind.PASSWORD),
        )
    }

    /**
     * A credential written by a previous run is only visible to [SecretVault.isSet] once the store
     * has told the vault which profiles exist — which is why the UI has to wait for
     * [ProfileStoreState.READY] before it trusts the answer.
     */
    @Test
    fun `a credential already on disk is visible to isSet once the store has loaded`() {
        val disk = FakePreferences(
            mapOf(
                KEY_ORDER to "p1",
                "profile.p1.name" to "Home",
                "secret.p1.psk" to "psk",
            ),
        )
        val other = StoreFixture(disk)

        assertEquals(ProfileStoreState.READY, other.awaitLoaded())
        assertTrue(other.secrets.isSet("p1", SecretKind.PRESHARED_KEY))
        assertFalse(other.secrets.isSet("p1", SecretKind.PASSWORD))
    }

    // ------------------------------------------------------------------ a store that fails

    @Test
    fun `a store that refuses writes keeps the credential usable and never throws`() {
        fixture.prefs.writesFail = true

        fixture.secrets.store("p1", SecretKind.PRESHARED_KEY, "psk".toCharArray())
        val flushed = fixture.flushSecrets()

        assertFalse("the write cannot have succeeded", flushed)
        assertTrue("but this process must still work", vault.isSet("p1", SecretKind.PRESHARED_KEY))
        assertArrayEquals(
            "psk".toCharArray(),
            fixture.reader.read("p1", SecretKind.PRESHARED_KEY),
        )
        assertTrue(fixture.logText(), fixture.logged.any { it.startsWith("ERROR") })
    }

    @Test
    fun `a store that refuses reads yields null instead of propagating`() {
        val disk = FakePreferences(mapOf("secret.p1.psk" to "psk"))
        val other = StoreFixture(disk)
        disk.readsFail = true

        assertNull(other.reader.read("p1", SecretKind.PRESHARED_KEY))
        assertTrue(other.logText(), other.logged.any { it.startsWith("ERROR") })
    }

    // ------------------------------------------------------------------ redaction

    /**
     * Requirement 4, checked over every path that can log: a secret must not reach the in-app log
     * buffer, which the Logs sheet renders and the user can copy and share.
     */
    @Test
    fun `no code path in the vault logs a secret`() {
        val psk = "s3cr3t-psk"
        val password = "hunter2"

        fixture.secrets.store("p1", SecretKind.PRESHARED_KEY, psk.toCharArray())
        fixture.secrets.store("p1", SecretKind.PASSWORD, password.toCharArray())
        fixture.flushSecrets()
        fixture.reader.read("p1", SecretKind.PRESHARED_KEY)
        fixture.secrets.clearAll("p1")
        fixture.flushSecrets()

        // …and again with a store that fails at every turn, which is where the log gets chatty.
        fixture.prefs.writesFail = true
        fixture.prefs.readsFail = true
        fixture.secrets.store("p1", SecretKind.PRESHARED_KEY, psk.toCharArray())
        fixture.flushSecrets()
        fixture.reader.read("p1", SecretKind.PASSWORD)

        val text = fixture.logText()
        assertFalse("the pre-shared key reached the log:\n$text", text.contains(psk))
        assertFalse("the password reached the log:\n$text", text.contains(password))
        assertTrue("the failures were still reported", fixture.logged.any { it.startsWith("ERROR") })
    }

    @Test
    fun `the key layout keeps the two kinds apart`() {
        assertEquals(
            "secret.abc.psk",
            PreferenceSecretVault.secretKey("abc", SecretKind.PRESHARED_KEY),
        )
        assertEquals(
            "secret.abc.password",
            PreferenceSecretVault.secretKey("abc", SecretKind.PASSWORD),
        )
    }
}
