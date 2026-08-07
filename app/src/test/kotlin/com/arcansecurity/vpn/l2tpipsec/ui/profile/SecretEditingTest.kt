package com.arcansecurity.vpn.l2tpipsec.ui.profile

import com.arcansecurity.vpn.l2tpipsec.data.SecretKind
import com.arcansecurity.vpn.l2tpipsec.data.wipe
import com.arcansecurity.vpn.l2tpipsec.data.SecretVault
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The "did the user replace this secret" decision.
 *
 * Every case here is a way the previous single-profile build could destroy a working credential
 * during an unrelated edit, so they are spelled out one by one rather than folded into a table.
 */
class SecretEditingTest {

    private fun model(
        stored: Boolean,
        intent: SecretIntent = SecretIntent.KEEP,
        typedLength: Int = 0,
    ) = SecretFieldModel(SecretKind.PRESHARED_KEY, stored, intent, typedLength)

    @Test
    fun `an untouched stored secret is left alone`() {
        assertEquals(SecretCommit.Keep, model(stored = true).commit())
    }

    @Test
    fun `an untouched absent secret is still left alone`() {
        assertEquals(SecretCommit.Keep, model(stored = false).commit())
    }

    @Test
    fun `typing a replacement stores it`() {
        assertEquals(
            SecretCommit.Store,
            model(stored = true, intent = SecretIntent.REPLACE, typedLength = 12).commit(),
        )
    }

    @Test
    fun `typing a first secret stores it`() {
        assertEquals(
            SecretCommit.Store,
            model(stored = false, intent = SecretIntent.REPLACE, typedLength = 1).commit(),
        )
    }

    /**
     * The regression that matters: tapping Replace, thinking better of it and leaving the field
     * empty must not wipe the key. "Keep", not "Store an empty string" and not "Clear".
     */
    @Test
    fun `opening Replace and typing nothing keeps the stored secret`() {
        assertEquals(
            SecretCommit.Keep,
            model(stored = true, intent = SecretIntent.REPLACE, typedLength = 0).commit(),
        )
    }

    @Test
    fun `clearing is honoured even when something was typed first`() {
        assertEquals(
            SecretCommit.Clear,
            model(stored = true, intent = SecretIntent.CLEAR, typedLength = 8).commit(),
        )
    }

    // ------------------------------------------------------------------ validation from isSet

    @Test
    fun `a stored secret satisfies the requirement without the UI seeing it`() {
        assertTrue(model(stored = true).isSatisfied)
    }

    @Test
    fun `an absent and untyped secret does not satisfy the requirement`() {
        assertFalse(model(stored = false).isSatisfied)
    }

    @Test
    fun `a typed replacement satisfies the requirement`() {
        assertTrue(model(stored = false, intent = SecretIntent.REPLACE, typedLength = 4).isSatisfied)
    }

    @Test
    fun `an abandoned replacement is still satisfied by what is stored`() {
        assertTrue(model(stored = true, intent = SecretIntent.REPLACE, typedLength = 0).isSatisfied)
    }

    @Test
    fun `a cleared secret no longer satisfies the requirement`() {
        assertFalse(model(stored = true, intent = SecretIntent.CLEAR).isSatisfied)
    }

    // ------------------------------------------------------------------------------ rendering

    @Test
    fun `a stored untouched secret is drawn as a placeholder, not a text field`() {
        assertFalse(model(stored = true).isEditable)
    }

    @Test
    fun `an absent secret is drawn as an ordinary editable field`() {
        assertTrue(model(stored = false).isEditable)
    }

    @Test
    fun `a secret being replaced is editable`() {
        assertTrue(model(stored = true, intent = SecretIntent.REPLACE).isEditable)
    }

    @Test
    fun `a secret marked for clearing is not editable`() {
        assertFalse(model(stored = true, intent = SecretIntent.CLEAR).isEditable)
    }

    /** A per-character placeholder would leak the length of a key the UI is not allowed to know. */
    @Test
    fun `the placeholder is a fixed string`() {
        assertEquals("••••••••", STORED_SECRET_PLACEHOLDER)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `a negative typed length is rejected`() {
        model(stored = false, typedLength = -1)
    }

    // --------------------------------------------------------------------------------- scrubbing

    /**
     * Asserts the resulting characters rather than merely calling the function.
     *
     * The first version of `wipe()` was written with a character literal that turned out to hold an
     * invisible control character; it compiled, it looked right in review, and it was this assertion
     * that caught it. A test that only checked "no exception" would have passed.
     */
    @Test
    fun `wiping overwrites every character`() {
        val secret = "hunter2".toCharArray()
        val length = secret.size
        secret.wipe()
        assertEquals(length, secret.size)
        assertTrue(secret.all { it.code == 0 })
        assertFalse(String(secret).contains("hunter"))
    }

    @Test
    fun `wiping an empty array is harmless`() {
        val empty = CharArray(0)
        empty.wipe()
        assertEquals(0, empty.size)
    }

    @Test
    fun `wiping through a nullable reference is a no-op`() {
        val absent: CharArray? = null
        absent?.wipe()
    }

    // -------------------------------------------------------------------------- the write path

    /** Records what the vault was asked to do, and refuses to hand anything back. */
    private class FakeVault : SecretVault {
        val stored = mutableMapOf<Pair<String, SecretKind>, String>()
        val calls = mutableListOf<String>()

        override fun isSet(profileId: String, kind: SecretKind) =
            stored.containsKey(profileId to kind)

        override fun store(profileId: String, kind: SecretKind, secret: CharArray) {
            calls += "store:$kind"
            stored[profileId to kind] = String(secret)
        }

        override fun clear(profileId: String, kind: SecretKind) {
            calls += "clear:$kind"
            stored.remove(profileId to kind)
        }

        override fun clearAll(profileId: String) {
            calls += "clearAll"
            SecretKind.entries.forEach { stored.remove(profileId to it) }
        }
    }

    private fun vaultHolding(vararg kinds: SecretKind) = FakeVault().apply {
        kinds.forEach { stored[PROFILE to it] = "original-$it" }
    }

    /** The headline requirement: an edit that did not touch the secret must not disturb it. */
    @Test
    fun `keeping does not touch the vault at all`() {
        val vault = vaultHolding(SecretKind.PRESHARED_KEY)
        applySecretCommit(vault, PROFILE, SecretKind.PRESHARED_KEY, SecretCommit.Keep, null)
        assertTrue(vault.calls.isEmpty())
        assertEquals("original-PRESHARED_KEY", vault.stored[PROFILE to SecretKind.PRESHARED_KEY])
    }

    @Test
    fun `an abandoned replacement leaves the stored secret intact`() {
        val vault = vaultHolding(SecretKind.PRESHARED_KEY)
        val field = model(stored = true, intent = SecretIntent.REPLACE, typedLength = 0)
        applySecretCommit(vault, PROFILE, field.kind, field.commit(), CharArray(0))
        assertTrue(vault.calls.isEmpty())
        assertEquals("original-PRESHARED_KEY", vault.stored[PROFILE to SecretKind.PRESHARED_KEY])
    }

    @Test
    fun `storing replaces what was there`() {
        val vault = vaultHolding(SecretKind.PRESHARED_KEY)
        applySecretCommit(
            vault,
            PROFILE,
            SecretKind.PRESHARED_KEY,
            SecretCommit.Store,
            "brand-new".toCharArray(),
        )
        assertEquals(listOf("store:PRESHARED_KEY"), vault.calls)
        assertEquals("brand-new", vault.stored[PROFILE to SecretKind.PRESHARED_KEY])
    }

    @Test
    fun `clearing removes it`() {
        val vault = vaultHolding(SecretKind.PRESHARED_KEY, SecretKind.PASSWORD)
        applySecretCommit(vault, PROFILE, SecretKind.PASSWORD, SecretCommit.Clear, null)
        assertEquals(listOf("clear:PASSWORD"), vault.calls)
        assertFalse(vault.isSet(PROFILE, SecretKind.PASSWORD))
        // and only that one
        assertTrue(vault.isSet(PROFILE, SecretKind.PRESHARED_KEY))
    }

    /** Storing "" would authenticate and fail with nothing on screen to explain why. */
    @Test
    fun `a Store with a null buffer is refused rather than writing an empty secret`() {
        val vault = vaultHolding(SecretKind.PRESHARED_KEY)
        applySecretCommit(vault, PROFILE, SecretKind.PRESHARED_KEY, SecretCommit.Store, null)
        assertTrue(vault.calls.isEmpty())
        assertEquals("original-PRESHARED_KEY", vault.stored[PROFILE to SecretKind.PRESHARED_KEY])
    }

    /** An empty-but-present buffer is the same mistake wearing a different hat. */
    @Test
    fun `a Store with an empty buffer is refused rather than writing an empty secret`() {
        val vault = vaultHolding(SecretKind.PRESHARED_KEY)
        applySecretCommit(
            vault,
            PROFILE,
            SecretKind.PRESHARED_KEY,
            SecretCommit.Store,
            CharArray(0),
        )
        assertTrue(vault.calls.isEmpty())
        assertEquals("original-PRESHARED_KEY", vault.stored[PROFILE to SecretKind.PRESHARED_KEY])
    }

    @Test
    fun `the buffer is scrubbed once the vault has taken a copy`() {
        val vault = FakeVault()
        val typed = "top-secret".toCharArray()
        applySecretCommit(vault, PROFILE, SecretKind.PASSWORD, SecretCommit.Store, typed)
        assertEquals("top-secret", vault.stored[PROFILE to SecretKind.PASSWORD])
        assertTrue(typed.all { it.code == 0 })
    }

    @Test
    fun `the buffer is scrubbed even when the commit ignores it`() {
        val typed = "top-secret".toCharArray()
        applySecretCommit(FakeVault(), PROFILE, SecretKind.PASSWORD, SecretCommit.Keep, typed)
        assertTrue(typed.all { it.code == 0 })
    }

    /** A vault that throws must not leave the characters behind in a live array. */
    @Test
    fun `the buffer is scrubbed even when the vault throws`() {
        val exploding = object : SecretVault {
            override fun isSet(profileId: String, kind: SecretKind) = false
            override fun store(profileId: String, kind: SecretKind, secret: CharArray) =
                throw IllegalStateException("keystore is gone")

            override fun clear(profileId: String, kind: SecretKind) = Unit
            override fun clearAll(profileId: String) = Unit
        }
        val typed = "top-secret".toCharArray()
        try {
            applySecretCommit(exploding, PROFILE, SecretKind.PASSWORD, SecretCommit.Store, typed)
        } catch (expected: IllegalStateException) {
            // the point is what happened to the buffer, not the exception
        }
        assertTrue(typed.all { it.code == 0 })
    }

    private companion object {
        const val PROFILE = "profile-1"
    }
}
