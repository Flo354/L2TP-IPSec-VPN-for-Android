package com.arcansecurity.vpn.l2tpipsec.core.tunnel

import java.lang.reflect.Modifier
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The pre-shared key and the PPP password must never reach a human-readable string.
 *
 * This is not a theoretical concern. The Android app keeps the stack's trace in a ring buffer
 * behind a screen with a "copy" and a "share" button, so anything a log line, an exception message
 * or a crash report can render is one tap away from leaving the device. A `data class` hands out a
 * compiler-generated `toString()` that prints every property, which makes a single
 * `log.d { "$config" }` enough to publish both credentials.
 */
class VpnConfigSecrecyTest {

    private fun config() = VpnConfig(
        serverHost = "vpn.example.com",
        presharedKey = PSK,
        username = "alice",
        password = PASSWORD,
    )

    @Test
    fun `toString prints neither the pre-shared key nor the password`() {
        val rendered = config().toString()

        assertFalse("toString() leaked the pre-shared key: $rendered", rendered.contains(PSK))
        assertFalse("toString() leaked the password: $rendered", rendered.contains(PASSWORD))
    }

    @Test
    fun `toString says whether each secret is set, and nothing more`() {
        val withPassword = config().toString()
        val withoutPassword = config().copy(password = "").toString()

        assertTrue(withPassword, withPassword.contains("presharedKey=<redacted>"))
        assertTrue(withPassword, withPassword.contains("password=<redacted>"))
        assertTrue(withoutPassword, withoutPassword.contains("password=<unset>"))
    }

    /**
     * A redaction that grew a length, a prefix or a hash would be a leak in slow motion: the length
     * of a pre-shared key is exactly the parameter that decides how expensive guessing it is.
     */
    @Test
    fun `the redaction reveals nothing about the secret it stands for`() {
        val short = config().copy(presharedKey = "x", password = "y").toString()
        val long = config().copy(presharedKey = "x".repeat(64), password = "y".repeat(64)).toString()

        assertEquals(short, long)
    }

    /** Redacting must not cost the diagnostics that make a shared trace worth reading. */
    @Test
    fun `toString keeps the detail a support trace needs`() {
        val rendered = config().toString()

        assertTrue(rendered, rendered.contains("serverHost=vpn.example.com"))
        assertTrue(rendered, rendered.contains("mtu=1400"))
        assertTrue(rendered, rendered.contains("exchangeMode=MAIN"))
    }

    /**
     * `require` messages are the classic second leak: they are built from the very values that were
     * just rejected, and they travel further than a log line because they ride an exception.
     */
    @Test
    fun `no constructor check puts a secret in its message`() {
        val rejected = listOf(
            runCatching { config().copy(serverHost = " ") },
            runCatching { config().copy(presharedKey = "") },
            runCatching { config().copy(mtu = 42) },
            runCatching { config().copy(allowedPppAuth = emptyList()) },
        )

        for (attempt in rejected) {
            val error = attempt.exceptionOrNull()
            assertTrue("this input should have been rejected: $attempt", error is IllegalArgumentException)
            val text = error.toString()
            assertFalse("a constructor check leaked the pre-shared key: $text", text.contains(PSK))
            assertFalse("a constructor check leaked the password: $text", text.contains(PASSWORD))
        }
    }

    /**
     * The guard that outlives this commit. [toString] is hand-written, so a property added later is
     * invisible to it — safe by omission, but only until someone appends the new field by hand. By
     * enumerating the class the test forces that author through here, where the choice between
     * "secret" and "safe" has to be made explicitly.
     */
    @Test
    fun `every property of VpnConfig is classified as secret or safe`() {
        val declared = VpnConfig::class.java.declaredFields
            .filterNot { it.isSynthetic || Modifier.isStatic(it.modifiers) }
            .map { it.name }
            .toSet()

        assertEquals(
            "VpnConfig gained or lost a property: list it in SECRET_PROPERTIES or SAFE_PROPERTIES, " +
                "and make sure toString() redacts it if it is a credential",
            SECRET_PROPERTIES + SAFE_PROPERTIES,
            declared,
        )
    }

    /** Applies the classification above to the real values, so a new secret cannot be printed raw. */
    @Test
    fun `no property classified as secret appears in toString`() {
        val config = config()
        val rendered = config.toString()

        for (name in SECRET_PROPERTIES) {
            val value = VpnConfig::class.java.getDeclaredField(name)
                .apply { isAccessible = true }
                .get(config) as String

            assertTrue(
                "$name is classified secret but the fixture leaves it empty, so this test proves " +
                    "nothing about it: give it a sentinel in config()",
                value.isNotEmpty(),
            )
            assertFalse("toString() leaked $name: $rendered", rendered.contains(value))
        }
    }

    /**
     * `data class` also generates `componentN()`, so `val (host, psk, user, password) = config`
     * compiles. That is not an access hole — every property already has a public getter, and
     * destructuring reads exactly what the getter would. The hazard is that it binds by *position*
     * among four same-typed `String`s: inserting or reordering a constructor parameter would
     * silently rebind every destructuring site, and a local named `host` holding the pre-shared key
     * would then flow into a log line that had been audited as safe, with nothing for the compiler
     * to complain about. Nothing destructures [VpnConfig] today; pinning the positions means such a
     * reorder fails here rather than in somebody's shared log file.
     */
    @Test
    fun `the secrets keep the component positions any destructuring would bind to`() {
        val config = config()

        assertEquals("component2() is no longer the pre-shared key", PSK, config.component2())
        assertEquals("component4() is no longer the password", PASSWORD, config.component4())
    }

    private companion object {
        /** Distinctive enough that a substring match cannot succeed by accident. */
        const val PSK = "psk-sentinel-4f3a9c7e"
        const val PASSWORD = "password-sentinel-7b21de08"

        val SECRET_PROPERTIES = setOf("presharedKey", "password")

        val SAFE_PROPERTIES = setOf(
            "serverHost", "username", "exchangeMode", "localIdentity", "phase1", "phase2",
            "forceUdpEncapsulation", "ikePort", "natTraversalPort", "l2tpPort", "allowedPppAuth",
            "mtu", "l2tpHostName", "dnsOverride", "blockIpv6", "rekeyEnabled", "saOverlapMs",
            "ikeRetransmitTimeoutMs", "ikeMaxRetransmits", "connectTimeoutMs",
            "natKeepaliveIntervalMs", "l2tpHelloIntervalMs", "debugLogging",
        )
    }
}
