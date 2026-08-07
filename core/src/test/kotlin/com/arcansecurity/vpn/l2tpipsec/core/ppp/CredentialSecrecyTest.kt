package com.arcansecurity.vpn.l2tpipsec.core.ppp

import com.arcansecurity.vpn.l2tpipsec.core.l2tp.L2tpAvp
import com.arcansecurity.vpn.l2tpipsec.core.l2tp.L2tpAvpType
import com.arcansecurity.vpn.l2tpipsec.core.util.Bytes
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The bodies of PPP control packets and L2TP AVPs are not automatically harmless: a PAP
 * Authenticate-Request body is literally the cleartext password, a CHAP response is authentication
 * material, and an un-hidden L2TP AVP carries whatever the tunnel secret protected.
 *
 * Nothing logs these objects today, so this pins the property rather than fixing a live leak — but
 * `toString()` is one interpolation away from logcat and from the app's share-log action, and that
 * is exactly the kind of change nobody re-audits.
 */
class CredentialSecrecyTest {

    private val password = "hunter2-correct-horse"

    @Test
    fun `a PAP authenticate-request does not print the password`() {
        // Body layout is peer-id length, peer-id, password length, password.
        val user = "vpnuser".toByteArray()
        val secret = password.toByteArray()
        val body = ByteArray(2 + user.size + secret.size)
        body[0] = user.size.toByte()
        user.copyInto(body, 1)
        body[1 + user.size] = secret.size.toByte()
        secret.copyInto(body, 2 + user.size)

        val rendered = PppControlPacket(PppCode.CONFIGURE_REQUEST, 1, body).toString()

        assertFalse("the password must not appear", rendered.contains(password))
        assertFalse("nor its hex encoding", rendered.contains(Bytes.toHex(secret)))
        assertTrue("the size is still worth reporting", rendered.contains("${body.size} bytes"))
    }

    @Test
    fun `a ppp option does not print its value`() {
        val secretish = Bytes.fromHex("0badc0ffee")
        val rendered = PppOption(3, secretish).toString()

        assertFalse(rendered.contains(Bytes.toHex(secretish)))
        assertTrue(rendered.contains("type=3"))
        assertTrue(rendered.contains("5 bytes"))
    }

    @Test
    fun `an l2tp avp does not print its body`() {
        val challenge = Bytes.fromHex("00112233445566778899aabbccddeeff")
        val rendered = L2tpAvp.raw(L2tpAvpType.ChallengeResponse, challenge).toString()

        assertFalse("challenge material must not appear", rendered.contains(Bytes.toHex(challenge)))
        assertTrue("the attribute is still identifiable", rendered.contains("ChallengeResponse"))
        assertTrue(rendered.contains("16 bytes"))
    }

    @Test
    fun `an unknown avp is still identifiable in a log line without its body`() {
        val body = Bytes.fromHex("deadbeef")
        // This is the shape L2tpTunnel logs for an unknown mandatory AVP.
        val rendered = L2tpAvp(mandatory = true, hidden = false, vendorId = 0, type = 9999, value = body).toString()

        assertFalse(rendered.contains("deadbeef"))
        assertTrue("the type is what makes the warning actionable", rendered.contains("9999"))
        assertTrue("and that it was mandatory", rendered.contains("(M)"))
    }
}
