package com.arcansecurity.vpn.l2tpipsec.service

import org.junit.Assert.assertEquals
import org.junit.Test

class StartActionTest {

    @Test
    fun `our own connect action connects`() {
        assertEquals(
            StartAction.CONNECT,
            startActionFor(L2tpVpnService.ACTION_CONNECT, tunnelRunning = false),
        )
    }

    /**
     * Always-on VPN is started by the framework with `VpnService.SERVICE_INTERFACE`, which is the
     * action the manifest advertises. Falling through to the unknown-action branch stopped the
     * service the instant the platform started it, so always-on never came up at all.
     */
    @Test
    fun `the platform's always-on start action connects`() {
        assertEquals(
            StartAction.CONNECT,
            startActionFor(VPN_SERVICE_INTERFACE, tunnelRunning = false),
        )
        assertEquals("android.net.VpnService", VPN_SERVICE_INTERFACE)
    }

    @Test
    fun `the disconnect action disconnects`() {
        assertEquals(
            StartAction.DISCONNECT,
            startActionFor(L2tpVpnService.ACTION_DISCONNECT, tunnelRunning = true),
        )
    }

    @Test
    fun `a redelivered start command leaves a live tunnel alone`() {
        assertEquals(StartAction.KEEP_RUNNING, startActionFor(null, tunnelRunning = true))
    }

    @Test
    fun `a redelivered start command with nothing running stops the service`() {
        assertEquals(StartAction.DISCONNECT, startActionFor(null, tunnelRunning = false))
    }

    @Test
    fun `an action nobody recognises stops the service`() {
        assertEquals(
            StartAction.DISCONNECT,
            startActionFor("com.example.NOPE", tunnelRunning = true),
        )
    }
}
