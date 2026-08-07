package com.arcansecurity.vpn.l2tpipsec.ui

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import com.arcansecurity.vpn.l2tpipsec.service.L2tpVpnService
import com.arcansecurity.vpn.l2tpipsec.ui.theme.L2tpVpnTheme

/**
 * The app's only Activity.
 *
 * Its job beyond hosting the Compose tree is the connect handshake: `VpnService.prepare` returns
 * an Intent the first time (the system consent dialog), and the service must not be started until
 * that dialog comes back `RESULT_OK`. Android 13+ additionally needs `POST_NOTIFICATIONS` for the
 * foreground service's notification to be visible.
 */
class MainActivity : ComponentActivity() {

    private lateinit var controller: VpnController
    private lateinit var vpnConsentLauncher: ActivityResultLauncher<Intent>
    private lateinit var notificationPermissionLauncher: ActivityResultLauncher<String>

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        controller = VpnController.get(this)

        vpnConsentLauncher = registerForActivityResult(
            ActivityResultContracts.StartActivityForResult(),
        ) { result ->
            if (result.resultCode == RESULT_OK) {
                startTunnel()
            } else {
                controller.showMessage("VPN permission was denied")
            }
        }

        notificationPermissionLauncher = registerForActivityResult(
            ActivityResultContracts.RequestPermission(),
        ) { granted ->
            if (!granted) {
                controller.showMessage(
                    "Without the notification permission the tunnel may be stopped in the background",
                )
            }
        }

        setContent {
            L2tpVpnTheme {
                VpnApp(
                    controller = controller,
                    onConnect = ::requestConnect,
                    onDisconnect = ::requestDisconnect,
                )
            }
        }
    }

    override fun onStop() {
        // Keep whatever was typed, even if the process is killed while in the background.
        controller.persist()
        super.onStop()
    }

    private fun requestConnect() {
        if (!controller.prepareForConnect()) return
        requestNotificationPermissionIfNeeded()

        val consent = VpnService.prepare(this)
        if (consent != null) {
            vpnConsentLauncher.launch(consent)
        } else {
            startTunnel()
        }
    }

    private fun requestDisconnect() {
        L2tpVpnService.disconnect(this)
    }

    private fun startTunnel() = L2tpVpnService.connect(this)

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        val granted = ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
        if (!granted) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }
}
