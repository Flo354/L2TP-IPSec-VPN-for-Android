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
 *
 * Nothing here touches storage. [VpnController.get] only allocates the state holder; the encrypted
 * store is opened by a coroutine on [kotlinx.coroutines.Dispatchers.IO], and the UI shows a loading
 * state until it is ready. Opening it inline in `onCreate`, as this class used to, put keystore
 * work and file I/O on the main looper of a cold start.
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
                    "Without the notification permission you will not see the tunnel's status",
                )
            }
            // Either way the connect carries on: POST_NOTIFICATIONS only decides whether the
            // ongoing notification is visible, not whether the foreground service may run.
            requestConsentAndStart()
        }

        setContent {
            L2tpVpnTheme {
                VpnApp(
                    controller = controller,
                    onConnect = ::requestConnect,
                    onDisconnect = ::requestDisconnect,
                    onExit = ::finish,
                )
            }
        }
    }

    /**
     * The two system dialogs are chained rather than launched together: firing both in the same
     * frame stacks the VPN consent on top of the permission prompt, and whichever the user answers
     * first silently answers for the other.
     *
     * The profile check in front of them is asynchronous now — it probes the secret vault, which is
     * keystore-backed file I/O and has no business running on the frame that handled the tap. The
     * controller calls back on the main thread once it knows.
     */
    private fun requestConnect() {
        controller.requestConnect {
            if (requestNotificationPermission()) return@requestConnect // its callback resumes
            requestConsentAndStart()
        }
    }

    private fun requestDisconnect() {
        L2tpVpnService.disconnect(this)
    }

    private fun requestConsentAndStart() {
        val consent = VpnService.prepare(this)
        if (consent != null) {
            vpnConsentLauncher.launch(consent)
        } else {
            startTunnel()
        }
    }

    private fun startTunnel() = L2tpVpnService.connect(this)

    /** @return `true` when a prompt was shown and the connect has to wait for its result. */
    private fun requestNotificationPermission(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return false
        val granted = ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
        if (granted) return false
        notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        return true
    }
}
