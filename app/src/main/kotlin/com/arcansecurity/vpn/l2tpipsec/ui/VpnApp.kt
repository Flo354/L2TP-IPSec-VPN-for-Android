package com.arcansecurity.vpn.l2tpipsec.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunnelState
import com.arcansecurity.vpn.l2tpipsec.data.ProfileStoreState
import com.arcansecurity.vpn.l2tpipsec.ui.screens.HomeScreen
import com.arcansecurity.vpn.l2tpipsec.ui.screens.ProfileEditScreen
import com.arcansecurity.vpn.l2tpipsec.ui.screens.ProfileListScreen

/**
 * The whole app: three screens over one Activity, plus the logs on a bottom sheet.
 *
 * Navigation is a plain back stack in [VpnController] rather than a navigation library — there are
 * three destinations, one of them has an argument, and the state holder already outlives the
 * Activity, which is the only thing a library would have bought.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VpnApp(
    controller: VpnController,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
    onExit: () -> Unit,
) {
    val backStack by controller.backStack.collectAsState()
    val route = backStack.last()
    val storeState by controller.storeState.collectAsState()
    val profiles by controller.profiles.collectAsState()
    val activeProfileId by controller.activeProfileId.collectAsState()
    val usesEncryptedStorage by controller.usesEncryptedStorage.collectAsState()
    val editor by controller.editor.collectAsState()
    val saving by controller.saving.collectAsState()
    val message by controller.message.collectAsState()

    val state by controller.status.state.collectAsState()
    val detail by controller.status.detail.collectAsState()
    val info by controller.status.info.collectAsState()
    val stats by controller.status.stats.collectAsState()
    val failure by controller.status.failure.collectAsState()
    val connectedSince by controller.status.connectedSinceMs.collectAsState()

    var logsVisible by remember { mutableStateOf(false) }
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(message) {
        message?.let {
            snackbarHostState.showSnackbar(it)
            controller.consumeMessage()
        }
    }

    BackHandler(enabled = true) {
        if (!controller.back()) onExit()
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(titleFor(route, editor)) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background,
                ),
                navigationIcon = {
                    if (backStack.size > 1) {
                        IconButton(onClick = { controller.back() }) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                        }
                    }
                },
                actions = {
                    if (route == Route.Profiles) {
                        IconButton(onClick = { controller.openEditor(null) }) {
                            Icon(Icons.Filled.Add, contentDescription = "Add a profile")
                        }
                    }
                    IconButton(onClick = { logsVisible = true }) {
                        Icon(Icons.AutoMirrored.Filled.List, contentDescription = "Logs")
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
        containerColor = MaterialTheme.colorScheme.background,
    ) { padding ->
        Box(modifier = Modifier.fillMaxSize().padding(padding)) {
            // The store is opened off the main thread, so there is a real moment before anything is
            // known. Showing it beats an empty list that briefly claims the user has no profiles.
            if (storeState == ProfileStoreState.LOADING) {
                Loading("Opening the profile store…")
                return@Box
            }

            when (route) {
                Route.Home -> HomeScreen(
                    state = state,
                    detail = detail,
                    info = info,
                    stats = stats,
                    failure = failure,
                    connectedSinceMs = connectedSince,
                    activeProfile = profiles.firstOrNull { it.id == activeProfileId },
                    profileCount = profiles.size,
                    storeIsUnreadable = storeState == ProfileStoreState.UNREADABLE,
                    usesEncryptedStorage = usesEncryptedStorage,
                    onConnect = onConnect,
                    onDisconnect = onDisconnect,
                    onEditActive = { controller.openEditor(activeProfileId) },
                    onOpenProfiles = { controller.navigateTo(Route.Profiles) },
                    onCreateProfile = { controller.openEditor(null) },
                )

                Route.Profiles -> ProfileListScreen(
                    profiles = profiles,
                    activeProfileId = activeProfileId,
                    onActivate = { controller.setActive(it.id) },
                    onEdit = { controller.openEditor(it.id) },
                    onDuplicate = { controller.duplicate(it) },
                    onDelete = { controller.delete(it) },
                    onCreate = { controller.openEditor(null) },
                )

                Route.Editor -> when (val current = editor) {
                    null, EditorState.Loading -> Loading("Loading the profile…")
                    is EditorState.Ready -> ProfileEditScreen(
                        form = current.form,
                        saving = saving,
                        tunnelIsUp = state == TunnelState.CONNECTED,
                        onFormChange = { transform -> controller.updateEditor(transform) },
                        onSave = { psk, password ->
                            controller.saveEditor(psk, password) { controller.back() }
                        },
                    )
                }
            }
        }
    }

    if (logsVisible) {
        LogsSheet(logger = controller.logger, onDismiss = { logsVisible = false })
    }
}

@Composable
private fun Loading(text: String) {
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            CircularProgressIndicator()
            Spacer(Modifier.height(16.dp))
            Text(
                text = text,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
        }
    }
}

private fun titleFor(route: Route, editor: EditorState?): String = when (route) {
    Route.Home -> "L2TP/IPsec VPN"
    Route.Profiles -> "Profiles"
    Route.Editor -> when {
        editor !is EditorState.Ready -> "Profile"
        editor.form.isNew -> "New profile"
        else -> "Edit profile"
    }
}
