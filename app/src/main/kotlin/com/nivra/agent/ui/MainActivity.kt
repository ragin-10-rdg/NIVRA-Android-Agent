package com.nivra.agent.ui

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.nivra.agent.agent.AgentService
import com.nivra.agent.dpc.NivraDeviceAdminReceiver
import com.nivra.agent.ui.theme.NivraTheme

/**
 * NIVRA is a normal, launchable Android application: it appears in the App
 * Drawer with its own icon (see AndroidManifest's LAUNCHER intent-filter)
 * and this Activity, not a hidden background-only component. The UI here
 * is a *view into* the agent (via AgentViewModel -> AgentManager.status);
 * closing this Activity does not stop telemetry collection, which
 * continues via AgentService/WorkManager per Android background-execution
 * rules.
 */
sealed class Screen(val route: String, val label: String, val icon: androidx.compose.ui.graphics.vector.ImageVector) {
    object Dashboard : Screen("dashboard", "Dashboard", Icons.Filled.Dashboard)
    object Device : Screen("device", "Device", Icons.Filled.PhoneAndroid)
    object Applications : Screen("applications", "Apps", Icons.Filled.Apps)
    object Security : Screen("security", "Security", Icons.Filled.Security)
    object Events : Screen("events", "Events", Icons.Filled.History)
    object Connection : Screen("connection", "Wazuh", Icons.Filled.Cloud)
    object Settings : Screen("settings", "Settings", Icons.Filled.Settings)
}


class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        if (NivraDeviceAdminReceiver.isDeviceOwner(this)) {
            AgentService.start(this)
        }

        setContent {
            NivraTheme {
                NivraApp()
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NivraApp(viewModel: AgentViewModel = viewModel()) {
    val navController = rememberNavController()
    val status by viewModel.status.collectAsState()
    val focusManager = LocalFocusManager.current
    val keyboardController = LocalSoftwareKeyboardController.current

    // A focused text field (e.g. on the Settings screen) can leave an IME
    // session active; on some devices/configurations a tap on the bottom
    // nav bar or top bar icons right next to a screen edge is then consumed
    // by focus/IME handling instead of reaching the destination's onClick,
    // making navigation away feel stuck. Always drop focus and hide the
    // keyboard before navigating so this precondition never applies.
    fun navigateTo(route: String, block: androidx.navigation.NavOptionsBuilder.() -> Unit = {}) {
        focusManager.clearFocus(force = true)
        keyboardController?.hide()
        navController.navigate(route, block)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("NIVRA") },
                actions = {
                    IconButton(onClick = {
                        navigateTo(Screen.Connection.route) { launchSingleTop = true }
                    }) {
                        Icon(Screen.Connection.icon, contentDescription = Screen.Connection.label)
                    }
                    IconButton(onClick = {
                        navigateTo(Screen.Settings.route) { launchSingleTop = true }
                    }) {
                        Icon(Screen.Settings.icon, contentDescription = Screen.Settings.label)
                    }
                }
            )
        },
        bottomBar = {
            val navScreens = listOf(
                Screen.Dashboard, Screen.Device, Screen.Applications, Screen.Security, Screen.Events
            )
            NavigationBar {
                val backStackEntry by navController.currentBackStackEntryAsState()
                val currentDestination = backStackEntry?.destination
                navScreens.forEach { screen ->
                    NavigationBarItem(
                        icon = { Icon(screen.icon, contentDescription = screen.label) },
                        label = { Text(screen.label) },
                        selected = currentDestination?.hierarchy?.any { it.route == screen.route } == true,
                        onClick = {
                            // Deliberately no saveState/restoreState: that
                            // combination with popUpTo(startDestination)
                            // reproducibly failed to navigate to the start
                            // destination (Dashboard) when coming from a
                            // screen outside the tab set (e.g. Settings) --
                            // popUpTo+launchSingleTop alone reliably bounds
                            // the back stack to Dashboard without it.
                            navigateTo(screen.route) {
                                popUpTo(Screen.Dashboard.route) { inclusive = false }
                                launchSingleTop = true
                            }
                        }
                    )
                }
            }
        }
    ) { padding ->
        NavHost(
            navController = navController,
            startDestination = Screen.Dashboard.route,
            modifier = Modifier.padding(padding)
        ) {
            composable(Screen.Dashboard.route) { DashboardScreen(status, onRefresh = { viewModel.refresh() }) }
            composable(Screen.Device.route) { DeviceScreen(status) }
            composable(Screen.Applications.route) { ApplicationsScreen(status) }
            composable(Screen.Security.route) { SecurityScreen(status) }
            composable(Screen.Events.route) { EventsScreen(status) }
            composable(Screen.Connection.route) { WazuhConnectionScreen(status, onForceSend = { viewModel.forceDrainNow() }) }
            composable(Screen.Settings.route) {
                SettingsScreen(
                    prefs = viewModel.prefs,
                    onSave = { host, port, tls, hb, enabled, level ->
                        viewModel.saveSettings(host, port, tls, hb, enabled, level)
                    }
                )
            }
        }
    }
}
