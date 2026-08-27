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
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
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

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("NIVRA") },
                actions = {
                    IconButton(onClick = { navController.navigate(Screen.Connection.route) }) {
                        Icon(Screen.Connection.icon, contentDescription = Screen.Connection.label)
                    }
                    IconButton(onClick = { navController.navigate(Screen.Settings.route) }) {
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
                            navController.navigate(screen.route) {
                                popUpTo(navController.graph.findStartDestination().id) { saveState = true }
                                launchSingleTop = true
                                restoreState = true
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
