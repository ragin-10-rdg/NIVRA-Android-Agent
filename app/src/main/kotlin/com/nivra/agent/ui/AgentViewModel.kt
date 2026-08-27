package com.nivra.agent.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.nivra.agent.agent.AgentManager
import com.nivra.agent.storage.Preferences
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

/**
 * The only bridge between Compose screens and the agent. Screens read
 * [status] and call the thin action wrappers below; they never construct
 * collectors, the queue, or the transport themselves.
 */
class AgentViewModel(application: Application) : AndroidViewModel(application) {

    val status: StateFlow<com.nivra.agent.models.AgentStatus> = AgentManager.status
    val prefs = Preferences(application)

    init {
        viewModelScope.launch {
            AgentManager.attach(application)
            AgentManager.refreshStatus()
        }
    }

    fun refresh() {
        viewModelScope.launch { AgentManager.refreshStatus() }
    }

    fun forceDrainNow() {
        viewModelScope.launch { AgentManager.drainQueue() }
    }

    fun saveSettings(
        host: String,
        port: Int,
        tlsEnabled: Boolean,
        heartbeatSeconds: Int,
        agentEnabled: Boolean,
        logLevel: String
    ) {
        prefs.wazuhHost = host
        prefs.wazuhPort = port
        prefs.tlsEnabled = tlsEnabled
        prefs.heartbeatIntervalSeconds = heartbeatSeconds
        prefs.agentEnabled = agentEnabled
        prefs.logLevel = logLevel
        refresh()
    }
}
