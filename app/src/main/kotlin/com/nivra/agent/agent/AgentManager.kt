package com.nivra.agent.agent

import android.content.Context
import com.nivra.agent.collectors.ApplicationCollector
import com.nivra.agent.collectors.DeviceCollector
import com.nivra.agent.collectors.SecurityConfigCollector
import com.nivra.agent.collectors.SecurityLogCollector
import com.nivra.agent.dpc.NivraDeviceAdminReceiver
import com.nivra.agent.models.*
import com.nivra.agent.storage.EventQueue
import com.nivra.agent.storage.MetricsRecorder
import com.nivra.agent.storage.Preferences
import com.nivra.agent.transport.WazuhTransport
import com.nivra.agent.utils.CapabilityChecker
import com.nivra.agent.utils.Logger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONObject

/**
 * The single coordination point between collectors/queue/transport and
 * everything else. Per the layering requirement: the UI reads
 * AgentManager.status; it never talks to collectors or the transport
 * directly, and the agent keeps running to this same state regardless of
 * whether any UI screen is currently open.
 */
object AgentManager {

    private lateinit var appContext: Context
    private val initMutex = Mutex()
    private var initialized = false

    private lateinit var deviceCollector: DeviceCollector
    private lateinit var appCollector: ApplicationCollector
    private lateinit var configCollector: SecurityConfigCollector
    private lateinit var securityLogCollector: SecurityLogCollector
    private lateinit var queue: EventQueue
    private lateinit var transport: WazuhTransport
    private lateinit var metrics: MetricsRecorder
    private lateinit var prefs: Preferences

    private val _status = MutableStateFlow(AgentStatus())
    val status: StateFlow<AgentStatus> = _status.asStateFlow()

    suspend fun attach(context: Context) {
        initMutex.withLock {
            if (initialized) return
            appContext = context.applicationContext
            deviceCollector = DeviceCollector(appContext)
            appCollector = ApplicationCollector(appContext)
            configCollector = SecurityConfigCollector(appContext)
            securityLogCollector = SecurityLogCollector(appContext)
            queue = EventQueue(appContext)
            transport = WazuhTransport(appContext)
            metrics = MetricsRecorder(appContext)
            prefs = Preferences(appContext)
            initialized = true
        }
        refreshStatus()
    }

    suspend fun collectDeviceInfo() {
        val event = deviceCollector.collect()
        queue.enqueue(event)
        pushRecent(event)
    }

    suspend fun collectAppInventory() {
        val event = appCollector.collectSnapshot()
        queue.enqueue(event)
        pushRecent(event)

        appCollector.detectNewInstalls().forEach {
            queue.enqueue(it)
            pushRecent(it)
        }
    }

    suspend fun collectSecurityConfig() {
        val event = configCollector.collectIfDrifted()
        if (event != null) {
            queue.enqueue(event)
            pushRecent(event)
        }
    }

    suspend fun pollSecurityLogs() {
        securityLogCollector.collect().forEach {
            queue.enqueue(it)
            pushRecent(it)
        }
    }

    suspend fun sendHeartbeat() {
        val heartbeat = com.nivra.agent.normalization.EventNormalizer(appContext).normalize(
            EventType.HEARTBEAT, Severity.INFO, emptyMap()
        )
        queue.enqueue(heartbeat)
        pushRecent(heartbeat)
    }

    suspend fun drainQueue() {
        queue.drain(sendFn = { payload -> transport.send(payload) }, maxAttempts = 10)
        refreshStatus()
    }

    /** Recomputes the full observable AgentStatus snapshot for the UI. */
    suspend fun refreshStatus() {
        if (!initialized) return

        // deviceCollector.snapshot(), CapabilityChecker.allCapabilities() and
        // appCollector.currentInventory() are blocking DevicePolicyManager /
        // PackageManager Binder calls; refreshStatus() is called from
        // AgentViewModel on viewModelScope (Main dispatcher), so these must
        // not run on the caller's dispatcher.
        val (deviceInfo, capabilities, applications) = withContext(Dispatchers.IO) {
            Triple(
                deviceCollector.snapshot(),
                CapabilityChecker.allCapabilities(appContext),
                appCollector.currentInventory()
            )
        }
        val pending = queue.pendingCount()
        val sent = queue.sentCount()
        val failed = queue.failedCount()
        val recentEntities = queue.recent(25)
        val metricsSummary = metrics.summary()

        val recentEvents = recentEntities.mapNotNull { entity ->
            runCatching {
                val json = JSONObject(entity.payloadJson)
                val eventObj = json.optJSONObject("event")
                SecurityEvent(
                    eventId = json.optString("event_id"),
                    timestampUtc = java.time.Instant.parse(json.optString("timestamp")),
                    deviceId = json.optJSONObject("device")?.optString("device_id") ?: "",
                    androidVersion = json.optJSONObject("device")?.optString("android_version") ?: "",
                    securityPatch = json.optJSONObject("device")?.optString("security_patch") ?: "",
                    eventType = EventType.valueOf(eventObj?.optString("type") ?: "HEARTBEAT"),
                    severity = Severity.valueOf(eventObj?.optString("severity") ?: "INFO"),
                    data = emptyMap(),
                    state = EventState.valueOf(entity.state)
                )
            }.onFailure { e ->
                Logger.w(
                    "Failed to parse queued event ${entity.eventId} " +
                        "(type=${entity.eventType}) for status display: " +
                        "${e.javaClass.simpleName}: ${e.message}"
                )
            }.getOrNull()
        }

        _status.value = AgentStatus(
            isDeviceOwner = deviceInfo.isDeviceOwner,
            isRunning = true,
            device = deviceInfo,
            capabilities = capabilities,
            connectionStatus = connectionStatusFrom(pending, failed),
            wazuhServer = "${prefs.wazuhHost}:${prefs.wazuhPort}",
            eventsCollected = metricsSummary.eventsCollected,
            eventsSent = sent.toLong(),
            eventsPending = pending.toLong(),
            eventsFailed = failed.toLong(),
            lastHeartbeatEpochMs = recentEvents.firstOrNull { it.eventType == EventType.HEARTBEAT }
                ?.timestampUtc?.toEpochMilli(),
            lastSuccessfulDeliveryEpochMs = recentEvents.firstOrNull { it.state == EventState.SENT }
                ?.timestampUtc?.toEpochMilli(),
            recentEvents = recentEvents,
            applications = applications,
            securityEventCount24h = recentEvents.count {
                it.eventType == EventType.SECURITY_LOG &&
                    it.timestampUtc.isAfter(java.time.Instant.now().minusSeconds(86_400))
            }.toLong(),
            collectionSuccessRatePct = metricsSummary.collectionSuccessRatePct,
            deliveryReliabilityPct = metricsSummary.deliveryReliabilityPct
        )
    }

    private fun connectionStatusFrom(pending: Int, failed: Int): ConnectionStatus = when {
        failed > 5 -> ConnectionStatus.DISCONNECTED
        pending > 10 -> ConnectionStatus.DEGRADED
        else -> ConnectionStatus.CONNECTED
    }

    private fun pushRecent(event: SecurityEvent) {
        _status.value = _status.value.copy(
            recentEvents = (listOf(event) + _status.value.recentEvents).take(25)
        )
    }

    fun isDeviceOwner(context: Context) = NivraDeviceAdminReceiver.isDeviceOwner(context)
}
