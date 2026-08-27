package com.nivra.agent.storage

import com.nivra.agent.models.EventState
import com.nivra.agent.models.SecurityEvent

/**
 * Local durable queue. Every collected event is persisted here first
 * (PENDING), then a background pass in AgentManager attempts delivery:
 * SENDING -> SENT on success, SENDING -> FAILED (retry later) on failure.
 * Exhausted events (max attempts reached) are dropped and counted toward
 * the delivery-reliability metric as permanent failures.
 */
class EventQueue(context: android.content.Context) {

    private val dao = EventDatabase.get(context).eventDao()
    private val metrics = MetricsRecorder(context)

    suspend fun enqueue(event: SecurityEvent) {
        dao.insert(
            QueuedEventEntity(
                eventId = event.eventId,
                payloadJson = event.toJson().toString(),
                eventType = event.eventType.name,
                createdAtMs = System.currentTimeMillis()
            )
        )
        metrics.recordCollected(event.eventType.name)
    }

    suspend fun pendingCount(): Int = dao.pendingCount()
    suspend fun sentCount(): Int = dao.sentCount()
    suspend fun failedCount(): Int = dao.failedCount()
    suspend fun recent(limit: Int = 25): List<QueuedEventEntity> = dao.recent(limit)

    /**
     * Attempts delivery of the next batch. [sendFn] returns true on a
     * confirmed 2xx from the receiver. Retries use the existing attemptCount
     * (simple linear backoff via the drain interval itself, since Android
     * WorkManager already re-runs this periodically -- see AgentManager).
     */
    suspend fun drain(sendFn: suspend (String) -> Boolean, maxAttempts: Int) {
        dao.dropExhausted(maxAttempts)
        val batch = dao.nextBatch()
        for (entity in batch) {
            dao.markAttempt(entity.eventId, EventState.SENDING.name, System.currentTimeMillis())
            val delivered = try {
                sendFn(entity.payloadJson)
            } catch (e: Exception) {
                false
            }
            val finalState = if (delivered) EventState.SENT else EventState.FAILED
            dao.markAttempt(entity.eventId, finalState.name, System.currentTimeMillis())
            if (delivered) {
                metrics.recordDeliverySuccess(entity.eventType)
            } else {
                metrics.recordDeliveryFailure(entity.eventType)
            }
        }
        dao.pruneDelivered(System.currentTimeMillis() - PRUNE_AFTER_MS)
    }

    companion object {
        private const val PRUNE_AFTER_MS = 24L * 60 * 60 * 1000 // keep 24h of SENT history for the Events screen
    }
}
