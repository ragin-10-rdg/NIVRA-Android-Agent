package com.nivra.agent.storage

/**
 * Persists the counters needed to actually calculate the proposal's success
 * metrics (collection success rate, delivery reliability, and -- combined
 * with the Wazuh-side alert log -- detection accuracy / false-positive
 * rate) rather than just asserting targets were met.
 */
class MetricsRecorder(context: android.content.Context) {

    private val dao = EventDatabase.get(context).metricsDao()

    /** Raw count of individual events produced, for the Dashboard's "Collected" display only. */
    suspend fun recordCollected(eventType: String) {
        dao.increment("collect_success_$eventType")
    }

    suspend fun recordCollectionAttempt(eventType: String) {
        dao.increment("collect_attempt_$eventType")
    }

    suspend fun recordCollectionUnavailable(eventType: String) {
        dao.increment("collect_unavailable_$eventType")
    }

    /**
     * One per successfully-completed collector *invocation* (not per event
     * produced) -- pairs 1:1 with recordCollectionAttempt so their ratio is a
     * real success rate. A collector call that completes without throwing
     * counts as a success here even if it produced zero events (e.g. "no
     * config drift this cycle" is a successful poll, not a failure).
     */
    suspend fun recordCollectionCompleted(eventType: String) {
        dao.increment("collect_completed_$eventType")
    }

    suspend fun recordDeliverySuccess(eventType: String) {
        dao.increment("delivery_success_$eventType")
        dao.increment("delivery_success_total")
    }

    suspend fun recordDeliveryFailure(eventType: String) {
        dao.increment("delivery_failure_$eventType")
        dao.increment("delivery_failure_total")
    }

    /**
     * Returns collection success rate and delivery reliability as
     * percentages, ready for the Dashboard/Settings screens and for the
     * evaluation phase writeup.
     */
    suspend fun summary(): MetricsSummary {
        val all = dao.all().associate { it.name to it.value }
        val attempts = all.filterKeys { it.startsWith("collect_attempt_") }.values.sum()
        val completed = all.filterKeys { it.startsWith("collect_completed_") }.values.sum()
        val eventsCollected = all.filterKeys { it.startsWith("collect_success_") }.values.sum()
        val deliverySuccess = all["delivery_success_total"] ?: 0
        val deliveryFailure = all["delivery_failure_total"] ?: 0
        val deliveryTotal = deliverySuccess + deliveryFailure

        return MetricsSummary(
            collectionSuccessRatePct = percentage(completed, attempts),
            deliveryReliabilityPct = percentage(deliverySuccess, deliveryTotal),
            eventsCollected = eventsCollected,
            eventsDelivered = deliverySuccess,
            eventsFailed = deliveryFailure
        )
    }

    private fun percentage(numerator: Long, denominator: Long): Double =
        if (denominator == 0L) 100.0 else (numerator.toDouble() / denominator.toDouble()) * 100.0
}

data class MetricsSummary(
    val collectionSuccessRatePct: Double,
    val deliveryReliabilityPct: Double,
    val eventsCollected: Long,
    val eventsDelivered: Long,
    val eventsFailed: Long
)
