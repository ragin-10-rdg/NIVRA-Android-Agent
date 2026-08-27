package com.nivra.agent.storage

import androidx.room.*
import com.nivra.agent.models.EventState

@Entity(tableName = "queued_events")
data class QueuedEventEntity(
    @PrimaryKey val eventId: String,
    val payloadJson: String,
    val eventType: String,
    val createdAtMs: Long,
    var state: String = EventState.PENDING.name,
    var attemptCount: Int = 0,
    var lastAttemptAtMs: Long? = null
)

@Dao
interface EventDao {
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insert(event: QueuedEventEntity)

    @Query("SELECT * FROM queued_events WHERE state IN ('PENDING','FAILED') ORDER BY createdAtMs ASC LIMIT :limit")
    suspend fun nextBatch(limit: Int = 50): List<QueuedEventEntity>

    @Query("UPDATE queued_events SET state = :state, attemptCount = attemptCount + 1, lastAttemptAtMs = :attemptAtMs WHERE eventId = :eventId")
    suspend fun markAttempt(eventId: String, state: String, attemptAtMs: Long)

    @Query("DELETE FROM queued_events WHERE state = 'SENT' AND createdAtMs < :beforeMs")
    suspend fun pruneDelivered(beforeMs: Long)

    @Query("DELETE FROM queued_events WHERE attemptCount >= :maxAttempts")
    suspend fun dropExhausted(maxAttempts: Int)

    @Query("SELECT COUNT(*) FROM queued_events WHERE state IN ('PENDING','FAILED')")
    suspend fun pendingCount(): Int

    @Query("SELECT COUNT(*) FROM queued_events WHERE state = 'SENT'")
    suspend fun sentCount(): Int

    @Query("SELECT COUNT(*) FROM queued_events WHERE state = 'FAILED'")
    suspend fun failedCount(): Int

    @Query("SELECT * FROM queued_events ORDER BY createdAtMs DESC LIMIT :limit")
    suspend fun recent(limit: Int = 25): List<QueuedEventEntity>
}

/** Persisted baseline of known-installed packages, so the new-install diff survives process death. */
@Entity(tableName = "known_packages")
data class KnownPackageEntity(
    @PrimaryKey val packageName: String,
    val firstSeenAtMs: Long
)

@Dao
interface KnownPackageDao {
    @Query("SELECT packageName FROM known_packages")
    suspend fun allPackageNames(): List<String>

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertAll(entities: List<KnownPackageEntity>)

    @Query("DELETE FROM known_packages WHERE packageName = :packageName")
    suspend fun remove(packageName: String)

    @Query("SELECT COUNT(*) FROM known_packages")
    suspend fun count(): Int
}

/** Persisted counters backing the four success metrics from the proposal. */
@Entity(tableName = "metrics_counters")
data class MetricsCounterEntity(
    @PrimaryKey val name: String,
    val value: Long
)

@Dao
interface MetricsDao {
    @Query("SELECT value FROM metrics_counters WHERE name = :name")
    suspend fun get(name: String): Long?

    @Query("""
        INSERT INTO metrics_counters (name, value) VALUES (:name, 1)
        ON CONFLICT(name) DO UPDATE SET value = value + 1
    """)
    suspend fun increment(name: String)

    @Query("SELECT * FROM metrics_counters")
    suspend fun all(): List<MetricsCounterEntity>
}

@Database(
    entities = [QueuedEventEntity::class, KnownPackageEntity::class, MetricsCounterEntity::class],
    version = 1,
    exportSchema = false
)
abstract class EventDatabase : RoomDatabase() {
    abstract fun eventDao(): EventDao
    abstract fun knownPackageDao(): KnownPackageDao
    abstract fun metricsDao(): MetricsDao

    companion object {
        @Volatile private var instance: EventDatabase? = null

        fun get(context: android.content.Context): EventDatabase =
            instance ?: synchronized(this) {
                instance ?: Room.databaseBuilder(
                    context.applicationContext,
                    EventDatabase::class.java,
                    "nivra_events.db"
                ).build().also { instance = it }
            }
    }
}
