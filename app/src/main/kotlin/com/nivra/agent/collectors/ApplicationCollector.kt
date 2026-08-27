package com.nivra.agent.collectors

import android.content.Context
import android.content.pm.ApplicationInfo as AndroidAppInfo
import android.content.pm.PackageManager
import com.nivra.agent.baseline.ApplicationBaseline
import com.nivra.agent.models.ApplicationInfo
import com.nivra.agent.models.EventType
import com.nivra.agent.models.SecurityEvent
import com.nivra.agent.models.Severity
import com.nivra.agent.normalization.EventNormalizer
import com.nivra.agent.storage.EventDatabase
import com.nivra.agent.storage.KnownPackageEntity
import com.nivra.agent.storage.MetricsRecorder

/**
 * Collects application inventory metadata (never app content) and, using a
 * Room-persisted known-package table, reliably detects genuinely new
 * installs across process restarts -- the in-memory diff from the earlier
 * prototype has been replaced per the "known simplification" callout.
 */
class ApplicationCollector(private val context: Context) {

    private val normalizer = EventNormalizer(context)
    private val metrics = MetricsRecorder(context)
    private val baseline = ApplicationBaseline(context)
    private val knownPackageDao = EventDatabase.get(context).knownPackageDao()

    fun currentInventory(): List<ApplicationInfo> {
        val pm = context.packageManager
        val apps = pm.getInstalledApplications(PackageManager.GET_META_DATA)

        return apps.map { appInfo ->
            val packageName = appInfo.packageName
            val installerPackage = try {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(packageName)
            } catch (e: Exception) {
                null
            }
            val pkgInfo = pm.getPackageInfo(packageName, 0)
            val isSystem = (appInfo.flags and AndroidAppInfo.FLAG_SYSTEM) != 0

            ApplicationInfo(
                packageName = packageName,
                versionName = pkgInfo.versionName,
                isSystemApp = isSystem,
                installerPackage = installerPackage,
                firstInstallTime = pkgInfo.firstInstallTime,
                lastUpdateTime = pkgInfo.lastUpdateTime,
                approved = baseline.isApproved(packageName, isSystem)
            )
        }
    }

    /** Full-inventory snapshot event, collected periodically. */
    suspend fun collectSnapshot(): SecurityEvent {
        metrics.recordCollectionAttempt(EventType.APPLICATION_INVENTORY.name)
        val inventory = currentInventory()

        val data = mapOf(
            "app_count" to inventory.size,
            "applications" to inventory.map {
                mapOf(
                    "package_name" to it.packageName,
                    "version_name" to it.versionName,
                    "is_system_app" to it.isSystemApp,
                    "installer_package" to it.installerPackage,
                    "first_install_time" to it.firstInstallTime,
                    "last_update_time" to it.lastUpdateTime,
                    "approved" to it.approved
                )
            }
        )

        return normalizer.normalize(EventType.APPLICATION_INVENTORY, Severity.INFO, data)
    }

    /**
     * Diffs the current package set against the persisted known-package
     * table, returning one APPLICATION_INSTALL event per genuinely new
     * package (severity escalated if it's not on the approved baseline),
     * and updates the table so the diff survives process death/reboot.
     */
    suspend fun detectNewInstalls(): List<SecurityEvent> {
        val currentPackages = context.packageManager
            .getInstalledApplications(PackageManager.GET_META_DATA)
            .associateBy { it.packageName }

        val known = knownPackageDao.allPackageNames().toSet()
        val currentNames = currentPackages.keys

        if (known.isEmpty()) {
            // First run: seed the baseline table without emitting alerts for
            // the device's pre-existing inventory.
            knownPackageDao.insertAll(
                currentNames.map { KnownPackageEntity(it, System.currentTimeMillis()) }
            )
            return emptyList()
        }

        val newlyInstalled = currentNames - known
        if (newlyInstalled.isEmpty()) return emptyList()

        knownPackageDao.insertAll(
            newlyInstalled.map { KnownPackageEntity(it, System.currentTimeMillis()) }
        )

        return newlyInstalled.map { pkg ->
            val appInfo = currentPackages[pkg]
            val isSystem = appInfo != null && (appInfo.flags and AndroidAppInfo.FLAG_SYSTEM) != 0
            val approved = baseline.isApproved(pkg, isSystem)

            normalizer.normalize(
                EventType.APPLICATION_INSTALL,
                severity = if (approved) Severity.LOW else Severity.MEDIUM,
                data = mapOf("package_name" to pkg, "approved" to approved, "is_system_app" to isSystem)
            )
        }
    }
}
