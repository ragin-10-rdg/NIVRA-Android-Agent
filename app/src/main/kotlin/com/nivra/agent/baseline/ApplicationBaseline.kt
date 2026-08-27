package com.nivra.agent.baseline

import android.content.Context
import com.nivra.agent.storage.Preferences

/**
 * Defines exactly what "unexpected application" means, per the technical
 * spec's requirement that this not be left implicit. A package is
 * "approved" if it's in the Settings-configured baseline list OR is a
 * system app (system apps are pre-provisioned by the OEM/enrollment
 * profile, not installed by a user action worth alerting on).
 */
class ApplicationBaseline(context: Context) {

    private val prefs = Preferences(context)

    fun isApproved(packageName: String, isSystemApp: Boolean): Boolean {
        if (isSystemApp) return true
        return prefs.approvedPackages().contains(packageName)
    }

    fun approvedSet(): Set<String> = prefs.approvedPackages()

    fun addToBaseline(packageName: String) {
        val updated = (prefs.approvedPackages() + packageName).joinToString(",")
        prefs.approvedPackagesCsv = updated
    }
}
