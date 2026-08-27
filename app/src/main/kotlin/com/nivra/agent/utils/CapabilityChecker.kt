package com.nivra.agent.utils

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.os.Build
import com.nivra.agent.dpc.NivraDeviceAdminReceiver
import com.nivra.agent.models.CapabilityInfo
import com.nivra.agent.models.CapabilityStatus

/**
 * Detects, per the spec's "capability detection" requirement, whether a
 * given privileged telemetry source is actually available and authorized on
 * *this* device/Android build -- rather than assuming SecurityLog or
 * network-logging will always be present. Collectors consult this before
 * collecting and degrade gracefully (skip + report the limitation) when a
 * capability is unavailable.
 */
object CapabilityChecker {

    fun securityLogCapability(context: Context): CapabilityInfo {
        if (!NivraDeviceAdminReceiver.isDeviceOwner(context)) {
            return CapabilityInfo("security_log", CapabilityStatus.UNAVAILABLE, "Not Device Owner")
        }
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val admin = NivraDeviceAdminReceiver.componentName(context)
        return try {
            val enabled = dpm.isSecurityLoggingEnabled(admin)
            if (enabled) {
                CapabilityInfo("security_log", CapabilityStatus.AVAILABLE)
            } else {
                CapabilityInfo("security_log", CapabilityStatus.UNAVAILABLE, "Security logging not enabled")
            }
        } catch (e: SecurityException) {
            CapabilityInfo("security_log", CapabilityStatus.UNAVAILABLE, e.message)
        }
    }

    fun networkLoggingCapability(context: Context): CapabilityInfo {
        if (!NivraDeviceAdminReceiver.isDeviceOwner(context)) {
            return CapabilityInfo("network_logging", CapabilityStatus.UNAVAILABLE, "Not Device Owner")
        }
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val admin = NivraDeviceAdminReceiver.componentName(context)
        return try {
            val enabled = dpm.isNetworkLoggingEnabled(admin)
            if (enabled) {
                CapabilityInfo("network_logging", CapabilityStatus.AVAILABLE)
            } else {
                CapabilityInfo("network_logging", CapabilityStatus.UNAVAILABLE, "Network logging not enabled")
            }
        } catch (e: SecurityException) {
            CapabilityInfo("network_logging", CapabilityStatus.UNAVAILABLE, e.message)
        }
    }

    fun deviceOwnerCapability(context: Context): CapabilityInfo =
        if (NivraDeviceAdminReceiver.isDeviceOwner(context)) {
            CapabilityInfo("device_owner", CapabilityStatus.AVAILABLE)
        } else {
            CapabilityInfo("device_owner", CapabilityStatus.UNAVAILABLE, "Not provisioned as Device Owner")
        }

    fun securityPatchCapability(): CapabilityInfo =
        if (Build.VERSION.SECURITY_PATCH.isNullOrBlank()) {
            CapabilityInfo("security_patch", CapabilityStatus.UNAVAILABLE, "Not reported by this build")
        } else {
            CapabilityInfo("security_patch", CapabilityStatus.AVAILABLE)
        }

    fun allCapabilities(context: Context): List<CapabilityInfo> = listOf(
        deviceOwnerCapability(context),
        securityLogCapability(context),
        networkLoggingCapability(context),
        securityPatchCapability()
    )
}
