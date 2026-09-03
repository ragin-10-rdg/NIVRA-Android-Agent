package com.nivra.agent.collectors

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.os.Build
import com.nivra.agent.dpc.NivraDeviceAdminReceiver
import com.nivra.agent.models.DeviceInfo
import com.nivra.agent.models.EventType
import com.nivra.agent.models.SecurityEvent
import com.nivra.agent.models.Severity
import com.nivra.agent.normalization.EventNormalizer
import com.nivra.agent.storage.MetricsRecorder

class DeviceCollector(private val context: Context) {

    private val normalizer = EventNormalizer(context)
    private val metrics = MetricsRecorder(context)

    suspend fun collect(): SecurityEvent {
        metrics.recordCollectionAttempt(EventType.DEVICE_INFO.name)
        val info = snapshot()

        val data = mapOf(
            "manufacturer" to info.manufacturer,
            "model" to info.model,
            "android_release" to info.androidRelease,
            "sdk_int" to info.sdkInt,
            "security_patch" to info.securityPatch,
            "encryption_status" to info.encryptionStatus,
            "is_device_owner" to info.isDeviceOwner
        )

        val event = normalizer.normalize(EventType.DEVICE_INFO, Severity.INFO, data)
        metrics.recordCollectionCompleted(EventType.DEVICE_INFO.name)
        return event
    }

    fun snapshot(): DeviceInfo {
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val isOwner = NivraDeviceAdminReceiver.isDeviceOwner(context)

        val encryptionStatus = if (isOwner) {
            try {
                encryptionStatusLabel(dpm.storageEncryptionStatus)
            } catch (e: SecurityException) {
                "UNKNOWN"
            }
        } else "UNKNOWN"

        return DeviceInfo(
            deviceId = com.nivra.agent.utils.DeviceIdentity.get(context),
            manufacturer = Build.MANUFACTURER,
            model = Build.MODEL,
            androidRelease = Build.VERSION.RELEASE ?: "unknown",
            sdkInt = Build.VERSION.SDK_INT,
            securityPatch = Build.VERSION.SECURITY_PATCH ?: "unknown",
            encryptionStatus = encryptionStatus,
            isDeviceOwner = isOwner
        )
    }

    private fun encryptionStatusLabel(status: Int): String = when (status) {
        DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE -> "ACTIVE"
        DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER -> "ACTIVE_PER_USER"
        DevicePolicyManager.ENCRYPTION_STATUS_ACTIVATING -> "ACTIVATING"
        DevicePolicyManager.ENCRYPTION_STATUS_INACTIVE -> "INACTIVE"
        DevicePolicyManager.ENCRYPTION_STATUS_UNSUPPORTED -> "UNSUPPORTED"
        else -> "UNKNOWN"
    }
}
