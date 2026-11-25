package com.eyalm.adns.data.activation

import com.hamondev.shevery.api.SheveryApiConstants
import java.util.concurrent.atomic.AtomicReference

enum class PrivilegedApiBackend {
    Shevery,
    Shizuku,
}

enum class BinderDeliverySource {
    None,
    SheveryProvider,
    SheveryConnectFast,
    ShizukuProvider,
}

object PrivilegedBinderOriginTracker {
    private val source = AtomicReference(BinderDeliverySource.None)

    fun current(): BinderDeliverySource = source.get()

    fun mark(newSource: BinderDeliverySource) {
        source.set(newSource)
    }

    fun clear() {
        source.set(BinderDeliverySource.None)
    }
}

object PrivilegedBinderChannelPolicy {
    const val ROOT_UID = 0
    const val SHELL_UID = 2000

    fun isTrustedServerUid(uid: Int): Boolean =
        uid == ROOT_UID || uid == SHELL_UID

    fun isTrustedBinderSenderUid(callingUid: Int, myUid: Int): Boolean =
        isTrustedServerUid(callingUid) || callingUid == myUid

    /**
     * Validates a ContentProvider.call() invocation on a client app's Shevery/Shizuku provider.
     *
     * Returns true if the call is permitted to proceed, false if the caller is trusted but the
     * method is unsupported on a client provider, or throws [SecurityException] if unauthorized.
     */
    fun enforceProviderCall(
        method: String,
        callingUid: Int,
        myUid: Int,
        isSheveryProvider: Boolean,
    ): Boolean {
        if (!isTrustedBinderSenderUid(callingUid, myUid)) {
            throw SecurityException("Unauthorized privileged provider call from uid=$callingUid")
        }
        return when (method) {
            SheveryApiConstants.METHOD_SEND_BINDER -> true
            SheveryApiConstants.METHOD_GET_BINDER -> {
                if (callingUid != myUid) {
                    throw SecurityException("Unauthorized binder read from uid=$callingUid")
                }
                true
            }
            SheveryApiConstants.METHOD_REQUEST_BINDER -> {
                if (!isSheveryProvider) {
                    false
                } else if (callingUid != myUid) {
                    throw SecurityException("Unauthorized binder request from uid=$callingUid")
                } else {
                    true
                }
            }
            else -> false
        }
    }
}

data class PrivilegedBackendDetectionInput(
    val isSui: Boolean,
    val sheveryBinderAlive: Boolean,
    val shizukuBinderAlive: Boolean,
    val deliverySource: BinderDeliverySource,
    val sheveryServerVersion: Int,
    val shizukuServerVersion: Int,
)

object PrivilegedBackendDetector {
    fun detectActiveBackend(input: PrivilegedBackendDetectionInput): PrivilegedApiBackend? {
        if (input.isSui && input.shizukuBinderAlive) {
            return PrivilegedApiBackend.Shizuku
        }
        if (!input.sheveryBinderAlive && !input.shizukuBinderAlive) {
            return null
        }

        when (input.deliverySource) {
            BinderDeliverySource.SheveryProvider,
            BinderDeliverySource.SheveryConnectFast,
            -> if (input.sheveryBinderAlive) return PrivilegedApiBackend.Shevery

            BinderDeliverySource.ShizukuProvider ->
                if (input.shizukuBinderAlive) return PrivilegedApiBackend.Shizuku

            BinderDeliverySource.None -> Unit
        }

        if (
            input.sheveryBinderAlive &&
            input.sheveryServerVersion >= SheveryApiConstants.SERVER_VERSION
        ) {
            return PrivilegedApiBackend.Shevery
        }
        if (input.shizukuBinderAlive) {
            return PrivilegedApiBackend.Shizuku
        }
        return if (input.sheveryBinderAlive) PrivilegedApiBackend.Shevery else null
    }

    fun shouldUseExecFast(
        backend: PrivilegedApiBackend,
        serverVersion: Int,
        hasShellExecCapability: Boolean,
    ): Boolean = backend == PrivilegedApiBackend.Shevery &&
        serverVersion >= SheveryApiConstants.SERVER_VERSION &&
        hasShellExecCapability

    fun detectPreferredInstalledBackend(
        sheveryManagerInstalled: Boolean,
        shizukuManagerInstalled: Boolean,
    ): PrivilegedApiBackend? = when {
        sheveryManagerInstalled && !shizukuManagerInstalled -> PrivilegedApiBackend.Shevery
        shizukuManagerInstalled && !sheveryManagerInstalled -> PrivilegedApiBackend.Shizuku
        else -> null
    }
}

object PrivilegedGrantCommand {
    const val SYSTEM_PM_PATH = "/system/bin/pm"
    const val WRITE_SECURE_SETTINGS_PERMISSION = "android.permission.WRITE_SECURE_SETTINGS"

    private val VALID_PACKAGE_NAME = Regex("^[a-zA-Z][a-zA-Z0-9_]*(\\.[a-zA-Z][a-zA-Z0-9_]*)+$")

    fun buildPmGrantCommand(
        packageName: String,
        expectedApplicationId: String,
        pmBinaryPath: String = SYSTEM_PM_PATH,
    ): List<String> {
        if (packageName != expectedApplicationId || !VALID_PACKAGE_NAME.matches(expectedApplicationId)) {
            throw SecurityException("Refusing to grant permission to non-app package")
        }
        return listOf(
            pmBinaryPath,
            "grant",
            expectedApplicationId,
            WRITE_SECURE_SETTINGS_PERMISSION,
        )
    }
}
