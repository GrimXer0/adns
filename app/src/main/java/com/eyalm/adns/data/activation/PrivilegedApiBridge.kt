package com.eyalm.adns.data.activation

import android.content.ComponentName
import android.content.Context
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.IBinder
import androidx.core.content.pm.PackageInfoCompat
import com.eyalm.adns.BuildConfig
import com.eyalm.adns.IPrivilegedService
import com.eyalm.adns.PrivilegedService
import com.hamondev.shevery.api.SheveryApiConstants
import com.hamondev.shevery.api.SheveryPrivilege
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import rikka.shizuku.Shizuku
import rikka.sui.Sui

data class ExecGrantOutcome(
    val succeeded: Boolean,
    val timedOut: Boolean = false,
    val errorMessage: String? = null,
)

interface PrivilegedApiBridge {
    val applicationPackageName: String

    suspend fun connectAndDetect(): PrivilegedApiBackend?

    fun detectPreferredInstalledBackend(): PrivilegedApiBackend?

    fun checkSelfPermission(backend: PrivilegedApiBackend): Boolean

    fun shouldShowRequestPermissionRationale(backend: PrivilegedApiBackend): Boolean

    fun requestPermission(
        backend: PrivilegedApiBackend,
        requestCode: Int,
        onResult: (Boolean) -> Unit,
    )

    fun unregisterPermissionListener()

    fun registerBinderReceivedListener(onBinderReceived: () -> Unit)

    fun unregisterBinderReceivedListener()

    fun getServerUid(backend: PrivilegedApiBackend): Int

    fun getServerVersion(backend: PrivilegedApiBackend): Int

    fun hasCapability(backend: PrivilegedApiBackend, capabilityFlag: Int): Boolean

    suspend fun execFastGrant(packageName: String): ExecGrantOutcome

    suspend fun grantViaUserService(
        backend: PrivilegedApiBackend,
        packageName: String,
    ): ExecGrantOutcome
}

class AndroidPrivilegedApiBridge(
    context: Context,
) : PrivilegedApiBridge {
    private val appContext = context.applicationContext

    override val applicationPackageName: String
        get() = appContext.packageName

    private var sheveryPermissionListener: SheveryPrivilege.OnPermissionResultListener? = null
    private var shizukuPermissionListener: Shizuku.OnRequestPermissionResultListener? = null
    private var sheveryBinderListener: SheveryPrivilege.OnBinderReceivedListener? = null
    private var shizukuBinderListener: Shizuku.OnBinderReceivedListener? = null

    override suspend fun connectAndDetect(): PrivilegedApiBackend? = withContext(Dispatchers.IO) {
        val isSui = runCatching { Sui.isSui() }.getOrDefault(false)
        var sheveryAlive = runCatching { SheveryPrivilege.pingBinder() }.getOrDefault(false)
        var shizukuAlive = runCatching { Shizuku.pingBinder() }.getOrDefault(false)

        if (!sheveryAlive && !shizukuAlive) {
            PrivilegedBinderOriginTracker.clear()
            if (!isSui) {
                val pulled = runCatching { SheveryPrivilege.connectFast(appContext) }.getOrDefault(false)
                if (pulled && runCatching { SheveryPrivilege.pingBinder() }.getOrDefault(false)) {
                    PrivilegedBinderOriginTracker.mark(BinderDeliverySource.SheveryConnectFast)
                }
                sheveryAlive = runCatching { SheveryPrivilege.pingBinder() }.getOrDefault(false)
                shizukuAlive = runCatching { Shizuku.pingBinder() }.getOrDefault(false)
            }
        }

        val sheveryVersion = if (sheveryAlive) {
            runCatching { SheveryPrivilege.getVersion() }.getOrDefault(-1)
        } else {
            -1
        }
        val shizukuVersion = if (shizukuAlive) {
            runCatching { Shizuku.getVersion() }.getOrDefault(-1)
        } else {
            -1
        }

        PrivilegedBackendDetector.detectActiveBackend(
            PrivilegedBackendDetectionInput(
                isSui = isSui,
                sheveryBinderAlive = sheveryAlive,
                shizukuBinderAlive = shizukuAlive,
                deliverySource = PrivilegedBinderOriginTracker.current(),
                sheveryServerVersion = sheveryVersion,
                shizukuServerVersion = shizukuVersion,
            )
        )
    }

    override fun detectPreferredInstalledBackend(): PrivilegedApiBackend? =
        PrivilegedBackendDetector.detectPreferredInstalledBackend(
            sheveryManagerInstalled = isPackageInstalled(SheveryApiConstants.MANAGER_APPLICATION_ID),
            shizukuManagerInstalled = isPackageInstalled(SheveryApiConstants.SHIZUKU_STUB_APPLICATION_ID),
        )

    override fun checkSelfPermission(backend: PrivilegedApiBackend): Boolean = when (backend) {
        PrivilegedApiBackend.Shevery ->
            SheveryPrivilege.checkSelfPermission() == PackageManager.PERMISSION_GRANTED
        PrivilegedApiBackend.Shizuku ->
            Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED
    }

    override fun shouldShowRequestPermissionRationale(backend: PrivilegedApiBackend): Boolean =
        when (backend) {
            PrivilegedApiBackend.Shevery -> SheveryPrivilege.shouldShowRequestPermissionRationale()
            PrivilegedApiBackend.Shizuku -> Shizuku.shouldShowRequestPermissionRationale()
        }

    override fun requestPermission(
        backend: PrivilegedApiBackend,
        requestCode: Int,
        onResult: (Boolean) -> Unit,
    ) {
        unregisterPermissionListener()
        when (backend) {
            PrivilegedApiBackend.Shevery -> {
                val listener = SheveryPrivilege.OnPermissionResultListener { code, grantResult ->
                    if (code == requestCode) {
                        unregisterPermissionListener()
                        onResult(grantResult == PackageManager.PERMISSION_GRANTED)
                    }
                }
                sheveryPermissionListener = listener
                SheveryPrivilege.addPermissionResultListener(listener)
                SheveryPrivilege.requestPermission(requestCode)
            }

            PrivilegedApiBackend.Shizuku -> {
                val listener = Shizuku.OnRequestPermissionResultListener { code, grantResult ->
                    if (code == requestCode) {
                        unregisterPermissionListener()
                        onResult(grantResult == PackageManager.PERMISSION_GRANTED)
                    }
                }
                shizukuPermissionListener = listener
                Shizuku.addRequestPermissionResultListener(listener)
                Shizuku.requestPermission(requestCode)
            }
        }
    }

    override fun unregisterPermissionListener() {
        sheveryPermissionListener?.let { listener ->
            runCatching { SheveryPrivilege.removePermissionResultListener(listener) }
        }
        sheveryPermissionListener = null

        shizukuPermissionListener?.let { listener ->
            runCatching { Shizuku.removeRequestPermissionResultListener(listener) }
        }
        shizukuPermissionListener = null
    }

    override fun registerBinderReceivedListener(onBinderReceived: () -> Unit) {
        unregisterBinderReceivedListener()
        val sheveryListener = SheveryPrivilege.OnBinderReceivedListener { onBinderReceived() }
        val shizukuListener = Shizuku.OnBinderReceivedListener { onBinderReceived() }
        sheveryBinderListener = sheveryListener
        shizukuBinderListener = shizukuListener
        runCatching { SheveryPrivilege.addBinderReceivedListener(sheveryListener) }
        runCatching { Shizuku.addBinderReceivedListener(shizukuListener) }
    }

    override fun unregisterBinderReceivedListener() {
        sheveryBinderListener?.let { listener ->
            runCatching { SheveryPrivilege.removeBinderReceivedListener(listener) }
        }
        sheveryBinderListener = null

        shizukuBinderListener?.let { listener ->
            runCatching { Shizuku.removeBinderReceivedListener(listener) }
        }
        shizukuBinderListener = null
    }

    override fun getServerUid(backend: PrivilegedApiBackend): Int = when (backend) {
        PrivilegedApiBackend.Shevery -> runCatching { SheveryPrivilege.getUid() }.getOrDefault(-1)
        PrivilegedApiBackend.Shizuku -> runCatching { Shizuku.getUid() }.getOrDefault(-1)
    }

    override fun getServerVersion(backend: PrivilegedApiBackend): Int = when (backend) {
        PrivilegedApiBackend.Shevery -> runCatching { SheveryPrivilege.getVersion() }.getOrDefault(-1)
        PrivilegedApiBackend.Shizuku -> runCatching { Shizuku.getVersion() }.getOrDefault(-1)
    }

    override fun hasCapability(backend: PrivilegedApiBackend, capabilityFlag: Int): Boolean =
        when (backend) {
            PrivilegedApiBackend.Shevery ->
                runCatching { SheveryPrivilege.hasCapability(capabilityFlag) }.getOrDefault(false)
            PrivilegedApiBackend.Shizuku ->
                capabilityFlag == SheveryApiConstants.CAP_USER_SERVICE
        }

    override suspend fun execFastGrant(packageName: String): ExecGrantOutcome =
        withContext(Dispatchers.IO) {
            val command = PrivilegedGrantCommand.buildPmGrantCommand(
                packageName = packageName,
                expectedApplicationId = BuildConfig.APPLICATION_ID,
            ).toTypedArray()

            runCatching {
                val result = SheveryPrivilege.execFast(command, null, null, EXEC_FAST_TIMEOUT_MS)
                when {
                    result.timedOut -> ExecGrantOutcome(
                        succeeded = false,
                        timedOut = true,
                        errorMessage = "pm grant timed out",
                    )
                    result.exitCode != 0 -> {
                        val detail = result.errorText.ifBlank { result.outputText }.trim()
                        ExecGrantOutcome(
                            succeeded = false,
                            errorMessage = if (detail.isNotEmpty()) {
                                "pm grant failed (exit=${result.exitCode}): $detail"
                            } else {
                                "pm grant failed (exit=${result.exitCode})"
                            },
                        )
                    }
                    else -> ExecGrantOutcome(succeeded = true)
                }
            }.getOrElse { error ->
                ExecGrantOutcome(
                    succeeded = false,
                    errorMessage = error.message,
                )
            }
        }

    override suspend fun grantViaUserService(
        backend: PrivilegedApiBackend,
        packageName: String,
    ): ExecGrantOutcome {
        PrivilegedGrantCommand.buildPmGrantCommand(
            packageName = packageName,
            expectedApplicationId = BuildConfig.APPLICATION_ID,
        )

        val componentName = ComponentName(
            BuildConfig.APPLICATION_ID,
            PrivilegedService::class.java.name,
        )
        val versionCode = resolveVersionCode()
        val binderDeferred = CompletableDeferred<IBinder?>()
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
                binderDeferred.complete(service)
            }

            override fun onServiceDisconnected(name: ComponentName?) {
                binderDeferred.complete(null)
            }
        }

        var sheveryArgs: SheveryPrivilege.UserServiceArgs? = null
        var shizukuArgs: Shizuku.UserServiceArgs? = null

        return try {
            withContext(Dispatchers.IO) {
                when (backend) {
                    PrivilegedApiBackend.Shevery -> {
                        val args = SheveryPrivilege.UserServiceArgs(componentName)
                            .processNameSuffix(USER_SERVICE_PROCESS_SUFFIX)
                            .debuggable(BuildConfig.DEBUG)
                            .daemon(false)
                            .version(versionCode)
                        sheveryArgs = args
                        SheveryPrivilege.bindUserService(args, connection)
                    }

                    PrivilegedApiBackend.Shizuku -> {
                        val args = Shizuku.UserServiceArgs(componentName)
                            .processNameSuffix(USER_SERVICE_PROCESS_SUFFIX)
                            .debuggable(BuildConfig.DEBUG)
                            .daemon(false)
                            .version(versionCode)
                        shizukuArgs = args
                        Shizuku.bindUserService(args, connection)
                    }
                }
            }

            val binder = withTimeout(USER_SERVICE_BIND_TIMEOUT_MS) {
                binderDeferred.await()
            }
            if (binder == null || !binder.pingBinder()) {
                return ExecGrantOutcome(
                    succeeded = false,
                    errorMessage = "Privileged service binder unavailable",
                )
            }

            withContext(Dispatchers.IO) {
                val service = IPrivilegedService.Stub.asInterface(binder)
                service.grantWriteSecureSettings(BuildConfig.APPLICATION_ID)
            }
            ExecGrantOutcome(succeeded = true)
        } catch (_: TimeoutCancellationException) {
            ExecGrantOutcome(
                succeeded = false,
                timedOut = true,
                errorMessage = "Privileged service connection timed out",
            )
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: Throwable) {
            ExecGrantOutcome(
                succeeded = false,
                errorMessage = error.message,
            )
        } finally {
            sheveryArgs?.let { args ->
                runCatching { SheveryPrivilege.unbindUserService(args, connection, true) }
            }
            shizukuArgs?.let { args ->
                runCatching { Shizuku.unbindUserService(args, connection, true) }
            }
        }
    }

    private fun resolveVersionCode(): Int = runCatching {
        PackageInfoCompat.getLongVersionCode(
            appContext.packageManager.getPackageInfo(appContext.packageName, 0),
        )
            .coerceAtMost(Int.MAX_VALUE.toLong())
            .toInt()
    }.getOrDefault(1)

    private fun isPackageInstalled(packageName: String): Boolean = runCatching {
        appContext.packageManager.getPackageInfo(packageName, 0)
        true
    }.getOrDefault(false)

    private companion object {
        const val USER_SERVICE_PROCESS_SUFFIX = "service"
        const val EXEC_FAST_TIMEOUT_MS = 10_000L
        const val USER_SERVICE_BIND_TIMEOUT_MS = 15_000L
    }
}
