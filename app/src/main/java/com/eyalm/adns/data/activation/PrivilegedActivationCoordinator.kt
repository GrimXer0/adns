package com.eyalm.adns.data.activation

import com.eyalm.adns.viewmodel.PermissionAcquisitionState
import com.hamondev.shevery.api.SheveryApiConstants
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class PrivilegedActivationCoordinator(
    private val bridge: PrivilegedApiBridge,
    private val expectedApplicationId: String,
    private val scope: CoroutineScope,
    private val isWriteSecureSettingsGranted: () -> Boolean,
    private val onWriteSecureSettingsGranted: () -> Unit,
    private val onStartPermissionPolling: () -> Unit,
    private val onStateChanged: (PermissionAcquisitionState) -> Unit,
    private val currentState: () -> PermissionAcquisitionState,
    private val permissionPropagationChecks: Int = 5,
    private val permissionPropagationDelayMs: Long = 100L,
) {
    private val _detectedBackend = MutableStateFlow<PrivilegedApiBackend?>(
        bridge.detectPreferredInstalledBackend()
    )
    val detectedBackend: StateFlow<PrivilegedApiBackend?> = _detectedBackend.asStateFlow()

    private var activationJob: Job? = null

    fun refreshPreferredBackend() {
        if (_detectedBackend.value == null) {
            _detectedBackend.value = bridge.detectPreferredInstalledBackend()
        }
    }

    fun startActivation() {
        val state = currentState()
        if (
            state == PermissionAcquisitionState.RequestingShizuku ||
            state == PermissionAcquisitionState.Granting
        ) {
            return
        }

        if (isWriteSecureSettingsGranted()) {
            onStateChanged(PermissionAcquisitionState.Granted)
            onWriteSecureSettingsGranted()
            return
        }

        activationJob?.cancel()
        activationJob = scope.launch {
            onStateChanged(PermissionAcquisitionState.RequestingShizuku)

            val backend = bridge.connectAndDetect()
            if (backend == null) {
                _detectedBackend.value = bridge.detectPreferredInstalledBackend()
                onStateChanged(PermissionAcquisitionState.ShizukuUnavailable)
                bridge.registerBinderReceivedListener {
                    if (currentState() == PermissionAcquisitionState.ShizukuUnavailable) {
                        bridge.unregisterBinderReceivedListener()
                        startActivation()
                    }
                }
                return@launch
            }

            bridge.unregisterBinderReceivedListener()
            _detectedBackend.value = backend

            val hasPermission = runCatching { bridge.checkSelfPermission(backend) }.getOrElse {
                onStateChanged(PermissionAcquisitionState.ShizukuUnavailable)
                return@launch
            }

            when {
                hasPermission -> executePrivilegedGrant(backend)
                runCatching { bridge.shouldShowRequestPermissionRationale(backend) }
                    .getOrDefault(false) -> {
                    onStateChanged(PermissionAcquisitionState.Denied)
                }

                else -> {
                    runCatching {
                        bridge.requestPermission(backend, PRIVILEGED_PERMISSION_REQUEST) { granted ->
                            if (granted) {
                                activationJob?.cancel()
                                activationJob = scope.launch {
                                    executePrivilegedGrant(backend)
                                }
                            } else {
                                onStateChanged(PermissionAcquisitionState.Denied)
                            }
                        }
                    }.onFailure {
                        bridge.unregisterPermissionListener()
                        onStateChanged(PermissionAcquisitionState.ShizukuUnavailable)
                    }
                }
            }
        }
    }

    fun stop() {
        activationJob?.cancel()
        activationJob = null
        bridge.unregisterPermissionListener()
        bridge.unregisterBinderReceivedListener()
        val state = currentState()
        if (
            state == PermissionAcquisitionState.RequestingShizuku ||
            state == PermissionAcquisitionState.Granting
        ) {
            onStateChanged(PermissionAcquisitionState.Idle)
        }
    }

    private suspend fun executePrivilegedGrant(backend: PrivilegedApiBackend) {
        try {
            val serverUid = bridge.getServerUid(backend)
            if (!PrivilegedBinderChannelPolicy.isTrustedServerUid(serverUid)) {
                onStateChanged(PermissionAcquisitionState.UntrustedServer)
                return
            }

            val packageName = bridge.applicationPackageName
            if (packageName != expectedApplicationId) {
                onStateChanged(PermissionAcquisitionState.Error("Package identity mismatch"))
                return
            }

            onStateChanged(PermissionAcquisitionState.Granting)

            if (backend == PrivilegedApiBackend.Shevery) {
                val serverVersion = bridge.getServerVersion(backend)
                val canExecFast = PrivilegedBackendDetector.shouldUseExecFast(
                    backend = backend,
                    serverVersion = serverVersion,
                    hasShellExecCapability = bridge.hasCapability(
                        backend,
                        SheveryApiConstants.CAP_SHELL_EXEC,
                    ),
                )
                val canUserService = bridge.hasCapability(
                    backend,
                    SheveryApiConstants.CAP_USER_SERVICE,
                )

                if (!canExecFast && !canUserService) {
                    onStateChanged(PermissionAcquisitionState.Denied)
                    return
                }

                if (canExecFast) {
                    val fastOutcome = bridge.execFastGrant(packageName)
                    if (fastOutcome.succeeded && awaitWriteSecureSettingsGrant()) {
                        onStateChanged(PermissionAcquisitionState.Granted)
                        onWriteSecureSettingsGranted()
                        return
                    }
                    if (!canUserService) {
                        onStateChanged(PermissionAcquisitionState.Error(fastOutcome.errorMessage))
                        return
                    }
                }
            }

            val serviceOutcome = bridge.grantViaUserService(backend, packageName)
            if (!serviceOutcome.succeeded) {
                onStateChanged(PermissionAcquisitionState.Error(serviceOutcome.errorMessage))
                return
            }

            if (awaitWriteSecureSettingsGrant()) {
                onStateChanged(PermissionAcquisitionState.Granted)
                onWriteSecureSettingsGranted()
            } else {
                onStartPermissionPolling()
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: Throwable) {
            onStateChanged(PermissionAcquisitionState.Error(error.message))
        }
    }

    private suspend fun awaitWriteSecureSettingsGrant(): Boolean {
        repeat(permissionPropagationChecks.coerceAtLeast(1)) { attempt ->
            if (isWriteSecureSettingsGranted()) {
                return true
            }
            if (attempt + 1 < permissionPropagationChecks && permissionPropagationDelayMs > 0L) {
                delay(permissionPropagationDelayMs)
            }
        }
        return false
    }

    private companion object {
        const val PRIVILEGED_PERMISSION_REQUEST = 1
    }
}
