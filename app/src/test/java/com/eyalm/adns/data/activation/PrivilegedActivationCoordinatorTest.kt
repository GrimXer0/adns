package com.eyalm.adns.data.activation

import com.eyalm.adns.viewmodel.PermissionAcquisitionState
import com.hamondev.shevery.api.SheveryApiConstants
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class PrivilegedActivationCoordinatorTest {
    @Test
    fun `auto-detects shevery and grants permission via execFast without user service`() = runTest {
        var writeSecureGranted = false
        var grantedCallbackCount = 0
        var state: PermissionAcquisitionState = PermissionAcquisitionState.Idle
        val bridge = FakePrivilegedApiBridge(
            activeBackend = PrivilegedApiBackend.Shevery,
            permissionGranted = true,
            serverUid = 2000,
            serverVersion = SheveryApiConstants.SERVER_VERSION,
            capabilities = SheveryApiConstants.DEFAULT_CAPABILITIES,
            onExecFast = {
                writeSecureGranted = true
                ExecGrantOutcome(succeeded = true)
            },
        )
        val coordinator = createCoordinator(
            bridge = bridge,
            isGranted = { writeSecureGranted },
            onGranted = { grantedCallbackCount++ },
            onState = { state = it },
            currentState = { state },
        )

        coordinator.startActivation()
        advanceUntilIdle()

        assertEquals(PrivilegedApiBackend.Shevery, coordinator.detectedBackend.value)
        assertEquals(PermissionAcquisitionState.Granted, state)
        assertEquals(1, grantedCallbackCount)
        assertEquals(1, bridge.execFastCalls)
        assertEquals(0, bridge.userServiceCalls)
    }

    @Test
    fun `shevery requests permission then executes execFast after user approves`() = runTest {
        var writeSecureGranted = false
        var state: PermissionAcquisitionState = PermissionAcquisitionState.Idle
        val bridge = FakePrivilegedApiBridge(
            activeBackend = PrivilegedApiBackend.Shevery,
            permissionGranted = false,
            serverUid = 0,
            serverVersion = SheveryApiConstants.SERVER_VERSION,
            capabilities = SheveryApiConstants.CAP_SHELL_EXEC,
            onExecFast = {
                writeSecureGranted = true
                ExecGrantOutcome(succeeded = true)
            },
        )
        val coordinator = createCoordinator(
            bridge = bridge,
            isGranted = { writeSecureGranted },
            onState = { state = it },
            currentState = { state },
        )

        coordinator.startActivation()
        advanceUntilIdle()
        assertEquals(PermissionAcquisitionState.RequestingShizuku, state)
        assertEquals(PrivilegedApiBackend.Shevery, bridge.requestedPermissionBackend)

        bridge.dispatchPermissionResult(true)
        advanceUntilIdle()

        assertEquals(PermissionAcquisitionState.Granted, state)
        assertEquals(1, bridge.execFastCalls)
        assertEquals(0, bridge.userServiceCalls)
    }

    @Test
    fun `shevery falls back to user service when CAP_SHELL_EXEC is absent`() = runTest {
        var writeSecureGranted = false
        var state: PermissionAcquisitionState = PermissionAcquisitionState.Idle
        val bridge = FakePrivilegedApiBridge(
            activeBackend = PrivilegedApiBackend.Shevery,
            permissionGranted = true,
            serverUid = 2000,
            serverVersion = SheveryApiConstants.SERVER_VERSION,
            capabilities = SheveryApiConstants.CAP_USER_SERVICE,
            onUserService = {
                writeSecureGranted = true
                ExecGrantOutcome(succeeded = true)
            },
        )
        val coordinator = createCoordinator(
            bridge = bridge,
            isGranted = { writeSecureGranted },
            onState = { state = it },
            currentState = { state },
        )

        coordinator.startActivation()
        advanceUntilIdle()

        assertEquals(PermissionAcquisitionState.Granted, state)
        assertEquals(0, bridge.execFastCalls)
        assertEquals(1, bridge.userServiceCalls)
        assertEquals(PrivilegedApiBackend.Shevery, bridge.lastUserServiceBackend)
    }

    @Test
    fun `shevery falls back to user service when execFast fails`() = runTest {
        var writeSecureGranted = false
        var state: PermissionAcquisitionState = PermissionAcquisitionState.Idle
        val bridge = FakePrivilegedApiBridge(
            activeBackend = PrivilegedApiBackend.Shevery,
            permissionGranted = true,
            serverUid = 2000,
            serverVersion = SheveryApiConstants.SERVER_VERSION,
            capabilities = SheveryApiConstants.CAP_SHELL_EXEC or SheveryApiConstants.CAP_USER_SERVICE,
            onExecFast = { ExecGrantOutcome(succeeded = false, errorMessage = "execFast failed") },
            onUserService = {
                writeSecureGranted = true
                ExecGrantOutcome(succeeded = true)
            },
        )
        val coordinator = createCoordinator(
            bridge = bridge,
            isGranted = { writeSecureGranted },
            onState = { state = it },
            currentState = { state },
        )

        coordinator.startActivation()
        advanceUntilIdle()

        assertEquals(PermissionAcquisitionState.Granted, state)
        assertEquals(1, bridge.execFastCalls)
        assertEquals(1, bridge.userServiceCalls)
    }

    @Test
    fun `shevery denies activation if neither shell exec nor user service capability is granted`() = runTest {
        var state: PermissionAcquisitionState = PermissionAcquisitionState.Idle
        val bridge = FakePrivilegedApiBridge(
            activeBackend = PrivilegedApiBackend.Shevery,
            permissionGranted = true,
            serverUid = 2000,
            serverVersion = SheveryApiConstants.SERVER_VERSION,
            capabilities = SheveryApiConstants.CAP_SYSTEM_PROPS,
        )
        val coordinator = createCoordinator(
            bridge = bridge,
            isGranted = { false },
            onState = { state = it },
            currentState = { state },
        )

        coordinator.startActivation()
        advanceUntilIdle()

        assertEquals(PermissionAcquisitionState.Denied, state)
        assertEquals(0, bridge.execFastCalls)
        assertEquals(0, bridge.userServiceCalls)
    }

    @Test
    fun `rejects untrusted server uid and never runs privileged operations`() = runTest {
        var state: PermissionAcquisitionState = PermissionAcquisitionState.Idle
        val bridge = FakePrivilegedApiBridge(
            activeBackend = PrivilegedApiBackend.Shevery,
            permissionGranted = true,
            serverUid = 10420,
            serverVersion = SheveryApiConstants.SERVER_VERSION,
            capabilities = SheveryApiConstants.DEFAULT_CAPABILITIES,
        )
        val coordinator = createCoordinator(
            bridge = bridge,
            isGranted = { false },
            onState = { state = it },
            currentState = { state },
        )

        coordinator.startActivation()
        advanceUntilIdle()

        assertEquals(PermissionAcquisitionState.UntrustedServer, state)
        assertEquals(0, bridge.execFastCalls)
        assertEquals(0, bridge.userServiceCalls)
    }

    @Test
    fun `rejects package identity mismatch and never runs privileged operations`() = runTest {
        var state: PermissionAcquisitionState = PermissionAcquisitionState.Idle
        val bridge = FakePrivilegedApiBridge(
            applicationPackageName = "com.evil.spoofed",
            activeBackend = PrivilegedApiBackend.Shevery,
            permissionGranted = true,
            serverUid = 2000,
            serverVersion = SheveryApiConstants.SERVER_VERSION,
            capabilities = SheveryApiConstants.DEFAULT_CAPABILITIES,
        )
        val coordinator = createCoordinator(
            bridge = bridge,
            isGranted = { false },
            onState = { state = it },
            currentState = { state },
        )

        coordinator.startActivation()
        advanceUntilIdle()

        assertTrue(state is PermissionAcquisitionState.Error)
        assertEquals(0, bridge.execFastCalls)
        assertEquals(0, bridge.userServiceCalls)
    }

    @Test
    fun `auto-detects legacy shizuku and uses user service without calling execFast`() = runTest {
        var writeSecureGranted = false
        var state: PermissionAcquisitionState = PermissionAcquisitionState.Idle
        val bridge = FakePrivilegedApiBridge(
            activeBackend = PrivilegedApiBackend.Shizuku,
            permissionGranted = true,
            serverUid = 2000,
            serverVersion = 13,
            capabilities = SheveryApiConstants.CAP_USER_SERVICE,
            onUserService = {
                writeSecureGranted = true
                ExecGrantOutcome(succeeded = true)
            },
        )
        val coordinator = createCoordinator(
            bridge = bridge,
            isGranted = { writeSecureGranted },
            onState = { state = it },
            currentState = { state },
        )

        coordinator.startActivation()
        advanceUntilIdle()

        assertEquals(PrivilegedApiBackend.Shizuku, coordinator.detectedBackend.value)
        assertEquals(PermissionAcquisitionState.Granted, state)
        assertEquals(0, bridge.execFastCalls)
        assertEquals(1, bridge.userServiceCalls)
        assertEquals(PrivilegedApiBackend.Shizuku, bridge.lastUserServiceBackend)
    }

    @Test
    fun `unavailable state registers binder listener and auto-activates when binder arrives`() = runTest {
        var writeSecureGranted = false
        var state: PermissionAcquisitionState = PermissionAcquisitionState.Idle
        val bridge = FakePrivilegedApiBridge(
            activeBackend = null,
            preferredInstalledBackend = PrivilegedApiBackend.Shevery,
            permissionGranted = true,
            serverUid = 2000,
            serverVersion = SheveryApiConstants.SERVER_VERSION,
            capabilities = SheveryApiConstants.DEFAULT_CAPABILITIES,
            onExecFast = {
                writeSecureGranted = true
                ExecGrantOutcome(succeeded = true)
            },
        )
        val coordinator = createCoordinator(
            bridge = bridge,
            isGranted = { writeSecureGranted },
            onState = { state = it },
            currentState = { state },
        )

        coordinator.startActivation()
        advanceUntilIdle()

        assertEquals(PermissionAcquisitionState.ShizukuUnavailable, state)
        assertTrue(bridge.binderListenerRegistered)

        // Simulate Shevery starting up and delivering its binder
        bridge.activeBackend = PrivilegedApiBackend.Shevery
        bridge.dispatchBinderReceived()
        advanceUntilIdle()

        assertFalse(bridge.binderListenerRegistered)
        assertEquals(PermissionAcquisitionState.Granted, state)
        assertEquals(1, bridge.execFastCalls)
    }

    private fun TestScope.createCoordinator(
        bridge: PrivilegedApiBridge,
        isGranted: () -> Boolean,
        onGranted: () -> Unit = {},
        onPolling: () -> Unit = {},
        onState: (PermissionAcquisitionState) -> Unit,
        currentState: () -> PermissionAcquisitionState,
    ) = PrivilegedActivationCoordinator(
        bridge = bridge,
        expectedApplicationId = "com.eyalm.adns",
        scope = this,
        isWriteSecureSettingsGranted = isGranted,
        onWriteSecureSettingsGranted = onGranted,
        onStartPermissionPolling = onPolling,
        onStateChanged = onState,
        currentState = currentState,
        permissionPropagationChecks = 1,
        permissionPropagationDelayMs = 0L,
    )

    private class FakePrivilegedApiBridge(
        override val applicationPackageName: String = "com.eyalm.adns",
        var activeBackend: PrivilegedApiBackend?,
        private val preferredInstalledBackend: PrivilegedApiBackend? = null,
        private val permissionGranted: Boolean,
        private val shouldShowRationale: Boolean = false,
        private val serverUid: Int,
        private val serverVersion: Int,
        private val capabilities: Int,
        private val onExecFast: () -> ExecGrantOutcome = { ExecGrantOutcome(succeeded = false) },
        private val onUserService: () -> ExecGrantOutcome = { ExecGrantOutcome(succeeded = false) },
    ) : PrivilegedApiBridge {
        var execFastCalls = 0
        var userServiceCalls = 0
        var lastUserServiceBackend: PrivilegedApiBackend? = null
        var requestedPermissionBackend: PrivilegedApiBackend? = null
        var binderListenerRegistered = false

        private var permissionCallback: ((Boolean) -> Unit)? = null
        private var binderCallback: (() -> Unit)? = null

        override suspend fun connectAndDetect(): PrivilegedApiBackend? = activeBackend

        override fun detectPreferredInstalledBackend(): PrivilegedApiBackend? =
            preferredInstalledBackend

        override fun checkSelfPermission(backend: PrivilegedApiBackend): Boolean = permissionGranted

        override fun shouldShowRequestPermissionRationale(backend: PrivilegedApiBackend): Boolean =
            shouldShowRationale

        override fun requestPermission(
            backend: PrivilegedApiBackend,
            requestCode: Int,
            onResult: (Boolean) -> Unit,
        ) {
            requestedPermissionBackend = backend
            permissionCallback = onResult
        }

        override fun unregisterPermissionListener() {
            permissionCallback = null
        }

        override fun registerBinderReceivedListener(onBinderReceived: () -> Unit) {
            binderListenerRegistered = true
            binderCallback = onBinderReceived
        }

        override fun unregisterBinderReceivedListener() {
            binderListenerRegistered = false
            binderCallback = null
        }

        override fun getServerUid(backend: PrivilegedApiBackend): Int = serverUid

        override fun getServerVersion(backend: PrivilegedApiBackend): Int = serverVersion

        override fun hasCapability(backend: PrivilegedApiBackend, capabilityFlag: Int): Boolean =
            (capabilities and capabilityFlag) != 0

        override suspend fun execFastGrant(packageName: String): ExecGrantOutcome {
            execFastCalls++
            return onExecFast()
        }

        override suspend fun grantViaUserService(
            backend: PrivilegedApiBackend,
            packageName: String,
        ): ExecGrantOutcome {
            userServiceCalls++
            lastUserServiceBackend = backend
            return onUserService()
        }

        fun dispatchPermissionResult(granted: Boolean) {
            val cb = permissionCallback
            permissionCallback = null
            cb?.invoke(granted)
        }

        fun dispatchBinderReceived() {
            binderCallback?.invoke()
        }
    }
}
