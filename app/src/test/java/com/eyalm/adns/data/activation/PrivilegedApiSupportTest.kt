package com.eyalm.adns.data.activation

import com.hamondev.shevery.api.SheveryApiConstants
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class PrivilegedApiSupportTest {
    @Test
    fun `trusted server uids allow only root and shell`() {
        assertTrue(PrivilegedBinderChannelPolicy.isTrustedServerUid(0))
        assertTrue(PrivilegedBinderChannelPolicy.isTrustedServerUid(2000))
        assertFalse(PrivilegedBinderChannelPolicy.isTrustedServerUid(1000))
        assertFalse(PrivilegedBinderChannelPolicy.isTrustedServerUid(10420))
        assertFalse(PrivilegedBinderChannelPolicy.isTrustedServerUid(-1))
    }

    @Test
    fun `shevery provider enforces trusted sender uids and self-only binder reads`() {
        val myUid = 10420

        // sendBinder allows root, shell, and self
        assertTrue(
            PrivilegedBinderChannelPolicy.enforceProviderCall(
                method = SheveryApiConstants.METHOD_SEND_BINDER,
                callingUid = 0,
                myUid = myUid,
                isSheveryProvider = true,
            )
        )
        assertTrue(
            PrivilegedBinderChannelPolicy.enforceProviderCall(
                method = SheveryApiConstants.METHOD_SEND_BINDER,
                callingUid = 2000,
                myUid = myUid,
                isSheveryProvider = true,
            )
        )
        assertTrue(
            PrivilegedBinderChannelPolicy.enforceProviderCall(
                method = SheveryApiConstants.METHOD_SEND_BINDER,
                callingUid = myUid,
                myUid = myUid,
                isSheveryProvider = true,
            )
        )

        // getBinder and requestBinder on client provider allow ONLY self
        assertTrue(
            PrivilegedBinderChannelPolicy.enforceProviderCall(
                method = SheveryApiConstants.METHOD_GET_BINDER,
                callingUid = myUid,
                myUid = myUid,
                isSheveryProvider = true,
            )
        )
        assertTrue(
            PrivilegedBinderChannelPolicy.enforceProviderCall(
                method = SheveryApiConstants.METHOD_REQUEST_BINDER,
                callingUid = myUid,
                myUid = myUid,
                isSheveryProvider = true,
            )
        )

        for (nonSelfTrustedUid in listOf(0, 2000)) {
            assertThrowsSecurityException {
                PrivilegedBinderChannelPolicy.enforceProviderCall(
                    method = SheveryApiConstants.METHOD_GET_BINDER,
                    callingUid = nonSelfTrustedUid,
                    myUid = myUid,
                    isSheveryProvider = true,
                )
            }
            assertThrowsSecurityException {
                PrivilegedBinderChannelPolicy.enforceProviderCall(
                    method = SheveryApiConstants.METHOD_REQUEST_BINDER,
                    callingUid = nonSelfTrustedUid,
                    myUid = myUid,
                    isSheveryProvider = true,
                )
            }
        }

        // Arbitrary apps (including system uid 1000 and cross-user uid) are always rejected
        for (untrustedUid in listOf(1000, 10234, myUid + 1, 10010420, -1)) {
            for (method in listOf(
                SheveryApiConstants.METHOD_SEND_BINDER,
                SheveryApiConstants.METHOD_GET_BINDER,
                SheveryApiConstants.METHOD_REQUEST_BINDER,
                SheveryApiConstants.METHOD_SEND_USER_SERVICE,
                "unknownMethod",
            )) {
                assertThrowsSecurityException {
                    PrivilegedBinderChannelPolicy.enforceProviderCall(
                        method = method,
                        callingUid = untrustedUid,
                        myUid = myUid,
                        isSheveryProvider = true,
                    )
                }
            }
        }

        // Unsupported methods from trusted callers return false (no-op null reply)
        assertFalse(
            PrivilegedBinderChannelPolicy.enforceProviderCall(
                method = SheveryApiConstants.METHOD_SEND_USER_SERVICE,
                callingUid = 0,
                myUid = myUid,
                isSheveryProvider = true,
            )
        )
    }

    @Test
    fun `shizuku provider rejects requestBinder and untrusted uids`() {
        val myUid = 10555

        assertTrue(
            PrivilegedBinderChannelPolicy.enforceProviderCall(
                method = SheveryApiConstants.METHOD_SEND_BINDER,
                callingUid = 2000,
                myUid = myUid,
                isSheveryProvider = false,
            )
        )
        assertTrue(
            PrivilegedBinderChannelPolicy.enforceProviderCall(
                method = SheveryApiConstants.METHOD_GET_BINDER,
                callingUid = myUid,
                myUid = myUid,
                isSheveryProvider = false,
            )
        )
        assertFalse(
            PrivilegedBinderChannelPolicy.enforceProviderCall(
                method = SheveryApiConstants.METHOD_REQUEST_BINDER,
                callingUid = myUid,
                myUid = myUid,
                isSheveryProvider = false,
            )
        )
        assertThrowsSecurityException {
            PrivilegedBinderChannelPolicy.enforceProviderCall(
                method = SheveryApiConstants.METHOD_SEND_BINDER,
                callingUid = 10001,
                myUid = myUid,
                isSheveryProvider = false,
            )
        }
    }

    @Test
    fun `detector distinguishes shevery, legacy shizuku with mirrored binder, and sui`() {
        // Sui always uses legacy Shizuku backend
        assertEquals(
            PrivilegedApiBackend.Shizuku,
            PrivilegedBackendDetector.detectActiveBackend(
                PrivilegedBackendDetectionInput(
                    isSui = true,
                    sheveryBinderAlive = true,
                    shizukuBinderAlive = true,
                    deliverySource = BinderDeliverySource.None,
                    sheveryServerVersion = 13,
                    shizukuServerVersion = 13,
                )
            ),
        )

        // Legacy Shizuku mirrors state into SheveryPrivilege via syncFromShizuku;
        // delivery source must still identify it as Shizuku.
        assertEquals(
            PrivilegedApiBackend.Shizuku,
            PrivilegedBackendDetector.detectActiveBackend(
                PrivilegedBackendDetectionInput(
                    isSui = false,
                    sheveryBinderAlive = true,
                    shizukuBinderAlive = true,
                    deliverySource = BinderDeliverySource.ShizukuProvider,
                    sheveryServerVersion = 13,
                    shizukuServerVersion = 13,
                )
            ),
        )

        // Shevery via connectFast or SheveryProvider selects Shevery
        assertEquals(
            PrivilegedApiBackend.Shevery,
            PrivilegedBackendDetector.detectActiveBackend(
                PrivilegedBackendDetectionInput(
                    isSui = false,
                    sheveryBinderAlive = true,
                    shizukuBinderAlive = true,
                    deliverySource = BinderDeliverySource.SheveryConnectFast,
                    sheveryServerVersion = 14,
                    shizukuServerVersion = 14,
                )
            ),
        )
        assertEquals(
            PrivilegedApiBackend.Shevery,
            PrivilegedBackendDetector.detectActiveBackend(
                PrivilegedBackendDetectionInput(
                    isSui = false,
                    sheveryBinderAlive = true,
                    shizukuBinderAlive = true,
                    deliverySource = BinderDeliverySource.SheveryProvider,
                    sheveryServerVersion = 14,
                    shizukuServerVersion = 14,
                )
            ),
        )

        // Fallback without tracked delivery source uses server version
        assertEquals(
            PrivilegedApiBackend.Shevery,
            PrivilegedBackendDetector.detectActiveBackend(
                PrivilegedBackendDetectionInput(
                    isSui = false,
                    sheveryBinderAlive = true,
                    shizukuBinderAlive = true,
                    deliverySource = BinderDeliverySource.None,
                    sheveryServerVersion = SheveryApiConstants.SERVER_VERSION,
                    shizukuServerVersion = SheveryApiConstants.SERVER_VERSION,
                )
            ),
        )
        assertEquals(
            PrivilegedApiBackend.Shizuku,
            PrivilegedBackendDetector.detectActiveBackend(
                PrivilegedBackendDetectionInput(
                    isSui = false,
                    sheveryBinderAlive = true,
                    shizukuBinderAlive = true,
                    deliverySource = BinderDeliverySource.None,
                    sheveryServerVersion = 13,
                    shizukuServerVersion = 13,
                )
            ),
        )

        // Neither binder alive returns null
        assertNull(
            PrivilegedBackendDetector.detectActiveBackend(
                PrivilegedBackendDetectionInput(
                    isSui = false,
                    sheveryBinderAlive = false,
                    shizukuBinderAlive = false,
                    deliverySource = BinderDeliverySource.None,
                    sheveryServerVersion = -1,
                    shizukuServerVersion = -1,
                )
            ),
        )
    }

    @Test
    fun `execFast is enabled only for Shevery v14+ with CAP_SHELL_EXEC`() {
        assertTrue(
            PrivilegedBackendDetector.shouldUseExecFast(
                backend = PrivilegedApiBackend.Shevery,
                serverVersion = SheveryApiConstants.SERVER_VERSION,
                hasShellExecCapability = true,
            )
        )
        assertFalse(
            PrivilegedBackendDetector.shouldUseExecFast(
                backend = PrivilegedApiBackend.Shevery,
                serverVersion = SheveryApiConstants.SERVER_VERSION,
                hasShellExecCapability = false,
            )
        )
        assertFalse(
            PrivilegedBackendDetector.shouldUseExecFast(
                backend = PrivilegedApiBackend.Shevery,
                serverVersion = 13,
                hasShellExecCapability = true,
            )
        )
        assertFalse(
            PrivilegedBackendDetector.shouldUseExecFast(
                backend = PrivilegedApiBackend.Shizuku,
                serverVersion = SheveryApiConstants.SERVER_VERSION,
                hasShellExecCapability = true,
            )
        )
    }

    @Test
    fun `preferred installed backend distinguishes single vs both managers`() {
        assertEquals(
            PrivilegedApiBackend.Shevery,
            PrivilegedBackendDetector.detectPreferredInstalledBackend(
                sheveryManagerInstalled = true,
                shizukuManagerInstalled = false,
            ),
        )
        assertEquals(
            PrivilegedApiBackend.Shizuku,
            PrivilegedBackendDetector.detectPreferredInstalledBackend(
                sheveryManagerInstalled = false,
                shizukuManagerInstalled = true,
            ),
        )
        assertNull(
            PrivilegedBackendDetector.detectPreferredInstalledBackend(
                sheveryManagerInstalled = true,
                shizukuManagerInstalled = true,
            ),
        )
        assertNull(
            PrivilegedBackendDetector.detectPreferredInstalledBackend(
                sheveryManagerInstalled = false,
                shizukuManagerInstalled = false,
            ),
        )
    }

    @Test
    fun `grant command enforces exact application id and rejects invalid targets`() {
        val cmd = PrivilegedGrantCommand.buildPmGrantCommand(
            packageName = "com.eyalm.adns",
            expectedApplicationId = "com.eyalm.adns",
        )
        assertEquals(
            listOf(
                "/system/bin/pm",
                "grant",
                "com.eyalm.adns",
                "android.permission.WRITE_SECURE_SETTINGS",
            ),
            cmd,
        )

        assertThrowsSecurityException {
            PrivilegedGrantCommand.buildPmGrantCommand(
                packageName = "com.evil.other",
                expectedApplicationId = "com.eyalm.adns",
            )
        }
        assertThrowsSecurityException {
            PrivilegedGrantCommand.buildPmGrantCommand(
                packageName = "com.eyalm.adns; id",
                expectedApplicationId = "com.eyalm.adns; id",
            )
        }
    }

    private fun assertThrowsSecurityException(block: () -> Unit) {
        try {
            block()
            fail("Expected SecurityException")
        } catch (_: SecurityException) {
            // Expected
        }
    }
}
