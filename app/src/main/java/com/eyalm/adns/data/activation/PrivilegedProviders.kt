package com.eyalm.adns.data.activation

import android.os.Binder
import android.os.Bundle
import android.os.Process
import com.hamondev.shevery.api.SheveryPrivilege
import com.hamondev.shevery.api.SheveryProvider
import rikka.shizuku.Shizuku
import rikka.shizuku.ShizukuProvider

/**
 * Hardened client ContentProvider for the native Shevery Privilege API.
 *
 * Enforces strict caller UID validation on every [call] invocation so untrusted apps cannot
 * inject spoofed binders via `sendBinder` or extract this app's binder via `getBinder` /
 * `requestBinder`.
 */
class SecureSheveryProvider : SheveryProvider() {
    override fun onCreate(): Boolean {
        val wasAlive = runCatching { SheveryPrivilege.pingBinder() }.getOrDefault(false)
        val created = super.onCreate()
        if (!wasAlive && runCatching { SheveryPrivilege.pingBinder() }.getOrDefault(false)) {
            PrivilegedBinderOriginTracker.mark(BinderDeliverySource.SheveryConnectFast)
        }
        return created
    }

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle? {
        val allowed = PrivilegedBinderChannelPolicy.enforceProviderCall(
            method = method,
            callingUid = Binder.getCallingUid(),
            myUid = Process.myUid(),
            isSheveryProvider = true,
        )
        if (!allowed) return null

        if (method == METHOD_SEND_BINDER) {
            if (extras == null) return null
            val wasAlive = runCatching { SheveryPrivilege.pingBinder() }.getOrDefault(false)
            val result = super.call(method, arg, extras)
            if (!wasAlive && runCatching { SheveryPrivilege.pingBinder() }.getOrDefault(false)) {
                PrivilegedBinderOriginTracker.mark(BinderDeliverySource.SheveryProvider)
            }
            return result
        }

        return super.call(method, arg, extras)
    }
}

/**
 * Hardened client ContentProvider for the legacy Shizuku / Sui compatibility API.
 *
 * Enforces strict caller UID validation on every [call] invocation so untrusted apps cannot
 * inject spoofed binders or read this app's binder.
 */
class SecureShizukuProvider : ShizukuProvider() {
    override fun call(method: String, arg: String?, extras: Bundle?): Bundle? {
        val allowed = PrivilegedBinderChannelPolicy.enforceProviderCall(
            method = method,
            callingUid = Binder.getCallingUid(),
            myUid = Process.myUid(),
            isSheveryProvider = false,
        )
        if (!allowed) return null

        if (method == METHOD_SEND_BINDER) {
            if (extras == null) return null
            val wasAlive = runCatching { Shizuku.pingBinder() }.getOrDefault(false)
            val result = super.call(method, arg, extras)
            if (!wasAlive && runCatching { Shizuku.pingBinder() }.getOrDefault(false)) {
                PrivilegedBinderOriginTracker.mark(BinderDeliverySource.ShizukuProvider)
            }
            return result
        }

        return super.call(method, arg, extras)
    }
}
