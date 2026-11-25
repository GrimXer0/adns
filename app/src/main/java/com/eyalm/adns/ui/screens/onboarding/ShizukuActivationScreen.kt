package com.eyalm.adns.ui.screens.onboarding

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.LinearWavyProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.eyalm.adns.R
import com.eyalm.adns.data.activation.PrivilegedApiBackend
import com.eyalm.adns.ui.components.OnboardingTemplate
import com.eyalm.adns.ui.theme.pageTitle
import com.eyalm.adns.viewmodel.PermissionAcquisitionState

@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Composable
fun ShizukuActivationScreen(
    state: PermissionAcquisitionState,
    detectedBackend: PrivilegedApiBackend? = null,
    onBack: () -> Unit,
    onStart: () -> Unit,
    onStop: () -> Unit,
) {
    val lifecycleOwner = LocalLifecycleOwner.current
    val currentState by rememberUpdatedState(state)
    val currentOnStart by rememberUpdatedState(onStart)

    DisposableEffect(Unit) {
        onStart()
        onDispose(onStop)
    }

    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (
                event == Lifecycle.Event.ON_RESUME &&
                currentState == PermissionAcquisitionState.ShizukuUnavailable
            ) {
                currentOnStart()
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose {
            lifecycleOwner.lifecycle.removeObserver(observer)
        }
    }

    val titleRes = when (detectedBackend) {
        PrivilegedApiBackend.Shevery -> R.string.shevery
        PrivilegedApiBackend.Shizuku -> R.string.shizuku
        null -> R.string.shevery_or_shizuku
    }
    val unavailableRes = when (detectedBackend) {
        PrivilegedApiBackend.Shevery -> R.string.shevery_unavailable
        PrivilegedApiBackend.Shizuku -> R.string.shizuku_unavailable
        null -> R.string.shevery_or_shizuku_unavailable
    }
    val deniedRes = when (detectedBackend) {
        PrivilegedApiBackend.Shevery -> R.string.shevery_permission_denied
        PrivilegedApiBackend.Shizuku -> R.string.shizuku_permission_denied
        null -> R.string.shevery_or_shizuku_permission_denied
    }

    OnboardingTemplate(
        onBackClick = onBack,
        bottomBarContent = {
            if (
                state == PermissionAcquisitionState.RequestingShizuku ||
                state == PermissionAcquisitionState.Granting
            ) {
                LinearWavyProgressIndicator(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp)
                )
            }
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                stringResource(titleRes),
                style = MaterialTheme.typography.pageTitle,
                modifier = Modifier.padding(top = 16.dp),
            )
            when (state) {
                PermissionAcquisitionState.ShizukuUnavailable -> Text(
                    stringResource(unavailableRes),
                    color = MaterialTheme.colorScheme.error,
                )

                PermissionAcquisitionState.Denied -> Text(
                    stringResource(deniedRes),
                    color = MaterialTheme.colorScheme.error,
                )

                PermissionAcquisitionState.UntrustedServer -> Text(
                    stringResource(R.string.privileged_server_untrusted),
                    color = MaterialTheme.colorScheme.error,
                )

                is PermissionAcquisitionState.Error -> Text(
                    state.message ?: stringResource(R.string.login_failed_try_again),
                    color = MaterialTheme.colorScheme.error,
                )

                else -> Text(
                    stringResource(R.string.waiting_for_permission),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}
