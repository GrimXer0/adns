package com.eyalm.adns.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.viewModelScope
import com.eyalm.adns.BuildConfig
import com.eyalm.adns.data.DnsRepository
import com.eyalm.adns.data.activation.ActivationRepositories
import com.eyalm.adns.data.activation.AndroidPrivilegedApiBridge
import com.eyalm.adns.data.activation.PermissionState
import com.eyalm.adns.data.activation.PrivilegedActivationCoordinator
import com.eyalm.adns.data.activation.PrivilegedApiBackend
import com.eyalm.adns.data.nextdns.api.NextDnsProfile
import com.eyalm.adns.data.nextdns.profile.NextDnsProfileRepository
import com.eyalm.adns.data.provider.DnsProviderCatalog
import com.eyalm.adns.data.provider.DnsProviderSelection
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

sealed interface PermissionAcquisitionState {
    data object Idle : PermissionAcquisitionState
    data object WaitingForAdb : PermissionAcquisitionState
    data object RequestingShizuku : PermissionAcquisitionState
    data object Granting : PermissionAcquisitionState
    data object Granted : PermissionAcquisitionState
    data object ShizukuUnavailable : PermissionAcquisitionState
    data object Denied : PermissionAcquisitionState
    data object UntrustedServer : PermissionAcquisitionState
    data class Error(val message: String?) : PermissionAcquisitionState
}

class OnboardingViewModel(
    application: Application,
    private val savedStateHandle: SavedStateHandle,
) : AndroidViewModel(application) {
    private val catalog = DnsProviderCatalog.default
    private val activationRepository = ActivationRepositories.getInstance(application)
    private val dnsRepository = DnsRepository(application)
    private val profileRepository = NextDnsProfileRepository(application)
    private val flow = OnboardingFlow(
        catalog = catalog,
        initialState = restoreState(savedStateHandle).let { restored ->
            if (
                restored == OnboardingFlowState() &&
                activationRepository.state.value.needsModeChoice &&
                dnsRepository.currentSelection() is DnsProviderSelection.Enhanced
            ) {
                OnboardingFlowState(
                    step = OnboardingStep.ActivationMode,
                    draft = OnboardingDraft(
                        providerSelection = dnsRepository.currentSelection(),
                        nextDnsProfileId = profileRepository.currentProfileId(),
                    ),
                )
            } else {
                restored
            }
        },
    )

    val state = flow.state
    private val _permissionState = MutableStateFlow<PermissionAcquisitionState>(
        PermissionAcquisitionState.Idle
    )
    val permissionState = _permissionState.asStateFlow()
    private val _completion = MutableSharedFlow<Unit>(extraBufferCapacity = 1)
    val completion = _completion.asSharedFlow()

    private var permissionCheckJob: Job? = null

    private val privilegedCoordinator = PrivilegedActivationCoordinator(
        bridge = AndroidPrivilegedApiBridge(application),
        expectedApplicationId = BuildConfig.APPLICATION_ID,
        scope = viewModelScope,
        isWriteSecureSettingsGranted = {
            activationRepository.refreshPermission()
            activationRepository.state.value.permission == PermissionState.Granted
        },
        onWriteSecureSettingsGranted = {
            flow.dispatch(OnboardingIntent.ActivationGranted)
            persistState()
        },
        onStartPermissionPolling = ::startPermissionCheck,
        onStateChanged = { newState ->
            _permissionState.value = newState
        },
        currentState = { _permissionState.value },
    )

    val detectedPrivilegedBackend: StateFlow<PrivilegedApiBackend?> =
        privilegedCoordinator.detectedBackend

    fun dispatch(intent: OnboardingIntent) {
        if (intent == OnboardingIntent.Back) stopPermissionAcquisition()
        flow.dispatch(intent)
        persistState()
    }

    fun selectNextDnsProfile(profile: NextDnsProfile) {
        dispatch(OnboardingIntent.ProviderLoginCompleted(profile.id))
    }

    fun startPermissionCheck() {
        if (permissionCheckJob?.isActive == true) return
        _permissionState.value = PermissionAcquisitionState.WaitingForAdb
        permissionCheckJob = viewModelScope.launch {
            while (true) {
                activationRepository.refreshPermission()
                if (activationRepository.state.value.permission == PermissionState.Granted) {
                    _permissionState.value = PermissionAcquisitionState.Granted
                    flow.dispatch(OnboardingIntent.ActivationGranted)
                    persistState()
                    return@launch
                }
                delay(PERMISSION_POLL_INTERVAL_MS)
            }
        }
    }

    fun stopPermissionCheck() {
        permissionCheckJob?.cancel()
        permissionCheckJob = null
        if (_permissionState.value == PermissionAcquisitionState.WaitingForAdb) {
            _permissionState.value = PermissionAcquisitionState.Idle
        }
    }

    fun stopPermissionAcquisition() {
        stopPermissionCheck()
        privilegedCoordinator.stop()
    }

    fun requestShizukuActivation() {
        privilegedCoordinator.startActivation()
    }

    fun finish() {
        val draft = state.value.draft
        val mode = draft.mode ?: return
        val selection = draft.providerSelection ?: return
        if (
            mode == com.eyalm.adns.data.activation.ActivationMode.PrivilegedDnsControl &&
            activationRepository.state.value.permission != PermissionState.Granted
        ) {
            return
        }
        viewModelScope.launch {
            when (selection) {
                is DnsProviderSelection.Enhanced -> {
                    val profileId = draft.nextDnsProfileId ?: return@launch
                    profileRepository.selectProfileId(profileId)
                }

                is DnsProviderSelection.Standard,
                is DnsProviderSelection.Custom,
                -> dnsRepository.stageSelection(selection)
            }
            activationRepository.completeOnboarding(mode)
            clearSavedState()
            _completion.emit(Unit)
        }
    }

    private fun persistState() {
        OnboardingStateCodec.encode(state.value).forEach { (key, value) ->
            savedStateHandle[key] = value
        }
    }

    private fun clearSavedState() {
        OnboardingStateCodec.encode(OnboardingFlowState()).keys.forEach { key ->
            savedStateHandle.remove<String>(key)
        }
    }

    override fun onCleared() {
        stopPermissionAcquisition()
        super.onCleared()
    }

    companion object {
        private const val PERMISSION_POLL_INTERVAL_MS = 1_000L

        private fun restoreState(handle: SavedStateHandle): OnboardingFlowState {
            val keys = OnboardingStateCodec.encode(OnboardingFlowState()).keys
            val values = keys.associateWith { key -> handle.get<String>(key) }
            return OnboardingStateCodec.decode(values)
        }
    }
}
