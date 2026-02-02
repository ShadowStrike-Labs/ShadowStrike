/**
 * ============================================================================
 * ShadowStrike NGAV - POWER MANAGEMENT IMPLEMENTATION
 * ============================================================================
 */
#include "PowerCallback.h"

static PVOID g_PowerRegistrationHandle = NULL;

NTSTATUS ShadowRegisterPowerCallbacks(VOID) {
    // TODO: PoRegisterPowerSettingCallback
    return STATUS_SUCCESS;
}

VOID ShadowUnregisterPowerCallbacks(VOID) {
    if (g_PowerRegistrationHandle) {
        // PoUnregisterPowerSettingCallback(g_PowerRegistrationHandle);
    }
}
