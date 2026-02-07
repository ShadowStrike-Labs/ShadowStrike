/**
 * ============================================================================
 * ShadowStrike NGAV - POWER MANAGEMENT HEADER
 * ============================================================================
 * @brief Handles system power transitions (Sleep/Hibernate/Resume).
 */
#ifndef SHADOWSTRIKE_POWER_CALLBACK_H
#define SHADOWSTRIKE_POWER_CALLBACK_H

#include <ntddk.h>

NTSTATUS ShadowRegisterPowerCallbacks(VOID);
VOID ShadowUnregisterPowerCallbacks(VOID);

#endif
