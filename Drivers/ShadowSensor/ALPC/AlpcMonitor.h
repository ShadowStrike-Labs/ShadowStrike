/**
 * ============================================================================
 * ShadowStrike NGAV - ALPC MONITOR HEADER
 * ============================================================================
 * @brief Monitoring of Advanced Local Procedure Calls (ALPC).
 */
#ifndef SHADOWSTRIKE_ALPC_MONITOR_H
#define SHADOWSTRIKE_ALPC_MONITOR_H

#include <ntddk.h>

NTSTATUS ShadowRegisterAlpcCallbacks(VOID);
VOID ShadowUnregisterAlpcCallbacks(VOID);

#endif
