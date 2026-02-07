/*++
    ShadowStrike Next-Generation Antivirus
    Module: ResourceThrottling.h - Resource usage throttling
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

#define RT_POOL_TAG 'RHTR'

typedef enum _RT_RESOURCE_TYPE {
    RtResource_CPU = 0,
    RtResource_Memory,
    RtResource_DiskIO,
    RtResource_NetworkIO,
    RtResource_Callbacks,
} RT_RESOURCE_TYPE;

typedef enum _RT_THROTTLE_ACTION {
    RtAction_None = 0,
    RtAction_Delay,                     // Add delay to operations
    RtAction_Skip,                      // Skip low-priority operations
    RtAction_Queue,                     // Queue for later processing
    RtAction_Abort,                     // Abort operation
} RT_THROTTLE_ACTION;

typedef struct _RT_RESOURCE_LIMITS {
    RT_RESOURCE_TYPE Type;
    
    // Soft limit (warning)
    ULONG64 SoftLimit;
    
    // Hard limit (throttle)
    ULONG64 HardLimit;
    
    // Current usage
    volatile ULONG64 CurrentUsage;
    
    // Throttle settings
    RT_THROTTLE_ACTION SoftAction;
    RT_THROTTLE_ACTION HardAction;
    ULONG DelayMs;
    
} RT_RESOURCE_LIMITS, *PRT_RESOURCE_LIMITS;

typedef VOID (*RT_THROTTLE_CALLBACK)(
    _In_ RT_RESOURCE_TYPE Resource,
    _In_ RT_THROTTLE_ACTION Action,
    _In_ ULONG64 CurrentUsage,
    _In_ ULONG64 Limit,
    _In_opt_ PVOID Context
);

typedef struct _RT_THROTTLER {
    BOOLEAN Initialized;
    
    // Resource limits
    RT_RESOURCE_LIMITS Resources[8];
    ULONG ResourceCount;
    EX_PUSH_LOCK ResourceLock;
    
    // Callback
    RT_THROTTLE_CALLBACK ThrottleCallback;
    PVOID CallbackContext;
    
    // Global throttle state
    BOOLEAN IsThrottled;
    RT_RESOURCE_TYPE ThrottledResource;
    
    // Monitoring
    KTIMER MonitorTimer;
    KDPC MonitorDpc;
    ULONG MonitorIntervalMs;
    
    struct {
        volatile LONG64 ThrottleEvents;
        volatile LONG64 SkippedOperations;
        volatile LONG64 DelayedOperations;
        LARGE_INTEGER StartTime;
    } Stats;
} RT_THROTTLER, *PRT_THROTTLER;

NTSTATUS RtInitialize(_Out_ PRT_THROTTLER* Throttler);
VOID RtShutdown(_Inout_ PRT_THROTTLER Throttler);
NTSTATUS RtSetLimit(_In_ PRT_THROTTLER Throttler, _In_ RT_RESOURCE_TYPE Resource, _In_ ULONG64 SoftLimit, _In_ ULONG64 HardLimit);
NTSTATUS RtSetActions(_In_ PRT_THROTTLER Throttler, _In_ RT_RESOURCE_TYPE Resource, _In_ RT_THROTTLE_ACTION SoftAction, _In_ RT_THROTTLE_ACTION HardAction, _In_ ULONG DelayMs);
NTSTATUS RtRegisterCallback(_In_ PRT_THROTTLER Throttler, _In_ RT_THROTTLE_CALLBACK Callback, _In_opt_ PVOID Context);
NTSTATUS RtReportUsage(_In_ PRT_THROTTLER Throttler, _In_ RT_RESOURCE_TYPE Resource, _In_ ULONG64 Delta);
NTSTATUS RtCheckThrottle(_In_ PRT_THROTTLER Throttler, _In_ RT_RESOURCE_TYPE Resource, _Out_ PRT_THROTTLE_ACTION Action);
BOOLEAN RtShouldProceed(_In_ PRT_THROTTLER Throttler, _In_ RT_RESOURCE_TYPE Resource);

#ifdef __cplusplus
}
#endif
