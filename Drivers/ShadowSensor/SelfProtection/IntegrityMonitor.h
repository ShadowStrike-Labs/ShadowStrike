/*++
    ShadowStrike Next-Generation Antivirus
    Module: IntegrityMonitor.h - Self-integrity monitoring
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

#define IM_POOL_TAG 'NOIM'

typedef enum _IM_COMPONENT {
    ImComp_DriverImage = 0,
    ImComp_CodeSection,
    ImComp_DataSection,
    ImComp_ImportTable,
    ImComp_ExportTable,
    ImComp_Callbacks,
    ImComp_Handles,
    ImComp_Configuration,
} IM_COMPONENT;

typedef enum _IM_MODIFICATION {
    ImMod_None = 0,
    ImMod_CodePatch,
    ImMod_DataTamper,
    ImMod_CallbackRemoved,
    ImMod_HandleRevoked,
    ImMod_ConfigChanged,
    ImMod_MemoryProtectionChanged,
} IM_MODIFICATION;

typedef struct _IM_INTEGRITY_CHECK {
    IM_COMPONENT Component;
    
    // Original state
    UCHAR OriginalHash[32];
    SIZE_T OriginalSize;
    ULONG OriginalProtection;
    
    // Current state
    UCHAR CurrentHash[32];
    SIZE_T CurrentSize;
    ULONG CurrentProtection;
    
    // Result
    BOOLEAN IsIntact;
    IM_MODIFICATION Modification;
    
    LARGE_INTEGER CheckTime;
} IM_INTEGRITY_CHECK, *PIM_INTEGRITY_CHECK;

typedef VOID (*IM_TAMPER_CALLBACK)(
    _In_ IM_COMPONENT Component,
    _In_ IM_MODIFICATION Modification,
    _In_opt_ PVOID Context
);

typedef struct _IM_MONITOR {
    BOOLEAN Initialized;
    
    PVOID DriverBase;
    SIZE_T DriverSize;
    
    // Baseline hashes
    struct {
        UCHAR CodeHash[32];
        UCHAR DataHash[32];
        UCHAR ImportHash[32];
        UCHAR ExportHash[32];
    } Baseline;
    
    // Callback registration
    IM_TAMPER_CALLBACK TamperCallback;
    PVOID CallbackContext;
    
    // Periodic check
    KTIMER CheckTimer;
    KDPC CheckDpc;
    ULONG CheckIntervalMs;
    BOOLEAN PeriodicEnabled;
    
    struct {
        volatile LONG64 ChecksPerformed;
        volatile LONG64 TamperDetected;
        LARGE_INTEGER StartTime;
    } Stats;
} IM_MONITOR, *PIM_MONITOR;

NTSTATUS ImInitialize(_In_ PVOID DriverBase, _In_ SIZE_T DriverSize, _Out_ PIM_MONITOR* Monitor);
VOID ImShutdown(_Inout_ PIM_MONITOR Monitor);
NTSTATUS ImRegisterCallback(_In_ PIM_MONITOR Monitor, _In_ IM_TAMPER_CALLBACK Callback, _In_opt_ PVOID Context);
NTSTATUS ImEnablePeriodicCheck(_In_ PIM_MONITOR Monitor, _In_ ULONG IntervalMs);
NTSTATUS ImDisablePeriodicCheck(_In_ PIM_MONITOR Monitor);
NTSTATUS ImCheckIntegrity(_In_ PIM_MONITOR Monitor, _In_ IM_COMPONENT Component, _Out_ PIM_INTEGRITY_CHECK* Result);
NTSTATUS ImCheckAll(_In_ PIM_MONITOR Monitor, _Out_writes_to_(8, *Count) PIM_INTEGRITY_CHECK* Results, _Out_ PULONG Count);

#ifdef __cplusplus
}
#endif
