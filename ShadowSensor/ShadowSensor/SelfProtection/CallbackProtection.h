/*++
    ShadowStrike Next-Generation Antivirus
    Module: CallbackProtection.h - Callback registration protection
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

#define CP_POOL_TAG 'ORPC'

typedef enum _CP_CALLBACK_TYPE {
    CpCallback_Process = 0,
    CpCallback_Thread,
    CpCallback_Image,
    CpCallback_Registry,
    CpCallback_Object,
    CpCallback_Minifilter,
    CpCallback_WFP,
    CpCallback_ETW,
} CP_CALLBACK_TYPE;

typedef struct _CP_CALLBACK_ENTRY {
    CP_CALLBACK_TYPE Type;
    PVOID Registration;                 // Registration handle
    PVOID Callback;                     // Callback function
    UCHAR CallbackHash[32];             // SHA-256 of callback code
    
    // Protection state
    BOOLEAN IsProtected;
    BOOLEAN WasTampered;
    
    LIST_ENTRY ListEntry;
} CP_CALLBACK_ENTRY, *PCP_CALLBACK_ENTRY;

typedef VOID (*CP_TAMPER_CALLBACK)(
    _In_ CP_CALLBACK_TYPE Type,
    _In_ PVOID Registration,
    _In_opt_ PVOID Context
);

typedef struct _CP_PROTECTOR {
    BOOLEAN Initialized;
    
    // Protected callbacks
    LIST_ENTRY CallbackList;
    EX_PUSH_LOCK CallbackLock;
    ULONG CallbackCount;
    
    // Tamper callback
    CP_TAMPER_CALLBACK TamperCallback;
    PVOID CallbackContext;
    
    // Periodic verification
    KTIMER VerifyTimer;
    KDPC VerifyDpc;
    ULONG VerifyIntervalMs;
    BOOLEAN PeriodicEnabled;
    
    struct {
        volatile LONG64 CallbacksProtected;
        volatile LONG64 TamperAttempts;
        volatile LONG64 CallbacksRestored;
        LARGE_INTEGER StartTime;
    } Stats;
} CP_PROTECTOR, *PCP_PROTECTOR;

NTSTATUS CpInitialize(_Out_ PCP_PROTECTOR* Protector);
VOID CpShutdown(_Inout_ PCP_PROTECTOR Protector);
NTSTATUS CpProtectCallback(_In_ PCP_PROTECTOR Protector, _In_ CP_CALLBACK_TYPE Type, _In_ PVOID Registration, _In_ PVOID Callback);
NTSTATUS CpUnprotectCallback(_In_ PCP_PROTECTOR Protector, _In_ PVOID Registration);
NTSTATUS CpRegisterTamperCallback(_In_ PCP_PROTECTOR Protector, _In_ CP_TAMPER_CALLBACK Callback, _In_opt_ PVOID Context);
NTSTATUS CpEnablePeriodicVerify(_In_ PCP_PROTECTOR Protector, _In_ ULONG IntervalMs);
NTSTATUS CpVerifyAll(_In_ PCP_PROTECTOR Protector, _Out_ PULONG TamperedCount);

#ifdef __cplusplus
}
#endif
