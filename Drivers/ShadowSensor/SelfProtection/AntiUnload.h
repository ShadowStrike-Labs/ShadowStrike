/*++
    ShadowStrike Next-Generation Antivirus
    Module: AntiUnload.h - Driver unload protection
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

#define AU_POOL_TAG 'LNUA'

typedef enum _AU_PROTECTION_LEVEL {
    AuLevel_None = 0,
    AuLevel_Basic,                      // Reference count only
    AuLevel_Medium,                     // + DriverObject protection
    AuLevel_High,                       // + Callback protection
    AuLevel_Maximum,                    // + Tamper detection
} AU_PROTECTION_LEVEL;

typedef enum _AU_UNLOAD_ATTEMPT {
    AuAttempt_None = 0,
    AuAttempt_ServiceStop,
    AuAttempt_ServiceDelete,
    AuAttempt_DriverUnload,
    AuAttempt_DeviceRemove,
    AuAttempt_ProcessTerminate,
    AuAttempt_HandleClose,
    AuAttempt_Direct,
} AU_UNLOAD_ATTEMPT;

typedef struct _AU_UNLOAD_EVENT {
    AU_UNLOAD_ATTEMPT Type;
    HANDLE ProcessId;
    UNICODE_STRING ProcessName;
    LARGE_INTEGER Timestamp;
    BOOLEAN WasBlocked;
    LIST_ENTRY ListEntry;
} AU_UNLOAD_EVENT, *PAU_UNLOAD_EVENT;

typedef BOOLEAN (*AU_UNLOAD_CALLBACK)(
    _In_ AU_UNLOAD_ATTEMPT AttemptType,
    _In_ HANDLE SourceProcessId,
    _In_opt_ PVOID Context
);

typedef struct _AU_PROTECTOR {
    BOOLEAN Initialized;
    AU_PROTECTION_LEVEL Level;
    
    PDRIVER_OBJECT ProtectedDriver;
    
    // Reference count to prevent unload
    volatile LONG RefCount;
    
    // Object callbacks
    PVOID ProcessCallbackHandle;
    PVOID ThreadCallbackHandle;
    
    // Callback
    AU_UNLOAD_CALLBACK UserCallback;
    PVOID CallbackContext;
    
    // Event history
    LIST_ENTRY EventList;
    KSPIN_LOCK EventLock;
    ULONG EventCount;
    
    struct {
        volatile LONG64 UnloadAttempts;
        volatile LONG64 AttemptsBlocked;
        LARGE_INTEGER StartTime;
    } Stats;
} AU_PROTECTOR, *PAU_PROTECTOR;

NTSTATUS AuInitialize(_In_ PDRIVER_OBJECT DriverObject, _Out_ PAU_PROTECTOR* Protector);
VOID AuShutdown(_Inout_ PAU_PROTECTOR Protector);
NTSTATUS AuSetLevel(_In_ PAU_PROTECTOR Protector, _In_ AU_PROTECTION_LEVEL Level);
NTSTATUS AuRegisterCallback(_In_ PAU_PROTECTOR Protector, _In_ AU_UNLOAD_CALLBACK Callback, _In_opt_ PVOID Context);
VOID AuAddRef(_In_ PAU_PROTECTOR Protector);
VOID AuRelease(_In_ PAU_PROTECTOR Protector);
NTSTATUS AuGetEvents(_In_ PAU_PROTECTOR Protector, _Out_writes_to_(Max, *Count) PAU_UNLOAD_EVENT* Events, _In_ ULONG Max, _Out_ PULONG Count);

#ifdef __cplusplus
}
#endif
