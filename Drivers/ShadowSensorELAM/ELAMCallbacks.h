/*++
    ShadowStrike Next-Generation Antivirus
    Module: ELAMCallbacks.h - ELAM callback registration
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

#define EC_POOL_TAG 'BCLE'

typedef enum _EC_BOOT_PHASE {
    EcPhase_Early = 0,                  // Before PnP
    EcPhase_BeforeDriverInit,           // Driver about to initialize
    EcPhase_AfterDriverInit,            // Driver initialized
    EcPhase_Complete,                   // Boot complete
} EC_BOOT_PHASE;

typedef struct _EC_BOOT_DRIVER {
    UNICODE_STRING DriverPath;
    UNICODE_STRING RegistryPath;
    PVOID ImageBase;
    SIZE_T ImageSize;
    
    // From BDCB
    ULONG Classification;               // BDCB_CLASSIFICATION
    ULONG ImageFlags;                   // BDCB_IMAGEFLAGS
    
    // Our analysis
    BOOLEAN IsAllowed;
    CHAR BlockReason[128];
    
    LIST_ENTRY ListEntry;
} EC_BOOT_DRIVER, *PEC_BOOT_DRIVER;

typedef VOID (*EC_DRIVER_CALLBACK)(
    _In_ PEC_BOOT_DRIVER Driver,
    _In_ EC_BOOT_PHASE Phase,
    _Out_ PBOOLEAN Allow,
    _In_opt_ PVOID Context
);

typedef struct _EC_ELAM_CALLBACKS {
    BOOLEAN Initialized;
    BOOLEAN Registered;
    
    // Callback registration
    PVOID CallbackRegistration;
    
    // Our callback
    EC_DRIVER_CALLBACK UserCallback;
    PVOID UserContext;
    
    // Driver list
    LIST_ENTRY DriverList;
    EX_PUSH_LOCK DriverLock;
    ULONG DriverCount;
    
    // Policy
    BOOLEAN BlockUnknown;
    BOOLEAN AllowUnsigned;
    
    struct {
        volatile LONG64 DriversProcessed;
        volatile LONG64 DriversAllowed;
        volatile LONG64 DriversBlocked;
        LARGE_INTEGER StartTime;
    } Stats;
} EC_ELAM_CALLBACKS, *PEC_ELAM_CALLBACKS;

NTSTATUS EcInitialize(_Out_ PEC_ELAM_CALLBACKS* Callbacks);
VOID EcShutdown(_Inout_ PEC_ELAM_CALLBACKS Callbacks);
NTSTATUS EcRegisterCallbacks(_In_ PEC_ELAM_CALLBACKS Callbacks);
NTSTATUS EcUnregisterCallbacks(_In_ PEC_ELAM_CALLBACKS Callbacks);
NTSTATUS EcSetUserCallback(_In_ PEC_ELAM_CALLBACKS Callbacks, _In_ EC_DRIVER_CALLBACK Callback, _In_opt_ PVOID Context);
NTSTATUS EcSetPolicy(_In_ PEC_ELAM_CALLBACKS Callbacks, _In_ BOOLEAN BlockUnknown, _In_ BOOLEAN AllowUnsigned);
NTSTATUS EcGetBootDrivers(_In_ PEC_ELAM_CALLBACKS Callbacks, _Out_writes_to_(Max, *Count) PEC_BOOT_DRIVER* Drivers, _In_ ULONG Max, _Out_ PULONG Count);

#ifdef __cplusplus
}
#endif
