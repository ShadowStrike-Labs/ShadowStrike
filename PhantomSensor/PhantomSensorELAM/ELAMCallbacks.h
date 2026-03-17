/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/*++
    ShadowStrike Next-Generation Antivirus
    Module: ELAMCallbacks.h - ELAM callback registration
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntifs.h>

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
    BOOLEAN IsSigned;
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
    volatile LONG Initialized;
    volatile LONG Registered;
    
    // Callback registration
    PVOID CallbackRegistration;
    
    // Our callback
    EC_DRIVER_CALLBACK UserCallback;
    PVOID UserContext;
    
    // Driver list
    LIST_ENTRY DriverList;
    EX_PUSH_LOCK DriverLock;
    ULONG DriverCount;
    
    // Rundown protection: all public APIs acquire before proceeding,
    // ElcbShutdown waits for all in-flight calls to drain before freeing.
    EX_RUNDOWN_REF RundownRef;
    
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

NTSTATUS ElcbInitialize(_Out_ PEC_ELAM_CALLBACKS* Callbacks);
VOID ElcbShutdown(_Inout_ PEC_ELAM_CALLBACKS Callbacks);
NTSTATUS ElcbRegisterCallbacks(_In_ PEC_ELAM_CALLBACKS Callbacks);
NTSTATUS ElcbUnregisterCallbacks(_In_ PEC_ELAM_CALLBACKS Callbacks);
NTSTATUS ElcbSetUserCallback(_In_ PEC_ELAM_CALLBACKS Callbacks, _In_ EC_DRIVER_CALLBACK Callback, _In_opt_ PVOID Context);
NTSTATUS ElcbSetPolicy(_In_ PEC_ELAM_CALLBACKS Callbacks, _In_ BOOLEAN BlockUnknown, _In_ BOOLEAN AllowUnsigned);
NTSTATUS ElcbGetBootDrivers(_In_ PEC_ELAM_CALLBACKS Callbacks, _Out_writes_to_(Max, *Count) PEC_BOOT_DRIVER* Drivers, _In_ ULONG Max, _Out_ PULONG Count);
VOID ElcbFreeBootDriverSnapshot(_In_reads_(Count) PEC_BOOT_DRIVER* Drivers, _In_ ULONG Count);

// ============================================================================
// INTERNAL API - Called by ELAMDriver.c
// ============================================================================

//
// BDCB_CLASSIFICATION equivalents for use without ELAM headers
//
#define EC_BDCB_UNKNOWN_IMAGE       0
#define EC_BDCB_KNOWN_GOOD_IMAGE    1
#define EC_BDCB_KNOWN_BAD_IMAGE     2

NTSTATUS ElcbProcessBootDriver(
    _In_ PEC_ELAM_CALLBACKS Callbacks,
    _In_ PCUNICODE_STRING DriverPath,
    _In_opt_ PCUNICODE_STRING RegistryPath,
    _In_ PVOID ImageBase,
    _In_ SIZE_T ImageSize,
    _In_ ULONG Classification,
    _In_ BOOLEAN IsSigned,
    _In_ EC_BOOT_PHASE Phase,
    _Out_opt_ PBOOLEAN AllowDriver
    );

NTSTATUS ElcbSetBootPhase(
    _In_ PEC_ELAM_CALLBACKS Callbacks,
    _In_ EC_BOOT_PHASE Phase
    );

EC_BOOT_PHASE ElcbGetBootPhase(
    _In_ PEC_ELAM_CALLBACKS Callbacks
    );

BOOLEAN ElcbIsBootComplete(
    _In_ PEC_ELAM_CALLBACKS Callbacks
    );

NTSTATUS ElcbGetStatistics(
    _In_ PEC_ELAM_CALLBACKS Callbacks,
    _Out_ PLONG64 DriversProcessed,
    _Out_ PLONG64 DriversAllowed,
    _Out_ PLONG64 DriversBlocked
    );

#ifdef __cplusplus
}
#endif
