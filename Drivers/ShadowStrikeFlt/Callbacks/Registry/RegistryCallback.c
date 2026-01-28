/**
 * ============================================================================
 * ShadowStrike NGAV - REGISTRY CALLBACK IMPLEMENTATION
 * ============================================================================
 *
 * @file RegistryCallback.c
 * @brief Registry filtering and monitoring implementation.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "RegistryCallback.h"
#include "../../Core/Globals.h"
#include "../../SelfProtection/SelfProtect.h"
#include "../../Communication/CommPort.h"
#include "../../Communication/ScanBridge.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, ShadowStrikeRegistryCallbackRoutine)
#pragma alloc_text(PAGE, ShadowStrikeCheckRegistrySelfProtection)
#pragma alloc_text(PAGE, ShadowStrikeGetRegistryObjectPath)
#pragma alloc_text(PAGE, ShadowStrikeAnalyzeRegistryPersistence)
#endif

// ============================================================================
// INTERNAL HELPERS
// ============================================================================

/**
 * @brief Get full registry path from key object.
 *
 * @param KeyObject Key object to query.
 * @param Path      Receives the allocated path (caller must free).
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ShadowStrikeGetRegistryObjectPath(
    _In_ PVOID KeyObject,
    _Out_ PUNICODE_STRING Path
    )
{
    NTSTATUS status;
    ULONG returnLength;
    PUNICODE_STRING objectName = NULL;

    //
    // Query object name information
    //
    status = ObQueryNameString(
        KeyObject,
        NULL,
        0,
        &returnLength
    );

    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        return status;
    }

    objectName = (PUNICODE_STRING)ExAllocatePoolZero(
        PagedPool,
        returnLength + sizeof(WCHAR), // Safety margin
        SHADOWSTRIKE_POOL_TAG
    );

    if (objectName == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ObQueryNameString(
        KeyObject,
        (POBJECT_NAME_INFORMATION)objectName,
        returnLength,
        &returnLength
    );

    if (NT_SUCCESS(status)) {
        // Deep copy to caller's structure to avoid pointer confusion with POBJECT_NAME_INFORMATION
        Path->Length = objectName->Length;
        Path->MaximumLength = objectName->MaximumLength;

        Path->Buffer = (PWCH)ExAllocatePoolZero(
            PagedPool,
            Path->MaximumLength,
            SHADOWSTRIKE_POOL_TAG
        );

        if (Path->Buffer == NULL) {
            ExFreePoolWithTag(objectName, SHADOWSTRIKE_POOL_TAG);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlCopyMemory(Path->Buffer, objectName->Buffer, Path->Length);
    }

    ExFreePoolWithTag(objectName, SHADOWSTRIKE_POOL_TAG);
    return status;
}

// ============================================================================
// MAIN CALLBACK ROUTINE
// ============================================================================

NTSTATUS
ShadowStrikeRegistryCallbackRoutine(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    UNICODE_STRING keyPath = {0};
    HANDLE processId;
    BOOLEAN blockOperation = FALSE;

    UNREFERENCED_PARAMETER(CallbackContext);

    if (!SHADOWSTRIKE_IS_READY()) {
        return STATUS_SUCCESS;
    }

    //
    // We mainly care about write/delete operations
    //
    switch (notifyClass) {
        case RegNtPreDeleteKey:
        case RegNtPreSetValueKey:
        case RegNtPreDeleteValueKey:
        case RegNtPreRenameKey:
            break;
        default:
            return STATUS_SUCCESS;
    }

    processId = PsGetCurrentProcessId();

    //
    // Check self-protection first
    //
    if (g_DriverData.Config.SelfProtectionEnabled) {
        PVOID keyObject = NULL;

        // Extract key object based on operation
        if (notifyClass == RegNtPreSetValueKey) {
            PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
            keyObject = info->Object;
        }
        else if (notifyClass == RegNtPreDeleteKey) {
            PREG_DELETE_KEY_INFORMATION info = (PREG_DELETE_KEY_INFORMATION)Argument2;
            keyObject = info->Object;
        }
        else if (notifyClass == RegNtPreDeleteValueKey) {
            PREG_DELETE_VALUE_KEY_INFORMATION info = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
            keyObject = info->Object;
        }
        else if (notifyClass == RegNtPreRenameKey) {
            PREG_RENAME_KEY_INFORMATION info = (PREG_RENAME_KEY_INFORMATION)Argument2;
            keyObject = info->Object;
        }

        if (keyObject != NULL) {
            status = ShadowStrikeGetRegistryObjectPath(keyObject, &keyPath);

            if (NT_SUCCESS(status)) {
                if (ShadowStrikeCheckRegistrySelfProtection(&keyPath, processId)) {
                    blockOperation = TRUE;

                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                               "[ShadowStrike] BLOCKED registry modification to protected key: %wZ (PID: %p)\n",
                               &keyPath, processId);
                }

                //
                // Persistence Detection
                // Only if not already blocked and notifications enabled
                //
                if (!blockOperation &&
                    g_DriverData.Config.NotificationsEnabled &&
                    notifyClass == RegNtPreSetValueKey) {

                    PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
                    ShadowStrikeAnalyzeRegistryPersistence(
                        &keyPath,
                        info->ValueName,
                        info->Data,
                        info->DataSize,
                        info->Type
                    );
                }

                // Cleanup path buffer
                if (keyPath.Buffer != NULL) {
                    ExFreePoolWithTag(keyPath.Buffer, SHADOWSTRIKE_POOL_TAG);
                }
            }
        }
    }

    if (blockOperation) {
        return STATUS_ACCESS_DENIED;
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// SELF PROTECTION LOGIC
// ============================================================================

BOOLEAN
ShadowStrikeCheckRegistrySelfProtection(
    _In_ PUNICODE_STRING RegistryPath,
    _In_ HANDLE ProcessId
    )
{
    UNICODE_STRING servicePath;
    UNICODE_STRING softwarePath;
    BOOLEAN protected = FALSE;

    //
    // Trust our own service
    //
    if (ShadowStrikeIsProtectedProcess(ProcessId)) {
        return FALSE;
    }

    RtlInitUnicodeString(&servicePath, SHADOWSTRIKE_REG_SERVICES_PATH L"\\" SHADOWSTRIKE_SERVICE_NAME);
    RtlInitUnicodeString(&softwarePath, L"\\REGISTRY\\MACHINE\\SOFTWARE\\ShadowStrike");

    //
    // Check if modifying our service configuration
    //
    if (RtlPrefixUnicodeString(&servicePath, RegistryPath, TRUE)) {
        protected = TRUE;
    }
    //
    // Check if modifying our software configuration
    //
    else if (RtlPrefixUnicodeString(&softwarePath, RegistryPath, TRUE)) {
        protected = TRUE;
    }

    return protected;
}

// ============================================================================
// PERSISTENCE DETECTION
// ============================================================================

VOID
ShadowStrikeAnalyzeRegistryPersistence(
    _In_ PUNICODE_STRING RegistryPath,
    _In_ PUNICODE_STRING ValueName,
    _In_ PVOID Data,
    _In_ ULONG DataSize,
    _In_ ULONG DataType
    )
{
    UNICODE_STRING runKey;
    UNICODE_STRING runOnceKey;
    UNICODE_STRING servicesKey;
    BOOLEAN potentialPersistence = FALSE;

    RtlInitUnicodeString(&runKey, SHADOWSTRIKE_REG_RUN_KEY);
    RtlInitUnicodeString(&runOnceKey, SHADOWSTRIKE_REG_RUNONCE_KEY);
    RtlInitUnicodeString(&servicesKey, SHADOWSTRIKE_REG_SERVICES_PATH);

    //
    // Check Run keys
    //
    if (RtlPrefixUnicodeString(&runKey, RegistryPath, TRUE) ||
        RtlPrefixUnicodeString(&runOnceKey, RegistryPath, TRUE)) {
        potentialPersistence = TRUE;
    }
    //
    // Check Services (but exclude our own)
    //
    else if (RtlPrefixUnicodeString(&servicesKey, RegistryPath, TRUE)) {
        UNICODE_STRING myService;
        RtlInitUnicodeString(&myService, SHADOWSTRIKE_REG_SERVICES_PATH L"\\" SHADOWSTRIKE_SERVICE_NAME);

        if (!RtlPrefixUnicodeString(&myService, RegistryPath, TRUE)) {
            potentialPersistence = TRUE;
        }
    }

    if (potentialPersistence) {
        //
        // Send notification to user mode
        //
        ShadowStrikeSendRegistryNotification(
            PsGetCurrentProcessId(),
            PsGetCurrentThreadId(),
            2, // Operation: SetValue (See VerdictTypes or MessageProtocol, assuming 2 is write/set)
               // Better to define this properly. In MessageTypes/VerdictTypes we don't have explicit RegOp enum in shared.
               // We used ShadowStrikeAccessWrite (2) for file, let's assume strict mapping or just 2 for now.
               // ScanBridge.h defines SHADOWSTRIKE_ACCESS_TYPE where ShadowStrikeAccessWrite = 2.
            RegistryPath,
            ValueName,
            Data,
            DataSize,
            DataType
        );

        SHADOWSTRIKE_INC_STAT(TotalRegistryOperations);
    }
}
