/**
 * ============================================================================
 * ShadowStrike NGAV - SELF-PROTECTION IMPLEMENTATION
 * ============================================================================
 *
 * @file SelfProtect.c
 * @brief Self-protection against malware termination and tampering.
 *
 * CRITICAL SECURITY MODULE - This prevents malware from:
 * 1. Terminating our service process
 * 2. Injecting code into our process
 * 3. Modifying our binaries on disk
 * 4. Tampering with our registry keys
 *
 * Without ELAM, this is our primary defense. Handle with extreme care.
 *
 * BSOD PREVENTION:
 * - All pointer parameters validated before use
 * - All locks acquired with proper IRQL awareness
 * - Never block in callbacks - only strip access rights
 * - Fail-open on any unexpected errors
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "SelfProtect.h"
#include "../Core/Globals.h"
#include "../Shared/SharedDefs.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, ShadowStrikeInitializeSelfProtection)
#pragma alloc_text(PAGE, ShadowStrikeShutdownSelfProtection)
#pragma alloc_text(PAGE, ShadowStrikeProtectProcess)
#pragma alloc_text(PAGE, ShadowStrikeUnprotectProcess)
#pragma alloc_text(PAGE, ShadowStrikeAddProtectedPath)
#pragma alloc_text(PAGE, ShadowStrikeAddProtectedRegistryKey)
#endif

// ============================================================================
// GLOBAL STATE
// ============================================================================

/**
 * @brief Protected process list (linked list).
 */
static LIST_ENTRY g_ProtectedProcessList;
static EX_PUSH_LOCK g_ProtectedProcessLock;
static LONG g_ProtectedProcessCount = 0;

/**
 * @brief Protected file paths (static array for simplicity).
 */
static SHADOWSTRIKE_PROTECTED_PATH g_ProtectedPaths[SHADOWSTRIKE_MAX_PROTECTED_PATHS];
static EX_PUSH_LOCK g_ProtectedPathLock;
static LONG g_ProtectedPathCount = 0;

/**
 * @brief Protected registry keys.
 */
static SHADOWSTRIKE_PROTECTED_REGKEY g_ProtectedRegKeys[SHADOWSTRIKE_MAX_PROTECTED_REGKEYS];
static EX_PUSH_LOCK g_ProtectedRegKeyLock;
static LONG g_ProtectedRegKeyCount = 0;

/**
 * @brief Self-protection statistics.
 */
static SHADOWSTRIKE_SELFPROTECT_STATS g_SelfProtectStats = {0};

/**
 * @brief Initialization state.
 */
static BOOLEAN g_SelfProtectInitialized = FALSE;

// ============================================================================
// INITIALIZATION / SHUTDOWN
// ============================================================================

NTSTATUS
ShadowStrikeInitializeSelfProtection(
    VOID
    )
{
    PAGED_CODE();

    if (g_SelfProtectInitialized) {
        return STATUS_SUCCESS;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Initializing self-protection subsystem\n");

    //
    // Initialize protected process list
    //
    InitializeListHead(&g_ProtectedProcessList);
    ExInitializePushLock(&g_ProtectedProcessLock);
    g_ProtectedProcessCount = 0;

    //
    // Initialize protected paths
    //
    RtlZeroMemory(g_ProtectedPaths, sizeof(g_ProtectedPaths));
    ExInitializePushLock(&g_ProtectedPathLock);
    g_ProtectedPathCount = 0;

    //
    // Initialize protected registry keys
    //
    RtlZeroMemory(g_ProtectedRegKeys, sizeof(g_ProtectedRegKeys));
    ExInitializePushLock(&g_ProtectedRegKeyLock);
    g_ProtectedRegKeyCount = 0;

    //
    // Reset statistics
    //
    RtlZeroMemory(&g_SelfProtectStats, sizeof(g_SelfProtectStats));

    //
    // Add default protected paths (ShadowStrike installation directory)
    // These are added when user-mode connects and provides actual paths
    //

    g_SelfProtectInitialized = TRUE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Self-protection initialized\n");

    return STATUS_SUCCESS;
}

VOID
ShadowStrikeShutdownSelfProtection(
    VOID
    )
{
    PLIST_ENTRY entry;
    PLIST_ENTRY nextEntry;
    PSHADOWSTRIKE_PROTECTED_PROCESS_ENTRY processEntry;

    PAGED_CODE();

    if (!g_SelfProtectInitialized) {
        return;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Shutting down self-protection\n");

    //
    // Free all protected process entries
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ProtectedProcessLock);

    for (entry = g_ProtectedProcessList.Flink;
         entry != &g_ProtectedProcessList;
         entry = nextEntry) {

        nextEntry = entry->Flink;

        processEntry = CONTAINING_RECORD(
            entry,
            SHADOWSTRIKE_PROTECTED_PROCESS_ENTRY,
            ListEntry
        );

        RemoveEntryList(entry);

        //
        // Dereference process object if we have one
        //
        if (processEntry->Process != NULL) {
            ObDereferenceObject(processEntry->Process);
        }

        ExFreePoolWithTag(processEntry, SHADOWSTRIKE_POOL_TAG);
    }

    g_ProtectedProcessCount = 0;

    ExReleasePushLockExclusive(&g_ProtectedProcessLock);
    KeLeaveCriticalRegion();

    //
    // Clear protected paths
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ProtectedPathLock);
    RtlZeroMemory(g_ProtectedPaths, sizeof(g_ProtectedPaths));
    g_ProtectedPathCount = 0;
    ExReleasePushLockExclusive(&g_ProtectedPathLock);
    KeLeaveCriticalRegion();

    //
    // Clear protected registry keys
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ProtectedRegKeyLock);
    RtlZeroMemory(g_ProtectedRegKeys, sizeof(g_ProtectedRegKeys));
    g_ProtectedRegKeyCount = 0;
    ExReleasePushLockExclusive(&g_ProtectedRegKeyLock);
    KeLeaveCriticalRegion();

    g_SelfProtectInitialized = FALSE;

    //
    // Log final stats
    //
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Self-protection stats: HandleStrips=%lld, TermBlocks=%lld, "
               "FileBlocks=%lld, RegBlocks=%lld\n",
               g_SelfProtectStats.HandleStrips,
               g_SelfProtectStats.ProcessTerminateBlocks,
               g_SelfProtectStats.FileWriteBlocks + g_SelfProtectStats.FileDeleteBlocks,
               g_SelfProtectStats.RegistryBlocks);
}

// ============================================================================
// PROTECTED PROCESS MANAGEMENT
// ============================================================================

NTSTATUS
ShadowStrikeProtectProcess(
    _In_ HANDLE ProcessId,
    _In_ ULONG Flags,
    _In_opt_ PCWSTR ImagePath
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PSHADOWSTRIKE_PROTECTED_PROCESS_ENTRY entry = NULL;
    PEPROCESS process = NULL;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (ProcessId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!g_SelfProtectInitialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Check if already at max
    //
    if (g_ProtectedProcessCount >= SHADOWSTRIKE_MAX_PROTECTED_PROCESSES) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Max protected processes reached\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Get process object reference
    //
    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Failed to lookup process %p: 0x%08X\n",
                   ProcessId, status);
        return status;
    }

    //
    // Allocate entry
    //
    entry = (PSHADOWSTRIKE_PROTECTED_PROCESS_ENTRY)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(SHADOWSTRIKE_PROTECTED_PROCESS_ENTRY),
        SHADOWSTRIKE_POOL_TAG
    );

    if (entry == NULL) {
        ObDereferenceObject(process);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize entry
    //
    entry->ProcessId = ProcessId;
    entry->Process = process;  // Transfer reference ownership
    entry->Flags = Flags;
    KeQuerySystemTime(&entry->RegistrationTime);

    if (ImagePath != NULL) {
        SIZE_T copyLen = wcslen(ImagePath);
        if (copyLen > 259) copyLen = 259;
        RtlCopyMemory(entry->ImagePath, ImagePath, copyLen * sizeof(WCHAR));
        entry->ImagePath[copyLen] = L'\0';
    }

    //
    // Add to list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ProtectedProcessLock);

    //
    // Check for duplicate
    //
    PLIST_ENTRY listEntry;
    BOOLEAN duplicate = FALSE;
    for (listEntry = g_ProtectedProcessList.Flink;
         listEntry != &g_ProtectedProcessList;
         listEntry = listEntry->Flink) {

        PSHADOWSTRIKE_PROTECTED_PROCESS_ENTRY existing = CONTAINING_RECORD(
            listEntry,
            SHADOWSTRIKE_PROTECTED_PROCESS_ENTRY,
            ListEntry
        );

        if (existing->ProcessId == ProcessId) {
            duplicate = TRUE;
            break;
        }
    }

    if (!duplicate) {
        InsertTailList(&g_ProtectedProcessList, &entry->ListEntry);
        InterlockedIncrement(&g_ProtectedProcessCount);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[ShadowStrike] Protected process registered: PID=%p, Flags=0x%X\n",
                   ProcessId, Flags);
    }

    ExReleasePushLockExclusive(&g_ProtectedProcessLock);
    KeLeaveCriticalRegion();

    if (duplicate) {
        // Already protected - free and dereference
        ObDereferenceObject(process);
        ExFreePoolWithTag(entry, SHADOWSTRIKE_POOL_TAG);
        return STATUS_OBJECT_NAME_COLLISION;
    }

    return STATUS_SUCCESS;
}

VOID
ShadowStrikeUnprotectProcess(
    _In_ HANDLE ProcessId
    )
{
    PLIST_ENTRY entry;
    PSHADOWSTRIKE_PROTECTED_PROCESS_ENTRY processEntry = NULL;
    PSHADOWSTRIKE_PROTECTED_PROCESS_ENTRY found = NULL;

    PAGED_CODE();

    if (!g_SelfProtectInitialized || ProcessId == NULL) {
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ProtectedProcessLock);

    for (entry = g_ProtectedProcessList.Flink;
         entry != &g_ProtectedProcessList;
         entry = entry->Flink) {

        processEntry = CONTAINING_RECORD(
            entry,
            SHADOWSTRIKE_PROTECTED_PROCESS_ENTRY,
            ListEntry
        );

        if (processEntry->ProcessId == ProcessId) {
            RemoveEntryList(entry);
            InterlockedDecrement(&g_ProtectedProcessCount);
            found = processEntry;
            break;
        }
    }

    ExReleasePushLockExclusive(&g_ProtectedProcessLock);
    KeLeaveCriticalRegion();

    if (found != NULL) {
        if (found->Process != NULL) {
            ObDereferenceObject(found->Process);
        }
        ExFreePoolWithTag(found, SHADOWSTRIKE_POOL_TAG);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[ShadowStrike] Process unprotected: PID=%p\n", ProcessId);
    }
}

BOOLEAN
ShadowStrikeIsProcessProtected(
    _In_ HANDLE ProcessId,
    _Out_opt_ PULONG OutFlags
    )
{
    BOOLEAN isProtected = FALSE;
    ULONG flags = 0;
    PLIST_ENTRY entry;

    if (!g_SelfProtectInitialized || ProcessId == NULL) {
        if (OutFlags) *OutFlags = 0;
        return FALSE;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_ProtectedProcessLock);

    for (entry = g_ProtectedProcessList.Flink;
         entry != &g_ProtectedProcessList;
         entry = entry->Flink) {

        PSHADOWSTRIKE_PROTECTED_PROCESS_ENTRY processEntry = CONTAINING_RECORD(
            entry,
            SHADOWSTRIKE_PROTECTED_PROCESS_ENTRY,
            ListEntry
        );

        if (processEntry->ProcessId == ProcessId) {
            isProtected = TRUE;
            flags = processEntry->Flags;
            break;
        }
    }

    ExReleasePushLockShared(&g_ProtectedProcessLock);
    KeLeaveCriticalRegion();

    if (OutFlags) *OutFlags = flags;
    return isProtected;
}

// ============================================================================
// PROTECTED PATH MANAGEMENT
// ============================================================================

NTSTATUS
ShadowStrikeAddProtectedPath(
    _In_ PCWSTR Path,
    _In_ ULONG Flags
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    SIZE_T pathLen;
    LONG i;

    PAGED_CODE();

    if (Path == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!g_SelfProtectInitialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    pathLen = wcslen(Path);
    if (pathLen == 0 || pathLen >= SHADOWSTRIKE_MAX_PROTECTED_PATH_LENGTH) {
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ProtectedPathLock);

    //
    // Find empty slot
    //
    for (i = 0; i < SHADOWSTRIKE_MAX_PROTECTED_PATHS; i++) {
        if (!g_ProtectedPaths[i].InUse) {
            g_ProtectedPaths[i].InUse = TRUE;
            g_ProtectedPaths[i].PathLength = (USHORT)pathLen;
            g_ProtectedPaths[i].Flags = Flags;
            RtlCopyMemory(g_ProtectedPaths[i].Path, Path, pathLen * sizeof(WCHAR));
            g_ProtectedPaths[i].Path[pathLen] = L'\0';
            InterlockedIncrement(&g_ProtectedPathCount);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "[ShadowStrike] Protected path added: %ws\n", Path);
            break;
        }
    }

    if (i >= SHADOWSTRIKE_MAX_PROTECTED_PATHS) {
        status = STATUS_INSUFFICIENT_RESOURCES;
    }

    ExReleasePushLockExclusive(&g_ProtectedPathLock);
    KeLeaveCriticalRegion();

    return status;
}

BOOLEAN
ShadowStrikeIsPathProtected(
    _In_ PCUNICODE_STRING Path
    )
{
    BOOLEAN isProtected = FALSE;
    LONG i;
    UNICODE_STRING protectedPath;

    if (!g_SelfProtectInitialized || Path == NULL || Path->Buffer == NULL) {
        return FALSE;
    }

    if (g_ProtectedPathCount == 0) {
        return FALSE;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_ProtectedPathLock);

    for (i = 0; i < SHADOWSTRIKE_MAX_PROTECTED_PATHS; i++) {
        if (g_ProtectedPaths[i].InUse) {
            //
            // Check if path starts with protected prefix
            //
            protectedPath.Buffer = g_ProtectedPaths[i].Path;
            protectedPath.Length = g_ProtectedPaths[i].PathLength * sizeof(WCHAR);
            protectedPath.MaximumLength = protectedPath.Length + sizeof(WCHAR);

            if (Path->Length >= protectedPath.Length) {
                //
                // Compare prefix (case-insensitive)
                //
                UNICODE_STRING pathPrefix;
                pathPrefix.Buffer = Path->Buffer;
                pathPrefix.Length = protectedPath.Length;
                pathPrefix.MaximumLength = pathPrefix.Length;

                if (RtlCompareUnicodeString(&pathPrefix, &protectedPath, TRUE) == 0) {
                    isProtected = TRUE;
                    break;
                }
            }
        }
    }

    ExReleasePushLockShared(&g_ProtectedPathLock);
    KeLeaveCriticalRegion();

    return isProtected;
}

// ============================================================================
// PROTECTED REGISTRY KEY MANAGEMENT
// ============================================================================

NTSTATUS
ShadowStrikeAddProtectedRegistryKey(
    _In_ PCWSTR KeyPath,
    _In_ ULONG Flags
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    SIZE_T pathLen;
    LONG i;

    PAGED_CODE();

    if (KeyPath == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!g_SelfProtectInitialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    pathLen = wcslen(KeyPath);
    if (pathLen == 0 || pathLen >= SHADOWSTRIKE_MAX_PROTECTED_PATH_LENGTH) {
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ProtectedRegKeyLock);

    for (i = 0; i < SHADOWSTRIKE_MAX_PROTECTED_REGKEYS; i++) {
        if (!g_ProtectedRegKeys[i].InUse) {
            g_ProtectedRegKeys[i].InUse = TRUE;
            g_ProtectedRegKeys[i].KeyPathLength = (USHORT)pathLen;
            g_ProtectedRegKeys[i].Flags = Flags;
            RtlCopyMemory(g_ProtectedRegKeys[i].KeyPath, KeyPath, pathLen * sizeof(WCHAR));
            g_ProtectedRegKeys[i].KeyPath[pathLen] = L'\0';
            InterlockedIncrement(&g_ProtectedRegKeyCount);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "[ShadowStrike] Protected registry key added: %ws\n", KeyPath);
            break;
        }
    }

    if (i >= SHADOWSTRIKE_MAX_PROTECTED_REGKEYS) {
        status = STATUS_INSUFFICIENT_RESOURCES;
    }

    ExReleasePushLockExclusive(&g_ProtectedRegKeyLock);
    KeLeaveCriticalRegion();

    return status;
}

BOOLEAN
ShadowStrikeIsRegistryKeyProtected(
    _In_ PCUNICODE_STRING KeyPath
    )
{
    BOOLEAN isProtected = FALSE;
    LONG i;
    UNICODE_STRING protectedKey;

    if (!g_SelfProtectInitialized || KeyPath == NULL || KeyPath->Buffer == NULL) {
        return FALSE;
    }

    if (g_ProtectedRegKeyCount == 0) {
        return FALSE;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_ProtectedRegKeyLock);

    for (i = 0; i < SHADOWSTRIKE_MAX_PROTECTED_REGKEYS; i++) {
        if (g_ProtectedRegKeys[i].InUse) {
            protectedKey.Buffer = g_ProtectedRegKeys[i].KeyPath;
            protectedKey.Length = g_ProtectedRegKeys[i].KeyPathLength * sizeof(WCHAR);
            protectedKey.MaximumLength = protectedKey.Length + sizeof(WCHAR);

            if (KeyPath->Length >= protectedKey.Length) {
                UNICODE_STRING keyPrefix;
                keyPrefix.Buffer = KeyPath->Buffer;
                keyPrefix.Length = protectedKey.Length;
                keyPrefix.MaximumLength = keyPrefix.Length;

                if (RtlCompareUnicodeString(&keyPrefix, &protectedKey, TRUE) == 0) {
                    isProtected = TRUE;
                    break;
                }
            }
        }
    }

    ExReleasePushLockShared(&g_ProtectedRegKeyLock);
    KeLeaveCriticalRegion();

    return isProtected;
}

// ============================================================================
// OBJECT CALLBACK - HANDLE PROTECTION (CRITICAL)
// ============================================================================

OB_PREOP_CALLBACK_STATUS
ShadowStrikeObjectPreCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    )
{
    HANDLE targetProcessId = NULL;
    HANDLE callerProcessId = NULL;
    ULONG protectionFlags = 0;
    ACCESS_MASK originalAccess;
    ACCESS_MASK strippedAccess;

    UNREFERENCED_PARAMETER(RegistrationContext);

    //
    // CRITICAL: Validate all parameters before use
    //
    if (OperationInformation == NULL) {
        return OB_PREOP_SUCCESS;
    }

    if (OperationInformation->Object == NULL) {
        return OB_PREOP_SUCCESS;
    }

    //
    // Skip if self-protection not enabled
    //
    if (!g_SelfProtectInitialized || !g_DriverData.Config.SelfProtectionEnabled) {
        return OB_PREOP_SUCCESS;
    }

    //
    // Skip kernel-mode callers (trusted)
    //
    if (OperationInformation->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }

    callerProcessId = PsGetCurrentProcessId();

    //
    // Handle process objects
    //
    if (OperationInformation->ObjectType == *PsProcessType) {
        PEPROCESS targetProcess = (PEPROCESS)OperationInformation->Object;
        targetProcessId = PsGetProcessId(targetProcess);

        //
        // Don't restrict a process accessing itself
        //
        if (callerProcessId == targetProcessId) {
            return OB_PREOP_SUCCESS;
        }

        //
        // Check if target is protected
        //
        if (!ShadowStrikeIsProcessProtected(targetProcessId, &protectionFlags)) {
            return OB_PREOP_SUCCESS;
        }

        //
        // Skip if caller is also protected (trusted internal process)
        //
        if (ShadowStrikeIsProcessProtected(callerProcessId, NULL)) {
            return OB_PREOP_SUCCESS;
        }

        //
        // Strip dangerous access rights based on operation type
        //
        if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
            originalAccess = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
            strippedAccess = originalAccess;

            if (protectionFlags & ProtectionFlagBlockTerminate) {
                strippedAccess &= ~PROCESS_TERMINATE;
            }
            if (protectionFlags & ProtectionFlagBlockVMWrite) {
                strippedAccess &= ~(PROCESS_VM_WRITE | PROCESS_VM_OPERATION);
            }
            if (protectionFlags & ProtectionFlagBlockInject) {
                strippedAccess &= ~PROCESS_CREATE_THREAD;
            }
            if (protectionFlags & ProtectionFlagBlockSuspend) {
                strippedAccess &= ~PROCESS_SUSPEND_RESUME;
            }

            if (strippedAccess != originalAccess) {
                OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = strippedAccess;
                InterlockedIncrement64(&g_SelfProtectStats.HandleStrips);

                if ((originalAccess & PROCESS_TERMINATE) && !(strippedAccess & PROCESS_TERMINATE)) {
                    InterlockedIncrement64(&g_SelfProtectStats.ProcessTerminateBlocks);
                }
                if ((originalAccess & PROCESS_VM_WRITE) && !(strippedAccess & PROCESS_VM_WRITE)) {
                    InterlockedIncrement64(&g_SelfProtectStats.VMWriteBlocks);
                }

                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike] PROTECTED: Stripped access 0x%X -> 0x%X for PID %p -> PID %p\n",
                           originalAccess, strippedAccess, callerProcessId, targetProcessId);
            }

        } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
            originalAccess = OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
            strippedAccess = originalAccess;

            if (protectionFlags & ProtectionFlagBlockTerminate) {
                strippedAccess &= ~PROCESS_TERMINATE;
            }
            if (protectionFlags & ProtectionFlagBlockVMWrite) {
                strippedAccess &= ~(PROCESS_VM_WRITE | PROCESS_VM_OPERATION);
            }
            if (protectionFlags & ProtectionFlagBlockInject) {
                strippedAccess &= ~PROCESS_CREATE_THREAD;
            }
            if (protectionFlags & ProtectionFlagBlockSuspend) {
                strippedAccess &= ~PROCESS_SUSPEND_RESUME;
            }

            if (strippedAccess != originalAccess) {
                OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = strippedAccess;
                InterlockedIncrement64(&g_SelfProtectStats.HandleStrips);
            }
        }

    //
    // Handle thread objects
    //
    } else if (OperationInformation->ObjectType == *PsThreadType) {
        PETHREAD targetThread = (PETHREAD)OperationInformation->Object;
        PEPROCESS ownerProcess = IoThreadToProcess(targetThread);

        if (ownerProcess != NULL) {
            targetProcessId = PsGetProcessId(ownerProcess);

            if (callerProcessId == targetProcessId) {
                return OB_PREOP_SUCCESS;
            }

            if (!ShadowStrikeIsProcessProtected(targetProcessId, &protectionFlags)) {
                return OB_PREOP_SUCCESS;
            }

            if (ShadowStrikeIsProcessProtected(callerProcessId, NULL)) {
                return OB_PREOP_SUCCESS;
            }

            //
            // Strip dangerous thread access rights
            //
            if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
                originalAccess = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
                strippedAccess = originalAccess & ~SHADOWSTRIKE_DANGEROUS_THREAD_ACCESS;

                if (strippedAccess != originalAccess) {
                    OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = strippedAccess;
                    InterlockedIncrement64(&g_SelfProtectStats.HandleStrips);
                    InterlockedIncrement64(&g_SelfProtectStats.ThreadInjectBlocks);
                }

            } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
                originalAccess = OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
                strippedAccess = originalAccess & ~SHADOWSTRIKE_DANGEROUS_THREAD_ACCESS;

                if (strippedAccess != originalAccess) {
                    OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = strippedAccess;
                    InterlockedIncrement64(&g_SelfProtectStats.HandleStrips);
                }
            }
        }
    }

    return OB_PREOP_SUCCESS;
}

// ============================================================================
// FILE ACCESS PROTECTION
// ============================================================================

BOOLEAN
ShadowStrikeShouldBlockFileAccess(
    _In_ PCUNICODE_STRING FilePath,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ HANDLE RequestorPid,
    _In_ BOOLEAN IsDelete
    )
{
    //
    // CRITICAL: Never block if not initialized
    //
    if (!g_SelfProtectInitialized || !g_DriverData.Config.SelfProtectionEnabled) {
        return FALSE;
    }

    //
    // Validate parameters
    //
    if (FilePath == NULL || FilePath->Buffer == NULL) {
        return FALSE;
    }

    //
    // Allow protected processes to modify their own files
    //
    if (ShadowStrikeIsProcessProtected(RequestorPid, NULL)) {
        return FALSE;
    }

    //
    // Check if path is protected
    //
    if (!ShadowStrikeIsPathProtected(FilePath)) {
        return FALSE;
    }

    //
    // Block if delete operation
    //
    if (IsDelete) {
        InterlockedIncrement64(&g_SelfProtectStats.FileDeleteBlocks);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] BLOCKED delete of protected file by PID %p: %wZ\n",
                   RequestorPid, FilePath);
        return TRUE;
    }

    //
    // Block if write access requested
    //
    if (DesiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE | WRITE_DAC | WRITE_OWNER)) {
        InterlockedIncrement64(&g_SelfProtectStats.FileWriteBlocks);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] BLOCKED write to protected file by PID %p: %wZ\n",
                   RequestorPid, FilePath);
        return TRUE;
    }

    return FALSE;
}

// ============================================================================
// REGISTRY ACCESS PROTECTION
// ============================================================================

BOOLEAN
ShadowStrikeShouldBlockRegistryAccess(
    _In_ PCUNICODE_STRING KeyPath,
    _In_ REG_NOTIFY_CLASS Operation,
    _In_ HANDLE RequestorPid
    )
{
    if (!g_SelfProtectInitialized || !g_DriverData.Config.SelfProtectionEnabled) {
        return FALSE;
    }

    if (KeyPath == NULL || KeyPath->Buffer == NULL) {
        return FALSE;
    }

    //
    // Allow protected processes to modify registry
    //
    if (ShadowStrikeIsProcessProtected(RequestorPid, NULL)) {
        return FALSE;
    }

    //
    // Check if key is protected
    //
    if (!ShadowStrikeIsRegistryKeyProtected(KeyPath)) {
        return FALSE;
    }

    //
    // Block modification operations
    //
    switch (Operation) {
        case RegNtPreDeleteKey:
        case RegNtPreSetValueKey:
        case RegNtPreDeleteValueKey:
        case RegNtPreRenameKey:
        case RegNtPreSetKeySecurity:
            InterlockedIncrement64(&g_SelfProtectStats.RegistryBlocks);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] BLOCKED registry change by PID %p: %wZ (op=%d)\n",
                       RequestorPid, KeyPath, Operation);
            return TRUE;

        default:
            break;
    }

    return FALSE;
}

// ============================================================================
// STATISTICS
// ============================================================================

VOID
ShadowStrikeGetSelfProtectStats(
    _Out_ PSHADOWSTRIKE_SELFPROTECT_STATS Stats
    )
{
    if (Stats == NULL) {
        return;
    }

    Stats->HandleStrips = g_SelfProtectStats.HandleStrips;
    Stats->ProcessTerminateBlocks = g_SelfProtectStats.ProcessTerminateBlocks;
    Stats->VMWriteBlocks = g_SelfProtectStats.VMWriteBlocks;
    Stats->ThreadInjectBlocks = g_SelfProtectStats.ThreadInjectBlocks;
    Stats->FileWriteBlocks = g_SelfProtectStats.FileWriteBlocks;
    Stats->FileDeleteBlocks = g_SelfProtectStats.FileDeleteBlocks;
    Stats->RegistryBlocks = g_SelfProtectStats.RegistryBlocks;
}
