/**
 * ============================================================================
 * ShadowStrike NGAV - EXCLUSION MANAGER IMPLEMENTATION
 * ============================================================================
 *
 * @file ExclusionManager.c
 * @brief Kernel-mode exclusion management implementation.
 *
 * Implements efficient matching for paths, extensions, and processes to
 * filter out safe or problematic operations before scanning.
 *
 * Performance considerations:
 * - O(1) hash lookup for extensions and process names
 * - O(N) list traversal for paths (optimized with length checks)
 * - Reader-writer locks to maximize concurrency during scans
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "ExclusionManager.h"
#include "../Core/Globals.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, ShadowStrikeExclusionInitialize)
#pragma alloc_text(PAGE, ShadowStrikeExclusionShutdown)
#pragma alloc_text(PAGE, ShadowStrikeClearExclusions)
#pragma alloc_text(PAGE, ShadowStrikeLoadDefaultExclusions)
#endif

// ============================================================================
// GLOBAL INSTANCE
// ============================================================================

SHADOWSTRIKE_EXCLUSION_MANAGER g_ExclusionManager = {0};

// ============================================================================
// INTERNAL HELPERS
// ============================================================================

static
BOOLEAN
ShadowStrikeMatchPattern(
    _In_ PCWSTR String,
    _In_ USHORT StringLen,
    _In_ PCWSTR Pattern,
    _In_ USHORT PatternLen,
    _In_ BOOLEAN Recursive
    )
{
    //
    // Simple prefix match for now
    // TODO: Implement full wildcard matching if needed
    //

    // Check if pattern is longer than string
    if (PatternLen > StringLen) {
        return FALSE;
    }

    // Check prefix
    if (RtlCompareMemory(String, Pattern, PatternLen * sizeof(WCHAR)) != PatternLen * sizeof(WCHAR)) {
        return FALSE;
    }

    // If recursive/directory match, ensure we matched a whole path component
    if (Recursive) {
        // If exact match, it's excluded
        if (StringLen == PatternLen) {
            return TRUE;
        }

        // If prefix ends with separator, it matches children
        if (Pattern[PatternLen - 1] == L'\\') {
            return TRUE;
        }

        // If string continues with separator, it matches children
        if (String[PatternLen] == L'\\') {
            return TRUE;
        }

        return FALSE;
    }

    // Exact match required if not recursive
    return (StringLen == PatternLen);
}

// ============================================================================
// INITIALIZATION / SHUTDOWN
// ============================================================================

NTSTATUS
ShadowStrikeExclusionInitialize(
    VOID
    )
{
    ULONG i;

    PAGED_CODE();

    if (g_ExclusionManager.Initialized) {
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&g_ExclusionManager, sizeof(SHADOWSTRIKE_EXCLUSION_MANAGER));

    //
    // Initialize locks
    //
    ExInitializePushLock(&g_ExclusionManager.PathLock);
    ExInitializePushLock(&g_ExclusionManager.ExtensionLock);
    ExInitializePushLock(&g_ExclusionManager.ProcessLock);
    ExInitializePushLock(&g_ExclusionManager.PidLock);

    //
    // Initialize lists
    //
    InitializeListHead(&g_ExclusionManager.PathExclusions);

    for (i = 0; i < SHADOWSTRIKE_EXTENSION_HASH_BUCKETS; i++) {
        InitializeListHead(&g_ExclusionManager.ExtensionBuckets[i].ListHead);
        g_ExclusionManager.ExtensionBuckets[i].EntryCount = 0;
    }

    for (i = 0; i < SHADOWSTRIKE_PROCESS_HASH_BUCKETS; i++) {
        InitializeListHead(&g_ExclusionManager.ProcessBuckets[i].ListHead);
        g_ExclusionManager.ProcessBuckets[i].EntryCount = 0;
    }

    //
    // Enable exclusions by default
    //
    g_ExclusionManager.Enabled = TRUE;
    g_ExclusionManager.Initialized = TRUE;

    //
    // Load defaults
    //
    ShadowStrikeLoadDefaultExclusions();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Exclusion manager initialized\n");

    return STATUS_SUCCESS;
}

VOID
ShadowStrikeExclusionShutdown(
    VOID
    )
{
    PAGED_CODE();

    if (!g_ExclusionManager.Initialized) {
        return;
    }

    //
    // Disable exclusions
    //
    g_ExclusionManager.Enabled = FALSE;

    //
    // Clear all exclusions
    //
    ShadowStrikeClearExclusions(ShadowStrikeExclusionPath);
    ShadowStrikeClearExclusions(ShadowStrikeExclusionExtension);
    ShadowStrikeClearExclusions(ShadowStrikeExclusionProcessName);
    ShadowStrikeClearExclusions(ShadowStrikeExclusionProcessId);

    g_ExclusionManager.Initialized = FALSE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Exclusion manager shutdown\n");
}

// ============================================================================
// MATCHING LOGIC
// ============================================================================

BOOLEAN
ShadowStrikeIsPathExcluded(
    _In_ PCUNICODE_STRING FilePath,
    _In_opt_ PCUNICODE_STRING Extension
    )
{
    PLIST_ENTRY listEntry;
    PSHADOWSTRIKE_PATH_EXCLUSION entry;
    BOOLEAN excluded = FALSE;
    UNICODE_STRING upcasePath = {0};
    WCHAR *pathBuffer = NULL;

    if (!g_ExclusionManager.Initialized || !g_ExclusionManager.Enabled) {
        return FALSE;
    }

    // Increment stats
    InterlockedIncrement64(&g_ExclusionManager.Stats.TotalChecks);

    //
    // Check extension exclusion first (faster)
    //
    if (Extension != NULL && Extension->Length > 0) {
        if (ShadowStrikeIsExtensionExcluded(Extension)) {
            return TRUE;
        }
    }

    //
    // Need upper case path for matching
    //
    // Note: We avoid allocating if possible. If the path is short enough,
    // we could use a stack buffer, but paths can be long.
    // Ideally we would do case-insensitive comparison char-by-char,
    // but our simple matcher assumes pre-normalized data.
    //
    // For now, we do case-insensitive comparison in the loop.
    //

    //
    // Check path exclusions
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_ExclusionManager.PathLock);

    for (listEntry = g_ExclusionManager.PathExclusions.Flink;
         listEntry != &g_ExclusionManager.PathExclusions;
         listEntry = listEntry->Flink) {

        entry = CONTAINING_RECORD(listEntry, SHADOWSTRIKE_PATH_EXCLUSION, ListEntry);

        // Optimization: check if expired
        if (entry->ExpireTime.QuadPart != 0) {
            LARGE_INTEGER currentTime;
            KeQuerySystemTime(&currentTime);
            if (currentTime.QuadPart > entry->ExpireTime.QuadPart) {
                continue;
            }
        }

        //
        // Perform match
        //
        if (RtlPrefixUnicodeString(&entry->Path, (PUNICODE_STRING)FilePath, TRUE)) {
            // Check boundary condition for directories
            if (entry->Flags & ShadowStrikeExclusionFlagRecursive) {
                // If match length equals path length, it's exact match
                if (entry->PathLength == FilePath->Length / sizeof(WCHAR)) {
                    excluded = TRUE;
                }
                // Or if match ends with separator
                else if (entry->Path[entry->PathLength - 1] == L'\\') {
                    excluded = TRUE;
                }
                // Or if next char in path is separator
                else if (FilePath->Length / sizeof(WCHAR) > entry->PathLength &&
                         FilePath->Buffer[entry->PathLength] == L'\\') {
                    excluded = TRUE;
                }
            } else {
                // Exact match required
                if (entry->PathLength == FilePath->Length / sizeof(WCHAR)) {
                    excluded = TRUE;
                }
            }
        }

        if (excluded) {
            InterlockedIncrement(&entry->HitCount);
            InterlockedIncrement64(&g_ExclusionManager.Stats.PathMatches);
            InterlockedIncrement64(&g_ExclusionManager.Stats.TotalBypassed);
            break;
        }
    }

    ExReleasePushLockShared(&g_ExclusionManager.PathLock);
    KeLeaveCriticalRegion();

    return excluded;
}

BOOLEAN
ShadowStrikeIsExtensionExcluded(
    _In_ PCUNICODE_STRING Extension
    )
{
    ULONG hash;
    ULONG bucketIndex;
    PSHADOWSTRIKE_EXTENSION_BUCKET bucket;
    PLIST_ENTRY listEntry;
    PSHADOWSTRIKE_EXTENSION_EXCLUSION entry;
    BOOLEAN excluded = FALSE;

    if (!g_ExclusionManager.Initialized || !g_ExclusionManager.Enabled) {
        return FALSE;
    }

    hash = ShadowStrikeExtensionHash(Extension);
    bucketIndex = hash;
    bucket = &g_ExclusionManager.ExtensionBuckets[bucketIndex];

    if (bucket->EntryCount == 0) {
        return FALSE;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_ExclusionManager.ExtensionLock);

    for (listEntry = bucket->ListHead.Flink;
         listEntry != &bucket->ListHead;
         listEntry = listEntry->Flink) {

        entry = CONTAINING_RECORD(listEntry, SHADOWSTRIKE_EXTENSION_EXCLUSION, ListEntry);

        // Case-insensitive comparison
        if (entry->ExtensionLength == Extension->Length / sizeof(WCHAR)) {
             // Create temporary UNICODE_STRING for entry
            UNICODE_STRING entryExt;
            entryExt.Buffer = entry->Extension;
            entryExt.Length = entry->ExtensionLength * sizeof(WCHAR);
            entryExt.MaximumLength = entryExt.Length;

            if (RtlCompareUnicodeString(&entryExt, Extension, TRUE) == 0) {
                excluded = TRUE;
                InterlockedIncrement(&entry->HitCount);
                InterlockedIncrement64(&g_ExclusionManager.Stats.ExtensionMatches);
                break;
            }
        }
    }

    ExReleasePushLockShared(&g_ExclusionManager.ExtensionLock);
    KeLeaveCriticalRegion();

    return excluded;
}

BOOLEAN
ShadowStrikeIsProcessExcluded(
    _In_ HANDLE ProcessId,
    _In_opt_ PCUNICODE_STRING ProcessName
    )
{
    ULONG i;
    ULONG hash;
    ULONG bucketIndex;
    PSHADOWSTRIKE_PROCESS_BUCKET bucket;
    PLIST_ENTRY listEntry;
    PSHADOWSTRIKE_PROCESS_EXCLUSION entry;
    BOOLEAN excluded = FALSE;
    LARGE_INTEGER currentTime;

    if (!g_ExclusionManager.Initialized || !g_ExclusionManager.Enabled) {
        return FALSE;
    }

    //
    // Check PID exclusions first (O(1) array lookup)
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_ExclusionManager.PidLock);

    KeQuerySystemTime(&currentTime);

    for (i = 0; i < SHADOWSTRIKE_MAX_PID_EXCLUSIONS; i++) {
        if (g_ExclusionManager.PidExclusions[i].Valid &&
            g_ExclusionManager.PidExclusions[i].ProcessId == ProcessId) {

            // Check expiration
            if (g_ExclusionManager.PidExclusions[i].ExpireTime.QuadPart == 0 ||
                currentTime.QuadPart < g_ExclusionManager.PidExclusions[i].ExpireTime.QuadPart) {

                excluded = TRUE;
                InterlockedIncrement(&g_ExclusionManager.PidExclusions[i].HitCount);
                InterlockedIncrement64(&g_ExclusionManager.Stats.PidMatches);
                InterlockedIncrement64(&g_ExclusionManager.Stats.TotalBypassed);
            }
            break;
        }
    }

    ExReleasePushLockShared(&g_ExclusionManager.PidLock);
    KeLeaveCriticalRegion();

    if (excluded) {
        return TRUE;
    }

    //
    // Check process name exclusions
    //
    if (ProcessName == NULL || ProcessName->Length == 0) {
        return FALSE;
    }

    hash = ShadowStrikeProcessNameHash(ProcessName);
    bucketIndex = hash;
    bucket = &g_ExclusionManager.ProcessBuckets[bucketIndex];

    if (bucket->EntryCount == 0) {
        return FALSE;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_ExclusionManager.ProcessLock);

    for (listEntry = bucket->ListHead.Flink;
         listEntry != &bucket->ListHead;
         listEntry = listEntry->Flink) {

        entry = CONTAINING_RECORD(listEntry, SHADOWSTRIKE_PROCESS_EXCLUSION, ListEntry);

        // Case-insensitive comparison
        if (entry->NameLength == ProcessName->Length / sizeof(WCHAR)) {
            UNICODE_STRING entryName;
            entryName.Buffer = entry->ProcessName;
            entryName.Length = entry->NameLength * sizeof(WCHAR);
            entryName.MaximumLength = entryName.Length;

            if (RtlCompareUnicodeString(&entryName, ProcessName, TRUE) == 0) {
                excluded = TRUE;
                InterlockedIncrement(&entry->HitCount);
                InterlockedIncrement64(&g_ExclusionManager.Stats.ProcessNameMatches);
                InterlockedIncrement64(&g_ExclusionManager.Stats.TotalBypassed);
                break;
            }
        }
    }

    ExReleasePushLockShared(&g_ExclusionManager.ProcessLock);
    KeLeaveCriticalRegion();

    return excluded;
}

// ============================================================================
// MANAGEMENT FUNCTIONS
// ============================================================================

NTSTATUS
ShadowStrikeAddPathExclusion(
    _In_ PCUNICODE_STRING Path,
    _In_ UINT8 Flags
    )
{
    PSHADOWSTRIKE_PATH_EXCLUSION entry;
    ULONG currentCount;

    if (Path == NULL || Path->Length == 0 || !g_ExclusionManager.Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    // Check limit
    currentCount = g_ExclusionManager.Stats.PathExclusionCount;
    if (currentCount >= SHADOWSTRIKE_MAX_PATH_EXCLUSIONS) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    entry = (PSHADOWSTRIKE_PATH_EXCLUSION)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(SHADOWSTRIKE_PATH_EXCLUSION),
        SHADOWSTRIKE_EXCLUSION_POOL_TAG
    );

    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Initialize entry
    entry->Flags = Flags;
    entry->PathLength = (USHORT)min(Path->Length / sizeof(WCHAR), SHADOWSTRIKE_MAX_EXCLUSION_PATH_LENGTH - 1);

    RtlCopyMemory(entry->Path, Path->Buffer, entry->PathLength * sizeof(WCHAR));
    entry->Path[entry->PathLength] = L'\0';

    KeQuerySystemTime(&entry->CreateTime);

    // Insert into list
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ExclusionManager.PathLock);

    InsertTailList(&g_ExclusionManager.PathExclusions, &entry->ListEntry);
    InterlockedIncrement(&g_ExclusionManager.Stats.PathExclusionCount);

    ExReleasePushLockExclusive(&g_ExclusionManager.PathLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

NTSTATUS
ShadowStrikeAddExtensionExclusion(
    _In_ PCUNICODE_STRING Extension,
    _In_ UINT8 Flags
    )
{
    PSHADOWSTRIKE_EXTENSION_EXCLUSION entry;
    ULONG hash;
    ULONG bucketIndex;
    ULONG currentCount;

    if (Extension == NULL || Extension->Length == 0 || !g_ExclusionManager.Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    // Check limit
    currentCount = g_ExclusionManager.Stats.ExtensionExclusionCount;
    if (currentCount >= SHADOWSTRIKE_MAX_EXTENSION_EXCLUSIONS) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    entry = (PSHADOWSTRIKE_EXTENSION_EXCLUSION)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(SHADOWSTRIKE_EXTENSION_EXCLUSION),
        SHADOWSTRIKE_EXCLUSION_POOL_TAG
    );

    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Initialize entry
    entry->Flags = Flags;
    entry->ExtensionLength = (USHORT)min(Extension->Length / sizeof(WCHAR), SHADOWSTRIKE_MAX_EXTENSION_LENGTH - 1);

    RtlCopyMemory(entry->Extension, Extension->Buffer, entry->ExtensionLength * sizeof(WCHAR));
    entry->Extension[entry->ExtensionLength] = L'\0';

    // Calculate hash
    hash = ShadowStrikeExtensionHash(Extension);
    bucketIndex = hash;

    // Insert into bucket
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ExclusionManager.ExtensionLock);

    InsertHeadList(&g_ExclusionManager.ExtensionBuckets[bucketIndex].ListHead, &entry->ListEntry);
    InterlockedIncrement(&g_ExclusionManager.ExtensionBuckets[bucketIndex].EntryCount);
    InterlockedIncrement(&g_ExclusionManager.Stats.ExtensionExclusionCount);

    ExReleasePushLockExclusive(&g_ExclusionManager.ExtensionLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

NTSTATUS
ShadowStrikeAddProcessExclusion(
    _In_ PCUNICODE_STRING ProcessName,
    _In_ UINT8 Flags
    )
{
    PSHADOWSTRIKE_PROCESS_EXCLUSION entry;
    ULONG hash;
    ULONG bucketIndex;
    ULONG currentCount;

    if (ProcessName == NULL || ProcessName->Length == 0 || !g_ExclusionManager.Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    // Check limit
    currentCount = g_ExclusionManager.Stats.ProcessExclusionCount;
    if (currentCount >= SHADOWSTRIKE_MAX_PROCESS_EXCLUSIONS) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    entry = (PSHADOWSTRIKE_PROCESS_EXCLUSION)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(SHADOWSTRIKE_PROCESS_EXCLUSION),
        SHADOWSTRIKE_EXCLUSION_POOL_TAG
    );

    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Initialize entry
    entry->Flags = Flags;
    entry->NameLength = (USHORT)min(ProcessName->Length / sizeof(WCHAR), SHADOWSTRIKE_MAX_PROCESS_NAME_LENGTH - 1);

    RtlCopyMemory(entry->ProcessName, ProcessName->Buffer, entry->NameLength * sizeof(WCHAR));
    entry->ProcessName[entry->NameLength] = L'\0';

    // Calculate hash
    hash = ShadowStrikeProcessNameHash(ProcessName);
    bucketIndex = hash;

    // Insert into bucket
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ExclusionManager.ProcessLock);

    InsertHeadList(&g_ExclusionManager.ProcessBuckets[bucketIndex].ListHead, &entry->ListEntry);
    InterlockedIncrement(&g_ExclusionManager.ProcessBuckets[bucketIndex].EntryCount);
    InterlockedIncrement(&g_ExclusionManager.Stats.ProcessExclusionCount);

    ExReleasePushLockExclusive(&g_ExclusionManager.ProcessLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

VOID
ShadowStrikeClearExclusions(
    _In_ SHADOWSTRIKE_EXCLUSION_TYPE Type
    )
{
    PAGED_CODE();

    if (!g_ExclusionManager.Initialized) {
        return;
    }

    if (Type == ShadowStrikeExclusionPath) {
        PLIST_ENTRY listEntry;
        PSHADOWSTRIKE_PATH_EXCLUSION entry;

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&g_ExclusionManager.PathLock);

        while (!IsListEmpty(&g_ExclusionManager.PathExclusions)) {
            listEntry = RemoveHeadList(&g_ExclusionManager.PathExclusions);
            entry = CONTAINING_RECORD(listEntry, SHADOWSTRIKE_PATH_EXCLUSION, ListEntry);
            ExFreePoolWithTag(entry, SHADOWSTRIKE_EXCLUSION_POOL_TAG);
        }
        g_ExclusionManager.Stats.PathExclusionCount = 0;

        ExReleasePushLockExclusive(&g_ExclusionManager.PathLock);
        KeLeaveCriticalRegion();
    }
    else if (Type == ShadowStrikeExclusionExtension) {
        ULONG i;
        PLIST_ENTRY listEntry;
        PSHADOWSTRIKE_EXTENSION_EXCLUSION entry;

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&g_ExclusionManager.ExtensionLock);

        for (i = 0; i < SHADOWSTRIKE_EXTENSION_HASH_BUCKETS; i++) {
            while (!IsListEmpty(&g_ExclusionManager.ExtensionBuckets[i].ListHead)) {
                listEntry = RemoveHeadList(&g_ExclusionManager.ExtensionBuckets[i].ListHead);
                entry = CONTAINING_RECORD(listEntry, SHADOWSTRIKE_EXTENSION_EXCLUSION, ListEntry);
                ExFreePoolWithTag(entry, SHADOWSTRIKE_EXCLUSION_POOL_TAG);
            }
            g_ExclusionManager.ExtensionBuckets[i].EntryCount = 0;
        }
        g_ExclusionManager.Stats.ExtensionExclusionCount = 0;

        ExReleasePushLockExclusive(&g_ExclusionManager.ExtensionLock);
        KeLeaveCriticalRegion();
    }
    else if (Type == ShadowStrikeExclusionProcessName) {
        ULONG i;
        PLIST_ENTRY listEntry;
        PSHADOWSTRIKE_PROCESS_EXCLUSION entry;

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&g_ExclusionManager.ProcessLock);

        for (i = 0; i < SHADOWSTRIKE_PROCESS_HASH_BUCKETS; i++) {
            while (!IsListEmpty(&g_ExclusionManager.ProcessBuckets[i].ListHead)) {
                listEntry = RemoveHeadList(&g_ExclusionManager.ProcessBuckets[i].ListHead);
                entry = CONTAINING_RECORD(listEntry, SHADOWSTRIKE_PROCESS_EXCLUSION, ListEntry);
                ExFreePoolWithTag(entry, SHADOWSTRIKE_EXCLUSION_POOL_TAG);
            }
            g_ExclusionManager.ProcessBuckets[i].EntryCount = 0;
        }
        g_ExclusionManager.Stats.ProcessExclusionCount = 0;

        ExReleasePushLockExclusive(&g_ExclusionManager.ProcessLock);
        KeLeaveCriticalRegion();
    }
    else if (Type == ShadowStrikeExclusionProcessId) {
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&g_ExclusionManager.PidLock);

        RtlZeroMemory(g_ExclusionManager.PidExclusions, sizeof(g_ExclusionManager.PidExclusions));
        g_ExclusionManager.Stats.PidExclusionCount = 0;

        ExReleasePushLockExclusive(&g_ExclusionManager.PidLock);
        KeLeaveCriticalRegion();
    }
}

VOID
ShadowStrikeLoadDefaultExclusions(
    VOID
    )
{
    UNICODE_STRING str;

    PAGED_CODE();

    //
    // System critical files (perf optimization)
    //
    RtlInitUnicodeString(&str, L"\\$LogFile");
    ShadowStrikeAddPathExclusion(&str, ShadowStrikeExclusionFlagSystem);

    RtlInitUnicodeString(&str, L"\\$Mft");
    ShadowStrikeAddPathExclusion(&str, ShadowStrikeExclusionFlagSystem);

    RtlInitUnicodeString(&str, L"\\pagefile.sys");
    ShadowStrikeAddPathExclusion(&str, ShadowStrikeExclusionFlagSystem);

    RtlInitUnicodeString(&str, L"\\swapfile.sys");
    ShadowStrikeAddPathExclusion(&str, ShadowStrikeExclusionFlagSystem);

    RtlInitUnicodeString(&str, L"\\hiberfil.sys");
    ShadowStrikeAddPathExclusion(&str, ShadowStrikeExclusionFlagSystem);

    //
    // Safe extensions
    //
    RtlInitUnicodeString(&str, L"log");
    ShadowStrikeAddExtensionExclusion(&str, ShadowStrikeExclusionFlagSystem);

    RtlInitUnicodeString(&str, L"txt");
    ShadowStrikeAddExtensionExclusion(&str, ShadowStrikeExclusionFlagSystem);

    RtlInitUnicodeString(&str, L"db");
    ShadowStrikeAddExtensionExclusion(&str, ShadowStrikeExclusionFlagSystem);

    RtlInitUnicodeString(&str, L"dat");
    ShadowStrikeAddExtensionExclusion(&str, ShadowStrikeExclusionFlagSystem);
}

VOID
ShadowStrikeExclusionSetEnabled(
    _In_ BOOLEAN Enable
    )
{
    g_ExclusionManager.Enabled = Enable;
}

BOOLEAN
ShadowStrikeExclusionIsEnabled(
    VOID
    )
{
    return g_ExclusionManager.Enabled;
}
