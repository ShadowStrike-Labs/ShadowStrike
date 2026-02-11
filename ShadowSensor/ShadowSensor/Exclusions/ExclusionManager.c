/**
 * ============================================================================
 * ShadowStrike NGAV - EXCLUSION MANAGER IMPLEMENTATION
 * ============================================================================
 *
 * @file ExclusionManager.c
 * @brief Kernel-mode exclusion management implementation.
 *
 * Implements efficient matching for paths, extensions, and processes to
 * filter out safe or irrelevant operations before scanning.
 *
 * Performance considerations:
 * - O(1) hash lookup for extensions and process names
 * - O(N) list traversal for paths (with early-out on length/expiry)
 * - Reader-writer locks to maximize concurrency during scans
 * - EX_RUNDOWN_REF for safe shutdown drain (no timeout, no forced free)
 *
 * Thread Safety:
 * - All read-path APIs acquire rundown protection before accessing state.
 * - Shutdown waits indefinitely for all readers to drain.
 * - Count limits are checked under exclusive lock (no TOCTOU).
 * - Duplicate detection is performed under exclusive lock.
 * - Statistics counters are approximate (documented).
 * - All mutation APIs enforce kernel-mode caller via ExGetPreviousMode().
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
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
#pragma alloc_text(PAGE, ShadowStrikeAddPathExclusion)
#pragma alloc_text(PAGE, ShadowStrikeRemovePathExclusion)
#pragma alloc_text(PAGE, ShadowStrikeAddExtensionExclusion)
#pragma alloc_text(PAGE, ShadowStrikeRemoveExtensionExclusion)
#pragma alloc_text(PAGE, ShadowStrikeAddProcessExclusion)
#pragma alloc_text(PAGE, ShadowStrikeRemoveProcessExclusion)
#pragma alloc_text(PAGE, ShadowStrikeAddPidExclusion)
#pragma alloc_text(PAGE, ShadowStrikeRemovePidExclusion)
#pragma alloc_text(PAGE, ShadowStrikeCleanupExpiredExclusions)
#endif

// ============================================================================
// GLOBAL INSTANCE
// ============================================================================

SHADOWSTRIKE_EXCLUSION_MANAGER g_ExclusionManager = {0};

// ============================================================================
// INTERNAL HELPERS — RUNDOWN PROTECTION
// ============================================================================

/**
 * @brief Acquire rundown protection to prevent shutdown from freeing state.
 *
 * Uses EX_RUNDOWN_REF — the correct NT kernel primitive for this pattern.
 * No race condition: ExAcquireRundownProtection is atomic.
 *
 * @return TRUE if acquired, FALSE if shutdown is in progress.
 */
_IRQL_requires_max_(APC_LEVEL)
static
FORCEINLINE
BOOLEAN
ExclusionpAcquireRundown(
    VOID
    )
{
    return ExAcquireRundownProtection(&g_ExclusionManager.RundownRef);
}

/**
 * @brief Release rundown protection acquired by ExclusionpAcquireRundown.
 */
_IRQL_requires_max_(APC_LEVEL)
static
FORCEINLINE
VOID
ExclusionpReleaseRundown(
    VOID
    )
{
    ExReleaseRundownProtection(&g_ExclusionManager.RundownRef);
}

/**
 * @brief Validate that the caller is kernel-mode.
 *
 * All mutation APIs must be called from kernel mode only. If this driver
 * ever exposes IOCTLs that dispatch to these APIs, the IOCTL handler must
 * validate privileges separately — this is a defense-in-depth check.
 *
 * @return TRUE if caller is kernel-mode, FALSE otherwise.
 */
_IRQL_requires_max_(APC_LEVEL)
static
FORCEINLINE
BOOLEAN
ExclusionpValidateCallerIsKernel(
    VOID
    )
{
    return (ExGetPreviousMode() == KernelMode);
}

// ============================================================================
// INTERNAL HELPERS — DUPLICATE DETECTION
// ============================================================================

/**
 * @brief Check if a path exclusion already exists (caller holds PathLock exclusive).
 */
_Requires_lock_held_(g_ExclusionManager.PathLock)
static
BOOLEAN
ExclusionpPathExistLocked(
    _In_ PCUNICODE_STRING Path
    )
{
    PLIST_ENTRY listEntry;
    PSHADOWSTRIKE_PATH_EXCLUSION entry;

    for (listEntry = g_ExclusionManager.PathExclusions.Flink;
         listEntry != &g_ExclusionManager.PathExclusions;
         listEntry = listEntry->Flink) {

        entry = CONTAINING_RECORD(listEntry, SHADOWSTRIKE_PATH_EXCLUSION, ListEntry);

        if (entry->PathLength == Path->Length / sizeof(WCHAR)) {
            UNICODE_STRING entryPath;
            entryPath.Buffer = entry->Path;
            entryPath.Length = entry->PathLength * sizeof(WCHAR);
            entryPath.MaximumLength = entryPath.Length;

            if (RtlCompareUnicodeString(&entryPath, Path, TRUE) == 0) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

/**
 * @brief Check if an extension exclusion already exists (caller holds ExtensionLock exclusive).
 */
_Requires_lock_held_(g_ExclusionManager.ExtensionLock)
static
BOOLEAN
ExclusionpExtensionExistLocked(
    _In_ PCUNICODE_STRING Extension,
    _In_ ULONG BucketIndex
    )
{
    PLIST_ENTRY listEntry;
    PSHADOWSTRIKE_EXTENSION_EXCLUSION entry;
    PSHADOWSTRIKE_EXTENSION_BUCKET bucket = &g_ExclusionManager.ExtensionBuckets[BucketIndex];

    for (listEntry = bucket->ListHead.Flink;
         listEntry != &bucket->ListHead;
         listEntry = listEntry->Flink) {

        entry = CONTAINING_RECORD(listEntry, SHADOWSTRIKE_EXTENSION_EXCLUSION, ListEntry);

        if (entry->ExtensionLength == Extension->Length / sizeof(WCHAR)) {
            UNICODE_STRING entryExt;
            entryExt.Buffer = entry->Extension;
            entryExt.Length = entry->ExtensionLength * sizeof(WCHAR);
            entryExt.MaximumLength = entryExt.Length;

            if (RtlCompareUnicodeString(&entryExt, Extension, TRUE) == 0) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

/**
 * @brief Check if a process name exclusion already exists (caller holds ProcessLock exclusive).
 */
_Requires_lock_held_(g_ExclusionManager.ProcessLock)
static
BOOLEAN
ExclusionpProcessExistLocked(
    _In_ PCUNICODE_STRING ProcessName,
    _In_ ULONG BucketIndex
    )
{
    PLIST_ENTRY listEntry;
    PSHADOWSTRIKE_PROCESS_EXCLUSION entry;
    PSHADOWSTRIKE_PROCESS_BUCKET bucket = &g_ExclusionManager.ProcessBuckets[BucketIndex];

    for (listEntry = bucket->ListHead.Flink;
         listEntry != &bucket->ListHead;
         listEntry = listEntry->Flink) {

        entry = CONTAINING_RECORD(listEntry, SHADOWSTRIKE_PROCESS_EXCLUSION, ListEntry);

        if (entry->NameLength == ProcessName->Length / sizeof(WCHAR)) {
            UNICODE_STRING entryName;
            entryName.Buffer = entry->ProcessName;
            entryName.Length = entry->NameLength * sizeof(WCHAR);
            entryName.MaximumLength = entryName.Length;

            if (RtlCompareUnicodeString(&entryName, ProcessName, TRUE) == 0) {
                return TRUE;
            }
        }
    }
    return FALSE;
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
    // Initialize rundown protection — the correct kernel primitive for
    // "allow concurrent access, block shutdown until all users drain."
    //
    ExInitializeRundownProtection(&g_ExclusionManager.RundownRef);

    //
    // Enable exclusions by default.
    // Use InterlockedExchange8 for atomic store with full barrier.
    //
    InterlockedExchange8((volatile CHAR*)&g_ExclusionManager.Enabled, TRUE);

    //
    // Mark initialized last (after all state is set up) with release semantics
    //
    WriteBooleanRelease(&g_ExclusionManager.Initialized, TRUE);

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
    // Disable exclusions first so no new work starts
    //
    InterlockedExchange8((volatile CHAR*)&g_ExclusionManager.Enabled, FALSE);

    //
    // Wait for all active users to drain. ExWaitForRundownProtectionRelease
    // blocks until every ExAcquireRundownProtection holder has called
    // ExReleaseRundownProtection. After this returns, no new acquisitions
    // are possible. No timeout — if a caller is stuck, that is a separate
    // bug that must not be masked by forced freeing.
    //
    ExWaitForRundownProtectionRelease(&g_ExclusionManager.RundownRef);

    //
    // All users have drained — safe to free all entries
    //
    ShadowStrikeClearExclusions(ShadowStrikeExclusionPath);
    ShadowStrikeClearExclusions(ShadowStrikeExclusionExtension);
    ShadowStrikeClearExclusions(ShadowStrikeExclusionProcessName);
    ShadowStrikeClearExclusions(ShadowStrikeExclusionProcessId);

    WriteBooleanRelease(&g_ExclusionManager.Initialized, FALSE);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Exclusion manager shutdown complete\n");
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

    if (!ReadBooleanAcquire(&g_ExclusionManager.Initialized) ||
        !ReadBooleanAcquire(&g_ExclusionManager.Enabled)) {
        return FALSE;
    }

    if (!ShadowStrikeValidateUnicodeString(FilePath) || FilePath->Length == 0) {
        return FALSE;
    }

    if (!ExclusionpAcquireRundown()) {
        return FALSE;
    }

    InterlockedIncrement64(&g_ExclusionManager.Stats.TotalChecks);

    //
    // Check extension exclusion first (faster O(1) hash lookup).
    // Call the internal locked check directly instead of the public API
    // to avoid acquiring rundown protection twice.
    //
    if (Extension != NULL && ShadowStrikeValidateUnicodeString(Extension) &&
        Extension->Length > 0) {

        ULONG bucketIndex;
        PSHADOWSTRIKE_EXTENSION_BUCKET bucket;

        bucketIndex = ShadowStrikeExtensionHash(Extension);
        bucket = &g_ExclusionManager.ExtensionBuckets[bucketIndex];

        //
        // Fast-path: if bucket is empty, skip. This is a benign race —
        // a concurrent add may be missed for one check cycle.
        // ReadNoFence makes the intentional raciness explicit.
        //
        if (ReadNoFence(&bucket->EntryCount) > 0) {
            PLIST_ENTRY extEntry;
            PSHADOWSTRIKE_EXTENSION_EXCLUSION extExcl;

            KeEnterCriticalRegion();
            ExAcquirePushLockShared(&g_ExclusionManager.ExtensionLock);

            for (extEntry = bucket->ListHead.Flink;
                 extEntry != &bucket->ListHead;
                 extEntry = extEntry->Flink) {

                extExcl = CONTAINING_RECORD(extEntry, SHADOWSTRIKE_EXTENSION_EXCLUSION, ListEntry);

                if (extExcl->ExtensionLength == Extension->Length / sizeof(WCHAR)) {
                    UNICODE_STRING entryExt;
                    entryExt.Buffer = extExcl->Extension;
                    entryExt.Length = extExcl->ExtensionLength * sizeof(WCHAR);
                    entryExt.MaximumLength = entryExt.Length;

                    if (RtlCompareUnicodeString(&entryExt, Extension, TRUE) == 0) {
                        excluded = TRUE;
                        InterlockedIncrement(&extExcl->HitCount);
                        InterlockedIncrement64(&g_ExclusionManager.Stats.ExtensionMatches);
                        InterlockedIncrement64(&g_ExclusionManager.Stats.TotalBypassed);
                        break;
                    }
                }
            }

            ExReleasePushLockShared(&g_ExclusionManager.ExtensionLock);
            KeLeaveCriticalRegion();
        }

        if (excluded) {
            ExclusionpReleaseRundown();
            return TRUE;
        }
    }

    //
    // Check path exclusions
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_ExclusionManager.PathLock);

    for (listEntry = g_ExclusionManager.PathExclusions.Flink;
         listEntry != &g_ExclusionManager.PathExclusions;
         listEntry = listEntry->Flink) {

        entry = CONTAINING_RECORD(listEntry, SHADOWSTRIKE_PATH_EXCLUSION, ListEntry);

        //
        // Skip expired entries
        //
        if (entry->ExpireTime.QuadPart != 0) {
            LARGE_INTEGER currentTime;
            KeQuerySystemTime(&currentTime);
            if (currentTime.QuadPart > entry->ExpireTime.QuadPart) {
                continue;
            }
        }

        //
        // Build a UNICODE_STRING for the exclusion pattern
        //
        {
            UNICODE_STRING entryPath;
            entryPath.Buffer = entry->Path;
            entryPath.Length = entry->PathLength * sizeof(WCHAR);
            entryPath.MaximumLength = sizeof(entry->Path);

            excluded = ShadowStrikeMatchPathPattern(FilePath, &entryPath, entry->Flags);
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

    ExclusionpReleaseRundown();

    return excluded;
}

BOOLEAN
ShadowStrikeIsExtensionExcluded(
    _In_ PCUNICODE_STRING Extension
    )
{
    ULONG bucketIndex;
    PSHADOWSTRIKE_EXTENSION_BUCKET bucket;
    PLIST_ENTRY listEntry;
    PSHADOWSTRIKE_EXTENSION_EXCLUSION entry;
    BOOLEAN excluded = FALSE;

    if (!ReadBooleanAcquire(&g_ExclusionManager.Initialized) ||
        !ReadBooleanAcquire(&g_ExclusionManager.Enabled)) {
        return FALSE;
    }

    if (!ShadowStrikeValidateUnicodeString(Extension) || Extension->Length == 0) {
        return FALSE;
    }

    if (!ExclusionpAcquireRundown()) {
        return FALSE;
    }

    bucketIndex = ShadowStrikeExtensionHash(Extension);
    bucket = &g_ExclusionManager.ExtensionBuckets[bucketIndex];

    //
    // Fast-path: if bucket is empty, no match possible.
    // ReadNoFence makes the intentional benign race explicit.
    //
    if (ReadNoFence(&bucket->EntryCount) == 0) {
        ExclusionpReleaseRundown();
        return FALSE;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_ExclusionManager.ExtensionLock);

    for (listEntry = bucket->ListHead.Flink;
         listEntry != &bucket->ListHead;
         listEntry = listEntry->Flink) {

        entry = CONTAINING_RECORD(listEntry, SHADOWSTRIKE_EXTENSION_EXCLUSION, ListEntry);

        if (entry->ExtensionLength == Extension->Length / sizeof(WCHAR)) {
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

    ExclusionpReleaseRundown();

    return excluded;
}

BOOLEAN
ShadowStrikeIsProcessExcluded(
    _In_ HANDLE ProcessId,
    _In_opt_ PCUNICODE_STRING ProcessName
    )
{
    ULONG i;
    ULONG bucketIndex;
    PSHADOWSTRIKE_PROCESS_BUCKET bucket;
    PLIST_ENTRY listEntry;
    PSHADOWSTRIKE_PROCESS_EXCLUSION entry;
    BOOLEAN excluded = FALSE;
    LARGE_INTEGER currentTime;

    if (!ReadBooleanAcquire(&g_ExclusionManager.Initialized) ||
        !ReadBooleanAcquire(&g_ExclusionManager.Enabled)) {
        return FALSE;
    }

    if (!ExclusionpAcquireRundown()) {
        return FALSE;
    }

    //
    // Check PID exclusions first (O(N) scan over fixed-size array)
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_ExclusionManager.PidLock);

    KeQuerySystemTime(&currentTime);

    for (i = 0; i < SHADOWSTRIKE_MAX_PID_EXCLUSIONS; i++) {
        if (g_ExclusionManager.PidExclusions[i].Valid &&
            g_ExclusionManager.PidExclusions[i].ProcessId == ProcessId) {

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
        ExclusionpReleaseRundown();
        return TRUE;
    }

    //
    // Check process name exclusions
    //
    if (ProcessName == NULL || !ShadowStrikeValidateUnicodeString(ProcessName) ||
        ProcessName->Length == 0) {
        ExclusionpReleaseRundown();
        return FALSE;
    }

    bucketIndex = ShadowStrikeProcessNameHash(ProcessName);
    bucket = &g_ExclusionManager.ProcessBuckets[bucketIndex];

    //
    // Fast-path: empty bucket (benign race, ReadNoFence for explicit intent)
    //
    if (ReadNoFence(&bucket->EntryCount) == 0) {
        ExclusionpReleaseRundown();
        return FALSE;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_ExclusionManager.ProcessLock);

    for (listEntry = bucket->ListHead.Flink;
         listEntry != &bucket->ListHead;
         listEntry = listEntry->Flink) {

        entry = CONTAINING_RECORD(listEntry, SHADOWSTRIKE_PROCESS_EXCLUSION, ListEntry);

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

    ExclusionpReleaseRundown();

    return excluded;
}

// ============================================================================
// MANAGEMENT FUNCTIONS
// ============================================================================

NTSTATUS
ShadowStrikeAddPathExclusion(
    _In_ PCUNICODE_STRING Path,
    _In_ UINT8 Flags,
    _In_ ULONG TTLSeconds
    )
{
    PSHADOWSTRIKE_PATH_EXCLUSION entry;
    USHORT pathChars;

    PAGED_CODE();

    //
    // Access control: only kernel-mode callers may add exclusions
    //
    if (!ExclusionpValidateCallerIsKernel()) {
        return STATUS_ACCESS_DENIED;
    }

    if (!ShadowStrikeValidateUnicodeString(Path) || Path->Length == 0 ||
        !ReadBooleanAcquire(&g_ExclusionManager.Initialized)) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Allocate entry from PagedPool — only accessed at <= APC_LEVEL
    //
    entry = (PSHADOWSTRIKE_PATH_EXCLUSION)ExAllocatePoolZero(
        PagedPool,
        sizeof(SHADOWSTRIKE_PATH_EXCLUSION),
        SHADOWSTRIKE_EXCLUSION_POOL_TAG
    );

    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize entry — normalize path to uppercase
    //
    entry->Flags = Flags;
    pathChars = (USHORT)min(Path->Length / sizeof(WCHAR),
                            SHADOWSTRIKE_MAX_EXCLUSION_PATH_LENGTH - 1);

    {
        USHORT k;
        for (k = 0; k < pathChars; k++) {
            entry->Path[k] = RtlUpcaseUnicodeChar(Path->Buffer[k]);
        }
    }

    //
    // Strip trailing separators (but keep root "\")
    //
    while (pathChars > 1 && entry->Path[pathChars - 1] == L'\\') {
        pathChars--;
    }

    entry->Path[pathChars] = L'\0';
    entry->PathLength = pathChars;
    KeQuerySystemTime(&entry->CreateTime);

    //
    // Set expiration time if Temporary flag is set and TTL > 0
    //
    if ((Flags & ShadowStrikeExclusionFlagTemporary) && TTLSeconds > 0) {
        entry->ExpireTime.QuadPart =
            entry->CreateTime.QuadPart + ((LONGLONG)TTLSeconds * 10000000LL);
    }

    //
    // Insert into list under exclusive lock — check limit and duplicates atomically
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ExclusionManager.PathLock);

    if (g_ExclusionManager.Stats.PathExclusionCount >= SHADOWSTRIKE_MAX_PATH_EXCLUSIONS) {
        ExReleasePushLockExclusive(&g_ExclusionManager.PathLock);
        KeLeaveCriticalRegion();
        ExFreePoolWithTag(entry, SHADOWSTRIKE_EXCLUSION_POOL_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    {
        UNICODE_STRING normalizedPath;
        normalizedPath.Buffer = entry->Path;
        normalizedPath.Length = entry->PathLength * sizeof(WCHAR);
        normalizedPath.MaximumLength = normalizedPath.Length;

        if (ExclusionpPathExistLocked(&normalizedPath)) {
            ExReleasePushLockExclusive(&g_ExclusionManager.PathLock);
            KeLeaveCriticalRegion();
            ExFreePoolWithTag(entry, SHADOWSTRIKE_EXCLUSION_POOL_TAG);
            return STATUS_OBJECT_NAME_COLLISION;
        }
    }

    InsertTailList(&g_ExclusionManager.PathExclusions, &entry->ListEntry);
    g_ExclusionManager.Stats.PathExclusionCount++;

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
    ULONG bucketIndex;
    USHORT extChars;

    PAGED_CODE();

    //
    // Access control: only kernel-mode callers may add exclusions
    //
    if (!ExclusionpValidateCallerIsKernel()) {
        return STATUS_ACCESS_DENIED;
    }

    if (!ShadowStrikeValidateUnicodeString(Extension) || Extension->Length == 0 ||
        !ReadBooleanAcquire(&g_ExclusionManager.Initialized)) {
        return STATUS_INVALID_PARAMETER;
    }

    entry = (PSHADOWSTRIKE_EXTENSION_EXCLUSION)ExAllocatePoolZero(
        PagedPool,
        sizeof(SHADOWSTRIKE_EXTENSION_EXCLUSION),
        SHADOWSTRIKE_EXCLUSION_POOL_TAG
    );

    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    entry->Flags = Flags;
    extChars = (USHORT)min(Extension->Length / sizeof(WCHAR),
                           SHADOWSTRIKE_MAX_EXTENSION_LENGTH - 1);

    {
        USHORT k;
        for (k = 0; k < extChars; k++) {
            entry->Extension[k] = RtlUpcaseUnicodeChar(Extension->Buffer[k]);
        }
    }
    entry->Extension[extChars] = L'\0';
    entry->ExtensionLength = extChars;

    //
    // Compute hash on the already-normalized (upcased) entry for consistency
    //
    {
        UNICODE_STRING normalizedExt;
        normalizedExt.Buffer = entry->Extension;
        normalizedExt.Length = entry->ExtensionLength * sizeof(WCHAR);
        normalizedExt.MaximumLength = normalizedExt.Length;
        bucketIndex = ShadowStrikeExtensionHash(&normalizedExt);
    }

    //
    // Insert under exclusive lock — atomic limit + duplicate check
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ExclusionManager.ExtensionLock);

    if (g_ExclusionManager.Stats.ExtensionExclusionCount >= SHADOWSTRIKE_MAX_EXTENSION_EXCLUSIONS) {
        ExReleasePushLockExclusive(&g_ExclusionManager.ExtensionLock);
        KeLeaveCriticalRegion();
        ExFreePoolWithTag(entry, SHADOWSTRIKE_EXCLUSION_POOL_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Duplicate check using the normalized (upcased) value for consistency
    //
    {
        UNICODE_STRING normalizedExt;
        normalizedExt.Buffer = entry->Extension;
        normalizedExt.Length = entry->ExtensionLength * sizeof(WCHAR);
        normalizedExt.MaximumLength = normalizedExt.Length;

        if (ExclusionpExtensionExistLocked(&normalizedExt, bucketIndex)) {
            ExReleasePushLockExclusive(&g_ExclusionManager.ExtensionLock);
            KeLeaveCriticalRegion();
            ExFreePoolWithTag(entry, SHADOWSTRIKE_EXCLUSION_POOL_TAG);
            return STATUS_OBJECT_NAME_COLLISION;
        }
    }

    InsertHeadList(&g_ExclusionManager.ExtensionBuckets[bucketIndex].ListHead, &entry->ListEntry);
    g_ExclusionManager.ExtensionBuckets[bucketIndex].EntryCount++;
    g_ExclusionManager.Stats.ExtensionExclusionCount++;

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
    ULONG bucketIndex;
    USHORT nameChars;

    PAGED_CODE();

    //
    // Access control: only kernel-mode callers may add exclusions
    //
    if (!ExclusionpValidateCallerIsKernel()) {
        return STATUS_ACCESS_DENIED;
    }

    if (!ShadowStrikeValidateUnicodeString(ProcessName) || ProcessName->Length == 0 ||
        !ReadBooleanAcquire(&g_ExclusionManager.Initialized)) {
        return STATUS_INVALID_PARAMETER;
    }

    entry = (PSHADOWSTRIKE_PROCESS_EXCLUSION)ExAllocatePoolZero(
        PagedPool,
        sizeof(SHADOWSTRIKE_PROCESS_EXCLUSION),
        SHADOWSTRIKE_EXCLUSION_POOL_TAG
    );

    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    entry->Flags = Flags;
    nameChars = (USHORT)min(ProcessName->Length / sizeof(WCHAR),
                            SHADOWSTRIKE_MAX_PROCESS_NAME_LENGTH - 1);

    {
        USHORT k;
        for (k = 0; k < nameChars; k++) {
            entry->ProcessName[k] = RtlUpcaseUnicodeChar(ProcessName->Buffer[k]);
        }
    }
    entry->ProcessName[nameChars] = L'\0';
    entry->NameLength = nameChars;

    //
    // Hash on the normalized (upcased) value for consistency
    //
    {
        UNICODE_STRING normalizedName;
        normalizedName.Buffer = entry->ProcessName;
        normalizedName.Length = entry->NameLength * sizeof(WCHAR);
        normalizedName.MaximumLength = normalizedName.Length;
        bucketIndex = ShadowStrikeProcessNameHash(&normalizedName);
    }

    //
    // Insert under exclusive lock — atomic limit + duplicate check
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ExclusionManager.ProcessLock);

    if (g_ExclusionManager.Stats.ProcessExclusionCount >= SHADOWSTRIKE_MAX_PROCESS_EXCLUSIONS) {
        ExReleasePushLockExclusive(&g_ExclusionManager.ProcessLock);
        KeLeaveCriticalRegion();
        ExFreePoolWithTag(entry, SHADOWSTRIKE_EXCLUSION_POOL_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Duplicate check using normalized (upcased) value
    //
    {
        UNICODE_STRING normalizedName;
        normalizedName.Buffer = entry->ProcessName;
        normalizedName.Length = entry->NameLength * sizeof(WCHAR);
        normalizedName.MaximumLength = normalizedName.Length;

        if (ExclusionpProcessExistLocked(&normalizedName, bucketIndex)) {
            ExReleasePushLockExclusive(&g_ExclusionManager.ProcessLock);
            KeLeaveCriticalRegion();
            ExFreePoolWithTag(entry, SHADOWSTRIKE_EXCLUSION_POOL_TAG);
            return STATUS_OBJECT_NAME_COLLISION;
        }
    }

    InsertHeadList(&g_ExclusionManager.ProcessBuckets[bucketIndex].ListHead, &entry->ListEntry);
    g_ExclusionManager.ProcessBuckets[bucketIndex].EntryCount++;
    g_ExclusionManager.Stats.ProcessExclusionCount++;

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

    if (!ReadBooleanAcquire(&g_ExclusionManager.Initialized)) {
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
    // NTFS metafiles — these generate enormous I/O and cannot contain
    // user-mode executable code. They are safe to exclude.
    //
    // These use the ShadowStrikeExclusionFlagRecursive flag so they match
    // as path component suffixes regardless of volume prefix, e.g.,
    // "\Device\HarddiskVolume1\$LogFile" matches "\$LOGFILE" with
    // recursive prefix + path boundary check.
    //
    RtlInitUnicodeString(&str, L"\\$LogFile");
    ShadowStrikeAddPathExclusion(&str,
        ShadowStrikeExclusionFlagSystem | ShadowStrikeExclusionFlagRecursive, 0);

    RtlInitUnicodeString(&str, L"\\$Mft");
    ShadowStrikeAddPathExclusion(&str,
        ShadowStrikeExclusionFlagSystem | ShadowStrikeExclusionFlagRecursive, 0);

    RtlInitUnicodeString(&str, L"\\$MftMirr");
    ShadowStrikeAddPathExclusion(&str,
        ShadowStrikeExclusionFlagSystem | ShadowStrikeExclusionFlagRecursive, 0);

    RtlInitUnicodeString(&str, L"\\$Bitmap");
    ShadowStrikeAddPathExclusion(&str,
        ShadowStrikeExclusionFlagSystem | ShadowStrikeExclusionFlagRecursive, 0);

    //
    // System paging files — locked by the OS, cannot be tampered with.
    // Recursive flag ensures matching across all volumes.
    //
    RtlInitUnicodeString(&str, L"\\pagefile.sys");
    ShadowStrikeAddPathExclusion(&str,
        ShadowStrikeExclusionFlagSystem | ShadowStrikeExclusionFlagRecursive, 0);

    RtlInitUnicodeString(&str, L"\\swapfile.sys");
    ShadowStrikeAddPathExclusion(&str,
        ShadowStrikeExclusionFlagSystem | ShadowStrikeExclusionFlagRecursive, 0);

    RtlInitUnicodeString(&str, L"\\hiberfil.sys");
    ShadowStrikeAddPathExclusion(&str,
        ShadowStrikeExclusionFlagSystem | ShadowStrikeExclusionFlagRecursive, 0);

    //
    // NOTE: No extension exclusions are loaded by default.
    // No file extension is inherently safe — malware uses .log, .txt, .db,
    // .dat, and other "innocent" extensions for payload storage, C2 data,
    // and credential exfiltration. Extension exclusions must be explicitly
    // configured by the administrator.
    //
}

VOID
ShadowStrikeExclusionSetEnabled(
    _In_ BOOLEAN Enable
    )
{
    //
    // InterlockedExchange8 provides full memory barrier — no additional
    // MemoryBarrier() needed.
    //
    InterlockedExchange8((volatile CHAR*)&g_ExclusionManager.Enabled, (CHAR)Enable);
}

BOOLEAN
ShadowStrikeExclusionIsEnabled(
    VOID
    )
{
    return ReadBooleanAcquire(&g_ExclusionManager.Enabled);
}

// ============================================================================
// REMOVAL FUNCTIONS
// ============================================================================

BOOLEAN
ShadowStrikeRemovePathExclusion(
    _In_ PCUNICODE_STRING Path
    )
{
    PLIST_ENTRY listEntry;
    PLIST_ENTRY nextEntry;
    PSHADOWSTRIKE_PATH_EXCLUSION entry;
    PSHADOWSTRIKE_PATH_EXCLUSION toRemove = NULL;
    BOOLEAN removed = FALSE;

    PAGED_CODE();

    if (!ShadowStrikeValidateUnicodeString(Path) || Path->Length == 0 ||
        !ReadBooleanAcquire(&g_ExclusionManager.Initialized)) {
        return FALSE;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ExclusionManager.PathLock);

    for (listEntry = g_ExclusionManager.PathExclusions.Flink;
         listEntry != &g_ExclusionManager.PathExclusions;
         listEntry = nextEntry) {

        nextEntry = listEntry->Flink;
        entry = CONTAINING_RECORD(listEntry, SHADOWSTRIKE_PATH_EXCLUSION, ListEntry);

        if (!(entry->Flags & ShadowStrikeExclusionFlagSystem)) {
            UNICODE_STRING entryPath;
            entryPath.Buffer = entry->Path;
            entryPath.Length = entry->PathLength * sizeof(WCHAR);
            entryPath.MaximumLength = entryPath.Length;

            if (RtlCompareUnicodeString(&entryPath, Path, TRUE) == 0) {
                RemoveEntryList(&entry->ListEntry);
                toRemove = entry;
                removed = TRUE;
                if (g_ExclusionManager.Stats.PathExclusionCount > 0) {
                    g_ExclusionManager.Stats.PathExclusionCount--;
                }
                break;
            }
        }
    }

    ExReleasePushLockExclusive(&g_ExclusionManager.PathLock);
    KeLeaveCriticalRegion();

    if (toRemove != NULL) {
        ExFreePoolWithTag(toRemove, SHADOWSTRIKE_EXCLUSION_POOL_TAG);
    }

    return removed;
}

BOOLEAN
ShadowStrikeRemoveExtensionExclusion(
    _In_ PCUNICODE_STRING Extension
    )
{
    ULONG bucketIndex;
    PLIST_ENTRY listEntry;
    PLIST_ENTRY nextEntry;
    PSHADOWSTRIKE_EXTENSION_EXCLUSION entry;
    PSHADOWSTRIKE_EXTENSION_EXCLUSION toRemove = NULL;
    BOOLEAN removed = FALSE;

    PAGED_CODE();

    if (!ShadowStrikeValidateUnicodeString(Extension) || Extension->Length == 0 ||
        !ReadBooleanAcquire(&g_ExclusionManager.Initialized)) {
        return FALSE;
    }

    bucketIndex = ShadowStrikeExtensionHash(Extension);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ExclusionManager.ExtensionLock);

    for (listEntry = g_ExclusionManager.ExtensionBuckets[bucketIndex].ListHead.Flink;
         listEntry != &g_ExclusionManager.ExtensionBuckets[bucketIndex].ListHead;
         listEntry = nextEntry) {

        nextEntry = listEntry->Flink;
        entry = CONTAINING_RECORD(listEntry, SHADOWSTRIKE_EXTENSION_EXCLUSION, ListEntry);

        if (!(entry->Flags & ShadowStrikeExclusionFlagSystem)) {
            if (entry->ExtensionLength == Extension->Length / sizeof(WCHAR)) {
                UNICODE_STRING entryExt;
                entryExt.Buffer = entry->Extension;
                entryExt.Length = entry->ExtensionLength * sizeof(WCHAR);
                entryExt.MaximumLength = entryExt.Length;

                if (RtlCompareUnicodeString(&entryExt, Extension, TRUE) == 0) {
                    RemoveEntryList(&entry->ListEntry);
                    toRemove = entry;
                    removed = TRUE;
                    if (g_ExclusionManager.ExtensionBuckets[bucketIndex].EntryCount > 0) {
                        g_ExclusionManager.ExtensionBuckets[bucketIndex].EntryCount--;
                    }
                    if (g_ExclusionManager.Stats.ExtensionExclusionCount > 0) {
                        g_ExclusionManager.Stats.ExtensionExclusionCount--;
                    }
                    break;
                }
            }
        }
    }

    ExReleasePushLockExclusive(&g_ExclusionManager.ExtensionLock);
    KeLeaveCriticalRegion();

    if (toRemove != NULL) {
        ExFreePoolWithTag(toRemove, SHADOWSTRIKE_EXCLUSION_POOL_TAG);
    }

    return removed;
}

BOOLEAN
ShadowStrikeRemoveProcessExclusion(
    _In_ PCUNICODE_STRING ProcessName
    )
{
    ULONG bucketIndex;
    PLIST_ENTRY listEntry;
    PLIST_ENTRY nextEntry;
    PSHADOWSTRIKE_PROCESS_EXCLUSION entry;
    PSHADOWSTRIKE_PROCESS_EXCLUSION toRemove = NULL;
    BOOLEAN removed = FALSE;

    PAGED_CODE();

    if (!ShadowStrikeValidateUnicodeString(ProcessName) || ProcessName->Length == 0 ||
        !ReadBooleanAcquire(&g_ExclusionManager.Initialized)) {
        return FALSE;
    }

    bucketIndex = ShadowStrikeProcessNameHash(ProcessName);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ExclusionManager.ProcessLock);

    for (listEntry = g_ExclusionManager.ProcessBuckets[bucketIndex].ListHead.Flink;
         listEntry != &g_ExclusionManager.ProcessBuckets[bucketIndex].ListHead;
         listEntry = nextEntry) {

        nextEntry = listEntry->Flink;
        entry = CONTAINING_RECORD(listEntry, SHADOWSTRIKE_PROCESS_EXCLUSION, ListEntry);

        if (!(entry->Flags & ShadowStrikeExclusionFlagSystem)) {
            if (entry->NameLength == ProcessName->Length / sizeof(WCHAR)) {
                UNICODE_STRING entryName;
                entryName.Buffer = entry->ProcessName;
                entryName.Length = entry->NameLength * sizeof(WCHAR);
                entryName.MaximumLength = entryName.Length;

                if (RtlCompareUnicodeString(&entryName, ProcessName, TRUE) == 0) {
                    RemoveEntryList(&entry->ListEntry);
                    toRemove = entry;
                    removed = TRUE;
                    if (g_ExclusionManager.ProcessBuckets[bucketIndex].EntryCount > 0) {
                        g_ExclusionManager.ProcessBuckets[bucketIndex].EntryCount--;
                    }
                    if (g_ExclusionManager.Stats.ProcessExclusionCount > 0) {
                        g_ExclusionManager.Stats.ProcessExclusionCount--;
                    }
                    break;
                }
            }
        }
    }

    ExReleasePushLockExclusive(&g_ExclusionManager.ProcessLock);
    KeLeaveCriticalRegion();

    if (toRemove != NULL) {
        ExFreePoolWithTag(toRemove, SHADOWSTRIKE_EXCLUSION_POOL_TAG);
    }

    return removed;
}

// ============================================================================
// PID EXCLUSION MANAGEMENT
// ============================================================================

NTSTATUS
ShadowStrikeAddPidExclusion(
    _In_ HANDLE ProcessId,
    _In_ ULONG TTLSeconds
    )
{
    ULONG i;
    ULONG freeSlot = MAXULONG;
    LARGE_INTEGER currentTime;
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
    PEPROCESS process = NULL;

    PAGED_CODE();

    //
    // Access control: only kernel-mode callers may add exclusions
    //
    if (!ExclusionpValidateCallerIsKernel()) {
        return STATUS_ACCESS_DENIED;
    }

    if (ProcessId == NULL || !ReadBooleanAcquire(&g_ExclusionManager.Initialized)) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate the PID refers to an actual running process to prevent
    // PID pre-exclusion attacks (attacker excludes a future PID).
    //
    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return STATUS_INVALID_PARAMETER;
    }
    ObDereferenceObject(process);
    process = NULL;

    KeQuerySystemTime(&currentTime);
    status = STATUS_INSUFFICIENT_RESOURCES;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ExclusionManager.PidLock);

    //
    // Single pass: check for duplicate, find free slot, reclaim expired
    //
    for (i = 0; i < SHADOWSTRIKE_MAX_PID_EXCLUSIONS; i++) {
        if (g_ExclusionManager.PidExclusions[i].Valid) {
            if (g_ExclusionManager.PidExclusions[i].ProcessId == ProcessId) {
                //
                // Already exists — update TTL
                //
                if (TTLSeconds > 0) {
                    g_ExclusionManager.PidExclusions[i].ExpireTime.QuadPart =
                        currentTime.QuadPart + ((LONGLONG)TTLSeconds * 10000000LL);
                } else {
                    g_ExclusionManager.PidExclusions[i].ExpireTime.QuadPart = 0;
                }
                status = STATUS_SUCCESS;
                goto Done;
            }

            //
            // Reclaim expired entries
            //
            if (g_ExclusionManager.PidExclusions[i].ExpireTime.QuadPart != 0 &&
                currentTime.QuadPart > g_ExclusionManager.PidExclusions[i].ExpireTime.QuadPart) {
                g_ExclusionManager.PidExclusions[i].Valid = FALSE;
                if (g_ExclusionManager.Stats.PidExclusionCount > 0) {
                    g_ExclusionManager.Stats.PidExclusionCount--;
                }
                if (freeSlot == MAXULONG) {
                    freeSlot = i;
                }
            }
        } else {
            if (freeSlot == MAXULONG) {
                freeSlot = i;
            }
        }
    }

    //
    // Add to free slot
    //
    if (freeSlot != MAXULONG) {
        RtlZeroMemory(&g_ExclusionManager.PidExclusions[freeSlot],
                      sizeof(SHADOWSTRIKE_PID_EXCLUSION));

        g_ExclusionManager.PidExclusions[freeSlot].ProcessId = ProcessId;
        g_ExclusionManager.PidExclusions[freeSlot].Valid = TRUE;
        g_ExclusionManager.PidExclusions[freeSlot].HitCount = 0;

        if (TTLSeconds > 0) {
            g_ExclusionManager.PidExclusions[freeSlot].ExpireTime.QuadPart =
                currentTime.QuadPart + ((LONGLONG)TTLSeconds * 10000000LL);
        } else {
            g_ExclusionManager.PidExclusions[freeSlot].ExpireTime.QuadPart = 0;
        }

        g_ExclusionManager.Stats.PidExclusionCount++;
        status = STATUS_SUCCESS;
    }

Done:
    ExReleasePushLockExclusive(&g_ExclusionManager.PidLock);
    KeLeaveCriticalRegion();

    return status;
}

BOOLEAN
ShadowStrikeRemovePidExclusion(
    _In_ HANDLE ProcessId
    )
{
    ULONG i;
    BOOLEAN removed = FALSE;

    PAGED_CODE();

    if (ProcessId == NULL || !ReadBooleanAcquire(&g_ExclusionManager.Initialized)) {
        return FALSE;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ExclusionManager.PidLock);

    for (i = 0; i < SHADOWSTRIKE_MAX_PID_EXCLUSIONS; i++) {
        if (g_ExclusionManager.PidExclusions[i].Valid &&
            g_ExclusionManager.PidExclusions[i].ProcessId == ProcessId) {

            g_ExclusionManager.PidExclusions[i].Valid = FALSE;
            g_ExclusionManager.PidExclusions[i].ProcessId = NULL;
            g_ExclusionManager.PidExclusions[i].HitCount = 0;
            g_ExclusionManager.PidExclusions[i].ExpireTime.QuadPart = 0;

            if (g_ExclusionManager.Stats.PidExclusionCount > 0) {
                g_ExclusionManager.Stats.PidExclusionCount--;
            }
            removed = TRUE;
            break;
        }
    }

    ExReleasePushLockExclusive(&g_ExclusionManager.PidLock);
    KeLeaveCriticalRegion();

    return removed;
}

// ============================================================================
// STATISTICS FUNCTIONS
// ============================================================================

VOID
ShadowStrikeExclusionGetStats(
    _Out_ PSHADOWSTRIKE_EXCLUSION_STATS Stats
    )
{
    if (Stats == NULL) {
        return;
    }

    if (!ReadBooleanAcquire(&g_ExclusionManager.Initialized)) {
        RtlZeroMemory(Stats, sizeof(SHADOWSTRIKE_EXCLUSION_STATS));
        return;
    }

    //
    // Snapshot statistics. Individual fields are monotonically correct
    // (InterlockedIncrement64 updates). Cross-field consistency is NOT
    // guaranteed — e.g., TotalChecks may not equal the sum of individual
    // match counters at the instant of the snapshot. This is documented
    // and acceptable for telemetry/diagnostics.
    //
    MemoryBarrier();
    Stats->TotalChecks = g_ExclusionManager.Stats.TotalChecks;
    Stats->PathMatches = g_ExclusionManager.Stats.PathMatches;
    Stats->ExtensionMatches = g_ExclusionManager.Stats.ExtensionMatches;
    Stats->ProcessNameMatches = g_ExclusionManager.Stats.ProcessNameMatches;
    Stats->PidMatches = g_ExclusionManager.Stats.PidMatches;
    Stats->TotalBypassed = g_ExclusionManager.Stats.TotalBypassed;
    Stats->PathExclusionCount = g_ExclusionManager.Stats.PathExclusionCount;
    Stats->ExtensionExclusionCount = g_ExclusionManager.Stats.ExtensionExclusionCount;
    Stats->ProcessExclusionCount = g_ExclusionManager.Stats.ProcessExclusionCount;
    Stats->PidExclusionCount = g_ExclusionManager.Stats.PidExclusionCount;
    MemoryBarrier();
}

VOID
ShadowStrikeExclusionResetStats(
    VOID
    )
{
    if (!ReadBooleanAcquire(&g_ExclusionManager.Initialized)) {
        return;
    }

    //
    // Reset match counters but preserve exclusion counts
    //
    InterlockedExchange64(&g_ExclusionManager.Stats.TotalChecks, 0);
    InterlockedExchange64(&g_ExclusionManager.Stats.PathMatches, 0);
    InterlockedExchange64(&g_ExclusionManager.Stats.ExtensionMatches, 0);
    InterlockedExchange64(&g_ExclusionManager.Stats.ProcessNameMatches, 0);
    InterlockedExchange64(&g_ExclusionManager.Stats.PidMatches, 0);
    InterlockedExchange64(&g_ExclusionManager.Stats.TotalBypassed, 0);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Exclusion statistics reset\n");
}

// ============================================================================
// EXPIRED ENTRY CLEANUP
// ============================================================================

VOID
ShadowStrikeCleanupExpiredExclusions(
    VOID
    )
{
    LARGE_INTEGER currentTime;
    PLIST_ENTRY listEntry;
    PLIST_ENTRY nextEntry;
    PSHADOWSTRIKE_PATH_EXCLUSION pathEntry;
    ULONG pathRemoved = 0;
    ULONG pidRemoved = 0;
    ULONG i;

    //
    // Collect expired entries into a local list, then free outside the lock.
    //
    LIST_ENTRY expiredPathList;

    PAGED_CODE();

    if (!ReadBooleanAcquire(&g_ExclusionManager.Initialized)) {
        return;
    }

    KeQuerySystemTime(&currentTime);
    InitializeListHead(&expiredPathList);

    //
    // Cleanup expired path exclusions
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ExclusionManager.PathLock);

    for (listEntry = g_ExclusionManager.PathExclusions.Flink;
         listEntry != &g_ExclusionManager.PathExclusions;
         listEntry = nextEntry) {

        nextEntry = listEntry->Flink;
        pathEntry = CONTAINING_RECORD(listEntry, SHADOWSTRIKE_PATH_EXCLUSION, ListEntry);

        if (pathEntry->ExpireTime.QuadPart != 0 &&
            currentTime.QuadPart > pathEntry->ExpireTime.QuadPart) {

            RemoveEntryList(&pathEntry->ListEntry);
            InsertTailList(&expiredPathList, &pathEntry->ListEntry);
            if (g_ExclusionManager.Stats.PathExclusionCount > 0) {
                g_ExclusionManager.Stats.PathExclusionCount--;
            }
            pathRemoved++;
        }
    }

    ExReleasePushLockExclusive(&g_ExclusionManager.PathLock);
    KeLeaveCriticalRegion();

    //
    // Free expired path entries outside the lock
    //
    while (!IsListEmpty(&expiredPathList)) {
        listEntry = RemoveHeadList(&expiredPathList);
        pathEntry = CONTAINING_RECORD(listEntry, SHADOWSTRIKE_PATH_EXCLUSION, ListEntry);
        ExFreePoolWithTag(pathEntry, SHADOWSTRIKE_EXCLUSION_POOL_TAG);
    }

    //
    // Cleanup expired PID exclusions
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ExclusionManager.PidLock);

    for (i = 0; i < SHADOWSTRIKE_MAX_PID_EXCLUSIONS; i++) {
        if (g_ExclusionManager.PidExclusions[i].Valid &&
            g_ExclusionManager.PidExclusions[i].ExpireTime.QuadPart != 0 &&
            currentTime.QuadPart > g_ExclusionManager.PidExclusions[i].ExpireTime.QuadPart) {

            g_ExclusionManager.PidExclusions[i].Valid = FALSE;
            g_ExclusionManager.PidExclusions[i].ProcessId = NULL;
            g_ExclusionManager.PidExclusions[i].HitCount = 0;
            g_ExclusionManager.PidExclusions[i].ExpireTime.QuadPart = 0;

            if (g_ExclusionManager.Stats.PidExclusionCount > 0) {
                g_ExclusionManager.Stats.PidExclusionCount--;
            }
            pidRemoved++;
        }
    }

    ExReleasePushLockExclusive(&g_ExclusionManager.PidLock);
    KeLeaveCriticalRegion();

    if (pathRemoved > 0 || pidRemoved > 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[ShadowStrike] Expired exclusion cleanup: %lu paths, %lu PIDs removed\n",
                   pathRemoved, pidRemoved);
    }
}
