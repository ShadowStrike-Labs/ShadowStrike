// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
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
===============================================================================
ShadowStrike NGAV - APPLICATION CONTROL IMPLEMENTATION
===============================================================================

@file AppControl.c
@brief Zero-trust execution model enforcement engine.

Application control operates in three modes:
  - Audit: logs unauthorized execution but does not block
  - Enforce: blocks unauthorized executables
  - Learning: auto-populates allowlist from observed executions

Default configuration starts in Audit mode for safe deployment.
Policies are managed via user-space service IOCTL commands.

@author ShadowStrike Security Team
@version 1.0.0
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#include "AppControl.h"
#include "../../Core/Globals.h"
#include "../../Behavioral/BehaviorEngine.h"
#include "../../Exclusions/ExclusionManager.h"
#include <ntstrsafe.h>

// ============================================================================
// PRIVATE TYPES
// ============================================================================

typedef struct _AC_STATE {

    volatile LONG       State;
    EX_RUNDOWN_REF      RundownRef;

    //
    // Hash rule table
    //
    struct {
        LIST_ENTRY      Head;
        EX_PUSH_LOCK    Lock;
    } HashBuckets[AC_HASH_BUCKET_COUNT];
    volatile LONG       HashRuleCount;

    //
    // Path rules
    //
    LIST_ENTRY          PathAllowList;
    LIST_ENTRY          PathBlockList;
    EX_PUSH_LOCK        PathLock;
    volatile LONG       PathRuleCount;

    //
    // Policy mode
    //
    volatile LONG       PolicyMode;     // AC_POLICY_MODE

    //
    // Statistics
    //
    AC_STATISTICS       Stats;

    //
    // Allocation
    //
    NPAGED_LOOKASIDE_LIST HashRuleLookaside;
    NPAGED_LOOKASIDE_LIST PathRuleLookaside;

} AC_STATE, *PAC_STATE;

// ============================================================================
// GLOBAL STATE
// ============================================================================

static AC_STATE g_AcState;

// ============================================================================
// TRUSTED PATH PREFIXES (built-in allowlist)
// ============================================================================

static const UNICODE_STRING g_TrustedPaths[] = {
    RTL_CONSTANT_STRING(L"\\Windows\\"),
    RTL_CONSTANT_STRING(L"\\Windows\\System32\\"),
    RTL_CONSTANT_STRING(L"\\Windows\\SysWOW64\\"),
    RTL_CONSTANT_STRING(L"\\Program Files\\"),
    RTL_CONSTANT_STRING(L"\\Program Files (x86)\\"),
};

#define AC_TRUSTED_PATH_COUNT \
    (sizeof(g_TrustedPaths) / sizeof(g_TrustedPaths[0]))

static const UNICODE_STRING g_SystemRootPrefix =
    RTL_CONSTANT_STRING(L"\\SystemRoot\\");

static const UNICODE_STRING g_DevicePrefix =
    RTL_CONSTANT_STRING(L"\\Device\\");

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static ULONG
AcpHashBucketIndex(
    _In_ const UCHAR* Hash
    );

static BOOLEAN
AcpFindHashRule(
    _In_ const UCHAR* Hash,
    _Out_ AC_RULE_TYPE* FoundRuleType
    );

static AC_VERDICT
AcpCheckPathRules(
    _In_ PCUNICODE_STRING ImagePath
    );

static BOOLEAN
AcpIsTrustedPath(
    _In_ PCUNICODE_STRING ImagePath
    );

static BOOLEAN
AcpEnterOperation(VOID);

static VOID
AcpLeaveOperation(VOID);

static VOID
AcpLearnHashRule(
    _In_ const UCHAR* Hash
    );

// ============================================================================
// SECTION ASSIGNMENTS
// ============================================================================

#pragma alloc_text(PAGE, AcInitialize)
#pragma alloc_text(PAGE, AcShutdown)
#pragma alloc_text(PAGE, AcCheckProcessExecution)
#pragma alloc_text(PAGE, AcCheckImageLoad)
#pragma alloc_text(PAGE, AcpHashBucketIndex)
#pragma alloc_text(PAGE, AcpFindHashRule)
#pragma alloc_text(PAGE, AcpCheckPathRules)
#pragma alloc_text(PAGE, AcpIsTrustedPath)
#pragma alloc_text(PAGE, AcpLearnHashRule)

// ============================================================================
// LIFECYCLE
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
AcInitialize(VOID)
{
    LONG Previous;

    PAGED_CODE();

    Previous = InterlockedCompareExchange(&g_AcState.State, 1, 0);
    if (Previous != 0) {
        return (Previous == 2) ? STATUS_SUCCESS : STATUS_DEVICE_BUSY;
    }

    ExInitializeRundownProtection(&g_AcState.RundownRef);

    for (ULONG i = 0; i < AC_HASH_BUCKET_COUNT; i++) {
        InitializeListHead(&g_AcState.HashBuckets[i].Head);
        FltInitializePushLock(&g_AcState.HashBuckets[i].Lock);
    }
    g_AcState.HashRuleCount = 0;

    InitializeListHead(&g_AcState.PathAllowList);
    InitializeListHead(&g_AcState.PathBlockList);
    FltInitializePushLock(&g_AcState.PathLock);
    g_AcState.PathRuleCount = 0;

    //
    // Default: Audit mode (safe for initial deployment)
    // Enforce mode requires a populated allowlist/blocklist database.
    //
    g_AcState.PolicyMode = AcMode_Audit;

    ExInitializeNPagedLookasideList(
        &g_AcState.HashRuleLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(AC_HASH_RULE),
        AC_RULE_POOL_TAG,
        0
        );

    ExInitializeNPagedLookasideList(
        &g_AcState.PathRuleLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(AC_PATH_RULE),
        AC_RULE_POOL_TAG,
        0
        );

    RtlZeroMemory(&g_AcState.Stats, sizeof(AC_STATISTICS));

    InterlockedExchange(&g_AcState.State, 2);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/AC] Application Control initialized (Mode=Audit)\n");

    return STATUS_SUCCESS;
}


_IRQL_requires_(PASSIVE_LEVEL)
VOID
AcShutdown(VOID)
{
    LIST_ENTRY *ListEntry;

    PAGED_CODE();

    if (InterlockedCompareExchange(&g_AcState.State, 3, 2) != 2) {
        return;
    }

    ExWaitForRundownProtectionRelease(&g_AcState.RundownRef);

    //
    // Free hash rules
    //
    for (ULONG i = 0; i < AC_HASH_BUCKET_COUNT; i++) {
        ULONG Freed = 0;
        FltAcquirePushLockExclusive(&g_AcState.HashBuckets[i].Lock);
        while (!IsListEmpty(&g_AcState.HashBuckets[i].Head) &&
               Freed < AC_MAX_HASH_RULES) {
            ListEntry = RemoveHeadList(&g_AcState.HashBuckets[i].Head);
            PAC_HASH_RULE Rule = CONTAINING_RECORD(
                ListEntry, AC_HASH_RULE, Link);
            ExFreeToNPagedLookasideList(&g_AcState.HashRuleLookaside, Rule);
            Freed++;
        }
        FltReleasePushLock(&g_AcState.HashBuckets[i].Lock);
        FltDeletePushLock(&g_AcState.HashBuckets[i].Lock);
    }

    //
    // Free path rules
    //
    {
        ULONG Freed = 0;
        FltAcquirePushLockExclusive(&g_AcState.PathLock);
        while (!IsListEmpty(&g_AcState.PathAllowList) &&
               Freed < AC_MAX_PATH_RULES) {
            ListEntry = RemoveHeadList(&g_AcState.PathAllowList);
            PAC_PATH_RULE Rule = CONTAINING_RECORD(
                ListEntry, AC_PATH_RULE, Link);
            ExFreeToNPagedLookasideList(&g_AcState.PathRuleLookaside, Rule);
            Freed++;
        }
        Freed = 0;
        while (!IsListEmpty(&g_AcState.PathBlockList) &&
               Freed < AC_MAX_PATH_RULES) {
            ListEntry = RemoveHeadList(&g_AcState.PathBlockList);
            PAC_PATH_RULE Rule = CONTAINING_RECORD(
                ListEntry, AC_PATH_RULE, Link);
            ExFreeToNPagedLookasideList(&g_AcState.PathRuleLookaside, Rule);
            Freed++;
        }
    }
    FltReleasePushLock(&g_AcState.PathLock);
    FltDeletePushLock(&g_AcState.PathLock);

    ExDeleteNPagedLookasideList(&g_AcState.HashRuleLookaside);
    ExDeleteNPagedLookasideList(&g_AcState.PathRuleLookaside);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/AC] Shutdown complete. "
               "Checked=%lld, Blocked=%lld, Audited=%lld\n",
               ReadNoFence64(&g_AcState.Stats.ExecutionsChecked),
               ReadNoFence64(&g_AcState.Stats.ExecutionsBlocked),
               ReadNoFence64(&g_AcState.Stats.ExecutionsAudited));
}

// ============================================================================
// EXECUTION CHECKS
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
AC_VERDICT
AcCheckProcessExecution(
    _In_ PCUNICODE_STRING ImageFileName,
    _In_opt_ const UCHAR* ImageHash,
    _In_ HANDLE ProcessId,
    _In_ HANDLE ParentProcessId
    )
{
    AC_VERDICT Verdict = AcVerdict_Unknown;
    AC_POLICY_MODE Mode;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ParentProcessId);

    if (!AcpEnterOperation()) {
        return AcVerdict_Allow;
    }

    //
    // Exclusion check â€” exempt excluded processes from app control policy.
    // Excluded processes are typically trusted management tools that must
    // never be blocked by allowlisting policies.
    //
    if (ShadowStrikeIsProcessExcluded(ProcessId, NULL) ||
        ShadowStrikeIsPathExcluded(ImageFileName, NULL)) {
        AcpLeaveOperation();
        return AcVerdict_Allow;
    }

    InterlockedIncrement64(&g_AcState.Stats.ExecutionsChecked);
    Mode = (AC_POLICY_MODE)g_AcState.PolicyMode;

    //
    // Step 1: Hash-based lookup (most specific)
    //
    if (ImageHash != NULL) {
        AC_RULE_TYPE HashRuleType;
        InterlockedIncrement64(&g_AcState.Stats.HashLookups);
        if (AcpFindHashRule(ImageHash, &HashRuleType)) {
            if (HashRuleType == AcRule_HashBlock) {
                Verdict = (Mode == AcMode_Enforce) ? AcVerdict_Block : AcVerdict_Audit;
            } else {
                Verdict = AcVerdict_Allow;
            }
        }
    }

    //
    // Step 2: Path-based rules (if hash didn't match)
    //
    if (Verdict == AcVerdict_Unknown) {
        InterlockedIncrement64(&g_AcState.Stats.PathLookups);
        Verdict = AcpCheckPathRules(ImageFileName);
    }

    //
    // Step 3: Built-in trusted paths (if no explicit rule)
    //
    if (Verdict == AcVerdict_Unknown) {
        if (AcpIsTrustedPath(ImageFileName)) {
            Verdict = AcVerdict_Allow;
        }
    }

    //
    // Step 4: Apply default policy
    //
    if (Verdict == AcVerdict_Unknown) {
        switch (Mode) {
        case AcMode_Enforce:
            Verdict = AcVerdict_Block;
            break;
        case AcMode_Audit:
            Verdict = AcVerdict_Audit;
            break;
        case AcMode_Learning:
            Verdict = AcVerdict_Allow;
            //
            // Auto-learn: add hash-allow rule for observed executable.
            // Only learns when a hash is available (caller computed it).
            //
            if (ImageHash != NULL) {
                AcpLearnHashRule(ImageHash);
            }
            InterlockedIncrement64(&g_AcState.Stats.RulesLearned);
            break;
        }
    }

    //
    // Update statistics
    //
    switch (Verdict) {
    case AcVerdict_Allow:
        InterlockedIncrement64(&g_AcState.Stats.ExecutionsAllowed);
        break;
    case AcVerdict_Block:
        InterlockedIncrement64(&g_AcState.Stats.ExecutionsBlocked);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike/AC] BLOCKED execution: %wZ (PID=%lu)\n",
                   ImageFileName, HandleToULong(ProcessId));

        BeEngineSubmitEvent(
            BehaviorEvent_AppControlBlocked,
            BehaviorCategory_ProcessExecution,
            HandleToULong(ProcessId),
            ImageFileName->Buffer,
            (ImageFileName->Length < 512) ? ImageFileName->Length : 512,
            90,     // High suspicion â€” actively blocked
            FALSE,
            NULL
        );
        break;
    case AcVerdict_Audit:
        InterlockedIncrement64(&g_AcState.Stats.ExecutionsAudited);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                   "[ShadowStrike/AC] AUDIT: Unauthorized execution: %wZ (PID=%lu)\n",
                   ImageFileName, HandleToULong(ProcessId));

        BeEngineSubmitEvent(
            BehaviorEvent_AppControlAudited,
            BehaviorCategory_ProcessExecution,
            HandleToULong(ProcessId),
            ImageFileName->Buffer,
            (ImageFileName->Length < 512) ? ImageFileName->Length : 512,
            40,     // Medium suspicion â€” audit only
            FALSE,
            NULL
        );
        break;
    default:
        break;
    }

    AcpLeaveOperation();
    return Verdict;
}


_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
AC_VERDICT
AcCheckImageLoad(
    _In_ PCUNICODE_STRING ImageFileName,
    _In_ HANDLE ProcessId
    )
{
    AC_VERDICT Verdict;

    PAGED_CODE();

    if (!AcpEnterOperation()) {
        return AcVerdict_Allow;
    }

    //
    // Exclusion check â€” exempt excluded processes from DLL load control
    //
    if (ShadowStrikeIsProcessExcluded(ProcessId, NULL) ||
        ShadowStrikeIsPathExcluded(ImageFileName, NULL)) {
        AcpLeaveOperation();
        return AcVerdict_Allow;
    }

    InterlockedIncrement64(&g_AcState.Stats.ImagesChecked);

    //
    // For DLL loads, use path-based rules only (hash verification is expensive)
    //
    Verdict = AcpCheckPathRules(ImageFileName);

    if (Verdict == AcVerdict_Unknown) {
        if (AcpIsTrustedPath(ImageFileName)) {
            Verdict = AcVerdict_Allow;
        } else {
            AC_POLICY_MODE Mode = (AC_POLICY_MODE)g_AcState.PolicyMode;
            Verdict = (Mode == AcMode_Enforce) ? AcVerdict_Block : AcVerdict_Allow;
        }
    }

    if (Verdict == AcVerdict_Block) {
        InterlockedIncrement64(&g_AcState.Stats.ImagesBlocked);
    }

    AcpLeaveOperation();
    return Verdict;
}

// ============================================================================
// QUERY
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
AcGetStatistics(
    _Out_ PAC_STATISTICS Statistics
    )
{
    Statistics->ExecutionsChecked = ReadNoFence64(&g_AcState.Stats.ExecutionsChecked);
    Statistics->ExecutionsAllowed = ReadNoFence64(&g_AcState.Stats.ExecutionsAllowed);
    Statistics->ExecutionsBlocked = ReadNoFence64(&g_AcState.Stats.ExecutionsBlocked);
    Statistics->ExecutionsAudited = ReadNoFence64(&g_AcState.Stats.ExecutionsAudited);
    Statistics->ImagesChecked = ReadNoFence64(&g_AcState.Stats.ImagesChecked);
    Statistics->ImagesBlocked = ReadNoFence64(&g_AcState.Stats.ImagesBlocked);
    Statistics->RulesLearned = ReadNoFence64(&g_AcState.Stats.RulesLearned);
    Statistics->HashLookups = ReadNoFence64(&g_AcState.Stats.HashLookups);
    Statistics->PathLookups = ReadNoFence64(&g_AcState.Stats.PathLookups);
}

// ============================================================================
// PRIVATE â€” HASH LOOKUP
// ============================================================================

static ULONG
AcpHashBucketIndex(
    _In_ const UCHAR* Hash
    )
{
    PAGED_CODE();

    //
    // XOR-fold first 4 bytes of SHA-256 for uniform bucket distribution.
    // Previous: (Hash[0]|(Hash[1]<<8)) % 256 always reduced to Hash[0].
    //
    ULONG Index = (ULONG)(Hash[0] ^ Hash[1] ^ Hash[2] ^ Hash[3]);
    return Index % AC_HASH_BUCKET_COUNT;
}


static BOOLEAN
AcpFindHashRule(
    _In_ const UCHAR* Hash,
    _Out_ AC_RULE_TYPE* FoundRuleType
    )
{
    ULONG Bucket = AcpHashBucketIndex(Hash);
    LIST_ENTRY *ListEntry;
    ULONG WalkCount = 0;
    BOOLEAN Found = FALSE;

    PAGED_CODE();

    FltAcquirePushLockShared(&g_AcState.HashBuckets[Bucket].Lock);

    for (ListEntry = g_AcState.HashBuckets[Bucket].Head.Flink;
         ListEntry != &g_AcState.HashBuckets[Bucket].Head &&
         WalkCount < AC_MAX_BUCKET_WALK;
         ListEntry = ListEntry->Flink, WalkCount++) {

        PAC_HASH_RULE Rule = CONTAINING_RECORD(
            ListEntry, AC_HASH_RULE, Link);

        if (RtlCompareMemory(Rule->Hash, Hash, AC_HASH_SIZE) == AC_HASH_SIZE) {
            *FoundRuleType = Rule->RuleType;
            Found = TRUE;
            break;
        }
    }

    FltReleasePushLock(&g_AcState.HashBuckets[Bucket].Lock);
    return Found;
}

// ============================================================================
// PRIVATE â€” PATH RULES
// ============================================================================

static AC_VERDICT
AcpCheckPathRules(
    _In_ PCUNICODE_STRING ImagePath
    )
{
    LIST_ENTRY *ListEntry;
    ULONG WalkCount;
    AC_VERDICT Verdict = AcVerdict_Unknown;

    PAGED_CODE();

    FltAcquirePushLockShared(&g_AcState.PathLock);

    //
    // Check blocklist first (higher priority)
    //
    WalkCount = 0;
    for (ListEntry = g_AcState.PathBlockList.Flink;
         ListEntry != &g_AcState.PathBlockList &&
         WalkCount < AC_MAX_PATH_WALK;
         ListEntry = ListEntry->Flink, WalkCount++) {

        PAC_PATH_RULE Rule = CONTAINING_RECORD(
            ListEntry, AC_PATH_RULE, Link);

        if (ImagePath->Length >= Rule->PathPrefix.Length) {
            UNICODE_STRING Prefix;
            Prefix.Buffer = ImagePath->Buffer;
            Prefix.Length = Rule->PathPrefix.Length;
            Prefix.MaximumLength = Rule->PathPrefix.Length;

            if (RtlEqualUnicodeString(&Prefix, &Rule->PathPrefix, TRUE)) {
                AC_POLICY_MODE Mode = (AC_POLICY_MODE)g_AcState.PolicyMode;
                Verdict = (Mode == AcMode_Enforce) ? AcVerdict_Block : AcVerdict_Audit;
                break;
            }
        }
    }

    //
    // Check allowlist (only if blocklist didn't match)
    //
    if (Verdict == AcVerdict_Unknown) {
        WalkCount = 0;
        for (ListEntry = g_AcState.PathAllowList.Flink;
             ListEntry != &g_AcState.PathAllowList &&
             WalkCount < AC_MAX_PATH_WALK;
             ListEntry = ListEntry->Flink, WalkCount++) {

            PAC_PATH_RULE Rule = CONTAINING_RECORD(
                ListEntry, AC_PATH_RULE, Link);

            if (ImagePath->Length >= Rule->PathPrefix.Length) {
                UNICODE_STRING Prefix;
                Prefix.Buffer = ImagePath->Buffer;
                Prefix.Length = Rule->PathPrefix.Length;
                Prefix.MaximumLength = Rule->PathPrefix.Length;

                if (RtlEqualUnicodeString(&Prefix, &Rule->PathPrefix, TRUE)) {
                    Verdict = AcVerdict_Allow;
                    break;
                }
            }
        }
    }

    FltReleasePushLock(&g_AcState.PathLock);
    return Verdict;
}


static BOOLEAN
AcpIsTrustedPath(
    _In_ PCUNICODE_STRING ImagePath
    )
{
    USHORT LenChars;
    USHORT RootOffset = MAXUSHORT;
    USHORT RemainingBytes;

    PAGED_CODE();

    if (ImagePath == NULL || ImagePath->Buffer == NULL ||
        ImagePath->Length < 8) {
        return FALSE;
    }

    LenChars = ImagePath->Length / sizeof(WCHAR);

    //
    // \SystemRoot\ paths are inherently trusted (always maps to %SystemRoot%)
    //
    if (ImagePath->Length >= g_SystemRootPrefix.Length) {
        UNICODE_STRING Sub;
        Sub.Buffer = ImagePath->Buffer;
        Sub.Length = g_SystemRootPrefix.Length;
        Sub.MaximumLength = g_SystemRootPrefix.Length;
        if (RtlEqualUnicodeString(&Sub, &g_SystemRootPrefix, TRUE)) {
            return TRUE;
        }
    }

    //
    // \??\X:\ â€” DOS device path, root starts after drive letter colon
    //
    if (LenChars > 6 &&
        ImagePath->Buffer[0] == L'\\' &&
        ImagePath->Buffer[1] == L'?' &&
        ImagePath->Buffer[2] == L'?' &&
        ImagePath->Buffer[3] == L'\\' &&
        ImagePath->Buffer[5] == L':' &&
        ImagePath->Buffer[6] == L'\\') {
        RootOffset = 6;
    }

    //
    // \Device\<name>\ â€” NT device path, find backslash after device name.
    // Cap scan at 80 chars to prevent runaway on malformed paths.
    //
    if (RootOffset == MAXUSHORT && LenChars > 9) {
        if (ImagePath->Length >= g_DevicePrefix.Length) {
            UNICODE_STRING Sub;
            Sub.Buffer = ImagePath->Buffer;
            Sub.Length = g_DevicePrefix.Length;
            Sub.MaximumLength = g_DevicePrefix.Length;
            if (RtlEqualUnicodeString(&Sub, &g_DevicePrefix, TRUE)) {
                USHORT ScanLimit = (LenChars < 80) ? LenChars : 80;
                for (USHORT i = 8; i < ScanLimit; i++) {
                    if (ImagePath->Buffer[i] == L'\\') {
                        RootOffset = i;
                        break;
                    }
                }
            }
        }
    }

    if (RootOffset == MAXUSHORT || RootOffset >= LenChars) {
        return FALSE;
    }

    //
    // Check if the root-relative portion starts with a trusted directory
    //
    RemainingBytes = (USHORT)((LenChars - RootOffset) * sizeof(WCHAR));
    for (ULONG i = 0; i < AC_TRUSTED_PATH_COUNT; i++) {
        if (RemainingBytes >= g_TrustedPaths[i].Length) {
            UNICODE_STRING Sub;
            Sub.Buffer = &ImagePath->Buffer[RootOffset];
            Sub.Length = g_TrustedPaths[i].Length;
            Sub.MaximumLength = g_TrustedPaths[i].Length;

            if (RtlEqualUnicodeString(&Sub, &g_TrustedPaths[i], TRUE)) {
                return TRUE;
            }
        }
    }

    return FALSE;
}

// ============================================================================
// PRIVATE â€” LEARNING MODE
// ============================================================================

static VOID
AcpLearnHashRule(
    _In_ const UCHAR* Hash
    )
{
    ULONG Bucket;
    PAC_HASH_RULE NewRule;
    LIST_ENTRY *ListEntry;
    ULONG WalkCount = 0;

    PAGED_CODE();

    //
    // Cap total hash rules to prevent unbounded growth during learning
    //
    if ((ULONG)g_AcState.HashRuleCount >= AC_MAX_HASH_RULES) {
        return;
    }

    Bucket = AcpHashBucketIndex(Hash);

    //
    // Check if hash already exists (avoid duplicates)
    //
    FltAcquirePushLockShared(&g_AcState.HashBuckets[Bucket].Lock);
    for (ListEntry = g_AcState.HashBuckets[Bucket].Head.Flink;
         ListEntry != &g_AcState.HashBuckets[Bucket].Head &&
         WalkCount < AC_MAX_BUCKET_WALK;
         ListEntry = ListEntry->Flink, WalkCount++) {

        PAC_HASH_RULE Existing = CONTAINING_RECORD(
            ListEntry, AC_HASH_RULE, Link);
        if (RtlCompareMemory(Existing->Hash, Hash, AC_HASH_SIZE) == AC_HASH_SIZE) {
            FltReleasePushLock(&g_AcState.HashBuckets[Bucket].Lock);
            return;  // Already known
        }
    }
    FltReleasePushLock(&g_AcState.HashBuckets[Bucket].Lock);

    //
    // Allocate and insert new allow rule
    //
    NewRule = (PAC_HASH_RULE)ExAllocateFromNPagedLookasideList(
        &g_AcState.HashRuleLookaside);
    if (NewRule == NULL) {
        return;
    }

    RtlZeroMemory(NewRule, sizeof(AC_HASH_RULE));
    NewRule->RuleType = AcRule_HashAllow;
    RtlCopyMemory(NewRule->Hash, Hash, AC_HASH_SIZE);
    NewRule->RuleId = (ULONG)InterlockedIncrement(&g_AcState.HashRuleCount);
    KeQuerySystemTimePrecise(&NewRule->CreatedTime);

    FltAcquirePushLockExclusive(&g_AcState.HashBuckets[Bucket].Lock);
    InsertTailList(&g_AcState.HashBuckets[Bucket].Head, &NewRule->Link);
    FltReleasePushLock(&g_AcState.HashBuckets[Bucket].Lock);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[ShadowStrike/AC] LEARNED: Added hash-allow rule #%lu (bucket=%lu)\n",
               NewRule->RuleId, Bucket);
}

// ============================================================================
// PRIVATE â€” LIFECYCLE
// ============================================================================

static BOOLEAN
AcpEnterOperation(VOID)
{
    if (g_AcState.State != 2) return FALSE;
    return ExAcquireRundownProtection(&g_AcState.RundownRef);
}

static VOID
AcpLeaveOperation(VOID)
{
    ExReleaseRundownProtection(&g_AcState.RundownRef);
}
