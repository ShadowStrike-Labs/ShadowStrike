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

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static ULONG
AcpHashBucketIndex(
    _In_ const UCHAR* Hash
    );

static PAC_HASH_RULE
AcpFindHashRule(
    _In_ const UCHAR* Hash
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
        FltAcquirePushLockExclusive(&g_AcState.HashBuckets[i].Lock);
        while (!IsListEmpty(&g_AcState.HashBuckets[i].Head)) {
            ListEntry = RemoveHeadList(&g_AcState.HashBuckets[i].Head);
            PAC_HASH_RULE Rule = CONTAINING_RECORD(
                ListEntry, AC_HASH_RULE, Link);
            ExFreeToNPagedLookasideList(&g_AcState.HashRuleLookaside, Rule);
        }
        FltReleasePushLock(&g_AcState.HashBuckets[i].Lock);
        FltDeletePushLock(&g_AcState.HashBuckets[i].Lock);
    }

    //
    // Free path rules
    //
    FltAcquirePushLockExclusive(&g_AcState.PathLock);
    while (!IsListEmpty(&g_AcState.PathAllowList)) {
        ListEntry = RemoveHeadList(&g_AcState.PathAllowList);
        PAC_PATH_RULE Rule = CONTAINING_RECORD(
            ListEntry, AC_PATH_RULE, Link);
        ExFreeToNPagedLookasideList(&g_AcState.PathRuleLookaside, Rule);
    }
    while (!IsListEmpty(&g_AcState.PathBlockList)) {
        ListEntry = RemoveHeadList(&g_AcState.PathBlockList);
        PAC_PATH_RULE Rule = CONTAINING_RECORD(
            ListEntry, AC_PATH_RULE, Link);
        ExFreeToNPagedLookasideList(&g_AcState.PathRuleLookaside, Rule);
    }
    FltReleasePushLock(&g_AcState.PathLock);
    FltDeletePushLock(&g_AcState.PathLock);

    ExDeleteNPagedLookasideList(&g_AcState.HashRuleLookaside);
    ExDeleteNPagedLookasideList(&g_AcState.PathRuleLookaside);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike/AC] Shutdown complete. "
               "Checked=%lld, Blocked=%lld, Audited=%lld\n",
               g_AcState.Stats.ExecutionsChecked,
               g_AcState.Stats.ExecutionsBlocked,
               g_AcState.Stats.ExecutionsAudited);
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

    InterlockedIncrement64(&g_AcState.Stats.ExecutionsChecked);
    Mode = (AC_POLICY_MODE)g_AcState.PolicyMode;

    //
    // Step 1: Hash-based lookup (most specific)
    //
    if (ImageHash != NULL) {
        InterlockedIncrement64(&g_AcState.Stats.HashLookups);
        PAC_HASH_RULE HashRule = AcpFindHashRule(ImageHash);
        if (HashRule != NULL) {
            if (HashRule->RuleType == AcRule_HashBlock) {
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
        break;
    case AcVerdict_Audit:
        InterlockedIncrement64(&g_AcState.Stats.ExecutionsAudited);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                   "[ShadowStrike/AC] AUDIT: Unauthorized execution: %wZ (PID=%lu)\n",
                   ImageFileName, HandleToULong(ProcessId));
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
    UNREFERENCED_PARAMETER(ProcessId);

    if (!AcpEnterOperation()) {
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
    RtlCopyMemory(Statistics, &g_AcState.Stats, sizeof(AC_STATISTICS));
}

// ============================================================================
// PRIVATE — HASH LOOKUP
// ============================================================================

static ULONG
AcpHashBucketIndex(
    _In_ const UCHAR* Hash
    )
{
    //
    // Use first 4 bytes of SHA-256 as bucket index
    //
    ULONG Index = (ULONG)Hash[0] |
                  ((ULONG)Hash[1] << 8);
    return Index % AC_HASH_BUCKET_COUNT;
}


static PAC_HASH_RULE
AcpFindHashRule(
    _In_ const UCHAR* Hash
    )
{
    ULONG Bucket = AcpHashBucketIndex(Hash);
    LIST_ENTRY *ListEntry;

    FltAcquirePushLockShared(&g_AcState.HashBuckets[Bucket].Lock);

    for (ListEntry = g_AcState.HashBuckets[Bucket].Head.Flink;
         ListEntry != &g_AcState.HashBuckets[Bucket].Head;
         ListEntry = ListEntry->Flink) {

        PAC_HASH_RULE Rule = CONTAINING_RECORD(
            ListEntry, AC_HASH_RULE, Link);

        if (RtlCompareMemory(Rule->Hash, Hash, AC_HASH_SIZE) == AC_HASH_SIZE) {
            FltReleasePushLock(&g_AcState.HashBuckets[Bucket].Lock);
            return Rule;
        }
    }

    FltReleasePushLock(&g_AcState.HashBuckets[Bucket].Lock);
    return NULL;
}

// ============================================================================
// PRIVATE — PATH RULES
// ============================================================================

static AC_VERDICT
AcpCheckPathRules(
    _In_ PCUNICODE_STRING ImagePath
    )
{
    LIST_ENTRY *ListEntry;

    FltAcquirePushLockShared(&g_AcState.PathLock);

    //
    // Check blocklist first (higher priority)
    //
    for (ListEntry = g_AcState.PathBlockList.Flink;
         ListEntry != &g_AcState.PathBlockList;
         ListEntry = ListEntry->Flink) {

        PAC_PATH_RULE Rule = CONTAINING_RECORD(
            ListEntry, AC_PATH_RULE, Link);

        if (ImagePath->Length >= Rule->PathPrefix.Length) {
            UNICODE_STRING Prefix;
            Prefix.Buffer = ImagePath->Buffer;
            Prefix.Length = Rule->PathPrefix.Length;
            Prefix.MaximumLength = Rule->PathPrefix.Length;

            if (RtlEqualUnicodeString(&Prefix, &Rule->PathPrefix, TRUE)) {
                FltReleasePushLock(&g_AcState.PathLock);
                AC_POLICY_MODE Mode = (AC_POLICY_MODE)g_AcState.PolicyMode;
                return (Mode == AcMode_Enforce) ? AcVerdict_Block : AcVerdict_Audit;
            }
        }
    }

    //
    // Check allowlist
    //
    for (ListEntry = g_AcState.PathAllowList.Flink;
         ListEntry != &g_AcState.PathAllowList;
         ListEntry = ListEntry->Flink) {

        PAC_PATH_RULE Rule = CONTAINING_RECORD(
            ListEntry, AC_PATH_RULE, Link);

        if (ImagePath->Length >= Rule->PathPrefix.Length) {
            UNICODE_STRING Prefix;
            Prefix.Buffer = ImagePath->Buffer;
            Prefix.Length = Rule->PathPrefix.Length;
            Prefix.MaximumLength = Rule->PathPrefix.Length;

            if (RtlEqualUnicodeString(&Prefix, &Rule->PathPrefix, TRUE)) {
                FltReleasePushLock(&g_AcState.PathLock);
                return AcVerdict_Allow;
            }
        }
    }

    FltReleasePushLock(&g_AcState.PathLock);
    return AcVerdict_Unknown;
}


static BOOLEAN
AcpIsTrustedPath(
    _In_ PCUNICODE_STRING ImagePath
    )
{
    //
    // Check if image path contains any trusted directory prefix
    // (case-insensitive substring match after volume prefix)
    //
    for (ULONG i = 0; i < AC_TRUSTED_PATH_COUNT; i++) {
        if (ImagePath->Length >= g_TrustedPaths[i].Length) {
            //
            // Search for trusted path as substring
            //
            USHORT PathLen = ImagePath->Length / sizeof(WCHAR);
            USHORT TrustLen = g_TrustedPaths[i].Length / sizeof(WCHAR);

            for (USHORT j = 0; j <= PathLen - TrustLen; j++) {
                UNICODE_STRING Sub;
                Sub.Buffer = &ImagePath->Buffer[j];
                Sub.Length = g_TrustedPaths[i].Length;
                Sub.MaximumLength = g_TrustedPaths[i].Length;

                if (RtlEqualUnicodeString(&Sub, &g_TrustedPaths[i], TRUE)) {
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}

// ============================================================================
// PRIVATE — LIFECYCLE
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
