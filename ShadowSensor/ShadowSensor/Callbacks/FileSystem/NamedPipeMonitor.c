/**
 * ============================================================================
 * ShadowStrike NGAV - NAMED PIPE MONITORING IMPLEMENTATION
 * ============================================================================
 *
 * @file NamedPipeMonitor.c
 * @brief Enterprise-grade Named Pipe monitoring for lateral movement
 *        and C2 communication detection.
 *
 * Implementation Strategy:
 * ========================
 * 1. IRP_MJ_CREATE_NAMED_PIPE pre-callback classifies pipe name
 * 2. Known C2 patterns matched via static table (compile-time offsets)
 * 3. Unknown pipes analyzed for Shannon entropy (randomized C2 names)
 * 4. Tracked entries stored in per-bucket push-locked hash table
 * 5. Events queued for user-mode delivery via spin-locked FIFO
 * 6. LRU eviction prevents unbounded memory growth
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "NamedPipeMonitor.h"
#include "../../Core/Globals.h"
#include "../../Shared/SharedDefs.h"
#include "../../Shared/BehaviorTypes.h"
#include <ntstrsafe.h>

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

//
// Named pipe device prefix: \Device\NamedPipe\ 
//
static const WCHAR NpmDevicePrefix[] = L"\\Device\\NamedPipe\\";
static const USHORT NpmDevicePrefixLen = sizeof(NpmDevicePrefix) - sizeof(WCHAR);

// ============================================================================
// KNOWN C2 PIPE PATTERNS
// ============================================================================

/**
 * @brief Known malicious pipe name pattern entry.
 *
 * MatchType: 0 = exact, 1 = prefix, 2 = contains
 */
typedef struct _NPM_KNOWN_PATTERN {
    PCWSTR Pattern;
    USHORT PatternLengthBytes;      // Excluding null
    UCHAR MatchType;                // 0=exact, 1=prefix, 2=contains
    NPM_PIPE_CLASS Classification;
    ULONG BaseThreatScore;
} NPM_KNOWN_PATTERN, *PNPM_KNOWN_PATTERN;

//
// CobaltStrike default pipe name patterns
//
static const NPM_KNOWN_PATTERN g_KnownC2Patterns[] = {
    // CobaltStrike SMB beacon defaults
    { L"MSSE-",         sizeof(L"MSSE-") - sizeof(WCHAR),         1, NpmClass_C2_CobaltStrike, 90 },
    { L"msagent_",      sizeof(L"msagent_") - sizeof(WCHAR),      1, NpmClass_C2_CobaltStrike, 90 },
    { L"postex_",       sizeof(L"postex_") - sizeof(WCHAR),       1, NpmClass_C2_CobaltStrike, 95 },
    { L"postex_ssh_",   sizeof(L"postex_ssh_") - sizeof(WCHAR),   1, NpmClass_C2_CobaltStrike, 95 },
    { L"status_",       sizeof(L"status_") - sizeof(WCHAR),       1, NpmClass_C2_CobaltStrike, 85 },
    { L"\\interprocess_", sizeof(L"\\interprocess_") - sizeof(WCHAR), 2, NpmClass_C2_CobaltStrike, 80 },

    // PsExec
    { L"PSEXESVC",      sizeof(L"PSEXESVC") - sizeof(WCHAR),      0, NpmClass_C2_PsExec, 70 },
    { L"psexesvc",      sizeof(L"psexesvc") - sizeof(WCHAR),      0, NpmClass_C2_PsExec, 70 },
    { L"PSEXECSVC",     sizeof(L"PSEXECSVC") - sizeof(WCHAR),     0, NpmClass_C2_PsExec, 70 },
    { L"csexec",        sizeof(L"csexec") - sizeof(WCHAR),        1, NpmClass_C2_PsExec, 65 },
    { L"PAExec",        sizeof(L"PAExec") - sizeof(WCHAR),        1, NpmClass_C2_PsExec, 65 },
    { L"remcom",        sizeof(L"remcom") - sizeof(WCHAR),        1, NpmClass_C2_PsExec, 60 },

    // Meterpreter
    { L"meterpreter",   sizeof(L"meterpreter") - sizeof(WCHAR),   1, NpmClass_C2_Meterpreter, 95 },

    // Impacket / WMIExec / SMBExec
    { L"__output",      sizeof(L"__output") - sizeof(WCHAR),      1, NpmClass_C2_Impacket, 75 },
    { L"RemCom_comm",   sizeof(L"RemCom_comm") - sizeof(WCHAR),   1, NpmClass_C2_Impacket, 70 },

    // Covenant / Sliver / Other C2 frameworks
    { L"gruntsvc",      sizeof(L"gruntsvc") - sizeof(WCHAR),      1, NpmClass_C2_Generic, 85 },
    { L"dceservice",    sizeof(L"dceservice") - sizeof(WCHAR),     1, NpmClass_C2_Generic, 80 },

    // Generic suspicious patterns
    { L"\\evil",        sizeof(L"\\evil") - sizeof(WCHAR),         2, NpmClass_Suspicious, 60 },
    { L"\\shell",       sizeof(L"\\shell") - sizeof(WCHAR),        2, NpmClass_Suspicious, 50 },
};

// ============================================================================
// KNOWN SYSTEM / LEGITIMATE PIPES (whitelist — reduce false positives)
// ============================================================================

static const PCWSTR g_SystemPipes[] = {
    L"lsass",
    L"ntsvcs",
    L"scerpc",
    L"browser",
    L"wkssvc",
    L"srvsvc",
    L"winreg",
    L"samr",
    L"netlogon",
    L"svcctl",
    L"epmapper",
    L"spoolss",
    L"DAV RPC SERVICE",
    L"atsvc",
    L"eventlog",
    L"InitShutdown",
    L"lsarpc",
    L"protected_storage",
    L"MsFteWds",
    L"msfte",
};

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

typedef struct _NPM_HASH_BUCKET {
    LIST_ENTRY List;
    EX_PUSH_LOCK Lock;
    volatile LONG Count;
} NPM_HASH_BUCKET, *PNPM_HASH_BUCKET;

typedef struct _NPM_MONITOR_STATE {
    //
    // Lifecycle
    //
    volatile LONG State;
    EX_RUNDOWN_REF RundownRef;

    //
    // Hash table for tracked pipes
    //
    NPM_HASH_BUCKET HashTable[NPM_HASH_TABLE_SIZE];
    volatile LONG TotalEntries;

    //
    // LRU eviction
    //
    LIST_ENTRY LruList;
    EX_PUSH_LOCK LruLock;

    //
    // Event queue (for user-mode delivery)
    //
    LIST_ENTRY EventQueue;
    KSPIN_LOCK EventLock;
    volatile LONG EventCount;

    //
    // Lookaside lists
    //
    NPAGED_LOOKASIDE_LIST EntryLookaside;
    NPAGED_LOOKASIDE_LIST EventLookaside;
    BOOLEAN LookasideInitialized;

    //
    // Rate limiting
    //
    LARGE_INTEGER RateWindowStart;
    volatile LONG RateWindowCount;

    //
    // Statistics
    //
    NPM_STATISTICS Stats;

} NPM_MONITOR_STATE, *PNPM_MONITOR_STATE;

static NPM_MONITOR_STATE g_NpmState;

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static ULONG
NpmHashPipeName(
    _In_ PCWSTR PipeName,
    _In_ USHORT NameLengthBytes
    );

static NPM_PIPE_CLASS
NpmClassifyPipe(
    _In_ PCWSTR PipeName,
    _In_ USHORT NameLengthBytes,
    _Out_ PULONG ThreatScore
    );

static BOOLEAN
NpmIsSystemPipe(
    _In_ PCWSTR PipeName,
    _In_ USHORT NameLengthChars
    );

static float
NpmCalculateEntropy(
    _In_ PCWSTR String,
    _In_ USHORT LengthChars
    );

static PNPM_PIPE_ENTRY
NpmAllocateEntry(
    VOID
    );

static VOID
NpmFreeEntry(
    _In_ PNPM_PIPE_ENTRY Entry
    );

static NTSTATUS
NpmTrackPipe(
    _In_ PCWSTR PipeName,
    _In_ USHORT NameLengthBytes,
    _In_ HANDLE CreatorPid,
    _In_ NPM_PIPE_CLASS Classification,
    _In_ ULONG ThreatScore
    );

static NTSTATUS
NpmQueueEvent(
    _In_ PCWSTR PipeName,
    _In_ USHORT NameLengthBytes,
    _In_ HANDLE CreatorPid,
    _In_opt_ HANDLE ConnectorPid,
    _In_ NPM_PIPE_CLASS Classification,
    _In_ NPM_THREAT_LEVEL ThreatLevel,
    _In_ ULONG ThreatScore,
    _In_ BOOLEAN WasBlocked,
    _In_ BOOLEAN IsCreation
    );

static BOOLEAN
NpmCheckRateLimit(
    VOID
    );

static VOID
NpmEvictLruEntries(
    _In_ ULONG Count
    );

static BOOLEAN
NpmExtractPipeName(
    _In_ PFLT_CALLBACK_DATA Data,
    _Out_writes_(NPM_MAX_PIPE_NAME_CCH) PWCHAR NameBuffer,
    _Out_ PUSHORT NameLengthBytes
    );

// ============================================================================
// LIFECYCLE
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
NpMonInitialize(
    VOID
    )
{
    LONG prevState;

    prevState = InterlockedCompareExchange(
        &g_NpmState.State,
        NPM_STATE_INITIALIZING,
        NPM_STATE_UNINITIALIZED
    );

    if (prevState != NPM_STATE_UNINITIALIZED) {
        return STATUS_ALREADY_INITIALIZED;
    }

    RtlZeroMemory(&g_NpmState.Stats, sizeof(NPM_STATISTICS));

    //
    // Initialize hash table
    //
    for (ULONG i = 0; i < NPM_HASH_TABLE_SIZE; i++) {
        InitializeListHead(&g_NpmState.HashTable[i].List);
        ExInitializePushLock(&g_NpmState.HashTable[i].Lock);
        g_NpmState.HashTable[i].Count = 0;
    }

    //
    // Initialize LRU list
    //
    InitializeListHead(&g_NpmState.LruList);
    ExInitializePushLock(&g_NpmState.LruLock);

    //
    // Initialize event queue
    //
    InitializeListHead(&g_NpmState.EventQueue);
    KeInitializeSpinLock(&g_NpmState.EventLock);
    g_NpmState.EventCount = 0;

    //
    // Initialize lookaside lists
    //
    ExInitializeNPagedLookasideList(
        &g_NpmState.EntryLookaside,
        NULL, NULL,
        POOL_NX_ALLOCATION,
        sizeof(NPM_PIPE_ENTRY),
        NPM_POOL_TAG_ENTRY,
        0
    );

    ExInitializeNPagedLookasideList(
        &g_NpmState.EventLookaside,
        NULL, NULL,
        POOL_NX_ALLOCATION,
        sizeof(NPM_PIPE_EVENT),
        NPM_POOL_TAG_EVENT,
        0
    );

    g_NpmState.LookasideInitialized = TRUE;

    //
    // Initialize rundown protection
    //
    ExInitializeRundownProtection(&g_NpmState.RundownRef);

    //
    // Initialize rate limiting
    //
    KeQuerySystemTimePrecise(&g_NpmState.RateWindowStart);
    g_NpmState.RateWindowCount = 0;
    g_NpmState.TotalEntries = 0;

    MemoryBarrier();
    InterlockedExchange(&g_NpmState.State, NPM_STATE_READY);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Named Pipe Monitor initialized (%u C2 patterns, %u system pipes)\n",
               (ULONG)ARRAYSIZE(g_KnownC2Patterns),
               (ULONG)ARRAYSIZE(g_SystemPipes));

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
NpMonShutdown(
    VOID
    )
{
    LONG prevState;

    prevState = InterlockedCompareExchange(
        &g_NpmState.State,
        NPM_STATE_SHUTTING_DOWN,
        NPM_STATE_READY
    );

    if (prevState != NPM_STATE_READY) {
        return;
    }

    //
    // Wait for in-flight operations to drain
    //
    ExWaitForRundownProtectionRelease(&g_NpmState.RundownRef);

    //
    // Free all tracked pipe entries
    //
    for (ULONG i = 0; i < NPM_HASH_TABLE_SIZE; i++) {
        while (!IsListEmpty(&g_NpmState.HashTable[i].List)) {
            PLIST_ENTRY entry = RemoveHeadList(&g_NpmState.HashTable[i].List);
            PNPM_PIPE_ENTRY pipeEntry = CONTAINING_RECORD(entry, NPM_PIPE_ENTRY, ListEntry);
            ExFreeToNPagedLookasideList(&g_NpmState.EntryLookaside, pipeEntry);
        }
    }

    //
    // Drain event queue
    //
    {
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_NpmState.EventLock, &oldIrql);
        while (!IsListEmpty(&g_NpmState.EventQueue)) {
            PLIST_ENTRY entry = RemoveHeadList(&g_NpmState.EventQueue);
            PNPM_PIPE_EVENT evt = CONTAINING_RECORD(entry, NPM_PIPE_EVENT, ListEntry);
            ExFreeToNPagedLookasideList(&g_NpmState.EventLookaside, evt);
        }
        g_NpmState.EventCount = 0;
        KeReleaseSpinLock(&g_NpmState.EventLock, oldIrql);
    }

    //
    // Destroy lookaside lists
    //
    if (g_NpmState.LookasideInitialized) {
        ExDeleteNPagedLookasideList(&g_NpmState.EntryLookaside);
        ExDeleteNPagedLookasideList(&g_NpmState.EventLookaside);
        g_NpmState.LookasideInitialized = FALSE;
    }

    InterlockedExchange(&g_NpmState.State, NPM_STATE_UNINITIALIZED);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Named Pipe Monitor shutdown complete "
               "(Tracked=%lld, Blocked=%lld, C2=%lld)\n",
               g_NpmState.Stats.TotalPipesCreated,
               g_NpmState.Stats.TotalPipesBlocked,
               g_NpmState.Stats.C2PipesDetected);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
NpMonIsActive(
    VOID
    )
{
    return (ReadAcquire(&g_NpmState.State) == NPM_STATE_READY);
}

// ============================================================================
// MINIFILTER CALLBACKS
// ============================================================================

FLT_PREOP_CALLBACK_STATUS
NpMonPreCreateNamedPipe(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    WCHAR pipeName[NPM_MAX_PIPE_NAME_CCH];
    USHORT nameLength = 0;
    NPM_PIPE_CLASS classification;
    ULONG threatScore = 0;
    HANDLE creatorPid;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    if (!NpMonIsActive()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!ExAcquireRundownProtection(&g_NpmState.RundownRef)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Extract pipe name from the callback data
    //
    if (!NpmExtractPipeName(Data, pipeName, &nameLength)) {
        ExReleaseRundownProtection(&g_NpmState.RundownRef);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    creatorPid = PsGetCurrentProcessId();

    //
    // Rate limit check — prevent DoS via pipe creation storm
    //
    if (!NpmCheckRateLimit()) {
        ExReleaseRundownProtection(&g_NpmState.RundownRef);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    InterlockedIncrement64(&g_NpmState.Stats.TotalPipesCreated);

    //
    // Classify the pipe name
    //
    classification = NpmClassifyPipe(pipeName, nameLength, &threatScore);

    if (classification == NpmClass_System ||
        classification == NpmClass_KnownApplication) {
        //
        // Known benign pipe — allow without tracking
        //
        ExReleaseRundownProtection(&g_NpmState.RundownRef);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Track the pipe
    //
    NpmTrackPipe(pipeName, nameLength, creatorPid, classification, threatScore);

    //
    // Determine threat level and action
    //
    if (classification >= NpmClass_C2_CobaltStrike &&
        classification <= NpmClass_C2_Generic) {
        //
        // Known C2 pipe pattern detected
        //
        NPM_THREAT_LEVEL level = (threatScore >= 90) ? NpmThreat_Critical :
                                  (threatScore >= 70) ? NpmThreat_High :
                                  NpmThreat_Medium;

        InterlockedIncrement64(&g_NpmState.Stats.C2PipesDetected);
        InterlockedIncrement64(&g_NpmState.Stats.SuspiciousPipesDetected);

        NpmQueueEvent(
            pipeName, nameLength,
            creatorPid, NULL,
            classification, level, threatScore,
            (threatScore >= 90),    // Block critical C2 pipes
            TRUE
        );

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] C2 Named Pipe DETECTED: class=%d score=%u creator=PID %lu\n",
                   (int)classification, threatScore, HandleToUlong(creatorPid));

        if (threatScore >= 90) {
            InterlockedIncrement64(&g_NpmState.Stats.TotalPipesBlocked);
            ExReleaseRundownProtection(&g_NpmState.RundownRef);
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
    }
    else if (classification == NpmClass_HighEntropy) {
        //
        // High-entropy pipe name — potential randomized C2
        //
        InterlockedIncrement64(&g_NpmState.Stats.HighEntropyPipesDetected);
        InterlockedIncrement64(&g_NpmState.Stats.SuspiciousPipesDetected);

        NpmQueueEvent(
            pipeName, nameLength,
            creatorPid, NULL,
            classification, NpmThreat_Medium, threatScore,
            FALSE, TRUE
        );
    }
    else if (classification == NpmClass_Suspicious) {
        InterlockedIncrement64(&g_NpmState.Stats.SuspiciousPipesDetected);

        NpmQueueEvent(
            pipeName, nameLength,
            creatorPid, NULL,
            classification, NpmThreat_Low, threatScore,
            FALSE, TRUE
        );
    }

    ExReleaseRundownProtection(&g_NpmState.RundownRef);
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
NpMonPostCreateNamedPipe(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    //
    // Post-operation: no additional processing needed.
    // Tracking was done in pre-op. If pipe creation succeeded,
    // the entry is already in the hash table.
    //
    return FLT_POSTOP_FINISHED_PROCESSING;
}

// ============================================================================
// PUBLIC API — STATISTICS / EVENTS
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
NpMonGetStatistics(
    _Out_ PNPM_STATISTICS Stats
    )
{
    Stats->TotalPipesCreated       = ReadNoFence64((PLONG64)&g_NpmState.Stats.TotalPipesCreated);
    Stats->TotalPipesConnected     = ReadNoFence64((PLONG64)&g_NpmState.Stats.TotalPipesConnected);
    Stats->TotalPipesBlocked       = ReadNoFence64((PLONG64)&g_NpmState.Stats.TotalPipesBlocked);
    Stats->SuspiciousPipesDetected = ReadNoFence64((PLONG64)&g_NpmState.Stats.SuspiciousPipesDetected);
    Stats->C2PipesDetected         = ReadNoFence64((PLONG64)&g_NpmState.Stats.C2PipesDetected);
    Stats->HighEntropyPipesDetected= ReadNoFence64((PLONG64)&g_NpmState.Stats.HighEntropyPipesDetected);
    Stats->CrossProcessConnections = ReadNoFence64((PLONG64)&g_NpmState.Stats.CrossProcessConnections);
    Stats->EventsQueued            = ReadNoFence64((PLONG64)&g_NpmState.Stats.EventsQueued);
    Stats->EventsDropped           = ReadNoFence64((PLONG64)&g_NpmState.Stats.EventsDropped);
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
NpMonDequeueEvent(
    _Outptr_ PNPM_PIPE_EVENT *Event
    )
{
    KIRQL oldIrql;
    PLIST_ENTRY entry;

    *Event = NULL;

    KeAcquireSpinLock(&g_NpmState.EventLock, &oldIrql);

    if (IsListEmpty(&g_NpmState.EventQueue)) {
        KeReleaseSpinLock(&g_NpmState.EventLock, oldIrql);
        return STATUS_NO_MORE_ENTRIES;
    }

    entry = RemoveHeadList(&g_NpmState.EventQueue);
    InterlockedDecrement(&g_NpmState.EventCount);

    KeReleaseSpinLock(&g_NpmState.EventLock, oldIrql);

    *Event = CONTAINING_RECORD(entry, NPM_PIPE_EVENT, ListEntry);
    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE — PIPE NAME EXTRACTION
// ============================================================================

static BOOLEAN
NpmExtractPipeName(
    _In_ PFLT_CALLBACK_DATA Data,
    _Out_writes_(NPM_MAX_PIPE_NAME_CCH) PWCHAR NameBuffer,
    _Out_ PUSHORT NameLengthBytes
    )
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    USHORT copyLen;

    *NameLengthBytes = 0;

    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
    );

    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return FALSE;
    }

    //
    // Use FinalComponent (the actual pipe name, not the full path)
    //
    if (nameInfo->FinalComponent.Length == 0 ||
        nameInfo->FinalComponent.Buffer == NULL) {
        FltReleaseFileNameInformation(nameInfo);
        return FALSE;
    }

    copyLen = nameInfo->FinalComponent.Length;
    if (copyLen > (NPM_MAX_PIPE_NAME_CCH - 1) * sizeof(WCHAR)) {
        copyLen = (NPM_MAX_PIPE_NAME_CCH - 1) * sizeof(WCHAR);
    }

    RtlCopyMemory(NameBuffer, nameInfo->FinalComponent.Buffer, copyLen);
    NameBuffer[copyLen / sizeof(WCHAR)] = L'\0';
    *NameLengthBytes = copyLen;

    FltReleaseFileNameInformation(nameInfo);
    return TRUE;
}

// ============================================================================
// PRIVATE — CLASSIFICATION ENGINE
// ============================================================================

static NPM_PIPE_CLASS
NpmClassifyPipe(
    _In_ PCWSTR PipeName,
    _In_ USHORT NameLengthBytes,
    _Out_ PULONG ThreatScore
    )
{
    USHORT nameChars = NameLengthBytes / sizeof(WCHAR);
    float entropy;

    *ThreatScore = 0;

    if (nameChars == 0) {
        return NpmClass_Unknown;
    }

    //
    // Check system pipe whitelist first
    //
    if (NpmIsSystemPipe(PipeName, nameChars)) {
        return NpmClass_System;
    }

    //
    // Match against known C2 patterns
    //
    for (ULONG i = 0; i < ARRAYSIZE(g_KnownC2Patterns); i++) {
        const NPM_KNOWN_PATTERN *pat = &g_KnownC2Patterns[i];
        USHORT patChars = pat->PatternLengthBytes / sizeof(WCHAR);

        switch (pat->MatchType) {
        case 0: // Exact
            if (nameChars == patChars &&
                _wcsnicmp(PipeName, pat->Pattern, patChars) == 0) {
                *ThreatScore = pat->BaseThreatScore;
                return pat->Classification;
            }
            break;

        case 1: // Prefix
            if (nameChars >= patChars &&
                _wcsnicmp(PipeName, pat->Pattern, patChars) == 0) {
                *ThreatScore = pat->BaseThreatScore;
                return pat->Classification;
            }
            break;

        case 2: // Contains
            if (nameChars >= patChars) {
                for (USHORT j = 0; j <= nameChars - patChars; j++) {
                    if (_wcsnicmp(&PipeName[j], pat->Pattern, patChars) == 0) {
                        *ThreatScore = pat->BaseThreatScore;
                        return pat->Classification;
                    }
                }
            }
            break;
        }
    }

    //
    // Shannon entropy analysis for randomized pipe names.
    // High-entropy names are common in C2 frameworks that generate
    // random pipe names to avoid signature-based detection.
    //
    entropy = NpmCalculateEntropy(PipeName, nameChars);
    if (entropy > NPM_ENTROPY_THRESHOLD_HIGH && nameChars >= 8) {
        *ThreatScore = 55 + (ULONG)((entropy - NPM_ENTROPY_THRESHOLD_HIGH) * 10.0f);
        if (*ThreatScore > 85) {
            *ThreatScore = 85;
        }
        return NpmClass_HighEntropy;
    }

    return NpmClass_Unknown;
}

static BOOLEAN
NpmIsSystemPipe(
    _In_ PCWSTR PipeName,
    _In_ USHORT NameLengthChars
    )
{
    for (ULONG i = 0; i < ARRAYSIZE(g_SystemPipes); i++) {
        SIZE_T sysLen = wcslen(g_SystemPipes[i]);
        if (NameLengthChars == (USHORT)sysLen &&
            _wcsnicmp(PipeName, g_SystemPipes[i], sysLen) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

// ============================================================================
// PRIVATE — ENTROPY CALCULATION
// ============================================================================

/**
 * @brief Calculates Shannon entropy of a wide-character string.
 *
 * Uses frequency analysis of printable ASCII characters.
 * Returns bits-per-character (0.0 for uniform, ~4.7 for random alphanumeric).
 */
static float
NpmCalculateEntropy(
    _In_ PCWSTR String,
    _In_ USHORT LengthChars
    )
{
    ULONG freq[128];
    float entropy = 0.0f;
    float len = (float)LengthChars;

    if (LengthChars < 2) {
        return 0.0f;
    }

    RtlZeroMemory(freq, sizeof(freq));

    //
    // Count character frequencies (only printable ASCII range)
    //
    for (USHORT i = 0; i < LengthChars; i++) {
        WCHAR c = String[i];
        if (c < 128) {
            freq[(ULONG)c]++;
        }
    }

    //
    // Calculate Shannon entropy: H = -Σ p(x) * log2(p(x))
    // We use a lookup approximation to avoid FP division in kernel
    // at high IRQL. Since this runs at PASSIVE_LEVEL in pre-op,
    // floating point is safe on x64 (kernel saves FP state).
    //
    for (ULONG i = 0; i < 128; i++) {
        if (freq[i] > 0) {
            float p = (float)freq[i] / len;
            //
            // log2(p) = ln(p) / ln(2)
            // Approximation: -p * log2(p) via table or direct computation
            // For kernel safety, we use the identity:
            //   -p*log2(p) = p * log2(1/p) = p * (log2(len) - log2(freq[i]))
            //
            // Simplified: we accumulate -p * log2(p) directly
            //
            float log2p = 0.0f;
            float v = p;

            // Fast log2 approximation for 0 < v <= 1
            // Using: log2(x) ≈ (x-1)/ln(2) for x near 1 isn't accurate enough.
            // Instead, use bit manipulation on the float.
            //
            // For kernel driver simplicity, we use the series:
            // log2(v) where v = freq/len
            // -v * log2(v) = v * (log2(len) - log2(freq))
            //
            // We compute log2 via repeated squaring approximation:
            {
                // Natural log approach: ln(x) for 0 < x < 1
                // ln(x) = -(1-x) - (1-x)^2/2 - (1-x)^3/3 ... (for x near 1)
                // But for small p this diverges. Use ratio instead.
                float ratio = (float)freq[i];
                float logFreq = 0.0f, logLen = 0.0f;
                float temp;

                // log2(n) ≈ bit length - 1 + fraction
                // Simple: count bits for integer part
                ULONG n = freq[i];
                while (n > 1) { logFreq += 1.0f; n >>= 1; }

                n = LengthChars;
                while (n > 1) { logLen += 1.0f; n >>= 1; }

                // Fractional refinement
                temp = (float)freq[i];
                while (temp >= 2.0f) temp /= 2.0f;
                logFreq += (temp - 1.0f) * 0.6f;  // Linear approx of log2 frac

                temp = (float)LengthChars;
                while (temp >= 2.0f) temp /= 2.0f;
                logLen += (temp - 1.0f) * 0.6f;

                log2p = logFreq - logLen;  // log2(freq/len) = log2(freq) - log2(len)
            }

            entropy -= p * log2p;
        }
    }

    return entropy;
}

// ============================================================================
// PRIVATE — HASH TABLE OPERATIONS
// ============================================================================

static ULONG
NpmHashPipeName(
    _In_ PCWSTR PipeName,
    _In_ USHORT NameLengthBytes
    )
{
    //
    // DJB2 hash — fast, good distribution for short strings
    //
    ULONG hash = 5381;
    USHORT chars = NameLengthBytes / sizeof(WCHAR);

    for (USHORT i = 0; i < chars; i++) {
        WCHAR c = PipeName[i];
        // Case-insensitive: fold to lowercase
        if (c >= L'A' && c <= L'Z') {
            c += (L'a' - L'A');
        }
        hash = ((hash << 5) + hash) + (ULONG)c;
    }

    return hash % NPM_HASH_TABLE_SIZE;
}

static PNPM_PIPE_ENTRY
NpmAllocateEntry(
    VOID
    )
{
    PNPM_PIPE_ENTRY entry;

    entry = (PNPM_PIPE_ENTRY)ExAllocateFromNPagedLookasideList(
        &g_NpmState.EntryLookaside
    );

    if (entry != NULL) {
        RtlZeroMemory(entry, sizeof(NPM_PIPE_ENTRY));
        entry->ReferenceCount = 1;
    }

    return entry;
}

static VOID
NpmFreeEntry(
    _In_ PNPM_PIPE_ENTRY Entry
    )
{
    ExFreeToNPagedLookasideList(&g_NpmState.EntryLookaside, Entry);
}

static NTSTATUS
NpmTrackPipe(
    _In_ PCWSTR PipeName,
    _In_ USHORT NameLengthBytes,
    _In_ HANDLE CreatorPid,
    _In_ NPM_PIPE_CLASS Classification,
    _In_ ULONG ThreatScore
    )
{
    ULONG bucket;
    PNPM_PIPE_ENTRY entry;
    USHORT copyLen;

    //
    // Check capacity — evict if needed
    //
    if (InterlockedCompareExchange(&g_NpmState.TotalEntries, 0, 0) >= NPM_MAX_TRACKED_PIPES) {
        NpmEvictLruEntries(64);
    }

    entry = NpmAllocateEntry();
    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Populate entry
    //
    copyLen = NameLengthBytes;
    if (copyLen > (NPM_MAX_PIPE_NAME_CCH - 1) * sizeof(WCHAR)) {
        copyLen = (NPM_MAX_PIPE_NAME_CCH - 1) * sizeof(WCHAR);
    }

    RtlCopyMemory(entry->PipeName, PipeName, copyLen);
    entry->PipeName[copyLen / sizeof(WCHAR)] = L'\0';
    entry->PipeNameLength = copyLen;
    entry->CreatorProcessId = CreatorPid;
    entry->Classification = Classification;
    entry->ThreatLevel = (ThreatScore >= 90) ? NpmThreat_Critical :
                          (ThreatScore >= 70) ? NpmThreat_High :
                          (ThreatScore >= 50) ? NpmThreat_Medium :
                          (ThreatScore >= 25) ? NpmThreat_Low :
                          NpmThreat_None;
    entry->ThreatScore = ThreatScore;
    entry->ConnectionCount = 0;
    entry->IsBlocked = (ThreatScore >= 90);
    entry->IsMonitored = (ThreatScore >= 25);

    KeQuerySystemTimePrecise(&entry->CreateTime);
    entry->LastAccessTime = entry->CreateTime;

    //
    // Insert into hash table
    //
    bucket = NpmHashPipeName(PipeName, NameLengthBytes);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_NpmState.HashTable[bucket].Lock);

    InsertTailList(&g_NpmState.HashTable[bucket].List, &entry->ListEntry);
    InterlockedIncrement(&g_NpmState.HashTable[bucket].Count);
    InterlockedIncrement(&g_NpmState.TotalEntries);

    ExReleasePushLockExclusive(&g_NpmState.HashTable[bucket].Lock);
    KeLeaveCriticalRegion();

    //
    // Add to LRU list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_NpmState.LruLock);
    InsertTailList(&g_NpmState.LruList, &entry->LruEntry);
    ExReleasePushLockExclusive(&g_NpmState.LruLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE — EVENT QUEUE
// ============================================================================

static NTSTATUS
NpmQueueEvent(
    _In_ PCWSTR PipeName,
    _In_ USHORT NameLengthBytes,
    _In_ HANDLE CreatorPid,
    _In_opt_ HANDLE ConnectorPid,
    _In_ NPM_PIPE_CLASS Classification,
    _In_ NPM_THREAT_LEVEL ThreatLevel,
    _In_ ULONG ThreatScore,
    _In_ BOOLEAN WasBlocked,
    _In_ BOOLEAN IsCreation
    )
{
    PNPM_PIPE_EVENT evt;
    KIRQL oldIrql;
    USHORT copyLen;

    //
    // Check queue depth
    //
    if (InterlockedCompareExchange(&g_NpmState.EventCount, 0, 0) >= NPM_MAX_EVENT_QUEUE) {
        InterlockedIncrement64(&g_NpmState.Stats.EventsDropped);
        return STATUS_QUOTA_EXCEEDED;
    }

    evt = (PNPM_PIPE_EVENT)ExAllocateFromNPagedLookasideList(
        &g_NpmState.EventLookaside
    );

    if (evt == NULL) {
        InterlockedIncrement64(&g_NpmState.Stats.EventsDropped);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(evt, sizeof(NPM_PIPE_EVENT));

    KeQuerySystemTimePrecise(&evt->Timestamp);
    evt->CreatorProcessId = CreatorPid;
    evt->ConnectorProcessId = ConnectorPid;
    evt->Classification = Classification;
    evt->ThreatLevel = ThreatLevel;
    evt->ThreatScore = ThreatScore;
    evt->WasBlocked = WasBlocked;
    evt->IsCreation = IsCreation;

    copyLen = NameLengthBytes;
    if (copyLen > (NPM_MAX_PIPE_NAME_CCH - 1) * sizeof(WCHAR)) {
        copyLen = (NPM_MAX_PIPE_NAME_CCH - 1) * sizeof(WCHAR);
    }
    RtlCopyMemory(evt->PipeName, PipeName, copyLen);
    evt->PipeName[copyLen / sizeof(WCHAR)] = L'\0';
    evt->PipeNameLength = copyLen;

    //
    // Enqueue
    //
    KeAcquireSpinLock(&g_NpmState.EventLock, &oldIrql);
    InsertTailList(&g_NpmState.EventQueue, &evt->ListEntry);
    InterlockedIncrement(&g_NpmState.EventCount);
    KeReleaseSpinLock(&g_NpmState.EventLock, oldIrql);

    InterlockedIncrement64(&g_NpmState.Stats.EventsQueued);

    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE — RATE LIMITING
// ============================================================================

static BOOLEAN
NpmCheckRateLimit(
    VOID
    )
{
    LARGE_INTEGER now;
    LARGE_INTEGER elapsed;

    KeQuerySystemTimePrecise(&now);

    elapsed.QuadPart = now.QuadPart - g_NpmState.RateWindowStart.QuadPart;

    //
    // If window expired, reset
    //
    if (elapsed.QuadPart > (LONGLONG)NPM_RATE_LIMIT_WINDOW_MS * 10000LL) {
        g_NpmState.RateWindowStart = now;
        InterlockedExchange(&g_NpmState.RateWindowCount, 1);
        return TRUE;
    }

    //
    // Check if within rate limit
    //
    LONG count = InterlockedIncrement(&g_NpmState.RateWindowCount);
    if (count > NPM_RATE_LIMIT_MAX_CREATES) {
        return FALSE;
    }

    return TRUE;
}

// ============================================================================
// PRIVATE — LRU EVICTION
// ============================================================================

static VOID
NpmEvictLruEntries(
    _In_ ULONG Count
    )
{
    ULONG evicted = 0;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_NpmState.LruLock);

    while (!IsListEmpty(&g_NpmState.LruList) && evicted < Count) {
        PLIST_ENTRY lruEntry = RemoveHeadList(&g_NpmState.LruList);
        PNPM_PIPE_ENTRY pipeEntry = CONTAINING_RECORD(lruEntry, NPM_PIPE_ENTRY, LruEntry);
        ULONG bucket = NpmHashPipeName(pipeEntry->PipeName, pipeEntry->PipeNameLength);

        //
        // Remove from hash table
        //
        ExAcquirePushLockExclusive(&g_NpmState.HashTable[bucket].Lock);
        RemoveEntryList(&pipeEntry->ListEntry);
        InterlockedDecrement(&g_NpmState.HashTable[bucket].Count);
        InterlockedDecrement(&g_NpmState.TotalEntries);
        ExReleasePushLockExclusive(&g_NpmState.HashTable[bucket].Lock);

        NpmFreeEntry(pipeEntry);
        evicted++;
    }

    ExReleasePushLockExclusive(&g_NpmState.LruLock);
    KeLeaveCriticalRegion();
}
