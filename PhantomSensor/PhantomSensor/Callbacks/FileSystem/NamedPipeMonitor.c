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

//
// PsGetProcessImageFileName may not be declared in all WDK configurations.
// It is exported by ntoskrnl and safe to call at any IRQL.
//
extern PUCHAR PsGetProcessImageFileName(_In_ PEPROCESS Process);

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
    //
    // CobaltStrike SMB beacon defaults + common malleable C2 profiles
    //
    { L"MSSE-",         sizeof(L"MSSE-") - sizeof(WCHAR),         1, NpmClass_C2_CobaltStrike, 90 },
    { L"msagent_",      sizeof(L"msagent_") - sizeof(WCHAR),      1, NpmClass_C2_CobaltStrike, 90 },
    { L"postex_",       sizeof(L"postex_") - sizeof(WCHAR),       1, NpmClass_C2_CobaltStrike, 95 },
    { L"postex_ssh_",   sizeof(L"postex_ssh_") - sizeof(WCHAR),   1, NpmClass_C2_CobaltStrike, 95 },
    { L"status_",       sizeof(L"status_") - sizeof(WCHAR),       1, NpmClass_C2_CobaltStrike, 70 },
    { L"DserNamePipe",  sizeof(L"DserNamePipe") - sizeof(WCHAR),  1, NpmClass_C2_CobaltStrike, 85 },
    { L"srvsvc_",       sizeof(L"srvsvc_") - sizeof(WCHAR),       1, NpmClass_C2_CobaltStrike, 80 },
    { L"wkssvc_",       sizeof(L"wkssvc_") - sizeof(WCHAR),       1, NpmClass_C2_CobaltStrike, 80 },
    { L"ntsvcs_",       sizeof(L"ntsvcs_") - sizeof(WCHAR),       1, NpmClass_C2_CobaltStrike, 80 },
    { L"scerpc_",       sizeof(L"scerpc_") - sizeof(WCHAR),       1, NpmClass_C2_CobaltStrike, 80 },
    { L"interprocess_", sizeof(L"interprocess_") - sizeof(WCHAR), 2, NpmClass_C2_CobaltStrike, 80 },

    //
    // PsExec + remote execution variants
    //
    { L"PSEXESVC",      sizeof(L"PSEXESVC") - sizeof(WCHAR),      0, NpmClass_C2_PsExec, 70 },
    { L"psexesvc",      sizeof(L"psexesvc") - sizeof(WCHAR),      0, NpmClass_C2_PsExec, 70 },
    { L"PSEXECSVC",     sizeof(L"PSEXECSVC") - sizeof(WCHAR),     0, NpmClass_C2_PsExec, 70 },
    { L"csexec",        sizeof(L"csexec") - sizeof(WCHAR),        1, NpmClass_C2_PsExec, 65 },
    { L"PAExec",        sizeof(L"PAExec") - sizeof(WCHAR),        1, NpmClass_C2_PsExec, 65 },
    { L"remcom",        sizeof(L"remcom") - sizeof(WCHAR),        1, NpmClass_C2_PsExec, 60 },
    { L"RemCom_comm",   sizeof(L"RemCom_comm") - sizeof(WCHAR),   1, NpmClass_C2_PsExec, 70 },

    //
    // Meterpreter / Metasploit
    //
    { L"meterpreter",   sizeof(L"meterpreter") - sizeof(WCHAR),   1, NpmClass_C2_Meterpreter, 95 },
    { L"metsrv",        sizeof(L"metsrv") - sizeof(WCHAR),        1, NpmClass_C2_Meterpreter, 90 },

    //
    // Impacket / WMIExec / SMBExec / atexec
    //
    { L"__output",      sizeof(L"__output") - sizeof(WCHAR),      1, NpmClass_C2_Impacket, 75 },
    { L"__aexec",       sizeof(L"__aexec") - sizeof(WCHAR),       1, NpmClass_C2_Impacket, 75 },

    //
    // Havoc C2 framework
    //
    { L"havoc",         sizeof(L"havoc") - sizeof(WCHAR),         1, NpmClass_C2_Generic, 90 },
    { L"demon_",        sizeof(L"demon_") - sizeof(WCHAR),        1, NpmClass_C2_Generic, 85 },

    //
    // Brute Ratel C4
    //
    { L"demoagent_",    sizeof(L"demoagent_") - sizeof(WCHAR),    1, NpmClass_C2_Generic, 85 },
    { L"brc4_",         sizeof(L"brc4_") - sizeof(WCHAR),         1, NpmClass_C2_Generic, 90 },

    //
    // Sliver C2
    //
    { L"sliver",        sizeof(L"sliver") - sizeof(WCHAR),        1, NpmClass_C2_Generic, 85 },

    //
    // Mythic C2
    //
    { L"mythic",        sizeof(L"mythic") - sizeof(WCHAR),        1, NpmClass_C2_Generic, 85 },

    //
    // Covenant C2
    //
    { L"gruntsvc",      sizeof(L"gruntsvc") - sizeof(WCHAR),      1, NpmClass_C2_Generic, 85 },

    //
    // Other known offensive tools
    //
    { L"dceservice",    sizeof(L"dceservice") - sizeof(WCHAR),    1, NpmClass_C2_Generic, 80 },
    { L"poshc2",        sizeof(L"poshc2") - sizeof(WCHAR),        1, NpmClass_C2_Generic, 80 },
    { L"nimplant",      sizeof(L"nimplant") - sizeof(WCHAR),      1, NpmClass_C2_Generic, 85 },

    //
    // PrintSpoofer / Privilege escalation
    //
    { L"SpoolSS_LPC",   sizeof(L"SpoolSS_LPC") - sizeof(WCHAR),  1, NpmClass_Suspicious, 65 },

    //
    // Generic suspicious substrings (contains-match, no path prefixes)
    //
    { L"beacon",        sizeof(L"beacon") - sizeof(WCHAR),        2, NpmClass_Suspicious, 55 },
    { L"implant",       sizeof(L"implant") - sizeof(WCHAR),       2, NpmClass_Suspicious, 55 },
    { L"payload",       sizeof(L"payload") - sizeof(WCHAR),       2, NpmClass_Suspicious, 50 },
    { L"backdoor",      sizeof(L"backdoor") - sizeof(WCHAR),      2, NpmClass_Suspicious, 60 },
    { L"c2pipe",        sizeof(L"c2pipe") - sizeof(WCHAR),        2, NpmClass_Suspicious, 55 },
    { L"evil",          sizeof(L"evil") - sizeof(WCHAR),          2, NpmClass_Suspicious, 50 },
};

// ============================================================================
// SYSTEM PIPE → EXPECTED PROCESS MAPPING (T1036 defense)
// ============================================================================

/**
 * @brief Maps known system pipe names to their expected creator processes.
 *
 * An attacker masquerading as a system pipe (e.g. creating "\Device\NamedPipe\lsass"
 * from malware.exe instead of lsass.exe) is classified as NpmClass_SpoofedSystem
 * and immediately blocked. This defends against MITRE T1036.004 / T1036.005.
 *
 * ExpectedCreators: Null-terminated list of valid image names from
 * PsGetProcessImageFileName (max 15 chars, case-insensitive comparison).
 */
typedef struct _NPM_SYSTEM_PIPE_MAP {
    PCWSTR PipeName;
    PCSTR  ExpectedCreators[4];
} NPM_SYSTEM_PIPE_MAP;

static const NPM_SYSTEM_PIPE_MAP g_SystemPipeMappings[] = {
    // LSASS pipes — only lsass.exe may create these
    { L"lsass",              { "lsass.exe", NULL } },
    { L"lsarpc",             { "lsass.exe", NULL } },
    { L"samr",               { "lsass.exe", NULL } },
    { L"netlogon",           { "lsass.exe", NULL } },
    { L"protected_storage",  { "lsass.exe", NULL } },

    // Service Control Manager pipes
    { L"scerpc",             { "services.exe", NULL } },
    { L"svcctl",             { "services.exe", NULL } },
    { L"ntsvcs",             { "services.exe", "svchost.exe", NULL } },

    // General Windows services (hosted by svchost.exe)
    { L"browser",            { "svchost.exe", NULL } },
    { L"wkssvc",             { "svchost.exe", NULL } },
    { L"srvsvc",             { "svchost.exe", NULL } },
    { L"winreg",             { "svchost.exe", "services.exe", NULL } },
    { L"eventlog",           { "svchost.exe", NULL } },
    { L"epmapper",           { "svchost.exe", NULL } },
    { L"atsvc",              { "svchost.exe", NULL } },
    { L"DAV RPC SERVICE",    { "svchost.exe", NULL } },

    // Print Spooler
    { L"spoolss",            { "spoolsv.exe", NULL } },

    // System init
    { L"InitShutdown",       { "wininit.exe", NULL } },

    // Windows Search
    { L"MsFteWds",           { "SearchIndexer", NULL } },
    { L"msfte",              { "SearchIndexer", NULL } },
};

/**
 * @brief Result of system pipe name + creator process validation.
 */
typedef enum _NPM_SYSTEM_PIPE_RESULT {
    NpmSysPipe_NotSystem = 0,   // Not a system pipe name
    NpmSysPipe_Validated = 1,   // System pipe + correct creator
    NpmSysPipe_Spoofed   = 2    // System pipe name + WRONG creator
} NPM_SYSTEM_PIPE_RESULT;

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

static NPM_SYSTEM_PIPE_RESULT
NpmValidateSystemPipe(
    _In_ PCWSTR PipeName,
    _In_ USHORT NameLengthChars,
    _In_z_ PCSTR CreatorImageName
    );

static VOID
NpmGetCreatorImageName(
    _In_ PEPROCESS Process,
    _Out_writes_(16) PCHAR ImageNameOut
    );

static BOOLEAN
NpmImageNameEquals(
    _In_z_ PCSTR Name1,
    _In_z_ PCSTR Name2
    );

static ULONG
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
    _In_z_ PCSTR CreatorImageName,
    _In_ NPM_PIPE_CLASS Classification,
    _In_ ULONG ThreatScore
    );

static NTSTATUS
NpmQueueEvent(
    _In_ PCWSTR PipeName,
    _In_ USHORT NameLengthBytes,
    _In_ HANDLE CreatorPid,
    _In_opt_ HANDLE ConnectorPid,
    _In_z_ PCSTR CreatorImageName,
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
// PAGE ALLOCATION
// ============================================================================

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, NpMonInitialize)
#pragma alloc_text(PAGE, NpMonShutdown)
#pragma alloc_text(PAGE, NpMonDequeueEvent)
#pragma alloc_text(PAGE, NpmExtractPipeName)
#pragma alloc_text(PAGE, NpmClassifyPipe)
#pragma alloc_text(PAGE, NpmValidateSystemPipe)
#pragma alloc_text(PAGE, NpmCalculateEntropy)
#pragma alloc_text(PAGE, NpmTrackPipe)
#pragma alloc_text(PAGE, NpmEvictLruEntries)
#endif

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

    PAGED_CODE();

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
               (ULONG)ARRAYSIZE(g_SystemPipeMappings));

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
NpMonShutdown(
    VOID
    )
{
    LONG prevState;

    PAGED_CODE();

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
    // Destroy lookaside lists — mark unavailable FIRST to prevent
    // in-flight NpMonFreeEvent from using them after deletion
    //
    if (g_NpmState.LookasideInitialized) {
        g_NpmState.LookasideInitialized = FALSE;
        MemoryBarrier();
        ExDeleteNPagedLookasideList(&g_NpmState.EntryLookaside);
        ExDeleteNPagedLookasideList(&g_NpmState.EventLookaside);
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
// PRIVATE — CREATOR PROCESS IDENTIFICATION
// ============================================================================

/**
 * @brief Case-insensitive ANSI string comparison for process image names.
 * Safe at any IRQL — no allocations, no kernel string objects.
 */
static BOOLEAN
NpmImageNameEquals(
    _In_z_ PCSTR Name1,
    _In_z_ PCSTR Name2
    )
{
    while (*Name1 != '\0' && *Name2 != '\0') {
        CHAR c1 = *Name1;
        CHAR c2 = *Name2;
        if (c1 >= 'A' && c1 <= 'Z') c1 += ('a' - 'A');
        if (c2 >= 'A' && c2 <= 'Z') c2 += ('a' - 'A');
        if (c1 != c2) return FALSE;
        Name1++;
        Name2++;
    }
    return (*Name1 == '\0' && *Name2 == '\0');
}

/**
 * @brief Capture the creating process's image name for validation and forensics.
 *
 * Uses PsGetProcessImageFileName which returns the 15-char internal
 * EPROCESS.ImageFileName buffer — available at any IRQL, no allocation needed.
 */
static VOID
NpmGetCreatorImageName(
    _In_ PEPROCESS Process,
    _Out_writes_(16) PCHAR ImageNameOut
    )
{
    PUCHAR imageName = PsGetProcessImageFileName(Process);

    if (imageName != NULL) {
        RtlCopyMemory(ImageNameOut, imageName, 15);
        ImageNameOut[15] = '\0';
    } else {
        ImageNameOut[0] = '\0';
    }
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
    CHAR creatorImage[16];
    NPM_SYSTEM_PIPE_RESULT sysResult;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    if (!NpMonIsActive()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!ExAcquireRundownProtection(&g_NpmState.RundownRef)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!NpmExtractPipeName(Data, pipeName, &nameLength)) {
        ExReleaseRundownProtection(&g_NpmState.RundownRef);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    creatorPid = PsGetCurrentProcessId();

    //
    // Capture creator process identity for validation and forensics.
    //
    NpmGetCreatorImageName(PsGetCurrentProcess(), creatorImage);

    //
    // ================================================================
    // PHASE 1: System pipe validation — RATE LIMIT EXEMPT.
    //
    // System pipe spoofing is a CRITICAL threat (MITRE T1036).
    // An attacker could flood pipe creations to exhaust the rate limiter,
    // then create spoofed system pipes unmonitored. By validating system
    // pipes BEFORE rate limiting, this bypass is impossible.
    // ================================================================
    //
    sysResult = NpmValidateSystemPipe(
        pipeName,
        nameLength / sizeof(WCHAR),
        creatorImage
    );

    if (sysResult == NpmSysPipe_Validated) {
        //
        // Legitimate system pipe from verified creator — allow immediately
        //
        ExReleaseRundownProtection(&g_NpmState.RundownRef);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (sysResult == NpmSysPipe_Spoofed) {
        //
        // CRITICAL: System pipe name from unauthorized process.
        // This is pipe masquerading — block immediately regardless of rate limit.
        //
        InterlockedIncrement64(&g_NpmState.Stats.TotalPipesCreated);
        InterlockedIncrement64(&g_NpmState.Stats.SpoofedSystemPipes);
        InterlockedIncrement64(&g_NpmState.Stats.SuspiciousPipesDetected);
        InterlockedIncrement64(&g_NpmState.Stats.TotalPipesBlocked);

        NpmTrackPipe(pipeName, nameLength, creatorPid, creatorImage,
                     NpmClass_SpoofedSystem, 95);

        NpmQueueEvent(
            pipeName, nameLength,
            creatorPid, NULL, creatorImage,
            NpmClass_SpoofedSystem, NpmThreat_Critical, 95,
            TRUE, TRUE
        );

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] SPOOFED SYSTEM PIPE BLOCKED: '%.64ws' "
                   "creator=%hs PID=%lu\n",
                   pipeName, creatorImage, HandleToUlong(creatorPid));

        ExReleaseRundownProtection(&g_NpmState.RundownRef);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    //
    // ================================================================
    // PHASE 2: General classification — subject to rate limiting.
    // At this point we know the pipe is NOT a system pipe name.
    // ================================================================
    //
    if (!NpmCheckRateLimit()) {
        ExReleaseRundownProtection(&g_NpmState.RundownRef);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    InterlockedIncrement64(&g_NpmState.Stats.TotalPipesCreated);

    classification = NpmClassifyPipe(pipeName, nameLength, &threatScore);

    if (classification == NpmClass_KnownApplication) {
        ExReleaseRundownProtection(&g_NpmState.RundownRef);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Track the pipe
    //
    NpmTrackPipe(pipeName, nameLength, creatorPid, creatorImage,
                 classification, threatScore);

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
            creatorPid, NULL, creatorImage,
            classification, level, threatScore,
            (threatScore >= 90),
            TRUE
        );

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] C2 Named Pipe DETECTED: class=%d score=%u "
                   "creator=%hs PID=%lu\n",
                   (int)classification, threatScore,
                   creatorImage, HandleToUlong(creatorPid));

        if (threatScore >= 90) {
            InterlockedIncrement64(&g_NpmState.Stats.TotalPipesBlocked);
            ExReleaseRundownProtection(&g_NpmState.RundownRef);
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
    }
    else if (classification == NpmClass_HighEntropy) {
        InterlockedIncrement64(&g_NpmState.Stats.HighEntropyPipesDetected);
        InterlockedIncrement64(&g_NpmState.Stats.SuspiciousPipesDetected);

        NpmQueueEvent(
            pipeName, nameLength,
            creatorPid, NULL, creatorImage,
            classification, NpmThreat_Medium, threatScore,
            FALSE, TRUE
        );
    }
    else if (classification == NpmClass_Suspicious) {
        InterlockedIncrement64(&g_NpmState.Stats.SuspiciousPipesDetected);

        NpmQueueEvent(
            pipeName, nameLength,
            creatorPid, NULL, creatorImage,
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
    Stats->SpoofedSystemPipes      = ReadNoFence64((PLONG64)&g_NpmState.Stats.SpoofedSystemPipes);
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

    PAGED_CODE();

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


_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
NpMonFreeEvent(
    _In_opt_ PNPM_PIPE_EVENT Event
    )
{
    if (Event == NULL) {
        return;
    }

    if (g_NpmState.LookasideInitialized) {
        ExFreeToNPagedLookasideList(&g_NpmState.EventLookaside, Event);
    }
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

    PAGED_CODE();

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
    ULONG entropy1024;

    //
    // Entropy threshold: 4.2 bits * 1024 = 4300 (fixed-point)
    //
    static const ULONG ENTROPY_THRESHOLD_FIXED = 4300;

    PAGED_CODE();

    *ThreatScore = 0;

    if (nameChars == 0) {
        return NpmClass_Unknown;
    }

    //
    // System pipe validation is handled in Phase 1 of NpMonPreCreateNamedPipe
    // (rate-limit exempt). By the time we reach here, the pipe is confirmed
    // NOT a system pipe name. Proceed directly to C2 pattern matching.
    //

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
    // entropy1024 is in fixed-point (actual_entropy * 1024).
    //
    entropy1024 = NpmCalculateEntropy(PipeName, nameChars);
    if (entropy1024 > ENTROPY_THRESHOLD_FIXED && nameChars >= 8) {
        *ThreatScore = 55 + (entropy1024 - ENTROPY_THRESHOLD_FIXED) / 100;
        if (*ThreatScore > 85) {
            *ThreatScore = 85;
        }
        return NpmClass_HighEntropy;
    }

    return NpmClass_Unknown;
}

/**
 * @brief Validates a pipe name against the system pipe mapping table.
 *
 * Returns NpmSysPipe_Validated if the name matches a known system pipe AND
 * the creator process is one of the expected creators for that pipe.
 * Returns NpmSysPipe_Spoofed if the name matches but the creator is WRONG.
 * Returns NpmSysPipe_NotSystem if the name doesn't match any system pipe.
 *
 * This is the core defense against pipe masquerading (MITRE T1036.004/T1036.005).
 * Without this, any malware could create "\Device\NamedPipe\lsass" and bypass
 * all monitoring.
 */
static NPM_SYSTEM_PIPE_RESULT
NpmValidateSystemPipe(
    _In_ PCWSTR PipeName,
    _In_ USHORT NameLengthChars,
    _In_z_ PCSTR CreatorImageName
    )
{
    PAGED_CODE();

    for (ULONG i = 0; i < ARRAYSIZE(g_SystemPipeMappings); i++) {
        SIZE_T sysLen = wcslen(g_SystemPipeMappings[i].PipeName);
        if (NameLengthChars == (USHORT)sysLen &&
            _wcsnicmp(PipeName, g_SystemPipeMappings[i].PipeName, sysLen) == 0) {
            //
            // Pipe name matches a known system pipe.
            // Now validate that the creator is one of the expected processes.
            //
            for (ULONG j = 0; g_SystemPipeMappings[i].ExpectedCreators[j] != NULL; j++) {
                if (NpmImageNameEquals(CreatorImageName,
                                       g_SystemPipeMappings[i].ExpectedCreators[j])) {
                    return NpmSysPipe_Validated;
                }
            }

            //
            // System pipe name but creator doesn't match ANY expected process.
            // Strong indicator of masquerading.
            //
            return NpmSysPipe_Spoofed;
        }
    }

    return NpmSysPipe_NotSystem;
}

// ============================================================================
// PRIVATE — ENTROPY CALCULATION
// ============================================================================

/**
 * @brief Calculates Shannon entropy of a wide-character string using integer math.
 *
 * Returns entropy in fixed-point format: result / 1024 = actual entropy in bits.
 * Threshold comparisons should use scaled values (e.g. 4.2 * 1024 = 4300).
 * Uses a pre-computed log2 lookup table to avoid floating-point in kernel mode.
 */

//
// Fixed-point log2 table: log2_table[n] = round(log2(n) * 1024) for n=1..256
// log2(1)=0, log2(2)=1024, log2(3)=1623, ..., log2(256)=8192
//
static const USHORT g_Log2Table[257] = {
       0,    0, 1024, 1623, 2048, 2378, 2647, 2874,
    3072, 3247, 3402, 3542, 3671, 3789, 3898, 4001,
    4096, 4186, 4271, 4351, 4427, 4499, 4568, 4634,
    4697, 4757, 4815, 4871, 4925, 4977, 5027, 5075,
    5120, 5165, 5208, 5249, 5290, 5329, 5367, 5404,
    5440, 5475, 5509, 5542, 5574, 5606, 5637, 5667,
    5696, 5725, 5753, 5781, 5808, 5834, 5860, 5886,
    5910, 5935, 5959, 5982, 6006, 6028, 6051, 6073,
    6094, 6116, 6136, 6157, 6177, 6197, 6217, 6236,
    6255, 6274, 6293, 6311, 6329, 6347, 6365, 6382,
    6400, 6417, 6434, 6450, 6467, 6483, 6499, 6515,
    6531, 6546, 6562, 6577, 6592, 6607, 6621, 6636,
    6650, 6665, 6679, 6693, 6706, 6720, 6734, 6747,
    6760, 6773, 6786, 6799, 6812, 6824, 6837, 6849,
    6861, 6873, 6885, 6897, 6909, 6921, 6932, 6944,
    6955, 6966, 6977, 6989, 6999, 7010, 7021, 7032,
    7042, 7053, 7063, 7073, 7084, 7094, 7104, 7114,
    7124, 7134, 7143, 7153, 7163, 7172, 7182, 7191,
    7201, 7210, 7219, 7228, 7237, 7247, 7256, 7264,
    7273, 7282, 7291, 7300, 7308, 7317, 7325, 7334,
    7342, 7350, 7359, 7367, 7375, 7383, 7391, 7399,
    7407, 7415, 7423, 7431, 7438, 7446, 7454, 7461,
    7469, 7476, 7484, 7491, 7499, 7506, 7513, 7521,
    7528, 7535, 7542, 7549, 7556, 7563, 7570, 7577,
    7584, 7591, 7597, 7604, 7611, 7618, 7624, 7631,
    7637, 7644, 7650, 7657, 7663, 7669, 7676, 7682,
    7688, 7694, 7700, 7707, 7713, 7719, 7725, 7731,
    7737, 7743, 7749, 7754, 7760, 7766, 7772, 7778,
    7783, 7789, 7795, 7800, 7806, 7812, 7817, 7823,
    7828, 7834, 7839, 7844, 7850, 7855, 7861, 7866,
    7871, 7877, 7882, 7887, 7892, 7897, 7903, 7908,
    7913, 7918, 7923, 7928, 7933, 7938, 7943, 7948,
    7953
};

//
// Integer log2 for values > 256 using bit scan + table interpolation
//
FORCEINLINE
ULONG
NpmLog2Fixed(
    _In_ ULONG Value
    )
{
    ULONG shift = 0;
    ULONG v = Value;

    if (v == 0) return 0;
    if (v <= 256) return g_Log2Table[v];

    while (v > 256) {
        v >>= 1;
        shift++;
    }

    return g_Log2Table[v] + (shift * 1024);
}

static ULONG
NpmCalculateEntropy(
    _In_ PCWSTR String,
    _In_ USHORT LengthChars
    )
{
    ULONG freq[128];
    ULONG entropy1024 = 0;
    ULONG logLen;

    PAGED_CODE();

    if (LengthChars < 2) {
        return 0;
    }

    RtlZeroMemory(freq, sizeof(freq));

    for (USHORT i = 0; i < LengthChars; i++) {
        WCHAR c = String[i];
        if (c < 128) {
            freq[(ULONG)c]++;
        }
    }

    //
    // Shannon entropy: H = log2(N) - (1/N) * Σ freq[i] * log2(freq[i])
    // In fixed-point (*1024):
    //   H*1024 = log2(N)*1024 - (1/N) * Σ freq[i] * log2(freq[i])*1024
    //
    logLen = NpmLog2Fixed(LengthChars);

    for (ULONG i = 0; i < 128; i++) {
        if (freq[i] > 0 && freq[i] <= 256) {
            entropy1024 += freq[i] * g_Log2Table[freq[i]];
        } else if (freq[i] > 256) {
            entropy1024 += freq[i] * NpmLog2Fixed(freq[i]);
        }
    }

    //
    // H*1024 = log2(N)*1024 - entropy_sum / N
    //
    entropy1024 = logLen - (entropy1024 / LengthChars);

    return entropy1024;
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
    _In_z_ PCSTR CreatorImageName,
    _In_ NPM_PIPE_CLASS Classification,
    _In_ ULONG ThreatScore
    )
{
    ULONG bucket;
    PNPM_PIPE_ENTRY entry;
    USHORT copyLen;
    PLIST_ENTRY listEntry;
    BOOLEAN duplicate = FALSE;

    PAGED_CODE();

    //
    // Check capacity — evict if needed
    //
    if (InterlockedCompareExchange(&g_NpmState.TotalEntries, 0, 0) >= NPM_MAX_TRACKED_PIPES) {
        NpmEvictLruEntries(64);
    }

    bucket = NpmHashPipeName(PipeName, NameLengthBytes);

    //
    // Check for duplicate entry in the bucket before allocating.
    // Lock ordering: bucket lock FIRST, then LRU lock (matches eviction order).
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_NpmState.HashTable[bucket].Lock);

    for (listEntry = g_NpmState.HashTable[bucket].List.Flink;
         listEntry != &g_NpmState.HashTable[bucket].List;
         listEntry = listEntry->Flink) {

        PNPM_PIPE_ENTRY existing = CONTAINING_RECORD(listEntry, NPM_PIPE_ENTRY, ListEntry);
        if (existing->PipeNameLength == NameLengthBytes &&
            _wcsnicmp(existing->PipeName, PipeName, NameLengthBytes / sizeof(WCHAR)) == 0) {
            //
            // Duplicate — update existing entry instead of inserting new one
            //
            InterlockedIncrement(&existing->ConnectionCount);
            KeQuerySystemTimePrecise(&existing->LastAccessTime);

            if (ThreatScore > existing->ThreatScore) {
                existing->ThreatScore = ThreatScore;
                existing->Classification = Classification;
            }

            duplicate = TRUE;
            break;
        }
    }

    if (duplicate) {
        ExReleasePushLockExclusive(&g_NpmState.HashTable[bucket].Lock);
        KeLeaveCriticalRegion();
        return STATUS_SUCCESS;
    }

    //
    // Not a duplicate — allocate and insert
    //
    entry = NpmAllocateEntry();
    if (entry == NULL) {
        ExReleasePushLockExclusive(&g_NpmState.HashTable[bucket].Lock);
        KeLeaveCriticalRegion();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    copyLen = NameLengthBytes;
    if (copyLen > (NPM_MAX_PIPE_NAME_CCH - 1) * sizeof(WCHAR)) {
        copyLen = (NPM_MAX_PIPE_NAME_CCH - 1) * sizeof(WCHAR);
    }

    RtlCopyMemory(entry->PipeName, PipeName, copyLen);
    entry->PipeName[copyLen / sizeof(WCHAR)] = L'\0';
    entry->PipeNameLength = copyLen;
    entry->CreatorProcessId = CreatorPid;
    RtlCopyMemory(entry->CreatorImageName, CreatorImageName, 16);
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

    InsertTailList(&g_NpmState.HashTable[bucket].List, &entry->ListEntry);
    InterlockedIncrement(&g_NpmState.HashTable[bucket].Count);
    InterlockedIncrement(&g_NpmState.TotalEntries);

    ExReleasePushLockExclusive(&g_NpmState.HashTable[bucket].Lock);
    KeLeaveCriticalRegion();

    //
    // Add to LRU list (separate lock scope — always acquired AFTER bucket lock)
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
    _In_z_ PCSTR CreatorImageName,
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
    RtlCopyMemory(evt->CreatorImageName, CreatorImageName, 16);
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
    LONGLONG oldStart;
    LONGLONG elapsed;

    KeQuerySystemTimePrecise(&now);

    oldStart = InterlockedCompareExchange64(
        &g_NpmState.RateWindowStart.QuadPart,
        g_NpmState.RateWindowStart.QuadPart,
        g_NpmState.RateWindowStart.QuadPart
    );

    elapsed = now.QuadPart - oldStart;

    //
    // If window expired, attempt atomic reset.
    // Only one thread wins the CAS — others see the new window and proceed normally.
    //
    if (elapsed > (LONGLONG)NPM_RATE_LIMIT_WINDOW_MS * 10000LL) {
        LONGLONG swapped = InterlockedCompareExchange64(
            &g_NpmState.RateWindowStart.QuadPart,
            now.QuadPart,
            oldStart
        );

        if (swapped == oldStart) {
            InterlockedExchange(&g_NpmState.RateWindowCount, 1);
            return TRUE;
        }
        //
        // Another thread already reset — fall through to normal increment
        //
    }

    //
    // Atomic increment within current window
    //
    {
        LONG count = InterlockedIncrement(&g_NpmState.RateWindowCount);
        if (count > NPM_RATE_LIMIT_MAX_CREATES) {
            return FALSE;
        }
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
    ULONG collected = 0;
    PNPM_PIPE_ENTRY victims[64];

    PAGED_CODE();

    if (Count > 64) {
        Count = 64;
    }

    //
    // Phase 1: Collect victims from LRU list under LRU lock only.
    // Do NOT acquire bucket locks here — that would violate lock ordering
    // (NpmTrackPipe acquires bucket lock then LRU lock).
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_NpmState.LruLock);

    while (!IsListEmpty(&g_NpmState.LruList) && collected < Count) {
        PLIST_ENTRY lruEntry = RemoveHeadList(&g_NpmState.LruList);
        victims[collected] = CONTAINING_RECORD(lruEntry, NPM_PIPE_ENTRY, LruEntry);
        collected++;
    }

    ExReleasePushLockExclusive(&g_NpmState.LruLock);
    KeLeaveCriticalRegion();

    //
    // Phase 2: Remove collected victims from their hash buckets.
    // Now safe to acquire bucket locks without holding LRU lock.
    //
    for (ULONG i = 0; i < collected; i++) {
        PNPM_PIPE_ENTRY pipeEntry = victims[i];
        ULONG bucket = NpmHashPipeName(pipeEntry->PipeName, pipeEntry->PipeNameLength);

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&g_NpmState.HashTable[bucket].Lock);

        RemoveEntryList(&pipeEntry->ListEntry);
        InterlockedDecrement(&g_NpmState.HashTable[bucket].Count);
        InterlockedDecrement(&g_NpmState.TotalEntries);

        ExReleasePushLockExclusive(&g_NpmState.HashTable[bucket].Lock);
        KeLeaveCriticalRegion();

        NpmFreeEntry(pipeEntry);
        evicted++;
    }
}
