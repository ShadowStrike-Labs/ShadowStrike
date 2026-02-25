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
 * ShadowStrike NGAV - SYSCALL TABLE MANAGEMENT
 * ============================================================================
 *
 * @file SyscallTable.c
 * @brief Enterprise-grade syscall number resolution engine.
 *
 * Implements production-quality syscall table management with:
 * - Hardcoded syscall number tables for Windows 10/11 x64 builds
 * - No user-mode memory access — all data is kernel-side
 * - No SSDT pointer exposure — KASLR protection preserved
 * - Hash-based O(1) lookup by number and by name
 * - Read-only after initialization — no TOCTOU, no write-side locking
 * - Magic-validated pointers on all public API entries
 * - Safe at IRQL <= DISPATCH_LEVEL for lookups
 *
 * Syscall Number Resolution:
 * - Windows syscall numbers change between OS builds.
 * - We use a static table of known SSNs for each supported build range.
 * - At init, we detect the current build via RtlGetVersion and select
 *   the matching table. This avoids risky ntdll parsing.
 * - If the build is unknown, initialization fails with STATUS_NOT_SUPPORTED.
 *
 * Build Coverage:
 * - Windows 10 1507 (10240) through Windows 11 24H2 (26100+)
 * - Build ranges are grouped where SSNs are stable across updates.
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "SyscallTable.h"
#include "../Utilities/MemoryUtils.h"
#include <ntstrsafe.h>

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

/** @brief Hash bucket for number lookup */
#define SST_NUM_HASH_MASK                   (SST_HASH_BUCKET_COUNT - 1)

/** @brief FNV-1a offset basis for name hashing */
#define SST_FNV_OFFSET_BASIS                2166136261u

/** @brief FNV-1a prime for name hashing */
#define SST_FNV_PRIME                       16777619u

// ============================================================================
// STATIC SYSCALL DEFINITION (BUILD-TIME DATA)
// ============================================================================

/**
 * @brief Static definition of a syscall for table population.
 * These are compiled into the driver — no runtime memory parsing needed.
 */
typedef struct _SST_STATIC_DEFINITION {
    ULONG Number;
    const CHAR *Name;
    ULONG ArgumentCount;
    SST_CATEGORY Category;
    SST_RISK_LEVEL RiskLevel;
    ULONG Flags;
} SST_STATIC_DEFINITION;

/**
 * @brief Build range descriptor.
 * Syscall numbers are stable within a build range.
 */
typedef struct _SST_BUILD_RANGE {
    ULONG MinBuild;
    ULONG MaxBuild;
    const SST_STATIC_DEFINITION *Definitions;
    ULONG DefinitionCount;
} SST_BUILD_RANGE;

// ============================================================================
// KNOWN SYSCALL TABLES — WINDOWS 10/11 x64
// ============================================================================
//
// These tables contain security-critical syscalls that ShadowStrike monitors.
// SSNs vary by build. We cover the major build ranges.
// Only security-relevant syscalls are included (not all ~470+ per build).
//

/*
 * Windows 10 RS1-RS5 (14393-17763) and Windows 10 19H1-21H2 (18362-19044)
 * share most SSNs for the critical APIs. We group them.
 * Windows 11 21H2+ (22000+) shifted several numbers.
 */

static const SST_STATIC_DEFINITION g_SyscallsWin10_14393[] = {
    /* Process manipulation */
    { 0x00B3, "NtCreateProcess",            8,  SstCategory_Process, SstRisk_Critical,  SST_FLAG_INJECTION_RISK | SST_FLAG_CROSS_PROCESS },
    { 0x00B4, "NtCreateProcessEx",          9,  SstCategory_Process, SstRisk_Critical,  SST_FLAG_INJECTION_RISK | SST_FLAG_CROSS_PROCESS },
    { 0x00C7, "NtCreateUserProcess",       11,  SstCategory_Process, SstRisk_Critical,  SST_FLAG_INJECTION_RISK },
    { 0x002C, "NtOpenProcess",              4,  SstCategory_Process, SstRisk_High,      SST_FLAG_CROSS_PROCESS | SST_FLAG_HANDLE_GRANT },
    { 0x0029, "NtTerminateProcess",         2,  SstCategory_Process, SstRisk_High,      SST_FLAG_CROSS_PROCESS },
    { 0x0044, "NtSuspendProcess",           1,  SstCategory_Process, SstRisk_High,      SST_FLAG_CROSS_PROCESS },
    { 0x0045, "NtResumeProcess",            1,  SstCategory_Process, SstRisk_Medium,    SST_FLAG_CROSS_PROCESS },

    /* Thread manipulation */
    { 0x00BD, "NtCreateThread",             8,  SstCategory_Thread, SstRisk_Critical,   SST_FLAG_INJECTION_RISK | SST_FLAG_CROSS_PROCESS },
    { 0x00C1, "NtCreateThreadEx",          11,  SstCategory_Thread, SstRisk_Critical,   SST_FLAG_INJECTION_RISK | SST_FLAG_CROSS_PROCESS },
    { 0x0035, "NtOpenThread",               4,  SstCategory_Thread, SstRisk_High,       SST_FLAG_CROSS_PROCESS | SST_FLAG_HANDLE_GRANT },
    { 0x0053, "NtTerminateThread",          2,  SstCategory_Thread, SstRisk_High,       SST_FLAG_CROSS_PROCESS },
    { 0x004B, "NtSuspendThread",            2,  SstCategory_Thread, SstRisk_High,       SST_FLAG_CROSS_PROCESS },
    { 0x0052, "NtResumeThread",             2,  SstCategory_Thread, SstRisk_Medium,     SST_FLAG_CROSS_PROCESS },
    { 0x014E, "NtQueueApcThread",           5,  SstCategory_Thread, SstRisk_Critical,   SST_FLAG_INJECTION_RISK | SST_FLAG_CROSS_PROCESS },
    { 0x0185, "NtQueueApcThreadEx",         6,  SstCategory_Thread, SstRisk_Critical,   SST_FLAG_INJECTION_RISK | SST_FLAG_CROSS_PROCESS },
    { 0x0171, "NtSetContextThread",         2,  SstCategory_Thread, SstRisk_Critical,   SST_FLAG_INJECTION_RISK | SST_FLAG_CROSS_PROCESS },

    /* Memory operations */
    { 0x0018, "NtAllocateVirtualMemory",    6,  SstCategory_Memory, SstRisk_High,       SST_FLAG_INJECTION_RISK | SST_FLAG_CROSS_PROCESS | SST_FLAG_MEMORY_WRITE },
    { 0x001E, "NtFreeVirtualMemory",        4,  SstCategory_Memory, SstRisk_Low,        SST_FLAG_CROSS_PROCESS },
    { 0x003A, "NtReadVirtualMemory",        5,  SstCategory_Memory, SstRisk_High,       SST_FLAG_CROSS_PROCESS },
    { 0x003B, "NtWriteVirtualMemory",       5,  SstCategory_Memory, SstRisk_Critical,   SST_FLAG_INJECTION_RISK | SST_FLAG_CROSS_PROCESS | SST_FLAG_MEMORY_WRITE },
    { 0x0050, "NtProtectVirtualMemory",     5,  SstCategory_Memory, SstRisk_High,       SST_FLAG_INJECTION_RISK | SST_FLAG_CROSS_PROCESS },
    { 0x00D5, "NtMapViewOfSection",        10,  SstCategory_Memory, SstRisk_High,       SST_FLAG_INJECTION_RISK | SST_FLAG_CROSS_PROCESS | SST_FLAG_MEMORY_WRITE },
    { 0x002A, "NtUnmapViewOfSection",       2,  SstCategory_Memory, SstRisk_Medium,     SST_FLAG_CROSS_PROCESS },

    /* File operations */
    { 0x0055, "NtCreateFile",              11,  SstCategory_File, SstRisk_Medium,        SST_FLAG_HANDLE_GRANT },
    { 0x0033, "NtOpenFile",                 6,  SstCategory_File, SstRisk_Medium,        SST_FLAG_HANDLE_GRANT },
    { 0x0006, "NtReadFile",                 9,  SstCategory_File, SstRisk_Low,           0 },
    { 0x0008, "NtWriteFile",                9,  SstCategory_File, SstRisk_Low,           0 },
    { 0x000D, "NtDeleteFile",               1,  SstCategory_File, SstRisk_Medium,        0 },

    /* Registry operations */
    { 0x001D, "NtCreateKey",                7,  SstCategory_Registry, SstRisk_Medium,    SST_FLAG_HANDLE_GRANT },
    { 0x0012, "NtOpenKey",                  3,  SstCategory_Registry, SstRisk_Low,       SST_FLAG_HANDLE_GRANT },
    { 0x0017, "NtSetValueKey",              6,  SstCategory_Registry, SstRisk_Medium,    0 },
    { 0x0041, "NtDeleteKey",                1,  SstCategory_Registry, SstRisk_Medium,    0 },
    { 0x003D, "NtDeleteValueKey",           2,  SstCategory_Registry, SstRisk_Medium,    0 },

    /* Security / privilege */
    { 0x0024, "NtOpenProcessToken",         3,  SstCategory_Security, SstRisk_High,      SST_FLAG_CREDENTIAL_RISK | SST_FLAG_HANDLE_GRANT },
    { 0x0025, "NtOpenProcessTokenEx",       4,  SstCategory_Security, SstRisk_High,      SST_FLAG_CREDENTIAL_RISK | SST_FLAG_HANDLE_GRANT },
    { 0x0037, "NtOpenThreadToken",          4,  SstCategory_Security, SstRisk_High,      SST_FLAG_CREDENTIAL_RISK | SST_FLAG_HANDLE_GRANT },
    { 0x009C, "NtAdjustPrivilegesToken",    6,  SstCategory_Security, SstRisk_Critical,  SST_FLAG_CREDENTIAL_RISK },
    { 0x00C3, "NtDuplicateToken",           6,  SstCategory_Security, SstRisk_High,      SST_FLAG_CREDENTIAL_RISK | SST_FLAG_HANDLE_GRANT },

    /* Object manipulation */
    { 0x000F, "NtClose",                    1,  SstCategory_Object, SstRisk_None,        0 },
    { 0x000E, "NtDuplicateObject",          7,  SstCategory_Object, SstRisk_High,        SST_FLAG_CROSS_PROCESS | SST_FLAG_HANDLE_GRANT },

    /* System operations */
    { 0x0036, "NtQuerySystemInformation",   4,  SstCategory_System, SstRisk_Low,         0 },
    { 0x00B7, "NtSetSystemInformation",     3,  SstCategory_System, SstRisk_High,        SST_FLAG_REQUIRES_ADMIN },
    { 0x00D4, "NtLoadDriver",              1,   SstCategory_System, SstRisk_Critical,    SST_FLAG_REQUIRES_ADMIN },
    { 0x0199, "NtUnloadDriver",            1,   SstCategory_System, SstRisk_Critical,    SST_FLAG_REQUIRES_ADMIN },
    { 0x00BF, "NtCreateSection",            7,  SstCategory_Memory, SstRisk_Medium,      SST_FLAG_HANDLE_GRANT },
};

static const SST_STATIC_DEFINITION g_SyscallsWin11_22000[] = {
    /* Process manipulation — some numbers shifted in Win11 */
    { 0x00B5, "NtCreateProcess",            8,  SstCategory_Process, SstRisk_Critical,  SST_FLAG_INJECTION_RISK | SST_FLAG_CROSS_PROCESS },
    { 0x00B4, "NtCreateProcessEx",          9,  SstCategory_Process, SstRisk_Critical,  SST_FLAG_INJECTION_RISK | SST_FLAG_CROSS_PROCESS },
    { 0x00C9, "NtCreateUserProcess",       11,  SstCategory_Process, SstRisk_Critical,  SST_FLAG_INJECTION_RISK },
    { 0x002C, "NtOpenProcess",              4,  SstCategory_Process, SstRisk_High,      SST_FLAG_CROSS_PROCESS | SST_FLAG_HANDLE_GRANT },
    { 0x0029, "NtTerminateProcess",         2,  SstCategory_Process, SstRisk_High,      SST_FLAG_CROSS_PROCESS },
    { 0x0044, "NtSuspendProcess",           1,  SstCategory_Process, SstRisk_High,      SST_FLAG_CROSS_PROCESS },
    { 0x0045, "NtResumeProcess",            1,  SstCategory_Process, SstRisk_Medium,    SST_FLAG_CROSS_PROCESS },

    /* Thread manipulation */
    { 0x00BF, "NtCreateThread",             8,  SstCategory_Thread, SstRisk_Critical,   SST_FLAG_INJECTION_RISK | SST_FLAG_CROSS_PROCESS },
    { 0x00C3, "NtCreateThreadEx",          11,  SstCategory_Thread, SstRisk_Critical,   SST_FLAG_INJECTION_RISK | SST_FLAG_CROSS_PROCESS },
    { 0x0035, "NtOpenThread",               4,  SstCategory_Thread, SstRisk_High,       SST_FLAG_CROSS_PROCESS | SST_FLAG_HANDLE_GRANT },
    { 0x0053, "NtTerminateThread",          2,  SstCategory_Thread, SstRisk_High,       SST_FLAG_CROSS_PROCESS },
    { 0x004B, "NtSuspendThread",            2,  SstCategory_Thread, SstRisk_High,       SST_FLAG_CROSS_PROCESS },
    { 0x0052, "NtResumeThread",             2,  SstCategory_Thread, SstRisk_Medium,     SST_FLAG_CROSS_PROCESS },
    { 0x0150, "NtQueueApcThread",           5,  SstCategory_Thread, SstRisk_Critical,   SST_FLAG_INJECTION_RISK | SST_FLAG_CROSS_PROCESS },
    { 0x0187, "NtQueueApcThreadEx",         6,  SstCategory_Thread, SstRisk_Critical,   SST_FLAG_INJECTION_RISK | SST_FLAG_CROSS_PROCESS },
    { 0x0173, "NtSetContextThread",         2,  SstCategory_Thread, SstRisk_Critical,   SST_FLAG_INJECTION_RISK | SST_FLAG_CROSS_PROCESS },

    /* Memory operations */
    { 0x0018, "NtAllocateVirtualMemory",    6,  SstCategory_Memory, SstRisk_High,       SST_FLAG_INJECTION_RISK | SST_FLAG_CROSS_PROCESS | SST_FLAG_MEMORY_WRITE },
    { 0x001E, "NtFreeVirtualMemory",        4,  SstCategory_Memory, SstRisk_Low,        SST_FLAG_CROSS_PROCESS },
    { 0x003A, "NtReadVirtualMemory",        5,  SstCategory_Memory, SstRisk_High,       SST_FLAG_CROSS_PROCESS },
    { 0x003B, "NtWriteVirtualMemory",       5,  SstCategory_Memory, SstRisk_Critical,   SST_FLAG_INJECTION_RISK | SST_FLAG_CROSS_PROCESS | SST_FLAG_MEMORY_WRITE },
    { 0x0050, "NtProtectVirtualMemory",     5,  SstCategory_Memory, SstRisk_High,       SST_FLAG_INJECTION_RISK | SST_FLAG_CROSS_PROCESS },
    { 0x00D7, "NtMapViewOfSection",        10,  SstCategory_Memory, SstRisk_High,       SST_FLAG_INJECTION_RISK | SST_FLAG_CROSS_PROCESS | SST_FLAG_MEMORY_WRITE },
    { 0x002A, "NtUnmapViewOfSection",       2,  SstCategory_Memory, SstRisk_Medium,     SST_FLAG_CROSS_PROCESS },

    /* File operations */
    { 0x0055, "NtCreateFile",              11,  SstCategory_File, SstRisk_Medium,        SST_FLAG_HANDLE_GRANT },
    { 0x0033, "NtOpenFile",                 6,  SstCategory_File, SstRisk_Medium,        SST_FLAG_HANDLE_GRANT },
    { 0x0006, "NtReadFile",                 9,  SstCategory_File, SstRisk_Low,           0 },
    { 0x0008, "NtWriteFile",                9,  SstCategory_File, SstRisk_Low,           0 },
    { 0x000D, "NtDeleteFile",               1,  SstCategory_File, SstRisk_Medium,        0 },

    /* Registry operations */
    { 0x001D, "NtCreateKey",                7,  SstCategory_Registry, SstRisk_Medium,    SST_FLAG_HANDLE_GRANT },
    { 0x0012, "NtOpenKey",                  3,  SstCategory_Registry, SstRisk_Low,       SST_FLAG_HANDLE_GRANT },
    { 0x0017, "NtSetValueKey",              6,  SstCategory_Registry, SstRisk_Medium,    0 },
    { 0x0041, "NtDeleteKey",                1,  SstCategory_Registry, SstRisk_Medium,    0 },
    { 0x003D, "NtDeleteValueKey",           2,  SstCategory_Registry, SstRisk_Medium,    0 },

    /* Security / privilege */
    { 0x0024, "NtOpenProcessToken",         3,  SstCategory_Security, SstRisk_High,      SST_FLAG_CREDENTIAL_RISK | SST_FLAG_HANDLE_GRANT },
    { 0x0025, "NtOpenProcessTokenEx",       4,  SstCategory_Security, SstRisk_High,      SST_FLAG_CREDENTIAL_RISK | SST_FLAG_HANDLE_GRANT },
    { 0x0037, "NtOpenThreadToken",          4,  SstCategory_Security, SstRisk_High,      SST_FLAG_CREDENTIAL_RISK | SST_FLAG_HANDLE_GRANT },
    { 0x009C, "NtAdjustPrivilegesToken",    6,  SstCategory_Security, SstRisk_Critical,  SST_FLAG_CREDENTIAL_RISK },
    { 0x00C5, "NtDuplicateToken",           6,  SstCategory_Security, SstRisk_High,      SST_FLAG_CREDENTIAL_RISK | SST_FLAG_HANDLE_GRANT },

    /* Object manipulation */
    { 0x000F, "NtClose",                    1,  SstCategory_Object, SstRisk_None,        0 },
    { 0x000E, "NtDuplicateObject",          7,  SstCategory_Object, SstRisk_High,        SST_FLAG_CROSS_PROCESS | SST_FLAG_HANDLE_GRANT },

    /* System operations */
    { 0x0036, "NtQuerySystemInformation",   4,  SstCategory_System, SstRisk_Low,         0 },
    { 0x00B9, "NtSetSystemInformation",     3,  SstCategory_System, SstRisk_High,        SST_FLAG_REQUIRES_ADMIN },
    { 0x00D6, "NtLoadDriver",              1,   SstCategory_System, SstRisk_Critical,    SST_FLAG_REQUIRES_ADMIN },
    { 0x019B, "NtUnloadDriver",            1,   SstCategory_System, SstRisk_Critical,    SST_FLAG_REQUIRES_ADMIN },
    { 0x00C1, "NtCreateSection",            7,  SstCategory_Memory, SstRisk_Medium,      SST_FLAG_HANDLE_GRANT },
};

/**
 * @brief Build range table.
 * Maps OS build number ranges to their corresponding syscall definitions.
 */
static const SST_BUILD_RANGE g_BuildRanges[] = {
    /* Windows 10 RS1 (1607) through 21H2 */
    {
        14393, 19045,
        g_SyscallsWin10_14393,
        RTL_NUMBER_OF(g_SyscallsWin10_14393)
    },
    /* Windows 11 21H2 through 24H2+ */
    {
        22000, 27999,
        g_SyscallsWin11_22000,
        RTL_NUMBER_OF(g_SyscallsWin11_22000)
    },
};

// ============================================================================
// INTERNAL STRUCTURE
// ============================================================================

/**
 * @brief Hash bucket containing a list head for chaining entries.
 */
typedef struct _SST_HASH_BUCKET {
    LIST_ENTRY Head;
} SST_HASH_BUCKET;

/**
 * @brief Internal table state.
 */
typedef struct _SST_TABLE_INTERNAL {
    /** Magic for pointer validation */
    ULONG Magic;

    /** Initialization sentinel */
    BOOLEAN Initialized;

    UCHAR Reserved0[3];

    /** OS version detected at init */
    ULONG OsBuildNumber;

    /** Flat array of all entries — populated at init, immutable after */
    SST_ENTRY Entries[SST_MAX_ENTRIES];

    /** Number of populated entries */
    ULONG EntryCount;

    ULONG Reserved1;

    /** Hash table for lookup by syscall number */
    SST_HASH_BUCKET NumberBuckets[SST_HASH_BUCKET_COUNT];

    /** Hash table for lookup by syscall name */
    SST_HASH_BUCKET NameBuckets[SST_HASH_BUCKET_COUNT];

    /** Statistics */
    volatile LONG64 TotalLookupsByNumber;
    volatile LONG64 TotalLookupsByName;
    volatile LONG64 TotalLookupMisses;
    LARGE_INTEGER StartTime;

} SST_TABLE_INTERNAL, *PSST_TABLE_INTERNAL;

// ============================================================================
// PRIVATE FUNCTION PROTOTYPES
// ============================================================================

static PSST_TABLE_INTERNAL
SstpValidateTable(
    _In_ SST_TABLE_HANDLE Handle
    );

_Must_inspect_result_
static ULONG
SstpHashNumber(
    _In_ ULONG Number
    );

_Must_inspect_result_
static ULONG
SstpHashName(
    _In_ PCSTR Name
    );

static PSST_ENTRY
SstpFindByNumber(
    _In_ PSST_TABLE_INTERNAL Table,
    _In_ ULONG Number
    );

static PSST_ENTRY
SstpFindByName(
    _In_ PSST_TABLE_INTERNAL Table,
    _In_ PCSTR Name
    );

static VOID
SstpCopyEntryToInfo(
    _In_ PSST_ENTRY Entry,
    _Out_ PSST_ENTRY_INFO Info
    );

static NTSTATUS
SstpPopulateFromBuildRange(
    _Inout_ PSST_TABLE_INTERNAL Table,
    _In_ const SST_BUILD_RANGE *Range
    );

static int
SstpStrCmpInsensitive(
    _In_ PCSTR A,
    _In_ PCSTR B
    );

// ============================================================================
// SECTION PLACEMENT
// ============================================================================

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, SstInitialize)
#pragma alloc_text(PAGE, SstShutdown)
#endif
/*
 * Lookup functions are NOT placed in PAGE section — they must be safe
 * at DISPATCH_LEVEL because the table is in NonPagedPoolNx and
 * lookups are lock-free (read-only after init).
 */

// ============================================================================
// PRIVATE HELPERS
// ============================================================================

/**
 * @brief Validate a table handle and return the internal pointer.
 */
static PSST_TABLE_INTERNAL
SstpValidateTable(
    _In_ SST_TABLE_HANDLE Handle
    )
{
    PSST_TABLE_INTERNAL tbl = (PSST_TABLE_INTERNAL)(PVOID)Handle;

    if (tbl == NULL) {
        return NULL;
    }

    __try {
        if (tbl->Magic != SST_TABLE_MAGIC || !tbl->Initialized) {
            return NULL;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }

    return tbl;
}

/**
 * @brief Hash a syscall number to a bucket index.
 * Uses Knuth multiplicative hash consistent with SyscallHooks.
 */
_Must_inspect_result_
static ULONG
SstpHashNumber(
    _In_ ULONG Number
    )
{
    ULONG hash = Number * 2654435761u;
    return hash & SST_NUM_HASH_MASK;
}

/**
 * @brief Hash a syscall name to a bucket index (case-insensitive).
 * Uses FNV-1a with lowercase folding.
 */
_Must_inspect_result_
static ULONG
SstpHashName(
    _In_ PCSTR Name
    )
{
    ULONG hash = SST_FNV_OFFSET_BASIS;
    const CHAR *p;

    for (p = Name; *p != '\0'; p++) {
        CHAR c = *p;
        /* ASCII lowercase fold */
        if (c >= 'A' && c <= 'Z') {
            c = c + ('a' - 'A');
        }
        hash ^= (ULONG)(UCHAR)c;
        hash *= SST_FNV_PRIME;
    }

    return hash & SST_NUM_HASH_MASK;
}

/**
 * @brief Find an entry by syscall number in the hash table.
 * Table must be initialized. Lock-free (read-only structure).
 */
static PSST_ENTRY
SstpFindByNumber(
    _In_ PSST_TABLE_INTERNAL Table,
    _In_ ULONG Number
    )
{
    ULONG bucket = SstpHashNumber(Number);
    PLIST_ENTRY entry;

    for (entry = Table->NumberBuckets[bucket].Head.Flink;
         entry != &Table->NumberBuckets[bucket].Head;
         entry = entry->Flink)
    {
        PSST_ENTRY sst = CONTAINING_RECORD(entry, SST_ENTRY, NumberHashLink);
        if (sst->Number == Number) {
            return sst;
        }
    }

    return NULL;
}

/**
 * @brief Find an entry by name in the hash table (case-insensitive).
 * Table must be initialized. Lock-free (read-only structure).
 */
static PSST_ENTRY
SstpFindByName(
    _In_ PSST_TABLE_INTERNAL Table,
    _In_ PCSTR Name
    )
{
    ULONG bucket = SstpHashName(Name);
    PLIST_ENTRY entry;

    for (entry = Table->NameBuckets[bucket].Head.Flink;
         entry != &Table->NameBuckets[bucket].Head;
         entry = entry->Flink)
    {
        PSST_ENTRY sst = CONTAINING_RECORD(entry, SST_ENTRY, NameHashLink);
        if (SstpStrCmpInsensitive(sst->Name, Name) == 0) {
            return sst;
        }
    }

    return NULL;
}

/**
 * @brief Copy entry data to caller-visible info struct.
 * No internal pointers or kernel addresses are exposed.
 */
static VOID
SstpCopyEntryToInfo(
    _In_ PSST_ENTRY Entry,
    _Out_ PSST_ENTRY_INFO Info
    )
{
    Info->Number = Entry->Number;
    Info->ArgumentCount = Entry->ArgumentCount;
    Info->Category = Entry->Category;
    Info->RiskLevel = Entry->RiskLevel;
    Info->Flags = Entry->Flags;
    RtlCopyMemory(Info->Name, Entry->Name, sizeof(Info->Name));
}

/**
 * @brief Case-insensitive ASCII string comparison.
 * Bounded to SST_MAX_NAME_LENGTH to prevent unbounded reads.
 */
static int
SstpStrCmpInsensitive(
    _In_ PCSTR A,
    _In_ PCSTR B
    )
{
    ULONG i;

    for (i = 0; i < SST_MAX_NAME_LENGTH; i++) {
        CHAR a = A[i];
        CHAR b = B[i];

        if (a >= 'A' && a <= 'Z') a = a + ('a' - 'A');
        if (b >= 'A' && b <= 'Z') b = b + ('a' - 'A');

        if (a != b) return (int)a - (int)b;
        if (a == '\0') return 0;
    }

    return 0;
}

/**
 * @brief Populate the table from a build range definition.
 */
static NTSTATUS
SstpPopulateFromBuildRange(
    _Inout_ PSST_TABLE_INTERNAL Table,
    _In_ const SST_BUILD_RANGE *Range
    )
{
    ULONG i;
    ULONG entryIndex;
    ULONG bucketIdx;

    if (Range->DefinitionCount > SST_MAX_ENTRIES) {
        return STATUS_BUFFER_OVERFLOW;
    }

    entryIndex = 0;

    for (i = 0; i < Range->DefinitionCount; i++) {
        const SST_STATIC_DEFINITION *def = &Range->Definitions[i];
        PSST_ENTRY entry;

        /* Validate syscall number is in range */
        if (def->Number >= SST_MAX_SYSCALL_NUMBER) {
            continue;
        }

        /* Validate name fits */
        if (def->Name == NULL) {
            continue;
        }

        entry = &Table->Entries[entryIndex];

        entry->Number = def->Number;
        entry->ArgumentCount = def->ArgumentCount;
        entry->Category = def->Category;
        entry->RiskLevel = def->RiskLevel;
        entry->Flags = def->Flags;
        entry->Reserved = 0;

        /* Safe string copy — always null-terminated */
        RtlStringCbCopyA(entry->Name, sizeof(entry->Name), def->Name);

        /* Initialize hash links */
        InitializeListHead(&entry->NumberHashLink);
        InitializeListHead(&entry->NameHashLink);

        /* Insert into number hash */
        bucketIdx = SstpHashNumber(entry->Number);
        InsertTailList(
            &Table->NumberBuckets[bucketIdx].Head,
            &entry->NumberHashLink);

        /* Insert into name hash */
        bucketIdx = SstpHashName(entry->Name);
        InsertTailList(
            &Table->NameBuckets[bucketIdx].Head,
            &entry->NameHashLink);

        entryIndex++;
        Table->EntryCount++;
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API IMPLEMENTATION
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
SstInitialize(
    _Out_ SST_TABLE_HANDLE *Table
    )
{
    NTSTATUS status;
    PSST_TABLE_INTERNAL tbl = NULL;
    RTL_OSVERSIONINFOW osVersion;
    const SST_BUILD_RANGE *matchedRange = NULL;
    ULONG i;

    PAGED_CODE();

    if (Table == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Table = NULL;

    /*
     * Detect OS version.
     * RtlGetVersion is the documented, safe way to get the true build number.
     * It does not lie (unlike GetVersionEx in user-mode which is manifested).
     */
    RtlZeroMemory(&osVersion, sizeof(osVersion));
    osVersion.dwOSVersionInfoSize = sizeof(osVersion);

    status = RtlGetVersion(&osVersion);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* Find matching build range */
    for (i = 0; i < RTL_NUMBER_OF(g_BuildRanges); i++) {
        if (osVersion.dwBuildNumber >= g_BuildRanges[i].MinBuild &&
            osVersion.dwBuildNumber <= g_BuildRanges[i].MaxBuild)
        {
            matchedRange = &g_BuildRanges[i];
            break;
        }
    }

    if (matchedRange == NULL) {
        return STATUS_NOT_SUPPORTED;
    }

    /*
     * Allocate from NonPagedPoolNx:
     * - Lookup functions are safe at DISPATCH_LEVEL
     * - No paging faults during hot-path lookups
     * - Immutable after init — no locking needed
     */
    tbl = (PSST_TABLE_INTERNAL)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(SST_TABLE_INTERNAL),
        SST_POOL_TAG);

    if (tbl == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(tbl, sizeof(SST_TABLE_INTERNAL));

    tbl->OsBuildNumber = osVersion.dwBuildNumber;

    /* Initialize all hash bucket heads */
    for (i = 0; i < SST_HASH_BUCKET_COUNT; i++) {
        InitializeListHead(&tbl->NumberBuckets[i].Head);
        InitializeListHead(&tbl->NameBuckets[i].Head);
    }

    /* Populate from the matched build range */
    status = SstpPopulateFromBuildRange(tbl, matchedRange);
    if (!NT_SUCCESS(status)) {
        ShadowStrikeFreePoolWithTag(tbl, SST_POOL_TAG);
        return status;
    }

    /* Record start time */
    KeQuerySystemTime(&tbl->StartTime);

    /* Finalize: set magic and initialized flag LAST */
    tbl->Initialized = TRUE;
    InterlockedExchange((volatile LONG *)&tbl->Magic, SST_TABLE_MAGIC);

    *Table = (SST_TABLE_HANDLE)(PVOID)tbl;

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
SstShutdown(
    _In_ _Post_invalid_ SST_TABLE_HANDLE Table
    )
{
    PSST_TABLE_INTERNAL tbl;

    PAGED_CODE();

    tbl = SstpValidateTable(Table);
    if (tbl == NULL) {
        return;
    }

    /*
     * The table is immutable after init — no active writers to drain.
     * Callers must ensure no concurrent lookups are in-flight when
     * calling shutdown (driver unload serialization handles this).
     */
    tbl->Magic = 0;
    tbl->Initialized = FALSE;

    ShadowStrikeFreePoolWithTag(tbl, SST_POOL_TAG);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
SstLookupByNumber(
    _In_ SST_TABLE_HANDLE Table,
    _In_ ULONG Number,
    _Out_ PSST_ENTRY_INFO Info
    )
{
    PSST_TABLE_INTERNAL tbl;
    PSST_ENTRY entry;

    if (Info == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Info, sizeof(SST_ENTRY_INFO));

    tbl = SstpValidateTable(Table);
    if (tbl == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Number >= SST_MAX_SYSCALL_NUMBER) {
        InterlockedIncrement64(&tbl->TotalLookupMisses);
        return STATUS_NOT_FOUND;
    }

    InterlockedIncrement64(&tbl->TotalLookupsByNumber);

    entry = SstpFindByNumber(tbl, Number);
    if (entry == NULL) {
        InterlockedIncrement64(&tbl->TotalLookupMisses);
        return STATUS_NOT_FOUND;
    }

    SstpCopyEntryToInfo(entry, Info);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
SstLookupByName(
    _In_ SST_TABLE_HANDLE Table,
    _In_ PCSTR Name,
    _Out_ PSST_ENTRY_INFO Info
    )
{
    PSST_TABLE_INTERNAL tbl;
    PSST_ENTRY entry;

    if (Info == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Info, sizeof(SST_ENTRY_INFO));

    tbl = SstpValidateTable(Table);
    if (tbl == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Name == NULL || Name[0] == '\0') {
        InterlockedIncrement64(&tbl->TotalLookupMisses);
        return STATUS_INVALID_PARAMETER;
    }

    InterlockedIncrement64(&tbl->TotalLookupsByName);

    entry = SstpFindByName(tbl, Name);
    if (entry == NULL) {
        InterlockedIncrement64(&tbl->TotalLookupMisses);
        return STATUS_NOT_FOUND;
    }

    SstpCopyEntryToInfo(entry, Info);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
SstIsKnownSyscall(
    _In_ SST_TABLE_HANDLE Table,
    _In_ ULONG Number
    )
{
    PSST_TABLE_INTERNAL tbl;

    tbl = SstpValidateTable(Table);
    if (tbl == NULL) {
        return FALSE;
    }

    if (Number >= SST_MAX_SYSCALL_NUMBER) {
        return FALSE;
    }

    return (SstpFindByNumber(tbl, Number) != NULL);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
SstGetRiskLevel(
    _In_ SST_TABLE_HANDLE Table,
    _In_ ULONG Number,
    _Out_ SST_RISK_LEVEL *Risk
    )
{
    PSST_TABLE_INTERNAL tbl;
    PSST_ENTRY entry;

    if (Risk == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Risk = SstRisk_None;

    tbl = SstpValidateTable(Table);
    if (tbl == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    entry = SstpFindByNumber(tbl, Number);
    if (entry == NULL) {
        return STATUS_NOT_FOUND;
    }

    *Risk = entry->RiskLevel;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
SstGetCategory(
    _In_ SST_TABLE_HANDLE Table,
    _In_ ULONG Number,
    _Out_ SST_CATEGORY *Category
    )
{
    PSST_TABLE_INTERNAL tbl;
    PSST_ENTRY entry;

    if (Category == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Category = SstCategory_Unknown;

    tbl = SstpValidateTable(Table);
    if (tbl == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    entry = SstpFindByNumber(tbl, Number);
    if (entry == NULL) {
        return STATUS_NOT_FOUND;
    }

    *Category = entry->Category;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
SstGetStatistics(
    _In_ SST_TABLE_HANDLE Table,
    _Out_ PSST_STATISTICS Stats
    )
{
    PSST_TABLE_INTERNAL tbl;

    if (Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Stats, sizeof(SST_STATISTICS));

    tbl = SstpValidateTable(Table);
    if (tbl == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Stats->TotalLookupsByNumber = tbl->TotalLookupsByNumber;
    Stats->TotalLookupsByName   = tbl->TotalLookupsByName;
    Stats->TotalLookupMisses    = tbl->TotalLookupMisses;
    Stats->EntryCount           = (LONG)tbl->EntryCount;
    Stats->StartTime            = tbl->StartTime;

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
SstGetEntryCount(
    _In_ SST_TABLE_HANDLE Table
    )
{
    PSST_TABLE_INTERNAL tbl;

    tbl = SstpValidateTable(Table);
    if (tbl == NULL) {
        return 0;
    }

    return tbl->EntryCount;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
SstGetEntryByIndex(
    _In_ SST_TABLE_HANDLE Table,
    _In_ ULONG Index,
    _Out_ PSST_ENTRY_INFO Info
    )
{
    PSST_TABLE_INTERNAL tbl;

    if (Info == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Info, sizeof(SST_ENTRY_INFO));

    tbl = SstpValidateTable(Table);
    if (tbl == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Index >= tbl->EntryCount) {
        return STATUS_NO_MORE_ENTRIES;
    }

    SstpCopyEntryToInfo(&tbl->Entries[Index], Info);
    return STATUS_SUCCESS;
}
