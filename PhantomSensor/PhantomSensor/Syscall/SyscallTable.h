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
 * @file SyscallTable.h
 * @brief Enterprise-grade syscall number resolution and table management.
 *
 * This module provides the authoritative mapping between:
 * - Syscall numbers (OS-version-specific)
 * - Syscall names (NtXxx / ZwXxx)
 * - Argument counts
 * - Classification metadata (category, risk level)
 *
 * Architectural Role:
 * - SyscallTable owns the DATA (syscall number ↔ name ↔ metadata)
 * - SyscallHooks owns the MECHANISM (register, dispatch, lifecycle)
 * - SyscallMonitor owns the POLICY (what to monitor, analysis, decisions)
 *
 * Design Principles:
 * - Syscall numbers are OS-build-specific and resolved dynamically
 *   at initialization from a hardcoded table indexed by build range.
 * - NO user-mode memory access (no ntdll parsing, no process attachment).
 *   Syscall numbers are derived from known Windows build tables.
 * - NO raw SSDT pointers stored or exposed (KASLR protection).
 * - Hash-based O(1) lookup by both number and name.
 * - Read-mostly structure: populated once at init, immutable after.
 *   No write-side locking needed for lookups.
 * - All lookups are safe at IRQL <= DISPATCH_LEVEL (NonPagedPoolNx).
 *
 * Security:
 * - No kernel address disclosure to callers.
 * - No user-mode memory reads.
 * - Immutable after initialization — no TOCTOU.
 * - Bounded table size — no resource exhaustion.
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef _SHADOWSTRIKE_SYSCALL_TABLE_H_
#define _SHADOWSTRIKE_SYSCALL_TABLE_H_

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntifs.h>
#include <ntddk.h>

// ============================================================================
// POOL TAGS & CONSTANTS
// ============================================================================

/** @brief Pool tag for SyscallTable allocations: 'SsTb' (little-endian) */
#define SST_POOL_TAG                        'bTsS'

/** @brief Pool tag for hash bucket arrays */
#define SST_HASH_TAG                        'hTsS'

/**
 * @brief Maximum number of syscall entries the table can hold.
 * Covers all known Windows 10/11 x64 syscalls with headroom.
 */
#define SST_MAX_ENTRIES                     512

/**
 * @brief Maximum syscall number value accepted.
 * Must match SH_MAX_SYSCALL_NUMBER from SyscallHooks.h.
 */
#define SST_MAX_SYSCALL_NUMBER              0x1000

/**
 * @brief Hash bucket count for number and name lookups.
 * Must be power of 2 for mask-based indexing.
 */
#define SST_HASH_BUCKET_COUNT               128

/** @brief Maximum syscall name length (including NUL terminator) */
#define SST_MAX_NAME_LENGTH                 64

/** @brief Table magic for pointer validation */
#define SST_TABLE_MAGIC                     0x53545442  /* 'STTB' */

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Syscall functional category.
 */
typedef enum _SST_CATEGORY {
    SstCategory_Unknown     = 0,
    SstCategory_Process     = 1,    /**< Process creation/manipulation */
    SstCategory_Thread      = 2,    /**< Thread creation/manipulation */
    SstCategory_Memory      = 3,    /**< Virtual memory operations */
    SstCategory_File        = 4,    /**< File system operations */
    SstCategory_Registry    = 5,    /**< Registry operations */
    SstCategory_Object      = 6,    /**< Object manager operations */
    SstCategory_Security    = 7,    /**< Token/privilege/security */
    SstCategory_System      = 8,    /**< System information/config */
    SstCategory_Network     = 9,    /**< Network operations */
    SstCategory_Synchronization = 10, /**< Wait/signal operations */
    SstCategory_Max
} SST_CATEGORY;

/**
 * @brief Syscall risk classification for security monitoring.
 */
typedef enum _SST_RISK_LEVEL {
    SstRisk_None        = 0,    /**< Not security-relevant */
    SstRisk_Low         = 1,    /**< Informational */
    SstRisk_Medium      = 2,    /**< May indicate suspicious activity */
    SstRisk_High        = 3,    /**< Commonly abused by malware */
    SstRisk_Critical    = 4,    /**< Primary attack vector (injection, privesc) */
} SST_RISK_LEVEL;

/**
 * @brief Flags describing syscall security properties.
 */
#define SST_FLAG_INJECTION_RISK             0x00000001  /**< Can be used for injection */
#define SST_FLAG_CREDENTIAL_RISK            0x00000002  /**< Can access credentials */
#define SST_FLAG_EVASION_RISK               0x00000004  /**< Used for defense evasion */
#define SST_FLAG_CROSS_PROCESS              0x00000008  /**< Can operate on other processes */
#define SST_FLAG_REQUIRES_ADMIN             0x00000010  /**< Normally requires elevation */
#define SST_FLAG_MEMORY_WRITE               0x00000020  /**< Can write to process memory */
#define SST_FLAG_HANDLE_GRANT               0x00000040  /**< Grants a handle with access rights */

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Syscall entry — immutable after table initialization.
 *
 * Contains all metadata for a single syscall. Stored in a flat array
 * and referenced by hash bucket chains via two separate LIST_ENTRY fields.
 */
typedef struct _SST_ENTRY {
    /** Syscall number (specific to OS build) */
    ULONG Number;

    /** Number of arguments */
    ULONG ArgumentCount;

    /** NtXxx name (null-terminated ASCII) */
    CHAR Name[SST_MAX_NAME_LENGTH];

    /** Functional category */
    SST_CATEGORY Category;

    /** Security risk level */
    SST_RISK_LEVEL RiskLevel;

    /** Security property flags (SST_FLAG_*) */
    ULONG Flags;

    /** Reserved for future use */
    ULONG Reserved;

    /** Link in number-hash bucket chain */
    LIST_ENTRY NumberHashLink;

    /** Link in name-hash bucket chain */
    LIST_ENTRY NameHashLink;

} SST_ENTRY, *PSST_ENTRY;

/**
 * @brief Opaque handle to the syscall table.
 * Allocated by SstInitialize, freed by SstShutdown.
 */
DECLARE_HANDLE(SST_TABLE_HANDLE);

/**
 * @brief Read-only view of a syscall entry returned to callers.
 * Contains no kernel addresses or sensitive internal data.
 */
typedef struct _SST_ENTRY_INFO {
    ULONG Number;
    ULONG ArgumentCount;
    CHAR Name[SST_MAX_NAME_LENGTH];
    SST_CATEGORY Category;
    SST_RISK_LEVEL RiskLevel;
    ULONG Flags;
} SST_ENTRY_INFO, *PSST_ENTRY_INFO;

/**
 * @brief Syscall table statistics (read-only snapshot).
 */
typedef struct _SST_STATISTICS {
    LONG64 TotalLookupsByNumber;
    LONG64 TotalLookupsByName;
    LONG64 TotalLookupMisses;
    LONG EntryCount;
    LARGE_INTEGER StartTime;
} SST_STATISTICS, *PSST_STATISTICS;

// ============================================================================
// PUBLIC API — LIFECYCLE
// ============================================================================

/**
 * @brief Initialize the syscall table for the current OS build.
 *
 * Detects the OS version via RtlGetVersion, selects the appropriate
 * syscall number table, populates entries, and builds hash indices.
 * The table is immutable after this call.
 *
 * @param[out] Table    Receives the table handle on success.
 * @return STATUS_SUCCESS on success.
 * @return STATUS_INVALID_PARAMETER if Table is NULL.
 * @return STATUS_NOT_SUPPORTED if the OS build is not recognized.
 * @return STATUS_INSUFFICIENT_RESOURCES if allocation fails.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
SstInitialize(
    _Out_ SST_TABLE_HANDLE *Table
    );

/**
 * @brief Shut down and free the syscall table.
 *
 * @param[in] Table     Table handle from SstInitialize.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
SstShutdown(
    _In_ _Post_invalid_ SST_TABLE_HANDLE Table
    );

// ============================================================================
// PUBLIC API — LOOKUPS
// ============================================================================

/**
 * @brief Look up a syscall entry by number.
 *
 * Returns a copy of the entry info (no internal pointers exposed).
 *
 * @param[in]  Table    Table handle.
 * @param[in]  Number   Syscall number.
 * @param[out] Info     Receives the entry info.
 * @return STATUS_SUCCESS if found.
 * @return STATUS_NOT_FOUND if the number is not in the table.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
SstLookupByNumber(
    _In_ SST_TABLE_HANDLE Table,
    _In_ ULONG Number,
    _Out_ PSST_ENTRY_INFO Info
    );

/**
 * @brief Look up a syscall entry by name (case-insensitive).
 *
 * @param[in]  Table    Table handle.
 * @param[in]  Name     Null-terminated NtXxx name.
 * @param[out] Info     Receives the entry info.
 * @return STATUS_SUCCESS if found.
 * @return STATUS_NOT_FOUND if the name is not in the table.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
SstLookupByName(
    _In_ SST_TABLE_HANDLE Table,
    _In_ PCSTR Name,
    _Out_ PSST_ENTRY_INFO Info
    );

/**
 * @brief Check if a syscall number is known to the table.
 *
 * @param[in] Table     Table handle.
 * @param[in] Number    Syscall number.
 * @return TRUE if known, FALSE otherwise.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
SstIsKnownSyscall(
    _In_ SST_TABLE_HANDLE Table,
    _In_ ULONG Number
    );

/**
 * @brief Get the risk level for a syscall number.
 *
 * @param[in]  Table    Table handle.
 * @param[in]  Number   Syscall number.
 * @param[out] Risk     Receives the risk level.
 * @return STATUS_SUCCESS if found.
 * @return STATUS_NOT_FOUND if unknown.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
SstGetRiskLevel(
    _In_ SST_TABLE_HANDLE Table,
    _In_ ULONG Number,
    _Out_ SST_RISK_LEVEL *Risk
    );

/**
 * @brief Get the category for a syscall number.
 *
 * @param[in]  Table    Table handle.
 * @param[in]  Number   Syscall number.
 * @param[out] Category Receives the category.
 * @return STATUS_SUCCESS if found.
 * @return STATUS_NOT_FOUND if unknown.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
SstGetCategory(
    _In_ SST_TABLE_HANDLE Table,
    _In_ ULONG Number,
    _Out_ SST_CATEGORY *Category
    );

// ============================================================================
// PUBLIC API — STATISTICS
// ============================================================================

/**
 * @brief Get a snapshot of table statistics.
 *
 * @param[in]  Table    Table handle.
 * @param[out] Stats    Receives the statistics.
 * @return STATUS_SUCCESS on success.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
SstGetStatistics(
    _In_ SST_TABLE_HANDLE Table,
    _Out_ PSST_STATISTICS Stats
    );

// ============================================================================
// PUBLIC API — ENUMERATION
// ============================================================================

/**
 * @brief Get the number of entries in the table.
 *
 * @param[in] Table     Table handle.
 * @return Entry count, or 0 if table is invalid.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
SstGetEntryCount(
    _In_ SST_TABLE_HANDLE Table
    );

/**
 * @brief Get an entry by index (for enumeration).
 *
 * @param[in]  Table    Table handle.
 * @param[in]  Index    Zero-based index (0..SstGetEntryCount()-1).
 * @param[out] Info     Receives the entry info.
 * @return STATUS_SUCCESS if valid index.
 * @return STATUS_NO_MORE_ENTRIES if index is out of range.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
SstGetEntryByIndex(
    _In_ SST_TABLE_HANDLE Table,
    _In_ ULONG Index,
    _Out_ PSST_ENTRY_INFO Info
    );

#ifdef __cplusplus
}
#endif

#endif /* _SHADOWSTRIKE_SYSCALL_TABLE_H_ */
