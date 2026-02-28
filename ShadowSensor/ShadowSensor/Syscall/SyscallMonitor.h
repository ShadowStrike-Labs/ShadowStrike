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
 * ShadowStrike NGAV - SYSCALL MONITOR
 * ============================================================================
 *
 * @file SyscallMonitor.h
 * @brief Syscall monitoring orchestration layer for ShadowSensor kernel driver.
 *
 * This module is the top-level coordinator for syscall monitoring. It delegates
 * to the specialized subsystems (SyscallTable, SyscallHooks, DirectSyscallDetector)
 * and provides:
 * - Unified syscall analysis entry point
 * - Per-process syscall context tracking with reference counting
 * - NTDLL integrity verification
 * - Call stack anomaly analysis
 * - Behavioral event emission for direct syscall / Heaven's Gate detections
 * - Process lifecycle integration (create/destroy tracking)
 *
 * Thread Safety:
 * - All public APIs are safe to call from PASSIVE_LEVEL.
 * - Process contexts are reference-counted. Callers MUST pair
 *   ScMonitorGetProcessContext with ScMonitorReleaseProcessContext.
 * - Context removal marks the context as "removed" and the last Release
 *   call performs the actual free (deferred-deletion pattern).
 *
 * Object Lifetime:
 * - SC_PROCESS_CONTEXT.ProcessObject is referenced via ObReferenceObject
 *   at creation and dereferenced via ObDereferenceObject on final release.
 *
 * Memory:
 * - SYSCALL_CALL_CONTEXT is ~800 bytes. Callers on hot paths MUST allocate
 *   from pool (or use the EventLookaside), NOT from stack.
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef SHADOWSTRIKE_SYSCALL_MONITOR_H
#define SHADOWSTRIKE_SYSCALL_MONITOR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include "../../Shared/BehaviorTypes.h"
#include "SyscallTable.h"
#include "DirectSyscallDetector.h"
#include "SyscallHooks.h"
#include "NtdllIntegrity.h"
#include "HeavensGateDetector.h"
#include "CallstackAnalyzer.h"

// ============================================================================
// SYSCALL MONITOR CONFIGURATION
// ============================================================================

/**
 * @brief Pool tags.
 */
#define SC_POOL_TAG_GENERAL     'cSsS'
#define SC_POOL_TAG_CACHE       'hSsS'
#define SC_POOL_TAG_EVENT       'eSsS'

/**
 * @brief Syscall numbers for critical APIs (Windows 10/11 x64).
 * Note: These vary by build and must be resolved dynamically.
 */
#define SC_MAX_SYSCALL_NUMBER       0x1000
#define SC_MAX_MONITORED_SYSCALLS   256

// ============================================================================
// SYSCALL CLASSIFICATION
// ============================================================================

/**
 * @brief Syscall risk category.
 */
typedef enum _SYSCALL_RISK_CATEGORY {
    SyscallRisk_None = 0,
    SyscallRisk_Low,
    SyscallRisk_Medium,
    SyscallRisk_High,
    SyscallRisk_Critical
} SYSCALL_RISK_CATEGORY;

/**
 * @brief Syscall category.
 */
typedef enum _SYSCALL_CATEGORY {
    SyscallCategory_Unknown = 0,
    SyscallCategory_Process,              // Process manipulation
    SyscallCategory_Thread,               // Thread manipulation
    SyscallCategory_Memory,               // Memory operations
    SyscallCategory_File,                 // File operations
    SyscallCategory_Registry,             // Registry operations
    SyscallCategory_Object,               // Object manipulation
    SyscallCategory_Security,             // Security operations
    SyscallCategory_System,               // System operations
    SyscallCategory_Network,              // Network operations
    SyscallCategory_Max
} SYSCALL_CATEGORY;

// ============================================================================
// SYSCALL INFORMATION
// ============================================================================

/**
 * @brief Syscall definition entry.
 */
typedef struct _SYSCALL_DEFINITION {
    UINT32 SyscallNumber;
    CHAR SyscallName[64];
    SYSCALL_CATEGORY Category;
    SYSCALL_RISK_CATEGORY RiskCategory;
    UINT32 ArgumentCount;
    UINT32 Flags;
    UINT32 BaselineCount;                 // Expected normal call rate
    UINT32 Reserved;
} SYSCALL_DEFINITION, *PSYSCALL_DEFINITION;

// Syscall flags
#define SC_FLAG_CRITICAL                  0x00000001  // Critical security API
#define SC_FLAG_INJECTION_RISK            0x00000002  // Can be used for injection
#define SC_FLAG_CREDENTIAL_RISK           0x00000004  // Can access credentials
#define SC_FLAG_EVASION_RISK              0x00000008  // Used for evasion
#define SC_FLAG_MONITOR_ARGS              0x00000010  // Monitor arguments
#define SC_FLAG_MONITOR_CALLER            0x00000020  // Monitor caller address
#define SC_FLAG_REQUIRES_ELEVATION        0x00000040  // Normally requires elevation
#define SC_FLAG_CROSS_PROCESS             0x00000080  // Can operate cross-process

/**
 * @brief Syscall call context.
 */
typedef struct _SYSCALL_CALL_CONTEXT {
    // Syscall info
    UINT32 SyscallNumber;
    UINT64 Timestamp;
    
    // Caller info
    UINT32 ProcessId;
    UINT32 ThreadId;
    UINT64 ReturnAddress;                 // Immediate return address
    UINT64 CallerModuleBase;              // Module containing caller
    UINT64 CallerModuleSize;
    
    // Module info
    BOOLEAN IsFromNtdll;
    BOOLEAN IsFromKnownModule;
    BOOLEAN IsSuspiciousRegion;
    BOOLEAN IsFromWoW64;
    UINT32 Reserved;
    
    WCHAR CallerModuleName[MAX_PROCESS_NAME_LENGTH];
    
    // Arguments (first 8)
    UINT64 Arguments[8];
    UINT32 ArgumentCount;
    
    // Stack analysis
    UINT64 StackPointer;
    UINT64 StackBase;
    UINT64 StackFrames[16];
    UINT32 StackFrameCount;
    
    // Analysis results
    UINT32 ThreatScore;
    UINT32 DetectionFlags;
} SYSCALL_CALL_CONTEXT, *PSYSCALL_CALL_CONTEXT;

// Detection flags
#define SC_DETECT_DIRECT_SYSCALL          0x00000001  // Not from ntdll
#define SC_DETECT_HEAVENS_GATE            0x00000002  // WoW64 abuse
#define SC_DETECT_UNBACKED_CALLER         0x00000004  // From unbacked memory
#define SC_DETECT_SUSPICIOUS_ARGS         0x00000008  // Suspicious arguments
#define SC_DETECT_UNUSUAL_CALLER          0x00000010  // Unusual calling module
#define SC_DETECT_STACK_ANOMALY           0x00000020  // Stack anomaly
#define SC_DETECT_CROSS_PROCESS           0x00000040  // Cross-process operation
#define SC_DETECT_SHELLCODE_CALLER        0x00000080  // Caller looks like shellcode
#define SC_DETECT_HOOK_BYPASS             0x00000100  // Bypassing hooks

// ============================================================================
// NTDLL INTEGRITY
// ============================================================================

/**
 * @brief NTDLL integrity state.
 */
typedef struct _NTDLL_INTEGRITY_STATE {
    UINT64 NtdllBase;
    UINT64 NtdllSize;
    UINT64 TextSectionBase;
    UINT64 TextSectionSize;
    UINT8 TextSectionHash[32];            // SHA-256 of .text
    UINT64 LastVerifyTime;
    BOOLEAN IsIntact;
    BOOLEAN IsHooked;
    UINT16 HookedFunctionCount;
    UINT32 Reserved;
} NTDLL_INTEGRITY_STATE, *PNTDLL_INTEGRITY_STATE;

/**
 * @brief Hooked function entry.
 */
typedef struct _HOOKED_FUNCTION_ENTRY {
    CHAR FunctionName[64];
    UINT64 OriginalAddress;
    UINT64 CurrentAddress;
    UINT64 HookDestination;
    UINT32 HookType;                      // HOOK_TYPE
    UINT32 Reserved;
} HOOKED_FUNCTION_ENTRY, *PHOOKED_FUNCTION_ENTRY;

// Hook types
typedef enum _HOOK_TYPE {
    HookType_None = 0,
    HookType_InlineJmp,                   // JMP instruction
    HookType_InlineCall,                  // CALL instruction
    HookType_IAT,                         // Import Address Table
    HookType_EAT,                         // Export Address Table
    HookType_VTable,                      // Virtual function table
    HookType_Trampoline,                  // Trampoline hook
    HookType_Max
} HOOK_TYPE;

// ============================================================================
// PROCESS SYSCALL CONTEXT
// ============================================================================

/**
 * @brief Maximum suspicious caller cache entries.
 */
#define SC_MAX_SUSPICIOUS_CALLERS         64

/**
 * @brief Per-process syscall monitoring context.
 *
 * Lifetime:
 * - Created via ScMonitorGetProcessContext (auto-creates if absent).
 * - ProcessObject is ObReferenceObject'd at creation; dereferenced on final release.
 * - Reference-counted. Callers MUST pair Get with Release.
 * - ScMonitorRemoveProcessContext sets the Removed flag and unlinks from the list.
 *   The last ScMonitorReleaseProcessContext call performs the actual free.
 *
 * SyscallCounts[] indexing:
 * - Indexed by a lookup index [0..MonitoredSyscallCount), NOT by raw syscall number.
 *   The implementation maintains a mapping from syscall number to index via the
 *   SyscallTable module.
 */
typedef struct _SC_PROCESS_CONTEXT {
    LIST_ENTRY ListEntry;

    // Process identification
    UINT32 ProcessId;
    PEPROCESS ProcessObject;              // ObReferenceObject'd; deref on final release
    UINT64 ProcessCreateTime;
    BOOLEAN IsWoW64;
    BOOLEAN Removed;                      // Set when unlinked; last Release frees
    UINT8 Reserved[2];

    // NTDLL info for this process
    UINT64 NtdllBase;
    UINT64 NtdllSize;
    UINT64 Wow64NtdllBase;                // For WoW64 processes
    UINT64 Wow64NtdllSize;

    // Statistics (interlocked updates)
    volatile LONG64 TotalSyscalls;
    volatile LONG64 DirectSyscalls;       // Not from ntdll
    volatile LONG64 SuspiciousSyscalls;
    UINT32 UniqueCallers;
    UINT32 Flags;

    // Per-syscall counts (indexed by monitored-syscall index, not raw number)
    UINT32 SyscallCounts[SC_MAX_MONITORED_SYSCALLS];
    UINT32 MonitoredSyscallCount;

    // Suspicious callers circular buffer
    UINT64 SuspiciousCallers[SC_MAX_SUSPICIOUS_CALLERS];
    UINT32 SuspiciousCallerCount;         // Total added (wraps; index = Count % MAX)

    // Integrity state
    NTDLL_INTEGRITY_STATE NtdllIntegrity;

    // Reference counting (interlocked)
    volatile LONG RefCount;
} SC_PROCESS_CONTEXT, *PSC_PROCESS_CONTEXT;

// Process flags
#define SC_PROC_FLAG_MONITORED            0x00000001
#define SC_PROC_FLAG_HIGH_RISK            0x00000002
#define SC_PROC_FLAG_DIRECT_SYSCALLS      0x00000004
#define SC_PROC_FLAG_NTDLL_MODIFIED       0x00000008
#define SC_PROC_FLAG_HEAVENS_GATE         0x00000010

// ============================================================================
// SYSCALL MONITOR GLOBAL STATE
// ============================================================================

/**
 * @brief Maximum process contexts to track concurrently.
 */
#define SC_MAX_PROCESS_CONTEXTS           8192

/**
 * @brief Maximum known good caller cache entries.
 */
#define SC_MAX_KNOWN_GOOD_CALLERS         4096

/**
 * @brief Known good caller cache entry.
 */
typedef struct _SC_KNOWN_GOOD_CALLER {
    LIST_ENTRY ListEntry;
    UINT64 CallerAddress;
    UINT64 ModuleBase;
    UINT64 ModuleSize;
    WCHAR ModuleName[64];
    UINT64 AddedTimestamp;
} SC_KNOWN_GOOD_CALLER, *PSC_KNOWN_GOOD_CALLER;

/**
 * @brief Syscall monitor global state (INTERNAL — never exposed to callers).
 *
 * Synchronization:
 * - ProcessLock: EX_PUSH_LOCK protecting ProcessContextList.
 * - CallerCacheLock: EX_PUSH_LOCK protecting KnownGoodCallers.
 * - Both require KeEnterCriticalRegion before acquisition.
 */
typedef struct _SYSCALL_MONITOR_GLOBALS {
    // Initialization state
    BOOLEAN Initialized;
    BOOLEAN Enabled;
    volatile LONG ShuttingDown;

    // Magic for validation
    ULONG Magic;

    // Syscall table (delegated to SyscallTable module)
    SST_TABLE_HANDLE SyscallTableHandle;

    // Direct syscall detector (delegated)
    PDSD_DETECTOR DirectSyscallDetector;

    // NtDll integrity monitor (delegated)
    PNI_MONITOR NtdllIntegrityMonitor;

    // Heaven's Gate detector (delegated)
    PHGD_DETECTOR HeavensGateDetector;

    // Call stack analyzer (delegated)
    PCSA_ANALYZER CallstackAnalyzer;

    // Syscall hooks framework (delegated)
    SH_FRAMEWORK_HANDLE SyscallHooksFramework;

    // System NTDLL reference
    UINT64 SystemNtdllBase;
    UINT64 SystemNtdllSize;
    UINT8 SystemNtdllHash[32];

    // Process contexts
    LIST_ENTRY ProcessContextList;
    EX_PUSH_LOCK ProcessLock;
    volatile LONG ProcessContextCount;

    // Known good caller cache
    LIST_ENTRY KnownGoodCallers;
    EX_PUSH_LOCK CallerCacheLock;
    volatile LONG KnownGoodCallerCount;

    // Lookaside lists
    NPAGED_LOOKASIDE_LIST ContextLookaside;
    BOOLEAN ContextLookasideInitialized;
    NPAGED_LOOKASIDE_LIST EventLookaside;
    BOOLEAN EventLookasideInitialized;

    // Statistics (interlocked updates only)
    volatile LONG64 TotalSyscallsMonitored;
    volatile LONG64 TotalDirectSyscalls;
    volatile LONG64 TotalHeavensGate;
    volatile LONG64 TotalSuspiciousCalls;
    volatile LONG64 TotalBlocked;

    // Reference counting for graceful shutdown
    volatile LONG ReferenceCount;
    KEVENT ShutdownEvent;
} SYSCALL_MONITOR_GLOBALS, *PSYSCALL_MONITOR_GLOBALS;

/**
 * @brief Safe statistics snapshot (safe to copy — contains only scalar fields).
 *
 * Use ScMonitorGetStatistics to populate this struct. This is the ONLY
 * struct callers should use to read monitor statistics.
 */
typedef struct _SYSCALL_MONITOR_STATISTICS {
    BOOLEAN Initialized;
    BOOLEAN Enabled;
    UINT32 ProcessContextCount;
    UINT32 KnownGoodCallerCount;
    LONG64 TotalSyscallsMonitored;
    LONG64 TotalDirectSyscalls;
    LONG64 TotalHeavensGate;
    LONG64 TotalSuspiciousCalls;
    LONG64 TotalBlocked;
} SYSCALL_MONITOR_STATISTICS, *PSYSCALL_MONITOR_STATISTICS;

// ============================================================================
// PUBLIC API - INITIALIZATION
// ============================================================================

/**
 * @brief Initialize the syscall monitoring subsystem.
 * @return STATUS_SUCCESS on success.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ScMonitorInitialize(VOID);

/**
 * @brief Shutdown the syscall monitoring subsystem.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ScMonitorShutdown(VOID);

/**
 * @brief Enable or disable syscall monitoring.
 * @param Enable TRUE to enable, FALSE to disable.
 * @return STATUS_SUCCESS on success.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ScMonitorSetEnabled(
    _In_ BOOLEAN Enable
    );

// ============================================================================
// PUBLIC API - SYSCALL ANALYSIS
// ============================================================================

/**
 * @brief Analyze syscall call context.
 *
 * Core analysis entry point. Determines if a syscall is suspicious by checking:
 * - Whether the caller is from ntdll (direct syscall detection)
 * - Heaven's Gate indicators
 * - Call stack anomalies
 * - Cross-process operation flags
 *
 * @param ProcessId Calling process ID.
 * @param ThreadId Calling thread ID.
 * @param SyscallNumber Syscall number.
 * @param ReturnAddress Return address of syscall.
 * @param Arguments Syscall arguments (may be NULL).
 * @param ArgumentCount Number of arguments (max 8).
 * @param Context Output call context (pool-allocated by caller; may be NULL).
 * @return STATUS_SUCCESS to allow, STATUS_ACCESS_DENIED to block.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ScMonitorAnalyzeSyscall(
    _In_ UINT32 ProcessId,
    _In_ UINT32 ThreadId,
    _In_ UINT32 SyscallNumber,
    _In_ UINT64 ReturnAddress,
    _In_reads_opt_(ArgumentCount) PUINT64 Arguments,
    _In_ UINT32 ArgumentCount,
    _Out_opt_ PSYSCALL_CALL_CONTEXT Context
    );

/**
 * @brief Check if return address is from ntdll.
 * @param ProcessId Process ID.
 * @param ReturnAddress Return address to check.
 * @param IsWoW64 TRUE if checking WoW64 ntdll.
 * @return TRUE if from ntdll.
 */
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
ScMonitorIsFromNtdll(
    _In_ UINT32 ProcessId,
    _In_ UINT64 ReturnAddress,
    _In_ BOOLEAN IsWoW64
    );

/**
 * @brief Detect Heaven's Gate (WoW64 abuse).
 * @param ProcessId Process ID.
 * @param Context Call context.
 * @return TRUE if Heaven's Gate detected.
 */
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
ScMonitorDetectHeavensGate(
    _In_ UINT32 ProcessId,
    _In_ PSYSCALL_CALL_CONTEXT Context
    );

/**
 * @brief Analyze call stack for anomalies.
 * @param ProcessId Process ID.
 * @param ThreadId Thread ID.
 * @param StackFrames Output stack frame array.
 * @param MaxFrames Maximum frames to capture.
 * @param FrameCount Output number of frames captured.
 * @param AnomalyFlags Output anomaly flags.
 * @return STATUS_SUCCESS on success.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ScMonitorAnalyzeCallStack(
    _In_ UINT32 ProcessId,
    _In_ UINT32 ThreadId,
    _Out_writes_to_(MaxFrames, *FrameCount) PUINT64 StackFrames,
    _In_ UINT32 MaxFrames,
    _Out_ PUINT32 FrameCount,
    _Out_ PUINT32 AnomalyFlags
    );

// Stack anomaly flags
#define SC_STACK_ANOMALY_UNBACKED         0x00000001  // Return to unbacked memory
#define SC_STACK_ANOMALY_RWX              0x00000002  // Return to RWX memory
#define SC_STACK_ANOMALY_PIVOT            0x00000004  // Stack pivot detected
#define SC_STACK_ANOMALY_GADGET           0x00000008  // ROP gadget chain
#define SC_STACK_ANOMALY_CORRUPTED        0x00000010  // Stack corruption

// ============================================================================
// PUBLIC API - NTDLL INTEGRITY
// ============================================================================

/**
 * @brief Verify ntdll integrity for process.
 * @param ProcessId Process ID.
 * @param IntegrityState Output integrity state.
 * @return STATUS_SUCCESS on success.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ScMonitorVerifyNtdllIntegrity(
    _In_ UINT32 ProcessId,
    _Out_ PNTDLL_INTEGRITY_STATE IntegrityState
    );

/**
 * @brief Get hooked functions in ntdll.
 * @param ProcessId Process ID.
 * @param HookedFunctions Output array of hooked functions.
 * @param MaxFunctions Maximum functions to return.
 * @param FunctionCount Output number of hooked functions.
 * @return STATUS_SUCCESS on success.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ScMonitorGetNtdllHooks(
    _In_ UINT32 ProcessId,
    _Out_writes_to_(MaxFunctions, *FunctionCount) PHOOKED_FUNCTION_ENTRY HookedFunctions,
    _In_ UINT32 MaxFunctions,
    _Out_ PUINT32 FunctionCount
    );

/**
 * @brief Restore a hooked ntdll function to its original bytes.
 *
 * SECURITY WARNING: This writes to another process's address space.
 * - FunctionName is validated against a hardcoded allowlist of Nt* functions.
 * - Original bytes are verified against the SystemNtdllHash before writing.
 * - Every restore operation is logged for forensic audit.
 * - FunctionName must be null-terminated and <= 63 characters.
 *
 * @param ProcessId Process ID to restore function in.
 * @param FunctionName Name of the Nt* function to restore.
 * @return STATUS_SUCCESS on success.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ScMonitorRestoreNtdllFunction(
    _In_ UINT32 ProcessId,
    _In_z_ PCSTR FunctionName
    );

// ============================================================================
// PUBLIC API - PROCESS CONTEXT
// ============================================================================

/**
 * @brief Get syscall context for process (creates if absent).
 *
 * Increments the context reference count. Caller MUST call
 * ScMonitorReleaseProcessContext when done.
 *
 * @param ProcessId Process ID.
 * @param Context Output context pointer (referenced; caller must release).
 * @return STATUS_SUCCESS if found or created.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ScMonitorGetProcessContext(
    _In_ UINT32 ProcessId,
    _Outptr_ PSC_PROCESS_CONTEXT* Context
    );

/**
 * @brief Release process context reference.
 *
 * If this is the last reference and the context is marked Removed,
 * the context is freed and ProcessObject is ObDereferenced.
 *
 * @param Context Context to release.
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
ScMonitorReleaseProcessContext(
    _In_ PSC_PROCESS_CONTEXT Context
    );

/**
 * @brief Remove process context (marks as removed, unlinks from list).
 *
 * The actual free is deferred until the last reference is released.
 *
 * @param ProcessId Process ID.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ScMonitorRemoveProcessContext(
    _In_ UINT32 ProcessId
    );

// ============================================================================
// PUBLIC API - SYSCALL TABLE
// ============================================================================

/**
 * @brief Resolve syscall number to name (delegates to SyscallTable).
 * @param SyscallNumber Syscall number.
 * @param Name Output name buffer.
 * @param NameSize Buffer size in bytes.
 * @return STATUS_SUCCESS on success.
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ScMonitorGetSyscallName(
    _In_ UINT32 SyscallNumber,
    _Out_writes_z_(NameSize) PSTR Name,
    _In_ UINT32 NameSize
    );

/**
 * @brief Resolve syscall name to number (delegates to SyscallTable).
 * @param Name Syscall name (null-terminated).
 * @param SyscallNumber Output syscall number.
 * @return STATUS_SUCCESS on success.
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ScMonitorGetSyscallNumber(
    _In_z_ PCSTR Name,
    _Out_ PUINT32 SyscallNumber
    );

/**
 * @brief Get syscall definition.
 * @param SyscallNumber Syscall number.
 * @param Definition Output definition.
 * @return STATUS_SUCCESS on success.
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ScMonitorGetSyscallDefinition(
    _In_ UINT32 SyscallNumber,
    _Out_ PSYSCALL_DEFINITION Definition
    );

// ============================================================================
// PUBLIC API - STATISTICS
// ============================================================================

/**
 * @brief Get syscall monitor statistics (safe snapshot — no kernel objects).
 * @param Stats Output statistics snapshot.
 * @return STATUS_SUCCESS on success.
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
ScMonitorGetStatistics(
    _Out_ PSYSCALL_MONITOR_STATISTICS Stats
    );

/**
 * @brief Get syscall statistics for process.
 * @param ProcessId Process ID.
 * @param TotalSyscalls Output total syscalls.
 * @param DirectSyscalls Output direct syscalls.
 * @param SuspiciousSyscalls Output suspicious syscalls.
 * @return STATUS_SUCCESS on success.
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ScMonitorGetProcessStats(
    _In_ UINT32 ProcessId,
    _Out_ PUINT64 TotalSyscalls,
    _Out_ PUINT64 DirectSyscalls,
    _Out_ PUINT64 SuspiciousSyscalls
    );

#ifdef __cplusplus
}
#endif

#endif // SHADOWSTRIKE_SYSCALL_MONITOR_H
