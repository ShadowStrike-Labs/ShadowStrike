/**
 * ============================================================================
 * ShadowStrike NGAV - SYSCALL MONITOR
 * ============================================================================
 *
 * @file SyscallMonitor.h
 * @brief Syscall monitoring subsystem header for ShadowSensor kernel driver.
 *
 * This module provides syscall monitoring capabilities including:
 * - Direct syscall detection (syscalls not from ntdll.dll)
 * - Heaven's Gate detection (WoW64 abuse)
 * - Syscall argument validation
 * - Call stack analysis
 * - SSDT integrity monitoring
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#pragma once

#include <fltKernel.h>
#include "../../Shared/BehaviorTypes.h"

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
 * @brief Per-process syscall monitoring context.
 */
typedef struct _SC_PROCESS_CONTEXT {
    LIST_ENTRY ListEntry;
    
    // Process info
    UINT32 ProcessId;
    PEPROCESS ProcessObject;
    UINT64 ProcessCreateTime;
    BOOLEAN IsWoW64;
    UINT8 Reserved[3];
    
    // NTDLL info for this process
    UINT64 NtdllBase;
    UINT64 NtdllSize;
    UINT64 Wow64NtdllBase;                // For WoW64 processes
    UINT64 Wow64NtdllSize;
    
    // Statistics
    UINT64 TotalSyscalls;
    UINT64 DirectSyscalls;                // Not from ntdll
    UINT64 SuspiciousSyscalls;
    UINT32 UniqueCallers;
    UINT32 Flags;
    
    // Per-syscall counts (for anomaly detection)
    UINT32 SyscallCounts[SC_MAX_MONITORED_SYSCALLS];
    UINT32 MonitoredSyscallCount;
    
    // Suspicious callers cache
    UINT64 SuspiciousCallers[32];
    UINT32 SuspiciousCallerCount;
    
    // Integrity state
    NTDLL_INTEGRITY_STATE NtdllIntegrity;
    
    // Reference counting
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
 * @brief Syscall monitor global state.
 */
typedef struct _SYSCALL_MONITOR_GLOBALS {
    // Initialization state
    BOOLEAN Initialized;
    BOOLEAN Enabled;
    UINT16 Reserved1;
    
    // Syscall table
    PSYSCALL_DEFINITION SyscallTable;
    UINT32 SyscallTableSize;
    UINT32 MonitoredSyscallCount;
    
    // System NTDLL reference
    UINT64 SystemNtdllBase;
    UINT64 SystemNtdllSize;
    UINT8 SystemNtdllHash[32];
    
    // Process contexts
    LIST_ENTRY ProcessContextList;
    ERESOURCE ProcessLock;
    UINT32 ProcessContextCount;
    UINT32 Reserved2;
    
    // Known good caller cache
    LIST_ENTRY KnownGoodCallers;
    ERESOURCE CallerCacheLock;
    UINT32 KnownGoodCallerCount;
    UINT32 Reserved3;
    
    // Lookaside lists
    NPAGED_LOOKASIDE_LIST ContextLookaside;
    NPAGED_LOOKASIDE_LIST EventLookaside;
    
    // Statistics
    volatile LONG64 TotalSyscallsMonitored;
    volatile LONG64 TotalDirectSyscalls;
    volatile LONG64 TotalHeavensGate;
    volatile LONG64 TotalSuspiciousCalls;
    volatile LONG64 TotalBlocked;
    
    // Hooks (if using hook-based monitoring)
    PVOID SyscallHookHandle;
    BOOLEAN UsingHookMonitoring;
    UINT8 Reserved4[7];
} SYSCALL_MONITOR_GLOBALS, *PSYSCALL_MONITOR_GLOBALS;

// ============================================================================
// PUBLIC API - INITIALIZATION
// ============================================================================

/**
 * @brief Initialize the syscall monitoring subsystem.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ScMonitorInitialize(VOID);

/**
 * @brief Shutdown the syscall monitoring subsystem.
 */
VOID
ScMonitorShutdown(VOID);

/**
 * @brief Enable or disable syscall monitoring.
 * @param Enable TRUE to enable, FALSE to disable.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ScMonitorSetEnabled(
    _In_ BOOLEAN Enable
    );

// ============================================================================
// PUBLIC API - SYSCALL ANALYSIS
// ============================================================================

/**
 * @brief Analyze syscall call context.
 * @param ProcessId Calling process ID.
 * @param ThreadId Calling thread ID.
 * @param SyscallNumber Syscall number.
 * @param ReturnAddress Return address of syscall.
 * @param Arguments Syscall arguments.
 * @param ArgumentCount Number of arguments.
 * @param Context Output call context.
 * @return STATUS_SUCCESS to allow, STATUS_ACCESS_DENIED to block.
 */
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
NTSTATUS
ScMonitorGetNtdllHooks(
    _In_ UINT32 ProcessId,
    _Out_writes_to_(MaxFunctions, *FunctionCount) PHOOKED_FUNCTION_ENTRY HookedFunctions,
    _In_ UINT32 MaxFunctions,
    _Out_ PUINT32 FunctionCount
    );

/**
 * @brief Restore ntdll hooks (for our own protection bypass).
 * @param ProcessId Process ID.
 * @param FunctionName Function name to restore.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ScMonitorRestoreNtdllFunction(
    _In_ UINT32 ProcessId,
    _In_ PCSTR FunctionName
    );

// ============================================================================
// PUBLIC API - PROCESS CONTEXT
// ============================================================================

/**
 * @brief Get syscall context for process.
 * @param ProcessId Process ID.
 * @param Context Output context pointer.
 * @return STATUS_SUCCESS if found.
 */
NTSTATUS
ScMonitorGetProcessContext(
    _In_ UINT32 ProcessId,
    _Out_ PSC_PROCESS_CONTEXT* Context
    );

/**
 * @brief Release process context reference.
 * @param Context Context to release.
 */
VOID
ScMonitorReleaseProcessContext(
    _In_ PSC_PROCESS_CONTEXT Context
    );

/**
 * @brief Remove process context.
 * @param ProcessId Process ID.
 */
VOID
ScMonitorRemoveProcessContext(
    _In_ UINT32 ProcessId
    );

// ============================================================================
// PUBLIC API - SYSCALL TABLE
// ============================================================================

/**
 * @brief Resolve syscall number to name.
 * @param SyscallNumber Syscall number.
 * @param Name Output name buffer.
 * @param NameSize Buffer size.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ScMonitorGetSyscallName(
    _In_ UINT32 SyscallNumber,
    _Out_writes_z_(NameSize) PSTR Name,
    _In_ UINT32 NameSize
    );

/**
 * @brief Resolve syscall name to number.
 * @param Name Syscall name.
 * @param SyscallNumber Output syscall number.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ScMonitorGetSyscallNumber(
    _In_ PCSTR Name,
    _Out_ PUINT32 SyscallNumber
    );

/**
 * @brief Get syscall definition.
 * @param SyscallNumber Syscall number.
 * @param Definition Output definition.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ScMonitorGetSyscallDefinition(
    _In_ UINT32 SyscallNumber,
    _Out_ PSYSCALL_DEFINITION Definition
    );

// ============================================================================
// PUBLIC API - STATISTICS
// ============================================================================

/**
 * @brief Get syscall monitor statistics.
 * @param Stats Output statistics.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ScMonitorGetStatistics(
    _Out_ PSYSCALL_MONITOR_GLOBALS Stats
    );

/**
 * @brief Get syscall statistics for process.
 * @param ProcessId Process ID.
 * @param TotalSyscalls Output total syscalls.
 * @param DirectSyscalls Output direct syscalls.
 * @param SuspiciousSyscalls Output suspicious syscalls.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ScMonitorGetProcessStats(
    _In_ UINT32 ProcessId,
    _Out_ PUINT64 TotalSyscalls,
    _Out_ PUINT64 DirectSyscalls,
    _Out_ PUINT64 SuspiciousSyscalls
    );

#endif // SHADOWSTRIKE_SYSCALL_MONITOR_H
