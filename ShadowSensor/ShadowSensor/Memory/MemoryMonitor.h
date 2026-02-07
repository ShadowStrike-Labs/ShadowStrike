/**
 * ============================================================================
 * ShadowStrike NGAV - MEMORY MONITOR
 * ============================================================================
 *
 * @file MemoryMonitor.h
 * @brief Memory monitoring subsystem header for ShadowSensor kernel driver.
 *
 * This module provides comprehensive memory monitoring capabilities including:
 * - VirtualAlloc/VirtualProtect tracking
 * - Cross-process memory operations
 * - Section object monitoring
 * - Shellcode detection
 * - Code injection detection
 * - Process hollowing detection
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#pragma once

#include <fltKernel.h>
#include "../../Shared/MemoryTypes.h"
#include "../../Shared/BehaviorTypes.h"

// ============================================================================
// MEMORY MONITOR CONFIGURATION
// ============================================================================

/**
 * @brief Default configuration values.
 */
#define MM_DEFAULT_MIN_ALLOC_SIZE           4096        // 4KB minimum to track
#define MM_DEFAULT_MAX_EVENTS_PER_SEC       10000       // Rate limit
#define MM_DEFAULT_SHELLCODE_SCAN_THRESHOLD 6000        // Entropy * 1000
#define MM_DEFAULT_MAX_REGION_SCAN_SIZE     (1024*1024) // 1MB max to scan

/**
 * @brief Pool tags for memory monitor allocations.
 */
#define MM_POOL_TAG_GENERAL     'mMsS'  // General allocations
#define MM_POOL_TAG_CONTEXT     'cMsS'  // Context structures
#define MM_POOL_TAG_EVENT       'eMsS'  // Event structures
#define MM_POOL_TAG_CACHE       'hMsS'  // Cache entries

// ============================================================================
// MEMORY REGION TRACKING
// ============================================================================

/**
 * @brief Tracked memory region state.
 */
typedef struct _MM_TRACKED_REGION {
    LIST_ENTRY ListEntry;
    
    // Region identification
    UINT64 BaseAddress;
    UINT64 Size;
    UINT32 ProcessId;
    
    // Current state
    UINT32 Protection;
    UINT32 State;                         // MEM_COMMIT, MEM_RESERVE
    UINT32 Type;                          // MEM_PRIVATE, MEM_MAPPED
    MEMORY_REGION_TYPE RegionType;
    
    // Tracking info
    UINT64 AllocationTime;
    UINT64 LastProtectionChangeTime;
    UINT32 ProtectionChangeCount;
    UINT32 Flags;
    
    // Content analysis
    UINT32 LastContentEntropy;            // Entropy * 1000
    BOOLEAN WasWritten;
    BOOLEAN NowExecutable;
    BOOLEAN IsHighRisk;
    UINT8 Reserved;
    
    // Backing info
    UNICODE_STRING BackingFile;
    WCHAR BackingFileBuffer[MAX_FILE_PATH_LENGTH];
} MM_TRACKED_REGION, *PMM_TRACKED_REGION;

// Tracked region flags
#define MM_REGION_FLAG_MONITORED          0x00000001
#define MM_REGION_FLAG_HIGH_ENTROPY       0x00000002
#define MM_REGION_FLAG_SHELLCODE_SCAN     0x00000004
#define MM_REGION_FLAG_INJECTION_SRC      0x00000008
#define MM_REGION_FLAG_INJECTION_DST      0x00000010
#define MM_REGION_FLAG_HOLLOWING          0x00000020

// ============================================================================
// PROCESS MEMORY CONTEXT
// ============================================================================

/**
 * @brief Per-process memory monitoring context.
 */
typedef struct _MM_PROCESS_CONTEXT {
    LIST_ENTRY ListEntry;
    
    // Process identification
    UINT32 ProcessId;
    PEPROCESS ProcessObject;
    UINT64 ProcessCreateTime;
    
    // Tracked regions
    LIST_ENTRY TrackedRegions;
    KSPIN_LOCK RegionLock;
    UINT32 TrackedRegionCount;
    
    // Statistics
    UINT64 TotalAllocations;
    UINT64 TotalProtectionChanges;
    UINT64 SuspiciousOperations;
    
    // Risk scoring
    UINT32 MemoryRiskScore;               // 0-1000
    UINT32 ShellcodeDetectionCount;
    UINT32 InjectionAttemptCount;
    
    // Flags
    UINT32 Flags;
    BOOLEAN IsMonitored;
    BOOLEAN IsHighRisk;
    UINT16 Reserved;
    
    // Reference counting
    volatile LONG RefCount;
} MM_PROCESS_CONTEXT, *PMM_PROCESS_CONTEXT;

// Process context flags
#define MM_PROCESS_FLAG_SYSTEM            0x00000001
#define MM_PROCESS_FLAG_PROTECTED         0x00000002
#define MM_PROCESS_FLAG_ELEVATED          0x00000004
#define MM_PROCESS_FLAG_HOLLOWING_TARGET  0x00000008
#define MM_PROCESS_FLAG_INJECTION_SOURCE  0x00000010
#define MM_PROCESS_FLAG_INJECTION_TARGET  0x00000020

// ============================================================================
// MEMORY MONITOR GLOBAL STATE
// ============================================================================

/**
 * @brief Memory monitor global state.
 */
typedef struct _MEMORY_MONITOR_GLOBALS {
    // Initialization state
    BOOLEAN Initialized;
    BOOLEAN Enabled;
    UINT16 Reserved1;
    
    // Configuration
    MEMORY_MONITOR_CONFIG Config;
    
    // Process contexts
    LIST_ENTRY ProcessContextList;
    ERESOURCE ProcessContextLock;
    UINT32 ProcessContextCount;
    UINT32 Reserved2;
    
    // Lookaside lists for allocations
    NPAGED_LOOKASIDE_LIST RegionLookaside;
    NPAGED_LOOKASIDE_LIST ContextLookaside;
    NPAGED_LOOKASIDE_LIST EventLookaside;
    
    // Statistics
    volatile LONG64 TotalEventsProcessed;
    volatile LONG64 TotalShellcodeDetections;
    volatile LONG64 TotalInjectionDetections;
    volatile LONG64 TotalHollowingDetections;
    volatile LONG64 EventsDropped;
    
    // Rate limiting
    volatile LONG EventsThisSecond;
    UINT64 CurrentSecondStart;
    
    // Callback registrations (for hooks)
    PVOID AllocationCallbackHandle;
    PVOID ProtectionCallbackHandle;
    PVOID SectionCallbackHandle;
} MEMORY_MONITOR_GLOBALS, *PMEMORY_MONITOR_GLOBALS;

// ============================================================================
// PUBLIC API
// ============================================================================

/**
 * @brief Initialize the memory monitoring subsystem.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
MmMonitorInitialize(VOID);

/**
 * @brief Shutdown the memory monitoring subsystem.
 */
VOID
MmMonitorShutdown(VOID);

/**
 * @brief Enable or disable memory monitoring.
 * @param Enable TRUE to enable, FALSE to disable.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
MmMonitorSetEnabled(
    _In_ BOOLEAN Enable
    );

/**
 * @brief Update memory monitor configuration.
 * @param Config New configuration.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
MmMonitorUpdateConfig(
    _In_ PMEMORY_MONITOR_CONFIG Config
    );

/**
 * @brief Get current memory monitor statistics.
 * @param Stats Output statistics structure.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
MmMonitorGetStatistics(
    _Out_ PMEMORY_MONITOR_GLOBALS Stats
    );

// ============================================================================
// PROCESS CONTEXT MANAGEMENT
// ============================================================================

/**
 * @brief Create or get memory context for a process.
 * @param ProcessId Process ID.
 * @param ProcessObject Optional EPROCESS pointer.
 * @param Context Output context pointer.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
MmMonitorGetProcessContext(
    _In_ UINT32 ProcessId,
    _In_opt_ PEPROCESS ProcessObject,
    _Out_ PMM_PROCESS_CONTEXT* Context
    );

/**
 * @brief Release reference to process context.
 * @param Context Context to release.
 */
VOID
MmMonitorReleaseProcessContext(
    _In_ PMM_PROCESS_CONTEXT Context
    );

/**
 * @brief Remove process context (on process termination).
 * @param ProcessId Process ID.
 */
VOID
MmMonitorRemoveProcessContext(
    _In_ UINT32 ProcessId
    );

// ============================================================================
// MEMORY OPERATION HANDLERS
// ============================================================================

/**
 * @brief Handle memory allocation operation.
 * @param ProcessId Target process ID.
 * @param BaseAddress Allocation base address.
 * @param RegionSize Allocation size.
 * @param AllocationType Allocation type (MEM_COMMIT, etc.).
 * @param Protection Memory protection.
 * @param IsCrossProcess TRUE if cross-process allocation.
 * @param SourceProcessId Source process ID (if cross-process).
 * @return STATUS_SUCCESS to allow, STATUS_ACCESS_DENIED to block.
 */
NTSTATUS
MmMonitorHandleAllocation(
    _In_ UINT32 ProcessId,
    _In_ UINT64 BaseAddress,
    _In_ UINT64 RegionSize,
    _In_ UINT32 AllocationType,
    _In_ UINT32 Protection,
    _In_ BOOLEAN IsCrossProcess,
    _In_ UINT32 SourceProcessId
    );

/**
 * @brief Handle memory protection change.
 * @param ProcessId Target process ID.
 * @param BaseAddress Region base address.
 * @param RegionSize Region size.
 * @param OldProtection Old protection.
 * @param NewProtection New protection.
 * @param IsCrossProcess TRUE if cross-process operation.
 * @param SourceProcessId Source process ID (if cross-process).
 * @return STATUS_SUCCESS to allow, STATUS_ACCESS_DENIED to block.
 */
NTSTATUS
MmMonitorHandleProtectionChange(
    _In_ UINT32 ProcessId,
    _In_ UINT64 BaseAddress,
    _In_ UINT64 RegionSize,
    _In_ UINT32 OldProtection,
    _In_ UINT32 NewProtection,
    _In_ BOOLEAN IsCrossProcess,
    _In_ UINT32 SourceProcessId
    );

/**
 * @brief Handle cross-process memory write.
 * @param SourceProcessId Writer process ID.
 * @param TargetProcessId Target process ID.
 * @param TargetAddress Target address.
 * @param Size Write size.
 * @param SourceBuffer Source buffer (kernel address).
 * @return STATUS_SUCCESS to allow, STATUS_ACCESS_DENIED to block.
 */
NTSTATUS
MmMonitorHandleCrossProcessWrite(
    _In_ UINT32 SourceProcessId,
    _In_ UINT32 TargetProcessId,
    _In_ UINT64 TargetAddress,
    _In_ UINT64 Size,
    _In_opt_ PVOID SourceBuffer
    );

/**
 * @brief Handle section create/map operation.
 * @param ProcessId Process creating/mapping section.
 * @param SectionHandle Section handle.
 * @param BaseAddress Mapped base address.
 * @param ViewSize View size.
 * @param Protection Protection.
 * @param IsCrossProcess TRUE if mapping into another process.
 * @param TargetProcessId Target process (if cross-process).
 * @return STATUS_SUCCESS to allow, STATUS_ACCESS_DENIED to block.
 */
NTSTATUS
MmMonitorHandleSectionMap(
    _In_ UINT32 ProcessId,
    _In_ HANDLE SectionHandle,
    _In_ UINT64 BaseAddress,
    _In_ UINT64 ViewSize,
    _In_ UINT32 Protection,
    _In_ BOOLEAN IsCrossProcess,
    _In_ UINT32 TargetProcessId
    );

// ============================================================================
// DETECTION FUNCTIONS
// ============================================================================

/**
 * @brief Scan memory region for shellcode.
 * @param ProcessId Process ID.
 * @param BaseAddress Region base.
 * @param Size Region size.
 * @param Event Output detection event (if detected).
 * @return TRUE if shellcode detected.
 */
BOOLEAN
MmMonitorScanForShellcode(
    _In_ UINT32 ProcessId,
    _In_ UINT64 BaseAddress,
    _In_ UINT64 Size,
    _Out_opt_ PSHELLCODE_DETECTION_EVENT Event
    );

/**
 * @brief Detect code injection attempt.
 * @param SourceProcessId Source (attacker) process.
 * @param TargetProcessId Target (victim) process.
 * @param TargetAddress Injection address.
 * @param Size Injection size.
 * @param InjectionType Detected injection type.
 * @param Event Output detection event.
 * @return TRUE if injection detected.
 */
BOOLEAN
MmMonitorDetectInjection(
    _In_ UINT32 SourceProcessId,
    _In_ UINT32 TargetProcessId,
    _In_ UINT64 TargetAddress,
    _In_ UINT64 Size,
    _In_ INJECTION_TYPE InjectionType,
    _Out_opt_ PINJECTION_DETECTION_EVENT Event
    );

/**
 * @brief Detect process hollowing.
 * @param ProcessId Suspected hollowed process.
 * @param Event Output detection event.
 * @return TRUE if hollowing detected.
 */
BOOLEAN
MmMonitorDetectHollowing(
    _In_ UINT32 ProcessId,
    _Out_opt_ PHOLLOWING_DETECTION_EVENT Event
    );

/**
 * @brief Calculate entropy of memory region.
 * @param Buffer Memory buffer.
 * @param Size Buffer size.
 * @return Entropy value * 1000 (0-8000).
 */
UINT32
MmMonitorCalculateEntropy(
    _In_reads_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size
    );

// ============================================================================
// VAD TRACKING
// ============================================================================

/**
 * @brief Build VAD map for a process.
 * @param ProcessId Process ID.
 * @param VadMap Output VAD map (caller must free).
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
MmMonitorBuildVadMap(
    _In_ UINT32 ProcessId,
    _Out_ PPROCESS_VAD_MAP* VadMap
    );

/**
 * @brief Free VAD map.
 * @param VadMap VAD map to free.
 */
VOID
MmMonitorFreeVadMap(
    _In_ PPROCESS_VAD_MAP VadMap
    );

/**
 * @brief Find suspicious VAD entries.
 * @param ProcessId Process ID.
 * @param SuspiciousEntries Output array of suspicious VAD entries.
 * @param MaxEntries Maximum entries to return.
 * @param EntryCount Output number of entries found.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
MmMonitorFindSuspiciousVads(
    _In_ UINT32 ProcessId,
    _Out_writes_to_(MaxEntries, *EntryCount) PVAD_ENTRY SuspiciousEntries,
    _In_ UINT32 MaxEntries,
    _Out_ PUINT32 EntryCount
    );

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Check if address is in executable region.
 * @param ProcessId Process ID.
 * @param Address Address to check.
 * @return TRUE if in executable region.
 */
BOOLEAN
MmMonitorIsAddressExecutable(
    _In_ UINT32 ProcessId,
    _In_ UINT64 Address
    );

/**
 * @brief Get backing file for memory region.
 * @param ProcessId Process ID.
 * @param Address Address in region.
 * @param FileName Output file name buffer.
 * @param FileNameSize Buffer size in bytes.
 * @return STATUS_SUCCESS on success, STATUS_NOT_FOUND if unbacked.
 */
NTSTATUS
MmMonitorGetBackingFile(
    _In_ UINT32 ProcessId,
    _In_ UINT64 Address,
    _Out_writes_bytes_(FileNameSize) PWCHAR FileName,
    _In_ UINT32 FileNameSize
    );

/**
 * @brief Check if protection change is suspicious.
 * @param OldProtection Old protection.
 * @param NewProtection New protection.
 * @param RegionType Region type.
 * @return Suspicion score 0-100.
 */
UINT32
MmMonitorGetProtectionChangeSuspicion(
    _In_ UINT32 OldProtection,
    _In_ UINT32 NewProtection,
    _In_ MEMORY_REGION_TYPE RegionType
    );

#endif // SHADOWSTRIKE_MEMORY_MONITOR_H
