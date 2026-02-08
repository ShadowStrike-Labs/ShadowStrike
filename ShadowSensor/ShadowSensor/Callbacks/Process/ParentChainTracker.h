/*++
    ShadowStrike Next-Generation Antivirus
    Module: ParentChainTracker.h - Process ancestry tracking
    Copyright (c) ShadowStrike Team

    Enterprise-grade process chain tracking with PPID spoofing detection,
    suspicious ancestry pattern matching, and full MITRE ATT&CK coverage.

    Version: 2.1.0 - Security hardened edition
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

// ============================================================================
// POOL TAGS AND LIMITS
// ============================================================================

#define PCT_POOL_TAG                    'TCPP'
#define PCT_MAX_CHAIN_DEPTH             32
#define PCT_MAX_CACHED_CHAINS           256
#define PCT_MAX_SUSPICIOUS_PATTERNS     64
#define PCT_MAX_IMAGE_NAME_LENGTH       260
#define PCT_MAX_COMMAND_LINE_LENGTH     4096

//
// Signature for structure validation
//
#define PCT_SIGNATURE                   0x50435454  // 'PCTT'
#define PCT_CHAIN_SIGNATURE             0x50434348  // 'PCCH'
#define PCT_NODE_SIGNATURE              0x50434E44  // 'PCND'

// ============================================================================
// ALLOCATION SOURCE TRACKING
// ============================================================================

/**
 * @brief Tracks how memory was allocated for proper deallocation.
 */
typedef enum _PCT_ALLOC_SOURCE {
    PctAllocSourcePool = 0,
    PctAllocSourceLookaside = 1
} PCT_ALLOC_SOURCE;

// ============================================================================
// CHAIN NODE STRUCTURE
// ============================================================================

/**
 * @brief Represents a single node in the process ancestry chain.
 *
 * Each node contains information about one process in the chain,
 * from the leaf process up to the root (System or orphaned).
 */
typedef struct _PCT_CHAIN_NODE {
    //
    // Validation signature
    //
    ULONG Signature;

    //
    // Allocation tracking for safe deallocation
    //
    PCT_ALLOC_SOURCE AllocSource;

    //
    // Process identification
    //
    HANDLE ProcessId;
    LARGE_INTEGER CreateTime;

    //
    // Process image information (null-terminated, allocated separately)
    //
    UNICODE_STRING ImageName;
    UNICODE_STRING CommandLine;

    //
    // Process flags
    //
    BOOLEAN IsSystem;
    BOOLEAN IsSuspicious;
    BOOLEAN IsTerminated;

    //
    // List linkage
    //
    LIST_ENTRY ListEntry;

} PCT_CHAIN_NODE, *PPCT_CHAIN_NODE;

// ============================================================================
// PROCESS CHAIN STRUCTURE
// ============================================================================

/**
 * @brief Represents a complete process ancestry chain.
 *
 * Contains all ancestor nodes from the leaf process up to System,
 * along with analysis results and suspicion scoring.
 */
typedef struct _PCT_PROCESS_CHAIN {
    //
    // Validation signature
    //
    ULONG Signature;

    //
    // Allocation tracking for safe deallocation
    //
    PCT_ALLOC_SOURCE AllocSource;

    //
    // Opaque pointer to owning tracker (for proper deallocation)
    //
    PVOID OwningTracker;

    //
    // Target process identification
    //
    HANDLE LeafProcessId;
    LARGE_INTEGER BuildTime;

    //
    // Chain of ancestor nodes (ordered leaf -> root)
    //
    LIST_ENTRY ChainList;
    ULONG ChainDepth;

    //
    // Analysis results
    //
    BOOLEAN HasSuspiciousAncestor;
    BOOLEAN IsParentSpoofed;
    BOOLEAN HasOrphanedProcess;
    BOOLEAN HasTerminatedAncestor;

    //
    // Suspicion scoring
    //
    ULONG SuspicionScore;
    ULONG HighestNodeScore;

    //
    // List linkage (for caching)
    //
    LIST_ENTRY ListEntry;

} PCT_PROCESS_CHAIN, *PPCT_PROCESS_CHAIN;

// ============================================================================
// TRACKER STATISTICS
// ============================================================================

/**
 * @brief Runtime statistics for the parent chain tracker.
 */
typedef struct _PCT_STATISTICS {
    volatile LONG64 ChainsBuilt;
    volatile LONG64 ChainsFromCache;
    volatile LONG64 SpoofingDetected;
    volatile LONG64 SuspiciousChains;
    volatile LONG64 OrphanedProcesses;
    volatile LONG64 AllocationFailures;
    volatile LONG64 ProcessLookupFailures;
    LARGE_INTEGER StartTime;
} PCT_STATISTICS, *PPCT_STATISTICS;

// ============================================================================
// MAIN TRACKER STRUCTURE (PUBLIC VIEW)
// ============================================================================

/**
 * @brief Public view of the parent chain tracker.
 *
 * Internal implementation details are hidden in the .c file.
 */
typedef struct _PCT_TRACKER {
    //
    // Initialization state
    //
    BOOLEAN Initialized;
    volatile LONG ShuttingDown;

    //
    // Chain cache
    //
    LIST_ENTRY ChainList;
    EX_PUSH_LOCK ChainLock;
    volatile LONG ChainCount;

    //
    // Suspicious patterns
    //
    LIST_ENTRY SuspiciousPatterns;

    //
    // Statistics
    //
    PCT_STATISTICS Stats;

} PCT_TRACKER, *PPCT_TRACKER;

// ============================================================================
// PUBLIC API - LIFECYCLE
// ============================================================================

/**
 * @brief Initializes the parent chain tracker.
 *
 * @param[out] Tracker Receives pointer to initialized tracker.
 * @return STATUS_SUCCESS on success.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PctInitialize(
    _Out_ PPCT_TRACKER* Tracker
    );

/**
 * @brief Shuts down the parent chain tracker and frees all resources.
 *
 * Waits for all active operations to complete before cleanup.
 *
 * @param[in,out] Tracker Tracker to shutdown. Set to NULL on return.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
PctShutdown(
    _Inout_ PPCT_TRACKER Tracker
    );

// ============================================================================
// PUBLIC API - CHAIN OPERATIONS
// ============================================================================

/**
 * @brief Builds a complete process ancestry chain.
 *
 * Traverses from the specified process up to System or an orphaned
 * process, collecting information about each ancestor. Performs
 * analysis for suspicious patterns and PPID spoofing.
 *
 * @param[in] Tracker Initialized tracker instance.
 * @param[in] ProcessId Target process to build chain for.
 * @param[out] Chain Receives the built chain. Caller must free with PctFreeChain.
 * @return STATUS_SUCCESS on success.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PctBuildChain(
    _In_ PPCT_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _Out_ PPCT_PROCESS_CHAIN* Chain
    );

/**
 * @brief Frees a process chain returned by PctBuildChain.
 *
 * Properly handles both lookaside and pool allocations based on
 * the allocation source tracked in each structure.
 *
 * @param[in] Chain Chain to free. Safe to pass NULL.
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
PctFreeChain(
    _In_opt_ PPCT_PROCESS_CHAIN Chain
    );

// ============================================================================
// PUBLIC API - DETECTION
// ============================================================================

/**
 * @brief Detects PPID spoofing for a process.
 *
 * Compares claimed parent with actual parent from system structures,
 * validates creation time ordering, and checks for PID reuse attacks.
 *
 * @param[in] Tracker Initialized tracker instance.
 * @param[in] ProcessId Process to check.
 * @param[in] ClaimedParentId Parent ID claimed by the process.
 * @param[in] ClaimedParentCreateTime Creation time of claimed parent (for PID reuse protection).
 * @param[out] IsSpoofed Receives TRUE if spoofing is detected.
 * @return STATUS_SUCCESS on success.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PctDetectSpoofing(
    _In_ PPCT_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _In_ HANDLE ClaimedParentId,
    _In_opt_ PLARGE_INTEGER ClaimedParentCreateTime,
    _Out_ PBOOLEAN IsSpoofed
    );

/**
 * @brief Checks if a process has a specific ancestor in its chain.
 *
 * @param[in] Tracker Initialized tracker instance.
 * @param[in] ProcessId Process to check.
 * @param[in] AncestorName Image name to search for (e.g., L"explorer.exe").
 * @param[out] HasAncestor Receives TRUE if ancestor is found.
 * @return STATUS_SUCCESS on success.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PctCheckAncestry(
    _In_ PPCT_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _In_ PUNICODE_STRING AncestorName,
    _Out_ PBOOLEAN HasAncestor
    );

// ============================================================================
// PUBLIC API - STATISTICS
// ============================================================================

/**
 * @brief Retrieves current tracker statistics.
 *
 * @param[in] Tracker Initialized tracker instance.
 * @param[out] Stats Receives copy of current statistics.
 * @return STATUS_SUCCESS on success.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
PctGetStatistics(
    _In_ PPCT_TRACKER Tracker,
    _Out_ PPCT_STATISTICS Stats
    );

#ifdef __cplusplus
}
#endif
