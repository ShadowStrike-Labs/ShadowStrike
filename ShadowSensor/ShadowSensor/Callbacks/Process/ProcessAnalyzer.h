/*++
===============================================================================
ShadowStrike NGAV - PROCESS ANALYZER HEADER
===============================================================================

@file ProcessAnalyzer.h
@brief Enterprise-grade deep process analysis for comprehensive threat detection.

This module provides real-time process analysis capabilities including:
- PE header analysis and validation
- Security mitigation detection (DEP, ASLR, CFG, ACG)
- Process integrity level assessment
- Behavioral indicator detection
- Suspicion scoring and threat classification
- Parent-child relationship analysis
- Token and privilege inspection
- Code signing verification
- Entropy-based packing detection

IRQL Requirements:
- All public APIs must be called at IRQL == PASSIVE_LEVEL
- Internal caching uses EX_PUSH_LOCK requiring IRQL < DISPATCH_LEVEL

Thread Safety:
- All public APIs are thread-safe
- Analysis objects are reference-counted
- Callers MUST call PaFreeAnalysis when done with analysis results

@author ShadowStrike Security Team
@version 3.0.0 (Enterprise Edition - Security Hardened)
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

//
// Pool tags for memory tracking
//
#define PA_POOL_TAG             'APSS'
#define PA_POOL_TAG_ANALYSIS    'AnSS'
#define PA_POOL_TAG_CACHE       'CaSS'
#define PA_POOL_TAG_STRING      'StSS'
#define PA_POOL_TAG_BUFFER      'BuSS'

//
// Version information for ABI compatibility
//
#define PA_VERSION_MAJOR        3
#define PA_VERSION_MINOR        0
#define PA_VERSION_PATCH        0
#define PA_VERSION              ((PA_VERSION_MAJOR << 16) | (PA_VERSION_MINOR << 8) | PA_VERSION_PATCH)

//
// Configuration limits
//
#define PA_MAX_PATH_LENGTH              1024
#define PA_MAX_CMDLINE_LENGTH           8192
#define PA_MAX_CACHED_ANALYSES          4096

//
// Suspicion score thresholds
//
#define PA_SUSPICION_THRESHOLD_LOW      25
#define PA_SUSPICION_THRESHOLD_MEDIUM   50
#define PA_SUSPICION_THRESHOLD_HIGH     75
#define PA_SUSPICION_THRESHOLD_CRITICAL 90

//
// Behavior flags for suspicious indicators
//
#define PA_BEHAVIOR_NONE                    0x00000000
#define PA_BEHAVIOR_SUSPICIOUS_PARENT       0x00000001
#define PA_BEHAVIOR_UNUSUAL_PATH            0x00000002
#define PA_BEHAVIOR_UNSIGNED                0x00000004
#define PA_BEHAVIOR_PACKED                  0x00000008
#define PA_BEHAVIOR_NO_DEP                  0x00000010
#define PA_BEHAVIOR_NO_ASLR                 0x00000020
#define PA_BEHAVIOR_ELEVATED                0x00000040
#define PA_BEHAVIOR_SYSTEM_IMPERSONATION    0x00000080
#define PA_BEHAVIOR_HOLLOWED                0x00000100
#define PA_BEHAVIOR_INJECTED                0x00000200
#define PA_BEHAVIOR_MASQUERADING            0x00000400
#define PA_BEHAVIOR_ANOMALOUS_TOKEN         0x00000800
#define PA_BEHAVIOR_SUSPICIOUS_CMDLINE      0x00001000
#define PA_BEHAVIOR_SCRIPT_HOST             0x00002000
#define PA_BEHAVIOR_LOL_BINARY              0x00004000
#define PA_BEHAVIOR_UNUSUAL_EXTENSION       0x00008000
#define PA_BEHAVIOR_HIDDEN_WINDOW           0x00010000
#define PA_BEHAVIOR_DEBUGGER_PRESENT        0x00020000
#define PA_BEHAVIOR_SHORT_LIVED             0x00040000
#define PA_BEHAVIOR_HIGH_ENTROPY            0x00080000
#define PA_BEHAVIOR_PARENT_CHILD_MISMATCH   0x00100000
#define PA_BEHAVIOR_DANGEROUS_PRIVILEGES    0x00200000

//
// Integrity levels
//
#define PA_INTEGRITY_UNTRUSTED      0x0000
#define PA_INTEGRITY_LOW            0x1000
#define PA_INTEGRITY_MEDIUM         0x2000
#define PA_INTEGRITY_MEDIUM_PLUS    0x2100
#define PA_INTEGRITY_HIGH           0x3000
#define PA_INTEGRITY_SYSTEM         0x4000
#define PA_INTEGRITY_PROTECTED      0x5000

//
// Forward declarations - opaque types for API stability
//
typedef struct _PA_ANALYZER *PPA_ANALYZER;
typedef struct _PA_PROCESS_ANALYSIS *PPA_PROCESS_ANALYSIS;

//
// PE analysis results (read-only view for callers)
//
typedef struct _PA_PE_INFO {
    BOOLEAN IsPE;
    BOOLEAN Is64Bit;
    BOOLEAN IsDotNet;
    BOOLEAN IsPacked;
    BOOLEAN IsSigned;
    BOOLEAN HasValidChecksum;
    ULONG Entropy;              // 0-1000 scale
    ULONG Characteristics;
    ULONG Subsystem;
    ULONG TimeDateStamp;
    ULONG ImageSize;
    USHORT DllCharacteristics;
    USHORT Machine;
} PA_PE_INFO, *PPA_PE_INFO;

//
// Security analysis results (read-only view for callers)
//
typedef struct _PA_SECURITY_INFO {
    BOOLEAN HasDEP;
    BOOLEAN HasASLR;
    BOOLEAN HasCFG;
    BOOLEAN HasACG;
    BOOLEAN HasHighEntropyASLR;
    BOOLEAN HasStrictHandleChecks;
    BOOLEAN HasIntegrityLevel;
    BOOLEAN IsElevated;
    BOOLEAN IsProtectedProcess;
    BOOLEAN IsProtectedProcessLight;
    BOOLEAN HasSeDebugPrivilege;
    BOOLEAN HasSeLoadDriverPrivilege;
    BOOLEAN HasSeTcbPrivilege;
    BOOLEAN HasSeBackupPrivilege;
    BOOLEAN HasSeRestorePrivilege;
    ULONG IntegrityLevel;
    ULONG ProtectionLevel;
} PA_SECURITY_INFO, *PPA_SECURITY_INFO;

//
// Parent process info (read-only view for callers)
//
typedef struct _PA_PARENT_INFO {
    HANDLE ParentId;
    UNICODE_STRING ImagePath;
    BOOLEAN IsKnownParent;
    BOOLEAN ParentChildMismatch;
    ULONG ParentSuspicionScore;
} PA_PARENT_INFO, *PPA_PARENT_INFO;

//
// Complete process analysis results
// Returned by PaAnalyzeProcess - caller must call PaFreeAnalysis when done
//
typedef struct _PA_ANALYSIS_RESULT {
    //
    // Process identification
    //
    HANDLE ProcessId;
    LARGE_INTEGER CreationTime;
    UNICODE_STRING ImagePath;
    UNICODE_STRING CommandLine;

    //
    // Analysis results
    //
    PA_PE_INFO PE;
    PA_SECURITY_INFO Security;
    PA_PARENT_INFO Parent;

    //
    // Threat assessment
    //
    ULONG SuspicionScore;       // 0-100
    ULONG BehaviorFlags;        // PA_BEHAVIOR_* flags
    BOOLEAN IsSuspicious;
    BOOLEAN RequiresAction;

} PA_ANALYSIS_RESULT, *PPA_ANALYSIS_RESULT;

//
// Analyzer statistics
//
typedef struct _PA_STATISTICS {
    volatile LONG64 ProcessesAnalyzed;
    volatile LONG64 SuspiciousFound;
    volatile LONG64 CacheHits;
    volatile LONG64 CacheMisses;
    volatile LONG64 AnalysisErrors;
    volatile LONG64 PackedDetections;
    volatile LONG64 UnsignedDetections;
    volatile LONG64 ElevatedProcesses;
    volatile LONG64 SuspiciousParents;
    volatile LONG64 ParentMismatchDetections;
    LARGE_INTEGER StartTime;
} PA_STATISTICS, *PPA_STATISTICS;

//
// Analyzer configuration
//
typedef struct _PA_CONFIG {
    ULONG CacheTimeoutMs;
    ULONG MaxCachedAnalyses;
    ULONG SuspicionThreshold;
    BOOLEAN EnableDeepAnalysis;
    BOOLEAN EnableSignatureCheck;
    BOOLEAN EnableEntropyAnalysis;
    BOOLEAN EnableParentValidation;
    BOOLEAN EnableMitigationCheck;
} PA_CONFIG, *PPA_CONFIG;

// ============================================================================
// PUBLIC API
// ============================================================================

/*++
Routine Description:
    Initializes the process analyzer subsystem.

    IRQL: Must be called at PASSIVE_LEVEL.

Arguments:
    Analyzer - Receives pointer to initialized analyzer.
    Config - Optional configuration. If NULL, defaults are used.

Return Value:
    STATUS_SUCCESS on success.
    STATUS_INSUFFICIENT_RESOURCES if memory allocation fails.
    STATUS_INVALID_PARAMETER if Analyzer is NULL.
--*/
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PaInitialize(
    _Out_ PPA_ANALYZER* Analyzer,
    _In_opt_ PPA_CONFIG Config
    );

/*++
Routine Description:
    Shuts down the process analyzer and frees all resources.

    IRQL: Must be called at PASSIVE_LEVEL.

    WARNING: All outstanding analysis results become invalid after this call.
    Ensure all callers have called PaFreeAnalysis before shutdown.

Arguments:
    Analyzer - Analyzer instance to shutdown. Set to NULL on return.
--*/
_IRQL_requires_(PASSIVE_LEVEL)
VOID
PaShutdown(
    _Inout_ PPA_ANALYZER* Analyzer
    );

/*++
Routine Description:
    Performs comprehensive analysis of a process.

    IRQL: Must be called at PASSIVE_LEVEL.

    The returned analysis is reference-counted. Caller MUST call PaFreeAnalysis
    when done with the result to release the reference.

Arguments:
    Analyzer - Analyzer instance.
    ProcessId - Process to analyze.
    Analysis - Receives analysis results. Valid until PaFreeAnalysis is called.

Return Value:
    STATUS_SUCCESS on success.
    STATUS_INVALID_PARAMETER if parameters are invalid.
    STATUS_NOT_FOUND if process does not exist.
    STATUS_INSUFFICIENT_RESOURCES if memory allocation fails.
--*/
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PaAnalyzeProcess(
    _In_ PPA_ANALYZER Analyzer,
    _In_ HANDLE ProcessId,
    _Out_ PPA_ANALYSIS_RESULT* Analysis
    );

/*++
Routine Description:
    Performs a quick suspicion check without full analysis.
    Does not allocate memory or return a reference-counted object.

    IRQL: Must be called at PASSIVE_LEVEL.

Arguments:
    Analyzer - Analyzer instance.
    ProcessId - Process to check.
    SuspicionScore - Receives suspicion score (0-100).

Return Value:
    STATUS_SUCCESS on success.
    STATUS_INVALID_PARAMETER if parameters are invalid.
    STATUS_NOT_FOUND if process does not exist.
--*/
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PaQuickCheck(
    _In_ PPA_ANALYZER Analyzer,
    _In_ HANDLE ProcessId,
    _Out_ PULONG SuspicionScore
    );

/*++
Routine Description:
    Releases a process analysis result.

    IRQL: Must be called at PASSIVE_LEVEL.

    This function decrements the reference count on the analysis.
    The memory is freed when the reference count reaches zero.
    After this call, the Analysis pointer is invalid and must not be used.

Arguments:
    Analyzer - Analyzer instance that created the analysis.
    Analysis - Analysis to release. Set to NULL on return.
--*/
_IRQL_requires_(PASSIVE_LEVEL)
VOID
PaFreeAnalysis(
    _In_ PPA_ANALYZER Analyzer,
    _Inout_ PPA_ANALYSIS_RESULT* Analysis
    );

/*++
Routine Description:
    Retrieves analyzer statistics.

    IRQL: Can be called at any IRQL <= DISPATCH_LEVEL.

Arguments:
    Analyzer - Analyzer instance.
    Statistics - Receives current statistics snapshot.

Return Value:
    STATUS_SUCCESS on success.
    STATUS_INVALID_PARAMETER if parameters are invalid.
--*/
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
PaGetStatistics(
    _In_ PPA_ANALYZER Analyzer,
    _Out_ PPA_STATISTICS* Statistics
    );

/*++
Routine Description:
    Invalidates cached analysis for a specific process.
    Call this when a process exits to prevent PID reuse issues.

    IRQL: Must be called at PASSIVE_LEVEL.

Arguments:
    Analyzer - Analyzer instance.
    ProcessId - Process ID to invalidate.
--*/
_IRQL_requires_(PASSIVE_LEVEL)
VOID
PaInvalidateProcess(
    _In_ PPA_ANALYZER Analyzer,
    _In_ HANDLE ProcessId
    );

/*++
Routine Description:
    Gets the API version for compatibility checking.

Return Value:
    Version number in format (Major << 16) | (Minor << 8) | Patch.
--*/
ULONG
PaGetVersion(
    VOID
    );

#ifdef __cplusplus
}
#endif
