/*++
    ShadowStrike Next-Generation Antivirus
    Module: MemoryScanner.h
    
    Purpose: Memory scanning engine for detecting malicious content
             in process memory, including patterns and signatures.
             
    Architecture:
    - Boyer-Moore-Horspool fast pattern matching
    - Aho-Corasick multi-pattern scanning
    - YARA rule support (optional)
    - Asynchronous scanning for performance
    
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>
#include "../../Shared/MemoryTypes.h"

//=============================================================================
// Pool Tags
//=============================================================================

#define MS_POOL_TAG_PATTERN     'PMSM'  // Memory Scanner - Pattern
#define MS_POOL_TAG_CONTEXT     'CMSM'  // Memory Scanner - Context
#define MS_POOL_TAG_RESULT      'RMSM'  // Memory Scanner - Result
#define MS_POOL_TAG_BUFFER      'BMSM'  // Memory Scanner - Buffer

//=============================================================================
// Configuration Constants
//=============================================================================

#define MS_MAX_PATTERNS                 4096
#define MS_MAX_PATTERN_SIZE             1024
#define MS_MIN_PATTERN_SIZE             4
#define MS_SCAN_CHUNK_SIZE              (64 * 1024)     // 64 KB chunks
#define MS_MAX_SCAN_SIZE                (256 * 1024 * 1024)  // 256 MB
#define MS_MAX_MATCHES_PER_SCAN         1024
#define MS_SCAN_TIMEOUT_MS              30000           // 30 seconds

//=============================================================================
// Pattern Types
//=============================================================================

typedef enum _MS_PATTERN_TYPE {
    MsPattern_Exact = 0,                // Exact byte match
    MsPattern_Wildcard,                 // With wildcards (??)
    MsPattern_Regex,                    // Regular expression
    MsPattern_Signature,                // Multi-part signature
    MsPattern_Entropy,                  // High entropy region
    MsPattern_API,                      // API call pattern
} MS_PATTERN_TYPE;

//=============================================================================
// Pattern Flags
//=============================================================================

typedef enum _MS_PATTERN_FLAGS {
    MsPatternFlag_None              = 0x00000000,
    MsPatternFlag_CaseSensitive     = 0x00000001,
    MsPatternFlag_WholeWord         = 0x00000002,
    MsPatternFlag_AtStart           = 0x00000004,
    MsPatternFlag_AtEnd             = 0x00000008,
    MsPatternFlag_Negated           = 0x00000010,   // Match if NOT found
    MsPatternFlag_Critical          = 0x00000020,   // High priority pattern
    MsPatternFlag_Disabled          = 0x00000040,   // Temporarily disabled
} MS_PATTERN_FLAGS;

//=============================================================================
// Scan Type
//=============================================================================

typedef enum _MS_SCAN_TYPE {
    MsScanType_Quick = 0,               // Scan executable regions only
    MsScanType_Standard,                // Scan private regions
    MsScanType_Full,                    // Scan all regions
    MsScanType_Targeted,                // Scan specific region
} MS_SCAN_TYPE;

//=============================================================================
// Scan Flags
//=============================================================================

typedef enum _MS_SCAN_FLAGS {
    MsScanFlag_None                 = 0x00000000,
    MsScanFlag_StopOnFirstMatch     = 0x00000001,
    MsScanFlag_IncludeOffset        = 0x00000002,
    MsScanFlag_IncludeContext       = 0x00000004,   // Include surrounding bytes
    MsScanFlag_Async                = 0x00000008,   // Asynchronous scan
    MsScanFlag_LowPriority          = 0x00000010,   // Lower CPU priority
    MsScanFlag_SkipMapped           = 0x00000020,   // Skip mapped regions
    MsScanFlag_SkipImages           = 0x00000040,   // Skip image regions
    MsScanFlag_OnlyExecutable       = 0x00000080,   // Only executable regions
} MS_SCAN_FLAGS;

//=============================================================================
// Pattern Definition
//=============================================================================

typedef struct _MS_PATTERN {
    //
    // Pattern identification
    //
    ULONG PatternId;
    CHAR PatternName[64];
    MS_PATTERN_TYPE Type;
    MS_PATTERN_FLAGS Flags;
    
    //
    // Pattern data
    //
    PUCHAR PatternData;
    ULONG PatternSize;
    PUCHAR WildcardMask;                // 1 = wildcard at position
    
    //
    // Multi-part signature
    //
    struct {
        ULONG PartCount;
        PUCHAR* Parts;
        ULONG* PartSizes;
        ULONG* PartOffsets;             // Relative offsets
    } Signature;
    
    //
    // Pre-computed search tables (BMH)
    //
    ULONG* BadCharTable;
    BOOLEAN TableComputed;
    
    //
    // Detection metadata
    //
    CHAR ThreatName[128];
    ULONG Severity;                     // 1-100
    ULONG Category;                     // MITRE category
    
    //
    // Statistics
    //
    volatile LONG64 MatchCount;
    LARGE_INTEGER LastMatchTime;
    
    //
    // List linkage
    //
    LIST_ENTRY ListEntry;
    
} MS_PATTERN, *PMS_PATTERN;

//=============================================================================
// Match Result
//=============================================================================

typedef struct _MS_MATCH {
    //
    // Pattern that matched
    //
    ULONG PatternId;
    CHAR PatternName[64];
    
    //
    // Match location
    //
    PVOID MatchAddress;
    ULONG64 MatchOffset;                // Offset within region
    ULONG MatchSize;
    
    //
    // Region information
    //
    PVOID RegionBase;
    SIZE_T RegionSize;
    ULONG RegionProtection;
    
    //
    // Match context (surrounding bytes)
    //
    UCHAR ContextBefore[32];
    UCHAR ContextAfter[32];
    ULONG ContextBeforeSize;
    ULONG ContextAfterSize;
    
    //
    // Detection info
    //
    CHAR ThreatName[128];
    ULONG Severity;
    
    //
    // List linkage
    //
    LIST_ENTRY ListEntry;
    
} MS_MATCH, *PMS_MATCH;

//=============================================================================
// Scan Request
//=============================================================================

typedef struct _MS_SCAN_REQUEST {
    //
    // Target process
    //
    HANDLE ProcessId;
    PEPROCESS Process;
    
    //
    // Scan parameters
    //
    MS_SCAN_TYPE Type;
    MS_SCAN_FLAGS Flags;
    
    //
    // Optional target region
    //
    PVOID TargetAddress;
    SIZE_T TargetSize;
    
    //
    // Pattern filter
    //
    PULONG PatternIds;                  // NULL = all patterns
    ULONG PatternCount;
    
    //
    // Limits
    //
    ULONG MaxMatches;
    ULONG TimeoutMs;
    
    //
    // Async support
    //
    PKEVENT CompletionEvent;
    PVOID CallbackContext;
    
} MS_SCAN_REQUEST, *PMS_SCAN_REQUEST;

//=============================================================================
// Scan Result
//=============================================================================

typedef struct _MS_SCAN_RESULT {
    //
    // Request identification
    //
    HANDLE ProcessId;
    MS_SCAN_TYPE Type;
    
    //
    // Status
    //
    NTSTATUS Status;
    BOOLEAN Completed;
    BOOLEAN TimedOut;
    
    //
    // Matches
    //
    LIST_ENTRY MatchList;
    volatile LONG MatchCount;
    
    //
    // Statistics
    //
    SIZE_T BytesScanned;
    ULONG RegionsScanned;
    LARGE_INTEGER StartTime;
    LARGE_INTEGER EndTime;
    ULONG DurationMs;
    
    //
    // Threat summary
    //
    ULONG MaxSeverity;
    ULONG ThreatCount;
    
} MS_SCAN_RESULT, *PMS_SCAN_RESULT;

//=============================================================================
// Memory Scanner
//=============================================================================

typedef struct _MS_SCANNER {
    //
    // Initialization state
    //
    BOOLEAN Initialized;
    
    //
    // Pattern database
    //
    LIST_ENTRY PatternList;
    EX_PUSH_LOCK PatternLock;
    volatile LONG PatternCount;
    volatile LONG NextPatternId;
    
    //
    // Aho-Corasick automaton (for multi-pattern)
    //
    PVOID AhoCorasickState;
    BOOLEAN AhoCorasickReady;
    EX_PUSH_LOCK AhoCorasickLock;
    
    //
    // Active scans
    //
    LIST_ENTRY ActiveScans;
    KSPIN_LOCK ActiveScansLock;
    volatile LONG ActiveScanCount;
    
    //
    // Work queue
    //
    PVOID WorkQueue;                    // PAWQ_MANAGER
    
    //
    // Statistics
    //
    struct {
        volatile LONG64 TotalScans;
        volatile LONG64 TotalMatches;
        volatile LONG64 BytesScanned;
        volatile LONG64 Timeouts;
        LARGE_INTEGER StartTime;
    } Stats;
    
    //
    // Configuration
    //
    struct {
        ULONG MaxPatterns;
        ULONG ChunkSize;
        ULONG DefaultTimeoutMs;
        BOOLEAN EnableAhoCorasick;
    } Config;
    
} MS_SCANNER, *PMS_SCANNER;

//=============================================================================
// Callback Types
//=============================================================================

typedef VOID (*MS_MATCH_CALLBACK)(
    _In_ PMS_MATCH Match,
    _In_opt_ PVOID Context
    );

typedef VOID (*MS_SCAN_COMPLETE_CALLBACK)(
    _In_ PMS_SCAN_RESULT Result,
    _In_opt_ PVOID Context
    );

//=============================================================================
// Public API - Initialization
//=============================================================================

NTSTATUS
MsInitialize(
    _Out_ PMS_SCANNER* Scanner
    );

VOID
MsShutdown(
    _Inout_ PMS_SCANNER Scanner
    );

NTSTATUS
MsSetWorkQueue(
    _Inout_ PMS_SCANNER Scanner,
    _In_ PVOID WorkQueue
    );

//=============================================================================
// Public API - Pattern Management
//=============================================================================

NTSTATUS
MsAddPattern(
    _In_ PMS_SCANNER Scanner,
    _In_ PCSTR PatternName,
    _In_reads_bytes_(PatternSize) PUCHAR PatternData,
    _In_ ULONG PatternSize,
    _In_ MS_PATTERN_TYPE Type,
    _In_ MS_PATTERN_FLAGS Flags,
    _In_opt_ PCSTR ThreatName,
    _In_ ULONG Severity,
    _Out_ PULONG PatternId
    );

NTSTATUS
MsAddPatternWithMask(
    _In_ PMS_SCANNER Scanner,
    _In_ PCSTR PatternName,
    _In_reads_bytes_(PatternSize) PUCHAR PatternData,
    _In_reads_bytes_(PatternSize) PUCHAR WildcardMask,
    _In_ ULONG PatternSize,
    _In_opt_ PCSTR ThreatName,
    _In_ ULONG Severity,
    _Out_ PULONG PatternId
    );

NTSTATUS
MsRemovePattern(
    _In_ PMS_SCANNER Scanner,
    _In_ ULONG PatternId
    );

NTSTATUS
MsEnablePattern(
    _In_ PMS_SCANNER Scanner,
    _In_ ULONG PatternId,
    _In_ BOOLEAN Enable
    );

NTSTATUS
MsRebuildSearchTables(
    _In_ PMS_SCANNER Scanner
    );

//=============================================================================
// Public API - Scanning
//=============================================================================

NTSTATUS
MsScanProcess(
    _In_ PMS_SCANNER Scanner,
    _In_ HANDLE ProcessId,
    _In_ MS_SCAN_TYPE Type,
    _In_ MS_SCAN_FLAGS Flags,
    _Out_ PMS_SCAN_RESULT* Result
    );

NTSTATUS
MsScanRegion(
    _In_ PMS_SCANNER Scanner,
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _In_ SIZE_T Size,
    _In_ MS_SCAN_FLAGS Flags,
    _Out_ PMS_SCAN_RESULT* Result
    );

NTSTATUS
MsScanBuffer(
    _In_ PMS_SCANNER Scanner,
    _In_reads_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _In_ MS_SCAN_FLAGS Flags,
    _Out_ PMS_SCAN_RESULT* Result
    );

NTSTATUS
MsScanAsync(
    _In_ PMS_SCANNER Scanner,
    _In_ PMS_SCAN_REQUEST Request,
    _In_ MS_SCAN_COMPLETE_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_ PULONG ScanId
    );

NTSTATUS
MsCancelScan(
    _In_ PMS_SCANNER Scanner,
    _In_ ULONG ScanId
    );

//=============================================================================
// Public API - Results
//=============================================================================

VOID
MsFreeScanResult(
    _In_ PMS_SCAN_RESULT Result
    );

NTSTATUS
MsGetNextMatch(
    _In_ PMS_SCAN_RESULT Result,
    _Inout_ PLIST_ENTRY* Iterator,
    _Out_ PMS_MATCH* Match
    );

//=============================================================================
// Public API - Entropy Analysis
//=============================================================================

NTSTATUS
MsCalculateEntropy(
    _In_reads_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _Out_ PULONG EntropyPercent
    );

NTSTATUS
MsFindHighEntropyRegions(
    _In_ PMS_SCANNER Scanner,
    _In_ HANDLE ProcessId,
    _In_ ULONG EntropyThreshold,
    _Out_writes_to_(MaxResults, *ResultCount) PVOID* Results,
    _In_ ULONG MaxResults,
    _Out_ PULONG ResultCount
    );

//=============================================================================
// Public API - Statistics
//=============================================================================

typedef struct _MS_STATISTICS {
    ULONG PatternCount;
    ULONG ActiveScans;
    ULONG64 TotalScans;
    ULONG64 TotalMatches;
    ULONG64 BytesScanned;
    ULONG64 Timeouts;
    LARGE_INTEGER UpTime;
    ULONG AverageScanTimeMs;
} MS_STATISTICS, *PMS_STATISTICS;

NTSTATUS
MsGetStatistics(
    _In_ PMS_SCANNER Scanner,
    _Out_ PMS_STATISTICS Stats
    );

#ifdef __cplusplus
}
#endif
