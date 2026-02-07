/*++
    ShadowStrike Next-Generation Antivirus
    Module: HollowingDetector.h
    
    Purpose: Process hollowing and process ghosting detection
             through memory and section analysis.
             
    Architecture:
    - Image section vs file comparison
    - Entry point validation
    - PEB/TEB tampering detection
    - Transacted section detection (doppelganging)
    
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

#define PH_POOL_TAG_CONTEXT     'CXHP'  // Process Hollowing - Context
#define PH_POOL_TAG_RESULT      'ERHP'  // Process Hollowing - Result
#define PH_POOL_TAG_BUFFER      'FBHP'  // Process Hollowing - Buffer

//=============================================================================
// Configuration Constants
//=============================================================================

#define PH_MAX_HEADER_SIZE              4096
#define PH_SCAN_TIMEOUT_MS              30000
#define PH_MAX_SECTION_COMPARE_SIZE     (64 * 1024)

//=============================================================================
// Hollowing Types
//=============================================================================

typedef enum _PH_HOLLOWING_TYPE {
    PhHollowing_None = 0,
    PhHollowing_Classic,                // Classic process hollowing
    PhHollowing_Doppelganging,          // Process doppelganging
    PhHollowing_Herpaderping,           // Process herpaderping
    PhHollowing_Ghosting,               // Process ghosting
    PhHollowing_Overwriting,            // Process overwriting
    PhHollowing_Phantom,                // Phantom DLL hollowing
    PhHollowing_ModuleStomping,         // Module stomping
    PhHollowing_TransactionHollow,      // Transacted hollowing
} PH_HOLLOWING_TYPE;

//=============================================================================
// Detection Indicators
//=============================================================================

typedef enum _PH_INDICATORS {
    PhIndicator_None                    = 0x00000000,
    PhIndicator_ImagePathMismatch       = 0x00000001,   // PEB vs actual image
    PhIndicator_SectionMismatch         = 0x00000002,   // Memory != file
    PhIndicator_EntryPointModified      = 0x00000004,   // EP tampered
    PhIndicator_HeaderModified          = 0x00000008,   // PE header changed
    PhIndicator_UnmappedMainModule      = 0x00000010,   // Main module unmapped
    PhIndicator_TransactedFile          = 0x00000020,   // TxF transaction
    PhIndicator_DeletedFile             = 0x00000040,   // Backing file deleted
    PhIndicator_SuspiciousThread        = 0x00000080,   // Suspended at creation
    PhIndicator_ModifiedPEB             = 0x00000100,   // PEB tampering
    PhIndicator_HiddenMemory            = 0x00000200,   // Hidden memory regions
    PhIndicator_NoPhysicalFile          = 0x00000400,   // No file on disk
    PhIndicator_HashMismatch            = 0x00000800,   // File hash mismatch
    PhIndicator_TimestampAnomaly        = 0x00001000,   // Timestamp issues
    PhIndicator_SectionCreation         = 0x00002000,   // Suspicious section
    PhIndicator_MemoryProtection        = 0x00004000,   // RWX regions
} PH_INDICATORS;

//=============================================================================
// Process Analysis Result
//=============================================================================

typedef struct _PH_ANALYSIS_RESULT {
    //
    // Detection summary
    //
    BOOLEAN HollowingDetected;
    PH_HOLLOWING_TYPE Type;
    PH_INDICATORS Indicators;
    ULONG ConfidenceScore;              // 0-100
    ULONG SeverityScore;                // 0-100
    
    //
    // Process information
    //
    HANDLE ProcessId;
    UNICODE_STRING ClaimedImagePath;    // What PEB says
    UNICODE_STRING ActualImagePath;     // What we found
    UNICODE_STRING ProcessName;
    
    //
    // Image comparison
    //
    struct {
        PVOID MemoryBase;
        SIZE_T MemorySize;
        UCHAR MemoryHash[32];           // SHA-256
        
        PVOID FileBase;
        ULONG64 FileSize;
        UCHAR FileHash[32];
        
        BOOLEAN HashMatch;
        ULONG MismatchOffset;           // First mismatch location
        SIZE_T MismatchSize;            // Size of mismatch region
    } ImageComparison;
    
    //
    // Entry point analysis
    //
    struct {
        PVOID DeclaredEntryPoint;       // From PE header
        PVOID ActualEntryPoint;         // From memory
        BOOLEAN EntryPointValid;
        BOOLEAN EntryPointExecutable;
        BOOLEAN EntryPointInImage;      // In image bounds
    } EntryPoint;
    
    //
    // Section analysis
    //
    struct {
        BOOLEAN HasBackingFile;
        BOOLEAN FileIsTransacted;
        BOOLEAN FileIsDeleted;
        BOOLEAN FileIsLocked;
        UNICODE_STRING BackingFileName;
    } Section;
    
    //
    // PEB analysis
    //
    struct {
        BOOLEAN PebModified;
        BOOLEAN ImageBaseModified;
        BOOLEAN ProcessParametersModified;
        BOOLEAN CommandLineModified;
    } PEB;
    
    //
    // Memory regions
    //
    struct {
        ULONG SuspiciousRegionCount;
        ULONG RWXRegionCount;
        ULONG UnbackedExecutableCount;
        SIZE_T TotalSuspiciousSize;
    } Memory;
    
    //
    // Timing
    //
    LARGE_INTEGER ProcessCreateTime;
    LARGE_INTEGER FirstThreadCreateTime;
    LARGE_INTEGER AnalysisTime;
    ULONG AnalysisDurationMs;
    
} PH_ANALYSIS_RESULT, *PPH_ANALYSIS_RESULT;

//=============================================================================
// Process Hollowing Detector
//=============================================================================

typedef struct _PH_DETECTOR {
    //
    // Initialization state
    //
    BOOLEAN Initialized;
    
    //
    // Active analyses
    //
    LIST_ENTRY ActiveAnalyses;
    KSPIN_LOCK AnalysisLock;
    volatile LONG ActiveCount;
    
    //
    // Configuration
    //
    struct {
        BOOLEAN CompareWithFile;
        BOOLEAN AnalyzePEB;
        BOOLEAN AnalyzeEntryPoint;
        BOOLEAN AnalyzeMemoryRegions;
        ULONG TimeoutMs;
        ULONG MinConfidenceToReport;
    } Config;
    
    //
    // Statistics
    //
    struct {
        volatile LONG64 ProcessesAnalyzed;
        volatile LONG64 HollowingDetected;
        volatile LONG64 DoppelgangingDetected;
        volatile LONG64 GhostingDetected;
        LARGE_INTEGER StartTime;
    } Stats;
    
} PH_DETECTOR, *PPH_DETECTOR;

//=============================================================================
// Callback Types
//=============================================================================

typedef VOID (*PH_DETECTION_CALLBACK)(
    _In_ PPH_ANALYSIS_RESULT Result,
    _In_opt_ PVOID Context
    );

//=============================================================================
// Public API - Initialization
//=============================================================================

NTSTATUS
PhInitialize(
    _Out_ PPH_DETECTOR* Detector
    );

VOID
PhShutdown(
    _Inout_ PPH_DETECTOR Detector
    );

//=============================================================================
// Public API - Detection
//=============================================================================

NTSTATUS
PhAnalyzeProcess(
    _In_ PPH_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _Out_ PPH_ANALYSIS_RESULT* Result
    );

NTSTATUS
PhAnalyzeAtCreation(
    _In_ PPH_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ HANDLE ParentId,
    _In_ PEPROCESS Process,
    _Out_ PPH_ANALYSIS_RESULT* Result
    );

NTSTATUS
PhQuickCheck(
    _In_ PPH_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _Out_ PBOOLEAN IsHollowed,
    _Out_opt_ PPH_HOLLOWING_TYPE Type,
    _Out_opt_ PULONG Score
    );

//=============================================================================
// Public API - Specific Checks
//=============================================================================

NTSTATUS
PhCompareImageWithFile(
    _In_ PPH_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _Out_ PBOOLEAN Match,
    _Out_opt_ PULONG MismatchOffset
    );

NTSTATUS
PhValidateEntryPoint(
    _In_ PPH_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _Out_ PBOOLEAN Valid
    );

NTSTATUS
PhCheckForDoppelganging(
    _In_ PPH_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _Out_ PBOOLEAN IsDoppelganging
    );

NTSTATUS
PhCheckForGhosting(
    _In_ PPH_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _Out_ PBOOLEAN IsGhosting
    );

//=============================================================================
// Public API - Callbacks
//=============================================================================

NTSTATUS
PhRegisterCallback(
    _In_ PPH_DETECTOR Detector,
    _In_ PH_DETECTION_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

VOID
PhUnregisterCallback(
    _In_ PPH_DETECTOR Detector,
    _In_ PH_DETECTION_CALLBACK Callback
    );

//=============================================================================
// Public API - Results
//=============================================================================

VOID
PhFreeResult(
    _In_ PPH_ANALYSIS_RESULT Result
    );

//=============================================================================
// Public API - Statistics
//=============================================================================

typedef struct _PH_STATISTICS {
    ULONG64 ProcessesAnalyzed;
    ULONG64 HollowingDetected;
    ULONG64 DoppelgangingDetected;
    ULONG64 GhostingDetected;
    LARGE_INTEGER UpTime;
} PH_STATISTICS, *PPH_STATISTICS;

NTSTATUS
PhGetStatistics(
    _In_ PPH_DETECTOR Detector,
    _Out_ PPH_STATISTICS Stats
    );

#ifdef __cplusplus
}
#endif
