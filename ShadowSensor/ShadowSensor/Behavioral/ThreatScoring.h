/*++
    ShadowStrike Next-Generation Antivirus
    Module: ThreatScoring.h - Enterprise-Grade Threat Score Calculation Engine

    Purpose:
        Production-ready threat scoring subsystem for EDR/XDR operations.
        Provides multi-factor threat aggregation with proper kernel object
        lifecycle management, hash-based lookups, and process exit handling.

    Key Features:
        - O(1) hash table lookup by ProcessId
        - Process creation time validation (PID reuse protection)
        - Proper reference counting with cleanup
        - Process exit notification integration
        - Factor aging and decay
        - Configurable Blocked threshold
        - Thread-safe operations with reader-writer locks
        - In-place score calculation for hot paths

    Security Guarantees:
        - No use-after-free (proper refcounting)
        - No memory leaks (process exit cleanup)
        - No PID reuse attacks (creation time validation)
        - No shutdown races (drain before free)
        - Integer overflow protection
        - DoS prevention via quota and LRU eviction

    IRQL Requirements:
        - All public APIs: PASSIVE_LEVEL (paged code)
        - Internal hash operations: <= APC_LEVEL

    Copyright (c) ShadowStrike Team. All rights reserved.
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>
#include <ntstrsafe.h>

//=============================================================================
// Pool Tags
//=============================================================================

#define TS_POOL_TAG_ENGINE      'ETST'
#define TS_POOL_TAG_SCORE       'STST'
#define TS_POOL_TAG_FACTOR      'FTST'
#define TS_POOL_TAG_PATH        'PTST'

//=============================================================================
// Configuration Constants
//=============================================================================

#define TS_MAX_FACTORS              32
#define TS_HASH_BUCKET_COUNT        256
#define TS_MAX_SCORES_TRACKED       65536
#define TS_MAX_FACTOR_NAME_LEN      64
#define TS_MAX_REASON_LEN           128
#define TS_MAX_VERDICT_REASON_LEN   256
#define TS_MAX_PROCESS_PATH_CHARS   520

//=============================================================================
// Enumerations
//=============================================================================

typedef enum _TS_FACTOR_TYPE {
    TsFactor_Static = 0,                // PE analysis results
    TsFactor_Behavioral,                // Runtime behavior
    TsFactor_Reputation,                // Known good/bad
    TsFactor_Context,                   // Environmental factors
    TsFactor_IOC,                       // IOC matches
    TsFactor_MITRE,                     // MITRE technique matches
    TsFactor_Anomaly,                   // Anomaly detection
    TsFactor_UserDefined,
    TsFactor_MaxValue                   // Sentinel for validation
} TS_FACTOR_TYPE;

typedef enum _TS_VERDICT {
    TsVerdict_Unknown = 0,
    TsVerdict_Clean,
    TsVerdict_Suspicious,
    TsVerdict_Malicious,
    TsVerdict_Blocked,                  // Above blocked threshold - action taken
} TS_VERDICT;

//=============================================================================
// Structures - Public
//=============================================================================

//
// Individual scoring factor (public view)
//
typedef struct _TS_SCORE_FACTOR {
    TS_FACTOR_TYPE Type;
    CHAR FactorName[TS_MAX_FACTOR_NAME_LEN];
    LONG Score;                         // Can be negative (trust) or positive (threat)
    LONG Weight;                        // Multiplier applied
    CHAR Reason[TS_MAX_REASON_LEN];
    LIST_ENTRY ListEntry;               // For internal use
} TS_SCORE_FACTOR, *PTS_SCORE_FACTOR;

//
// Complete threat score result (returned to caller)
//
typedef struct _TS_THREAT_SCORE {
    //
    // Process identification
    //
    HANDLE ProcessId;
    LARGE_INTEGER ProcessCreateTime;    // For PID reuse detection
    UNICODE_STRING ProcessPath;         // Caller must free via TsFreeScore

    //
    // Factors array (embedded, no separate allocation)
    //
    TS_SCORE_FACTOR Factors[TS_MAX_FACTORS];
    ULONG FactorCount;

    //
    // Calculated scores
    //
    LONG RawScore;                      // Sum of weighted factors (clamped)
    ULONG NormalizedScore;              // 0-100 scale

    //
    // Verdict
    //
    TS_VERDICT Verdict;
    CHAR VerdictReason[TS_MAX_VERDICT_REASON_LEN];

    //
    // Thresholds used for verdict
    //
    ULONG SuspiciousThreshold;
    ULONG MaliciousThreshold;
    ULONG BlockedThreshold;

    //
    // Timing
    //
    LARGE_INTEGER CalculationTime;

    //
    // List entry for internal use
    //
    LIST_ENTRY ListEntry;

} TS_THREAT_SCORE, *PTS_THREAT_SCORE;

//
// Factor weight configuration
//
typedef struct _TS_WEIGHT_CONFIG {
    LONG StaticWeight;
    LONG BehavioralWeight;
    LONG ReputationWeight;
    LONG ContextWeight;
    LONG IOCWeight;
    LONG MITREWeight;
    LONG AnomalyWeight;
    LONG UserDefinedWeight;
} TS_WEIGHT_CONFIG, *PTS_WEIGHT_CONFIG;

//
// Factor decay configuration
//
typedef struct _TS_DECAY_CONFIG {
    BOOLEAN EnableDecay;                // Enable factor aging
    ULONG DecayIntervalSeconds;         // Interval between decay steps
    ULONG DecayPercentPerInterval;      // Percent to reduce per interval (0-100)
    ULONG MaxAgeSeconds;                // Maximum factor age before removal
} TS_DECAY_CONFIG, *PTS_DECAY_CONFIG;

//
// Threshold configuration
//
typedef struct _TS_THRESHOLD_CONFIG {
    ULONG SuspiciousThreshold;          // 0-100, default 50
    ULONG MaliciousThreshold;           // 0-100, default 80
    ULONG BlockedThreshold;             // 0-100, default 95
} TS_THRESHOLD_CONFIG, *PTS_THRESHOLD_CONFIG;

//
// Engine statistics
//
typedef struct _TS_STATISTICS {
    volatile LONG64 ScoresCalculated;
    volatile LONG64 FactorsAdded;
    volatile LONG64 VerdictClean;
    volatile LONG64 VerdictSuspicious;
    volatile LONG64 VerdictMalicious;
    volatile LONG64 VerdictBlocked;
    volatile LONG64 ContextsCreated;
    volatile LONG64 ContextsDestroyed;
    volatile LONG64 PidReuseDetected;
    volatile LONG64 FactorsExpired;
    LARGE_INTEGER StartTime;
} TS_STATISTICS, *PTS_STATISTICS;

//
// Opaque engine handle
//
typedef struct _TS_SCORING_ENGINE *PTS_SCORING_ENGINE;

//=============================================================================
// Public API - Initialization
//=============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TsInitialize(
    _Out_ PTS_SCORING_ENGINE* Engine
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
TsShutdown(
    _Inout_ PTS_SCORING_ENGINE Engine
    );

//=============================================================================
// Public API - Configuration
//=============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TsSetThresholds(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ ULONG SuspiciousThreshold,
    _In_ ULONG MaliciousThreshold,
    _In_ ULONG BlockedThreshold
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TsSetWeights(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ PTS_WEIGHT_CONFIG Weights
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TsSetDecayConfig(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ PTS_DECAY_CONFIG DecayConfig
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
TsGetStatistics(
    _In_ PTS_SCORING_ENGINE Engine,
    _Out_ PTS_STATISTICS Statistics
    );

//=============================================================================
// Public API - Scoring Operations
//=============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TsAddFactor(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ HANDLE ProcessId,
    _In_ TS_FACTOR_TYPE Type,
    _In_ PCSTR FactorName,
    _In_ LONG Score,
    _In_ PCSTR Reason
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TsCalculateScore(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ HANDLE ProcessId,
    _Out_ PTS_THREAT_SCORE* Score
    );

//
// In-place calculation - no allocation, caller provides buffer
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TsCalculateScoreInPlace(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ HANDLE ProcessId,
    _Out_ PTS_THREAT_SCORE Score
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TsGetVerdict(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ HANDLE ProcessId,
    _Out_ TS_VERDICT* Verdict,
    _Out_opt_ PULONG NormalizedScore
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TsGetScore(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ HANDLE ProcessId,
    _Out_ PTS_THREAT_SCORE* Score
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
TsFreeScore(
    _In_opt_ PTS_THREAT_SCORE Score
    );

//=============================================================================
// Public API - Process Lifecycle
//=============================================================================

//
// Call from process creation callback to register process
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
TsOnProcessCreate(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ HANDLE ProcessId,
    _In_ LARGE_INTEGER CreateTime
    );

//
// Call from process exit callback to cleanup
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
TsOnProcessExit(
    _In_ PTS_SCORING_ENGINE Engine,
    _In_ HANDLE ProcessId
    );

//=============================================================================
// Public API - Maintenance
//=============================================================================

//
// Run decay/expiration pass (call periodically from worker thread)
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
TsRunMaintenancePass(
    _In_ PTS_SCORING_ENGINE Engine
    );

//
// Remove stale contexts for processes that no longer exist
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
TsPurgeStaleContexts(
    _In_ PTS_SCORING_ENGINE Engine,
    _Out_opt_ PULONG PurgedCount
    );

#ifdef __cplusplus
}
#endif
