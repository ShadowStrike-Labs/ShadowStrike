/*++
    ShadowStrike Next-Generation Antivirus
    Module: ThreatScoring.h - Threat score calculation
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

#define TS_POOL_TAG 'OCST'
#define TS_MAX_FACTORS 32

typedef enum _TS_FACTOR_TYPE {
    TsFactor_Static = 0,                // PE analysis results
    TsFactor_Behavioral,                // Runtime behavior
    TsFactor_Reputation,                // Known good/bad
    TsFactor_Context,                   // Environmental factors
    TsFactor_IOC,                       // IOC matches
    TsFactor_MITRE,                     // MITRE technique matches
    TsFactor_Anomaly,                   // Anomaly detection
    TsFactor_UserDefined,
} TS_FACTOR_TYPE;

typedef struct _TS_SCORE_FACTOR {
    TS_FACTOR_TYPE Type;
    CHAR FactorName[64];
    LONG Score;                         // Can be negative (trust) or positive (threat)
    LONG Weight;                        // Multiplier
    CHAR Reason[128];
    LIST_ENTRY ListEntry;
} TS_SCORE_FACTOR, *PTS_SCORE_FACTOR;

typedef enum _TS_VERDICT {
    TsVerdict_Unknown = 0,
    TsVerdict_Clean,
    TsVerdict_Suspicious,
    TsVerdict_Malicious,
    TsVerdict_Blocked,
} TS_VERDICT;

typedef struct _TS_THREAT_SCORE {
    HANDLE ProcessId;
    UNICODE_STRING ProcessPath;
    
    // Factors
    TS_SCORE_FACTOR Factors[TS_MAX_FACTORS];
    ULONG FactorCount;
    
    // Calculated scores
    LONG RawScore;                      // Sum of weighted factors
    ULONG NormalizedScore;              // 0-100
    
    // Verdict
    TS_VERDICT Verdict;
    CHAR VerdictReason[256];
    
    // Thresholds used
    ULONG SuspiciousThreshold;
    ULONG MaliciousThreshold;
    
    LARGE_INTEGER CalculationTime;
    LIST_ENTRY ListEntry;
} TS_THREAT_SCORE, *PTS_THREAT_SCORE;

typedef struct _TS_SCORING_ENGINE {
    BOOLEAN Initialized;
    
    // Configuration
    ULONG SuspiciousThreshold;          // Default 50
    ULONG MaliciousThreshold;           // Default 80
    
    // Factor weights
    struct {
        LONG StaticWeight;
        LONG BehavioralWeight;
        LONG ReputationWeight;
        LONG IOCWeight;
        LONG MITREWeight;
        LONG AnomalyWeight;
    } Weights;
    
    // Scores
    LIST_ENTRY ScoreList;
    EX_PUSH_LOCK ScoreLock;
    volatile LONG ScoreCount;
    
    struct {
        volatile LONG64 ScoresCalculated;
        volatile LONG64 Suspicious;
        volatile LONG64 Malicious;
        LARGE_INTEGER StartTime;
    } Stats;
} TS_SCORING_ENGINE, *PTS_SCORING_ENGINE;

NTSTATUS TsInitialize(_Out_ PTS_SCORING_ENGINE* Engine);
VOID TsShutdown(_Inout_ PTS_SCORING_ENGINE Engine);
NTSTATUS TsSetThresholds(_In_ PTS_SCORING_ENGINE Engine, _In_ ULONG Suspicious, _In_ ULONG Malicious);
NTSTATUS TsAddFactor(_In_ PTS_SCORING_ENGINE Engine, _In_ HANDLE ProcessId, _In_ TS_FACTOR_TYPE Type, _In_ PCSTR FactorName, _In_ LONG Score, _In_ PCSTR Reason);
NTSTATUS TsCalculateScore(_In_ PTS_SCORING_ENGINE Engine, _In_ HANDLE ProcessId, _Out_ PTS_THREAT_SCORE* Score);
NTSTATUS TsGetVerdict(_In_ PTS_SCORING_ENGINE Engine, _In_ HANDLE ProcessId, _Out_ PTS_VERDICT* Verdict, _Out_opt_ PULONG Score);
NTSTATUS TsGetScore(_In_ PTS_SCORING_ENGINE Engine, _In_ HANDLE ProcessId, _Out_ PTS_THREAT_SCORE* Score);
VOID TsFreeScore(_In_ PTS_THREAT_SCORE Score);

#ifdef __cplusplus
}
#endif
