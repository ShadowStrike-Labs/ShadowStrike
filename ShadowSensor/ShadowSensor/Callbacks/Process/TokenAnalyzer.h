/*++
    ShadowStrike Next-Generation Antivirus
    Module: TokenAnalyzer.h - Token manipulation detection
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

#define TA_POOL_TAG 'ANOT'

typedef enum _TA_TOKEN_ATTACK {
    TaAttack_None = 0,
    TaAttack_Impersonation,
    TaAttack_TokenStealing,
    TaAttack_PrivilegeEscalation,
    TaAttack_SIDInjection,
    TaAttack_IntegrityDowngrade,
    TaAttack_GroupModification,
    TaAttack_PrimaryTokenReplace,
} TA_TOKEN_ATTACK;

typedef struct _TA_TOKEN_INFO {
    HANDLE ProcessId;
    HANDLE TokenHandle;
    
    // Token properties
    LUID AuthenticationId;
    TOKEN_TYPE TokenType;
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
    ULONG IntegrityLevel;
    
    // Privileges
    ULONG EnabledPrivileges;
    ULONG PrivilegeCount;
    BOOLEAN HasDebugPrivilege;
    BOOLEAN HasImpersonatePrivilege;
    BOOLEAN HasAssignPrimaryPrivilege;
    
    // Groups
    ULONG GroupCount;
    BOOLEAN IsAdmin;
    BOOLEAN IsSystem;
    BOOLEAN IsService;
    
    // Detection
    TA_TOKEN_ATTACK DetectedAttack;
    ULONG SuspicionScore;
    
} TA_TOKEN_INFO, *PTA_TOKEN_INFO;

typedef struct _TA_ANALYZER {
    BOOLEAN Initialized;
    
    // Token cache
    LIST_ENTRY TokenCache;
    EX_PUSH_LOCK CacheLock;
    volatile LONG CacheCount;
    
    struct {
        volatile LONG64 TokensAnalyzed;
        volatile LONG64 AttacksDetected;
        LARGE_INTEGER StartTime;
    } Stats;
} TA_ANALYZER, *PTA_ANALYZER;

NTSTATUS TaInitialize(_Out_ PTA_ANALYZER* Analyzer);
VOID TaShutdown(_Inout_ PTA_ANALYZER Analyzer);
NTSTATUS TaAnalyzeToken(_In_ PTA_ANALYZER Analyzer, _In_ HANDLE ProcessId, _Out_ PTA_TOKEN_INFO* Info);
NTSTATUS TaDetectTokenManipulation(_In_ PTA_ANALYZER Analyzer, _In_ HANDLE ProcessId, _Out_ PTA_TOKEN_ATTACK* Attack, _Out_ PULONG Score);
NTSTATUS TaCompareTokens(_In_ PTA_ANALYZER Analyzer, _In_ PTA_TOKEN_INFO Original, _In_ PTA_TOKEN_INFO Current, _Out_ PBOOLEAN Changed);
VOID TaFreeTokenInfo(_In_ PTA_TOKEN_INFO Info);

#ifdef __cplusplus
}
#endif
