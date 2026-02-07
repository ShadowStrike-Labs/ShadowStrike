/*++
    ShadowStrike Next-Generation Antivirus
    Module: IOCMatcher.h - Indicator of Compromise matching
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

#define IOM_POOL_TAG 'MOOI'
#define IOM_MAX_IOC_LENGTH 512

typedef enum _IOM_IOC_TYPE {
    IomType_Unknown = 0,
    IomType_FileHash_MD5,
    IomType_FileHash_SHA1,
    IomType_FileHash_SHA256,
    IomType_FilePath,
    IomType_FileName,
    IomType_Registry,
    IomType_Mutex,
    IomType_IPAddress,
    IomType_Domain,
    IomType_URL,
    IomType_EmailAddress,
    IomType_ProcessName,
    IomType_CommandLine,
    IomType_JA3,
    IomType_YARA,
    IomType_Custom,
} IOM_IOC_TYPE;

typedef enum _IOM_SEVERITY {
    IomSeverity_Unknown = 0,
    IomSeverity_Info,
    IomSeverity_Low,
    IomSeverity_Medium,
    IomSeverity_High,
    IomSeverity_Critical,
} IOM_SEVERITY;

typedef struct _IOM_IOC {
    IOM_IOC_TYPE Type;
    IOM_SEVERITY Severity;
    
    // IOC value
    CHAR Value[IOM_MAX_IOC_LENGTH];
    SIZE_T ValueLength;
    
    // Metadata
    CHAR Description[256];
    CHAR ThreatName[64];
    CHAR Source[64];                    // Feed source
    LARGE_INTEGER LastUpdated;
    LARGE_INTEGER Expiry;
    
    // Matching info
    BOOLEAN CaseSensitive;
    BOOLEAN IsRegex;
    
    volatile LONG64 MatchCount;
    LIST_ENTRY ListEntry;
    LIST_ENTRY HashEntry;
} IOM_IOC, *PIOM_IOC;

typedef struct _IOM_MATCH_RESULT {
    PIOM_IOC MatchedIOC;
    IOM_IOC_TYPE Type;
    IOM_SEVERITY Severity;
    
    // Match details
    CHAR MatchedValue[IOM_MAX_IOC_LENGTH];
    HANDLE ProcessId;
    UNICODE_STRING Context;
    
    LARGE_INTEGER MatchTime;
    LIST_ENTRY ListEntry;
} IOM_MATCH_RESULT, *PIOM_MATCH_RESULT;

typedef VOID (*IOM_MATCH_CALLBACK)(
    _In_ PIOM_MATCH_RESULT Match,
    _In_opt_ PVOID Context
);

typedef struct _IOM_MATCHER {
    BOOLEAN Initialized;
    
    // IOC database
    LIST_ENTRY IOCList;
    EX_PUSH_LOCK IOCLock;
    volatile LONG IOCCount;
    
    // Hash tables for fast lookup
    struct {
        LIST_ENTRY* Buckets;
        ULONG BucketCount;
    } HashTable;
    
    // Callbacks
    IOM_MATCH_CALLBACK MatchCallback;
    PVOID CallbackContext;
    
    struct {
        volatile LONG64 IOCsLoaded;
        volatile LONG64 MatchesFound;
        volatile LONG64 QueriesPerformed;
        LARGE_INTEGER StartTime;
    } Stats;
} IOM_MATCHER, *PIOM_MATCHER;

NTSTATUS IomInitialize(_Out_ PIOM_MATCHER* Matcher);
VOID IomShutdown(_Inout_ PIOM_MATCHER Matcher);
NTSTATUS IomLoadIOC(_In_ PIOM_MATCHER Matcher, _In_ PIOM_IOC IOC);
NTSTATUS IomLoadFromBuffer(_In_ PIOM_MATCHER Matcher, _In_ PVOID Buffer, _In_ SIZE_T Size);
NTSTATUS IomRegisterCallback(_In_ PIOM_MATCHER Matcher, _In_ IOM_MATCH_CALLBACK Callback, _In_opt_ PVOID Context);
NTSTATUS IomMatch(_In_ PIOM_MATCHER Matcher, _In_ IOM_IOC_TYPE Type, _In_ PCSTR Value, _Out_ PIOM_MATCH_RESULT* Result);
NTSTATUS IomMatchHash(_In_ PIOM_MATCHER Matcher, _In_ PUCHAR Hash, _In_ SIZE_T HashLength, _In_ IOM_IOC_TYPE HashType, _Out_ PIOM_MATCH_RESULT* Result);
VOID IomFreeResult(_In_ PIOM_MATCH_RESULT Result);

#ifdef __cplusplus
}
#endif
