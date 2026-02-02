/*++
    ShadowStrike Next-Generation Antivirus
    Module: CommandLineParser.h - Command line analysis
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

#define CLP_POOL_TAG 'PPLC'
#define CLP_MAX_ARGS 128
#define CLP_MAX_ARG_LENGTH 4096

typedef enum _CLP_SUSPICION {
    ClpSuspicion_None               = 0x00000000,
    ClpSuspicion_EncodedCommand     = 0x00000001,
    ClpSuspicion_ObfuscatedArgs     = 0x00000002,
    ClpSuspicion_DownloadCradle     = 0x00000004,
    ClpSuspicion_ExecutionBypass    = 0x00000008,
    ClpSuspicion_HiddenWindow       = 0x00000010,
    ClpSuspicion_RemoteExecution    = 0x00000020,
    ClpSuspicion_LOLBinAbuse        = 0x00000040,
    ClpSuspicion_ScriptExecution    = 0x00000080,
    ClpSuspicion_SuspiciousPath     = 0x00000100,
    ClpSuspicion_LongCommand        = 0x00000200,
} CLP_SUSPICION;

typedef struct _CLP_PARSED_COMMAND {
    // Original
    UNICODE_STRING FullCommandLine;
    
    // Parsed
    UNICODE_STRING Executable;
    struct {
        UNICODE_STRING Value;
        BOOLEAN IsFlag;
    } Arguments[CLP_MAX_ARGS];
    ULONG ArgumentCount;
    
    // Analysis
    CLP_SUSPICION SuspicionFlags;
    ULONG SuspicionScore;
    
    // Decoded content (if encoded)
    UNICODE_STRING DecodedContent;
    BOOLEAN WasDecoded;
    
} CLP_PARSED_COMMAND, *PCLP_PARSED_COMMAND;

typedef struct _CLP_PARSER {
    BOOLEAN Initialized;
    
    // LOLBin database
    LIST_ENTRY LOLBinList;
    EX_PUSH_LOCK LOLBinLock;
    
    // Suspicious patterns
    LIST_ENTRY PatternList;
    
    struct {
        volatile LONG64 CommandsParsed;
        volatile LONG64 SuspiciousFound;
        LARGE_INTEGER StartTime;
    } Stats;
} CLP_PARSER, *PCLP_PARSER;

NTSTATUS ClpInitialize(_Out_ PCLP_PARSER* Parser);
VOID ClpShutdown(_Inout_ PCLP_PARSER Parser);
NTSTATUS ClpParse(_In_ PCLP_PARSER Parser, _In_ PUNICODE_STRING CommandLine, _Out_ PCLP_PARSED_COMMAND* Parsed);
NTSTATUS ClpAnalyze(_In_ PCLP_PARSER Parser, _In_ PCLP_PARSED_COMMAND Parsed, _Out_ PCLP_SUSPICION Flags, _Out_ PULONG Score);
NTSTATUS ClpDecodeBase64(_In_ PUNICODE_STRING Encoded, _Out_ PUNICODE_STRING Decoded);
NTSTATUS ClpIsLOLBin(_In_ PCLP_PARSER Parser, _In_ PUNICODE_STRING Executable, _Out_ PBOOLEAN IsLOLBin);
VOID ClpFreeParsed(_In_ PCLP_PARSED_COMMAND Parsed);

#ifdef __cplusplus
}
#endif
