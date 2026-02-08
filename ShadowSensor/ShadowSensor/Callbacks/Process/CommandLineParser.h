/*++
===============================================================================
ShadowStrike NGAV - ENTERPRISE COMMAND LINE PARSER
===============================================================================

@file CommandLineParser.h
@brief Kernel-mode command line analysis for EDR operations.

This module provides comprehensive command line parsing and threat detection
for process creation monitoring. All functions are designed for kernel-mode
execution with strict IRQL and memory safety guarantees.

IRQL Requirements:
- All public functions require PASSIVE_LEVEL
- All UNICODE_STRING buffers returned are guaranteed null-terminated

Thread Safety:
- Parser structure is thread-safe for concurrent access
- Parsed command structures are single-owner (not shared)

@author ShadowStrike Security Team
@version 2.1.0 (Enterprise Edition - Hardened)
@copyright (c) 2024 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

//
// Pool tag for all CLP allocations
//
#define CLP_POOL_TAG 'PPLC'

//
// Maximum limits - chosen to balance detection coverage with resource safety
//
#define CLP_MAX_ARGS            128
#define CLP_MAX_ARG_LENGTH      4096
#define CLP_MAX_CMDLINE_LENGTH  32768   // 32KB max command line
#define CLP_MAX_PATH            520     // MAX_PATH + margin

//
// UNICODE_STRING maximum safe length (USHORT max)
//
#define CLP_UNICODE_STRING_MAX_BYTES    65534

//
// Suspicion flags bitmap - each flag represents a detection category
//
typedef enum _CLP_SUSPICION {
    ClpSuspicion_None               = 0x00000000,
    ClpSuspicion_EncodedCommand     = 0x00000001,   // Base64/encoded command detected
    ClpSuspicion_ObfuscatedArgs     = 0x00000002,   // Caret/tick/variable obfuscation
    ClpSuspicion_DownloadCradle     = 0x00000004,   // Download and execute pattern
    ClpSuspicion_ExecutionBypass    = 0x00000008,   // Policy/AMSI bypass attempt
    ClpSuspicion_HiddenWindow       = 0x00000010,   // Hidden window execution
    ClpSuspicion_RemoteExecution    = 0x00000020,   // Remote/lateral movement
    ClpSuspicion_LOLBinAbuse        = 0x00000040,   // Living Off the Land binary
    ClpSuspicion_ScriptExecution    = 0x00000080,   // Script interpreter abuse
    ClpSuspicion_SuspiciousPath     = 0x00000100,   // Execution from suspicious path
    ClpSuspicion_LongCommand        = 0x00000200,   // Anomalously long command
} CLP_SUSPICION;

//
// Parsed command structure
// All UNICODE_STRING buffers are guaranteed null-terminated when valid
//
typedef struct _CLP_PARSED_COMMAND {
    //
    // Original command line (null-terminated copy)
    //
    UNICODE_STRING FullCommandLine;

    //
    // Extracted executable path (null-terminated)
    //
    UNICODE_STRING Executable;

    //
    // Parsed arguments array
    //
    struct {
        UNICODE_STRING Value;   // Null-terminated argument value
        BOOLEAN IsFlag;         // TRUE if starts with - or /
    } Arguments[CLP_MAX_ARGS];
    ULONG ArgumentCount;

    //
    // Analysis results
    //
    CLP_SUSPICION SuspicionFlags;
    ULONG SuspicionScore;           // 0-100 composite score

    //
    // Decoded content (if Base64 encoded command detected)
    //
    UNICODE_STRING DecodedContent;  // Null-terminated decoded command
    BOOLEAN WasDecoded;

} CLP_PARSED_COMMAND, *PCLP_PARSED_COMMAND;

//
// Parser context structure
//
typedef struct _CLP_PARSER {
    BOOLEAN Initialized;

    //
    // LOLBin database with reader-writer synchronization
    //
    LIST_ENTRY LOLBinList;
    EX_PUSH_LOCK LOLBinLock;
    ULONG LOLBinCount;

    //
    // Runtime statistics (atomic access)
    //
    struct {
        volatile LONG64 CommandsParsed;
        volatile LONG64 SuspiciousFound;
        LARGE_INTEGER StartTime;
    } Stats;
} CLP_PARSER, *PCLP_PARSER;

//
// Public API Functions
// All require IRQL == PASSIVE_LEVEL
//

_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
_Must_inspect_result_
NTSTATUS
ClpInitialize(
    _Out_ PCLP_PARSER* Parser
    );

_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID
ClpShutdown(
    _Inout_ PCLP_PARSER Parser
    );

_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
_Must_inspect_result_
NTSTATUS
ClpParse(
    _In_ PCLP_PARSER Parser,
    _In_ PCUNICODE_STRING CommandLine,
    _Out_ PCLP_PARSED_COMMAND* Parsed
    );

_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
_Must_inspect_result_
NTSTATUS
ClpAnalyze(
    _In_ PCLP_PARSER Parser,
    _Inout_ PCLP_PARSED_COMMAND Parsed,
    _Out_ CLP_SUSPICION* Flags,
    _Out_ PULONG Score
    );

_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
_Must_inspect_result_
NTSTATUS
ClpDecodeBase64(
    _In_ PCUNICODE_STRING Encoded,
    _Out_ PUNICODE_STRING Decoded
    );

_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
_Must_inspect_result_
NTSTATUS
ClpIsLOLBin(
    _In_ PCLP_PARSER Parser,
    _In_ PCUNICODE_STRING Executable,
    _Out_ PBOOLEAN IsLOLBin
    );

_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID
ClpFreeParsed(
    _In_opt_ PCLP_PARSED_COMMAND Parsed
    );

#ifdef __cplusplus
}
#endif
