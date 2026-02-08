/*++
===============================================================================
ShadowStrike NGAV - ENTERPRISE COMMAND LINE PARSER IMPLEMENTATION
===============================================================================

@file CommandLineParser.c
@brief Enterprise-grade command line analysis for kernel-mode EDR operations.

This module provides comprehensive command line parsing and threat detection:
- Full argument parsing with proper quote and escape handling
- Base64/encoded command detection and decoding
- LOLBin (Living Off the Land Binary) detection
- Obfuscation pattern recognition (caret insertion, variable expansion)
- Download cradle detection (PowerShell, certutil, bitsadmin)
- Execution policy bypass detection
- Hidden window execution detection
- Remote execution pattern detection
- Suspicious path detection (temp, appdata, recycle bin)
- Long command line anomaly detection
- Script interpreter abuse detection

Detection Techniques Covered (MITRE ATT&CK):
- T1059: Command and Scripting Interpreter
- T1059.001: PowerShell
- T1059.003: Windows Command Shell
- T1059.005: Visual Basic
- T1059.007: JavaScript
- T1218: System Binary Proxy Execution (LOLBins)
- T1027: Obfuscated Files or Information
- T1027.010: Command Obfuscation
- T1105: Ingress Tool Transfer (download cradles)
- T1564.003: Hidden Window

Security Hardening (v2.1.0):
- All string operations use length-bounded comparisons (NO CRT functions)
- All allocations from PagedPool where safe, with size validation
- Integer overflow protection on all length calculations
- Explicit IRQL requirements and SAL annotations
- Guaranteed null-termination on all returned strings

@author ShadowStrike Security Team
@version 2.1.0 (Enterprise Edition - Hardened)
@copyright (c) 2024 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#include "CommandLineParser.h"
#include "../../Utilities/MemoryUtils.h"
#include "../../Utilities/StringUtils.h"
#include <ntstrsafe.h>

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, ClpInitialize)
#pragma alloc_text(PAGE, ClpShutdown)
#pragma alloc_text(PAGE, ClpParse)
#pragma alloc_text(PAGE, ClpAnalyze)
#pragma alloc_text(PAGE, ClpDecodeBase64)
#pragma alloc_text(PAGE, ClpIsLOLBin)
#pragma alloc_text(PAGE, ClpFreeParsed)
#endif

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

//
// Base64 decoding limits
//
#define CLP_MAX_DECODED_LENGTH      65534   // Must fit in USHORT
#define CLP_MIN_BASE64_LENGTH       8

//
// Command line length thresholds for anomaly detection
// Rationale: Normal commands rarely exceed 2KB; malware often uses very long
// encoded/obfuscated commands to evade simple pattern matching
//
#define CLP_LONG_CMDLINE_THRESHOLD  2048
#define CLP_VERY_LONG_THRESHOLD     8192

//
// Obfuscation detection thresholds
// These values are tuned based on analysis of real-world attack samples:
// - Caret insertion (cmd.exe): p^o^w^e^r^s^h^e^l^l requires 5+ carets
// - Environment variable abuse: %COMSPEC:~0,1% patterns use many % signs
// - PowerShell tick escaping: pow`er`shell uses 3+ backticks
//
#define CLP_OBFUSCATION_CARET_THRESHOLD     5
#define CLP_OBFUSCATION_PERCENT_THRESHOLD   10
#define CLP_OBFUSCATION_TICK_THRESHOLD      3

//
// Suspicion score weights
// Scores are additive; higher weight = stronger indicator of malicious intent
//
#define CLP_SCORE_ENCODED_COMMAND       25
#define CLP_SCORE_OBFUSCATED            20
#define CLP_SCORE_DOWNLOAD_CRADLE       30
#define CLP_SCORE_EXECUTION_BYPASS      15
#define CLP_SCORE_HIDDEN_WINDOW         10
#define CLP_SCORE_REMOTE_EXECUTION      25
#define CLP_SCORE_LOLBIN_ABUSE          15
#define CLP_SCORE_SCRIPT_EXECUTION      10
#define CLP_SCORE_SUSPICIOUS_PATH       15
#define CLP_SCORE_LONG_COMMAND          5
#define CLP_SCORE_VERY_LONG_COMMAND     10
#define CLP_SCORE_LOLBIN_ENCODED_COMBO  10
#define CLP_SCORE_LOLBIN_DOWNLOAD_COMBO 10
#define CLP_SCORE_MAX                   100

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

//
// LOLBin entry for hash-based lookup
//
typedef struct _CLP_LOLBIN_ENTRY {
    LIST_ENTRY ListEntry;
    UNICODE_STRING Name;            // Points to static string (do not free)
    ULONG NameHash;
    ULONG ThreatLevel;              // 1=Low, 2=Medium, 3=High
    ULONG Category;                 // Bitmap of usage categories
    BOOLEAN IsStaticString;         // TRUE = Name.Buffer is static, do not free
} CLP_LOLBIN_ENTRY, *PCLP_LOLBIN_ENTRY;

//
// LOLBin categories
//
#define CLP_LOLBIN_CAT_EXECUTE      0x0001
#define CLP_LOLBIN_CAT_DOWNLOAD     0x0002
#define CLP_LOLBIN_CAT_ENCODE       0x0004
#define CLP_LOLBIN_CAT_COMPILE      0x0008
#define CLP_LOLBIN_CAT_SCRIPT       0x0010
#define CLP_LOLBIN_CAT_UAC_BYPASS   0x0020
#define CLP_LOLBIN_CAT_ADS          0x0040
#define CLP_LOLBIN_CAT_COPY         0x0080

// ============================================================================
// STATIC LOLBin DATABASE
// ============================================================================

typedef struct _CLP_LOLBIN_DEF {
    PCWSTR Name;
    ULONG ThreatLevel;
    ULONG Category;
} CLP_LOLBIN_DEF;

static const CLP_LOLBIN_DEF g_LOLBinDefinitions[] = {
    // High threat LOLBins
    { L"mshta.exe",         3, CLP_LOLBIN_CAT_EXECUTE | CLP_LOLBIN_CAT_SCRIPT },
    { L"regsvr32.exe",      3, CLP_LOLBIN_CAT_EXECUTE | CLP_LOLBIN_CAT_SCRIPT },
    { L"rundll32.exe",      3, CLP_LOLBIN_CAT_EXECUTE },
    { L"msiexec.exe",       3, CLP_LOLBIN_CAT_EXECUTE | CLP_LOLBIN_CAT_DOWNLOAD },
    { L"certutil.exe",      3, CLP_LOLBIN_CAT_DOWNLOAD | CLP_LOLBIN_CAT_ENCODE },
    { L"bitsadmin.exe",     3, CLP_LOLBIN_CAT_DOWNLOAD | CLP_LOLBIN_CAT_EXECUTE },

    // Medium threat LOLBins
    { L"wmic.exe",          2, CLP_LOLBIN_CAT_EXECUTE | CLP_LOLBIN_CAT_SCRIPT },
    { L"wscript.exe",       2, CLP_LOLBIN_CAT_SCRIPT },
    { L"cscript.exe",       2, CLP_LOLBIN_CAT_SCRIPT },
    { L"msbuild.exe",       2, CLP_LOLBIN_CAT_COMPILE | CLP_LOLBIN_CAT_EXECUTE },
    { L"installutil.exe",   2, CLP_LOLBIN_CAT_EXECUTE },
    { L"regasm.exe",        2, CLP_LOLBIN_CAT_EXECUTE },
    { L"regsvcs.exe",       2, CLP_LOLBIN_CAT_EXECUTE },
    { L"cmstp.exe",         2, CLP_LOLBIN_CAT_EXECUTE | CLP_LOLBIN_CAT_UAC_BYPASS },
    { L"msconfig.exe",      2, CLP_LOLBIN_CAT_UAC_BYPASS },
    { L"mmc.exe",           2, CLP_LOLBIN_CAT_EXECUTE },
    { L"control.exe",       2, CLP_LOLBIN_CAT_EXECUTE },
    { L"pcalua.exe",        2, CLP_LOLBIN_CAT_EXECUTE },
    { L"infdefaultinstall.exe", 2, CLP_LOLBIN_CAT_EXECUTE },
    { L"syncappvpublishingserver.exe", 2, CLP_LOLBIN_CAT_EXECUTE },
    { L"hh.exe",            2, CLP_LOLBIN_CAT_EXECUTE },
    { L"ieexec.exe",        2, CLP_LOLBIN_CAT_EXECUTE | CLP_LOLBIN_CAT_DOWNLOAD },
    { L"dnscmd.exe",        2, CLP_LOLBIN_CAT_EXECUTE },
    { L"ftp.exe",           2, CLP_LOLBIN_CAT_DOWNLOAD },
    { L"replace.exe",       2, CLP_LOLBIN_CAT_COPY },
    { L"eudcedit.exe",      2, CLP_LOLBIN_CAT_UAC_BYPASS },
    { L"eventvwr.exe",      2, CLP_LOLBIN_CAT_UAC_BYPASS },
    { L"fodhelper.exe",     2, CLP_LOLBIN_CAT_UAC_BYPASS },
    { L"computerdefaults.exe", 2, CLP_LOLBIN_CAT_UAC_BYPASS },
    { L"slui.exe",          2, CLP_LOLBIN_CAT_UAC_BYPASS },
    { L"sdclt.exe",         2, CLP_LOLBIN_CAT_UAC_BYPASS },

    // Lower threat but monitored
    { L"forfiles.exe",      1, CLP_LOLBIN_CAT_EXECUTE },
    { L"schtasks.exe",      1, CLP_LOLBIN_CAT_EXECUTE },
    { L"at.exe",            1, CLP_LOLBIN_CAT_EXECUTE },
    { L"sc.exe",            1, CLP_LOLBIN_CAT_EXECUTE },
    { L"reg.exe",           1, CLP_LOLBIN_CAT_EXECUTE },
    { L"netsh.exe",         1, CLP_LOLBIN_CAT_EXECUTE },
    { L"curl.exe",          1, CLP_LOLBIN_CAT_DOWNLOAD },
    { L"wget.exe",          1, CLP_LOLBIN_CAT_DOWNLOAD },
    { L"expand.exe",        1, CLP_LOLBIN_CAT_COPY },
    { L"extrac32.exe",      1, CLP_LOLBIN_CAT_COPY },
    { L"makecab.exe",       1, CLP_LOLBIN_CAT_COPY },
    { L"esentutl.exe",      1, CLP_LOLBIN_CAT_COPY | CLP_LOLBIN_CAT_ADS },
    { L"findstr.exe",       1, CLP_LOLBIN_CAT_ADS },
    { L"print.exe",         1, CLP_LOLBIN_CAT_COPY },
    { L"xwizard.exe",       1, CLP_LOLBIN_CAT_EXECUTE },
    { L"presentationhost.exe", 1, CLP_LOLBIN_CAT_EXECUTE },
    { L"bash.exe",          1, CLP_LOLBIN_CAT_EXECUTE | CLP_LOLBIN_CAT_SCRIPT },
    { L"wsl.exe",           1, CLP_LOLBIN_CAT_EXECUTE | CLP_LOLBIN_CAT_SCRIPT },
};

#define CLP_LOLBIN_COUNT (sizeof(g_LOLBinDefinitions) / sizeof(g_LOLBinDefinitions[0]))

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static NTSTATUS
ClppInitializeLOLBinDatabase(
    _Inout_ PCLP_PARSER Parser
    );

static VOID
ClppCleanupLOLBinDatabase(
    _Inout_ PCLP_PARSER Parser
    );

static ULONG
ClppHashStringBounded(
    _In_reads_(Length) PCWCH Buffer,
    _In_ USHORT Length,
    _In_ BOOLEAN CaseInsensitive
    );

static NTSTATUS
ClppAllocateParsedCommand(
    _Out_ PCLP_PARSED_COMMAND* Parsed
    );

static NTSTATUS
ClppParseArguments(
    _In_ PCUNICODE_STRING CommandLine,
    _Inout_ PCLP_PARSED_COMMAND Parsed
    );

static NTSTATUS
ClppExtractExecutable(
    _In_ PCUNICODE_STRING CommandLine,
    _Out_ PUNICODE_STRING Executable
    );

static BOOLEAN
ClppDetectEncodedCommand(
    _In_ PCLP_PARSED_COMMAND Parsed
    );

static BOOLEAN
ClppDetectObfuscation(
    _In_ PCUNICODE_STRING CommandLine
    );

static BOOLEAN
ClppDetectDownloadCradle(
    _In_ PCUNICODE_STRING CommandLine
    );

static BOOLEAN
ClppDetectExecutionBypass(
    _In_ PCUNICODE_STRING CommandLine
    );

static BOOLEAN
ClppDetectHiddenWindow(
    _In_ PCUNICODE_STRING CommandLine
    );

static BOOLEAN
ClppDetectRemoteExecution(
    _In_ PCUNICODE_STRING CommandLine
    );

static BOOLEAN
ClppDetectSuspiciousPath(
    _In_ PCUNICODE_STRING CommandLine
    );

static BOOLEAN
ClppDetectScriptExecution(
    _In_ PCLP_PARSED_COMMAND Parsed
    );

static BOOLEAN
ClppContainsPatternBounded(
    _In_ PCUNICODE_STRING String,
    _In_ PCWSTR Pattern,
    _In_ USHORT PatternLengthChars,
    _In_ BOOLEAN CaseInsensitive
    );

static NTSTATUS
ClppDecodeBase64Unicode(
    _In_ PCUNICODE_STRING Encoded,
    _Out_ PUNICODE_STRING Decoded
    );

static BOOLEAN
ClppIsValidBase64Char(
    _In_ WCHAR Ch
    );

static UCHAR
ClppBase64CharToValue(
    _In_ WCHAR Ch,
    _Out_ PBOOLEAN IsValid
    );

static NTSTATUS
ClppCopyUnicodeStringSafe(
    _Out_ PUNICODE_STRING Destination,
    _In_ PCUNICODE_STRING Source
    );

static VOID
ClppFreeUnicodeStringSafe(
    _Inout_ PUNICODE_STRING String
    );

static WCHAR
ClppToLowerAscii(
    _In_ WCHAR Ch
    );

static BOOLEAN
ClppCompareStringBoundedCaseInsensitive(
    _In_reads_(Length1) PCWCH Buffer1,
    _In_ USHORT Length1,
    _In_reads_(Length2) PCWCH Buffer2,
    _In_ USHORT Length2
    );

static USHORT
ClppFindLastCharBounded(
    _In_reads_(LengthChars) PCWCH Buffer,
    _In_ USHORT LengthChars,
    _In_ WCHAR Target
    );

// ============================================================================
// INITIALIZATION AND CLEANUP
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ClpInitialize(
    _Out_ PCLP_PARSER* Parser
    )
/*++
Routine Description:
    Initializes the command line parser subsystem.

Arguments:
    Parser - Receives pointer to initialized parser.

Return Value:
    STATUS_SUCCESS on success.
    STATUS_INVALID_PARAMETER if Parser is NULL.
    STATUS_INSUFFICIENT_RESOURCES on allocation failure.

IRQL:
    Must be called at PASSIVE_LEVEL.
--*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    PCLP_PARSER NewParser = NULL;

    PAGED_CODE();

    if (Parser == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Parser = NULL;

    //
    // Allocate parser structure from NonPagedPoolNx
    // Parser itself needs NonPaged as it contains synchronization primitives
    //
    NewParser = (PCLP_PARSER)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(CLP_PARSER),
        CLP_POOL_TAG
        );

    if (NewParser == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(NewParser, sizeof(CLP_PARSER));

    //
    // Initialize synchronization
    //
    InitializeListHead(&NewParser->LOLBinList);
    ExInitializePushLock(&NewParser->LOLBinLock);

    //
    // Initialize LOLBin database
    //
    Status = ClppInitializeLOLBinDatabase(NewParser);
    if (!NT_SUCCESS(Status)) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "[ShadowStrike/CLP] Failed to initialize LOLBin database: 0x%08X\n",
            Status
            );
        goto Cleanup;
    }

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&NewParser->Stats.StartTime);
    InterlockedExchange64(&NewParser->Stats.CommandsParsed, 0);
    InterlockedExchange64(&NewParser->Stats.SuspiciousFound, 0);

    NewParser->Initialized = TRUE;
    *Parser = NewParser;

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[ShadowStrike/CLP] Command line parser initialized with %lu LOLBins\n",
        NewParser->LOLBinCount
        );

    return STATUS_SUCCESS;

Cleanup:
    if (NewParser != NULL) {
        ClppCleanupLOLBinDatabase(NewParser);
        ShadowStrikeFreePoolWithTag(NewParser, CLP_POOL_TAG);
    }

    return Status;
}


_Use_decl_annotations_
VOID
ClpShutdown(
    _Inout_ PCLP_PARSER Parser
    )
/*++
Routine Description:
    Shuts down the command line parser and frees resources.

Arguments:
    Parser - Parser to shutdown.

IRQL:
    Must be called at PASSIVE_LEVEL.
--*/
{
    LONG64 CommandsParsed;
    LONG64 SuspiciousFound;

    PAGED_CODE();

    if (Parser == NULL) {
        return;
    }

    if (!Parser->Initialized) {
        return;
    }

    Parser->Initialized = FALSE;

    //
    // Read statistics atomically for logging
    //
    CommandsParsed = InterlockedCompareExchange64(
        &Parser->Stats.CommandsParsed, 0, 0);
    SuspiciousFound = InterlockedCompareExchange64(
        &Parser->Stats.SuspiciousFound, 0, 0);

    //
    // Cleanup databases
    //
    ClppCleanupLOLBinDatabase(Parser);

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[ShadowStrike/CLP] Command line parser shutdown. "
        "Stats: Parsed=%lld, Suspicious=%lld\n",
        CommandsParsed,
        SuspiciousFound
        );

    //
    // Free parser structure
    //
    ShadowStrikeFreePoolWithTag(Parser, CLP_POOL_TAG);
}


// ============================================================================
// MAIN PARSING FUNCTIONS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ClpParse(
    _In_ PCLP_PARSER Parser,
    _In_ PCUNICODE_STRING CommandLine,
    _Out_ PCLP_PARSED_COMMAND* Parsed
    )
/*++
Routine Description:
    Parses a command line into its components.

Arguments:
    Parser      - Initialized parser.
    CommandLine - Command line to parse.
    Parsed      - Receives parsed command structure.

Return Value:
    STATUS_SUCCESS on success.

IRQL:
    Must be called at PASSIVE_LEVEL.
--*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    PCLP_PARSED_COMMAND ParsedCmd = NULL;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (Parser == NULL || !Parser->Initialized) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (CommandLine == NULL || CommandLine->Buffer == NULL || CommandLine->Length == 0) {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (Parsed == NULL) {
        return STATUS_INVALID_PARAMETER_3;
    }

    *Parsed = NULL;

    //
    // Validate command line length to prevent DoS
    //
    if (CommandLine->Length > CLP_MAX_CMDLINE_LENGTH) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_WARNING_LEVEL,
            "[ShadowStrike/CLP] Command line too long: %u bytes (max %u)\n",
            CommandLine->Length,
            CLP_MAX_CMDLINE_LENGTH
            );
        return STATUS_BUFFER_OVERFLOW;
    }

    //
    // Allocate parsed command structure
    //
    Status = ClppAllocateParsedCommand(&ParsedCmd);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Copy full command line (creates null-terminated copy)
    //
    Status = ClppCopyUnicodeStringSafe(&ParsedCmd->FullCommandLine, CommandLine);
    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    //
    // Extract executable path
    //
    Status = ClppExtractExecutable(CommandLine, &ParsedCmd->Executable);
    if (!NT_SUCCESS(Status)) {
        //
        // Non-fatal: continue without executable
        //
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_TRACE_LEVEL,
            "[ShadowStrike/CLP] Could not extract executable from command line\n"
            );
        Status = STATUS_SUCCESS;
    }

    //
    // Parse arguments
    //
    Status = ClppParseArguments(CommandLine, ParsedCmd);
    if (!NT_SUCCESS(Status)) {
        //
        // Non-fatal: continue with what we have
        //
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_TRACE_LEVEL,
            "[ShadowStrike/CLP] Argument parsing incomplete: 0x%08X\n",
            Status
            );
        Status = STATUS_SUCCESS;
    }

    //
    // Update statistics
    //
    InterlockedIncrement64(&Parser->Stats.CommandsParsed);

    *Parsed = ParsedCmd;
    return STATUS_SUCCESS;

Cleanup:
    if (ParsedCmd != NULL) {
        ClpFreeParsed(ParsedCmd);
    }

    return Status;
}


_Use_decl_annotations_
NTSTATUS
ClpAnalyze(
    _In_ PCLP_PARSER Parser,
    _Inout_ PCLP_PARSED_COMMAND Parsed,
    _Out_ CLP_SUSPICION* Flags,
    _Out_ PULONG Score
    )
/*++
Routine Description:
    Analyzes a parsed command for suspicious indicators.

Arguments:
    Parser  - Initialized parser.
    Parsed  - Parsed command to analyze (may be modified to store decoded content).
    Flags   - Receives suspicion flags.
    Score   - Receives suspicion score (0-100).

Return Value:
    STATUS_SUCCESS on success.

IRQL:
    Must be called at PASSIVE_LEVEL.
--*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    CLP_SUSPICION SuspicionFlags = ClpSuspicion_None;
    ULONG SuspicionScore = 0;
    BOOLEAN IsLOLBin = FALSE;
    SIZE_T CmdLineLength;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (Parser == NULL || !Parser->Initialized) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (Parsed == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (Flags == NULL || Score == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Flags = ClpSuspicion_None;
    *Score = 0;

    //
    // Check for encoded commands (PowerShell -enc, etc.)
    //
    if (ClppDetectEncodedCommand(Parsed)) {
        SuspicionFlags |= ClpSuspicion_EncodedCommand;
        SuspicionScore += CLP_SCORE_ENCODED_COMMAND;

        //
        // Attempt to decode for further analysis
        //
        if (!Parsed->WasDecoded) {
            for (ULONG i = 0; i < Parsed->ArgumentCount; i++) {
                //
                // Look for the argument after -enc/-e
                //
                if (Parsed->Arguments[i].IsFlag &&
                    Parsed->Arguments[i].Value.Buffer != NULL &&
                    Parsed->Arguments[i].Value.Length > 0) {

                    PCUNICODE_STRING Flag = &Parsed->Arguments[i].Value;
                    USHORT FlagLenChars = Flag->Length / sizeof(WCHAR);

                    //
                    // Check for encoded command flags using bounded comparison
                    //
                    BOOLEAN IsEncFlag = FALSE;

                    if (FlagLenChars == 4 &&
                        ClppCompareStringBoundedCaseInsensitive(
                            Flag->Buffer, FlagLenChars, L"-enc", 4)) {
                        IsEncFlag = TRUE;
                    } else if (FlagLenChars == 2 &&
                        ClppCompareStringBoundedCaseInsensitive(
                            Flag->Buffer, FlagLenChars, L"-e", 2)) {
                        IsEncFlag = TRUE;
                    } else if (FlagLenChars == 3 &&
                        ClppCompareStringBoundedCaseInsensitive(
                            Flag->Buffer, FlagLenChars, L"-ec", 3)) {
                        IsEncFlag = TRUE;
                    } else if (FlagLenChars == 15 &&
                        ClppCompareStringBoundedCaseInsensitive(
                            Flag->Buffer, FlagLenChars, L"-encodedcommand", 15)) {
                        IsEncFlag = TRUE;
                    }

                    if (IsEncFlag && i + 1 < Parsed->ArgumentCount) {
                        Status = ClpDecodeBase64(
                            &Parsed->Arguments[i + 1].Value,
                            &Parsed->DecodedContent
                            );
                        if (NT_SUCCESS(Status)) {
                            Parsed->WasDecoded = TRUE;
                        }
                        break;
                    }
                }
            }
        }
    }

    //
    // Check for obfuscation patterns
    //
    if (ClppDetectObfuscation(&Parsed->FullCommandLine)) {
        SuspicionFlags |= ClpSuspicion_ObfuscatedArgs;
        SuspicionScore += CLP_SCORE_OBFUSCATED;
    }

    //
    // Check for download cradles
    //
    if (ClppDetectDownloadCradle(&Parsed->FullCommandLine)) {
        SuspicionFlags |= ClpSuspicion_DownloadCradle;
        SuspicionScore += CLP_SCORE_DOWNLOAD_CRADLE;
    }

    //
    // Check for execution bypass
    //
    if (ClppDetectExecutionBypass(&Parsed->FullCommandLine)) {
        SuspicionFlags |= ClpSuspicion_ExecutionBypass;
        SuspicionScore += CLP_SCORE_EXECUTION_BYPASS;
    }

    //
    // Check for hidden window execution
    //
    if (ClppDetectHiddenWindow(&Parsed->FullCommandLine)) {
        SuspicionFlags |= ClpSuspicion_HiddenWindow;
        SuspicionScore += CLP_SCORE_HIDDEN_WINDOW;
    }

    //
    // Check for remote execution patterns
    //
    if (ClppDetectRemoteExecution(&Parsed->FullCommandLine)) {
        SuspicionFlags |= ClpSuspicion_RemoteExecution;
        SuspicionScore += CLP_SCORE_REMOTE_EXECUTION;
    }

    //
    // Check for LOLBin abuse
    //
    if (Parsed->Executable.Buffer != NULL && Parsed->Executable.Length > 0) {
        Status = ClpIsLOLBin(Parser, &Parsed->Executable, &IsLOLBin);
        if (NT_SUCCESS(Status) && IsLOLBin) {
            SuspicionFlags |= ClpSuspicion_LOLBinAbuse;
            SuspicionScore += CLP_SCORE_LOLBIN_ABUSE;

            //
            // LOLBin combined with other indicators is more suspicious
            //
            if (SuspicionFlags & ClpSuspicion_EncodedCommand) {
                SuspicionScore += CLP_SCORE_LOLBIN_ENCODED_COMBO;
            }
            if (SuspicionFlags & ClpSuspicion_DownloadCradle) {
                SuspicionScore += CLP_SCORE_LOLBIN_DOWNLOAD_COMBO;
            }
        }
    }

    //
    // Check for script execution
    //
    if (ClppDetectScriptExecution(Parsed)) {
        SuspicionFlags |= ClpSuspicion_ScriptExecution;
        SuspicionScore += CLP_SCORE_SCRIPT_EXECUTION;
    }

    //
    // Check for suspicious paths
    //
    if (ClppDetectSuspiciousPath(&Parsed->FullCommandLine)) {
        SuspicionFlags |= ClpSuspicion_SuspiciousPath;
        SuspicionScore += CLP_SCORE_SUSPICIOUS_PATH;
    }

    //
    // Check command line length
    //
    CmdLineLength = Parsed->FullCommandLine.Length / sizeof(WCHAR);
    if (CmdLineLength > CLP_VERY_LONG_THRESHOLD) {
        SuspicionFlags |= ClpSuspicion_LongCommand;
        SuspicionScore += CLP_SCORE_VERY_LONG_COMMAND;
    } else if (CmdLineLength > CLP_LONG_CMDLINE_THRESHOLD) {
        SuspicionFlags |= ClpSuspicion_LongCommand;
        SuspicionScore += CLP_SCORE_LONG_COMMAND;
    }

    //
    // Also analyze decoded content if available
    //
    if (Parsed->WasDecoded &&
        Parsed->DecodedContent.Buffer != NULL &&
        Parsed->DecodedContent.Length > 0) {

        if (ClppDetectDownloadCradle(&Parsed->DecodedContent)) {
            if (!(SuspicionFlags & ClpSuspicion_DownloadCradle)) {
                SuspicionFlags |= ClpSuspicion_DownloadCradle;
                SuspicionScore += CLP_SCORE_DOWNLOAD_CRADLE;
            }
        }
    }

    //
    // Cap score at maximum
    //
    if (SuspicionScore > CLP_SCORE_MAX) {
        SuspicionScore = CLP_SCORE_MAX;
    }

    //
    // Store results in parsed command
    //
    Parsed->SuspicionFlags = SuspicionFlags;
    Parsed->SuspicionScore = SuspicionScore;

    *Flags = SuspicionFlags;
    *Score = SuspicionScore;

    //
    // Update statistics if suspicious
    //
    if (SuspicionScore > 0) {
        InterlockedIncrement64(&Parser->Stats.SuspiciousFound);
    }

    return STATUS_SUCCESS;
}


// ============================================================================
// BASE64 DECODING
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ClpDecodeBase64(
    _In_ PCUNICODE_STRING Encoded,
    _Out_ PUNICODE_STRING Decoded
    )
/*++
Routine Description:
    Decodes a Base64 encoded string.

    PowerShell -EncodedCommand uses UTF-16LE Base64 encoding.

Arguments:
    Encoded - Base64 encoded string.
    Decoded - Receives decoded string (null-terminated).

Return Value:
    STATUS_SUCCESS on success.

IRQL:
    Must be called at PASSIVE_LEVEL.
--*/
{
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE();

    if (Encoded == NULL || Encoded->Buffer == NULL) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (Decoded == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }

    RtlZeroMemory(Decoded, sizeof(UNICODE_STRING));

    //
    // Validate minimum length
    //
    if (Encoded->Length < CLP_MIN_BASE64_LENGTH * sizeof(WCHAR)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    Status = ClppDecodeBase64Unicode(Encoded, Decoded);

    return Status;
}


// ============================================================================
// LOLBIN DETECTION
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ClpIsLOLBin(
    _In_ PCLP_PARSER Parser,
    _In_ PCUNICODE_STRING Executable,
    _Out_ PBOOLEAN IsLOLBin
    )
/*++
Routine Description:
    Checks if an executable is a known LOLBin.

Arguments:
    Parser      - Initialized parser.
    Executable  - Executable name or path.
    IsLOLBin    - Receives TRUE if LOLBin.

Return Value:
    STATUS_SUCCESS on success.

IRQL:
    Must be called at PASSIVE_LEVEL.
--*/
{
    UNICODE_STRING FileName;
    PLIST_ENTRY Entry;
    PCLP_LOLBIN_ENTRY LOLBin;
    ULONG Hash;
    USHORT LastSlashPos;
    USHORT ExeLenChars;

    PAGED_CODE();

    if (Parser == NULL || !Parser->Initialized) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (Executable == NULL || Executable->Buffer == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (IsLOLBin == NULL) {
        return STATUS_INVALID_PARAMETER_3;
    }

    *IsLOLBin = FALSE;

    ExeLenChars = Executable->Length / sizeof(WCHAR);
    if (ExeLenChars == 0) {
        return STATUS_SUCCESS;
    }

    //
    // Extract just the filename from path using bounded search
    //
    LastSlashPos = ClppFindLastCharBounded(
        Executable->Buffer,
        ExeLenChars,
        L'\\'
        );

    if (LastSlashPos != (USHORT)-1 && LastSlashPos + 1 < ExeLenChars) {
        FileName.Buffer = Executable->Buffer + LastSlashPos + 1;
        FileName.Length = (USHORT)((ExeLenChars - LastSlashPos - 1) * sizeof(WCHAR));
        FileName.MaximumLength = FileName.Length;
    } else {
        FileName = *Executable;
    }

    if (FileName.Length == 0) {
        return STATUS_SUCCESS;
    }

    //
    // Compute hash for lookup
    //
    Hash = ClppHashStringBounded(
        FileName.Buffer,
        FileName.Length,
        TRUE
        );

    //
    // Search LOLBin list with reader lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Parser->LOLBinLock);

    for (Entry = Parser->LOLBinList.Flink;
         Entry != &Parser->LOLBinList;
         Entry = Entry->Flink) {

        LOLBin = CONTAINING_RECORD(Entry, CLP_LOLBIN_ENTRY, ListEntry);

        if (LOLBin->NameHash == Hash) {
            //
            // Hash match - verify with bounded string comparison
            //
            if (ClppCompareStringBoundedCaseInsensitive(
                    FileName.Buffer,
                    FileName.Length / sizeof(WCHAR),
                    LOLBin->Name.Buffer,
                    LOLBin->Name.Length / sizeof(WCHAR))) {
                *IsLOLBin = TRUE;
                break;
            }
        }
    }

    ExReleasePushLockShared(&Parser->LOLBinLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}


// ============================================================================
// CLEANUP
// ============================================================================

_Use_decl_annotations_
VOID
ClpFreeParsed(
    _In_opt_ PCLP_PARSED_COMMAND Parsed
    )
/*++
Routine Description:
    Frees a parsed command structure.

Arguments:
    Parsed - Structure to free (may be NULL).

IRQL:
    Must be called at PASSIVE_LEVEL.
--*/
{
    ULONG i;

    PAGED_CODE();

    if (Parsed == NULL) {
        return;
    }

    //
    // Free full command line
    //
    ClppFreeUnicodeStringSafe(&Parsed->FullCommandLine);

    //
    // Free executable
    //
    ClppFreeUnicodeStringSafe(&Parsed->Executable);

    //
    // Free arguments
    //
    for (i = 0; i < Parsed->ArgumentCount && i < CLP_MAX_ARGS; i++) {
        ClppFreeUnicodeStringSafe(&Parsed->Arguments[i].Value);
    }

    //
    // Free decoded content
    //
    ClppFreeUnicodeStringSafe(&Parsed->DecodedContent);

    //
    // Free structure
    //
    ShadowStrikeFreePoolWithTag(Parsed, CLP_POOL_TAG);
}


// ============================================================================
// INTERNAL: DATABASE INITIALIZATION
// ============================================================================

static NTSTATUS
ClppInitializeLOLBinDatabase(
    _Inout_ PCLP_PARSER Parser
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    PCLP_LOLBIN_ENTRY Entry = NULL;
    ULONG i;
    ULONG SuccessCount = 0;

    for (i = 0; i < CLP_LOLBIN_COUNT; i++) {
        Entry = (PCLP_LOLBIN_ENTRY)ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            sizeof(CLP_LOLBIN_ENTRY),
            CLP_POOL_TAG
            );

        if (Entry == NULL) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }

        RtlZeroMemory(Entry, sizeof(CLP_LOLBIN_ENTRY));
        InitializeListHead(&Entry->ListEntry);

        //
        // Initialize name - points to static string
        //
        RtlInitUnicodeString(&Entry->Name, g_LOLBinDefinitions[i].Name);
        Entry->IsStaticString = TRUE;  // Mark as static - do not free

        //
        // Compute hash using bounded function
        //
        Entry->NameHash = ClppHashStringBounded(
            Entry->Name.Buffer,
            Entry->Name.Length,
            TRUE
            );
        Entry->ThreatLevel = g_LOLBinDefinitions[i].ThreatLevel;
        Entry->Category = g_LOLBinDefinitions[i].Category;

        //
        // Insert into list
        //
        InsertTailList(&Parser->LOLBinList, &Entry->ListEntry);
        SuccessCount++;
        Entry = NULL;
    }

    Parser->LOLBinCount = SuccessCount;
    return STATUS_SUCCESS;

Cleanup:
    if (Entry != NULL) {
        ShadowStrikeFreePoolWithTag(Entry, CLP_POOL_TAG);
    }

    ClppCleanupLOLBinDatabase(Parser);
    return Status;
}


static VOID
ClppCleanupLOLBinDatabase(
    _Inout_ PCLP_PARSER Parser
    )
{
    PLIST_ENTRY Entry;
    PCLP_LOLBIN_ENTRY LOLBin;

    while (!IsListEmpty(&Parser->LOLBinList)) {
        Entry = RemoveHeadList(&Parser->LOLBinList);
        LOLBin = CONTAINING_RECORD(Entry, CLP_LOLBIN_ENTRY, ListEntry);

        //
        // Only free Name.Buffer if it was dynamically allocated
        // Currently all LOLBin names are static, so we don't free
        //
        if (!LOLBin->IsStaticString && LOLBin->Name.Buffer != NULL) {
            ShadowStrikeFreePoolWithTag(LOLBin->Name.Buffer, CLP_POOL_TAG);
        }

        ShadowStrikeFreePoolWithTag(LOLBin, CLP_POOL_TAG);
    }

    Parser->LOLBinCount = 0;
}


// ============================================================================
// INTERNAL: SAFE STRING OPERATIONS
// ============================================================================

static WCHAR
ClppToLowerAscii(
    _In_ WCHAR Ch
    )
/*++
Routine Description:
    Converts ASCII uppercase to lowercase.
    Non-ASCII characters are returned unchanged.
--*/
{
    if (Ch >= L'A' && Ch <= L'Z') {
        return Ch - L'A' + L'a';
    }
    return Ch;
}


static ULONG
ClppHashStringBounded(
    _In_reads_(Length) PCWCH Buffer,
    _In_ USHORT Length,
    _In_ BOOLEAN CaseInsensitive
    )
/*++
Routine Description:
    Computes FNV-1a hash of a bounded wide string.

Arguments:
    Buffer          - String buffer.
    Length          - Length in BYTES (not characters).
    CaseInsensitive - If TRUE, converts to lowercase before hashing.
--*/
{
    ULONG Hash = 0x811c9dc5;  // FNV-1a seed
    USHORT LengthChars;
    USHORT i;
    WCHAR Ch;

    if (Buffer == NULL || Length == 0) {
        return 0;
    }

    LengthChars = Length / sizeof(WCHAR);

    for (i = 0; i < LengthChars; i++) {
        Ch = Buffer[i];
        if (CaseInsensitive) {
            Ch = ClppToLowerAscii(Ch);
        }
        Hash ^= (UCHAR)(Ch & 0xFF);
        Hash *= 0x01000193;  // FNV-1a prime
        Hash ^= (UCHAR)((Ch >> 8) & 0xFF);
        Hash *= 0x01000193;
    }

    return Hash;
}


static BOOLEAN
ClppCompareStringBoundedCaseInsensitive(
    _In_reads_(Length1) PCWCH Buffer1,
    _In_ USHORT Length1,
    _In_reads_(Length2) PCWCH Buffer2,
    _In_ USHORT Length2
    )
/*++
Routine Description:
    Case-insensitive comparison of two bounded wide strings.

Arguments:
    Buffer1 - First string buffer.
    Length1 - Length in CHARACTERS of first string.
    Buffer2 - Second string buffer.
    Length2 - Length in CHARACTERS of second string.

Return Value:
    TRUE if strings are equal (case-insensitive).
--*/
{
    USHORT i;

    if (Length1 != Length2) {
        return FALSE;
    }

    if (Buffer1 == NULL || Buffer2 == NULL) {
        return (Buffer1 == Buffer2);
    }

    for (i = 0; i < Length1; i++) {
        if (ClppToLowerAscii(Buffer1[i]) != ClppToLowerAscii(Buffer2[i])) {
            return FALSE;
        }
    }

    return TRUE;
}


static USHORT
ClppFindLastCharBounded(
    _In_reads_(LengthChars) PCWCH Buffer,
    _In_ USHORT LengthChars,
    _In_ WCHAR Target
    )
/*++
Routine Description:
    Finds the last occurrence of a character in a bounded buffer.

Return Value:
    Index of last occurrence, or (USHORT)-1 if not found.
--*/
{
    USHORT i;

    if (Buffer == NULL || LengthChars == 0) {
        return (USHORT)-1;
    }

    for (i = LengthChars; i > 0; i--) {
        if (Buffer[i - 1] == Target) {
            return (USHORT)(i - 1);
        }
    }

    return (USHORT)-1;
}


static NTSTATUS
ClppAllocateParsedCommand(
    _Out_ PCLP_PARSED_COMMAND* Parsed
    )
{
    PCLP_PARSED_COMMAND Cmd;

    *Parsed = NULL;

    //
    // Use PagedPool since parsed commands are only used at PASSIVE_LEVEL
    //
    Cmd = (PCLP_PARSED_COMMAND)ShadowStrikeAllocatePoolWithTag(
        PagedPool,
        sizeof(CLP_PARSED_COMMAND),
        CLP_POOL_TAG
        );

    if (Cmd == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Cmd, sizeof(CLP_PARSED_COMMAND));
    *Parsed = Cmd;

    return STATUS_SUCCESS;
}


static NTSTATUS
ClppParseArguments(
    _In_ PCUNICODE_STRING CommandLine,
    _Inout_ PCLP_PARSED_COMMAND Parsed
    )
/*++
Routine Description:
    Parses command line into individual arguments.

    Handles:
    - Quoted strings (double quotes)
    - Escaped quotes (\")
    - Flag detection (starts with - or /)

Note:
    Allocates argument buffer from pool to avoid stack overflow.
--*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    PCWSTR Ptr;
    PCWSTR End;
    PWCHAR ArgBuffer = NULL;
    ULONG ArgLen = 0;
    BOOLEAN InQuotes = FALSE;
    BOOLEAN IsFlag = FALSE;
    BOOLEAN SkipFirst = TRUE;
    USHORT CmdLenChars;

    CmdLenChars = CommandLine->Length / sizeof(WCHAR);
    Ptr = CommandLine->Buffer;
    End = CommandLine->Buffer + CmdLenChars;

    //
    // Allocate argument buffer from pool (NOT stack) to prevent overflow
    //
    ArgBuffer = (PWCHAR)ShadowStrikeAllocatePoolWithTag(
        PagedPool,
        CLP_MAX_ARG_LENGTH * sizeof(WCHAR),
        CLP_POOL_TAG
        );

    if (ArgBuffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    while (Ptr < End && Parsed->ArgumentCount < CLP_MAX_ARGS) {
        //
        // Skip whitespace
        //
        while (Ptr < End && (*Ptr == L' ' || *Ptr == L'\t')) {
            Ptr++;
        }

        if (Ptr >= End) {
            break;
        }

        //
        // Start of argument
        //
        ArgLen = 0;
        InQuotes = FALSE;
        IsFlag = FALSE;
        RtlZeroMemory(ArgBuffer, CLP_MAX_ARG_LENGTH * sizeof(WCHAR));

        //
        // Check for flag
        //
        if (*Ptr == L'-' || *Ptr == L'/') {
            IsFlag = TRUE;
        }

        //
        // Check for opening quote
        //
        if (*Ptr == L'"') {
            InQuotes = TRUE;
            Ptr++;
        }

        //
        // Parse argument content
        //
        while (Ptr < End) {
            if (InQuotes) {
                if (*Ptr == L'"') {
                    //
                    // Check for escaped quote ("")
                    //
                    if (Ptr + 1 < End && *(Ptr + 1) == L'"') {
                        if (ArgLen < CLP_MAX_ARG_LENGTH - 1) {
                            ArgBuffer[ArgLen++] = L'"';
                        }
                        Ptr += 2;
                        continue;
                    }
                    //
                    // End of quoted string
                    //
                    Ptr++;
                    break;
                }
            } else {
                if (*Ptr == L' ' || *Ptr == L'\t') {
                    break;
                }
            }

            //
            // Handle backslash escape (\")
            //
            if (*Ptr == L'\\' && Ptr + 1 < End && *(Ptr + 1) == L'"') {
                if (ArgLen < CLP_MAX_ARG_LENGTH - 1) {
                    ArgBuffer[ArgLen++] = L'"';
                }
                Ptr += 2;
                continue;
            }

            if (ArgLen < CLP_MAX_ARG_LENGTH - 1) {
                ArgBuffer[ArgLen++] = *Ptr;
            }
            Ptr++;
        }

        //
        // Skip first argument (executable)
        //
        if (SkipFirst) {
            SkipFirst = FALSE;
            continue;
        }

        //
        // Store argument if non-empty
        //
        if (ArgLen > 0) {
            UNICODE_STRING ArgString;

            //
            // Ensure null termination
            //
            ArgBuffer[ArgLen] = L'\0';

            //
            // Create bounded string (not using RtlInitUnicodeString which scans)
            //
            ArgString.Buffer = ArgBuffer;
            ArgString.Length = (USHORT)(ArgLen * sizeof(WCHAR));
            ArgString.MaximumLength = (USHORT)((ArgLen + 1) * sizeof(WCHAR));

            //
            // Validate length fits in USHORT
            //
            if (ArgString.Length <= CLP_UNICODE_STRING_MAX_BYTES) {
                Status = ClppCopyUnicodeStringSafe(
                    &Parsed->Arguments[Parsed->ArgumentCount].Value,
                    &ArgString
                    );

                if (NT_SUCCESS(Status)) {
                    Parsed->Arguments[Parsed->ArgumentCount].IsFlag = IsFlag;
                    Parsed->ArgumentCount++;
                }
            }
        }
    }

    //
    // Free temporary buffer
    //
    ShadowStrikeFreePoolWithTag(ArgBuffer, CLP_POOL_TAG);

    return STATUS_SUCCESS;
}


static NTSTATUS
ClppExtractExecutable(
    _In_ PCUNICODE_STRING CommandLine,
    _Out_ PUNICODE_STRING Executable
    )
{
    PCWSTR Ptr;
    PCWSTR End;
    PCWSTR ExeStart = NULL;
    PCWSTR ExeEnd = NULL;
    BOOLEAN InQuotes = FALSE;
    UNICODE_STRING TempString;
    SIZE_T ExeLen;
    USHORT CmdLenChars;

    RtlZeroMemory(Executable, sizeof(UNICODE_STRING));

    CmdLenChars = CommandLine->Length / sizeof(WCHAR);
    if (CmdLenChars == 0) {
        return STATUS_NOT_FOUND;
    }

    Ptr = CommandLine->Buffer;
    End = CommandLine->Buffer + CmdLenChars;

    //
    // Skip leading whitespace
    //
    while (Ptr < End && (*Ptr == L' ' || *Ptr == L'\t')) {
        Ptr++;
    }

    if (Ptr >= End) {
        return STATUS_NOT_FOUND;
    }

    //
    // Check for quoted path
    //
    if (*Ptr == L'"') {
        InQuotes = TRUE;
        Ptr++;
    }

    ExeStart = Ptr;

    //
    // Find end of executable
    //
    while (Ptr < End) {
        if (InQuotes) {
            if (*Ptr == L'"') {
                ExeEnd = Ptr;
                break;
            }
        } else {
            if (*Ptr == L' ' || *Ptr == L'\t') {
                ExeEnd = Ptr;
                break;
            }
        }
        Ptr++;
    }

    if (ExeEnd == NULL) {
        ExeEnd = Ptr;
    }

    if (ExeEnd <= ExeStart) {
        return STATUS_NOT_FOUND;
    }

    ExeLen = (SIZE_T)(ExeEnd - ExeStart);

    //
    // Validate length
    //
    if (ExeLen > CLP_MAX_PATH) {
        ExeLen = CLP_MAX_PATH;
    }

    //
    // Validate fits in UNICODE_STRING
    //
    if (ExeLen * sizeof(WCHAR) > CLP_UNICODE_STRING_MAX_BYTES) {
        return STATUS_BUFFER_OVERFLOW;
    }

    //
    // Create bounded temporary string (no null scan)
    //
    TempString.Buffer = (PWCHAR)ExeStart;
    TempString.Length = (USHORT)(ExeLen * sizeof(WCHAR));
    TempString.MaximumLength = TempString.Length;

    return ClppCopyUnicodeStringSafe(Executable, &TempString);
}


// ============================================================================
// INTERNAL: DETECTION FUNCTIONS
// ============================================================================

//
// Helper macro for pattern detection with length
//
#define CLPP_CONTAINS_PATTERN(str, pat) \
    ClppContainsPatternBounded((str), (pat), (USHORT)(sizeof(pat)/sizeof(WCHAR) - 1), TRUE)


static BOOLEAN
ClppDetectEncodedCommand(
    _In_ PCLP_PARSED_COMMAND Parsed
    )
{
    ULONG i;

    for (i = 0; i < Parsed->ArgumentCount; i++) {
        if (Parsed->Arguments[i].IsFlag &&
            Parsed->Arguments[i].Value.Buffer != NULL &&
            Parsed->Arguments[i].Value.Length > 0) {

            PCUNICODE_STRING Flag = &Parsed->Arguments[i].Value;
            USHORT FlagLenChars = Flag->Length / sizeof(WCHAR);

            //
            // PowerShell encoded command flags - bounded comparison
            //
            if ((FlagLenChars == 4 && ClppCompareStringBoundedCaseInsensitive(
                    Flag->Buffer, FlagLenChars, L"-enc", 4)) ||
                (FlagLenChars == 2 && ClppCompareStringBoundedCaseInsensitive(
                    Flag->Buffer, FlagLenChars, L"-e", 2)) ||
                (FlagLenChars == 3 && ClppCompareStringBoundedCaseInsensitive(
                    Flag->Buffer, FlagLenChars, L"-ec", 3)) ||
                (FlagLenChars == 15 && ClppCompareStringBoundedCaseInsensitive(
                    Flag->Buffer, FlagLenChars, L"-encodedcommand", 15)) ||
                (FlagLenChars == 5 && ClppCompareStringBoundedCaseInsensitive(
                    Flag->Buffer, FlagLenChars, L"-enco", 5)) ||
                (FlagLenChars == 6 && ClppCompareStringBoundedCaseInsensitive(
                    Flag->Buffer, FlagLenChars, L"-encod", 6)) ||
                (FlagLenChars == 7 && ClppCompareStringBoundedCaseInsensitive(
                    Flag->Buffer, FlagLenChars, L"-encode", 7)) ||
                (FlagLenChars == 8 && ClppCompareStringBoundedCaseInsensitive(
                    Flag->Buffer, FlagLenChars, L"-encoded", 8))) {
                return TRUE;
            }
        }
    }

    //
    // Also check full command line for obfuscated variants
    //
    if (CLPP_CONTAINS_PATTERN(&Parsed->FullCommandLine, L"-enc")) {
        //
        // Verify it's likely a PowerShell command
        //
        if (CLPP_CONTAINS_PATTERN(&Parsed->FullCommandLine, L"powershell") ||
            CLPP_CONTAINS_PATTERN(&Parsed->FullCommandLine, L"pwsh")) {
            return TRUE;
        }
    }

    return FALSE;
}


static BOOLEAN
ClppDetectObfuscation(
    _In_ PCUNICODE_STRING CommandLine
    )
{
    USHORT i;
    ULONG CaretCount = 0;
    ULONG PercentCount = 0;
    ULONG TickCount = 0;
    USHORT CmdLen;

    if (CommandLine->Buffer == NULL || CommandLine->Length == 0) {
        return FALSE;
    }

    CmdLen = CommandLine->Length / sizeof(WCHAR);

    //
    // Count obfuscation indicators
    //
    for (i = 0; i < CmdLen; i++) {
        WCHAR Ch = CommandLine->Buffer[i];

        switch (Ch) {
            case L'^':
                CaretCount++;
                break;
            case L'%':
                PercentCount++;
                break;
            case L'`':
                TickCount++;
                break;
        }
    }

    //
    // Check against thresholds
    // Caret insertion: cmd /c p^o^w^e^r^s^h^e^l^l
    //
    if (CaretCount > CLP_OBFUSCATION_CARET_THRESHOLD) {
        return TRUE;
    }

    //
    // Environment variable abuse: %COMSPEC:~0,1%%COMSPEC:~4,1%...
    //
    if (PercentCount > CLP_OBFUSCATION_PERCENT_THRESHOLD &&
        CLPP_CONTAINS_PATTERN(CommandLine, L"~")) {
        return TRUE;
    }

    //
    // PowerShell tick escaping: pow`er`shell
    //
    if (TickCount > CLP_OBFUSCATION_TICK_THRESHOLD) {
        return TRUE;
    }

    //
    // Check for character concatenation patterns
    //
    if (CLPP_CONTAINS_PATTERN(CommandLine, L"+[char]") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"-join") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"[char]") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"-f '") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"-replace")) {
        return TRUE;
    }

    //
    // Check for invoke-expression variants
    //
    if (CLPP_CONTAINS_PATTERN(CommandLine, L"iex") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"invoke-expression") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"i`e`x") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"&(") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L".(")) {
        return TRUE;
    }

    return FALSE;
}


static BOOLEAN
ClppDetectDownloadCradle(
    _In_ PCUNICODE_STRING CommandLine
    )
{
    //
    // PowerShell download methods
    //
    if (CLPP_CONTAINS_PATTERN(CommandLine, L"downloadstring") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"downloadfile") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"downloaddata") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"webclient") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"invoke-webrequest") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"iwr ") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"invoke-restmethod") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"irm ") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"start-bitstransfer") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"net.webclient") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"httpwebrequest") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"system.net.webclient")) {
        return TRUE;
    }

    //
    // Certutil download
    //
    if (CLPP_CONTAINS_PATTERN(CommandLine, L"certutil") &&
        (CLPP_CONTAINS_PATTERN(CommandLine, L"-urlcache") ||
         CLPP_CONTAINS_PATTERN(CommandLine, L"-verifyctl") ||
         CLPP_CONTAINS_PATTERN(CommandLine, L"-ping"))) {
        return TRUE;
    }

    //
    // Bitsadmin download
    //
    if (CLPP_CONTAINS_PATTERN(CommandLine, L"bitsadmin") &&
        (CLPP_CONTAINS_PATTERN(CommandLine, L"/transfer") ||
         CLPP_CONTAINS_PATTERN(CommandLine, L"/create") ||
         CLPP_CONTAINS_PATTERN(CommandLine, L"/addfile"))) {
        return TRUE;
    }

    //
    // Curl/wget with output
    //
    if ((CLPP_CONTAINS_PATTERN(CommandLine, L"curl ") ||
         CLPP_CONTAINS_PATTERN(CommandLine, L"curl.exe") ||
         CLPP_CONTAINS_PATTERN(CommandLine, L"wget ") ||
         CLPP_CONTAINS_PATTERN(CommandLine, L"wget.exe")) &&
        (CLPP_CONTAINS_PATTERN(CommandLine, L"-o ") ||
         CLPP_CONTAINS_PATTERN(CommandLine, L"--output") ||
         CLPP_CONTAINS_PATTERN(CommandLine, L"> "))) {
        return TRUE;
    }

    //
    // WMIC download
    //
    if (CLPP_CONTAINS_PATTERN(CommandLine, L"wmic") &&
        CLPP_CONTAINS_PATTERN(CommandLine, L"http")) {
        return TRUE;
    }

    //
    // URL patterns combined with execution
    //
    if ((CLPP_CONTAINS_PATTERN(CommandLine, L"http://") ||
         CLPP_CONTAINS_PATTERN(CommandLine, L"https://") ||
         CLPP_CONTAINS_PATTERN(CommandLine, L"ftp://")) &&
        (CLPP_CONTAINS_PATTERN(CommandLine, L"|") ||
         CLPP_CONTAINS_PATTERN(CommandLine, L"iex") ||
         CLPP_CONTAINS_PATTERN(CommandLine, L"invoke"))) {
        return TRUE;
    }

    return FALSE;
}


static BOOLEAN
ClppDetectExecutionBypass(
    _In_ PCUNICODE_STRING CommandLine
    )
{
    //
    // PowerShell execution policy bypass
    //
    if (CLPP_CONTAINS_PATTERN(CommandLine, L"-ep bypass") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"-executionpolicy bypass") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"-exec bypass") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"-ep unrestricted") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"-executionpolicy unrestricted") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"set-executionpolicy")) {
        return TRUE;
    }

    //
    // Combined bypass + powershell check
    //
    if (CLPP_CONTAINS_PATTERN(CommandLine, L"bypass") &&
        CLPP_CONTAINS_PATTERN(CommandLine, L"powershell")) {
        return TRUE;
    }

    //
    // PowerShell AMSI bypass patterns
    //
    if (CLPP_CONTAINS_PATTERN(CommandLine, L"amsiutils") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"amsiinitfailed") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"amsi.dll") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"amsiscanbuffer") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"amsicontext")) {
        return TRUE;
    }

    //
    // Constrained language mode bypass
    //
    if (CLPP_CONTAINS_PATTERN(CommandLine, L"__pslockeddown") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"fulllanguage")) {
        return TRUE;
    }

    //
    // Script block logging bypass
    //
    if (CLPP_CONTAINS_PATTERN(CommandLine, L"scriptblocklogging") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"enablescriptblocklogging")) {
        return TRUE;
    }

    //
    // Windows Defender exclusions
    //
    if (CLPP_CONTAINS_PATTERN(CommandLine, L"add-mppreference") &&
        CLPP_CONTAINS_PATTERN(CommandLine, L"-exclusion")) {
        return TRUE;
    }

    return FALSE;
}


static BOOLEAN
ClppDetectHiddenWindow(
    _In_ PCUNICODE_STRING CommandLine
    )
{
    //
    // PowerShell hidden window
    //
    if (CLPP_CONTAINS_PATTERN(CommandLine, L"-w hidden") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"-windowstyle hidden") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"-win hidden") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"-window hidden") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"-wi hidden") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"-winds hidden")) {
        return TRUE;
    }

    //
    // VBScript/WScript hidden
    //
    if (CLPP_CONTAINS_PATTERN(CommandLine, L"wscript.shell") &&
        CLPP_CONTAINS_PATTERN(CommandLine, L", 0")) {
        return TRUE;
    }

    //
    // VBS Run hidden
    //
    if (CLPP_CONTAINS_PATTERN(CommandLine, L".run") &&
        CLPP_CONTAINS_PATTERN(CommandLine, L", 0,")) {
        return TRUE;
    }

    //
    // CMD start hidden
    //
    if (CLPP_CONTAINS_PATTERN(CommandLine, L"start /min") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"start /b")) {
        return TRUE;
    }

    //
    // PowerShell NoProfile and NonInteractive (often combined with hidden)
    //
    if ((CLPP_CONTAINS_PATTERN(CommandLine, L"-nop") ||
         CLPP_CONTAINS_PATTERN(CommandLine, L"-noprofile")) &&
        (CLPP_CONTAINS_PATTERN(CommandLine, L"-noni") ||
         CLPP_CONTAINS_PATTERN(CommandLine, L"-noninteractive"))) {
        return TRUE;
    }

    return FALSE;
}


static BOOLEAN
ClppDetectRemoteExecution(
    _In_ PCUNICODE_STRING CommandLine
    )
{
    //
    // PowerShell remoting
    //
    if (CLPP_CONTAINS_PATTERN(CommandLine, L"invoke-command") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"enter-pssession") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"new-pssession") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"-computername") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"-cn ") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"-session ")) {
        return TRUE;
    }

    //
    // WMI remote execution
    //
    if (CLPP_CONTAINS_PATTERN(CommandLine, L"wmic") &&
        CLPP_CONTAINS_PATTERN(CommandLine, L"/node:")) {
        return TRUE;
    }

    //
    // PsExec patterns
    //
    if (CLPP_CONTAINS_PATTERN(CommandLine, L"psexec")) {
        return TRUE;
    }

    //
    // UNC paths with commands
    //
    if (CLPP_CONTAINS_PATTERN(CommandLine, L"\\\\") &&
        (CLPP_CONTAINS_PATTERN(CommandLine, L"cmd") ||
         CLPP_CONTAINS_PATTERN(CommandLine, L"powershell"))) {
        return TRUE;
    }

    //
    // WinRM
    //
    if (CLPP_CONTAINS_PATTERN(CommandLine, L"winrs") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"winrm ")) {
        return TRUE;
    }

    //
    // DCOM execution
    //
    if (CLPP_CONTAINS_PATTERN(CommandLine, L"activator") &&
        CLPP_CONTAINS_PATTERN(CommandLine, L"createinstance")) {
        return TRUE;
    }

    return FALSE;
}


static BOOLEAN
ClppDetectSuspiciousPath(
    _In_ PCUNICODE_STRING CommandLine
    )
{
    //
    // Temp directories
    //
    if (CLPP_CONTAINS_PATTERN(CommandLine, L"\\temp\\") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"\\tmp\\") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"%temp%") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"$env:temp")) {
        return TRUE;
    }

    //
    // AppData
    //
    if (CLPP_CONTAINS_PATTERN(CommandLine, L"\\appdata\\local\\") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"\\appdata\\roaming\\") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"%appdata%") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"$env:appdata")) {
        return TRUE;
    }

    //
    // Recycle bin
    //
    if (CLPP_CONTAINS_PATTERN(CommandLine, L"\\$recycle.bin\\") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"\\recycler\\")) {
        return TRUE;
    }

    //
    // Public folders
    //
    if (CLPP_CONTAINS_PATTERN(CommandLine, L"\\users\\public\\") ||
        CLPP_CONTAINS_PATTERN(CommandLine, L"\\public\\")) {
        return TRUE;
    }

    //
    // ProgramData (often abused)
    //
    if (CLPP_CONTAINS_PATTERN(CommandLine, L"\\programdata\\") &&
        !CLPP_CONTAINS_PATTERN(CommandLine, L"\\microsoft\\")) {
        return TRUE;
    }

    //
    // Perflogs
    //
    if (CLPP_CONTAINS_PATTERN(CommandLine, L"\\perflogs\\")) {
        return TRUE;
    }

    return FALSE;
}


static BOOLEAN
ClppDetectScriptExecution(
    _In_ PCLP_PARSED_COMMAND Parsed
    )
{
    ULONG i;
    USHORT ExeLenChars;

    //
    // Check executable for script interpreters using bounded comparisons
    //
    if (Parsed->Executable.Buffer != NULL && Parsed->Executable.Length > 0) {
        ExeLenChars = Parsed->Executable.Length / sizeof(WCHAR);

        //
        // Use bounded pattern search instead of wcsstr
        //
        BOOLEAN IsScriptInterpreter = FALSE;

        if (CLPP_CONTAINS_PATTERN(&Parsed->Executable, L"wscript") ||
            CLPP_CONTAINS_PATTERN(&Parsed->Executable, L"cscript") ||
            CLPP_CONTAINS_PATTERN(&Parsed->Executable, L"mshta")) {
            IsScriptInterpreter = TRUE;
        }

        if (IsScriptInterpreter) {
            //
            // Script interpreter running - check for script file
            //
            for (i = 0; i < Parsed->ArgumentCount && i < CLP_MAX_ARGS; i++) {
                if (!Parsed->Arguments[i].IsFlag &&
                    Parsed->Arguments[i].Value.Buffer != NULL &&
                    Parsed->Arguments[i].Value.Length > 0) {

                    PCUNICODE_STRING Arg = &Parsed->Arguments[i].Value;

                    if (CLPP_CONTAINS_PATTERN(Arg, L".vbs") ||
                        CLPP_CONTAINS_PATTERN(Arg, L".vbe") ||
                        CLPP_CONTAINS_PATTERN(Arg, L".js") ||
                        CLPP_CONTAINS_PATTERN(Arg, L".jse") ||
                        CLPP_CONTAINS_PATTERN(Arg, L".wsf") ||
                        CLPP_CONTAINS_PATTERN(Arg, L".wsh") ||
                        CLPP_CONTAINS_PATTERN(Arg, L".hta")) {
                        return TRUE;
                    }
                }
            }
        }
    }

    //
    // Check for inline script execution
    //
    if (CLPP_CONTAINS_PATTERN(&Parsed->FullCommandLine, L"javascript:") ||
        CLPP_CONTAINS_PATTERN(&Parsed->FullCommandLine, L"vbscript:")) {
        return TRUE;
    }

    return FALSE;
}


static BOOLEAN
ClppContainsPatternBounded(
    _In_ PCUNICODE_STRING String,
    _In_ PCWSTR Pattern,
    _In_ USHORT PatternLengthChars,
    _In_ BOOLEAN CaseInsensitive
    )
/*++
Routine Description:
    Case-insensitive bounded substring search.
    Does NOT assume null-termination - uses explicit lengths.

Arguments:
    String              - String to search in.
    Pattern             - Pattern to search for.
    PatternLengthChars  - Length of pattern in CHARACTERS.
    CaseInsensitive     - If TRUE, performs case-insensitive comparison.
--*/
{
    SIZE_T StringLen;
    SIZE_T i, j;

    if (String == NULL || String->Buffer == NULL || Pattern == NULL) {
        return FALSE;
    }

    if (PatternLengthChars == 0) {
        return FALSE;
    }

    StringLen = String->Length / sizeof(WCHAR);

    if (PatternLengthChars > StringLen) {
        return FALSE;
    }

    //
    // Simple bounded substring search
    //
    for (i = 0; i <= StringLen - PatternLengthChars; i++) {
        BOOLEAN Match = TRUE;

        for (j = 0; j < PatternLengthChars; j++) {
            WCHAR C1 = String->Buffer[i + j];
            WCHAR C2 = Pattern[j];

            if (CaseInsensitive) {
                C1 = ClppToLowerAscii(C1);
                C2 = ClppToLowerAscii(C2);
            }

            if (C1 != C2) {
                Match = FALSE;
                break;
            }
        }

        if (Match) {
            return TRUE;
        }
    }

    return FALSE;
}


// ============================================================================
// INTERNAL: BASE64 DECODING
// ============================================================================

static BOOLEAN
ClppIsValidBase64Char(
    _In_ WCHAR Ch
    )
{
    return ((Ch >= L'A' && Ch <= L'Z') ||
            (Ch >= L'a' && Ch <= L'z') ||
            (Ch >= L'0' && Ch <= L'9') ||
            Ch == L'+' || Ch == L'/' || Ch == L'=');
}


static UCHAR
ClppBase64CharToValue(
    _In_ WCHAR Ch,
    _Out_ PBOOLEAN IsValid
    )
/*++
Routine Description:
    Converts Base64 character to its 6-bit value.

Arguments:
    Ch      - Base64 character.
    IsValid - Receives TRUE if character is valid Base64.

Return Value:
    6-bit value (0-63) for valid characters.
    0 for padding or invalid (check IsValid).
--*/
{
    *IsValid = TRUE;

    if (Ch >= L'A' && Ch <= L'Z') {
        return (UCHAR)(Ch - L'A');
    }
    if (Ch >= L'a' && Ch <= L'z') {
        return (UCHAR)(Ch - L'a' + 26);
    }
    if (Ch >= L'0' && Ch <= L'9') {
        return (UCHAR)(Ch - L'0' + 52);
    }
    if (Ch == L'+') {
        return 62;
    }
    if (Ch == L'/') {
        return 63;
    }
    if (Ch == L'=') {
        *IsValid = TRUE;  // Padding is "valid" but returns 0
        return 0;
    }

    *IsValid = FALSE;
    return 0;
}


static NTSTATUS
ClppDecodeBase64Unicode(
    _In_ PCUNICODE_STRING Encoded,
    _Out_ PUNICODE_STRING Decoded
    )
/*++
Routine Description:
    Decodes Base64 to UTF-16LE (as used by PowerShell -EncodedCommand).

    Base64 alphabet: A-Za-z0-9+/
    Padding: =

SECURITY:
    - Validates all lengths before allocation
    - Checks for integer overflow
    - Ensures output fits in UNICODE_STRING
--*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    PCWSTR Src;
    SIZE_T SrcLen;
    SIZE_T ValidChars = 0;
    SIZE_T DecodedByteLen;
    SIZE_T DecodedCharLen;
    PUCHAR DecodedBytes = NULL;
    SIZE_T i;
    UCHAR Quad[4];
    SIZE_T ByteIndex = 0;
    SIZE_T TrimmedLen;
    BOOLEAN IsValid;

    RtlZeroMemory(Decoded, sizeof(UNICODE_STRING));

    Src = Encoded->Buffer;
    SrcLen = Encoded->Length / sizeof(WCHAR);

    if (SrcLen == 0) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Trim trailing whitespace
    //
    TrimmedLen = SrcLen;
    while (TrimmedLen > 0) {
        WCHAR Ch = Src[TrimmedLen - 1];
        if (Ch == L' ' || Ch == L'\t' || Ch == L'\r' || Ch == L'\n') {
            TrimmedLen--;
        } else {
            break;
        }
    }

    if (TrimmedLen == 0) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Count valid Base64 characters
    //
    for (i = 0; i < TrimmedLen; i++) {
        WCHAR Ch = Src[i];

        if (Ch == L' ' || Ch == L'\t' || Ch == L'\r' || Ch == L'\n') {
            continue;  // Skip whitespace
        }

        if (Ch == L'=') {
            break;  // Padding - stop counting
        }

        if (!ClppIsValidBase64Char(Ch)) {
            return STATUS_INVALID_PARAMETER;
        }

        ValidChars++;
    }

    if (ValidChars < CLP_MIN_BASE64_LENGTH) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Integer overflow check before multiplication
    //
    if (ValidChars > (SIZE_T_MAX / 3)) {
        return STATUS_INTEGER_OVERFLOW;
    }

    //
    // Calculate decoded length
    // Every 4 Base64 chars = 3 bytes
    //
    DecodedByteLen = (ValidChars * 3) / 4;

    //
    // Account for padding
    //
    for (i = TrimmedLen; i > 0 && Src[i - 1] == L'='; i--) {
        if (DecodedByteLen > 0) {
            DecodedByteLen--;
        }
    }

    if (DecodedByteLen > CLP_MAX_DECODED_LENGTH) {
        return STATUS_BUFFER_OVERFLOW;
    }

    if (DecodedByteLen == 0) {
        return STATUS_NO_MATCH;
    }

    //
    // Allocate buffer for decoded bytes
    //
    DecodedBytes = (PUCHAR)ShadowStrikeAllocatePoolWithTag(
        PagedPool,
        DecodedByteLen + 2,  // +2 for potential null terminator
        CLP_POOL_TAG
        );

    if (DecodedBytes == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(DecodedBytes, DecodedByteLen + 2);

    //
    // Decode Base64
    //
    i = 0;
    while (i < TrimmedLen && ByteIndex < DecodedByteLen) {
        //
        // Collect 4 Base64 characters
        //
        ULONG QuadIndex = 0;
        RtlZeroMemory(Quad, sizeof(Quad));

        while (QuadIndex < 4 && i < TrimmedLen) {
            WCHAR Ch = Src[i++];

            if (Ch == L' ' || Ch == L'\t' || Ch == L'\r' || Ch == L'\n') {
                continue;
            }

            if (Ch == L'=') {
                Quad[QuadIndex++] = 0;
                continue;
            }

            Quad[QuadIndex] = ClppBase64CharToValue(Ch, &IsValid);
            if (!IsValid) {
                Status = STATUS_INVALID_PARAMETER;
                goto Cleanup;
            }
            QuadIndex++;
        }

        if (QuadIndex < 4) {
            break;
        }

        //
        // Decode 4 Base64 chars to 3 bytes
        //
        if (ByteIndex < DecodedByteLen) {
            DecodedBytes[ByteIndex++] = (UCHAR)((Quad[0] << 2) | (Quad[1] >> 4));
        }
        if (ByteIndex < DecodedByteLen) {
            DecodedBytes[ByteIndex++] = (UCHAR)((Quad[1] << 4) | (Quad[2] >> 2));
        }
        if (ByteIndex < DecodedByteLen) {
            DecodedBytes[ByteIndex++] = (UCHAR)((Quad[2] << 6) | Quad[3]);
        }
    }

    //
    // Convert to UNICODE_STRING (UTF-16LE)
    // The decoded bytes should already be UTF-16LE
    //
    DecodedCharLen = ByteIndex / sizeof(WCHAR);

    if (DecodedCharLen == 0) {
        Status = STATUS_NO_MATCH;
        goto Cleanup;
    }

    //
    // Validate length fits in UNICODE_STRING
    //
    if (DecodedCharLen * sizeof(WCHAR) > CLP_UNICODE_STRING_MAX_BYTES) {
        Status = STATUS_BUFFER_OVERFLOW;
        goto Cleanup;
    }

    //
    // Allocate the unicode string buffer
    //
    Decoded->Buffer = (PWCHAR)ShadowStrikeAllocatePoolWithTag(
        PagedPool,
        (DecodedCharLen + 1) * sizeof(WCHAR),
        CLP_POOL_TAG
        );

    if (Decoded->Buffer == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    RtlCopyMemory(Decoded->Buffer, DecodedBytes, DecodedCharLen * sizeof(WCHAR));
    Decoded->Buffer[DecodedCharLen] = L'\0';  // Guaranteed null termination
    Decoded->Length = (USHORT)(DecodedCharLen * sizeof(WCHAR));
    Decoded->MaximumLength = (USHORT)((DecodedCharLen + 1) * sizeof(WCHAR));

    Status = STATUS_SUCCESS;

Cleanup:
    if (DecodedBytes != NULL) {
        ShadowStrikeFreePoolWithTag(DecodedBytes, CLP_POOL_TAG);
    }

    if (!NT_SUCCESS(Status) && Decoded->Buffer != NULL) {
        ShadowStrikeFreePoolWithTag(Decoded->Buffer, CLP_POOL_TAG);
        RtlZeroMemory(Decoded, sizeof(UNICODE_STRING));
    }

    return Status;
}


// ============================================================================
// INTERNAL: STRING HELPERS
// ============================================================================

static NTSTATUS
ClppCopyUnicodeStringSafe(
    _Out_ PUNICODE_STRING Destination,
    _In_ PCUNICODE_STRING Source
    )
/*++
Routine Description:
    Safely copies a UNICODE_STRING with null termination guarantee.

    SECURITY:
    - Validates length before allocation
    - Checks for USHORT overflow
    - Guarantees null termination
--*/
{
    PWCHAR Buffer;
    SIZE_T BufferSize;

    RtlZeroMemory(Destination, sizeof(UNICODE_STRING));

    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0) {
        return STATUS_SUCCESS;
    }

    //
    // Validate length fits in USHORT
    //
    if (Source->Length > CLP_UNICODE_STRING_MAX_BYTES) {
        return STATUS_BUFFER_OVERFLOW;
    }

    BufferSize = Source->Length + sizeof(WCHAR);  // +null terminator

    //
    // Integer overflow check
    //
    if (BufferSize < Source->Length) {
        return STATUS_INTEGER_OVERFLOW;
    }

    //
    // Use PagedPool for string buffers (PASSIVE_LEVEL only)
    //
    Buffer = (PWCHAR)ShadowStrikeAllocatePoolWithTag(
        PagedPool,
        BufferSize,
        CLP_POOL_TAG
        );

    if (Buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(Buffer, Source->Buffer, Source->Length);
    Buffer[Source->Length / sizeof(WCHAR)] = L'\0';  // Guaranteed null termination

    Destination->Buffer = Buffer;
    Destination->Length = Source->Length;
    Destination->MaximumLength = (USHORT)BufferSize;

    return STATUS_SUCCESS;
}


static VOID
ClppFreeUnicodeStringSafe(
    _Inout_ PUNICODE_STRING String
    )
{
    if (String != NULL && String->Buffer != NULL) {
        ShadowStrikeFreePoolWithTag(String->Buffer, CLP_POOL_TAG);
        RtlZeroMemory(String, sizeof(UNICODE_STRING));
    }
}
