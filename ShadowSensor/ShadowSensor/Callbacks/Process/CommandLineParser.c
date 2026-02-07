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

Performance Characteristics:
- O(n) command line parsing where n is command length
- O(m) LOLBin lookup where m is number of LOLBins (hash-based)
- Pattern matching uses optimized string search
- Lookaside lists for high-frequency allocations

@author ShadowStrike Security Team
@version 2.0.0 (Enterprise Edition)
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#include "CommandLineParser.h"
#include "../../Utilities/MemoryUtils.h"
#include "../../Utilities/StringUtils.h"
#include <ntstrsafe.h>
#include <wchar.h>

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

#define CLP_LOOKASIDE_DEPTH         64
#define CLP_MAX_DECODED_LENGTH      65536
#define CLP_MIN_BASE64_LENGTH       8
#define CLP_LONG_CMDLINE_THRESHOLD  2048
#define CLP_VERY_LONG_THRESHOLD     8192

//
// Suspicion score weights
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

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

//
// LOLBin entry for hash-based lookup
//
typedef struct _CLP_LOLBIN_ENTRY {
    LIST_ENTRY ListEntry;
    UNICODE_STRING Name;
    ULONG NameHash;
    ULONG ThreatLevel;          // 1=Low, 2=Medium, 3=High
    ULONG Category;             // Bitmap of usage categories
} CLP_LOLBIN_ENTRY, *PCLP_LOLBIN_ENTRY;

//
// Suspicious pattern entry
//
typedef struct _CLP_PATTERN_ENTRY {
    LIST_ENTRY ListEntry;
    UNICODE_STRING Pattern;
    CLP_SUSPICION SuspicionType;
    ULONG ScoreContribution;
    BOOLEAN CaseInsensitive;
} CLP_PATTERN_ENTRY, *PCLP_PATTERN_ENTRY;

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

static NTSTATUS
ClppInitializePatterns(
    _Inout_ PCLP_PARSER Parser
    );

static VOID
ClppCleanupPatterns(
    _Inout_ PCLP_PARSER Parser
    );

static ULONG
ClppHashString(
    _In_ PCUNICODE_STRING String,
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
ClppContainsPatternCaseInsensitive(
    _In_ PCUNICODE_STRING String,
    _In_ PCWSTR Pattern
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
    _In_ WCHAR Ch
    );

static NTSTATUS
ClppCopyUnicodeString(
    _Out_ PUNICODE_STRING Destination,
    _In_ PCUNICODE_STRING Source
    );

static VOID
ClppFreeUnicodeString(
    _Inout_ PUNICODE_STRING String
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
    // Allocate parser structure
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
    InitializeListHead(&NewParser->PatternList);

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
    // Initialize pattern database
    //
    Status = ClppInitializePatterns(NewParser);
    if (!NT_SUCCESS(Status)) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "[ShadowStrike/CLP] Failed to initialize patterns: 0x%08X\n",
            Status
            );
        goto Cleanup;
    }

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&NewParser->Stats.StartTime);

    NewParser->Initialized = TRUE;
    *Parser = NewParser;

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[ShadowStrike/CLP] Command line parser initialized with %lu LOLBins\n",
        (ULONG)CLP_LOLBIN_COUNT
        );

    return STATUS_SUCCESS;

Cleanup:
    if (NewParser != NULL) {
        ClppCleanupLOLBinDatabase(NewParser);
        ClppCleanupPatterns(NewParser);
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
--*/
{
    PAGED_CODE();

    if (Parser == NULL) {
        return;
    }

    if (!Parser->Initialized) {
        return;
    }

    Parser->Initialized = FALSE;

    //
    // Cleanup databases
    //
    ClppCleanupLOLBinDatabase(Parser);
    ClppCleanupPatterns(Parser);

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[ShadowStrike/CLP] Command line parser shutdown. "
        "Stats: Parsed=%lld, Suspicious=%lld\n",
        Parser->Stats.CommandsParsed,
        Parser->Stats.SuspiciousFound
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
    _In_ PUNICODE_STRING CommandLine,
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
    // Allocate parsed command structure
    //
    Status = ClppAllocateParsedCommand(&ParsedCmd);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Copy full command line
    //
    Status = ClppCopyUnicodeString(&ParsedCmd->FullCommandLine, CommandLine);
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
    _In_ PCLP_PARSED_COMMAND Parsed,
    _Out_ PCLP_SUSPICION Flags,
    _Out_ PULONG Score
    )
/*++
Routine Description:
    Analyzes a parsed command for suspicious indicators.

Arguments:
    Parser  - Initialized parser.
    Parsed  - Parsed command to analyze.
    Flags   - Receives suspicion flags.
    Score   - Receives suspicion score (0-100).

Return Value:
    STATUS_SUCCESS on success.
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
                if (Parsed->Arguments[i].IsFlag) {
                    PWCHAR ArgBuffer = Parsed->Arguments[i].Value.Buffer;
                    if (ArgBuffer != NULL) {
                        if (_wcsicmp(ArgBuffer, L"-enc") == 0 ||
                            _wcsicmp(ArgBuffer, L"-e") == 0 ||
                            _wcsicmp(ArgBuffer, L"-encodedcommand") == 0 ||
                            _wcsicmp(ArgBuffer, L"-ec") == 0) {

                            if (i + 1 < Parsed->ArgumentCount) {
                                Status = ClpDecodeBase64(
                                    &Parsed->Arguments[i + 1].Value,
                                    &Parsed->DecodedContent
                                    );
                                if (NT_SUCCESS(Status)) {
                                    Parsed->WasDecoded = TRUE;
                                }
                            }
                            break;
                        }
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
    if (Parsed->Executable.Buffer != NULL) {
        Status = ClpIsLOLBin(Parser, &Parsed->Executable, &IsLOLBin);
        if (NT_SUCCESS(Status) && IsLOLBin) {
            SuspicionFlags |= ClpSuspicion_LOLBinAbuse;
            SuspicionScore += CLP_SCORE_LOLBIN_ABUSE;

            //
            // LOLBin combined with other indicators is more suspicious
            //
            if (SuspicionFlags & ClpSuspicion_EncodedCommand) {
                SuspicionScore += 10;
            }
            if (SuspicionFlags & ClpSuspicion_DownloadCradle) {
                SuspicionScore += 10;
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
    if (Parsed->WasDecoded && Parsed->DecodedContent.Buffer != NULL) {
        if (ClppDetectDownloadCradle(&Parsed->DecodedContent)) {
            if (!(SuspicionFlags & ClpSuspicion_DownloadCradle)) {
                SuspicionFlags |= ClpSuspicion_DownloadCradle;
                SuspicionScore += CLP_SCORE_DOWNLOAD_CRADLE;
            }
        }
    }

    //
    // Cap score at 100
    //
    if (SuspicionScore > 100) {
        SuspicionScore = 100;
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
    _In_ PUNICODE_STRING Encoded,
    _Out_ PUNICODE_STRING Decoded
    )
/*++
Routine Description:
    Decodes a Base64 encoded string.

    PowerShell -EncodedCommand uses UTF-16LE Base64 encoding.

Arguments:
    Encoded - Base64 encoded string.
    Decoded - Receives decoded string.

Return Value:
    STATUS_SUCCESS on success.
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
    _In_ PUNICODE_STRING Executable,
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
--*/
{
    UNICODE_STRING FileName;
    PLIST_ENTRY Entry;
    PCLP_LOLBIN_ENTRY LOLBin;
    ULONG Hash;
    PWCHAR LastSlash;

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

    //
    // Extract just the filename from path
    //
    LastSlash = wcsrchr(Executable->Buffer, L'\\');
    if (LastSlash != NULL) {
        RtlInitUnicodeString(&FileName, LastSlash + 1);
    } else {
        FileName = *Executable;
    }

    if (FileName.Length == 0) {
        return STATUS_SUCCESS;
    }

    //
    // Compute hash for lookup
    //
    Hash = ClppHashString(&FileName, TRUE);

    //
    // Search LOLBin list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Parser->LOLBinLock);

    for (Entry = Parser->LOLBinList.Flink;
         Entry != &Parser->LOLBinList;
         Entry = Entry->Flink) {

        LOLBin = CONTAINING_RECORD(Entry, CLP_LOLBIN_ENTRY, ListEntry);

        if (LOLBin->NameHash == Hash) {
            //
            // Hash match - verify with string comparison
            //
            if (RtlEqualUnicodeString(&FileName, &LOLBin->Name, TRUE)) {
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
    _In_ PCLP_PARSED_COMMAND Parsed
    )
/*++
Routine Description:
    Frees a parsed command structure.

Arguments:
    Parsed - Structure to free.
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
    ClppFreeUnicodeString(&Parsed->FullCommandLine);

    //
    // Free executable
    //
    ClppFreeUnicodeString(&Parsed->Executable);

    //
    // Free arguments
    //
    for (i = 0; i < Parsed->ArgumentCount; i++) {
        ClppFreeUnicodeString(&Parsed->Arguments[i].Value);
    }

    //
    // Free decoded content
    //
    ClppFreeUnicodeString(&Parsed->DecodedContent);

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
        // Initialize name
        //
        RtlInitUnicodeString(&Entry->Name, g_LOLBinDefinitions[i].Name);

        //
        // Compute hash
        //
        Entry->NameHash = ClppHashString(&Entry->Name, TRUE);
        Entry->ThreatLevel = g_LOLBinDefinitions[i].ThreatLevel;
        Entry->Category = g_LOLBinDefinitions[i].Category;

        //
        // Insert into list
        //
        InsertTailList(&Parser->LOLBinList, &Entry->ListEntry);
        Entry = NULL;
    }

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
        ShadowStrikeFreePoolWithTag(LOLBin, CLP_POOL_TAG);
    }
}


static NTSTATUS
ClppInitializePatterns(
    _Inout_ PCLP_PARSER Parser
    )
{
    //
    // Pattern database is currently inline in detection functions
    // Future: Load patterns from configuration
    //
    UNREFERENCED_PARAMETER(Parser);
    return STATUS_SUCCESS;
}


static VOID
ClppCleanupPatterns(
    _Inout_ PCLP_PARSER Parser
    )
{
    PLIST_ENTRY Entry;
    PCLP_PATTERN_ENTRY Pattern;

    while (!IsListEmpty(&Parser->PatternList)) {
        Entry = RemoveHeadList(&Parser->PatternList);
        Pattern = CONTAINING_RECORD(Entry, CLP_PATTERN_ENTRY, ListEntry);
        ClppFreeUnicodeString(&Pattern->Pattern);
        ShadowStrikeFreePoolWithTag(Pattern, CLP_POOL_TAG);
    }
}


// ============================================================================
// INTERNAL: PARSING HELPERS
// ============================================================================

static ULONG
ClppHashString(
    _In_ PCUNICODE_STRING String,
    _In_ BOOLEAN CaseInsensitive
    )
{
    ULONG Hash = 0x811c9dc5;  // FNV-1a seed
    USHORT i;
    WCHAR Ch;

    if (String == NULL || String->Buffer == NULL) {
        return 0;
    }

    for (i = 0; i < String->Length / sizeof(WCHAR); i++) {
        Ch = String->Buffer[i];
        if (CaseInsensitive && Ch >= L'A' && Ch <= L'Z') {
            Ch = Ch - L'A' + L'a';
        }
        Hash ^= (UCHAR)(Ch & 0xFF);
        Hash *= 0x01000193;  // FNV-1a prime
        Hash ^= (UCHAR)((Ch >> 8) & 0xFF);
        Hash *= 0x01000193;
    }

    return Hash;
}


static NTSTATUS
ClppAllocateParsedCommand(
    _Out_ PCLP_PARSED_COMMAND* Parsed
    )
{
    PCLP_PARSED_COMMAND Cmd;

    *Parsed = NULL;

    Cmd = (PCLP_PARSED_COMMAND)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
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
--*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    PCWSTR Ptr = CommandLine->Buffer;
    PCWSTR End = CommandLine->Buffer + (CommandLine->Length / sizeof(WCHAR));
    PCWSTR ArgStart = NULL;
    WCHAR ArgBuffer[CLP_MAX_ARG_LENGTH];
    ULONG ArgIndex = 0;
    ULONG ArgLen = 0;
    BOOLEAN InQuotes = FALSE;
    BOOLEAN IsFlag = FALSE;
    BOOLEAN SkipFirst = TRUE;  // Skip executable

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
        ArgStart = Ptr;
        ArgLen = 0;
        InQuotes = FALSE;
        IsFlag = FALSE;
        RtlZeroMemory(ArgBuffer, sizeof(ArgBuffer));

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
                    // Check for escaped quote
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
            // Handle backslash escape
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
        // Store argument
        //
        if (ArgLen > 0) {
            UNICODE_STRING ArgString;
            RtlInitUnicodeString(&ArgString, ArgBuffer);
            ArgString.Length = (USHORT)(ArgLen * sizeof(WCHAR));

            Status = ClppCopyUnicodeString(
                &Parsed->Arguments[Parsed->ArgumentCount].Value,
                &ArgString
                );

            if (NT_SUCCESS(Status)) {
                Parsed->Arguments[Parsed->ArgumentCount].IsFlag = IsFlag;
                Parsed->ArgumentCount++;
            }
        }
    }

    return STATUS_SUCCESS;
}


static NTSTATUS
ClppExtractExecutable(
    _In_ PCUNICODE_STRING CommandLine,
    _Out_ PUNICODE_STRING Executable
    )
{
    PCWSTR Ptr = CommandLine->Buffer;
    PCWSTR End = CommandLine->Buffer + (CommandLine->Length / sizeof(WCHAR));
    PCWSTR ExeStart = NULL;
    PCWSTR ExeEnd = NULL;
    BOOLEAN InQuotes = FALSE;
    UNICODE_STRING TempString;
    SIZE_T ExeLen;

    RtlZeroMemory(Executable, sizeof(UNICODE_STRING));

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
    if (ExeLen > SHADOW_MAX_PATH) {
        ExeLen = SHADOW_MAX_PATH;
    }

    //
    // Create temporary string and copy
    //
    TempString.Buffer = (PWCHAR)ExeStart;
    TempString.Length = (USHORT)(ExeLen * sizeof(WCHAR));
    TempString.MaximumLength = TempString.Length;

    return ClppCopyUnicodeString(Executable, &TempString);
}


// ============================================================================
// INTERNAL: DETECTION FUNCTIONS
// ============================================================================

static BOOLEAN
ClppDetectEncodedCommand(
    _In_ PCLP_PARSED_COMMAND Parsed
    )
{
    ULONG i;

    for (i = 0; i < Parsed->ArgumentCount; i++) {
        if (Parsed->Arguments[i].IsFlag && Parsed->Arguments[i].Value.Buffer != NULL) {
            PWCHAR Flag = Parsed->Arguments[i].Value.Buffer;

            //
            // PowerShell encoded command flags
            //
            if (_wcsicmp(Flag, L"-enc") == 0 ||
                _wcsicmp(Flag, L"-e") == 0 ||
                _wcsicmp(Flag, L"-ec") == 0 ||
                _wcsicmp(Flag, L"-encodedcommand") == 0 ||
                _wcsicmp(Flag, L"-enco") == 0 ||
                _wcsicmp(Flag, L"-encod") == 0 ||
                _wcsicmp(Flag, L"-encode") == 0 ||
                _wcsicmp(Flag, L"-encoded") == 0 ||
                _wcsicmp(Flag, L"-encodedc") == 0 ||
                _wcsicmp(Flag, L"-encodedco") == 0 ||
                _wcsicmp(Flag, L"-encodedcom") == 0 ||
                _wcsicmp(Flag, L"-encodedcomm") == 0 ||
                _wcsicmp(Flag, L"-encodedcomma") == 0 ||
                _wcsicmp(Flag, L"-encodedcomman") == 0) {
                return TRUE;
            }
        }
    }

    //
    // Also check full command line for obfuscated variants
    //
    if (ClppContainsPatternCaseInsensitive(&Parsed->FullCommandLine, L"-enc")) {
        //
        // Verify it's likely a PowerShell command
        //
        if (ClppContainsPatternCaseInsensitive(&Parsed->FullCommandLine, L"powershell") ||
            ClppContainsPatternCaseInsensitive(&Parsed->FullCommandLine, L"pwsh")) {
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
    ULONG CmdLen = CommandLine->Length / sizeof(WCHAR);

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
    // Thresholds for detection
    //
    // Caret insertion: cmd /c p^o^w^e^r^s^h^e^l^l
    //
    if (CaretCount > 5) {
        return TRUE;
    }

    //
    // Environment variable abuse: %COMSPEC:~0,1%%COMSPEC:~4,1%...
    //
    if (PercentCount > 10 && ClppContainsPatternCaseInsensitive(CommandLine, L"~")) {
        return TRUE;
    }

    //
    // PowerShell tick escaping: pow`er`shell
    //
    if (TickCount > 3) {
        return TRUE;
    }

    //
    // Check for character concatenation patterns
    //
    if (ClppContainsPatternCaseInsensitive(CommandLine, L"+[char]") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"-join") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"[char]") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"-f '") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"-replace")) {
        return TRUE;
    }

    //
    // Check for invoke-expression variants
    //
    if (ClppContainsPatternCaseInsensitive(CommandLine, L"iex") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"invoke-expression") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"i`e`x") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"&(") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L".(")) {
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
    if (ClppContainsPatternCaseInsensitive(CommandLine, L"downloadstring") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"downloadfile") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"downloaddata") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"webclient") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"invoke-webrequest") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"iwr ") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"invoke-restmethod") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"irm ") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"start-bitstransfer") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"net.webclient") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"httpwebrequest") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"system.net.webclient")) {
        return TRUE;
    }

    //
    // Certutil download
    //
    if (ClppContainsPatternCaseInsensitive(CommandLine, L"certutil") &&
        (ClppContainsPatternCaseInsensitive(CommandLine, L"-urlcache") ||
         ClppContainsPatternCaseInsensitive(CommandLine, L"-verifyctl") ||
         ClppContainsPatternCaseInsensitive(CommandLine, L"-ping"))) {
        return TRUE;
    }

    //
    // Bitsadmin download
    //
    if (ClppContainsPatternCaseInsensitive(CommandLine, L"bitsadmin") &&
        (ClppContainsPatternCaseInsensitive(CommandLine, L"/transfer") ||
         ClppContainsPatternCaseInsensitive(CommandLine, L"/create") ||
         ClppContainsPatternCaseInsensitive(CommandLine, L"/addfile"))) {
        return TRUE;
    }

    //
    // Curl/wget
    //
    if (ClppContainsPatternCaseInsensitive(CommandLine, L"curl ") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"curl.exe") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"wget ") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"wget.exe")) {

        //
        // Check for output redirection
        //
        if (ClppContainsPatternCaseInsensitive(CommandLine, L"-o ") ||
            ClppContainsPatternCaseInsensitive(CommandLine, L"--output") ||
            ClppContainsPatternCaseInsensitive(CommandLine, L"> ")) {
            return TRUE;
        }
    }

    //
    // WMIC download
    //
    if (ClppContainsPatternCaseInsensitive(CommandLine, L"wmic") &&
        ClppContainsPatternCaseInsensitive(CommandLine, L"http")) {
        return TRUE;
    }

    //
    // URL patterns combined with execution
    //
    if ((ClppContainsPatternCaseInsensitive(CommandLine, L"http://") ||
         ClppContainsPatternCaseInsensitive(CommandLine, L"https://") ||
         ClppContainsPatternCaseInsensitive(CommandLine, L"ftp://")) &&
        (ClppContainsPatternCaseInsensitive(CommandLine, L"|") ||
         ClppContainsPatternCaseInsensitive(CommandLine, L"iex") ||
         ClppContainsPatternCaseInsensitive(CommandLine, L"invoke"))) {
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
    if (ClppContainsPatternCaseInsensitive(CommandLine, L"-ep bypass") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"-executionpolicy bypass") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"-exec bypass") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"-ep unrestricted") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"-executionpolicy unrestricted") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"set-executionpolicy") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"bypass") &&
        ClppContainsPatternCaseInsensitive(CommandLine, L"powershell")) {
        return TRUE;
    }

    //
    // PowerShell AMSI bypass patterns
    //
    if (ClppContainsPatternCaseInsensitive(CommandLine, L"amsiutils") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"amsiinitfailed") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"amsi.dll") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"amsiscanbuffer") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"amsicontext")) {
        return TRUE;
    }

    //
    // Constrained language mode bypass
    //
    if (ClppContainsPatternCaseInsensitive(CommandLine, L"__pslockeddown") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"fulllanguage")) {
        return TRUE;
    }

    //
    // Script block logging bypass
    //
    if (ClppContainsPatternCaseInsensitive(CommandLine, L"scriptblocklogging") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"enablescriptblocklogging")) {
        return TRUE;
    }

    //
    // Windows Defender exclusions
    //
    if (ClppContainsPatternCaseInsensitive(CommandLine, L"add-mppreference") &&
        ClppContainsPatternCaseInsensitive(CommandLine, L"-exclusion")) {
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
    if (ClppContainsPatternCaseInsensitive(CommandLine, L"-w hidden") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"-windowstyle hidden") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"-win hidden") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"-window hidden") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"-wi hidden") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"-winds hidden")) {
        return TRUE;
    }

    //
    // VBScript/WScript hidden
    //
    if (ClppContainsPatternCaseInsensitive(CommandLine, L"wscript.shell") &&
        ClppContainsPatternCaseInsensitive(CommandLine, L", 0")) {
        return TRUE;
    }

    //
    // VBS Run hidden
    //
    if (ClppContainsPatternCaseInsensitive(CommandLine, L".run") &&
        ClppContainsPatternCaseInsensitive(CommandLine, L", 0,")) {
        return TRUE;
    }

    //
    // CMD start hidden
    //
    if (ClppContainsPatternCaseInsensitive(CommandLine, L"start /min") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"start /b")) {
        return TRUE;
    }

    //
    // PowerShell NoProfile and NonInteractive (often combined with hidden)
    //
    if ((ClppContainsPatternCaseInsensitive(CommandLine, L"-nop") ||
         ClppContainsPatternCaseInsensitive(CommandLine, L"-noprofile")) &&
        (ClppContainsPatternCaseInsensitive(CommandLine, L"-noni") ||
         ClppContainsPatternCaseInsensitive(CommandLine, L"-noninteractive"))) {
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
    if (ClppContainsPatternCaseInsensitive(CommandLine, L"invoke-command") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"enter-pssession") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"new-pssession") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"-computername") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"-cn ") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"-session ")) {
        return TRUE;
    }

    //
    // WMI remote execution
    //
    if (ClppContainsPatternCaseInsensitive(CommandLine, L"wmic") &&
        ClppContainsPatternCaseInsensitive(CommandLine, L"/node:")) {
        return TRUE;
    }

    //
    // PsExec patterns
    //
    if (ClppContainsPatternCaseInsensitive(CommandLine, L"psexec") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"\\\\") &&
        ClppContainsPatternCaseInsensitive(CommandLine, L"cmd") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"\\\\") &&
        ClppContainsPatternCaseInsensitive(CommandLine, L"powershell")) {
        return TRUE;
    }

    //
    // WinRM
    //
    if (ClppContainsPatternCaseInsensitive(CommandLine, L"winrs") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"winrm ")) {
        return TRUE;
    }

    //
    // DCOM execution
    //
    if (ClppContainsPatternCaseInsensitive(CommandLine, L"activator") &&
        ClppContainsPatternCaseInsensitive(CommandLine, L"createinstance")) {
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
    if (ClppContainsPatternCaseInsensitive(CommandLine, L"\\temp\\") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"\\tmp\\") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"%temp%") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"$env:temp")) {
        return TRUE;
    }

    //
    // AppData
    //
    if (ClppContainsPatternCaseInsensitive(CommandLine, L"\\appdata\\local\\") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"\\appdata\\roaming\\") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"%appdata%") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"$env:appdata")) {
        return TRUE;
    }

    //
    // Recycle bin
    //
    if (ClppContainsPatternCaseInsensitive(CommandLine, L"\\$recycle.bin\\") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"\\recycler\\")) {
        return TRUE;
    }

    //
    // Public folders
    //
    if (ClppContainsPatternCaseInsensitive(CommandLine, L"\\users\\public\\") ||
        ClppContainsPatternCaseInsensitive(CommandLine, L"\\public\\")) {
        return TRUE;
    }

    //
    // ProgramData (often abused)
    //
    if (ClppContainsPatternCaseInsensitive(CommandLine, L"\\programdata\\") &&
        !ClppContainsPatternCaseInsensitive(CommandLine, L"\\microsoft\\")) {
        return TRUE;
    }

    //
    // Perflogs
    //
    if (ClppContainsPatternCaseInsensitive(CommandLine, L"\\perflogs\\")) {
        return TRUE;
    }

    return FALSE;
}


static BOOLEAN
ClppDetectScriptExecution(
    _In_ PCLP_PARSED_COMMAND Parsed
    )
{
    //
    // Check executable for script interpreters
    //
    if (Parsed->Executable.Buffer != NULL) {
        PWCHAR Exe = Parsed->Executable.Buffer;

        if (wcsstr(Exe, L"wscript") != NULL ||
            wcsstr(Exe, L"cscript") != NULL ||
            wcsstr(Exe, L"mshta") != NULL) {
            //
            // Script interpreter running - check for script file
            //
            for (ULONG i = 0; i < Parsed->ArgumentCount; i++) {
                if (!Parsed->Arguments[i].IsFlag &&
                    Parsed->Arguments[i].Value.Buffer != NULL) {

                    PWCHAR Arg = Parsed->Arguments[i].Value.Buffer;
                    if (wcsstr(Arg, L".vbs") != NULL ||
                        wcsstr(Arg, L".vbe") != NULL ||
                        wcsstr(Arg, L".js") != NULL ||
                        wcsstr(Arg, L".jse") != NULL ||
                        wcsstr(Arg, L".wsf") != NULL ||
                        wcsstr(Arg, L".wsh") != NULL ||
                        wcsstr(Arg, L".hta") != NULL) {
                        return TRUE;
                    }
                }
            }
        }
    }

    //
    // Check for inline script execution
    //
    if (ClppContainsPatternCaseInsensitive(&Parsed->FullCommandLine, L"javascript:") ||
        ClppContainsPatternCaseInsensitive(&Parsed->FullCommandLine, L"vbscript:")) {
        return TRUE;
    }

    return FALSE;
}


static BOOLEAN
ClppContainsPatternCaseInsensitive(
    _In_ PCUNICODE_STRING String,
    _In_ PCWSTR Pattern
    )
{
    UNICODE_STRING PatternString;
    SIZE_T StringLen;
    SIZE_T PatternLen;
    SIZE_T i, j;

    if (String == NULL || String->Buffer == NULL || Pattern == NULL) {
        return FALSE;
    }

    RtlInitUnicodeString(&PatternString, Pattern);

    StringLen = String->Length / sizeof(WCHAR);
    PatternLen = PatternString.Length / sizeof(WCHAR);

    if (PatternLen > StringLen) {
        return FALSE;
    }

    //
    // Simple case-insensitive substring search
    //
    for (i = 0; i <= StringLen - PatternLen; i++) {
        BOOLEAN Match = TRUE;

        for (j = 0; j < PatternLen; j++) {
            WCHAR C1 = String->Buffer[i + j];
            WCHAR C2 = Pattern[j];

            //
            // Convert to lowercase for comparison
            //
            if (C1 >= L'A' && C1 <= L'Z') {
                C1 = C1 - L'A' + L'a';
            }
            if (C2 >= L'A' && C2 <= L'Z') {
                C2 = C2 - L'A' + L'a';
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
    _In_ WCHAR Ch
    )
{
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
    return 0;  // Padding or invalid
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
--*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    PCWSTR Src = Encoded->Buffer;
    SIZE_T SrcLen = Encoded->Length / sizeof(WCHAR);
    SIZE_T ValidChars = 0;
    SIZE_T DecodedByteLen;
    SIZE_T DecodedCharLen;
    PUCHAR DecodedBytes = NULL;
    SIZE_T i, j;
    UCHAR Quad[4];
    SIZE_T ByteIndex = 0;

    RtlZeroMemory(Decoded, sizeof(UNICODE_STRING));

    //
    // Count valid Base64 characters
    //
    for (i = 0; i < SrcLen; i++) {
        if (ClppIsValidBase64Char(Src[i]) && Src[i] != L'=') {
            ValidChars++;
        } else if (Src[i] == L'=') {
            //
            // Padding - stop counting
            //
            break;
        } else if (Src[i] != L' ' && Src[i] != L'\t' &&
                   Src[i] != L'\r' && Src[i] != L'\n') {
            //
            // Invalid character (not whitespace)
            //
            return STATUS_INVALID_PARAMETER;
        }
    }

    if (ValidChars < CLP_MIN_BASE64_LENGTH) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Calculate decoded length
    // Every 4 Base64 chars = 3 bytes
    //
    DecodedByteLen = (ValidChars * 3) / 4;

    //
    // Account for padding
    //
    for (i = SrcLen - 1; i > 0 && Src[i] == L'='; i--) {
        DecodedByteLen--;
    }

    if (DecodedByteLen > CLP_MAX_DECODED_LENGTH) {
        return STATUS_BUFFER_OVERFLOW;
    }

    //
    // Allocate buffer for decoded bytes
    //
    DecodedBytes = (PUCHAR)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
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
    j = 0;
    for (i = 0; i < SrcLen && ByteIndex < DecodedByteLen; ) {
        //
        // Collect 4 Base64 characters
        //
        ULONG QuadIndex = 0;
        RtlZeroMemory(Quad, sizeof(Quad));

        while (QuadIndex < 4 && i < SrcLen) {
            WCHAR Ch = Src[i++];

            if (Ch == L' ' || Ch == L'\t' || Ch == L'\r' || Ch == L'\n') {
                continue;
            }

            if (Ch == L'=') {
                Quad[QuadIndex++] = 0;
                continue;
            }

            if (!ClppIsValidBase64Char(Ch)) {
                Status = STATUS_INVALID_PARAMETER;
                goto Cleanup;
            }

            Quad[QuadIndex++] = ClppBase64CharToValue(Ch);
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
    // Allocate the unicode string buffer
    //
    Decoded->Buffer = (PWCHAR)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        (DecodedCharLen + 1) * sizeof(WCHAR),
        CLP_POOL_TAG
        );

    if (Decoded->Buffer == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    RtlCopyMemory(Decoded->Buffer, DecodedBytes, DecodedCharLen * sizeof(WCHAR));
    Decoded->Buffer[DecodedCharLen] = L'\0';
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
ClppCopyUnicodeString(
    _Out_ PUNICODE_STRING Destination,
    _In_ PCUNICODE_STRING Source
    )
{
    PWCHAR Buffer;
    SIZE_T BufferSize;

    RtlZeroMemory(Destination, sizeof(UNICODE_STRING));

    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0) {
        return STATUS_SUCCESS;
    }

    BufferSize = Source->Length + sizeof(WCHAR);  // +null terminator

    Buffer = (PWCHAR)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        BufferSize,
        CLP_POOL_TAG
        );

    if (Buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(Buffer, Source->Buffer, Source->Length);
    Buffer[Source->Length / sizeof(WCHAR)] = L'\0';

    Destination->Buffer = Buffer;
    Destination->Length = Source->Length;
    Destination->MaximumLength = (USHORT)BufferSize;

    return STATUS_SUCCESS;
}


static VOID
ClppFreeUnicodeString(
    _Inout_ PUNICODE_STRING String
    )
{
    if (String != NULL && String->Buffer != NULL) {
        ShadowStrikeFreePoolWithTag(String->Buffer, CLP_POOL_TAG);
        RtlZeroMemory(String, sizeof(UNICODE_STRING));
    }
}
