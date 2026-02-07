/*++
    ShadowStrike Next-Generation Antivirus
    Module: ShellcodeDetector.h
    
    Purpose: Advanced shellcode detection engine using pattern
             matching, heuristics, and behavioral analysis.
             
    Architecture:
    - NOP sled detection
    - Egg hunter pattern recognition
    - Encoder/decoder detection (XOR, ADD, ROL)
    - API hashing resolution detection
    - Direct syscall stub detection
    - Stack pivot detection
    
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

#define SD_POOL_TAG_CONTEXT     'CXDS'  // Shellcode Detector - Context
#define SD_POOL_TAG_RESULT      'ERDS'  // Shellcode Detector - Result
#define SD_POOL_TAG_PATTERN     'TPDS'  // Shellcode Detector - Pattern

//=============================================================================
// Configuration Constants
//=============================================================================

#define SD_MIN_SCAN_SIZE                64
#define SD_MAX_SCAN_SIZE                (64 * 1024 * 1024)  // 64 MB
#define SD_NOP_SLED_MIN_LENGTH          16
#define SD_EGG_HUNTER_MAX_SIZE          128
#define SD_ENCODER_LOOP_MAX_SIZE        256
#define SD_MAX_API_HASHES               1024
#define SD_SYSCALL_STUB_SIZE            32

//=============================================================================
// Shellcode Types
//=============================================================================

typedef enum _SD_SHELLCODE_TYPE {
    SdShellcode_Unknown = 0,
    SdShellcode_NopSled,                // NOP sled pattern
    SdShellcode_EggHunter,              // Egg hunter shellcode
    SdShellcode_XorEncoder,             // XOR encoded shellcode
    SdShellcode_AddEncoder,             // ADD encoded shellcode
    SdShellcode_RolEncoder,             // ROL/ROR encoded shellcode
    SdShellcode_AlphanumEncoder,        // Alphanumeric encoder
    SdShellcode_UnicodeEncoder,         // Unicode-safe encoder
    SdShellcode_APIHashing,             // API hash resolution
    SdShellcode_DirectSyscall,          // Direct syscall stub
    SdShellcode_HeavensGate,            // WoW64 Heaven's Gate
    SdShellcode_StackPivot,             // Stack pivot gadget
    SdShellcode_Position Independent,   // Position-independent code
    SdShellcode_Staged,                 // Staged shellcode loader
    SdShellcode_Meterpreter,            // Meterpreter patterns
    SdShellcode_CobaltStrike,           // Cobalt Strike patterns
    SdShellcode_Generic,                // Generic shellcode
} SD_SHELLCODE_TYPE;

//=============================================================================
// Detection Flags
//=============================================================================

typedef enum _SD_DETECTION_FLAGS {
    SdFlag_None                 = 0x00000000,
    SdFlag_NopSled              = 0x00000001,
    SdFlag_EggHunter            = 0x00000002,
    SdFlag_Encoder              = 0x00000004,
    SdFlag_APIHashing           = 0x00000008,
    SdFlag_DirectSyscall        = 0x00000010,
    SdFlag_HeavensGate          = 0x00000020,
    SdFlag_StackPivot           = 0x00000040,
    SdFlag_PIC                  = 0x00000080,
    SdFlag_HighEntropy          = 0x00000100,
    SdFlag_SuspiciousCall       = 0x00000200,
    SdFlag_Polymorphic          = 0x00000400,
    SdFlag_KnownSignature       = 0x00000800,
} SD_DETECTION_FLAGS;

//=============================================================================
// Encoder Information
//=============================================================================

typedef struct _SD_ENCODER_INFO {
    //
    // Encoder type
    //
    enum {
        EncoderType_None = 0,
        EncoderType_XOR,
        EncoderType_ADD,
        EncoderType_SUB,
        EncoderType_ROL,
        EncoderType_ROR,
        EncoderType_Alphanumeric,
        EncoderType_Unicode,
        EncoderType_Custom
    } Type;
    
    //
    // Encoder parameters
    //
    UCHAR Key[16];                      // Encoding key
    ULONG KeyLength;
    ULONG KeyOffset;                    // Offset where key was found
    
    //
    // Decode loop location
    //
    ULONG64 LoopStart;
    ULONG64 LoopEnd;
    ULONG LoopIterations;
    
    //
    // Decoded size estimate
    //
    ULONG EncodedSize;
    ULONG DecodedSizeEstimate;
    
} SD_ENCODER_INFO, *PSD_ENCODER_INFO;

//=============================================================================
// API Hash Information
//=============================================================================

typedef struct _SD_API_HASH_INFO {
    //
    // Hash algorithm
    //
    enum {
        HashAlgorithm_Unknown = 0,
        HashAlgorithm_CRC32,
        HashAlgorithm_ROR13,            // Common in shellcode
        HashAlgorithm_DJBX33A,
        HashAlgorithm_FNV1A,
        HashAlgorithm_Custom
    } Algorithm;
    
    //
    // Resolved APIs
    //
    struct {
        ULONG Hash;
        CHAR ApiName[64];
        CHAR DllName[32];
    } ResolvedApis[32];
    ULONG ResolvedCount;
    
    //
    // Resolution code location
    //
    ULONG64 ResolutionCodeStart;
    ULONG ResolutionCodeSize;
    
} SD_API_HASH_INFO, *PSD_API_HASH_INFO;

//=============================================================================
// Syscall Stub Information
//=============================================================================

typedef struct _SD_SYSCALL_INFO {
    //
    // Syscall number
    //
    ULONG SyscallNumber;
    CHAR SyscallName[64];               // If resolved
    
    //
    // Stub location
    //
    ULONG64 StubAddress;
    ULONG StubSize;
    
    //
    // Stub type
    //
    enum {
        StubType_Direct,                // Direct syscall
        StubType_Indirect,              // JMP to syscall
        StubType_HeavensGate,           // 32->64 transition
        StubType_Hooked                 // Possible hook bypass
    } Type;
    
    //
    // Associated bytes
    //
    UCHAR StubBytes[SD_SYSCALL_STUB_SIZE];
    
} SD_SYSCALL_INFO, *PSD_SYSCALL_INFO;

//=============================================================================
// Detection Result
//=============================================================================

typedef struct _SD_DETECTION_RESULT {
    //
    // Detection summary
    //
    BOOLEAN IsShellcode;
    SD_SHELLCODE_TYPE Type;
    SD_DETECTION_FLAGS Flags;
    ULONG ConfidenceScore;              // 0-100
    ULONG SeverityScore;                // 0-100
    
    //
    // Location
    //
    HANDLE ProcessId;
    PVOID Address;
    SIZE_T Size;
    ULONG Protection;
    
    //
    // NOP sled info
    //
    struct {
        BOOLEAN Found;
        PVOID StartAddress;
        ULONG Length;
        UCHAR NopByte;                  // Usually 0x90
    } NopSled;
    
    //
    // Egg hunter info
    //
    struct {
        BOOLEAN Found;
        UCHAR EggBytes[8];
        ULONG EggLength;
        PVOID HunterAddress;
        ULONG HunterSize;
    } EggHunter;
    
    //
    // Encoder info
    //
    SD_ENCODER_INFO Encoder;
    
    //
    // API hashing info
    //
    SD_API_HASH_INFO ApiHashing;
    
    //
    // Syscall info
    //
    struct {
        BOOLEAN Found;
        ULONG Count;
        SD_SYSCALL_INFO Syscalls[16];
    } Syscalls;
    
    //
    // Stack pivot info
    //
    struct {
        BOOLEAN Found;
        PVOID GadgetAddress;
        ULONG GadgetSize;
        UCHAR GadgetBytes[32];
    } StackPivot;
    
    //
    // Entropy analysis
    //
    ULONG EntropyPercent;
    BOOLEAN HighEntropy;
    
    //
    // Known signature match
    //
    struct {
        BOOLEAN Matched;
        CHAR SignatureName[64];
        CHAR ThreatFamily[64];
    } Signature;
    
    //
    // Timing
    //
    LARGE_INTEGER DetectionTime;
    ULONG AnalysisDurationMs;
    
} SD_DETECTION_RESULT, *PSD_DETECTION_RESULT;

//=============================================================================
// Shellcode Detector Configuration
//=============================================================================

typedef struct _SD_CONFIG {
    //
    // Detection toggles
    //
    BOOLEAN EnableNopSledDetection;
    BOOLEAN EnableEggHunterDetection;
    BOOLEAN EnableEncoderDetection;
    BOOLEAN EnableApiHashDetection;
    BOOLEAN EnableSyscallDetection;
    BOOLEAN EnableStackPivotDetection;
    BOOLEAN EnableEntropyAnalysis;
    BOOLEAN EnableSignatureMatching;
    
    //
    // Thresholds
    //
    ULONG NopSledMinLength;
    ULONG EntropyThreshold;             // 0-100
    ULONG MinConfidenceScore;           // Report threshold
    
    //
    // Performance
    //
    ULONG MaxScanSizeBytes;
    ULONG ScanTimeoutMs;
    
} SD_CONFIG, *PSD_CONFIG;

//=============================================================================
// Shellcode Detector
//=============================================================================

typedef struct _SD_DETECTOR {
    //
    // Initialization state
    //
    BOOLEAN Initialized;
    
    //
    // Configuration
    //
    SD_CONFIG Config;
    
    //
    // Known API hashes database
    //
    struct {
        PVOID HashTable;                // Hash -> API name mapping
        ULONG HashCount;
        EX_PUSH_LOCK Lock;
    } ApiHashes;
    
    //
    // Known shellcode signatures
    //
    struct {
        PVOID SignatureDatabase;
        ULONG SignatureCount;
        EX_PUSH_LOCK Lock;
    } Signatures;
    
    //
    // Statistics
    //
    struct {
        volatile LONG64 TotalScans;
        volatile LONG64 DetectionsFound;
        volatile LONG64 NopSledsFound;
        volatile LONG64 EggHuntersFound;
        volatile LONG64 EncodersFound;
        volatile LONG64 ApiHashingFound;
        volatile LONG64 SyscallsFound;
        LARGE_INTEGER StartTime;
    } Stats;
    
} SD_DETECTOR, *PSD_DETECTOR;

//=============================================================================
// Callback Types
//=============================================================================

typedef VOID (*SD_DETECTION_CALLBACK)(
    _In_ PSD_DETECTION_RESULT Result,
    _In_opt_ PVOID Context
    );

//=============================================================================
// Public API - Initialization
//=============================================================================

NTSTATUS
SdInitialize(
    _Out_ PSD_DETECTOR* Detector,
    _In_opt_ PSD_CONFIG Config
    );

VOID
SdShutdown(
    _Inout_ PSD_DETECTOR Detector
    );

NTSTATUS
SdSetConfig(
    _Inout_ PSD_DETECTOR Detector,
    _In_ PSD_CONFIG Config
    );

//=============================================================================
// Public API - Detection
//=============================================================================

NTSTATUS
SdAnalyzeBuffer(
    _In_ PSD_DETECTOR Detector,
    _In_reads_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _Out_ PSD_DETECTION_RESULT* Result
    );

NTSTATUS
SdAnalyzeRegion(
    _In_ PSD_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _In_ SIZE_T Size,
    _Out_ PSD_DETECTION_RESULT* Result
    );

NTSTATUS
SdScanProcess(
    _In_ PSD_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _Out_writes_to_(MaxResults, *ResultCount) PSD_DETECTION_RESULT* Results,
    _In_ ULONG MaxResults,
    _Out_ PULONG ResultCount
    );

//=============================================================================
// Public API - Specific Detections
//=============================================================================

NTSTATUS
SdDetectNopSled(
    _In_ PSD_DETECTOR Detector,
    _In_reads_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _Out_ PBOOLEAN Found,
    _Out_opt_ PULONG Offset,
    _Out_opt_ PULONG Length
    );

NTSTATUS
SdDetectEncoder(
    _In_ PSD_DETECTOR Detector,
    _In_reads_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _Out_ PSD_ENCODER_INFO EncoderInfo
    );

NTSTATUS
SdDetectApiHashing(
    _In_ PSD_DETECTOR Detector,
    _In_reads_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _Out_ PSD_API_HASH_INFO ApiHashInfo
    );

NTSTATUS
SdDetectDirectSyscall(
    _In_ PSD_DETECTOR Detector,
    _In_reads_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _Out_writes_to_(MaxSyscalls, *SyscallCount) PSD_SYSCALL_INFO Syscalls,
    _In_ ULONG MaxSyscalls,
    _Out_ PULONG SyscallCount
    );

//=============================================================================
// Public API - API Hash Database
//=============================================================================

NTSTATUS
SdAddApiHash(
    _In_ PSD_DETECTOR Detector,
    _In_ ULONG Hash,
    _In_ PCSTR ApiName,
    _In_ PCSTR DllName
    );

NTSTATUS
SdLookupApiHash(
    _In_ PSD_DETECTOR Detector,
    _In_ ULONG Hash,
    _Out_writes_z_(ApiNameSize) PSTR ApiName,
    _In_ ULONG ApiNameSize,
    _Out_writes_z_(DllNameSize) PSTR DllName,
    _In_ ULONG DllNameSize
    );

NTSTATUS
SdLoadApiHashDatabase(
    _In_ PSD_DETECTOR Detector,
    _In_ PUNICODE_STRING FilePath
    );

//=============================================================================
// Public API - Results
//=============================================================================

VOID
SdFreeResult(
    _In_ PSD_DETECTION_RESULT Result
    );

//=============================================================================
// Public API - Statistics
//=============================================================================

typedef struct _SD_STATISTICS {
    ULONG64 TotalScans;
    ULONG64 DetectionsFound;
    ULONG64 NopSledsFound;
    ULONG64 EggHuntersFound;
    ULONG64 EncodersFound;
    ULONG64 ApiHashingFound;
    ULONG64 SyscallsFound;
    ULONG ApiHashCount;
    ULONG SignatureCount;
    LARGE_INTEGER UpTime;
} SD_STATISTICS, *PSD_STATISTICS;

NTSTATUS
SdGetStatistics(
    _In_ PSD_DETECTOR Detector,
    _Out_ PSD_STATISTICS Stats
    );

#ifdef __cplusplus
}
#endif
