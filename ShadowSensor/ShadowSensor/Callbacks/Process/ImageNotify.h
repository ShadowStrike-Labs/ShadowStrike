/*++
    ShadowStrike Next-Generation Antivirus
    Module: ImageNotify.h

    Purpose: Enterprise-grade image load notification callback for
             DLL injection detection, driver load monitoring, and
             malicious module identification.

    Architecture:
    - PsSetLoadImageNotifyRoutineEx integration
    - PE header validation and anomaly detection
    - Unsigned/untrusted module flagging
    - DLL side-loading detection
    - Reflective DLL injection detection
    - Module stomping detection
    - Known vulnerable driver detection
    - Telemetry generation for SIEM integration

    MITRE ATT&CK Coverage:
    - T1055.001: Process Injection - Dynamic-link Library Injection
    - T1055.004: Process Injection - Asynchronous Procedure Call
    - T1574.001: Hijack Execution Flow - DLL Search Order Hijacking
    - T1574.002: Hijack Execution Flow - DLL Side-Loading
    - T1014: Rootkit (driver load monitoring)
    - T1068: Exploitation for Privilege Escalation (vulnerable drivers)

    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>
#include <ntimage.h>

//=============================================================================
// Pool Tags
//=============================================================================

#define IMG_POOL_TAG_CONTEXT        'gImS'  // Image Notify - Context
#define IMG_POOL_TAG_EVENT          'eImS'  // Image Notify - Event
#define IMG_POOL_TAG_CACHE          'cImS'  // Image Notify - Cache
#define IMG_POOL_TAG_HASH           'hImS'  // Image Notify - Hash

//=============================================================================
// Configuration Constants
//=============================================================================

#define IMG_MAX_PATH_LENGTH             520
#define IMG_MAX_TRACKED_MODULES         4096
#define IMG_MAX_SUSPICIOUS_DLLS         256
#define IMG_HASH_BUCKET_COUNT           256
#define IMG_CACHE_TTL_SECONDS           300
#define IMG_MAX_PE_HEADER_SIZE          4096
#define IMG_LOOKASIDE_DEPTH             128

//=============================================================================
// Image Load Flags
//=============================================================================

typedef enum _IMG_LOAD_FLAGS {
    ImgFlag_None                    = 0x00000000,

    //
    // Image type flags
    //
    ImgFlag_KernelMode              = 0x00000001,   // Kernel-mode driver
    ImgFlag_UserMode                = 0x00000002,   // User-mode DLL/EXE
    ImgFlag_MappedAsImage           = 0x00000004,   // SEC_IMAGE mapping
    ImgFlag_MappedAsDataFile        = 0x00000008,   // Data file mapping
    ImgFlag_PartialMap              = 0x00000010,   // Partial map (not full image)
    ImgFlag_SystemModule            = 0x00000020,   // System32/SysWOW64 module

    //
    // Signature flags
    //
    ImgFlag_Signed                  = 0x00000100,   // Digitally signed
    ImgFlag_Catalog                 = 0x00000200,   // Catalog signed
    ImgFlag_Embedded                = 0x00000400,   // Embedded signature
    ImgFlag_MicrosoftSigned         = 0x00000800,   // Microsoft signature
    ImgFlag_WhqlSigned              = 0x00001000,   // WHQL signed driver
    ImgFlag_Revoked                 = 0x00002000,   // Revoked certificate
    ImgFlag_Expired                 = 0x00004000,   // Expired certificate

    //
    // Suspicious indicators
    //
    ImgFlag_Unsigned                = 0x00010000,   // No valid signature
    ImgFlag_SuspiciousPath          = 0x00020000,   // Loaded from suspicious location
    ImgFlag_NameMismatch            = 0x00040000,   // Internal name doesn't match file
    ImgFlag_HiddenExport            = 0x00080000,   // Hidden/obfuscated exports
    ImgFlag_PackedPE                = 0x00100000,   // Packed/encrypted PE
    ImgFlag_AbnormalSections        = 0x00200000,   // Abnormal section characteristics
    ImgFlag_NoExports               = 0x00400000,   // DLL with no exports
    ImgFlag_HighEntropy             = 0x00800000,   // High entropy sections
    ImgFlag_SelfModifying           = 0x01000000,   // Writable code section
    ImgFlag_RemoteLoad              = 0x02000000,   // Loaded by remote process
    ImgFlag_ReflectiveLoad          = 0x04000000,   // Reflective DLL pattern
    ImgFlag_UnbackedMemory          = 0x08000000,   // Not backed by file
    ImgFlag_KnownVulnerable         = 0x10000000,   // Known vulnerable driver
    ImgFlag_Blocked                 = 0x20000000,   // Load was blocked

} IMG_LOAD_FLAGS;

//=============================================================================
// Image Types
//=============================================================================

typedef enum _IMG_TYPE {
    ImgType_Unknown = 0,
    ImgType_Exe,                    // Executable
    ImgType_Dll,                    // Dynamic-link library
    ImgType_Sys,                    // Kernel driver
    ImgType_Ocx,                    // ActiveX control
    ImgType_Cpl,                    // Control panel applet
    ImgType_Scr,                    // Screen saver
    ImgType_Drv,                    // Legacy driver
    ImgType_Efi,                    // EFI binary
    ImgType_Clr,                    // .NET assembly
    ImgType_Max
} IMG_TYPE;

//=============================================================================
// Suspicious Load Reasons
//=============================================================================

typedef enum _IMG_SUSPICIOUS_REASON {
    ImgSuspicious_None              = 0x00000000,
    ImgSuspicious_TempDirectory     = 0x00000001,   // Loaded from %TEMP%
    ImgSuspicious_DownloadsDir      = 0x00000002,   // Loaded from Downloads
    ImgSuspicious_UserWritable      = 0x00000004,   // User-writable location
    ImgSuspicious_NetworkPath       = 0x00000008,   // UNC/network path
    ImgSuspicious_HiddenFile        = 0x00000010,   // Hidden file attribute
    ImgSuspicious_DoubleExtension   = 0x00000020,   // Double extension (e.g., .pdf.dll)
    ImgSuspicious_RandomName        = 0x00000040,   // Random-looking filename
    ImgSuspicious_MasqueradingName  = 0x00000080,   // Similar to system DLL name
    ImgSuspicious_SideLoadPath      = 0x00000100,   // Potential DLL side-loading
    ImgSuspicious_UnusualParent     = 0x00000200,   // Unusual parent process
    ImgSuspicious_ProcessHollow     = 0x00000400,   // Process hollowing indicator
    ImgSuspicious_RemoteThread      = 0x00000800,   // Loaded via remote thread
    ImgSuspicious_KnownMalware      = 0x00001000,   // Known malware hash
    ImgSuspicious_BlacklistedCert   = 0x00002000,   // Blacklisted certificate
    ImgSuspicious_StompedModule     = 0x00004000,   // Module stomping detected
    ImgSuspicious_PhantomDll        = 0x00008000,   // DLL doesn't exist on disk
} IMG_SUSPICIOUS_REASON;

//=============================================================================
// PE Analysis Results
//=============================================================================

typedef struct _IMG_PE_INFO {
    //
    // Basic PE information
    //
    BOOLEAN Is64Bit;
    BOOLEAN IsDll;
    BOOLEAN IsDriver;
    BOOLEAN IsDotNet;
    USHORT Machine;
    USHORT Subsystem;
    USHORT DllCharacteristics;
    ULONG Characteristics;

    //
    // Timestamps
    //
    ULONG TimeDateStamp;
    ULONG CheckSum;
    ULONG CalculatedCheckSum;
    BOOLEAN ChecksumValid;

    //
    // Entry point
    //
    ULONG AddressOfEntryPoint;
    PVOID EntryPointVa;
    BOOLEAN EntryPointInCode;

    //
    // Sections
    //
    USHORT NumberOfSections;
    struct {
        CHAR Name[9];
        ULONG VirtualSize;
        ULONG VirtualAddress;
        ULONG Characteristics;
        ULONG Entropy;          // Entropy * 100
        BOOLEAN IsExecutable;
        BOOLEAN IsWritable;
    } Sections[16];

    //
    // Imports/Exports
    //
    ULONG ImportCount;
    ULONG ExportCount;
    BOOLEAN HasDelayLoadImports;
    BOOLEAN HasTlsCallbacks;
    ULONG TlsCallbackCount;

    //
    // Security directory
    //
    BOOLEAN HasSecurityDirectory;
    ULONG SecurityDirectorySize;

    //
    // Debug information
    //
    BOOLEAN HasDebugInfo;
    GUID PdbGuid;
    ULONG PdbAge;

    //
    // Version information
    //
    BOOLEAN HasVersionInfo;
    WCHAR InternalName[64];
    WCHAR OriginalFilename[64];
    WCHAR FileDescription[128];
    WCHAR CompanyName[64];
    WCHAR ProductName[64];

} IMG_PE_INFO, *PIMG_PE_INFO;

//=============================================================================
// Image Load Event
//=============================================================================

typedef struct _IMG_LOAD_EVENT {
    //
    // Event header
    //
    ULONG Size;
    ULONG Version;
    LARGE_INTEGER Timestamp;
    ULONG64 EventId;

    //
    // Process context
    //
    HANDLE ProcessId;
    HANDLE ThreadId;
    HANDLE ParentProcessId;
    ULONG SessionId;

    //
    // Image information
    //
    PVOID ImageBase;
    SIZE_T ImageSize;
    IMG_TYPE ImageType;
    IMG_LOAD_FLAGS Flags;

    //
    // File information
    //
    WCHAR FullImagePath[IMG_MAX_PATH_LENGTH];
    WCHAR ImageFileName[64];
    ULONG64 FileId;

    //
    // Hash information
    //
    UCHAR Sha256Hash[32];
    UCHAR Sha1Hash[20];
    UCHAR Md5Hash[16];
    BOOLEAN HashesComputed;

    //
    // Signature information
    //
    struct {
        BOOLEAN IsSigned;
        BOOLEAN IsVerified;
        WCHAR SignerName[128];
        WCHAR IssuerName[128];
        LARGE_INTEGER NotBefore;
        LARGE_INTEGER NotAfter;
    } Signature;

    //
    // Suspicious indicators
    //
    IMG_SUSPICIOUS_REASON SuspiciousReasons;
    ULONG ThreatScore;              // 0-100
    ULONG ConfidenceScore;          // 0-100

    //
    // PE analysis (optional)
    //
    BOOLEAN PeAnalyzed;
    IMG_PE_INFO PeInfo;

    //
    // Process context
    //
    WCHAR ProcessImagePath[IMG_MAX_PATH_LENGTH];

    //
    // List linkage for tracking
    //
    LIST_ENTRY ListEntry;

} IMG_LOAD_EVENT, *PIMG_LOAD_EVENT;

//=============================================================================
// Image Notify Configuration
//=============================================================================

typedef struct _IMG_NOTIFY_CONFIG {
    //
    // Feature toggles
    //
    BOOLEAN EnablePeAnalysis;
    BOOLEAN EnableHashComputation;
    BOOLEAN EnableSignatureCheck;
    BOOLEAN EnableSuspiciousDetection;
    BOOLEAN EnableDriverMonitoring;
    BOOLEAN EnableVulnerableDriverCheck;
    BOOLEAN MonitorSystemProcesses;
    BOOLEAN MonitorKernelImages;

    //
    // Filtering
    //
    BOOLEAN SkipMicrosoftSigned;
    BOOLEAN SkipWhqlSigned;
    BOOLEAN SkipCatalogSigned;

    //
    // Thresholds
    //
    ULONG MinThreatScoreToReport;
    ULONG HighEntropyThreshold;     // Entropy * 100

    //
    // Rate limiting
    //
    ULONG MaxEventsPerSecond;

} IMG_NOTIFY_CONFIG, *PIMG_NOTIFY_CONFIG;

//=============================================================================
// Image Notify Statistics
//=============================================================================

typedef struct _IMG_NOTIFY_STATISTICS {
    volatile LONG64 TotalImagesLoaded;
    volatile LONG64 UserModeImages;
    volatile LONG64 KernelModeImages;
    volatile LONG64 SignedImages;
    volatile LONG64 UnsignedImages;
    volatile LONG64 SuspiciousImages;
    volatile LONG64 BlockedImages;
    volatile LONG64 HashesComputed;
    volatile LONG64 PeAnalyses;
    volatile LONG64 CacheHits;
    volatile LONG64 CacheMisses;
    volatile LONG64 EventsDropped;
    LARGE_INTEGER StartTime;
} IMG_NOTIFY_STATISTICS, *PIMG_NOTIFY_STATISTICS;

//=============================================================================
// Callback Types
//=============================================================================

//
// Pre-load callback - can block driver loads
//
typedef NTSTATUS (*IMG_PRE_LOAD_CALLBACK)(
    _In_ HANDLE ProcessId,
    _In_ PUNICODE_STRING FullImageName,
    _In_ PIMAGE_INFO ImageInfo,
    _Out_ PBOOLEAN BlockLoad,
    _In_opt_ PVOID Context
    );

//
// Post-load callback - for telemetry
//
typedef VOID (*IMG_POST_LOAD_CALLBACK)(
    _In_ PIMG_LOAD_EVENT Event,
    _In_opt_ PVOID Context
    );

//=============================================================================
// Public API - Initialization
//=============================================================================

//
// Routine Description:
//    Initializes the image load notification subsystem with
//    enterprise-grade detection capabilities.
//
// Arguments:
//    Config - Optional configuration (NULL for defaults)
//
// Return Value:
//    STATUS_SUCCESS if successful
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ImageNotifyInitialize(
    _In_opt_ PIMG_NOTIFY_CONFIG Config
    );

//
// Routine Description:
//    Registers the image load notification callback with the kernel.
//
// Arguments:
//    None
//
// Return Value:
//    STATUS_SUCCESS if successful
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
RegisterImageNotify(
    VOID
    );

//
// Routine Description:
//    Unregisters the image load notification callback.
//
// Arguments:
//    None
//
// Return Value:
//    STATUS_SUCCESS if successful
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
UnregisterImageNotify(
    VOID
    );

//
// Routine Description:
//    Shuts down the image notification subsystem and releases resources.
//
// Arguments:
//    None
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ImageNotifyShutdown(
    VOID
    );

//=============================================================================
// Public API - Configuration
//=============================================================================

//
// Routine Description:
//    Updates the image notification configuration.
//
// Arguments:
//    Config - New configuration
//
// Return Value:
//    STATUS_SUCCESS if successful
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ImageNotifySetConfig(
    _In_ PIMG_NOTIFY_CONFIG Config
    );

//
// Routine Description:
//    Retrieves the current configuration.
//
// Arguments:
//    Config - Receives current configuration
//
// Return Value:
//    STATUS_SUCCESS if successful
//
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ImageNotifyGetConfig(
    _Out_ PIMG_NOTIFY_CONFIG Config
    );

//=============================================================================
// Public API - Callbacks
//=============================================================================

//
// Routine Description:
//    Registers a pre-load callback that can block driver loads.
//
// Arguments:
//    Callback - Callback function
//    Context - User context
//
// Return Value:
//    STATUS_SUCCESS if successful
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ImageNotifyRegisterPreLoadCallback(
    _In_ IMG_PRE_LOAD_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

//
// Routine Description:
//    Registers a post-load callback for event notification.
//
// Arguments:
//    Callback - Callback function
//    Context - User context
//
// Return Value:
//    STATUS_SUCCESS if successful
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ImageNotifyRegisterPostLoadCallback(
    _In_ IMG_POST_LOAD_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

//
// Routine Description:
//    Unregisters a previously registered callback.
//
// Arguments:
//    Callback - Callback to unregister (either pre or post)
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ImageNotifyUnregisterCallback(
    _In_ PVOID Callback
    );

//=============================================================================
// Public API - Vulnerable Driver Database
//=============================================================================

//
// Routine Description:
//    Adds a hash to the vulnerable driver database.
//
// Arguments:
//    Sha256Hash - SHA-256 hash of vulnerable driver
//    DriverName - Name of the driver
//    CveId - CVE identifier (optional)
//
// Return Value:
//    STATUS_SUCCESS if successful
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ImageNotifyAddVulnerableDriver(
    _In_reads_bytes_(32) PUCHAR Sha256Hash,
    _In_ PCWSTR DriverName,
    _In_opt_ PCSTR CveId
    );

//
// Routine Description:
//    Checks if a hash matches a known vulnerable driver.
//
// Arguments:
//    Sha256Hash - Hash to check
//
// Return Value:
//    TRUE if hash matches a known vulnerable driver
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ImageNotifyIsVulnerableDriver(
    _In_reads_bytes_(32) PUCHAR Sha256Hash
    );

//=============================================================================
// Public API - Statistics
//=============================================================================

//
// Routine Description:
//    Retrieves image notification statistics.
//
// Arguments:
//    Stats - Receives statistics snapshot
//
// Return Value:
//    STATUS_SUCCESS if successful
//
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ImageNotifyGetStatistics(
    _Out_ PIMG_NOTIFY_STATISTICS Stats
    );

//
// Routine Description:
//    Resets all statistics counters.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ImageNotifyResetStatistics(
    VOID
    );

//=============================================================================
// Public API - Query Functions
//=============================================================================

//
// Routine Description:
//    Queries loaded modules for a specific process.
//
// Arguments:
//    ProcessId - Target process ID
//    Modules - Array to receive module info
//    MaxModules - Maximum entries in array
//    ModuleCount - Receives actual count
//
// Return Value:
//    STATUS_SUCCESS if successful
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ImageNotifyQueryProcessModules(
    _In_ HANDLE ProcessId,
    _Out_writes_to_(MaxModules, *ModuleCount) PIMG_LOAD_EVENT Modules,
    _In_ ULONG MaxModules,
    _Out_ PULONG ModuleCount
    );

//
// Routine Description:
//    Checks if a module is loaded in a process.
//
// Arguments:
//    ProcessId - Target process ID
//    ModuleName - Module name to check
//    ImageBase - Receives base address if found
//
// Return Value:
//    TRUE if module is loaded
//
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
ImageNotifyIsModuleLoaded(
    _In_ HANDLE ProcessId,
    _In_ PUNICODE_STRING ModuleName,
    _Out_opt_ PPVOID ImageBase
    );

#ifdef __cplusplus
}
#endif
