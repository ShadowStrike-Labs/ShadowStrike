/**
 * ============================================================================
 * ShadowStrike NGAV - MEMORY MONITORING TYPES
 * ============================================================================
 *
 * @file MemoryTypes.h
 * @brief Memory monitoring data structures for kernel<->user communication.
 *
 * This file defines all data structures used for memory monitoring,
 * shellcode detection, code injection detection, and VAD tracking
 * between the kernel driver and user-mode analysis engine.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef MEMORY_TYPES_H
#define MEMORY_TYPES_H


#ifdef _KERNEL_MODE
    #include <fltKernel.h>
#else
    #include <windows.h>
#endif

#include "SharedDefs.h"

// ============================================================================
// MEMORY OPERATION TYPES
// ============================================================================

/**
 * @brief Memory operation types for monitoring.
 */
typedef enum _MEMORY_OPERATION_TYPE {
    MemoryOp_None = 0,
    
    // Allocation operations
    MemoryOp_Allocate,                    // VirtualAlloc/NtAllocateVirtualMemory
    MemoryOp_AllocateEx,                  // VirtualAllocEx (cross-process)
    MemoryOp_Free,                        // VirtualFree/NtFreeVirtualMemory
    
    // Protection operations
    MemoryOp_ProtectChange,               // VirtualProtect/NtProtectVirtualMemory
    MemoryOp_ProtectChangeEx,             // Cross-process protection change
    
    // Section operations
    MemoryOp_SectionCreate,               // NtCreateSection
    MemoryOp_SectionMap,                  // NtMapViewOfSection
    MemoryOp_SectionUnmap,                // NtUnmapViewOfSection
    
    // Read/Write operations
    MemoryOp_Read,                        // NtReadVirtualMemory
    MemoryOp_Write,                       // NtWriteVirtualMemory
    MemoryOp_Copy,                        // MmCopyVirtualMemory (kernel)
    
    // Working set operations
    MemoryOp_Lock,                        // VirtualLock
    MemoryOp_Unlock,                      // VirtualUnlock
    
    // Query operations
    MemoryOp_Query,                       // VirtualQuery
    
    MemoryOp_Max
} MEMORY_OPERATION_TYPE;

/**
 * @brief Memory region types.
 */
typedef enum _MEMORY_REGION_TYPE {
    MemRegion_Unknown = 0,
    MemRegion_Image,                      // MEM_IMAGE (DLL/EXE)
    MemRegion_Private,                    // MEM_PRIVATE (heap/stack)
    MemRegion_Mapped,                     // MEM_MAPPED (file mapping)
    MemRegion_Stack,                      // Thread stack
    MemRegion_Heap,                       // Process heap
    MemRegion_PEB,                        // Process Environment Block
    MemRegion_TEB,                        // Thread Environment Block
    MemRegion_CFG,                        // Control Flow Guard
    MemRegion_Max
} MEMORY_REGION_TYPE;

/**
 * @brief Shellcode detection types.
 */
typedef enum _SHELLCODE_TYPE {
    Shellcode_None = 0,
    Shellcode_Generic,                    // Generic shellcode patterns
    Shellcode_Egghunter,                  // Egg hunter shellcode
    Shellcode_Stager,                     // Multi-stage loader
    Shellcode_Meterpreter,                // Metasploit payload
    Shellcode_CobaltStrike,               // Cobalt Strike beacon
    Shellcode_Syscall,                    // Direct syscall stub
    Shellcode_APIHash,                    // API hashing resolution
    Shellcode_Encoder,                    // Encoded shellcode
    Shellcode_Polymorphic,                // Polymorphic shellcode
    Shellcode_HeapSpray,                  // Heap spray payload
    Shellcode_ROP,                        // ROP chain
    Shellcode_JOP,                        // JOP chain
    Shellcode_Custom,                     // Unknown custom shellcode
    Shellcode_Max
} SHELLCODE_TYPE;

/**
 * @brief Code injection detection types.
 */
typedef enum _INJECTION_TYPE {
    Injection_None = 0,
    Injection_ClassicDLL,                 // LoadLibrary injection
    Injection_ReflectiveDLL,              // Reflective DLL loading
    Injection_ProcessHollowing,           // Process hollowing
    Injection_ProcessDoppelganging,       // Process doppelganging
    Injection_AtomBombing,                // Atom table injection
    Injection_EarlyBird,                  // Early bird APC injection
    Injection_ThreadHijack,               // Thread execution hijack
    Injection_APCInjection,               // QueueUserAPC injection
    Injection_NtMapViewInjection,         // NtMapViewOfSection injection
    Injection_SetWindowsHookEx,           // Hook-based injection
    Injection_GhostWriting,               // Ghost writing technique
    Injection_ModuleStomping,             // Module stomping/overwriting
    Injection_Transacted,                 // Transacted section (TxF)
    Injection_PROPagate,                  // Window subclassing
    Injection_ListPlanting,               // List entry hijacking
    Injection_Max
} INJECTION_TYPE;

// ============================================================================
// MEMORY PROTECTION FLAGS (Extended)
// ============================================================================

// Standard Windows protection flags for reference
#define SS_PAGE_NOACCESS          0x01
#define SS_PAGE_READONLY          0x02
#define SS_PAGE_READWRITE         0x04
#define SS_PAGE_WRITECOPY         0x08
#define SS_PAGE_EXECUTE           0x10
#define SS_PAGE_EXECUTE_READ      0x20
#define SS_PAGE_EXECUTE_READWRITE 0x40
#define SS_PAGE_EXECUTE_WRITECOPY 0x80
#define SS_PAGE_GUARD             0x100
#define SS_PAGE_NOCACHE           0x200
#define SS_PAGE_WRITECOMBINE      0x400

// Check macros
#define SS_IS_EXECUTABLE(prot) \
    (((prot) & (SS_PAGE_EXECUTE | SS_PAGE_EXECUTE_READ | \
                SS_PAGE_EXECUTE_READWRITE | SS_PAGE_EXECUTE_WRITECOPY)) != 0)

#define SS_IS_WRITABLE(prot) \
    (((prot) & (SS_PAGE_READWRITE | SS_PAGE_WRITECOPY | \
                SS_PAGE_EXECUTE_READWRITE | SS_PAGE_EXECUTE_WRITECOPY)) != 0)

#define SS_IS_RWX(prot) \
    (((prot) & SS_PAGE_EXECUTE_READWRITE) != 0)

// ============================================================================
// MEMORY EVENT STRUCTURES
// ============================================================================

#pragma pack(push, 1)

/**
 * @brief Memory allocation event.
 */
typedef struct _MEMORY_ALLOC_EVENT {
    // Header
    UINT32 Size;                          // Structure size
    UINT32 Version;                       // Structure version
    UINT64 Timestamp;                     // Event timestamp
    UINT64 MessageId;                     // Unique message ID
    
    // Process info
    UINT32 ProcessId;
    UINT32 ThreadId;
    UINT32 ParentProcessId;
    UINT32 SessionId;
    
    // Allocation details
    MEMORY_OPERATION_TYPE Operation;
    UINT64 BaseAddress;                   // Requested or returned base
    UINT64 RegionSize;                    // Requested or returned size
    UINT32 AllocationType;                // MEM_COMMIT, MEM_RESERVE, etc.
    UINT32 Protection;                    // PAGE_* protection
    
    // Cross-process info (if applicable)
    UINT32 TargetProcessId;               // Target process for Ex operations
    UINT32 Flags;
    
    // Analysis results
    UINT32 ThreatScore;                   // 0-1000
    UINT32 DetectionFlags;
    
    // Process info
    WCHAR ProcessImagePath[MAX_FILE_PATH_LENGTH];
} MEMORY_ALLOC_EVENT, *PMEMORY_ALLOC_EVENT;

// Detection flags for memory allocation
#define MEMALLOC_FLAG_RWX_INITIAL         0x00000001  // RWX from start
#define MEMALLOC_FLAG_LARGE_SIZE          0x00000002  // Unusually large
#define MEMALLOC_FLAG_UNBACKED            0x00000004  // No file backing
#define MEMALLOC_FLAG_CROSS_PROCESS       0x00000008  // Cross-process alloc
#define MEMALLOC_FLAG_IN_KNOWN_REGION     0x00000010  // In suspicious region
#define MEMALLOC_FLAG_NEAR_NTDLL          0x00000020  // Near ntdll.dll
#define MEMALLOC_FLAG_STACK_REGION        0x00000040  // Stack-like allocation
#define MEMALLOC_FLAG_HIGH_ENTROPY_AFTER  0x00000080  // High entropy content after
#define MEMALLOC_FLAG_FOLLOWS_PATTERN     0x00000100  // Follows shellcode alloc pattern

/**
 * @brief Memory protection change event.
 */
typedef struct _MEMORY_PROTECT_EVENT {
    // Header
    UINT32 Size;
    UINT32 Version;
    UINT64 Timestamp;
    UINT64 MessageId;
    
    // Process info
    UINT32 ProcessId;
    UINT32 ThreadId;
    UINT32 ParentProcessId;
    UINT32 SessionId;
    
    // Protection change details
    MEMORY_OPERATION_TYPE Operation;
    UINT64 BaseAddress;
    UINT64 RegionSize;
    UINT32 OldProtection;
    UINT32 NewProtection;
    
    // Cross-process info
    UINT32 TargetProcessId;
    UINT32 Flags;
    
    // Region context
    MEMORY_REGION_TYPE RegionType;
    UINT64 AllocationBase;                // Start of allocation
    UINT64 AllocationSize;                // Full allocation size
    
    // Analysis results
    UINT32 ThreatScore;
    UINT32 DetectionFlags;
    
    // Backing info
    WCHAR MappedFileName[MAX_FILE_PATH_LENGTH];
    WCHAR ProcessImagePath[MAX_FILE_PATH_LENGTH];
} MEMORY_PROTECT_EVENT, *PMEMORY_PROTECT_EVENT;

// Detection flags for protection change
#define MEMPROT_FLAG_RW_TO_RX             0x00000001  // Classic unpacking
#define MEMPROT_FLAG_RW_TO_RWX            0x00000002  // Dynamic code
#define MEMPROT_FLAG_UNBACKED_TO_EXEC     0x00000004  // Shellcode execution
#define MEMPROT_FLAG_CROSS_PROCESS        0x00000008  // Cross-process change
#define MEMPROT_FLAG_NTDLL_REGION         0x00000010  // ntdll.dll region
#define MEMPROT_FLAG_KERNEL32_REGION      0x00000020  // kernel32.dll region
#define MEMPROT_FLAG_CFG_BYPASS           0x00000040  // CFG may be bypassed
#define MEMPROT_FLAG_DEP_BYPASS           0x00000080  // DEP bypass attempt
#define MEMPROT_FLAG_IMAGE_SECTION        0x00000100  // Modifying loaded image
#define MEMPROT_FLAG_MULTIPLE_RAPID       0x00000200  // Multiple rapid changes

/**
 * @brief Memory read/write event (cross-process).
 */
typedef struct _MEMORY_ACCESS_EVENT {
    // Header
    UINT32 Size;
    UINT32 Version;
    UINT64 Timestamp;
    UINT64 MessageId;
    
    // Source process
    UINT32 SourceProcessId;
    UINT32 SourceThreadId;
    UINT32 SourceParentPid;
    UINT32 SourceSessionId;
    
    // Target process
    UINT32 TargetProcessId;
    UINT32 TargetSessionId;
    
    // Access details
    MEMORY_OPERATION_TYPE Operation;      // Read or Write
    UINT64 TargetAddress;                 // Address in target
    UINT64 Size_;                         // Bytes read/written
    UINT64 SourceBuffer;                  // Buffer in source (for writes)
    
    // Analysis
    UINT32 ThreatScore;
    UINT32 DetectionFlags;
    
    // Content analysis (writes only)
    UINT8 ContentHash[32];                // SHA-256 of content (limited)
    UINT32 ContentEntropy;                // Entropy * 1000 (0-8000)
    SHELLCODE_TYPE ShellcodeType;         // If shellcode detected
    UINT32 Reserved;
    
    // Paths
    WCHAR SourceProcessPath[MAX_FILE_PATH_LENGTH];
    WCHAR TargetProcessPath[MAX_FILE_PATH_LENGTH];
} MEMORY_ACCESS_EVENT, *PMEMORY_ACCESS_EVENT;

// Detection flags for memory access
#define MEMACCESS_FLAG_LSASS_TARGET       0x00000001  // Accessing LSASS
#define MEMACCESS_FLAG_CSRSS_TARGET       0x00000002  // Accessing CSRSS
#define MEMACCESS_FLAG_SYSTEM_TARGET      0x00000004  // Accessing System process
#define MEMACCESS_FLAG_AV_TARGET          0x00000008  // Accessing AV process
#define MEMACCESS_FLAG_WRITE_EXEC         0x00000010  // Writing to executable region
#define MEMACCESS_FLAG_WRITE_NTDLL        0x00000020  // Writing to ntdll
#define MEMACCESS_FLAG_SHELLCODE_CONTENT  0x00000040  // Content looks like shellcode
#define MEMACCESS_FLAG_HIGH_ENTROPY       0x00000080  // High entropy content
#define MEMACCESS_FLAG_PE_HEADER          0x00000100  // PE header in content
#define MEMACCESS_FLAG_CREDENTIAL_READ    0x00000200  // Credential-related read

/**
 * @brief Section create/map event.
 */
typedef struct _MEMORY_SECTION_EVENT {
    // Header
    UINT32 Size;
    UINT32 Version;
    UINT64 Timestamp;
    UINT64 MessageId;
    
    // Process info
    UINT32 ProcessId;
    UINT32 ThreadId;
    UINT32 ParentProcessId;
    UINT32 SessionId;
    
    // Section details
    MEMORY_OPERATION_TYPE Operation;
    UINT64 SectionHandle;                 // Section object handle
    UINT64 BaseAddress;                   // Mapped base (for map operations)
    UINT64 ViewSize;                      // Mapped size
    UINT32 SectionAttributes;             // SEC_* attributes
    UINT32 PageProtection;                // Initial protection
    UINT64 AllocationAttributes;          // Allocation attributes
    
    // Cross-process (for NtMapViewOfSection with target)
    UINT32 TargetProcessId;
    UINT32 InheritDisposition;
    
    // File backing (if applicable)
    UINT64 FileSize;
    UINT64 FileObject;                    // Kernel file object ptr
    UINT32 Flags;
    UINT32 DetectionFlags;
    
    // Analysis
    UINT32 ThreatScore;
    INJECTION_TYPE InjectionType;         // If injection detected
    
    WCHAR ProcessImagePath[MAX_FILE_PATH_LENGTH];
    WCHAR BackingFilePath[MAX_FILE_PATH_LENGTH];
} MEMORY_SECTION_EVENT, *PMEMORY_SECTION_EVENT;

// Section detection flags
#define SECTION_FLAG_NO_BACKING           0x00000001  // No file backing
#define SECTION_FLAG_SEC_IMAGE            0x00000002  // Image section
#define SECTION_FLAG_SEC_COMMIT           0x00000004  // Commit immediately
#define SECTION_FLAG_CROSS_PROCESS        0x00000008  // Cross-process map
#define SECTION_FLAG_TRANSACTED           0x00000010  // TxF transaction
#define SECTION_FLAG_LARGE_PAGES          0x00000020  // Large pages
#define SECTION_FLAG_PHYSICAL             0x00000040  // Physical memory
#define SECTION_FLAG_INHERIT_HANDLE       0x00000080  // Inheritable handle
#define SECTION_FLAG_SUSPICIOUS_SIZE      0x00000100  // Suspicious size
#define SECTION_FLAG_HOLLOWING_PATTERN    0x00000200  // Hollowing pattern

// ============================================================================
// SHELLCODE DETECTION STRUCTURES
// ============================================================================

/**
 * @brief Shellcode pattern match.
 */
typedef struct _SHELLCODE_PATTERN_MATCH {
    SHELLCODE_TYPE Type;
    UINT32 Confidence;                    // 0-100
    UINT32 PatternId;                     // Internal pattern ID
    UINT32 Offset;                        // Offset in region
    UINT32 Size;                          // Pattern size
    WCHAR PatternName[64];                // Human-readable name
} SHELLCODE_PATTERN_MATCH, *PSHELLCODE_PATTERN_MATCH;

/**
 * @brief Shellcode detection event.
 */
typedef struct _SHELLCODE_DETECTION_EVENT {
    // Header
    UINT32 Size;
    UINT32 Version;
    UINT64 Timestamp;
    UINT64 MessageId;
    
    // Process info
    UINT32 ProcessId;
    UINT32 ThreadId;
    UINT32 ParentProcessId;
    UINT32 SessionId;
    
    // Detection location
    UINT64 DetectionAddress;
    UINT64 RegionBase;
    UINT64 RegionSize;
    UINT32 RegionProtection;
    MEMORY_REGION_TYPE RegionType;
    
    // Detection details
    SHELLCODE_TYPE PrimaryType;
    UINT32 TotalPatternMatches;
    UINT32 ThreatScore;
    UINT32 Confidence;
    
    // Analysis results
    UINT32 Entropy;                       // Entropy * 1000
    UINT32 Flags;
    BOOLEAN HasNopSled;
    BOOLEAN HasAPIHashing;
    BOOLEAN HasSyscallStub;
    BOOLEAN HasEncoderStub;
    BOOLEAN IsPolymorphic;
    BOOLEAN HasStackPivot;
    UINT8 Reserved[2];
    
    // Content sample
    UINT8 ContentSample[256];             // First 256 bytes
    UINT8 ContentHash[32];                // SHA-256 of full region
    
    // Pattern matches (first 8)
    UINT32 MatchCount;
    SHELLCODE_PATTERN_MATCH Matches[8];
    
    WCHAR ProcessImagePath[MAX_FILE_PATH_LENGTH];
} SHELLCODE_DETECTION_EVENT, *PSHELLCODE_DETECTION_EVENT;

// Shellcode detection flags
#define SHELLCODE_FLAG_UNBACKED_EXEC      0x00000001  // Unbacked executable
#define SHELLCODE_FLAG_RECENTLY_WRITTEN   0x00000002  // Recently written
#define SHELLCODE_FLAG_RECENTLY_RWX       0x00000004  // Recently made RWX
#define SHELLCODE_FLAG_HEAP_REGION        0x00000008  // In heap
#define SHELLCODE_FLAG_STACK_REGION       0x00000010  // Near stack
#define SHELLCODE_FLAG_HIGH_ENTROPY       0x00000020  // High entropy
#define SHELLCODE_FLAG_KNOWN_SIGNATURE    0x00000040  // Known malware sig
#define SHELLCODE_FLAG_METAMORPHIC        0x00000080  // Metamorphic code
#define SHELLCODE_FLAG_POSITION_INDEP     0x00000100  // Position independent
#define SHELLCODE_FLAG_MULTI_STAGE        0x00000200  // Multi-stage loader

// ============================================================================
// CODE INJECTION DETECTION STRUCTURES
// ============================================================================

/**
 * @brief Injection indicator structure.
 */
typedef struct _INJECTION_INDICATOR {
    UINT32 Type;                          // Indicator type
    UINT32 Weight;                        // Weight in scoring
    UINT32 Confidence;                    // 0-100
    UINT32 Reserved;
    WCHAR Description[128];
} INJECTION_INDICATOR, *PINJECTION_INDICATOR;

/**
 * @brief Code injection detection event.
 */
typedef struct _INJECTION_DETECTION_EVENT {
    // Header
    UINT32 Size;
    UINT32 Version;
    UINT64 Timestamp;
    UINT64 MessageId;
    
    // Source process (attacker)
    UINT32 SourceProcessId;
    UINT32 SourceThreadId;
    UINT32 SourceParentPid;
    UINT32 SourceSessionId;
    UINT64 SourceImageBase;
    
    // Target process (victim)
    UINT32 TargetProcessId;
    UINT32 TargetThreadId;
    UINT32 TargetParentPid;
    UINT32 TargetSessionId;
    UINT64 TargetImageBase;
    
    // Injection details
    INJECTION_TYPE InjectionType;
    UINT64 InjectedAddress;               // Where code was injected
    UINT64 InjectedSize;
    UINT32 InjectedProtection;
    UINT32 Flags;
    
    // Thread info (if thread-based)
    UINT32 CreatedThreadId;               // New thread ID (remote thread)
    UINT32 HijackedThreadId;              // Hijacked thread ID
    UINT64 ThreadStartAddress;            // Thread start address
    UINT64 ThreadParameter;               // Thread parameter
    
    // APC info (if APC-based)
    UINT64 APCRoutine;
    UINT64 APCArgument1;
    UINT64 APCArgument2;
    UINT64 APCArgument3;
    
    // Analysis
    UINT32 ThreatScore;
    UINT32 Confidence;
    UINT32 IndicatorCount;
    UINT32 Reserved2;
    
    // Content analysis
    UINT8 InjectedCodeHash[32];
    SHELLCODE_TYPE DetectedShellcode;
    UINT32 Entropy;
    
    // Indicators (first 8)
    INJECTION_INDICATOR Indicators[8];
    
    // Paths
    WCHAR SourceProcessPath[MAX_FILE_PATH_LENGTH];
    WCHAR TargetProcessPath[MAX_FILE_PATH_LENGTH];
    WCHAR InjectedModulePath[MAX_FILE_PATH_LENGTH];  // If DLL injection
} INJECTION_DETECTION_EVENT, *PINJECTION_DETECTION_EVENT;

// Injection detection flags
#define INJECTION_FLAG_CROSS_SESSION      0x00000001  // Cross-session injection
#define INJECTION_FLAG_ELEVATED_SOURCE    0x00000002  // Source is elevated
#define INJECTION_FLAG_SYSTEM_TARGET      0x00000004  // Target is system process
#define INJECTION_FLAG_AV_TARGET          0x00000008  // Target is AV process
#define INJECTION_FLAG_UNSIGNED_SOURCE    0x00000010  // Source is unsigned
#define INJECTION_FLAG_BLOCKED            0x00000020  // Injection was blocked
#define INJECTION_FLAG_THREAD_CREATED     0x00000040  // New thread created
#define INJECTION_FLAG_THREAD_HIJACKED    0x00000080  // Thread was hijacked
#define INJECTION_FLAG_APC_QUEUED         0x00000100  // APC was queued
#define INJECTION_FLAG_SECTION_MAPPED     0x00000200  // Section was mapped
#define INJECTION_FLAG_CODE_CAVE          0x00000400  // Code cave used

// ============================================================================
// VAD (Virtual Address Descriptor) TRACKING
// ============================================================================

/**
 * @brief VAD entry for process memory map.
 */
typedef struct _VAD_ENTRY {
    UINT64 StartVpn;                      // Start virtual page number
    UINT64 EndVpn;                        // End virtual page number
    UINT64 BaseAddress;                   // Base address
    UINT64 Size;                          // Region size
    UINT32 Protection;                    // Page protection
    UINT32 VadType;                       // VAD type flags
    MEMORY_REGION_TYPE RegionType;
    UINT32 Flags;
    UINT64 FileObject;                    // Backing file object
    WCHAR FileName[MAX_FILE_PATH_LENGTH]; // Backing file name
} VAD_ENTRY, *PVAD_ENTRY;

/**
 * @brief Process VAD map summary.
 */
typedef struct _PROCESS_VAD_MAP {
    UINT32 ProcessId;
    UINT32 VadCount;
    UINT64 TotalVirtualSize;
    UINT64 TotalCommittedSize;
    UINT64 TotalExecutableSize;
    UINT64 TotalWritableSize;
    UINT64 TotalRWXSize;
    UINT32 UnbackedExecutableCount;       // Suspicious regions
    UINT32 Flags;
    // Variable: VAD_ENTRY entries follow
} PROCESS_VAD_MAP, *PPROCESS_VAD_MAP;

// VAD flags
#define VAD_FLAG_EXECUTABLE               0x00000001
#define VAD_FLAG_WRITABLE                 0x00000002
#define VAD_FLAG_RWX                      0x00000004
#define VAD_FLAG_UNBACKED                 0x00000008
#define VAD_FLAG_PRIVATE                  0x00000010
#define VAD_FLAG_MAPPED                   0x00000020
#define VAD_FLAG_IMAGE                    0x00000040
#define VAD_FLAG_MODIFIED                 0x00000080  // Recently modified
#define VAD_FLAG_SUSPICIOUS               0x00000100  // Flagged suspicious

// ============================================================================
// PROCESS HOLLOWING DETECTION
// ============================================================================

/**
 * @brief Process hollowing indicator.
 */
typedef struct _HOLLOWING_INDICATOR {
    UINT32 Type;                          // HOLLOWING_INDICATOR_TYPE
    UINT32 Confidence;                    // 0-100
    UINT64 Value1;                        // Type-specific value
    UINT64 Value2;                        // Type-specific value
    WCHAR Description[128];
} HOLLOWING_INDICATOR, *PHOLLOWING_INDICATOR;

// Hollowing indicator types
typedef enum _HOLLOWING_INDICATOR_TYPE {
    HollowingInd_None = 0,
    HollowingInd_ImagePathMismatch,       // PEB path != section path
    HollowingInd_SectionBaseMismatch,     // Section base != image base
    HollowingInd_EntryPointOutside,       // Entry point outside image
    HollowingInd_UnmappedPrimaryModule,   // Primary module unmapped
    HollowingInd_SuspiciousVAD,           // Suspicious VAD structure
    HollowingInd_ModifiedPEB,             // PEB tampering
    HollowingInd_TransactedSection,       // TxF transaction used
    HollowingInd_SuspiciousParentChild,   // Suspicious parent-child
    HollowingInd_CommandLineMismatch,     // Command line doesn't match
    HollowingInd_HeaderMismatch,          // PE header mismatch
    HollowingInd_Max
} HOLLOWING_INDICATOR_TYPE;

/**
 * @brief Process hollowing detection event.
 */
typedef struct _HOLLOWING_DETECTION_EVENT {
    // Header
    UINT32 Size;
    UINT32 Version;
    UINT64 Timestamp;
    UINT64 MessageId;
    
    // Hollow process info
    UINT32 HollowedProcessId;
    UINT32 HollowedThreadId;
    UINT32 ParentProcessId;
    UINT32 SessionId;
    
    // Detection point
    UINT32 DetectionPhase;                // DETECTION_PHASE
    UINT32 Flags;
    
    // Image analysis
    UINT64 ClaimedImageBase;              // What PEB says
    UINT64 ActualImageBase;               // What's actually there
    UINT64 ClaimedImageSize;
    UINT64 ActualImageSize;
    UINT64 ClaimedEntryPoint;
    UINT64 ActualEntryPoint;
    
    // Section analysis
    UINT64 SectionObject;
    UINT64 SectionBase;
    UINT64 SectionSize;
    UINT32 SectionFlags;
    UINT32 Reserved;
    
    // Analysis
    UINT32 ThreatScore;
    UINT32 Confidence;
    UINT32 IndicatorCount;
    INJECTION_TYPE TechniqueType;
    
    // Indicators (first 8)
    HOLLOWING_INDICATOR Indicators[8];
    
    // Paths
    WCHAR ClaimedImagePath[MAX_FILE_PATH_LENGTH];
    WCHAR ActualImagePath[MAX_FILE_PATH_LENGTH];
    WCHAR ParentImagePath[MAX_FILE_PATH_LENGTH];
    WCHAR CommandLine[MAX_COMMAND_LINE_LENGTH];
} HOLLOWING_DETECTION_EVENT, *PHOLLOWING_DETECTION_EVENT;

// Detection phases
typedef enum _DETECTION_PHASE {
    DetectionPhase_ProcessCreate = 0,     // At process creation
    DetectionPhase_ThreadCreate,          // At first thread creation
    DetectionPhase_ImageLoad,             // At image load callback
    DetectionPhase_Execution,             // At first execution
    DetectionPhase_Periodic,              // Periodic scan
    DetectionPhase_Max
} DETECTION_PHASE;

// Hollowing detection flags
#define HOLLOWING_FLAG_BLOCKED            0x00000001  // Execution blocked
#define HOLLOWING_FLAG_CONFIRMED          0x00000002  // Confirmed hollowing
#define HOLLOWING_FLAG_DOPPELGANGING      0x00000004  // Doppelganging variant
#define HOLLOWING_FLAG_HERPADERPING       0x00000008  // Herpaderping variant
#define HOLLOWING_FLAG_GHOSTING           0x00000010  // Ghosting variant
#define HOLLOWING_FLAG_TRANSACTED         0x00000020  // Used TxF
#define HOLLOWING_FLAG_SUSPENDED_CREATE   0x00000040  // Created suspended

#pragma pack(pop)

// ============================================================================
// MEMORY MONITORING CONFIGURATION
// ============================================================================

/**
 * @brief Memory monitoring configuration.
 */
typedef struct _MEMORY_MONITOR_CONFIG {
    BOOLEAN EnableAllocationMonitoring;
    BOOLEAN EnableProtectionMonitoring;
    BOOLEAN EnableCrossProcessMonitoring;
    BOOLEAN EnableSectionMonitoring;
    BOOLEAN EnableShellcodeDetection;
    BOOLEAN EnableInjectionDetection;
    BOOLEAN EnableHollowingDetection;
    BOOLEAN EnableVADTracking;
    
    UINT32 MinAllocationSizeToTrack;      // Minimum size (bytes)
    UINT32 MaxEventsPerSecond;            // Rate limiting
    UINT32 ShellcodeScanThreshold;        // Entropy threshold
    UINT32 MaxRegionSizeToScan;           // Max region to scan for shellcode
    
    UINT32 Flags;
    UINT32 Reserved[4];
} MEMORY_MONITOR_CONFIG, *PMEMORY_MONITOR_CONFIG;

// ============================================================================
// HELPER MACROS
// ============================================================================

#define MEMORY_EVENT_SIZE(type) sizeof(type)

#define IS_SUSPICIOUS_PROTECTION_CHANGE(old, new) \
    (!SS_IS_EXECUTABLE(old) && SS_IS_EXECUTABLE(new) && SS_IS_WRITABLE(old))

#define IS_CROSS_PROCESS_EVENT(event) \
    ((event)->TargetProcessId != 0 && (event)->TargetProcessId != (event)->ProcessId)

#endif // SHADOWSTRIKE_MEMORY_TYPES_H
