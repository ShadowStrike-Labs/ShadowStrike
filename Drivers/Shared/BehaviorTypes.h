/**
 * ============================================================================
 * ShadowStrike NGAV - BEHAVIORAL DETECTION TYPES
 * ============================================================================
 *
 * @file BehaviorTypes.h
 * @brief Behavioral detection data structures for kernel<->user communication.
 *
 * This file defines all data structures used for behavioral analysis,
 * attack chain tracking, and threat scoring between the kernel driver
 * and user-mode behavioral engine.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#pragma once

#ifdef _KERNEL_MODE
    #include <fltKernel.h>
#else
    #include <windows.h>
#endif

#include "SharedDefs.h"

// ============================================================================
// BEHAVIORAL EVENT TYPES
// ============================================================================

/**
 * @brief Categories of behavioral events.
 */
typedef enum _BEHAVIOR_EVENT_CATEGORY {
    BehaviorCategory_None = 0,
    BehaviorCategory_ProcessExecution,
    BehaviorCategory_CodeInjection,
    BehaviorCategory_MemoryOperation,
    BehaviorCategory_FileOperation,
    BehaviorCategory_RegistryOperation,
    BehaviorCategory_NetworkOperation,
    BehaviorCategory_PrivilegeOperation,
    BehaviorCategory_PersistenceOperation,
    BehaviorCategory_CredentialAccess,
    BehaviorCategory_Discovery,
    BehaviorCategory_LateralMovement,
    BehaviorCategory_Collection,
    BehaviorCategory_Exfiltration,
    BehaviorCategory_Impact,
    BehaviorCategory_DefenseEvasion,
    BehaviorCategory_Max
} BEHAVIOR_EVENT_CATEGORY;

/**
 * @brief Specific behavioral event types.
 */
typedef enum _BEHAVIOR_EVENT_TYPE {
    // Process Execution (0x0000 - 0x00FF)
    BehaviorEvent_ProcessCreate                 = 0x0001,
    BehaviorEvent_ProcessTerminate              = 0x0002,
    BehaviorEvent_ChildProcessSpawn             = 0x0003,
    BehaviorEvent_CommandLineExecution          = 0x0004,
    BehaviorEvent_ScriptExecution               = 0x0005,
    BehaviorEvent_PowerShellExecution           = 0x0006,
    BehaviorEvent_WMIExecution                  = 0x0007,
    BehaviorEvent_ScheduledTaskCreate           = 0x0008,
    BehaviorEvent_ServiceCreate                 = 0x0009,
    BehaviorEvent_DriverLoad                    = 0x000A,
    BehaviorEvent_SuspiciousParentChild         = 0x000B,
    BehaviorEvent_LOLBinExecution               = 0x000C,  // Living-off-the-land

    // Code Injection (0x0100 - 0x01FF)
    BehaviorEvent_RemoteThreadCreate            = 0x0100,
    BehaviorEvent_APCQueueInjection             = 0x0101,
    BehaviorEvent_ProcessHollowing              = 0x0102,
    BehaviorEvent_ProcessDoppelganging          = 0x0103,
    BehaviorEvent_AtomBombing                   = 0x0104,
    BehaviorEvent_ModuleStomping                = 0x0105,
    BehaviorEvent_ReflectiveDLLLoad             = 0x0106,
    BehaviorEvent_EarlyBirdInjection            = 0x0107,
    BehaviorEvent_ThreadExecutionHijack         = 0x0108,
    BehaviorEvent_NtMapViewInjection            = 0x0109,
    BehaviorEvent_SetWindowsHookEx              = 0x010A,
    BehaviorEvent_QueueUserAPC                  = 0x010B,
    BehaviorEvent_CallbackInjection             = 0x010C,
    BehaviorEvent_ContextHijacking              = 0x010D,

    // Memory Operations (0x0200 - 0x02FF)
    BehaviorEvent_SuspiciousAllocation          = 0x0200,
    BehaviorEvent_RWXMemory                     = 0x0201,
    BehaviorEvent_MemoryProtectionChange        = 0x0202,
    BehaviorEvent_CrossProcessRead              = 0x0203,
    BehaviorEvent_CrossProcessWrite             = 0x0204,
    BehaviorEvent_UnbackedExecutable            = 0x0205,
    BehaviorEvent_ShellcodeDetected             = 0x0206,
    BehaviorEvent_HeapSprayDetected             = 0x0207,
    BehaviorEvent_ROPChainDetected              = 0x0208,
    BehaviorEvent_StackPivot                    = 0x0209,
    BehaviorEvent_GuardPageViolation            = 0x020A,
    BehaviorEvent_DEPViolation                  = 0x020B,

    // Privilege Operations (0x0300 - 0x03FF)
    BehaviorEvent_PrivilegeEscalation           = 0x0300,
    BehaviorEvent_TokenManipulation             = 0x0301,
    BehaviorEvent_TokenImpersonation            = 0x0302,
    BehaviorEvent_TokenStealing                 = 0x0303,
    BehaviorEvent_IntegrityLevelChange          = 0x0304,
    BehaviorEvent_SIDManipulation               = 0x0305,
    BehaviorEvent_BypassUAC                     = 0x0306,
    BehaviorEvent_ElevationOfPrivilege          = 0x0307,
    BehaviorEvent_SeDebugPrivilege              = 0x0308,

    // Persistence (0x0400 - 0x04FF)
    BehaviorEvent_RegistryRunKey                = 0x0400,
    BehaviorEvent_ScheduledTaskPersistence      = 0x0401,
    BehaviorEvent_ServicePersistence            = 0x0402,
    BehaviorEvent_StartupFolderDrop             = 0x0403,
    BehaviorEvent_WMISubscription               = 0x0404,
    BehaviorEvent_DLLHijacking                  = 0x0405,
    BehaviorEvent_COMHijacking                  = 0x0406,
    BehaviorEvent_BootkitInstall                = 0x0407,
    BehaviorEvent_ImageFilePersistence          = 0x0408,
    BehaviorEvent_BrowserExtensionInstall       = 0x0409,
    BehaviorEvent_OfficeTemplateMod             = 0x040A,
    BehaviorEvent_PrinterDriverInstall          = 0x040B,

    // Defense Evasion (0x0500 - 0x05FF)
    BehaviorEvent_DirectSyscall                 = 0x0500,
    BehaviorEvent_NtdllUnhooking                = 0x0501,
    BehaviorEvent_HeavensGate                   = 0x0502,  // WoW64 abuse
    BehaviorEvent_ETWPatching                   = 0x0503,
    BehaviorEvent_AMSIBypass                    = 0x0504,
    BehaviorEvent_DisableWindowsDefender        = 0x0505,
    BehaviorEvent_DisableFirewall               = 0x0506,
    BehaviorEvent_ProcessMasquerading           = 0x0507,
    BehaviorEvent_TimestampModification         = 0x0508,
    BehaviorEvent_FileSignatureSpoofing         = 0x0509,
    BehaviorEvent_HiddenFileCreation            = 0x050A,
    BehaviorEvent_AlternateDataStream           = 0x050B,
    BehaviorEvent_LogDeletion                   = 0x050C,
    BehaviorEvent_VirtualizationEvasion         = 0x050D,
    BehaviorEvent_DebuggerEvasion               = 0x050E,
    BehaviorEvent_SandboxEvasion                = 0x050F,
    BehaviorEvent_PPLBypass                     = 0x0510,  // Protected Process Light
    BehaviorEvent_CallbackRemoval               = 0x0511,

    // Credential Access (0x0600 - 0x06FF)
    BehaviorEvent_LSASSAccess                   = 0x0600,
    BehaviorEvent_SAMRegistryAccess             = 0x0601,
    BehaviorEvent_NTDSAccess                    = 0x0602,
    BehaviorEvent_CredentialDumping             = 0x0603,
    BehaviorEvent_KeyloggerBehavior             = 0x0604,
    BehaviorEvent_BrowserCredentialAccess       = 0x0605,
    BehaviorEvent_PasswordFileAccess            = 0x0606,
    BehaviorEvent_VaultEnumeration              = 0x0607,
    BehaviorEvent_KerberosTicketAccess          = 0x0608,
    BehaviorEvent_DCSync                        = 0x0609,

    // Network (0x0700 - 0x07FF)
    BehaviorEvent_C2Communication               = 0x0700,
    BehaviorEvent_DNSTunneling                  = 0x0701,
    BehaviorEvent_DGADomain                     = 0x0702,
    BehaviorEvent_Beaconing                     = 0x0703,
    BehaviorEvent_DataExfiltration              = 0x0704,
    BehaviorEvent_LateralMovementNetwork        = 0x0705,
    BehaviorEvent_ProxyConnection               = 0x0706,
    BehaviorEvent_TorConnection                 = 0x0707,
    BehaviorEvent_EncryptedChannel              = 0x0708,
    BehaviorEvent_ReverseShell                  = 0x0709,
    BehaviorEvent_PortScanning                  = 0x070A,

    // Impact (0x0800 - 0x08FF)
    BehaviorEvent_RansomwareBehavior            = 0x0800,
    BehaviorEvent_MassFileEncryption            = 0x0801,
    BehaviorEvent_MassFileDeletion              = 0x0802,
    BehaviorEvent_VSSDestruction                = 0x0803,
    BehaviorEvent_BackupDeletion                = 0x0804,
    BehaviorEvent_DiskWipe                      = 0x0805,
    BehaviorEvent_BootSectorModification        = 0x0806,
    BehaviorEvent_ServiceStopping               = 0x0807,
    BehaviorEvent_DataDestruction               = 0x0808,

    BehaviorEvent_Max                           = 0xFFFF
} BEHAVIOR_EVENT_TYPE;

// ============================================================================
// THREAT SEVERITY LEVELS
// ============================================================================

typedef enum _THREAT_SEVERITY {
    ThreatSeverity_None           = 0,
    ThreatSeverity_Informational  = 1,
    ThreatSeverity_Low            = 2,
    ThreatSeverity_Medium         = 3,
    ThreatSeverity_High           = 4,
    ThreatSeverity_Critical       = 5
} THREAT_SEVERITY;

// ============================================================================
// ATTACK CHAIN STATE
// ============================================================================

/**
 * @brief Attack chain/kill chain stages.
 */
typedef enum _ATTACK_CHAIN_STAGE {
    AttackStage_None              = 0,
    AttackStage_Reconnaissance    = 1,
    AttackStage_Weaponization     = 2,
    AttackStage_Delivery          = 3,
    AttackStage_Exploitation      = 4,
    AttackStage_Installation      = 5,
    AttackStage_CommandControl    = 6,
    AttackStage_Actions           = 7,
    AttackStage_Max
} ATTACK_CHAIN_STAGE;

// ============================================================================
// BEHAVIORAL EVENT STRUCTURES
// ============================================================================

#pragma pack(push, 1)

/**
 * @brief Unique identifier for behavior tracking across events.
 */
typedef struct _BEHAVIOR_CORRELATION_ID {
    UINT64 SessionId;         // Session identifier
    UINT64 SequenceNumber;    // Monotonic sequence
    UINT64 Timestamp;         // Event timestamp (100ns intervals)
    UINT32 ProcessId;         // Originating process
    UINT32 ThreadId;          // Originating thread
} BEHAVIOR_CORRELATION_ID, *PBEHAVIOR_CORRELATION_ID;

/**
 * @brief Base behavioral event header.
 */
typedef struct _BEHAVIOR_EVENT_HEADER {
    UINT32 Size;                          // Total structure size
    UINT16 Version;                       // Structure version
    UINT16 Flags;                         // Event flags
    BEHAVIOR_EVENT_TYPE EventType;        // Specific event type (32-bit)
    BEHAVIOR_EVENT_CATEGORY Category;     // Event category (32-bit)
    BEHAVIOR_CORRELATION_ID CorrelationId; // Correlation info
    THREAT_SEVERITY Severity;             // Threat severity (32-bit)
    UINT32 ThreatScore;                   // 0-1000 threat score
    UINT64 RawTimestamp;                  // FILETIME timestamp
    UINT32 Reserved[2];
} BEHAVIOR_EVENT_HEADER, *PBEHAVIOR_EVENT_HEADER;

// Event header flags
#define BEHAVIOR_FLAG_BLOCKING_EVENT      0x0001  // Event can block operation
#define BEHAVIOR_FLAG_HIGH_CONFIDENCE     0x0002  // High confidence detection
#define BEHAVIOR_FLAG_REQUIRES_RESPONSE   0x0004  // Needs user-mode decision
#define BEHAVIOR_FLAG_CHAIN_MEMBER        0x0008  // Part of attack chain
#define BEHAVIOR_FLAG_IOC_MATCH           0x0010  // Matches known IOC
#define BEHAVIOR_FLAG_RULE_MATCH          0x0020  // Matches behavioral rule
#define BEHAVIOR_FLAG_ANOMALY             0x0040  // Anomaly-based detection
#define BEHAVIOR_FLAG_HEURISTIC           0x0080  // Heuristic detection
#define BEHAVIOR_FLAG_MACHINE_LEARNING    0x0100  // ML-based detection

/**
 * @brief Process context for behavioral events.
 */
typedef struct _BEHAVIOR_PROCESS_CONTEXT {
    UINT32 ProcessId;
    UINT32 ParentProcessId;
    UINT32 SessionId;
    UINT32 TokenElevationType;            // TokenElevationTypeDefault/Full/Limited
    UINT32 IntegrityLevel;                // SECURITY_MANDATORY_*_RID
    UINT32 Flags;
    UINT64 CreateTime;                    // Process create time
    UINT64 ImageBase;                     // Main module base
    UINT64 ImageSize;                     // Main module size
    UINT64 PebAddress;                    // PEB address
    UINT64 UniqueProcessKey;              // Unique identifier across reboots
    WCHAR ImagePath[MAX_FILE_PATH_LENGTH];
    WCHAR CommandLine[MAX_COMMAND_LINE_LENGTH];
    WCHAR UserSid[256];                   // User SID string
} BEHAVIOR_PROCESS_CONTEXT, *PBEHAVIOR_PROCESS_CONTEXT;

// Process context flags
#define PROCESS_FLAG_ELEVATED             0x00000001
#define PROCESS_FLAG_PROTECTED            0x00000002  // PPL
#define PROCESS_FLAG_SYSTEM               0x00000004
#define PROCESS_FLAG_WOW64                0x00000008
#define PROCESS_FLAG_GUI                  0x00000010
#define PROCESS_FLAG_SERVICE              0x00000020
#define PROCESS_FLAG_NETWORK_SERVICE      0x00000040
#define PROCESS_FLAG_LOCAL_SERVICE        0x00000080
#define PROCESS_FLAG_MICROSOFT_SIGNED     0x00000100
#define PROCESS_FLAG_TRUSTED_SIGNED       0x00000200
#define PROCESS_FLAG_CATALOG_SIGNED       0x00000400
#define PROCESS_FLAG_UNSIGNED             0x00000800
#define PROCESS_FLAG_DEBUGGED             0x00001000
#define PROCESS_FLAG_CONSOLE              0x00002000
#define PROCESS_FLAG_CRITICAL             0x00004000  // System critical
#define PROCESS_FLAG_SANDBOX_CHILD        0x00008000  // Spawned by sandbox

/**
 * @brief Code injection detection event.
 */
typedef struct _BEHAVIOR_INJECTION_EVENT {
    BEHAVIOR_EVENT_HEADER Header;
    BEHAVIOR_PROCESS_CONTEXT SourceProcess;
    BEHAVIOR_PROCESS_CONTEXT TargetProcess;
    UINT64 SourceAddress;                 // Source memory address
    UINT64 TargetAddress;                 // Target memory address
    UINT64 Size;                          // Injection size
    UINT32 Protection;                    // Memory protection
    UINT32 InjectionMethod;               // Detected injection technique
    UINT32 ThreadId;                      // Created/hijacked thread ID
    UINT32 Reserved;
    UINT8 InjectedCodeHash[32];           // SHA-256 of injected code
    WCHAR ModuleName[MAX_PROCESS_NAME_LENGTH];  // If module-based
} BEHAVIOR_INJECTION_EVENT, *PBEHAVIOR_INJECTION_EVENT;

// Injection methods
#define INJECTION_METHOD_UNKNOWN                0
#define INJECTION_METHOD_REMOTE_THREAD          1
#define INJECTION_METHOD_APC_INJECTION          2
#define INJECTION_METHOD_THREAD_HIJACK          3
#define INJECTION_METHOD_PROCESS_HOLLOWING      4
#define INJECTION_METHOD_PROCESS_DOPPELGANGING  5
#define INJECTION_METHOD_ATOM_BOMBING           6
#define INJECTION_METHOD_MODULE_STOMPING        7
#define INJECTION_METHOD_REFLECTIVE_DLL         8
#define INJECTION_METHOD_EARLY_BIRD             9
#define INJECTION_METHOD_SECTION_MAP            10
#define INJECTION_METHOD_WINDOWS_HOOK           11
#define INJECTION_METHOD_CALLBACK               12
#define INJECTION_METHOD_CONTEXT_HIJACK         13

/**
 * @brief Memory operation event.
 */
typedef struct _BEHAVIOR_MEMORY_EVENT {
    BEHAVIOR_EVENT_HEADER Header;
    BEHAVIOR_PROCESS_CONTEXT Process;
    UINT64 BaseAddress;
    UINT64 RegionSize;
    UINT32 AllocationType;                // MEM_COMMIT, MEM_RESERVE, etc.
    UINT32 OldProtection;
    UINT32 NewProtection;
    UINT32 State;                         // MEM_COMMIT, MEM_FREE, etc.
    UINT32 Type;                          // MEM_PRIVATE, MEM_MAPPED, etc.
    UINT32 Flags;
    BOOLEAN IsCrossProcess;
    BOOLEAN IsExecutable;
    BOOLEAN IsWritable;
    BOOLEAN IsRWX;
    UINT32 TargetProcessId;               // If cross-process
    UINT8 ContentHash[32];                // SHA-256 of content (if sampled)
    WCHAR MappedFileName[MAX_FILE_PATH_LENGTH];  // If backed by file
} BEHAVIOR_MEMORY_EVENT, *PBEHAVIOR_MEMORY_EVENT;

// Memory event flags
#define MEMORY_FLAG_HIGH_ENTROPY          0x00000001  // Content appears encrypted/packed
#define MEMORY_FLAG_SHELLCODE_PATTERN     0x00000002  // Matches shellcode patterns
#define MEMORY_FLAG_UNBACKED              0x00000004  // Not backed by file
#define MEMORY_FLAG_HEAP_SPRAY            0x00000008  // Heap spray pattern
#define MEMORY_FLAG_ROP_GADGETS           0x00000010  // ROP gadgets detected
#define MEMORY_FLAG_JOP_GADGETS           0x00000020  // JOP gadgets detected
#define MEMORY_FLAG_NOP_SLED              0x00000040  // NOP sled detected
#define MEMORY_FLAG_API_HASHING           0x00000080  // API hashing code
#define MEMORY_FLAG_SYSCALL_STUB          0x00000100  // Direct syscall stub
#define MEMORY_FLAG_PE_HEADER             0x00000200  // PE header in memory

/**
 * @brief Privilege escalation event.
 */
typedef struct _BEHAVIOR_PRIVILEGE_EVENT {
    BEHAVIOR_EVENT_HEADER Header;
    BEHAVIOR_PROCESS_CONTEXT Process;
    UINT32 PrivilegeType;                 // SE_*_PRIVILEGE
    UINT32 OldIntegrityLevel;
    UINT32 NewIntegrityLevel;
    UINT32 AttackType;                    // TOKEN_ATTACK_TYPE
    UINT64 SourceTokenHandle;
    UINT64 TargetTokenHandle;
    UINT32 SourceProcessId;
    UINT32 TargetProcessId;
    WCHAR OldUserSid[256];
    WCHAR NewUserSid[256];
} BEHAVIOR_PRIVILEGE_EVENT, *PBEHAVIOR_PRIVILEGE_EVENT;

// Token attack types
typedef enum _TOKEN_ATTACK_TYPE {
    TokenAttack_None = 0,
    TokenAttack_Impersonation,
    TokenAttack_TokenStealing,
    TokenAttack_PrivilegeEscalation,
    TokenAttack_SIDInjection,
    TokenAttack_IntegrityDowngrade,
    TokenAttack_GroupModification,
    TokenAttack_PrimaryTokenReplace,
    TokenAttack_Max
} TOKEN_ATTACK_TYPE;

/**
 * @brief Defense evasion event.
 */
typedef struct _BEHAVIOR_EVASION_EVENT {
    BEHAVIOR_EVENT_HEADER Header;
    BEHAVIOR_PROCESS_CONTEXT Process;
    UINT32 EvasionTechnique;              // EVASION_TECHNIQUE
    UINT32 TargetComponent;               // What's being evaded
    UINT64 TargetAddress;                 // Address being modified
    UINT64 OriginalValue;                 // Original bytes/value
    UINT64 NewValue;                      // New bytes/value
    UINT32 ModificationSize;
    UINT32 Reserved;
    WCHAR TargetModuleName[MAX_PROCESS_NAME_LENGTH];
    WCHAR TargetFunctionName[256];
} BEHAVIOR_EVASION_EVENT, *PBEHAVIOR_EVASION_EVENT;

// Evasion techniques
typedef enum _EVASION_TECHNIQUE {
    Evasion_None = 0,
    Evasion_DirectSyscall,
    Evasion_NtdllUnhooking,
    Evasion_HeavensGate,
    Evasion_ETWBlinding,
    Evasion_AMSIBypass,
    Evasion_WDDisable,
    Evasion_FirewallDisable,
    Evasion_ProcessMasquerade,
    Evasion_Timestomping,
    Evasion_SignatureSpoofing,
    Evasion_HiddenFile,
    Evasion_ADS,
    Evasion_LogDeletion,
    Evasion_VMEvasion,
    Evasion_DebugEvasion,
    Evasion_SandboxEvasion,
    Evasion_PPLBypass,
    Evasion_CallbackRemoval,
    Evasion_Max
} EVASION_TECHNIQUE;

// Target components
typedef enum _EVASION_TARGET {
    EvasionTarget_None = 0,
    EvasionTarget_ShadowStrike,           // Our product
    EvasionTarget_WindowsDefender,
    EvasionTarget_AMSI,
    EvasionTarget_ETW,
    EvasionTarget_Firewall,
    EvasionTarget_EventLog,
    EvasionTarget_Sysmon,
    EvasionTarget_EDR,                    // Generic EDR
    EvasionTarget_Max
} EVASION_TARGET;

/**
 * @brief Persistence event.
 */
typedef struct _BEHAVIOR_PERSISTENCE_EVENT {
    BEHAVIOR_EVENT_HEADER Header;
    BEHAVIOR_PROCESS_CONTEXT Process;
    UINT32 PersistenceType;               // PERSISTENCE_TYPE
    UINT32 Flags;
    WCHAR TargetPath[MAX_FILE_PATH_LENGTH];      // Registry key or file path
    WCHAR ValueName[MAX_REGISTRY_VALUE_LENGTH];  // Registry value if applicable
    WCHAR PayloadPath[MAX_FILE_PATH_LENGTH];     // Path to persisted payload
    WCHAR CommandLine[MAX_COMMAND_LINE_LENGTH];  // Command to be executed
    UINT8 PayloadHash[32];                       // SHA-256 of payload
} BEHAVIOR_PERSISTENCE_EVENT, *PBEHAVIOR_PERSISTENCE_EVENT;

// Persistence types
typedef enum _PERSISTENCE_TYPE {
    Persistence_None = 0,
    Persistence_RegistryRun,
    Persistence_RegistryRunOnce,
    Persistence_ScheduledTask,
    Persistence_Service,
    Persistence_StartupFolder,
    Persistence_WMISubscription,
    Persistence_DLLHijack,
    Persistence_COMHijack,
    Persistence_Bootkit,
    Persistence_ImageFileExecution,
    Persistence_BrowserExtension,
    Persistence_OfficeTemplate,
    Persistence_PrintProcessor,
    Persistence_LSAPackage,
    Persistence_AppInit,
    Persistence_Winlogon,
    Persistence_ActiveSetup,
    Persistence_ScreenSaver,
    Persistence_Max
} PERSISTENCE_TYPE;

/**
 * @brief Credential access event.
 */
typedef struct _BEHAVIOR_CREDENTIAL_EVENT {
    BEHAVIOR_EVENT_HEADER Header;
    BEHAVIOR_PROCESS_CONTEXT Process;
    UINT32 CredentialAccessType;          // CREDENTIAL_ACCESS_TYPE
    UINT32 TargetProcessId;               // LSASS, etc.
    UINT64 AccessMask;                    // PROCESS_* access rights
    UINT32 Flags;
    UINT32 Reserved;
    WCHAR TargetProcessName[MAX_PROCESS_NAME_LENGTH];
    WCHAR TargetFilePath[MAX_FILE_PATH_LENGTH];  // SAM, NTDS.dit, etc.
} BEHAVIOR_CREDENTIAL_EVENT, *PBEHAVIOR_CREDENTIAL_EVENT;

// Credential access types
typedef enum _CREDENTIAL_ACCESS_TYPE {
    CredAccess_None = 0,
    CredAccess_LSASSRead,
    CredAccess_LSASSDump,
    CredAccess_SAMRead,
    CredAccess_NTDSRead,
    CredAccess_NTDSCopy,
    CredAccess_SecurityHiveRead,
    CredAccess_Keylogging,
    CredAccess_BrowserCredentials,
    CredAccess_PasswordFile,
    CredAccess_CredentialVault,
    CredAccess_KerberosTicket,
    CredAccess_DCSync,
    CredAccess_MiniDump,
    CredAccess_Max
} CREDENTIAL_ACCESS_TYPE;

// ============================================================================
// ATTACK CHAIN TRACKING
// ============================================================================

/**
 * @brief Attack chain entry for tracking multi-stage attacks.
 */
typedef struct _ATTACK_CHAIN_ENTRY {
    UINT64 ChainId;                       // Unique chain identifier
    UINT32 EntryIndex;                    // Position in chain (0-based)
    UINT32 TotalEntries;                  // Total entries so far
    ATTACK_CHAIN_STAGE Stage;             // Kill chain stage
    BEHAVIOR_EVENT_TYPE EventType;        // Event type
    UINT64 Timestamp;
    UINT32 ProcessId;
    UINT32 ThreatScore;                   // Cumulative score at this point
    UINT32 MitreAttackId;                 // MITRE ATT&CK technique ID
    UINT32 Reserved;
} ATTACK_CHAIN_ENTRY, *PATTACK_CHAIN_ENTRY;

/**
 * @brief Full attack chain summary.
 */
typedef struct _ATTACK_CHAIN_SUMMARY {
    UINT64 ChainId;
    UINT64 StartTime;
    UINT64 LastUpdateTime;
    UINT32 TotalEvents;
    UINT32 CumulativeThreatScore;         // 0-10000
    THREAT_SEVERITY HighestSeverity;
    ATTACK_CHAIN_STAGE CurrentStage;
    UINT32 UniqueProcessCount;
    UINT32 Flags;
    UINT32 PrimaryProcessId;              // Initial process
    UINT32 Reserved;
    WCHAR PrimaryImagePath[MAX_FILE_PATH_LENGTH];
    // Variable: ATTACK_CHAIN_ENTRY entries follow
} ATTACK_CHAIN_SUMMARY, *PATTACK_CHAIN_SUMMARY;

// Attack chain flags
#define CHAIN_FLAG_ACTIVE                 0x00000001  // Chain is still active
#define CHAIN_FLAG_REMEDIATED             0x00000002  // Threat was remediated
#define CHAIN_FLAG_FALSE_POSITIVE         0x00000004  // Marked as FP
#define CHAIN_FLAG_BLOCKED                0x00000008  // Attack was blocked
#define CHAIN_FLAG_USER_ALLOWED           0x00000010  // User allowed action
#define CHAIN_FLAG_CRITICAL               0x00000020  // Critical severity reached

// ============================================================================
// BEHAVIORAL RESPONSE STRUCTURES
// ============================================================================

/**
 * @brief Response to behavioral event from user-mode.
 */
typedef struct _BEHAVIOR_EVENT_RESPONSE {
    BEHAVIOR_CORRELATION_ID CorrelationId;
    UINT32 Action;                        // BEHAVIOR_RESPONSE_ACTION
    UINT32 Flags;
    UINT64 ResponseTimestamp;
    UINT32 ThreatScoreOverride;           // User-mode score adjustment (-1000 to +1000)
    UINT32 Reserved;
} BEHAVIOR_EVENT_RESPONSE, *PBEHAVIOR_EVENT_RESPONSE;

// Response actions
typedef enum _BEHAVIOR_RESPONSE_ACTION {
    BehaviorResponse_Allow = 0,
    BehaviorResponse_Block,
    BehaviorResponse_Terminate,           // Kill process
    BehaviorResponse_Quarantine,          // Quarantine file
    BehaviorResponse_Alert,               // Alert only
    BehaviorResponse_Remediate,           // Auto-remediate
    BehaviorResponse_Investigate,         // Collect more data
    BehaviorResponse_Max
} BEHAVIOR_RESPONSE_ACTION;

// ============================================================================
// BEHAVIORAL RULE STRUCTURES
// ============================================================================

/**
 * @brief Behavioral detection rule definition.
 */
typedef struct _BEHAVIOR_RULE {
    UINT32 RuleId;
    UINT32 Version;
    UINT32 Flags;
    UINT32 Priority;                      // Higher = more important
    THREAT_SEVERITY Severity;
    UINT32 ThreatScore;                   // Score when rule matches
    UINT32 MitreAttackId;                 // Associated MITRE technique
    BEHAVIOR_EVENT_TYPE RequiredEvent;    // Primary event type
    BEHAVIOR_EVENT_CATEGORY Category;
    UINT32 ConditionCount;                // Number of conditions
    UINT32 TimeWindowMs;                  // Time window for correlations
    WCHAR RuleName[128];
    WCHAR Description[512];
    // Variable: Rule conditions follow
} BEHAVIOR_RULE, *PBEHAVIOR_RULE;

// Rule flags
#define RULE_FLAG_ENABLED                 0x00000001
#define RULE_FLAG_BLOCKING                0x00000002
#define RULE_FLAG_ALERTING                0x00000004
#define RULE_FLAG_REQUIRES_CORRELATION    0x00000008
#define RULE_FLAG_KERNEL_ONLY             0x00000010
#define RULE_FLAG_USER_MODE_ONLY          0x00000020
#define RULE_FLAG_HIGH_CONFIDENCE         0x00000040
#define RULE_FLAG_EXPERIMENTAL            0x00000080

#pragma pack(pop)

// ============================================================================
// HELPER MACROS
// ============================================================================

/**
 * @brief Check if event is high severity.
 */
#define BEHAVIOR_IS_HIGH_SEVERITY(event) \
    ((event)->Header.Severity >= ThreatSeverity_High)

/**
 * @brief Check if event requires response.
 */
#define BEHAVIOR_REQUIRES_RESPONSE(event) \
    (((event)->Header.Flags & BEHAVIOR_FLAG_REQUIRES_RESPONSE) != 0)

/**
 * @brief Check if event is part of attack chain.
 */
#define BEHAVIOR_IS_CHAIN_MEMBER(event) \
    (((event)->Header.Flags & BEHAVIOR_FLAG_CHAIN_MEMBER) != 0)

/**
 * @brief Get category name string.
 */
#ifdef __cplusplus
extern "C" {
#endif

#ifndef _KERNEL_MODE
const wchar_t* BehaviorCategoryToString(BEHAVIOR_EVENT_CATEGORY category);
const wchar_t* BehaviorEventTypeToString(BEHAVIOR_EVENT_TYPE type);
const wchar_t* ThreatSeverityToString(THREAT_SEVERITY severity);
const wchar_t* AttackStageToString(ATTACK_CHAIN_STAGE stage);
#endif

#ifdef __cplusplus
}
#endif

#endif // SHADOWSTRIKE_BEHAVIOR_TYPES_H
