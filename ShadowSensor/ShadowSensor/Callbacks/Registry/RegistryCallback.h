/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE REGISTRY CALLBACKS
 * ============================================================================
 *
 * @file RegistryCallback.h
 * @brief Enterprise-grade registry filtering and monitoring for kernel EDR.
 *
 * This module provides comprehensive registry monitoring via CmRegisterCallbackEx:
 * - Full registry operation interception (Create, Set, Delete, Rename, Query)
 * - Persistence mechanism detection (Run keys, Services, Scheduled Tasks)
 * - Self-protection for driver registry keys
 * - MITRE ATT&CK technique correlation
 * - Behavioral pattern analysis for registry-based attacks
 * - Ransomware behavior detection (VSS, backup key modifications)
 * - Defense evasion detection (security policy modifications)
 * - Per-process registry activity tracking
 * - Asynchronous notification with rate limiting
 *
 * Detection Techniques Covered (MITRE ATT&CK):
 * - T1547.001: Boot or Logon Autostart Execution: Registry Run Keys
 * - T1543.003: Create or Modify System Process: Windows Service
 * - T1112: Modify Registry
 * - T1562.001: Impair Defenses: Disable or Modify Tools
 * - T1562.004: Impair Defenses: Disable or Modify System Firewall
 * - T1564.001: Hide Artifacts: Hidden Files and Directories
 * - T1553.004: Subvert Trust Controls: Install Root Certificate
 * - T1546.015: Event Triggered Execution: Component Object Model Hijacking
 * - T1546.012: Event Triggered Execution: Image File Execution Options
 * - T1490: Inhibit System Recovery (VSS/Backup key modifications)
 *
 * Performance Characteristics:
 * - O(1) protected key lookup via hash table
 * - Lock-free statistics using InterlockedXxx
 * - Lookaside lists for high-frequency allocations
 * - Early exit for system/trusted processes
 * - Configurable monitoring depth
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef SHADOWSTRIKE_REGISTRY_CALLBACK_H
#define SHADOWSTRIKE_REGISTRY_CALLBACK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * @brief Maximum registry path length to track.
 */
#define SHADOWSTRIKE_MAX_REG_PATH_LENGTH        512

/**
 * @brief Maximum registry value name length.
 */
#define SHADOWSTRIKE_MAX_REG_VALUE_LENGTH       256

/**
 * @brief Maximum registry data size to capture for analysis.
 */
#define SHADOWSTRIKE_MAX_REG_DATA_CAPTURE       4096

/**
 * @brief Pool tag for registry callback allocations.
 */
#define REG_POOL_TAG                            'geRS'

/**
 * @brief Pool tag for registry context allocations.
 */
#define REG_CONTEXT_POOL_TAG                    'xCRS'

/**
 * @brief Hash bucket count for protected key lookup.
 */
#define REG_PROTECTED_KEY_HASH_BUCKETS          64

/**
 * @brief Maximum protected keys.
 */
#define REG_MAX_PROTECTED_KEYS                  128

/**
 * @brief Maximum persistence patterns to track.
 */
#define REG_MAX_PERSISTENCE_PATTERNS            256

/**
 * @brief Context cleanup interval in milliseconds.
 */
#define REG_CLEANUP_INTERVAL_MS                 120000

/**
 * @brief Context timeout in milliseconds.
 */
#define REG_CONTEXT_TIMEOUT_MS                  600000

// ============================================================================
// WELL-KNOWN REGISTRY PATHS
// ============================================================================

//
// Persistence Locations - Run Keys
//
#define SHADOWSTRIKE_REG_RUN_KEY \
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"

#define SHADOWSTRIKE_REG_RUNONCE_KEY \
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"

#define SHADOWSTRIKE_REG_RUN_KEY_USER \
    L"\\REGISTRY\\USER\\*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"

#define SHADOWSTRIKE_REG_RUNONCE_KEY_USER \
    L"\\REGISTRY\\USER\\*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"

#define SHADOWSTRIKE_REG_RUNONCEEX_KEY \
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx"

//
// Persistence Locations - Services
//
#define SHADOWSTRIKE_REG_SERVICES_PATH \
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services"

#define SHADOWSTRIKE_REG_SERVICES_PATH_ALT \
    L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services"

//
// Persistence Locations - Scheduled Tasks (Legacy)
//
#define SHADOWSTRIKE_REG_SCHEDULED_TASKS \
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks"

//
// Persistence Locations - Image File Execution Options (IFEO)
//
#define SHADOWSTRIKE_REG_IFEO \
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"

//
// Persistence Locations - AppInit DLLs
//
#define SHADOWSTRIKE_REG_APPINIT \
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"

//
// Persistence Locations - Winlogon
//
#define SHADOWSTRIKE_REG_WINLOGON \
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"

//
// Persistence Locations - Shell Extensions
//
#define SHADOWSTRIKE_REG_SHELL_EXTENSIONS \
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved"

//
// Persistence Locations - COM Objects
//
#define SHADOWSTRIKE_REG_CLSID \
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\CLSID"

#define SHADOWSTRIKE_REG_INPROCSERVER \
    L"InprocServer32"

//
// Security Policy Locations
//
#define SHADOWSTRIKE_REG_SECURITY_CENTER \
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Security Center"

#define SHADOWSTRIKE_REG_WINDOWS_DEFENDER \
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows Defender"

#define SHADOWSTRIKE_REG_POLICIES \
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft"

#define SHADOWSTRIKE_REG_FIREWALL \
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy"

//
// Ransomware Indicators
//
#define SHADOWSTRIKE_REG_VSS_ADMIN \
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\VSS"

#define SHADOWSTRIKE_REG_BACKUP_EXEC \
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Symantec\\Backup Exec"

#define SHADOWSTRIKE_REG_WBENGINE \
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\wbengine"

//
// Certificate Stores
//
#define SHADOWSTRIKE_REG_ROOT_CERTS \
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\SystemCertificates\\Root\\Certificates"

#define SHADOWSTRIKE_REG_AUTH_ROOT \
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates"

//
// ShadowStrike Self-Protection
//
#define SHADOWSTRIKE_SERVICE_NAME               L"ShadowStrikeFlt"

#define SHADOWSTRIKE_REG_OUR_SERVICE \
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\ShadowStrikeFlt"

#define SHADOWSTRIKE_REG_OUR_SOFTWARE \
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\ShadowStrike"

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Registry operation types.
 */
typedef enum _SHADOWSTRIKE_REG_OPERATION {
    RegOpNone = 0,
    RegOpCreateKey,
    RegOpOpenKey,
    RegOpDeleteKey,
    RegOpRenameKey,
    RegOpSetValue,
    RegOpDeleteValue,
    RegOpQueryValue,
    RegOpEnumerateKey,
    RegOpEnumerateValue,
    RegOpQueryKey,
    RegOpSetKeySecurity,
    RegOpMax
} SHADOWSTRIKE_REG_OPERATION;

/**
 * @brief Registry monitoring flags.
 */
typedef enum _SHADOWSTRIKE_REG_FLAGS {
    RegFlagNone                 = 0x00000000,
    RegFlagPersistenceKey       = 0x00000001,   // Known persistence location
    RegFlagSecurityKey          = 0x00000002,   // Security-related key
    RegFlagServiceKey           = 0x00000004,   // Service configuration
    RegFlagProtectedKey         = 0x00000008,   // Self-protection key
    RegFlagRunKey               = 0x00000010,   // Run/RunOnce key
    RegFlagIFEOKey              = 0x00000020,   // Image File Execution Options
    RegFlagCOMKey               = 0x00000040,   // COM object registration
    RegFlagCertificateKey       = 0x00000080,   // Certificate store
    RegFlagFirewallKey          = 0x00000100,   // Firewall configuration
    RegFlagDefenderKey          = 0x00000200,   // Windows Defender
    RegFlagVSSKey               = 0x00000400,   // Volume Shadow Copy
    RegFlagScheduledTaskKey     = 0x00000800,   // Scheduled task
    RegFlagWinlogonKey          = 0x00001000,   // Winlogon
    RegFlagAppInitKey           = 0x00002000,   // AppInit_DLLs
    RegFlagHighRisk             = 0x80000000    // High-risk modification
} SHADOWSTRIKE_REG_FLAGS;

/**
 * @brief Registry threat indicators.
 */
typedef enum _SHADOWSTRIKE_REG_THREAT_INDICATOR {
    RegThreatNone               = 0x00000000,
    RegThreatPersistence        = 0x00000001,   // Persistence mechanism
    RegThreatDefenseEvasion     = 0x00000002,   // Security bypass
    RegThreatPrivilegeEsc       = 0x00000004,   // Privilege escalation
    RegThreatCredentialAccess   = 0x00000008,   // Credential access
    RegThreatLateralMovement    = 0x00000010,   // Lateral movement prep
    RegThreatRansomware         = 0x00000020,   // Ransomware behavior
    RegThreatRootkit            = 0x00000040,   // Rootkit behavior
    RegThreatInfoStealer        = 0x00000080,   // Info stealer behavior
    RegThreatTampering          = 0x00000100    // AV/EDR tampering
} SHADOWSTRIKE_REG_THREAT_INDICATOR;

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Registry operation context for tracking.
 */
typedef struct _SHADOWSTRIKE_REG_OP_CONTEXT {
    //
    // Operation identification
    //
    UINT64 OperationId;
    SHADOWSTRIKE_REG_OPERATION Operation;
    LARGE_INTEGER Timestamp;

    //
    // Process context
    //
    HANDLE ProcessId;
    HANDLE ThreadId;
    PEPROCESS Process;
    BOOLEAN IsElevated;
    BOOLEAN IsSystem;
    BOOLEAN IsService;
    BOOLEAN IsProtectedProcess;

    //
    // Key information
    //
    UNICODE_STRING KeyPath;
    UNICODE_STRING ValueName;
    PVOID KeyObject;

    //
    // Value data (for SetValue operations)
    //
    ULONG DataType;
    ULONG DataSize;
    PVOID Data;

    //
    // Analysis results
    //
    ULONG KeyFlags;
    ULONG ThreatIndicators;
    ULONG SuspicionScore;

    //
    // Blocking decision
    //
    BOOLEAN ShouldBlock;
    BOOLEAN BlockedBySelfProtection;
    BOOLEAN NotificationSent;

    //
    // Reference counting
    //
    volatile LONG RefCount;

    //
    // List linkage
    //
    LIST_ENTRY ListEntry;

} SHADOWSTRIKE_REG_OP_CONTEXT, *PSHADOWSTRIKE_REG_OP_CONTEXT;

/**
 * @brief Per-process registry activity tracking.
 */
typedef struct _SHADOWSTRIKE_REG_PROCESS_CONTEXT {
    //
    // Process identification
    //
    HANDLE ProcessId;
    PEPROCESS Process;
    LARGE_INTEGER CreateTime;

    //
    // Activity counters
    //
    volatile LONG64 TotalOperations;
    volatile LONG64 CreateKeyCount;
    volatile LONG64 SetValueCount;
    volatile LONG64 DeleteKeyCount;
    volatile LONG64 DeleteValueCount;
    volatile LONG64 PersistenceAttempts;
    volatile LONG64 SecurityKeyAccesses;
    volatile LONG64 BlockedOperations;

    //
    // Behavioral tracking
    //
    ULONG ThreatIndicators;
    ULONG SuspicionScore;
    ULONG RunKeyModifications;
    ULONG ServiceModifications;
    ULONG IFEOModifications;
    ULONG SecurityPolicyModifications;

    //
    // Recent operations (ring buffer)
    //
    SHADOWSTRIKE_REG_OPERATION RecentOps[32];
    LARGE_INTEGER RecentOpTimes[32];
    ULONG RecentOpIndex;

    //
    // Reference counting
    //
    volatile LONG RefCount;

    //
    // List linkage
    //
    LIST_ENTRY ListEntry;
    LIST_ENTRY HashEntry;

} SHADOWSTRIKE_REG_PROCESS_CONTEXT, *PSHADOWSTRIKE_REG_PROCESS_CONTEXT;

/**
 * @brief Registry monitoring statistics.
 */
typedef struct _SHADOWSTRIKE_REG_STATISTICS {
    //
    // Operation counts
    //
    volatile LONG64 TotalOperations;
    volatile LONG64 CreateKeyOperations;
    volatile LONG64 OpenKeyOperations;
    volatile LONG64 DeleteKeyOperations;
    volatile LONG64 RenameKeyOperations;
    volatile LONG64 SetValueOperations;
    volatile LONG64 DeleteValueOperations;
    volatile LONG64 QueryOperations;

    //
    // Detection counts
    //
    volatile LONG64 PersistenceDetections;
    volatile LONG64 DefenseEvasionDetections;
    volatile LONG64 RansomwareIndicators;
    volatile LONG64 SecurityPolicyChanges;
    volatile LONG64 CertificateStoreChanges;
    volatile LONG64 ServiceCreations;
    volatile LONG64 RunKeyModifications;
    volatile LONG64 IFEOModifications;

    //
    // Blocking counts
    //
    volatile LONG64 SelfProtectionBlocks;
    volatile LONG64 ThreatBlocks;
    volatile LONG64 PolicyBlocks;

    //
    // Notification counts
    //
    volatile LONG64 NotificationsSent;
    volatile LONG64 NotificationsDropped;

    //
    // Error counts
    //
    volatile LONG64 PathResolutionErrors;
    volatile LONG64 ContextAllocationErrors;
    volatile LONG64 AnalysisErrors;

    //
    // Timing
    //
    LARGE_INTEGER StartTime;
    volatile LONG64 TotalLatencyUs;
    volatile LONG64 MaxLatencyUs;

} SHADOWSTRIKE_REG_STATISTICS, *PSHADOWSTRIKE_REG_STATISTICS;

/**
 * @brief Registry monitoring configuration.
 */
typedef struct _SHADOWSTRIKE_REG_CONFIG {
    //
    // Monitoring flags
    //
    BOOLEAN Enabled;
    BOOLEAN SelfProtectionEnabled;
    BOOLEAN PersistenceMonitoringEnabled;
    BOOLEAN SecurityPolicyMonitoringEnabled;
    BOOLEAN ServiceMonitoringEnabled;
    BOOLEAN CertificateMonitoringEnabled;
    BOOLEAN DetailedNotificationsEnabled;
    BOOLEAN BlockHighRiskOperations;

    //
    // Thresholds
    //
    ULONG MinBlockScore;
    ULONG PersistenceAlertScore;
    ULONG AnalysisTimeoutMs;
    ULONG NotificationRateLimitPerSec;

} SHADOWSTRIKE_REG_CONFIG, *PSHADOWSTRIKE_REG_CONFIG;

// ============================================================================
// FUNCTION PROTOTYPES - INITIALIZATION
// ============================================================================

/**
 * @brief Initialize the registry monitoring subsystem.
 *
 * Must be called during driver initialization before registering
 * the registry callback.
 *
 * @return STATUS_SUCCESS on success.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeInitializeRegistryMonitoring(
    VOID
    );

/**
 * @brief Shutdown the registry monitoring subsystem.
 *
 * Cleans up all resources and unregisters callbacks.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeCleanupRegistryMonitoring(
    VOID
    );

/**
 * @brief Register the registry callback with Configuration Manager.
 *
 * @param DriverObject  Driver object for registration.
 * @return STATUS_SUCCESS on success.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeRegisterRegistryCallback(
    _In_ PDRIVER_OBJECT DriverObject
    );

/**
 * @brief Unregister the registry callback.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeUnregisterRegistryCallback(
    VOID
    );

// ============================================================================
// FUNCTION PROTOTYPES - MAIN CALLBACK
// ============================================================================

/**
 * @brief Main registry callback routine.
 *
 * Called by Configuration Manager for all registry operations.
 *
 * @param CallbackContext   Context provided at registration.
 * @param Argument1         Operation type (REG_NOTIFY_CLASS).
 * @param Argument2         Operation specific data.
 * @return STATUS_SUCCESS to allow, error status to deny.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeRegistryCallbackRoutine(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
    );

// ============================================================================
// FUNCTION PROTOTYPES - ANALYSIS
// ============================================================================

/**
 * @brief Check if registry operation should be blocked for self-protection.
 *
 * @param RegistryPath  Full path of the key.
 * @param ProcessId     Requesting process ID.
 * @return TRUE if access should be denied.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
ShadowStrikeCheckRegistrySelfProtection(
    _In_ PUNICODE_STRING RegistryPath,
    _In_ HANDLE ProcessId
    );

/**
 * @brief Analyze registry write for persistence mechanisms.
 *
 * @param RegistryPath  Full path of the key.
 * @param ValueName     Name of the value being written.
 * @param Data          Data being written.
 * @param DataSize      Size of data.
 * @param DataType      Type of data (REG_SZ, etc.).
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
ShadowStrikeAnalyzeRegistryPersistence(
    _In_ PUNICODE_STRING RegistryPath,
    _In_ PUNICODE_STRING ValueName,
    _In_opt_ PVOID Data,
    _In_ ULONG DataSize,
    _In_ ULONG DataType
    );

/**
 * @brief Classify registry key path for monitoring.
 *
 * @param KeyPath   Full registry key path.
 * @return Flags indicating key classification.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
ShadowStrikeClassifyRegistryKey(
    _In_ PCUNICODE_STRING KeyPath
    );

/**
 * @brief Calculate suspicion score for registry operation.
 *
 * @param Context   Registry operation context.
 * @return Suspicion score (0-100).
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
ULONG
ShadowStrikeCalculateRegistrySuspicionScore(
    _In_ PSHADOWSTRIKE_REG_OP_CONTEXT Context
    );

/**
 * @brief Detect ransomware indicators in registry operation.
 *
 * @param KeyPath       Registry key path.
 * @param ValueName     Value name (optional).
 * @param Operation     Registry operation type.
 * @return TRUE if ransomware indicator detected.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
ShadowStrikeDetectRansomwareRegistryBehavior(
    _In_ PCUNICODE_STRING KeyPath,
    _In_opt_ PCUNICODE_STRING ValueName,
    _In_ SHADOWSTRIKE_REG_OPERATION Operation
    );

/**
 * @brief Detect defense evasion in registry operation.
 *
 * @param KeyPath       Registry key path.
 * @param ValueName     Value name (optional).
 * @param Data          Value data (optional).
 * @param DataSize      Size of data.
 * @return Threat indicators bitmask.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
ULONG
ShadowStrikeDetectDefenseEvasionRegistry(
    _In_ PCUNICODE_STRING KeyPath,
    _In_opt_ PCUNICODE_STRING ValueName,
    _In_opt_ PVOID Data,
    _In_ ULONG DataSize
    );

// ============================================================================
// FUNCTION PROTOTYPES - PROCESS CONTEXT
// ============================================================================

/**
 * @brief Get or create process context for registry tracking.
 *
 * @param ProcessId     Process ID.
 * @return Process context (caller must release).
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
PSHADOWSTRIKE_REG_PROCESS_CONTEXT
ShadowStrikeGetRegistryProcessContext(
    _In_ HANDLE ProcessId
    );

/**
 * @brief Release process context reference.
 *
 * @param Context   Process context to release.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeReleaseRegistryProcessContext(
    _In_ PSHADOWSTRIKE_REG_PROCESS_CONTEXT Context
    );

/**
 * @brief Handle process termination - cleanup registry context.
 *
 * @param ProcessId     Terminating process ID.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
ShadowStrikeRegistryProcessTerminated(
    _In_ HANDLE ProcessId
    );

// ============================================================================
// FUNCTION PROTOTYPES - STATISTICS AND CONFIGURATION
// ============================================================================

/**
 * @brief Get registry monitoring statistics.
 *
 * @param Statistics    Receives current statistics.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeGetRegistryStatistics(
    _Out_ PSHADOWSTRIKE_REG_STATISTICS Statistics
    );

/**
 * @brief Reset registry monitoring statistics.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeResetRegistryStatistics(
    VOID
    );

/**
 * @brief Update registry monitoring configuration.
 *
 * @param Config    New configuration settings.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeUpdateRegistryConfig(
    _In_ PSHADOWSTRIKE_REG_CONFIG Config
    );

/**
 * @brief Get current registry monitoring configuration.
 *
 * @param Config    Receives current configuration.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ShadowStrikeGetRegistryConfig(
    _Out_ PSHADOWSTRIKE_REG_CONFIG Config
    );

// ============================================================================
// FUNCTION PROTOTYPES - PROTECTED KEYS
// ============================================================================

/**
 * @brief Add a registry key to the protection list.
 *
 * @param KeyPath   Key path to protect.
 * @param Flags     Protection flags.
 * @return STATUS_SUCCESS on success.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeAddProtectedRegistryKey(
    _In_ PCUNICODE_STRING KeyPath,
    _In_ ULONG Flags
    );

/**
 * @brief Remove a registry key from the protection list.
 *
 * @param KeyPath   Key path to unprotect.
 * @return TRUE if removed, FALSE if not found.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
ShadowStrikeRemoveProtectedRegistryKey(
    _In_ PCUNICODE_STRING KeyPath
    );

/**
 * @brief Check if a registry key is in the protection list.
 *
 * @param KeyPath   Key path to check.
 * @return TRUE if protected.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeIsRegistryKeyProtected(
    _In_ PCUNICODE_STRING KeyPath
    );

// ============================================================================
// FUNCTION PROTOTYPES - UTILITY
// ============================================================================

/**
 * @brief Get full registry path from key object.
 *
 * @param KeyObject     Key object to query.
 * @param KeyPath       Receives the allocated path (caller must free).
 * @return STATUS_SUCCESS on success.
 *
 * @irql PASSIVE_LEVEL
 *
 * @note Caller must free KeyPath->Buffer with ExFreePoolWithTag.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeGetRegistryObjectPath(
    _In_ PVOID KeyObject,
    _Out_ PUNICODE_STRING KeyPath
    );

/**
 * @brief Get string representation of registry operation.
 *
 * @param Operation     Registry operation type.
 * @return Static string name.
 *
 * @irql Any
 */
PCWSTR
ShadowStrikeGetRegistryOperationName(
    _In_ SHADOWSTRIKE_REG_OPERATION Operation
    );

/**
 * @brief Get string representation of registry data type.
 *
 * @param DataType      Registry data type (REG_*).
 * @return Static string name.
 *
 * @irql Any
 */
PCWSTR
ShadowStrikeGetRegistryDataTypeName(
    _In_ ULONG DataType
    );

#ifdef __cplusplus
}
#endif

#endif // SHADOWSTRIKE_REGISTRY_CALLBACK_H
