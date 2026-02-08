/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE REGISTRY CALLBACK IMPLEMENTATION
 * ============================================================================
 *
 * @file RegistryCallback.c
 * @brief Enterprise-grade registry filtering and monitoring implementation.
 *
 * This module provides comprehensive registry monitoring via CmRegisterCallbackEx:
 * - Full registry operation interception
 * - Persistence mechanism detection (Run keys, Services, IFEO, COM hijacking)
 * - Self-protection for driver registry keys
 * - MITRE ATT&CK technique correlation
 * - Behavioral pattern analysis for registry-based attacks
 * - Ransomware behavior detection (VSS, backup key modifications)
 * - Defense evasion detection (security policy modifications)
 * - Per-process registry activity tracking
 * - Asynchronous notification with rate limiting
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "RegistryCallback.h"
#include "../../Core/Globals.h"
#include "../../SelfProtection/SelfProtect.h"
#include "../../Communication/ScanBridge.h"

// ============================================================================
// POOL TAGS
// ============================================================================

#define REG_MONITOR_TAG         'noMR'  // Registry monitor state
#define REG_CONTEXT_TAG         'txCR'  // Registry context
#define REG_PATH_TAG            'htPR'  // Registry path buffer
#define REG_HASH_TAG            'shHR'  // Registry hash table
#define REG_PROCCTX_TAG         'cPrR'  // Process context

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

#define REG_PROCESS_HASH_BUCKETS        64
#define REG_MAX_PATH_ALLOCATION         (SHADOWSTRIKE_MAX_REG_PATH_LENGTH * sizeof(WCHAR))
#define REG_NOTIFICATION_RATE_LIMIT     100     // Max notifications per second
#define REG_NOTIFICATION_WINDOW_MS      1000    // Rate limit window

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

/**
 * @brief Hash table entry for process context lookup.
 */
typedef struct _REG_PROCESS_HASH_ENTRY {
    LIST_ENTRY HashLink;
    PSHADOWSTRIKE_REG_PROCESS_CONTEXT Context;
} REG_PROCESS_HASH_ENTRY, *PREG_PROCESS_HASH_ENTRY;

/**
 * @brief Protected registry key entry for hash table.
 */
typedef struct _REG_PROTECTED_KEY_ENTRY {
    LIST_ENTRY HashLink;
    UNICODE_STRING KeyPath;
    ULONG Flags;
    WCHAR PathBuffer[SHADOWSTRIKE_MAX_REG_PATH_LENGTH];
} REG_PROTECTED_KEY_ENTRY, *PREG_PROTECTED_KEY_ENTRY;

/**
 * @brief Global registry monitoring state.
 *
 * Single instance containing all state for registry monitoring.
 */
typedef struct _SHADOWSTRIKE_REGISTRY_MONITOR {

    //
    // Initialization state
    //
    BOOLEAN Initialized;
    BOOLEAN CallbackRegistered;
    ULONG Reserved1;

    //
    // Callback registration
    //
    LARGE_INTEGER CallbackCookie;

    //
    // Process context hash table
    //
    LIST_ENTRY ProcessHashBuckets[REG_PROCESS_HASH_BUCKETS];
    EX_PUSH_LOCK ProcessHashLock;
    volatile LONG ProcessContextCount;

    //
    // Protected key hash table
    //
    LIST_ENTRY ProtectedKeyBuckets[REG_PROTECTED_KEY_HASH_BUCKETS];
    EX_PUSH_LOCK ProtectedKeyLock;
    volatile LONG ProtectedKeyCount;

    //
    // Lookaside list for context allocations
    //
    NPAGED_LOOKASIDE_LIST ContextLookaside;
    BOOLEAN LookasideInitialized;

    //
    // Statistics
    //
    SHADOWSTRIKE_REG_STATISTICS Statistics;

    //
    // Configuration
    //
    SHADOWSTRIKE_REG_CONFIG Config;
    EX_PUSH_LOCK ConfigLock;

    //
    // Rate limiting
    //
    volatile LONG64 NotificationCount;
    LARGE_INTEGER NotificationWindowStart;
    EX_PUSH_LOCK RateLimitLock;

    //
    // Operation ID generator
    //
    volatile LONG64 NextOperationId;

} SHADOWSTRIKE_REGISTRY_MONITOR, *PSHADOWSTRIKE_REGISTRY_MONITOR;

// ============================================================================
// GLOBAL STATE
// ============================================================================

static SHADOWSTRIKE_REGISTRY_MONITOR g_RegistryMonitor = {0};

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static ULONG
RegpHashString(
    _In_ PCUNICODE_STRING String
    );

static ULONG
RegpHashProcessId(
    _In_ HANDLE ProcessId
    );

static BOOLEAN
RegpCheckRateLimit(
    VOID
    );

static NTSTATUS
RegpAllocateProcessContext(
    _In_ HANDLE ProcessId,
    _Out_ PSHADOWSTRIKE_REG_PROCESS_CONTEXT* Context
    );

static VOID
RegpFreeProcessContext(
    _In_ PSHADOWSTRIKE_REG_PROCESS_CONTEXT Context
    );

static SHADOWSTRIKE_REG_OPERATION
RegpNotifyClassToOperation(
    _In_ REG_NOTIFY_CLASS NotifyClass
    );

// ============================================================================
// PAGED CODE SECTIONS
// ============================================================================

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, ShadowStrikeInitializeRegistryMonitoring)
#pragma alloc_text(PAGE, ShadowStrikeCleanupRegistryMonitoring)
#pragma alloc_text(PAGE, ShadowStrikeRegisterRegistryCallback)
#pragma alloc_text(PAGE, ShadowStrikeUnregisterRegistryCallback)
#pragma alloc_text(PAGE, ShadowStrikeRegistryCallbackRoutine)
#pragma alloc_text(PAGE, ShadowStrikeCheckRegistrySelfProtection)
#pragma alloc_text(PAGE, ShadowStrikeGetRegistryObjectPath)
#pragma alloc_text(PAGE, ShadowStrikeAnalyzeRegistryPersistence)
#pragma alloc_text(PAGE, ShadowStrikeCalculateRegistrySuspicionScore)
#pragma alloc_text(PAGE, ShadowStrikeDetectRansomwareRegistryBehavior)
#pragma alloc_text(PAGE, ShadowStrikeDetectDefenseEvasionRegistry)
#pragma alloc_text(PAGE, ShadowStrikeGetRegistryProcessContext)
#pragma alloc_text(PAGE, ShadowStrikeRegistryProcessTerminated)
#pragma alloc_text(PAGE, ShadowStrikeUpdateRegistryConfig)
#pragma alloc_text(PAGE, ShadowStrikeAddProtectedRegistryKey)
#pragma alloc_text(PAGE, ShadowStrikeRemoveProtectedRegistryKey)
#endif

// ============================================================================
// HASH FUNCTIONS
// ============================================================================

/**
 * @brief Compute hash for Unicode string (case-insensitive).
 */
static ULONG
RegpHashString(
    _In_ PCUNICODE_STRING String
    )
{
    ULONG hash = 5381;
    ULONG i;
    PWCH buffer;
    USHORT length;

    if (String == NULL || String->Buffer == NULL || String->Length == 0) {
        return 0;
    }

    buffer = String->Buffer;
    length = String->Length / sizeof(WCHAR);

    for (i = 0; i < length; i++) {
        WCHAR ch = RtlUpcaseUnicodeChar(buffer[i]);
        hash = ((hash << 5) + hash) + (ULONG)ch;
    }

    return hash;
}

/**
 * @brief Compute hash for process ID.
 */
static ULONG
RegpHashProcessId(
    _In_ HANDLE ProcessId
    )
{
    ULONG_PTR value = (ULONG_PTR)ProcessId;
    return (ULONG)((value >> 2) ^ (value >> 12));
}

// ============================================================================
// RATE LIMITING
// ============================================================================

/**
 * @brief Check if notification should be rate-limited.
 *
 * @return TRUE if notification should proceed, FALSE if rate-limited.
 */
static BOOLEAN
RegpCheckRateLimit(
    VOID
    )
{
    LARGE_INTEGER currentTime;
    LARGE_INTEGER elapsed;
    LONG64 count;

    KeQuerySystemTime(&currentTime);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_RegistryMonitor.RateLimitLock);

    //
    // Check if we're in a new window
    //
    elapsed.QuadPart = currentTime.QuadPart - g_RegistryMonitor.NotificationWindowStart.QuadPart;

    if (elapsed.QuadPart > (REG_NOTIFICATION_WINDOW_MS * 10000LL)) {
        //
        // New window - reset counter
        //
        g_RegistryMonitor.NotificationWindowStart = currentTime;
        g_RegistryMonitor.NotificationCount = 1;
        ExReleasePushLockExclusive(&g_RegistryMonitor.RateLimitLock);
        KeLeaveCriticalRegion();
        return TRUE;
    }

    count = InterlockedIncrement64(&g_RegistryMonitor.NotificationCount);

    ExReleasePushLockExclusive(&g_RegistryMonitor.RateLimitLock);
    KeLeaveCriticalRegion();

    if (count > g_RegistryMonitor.Config.NotificationRateLimitPerSec) {
        InterlockedIncrement64(&g_RegistryMonitor.Statistics.NotificationsDropped);
        return FALSE;
    }

    return TRUE;
}

// ============================================================================
// INITIALIZATION AND CLEANUP
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowStrikeInitializeRegistryMonitoring(
    VOID
    )
{
    ULONG i;

    PAGED_CODE();

    if (g_RegistryMonitor.Initialized) {
        return STATUS_ALREADY_INITIALIZED;
    }

    //
    // Zero the entire structure
    //
    RtlZeroMemory(&g_RegistryMonitor, sizeof(g_RegistryMonitor));

    //
    // Initialize process hash buckets
    //
    for (i = 0; i < REG_PROCESS_HASH_BUCKETS; i++) {
        InitializeListHead(&g_RegistryMonitor.ProcessHashBuckets[i]);
    }
    ExInitializePushLock(&g_RegistryMonitor.ProcessHashLock);

    //
    // Initialize protected key hash buckets
    //
    for (i = 0; i < REG_PROTECTED_KEY_HASH_BUCKETS; i++) {
        InitializeListHead(&g_RegistryMonitor.ProtectedKeyBuckets[i]);
    }
    ExInitializePushLock(&g_RegistryMonitor.ProtectedKeyLock);

    //
    // Initialize configuration lock
    //
    ExInitializePushLock(&g_RegistryMonitor.ConfigLock);

    //
    // Initialize rate limit lock
    //
    ExInitializePushLock(&g_RegistryMonitor.RateLimitLock);

    //
    // Initialize lookaside list for context allocations
    //
    ExInitializeNPagedLookasideList(
        &g_RegistryMonitor.ContextLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(SHADOWSTRIKE_REG_OP_CONTEXT),
        REG_CONTEXT_TAG,
        0
    );
    g_RegistryMonitor.LookasideInitialized = TRUE;

    //
    // Set default configuration
    //
    g_RegistryMonitor.Config.Enabled = TRUE;
    g_RegistryMonitor.Config.SelfProtectionEnabled = TRUE;
    g_RegistryMonitor.Config.PersistenceMonitoringEnabled = TRUE;
    g_RegistryMonitor.Config.SecurityPolicyMonitoringEnabled = TRUE;
    g_RegistryMonitor.Config.ServiceMonitoringEnabled = TRUE;
    g_RegistryMonitor.Config.CertificateMonitoringEnabled = TRUE;
    g_RegistryMonitor.Config.DetailedNotificationsEnabled = TRUE;
    g_RegistryMonitor.Config.BlockHighRiskOperations = FALSE;
    g_RegistryMonitor.Config.MinBlockScore = 80;
    g_RegistryMonitor.Config.PersistenceAlertScore = 50;
    g_RegistryMonitor.Config.AnalysisTimeoutMs = 1000;
    g_RegistryMonitor.Config.NotificationRateLimitPerSec = REG_NOTIFICATION_RATE_LIMIT;

    //
    // Initialize statistics timestamp
    //
    KeQuerySystemTime(&g_RegistryMonitor.Statistics.StartTime);

    //
    // Initialize rate limit window
    //
    KeQuerySystemTime(&g_RegistryMonitor.NotificationWindowStart);

    g_RegistryMonitor.Initialized = TRUE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Registry monitoring initialized\n");

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
ShadowStrikeCleanupRegistryMonitoring(
    VOID
    )
{
    ULONG i;
    PLIST_ENTRY listEntry;
    PREG_PROTECTED_KEY_ENTRY keyEntry;
    PSHADOWSTRIKE_REG_PROCESS_CONTEXT procContext;

    PAGED_CODE();

    if (!g_RegistryMonitor.Initialized) {
        return;
    }

    //
    // Unregister callback if still registered
    //
    if (g_RegistryMonitor.CallbackRegistered) {
        ShadowStrikeUnregisterRegistryCallback();
    }

    //
    // Free all protected key entries
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_RegistryMonitor.ProtectedKeyLock);

    for (i = 0; i < REG_PROTECTED_KEY_HASH_BUCKETS; i++) {
        while (!IsListEmpty(&g_RegistryMonitor.ProtectedKeyBuckets[i])) {
            listEntry = RemoveHeadList(&g_RegistryMonitor.ProtectedKeyBuckets[i]);
            keyEntry = CONTAINING_RECORD(listEntry, REG_PROTECTED_KEY_ENTRY, HashLink);
            ExFreePoolWithTag(keyEntry, REG_HASH_TAG);
        }
    }

    ExReleasePushLockExclusive(&g_RegistryMonitor.ProtectedKeyLock);
    KeLeaveCriticalRegion();

    //
    // Free all process contexts
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_RegistryMonitor.ProcessHashLock);

    for (i = 0; i < REG_PROCESS_HASH_BUCKETS; i++) {
        while (!IsListEmpty(&g_RegistryMonitor.ProcessHashBuckets[i])) {
            listEntry = RemoveHeadList(&g_RegistryMonitor.ProcessHashBuckets[i]);
            procContext = CONTAINING_RECORD(listEntry, SHADOWSTRIKE_REG_PROCESS_CONTEXT, HashEntry);

            if (procContext->Process != NULL) {
                ObDereferenceObject(procContext->Process);
            }
            ExFreePoolWithTag(procContext, REG_PROCCTX_TAG);
        }
    }

    ExReleasePushLockExclusive(&g_RegistryMonitor.ProcessHashLock);
    KeLeaveCriticalRegion();

    //
    // Delete lookaside list
    //
    if (g_RegistryMonitor.LookasideInitialized) {
        ExDeleteNPagedLookasideList(&g_RegistryMonitor.ContextLookaside);
        g_RegistryMonitor.LookasideInitialized = FALSE;
    }

    g_RegistryMonitor.Initialized = FALSE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Registry monitoring cleaned up\n");
}

// ============================================================================
// CALLBACK REGISTRATION
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowStrikeRegisterRegistryCallback(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    NTSTATUS status;
    UNICODE_STRING altitude;

    PAGED_CODE();

    if (!g_RegistryMonitor.Initialized) {
        return STATUS_UNSUCCESSFUL;
    }

    if (g_RegistryMonitor.CallbackRegistered) {
        return STATUS_ALREADY_REGISTERED;
    }

    //
    // Use altitude for registry callbacks
    // This determines our position in the callback stack
    //
    RtlInitUnicodeString(&altitude, L"380050");

    status = CmRegisterCallbackEx(
        ShadowStrikeRegistryCallbackRoutine,
        &altitude,
        DriverObject,
        NULL,   // Context
        &g_RegistryMonitor.CallbackCookie,
        NULL    // Reserved
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Failed to register registry callback: 0x%08X\n",
                   status);
        return status;
    }

    //
    // Store cookie in global driver data as well
    //
    g_DriverData.RegistryCallbackCookie = g_RegistryMonitor.CallbackCookie;
    g_RegistryMonitor.CallbackRegistered = TRUE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Registry callback registered (Cookie: 0x%I64X)\n",
               g_RegistryMonitor.CallbackCookie.QuadPart);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
ShadowStrikeUnregisterRegistryCallback(
    VOID
    )
{
    NTSTATUS status;

    PAGED_CODE();

    if (!g_RegistryMonitor.CallbackRegistered) {
        return;
    }

    if (g_RegistryMonitor.CallbackCookie.QuadPart == 0) {
        g_RegistryMonitor.CallbackRegistered = FALSE;
        return;
    }

    status = CmUnRegisterCallback(g_RegistryMonitor.CallbackCookie);

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Failed to unregister registry callback: 0x%08X\n",
                   status);
    }

    g_RegistryMonitor.CallbackCookie.QuadPart = 0;
    g_DriverData.RegistryCallbackCookie.QuadPart = 0;
    g_RegistryMonitor.CallbackRegistered = FALSE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Registry callback unregistered\n");
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Convert REG_NOTIFY_CLASS to internal operation enum.
 */
static SHADOWSTRIKE_REG_OPERATION
RegpNotifyClassToOperation(
    _In_ REG_NOTIFY_CLASS NotifyClass
    )
{
    switch (NotifyClass) {
        case RegNtPreCreateKey:
        case RegNtPreCreateKeyEx:
            return RegOpCreateKey;
        case RegNtPreOpenKey:
        case RegNtPreOpenKeyEx:
            return RegOpOpenKey;
        case RegNtPreDeleteKey:
            return RegOpDeleteKey;
        case RegNtPreRenameKey:
            return RegOpRenameKey;
        case RegNtPreSetValueKey:
            return RegOpSetValue;
        case RegNtPreDeleteValueKey:
            return RegOpDeleteValue;
        case RegNtPreQueryValueKey:
            return RegOpQueryValue;
        case RegNtPreEnumerateKey:
            return RegOpEnumerateKey;
        case RegNtPreEnumerateValueKey:
            return RegOpEnumerateValue;
        case RegNtPreQueryKey:
            return RegOpQueryKey;
        case RegNtPreSetKeySecurity:
            return RegOpSetKeySecurity;
        default:
            return RegOpNone;
    }
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeGetRegistryObjectPath(
    _In_ PVOID KeyObject,
    _Out_ PUNICODE_STRING KeyPath
    )
{
    NTSTATUS status;
    ULONG returnLength = 0;
    POBJECT_NAME_INFORMATION nameInfo = NULL;
    ULONG allocationSize;

    PAGED_CODE();

    //
    // CRITICAL: Initialize output parameter immediately
    //
    RtlZeroMemory(KeyPath, sizeof(UNICODE_STRING));

    if (KeyObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Query required size
    //
    status = ObQueryNameString(
        KeyObject,
        NULL,
        0,
        &returnLength
    );

    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        if (status == STATUS_SUCCESS) {
            //
            // Empty name
            //
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
        return status;
    }

    //
    // SECURITY: Validate size to prevent integer overflow and excessive allocation
    //
    if (returnLength > REG_MAX_PATH_ALLOCATION) {
        InterlockedIncrement64(&g_RegistryMonitor.Statistics.PathResolutionErrors);
        return STATUS_NAME_TOO_LONG;
    }

    //
    // SECURITY: Check for integer overflow
    //
    allocationSize = returnLength + sizeof(WCHAR);
    if (allocationSize < returnLength) {
        return STATUS_INTEGER_OVERFLOW;
    }

    //
    // Allocate buffer for object name information
    //
    nameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePoolZero(
        PagedPool,
        allocationSize,
        REG_PATH_TAG
    );

    if (nameInfo == NULL) {
        InterlockedIncrement64(&g_RegistryMonitor.Statistics.ContextAllocationErrors);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Query the actual name
    //
    status = ObQueryNameString(
        KeyObject,
        nameInfo,
        returnLength,
        &returnLength
    );

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(nameInfo, REG_PATH_TAG);
        InterlockedIncrement64(&g_RegistryMonitor.Statistics.PathResolutionErrors);
        return status;
    }

    //
    // Validate returned data
    //
    if (nameInfo->Name.Length == 0 || nameInfo->Name.Buffer == NULL) {
        ExFreePoolWithTag(nameInfo, REG_PATH_TAG);
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    //
    // Allocate separate buffer for caller (deep copy)
    //
    KeyPath->MaximumLength = nameInfo->Name.Length + sizeof(WCHAR);
    KeyPath->Buffer = (PWCH)ExAllocatePoolZero(
        PagedPool,
        KeyPath->MaximumLength,
        REG_PATH_TAG
    );

    if (KeyPath->Buffer == NULL) {
        ExFreePoolWithTag(nameInfo, REG_PATH_TAG);
        RtlZeroMemory(KeyPath, sizeof(UNICODE_STRING));
        InterlockedIncrement64(&g_RegistryMonitor.Statistics.ContextAllocationErrors);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Copy the path data
    //
    KeyPath->Length = nameInfo->Name.Length;
    RtlCopyMemory(KeyPath->Buffer, nameInfo->Name.Buffer, nameInfo->Name.Length);
    KeyPath->Buffer[KeyPath->Length / sizeof(WCHAR)] = L'\0';

    ExFreePoolWithTag(nameInfo, REG_PATH_TAG);

    return STATUS_SUCCESS;
}

// ============================================================================
// KEY CLASSIFICATION
// ============================================================================

_Use_decl_annotations_
ULONG
ShadowStrikeClassifyRegistryKey(
    _In_ PCUNICODE_STRING KeyPath
    )
{
    ULONG flags = RegFlagNone;
    UNICODE_STRING testPath;

    if (KeyPath == NULL || KeyPath->Buffer == NULL || KeyPath->Length == 0) {
        return RegFlagNone;
    }

    //
    // Run Keys (T1547.001)
    //
    RtlInitUnicodeString(&testPath, SHADOWSTRIKE_REG_RUN_KEY);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= RegFlagRunKey | RegFlagPersistenceKey;
    }

    RtlInitUnicodeString(&testPath, SHADOWSTRIKE_REG_RUNONCE_KEY);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= RegFlagRunKey | RegFlagPersistenceKey;
    }

    RtlInitUnicodeString(&testPath, SHADOWSTRIKE_REG_RUNONCEEX_KEY);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= RegFlagRunKey | RegFlagPersistenceKey;
    }

    //
    // Services (T1543.003)
    //
    RtlInitUnicodeString(&testPath, SHADOWSTRIKE_REG_SERVICES_PATH);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= RegFlagServiceKey | RegFlagPersistenceKey;
    }

    RtlInitUnicodeString(&testPath, SHADOWSTRIKE_REG_SERVICES_PATH_ALT);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= RegFlagServiceKey | RegFlagPersistenceKey;
    }

    //
    // Image File Execution Options (T1546.012)
    //
    RtlInitUnicodeString(&testPath, SHADOWSTRIKE_REG_IFEO);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= RegFlagIFEOKey | RegFlagPersistenceKey | RegFlagHighRisk;
    }

    //
    // AppInit_DLLs
    //
    RtlInitUnicodeString(&testPath, SHADOWSTRIKE_REG_APPINIT);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= RegFlagAppInitKey | RegFlagPersistenceKey | RegFlagHighRisk;
    }

    //
    // Winlogon
    //
    RtlInitUnicodeString(&testPath, SHADOWSTRIKE_REG_WINLOGON);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= RegFlagWinlogonKey | RegFlagPersistenceKey;
    }

    //
    // COM Objects (T1546.015)
    //
    RtlInitUnicodeString(&testPath, SHADOWSTRIKE_REG_CLSID);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= RegFlagCOMKey | RegFlagPersistenceKey;
    }

    //
    // Scheduled Tasks
    //
    RtlInitUnicodeString(&testPath, SHADOWSTRIKE_REG_SCHEDULED_TASKS);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= RegFlagScheduledTaskKey | RegFlagPersistenceKey;
    }

    //
    // Windows Defender (T1562.001)
    //
    RtlInitUnicodeString(&testPath, SHADOWSTRIKE_REG_WINDOWS_DEFENDER);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= RegFlagDefenderKey | RegFlagSecurityKey;
    }

    //
    // Security Center
    //
    RtlInitUnicodeString(&testPath, SHADOWSTRIKE_REG_SECURITY_CENTER);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= RegFlagSecurityKey;
    }

    //
    // Firewall (T1562.004)
    //
    RtlInitUnicodeString(&testPath, SHADOWSTRIKE_REG_FIREWALL);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= RegFlagFirewallKey | RegFlagSecurityKey;
    }

    //
    // VSS / Backup Services (T1490)
    //
    RtlInitUnicodeString(&testPath, SHADOWSTRIKE_REG_VSS_ADMIN);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= RegFlagVSSKey | RegFlagSecurityKey;
    }

    RtlInitUnicodeString(&testPath, SHADOWSTRIKE_REG_WBENGINE);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= RegFlagVSSKey | RegFlagSecurityKey;
    }

    //
    // Certificate Stores (T1553.004)
    //
    RtlInitUnicodeString(&testPath, SHADOWSTRIKE_REG_ROOT_CERTS);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= RegFlagCertificateKey | RegFlagSecurityKey | RegFlagHighRisk;
    }

    RtlInitUnicodeString(&testPath, SHADOWSTRIKE_REG_AUTH_ROOT);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= RegFlagCertificateKey | RegFlagSecurityKey | RegFlagHighRisk;
    }

    //
    // Policies
    //
    RtlInitUnicodeString(&testPath, SHADOWSTRIKE_REG_POLICIES);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= RegFlagSecurityKey;
    }

    //
    // Self-protection keys
    //
    RtlInitUnicodeString(&testPath, SHADOWSTRIKE_REG_OUR_SERVICE);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= RegFlagProtectedKey;
    }

    RtlInitUnicodeString(&testPath, SHADOWSTRIKE_REG_OUR_SOFTWARE);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= RegFlagProtectedKey;
    }

    return flags;
}

// ============================================================================
// SELF-PROTECTION
// ============================================================================

_Use_decl_annotations_
BOOLEAN
ShadowStrikeCheckRegistrySelfProtection(
    _In_ PUNICODE_STRING RegistryPath,
    _In_ HANDLE ProcessId
    )
{
    PAGED_CODE();

    if (RegistryPath == NULL || RegistryPath->Buffer == NULL) {
        return FALSE;
    }

    //
    // Delegate to the unified self-protection module
    // This ensures consistent protection logic across all callbacks
    //
    return ShadowStrikeShouldBlockRegistryAccess(
        RegistryPath,
        RegNtPreSetValueKey,    // Use a write operation as baseline
        ProcessId
    );
}

// ============================================================================
// RANSOMWARE DETECTION
// ============================================================================

_Use_decl_annotations_
BOOLEAN
ShadowStrikeDetectRansomwareRegistryBehavior(
    _In_ PCUNICODE_STRING KeyPath,
    _In_opt_ PCUNICODE_STRING ValueName,
    _In_ SHADOWSTRIKE_REG_OPERATION Operation
    )
{
    UNICODE_STRING testPath;
    UNICODE_STRING startValue;
    BOOLEAN isRansomwareIndicator = FALSE;

    PAGED_CODE();

    if (KeyPath == NULL || KeyPath->Buffer == NULL) {
        return FALSE;
    }

    //
    // Only care about modifications
    //
    if (Operation != RegOpSetValue &&
        Operation != RegOpDeleteKey &&
        Operation != RegOpDeleteValue) {
        return FALSE;
    }

    //
    // Check VSS service manipulation
    //
    RtlInitUnicodeString(&testPath, SHADOWSTRIKE_REG_VSS_ADMIN);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        //
        // Check if disabling the service (Start value = 4)
        //
        if (ValueName != NULL) {
            RtlInitUnicodeString(&startValue, L"Start");
            if (RtlEqualUnicodeString(ValueName, &startValue, TRUE)) {
                isRansomwareIndicator = TRUE;
            }
        }

        if (Operation == RegOpDeleteKey || Operation == RegOpDeleteValue) {
            isRansomwareIndicator = TRUE;
        }
    }

    //
    // Check Windows Backup Engine
    //
    RtlInitUnicodeString(&testPath, SHADOWSTRIKE_REG_WBENGINE);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        if (Operation == RegOpSetValue ||
            Operation == RegOpDeleteKey ||
            Operation == RegOpDeleteValue) {
            isRansomwareIndicator = TRUE;
        }
    }

    //
    // Check Backup Exec
    //
    RtlInitUnicodeString(&testPath, SHADOWSTRIKE_REG_BACKUP_EXEC);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        if (Operation == RegOpSetValue ||
            Operation == RegOpDeleteKey) {
            isRansomwareIndicator = TRUE;
        }
    }

    if (isRansomwareIndicator) {
        InterlockedIncrement64(&g_RegistryMonitor.Statistics.RansomwareIndicators);
    }

    return isRansomwareIndicator;
}

// ============================================================================
// DEFENSE EVASION DETECTION
// ============================================================================

_Use_decl_annotations_
ULONG
ShadowStrikeDetectDefenseEvasionRegistry(
    _In_ PCUNICODE_STRING KeyPath,
    _In_opt_ PCUNICODE_STRING ValueName,
    _In_opt_ PVOID Data,
    _In_ ULONG DataSize
    )
{
    UNICODE_STRING testPath;
    UNICODE_STRING disableValue;
    ULONG threatIndicators = RegThreatNone;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(DataSize);

    if (KeyPath == NULL || KeyPath->Buffer == NULL) {
        return RegThreatNone;
    }

    //
    // Windows Defender tampering
    //
    RtlInitUnicodeString(&testPath, SHADOWSTRIKE_REG_WINDOWS_DEFENDER);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        threatIndicators |= RegThreatDefenseEvasion | RegThreatTampering;

        if (ValueName != NULL) {
            RtlInitUnicodeString(&disableValue, L"DisableAntiSpyware");
            if (RtlEqualUnicodeString(ValueName, &disableValue, TRUE)) {
                threatIndicators |= RegThreatDefenseEvasion;
            }

            RtlInitUnicodeString(&disableValue, L"DisableRealtimeMonitoring");
            if (RtlEqualUnicodeString(ValueName, &disableValue, TRUE)) {
                threatIndicators |= RegThreatDefenseEvasion;
            }
        }

        InterlockedIncrement64(&g_RegistryMonitor.Statistics.DefenseEvasionDetections);
    }

    //
    // Security Center tampering
    //
    RtlInitUnicodeString(&testPath, SHADOWSTRIKE_REG_SECURITY_CENTER);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        threatIndicators |= RegThreatDefenseEvasion;
        InterlockedIncrement64(&g_RegistryMonitor.Statistics.SecurityPolicyChanges);
    }

    //
    // Firewall tampering
    //
    RtlInitUnicodeString(&testPath, SHADOWSTRIKE_REG_FIREWALL);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        threatIndicators |= RegThreatDefenseEvasion;
        InterlockedIncrement64(&g_RegistryMonitor.Statistics.SecurityPolicyChanges);
    }

    //
    // Policy tampering
    //
    RtlInitUnicodeString(&testPath, SHADOWSTRIKE_REG_POLICIES);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        threatIndicators |= RegThreatDefenseEvasion;
    }

    return threatIndicators;
}

// ============================================================================
// SUSPICION SCORING
// ============================================================================

_Use_decl_annotations_
ULONG
ShadowStrikeCalculateRegistrySuspicionScore(
    _In_ PSHADOWSTRIKE_REG_OP_CONTEXT Context
    )
{
    ULONG score = 0;

    PAGED_CODE();

    if (Context == NULL) {
        return 0;
    }

    //
    // Base score from key classification
    //
    if (Context->KeyFlags & RegFlagHighRisk) {
        score += 40;
    }
    if (Context->KeyFlags & RegFlagPersistenceKey) {
        score += 20;
    }
    if (Context->KeyFlags & RegFlagSecurityKey) {
        score += 15;
    }
    if (Context->KeyFlags & RegFlagRunKey) {
        score += 10;
    }
    if (Context->KeyFlags & RegFlagIFEOKey) {
        score += 25;
    }
    if (Context->KeyFlags & RegFlagCertificateKey) {
        score += 20;
    }

    //
    // Operation type scoring
    //
    switch (Context->Operation) {
        case RegOpSetValue:
            score += 5;
            break;
        case RegOpDeleteKey:
        case RegOpDeleteValue:
            score += 10;
            break;
        case RegOpSetKeySecurity:
            score += 15;
            break;
        default:
            break;
    }

    //
    // Threat indicator scoring
    //
    if (Context->ThreatIndicators & RegThreatPersistence) {
        score += 15;
    }
    if (Context->ThreatIndicators & RegThreatDefenseEvasion) {
        score += 25;
    }
    if (Context->ThreatIndicators & RegThreatRansomware) {
        score += 35;
    }
    if (Context->ThreatIndicators & RegThreatTampering) {
        score += 30;
    }

    //
    // Process context scoring
    //
    if (!Context->IsSystem && !Context->IsService) {
        score += 5;
    }
    if (!Context->IsElevated) {
        //
        // Non-elevated process modifying sensitive keys is suspicious
        //
        if (Context->KeyFlags & (RegFlagServiceKey | RegFlagSecurityKey)) {
            score += 10;
        }
    }

    //
    // Cap at 100
    //
    if (score > 100) {
        score = 100;
    }

    return score;
}

// ============================================================================
// PERSISTENCE ANALYSIS
// ============================================================================

_Use_decl_annotations_
VOID
ShadowStrikeAnalyzeRegistryPersistence(
    _In_ PUNICODE_STRING RegistryPath,
    _In_ PUNICODE_STRING ValueName,
    _In_opt_ PVOID Data,
    _In_ ULONG DataSize,
    _In_ ULONG DataType
    )
{
    ULONG keyFlags;
    ULONG threatIndicators = RegThreatNone;
    BOOLEAN shouldNotify = FALSE;
    ULONG captureSize;

    PAGED_CODE();

    if (RegistryPath == NULL || RegistryPath->Buffer == NULL) {
        return;
    }

    //
    // Classify the key
    //
    keyFlags = ShadowStrikeClassifyRegistryKey(RegistryPath);

    //
    // Check for persistence indicators
    //
    if (keyFlags & RegFlagPersistenceKey) {
        threatIndicators |= RegThreatPersistence;
        shouldNotify = TRUE;
        InterlockedIncrement64(&g_RegistryMonitor.Statistics.PersistenceDetections);

        if (keyFlags & RegFlagRunKey) {
            InterlockedIncrement64(&g_RegistryMonitor.Statistics.RunKeyModifications);
        }
        if (keyFlags & RegFlagServiceKey) {
            InterlockedIncrement64(&g_RegistryMonitor.Statistics.ServiceCreations);
        }
        if (keyFlags & RegFlagIFEOKey) {
            InterlockedIncrement64(&g_RegistryMonitor.Statistics.IFEOModifications);
        }
    }

    //
    // Check for security-related modifications
    //
    if (keyFlags & RegFlagSecurityKey) {
        threatIndicators |= ShadowStrikeDetectDefenseEvasionRegistry(
            RegistryPath,
            ValueName,
            Data,
            DataSize
        );
        shouldNotify = TRUE;
    }

    //
    // Check for certificate modifications
    //
    if (keyFlags & RegFlagCertificateKey) {
        threatIndicators |= RegThreatPrivilegeEsc;
        shouldNotify = TRUE;
        InterlockedIncrement64(&g_RegistryMonitor.Statistics.CertificateStoreChanges);
    }

    //
    // Check for ransomware behavior
    //
    if (ShadowStrikeDetectRansomwareRegistryBehavior(RegistryPath, ValueName, RegOpSetValue)) {
        threatIndicators |= RegThreatRansomware;
        shouldNotify = TRUE;
    }

    //
    // Send notification if warranted
    //
    if (shouldNotify && g_RegistryMonitor.Config.DetailedNotificationsEnabled) {
        //
        // Rate limiting check
        //
        if (RegpCheckRateLimit()) {
            //
            // Cap data size for notification
            //
            captureSize = DataSize;
            if (captureSize > MAX_REGISTRY_DATA_SIZE) {
                captureSize = MAX_REGISTRY_DATA_SIZE;
            }

            ShadowStrikeSendRegistryNotification(
                PsGetCurrentProcessId(),
                PsGetCurrentThreadId(),
                (UINT8)RegOpSetValue,
                RegistryPath,
                ValueName,
                Data,
                captureSize,
                DataType
            );

            InterlockedIncrement64(&g_RegistryMonitor.Statistics.NotificationsSent);
        }
    }

    SHADOWSTRIKE_INC_STAT(TotalRegistryOperations);
}

// ============================================================================
// MAIN CALLBACK ROUTINE
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowStrikeRegistryCallbackRoutine(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    REG_NOTIFY_CLASS notifyClass;
    SHADOWSTRIKE_REG_OPERATION operation;
    UNICODE_STRING keyPath = {0};
    HANDLE processId;
    BOOLEAN blockOperation = FALSE;
    PVOID keyObject = NULL;
    ULONG keyFlags;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(CallbackContext);

    //
    // CRITICAL: Check driver readiness
    //
    if (!SHADOWSTRIKE_IS_READY()) {
        return STATUS_SUCCESS;
    }

    //
    // CRITICAL: Validate Argument1 (notify class)
    //
    if (Argument1 == NULL) {
        return STATUS_SUCCESS;
    }

    notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    operation = RegpNotifyClassToOperation(notifyClass);

    //
    // Filter to operations we care about
    //
    if (operation == RegOpNone) {
        return STATUS_SUCCESS;
    }

    //
    // Only process Pre-operations for blocking, Post for logging
    //
    switch (notifyClass) {
        case RegNtPreDeleteKey:
        case RegNtPreSetValueKey:
        case RegNtPreDeleteValueKey:
        case RegNtPreRenameKey:
        case RegNtPreCreateKeyEx:
        case RegNtPreSetKeySecurity:
            break;
        default:
            //
            // Not a pre-operation we handle
            //
            return STATUS_SUCCESS;
    }

    //
    // CRITICAL: Validate Argument2 before any dereference
    //
    if (Argument2 == NULL) {
        return STATUS_SUCCESS;
    }

    processId = PsGetCurrentProcessId();

    //
    // Extract key object based on operation type
    //
    switch (notifyClass) {
        case RegNtPreSetValueKey: {
            PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
            keyObject = info->Object;
            break;
        }
        case RegNtPreDeleteKey: {
            PREG_DELETE_KEY_INFORMATION info = (PREG_DELETE_KEY_INFORMATION)Argument2;
            keyObject = info->Object;
            break;
        }
        case RegNtPreDeleteValueKey: {
            PREG_DELETE_VALUE_KEY_INFORMATION info = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
            keyObject = info->Object;
            break;
        }
        case RegNtPreRenameKey: {
            PREG_RENAME_KEY_INFORMATION info = (PREG_RENAME_KEY_INFORMATION)Argument2;
            keyObject = info->Object;
            break;
        }
        case RegNtPreCreateKeyEx: {
            PREG_CREATE_KEY_INFORMATION info = (PREG_CREATE_KEY_INFORMATION)Argument2;
            keyObject = info->RootObject;
            break;
        }
        case RegNtPreSetKeySecurity: {
            PREG_SET_KEY_SECURITY_INFORMATION info = (PREG_SET_KEY_SECURITY_INFORMATION)Argument2;
            keyObject = info->Object;
            break;
        }
        default:
            return STATUS_SUCCESS;
    }

    if (keyObject == NULL) {
        return STATUS_SUCCESS;
    }

    //
    // Resolve key path
    //
    status = ShadowStrikeGetRegistryObjectPath(keyObject, &keyPath);
    if (!NT_SUCCESS(status)) {
        //
        // Path resolution failed - allow operation but log
        //
        InterlockedIncrement64(&g_RegistryMonitor.Statistics.PathResolutionErrors);
        return STATUS_SUCCESS;
    }

    //
    // UNCONDITIONAL: Self-protection check (not configurable for security)
    //
    if (ShadowStrikeShouldBlockRegistryAccess(&keyPath, notifyClass, processId)) {
        blockOperation = TRUE;
        InterlockedIncrement64(&g_RegistryMonitor.Statistics.SelfProtectionBlocks);
        SHADOWSTRIKE_INC_STAT(SelfProtectionBlocks);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] BLOCKED registry modification to protected key: %wZ (PID: %p, Op: %d)\n",
                   &keyPath, processId, (int)notifyClass);
    }

    //
    // Classification and analysis (if not already blocked)
    //
    if (!blockOperation && g_RegistryMonitor.Config.Enabled) {
        keyFlags = ShadowStrikeClassifyRegistryKey(&keyPath);

        //
        // Persistence detection for write operations
        //
        if (notifyClass == RegNtPreSetValueKey &&
            g_RegistryMonitor.Config.PersistenceMonitoringEnabled) {

            PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;

            ShadowStrikeAnalyzeRegistryPersistence(
                &keyPath,
                info->ValueName,
                info->Data,
                info->DataSize,
                info->Type
            );
        }

        //
        // Ransomware detection
        //
        if (ShadowStrikeDetectRansomwareRegistryBehavior(&keyPath, NULL, operation)) {
            if (g_RegistryMonitor.Config.BlockHighRiskOperations) {
                blockOperation = TRUE;
                InterlockedIncrement64(&g_RegistryMonitor.Statistics.ThreatBlocks);
            }
        }

        //
        // Update statistics based on operation
        //
        switch (operation) {
            case RegOpCreateKey:
                InterlockedIncrement64(&g_RegistryMonitor.Statistics.CreateKeyOperations);
                break;
            case RegOpDeleteKey:
                InterlockedIncrement64(&g_RegistryMonitor.Statistics.DeleteKeyOperations);
                break;
            case RegOpRenameKey:
                InterlockedIncrement64(&g_RegistryMonitor.Statistics.RenameKeyOperations);
                break;
            case RegOpSetValue:
                InterlockedIncrement64(&g_RegistryMonitor.Statistics.SetValueOperations);
                break;
            case RegOpDeleteValue:
                InterlockedIncrement64(&g_RegistryMonitor.Statistics.DeleteValueOperations);
                break;
            default:
                break;
        }

        InterlockedIncrement64(&g_RegistryMonitor.Statistics.TotalOperations);
    }

    //
    // Cleanup path buffer
    //
    if (keyPath.Buffer != NULL) {
        ExFreePoolWithTag(keyPath.Buffer, REG_PATH_TAG);
        keyPath.Buffer = NULL;
        keyPath.Length = 0;
        keyPath.MaximumLength = 0;
    }

    if (blockOperation) {
        InterlockedIncrement64(&g_RegistryMonitor.Statistics.TotalOperations);
        SHADOWSTRIKE_INC_STAT(RegistryOperationsBlocked);
        return STATUS_ACCESS_DENIED;
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// PROCESS CONTEXT MANAGEMENT
// ============================================================================

_Use_decl_annotations_
PSHADOWSTRIKE_REG_PROCESS_CONTEXT
ShadowStrikeGetRegistryProcessContext(
    _In_ HANDLE ProcessId
    )
{
    ULONG bucket;
    PLIST_ENTRY listEntry;
    PSHADOWSTRIKE_REG_PROCESS_CONTEXT context = NULL;
    PSHADOWSTRIKE_REG_PROCESS_CONTEXT newContext = NULL;
    NTSTATUS status;
    PEPROCESS process = NULL;

    PAGED_CODE();

    bucket = RegpHashProcessId(ProcessId) % REG_PROCESS_HASH_BUCKETS;

    //
    // First, try to find existing context (shared lock)
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_RegistryMonitor.ProcessHashLock);

    for (listEntry = g_RegistryMonitor.ProcessHashBuckets[bucket].Flink;
         listEntry != &g_RegistryMonitor.ProcessHashBuckets[bucket];
         listEntry = listEntry->Flink) {

        context = CONTAINING_RECORD(listEntry, SHADOWSTRIKE_REG_PROCESS_CONTEXT, HashEntry);

        if (context->ProcessId == ProcessId) {
            InterlockedIncrement(&context->RefCount);
            ExReleasePushLockShared(&g_RegistryMonitor.ProcessHashLock);
            KeLeaveCriticalRegion();
            return context;
        }
    }

    ExReleasePushLockShared(&g_RegistryMonitor.ProcessHashLock);
    KeLeaveCriticalRegion();

    //
    // Context not found - need to create one
    //
    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return NULL;
    }

    newContext = (PSHADOWSTRIKE_REG_PROCESS_CONTEXT)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(SHADOWSTRIKE_REG_PROCESS_CONTEXT),
        REG_PROCCTX_TAG
    );

    if (newContext == NULL) {
        ObDereferenceObject(process);
        InterlockedIncrement64(&g_RegistryMonitor.Statistics.ContextAllocationErrors);
        return NULL;
    }

    //
    // Initialize new context
    //
    newContext->ProcessId = ProcessId;
    newContext->Process = process;  // Transfer reference
    KeQuerySystemTime(&newContext->CreateTime);
    newContext->RefCount = 2;  // One for hash table, one for caller
    InitializeListHead(&newContext->ListEntry);
    InitializeListHead(&newContext->HashEntry);

    //
    // Insert into hash table (exclusive lock)
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_RegistryMonitor.ProcessHashLock);

    //
    // Double-check no one else added it while we were allocating
    //
    for (listEntry = g_RegistryMonitor.ProcessHashBuckets[bucket].Flink;
         listEntry != &g_RegistryMonitor.ProcessHashBuckets[bucket];
         listEntry = listEntry->Flink) {

        context = CONTAINING_RECORD(listEntry, SHADOWSTRIKE_REG_PROCESS_CONTEXT, HashEntry);

        if (context->ProcessId == ProcessId) {
            //
            // Someone else added it - use theirs
            //
            InterlockedIncrement(&context->RefCount);
            ExReleasePushLockExclusive(&g_RegistryMonitor.ProcessHashLock);
            KeLeaveCriticalRegion();

            //
            // Free our allocation
            //
            ObDereferenceObject(newContext->Process);
            ExFreePoolWithTag(newContext, REG_PROCCTX_TAG);

            return context;
        }
    }

    //
    // Insert our new context
    //
    InsertTailList(&g_RegistryMonitor.ProcessHashBuckets[bucket], &newContext->HashEntry);
    InterlockedIncrement(&g_RegistryMonitor.ProcessContextCount);

    ExReleasePushLockExclusive(&g_RegistryMonitor.ProcessHashLock);
    KeLeaveCriticalRegion();

    return newContext;
}

_Use_decl_annotations_
VOID
ShadowStrikeReleaseRegistryProcessContext(
    _In_ PSHADOWSTRIKE_REG_PROCESS_CONTEXT Context
    )
{
    LONG refCount;

    if (Context == NULL) {
        return;
    }

    refCount = InterlockedDecrement(&Context->RefCount);

    //
    // Note: We don't free on refcount=0 here because the hash table
    // holds a reference. Cleanup happens in ProcessTerminated or module cleanup.
    //
    UNREFERENCED_PARAMETER(refCount);
}

_Use_decl_annotations_
VOID
ShadowStrikeRegistryProcessTerminated(
    _In_ HANDLE ProcessId
    )
{
    ULONG bucket;
    PLIST_ENTRY listEntry;
    PSHADOWSTRIKE_REG_PROCESS_CONTEXT context = NULL;
    BOOLEAN found = FALSE;

    PAGED_CODE();

    bucket = RegpHashProcessId(ProcessId) % REG_PROCESS_HASH_BUCKETS;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_RegistryMonitor.ProcessHashLock);

    for (listEntry = g_RegistryMonitor.ProcessHashBuckets[bucket].Flink;
         listEntry != &g_RegistryMonitor.ProcessHashBuckets[bucket];
         listEntry = listEntry->Flink) {

        context = CONTAINING_RECORD(listEntry, SHADOWSTRIKE_REG_PROCESS_CONTEXT, HashEntry);

        if (context->ProcessId == ProcessId) {
            RemoveEntryList(&context->HashEntry);
            InterlockedDecrement(&g_RegistryMonitor.ProcessContextCount);
            found = TRUE;
            break;
        }
    }

    ExReleasePushLockExclusive(&g_RegistryMonitor.ProcessHashLock);
    KeLeaveCriticalRegion();

    if (found && context != NULL) {
        //
        // Release hash table's reference
        //
        if (InterlockedDecrement(&context->RefCount) == 0) {
            if (context->Process != NULL) {
                ObDereferenceObject(context->Process);
            }
            ExFreePoolWithTag(context, REG_PROCCTX_TAG);
        }
    }
}

// ============================================================================
// STATISTICS AND CONFIGURATION
// ============================================================================

_Use_decl_annotations_
VOID
ShadowStrikeGetRegistryStatistics(
    _Out_ PSHADOWSTRIKE_REG_STATISTICS Statistics
    )
{
    if (Statistics == NULL) {
        return;
    }

    //
    // Copy statistics - no lock needed for atomic reads
    //
    RtlCopyMemory(Statistics, &g_RegistryMonitor.Statistics, sizeof(SHADOWSTRIKE_REG_STATISTICS));
}

_Use_decl_annotations_
VOID
ShadowStrikeResetRegistryStatistics(
    VOID
    )
{
    RtlZeroMemory(&g_RegistryMonitor.Statistics, sizeof(SHADOWSTRIKE_REG_STATISTICS));
    KeQuerySystemTime(&g_RegistryMonitor.Statistics.StartTime);
}

_Use_decl_annotations_
VOID
ShadowStrikeUpdateRegistryConfig(
    _In_ PSHADOWSTRIKE_REG_CONFIG Config
    )
{
    PAGED_CODE();

    if (Config == NULL) {
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_RegistryMonitor.ConfigLock);

    RtlCopyMemory(&g_RegistryMonitor.Config, Config, sizeof(SHADOWSTRIKE_REG_CONFIG));

    ExReleasePushLockExclusive(&g_RegistryMonitor.ConfigLock);
    KeLeaveCriticalRegion();
}

_Use_decl_annotations_
VOID
ShadowStrikeGetRegistryConfig(
    _Out_ PSHADOWSTRIKE_REG_CONFIG Config
    )
{
    if (Config == NULL) {
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_RegistryMonitor.ConfigLock);

    RtlCopyMemory(Config, &g_RegistryMonitor.Config, sizeof(SHADOWSTRIKE_REG_CONFIG));

    ExReleasePushLockShared(&g_RegistryMonitor.ConfigLock);
    KeLeaveCriticalRegion();
}

// ============================================================================
// PROTECTED KEY MANAGEMENT
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowStrikeAddProtectedRegistryKey(
    _In_ PCUNICODE_STRING KeyPath,
    _In_ ULONG Flags
    )
{
    ULONG bucket;
    PREG_PROTECTED_KEY_ENTRY entry;
    PLIST_ENTRY listEntry;
    PREG_PROTECTED_KEY_ENTRY existingEntry;

    PAGED_CODE();

    if (KeyPath == NULL || KeyPath->Buffer == NULL || KeyPath->Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (KeyPath->Length >= sizeof(entry->PathBuffer)) {
        return STATUS_NAME_TOO_LONG;
    }

    if (g_RegistryMonitor.ProtectedKeyCount >= REG_MAX_PROTECTED_KEYS) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    bucket = RegpHashString(KeyPath) % REG_PROTECTED_KEY_HASH_BUCKETS;

    //
    // Check for existing entry
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_RegistryMonitor.ProtectedKeyLock);

    for (listEntry = g_RegistryMonitor.ProtectedKeyBuckets[bucket].Flink;
         listEntry != &g_RegistryMonitor.ProtectedKeyBuckets[bucket];
         listEntry = listEntry->Flink) {

        existingEntry = CONTAINING_RECORD(listEntry, REG_PROTECTED_KEY_ENTRY, HashLink);

        if (RtlEqualUnicodeString(&existingEntry->KeyPath, KeyPath, TRUE)) {
            //
            // Already exists - update flags
            //
            existingEntry->Flags = Flags;
            ExReleasePushLockExclusive(&g_RegistryMonitor.ProtectedKeyLock);
            KeLeaveCriticalRegion();
            return STATUS_SUCCESS;
        }
    }

    //
    // Allocate new entry
    //
    entry = (PREG_PROTECTED_KEY_ENTRY)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(REG_PROTECTED_KEY_ENTRY),
        REG_HASH_TAG
    );

    if (entry == NULL) {
        ExReleasePushLockExclusive(&g_RegistryMonitor.ProtectedKeyLock);
        KeLeaveCriticalRegion();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize entry
    //
    entry->Flags = Flags;
    entry->KeyPath.Buffer = entry->PathBuffer;
    entry->KeyPath.Length = KeyPath->Length;
    entry->KeyPath.MaximumLength = sizeof(entry->PathBuffer);
    RtlCopyMemory(entry->PathBuffer, KeyPath->Buffer, KeyPath->Length);

    //
    // Insert into hash table
    //
    InsertTailList(&g_RegistryMonitor.ProtectedKeyBuckets[bucket], &entry->HashLink);
    InterlockedIncrement(&g_RegistryMonitor.ProtectedKeyCount);

    ExReleasePushLockExclusive(&g_RegistryMonitor.ProtectedKeyLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
BOOLEAN
ShadowStrikeRemoveProtectedRegistryKey(
    _In_ PCUNICODE_STRING KeyPath
    )
{
    ULONG bucket;
    PLIST_ENTRY listEntry;
    PREG_PROTECTED_KEY_ENTRY entry;
    BOOLEAN found = FALSE;

    PAGED_CODE();

    if (KeyPath == NULL || KeyPath->Buffer == NULL) {
        return FALSE;
    }

    bucket = RegpHashString(KeyPath) % REG_PROTECTED_KEY_HASH_BUCKETS;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_RegistryMonitor.ProtectedKeyLock);

    for (listEntry = g_RegistryMonitor.ProtectedKeyBuckets[bucket].Flink;
         listEntry != &g_RegistryMonitor.ProtectedKeyBuckets[bucket];
         listEntry = listEntry->Flink) {

        entry = CONTAINING_RECORD(listEntry, REG_PROTECTED_KEY_ENTRY, HashLink);

        if (RtlEqualUnicodeString(&entry->KeyPath, KeyPath, TRUE)) {
            RemoveEntryList(&entry->HashLink);
            InterlockedDecrement(&g_RegistryMonitor.ProtectedKeyCount);
            found = TRUE;
            break;
        }
    }

    ExReleasePushLockExclusive(&g_RegistryMonitor.ProtectedKeyLock);
    KeLeaveCriticalRegion();

    if (found) {
        ExFreePoolWithTag(entry, REG_HASH_TAG);
    }

    return found;
}

_Use_decl_annotations_
BOOLEAN
ShadowStrikeIsRegistryKeyProtected(
    _In_ PCUNICODE_STRING KeyPath
    )
{
    ULONG bucket;
    PLIST_ENTRY listEntry;
    PREG_PROTECTED_KEY_ENTRY entry;
    BOOLEAN found = FALSE;

    if (KeyPath == NULL || KeyPath->Buffer == NULL) {
        return FALSE;
    }

    bucket = RegpHashString(KeyPath) % REG_PROTECTED_KEY_HASH_BUCKETS;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_RegistryMonitor.ProtectedKeyLock);

    for (listEntry = g_RegistryMonitor.ProtectedKeyBuckets[bucket].Flink;
         listEntry != &g_RegistryMonitor.ProtectedKeyBuckets[bucket];
         listEntry = listEntry->Flink) {

        entry = CONTAINING_RECORD(listEntry, REG_PROTECTED_KEY_ENTRY, HashLink);

        //
        // Check for exact match or prefix match
        //
        if (RtlEqualUnicodeString(&entry->KeyPath, KeyPath, TRUE) ||
            RtlPrefixUnicodeString(&entry->KeyPath, KeyPath, TRUE)) {
            found = TRUE;
            break;
        }
    }

    ExReleasePushLockShared(&g_RegistryMonitor.ProtectedKeyLock);
    KeLeaveCriticalRegion();

    return found;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

PCWSTR
ShadowStrikeGetRegistryOperationName(
    _In_ SHADOWSTRIKE_REG_OPERATION Operation
    )
{
    static const PCWSTR OperationNames[] = {
        L"None",
        L"CreateKey",
        L"OpenKey",
        L"DeleteKey",
        L"RenameKey",
        L"SetValue",
        L"DeleteValue",
        L"QueryValue",
        L"EnumerateKey",
        L"EnumerateValue",
        L"QueryKey",
        L"SetKeySecurity"
    };

    if (Operation >= RegOpMax) {
        return L"Unknown";
    }

    return OperationNames[Operation];
}

PCWSTR
ShadowStrikeGetRegistryDataTypeName(
    _In_ ULONG DataType
    )
{
    switch (DataType) {
        case REG_NONE:
            return L"REG_NONE";
        case REG_SZ:
            return L"REG_SZ";
        case REG_EXPAND_SZ:
            return L"REG_EXPAND_SZ";
        case REG_BINARY:
            return L"REG_BINARY";
        case REG_DWORD:
            return L"REG_DWORD";
        case REG_DWORD_BIG_ENDIAN:
            return L"REG_DWORD_BIG_ENDIAN";
        case REG_LINK:
            return L"REG_LINK";
        case REG_MULTI_SZ:
            return L"REG_MULTI_SZ";
        case REG_RESOURCE_LIST:
            return L"REG_RESOURCE_LIST";
        case REG_FULL_RESOURCE_DESCRIPTOR:
            return L"REG_FULL_RESOURCE_DESCRIPTOR";
        case REG_RESOURCE_REQUIREMENTS_LIST:
            return L"REG_RESOURCE_REQUIREMENTS_LIST";
        case REG_QWORD:
            return L"REG_QWORD";
        default:
            return L"Unknown";
    }
}
