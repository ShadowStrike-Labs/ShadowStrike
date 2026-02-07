/*++
    ShadowStrike Next-Generation Antivirus
    Module: ETWProvider.c

    Purpose: Enterprise-grade ETW (Event Tracing for Windows) provider for
             high-performance telemetry streaming, SIEM integration, and
             real-time diagnostics.

    Architecture:
    - Kernel-mode ETW provider registration via EtwRegister
    - Event descriptor-based event writing
    - Rate limiting to prevent event flooding
    - Lookaside list for efficient event buffer allocation
    - Keywords and levels for granular event filtering
    - Statistics tracking for monitoring and diagnostics

    MITRE ATT&CK Coverage:
    - T1059: Command and Scripting Interpreter (process execution logging)
    - T1055: Process Injection (injection detection events)
    - T1071: Application Layer Protocol (network event logging)

    Copyright (c) ShadowStrike Team
--*/

#include "ETWProvider.h"
#include "../Utilities/MemoryUtils.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, EtwProviderInitialize)
#pragma alloc_text(PAGE, EtwProviderShutdown)
#endif

//=============================================================================
// Internal Constants
//=============================================================================

#define ETW_SIGNATURE                   'WTEZ'  // 'ZETW' reversed
#define ETW_MAX_EVENTS_PER_SECOND       10000
#define ETW_EVENT_BUFFER_SIZE           4096
#define ETW_LOOKASIDE_DEPTH             256
#define ETW_RATE_LIMIT_WINDOW_MS        1000

//=============================================================================
// Global State
//=============================================================================

static ETW_PROVIDER_GLOBALS g_EtwGlobals = { 0 };

//=============================================================================
// Forward Declarations
//=============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
EtwpCheckRateLimit(
    VOID
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
EtwpUpdateStatistics(
    _In_ ULONG EventSize,
    _In_ BOOLEAN Success
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
EtwpFillCommonHeader(
    _Out_ PETW_EVENT_COMMON Common,
    _In_ UINT32 ProcessId
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static NTSTATUS
EtwpWriteEvent(
    _In_ PCEVENT_DESCRIPTOR EventDescriptor,
    _In_ ULONG UserDataCount,
    _In_reads_opt_(UserDataCount) PEVENT_DATA_DESCRIPTOR UserData
    );

static VOID NTAPI
EtwpEnableCallback(
    _In_ LPCGUID SourceId,
    _In_ ULONG IsEnabled,
    _In_ UCHAR Level,
    _In_ ULONGLONG MatchAnyKeyword,
    _In_ ULONGLONG MatchAllKeyword,
    _In_opt_ PEVENT_FILTER_DESCRIPTOR FilterData,
    _In_opt_ PVOID CallbackContext
    );

//=============================================================================
// Event Descriptors
//=============================================================================

//
// Process Events
//
static const EVENT_DESCRIPTOR EtwDescriptor_ProcessCreate = {
    EtwEventId_ProcessCreate,       // Id
    0,                              // Version
    0,                              // Channel
    ETW_LEVEL_INFORMATIONAL,        // Level
    0,                              // Opcode
    0,                              // Task
    ETW_KEYWORD_PROCESS             // Keyword
};

static const EVENT_DESCRIPTOR EtwDescriptor_ProcessTerminate = {
    EtwEventId_ProcessTerminate,
    0, 0, ETW_LEVEL_INFORMATIONAL, 0, 0, ETW_KEYWORD_PROCESS
};

static const EVENT_DESCRIPTOR EtwDescriptor_ProcessSuspicious = {
    EtwEventId_ProcessSuspicious,
    0, 0, ETW_LEVEL_WARNING, 0, 0, ETW_KEYWORD_PROCESS | ETW_KEYWORD_THREAT
};

static const EVENT_DESCRIPTOR EtwDescriptor_ProcessBlocked = {
    EtwEventId_ProcessBlocked,
    0, 0, ETW_LEVEL_WARNING, 0, 0, ETW_KEYWORD_PROCESS | ETW_KEYWORD_THREAT
};

//
// File Events
//
static const EVENT_DESCRIPTOR EtwDescriptor_FileCreate = {
    EtwEventId_FileCreate,
    0, 0, ETW_LEVEL_VERBOSE, 0, 0, ETW_KEYWORD_FILE
};

static const EVENT_DESCRIPTOR EtwDescriptor_FileWrite = {
    EtwEventId_FileWrite,
    0, 0, ETW_LEVEL_VERBOSE, 0, 0, ETW_KEYWORD_FILE
};

static const EVENT_DESCRIPTOR EtwDescriptor_FileScanResult = {
    EtwEventId_FileScanResult,
    0, 0, ETW_LEVEL_INFORMATIONAL, 0, 0, ETW_KEYWORD_FILE | ETW_KEYWORD_THREAT
};

static const EVENT_DESCRIPTOR EtwDescriptor_FileBlocked = {
    EtwEventId_FileBlocked,
    0, 0, ETW_LEVEL_WARNING, 0, 0, ETW_KEYWORD_FILE | ETW_KEYWORD_THREAT
};

static const EVENT_DESCRIPTOR EtwDescriptor_FileQuarantined = {
    EtwEventId_FileQuarantined,
    0, 0, ETW_LEVEL_WARNING, 0, 0, ETW_KEYWORD_FILE | ETW_KEYWORD_THREAT
};

//
// Network Events
//
static const EVENT_DESCRIPTOR EtwDescriptor_NetworkConnect = {
    EtwEventId_NetworkConnect,
    0, 0, ETW_LEVEL_INFORMATIONAL, 0, 0, ETW_KEYWORD_NETWORK
};

static const EVENT_DESCRIPTOR EtwDescriptor_NetworkBlocked = {
    EtwEventId_NetworkBlocked,
    0, 0, ETW_LEVEL_WARNING, 0, 0, ETW_KEYWORD_NETWORK | ETW_KEYWORD_THREAT
};

static const EVENT_DESCRIPTOR EtwDescriptor_C2Detected = {
    EtwEventId_C2Detected,
    0, 0, ETW_LEVEL_CRITICAL, 0, 0, ETW_KEYWORD_NETWORK | ETW_KEYWORD_THREAT | ETW_KEYWORD_SECURITY
};

//
// Behavioral Events
//
static const EVENT_DESCRIPTOR EtwDescriptor_BehaviorAlert = {
    EtwEventId_BehaviorAlert,
    0, 0, ETW_LEVEL_WARNING, 0, 0, ETW_KEYWORD_BEHAVIOR | ETW_KEYWORD_THREAT
};

static const EVENT_DESCRIPTOR EtwDescriptor_AttackChainStarted = {
    EtwEventId_AttackChainStarted,
    0, 0, ETW_LEVEL_WARNING, 0, 0, ETW_KEYWORD_BEHAVIOR | ETW_KEYWORD_THREAT
};

static const EVENT_DESCRIPTOR EtwDescriptor_MitreDetection = {
    EtwEventId_MitreDetection,
    0, 0, ETW_LEVEL_WARNING, 0, 0, ETW_KEYWORD_BEHAVIOR | ETW_KEYWORD_THREAT
};

//
// Security Events
//
static const EVENT_DESCRIPTOR EtwDescriptor_TamperAttempt = {
    EtwEventId_TamperAttempt,
    0, 0, ETW_LEVEL_CRITICAL, 0, 0, ETW_KEYWORD_SECURITY | ETW_KEYWORD_THREAT
};

static const EVENT_DESCRIPTOR EtwDescriptor_EvasionAttempt = {
    EtwEventId_EvasionAttempt,
    0, 0, ETW_LEVEL_WARNING, 0, 0, ETW_KEYWORD_SECURITY | ETW_KEYWORD_THREAT
};

static const EVENT_DESCRIPTOR EtwDescriptor_DirectSyscall = {
    EtwEventId_DirectSyscall,
    0, 0, ETW_LEVEL_WARNING, 0, 0, ETW_KEYWORD_SECURITY
};

//
// Diagnostic Events
//
static const EVENT_DESCRIPTOR EtwDescriptor_DriverStarted = {
    EtwEventId_DriverStarted,
    0, 0, ETW_LEVEL_INFORMATIONAL, 0, 0, ETW_KEYWORD_DIAGNOSTIC
};

static const EVENT_DESCRIPTOR EtwDescriptor_DriverStopping = {
    EtwEventId_DriverStopping,
    0, 0, ETW_LEVEL_INFORMATIONAL, 0, 0, ETW_KEYWORD_DIAGNOSTIC
};

static const EVENT_DESCRIPTOR EtwDescriptor_Heartbeat = {
    EtwEventId_Heartbeat,
    0, 0, ETW_LEVEL_VERBOSE, 0, 0, ETW_KEYWORD_DIAGNOSTIC | ETW_KEYWORD_TELEMETRY
};

static const EVENT_DESCRIPTOR EtwDescriptor_PerformanceStats = {
    EtwEventId_PerformanceStats,
    0, 0, ETW_LEVEL_INFORMATIONAL, 0, 0, ETW_KEYWORD_DIAGNOSTIC | ETW_KEYWORD_TELEMETRY
};

static const EVENT_DESCRIPTOR EtwDescriptor_ComponentHealth = {
    EtwEventId_ComponentHealth,
    0, 0, ETW_LEVEL_INFORMATIONAL, 0, 0, ETW_KEYWORD_DIAGNOSTIC
};

static const EVENT_DESCRIPTOR EtwDescriptor_Error = {
    EtwEventId_Error,
    0, 0, ETW_LEVEL_ERROR, 0, 0, ETW_KEYWORD_DIAGNOSTIC
};

//=============================================================================
// Initialization / Shutdown
//=============================================================================

_Use_decl_annotations_
NTSTATUS
EtwProviderInitialize(
    VOID
    )
/*++

Routine Description:

    Initializes the ETW provider subsystem. Registers with ETW and
    prepares event buffer infrastructure.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    NTSTATUS status;

    PAGED_CODE();

    if (g_EtwGlobals.Initialized) {
        return STATUS_ALREADY_INITIALIZED;
    }

    RtlZeroMemory(&g_EtwGlobals, sizeof(ETW_PROVIDER_GLOBALS));

    //
    // Register the ETW provider
    //
    status = EtwRegister(
        &SHADOWSTRIKE_ETW_PROVIDER_GUID,
        EtwpEnableCallback,
        NULL,
        &g_EtwGlobals.ProviderHandle
        );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Initialize lookaside list for event buffers
    //
    ExInitializeNPagedLookasideList(
        &g_EtwGlobals.EventBufferLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        ETW_EVENT_BUFFER_SIZE,
        ETW_POOL_TAG_BUFFER,
        ETW_LOOKASIDE_DEPTH
        );

    //
    // Initialize rate limiting
    //
    g_EtwGlobals.MaxEventsPerSecond = ETW_MAX_EVENTS_PER_SECOND;
    g_EtwGlobals.EventsThisSecond = 0;
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&g_EtwGlobals.CurrentSecondStart);

    //
    // Initialize statistics
    //
    g_EtwGlobals.EventsWritten = 0;
    g_EtwGlobals.EventsDropped = 0;
    g_EtwGlobals.BytesWritten = 0;

    //
    // Mark as initialized
    //
    g_EtwGlobals.Initialized = TRUE;
    g_EtwGlobals.Enabled = FALSE;  // Will be set by enable callback

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
EtwProviderShutdown(
    VOID
    )
/*++

Routine Description:

    Shuts down the ETW provider. Unregisters from ETW and releases
    all resources.

--*/
{
    PAGED_CODE();

    if (!g_EtwGlobals.Initialized) {
        return;
    }

    g_EtwGlobals.Initialized = FALSE;
    g_EtwGlobals.Enabled = FALSE;

    //
    // Unregister from ETW
    //
    if (g_EtwGlobals.ProviderHandle != 0) {
        EtwUnregister(g_EtwGlobals.ProviderHandle);
        g_EtwGlobals.ProviderHandle = 0;
    }

    //
    // Cleanup lookaside list
    //
    ExDeleteNPagedLookasideList(&g_EtwGlobals.EventBufferLookaside);
}


_Use_decl_annotations_
BOOLEAN
EtwProviderIsEnabled(
    _In_ UCHAR Level,
    _In_ ULONGLONG Keywords
    )
/*++

Routine Description:

    Checks if the ETW provider is enabled for the specified level and keywords.

Arguments:

    Level - Event level to check.
    Keywords - Event keywords to check.

Return Value:

    TRUE if enabled, FALSE otherwise.

--*/
{
    if (!g_EtwGlobals.Initialized || !g_EtwGlobals.Enabled) {
        return FALSE;
    }

    if (g_EtwGlobals.ProviderHandle == 0) {
        return FALSE;
    }

    //
    // Check if level and keywords match enabled settings
    //
    if (Level > g_EtwGlobals.EnableLevel) {
        return FALSE;
    }

    if ((Keywords & g_EtwGlobals.EnableFlags) == 0) {
        return FALSE;
    }

    return TRUE;
}


//=============================================================================
// Event Writing - Process Events
//=============================================================================

_Use_decl_annotations_
NTSTATUS
EtwWriteProcessEvent(
    _In_ SHADOWSTRIKE_ETW_EVENT_ID EventId,
    _In_ UINT32 ProcessId,
    _In_ UINT32 ParentProcessId,
    _In_opt_ PCUNICODE_STRING ImagePath,
    _In_opt_ PCUNICODE_STRING CommandLine,
    _In_ UINT32 ThreatScore,
    _In_ UINT32 Flags
    )
/*++

Routine Description:

    Writes a process-related ETW event.

--*/
{
    NTSTATUS status;
    PETW_PROCESS_EVENT event = NULL;
    PCEVENT_DESCRIPTOR descriptor;
    EVENT_DATA_DESCRIPTOR dataDescriptor;

    if (!g_EtwGlobals.Initialized || !g_EtwGlobals.Enabled) {
        return STATUS_SUCCESS;  // Silently succeed if not enabled
    }

    //
    // Rate limit check
    //
    if (!EtwpCheckRateLimit()) {
        InterlockedIncrement64(&g_EtwGlobals.EventsDropped);
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Select event descriptor based on event ID
    //
    switch (EventId) {
        case EtwEventId_ProcessCreate:
            descriptor = &EtwDescriptor_ProcessCreate;
            break;
        case EtwEventId_ProcessTerminate:
            descriptor = &EtwDescriptor_ProcessTerminate;
            break;
        case EtwEventId_ProcessSuspicious:
            descriptor = &EtwDescriptor_ProcessSuspicious;
            break;
        case EtwEventId_ProcessBlocked:
            descriptor = &EtwDescriptor_ProcessBlocked;
            break;
        default:
            return STATUS_INVALID_PARAMETER;
    }

    //
    // Check if this event type is enabled
    //
    if (!EtwProviderIsEnabled(descriptor->Level, descriptor->Keyword)) {
        return STATUS_SUCCESS;
    }

    //
    // Allocate event buffer from lookaside
    //
    event = (PETW_PROCESS_EVENT)ExAllocateFromNPagedLookasideList(
        &g_EtwGlobals.EventBufferLookaside
        );

    if (event == NULL) {
        InterlockedIncrement64(&g_EtwGlobals.EventsDropped);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(event, sizeof(ETW_PROCESS_EVENT));

    //
    // Fill common header
    //
    EtwpFillCommonHeader(&event->Common, ProcessId);

    //
    // Fill process-specific fields
    //
    event->ParentProcessId = ParentProcessId;
    event->Flags = Flags;
    event->ThreatScore = ThreatScore;
    event->ExitCode = 0;

    //
    // Copy image path (truncate if necessary)
    //
    if (ImagePath != NULL && ImagePath->Buffer != NULL && ImagePath->Length > 0) {
        USHORT copyLen = min(ImagePath->Length, sizeof(event->ImagePath) - sizeof(WCHAR));
        RtlCopyMemory(event->ImagePath, ImagePath->Buffer, copyLen);
        event->ImagePath[copyLen / sizeof(WCHAR)] = L'\0';
    }

    //
    // Copy command line (truncate if necessary)
    //
    if (CommandLine != NULL && CommandLine->Buffer != NULL && CommandLine->Length > 0) {
        USHORT copyLen = min(CommandLine->Length, sizeof(event->CommandLine) - sizeof(WCHAR));
        RtlCopyMemory(event->CommandLine, CommandLine->Buffer, copyLen);
        event->CommandLine[copyLen / sizeof(WCHAR)] = L'\0';
    }

    //
    // Write the event
    //
    EventDataDescCreate(&dataDescriptor, event, sizeof(ETW_PROCESS_EVENT));

    status = EtwpWriteEvent(descriptor, 1, &dataDescriptor);

    EtwpUpdateStatistics(sizeof(ETW_PROCESS_EVENT), NT_SUCCESS(status));

    ExFreeToNPagedLookasideList(&g_EtwGlobals.EventBufferLookaside, event);

    return status;
}


//=============================================================================
// Event Writing - File Events
//=============================================================================

_Use_decl_annotations_
NTSTATUS
EtwWriteFileEvent(
    _In_ SHADOWSTRIKE_ETW_EVENT_ID EventId,
    _In_ UINT32 ProcessId,
    _In_ PCUNICODE_STRING FilePath,
    _In_ UINT32 Operation,
    _In_ UINT64 FileSize,
    _In_ UINT32 Verdict,
    _In_opt_ PCWSTR ThreatName,
    _In_ UINT32 ThreatScore
    )
/*++

Routine Description:

    Writes a file-related ETW event.

--*/
{
    NTSTATUS status;
    PETW_FILE_EVENT event = NULL;
    PCEVENT_DESCRIPTOR descriptor;
    EVENT_DATA_DESCRIPTOR dataDescriptor;

    if (!g_EtwGlobals.Initialized || !g_EtwGlobals.Enabled) {
        return STATUS_SUCCESS;
    }

    if (!EtwpCheckRateLimit()) {
        InterlockedIncrement64(&g_EtwGlobals.EventsDropped);
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Select event descriptor
    //
    switch (EventId) {
        case EtwEventId_FileCreate:
            descriptor = &EtwDescriptor_FileCreate;
            break;
        case EtwEventId_FileWrite:
            descriptor = &EtwDescriptor_FileWrite;
            break;
        case EtwEventId_FileScanResult:
            descriptor = &EtwDescriptor_FileScanResult;
            break;
        case EtwEventId_FileBlocked:
            descriptor = &EtwDescriptor_FileBlocked;
            break;
        case EtwEventId_FileQuarantined:
            descriptor = &EtwDescriptor_FileQuarantined;
            break;
        default:
            return STATUS_INVALID_PARAMETER;
    }

    if (!EtwProviderIsEnabled(descriptor->Level, descriptor->Keyword)) {
        return STATUS_SUCCESS;
    }

    event = (PETW_FILE_EVENT)ExAllocateFromNPagedLookasideList(
        &g_EtwGlobals.EventBufferLookaside
        );

    if (event == NULL) {
        InterlockedIncrement64(&g_EtwGlobals.EventsDropped);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(event, sizeof(ETW_FILE_EVENT));

    EtwpFillCommonHeader(&event->Common, ProcessId);

    event->Operation = Operation;
    event->Disposition = 0;
    event->FileSize = FileSize;
    event->Verdict = Verdict;
    event->ThreatScore = ThreatScore;

    //
    // Copy file path
    //
    if (FilePath != NULL && FilePath->Buffer != NULL && FilePath->Length > 0) {
        USHORT copyLen = min(FilePath->Length, sizeof(event->FilePath) - sizeof(WCHAR));
        RtlCopyMemory(event->FilePath, FilePath->Buffer, copyLen);
        event->FilePath[copyLen / sizeof(WCHAR)] = L'\0';
    }

    //
    // Copy threat name
    //
    if (ThreatName != NULL) {
        size_t threatNameLen = wcslen(ThreatName);
        SIZE_T copyLen = min(threatNameLen * sizeof(WCHAR), sizeof(event->ThreatName) - sizeof(WCHAR));
        RtlCopyMemory(event->ThreatName, ThreatName, copyLen);
        event->ThreatName[copyLen / sizeof(WCHAR)] = L'\0';
    }

    EventDataDescCreate(&dataDescriptor, event, sizeof(ETW_FILE_EVENT));

    status = EtwpWriteEvent(descriptor, 1, &dataDescriptor);

    EtwpUpdateStatistics(sizeof(ETW_FILE_EVENT), NT_SUCCESS(status));

    ExFreeToNPagedLookasideList(&g_EtwGlobals.EventBufferLookaside, event);

    return status;
}


//=============================================================================
// Event Writing - Network Events
//=============================================================================

_Use_decl_annotations_
NTSTATUS
EtwWriteNetworkEvent(
    _In_ SHADOWSTRIKE_ETW_EVENT_ID EventId,
    _In_ PETW_NETWORK_EVENT Event
    )
/*++

Routine Description:

    Writes a network-related ETW event.

--*/
{
    NTSTATUS status;
    PCEVENT_DESCRIPTOR descriptor;
    EVENT_DATA_DESCRIPTOR dataDescriptor;

    if (!g_EtwGlobals.Initialized || !g_EtwGlobals.Enabled) {
        return STATUS_SUCCESS;
    }

    if (Event == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!EtwpCheckRateLimit()) {
        InterlockedIncrement64(&g_EtwGlobals.EventsDropped);
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Select event descriptor
    //
    switch (EventId) {
        case EtwEventId_NetworkConnect:
        case EtwEventId_NetworkListen:
        case EtwEventId_DnsQuery:
            descriptor = &EtwDescriptor_NetworkConnect;
            break;
        case EtwEventId_NetworkBlocked:
        case EtwEventId_ExfiltrationDetected:
            descriptor = &EtwDescriptor_NetworkBlocked;
            break;
        case EtwEventId_C2Detected:
            descriptor = &EtwDescriptor_C2Detected;
            break;
        default:
            return STATUS_INVALID_PARAMETER;
    }

    if (!EtwProviderIsEnabled(descriptor->Level, descriptor->Keyword)) {
        return STATUS_SUCCESS;
    }

    //
    // Ensure common header is filled
    //
    if (Event->Common.Timestamp == 0) {
        EtwpFillCommonHeader(&Event->Common, Event->Common.ProcessId);
    }

    EventDataDescCreate(&dataDescriptor, Event, sizeof(ETW_NETWORK_EVENT));

    status = EtwpWriteEvent(descriptor, 1, &dataDescriptor);

    EtwpUpdateStatistics(sizeof(ETW_NETWORK_EVENT), NT_SUCCESS(status));

    return status;
}


//=============================================================================
// Event Writing - Behavioral Events
//=============================================================================

_Use_decl_annotations_
NTSTATUS
EtwWriteBehaviorEvent(
    _In_ SHADOWSTRIKE_ETW_EVENT_ID EventId,
    _In_ UINT32 ProcessId,
    _In_ UINT32 BehaviorType,
    _In_ UINT32 Category,
    _In_ UINT64 ChainId,
    _In_ UINT32 MitreTechnique,
    _In_ UINT32 ThreatScore,
    _In_opt_ PCWSTR Description
    )
/*++

Routine Description:

    Writes a behavioral analysis ETW event.

--*/
{
    NTSTATUS status;
    PETW_BEHAVIOR_EVENT event = NULL;
    PCEVENT_DESCRIPTOR descriptor;
    EVENT_DATA_DESCRIPTOR dataDescriptor;

    if (!g_EtwGlobals.Initialized || !g_EtwGlobals.Enabled) {
        return STATUS_SUCCESS;
    }

    if (!EtwpCheckRateLimit()) {
        InterlockedIncrement64(&g_EtwGlobals.EventsDropped);
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Select event descriptor
    //
    switch (EventId) {
        case EtwEventId_BehaviorAlert:
            descriptor = &EtwDescriptor_BehaviorAlert;
            break;
        case EtwEventId_AttackChainStarted:
        case EtwEventId_AttackChainUpdated:
        case EtwEventId_AttackChainCompleted:
            descriptor = &EtwDescriptor_AttackChainStarted;
            break;
        case EtwEventId_MitreDetection:
            descriptor = &EtwDescriptor_MitreDetection;
            break;
        default:
            return STATUS_INVALID_PARAMETER;
    }

    if (!EtwProviderIsEnabled(descriptor->Level, descriptor->Keyword)) {
        return STATUS_SUCCESS;
    }

    event = (PETW_BEHAVIOR_EVENT)ExAllocateFromNPagedLookasideList(
        &g_EtwGlobals.EventBufferLookaside
        );

    if (event == NULL) {
        InterlockedIncrement64(&g_EtwGlobals.EventsDropped);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(event, sizeof(ETW_BEHAVIOR_EVENT));

    EtwpFillCommonHeader(&event->Common, ProcessId);

    event->BehaviorType = BehaviorType;
    event->Category = Category;
    event->ThreatScore = ThreatScore;
    event->Confidence = 0;  // To be set by caller if needed
    event->ChainId = ChainId;
    event->MitreTechnique = MitreTechnique;
    event->MitreTactic = 0;  // Derived from technique if needed

    //
    // Copy description
    //
    if (Description != NULL) {
        size_t descLen = wcslen(Description);
        SIZE_T copyLen = min(descLen * sizeof(WCHAR), sizeof(event->Description) - sizeof(WCHAR));
        RtlCopyMemory(event->Description, Description, copyLen);
        event->Description[copyLen / sizeof(WCHAR)] = L'\0';
    }

    EventDataDescCreate(&dataDescriptor, event, sizeof(ETW_BEHAVIOR_EVENT));

    status = EtwpWriteEvent(descriptor, 1, &dataDescriptor);

    EtwpUpdateStatistics(sizeof(ETW_BEHAVIOR_EVENT), NT_SUCCESS(status));

    ExFreeToNPagedLookasideList(&g_EtwGlobals.EventBufferLookaside, event);

    return status;
}


//=============================================================================
// Event Writing - Security Alerts
//=============================================================================

_Use_decl_annotations_
NTSTATUS
EtwWriteSecurityAlert(
    _In_ UINT32 AlertType,
    _In_ UINT32 Severity,
    _In_ UINT32 ProcessId,
    _In_ UINT64 ChainId,
    _In_ PCWSTR Title,
    _In_ PCWSTR Description,
    _In_opt_ PCWSTR ProcessPath,
    _In_opt_ PCWSTR TargetPath,
    _In_ UINT32 ThreatScore,
    _In_ UINT32 ResponseAction
    )
/*++

Routine Description:

    Writes a security alert ETW event for critical detections.

--*/
{
    NTSTATUS status;
    PETW_SECURITY_ALERT event = NULL;
    PCEVENT_DESCRIPTOR descriptor;
    EVENT_DATA_DESCRIPTOR dataDescriptor;

    if (!g_EtwGlobals.Initialized || !g_EtwGlobals.Enabled) {
        return STATUS_SUCCESS;
    }

    if (Title == NULL || Description == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!EtwpCheckRateLimit()) {
        InterlockedIncrement64(&g_EtwGlobals.EventsDropped);
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Select descriptor based on alert type
    //
    switch (AlertType) {
        case EtwEventId_TamperAttempt:
            descriptor = &EtwDescriptor_TamperAttempt;
            break;
        case EtwEventId_EvasionAttempt:
            descriptor = &EtwDescriptor_EvasionAttempt;
            break;
        case EtwEventId_DirectSyscall:
            descriptor = &EtwDescriptor_DirectSyscall;
            break;
        default:
            descriptor = &EtwDescriptor_TamperAttempt;
            break;
    }

    if (!EtwProviderIsEnabled(descriptor->Level, descriptor->Keyword)) {
        return STATUS_SUCCESS;
    }

    event = (PETW_SECURITY_ALERT)ExAllocateFromNPagedLookasideList(
        &g_EtwGlobals.EventBufferLookaside
        );

    if (event == NULL) {
        InterlockedIncrement64(&g_EtwGlobals.EventsDropped);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(event, sizeof(ETW_SECURITY_ALERT));

    EtwpFillCommonHeader(&event->Common, ProcessId);

    event->AlertType = AlertType;
    event->Severity = Severity;
    event->ThreatScore = ThreatScore;
    event->ResponseAction = ResponseAction;
    event->ChainId = ChainId;

    //
    // Copy strings with truncation
    //
    {
        size_t len = wcslen(Title);
        SIZE_T copyLen = min(len * sizeof(WCHAR), sizeof(event->AlertTitle) - sizeof(WCHAR));
        RtlCopyMemory(event->AlertTitle, Title, copyLen);
        event->AlertTitle[copyLen / sizeof(WCHAR)] = L'\0';
    }

    {
        size_t len = wcslen(Description);
        SIZE_T copyLen = min(len * sizeof(WCHAR), sizeof(event->AlertDescription) - sizeof(WCHAR));
        RtlCopyMemory(event->AlertDescription, Description, copyLen);
        event->AlertDescription[copyLen / sizeof(WCHAR)] = L'\0';
    }

    if (ProcessPath != NULL) {
        size_t len = wcslen(ProcessPath);
        SIZE_T copyLen = min(len * sizeof(WCHAR), sizeof(event->ProcessPath) - sizeof(WCHAR));
        RtlCopyMemory(event->ProcessPath, ProcessPath, copyLen);
        event->ProcessPath[copyLen / sizeof(WCHAR)] = L'\0';
    }

    if (TargetPath != NULL) {
        size_t len = wcslen(TargetPath);
        SIZE_T copyLen = min(len * sizeof(WCHAR), sizeof(event->TargetPath) - sizeof(WCHAR));
        RtlCopyMemory(event->TargetPath, TargetPath, copyLen);
        event->TargetPath[copyLen / sizeof(WCHAR)] = L'\0';
    }

    EventDataDescCreate(&dataDescriptor, event, sizeof(ETW_SECURITY_ALERT));

    status = EtwpWriteEvent(descriptor, 1, &dataDescriptor);

    EtwpUpdateStatistics(sizeof(ETW_SECURITY_ALERT), NT_SUCCESS(status));

    ExFreeToNPagedLookasideList(&g_EtwGlobals.EventBufferLookaside, event);

    return status;
}


//=============================================================================
// Event Writing - Diagnostic Events
//=============================================================================

_Use_decl_annotations_
NTSTATUS
EtwWriteDiagnosticEvent(
    _In_ SHADOWSTRIKE_ETW_EVENT_ID EventId,
    _In_ UCHAR Level,
    _In_ UINT32 ComponentId,
    _In_ PCWSTR Message,
    _In_ UINT32 ErrorCode
    )
/*++

Routine Description:

    Writes a diagnostic/error ETW event.

--*/
{
    NTSTATUS status;
    PCEVENT_DESCRIPTOR descriptor;
    EVENT_DATA_DESCRIPTOR dataDescriptors[4];
    UINT64 timestamp;

    if (!g_EtwGlobals.Initialized || !g_EtwGlobals.Enabled) {
        return STATUS_SUCCESS;
    }

    if (Message == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Select descriptor based on event ID
    //
    switch (EventId) {
        case EtwEventId_DriverStarted:
            descriptor = &EtwDescriptor_DriverStarted;
            break;
        case EtwEventId_DriverStopping:
            descriptor = &EtwDescriptor_DriverStopping;
            break;
        case EtwEventId_Heartbeat:
            descriptor = &EtwDescriptor_Heartbeat;
            break;
        case EtwEventId_ComponentHealth:
            descriptor = &EtwDescriptor_ComponentHealth;
            break;
        case EtwEventId_Error:
        default:
            descriptor = &EtwDescriptor_Error;
            break;
    }

    if (!EtwProviderIsEnabled(Level, ETW_KEYWORD_DIAGNOSTIC)) {
        return STATUS_SUCCESS;
    }

    //
    // Build event data
    //
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&timestamp);

    EventDataDescCreate(&dataDescriptors[0], &timestamp, sizeof(UINT64));
    EventDataDescCreate(&dataDescriptors[1], &ComponentId, sizeof(UINT32));
    EventDataDescCreate(&dataDescriptors[2], &ErrorCode, sizeof(UINT32));
    EventDataDescCreate(&dataDescriptors[3], Message, (ULONG)((wcslen(Message) + 1) * sizeof(WCHAR)));

    status = EtwpWriteEvent(descriptor, 4, dataDescriptors);

    EtwpUpdateStatistics(sizeof(UINT64) + sizeof(UINT32) * 2 + (ULONG)((wcslen(Message) + 1) * sizeof(WCHAR)),
                         NT_SUCCESS(status));

    return status;
}


_Use_decl_annotations_
NTSTATUS
EtwWritePerformanceStats(
    _In_ PTELEMETRY_PERFORMANCE Stats
    )
/*++

Routine Description:

    Writes performance statistics as an ETW event.

--*/
{
    NTSTATUS status;
    EVENT_DATA_DESCRIPTOR dataDescriptor;

    if (!g_EtwGlobals.Initialized || !g_EtwGlobals.Enabled) {
        return STATUS_SUCCESS;
    }

    if (Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!EtwProviderIsEnabled(ETW_LEVEL_INFORMATIONAL, ETW_KEYWORD_TELEMETRY)) {
        return STATUS_SUCCESS;
    }

    if (!EtwpCheckRateLimit()) {
        InterlockedIncrement64(&g_EtwGlobals.EventsDropped);
        return STATUS_QUOTA_EXCEEDED;
    }

    EventDataDescCreate(&dataDescriptor, Stats, sizeof(TELEMETRY_PERFORMANCE));

    status = EtwpWriteEvent(&EtwDescriptor_PerformanceStats, 1, &dataDescriptor);

    EtwpUpdateStatistics(sizeof(TELEMETRY_PERFORMANCE), NT_SUCCESS(status));

    return status;
}


//=============================================================================
// Statistics
//=============================================================================

_Use_decl_annotations_
NTSTATUS
EtwProviderGetStatistics(
    _Out_ PUINT64 EventsWritten,
    _Out_ PUINT64 EventsDropped,
    _Out_ PUINT64 BytesWritten
    )
/*++

Routine Description:

    Retrieves ETW provider statistics.

--*/
{
    if (EventsWritten == NULL || EventsDropped == NULL || BytesWritten == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *EventsWritten = g_EtwGlobals.EventsWritten;
    *EventsDropped = g_EtwGlobals.EventsDropped;
    *BytesWritten = g_EtwGlobals.BytesWritten;

    return STATUS_SUCCESS;
}


//=============================================================================
// Internal Functions
//=============================================================================

static
_Use_decl_annotations_
BOOLEAN
EtwpCheckRateLimit(
    VOID
    )
/*++

Routine Description:

    Checks if we're within the rate limit for event writing.
    Resets counter each second.

Return Value:

    TRUE if under rate limit, FALSE if limit exceeded.

--*/
{
    UINT64 currentTime;
    UINT64 elapsedMs;
    LONG currentCount;

    KeQuerySystemTimePrecise((PLARGE_INTEGER)&currentTime);

    //
    // Calculate elapsed time in milliseconds
    //
    elapsedMs = (currentTime - g_EtwGlobals.CurrentSecondStart) / 10000;

    if (elapsedMs >= ETW_RATE_LIMIT_WINDOW_MS) {
        //
        // New window - reset counter
        //
        g_EtwGlobals.CurrentSecondStart = currentTime;
        InterlockedExchange(&g_EtwGlobals.EventsThisSecond, 1);
        return TRUE;
    }

    //
    // Increment and check
    //
    currentCount = InterlockedIncrement(&g_EtwGlobals.EventsThisSecond);

    return (currentCount <= (LONG)g_EtwGlobals.MaxEventsPerSecond);
}


static
_Use_decl_annotations_
VOID
EtwpUpdateStatistics(
    _In_ ULONG EventSize,
    _In_ BOOLEAN Success
    )
/*++

Routine Description:

    Updates statistics counters after event writing.

--*/
{
    if (Success) {
        InterlockedIncrement64(&g_EtwGlobals.EventsWritten);
        InterlockedAdd64((LONG64*)&g_EtwGlobals.BytesWritten, EventSize);
    } else {
        InterlockedIncrement64(&g_EtwGlobals.EventsDropped);
    }
}


static
_Use_decl_annotations_
VOID
EtwpFillCommonHeader(
    _Out_ PETW_EVENT_COMMON Common,
    _In_ UINT32 ProcessId
    )
/*++

Routine Description:

    Fills the common event header fields.

--*/
{
    LARGE_INTEGER timestamp;

    KeQuerySystemTimePrecise(&timestamp);

    Common->Timestamp = (UINT64)timestamp.QuadPart;
    Common->ProcessId = ProcessId;
    Common->ThreadId = (UINT32)(ULONG_PTR)PsGetCurrentThreadId();
    Common->SessionId = 0;  // Would require additional lookup
    Common->Reserved = 0;
}


static
_Use_decl_annotations_
NTSTATUS
EtwpWriteEvent(
    _In_ PCEVENT_DESCRIPTOR EventDescriptor,
    _In_ ULONG UserDataCount,
    _In_reads_opt_(UserDataCount) PEVENT_DATA_DESCRIPTOR UserData
    )
/*++

Routine Description:

    Internal wrapper for EtwWrite with error handling.

--*/
{
    NTSTATUS status;

    if (g_EtwGlobals.ProviderHandle == 0) {
        return STATUS_INVALID_HANDLE;
    }

    status = EtwWrite(
        g_EtwGlobals.ProviderHandle,
        EventDescriptor,
        NULL,       // ActivityId
        UserDataCount,
        UserData
        );

    return status;
}


static
VOID NTAPI
EtwpEnableCallback(
    _In_ LPCGUID SourceId,
    _In_ ULONG IsEnabled,
    _In_ UCHAR Level,
    _In_ ULONGLONG MatchAnyKeyword,
    _In_ ULONGLONG MatchAllKeyword,
    _In_opt_ PEVENT_FILTER_DESCRIPTOR FilterData,
    _In_opt_ PVOID CallbackContext
    )
/*++

Routine Description:

    Callback invoked when an ETW session enables/disables the provider.

--*/
{
    UNREFERENCED_PARAMETER(SourceId);
    UNREFERENCED_PARAMETER(MatchAllKeyword);
    UNREFERENCED_PARAMETER(FilterData);
    UNREFERENCED_PARAMETER(CallbackContext);

    if (IsEnabled == EVENT_CONTROL_CODE_ENABLE_PROVIDER) {
        //
        // Provider is being enabled
        //
        g_EtwGlobals.Enabled = TRUE;
        g_EtwGlobals.EnableLevel = Level;
        g_EtwGlobals.EnableFlags = MatchAnyKeyword;
        InterlockedIncrement((LONG*)&g_EtwGlobals.ConsumerCount);

    } else if (IsEnabled == EVENT_CONTROL_CODE_DISABLE_PROVIDER) {
        //
        // Provider is being disabled
        //
        if (InterlockedDecrement((LONG*)&g_EtwGlobals.ConsumerCount) == 0) {
            g_EtwGlobals.Enabled = FALSE;
            g_EtwGlobals.EnableLevel = 0;
            g_EtwGlobals.EnableFlags = 0;
        }

    } else if (IsEnabled == EVENT_CONTROL_CODE_CAPTURE_STATE) {
        //
        // Consumer requesting state capture - write current state
        //
        if (g_EtwGlobals.Enabled) {
            EtwWriteDiagnosticEvent(
                EtwEventId_ComponentHealth,
                ETW_LEVEL_INFORMATIONAL,
                Component_ETWProvider,
                L"ETW Provider state captured",
                0
                );
        }
    }
}

