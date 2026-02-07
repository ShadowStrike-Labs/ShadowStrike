/**
 * ============================================================================
 * ShadowStrike NGAV - PROCESS UTILITIES
 * ============================================================================
 *
 * @file ProcessUtils.c
 * @brief Enterprise-grade process analysis for kernel-mode EDR operations.
 *
 * Provides comprehensive process introspection capabilities for threat
 * detection, behavioral analysis, and security monitoring. This module
 * is designed to handle millions of process events per day on Fortune 500
 * endpoints with zero tolerance for failures or security bypasses.
 *
 * Implementation Features:
 * - Full EPROCESS/ETHREAD introspection via documented and safe APIs
 * - Token analysis for privilege escalation detection
 * - Parent-child validation for process injection detection
 * - WOW64/Protected Process/Secure Process detection
 * - Command line extraction from process PEB
 * - Thread start address analysis for shellcode detection
 * - IRQL-aware implementations with proper synchronization
 * - Comprehensive error handling and logging
 *
 * Security Fixes (v2.1.0):
 * - Fixed SeQueryInformationToken usage (proper buffer handling)
 * - Fixed SePrivilegeCheck to use SeCaptureSubjectContext
 * - Corrected IRQL annotations throughout
 * - Added atomic initialization with InterlockedCompareExchange
 * - Fixed ShadowStrikeIsValidProcessId to accept System process
 * - Added UNICODE_STRING validation for ZwQueryInformationProcess
 * - Consistent use of ExFreePoolWithTag
 * - Complete implementation of creating process tracking
 *
 * @author ShadowStrike Security Team
 * @version 2.1.0 (Enterprise Edition - Security Hardened)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "ProcessUtils.h"
#include "MemoryUtils.h"
#include "StringUtils.h"

// ============================================================================
// UNDOCUMENTED STRUCTURES (Required for full process introspection)
// ============================================================================

//
// Process information classes not in public headers
//
#ifndef ProcessImageFileName
#define ProcessImageFileName 27
#endif

#ifndef ProcessCommandLineInformation
#define ProcessCommandLineInformation 60
#endif

#ifndef ProcessProtectionInformation
#define ProcessProtectionInformation 61
#endif

//
// PS_PROTECTION structure for protected process detection
//
typedef struct _PS_PROTECTION {
    union {
        UCHAR Level;
        struct {
            UCHAR Type   : 3;
            UCHAR Audit  : 1;
            UCHAR Signer : 4;
        };
    };
} PS_PROTECTION, *PPS_PROTECTION;

//
// Protection types
//
#define PsProtectedTypeNone             0
#define PsProtectedTypeProtectedLight   1
#define PsProtectedTypeProtected        2

//
// Signer types (map to SHADOW_SIGNER_TYPE)
//
#define PsProtectedSignerNone           0
#define PsProtectedSignerAuthenticode   1
#define PsProtectedSignerCodeGen        2
#define PsProtectedSignerAntimalware    3
#define PsProtectedSignerLsa            4
#define PsProtectedSignerWindows        5
#define PsProtectedSignerWinTcb         6
#define PsProtectedSignerWinSystem      7
#define PsProtectedSignerApp            8

//
// Token integrity levels
//
#define SECURITY_MANDATORY_UNTRUSTED_RID        0x00000000
#define SECURITY_MANDATORY_LOW_RID              0x00001000
#define SECURITY_MANDATORY_MEDIUM_RID           0x00002000
#define SECURITY_MANDATORY_MEDIUM_PLUS_RID      0x00002100
#define SECURITY_MANDATORY_HIGH_RID             0x00003000
#define SECURITY_MANDATORY_SYSTEM_RID           0x00004000
#define SECURITY_MANDATORY_PROTECTED_PROCESS_RID 0x00005000

// ============================================================================
// FUNCTION POINTER TYPES
// ============================================================================

typedef NTSTATUS (NTAPI *PFN_ZWQUERYINFORMATIONPROCESS)(
    _In_      HANDLE           ProcessHandle,
    _In_      PROCESSINFOCLASS ProcessInformationClass,
    _Out_     PVOID            ProcessInformation,
    _In_      ULONG            ProcessInformationLength,
    _Out_opt_ PULONG           ReturnLength
);

typedef NTSTATUS (NTAPI *PFN_ZWQUERYINFORMATIONTHREAD)(
    _In_      HANDLE          ThreadHandle,
    _In_      THREADINFOCLASS ThreadInformationClass,
    _Out_     PVOID           ThreadInformation,
    _In_      ULONG           ThreadInformationLength,
    _Out_opt_ PULONG          ReturnLength
);

typedef PPEB (NTAPI *PFN_PSGETPROCESSPEB)(
    _In_ PEPROCESS Process
);

typedef PPEB32 (NTAPI *PFN_PSGETPROCESSWOW64PROCESS)(
    _In_ PEPROCESS Process
);

typedef BOOLEAN (NTAPI *PFN_PSISPROCESSTERMINATING)(
    _In_ PEPROCESS Process
);

typedef BOOLEAN (NTAPI *PFN_PSISPROTECTEDPROCESS)(
    _In_ PEPROCESS Process
);

typedef BOOLEAN (NTAPI *PFN_PSISSECUREPROCESS)(
    _In_ PEPROCESS Process
);

typedef PACCESS_TOKEN (NTAPI *PFN_PSREFERENCEPRIMARYTOKEN)(
    _In_ PEPROCESS Process
);

// ============================================================================
// INITIALIZATION STATE VALUES
// ============================================================================

#define PROCUTILS_STATE_UNINITIALIZED   0
#define PROCUTILS_STATE_INITIALIZING    1
#define PROCUTILS_STATE_INITIALIZED     2

// ============================================================================
// CREATING PROCESS CONTEXT TABLE
// ============================================================================

//
// Maximum entries in the creating process context table
// Uses a simple hash table for O(1) lookup
//
#define SHADOW_CREATING_CONTEXT_TABLE_SIZE  4096
#define SHADOW_CREATING_CONTEXT_HASH_MASK   (SHADOW_CREATING_CONTEXT_TABLE_SIZE - 1)

typedef struct _SHADOW_CREATING_CONTEXT_ENTRY {
    LIST_ENTRY ListEntry;
    HANDLE TargetProcessId;
    HANDLE CreatingProcessId;
    HANDLE CreatingThreadId;
    LARGE_INTEGER CaptureTime;
} SHADOW_CREATING_CONTEXT_ENTRY, *PSHADOW_CREATING_CONTEXT_ENTRY;

// ============================================================================
// GLOBAL STATE
// ============================================================================

typedef struct _SHADOW_PROCESS_UTILS_STATE {
    //
    // Atomic initialization state
    //
    volatile LONG InitializationState;

    //
    // Function pointers resolved at runtime
    //
    PFN_ZWQUERYINFORMATIONPROCESS   ZwQueryInformationProcess;
    PFN_ZWQUERYINFORMATIONTHREAD    ZwQueryInformationThread;
    PFN_PSGETPROCESSPEB             PsGetProcessPeb;
    PFN_PSGETPROCESSWOW64PROCESS    PsGetProcessWow64Process;
    PFN_PSISPROCESSTERMINATING      PsIsProcessTerminating;
    PFN_PSISPROTECTEDPROCESS        PsIsProtectedProcess;
    PFN_PSISSECUREPROCESS           PsIsSecureProcess;
    PFN_PSREFERENCEPRIMARYTOKEN     PsReferencePrimaryToken;

    //
    // System process EPROCESS for reference
    //
    PEPROCESS SystemProcess;

    //
    // Windows version info
    //
    RTL_OSVERSIONINFOW OsVersionInfo;

    //
    // Lock for creating context table
    //
    EX_PUSH_LOCK CreatingContextLock;

    //
    // Creating process context hash table
    //
    LIST_ENTRY CreatingContextTable[SHADOW_CREATING_CONTEXT_TABLE_SIZE];
    volatile LONG CreatingContextCount;

} SHADOW_PROCESS_UTILS_STATE, *PSHADOW_PROCESS_UTILS_STATE;

static SHADOW_PROCESS_UTILS_STATE g_ProcessUtilsState = { 0 };

// ============================================================================
// PRAGMA DIRECTIVES
// ============================================================================

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, ShadowProcessUtilsInitialize)
#pragma alloc_text(PAGE, ShadowProcessUtilsCleanup)
#pragma alloc_text(PAGE, ShadowStrikeGetProcessImagePath)
#pragma alloc_text(PAGE, ShadowStrikeGetProcessImageName)
#pragma alloc_text(PAGE, ShadowStrikeGetProcessCommandLine)
#pragma alloc_text(PAGE, ShadowStrikeGetProcessInfo)
#pragma alloc_text(PAGE, ShadowFreeProcessInfo)
#pragma alloc_text(PAGE, ShadowFreeProcessString)
#pragma alloc_text(PAGE, ShadowStrikeGetParentProcessId)
#pragma alloc_text(PAGE, ShadowStrikeGetCreatingProcess)
#pragma alloc_text(PAGE, ShadowStrikeStoreCreatingProcessContext)
#pragma alloc_text(PAGE, ShadowStrikeValidateParentChild)
#pragma alloc_text(PAGE, ShadowStrikeIsSystemProcess)
#pragma alloc_text(PAGE, ShadowStrikeIsProcessElevated)
#pragma alloc_text(PAGE, ShadowStrikeGetProcessIntegrityLevel)
#pragma alloc_text(PAGE, ShadowStrikeGetProcessSessionId)
#pragma alloc_text(PAGE, ShadowStrikeProcessHasPrivilege)
#pragma alloc_text(PAGE, ShadowStrikeGetProcessUserSid)
#pragma alloc_text(PAGE, ShadowStrikeGetProcessIdFromHandle)
#pragma alloc_text(PAGE, ShadowStrikeGetProcessObject)
#pragma alloc_text(PAGE, ShadowStrikeOpenProcess)
#pragma alloc_text(PAGE, ShadowStrikeGetThreadInfo)
#pragma alloc_text(PAGE, ShadowStrikeGetThreadStartAddress)
#pragma alloc_text(PAGE, ShadowStrikeValidateProcessSignature)
#pragma alloc_text(PAGE, ShadowStrikeIsWindowsProcess)
#pragma alloc_text(PAGE, ShadowStrikeClassifyProcess)
#endif

// ============================================================================
// INTERNAL HELPER FUNCTIONS
// ============================================================================

/**
 * @brief Resolve system routine address safely.
 */
static
PVOID
ShadowResolveSystemRoutine(
    _In_ PCWSTR RoutineName
)
{
    UNICODE_STRING RoutineString;

    RtlInitUnicodeString(&RoutineString, RoutineName);
    return MmGetSystemRoutineAddress(&RoutineString);
}

/**
 * @brief Open process handle with kernel-mode access.
 */
static
NTSTATUS
ShadowOpenProcessInternal(
    _In_ HANDLE ProcessId,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE ProcessHandle
)
{
    NTSTATUS Status;
    OBJECT_ATTRIBUTES ObjectAttributes;
    CLIENT_ID ClientId;

    *ProcessHandle = NULL;

    InitializeObjectAttributes(
        &ObjectAttributes,
        NULL,
        OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );

    ClientId.UniqueProcess = ProcessId;
    ClientId.UniqueThread = NULL;

    Status = ZwOpenProcess(
        ProcessHandle,
        DesiredAccess,
        &ObjectAttributes,
        &ClientId
    );

    return Status;
}

/**
 * @brief Get token from process with proper reference.
 */
static
NTSTATUS
ShadowGetProcessToken(
    _In_ HANDLE ProcessId,
    _Out_ PACCESS_TOKEN* Token
)
{
    NTSTATUS Status;
    PEPROCESS Process = NULL;

    *Token = NULL;

    Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Check if process is terminating before accessing token
    //
    if (g_ProcessUtilsState.PsIsProcessTerminating != NULL &&
        g_ProcessUtilsState.PsIsProcessTerminating(Process)) {
        ObDereferenceObject(Process);
        return STATUS_PROCESS_IS_TERMINATING;
    }

    *Token = PsReferencePrimaryToken(Process);

    ObDereferenceObject(Process);

    if (*Token == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Extract integrity level from token using ZwQueryInformationToken.
 *
 * CRITICAL FIX: Uses proper token query method instead of SeQueryInformationToken
 * with incorrect buffer passing.
 */
static
NTSTATUS
ShadowGetTokenIntegrityLevel(
    _In_ PACCESS_TOKEN Token,
    _Out_ PSHADOW_INTEGRITY_LEVEL IntegrityLevel
)
{
    NTSTATUS Status;
    HANDLE TokenHandle = NULL;
    PTOKEN_MANDATORY_LABEL Label = NULL;
    ULONG LabelSize = 0;
    ULONG ReturnLength = 0;
    ULONG IntegrityRid;
    PUCHAR SubAuthorityCount;
    PULONG SubAuthority;

    PAGED_CODE();

    *IntegrityLevel = ShadowIntegrityUnknown;

    //
    // We need to open a handle to the token to use ZwQueryInformationToken
    // Since we have the token object, use ObOpenObjectByPointer
    //
    Status = ObOpenObjectByPointer(
        Token,
        OBJ_KERNEL_HANDLE,
        NULL,
        TOKEN_QUERY,
        *SeTokenObjectType,
        KernelMode,
        &TokenHandle
    );

    if (!NT_SUCCESS(Status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Failed to open token handle: 0x%X\n", Status);
        return Status;
    }

    //
    // Query required size for TokenIntegrityLevel
    //
    Status = ZwQueryInformationToken(
        TokenHandle,
        TokenIntegrityLevel,
        NULL,
        0,
        &ReturnLength
    );

    if (Status != STATUS_BUFFER_TOO_SMALL || ReturnLength == 0) {
        ZwClose(TokenHandle);
        if (NT_SUCCESS(Status)) {
            return STATUS_INTERNAL_ERROR;
        }
        //
        // Some tokens may not have integrity level (pre-Vista)
        //
        *IntegrityLevel = ShadowIntegrityUnknown;
        return STATUS_SUCCESS;
    }

    //
    // Safety check on size
    //
    if (ReturnLength > SHADOW_MAX_TOKEN_INFO_SIZE) {
        ZwClose(TokenHandle);
        return STATUS_BUFFER_OVERFLOW;
    }

    LabelSize = ReturnLength;
    Label = (PTOKEN_MANDATORY_LABEL)ShadowStrikeAllocatePagedWithTag(
        LabelSize,
        SHADOW_TOKEN_TAG
    );

    if (Label == NULL) {
        ZwClose(TokenHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Query the integrity level
    //
    Status = ZwQueryInformationToken(
        TokenHandle,
        TokenIntegrityLevel,
        Label,
        LabelSize,
        &ReturnLength
    );

    ZwClose(TokenHandle);
    TokenHandle = NULL;

    if (!NT_SUCCESS(Status)) {
        ShadowStrikeFreePoolWithTag(Label, SHADOW_TOKEN_TAG);
        *IntegrityLevel = ShadowIntegrityUnknown;
        return STATUS_SUCCESS; // Don't fail, just report unknown
    }

    //
    // Validate the SID before accessing it
    //
    if (Label->Label.Sid == NULL || !RtlValidSid(Label->Label.Sid)) {
        ShadowStrikeFreePoolWithTag(Label, SHADOW_TOKEN_TAG);
        *IntegrityLevel = ShadowIntegrityUnknown;
        return STATUS_SUCCESS;
    }

    //
    // Extract RID from integrity SID
    //
    SubAuthorityCount = RtlSubAuthorityCountSid(Label->Label.Sid);
    if (SubAuthorityCount == NULL || *SubAuthorityCount == 0) {
        ShadowStrikeFreePoolWithTag(Label, SHADOW_TOKEN_TAG);
        *IntegrityLevel = ShadowIntegrityUnknown;
        return STATUS_SUCCESS;
    }

    SubAuthority = RtlSubAuthoritySid(
        Label->Label.Sid,
        *SubAuthorityCount - 1
    );

    if (SubAuthority == NULL) {
        ShadowStrikeFreePoolWithTag(Label, SHADOW_TOKEN_TAG);
        *IntegrityLevel = ShadowIntegrityUnknown;
        return STATUS_SUCCESS;
    }

    IntegrityRid = *SubAuthority;

    if (IntegrityRid >= SECURITY_MANDATORY_PROTECTED_PROCESS_RID) {
        *IntegrityLevel = ShadowIntegrityProtected;
    } else if (IntegrityRid >= SECURITY_MANDATORY_SYSTEM_RID) {
        *IntegrityLevel = ShadowIntegritySystem;
    } else if (IntegrityRid >= SECURITY_MANDATORY_HIGH_RID) {
        *IntegrityLevel = ShadowIntegrityHigh;
    } else if (IntegrityRid >= SECURITY_MANDATORY_MEDIUM_PLUS_RID) {
        *IntegrityLevel = ShadowIntegrityMediumPlus;
    } else if (IntegrityRid >= SECURITY_MANDATORY_MEDIUM_RID) {
        *IntegrityLevel = ShadowIntegrityMedium;
    } else if (IntegrityRid >= SECURITY_MANDATORY_LOW_RID) {
        *IntegrityLevel = ShadowIntegrityLow;
    } else {
        *IntegrityLevel = ShadowIntegrityUntrusted;
    }

    ShadowStrikeFreePoolWithTag(Label, SHADOW_TOKEN_TAG);
    return STATUS_SUCCESS;
}

/**
 * @brief Check if process runs in SYSTEM context using ZwQueryInformationToken.
 *
 * CRITICAL FIX: Uses proper token query method.
 */
static
BOOLEAN
ShadowIsSystemToken(
    _In_ PACCESS_TOKEN Token
)
{
    NTSTATUS Status;
    HANDLE TokenHandle = NULL;
    PTOKEN_USER TokenUser = NULL;
    ULONG TokenUserSize = 0;
    ULONG ReturnLength = 0;
    BOOLEAN IsSystem = FALSE;
    UCHAR LocalSystemSidBuffer[SECURITY_MAX_SID_SIZE];
    PSID LocalSystemSid = (PSID)LocalSystemSidBuffer;
    ULONG SidSize = sizeof(LocalSystemSidBuffer);

    PAGED_CODE();

    //
    // Create well-known LocalSystem SID (S-1-5-18)
    //
    Status = RtlCreateWellKnownSid(
        WinLocalSystemSid,
        NULL,
        LocalSystemSid,
        &SidSize
    );

    if (!NT_SUCCESS(Status)) {
        return FALSE;
    }

    //
    // Open handle to token
    //
    Status = ObOpenObjectByPointer(
        Token,
        OBJ_KERNEL_HANDLE,
        NULL,
        TOKEN_QUERY,
        *SeTokenObjectType,
        KernelMode,
        &TokenHandle
    );

    if (!NT_SUCCESS(Status)) {
        return FALSE;
    }

    //
    // Query required size for TokenUser
    //
    Status = ZwQueryInformationToken(
        TokenHandle,
        TokenUser,
        NULL,
        0,
        &ReturnLength
    );

    if (Status != STATUS_BUFFER_TOO_SMALL || ReturnLength == 0) {
        ZwClose(TokenHandle);
        return FALSE;
    }

    if (ReturnLength > SHADOW_MAX_TOKEN_INFO_SIZE) {
        ZwClose(TokenHandle);
        return FALSE;
    }

    TokenUserSize = ReturnLength;
    TokenUser = (PTOKEN_USER)ShadowStrikeAllocatePagedWithTag(
        TokenUserSize,
        SHADOW_TOKEN_TAG
    );

    if (TokenUser == NULL) {
        ZwClose(TokenHandle);
        return FALSE;
    }

    Status = ZwQueryInformationToken(
        TokenHandle,
        TokenUser,
        TokenUser,
        TokenUserSize,
        &ReturnLength
    );

    ZwClose(TokenHandle);

    if (!NT_SUCCESS(Status)) {
        ShadowStrikeFreePoolWithTag(TokenUser, SHADOW_TOKEN_TAG);
        return FALSE;
    }

    //
    // Validate and compare SIDs
    //
    if (TokenUser->User.Sid != NULL && RtlValidSid(TokenUser->User.Sid)) {
        IsSystem = RtlEqualSid(TokenUser->User.Sid, LocalSystemSid);
    }

    ShadowStrikeFreePoolWithTag(TokenUser, SHADOW_TOKEN_TAG);
    return IsSystem;
}

/**
 * @brief Validate UNICODE_STRING returned from ZwQueryInformationProcess.
 *
 * Ensures the string structure is properly formed and within expected bounds.
 */
static
BOOLEAN
ShadowValidateUnicodeStringFromQuery(
    _In_ PUNICODE_STRING String,
    _In_ ULONG BufferSize
)
{
    //
    // Basic structure validation
    //
    if (String == NULL) {
        return FALSE;
    }

    //
    // Length must be even (WCHAR aligned)
    //
    if ((String->Length & 1) != 0) {
        return FALSE;
    }

    //
    // Length must not exceed MaximumLength
    //
    if (String->Length > String->MaximumLength) {
        return FALSE;
    }

    //
    // Buffer must be within the allocated space
    // The UNICODE_STRING is at the start of the buffer, data follows
    //
    if (String->Buffer == NULL && String->Length > 0) {
        return FALSE;
    }

    //
    // Validate that buffer pointer is after the UNICODE_STRING header
    // and within reasonable bounds
    //
    if (String->Buffer != NULL) {
        ULONG_PTR BufferStart = (ULONG_PTR)String;
        ULONG_PTR BufferEnd = BufferStart + BufferSize;
        ULONG_PTR StringBuffer = (ULONG_PTR)String->Buffer;

        if (StringBuffer < BufferStart || StringBuffer >= BufferEnd) {
            //
            // Buffer pointer outside allocated memory - invalid
            //
            return FALSE;
        }

        if (StringBuffer + String->Length > BufferEnd) {
            //
            // String data extends beyond buffer - invalid
            //
            return FALSE;
        }
    }

    return TRUE;
}

/**
 * @brief Hash function for creating context table.
 */
static
FORCEINLINE
ULONG
ShadowHashProcessId(
    _In_ HANDLE ProcessId
)
{
    ULONG_PTR Value = (ULONG_PTR)ProcessId;
    return (ULONG)((Value >> 2) & SHADOW_CREATING_CONTEXT_HASH_MASK);
}

// ============================================================================
// INITIALIZATION
// ============================================================================

NTSTATUS
ShadowProcessUtilsInitialize(
    VOID
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    LONG PreviousState;
    ULONG i;

    PAGED_CODE();

    //
    // CRITICAL FIX: Atomic initialization to prevent race conditions
    //
    PreviousState = InterlockedCompareExchange(
        &g_ProcessUtilsState.InitializationState,
        PROCUTILS_STATE_INITIALIZING,
        PROCUTILS_STATE_UNINITIALIZED
    );

    if (PreviousState == PROCUTILS_STATE_INITIALIZED) {
        return STATUS_SUCCESS;
    }

    if (PreviousState == PROCUTILS_STATE_INITIALIZING) {
        //
        // Another thread is initializing - wait for completion
        //
        LARGE_INTEGER SleepInterval;
        SleepInterval.QuadPart = -((LONGLONG)10 * 10000LL); // 10ms

        for (i = 0; i < 500; i++) { // 5 second timeout
            KeDelayExecutionThread(KernelMode, FALSE, &SleepInterval);

            if (g_ProcessUtilsState.InitializationState == PROCUTILS_STATE_INITIALIZED) {
                return STATUS_SUCCESS;
            }
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] ProcessUtils initialization timeout\n");
        return STATUS_TIMEOUT;
    }

    //
    // Initialize creating context table
    //
    ExInitializePushLock(&g_ProcessUtilsState.CreatingContextLock);
    for (i = 0; i < SHADOW_CREATING_CONTEXT_TABLE_SIZE; i++) {
        InitializeListHead(&g_ProcessUtilsState.CreatingContextTable[i]);
    }
    g_ProcessUtilsState.CreatingContextCount = 0;

    //
    // Get OS version
    //
    g_ProcessUtilsState.OsVersionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
    Status = RtlGetVersion(&g_ProcessUtilsState.OsVersionInfo);
    if (!NT_SUCCESS(Status)) {
        InterlockedExchange(&g_ProcessUtilsState.InitializationState, PROCUTILS_STATE_UNINITIALIZED);
        return Status;
    }

    //
    // Resolve required function pointers
    //
    g_ProcessUtilsState.ZwQueryInformationProcess =
        (PFN_ZWQUERYINFORMATIONPROCESS)ShadowResolveSystemRoutine(L"ZwQueryInformationProcess");

    if (g_ProcessUtilsState.ZwQueryInformationProcess == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Failed to resolve ZwQueryInformationProcess\n");
        InterlockedExchange(&g_ProcessUtilsState.InitializationState, PROCUTILS_STATE_UNINITIALIZED);
        return STATUS_NOT_FOUND;
    }

    g_ProcessUtilsState.ZwQueryInformationThread =
        (PFN_ZWQUERYINFORMATIONTHREAD)ShadowResolveSystemRoutine(L"ZwQueryInformationThread");

    //
    // Resolve optional functions (may not exist on all Windows versions)
    //
    g_ProcessUtilsState.PsGetProcessPeb =
        (PFN_PSGETPROCESSPEB)ShadowResolveSystemRoutine(L"PsGetProcessPeb");

    g_ProcessUtilsState.PsGetProcessWow64Process =
        (PFN_PSGETPROCESSWOW64PROCESS)ShadowResolveSystemRoutine(L"PsGetProcessWow64Process");

    g_ProcessUtilsState.PsIsProcessTerminating =
        (PFN_PSISPROCESSTERMINATING)ShadowResolveSystemRoutine(L"PsIsProcessTerminating");

    g_ProcessUtilsState.PsIsProtectedProcess =
        (PFN_PSISPROTECTEDPROCESS)ShadowResolveSystemRoutine(L"PsIsProtectedProcess");

    g_ProcessUtilsState.PsIsSecureProcess =
        (PFN_PSISSECUREPROCESS)ShadowResolveSystemRoutine(L"PsIsSecureProcess");

    g_ProcessUtilsState.PsReferencePrimaryToken =
        (PFN_PSREFERENCEPRIMARYTOKEN)ShadowResolveSystemRoutine(L"PsReferencePrimaryToken");

    //
    // Get System process reference
    //
    g_ProcessUtilsState.SystemProcess = PsInitialSystemProcess;

    //
    // Mark as initialized
    //
    InterlockedExchange(&g_ProcessUtilsState.InitializationState, PROCUTILS_STATE_INITIALIZED);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] ProcessUtils initialized successfully (v2.1.0)\n");

    return STATUS_SUCCESS;
}

VOID
ShadowProcessUtilsCleanup(
    VOID
)
{
    ULONG i;
    PLIST_ENTRY ListHead;
    PLIST_ENTRY Entry;
    PSHADOW_CREATING_CONTEXT_ENTRY ContextEntry;

    PAGED_CODE();

    //
    // Mark as uninitialized first
    //
    InterlockedExchange(&g_ProcessUtilsState.InitializationState, PROCUTILS_STATE_UNINITIALIZED);

    //
    // Cleanup creating context table
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ProcessUtilsState.CreatingContextLock);

    for (i = 0; i < SHADOW_CREATING_CONTEXT_TABLE_SIZE; i++) {
        ListHead = &g_ProcessUtilsState.CreatingContextTable[i];

        while (!IsListEmpty(ListHead)) {
            Entry = RemoveHeadList(ListHead);
            ContextEntry = CONTAINING_RECORD(Entry, SHADOW_CREATING_CONTEXT_ENTRY, ListEntry);
            ShadowStrikeFreePoolWithTag(ContextEntry, SHADOW_PROCINFO_TAG);
        }
    }

    g_ProcessUtilsState.CreatingContextCount = 0;

    ExReleasePushLockExclusive(&g_ProcessUtilsState.CreatingContextLock);
    KeLeaveCriticalRegion();

    //
    // Clear function pointers
    //
    g_ProcessUtilsState.ZwQueryInformationProcess = NULL;
    g_ProcessUtilsState.ZwQueryInformationThread = NULL;
    g_ProcessUtilsState.PsGetProcessPeb = NULL;
    g_ProcessUtilsState.PsGetProcessWow64Process = NULL;
    g_ProcessUtilsState.PsIsProcessTerminating = NULL;
    g_ProcessUtilsState.PsIsProtectedProcess = NULL;
    g_ProcessUtilsState.PsIsSecureProcess = NULL;
    g_ProcessUtilsState.SystemProcess = NULL;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] ProcessUtils cleaned up\n");
}

// ============================================================================
// PROCESS INFORMATION RETRIEVAL
// ============================================================================

NTSTATUS
ShadowStrikeGetProcessImagePath(
    _In_ HANDLE ProcessId,
    _Out_ PUNICODE_STRING ImagePath
)
{
    NTSTATUS Status;
    HANDLE ProcessHandle = NULL;
    ULONG ReturnLength = 0;
    PVOID Buffer = NULL;
    ULONG BufferSize = SHADOW_MAX_PROCESS_PATH * sizeof(WCHAR) + sizeof(UNICODE_STRING);
    PUNICODE_STRING ReturnedPath;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (ImagePath == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(ImagePath, sizeof(UNICODE_STRING));

    //
    // Ensure initialized
    //
    if (g_ProcessUtilsState.InitializationState != PROCUTILS_STATE_INITIALIZED) {
        Status = ShadowProcessUtilsInitialize();
        if (!NT_SUCCESS(Status)) {
            return Status;
        }
    }

    //
    // Validate process ID (allow System process)
    //
    if (!ShadowStrikeIsValidProcessId(ProcessId)) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Open process with query access
    //
    Status = ShadowOpenProcessInternal(
        ProcessId,
        PROCESS_QUERY_LIMITED_INFORMATION,
        &ProcessHandle
    );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Allocate buffer for image path
    //
    Buffer = ShadowStrikeAllocatePagedWithTag(BufferSize, SHADOW_PROCINFO_TAG);
    if (Buffer == NULL) {
        ZwClose(ProcessHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Query process image file name
    //
    Status = g_ProcessUtilsState.ZwQueryInformationProcess(
        ProcessHandle,
        ProcessImageFileName,
        Buffer,
        BufferSize,
        &ReturnLength
    );

    if (Status == STATUS_INFO_LENGTH_MISMATCH && ReturnLength > BufferSize) {
        //
        // Reallocate with larger buffer
        //
        ShadowStrikeFreePoolWithTag(Buffer, SHADOW_PROCINFO_TAG);
        BufferSize = ReturnLength;

        //
        // Safety check
        //
        if (BufferSize > SHADOW_MAX_CMDLINE_LENGTH * sizeof(WCHAR)) {
            ZwClose(ProcessHandle);
            return STATUS_BUFFER_OVERFLOW;
        }

        Buffer = ShadowStrikeAllocatePagedWithTag(BufferSize, SHADOW_PROCINFO_TAG);
        if (Buffer == NULL) {
            ZwClose(ProcessHandle);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        Status = g_ProcessUtilsState.ZwQueryInformationProcess(
            ProcessHandle,
            ProcessImageFileName,
            Buffer,
            BufferSize,
            &ReturnLength
        );
    }

    ZwClose(ProcessHandle);
    ProcessHandle = NULL;

    if (!NT_SUCCESS(Status)) {
        ShadowStrikeFreePoolWithTag(Buffer, SHADOW_PROCINFO_TAG);
        return Status;
    }

    //
    // CRITICAL FIX: Validate the returned UNICODE_STRING
    //
    ReturnedPath = (PUNICODE_STRING)Buffer;

    if (!ShadowValidateUnicodeStringFromQuery(ReturnedPath, BufferSize)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Invalid UNICODE_STRING from ProcessImageFileName query\n");
        ShadowStrikeFreePoolWithTag(Buffer, SHADOW_PROCINFO_TAG);
        return STATUS_INVALID_BUFFER_SIZE;
    }

    if (ReturnedPath->Length == 0 || ReturnedPath->Buffer == NULL) {
        ShadowStrikeFreePoolWithTag(Buffer, SHADOW_PROCINFO_TAG);
        return STATUS_NOT_FOUND;
    }

    //
    // Allocate new buffer for caller
    //
    ImagePath->MaximumLength = ReturnedPath->Length + sizeof(WCHAR);
    ImagePath->Buffer = (PWCH)ShadowStrikeAllocatePagedWithTag(
        ImagePath->MaximumLength,
        SHADOW_PROCESS_TAG
    );

    if (ImagePath->Buffer == NULL) {
        ShadowStrikeFreePoolWithTag(Buffer, SHADOW_PROCINFO_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Copy string
    //
    RtlCopyUnicodeString(ImagePath, ReturnedPath);

    //
    // Null-terminate for safety
    //
    ImagePath->Buffer[ImagePath->Length / sizeof(WCHAR)] = UNICODE_NULL;

    ShadowStrikeFreePoolWithTag(Buffer, SHADOW_PROCINFO_TAG);
    return STATUS_SUCCESS;
}

NTSTATUS
ShadowStrikeGetProcessImageName(
    _In_ HANDLE ProcessId,
    _Out_ PUNICODE_STRING ImageName
)
{
    NTSTATUS Status;
    UNICODE_STRING FullPath = { 0 };
    UNICODE_STRING FileName = { 0 };

    PAGED_CODE();

    if (ImageName == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(ImageName, sizeof(UNICODE_STRING));

    //
    // Get full image path
    //
    Status = ShadowStrikeGetProcessImagePath(ProcessId, &FullPath);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Extract filename from path
    //
    Status = ShadowStrikeGetFileName(&FullPath, &FileName);
    if (!NT_SUCCESS(Status)) {
        ShadowFreeProcessString(&FullPath);
        return Status;
    }

    //
    // Clone filename (ShadowStrikeGetFileName returns pointer into original buffer)
    //
    ImageName->MaximumLength = FileName.Length + sizeof(WCHAR);
    ImageName->Buffer = (PWCH)ShadowStrikeAllocatePagedWithTag(
        ImageName->MaximumLength,
        SHADOW_PROCESS_TAG
    );

    if (ImageName->Buffer == NULL) {
        ShadowFreeProcessString(&FullPath);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyUnicodeString(ImageName, &FileName);
    ImageName->Buffer[ImageName->Length / sizeof(WCHAR)] = UNICODE_NULL;

    ShadowFreeProcessString(&FullPath);
    return STATUS_SUCCESS;
}

NTSTATUS
ShadowStrikeGetProcessCommandLine(
    _In_ HANDLE ProcessId,
    _Out_ PUNICODE_STRING CommandLine
)
{
    NTSTATUS Status;
    HANDLE ProcessHandle = NULL;
    ULONG ReturnLength = 0;
    PVOID Buffer = NULL;
    ULONG BufferSize;
    PUNICODE_STRING ReturnedCmdLine;

    PAGED_CODE();

    if (CommandLine == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(CommandLine, sizeof(UNICODE_STRING));

    if (g_ProcessUtilsState.InitializationState != PROCUTILS_STATE_INITIALIZED) {
        Status = ShadowProcessUtilsInitialize();
        if (!NT_SUCCESS(Status)) {
            return Status;
        }
    }

    if (!ShadowStrikeIsValidProcessId(ProcessId)) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // System process (PID 4) has no command line
    //
    if (ShadowStrikeIsSystemProcessId(ProcessId)) {
        CommandLine->Buffer = (PWCH)ShadowStrikeAllocatePagedWithTag(sizeof(WCHAR), SHADOW_PROCESS_TAG);
        if (CommandLine->Buffer == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        CommandLine->Buffer[0] = UNICODE_NULL;
        CommandLine->Length = 0;
        CommandLine->MaximumLength = sizeof(WCHAR);
        return STATUS_SUCCESS;
    }

    //
    // Open process
    //
    Status = ShadowOpenProcessInternal(
        ProcessId,
        PROCESS_QUERY_LIMITED_INFORMATION,
        &ProcessHandle
    );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Initial buffer allocation - start smaller for efficiency
    //
    BufferSize = 4096;
    Buffer = ShadowStrikeAllocatePagedWithTag(BufferSize, SHADOW_PROCINFO_TAG);
    if (Buffer == NULL) {
        ZwClose(ProcessHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Query command line (ProcessCommandLineInformation = 60)
    //
    Status = g_ProcessUtilsState.ZwQueryInformationProcess(
        ProcessHandle,
        ProcessCommandLineInformation,
        Buffer,
        BufferSize,
        &ReturnLength
    );

    if (Status == STATUS_INFO_LENGTH_MISMATCH && ReturnLength > 0) {
        ShadowStrikeFreePoolWithTag(Buffer, SHADOW_PROCINFO_TAG);

        //
        // Safety limit
        //
        if (ReturnLength > SHADOW_MAX_CMDLINE_LENGTH * sizeof(WCHAR)) {
            ZwClose(ProcessHandle);
            return STATUS_BUFFER_OVERFLOW;
        }

        BufferSize = ReturnLength;
        Buffer = ShadowStrikeAllocatePagedWithTag(BufferSize, SHADOW_PROCINFO_TAG);
        if (Buffer == NULL) {
            ZwClose(ProcessHandle);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        Status = g_ProcessUtilsState.ZwQueryInformationProcess(
            ProcessHandle,
            ProcessCommandLineInformation,
            Buffer,
            BufferSize,
            &ReturnLength
        );
    }

    ZwClose(ProcessHandle);

    if (!NT_SUCCESS(Status)) {
        ShadowStrikeFreePoolWithTag(Buffer, SHADOW_PROCINFO_TAG);
        return Status;
    }

    //
    // CRITICAL FIX: Validate the returned UNICODE_STRING
    //
    ReturnedCmdLine = (PUNICODE_STRING)Buffer;

    if (!ShadowValidateUnicodeStringFromQuery(ReturnedCmdLine, BufferSize)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Invalid UNICODE_STRING from ProcessCommandLineInformation query\n");
        ShadowStrikeFreePoolWithTag(Buffer, SHADOW_PROCINFO_TAG);
        //
        // Return empty command line instead of failing
        //
        CommandLine->Buffer = (PWCH)ShadowStrikeAllocatePagedWithTag(sizeof(WCHAR), SHADOW_PROCESS_TAG);
        if (CommandLine->Buffer == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        CommandLine->Buffer[0] = UNICODE_NULL;
        CommandLine->Length = 0;
        CommandLine->MaximumLength = sizeof(WCHAR);
        return STATUS_SUCCESS;
    }

    if (ReturnedCmdLine->Length == 0 || ReturnedCmdLine->Buffer == NULL) {
        //
        // Empty command line is valid
        //
        ShadowStrikeFreePoolWithTag(Buffer, SHADOW_PROCINFO_TAG);
        CommandLine->Buffer = (PWCH)ShadowStrikeAllocatePagedWithTag(sizeof(WCHAR), SHADOW_PROCESS_TAG);
        if (CommandLine->Buffer == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        CommandLine->Buffer[0] = UNICODE_NULL;
        CommandLine->Length = 0;
        CommandLine->MaximumLength = sizeof(WCHAR);
        return STATUS_SUCCESS;
    }

    //
    // Allocate and copy
    //
    CommandLine->MaximumLength = ReturnedCmdLine->Length + sizeof(WCHAR);
    CommandLine->Buffer = (PWCH)ShadowStrikeAllocatePagedWithTag(
        CommandLine->MaximumLength,
        SHADOW_PROCESS_TAG
    );

    if (CommandLine->Buffer == NULL) {
        ShadowStrikeFreePoolWithTag(Buffer, SHADOW_PROCINFO_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyUnicodeString(CommandLine, ReturnedCmdLine);
    CommandLine->Buffer[CommandLine->Length / sizeof(WCHAR)] = UNICODE_NULL;

    ShadowStrikeFreePoolWithTag(Buffer, SHADOW_PROCINFO_TAG);
    return STATUS_SUCCESS;
}

NTSTATUS
ShadowStrikeGetProcessInfo(
    _In_ HANDLE ProcessId,
    _Out_ PSHADOW_PROCESS_INFO ProcessInfo
)
{
    NTSTATUS Status;
    PEPROCESS Process = NULL;
    PACCESS_TOKEN Token = NULL;
    HANDLE ParentPid = NULL;

    PAGED_CODE();

    if (ProcessInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(ProcessInfo, sizeof(SHADOW_PROCESS_INFO));

    if (!ShadowStrikeIsValidProcessId(ProcessId)) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Basic IDs
    //
    ProcessInfo->ProcessId = ProcessId;

    //
    // Get EPROCESS
    //
    Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Check termination state
    //
    if (ShadowStrikeIsProcessTerminating(Process)) {
        ProcessInfo->IsTerminating = TRUE;
        ObDereferenceObject(Process);
        return STATUS_SUCCESS;
    }

    //
    // Get parent process ID
    //
    Status = ShadowStrikeGetParentProcessId(ProcessId, &ParentPid);
    if (NT_SUCCESS(Status)) {
        ProcessInfo->ParentProcessId = ParentPid;
    }

    //
    // Get creating process/thread
    //
    ShadowStrikeGetCreatingProcess(
        Process,
        &ProcessInfo->CreatingProcessId,
        &ProcessInfo->CreatingThreadId
    );

    //
    // Image path
    //
    Status = ShadowStrikeGetProcessImagePath(ProcessId, &ProcessInfo->ImagePath);
    if (NT_SUCCESS(Status) && ProcessInfo->ImagePath.Length > 0) {
        //
        // Extract filename
        //
        UNICODE_STRING TempFileName = { 0 };
        if (NT_SUCCESS(ShadowStrikeGetFileName(&ProcessInfo->ImagePath, &TempFileName))) {
            ProcessInfo->ImageFileName.MaximumLength = TempFileName.Length + sizeof(WCHAR);
            ProcessInfo->ImageFileName.Buffer = (PWCH)ShadowStrikeAllocatePagedWithTag(
                ProcessInfo->ImageFileName.MaximumLength,
                SHADOW_PROCESS_TAG
            );
            if (ProcessInfo->ImageFileName.Buffer != NULL) {
                RtlCopyUnicodeString(&ProcessInfo->ImageFileName, &TempFileName);
            }
        }
    }

    //
    // Command line
    //
    ShadowStrikeGetProcessCommandLine(ProcessId, &ProcessInfo->CommandLine);

    //
    // Session ID
    //
    ShadowStrikeGetProcessSessionId(ProcessId, &ProcessInfo->SessionId);

    //
    // Security attributes
    //
    ShadowStrikeGetProcessIntegrityLevel(ProcessId, &ProcessInfo->IntegrityLevel);

    //
    // Process flags
    //
    ProcessInfo->IsWow64 = ShadowStrikeIsProcessWow64(Process);
    ProcessInfo->IsProtectedProcess = ShadowStrikeIsProcessProtected(Process);
    ProcessInfo->IsDebugged = ShadowStrikeIsProcessDebugged(Process);

    //
    // Check for secure process (Windows 10+)
    //
    if (g_ProcessUtilsState.PsIsSecureProcess != NULL) {
        ProcessInfo->IsSecureProcess = g_ProcessUtilsState.PsIsSecureProcess(Process);
    }

    //
    // Token analysis
    //
    Status = ShadowGetProcessToken(ProcessId, &Token);
    if (NT_SUCCESS(Status) && Token != NULL) {
        //
        // Check elevation
        //
        ProcessInfo->IsElevated = SeTokenIsAdmin(Token);

        //
        // Get user SID using ZwQueryInformationToken (proper method)
        //
        HANDLE TokenHandle = NULL;
        Status = ObOpenObjectByPointer(
            Token,
            OBJ_KERNEL_HANDLE,
            NULL,
            TOKEN_QUERY,
            *SeTokenObjectType,
            KernelMode,
            &TokenHandle
        );

        if (NT_SUCCESS(Status)) {
            PTOKEN_USER TokenUser = NULL;
            ULONG TokenUserSize = 0;
            ULONG ReturnLength = 0;

            Status = ZwQueryInformationToken(
                TokenHandle,
                TokenUser,
                NULL,
                0,
                &ReturnLength
            );

            if (Status == STATUS_BUFFER_TOO_SMALL && ReturnLength > 0 &&
                ReturnLength <= SHADOW_MAX_TOKEN_INFO_SIZE) {

                TokenUserSize = ReturnLength;
                TokenUser = (PTOKEN_USER)ShadowStrikeAllocatePagedWithTag(
                    TokenUserSize,
                    SHADOW_TOKEN_TAG
                );

                if (TokenUser != NULL) {
                    Status = ZwQueryInformationToken(
                        TokenHandle,
                        TokenUser,
                        TokenUser,
                        TokenUserSize,
                        &ReturnLength
                    );

                    if (NT_SUCCESS(Status) && TokenUser->User.Sid != NULL &&
                        RtlValidSid(TokenUser->User.Sid)) {

                        ULONG SidLength = RtlLengthSid(TokenUser->User.Sid);
                        ProcessInfo->TokenUser = (PTOKEN_USER)ShadowStrikeAllocatePagedWithTag(
                            sizeof(TOKEN_USER) + SidLength,
                            SHADOW_PROCESS_TAG
                        );

                        if (ProcessInfo->TokenUser != NULL) {
                            ProcessInfo->TokenUser->User.Attributes = TokenUser->User.Attributes;
                            ProcessInfo->TokenUser->User.Sid = (PSID)((PUCHAR)ProcessInfo->TokenUser + sizeof(TOKEN_USER));
                            RtlCopySid(SidLength, ProcessInfo->TokenUser->User.Sid, TokenUser->User.Sid);
                            ProcessInfo->TokenUserSize = sizeof(TOKEN_USER) + SidLength;
                        }
                    }

                    ShadowStrikeFreePoolWithTag(TokenUser, SHADOW_TOKEN_TAG);
                }
            }

            ZwClose(TokenHandle);
        }

        PsDereferencePrimaryToken(Token);
    }

    //
    // Protection level
    //
    if (ProcessInfo->IsSecureProcess) {
        ProcessInfo->ProtectionLevel = ShadowProtectionSecure;
    } else if (ProcessInfo->IsProtectedProcess) {
        ProcessInfo->ProtectionLevel = ShadowProtectionLight;
    } else {
        ProcessInfo->ProtectionLevel = ShadowProtectionNone;
    }

    //
    // Signature validation
    //
    ShadowStrikeValidateProcessSignature(
        ProcessId,
        &ProcessInfo->IsSigned,
        &ProcessInfo->SignerType
    );

    //
    // Process type classification
    //
    ShadowStrikeClassifyProcess(ProcessId, &ProcessInfo->ProcessType);

    //
    // Timestamps
    //
    ProcessInfo->CreateTime.QuadPart = PsGetProcessCreateTimeQuadPart(Process);

    ObDereferenceObject(Process);
    return STATUS_SUCCESS;
}

VOID
ShadowFreeProcessInfo(
    _Inout_ PSHADOW_PROCESS_INFO ProcessInfo
)
{
    PAGED_CODE();

    if (ProcessInfo == NULL) {
        return;
    }

    if (ProcessInfo->ImagePath.Buffer != NULL) {
        ShadowStrikeFreePoolWithTag(ProcessInfo->ImagePath.Buffer, SHADOW_PROCESS_TAG);
        ProcessInfo->ImagePath.Buffer = NULL;
    }

    if (ProcessInfo->ImageFileName.Buffer != NULL) {
        ShadowStrikeFreePoolWithTag(ProcessInfo->ImageFileName.Buffer, SHADOW_PROCESS_TAG);
        ProcessInfo->ImageFileName.Buffer = NULL;
    }

    if (ProcessInfo->CommandLine.Buffer != NULL) {
        ShadowStrikeFreePoolWithTag(ProcessInfo->CommandLine.Buffer, SHADOW_PROCESS_TAG);
        ProcessInfo->CommandLine.Buffer = NULL;
    }

    if (ProcessInfo->TokenUser != NULL) {
        ShadowStrikeFreePoolWithTag(ProcessInfo->TokenUser, SHADOW_PROCESS_TAG);
        ProcessInfo->TokenUser = NULL;
    }

    RtlZeroMemory(ProcessInfo, sizeof(SHADOW_PROCESS_INFO));
}

VOID
ShadowFreeProcessString(
    _Inout_ PUNICODE_STRING String
)
{
    PAGED_CODE();

    if (String == NULL) {
        return;
    }

    if (String->Buffer != NULL) {
        ShadowStrikeFreePoolWithTag(String->Buffer, SHADOW_PROCESS_TAG);
        String->Buffer = NULL;
    }

    String->Length = 0;
    String->MaximumLength = 0;
}

// ============================================================================
// PARENT/CHILD RELATIONSHIPS
// ============================================================================

NTSTATUS
ShadowStrikeGetParentProcessId(
    _In_ HANDLE ProcessId,
    _Out_ PHANDLE ParentProcessId
)
{
    NTSTATUS Status;
    HANDLE ProcessHandle = NULL;
    PROCESS_BASIC_INFORMATION BasicInfo;
    ULONG ReturnLength;

    PAGED_CODE();

    if (ParentProcessId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ParentProcessId = NULL;

    if (g_ProcessUtilsState.InitializationState != PROCUTILS_STATE_INITIALIZED) {
        Status = ShadowProcessUtilsInitialize();
        if (!NT_SUCCESS(Status)) {
            return Status;
        }
    }

    if (!ShadowStrikeIsValidProcessId(ProcessId)) {
        return STATUS_INVALID_PARAMETER;
    }

    Status = ShadowOpenProcessInternal(
        ProcessId,
        PROCESS_QUERY_LIMITED_INFORMATION,
        &ProcessHandle
    );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    RtlZeroMemory(&BasicInfo, sizeof(BasicInfo));

    Status = g_ProcessUtilsState.ZwQueryInformationProcess(
        ProcessHandle,
        ProcessBasicInformation,
        &BasicInfo,
        sizeof(BasicInfo),
        &ReturnLength
    );

    ZwClose(ProcessHandle);

    if (NT_SUCCESS(Status)) {
        *ParentProcessId = (HANDLE)BasicInfo.InheritedFromUniqueProcessId;
    }

    return Status;
}

NTSTATUS
ShadowStrikeGetCreatingProcess(
    _In_ PEPROCESS Process,
    _Out_ PHANDLE CreatingProcessId,
    _Out_opt_ PHANDLE CreatingThreadId
)
{
    HANDLE ProcessId;
    ULONG Hash;
    PLIST_ENTRY ListHead;
    PLIST_ENTRY Entry;
    PSHADOW_CREATING_CONTEXT_ENTRY ContextEntry;
    BOOLEAN Found = FALSE;

    PAGED_CODE();

    if (Process == NULL || CreatingProcessId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *CreatingProcessId = NULL;
    if (CreatingThreadId != NULL) {
        *CreatingThreadId = NULL;
    }

    ProcessId = PsGetProcessId(Process);

    //
    // Look up in our creating context table
    //
    Hash = ShadowHashProcessId(ProcessId);

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_ProcessUtilsState.CreatingContextLock);

    ListHead = &g_ProcessUtilsState.CreatingContextTable[Hash];

    for (Entry = ListHead->Flink; Entry != ListHead; Entry = Entry->Flink) {
        ContextEntry = CONTAINING_RECORD(Entry, SHADOW_CREATING_CONTEXT_ENTRY, ListEntry);

        if (ContextEntry->TargetProcessId == ProcessId) {
            *CreatingProcessId = ContextEntry->CreatingProcessId;
            if (CreatingThreadId != NULL) {
                *CreatingThreadId = ContextEntry->CreatingThreadId;
            }
            Found = TRUE;
            break;
        }
    }

    ExReleasePushLockShared(&g_ProcessUtilsState.CreatingContextLock);
    KeLeaveCriticalRegion();

    if (!Found) {
        //
        // Fallback to inherited parent process ID
        //
        *CreatingProcessId = PsGetProcessInheritedFromUniqueProcessId(Process);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
ShadowStrikeStoreCreatingProcessContext(
    _In_ HANDLE TargetProcessId,
    _In_ HANDLE CreatingProcessId,
    _In_ HANDLE CreatingThreadId
)
{
    PSHADOW_CREATING_CONTEXT_ENTRY ContextEntry;
    ULONG Hash;
    PLIST_ENTRY ListHead;

    PAGED_CODE();

    if (!ShadowStrikeIsValidProcessId(TargetProcessId)) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Limit table size to prevent unbounded growth
    //
    if (g_ProcessUtilsState.CreatingContextCount >= SHADOW_CREATING_CONTEXT_TABLE_SIZE * 4) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Creating context table full\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Allocate new entry
    //
    ContextEntry = (PSHADOW_CREATING_CONTEXT_ENTRY)ShadowStrikeAllocatePagedWithTag(
        sizeof(SHADOW_CREATING_CONTEXT_ENTRY),
        SHADOW_PROCINFO_TAG
    );

    if (ContextEntry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ContextEntry->TargetProcessId = TargetProcessId;
    ContextEntry->CreatingProcessId = CreatingProcessId;
    ContextEntry->CreatingThreadId = CreatingThreadId;
    KeQuerySystemTime(&ContextEntry->CaptureTime);

    Hash = ShadowHashProcessId(TargetProcessId);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ProcessUtilsState.CreatingContextLock);

    ListHead = &g_ProcessUtilsState.CreatingContextTable[Hash];
    InsertTailList(ListHead, &ContextEntry->ListEntry);
    InterlockedIncrement(&g_ProcessUtilsState.CreatingContextCount);

    ExReleasePushLockExclusive(&g_ProcessUtilsState.CreatingContextLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

NTSTATUS
ShadowStrikeValidateParentChild(
    _In_ HANDLE ChildId,
    _In_ HANDLE ClaimedParentId,
    _Out_ PBOOLEAN IsValid
)
{
    NTSTATUS Status;
    HANDLE ActualParentId = NULL;

    PAGED_CODE();

    if (IsValid == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsValid = FALSE;

    if (!ShadowStrikeIsValidProcessId(ChildId)) {
        return STATUS_INVALID_PARAMETER;
    }

    Status = ShadowStrikeGetParentProcessId(ChildId, &ActualParentId);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Compare claimed parent with actual parent
    // This detects parent PID spoofing attacks (T1134.004)
    //
    *IsValid = (ActualParentId == ClaimedParentId);

    return STATUS_SUCCESS;
}

// ============================================================================
// PROCESS STATE AND FLAGS
// ============================================================================

BOOLEAN
ShadowStrikeIsProcessTerminating(
    _In_ PEPROCESS Process
)
{
    if (Process == NULL) {
        return TRUE;
    }

    //
    // Use documented API if available (Windows 10+)
    //
    if (g_ProcessUtilsState.PsIsProcessTerminating != NULL) {
        return g_ProcessUtilsState.PsIsProcessTerminating(Process);
    }

    //
    // Fallback: Check if process exit time is set
    // This is less reliable but works on older systems
    //
    LARGE_INTEGER ExitTime = PsGetProcessExitTime(Process);
    return (ExitTime.QuadPart != 0);
}

BOOLEAN
ShadowStrikeIsProcessWow64(
    _In_ PEPROCESS Process
)
{
    if (Process == NULL) {
        return FALSE;
    }

#ifdef _WIN64
    //
    // On 64-bit, check for WOW64 process using the documented API
    //
    return (PsGetProcessWow64Process(Process) != NULL);
#else
    //
    // On 32-bit, no WOW64
    //
    UNREFERENCED_PARAMETER(Process);
    return FALSE;
#endif
}

BOOLEAN
ShadowStrikeIsProcessProtected(
    _In_ PEPROCESS Process
)
{
    if (Process == NULL) {
        return FALSE;
    }

    //
    // Use documented API (Windows 8.1+)
    //
    if (g_ProcessUtilsState.PsIsProtectedProcess != NULL) {
        return g_ProcessUtilsState.PsIsProtectedProcess(Process);
    }

    //
    // For older systems, protected processes don't exist
    //
    return FALSE;
}

BOOLEAN
ShadowStrikeIsProcessDebugged(
    _In_ PEPROCESS Process
)
{
    if (Process == NULL) {
        return FALSE;
    }

    //
    // Check debug port
    // PsGetProcessDebugPort returns non-NULL if debugger attached
    //
    return (PsGetProcessDebugPort(Process) != NULL);
}

BOOLEAN
ShadowStrikeIsSystemProcess(
    _In_ HANDLE ProcessId
)
{
    NTSTATUS Status;
    PACCESS_TOKEN Token = NULL;
    BOOLEAN IsSystem = FALSE;

    PAGED_CODE();

    //
    // PID 4 is always System
    //
    if (ShadowStrikeIsSystemProcessId(ProcessId)) {
        return TRUE;
    }

    if (!ShadowStrikeIsValidProcessId(ProcessId)) {
        return FALSE;
    }

    Status = ShadowGetProcessToken(ProcessId, &Token);
    if (!NT_SUCCESS(Status) || Token == NULL) {
        return FALSE;
    }

    IsSystem = ShadowIsSystemToken(Token);

    PsDereferencePrimaryToken(Token);
    return IsSystem;
}

NTSTATUS
ShadowStrikeIsProcessElevated(
    _In_ HANDLE ProcessId,
    _Out_ PBOOLEAN IsElevated
)
{
    NTSTATUS Status;
    PACCESS_TOKEN Token = NULL;

    PAGED_CODE();

    if (IsElevated == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsElevated = FALSE;

    if (!ShadowStrikeIsValidProcessId(ProcessId)) {
        return STATUS_INVALID_PARAMETER;
    }

    Status = ShadowGetProcessToken(ProcessId, &Token);
    if (!NT_SUCCESS(Status) || Token == NULL) {
        return Status;
    }

    //
    // SeTokenIsAdmin returns TRUE if token has admin group enabled
    //
    *IsElevated = SeTokenIsAdmin(Token);

    PsDereferencePrimaryToken(Token);
    return STATUS_SUCCESS;
}

// ============================================================================
// TOKEN AND PRIVILEGE ANALYSIS
// ============================================================================

NTSTATUS
ShadowStrikeGetProcessIntegrityLevel(
    _In_ HANDLE ProcessId,
    _Out_ PSHADOW_INTEGRITY_LEVEL IntegrityLevel
)
{
    NTSTATUS Status;
    PACCESS_TOKEN Token = NULL;

    PAGED_CODE();

    if (IntegrityLevel == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IntegrityLevel = ShadowIntegrityUnknown;

    if (!ShadowStrikeIsValidProcessId(ProcessId)) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // System process is always System integrity
    //
    if (ShadowStrikeIsSystemProcessId(ProcessId)) {
        *IntegrityLevel = ShadowIntegritySystem;
        return STATUS_SUCCESS;
    }

    Status = ShadowGetProcessToken(ProcessId, &Token);
    if (!NT_SUCCESS(Status) || Token == NULL) {
        return Status;
    }

    Status = ShadowGetTokenIntegrityLevel(Token, IntegrityLevel);

    PsDereferencePrimaryToken(Token);
    return Status;
}

NTSTATUS
ShadowStrikeGetProcessSessionId(
    _In_ HANDLE ProcessId,
    _Out_ PULONG SessionId
)
{
    NTSTATUS Status;
    PEPROCESS Process = NULL;

    PAGED_CODE();

    if (SessionId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *SessionId = (ULONG)-1;

    if (!ShadowStrikeIsValidProcessId(ProcessId)) {
        return STATUS_INVALID_PARAMETER;
    }

    Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    *SessionId = PsGetProcessSessionId(Process);

    ObDereferenceObject(Process);
    return STATUS_SUCCESS;
}

NTSTATUS
ShadowStrikeProcessHasPrivilege(
    _In_ HANDLE ProcessId,
    _In_ LUID PrivilegeLuid,
    _Out_ PBOOLEAN HasPrivilege
)
{
    NTSTATUS Status;
    PEPROCESS Process = NULL;
    SECURITY_SUBJECT_CONTEXT SubjectContext;
    PRIVILEGE_SET PrivilegeSet;
    BOOLEAN Result = FALSE;

    PAGED_CODE();

    if (HasPrivilege == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *HasPrivilege = FALSE;

    if (!ShadowStrikeIsValidProcessId(ProcessId)) {
        return STATUS_INVALID_PARAMETER;
    }

    Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // CRITICAL FIX: Use SeCaptureSubjectContext instead of accessing
    // Token->PrimarySecurityContext directly (which is an opaque structure)
    //
    // We need to attach to the target process context to capture its security context
    //
    KAPC_STATE ApcState;
    KeStackAttachProcess(Process, &ApcState);

    SeCaptureSubjectContext(&SubjectContext);

    //
    // Build privilege set
    //
    PrivilegeSet.PrivilegeCount = 1;
    PrivilegeSet.Control = PRIVILEGE_SET_ALL_NECESSARY;
    PrivilegeSet.Privilege[0].Luid = PrivilegeLuid;
    PrivilegeSet.Privilege[0].Attributes = 0;

    //
    // Check privilege using proper subject context
    //
    Result = SePrivilegeCheck(&PrivilegeSet, &SubjectContext, UserMode);

    SeReleaseSubjectContext(&SubjectContext);

    KeUnstackDetachProcess(&ApcState);

    ObDereferenceObject(Process);

    *HasPrivilege = Result;
    return STATUS_SUCCESS;
}

NTSTATUS
ShadowStrikeGetProcessUserSid(
    _In_ HANDLE ProcessId,
    _Out_ PSID* UserSid,
    _Out_ PULONG SidSize
)
{
    NTSTATUS Status;
    PACCESS_TOKEN Token = NULL;
    HANDLE TokenHandle = NULL;
    PTOKEN_USER TokenUser = NULL;
    ULONG TokenUserSize = 0;
    ULONG ReturnLength = 0;
    ULONG SidLength;

    PAGED_CODE();

    if (UserSid == NULL || SidSize == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *UserSid = NULL;
    *SidSize = 0;

    if (!ShadowStrikeIsValidProcessId(ProcessId)) {
        return STATUS_INVALID_PARAMETER;
    }

    Status = ShadowGetProcessToken(ProcessId, &Token);
    if (!NT_SUCCESS(Status) || Token == NULL) {
        return Status;
    }

    //
    // Open handle to token for query
    //
    Status = ObOpenObjectByPointer(
        Token,
        OBJ_KERNEL_HANDLE,
        NULL,
        TOKEN_QUERY,
        *SeTokenObjectType,
        KernelMode,
        &TokenHandle
    );

    if (!NT_SUCCESS(Status)) {
        PsDereferencePrimaryToken(Token);
        return Status;
    }

    //
    // Query required size for TokenUser
    //
    Status = ZwQueryInformationToken(
        TokenHandle,
        TokenUser,
        NULL,
        0,
        &ReturnLength
    );

    if (Status != STATUS_BUFFER_TOO_SMALL || ReturnLength == 0) {
        ZwClose(TokenHandle);
        PsDereferencePrimaryToken(Token);
        return (NT_SUCCESS(Status)) ? STATUS_INTERNAL_ERROR : Status;
    }

    if (ReturnLength > SHADOW_MAX_TOKEN_INFO_SIZE) {
        ZwClose(TokenHandle);
        PsDereferencePrimaryToken(Token);
        return STATUS_BUFFER_OVERFLOW;
    }

    TokenUserSize = ReturnLength;
    TokenUser = (PTOKEN_USER)ShadowStrikeAllocatePagedWithTag(TokenUserSize, SHADOW_TOKEN_TAG);

    if (TokenUser == NULL) {
        ZwClose(TokenHandle);
        PsDereferencePrimaryToken(Token);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = ZwQueryInformationToken(
        TokenHandle,
        TokenUser,
        TokenUser,
        TokenUserSize,
        &ReturnLength
    );

    ZwClose(TokenHandle);
    PsDereferencePrimaryToken(Token);

    if (!NT_SUCCESS(Status)) {
        ShadowStrikeFreePoolWithTag(TokenUser, SHADOW_TOKEN_TAG);
        return Status;
    }

    //
    // Validate SID
    //
    if (TokenUser->User.Sid == NULL || !RtlValidSid(TokenUser->User.Sid)) {
        ShadowStrikeFreePoolWithTag(TokenUser, SHADOW_TOKEN_TAG);
        return STATUS_INVALID_SID;
    }

    //
    // Allocate and copy SID
    //
    SidLength = RtlLengthSid(TokenUser->User.Sid);
    *UserSid = (PSID)ShadowStrikeAllocatePagedWithTag(SidLength, SHADOW_SID_TAG);

    if (*UserSid == NULL) {
        ShadowStrikeFreePoolWithTag(TokenUser, SHADOW_TOKEN_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = RtlCopySid(SidLength, *UserSid, TokenUser->User.Sid);
    if (!NT_SUCCESS(Status)) {
        ShadowStrikeFreePoolWithTag(*UserSid, SHADOW_SID_TAG);
        *UserSid = NULL;
        ShadowStrikeFreePoolWithTag(TokenUser, SHADOW_TOKEN_TAG);
        return Status;
    }

    *SidSize = SidLength;

    ShadowStrikeFreePoolWithTag(TokenUser, SHADOW_TOKEN_TAG);
    return STATUS_SUCCESS;
}

// ============================================================================
// HANDLE OPERATIONS
// ============================================================================

NTSTATUS
ShadowStrikeGetProcessIdFromHandle(
    _In_ HANDLE ProcessHandle,
    _Out_ PHANDLE ProcessId
)
{
    NTSTATUS Status;
    PROCESS_BASIC_INFORMATION BasicInfo;
    ULONG ReturnLength;

    PAGED_CODE();

    if (ProcessId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ProcessId = NULL;

    if (g_ProcessUtilsState.InitializationState != PROCUTILS_STATE_INITIALIZED) {
        Status = ShadowProcessUtilsInitialize();
        if (!NT_SUCCESS(Status)) {
            return Status;
        }
    }

    if (ProcessHandle == NULL || ProcessHandle == NtCurrentProcess()) {
        *ProcessId = PsGetCurrentProcessId();
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&BasicInfo, sizeof(BasicInfo));

    Status = g_ProcessUtilsState.ZwQueryInformationProcess(
        ProcessHandle,
        ProcessBasicInformation,
        &BasicInfo,
        sizeof(BasicInfo),
        &ReturnLength
    );

    if (NT_SUCCESS(Status)) {
        *ProcessId = (HANDLE)BasicInfo.UniqueProcessId;
    }

    return Status;
}

NTSTATUS
ShadowStrikeGetProcessObject(
    _In_ HANDLE ProcessId,
    _Outptr_ PEPROCESS* Process
)
{
    PAGED_CODE();

    if (Process == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Process = NULL;

    if (!ShadowStrikeIsValidProcessId(ProcessId)) {
        return STATUS_INVALID_PARAMETER;
    }

    return PsLookupProcessByProcessId(ProcessId, Process);
}

NTSTATUS
ShadowStrikeOpenProcess(
    _In_ HANDLE ProcessId,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE ProcessHandle
)
{
    PAGED_CODE();

    if (ProcessHandle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ProcessHandle = NULL;

    if (!ShadowStrikeIsValidProcessId(ProcessId)) {
        return STATUS_INVALID_PARAMETER;
    }

    return ShadowOpenProcessInternal(ProcessId, DesiredAccess, ProcessHandle);
}

// ============================================================================
// THREAD OPERATIONS
// ============================================================================

NTSTATUS
ShadowStrikeGetThreadInfo(
    _In_ HANDLE ThreadId,
    _Out_ PSHADOW_THREAD_INFO ThreadInfo
)
{
    NTSTATUS Status;
    PETHREAD Thread = NULL;

    PAGED_CODE();

    if (ThreadInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(ThreadInfo, sizeof(SHADOW_THREAD_INFO));

    if (ThreadId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Status = PsLookupThreadByThreadId(ThreadId, &Thread);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    ThreadInfo->ThreadId = ThreadId;
    ThreadInfo->ProcessId = PsGetThreadProcessId(Thread);
    ThreadInfo->IsTerminating = PsIsThreadTerminating(Thread);

    //
    // Get start address
    //
    ShadowStrikeGetThreadStartAddress(
        ThreadId,
        &ThreadInfo->StartAddress,
        &ThreadInfo->Win32StartAddress
    );

    //
    // Get creation time
    //
    ThreadInfo->CreateTime = PsGetThreadCreateTime(Thread);

    //
    // Check if system thread
    //
    ThreadInfo->IsSystemThread = PsIsSystemThread(Thread);

    ObDereferenceObject(Thread);
    return STATUS_SUCCESS;
}

BOOLEAN
ShadowStrikeIsThreadTerminating(
    _In_ PETHREAD Thread
)
{
    if (Thread == NULL) {
        return TRUE;
    }

    return PsIsThreadTerminating(Thread);
}

NTSTATUS
ShadowStrikeGetThreadStartAddress(
    _In_ HANDLE ThreadId,
    _Out_ PVOID* StartAddress,
    _Out_opt_ PVOID* Win32StartAddress
)
{
    NTSTATUS Status;
    HANDLE ThreadHandle = NULL;
    OBJECT_ATTRIBUTES ObjectAttributes;
    CLIENT_ID ClientId;
    PVOID ThreadStartAddress = NULL;
    ULONG ReturnLength;

    PAGED_CODE();

    if (StartAddress == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *StartAddress = NULL;
    if (Win32StartAddress != NULL) {
        *Win32StartAddress = NULL;
    }

    if (g_ProcessUtilsState.InitializationState != PROCUTILS_STATE_INITIALIZED ||
        g_ProcessUtilsState.ZwQueryInformationThread == NULL) {
        return STATUS_NOT_SUPPORTED;
    }

    //
    // Open thread
    //
    InitializeObjectAttributes(
        &ObjectAttributes,
        NULL,
        OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );

    ClientId.UniqueProcess = NULL;
    ClientId.UniqueThread = ThreadId;

    Status = ZwOpenThread(
        &ThreadHandle,
        THREAD_QUERY_LIMITED_INFORMATION,
        &ObjectAttributes,
        &ClientId
    );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Query thread start address (ThreadQuerySetWin32StartAddress = 9)
    //
    Status = g_ProcessUtilsState.ZwQueryInformationThread(
        ThreadHandle,
        ThreadQuerySetWin32StartAddress,
        &ThreadStartAddress,
        sizeof(PVOID),
        &ReturnLength
    );

    if (NT_SUCCESS(Status)) {
        *StartAddress = ThreadStartAddress;
        if (Win32StartAddress != NULL) {
            *Win32StartAddress = ThreadStartAddress;
        }
    }

    ZwClose(ThreadHandle);
    return Status;
}

// ============================================================================
// PROCESS VALIDATION
// ============================================================================

NTSTATUS
ShadowStrikeValidateProcessSignature(
    _In_ HANDLE ProcessId,
    _Out_ PBOOLEAN IsSigned,
    _Out_opt_ PSHADOW_SIGNER_TYPE SignerType
)
{
    NTSTATUS Status;
    HANDLE ProcessHandle = NULL;
    PS_PROTECTION Protection;
    ULONG ReturnLength;

    PAGED_CODE();

    if (IsSigned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsSigned = FALSE;
    if (SignerType != NULL) {
        *SignerType = ShadowSignerNone;
    }

    if (!ShadowStrikeIsValidProcessId(ProcessId)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_ProcessUtilsState.InitializationState != PROCUTILS_STATE_INITIALIZED) {
        Status = ShadowProcessUtilsInitialize();
        if (!NT_SUCCESS(Status)) {
            return Status;
        }
    }

    //
    // Query protection information (Windows 8.1+)
    //
    Status = ShadowOpenProcessInternal(
        ProcessId,
        PROCESS_QUERY_LIMITED_INFORMATION,
        &ProcessHandle
    );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    RtlZeroMemory(&Protection, sizeof(Protection));

    Status = g_ProcessUtilsState.ZwQueryInformationProcess(
        ProcessHandle,
        ProcessProtectionInformation,
        &Protection,
        sizeof(Protection),
        &ReturnLength
    );

    ZwClose(ProcessHandle);

    if (NT_SUCCESS(Status)) {
        //
        // Protected processes are by definition signed
        //
        if (Protection.Type != PsProtectedTypeNone) {
            *IsSigned = TRUE;
            if (SignerType != NULL) {
                //
                // Map protection signer to our enum
                //
                switch (Protection.Signer) {
                    case PsProtectedSignerAuthenticode:
                        *SignerType = ShadowSignerAuthenticode;
                        break;
                    case PsProtectedSignerCodeGen:
                        *SignerType = ShadowSignerCodeGen;
                        break;
                    case PsProtectedSignerAntimalware:
                        *SignerType = ShadowSignerAntimalware;
                        break;
                    case PsProtectedSignerLsa:
                        *SignerType = ShadowSignerLsa;
                        break;
                    case PsProtectedSignerWindows:
                        *SignerType = ShadowSignerWindows;
                        break;
                    case PsProtectedSignerWinTcb:
                        *SignerType = ShadowSignerWinTcb;
                        break;
                    case PsProtectedSignerWinSystem:
                        *SignerType = ShadowSignerWinSystem;
                        break;
                    case PsProtectedSignerApp:
                        *SignerType = ShadowSignerApp;
                        break;
                    default:
                        *SignerType = ShadowSignerNone;
                        break;
                }
            }
        }
    } else if (Status == STATUS_INVALID_INFO_CLASS) {
        //
        // ProcessProtectionInformation not supported on this OS version
        // This is expected on older systems
        //
        Status = STATUS_SUCCESS;
    }

    //
    // Note: For complete signature validation of non-protected processes,
    // we would need to use Code Integrity APIs (CiCheckSignedFile, etc.)
    // or hook into the image load callback infrastructure.
    // This is typically done at image load time and cached.
    //

    return STATUS_SUCCESS;
}

NTSTATUS
ShadowStrikeIsWindowsProcess(
    _In_ HANDLE ProcessId,
    _Out_ PBOOLEAN IsWindowsProcess
)
{
    NTSTATUS Status;
    UNICODE_STRING ImagePath = { 0 };
    UNICODE_STRING WindowsDir;
    UNICODE_STRING System32Dir;
    UNICODE_STRING SysWow64Dir;

    PAGED_CODE();

    if (IsWindowsProcess == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsWindowsProcess = FALSE;

    //
    // System process is Windows
    //
    if (ShadowStrikeIsSystemProcessId(ProcessId)) {
        *IsWindowsProcess = TRUE;
        return STATUS_SUCCESS;
    }

    Status = ShadowStrikeGetProcessImagePath(ProcessId, &ImagePath);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Check common Windows paths
    //
    RtlInitUnicodeString(&WindowsDir, L"\\Windows\\");
    RtlInitUnicodeString(&System32Dir, L"\\System32\\");
    RtlInitUnicodeString(&SysWow64Dir, L"\\SysWOW64\\");

    if (ShadowStrikeStringContains(&ImagePath, &WindowsDir, TRUE) &&
        (ShadowStrikeStringContains(&ImagePath, &System32Dir, TRUE) ||
         ShadowStrikeStringContains(&ImagePath, &SysWow64Dir, TRUE))) {
        *IsWindowsProcess = TRUE;
    }

    ShadowFreeProcessString(&ImagePath);
    return STATUS_SUCCESS;
}

NTSTATUS
ShadowStrikeClassifyProcess(
    _In_ HANDLE ProcessId,
    _Out_ PSHADOW_PROCESS_TYPE ProcessType
)
{
    NTSTATUS Status;
    PEPROCESS Process = NULL;
    SHADOW_INTEGRITY_LEVEL IntegrityLevel;
    BOOLEAN IsWow64;
    BOOLEAN IsProtected;
    BOOLEAN IsWindowsProc;
    ULONG SessionId;

    PAGED_CODE();

    if (ProcessType == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ProcessType = ShadowProcessUnknown;

    if (!ShadowStrikeIsValidProcessId(ProcessId)) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // System process
    //
    if (ShadowStrikeIsSystemProcessId(ProcessId)) {
        *ProcessType = ShadowProcessSystem;
        return STATUS_SUCCESS;
    }

    Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Check process attributes
    //
    IsWow64 = ShadowStrikeIsProcessWow64(Process);
    IsProtected = ShadowStrikeIsProcessProtected(Process);

    ObDereferenceObject(Process);

    //
    // Protected process
    //
    if (IsProtected) {
        *ProcessType = ShadowProcessProtected;
        return STATUS_SUCCESS;
    }

    //
    // Check session
    //
    ShadowStrikeGetProcessSessionId(ProcessId, &SessionId);

    //
    // Session 0 is typically services
    //
    if (SessionId == 0) {
        //
        // Could be System, Service, or Native
        //
        ShadowStrikeGetProcessIntegrityLevel(ProcessId, &IntegrityLevel);
        if (IntegrityLevel == ShadowIntegritySystem) {
            *ProcessType = ShadowProcessService;
        } else {
            *ProcessType = ShadowProcessService;
        }
        return STATUS_SUCCESS;
    }

    //
    // WOW64 process
    //
    if (IsWow64) {
        *ProcessType = ShadowProcessWow64;
        return STATUS_SUCCESS;
    }

    //
    // Check if Windows process
    //
    ShadowStrikeIsWindowsProcess(ProcessId, &IsWindowsProc);
    if (IsWindowsProc) {
        ShadowStrikeGetProcessIntegrityLevel(ProcessId, &IntegrityLevel);
        if (IntegrityLevel == ShadowIntegritySystem) {
            *ProcessType = ShadowProcessSystem;
        } else {
            *ProcessType = ShadowProcessNative;
        }
        return STATUS_SUCCESS;
    }

    //
    // Default to user process
    //
    *ProcessType = ShadowProcessUser;
    return STATUS_SUCCESS;
}
