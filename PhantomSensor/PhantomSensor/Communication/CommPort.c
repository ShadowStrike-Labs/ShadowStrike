/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/**
 * ============================================================================
 * ShadowStrike NGAV - COMMUNICATION PORT
 * ============================================================================
 *
 * @file CommPort.c
 * @brief Filter Manager communication port implementation.
 *
 * Implements the kernel-to-user-mode communication channel using
 * Filter Manager communication ports with:
 * - Reference counting for safe client port access
 * - Client authentication and capability-based authorization
 * - Proper user-mode buffer validation with try/except
 * - Protected process registration
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "CommPort.h"
#include "MessageHandler.h"
#include "Compression.h"
#include "Encryption.h"
#include "MessageQueue.h"
#include "../Core/Globals.h"
#include "../Core/DriverEntry.h"
#include "../../Shared/SharedDefs.h"
#include "../../Shared/MessageTypes.h"
#include "../../Shared/ErrorCodes.h"
#include "../Context/InstanceContext.h"
#include "../Utilities/FileUtils.h"

//
// PID of the connected primary scanner service. The kernel must NEVER issue a
// synchronous user-mode scan for this process's OWN file I/O: while servicing a
// scan request the scanner's worker threads open/read files (and load DLLs,
// write logs, etc.), and scanning those opens would recurse back into the
// synchronous IRP_MJ_CREATE -> SbSendScanRequest path, exhaust the scanner's
// worker pool, and deadlock all file I/O on the system (every other process's
// create then stalls on the scan timeout). Recorded directly at connect time —
// before the encrypted channel can carry any scan traffic — so the exemption is
// race-free, and cleared at disconnect.
//
// NOTE: the user-mode RegisterProtectedProcess path inserts into
// g_DriverData.ProtectedProcessList, which is a DIFFERENT list than the one
// ShadowStrikeIsProcessProtected() (consulted by the file callbacks) reads, so
// it does NOT provide this exemption. This dedicated record does.
//
static volatile LONG g_ScannerServiceProcessId = 0;

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
ShadowStrikeIsScannerProcess(
    _In_ HANDLE ProcessId
    )
{
    LONG scannerPid = ReadNoFence(&g_ScannerServiceProcessId);
    return (BOOLEAN)(scannerPid != 0 && HandleToLong(ProcessId) == scannerPid);
}

//
// PsGetProcessInheritedFromUniqueProcessId â€” exported by ntoskrnl.exe
// since Windows XP. Not declared in public WDK headers but stable and
// widely used in production security drivers (minifilters, EDR agents).
// Returns the parent process ID from the EPROCESS structure.
//
NTKERNELAPI
HANDLE
NTAPI
PsGetProcessInheritedFromUniqueProcessId(
    _In_ PEPROCESS Process
    );

//
// Forward declaration for the deferred-kex work-item routine. Required
// before its alloc_text pragma below.
//
_Function_class_(FLT_GENERIC_WORKITEM_ROUTINE)
static VOID FLTAPI
ShadowStrikeDeliverKexWorker(
    _In_ PFLT_GENERIC_WORKITEM FltWorkItem,
    _In_ PFLT_FILTER FltObject,
    _In_opt_ PVOID Context
    );

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, ShadowStrikeCreateCommunicationPort)
#pragma alloc_text(PAGE, ShadowStrikeCloseCommunicationPort)
#pragma alloc_text(PAGE, ShadowStrikeConnectNotify)
#pragma alloc_text(PAGE, ShadowStrikeDisconnectNotify)
#pragma alloc_text(PAGE, ShadowStrikeMessageNotify)
#pragma alloc_text(PAGE, ShadowStrikeVerifyClient)
#pragma alloc_text(PAGE, ShadowStrikeDeliverKexWorker)
#pragma alloc_text(PAGE, ShadowStrikeRegisterProtectedProcess)
#pragma alloc_text(PAGE, ShadowStrikeUnregisterProtectedProcess)
#pragma alloc_text(PAGE, ShadowStrikeBuildFileScanRequest)
#endif

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

/**
 * @brief Protected process entry for self-protection list.
 */
typedef struct _SHADOWSTRIKE_PROTECTED_PROCESS_ENTRY {
    LIST_ENTRY ListEntry;
    ULONG ProcessId;
    ULONG ProtectionFlags;
    WCHAR ProcessName[MAX_PROCESS_NAME_LENGTH];
} SHADOWSTRIKE_PROTECTED_PROCESS_ENTRY, *PSHADOWSTRIKE_PROTECTED_PROCESS_ENTRY;

// ============================================================================
// EXTENDED CLIENT PORT ARRAY
// ============================================================================

/**
 * @brief Extended client port storage with reference counting.
 *
 * This replaces the simple SHADOWSTRIKE_CLIENT_PORT in globals with
 * the reference-counted version.
 */
static SHADOWSTRIKE_CLIENT_PORT_REF g_ClientPortRefs[SHADOWSTRIKE_MAX_CONNECTIONS];
static PENC_KEY g_ClientSessionEncKeys[SHADOWSTRIKE_MAX_CONNECTIONS];

//
// HMAC-SHA256 transport authentication key (32 bytes, generated per boot)
//
#define SHADOWSTRIKE_HMAC_KEY_SIZE     32
#define SHADOWSTRIKE_HMAC_OUTPUT_SIZE  32

static UCHAR g_CommHmacKey[SHADOWSTRIKE_HMAC_KEY_SIZE] = {0};
static volatile LONG g_CommHmacKeyReady = 0;

static __forceinline BOOLEAN
ShadowStrikeIsCommHmacKeyReady(
    VOID
    )
{
    return (InterlockedCompareExchange(&g_CommHmacKeyReady, 0, 0) != 0);
}

static __forceinline VOID
ShadowStrikeSetCommHmacKeyReady(
    _In_ BOOLEAN Ready
    )
{
    InterlockedExchange(&g_CommHmacKeyReady, Ready ? 1 : 0);
}

// ============================================================================
// INTERNAL HELPER DECLARATIONS
// ============================================================================

#define COMMPORT_SID_POOL_TAG  'dISC'

/**
 * @brief Allocate and initialize a SID using exported kernel APIs.
 *
 * Kernel-mode replacement for RtlAllocateAndInitializeSid which is not
 * in the WDK import library. Uses RtlLengthRequiredSid + RtlInitializeSid +
 * RtlSubAuthoritySid.
 */
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
CppAllocateAndInitializeSid(
    _In_ PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
    _In_ UCHAR SubAuthorityCount,
    _In_ ULONG SubAuthority0,
    _Outptr_ PSID* Sid
    )
{
    ULONG sidLength;
    PSID newSid;
    NTSTATUS status;

    PAGED_CODE();

    *Sid = NULL;

    if (SubAuthorityCount == 0 || SubAuthorityCount > SID_MAX_SUB_AUTHORITIES) {
        return STATUS_INVALID_PARAMETER;
    }

    sidLength = RtlLengthRequiredSid(SubAuthorityCount);

    newSid = ExAllocatePool2(POOL_FLAG_PAGED, sidLength, COMMPORT_SID_POOL_TAG);
    if (newSid == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = RtlInitializeSid(newSid, IdentifierAuthority, SubAuthorityCount);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(newSid, COMMPORT_SID_POOL_TAG);
        return status;
    }

    *RtlSubAuthoritySid(newSid, 0) = SubAuthority0;

    *Sid = newSid;
    return STATUS_SUCCESS;
}

static NTSTATUS
ShadowStrikeValidateInputBuffer(
    _In_reads_bytes_(BufferLength) PVOID Buffer,
    _In_ ULONG BufferLength,
    _Out_ PSHADOWSTRIKE_MESSAGE_HEADER Header
    );

static NTSTATUS
ShadowStrikeHandleQueryDriverStatus(
    _In_ PSHADOWSTRIKE_MESSAGE_HEADER InputHeader,
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnLength
    );

static NTSTATUS
ShadowStrikeHandleUpdatePolicy(
    _In_ LONG ClientIndex,
    _In_reads_bytes_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _In_ BOOLEAN InputBufferTrusted
    );

static NTSTATUS
ShadowStrikeHandleEnableDisableFiltering(
    _In_ LONG ClientIndex,
    _In_ BOOLEAN Enable
    );

static NTSTATUS
ShadowStrikeHandleRegisterProtectedProcess(
    _In_ LONG ClientIndex,
    _In_reads_bytes_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _In_ BOOLEAN InputBufferTrusted
    );

static NTSTATUS
ShadowStrikeCopyMessagePayload(
    _In_reads_bytes_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _In_ ULONG PayloadOffset,
    _Out_writes_bytes_(PayloadSize) PVOID LocalPayload,
    _In_ ULONG PayloadSize,
    _In_ BOOLEAN InputBufferTrusted
    );

static NTSTATUS
ShadowStrikeAcquireClientPortBySlot(
    _In_ LONG SlotIndex,
    _Out_ PSHADOWSTRIKE_CLIENT_PORT_REF* ClientRef
    );

static VOID
ShadowStrikePrepareEncryptedMessageHeader(
    _Out_ PSHADOWSTRIKE_MESSAGE_HEADER DestinationHeader,
    _In_ PSHADOWSTRIKE_MESSAGE_HEADER SourceHeader,
    _In_ ULONG EncryptedPayloadSize
    );

static VOID
ShadowStrikeReleaseSessionCryptoKey(
    _Inout_opt_ PENC_KEY* SessionKey
    );

static VOID
ShadowStrikeFinalizeClientDisconnect(
    _In_ LONG SlotIndex
    );

static NTSTATUS
ShadowStrikeHandleHeartbeat(
    _In_ PSHADOWSTRIKE_MESSAGE_HEADER InputHeader,
    _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnLength
    );

static NTSTATUS
ShadowStrikeGetProcessImagePath(
    _In_ HANDLE ProcessId,
    _Out_writes_bytes_(BufferSize) PWCHAR Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG ActualLength
    );

// ============================================================================
// INTERNAL HELPER IMPLEMENTATIONS
// ============================================================================

/**
 * @brief Validate user-mode input buffer and safely copy message header.
 *
 * Probes the buffer, copies the header to a safe kernel location,
 * and validates magic, version, size consistency.
 */
static NTSTATUS
ShadowStrikeValidateInputBuffer(
    _In_reads_bytes_(BufferLength) PVOID Buffer,
    _In_ ULONG BufferLength,
    _Out_ PSHADOWSTRIKE_MESSAGE_HEADER Header
    )
{
    if (Buffer == NULL || Header == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (BufferLength < sizeof(SHADOWSTRIKE_MESSAGE_HEADER)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Safely probe and copy from user-mode buffer
    //
    __try {
        ProbeForRead(Buffer, BufferLength, sizeof(UINT32));
        RtlCopyMemory(Header, Buffer, sizeof(SHADOWSTRIKE_MESSAGE_HEADER));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Exception probing input buffer (status=0x%08X)\n",
                   GetExceptionCode());
        return STATUS_INVALID_USER_BUFFER;
    }

    //
    // Validate magic and version
    //
    if (!SHADOWSTRIKE_VALID_MESSAGE_HEADER(Header)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Invalid message header (magic=0x%08X, version=%u)\n",
                   Header->Magic, Header->Version);
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate TotalSize does not exceed buffer
    //
    if (Header->TotalSize > BufferLength) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Message size mismatch: header=%u, buffer=%u\n",
                   Header->TotalSize, BufferLength);
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate DataSize consistency
    //
    if (Header->DataSize > Header->TotalSize - sizeof(SHADOWSTRIKE_MESSAGE_HEADER)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] DataSize exceeds available space\n");
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

static VOID
ShadowStrikePrepareEncryptedMessageHeader(
    _Out_ PSHADOWSTRIKE_MESSAGE_HEADER DestinationHeader,
    _In_ PSHADOWSTRIKE_MESSAGE_HEADER SourceHeader,
    _In_ ULONG EncryptedPayloadSize
    )
{
    if (DestinationHeader == NULL || SourceHeader == NULL) {
        return;
    }

    RtlCopyMemory(
        DestinationHeader,
        SourceHeader,
        sizeof(SHADOWSTRIKE_MESSAGE_HEADER)
    );
    DestinationHeader->Flags |= SHADOWSTRIKE_MSG_FLAG_ENCRYPTED;
    DestinationHeader->DataSize = EncryptedPayloadSize;
    DestinationHeader->TotalSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + EncryptedPayloadSize;
}

static VOID
ShadowStrikeReleaseSessionCryptoKey(
    _Inout_opt_ PENC_KEY* SessionKey
    )
{
    PENC_KEY key;
    LONG remainingRefs;
    PENC_MANAGER encMgr;

    if (SessionKey == NULL || *SessionKey == NULL) {
        return;
    }

    key = *SessionKey;
    *SessionKey = NULL;

    remainingRefs = EncKeyRelease(key);
    if (remainingRefs == 0) {
        encMgr = ShadowStrikeGetEncryptionManager();
        if (encMgr != NULL) {
            EncDestroyKey(encMgr, key);
        }
    }
}

static NTSTATUS
ShadowStrikeCopyMessagePayload(
    _In_reads_bytes_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _In_ ULONG PayloadOffset,
    _Out_writes_bytes_(PayloadSize) PVOID LocalPayload,
    _In_ ULONG PayloadSize,
    _In_ BOOLEAN InputBufferTrusted
    )
{
    if (InputBuffer == NULL || LocalPayload == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InputBufferLength < PayloadOffset ||
        InputBufferLength - PayloadOffset < PayloadSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    __try {
        if (!InputBufferTrusted) {
            ProbeForRead(InputBuffer, InputBufferLength, sizeof(UINT32));
        }

        RtlCopyMemory(
            LocalPayload,
            (PUCHAR)InputBuffer + PayloadOffset,
            PayloadSize
        );
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return InputBufferTrusted ? STATUS_ACCESS_VIOLATION : STATUS_INVALID_USER_BUFFER;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Get process image path for a given process ID.
 *
 * Uses SeLocateProcessImageName to retrieve the full image path,
 * copies it to the caller-provided buffer with null termination.
 */
static NTSTATUS
ShadowStrikeGetProcessImagePath(
    _In_ HANDLE ProcessId,
    _Out_writes_bytes_(BufferSize) PWCHAR Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG ActualLength
    )
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PUNICODE_STRING imageName = NULL;
    ULONG copyLength;

    PAGED_CODE();

    if (Buffer == NULL || ActualLength == NULL || BufferSize < sizeof(WCHAR)) {
        return STATUS_INVALID_PARAMETER;
    }

    *ActualLength = 0;
    Buffer[0] = L'\0';

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = SeLocateProcessImageName(process, &imageName);
    ObDereferenceObject(process);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (imageName == NULL || imageName->Buffer == NULL || imageName->Length == 0) {
        if (imageName != NULL) {
            ExFreePool(imageName);
        }
        return STATUS_NOT_FOUND;
    }

    //
    // Copy as much as fits, always null-terminate
    //
    copyLength = imageName->Length;
    if (copyLength > BufferSize - sizeof(WCHAR)) {
        copyLength = BufferSize - sizeof(WCHAR);
    }

    RtlCopyMemory(Buffer, imageName->Buffer, copyLength);
    Buffer[copyLength / sizeof(WCHAR)] = L'\0';
    *ActualLength = copyLength + sizeof(WCHAR);

    ExFreePool(imageName);
    return STATUS_SUCCESS;
}

// ============================================================================
// PORT CREATION AND DESTRUCTION
// ============================================================================

NTSTATUS
ShadowStrikeCreateCommunicationPort(
    _In_ PFLT_FILTER FilterHandle
    )
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR securityDescriptor = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING portName;
    LONG i;

    PAGED_CODE();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Creating communication port: %ws\n",
               SHADOWSTRIKE_PORT_NAME);

    //
    // Initialize client port reference array
    //
    RtlZeroMemory(g_ClientPortRefs, sizeof(g_ClientPortRefs));
    RtlZeroMemory(g_ClientSessionEncKeys, sizeof(g_ClientSessionEncKeys));
    for (i = 0; i < SHADOWSTRIKE_MAX_CONNECTIONS; i++) {
        g_ClientPortRefs[i].SlotIndex = i;
    }

    //
    // Generate per-boot HMAC transport key BEFORE creating the port.
    //
    // SECURITY: FltCreateCommunicationPort publishes the port atomically;
    // a connecting client could fire ConnectNotify immediately after the port
    // becomes visible. Seed the mandatory transport secret first using the
    // encryption manager's already-open RNG provider. If early-boot CNG is not
    // ready yet, ConnectNotify will retry seeding and fail closed with
    // STATUS_DEVICE_NOT_READY until strong randomness is available.
    //
    {
        PENC_MANAGER encMgr = ShadowStrikeGetEncryptionManager();
        NTSTATUS keyStatus = (encMgr != NULL) ?
            EncRandomBytes(encMgr, g_CommHmacKey, SHADOWSTRIKE_HMAC_KEY_SIZE) :
            STATUS_DEVICE_NOT_READY;

        if (NT_SUCCESS(keyStatus)) {
            ShadowStrikeSetCommHmacKeyReady(TRUE);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "[ShadowStrike] HMAC transport key generated\n");
        } else {
            ShadowStrikeSetCommHmacKeyReady(FALSE);
            RtlSecureZeroMemory(g_CommHmacKey, sizeof(g_CommHmacKey));
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] HMAC key generation deferred (0x%08X) — "
                       "mandatory encryption will reject clients until reseeded\n",
                       keyStatus);
        }
    }

    //
    // Build explicit, audit-grade security descriptor for the filter port.
    //
    // Trustees:
    //   - NT AUTHORITY\SYSTEM (S-1-5-18)        -> FLT_PORT_ALL_ACCESS (service)
    //   - BUILTIN\Administrators (S-1-5-32-544) -> FLT_PORT_CONNECT    (diag tools)
    //
    // We do NOT use FltBuildDefaultSecurityDescriptor: its trustee set is
    // implementation-defined and not auditable from a security-descriptor
    // dump. Concretely building the DACL gives us a self-relative SD that
    // a `!sd` in WinDbg (or an SDDL audit) reads exactly as the trustees
    // we intend, immune to WDK behavior drift across versions.
    //
    // No Everyone-allow ACE is added: any token that is neither SYSTEM nor
    // a member of Administrators is therefore implicitly denied by the
    // standard NT access-check default-deny semantics. We deliberately do
    // NOT add an Everyone-deny ACE: canonical ACL ordering places DENY
    // ACEs before ALLOW ACEs, which would also deny SYSTEM/Admins
    // (transitive members of Everyone).
    //
    {
        SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
        PSID    systemSid = NULL;
        PSID    adminsSid = NULL;
        PACL    dacl      = NULL;
        ULONG   daclSize  = 0;
        ULONG   selfRelSize = 0;
        SECURITY_DESCRIPTOR absoluteSd;

        securityDescriptor = NULL;

        //
        // Build LocalSystem SID (1 sub-authority).
        //
        status = CppAllocateAndInitializeSid(&ntAuth, 1,
                                             SECURITY_LOCAL_SYSTEM_RID, &systemSid);
        if (!NT_SUCCESS(status)) {
            goto SdCleanup;
        }

        //
        // Built-in Administrators: S-1-5-32-544 (2 sub-authorities).
        // CppAllocateAndInitializeSid only takes one sub-authority, so build
        // it inline using the same kernel primitives.
        //
        {
            ULONG sidLen = RtlLengthRequiredSid(2);
            adminsSid = ExAllocatePool2(POOL_FLAG_PAGED, sidLen, COMMPORT_SID_POOL_TAG);
            if (adminsSid == NULL) {
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto SdCleanup;
            }
            status = RtlInitializeSid(adminsSid, &ntAuth, 2);
            if (!NT_SUCCESS(status)) {
                goto SdCleanup;
            }
            *RtlSubAuthoritySid(adminsSid, 0) = SECURITY_BUILTIN_DOMAIN_RID;
            *RtlSubAuthoritySid(adminsSid, 1) = DOMAIN_ALIAS_RID_ADMINS;
        }

        //
        // DACL size: ACL header + (ACCESS_ALLOWED_ACE - SidStart) * 2 + sizes
        // of the two SIDs, rounded up to ULONG alignment.
        //
        daclSize = sizeof(ACL)
                 + (sizeof(ACCESS_ALLOWED_ACE) - sizeof(ULONG)) + RtlLengthSid(systemSid)
                 + (sizeof(ACCESS_ALLOWED_ACE) - sizeof(ULONG)) + RtlLengthSid(adminsSid);
        daclSize = (daclSize + sizeof(ULONG) - 1) & ~(sizeof(ULONG) - 1);

        dacl = ExAllocatePool2(POOL_FLAG_PAGED, daclSize, COMMPORT_SID_POOL_TAG);
        if (dacl == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto SdCleanup;
        }

        status = RtlCreateAcl(dacl, daclSize, ACL_REVISION);
        if (!NT_SUCCESS(status)) {
            goto SdCleanup;
        }

        //
        // ALLOW SYSTEM all access, ALLOW Admins connect-only. No Everyone ACE.
        //
        status = RtlAddAccessAllowedAce(dacl, ACL_REVISION,
                                        FLT_PORT_ALL_ACCESS, systemSid);
        if (!NT_SUCCESS(status)) {
            goto SdCleanup;
        }

        status = RtlAddAccessAllowedAce(dacl, ACL_REVISION,
                                        FLT_PORT_CONNECT, adminsSid);
        if (!NT_SUCCESS(status)) {
            goto SdCleanup;
        }

        //
        // Compose absolute SD, attach DACL, set owner to SYSTEM, then convert
        // to self-relative form (required by OBJECT_ATTRIBUTES).
        //
        status = RtlCreateSecurityDescriptor(&absoluteSd,
                                             SECURITY_DESCRIPTOR_REVISION);
        if (!NT_SUCCESS(status)) {
            goto SdCleanup;
        }

        status = RtlSetDaclSecurityDescriptor(&absoluteSd, TRUE, dacl, FALSE);
        if (!NT_SUCCESS(status)) {
            goto SdCleanup;
        }

        status = RtlSetOwnerSecurityDescriptor(&absoluteSd, systemSid, FALSE);
        if (!NT_SUCCESS(status)) {
            goto SdCleanup;
        }

        //
        // Two-phase conversion: first ask for the required size, then
        // allocate and convert.
        //
        status = RtlAbsoluteToSelfRelativeSD(&absoluteSd, NULL, &selfRelSize);
        if (status != STATUS_BUFFER_TOO_SMALL) {
            if (NT_SUCCESS(status)) {
                status = STATUS_UNSUCCESSFUL;
            }
            goto SdCleanup;
        }

        securityDescriptor = ExAllocatePool2(POOL_FLAG_PAGED, selfRelSize,
                                             COMMPORT_SID_POOL_TAG);
        if (securityDescriptor == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto SdCleanup;
        }

        status = RtlAbsoluteToSelfRelativeSD(&absoluteSd,
                                             securityDescriptor, &selfRelSize);

    SdCleanup:
        if (systemSid) ExFreePoolWithTag(systemSid, COMMPORT_SID_POOL_TAG);
        if (adminsSid) ExFreePoolWithTag(adminsSid, COMMPORT_SID_POOL_TAG);
        if (dacl)      ExFreePoolWithTag(dacl,      COMMPORT_SID_POOL_TAG);

        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[ShadowStrike] Build hardened SD failed: 0x%08X\n",
                       status);
            if (securityDescriptor) {
                ExFreePoolWithTag(securityDescriptor, COMMPORT_SID_POOL_TAG);
                securityDescriptor = NULL;
            }
            return status;
        }
    }

    RtlInitUnicodeString(&portName, SHADOWSTRIKE_PORT_NAME);

    InitializeObjectAttributes(
        &objectAttributes,
        &portName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        securityDescriptor
    );

    //
    // Create the server port
    //
    status = FltCreateCommunicationPort(
        FilterHandle,
        &g_DriverData.ServerPort,
        &objectAttributes,
        NULL,                               // ServerPortCookie
        ShadowStrikeConnectNotify,          // ConnectNotifyCallback
        ShadowStrikeDisconnectNotify,       // DisconnectNotifyCallback
        ShadowStrikeMessageNotify,          // MessageNotifyCallback
        SHADOWSTRIKE_PORT_MAX_CONNECTIONS   // MaxConnections
    );

    //
    // Free the self-relative SD with the matching tag we allocated under.
    // Note: this is NOT FltFreeSecurityDescriptor — that API is paired with
    // FltBuildDefaultSecurityDescriptor, which we no longer use.
    //
    ExFreePoolWithTag(securityDescriptor, COMMPORT_SID_POOL_TAG);
    securityDescriptor = NULL;

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] FltCreateCommunicationPort failed: 0x%08X\n",
                   status);
        g_DriverData.ServerPort = NULL;
        return status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Communication port created successfully\n");

    return STATUS_SUCCESS;
}

VOID
ShadowStrikeCloseCommunicationPort(
    VOID
    )
{
    LONG i;
    LONG waitCount;
    LARGE_INTEGER waitInterval;
    BOOLEAN markedForFinalize[SHADOWSTRIKE_MAX_CONNECTIONS] = {0};

    PAGED_CODE();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Closing communication port\n");

    //
    // PASS 1: Atomically transition each live slot to "disconnecting".
    //
    // We track which slots WE marked (Disconnecting transitioned 0->1) so we
    // alone are responsible for releasing the baseline reference held since
    // ConnectNotify.  Slots already marked by a prior DisconnectNotify path
    // are owned by that path and must not be double-decremented.
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_DriverData.ClientPortLock);

    for (i = 0; i < SHADOWSTRIKE_MAX_CONNECTIONS; i++) {
        if (g_ClientPortRefs[i].ClientPort == NULL) {
            continue;
        }
        if (InterlockedExchange(&g_ClientPortRefs[i].Disconnecting, 1) == 0) {
            //
            // Transitioned 0 -> 1; we own the baseline reference drop.
            //
            markedForFinalize[i] = TRUE;
        }
    }

    ExReleasePushLockExclusive(&g_DriverData.ClientPortLock);
    KeLeaveCriticalRegion();

    //
    // PASS 2: Drop the baseline reference for every slot we marked.  The
    // last reference releaser (could be us, could be an in-flight sender)
    // will call ShadowStrikeFinalizeClientDisconnect, which closes the
    // client port handle and scrubs session key material.  This restores
    // proper cleanup semantics — previously the baseline reference was
    // never dropped at shutdown, leaking every connected client port plus
    // its session key for the lifetime of the OS load.
    //
    for (i = 0; i < SHADOWSTRIKE_MAX_CONNECTIONS; i++) {
        if (!markedForFinalize[i]) {
            continue;
        }
        if (InterlockedDecrement(&g_ClientPortRefs[i].ReferenceCount) == 0) {
            ShadowStrikeFinalizeClientDisconnect(i);
        }
    }

    //
    // PASS 3: Wait for any slots whose references are still held by
    // in-flight senders to drain naturally.  Once their last sender
    // releases, finalize will run and clean the slot.
    //
    waitInterval.QuadPart = -10000LL * 100;  // 100ms intervals

    for (i = 0; i < SHADOWSTRIKE_MAX_CONNECTIONS; i++) {
        if (g_ClientPortRefs[i].ClientPort == NULL) {
            continue;
        }
        waitCount = 0;
        while (g_ClientPortRefs[i].ClientPort != NULL && waitCount < 50) {
            KeDelayExecutionThread(KernelMode, FALSE, &waitInterval);
            waitCount++;
        }

        if (g_ClientPortRefs[i].ClientPort != NULL) {
            //
            // Drain timed out — an in-flight sender is stuck holding a
            // reference (e.g., FltSendMessage waiting on user-mode reply).
            // Leak the slot rather than UAF: the port handle and key
            // material will be reclaimed by the OS at full driver unload.
            //
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[ShadowStrike] CRITICAL: Client slot %ld still has %ld refs after drain timeout — "
                       "leaking port to avoid use-after-free BSOD\n",
                       i, g_ClientPortRefs[i].ReferenceCount);
        }
    }

    //
    // ConnectedClients is decremented inside ShadowStrikeFinalizeClientDisconnect
    // for every successfully closed slot.  Force the global counter to zero
    // so observers cannot see stale "connected" state for any leaked slot.
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_DriverData.ClientPortLock);
    g_DriverData.ConnectedClients = 0;
    ExReleasePushLockExclusive(&g_DriverData.ClientPortLock);
    KeLeaveCriticalRegion();

    //
    // Close the server port
    //
    if (g_DriverData.ServerPort != NULL) {
        FltCloseCommunicationPort(g_DriverData.ServerPort);
        g_DriverData.ServerPort = NULL;
    }

    //
    // Scrub HMAC key material from memory (crypto hygiene)
    //
    ShadowStrikeSetCommHmacKeyReady(FALSE);
    RtlSecureZeroMemory(g_CommHmacKey, sizeof(g_CommHmacKey));

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Communication port closed\n");
}

// ============================================================================
// CONNECTION CALLBACKS
// ============================================================================

//
// ShadowStrikeDrainMessageQueue
//
// Drains messages buffered in MessageQueue while no user-mode client was
// connected.  Called at PASSIVE_LEVEL after a new client registers.
// Encrypts each message using the session key before sending.
//
static
VOID
ShadowStrikeDrainMessageQueue(
    _In_ LONG SlotIndex
    )
{
    PQUEUED_MESSAGE messages[32];
    PSHADOWSTRIKE_CLIENT_PORT_REF clientRef = NULL;
    PFLT_PORT clientPort = NULL;
    UINT32 count = 0;
    UINT32 totalDrained = 0;
    LARGE_INTEGER timeout;
    NTSTATUS status;
    BOOLEAN canEncrypt = FALSE;
    PENC_MANAGER encMgr = NULL;
    PENC_KEY sessionKey = NULL;

    PAGED_CODE();

    //
    // Cap at 512 messages per drain to avoid monopolising the connect path
    //
    timeout.QuadPart = 0;  // fire-and-forget

    status = ShadowStrikeAcquireClientPortBySlot(SlotIndex, &clientRef);
    if (!NT_SUCCESS(status)) {
        return;
    }

    clientPort = clientRef->ClientPort;
    canEncrypt = (clientRef->EncryptionEstablished != FALSE);
    if (canEncrypt) {
        encMgr = ShadowStrikeGetEncryptionManager();
        sessionKey = g_ClientSessionEncKeys[SlotIndex];
        if (encMgr == NULL || sessionKey == NULL) {
            canEncrypt = FALSE;
        }
    }

    while (totalDrained < 512) {
        status = MqDequeueBatch(messages, 32, &count, 0);
        if (!NT_SUCCESS(status) || count == 0) {
            break;
        }

        for (UINT32 i = 0; i < count; i++) {
            PVOID sendData = messages[i]->Data;
            ULONG sendSize = messages[i]->MessageSize;
            PVOID encBuf = NULL;
            BOOLEAN dropMessage = FALSE;

            //
            // Encrypt the queued message before sending.
            // If encryption fails, DROP the message — never send plaintext.
            //
            if (sendSize > sizeof(SHADOWSTRIKE_MESSAGE_HEADER)) {
                ULONG dataSize = sendSize - sizeof(SHADOWSTRIKE_MESSAGE_HEADER);
                ULONG encryptedSize = 0;
                NTSTATUS encSizeStatus;

                if (!canEncrypt) {
                    dropMessage = TRUE;
                } else {
                    encSizeStatus = EncGetEncryptedSize(dataSize, TRUE, &encryptedSize);
                    if (!NT_SUCCESS(encSizeStatus) || encryptedSize == 0) {
                        dropMessage = TRUE;
                    } else {
                        ULONG totalEncSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + encryptedSize;
                        encBuf = ExAllocatePool2(
                            POOL_FLAG_NON_PAGED,
                            totalEncSize,
                            'edCP'
                        );

                        if (encBuf == NULL) {
                            dropMessage = TRUE;
                        } else {
                            PSHADOWSTRIKE_MESSAGE_HEADER encHeader =
                                (PSHADOWSTRIKE_MESSAGE_HEADER)encBuf;
                            ENC_OPTIONS encOpts = {0};
                            ULONG ciphertextSize = 0;
                            NTSTATUS encStatus;

                            ShadowStrikePrepareEncryptedMessageHeader(
                                encHeader,
                                (PSHADOWSTRIKE_MESSAGE_HEADER)sendData,
                                encryptedSize
                            );

                            encOpts.Flags = EncFlag_IncludeHeader | EncFlag_UseAAD;
                            encOpts.Key = sessionKey;
                            encOpts.AAD = encBuf;
                            encOpts.AADSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER);
                            encOpts.TagSize = ENC_GCM_TAG_SIZE;

                            encStatus = EncEncrypt(
                                encMgr,
                                EncKeyType_Ephemeral,
                                (PUCHAR)sendData + sizeof(SHADOWSTRIKE_MESSAGE_HEADER),
                                dataSize,
                                (PUCHAR)encBuf + sizeof(SHADOWSTRIKE_MESSAGE_HEADER),
                                encryptedSize,
                                &ciphertextSize,
                                &encOpts
                            );

                            if (!NT_SUCCESS(encStatus) ||
                                ciphertextSize == 0 ||
                                ciphertextSize != encryptedSize) {
                                ExFreePoolWithTag(encBuf, 'edCP');
                                encBuf = NULL;
                                dropMessage = TRUE;
                            } else {
                                sendData = encBuf;
                                sendSize = encHeader->TotalSize;
                                InterlockedExchange64(
                                    &clientRef->NonceCounter,
                                    sessionKey->NonceCounter
                                );
                            }
                        }
                    }
                }
            }

            if (dropMessage) {
                if (encBuf != NULL) {
                    ExFreePoolWithTag(encBuf, 'edCP');
                }
                MqFreeMessage(messages[i]);
                SHADOWSTRIKE_INC_STAT(MessagesDropped);
                continue;
            }

            (void)FltSendMessage(
                g_DriverData.FilterHandle,
                &clientPort,
                sendData,
                sendSize,
                NULL,
                NULL,
                &timeout
            );

            if (encBuf != NULL) {
                ExFreePoolWithTag(encBuf, 'edCP');
            }

            MqFreeMessage(messages[i]);
        }

        totalDrained += count;

        if (count < 32) {
            break;  // queue drained
        }
    }

    if (totalDrained > 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[ShadowStrike] Drained %lu queued messages on client connect\n",
                   totalDrained);
    }

    ShadowStrikeReleaseClientPort(clientRef);
}

// ============================================================================
// DEFERRED KEY-EXCHANGE DELIVERY
// ============================================================================
//
// FltSendMessage MUST NOT be issued from inside ShadowStrikeConnectNotify.
// The calling user-mode thread is blocked inside FilterConnectCommunicationPort
// and physically cannot service FilterGetMessage until ConnectNotify returns,
// so a synchronous send from here will always wait the full timeout while
// holding g_DriverData.ClientPortLock exclusive — wedging every minifilter
// callback that needs the lock shared and freezing system I/O.
//
// Instead the kex blob is captured into a non-paged context and shipped via
// an FltMgr generic work item that runs at PASSIVE_LEVEL after ConnectNotify
// has returned and the lock has been released. The work item holds a slot
// reference for the duration of the send so the port cannot be reclaimed
// from under it; on failure it closes the port, surfacing a normal disconnect
// to user-mode which then retries the handshake.
//
#define SHADOWSTRIKE_KEX_POOL_TAG  'xeCS'

typedef struct _SHADOWSTRIKE_KEX_DELIVERY_CONTEXT {
    PFLT_PORT                              ClientPort;
    LONG                                   SlotIndex;
    SHADOWSTRIKE_KEY_EXCHANGE_MESSAGE      KexMessage;
} SHADOWSTRIKE_KEX_DELIVERY_CONTEXT, *PSHADOWSTRIKE_KEX_DELIVERY_CONTEXT;

_Function_class_(FLT_GENERIC_WORKITEM_ROUTINE)
static VOID FLTAPI
ShadowStrikeDeliverKexWorker(
    _In_ PFLT_GENERIC_WORKITEM FltWorkItem,
    _In_ PFLT_FILTER FltObject,
    _In_opt_ PVOID Context
    )
{
    PSHADOWSTRIKE_KEX_DELIVERY_CONTEXT ctx = (PSHADOWSTRIKE_KEX_DELIVERY_CONTEXT)Context;
    PSHADOWSTRIKE_CLIENT_PORT_REF clientRef = NULL;
    NTSTATUS status;
    LARGE_INTEGER timeout;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(FltObject);

    if (ctx == NULL) {
        FltFreeGenericWorkItem(FltWorkItem);
        return;
    }

    //
    // Acquire a slot reference so the port can't be reclaimed underneath us.
    // If the user-mode peer disconnected between ConnectNotify returning and
    // this work item running, the slot will already be marked Disconnecting
    // and the acquire will fail — drop the kex silently in that case.
    //
    status = ShadowStrikeAcquireClientPortBySlot(ctx->SlotIndex, &clientRef);
    if (!NT_SUCCESS(status) || clientRef == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Kex delivery: slot %ld no longer connectable (0x%08X)\n",
                   ctx->SlotIndex, status);
        goto Cleanup;
    }

    //
    // Confirm the slot still owns the same port. If the slot was reused for
    // a different peer between queue and dispatch, do not send the kex to
    // the new peer — its DH share is different.
    //
    if (clientRef->ClientPort != ctx->ClientPort) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Kex delivery: slot %ld port reused, skipping stale send\n",
                   ctx->SlotIndex);
        ShadowStrikeReleaseClientPort(clientRef);
        goto Cleanup;
    }

    //
    // 30-second timeout: by the time we run, user-mode's
    // FilterConnectCommunicationPort has already returned and its receive
    // worker is parked in FilterGetMessage. The kex must be the first
    // message it sees — its IPC layer waits on this before unblocking the
    // service start-up.
    //
    timeout.QuadPart = -300000000LL;

    status = FltSendMessage(
        g_DriverData.FilterHandle,
        &ctx->ClientPort,
        &ctx->KexMessage,
        sizeof(ctx->KexMessage),
        NULL, NULL,
        &timeout
    );

    if (NT_SUCCESS(status)) {
        //
        // Publish the "encryption is live" flag so subsequent send paths
        // (which gate on EncryptionEstablished) will start using it.
        //
        clientRef->EncryptionEstablished = TRUE;
        if (clientRef->IsPrimaryScanner) {
            //
            // Publish primary-scanner readiness for the lock-free scan-path
            // gate (ShadowStrikeIsPrimaryScannerConnected). This increment is
            // performed while we still hold our slot reference (released just
            // below), which guarantees it happens-before any disconnect
            // finalize (which can only run once the reference count reaches 0),
            // so the matching decrement in ShadowStrikeFinalizeClientDisconnect
            // can never be lost or run first.
            //
            InterlockedIncrement(&g_DriverData.PrimaryScannersReady);
        }
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[ShadowStrike] Kex delivered for slot %ld\n", ctx->SlotIndex);
        ShadowStrikeReleaseClientPort(clientRef);
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Kex delivery failed on slot %ld: 0x%08X — closing port\n",
                   ctx->SlotIndex, status);
        //
        // Release our reference first, then close the port. FltCloseClientPort
        // triggers DisconnectNotify which acquires the lock exclusive; we must
        // not be holding any slot reference when it runs.
        //
        ShadowStrikeReleaseClientPort(clientRef);
        FltCloseClientPort(g_DriverData.FilterHandle, &ctx->ClientPort);
    }

Cleanup:
    RtlSecureZeroMemory(&ctx->KexMessage, sizeof(ctx->KexMessage));
    ExFreePoolWithTag(ctx, SHADOWSTRIKE_KEX_POOL_TAG);
    FltFreeGenericWorkItem(FltWorkItem);
}

NTSTATUS
ShadowStrikeConnectNotify(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionPortCookie
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    LONG slotIndex = -1;
    LONG i;
    HANDLE clientProcessId;
    BOOLEAN isPrimaryScanner = FALSE;
    ULONG capabilities = 0;
    UCHAR imageHash[32] = {0};
    UINT32 connectionType = 0;
    PSHADOWSTRIKE_KEX_DELIVERY_CONTEXT kexCtx = NULL;
    PFLT_GENERIC_WORKITEM kexWorkItem = NULL;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(ServerPortCookie);

    *ConnectionPortCookie = NULL;

    //
    // Get client process ID
    //
    clientProcessId = PsGetCurrentProcessId();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Client connecting: PID=%p\n", clientProcessId);

    //
    // Verify client and determine capabilities
    //
    status = ShadowStrikeVerifyClient(clientProcessId, &capabilities, imageHash);
    if (!NT_SUCCESS(status)) {
        //
        // Hard failure inside the verifier (PsLookupProcessByProcessId or
        // SeLocateProcessImageName failed). Distinct from the "verified but
        // minimal capabilities" denial below: this one logs the propagated
        // NTSTATUS so post-mortem can distinguish the two ACCESS_DENIED
        // sites observed by user-mode as a single 0x80070005.
        //
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] ConnectNotify DENY: VerifyClient hard-failed "
                   "PID=%p status=0x%08X\n",
                   clientProcessId, status);
        return STATUS_ACCESS_DENIED;
    }

    //
    // Unverified clients (minimal capabilities) are denied connection.
    // Only clients that pass filename + SYSTEM token checks are allowed.
    // ShadowStrikeVerifyClient has already emitted a precise DPFLTR_ERROR
    // line identifying whether nameMatch or isSystem failed.
    //
    if (capabilities == (ULONG)ShadowStrikeCapMinimal) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] ConnectNotify DENY: PID=%p failed verification "
                   "(see VerifyClient log above for nameMatch/isSystem detail)\n",
                   clientProcessId);
        return STATUS_ACCESS_DENIED;
    }

    //
    // Read the optional connection type from the connection context.
    //
    // CRITICAL: The Filter Manager copies the user-mode ConnectionContext
    // (passed to FilterConnectCommunicationPort) into kernel-mode pool BEFORE
    // invoking this callback — per the FLT_CONNECT_NOTIFY contract the pointer
    // we receive is already a captured, validated kernel-mode buffer of
    // SizeOfContext bytes. It is therefore WRONG to call ProbeForRead on it:
    // ProbeForRead is for user-mode addresses and RAISES on a kernel address,
    // which made this callback fault into the __except below and reject EVERY
    // connection with STATUS_INVALID_PARAMETER (the user-mode side saw a
    // perpetual 0x80070057 and the encrypted channel never came up).
    //
    // We read it directly with RtlCopyMemory (alignment-safe). The buffer is
    // guaranteed valid kernel memory, so no probe/SEH is required. The context
    // is optional: clients that omit it (or send <4 bytes) are simply treated
    // as auxiliary (non-primary) connections rather than being rejected.
    //
    if (ConnectionContext != NULL && SizeOfContext >= sizeof(UINT32)) {
        UINT32 ctxConnectionType = 0;
        RtlCopyMemory(&ctxConnectionType, ConnectionContext, sizeof(ctxConnectionType));

        connectionType = ctxConnectionType;
        if (connectionType == 1) {
            isPrimaryScanner = TRUE;

            //
            // Record the scanner service PID so the file callbacks never issue a
            // synchronous user-mode scan for the scanner's OWN file I/O (which
            // would recurse into PreCreate -> SbSendScanRequest, exhaust the
            // scanner worker pool, and deadlock all system file I/O). Set here at
            // connect, before the encrypted channel can carry scan traffic, so
            // there is no race with the scan flood that starts once it is live.
            //
            InterlockedExchange(&g_ScannerServiceProcessId, HandleToLong(clientProcessId));
        }

        //
        // Optional client-supplied image hash (SHA-256 of the client's OWN
        // executable, computed in USER MODE and carried in the connection
        // context — see SHADOWSTRIKE_CONNECTION_CONTEXT). Using it as the
        // key-exchange input lets both sides derive the identical key-wrapping
        // key while the kernel performs ZERO file I/O in this connect callback,
        // eliminating the filter-stack re-entrancy/deadlock risk of hashing a
        // file here. This is a pure in-memory read from the FltMgr-captured
        // context buffer; the connection is already authenticated by
        // ShadowStrikeVerifyClient (exact image path + SYSTEM token), so a
        // client-supplied value here only binds the local key handoff.
        //
        // If the client supplies a short/legacy context the override is skipped
        // and the verifier's hash stands — the key exchange then simply will
        // not match, rather than the connection being rejected or the kernel
        // touching the filesystem.
        //
        if (SizeOfContext >= sizeof(SHADOWSTRIKE_CONNECTION_CONTEXT)) {
            const SHADOWSTRIKE_CONNECTION_CONTEXT* connCtx =
                (const SHADOWSTRIKE_CONNECTION_CONTEXT*)ConnectionContext;
            RtlCopyMemory(imageHash, connCtx->ClientImageHash, sizeof(imageHash));
        }
    }

    //
    // Find available slot under lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_DriverData.ClientPortLock);

    //
    // Check if already at max connections
    //
    if (g_DriverData.ConnectedClients >= SHADOWSTRIKE_MAX_CONNECTIONS) {
        ExReleasePushLockExclusive(&g_DriverData.ClientPortLock);
        KeLeaveCriticalRegion();

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Connection rejected: max connections reached\n");
        return STATUS_CONNECTION_COUNT_LIMIT;
    }

    //
    // Find empty slot
    //
    for (i = 0; i < SHADOWSTRIKE_MAX_CONNECTIONS; i++) {
        if (g_ClientPortRefs[i].ClientPort == NULL &&
            g_ClientPortRefs[i].Disconnecting == 0) {
            slotIndex = i;
            break;
        }
    }

    if (slotIndex < 0) {
        ExReleasePushLockExclusive(&g_DriverData.ClientPortLock);
        KeLeaveCriticalRegion();

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] No available client slots\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize client slot with reference count of 1 (for the connection itself)
    //
    RtlZeroMemory(&g_ClientPortRefs[slotIndex], sizeof(SHADOWSTRIKE_CLIENT_PORT_REF));
    g_ClientSessionEncKeys[slotIndex] = NULL;
    g_ClientPortRefs[slotIndex].ClientPort = ClientPort;
    g_ClientPortRefs[slotIndex].ClientProcessId = clientProcessId;
    g_ClientPortRefs[slotIndex].IsPrimaryScanner = isPrimaryScanner;
    g_ClientPortRefs[slotIndex].Capabilities = capabilities;
    g_ClientPortRefs[slotIndex].ReferenceCount = 1;  // Initial reference for connection
    g_ClientPortRefs[slotIndex].Disconnecting = 0;
    g_ClientPortRefs[slotIndex].SlotIndex = slotIndex;
    RtlCopyMemory(g_ClientPortRefs[slotIndex].ImagePathHash, imageHash, sizeof(imageHash));
    KeQuerySystemTime(&g_ClientPortRefs[slotIndex].ConnectedTime);

    //
    // Derive per-session encryption key using HKDF.
    //
    // IKM is the concatenation of:
    //   - the verified client image hash (binds key to authenticated identity)
    //   - the per-boot kernel HMAC secret  (binds key to this kernel session,
    //                                       defeats any attacker who only knows
    //                                       the deterministic image hash and
    //                                       the wire salt)
    //
    // Salt = random per session, Info = "ShadowStrike-KEX-v1" for domain
    // separation. If the per-boot secret is unavailable, fail closed with
    // STATUS_DEVICE_NOT_READY so user-mode retries instead of negotiating a
    // weaker image-hash-only session.
    //
    {
        PENC_MANAGER encMgr = ShadowStrikeGetEncryptionManager();
        BCRYPT_ALG_HANDLE hmacHandle = (encMgr != NULL) ?
            EncGetHmacAlgHandle(encMgr) : NULL;
        BOOLEAN hmacHandleNull = (hmacHandle == NULL);
        NTSTATUS nonceRandomStatus = STATUS_UNSUCCESSFUL;
        NTSTATUS saltRandomStatus = STATUS_UNSUCCESSFUL;
        NTSTATUS hmacKeySeedStatus = ShadowStrikeIsCommHmacKeyReady() ? STATUS_SUCCESS : STATUS_DEVICE_NOT_READY;
        NTSTATUS hkdfStatus = STATUS_UNSUCCESSFUL;
        NTSTATUS sessionKeyMaterialStatus = STATUS_UNSUCCESSFUL;
        BOOLEAN sessionKeyAllZero = TRUE;

        //
        // Generate random salt for HKDF and nonce prefix for this session
        //
        UCHAR hkdfSalt[32] = {0};
        UCHAR ikm[sizeof(imageHash) + SHADOWSTRIKE_HMAC_KEY_SIZE];
        ULONG ikmLength = sizeof(imageHash);
        NTSTATUS keyStatus = STATUS_SUCCESS;

        RtlCopyMemory(ikm, imageHash, sizeof(imageHash));

        if (encMgr == NULL || hmacHandle == NULL) {
            keyStatus = STATUS_DEVICE_NOT_READY;
        }

        if (NT_SUCCESS(keyStatus) && !ShadowStrikeIsCommHmacKeyReady()) {
            hmacKeySeedStatus = EncRandomBytes(
                encMgr,
                g_CommHmacKey,
                SHADOWSTRIKE_HMAC_KEY_SIZE
            );
            if (NT_SUCCESS(hmacKeySeedStatus)) {
                ShadowStrikeSetCommHmacKeyReady(TRUE);
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                           "[ShadowStrike] HMAC transport key generated during ConnectNotify\n");
            } else {
                RtlSecureZeroMemory(g_CommHmacKey, sizeof(g_CommHmacKey));
                keyStatus = STATUS_DEVICE_NOT_READY;
            }
        }

        if (NT_SUCCESS(keyStatus) && ShadowStrikeIsCommHmacKeyReady()) {
            RtlCopyMemory(ikm + sizeof(imageHash), g_CommHmacKey,
                          SHADOWSTRIKE_HMAC_KEY_SIZE);
            ikmLength = sizeof(imageHash) + SHADOWSTRIKE_HMAC_KEY_SIZE;
        } else if (NT_SUCCESS(keyStatus)) {
            keyStatus = STATUS_DEVICE_NOT_READY;
        }

        if (NT_SUCCESS(keyStatus)) {
            nonceRandomStatus = EncRandomBytes(
                encMgr,
                g_ClientPortRefs[slotIndex].SessionNoncePrefix,
                sizeof(g_ClientPortRefs[slotIndex].SessionNoncePrefix)
            );
            keyStatus = nonceRandomStatus;
        }

        if (NT_SUCCESS(keyStatus)) {
            saltRandomStatus = EncRandomBytes(encMgr, hkdfSalt, sizeof(hkdfSalt));
            keyStatus = saltRandomStatus;

            if (NT_SUCCESS(keyStatus)) {
                static const char hkdfInfo[] = "ShadowStrike-KEX-v1";
                hkdfStatus = EncHkdfDerive(
                    hmacHandle,
                    ikm, ikmLength,                 // IKM = imageHash || perBootSecret
                    hkdfSalt, sizeof(hkdfSalt),     // Salt = random
                    (PVOID)hkdfInfo, sizeof(hkdfInfo) - 1,
                    g_ClientPortRefs[slotIndex].SessionKey,
                    sizeof(g_ClientPortRefs[slotIndex].SessionKey)
                );
                keyStatus = hkdfStatus;
            }
        }

        if (NT_SUCCESS(keyStatus)) {
            ULONG keyByte = 0;

            for (keyByte = 0; keyByte < sizeof(g_ClientPortRefs[slotIndex].SessionKey); keyByte++) {
                if (g_ClientPortRefs[slotIndex].SessionKey[keyByte] != 0) {
                    sessionKeyAllZero = FALSE;
                    break;
                }
            }

            if (sessionKeyAllZero) {
                keyStatus = STATUS_ENCRYPTION_FAILED;
            } else {
                PENC_KEY sessionCryptoKey = NULL;
                sessionKeyMaterialStatus = EncImportKey(
                    encMgr,
                    EncKeyType_Ephemeral,
                    EncAlgorithm_AES_256_GCM,
                    g_ClientPortRefs[slotIndex].SessionKey,
                    sizeof(g_ClientPortRefs[slotIndex].SessionKey),
                    &sessionCryptoKey
                );

                if (NT_SUCCESS(sessionKeyMaterialStatus) && sessionCryptoKey != NULL) {
                    g_ClientSessionEncKeys[slotIndex] = sessionCryptoKey;
                } else {
                    if (sessionCryptoKey != NULL) {
                        ShadowStrikeReleaseSessionCryptoKey(&sessionCryptoKey);
                    }
                    keyStatus = NT_SUCCESS(sessionKeyMaterialStatus) ? STATUS_ENCRYPTION_FAILED
                                                                     : sessionKeyMaterialStatus;
                }
            }
        }

        if (NT_SUCCESS(keyStatus)) {
            g_ClientPortRefs[slotIndex].NonceCounter = 0;

            //
            // Send key exchange message to user-mode.
            // The session key is wrapped (encrypted) using a Key-Wrapping-Key (KWK)
            // derived from the verified executable hash + salt, matching the
            // shared protocol and user-mode receiver.
            //
            // Build SHADOWSTRIKE_KEY_EXCHANGE_MESSAGE with:
            //   - Salt: the HKDF salt (user-mode needs this to derive KWK)
            //   - WrappedSessionKey: session key encrypted with KWK via AES-256-GCM
            //   - Nonce: GCM nonce for the wrapping operation
            //   - Tag: GCM auth tag
            //   - SessionNoncePrefix: 4-byte prefix for message nonces
            //
            SHADOWSTRIKE_KEY_EXCHANGE_MESSAGE kexMsg = {0};
            ShadowStrikeInitMessageHeader(&kexMsg.Header,
                FilterMessageType_KeyExchange,
                sizeof(SHADOWSTRIKE_KEY_EXCHANGE_MESSAGE) - sizeof(SS_MESSAGE_HEADER));

            RtlCopyMemory(kexMsg.Salt, hkdfSalt, sizeof(kexMsg.Salt));
            RtlCopyMemory(kexMsg.SessionNoncePrefix,
                          g_ClientPortRefs[slotIndex].SessionNoncePrefix,
                          sizeof(kexMsg.SessionNoncePrefix));
            kexMsg.KeyExpirySeconds = 0;  // No expiry
            kexMsg.ProtocolFlags = SHADOWSTRIKE_KEX_PROTOCOL_FLAG_MANDATORY_ENCRYPTION;

            //
            // Derive KWK (Key-Wrapping-Key) exactly as documented in the
            // shared protocol and user-mode FilterConnection: HKDF over the
            // verified client image hash. The random session key itself was
            // derived above from imageHash || perBootSecret and is never sent
            // in plaintext; KWK only protects the one-time local delivery.
            //
            UCHAR kwk[32] = {0};
            static const char kwkInfo[] = "ShadowStrike-KWK-v1";
            NTSTATUS kwkStatus = EncHkdfDerive(
                hmacHandle,
                imageHash, sizeof(imageHash),
                hkdfSalt, sizeof(hkdfSalt),
                (PVOID)kwkInfo, sizeof(kwkInfo) - 1,
                kwk, sizeof(kwk)
            );

            if (NT_SUCCESS(kwkStatus) && encMgr != NULL) {
                //
                // Wrap (encrypt) the session key with KWK using AES-256-GCM.
                // EncEncrypt emits [ENC_HEADER][ciphertext], so extract the
                // nonce and tag from ENC_HEADER and the ciphertext from the
                // bytes immediately after it.
                //
                PENC_KEY wrapKey = NULL;
                NTSTATUS wrapKeyStatus = EncImportKey(
                    encMgr, EncKeyType_Ephemeral, EncAlgorithm_AES_256_GCM,
                    kwk, sizeof(kwk), &wrapKey);

                if (NT_SUCCESS(wrapKeyStatus) && wrapKey != NULL) {
                    ENC_OPTIONS wrapOpts = {0};
                    wrapOpts.Flags = EncFlag_UseAAD;
                    wrapOpts.Key = wrapKey;
                    wrapOpts.AAD = kexMsg.Salt;
                    wrapOpts.AADSize = sizeof(kexMsg.Salt);
                    wrapOpts.TagSize = ENC_GCM_TAG_SIZE;

                    UCHAR wrappedOutput[128] = {0};
                    ULONG wrappedSize = 0;

                    NTSTATUS wrapStatus = EncEncrypt(
                        encMgr, EncKeyType_Ephemeral,
                        g_ClientPortRefs[slotIndex].SessionKey,
                        sizeof(g_ClientPortRefs[slotIndex].SessionKey),
                        wrappedOutput, sizeof(wrappedOutput),
                        &wrappedSize, &wrapOpts);

                    if (NT_SUCCESS(wrapStatus) &&
                        wrappedSize >= sizeof(ENC_HEADER) + sizeof(kexMsg.WrappedSessionKey)) {
                        PENC_HEADER wrappedHeader = (PENC_HEADER)wrappedOutput;
                        RtlCopyMemory(kexMsg.Nonce,
                                      wrappedHeader->Nonce,
                                      sizeof(kexMsg.Nonce));
                        RtlCopyMemory(kexMsg.Tag,
                                      wrappedHeader->Tag,
                                      sizeof(kexMsg.Tag));
                        RtlCopyMemory(kexMsg.WrappedSessionKey,
                                      wrappedOutput + sizeof(ENC_HEADER),
                                      sizeof(kexMsg.WrappedSessionKey));
                    } else {
                        kwkStatus = NT_SUCCESS(wrapStatus) ? STATUS_ENCRYPTION_FAILED
                                                           : wrapStatus;
                    }

                    RtlSecureZeroMemory(wrappedOutput, sizeof(wrappedOutput));
                    //
                    // EncKeyRelease decrements refs but does NOT auto-destroy
                    // when the count hits zero — the contract (see Encryption.h
                    // and ShadowStrikeReleaseSessionCryptoKey) requires the
                    // caller to invoke EncDestroyKey on the final release.
                    // Use the helper which encapsulates that contract.
                    //
                    ShadowStrikeReleaseSessionCryptoKey(&wrapKey);
                } else {
                    kwkStatus = NT_SUCCESS(wrapKeyStatus) ? STATUS_ENCRYPTION_FAILED
                                                          : wrapKeyStatus;
                }
            } else if (NT_SUCCESS(kwkStatus)) {
                kwkStatus = STATUS_INVALID_DEVICE_STATE;
            }

            RtlSecureZeroMemory(kwk, sizeof(kwk));
            if (!NT_SUCCESS(kwkStatus)) {
                keyStatus = kwkStatus;
            }

            if (!NT_SUCCESS(keyStatus)) {
                RtlSecureZeroMemory(&kexMsg, sizeof(kexMsg));
                RtlSecureZeroMemory(hkdfSalt, sizeof(hkdfSalt));
                RtlSecureZeroMemory(ikm, sizeof(ikm));
                if (g_ClientSessionEncKeys[slotIndex] != NULL) {
                    ShadowStrikeReleaseSessionCryptoKey(&g_ClientSessionEncKeys[slotIndex]);
                }
                g_ClientPortRefs[slotIndex].EncryptionEstablished = FALSE;
                RtlSecureZeroMemory(g_ClientPortRefs[slotIndex].SessionKey,
                                    sizeof(g_ClientPortRefs[slotIndex].SessionKey));
                RtlSecureZeroMemory(g_ClientPortRefs[slotIndex].SessionNoncePrefix,
                                    sizeof(g_ClientPortRefs[slotIndex].SessionNoncePrefix));
                RtlZeroMemory(&g_ClientPortRefs[slotIndex], sizeof(SHADOWSTRIKE_CLIENT_PORT_REF));
                g_ClientPortRefs[slotIndex].SlotIndex = slotIndex;

                ExReleasePushLockExclusive(&g_DriverData.ClientPortLock);
                KeLeaveCriticalRegion();
                return STATUS_ENCRYPTION_FAILED;
            }

            //
            // Capture the key exchange message into a deferred-delivery
            // context. We MUST NOT call FltSendMessage here — see the
            // ShadowStrikeDeliverKexWorker comment above. Allocation happens
            // under the lock so on failure we can fold cleanly into the
            // existing encryption-failure teardown without re-acquiring it.
            //
            kexCtx = (PSHADOWSTRIKE_KEX_DELIVERY_CONTEXT)ExAllocatePool2(
                POOL_FLAG_NON_PAGED,
                sizeof(*kexCtx),
                SHADOWSTRIKE_KEX_POOL_TAG);

            if (kexCtx != NULL) {
                kexWorkItem = FltAllocateGenericWorkItem();
                if (kexWorkItem == NULL) {
                    ExFreePoolWithTag(kexCtx, SHADOWSTRIKE_KEX_POOL_TAG);
                    kexCtx = NULL;
                }
            }

            if (kexCtx == NULL || kexWorkItem == NULL) {
                RtlSecureZeroMemory(&kexMsg, sizeof(kexMsg));
                RtlSecureZeroMemory(hkdfSalt, sizeof(hkdfSalt));
                RtlSecureZeroMemory(ikm, sizeof(ikm));
                if (g_ClientSessionEncKeys[slotIndex] != NULL) {
                    ShadowStrikeReleaseSessionCryptoKey(&g_ClientSessionEncKeys[slotIndex]);
                }
                g_ClientPortRefs[slotIndex].EncryptionEstablished = FALSE;
                RtlSecureZeroMemory(g_ClientPortRefs[slotIndex].SessionKey,
                                    sizeof(g_ClientPortRefs[slotIndex].SessionKey));
                RtlSecureZeroMemory(g_ClientPortRefs[slotIndex].SessionNoncePrefix,
                                    sizeof(g_ClientPortRefs[slotIndex].SessionNoncePrefix));
                RtlZeroMemory(&g_ClientPortRefs[slotIndex], sizeof(SHADOWSTRIKE_CLIENT_PORT_REF));
                g_ClientPortRefs[slotIndex].SlotIndex = slotIndex;

                ExReleasePushLockExclusive(&g_DriverData.ClientPortLock);
                KeLeaveCriticalRegion();
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                           "[ShadowStrike] Kex work-item allocation failed for slot %ld\n",
                           slotIndex);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            kexCtx->ClientPort = ClientPort;
            kexCtx->SlotIndex  = slotIndex;
            RtlCopyMemory(&kexCtx->KexMessage, &kexMsg, sizeof(kexMsg));
            RtlSecureZeroMemory(&kexMsg, sizeof(kexMsg));

            //
            // EncryptionEstablished stays FALSE until the work item confirms
            // the kex was delivered. Other kernel→user send paths gate on
            // this flag and will either queue or refuse to send unencrypted.
            //
            g_ClientPortRefs[slotIndex].EncryptionEstablished = FALSE;

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "[ShadowStrike] Per-session encryption key derived for slot %ld (kex delivery deferred)\n",
                       slotIndex);
        } else {
            //
            // Key derivation failed — REJECT the connection.
            // An enterprise security product must not operate with degraded
            // encryption. If key derivation fails, the session is unsafe.
            //
            g_ClientPortRefs[slotIndex].EncryptionEstablished = FALSE;
            if (g_ClientSessionEncKeys[slotIndex] != NULL) {
                ShadowStrikeReleaseSessionCryptoKey(&g_ClientSessionEncKeys[slotIndex]);
            }
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[ShadowStrike] Session key derivation diagnostics slot %ld: "
                       "hmacHandleNull=%u hmacKeySeedStatus=0x%08X "
                       "NonceRandomStatus=0x%08X BCryptGenRandomSaltStatus=0x%08X "
                       "EncHkdfDeriveStatus=0x%08X sessionKeyAllZero=%u "
                       "SessionKeyImportStatus=0x%08X\n",
                       slotIndex,
                       hmacHandleNull ? 1u : 0u,
                       hmacKeySeedStatus,
                       nonceRandomStatus,
                       saltRandomStatus,
                       hkdfStatus,
                       sessionKeyAllZero ? 1u : 0u,
                       sessionKeyMaterialStatus);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[ShadowStrike] Session key derivation FAILED for slot %ld: 0x%08X "
                       "(connection rejected — encryption is mandatory)\n",
                       slotIndex, keyStatus);

            // Clean up slot
            RtlSecureZeroMemory(g_ClientPortRefs[slotIndex].SessionKey,
                                sizeof(g_ClientPortRefs[slotIndex].SessionKey));
            RtlSecureZeroMemory(g_ClientPortRefs[slotIndex].SessionNoncePrefix,
                                sizeof(g_ClientPortRefs[slotIndex].SessionNoncePrefix));
            RtlZeroMemory(&g_ClientPortRefs[slotIndex], sizeof(SHADOWSTRIKE_CLIENT_PORT_REF));
            g_ClientPortRefs[slotIndex].SlotIndex = slotIndex;
            RtlSecureZeroMemory(hkdfSalt, sizeof(hkdfSalt));
            RtlSecureZeroMemory(ikm, sizeof(ikm));

            ExReleasePushLockExclusive(&g_DriverData.ClientPortLock);
            KeLeaveCriticalRegion();
            return keyStatus;
        }
        RtlSecureZeroMemory(hkdfSalt, sizeof(hkdfSalt));
        RtlSecureZeroMemory(ikm, sizeof(ikm));
    }

    //
    // Update global connected count
    //
    g_DriverData.ConnectedClients++;

    ExReleasePushLockExclusive(&g_DriverData.ClientPortLock);
    KeLeaveCriticalRegion();

    //
    // Queue deferred kex delivery NOW that the lock is released and the slot
    // is published. The work item runs at PASSIVE_LEVEL on an FltMgr worker
    // thread, calls FltSendMessage with a generous timeout, and on success
    // flips EncryptionEstablished=TRUE for the slot. On failure it closes
    // the client port, which surfaces a normal disconnect to user-mode.
    //
    // kexCtx / kexWorkItem are only non-NULL when key derivation succeeded
    // (i.e. SizeOfContext indicated a kex-capable client). For clients that
    // skip key derivation entirely, no kex is required.
    //
    if (kexCtx != NULL && kexWorkItem != NULL) {
        FltQueueGenericWorkItem(
            kexWorkItem,
            g_DriverData.FilterHandle,
            ShadowStrikeDeliverKexWorker,
            DelayedWorkQueue,
            kexCtx
        );
    }

    //
    // Return slot index as cookie (add 1 to avoid NULL)
    //
    *ConnectionPortCookie = (PVOID)(ULONG_PTR)(slotIndex + 1);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Client connected: slot=%ld, primary=%d, caps=0x%08X, total=%ld\n",
               slotIndex, isPrimaryScanner, capabilities, g_DriverData.ConnectedClients);

    //
    // Drain any messages queued while no client was connected.
    // Must happen AFTER the slot is published so concurrent senders
    // can also reach the new port.
    //
    ShadowStrikeDrainMessageQueue(slotIndex);

    return status;
}

static VOID
ShadowStrikeFinalizeClientDisconnect(
    _In_ LONG SlotIndex
    )
{
    PENC_KEY sessionKey = NULL;

    if (SlotIndex < 0 || SlotIndex >= SHADOWSTRIKE_MAX_CONNECTIONS) {
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_DriverData.ClientPortLock);

    if (g_ClientPortRefs[SlotIndex].Disconnecting == 0 ||
        g_ClientPortRefs[SlotIndex].ReferenceCount != 0 ||
        g_ClientPortRefs[SlotIndex].ClientPort == NULL) {
        ExReleasePushLockExclusive(&g_DriverData.ClientPortLock);
        KeLeaveCriticalRegion();
        return;
    }

    sessionKey = g_ClientSessionEncKeys[SlotIndex];
    g_ClientSessionEncKeys[SlotIndex] = NULL;

    FltCloseClientPort(
        g_DriverData.FilterHandle,
        &g_ClientPortRefs[SlotIndex].ClientPort
    );

    RtlSecureZeroMemory(
        g_ClientPortRefs[SlotIndex].SessionKey,
        sizeof(g_ClientPortRefs[SlotIndex].SessionKey)
    );
    RtlSecureZeroMemory(
        g_ClientPortRefs[SlotIndex].SessionNoncePrefix,
        sizeof(g_ClientPortRefs[SlotIndex].SessionNoncePrefix)
    );
    //
    // Retire this slot from the primary-scanner readiness count if it was a
    // KEX-completed primary scanner. Read both flags BEFORE the zeroing below.
    // This runs under the exclusive ClientPortLock with ReferenceCount == 0,
    // so it is strictly ordered after the matching increment in the KEX worker
    // (which held a reference). The pair is therefore always balanced.
    //
    if (g_ClientPortRefs[SlotIndex].IsPrimaryScanner &&
        g_ClientPortRefs[SlotIndex].EncryptionEstablished) {
        InterlockedDecrement(&g_DriverData.PrimaryScannersReady);
    }

    //
    // Clear the scanner-process scan exemption if this primary scanner owned it,
    // so a later reuse of the same PID by another process is not silently
    // exempted from on-access scanning. Compare-exchange so we only clear our own
    // PID (never a newer scanner's).
    //
    if (g_ClientPortRefs[SlotIndex].IsPrimaryScanner) {
        InterlockedCompareExchange(&g_ScannerServiceProcessId, 0,
                                   HandleToLong(g_ClientPortRefs[SlotIndex].ClientProcessId));
    }
    g_ClientPortRefs[SlotIndex].EncryptionEstablished = FALSE;

    RtlZeroMemory(&g_ClientPortRefs[SlotIndex], sizeof(SHADOWSTRIKE_CLIENT_PORT_REF));
    g_ClientPortRefs[SlotIndex].SlotIndex = SlotIndex;

    if (g_DriverData.ConnectedClients > 0) {
        g_DriverData.ConnectedClients--;
    }

    ExReleasePushLockExclusive(&g_DriverData.ClientPortLock);
    KeLeaveCriticalRegion();

    if (sessionKey != NULL) {
        ShadowStrikeReleaseSessionCryptoKey(&sessionKey);
    }

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[ShadowStrike] Client disconnected, remaining=%ld\n",
        g_DriverData.ConnectedClients
    );
}

VOID
ShadowStrikeDisconnectNotify(
    _In_opt_ PVOID ConnectionCookie
    )
{
    LONG slotIndex;
    LONG remainingRefs;

    PAGED_CODE();

    if (ConnectionCookie == NULL) {
        return;
    }

    slotIndex = (LONG)(ULONG_PTR)ConnectionCookie - 1;

    if (slotIndex < 0 || slotIndex >= SHADOWSTRIKE_MAX_CONNECTIONS) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Invalid disconnect cookie: %p\n", ConnectionCookie);
        return;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Client disconnecting: slot=%ld\n", slotIndex);

    //
    // Mark as disconnecting - prevents new references from being acquired
    //
    InterlockedExchange(&g_ClientPortRefs[slotIndex].Disconnecting, 1);

    //
    // Decrement the initial connection reference
    //
    remainingRefs = InterlockedDecrement(&g_ClientPortRefs[slotIndex].ReferenceCount);

    if (remainingRefs > 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Deferring disconnect cleanup for slot %ld until %ld references drain\n",
                   slotIndex, remainingRefs);
    }

    ShadowStrikeFinalizeClientDisconnect(slotIndex);
}

// ============================================================================
// MESSAGE HANDLING
// ============================================================================

NTSTATUS
ShadowStrikeMessageNotify(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    SHADOWSTRIKE_MESSAGE_HEADER localHeader;
    PSHADOWSTRIKE_MESSAGE_HEADER header = NULL;
    PSHADOWSTRIKE_CLIENT_PORT_REF clientRef = NULL;
    PVOID dispatchBuffer = InputBuffer;
    ULONG dispatchBufferLength = InputBufferLength;
    PVOID encryptedTransportBuffer = NULL;
    PVOID decryptedBuffer = NULL;
    BOOLEAN dispatchBufferTrusted = FALSE;
    LONG slotIndex;

    PAGED_CODE();

    *ReturnOutputBufferLength = 0;

    //
    // Validate slot index from cookie
    //
    if (PortCookie == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    slotIndex = (LONG)(ULONG_PTR)PortCookie - 1;
    if (slotIndex < 0 || slotIndex >= SHADOWSTRIKE_MAX_CONNECTIONS) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate input buffer and safely copy header
    //
    status = ShadowStrikeValidateInputBuffer(InputBuffer, InputBufferLength, &localHeader);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    header = &localHeader;

    status = ShadowStrikeAcquireClientPortBySlot(slotIndex, &clientRef);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Decrypt encrypted user-mode payloads before dispatching to handlers.
    // The transport keeps SHADOWSTRIKE_MESSAGE_HEADER in plaintext and wraps the
    // data portion as [ENC_HEADER][ciphertext] with the outer header as AAD.
    //
    if ((header->Flags & SHADOWSTRIKE_MSG_FLAG_ENCRYPTED) != 0) {
        PENC_MANAGER encMgr = ShadowStrikeGetEncryptionManager();
        PENC_KEY sessionKey = g_ClientSessionEncKeys[slotIndex];
        ULONG encryptedDataSize;
        ENC_HEADER localEncryptedHeader;
        PENC_HEADER encryptedHeader;
        ULONG plaintextSize = 0;
        ULONG totalDecryptedSize;
        PSHADOWSTRIKE_MESSAGE_HEADER decryptedHeader;
        ENC_OPTIONS decryptOpts = {0};

        if (encMgr == NULL || sessionKey == NULL) {
            status = STATUS_ENCRYPTION_FAILED;
            goto Cleanup;
        }

        if (InputBufferLength <= sizeof(SHADOWSTRIKE_MESSAGE_HEADER)) {
            status = STATUS_INVALID_BUFFER_SIZE;
            goto Cleanup;
        }

        encryptedDataSize = InputBufferLength - sizeof(SHADOWSTRIKE_MESSAGE_HEADER);
        if (encryptedDataSize < sizeof(ENC_HEADER)) {
            status = STATUS_DECRYPTION_FAILED;
            goto Cleanup;
        }

        status = ShadowStrikeCopyMessagePayload(
            InputBuffer,
            InputBufferLength,
            sizeof(SHADOWSTRIKE_MESSAGE_HEADER),
            &localEncryptedHeader,
            sizeof(localEncryptedHeader),
            FALSE
        );
        if (!NT_SUCCESS(status)) {
            goto Cleanup;
        }

        if (localEncryptedHeader.Magic != ENC_MAGIC ||
            localEncryptedHeader.Version != ENC_VERSION ||
            localEncryptedHeader.PlaintextSize == 0 ||
            localEncryptedHeader.PlaintextSize > ENC_MAX_PLAINTEXT_SIZE ||
            localEncryptedHeader.PlaintextSize != localEncryptedHeader.CiphertextSize ||
            encryptedDataSize < sizeof(ENC_HEADER) + localEncryptedHeader.CiphertextSize) {
            status = STATUS_DECRYPTION_FAILED;
            goto Cleanup;
        }

        encryptedTransportBuffer = ExAllocatePool2(POOL_FLAG_PAGED, encryptedDataSize, 'emCP');
        if (encryptedTransportBuffer == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }

        status = ShadowStrikeCopyMessagePayload(
            InputBuffer,
            InputBufferLength,
            sizeof(SHADOWSTRIKE_MESSAGE_HEADER),
            encryptedTransportBuffer,
            encryptedDataSize,
            FALSE
        );
        if (!NT_SUCCESS(status)) {
            goto Cleanup;
        }

        encryptedHeader = (PENC_HEADER)encryptedTransportBuffer;

        //
        // CRITICAL: Use the VALIDATED first-copy sizes, not the second-copy.
        // The user buffer could be modified between the two copies (TOCTOU).
        // The GCM tag will detect any tampering with ciphertext, but
        // PlaintextSize is not part of the authenticated ciphertext.
        //
        totalDecryptedSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + localEncryptedHeader.PlaintextSize;

        decryptedBuffer = ExAllocatePool2(POOL_FLAG_PAGED, totalDecryptedSize, 'dmCP');
        if (decryptedBuffer == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }

        RtlCopyMemory(decryptedBuffer, header, sizeof(SHADOWSTRIKE_MESSAGE_HEADER));

        decryptOpts.Key = sessionKey;
        decryptOpts.AAD = decryptedBuffer;
        decryptOpts.AADSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER);

        status = EncDecrypt(
            encMgr,
            encryptedTransportBuffer,
            encryptedDataSize,
            (PUCHAR)decryptedBuffer + sizeof(SHADOWSTRIKE_MESSAGE_HEADER),
            localEncryptedHeader.PlaintextSize,
            &plaintextSize,
            &decryptOpts
        );

        if (!NT_SUCCESS(status)) {
            goto Cleanup;
        }

        decryptedHeader = (PSHADOWSTRIKE_MESSAGE_HEADER)decryptedBuffer;
        decryptedHeader->Flags &= ~SHADOWSTRIKE_MSG_FLAG_ENCRYPTED;
        decryptedHeader->DataSize = plaintextSize;
        decryptedHeader->TotalSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + plaintextSize;

        dispatchBuffer = decryptedBuffer;
        dispatchBufferLength = decryptedHeader->TotalSize;
        dispatchBufferTrusted = TRUE;
        localHeader = *decryptedHeader;
        header = &localHeader;
    }
    else if (clientRef->EncryptionEstablished) {
        //
        // Reject plaintext messages when encryption has been established.
        // A legitimate client always encrypts after KEX succeeds.
        //
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Rejecting plaintext message type=%u from slot=%ld "
                   "(encryption mandatory after KEX)\n",
                   header->MessageType, slotIndex);
        status = STATUS_ENCRYPTION_FAILED;
        goto Cleanup;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[ShadowStrike] Message received: type=%u, id=%llu, slot=%ld\n",
               header->MessageType, header->MessageId, slotIndex);

    //
    // Dispatch based on message type with capability checks
    //
    switch (header->MessageType) {

        case ShadowStrikeMessageQueryDriverStatus:
            //
            // Query status - requires QueryStatus capability
            //
            if (!ShadowStrikeClientHasCapability(slotIndex, ShadowStrikeCapQueryStatus)) {
                status = STATUS_ACCESS_DENIED;
                break;
            }
            status = ShadowStrikeHandleQueryDriverStatus(
                header,
                OutputBuffer,
                OutputBufferLength,
                ReturnOutputBufferLength
            );
            break;

        case ShadowStrikeMessageUpdatePolicy:
            //
            // Update policy - requires UpdatePolicy capability
            //
            if (!ShadowStrikeClientHasCapability(slotIndex, ShadowStrikeCapUpdatePolicy)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike] Policy update denied - insufficient capability\n");
                status = STATUS_ACCESS_DENIED;
                break;
            }
            status = ShadowStrikeHandleUpdatePolicy(
                slotIndex,
                dispatchBuffer,
                dispatchBufferLength,
                dispatchBufferTrusted
            );
            break;

        case ShadowStrikeMessageEnableFiltering:
            //
            // Enable filtering - requires ControlFiltering capability
            //
            if (!ShadowStrikeClientHasCapability(slotIndex, ShadowStrikeCapControlFiltering)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike] Enable filtering denied - insufficient capability\n");
                status = STATUS_ACCESS_DENIED;
                break;
            }
            status = ShadowStrikeHandleEnableDisableFiltering(slotIndex, TRUE);
            break;

        case ShadowStrikeMessageDisableFiltering:
            //
            // Disable filtering - requires ControlFiltering capability
            //
            if (!ShadowStrikeClientHasCapability(slotIndex, ShadowStrikeCapControlFiltering)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike] Disable filtering denied - insufficient capability\n");
                status = STATUS_ACCESS_DENIED;
                break;
            }
            status = ShadowStrikeHandleEnableDisableFiltering(slotIndex, FALSE);
            break;

        case ShadowStrikeMessageRegisterProtectedProcess:
            //
            // Register protected process - requires ProtectProcess capability
            //
            if (!ShadowStrikeClientHasCapability(slotIndex, ShadowStrikeCapProtectProcess)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike] Protected process registration denied\n");
                status = STATUS_ACCESS_DENIED;
                break;
            }
            status = ShadowStrikeHandleRegisterProtectedProcess(
                slotIndex,
                dispatchBuffer,
                dispatchBufferLength,
                dispatchBufferTrusted
            );
            break;

        case ShadowStrikeMessageHeartbeat:
            status = ShadowStrikeHandleHeartbeat(
                header,
                OutputBuffer,
                OutputBufferLength,
                ReturnOutputBufferLength
            );
            break;

        case ShadowStrikeMessageScanVerdict:
            //
            // Scan verdict reply - handled via FltSendMessage reply mechanism
            //
            SHADOWSTRIKE_INC_STAT(RepliesReceived);
            break;

        default:
            //
            // Route extended message types (data push, telemetry, etc.)
            // through MessageHandler's registered handler table.
            // This bridges CommPort's transport layer with MessageHandler's
            // extensible dispatch framework for push messages, behavioral
            // rule updates, exclusion syncs, and network IoC injection.
            //
            {
                SHADOWSTRIKE_CLIENT_PORT clientPortContext;

                RtlZeroMemory(&clientPortContext, sizeof(clientPortContext));
                clientPortContext.ClientPort = clientRef->ClientPort;
                clientPortContext.ClientProcessId = clientRef->ClientProcessId;
                clientPortContext.ConnectedTime = clientRef->ConnectedTime;
                clientPortContext.MessagesSent =
                    (UINT64)InterlockedOr64((volatile LONG64*)&clientRef->MessagesSent, 0);
                clientPortContext.RepliesReceived =
                    (UINT64)InterlockedOr64((volatile LONG64*)&clientRef->RepliesReceived, 0);
                clientPortContext.IsPrimaryScanner = clientRef->IsPrimaryScanner;

                status = ShadowStrikeProcessUserMessage(
                    &clientPortContext,
                    dispatchBuffer,
                    dispatchBufferLength,
                    dispatchBufferTrusted,
                    OutputBuffer,
                    OutputBufferLength,
                    ReturnOutputBufferLength
                );

                if (!NT_SUCCESS(status)) {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                               "[ShadowStrike] MessageHandler dispatch failed: type=%u, status=0x%08X\n",
                               header->MessageType, status);
                }
            }
            break;
    }

Cleanup:
    if (encryptedTransportBuffer != NULL) {
        ExFreePoolWithTag(encryptedTransportBuffer, 'emCP');
    }

    if (decryptedBuffer != NULL) {
        ExFreePoolWithTag(decryptedBuffer, 'dmCP');
    }

    if (clientRef != NULL) {
        ShadowStrikeReleaseClientPort(clientRef);
    }

    return status;
}

// ============================================================================
// MESSAGE TYPE HANDLERS
// ============================================================================

static NTSTATUS
ShadowStrikeHandleQueryDriverStatus(
    _In_ PSHADOWSTRIKE_MESSAGE_HEADER InputHeader,
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnLength
    )
{
    SHADOWSTRIKE_MESSAGE_HEADER replyHeader;
    SHADOWSTRIKE_DRIVER_STATUS driverStatus;
    ULONG requiredSize;

    PAGED_CODE();

    *ReturnLength = 0;
    requiredSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + sizeof(SHADOWSTRIKE_DRIVER_STATUS);

    if (OutputBuffer == NULL || OutputBufferLength < requiredSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Build reply header
    //
    ShadowStrikeInitMessageHeader(
        &replyHeader,
        ShadowStrikeMessageQueryDriverStatus,
        sizeof(SHADOWSTRIKE_DRIVER_STATUS)
    );
    replyHeader.MessageId = InputHeader->MessageId;  // Correlation

    //
    // Build driver status — acquire config lock for consistent reads
    //
    RtlZeroMemory(&driverStatus, sizeof(SHADOWSTRIKE_DRIVER_STATUS));
    driverStatus.VersionMajor = SHADOWSTRIKE_VERSION_MAJOR;
    driverStatus.VersionMinor = SHADOWSTRIKE_VERSION_MINOR;
    driverStatus.VersionBuild = SHADOWSTRIKE_VERSION_BUILD;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_DriverData.ConfigLock);
    driverStatus.FilteringActive = g_DriverData.FilteringStarted;
    driverStatus.ScanOnOpenEnabled = g_DriverData.Config.ScanOnOpen;
    driverStatus.ScanOnExecuteEnabled = g_DriverData.Config.ScanOnExecute;
    driverStatus.ScanOnWriteEnabled = g_DriverData.Config.ScanOnWrite;
    driverStatus.NotificationsEnabled = g_DriverData.Config.NotificationsEnabled;
    ExReleasePushLockShared(&g_DriverData.ConfigLock);
    KeLeaveCriticalRegion();
    //
    // Read 64-bit volatile counters atomically (LONG64 reads are NOT atomic on x86)
    //
    driverStatus.TotalFilesScanned = (UINT64)InterlockedOr64(
        (volatile LONG64*)&g_DriverData.Stats.TotalFilesScanned, 0);
    driverStatus.FilesBlocked = (UINT64)InterlockedOr64(
        (volatile LONG64*)&g_DriverData.Stats.FilesBlocked, 0);
    driverStatus.PendingRequests = InterlockedCompareExchange(
        &g_DriverData.Stats.PendingRequests, 0, 0);
    driverStatus.PeakPendingRequests = InterlockedCompareExchange(
        &g_DriverData.Stats.PeakPendingRequests, 0, 0);
    driverStatus.CacheHits = (UINT64)InterlockedOr64(
        (volatile LONG64*)&g_DriverData.Stats.CacheHits, 0);
    driverStatus.CacheMisses = (UINT64)InterlockedOr64(
        (volatile LONG64*)&g_DriverData.Stats.CacheMisses, 0);
    driverStatus.ConnectedClients = g_DriverData.ConnectedClients;

    //
    // Instance context aggregate statistics
    //
    {
        PFLT_INSTANCE instanceBuffer[32];
        ULONG actualCount = 0;
        NTSTATUS icStatus;

        icStatus = FltEnumerateInstances(
            NULL,
            g_DriverData.FilterHandle,
            instanceBuffer,
            ARRAYSIZE(instanceBuffer),
            &actualCount
        );

        if (NT_SUCCESS(icStatus)) {
            driverStatus.IcActiveInstances = actualCount;

            for (ULONG i = 0; i < actualCount; i++) {
                PSHADOW_INSTANCE_CONTEXT instCtx = NULL;

                if (NT_SUCCESS(FltGetInstanceContext(instanceBuffer[i], (PFLT_CONTEXT*)&instCtx))
                    && instCtx != NULL)
                {
                    driverStatus.IcTotalCreateOps += instCtx->TotalCreateOperations;
                    driverStatus.IcTotalScans += instCtx->TotalFilesScanned;
                    driverStatus.IcTotalBlocks += instCtx->TotalFilesBlocked;
                    driverStatus.IcTotalWrites += instCtx->TotalWriteOperations;
                    driverStatus.IcCleanVerdicts += instCtx->TotalCleanVerdicts;
                    driverStatus.IcMalwareVerdicts += instCtx->TotalMalwareVerdicts;
                    driverStatus.IcScanErrors += instCtx->TotalScanErrors;
                    driverStatus.IcCacheHits += instCtx->TotalCacheHits;
                    FltReleaseContext((PFLT_CONTEXT)instCtx);
                }

                FltObjectDereference(instanceBuffer[i]);
            }
        }
    }

    //
    // Copy to user buffer with try/except
    //
    __try {
        ProbeForWrite(OutputBuffer, requiredSize, sizeof(UINT32));
        RtlCopyMemory(OutputBuffer, &replyHeader, sizeof(SHADOWSTRIKE_MESSAGE_HEADER));
        RtlCopyMemory(
            (PUCHAR)OutputBuffer + sizeof(SHADOWSTRIKE_MESSAGE_HEADER),
            &driverStatus,
            sizeof(SHADOWSTRIKE_DRIVER_STATUS)
        );
        *ReturnLength = requiredSize;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_INVALID_USER_BUFFER;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
ShadowStrikeHandleUpdatePolicy(
    _In_ LONG ClientIndex,
    _In_reads_bytes_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _In_ BOOLEAN InputBufferTrusted
    )
{
    SHADOWSTRIKE_POLICY_UPDATE localPolicy;
    ULONG requiredSize;
    NTSTATUS copyStatus;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(ClientIndex);

    requiredSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + sizeof(SHADOWSTRIKE_POLICY_UPDATE);
    if (InputBufferLength < requiredSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Safely copy policy from user buffer
    //
    copyStatus = ShadowStrikeCopyMessagePayload(
        InputBuffer,
        InputBufferLength,
        sizeof(SHADOWSTRIKE_MESSAGE_HEADER),
        &localPolicy,
        sizeof(localPolicy),
        InputBufferTrusted
    );
    if (!NT_SUCCESS(copyStatus)) {
        return copyStatus;
    }

    //
    // Validate policy values before applying
    //
    if (localPolicy.ScanTimeoutMs < SHADOWSTRIKE_MIN_SCAN_TIMEOUT_MS ||
        localPolicy.ScanTimeoutMs > SHADOWSTRIKE_MAX_SCAN_TIMEOUT_MS) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Apply policy under lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_DriverData.ConfigLock);

    g_DriverData.Config.ScanOnOpen = localPolicy.ScanOnOpen;
    g_DriverData.Config.ScanOnExecute = localPolicy.ScanOnExecute;
    g_DriverData.Config.ScanOnWrite = localPolicy.ScanOnWrite;
    g_DriverData.Config.NotificationsEnabled = localPolicy.EnableNotifications;
    g_DriverData.Config.BlockOnTimeout = localPolicy.BlockOnTimeout;
    g_DriverData.Config.BlockOnError = localPolicy.BlockOnError;
    g_DriverData.Config.ScanNetworkFiles = localPolicy.ScanNetworkFiles;
    g_DriverData.Config.ScanRemovableMedia = localPolicy.ScanRemovableMedia;
    g_DriverData.Config.MaxScanFileSize = localPolicy.MaxScanFileSize;
    g_DriverData.Config.ScanTimeoutMs = localPolicy.ScanTimeoutMs;
    g_DriverData.Config.CacheTTLSeconds = localPolicy.CacheTTLSeconds;

    if (localPolicy.MaxPendingRequests > 0 &&
        localPolicy.MaxPendingRequests <= SHADOWSTRIKE_DEFAULT_MAX_PENDING) {
        g_DriverData.Config.MaxPendingRequests = localPolicy.MaxPendingRequests;
    }

    ExReleasePushLockExclusive(&g_DriverData.ConfigLock);
    KeLeaveCriticalRegion();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Policy updated by authorized client\n");

    return STATUS_SUCCESS;
}

static NTSTATUS
ShadowStrikeHandleEnableDisableFiltering(
    _In_ LONG ClientIndex,
    _In_ BOOLEAN Enable
    )
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(ClientIndex);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_DriverData.ConfigLock);

    g_DriverData.Config.FilteringEnabled = Enable;

    ExReleasePushLockExclusive(&g_DriverData.ConfigLock);
    KeLeaveCriticalRegion();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Filtering %s by authorized client\n",
               Enable ? "enabled" : "disabled");

    return STATUS_SUCCESS;
}

static NTSTATUS
ShadowStrikeHandleRegisterProtectedProcess(
    _In_ LONG ClientIndex,
    _In_reads_bytes_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _In_ BOOLEAN InputBufferTrusted
    )
{
    SHADOWSTRIKE_PROTECTED_PROCESS localProtectedProcess;
    ULONG requiredSize;
    NTSTATUS status;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(ClientIndex);

    requiredSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + sizeof(SHADOWSTRIKE_PROTECTED_PROCESS);
    if (InputBufferLength < requiredSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Safely copy protected process info from user buffer
    //
    status = ShadowStrikeCopyMessagePayload(
        InputBuffer,
        InputBufferLength,
        sizeof(SHADOWSTRIKE_MESSAGE_HEADER),
        &localProtectedProcess,
        sizeof(localProtectedProcess),
        InputBufferTrusted
    );
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Validate process ID
    //
    if (localProtectedProcess.ProcessId == 0 || localProtectedProcess.ProcessId == 4) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Ensure process name is null-terminated
    //
    localProtectedProcess.ProcessName[MAX_PROCESS_NAME_LENGTH - 1] = L'\0';

    //
    // Register the protected process
    //
    status = ShadowStrikeRegisterProtectedProcess(
        localProtectedProcess.ProcessId,
        localProtectedProcess.ProtectionFlags,
        localProtectedProcess.ProcessName
    );

    return status;
}

static NTSTATUS
ShadowStrikeHandleHeartbeat(
    _In_ PSHADOWSTRIKE_MESSAGE_HEADER InputHeader,
    _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnLength
    )
{
    SHADOWSTRIKE_GENERIC_REPLY reply;

    PAGED_CODE();

    *ReturnLength = 0;

    if (OutputBuffer == NULL || OutputBufferLength < sizeof(SHADOWSTRIKE_GENERIC_REPLY)) {
        return STATUS_SUCCESS;  // Heartbeat can succeed without reply
    }

    RtlZeroMemory(&reply, sizeof(reply));
    reply.MessageId = InputHeader->MessageId;
    reply.Status = 0;

    __try {
        ProbeForWrite(OutputBuffer, sizeof(SHADOWSTRIKE_GENERIC_REPLY), sizeof(UINT32));
        RtlCopyMemory(OutputBuffer, &reply, sizeof(SHADOWSTRIKE_GENERIC_REPLY));
        *ReturnLength = sizeof(SHADOWSTRIKE_GENERIC_REPLY);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_INVALID_USER_BUFFER;
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// PORT ACCESS HELPERS
// ============================================================================

//
// DEPRECATED: Returns raw PFLT_PORT without reference increment.
// Use ShadowStrikeAcquirePrimaryScannerPort() for safe, ref-counted access.
// Retained only for backward compatibility â€” zero external callers.
//
PFLT_PORT
ShadowStrikeGetPrimaryScannerPort(
    VOID
    )
{
    PFLT_PORT port = NULL;
    LONG i;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_DriverData.ClientPortLock);

    for (i = 0; i < SHADOWSTRIKE_MAX_CONNECTIONS; i++) {
        if (g_ClientPortRefs[i].ClientPort != NULL &&
            g_ClientPortRefs[i].Disconnecting == 0 &&
            g_ClientPortRefs[i].IsPrimaryScanner) {
            port = g_ClientPortRefs[i].ClientPort;
            break;
        }
    }

    if (port == NULL) {
        for (i = 0; i < SHADOWSTRIKE_MAX_CONNECTIONS; i++) {
            if (g_ClientPortRefs[i].ClientPort != NULL &&
                g_ClientPortRefs[i].Disconnecting == 0) {
                port = g_ClientPortRefs[i].ClientPort;
                break;
            }
        }
    }

    ExReleasePushLockShared(&g_DriverData.ClientPortLock);
    KeLeaveCriticalRegion();

    return port;
}

// ============================================================================
// MESSAGE SENDING WITH REFERENCE COUNTING
// ============================================================================

static NTSTATUS
ShadowStrikeAcquireClientPortBySlot(
    _In_ LONG SlotIndex,
    _Out_ PSHADOWSTRIKE_CLIENT_PORT_REF* ClientRef
    )
{
    LONG oldRefCount;

    if (ClientRef == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ClientRef = NULL;

    if (SlotIndex < 0 || SlotIndex >= SHADOWSTRIKE_MAX_CONNECTIONS) {
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_DriverData.ClientPortLock);

    if (g_ClientPortRefs[SlotIndex].ClientPort == NULL ||
        g_ClientPortRefs[SlotIndex].Disconnecting != 0) {
        ExReleasePushLockShared(&g_DriverData.ClientPortLock);
        KeLeaveCriticalRegion();
        return SHADOWSTRIKE_ERROR_CLIENT_DISCONNECTED;
    }

    oldRefCount = InterlockedIncrement(&g_ClientPortRefs[SlotIndex].ReferenceCount);
    if (oldRefCount <= 0 ||
        InterlockedCompareExchange(&g_ClientPortRefs[SlotIndex].Disconnecting, 0, 0) != 0) {
        InterlockedDecrement(&g_ClientPortRefs[SlotIndex].ReferenceCount);
        ExReleasePushLockShared(&g_DriverData.ClientPortLock);
        KeLeaveCriticalRegion();
        return SHADOWSTRIKE_ERROR_CLIENT_DISCONNECTED;
    }

    *ClientRef = &g_ClientPortRefs[SlotIndex];

    ExReleasePushLockShared(&g_DriverData.ClientPortLock);
    KeLeaveCriticalRegion();
    return STATUS_SUCCESS;
}

NTSTATUS
ShadowStrikeAcquirePrimaryScannerPort(
    _Out_ PSHADOWSTRIKE_CLIENT_PORT_REF* ClientRef,
    _In_ BOOLEAN AllowFallback
    )
{
    LONG i;
    LONG targetSlot = -1;
    LONG oldRefCount;

    *ClientRef = NULL;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_DriverData.ClientPortLock);

    //
    // First try to find primary scanner
    //
    for (i = 0; i < SHADOWSTRIKE_MAX_CONNECTIONS; i++) {
        if (g_ClientPortRefs[i].ClientPort != NULL &&
            g_ClientPortRefs[i].Disconnecting == 0 &&
            g_ClientPortRefs[i].IsPrimaryScanner) {
            targetSlot = i;
            break;
        }
    }

    //
    // Fall back to first connected client.
    //
    // CRITICAL: the fallback is ONLY permitted for fire-and-forget telemetry
    // paths (process/alert notifications) where delivering to any verified
    // client — or buffering on failure — is acceptable. The verdict-blocking
    // scan path MUST pass AllowFallback == FALSE: routing a synchronous scan to
    // a non-scanner connection (which has no scan-reply loop) would block
    // FltSendMessage for the entire timeout budget on every file create and
    // freeze the system. With fallback disabled the scan path fails fast with
    // SHADOWSTRIKE_ERROR_PORT_NOT_CONNECTED and the caller fails open.
    //
    if (targetSlot < 0 && AllowFallback) {
        for (i = 0; i < SHADOWSTRIKE_MAX_CONNECTIONS; i++) {
            if (g_ClientPortRefs[i].ClientPort != NULL &&
                g_ClientPortRefs[i].Disconnecting == 0) {
                targetSlot = i;
                break;
            }
        }
    }

    if (targetSlot < 0) {
        ExReleasePushLockShared(&g_DriverData.ClientPortLock);
        KeLeaveCriticalRegion();
        return SHADOWSTRIKE_ERROR_PORT_NOT_CONNECTED;
    }

    //
    // Atomically increment reference count only if not disconnecting.
    // We must re-check Disconnecting AFTER incrementing to close the
    // TOCTOU window where disconnect can race between our check and
    // the increment.
    //
    oldRefCount = InterlockedIncrement(&g_ClientPortRefs[targetSlot].ReferenceCount);
    if (oldRefCount <= 0 ||
        InterlockedCompareExchange(&g_ClientPortRefs[targetSlot].Disconnecting, 0, 0) != 0) {
        //
        // Either ref count was invalid or client started disconnecting
        // between our scan and the increment â€” undo and fail.
        //
        InterlockedDecrement(&g_ClientPortRefs[targetSlot].ReferenceCount);
        ExReleasePushLockShared(&g_DriverData.ClientPortLock);
        KeLeaveCriticalRegion();
        return SHADOWSTRIKE_ERROR_CLIENT_DISCONNECTED;
    }

    *ClientRef = &g_ClientPortRefs[targetSlot];

    ExReleasePushLockShared(&g_DriverData.ClientPortLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

VOID
ShadowStrikeReleaseClientPort(
    _In_ PSHADOWSTRIKE_CLIENT_PORT_REF ClientRef
    )
{
    LONG slotIndex;
    LONG remainingRefs;

    if (ClientRef == NULL) {
        return;
    }

    slotIndex = ClientRef->SlotIndex;
    remainingRefs = InterlockedDecrement(&ClientRef->ReferenceCount);

    if (remainingRefs < 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] CRITICAL: Negative refcount %ld on slot %ld — double release detected\n",
                   remainingRefs, slotIndex);
        NT_ASSERT(remainingRefs >= 0);
        return;
    }

    if (remainingRefs == 0) {
        ShadowStrikeFinalizeClientDisconnect(slotIndex);
    }
}

NTSTATUS
ShadowStrikeSendScanRequest(
    _In_reads_bytes_(RequestSize) PSHADOWSTRIKE_MESSAGE_HEADER Request,
    _In_ ULONG RequestSize,
    _Out_writes_bytes_to_(*ReplySize, *ReplySize) PSHADOWSTRIKE_SCAN_VERDICT_REPLY Reply,
    _Inout_ PULONG ReplySize,
    _In_ ULONG TimeoutMs
    )
{
    NTSTATUS status;
    PSHADOWSTRIKE_CLIENT_PORT_REF clientRef = NULL;
    PFLT_PORT clientPort;
    LARGE_INTEGER timeout;
    LONG pendingCount;
    ULONG replySize;
    PVOID sendBuffer = Request;
    ULONG sendSize = RequestSize;
    BOOLEAN hmacAllocated = FALSE;

    //
    // Validate parameters
    //
    if (Request == NULL || Reply == NULL || ReplySize == NULL || *ReplySize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Boot-phase guards (defense-in-depth):
    //   1. If the user-mode service has not registered any client yet, fail
    //      fast with STATUS_PORT_DISCONNECTED instead of stalling inside
    //      FltSendMessage with no listener.
    //   2. During the first ~120 s of driver lifetime, hard-clamp the caller's
    //      timeout to 250 ms so a misbehaving / slow user-mode reply cannot
    //      stall winlogon/lsass/csrss DLL loads.
    //
    if (g_DriverData.ConnectedClients == 0) {
        SHADOWSTRIKE_INC_STAT(MessagesDropped);
        return STATUS_PORT_DISCONNECTED;
    }
    if (ShadowFsIsBootPhase() && TimeoutMs > 250) {
        TimeoutMs = 250;
    }

    //
    // Check pending request limit before acquiring port
    //
    pendingCount = InterlockedIncrement(&g_DriverData.Stats.PendingRequests);
    {
        LONG currentPeak = g_DriverData.Stats.PeakPendingRequests;
        while (pendingCount > currentPeak) {
            LONG prev = InterlockedCompareExchange(
                &g_DriverData.Stats.PeakPendingRequests,
                pendingCount, currentPeak);
            if (prev == currentPeak) break;
            currentPeak = prev;
        }
    }

    if ((ULONG)pendingCount > g_DriverData.Config.MaxPendingRequests) {
        InterlockedDecrement(&g_DriverData.Stats.PendingRequests);
        SHADOWSTRIKE_INC_STAT(MessagesDropped);
        return SHADOWSTRIKE_ERROR_QUEUE_FULL;
    }

    //
    // Acquire reference to client port FIRST — needed for session key access.
    // This must precede the encryption and HMAC blocks.
    //
    // AllowFallback == FALSE: this is the verdict-blocking scan transport. It
    // must only ever target a real primary scanner; never fall back to a
    // non-scanner client (which would block FltSendMessage for the full timeout
    // and freeze the system). When no primary scanner is present the acquire
    // fails fast and the caller (ScanBridge → PreCreate) fails open.
    //
    status = ShadowStrikeAcquirePrimaryScannerPort(&clientRef, FALSE);
    if (!NT_SUCCESS(status)) {
        InterlockedDecrement(&g_DriverData.Stats.PendingRequests);
        return status;
    }

    //
    // Per-session AES-256-GCM encryption of the message payload.
    // Encrypts the data portion (after SHADOWSTRIKE_MESSAGE_HEADER) using the
    // session key derived at connection time. The message header is used as AAD
    // (Additional Authenticated Data) to bind header to ciphertext.
    //
    // Allocation: [Header (40B)][ENC_HEADER (72B)][Encrypted Data]
    // If encryption succeeds, the HMAC step below operates on the encrypted form.
    //
    PVOID encryptedBuffer = NULL;
    ULONG encryptedSendSize = 0;
    BOOLEAN encryptionAllocated = FALSE;

    if (RequestSize > sizeof(SHADOWSTRIKE_MESSAGE_HEADER)) {
        PENC_MANAGER encMgr = ShadowStrikeGetEncryptionManager();
        if (!clientRef->EncryptionEstablished || encMgr == NULL) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[ShadowStrike] Scan request transport unavailable: slot=%ld, encReady=%d\n",
                       clientRef->SlotIndex, clientRef->EncryptionEstablished);
            ShadowStrikeReleaseClientPort(clientRef);
            InterlockedDecrement(&g_DriverData.Stats.PendingRequests);
            SHADOWSTRIKE_INC_STAT(MessagesDropped);
            return STATUS_ENCRYPTION_FAILED;
        }

            ULONG dataSize = RequestSize - sizeof(SHADOWSTRIKE_MESSAGE_HEADER);
            PVOID dataStart = (PUCHAR)Request + sizeof(SHADOWSTRIKE_MESSAGE_HEADER);
            ULONG encryptedSize = 0;

            //
            // Calculate required buffer size for encrypted output
            //
            NTSTATUS encSizeStatus = EncGetEncryptedSize(dataSize, TRUE, &encryptedSize);
            if (NT_SUCCESS(encSizeStatus) && encryptedSize > 0) {
                ULONG totalEncSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + encryptedSize;
                PVOID encBuf = ExAllocatePool2(
                    POOL_FLAG_NON_PAGED, totalEncSize, 'enCP');
                if (encBuf != NULL) {
                    //
                    // Prepare the final on-wire header before encryption so
                    // the authenticated AAD matches what user-mode receives.
                    //
                    ShadowStrikePrepareEncryptedMessageHeader(
                        (PSHADOWSTRIKE_MESSAGE_HEADER)encBuf,
                        Request,
                        encryptedSize
                    );

                    //
                    // Message authentication is provided by AES-256-GCM, which
                    // is an AEAD: the GCM tag (computed below) authenticates BOTH
                    // the ciphertext AND the message header supplied as AAD. We
                    // deliberately do NOT set SHADOWSTRIKE_MSG_FLAG_HMAC nor append
                    // a separate HMAC-SHA256. That redundant second layer was
                    // mis-keyed relative to the user-mode verifier, so every
                    // message failed its pre-decryption HMAC check and was dropped
                    // before it could be decrypted — collapsing the scanner channel
                    // (observed: thousands of "HMAC verification FAILED" with a
                    // correct, KEX-matched session key). GCM is the single, correct
                    // authentication primitive for this transport; the header flag
                    // therefore stays clear so the AAD the receiver authenticates
                    // matches the on-wire header byte-for-byte.
                    //
                    ENC_OPTIONS encOpts = {0};
                    encOpts.Flags = EncFlag_IncludeHeader | EncFlag_UseAAD;
                    encOpts.AAD = encBuf;  // Header as AAD
                    encOpts.AADSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER);
                    encOpts.TagSize = ENC_GCM_TAG_SIZE;

                    PENC_KEY sessionKey = g_ClientSessionEncKeys[clientRef->SlotIndex];
                    if (sessionKey != NULL) {
                        encOpts.Key = sessionKey;

                        ULONG ciphertextSize = 0;
                        NTSTATUS encStatus = EncEncrypt(
                            encMgr,
                            EncKeyType_Ephemeral,
                            dataStart, dataSize,
                            (PUCHAR)encBuf + sizeof(SHADOWSTRIKE_MESSAGE_HEADER),
                            encryptedSize,
                            &ciphertextSize,
                            &encOpts
                        );

                        if (NT_SUCCESS(encStatus) &&
                            ciphertextSize == encryptedSize &&
                            ciphertextSize > 0) {
                            PSHADOWSTRIKE_MESSAGE_HEADER encHeader =
                                (PSHADOWSTRIKE_MESSAGE_HEADER)encBuf;
                            encryptedBuffer = encBuf;
                            encryptedSendSize = encHeader->TotalSize;
                            encryptionAllocated = TRUE;

                            //
                            // Mirror the actual encryption library nonce counter so
                            // transport diagnostics reflect the real GCM nonce state.
                            //
                            InterlockedExchange64(&clientRef->NonceCounter,
                                                 sessionKey->NonceCounter);

                            // Update send pointers
                            sendBuffer = encryptedBuffer;
                            sendSize = encryptedSendSize;
                        } else {
                            ExFreePoolWithTag(encBuf, 'enCP');
                            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                                       "[ShadowStrike] Scan request encryption failed: 0x%08X, "
                                       "DROPPING message (no plaintext fallback)\n", encStatus);
                            ShadowStrikeReleaseClientPort(clientRef);
                            InterlockedDecrement(&g_DriverData.Stats.PendingRequests);
                            SHADOWSTRIKE_INC_STAT(MessagesDropped);
                            return STATUS_ENCRYPTION_FAILED;
                        }
                    } else {
                        ExFreePoolWithTag(encBuf, 'enCP');
                        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                                   "[ShadowStrike] Scan request session key missing for slot %ld, "
                                   "DROPPING message (no plaintext fallback)\n",
                                   clientRef->SlotIndex);
                        ShadowStrikeReleaseClientPort(clientRef);
                        InterlockedDecrement(&g_DriverData.Stats.PendingRequests);
                        SHADOWSTRIKE_INC_STAT(MessagesDropped);
                        return STATUS_ENCRYPTION_FAILED;
                    }
                }
                else {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                               "[ShadowStrike] Scan request encryption allocation failed\n");
                    ShadowStrikeReleaseClientPort(clientRef);
                    InterlockedDecrement(&g_DriverData.Stats.PendingRequests);
                    SHADOWSTRIKE_INC_STAT(MessagesDropped);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
            }
            else {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                           "[ShadowStrike] Scan request encrypted size calculation failed: 0x%08X\n",
                           encSizeStatus);
                ShadowStrikeReleaseClientPort(clientRef);
                InterlockedDecrement(&g_DriverData.Stats.PendingRequests);
                SHADOWSTRIKE_INC_STAT(MessagesDropped);
                return STATUS_ENCRYPTION_FAILED;
            }
    }

    //
    // No separate message HMAC is appended. AES-256-GCM (applied above) is an
    // AEAD: its authentication tag already covers the ciphertext and the
    // message header (passed as AAD), giving full integrity + authenticity with
    // the per-session key both ends derived during the key exchange. The former
    // HMAC-SHA256 layer was redundant with GCM and was keyed off material the
    // user-mode receiver does not possess, so it failed verification on every
    // message and silently dropped all encrypted scan requests before they
    // could be decrypted or replied to. Relying on GCM alone is the correct,
    // provably-keyed authentication for this transport.
    //

    clientPort = clientRef->ClientPort;
    replySize = *ReplySize;

    //
    // Calculate timeout (negative = relative time in 100ns units)
    //
    timeout.QuadPart = -(LONGLONG)TimeoutMs * 10000LL;

    //
    // Send message and wait for reply
    //
    status = FltSendMessage(
        g_DriverData.FilterHandle,
        &clientPort,
        sendBuffer,
        sendSize,
        Reply,
        &replySize,
        &timeout
    );

    //
    // Update per-client stats BEFORE releasing reference
    //
    if (NT_SUCCESS(status)) {
        InterlockedIncrement64(&clientRef->MessagesSent);
        InterlockedIncrement64(&clientRef->RepliesReceived);
    }

    //
    // Release client reference
    //
    ShadowStrikeReleaseClientPort(clientRef);

    InterlockedDecrement(&g_DriverData.Stats.PendingRequests);

    if (hmacAllocated) {
        ExFreePoolWithTag(sendBuffer, 'hmCP');
    }
    if (encryptionAllocated) {
        ExFreePoolWithTag(encryptedBuffer, 'enCP');
    }

    if (NT_SUCCESS(status)) {
        SHADOWSTRIKE_INC_STAT(MessagesSent);
        SHADOWSTRIKE_INC_STAT(RepliesReceived);
        *ReplySize = replySize;
    } else if (status == STATUS_TIMEOUT) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Scan request timeout (id=%llu)\n",
                   Request->MessageId);
        SHADOWSTRIKE_INC_STAT(ScanTimeouts);
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] FltSendMessage failed: 0x%08X\n", status);
    }

    return status;
}

NTSTATUS
ShadowStrikeSendNotification(
    _In_reads_bytes_(Size) PSHADOWSTRIKE_MESSAGE_HEADER Notification,
    _In_ ULONG Size
    )
{
    NTSTATUS status;
    PSHADOWSTRIKE_CLIENT_PORT_REF clientRef = NULL;
    PFLT_PORT clientPort;
    LARGE_INTEGER timeout;
    PVOID sendBuffer = Notification;
    ULONG sendSize = Size;
    PVOID compressedPayload = NULL;
    PVOID compressedSendBuffer = NULL;  // Track compressed allocation separately
    BOOLEAN usedCompression = FALSE;

    if (!g_DriverData.Config.NotificationsEnabled) {
        return STATUS_SUCCESS;
    }

    //
    // Fast-path bail when no user-mode client has connected yet. Avoids
    // allocating compression / encryption buffers and walking the port
    // list during early boot before the service registers.
    //
    if (g_DriverData.ConnectedClients == 0) {
        SHADOWSTRIKE_INC_STAT(MessagesDropped);
        return STATUS_PORT_DISCONNECTED;
    }

    //
    // Attempt payload compression for messages exceeding threshold.
    // Data portion starts after the header; compress only the data.
    //
    if (Notification->DataSize > COMP_MIN_INPUT_SIZE) {
        PVOID dataStart = (PUCHAR)Notification + sizeof(SHADOWSTRIKE_MESSAGE_HEADER);
        ULONG dataSize = Notification->DataSize;
        //
        // Compression can expand incompressible data; allocate margin.
        // LZ4 worst case is input + input/255 + 16; we use input + input/128 + 64
        // as a conservative upper bound for any algorithm.
        //
        ULONG compBufSize = dataSize + (dataSize >> 7) + 64;
        ULONG compressedSize = 0;

        compressedPayload = ExAllocatePool2(POOL_FLAG_NON_PAGED, compBufSize, 'cmCP');
        if (compressedPayload != NULL) {
            status = CompCompress(
                dataStart,
                dataSize,
                compressedPayload,
                compBufSize,
                &compressedSize,
                NULL
            );

            //
            // Verify compressed data integrity before sending.
            // Catches silent LZ4 corruption from memory errors or bugs.
            //
            if (NT_SUCCESS(status) && compressedSize > 0) {
                NTSTATUS verifyStatus = CompVerify(compressedPayload, compressedSize);
                if (!NT_SUCCESS(verifyStatus)) {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                               "[ShadowStrike/CommPort] Compressed data verification failed: 0x%08X, sending uncompressed\n",
                               verifyStatus);
                    status = verifyStatus;  // fall through to send uncompressed
                }
            }

            //
            // Only use compressed form if it saves at least 10% space
            //
            if (NT_SUCCESS(status) &&
                compressedSize > 0 &&
                compressedSize < (dataSize - dataSize / 10))
            {
                ULONG newTotal = sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + compressedSize;
                PSHADOWSTRIKE_MESSAGE_HEADER compMsg =
                    (PSHADOWSTRIKE_MESSAGE_HEADER)ExAllocatePool2(
                        POOL_FLAG_NON_PAGED, newTotal, 'cmCP');
                if (compMsg != NULL) {
                    RtlCopyMemory(compMsg, Notification, sizeof(SHADOWSTRIKE_MESSAGE_HEADER));
                    RtlCopyMemory(
                        (PUCHAR)compMsg + sizeof(SHADOWSTRIKE_MESSAGE_HEADER),
                        compressedPayload,
                        compressedSize
                    );
                    compMsg->Flags |= SHADOWSTRIKE_MSG_FLAG_COMPRESSED;
                    compMsg->Reserved = dataSize;   // original uncompressed size
                    compMsg->DataSize = compressedSize;
                    compMsg->TotalSize = newTotal;
                    sendBuffer = compMsg;
                    sendSize = newTotal;
                    compressedSendBuffer = compMsg;  // Track for cleanup
                    usedCompression = TRUE;
                }
            }

            ExFreePoolWithTag(compressedPayload, 'cmCP');
            compressedPayload = NULL;
        }
    }

    //
    // Per-session AES-256-GCM encryption of the notification payload.
    // At this point sendBuffer/sendSize may contain compressed data.
    // We encrypt the data portion (after header), using the header as AAD.
    //
    PVOID encryptedNotifBuffer = NULL;
    BOOLEAN notifEncrypted = FALSE;

    //
    // Acquire reference to client port.
    //
    // AllowFallback == TRUE: this is a fire-and-forget telemetry/notification
    // path. Delivering to any verified connected client (or buffering on
    // failure) is acceptable, and there is no synchronous reply to block on.
    //
    status = ShadowStrikeAcquirePrimaryScannerPort(&clientRef, TRUE);
    if (!NT_SUCCESS(status)) {
        //
        // No connected user-mode client â€” buffer the message in MessageQueue
        // for delivery when a client reconnects.  This prevents telemetry
        // loss during user-mode agent restart / reconnect windows.
        //
        // Backpressure check: log if queue is at high water mark
        //
        if (MqIsHighWaterMark()) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike/CommPort] Queue at high water mark (depth=%u), "
                       "enqueue may be dropped. Consider client reconnect.\n",
                       MqGetQueueDepth());
        }
        {
            NTSTATUS mqStatus = MqEnqueueMessage(
                (SHADOWSTRIKE_MESSAGE_TYPE)Notification->MessageType,
                sendBuffer,
                sendSize,
                MessagePriority_Normal,
                MQ_MSG_FLAG_NOTIFY_ONLY,
                NULL
            );
            if (!NT_SUCCESS(mqStatus)) {
                SHADOWSTRIKE_INC_STAT(MessagesDropped);
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike/CommPort] MqEnqueueMessage dropped notification "
                           "(type=%u, size=%lu, status=0x%08X, depth=%u)\n",
                           (unsigned)Notification->MessageType,
                           (unsigned long)sendSize, mqStatus, MqGetQueueDepth());
            }
        }

        if (usedCompression) {
            ExFreePoolWithTag(sendBuffer, 'cmCP');
        }
        return status;
    }

    clientPort = clientRef->ClientPort;

    //
    // Encrypt notification if session key is established
    //
    if (sendSize > sizeof(SHADOWSTRIKE_MESSAGE_HEADER)) {
        PENC_MANAGER encMgr = ShadowStrikeGetEncryptionManager();
        if (!clientRef->EncryptionEstablished || encMgr == NULL) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[ShadowStrike] Notification transport unavailable: slot=%ld, encReady=%d\n",
                       clientRef->SlotIndex, clientRef->EncryptionEstablished);
            ShadowStrikeReleaseClientPort(clientRef);
            if (usedCompression) {
                ExFreePoolWithTag(sendBuffer, 'cmCP');
            }
            SHADOWSTRIKE_INC_STAT(MessagesDropped);
            return STATUS_ENCRYPTION_FAILED;
        }

            ULONG dataSize = sendSize - sizeof(SHADOWSTRIKE_MESSAGE_HEADER);
            PVOID dataStart = (PUCHAR)sendBuffer + sizeof(SHADOWSTRIKE_MESSAGE_HEADER);
            ULONG encryptedSize = 0;

            NTSTATUS encSizeStatus = EncGetEncryptedSize(dataSize, TRUE, &encryptedSize);
            if (NT_SUCCESS(encSizeStatus) && encryptedSize > 0) {
                ULONG totalEncSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + encryptedSize;
                PVOID encBuf = ExAllocatePool2(
                    POOL_FLAG_NON_PAGED, totalEncSize, 'enCP');
                if (encBuf != NULL) {
                    ShadowStrikePrepareEncryptedMessageHeader(
                        (PSHADOWSTRIKE_MESSAGE_HEADER)encBuf,
                        (PSHADOWSTRIKE_MESSAGE_HEADER)sendBuffer,
                        encryptedSize
                    );

                    ENC_OPTIONS encOpts = {0};
                    encOpts.Flags = EncFlag_IncludeHeader | EncFlag_UseAAD;
                    encOpts.AAD = encBuf;
                    encOpts.AADSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER);
                    encOpts.TagSize = ENC_GCM_TAG_SIZE;

                    PENC_KEY sessionKey = g_ClientSessionEncKeys[clientRef->SlotIndex];
                    if (sessionKey != NULL) {
                        encOpts.Key = sessionKey;
                        ULONG ciphertextSize = 0;
                        NTSTATUS encStatus = EncEncrypt(
                            encMgr, EncKeyType_Ephemeral,
                            dataStart, dataSize,
                            (PUCHAR)encBuf + sizeof(SHADOWSTRIKE_MESSAGE_HEADER),
                            encryptedSize, &ciphertextSize, &encOpts);

                        if (NT_SUCCESS(encStatus) &&
                            ciphertextSize == encryptedSize &&
                            ciphertextSize > 0) {
                            PSHADOWSTRIKE_MESSAGE_HEADER encHeader =
                                (PSHADOWSTRIKE_MESSAGE_HEADER)encBuf;
                            encryptedNotifBuffer = encBuf;
                            sendBuffer = encryptedNotifBuffer;
                            sendSize = encHeader->TotalSize;
                            notifEncrypted = TRUE;
                            InterlockedExchange64(&clientRef->NonceCounter,
                                                 sessionKey->NonceCounter);
                        } else {
                            ExFreePoolWithTag(encBuf, 'enCP');
                            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                                       "[ShadowStrike] Notification encryption failed: 0x%08X, "
                                       "DROPPING message (no plaintext fallback)\n", encStatus);
                            ShadowStrikeReleaseClientPort(clientRef);
                            if (usedCompression) {
                                ExFreePoolWithTag(sendBuffer, 'cmCP');
                            }
                            SHADOWSTRIKE_INC_STAT(MessagesDropped);
                            return STATUS_ENCRYPTION_FAILED;
                        }
                    } else {
                        ExFreePoolWithTag(encBuf, 'enCP');
                        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                                   "[ShadowStrike] Notification session key missing for slot %ld, "
                                   "DROPPING message (no plaintext fallback)\n",
                                   clientRef->SlotIndex);
                        ShadowStrikeReleaseClientPort(clientRef);
                        if (usedCompression) {
                            ExFreePoolWithTag(sendBuffer, 'cmCP');
                        }
                        SHADOWSTRIKE_INC_STAT(MessagesDropped);
                        return STATUS_ENCRYPTION_FAILED;
                    }
                }
                else {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                               "[ShadowStrike] Notification encryption allocation failed\n");
                    ShadowStrikeReleaseClientPort(clientRef);
                    if (usedCompression) {
                        ExFreePoolWithTag(sendBuffer, 'cmCP');
                    }
                    SHADOWSTRIKE_INC_STAT(MessagesDropped);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
            }
            else {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                           "[ShadowStrike] Notification encrypted size calculation failed: 0x%08X\n",
                           encSizeStatus);
                ShadowStrikeReleaseClientPort(clientRef);
                if (usedCompression) {
                    ExFreePoolWithTag(sendBuffer, 'cmCP');
                }
                SHADOWSTRIKE_INC_STAT(MessagesDropped);
                return STATUS_ENCRYPTION_FAILED;
            }
    }

    //
    // Use zero timeout for fire-and-forget (returns immediately)
    //
    timeout.QuadPart = 0;

    status = FltSendMessage(
        g_DriverData.FilterHandle,
        &clientPort,
        sendBuffer,
        sendSize,
        NULL,
        NULL,
        &timeout
    );

    //
    // Update per-client stats BEFORE releasing reference
    //
    if (NT_SUCCESS(status)) {
        InterlockedIncrement64(&clientRef->MessagesSent);
    }

    ShadowStrikeReleaseClientPort(clientRef);

    if (notifEncrypted) {
        ExFreePoolWithTag(encryptedNotifBuffer, 'enCP');
    }
    if (usedCompression && compressedSendBuffer != NULL) {
        ExFreePoolWithTag(compressedSendBuffer, 'cmCP');
    }

    if (NT_SUCCESS(status)) {
        SHADOWSTRIKE_INC_STAT(MessagesSent);
    }

    return status;
}

NTSTATUS
ShadowStrikeSendProcessNotification(
    _In_reads_bytes_(Size) PSHADOWSTRIKE_PROCESS_NOTIFICATION Notification,
    _In_ ULONG Size,
    _In_ BOOLEAN RequireReply,
    _Out_writes_bytes_opt_(*ReplySize) PSHADOWSTRIKE_PROCESS_VERDICT_REPLY Reply,
    _Inout_opt_ PULONG ReplySize
    )
{
    NTSTATUS status;
    PSHADOWSTRIKE_CLIENT_PORT_REF clientRef = NULL;
    PFLT_PORT clientPort;
    LARGE_INTEGER timeout;
    LONG pendingCount;
    PSHADOWSTRIKE_MESSAGE_HEADER header = NULL;
    ULONG totalSize;
    ULONG replyBufferSize = 0;

    //
    // Validate parameters
    //
    if (Notification == NULL || Size < sizeof(SHADOWSTRIKE_PROCESS_NOTIFICATION)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (RequireReply && (Reply == NULL || ReplySize == NULL)) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Boot-phase guard: no listener yet → fast bail. Avoids per-process
    // boot storm hitting FltSendMessage with no client registered.
    //
    if (g_DriverData.ConnectedClients == 0) {
        SHADOWSTRIKE_INC_STAT(MessagesDropped);
        return STATUS_PORT_DISCONNECTED;
    }

    if (!g_DriverData.Config.NotificationsEnabled) {
        return STATUS_SUCCESS;
    }

    //
    // Acquire reference to client port.
    //
    // AllowFallback == TRUE: process-notification delivery path. Fire-and-forget
    // notifications buffer on failure; this preserves existing telemetry routing
    // and is not the verdict-blocking file-create scan path responsible for the
    // boot-time freeze.
    //
    status = ShadowStrikeAcquirePrimaryScannerPort(&clientRef, TRUE);
    if (!NT_SUCCESS(status)) {
        //
        // No connected client.  For fire-and-forget notifications,
        // buffer to MessageQueue for delivery on reconnect so that
        // process-create/terminate events are not lost during agent
        // restart windows.  Reply-required messages cannot be buffered
        // (caller needs a synchronous verdict).
        //
        if (!RequireReply) {
            ULONG mqSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + Size;
            PSHADOWSTRIKE_MESSAGE_HEADER mqHeader =
                (PSHADOWSTRIKE_MESSAGE_HEADER)ExAllocatePool2(
                    POOL_FLAG_NON_PAGED, mqSize, 'mqCP');
            if (mqHeader != NULL) {
                ShadowStrikeInitMessageHeader(
                    mqHeader, ShadowStrikeMessageProcessNotify, Size);
                RtlCopyMemory(
                    (PUCHAR)mqHeader + sizeof(SHADOWSTRIKE_MESSAGE_HEADER),
                    Notification, Size);
                {
                    NTSTATUS mqStatus = MqEnqueueMessage(
                        ShadowStrikeMessageProcessNotify,
                        mqHeader,
                        mqSize,
                        MessagePriority_Normal,
                        MQ_MSG_FLAG_NOTIFY_ONLY,
                        NULL
                    );
                    if (!NT_SUCCESS(mqStatus)) {
                        SHADOWSTRIKE_INC_STAT(MessagesDropped);
                        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                                   "[ShadowStrike/CommPort] MqEnqueueMessage dropped process notify "
                                   "(size=%lu, status=0x%08X, depth=%u)\n",
                                   (unsigned long)mqSize, mqStatus, MqGetQueueDepth());
                    }
                }
                ExFreePoolWithTag(mqHeader, 'mqCP');
            }
        }
        return status;
    }

    clientPort = clientRef->ClientPort;

    //
    // Calculate total message size
    //
    totalSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + Size;

    //
    // Allocate message buffer
    //
    header = (PSHADOWSTRIKE_MESSAGE_HEADER)ShadowStrikeAllocateMessageBuffer(totalSize);
    if (header == NULL) {
        ShadowStrikeReleaseClientPort(clientRef);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize header and copy notification
    //
    ShadowStrikeInitMessageHeader(header, ShadowStrikeMessageProcessNotify, Size);
    RtlCopyMemory((PUCHAR)header + sizeof(SHADOWSTRIKE_MESSAGE_HEADER), Notification, Size);

    //
    // Encrypt the process notification payload if session key is established.
    // The encrypted message replaces the original; header + encrypted data.
    //
    PVOID encryptedProcBuf = NULL;
    BOOLEAN procEncrypted = FALSE;

    if (Size > 0) {
        PENC_MANAGER encMgr = ShadowStrikeGetEncryptionManager();
        if (!clientRef->EncryptionEstablished || encMgr == NULL) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[ShadowStrike] ProcessNotification transport unavailable: slot=%ld, encReady=%d\n",
                       clientRef->SlotIndex, clientRef->EncryptionEstablished);
            ShadowStrikeFreeMessageBuffer(header);
            ShadowStrikeReleaseClientPort(clientRef);
            SHADOWSTRIKE_INC_STAT(MessagesDropped);
            return STATUS_ENCRYPTION_FAILED;
        }

            ULONG encryptedSize = 0;
            NTSTATUS encSizeStatus = EncGetEncryptedSize(Size, TRUE, &encryptedSize);
            if (NT_SUCCESS(encSizeStatus) && encryptedSize > 0) {
                ULONG totalEncSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + encryptedSize;
                PVOID encBuf = ExAllocatePool2(
                    POOL_FLAG_NON_PAGED, totalEncSize, 'enCP');
                if (encBuf != NULL) {
                    ShadowStrikePrepareEncryptedMessageHeader(
                        (PSHADOWSTRIKE_MESSAGE_HEADER)encBuf,
                        header,
                        encryptedSize
                    );

                    ENC_OPTIONS encOpts = {0};
                    encOpts.Flags = EncFlag_IncludeHeader | EncFlag_UseAAD;
                    encOpts.AAD = encBuf;
                    encOpts.AADSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER);
                    encOpts.TagSize = ENC_GCM_TAG_SIZE;

                    PENC_KEY sessionKey = g_ClientSessionEncKeys[clientRef->SlotIndex];
                    if (sessionKey != NULL) {
                        encOpts.Key = sessionKey;
                        ULONG ciphertextSize = 0;
                        NTSTATUS encStatus = EncEncrypt(
                            encMgr, EncKeyType_Ephemeral,
                            (PUCHAR)header + sizeof(SHADOWSTRIKE_MESSAGE_HEADER),
                            Size,
                            (PUCHAR)encBuf + sizeof(SHADOWSTRIKE_MESSAGE_HEADER),
                            encryptedSize, &ciphertextSize, &encOpts);

                        if (NT_SUCCESS(encStatus) &&
                            ciphertextSize == encryptedSize &&
                            ciphertextSize > 0) {
                            PSHADOWSTRIKE_MESSAGE_HEADER encHeader =
                                (PSHADOWSTRIKE_MESSAGE_HEADER)encBuf;
                            // Free original unencrypted buffer, use encrypted one
                            ShadowStrikeFreeMessageBuffer(header);
                            header = (PSHADOWSTRIKE_MESSAGE_HEADER)encBuf;
                            totalSize = encHeader->TotalSize;
                            encryptedProcBuf = encBuf;
                            procEncrypted = TRUE;
                            InterlockedExchange64(&clientRef->NonceCounter,
                                                 sessionKey->NonceCounter);
                        } else {
                            ExFreePoolWithTag(encBuf, 'enCP');
                            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                                       "[ShadowStrike] ProcessNotification encryption failed: 0x%08X, "
                                       "DROPPING message (no plaintext fallback)\n", encStatus);
                            ShadowStrikeFreeMessageBuffer(header);
                            ShadowStrikeReleaseClientPort(clientRef);
                            SHADOWSTRIKE_INC_STAT(MessagesDropped);
                            return STATUS_ENCRYPTION_FAILED;
                        }
                    } else {
                        ExFreePoolWithTag(encBuf, 'enCP');
                        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                                   "[ShadowStrike] ProcessNotification session key missing for slot %ld, "
                                   "DROPPING message (no plaintext fallback)\n",
                                   clientRef->SlotIndex);
                        ShadowStrikeFreeMessageBuffer(header);
                        ShadowStrikeReleaseClientPort(clientRef);
                        SHADOWSTRIKE_INC_STAT(MessagesDropped);
                        return STATUS_ENCRYPTION_FAILED;
                    }
                }
                else {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                               "[ShadowStrike] ProcessNotification encryption allocation failed\n");
                    ShadowStrikeFreeMessageBuffer(header);
                    ShadowStrikeReleaseClientPort(clientRef);
                    SHADOWSTRIKE_INC_STAT(MessagesDropped);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
            }
            else {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                           "[ShadowStrike] ProcessNotification encrypted size calculation failed: 0x%08X\n",
                           encSizeStatus);
                ShadowStrikeFreeMessageBuffer(header);
                ShadowStrikeReleaseClientPort(clientRef);
                SHADOWSTRIKE_INC_STAT(MessagesDropped);
                return STATUS_ENCRYPTION_FAILED;
            }
    }

    if (RequireReply) {
        //
        // Track pending requests
        //
        pendingCount = InterlockedIncrement(&g_DriverData.Stats.PendingRequests);
        {
            LONG currentPeak = g_DriverData.Stats.PeakPendingRequests;
            while (pendingCount > currentPeak) {
                LONG prev = InterlockedCompareExchange(
                    &g_DriverData.Stats.PeakPendingRequests,
                    pendingCount, currentPeak);
                if (prev == currentPeak) break;
                currentPeak = prev;
            }
        }

        if ((ULONG)pendingCount > g_DriverData.Config.MaxPendingRequests) {
            InterlockedDecrement(&g_DriverData.Stats.PendingRequests);
            if (procEncrypted) {
                ExFreePoolWithTag(encryptedProcBuf, 'enCP');
            } else {
                ShadowStrikeFreeMessageBuffer(header);
            }
            ShadowStrikeReleaseClientPort(clientRef);
            SHADOWSTRIKE_INC_STAT(MessagesDropped);
            return SHADOWSTRIKE_ERROR_QUEUE_FULL;
        }

        replyBufferSize = *ReplySize;
        {
            ULONG _toMs = g_DriverData.Config.ScanTimeoutMs;
            if (ShadowFsIsBootPhase() && _toMs > 250) _toMs = 250;
            timeout.QuadPart = -(LONGLONG)_toMs * 10000LL;
        }

        status = FltSendMessage(
            g_DriverData.FilterHandle,
            &clientPort,
            header,
            totalSize,
            Reply,
            &replyBufferSize,
            &timeout
        );

        InterlockedDecrement(&g_DriverData.Stats.PendingRequests);

        if (NT_SUCCESS(status)) {
            SHADOWSTRIKE_INC_STAT(MessagesSent);
            SHADOWSTRIKE_INC_STAT(RepliesReceived);
            *ReplySize = replyBufferSize;
        } else if (status == STATUS_TIMEOUT) {
            SHADOWSTRIKE_INC_STAT(ScanTimeouts);
        }
    } else {
        //
        // Fire-and-forget with zero timeout
        //
        timeout.QuadPart = 0;

        status = FltSendMessage(
            g_DriverData.FilterHandle,
            &clientPort,
            header,
            totalSize,
            NULL,
            NULL,
            &timeout
        );

        if (NT_SUCCESS(status)) {
            SHADOWSTRIKE_INC_STAT(MessagesSent);
        }
    }

    if (procEncrypted) {
        ExFreePoolWithTag(encryptedProcBuf, 'enCP');
    } else {
        ShadowStrikeFreeMessageBuffer(header);
    }
    ShadowStrikeReleaseClientPort(clientRef);

    return status;
}

// ============================================================================
// CONNECTION STATE QUERIES
// ============================================================================

BOOLEAN
ShadowStrikeIsUserModeConnected(
    VOID
    )
{
    //
    // Read with memory barrier for visibility
    //
    return (InterlockedCompareExchange(&g_DriverData.ConnectedClients, 0, 0) > 0);
}

BOOLEAN
ShadowStrikeIsPrimaryScannerConnected(
    VOID
    )
{
    //
    // Lock-free readiness gate for the verdict-blocking scan path. Returns TRUE
    // only when at least one primary-scanner connection has completed its key
    // exchange and can therefore decrypt and reply to scan requests. Keying the
    // scan gate on this (instead of the raw ConnectedClients count) prevents
    // routing synchronous file-create scans to a non-scanner connection (e.g.
    // the bootstrap gate, UI, or tray client) — which has no scan-reply loop and
    // would otherwise block FltSendMessage for the full timeout budget on every
    // file create, freezing the system during the service start-up window.
    //
    // Read-only Interlocked load: safe at any IRQL up to DISPATCH_LEVEL, matching
    // the SAL contract of ShadowStrikeScanBridgeIsReady, which calls this without
    // holding ClientPortLock.
    //
    return (InterlockedCompareExchange(&g_DriverData.PrimaryScannersReady, 0, 0) > 0);
}

LONG
ShadowStrikeGetConnectedClientCount(
    VOID
    )
{
    return InterlockedCompareExchange(&g_DriverData.ConnectedClients, 0, 0);
}

// ============================================================================
// CLIENT MANAGEMENT
// ============================================================================

LONG
ShadowStrikeFindClientByProcessId(
    _In_ HANDLE ProcessId
    )
{
    LONG result = -1;
    LONG i;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_DriverData.ClientPortLock);

    for (i = 0; i < SHADOWSTRIKE_MAX_CONNECTIONS; i++) {
        if (g_ClientPortRefs[i].ClientPort != NULL &&
            g_ClientPortRefs[i].ClientProcessId == ProcessId) {
            result = i;
            break;
        }
    }

    ExReleasePushLockShared(&g_DriverData.ClientPortLock);
    KeLeaveCriticalRegion();

    return result;
}

BOOLEAN
ShadowStrikeValidateClient(
    _In_ LONG ClientIndex
    )
{
    BOOLEAN valid = FALSE;

    if (ClientIndex < 0 || ClientIndex >= SHADOWSTRIKE_MAX_CONNECTIONS) {
        return FALSE;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_DriverData.ClientPortLock);

    valid = (g_ClientPortRefs[ClientIndex].ClientPort != NULL &&
             g_ClientPortRefs[ClientIndex].Disconnecting == 0);

    ExReleasePushLockShared(&g_DriverData.ClientPortLock);
    KeLeaveCriticalRegion();

    return valid;
}

BOOLEAN
ShadowStrikeClientHasCapability(
    _In_ LONG ClientIndex,
    _In_ SHADOWSTRIKE_CLIENT_CAPABILITY Capability
    )
{
    BOOLEAN hasCapability = FALSE;

    if (ClientIndex < 0 || ClientIndex >= SHADOWSTRIKE_MAX_CONNECTIONS) {
        return FALSE;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_DriverData.ClientPortLock);

    if (g_ClientPortRefs[ClientIndex].ClientPort != NULL) {
        hasCapability = ((g_ClientPortRefs[ClientIndex].Capabilities & (ULONG)Capability) != 0);
    }

    ExReleasePushLockShared(&g_DriverData.ClientPortLock);
    KeLeaveCriticalRegion();

    return hasCapability;
}

// ============================================================================
// MESSAGE BUFFER ALLOCATION WITH TRACKING
// ============================================================================

PVOID
ShadowStrikeAllocateMessageBuffer(
    _In_ ULONG Size
    )
{
    PSHADOWSTRIKE_MESSAGE_BUFFER_HEADER header = NULL;
    ULONG totalSize;
    ULONG lookasideMaxPayload;

    if (Size == 0) {
        return NULL;
    }

    //
    // Integer overflow check: sizeof(header) + Size must not wrap ULONG
    //
    if (Size > ((ULONG)-1) - sizeof(SHADOWSTRIKE_MESSAGE_BUFFER_HEADER)) {
        return NULL;
    }

    totalSize = sizeof(SHADOWSTRIKE_MESSAGE_BUFFER_HEADER) + Size;

    //
    // Calculate max payload that fits in lookaside
    //
    lookasideMaxPayload = SHADOWSTRIKE_MAX_MESSAGE_SIZE - sizeof(SHADOWSTRIKE_MESSAGE_BUFFER_HEADER);

    if (Size <= lookasideMaxPayload && g_DriverData.LookasideInitialized) {
        //
        // Allocate from lookaside list
        //
        header = (PSHADOWSTRIKE_MESSAGE_BUFFER_HEADER)
            ExAllocateFromNPagedLookasideList(&g_DriverData.MessageLookaside);

        if (header != NULL) {
            header->Magic = SHADOWSTRIKE_BUFFER_MAGIC;
            header->AllocationSource = SHADOWSTRIKE_ALLOC_LOOKASIDE;
            header->RequestedSize = Size;
            header->AllocatedSize = SHADOWSTRIKE_MAX_MESSAGE_SIZE;
            return (PVOID)(header + 1);
        }
    }

    //
    // Allocate from pool (either too large or lookaside failed)
    //
    header = (PSHADOWSTRIKE_MESSAGE_BUFFER_HEADER)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        totalSize,
        SHADOWSTRIKE_POOL_TAG
    );

    if (header != NULL) {
        header->Magic = SHADOWSTRIKE_BUFFER_MAGIC;
        header->AllocationSource = SHADOWSTRIKE_ALLOC_POOL;
        header->RequestedSize = Size;
        header->AllocatedSize = totalSize;
        return (PVOID)(header + 1);
    }

    return NULL;
}

VOID
ShadowStrikeFreeMessageBuffer(
    _In_opt_ PVOID Buffer
    )
{
    PSHADOWSTRIKE_MESSAGE_BUFFER_HEADER header;

    if (Buffer == NULL) {
        return;
    }

    //
    // Get header from buffer pointer
    //
    header = ((PSHADOWSTRIKE_MESSAGE_BUFFER_HEADER)Buffer) - 1;

    //
    // Validate magic to catch corruption
    //
    if (header->Magic != SHADOWSTRIKE_BUFFER_MAGIC) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] ERROR: Invalid buffer magic in free (0x%08X)\n",
                   header->Magic);
        //
        // Do not free - this is a bug indicator
        //
        return;
    }

    //
    // Clear magic to detect double-free
    //
    header->Magic = 0;

    //
    // Free based on allocation source
    //
    if (header->AllocationSource == SHADOWSTRIKE_ALLOC_LOOKASIDE) {
        if (g_DriverData.LookasideInitialized) {
            ExFreeToNPagedLookasideList(&g_DriverData.MessageLookaside, header);
        } else {
            //
            // Lookaside was deleted - fall back to pool free
            // This can happen during driver unload
            //
            ExFreePoolWithTag(header, SHADOWSTRIKE_POOL_TAG);
        }
    } else if (header->AllocationSource == SHADOWSTRIKE_ALLOC_POOL) {
        ExFreePoolWithTag(header, SHADOWSTRIKE_POOL_TAG);
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] ERROR: Unknown allocation source %u\n",
                   header->AllocationSource);
    }
}

// ============================================================================
// MESSAGE CONSTRUCTION HELPERS
// ============================================================================

VOID
ShadowStrikeInitMessageHeader(
    _Out_ PSHADOWSTRIKE_MESSAGE_HEADER Header,
    _In_ SHADOWSTRIKE_MESSAGE_TYPE MessageType,
    _In_ ULONG DataSize
    )
{
    LARGE_INTEGER timestamp;

    RtlZeroMemory(Header, sizeof(SHADOWSTRIKE_MESSAGE_HEADER));

    KeQuerySystemTime(&timestamp);

    Header->Magic = SHADOWSTRIKE_MESSAGE_MAGIC;
    Header->Version = SHADOWSTRIKE_PROTOCOL_VERSION;
    Header->MessageType = (UINT16)MessageType;
    Header->MessageId = SHADOWSTRIKE_NEXT_MESSAGE_ID();
    Header->TotalSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + DataSize;
    Header->DataSize = DataSize;
    Header->Timestamp = timestamp.QuadPart;
    Header->Flags = 0;
    Header->Reserved = 0;
}

NTSTATUS
ShadowStrikeBuildFileScanRequest(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ SHADOWSTRIKE_FILE_ACCESS_TYPE AccessType,
    _Out_ PSHADOWSTRIKE_MESSAGE_HEADER* Request,
    _Out_ PULONG RequestSize
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PSHADOWSTRIKE_MESSAGE_HEADER header = NULL;
    PSHADOWSTRIKE_FILE_SCAN_REQUEST scanRequest = NULL;
    ULONG totalSize;
    PWCHAR variableData;
    PEPROCESS process;
    WCHAR processImagePath[MAX_PROCESS_NAME_LENGTH];
    ULONG processNameLength = 0;
    PUNICODE_STRING processImageName = NULL;

    PAGED_CODE();

    *Request = NULL;
    *RequestSize = 0;

    UNREFERENCED_PARAMETER(FltObjects);

    //
    // Get file name
    //
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return status;
    }

    //
    // Get process image name
    //
    RtlZeroMemory(processImagePath, sizeof(processImagePath));
    process = IoThreadToProcess(Data->Thread);

    if (process != NULL) {
        status = SeLocateProcessImageName(process, &processImageName);
        if (NT_SUCCESS(status) && processImageName != NULL) {
            //
            // Extract just the file name portion using length arithmetic.
            // UNICODE_STRING is NOT guaranteed null-terminated â€” do NOT use wcslen.
            //
            USHORT totalChars = processImageName->Length / sizeof(WCHAR);
            USHORT lastSepIdx = 0;
            USHORT ci;
            BOOLEAN foundSep = FALSE;

            for (ci = 0; ci < totalChars; ci++) {
                if (processImageName->Buffer[ci] == L'\\' ||
                    processImageName->Buffer[ci] == L'/') {
                    lastSepIdx = ci + 1;
                    foundSep = TRUE;
                }
            }

            if (foundSep && lastSepIdx < totalChars) {
                processNameLength = (ULONG)(totalChars - lastSepIdx);
            } else {
                processNameLength = (ULONG)totalChars;
                lastSepIdx = 0;
            }

            if (processNameLength >= MAX_PROCESS_NAME_LENGTH) {
                processNameLength = MAX_PROCESS_NAME_LENGTH - 1;
            }
            RtlCopyMemory(processImagePath,
                          &processImageName->Buffer[lastSepIdx],
                          processNameLength * sizeof(WCHAR));

            ExFreePool(processImageName);
        }
    }

    //
    // Calculate total message size
    //
    totalSize = SHADOWSTRIKE_FILE_SCAN_REQUEST_SIZE(
        nameInfo->Name.Length / sizeof(WCHAR),
        processNameLength
    );

    //
    // Cap total size
    //
    if (totalSize > SHADOWSTRIKE_MAX_MESSAGE_SIZE) {
        FltReleaseFileNameInformation(nameInfo);
        return STATUS_BUFFER_OVERFLOW;
    }

    //
    // Allocate message buffer
    //
    header = (PSHADOWSTRIKE_MESSAGE_HEADER)ShadowStrikeAllocateMessageBuffer(totalSize);
    if (header == NULL) {
        FltReleaseFileNameInformation(nameInfo);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize header
    //
    ShadowStrikeInitMessageHeader(
        header,
        (AccessType == ShadowStrikeAccessExecute) ?
            ShadowStrikeMessageFileScanOnExecute : ShadowStrikeMessageFileScanOnOpen,
        totalSize - sizeof(SHADOWSTRIKE_MESSAGE_HEADER)
    );

    //
    // Fill scan request
    //
    scanRequest = (PSHADOWSTRIKE_FILE_SCAN_REQUEST)((PUCHAR)header + sizeof(SHADOWSTRIKE_MESSAGE_HEADER));

    scanRequest->MessageId = header->MessageId;
    scanRequest->AccessType = (UINT8)AccessType;
    scanRequest->Disposition = 0;
    scanRequest->Priority = (UINT8)ShadowStrikePriorityNormal;
    scanRequest->RequiresReply = 1;
    scanRequest->ProcessId = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();
    scanRequest->ThreadId = (UINT32)(ULONG_PTR)PsGetCurrentThreadId();

    //
    // Get parent process ID
    //
    if (process != NULL) {
        scanRequest->ParentProcessId = (UINT32)(ULONG_PTR)PsGetProcessInheritedFromUniqueProcessId(process);
    } else {
        scanRequest->ParentProcessId = 0;
    }

    //
    // Get session ID from callback data
    //
    {
        ULONG sessionId = 0;
        FltGetRequestorSessionId(Data, &sessionId);
        scanRequest->SessionId = sessionId;
    }

    scanRequest->FileSize = 0;  // Set in post-create if needed
    scanRequest->FileAttributes = 0;
    //
    // Create-only parameters: Data->Iopb->Parameters is a union whose
    // SecurityContext / ShareAccess / Options members are only valid for
    // IRP_MJ_CREATE.  When this builder is invoked from a SetInformation
    // post-op (Delete/Rename notifications), the underlying parameter slot
    // is SetFileInformation and the "Create" view is garbage — dereferencing
    // SecurityContext was crashing with KMODE_EXCEPTION_NOT_HANDLED (0x3B)
    // at a small bogus pointer.  Guard the access so the optional metadata
    // is only filled in for genuine Create callbacks.
    //
    if (Data->Iopb != NULL &&
        Data->Iopb->MajorFunction == IRP_MJ_CREATE) {
        PIO_SECURITY_CONTEXT secCtx =
            Data->Iopb->Parameters.Create.SecurityContext;
        scanRequest->DesiredAccess =
            (secCtx != NULL) ? secCtx->DesiredAccess : 0;
        scanRequest->ShareAccess  = Data->Iopb->Parameters.Create.ShareAccess;
        scanRequest->CreateOptions = Data->Iopb->Parameters.Create.Options;
    } else {
        scanRequest->DesiredAccess = 0;
        scanRequest->ShareAccess   = 0;
        scanRequest->CreateOptions = 0;
    }
    scanRequest->VolumeSerial = 0;
    scanRequest->FileId = 0;
    scanRequest->IsDirectory = FALSE;
    scanRequest->IsNetworkFile = FALSE;
    scanRequest->IsRemovableMedia = FALSE;
    scanRequest->HasADS = FALSE;
    scanRequest->PathLength = (UINT16)(nameInfo->Name.Length / sizeof(WCHAR));
    scanRequest->ProcessNameLength = (UINT16)processNameLength;

    //
    // Copy variable-length data
    //
    variableData = (PWCHAR)((PUCHAR)scanRequest + sizeof(SHADOWSTRIKE_FILE_SCAN_REQUEST));

    if (nameInfo->Name.Length > 0) {
        RtlCopyMemory(variableData, nameInfo->Name.Buffer, nameInfo->Name.Length);
        variableData += nameInfo->Name.Length / sizeof(WCHAR);
    }

    if (processNameLength > 0) {
        RtlCopyMemory(variableData, processImagePath, processNameLength * sizeof(WCHAR));
    }

    FltReleaseFileNameInformation(nameInfo);

    *Request = header;
    *RequestSize = totalSize;

    return STATUS_SUCCESS;
}

// ============================================================================
// CLIENT VERIFICATION
// ============================================================================

/**
 * @brief Case-insensitive substring search in a counted wide string.
 *
 * Searches within Source (Length chars) for Needle (null-terminated).
 * Returns TRUE if found, FALSE otherwise. Does NOT require null-termination
 * of Source â€” operates on character count only.
 */
static BOOLEAN
ShadowStrikepFindSubstringNoCase(
    _In_reads_(SourceLengthChars) PCWCH Source,
    _In_ USHORT SourceLengthChars,
    _In_ PCWSTR Needle
    )
{
    USHORT needleLen = 0;
    USHORT i;
    USHORT j;
    WCHAR sc;
    WCHAR nc;

    //
    // Calculate needle length
    //
    while (Needle[needleLen] != L'\0') {
        needleLen++;
    }

    if (needleLen == 0 || needleLen > SourceLengthChars) {
        return FALSE;
    }

    for (i = 0; i <= SourceLengthChars - needleLen; i++) {
        BOOLEAN match = TRUE;

        for (j = 0; j < needleLen; j++) {
            sc = Source[i + j];
            nc = Needle[j];

            //
            // Lowercase ASCII for comparison
            //
            if (sc >= L'A' && sc <= L'Z') { sc += 32; }
            if (nc >= L'A' && nc <= L'Z') { nc += 32; }

            if (sc != nc) {
                match = FALSE;
                break;
            }
        }

        if (match) {
            return TRUE;
        }
    }

    return FALSE;
}

/**
 * @brief Extract filename from a counted wide string path.
 *
 * Returns pointer into Source at the last path separator + 1,
 * and sets OutLength to the remaining character count.
 * Does NOT require null-termination.
 */
static PCWCH
ShadowStrikepExtractFilename(
    _In_reads_(SourceLengthChars) PCWCH Source,
    _In_ USHORT SourceLengthChars,
    _Out_ PUSHORT OutLengthChars
    )
{
    USHORT lastSep = 0;
    USHORT i;
    BOOLEAN foundSep = FALSE;

    for (i = 0; i < SourceLengthChars; i++) {
        if (Source[i] == L'\\' || Source[i] == L'/') {
            lastSep = i + 1;
            foundSep = TRUE;
        }
    }

    if (foundSep && lastSep < SourceLengthChars) {
        *OutLengthChars = SourceLengthChars - lastSep;
        return &Source[lastSep];
    }

    *OutLengthChars = SourceLengthChars;
    return Source;
}

/**
 * @brief Compute FNV-1a hash of a wide character buffer.
 *
 * Produces a deterministic 32-bit hash for tracking purposes.
 * Not cryptographic â€” used for fast image path fingerprinting.
 */
static ULONG
ShadowStrikepFnv1aHashW(
    _In_reads_(LengthChars) PCWCH Buffer,
    _In_ USHORT LengthChars
    )
{
    ULONG hash = 0x811C9DC5u;  // FNV-1a offset basis
    ULONG i;
    PUCHAR bytes;
    ULONG byteLen;

    bytes = (PUCHAR)Buffer;
    byteLen = (ULONG)LengthChars * sizeof(WCHAR);

    for (i = 0; i < byteLen; i++) {
        hash ^= bytes[i];
        hash *= 0x01000193u;  // FNV-1a prime
    }

    return hash;
}

/**
 * @brief Verify a connecting user-mode client process.
 *
 * Enterprise verification flow:
 * 1. Obtain full image path via SeLocateProcessImageName.
 * 2. Extract filename and perform case-insensitive match against
 *    the expected service executable name (SHADOWSTRIKE_SERVICE_EXECUTABLE).
 * 3. Verify the process token belongs to LocalSystem (S-1-5-18).
 * 4. Compute FNV-1a hash of the full image path for audit trail.
 *
 * A client must pass BOTH the filename match AND the SYSTEM token
 * check to receive full (ShadowStrikeCapServiceDefault) capabilities.
 * All other clients receive ShadowStrikeCapMinimal.
 *
 * @param ClientProcessId  Process ID of the connecting client.
 * @param Capabilities     Receives the granted capability bitmask.
 * @param ImageHash        Receives 32-byte hash output (FNV-1a in first 4 bytes, zero-padded).
 *
 * @return STATUS_SUCCESS on completion (even if verification fails â€” the
 *         Capabilities output distinguishes verified vs minimal).
 */
NTSTATUS
ShadowStrikeVerifyClient(
    _In_ HANDLE ClientProcessId,
    _Out_ PULONG Capabilities,
    _Out_writes_bytes_(32) PUCHAR ImageHash
    )
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PUNICODE_STRING imageName = NULL;
    BOOLEAN nameMatch = FALSE;
    BOOLEAN isSystem = FALSE;
    ULONG hash;
    USHORT charCount = 0;
    PCWCH filename = NULL;
    USHORT filenameLen = 0;
    USHORT expectedLen;
    PACCESS_TOKEN token = NULL;
    PTOKEN_USER tokenUser = NULL;
    PSID systemSid = NULL;

    //
    // Well-known LocalSystem SID: S-1-5-18
    //
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    PAGED_CODE();

    *Capabilities = (ULONG)ShadowStrikeCapMinimal;
    RtlZeroMemory(ImageHash, 32);

    //
    // Step 1: Get process object.
    //
    status = PsLookupProcessByProcessId(ClientProcessId, &process);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] VerifyClient[PID=%p] DENY: "
                   "PsLookupProcessByProcessId failed 0x%08X\n",
                   ClientProcessId, status);
        return status;
    }

    //
    // Step 2: Get process image name.
    //
    status = SeLocateProcessImageName(process, &imageName);
    if (!NT_SUCCESS(status) || imageName == NULL ||
        imageName->Buffer == NULL || imageName->Length == 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] VerifyClient[PID=%p] DENY: "
                   "SeLocateProcessImageName failed status=0x%08X imageName=%p\n",
                   ClientProcessId, status, imageName);
        if (imageName) {
            ExFreePool(imageName);
        }
        ObDereferenceObject(process);
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }

    //
    // Step 3: Verify image filename matches expected service executable.
    // Use length-safe comparison — no wcsstr, no null-termination assumption.
    //
    charCount = imageName->Length / sizeof(WCHAR);
    filename = ShadowStrikepExtractFilename(imageName->Buffer, charCount, &filenameLen);

    //
    // Calculate expected executable name length.
    //
    expectedLen = 0;
    while (SHADOWSTRIKE_SERVICE_EXECUTABLE[expectedLen] != L'\0') {
        expectedLen++;
    }

    //
    // Case-insensitive filename comparison.
    //
    if (filenameLen == expectedLen) {
        USHORT ci;
        nameMatch = TRUE;
        for (ci = 0; ci < filenameLen; ci++) {
            WCHAR fc = filename[ci];
            WCHAR ec = SHADOWSTRIKE_SERVICE_EXECUTABLE[ci];

            if (fc >= L'A' && fc <= L'Z') { fc += 32; }
            if (ec >= L'A' && ec <= L'Z') { ec += 32; }

            if (fc != ec) {
                nameMatch = FALSE;
                break;
            }
        }
    }

    //
    // Compute FNV-1a hash of full image path for audit tracking.
    //
    hash = ShadowStrikepFnv1aHashW(imageName->Buffer, charCount);
    RtlCopyMemory(ImageHash, &hash, sizeof(hash));

    if (!nameMatch) {
        //
        // ACTIONABLE LOG: emit the full NT path so post-mortem can compare
        // it against SHADOWSTRIKE_SERVICE_EXECUTABLE byte-for-byte. %wZ is
        // safe at PASSIVE_LEVEL on a kernel-owned UNICODE_STRING.
        //
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] VerifyClient[PID=%p] DENY name: "
                   "got=\"%wZ\" expected=\"%ws\" filenameLen=%u expectedLen=%u\n",
                   ClientProcessId, imageName, SHADOWSTRIKE_SERVICE_EXECUTABLE,
                   (UINT)filenameLen, (UINT)expectedLen);
    }

    ExFreePool(imageName);
    imageName = NULL;

    //
    // Step 4: Verify process is running as LocalSystem (S-1-5-18).
    // Every failure site below logs an explicit DENY token: line so a
    // post-mortem can identify which sub-check failed without speculation.
    //
    token = PsReferencePrimaryToken(process);
    if (token == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] VerifyClient[PID=%p] DENY token: "
                   "PsReferencePrimaryToken returned NULL\n",
                   ClientProcessId);
    } else {
        NTSTATUS qstatus = SeQueryInformationToken(token, TokenUser, (PVOID*)&tokenUser);
        if (!NT_SUCCESS(qstatus) || tokenUser == NULL) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[ShadowStrike] VerifyClient[PID=%p] DENY token: "
                       "SeQueryInformationToken failed 0x%08X tokenUser=%p\n",
                       ClientProcessId, qstatus, tokenUser);
        } else {
            NTSTATUS sidStatus = CppAllocateAndInitializeSid(
                &ntAuthority,
                1,
                SECURITY_LOCAL_SYSTEM_RID,
                &systemSid
            );

            if (!NT_SUCCESS(sidStatus) || systemSid == NULL) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                           "[ShadowStrike] VerifyClient[PID=%p] DENY token: "
                           "BuildSystemSid failed 0x%08X\n",
                           ClientProcessId, sidStatus);
            } else {
                if (RtlEqualSid(tokenUser->User.Sid, systemSid)) {
                    isSystem = TRUE;
                } else {
                    //
                    // ACTIONABLE LOG: dump the first 8 raw bytes of the SID
                    // structure so post-mortem can identify which non-SYSTEM
                    // identity the connecting process is using (network
                    // service, local service, an admin account, etc.).
                    //
                    PUCHAR observed = (PUCHAR)tokenUser->User.Sid;
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                               "[ShadowStrike] VerifyClient[PID=%p] DENY token: "
                               "user-SID is NOT S-1-5-18; first bytes "
                               "%02X %02X %02X %02X %02X %02X %02X %02X\n",
                               ClientProcessId,
                               observed[0], observed[1], observed[2], observed[3],
                               observed[4], observed[5], observed[6], observed[7]);
                }
                ExFreePoolWithTag(systemSid, COMMPORT_SID_POOL_TAG);
                systemSid = NULL;
            }

            ExFreePool(tokenUser);
            tokenUser = NULL;
        }
        PsDereferencePrimaryToken(token);
        token = NULL;
    }

    ObDereferenceObject(process);

    //
    // Step 5: Grant full capabilities only if BOTH checks pass. Both branches
    // log conclusively so DbgView gives a single line of ground truth.
    //
    if (nameMatch && isSystem) {
        *Capabilities = (ULONG)ShadowStrikeCapServiceDefault;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[ShadowStrike] Client VERIFIED: PID=%p caps=0x%08X\n",
                   ClientProcessId, *Capabilities);
    } else {
        *Capabilities = (ULONG)ShadowStrikeCapMinimal;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Client REJECTED: PID=%p nameMatch=%u isSystem=%u\n",
                   ClientProcessId, (UINT)nameMatch, (UINT)isSystem);
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// PROTECTED PROCESS MANAGEMENT
// ============================================================================

NTSTATUS
ShadowStrikeRegisterProtectedProcess(
    _In_ ULONG ProcessId,
    _In_ ULONG ProtectionFlags,
    _In_opt_ PCWSTR ProcessName
    )
{
    PSHADOWSTRIKE_PROTECTED_PROCESS_ENTRY entry = NULL;
    PLIST_ENTRY listEntry;
    BOOLEAN alreadyExists = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    PAGED_CODE();

    //
    // Validate process ID
    //
    if (ProcessId == 0 || ProcessId == 4) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Pre-allocate entry BEFORE acquiring lock to minimize hold time
    //
    entry = (PSHADOWSTRIKE_PROTECTED_PROCESS_ENTRY)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(SHADOWSTRIKE_PROTECTED_PROCESS_ENTRY),
        SHADOWSTRIKE_POOL_TAG
    );

    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    entry->ProcessId = ProcessId;
    entry->ProtectionFlags = ProtectionFlags;

    if (ProcessName != NULL) {
        SIZE_T nameLen = wcsnlen(ProcessName, MAX_PROCESS_NAME_LENGTH);
        if (nameLen >= MAX_PROCESS_NAME_LENGTH) {
            nameLen = MAX_PROCESS_NAME_LENGTH - 1;
        }
        RtlCopyMemory(entry->ProcessName, ProcessName, nameLen * sizeof(WCHAR));
        entry->ProcessName[nameLen] = L'\0';
    }

    //
    // Perform limit check + existence check + insertion under ONE exclusive lock
    // to eliminate the TOCTOU between separate lock acquisitions.
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_DriverData.ProtectedProcessLock);

    //
    // Check limit under lock
    //
    if (g_DriverData.ProtectedProcessCount >= 64) {
        status = SHADOWSTRIKE_ERROR_MAX_PROTECTED;
        goto Cleanup;
    }

    //
    // Check if already protected under same lock
    //
    for (listEntry = g_DriverData.ProtectedProcessList.Flink;
         listEntry != &g_DriverData.ProtectedProcessList;
         listEntry = listEntry->Flink) {

        PSHADOWSTRIKE_PROTECTED_PROCESS_ENTRY existing =
            CONTAINING_RECORD(listEntry, SHADOWSTRIKE_PROTECTED_PROCESS_ENTRY, ListEntry);
        if (existing->ProcessId == ProcessId) {
            alreadyExists = TRUE;
            break;
        }
    }

    if (alreadyExists) {
        status = STATUS_OBJECTID_EXISTS;
        goto Cleanup;
    }

    //
    // Insert â€” still under the same exclusive lock
    //
    InsertTailList(&g_DriverData.ProtectedProcessList, &entry->ListEntry);
    InterlockedIncrement(&g_DriverData.ProtectedProcessCount);

    ExReleasePushLockExclusive(&g_DriverData.ProtectedProcessLock);
    KeLeaveCriticalRegion();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Protected process registered: PID=%u, flags=0x%08X\n",
               ProcessId, ProtectionFlags);

    return STATUS_SUCCESS;

Cleanup:
    ExReleasePushLockExclusive(&g_DriverData.ProtectedProcessLock);
    KeLeaveCriticalRegion();
    ExFreePoolWithTag(entry, SHADOWSTRIKE_POOL_TAG);
    return status;
}

NTSTATUS
ShadowStrikeUnregisterProtectedProcess(
    _In_ ULONG ProcessId
    )
{
    PLIST_ENTRY listEntry;
    PSHADOWSTRIKE_PROTECTED_PROCESS_ENTRY entry = NULL;
    PSHADOWSTRIKE_PROTECTED_PROCESS_ENTRY foundEntry = NULL;

    PAGED_CODE();

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_DriverData.ProtectedProcessLock);

    for (listEntry = g_DriverData.ProtectedProcessList.Flink;
         listEntry != &g_DriverData.ProtectedProcessList;
         listEntry = listEntry->Flink) {

        entry = CONTAINING_RECORD(listEntry, SHADOWSTRIKE_PROTECTED_PROCESS_ENTRY, ListEntry);
        if (entry->ProcessId == ProcessId) {
            foundEntry = entry;
            RemoveEntryList(&entry->ListEntry);
            InterlockedDecrement(&g_DriverData.ProtectedProcessCount);
            break;
        }
    }

    ExReleasePushLockExclusive(&g_DriverData.ProtectedProcessLock);
    KeLeaveCriticalRegion();

    if (foundEntry != NULL) {
        ExFreePoolWithTag(foundEntry, SHADOWSTRIKE_POOL_TAG);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[ShadowStrike] Protected process unregistered: PID=%u\n", ProcessId);
        return STATUS_SUCCESS;
    }

    return SHADOWSTRIKE_ERROR_NOT_PROTECTED;
}
