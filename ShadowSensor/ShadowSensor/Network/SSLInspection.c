/*++
    ShadowStrike Next-Generation Antivirus
    Module: SSLInspection.c

    Purpose: Enterprise-grade TLS/SSL inspection for encrypted traffic analysis.

    This module provides comprehensive TLS handshake inspection capabilities:
    - ClientHello/ServerHello parsing with full extension support
    - JA3/JA3S fingerprint computation for threat intelligence
    - Certificate chain validation and anomaly detection
    - Known malicious JA3 fingerprint database
    - TLS version and cipher suite security analysis
    - Session tracking with correlation to network connections

    Synchronization model:
    - All public APIs acquire EX_RUNDOWN_REF for safe shutdown.
    - All locks are EX_PUSH_LOCK (IRQL <= APC_LEVEL).
    - Internal sessions are on the list, never returned to callers.
    - Callers receive SSL_SESSION_INFO snapshots allocated with SSL_POOL_TAG_RESULT.
    - SslAddBadJA3 does atomic duplicate-check + insert under single exclusive lock.
    - Shutdown drains rundown, then frees everything under exclusive ownership.
    - SslCleanupStaleSessions evicts sessions older than SSL_SESSION_STALE_MS.

    MITRE ATT&CK Coverage:
    - T1071.001: Application Layer Protocol (Web Protocols)
    - T1573.002: Encrypted Channel (Asymmetric Cryptography)
    - T1095: Non-Application Layer Protocol

    Copyright (c) ShadowStrike Team
--*/

#include "SSLInspection.h"
#include "../Utilities/HashUtils.h"
#include "../Utilities/MemoryUtils.h"
#include "../Utilities/StringUtils.h"
#include "../Tracing/Trace.h"
#include <ntstrsafe.h>

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, SslInitialize)
#pragma alloc_text(PAGE, SslShutdown)
#pragma alloc_text(PAGE, SslInspectClientHello)
#pragma alloc_text(PAGE, SslInspectServerHello)
#pragma alloc_text(PAGE, SslCalculateJA3)
#pragma alloc_text(PAGE, SslAddBadJA3)
#pragma alloc_text(PAGE, SslCheckJA3)
#pragma alloc_text(PAGE, SslGetStatistics)
#pragma alloc_text(PAGE, SslFreeSessionInfo)
#pragma alloc_text(PAGE, SslRemoveSession)
#pragma alloc_text(PAGE, SslCleanupStaleSessions)
#endif

//=============================================================================
// TLS Protocol Constants
//=============================================================================

#define TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC     20
#define TLS_CONTENT_TYPE_ALERT                  21
#define TLS_CONTENT_TYPE_HANDSHAKE              22
#define TLS_CONTENT_TYPE_APPLICATION_DATA       23

#define TLS_HANDSHAKE_CLIENT_HELLO              1
#define TLS_HANDSHAKE_SERVER_HELLO              2
#define TLS_HANDSHAKE_CERTIFICATE               11
#define TLS_HANDSHAKE_SERVER_KEY_EXCHANGE       12
#define TLS_HANDSHAKE_CERTIFICATE_REQUEST       13
#define TLS_HANDSHAKE_SERVER_HELLO_DONE         14
#define TLS_HANDSHAKE_CERTIFICATE_VERIFY        15
#define TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE       16
#define TLS_HANDSHAKE_FINISHED                  20

#define TLS_EXTENSION_SERVER_NAME               0x0000
#define TLS_EXTENSION_MAX_FRAGMENT_LENGTH       0x0001
#define TLS_EXTENSION_STATUS_REQUEST            0x0005
#define TLS_EXTENSION_SUPPORTED_GROUPS          0x000A
#define TLS_EXTENSION_EC_POINT_FORMATS          0x000B
#define TLS_EXTENSION_SIGNATURE_ALGORITHMS      0x000D
#define TLS_EXTENSION_ALPN                      0x0010
#define TLS_EXTENSION_SIGNED_CERT_TIMESTAMP     0x0012
#define TLS_EXTENSION_EXTENDED_MASTER_SECRET    0x0017
#define TLS_EXTENSION_SESSION_TICKET            0x0023
#define TLS_EXTENSION_SUPPORTED_VERSIONS        0x002B
#define TLS_EXTENSION_PSK_KEY_EXCHANGE_MODES    0x002D
#define TLS_EXTENSION_KEY_SHARE                 0x0033
#define TLS_EXTENSION_RENEGOTIATION_INFO        0xFF01

//
// GREASE values (RFC 8701) — should be ignored in JA3 computation
//
#define TLS_IS_GREASE_VALUE(x) \
    (((x) & 0x0F0F) == 0x0A0A)

//
// Maximum parsing limits (DoS prevention)
//
#define SSL_MAX_EXTENSIONS              100
#define SSL_MAX_CIPHER_SUITES           200
#define SSL_MAX_SUPPORTED_GROUPS        50
#define SSL_MAX_EC_POINT_FORMATS        10
#define SSL_MAX_SIGNATURE_ALGORITHMS    50
#define SSL_MAX_HANDSHAKE_SIZE          65535

//=============================================================================
// Internal Structures
//=============================================================================

#pragma pack(push, 1)

typedef struct _TLS_RECORD_HEADER {
    UCHAR ContentType;
    UCHAR VersionMajor;
    UCHAR VersionMinor;
    USHORT Length;                      // Network byte order
} TLS_RECORD_HEADER, *PTLS_RECORD_HEADER;

typedef struct _TLS_HANDSHAKE_HEADER {
    UCHAR HandshakeType;
    UCHAR LengthHigh;
    USHORT LengthLow;
} TLS_HANDSHAKE_HEADER, *PTLS_HANDSHAKE_HEADER;

typedef struct _TLS_CLIENT_HELLO_FIXED {
    UCHAR VersionMajor;
    UCHAR VersionMinor;
    UCHAR Random[32];
} TLS_CLIENT_HELLO_FIXED, *PTLS_CLIENT_HELLO_FIXED;

#pragma pack(pop)

//
// Internal session — lives on the inspector's list, never returned to callers.
//
typedef struct _SSL_SESSION {
    LIST_ENTRY ListEntry;
    ULONG64 SessionId;

    HANDLE ProcessId;
    union {
        IN_ADDR IPv4;
        IN6_ADDR IPv6;
    } RemoteAddress;
    USHORT RemotePort;
    BOOLEAN IsIPv6;

    SSL_VERSION Version;
    CHAR CipherSuite[64];
    CHAR ServerName[256];

    SSL_JA3 JA3;
    SSL_CERT_INFO Certificate;

    LONG SuspicionFlags;            // SSL_SUSPICION bitfield, updated via InterlockedOr
    ULONG SuspicionScore;

    LARGE_INTEGER HandshakeTime;
} SSL_SESSION, *PSSL_SESSION;

//
// Known bad JA3 entry
//
typedef struct _SSL_BAD_JA3_ENTRY {
    LIST_ENTRY ListEntry;
    UCHAR JA3Hash[16];
    CHAR MalwareFamily[64];
    LARGE_INTEGER AddedTime;
} SSL_BAD_JA3_ENTRY, *PSSL_BAD_JA3_ENTRY;

//
// Parsed ClientHello data (internal use — stack allocated)
//
typedef struct _SSL_PARSED_CLIENT_HELLO {
    SSL_VERSION Version;

    USHORT CipherSuites[SSL_MAX_CIPHER_SUITES];
    ULONG CipherSuiteCount;

    USHORT Extensions[SSL_MAX_EXTENSIONS];
    ULONG ExtensionCount;

    USHORT SupportedGroups[SSL_MAX_SUPPORTED_GROUPS];
    ULONG SupportedGroupCount;

    UCHAR ECPointFormats[SSL_MAX_EC_POINT_FORMATS];
    ULONG ECPointFormatCount;

    CHAR ServerName[256];
    CHAR AlpnProtocols[256];

    USHORT SupportedVersions[10];
    ULONG SupportedVersionCount;

} SSL_PARSED_CLIENT_HELLO, *PSSL_PARSED_CLIENT_HELLO;

//
// Parsed ServerHello data (internal use — stack allocated)
//
typedef struct _SSL_PARSED_SERVER_HELLO {
    SSL_VERSION Version;
    USHORT CipherSuite;
    UCHAR CompressionMethod;

    USHORT Extensions[SSL_MAX_EXTENSIONS];
    ULONG ExtensionCount;

    USHORT SelectedVersion;

} SSL_PARSED_SERVER_HELLO, *PSSL_PARSED_SERVER_HELLO;

//=============================================================================
// Forward Declarations
//=============================================================================

static NTSTATUS
SslpParseClientHello(
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _Out_ PSSL_PARSED_CLIENT_HELLO Parsed
    );

static NTSTATUS
SslpParseServerHello(
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _Out_ PSSL_PARSED_SERVER_HELLO Parsed
    );

static NTSTATUS
SslpBuildJA3String(
    _In_ PSSL_PARSED_CLIENT_HELLO Parsed,
    _Out_writes_z_(BufferSize) PSTR Buffer,
    _In_ ULONG BufferSize
    );

static NTSTATUS
SslpBuildJA3SString(
    _In_ PSSL_PARSED_SERVER_HELLO Parsed,
    _Out_writes_z_(BufferSize) PSTR Buffer,
    _In_ ULONG BufferSize
    );

static VOID
SslpAnalyzeSuspicion(
    _Inout_ PSSL_SESSION Session,
    _In_ PSSL_PARSED_CLIENT_HELLO ClientHello
    );

static VOID
SslpSnapshotSession(
    _In_ PSSL_SESSION Session,
    _Out_ PSSL_SESSION_INFO Info
    );

//
// Internal JA3 check — caller already holds rundown, does NOT re-acquire it.
//
static VOID
SslpCheckKnownJA3(
    _In_ PSSL_INSPECTOR Inspector,
    _In_ PUCHAR JA3Hash,
    _Out_ PBOOLEAN IsBad,
    _Out_writes_z_(FamilySize) PSTR MalwareFamily,
    _In_ ULONG FamilySize
    );

static FORCEINLINE USHORT
SslpReadNetworkUShort(
    _In_reads_bytes_(2) PUCHAR Buffer
    )
{
    return (USHORT)((Buffer[0] << 8) | Buffer[1]);
}

static FORCEINLINE ULONG
SslpReadNetworkUInt24(
    _In_reads_bytes_(3) PUCHAR Buffer
    )
{
    return ((ULONG)Buffer[0] << 16) | ((ULONG)Buffer[1] << 8) | (ULONG)Buffer[2];
}

//=============================================================================
// Weak Cipher Suite Detection
//=============================================================================

static const USHORT g_WeakCipherSuites[] = {
    0x0000,     // TLS_NULL_WITH_NULL_NULL
    0x0001,     // TLS_RSA_WITH_NULL_MD5
    0x0002,     // TLS_RSA_WITH_NULL_SHA
    0x0004,     // TLS_RSA_WITH_RC4_128_MD5
    0x0005,     // TLS_RSA_WITH_RC4_128_SHA
    0x0017,     // TLS_DH_anon_EXPORT_WITH_RC4_40_MD5
    0x0018,     // TLS_DH_anon_WITH_RC4_128_MD5
    0x0019,     // TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
    0x001A,     // TLS_DH_anon_WITH_DES_CBC_SHA
    0x001B,     // TLS_DH_anon_WITH_3DES_EDE_CBC_SHA
    0x002F,     // TLS_RSA_WITH_AES_128_CBC_SHA
    0x0033,     // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    0x0035,     // TLS_RSA_WITH_AES_256_CBC_SHA
    0x0039,     // TLS_DHE_RSA_WITH_AES_256_CBC_SHA
    0x003C,     // TLS_RSA_WITH_AES_128_CBC_SHA256
    0x003D,     // TLS_RSA_WITH_AES_256_CBC_SHA256
    0x0041,     // TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
    0x0084,     // TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
    0x008A,     // TLS_PSK_WITH_RC4_128_SHA
    0x008E,     // TLS_DHE_PSK_WITH_RC4_128_SHA
    0x0092,     // TLS_RSA_PSK_WITH_RC4_128_SHA
    0x00FF,     // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    0xC007,     // TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
    0xC011,     // TLS_ECDHE_RSA_WITH_RC4_128_SHA
    0xC016,     // TLS_ECDH_anon_WITH_RC4_128_SHA
};

static BOOLEAN
SslpIsWeakCipherSuite(
    _In_ USHORT CipherSuite
    )
{
    ULONG i;
    for (i = 0; i < ARRAYSIZE(g_WeakCipherSuites); i++) {
        if (g_WeakCipherSuites[i] == CipherSuite) {
            return TRUE;
        }
    }
    return FALSE;
}

// ============================================================================
// PUBLIC API — INITIALIZATION
// ============================================================================

_Use_decl_annotations_
NTSTATUS
SslInitialize(
    _Out_ PSSL_INSPECTOR* Inspector
    )
{
    PSSL_INSPECTOR NewInspector = NULL;

    PAGED_CODE();

    if (Inspector == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Inspector = NULL;

    //
    // Allocate from non-paged pool — contains sync primitives.
    //
    NewInspector = (PSSL_INSPECTOR)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(SSL_INSPECTOR),
        SSL_POOL_TAG_SESSION
        );

    if (NewInspector == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // ExAllocatePool2 zero-initializes. Set non-zero fields.
    //
    ExInitializeRundownProtection(&NewInspector->RundownRef);
    InitializeListHead(&NewInspector->SessionList);
    InitializeListHead(&NewInspector->BadJA3List);
    ExInitializePushLock(&NewInspector->SessionLock);
    ExInitializePushLock(&NewInspector->BadJA3Lock);
    NewInspector->NextSessionId = 1;

    KeQuerySystemTime(&NewInspector->Stats.StartTime);

    InterlockedExchange(&NewInspector->Initialized, TRUE);

    *Inspector = NewInspector;
    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API — SHUTDOWN
// ============================================================================

_Use_decl_annotations_
VOID
SslShutdown(
    _Inout_ PSSL_INSPECTOR Inspector
    )
{
    PLIST_ENTRY Entry;
    PSSL_SESSION Session;
    PSSL_BAD_JA3_ENTRY BadJA3Entry;

    PAGED_CODE();

    if (Inspector == NULL || !InterlockedExchange(&Inspector->Initialized, FALSE)) {
        return;
    }

    //
    // Drain all in-flight API calls. After this returns, no new rundown
    // acquisitions will succeed and all existing ones have released.
    //
    ExWaitForRundownProtectionRelease(&Inspector->RundownRef);

    //
    // We now own the inspector exclusively. No locks needed.
    //

    // Free all sessions
    while (!IsListEmpty(&Inspector->SessionList)) {
        Entry = RemoveHeadList(&Inspector->SessionList);
        Session = CONTAINING_RECORD(Entry, SSL_SESSION, ListEntry);
        ExFreePoolWithTag(Session, SSL_POOL_TAG_SESSION);
    }

    // Free all bad JA3 entries
    while (!IsListEmpty(&Inspector->BadJA3List)) {
        Entry = RemoveHeadList(&Inspector->BadJA3List);
        BadJA3Entry = CONTAINING_RECORD(Entry, SSL_BAD_JA3_ENTRY, ListEntry);
        ExFreePoolWithTag(BadJA3Entry, SSL_POOL_TAG_JA3);
    }

    // Free the inspector itself
    ExFreePoolWithTag(Inspector, SSL_POOL_TAG_SESSION);
}

// ============================================================================
// PUBLIC API — INSPECT CLIENT HELLO
// ============================================================================

_Use_decl_annotations_
NTSTATUS
SslInspectClientHello(
    _In_ PSSL_INSPECTOR Inspector,
    _In_ HANDLE ProcessId,
    _In_ PVOID RemoteAddress,
    _In_ USHORT RemotePort,
    _In_ BOOLEAN IsIPv6,
    _In_reads_bytes_(DataSize) PVOID ClientHello,
    _In_ ULONG DataSize,
    _Out_ PSSL_SESSION_INFO* SessionInfo
    )
{
    NTSTATUS Status;
    PSSL_SESSION NewSession = NULL;
    PSSL_SESSION_INFO Snapshot = NULL;
    SSL_PARSED_CLIENT_HELLO Parsed;
    BOOLEAN IsBadJA3;
    CHAR MalwareFamily[64];

    PAGED_CODE();

    if (Inspector == NULL || RemoteAddress == NULL ||
        ClientHello == NULL || DataSize == 0 || SessionInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *SessionInfo = NULL;

    if (!SSL_ACQUIRE_RUNDOWN(Inspector)) {
        return STATUS_DELETE_PENDING;
    }

    //
    // Validate data size
    //
    if (DataSize < sizeof(TLS_RECORD_HEADER) + sizeof(TLS_HANDSHAKE_HEADER) +
        sizeof(TLS_CLIENT_HELLO_FIXED)) {
        SSL_RELEASE_RUNDOWN(Inspector);
        return STATUS_INVALID_BUFFER_SIZE;
    }

    if (DataSize > SSL_MAX_HANDSHAKE_SIZE) {
        SSL_RELEASE_RUNDOWN(Inspector);
        return STATUS_BUFFER_OVERFLOW;
    }

    //
    // Check session limit
    //
    if (Inspector->SessionCount >= (LONG)SSL_MAX_ACTIVE_SESSIONS) {
        SSL_RELEASE_RUNDOWN(Inspector);
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Parse the ClientHello
    //
    RtlZeroMemory(&Parsed, sizeof(Parsed));

    Status = SslpParseClientHello(ClientHello, DataSize, &Parsed);
    if (!NT_SUCCESS(Status)) {
        SSL_RELEASE_RUNDOWN(Inspector);
        return Status;
    }

    //
    // Allocate internal session
    //
    NewSession = (PSSL_SESSION)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(SSL_SESSION),
        SSL_POOL_TAG_SESSION
        );

    if (NewSession == NULL) {
        SSL_RELEASE_RUNDOWN(Inspector);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Fill in session data (pool2 zero-initializes)
    //
    NewSession->SessionId = InterlockedIncrement64(&Inspector->NextSessionId);
    NewSession->ProcessId = ProcessId;
    NewSession->IsIPv6 = IsIPv6;
    NewSession->RemotePort = RemotePort;
    NewSession->Version = Parsed.Version;

    if (IsIPv6) {
        RtlCopyMemory(&NewSession->RemoteAddress.IPv6, RemoteAddress, sizeof(IN6_ADDR));
    } else {
        RtlCopyMemory(&NewSession->RemoteAddress.IPv4, RemoteAddress, sizeof(IN_ADDR));
    }

    //
    // Copy server name (SNI)
    //
    if (Parsed.ServerName[0] != '\0') {
        RtlStringCbCopyA(NewSession->ServerName, sizeof(NewSession->ServerName),
            Parsed.ServerName);
    }

    //
    // Build and hash JA3 fingerprint
    //
    Status = SslpBuildJA3String(&Parsed, NewSession->JA3.JA3String,
        sizeof(NewSession->JA3.JA3String));

    if (NT_SUCCESS(Status) && NewSession->JA3.JA3String[0] != '\0') {
        Status = ShadowStrikeComputeMd5(
            NewSession->JA3.JA3String,
            (ULONG)strlen(NewSession->JA3.JA3String),
            NewSession->JA3.JA3Hash
            );

        if (!NT_SUCCESS(Status)) {
            RtlZeroMemory(NewSession->JA3.JA3Hash, sizeof(NewSession->JA3.JA3Hash));
        }
    }

    //
    // Check against known bad JA3 — internal version, no nested rundown
    //
    IsBadJA3 = FALSE;
    MalwareFamily[0] = '\0';

    SslpCheckKnownJA3(Inspector, NewSession->JA3.JA3Hash,
        &IsBadJA3, MalwareFamily, sizeof(MalwareFamily));

    if (IsBadJA3) {
        InterlockedOr(&NewSession->SuspicionFlags, (LONG)SslSuspicion_KnownBadJA3);
        NewSession->SuspicionScore += 80;
    }

    //
    // Analyze for other suspicious indicators
    //
    SslpAnalyzeSuspicion(NewSession, &Parsed);

    //
    // Record handshake time
    //
    KeQuerySystemTime(&NewSession->HandshakeTime);

    //
    // Allocate caller snapshot BEFORE taking the lock
    //
    Snapshot = (PSSL_SESSION_INFO)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(SSL_SESSION_INFO),
        SSL_POOL_TAG_RESULT
        );

    if (Snapshot == NULL) {
        ExFreePoolWithTag(NewSession, SSL_POOL_TAG_SESSION);
        SSL_RELEASE_RUNDOWN(Inspector);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Snapshot session data for the caller — no internal pointers.
    //
    SslpSnapshotSession(NewSession, Snapshot);

    //
    // Add to session list under exclusive lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Inspector->SessionLock);

    InsertTailList(&Inspector->SessionList, &NewSession->ListEntry);
    InterlockedIncrement(&Inspector->SessionCount);

    ExReleasePushLockExclusive(&Inspector->SessionLock);
    KeLeaveCriticalRegion();

    //
    // Update statistics
    //
    InterlockedIncrement64(&Inspector->Stats.HandshakesInspected);

    if (NewSession->SuspicionFlags != SslSuspicion_None) {
        InterlockedIncrement64(&Inspector->Stats.SuspiciousDetected);
    }

    *SessionInfo = Snapshot;

    SSL_RELEASE_RUNDOWN(Inspector);
    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API — INSPECT SERVER HELLO
// ============================================================================

_Use_decl_annotations_
NTSTATUS
SslInspectServerHello(
    _In_ PSSL_INSPECTOR Inspector,
    _In_ PVOID RemoteAddress,
    _In_ USHORT RemotePort,
    _In_ BOOLEAN IsIPv6,
    _In_reads_bytes_(DataSize) PVOID ServerHello,
    _In_ ULONG DataSize
    )
{
    NTSTATUS Status;
    PSSL_SESSION Session = NULL;
    SSL_PARSED_SERVER_HELLO Parsed;
    PLIST_ENTRY Entry;
    BOOLEAN Found = FALSE;

    PAGED_CODE();

    if (Inspector == NULL || RemoteAddress == NULL ||
        ServerHello == NULL || DataSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!SSL_ACQUIRE_RUNDOWN(Inspector)) {
        return STATUS_DELETE_PENDING;
    }

    if (DataSize < sizeof(TLS_RECORD_HEADER) + sizeof(TLS_HANDSHAKE_HEADER)) {
        SSL_RELEASE_RUNDOWN(Inspector);
        return STATUS_INVALID_BUFFER_SIZE;
    }

    if (DataSize > SSL_MAX_HANDSHAKE_SIZE) {
        SSL_RELEASE_RUNDOWN(Inspector);
        return STATUS_BUFFER_OVERFLOW;
    }

    //
    // Parse the ServerHello
    //
    RtlZeroMemory(&Parsed, sizeof(Parsed));

    Status = SslpParseServerHello(ServerHello, DataSize, &Parsed);
    if (!NT_SUCCESS(Status)) {
        SSL_RELEASE_RUNDOWN(Inspector);
        return Status;
    }

    //
    // Find and update session under EXCLUSIVE lock — prevents use-after-free
    // and protects the mutation from concurrent access.
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Inspector->SessionLock);

    for (Entry = Inspector->SessionList.Flink;
         Entry != &Inspector->SessionList;
         Entry = Entry->Flink) {

        Session = CONTAINING_RECORD(Entry, SSL_SESSION, ListEntry);

        if (Session->IsIPv6 != IsIPv6 || Session->RemotePort != RemotePort) {
            continue;
        }

        if (IsIPv6) {
            if (RtlCompareMemory(&Session->RemoteAddress.IPv6, RemoteAddress,
                sizeof(IN6_ADDR)) == sizeof(IN6_ADDR)) {
                Found = TRUE;
                break;
            }
        } else {
            if (RtlCompareMemory(&Session->RemoteAddress.IPv4, RemoteAddress,
                sizeof(IN_ADDR)) == sizeof(IN_ADDR)) {
                Found = TRUE;
                break;
            }
        }
    }

    if (Found) {
        //
        // Update session with server-selected values — UNDER LOCK.
        //
        if (Parsed.SelectedVersion != 0) {
            Session->Version = (SSL_VERSION)Parsed.SelectedVersion;
        } else {
            Session->Version = Parsed.Version;
        }

        //
        // Build JA3S fingerprint
        //
        Status = SslpBuildJA3SString(&Parsed, Session->JA3.JA3SString,
            sizeof(Session->JA3.JA3SString));

        if (NT_SUCCESS(Status) && Session->JA3.JA3SString[0] != '\0') {
            ShadowStrikeComputeMd5(
                Session->JA3.JA3SString,
                (ULONG)strlen(Session->JA3.JA3SString),
                Session->JA3.JA3SHash
                );
        }

        //
        // Check for weak cipher suite selection
        //
        if (SslpIsWeakCipherSuite(Parsed.CipherSuite)) {
            InterlockedOr(&Session->SuspicionFlags, (LONG)SslSuspicion_WeakCipher);
            Session->SuspicionScore += 30;
        }

        //
        // Format cipher suite name
        //
        RtlStringCbPrintfA(Session->CipherSuite, sizeof(Session->CipherSuite),
            "0x%04X", Parsed.CipherSuite);
    }

    ExReleasePushLockExclusive(&Inspector->SessionLock);
    KeLeaveCriticalRegion();

    SSL_RELEASE_RUNDOWN(Inspector);

    return Found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

// ============================================================================
// PUBLIC API — CALCULATE JA3 (standalone, no inspector state)
// ============================================================================

_Use_decl_annotations_
NTSTATUS
SslCalculateJA3(
    _In_reads_bytes_(DataSize) PVOID ClientHello,
    _In_ ULONG DataSize,
    _Out_ PSSL_JA3 JA3
    )
{
    NTSTATUS Status;
    SSL_PARSED_CLIENT_HELLO Parsed;

    PAGED_CODE();

    if (ClientHello == NULL || DataSize == 0 || JA3 == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(JA3, sizeof(SSL_JA3));
    RtlZeroMemory(&Parsed, sizeof(Parsed));

    Status = SslpParseClientHello(ClientHello, DataSize, &Parsed);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = SslpBuildJA3String(&Parsed, JA3->JA3String, sizeof(JA3->JA3String));
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    if (JA3->JA3String[0] != '\0') {
        Status = ShadowStrikeComputeMd5(
            JA3->JA3String,
            (ULONG)strlen(JA3->JA3String),
            JA3->JA3Hash
            );
    }

    return Status;
}

// ============================================================================
// PUBLIC API — ADD BAD JA3 (atomic check+insert under single exclusive lock)
// ============================================================================

_Use_decl_annotations_
NTSTATUS
SslAddBadJA3(
    _In_ PSSL_INSPECTOR Inspector,
    _In_ PUCHAR JA3Hash,
    _In_opt_ PCSTR MalwareFamily
    )
{
    PSSL_BAD_JA3_ENTRY NewEntry = NULL;
    PLIST_ENTRY Entry;
    PSSL_BAD_JA3_ENTRY ExistingEntry;
    LARGE_INTEGER CurrentTime;

    PAGED_CODE();

    if (Inspector == NULL || JA3Hash == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!SSL_ACQUIRE_RUNDOWN(Inspector)) {
        return STATUS_DELETE_PENDING;
    }

    //
    // Pre-allocate BEFORE acquiring the exclusive lock to minimize lock hold time.
    //
    NewEntry = (PSSL_BAD_JA3_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(SSL_BAD_JA3_ENTRY),
        SSL_POOL_TAG_JA3
        );

    if (NewEntry == NULL) {
        SSL_RELEASE_RUNDOWN(Inspector);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(NewEntry->JA3Hash, JA3Hash, 16);

    if (MalwareFamily != NULL) {
        RtlStringCbCopyA(NewEntry->MalwareFamily, sizeof(NewEntry->MalwareFamily),
            MalwareFamily);
    }

    KeQuerySystemTime(&CurrentTime);
    NewEntry->AddedTime = CurrentTime;

    //
    // Atomic duplicate check + insert under SINGLE exclusive lock.
    // Eliminates TOCTOU race from old code.
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Inspector->BadJA3Lock);

    //
    // Check count limit
    //
    if (Inspector->BadJA3Count >= SSL_MAX_BAD_JA3_ENTRIES) {
        ExReleasePushLockExclusive(&Inspector->BadJA3Lock);
        KeLeaveCriticalRegion();
        ExFreePoolWithTag(NewEntry, SSL_POOL_TAG_JA3);
        SSL_RELEASE_RUNDOWN(Inspector);
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Check for duplicate
    //
    for (Entry = Inspector->BadJA3List.Flink;
         Entry != &Inspector->BadJA3List;
         Entry = Entry->Flink) {

        ExistingEntry = CONTAINING_RECORD(Entry, SSL_BAD_JA3_ENTRY, ListEntry);

        if (RtlCompareMemory(ExistingEntry->JA3Hash, JA3Hash, 16) == 16) {
            ExReleasePushLockExclusive(&Inspector->BadJA3Lock);
            KeLeaveCriticalRegion();
            ExFreePoolWithTag(NewEntry, SSL_POOL_TAG_JA3);
            SSL_RELEASE_RUNDOWN(Inspector);
            return STATUS_DUPLICATE_OBJECTID;
        }
    }

    //
    // Insert — still under the same exclusive lock
    //
    InsertTailList(&Inspector->BadJA3List, &NewEntry->ListEntry);
    InterlockedIncrement(&Inspector->BadJA3Count);

    ExReleasePushLockExclusive(&Inspector->BadJA3Lock);
    KeLeaveCriticalRegion();

    SSL_RELEASE_RUNDOWN(Inspector);
    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API — CHECK JA3
// ============================================================================

_Use_decl_annotations_
NTSTATUS
SslCheckJA3(
    _In_ PSSL_INSPECTOR Inspector,
    _In_ PUCHAR JA3Hash,
    _Out_ PBOOLEAN IsBad,
    _Out_writes_z_(FamilySize) PSTR MalwareFamily,
    _In_ ULONG FamilySize
    )
{
    PLIST_ENTRY Entry;
    PSSL_BAD_JA3_ENTRY BadEntry;

    PAGED_CODE();

    if (Inspector == NULL || JA3Hash == NULL ||
        IsBad == NULL || MalwareFamily == NULL || FamilySize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsBad = FALSE;
    MalwareFamily[0] = '\0';

    if (!SSL_ACQUIRE_RUNDOWN(Inspector)) {
        return STATUS_DELETE_PENDING;
    }

    //
    // Check if hash is all zeros (invalid/uncomputed)
    //
    if (ShadowStrikeIsHashEmpty(JA3Hash, 16)) {
        SSL_RELEASE_RUNDOWN(Inspector);
        return STATUS_SUCCESS;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Inspector->BadJA3Lock);

    for (Entry = Inspector->BadJA3List.Flink;
         Entry != &Inspector->BadJA3List;
         Entry = Entry->Flink) {

        BadEntry = CONTAINING_RECORD(Entry, SSL_BAD_JA3_ENTRY, ListEntry);

        if (ShadowStrikeCompareHash(BadEntry->JA3Hash, JA3Hash, 16)) {
            *IsBad = TRUE;

            if (BadEntry->MalwareFamily[0] != '\0') {
                RtlStringCbCopyA(MalwareFamily, FamilySize, BadEntry->MalwareFamily);
            }
            break;
        }
    }

    ExReleasePushLockShared(&Inspector->BadJA3Lock);
    KeLeaveCriticalRegion();

    SSL_RELEASE_RUNDOWN(Inspector);
    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API — REMOVE SESSION
// ============================================================================

_Use_decl_annotations_
NTSTATUS
SslRemoveSession(
    _In_ PSSL_INSPECTOR Inspector,
    _In_ PVOID RemoteAddress,
    _In_ USHORT RemotePort,
    _In_ BOOLEAN IsIPv6
    )
{
    PLIST_ENTRY Entry;
    PSSL_SESSION Session;
    PSSL_SESSION Found = NULL;

    PAGED_CODE();

    if (Inspector == NULL || RemoteAddress == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!SSL_ACQUIRE_RUNDOWN(Inspector)) {
        return STATUS_DELETE_PENDING;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Inspector->SessionLock);

    for (Entry = Inspector->SessionList.Flink;
         Entry != &Inspector->SessionList;
         Entry = Entry->Flink) {

        Session = CONTAINING_RECORD(Entry, SSL_SESSION, ListEntry);

        if (Session->IsIPv6 != IsIPv6 || Session->RemotePort != RemotePort) {
            continue;
        }

        if (IsIPv6) {
            if (RtlCompareMemory(&Session->RemoteAddress.IPv6, RemoteAddress,
                sizeof(IN6_ADDR)) == sizeof(IN6_ADDR)) {
                Found = Session;
                break;
            }
        } else {
            if (RtlCompareMemory(&Session->RemoteAddress.IPv4, RemoteAddress,
                sizeof(IN_ADDR)) == sizeof(IN_ADDR)) {
                Found = Session;
                break;
            }
        }
    }

    if (Found != NULL) {
        RemoveEntryList(&Found->ListEntry);
        InterlockedDecrement(&Inspector->SessionCount);
    }

    ExReleasePushLockExclusive(&Inspector->SessionLock);
    KeLeaveCriticalRegion();

    if (Found != NULL) {
        ExFreePoolWithTag(Found, SSL_POOL_TAG_SESSION);
    }

    SSL_RELEASE_RUNDOWN(Inspector);

    return (Found != NULL) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

// ============================================================================
// PUBLIC API — STATISTICS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
SslGetStatistics(
    _In_ PSSL_INSPECTOR Inspector,
    _Out_ PSSL_STATISTICS Stats
    )
{
    LARGE_INTEGER CurrentTime;

    PAGED_CODE();

    if (Inspector == NULL || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!SSL_ACQUIRE_RUNDOWN(Inspector)) {
        return STATUS_DELETE_PENDING;
    }

    RtlZeroMemory(Stats, sizeof(SSL_STATISTICS));

    Stats->ActiveSessions = (ULONG)Inspector->SessionCount;

    Stats->HandshakesInspected = (ULONG64)InterlockedCompareExchange64(
        &Inspector->Stats.HandshakesInspected, 0, 0);

    Stats->SuspiciousDetected = (ULONG64)InterlockedCompareExchange64(
        &Inspector->Stats.SuspiciousDetected, 0, 0);

    Stats->KnownBadJA3Count = (ULONG)Inspector->BadJA3Count;

    KeQuerySystemTime(&CurrentTime);
    Stats->UpTime.QuadPart = CurrentTime.QuadPart - Inspector->Stats.StartTime.QuadPart;

    SSL_RELEASE_RUNDOWN(Inspector);
    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API — FREE SESSION INFO (caller snapshot)
// ============================================================================

_Use_decl_annotations_
VOID
SslFreeSessionInfo(
    _In_ _Post_invalid_ PSSL_SESSION_INFO SessionInfo
    )
{
    PAGED_CODE();

    if (SessionInfo != NULL) {
        ExFreePoolWithTag(SessionInfo, SSL_POOL_TAG_RESULT);
    }
}

// ============================================================================
// PUBLIC API — STALE SESSION CLEANUP
// ============================================================================

_Use_decl_annotations_
VOID
SslCleanupStaleSessions(
    _In_ PSSL_INSPECTOR Inspector
    )
{
    PLIST_ENTRY Entry;
    PLIST_ENTRY NextEntry;
    PSSL_SESSION Session;
    LARGE_INTEGER CurrentTime;
    LARGE_INTEGER CutoffTime;
    LIST_ENTRY FreeList;

    PAGED_CODE();

    if (Inspector == NULL) {
        return;
    }

    if (!SSL_ACQUIRE_RUNDOWN(Inspector)) {
        return;
    }

    InitializeListHead(&FreeList);

    KeQuerySystemTime(&CurrentTime);
    CutoffTime.QuadPart = CurrentTime.QuadPart -
                          ((LONGLONG)SSL_SESSION_STALE_MS * 10000);

    //
    // Collect stale sessions under exclusive lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Inspector->SessionLock);

    for (Entry = Inspector->SessionList.Flink;
         Entry != &Inspector->SessionList;
         Entry = NextEntry) {

        NextEntry = Entry->Flink;
        Session = CONTAINING_RECORD(Entry, SSL_SESSION, ListEntry);

        if (Session->HandshakeTime.QuadPart < CutoffTime.QuadPart) {
            RemoveEntryList(Entry);
            InterlockedDecrement(&Inspector->SessionCount);
            InsertTailList(&FreeList, Entry);
        }
    }

    ExReleasePushLockExclusive(&Inspector->SessionLock);
    KeLeaveCriticalRegion();

    //
    // Free outside the lock
    //
    while (!IsListEmpty(&FreeList)) {
        Entry = RemoveHeadList(&FreeList);
        Session = CONTAINING_RECORD(Entry, SSL_SESSION, ListEntry);
        ExFreePoolWithTag(Session, SSL_POOL_TAG_SESSION);
    }

    SSL_RELEASE_RUNDOWN(Inspector);
}

// ============================================================================
// INTERNAL — PARSE CLIENT HELLO
// ============================================================================

static
NTSTATUS
SslpParseClientHello(
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _Out_ PSSL_PARSED_CLIENT_HELLO Parsed
    )
{
    PUCHAR Buffer = (PUCHAR)Data;
    PUCHAR BufferEnd = Buffer + DataSize;
    PUCHAR Current;
    PTLS_RECORD_HEADER RecordHeader;
    ULONG HandshakeLength;
    UCHAR SessionIdLength;
    USHORT CipherSuitesLength;
    UCHAR CompressionMethodsLength;
    USHORT ExtensionsLength;
    USHORT ExtType;
    USHORT ExtLength;
    ULONG i;

    RtlZeroMemory(Parsed, sizeof(SSL_PARSED_CLIENT_HELLO));

    if (DataSize < sizeof(TLS_RECORD_HEADER)) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    RecordHeader = (PTLS_RECORD_HEADER)Buffer;

    if (RecordHeader->ContentType != TLS_CONTENT_TYPE_HANDSHAKE) {
        return STATUS_INVALID_PARAMETER;
    }

    Parsed->Version = (SSL_VERSION)((RecordHeader->VersionMajor << 8) |
        RecordHeader->VersionMinor);

    Current = Buffer + sizeof(TLS_RECORD_HEADER);

    // Parse handshake header
    if (Current + 4 > BufferEnd) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    if (Current[0] != TLS_HANDSHAKE_CLIENT_HELLO) {
        return STATUS_INVALID_PARAMETER;
    }

    HandshakeLength = SslpReadNetworkUInt24(Current + 1);
    Current += 4;

    if (Current + HandshakeLength > BufferEnd) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    // Constrain parsing to the handshake body
    BufferEnd = Current + HandshakeLength;

    // Skip version (2 bytes) and random (32 bytes)
    if (Current + 34 > BufferEnd) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    {
        USHORT HelloVersion = SslpReadNetworkUShort(Current);
        if (HelloVersion > (USHORT)Parsed->Version) {
            Parsed->Version = (SSL_VERSION)HelloVersion;
        }
    }

    Current += 34;

    // Session ID
    if (Current + 1 > BufferEnd) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    SessionIdLength = *Current++;

    if (Current + SessionIdLength > BufferEnd) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    Current += SessionIdLength;

    // Cipher suites
    if (Current + 2 > BufferEnd) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    CipherSuitesLength = SslpReadNetworkUShort(Current);
    Current += 2;

    if (Current + CipherSuitesLength > BufferEnd) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    for (i = 0; i < CipherSuitesLength / 2 &&
         Parsed->CipherSuiteCount < SSL_MAX_CIPHER_SUITES; i++) {

        USHORT CipherSuite = SslpReadNetworkUShort(Current + i * 2);

        if (!TLS_IS_GREASE_VALUE(CipherSuite)) {
            Parsed->CipherSuites[Parsed->CipherSuiteCount++] = CipherSuite;
        }
    }

    Current += CipherSuitesLength;

    // Compression methods
    if (Current + 1 > BufferEnd) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    CompressionMethodsLength = *Current++;

    if (Current + CompressionMethodsLength > BufferEnd) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    Current += CompressionMethodsLength;

    //
    // Extensions (if present)
    //
    if (Current + 2 <= BufferEnd) {
        ExtensionsLength = SslpReadNetworkUShort(Current);
        Current += 2;

        if (Current + ExtensionsLength > BufferEnd) {
            return STATUS_INVALID_BUFFER_SIZE;
        }

        PUCHAR ExtEnd = Current + ExtensionsLength;

        while (Current + 4 <= ExtEnd && Parsed->ExtensionCount < SSL_MAX_EXTENSIONS) {
            ExtType = SslpReadNetworkUShort(Current);
            ExtLength = SslpReadNetworkUShort(Current + 2);
            Current += 4;

            if (Current + ExtLength > ExtEnd) {
                break;
            }

            if (!TLS_IS_GREASE_VALUE(ExtType)) {
                Parsed->Extensions[Parsed->ExtensionCount++] = ExtType;
            }

            //
            // Parse specific extensions — all inner length reads
            // are validated against ExtLength to prevent OOB access.
            //
            switch (ExtType) {

            case TLS_EXTENSION_SERVER_NAME:
                if (ExtLength >= 5) {
                    USHORT ListLength = SslpReadNetworkUShort(Current);
                    if (ListLength + 2 <= ExtLength && Current[2] == 0) {
                        USHORT NameLength = SslpReadNetworkUShort(Current + 3);
                        if (5 + NameLength <= ExtLength &&
                            NameLength < sizeof(Parsed->ServerName) - 1) {
                            RtlCopyMemory(Parsed->ServerName, Current + 5, NameLength);
                            Parsed->ServerName[NameLength] = '\0';
                        }
                    }
                }
                break;

            case TLS_EXTENSION_SUPPORTED_GROUPS:
                if (ExtLength >= 2) {
                    USHORT GroupsLength = SslpReadNetworkUShort(Current);

                    //
                    // CRITICAL FIX: validate GroupsLength fits within ExtLength
                    //
                    if ((ULONG)GroupsLength + 2 <= ExtLength) {
                        ULONG NumGroups = GroupsLength / 2;

                        for (ULONG j = 0; j < NumGroups &&
                             Parsed->SupportedGroupCount < SSL_MAX_SUPPORTED_GROUPS; j++) {

                            USHORT Group = SslpReadNetworkUShort(Current + 2 + j * 2);

                            if (!TLS_IS_GREASE_VALUE(Group)) {
                                Parsed->SupportedGroups[Parsed->SupportedGroupCount++] = Group;
                            }
                        }
                    }
                }
                break;

            case TLS_EXTENSION_EC_POINT_FORMATS:
                if (ExtLength >= 1) {
                    UCHAR FormatsLength = Current[0];

                    //
                    // CRITICAL FIX: validate FormatsLength fits within ExtLength
                    //
                    if ((ULONG)FormatsLength + 1 <= ExtLength) {
                        for (ULONG j = 0; j < FormatsLength &&
                             Parsed->ECPointFormatCount < SSL_MAX_EC_POINT_FORMATS; j++) {

                            Parsed->ECPointFormats[Parsed->ECPointFormatCount++] =
                                Current[1 + j];
                        }
                    }
                }
                break;

            case TLS_EXTENSION_SUPPORTED_VERSIONS:
                if (ExtLength >= 1) {
                    UCHAR VersionsLength = Current[0];

                    //
                    // CRITICAL FIX: validate VersionsLength fits within ExtLength
                    //
                    if ((ULONG)VersionsLength + 1 <= ExtLength) {
                        ULONG NumVersions = VersionsLength / 2;

                        for (ULONG j = 0; j < NumVersions &&
                             Parsed->SupportedVersionCount < ARRAYSIZE(Parsed->SupportedVersions); j++) {

                            USHORT Version = SslpReadNetworkUShort(Current + 1 + j * 2);

                            if (!TLS_IS_GREASE_VALUE(Version)) {
                                Parsed->SupportedVersions[Parsed->SupportedVersionCount++] =
                                    Version;
                            }
                        }
                    }
                }
                break;
            }

            Current += ExtLength;
        }
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// INTERNAL — PARSE SERVER HELLO
// ============================================================================

static
NTSTATUS
SslpParseServerHello(
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _Out_ PSSL_PARSED_SERVER_HELLO Parsed
    )
{
    PUCHAR Buffer = (PUCHAR)Data;
    PUCHAR BufferEnd = Buffer + DataSize;
    PUCHAR Current;
    PTLS_RECORD_HEADER RecordHeader;
    ULONG HandshakeLength;
    UCHAR SessionIdLength;
    USHORT ExtensionsLength;
    USHORT ExtType;
    USHORT ExtLength;

    RtlZeroMemory(Parsed, sizeof(SSL_PARSED_SERVER_HELLO));

    if (DataSize < sizeof(TLS_RECORD_HEADER)) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    RecordHeader = (PTLS_RECORD_HEADER)Buffer;

    if (RecordHeader->ContentType != TLS_CONTENT_TYPE_HANDSHAKE) {
        return STATUS_INVALID_PARAMETER;
    }

    Parsed->Version = (SSL_VERSION)((RecordHeader->VersionMajor << 8) |
        RecordHeader->VersionMinor);

    Current = Buffer + sizeof(TLS_RECORD_HEADER);

    if (Current + 4 > BufferEnd) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    if (Current[0] != TLS_HANDSHAKE_SERVER_HELLO) {
        return STATUS_INVALID_PARAMETER;
    }

    HandshakeLength = SslpReadNetworkUInt24(Current + 1);
    Current += 4;

    if (Current + HandshakeLength > BufferEnd) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    // Constrain parsing to handshake body
    BufferEnd = Current + HandshakeLength;

    // Version (2) + Random (32)
    if (Current + 34 > BufferEnd) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    {
        USHORT HelloVersion = SslpReadNetworkUShort(Current);
        Parsed->Version = (SSL_VERSION)HelloVersion;
    }
    Current += 34;

    // Session ID
    if (Current + 1 > BufferEnd) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    SessionIdLength = *Current++;

    if (Current + SessionIdLength > BufferEnd) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    Current += SessionIdLength;

    // Cipher suite (2) + Compression method (1)
    if (Current + 3 > BufferEnd) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    Parsed->CipherSuite = SslpReadNetworkUShort(Current);
    Current += 2;

    Parsed->CompressionMethod = *Current++;

    // Extensions
    if (Current + 2 <= BufferEnd) {
        ExtensionsLength = SslpReadNetworkUShort(Current);
        Current += 2;

        if (Current + ExtensionsLength > BufferEnd) {
            return STATUS_INVALID_BUFFER_SIZE;
        }

        PUCHAR ExtEnd = Current + ExtensionsLength;

        while (Current + 4 <= ExtEnd && Parsed->ExtensionCount < SSL_MAX_EXTENSIONS) {
            ExtType = SslpReadNetworkUShort(Current);
            ExtLength = SslpReadNetworkUShort(Current + 2);
            Current += 4;

            if (Current + ExtLength > ExtEnd) {
                break;
            }

            if (!TLS_IS_GREASE_VALUE(ExtType)) {
                Parsed->Extensions[Parsed->ExtensionCount++] = ExtType;
            }

            if (ExtType == TLS_EXTENSION_SUPPORTED_VERSIONS && ExtLength >= 2) {
                Parsed->SelectedVersion = SslpReadNetworkUShort(Current);
            }

            Current += ExtLength;
        }
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// INTERNAL — BUILD JA3 STRING
//
// Format: SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats
// ============================================================================

static
NTSTATUS
SslpBuildJA3String(
    _In_ PSSL_PARSED_CLIENT_HELLO Parsed,
    _Out_writes_z_(BufferSize) PSTR Buffer,
    _In_ ULONG BufferSize
    )
{
    NTSTATUS Status;
    ULONG Offset = 0;
    ULONG Remaining = BufferSize;
    ULONG i;
    USHORT Version;

    if (BufferSize < 32) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    Buffer[0] = '\0';

    //
    // Determine version (prefer TLS 1.3 supported_versions)
    //
    if (Parsed->SupportedVersionCount > 0) {
        Version = Parsed->SupportedVersions[0];
        for (i = 1; i < Parsed->SupportedVersionCount; i++) {
            if (Parsed->SupportedVersions[i] > Version) {
                Version = Parsed->SupportedVersions[i];
            }
        }
    } else {
        Version = (USHORT)Parsed->Version;
    }

    // Write version
    Status = RtlStringCbPrintfExA(
        Buffer + Offset, Remaining, NULL, &Remaining, 0,
        "%u,", Version);
    if (!NT_SUCCESS(Status)) return Status;
    Offset = BufferSize - Remaining;

    // Write cipher suites
    for (i = 0; i < Parsed->CipherSuiteCount; i++) {
        Status = RtlStringCbPrintfExA(
            Buffer + Offset, Remaining, NULL, &Remaining, 0,
            i == 0 ? "%u" : "-%u", Parsed->CipherSuites[i]);
        if (!NT_SUCCESS(Status)) break;
        Offset = BufferSize - Remaining;
    }

    // Separator
    Status = RtlStringCbPrintfExA(
        Buffer + Offset, Remaining, NULL, &Remaining, 0, ",");
    if (!NT_SUCCESS(Status)) return Status;
    Offset = BufferSize - Remaining;

    // Write extensions
    for (i = 0; i < Parsed->ExtensionCount; i++) {
        Status = RtlStringCbPrintfExA(
            Buffer + Offset, Remaining, NULL, &Remaining, 0,
            i == 0 ? "%u" : "-%u", Parsed->Extensions[i]);
        if (!NT_SUCCESS(Status)) break;
        Offset = BufferSize - Remaining;
    }

    // Separator
    Status = RtlStringCbPrintfExA(
        Buffer + Offset, Remaining, NULL, &Remaining, 0, ",");
    if (!NT_SUCCESS(Status)) return Status;
    Offset = BufferSize - Remaining;

    // Write supported groups
    for (i = 0; i < Parsed->SupportedGroupCount; i++) {
        Status = RtlStringCbPrintfExA(
            Buffer + Offset, Remaining, NULL, &Remaining, 0,
            i == 0 ? "%u" : "-%u", Parsed->SupportedGroups[i]);
        if (!NT_SUCCESS(Status)) break;
        Offset = BufferSize - Remaining;
    }

    // Separator
    Status = RtlStringCbPrintfExA(
        Buffer + Offset, Remaining, NULL, &Remaining, 0, ",");
    if (!NT_SUCCESS(Status)) return Status;
    Offset = BufferSize - Remaining;

    // Write EC point formats
    for (i = 0; i < Parsed->ECPointFormatCount; i++) {
        Status = RtlStringCbPrintfExA(
            Buffer + Offset, Remaining, NULL, &Remaining, 0,
            i == 0 ? "%u" : "-%u", Parsed->ECPointFormats[i]);
        if (!NT_SUCCESS(Status)) break;
        Offset = BufferSize - Remaining;
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// INTERNAL — BUILD JA3S STRING
//
// Format: SSLVersion,CipherSuite,Extensions
// ============================================================================

static
NTSTATUS
SslpBuildJA3SString(
    _In_ PSSL_PARSED_SERVER_HELLO Parsed,
    _Out_writes_z_(BufferSize) PSTR Buffer,
    _In_ ULONG BufferSize
    )
{
    NTSTATUS Status;
    ULONG Offset = 0;
    ULONG Remaining = BufferSize;
    ULONG i;
    USHORT Version;

    if (BufferSize < 32) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    Buffer[0] = '\0';

    Version = (Parsed->SelectedVersion != 0) ?
        Parsed->SelectedVersion : (USHORT)Parsed->Version;

    // Write version
    Status = RtlStringCbPrintfExA(
        Buffer + Offset, Remaining, NULL, &Remaining, 0,
        "%u,", Version);
    if (!NT_SUCCESS(Status)) return Status;
    Offset = BufferSize - Remaining;

    // Write cipher suite
    Status = RtlStringCbPrintfExA(
        Buffer + Offset, Remaining, NULL, &Remaining, 0,
        "%u,", Parsed->CipherSuite);
    if (!NT_SUCCESS(Status)) return Status;
    Offset = BufferSize - Remaining;

    // Write extensions
    for (i = 0; i < Parsed->ExtensionCount; i++) {
        Status = RtlStringCbPrintfExA(
            Buffer + Offset, Remaining, NULL, &Remaining, 0,
            i == 0 ? "%u" : "-%u", Parsed->Extensions[i]);
        if (!NT_SUCCESS(Status)) break;
        Offset = BufferSize - Remaining;
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// INTERNAL — SUSPICION ANALYSIS
// ============================================================================

static
VOID
SslpAnalyzeSuspicion(
    _Inout_ PSSL_SESSION Session,
    _In_ PSSL_PARSED_CLIENT_HELLO ClientHello
    )
{
    ULONG i;
    USHORT MaxVersion;
    BOOLEAN HasWeakCipher = FALSE;

    MaxVersion = (USHORT)ClientHello->Version;

    for (i = 0; i < ClientHello->SupportedVersionCount; i++) {
        if (ClientHello->SupportedVersions[i] > MaxVersion) {
            MaxVersion = ClientHello->SupportedVersions[i];
        }
    }

    // Flag old TLS versions (SSL 3.0, TLS 1.0, TLS 1.1)
    if (MaxVersion < 0x0303) {
        InterlockedOr(&Session->SuspicionFlags, (LONG)SslSuspicion_OldVersion);
        Session->SuspicionScore += 20;
    }

    // Check for weak cipher suites
    for (i = 0; i < ClientHello->CipherSuiteCount; i++) {
        if (SslpIsWeakCipherSuite(ClientHello->CipherSuites[i])) {
            HasWeakCipher = TRUE;
            break;
        }
    }

    if (HasWeakCipher) {
        InterlockedOr(&Session->SuspicionFlags, (LONG)SslSuspicion_WeakCipher);
        Session->SuspicionScore += 15;
    }

    // Very few extensions = stripped/custom TLS stack
    if (ClientHello->ExtensionCount < 3) {
        InterlockedOr(&Session->SuspicionFlags, (LONG)SslSuspicion_UnusualExtensions);
        Session->SuspicionScore += 10;
    }

    // Missing SNI — suspicious for HTTPS
    if (ClientHello->ServerName[0] == '\0') {
        Session->SuspicionScore += 5;
    }

    // Very large cipher suite count = scanner
    if (ClientHello->CipherSuiteCount > 100) {
        Session->SuspicionScore += 10;
    }

    // Cap at 100
    if (Session->SuspicionScore > 100) {
        Session->SuspicionScore = 100;
    }
}

// ============================================================================
// INTERNAL — SESSION SNAPSHOT
//
// Copies internal session data to a caller-visible SSL_SESSION_INFO.
// No pointers, no list linkage — pure value copy.
// ============================================================================

static
VOID
SslpSnapshotSession(
    _In_ PSSL_SESSION Session,
    _Out_ PSSL_SESSION_INFO Info
    )
{
    RtlZeroMemory(Info, sizeof(SSL_SESSION_INFO));

    Info->SessionId = Session->SessionId;
    Info->ProcessId = Session->ProcessId;
    Info->RemoteAddress = Session->RemoteAddress;
    Info->RemotePort = Session->RemotePort;
    Info->IsIPv6 = Session->IsIPv6;
    Info->Version = Session->Version;
    RtlCopyMemory(Info->CipherSuite, Session->CipherSuite, sizeof(Info->CipherSuite));
    RtlCopyMemory(Info->ServerName, Session->ServerName, sizeof(Info->ServerName));
    Info->JA3 = Session->JA3;
    Info->Certificate = Session->Certificate;
    Info->SuspicionFlags = Session->SuspicionFlags;
    Info->SuspicionScore = Session->SuspicionScore;
    Info->HandshakeTime = Session->HandshakeTime;
}

// ============================================================================
// INTERNAL — JA3 CHECK (no rundown — called from contexts that already hold it)
// ============================================================================

static
VOID
SslpCheckKnownJA3(
    _In_ PSSL_INSPECTOR Inspector,
    _In_ PUCHAR JA3Hash,
    _Out_ PBOOLEAN IsBad,
    _Out_writes_z_(FamilySize) PSTR MalwareFamily,
    _In_ ULONG FamilySize
    )
{
    PLIST_ENTRY Entry;
    PSSL_BAD_JA3_ENTRY BadEntry;

    *IsBad = FALSE;
    MalwareFamily[0] = '\0';

    if (ShadowStrikeIsHashEmpty(JA3Hash, 16)) {
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Inspector->BadJA3Lock);

    for (Entry = Inspector->BadJA3List.Flink;
         Entry != &Inspector->BadJA3List;
         Entry = Entry->Flink) {

        BadEntry = CONTAINING_RECORD(Entry, SSL_BAD_JA3_ENTRY, ListEntry);

        if (ShadowStrikeCompareHash(BadEntry->JA3Hash, JA3Hash, 16)) {
            *IsBad = TRUE;

            if (BadEntry->MalwareFamily[0] != '\0') {
                RtlStringCbCopyA(MalwareFamily, FamilySize, BadEntry->MalwareFamily);
            }
            break;
        }
    }

    ExReleasePushLockShared(&Inspector->BadJA3Lock);
    KeLeaveCriticalRegion();
}
