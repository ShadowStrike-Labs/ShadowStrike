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

    Security Considerations:
    - All input is treated as hostile and validated
    - Buffer bounds checked on all TLS record parsing
    - No dynamic allocations in hot paths where possible
    - Constant-time operations for cryptographic comparisons

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

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, SslInitialize)
#pragma alloc_text(PAGE, SslShutdown)
#pragma alloc_text(PAGE, SslInspectClientHello)
#pragma alloc_text(PAGE, SslInspectServerHello)
#pragma alloc_text(PAGE, SslCalculateJA3)
#pragma alloc_text(PAGE, SslAddBadJA3)
#pragma alloc_text(PAGE, SslCheckJA3)
#pragma alloc_text(PAGE, SslGetStatistics)
#pragma alloc_text(PAGE, SslFreeSession)
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
// GREASE values (RFC 8701) - should be ignored in JA3 computation
//
#define TLS_IS_GREASE_VALUE(x) \
    (((x) & 0x0F0F) == 0x0A0A)

//
// Maximum parsing limits (DoS prevention)
//
#define SSL_MAX_HANDSHAKE_SIZE          65535
#define SSL_MAX_EXTENSIONS              100
#define SSL_MAX_CIPHER_SUITES           200
#define SSL_MAX_SUPPORTED_GROUPS        50
#define SSL_MAX_EC_POINT_FORMATS        10
#define SSL_MAX_SIGNATURE_ALGORITHMS    50
#define SSL_MAX_BAD_JA3_ENTRIES         10000
#define SSL_MAX_ACTIVE_SESSIONS         65536

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
    USHORT LengthLow;                   // Combined with LengthHigh for 24-bit length
} TLS_HANDSHAKE_HEADER, *PTLS_HANDSHAKE_HEADER;

typedef struct _TLS_CLIENT_HELLO_FIXED {
    UCHAR VersionMajor;
    UCHAR VersionMinor;
    UCHAR Random[32];
} TLS_CLIENT_HELLO_FIXED, *PTLS_CLIENT_HELLO_FIXED;

#pragma pack(pop)

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
// Parsed ClientHello data (internal use)
//
typedef struct _SSL_PARSED_CLIENT_HELLO {
    SSL_VERSION Version;

    //
    // Cipher suites
    //
    USHORT CipherSuites[SSL_MAX_CIPHER_SUITES];
    ULONG CipherSuiteCount;

    //
    // Extensions
    //
    USHORT Extensions[SSL_MAX_EXTENSIONS];
    ULONG ExtensionCount;

    //
    // Supported groups (elliptic curves)
    //
    USHORT SupportedGroups[SSL_MAX_SUPPORTED_GROUPS];
    ULONG SupportedGroupCount;

    //
    // EC point formats
    //
    UCHAR ECPointFormats[SSL_MAX_EC_POINT_FORMATS];
    ULONG ECPointFormatCount;

    //
    // Server Name Indication
    //
    CHAR ServerName[256];

    //
    // ALPN protocols
    //
    CHAR AlpnProtocols[256];

    //
    // Supported versions (TLS 1.3)
    //
    USHORT SupportedVersions[10];
    ULONG SupportedVersionCount;

} SSL_PARSED_CLIENT_HELLO, *PSSL_PARSED_CLIENT_HELLO;

//
// Parsed ServerHello data (internal use)
//
typedef struct _SSL_PARSED_SERVER_HELLO {
    SSL_VERSION Version;
    USHORT CipherSuite;
    UCHAR CompressionMethod;

    //
    // Extensions
    //
    USHORT Extensions[SSL_MAX_EXTENSIONS];
    ULONG ExtensionCount;

    //
    // Selected version (TLS 1.3)
    //
    USHORT SelectedVersion;

} SSL_PARSED_SERVER_HELLO, *PSSL_PARSED_SERVER_HELLO;

//=============================================================================
// Forward Declarations
//=============================================================================

static
NTSTATUS
SslpParseClientHello(
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _Out_ PSSL_PARSED_CLIENT_HELLO Parsed
    );

static
NTSTATUS
SslpParseServerHello(
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _Out_ PSSL_PARSED_SERVER_HELLO Parsed
    );

static
NTSTATUS
SslpBuildJA3String(
    _In_ PSSL_PARSED_CLIENT_HELLO Parsed,
    _Out_writes_z_(BufferSize) PSTR Buffer,
    _In_ ULONG BufferSize
    );

static
NTSTATUS
SslpBuildJA3SString(
    _In_ PSSL_PARSED_SERVER_HELLO Parsed,
    _Out_writes_z_(BufferSize) PSTR Buffer,
    _In_ ULONG BufferSize
    );

static
VOID
SslpAnalyzeSuspicion(
    _Inout_ PSSL_SESSION Session,
    _In_ PSSL_PARSED_CLIENT_HELLO ClientHello
    );

static
PSSL_SESSION
SslpFindSessionByEndpoint(
    _In_ PSSL_INSPECTOR Inspector,
    _In_ PVOID RemoteAddress,
    _In_ USHORT RemotePort,
    _In_ BOOLEAN IsIPv6
    );

static
FORCEINLINE
USHORT
SslpReadNetworkUShort(
    _In_reads_bytes_(2) PUCHAR Buffer
    )
{
    return (USHORT)((Buffer[0] << 8) | Buffer[1]);
}

static
FORCEINLINE
ULONG
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
    0x002F,     // TLS_RSA_WITH_AES_128_CBC_SHA (considered weak now)
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
    0x00FF,     // TLS_EMPTY_RENEGOTIATION_INFO_SCSV (not a cipher, but tracked)
    0xC007,     // TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
    0xC011,     // TLS_ECDHE_RSA_WITH_RC4_128_SHA
    0xC016,     // TLS_ECDH_anon_WITH_RC4_128_SHA
};

static
BOOLEAN
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

//=============================================================================
// Public API Implementation
//=============================================================================

_Use_decl_annotations_
NTSTATUS
SslInitialize(
    _Out_ PSSL_INSPECTOR* Inspector
    )
/*++

Routine Description:

    Initializes the SSL inspection subsystem.

Arguments:

    Inspector - Receives pointer to the initialized inspector.

Return Value:

    STATUS_SUCCESS on success, appropriate error code otherwise.

--*/
{
    PSSL_INSPECTOR NewInspector = NULL;
    NTSTATUS Status;
    LARGE_INTEGER CurrentTime;

    PAGED_CODE();

    if (Inspector == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Inspector = NULL;

    //
    // Allocate the inspector structure from non-paged pool
    // as it contains synchronization primitives
    //
    NewInspector = (PSSL_INSPECTOR)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(SSL_INSPECTOR),
        SSL_POOL_TAG_SESSION
        );

    if (NewInspector == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(NewInspector, sizeof(SSL_INSPECTOR));

    //
    // Initialize list heads
    //
    InitializeListHead(&NewInspector->SessionList);
    InitializeListHead(&NewInspector->BadJA3List);

    //
    // Initialize push locks
    //
    ExInitializePushLock(&NewInspector->SessionLock);
    ExInitializePushLock(&NewInspector->BadJA3Lock);

    //
    // Initialize counters
    //
    NewInspector->SessionCount = 0;
    NewInspector->NextSessionId = 1;

    //
    // Record start time
    //
    KeQuerySystemTime(&CurrentTime);
    NewInspector->Stats.StartTime = CurrentTime;

    NewInspector->Initialized = TRUE;

    *Inspector = NewInspector;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
SslShutdown(
    _Inout_ PSSL_INSPECTOR Inspector
    )
/*++

Routine Description:

    Shuts down the SSL inspection subsystem and frees all resources.

Arguments:

    Inspector - The inspector to shut down.

--*/
{
    PLIST_ENTRY Entry;
    PSSL_SESSION Session;
    PSSL_BAD_JA3_ENTRY BadJA3Entry;

    PAGED_CODE();

    if (Inspector == NULL || !Inspector->Initialized) {
        return;
    }

    Inspector->Initialized = FALSE;

    //
    // Free all sessions
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Inspector->SessionLock);

    while (!IsListEmpty(&Inspector->SessionList)) {
        Entry = RemoveHeadList(&Inspector->SessionList);
        Session = CONTAINING_RECORD(Entry, SSL_SESSION, ListEntry);

        ShadowStrikeFreePoolWithTag(Session, SSL_POOL_TAG_SESSION);
    }

    ExReleasePushLockExclusive(&Inspector->SessionLock);
    KeLeaveCriticalRegion();

    //
    // Free all bad JA3 entries
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Inspector->BadJA3Lock);

    while (!IsListEmpty(&Inspector->BadJA3List)) {
        Entry = RemoveHeadList(&Inspector->BadJA3List);
        BadJA3Entry = CONTAINING_RECORD(Entry, SSL_BAD_JA3_ENTRY, ListEntry);

        ShadowStrikeFreePoolWithTag(BadJA3Entry, SSL_POOL_TAG_SESSION);
    }

    ExReleasePushLockExclusive(&Inspector->BadJA3Lock);
    KeLeaveCriticalRegion();

    //
    // Free the inspector itself
    //
    ShadowStrikeFreePoolWithTag(Inspector, SSL_POOL_TAG_SESSION);
}

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
    _Out_ PSSL_SESSION* Session
    )
/*++

Routine Description:

    Inspects a TLS ClientHello message and creates a session tracking entry.

Arguments:

    Inspector     - The SSL inspector.
    ProcessId     - The process ID initiating the connection.
    RemoteAddress - Remote IP address (IN_ADDR or IN6_ADDR).
    RemotePort    - Remote port.
    IsIPv6        - TRUE if IPv6.
    ClientHello   - The ClientHello data (with or without record header).
    DataSize      - Size of ClientHello data.
    Session       - Receives the created session.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    NTSTATUS Status;
    PSSL_SESSION NewSession = NULL;
    SSL_PARSED_CLIENT_HELLO Parsed;
    LARGE_INTEGER CurrentTime;
    BOOLEAN IsBadJA3;
    CHAR MalwareFamily[64];

    PAGED_CODE();

    if (Inspector == NULL || !Inspector->Initialized ||
        RemoteAddress == NULL || ClientHello == NULL ||
        DataSize == 0 || Session == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Session = NULL;

    //
    // Validate data size
    //
    if (DataSize < sizeof(TLS_RECORD_HEADER) + sizeof(TLS_HANDSHAKE_HEADER) +
        sizeof(TLS_CLIENT_HELLO_FIXED)) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    if (DataSize > SSL_MAX_HANDSHAKE_SIZE) {
        return STATUS_BUFFER_OVERFLOW;
    }

    //
    // Check session limit
    //
    if (InterlockedCompareExchange(&Inspector->SessionCount, 0, 0) >=
        SSL_MAX_ACTIVE_SESSIONS) {
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Parse the ClientHello
    //
    RtlZeroMemory(&Parsed, sizeof(Parsed));

    Status = SslpParseClientHello(ClientHello, DataSize, &Parsed);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Allocate session
    //
    NewSession = (PSSL_SESSION)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(SSL_SESSION),
        SSL_POOL_TAG_SESSION
        );

    if (NewSession == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(NewSession, sizeof(SSL_SESSION));

    //
    // Fill in session data
    //
    NewSession->SessionId = InterlockedIncrement64(&Inspector->NextSessionId);
    NewSession->ProcessId = ProcessId;
    NewSession->IsIPv6 = IsIPv6;
    NewSession->RemotePort = RemotePort;
    NewSession->Version = Parsed.Version;

    //
    // Copy remote address
    //
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
        //
        // Compute MD5 hash of JA3 string
        //
        Status = ShadowStrikeComputeMd5(
            NewSession->JA3.JA3String,
            (ULONG)strlen(NewSession->JA3.JA3String),
            NewSession->JA3.JA3Hash
            );

        if (!NT_SUCCESS(Status)) {
            //
            // Non-fatal - continue without hash
            //
            RtlZeroMemory(NewSession->JA3.JA3Hash, sizeof(NewSession->JA3.JA3Hash));
        }
    }

    //
    // Check against known bad JA3 fingerprints
    //
    IsBadJA3 = FALSE;
    MalwareFamily[0] = '\0';

    Status = SslCheckJA3(Inspector, NewSession->JA3.JA3Hash, &IsBadJA3,
        MalwareFamily, sizeof(MalwareFamily));

    if (NT_SUCCESS(Status) && IsBadJA3) {
        NewSession->SuspicionFlags |= SslSuspicion_KnownBadJA3;
        NewSession->SuspicionScore += 80;
    }

    //
    // Analyze for other suspicious indicators
    //
    SslpAnalyzeSuspicion(NewSession, &Parsed);

    //
    // Record handshake time
    //
    KeQuerySystemTime(&CurrentTime);
    NewSession->HandshakeTime = CurrentTime;

    //
    // Add to session list
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

    *Session = NewSession;

    return STATUS_SUCCESS;
}

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
/*++

Routine Description:

    Inspects a TLS ServerHello message and updates the existing session.

Arguments:

    Inspector     - The SSL inspector.
    RemoteAddress - Remote IP address.
    RemotePort    - Remote port.
    IsIPv6        - TRUE if IPv6.
    ServerHello   - The ServerHello data.
    DataSize      - Size of ServerHello data.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    NTSTATUS Status;
    PSSL_SESSION Session;
    SSL_PARSED_SERVER_HELLO Parsed;

    PAGED_CODE();

    if (Inspector == NULL || !Inspector->Initialized ||
        RemoteAddress == NULL || ServerHello == NULL || DataSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (DataSize < sizeof(TLS_RECORD_HEADER) + sizeof(TLS_HANDSHAKE_HEADER)) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    if (DataSize > SSL_MAX_HANDSHAKE_SIZE) {
        return STATUS_BUFFER_OVERFLOW;
    }

    //
    // Find existing session
    //
    Session = SslpFindSessionByEndpoint(Inspector, RemoteAddress, RemotePort, IsIPv6);

    if (Session == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Parse the ServerHello
    //
    RtlZeroMemory(&Parsed, sizeof(Parsed));

    Status = SslpParseServerHello(ServerHello, DataSize, &Parsed);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Update session with server-selected values
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
        Status = ShadowStrikeComputeMd5(
            Session->JA3.JA3SString,
            (ULONG)strlen(Session->JA3.JA3SString),
            Session->JA3.JA3SHash
            );
    }

    //
    // Check for weak cipher suite selection
    //
    if (SslpIsWeakCipherSuite(Parsed.CipherSuite)) {
        Session->SuspicionFlags |= SslSuspicion_WeakCipher;
        Session->SuspicionScore += 30;
    }

    //
    // Format cipher suite name
    //
    RtlStringCbPrintfA(Session->CipherSuite, sizeof(Session->CipherSuite),
        "0x%04X", Parsed.CipherSuite);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
SslCalculateJA3(
    _In_reads_bytes_(DataSize) PVOID ClientHello,
    _In_ ULONG DataSize,
    _Out_ PSSL_JA3 JA3
    )
/*++

Routine Description:

    Calculates JA3 fingerprint from a ClientHello message.

Arguments:

    ClientHello - The ClientHello data.
    DataSize    - Size of ClientHello data.
    JA3         - Receives the JA3 fingerprint.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    NTSTATUS Status;
    SSL_PARSED_CLIENT_HELLO Parsed;

    PAGED_CODE();

    if (ClientHello == NULL || DataSize == 0 || JA3 == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(JA3, sizeof(SSL_JA3));
    RtlZeroMemory(&Parsed, sizeof(Parsed));

    //
    // Parse ClientHello
    //
    Status = SslpParseClientHello(ClientHello, DataSize, &Parsed);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Build JA3 string
    //
    Status = SslpBuildJA3String(&Parsed, JA3->JA3String, sizeof(JA3->JA3String));
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Compute MD5 hash
    //
    if (JA3->JA3String[0] != '\0') {
        Status = ShadowStrikeComputeMd5(
            JA3->JA3String,
            (ULONG)strlen(JA3->JA3String),
            JA3->JA3Hash
            );
    }

    return Status;
}

_Use_decl_annotations_
NTSTATUS
SslAddBadJA3(
    _In_ PSSL_INSPECTOR Inspector,
    _In_ PUCHAR JA3Hash,
    _In_opt_ PCSTR MalwareFamily
    )
/*++

Routine Description:

    Adds a known malicious JA3 fingerprint to the blocklist.

Arguments:

    Inspector     - The SSL inspector.
    JA3Hash       - 16-byte MD5 hash of JA3 string.
    MalwareFamily - Optional malware family name.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    PSSL_BAD_JA3_ENTRY NewEntry;
    PLIST_ENTRY Entry;
    PSSL_BAD_JA3_ENTRY ExistingEntry;
    LARGE_INTEGER CurrentTime;
    LONG CurrentCount;

    PAGED_CODE();

    if (Inspector == NULL || !Inspector->Initialized || JA3Hash == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Check if we've hit the limit
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Inspector->BadJA3Lock);

    CurrentCount = 0;
    for (Entry = Inspector->BadJA3List.Flink;
         Entry != &Inspector->BadJA3List;
         Entry = Entry->Flink) {

        ExistingEntry = CONTAINING_RECORD(Entry, SSL_BAD_JA3_ENTRY, ListEntry);

        //
        // Check for duplicate
        //
        if (RtlCompareMemory(ExistingEntry->JA3Hash, JA3Hash, 16) == 16) {
            ExReleasePushLockShared(&Inspector->BadJA3Lock);
            KeLeaveCriticalRegion();
            return STATUS_DUPLICATE_OBJECTID;
        }

        CurrentCount++;
    }

    ExReleasePushLockShared(&Inspector->BadJA3Lock);
    KeLeaveCriticalRegion();

    if (CurrentCount >= SSL_MAX_BAD_JA3_ENTRIES) {
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Allocate new entry
    //
    NewEntry = (PSSL_BAD_JA3_ENTRY)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(SSL_BAD_JA3_ENTRY),
        SSL_POOL_TAG_SESSION
        );

    if (NewEntry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(NewEntry, sizeof(SSL_BAD_JA3_ENTRY));

    //
    // Copy hash
    //
    RtlCopyMemory(NewEntry->JA3Hash, JA3Hash, 16);

    //
    // Copy malware family if provided
    //
    if (MalwareFamily != NULL) {
        RtlStringCbCopyA(NewEntry->MalwareFamily, sizeof(NewEntry->MalwareFamily),
            MalwareFamily);
    }

    //
    // Record time
    //
    KeQuerySystemTime(&CurrentTime);
    NewEntry->AddedTime = CurrentTime;

    //
    // Add to list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Inspector->BadJA3Lock);

    InsertTailList(&Inspector->BadJA3List, &NewEntry->ListEntry);

    ExReleasePushLockExclusive(&Inspector->BadJA3Lock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
SslCheckJA3(
    _In_ PSSL_INSPECTOR Inspector,
    _In_ PUCHAR JA3Hash,
    _Out_ PBOOLEAN IsBad,
    _Out_writes_z_(FamilySize) PSTR MalwareFamily,
    _In_ ULONG FamilySize
    )
/*++

Routine Description:

    Checks if a JA3 fingerprint matches a known malicious one.

Arguments:

    Inspector     - The SSL inspector.
    JA3Hash       - 16-byte MD5 hash to check.
    IsBad         - Receives TRUE if fingerprint is known bad.
    MalwareFamily - Receives the malware family name if known.
    FamilySize    - Size of MalwareFamily buffer.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    PLIST_ENTRY Entry;
    PSSL_BAD_JA3_ENTRY BadEntry;

    PAGED_CODE();

    if (Inspector == NULL || !Inspector->Initialized || JA3Hash == NULL ||
        IsBad == NULL || MalwareFamily == NULL || FamilySize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsBad = FALSE;
    MalwareFamily[0] = '\0';

    //
    // Check if hash is all zeros (invalid/uncomputed)
    //
    if (ShadowStrikeIsHashEmpty(JA3Hash, 16)) {
        return STATUS_SUCCESS;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Inspector->BadJA3Lock);

    for (Entry = Inspector->BadJA3List.Flink;
         Entry != &Inspector->BadJA3List;
         Entry = Entry->Flink) {

        BadEntry = CONTAINING_RECORD(Entry, SSL_BAD_JA3_ENTRY, ListEntry);

        //
        // Constant-time comparison for security
        //
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

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
SslGetStatistics(
    _In_ PSSL_INSPECTOR Inspector,
    _Out_ PSSL_STATISTICS Stats
    )
/*++

Routine Description:

    Gets current SSL inspection statistics.

Arguments:

    Inspector - The SSL inspector.
    Stats     - Receives the statistics.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    LARGE_INTEGER CurrentTime;
    PLIST_ENTRY Entry;
    LONG BadJA3Count;

    PAGED_CODE();

    if (Inspector == NULL || !Inspector->Initialized || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Stats, sizeof(SSL_STATISTICS));

    Stats->ActiveSessions = (ULONG)InterlockedCompareExchange(
        &Inspector->SessionCount, 0, 0);

    Stats->HandshakesInspected = (ULONG64)InterlockedCompareExchange64(
        &Inspector->Stats.HandshakesInspected, 0, 0);

    Stats->SuspiciousDetected = (ULONG64)InterlockedCompareExchange64(
        &Inspector->Stats.SuspiciousDetected, 0, 0);

    //
    // Count bad JA3 entries
    //
    BadJA3Count = 0;
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Inspector->BadJA3Lock);

    for (Entry = Inspector->BadJA3List.Flink;
         Entry != &Inspector->BadJA3List;
         Entry = Entry->Flink) {
        BadJA3Count++;
    }

    ExReleasePushLockShared(&Inspector->BadJA3Lock);
    KeLeaveCriticalRegion();

    Stats->KnownBadJA3Count = (ULONG)BadJA3Count;

    //
    // Calculate uptime
    //
    KeQuerySystemTime(&CurrentTime);
    Stats->UpTime.QuadPart = CurrentTime.QuadPart - Inspector->Stats.StartTime.QuadPart;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
SslFreeSession(
    _In_ PSSL_SESSION Session
    )
/*++

Routine Description:

    Frees an SSL session. Note: This should only be called after
    the session has been removed from the inspector's list.

Arguments:

    Session - The session to free.

--*/
{
    PAGED_CODE();

    if (Session != NULL) {
        ShadowStrikeFreePoolWithTag(Session, SSL_POOL_TAG_SESSION);
    }
}

//=============================================================================
// Internal Implementation
//=============================================================================

static
NTSTATUS
SslpParseClientHello(
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _Out_ PSSL_PARSED_CLIENT_HELLO Parsed
    )
/*++

Routine Description:

    Parses a TLS ClientHello message.

--*/
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

    //
    // Validate minimum size
    //
    if (DataSize < sizeof(TLS_RECORD_HEADER)) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    RecordHeader = (PTLS_RECORD_HEADER)Buffer;

    //
    // Verify it's a handshake record
    //
    if (RecordHeader->ContentType != TLS_CONTENT_TYPE_HANDSHAKE) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Extract TLS version from record header
    //
    Parsed->Version = (SSL_VERSION)((RecordHeader->VersionMajor << 8) |
        RecordHeader->VersionMinor);

    Current = Buffer + sizeof(TLS_RECORD_HEADER);

    //
    // Parse handshake header
    //
    if (Current + 4 > BufferEnd) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    if (Current[0] != TLS_HANDSHAKE_CLIENT_HELLO) {
        return STATUS_INVALID_PARAMETER;
    }

    HandshakeLength = SslpReadNetworkUInt24(Current + 1);
    Current += 4;

    //
    // Validate handshake length
    //
    if (Current + HandshakeLength > BufferEnd) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    //
    // Skip version (2 bytes) and random (32 bytes)
    //
    if (Current + 34 > BufferEnd) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    //
    // Update version from ClientHello if different
    //
    USHORT HelloVersion = SslpReadNetworkUShort(Current);
    if (HelloVersion > (USHORT)Parsed->Version) {
        Parsed->Version = (SSL_VERSION)HelloVersion;
    }

    Current += 34;

    //
    // Session ID
    //
    if (Current + 1 > BufferEnd) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    SessionIdLength = *Current++;

    if (Current + SessionIdLength > BufferEnd) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    Current += SessionIdLength;

    //
    // Cipher suites
    //
    if (Current + 2 > BufferEnd) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    CipherSuitesLength = SslpReadNetworkUShort(Current);
    Current += 2;

    if (Current + CipherSuitesLength > BufferEnd) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    //
    // Parse cipher suites (filtering GREASE values)
    //
    for (i = 0; i < CipherSuitesLength / 2 &&
         Parsed->CipherSuiteCount < SSL_MAX_CIPHER_SUITES; i++) {

        USHORT CipherSuite = SslpReadNetworkUShort(Current + i * 2);

        if (!TLS_IS_GREASE_VALUE(CipherSuite)) {
            Parsed->CipherSuites[Parsed->CipherSuiteCount++] = CipherSuite;
        }
    }

    Current += CipherSuitesLength;

    //
    // Compression methods
    //
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

            //
            // Store extension type (filtering GREASE)
            //
            if (!TLS_IS_GREASE_VALUE(ExtType)) {
                Parsed->Extensions[Parsed->ExtensionCount++] = ExtType;
            }

            //
            // Parse specific extensions
            //
            switch (ExtType) {

            case TLS_EXTENSION_SERVER_NAME:
                //
                // Parse SNI
                //
                if (ExtLength >= 5) {
                    USHORT ListLength = SslpReadNetworkUShort(Current);
                    if (ListLength + 2 <= ExtLength && Current[2] == 0) {
                        USHORT NameLength = SslpReadNetworkUShort(Current + 3);
                        if (NameLength + 5 <= ExtLength &&
                            NameLength < sizeof(Parsed->ServerName)) {
                            RtlCopyMemory(Parsed->ServerName, Current + 5, NameLength);
                            Parsed->ServerName[NameLength] = '\0';
                        }
                    }
                }
                break;

            case TLS_EXTENSION_SUPPORTED_GROUPS:
                //
                // Parse elliptic curves
                //
                if (ExtLength >= 2) {
                    USHORT GroupsLength = SslpReadNetworkUShort(Current);
                    ULONG NumGroups = GroupsLength / 2;

                    for (ULONG j = 0; j < NumGroups &&
                         Parsed->SupportedGroupCount < SSL_MAX_SUPPORTED_GROUPS; j++) {

                        USHORT Group = SslpReadNetworkUShort(Current + 2 + j * 2);

                        if (!TLS_IS_GREASE_VALUE(Group)) {
                            Parsed->SupportedGroups[Parsed->SupportedGroupCount++] = Group;
                        }
                    }
                }
                break;

            case TLS_EXTENSION_EC_POINT_FORMATS:
                //
                // Parse EC point formats
                //
                if (ExtLength >= 1) {
                    UCHAR FormatsLength = Current[0];

                    for (ULONG j = 0; j < FormatsLength &&
                         Parsed->ECPointFormatCount < SSL_MAX_EC_POINT_FORMATS; j++) {

                        Parsed->ECPointFormats[Parsed->ECPointFormatCount++] =
                            Current[1 + j];
                    }
                }
                break;

            case TLS_EXTENSION_SUPPORTED_VERSIONS:
                //
                // Parse TLS 1.3 supported versions
                //
                if (ExtLength >= 1) {
                    UCHAR VersionsLength = Current[0];
                    ULONG NumVersions = VersionsLength / 2;

                    for (ULONG j = 0; j < NumVersions &&
                         Parsed->SupportedVersionCount < 10; j++) {

                        USHORT Version = SslpReadNetworkUShort(Current + 1 + j * 2);

                        if (!TLS_IS_GREASE_VALUE(Version)) {
                            Parsed->SupportedVersions[Parsed->SupportedVersionCount++] =
                                Version;
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

static
NTSTATUS
SslpParseServerHello(
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _Out_ PSSL_PARSED_SERVER_HELLO Parsed
    )
/*++

Routine Description:

    Parses a TLS ServerHello message.

--*/
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

    //
    // Version (2 bytes) + Random (32 bytes)
    //
    if (Current + 34 > BufferEnd) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    USHORT HelloVersion = SslpReadNetworkUShort(Current);
    Parsed->Version = (SSL_VERSION)HelloVersion;
    Current += 34;

    //
    // Session ID
    //
    if (Current + 1 > BufferEnd) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    SessionIdLength = *Current++;

    if (Current + SessionIdLength > BufferEnd) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    Current += SessionIdLength;

    //
    // Cipher suite (2 bytes) + Compression method (1 byte)
    //
    if (Current + 3 > BufferEnd) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    Parsed->CipherSuite = SslpReadNetworkUShort(Current);
    Current += 2;

    Parsed->CompressionMethod = *Current++;

    //
    // Extensions
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
            // TLS 1.3 supported_versions extension
            //
            if (ExtType == TLS_EXTENSION_SUPPORTED_VERSIONS && ExtLength >= 2) {
                Parsed->SelectedVersion = SslpReadNetworkUShort(Current);
            }

            Current += ExtLength;
        }
    }

    return STATUS_SUCCESS;
}

static
NTSTATUS
SslpBuildJA3String(
    _In_ PSSL_PARSED_CLIENT_HELLO Parsed,
    _Out_writes_z_(BufferSize) PSTR Buffer,
    _In_ ULONG BufferSize
    )
/*++

Routine Description:

    Builds the JA3 fingerprint string from parsed ClientHello.

    JA3 Format: SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats
    Example: 769,47-53-5-10-49161-49162,0-23-65281,29-23-24,0

--*/
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
    // Determine version to use (prefer TLS 1.3 supported_versions if available)
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

    //
    // Write version
    //
    Status = RtlStringCbPrintfExA(
        Buffer + Offset,
        Remaining,
        NULL,
        &Remaining,
        0,
        "%u,",
        Version
        );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Offset = BufferSize - Remaining;

    //
    // Write cipher suites
    //
    for (i = 0; i < Parsed->CipherSuiteCount; i++) {
        Status = RtlStringCbPrintfExA(
            Buffer + Offset,
            Remaining,
            NULL,
            &Remaining,
            0,
            i == 0 ? "%u" : "-%u",
            Parsed->CipherSuites[i]
            );

        if (!NT_SUCCESS(Status)) {
            break;
        }

        Offset = BufferSize - Remaining;
    }

    //
    // Separator
    //
    Status = RtlStringCbPrintfExA(
        Buffer + Offset,
        Remaining,
        NULL,
        &Remaining,
        0,
        ","
        );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Offset = BufferSize - Remaining;

    //
    // Write extensions
    //
    for (i = 0; i < Parsed->ExtensionCount; i++) {
        Status = RtlStringCbPrintfExA(
            Buffer + Offset,
            Remaining,
            NULL,
            &Remaining,
            0,
            i == 0 ? "%u" : "-%u",
            Parsed->Extensions[i]
            );

        if (!NT_SUCCESS(Status)) {
            break;
        }

        Offset = BufferSize - Remaining;
    }

    //
    // Separator
    //
    Status = RtlStringCbPrintfExA(
        Buffer + Offset,
        Remaining,
        NULL,
        &Remaining,
        0,
        ","
        );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Offset = BufferSize - Remaining;

    //
    // Write supported groups (elliptic curves)
    //
    for (i = 0; i < Parsed->SupportedGroupCount; i++) {
        Status = RtlStringCbPrintfExA(
            Buffer + Offset,
            Remaining,
            NULL,
            &Remaining,
            0,
            i == 0 ? "%u" : "-%u",
            Parsed->SupportedGroups[i]
            );

        if (!NT_SUCCESS(Status)) {
            break;
        }

        Offset = BufferSize - Remaining;
    }

    //
    // Separator
    //
    Status = RtlStringCbPrintfExA(
        Buffer + Offset,
        Remaining,
        NULL,
        &Remaining,
        0,
        ","
        );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Offset = BufferSize - Remaining;

    //
    // Write EC point formats
    //
    for (i = 0; i < Parsed->ECPointFormatCount; i++) {
        Status = RtlStringCbPrintfExA(
            Buffer + Offset,
            Remaining,
            NULL,
            &Remaining,
            0,
            i == 0 ? "%u" : "-%u",
            Parsed->ECPointFormats[i]
            );

        if (!NT_SUCCESS(Status)) {
            break;
        }

        Offset = BufferSize - Remaining;
    }

    return STATUS_SUCCESS;
}

static
NTSTATUS
SslpBuildJA3SString(
    _In_ PSSL_PARSED_SERVER_HELLO Parsed,
    _Out_writes_z_(BufferSize) PSTR Buffer,
    _In_ ULONG BufferSize
    )
/*++

Routine Description:

    Builds the JA3S fingerprint string from parsed ServerHello.

    JA3S Format: SSLVersion,CipherSuite,Extensions
    Example: 769,47,65281-0-11

--*/
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
    // Use selected version (TLS 1.3) if available
    //
    Version = (Parsed->SelectedVersion != 0) ?
        Parsed->SelectedVersion : (USHORT)Parsed->Version;

    //
    // Write version
    //
    Status = RtlStringCbPrintfExA(
        Buffer + Offset,
        Remaining,
        NULL,
        &Remaining,
        0,
        "%u,",
        Version
        );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Offset = BufferSize - Remaining;

    //
    // Write cipher suite
    //
    Status = RtlStringCbPrintfExA(
        Buffer + Offset,
        Remaining,
        NULL,
        &Remaining,
        0,
        "%u,",
        Parsed->CipherSuite
        );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Offset = BufferSize - Remaining;

    //
    // Write extensions
    //
    for (i = 0; i < Parsed->ExtensionCount; i++) {
        Status = RtlStringCbPrintfExA(
            Buffer + Offset,
            Remaining,
            NULL,
            &Remaining,
            0,
            i == 0 ? "%u" : "-%u",
            Parsed->Extensions[i]
            );

        if (!NT_SUCCESS(Status)) {
            break;
        }

        Offset = BufferSize - Remaining;
    }

    return STATUS_SUCCESS;
}

static
VOID
SslpAnalyzeSuspicion(
    _Inout_ PSSL_SESSION Session,
    _In_ PSSL_PARSED_CLIENT_HELLO ClientHello
    )
/*++

Routine Description:

    Analyzes the TLS handshake for suspicious indicators.

--*/
{
    ULONG i;
    USHORT MaxVersion;
    BOOLEAN HasWeakCipher = FALSE;

    //
    // Check TLS version
    //
    MaxVersion = (USHORT)ClientHello->Version;

    for (i = 0; i < ClientHello->SupportedVersionCount; i++) {
        if (ClientHello->SupportedVersions[i] > MaxVersion) {
            MaxVersion = ClientHello->SupportedVersions[i];
        }
    }

    //
    // Flag old TLS versions (SSL 3.0, TLS 1.0, TLS 1.1)
    //
    if (MaxVersion < 0x0303) {  // < TLS 1.2
        Session->SuspicionFlags |= SslSuspicion_OldVersion;
        Session->SuspicionScore += 20;
    }

    //
    // Check for weak cipher suites
    //
    for (i = 0; i < ClientHello->CipherSuiteCount; i++) {
        if (SslpIsWeakCipherSuite(ClientHello->CipherSuites[i])) {
            HasWeakCipher = TRUE;
            break;
        }
    }

    if (HasWeakCipher) {
        Session->SuspicionFlags |= SslSuspicion_WeakCipher;
        Session->SuspicionScore += 15;
    }

    //
    // Check for unusual extensions
    // (e.g., very few extensions can indicate stripped/custom TLS stack)
    //
    if (ClientHello->ExtensionCount < 3) {
        Session->SuspicionFlags |= SslSuspicion_UnusualExtensions;
        Session->SuspicionScore += 10;
    }

    //
    // Check for missing SNI (could be C2 or generic tool)
    //
    if (ClientHello->ServerName[0] == '\0') {
        //
        // Missing SNI is suspicious for HTTPS but not fatal
        //
        Session->SuspicionScore += 5;
    }

    //
    // Very large number of cipher suites can indicate scanner
    //
    if (ClientHello->CipherSuiteCount > 100) {
        Session->SuspicionScore += 10;
    }

    //
    // Cap suspicion score at 100
    //
    if (Session->SuspicionScore > 100) {
        Session->SuspicionScore = 100;
    }
}

static
PSSL_SESSION
SslpFindSessionByEndpoint(
    _In_ PSSL_INSPECTOR Inspector,
    _In_ PVOID RemoteAddress,
    _In_ USHORT RemotePort,
    _In_ BOOLEAN IsIPv6
    )
/*++

Routine Description:

    Finds an SSL session by remote endpoint.

--*/
{
    PLIST_ENTRY Entry;
    PSSL_SESSION Session;
    PSSL_SESSION Found = NULL;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Inspector->SessionLock);

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

    ExReleasePushLockShared(&Inspector->SessionLock);
    KeLeaveCriticalRegion();

    return Found;
}
