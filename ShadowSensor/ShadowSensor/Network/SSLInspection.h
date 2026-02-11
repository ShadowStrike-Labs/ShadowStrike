/*++
    ShadowStrike Next-Generation Antivirus
    Module: SSLInspection.h

    Purpose: TLS/SSL inspection for encrypted traffic analysis.

    Synchronization model:
    - All public APIs require IRQL <= APC_LEVEL.
    - EX_PUSH_LOCK used for all list protection.
    - EX_RUNDOWN_REF used for safe shutdown draining.
    - Sessions are reference-counted; callers receive a snapshot (SSL_SESSION_INFO)
      that is a standalone copy — no pointers into internal lists.
    - Internal sessions (SSL_SESSION) live on the SessionList and are
      exclusively owned by the inspector; never returned to callers.

    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>
#include "../../Shared/NetworkTypes.h"

//=============================================================================
// Pool Tags
//=============================================================================

#define SSL_POOL_TAG_SESSION    'SSLS'  // SSL - Session (internal list entries)
#define SSL_POOL_TAG_JA3        'JSLS'  // SSL - JA3 bad-list entries
#define SSL_POOL_TAG_RESULT     'RSLS'  // SSL - Session info snapshots (returned to caller)

//=============================================================================
// Limits
//=============================================================================

#define SSL_MAX_ACTIVE_SESSIONS         65536
#define SSL_MAX_BAD_JA3_ENTRIES         10000
#define SSL_SESSION_STALE_MS            (5 * 60 * 1000)  // 5-minute TTL

//=============================================================================
// TLS Versions
//=============================================================================

typedef enum _SSL_VERSION {
    SslVersion_Unknown = 0,
    SslVersion_SSL30 = 0x0300,
    SslVersion_TLS10 = 0x0301,
    SslVersion_TLS11 = 0x0302,
    SslVersion_TLS12 = 0x0303,
    SslVersion_TLS13 = 0x0304,
} SSL_VERSION;

//=============================================================================
// TLS Suspicion Flags — used with InterlockedOr, must be LONG-compatible
//=============================================================================

typedef enum _SSL_SUSPICION {
    SslSuspicion_None               = 0x00000000,
    SslSuspicion_OldVersion         = 0x00000001,
    SslSuspicion_WeakCipher         = 0x00000002,
    SslSuspicion_SelfSignedCert     = 0x00000004,
    SslSuspicion_ExpiredCert        = 0x00000008,
    SslSuspicion_MismatchedCN       = 0x00000010,
    SslSuspicion_KnownBadJA3        = 0x00000020,
    SslSuspicion_UnusualExtensions  = 0x00000040,
    SslSuspicion_CertPinningBypass  = 0x00000080,
} SSL_SUSPICION;

//=============================================================================
// JA3 Fingerprint
//=============================================================================

typedef struct _SSL_JA3 {
    CHAR JA3String[512];
    UCHAR JA3Hash[16];
    CHAR JA3SString[512];
    UCHAR JA3SHash[16];
} SSL_JA3, *PSSL_JA3;

//=============================================================================
// Certificate Info
//=============================================================================

typedef struct _SSL_CERT_INFO {
    CHAR Subject[256];
    CHAR Issuer[256];
    CHAR CommonName[256];
    LARGE_INTEGER NotBefore;
    LARGE_INTEGER NotAfter;
    BOOLEAN IsSelfSigned;
    BOOLEAN IsExpired;
    UCHAR Thumbprint[32];
} SSL_CERT_INFO, *PSSL_CERT_INFO;

//=============================================================================
// SSL_SESSION_INFO — Caller-visible snapshot (value type, no list linkage)
//
// Returned from SslInspectClientHello. Caller owns this allocation and
// must free it via SslFreeSessionInfo. Contains NO internal pointers.
//=============================================================================

typedef struct _SSL_SESSION_INFO {
    ULONG64 SessionId;

    // Connection
    HANDLE ProcessId;
    union {
        IN_ADDR IPv4;
        IN6_ADDR IPv6;
    } RemoteAddress;
    USHORT RemotePort;
    BOOLEAN IsIPv6;

    // TLS details
    SSL_VERSION Version;
    CHAR CipherSuite[64];
    CHAR ServerName[256];               // SNI

    // JA3
    SSL_JA3 JA3;

    // Certificate
    SSL_CERT_INFO Certificate;

    // Suspicion
    LONG SuspicionFlags;                // SSL_SUSPICION bitfield
    ULONG SuspicionScore;

    // Timing
    LARGE_INTEGER HandshakeTime;

} SSL_SESSION_INFO, *PSSL_SESSION_INFO;

//=============================================================================
// SSL Inspector
//=============================================================================

typedef struct _SSL_INSPECTOR {
    volatile LONG Initialized;

    // Shutdown synchronization — every public API acquires rundown
    EX_RUNDOWN_REF RundownRef;

    // Sessions — protected by SessionLock
    LIST_ENTRY SessionList;
    EX_PUSH_LOCK SessionLock;
    volatile LONG SessionCount;
    volatile LONG64 NextSessionId;

    // Known bad JA3 — protected by BadJA3Lock
    LIST_ENTRY BadJA3List;
    EX_PUSH_LOCK BadJA3Lock;
    volatile LONG BadJA3Count;

    // Statistics
    struct {
        volatile LONG64 HandshakesInspected;
        volatile LONG64 SuspiciousDetected;
        LARGE_INTEGER StartTime;
    } Stats;

} SSL_INSPECTOR, *PSSL_INSPECTOR;

//=============================================================================
// Rundown helpers
//=============================================================================

#define SSL_ACQUIRE_RUNDOWN(Inspector) \
    ExAcquireRundownProtection(&(Inspector)->RundownRef)

#define SSL_RELEASE_RUNDOWN(Inspector) \
    ExReleaseRundownProtection(&(Inspector)->RundownRef)

//=============================================================================
// Public API
//
// All functions require IRQL <= APC_LEVEL (PASSIVE_LEVEL recommended).
//=============================================================================

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
SslInitialize(
    _Out_ PSSL_INSPECTOR* Inspector
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
SslShutdown(
    _Inout_ PSSL_INSPECTOR Inspector
    );

//
// SslInspectClientHello — parses ClientHello, creates internal session,
// returns a SNAPSHOT copy to the caller. Caller must free via SslFreeSessionInfo.
//
_IRQL_requires_max_(APC_LEVEL)
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
    );

//
// SslInspectServerHello — parses ServerHello, updates the existing internal session.
// All mutation is done under SessionLock exclusive.
//
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
SslInspectServerHello(
    _In_ PSSL_INSPECTOR Inspector,
    _In_ PVOID RemoteAddress,
    _In_ USHORT RemotePort,
    _In_ BOOLEAN IsIPv6,
    _In_reads_bytes_(DataSize) PVOID ServerHello,
    _In_ ULONG DataSize
    );

//
// SslCalculateJA3 — standalone JA3 computation (no inspector state needed).
//
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
SslCalculateJA3(
    _In_reads_bytes_(DataSize) PVOID ClientHello,
    _In_ ULONG DataSize,
    _Out_ PSSL_JA3 JA3
    );

//
// SslAddBadJA3 — atomically checks for duplicate + inserts under exclusive lock.
//
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
SslAddBadJA3(
    _In_ PSSL_INSPECTOR Inspector,
    _In_ PUCHAR JA3Hash,
    _In_opt_ PCSTR MalwareFamily
    );

//
// SslCheckJA3 — checks if a JA3 hash matches the known-bad list.
//
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
SslCheckJA3(
    _In_ PSSL_INSPECTOR Inspector,
    _In_ PUCHAR JA3Hash,
    _Out_ PBOOLEAN IsBad,
    _Out_writes_z_(FamilySize) PSTR MalwareFamily,
    _In_ ULONG FamilySize
    );

//
// SslRemoveSession — removes and frees an internal session by endpoint.
//
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
SslRemoveSession(
    _In_ PSSL_INSPECTOR Inspector,
    _In_ PVOID RemoteAddress,
    _In_ USHORT RemotePort,
    _In_ BOOLEAN IsIPv6
    );

typedef struct _SSL_STATISTICS {
    ULONG ActiveSessions;
    ULONG64 HandshakesInspected;
    ULONG64 SuspiciousDetected;
    ULONG KnownBadJA3Count;
    LARGE_INTEGER UpTime;
} SSL_STATISTICS, *PSSL_STATISTICS;

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
SslGetStatistics(
    _In_ PSSL_INSPECTOR Inspector,
    _Out_ PSSL_STATISTICS Stats
    );

//
// SslFreeSessionInfo — frees a snapshot returned by SslInspectClientHello.
// This is a pure free of the caller's copy — no list removal.
//
_IRQL_requires_max_(APC_LEVEL)
VOID
SslFreeSessionInfo(
    _In_ _Post_invalid_ PSSL_SESSION_INFO SessionInfo
    );

//
// SslCleanupStaleSessions — evicts sessions older than SSL_SESSION_STALE_MS.
// Call periodically (e.g., from a timer work item).
//
_IRQL_requires_max_(APC_LEVEL)
VOID
SslCleanupStaleSessions(
    _In_ PSSL_INSPECTOR Inspector
    );

#ifdef __cplusplus
}
#endif
