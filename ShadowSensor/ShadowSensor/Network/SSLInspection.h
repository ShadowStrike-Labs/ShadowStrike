/*++
    ShadowStrike Next-Generation Antivirus
    Module: SSLInspection.h
    
    Purpose: TLS/SSL inspection for encrypted traffic analysis.
    
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

#define SSL_POOL_TAG_SESSION    'SSLS'  // SSL - Session
#define SSL_POOL_TAG_CERT       'CSLS'  // SSL - Certificate

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
// TLS Suspicion Flags
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
// TLS Session
//=============================================================================

typedef struct _SSL_SESSION {
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
    SSL_SUSPICION SuspicionFlags;
    ULONG SuspicionScore;
    
    // Timing
    LARGE_INTEGER HandshakeTime;
    
    LIST_ENTRY ListEntry;
    
} SSL_SESSION, *PSSL_SESSION;

//=============================================================================
// SSL Inspector
//=============================================================================

typedef struct _SSL_INSPECTOR {
    BOOLEAN Initialized;
    
    // Sessions
    LIST_ENTRY SessionList;
    EX_PUSH_LOCK SessionLock;
    volatile LONG SessionCount;
    volatile LONG64 NextSessionId;
    
    // Known bad JA3
    LIST_ENTRY BadJA3List;
    EX_PUSH_LOCK BadJA3Lock;
    
    // Statistics
    struct {
        volatile LONG64 HandshakesInspected;
        volatile LONG64 SuspiciousDetected;
        LARGE_INTEGER StartTime;
    } Stats;
    
} SSL_INSPECTOR, *PSSL_INSPECTOR;

//=============================================================================
// Public API
//=============================================================================

NTSTATUS
SslInitialize(
    _Out_ PSSL_INSPECTOR* Inspector
    );

VOID
SslShutdown(
    _Inout_ PSSL_INSPECTOR Inspector
    );

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
    );

NTSTATUS
SslInspectServerHello(
    _In_ PSSL_INSPECTOR Inspector,
    _In_ PVOID RemoteAddress,
    _In_ USHORT RemotePort,
    _In_ BOOLEAN IsIPv6,
    _In_reads_bytes_(DataSize) PVOID ServerHello,
    _In_ ULONG DataSize
    );

NTSTATUS
SslCalculateJA3(
    _In_reads_bytes_(DataSize) PVOID ClientHello,
    _In_ ULONG DataSize,
    _Out_ PSSL_JA3 JA3
    );

NTSTATUS
SslAddBadJA3(
    _In_ PSSL_INSPECTOR Inspector,
    _In_ PUCHAR JA3Hash,
    _In_opt_ PCSTR MalwareFamily
    );

NTSTATUS
SslCheckJA3(
    _In_ PSSL_INSPECTOR Inspector,
    _In_ PUCHAR JA3Hash,
    _Out_ PBOOLEAN IsBad,
    _Out_writes_z_(FamilySize) PSTR MalwareFamily,
    _In_ ULONG FamilySize
    );

typedef struct _SSL_STATISTICS {
    ULONG ActiveSessions;
    ULONG64 HandshakesInspected;
    ULONG64 SuspiciousDetected;
    ULONG KnownBadJA3Count;
    LARGE_INTEGER UpTime;
} SSL_STATISTICS, *PSSL_STATISTICS;

NTSTATUS
SslGetStatistics(
    _In_ PSSL_INSPECTOR Inspector,
    _Out_ PSSL_STATISTICS Stats
    );

VOID
SslFreeSession(
    _In_ PSSL_SESSION Session
    );

#ifdef __cplusplus
}
#endif
