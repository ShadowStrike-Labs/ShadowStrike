/*++
    ShadowStrike Next-Generation Antivirus
    Module: ProtocolParser.h
    
    Purpose: Network protocol parsing for HTTP, DNS, and other protocols.
    
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

#define PP_POOL_TAG_PARSER      'PPPP'  // Protocol Parser - Parser
#define PP_POOL_TAG_HEADER      'HPPP'  // Protocol Parser - Header

//=============================================================================
// Configuration
//=============================================================================

#define PP_MAX_HEADER_SIZE              8192
#define PP_MAX_URL_LENGTH               2048
#define PP_MAX_HEADER_NAME_LENGTH       64
#define PP_MAX_HEADER_VALUE_LENGTH      4096
#define PP_MAX_HEADERS                  64

//=============================================================================
// HTTP Methods
//=============================================================================

typedef enum _PP_HTTP_METHOD {
    HttpMethod_Unknown = 0,
    HttpMethod_GET,
    HttpMethod_POST,
    HttpMethod_PUT,
    HttpMethod_DELETE,
    HttpMethod_HEAD,
    HttpMethod_OPTIONS,
    HttpMethod_PATCH,
    HttpMethod_CONNECT,
    HttpMethod_TRACE,
} PP_HTTP_METHOD;

//=============================================================================
// HTTP Header
//=============================================================================

typedef struct _PP_HTTP_HEADER {
    CHAR Name[PP_MAX_HEADER_NAME_LENGTH];
    CHAR Value[PP_MAX_HEADER_VALUE_LENGTH];
} PP_HTTP_HEADER, *PPP_HTTP_HEADER;

//=============================================================================
// HTTP Request
//=============================================================================

typedef struct _PP_HTTP_REQUEST {
    // Request line
    PP_HTTP_METHOD Method;
    CHAR URI[PP_MAX_URL_LENGTH];
    CHAR Version[16];
    
    // Headers
    PP_HTTP_HEADER Headers[PP_MAX_HEADERS];
    ULONG HeaderCount;
    
    // Common headers
    CHAR Host[256];
    CHAR UserAgent[512];
    CHAR ContentType[128];
    ULONG ContentLength;
    CHAR Cookie[1024];
    CHAR Referer[PP_MAX_URL_LENGTH];
    
    // Body
    PVOID Body;
    ULONG BodySize;
    
    // Suspicion
    ULONG SuspicionScore;
    BOOLEAN IsSuspicious;
    
} PP_HTTP_REQUEST, *PPP_HTTP_REQUEST;

//=============================================================================
// HTTP Response
//=============================================================================

typedef struct _PP_HTTP_RESPONSE {
    // Status line
    CHAR Version[16];
    USHORT StatusCode;
    CHAR ReasonPhrase[64];
    
    // Headers
    PP_HTTP_HEADER Headers[PP_MAX_HEADERS];
    ULONG HeaderCount;
    
    // Common headers
    CHAR ContentType[128];
    ULONG ContentLength;
    CHAR Server[256];
    CHAR SetCookie[1024];
    
    // Body
    PVOID Body;
    ULONG BodySize;
    
} PP_HTTP_RESPONSE, *PPP_HTTP_RESPONSE;

//=============================================================================
// DNS Packet
//=============================================================================

typedef struct _PP_DNS_PACKET {
    // Header
    USHORT TransactionId;
    USHORT Flags;
    USHORT QuestionCount;
    USHORT AnswerCount;
    USHORT AuthorityCount;
    USHORT AdditionalCount;
    
    // Questions
    struct {
        CHAR Name[256];
        USHORT Type;
        USHORT Class;
    } Questions[8];
    
    // Answers
    struct {
        CHAR Name[256];
        USHORT Type;
        USHORT Class;
        ULONG TTL;
        union {
            IN_ADDR IPv4;
            IN6_ADDR IPv6;
            CHAR CNAME[256];
            CHAR TXT[512];
        } Data;
    } Answers[16];
    
    // Flags
    BOOLEAN IsQuery;
    BOOLEAN IsResponse;
    BOOLEAN IsRecursionDesired;
    BOOLEAN IsRecursionAvailable;
    USHORT ResponseCode;
    
} PP_DNS_PACKET, *PPP_DNS_PACKET;

//=============================================================================
// Protocol Parser
//=============================================================================

typedef struct _PP_PARSER {
    BOOLEAN Initialized;
    
    // Statistics
    struct {
        volatile LONG64 HTTPRequestsParsed;
        volatile LONG64 HTTPResponsesParsed;
        volatile LONG64 DNSPacketsParsed;
        volatile LONG64 ParseErrors;
        LARGE_INTEGER StartTime;
    } Stats;
    
} PP_PARSER, *PPP_PARSER;

//=============================================================================
// Public API
//=============================================================================

NTSTATUS
PpInitialize(
    _Out_ PPP_PARSER* Parser
    );

VOID
PpShutdown(
    _Inout_ PPP_PARSER Parser
    );

// HTTP Parsing
NTSTATUS
PpParseHTTPRequest(
    _In_ PPP_PARSER Parser,
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _Out_ PPP_HTTP_REQUEST* Request
    );

NTSTATUS
PpParseHTTPResponse(
    _In_ PPP_PARSER Parser,
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _Out_ PPP_HTTP_RESPONSE* Response
    );

VOID
PpFreeHTTPRequest(
    _In_ PPP_HTTP_REQUEST Request
    );

VOID
PpFreeHTTPResponse(
    _In_ PPP_HTTP_RESPONSE Response
    );

// DNS Parsing
NTSTATUS
PpParseDNSPacket(
    _In_ PPP_PARSER Parser,
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _Out_ PPP_DNS_PACKET* Packet
    );

VOID
PpFreeDNSPacket(
    _In_ PPP_DNS_PACKET Packet
    );

// Utility functions
BOOLEAN
PpIsHTTPData(
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize
    );

BOOLEAN
PpIsDNSData(
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize
    );

NTSTATUS
PpExtractHostFromRequest(
    _In_ PPP_HTTP_REQUEST Request,
    _Out_writes_z_(HostSize) PSTR Host,
    _In_ ULONG HostSize
    );

NTSTATUS
PpExtractURLFromRequest(
    _In_ PPP_HTTP_REQUEST Request,
    _Out_writes_z_(URLSize) PSTR URL,
    _In_ ULONG URLSize
    );

// Statistics
typedef struct _PP_STATISTICS {
    ULONG64 HTTPRequestsParsed;
    ULONG64 HTTPResponsesParsed;
    ULONG64 DNSPacketsParsed;
    ULONG64 ParseErrors;
    LARGE_INTEGER UpTime;
} PP_STATISTICS, *PPP_STATISTICS;

NTSTATUS
PpGetStatistics(
    _In_ PPP_PARSER Parser,
    _Out_ PPP_STATISTICS Stats
    );

#ifdef __cplusplus
}
#endif
