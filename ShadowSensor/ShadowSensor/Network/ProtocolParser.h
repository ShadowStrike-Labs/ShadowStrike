/*++
    ShadowStrike Next-Generation Antivirus
    Module: ProtocolParser.h

    Purpose: Network protocol parsing for HTTP/1.x, DNS, and other protocols.

    Threading: All parse functions require PASSIVE_LEVEL and acquire rundown
               protection on the parser, making concurrent parse + shutdown safe.

    Memory:    All output structures are allocated from PagedPool and owned by
               the caller. Body data is copied (not aliased) so the input buffer
               may be freed immediately after a successful parse.

    WARNING:   PP_HTTP_REQUEST and PP_HTTP_RESPONSE are large structures (~270KB).
               NEVER allocate them on the kernel stack. Always use pool allocation
               via the PpParseHTTP* functions.

    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>
#include <wdm.h>
#include "../../Shared/NetworkTypes.h"

//=============================================================================
// Pool Tags  (ShadowStrike Protocol Parser: 'SsPp', 'SsPh', 'SsPb')
//=============================================================================

#define PP_POOL_TAG_PARSER      'pPsS'  // SS Protocol Parser - Parser context
#define PP_POOL_TAG_HEADER      'hPsS'  // SS Protocol Parser - HTTP/DNS structs
#define PP_POOL_TAG_BODY        'bPsS'  // SS Protocol Parser - Body copy

//=============================================================================
// Configuration
//=============================================================================

#define PP_MAX_HEADER_SIZE              8192
#define PP_MAX_URL_LENGTH               2048
#define PP_MAX_HEADER_NAME_LENGTH       64
#define PP_MAX_HEADER_VALUE_LENGTH      4096
#define PP_MAX_HEADERS                  64

// Memory budgeting: maximum concurrent parsing allocations
#define PP_MAX_CONCURRENT_ALLOCS        256
#define PP_MAX_BODY_COPY_SIZE           (4 * 1024 * 1024)   // 4MB max body copy
#define PP_MAX_CONTENT_LENGTH           (64 * 1024 * 1024)  // 64MB max Content-Length

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
//     WARNING: Each instance is ~4KB. Do NOT place on stack.
//=============================================================================

typedef struct _PP_HTTP_HEADER {
    CHAR Name[PP_MAX_HEADER_NAME_LENGTH];
    CHAR Value[PP_MAX_HEADER_VALUE_LENGTH];
} PP_HTTP_HEADER, *PPP_HTTP_HEADER;

//=============================================================================
// HTTP Request
//     WARNING: ~270KB structure. Pool-allocate ONLY.
//=============================================================================

typedef struct _PP_HTTP_REQUEST {
    // Request line
    PP_HTTP_METHOD Method;
    CHAR URI[PP_MAX_URL_LENGTH];
    CHAR Version[16];

    // Headers
    PP_HTTP_HEADER Headers[PP_MAX_HEADERS];
    ULONG HeaderCount;

    // Common headers (extracted for convenience)
    CHAR Host[256];
    CHAR UserAgent[512];
    CHAR ContentType[128];
    ULONG ContentLength;
    CHAR Cookie[1024];
    CHAR Referer[PP_MAX_URL_LENGTH];

    // Body (owned copy — caller must free via PpFreeHTTPRequest)
    PVOID Body;
    ULONG BodySize;

    // Suspicion analysis
    ULONG SuspicionScore;
    BOOLEAN IsSuspicious;

} PP_HTTP_REQUEST, *PPP_HTTP_REQUEST;

//=============================================================================
// HTTP Response
//     WARNING: ~270KB structure. Pool-allocate ONLY.
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

    // Body (owned copy — caller must free via PpFreeHTTPResponse)
    PVOID Body;
    ULONG BodySize;

} PP_HTTP_RESPONSE, *PPP_HTTP_RESPONSE;

//=============================================================================
// DNS Packet
//=============================================================================

#define PP_MAX_DNS_QUESTIONS    8
#define PP_MAX_DNS_ANSWERS      16

typedef struct _PP_DNS_PACKET {
    // Raw header counts (as received on the wire)
    USHORT RawQuestionCount;
    USHORT RawAnswerCount;
    USHORT RawAuthorityCount;
    USHORT RawAdditionalCount;

    // Header
    USHORT TransactionId;
    USHORT Flags;
    USHORT QuestionCount;       // Clamped to PP_MAX_DNS_QUESTIONS
    USHORT AnswerCount;         // Clamped to PP_MAX_DNS_ANSWERS
    USHORT AuthorityCount;
    USHORT AdditionalCount;

    // Questions
    struct {
        CHAR Name[256];
        USHORT Type;
        USHORT Class;
    } Questions[PP_MAX_DNS_QUESTIONS];

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
    } Answers[PP_MAX_DNS_ANSWERS];

    // Decoded flags
    BOOLEAN IsQuery;
    BOOLEAN IsResponse;
    BOOLEAN IsRecursionDesired;
    BOOLEAN IsRecursionAvailable;
    USHORT ResponseCode;

} PP_DNS_PACKET, *PPP_DNS_PACKET;

//=============================================================================
// Protocol Parser Context
//=============================================================================

typedef struct _PP_PARSER {
    BOOLEAN Initialized;

    // Rundown protection for safe concurrent parse + shutdown
    EX_RUNDOWN_REF RundownRef;

    // Memory budgeting: limit concurrent outstanding allocations
    volatile LONG ActiveAllocations;

    // Statistics (interlocked, snapshot under lock for consistency)
    KSPIN_LOCK StatsLock;
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

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PpInitialize(
    _Out_ PPP_PARSER* Parser
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
PpShutdown(
    _Inout_ PPP_PARSER* Parser
    );

// HTTP Parsing (PASSIVE_LEVEL only, output is caller-owned)
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PpParseHTTPRequest(
    _In_ PPP_PARSER Parser,
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _Out_ PPP_HTTP_REQUEST* Request
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PpParseHTTPResponse(
    _In_ PPP_PARSER Parser,
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _Out_ PPP_HTTP_RESPONSE* Response
    );

_IRQL_requires_max_(APC_LEVEL)
VOID
PpFreeHTTPRequest(
    _In_opt_ _Post_invalid_ PPP_HTTP_REQUEST Request
    );

_IRQL_requires_max_(APC_LEVEL)
VOID
PpFreeHTTPResponse(
    _In_opt_ _Post_invalid_ PPP_HTTP_RESPONSE Response
    );

// DNS Parsing
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PpParseDNSPacket(
    _In_ PPP_PARSER Parser,
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _Out_ PPP_DNS_PACKET* Packet
    );

_IRQL_requires_max_(APC_LEVEL)
VOID
PpFreeDNSPacket(
    _In_opt_ _Post_invalid_ PPP_DNS_PACKET Packet
    );

// Utility functions — safe at any IRQL <= DISPATCH (read-only, no paged access)
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
PpIsHTTPData(
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
PpIsDNSData(
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize
    );

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
PpExtractHostFromRequest(
    _In_ PPP_HTTP_REQUEST Request,
    _Out_writes_z_(HostSize) PSTR Host,
    _In_ ULONG HostSize
    );

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
PpExtractURLFromRequest(
    _In_ PPP_HTTP_REQUEST Request,
    _In_ BOOLEAN IsSecure,
    _Out_writes_z_(URLSize) PSTR URL,
    _In_ ULONG URLSize
    );

// Statistics
typedef struct _PP_STATISTICS {
    ULONG64 HTTPRequestsParsed;
    ULONG64 HTTPResponsesParsed;
    ULONG64 DNSPacketsParsed;
    ULONG64 ParseErrors;
    LONG ActiveAllocations;
    LARGE_INTEGER UpTime;
} PP_STATISTICS, *PPP_STATISTICS;

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
PpGetStatistics(
    _In_ PPP_PARSER Parser,
    _Out_ PPP_STATISTICS Stats
    );

#ifdef __cplusplus
}
#endif
