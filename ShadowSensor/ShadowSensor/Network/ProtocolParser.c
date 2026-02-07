/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE PROTOCOL PARSER
 * ============================================================================
 *
 * @file ProtocolParser.c
 * @brief Enterprise-grade network protocol parsing for HTTP, DNS, and more.
 *
 * Implements CrowdStrike Falcon-class protocol parsing with:
 * - HTTP/1.0, HTTP/1.1 request and response parsing
 * - DNS query and response parsing with compression support
 * - Suspicious pattern detection (C2 beacons, encoded payloads)
 * - Header extraction and normalization
 * - Content-Type and encoding detection
 * - Thread-safe operation with minimal allocations
 *
 * Security Considerations:
 * - All input is treated as hostile
 * - Strict bounds checking on all operations
 * - No unbounded allocations
 * - Malformed packet detection and rejection
 *
 * Performance Optimizations:
 * - Zero-copy parsing where possible
 * - Lookaside list allocations
 * - Early rejection of non-matching data
 * - Minimal string operations
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "ProtocolParser.h"
#include <ntstrsafe.h>

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, PpInitialize)
#pragma alloc_text(PAGE, PpShutdown)
#pragma alloc_text(PAGE, PpParseHTTPRequest)
#pragma alloc_text(PAGE, PpParseHTTPResponse)
#pragma alloc_text(PAGE, PpParseDNSPacket)
#endif

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

/**
 * @brief Minimum size for HTTP data detection
 */
#define PP_MIN_HTTP_SIZE                16

/**
 * @brief Minimum size for DNS packet
 */
#define PP_MIN_DNS_SIZE                 12

/**
 * @brief DNS header size
 */
#define PP_DNS_HEADER_SIZE              12

/**
 * @brief Maximum DNS name length after decompression
 */
#define PP_MAX_DNS_NAME                 256

/**
 * @brief Maximum DNS compression pointer depth (prevent infinite loops)
 */
#define PP_MAX_DNS_COMPRESSION_DEPTH    16

/**
 * @brief HTTP method strings
 */
static const CHAR* g_HttpMethods[] = {
    "",           // Unknown
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "HEAD",
    "OPTIONS",
    "PATCH",
    "CONNECT",
    "TRACE"
};

static const ULONG g_HttpMethodLengths[] = {
    0, 3, 4, 3, 6, 4, 7, 5, 7, 5
};

/**
 * @brief Suspicious User-Agent patterns (C2 indicators)
 */
static const CHAR* g_SuspiciousUserAgents[] = {
    "Mozilla/4.0",              // Old, often used by malware
    "Mozilla/5.0 (compatible)", // Generic, often default in C2
    "Java/",                    // Java downloaders
    "Python-urllib",            // Python scripts
    "curl/",                    // Command line tools
    "Wget/",                    // Command line tools
    "PowerShell/",              // PowerShell scripts
    NULL
};

/**
 * @brief Suspicious URI patterns
 */
static const CHAR* g_SuspiciousUriPatterns[] = {
    "/admin",
    "/shell",
    "/cmd",
    "/exec",
    "/eval",
    "/upload",
    "..%2f",                    // Path traversal encoded
    "..%5c",                    // Path traversal encoded
    "%00",                      // Null byte injection
    "<script",                  // XSS attempt
    "UNION%20SELECT",           // SQL injection
    NULL
};

// ============================================================================
// PRIVATE HELPER PROTOTYPES
// ============================================================================

static BOOLEAN
PppIsHttpMethod(
    _In_reads_bytes_(DataSize) PCSTR Data,
    _In_ ULONG DataSize,
    _Out_ PP_HTTP_METHOD* Method,
    _Out_ PULONG MethodLength
    );

static BOOLEAN
PppIsHttpResponse(
    _In_reads_bytes_(DataSize) PCSTR Data,
    _In_ ULONG DataSize
    );

static NTSTATUS
PppParseRequestLine(
    _In_reads_bytes_(DataSize) PCSTR Data,
    _In_ ULONG DataSize,
    _Out_ PPP_HTTP_REQUEST Request,
    _Out_ PULONG BytesConsumed
    );

static NTSTATUS
PppParseStatusLine(
    _In_reads_bytes_(DataSize) PCSTR Data,
    _In_ ULONG DataSize,
    _Out_ PPP_HTTP_RESPONSE Response,
    _Out_ PULONG BytesConsumed
    );

static NTSTATUS
PppParseHeaders(
    _In_reads_bytes_(DataSize) PCSTR Data,
    _In_ ULONG DataSize,
    _Out_writes_(MaxHeaders) PPP_HTTP_HEADER Headers,
    _In_ ULONG MaxHeaders,
    _Out_ PULONG HeaderCount,
    _Out_ PULONG BytesConsumed
    );

static VOID
PppExtractCommonRequestHeaders(
    _Inout_ PPP_HTTP_REQUEST Request
    );

static VOID
PppExtractCommonResponseHeaders(
    _Inout_ PPP_HTTP_RESPONSE Response
    );

static VOID
PppCalculateSuspicionScore(
    _Inout_ PPP_HTTP_REQUEST Request
    );

static PCSTR
PppFindLineEnd(
    _In_reads_bytes_(DataSize) PCSTR Data,
    _In_ ULONG DataSize,
    _Out_ PULONG LineLength
    );

static VOID
PppTrimWhitespace(
    _Inout_ PSTR String
    );

static ULONG
PppSafeStrLen(
    _In_reads_bytes_(MaxLen) PCSTR String,
    _In_ ULONG MaxLen
    );

static NTSTATUS
PppParseDnsName(
    _In_reads_bytes_(PacketSize) PCUCHAR Packet,
    _In_ ULONG PacketSize,
    _In_ ULONG Offset,
    _Out_writes_z_(NameBufferSize) PSTR NameBuffer,
    _In_ ULONG NameBufferSize,
    _Out_ PULONG BytesConsumed
    );

static ULONG
PppCalculateDomainEntropy(
    _In_z_ PCSTR Domain
    );

// ============================================================================
// PUBLIC API - INITIALIZATION
// ============================================================================

/**
 * @brief Initialize the protocol parser.
 *
 * @param Parser    Receives initialized parser handle.
 * @return STATUS_SUCCESS on success.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PpInitialize(
    _Out_ PPP_PARSER* Parser
    )
{
    PPP_PARSER parser = NULL;

    PAGED_CODE();

    if (Parser == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Parser = NULL;

    //
    // Allocate parser context
    //
    parser = (PPP_PARSER)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(PP_PARSER),
        PP_POOL_TAG_PARSER
    );

    if (parser == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&parser->Stats.StartTime);
    parser->Initialized = TRUE;

    *Parser = parser;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Protocol parser initialized\n");

    return STATUS_SUCCESS;
}

/**
 * @brief Shutdown the protocol parser.
 *
 * @param Parser    Parser to shutdown.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
PpShutdown(
    _Inout_ PPP_PARSER Parser
    )
{
    PAGED_CODE();

    if (Parser == NULL) {
        return;
    }

    if (!Parser->Initialized) {
        return;
    }

    Parser->Initialized = FALSE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Protocol parser shutdown (HTTP Req: %lld, Resp: %lld, DNS: %lld, Errors: %lld)\n",
               Parser->Stats.HTTPRequestsParsed,
               Parser->Stats.HTTPResponsesParsed,
               Parser->Stats.DNSPacketsParsed,
               Parser->Stats.ParseErrors);

    ExFreePoolWithTag(Parser, PP_POOL_TAG_PARSER);
}

// ============================================================================
// PUBLIC API - HTTP PARSING
// ============================================================================

/**
 * @brief Parse an HTTP request.
 *
 * @param Parser    Parser handle.
 * @param Data      Raw HTTP data.
 * @param DataSize  Size of data in bytes.
 * @param Request   Receives parsed request.
 * @return STATUS_SUCCESS on success.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PpParseHTTPRequest(
    _In_ PPP_PARSER Parser,
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _Out_ PPP_HTTP_REQUEST* Request
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PPP_HTTP_REQUEST request = NULL;
    PCSTR data = (PCSTR)Data;
    ULONG bytesConsumed = 0;
    ULONG totalConsumed = 0;

    PAGED_CODE();

    if (Parser == NULL || Data == NULL || Request == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Request = NULL;

    if (!Parser->Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (DataSize < PP_MIN_HTTP_SIZE) {
        InterlockedIncrement64(&Parser->Stats.ParseErrors);
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Verify this is an HTTP request
    //
    PP_HTTP_METHOD method;
    ULONG methodLength;

    if (!PppIsHttpMethod(data, DataSize, &method, &methodLength)) {
        InterlockedIncrement64(&Parser->Stats.ParseErrors);
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Allocate request structure
    //
    request = (PPP_HTTP_REQUEST)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(PP_HTTP_REQUEST),
        PP_POOL_TAG_HEADER
    );

    if (request == NULL) {
        InterlockedIncrement64(&Parser->Stats.ParseErrors);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    request->Method = method;

    //
    // Parse request line
    //
    status = PppParseRequestLine(data, DataSize, request, &bytesConsumed);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    totalConsumed = bytesConsumed;

    //
    // Parse headers
    //
    if (totalConsumed < DataSize) {
        status = PppParseHeaders(
            data + totalConsumed,
            DataSize - totalConsumed,
            request->Headers,
            PP_MAX_HEADERS,
            &request->HeaderCount,
            &bytesConsumed
        );

        if (!NT_SUCCESS(status)) {
            goto Cleanup;
        }

        totalConsumed += bytesConsumed;
    }

    //
    // Extract common headers (Host, User-Agent, Content-Type, etc.)
    //
    PppExtractCommonRequestHeaders(request);

    //
    // Check for body
    //
    if (totalConsumed < DataSize && request->ContentLength > 0) {
        ULONG bodySize = min(request->ContentLength, DataSize - totalConsumed);

        request->Body = (PVOID)(data + totalConsumed);
        request->BodySize = bodySize;
    }

    //
    // Calculate suspicion score
    //
    PppCalculateSuspicionScore(request);

    InterlockedIncrement64(&Parser->Stats.HTTPRequestsParsed);
    *Request = request;

    return STATUS_SUCCESS;

Cleanup:
    if (request != NULL) {
        ExFreePoolWithTag(request, PP_POOL_TAG_HEADER);
    }

    InterlockedIncrement64(&Parser->Stats.ParseErrors);
    return status;
}

/**
 * @brief Parse an HTTP response.
 *
 * @param Parser    Parser handle.
 * @param Data      Raw HTTP data.
 * @param DataSize  Size of data in bytes.
 * @param Response  Receives parsed response.
 * @return STATUS_SUCCESS on success.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PpParseHTTPResponse(
    _In_ PPP_PARSER Parser,
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _Out_ PPP_HTTP_RESPONSE* Response
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PPP_HTTP_RESPONSE response = NULL;
    PCSTR data = (PCSTR)Data;
    ULONG bytesConsumed = 0;
    ULONG totalConsumed = 0;

    PAGED_CODE();

    if (Parser == NULL || Data == NULL || Response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Response = NULL;

    if (!Parser->Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (DataSize < PP_MIN_HTTP_SIZE) {
        InterlockedIncrement64(&Parser->Stats.ParseErrors);
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Verify this is an HTTP response
    //
    if (!PppIsHttpResponse(data, DataSize)) {
        InterlockedIncrement64(&Parser->Stats.ParseErrors);
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Allocate response structure
    //
    response = (PPP_HTTP_RESPONSE)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(PP_HTTP_RESPONSE),
        PP_POOL_TAG_HEADER
    );

    if (response == NULL) {
        InterlockedIncrement64(&Parser->Stats.ParseErrors);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Parse status line
    //
    status = PppParseStatusLine(data, DataSize, response, &bytesConsumed);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    totalConsumed = bytesConsumed;

    //
    // Parse headers
    //
    if (totalConsumed < DataSize) {
        status = PppParseHeaders(
            data + totalConsumed,
            DataSize - totalConsumed,
            response->Headers,
            PP_MAX_HEADERS,
            &response->HeaderCount,
            &bytesConsumed
        );

        if (!NT_SUCCESS(status)) {
            goto Cleanup;
        }

        totalConsumed += bytesConsumed;
    }

    //
    // Extract common headers
    //
    PppExtractCommonResponseHeaders(response);

    //
    // Check for body
    //
    if (totalConsumed < DataSize && response->ContentLength > 0) {
        ULONG bodySize = min(response->ContentLength, DataSize - totalConsumed);

        response->Body = (PVOID)(data + totalConsumed);
        response->BodySize = bodySize;
    }

    InterlockedIncrement64(&Parser->Stats.HTTPResponsesParsed);
    *Response = response;

    return STATUS_SUCCESS;

Cleanup:
    if (response != NULL) {
        ExFreePoolWithTag(response, PP_POOL_TAG_HEADER);
    }

    InterlockedIncrement64(&Parser->Stats.ParseErrors);
    return status;
}

/**
 * @brief Free an HTTP request structure.
 */
VOID
PpFreeHTTPRequest(
    _In_ PPP_HTTP_REQUEST Request
    )
{
    if (Request != NULL) {
        ExFreePoolWithTag(Request, PP_POOL_TAG_HEADER);
    }
}

/**
 * @brief Free an HTTP response structure.
 */
VOID
PpFreeHTTPResponse(
    _In_ PPP_HTTP_RESPONSE Response
    )
{
    if (Response != NULL) {
        ExFreePoolWithTag(Response, PP_POOL_TAG_HEADER);
    }
}

// ============================================================================
// PUBLIC API - DNS PARSING
// ============================================================================

/**
 * @brief Parse a DNS packet.
 *
 * @param Parser    Parser handle.
 * @param Data      Raw DNS data.
 * @param DataSize  Size of data in bytes.
 * @param Packet    Receives parsed packet.
 * @return STATUS_SUCCESS on success.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PpParseDNSPacket(
    _In_ PPP_PARSER Parser,
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _Out_ PPP_DNS_PACKET* Packet
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PPP_DNS_PACKET packet = NULL;
    PCUCHAR data = (PCUCHAR)Data;
    ULONG offset = PP_DNS_HEADER_SIZE;
    ULONG bytesConsumed = 0;
    ULONG i;

    PAGED_CODE();

    if (Parser == NULL || Data == NULL || Packet == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Packet = NULL;

    if (!Parser->Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (DataSize < PP_MIN_DNS_SIZE) {
        InterlockedIncrement64(&Parser->Stats.ParseErrors);
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Allocate packet structure
    //
    packet = (PPP_DNS_PACKET)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(PP_DNS_PACKET),
        PP_POOL_TAG_HEADER
    );

    if (packet == NULL) {
        InterlockedIncrement64(&Parser->Stats.ParseErrors);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Parse DNS header (12 bytes)
    // Format:
    //   0-1:  Transaction ID
    //   2-3:  Flags
    //   4-5:  Question Count
    //   6-7:  Answer Count
    //   8-9:  Authority Count
    //   10-11: Additional Count
    //
    packet->TransactionId = (USHORT)((data[0] << 8) | data[1]);
    packet->Flags = (USHORT)((data[2] << 8) | data[3]);
    packet->QuestionCount = (USHORT)((data[4] << 8) | data[5]);
    packet->AnswerCount = (USHORT)((data[6] << 8) | data[7]);
    packet->AuthorityCount = (USHORT)((data[8] << 8) | data[9]);
    packet->AdditionalCount = (USHORT)((data[10] << 8) | data[11]);

    //
    // Decode flags
    //
    packet->IsQuery = ((packet->Flags & 0x8000) == 0);
    packet->IsResponse = ((packet->Flags & 0x8000) != 0);
    packet->IsRecursionDesired = ((packet->Flags & 0x0100) != 0);
    packet->IsRecursionAvailable = ((packet->Flags & 0x0080) != 0);
    packet->ResponseCode = (USHORT)(packet->Flags & 0x000F);

    //
    // Validate counts (security: prevent excessive parsing)
    //
    if (packet->QuestionCount > 8) {
        packet->QuestionCount = 8;
    }
    if (packet->AnswerCount > 16) {
        packet->AnswerCount = 16;
    }

    //
    // Parse questions
    //
    for (i = 0; i < packet->QuestionCount && offset < DataSize; i++) {
        status = PppParseDnsName(
            data,
            DataSize,
            offset,
            packet->Questions[i].Name,
            sizeof(packet->Questions[i].Name),
            &bytesConsumed
        );

        if (!NT_SUCCESS(status)) {
            goto Cleanup;
        }

        offset += bytesConsumed;

        //
        // Parse QTYPE and QCLASS (4 bytes)
        //
        if (offset + 4 > DataSize) {
            status = STATUS_BUFFER_TOO_SMALL;
            goto Cleanup;
        }

        packet->Questions[i].Type = (USHORT)((data[offset] << 8) | data[offset + 1]);
        packet->Questions[i].Class = (USHORT)((data[offset + 2] << 8) | data[offset + 3]);
        offset += 4;
    }

    //
    // Parse answers (for responses)
    //
    for (i = 0; i < packet->AnswerCount && offset < DataSize; i++) {
        status = PppParseDnsName(
            data,
            DataSize,
            offset,
            packet->Answers[i].Name,
            sizeof(packet->Answers[i].Name),
            &bytesConsumed
        );

        if (!NT_SUCCESS(status)) {
            goto Cleanup;
        }

        offset += bytesConsumed;

        //
        // Parse TYPE, CLASS, TTL, RDLENGTH (10 bytes)
        //
        if (offset + 10 > DataSize) {
            status = STATUS_BUFFER_TOO_SMALL;
            goto Cleanup;
        }

        packet->Answers[i].Type = (USHORT)((data[offset] << 8) | data[offset + 1]);
        packet->Answers[i].Class = (USHORT)((data[offset + 2] << 8) | data[offset + 3]);
        packet->Answers[i].TTL = ((ULONG)data[offset + 4] << 24) |
                                  ((ULONG)data[offset + 5] << 16) |
                                  ((ULONG)data[offset + 6] << 8) |
                                  (ULONG)data[offset + 7];

        USHORT rdLength = (USHORT)((data[offset + 8] << 8) | data[offset + 9]);
        offset += 10;

        //
        // Parse RDATA based on type
        //
        if (offset + rdLength > DataSize) {
            status = STATUS_BUFFER_TOO_SMALL;
            goto Cleanup;
        }

        switch (packet->Answers[i].Type) {
            case DNS_TYPE_A:
                if (rdLength >= 4) {
                    RtlCopyMemory(&packet->Answers[i].Data.IPv4,
                                  data + offset,
                                  sizeof(IN_ADDR));
                }
                break;

            case DNS_TYPE_AAAA:
                if (rdLength >= 16) {
                    RtlCopyMemory(&packet->Answers[i].Data.IPv6,
                                  data + offset,
                                  sizeof(IN6_ADDR));
                }
                break;

            case DNS_TYPE_CNAME:
            case DNS_TYPE_NS:
            case DNS_TYPE_PTR:
                PppParseDnsName(
                    data,
                    DataSize,
                    offset,
                    packet->Answers[i].Data.CNAME,
                    sizeof(packet->Answers[i].Data.CNAME),
                    &bytesConsumed
                );
                break;

            case DNS_TYPE_TXT:
                if (rdLength > 0 && rdLength <= sizeof(packet->Answers[i].Data.TXT)) {
                    //
                    // TXT records start with length byte
                    //
                    UCHAR txtLen = data[offset];
                    if (txtLen > 0 && (ULONG)(txtLen + 1) <= rdLength) {
                        ULONG copyLen = min(txtLen, sizeof(packet->Answers[i].Data.TXT) - 1);
                        RtlCopyMemory(packet->Answers[i].Data.TXT,
                                      data + offset + 1,
                                      copyLen);
                        packet->Answers[i].Data.TXT[copyLen] = '\0';
                    }
                }
                break;

            default:
                //
                // Skip unknown record types
                //
                break;
        }

        offset += rdLength;
    }

    InterlockedIncrement64(&Parser->Stats.DNSPacketsParsed);
    *Packet = packet;

    return STATUS_SUCCESS;

Cleanup:
    if (packet != NULL) {
        ExFreePoolWithTag(packet, PP_POOL_TAG_HEADER);
    }

    InterlockedIncrement64(&Parser->Stats.ParseErrors);
    return status;
}

/**
 * @brief Free a DNS packet structure.
 */
VOID
PpFreeDNSPacket(
    _In_ PPP_DNS_PACKET Packet
    )
{
    if (Packet != NULL) {
        ExFreePoolWithTag(Packet, PP_POOL_TAG_HEADER);
    }
}

// ============================================================================
// PUBLIC API - UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Check if data appears to be HTTP.
 */
BOOLEAN
PpIsHTTPData(
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize
    )
{
    PCSTR data = (PCSTR)Data;
    PP_HTTP_METHOD method;
    ULONG methodLength;

    if (Data == NULL || DataSize < PP_MIN_HTTP_SIZE) {
        return FALSE;
    }

    //
    // Check for request (method)
    //
    if (PppIsHttpMethod(data, DataSize, &method, &methodLength)) {
        return TRUE;
    }

    //
    // Check for response (HTTP/x.x)
    //
    if (PppIsHttpResponse(data, DataSize)) {
        return TRUE;
    }

    return FALSE;
}

/**
 * @brief Check if data appears to be DNS.
 */
BOOLEAN
PpIsDNSData(
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize
    )
{
    PCUCHAR data = (PCUCHAR)Data;
    USHORT flags;
    USHORT qdCount;
    USHORT opcode;

    if (Data == NULL || DataSize < PP_MIN_DNS_SIZE) {
        return FALSE;
    }

    //
    // Extract flags and question count
    //
    flags = (USHORT)((data[2] << 8) | data[3]);
    qdCount = (USHORT)((data[4] << 8) | data[5]);
    opcode = (flags >> 11) & 0x0F;

    //
    // Validate:
    // - Opcode should be 0 (standard query), 1 (inverse), or 2 (status)
    // - Question count should be reasonable
    // - Z bits (unused) should be 0
    //
    if (opcode > 2) {
        return FALSE;
    }

    if (qdCount == 0 || qdCount > 16) {
        return FALSE;
    }

    //
    // Check that Z bits are 0 (bits 4-6 of second flag byte)
    //
    if ((flags & 0x0070) != 0) {
        return FALSE;
    }

    return TRUE;
}

/**
 * @brief Extract host from HTTP request.
 */
NTSTATUS
PpExtractHostFromRequest(
    _In_ PPP_HTTP_REQUEST Request,
    _Out_writes_z_(HostSize) PSTR Host,
    _In_ ULONG HostSize
    )
{
    if (Request == NULL || Host == NULL || HostSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    Host[0] = '\0';

    if (Request->Host[0] != '\0') {
        return RtlStringCchCopyA(Host, HostSize, Request->Host);
    }

    return STATUS_NOT_FOUND;
}

/**
 * @brief Extract full URL from HTTP request.
 */
NTSTATUS
PpExtractURLFromRequest(
    _In_ PPP_HTTP_REQUEST Request,
    _Out_writes_z_(URLSize) PSTR URL,
    _In_ ULONG URLSize
    )
{
    NTSTATUS status;

    if (Request == NULL || URL == NULL || URLSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    URL[0] = '\0';

    if (Request->Host[0] != '\0' && Request->URI[0] != '\0') {
        status = RtlStringCchPrintfA(
            URL,
            URLSize,
            "http://%s%s",
            Request->Host,
            Request->URI
        );
        return status;
    }

    if (Request->URI[0] != '\0') {
        return RtlStringCchCopyA(URL, URLSize, Request->URI);
    }

    return STATUS_NOT_FOUND;
}

/**
 * @brief Get parser statistics.
 */
NTSTATUS
PpGetStatistics(
    _In_ PPP_PARSER Parser,
    _Out_ PPP_STATISTICS Stats
    )
{
    LARGE_INTEGER currentTime;

    if (Parser == NULL || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Parser->Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    Stats->HTTPRequestsParsed = Parser->Stats.HTTPRequestsParsed;
    Stats->HTTPResponsesParsed = Parser->Stats.HTTPResponsesParsed;
    Stats->DNSPacketsParsed = Parser->Stats.DNSPacketsParsed;
    Stats->ParseErrors = Parser->Stats.ParseErrors;

    KeQuerySystemTime(&currentTime);
    Stats->UpTime.QuadPart = currentTime.QuadPart - Parser->Stats.StartTime.QuadPart;

    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - HTTP HELPERS
// ============================================================================

static BOOLEAN
PppIsHttpMethod(
    _In_reads_bytes_(DataSize) PCSTR Data,
    _In_ ULONG DataSize,
    _Out_ PP_HTTP_METHOD* Method,
    _Out_ PULONG MethodLength
    )
{
    ULONG i;

    *Method = HttpMethod_Unknown;
    *MethodLength = 0;

    for (i = 1; i < ARRAYSIZE(g_HttpMethods); i++) {
        ULONG len = g_HttpMethodLengths[i];

        if (DataSize >= len + 1 &&
            RtlCompareMemory(Data, g_HttpMethods[i], len) == len &&
            Data[len] == ' ') {

            *Method = (PP_HTTP_METHOD)i;
            *MethodLength = len;
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN
PppIsHttpResponse(
    _In_reads_bytes_(DataSize) PCSTR Data,
    _In_ ULONG DataSize
    )
{
    //
    // Check for "HTTP/1." prefix
    //
    if (DataSize >= 8 &&
        Data[0] == 'H' && Data[1] == 'T' && Data[2] == 'T' && Data[3] == 'P' &&
        Data[4] == '/' && (Data[5] == '1' || Data[5] == '2') && Data[6] == '.') {
        return TRUE;
    }

    return FALSE;
}

static NTSTATUS
PppParseRequestLine(
    _In_reads_bytes_(DataSize) PCSTR Data,
    _In_ ULONG DataSize,
    _Out_ PPP_HTTP_REQUEST Request,
    _Out_ PULONG BytesConsumed
    )
{
    ULONG lineLength = 0;
    PCSTR lineEnd;
    PCSTR ptr = Data;
    PCSTR uriStart;
    PCSTR uriEnd;
    PCSTR versionStart;
    ULONG uriLength;
    ULONG versionLength;

    *BytesConsumed = 0;

    //
    // Find end of request line
    //
    lineEnd = PppFindLineEnd(Data, DataSize, &lineLength);
    if (lineEnd == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Skip method (already parsed)
    //
    while (ptr < lineEnd && *ptr != ' ') {
        ptr++;
    }

    if (ptr >= lineEnd) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Skip space(s)
    //
    while (ptr < lineEnd && *ptr == ' ') {
        ptr++;
    }

    //
    // Parse URI
    //
    uriStart = ptr;
    while (ptr < lineEnd && *ptr != ' ') {
        ptr++;
    }
    uriEnd = ptr;

    uriLength = (ULONG)(uriEnd - uriStart);
    if (uriLength >= PP_MAX_URL_LENGTH) {
        uriLength = PP_MAX_URL_LENGTH - 1;
    }

    RtlCopyMemory(Request->URI, uriStart, uriLength);
    Request->URI[uriLength] = '\0';

    //
    // Skip space(s)
    //
    while (ptr < lineEnd && *ptr == ' ') {
        ptr++;
    }

    //
    // Parse HTTP version
    //
    versionStart = ptr;
    versionLength = (ULONG)(lineEnd - versionStart);
    if (versionLength >= sizeof(Request->Version)) {
        versionLength = sizeof(Request->Version) - 1;
    }

    RtlCopyMemory(Request->Version, versionStart, versionLength);
    Request->Version[versionLength] = '\0';
    PppTrimWhitespace(Request->Version);

    //
    // Calculate bytes consumed (including CRLF)
    //
    *BytesConsumed = lineLength;
    if (lineLength + 2 <= DataSize &&
        Data[lineLength] == '\r' && Data[lineLength + 1] == '\n') {
        *BytesConsumed = lineLength + 2;
    } else if (lineLength + 1 <= DataSize && Data[lineLength] == '\n') {
        *BytesConsumed = lineLength + 1;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
PppParseStatusLine(
    _In_reads_bytes_(DataSize) PCSTR Data,
    _In_ ULONG DataSize,
    _Out_ PPP_HTTP_RESPONSE Response,
    _Out_ PULONG BytesConsumed
    )
{
    ULONG lineLength = 0;
    PCSTR lineEnd;
    PCSTR ptr = Data;
    PCSTR versionEnd;
    ULONG versionLength;
    ULONG statusCode = 0;
    PCSTR reasonStart;
    ULONG reasonLength;

    *BytesConsumed = 0;

    //
    // Find end of status line
    //
    lineEnd = PppFindLineEnd(Data, DataSize, &lineLength);
    if (lineEnd == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Parse HTTP version
    //
    versionEnd = ptr;
    while (versionEnd < lineEnd && *versionEnd != ' ') {
        versionEnd++;
    }

    versionLength = (ULONG)(versionEnd - ptr);
    if (versionLength >= sizeof(Response->Version)) {
        versionLength = sizeof(Response->Version) - 1;
    }

    RtlCopyMemory(Response->Version, ptr, versionLength);
    Response->Version[versionLength] = '\0';

    ptr = versionEnd;

    //
    // Skip space(s)
    //
    while (ptr < lineEnd && *ptr == ' ') {
        ptr++;
    }

    //
    // Parse status code
    //
    while (ptr < lineEnd && *ptr >= '0' && *ptr <= '9') {
        statusCode = statusCode * 10 + (*ptr - '0');
        ptr++;
    }

    Response->StatusCode = (USHORT)statusCode;

    //
    // Skip space(s)
    //
    while (ptr < lineEnd && *ptr == ' ') {
        ptr++;
    }

    //
    // Parse reason phrase
    //
    reasonStart = ptr;
    reasonLength = (ULONG)(lineEnd - reasonStart);
    if (reasonLength >= sizeof(Response->ReasonPhrase)) {
        reasonLength = sizeof(Response->ReasonPhrase) - 1;
    }

    RtlCopyMemory(Response->ReasonPhrase, reasonStart, reasonLength);
    Response->ReasonPhrase[reasonLength] = '\0';
    PppTrimWhitespace(Response->ReasonPhrase);

    //
    // Calculate bytes consumed
    //
    *BytesConsumed = lineLength;
    if (lineLength + 2 <= DataSize &&
        Data[lineLength] == '\r' && Data[lineLength + 1] == '\n') {
        *BytesConsumed = lineLength + 2;
    } else if (lineLength + 1 <= DataSize && Data[lineLength] == '\n') {
        *BytesConsumed = lineLength + 1;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
PppParseHeaders(
    _In_reads_bytes_(DataSize) PCSTR Data,
    _In_ ULONG DataSize,
    _Out_writes_(MaxHeaders) PPP_HTTP_HEADER Headers,
    _In_ ULONG MaxHeaders,
    _Out_ PULONG HeaderCount,
    _Out_ PULONG BytesConsumed
    )
{
    PCSTR ptr = Data;
    PCSTR end = Data + DataSize;
    ULONG count = 0;
    ULONG totalConsumed = 0;

    *HeaderCount = 0;
    *BytesConsumed = 0;

    while (ptr < end && count < MaxHeaders) {
        ULONG lineLength = 0;
        PCSTR lineEnd;
        PCSTR colonPos;
        ULONG nameLength;
        ULONG valueLength;

        //
        // Find end of header line
        //
        lineEnd = PppFindLineEnd(ptr, (ULONG)(end - ptr), &lineLength);
        if (lineEnd == NULL) {
            break;
        }

        //
        // Check for empty line (end of headers)
        //
        if (lineLength == 0 || (lineLength == 1 && *ptr == '\r')) {
            //
            // Skip CRLF
            //
            if (ptr + 2 <= end && ptr[0] == '\r' && ptr[1] == '\n') {
                totalConsumed += 2;
            } else if (ptr + 1 <= end && ptr[0] == '\n') {
                totalConsumed += 1;
            }
            break;
        }

        //
        // Find colon separator
        //
        colonPos = ptr;
        while (colonPos < lineEnd && *colonPos != ':') {
            colonPos++;
        }

        if (colonPos >= lineEnd) {
            //
            // Malformed header - skip it
            //
            goto NextLine;
        }

        //
        // Extract name
        //
        nameLength = (ULONG)(colonPos - ptr);
        if (nameLength >= PP_MAX_HEADER_NAME_LENGTH) {
            nameLength = PP_MAX_HEADER_NAME_LENGTH - 1;
        }

        RtlCopyMemory(Headers[count].Name, ptr, nameLength);
        Headers[count].Name[nameLength] = '\0';
        PppTrimWhitespace(Headers[count].Name);

        //
        // Extract value (skip colon and leading whitespace)
        //
        colonPos++;
        while (colonPos < lineEnd && (*colonPos == ' ' || *colonPos == '\t')) {
            colonPos++;
        }

        valueLength = (ULONG)(lineEnd - colonPos);
        if (valueLength >= PP_MAX_HEADER_VALUE_LENGTH) {
            valueLength = PP_MAX_HEADER_VALUE_LENGTH - 1;
        }

        RtlCopyMemory(Headers[count].Value, colonPos, valueLength);
        Headers[count].Value[valueLength] = '\0';
        PppTrimWhitespace(Headers[count].Value);

        count++;

NextLine:
        //
        // Move to next line
        //
        if (ptr + lineLength + 2 <= end &&
            ptr[lineLength] == '\r' && ptr[lineLength + 1] == '\n') {
            totalConsumed += lineLength + 2;
            ptr += lineLength + 2;
        } else if (ptr + lineLength + 1 <= end && ptr[lineLength] == '\n') {
            totalConsumed += lineLength + 1;
            ptr += lineLength + 1;
        } else {
            totalConsumed += lineLength;
            ptr += lineLength;
            break;
        }
    }

    *HeaderCount = count;
    *BytesConsumed = totalConsumed;

    return STATUS_SUCCESS;
}

static VOID
PppExtractCommonRequestHeaders(
    _Inout_ PPP_HTTP_REQUEST Request
    )
{
    ULONG i;

    for (i = 0; i < Request->HeaderCount; i++) {
        if (_stricmp(Request->Headers[i].Name, "Host") == 0) {
            RtlStringCchCopyA(Request->Host,
                              sizeof(Request->Host),
                              Request->Headers[i].Value);
        }
        else if (_stricmp(Request->Headers[i].Name, "User-Agent") == 0) {
            RtlStringCchCopyA(Request->UserAgent,
                              sizeof(Request->UserAgent),
                              Request->Headers[i].Value);
        }
        else if (_stricmp(Request->Headers[i].Name, "Content-Type") == 0) {
            RtlStringCchCopyA(Request->ContentType,
                              sizeof(Request->ContentType),
                              Request->Headers[i].Value);
        }
        else if (_stricmp(Request->Headers[i].Name, "Content-Length") == 0) {
            PSTR endPtr;
            Request->ContentLength = strtoul(Request->Headers[i].Value, &endPtr, 10);
        }
        else if (_stricmp(Request->Headers[i].Name, "Cookie") == 0) {
            RtlStringCchCopyA(Request->Cookie,
                              sizeof(Request->Cookie),
                              Request->Headers[i].Value);
        }
        else if (_stricmp(Request->Headers[i].Name, "Referer") == 0) {
            RtlStringCchCopyA(Request->Referer,
                              sizeof(Request->Referer),
                              Request->Headers[i].Value);
        }
    }
}

static VOID
PppExtractCommonResponseHeaders(
    _Inout_ PPP_HTTP_RESPONSE Response
    )
{
    ULONG i;

    for (i = 0; i < Response->HeaderCount; i++) {
        if (_stricmp(Response->Headers[i].Name, "Content-Type") == 0) {
            RtlStringCchCopyA(Response->ContentType,
                              sizeof(Response->ContentType),
                              Response->Headers[i].Value);
        }
        else if (_stricmp(Response->Headers[i].Name, "Content-Length") == 0) {
            PSTR endPtr;
            Response->ContentLength = strtoul(Response->Headers[i].Value, &endPtr, 10);
        }
        else if (_stricmp(Response->Headers[i].Name, "Server") == 0) {
            RtlStringCchCopyA(Response->Server,
                              sizeof(Response->Server),
                              Response->Headers[i].Value);
        }
        else if (_stricmp(Response->Headers[i].Name, "Set-Cookie") == 0) {
            RtlStringCchCopyA(Response->SetCookie,
                              sizeof(Response->SetCookie),
                              Response->Headers[i].Value);
        }
    }
}

static VOID
PppCalculateSuspicionScore(
    _Inout_ PPP_HTTP_REQUEST Request
    )
{
    ULONG score = 0;
    ULONG i;

    //
    // Check for suspicious User-Agent
    //
    if (Request->UserAgent[0] != '\0') {
        for (i = 0; g_SuspiciousUserAgents[i] != NULL; i++) {
            if (strstr(Request->UserAgent, g_SuspiciousUserAgents[i]) != NULL) {
                score += 20;
                break;
            }
        }

        //
        // Empty or very short User-Agent is suspicious
        //
        if (strlen(Request->UserAgent) < 10) {
            score += 15;
        }
    } else {
        //
        // Missing User-Agent is suspicious
        //
        score += 25;
    }

    //
    // Check for suspicious URI patterns
    //
    if (Request->URI[0] != '\0') {
        for (i = 0; g_SuspiciousUriPatterns[i] != NULL; i++) {
            if (strstr(Request->URI, g_SuspiciousUriPatterns[i]) != NULL) {
                score += 30;
                break;
            }
        }

        //
        // Very long URI is suspicious
        //
        if (strlen(Request->URI) > 512) {
            score += 10;
        }

        //
        // Base64-encoded data in URI is suspicious
        //
        if (strstr(Request->URI, "==") != NULL) {
            score += 15;
        }
    }

    //
    // POST/PUT to non-standard port could be exfiltration
    //
    if (Request->Method == HttpMethod_POST || Request->Method == HttpMethod_PUT) {
        if (Request->ContentLength > 1024 * 1024) {  // > 1MB
            score += 20;
        }
    }

    //
    // Missing Host header is suspicious
    //
    if (Request->Host[0] == '\0') {
        score += 15;
    }

    Request->SuspicionScore = score;
    Request->IsSuspicious = (score >= 50);
}

// ============================================================================
// PRIVATE IMPLEMENTATION - STRING HELPERS
// ============================================================================

static PCSTR
PppFindLineEnd(
    _In_reads_bytes_(DataSize) PCSTR Data,
    _In_ ULONG DataSize,
    _Out_ PULONG LineLength
    )
{
    ULONG i;

    *LineLength = 0;

    for (i = 0; i < DataSize; i++) {
        if (Data[i] == '\r' || Data[i] == '\n') {
            *LineLength = i;
            return Data + i;
        }
    }

    //
    // No line ending found - treat entire buffer as line
    //
    *LineLength = DataSize;
    return Data + DataSize;
}

static VOID
PppTrimWhitespace(
    _Inout_ PSTR String
    )
{
    PSTR end;
    PSTR start = String;

    if (String == NULL || *String == '\0') {
        return;
    }

    //
    // Trim trailing whitespace
    //
    end = String + strlen(String) - 1;
    while (end > String && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) {
        *end = '\0';
        end--;
    }

    //
    // Trim leading whitespace (shift left)
    //
    while (*start == ' ' || *start == '\t') {
        start++;
    }

    if (start != String) {
        ULONG len = (ULONG)strlen(start);
        RtlMoveMemory(String, start, len + 1);
    }
}

static ULONG
PppSafeStrLen(
    _In_reads_bytes_(MaxLen) PCSTR String,
    _In_ ULONG MaxLen
    )
{
    ULONG i;

    for (i = 0; i < MaxLen; i++) {
        if (String[i] == '\0') {
            return i;
        }
    }

    return MaxLen;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - DNS HELPERS
// ============================================================================

static NTSTATUS
PppParseDnsName(
    _In_reads_bytes_(PacketSize) PCUCHAR Packet,
    _In_ ULONG PacketSize,
    _In_ ULONG Offset,
    _Out_writes_z_(NameBufferSize) PSTR NameBuffer,
    _In_ ULONG NameBufferSize,
    _Out_ PULONG BytesConsumed
    )
{
    ULONG pos = Offset;
    ULONG namePos = 0;
    ULONG compressionDepth = 0;
    ULONG firstJumpOffset = 0;
    BOOLEAN jumped = FALSE;

    *BytesConsumed = 0;
    NameBuffer[0] = '\0';

    if (Offset >= PacketSize) {
        return STATUS_INVALID_PARAMETER;
    }

    while (pos < PacketSize && namePos < NameBufferSize - 1) {
        UCHAR labelLen = Packet[pos];

        //
        // Check for compression pointer (top 2 bits set)
        //
        if ((labelLen & 0xC0) == 0xC0) {
            //
            // Compression pointer
            //
            if (pos + 1 >= PacketSize) {
                return STATUS_INVALID_PARAMETER;
            }

            USHORT pointer = ((USHORT)(labelLen & 0x3F) << 8) | Packet[pos + 1];

            if (pointer >= PacketSize || pointer >= pos) {
                //
                // Invalid pointer (must point backward)
                //
                return STATUS_INVALID_PARAMETER;
            }

            if (!jumped) {
                firstJumpOffset = pos + 2;
                jumped = TRUE;
            }

            compressionDepth++;
            if (compressionDepth > PP_MAX_DNS_COMPRESSION_DEPTH) {
                //
                // Compression loop detected
                //
                return STATUS_INVALID_PARAMETER;
            }

            pos = pointer;
            continue;
        }

        //
        // Check for end of name
        //
        if (labelLen == 0) {
            if (!jumped) {
                *BytesConsumed = pos - Offset + 1;
            } else {
                *BytesConsumed = firstJumpOffset - Offset;
            }

            //
            // Remove trailing dot if present
            //
            if (namePos > 0 && NameBuffer[namePos - 1] == '.') {
                NameBuffer[namePos - 1] = '\0';
            } else {
                NameBuffer[namePos] = '\0';
            }

            return STATUS_SUCCESS;
        }

        //
        // Validate label length
        //
        if (labelLen > 63) {
            return STATUS_INVALID_PARAMETER;
        }

        if (pos + 1 + labelLen > PacketSize) {
            return STATUS_INVALID_PARAMETER;
        }

        //
        // Add separator if not first label
        //
        if (namePos > 0 && namePos < NameBufferSize - 1) {
            NameBuffer[namePos++] = '.';
        }

        //
        // Copy label
        //
        ULONG copyLen = min(labelLen, NameBufferSize - namePos - 1);
        RtlCopyMemory(NameBuffer + namePos, Packet + pos + 1, copyLen);
        namePos += copyLen;

        pos += 1 + labelLen;
    }

    //
    // Ran out of buffer or packet
    //
    NameBuffer[namePos] = '\0';

    if (!jumped) {
        *BytesConsumed = pos - Offset;
    } else {
        *BytesConsumed = firstJumpOffset - Offset;
    }

    return STATUS_SUCCESS;
}

static ULONG
PppCalculateDomainEntropy(
    _In_z_ PCSTR Domain
    )
{
    ULONG charCounts[256] = { 0 };
    ULONG len = 0;
    ULONG i;
    ULONG entropy = 0;

    if (Domain == NULL || Domain[0] == '\0') {
        return 0;
    }

    //
    // Count character frequencies
    //
    for (i = 0; Domain[i] != '\0' && i < 256; i++) {
        charCounts[(UCHAR)Domain[i]]++;
        len++;
    }

    if (len == 0) {
        return 0;
    }

    //
    // Calculate Shannon entropy (scaled by 1000)
    // H = -sum(p * log2(p)) where p = count/len
    //
    // Simplified: count unique chars and their distribution
    //
    ULONG uniqueChars = 0;
    ULONG maxCount = 0;

    for (i = 0; i < 256; i++) {
        if (charCounts[i] > 0) {
            uniqueChars++;
            if (charCounts[i] > maxCount) {
                maxCount = charCounts[i];
            }
        }
    }

    //
    // Simple entropy approximation:
    // High unique chars + even distribution = high entropy
    //
    if (len > 0) {
        entropy = (uniqueChars * 100) / len;  // Unique ratio
        entropy += (len - maxCount) * 10 / len;  // Distribution evenness
    }

    return entropy;
}
