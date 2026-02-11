/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE PROTOCOL PARSER
 * ============================================================================
 *
 * @file ProtocolParser.c
 * @brief Enterprise-grade network protocol parsing for HTTP/1.x and DNS.
 *
 * Features:
 * - HTTP/1.0, HTTP/1.1 request and response parsing
 * - DNS query and response parsing with compression pointer safety
 * - Suspicious pattern detection (C2 beacons, encoded payloads)
 * - Header extraction and normalization
 * - Thread-safe via EX_RUNDOWN_REF (concurrent parse + safe shutdown)
 * - Memory-budgeted: caps concurrent outstanding allocations
 *
 * Security model:
 * - All input is treated as hostile / attacker-controlled
 * - Strict bounds checking on all buffer operations
 * - Bounded allocations from PagedPool (never NonPagedPool)
 * - Malformed packet detection and rejection
 * - No CRT string functions — all bounded kernel equivalents
 * - Body data is copied (never aliased into caller buffer)
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0 (Enterprise Edition)
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

#define PP_MIN_HTTP_SIZE                16
#define PP_MIN_DNS_SIZE                 12
#define PP_DNS_HEADER_SIZE              12
#define PP_MAX_DNS_NAME                 256
#define PP_MAX_DNS_COMPRESSION_DEPTH    8
#define PP_MAX_STATUS_CODE_DIGITS       3
#define PP_MAX_CONTENT_LENGTH_DIGITS    15

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
 * Suspicious URI patterns — indicators of exploitation attempts.
 * These are attack-vector patterns, not legitimate tool signatures.
 */
static const CHAR* g_SuspiciousUriPatterns[] = {
    "..%2f",                    // Path traversal (URL-encoded /)
    "..%5c",                    // Path traversal (URL-encoded \)
    "%00",                      // Null byte injection
    "<script",                  // XSS attempt
    "UNION%20SELECT",           // SQL injection
    "%27OR%20",                 // SQL injection (encoded ')
    "/etc/passwd",              // LFI attempt
    "cmd.exe",                  // RCE attempt
    "powershell%20",            // RCE attempt
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

static NTSTATUS
PppFindLineEnd(
    _In_reads_bytes_(DataSize) PCSTR Data,
    _In_ ULONG DataSize,
    _Out_ PULONG LineLength,
    _Out_ PCSTR* LineEnd
    );

static VOID
PppTrimWhitespace(
    _Inout_ PSTR String,
    _In_ ULONG MaxLen
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

static BOOLEAN
PppSafeBoundedSearch(
    _In_reads_bytes_(HaystackLen) PCSTR Haystack,
    _In_ ULONG HaystackLen,
    _In_z_ PCSTR Needle
    );

static NTSTATUS
PppParseUlongBounded(
    _In_reads_bytes_(MaxLen) PCSTR String,
    _In_ ULONG MaxLen,
    _In_ ULONG MaxValue,
    _Out_ PULONG Result
    );

// Rundown helpers
static BOOLEAN
PppAcquireRundown(
    _In_ PPP_PARSER Parser
    );

static VOID
PppReleaseRundown(
    _In_ PPP_PARSER Parser
    );

// Allocation tracking
static BOOLEAN
PppTrackAllocation(
    _In_ PPP_PARSER Parser
    );

static VOID
PppUntrackAllocation(
    _In_ PPP_PARSER Parser
    );

// ============================================================================
// PRIVATE - RUNDOWN + ALLOCATION TRACKING
// ============================================================================

static BOOLEAN
PppAcquireRundown(
    _In_ PPP_PARSER Parser
    )
{
    return ExAcquireRundownProtection(&Parser->RundownRef);
}

static VOID
PppReleaseRundown(
    _In_ PPP_PARSER Parser
    )
{
    ExReleaseRundownProtection(&Parser->RundownRef);
}

static BOOLEAN
PppTrackAllocation(
    _In_ PPP_PARSER Parser
    )
{
    LONG current = InterlockedIncrement(&Parser->ActiveAllocations);
    if (current > PP_MAX_CONCURRENT_ALLOCS) {
        InterlockedDecrement(&Parser->ActiveAllocations);
        return FALSE;
    }
    return TRUE;
}

static VOID
PppUntrackAllocation(
    _In_ PPP_PARSER Parser
    )
{
    InterlockedDecrement(&Parser->ActiveAllocations);
}

// ============================================================================
// PUBLIC API - INITIALIZATION
// ============================================================================

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

    parser = (PPP_PARSER)ExAllocatePoolZero(
        PagedPool,
        sizeof(PP_PARSER),
        PP_POOL_TAG_PARSER
    );

    if (parser == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ExInitializeRundownProtection(&parser->RundownRef);
    KeInitializeSpinLock(&parser->StatsLock);
    parser->ActiveAllocations = 0;
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
 * Waits for all outstanding parse operations to complete (via rundown),
 * then frees the parser and NULLs the caller's pointer.
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
PpShutdown(
    _Inout_ PPP_PARSER* Parser
    )
{
    PPP_PARSER parser;

    PAGED_CODE();

    if (Parser == NULL || *Parser == NULL) {
        return;
    }

    parser = *Parser;
    *Parser = NULL;

    if (!parser->Initialized) {
        ExFreePoolWithTag(parser, PP_POOL_TAG_PARSER);
        return;
    }

    parser->Initialized = FALSE;

    //
    // Wait for all in-flight parse operations to complete.
    // After this returns, no new rundown acquisitions will succeed.
    //
    ExWaitForRundownProtectionRelease(&parser->RundownRef);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Protocol parser shutdown (HTTP Req: %lld, Resp: %lld, DNS: %lld, Errors: %lld)\n",
               parser->Stats.HTTPRequestsParsed,
               parser->Stats.HTTPResponsesParsed,
               parser->Stats.DNSPacketsParsed,
               parser->Stats.ParseErrors);

    ExFreePoolWithTag(parser, PP_POOL_TAG_PARSER);
}

// ============================================================================
// PUBLIC API - HTTP PARSING
// ============================================================================

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

    //
    // Acquire rundown protection — prevents shutdown during this parse.
    //
    if (!PppAcquireRundown(Parser)) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (!Parser->Initialized) {
        status = STATUS_DEVICE_NOT_READY;
        goto ReleaseRundown;
    }

    if (DataSize < PP_MIN_HTTP_SIZE) {
        InterlockedIncrement64(&Parser->Stats.ParseErrors);
        status = STATUS_BUFFER_TOO_SMALL;
        goto ReleaseRundown;
    }

    //
    // Verify this is an HTTP request
    //
    PP_HTTP_METHOD method;
    ULONG methodLength;

    if (!PppIsHttpMethod(data, DataSize, &method, &methodLength)) {
        InterlockedIncrement64(&Parser->Stats.ParseErrors);
        status = STATUS_INVALID_PARAMETER;
        goto ReleaseRundown;
    }

    //
    // Check allocation budget
    //
    if (!PppTrackAllocation(Parser)) {
        InterlockedIncrement64(&Parser->Stats.ParseErrors);
        status = STATUS_QUOTA_EXCEEDED;
        goto ReleaseRundown;
    }

    //
    // Allocate request structure from PagedPool
    //
    request = (PPP_HTTP_REQUEST)ExAllocatePoolZero(
        PagedPool,
        sizeof(PP_HTTP_REQUEST),
        PP_POOL_TAG_HEADER
    );

    if (request == NULL) {
        PppUntrackAllocation(Parser);
        InterlockedIncrement64(&Parser->Stats.ParseErrors);
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto ReleaseRundown;
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
    // Copy body into owned allocation (never alias caller's buffer)
    //
    if (totalConsumed < DataSize && request->ContentLength > 0) {
        ULONG bodyAvailable = DataSize - totalConsumed;
        ULONG bodySize = min(request->ContentLength, bodyAvailable);
        bodySize = min(bodySize, PP_MAX_BODY_COPY_SIZE);

        if (bodySize > 0) {
            request->Body = ExAllocatePoolZero(
                PagedPool,
                bodySize,
                PP_POOL_TAG_BODY
            );

            if (request->Body != NULL) {
                RtlCopyMemory(request->Body, data + totalConsumed, bodySize);
                request->BodySize = bodySize;
            }
            // Non-fatal if body alloc fails — headers are still useful
        }
    }

    //
    // Calculate suspicion score
    //
    PppCalculateSuspicionScore(request);

    InterlockedIncrement64(&Parser->Stats.HTTPRequestsParsed);
    *Request = request;

    PppReleaseRundown(Parser);
    return STATUS_SUCCESS;

Cleanup:
    if (request != NULL) {
        if (request->Body != NULL) {
            ExFreePoolWithTag(request->Body, PP_POOL_TAG_BODY);
        }
        ExFreePoolWithTag(request, PP_POOL_TAG_HEADER);
    }

    PppUntrackAllocation(Parser);
    InterlockedIncrement64(&Parser->Stats.ParseErrors);

ReleaseRundown:
    PppReleaseRundown(Parser);
    return status;
}

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

    if (!PppAcquireRundown(Parser)) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (!Parser->Initialized) {
        status = STATUS_DEVICE_NOT_READY;
        goto ReleaseRundown;
    }

    if (DataSize < PP_MIN_HTTP_SIZE) {
        InterlockedIncrement64(&Parser->Stats.ParseErrors);
        status = STATUS_BUFFER_TOO_SMALL;
        goto ReleaseRundown;
    }

    if (!PppIsHttpResponse(data, DataSize)) {
        InterlockedIncrement64(&Parser->Stats.ParseErrors);
        status = STATUS_INVALID_PARAMETER;
        goto ReleaseRundown;
    }

    if (!PppTrackAllocation(Parser)) {
        InterlockedIncrement64(&Parser->Stats.ParseErrors);
        status = STATUS_QUOTA_EXCEEDED;
        goto ReleaseRundown;
    }

    response = (PPP_HTTP_RESPONSE)ExAllocatePoolZero(
        PagedPool,
        sizeof(PP_HTTP_RESPONSE),
        PP_POOL_TAG_HEADER
    );

    if (response == NULL) {
        PppUntrackAllocation(Parser);
        InterlockedIncrement64(&Parser->Stats.ParseErrors);
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto ReleaseRundown;
    }

    status = PppParseStatusLine(data, DataSize, response, &bytesConsumed);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    totalConsumed = bytesConsumed;

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

    PppExtractCommonResponseHeaders(response);

    //
    // Copy body into owned allocation
    //
    if (totalConsumed < DataSize && response->ContentLength > 0) {
        ULONG bodyAvailable = DataSize - totalConsumed;
        ULONG bodySize = min(response->ContentLength, bodyAvailable);
        bodySize = min(bodySize, PP_MAX_BODY_COPY_SIZE);

        if (bodySize > 0) {
            response->Body = ExAllocatePoolZero(
                PagedPool,
                bodySize,
                PP_POOL_TAG_BODY
            );

            if (response->Body != NULL) {
                RtlCopyMemory(response->Body, data + totalConsumed, bodySize);
                response->BodySize = bodySize;
            }
        }
    }

    InterlockedIncrement64(&Parser->Stats.HTTPResponsesParsed);
    *Response = response;

    PppReleaseRundown(Parser);
    return STATUS_SUCCESS;

Cleanup:
    if (response != NULL) {
        if (response->Body != NULL) {
            ExFreePoolWithTag(response->Body, PP_POOL_TAG_BODY);
        }
        ExFreePoolWithTag(response, PP_POOL_TAG_HEADER);
    }

    PppUntrackAllocation(Parser);
    InterlockedIncrement64(&Parser->Stats.ParseErrors);

ReleaseRundown:
    PppReleaseRundown(Parser);
    return status;
}

/**
 * @brief Free an HTTP request structure and its owned body.
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
PpFreeHTTPRequest(
    _In_opt_ _Post_invalid_ PPP_HTTP_REQUEST Request
    )
{
    if (Request != NULL) {
        if (Request->Body != NULL) {
            ExFreePoolWithTag(Request->Body, PP_POOL_TAG_BODY);
            Request->Body = NULL;
        }
        ExFreePoolWithTag(Request, PP_POOL_TAG_HEADER);
    }
}

/**
 * @brief Free an HTTP response structure and its owned body.
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
PpFreeHTTPResponse(
    _In_opt_ _Post_invalid_ PPP_HTTP_RESPONSE Response
    )
{
    if (Response != NULL) {
        if (Response->Body != NULL) {
            ExFreePoolWithTag(Response->Body, PP_POOL_TAG_BODY);
            Response->Body = NULL;
        }
        ExFreePoolWithTag(Response, PP_POOL_TAG_HEADER);
    }
}

// ============================================================================
// PUBLIC API - DNS PARSING
// ============================================================================

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

    if (!PppAcquireRundown(Parser)) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (!Parser->Initialized) {
        status = STATUS_DEVICE_NOT_READY;
        goto ReleaseRundown;
    }

    if (DataSize < PP_MIN_DNS_SIZE) {
        InterlockedIncrement64(&Parser->Stats.ParseErrors);
        status = STATUS_BUFFER_TOO_SMALL;
        goto ReleaseRundown;
    }

    if (!PppTrackAllocation(Parser)) {
        InterlockedIncrement64(&Parser->Stats.ParseErrors);
        status = STATUS_QUOTA_EXCEEDED;
        goto ReleaseRundown;
    }

    packet = (PPP_DNS_PACKET)ExAllocatePoolZero(
        PagedPool,
        sizeof(PP_DNS_PACKET),
        PP_POOL_TAG_HEADER
    );

    if (packet == NULL) {
        PppUntrackAllocation(Parser);
        InterlockedIncrement64(&Parser->Stats.ParseErrors);
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto ReleaseRundown;
    }

    //
    // Parse DNS header (12 bytes)
    //
    packet->TransactionId = (USHORT)((data[0] << 8) | data[1]);
    packet->Flags = (USHORT)((data[2] << 8) | data[3]);

    // Store raw wire counts before clamping
    packet->RawQuestionCount = (USHORT)((data[4] << 8) | data[5]);
    packet->RawAnswerCount = (USHORT)((data[6] << 8) | data[7]);
    packet->RawAuthorityCount = (USHORT)((data[8] << 8) | data[9]);
    packet->RawAdditionalCount = (USHORT)((data[10] << 8) | data[11]);

    // Decode flags
    packet->IsQuery = ((packet->Flags & 0x8000) == 0);
    packet->IsResponse = ((packet->Flags & 0x8000) != 0);
    packet->IsRecursionDesired = ((packet->Flags & 0x0100) != 0);
    packet->IsRecursionAvailable = ((packet->Flags & 0x0080) != 0);
    packet->ResponseCode = (USHORT)(packet->Flags & 0x000F);

    // Clamp to array bounds for safe parsing
    packet->QuestionCount = min(packet->RawQuestionCount, PP_MAX_DNS_QUESTIONS);
    packet->AnswerCount = min(packet->RawAnswerCount, PP_MAX_DNS_ANSWERS);
    packet->AuthorityCount = packet->RawAuthorityCount;
    packet->AdditionalCount = packet->RawAdditionalCount;

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

        // QTYPE + QCLASS = 4 bytes
        if (offset + 4 > DataSize) {
            status = STATUS_BUFFER_TOO_SMALL;
            goto Cleanup;
        }

        packet->Questions[i].Type = (USHORT)((data[offset] << 8) | data[offset + 1]);
        packet->Questions[i].Class = (USHORT)((data[offset + 2] << 8) | data[offset + 3]);
        offset += 4;
    }

    //
    // Parse answers
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

        // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10 bytes
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
                status = PppParseDnsName(
                    data,
                    DataSize,
                    offset,
                    packet->Answers[i].Data.CNAME,
                    sizeof(packet->Answers[i].Data.CNAME),
                    &bytesConsumed
                );
                if (!NT_SUCCESS(status)) {
                    // Non-fatal for individual RDATA — clear and continue
                    packet->Answers[i].Data.CNAME[0] = '\0';
                    status = STATUS_SUCCESS;
                }
                break;

            case DNS_TYPE_TXT:
                if (rdLength > 0 && rdLength <= sizeof(packet->Answers[i].Data.TXT)) {
                    UCHAR txtLen = data[offset];
                    if (txtLen > 0 && (ULONG)(txtLen + 1) <= rdLength) {
                        ULONG copyLen = min((ULONG)txtLen,
                                            sizeof(packet->Answers[i].Data.TXT) - 1);
                        RtlCopyMemory(packet->Answers[i].Data.TXT,
                                      data + offset + 1,
                                      copyLen);
                        packet->Answers[i].Data.TXT[copyLen] = '\0';
                    }
                }
                break;

            default:
                break;
        }

        offset += rdLength;
    }

    InterlockedIncrement64(&Parser->Stats.DNSPacketsParsed);
    *Packet = packet;

    PppReleaseRundown(Parser);
    return STATUS_SUCCESS;

Cleanup:
    if (packet != NULL) {
        ExFreePoolWithTag(packet, PP_POOL_TAG_HEADER);
    }

    PppUntrackAllocation(Parser);
    InterlockedIncrement64(&Parser->Stats.ParseErrors);

ReleaseRundown:
    PppReleaseRundown(Parser);
    return status;
}

/**
 * @brief Free a DNS packet structure.
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
PpFreeDNSPacket(
    _In_opt_ _Post_invalid_ PPP_DNS_PACKET Packet
    )
{
    if (Packet != NULL) {
        ExFreePoolWithTag(Packet, PP_POOL_TAG_HEADER);
    }
}

// ============================================================================
// PUBLIC API - UTILITY FUNCTIONS
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
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

    if (PppIsHttpMethod(data, DataSize, &method, &methodLength)) {
        return TRUE;
    }

    if (PppIsHttpResponse(data, DataSize)) {
        return TRUE;
    }

    return FALSE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
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

    flags = (USHORT)((data[2] << 8) | data[3]);
    qdCount = (USHORT)((data[4] << 8) | data[5]);
    opcode = (flags >> 11) & 0x0F;

    if (opcode > 2) {
        return FALSE;
    }

    if (qdCount == 0 || qdCount > 16) {
        return FALSE;
    }

    // Z bits (must be zero per RFC 1035)
    if ((flags & 0x0070) != 0) {
        return FALSE;
    }

    return TRUE;
}

_IRQL_requires_max_(APC_LEVEL)
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

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
PpExtractURLFromRequest(
    _In_ PPP_HTTP_REQUEST Request,
    _In_ BOOLEAN IsSecure,
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
            "%s://%s%s",
            IsSecure ? "https" : "http",
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
 * @brief Get parser statistics (atomic snapshot under spinlock).
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
PpGetStatistics(
    _In_ PPP_PARSER Parser,
    _Out_ PPP_STATISTICS Stats
    )
{
    LARGE_INTEGER currentTime;
    KIRQL oldIrql;

    if (Parser == NULL || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Stats, sizeof(PP_STATISTICS));

    if (!Parser->Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeAcquireSpinLock(&Parser->StatsLock, &oldIrql);

    Stats->HTTPRequestsParsed = Parser->Stats.HTTPRequestsParsed;
    Stats->HTTPResponsesParsed = Parser->Stats.HTTPResponsesParsed;
    Stats->DNSPacketsParsed = Parser->Stats.DNSPacketsParsed;
    Stats->ParseErrors = Parser->Stats.ParseErrors;
    Stats->ActiveAllocations = Parser->ActiveAllocations;

    KeReleaseSpinLock(&Parser->StatsLock, oldIrql);

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
    // Accept HTTP/1.x ONLY — HTTP/2 uses binary framing and cannot
    // be parsed with this line-based parser.
    //
    if (DataSize >= 8 &&
        Data[0] == 'H' && Data[1] == 'T' && Data[2] == 'T' && Data[3] == 'P' &&
        Data[4] == '/' && Data[5] == '1' && Data[6] == '.') {
        return TRUE;
    }

    return FALSE;
}

/**
 * @brief Find end of a line within a bounded buffer.
 *
 * Returns STATUS_SUCCESS if a line ending (\r or \n) is found.
 * Returns STATUS_BUFFER_TOO_SMALL if no line ending exists (incomplete data).
 */
static NTSTATUS
PppFindLineEnd(
    _In_reads_bytes_(DataSize) PCSTR Data,
    _In_ ULONG DataSize,
    _Out_ PULONG LineLength,
    _Out_ PCSTR* LineEnd
    )
{
    ULONG i;

    *LineLength = 0;
    *LineEnd = NULL;

    for (i = 0; i < DataSize; i++) {
        if (Data[i] == '\r' || Data[i] == '\n') {
            *LineLength = i;
            *LineEnd = Data + i;
            return STATUS_SUCCESS;
        }
    }

    // No line ending found — incomplete HTTP data
    return STATUS_BUFFER_TOO_SMALL;
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
    PCSTR lineEnd = NULL;
    PCSTR ptr = Data;
    PCSTR uriStart;
    PCSTR uriEnd;
    PCSTR versionStart;
    ULONG uriLength;
    ULONG versionLength;
    NTSTATUS status;

    *BytesConsumed = 0;

    status = PppFindLineEnd(Data, DataSize, &lineLength, &lineEnd);
    if (!NT_SUCCESS(status)) {
        return STATUS_INVALID_PARAMETER;
    }

    // Skip method (already parsed)
    while (ptr < lineEnd && *ptr != ' ') {
        ptr++;
    }

    if (ptr >= lineEnd) {
        return STATUS_INVALID_PARAMETER;
    }

    // Skip space(s)
    while (ptr < lineEnd && *ptr == ' ') {
        ptr++;
    }

    // Parse URI
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

    // Skip space(s)
    while (ptr < lineEnd && *ptr == ' ') {
        ptr++;
    }

    // Parse HTTP version
    versionStart = ptr;
    versionLength = (ULONG)(lineEnd - versionStart);
    if (versionLength >= sizeof(Request->Version)) {
        versionLength = sizeof(Request->Version) - 1;
    }

    RtlCopyMemory(Request->Version, versionStart, versionLength);
    Request->Version[versionLength] = '\0';
    PppTrimWhitespace(Request->Version, sizeof(Request->Version));

    // Calculate bytes consumed (including CRLF)
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
    PCSTR lineEnd = NULL;
    PCSTR ptr = Data;
    PCSTR versionEnd;
    ULONG versionLength;
    ULONG statusCode = 0;
    ULONG digitCount = 0;
    PCSTR reasonStart;
    ULONG reasonLength;
    NTSTATUS status;

    *BytesConsumed = 0;

    status = PppFindLineEnd(Data, DataSize, &lineLength, &lineEnd);
    if (!NT_SUCCESS(status)) {
        return STATUS_INVALID_PARAMETER;
    }

    // Parse HTTP version
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

    // Skip space(s)
    while (ptr < lineEnd && *ptr == ' ') {
        ptr++;
    }

    //
    // Parse status code — strictly 3 digits, range 100-599
    //
    while (ptr < lineEnd && *ptr >= '0' && *ptr <= '9' &&
           digitCount < PP_MAX_STATUS_CODE_DIGITS) {
        statusCode = statusCode * 10 + (ULONG)(*ptr - '0');
        ptr++;
        digitCount++;
    }

    if (digitCount != 3 || statusCode < 100 || statusCode > 599) {
        return STATUS_INVALID_PARAMETER;
    }

    Response->StatusCode = (USHORT)statusCode;

    // Skip space(s)
    while (ptr < lineEnd && *ptr == ' ') {
        ptr++;
    }

    // Parse reason phrase
    reasonStart = ptr;
    reasonLength = (ULONG)(lineEnd - reasonStart);
    if (reasonLength >= sizeof(Response->ReasonPhrase)) {
        reasonLength = sizeof(Response->ReasonPhrase) - 1;
    }

    RtlCopyMemory(Response->ReasonPhrase, reasonStart, reasonLength);
    Response->ReasonPhrase[reasonLength] = '\0';
    PppTrimWhitespace(Response->ReasonPhrase, sizeof(Response->ReasonPhrase));

    // Calculate bytes consumed
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
        PCSTR lineEnd = NULL;
        PCSTR colonPos;
        ULONG nameLength;
        ULONG valueLength;
        ULONG remaining = (ULONG)(end - ptr);
        NTSTATUS lineStatus;

        lineStatus = PppFindLineEnd(ptr, remaining, &lineLength, &lineEnd);
        if (!NT_SUCCESS(lineStatus)) {
            // No more complete lines — stop parsing
            break;
        }

        // Check for empty line (end of headers)
        if (lineLength == 0 || (lineLength == 1 && *ptr == '\r')) {
            if (ptr + 2 <= end && ptr[0] == '\r' && ptr[1] == '\n') {
                totalConsumed += 2;
            } else if (ptr + 1 <= end && ptr[0] == '\n') {
                totalConsumed += 1;
            }
            break;
        }

        // Find colon separator
        colonPos = ptr;
        while (colonPos < lineEnd && *colonPos != ':') {
            colonPos++;
        }

        if (colonPos >= lineEnd) {
            // Malformed header — skip
            goto NextLine;
        }

        // Extract name — reject if oversized (do not silently truncate)
        nameLength = (ULONG)(colonPos - ptr);
        if (nameLength == 0 || nameLength >= PP_MAX_HEADER_NAME_LENGTH) {
            goto NextLine;
        }

        RtlCopyMemory(Headers[count].Name, ptr, nameLength);
        Headers[count].Name[nameLength] = '\0';
        PppTrimWhitespace(Headers[count].Name, PP_MAX_HEADER_NAME_LENGTH);

        // Extract value (skip colon and leading whitespace)
        colonPos++;
        while (colonPos < lineEnd && (*colonPos == ' ' || *colonPos == '\t')) {
            colonPos++;
        }

        valueLength = (ULONG)(lineEnd - colonPos);
        if (valueLength >= PP_MAX_HEADER_VALUE_LENGTH) {
            // Reject oversized header values
            goto NextLine;
        }

        RtlCopyMemory(Headers[count].Value, colonPos, valueLength);
        Headers[count].Value[valueLength] = '\0';
        PppTrimWhitespace(Headers[count].Value, PP_MAX_HEADER_VALUE_LENGTH);

        count++;

NextLine:
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

/**
 * @brief Bounded case-insensitive comparison of two null-terminated
 *        strings within known-bounded buffers.
 */
static BOOLEAN
PppStrEqualInsensitive(
    _In_z_ PCSTR A,
    _In_ ULONG AMaxLen,
    _In_z_ PCSTR B
    )
{
    ULONG i;
    ULONG bLen = 0;
    ULONG aLen = PppSafeStrLen(A, AMaxLen);

    // Get B length (B is a compile-time constant — bounded)
    for (bLen = 0; B[bLen] != '\0'; bLen++) {}

    if (aLen != bLen) {
        return FALSE;
    }

    for (i = 0; i < aLen; i++) {
        CHAR ca = A[i];
        CHAR cb = B[i];

        // Uppercase both
        if (ca >= 'a' && ca <= 'z') ca -= ('a' - 'A');
        if (cb >= 'a' && cb <= 'z') cb -= ('a' - 'A');

        if (ca != cb) {
            return FALSE;
        }
    }

    return TRUE;
}

static VOID
PppExtractCommonRequestHeaders(
    _Inout_ PPP_HTTP_REQUEST Request
    )
{
    ULONG i;

    for (i = 0; i < Request->HeaderCount; i++) {
        if (PppStrEqualInsensitive(Request->Headers[i].Name,
                                   PP_MAX_HEADER_NAME_LENGTH, "Host")) {
            RtlStringCchCopyA(Request->Host,
                              sizeof(Request->Host),
                              Request->Headers[i].Value);
        }
        else if (PppStrEqualInsensitive(Request->Headers[i].Name,
                                        PP_MAX_HEADER_NAME_LENGTH, "User-Agent")) {
            RtlStringCchCopyA(Request->UserAgent,
                              sizeof(Request->UserAgent),
                              Request->Headers[i].Value);
        }
        else if (PppStrEqualInsensitive(Request->Headers[i].Name,
                                        PP_MAX_HEADER_NAME_LENGTH, "Content-Type")) {
            RtlStringCchCopyA(Request->ContentType,
                              sizeof(Request->ContentType),
                              Request->Headers[i].Value);
        }
        else if (PppStrEqualInsensitive(Request->Headers[i].Name,
                                        PP_MAX_HEADER_NAME_LENGTH, "Content-Length")) {
            ULONG value = 0;
            NTSTATUS clStatus = PppParseUlongBounded(
                Request->Headers[i].Value,
                PP_MAX_HEADER_VALUE_LENGTH,
                PP_MAX_CONTENT_LENGTH,
                &value
            );
            if (NT_SUCCESS(clStatus)) {
                Request->ContentLength = value;
            }
        }
        else if (PppStrEqualInsensitive(Request->Headers[i].Name,
                                        PP_MAX_HEADER_NAME_LENGTH, "Cookie")) {
            RtlStringCchCopyA(Request->Cookie,
                              sizeof(Request->Cookie),
                              Request->Headers[i].Value);
        }
        else if (PppStrEqualInsensitive(Request->Headers[i].Name,
                                        PP_MAX_HEADER_NAME_LENGTH, "Referer")) {
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
        if (PppStrEqualInsensitive(Response->Headers[i].Name,
                                   PP_MAX_HEADER_NAME_LENGTH, "Content-Type")) {
            RtlStringCchCopyA(Response->ContentType,
                              sizeof(Response->ContentType),
                              Response->Headers[i].Value);
        }
        else if (PppStrEqualInsensitive(Response->Headers[i].Name,
                                        PP_MAX_HEADER_NAME_LENGTH, "Content-Length")) {
            ULONG value = 0;
            NTSTATUS clStatus = PppParseUlongBounded(
                Response->Headers[i].Value,
                PP_MAX_HEADER_VALUE_LENGTH,
                PP_MAX_CONTENT_LENGTH,
                &value
            );
            if (NT_SUCCESS(clStatus)) {
                Response->ContentLength = value;
            }
        }
        else if (PppStrEqualInsensitive(Response->Headers[i].Name,
                                        PP_MAX_HEADER_NAME_LENGTH, "Server")) {
            RtlStringCchCopyA(Response->Server,
                              sizeof(Response->Server),
                              Response->Headers[i].Value);
        }
        else if (PppStrEqualInsensitive(Response->Headers[i].Name,
                                        PP_MAX_HEADER_NAME_LENGTH, "Set-Cookie")) {
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
    ULONG uaLen;
    ULONG uriLen;

    //
    // Check User-Agent
    //
    uaLen = PppSafeStrLen(Request->UserAgent, sizeof(Request->UserAgent));
    if (uaLen > 0) {
        if (uaLen < 10) {
            score += 15;    // Very short UA is suspicious
        }
    } else {
        score += 25;        // Missing UA is suspicious
    }

    //
    // Check for attack patterns in URI (not legitimate tool names)
    //
    uriLen = PppSafeStrLen(Request->URI, sizeof(Request->URI));
    if (uriLen > 0) {
        for (i = 0; g_SuspiciousUriPatterns[i] != NULL; i++) {
            if (PppSafeBoundedSearch(Request->URI, uriLen,
                                     g_SuspiciousUriPatterns[i])) {
                score += 30;
                break;
            }
        }

        if (uriLen > 512) {
            score += 10;    // Very long URI
        }
    }

    //
    // Large POST/PUT could indicate exfiltration
    //
    if (Request->Method == HttpMethod_POST || Request->Method == HttpMethod_PUT) {
        if (Request->ContentLength > 1024 * 1024) {
            score += 20;
        }
    }

    //
    // Missing Host header
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

static VOID
PppTrimWhitespace(
    _Inout_ PSTR String,
    _In_ ULONG MaxLen
    )
{
    ULONG len;
    PSTR end;
    PSTR start = String;

    if (String == NULL) {
        return;
    }

    len = PppSafeStrLen(String, MaxLen);
    if (len == 0) {
        return;
    }

    // Trim trailing whitespace
    end = String + len - 1;
    while (end > String && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) {
        *end = '\0';
        end--;
    }

    // Trim leading whitespace (shift left)
    while (*start == ' ' || *start == '\t') {
        start++;
    }

    if (start != String) {
        ULONG remaining = PppSafeStrLen(start, MaxLen - (ULONG)(start - String));
        RtlMoveMemory(String, start, remaining + 1);
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

/**
 * @brief Bounded substring search — safe replacement for strstr().
 *
 * Searches within a length-bounded haystack for a null-terminated needle.
 * Never reads past HaystackLen bytes.
 */
static BOOLEAN
PppSafeBoundedSearch(
    _In_reads_bytes_(HaystackLen) PCSTR Haystack,
    _In_ ULONG HaystackLen,
    _In_z_ PCSTR Needle
    )
{
    ULONG needleLen = 0;
    ULONG i, j;

    // Get needle length
    for (needleLen = 0; Needle[needleLen] != '\0'; needleLen++) {}

    if (needleLen == 0 || needleLen > HaystackLen) {
        return FALSE;
    }

    for (i = 0; i <= HaystackLen - needleLen; i++) {
        BOOLEAN match = TRUE;
        for (j = 0; j < needleLen; j++) {
            if (Haystack[i + j] != Needle[j]) {
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
 * @brief Parse a decimal ULONG from a bounded string with overflow protection.
 *
 * Stops at first non-digit. Rejects values > MaxValue.
 * Replaces strtoul() for kernel safety.
 */
static NTSTATUS
PppParseUlongBounded(
    _In_reads_bytes_(MaxLen) PCSTR String,
    _In_ ULONG MaxLen,
    _In_ ULONG MaxValue,
    _Out_ PULONG Result
    )
{
    ULONG i;
    ULONG value = 0;
    ULONG digitCount = 0;

    *Result = 0;

    for (i = 0; i < MaxLen && String[i] != '\0'; i++) {
        // Skip leading whitespace
        if (digitCount == 0 && (String[i] == ' ' || String[i] == '\t')) {
            continue;
        }

        if (String[i] < '0' || String[i] > '9') {
            break;
        }

        digitCount++;
        if (digitCount > PP_MAX_CONTENT_LENGTH_DIGITS) {
            return STATUS_INTEGER_OVERFLOW;
        }

        // Check for overflow before multiply
        if (value > (MAXULONG / 10)) {
            return STATUS_INTEGER_OVERFLOW;
        }
        value *= 10;

        ULONG digit = (ULONG)(String[i] - '0');
        if (value > MAXULONG - digit) {
            return STATUS_INTEGER_OVERFLOW;
        }
        value += digit;
    }

    if (digitCount == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (value > MaxValue) {
        return STATUS_INTEGER_OVERFLOW;
    }

    *Result = value;
    return STATUS_SUCCESS;
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

    if (Offset >= PacketSize || NameBufferSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    while (pos < PacketSize && namePos < NameBufferSize - 1) {
        UCHAR labelLen = Packet[pos];

        //
        // Check for compression pointer (top 2 bits set)
        //
        if ((labelLen & 0xC0) == 0xC0) {
            if (pos + 1 >= PacketSize) {
                return STATUS_INVALID_PARAMETER;
            }

            USHORT pointer = ((USHORT)(labelLen & 0x3F) << 8) | Packet[pos + 1];

            //
            // Pointer must point backward into the packet (never into
            // the DNS header's first 12 bytes of raw header if the name
            // data cannot be there, and must not point at or past current
            // position to prevent cycles).
            //
            if (pointer >= PacketSize || pointer >= pos) {
                return STATUS_INVALID_PARAMETER;
            }

            // DNS header is 12 bytes — valid name data starts at offset 12
            if (pointer < PP_DNS_HEADER_SIZE) {
                return STATUS_INVALID_PARAMETER;
            }

            if (!jumped) {
                firstJumpOffset = pos + 2;
                jumped = TRUE;
            }

            compressionDepth++;
            if (compressionDepth > PP_MAX_DNS_COMPRESSION_DEPTH) {
                return STATUS_INVALID_PARAMETER;
            }

            pos = pointer;
            continue;
        }

        // End of name
        if (labelLen == 0) {
            if (!jumped) {
                *BytesConsumed = pos - Offset + 1;
            } else {
                *BytesConsumed = firstJumpOffset - Offset;
            }

            if (namePos > 0 && NameBuffer[namePos - 1] == '.') {
                NameBuffer[namePos - 1] = '\0';
            } else {
                NameBuffer[namePos] = '\0';
            }

            return STATUS_SUCCESS;
        }

        // Validate label length (max 63 per RFC 1035)
        if (labelLen > 63) {
            return STATUS_INVALID_PARAMETER;
        }

        if (pos + 1 + labelLen > PacketSize) {
            return STATUS_INVALID_PARAMETER;
        }

        // Add separator
        if (namePos > 0 && namePos < NameBufferSize - 1) {
            NameBuffer[namePos++] = '.';
        }

        // Copy label
        ULONG copyLen = min((ULONG)labelLen, NameBufferSize - namePos - 1);
        RtlCopyMemory(NameBuffer + namePos, Packet + pos + 1, copyLen);
        namePos += copyLen;

        pos += 1 + labelLen;
    }

    // Ran out of buffer or packet — terminate what we have
    NameBuffer[min(namePos, NameBufferSize - 1)] = '\0';

    if (!jumped) {
        *BytesConsumed = pos - Offset;
    } else {
        *BytesConsumed = firstJumpOffset - Offset;
    }

    return STATUS_SUCCESS;
}
