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

#include "pch.h"
#include "PhantomCore/API/Http/HttpServer.hpp"
#include "PhantomCore/Utils/Logger.hpp"

#include <WinSock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

#include <algorithm>
#include <cassert>
#include <charconv>
#include <condition_variable>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include <deque>

namespace ShadowStrike {
namespace Http {

static constexpr wchar_t LOG_CAT[] = L"Http.Server";

// ============================================================================
// INTERNAL: IOCP Operation Types
// ============================================================================

enum class IoOperation : uint8_t {
    Accept  = 0,
    Read    = 1,
    Write   = 2,
    Close   = 3
};

// ============================================================================
// INTERNAL: Per-I/O Data (OVERLAPPED extension)
// ============================================================================

struct Connection;

struct IoContext : OVERLAPPED {
    IoOperation operation = IoOperation::Read;
    WSABUF wsaBuf{};
    std::vector<uint8_t> buffer;

    // DESIGN: Self-reference holding the owning Connection alive while an
    // overlapped I/O is in flight. Set immediately before WSARecv/WSASend,
    // cleared by the IOCP worker as soon as the completion is dequeued.
    // This is the lifetime guarantee that prevents OS-side use-after-free of
    // the OVERLAPPED block when CloseConnection erases the Connection from
    // the map while a WSARecv/WSASend is still pending in the kernel — the
    // close generates a cancellation completion that the worker must still
    // be able to dereference safely.
    //
    // No reference cycle: although the Connection owns this IoContext, the
    // self-reference only exists for the bounded interval between submit
    // and completion-dequeue. Every successful submit is paired with exactly
    // one completion (success, error, or cancellation), at which point the
    // worker moves the shared_ptr out and the cycle is broken.
    std::shared_ptr<Connection> selfRef;

    IoContext() noexcept {
        std::memset(static_cast<OVERLAPPED*>(this), 0, sizeof(OVERLAPPED));
        buffer.resize(DEFAULT_READ_BUFFER_SIZE);
        wsaBuf.buf = reinterpret_cast<char*>(buffer.data());
        wsaBuf.len = static_cast<ULONG>(buffer.size());
    }
};

// ============================================================================
// INTERNAL: Per-Connection State
// ============================================================================

struct Connection {
    SOCKET socket = INVALID_SOCKET;
    ConnectionState state = ConnectionState::Reading;
    std::string remoteAddress;
    uint16_t remotePort = 0;
    std::chrono::steady_clock::time_point connectedAt;

    // lastActivityAt is read by the timeout thread without holding ioMutex,
    // so we store it as an atomic of nanoseconds-since-epoch.
    std::atomic<int64_t> lastActivityNs{0};

    uint32_t requestCount = 0;

    // Receive accumulator
    std::vector<uint8_t> recvBuffer;

    // I/O context for async operations
    std::unique_ptr<IoContext> readCtx;
    std::unique_ptr<IoContext> writeCtx;

    // Pending send queue (serialized responses waiting to be sent)
    std::deque<std::vector<uint8_t>> sendQueue;
    bool sendInProgress = false;

    // Set by SendResponse when the response carries Connection: close so
    // OnWriteComplete actually closes the socket once the queue drains
    // instead of looping back into another WSARecv. Previously the keepAlive
    // flag was reflected only in the response header, leaving the connection
    // open after fatal parse errors and PayloadTooLarge responses.
    bool closeAfterSend = false;

    // SSE flag
    bool isSSE = false;

    // Per-connection serialisation. IOCP can deliver Read and Write
    // completions for the same socket on different worker threads
    // concurrently; without this lock OnReadComplete and OnWriteComplete
    // would race on recvBuffer / sendQueue / state / sendInProgress.
    std::mutex ioMutex;

    Connection() {
        recvBuffer.reserve(DEFAULT_READ_BUFFER_SIZE * 4);
        readCtx = std::make_unique<IoContext>();
        writeCtx = std::make_unique<IoContext>();
        const auto now = std::chrono::steady_clock::now().time_since_epoch();
        lastActivityNs.store(
            std::chrono::duration_cast<std::chrono::nanoseconds>(now).count(),
            std::memory_order_relaxed);
    }

    void TouchActivity() noexcept {
        const auto now = std::chrono::steady_clock::now().time_since_epoch();
        lastActivityNs.store(
            std::chrono::duration_cast<std::chrono::nanoseconds>(now).count(),
            std::memory_order_relaxed);
    }
};

// ============================================================================
// INTERNAL: Route Entry
// ============================================================================

struct RouteEntry {
    HttpMethod method = HttpMethod::Unknown;
    std::string pattern;
    std::vector<std::string> segments;     // split pattern segments
    std::vector<bool> isParam;             // true if segment is :param
    std::vector<std::string> paramNames;   // names of :param segments
    RequestHandler handler;
};

// ============================================================================
// INTERNAL: HTTP Request Parser
// ============================================================================

enum class ParseResult : uint8_t {
    Incomplete  = 0,    // Need more data
    Complete    = 1,    // Full request parsed
    Error       = 2     // Malformed request
};

struct ParseState {
    bool headersParsed = false;
    size_t headerEndPos = 0;
    size_t expectedBodyLength = 0;
    std::string parseError;
};

/**
 * @brief Incremental HTTP/1.1 request parser.
 *
 * Designed for security: every field is size-bounded, no unbounded allocations.
 * Handles partial reads gracefully (returns Incomplete until full request is available).
 */
class RequestParser {
public:
    explicit RequestParser(const HttpServerConfig& config) : m_config(config) {}

    /**
     * @brief Attempt to parse a complete request from the buffer.
     *
     * @param data     Raw bytes received so far
     * @param dataLen  Length of data
     * @param request  Output: parsed request (valid only if Complete returned)
     * @param consumed Output: number of bytes consumed from the buffer
     * @param error    Output: error message if Error returned
     * @return ParseResult
     */
    [[nodiscard]] ParseResult Parse(
        const uint8_t* data, size_t dataLen,
        HttpRequest& request,
        size_t& consumed,
        std::string& error) const;

private:
    const HttpServerConfig& m_config;

    [[nodiscard]] bool ParseRequestLine(
        std::string_view line, HttpRequest& request, std::string& error) const;

    [[nodiscard]] bool ParseHeaderLine(
        std::string_view line, HttpRequest& request, std::string& error) const;
};

ParseResult RequestParser::Parse(
    const uint8_t* data, size_t dataLen,
    HttpRequest& request,
    size_t& consumed,
    std::string& error) const
{
    consumed = 0;

    // Enforce maximum total request size (Slowloris / memory-exhaustion
    // protection). Compute the cap with a saturating add so two attacker-
    // chosen config values cannot wrap size_t.
    size_t maxTotal;
    if (m_config.maxBodySize > SIZE_MAX - m_config.maxHeadersTotalSize) {
        maxTotal = SIZE_MAX;
    } else {
        maxTotal = m_config.maxHeadersTotalSize + m_config.maxBodySize;
    }
    if (dataLen > maxTotal) {
        error = "Request exceeds maximum allowed size";
        return ParseResult::Error;
    }

    std::string_view view(reinterpret_cast<const char*>(data), dataLen);

    // Find end of headers (\r\n\r\n)
    auto headerEnd = view.find("\r\n\r\n");
    if (headerEnd == std::string_view::npos) {
        // Still reading headers
        if (dataLen > m_config.maxHeadersTotalSize) {
            error = "Headers exceed maximum size";
            return ParseResult::Error;
        }
        return ParseResult::Incomplete;
    }

    size_t headersSize = headerEnd + 4; // include \r\n\r\n

    if (headersSize > m_config.maxHeadersTotalSize) {
        error = "Headers exceed maximum size";
        return ParseResult::Error;
    }

    // Parse request line (first line)
    auto firstLineEnd = view.find("\r\n");
    if (firstLineEnd == std::string_view::npos || firstLineEnd == 0) {
        error = "Missing request line";
        return ParseResult::Error;
    }

    if (firstLineEnd > m_config.maxHeaderLineSize) {
        error = "Request line too long";
        return ParseResult::Error;
    }

    if (!ParseRequestLine(view.substr(0, firstLineEnd), request, error)) {
        return ParseResult::Error;
    }

    // Parse headers
    size_t headerCount = 0;
    size_t pos = firstLineEnd + 2; // skip \r\n
    bool sawContentLength = false;
    size_t contentLengthValue = 0;
    while (pos < headerEnd) {
        auto lineEnd = view.find("\r\n", pos);
        if (lineEnd == std::string_view::npos || lineEnd > headerEnd) break;

        auto line = view.substr(pos, lineEnd - pos);
        if (line.empty()) break;

        if (line.size() > m_config.maxHeaderLineSize) {
            error = "Header line too long";
            return ParseResult::Error;
        }

        if (++headerCount > m_config.maxHeaderCount) {
            error = "Too many headers";
            return ParseResult::Error;
        }

        // Reject obs-fold (RFC 7230 §3.2.4): a header line beginning with SP
        // or HTAB is a continuation of the previous header. We don't unfold,
        // and accepting it un-unfolded is itself a smuggling vector.
        if (line[0] == ' ' || line[0] == '\t') {
            error = "Obsolete header line folding is not supported";
            return ParseResult::Error;
        }

        // CL/TE smuggling defence: detect duplicate or conflicting
        // Content-Length values, and reject any Transfer-Encoding.
        const auto colon = line.find(':');
        if (colon != std::string_view::npos && colon > 0) {
            const auto name = line.substr(0, colon);
            if (CaseInsensitiveEqual{}(name, "Transfer-Encoding")) {
                error = "Transfer-Encoding is not supported";
                return ParseResult::Error;
            }
            if (CaseInsensitiveEqual{}(name, "Content-Length")) {
                // Extract value (trim OWS).
                size_t vs = colon + 1;
                while (vs < line.size() && (line[vs] == ' ' || line[vs] == '\t')) ++vs;
                size_t ve = line.size();
                while (ve > vs && (line[ve - 1] == ' ' || line[ve - 1] == '\t')) --ve;
                const auto valueSv = line.substr(vs, ve - vs);

                size_t parsed = 0;
                auto [ptr, ec] = std::from_chars(
                    valueSv.data(), valueSv.data() + valueSv.size(), parsed);
                if (ec != std::errc{} || ptr != valueSv.data() + valueSv.size()) {
                    error = "Malformed Content-Length";
                    return ParseResult::Error;
                }
                if (sawContentLength && parsed != contentLengthValue) {
                    // RFC 7230 §3.3.3: duplicate Content-Length with
                    // disagreeing values is a smuggling primitive — reject.
                    error = "Conflicting Content-Length headers";
                    return ParseResult::Error;
                }
                sawContentLength = true;
                contentLengthValue = parsed;
            }
        }

        if (!ParseHeaderLine(line, request, error)) {
            return ParseResult::Error;
        }

        pos = lineEnd + 2;
    }

    // Determine body length
    size_t bodyLength = 0;
    if (sawContentLength) {
        bodyLength = contentLengthValue;
        if (bodyLength > m_config.maxBodySize) {
            error = "Request body too large";
            return ParseResult::Error;
        }
    }

    // Check if we have the complete body. Use a saturating add so a
    // pathological Content-Length cannot wrap totalNeeded back below dataLen.
    if (bodyLength > SIZE_MAX - headersSize) {
        error = "Request body too large";
        return ParseResult::Error;
    }
    size_t totalNeeded = headersSize + bodyLength;
    if (dataLen < totalNeeded) {
        return ParseResult::Incomplete;
    }

    // Extract body
    if (bodyLength > 0) {
        request.body.assign(
            data + headersSize,
            data + headersSize + bodyLength);
    }

    consumed = totalNeeded;
    request.receivedAt = std::chrono::steady_clock::now();
    return ParseResult::Complete;
}

bool RequestParser::ParseRequestLine(
    std::string_view line, HttpRequest& request, std::string& error) const
{
    // Format: METHOD SP URI SP HTTP-version
    auto sp1 = line.find(' ');
    if (sp1 == std::string_view::npos) {
        error = "Malformed request line: missing first SP";
        return false;
    }

    auto methodStr = line.substr(0, sp1);
    if (methodStr.size() > MAX_METHOD_LENGTH) {
        error = "HTTP method too long";
        return false;
    }

    request.method = StringToHttpMethod(methodStr);
    if (request.method == HttpMethod::Unknown) {
        error = "Unknown HTTP method";
        return false;
    }

    auto rest = line.substr(sp1 + 1);
    auto sp2 = rest.find(' ');
    if (sp2 == std::string_view::npos) {
        error = "Malformed request line: missing second SP";
        return false;
    }

    auto uri = rest.substr(0, sp2);
    if (uri.size() > m_config.maxUrlLength) {
        error = "URI too long";
        return false;
    }

    // Split URI into path and query string
    auto qmark = uri.find('?');
    if (qmark != std::string_view::npos) {
        request.path = UrlDecode(uri.substr(0, qmark));
        request.queryString = std::string(uri.substr(qmark + 1));
    } else {
        request.path = UrlDecode(uri);
    }

    // Security: reject path traversal
    if (ContainsPathTraversal(request.path)) {
        error = "Path traversal detected";
        return false;
    }

    // Reject CR/LF/NUL and other C0 controls in the decoded path. Otherwise
    // a request like "GET /%0d%0aSet-Cookie:foo HTTP/1.1" would put raw CRLF
    // into request.path; any later code that echoes the path into a log line
    // or response header would trigger CRLF injection.
    for (unsigned char c : request.path) {
        if (c < 0x20 || c == 0x7F) {
            error = "Control characters in path";
            return false;
        }
    }
    for (unsigned char c : request.queryString) {
        if (c == '\r' || c == '\n' || c == '\0') {
            error = "Control characters in query string";
            return false;
        }
    }

    request.httpVersion = std::string(rest.substr(sp2 + 1));

    // Only accept HTTP/1.0 and HTTP/1.1
    if (request.httpVersion != "HTTP/1.1" && request.httpVersion != "HTTP/1.0") {
        error = "Unsupported HTTP version";
        return false;
    }

    return true;
}

bool RequestParser::ParseHeaderLine(
    std::string_view line, HttpRequest& request, std::string& error) const
{
    auto colon = line.find(':');
    if (colon == std::string_view::npos || colon == 0) {
        error = "Malformed header: missing colon";
        return false;
    }

    auto name = line.substr(0, colon);

    // Validate header name (RFC 7230: token chars only)
    for (char c : name) {
        if (c <= 0x20 || c == 0x7F || c == '(' || c == ')' || c == '<' || c == '>' ||
            c == '@' || c == ',' || c == ';' || c == ':' || c == '\\' || c == '"' ||
            c == '/' || c == '[' || c == ']' || c == '?' || c == '=' || c == '{' || c == '}') {
            error = "Invalid character in header name";
            return false;
        }
    }

    // Skip OWS (optional whitespace) after colon
    auto valStart = colon + 1;
    while (valStart < line.size() && (line[valStart] == ' ' || line[valStart] == '\t')) {
        ++valStart;
    }
    // Trim trailing OWS
    auto valEnd = line.size();
    while (valEnd > valStart && (line[valEnd - 1] == ' ' || line[valEnd - 1] == '\t')) {
        --valEnd;
    }

    auto rawValue = line.substr(valStart, valEnd - valStart);

    // RFC 7230 §3.2: reject NUL and other C0 controls except HTAB. CR/LF
    // cannot reach here (we split on CRLF) but a smuggled NUL or 0x01..0x08
    // in a header value would be propagated downstream; reject up front.
    for (unsigned char c : rawValue) {
        if (c == '\0' || c == 0x7F) {
            error = "NUL or DEL in header value";
            return false;
        }
        if (c < 0x20 && c != '\t') {
            error = "Control character in header value";
            return false;
        }
    }

    request.headers[std::string(name)] = std::string(rawValue);
    return true;
}

// ============================================================================
// INTERNAL: Route Matcher
// ============================================================================

class Router {
public:
    void AddRoute(HttpMethod method, std::string_view pattern, RequestHandler handler);

    struct MatchResult {
        const RouteEntry* route = nullptr;
        std::unordered_map<std::string, std::string> params;
        bool methodExists = false;  // path matched but method didn't
    };

    [[nodiscard]] MatchResult Match(HttpMethod method, std::string_view path) const;

private:
    std::vector<RouteEntry> m_routes;
    mutable std::shared_mutex m_mutex;

    static std::vector<std::string> SplitPath(std::string_view path);
};

std::vector<std::string> Router::SplitPath(std::string_view path) {
    std::vector<std::string> segments;
    size_t start = 0;
    // Skip leading slash
    if (!path.empty() && path[0] == '/') start = 1;

    while (start < path.size()) {
        auto end = path.find('/', start);
        if (end == std::string_view::npos) end = path.size();
        if (end > start) {
            segments.emplace_back(path.substr(start, end - start));
        }
        start = end + 1;
    }
    return segments;
}

void Router::AddRoute(HttpMethod method, std::string_view pattern, RequestHandler handler) {
    RouteEntry entry;
    entry.method = method;
    entry.pattern = std::string(pattern);
    entry.handler = std::move(handler);
    entry.segments = SplitPath(pattern);

    entry.isParam.resize(entry.segments.size(), false);
    for (size_t i = 0; i < entry.segments.size(); ++i) {
        if (!entry.segments[i].empty() && entry.segments[i][0] == ':') {
            entry.isParam[i] = true;
            entry.paramNames.push_back(entry.segments[i].substr(1));
        }
    }

    std::unique_lock lock(m_mutex);
    m_routes.push_back(std::move(entry));
}

Router::MatchResult Router::Match(HttpMethod method, std::string_view path) const {
    MatchResult result;
    auto pathSegments = SplitPath(path);

    std::shared_lock lock(m_mutex);

    for (const auto& route : m_routes) {
        if (route.segments.size() != pathSegments.size()) continue;

        bool pathMatch = true;
        std::unordered_map<std::string, std::string> params;
        size_t paramIdx = 0;

        for (size_t i = 0; i < route.segments.size(); ++i) {
            if (route.isParam[i]) {
                params[route.paramNames[paramIdx++]] = pathSegments[i];
            } else if (route.segments[i] != pathSegments[i]) {
                pathMatch = false;
                break;
            }
        }

        if (!pathMatch) continue;

        // Path matched — check method
        if (route.method != method) {
            result.methodExists = true;
            continue;
        }

        result.route = &route;
        result.params = std::move(params);
        return result;
    }

    return result;
}

// ============================================================================
// HttpServerImpl
// ============================================================================

class HttpServerImpl {
public:
    HttpServerImpl() = default;
    ~HttpServerImpl() { Shutdown(); }

    bool Initialize(const HttpServerConfig& config);
    bool Start();
    void Stop();
    void Shutdown();

    bool IsInitialized() const noexcept { return m_initialized.load(std::memory_order_acquire); }
    bool IsRunning() const noexcept { return m_state.load(std::memory_order_acquire) == ServerState::Running; }
    ServerState GetState() const noexcept { return m_state.load(std::memory_order_acquire); }
    uint16_t GetPort() const noexcept { return m_actualPort; }

    void AddRoute(HttpMethod method, std::string_view pattern, RequestHandler handler);
    void AddMiddleware(Middleware mw);

    void SetSSEEndpoint(std::string_view path);
    void BroadcastSSE(std::string_view eventType, std::string_view data);
    size_t GetSSEClientCount() const noexcept;

    HttpServerStats::Snapshot GetStats() const noexcept { return m_stats.TakeSnapshot(); }
    void ResetStats() noexcept { m_stats.Reset(); }

private:
    // Configuration
    HttpServerConfig m_config;
    std::atomic<bool> m_initialized{false};
    std::atomic<ServerState> m_state{ServerState::Stopped};
    uint16_t m_actualPort = 0;

    // Winsock
    SOCKET m_listenSocket = INVALID_SOCKET;
    HANDLE m_iocp = nullptr;
    bool m_wsaInitialized = false;

    // Threads
    std::thread m_acceptThread;
    std::vector<std::thread> m_workerThreads;
    std::atomic<bool> m_stopRequested{false};

    // Connections — shared_ptr so an in-flight worker can keep a Connection
    // alive past CloseConnection's map erase. Required for IOCP correctness:
    // closesocket() generates a cancellation completion for every pending
    // OVERLAPPED, and the kernel still dereferences our IoContext at that
    // point. The Connection (and its IoContext) must remain valid until
    // every outstanding I/O has completed.
    mutable std::shared_mutex m_connectionsMutex;
    std::unordered_map<SOCKET, std::shared_ptr<Connection>> m_connections;

    // Routing
    Router m_router;
    std::vector<Middleware> m_middlewares;
    mutable std::shared_mutex m_middlewareMutex;

    // SSE
    std::string m_sseEndpoint;
    mutable std::shared_mutex m_sseMutex;
    std::vector<SOCKET> m_sseClients;

    // Statistics
    HttpServerStats m_stats;

    // Timeout thread
    std::thread m_timeoutThread;

    // Internal methods
    void AcceptLoop();
    void WorkerLoop();
    void TimeoutLoop();

    void OnReadComplete(const std::shared_ptr<Connection>& conn, DWORD bytesTransferred);
    void OnWriteComplete(const std::shared_ptr<Connection>& conn, DWORD bytesTransferred);

    void ProcessRequest(const std::shared_ptr<Connection>& conn, HttpRequest& request);
    // Locked: caller holds conn->ioMutex.
    void SendResponseLocked(Connection& conn, HttpResponse& response, bool keepAlive);
    void StartAsyncRead(const std::shared_ptr<Connection>& conn);
    // Locked: caller holds conn->ioMutex.
    void StartAsyncSendLocked(const std::shared_ptr<Connection>& conn);
    void CloseConnection(SOCKET sock);

    void AddSecurityHeaders(HttpResponse& response) const;

    static bool InitWinsock();
    static void CleanupWinsock();
};

// ============================================================================
// Winsock Init/Cleanup
// ============================================================================

bool HttpServerImpl::InitWinsock() {
    WSADATA wsaData{};
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        SS_LOG_ERROR(LOG_CAT, L"WSAStartup failed: error=%d", result);
        return false;
    }
    return true;
}

void HttpServerImpl::CleanupWinsock() {
    WSACleanup();
}

// ============================================================================
// Initialize
// ============================================================================

bool HttpServerImpl::Initialize(const HttpServerConfig& config) {
    if (m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(LOG_CAT, L"HttpServer already initialized");
        return false;
    }

    if (!config.IsValid()) {
        SS_LOG_ERROR(LOG_CAT, L"Invalid HttpServer configuration");
        return false;
    }

    // Enforce localhost-only binding at initialization
    if (config.bindAddress != "127.0.0.1" && config.bindAddress != "::1" &&
        config.bindAddress != "localhost") {
        SS_LOG_ERROR(LOG_CAT,
            L"SECURITY VIOLATION: HttpServer MUST bind to localhost. "
            L"Attempted bind to non-local address.");
        return false;
    }

    if (!InitWinsock()) return false;
    m_wsaInitialized = true;

    // Create IOCP
    m_iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 0);
    if (!m_iocp) {
        SS_LOG_ERROR(LOG_CAT, L"CreateIoCompletionPort failed: error=%lu", GetLastError());
        CleanupWinsock();
        m_wsaInitialized = false;
        return false;
    }

    m_config = config;
    m_initialized.store(true, std::memory_order_release);

    SS_LOG_INFO(LOG_CAT, L"HttpServer initialized (bind=%hs port=%u workers=%zu)",
        config.bindAddress.c_str(), config.port,
        config.workerThreads == 0 ? std::thread::hardware_concurrency() : config.workerThreads);
    return true;
}

// ============================================================================
// Start
// ============================================================================

bool HttpServerImpl::Start() {
    if (!m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(LOG_CAT, L"Cannot start: not initialized");
        return false;
    }
    if (m_state.load(std::memory_order_acquire) == ServerState::Running) {
        SS_LOG_WARN(LOG_CAT, L"HttpServer already running");
        return false;
    }

    m_state.store(ServerState::Starting, std::memory_order_release);
    m_stopRequested.store(false, std::memory_order_release);

    // Create listening socket
    struct addrinfo hints{};
    hints.ai_family = (m_config.bindAddress == "::1") ? AF_INET6 : AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    std::string portStr = std::to_string(m_config.port);
    struct addrinfo* addrResult = nullptr;
    int rv = getaddrinfo(m_config.bindAddress.c_str(), portStr.c_str(), &hints, &addrResult);
    if (rv != 0) {
        SS_LOG_ERROR(LOG_CAT, L"getaddrinfo failed: error=%d", rv);
        m_state.store(ServerState::Error, std::memory_order_release);
        return false;
    }

    m_listenSocket = WSASocketW(
        addrResult->ai_family, addrResult->ai_socktype, addrResult->ai_protocol,
        nullptr, 0, WSA_FLAG_OVERLAPPED);

    if (m_listenSocket == INVALID_SOCKET) {
        SS_LOG_ERROR(LOG_CAT, L"WSASocket failed: error=%d", WSAGetLastError());
        freeaddrinfo(addrResult);
        m_state.store(ServerState::Error, std::memory_order_release);
        return false;
    }

    // Allow port reuse for rapid restart
    int optVal = 1;
    setsockopt(m_listenSocket, SOL_SOCKET, SO_REUSEADDR,
        reinterpret_cast<const char*>(&optVal), sizeof(optVal));

    // Disable Nagle for responsive API responses
    setsockopt(m_listenSocket, IPPROTO_TCP, TCP_NODELAY,
        reinterpret_cast<const char*>(&optVal), sizeof(optVal));

    // For an IPv6 listener, force IPV6_V6ONLY=1. Without this, on systems
    // where the OS default is dual-stack, "::1" would also accept IPv4
    // connections — bypassing the AF_INET-specific localhost check below
    // by surfacing peers as "::ffff:127.0.0.1".
    if (addrResult->ai_family == AF_INET6) {
        DWORD v6only = 1;
        setsockopt(m_listenSocket, IPPROTO_IPV6, IPV6_V6ONLY,
            reinterpret_cast<const char*>(&v6only), sizeof(v6only));
    }

    // Bind
    rv = bind(m_listenSocket, addrResult->ai_addr, static_cast<int>(addrResult->ai_addrlen));
    freeaddrinfo(addrResult);

    if (rv == SOCKET_ERROR) {
        SS_LOG_ERROR(LOG_CAT, L"bind failed: error=%d", WSAGetLastError());
        closesocket(m_listenSocket);
        m_listenSocket = INVALID_SOCKET;
        m_state.store(ServerState::Error, std::memory_order_release);
        return false;
    }

    // Listen
    if (listen(m_listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        SS_LOG_ERROR(LOG_CAT, L"listen failed: error=%d", WSAGetLastError());
        closesocket(m_listenSocket);
        m_listenSocket = INVALID_SOCKET;
        m_state.store(ServerState::Error, std::memory_order_release);
        return false;
    }

    // Retrieve actual port (useful if port 0 was requested)
    struct sockaddr_storage addr{};
    int addrLen = sizeof(addr);
    if (getsockname(m_listenSocket, reinterpret_cast<sockaddr*>(&addr), &addrLen) == 0) {
        if (addr.ss_family == AF_INET) {
            m_actualPort = ntohs(reinterpret_cast<sockaddr_in*>(&addr)->sin_port);
        } else if (addr.ss_family == AF_INET6) {
            m_actualPort = ntohs(reinterpret_cast<sockaddr_in6*>(&addr)->sin6_port);
        }
    } else {
        m_actualPort = m_config.port;
    }

    m_stats.startTime = std::chrono::steady_clock::now();

    // Start worker threads
    size_t numWorkers = m_config.workerThreads;
    if (numWorkers == 0) {
        numWorkers = std::max<size_t>(2, std::thread::hardware_concurrency());
    }
    numWorkers = std::min<size_t>(numWorkers, 32);

    m_workerThreads.reserve(numWorkers);
    for (size_t i = 0; i < numWorkers; ++i) {
        m_workerThreads.emplace_back(&HttpServerImpl::WorkerLoop, this);
    }

    // Start accept thread
    m_acceptThread = std::thread(&HttpServerImpl::AcceptLoop, this);

    // Start timeout monitor
    m_timeoutThread = std::thread(&HttpServerImpl::TimeoutLoop, this);

    m_state.store(ServerState::Running, std::memory_order_release);

    SS_LOG_INFO(LOG_CAT, L"HttpServer started on %hs:%u (%zu workers)",
        m_config.bindAddress.c_str(), m_actualPort, numWorkers);
    return true;
}

// ============================================================================
// Stop
// ============================================================================

void HttpServerImpl::Stop() {
    auto expected = ServerState::Running;
    if (!m_state.compare_exchange_strong(expected, ServerState::Stopping,
            std::memory_order_acq_rel)) {
        return;
    }

    SS_LOG_INFO(LOG_CAT, L"HttpServer stopping...");

    m_stopRequested.store(true, std::memory_order_release);

    // Close listen socket to unblock accept
    if (m_listenSocket != INVALID_SOCKET) {
        closesocket(m_listenSocket);
        m_listenSocket = INVALID_SOCKET;
    }

    // Wake up IOCP workers by posting null completions
    size_t workerCount = m_workerThreads.size();
    for (size_t i = 0; i < workerCount; ++i) {
        PostQueuedCompletionStatus(m_iocp, 0, 0, nullptr);
    }

    // Join accept thread
    if (m_acceptThread.joinable()) m_acceptThread.join();

    // Join worker threads
    for (auto& t : m_workerThreads) {
        if (t.joinable()) t.join();
    }
    m_workerThreads.clear();

    // Join timeout thread
    if (m_timeoutThread.joinable()) m_timeoutThread.join();

    // Close all connections
    {
        std::unique_lock lock(m_connectionsMutex);
        for (auto& [sock, conn] : m_connections) {
            if (sock != INVALID_SOCKET) {
                shutdown(sock, SD_BOTH);
                closesocket(sock);
            }
        }
        m_connections.clear();
    }

    // Clear SSE clients
    {
        std::unique_lock lock(m_sseMutex);
        m_sseClients.clear();
    }

    m_state.store(ServerState::Stopped, std::memory_order_release);
    SS_LOG_INFO(LOG_CAT, L"HttpServer stopped");
}

// ============================================================================
// Shutdown
// ============================================================================

void HttpServerImpl::Shutdown() {
    if (m_state.load(std::memory_order_acquire) == ServerState::Running) {
        Stop();
    }

    if (m_iocp) {
        CloseHandle(m_iocp);
        m_iocp = nullptr;
    }

    if (m_wsaInitialized) {
        CleanupWinsock();
        m_wsaInitialized = false;
    }

    m_initialized.store(false, std::memory_order_release);
}

// ============================================================================
// Accept Loop
// ============================================================================

void HttpServerImpl::AcceptLoop() {
    SetThreadDescription(GetCurrentThread(), L"SS-HttpAccept");

    while (!m_stopRequested.load(std::memory_order_acquire)) {
        struct sockaddr_storage clientAddr{};
        int clientAddrLen = sizeof(clientAddr);

        SOCKET clientSocket = accept(m_listenSocket,
            reinterpret_cast<sockaddr*>(&clientAddr), &clientAddrLen);

        if (clientSocket == INVALID_SOCKET) {
            if (m_stopRequested.load(std::memory_order_acquire)) break;
            int err = WSAGetLastError();
            if (err != WSAEINTR && err != WSAENOTSOCK) {
                SS_LOG_WARN(LOG_CAT, L"accept() failed: error=%d", err);
            }
            continue;
        }

        // Check connection limit
        {
            std::shared_lock lock(m_connectionsMutex);
            if (m_connections.size() >= m_config.maxConnections) {
                m_stats.rejectedConnections.fetch_add(1, std::memory_order_relaxed);
                closesocket(clientSocket);
                SS_LOG_WARN(LOG_CAT, L"Connection limit reached (%zu), rejected",
                    m_config.maxConnections);
                continue;
            }
        }

        // Extract remote address for logging
        char addrBuf[INET6_ADDRSTRLEN]{};
        uint16_t remotePort = 0;
        if (clientAddr.ss_family == AF_INET) {
            auto* sin = reinterpret_cast<sockaddr_in*>(&clientAddr);
            inet_ntop(AF_INET, &sin->sin_addr, addrBuf, sizeof(addrBuf));
            remotePort = ntohs(sin->sin_port);
        } else if (clientAddr.ss_family == AF_INET6) {
            auto* sin6 = reinterpret_cast<sockaddr_in6*>(&clientAddr);
            inet_ntop(AF_INET6, &sin6->sin6_addr, addrBuf, sizeof(addrBuf));
            remotePort = ntohs(sin6->sin6_port);
        }

        // Security: verify this is actually from localhost
        std::string_view remoteAddr(addrBuf);
        if (remoteAddr != "127.0.0.1" && remoteAddr != "::1") {
            SS_LOG_ERROR(LOG_CAT,
                L"SECURITY: Rejected non-localhost connection from %hs:%u",
                addrBuf, remotePort);
            closesocket(clientSocket);
            continue;
        }

        // Disable Nagle on accepted socket
        int optVal = 1;
        setsockopt(clientSocket, IPPROTO_TCP, TCP_NODELAY,
            reinterpret_cast<const char*>(&optVal), sizeof(optVal));

        // Associate with IOCP
        HANDLE result = CreateIoCompletionPort(
            reinterpret_cast<HANDLE>(clientSocket), m_iocp,
            static_cast<ULONG_PTR>(clientSocket), 0);

        if (!result) {
            SS_LOG_ERROR(LOG_CAT, L"Failed to associate socket with IOCP: error=%lu",
                GetLastError());
            closesocket(clientSocket);
            continue;
        }

        // Create connection state (shared_ptr — see m_connections design note)
        auto conn = std::make_shared<Connection>();
        conn->socket = clientSocket;
        conn->remoteAddress = addrBuf;
        conn->remotePort = remotePort;
        conn->connectedAt = std::chrono::steady_clock::now();
        conn->TouchActivity();

        {
            std::unique_lock lock(m_connectionsMutex);
            m_connections[clientSocket] = conn;
        }

        m_stats.totalConnections.fetch_add(1, std::memory_order_relaxed);
        m_stats.activeConnections.fetch_add(1, std::memory_order_relaxed);

        StartAsyncRead(conn);
    }
}

// ============================================================================
// Worker Loop (IOCP)
// ============================================================================

void HttpServerImpl::WorkerLoop() {
    SetThreadDescription(GetCurrentThread(), L"SS-HttpWorker");

    while (!m_stopRequested.load(std::memory_order_acquire)) {
        DWORD bytesTransferred = 0;
        ULONG_PTR completionKey = 0;
        OVERLAPPED* overlapped = nullptr;

        BOOL success = GetQueuedCompletionStatus(
            m_iocp, &bytesTransferred, &completionKey, &overlapped,
            1000); // 1 second timeout to allow periodic stop checks

        // Adopt the self-reference held by the IoContext (if any) BEFORE
        // doing anything else. This guarantees the Connection (and the
        // OVERLAPPED block) survive for the entire duration of this
        // dispatch even if CloseConnection has already removed it from
        // m_connections on another thread.
        std::shared_ptr<Connection> ioOwner;
        IoContext* ioCtx = nullptr;
        if (overlapped) {
            ioCtx = static_cast<IoContext*>(overlapped);
            ioOwner = std::move(ioCtx->selfRef);
        }

        if (!success) {
            if (!overlapped) {
                // Timeout or error not associated with any I/O.
                continue;
            }
            // I/O error or cancellation on a socket. ioOwner already keeps
            // the Connection alive; close drops the map entry once.
            const SOCKET sock = static_cast<SOCKET>(completionKey);
            CloseConnection(sock);
            continue;
        }

        if (!overlapped) {
            // Null overlapped = shutdown signal from PostQueuedCompletionStatus.
            break;
        }

        const SOCKET sock = static_cast<SOCKET>(completionKey);

        // Prefer the I/O-context-held shared_ptr over a fresh map lookup —
        // it is the canonical, race-free reference. Fall back to the map
        // only if the IoContext somehow had no selfRef (defence in depth).
        std::shared_ptr<Connection> conn = ioOwner;
        if (!conn) {
            std::shared_lock lock(m_connectionsMutex);
            auto it = m_connections.find(sock);
            if (it == m_connections.end()) continue;
            conn = it->second;
        }

        if (bytesTransferred == 0 && ioCtx->operation == IoOperation::Read) {
            // Graceful disconnect by peer.
            CloseConnection(sock);
            continue;
        }

        conn->TouchActivity();

        switch (ioCtx->operation) {
            case IoOperation::Read:
                OnReadComplete(conn, bytesTransferred);
                break;
            case IoOperation::Write:
                OnWriteComplete(conn, bytesTransferred);
                break;
            default:
                break;
        }
    }
}

// ============================================================================
// Timeout Loop (Slowloris/Idle Cleanup)
// ============================================================================

void HttpServerImpl::TimeoutLoop() {
    SetThreadDescription(GetCurrentThread(), L"SS-HttpTimeout");

    while (!m_stopRequested.load(std::memory_order_acquire)) {
        Sleep(2000); // Check every 2 seconds

        const auto now = std::chrono::steady_clock::now();
        const int64_t nowNs = std::chrono::duration_cast<std::chrono::nanoseconds>(
            now.time_since_epoch()).count();

        std::vector<SOCKET> toClose;

        {
            std::shared_lock lock(m_connectionsMutex);
            for (const auto& [sock, conn] : m_connections) {
                if (conn->isSSE) continue;

                const int64_t lastNs = conn->lastActivityNs.load(std::memory_order_relaxed);
                const auto idleSec = (nowNs - lastNs) / 1'000'000'000LL;

                std::lock_guard ioLock(conn->ioMutex);
                if (conn->state == ConnectionState::Reading &&
                    conn->recvBuffer.empty() &&
                    idleSec > static_cast<int64_t>(m_config.keepAliveTimeoutSec)) {
                    toClose.push_back(sock);
                } else if (conn->state == ConnectionState::Reading &&
                           !conn->recvBuffer.empty() &&
                           idleSec > static_cast<int64_t>(m_config.incompleteRequestTimeoutSec)) {
                    m_stats.timeouts.fetch_add(1, std::memory_order_relaxed);
                    SS_LOG_WARN(LOG_CAT,
                        L"Closing connection from %hs:%u (incomplete request timeout)",
                        conn->remoteAddress.c_str(), conn->remotePort);
                    toClose.push_back(sock);
                }
            }
        }

        for (SOCKET sock : toClose) {
            CloseConnection(sock);
        }
    }
}

// ============================================================================
// Async Read
// ============================================================================

void HttpServerImpl::StartAsyncRead(const std::shared_ptr<Connection>& conn) {
    auto& ctx = *conn->readCtx;
    ctx.operation = IoOperation::Read;
    std::memset(static_cast<OVERLAPPED*>(&ctx), 0, sizeof(OVERLAPPED));
    ctx.wsaBuf.buf = reinterpret_cast<char*>(ctx.buffer.data());
    ctx.wsaBuf.len = static_cast<ULONG>(ctx.buffer.size());

    // Self-reference must be set BEFORE WSARecv. If WSARecv succeeds (or
    // returns WSA_IO_PENDING) the OS owns the OVERLAPPED until completion;
    // the IOCP worker will move selfRef out then. If WSARecv fails
    // synchronously with anything else there is no completion, so we must
    // drop the selfRef here to avoid a permanent reference leak.
    ctx.selfRef = conn;

    DWORD flags = 0;
    DWORD bytesRecv = 0;
    int result = WSARecv(conn->socket, &ctx.wsaBuf, 1,
        &bytesRecv, &flags, &ctx, nullptr);

    if (result == SOCKET_ERROR) {
        const int err = WSAGetLastError();
        if (err != WSA_IO_PENDING) {
            ctx.selfRef.reset();
            SS_LOG_WARN(LOG_CAT, L"WSARecv failed: error=%d", err);
            CloseConnection(conn->socket);
        }
    }
}

// ============================================================================
// OnReadComplete
// ============================================================================

void HttpServerImpl::OnReadComplete(const std::shared_ptr<Connection>& conn, DWORD bytesTransferred) {
    m_stats.bytesReceived.fetch_add(bytesTransferred, std::memory_order_relaxed);

    // Take per-connection lock for the entire dispatch — Read and Write
    // completions can run concurrently on different worker threads and
    // both touch recvBuffer / sendQueue / state / sendInProgress.
    std::unique_lock ioLock(conn->ioMutex);

    // Append received data to the connection's accumulator
    conn->recvBuffer.insert(
        conn->recvBuffer.end(),
        conn->readCtx->buffer.data(),
        conn->readCtx->buffer.data() + bytesTransferred);

    // Try to parse as many complete pipelined requests as already buffered
    // before posting a fresh WSARecv. Without this loop a client that
    // pipelines two requests in one TCP segment would have its second
    // request stall until further bytes arrived — eventually closed by
    // the Slowloris timeout.
    while (true) {
        RequestParser parser(m_config);
        HttpRequest request;
        size_t consumed = 0;
        std::string parseError;

        const auto result = parser.Parse(
            conn->recvBuffer.data(), conn->recvBuffer.size(),
            request, consumed, parseError);

        if (result == ParseResult::Complete) {
            conn->recvBuffer.erase(
                conn->recvBuffer.begin(),
                conn->recvBuffer.begin() + static_cast<ptrdiff_t>(consumed));
            conn->requestCount++;

            request.remoteAddress = conn->remoteAddress;
            request.remotePort = conn->remotePort;
            conn->state = ConnectionState::Processing;

            m_stats.totalRequests.fetch_add(1, std::memory_order_relaxed);

            // ProcessRequest queues a response into sendQueue under the
            // ioMutex via SendResponseLocked. Release-and-reacquire is
            // unnecessary because handler invocation is itself serialised
            // by the lock.
            ProcessRequest(conn, request);

            // If we asked to close after this response, do not parse any
            // pipelined follow-up — the client gets one response and we
            // close.
            if (conn->closeAfterSend) break;

            // Bound the loop by the keep-alive cap to prevent a malicious
            // client from holding a worker thread indefinitely.
            if (conn->requestCount >= m_config.maxKeepAliveRequests) break;

            if (conn->recvBuffer.empty()) break;
            // Else try to parse another already-buffered request.
            continue;
        }

        if (result == ParseResult::Incomplete) {
            if (conn->recvBuffer.size() > m_config.maxHeadersTotalSize + m_config.maxBodySize) {
                HttpResponse resp = HttpResponse::MakeError(
                    HttpStatus::PayloadTooLarge, "Request too large");
                AddSecurityHeaders(resp);
                SendResponseLocked(*conn, resp, false);
                return;
            }
            // Need more data — post another read. Still under lock; the
            // submission path itself is non-blocking.
            StartAsyncRead(conn);
            return;
        }

        // ParseResult::Error
        m_stats.parseErrors.fetch_add(1, std::memory_order_relaxed);
        if (m_config.enableRequestLogging) {
            SS_LOG_WARN(LOG_CAT, L"HTTP parse error from %hs:%u: %hs",
                conn->remoteAddress.c_str(), conn->remotePort, parseError.c_str());
        }
        HttpResponse resp = HttpResponse::MakeError(
            HttpStatus::BadRequest, parseError);
        AddSecurityHeaders(resp);
        SendResponseLocked(*conn, resp, false);
        return;
    }
}

// ============================================================================
// Process Request (Route Dispatch)
// ============================================================================

void HttpServerImpl::ProcessRequest(const std::shared_ptr<Connection>& conn, HttpRequest& request) {
    HttpResponse response;

    // Check if this is an SSE endpoint
    if (!m_sseEndpoint.empty() && request.path == m_sseEndpoint &&
        request.method == HttpMethod::GET) {
        // SSE connection — hold open
        conn->isSSE = true;
        conn->state = ConnectionState::Writing;

        // Send SSE headers
        std::string sseHeaders = "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/event-stream\r\n"
            "Cache-Control: no-cache\r\n"
            "Connection: keep-alive\r\n"
            "X-Content-Type-Options: nosniff\r\n"
            "\r\n";

        std::vector<uint8_t> data(sseHeaders.begin(), sseHeaders.end());
        conn->sendQueue.push_back(std::move(data));
        StartAsyncSendLocked(conn);

        {
            std::unique_lock lock(m_sseMutex);
            m_sseClients.push_back(conn->socket);
        }

        SS_LOG_INFO(LOG_CAT, L"SSE client connected from %hs:%u",
            conn->remoteAddress.c_str(), conn->remotePort);
        return;
    }

    // Execute middleware chain
    bool proceed = true;
    {
        std::shared_lock lock(m_middlewareMutex);
        for (const auto& mw : m_middlewares) {
            if (!mw(request, response)) {
                proceed = false;
                break;
            }
        }
    }

    if (proceed) {
        // Route matching
        auto match = m_router.Match(request.method, request.path);

        if (match.route) {
            request.pathParams = std::move(match.params);
            try {
                match.route->handler(request, response);
            } catch (const std::exception& ex) {
                SS_LOG_ERROR(LOG_CAT, L"Handler exception on %hs %hs: %hs",
                    HttpMethodToString(request.method),
                    request.path.c_str(), ex.what());
                response = HttpResponse::MakeError(
                    HttpStatus::InternalError, "Internal server error");
            } catch (...) {
                SS_LOG_ERROR(LOG_CAT, L"Unknown handler exception on %hs %hs",
                    HttpMethodToString(request.method), request.path.c_str());
                response = HttpResponse::MakeError(
                    HttpStatus::InternalError, "Internal server error");
            }
        } else if (match.methodExists) {
            response = HttpResponse::MakeError(
                HttpStatus::MethodNotAllowed, "Method not allowed");
            response.SetHeader("Allow", "GET, POST, PUT, DELETE, PATCH");
        } else {
            response = HttpResponse::MakeError(
                HttpStatus::NotFound, "Not found");
        }
    }

    AddSecurityHeaders(response);

    if (m_config.enableRequestLogging) {
        SS_LOG_INFO(LOG_CAT, L"%hs %hs -> %u",
            HttpMethodToString(request.method),
            request.path.c_str(),
            static_cast<uint16_t>(response.status));
    }

    const bool keepAlive = request.IsKeepAlive() && m_config.enableKeepAlive &&
                           conn->requestCount < m_config.maxKeepAliveRequests;
    SendResponseLocked(*conn, response, keepAlive);
}

// ============================================================================
// Send Response
// ============================================================================

void HttpServerImpl::SendResponseLocked(Connection& conn, HttpResponse& response, bool keepAlive) {
    if (!keepAlive) {
        response.SetHeader("Connection", "close");
        // The previous code only set the header but kept reading from the
        // socket after the response drained. Mark the connection so
        // OnWriteComplete actually closes it once the queue empties.
        conn.closeAfterSend = true;
    } else {
        response.SetHeader("Connection", "keep-alive");
        response.SetHeader("Keep-Alive",
            "timeout=" + std::to_string(m_config.keepAliveTimeoutSec) +
            ", max=" + std::to_string(m_config.maxKeepAliveRequests));
    }

    auto serialized = response.Serialize();
    m_stats.bytesSent.fetch_add(serialized.size(), std::memory_order_relaxed);
    m_stats.totalResponses.fetch_add(1, std::memory_order_relaxed);

    conn.sendQueue.push_back(std::move(serialized));
    conn.state = ConnectionState::Writing;

    if (!conn.sendInProgress) {
        // Need a shared_ptr to attach to the IoContext selfRef. Look up
        // ourselves in the map under the connections lock.
        std::shared_ptr<Connection> connPtr;
        {
            std::shared_lock lock(m_connectionsMutex);
            auto it = m_connections.find(conn.socket);
            if (it != m_connections.end()) connPtr = it->second;
        }
        if (connPtr) {
            StartAsyncSendLocked(connPtr);
        }
    }
}

// ============================================================================
// Async Send
// ============================================================================

void HttpServerImpl::StartAsyncSendLocked(const std::shared_ptr<Connection>& conn) {
    if (conn->sendQueue.empty()) {
        // Nothing to send — caller is responsible for what comes next
        // (OnWriteComplete drives the post-send transition).
        conn->sendInProgress = false;
        return;
    }

    conn->sendInProgress = true;
    auto& data = conn->sendQueue.front();

    auto& ctx = *conn->writeCtx;
    ctx.operation = IoOperation::Write;
    std::memset(static_cast<OVERLAPPED*>(&ctx), 0, sizeof(OVERLAPPED));
    // Copy out of the deque so the buffer remains stable until completion.
    ctx.buffer = data;
    ctx.wsaBuf.buf = reinterpret_cast<char*>(ctx.buffer.data());
    ctx.wsaBuf.len = static_cast<ULONG>(ctx.buffer.size());

    conn->sendQueue.pop_front();

    ctx.selfRef = conn;

    DWORD bytesSent = 0;
    int result = WSASend(conn->socket, &ctx.wsaBuf, 1,
        &bytesSent, 0, &ctx, nullptr);

    if (result == SOCKET_ERROR) {
        const int err = WSAGetLastError();
        if (err != WSA_IO_PENDING) {
            ctx.selfRef.reset();
            SS_LOG_WARN(LOG_CAT, L"WSASend failed: error=%d", err);
            CloseConnection(conn->socket);
        }
    }
}

// ============================================================================
// OnWriteComplete
// ============================================================================

void HttpServerImpl::OnWriteComplete(const std::shared_ptr<Connection>& conn, DWORD bytesTransferred) {
    (void)bytesTransferred;

    std::unique_lock ioLock(conn->ioMutex);

    if (!conn->sendQueue.empty()) {
        // More data to send.
        StartAsyncSendLocked(conn);
        return;
    }

    conn->sendInProgress = false;

    if (conn->isSSE) {
        // SSE connections stay open — don't restart read.
        return;
    }

    // Honour Connection: close (parse errors, PayloadTooLarge, explicit
    // client request, request count cap).
    if (conn->closeAfterSend ||
        conn->requestCount >= m_config.maxKeepAliveRequests) {
        ioLock.unlock();
        CloseConnection(conn->socket);
        return;
    }

    // Keep-alive: post the next read. If recvBuffer already contains the
    // start of a pipelined request the next OnReadComplete will pick it up
    // — but to make sure no buffered data is forgotten when zero bytes
    // arrive on the next WSARecv, parse what we already have first.
    conn->state = ConnectionState::Reading;
    if (!conn->recvBuffer.empty()) {
        ioLock.unlock();
        // Reuse the pipelined-parse path by simulating a 0-byte completion.
        OnReadComplete(conn, 0);
        return;
    }
    StartAsyncRead(conn);
}

// ============================================================================
// Close Connection
// ============================================================================

void HttpServerImpl::CloseConnection(SOCKET sock) {
    std::shared_ptr<Connection> conn;
    {
        std::unique_lock lock(m_connectionsMutex);
        auto it = m_connections.find(sock);
        if (it == m_connections.end()) return;
        conn = std::move(it->second);
        m_connections.erase(it);
    }

    // Remove from SSE clients if applicable.
    if (conn->isSSE) {
        std::unique_lock lock(m_sseMutex);
        m_sseClients.erase(
            std::remove(m_sseClients.begin(), m_sseClients.end(), sock),
            m_sseClients.end());
    }

    // closesocket() triggers cancellation of every pending overlapped on
    // this socket; the cancellation completions flow through WorkerLoop,
    // which adopts the IoContext's selfRef. The Connection (and its
    // OVERLAPPED blocks) therefore stay alive until the kernel has signed
    // off on every outstanding I/O — preventing a kernel UAF on the
    // OVERLAPPED memory.
    shutdown(sock, SD_BOTH);
    closesocket(sock);
    m_stats.activeConnections.fetch_sub(1, std::memory_order_relaxed);
}

// ============================================================================
// Security Headers
// ============================================================================

void HttpServerImpl::AddSecurityHeaders(HttpResponse& response) const {
    response.SetHeader("X-Content-Type-Options", "nosniff");
    response.SetHeader("X-Frame-Options", "DENY");
    response.SetHeader("X-XSS-Protection", "0");
    response.SetHeader("Cache-Control", "no-store, no-cache, must-revalidate");
    response.SetHeader("Pragma", "no-cache");
    response.SetHeader("Referrer-Policy", "no-referrer");
    response.SetHeader("Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'");

    if (!m_config.serverIdentity.empty()) {
        response.SetHeader("Server", m_config.serverIdentity);
    }
}

// ============================================================================
// Route Registration Helpers
// ============================================================================

void HttpServerImpl::AddRoute(HttpMethod method, std::string_view pattern, RequestHandler handler) {
    m_router.AddRoute(method, pattern, std::move(handler));
}

void HttpServerImpl::AddMiddleware(Middleware mw) {
    std::unique_lock lock(m_middlewareMutex);
    m_middlewares.push_back(std::move(mw));
}

// ============================================================================
// SSE
// ============================================================================

void HttpServerImpl::SetSSEEndpoint(std::string_view path) {
    m_sseEndpoint = std::string(path);
}

void HttpServerImpl::BroadcastSSE(std::string_view eventType, std::string_view data) {
    std::string message = "event: ";
    message += eventType;
    message += "\ndata: ";
    message += data;
    message += "\n\n";

    std::vector<uint8_t> bytes(message.begin(), message.end());

    std::shared_lock lock(m_sseMutex);
    std::vector<SOCKET> deadClients;

    for (SOCKET sock : m_sseClients) {
        // Synchronous send for SSE (small payloads, localhost)
        int sent = send(sock, reinterpret_cast<const char*>(bytes.data()),
            static_cast<int>(bytes.size()), 0);
        if (sent == SOCKET_ERROR) {
            deadClients.push_back(sock);
        }
    }

    if (!deadClients.empty()) {
        lock.unlock();
        for (SOCKET sock : deadClients) {
            CloseConnection(sock);
        }
    }
}

size_t HttpServerImpl::GetSSEClientCount() const noexcept {
    std::shared_lock lock(m_sseMutex);
    return m_sseClients.size();
}

// ============================================================================
// HttpServerConfig::IsValid
// ============================================================================

bool HttpServerConfig::IsValid() const noexcept {
    // Localhost-only binding
    if (bindAddress != "127.0.0.1" && bindAddress != "::1" && bindAddress != "localhost") {
        return false;
    }
    if (port == 0) return false;
    if (maxConnections == 0 || maxConnections > 10000) return false;
    if (maxBodySize == 0 || maxBodySize > 100ULL * 1024 * 1024) return false;
    if (maxHeaderCount == 0 || maxHeaderCount > 1000) return false;
    if (keepAliveTimeoutSec == 0 || keepAliveTimeoutSec > 3600) return false;
    if (incompleteRequestTimeoutSec == 0 || incompleteRequestTimeoutSec > 300) return false;
    return true;
}

// ============================================================================
// HttpServerStats
// ============================================================================

HttpServerStats::Snapshot HttpServerStats::TakeSnapshot() const noexcept {
    Snapshot s;
    s.totalRequests       = totalRequests.load(std::memory_order_relaxed);
    s.totalResponses      = totalResponses.load(std::memory_order_relaxed);
    s.activeConnections   = activeConnections.load(std::memory_order_relaxed);
    s.totalConnections    = totalConnections.load(std::memory_order_relaxed);
    s.rejectedConnections = rejectedConnections.load(std::memory_order_relaxed);
    s.parseErrors         = parseErrors.load(std::memory_order_relaxed);
    s.timeouts            = timeouts.load(std::memory_order_relaxed);
    s.bytesReceived       = bytesReceived.load(std::memory_order_relaxed);
    s.bytesSent           = bytesSent.load(std::memory_order_relaxed);
    s.uptime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    return s;
}

void HttpServerStats::Reset() noexcept {
    totalRequests.store(0, std::memory_order_relaxed);
    totalResponses.store(0, std::memory_order_relaxed);
    rejectedConnections.store(0, std::memory_order_relaxed);
    parseErrors.store(0, std::memory_order_relaxed);
    timeouts.store(0, std::memory_order_relaxed);
    bytesReceived.store(0, std::memory_order_relaxed);
    bytesSent.store(0, std::memory_order_relaxed);
    startTime = std::chrono::steady_clock::now();
}

// ============================================================================
// HttpServer (Public API → PIMPL delegation)
// ============================================================================

HttpServer::HttpServer() : m_impl(std::make_unique<HttpServerImpl>()) {}
HttpServer::~HttpServer() = default;
HttpServer::HttpServer(HttpServer&&) noexcept = default;
HttpServer& HttpServer::operator=(HttpServer&&) noexcept = default;

bool HttpServer::Initialize(const HttpServerConfig& config) { return m_impl->Initialize(config); }
bool HttpServer::Start() { return m_impl->Start(); }
void HttpServer::Stop() { m_impl->Stop(); }
void HttpServer::Shutdown() { m_impl->Shutdown(); }
bool HttpServer::IsInitialized() const noexcept { return m_impl->IsInitialized(); }
bool HttpServer::IsRunning() const noexcept { return m_impl->IsRunning(); }
ServerState HttpServer::GetState() const noexcept { return m_impl->GetState(); }
uint16_t HttpServer::GetPort() const noexcept { return m_impl->GetPort(); }

void HttpServer::Get(std::string_view p, RequestHandler h) { m_impl->AddRoute(HttpMethod::GET, p, std::move(h)); }
void HttpServer::Post(std::string_view p, RequestHandler h) { m_impl->AddRoute(HttpMethod::POST, p, std::move(h)); }
void HttpServer::Put(std::string_view p, RequestHandler h) { m_impl->AddRoute(HttpMethod::PUT, p, std::move(h)); }
void HttpServer::Delete(std::string_view p, RequestHandler h) { m_impl->AddRoute(HttpMethod::DELETE_, p, std::move(h)); }
void HttpServer::Patch(std::string_view p, RequestHandler h) { m_impl->AddRoute(HttpMethod::PATCH, p, std::move(h)); }
void HttpServer::Route(HttpMethod m, std::string_view p, RequestHandler h) { m_impl->AddRoute(m, p, std::move(h)); }

void HttpServer::Use(Middleware mw) { m_impl->AddMiddleware(std::move(mw)); }

void HttpServer::SetSSEEndpoint(std::string_view path) { m_impl->SetSSEEndpoint(path); }
void HttpServer::BroadcastSSE(std::string_view eventType, std::string_view data) { m_impl->BroadcastSSE(eventType, data); }
size_t HttpServer::GetSSEClientCount() const noexcept { return m_impl->GetSSEClientCount(); }

HttpServerStats::Snapshot HttpServer::GetStats() const noexcept { return m_impl->GetStats(); }
void HttpServer::ResetStats() noexcept { m_impl->ResetStats(); }

} // namespace Http
} // namespace ShadowStrike
