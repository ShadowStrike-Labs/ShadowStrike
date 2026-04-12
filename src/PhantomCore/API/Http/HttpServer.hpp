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
 * ShadowStrike NGAV - EMBEDDED HTTP SERVER
 * ============================================================================
 *
 * @file HttpServer.hpp
 * @brief Winsock2-based HTTP/1.1 server with IOCP, routing, and middleware.
 *
 * Zero external dependencies. Built directly on Winsock2 and Windows IOCP.
 *
 * DESIGN:
 * =======
 *
 * 1. ACCEPT THREAD
 *    - Dedicated thread calling accept() in a loop
 *    - Associates new sockets with IOCP
 *    - Enforces connection limits before accept
 *
 * 2. I/O COMPLETION PORT
 *    - N worker threads dequeue completions via GetQueuedCompletionStatus
 *    - Non-blocking recv/send overlapped I/O
 *    - Scales to thousands of concurrent connections efficiently
 *
 * 3. HTTP PARSER (Inline, Zero-Copy Where Possible)
 *    - Incremental: handles partial reads gracefully
 *    - Validates method, path, headers, Content-Length
 *    - Rejects malformed requests before dispatching to handlers
 *    - Size limits on every field to prevent memory exhaustion
 *
 * 4. ROUTER
 *    - Trie-based path matching with :param support
 *    - Method-specific handlers (GET, POST, PUT, DELETE)
 *    - Middleware chain executed before each handler
 *    - 404 and 405 auto-responses
 *
 * 5. KEEP-ALIVE
 *    - HTTP/1.1 keep-alive by default
 *    - Configurable idle timeout per connection
 *    - Connection: close respected
 *
 * 6. SECURITY
 *    - Localhost-only bind (hard-enforced)
 *    - Request size limits on all fields
 *    - Slowloris protection (incomplete request timeout)
 *    - No server version disclosure
 *
 * @note Thread-safe. All public methods are safe to call from any thread.
 * @note Meyers' Singleton available but not required — can be instantiated.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. Licensed under AGPL-3.0-or-later.
 * ============================================================================
 */

#pragma once

#include "HttpTypes.hpp"

#include <memory>
#include <atomic>
#include <chrono>
#include <string>
#include <string_view>
#include <vector>
#include <functional>

namespace ShadowStrike {
namespace Http {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

class HttpServerImpl;

// ============================================================================
// CONSTANTS
// ============================================================================

/// Default port (HTTPS-like, but plain HTTP on localhost)
inline constexpr uint16_t DEFAULT_HTTP_PORT = 9443;

/// Default bind address (LOCALHOST ONLY — never 0.0.0.0)
inline constexpr const char* DEFAULT_HTTP_BIND = "127.0.0.1";

/// Default worker thread count (0 = hardware_concurrency)
inline constexpr size_t DEFAULT_WORKER_THREADS = 0;

/// Default maximum concurrent connections
inline constexpr size_t DEFAULT_MAX_CONNECTIONS = 64;

/// Default keep-alive timeout (30 seconds)
inline constexpr uint32_t DEFAULT_KEEPALIVE_TIMEOUT_SEC = 30;

/// Default incomplete request timeout (10 seconds — Slowloris protection)
inline constexpr uint32_t DEFAULT_INCOMPLETE_REQUEST_TIMEOUT_SEC = 10;

/// Maximum keep-alive requests per connection
inline constexpr uint32_t DEFAULT_MAX_KEEPALIVE_REQUESTS = 100;

// ============================================================================
// SERVER CONFIGURATION
// ============================================================================

/**
 * @brief HTTP server configuration.
 *
 * Secure by default. Every limit exists to prevent resource exhaustion.
 */
struct HttpServerConfig {
    /// Bind address — MUST be "127.0.0.1" or "::1"
    std::string bindAddress = DEFAULT_HTTP_BIND;

    /// Listen port
    uint16_t port = DEFAULT_HTTP_PORT;

    /// Number of IOCP worker threads (0 = auto-detect)
    size_t workerThreads = DEFAULT_WORKER_THREADS;

    /// Maximum concurrent connections
    size_t maxConnections = DEFAULT_MAX_CONNECTIONS;

    /// Maximum request body size in bytes
    size_t maxBodySize = DEFAULT_MAX_BODY_SIZE;

    /// Maximum single header line length
    size_t maxHeaderLineSize = MAX_HEADER_LINE_LENGTH;

    /// Maximum total headers size
    size_t maxHeadersTotalSize = MAX_HEADERS_TOTAL_SIZE;

    /// Maximum number of headers per request
    size_t maxHeaderCount = MAX_HEADER_COUNT;

    /// Maximum URL length
    size_t maxUrlLength = MAX_URL_LENGTH;

    /// Keep-alive idle timeout (seconds)
    uint32_t keepAliveTimeoutSec = DEFAULT_KEEPALIVE_TIMEOUT_SEC;

    /// Incomplete request timeout — Slowloris protection (seconds)
    uint32_t incompleteRequestTimeoutSec = DEFAULT_INCOMPLETE_REQUEST_TIMEOUT_SEC;

    /// Maximum keep-alive requests per connection
    uint32_t maxKeepAliveRequests = DEFAULT_MAX_KEEPALIVE_REQUESTS;

    /// Server identity string (for Server header; empty = no header)
    std::string serverIdentity = "ShadowStrike";

    /// Enable request logging via SS_LOG_*
    bool enableRequestLogging = true;

    /// Enable keep-alive
    bool enableKeepAlive = true;

    /// Validate the configuration for security and correctness
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// SERVER STATE
// ============================================================================

/**
 * @brief HTTP server operational state
 */
enum class ServerState : uint8_t {
    Stopped     = 0,
    Starting    = 1,
    Running     = 2,
    Stopping    = 3,
    Error       = 4
};

// ============================================================================
// SERVER STATISTICS
// ============================================================================

/**
 * @brief Atomic server statistics
 */
struct HttpServerStats {
    std::atomic<uint64_t> totalRequests{0};
    std::atomic<uint64_t> totalResponses{0};
    std::atomic<uint64_t> activeConnections{0};
    std::atomic<uint64_t> totalConnections{0};
    std::atomic<uint64_t> rejectedConnections{0};
    std::atomic<uint64_t> parseErrors{0};
    std::atomic<uint64_t> timeouts{0};
    std::atomic<uint64_t> bytesReceived{0};
    std::atomic<uint64_t> bytesSent{0};
    std::chrono::steady_clock::time_point startTime{};

    struct Snapshot {
        uint64_t totalRequests;
        uint64_t totalResponses;
        uint64_t activeConnections;
        uint64_t totalConnections;
        uint64_t rejectedConnections;
        uint64_t parseErrors;
        uint64_t timeouts;
        uint64_t bytesReceived;
        uint64_t bytesSent;
        std::chrono::milliseconds uptime;
    };

    [[nodiscard]] Snapshot TakeSnapshot() const noexcept;
    void Reset() noexcept;
};

// ============================================================================
// HTTP SERVER CLASS
// ============================================================================

/**
 * @class HttpServer
 * @brief Winsock2/IOCP-based HTTP/1.1 server.
 *
 * PIMPL for ABI stability. Thread-safe.
 *
 * Usage:
 * @code
 *   HttpServer server;
 *   HttpServerConfig config;
 *   config.port = 9443;
 *   server.Initialize(config);
 *
 *   server.Get("/api/v1/health", [](const HttpRequest& req, HttpResponse& res) {
 *       res.SetJsonBody(R"({"status":"ok"})");
 *   });
 *
 *   server.Use([](const HttpRequest& req, HttpResponse& res) -> bool {
 *       res.SetHeader("X-Request-Id", GenerateRequestId());
 *       return true;  // continue to handler
 *   });
 *
 *   server.Start();   // non-blocking, runs on background threads
 *   // ... later ...
 *   server.Stop();
 * @endcode
 */
class HttpServer final {
public:
    HttpServer();
    ~HttpServer();

    HttpServer(const HttpServer&) = delete;
    HttpServer& operator=(const HttpServer&) = delete;
    HttpServer(HttpServer&&) noexcept;
    HttpServer& operator=(HttpServer&&) noexcept;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    /**
     * @brief Initialize with configuration.
     *
     * Validates config, creates IOCP, initializes Winsock.
     * Does NOT start listening — call Start() for that.
     *
     * @param config Server configuration
     * @return true on success
     */
    [[nodiscard]] bool Initialize(const HttpServerConfig& config = {});

    /**
     * @brief Start accepting connections.
     *
     * Creates the listening socket, binds, and spawns worker threads.
     * Returns immediately; server runs on background threads.
     *
     * @return true if server started successfully
     */
    [[nodiscard]] bool Start();

    /**
     * @brief Gracefully stop the server.
     *
     * Stops accepting new connections, drains in-flight requests,
     * then closes all sockets and joins all threads.
     */
    void Stop();

    /**
     * @brief Full shutdown and resource release.
     *
     * After Shutdown(), Initialize() must be called again before Start().
     */
    void Shutdown();

    /// @brief Is the server initialized?
    [[nodiscard]] bool IsInitialized() const noexcept;

    /// @brief Is the server running?
    [[nodiscard]] bool IsRunning() const noexcept;

    /// @brief Current server state
    [[nodiscard]] ServerState GetState() const noexcept;

    /// @brief Actual listening port
    [[nodiscard]] uint16_t GetPort() const noexcept;

    // ========================================================================
    // ROUTING
    // ========================================================================

    /**
     * @brief Register a GET route handler.
     *
     * @param pattern URL pattern, e.g. "/api/v1/threats/:id"
     *                Supports :param for path parameters.
     * @param handler Request handler
     */
    void Get(std::string_view pattern, RequestHandler handler);

    /// @brief Register a POST route handler
    void Post(std::string_view pattern, RequestHandler handler);

    /// @brief Register a PUT route handler
    void Put(std::string_view pattern, RequestHandler handler);

    /// @brief Register a DELETE route handler
    void Delete(std::string_view pattern, RequestHandler handler);

    /// @brief Register a PATCH route handler
    void Patch(std::string_view pattern, RequestHandler handler);

    /// @brief Register a handler for any method
    void Route(HttpMethod method, std::string_view pattern, RequestHandler handler);

    // ========================================================================
    // MIDDLEWARE
    // ========================================================================

    /**
     * @brief Add a middleware to the chain.
     *
     * Middlewares are executed in registration order before the route handler.
     * Return false from middleware to stop the chain (response already set).
     */
    void Use(Middleware middleware);

    // ========================================================================
    // SERVER-SENT EVENTS
    // ========================================================================

    /**
     * @brief Register the SSE endpoint path.
     *
     * When a client connects to this path, the server holds the connection
     * open and streams events via BroadcastSSE().
     *
     * @param path The SSE endpoint path (e.g., "/api/v1/events/stream")
     */
    void SetSSEEndpoint(std::string_view path);

    /**
     * @brief Broadcast an SSE event to all connected clients.
     *
     * @param eventType The event type (sent as "event:" field)
     * @param data JSON data (sent as "data:" field)
     */
    void BroadcastSSE(std::string_view eventType, std::string_view data);

    /// @brief Get count of connected SSE clients
    [[nodiscard]] size_t GetSSEClientCount() const noexcept;

    // ========================================================================
    // STATISTICS
    // ========================================================================

    /// @brief Get statistics snapshot
    [[nodiscard]] HttpServerStats::Snapshot GetStats() const noexcept;

    /// @brief Reset statistics
    void ResetStats() noexcept;

private:
    std::unique_ptr<HttpServerImpl> m_impl;
};

} // namespace Http
} // namespace ShadowStrike
