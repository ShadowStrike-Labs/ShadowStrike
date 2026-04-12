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
 * ShadowStrike NGAV - EMBEDDED REST API SERVER
 * ============================================================================
 *
 * @file RESTServer.hpp
 * @brief Localhost-bound REST API server for the ShadowStrike web dashboard.
 *
 * Provides the HTTP API backend that the React SPA dashboard consumes.
 * Community edition runs on localhost; higher tiers use cloud endpoints.
 *
 * ARCHITECTURE:
 * =============
 *
 *   Browser (localhost:9443)
 *        │  HTTPS (self-signed TLS)
 *        ▼
 *   ┌──────────────────────────────────────────────────────────┐
 *   │                    REST API SERVER                        │ ◄── YOU ARE HERE
 *   │  (Custom IOCP HTTP server, PIMPL, rate limiter)          │
 *   └──────────────────┬───────────────────────────────────────┘
 *                      │  Calls internal C++ APIs directly
 *                      ▼
 *   ┌──────────────────────────────────────────────────────────┐
 *   │              PhantomCore Engine Modules                   │
 *   │  ScanEngine, RTP, QuarantineManager, ThreatIntel,        │
 *   │  ConfigManager, ProductTierManager, BehaviorAnalyzer...  │
 *   └──────────────────────────────────────────────────────────┘
 *
 * SECURITY MODEL:
 * ===============
 *
 * 1. LOCALHOST-ONLY BINDING
 *    - Binds exclusively to 127.0.0.1 (IPv4) or ::1 (IPv6)
 *    - Rejects any attempt to bind to 0.0.0.0 or external interfaces
 *    - Validated at startup with hard abort on misconfiguration
 *
 * 2. BEARER TOKEN AUTHENTICATION
 *    - Login returns a cryptographically random session token
 *    - All subsequent requests require Authorization: Bearer <token>
 *    - Tokens expire after configurable idle timeout (default: 30 min)
 *    - Constant-time token comparison to prevent timing attacks
 *
 * 3. CSRF PROTECTION
 *    - Double-submit cookie pattern: X-CSRF-Token header must match cookie
 *    - State-changing operations (POST/PUT/DELETE) require valid CSRF token
 *    - Token rotated on each login
 *
 * 4. RATE LIMITING
 *    - Per-IP sliding window rate limiter
 *    - Configurable burst/sustained limits
 *    - Authentication endpoints have stricter limits
 *    - Returns 429 Too Many Requests with Retry-After header
 *
 * 5. INPUT VALIDATION
 *    - Maximum request body size enforced (default: 1 MB)
 *    - JSON depth limit to prevent stack overflow
 *    - Content-Type validation on all POST/PUT requests
 *    - Path traversal prevention on all file-related endpoints
 *
 * 6. RESPONSE HARDENING
 *    - Strict security headers on every response:
 *      X-Content-Type-Options: nosniff
 *      X-Frame-Options: DENY
 *      Content-Security-Policy: default-src 'self'
 *      Cache-Control: no-store
 *      X-Request-Id for correlation
 *    - No server version disclosure
 *    - Structured JSON error responses (never raw exceptions)
 *
 * API ENDPOINTS:
 * ==============
 *
 * Authentication:
 *   POST /api/v1/auth/login           - Authenticate, get bearer token
 *   POST /api/v1/auth/logout          - Invalidate session
 *   GET  /api/v1/auth/session         - Current session info
 *
 * System:
 *   GET  /api/v1/status               - Engine status (RTP, modules, uptime)
 *   GET  /api/v1/stats                - Detection statistics
 *   GET  /api/v1/modules              - Module health/status list
 *   GET  /api/v1/license              - License/tier info
 *   GET  /api/v1/health               - Health check (no auth required)
 *
 * Scanning:
 *   POST /api/v1/scan/quick           - Start quick scan
 *   POST /api/v1/scan/full            - Start full scan
 *   POST /api/v1/scan/custom          - Start custom scan (paths in body)
 *   POST /api/v1/scan/stop            - Stop active scan
 *   GET  /api/v1/scan/progress        - Current scan progress
 *
 * Quarantine:
 *   GET  /api/v1/quarantine           - List quarantined items
 *   POST /api/v1/quarantine/restore   - Restore item
 *   POST /api/v1/quarantine/delete    - Permanently delete item
 *
 * Threat Intelligence:
 *   GET  /api/v1/threats              - Recent threat detections
 *   GET  /api/v1/threats/:id          - Threat detail
 *   GET  /api/v1/threatintel/feeds    - Feed status
 *
 * Configuration:
 *   GET  /api/v1/config               - Current configuration
 *   PUT  /api/v1/config               - Update configuration
 *
 * Events:
 *   GET  /api/v1/events/stream        - SSE (Server-Sent Events) stream
 *
 * @note Thread-safe. All public methods are safe to call from any thread.
 * @note Feature-gated via ProductTierManager (Dashboard feature category).
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. Licensed under AGPL-3.0-or-later.
 * ============================================================================
 */

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <memory>
#include <functional>
#include <vector>
#include <optional>
#include <chrono>
#include <atomic>

namespace ShadowStrike {
namespace API {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

class RESTServerImpl;

// ============================================================================
// CONSTANTS
// ============================================================================

/// Default listening port for the REST API server (HTTPS)
inline constexpr uint16_t DEFAULT_PORT = 9443;

/// Default bind address (localhost only — never change to 0.0.0.0)
inline constexpr const char* DEFAULT_BIND_ADDRESS = "127.0.0.1";

/// Maximum request body size (1 MB)
inline constexpr size_t MAX_REQUEST_BODY_SIZE = 1ULL * 1024 * 1024;

/// Maximum number of concurrent connections
inline constexpr size_t MAX_CONCURRENT_CONNECTIONS = 32;

/// Default session idle timeout (30 minutes)
inline constexpr uint32_t DEFAULT_SESSION_TIMEOUT_SECONDS = 1800;

/// Maximum active sessions
inline constexpr size_t MAX_ACTIVE_SESSIONS = 16;

/// Rate limit: requests per second (sustained)
inline constexpr uint32_t DEFAULT_RATE_LIMIT_PER_SECOND = 30;

/// Rate limit: burst allowance
inline constexpr uint32_t DEFAULT_RATE_LIMIT_BURST = 60;

/// Auth endpoint rate limit (stricter, per second)
inline constexpr uint32_t AUTH_RATE_LIMIT_PER_SECOND = 5;

/// Bearer token length in bytes (256-bit)
inline constexpr size_t TOKEN_BYTES = 32;

/// CSRF token length in bytes (128-bit)
inline constexpr size_t CSRF_TOKEN_BYTES = 16;

/// Maximum JSON parse depth for request bodies
inline constexpr size_t MAX_REQUEST_JSON_DEPTH = 32;

/// API version prefix
inline constexpr const char* API_PREFIX = "/api/v1";

/// Server name header value (no version disclosure)
inline constexpr const char* SERVER_IDENTITY = "ShadowStrike";

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief REST server operational state
 */
enum class ServerState : uint8_t {
    Stopped     = 0,    ///< Server is not running
    Starting    = 1,    ///< Server is initializing
    Running     = 2,    ///< Server is accepting requests
    Stopping    = 3,    ///< Server is shutting down gracefully
    Error       = 4     ///< Server encountered a fatal error
};

/**
 * @brief Authentication result for login attempts
 */
enum class AuthResult : uint8_t {
    Success             = 0,
    InvalidCredentials  = 1,
    RateLimited         = 2,
    AccountLocked       = 3,
    ServerError         = 4
};

/**
 * @brief Reason for request rejection
 */
enum class RejectReason : uint8_t {
    None                = 0,
    Unauthorized        = 1,    ///< Missing or invalid bearer token
    Forbidden           = 2,    ///< Valid token, insufficient permissions
    RateLimited         = 3,    ///< Too many requests
    InvalidCSRF         = 4,    ///< CSRF token mismatch
    BodyTooLarge        = 5,    ///< Request body exceeds limit
    InvalidContentType  = 6,    ///< Wrong Content-Type for endpoint
    InvalidJSON         = 7,    ///< Malformed JSON body
    FeatureDisabled     = 8,    ///< Feature not available in current tier
    InternalError       = 9     ///< Server-side failure
};

// ============================================================================
// CONFIGURATION
// ============================================================================

/**
 * @brief REST server configuration
 *
 * All security-critical defaults are deliberately restrictive.
 * Callers may relax constraints for development but MUST NOT
 * weaken them for deployment.
 */
struct RESTServerConfig {
    /// Bind address — MUST be "127.0.0.1" or "::1" in production
    std::string bindAddress = DEFAULT_BIND_ADDRESS;

    /// Listen port
    uint16_t port = DEFAULT_PORT;

    /// Enable TLS (recommended; requires cert/key paths)
    bool enableTLS = false;

    /// Path to PEM-encoded TLS certificate
    std::string tlsCertPath;

    /// Path to PEM-encoded TLS private key
    std::string tlsKeyPath;

    /// Maximum request body size in bytes
    size_t maxRequestBodySize = MAX_REQUEST_BODY_SIZE;

    /// Maximum concurrent connections
    size_t maxConnections = MAX_CONCURRENT_CONNECTIONS;

    /// Session idle timeout in seconds
    uint32_t sessionTimeoutSeconds = DEFAULT_SESSION_TIMEOUT_SECONDS;

    /// Maximum active sessions
    size_t maxSessions = MAX_ACTIVE_SESSIONS;

    /// Sustained rate limit (requests/second/IP)
    uint32_t rateLimitPerSecond = DEFAULT_RATE_LIMIT_PER_SECOND;

    /// Burst rate limit (requests in burst window)
    uint32_t rateLimitBurst = DEFAULT_RATE_LIMIT_BURST;

    /// Enable CORS headers (for browser SPA)
    bool enableCORS = true;

    /// Allowed CORS origins (empty = same-origin only)
    std::vector<std::string> corsOrigins;

    /// Path to static files directory (serves dashboard SPA)
    std::string staticFilesPath;

    /// Enable Server-Sent Events endpoint
    bool enableSSE = true;

    /// Thread pool size for the HTTP server (0 = auto-detect)
    size_t threadPoolSize = 0;

    /// Enable request logging
    bool enableRequestLogging = true;

    /// Enable authentication requirement (can be disabled for local dev)
    bool requireAuth = true;

    /// @brief Validate configuration for security and correctness
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// STATISTICS
// ============================================================================

/**
 * @brief Server runtime statistics (atomic, lock-free)
 */
struct RESTServerStatistics {
    std::atomic<uint64_t> totalRequests{0};
    std::atomic<uint64_t> successfulRequests{0};
    std::atomic<uint64_t> failedRequests{0};
    std::atomic<uint64_t> rejectedRequests{0};
    std::atomic<uint64_t> authFailures{0};
    std::atomic<uint64_t> rateLimitHits{0};
    std::atomic<uint64_t> activeSessions{0};
    std::atomic<uint64_t> bytesReceived{0};
    std::atomic<uint64_t> bytesSent{0};
    std::chrono::steady_clock::time_point startTime{};

    RESTServerStatistics() = default;

    // Atomic types are not copyable/movable — provide snapshot
    struct Snapshot {
        uint64_t totalRequests;
        uint64_t successfulRequests;
        uint64_t failedRequests;
        uint64_t rejectedRequests;
        uint64_t authFailures;
        uint64_t rateLimitHits;
        uint64_t activeSessions;
        uint64_t bytesReceived;
        uint64_t bytesSent;
        std::chrono::steady_clock::time_point startTime;
        std::chrono::milliseconds uptime;
    };

    [[nodiscard]] Snapshot TakeSnapshot() const noexcept;
    void Reset() noexcept;
};

// ============================================================================
// EVENT TYPES (for SSE)
// ============================================================================

/**
 * @brief Event type for Server-Sent Events stream
 */
enum class SSEEventType : uint8_t {
    ThreatDetected      = 0,
    ScanProgress        = 1,
    ScanComplete        = 2,
    ModuleStatusChange  = 3,
    QuarantineAction    = 4,
    SystemAlert         = 5,
    ConfigChange        = 6,
    UpdateAvailable     = 7
};

/**
 * @brief Callback invoked when a client connects to the SSE stream.
 * @param clientId  Unique identifier for the SSE client connection.
 */
using SSEClientCallback = std::function<void(uint64_t clientId)>;

/**
 * @brief Callback for custom route handlers.
 * @param requestBody  JSON request body (empty for GET)
 * @param responseBody Reference to fill with JSON response
 * @return HTTP status code
 */
using RouteHandler = std::function<int(std::string_view requestBody, std::string& responseBody)>;

// ============================================================================
// REST SERVER CLASS
// ============================================================================

/**
 * @class RESTServer
 * @brief Embedded REST API server for the ShadowStrike management dashboard.
 *
 * Meyers' Singleton. PIMPL for ABI stability. Thread-safe.
 *
 * The server provides a full RESTful API for the web dashboard to consume.
 * It bridges HTTP/JSON requests to internal C++ engine calls.
 *
 * Lifecycle:
 *   1. RESTServer::Instance()              — get singleton
 *   2. Initialize(config)                  — validate config, set up routes
 *   3. Start()                             — begin listening on background thread
 *   4. ... (server runs, handles requests) ...
 *   5. Stop()                              — graceful shutdown
 *   6. Shutdown()                          — release all resources
 *
 * @note The server validates that the Dashboard feature is enabled via
 *       ProductTierManager before accepting any requests beyond /health.
 */
class RESTServer final {
public:
    // ========================================================================
    // SINGLETON
    // ========================================================================

    [[nodiscard]] static RESTServer& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;

    RESTServer(const RESTServer&) = delete;
    RESTServer& operator=(const RESTServer&) = delete;
    RESTServer(RESTServer&&) = delete;
    RESTServer& operator=(RESTServer&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    /**
     * @brief Initialize the server with configuration.
     * @param config Server configuration (validated internally)
     * @return true if initialization succeeded
     */
    [[nodiscard]] bool Initialize(const RESTServerConfig& config = {});

    /**
     * @brief Start accepting connections on a background thread.
     * @return true if the server started successfully
     */
    [[nodiscard]] bool Start();

    /**
     * @brief Gracefully stop the server and drain active connections.
     *
     * Blocks until all in-flight requests complete or timeout expires.
     */
    void Stop();

    /**
     * @brief Full shutdown — release all resources.
     *
     * After Shutdown(), Initialize() must be called again before Start().
     */
    void Shutdown();

    /// @brief Is the server initialized?
    [[nodiscard]] bool IsInitialized() const noexcept;

    /// @brief Is the server currently accepting connections?
    [[nodiscard]] bool IsRunning() const noexcept;

    /// @brief Get current server state
    [[nodiscard]] ServerState GetState() const noexcept;

    /// @brief Get the port the server is actually listening on
    [[nodiscard]] uint16_t GetPort() const noexcept;

    /// @brief Get the bind address
    [[nodiscard]] std::string GetBindAddress() const noexcept;

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    /// @brief Update configuration (some changes require restart)
    [[nodiscard]] bool UpdateConfiguration(const RESTServerConfig& config);

    /// @brief Get current configuration
    [[nodiscard]] RESTServerConfig GetConfiguration() const;

    // ========================================================================
    // STATISTICS
    // ========================================================================

    /// @brief Get server statistics snapshot
    [[nodiscard]] RESTServerStatistics::Snapshot GetStatistics() const noexcept;

    /// @brief Reset statistics counters
    void ResetStatistics() noexcept;

    // ========================================================================
    // SERVER-SENT EVENTS
    // ========================================================================

    /**
     * @brief Push an event to all connected SSE clients.
     * @param type Event type
     * @param jsonData JSON-serialized event payload
     */
    void BroadcastEvent(SSEEventType type, std::string_view jsonData);

    /**
     * @brief Get the number of connected SSE clients.
     */
    [[nodiscard]] size_t GetSSEClientCount() const noexcept;

    // ========================================================================
    // EXTENSIBILITY
    // ========================================================================

    /**
     * @brief Register a custom GET route handler.
     * @param path Full URL path (e.g., "/api/v1/custom/myendpoint")
     * @param handler Callback invoked on matching request
     * @return true if route was registered
     *
     * @note Custom routes are still subject to auth and rate limiting.
     */
    [[nodiscard]] bool RegisterGetRoute(
        std::string_view path,
        RouteHandler handler);

    /**
     * @brief Register a custom POST route handler.
     */
    [[nodiscard]] bool RegisterPostRoute(
        std::string_view path,
        RouteHandler handler);

    // ========================================================================
    // SESSION MANAGEMENT
    // ========================================================================

    /// @brief Invalidate all active sessions (force re-login)
    void InvalidateAllSessions();

    /// @brief Get number of active sessions
    [[nodiscard]] size_t GetActiveSessionCount() const noexcept;

private:
    RESTServer();
    ~RESTServer();

    std::unique_ptr<RESTServerImpl> m_impl;

    static std::atomic<bool> s_instanceCreated;
};

} // namespace API
} // namespace ShadowStrike
