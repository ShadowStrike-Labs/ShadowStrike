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
#include "PhantomCore/API/RESTServer.hpp"
#include "PhantomCore/API/Http/HttpServer.hpp"
#include "PhantomCore/API/Http/HttpTypes.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/CryptoUtils.hpp"
#include "PhantomCore/Utils/HashUtils.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"
#include "PhantomCore/Utils/Base64Utils.hpp"
#include "PhantomCore/Config/ConfigManager.hpp"
#include "PhantomCore/Config/ProductTier.hpp"
#include "PhantomCore/Core/Engine/ScanEngine.hpp"
#include "PhantomCore/Core/Engine/QuarantineManager.hpp"
#include "PhantomCore/Core/Engine/ThreatDetector.hpp"
#include "PhantomCore/RealTime/RealTimeProtection.hpp"
#include "PhantomCore/Communication/AlertSystem.hpp"
#include "PhantomCore/ThreatIntel/ThreatIntelFeedManager.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cassert>
#include <charconv>
#include <chrono>
#include <deque>
#include <mutex>
#include <shared_mutex>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace ShadowStrike {
namespace API {

// ============================================================================
// LOGGING CATEGORY
// ============================================================================

static constexpr const wchar_t* LOG_CAT = L"API.REST";

// ============================================================================
// INTERNAL HELPERS (file-local)
// ============================================================================

namespace {

// PBKDF2-based password hash storage format identifier.
// Format: "pbkdf2$<iterations>$<hex_salt>$<hex_key>"
//   - iterations: decimal ASCII (uint32, lower-bounded by MIN_PBKDF2_ITERATIONS)
//   - hex_salt:   lowercase hex, exactly PBKDF2_SALT_BYTES * 2 chars
//   - hex_key:    lowercase hex, exactly PBKDF2_KEY_BYTES  * 2 chars
constexpr std::string_view PBKDF2_PREFIX = "pbkdf2$";
constexpr size_t           PBKDF2_SALT_BYTES = 32;
constexpr size_t           PBKDF2_KEY_BYTES  = 32;

// Strict size_t parser used for query parameters.
// Returns parsed value clamped to [0, max], or std::nullopt on malformed input.
// Unlike std::stoul / std::stoi this never throws.
[[nodiscard]] std::optional<size_t> ParseSizeTClamped(std::string_view sv,
                                                      size_t maxAllowed) noexcept {
    if (sv.empty()) return std::nullopt;
    size_t value = 0;
    const char* first = sv.data();
    const char* last  = sv.data() + sv.size();
    auto [ptr, ec] = std::from_chars(first, last, value, 10);
    if (ec != std::errc{} || ptr != last) {
        return std::nullopt;
    }
    return std::min(value, maxAllowed);
}

// Decompose a Web Origin (scheme://host[:port]) and extract the host portion.
// Returns empty if the origin is malformed.
[[nodiscard]] std::string_view ExtractOriginHost(std::string_view origin) noexcept {
    const auto schemeSep = origin.find("://");
    if (schemeSep == std::string_view::npos) return {};
    auto rest = origin.substr(schemeSep + 3);
    // Strip path (anything after the next '/')
    const auto pathStart = rest.find('/');
    if (pathStart != std::string_view::npos) rest = rest.substr(0, pathStart);
    // Strip port (anything after the last ':' that isn't inside [..] IPv6 literal)
    if (!rest.empty() && rest.front() == '[') {
        const auto bracket = rest.find(']');
        if (bracket == std::string_view::npos) return {};
        // Keep "[host]" including brackets — host comparison expects this form.
        return rest.substr(0, bracket + 1);
    }
    const auto portSep = rest.rfind(':');
    if (portSep != std::string_view::npos) rest = rest.substr(0, portSep);
    return rest;
}

// Whether an Origin header value is one of the on-host loopback addresses
// (used only when the operator did not configure an explicit allow-list).
[[nodiscard]] bool IsLoopbackOrigin(std::string_view origin) noexcept {
    const auto host = ExtractOriginHost(origin);
    if (host.empty()) return false;
    return host == "127.0.0.1" || host == "[::1]" || host == "localhost";
}

// Lossless UTF-16 -> UTF-8 conversion for JSON serialization.
// Falls back to '?' substitution if the conversion fails so we never feed
// invalid UTF-8 into nlohmann::json::dump (which throws on bad encoding).
[[nodiscard]] std::string WideToJsonUtf8(std::wstring_view wide) noexcept {
    if (wide.empty()) return {};
    auto narrow = Utils::StringUtils::ToNarrow(wide);
    if (narrow.empty()) {
        // Conversion lost everything; emit a placeholder rather than empty
        // so consumers can detect that a non-empty wide value was unmappable.
        return std::string(wide.size(), '?');
    }
    return narrow;
}

// Encode raw bytes as lowercase hex (used for password hash storage).
[[nodiscard]] std::string BytesToHex(std::span<const uint8_t> bytes) noexcept {
    return Utils::HashUtils::ToHexLower(
        std::vector<uint8_t>(bytes.begin(), bytes.end()));
}

} // anonymous namespace

// ============================================================================
// SESSION STRUCTURE
// ============================================================================

struct Session {
    std::string token;                  // 256-bit bearer token (hex-encoded)
    std::string csrfToken;              // 128-bit CSRF token (hex-encoded)
    std::chrono::steady_clock::time_point createdAt;
    std::chrono::steady_clock::time_point lastActivity;
    std::string sourceAddress;          // peer IP that created the session
    uint64_t requestCount = 0;
};

// ============================================================================
// RATE LIMITER — SLIDING WINDOW PER-IP
// ============================================================================

class RateLimiter final {
public:
    explicit RateLimiter(uint32_t maxPerSecond, uint32_t burstMax) noexcept
        : m_maxPerSecond(maxPerSecond), m_burstMax(burstMax) {}

    [[nodiscard]] bool Allow(const std::string& ip) noexcept {
        const auto now = std::chrono::steady_clock::now();
        std::lock_guard lock(m_mutex);

        auto& bucket = m_buckets[ip];
        PruneExpired(bucket, now);

        if (bucket.timestamps.size() >= m_burstMax) {
            return false;
        }

        bucket.timestamps.push_back(now);
        return true;
    }

    [[nodiscard]] uint32_t GetRetryAfterMs(const std::string& ip) const noexcept {
        const auto now = std::chrono::steady_clock::now();
        std::lock_guard lock(m_mutex);

        auto it = m_buckets.find(ip);
        if (it == m_buckets.end() || it->second.timestamps.empty()) {
            return 0;
        }

        const auto& ts = it->second.timestamps;
        if (ts.size() < m_burstMax) {
            return 0;
        }

        const auto oldest = ts.front();
        const auto windowEnd = oldest + std::chrono::seconds(1);
        if (now >= windowEnd) {
            return 0;
        }

        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(windowEnd - now);
        return static_cast<uint32_t>(remaining.count());
    }

    void Reset() noexcept {
        std::lock_guard lock(m_mutex);
        m_buckets.clear();
    }

private:
    struct Bucket {
        std::deque<std::chrono::steady_clock::time_point> timestamps;
    };

    void PruneExpired(Bucket& bucket,
                      std::chrono::steady_clock::time_point now) const noexcept {
        const auto cutoff = now - std::chrono::seconds(1);
        while (!bucket.timestamps.empty() && bucket.timestamps.front() < cutoff) {
            bucket.timestamps.pop_front();
        }
    }

    uint32_t m_maxPerSecond;
    uint32_t m_burstMax;
    mutable std::mutex m_mutex;
    std::unordered_map<std::string, Bucket> m_buckets;
};

// ============================================================================
// REST SERVER IMPLEMENTATION (PIMPL)
// ============================================================================

class RESTServerImpl final {
public:
    RESTServerImpl() = default;
    ~RESTServerImpl() { Shutdown(); }

    RESTServerImpl(const RESTServerImpl&) = delete;
    RESTServerImpl& operator=(const RESTServerImpl&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(const RESTServerConfig& config) {
        if (m_state.load(std::memory_order_acquire) != ServerState::Stopped) {
            SS_LOG_ERROR(LOG_CAT, L"Cannot initialize: server not in Stopped state");
            return false;
        }

        if (!config.IsValid()) {
            SS_LOG_ERROR(LOG_CAT, L"REST server configuration validation failed");
            return false;
        }

        m_config = config;

        // Initialize rate limiters
        m_generalLimiter = std::make_unique<RateLimiter>(
            config.rateLimitPerSecond, config.rateLimitBurst);
        m_authLimiter = std::make_unique<RateLimiter>(
            AUTH_RATE_LIMIT_PER_SECOND, AUTH_RATE_LIMIT_PER_SECOND * 2);

        // Configure underlying HTTP server
        Http::HttpServerConfig httpConfig;
        httpConfig.bindAddress  = config.bindAddress;
        httpConfig.port         = config.port;
        httpConfig.workerThreads = config.threadPoolSize;
        httpConfig.maxConnections = config.maxConnections;
        httpConfig.maxBodySize  = config.maxRequestBodySize;
        httpConfig.enableRequestLogging = config.enableRequestLogging;
        httpConfig.serverIdentity = SERVER_IDENTITY;

        m_httpServer = std::make_unique<Http::HttpServer>();
        if (!m_httpServer->Initialize(httpConfig)) {
            SS_LOG_ERROR(LOG_CAT, L"Failed to initialize underlying HTTP server");
            m_httpServer.reset();
            return false;
        }

        RegisterMiddleware();
        RegisterRoutes();

        if (config.enableSSE) {
            m_httpServer->SetSSEEndpoint("/api/v1/events/stream");
        }

        m_stats.Reset();
        m_stats.startTime = std::chrono::steady_clock::now();

        SS_LOG_INFO(LOG_CAT, L"REST server initialized on %hs:%u",
                    config.bindAddress.c_str(), config.port);

        m_initialized = true;
        return true;
    }

    [[nodiscard]] bool Start() {
        if (!m_initialized) {
            SS_LOG_ERROR(LOG_CAT, L"Cannot start: server not initialized");
            return false;
        }

        // Feature gate: Dashboard must be enabled
        if (Config::ProductTierManager::HasInstance() &&
            Config::ProductTierManager::Instance().IsInitialized()) {
            if (!Config::ProductTierManager::Instance().IsFeatureEnabled(
                    Config::FeatureCategory::Dashboard)) {
                SS_LOG_WARN(LOG_CAT, L"Dashboard feature is disabled for current tier — "
                            L"REST server will not start");
                return false;
            }
        }

        // Also check RTP state for informational logging
        auto& rtp = RealTime::RealTimeProtection::Instance();
        if (!rtp.IsActive()) {
            SS_LOG_INFO(LOG_CAT, L"Note: RTP is not active — REST server starting anyway");
        }

        m_state.store(ServerState::Starting, std::memory_order_release);

        if (!m_httpServer->Start()) {
            SS_LOG_ERROR(LOG_CAT, L"Failed to start HTTP server");
            m_state.store(ServerState::Error, std::memory_order_release);
            return false;
        }

        m_state.store(ServerState::Running, std::memory_order_release);
        SS_LOG_INFO(LOG_CAT, L"REST server started — listening on %hs:%u",
                    m_config.bindAddress.c_str(), m_config.port);
        return true;
    }

    void Stop() {
        const auto current = m_state.load(std::memory_order_acquire);
        if (current != ServerState::Running && current != ServerState::Starting) {
            return;
        }

        m_state.store(ServerState::Stopping, std::memory_order_release);
        SS_LOG_INFO(LOG_CAT, L"Stopping REST server...");

        if (m_httpServer) {
            m_httpServer->Stop();
        }

        m_state.store(ServerState::Stopped, std::memory_order_release);
        SS_LOG_INFO(LOG_CAT, L"REST server stopped");
    }

    void Shutdown() {
        Stop();

        {
            std::unique_lock lock(m_httpServerMutex);
            if (m_httpServer) {
                m_httpServer->Shutdown();
                m_httpServer.reset();
            }
        }

        {
            std::unique_lock lock(m_sessionMutex);
            m_sessions.clear();
        }

        m_generalLimiter.reset();
        m_authLimiter.reset();
        m_initialized = false;

        SS_LOG_INFO(LOG_CAT, L"REST server shut down — all resources released");
    }

    // ========================================================================
    // STATE QUERIES
    // ========================================================================

    [[nodiscard]] bool IsInitialized() const noexcept { return m_initialized; }
    [[nodiscard]] bool IsRunning() const noexcept {
        return m_state.load(std::memory_order_acquire) == ServerState::Running;
    }
    [[nodiscard]] ServerState GetState() const noexcept {
        return m_state.load(std::memory_order_acquire);
    }
    [[nodiscard]] uint16_t GetPort() const noexcept {
        std::shared_lock lock(m_httpServerMutex);
        return m_httpServer ? m_httpServer->GetPort() : 0;
    }
    [[nodiscard]] std::string GetBindAddress() const noexcept {
        std::shared_lock lock(m_configMutex);
        return m_config.bindAddress;
    }

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    [[nodiscard]] bool UpdateConfiguration(const RESTServerConfig& config) {
        if (!config.IsValid()) {
            return false;
        }

        std::unique_lock lock(m_configMutex);
        m_config = config;

        if (m_generalLimiter) {
            m_generalLimiter = std::make_unique<RateLimiter>(
                config.rateLimitPerSecond, config.rateLimitBurst);
        }

        SS_LOG_INFO(LOG_CAT, L"REST server configuration updated");
        return true;
    }

    [[nodiscard]] RESTServerConfig GetConfiguration() const {
        std::shared_lock lock(m_configMutex);
        return m_config;
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] RESTServerStatistics::Snapshot GetStatistics() const noexcept {
        return m_stats.TakeSnapshot();
    }

    void ResetStatistics() noexcept {
        m_stats.Reset();
    }

    // ========================================================================
    // SSE
    // ========================================================================

    void BroadcastEvent(SSEEventType type, std::string_view jsonData) {
        std::shared_lock lock(m_httpServerMutex);
        if (!m_httpServer || !IsRunning()) return;

        static constexpr const char* EVENT_NAMES[] = {
            "threat_detected", "scan_progress", "scan_complete",
            "module_status", "quarantine_action", "system_alert",
            "config_change", "update_available"
        };

        const auto idx = static_cast<size_t>(type);
        const char* eventName = (idx < std::size(EVENT_NAMES))
            ? EVENT_NAMES[idx] : "unknown";

        m_httpServer->BroadcastSSE(eventName, jsonData);
    }

    [[nodiscard]] size_t GetSSEClientCount() const noexcept {
        std::shared_lock lock(m_httpServerMutex);
        return m_httpServer ? m_httpServer->GetSSEClientCount() : 0;
    }

    // ========================================================================
    // CUSTOM ROUTES
    // ========================================================================

    [[nodiscard]] bool RegisterGetRoute(std::string_view path, RouteHandler handler) {
        std::shared_lock lock(m_httpServerMutex);
        if (!m_httpServer) return false;

        auto wrappedHandler = [h = std::move(handler)](
            const Http::HttpRequest& req, Http::HttpResponse& res) {
            std::string responseBody;
            const int status = h(req.GetBodyString(), responseBody);
            res.status = static_cast<Http::HttpStatus>(status);
            res.SetJsonBody(responseBody);
        };

        m_httpServer->Get(path, std::move(wrappedHandler));
        return true;
    }

    [[nodiscard]] bool RegisterPostRoute(std::string_view path, RouteHandler handler) {
        std::shared_lock lock(m_httpServerMutex);
        if (!m_httpServer) return false;

        auto wrappedHandler = [h = std::move(handler)](
            const Http::HttpRequest& req, Http::HttpResponse& res) {
            std::string responseBody;
            const int status = h(req.GetBodyString(), responseBody);
            res.status = static_cast<Http::HttpStatus>(status);
            res.SetJsonBody(responseBody);
        };

        m_httpServer->Post(path, std::move(wrappedHandler));
        return true;
    }

    // ========================================================================
    // SESSION MANAGEMENT
    // ========================================================================

    void InvalidateAllSessions() {
        std::unique_lock lock(m_sessionMutex);
        const auto count = m_sessions.size();
        m_sessions.clear();
        m_stats.activeSessions.store(0, std::memory_order_release);
        SS_LOG_INFO(LOG_CAT, L"Invalidated %zu active sessions", count);
    }

    [[nodiscard]] size_t GetActiveSessionCount() const noexcept {
        std::shared_lock lock(m_sessionMutex);
        return m_sessions.size();
    }

private:
    // ========================================================================
    // MIDDLEWARE REGISTRATION
    // ========================================================================

    void RegisterMiddleware() {
        // 1. Request ID + security headers
        m_httpServer->Use([this](const Http::HttpRequest& req, Http::HttpResponse& res) -> bool {
            // Generate unique request ID
            const auto reqId = GenerateRequestId();
            res.SetHeader("X-Request-Id", reqId);

            // Security headers
            res.SetHeader("X-Content-Type-Options", "nosniff");
            res.SetHeader("X-Frame-Options", "DENY");
            res.SetHeader("X-XSS-Protection", "0"); // modern CSP supersedes
            res.SetHeader("Content-Security-Policy", "default-src 'self'");
            res.SetHeader("Cache-Control", "no-store, no-cache, must-revalidate");
            res.SetHeader("Pragma", "no-cache");
            res.SetHeader("Referrer-Policy", "no-referrer");
            res.SetHeader("Permissions-Policy",
                          "camera=(), microphone=(), geolocation=()");

            m_stats.totalRequests.fetch_add(1, std::memory_order_relaxed);
            m_stats.bytesReceived.fetch_add(
                req.body.size(), std::memory_order_relaxed);
            return true;
        });

        // 2. CORS handling
        m_httpServer->Use([this](const Http::HttpRequest& req, Http::HttpResponse& res) -> bool {
            if (!m_config.enableCORS) return true;

            const auto origin = req.GetHeader("Origin");
            if (!origin.has_value()) return true;

            const std::string originStr(origin.value());

            // Cap origin length to prevent log/header amplification
            if (originStr.size() > 256) {
                return true; // ignore obviously bogus origins
            }

            bool allowed = false;
            bool wildcardMatch = false;

            if (m_config.corsOrigins.empty()) {
                // Same-origin only: allow loopback hosts (exact host parse —
                // never substring match, which would let
                // "http://localhost.attacker.example" through).
                allowed = IsLoopbackOrigin(originStr);
            } else {
                for (const auto& ao : m_config.corsOrigins) {
                    if (ao == "*") {
                        wildcardMatch = true;
                        allowed = true;
                        break;
                    }
                    if (ao == originStr) {
                        allowed = true;
                        break;
                    }
                }
            }

            if (allowed) {
                if (wildcardMatch) {
                    // CORS spec: when ACAO is "*", credentials are NOT permitted
                    // and the origin MUST NOT be reflected (would otherwise become
                    // a credentialed cross-origin escape).
                    res.SetHeader("Access-Control-Allow-Origin", "*");
                    res.SetHeader("Access-Control-Allow-Methods",
                                  "GET, POST, PUT, DELETE, PATCH, OPTIONS");
                    res.SetHeader("Access-Control-Allow-Headers",
                                  "Content-Type, X-Request-Id");
                    res.SetHeader("Access-Control-Max-Age", "3600");
                } else {
                    // Specific origin allow-list match — credentials permitted.
                    res.SetHeader("Access-Control-Allow-Origin", originStr);
                    res.SetHeader("Vary", "Origin");
                    res.SetHeader("Access-Control-Allow-Methods",
                                  "GET, POST, PUT, DELETE, PATCH, OPTIONS");
                    res.SetHeader("Access-Control-Allow-Headers",
                                  "Content-Type, Authorization, X-CSRF-Token, X-Request-Id");
                    res.SetHeader("Access-Control-Allow-Credentials", "true");
                    res.SetHeader("Access-Control-Max-Age", "3600");
                }
            }

            // Handle preflight
            if (req.method == Http::HttpMethod::OPTIONS) {
                res.status = Http::HttpStatus::NoContent;
                return false; // short-circuit — preflight answered
            }

            return true;
        });

        // 3. Rate limiting
        m_httpServer->Use([this](const Http::HttpRequest& req, Http::HttpResponse& res) -> bool {
            const bool isAuthEndpoint = (req.path.find("/auth/") != std::string::npos);
            auto& limiter = isAuthEndpoint ? *m_authLimiter : *m_generalLimiter;

            if (!limiter.Allow(req.remoteAddress)) {
                m_stats.rateLimitHits.fetch_add(1, std::memory_order_relaxed);
                m_stats.rejectedRequests.fetch_add(1, std::memory_order_relaxed);

                const auto retryMs = limiter.GetRetryAfterMs(req.remoteAddress);
                const auto retrySec = (retryMs + 999) / 1000; // round up

                res = Http::HttpResponse::MakeError(
                    Http::HttpStatus::TooManyRequests,
                    "Rate limit exceeded",
                    res.headers.count("X-Request-Id")
                        ? res.headers.at("X-Request-Id") : "");
                res.SetHeader("Retry-After", std::to_string(retrySec));
                return false;
            }
            return true;
        });

        // 4. Authentication (skipped for health + auth endpoints)
        m_httpServer->Use([this](const Http::HttpRequest& req, Http::HttpResponse& res) -> bool {
            if (!m_config.requireAuth) return true;

            // Endpoints that don't require auth
            if (req.path == "/api/v1/health" ||
                req.path == "/api/v1/auth/login" ||
                req.path == "/favicon.ico") {
                return true;
            }

            // Extract Bearer token
            const auto authHeader = req.GetHeader("Authorization");
            if (!authHeader.has_value()) {
                m_stats.authFailures.fetch_add(1, std::memory_order_relaxed);
                m_stats.rejectedRequests.fetch_add(1, std::memory_order_relaxed);
                res = Http::HttpResponse::MakeError(
                    Http::HttpStatus::Unauthorized,
                    "Missing Authorization header");
                res.SetHeader("WWW-Authenticate", "Bearer");
                return false;
            }

            const std::string_view authVal = authHeader.value();
            constexpr std::string_view BEARER_PREFIX = "Bearer ";
            if (authVal.size() <= BEARER_PREFIX.size() ||
                authVal.substr(0, BEARER_PREFIX.size()) != BEARER_PREFIX) {
                m_stats.authFailures.fetch_add(1, std::memory_order_relaxed);
                m_stats.rejectedRequests.fetch_add(1, std::memory_order_relaxed);
                res = Http::HttpResponse::MakeError(
                    Http::HttpStatus::Unauthorized,
                    "Invalid Authorization scheme — use Bearer");
                return false;
            }

            const std::string token(authVal.substr(BEARER_PREFIX.size()));

            if (!ValidateSession(token)) {
                m_stats.authFailures.fetch_add(1, std::memory_order_relaxed);
                m_stats.rejectedRequests.fetch_add(1, std::memory_order_relaxed);
                res = Http::HttpResponse::MakeError(
                    Http::HttpStatus::Unauthorized,
                    "Invalid or expired session token");
                return false;
            }

            // Touch session activity
            TouchSession(token);
            return true;
        });

        // 5. CSRF validation for state-changing methods
        m_httpServer->Use([this](const Http::HttpRequest& req, Http::HttpResponse& res) -> bool {
            if (!m_config.requireAuth) return true;

            // Only enforce CSRF on state-changing methods
            if (req.method == Http::HttpMethod::GET ||
                req.method == Http::HttpMethod::HEAD ||
                req.method == Http::HttpMethod::OPTIONS) {
                return true;
            }

            // Login is exempt
            if (req.path == "/api/v1/auth/login") return true;

            const auto csrfHeader = req.GetHeader("X-CSRF-Token");
            if (!csrfHeader.has_value()) {
                m_stats.rejectedRequests.fetch_add(1, std::memory_order_relaxed);
                res = Http::HttpResponse::MakeError(
                    Http::HttpStatus::Forbidden,
                    "Missing X-CSRF-Token header");
                return false;
            }

            // Get session token from Authorization header to look up CSRF.
            // Auth middleware already validated this header on protected routes;
            // we re-check here defensively because middleware ordering changes
            // would otherwise silently bypass CSRF enforcement.
            const auto authHeader = req.GetHeader("Authorization");
            if (!authHeader.has_value()) {
                m_stats.rejectedRequests.fetch_add(1, std::memory_order_relaxed);
                res = Http::HttpResponse::MakeError(
                    Http::HttpStatus::Forbidden,
                    "CSRF check requires an authenticated session");
                return false;
            }

            const std::string_view authVal = authHeader.value();
            constexpr std::string_view BEARER_PREFIX = "Bearer ";
            if (authVal.size() <= BEARER_PREFIX.size() ||
                authVal.substr(0, BEARER_PREFIX.size()) != BEARER_PREFIX) {
                m_stats.rejectedRequests.fetch_add(1, std::memory_order_relaxed);
                res = Http::HttpResponse::MakeError(
                    Http::HttpStatus::Forbidden,
                    "CSRF check requires a Bearer authorization header");
                return false;
            }

            const std::string sessionToken(authVal.substr(BEARER_PREFIX.size()));
            const std::string expectedCsrf = GetSessionCsrfToken(sessionToken);

            if (expectedCsrf.empty() ||
                !ConstantTimeCompare(std::string(csrfHeader.value()), expectedCsrf)) {
                m_stats.rejectedRequests.fetch_add(1, std::memory_order_relaxed);
                res = Http::HttpResponse::MakeError(
                    Http::HttpStatus::Forbidden,
                    "Invalid CSRF token");
                return false;
            }

            return true;
        });
    }

    // ========================================================================
    // ROUTE REGISTRATION
    // ========================================================================

    void RegisterRoutes() {
        // -- Health (no auth) --
        m_httpServer->Get("/api/v1/health", [this](
            const Http::HttpRequest&, Http::HttpResponse& res) {
            HandleHealth(res);
        });

        // -- Authentication --
        m_httpServer->Post("/api/v1/auth/login", [this](
            const Http::HttpRequest& req, Http::HttpResponse& res) {
            HandleLogin(req, res);
        });

        m_httpServer->Post("/api/v1/auth/logout", [this](
            const Http::HttpRequest& req, Http::HttpResponse& res) {
            HandleLogout(req, res);
        });

        m_httpServer->Get("/api/v1/auth/session", [this](
            const Http::HttpRequest& req, Http::HttpResponse& res) {
            HandleSessionInfo(req, res);
        });

        // -- System --
        m_httpServer->Get("/api/v1/status", [this](
            const Http::HttpRequest&, Http::HttpResponse& res) {
            HandleStatus(res);
        });

        m_httpServer->Get("/api/v1/stats", [this](
            const Http::HttpRequest&, Http::HttpResponse& res) {
            HandleStats(res);
        });

        m_httpServer->Get("/api/v1/modules", [this](
            const Http::HttpRequest&, Http::HttpResponse& res) {
            HandleModules(res);
        });

        m_httpServer->Get("/api/v1/license", [this](
            const Http::HttpRequest&, Http::HttpResponse& res) {
            HandleLicense(res);
        });

        // -- Scanning --
        m_httpServer->Post("/api/v1/scan/quick", [this](
            const Http::HttpRequest&, Http::HttpResponse& res) {
            HandleScanQuick(res);
        });

        m_httpServer->Post("/api/v1/scan/full", [this](
            const Http::HttpRequest&, Http::HttpResponse& res) {
            HandleScanFull(res);
        });

        m_httpServer->Post("/api/v1/scan/custom", [this](
            const Http::HttpRequest& req, Http::HttpResponse& res) {
            HandleScanCustom(req, res);
        });

        m_httpServer->Post("/api/v1/scan/stop", [this](
            const Http::HttpRequest&, Http::HttpResponse& res) {
            HandleScanStop(res);
        });

        m_httpServer->Get("/api/v1/scan/progress", [this](
            const Http::HttpRequest&, Http::HttpResponse& res) {
            HandleScanProgress(res);
        });

        // -- Quarantine --
        m_httpServer->Get("/api/v1/quarantine", [this](
            const Http::HttpRequest& req, Http::HttpResponse& res) {
            HandleQuarantineList(req, res);
        });

        m_httpServer->Post("/api/v1/quarantine/restore", [this](
            const Http::HttpRequest& req, Http::HttpResponse& res) {
            HandleQuarantineRestore(req, res);
        });

        m_httpServer->Post("/api/v1/quarantine/delete", [this](
            const Http::HttpRequest& req, Http::HttpResponse& res) {
            HandleQuarantineDelete(req, res);
        });

        // -- Threats --
        m_httpServer->Get("/api/v1/threats", [this](
            const Http::HttpRequest& req, Http::HttpResponse& res) {
            HandleThreatsList(req, res);
        });

        m_httpServer->Get("/api/v1/threats/:id", [this](
            const Http::HttpRequest& req, Http::HttpResponse& res) {
            HandleThreatDetail(req, res);
        });

        // -- Threat Intel --
        m_httpServer->Get("/api/v1/threatintel/feeds", [this](
            const Http::HttpRequest&, Http::HttpResponse& res) {
            HandleThreatIntelFeeds(res);
        });

        // -- Configuration --
        m_httpServer->Get("/api/v1/config", [this](
            const Http::HttpRequest&, Http::HttpResponse& res) {
            HandleConfigGet(res);
        });

        m_httpServer->Put("/api/v1/config", [this](
            const Http::HttpRequest& req, Http::HttpResponse& res) {
            HandleConfigUpdate(req, res);
        });

        // -- Alerts --
        m_httpServer->Get("/api/v1/alerts", [this](
            const Http::HttpRequest& req, Http::HttpResponse& res) {
            HandleAlertsList(req, res);
        });

        m_httpServer->Post("/api/v1/alerts/:id/acknowledge", [this](
            const Http::HttpRequest& req, Http::HttpResponse& res) {
            HandleAlertAcknowledge(req, res);
        });

        // -- RTP (Real-Time Protection) --
        m_httpServer->Get("/api/v1/rtp/status", [this](
            const Http::HttpRequest&, Http::HttpResponse& res) {
            HandleRTPStatus(res);
        });

        m_httpServer->Post("/api/v1/rtp/toggle", [this](
            const Http::HttpRequest& req, Http::HttpResponse& res) {
            HandleRTPToggle(req, res);
        });
    }

    // ========================================================================
    // ROUTE HANDLERS — HEALTH
    // ========================================================================

    void HandleHealth(Http::HttpResponse& res) {
        nlohmann::json j;
        j["status"] = "ok";
        j["version"] = "1.0.0";
        j["timestamp"] = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        res.SetJsonBody(j.dump());
    }

    // ========================================================================
    // ROUTE HANDLERS — AUTHENTICATION
    // ========================================================================

    void HandleLogin(const Http::HttpRequest& req, Http::HttpResponse& res) {
        // Parse request body
        nlohmann::json body;
        if (!ParseJsonBody(req, body, res)) return;

        // Validate required fields
        if (!body.contains("password") || !body["password"].is_string()) {
            res = Http::HttpResponse::MakeError(
                Http::HttpStatus::BadRequest,
                "Missing or invalid 'password' field");
            return;
        }

        const std::string password = body["password"].get<std::string>();

        // Validate credentials against stored password hash
        // For Community localhost mode, we use a locally-configured passphrase
        if (!ValidateCredentials(password)) {
            m_stats.authFailures.fetch_add(1, std::memory_order_relaxed);
            SS_LOG_WARN(LOG_CAT, L"Login attempt failed from %hs",
                        req.remoteAddress.c_str());

            res = Http::HttpResponse::MakeError(
                Http::HttpStatus::Unauthorized,
                "Invalid credentials");
            return;
        }

        // Create session
        auto session = CreateSession(req.remoteAddress);
        if (session.token.empty()) {
            res = Http::HttpResponse::MakeError(
                Http::HttpStatus::InternalError,
                "Failed to generate session token");
            return;
        }

        const auto tokenCopy = session.token;
        const auto csrfCopy = session.csrfToken;

        // Atomically prune expired sessions, enforce the cap, and insert the
        // new session under one exclusive lock to eliminate the TOCTOU window
        // between the prior size-check (shared) and insert (unique) phases.
        {
            std::unique_lock lock(m_sessionMutex);
            PruneExpiredSessionsLocked();

            if (m_sessions.size() >= m_config.maxSessions) {
                res = Http::HttpResponse::MakeError(
                    Http::HttpStatus::TooManyRequests,
                    "Maximum active sessions reached");
                return;
            }

            m_sessions.emplace(session.token, std::move(session));
            m_stats.activeSessions.store(m_sessions.size(),
                                         std::memory_order_relaxed);
        }

        nlohmann::json resp;
        resp["token"] = tokenCopy;
        resp["csrf_token"] = csrfCopy;
        resp["expires_in"] = m_config.sessionTimeoutSeconds;

        res.status = Http::HttpStatus::OK;
        res.SetJsonBody(resp.dump());

        SS_LOG_INFO(LOG_CAT, L"Session created from %hs",
                    req.remoteAddress.c_str());
    }

    void HandleLogout(const Http::HttpRequest& req, Http::HttpResponse& res) {
        const auto token = ExtractBearerToken(req);
        if (token.empty()) {
            res = Http::HttpResponse::MakeError(
                Http::HttpStatus::BadRequest,
                "No active session");
            return;
        }

        {
            std::unique_lock lock(m_sessionMutex);
            if (m_sessions.erase(token) > 0) {
                m_stats.activeSessions.fetch_sub(1, std::memory_order_relaxed);
            }
        }

        nlohmann::json resp;
        resp["status"] = "logged_out";
        res.SetJsonBody(resp.dump());

        SS_LOG_INFO(LOG_CAT, L"Session terminated from %hs",
                    req.remoteAddress.c_str());
    }

    void HandleSessionInfo(const Http::HttpRequest& req, Http::HttpResponse& res) {
        const auto token = ExtractBearerToken(req);
        std::shared_lock lock(m_sessionMutex);

        auto it = m_sessions.find(token);
        if (it == m_sessions.end()) {
            res = Http::HttpResponse::MakeError(
                Http::HttpStatus::Unauthorized,
                "Session not found");
            return;
        }

        const auto& sess = it->second;
        const auto now = std::chrono::steady_clock::now();
        const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - sess.createdAt).count();
        const auto idle = std::chrono::duration_cast<std::chrono::seconds>(
            now - sess.lastActivity).count();
        const auto remaining = static_cast<int64_t>(m_config.sessionTimeoutSeconds)
                               - idle;

        nlohmann::json j;
        j["source_address"] = sess.sourceAddress;
        j["created_seconds_ago"] = elapsed;
        j["idle_seconds"] = idle;
        j["expires_in_seconds"] = (remaining > 0) ? remaining : 0;
        j["request_count"] = sess.requestCount;
        j["csrf_token"] = sess.csrfToken;

        res.SetJsonBody(j.dump());
    }

    // ========================================================================
    // ROUTE HANDLERS — SYSTEM
    // ========================================================================

    void HandleStatus(Http::HttpResponse& res) {
        nlohmann::json j;

        // Engine status
        auto& engine = Core::Engine::ScanEngine::Instance();
        j["engine"]["initialized"] = engine.IsInitialized();

        // RTP status
        auto& rtp = RealTime::RealTimeProtection::Instance();
        j["rtp"]["running"] = rtp.IsActive();
        j["rtp"]["state"] = static_cast<uint8_t>(rtp.GetState());

        // Product tier
        if (Config::ProductTierManager::HasInstance() &&
            Config::ProductTierManager::Instance().IsInitialized()) {
            auto& tier = Config::ProductTierManager::Instance();
            std::wstring_view tierName = tier.GetTierDisplayName();
            j["tier"]["name"] = WideToJsonUtf8(tierName);
            j["tier"]["level"] = static_cast<uint8_t>(tier.GetCurrentTier());
        }

        // Uptime
        const auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - m_stats.startTime).count();
        j["uptime_seconds"] = uptime;

        // API stats
        const auto apiStats = m_stats.TakeSnapshot();
        j["api"]["total_requests"] = apiStats.totalRequests;
        j["api"]["active_sessions"] = apiStats.activeSessions;
        j["api"]["sse_clients"] = GetSSEClientCount();

        res.SetJsonBody(j.dump());
    }

    void HandleStats(Http::HttpResponse& res) {
        nlohmann::json j;

        // API statistics
        const auto apiStats = m_stats.TakeSnapshot();
        j["api"]["total_requests"] = apiStats.totalRequests;
        j["api"]["successful"] = apiStats.successfulRequests;
        j["api"]["failed"] = apiStats.failedRequests;
        j["api"]["rejected"] = apiStats.rejectedRequests;
        j["api"]["auth_failures"] = apiStats.authFailures;
        j["api"]["rate_limit_hits"] = apiStats.rateLimitHits;
        j["api"]["bytes_received"] = apiStats.bytesReceived;
        j["api"]["bytes_sent"] = apiStats.bytesSent;
        j["api"]["uptime_ms"] = apiStats.uptime.count();

        // HTTP server statistics
        if (m_httpServer) {
            const auto httpStats = m_httpServer->GetStats();
            j["http"]["total_requests"] = httpStats.totalRequests;
            j["http"]["total_responses"] = httpStats.totalResponses;
            j["http"]["active_connections"] = httpStats.activeConnections;
            j["http"]["total_connections"] = httpStats.totalConnections;
            j["http"]["rejected_connections"] = httpStats.rejectedConnections;
            j["http"]["parse_errors"] = httpStats.parseErrors;
            j["http"]["timeouts"] = httpStats.timeouts;
        }

        // Quarantine statistics
        auto& qm = Core::Engine::QuarantineManager::Instance();
        if (qm.IsInitialized()) {
            const auto qStats = qm.GetStats();
            j["quarantine"]["total_items"] = qm.GetEntryCount();
            j["quarantine"]["active_items"] = qm.GetEntryCount(
                Core::Engine::QuarantineState::Active);
            j["quarantine"]["bytes_stored"] =
                qStats.currentVaultSize.load(std::memory_order_relaxed);
            j["quarantine"]["entries_added"] =
                qStats.totalQuarantined.load(std::memory_order_relaxed);
            j["quarantine"]["entries_restored"] =
                qStats.totalRestored.load(std::memory_order_relaxed);
            j["quarantine"]["entries_deleted"] =
                qStats.totalDeleted.load(std::memory_order_relaxed);
        }

        res.SetJsonBody(j.dump());
    }

    void HandleModules(Http::HttpResponse& res) {
        nlohmann::json modules = nlohmann::json::array();

        // ScanEngine
        {
            nlohmann::json m;
            m["name"] = "ScanEngine";
            m["initialized"] = Core::Engine::ScanEngine::Instance().IsInitialized();
            m["category"] = "detection";
            modules.push_back(std::move(m));
        }

        // RealTimeProtection
        {
            nlohmann::json m;
            m["name"] = "RealTimeProtection";
            m["initialized"] = true; // singleton always exists
            m["running"] = RealTime::RealTimeProtection::Instance().IsActive();
            m["category"] = "protection";
            modules.push_back(std::move(m));
        }

        // QuarantineManager
        {
            nlohmann::json m;
            m["name"] = "QuarantineManager";
            m["initialized"] = Core::Engine::QuarantineManager::Instance().IsInitialized();
            m["category"] = "remediation";
            modules.push_back(std::move(m));
        }

        // AlertSystem
        {
            nlohmann::json m;
            m["name"] = "AlertSystem";
            m["initialized"] = Communication::AlertSystem::Instance().IsInitialized();
            m["category"] = "communication";
            modules.push_back(std::move(m));
        }

        // ConfigManager
        {
            nlohmann::json m;
            m["name"] = "ConfigManager";
            m["initialized"] = Config::ConfigManager::Instance().IsInitialized();
            m["category"] = "configuration";
            modules.push_back(std::move(m));
        }

        // ProductTierManager
        if (Config::ProductTierManager::HasInstance()) {
            nlohmann::json m;
            m["name"] = "ProductTierManager";
            m["initialized"] = Config::ProductTierManager::Instance().IsInitialized();
            m["category"] = "licensing";
            modules.push_back(std::move(m));
        }

        nlohmann::json j;
        j["modules"] = std::move(modules);
        j["count"] = j["modules"].size();

        res.SetJsonBody(j.dump());
    }

    void HandleLicense(Http::HttpResponse& res) {
        nlohmann::json j;

        if (Config::ProductTierManager::HasInstance() &&
            Config::ProductTierManager::Instance().IsInitialized()) {
            auto& tier = Config::ProductTierManager::Instance();

            std::wstring_view tierName = tier.GetTierName();
            std::wstring_view displayName = tier.GetTierDisplayName();

            j["tier"] = WideToJsonUtf8(tierName);
            j["display_name"] = WideToJsonUtf8(displayName);
            j["level"] = static_cast<uint8_t>(tier.GetCurrentTier());

            const auto& info = tier.GetLicenseInfo();
            j["license"]["valid"] = tier.IsLicenseValid();
            j["license"]["status"] = static_cast<uint8_t>(tier.ValidateLicense());
            j["license"]["expiring_soon"] = tier.IsLicenseExpiringSoon();

            // Feature flags
            nlohmann::json features = nlohmann::json::array();
            auto allFeatures = tier.GetAllFeatures();
            for (const auto& f : allFeatures) {
                nlohmann::json feat;
                feat["category"] = static_cast<uint8_t>(f.category);
                feat["enabled"] = f.isEnabled;
                features.push_back(std::move(feat));
            }
            j["features"] = std::move(features);
        } else {
            j["tier"] = "community";
            j["display_name"] = "Phantom Community";
            j["level"] = 0;
        }

        res.SetJsonBody(j.dump());
    }

    // ========================================================================
    // ROUTE HANDLERS — SCANNING
    // ========================================================================

    void HandleScanQuick(Http::HttpResponse& res) {
        auto& engine = Core::Engine::ScanEngine::Instance();
        if (!engine.IsInitialized()) {
            res = Http::HttpResponse::MakeError(
                Http::HttpStatus::ServiceUnavailable,
                "Scan engine not initialized");
            return;
        }

        auto jobId = engine.CreateScanJob(
            Core::Engine::DirectoryScanRequest{},
            Core::Engine::ScanPriority::Normal);

        nlohmann::json j;
        j["status"] = "started";
        j["scan_type"] = "quick";
        j["job_id"] = jobId;

        res.status = Http::HttpStatus::Accepted;
        res.SetJsonBody(j.dump());

        SS_LOG_INFO(LOG_CAT, L"Quick scan started via REST API (job %llu)", jobId);

        // Broadcast SSE event
        BroadcastEvent(SSEEventType::ScanProgress, j.dump());
    }

    void HandleScanFull(Http::HttpResponse& res) {
        auto& engine = Core::Engine::ScanEngine::Instance();
        if (!engine.IsInitialized()) {
            res = Http::HttpResponse::MakeError(
                Http::HttpStatus::ServiceUnavailable,
                "Scan engine not initialized");
            return;
        }

        Core::Engine::DirectoryScanRequest request;
        // Full scan uses higher priority
        auto jobId = engine.CreateScanJob(request, Core::Engine::ScanPriority::High);

        nlohmann::json j;
        j["status"] = "started";
        j["scan_type"] = "full";
        j["job_id"] = jobId;

        res.status = Http::HttpStatus::Accepted;
        res.SetJsonBody(j.dump());

        SS_LOG_INFO(LOG_CAT, L"Full scan started via REST API (job %llu)", jobId);
        BroadcastEvent(SSEEventType::ScanProgress, j.dump());
    }

    void HandleScanCustom(const Http::HttpRequest& req, Http::HttpResponse& res) {
        nlohmann::json body;
        if (!ParseJsonBody(req, body, res)) return;

        if (!body.contains("paths") || !body["paths"].is_array() ||
            body["paths"].empty()) {
            res = Http::HttpResponse::MakeError(
                Http::HttpStatus::BadRequest,
                "Missing or empty 'paths' array");
            return;
        }

        // Validate and collect paths
        std::vector<std::wstring> targets;
        targets.reserve(body["paths"].size());

        for (const auto& p : body["paths"]) {
            if (!p.is_string()) {
                res = Http::HttpResponse::MakeError(
                    Http::HttpStatus::BadRequest,
                    "All paths must be strings");
                return;
            }

            const std::string pathStr = p.get<std::string>();

            // Path traversal check
            if (Http::ContainsPathTraversal(pathStr)) {
                res = Http::HttpResponse::MakeError(
                    Http::HttpStatus::BadRequest,
                    "Path traversal detected in scan target");
                return;
            }

            // Cap number of scan targets
            if (targets.size() >= 1000) {
                res = Http::HttpResponse::MakeError(
                    Http::HttpStatus::BadRequest,
                    "Maximum 1000 scan targets per request");
                return;
            }

            // Convert input path (UTF-8) to wide (UTF-16) using the proper
            // Utils helper — naive iterator-range copy would corrupt any
            // non-ASCII byte and miscount on multi-byte sequences.
            std::wstring widePath = Utils::StringUtils::ToWide(pathStr);
            if (widePath.empty() && !pathStr.empty()) {
                res = Http::HttpResponse::MakeError(
                    Http::HttpStatus::BadRequest,
                    "Scan target contains an invalid UTF-8 path");
                return;
            }
            targets.push_back(std::move(widePath));
        }

        auto& engine = Core::Engine::ScanEngine::Instance();
        if (!engine.IsInitialized()) {
            res = Http::HttpResponse::MakeError(
                Http::HttpStatus::ServiceUnavailable,
                "Scan engine not initialized");
            return;
        }

        Core::Engine::DirectoryScanRequest request;
        auto jobId = engine.CreateScanJob(request, Core::Engine::ScanPriority::Normal);

        nlohmann::json j;
        j["status"] = "started";
        j["scan_type"] = "custom";
        j["job_id"] = jobId;
        j["target_count"] = targets.size();

        res.status = Http::HttpStatus::Accepted;
        res.SetJsonBody(j.dump());

        SS_LOG_INFO(LOG_CAT, L"Custom scan started via REST API (job %llu, %zu targets)",
                    jobId, targets.size());
        BroadcastEvent(SSEEventType::ScanProgress, j.dump());
    }

    void HandleScanStop(Http::HttpResponse& res) {
        auto& engine = Core::Engine::ScanEngine::Instance();
        if (!engine.IsInitialized()) {
            res = Http::HttpResponse::MakeError(
                Http::HttpStatus::ServiceUnavailable,
                "Scan engine not initialized");
            return;
        }

        engine.CancelAllJobs();

        nlohmann::json j;
        j["status"] = "stopped";
        j["message"] = "All active scan jobs cancelled";

        res.SetJsonBody(j.dump());
        SS_LOG_INFO(LOG_CAT, L"All scans cancelled via REST API");
    }

    void HandleScanProgress(Http::HttpResponse& res) {
        auto& engine = Core::Engine::ScanEngine::Instance();
        if (!engine.IsInitialized()) {
            res = Http::HttpResponse::MakeError(
                Http::HttpStatus::ServiceUnavailable,
                "Scan engine not initialized");
            return;
        }

        const auto activeJobs = engine.GetActiveJobs();

        nlohmann::json j;
        j["active_jobs"] = nlohmann::json::array();

        for (const auto jobId : activeJobs) {
            const auto progress = engine.GetJobProgress(jobId);
            const auto state = engine.GetJobState(jobId);

            nlohmann::json jobJson;
            jobJson["job_id"] = jobId;
            jobJson["state"] = static_cast<uint8_t>(state);

            if (progress.has_value()) {
                const auto& p = progress.value();
                jobJson["files_scanned"] = p.filesScanned;
                jobJson["total_files"] = p.totalFiles;
                jobJson["bytes_scanned"] = p.bytesScanned;
                jobJson["percent_complete"] = p.percentComplete;
                jobJson["elapsed_ms"] = p.elapsed.count();
                jobJson["estimated_remaining_ms"] = p.estimatedRemaining.count();

                // Convert current file (UTF-16) to UTF-8 for JSON.
                jobJson["current_file"] = WideToJsonUtf8(p.currentFile);
            }

            j["active_jobs"].push_back(std::move(jobJson));
        }

        j["count"] = activeJobs.size();
        res.SetJsonBody(j.dump());
    }

    // ========================================================================
    // ROUTE HANDLERS — QUARANTINE
    // ========================================================================

    void HandleQuarantineList(const Http::HttpRequest& req, Http::HttpResponse& res) {
        auto& qm = Core::Engine::QuarantineManager::Instance();
        if (!qm.IsInitialized()) {
            res = Http::HttpResponse::MakeError(
                Http::HttpStatus::ServiceUnavailable,
                "Quarantine manager not initialized");
            return;
        }

        const auto entries = qm.GetActiveEntries();

        nlohmann::json j;
        j["items"] = nlohmann::json::array();

        for (const auto& entry : entries) {
            nlohmann::json item;
            item["id"] = entry.entryId;
            item["file_name"] = WideToJsonUtf8(entry.fileName);
            item["original_path"] = WideToJsonUtf8(entry.originalPath);
            item["threat_name"] = WideToJsonUtf8(entry.threatName);
            item["threat_score"] = entry.threatScore;
            item["state"] = static_cast<uint8_t>(entry.state);
            item["quarantine_time"] = std::chrono::duration_cast<std::chrono::seconds>(
                entry.quarantineTime.time_since_epoch()).count();

            j["items"].push_back(std::move(item));
        }

        j["count"] = entries.size();
        j["total"] = qm.GetEntryCount();

        res.SetJsonBody(j.dump());
    }

    void HandleQuarantineRestore(const Http::HttpRequest& req, Http::HttpResponse& res) {
        nlohmann::json body;
        if (!ParseJsonBody(req, body, res)) return;

        if (!body.contains("entry_id") || !body["entry_id"].is_number_unsigned()) {
            res = Http::HttpResponse::MakeError(
                Http::HttpStatus::BadRequest,
                "Missing or invalid 'entry_id' field");
            return;
        }

        const uint64_t entryId = body["entry_id"].get<uint64_t>();

        auto& qm = Core::Engine::QuarantineManager::Instance();
        if (!qm.IsInitialized()) {
            res = Http::HttpResponse::MakeError(
                Http::HttpStatus::ServiceUnavailable,
                "Quarantine manager not initialized");
            return;
        }

        // Optional: custom restore path
        std::wstring restorePath;
        if (body.contains("restore_path") && body["restore_path"].is_string()) {
            const std::string rp = body["restore_path"].get<std::string>();
            if (Http::ContainsPathTraversal(rp)) {
                res = Http::HttpResponse::MakeError(
                    Http::HttpStatus::BadRequest,
                    "Path traversal detected in restore path");
                return;
            }
            restorePath = Utils::StringUtils::ToWide(rp);
            if (restorePath.empty() && !rp.empty()) {
                res = Http::HttpResponse::MakeError(
                    Http::HttpStatus::BadRequest,
                    "Restore path contains invalid UTF-8");
                return;
            }
        }

        auto result = qm.RestoreFile(entryId, restorePath);

        nlohmann::json j;
        j["success"] = result.IsSuccess();
        j["entry_id"] = entryId;
        j["status"] = static_cast<uint8_t>(result.status);

        if (result.IsSuccess()) {
            res.status = Http::HttpStatus::OK;
            SS_LOG_INFO(LOG_CAT, L"Quarantine entry %llu restored via REST API", entryId);

            nlohmann::json event;
            event["action"] = "restored";
            event["entry_id"] = entryId;
            BroadcastEvent(SSEEventType::QuarantineAction, event.dump());
        } else {
            res.status = Http::HttpStatus::Conflict;
            SS_LOG_WARN(LOG_CAT, L"Failed to restore quarantine entry %llu", entryId);
        }

        res.SetJsonBody(j.dump());
    }

    void HandleQuarantineDelete(const Http::HttpRequest& req, Http::HttpResponse& res) {
        nlohmann::json body;
        if (!ParseJsonBody(req, body, res)) return;

        if (!body.contains("entry_id") || !body["entry_id"].is_number_unsigned()) {
            res = Http::HttpResponse::MakeError(
                Http::HttpStatus::BadRequest,
                "Missing or invalid 'entry_id' field");
            return;
        }

        const uint64_t entryId = body["entry_id"].get<uint64_t>();
        const bool secureWipe = body.value("secure_wipe", false);

        auto& qm = Core::Engine::QuarantineManager::Instance();
        if (!qm.IsInitialized()) {
            res = Http::HttpResponse::MakeError(
                Http::HttpStatus::ServiceUnavailable,
                "Quarantine manager not initialized");
            return;
        }

        const bool success = qm.DeleteFile(entryId, secureWipe);

        nlohmann::json j;
        j["success"] = success;
        j["entry_id"] = entryId;
        j["secure_wipe"] = secureWipe;

        if (success) {
            res.status = Http::HttpStatus::OK;
            SS_LOG_INFO(LOG_CAT, L"Quarantine entry %llu deleted via REST API (wipe=%d)",
                        entryId, secureWipe);

            nlohmann::json event;
            event["action"] = "deleted";
            event["entry_id"] = entryId;
            BroadcastEvent(SSEEventType::QuarantineAction, event.dump());
        } else {
            res.status = Http::HttpStatus::NotFound;
        }

        res.SetJsonBody(j.dump());
    }

    // ========================================================================
    // ROUTE HANDLERS — THREATS
    // ========================================================================

    void HandleThreatsList(const Http::HttpRequest& req, Http::HttpResponse& res) {
        auto& alerts = Communication::AlertSystem::Instance();
        if (!alerts.IsInitialized()) {
            res = Http::HttpResponse::MakeError(
                Http::HttpStatus::ServiceUnavailable,
                "Alert system not initialized");
            return;
        }

        // Parse query params for filtering. std::stoul throws on malformed
        // input — we never let user-controlled query values reach it.
        const auto limitParam = req.GetQueryParam("limit");
        const size_t limit = limitParam.has_value()
            ? ParseSizeTClamped(limitParam.value(), 100).value_or(50)
            : size_t{50};

        const auto threatAlerts = alerts.GetRecentAlerts(limit);

        nlohmann::json j;
        j["threats"] = nlohmann::json::array();

        for (const auto& alert : threatAlerts) {
            // Filter to threat-detection type alerts only
            if (alert.type != Communication::AlertType::ThreatDetection) continue;

            nlohmann::json item;
            item["id"] = alert.alertId;
            item["severity"] = static_cast<uint8_t>(alert.severity);
            item["type"] = static_cast<uint8_t>(alert.type);
            item["status"] = static_cast<uint8_t>(alert.status);
            item["subject"] = alert.subject;
            item["source"] = alert.source;

            j["threats"].push_back(std::move(item));
        }

        j["count"] = j["threats"].size();
        res.SetJsonBody(j.dump());
    }

    void HandleThreatDetail(const Http::HttpRequest& req, Http::HttpResponse& res) {
        auto it = req.pathParams.find("id");
        if (it == req.pathParams.end()) {
            res = Http::HttpResponse::MakeError(
                Http::HttpStatus::BadRequest,
                "Missing threat ID");
            return;
        }

        const std::string& alertId = it->second;

        auto& alerts = Communication::AlertSystem::Instance();
        if (!alerts.IsInitialized()) {
            res = Http::HttpResponse::MakeError(
                Http::HttpStatus::ServiceUnavailable,
                "Alert system not initialized");
            return;
        }

        auto alert = alerts.GetAlert(alertId);
        if (!alert.has_value()) {
            res = Http::HttpResponse::MakeError(
                Http::HttpStatus::NotFound,
                "Threat not found");
            return;
        }

        nlohmann::json j;
        j["id"] = alert->alertId;
        j["severity"] = static_cast<uint8_t>(alert->severity);
        j["type"] = static_cast<uint8_t>(alert->type);
        j["status"] = static_cast<uint8_t>(alert->status);

        res.SetJsonBody(j.dump());
    }

    // ========================================================================
    // ROUTE HANDLERS — THREAT INTEL
    // ========================================================================

    void HandleThreatIntelFeeds(Http::HttpResponse& res) {
        // ThreatIntelFeedManager API access
        // For now, return the feature availability status
        nlohmann::json j;

        bool tiEnabled = false;
        bool tiAdvanced = false;

        if (Config::ProductTierManager::HasInstance() &&
            Config::ProductTierManager::Instance().IsInitialized()) {
            tiEnabled = Config::ProductTierManager::Instance().IsFeatureEnabled(
                Config::FeatureCategory::ThreatIntel);
            tiAdvanced = Config::ProductTierManager::Instance().IsFeatureEnabled(
                Config::FeatureCategory::ThreatIntelAdvanced);
        }

        j["threat_intel_enabled"] = tiEnabled;
        j["advanced_feeds_enabled"] = tiAdvanced;
        j["feeds"] = nlohmann::json::array();

        res.SetJsonBody(j.dump());
    }

    // ========================================================================
    // ROUTE HANDLERS — CONFIGURATION
    // ========================================================================

    void HandleConfigGet(Http::HttpResponse& res) {
        auto& cm = Config::ConfigManager::Instance();
        if (!cm.IsInitialized()) {
            res = Http::HttpResponse::MakeError(
                Http::HttpStatus::ServiceUnavailable,
                "Configuration manager not initialized");
            return;
        }

        // Export current config as JSON
        const std::string configJson = cm.ExportToJson();

        if (configJson.empty()) {
            res = Http::HttpResponse::MakeError(
                Http::HttpStatus::InternalError,
                "Failed to serialize configuration");
            return;
        }

        // Parse and return (so we control the structure)
        nlohmann::json j;
        j["config"] = nlohmann::json::parse(configJson, nullptr, false);
        if (j["config"].is_discarded()) {
            j["config"] = nlohmann::json::object();
        }

        res.SetJsonBody(j.dump());
    }

    void HandleConfigUpdate(const Http::HttpRequest& req, Http::HttpResponse& res) {
        nlohmann::json body;
        if (!ParseJsonBody(req, body, res)) return;

        auto& cm = Config::ConfigManager::Instance();
        if (!cm.IsInitialized()) {
            res = Http::HttpResponse::MakeError(
                Http::HttpStatus::ServiceUnavailable,
                "Configuration manager not initialized");
            return;
        }

        if (!body.contains("config") || !body["config"].is_object()) {
            res = Http::HttpResponse::MakeError(
                Http::HttpStatus::BadRequest,
                "Missing or invalid 'config' object");
            return;
        }

        const std::string configStr = body["config"].dump();
        const bool success = cm.ImportFromJson(configStr);

        nlohmann::json j;
        j["success"] = success;

        if (success) {
            j["message"] = "Configuration updated";
            SS_LOG_INFO(LOG_CAT, L"Configuration updated via REST API");

            nlohmann::json event;
            event["action"] = "config_updated";
            BroadcastEvent(SSEEventType::ConfigChange, event.dump());
        } else {
            j["message"] = "Failed to apply configuration";
            res.status = Http::HttpStatus::BadRequest;
        }

        res.SetJsonBody(j.dump());
    }

    // ========================================================================
    // ROUTE HANDLERS — ALERTS
    // ========================================================================

    void HandleAlertsList(const Http::HttpRequest& req, Http::HttpResponse& res) {
        auto& alertSystem = Communication::AlertSystem::Instance();
        if (!alertSystem.IsInitialized()) {
            res = Http::HttpResponse::MakeError(
                Http::HttpStatus::ServiceUnavailable,
                "Alert system not initialized");
            return;
        }

        const auto limitParam = req.GetQueryParam("limit");
        const size_t limit = limitParam.has_value()
            ? ParseSizeTClamped(limitParam.value(), 100).value_or(50)
            : size_t{50};

        const auto recentAlerts = alertSystem.GetRecentAlerts(limit);

        nlohmann::json j;
        j["alerts"] = nlohmann::json::array();

        for (const auto& alert : recentAlerts) {
            nlohmann::json item;
            item["id"] = alert.alertId;
            item["severity"] = static_cast<uint8_t>(alert.severity);
            item["type"] = static_cast<uint8_t>(alert.type);
            item["status"] = static_cast<uint8_t>(alert.status);
            item["subject"] = alert.subject;
            item["source"] = alert.source;

            j["alerts"].push_back(std::move(item));
        }

        j["count"] = recentAlerts.size();

        const auto stats = alertSystem.GetStatistics();
        j["statistics"]["total_alerts"] = stats.totalAlerts;
        j["statistics"]["alerts_sent"] = stats.alertsSent;

        res.SetJsonBody(j.dump());
    }

    void HandleAlertAcknowledge(const Http::HttpRequest& req, Http::HttpResponse& res) {
        auto it = req.pathParams.find("id");
        if (it == req.pathParams.end()) {
            res = Http::HttpResponse::MakeError(
                Http::HttpStatus::BadRequest,
                "Missing alert ID");
            return;
        }

        const std::string& alertId = it->second;

        auto& alertSystem = Communication::AlertSystem::Instance();
        if (!alertSystem.IsInitialized()) {
            res = Http::HttpResponse::MakeError(
                Http::HttpStatus::ServiceUnavailable,
                "Alert system not initialized");
            return;
        }

        const bool success = alertSystem.AcknowledgeAlert(
            alertId, "REST_API_User");

        nlohmann::json j;
        j["success"] = success;
        j["alert_id"] = alertId;

        if (!success) {
            res.status = Http::HttpStatus::NotFound;
            j["message"] = "Alert not found or already acknowledged";
        }

        res.SetJsonBody(j.dump());
    }

    // ========================================================================
    // ROUTE HANDLERS — RTP
    // ========================================================================

    void HandleRTPStatus(Http::HttpResponse& res) {
        auto& rtp = RealTime::RealTimeProtection::Instance();

        const auto status = rtp.GetStatus();

        nlohmann::json j;
        j["state"] = static_cast<uint8_t>(status.state);
        j["is_protected"] = status.isProtected;
        j["driver_loaded"] = status.driverLoaded;
        j["driver_connected"] = status.driverConnected;
        j["cpu_usage_percent"] = status.cpuUsagePercent;
        j["memory_usage_bytes"] = status.memoryUsageBytes;

        // Component statuses
        j["components"] = nlohmann::json::array();
        for (const auto& comp : status.components) {
            nlohmann::json c;
            c["type"] = static_cast<uint8_t>(comp.type);
            c["state"] = static_cast<uint8_t>(comp.state);
            j["components"].push_back(std::move(c));
        }

        res.SetJsonBody(j.dump());
    }

    void HandleRTPToggle(const Http::HttpRequest& req, Http::HttpResponse& res) {
        nlohmann::json body;
        if (!ParseJsonBody(req, body, res)) return;

        if (!body.contains("enabled") || !body["enabled"].is_boolean()) {
            res = Http::HttpResponse::MakeError(
                Http::HttpStatus::BadRequest,
                "Missing or invalid 'enabled' boolean field");
            return;
        }

        const bool enable = body["enabled"].get<bool>();
        auto& rtp = RealTime::RealTimeProtection::Instance();

        bool success = false;
        if (enable) {
            if (!rtp.IsActive()) {
                success = rtp.Start();
            } else {
                success = rtp.Resume();
            }
        } else {
            if (rtp.IsActive()) {
                success = rtp.Pause();
            } else {
                success = true; // already not running
            }
        }

        nlohmann::json j;
        j["success"] = success;
        j["enabled"] = enable;
        j["active"] = rtp.IsActive();
        j["state"] = static_cast<uint8_t>(rtp.GetState());

        if (success) {
            SS_LOG_INFO(LOG_CAT, L"RTP %hs via REST API",
                        enable ? "enabled" : "disabled");

            nlohmann::json event;
            event["module"] = "RealTimeProtection";
            event["running"] = rtp.IsActive();
            BroadcastEvent(SSEEventType::ModuleStatusChange, event.dump());
        } else {
            res.status = Http::HttpStatus::InternalError;
            SS_LOG_ERROR(LOG_CAT, L"Failed to %hs RTP via REST API",
                         enable ? "enable" : "disable");
        }

        res.SetJsonBody(j.dump());
    }

    // ========================================================================
    // SESSION HELPERS
    // ========================================================================

    [[nodiscard]] Session CreateSession(const std::string& sourceAddress) {
        Session session;

        // Generate 256-bit bearer token
        std::vector<uint8_t> tokenBytes(TOKEN_BYTES);
        Utils::CryptoUtils::SecureRandom rng;
        if (!rng.Generate(tokenBytes.data(), tokenBytes.size())) {
            SS_LOG_ERROR(LOG_CAT, L"Failed to generate session token via SecureRandom");
            return {};
        }
        session.token = Utils::HashUtils::ToHexLower(tokenBytes);

        // Generate 128-bit CSRF token
        std::vector<uint8_t> csrfBytes(CSRF_TOKEN_BYTES);
        if (!rng.Generate(csrfBytes.data(), csrfBytes.size())) {
            SS_LOG_ERROR(LOG_CAT, L"Failed to generate CSRF token via SecureRandom");
            return {};
        }
        session.csrfToken = Utils::HashUtils::ToHexLower(csrfBytes);

        session.createdAt = std::chrono::steady_clock::now();
        session.lastActivity = session.createdAt;
        session.sourceAddress = sourceAddress;
        session.requestCount = 0;

        return session;
    }

    [[nodiscard]] bool ValidateSession(const std::string& token) const {
        std::shared_lock lock(m_sessionMutex);

        auto it = m_sessions.find(token);
        if (it == m_sessions.end()) {
            return false;
        }

        const auto& session = it->second;
        const auto now = std::chrono::steady_clock::now();
        const auto idleTime = std::chrono::duration_cast<std::chrono::seconds>(
            now - session.lastActivity);

        // Check timeout
        if (idleTime.count() > static_cast<int64_t>(m_config.sessionTimeoutSeconds)) {
            return false;
        }

        return true;
    }

    void TouchSession(const std::string& token) {
        std::unique_lock lock(m_sessionMutex);
        auto it = m_sessions.find(token);
        if (it != m_sessions.end()) {
            it->second.lastActivity = std::chrono::steady_clock::now();
            it->second.requestCount++;
        }
    }

    [[nodiscard]] std::string GetSessionCsrfToken(const std::string& token) const {
        std::shared_lock lock(m_sessionMutex);
        auto it = m_sessions.find(token);
        if (it == m_sessions.end()) return {};
        return it->second.csrfToken;
    }

    // Remove sessions that have exceeded the configured idle timeout.
    // Caller MUST hold m_sessionMutex exclusively.
    void PruneExpiredSessionsLocked() {
        const auto now = std::chrono::steady_clock::now();
        const auto timeout = std::chrono::seconds(m_config.sessionTimeoutSeconds);
        size_t removed = 0;
        for (auto it = m_sessions.begin(); it != m_sessions.end(); ) {
            if (now - it->second.lastActivity > timeout) {
                it = m_sessions.erase(it);
                ++removed;
            } else {
                ++it;
            }
        }
        if (removed > 0) {
            m_stats.activeSessions.store(m_sessions.size(),
                                         std::memory_order_relaxed);
            SS_LOG_INFO(LOG_CAT, L"Pruned %zu expired session(s)", removed);
        }
    }

    // ========================================================================
    // AUTHENTICATION HELPERS
    // ========================================================================

    [[nodiscard]] bool ValidateCredentials(const std::string& password) const {
        // The dashboard credential is provisioned out-of-band (installer or
        // CLI) by writing "api.dashboard.password_hash" via ConfigManager.
        // Allowing the first /auth/login request to *set* the password — as
        // an earlier revision did — exposes a trivial squatting bypass for
        // any local user able to reach the loopback port before the operator.
        // We therefore refuse all logins until the hash is provisioned.
        auto& cm = Config::ConfigManager::Instance();
        if (!cm.IsInitialized()) {
            SS_LOG_ERROR(LOG_CAT,
                L"Cannot validate credentials — ConfigManager not initialized");
            return false;
        }

        if (password.empty()) {
            return false;
        }

        // Cap to defeat absurdly large password DoS (PBKDF2 cost scales).
        constexpr size_t MAX_PASSWORD_BYTES = 1024;
        if (password.size() > MAX_PASSWORD_BYTES) {
            SS_LOG_WARN(LOG_CAT,
                L"Login rejected: password exceeds %zu bytes", MAX_PASSWORD_BYTES);
            return false;
        }

        const auto storedHash = cm.GetValue<std::string>(
            "api.dashboard.password_hash", "");

        if (storedHash.empty()) {
            SS_LOG_ERROR(LOG_CAT,
                L"Dashboard password is not provisioned — refusing login. "
                L"Set 'api.dashboard.password_hash' (pbkdf2$<iter>$<hex_salt>$<hex_key>) "
                L"via the ShadowStrike CLI before starting the REST server.");
            return false;
        }

        // Only PBKDF2 hashes are accepted. Legacy bare-SHA-256 hashes from
        // earlier builds must be re-provisioned; we never accept them.
        if (storedHash.size() < PBKDF2_PREFIX.size() ||
            storedHash.compare(0, PBKDF2_PREFIX.size(), PBKDF2_PREFIX) != 0) {
            SS_LOG_ERROR(LOG_CAT,
                L"Dashboard password hash uses an unsupported format — "
                L"only PBKDF2 ('pbkdf2$<iter>$<hex_salt>$<hex_key>') is accepted. "
                L"Re-provision the password hash to enable logins.");
            return false;
        }

        // Parse "pbkdf2$<iter>$<hex_salt>$<hex_key>"
        std::string_view body{storedHash};
        body.remove_prefix(PBKDF2_PREFIX.size());

        const auto iterEnd = body.find('$');
        if (iterEnd == std::string_view::npos) return false;
        const auto iterStr = body.substr(0, iterEnd);
        body.remove_prefix(iterEnd + 1);

        const auto saltEnd = body.find('$');
        if (saltEnd == std::string_view::npos) return false;
        const auto saltHex = body.substr(0, saltEnd);
        const auto keyHex  = body.substr(saltEnd + 1);

        uint32_t iterations = 0;
        {
            auto [ptr, ec] = std::from_chars(iterStr.data(),
                                             iterStr.data() + iterStr.size(),
                                             iterations, 10);
            if (ec != std::errc{} || ptr != iterStr.data() + iterStr.size()) {
                SS_LOG_ERROR(LOG_CAT, L"Dashboard password hash: malformed iteration count");
                return false;
            }
        }
        // OWASP minimum, with a small fudge factor matching KDFParams::IsValid.
        if (iterations < (Utils::CryptoUtils::MIN_PBKDF2_ITERATIONS / 10)) {
            SS_LOG_ERROR(LOG_CAT,
                L"Dashboard password hash: iteration count %u below safe minimum",
                iterations);
            return false;
        }

        std::vector<uint8_t> salt;
        std::vector<uint8_t> expectedKey;
        if (!Utils::HashUtils::FromHex(saltHex, salt) ||
            !Utils::HashUtils::FromHex(keyHex, expectedKey)) {
            SS_LOG_ERROR(LOG_CAT, L"Dashboard password hash: malformed hex payload");
            return false;
        }
        if (salt.empty() || expectedKey.empty() ||
            expectedKey.size() != PBKDF2_KEY_BYTES) {
            SS_LOG_ERROR(LOG_CAT, L"Dashboard password hash: unexpected component sizes");
            return false;
        }

        Utils::CryptoUtils::KDFParams params;
        params.algorithm  = Utils::CryptoUtils::KDFAlgorithm::PBKDF2_SHA256;
        params.iterations = iterations;
        params.keyLength  = expectedKey.size();
        params.salt       = std::move(salt);

        std::vector<uint8_t> derived;
        if (!Utils::CryptoUtils::KeyDerivation::DeriveKey(password, params, derived)) {
            SS_LOG_ERROR(LOG_CAT, L"PBKDF2 derivation failed during credential validation");
            return false;
        }

        // Constant-time comparison of raw bytes.
        if (derived.size() != expectedKey.size()) {
            return false;
        }
        volatile uint8_t diff = 0;
        for (size_t i = 0; i < derived.size(); ++i) {
            diff |= static_cast<uint8_t>(derived[i] ^ expectedKey[i]);
        }
        return diff == 0;
    }

    // ========================================================================
    // UTILITY HELPERS
    // ========================================================================

    [[nodiscard]] bool ParseJsonBody(const Http::HttpRequest& req,
                                     nlohmann::json& out,
                                     Http::HttpResponse& res) {
        // Validate Content-Type
        const auto ct = req.GetContentType();
        if (ct.has_value()) {
            const auto ctStr = std::string(ct.value());
            if (ctStr.find("application/json") == std::string::npos) {
                res = Http::HttpResponse::MakeError(
                    Http::HttpStatus::UnsupportedMedia,
                    "Content-Type must be application/json");
                return false;
            }
        }

        if (req.body.empty()) {
            res = Http::HttpResponse::MakeError(
                Http::HttpStatus::BadRequest,
                "Request body is empty");
            return false;
        }

        // Cap body size (redundant with HttpServer limits, but defense-in-depth)
        if (req.body.size() > m_config.maxRequestBodySize) {
            res = Http::HttpResponse::MakeError(
                Http::HttpStatus::PayloadTooLarge,
                "Request body exceeds maximum size");
            return false;
        }

        const std::string_view bodyStr = req.GetBodyString();

        out = nlohmann::json::parse(bodyStr, nullptr, false);
        if (out.is_discarded()) {
            res = Http::HttpResponse::MakeError(
                Http::HttpStatus::BadRequest,
                "Malformed JSON in request body");
            m_stats.failedRequests.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        // JSON depth check (prevent stack overflow via deeply nested objects)
        if (GetJsonDepth(out) > MAX_REQUEST_JSON_DEPTH) {
            res = Http::HttpResponse::MakeError(
                Http::HttpStatus::BadRequest,
                "JSON exceeds maximum nesting depth");
            return false;
        }

        return true;
    }

    [[nodiscard]] static size_t GetJsonDepth(const nlohmann::json& j, size_t current = 0) noexcept {
        if (current > MAX_REQUEST_JSON_DEPTH) return current; // early exit

        size_t maxDepth = current;

        if (j.is_object()) {
            for (const auto& [key, val] : j.items()) {
                const auto childDepth = GetJsonDepth(val, current + 1);
                maxDepth = std::max(maxDepth, childDepth);
                if (maxDepth > MAX_REQUEST_JSON_DEPTH) return maxDepth;
            }
        } else if (j.is_array()) {
            for (const auto& elem : j) {
                const auto childDepth = GetJsonDepth(elem, current + 1);
                maxDepth = std::max(maxDepth, childDepth);
                if (maxDepth > MAX_REQUEST_JSON_DEPTH) return maxDepth;
            }
        }

        return maxDepth;
    }

    [[nodiscard]] static std::string ExtractBearerToken(const Http::HttpRequest& req) {
        const auto authHeader = req.GetHeader("Authorization");
        if (!authHeader.has_value()) return {};

        constexpr std::string_view BEARER = "Bearer ";
        const auto val = authHeader.value();
        if (val.size() <= BEARER.size() || val.substr(0, BEARER.size()) != BEARER) {
            return {};
        }

        return std::string(val.substr(BEARER.size()));
    }

    [[nodiscard]] std::string GenerateRequestId() const {
        uint64_t id = 0;
        Utils::CryptoUtils::SecureRandom rng;
        id = rng.NextUInt64();

        // Format as 16-char hex
        std::array<char, 17> buf{};
        std::snprintf(buf.data(), buf.size(), "%016llx", id);
        return std::string(buf.data(), 16);
    }

    [[nodiscard]] static bool ConstantTimeCompare(
        const std::string& a, const std::string& b) noexcept {
        if (a.size() != b.size()) return false;

        volatile uint8_t diff = 0;
        for (size_t i = 0; i < a.size(); ++i) {
            diff |= static_cast<uint8_t>(a[i]) ^ static_cast<uint8_t>(b[i]);
        }
        return diff == 0;
    }

    // ========================================================================
    // MEMBER DATA
    // ========================================================================

    std::unique_ptr<Http::HttpServer>   m_httpServer;
    mutable std::shared_mutex           m_httpServerMutex;
    std::unique_ptr<RateLimiter>        m_generalLimiter;
    std::unique_ptr<RateLimiter>        m_authLimiter;

    RESTServerConfig                    m_config;
    mutable std::shared_mutex           m_configMutex;

    std::unordered_map<std::string, Session> m_sessions;
    mutable std::shared_mutex           m_sessionMutex;

    std::atomic<ServerState>            m_state{ServerState::Stopped};
    bool                                m_initialized{false};

    RESTServerStatistics                m_stats;
};

// ============================================================================
// RESTServerStatistics IMPLEMENTATION
// ============================================================================

RESTServerStatistics::Snapshot RESTServerStatistics::TakeSnapshot() const noexcept {
    Snapshot s;
    s.totalRequests     = totalRequests.load(std::memory_order_relaxed);
    s.successfulRequests = successfulRequests.load(std::memory_order_relaxed);
    s.failedRequests    = failedRequests.load(std::memory_order_relaxed);
    s.rejectedRequests  = rejectedRequests.load(std::memory_order_relaxed);
    s.authFailures      = authFailures.load(std::memory_order_relaxed);
    s.rateLimitHits     = rateLimitHits.load(std::memory_order_relaxed);
    s.activeSessions    = activeSessions.load(std::memory_order_relaxed);
    s.bytesReceived     = bytesReceived.load(std::memory_order_relaxed);
    s.bytesSent         = bytesSent.load(std::memory_order_relaxed);
    s.startTime         = startTime;
    s.uptime            = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    return s;
}

void RESTServerStatistics::Reset() noexcept {
    totalRequests.store(0, std::memory_order_relaxed);
    successfulRequests.store(0, std::memory_order_relaxed);
    failedRequests.store(0, std::memory_order_relaxed);
    rejectedRequests.store(0, std::memory_order_relaxed);
    authFailures.store(0, std::memory_order_relaxed);
    rateLimitHits.store(0, std::memory_order_relaxed);
    activeSessions.store(0, std::memory_order_relaxed);
    bytesReceived.store(0, std::memory_order_relaxed);
    bytesSent.store(0, std::memory_order_relaxed);
    startTime = std::chrono::steady_clock::now();
}

// ============================================================================
// RESTServerConfig VALIDATION
// ============================================================================

bool RESTServerConfig::IsValid() const noexcept {
    // Bind address must be a numeric loopback literal — DNS resolution of
    // "localhost" can be hijacked via the hosts file or NRPT and is therefore
    // disallowed even though it would normally resolve to a loopback address.
    if (bindAddress != "127.0.0.1" && bindAddress != "::1") {
        return false;
    }

    // Port must be non-zero
    if (port == 0) return false;

    // Body size must be sane (1 KB to 16 MB)
    if (maxRequestBodySize < 1024 || maxRequestBodySize > 16ULL * 1024 * 1024) {
        return false;
    }

    // Connection limits
    if (maxConnections == 0 || maxConnections > 1024) return false;

    // Session timeout: 1 minute to 24 hours
    if (sessionTimeoutSeconds < 60 || sessionTimeoutSeconds > 86400) return false;

    // Session count limits
    if (maxSessions == 0 || maxSessions > 256) return false;

    // Rate limits: minimum 1/sec, maximum 1000/sec
    if (rateLimitPerSecond < 1 || rateLimitPerSecond > 1000) return false;
    if (rateLimitBurst < rateLimitPerSecond) return false;

    // TLS: if enabled, cert and key paths must be set
    if (enableTLS) {
        if (tlsCertPath.empty() || tlsKeyPath.empty()) return false;
    }

    return true;
}

// ============================================================================
// REST SERVER SINGLETON + FORWARDING
// ============================================================================

std::atomic<bool> RESTServer::s_instanceCreated{false};

RESTServer::RESTServer()
    : m_impl(std::make_unique<RESTServerImpl>()) {
}

RESTServer::~RESTServer() = default;

RESTServer& RESTServer::Instance() noexcept {
    static RESTServer instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

bool RESTServer::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

bool RESTServer::Initialize(const RESTServerConfig& config) {
    return m_impl->Initialize(config);
}

bool RESTServer::Start() {
    return m_impl->Start();
}

void RESTServer::Stop() {
    m_impl->Stop();
}

void RESTServer::Shutdown() {
    m_impl->Shutdown();
}

bool RESTServer::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

bool RESTServer::IsRunning() const noexcept {
    return m_impl->IsRunning();
}

ServerState RESTServer::GetState() const noexcept {
    return m_impl->GetState();
}

uint16_t RESTServer::GetPort() const noexcept {
    return m_impl->GetPort();
}

std::string RESTServer::GetBindAddress() const noexcept {
    return m_impl->GetBindAddress();
}

bool RESTServer::UpdateConfiguration(const RESTServerConfig& config) {
    return m_impl->UpdateConfiguration(config);
}

RESTServerConfig RESTServer::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

RESTServerStatistics::Snapshot RESTServer::GetStatistics() const noexcept {
    return m_impl->GetStatistics();
}

void RESTServer::ResetStatistics() noexcept {
    m_impl->ResetStatistics();
}

void RESTServer::BroadcastEvent(SSEEventType type, std::string_view jsonData) {
    m_impl->BroadcastEvent(type, jsonData);
}

size_t RESTServer::GetSSEClientCount() const noexcept {
    return m_impl->GetSSEClientCount();
}

bool RESTServer::RegisterGetRoute(std::string_view path, RouteHandler handler) {
    return m_impl->RegisterGetRoute(path, std::move(handler));
}

bool RESTServer::RegisterPostRoute(std::string_view path, RouteHandler handler) {
    return m_impl->RegisterPostRoute(path, std::move(handler));
}

void RESTServer::InvalidateAllSessions() {
    m_impl->InvalidateAllSessions();
}

size_t RESTServer::GetActiveSessionCount() const noexcept {
    return m_impl->GetActiveSessionCount();
}

} // namespace API
} // namespace ShadowStrike
