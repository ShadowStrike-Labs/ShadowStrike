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
 * ShadowStrike NGAV - COOKIE MANAGER IMPLEMENTATION
 * ============================================================================
 *
 * @file CookieManager.cpp
 * @brief Enterprise-grade HTTP cookie management implementation
 *
 * Provides comprehensive cookie management including enumeration, filtering,
 * tracking protection, supercookie detection, and secure deletion across
 * all major browsers.
 *
 * ARCHITECTURE:
 * =============
 * - PIMPL pattern for ABI stability
 * - Meyers' Singleton for thread-safe instance management
 * - std::shared_mutex for concurrent read access
 * - RAII for all resources (SQLite handles, file handles)
 * - Exception-safe with comprehensive error handling
 *
 * BROWSER DATABASE SUPPORT:
 * =========================
 * - Chrome/Chromium: SQLite3 Cookies database with DPAPI encryption
 * - Firefox: SQLite3 cookies.sqlite
 * - Edge: Chromium-based (same as Chrome)
 * - Opera/Brave/Vivaldi: Chromium-based
 * - IE: Registry-based (legacy)
 *
 * SUPERCOOKIE DETECTION:
 * ======================
 * - Flash LSO: %APPDATA%\Macromedia\Flash Player\#SharedObjects
 * - HTML5 LocalStorage: Browser profile\Local Storage
 * - IndexedDB: Browser profile\IndexedDB
 * - ETags: HTTP cache analysis
 *
 * PERFORMANCE:
 * ============
 * - Lazy database loading
 * - Cached tracker patterns
 * - Batch cookie operations
 * - Minimal memory footprint
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "pch.h"
#include "CookieManager.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/JSONUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/SystemUtils.hpp"

#include <algorithm>
#include <execution>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <regex>

// SQLite for browser database access
#include <SQLiteCpp/sqlite3.h>
#pragma comment(lib, "sqlite3.lib")

// Ensure SHGetFolderPathW / CSIDL_* are available (needed by Common.hpp helpers)
#include <shlobj.h>

// Third-party JSON library
#ifdef _MSC_VER
#  pragma warning(push)
#  pragma warning(disable: 4996)
#endif
#include <nlohmann/json.hpp>
#ifdef _MSC_VER
#  pragma warning(pop)
#endif

namespace ShadowStrike {
namespace Privacy {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace {
    template<typename T>
    [[nodiscard]] T AtomicValueLoadRelaxed(const T& value) noexcept {
        return std::atomic_ref<T>(const_cast<T&>(value)).load(std::memory_order_relaxed);
    }

    template<typename T>
    void AtomicValueStoreRelaxed(T& target, const T& value) noexcept {
        std::atomic_ref<T>(target).store(value, std::memory_order_relaxed);
    }

    /// @brief Chrome profile paths
    const std::vector<std::wstring> CHROME_PROFILES = {
        L"\\Google\\Chrome\\User Data\\Default",
        L"\\Google\\Chrome\\User Data\\Profile 1",
        L"\\Google\\Chrome\\User Data\\Profile 2",
        L"\\Chromium\\User Data\\Default"
    };

    /// @brief Firefox profile path pattern
    constexpr std::wstring_view FIREFOX_PROFILES = L"\\Mozilla\\Firefox\\Profiles";

    /// @brief Edge profile paths
    const std::vector<std::wstring> EDGE_PROFILES = {
        L"\\Microsoft\\Edge\\User Data\\Default",
        L"\\Microsoft\\Edge\\User Data\\Profile 1"
    };

    /// @brief Opera profile paths
    const std::vector<std::wstring> OPERA_PROFILES = {
        L"\\Opera Software\\Opera Stable",
        L"\\Opera Software\\Opera GX Stable"
    };

    /// @brief Brave profile paths
    const std::vector<std::wstring> BRAVE_PROFILES = {
        L"\\BraveSoftware\\Brave-Browser\\User Data\\Default"
    };

    /// @brief Known tracking domains
    const std::unordered_set<std::string> KNOWN_TRACKERS = {
        "doubleclick.net", "google-analytics.com", "googletagmanager.com",
        "facebook.com", "facebook.net", "fbcdn.net",
        "scorecardresearch.com", "quantserve.com", "chartbeat.com",
        "newrelic.com", "criteo.com", "adnxs.com",
        "rubiconproject.com", "pubmatic.com", "openx.net",
        "adsrvr.org", "casalemedia.com", "bluekai.com",
        "tapad.com", "exelator.com", "eyeota.net",
        "rlcdn.com", "krxd.net", "mathtag.com"
    };

    /// @brief Tracking cookie name patterns
    const std::vector<std::regex> TRACKING_PATTERNS = {
        std::regex("^_ga"),      // Google Analytics
        std::regex("^_gid"),     // Google Analytics
        std::regex("^__utm"),    // Google Analytics (legacy)
        std::regex("^_fbp"),     // Facebook Pixel
        std::regex("^fr$"),      // Facebook
        std::regex("^datr$"),    // Facebook
        std::regex("^IDE$"),     // DoubleClick
        std::regex("^test_cookie$"), // DoubleClick
        std::regex("^DSID$"),    // DoubleClick
        std::regex("^id$"),      // Generic tracking
        std::regex("^uid$"),     // Generic tracking
        std::regex("^uuid"),     // UUID tracking
        std::regex("^_kuid_")    // Krux
    };

    /// @brief Atomic counter for unique temp file names (thread-safe)
    std::atomic<uint64_t> s_tempFileCounter{0};

    /// @brief Generate a unique temp file path to avoid name collisions across threads
    [[nodiscard]] fs::path GenerateUniqueTempPath(const char* prefix) {
        auto counter = s_tempFileCounter.fetch_add(1, std::memory_order_relaxed);
        auto pid = ::GetCurrentProcessId();
        auto tid = ::GetCurrentThreadId();
        std::string name = std::string(prefix)
            + std::to_string(pid) + "_"
            + std::to_string(tid) + "_"
            + std::to_string(counter) + ".db";
        return fs::temp_directory_path() / name;
    }

    [[nodiscard]] fs::path NormalizePathForComparison(const fs::path& path) {
        std::error_code ec;
        fs::path normalized = fs::weakly_canonical(path, ec);
        if (ec) {
            ec.clear();
            normalized = path.lexically_normal();
        }
        return normalized;
    }

    [[nodiscard]] bool PathStartsWith(const fs::path& path, const fs::path& prefix) {
        auto normalizedPath = NormalizePathForComparison(path);
        auto normalizedPrefix = NormalizePathForComparison(prefix);
        auto [pathIt, prefixIt] = std::mismatch(
            normalizedPath.begin(), normalizedPath.end(),
            normalizedPrefix.begin(), normalizedPrefix.end());
        return prefixIt == normalizedPrefix.end();
    }

    [[nodiscard]] bool HasReparsePoint(const fs::path& path) noexcept {
#ifdef _WIN32
        const DWORD attributes = ::GetFileAttributesW(path.c_str());
        return attributes != INVALID_FILE_ATTRIBUTES &&
               (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
#else
        (void)path;
        return false;
#endif
    }

    [[nodiscard]] bool IsPathWithinUserBrowserRoots(const fs::path& path) {
        const fs::path localPath = GetKnownFolderSafe(CSIDL_LOCAL_APPDATA);
        const fs::path roamingPath = GetKnownFolderSafe(CSIDL_APPDATA);
        if (localPath.empty() || roamingPath.empty()) {
            return false;
        }
        return PathStartsWith(path, localPath) || PathStartsWith(path, roamingPath);
    }

    /// @brief RAII guard that deletes a temporary file on scope exit
    struct TempFileGuard {
        fs::path path;
        explicit TempFileGuard(fs::path p) : path(std::move(p)) {}
        ~TempFileGuard() {
            if (!path.empty()) {
                std::error_code ec;
                fs::remove(path, ec);
            }
        }
        TempFileGuard(const TempFileGuard&) = delete;
        TempFileGuard& operator=(const TempFileGuard&) = delete;
    };

    /// @brief RAII wrapper for sqlite3* — closes database on scope exit
    struct SqliteDbGuard {
        sqlite3* db = nullptr;
        explicit SqliteDbGuard(sqlite3* p) : db(p) {}
        ~SqliteDbGuard() { if (db) sqlite3_close(db); }
        SqliteDbGuard(const SqliteDbGuard&) = delete;
        SqliteDbGuard& operator=(const SqliteDbGuard&) = delete;
    };

    /// @brief RAII wrapper for sqlite3_stmt* — finalizes statement on scope exit
    struct SqliteStmtGuard {
        sqlite3_stmt* stmt = nullptr;
        explicit SqliteStmtGuard(sqlite3_stmt* p) : stmt(p) {}
        ~SqliteStmtGuard() { if (stmt) sqlite3_finalize(stmt); }
        SqliteStmtGuard(const SqliteStmtGuard&) = delete;
        SqliteStmtGuard& operator=(const SqliteStmtGuard&) = delete;
    };

}  // anonymous namespace

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

/**
 * @class CookieManagerImpl
 * @brief Implementation class for cookie manager (PIMPL pattern)
 */
class CookieManagerImpl final {
public:
    CookieManagerImpl() = default;
    ~CookieManagerImpl() = default;

    // Non-copyable, non-movable
    CookieManagerImpl(const CookieManagerImpl&) = delete;
    CookieManagerImpl& operator=(const CookieManagerImpl&) = delete;
    CookieManagerImpl(CookieManagerImpl&&) = delete;
    CookieManagerImpl& operator=(CookieManagerImpl&&) = delete;

    // ========================================================================
    // STATE
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    ModuleStatus m_status{ModuleStatus::Uninitialized};
    CookieConfiguration m_config;
    CookieStatistics m_stats;

    // Trackers
    std::unordered_map<std::string, TrackerInfo> m_trackers;
    mutable std::shared_mutex m_trackerMutex;

    // Whitelist
    std::unordered_map<std::string, CookieWhitelistEntry> m_whitelist;
    mutable std::shared_mutex m_whitelistMutex;

    // Callbacks
    std::vector<CookieCallback> m_cookieCallbacks;
    std::vector<SupercookieCallback> m_supercookieCallbacks;
    std::vector<PurgeCallback> m_purgeCallbacks;
    std::vector<ErrorCallback> m_errorCallbacks;
    mutable std::mutex m_callbackMutex;

    // Browser profile cache
    std::unordered_map<BrowserType, std::vector<fs::path>> m_browserProfiles;
    mutable std::shared_mutex m_profileMutex;

    // ========================================================================
    // HELPER METHODS
    // ========================================================================

    /**
     * @brief Check if module is in Running state (thread-safe).
     */
    [[nodiscard]] bool IsRunning() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_status == ModuleStatus::Running;
    }

    /**
     * @brief Fire cookie callback
     */
    void FireCookieCallback(const BrowserCookie& cookie) noexcept {
        try {
            std::lock_guard lock(m_callbackMutex);
            for (const auto& callback : m_cookieCallbacks) {
                if (callback) {
                    try {
                        callback(cookie);
                    } catch (...) {
                        Utils::Logger::Error("CookieManager: Cookie callback exception");
                    }
                }
            }
        } catch (...) {
        }
    }

    /**
     * @brief Fire supercookie callback
     */
    void FireSupercookieCallback(const Supercookie& supercookie) noexcept {
        try {
            std::lock_guard lock(m_callbackMutex);
            for (const auto& callback : m_supercookieCallbacks) {
                if (callback) {
                    try {
                        callback(supercookie);
                    } catch (...) {
                        Utils::Logger::Error("CookieManager: Supercookie callback exception");
                    }
                }
            }
        } catch (...) {
        }
    }

    /**
     * @brief Fire purge callback
     */
    void FirePurgeCallback(uint64_t purged, uint64_t bytes) noexcept {
        try {
            std::lock_guard lock(m_callbackMutex);
            for (const auto& callback : m_purgeCallbacks) {
                if (callback) {
                    try {
                        callback(purged, bytes);
                    } catch (...) {
                        Utils::Logger::Error("CookieManager: Purge callback exception");
                    }
                }
            }
        } catch (...) {
        }
    }

    /**
     * @brief Fire error callback
     */
    void FireErrorCallback(const std::string& message, int code) noexcept {
        try {
            std::lock_guard lock(m_callbackMutex);
            for (const auto& callback : m_errorCallbacks) {
                if (callback) {
                    try {
                        callback(message, code);
                    } catch (...) {
                        Utils::Logger::Error("CookieManager: Error callback exception");
                    }
                }
            }
        } catch (...) {
        }
    }

    /**
     * @brief Get browser profile paths
     */
    [[nodiscard]] std::vector<fs::path> GetBrowserProfiles(BrowserType browser) {
        std::vector<fs::path> profiles;

        try {
            // Check cache first
            {
                std::shared_lock lock(m_profileMutex);
                auto it = m_browserProfiles.find(browser);
                if (it != m_browserProfiles.end()) {
                    return it->second;
                }
            }

            // Get AppData paths using safe helper from Common.hpp
            fs::path localPath = GetKnownFolderSafe(CSIDL_LOCAL_APPDATA);
            fs::path roamingPath = GetKnownFolderSafe(CSIDL_APPDATA);

            if (localPath.empty() || roamingPath.empty()) {
                Utils::Logger::Error("CookieManager: Failed to resolve AppData folder paths");
                return profiles;
            }

            // Build profile paths based on browser
            std::vector<std::wstring> pathsToCheck;

            switch (browser) {
                case BrowserType::Chrome:
                case BrowserType::Chromium:
                    for (const auto& profile : CHROME_PROFILES) {
                        pathsToCheck.push_back(localPath.wstring() + profile);
                    }
                    break;

                case BrowserType::Firefox:
                    // Enumerate Firefox profiles
                    {
                        fs::path firefoxPath = roamingPath / L"Mozilla\\Firefox\\Profiles";
                        if (fs::exists(firefoxPath)) {
                            for (const auto& entry : fs::directory_iterator(firefoxPath)) {
                                if (entry.is_directory()) {
                                    pathsToCheck.push_back(entry.path().wstring());
                                }
                            }
                        }
                    }
                    break;

                case BrowserType::Edge:
                    for (const auto& profile : EDGE_PROFILES) {
                        pathsToCheck.push_back(localPath.wstring() + profile);
                    }
                    break;

                case BrowserType::Opera:
                    for (const auto& profile : OPERA_PROFILES) {
                        pathsToCheck.push_back(roamingPath.wstring() + profile);
                    }
                    break;

                case BrowserType::Brave:
                    for (const auto& profile : BRAVE_PROFILES) {
                        pathsToCheck.push_back(localPath.wstring() + profile);
                    }
                    break;

                default:
                    break;
            }

            // Verify paths exist and remain inside the expected AppData roots.
            for (const auto& pathStr : pathsToCheck) {
                fs::path p(pathStr);
                std::error_code ec;
                if (!fs::exists(p, ec) || ec) {
                    continue;
                }
                if (HasReparsePoint(p) || !IsPathWithinUserBrowserRoots(p)) {
                    Utils::Logger::Warn("CookieManager: Skipping untrusted browser profile path {}", p.string());
                    continue;
                }
                profiles.push_back(std::move(p));
            }

            // Cache the results
            {
                std::unique_lock lock(m_profileMutex);
                m_browserProfiles[browser] = profiles;
            }

        } catch (const std::exception& ex) {
            Utils::Logger::Error("CookieManager: Failed to get browser profiles: {}", ex.what());
        } catch (...) {
            Utils::Logger::Error("CookieManager: Failed to get browser profiles");
        }

        return profiles;
    }

    /**
     * @brief Read cookies from Chromium-based browser
     */
    [[nodiscard]] std::vector<BrowserCookie> ReadChromiumCookies(
        const fs::path& profilePath,
        BrowserType browser)
    {
        std::vector<BrowserCookie> cookies;

        try {
            fs::path cookieDbPath = profilePath / "Cookies";
            if (!fs::exists(cookieDbPath)) {
                cookieDbPath = profilePath / "Network" / "Cookies";
                if (!fs::exists(cookieDbPath)) {
                    return cookies;
                }
            }

            if (HasReparsePoint(profilePath) || HasReparsePoint(cookieDbPath) ||
                !IsPathWithinUserBrowserRoots(cookieDbPath)) {
                Utils::Logger::Warn("CookieManager: Refusing to read cookies from untrusted path {}",
                    cookieDbPath.string());
                return cookies;
            }

            // Copy database to temp (browser may have it locked)
            fs::path tempDb = GenerateUniqueTempPath("cookie_temp_");
            TempFileGuard tempGuard(tempDb);

            try {
                fs::copy_file(cookieDbPath, tempDb, fs::copy_options::overwrite_existing);
            } catch (const std::exception& ex) {
                Utils::Logger::Debug("CookieManager: Cookie DB locked or inaccessible: {}", ex.what());
                return cookies;
            }

            // Open SQLite database
            sqlite3* db = nullptr;
            if (sqlite3_open_v2(tempDb.string().c_str(), &db,
                                SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
                if (db) sqlite3_close(db);
                return cookies;
            }
            SqliteDbGuard dbGuard(db);

            // Query cookies
            const char* query =
                "SELECT host_key, name, value, path, expires_utc, is_secure, "
                "is_httponly, last_access_utc, has_expires, is_persistent, "
                "samesite, encrypted_value "
                "FROM cookies";

            sqlite3_stmt* stmt = nullptr;
            if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) {
                return cookies;
            }
            SqliteStmtGuard stmtGuard(stmt);

            // Process rows
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                BrowserCookie cookie;
                cookie.browser = browser;
                cookie.profile = profilePath.string();

                // Domain
                if (const char* domain = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0))) {
                    cookie.domain = domain;
                }

                // Name
                if (const char* name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1))) {
                    cookie.name = name;
                }

                // Value
                if (const char* value = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2))) {
                    cookie.value = value;
                }

                // Path
                if (const char* path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3))) {
                    cookie.path = path;
                }

                // Expiration (Chrome uses Windows epoch: microseconds since 1601-01-01)
                int64_t expiresUtc = sqlite3_column_int64(stmt, 4);
                if (expiresUtc > 0) {
                    // Convert Chrome time to Unix time
                    const int64_t CHROME_EPOCH_OFFSET = 11644473600LL * 1000000LL;
                    int64_t unixMicros = expiresUtc - CHROME_EPOCH_OFFSET;
                    cookie.expirationTime = std::chrono::system_clock::time_point(
                        std::chrono::microseconds(unixMicros));
                }

                // Flags
                cookie.isSecure = sqlite3_column_int(stmt, 5) != 0;
                cookie.isHttpOnly = sqlite3_column_int(stmt, 6) != 0;

                // Last access
                int64_t lastAccessUtc = sqlite3_column_int64(stmt, 7);
                if (lastAccessUtc > 0) {
                    const int64_t CHROME_EPOCH_OFFSET = 11644473600LL * 1000000LL;
                    int64_t unixMicros = lastAccessUtc - CHROME_EPOCH_OFFSET;
                    cookie.lastAccessTime = std::chrono::system_clock::time_point(
                        std::chrono::microseconds(unixMicros));
                }

                // Session/Persistent
                cookie.isSession = sqlite3_column_int(stmt, 8) == 0;
                cookie.isPersistent = sqlite3_column_int(stmt, 9) != 0;

                // SameSite
                int sameSite = sqlite3_column_int(stmt, 10);
                switch (sameSite) {
                    case 0: cookie.sameSite = SameSitePolicy::None; break;
                    case 1: cookie.sameSite = SameSitePolicy::Lax; break;
                    case 2: cookie.sameSite = SameSitePolicy::Strict; break;
                    default: cookie.sameSite = SameSitePolicy::Unset; break;
                }

                // Encrypted value
                int encryptedLen = sqlite3_column_bytes(stmt, 11);
                if (encryptedLen > 0) {
                    cookie.isEncrypted = true;
                }

                // Size
                cookie.sizeBytes = cookie.name.size() + cookie.value.size() +
                                  cookie.domain.size() + cookie.path.size();

                // Categorize
                cookie.category = CategorizeCookieInternal(cookie);
                cookie.isTracking = IsTrackingCookieInternal(cookie);
                cookie.scope = DetermineScope(cookie);

                cookies.push_back(cookie);

                if (cookies.size() >= CookieConstants::MAX_COOKIES) {
                    break;
                }
            }

            // TempFileGuard handles cleanup automatically

            Utils::Logger::Debug("CookieManager: Read {} cookies from Chromium profile",
                                cookies.size());

        } catch (const std::exception& ex) {
            Utils::Logger::Error("CookieManager: Failed to read Chromium cookies: {}", ex.what());
        } catch (...) {
            Utils::Logger::Error("CookieManager: Failed to read Chromium cookies");
        }

        return cookies;
    }

    /**
     * @brief Read cookies from Firefox
     */
    [[nodiscard]] std::vector<BrowserCookie> ReadFirefoxCookies(const fs::path& profilePath) {
        std::vector<BrowserCookie> cookies;

        try {
            fs::path cookieDbPath = profilePath / "cookies.sqlite";
            if (!fs::exists(cookieDbPath)) {
                return cookies;
            }

            if (HasReparsePoint(profilePath) || HasReparsePoint(cookieDbPath) ||
                !IsPathWithinUserBrowserRoots(cookieDbPath)) {
                Utils::Logger::Warn("CookieManager: Refusing to read Firefox cookies from untrusted path {}",
                    cookieDbPath.string());
                return cookies;
            }

            // Copy to temp (browser may have it locked)
            fs::path tempDb = GenerateUniqueTempPath("ff_cookie_temp_");
            TempFileGuard tempGuard(tempDb);

            try {
                fs::copy_file(cookieDbPath, tempDb, fs::copy_options::overwrite_existing);
            } catch (const std::exception& ex) {
                Utils::Logger::Debug("CookieManager: Firefox cookie DB locked or inaccessible: {}", ex.what());
                return cookies;
            }

            // Open database (read-only for enumeration)
            sqlite3* db = nullptr;
            if (sqlite3_open_v2(tempDb.string().c_str(), &db,
                                SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
                if (db) sqlite3_close(db);
                return cookies;
            }
            SqliteDbGuard dbGuard(db);

            // Query
            const char* query =
                "SELECT host, name, value, path, expiry, isSecure, "
                "isHttpOnly, sameSite, creationTime, lastAccessed "
                "FROM moz_cookies";

            sqlite3_stmt* stmt = nullptr;
            if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) {
                return cookies;
            }
            SqliteStmtGuard stmtGuard(stmt);

            while (sqlite3_step(stmt) == SQLITE_ROW) {
                BrowserCookie cookie;
                cookie.browser = BrowserType::Firefox;
                cookie.profile = profilePath.string();

                // Domain
                if (const char* host = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0))) {
                    cookie.domain = host;
                }

                // Name
                if (const char* name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1))) {
                    cookie.name = name;
                }

                // Value
                if (const char* value = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2))) {
                    cookie.value = value;
                }

                // Path
                if (const char* path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3))) {
                    cookie.path = path;
                }

                // Expiration (Unix timestamp)
                int64_t expiry = sqlite3_column_int64(stmt, 4);
                if (expiry > 0) {
                    cookie.expirationTime = std::chrono::system_clock::time_point(
                        std::chrono::seconds(expiry));
                }

                cookie.isSecure = sqlite3_column_int(stmt, 5) != 0;
                cookie.isHttpOnly = sqlite3_column_int(stmt, 6) != 0;

                int sameSite = sqlite3_column_int(stmt, 7);
                switch (sameSite) {
                    case 0: cookie.sameSite = SameSitePolicy::None; break;
                    case 1: cookie.sameSite = SameSitePolicy::Lax; break;
                    case 2: cookie.sameSite = SameSitePolicy::Strict; break;
                    default: cookie.sameSite = SameSitePolicy::Unset; break;
                }

                // Creation time (microseconds)
                int64_t creationTime = sqlite3_column_int64(stmt, 8);
                if (creationTime > 0) {
                    cookie.creationTime = std::chrono::system_clock::time_point(
                        std::chrono::microseconds(creationTime));
                }

                // Last accessed (microseconds)
                int64_t lastAccessed = sqlite3_column_int64(stmt, 9);
                if (lastAccessed > 0) {
                    cookie.lastAccessTime = std::chrono::system_clock::time_point(
                        std::chrono::microseconds(lastAccessed));
                }

                cookie.isSession = (expiry == 0);
                cookie.isPersistent = (expiry != 0);

                cookie.sizeBytes = cookie.name.size() + cookie.value.size() +
                                  cookie.domain.size() + cookie.path.size();

                cookie.category = CategorizeCookieInternal(cookie);
                cookie.isTracking = IsTrackingCookieInternal(cookie);
                cookie.scope = DetermineScope(cookie);

                cookies.push_back(cookie);

                if (cookies.size() >= CookieConstants::MAX_COOKIES) {
                    break;
                }
            }

            // TempFileGuard handles cleanup automatically

            Utils::Logger::Debug("CookieManager: Read {} cookies from Firefox profile",
                                cookies.size());

        } catch (const std::exception& ex) {
            Utils::Logger::Error("CookieManager: Failed to read Firefox cookies: {}", ex.what());
        } catch (...) {
            Utils::Logger::Error("CookieManager: Failed to read Firefox cookies");
        }

        return cookies;
    }

    /**
     * @brief Categorize cookie
     */
    [[nodiscard]] CookieCategory CategorizeCookieInternal(const BrowserCookie& cookie) const noexcept {
        try {
            // Check if tracking
            if (IsTrackingCookieInternal(cookie)) {
                // Check specific categories
                std::string lowerDomain = cookie.domain;
                std::transform(lowerDomain.begin(), lowerDomain.end(), lowerDomain.begin(), ::tolower);

                if (lowerDomain.find("facebook") != std::string::npos ||
                    lowerDomain.find("twitter") != std::string::npos ||
                    lowerDomain.find("linkedin") != std::string::npos) {
                    return CookieCategory::Social;
                }

                if (lowerDomain.find("doubleclick") != std::string::npos ||
                    lowerDomain.find("adnxs") != std::string::npos ||
                    lowerDomain.find("criteo") != std::string::npos) {
                    return CookieCategory::Advertising;
                }

                if (lowerDomain.find("analytics") != std::string::npos ||
                    lowerDomain.find("chartbeat") != std::string::npos) {
                    return CookieCategory::Analytics;
                }

                return CookieCategory::Tracking;
            }

            // Check essential
            std::string lowerName = cookie.name;
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

            if (lowerName.find("session") != std::string::npos ||
                lowerName.find("csrf") != std::string::npos ||
                lowerName.find("xsrf") != std::string::npos ||
                lowerName.find("auth") != std::string::npos ||
                lowerName.find("login") != std::string::npos) {
                return CookieCategory::Essential;
            }

            // Check functional
            if (lowerName.find("lang") != std::string::npos ||
                lowerName.find("theme") != std::string::npos ||
                lowerName.find("pref") != std::string::npos ||
                lowerName.find("settings") != std::string::npos) {
                return CookieCategory::Functional;
            }

            return CookieCategory::Unknown;

        } catch (...) {
            return CookieCategory::Unknown;
        }
    }

    /**
     * @brief Check if cookie is tracking cookie
     */
    [[nodiscard]] bool IsTrackingCookieInternal(const BrowserCookie& cookie) const noexcept {
        try {
            // Check domain against known trackers
            std::string baseDomain = GetBaseDomain(cookie.domain);

            std::shared_lock lock(m_trackerMutex);

            // Check built-in list
            if (KNOWN_TRACKERS.count(baseDomain) > 0) {
                return true;
            }

            // Check custom trackers
            for (const auto& [id, tracker] : m_trackers) {
                if (!tracker.isActive) continue;

                // Check domain pattern
                if (!tracker.domainPattern.empty()) {
                    if (cookie.domain.find(tracker.domainPattern) != std::string::npos) {
                        return true;
                    }
                }

                // Check cookie name pattern
                if (!tracker.cookiePattern.empty()) {
                    if (cookie.name.find(tracker.cookiePattern) != std::string::npos) {
                        return true;
                    }
                }
            }

            // Check name patterns
            for (const auto& pattern : TRACKING_PATTERNS) {
                if (std::regex_search(cookie.name, pattern)) {
                    return true;
                }
            }

            return false;

        } catch (...) {
            return false;
        }
    }

    /**
     * @brief Determine cookie scope
     */
    [[nodiscard]] CookieScope DetermineScope(const BrowserCookie& cookie) const noexcept {
        try {
            // Third-party if domain doesn't match typical first-party patterns
            std::string domain = cookie.domain;
            if (domain.empty()) {
                return CookieScope::FirstParty;
            }

            // Remove leading dot
            if (domain[0] == '.') {
                domain = domain.substr(1);
            }

            // Known third-party indicators
            if (KNOWN_TRACKERS.count(domain) > 0) {
                return CookieScope::ThirdParty;
            }

            // Check if cross-site tracking
            if (cookie.sameSite == SameSitePolicy::None && !cookie.isSecure) {
                return CookieScope::CrossSite;
            }

            return CookieScope::FirstParty;

        } catch (...) {
            return CookieScope::FirstParty;
        }
    }

    /**
     * @brief Check if domain is whitelisted
     */
    [[nodiscard]] bool IsWhitelistedInternal(const std::string& domain) const noexcept {
        try {
            std::shared_lock lock(m_whitelistMutex);

            for (const auto& [id, entry] : m_whitelist) {
                if (!entry.enabled) continue;

                if (entry.domainPattern.find('*') != std::string::npos ||
                    entry.domainPattern.find('?') != std::string::npos) {
                    // Glob pattern — use safe conversion from Common.hpp
                    try {
                        std::string regexStr = GlobToRegex(entry.domainPattern);
                        std::regex re(regexStr, std::regex_constants::icase);
                        if (std::regex_match(domain, re)) {
                            return true;
                        }
                    } catch (const std::regex_error&) {
                        // Malformed pattern — skip silently
                        continue;
                    }
                } else {
                    // Exact domain-suffix match (case-insensitive)
                    std::string lowerDomain = domain;
                    std::string lowerPattern = entry.domainPattern;
                    std::transform(lowerDomain.begin(), lowerDomain.end(),
                                   lowerDomain.begin(), ::tolower);
                    std::transform(lowerPattern.begin(), lowerPattern.end(),
                                   lowerPattern.begin(), ::tolower);

                    if (lowerDomain == lowerPattern ||
                        (lowerDomain.size() > lowerPattern.size() &&
                         lowerDomain.ends_with(lowerPattern) &&
                         lowerDomain[lowerDomain.size() - lowerPattern.size() - 1] == '.')) {
                        return true;
                    }
                }
            }

            return false;

        } catch (...) {
            return false;
        }
    }
};

// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

std::atomic<bool> CookieManager::s_instanceCreated{false};

CookieManager& CookieManager::Instance() noexcept {
    static CookieManager instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

bool CookieManager::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// LIFECYCLE
// ============================================================================

CookieManager::CookieManager()
    : m_impl(std::make_unique<CookieManagerImpl>())
{
    Utils::Logger::Info("CookieManager: Instance created");
}

CookieManager::~CookieManager() {
    try {
        Shutdown();
        Utils::Logger::Info("CookieManager: Instance destroyed");
    } catch (...) {
        // Destructors must not throw
    }
}

bool CookieManager::Initialize(const CookieConfiguration& config) {
    try {
        std::unique_lock lock(m_impl->m_mutex);

        if (m_impl->m_status != ModuleStatus::Uninitialized &&
            m_impl->m_status != ModuleStatus::Stopped) {
            Utils::Logger::Warn("CookieManager: Already initialized");
            return false;
        }

        // Validate configuration
        if (!config.IsValid()) {
            Utils::Logger::Error("CookieManager: Invalid configuration");
            return false;
        }

        m_impl->m_status = ModuleStatus::Initializing;
        m_impl->m_config = config;

        // Load tracker database if specified
        if (!config.trackerDatabasePath.empty() && fs::exists(config.trackerDatabasePath)) {
            ImportTrackerList(config.trackerDatabasePath);
        }

        // Load custom trackers
        for (const auto& tracker : config.customTrackers) {
            m_impl->m_trackers[tracker.trackerId] = tracker;
        }

        // Load whitelist
        for (const auto& entry : config.whitelist) {
            m_impl->m_whitelist[entry.entryId] = entry;
        }

        // Reset statistics
        m_impl->m_stats.Reset();
        AtomicValueStoreRelaxed(m_impl->m_stats.startTime, Clock::now());

        m_impl->m_status = ModuleStatus::Running;

        Utils::Logger::Info("CookieManager: Initialized successfully (v{})",
                           GetVersionString());

        return true;

    } catch (const std::exception& ex) {
        Utils::Logger::Error("CookieManager: Initialization failed: {}", ex.what());
        m_impl->m_status = ModuleStatus::Error;
        return false;
    } catch (...) {
        Utils::Logger::Error("CookieManager: Initialization failed (unknown exception)");
        m_impl->m_status = ModuleStatus::Error;
        return false;
    }
}

void CookieManager::Shutdown() {
    try {
        std::unique_lock lock(m_impl->m_mutex);

        if (m_impl->m_status == ModuleStatus::Uninitialized ||
            m_impl->m_status == ModuleStatus::Stopped) {
            return;
        }

        m_impl->m_status = ModuleStatus::Stopping;

        // Clear callbacks
        {
            std::lock_guard cbLock(m_impl->m_callbackMutex);
            m_impl->m_cookieCallbacks.clear();
            m_impl->m_supercookieCallbacks.clear();
            m_impl->m_purgeCallbacks.clear();
            m_impl->m_errorCallbacks.clear();
        }

        // Clear caches
        {
            std::unique_lock profileLock(m_impl->m_profileMutex);
            m_impl->m_browserProfiles.clear();
        }

        m_impl->m_status = ModuleStatus::Stopped;

        Utils::Logger::Info("CookieManager: Shutdown complete");

    } catch (const std::exception& ex) {
        Utils::Logger::Error("CookieManager: Shutdown error: {}", ex.what());
    } catch (...) {
        Utils::Logger::Error("CookieManager: Shutdown failed");
    }
}

bool CookieManager::IsInitialized() const noexcept {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_status == ModuleStatus::Running;
}

ModuleStatus CookieManager::GetStatus() const noexcept {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_status;
}

bool CookieManager::UpdateConfiguration(const CookieConfiguration& config) {
    try {
        if (!config.IsValid()) {
            Utils::Logger::Error("CookieManager: Invalid configuration");
            return false;
        }

        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_config = config;

        Utils::Logger::Info("CookieManager: Configuration updated");
        return true;

    } catch (const std::exception& ex) {
        Utils::Logger::Error("CookieManager: Config update failed: {}", ex.what());
        return false;
    } catch (...) {
        Utils::Logger::Error("CookieManager: Config update failed");
        return false;
    }
}

CookieConfiguration CookieManager::GetConfiguration() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_config;
}

// ============================================================================
// COOKIE ENUMERATION
// ============================================================================

std::vector<BrowserCookie> CookieManager::GetAllCookies() {
    std::vector<BrowserCookie> allCookies;

    try {
        // Chromium-based browsers
        for (auto browser : {BrowserType::Chrome, BrowserType::Edge, BrowserType::Opera,
                             BrowserType::Brave, BrowserType::Chromium}) {
            auto browserCookies = GetCookies(browser);
            allCookies.insert(allCookies.end(), browserCookies.begin(), browserCookies.end());
        }

        // Firefox
        auto firefoxCookies = GetCookies(BrowserType::Firefox);
        allCookies.insert(allCookies.end(), firefoxCookies.begin(), firefoxCookies.end());

        m_impl->m_stats.totalCookiesScanned += allCookies.size();

        Utils::Logger::Info("CookieManager: Enumerated {} total cookies", allCookies.size());

    } catch (const std::exception& ex) {
        Utils::Logger::Error("CookieManager: GetAllCookies failed: {}", ex.what());
    } catch (...) {
        Utils::Logger::Error("CookieManager: GetAllCookies failed");
    }

    return allCookies;
}

std::vector<BrowserCookie> CookieManager::GetCookies(BrowserType browser) {
    std::vector<BrowserCookie> cookies;

    try {
        if (!m_impl->IsRunning()) {
            Utils::Logger::Warn("CookieManager: GetCookies called while not running");
            return cookies;
        }

        auto profiles = m_impl->GetBrowserProfiles(browser);

        for (const auto& profile : profiles) {
            std::vector<BrowserCookie> profileCookies;

            if (browser == BrowserType::Firefox) {
                profileCookies = m_impl->ReadFirefoxCookies(profile);
            } else {
                // Chromium-based
                profileCookies = m_impl->ReadChromiumCookies(profile, browser);
            }

            cookies.insert(cookies.end(), profileCookies.begin(), profileCookies.end());
        }

        m_impl->m_stats.totalCookiesScanned += cookies.size();
        if (auto idx = BrowserTypeToIndex(browser)) {
            m_impl->m_stats.byBrowser[*idx] += cookies.size();
        }

        Utils::Logger::Debug("CookieManager: Found {} cookies for browser {}", 
                            cookies.size(), std::string(GetBrowserTypeName(browser)));

    } catch (const std::exception& ex) {
        Utils::Logger::Error("CookieManager: GetCookies failed: {}", ex.what());
    } catch (...) {
        Utils::Logger::Error("CookieManager: GetCookies failed");
    }

    return cookies;
}

std::vector<BrowserCookie> CookieManager::GetCookiesForDomain(const std::string& domain) {
    std::vector<BrowserCookie> result;

    try {
        std::string sanitized = SanitizeDomain(domain);
        if (sanitized.empty()) {
            Utils::Logger::Warn("CookieManager: GetCookiesForDomain rejected invalid domain input");
            return result;
        }

        auto allCookies = GetAllCookies();

        std::copy_if(allCookies.begin(), allCookies.end(), std::back_inserter(result),
            [&sanitized](const BrowserCookie& cookie) {
                std::string cookieDomain = SanitizeDomain(cookie.domain);
                return !cookieDomain.empty() &&
                       (cookieDomain == sanitized ||
                        (cookieDomain.size() > sanitized.size() &&
                         cookieDomain.ends_with(sanitized) &&
                         cookieDomain[cookieDomain.size() - sanitized.size() - 1] == '.'));
            });

        Utils::Logger::Debug("CookieManager: Found {} cookies for requested domain",
                            result.size());

    } catch (const std::exception& ex) {
        Utils::Logger::Error("CookieManager: GetCookiesForDomain failed: {}", ex.what());
    } catch (...) {
        Utils::Logger::Error("CookieManager: GetCookiesForDomain failed");
    }

    return result;
}

std::vector<BrowserCookie> CookieManager::GetTrackingCookies() {
    std::vector<BrowserCookie> result;

    try {
        auto allCookies = GetAllCookies();

        std::copy_if(allCookies.begin(), allCookies.end(), std::back_inserter(result),
            [](const BrowserCookie& cookie) {
                return cookie.isTracking;
            });

        Utils::Logger::Info("CookieManager: Found {} tracking cookies", result.size());

    } catch (const std::exception& ex) {
        Utils::Logger::Error("CookieManager: GetTrackingCookies failed: {}", ex.what());
    } catch (...) {
        Utils::Logger::Error("CookieManager: GetTrackingCookies failed");
    }

    return result;
}

std::vector<BrowserCookie> CookieManager::GetThirdPartyCookies() {
    std::vector<BrowserCookie> result;

    try {
        auto allCookies = GetAllCookies();

        std::copy_if(allCookies.begin(), allCookies.end(), std::back_inserter(result),
            [](const BrowserCookie& cookie) {
                return cookie.scope == CookieScope::ThirdParty ||
                       cookie.scope == CookieScope::CrossSite;
            });

        Utils::Logger::Info("CookieManager: Found {} third-party cookies", result.size());

    } catch (const std::exception& ex) {
        Utils::Logger::Error("CookieManager: GetThirdPartyCookies failed: {}", ex.what());
    } catch (...) {
        Utils::Logger::Error("CookieManager: GetThirdPartyCookies failed");
    }

    return result;
}

uint64_t CookieManager::GetCookieCount(BrowserType browser) {
    try {
        if (browser == BrowserType::All) {
            return GetAllCookies().size();
        } else {
            return GetCookies(browser).size();
        }
    } catch (...) {
        return 0;
    }
}

// ============================================================================
// SUPERCOOKIE DETECTION
// ============================================================================

std::vector<Supercookie> CookieManager::ScanForSupercookies() {
    std::vector<Supercookie> supercookies;

    try {
        if (!m_impl->IsRunning()) {
            Utils::Logger::Warn("CookieManager: ScanForSupercookies called while not running");
            return supercookies;
        }

        // Get AppData paths using safe helper from Common.hpp
        fs::path localAppData = GetKnownFolderSafe(CSIDL_LOCAL_APPDATA);
        fs::path roamingAppData = GetKnownFolderSafe(CSIDL_APPDATA);

        if (localAppData.empty() || roamingAppData.empty()) {
            Utils::Logger::Error("CookieManager: Failed to resolve AppData paths for supercookie scan");
            return supercookies;
        }

        constexpr auto dirOpts = fs::directory_options::skip_permission_denied;

        // Scan Flash LSO
        {
            fs::path flashPath = roamingAppData / L"Macromedia\\Flash Player\\#SharedObjects";
            if (fs::exists(flashPath)) {
                std::error_code ec;
                for (const auto& entry : fs::recursive_directory_iterator(flashPath, dirOpts, ec)) {
                    if (ec) break;
                    if (entry.is_regular_file() && entry.path().extension() == ".sol") {
                        Supercookie sc;
                        sc.type = SupercookieType::FlashLSO;
                        sc.storagePath = entry.path();
                        sc.sizeBytes = entry.file_size();
                        sc.creationTime = std::chrono::system_clock::now();
                        sc.isTracking = true;

                        supercookies.push_back(sc);
                        m_impl->FireSupercookieCallback(sc);
                    }
                }
            }
        }

        // Scan HTML5 LocalStorage (Chromium-based)
        for (auto browser : {BrowserType::Chrome, BrowserType::Edge, BrowserType::Opera}) {
            auto profiles = m_impl->GetBrowserProfiles(browser);
            for (const auto& profile : profiles) {
                fs::path localStoragePath = profile / "Local Storage" / "leveldb";
                if (fs::exists(localStoragePath)) {
                    std::error_code ec;
                    for (const auto& entry : fs::directory_iterator(localStoragePath, dirOpts, ec)) {
                        if (ec) break;
                        if (entry.is_regular_file()) {
                            Supercookie sc;
                            sc.type = SupercookieType::LocalStorage;
                            sc.browser = browser;
                            sc.storagePath = entry.path();
                            sc.sizeBytes = entry.file_size();
                            sc.creationTime = std::chrono::system_clock::now();

                            supercookies.push_back(sc);
                            m_impl->FireSupercookieCallback(sc);
                        }
                    }
                }
            }
        }

        // Scan IndexedDB
        for (auto browser : {BrowserType::Chrome, BrowserType::Edge, BrowserType::Opera}) {
            auto profiles = m_impl->GetBrowserProfiles(browser);
            for (const auto& profile : profiles) {
                fs::path indexedDBPath = profile / "IndexedDB";
                if (fs::exists(indexedDBPath)) {
                    std::error_code ec;
                    for (const auto& entry : fs::recursive_directory_iterator(indexedDBPath, dirOpts, ec)) {
                        if (ec) break;
                        if (entry.is_regular_file()) {
                            Supercookie sc;
                            sc.type = SupercookieType::IndexedDB;
                            sc.browser = browser;
                            sc.storagePath = entry.path();
                            sc.sizeBytes = entry.file_size();
                            sc.creationTime = std::chrono::system_clock::now();

                            supercookies.push_back(sc);
                            m_impl->FireSupercookieCallback(sc);
                        }
                    }
                }
            }
        }

        m_impl->m_stats.supercookiesFound += supercookies.size();

        Utils::Logger::Info("CookieManager: Found {} supercookies", supercookies.size());

    } catch (const std::exception& ex) {
        Utils::Logger::Error("CookieManager: ScanForSupercookies failed: {}", ex.what());
    } catch (...) {
        Utils::Logger::Error("CookieManager: ScanForSupercookies failed");
    }

    return supercookies;
}

std::vector<Supercookie> CookieManager::GetSupercookiesForDomain(const std::string& domain) {
    std::vector<Supercookie> result;

    try {
        std::string sanitized = SanitizeDomain(domain);
        if (sanitized.empty()) {
            Utils::Logger::Warn("CookieManager: GetSupercookiesForDomain rejected invalid domain");
            return result;
        }

        auto allSupercookies = ScanForSupercookies();

        std::copy_if(allSupercookies.begin(), allSupercookies.end(), std::back_inserter(result),
            [&sanitized](const Supercookie& sc) {
                return sc.domain.find(sanitized) != std::string::npos ||
                       sc.key.find(sanitized) != std::string::npos;
            });

    } catch (const std::exception& ex) {
        Utils::Logger::Error("CookieManager: GetSupercookiesForDomain failed: {}", ex.what());
    } catch (...) {
        Utils::Logger::Error("CookieManager: GetSupercookiesForDomain failed");
    }

    return result;
}

uint64_t CookieManager::DeleteSupercookies(const std::string& domain) {
    uint64_t deleted = 0;

    try {
        std::vector<Supercookie> supercookies;
        if (domain.empty()) {
            supercookies = ScanForSupercookies();
        } else {
            std::string sanitized = SanitizeDomain(domain);
            if (sanitized.empty()) {
                Utils::Logger::Warn("CookieManager: DeleteSupercookies rejected invalid domain");
                return 0;
            }
            supercookies = GetSupercookiesForDomain(sanitized);
        }

        for (const auto& sc : supercookies) {
            try {
                if (fs::exists(sc.storagePath)) {
                    if (fs::is_directory(sc.storagePath)) {
                        fs::remove_all(sc.storagePath);
                    } else {
                        fs::remove(sc.storagePath);
                    }
                    ++deleted;
                    m_impl->m_stats.bytesReclaimed += sc.sizeBytes;
                }
            } catch (...) {
                // Continue with next
            }
        }

        m_impl->m_stats.supercookiesDeleted += deleted;

        Utils::Logger::Info("CookieManager: Deleted {} supercookies", deleted);

    } catch (const std::exception& ex) {
        Utils::Logger::Error("CookieManager: DeleteSupercookies failed: {}", ex.what());
    } catch (...) {
        Utils::Logger::Error("CookieManager: DeleteSupercookies failed");
    }

    return deleted;
}

// ============================================================================
// TRACKING PROTECTION
// ============================================================================

uint64_t CookieManager::PurgeTrackers() {
    uint64_t purged = 0;
    uint64_t bytesReclaimed = 0;

    try {
        auto trackingCookies = GetTrackingCookies();

        for (const auto& cookie : trackingCookies) {
            if (DeleteCookie(cookie)) {
                ++purged;
                bytesReclaimed += cookie.sizeBytes;
            }
        }

        m_impl->m_stats.trackersBlocked += purged;
        m_impl->m_stats.bytesReclaimed += bytesReclaimed;

        m_impl->FirePurgeCallback(purged, bytesReclaimed);

        Utils::Logger::Info("CookieManager: Purged {} tracking cookies ({} bytes)",
                           purged, bytesReclaimed);

    } catch (const std::exception& ex) {
        Utils::Logger::Error("CookieManager: PurgeTrackers failed: {}", ex.what());
    } catch (...) {
        Utils::Logger::Error("CookieManager: PurgeTrackers failed");
    }

    return purged;
}

bool CookieManager::IsTrackerDomain(const std::string& domain) {
    try {
        std::string sanitized = SanitizeDomain(domain);
        if (sanitized.empty()) {
            return false;
        }

        std::string baseDomain = GetBaseDomain(sanitized);

        // Check built-in list
        if (KNOWN_TRACKERS.count(baseDomain) > 0) {
            return true;
        }

        // Check custom trackers
        std::shared_lock lock(m_impl->m_trackerMutex);
        for (const auto& [id, tracker] : m_impl->m_trackers) {
            if (!tracker.isActive) continue;

            if (!tracker.domainPattern.empty() &&
                sanitized.find(tracker.domainPattern) != std::string::npos) {
                return true;
            }
        }

        return false;

    } catch (...) {
        return false;
    }
}

bool CookieManager::IsTrackingCookie(const BrowserCookie& cookie) {
    return m_impl->IsTrackingCookieInternal(cookie);
}

std::vector<TrackerInfo> CookieManager::GetKnownTrackers() {
    std::vector<TrackerInfo> trackers;

    try {
        std::shared_lock lock(m_impl->m_trackerMutex);

        for (const auto& [id, tracker] : m_impl->m_trackers) {
            trackers.push_back(tracker);
        }

    } catch (const std::exception& ex) {
        Utils::Logger::Error("CookieManager: GetKnownTrackers failed: {}", ex.what());
    } catch (...) {
        Utils::Logger::Error("CookieManager: GetKnownTrackers failed");
    }

    return trackers;
}

bool CookieManager::AddTracker(const TrackerInfo& tracker) {
    try {
        std::unique_lock lock(m_impl->m_trackerMutex);

        m_impl->m_trackers[tracker.trackerId] = tracker;

        Utils::Logger::Info("CookieManager: Added tracker: {}", tracker.trackerId);
        return true;

    } catch (const std::exception& ex) {
        Utils::Logger::Error("CookieManager: AddTracker failed: {}", ex.what());
        return false;
    } catch (...) {
        Utils::Logger::Error("CookieManager: AddTracker failed");
        return false;
    }
}

bool CookieManager::RemoveTracker(const std::string& trackerId) {
    try {
        std::unique_lock lock(m_impl->m_trackerMutex);

        const bool removed = m_impl->m_trackers.erase(trackerId) > 0;

        if (removed) {
            Utils::Logger::Info("CookieManager: Removed tracker: {}", trackerId);
        }

        return removed;

    } catch (const std::exception& ex) {
        Utils::Logger::Error("CookieManager: RemoveTracker failed: {}", ex.what());
        return false;
    } catch (...) {
        Utils::Logger::Error("CookieManager: RemoveTracker failed");
        return false;
    }
}

bool CookieManager::ImportTrackerList(const fs::path& listPath) {
    try {
        if (!fs::exists(listPath)) {
            Utils::Logger::Error("CookieManager: Tracker list not found: {}", listPath.string());
            return false;
        }

        std::ifstream file(listPath);
        if (!file) {
            return false;
        }

        size_t imported = 0;
        std::string line;

        while (std::getline(file, line)) {
            // Skip comments and empty lines
            if (line.empty() || line[0] == '#' || line[0] == '!') {
                continue;
            }

            // Parse tracker entry (simple format: domain pattern)
            TrackerInfo tracker;
            tracker.trackerId = "IMPORTED-" + std::to_string(imported);
            tracker.domainPattern = line;
            tracker.category = CookieCategory::Tracking;
            tracker.isActive = true;

            AddTracker(tracker);
            ++imported;

            if (imported >= CookieConstants::MAX_TRACKER_LIST) {
                break;
            }
        }

        Utils::Logger::Info("CookieManager: Imported {} tracker patterns", imported);
        return true;

    } catch (const std::exception& ex) {
        Utils::Logger::Error("CookieManager: ImportTrackerList failed: {}", ex.what());
        return false;
    } catch (...) {
        Utils::Logger::Error("CookieManager: ImportTrackerList failed");
        return false;
    }
}

// ============================================================================
// COOKIE MANAGEMENT
// ============================================================================

bool CookieManager::DeleteCookie(const BrowserCookie& cookie) {
    try {
        if (!m_impl->IsRunning()) {
            Utils::Logger::Warn("CookieManager: DeleteCookie called while not running");
            return false;
        }

        if (cookie.domain.empty() || cookie.name.empty()) {
            Utils::Logger::Warn("CookieManager: DeleteCookie called with empty domain or name");
            return false;
        }

        if (cookie.profile.empty()) {
            Utils::Logger::Warn("CookieManager: DeleteCookie requires a profile path (cookie must come from enumeration)");
            return false;
        }

        // Determine the cookie database path based on browser type
        fs::path cookieDbPath;
        const char* deleteQuery = nullptr;

        if (cookie.browser == BrowserType::Firefox) {
            cookieDbPath = fs::path(cookie.profile) / "cookies.sqlite";
            deleteQuery = "DELETE FROM moz_cookies WHERE host = ?1 AND name = ?2 AND path = ?3";
        } else {
            // Chromium-based browsers
            cookieDbPath = fs::path(cookie.profile) / "Network" / "Cookies";
            if (!fs::exists(cookieDbPath)) {
                cookieDbPath = fs::path(cookie.profile) / "Cookies";
            }
            deleteQuery = "DELETE FROM cookies WHERE host_key = ?1 AND name = ?2 AND path = ?3";
        }

        if (!fs::exists(cookieDbPath)) {
            Utils::Logger::Warn("CookieManager: Cookie database not found for deletion: {}",
                               cookieDbPath.string());
            return false;
        }

        if (HasReparsePoint(fs::path(cookie.profile)) || HasReparsePoint(cookieDbPath) ||
            !IsPathWithinUserBrowserRoots(fs::path(cookie.profile)) ||
            !IsPathWithinUserBrowserRoots(cookieDbPath)) {
            Utils::Logger::Warn("CookieManager: Refusing to delete cookie outside trusted browser roots");
            return false;
        }

        // Open database for writing (not a temp copy — we modify the original)
        sqlite3* db = nullptr;
        int rc = sqlite3_open_v2(cookieDbPath.string().c_str(), &db,
                                  SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, nullptr);
        if (rc != SQLITE_OK) {
            Utils::Logger::Debug("CookieManager: Cannot open cookie DB for writing (rc={}): {}",
                                rc, db ? sqlite3_errmsg(db) : "null handle");
            if (db) sqlite3_close(db);
            return false;
        }
        SqliteDbGuard dbGuard(db);
        sqlite3_busy_timeout(db, 1000);

        // Use parameterized query — prevents SQL injection
        sqlite3_stmt* stmt = nullptr;
        rc = sqlite3_prepare_v2(db, deleteQuery, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            Utils::Logger::Error("CookieManager: Failed to prepare DELETE (rc={}): {}",
                                rc, sqlite3_errmsg(db));
            return false;
        }
        SqliteStmtGuard stmtGuard(stmt);

        // Bind all parameters (safe from SQL injection)
        sqlite3_bind_text(stmt, 1, cookie.domain.c_str(),
                          static_cast<int>(cookie.domain.size()), SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, cookie.name.c_str(),
                          static_cast<int>(cookie.name.size()), SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, cookie.path.c_str(),
                          static_cast<int>(cookie.path.size()), SQLITE_TRANSIENT);

        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            if (rc == SQLITE_BUSY || rc == SQLITE_LOCKED) {
                Utils::Logger::Debug("CookieManager: Cookie DB busy during delete (rc={})", rc);
            } else {
                Utils::Logger::Error("CookieManager: DELETE failed (rc={}): {}",
                                    rc, sqlite3_errmsg(db));
            }
            return false;
        }

        int changes = sqlite3_changes(db);
        if (changes > 0) {
            Utils::Logger::Debug("CookieManager: Deleted a cookie from {}",
                                std::string(GetBrowserTypeName(cookie.browser)));
            return true;
        }

        return false;

    } catch (const std::exception& ex) {
        Utils::Logger::Error("CookieManager: DeleteCookie failed: {}", ex.what());
        return false;
    } catch (...) {
        Utils::Logger::Error("CookieManager: DeleteCookie failed");
        return false;
    }
}

uint64_t CookieManager::DeleteCookiesForDomain(const std::string& domain) {
    uint64_t deleted = 0;

    try {
        std::string sanitized = SanitizeDomain(domain);
        if (sanitized.empty()) {
            Utils::Logger::Warn("CookieManager: DeleteCookiesForDomain rejected invalid domain input");
            return 0;
        }

        auto cookies = GetCookiesForDomain(sanitized);

        for (const auto& cookie : cookies) {
            if (DeleteCookie(cookie)) {
                ++deleted;
            }
        }

        m_impl->m_stats.totalCookiesDeleted += deleted;

        Utils::Logger::Info("CookieManager: Deleted {} cookies for requested domain",
                           deleted);

    } catch (const std::exception& ex) {
        Utils::Logger::Error("CookieManager: DeleteCookiesForDomain failed: {}", ex.what());
    } catch (...) {
        Utils::Logger::Error("CookieManager: DeleteCookiesForDomain failed");
    }

    return deleted;
}

uint64_t CookieManager::DeleteAllCookies(bool respectWhitelist) {
    uint64_t deleted = 0;

    try {
        // Snapshot config under lock to avoid data race
        bool preserveEssential = false;
        {
            std::shared_lock lock(m_impl->m_mutex);
            preserveEssential = m_impl->m_config.preserveEssential;
        }

        auto allCookies = GetAllCookies();

        for (const auto& cookie : allCookies) {
            // Check whitelist
            if (respectWhitelist && m_impl->IsWhitelistedInternal(cookie.domain)) {
                m_impl->m_stats.whitelistHits.fetch_add(1, std::memory_order_relaxed);
                continue;
            }

            // Preserve essential if configured
            if (preserveEssential &&
                cookie.category == CookieCategory::Essential) {
                m_impl->m_stats.essentialPreserved.fetch_add(1, std::memory_order_relaxed);
                continue;
            }

            if (DeleteCookie(cookie)) {
                ++deleted;
            }
        }

        m_impl->m_stats.totalCookiesDeleted += deleted;

        Utils::Logger::Info("CookieManager: Deleted {} cookies", deleted);

    } catch (const std::exception& ex) {
        Utils::Logger::Error("CookieManager: DeleteAllCookies failed: {}", ex.what());
    } catch (...) {
        Utils::Logger::Error("CookieManager: DeleteAllCookies failed");
    }

    return deleted;
}

uint64_t CookieManager::DeleteExpiredCookies() {
    uint64_t deleted = 0;

    try {
        auto allCookies = GetAllCookies();
        auto now = std::chrono::system_clock::now();

        for (const auto& cookie : allCookies) {
            if (cookie.IsExpired()) {
                if (DeleteCookie(cookie)) {
                    ++deleted;
                }
            }
        }

        m_impl->m_stats.totalCookiesDeleted += deleted;

        Utils::Logger::Info("CookieManager: Deleted {} expired cookies", deleted);

    } catch (const std::exception& ex) {
        Utils::Logger::Error("CookieManager: DeleteExpiredCookies failed: {}", ex.what());
    } catch (...) {
        Utils::Logger::Error("CookieManager: DeleteExpiredCookies failed");
    }

    return deleted;
}

uint64_t CookieManager::DeleteThirdPartyCookies() {
    uint64_t deleted = 0;

    try {
        auto thirdPartyCookies = GetThirdPartyCookies();

        for (const auto& cookie : thirdPartyCookies) {
            if (DeleteCookie(cookie)) {
                ++deleted;
            }
        }

        m_impl->m_stats.thirdPartyBlocked += deleted;
        m_impl->m_stats.totalCookiesDeleted += deleted;

        Utils::Logger::Info("CookieManager: Deleted {} third-party cookies", deleted);

    } catch (const std::exception& ex) {
        Utils::Logger::Error("CookieManager: DeleteThirdPartyCookies failed: {}", ex.what());
    } catch (...) {
        Utils::Logger::Error("CookieManager: DeleteThirdPartyCookies failed");
    }

    return deleted;
}

CookieCategory CookieManager::CategorizeCookie(const BrowserCookie& cookie) {
    return m_impl->CategorizeCookieInternal(cookie);
}

// ============================================================================
// WHITELIST MANAGEMENT
// ============================================================================

bool CookieManager::AddToWhitelist(const CookieWhitelistEntry& entry) {
    try {
        std::unique_lock lock(m_impl->m_whitelistMutex);

        m_impl->m_whitelist[entry.entryId] = entry;

        Utils::Logger::Info("CookieManager: Added a whitelist entry");
        return true;

    } catch (const std::exception& ex) {
        Utils::Logger::Error("CookieManager: AddToWhitelist failed: {}", ex.what());
        return false;
    } catch (...) {
        Utils::Logger::Error("CookieManager: AddToWhitelist failed");
        return false;
    }
}

bool CookieManager::RemoveFromWhitelist(const std::string& entryId) {
    try {
        std::unique_lock lock(m_impl->m_whitelistMutex);

        const bool removed = m_impl->m_whitelist.erase(entryId) > 0;

        if (removed) {
            Utils::Logger::Info("CookieManager: Removed from whitelist: {}", entryId);
        }

        return removed;

    } catch (const std::exception& ex) {
        Utils::Logger::Error("CookieManager: RemoveFromWhitelist failed: {}", ex.what());
        return false;
    } catch (...) {
        Utils::Logger::Error("CookieManager: RemoveFromWhitelist failed");
        return false;
    }
}

bool CookieManager::IsDomainWhitelisted(const std::string& domain) {
    std::string sanitized = SanitizeDomain(domain);
    if (sanitized.empty()) {
        return false;
    }
    return m_impl->IsWhitelistedInternal(sanitized);
}

std::vector<CookieWhitelistEntry> CookieManager::GetWhitelist() const {
    std::vector<CookieWhitelistEntry> whitelist;

    try {
        std::shared_lock lock(m_impl->m_whitelistMutex);

        for (const auto& [id, entry] : m_impl->m_whitelist) {
            whitelist.push_back(entry);
        }

    } catch (const std::exception& ex) {
        Utils::Logger::Error("CookieManager: GetWhitelist failed: {}", ex.what());
    } catch (...) {
        Utils::Logger::Error("CookieManager: GetWhitelist failed");
    }

    return whitelist;
}

// ============================================================================
// ANALYSIS
// ============================================================================

std::vector<DomainCookieSummary> CookieManager::GetDomainSummaries() {
    std::vector<DomainCookieSummary> summaries;

    try {
        auto allCookies = GetAllCookies();

        // Group by domain
        std::unordered_map<std::string, std::vector<BrowserCookie>> domainMap;
        for (const auto& cookie : allCookies) {
            std::string baseDomain = GetBaseDomain(cookie.domain);
            domainMap[baseDomain].push_back(cookie);
        }

        // Create summaries
        for (const auto& [domain, cookies] : domainMap) {
            DomainCookieSummary summary;
            summary.domain = domain;
            summary.totalCookies = static_cast<uint32_t>(cookies.size());

            for (const auto& cookie : cookies) {
                if (cookie.isSession) ++summary.sessionCookies;
                if (cookie.isPersistent) ++summary.persistentCookies;
                if (cookie.isTracking) ++summary.trackingCookies;
                summary.totalSizeBytes += cookie.sizeBytes;
            }

            summary.isWhitelisted = m_impl->IsWhitelistedInternal(domain);

            // Check if tracker
            if (IsTrackerDomain(domain)) {
                std::shared_lock lock(m_impl->m_trackerMutex);
                for (const auto& [id, tracker] : m_impl->m_trackers) {
                    if (domain.find(tracker.domainPattern) != std::string::npos) {
                        summary.trackerInfo = tracker;
                        break;
                    }
                }
            }

            summaries.push_back(summary);
        }

        m_impl->m_stats.domainsScanned += summaries.size();

        Utils::Logger::Debug("CookieManager: Generated summaries for {} domains",
                            summaries.size());

    } catch (const std::exception& ex) {
        Utils::Logger::Error("CookieManager: GetDomainSummaries failed: {}", ex.what());
    } catch (...) {
        Utils::Logger::Error("CookieManager: GetDomainSummaries failed");
    }

    return summaries;
}

DomainCookieSummary CookieManager::GetDomainSummary(const std::string& domain) {
    DomainCookieSummary summary;
    summary.domain = domain;

    try {
        auto cookies = GetCookiesForDomain(domain);
        summary.totalCookies = static_cast<uint32_t>(cookies.size());

        for (const auto& cookie : cookies) {
            if (cookie.isSession) ++summary.sessionCookies;
            if (cookie.isPersistent) ++summary.persistentCookies;
            if (cookie.isTracking) ++summary.trackingCookies;
            summary.totalSizeBytes += cookie.sizeBytes;
        }

        summary.isWhitelisted = m_impl->IsWhitelistedInternal(domain);

    } catch (const std::exception& ex) {
        Utils::Logger::Error("CookieManager: GetDomainSummary failed: {}", ex.what());
    } catch (...) {
        Utils::Logger::Error("CookieManager: GetDomainSummary failed");
    }

    return summary;
}

std::vector<std::string> CookieManager::GetTopTrackingDomains(size_t limit) {
    std::vector<std::string> topDomains;

    try {
        auto summaries = GetDomainSummaries();

        // Sort by tracking cookie count
        std::sort(summaries.begin(), summaries.end(),
            [](const DomainCookieSummary& a, const DomainCookieSummary& b) {
                return a.trackingCookies > b.trackingCookies;
            });

        // Get top N
        for (size_t i = 0; i < std::min(limit, summaries.size()); ++i) {
            if (summaries[i].trackingCookies > 0) {
                topDomains.push_back(summaries[i].domain);
            }
        }

    } catch (const std::exception& ex) {
        Utils::Logger::Error("CookieManager: GetTopTrackingDomains failed: {}", ex.what());
    } catch (...) {
        Utils::Logger::Error("CookieManager: GetTopTrackingDomains failed");
    }

    return topDomains;
}

// ============================================================================
// CALLBACKS
// ============================================================================

void CookieManager::RegisterCookieCallback(CookieCallback callback) {
    try {
        std::lock_guard lock(m_impl->m_callbackMutex);
        m_impl->m_cookieCallbacks.push_back(std::move(callback));

        Utils::Logger::Debug("CookieManager: Registered cookie callback");

    } catch (const std::exception& ex) {
        Utils::Logger::Error("CookieManager: RegisterCookieCallback failed: {}", ex.what());
    } catch (...) {
        Utils::Logger::Error("CookieManager: RegisterCookieCallback failed");
    }
}

void CookieManager::RegisterSupercookieCallback(SupercookieCallback callback) {
    try {
        std::lock_guard lock(m_impl->m_callbackMutex);
        m_impl->m_supercookieCallbacks.push_back(std::move(callback));

        Utils::Logger::Debug("CookieManager: Registered supercookie callback");

    } catch (const std::exception& ex) {
        Utils::Logger::Error("CookieManager: RegisterSupercookieCallback failed: {}", ex.what());
    } catch (...) {
        Utils::Logger::Error("CookieManager: RegisterSupercookieCallback failed");
    }
}

void CookieManager::RegisterPurgeCallback(PurgeCallback callback) {
    try {
        std::lock_guard lock(m_impl->m_callbackMutex);
        m_impl->m_purgeCallbacks.push_back(std::move(callback));

        Utils::Logger::Debug("CookieManager: Registered purge callback");

    } catch (const std::exception& ex) {
        Utils::Logger::Error("CookieManager: RegisterPurgeCallback failed: {}", ex.what());
    } catch (...) {
        Utils::Logger::Error("CookieManager: RegisterPurgeCallback failed");
    }
}

void CookieManager::RegisterErrorCallback(ErrorCallback callback) {
    try {
        std::lock_guard lock(m_impl->m_callbackMutex);
        m_impl->m_errorCallbacks.push_back(std::move(callback));

        Utils::Logger::Debug("CookieManager: Registered error callback");

    } catch (const std::exception& ex) {
        Utils::Logger::Error("CookieManager: RegisterErrorCallback failed: {}", ex.what());
    } catch (...) {
        Utils::Logger::Error("CookieManager: RegisterErrorCallback failed");
    }
}

void CookieManager::UnregisterCallbacks() {
    try {
        std::lock_guard lock(m_impl->m_callbackMutex);

        m_impl->m_cookieCallbacks.clear();
        m_impl->m_supercookieCallbacks.clear();
        m_impl->m_purgeCallbacks.clear();
        m_impl->m_errorCallbacks.clear();

        Utils::Logger::Info("CookieManager: Unregistered all callbacks");

    } catch (const std::exception& ex) {
        Utils::Logger::Error("CookieManager: UnregisterCallbacks failed: {}", ex.what());
    } catch (...) {
        Utils::Logger::Error("CookieManager: UnregisterCallbacks failed");
    }
}

// ============================================================================
// STATISTICS
// ============================================================================

CookieStatisticsSnapshot CookieManager::GetStatistics() const {
    std::shared_lock lock(m_impl->m_mutex);

    CookieStatisticsSnapshot snap;
    snap.totalCookiesScanned = m_impl->m_stats.totalCookiesScanned.load(std::memory_order_relaxed);
    snap.totalCookiesDeleted = m_impl->m_stats.totalCookiesDeleted.load(std::memory_order_relaxed);
    snap.trackersBlocked     = m_impl->m_stats.trackersBlocked.load(std::memory_order_relaxed);
    snap.thirdPartyBlocked   = m_impl->m_stats.thirdPartyBlocked.load(std::memory_order_relaxed);
    snap.supercookiesFound   = m_impl->m_stats.supercookiesFound.load(std::memory_order_relaxed);
    snap.supercookiesDeleted = m_impl->m_stats.supercookiesDeleted.load(std::memory_order_relaxed);
    snap.whitelistHits       = m_impl->m_stats.whitelistHits.load(std::memory_order_relaxed);
    snap.essentialPreserved  = m_impl->m_stats.essentialPreserved.load(std::memory_order_relaxed);
    snap.domainsScanned      = m_impl->m_stats.domainsScanned.load(std::memory_order_relaxed);
    snap.bytesReclaimed      = m_impl->m_stats.bytesReclaimed.load(std::memory_order_relaxed);

    for (size_t i = 0; i < m_impl->m_stats.byBrowser.size(); ++i) {
        snap.byBrowser[i] = m_impl->m_stats.byBrowser[i].load(std::memory_order_relaxed);
    }
    for (size_t i = 0; i < m_impl->m_stats.byCategory.size(); ++i) {
        snap.byCategory[i] = m_impl->m_stats.byCategory[i].load(std::memory_order_relaxed);
    }

    snap.startTime = AtomicValueLoadRelaxed(m_impl->m_stats.startTime);
    return snap;
}

void CookieManager::ResetStatistics() {
    try {
        std::unique_lock lock(m_impl->m_mutex);

        m_impl->m_stats.Reset();
        AtomicValueStoreRelaxed(m_impl->m_stats.startTime, Clock::now());

        Utils::Logger::Info("CookieManager: Statistics reset");

    } catch (const std::exception& ex) {
        Utils::Logger::Error("CookieManager: ResetStatistics failed: {}", ex.what());
    } catch (...) {
        Utils::Logger::Error("CookieManager: ResetStatistics failed");
    }
}

// ============================================================================
// SELF-TEST
// ============================================================================

bool CookieManager::SelfTest() {
    try {
        Utils::Logger::Info("CookieManager: Running self-test...");

        // Test 1: Configuration validation
        {
            CookieConfiguration config;
            if (!config.IsValid()) {
                Utils::Logger::Error("CookieManager: Self-test failed (config validation)");
                return false;
            }
        }

        // Test 2: Tracker detection
        {
            if (!IsTrackerDomain("doubleclick.net")) {
                Utils::Logger::Error("CookieManager: Self-test failed (tracker detection)");
                return false;
            }

            if (IsTrackerDomain("example.com")) {
                Utils::Logger::Error("CookieManager: Self-test failed (false positive)");
                return false;
            }
        }

        // Test 3: Base domain extraction
        {
            std::string baseDomain = GetBaseDomain(".example.com");
            if (baseDomain != "example.com") {
                Utils::Logger::Error("CookieManager: Self-test failed (base domain)");
                return false;
            }
        }

        // Test 4: Whitelist
        {
            CookieWhitelistEntry entry;
            entry.entryId = "TEST-001";
            entry.domainPattern = "test.com";
            entry.enabled = true;

            if (!AddToWhitelist(entry)) {
                Utils::Logger::Error("CookieManager: Self-test failed (whitelist add)");
                return false;
            }

            if (!IsDomainWhitelisted("test.com")) {
                Utils::Logger::Error("CookieManager: Self-test failed (whitelist check)");
                return false;
            }

            RemoveFromWhitelist("TEST-001");
        }

        Utils::Logger::Info("CookieManager: Self-test PASSED");
        return true;

    } catch (const std::exception& ex) {
        Utils::Logger::Error("CookieManager: Self-test failed with exception: {}", ex.what());
        return false;
    } catch (...) {
        Utils::Logger::Error("CookieManager: Self-test failed (unknown exception)");
        return false;
    }
}

std::string CookieManager::GetVersionString() noexcept {
    try {
        return std::to_string(CookieConstants::VERSION_MAJOR) + "." +
               std::to_string(CookieConstants::VERSION_MINOR) + "." +
               std::to_string(CookieConstants::VERSION_PATCH);
    } catch (...) {
        return "0.0.0";
    }
}

// ============================================================================
// STRUCTURE IMPLEMENTATIONS
// ============================================================================

bool BrowserCookie::IsExpired() const noexcept {
    try {
        if (isSession) {
            return false;
        }

        auto now = std::chrono::system_clock::now();
        return expirationTime < now;

    } catch (...) {
        return false;
    }
}

std::string BrowserCookie::ToJson() const {
    try {
        nlohmann::json j;
        j["domain"] = domain;
        j["name"] = name;
        j["path"] = path;
        j["isSecure"] = isSecure;
        j["isHttpOnly"] = isHttpOnly;
        j["sameSite"] = GetSameSitePolicyName(sameSite);
        j["isSession"] = isSession;
        j["isPersistent"] = isPersistent;
        j["category"] = GetCookieCategoryName(category);
        j["scope"] = GetCookieScopeName(scope);
        j["isTracking"] = isTracking;
        j["sizeBytes"] = sizeBytes;
        j["isExpired"] = IsExpired();

        return j.dump();
    } catch (...) {
        return "{}";
    }
}

std::string Supercookie::ToJson() const {
    try {
        nlohmann::json j;
        j["type"] = GetSupercookieTypeName(type);
        j["domain"] = domain;
        j["storagePath"] = storagePath.string();
        j["key"] = key;
        j["sizeBytes"] = sizeBytes;
        j["isTracking"] = isTracking;

        return j.dump();
    } catch (...) {
        return "{}";
    }
}

std::string TrackerInfo::ToJson() const {
    try {
        nlohmann::json j;
        j["trackerId"] = trackerId;
        j["domainPattern"] = domainPattern;
        j["cookiePattern"] = cookiePattern;
        j["company"] = company;
        j["category"] = GetCookieCategoryName(category);
        j["description"] = description;
        j["isActive"] = isActive;

        return j.dump();
    } catch (...) {
        return "{}";
    }
}

std::string CookieWhitelistEntry::ToJson() const {
    try {
        nlohmann::json j;
        j["entryId"] = entryId;
        j["domainPattern"] = domainPattern;
        j["cookieNamePattern"] = cookieNamePattern;
        j["reason"] = reason;
        j["enabled"] = enabled;
        j["addedBy"] = addedBy;

        return j.dump();
    } catch (...) {
        return "{}";
    }
}

std::string DomainCookieSummary::ToJson() const {
    try {
        nlohmann::json j;
        j["domain"] = domain;
        j["totalCookies"] = totalCookies;
        j["sessionCookies"] = sessionCookies;
        j["persistentCookies"] = persistentCookies;
        j["trackingCookies"] = trackingCookies;
        j["totalSizeBytes"] = totalSizeBytes;
        j["isWhitelisted"] = isWhitelisted;

        return j.dump();
    } catch (...) {
        return "{}";
    }
}

void CookieStatistics::Reset() noexcept {
    totalCookiesScanned.store(0);
    totalCookiesDeleted.store(0);
    trackersBlocked.store(0);
    thirdPartyBlocked.store(0);
    supercookiesFound.store(0);
    supercookiesDeleted.store(0);
    whitelistHits.store(0);
    essentialPreserved.store(0);
    domainsScanned.store(0);
    bytesReclaimed.store(0);

    for (auto& counter : byBrowser) {
        counter.store(0);
    }

    for (auto& counter : byCategory) {
        counter.store(0);
    }

    AtomicValueStoreRelaxed(startTime, Clock::now());
}

std::string CookieStatisticsSnapshot::ToJson() const {
    try {
        nlohmann::json j;
        j["totalCookiesScanned"] = totalCookiesScanned;
        j["totalCookiesDeleted"] = totalCookiesDeleted;
        j["trackersBlocked"] = trackersBlocked;
        j["thirdPartyBlocked"] = thirdPartyBlocked;
        j["supercookiesFound"] = supercookiesFound;
        j["supercookiesDeleted"] = supercookiesDeleted;
        j["whitelistHits"] = whitelistHits;
        j["essentialPreserved"] = essentialPreserved;
        j["domainsScanned"] = domainsScanned;
        j["bytesReclaimed"] = bytesReclaimed;

        const auto elapsed = Clock::now() - AtomicValueLoadRelaxed(startTime);
        const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
        j["uptimeSeconds"] = seconds;

        return j.dump();
    } catch (...) {
        return "{}";
    }
}

std::string CookieStatistics::ToJson() const {
    try {
        nlohmann::json j;
        j["totalCookiesScanned"] = totalCookiesScanned.load();
        j["totalCookiesDeleted"] = totalCookiesDeleted.load();
        j["trackersBlocked"] = trackersBlocked.load();
        j["thirdPartyBlocked"] = thirdPartyBlocked.load();
        j["supercookiesFound"] = supercookiesFound.load();
        j["supercookiesDeleted"] = supercookiesDeleted.load();
        j["whitelistHits"] = whitelistHits.load();
        j["essentialPreserved"] = essentialPreserved.load();
        j["domainsScanned"] = domainsScanned.load();
        j["bytesReclaimed"] = bytesReclaimed.load();

        const auto elapsed = Clock::now() - AtomicValueLoadRelaxed(startTime);
        const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
        j["uptimeSeconds"] = seconds;

        return j.dump();
    } catch (...) {
        return "{}";
    }
}

bool CookieConfiguration::IsValid() const noexcept {
    try {
        // Reject excessively large tracker/whitelist lists
        if (customTrackers.size() > CookieConstants::MAX_TRACKER_LIST) {
            return false;
        }
        if (whitelist.size() > CookieConstants::MAX_TRACKER_LIST) {
            return false;
        }

        // Validate tracker database path if specified (reject path traversal)
        if (!trackerDatabasePath.empty()) {
            auto pathStr = trackerDatabasePath.string();
            if (pathStr.find("..") != std::string::npos) {
                return false;
            }
        }

        // Validate custom tracker entries have non-empty IDs
        for (const auto& tracker : customTrackers) {
            if (tracker.trackerId.empty()) {
                return false;
            }
        }

        // Validate whitelist entries have non-empty IDs and patterns
        for (const auto& entry : whitelist) {
            if (entry.entryId.empty() || entry.domainPattern.empty()) {
                return false;
            }
        }

        return true;
    } catch (...) {
        return false;
    }
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetCookieCategoryName(CookieCategory category) noexcept {
    switch (category) {
        case CookieCategory::Essential: return "Essential";
        case CookieCategory::Functional: return "Functional";
        case CookieCategory::Analytics: return "Analytics";
        case CookieCategory::Advertising: return "Advertising";
        case CookieCategory::Social: return "Social";
        case CookieCategory::Tracking: return "Tracking";
        case CookieCategory::Fingerprinting: return "Fingerprinting";
        case CookieCategory::Malicious: return "Malicious";
        default: return "Unknown";
    }
}

std::string_view GetCookieScopeName(CookieScope scope) noexcept {
    switch (scope) {
        case CookieScope::FirstParty: return "First-Party";
        case CookieScope::ThirdParty: return "Third-Party";
        case CookieScope::CrossSite: return "Cross-Site";
        default: return "Unknown";
    }
}

std::string_view GetCookiePolicyName(CookiePolicy policy) noexcept {
    switch (policy) {
        case CookiePolicy::AllowAll: return "Allow All";
        case CookiePolicy::BlockThirdParty: return "Block Third-Party";
        case CookiePolicy::BlockTrackers: return "Block Trackers";
        case CookiePolicy::BlockAll: return "Block All";
        case CookiePolicy::SessionOnly: return "Session Only";
        case CookiePolicy::WhitelistOnly: return "Whitelist Only";
        default: return "Unknown";
    }
}

std::string_view GetSameSitePolicyName(SameSitePolicy policy) noexcept {
    switch (policy) {
        case SameSitePolicy::None: return "None";
        case SameSitePolicy::Lax: return "Lax";
        case SameSitePolicy::Strict: return "Strict";
        case SameSitePolicy::Unset: return "Unset";
        default: return "Unknown";
    }
}

std::string_view GetSupercookieTypeName(SupercookieType type) noexcept {
    switch (type) {
        case SupercookieType::FlashLSO: return "Flash LSO";
        case SupercookieType::SilverlightIS: return "Silverlight IS";
        case SupercookieType::LocalStorage: return "Local Storage";
        case SupercookieType::SessionStorage: return "Session Storage";
        case SupercookieType::IndexedDB: return "IndexedDB";
        case SupercookieType::WebSQL: return "WebSQL";
        case SupercookieType::CacheETag: return "Cache ETag";
        case SupercookieType::HSTS: return "HSTS";
        case SupercookieType::Canvas: return "Canvas";
        case SupercookieType::WebGL: return "WebGL";
        case SupercookieType::AudioContext: return "Audio Context";
        default: return "None";
    }
}

std::string GetBaseDomain(const std::string& domain) {
    try {
        std::string base = domain;

        // Remove leading dot
        if (!base.empty() && base[0] == '.') {
            base = base.substr(1);
        }

        // Simple TLD extraction (production would use Public Suffix List)
        size_t lastDot = base.find_last_of('.');
        if (lastDot != std::string::npos && lastDot > 0) {
            size_t secondLastDot = base.find_last_of('.', lastDot - 1);
            if (secondLastDot != std::string::npos) {
                return base.substr(secondLastDot + 1);
            }
        }

        return base;

    } catch (...) {
        return domain;
    }
}

bool IsThirdPartyCookie(const std::string& cookieDomain, const std::string& siteDomain) {
    try {
        std::string cookieBase = GetBaseDomain(cookieDomain);
        std::string siteBase = GetBaseDomain(siteDomain);

        return cookieBase != siteBase;

    } catch (...) {
        return false;
    }
}

}  // namespace Privacy
}  // namespace ShadowStrike
