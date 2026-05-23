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

#include "RollbackManager.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/Logger.hpp"

#include <WinSock2.h>
#pragma comment(lib, "ws2_32.lib")

#include <algorithm>
#include <charconv>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <format>
#include <random>
#include <shared_mutex>
#include <sstream>

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

namespace {

    constexpr const wchar_t* kLogCategory = L"RollbackManager";

    // Maximum total snapshot storage to prevent disk exhaustion (10 GB).
    constexpr uint64_t kMaxTotalSnapshotBytes = 10ULL * 1024 * 1024 * 1024;

    // Maximum individual snapshot size (2 GB).
    constexpr uint64_t kMaxSingleSnapshotBytes = 2ULL * 1024 * 1024 * 1024;

    // Maximum files in a single snapshot.
    constexpr uint32_t kMaxSnapshotFiles = 50000;

    // Minimum free disk space required to create a snapshot (500 MB).
    constexpr uint64_t kMinFreeDiskSpace = 500ULL * 1024 * 1024;

    // Maximum boot/crash record entries to keep in memory.
    constexpr size_t kMaxBootRecords = 256;

    // Manifest file name within each snapshot directory.
    constexpr const wchar_t* kManifestFileName = L"manifest.json";

    // Subdirectory names within a snapshot.
    constexpr const wchar_t* kFilesSubdir = L"files";
    constexpr const wchar_t* kConfigSubdir = L"config";

    // Service names to check during health validation.
    constexpr const wchar_t* kServiceNames[] = {
        L"ShadowStrikePhantomService",
        L"ShadowStrikeSensor"
    };

    // Critical file patterns to back up in a Full snapshot.
    constexpr const wchar_t* kCriticalFileExtensions[] = {
        L".exe", L".dll", L".sys", L".dat", L".db", L".sig"
    };

    constexpr const wchar_t* kConfigFileExtensions[] = {
        L".json", L".xml", L".cfg", L".ini", L".conf"
    };

    // Format a system_clock time_point as ISO-8601 string.
    [[nodiscard]] std::string FormatIso8601(
        const std::chrono::system_clock::time_point& tp) noexcept
    {
        try {
            const auto tt = std::chrono::system_clock::to_time_t(tp);
            std::tm tmBuf{};
            if (gmtime_s(&tmBuf, &tt) != 0) return "1970-01-01T00:00:00Z";
            char buf[32]{};
            if (std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tmBuf) == 0)
                return "1970-01-01T00:00:00Z";
            return std::string(buf);
        }
        catch (...) { return "1970-01-01T00:00:00Z"; }
    }

    // Escape a string for JSON output (minimal: backslash, quote, control chars).
    [[nodiscard]] std::string JsonEscape(const std::string& s) noexcept {
        std::string out;
        out.reserve(s.size() + 8);
        for (const char c : s) {
            switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char hex[8];
                    (void)std::snprintf(hex, sizeof(hex), "\\u%04x",
                        static_cast<unsigned>(static_cast<unsigned char>(c)));
                    out += hex;
                }
                else {
                    out += c;
                }
                break;
            }
        }
        return out;
    }

    // Check if a file extension matches any in a list.
    [[nodiscard]] bool MatchesExtension(
        const std::filesystem::path& p,
        const wchar_t* const* exts, size_t count) noexcept
    {
        try {
            const auto ext = p.extension().wstring();
            if (ext.empty()) return false;
            // Case-insensitive comparison.
            std::wstring lower = ext;
            for (auto& ch : lower) ch = static_cast<wchar_t>(::towlower(ch));
            for (size_t i = 0; i < count; ++i) {
                if (lower == exts[i]) return true;
            }
        }
        catch (...) {}
        return false;
    }

    // Check available disk space at a given path.
    [[nodiscard]] uint64_t GetAvailableDiskSpace(
        const std::filesystem::path& dir) noexcept
    {
        std::error_code ec;
        const auto info = std::filesystem::space(dir, ec);
        if (ec) return 0;
        return info.available;
    }

    // Validate a manifest-supplied relative path.
    //
    // Rejects:
    //   * empty paths
    //   * absolute paths (any root_name/root_directory)
    //   * any segment equal to "." or ".."
    //   * NUL characters
    //   * ADS-style ':' (alternate data stream) or wildcard chars
    //   * paths longer than 32k chars (defensive cap)
    //
    // The caller MUST additionally verify the resolved path is under the
    // intended root via FU::IsPathUnderRoot once concatenated with the root.
    [[nodiscard]] bool IsSafeManifestRelPath(const std::string& rel) noexcept {
        if (rel.empty() || rel.size() > 32768) return false;
        for (const char c : rel) {
            if (c == '\0') return false;
            // Reject characters that have special meaning on Windows and
            // could enable ADS or wildcard expansion in callers.
            if (c == ':' || c == '*' || c == '?' || c == '<' || c == '>' ||
                c == '|' || c == '"')
                return false;
        }
        try {
            std::filesystem::path p(rel);
            if (p.is_absolute()) return false;
            if (!p.root_name().empty()) return false;
            if (!p.root_directory().empty()) return false;
            for (const auto& seg : p) {
                const auto s = seg.generic_string();
                if (s == "." || s == "..") return false;
                if (s.empty()) continue;
            }
        }
        catch (...) {
            return false;
        }
        return true;
    }

    // Test whether a path is a reparse point (junction / symlink / mount
    // point). Treats missing/inaccessible files as not reparse points;
    // callers should additionally check existence where required.
    [[nodiscard]] bool IsReparsePoint(const std::filesystem::path& p) noexcept {
        ShadowStrike::Utils::FileUtils::FileStat st{};
        if (!ShadowStrike::Utils::FileUtils::Stat(p.wstring(), st, nullptr))
            return false;
        return st.isReparsePoint;
    }

    // Parse an ISO-8601 timestamp produced by FormatIso8601. Returns
    // nullopt on any parse failure. Uses the bounded sscanf_s variant
    // when targeting MSVC to silence C4996 and harden against any
    // future format change.
    [[nodiscard]] std::optional<std::chrono::system_clock::time_point>
    ParseIso8601(const std::string& s) noexcept
    {
        // Expected layout: YYYY-MM-DDTHH:MM:SSZ (20 chars).
        if (s.size() < 20) return std::nullopt;
        std::tm tmBuf{};
        int y=0, mo=0, d=0, h=0, mi=0, se=0;
#ifdef _MSC_VER
        if (::sscanf_s(s.c_str(), "%4d-%2d-%2dT%2d:%2d:%2dZ",
                       &y, &mo, &d, &h, &mi, &se) != 6) {
            return std::nullopt;
        }
#else
        if (std::sscanf(s.c_str(), "%4d-%2d-%2dT%2d:%2d:%2dZ",
                        &y, &mo, &d, &h, &mi, &se) != 6) {
            return std::nullopt;
        }
#endif
        if (y < 1970 || y > 9999 || mo < 1 || mo > 12 || d < 1 || d > 31 ||
            h < 0 || h > 23 || mi < 0 || mi > 59 || se < 0 || se > 60)
            return std::nullopt;
        tmBuf.tm_year = y - 1900;
        tmBuf.tm_mon  = mo - 1;
        tmBuf.tm_mday = d;
        tmBuf.tm_hour = h;
        tmBuf.tm_min  = mi;
        tmBuf.tm_sec  = se;
#ifdef _WIN32
        const auto tt = _mkgmtime(&tmBuf);
#else
        const auto tt = timegm(&tmBuf);
#endif
        if (tt == static_cast<time_t>(-1)) return std::nullopt;
        return std::chrono::system_clock::from_time_t(tt);
    }

}  // anonymous namespace

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

namespace ShadowStrike {
namespace Update {

namespace HU = ShadowStrike::Utils::HashUtils;
namespace FU = ShadowStrike::Utils::FileUtils;

class RollbackManagerImpl {
public:
    RollbackManagerConfiguration m_config;
    mutable std::shared_mutex    m_mutex;
    RollbackManagerStatus        m_status{RollbackManagerStatus::Uninitialized};
    std::atomic<bool>            m_initialized{false};

    // Snapshot storage
    std::vector<SnapshotInfo> m_snapshots;
    fs::path                  m_snapshotBaseDir;
    std::string               m_lastKnownGoodId;

    // Boot loop detection
    std::atomic<uint32_t>     m_bootCount{0};
    std::atomic<uint32_t>     m_crashCount{0};
    std::vector<TimePoint>    m_recentBoots;
    std::vector<TimePoint>    m_recentCrashes;

    // Rollback state
    std::atomic<bool>         m_rollbackInProgress{false};
    RollbackProgress          m_currentProgress;

    // Health
    HealthStatus              m_healthStatus{HealthStatus::Unknown};

    // Statistics & callbacks. Counter fields are intentionally separate
    // atomics rather than living in the public RollbackStatistics DTO so
    // that GetStatistics can return a trivially-copyable snapshot.
    struct AtomicStats {
        std::atomic<uint64_t> snapshotsCreated{0};
        std::atomic<uint64_t> snapshotsDeleted{0};
        std::atomic<uint64_t> rollbacksPerformed{0};
        std::atomic<uint64_t> rollbacksFailed{0};
        std::atomic<uint64_t> bootLoopsDetected{0};
        std::atomic<uint64_t> autoRollbacks{0};
        std::atomic<uint64_t> healthChecks{0};
        TimePoint             startTime{Clock::now()};
        void Reset() noexcept {
            snapshotsCreated.store(0, std::memory_order_relaxed);
            snapshotsDeleted.store(0, std::memory_order_relaxed);
            rollbacksPerformed.store(0, std::memory_order_relaxed);
            rollbacksFailed.store(0, std::memory_order_relaxed);
            bootLoopsDetected.store(0, std::memory_order_relaxed);
            autoRollbacks.store(0, std::memory_order_relaxed);
            healthChecks.store(0, std::memory_order_relaxed);
            startTime = Clock::now();
        }
    };
    AtomicStats               m_stats;
    RollbackProgressCallback  m_progressCallback;
    RollbackCompletionCallback m_completionCallback;
    HealthChangeCallback      m_healthChangeCallback;
    ErrorCallback             m_errorCallback;
    std::mutex                m_callbackMutex;

    // ========================================================================
    // CALLBACK HELPERS
    // ========================================================================

    void NotifyProgress(const RollbackProgress& progress) {
        std::lock_guard lock(m_callbackMutex);
        if (m_progressCallback) {
            try { m_progressCallback(progress); }
            catch (...) { SS_LOG_WARN(kLogCategory, L"Progress callback threw exception"); }
        }
    }

    void NotifyCompletion(const RollbackResult& result) {
        std::lock_guard lock(m_callbackMutex);
        if (m_completionCallback) {
            try { m_completionCallback(result); }
            catch (...) { SS_LOG_WARN(kLogCategory, L"Completion callback threw exception"); }
        }
    }

    void NotifyHealthChange(HealthStatus newStatus) {
        std::lock_guard lock(m_callbackMutex);
        if (m_healthChangeCallback) {
            try { m_healthChangeCallback(newStatus); }
            catch (...) { SS_LOG_WARN(kLogCategory, L"Health-change callback threw exception"); }
        }
    }

    void NotifyError(const std::string& message, int code) {
        std::lock_guard lock(m_callbackMutex);
        if (m_errorCallback) {
            try { m_errorCallback(message, code); }
            catch (...) { SS_LOG_WARN(kLogCategory, L"Error callback threw exception"); }
        }
    }

    // ========================================================================
    // PROGRESS UPDATE
    // ========================================================================

    void UpdateProgress(RollbackState state, uint8_t pct,
                        const std::string& operation,
                        uint32_t filesRestored = 0, uint32_t filesTotal = 0)
    {
        std::unique_lock lock(m_mutex);
        m_currentProgress.state            = state;
        m_currentProgress.progressPercent   = pct;
        m_currentProgress.currentOperation  = operation;
        m_currentProgress.filesRestored     = filesRestored;
        m_currentProgress.filesTotal        = filesTotal;
        auto progressCopy = m_currentProgress;
        lock.unlock();
        NotifyProgress(progressCopy);
    }

    // ========================================================================
    // SNAPSHOT HELPERS
    // ========================================================================

    // Find snapshot by ID (caller must hold m_mutex).
    [[nodiscard]] std::optional<size_t> FindSnapshotIndex(
        const std::string& id) const noexcept
    {
        for (size_t i = 0; i < m_snapshots.size(); ++i) {
            if (m_snapshots[i].snapshotId == id) return i;
        }
        return std::nullopt;
    }

    // Validate a snapshot ID contains only safe characters.
    [[nodiscard]] static bool IsValidSnapshotId(const std::string& id) noexcept {
        if (id.empty() || id.size() > 128) return false;
        return std::ranges::all_of(id, [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                   (c >= 'A' && c <= 'F') || c == '-' || c == '_';
        });
    }

    // Compute SHA-256 hex of a file.
    [[nodiscard]] std::optional<std::string> HashFile(const fs::path& filePath) const {
        std::vector<uint8_t> digest;
        if (!HU::ComputeFile(HU::Algorithm::SHA256,
                             filePath.wstring(), digest)) {
            SS_LOG_ERROR(kLogCategory, L"Failed to hash file: %s",
                         filePath.wstring().c_str());
            return std::nullopt;
        }
        return HU::ToHexLower(digest);
    }

    // Write the manifest.json for a snapshot.
    [[nodiscard]] bool WriteManifest(
        const fs::path& snapshotDir,
        const SnapshotInfo& info,
        const std::vector<std::tuple<std::string, std::string, uint64_t>>& fileEntries) const
    {
        std::ostringstream js;
        js << "{\n";
        js << "  \"snapshotId\": \"" << JsonEscape(info.snapshotId) << "\",\n";
        js << "  \"type\": \"" << JsonEscape(std::string(GetSnapshotTypeName(info.type))) << "\",\n";
        js << "  \"version\": \"" << JsonEscape(info.versionString) << "\",\n";
        js << "  \"created\": \"" << FormatIso8601(info.createdTime) << "\",\n";
        js << "  \"description\": \"" << JsonEscape(info.description) << "\",\n";
        js << "  \"files\": [\n";

        for (size_t i = 0; i < fileEntries.size(); ++i) {
            const auto& [path, hash, size] = fileEntries[i];
            js << "    {\"path\": \"" << JsonEscape(path)
               << "\", \"hash\": \"" << JsonEscape(hash)
               << "\", \"size\": " << size << "}";
            if (i + 1 < fileEntries.size()) js << ",";
            js << "\n";
        }
        js << "  ]\n";
        js << "}\n";

        const auto manifestPath = snapshotDir / kManifestFileName;
        return FU::WriteAllTextUtf8Atomic(manifestPath.wstring(), js.str());
    }

    // Read and parse the manifest.json for a snapshot (returns file entries).
    [[nodiscard]] bool ReadManifest(
        const fs::path& snapshotDir,
        std::vector<std::tuple<std::string, std::string, uint64_t>>& fileEntries) const
    {
        const auto manifestPath = snapshotDir / kManifestFileName;
        std::string content;
        if (!FU::ReadAllTextUtf8(manifestPath.wstring(), content)) {
            SS_LOG_ERROR(kLogCategory, L"Cannot read manifest: %s",
                         manifestPath.wstring().c_str());
            return false;
        }

        // Minimal JSON parser for our known manifest format.
        // Extract "files" array entries.
        fileEntries.clear();
        const auto filesPos = content.find("\"files\"");
        if (filesPos == std::string::npos) {
            SS_LOG_ERROR(kLogCategory, L"Manifest missing 'files' array: %s",
                         manifestPath.wstring().c_str());
            return false;
        }

        // Walk through each object in the files array.
        size_t searchStart = filesPos;
        while (true) {
            auto objStart = content.find('{', searchStart);
            // Stop if we hit the closing bracket of the files array first.
            auto arrayEnd = content.find(']', searchStart);
            if (objStart == std::string::npos || (arrayEnd != std::string::npos && objStart > arrayEnd))
                break;

            auto objEnd = content.find('}', objStart);
            if (objEnd == std::string::npos) break;

            std::string objStr = content.substr(objStart, objEnd - objStart + 1);

            // Extract "path", "hash", "size" from the object.
            auto extractString = [&](const std::string& key) -> std::string {
                auto kp = objStr.find("\"" + key + "\"");
                if (kp == std::string::npos) return {};
                auto colonPos = objStr.find(':', kp + key.size() + 2);
                if (colonPos == std::string::npos) return {};
                auto quoteStart = objStr.find('"', colonPos + 1);
                if (quoteStart == std::string::npos) return {};
                auto quoteEnd = objStr.find('"', quoteStart + 1);
                if (quoteEnd == std::string::npos) return {};
                return objStr.substr(quoteStart + 1, quoteEnd - quoteStart - 1);
            };

            auto extractUint64 = [&](const std::string& key) -> uint64_t {
                auto kp = objStr.find("\"" + key + "\"");
                if (kp == std::string::npos) return 0;
                auto colonPos = objStr.find(':', kp + key.size() + 2);
                if (colonPos == std::string::npos) return 0;
                // Skip whitespace.
                size_t numStart = colonPos + 1;
                while (numStart < objStr.size() && objStr[numStart] == ' ') ++numStart;
                uint64_t val = 0;
                auto [ptr, ec] = std::from_chars(
                    objStr.data() + numStart,
                    objStr.data() + objStr.size(), val);
                if (ec != std::errc{}) return 0;
                return val;
            };

            std::string path = extractString("path");
            std::string hash = extractString("hash");
            uint64_t    size = extractUint64("size");

            if (!path.empty()) {
                if (fileEntries.size() >= kMaxSnapshotFiles) {
                    SS_LOG_ERROR(kLogCategory,
                        L"Manifest exceeds maximum file count (%u): %s",
                        kMaxSnapshotFiles, manifestPath.wstring().c_str());
                    return false;
                }
                // Reject any manifest entry whose path is not a safe
                // relative path. This is the front line of defence
                // against a corrupted/attacker-controlled manifest
                // smuggling arbitrary destinations into the restore
                // walk (path-traversal, absolute paths, ADS, etc.).
                if (!IsSafeManifestRelPath(path)) {
                    SS_LOG_ERROR(kLogCategory,
                        L"Manifest contains unsafe relative path: %S",
                        path.c_str());
                    return false;
                }
                // Hash must be 64 lowercase hex characters or empty.
                if (!hash.empty() && hash.size() != 64) {
                    SS_LOG_ERROR(kLogCategory,
                        L"Manifest entry has malformed hash for: %S",
                        path.c_str());
                    return false;
                }
                fileEntries.emplace_back(std::move(path), std::move(hash), size);
            }
            searchStart = objEnd + 1;
        }

        return true;
    }

    // Load existing snapshots from disk on initialization.
    void LoadExistingSnapshots() {
        std::error_code ec;
        if (!fs::exists(m_snapshotBaseDir, ec) || ec) return;

        for (const auto& entry : fs::directory_iterator(m_snapshotBaseDir, ec)) {
            if (ec) break;
            if (!entry.is_directory(ec) || ec) continue;

            // Reject reparse-point snapshot directories. An attacker
            // who can drop a junction under Backup\Snapshots could
            // otherwise have the restore walk read/write through
            // an arbitrary filesystem target.
            if (IsReparsePoint(entry.path())) {
                SS_LOG_WARN(kLogCategory,
                    L"Skipping reparse-point snapshot directory: %s",
                    entry.path().wstring().c_str());
                continue;
            }

            // Confirm the directory really lives under the snapshot base
            // (defends against directory_iterator yielding a path that
            // resolves elsewhere via a normalised root mismatch).
            if (!FU::IsPathUnderRoot(entry.path().wstring(),
                                     m_snapshotBaseDir.wstring(), false)) {
                SS_LOG_WARN(kLogCategory,
                    L"Snapshot entry not under base directory, skipping: %s",
                    entry.path().wstring().c_str());
                continue;
            }

            const auto manifestPath = entry.path() / kManifestFileName;
            if (!fs::exists(manifestPath, ec) || ec) continue;

            std::string content;
            if (!FU::ReadAllTextUtf8(manifestPath.wstring(), content)) continue;

            SnapshotInfo info;
            info.snapshotPath = entry.path();

            // Extract snapshotId from manifest.
            auto extractJsonStr = [&](const std::string& key) -> std::string {
                auto kp = content.find("\"" + key + "\"");
                if (kp == std::string::npos) return {};
                auto colonPos = content.find(':', kp);
                if (colonPos == std::string::npos) return {};
                auto q1 = content.find('"', colonPos + 1);
                if (q1 == std::string::npos) return {};
                auto q2 = content.find('"', q1 + 1);
                if (q2 == std::string::npos) return {};
                return content.substr(q1 + 1, q2 - q1 - 1);
            };

            info.snapshotId    = extractJsonStr("snapshotId");
            info.versionString = extractJsonStr("version");
            info.description   = extractJsonStr("description");

            std::string typeName = extractJsonStr("type");
            if      (typeName == "Full")          info.type = SnapshotType::Full;
            else if (typeName == "Incremental")   info.type = SnapshotType::Incremental;
            else if (typeName == "Configuration") info.type = SnapshotType::Configuration;
            else if (typeName == "Database")      info.type = SnapshotType::Database;
            else if (typeName == "Drivers")       info.type = SnapshotType::Drivers;
            else if (typeName == "Emergency")     info.type = SnapshotType::Emergency;

            if (info.snapshotId.empty() || !IsValidSnapshotId(info.snapshotId)) continue;

            // Parse creation time from manifest; fall back to filesystem
            // mtime, then to current time, so ordering on disk is honoured
            // across restarts.
            if (auto parsed = ParseIso8601(extractJsonStr("created"));
                parsed.has_value()) {
                info.createdTime = parsed.value();
            }
            else {
                std::error_code mtimeEc;
                const auto mtime = fs::last_write_time(manifestPath, mtimeEc);
                if (!mtimeEc) {
                    // Convert file_time to system_clock via the C++20 clock_cast
                    // path; fall back to "now" if the implementation does not
                    // yet provide it.
#if defined(__cpp_lib_chrono) && __cpp_lib_chrono >= 201907L
                    info.createdTime = std::chrono::clock_cast<std::chrono::system_clock>(mtime);
#else
                    info.createdTime = std::chrono::system_clock::now();
#endif
                }
                else {
                    info.createdTime = std::chrono::system_clock::now();
                }
            }
            info.sizeBytes   = CalculateSnapshotSize(entry.path());
            info.isValid     = true;

            // Count files.
            uint32_t fcount = 0;
            const auto filesDir = entry.path() / kFilesSubdir;
            if (fs::exists(filesDir, ec) && !ec) {
                for ([[maybe_unused]] const auto& f :
                     fs::recursive_directory_iterator(filesDir, ec)) {
                    if (!ec) ++fcount;
                }
            }
            info.fileCount = fcount;

            // Mark if it matches the last known good ID.
            info.isCurrent = (!m_lastKnownGoodId.empty() &&
                              info.snapshotId == m_lastKnownGoodId);

            m_snapshots.push_back(std::move(info));
        }

        // Sort by creation time (newest first).
        std::ranges::sort(m_snapshots, [](const SnapshotInfo& a, const SnapshotInfo& b) {
            return a.createdTime > b.createdTime;
        });

        SS_LOG_INFO(kLogCategory, L"Loaded %zu existing snapshot(s) from disk",
                    m_snapshots.size());
    }

    // Prune the time-stamped boot/crash vectors of entries older than the window.
    void PruneTimeWindow(std::vector<TimePoint>& entries,
                         std::chrono::minutes window) const
    {
        const auto cutoff = Clock::now() - window;
        std::erase_if(entries, [&](const TimePoint& t) { return t < cutoff; });
    }

    // Check if a Windows service is running by name (SCM query).
    [[nodiscard]] static bool IsServiceRunning(const wchar_t* serviceName) noexcept {
#ifdef _WIN32
        SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scm) return false;

        SC_HANDLE svc = ::OpenServiceW(scm, serviceName, SERVICE_QUERY_STATUS);
        if (!svc) {
            ::CloseServiceHandle(scm);
            return false;
        }

        SERVICE_STATUS_PROCESS ssp{};
        DWORD needed = 0;
        BOOL ok = ::QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &needed);

        ::CloseServiceHandle(svc);
        ::CloseServiceHandle(scm);

        return ok && (ssp.dwCurrentState == SERVICE_RUNNING);
#else
        (void)serviceName;
        return false;
#endif
    }

    // Stop a Windows service if installed; logs errors. Returns true if the
    // service is stopped (or was already stopped, or is not installed).
    [[nodiscard]] static bool StopServiceIfRunning(const wchar_t* serviceName) noexcept {
#ifdef _WIN32
        SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scm) {
            const DWORD err = ::GetLastError();
            // ERROR_ACCESS_DENIED is logged but treated as "best effort".
            SS_LOG_WARN(kLogCategory,
                L"OpenSCManager failed when stopping service %s (err=%lu)",
                serviceName, err);
            return false;
        }
        SC_HANDLE svc = ::OpenServiceW(scm, serviceName,
                                        SERVICE_STOP | SERVICE_QUERY_STATUS);
        if (!svc) {
            const DWORD err = ::GetLastError();
            ::CloseServiceHandle(scm);
            if (err == ERROR_SERVICE_DOES_NOT_EXIST) return true;
            SS_LOG_WARN(kLogCategory,
                L"OpenService failed for %s (err=%lu)", serviceName, err);
            return false;
        }
        SERVICE_STATUS_PROCESS ssp{};
        DWORD needed = 0;
        if (::QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
                                   reinterpret_cast<LPBYTE>(&ssp),
                                   sizeof(ssp), &needed) &&
            ssp.dwCurrentState == SERVICE_STOPPED)
        {
            ::CloseServiceHandle(svc);
            ::CloseServiceHandle(scm);
            return true;
        }

        SERVICE_STATUS ss{};
        if (!::ControlService(svc, SERVICE_CONTROL_STOP, &ss)) {
            const DWORD err = ::GetLastError();
            if (err != ERROR_SERVICE_NOT_ACTIVE) {
                SS_LOG_WARN(kLogCategory,
                    L"ControlService(STOP) failed for %s (err=%lu)",
                    serviceName, err);
            }
        }

        // Poll up to 30 s for the service to reach SERVICE_STOPPED.
        const DWORD pollTimeoutMs = 30000;
        const DWORD pollIntervalMs = 250;
        DWORD waited = 0;
        while (waited < pollTimeoutMs) {
            if (!::QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
                                        reinterpret_cast<LPBYTE>(&ssp),
                                        sizeof(ssp), &needed))
                break;
            if (ssp.dwCurrentState == SERVICE_STOPPED) break;
            ::Sleep(pollIntervalMs);
            waited += pollIntervalMs;
        }

        const bool stopped = (ssp.dwCurrentState == SERVICE_STOPPED);
        ::CloseServiceHandle(svc);
        ::CloseServiceHandle(scm);
        if (!stopped) {
            SS_LOG_ERROR(kLogCategory,
                L"Service %s did not stop within %lu ms (state=%lu)",
                serviceName, pollTimeoutMs,
                static_cast<unsigned long>(ssp.dwCurrentState));
        }
        return stopped;
#else
        (void)serviceName;
        return true;
#endif
    }

    // Start a Windows service if installed.
    [[nodiscard]] static bool StartServiceIfInstalled(const wchar_t* serviceName) noexcept {
#ifdef _WIN32
        SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scm) return false;
        SC_HANDLE svc = ::OpenServiceW(scm, serviceName,
                                        SERVICE_START | SERVICE_QUERY_STATUS);
        if (!svc) {
            const DWORD err = ::GetLastError();
            ::CloseServiceHandle(scm);
            if (err == ERROR_SERVICE_DOES_NOT_EXIST) return true;
            SS_LOG_WARN(kLogCategory,
                L"OpenService(start) failed for %s (err=%lu)",
                serviceName, err);
            return false;
        }
        SERVICE_STATUS_PROCESS ssp{};
        DWORD needed = 0;
        if (::QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
                                   reinterpret_cast<LPBYTE>(&ssp),
                                   sizeof(ssp), &needed) &&
            ssp.dwCurrentState == SERVICE_RUNNING)
        {
            ::CloseServiceHandle(svc);
            ::CloseServiceHandle(scm);
            return true;
        }
        if (!::StartServiceW(svc, 0, nullptr)) {
            const DWORD err = ::GetLastError();
            if (err != ERROR_SERVICE_ALREADY_RUNNING) {
                SS_LOG_WARN(kLogCategory,
                    L"StartService failed for %s (err=%lu)",
                    serviceName, err);
                ::CloseServiceHandle(svc);
                ::CloseServiceHandle(scm);
                return false;
            }
        }
        ::CloseServiceHandle(svc);
        ::CloseServiceHandle(scm);
        return true;
#else
        (void)serviceName;
        return true;
#endif
    }

    // Copy files from source to a snapshot directory, computing hashes.
    // Returns the manifest file entries and the count of files copied.
    struct CopyResult {
        std::vector<std::tuple<std::string, std::string, uint64_t>> entries;
        uint32_t filesCopied = 0;
        uint64_t totalBytes  = 0;
        bool     success     = true;
    };

    [[nodiscard]] CopyResult CopyFilesToSnapshot(
        const fs::path& srcRoot,
        const fs::path& dstDir,
        const wchar_t* const* extensions,
        size_t extCount) const
    {
        CopyResult result;
        std::error_code ec;

        if (!fs::exists(srcRoot, ec) || ec) {
            SS_LOG_WARN(kLogCategory, L"Source directory does not exist: %s",
                        srcRoot.wstring().c_str());
            return result;
        }

        FU::WalkOptions walkOpts;
        walkOpts.recursive          = true;
        walkOpts.followReparsePoints = false;
        walkOpts.includeDirs        = false;
        walkOpts.skipHidden         = false;
        walkOpts.skipSystem         = false;

        FU::WalkCallback walker = [&](const std::wstring& fullPath,
                                      const WIN32_FIND_DATAW& /*fd*/) -> bool
        {
            if (result.filesCopied >= kMaxSnapshotFiles) {
                SS_LOG_WARN(kLogCategory,
                    L"Snapshot file limit reached (%u)", kMaxSnapshotFiles);
                return false;
            }
            if (result.totalBytes >= kMaxSingleSnapshotBytes) {
                SS_LOG_WARN(kLogCategory,
                    L"Snapshot size limit reached (%llu bytes)",
                    static_cast<unsigned long long>(kMaxSingleSnapshotBytes));
                return false;
            }

            fs::path srcFile(fullPath);
            if (!MatchesExtension(srcFile, extensions, extCount)) return true;

            // Compute relative path from source root.
            auto relPath = fs::relative(srcFile, srcRoot, ec);
            if (ec || relPath.empty()) return true;

            fs::path dstFile = dstDir / relPath;

            // Ensure parent directory exists.
            if (!FU::CreateDirectories(dstFile.parent_path().wstring())) {
                SS_LOG_ERROR(kLogCategory, L"Cannot create dir for: %s",
                             dstFile.wstring().c_str());
                result.success = false;
                return false;
            }

            // Copy the file.
            fs::copy_file(srcFile, dstFile,
                          fs::copy_options::overwrite_existing, ec);
            if (ec) {
                SS_LOG_ERROR(kLogCategory, L"Failed to copy %s -> %s: %S",
                             srcFile.wstring().c_str(),
                             dstFile.wstring().c_str(),
                             ec.message().c_str());
                result.success = false;
                return false;
            }

            // Hash the destination to verify integrity.
            auto hashOpt = HashFile(dstFile);
            if (!hashOpt.has_value()) {
                result.success = false;
                return false;
            }

            const auto fsize = fs::file_size(dstFile, ec);
            if (ec) {
                result.success = false;
                return false;
            }

            result.entries.emplace_back(
                relPath.generic_string(), hashOpt.value(), fsize);
            result.filesCopied++;
            result.totalBytes += fsize;
            return true;
        };

        if (!FU::WalkDirectory(srcRoot.wstring(), walkOpts, walker)) {
            SS_LOG_WARN(kLogCategory,
                L"WalkDirectory reported failure under: %s",
                srcRoot.wstring().c_str());
            result.success = false;
        }
        return result;
    }

    // Restore files from a snapshot back to the installation directory.
    //
    // SECURITY: every file path coming from the manifest is re-checked
    // here before any filesystem operation. The manifest reader
    // (ReadManifest) already rejects unsafe relative paths, but the
    // restore is the trust boundary that actually writes into the live
    // install tree — it must independently verify:
    //
    //   * the source path stays inside the snapshot directory;
    //   * the destination path stays inside the install root;
    //   * neither source nor destination is reached through a reparse
    //     point (junction / symlink / mount-point) that an attacker
    //     could have planted to redirect the write.
    [[nodiscard]] bool RestoreFiles(
        const fs::path& snapshotDir,
        const std::vector<std::tuple<std::string, std::string, uint64_t>>& entries,
        const fs::path& restoreRoot,
        uint32_t& filesRestoredOut)
    {
        filesRestoredOut = 0;
        const auto filesDir  = snapshotDir / kFilesSubdir;
        const auto configDir = snapshotDir / kConfigSubdir;

        // Refuse to restore through a reparse-point snapshot dir.
        if (IsReparsePoint(snapshotDir)) {
            SS_LOG_ERROR(kLogCategory,
                L"Refusing to restore through reparse-point snapshot dir: %s",
                snapshotDir.wstring().c_str());
            return false;
        }
        if (IsReparsePoint(restoreRoot)) {
            SS_LOG_ERROR(kLogCategory,
                L"Refusing to restore into reparse-point root: %s",
                restoreRoot.wstring().c_str());
            return false;
        }

        for (const auto& [relPath, expectedHash, expectedSize] : entries) {
            // Defence in depth: re-validate every manifest entry.
            if (!IsSafeManifestRelPath(relPath)) {
                SS_LOG_ERROR(kLogCategory,
                    L"Refusing unsafe manifest path during restore: %S",
                    relPath.c_str());
                return false;
            }

            // Determine which sub-directory the file is in.
            fs::path srcFile = filesDir / relPath;
            std::error_code ec;
            if (!fs::exists(srcFile, ec) || ec) {
                srcFile = configDir / relPath;
            }

            if (!fs::exists(srcFile, ec) || ec) {
                SS_LOG_ERROR(kLogCategory,
                    L"Snapshot file missing: %S", relPath.c_str());
                return false;
            }

            // Confirm the resolved source is still under the snapshot dir.
            if (!FU::IsPathUnderRoot(srcFile.wstring(),
                                     snapshotDir.wstring(), false)) {
                SS_LOG_ERROR(kLogCategory,
                    L"Snapshot file resolved outside snapshot dir: %s",
                    srcFile.wstring().c_str());
                return false;
            }
            if (IsReparsePoint(srcFile)) {
                SS_LOG_ERROR(kLogCategory,
                    L"Refusing reparse-point snapshot source: %s",
                    srcFile.wstring().c_str());
                return false;
            }

            // Verify hash before restoring.
            auto hashOpt = HashFile(srcFile);
            if (!hashOpt.has_value() ||
                (!expectedHash.empty() && hashOpt.value() != expectedHash)) {
                SS_LOG_ERROR(kLogCategory,
                    L"Snapshot file integrity check failed: %S "
                    L"(expected=%S, got=%S)",
                    relPath.c_str(),
                    expectedHash.c_str(),
                    hashOpt.value_or("FAILED").c_str());
                return false;
            }

            fs::path dstFile = restoreRoot / relPath;

            // Confirm the destination stays under the install root.
            if (!FU::IsPathUnderRoot(dstFile.wstring(),
                                     restoreRoot.wstring(), false)) {
                SS_LOG_ERROR(kLogCategory,
                    L"Refusing restore destination outside root: %s",
                    dstFile.wstring().c_str());
                return false;
            }

            // Refuse to overwrite a destination that is itself a reparse
            // point — that would let an attacker who already has write
            // access in the install dir redirect the restore to an
            // arbitrary file.
            if (fs::exists(dstFile, ec) && !ec && IsReparsePoint(dstFile)) {
                SS_LOG_ERROR(kLogCategory,
                    L"Refusing to overwrite reparse-point destination: %s",
                    dstFile.wstring().c_str());
                return false;
            }

            const auto dstParent = dstFile.parent_path();
            if (!FU::CreateDirectories(dstParent.wstring())) {
                SS_LOG_ERROR(kLogCategory,
                    L"Cannot create restore dir for: %s",
                    dstFile.wstring().c_str());
                return false;
            }
            if (IsReparsePoint(dstParent)) {
                SS_LOG_ERROR(kLogCategory,
                    L"Refusing to write into reparse-point parent: %s",
                    dstParent.wstring().c_str());
                return false;
            }

            fs::copy_file(srcFile, dstFile,
                          fs::copy_options::overwrite_existing, ec);
            if (ec) {
                SS_LOG_ERROR(kLogCategory,
                    L"Failed to restore %S -> %s: %S",
                    relPath.c_str(),
                    dstFile.wstring().c_str(),
                    ec.message().c_str());
                return false;
            }

            // Verify the restored file matches the recorded hash. An
            // empty expectedHash means the manifest did not record one;
            // accept the copy in that case but still require the hash
            // computation to succeed (so we never silently restore an
            // unreadable file).
            auto verifyHash = HashFile(dstFile);
            if (!verifyHash.has_value()) {
                SS_LOG_ERROR(kLogCategory,
                    L"Post-restore hash computation failed: %S",
                    relPath.c_str());
                return false;
            }
            if (!expectedHash.empty() && verifyHash.value() != expectedHash) {
                SS_LOG_ERROR(kLogCategory,
                    L"Post-restore integrity check failed: %S",
                    relPath.c_str());
                return false;
            }

            filesRestoredOut++;
        }

        return true;
    }
};

// ============================================================================
// STATIC MEMBERS
// ============================================================================

std::atomic<bool> RollbackManager::s_instanceCreated{false};

// ============================================================================
// SINGLETON
// ============================================================================

RollbackManager& RollbackManager::Instance() noexcept {
    static RollbackManager instance;
    return instance;
}

bool RollbackManager::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

RollbackManager::RollbackManager()
    : m_impl(std::make_unique<RollbackManagerImpl>())
{
    s_instanceCreated.store(true, std::memory_order_release);
    SS_LOG_DEBUG(kLogCategory, L"RollbackManager constructed");
}

RollbackManager::~RollbackManager() {
    if (m_impl && m_impl->m_initialized.load(std::memory_order_acquire)) {
        Shutdown();
    }
    s_instanceCreated.store(false, std::memory_order_release);
    SS_LOG_DEBUG(kLogCategory, L"RollbackManager destroyed");
}

// ============================================================================
// LIFECYCLE
// ============================================================================

bool RollbackManager::Initialize(const RollbackManagerConfiguration& config) {
    if (m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(kLogCategory, L"Initialize called on already-initialized instance");
        return true;
    }

    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_status = RollbackManagerStatus::Initializing;
    m_impl->m_config = config;

    SS_LOG_INFO(kLogCategory, L"Initializing RollbackManager v%u.%u.%u",
                RollbackConstants::VERSION_MAJOR,
                RollbackConstants::VERSION_MINOR,
                RollbackConstants::VERSION_PATCH);

    // Resolve snapshot base directory.
    if (config.snapshotDirectory.empty()) {
        // Default: relative to the executable.
        std::error_code ec;
        auto exePath = fs::path(ShadowStrike::Utils::SystemUtils::GetExecutablePath());
        if (exePath.empty()) {
            wchar_t buf[MAX_PATH]{};
            ::GetModuleFileNameW(nullptr, buf, MAX_PATH);
            exePath = fs::path(buf);
        }
        m_impl->m_snapshotBaseDir = exePath.parent_path() /
                                     RollbackConstants::SNAPSHOT_DIR;
    }
    else {
        m_impl->m_snapshotBaseDir = config.snapshotDirectory;
    }

    // Create base snapshot directory.
    if (!FU::CreateDirectories(m_impl->m_snapshotBaseDir.wstring())) {
        SS_LOG_ERROR(kLogCategory,
            L"Failed to create snapshot directory: %s",
            m_impl->m_snapshotBaseDir.wstring().c_str());
        m_impl->m_status = RollbackManagerStatus::Error;
        m_impl->NotifyError("Failed to create snapshot directory", ERROR_PATH_NOT_FOUND);
        return false;
    }

    // Validate configuration.
    if (!config.IsValid()) {
        SS_LOG_WARN(kLogCategory,
            L"Configuration validation failed, using defaults where needed");
    }

    // Load existing snapshots from disk.
    m_impl->LoadExistingSnapshots();

    // Initialize statistics timer.
    m_impl->m_stats.startTime = Clock::now();

    m_impl->m_initialized.store(true, std::memory_order_release);
    m_impl->m_status = RollbackManagerStatus::Running;

    SS_LOG_INFO(kLogCategory,
        L"RollbackManager initialized successfully "
        L"(snapshots=%zu, baseDir=%s, maxSnapshots=%u, bootLoopThreshold=%u)",
        m_impl->m_snapshots.size(),
        m_impl->m_snapshotBaseDir.wstring().c_str(),
        config.maxSnapshots,
        config.bootLoopThreshold);

    return true;
}

void RollbackManager::Shutdown() {
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    SS_LOG_INFO(kLogCategory, L"Shutting down RollbackManager");

    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_status = RollbackManagerStatus::Stopping;

    if (m_impl->m_rollbackInProgress.load(std::memory_order_acquire)) {
        SS_LOG_WARN(kLogCategory,
            L"Shutdown requested while rollback is in progress");
    }

    m_impl->m_initialized.store(false, std::memory_order_release);
    m_impl->m_status = RollbackManagerStatus::Stopped;

    lock.unlock();

    // Clear callbacks under their own lock.
    {
        std::lock_guard cbLock(m_impl->m_callbackMutex);
        m_impl->m_progressCallback  = nullptr;
        m_impl->m_completionCallback = nullptr;
        m_impl->m_healthChangeCallback = nullptr;
        m_impl->m_errorCallback      = nullptr;
    }

    SS_LOG_INFO(kLogCategory, L"RollbackManager shutdown complete");
}

bool RollbackManager::IsInitialized() const noexcept {
    return m_impl->m_initialized.load(std::memory_order_acquire);
}

RollbackManagerStatus RollbackManager::GetStatus() const noexcept {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_status;
}

// ============================================================================
// SNAPSHOT MANAGEMENT
// ============================================================================

void RollbackManager::BackupCurrentVersion() {
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory,
            L"BackupCurrentVersion called on uninitialized instance");
        return;
    }

    SS_LOG_INFO(kLogCategory,
        L"Backing up current version as Last Known Good");

    auto id = CreateSnapshot(SnapshotType::Full, "LastKnownGood-AutoBackup");
    if (id.empty()) {
        SS_LOG_ERROR(kLogCategory,
            L"Failed to create Last Known Good backup");
        return;
    }

    std::unique_lock lock(m_impl->m_mutex);
    // Unmark previous LKG.
    for (auto& s : m_impl->m_snapshots) {
        s.isCurrent = (s.snapshotId == id);
    }
    m_impl->m_lastKnownGoodId = id;

    SS_LOG_INFO(kLogCategory,
        L"Last Known Good snapshot set to: %S", id.c_str());
}

std::string RollbackManager::CreateSnapshot(
    SnapshotType type, const std::string& description)
{
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory,
            L"CreateSnapshot called on uninitialized instance");
        return {};
    }

    const auto startTime = Clock::now();
    const std::string snapshotId = GenerateSnapshotId();

    SS_LOG_INFO(kLogCategory,
        L"Creating snapshot id=%S type=%S desc=\"%S\"",
        snapshotId.c_str(),
        std::string(GetSnapshotTypeName(type)).c_str(),
        description.c_str());

    // Check disk space.
    const uint64_t freeSpace = GetAvailableDiskSpace(m_impl->m_snapshotBaseDir);
    if (freeSpace < kMinFreeDiskSpace) {
        SS_LOG_ERROR(kLogCategory,
            L"Insufficient disk space for snapshot: %llu bytes free, need %llu",
            static_cast<unsigned long long>(freeSpace),
            static_cast<unsigned long long>(kMinFreeDiskSpace));
        m_impl->NotifyError("Insufficient disk space for snapshot",
                            ERROR_DISK_FULL);
        return {};
    }

    // Create snapshot directory structure.
    const fs::path snapshotDir = m_impl->m_snapshotBaseDir / snapshotId;
    const fs::path filesDir    = snapshotDir / kFilesSubdir;
    const fs::path configDir   = snapshotDir / kConfigSubdir;

    // Validate path is under our base directory (prevent traversal).
    if (!FU::IsPathUnderRoot(snapshotDir.wstring(),
                             m_impl->m_snapshotBaseDir.wstring(), false)) {
        SS_LOG_ERROR(kLogCategory,
            L"Snapshot directory traversal detected: %s",
            snapshotDir.wstring().c_str());
        return {};
    }

    if (!FU::CreateDirectories(filesDir.wstring()) ||
        !FU::CreateDirectories(configDir.wstring()))
    {
        SS_LOG_ERROR(kLogCategory,
            L"Failed to create snapshot directories: %s",
            snapshotDir.wstring().c_str());
        m_impl->NotifyError("Failed to create snapshot directories",
                            ERROR_PATH_NOT_FOUND);
        return {};
    }

    // Determine the installation root (parent of snapshot base).
    const fs::path installRoot = m_impl->m_snapshotBaseDir.parent_path()
                                                           .parent_path();

    RollbackManagerImpl::CopyResult fileResult;
    RollbackManagerImpl::CopyResult configResult;

    switch (type) {
    case SnapshotType::Full:
        fileResult = m_impl->CopyFilesToSnapshot(
            installRoot, filesDir,
            kCriticalFileExtensions,
            std::size(kCriticalFileExtensions));
        configResult = m_impl->CopyFilesToSnapshot(
            installRoot, configDir,
            kConfigFileExtensions,
            std::size(kConfigFileExtensions));
        break;

    case SnapshotType::Configuration:
        configResult = m_impl->CopyFilesToSnapshot(
            installRoot, configDir,
            kConfigFileExtensions,
            std::size(kConfigFileExtensions));
        break;

    case SnapshotType::Database: {
        static constexpr const wchar_t* dbExts[] = { L".dat", L".db", L".sig" };
        fileResult = m_impl->CopyFilesToSnapshot(
            installRoot, filesDir, dbExts, std::size(dbExts));
        break;
    }

    case SnapshotType::Drivers: {
        static constexpr const wchar_t* drvExts[] = { L".sys" };
        fileResult = m_impl->CopyFilesToSnapshot(
            installRoot, filesDir, drvExts, std::size(drvExts));
        break;
    }

    case SnapshotType::Incremental:
    case SnapshotType::Emergency:
        fileResult = m_impl->CopyFilesToSnapshot(
            installRoot, filesDir,
            kCriticalFileExtensions,
            std::size(kCriticalFileExtensions));
        configResult = m_impl->CopyFilesToSnapshot(
            installRoot, configDir,
            kConfigFileExtensions,
            std::size(kConfigFileExtensions));
        break;
    }

    if (!fileResult.success || !configResult.success) {
        SS_LOG_ERROR(kLogCategory,
            L"Snapshot file copy failed, cleaning up: %s",
            snapshotDir.wstring().c_str());
        if (!FU::RemoveDirectoryRecursive(snapshotDir.wstring())) {
            SS_LOG_WARN(kLogCategory,
                L"Cleanup of failed snapshot directory incomplete: %s",
                snapshotDir.wstring().c_str());
        }
        m_impl->NotifyError("Snapshot file copy failed", ERROR_WRITE_FAULT);
        return {};
    }

    // Merge file entries for the manifest.
    auto allEntries = fileResult.entries;
    allEntries.insert(allEntries.end(),
                      configResult.entries.begin(),
                      configResult.entries.end());

    // Build SnapshotInfo.
    SnapshotInfo info;
    info.snapshotId    = snapshotId;
    info.type          = type;
    info.createdTime   = std::chrono::system_clock::now();
    info.versionString = GetVersionString();
    info.description   = description;
    info.sizeBytes     = fileResult.totalBytes + configResult.totalBytes;
    info.fileCount     = fileResult.filesCopied + configResult.filesCopied;
    info.snapshotPath  = snapshotDir;
    info.isCurrent     = false;
    info.isValid       = true;

    // Write manifest.
    if (!m_impl->WriteManifest(snapshotDir, info, allEntries)) {
        SS_LOG_ERROR(kLogCategory,
            L"Failed to write manifest, cleaning up snapshot: %S",
            snapshotId.c_str());
        if (!FU::RemoveDirectoryRecursive(snapshotDir.wstring())) {
            SS_LOG_WARN(kLogCategory,
                L"Cleanup of partial snapshot directory incomplete: %s",
                snapshotDir.wstring().c_str());
        }
        m_impl->NotifyError("Failed to write snapshot manifest",
                            ERROR_WRITE_FAULT);
        return {};
    }

    // Register the snapshot.
    {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_snapshots.insert(m_impl->m_snapshots.begin(), info);
    }
    m_impl->m_stats.snapshotsCreated++;

    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now() - startTime).count();

    SS_LOG_INFO(kLogCategory,
        L"Snapshot created: id=%S type=%S files=%u size=%llu bytes elapsed=%lldms",
        snapshotId.c_str(),
        std::string(GetSnapshotTypeName(type)).c_str(),
        info.fileCount,
        static_cast<unsigned long long>(info.sizeBytes),
        static_cast<long long>(elapsed));

    // Auto-cleanup if we exceed the limit.
    {
        std::shared_lock lock(m_impl->m_mutex);
        if (m_impl->m_snapshots.size() > m_impl->m_config.maxSnapshots) {
            lock.unlock();
            const uint32_t removed = CleanupSnapshots(
                m_impl->m_config.maxSnapshots);
            if (removed > 0) {
                SS_LOG_DEBUG(kLogCategory,
                    L"Auto-cleanup pruned %u old snapshot(s)", removed);
            }
        }
    }

    return snapshotId;
}

std::vector<SnapshotInfo> RollbackManager::GetSnapshots() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_snapshots;
}

std::optional<SnapshotInfo> RollbackManager::GetSnapshot(
    const std::string& snapshotId) const
{
    std::shared_lock lock(m_impl->m_mutex);
    auto idx = m_impl->FindSnapshotIndex(snapshotId);
    if (!idx.has_value()) return std::nullopt;
    return m_impl->m_snapshots[idx.value()];
}

bool RollbackManager::DeleteSnapshot(const std::string& snapshotId) {
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory,
            L"DeleteSnapshot called on uninitialized instance");
        return false;
    }

    if (!RollbackManagerImpl::IsValidSnapshotId(snapshotId)) {
        SS_LOG_ERROR(kLogCategory,
            L"Invalid snapshot ID for deletion: %S", snapshotId.c_str());
        return false;
    }

    std::unique_lock lock(m_impl->m_mutex);

    // Never delete the Last Known Good snapshot automatically.
    if (snapshotId == m_impl->m_lastKnownGoodId) {
        SS_LOG_WARN(kLogCategory,
            L"Refusing to delete Last Known Good snapshot: %S",
            snapshotId.c_str());
        return false;
    }

    auto idx = m_impl->FindSnapshotIndex(snapshotId);
    if (!idx.has_value()) {
        SS_LOG_WARN(kLogCategory,
            L"Snapshot not found for deletion: %S", snapshotId.c_str());
        return false;
    }

    const fs::path snapshotDir = m_impl->m_snapshots[idx.value()].snapshotPath;

    // Validate path before deletion.
    if (!FU::IsPathUnderRoot(snapshotDir.wstring(),
                             m_impl->m_snapshotBaseDir.wstring(), false)) {
        SS_LOG_ERROR(kLogCategory,
            L"Path traversal detected in snapshot deletion: %s",
            snapshotDir.wstring().c_str());
        return false;
    }

    m_impl->m_snapshots.erase(m_impl->m_snapshots.begin() +
                              static_cast<ptrdiff_t>(idx.value()));
    lock.unlock();

    // Delete from disk outside the lock.
    if (!FU::RemoveDirectoryRecursive(snapshotDir.wstring())) {
        SS_LOG_WARN(kLogCategory,
            L"Failed to remove snapshot directory: %s",
            snapshotDir.wstring().c_str());
    }

    m_impl->m_stats.snapshotsDeleted++;

    SS_LOG_INFO(kLogCategory,
        L"Snapshot deleted: %S", snapshotId.c_str());

    return true;
}

uint32_t RollbackManager::CleanupSnapshots(uint32_t keepCount) {
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        return 0;
    }

    if (keepCount == 0) {
        keepCount = m_impl->m_config.maxSnapshots;
    }

    uint32_t deleted = 0;
    std::vector<std::string> toDelete;

    {
        std::shared_lock lock(m_impl->m_mutex);

        if (m_impl->m_snapshots.size() <= keepCount) {
            return 0;
        }

        // Collect IDs of the oldest snapshots that exceed keepCount.
        // Skip LastKnownGood.
        for (size_t i = keepCount; i < m_impl->m_snapshots.size(); ++i) {
            if (m_impl->m_snapshots[i].snapshotId != m_impl->m_lastKnownGoodId) {
                toDelete.push_back(m_impl->m_snapshots[i].snapshotId);
            }
        }
    }

    for (const auto& id : toDelete) {
        if (DeleteSnapshot(id)) {
            ++deleted;
        }
    }

    if (deleted > 0) {
        SS_LOG_INFO(kLogCategory,
            L"Cleanup removed %u snapshot(s), keeping %u",
            deleted, keepCount);
    }

    return deleted;
}

std::optional<SnapshotInfo> RollbackManager::GetLastKnownGood() const {
    std::shared_lock lock(m_impl->m_mutex);
    if (m_impl->m_lastKnownGoodId.empty()) return std::nullopt;
    auto idx = m_impl->FindSnapshotIndex(m_impl->m_lastKnownGoodId);
    if (!idx.has_value()) return std::nullopt;
    return m_impl->m_snapshots[idx.value()];
}

// ============================================================================
// ROLLBACK OPERATIONS
// ============================================================================

bool RollbackManager::TriggerRollback() {
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory,
            L"TriggerRollback called on uninitialized instance");
        return false;
    }

    std::shared_lock lock(m_impl->m_mutex);
    if (m_impl->m_lastKnownGoodId.empty()) {
        SS_LOG_ERROR(kLogCategory,
            L"No Last Known Good snapshot available for rollback");
        lock.unlock();
        m_impl->NotifyError("No Last Known Good snapshot available",
                            ERROR_NOT_FOUND);
        return false;
    }
    std::string lkgId = m_impl->m_lastKnownGoodId;
    lock.unlock();

    SS_LOG_INFO(kLogCategory,
        L"Triggering rollback to Last Known Good: %S", lkgId.c_str());

    return RollbackTo(lkgId);
}

bool RollbackManager::RollbackTo(const std::string& snapshotId) {
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory,
            L"RollbackTo called on uninitialized instance");
        return false;
    }

    if (!RollbackManagerImpl::IsValidSnapshotId(snapshotId)) {
        SS_LOG_ERROR(kLogCategory,
            L"Invalid snapshot ID for rollback: %S", snapshotId.c_str());
        return false;
    }

    // Ensure no concurrent rollback.
    bool expected = false;
    if (!m_impl->m_rollbackInProgress.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel))
    {
        SS_LOG_WARN(kLogCategory,
            L"Rollback already in progress, rejecting new request");
        return false;
    }

    const auto rollbackStart = Clock::now();
    RollbackResult result;
    result.snapshotId = snapshotId;

    // Reset progress at the start of a new rollback so stale error
    // strings from a previously-cancelled run don't leak through.
    {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_currentProgress = RollbackProgress{};
        m_impl->m_status = RollbackManagerStatus::RollingBack;
    }

    // Phase 1: Validate snapshot.
    m_impl->UpdateProgress(RollbackState::Preparing, 5, "Validating snapshot");

    SnapshotInfo snapshotInfo;
    {
        std::shared_lock lock(m_impl->m_mutex);

        auto idx = m_impl->FindSnapshotIndex(snapshotId);
        if (!idx.has_value()) {
            SS_LOG_ERROR(kLogCategory,
                L"Snapshot not found for rollback: %S", snapshotId.c_str());
            lock.unlock();
            m_impl->m_rollbackInProgress.store(false, std::memory_order_release);
            {
                std::unique_lock wlock(m_impl->m_mutex);
                m_impl->m_status = RollbackManagerStatus::Running;
            }
            m_impl->NotifyError("Snapshot not found for rollback",
                                ERROR_NOT_FOUND);
            return false;
        }
        snapshotInfo = m_impl->m_snapshots[idx.value()];
    }

    if (!snapshotInfo.isValid) {
        SS_LOG_ERROR(kLogCategory,
            L"Snapshot marked as invalid: %S", snapshotId.c_str());
        m_impl->m_rollbackInProgress.store(false, std::memory_order_release);
        {
            std::unique_lock lock(m_impl->m_mutex);
            m_impl->m_status = RollbackManagerStatus::Running;
        }
        m_impl->NotifyError("Snapshot is invalid", ERROR_INVALID_DATA);
        return false;
    }

    // Read the manifest.
    std::vector<std::tuple<std::string, std::string, uint64_t>> fileEntries;
    if (!m_impl->ReadManifest(snapshotInfo.snapshotPath, fileEntries)) {
        SS_LOG_ERROR(kLogCategory,
            L"Cannot read snapshot manifest for rollback: %S",
            snapshotId.c_str());
        m_impl->m_rollbackInProgress.store(false, std::memory_order_release);
        {
            std::unique_lock lock(m_impl->m_mutex);
            m_impl->m_status = RollbackManagerStatus::Running;
        }
        m_impl->NotifyError("Cannot read snapshot manifest", ERROR_READ_FAULT);
        return false;
    }

    SS_LOG_INFO(kLogCategory,
        L"Rollback started: snapshot=%S files=%zu version=%S",
        snapshotId.c_str(), fileEntries.size(),
        snapshotInfo.versionString.c_str());

    // Phase 2: Stopping services.
    m_impl->UpdateProgress(RollbackState::StoppingServices, 15,
                           "Stopping services");
    SS_LOG_INFO(kLogCategory, L"Stopping services for rollback");

    // Attempt to stop ShadowStrike services via SCM.
    bool servicesWereStopped = false;
#ifdef _WIN32
    for (const auto* svcName : kServiceNames) {
        if (RollbackManagerImpl::StopServiceIfRunning(svcName)) {
            servicesWereStopped = true;
        }
    }
#endif

    // Helper closure: restart services on any failure path so we don't
    // leave the endpoint without protection.
    auto restartServicesBestEffort = [&]() noexcept {
#ifdef _WIN32
        for (const auto* svcName : kServiceNames) {
            (void)RollbackManagerImpl::StartServiceIfInstalled(svcName);
        }
#endif
    };

    // Phase 3: Restoring files.
    m_impl->UpdateProgress(RollbackState::RestoringFiles, 30,
                           "Restoring files",
                           0, static_cast<uint32_t>(fileEntries.size()));

    const fs::path installRoot = m_impl->m_snapshotBaseDir.parent_path()
                                                           .parent_path();

    uint32_t filesRestored = 0;
    bool restoreOk = m_impl->RestoreFiles(
        snapshotInfo.snapshotPath, fileEntries, installRoot, filesRestored);

    m_impl->UpdateProgress(RollbackState::RestoringFiles, 60,
                           "File restoration complete",
                           filesRestored,
                           static_cast<uint32_t>(fileEntries.size()));

    if (!restoreOk) {
        SS_LOG_ERROR(kLogCategory,
            L"File restoration failed during rollback to: %S",
            snapshotId.c_str());

        m_impl->UpdateProgress(RollbackState::Failed, 0,
                               "File restoration failed");

        // Try to bring the services back online even after a failed
        // restore — leaving them stopped would mean the endpoint is
        // unprotected.
        if (servicesWereStopped) {
            SS_LOG_WARN(kLogCategory,
                L"Restarting services after failed rollback");
            restartServicesBestEffort();
        }

        result.success       = false;
        result.errorMessage  = "File restoration failed";
        result.filesRestored = filesRestored;
        result.completionTime = std::chrono::system_clock::now();

        m_impl->m_stats.rollbacksFailed++;
        m_impl->m_rollbackInProgress.store(false, std::memory_order_release);
        {
            std::unique_lock lock(m_impl->m_mutex);
            m_impl->m_status = RollbackManagerStatus::Error;
        }
        m_impl->NotifyCompletion(result);
        m_impl->NotifyError("Rollback file restoration failed",
                            ERROR_WRITE_FAULT);
        return false;
    }

    // Phase 4: Restoring config (already included in file restore).
    m_impl->UpdateProgress(RollbackState::RestoringConfig, 70,
                           "Configuration restored");

    // Phase 5: Starting services.
    m_impl->UpdateProgress(RollbackState::StartingServices, 80,
                           "Starting services");

    SS_LOG_INFO(kLogCategory, L"Starting services after rollback");

#ifdef _WIN32
    for (const auto* svcName : kServiceNames) {
        if (!RollbackManagerImpl::StartServiceIfInstalled(svcName)) {
            SS_LOG_WARN(kLogCategory,
                L"Service did not restart cleanly after rollback: %s",
                svcName);
        }
    }
#endif

    // Phase 6: Verify health.
    m_impl->UpdateProgress(RollbackState::Verifying, 90, "Verifying health");

    auto healthResult = PerformHealthCheck();
    bool healthOk = (healthResult.overallStatus == HealthStatus::Healthy ||
                     healthResult.overallStatus == HealthStatus::Degraded);

    if (!healthOk) {
        SS_LOG_ERROR(kLogCategory,
            L"CRITICAL: Health check failed after rollback to %S, "
            L"status=%S",
            snapshotId.c_str(),
            std::string(GetHealthStatusName(healthResult.overallStatus)).c_str());
        for (const auto& issue : healthResult.issues) {
            SS_LOG_ERROR(kLogCategory, L"  Issue: %S", issue.c_str());
        }
    }

    // Phase 7: Complete.
    const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now() - rollbackStart);

    result.success          = true;
    result.snapshotId       = snapshotId;
    result.restoredVersion  = snapshotInfo.versionString;
    result.filesRestored    = filesRestored;
    result.durationSeconds  = static_cast<uint32_t>(elapsed.count());
    result.rebootRequired   = (snapshotInfo.type == SnapshotType::Drivers);
    result.completionTime   = std::chrono::system_clock::now();

    m_impl->UpdateProgress(RollbackState::Completed, 100,
                           "Rollback completed",
                           filesRestored,
                           static_cast<uint32_t>(fileEntries.size()));

    // Update LKG if rollback succeeded and health is OK.
    if (healthOk) {
        std::unique_lock lock(m_impl->m_mutex);
        for (auto& s : m_impl->m_snapshots) {
            s.isCurrent = (s.snapshotId == snapshotId);
        }
        m_impl->m_lastKnownGoodId = snapshotId;
    }

    m_impl->m_stats.rollbacksPerformed++;
    m_impl->m_rollbackInProgress.store(false, std::memory_order_release);

    {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_status = RollbackManagerStatus::Running;
    }

    m_impl->NotifyCompletion(result);

    SS_LOG_INFO(kLogCategory,
        L"Rollback completed: snapshot=%S files=%u duration=%us reboot=%s health=%S",
        snapshotId.c_str(),
        filesRestored,
        result.durationSeconds,
        result.rebootRequired ? L"yes" : L"no",
        std::string(GetHealthStatusName(healthResult.overallStatus)).c_str());

    return true;
}

bool RollbackManager::CanRollback() const {
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    if (m_impl->m_rollbackInProgress.load(std::memory_order_acquire)) {
        return false;
    }

    std::shared_lock lock(m_impl->m_mutex);

    if (!m_impl->m_config.enabled) {
        return false;
    }

    // Must have at least one valid snapshot.
    return std::ranges::any_of(m_impl->m_snapshots,
        [](const SnapshotInfo& s) { return s.isValid; });
}

bool RollbackManager::IsRollbackInProgress() const noexcept {
    return m_impl->m_rollbackInProgress.load(std::memory_order_acquire);
}

RollbackProgress RollbackManager::GetProgress() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_currentProgress;
}

void RollbackManager::CancelRollback() {
    if (!m_impl->m_rollbackInProgress.load(std::memory_order_acquire)) {
        SS_LOG_DEBUG(kLogCategory,
            L"CancelRollback called but no rollback is in progress");
        return;
    }

    SS_LOG_WARN(kLogCategory,
        L"Rollback cancellation requested — note: already-restored files "
        L"will NOT be reverted");

    m_impl->m_rollbackInProgress.store(false, std::memory_order_release);

    {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_currentProgress.state = RollbackState::Failed;
        m_impl->m_currentProgress.errorMessage = "Cancelled by user";
        m_impl->m_status = RollbackManagerStatus::Running;
    }
}

// ============================================================================
// HEALTH VALIDATION
// ============================================================================

bool RollbackManager::VerifyStability() {
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    SS_LOG_DEBUG(kLogCategory, L"Verifying system stability");

    auto result = PerformHealthCheck();

    bool stable = (result.overallStatus == HealthStatus::Healthy) &&
                  !IsBootLoopDetected();

    if (stable) {
        SS_LOG_INFO(kLogCategory, L"System stability verified: Healthy");
    }
    else {
        SS_LOG_WARN(kLogCategory,
            L"System stability check failed: status=%S bootLoop=%s",
            std::string(GetHealthStatusName(result.overallStatus)).c_str(),
            IsBootLoopDetected() ? L"yes" : L"no");
    }

    return stable;
}

HealthCheckResult RollbackManager::PerformHealthCheck() {
    HealthCheckResult result;
    result.checkTime = std::chrono::system_clock::now();
    m_impl->m_stats.healthChecks++;

    SS_LOG_DEBUG(kLogCategory, L"Performing health check");

    // 1. Check if critical services are running.
    result.serviceRunning = false;
    for (const auto* svcName : kServiceNames) {
        const bool running = RollbackManagerImpl::IsServiceRunning(svcName);

        // Convert wide service name to UTF-8 for the component-status map.
        // The service names in kServiceNames are ASCII so a direct widen
        // cast is safe; we use WideCharToMultiByte for correctness even so.
        std::string narrowName;
#ifdef _WIN32
        const int needed = ::WideCharToMultiByte(
            CP_UTF8, 0, svcName, -1, nullptr, 0, nullptr, nullptr);
        if (needed > 1) {
            narrowName.resize(static_cast<size_t>(needed - 1));
            ::WideCharToMultiByte(CP_UTF8, 0, svcName, -1,
                                  narrowName.data(), needed, nullptr, nullptr);
        }
#else
        std::wstring ws(svcName);
        narrowName.assign(ws.begin(), ws.end());
#endif
        if (narrowName.empty()) {
            // Fall back to a stable placeholder so the map key is unique
            // per iteration even on conversion failure.
            narrowName = "Service:<unknown>";
        }
        else {
            narrowName = "Service:" + narrowName;
        }

        result.componentStatuses[narrowName] =
            running ? ComponentHealth::Running : ComponentHealth::Stopped;

        if (running) {
            result.serviceRunning = true;
        }
        else {
            result.issues.push_back("Service not running: " + narrowName);
        }
    }

    // 2. Check signature databases.
    {
        result.databasesValid = false;
        std::error_code ec;
        const fs::path installRoot = m_impl->m_snapshotBaseDir.parent_path()
                                                                .parent_path();
        bool foundDb = false;
        for (const auto& entry : fs::directory_iterator(installRoot, ec)) {
            if (ec) break;
            if (!entry.is_regular_file(ec) || ec) continue;
            const auto ext = entry.path().extension().wstring();
            if (ext == L".dat" || ext == L".db" || ext == L".sig") {
                foundDb = true;
                // Verify file is readable (non-zero size).
                const auto sz = fs::file_size(entry.path(), ec);
                if (ec || sz == 0) {
                    result.issues.push_back(
                        "Database file empty or unreadable: " +
                        entry.path().filename().string());
                    result.componentStatuses["Database:" +
                        entry.path().filename().string()] =
                        ComponentHealth::Corrupted;
                }
                else {
                    result.componentStatuses["Database:" +
                        entry.path().filename().string()] =
                        ComponentHealth::Running;
                }
            }
        }
        result.databasesValid = foundDb && result.issues.empty();
        if (!foundDb) {
            result.issues.push_back("No signature databases found");
            result.componentStatuses["SignatureDatabases"] =
                ComponentHealth::Missing;
        }
    }

    // 3. Check disk space.
    {
        const uint64_t freeSpace = GetAvailableDiskSpace(
            m_impl->m_snapshotBaseDir);
        if (freeSpace < kMinFreeDiskSpace) {
            result.issues.push_back(
                "Low disk space: " +
                std::to_string(freeSpace / (1024 * 1024)) + " MB free");
            result.componentStatuses["DiskSpace"] = ComponentHealth::Error;
        }
        else {
            result.componentStatuses["DiskSpace"] = ComponentHealth::Running;
        }
    }

    // 4. Basic network stack availability check. We intentionally do NOT
    //    call WSAStartup/WSACleanup here: WSACleanup is process-wide and
    //    decrements the reference count for any other component that has
    //    started Winsock, so calling it from a transient health probe
    //    could break unrelated subsystems. Instead, attempt to create a
    //    UDP socket; if it succeeds Winsock is already initialised and
    //    routable by some other component of the service, which is all
    //    the information this probe is supposed to report. A genuine
    //    connectivity check belongs in the update-transport layer.
    {
        result.networkConnected = false;
#ifdef _WIN32
        const SOCKET sock = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock != INVALID_SOCKET) {
            result.networkConnected = true;
            ::closesocket(sock);
        }
        if (!result.networkConnected) {
            result.issues.push_back("Network stack unavailable");
            result.componentStatuses["Network"] = ComponentHealth::Error;
        }
        else {
            result.componentStatuses["Network"] = ComponentHealth::Running;
        }
#endif
    }

    // 5. Boot/crash counts.
    {
        std::shared_lock lock(m_impl->m_mutex);
        result.bootCount  = m_impl->m_bootCount.load(std::memory_order_relaxed);
        result.crashCount = m_impl->m_crashCount.load(std::memory_order_relaxed);
        if (!m_impl->m_recentCrashes.empty()) {
            // Convert steady_clock to system_clock approximation.
            auto latest = m_impl->m_recentCrashes.back();
            auto offset = std::chrono::duration_cast<std::chrono::system_clock::duration>(
                Clock::now() - latest);
            result.lastCrashTime = std::chrono::system_clock::now() - offset;
        }
    }

    // 6. Self-test.
    result.selfTestPassed = SelfTest();
    if (!result.selfTestPassed) {
        result.issues.push_back("Self-test failed");
        result.componentStatuses["SelfTest"] = ComponentHealth::Error;
    }
    else {
        result.componentStatuses["SelfTest"] = ComponentHealth::Running;
    }

    // Determine overall status.
    if (result.issues.empty()) {
        result.overallStatus = HealthStatus::Healthy;
    }
    else if (result.serviceRunning && result.databasesValid) {
        result.overallStatus = HealthStatus::Degraded;
    }
    else if (!result.serviceRunning) {
        result.overallStatus = HealthStatus::Critical;
    }
    else {
        result.overallStatus = HealthStatus::Unhealthy;
    }

    // Check for boot loop override.
    if (IsBootLoopDetected()) {
        result.overallStatus = HealthStatus::BootLoop;
    }

    // Notify if status changed.
    HealthStatus previousStatus;
    {
        std::unique_lock lock(m_impl->m_mutex);
        previousStatus = m_impl->m_healthStatus;
        m_impl->m_healthStatus = result.overallStatus;
    }

    if (previousStatus != result.overallStatus) {
        SS_LOG_INFO(kLogCategory,
            L"Health status changed: %S -> %S",
            std::string(GetHealthStatusName(previousStatus)).c_str(),
            std::string(GetHealthStatusName(result.overallStatus)).c_str());
        m_impl->NotifyHealthChange(result.overallStatus);
    }

    SS_LOG_DEBUG(kLogCategory,
        L"Health check complete: status=%S issues=%zu",
        std::string(GetHealthStatusName(result.overallStatus)).c_str(),
        result.issues.size());

    return result;
}

HealthStatus RollbackManager::GetHealthStatus() const noexcept {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_healthStatus;
}

bool RollbackManager::IsBootLoopDetected() const {
    std::shared_lock lock(m_impl->m_mutex);

    if (!m_impl->m_config.enableBootLoopDetection) {
        return false;
    }

    const auto windowDuration = std::chrono::minutes(
        m_impl->m_config.bootLoopWindowMinutes);
    const auto cutoff = Clock::now() - windowDuration;

    uint32_t recentCrashCount = 0;
    for (const auto& t : m_impl->m_recentCrashes) {
        if (t >= cutoff) ++recentCrashCount;
    }

    return recentCrashCount >= m_impl->m_config.bootLoopThreshold;
}

void RollbackManager::RecordBoot() {
    SS_LOG_DEBUG(kLogCategory, L"Recording boot event");

    m_impl->m_bootCount++;

    {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_recentBoots.push_back(Clock::now());
        if (m_impl->m_recentBoots.size() > kMaxBootRecords) {
            m_impl->m_recentBoots.erase(m_impl->m_recentBoots.begin());
        }
        m_impl->PruneTimeWindow(m_impl->m_recentBoots,
            std::chrono::minutes(m_impl->m_config.bootLoopWindowMinutes));
    }

    // Check for boot loop after recording.
    if (IsBootLoopDetected()) {
        SS_LOG_ERROR(kLogCategory,
            L"BOOT LOOP DETECTED: %u crashes within %u minutes",
            m_impl->m_config.bootLoopThreshold,
            m_impl->m_config.bootLoopWindowMinutes);
        m_impl->m_stats.bootLoopsDetected++;

        if (m_impl->m_config.autoRollbackOnBootLoop) {
            SS_LOG_WARN(kLogCategory,
                L"Auto-rollback enabled, triggering rollback");
            m_impl->m_stats.autoRollbacks++;
            if (!TriggerRollback()) {
                SS_LOG_ERROR(kLogCategory,
                    L"Auto-rollback request failed (boot-loop path)");
            }
        }
    }
}

void RollbackManager::RecordCrash() {
    SS_LOG_WARN(kLogCategory, L"Recording crash event");

    m_impl->m_crashCount++;

    {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_recentCrashes.push_back(Clock::now());
        if (m_impl->m_recentCrashes.size() > kMaxBootRecords) {
            m_impl->m_recentCrashes.erase(m_impl->m_recentCrashes.begin());
        }
        m_impl->PruneTimeWindow(m_impl->m_recentCrashes,
            std::chrono::minutes(m_impl->m_config.bootLoopWindowMinutes));
    }

    // Check for boot loop after recording crash.
    if (IsBootLoopDetected()) {
        SS_LOG_ERROR(kLogCategory,
            L"BOOT LOOP DETECTED after crash: %u crashes within %u minutes",
            m_impl->m_config.bootLoopThreshold,
            m_impl->m_config.bootLoopWindowMinutes);
        m_impl->m_stats.bootLoopsDetected++;

        {
            std::unique_lock lock(m_impl->m_mutex);
            m_impl->m_healthStatus = HealthStatus::BootLoop;
        }
        m_impl->NotifyHealthChange(HealthStatus::BootLoop);

        if (m_impl->m_config.autoRollbackOnBootLoop) {
            SS_LOG_WARN(kLogCategory,
                L"Auto-rollback triggered due to boot loop");
            m_impl->m_stats.autoRollbacks++;
            if (!TriggerRollback()) {
                SS_LOG_ERROR(kLogCategory,
                    L"Auto-rollback request failed (crash path)");
            }
        }
    }
}

void RollbackManager::ClearBootLoopCounter() {
    SS_LOG_INFO(kLogCategory, L"Clearing boot loop counters");

    m_impl->m_bootCount.store(0, std::memory_order_relaxed);
    m_impl->m_crashCount.store(0, std::memory_order_relaxed);

    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_recentBoots.clear();
    m_impl->m_recentCrashes.clear();
}

// ============================================================================
// CALLBACKS
// ============================================================================

void RollbackManager::RegisterProgressCallback(
    RollbackProgressCallback callback)
{
    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_progressCallback = std::move(callback);
    SS_LOG_DEBUG(kLogCategory, L"Progress callback registered");
}

void RollbackManager::RegisterCompletionCallback(
    RollbackCompletionCallback callback)
{
    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_completionCallback = std::move(callback);
    SS_LOG_DEBUG(kLogCategory, L"Completion callback registered");
}

void RollbackManager::RegisterHealthChangeCallback(
    HealthChangeCallback callback)
{
    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_healthChangeCallback = std::move(callback);
    SS_LOG_DEBUG(kLogCategory, L"Health-change callback registered");
}

void RollbackManager::RegisterErrorCallback(ErrorCallback callback) {
    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_errorCallback = std::move(callback);
    SS_LOG_DEBUG(kLogCategory, L"Error callback registered");
}

void RollbackManager::UnregisterCallbacks() {
    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_progressCallback     = nullptr;
    m_impl->m_completionCallback   = nullptr;
    m_impl->m_healthChangeCallback = nullptr;
    m_impl->m_errorCallback        = nullptr;
    SS_LOG_DEBUG(kLogCategory, L"All callbacks unregistered");
}

// ============================================================================
// STATISTICS
// ============================================================================

RollbackStatistics RollbackManager::GetStatistics() const {
    RollbackStatistics copy;
    copy.snapshotsCreated = m_impl->m_stats.snapshotsCreated;
    copy.snapshotsDeleted = m_impl->m_stats.snapshotsDeleted;
    copy.rollbacksPerformed = m_impl->m_stats.rollbacksPerformed;
    copy.rollbacksFailed = m_impl->m_stats.rollbacksFailed;
    copy.bootLoopsDetected = m_impl->m_stats.bootLoopsDetected;
    copy.autoRollbacks = m_impl->m_stats.autoRollbacks;
    copy.healthChecks = m_impl->m_stats.healthChecks;
    copy.startTime = m_impl->m_stats.startTime;
    return copy;
}

void RollbackManager::ResetStatistics() {
    SS_LOG_DEBUG(kLogCategory, L"Resetting statistics");
    m_impl->m_stats.Reset();
}

bool RollbackManager::SelfTest() {
    SS_LOG_DEBUG(kLogCategory, L"Running self-test");

    // Test 1: Verify hashing infrastructure.
    {
        const std::string testData = "ShadowStrike-RollbackManager-SelfTest";
        std::vector<uint8_t> digest;
        if (!HU::Compute(HU::Algorithm::SHA256,
                         testData.data(), testData.size(), digest)) {
            SS_LOG_ERROR(kLogCategory,
                L"Self-test FAILED: SHA-256 computation error");
            return false;
        }
        if (digest.size() != 32) {
            SS_LOG_ERROR(kLogCategory,
                L"Self-test FAILED: SHA-256 digest size mismatch (%zu)",
                digest.size());
            return false;
        }
        std::string hex = HU::ToHexLower(digest);
        if (hex.size() != 64) {
            SS_LOG_ERROR(kLogCategory,
                L"Self-test FAILED: hex encoding error");
            return false;
        }
    }

    // Test 2: Verify snapshot directory is accessible.
    {
        std::error_code ec;
        if (!fs::exists(m_impl->m_snapshotBaseDir, ec) || ec) {
            SS_LOG_ERROR(kLogCategory,
                L"Self-test FAILED: snapshot directory not accessible: %s",
                m_impl->m_snapshotBaseDir.wstring().c_str());
            return false;
        }
    }

    // Test 3: Verify snapshot ID generation produces valid IDs.
    {
        auto id1 = GenerateSnapshotId();
        auto id2 = GenerateSnapshotId();
        if (id1.empty() || id2.empty() || id1 == id2) {
            SS_LOG_ERROR(kLogCategory,
                L"Self-test FAILED: snapshot ID generation error");
            return false;
        }
        if (!RollbackManagerImpl::IsValidSnapshotId(id1) ||
            !RollbackManagerImpl::IsValidSnapshotId(id2))
        {
            SS_LOG_ERROR(kLogCategory,
                L"Self-test FAILED: generated snapshot ID validation error");
            return false;
        }
    }

    SS_LOG_DEBUG(kLogCategory, L"Self-test PASSED");
    return true;
}

std::string RollbackManager::GetVersionString() noexcept {
    try {
        return std::to_string(RollbackConstants::VERSION_MAJOR) + "." +
               std::to_string(RollbackConstants::VERSION_MINOR) + "." +
               std::to_string(RollbackConstants::VERSION_PATCH);
    }
    catch (...) { return "0.0.0"; }
}

// ============================================================================
// STRUCT SERIALIZATION
// ============================================================================

std::string SnapshotInfo::ToJson() const {
    std::ostringstream js;
    js << "{"
       << "\"snapshotId\":\"" << JsonEscape(snapshotId) << "\","
       << "\"type\":\"" << GetSnapshotTypeName(type) << "\","
       << "\"created\":\"" << FormatIso8601(createdTime) << "\","
       << "\"version\":\"" << JsonEscape(versionString) << "\","
       << "\"description\":\"" << JsonEscape(description) << "\","
       << "\"sizeBytes\":" << sizeBytes << ","
       << "\"fileCount\":" << fileCount << ","
       << "\"snapshotPath\":\"" << JsonEscape(snapshotPath.generic_string()) << "\","
       << "\"isCurrent\":" << (isCurrent ? "true" : "false") << ","
       << "\"isValid\":" << (isValid ? "true" : "false")
       << "}";
    return js.str();
}

std::string HealthCheckResult::ToJson() const {
    std::ostringstream js;
    js << "{"
       << "\"overallStatus\":\"" << GetHealthStatusName(overallStatus) << "\","
       << "\"serviceRunning\":" << (serviceRunning ? "true" : "false") << ","
       << "\"guiAccessible\":" << (guiAccessible ? "true" : "false") << ","
       << "\"databasesValid\":" << (databasesValid ? "true" : "false") << ","
       << "\"networkConnected\":" << (networkConnected ? "true" : "false") << ","
       << "\"selfTestPassed\":" << (selfTestPassed ? "true" : "false") << ","
       << "\"bootCount\":" << bootCount << ","
       << "\"crashCount\":" << crashCount << ","
       << "\"checkTime\":\"" << FormatIso8601(checkTime) << "\","
       << "\"issues\":[";
    for (size_t i = 0; i < issues.size(); ++i) {
        js << "\"" << JsonEscape(issues[i]) << "\"";
        if (i + 1 < issues.size()) js << ",";
    }
    js << "],"
       << "\"components\":{";
    size_t ci = 0;
    for (const auto& [name, health] : componentStatuses) {
        js << "\"" << JsonEscape(name) << "\":\""
           << GetComponentHealthName(health) << "\"";
        if (++ci < componentStatuses.size()) js << ",";
    }
    js << "}}";
    return js.str();
}

std::string RollbackProgress::ToJson() const {
    std::ostringstream js;
    js << "{"
       << "\"state\":\"" << GetRollbackStateName(state) << "\","
       << "\"progressPercent\":" << static_cast<int>(progressPercent) << ","
       << "\"currentOperation\":\"" << JsonEscape(currentOperation) << "\","
       << "\"filesRestored\":" << filesRestored << ","
       << "\"filesTotal\":" << filesTotal << ","
       << "\"errorMessage\":\"" << JsonEscape(errorMessage) << "\""
       << "}";
    return js.str();
}

std::string RollbackResult::ToJson() const {
    std::ostringstream js;
    js << "{"
       << "\"success\":" << (success ? "true" : "false") << ","
       << "\"snapshotId\":\"" << JsonEscape(snapshotId) << "\","
       << "\"restoredVersion\":\"" << JsonEscape(restoredVersion) << "\","
       << "\"filesRestored\":" << filesRestored << ","
       << "\"durationSeconds\":" << durationSeconds << ","
       << "\"rebootRequired\":" << (rebootRequired ? "true" : "false") << ","
       << "\"errorMessage\":\"" << JsonEscape(errorMessage) << "\","
       << "\"completionTime\":\"" << FormatIso8601(completionTime) << "\""
       << "}";
    return js.str();
}

void RollbackStatistics::Reset() noexcept {
    snapshotsCreated = 0;
    snapshotsDeleted = 0;
    rollbacksPerformed = 0;
    rollbacksFailed = 0;
    bootLoopsDetected = 0;
    autoRollbacks = 0;
    healthChecks = 0;
    startTime = Clock::now();
}

std::string RollbackStatistics::ToJson() const {
    const auto uptimeSec = std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now() - startTime).count();
    std::ostringstream js;
    js << "{"
       << "\"snapshotsCreated\":" << snapshotsCreated << ","
       << "\"snapshotsDeleted\":" << snapshotsDeleted << ","
       << "\"rollbacksPerformed\":" << rollbacksPerformed << ","
       << "\"rollbacksFailed\":" << rollbacksFailed << ","
       << "\"bootLoopsDetected\":" << bootLoopsDetected << ","
       << "\"autoRollbacks\":" << autoRollbacks << ","
       << "\"healthChecks\":" << healthChecks << ","
       << "\"uptimeSeconds\":" << uptimeSec
       << "}";
    return js.str();
}

bool RollbackManagerConfiguration::IsValid() const noexcept {
    if (maxSnapshots == 0 || maxSnapshots > 100) return false;
    if (bootLoopThreshold == 0 || bootLoopThreshold > 50) return false;
    if (bootLoopWindowMinutes == 0 || bootLoopWindowMinutes > 1440) return false;
    if (healthCheckTimeoutSeconds == 0 || healthCheckTimeoutSeconds > 300) return false;
    return true;
}

// ============================================================================
// UTILITY FUNCTIONS (FREE FUNCTIONS)
// ============================================================================

std::string_view GetSnapshotTypeName(SnapshotType type) noexcept {
    switch (type) {
    case SnapshotType::Full:          return "Full";
    case SnapshotType::Incremental:   return "Incremental";
    case SnapshotType::Configuration: return "Configuration";
    case SnapshotType::Database:      return "Database";
    case SnapshotType::Drivers:       return "Drivers";
    case SnapshotType::Emergency:     return "Emergency";
    default:                          return "Unknown";
    }
}

std::string_view GetRollbackStateName(RollbackState state) noexcept {
    switch (state) {
    case RollbackState::Idle:            return "Idle";
    case RollbackState::Preparing:       return "Preparing";
    case RollbackState::StoppingServices: return "StoppingServices";
    case RollbackState::RestoringFiles:  return "RestoringFiles";
    case RollbackState::RestoringConfig: return "RestoringConfig";
    case RollbackState::RestoringDrivers: return "RestoringDrivers";
    case RollbackState::StartingServices: return "StartingServices";
    case RollbackState::Verifying:       return "Verifying";
    case RollbackState::Completed:       return "Completed";
    case RollbackState::Failed:          return "Failed";
    default:                             return "Unknown";
    }
}

std::string_view GetHealthStatusName(HealthStatus status) noexcept {
    switch (status) {
    case HealthStatus::Unknown:   return "Unknown";
    case HealthStatus::Healthy:   return "Healthy";
    case HealthStatus::Degraded:  return "Degraded";
    case HealthStatus::Unhealthy: return "Unhealthy";
    case HealthStatus::Critical:  return "Critical";
    case HealthStatus::BootLoop:  return "BootLoop";
    default:                      return "Unknown";
    }
}

std::string_view GetComponentHealthName(ComponentHealth health) noexcept {
    switch (health) {
    case ComponentHealth::Unknown:   return "Unknown";
    case ComponentHealth::Running:   return "Running";
    case ComponentHealth::Stopped:   return "Stopped";
    case ComponentHealth::Error:     return "Error";
    case ComponentHealth::Missing:   return "Missing";
    case ComponentHealth::Corrupted: return "Corrupted";
    default:                         return "Unknown";
    }
}

std::string GenerateSnapshotId() {
    // Format: YYYYMMDD-HHMMSS-<8 hex random>
    const auto now = std::chrono::system_clock::now();
    const auto tt  = std::chrono::system_clock::to_time_t(now);
    std::tm tmBuf{};
    (void)gmtime_s(&tmBuf, &tt);

    char timePart[20]{};
    (void)std::strftime(timePart, sizeof(timePart), "%Y%m%d-%H%M%S", &tmBuf);

    // Cryptographically random suffix.
    std::array<uint8_t, 4> randomBytes{};
#ifdef _WIN32
    HCRYPTPROV hProv = 0;
    if (::CryptAcquireContextW(&hProv, nullptr, nullptr,
                                PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        ::CryptGenRandom(hProv, static_cast<DWORD>(randomBytes.size()),
                         randomBytes.data());
        ::CryptReleaseContext(hProv, 0);
    }
    else
#endif
    {
        // Fallback to thread-local Mersenne Twister seeded from random_device.
        thread_local std::mt19937 rng(std::random_device{}());
        std::uniform_int_distribution<int> dist(0, 255);
        for (auto& b : randomBytes) b = static_cast<uint8_t>(dist(rng));
    }

    std::string hex = HU::ToHexLower(randomBytes.data(), randomBytes.size());
    return std::string(timePart) + "-" + hex;
}

uint64_t CalculateSnapshotSize(const fs::path& directory) {
    uint64_t totalSize = 0;
    std::error_code ec;

    if (!fs::exists(directory, ec) || ec) return 0;

    for (const auto& entry : fs::recursive_directory_iterator(directory, ec)) {
        if (ec) break;
        if (entry.is_regular_file(ec) && !ec) {
            const auto sz = entry.file_size(ec);
            if (!ec) totalSize += sz;
        }
    }

    return totalSize;
}

}  // namespace Update
}  // namespace ShadowStrike
