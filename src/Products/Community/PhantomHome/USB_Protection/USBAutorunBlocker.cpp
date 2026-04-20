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
 * ShadowStrike NGAV - USB AUTORUN BLOCKER IMPLEMENTATION
 * ============================================================================
 *
 * @file USBAutorunBlocker.cpp
 * @brief Implementation of the enterprise USB autorun protection engine.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "pch.h"
#include "USBAutorunBlocker.hpp"

// ============================================================================
// STANDARD LIBRARY
// ============================================================================
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <set>
#include <cctype>
#include <cstdio>

// ============================================================================
// WINDOWS SDK
// ============================================================================
#include <aclapi.h>
#include <sddl.h>

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE
// ============================================================================
#include "PhantomCore/Core/Engine/QuarantineManager.hpp"
#include "PhantomCore/ThreatIntel/ThreatIntelManager.hpp"
#include <atomic>

namespace ShadowStrike {
namespace USB {

// ============================================================================
// LOGGING CATEGORY
// ============================================================================
static constexpr const wchar_t* LOG_CAT = L"AutorunBlk";

// ============================================================================
// STATIC INITIALIZATION
// ============================================================================
std::atomic<bool> USBAutorunBlocker::s_instanceCreated{false};

// ============================================================================
// ANONYMOUS HELPER UTILITIES
// ============================================================================
namespace {
    constexpr size_t kMaxAutorunLines = 4096;
    constexpr size_t kMaxAutorunLineLength = 4096;
    constexpr size_t kMaxAutorunFieldLength = 1024;

    template<typename T>
    [[nodiscard]] T AtomicValueLoadRelaxed(const T& value) noexcept {
        return std::atomic_ref<T>(const_cast<T&>(value)).load(std::memory_order_relaxed);
    }
    template<typename T>
    void AtomicValueStoreRelaxed(T& target, const T& value) noexcept {
        std::atomic_ref<T>(target).store(value, std::memory_order_relaxed);
    }


    /// RAII wrapper for Win32 HANDLE (file handles from CreateFileW).
    struct ScopedHandle {
        HANDLE h = INVALID_HANDLE_VALUE;
        ScopedHandle() = default;
        explicit ScopedHandle(HANDLE handle) noexcept : h(handle) {}
        ~ScopedHandle() { if (h != INVALID_HANDLE_VALUE) ::CloseHandle(h); }
        ScopedHandle(const ScopedHandle&) = delete;
        ScopedHandle& operator=(const ScopedHandle&) = delete;
        ScopedHandle(ScopedHandle&& o) noexcept : h(o.h) { o.h = INVALID_HANDLE_VALUE; }
        ScopedHandle& operator=(ScopedHandle&& o) noexcept {
            if (this != &o) {
                if (h != INVALID_HANDLE_VALUE) ::CloseHandle(h);
                h = o.h;
                o.h = INVALID_HANDLE_VALUE;
            }
            return *this;
        }
        [[nodiscard]] bool IsValid() const noexcept { return h != INVALID_HANDLE_VALUE; }
        [[nodiscard]] HANDLE Get() const noexcept { return h; }
    };

    std::string Trim(const std::string& str) {
        auto start = str.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) return {};
        auto end = str.find_last_not_of(" \t\r\n");
        return str.substr(start, end - start + 1);
    }

    bool ContainsCaseInsensitive(std::string_view str, std::string_view substr) {
        if (substr.empty()) return true;
        if (substr.size() > str.size()) return false;
        auto it = std::search(
            str.begin(), str.end(),
            substr.begin(), substr.end(),
            [](char a, char b) {
                return std::tolower(static_cast<unsigned char>(a)) ==
                       std::tolower(static_cast<unsigned char>(b));
            }
        );
        return it != str.end();
    }

    SystemTimePoint ToSystemTime([[maybe_unused]] const TimePoint& tp) {
        return std::chrono::system_clock::now() +
               std::chrono::duration_cast<std::chrono::system_clock::duration>(tp - Clock::now());
    }

    std::string SerializeTime(const SystemTimePoint& tp) {
        auto tt = std::chrono::system_clock::to_time_t(tp);
        std::tm tm{};
        gmtime_s(&tm, &tt);
        char buffer[32];
        std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &tm);
        return std::string(buffer);
    }

    std::string EscapeJson(const std::string& s) {
        std::ostringstream o;
        for (char c : s) {
            switch (c) {
                case '"':  o << "\\\""; break;
                case '\\': o << "\\\\"; break;
                case '\b': o << "\\b";  break;
                case '\f': o << "\\f";  break;
                case '\n': o << "\\n";  break;
                case '\r': o << "\\r";  break;
                case '\t': o << "\\t";  break;
                default:
                    if (static_cast<unsigned char>(c) < 0x20) {
                        o << "\\u" << std::hex << std::setw(4)
                          << std::setfill('0') << static_cast<int>(c);
                    } else {
                        o << c;
                    }
            }
        }
        return o.str();
    }

    /// Convert a 32-byte SHA-256 digest to lowercase hex string.
    std::string BytesToHexString(const std::array<uint8_t, 32>& bytes) {
        static constexpr char kHex[] = "0123456789abcdef";
        std::string hex;
        hex.reserve(64);
        for (uint8_t b : bytes) {
            hex.push_back(kHex[b >> 4]);
            hex.push_back(kHex[b & 0x0F]);
        }
        return hex;
    }

    /// Lowercase an ASCII string in-place.
    void LowercaseASCII(std::string& s) {
        std::transform(s.begin(), s.end(), s.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    }

    [[nodiscard]] std::string StripControlCharacters(std::string_view input) {
        std::string output;
        output.reserve(std::min(input.size(), kMaxAutorunFieldLength));

        for (unsigned char ch : input) {
            if (output.size() >= kMaxAutorunFieldLength) {
                break;
            }

            if (ch == '\r' || ch == '\n' || ch == '\0') {
                continue;
            }

            if (ch < 0x20 && ch != '\t') {
                continue;
            }

            output.push_back(static_cast<char>(ch));
        }

        return output;
    }

    /// Returns true if the autorun key typically references a file path.
    bool IsFileReferenceKey(std::string_view key) {
        std::string lower(key);
        LowercaseASCII(lower);
        if (lower == "open" || lower == "shellexecute" || lower == "icon") return true;
        if (lower.starts_with("shell\\") && lower.ends_with("\\command")) return true;
        return false;
    }

    /// C5: Check if a path string contains dangerous / evasion patterns.
    bool IsDangerousPathCheck(std::string_view path) {
        if (path.empty()) return true;

        // Overly long paths
        if (path.size() > MAX_PATH) return true;

        std::string lower(path);
        LowercaseASCII(lower);

        // Path traversal sequences
        if (lower.find("..") != std::string::npos) return true;

        // UNC paths (\\server\share)
        if (lower.size() >= 2 && lower[0] == '\\' && lower[1] == '\\') return true;

        // Alternate data streams — colon after the drive-letter position
        for (size_t i = 2; i < lower.size(); ++i) {
            if (lower[i] == ':') return true;
        }

        // Hidden/system extensions commonly abused for disguise
        static constexpr std::string_view kDangerousExts[] = {
            ".scr", ".pif", ".com", ".bat", ".cmd", ".vbs",
            ".js", ".wsh", ".wsf", ".hta", ".cpl"
        };
        for (auto ext : kDangerousExts) {
            if (lower.size() >= ext.size() &&
                lower.compare(lower.size() - ext.size(), ext.size(), ext) == 0) {
                return true;
            }
        }

        // Known malware directory patterns on USB drives
        static constexpr std::string_view kMalwareDirs[] = {
            "recycler", "$recycle.bin", "system volume information"
        };
        for (auto pattern : kMalwareDirs) {
            if (ContainsCaseInsensitive(lower, pattern)) return true;
        }

        return false;
    }

}  // anonymous namespace

// ============================================================================
// STRUCTURE IMPLEMENTATIONS
// ============================================================================

std::string AutorunEntry::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"section\":\"" << EscapeJson(section) << "\","
        << "\"key\":\"" << EscapeJson(key) << "\","
        << "\"value\":\"" << EscapeJson(value) << "\","
        << "\"lineNumber\":" << lineNumber << ","
        << "\"isDangerous\":" << (isDangerous ? "true" : "false") << ","
        << "\"threatType\":" << static_cast<int>(threatType)
        << "}";
    return oss.str();
}

std::string AutorunAnalysisResult::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"fileExists\":" << (fileExists ? "true" : "false") << ","
        << "\"isMalicious\":" << (isMalicious ? "true" : "false") << ","
        << "\"riskScore\":" << riskScore << ","
        << "\"primaryThreat\":" << static_cast<int>(primaryThreat) << ","
        << "\"entriesCount\":" << entries.size() << ","
        << "\"dangerousEntriesCount\":" << dangerousEntries.size() << ","
        << "\"openCommand\":\"" << EscapeJson(openCommand) << "\","
        << "\"actionCommand\":\"" << EscapeJson(actionCommand) << "\","
        << "\"sha256\":\"" << sha256 << "\","
        << "\"fileSize\":" << fileSize << ","
        << "\"analysisTime\":\"" << SerializeTime(analysisTime) << "\""
        << "}";
    return oss.str();
}

std::string EnforcementResult::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"action\":" << static_cast<int>(action) << ","
        << "\"success\":" << (success ? "true" : "false") << ","
        << "\"analysis\":" << analysis.ToJson() << ","
        << "\"linesRemovedCount\":" << linesRemoved.size() << ","
        << "\"errorMessage\":\"" << EscapeJson(errorMessage) << "\","
        << "\"enforcementTime\":\"" << SerializeTime(enforcementTime) << "\","
        << "\"durationUs\":" << duration.count()
        << "}";
    return oss.str();
}

std::string VaccinationResult::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"status\":" << static_cast<int>(status) << ","
        << "\"success\":" << (success ? "true" : "false") << ","
        << "\"drivePath\":\"" << EscapeJson(drivePath) << "\","
        << "\"errorMessage\":\"" << EscapeJson(errorMessage) << "\","
        << "\"vaccinationTime\":\"" << SerializeTime(vaccinationTime) << "\""
        << "}";
    return oss.str();
}

void AutorunStatistics::Reset() noexcept {
    drivesScanned.store(0, std::memory_order_relaxed);
    autorunFilesFound.store(0, std::memory_order_relaxed);
    maliciousDetected.store(0, std::memory_order_relaxed);
    filesBlocked.store(0, std::memory_order_relaxed);
    filesSanitized.store(0, std::memory_order_relaxed);
    filesDeleted.store(0, std::memory_order_relaxed);
    filesQuarantined.store(0, std::memory_order_relaxed);
    drivesVaccinated.store(0, std::memory_order_relaxed);
    vaccinationFailures.store(0, std::memory_order_relaxed);
    for (auto& count : byThreatType) count.store(0, std::memory_order_relaxed);
    AtomicValueStoreRelaxed(startTime, Clock::now());
}

// H3: AutorunStatisticsSnapshot::ToJson – the copyable snapshot type.
std::string AutorunStatisticsSnapshot::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"drivesScanned\":" << drivesScanned << ","
        << "\"autorunFilesFound\":" << autorunFilesFound << ","
        << "\"maliciousDetected\":" << maliciousDetected << ","
        << "\"filesBlocked\":" << filesBlocked << ","
        << "\"filesSanitized\":" << filesSanitized << ","
        << "\"filesDeleted\":" << filesDeleted << ","
        << "\"filesQuarantined\":" << filesQuarantined << ","
        << "\"drivesVaccinated\":" << drivesVaccinated << ","
        << "\"vaccinationFailures\":" << vaccinationFailures << ","
        << "\"uptimeSeconds\":"
        << std::chrono::duration_cast<std::chrono::seconds>(Clock::now() - AtomicValueLoadRelaxed(startTime)).count()
        << "}";
    return oss.str();
}

bool AutorunBlockerConfiguration::IsValid() const noexcept {
    // Policy mode must be in valid range
    return static_cast<uint8_t>(policyMode) <= static_cast<uint8_t>(AutorunPolicyMode::AllowTrusted);
}

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class USBAutorunBlockerImpl {
public:
    USBAutorunBlockerImpl() = default;
    ~USBAutorunBlockerImpl() { Shutdown(); }

    USBAutorunBlockerImpl(const USBAutorunBlockerImpl&) = delete;
    USBAutorunBlockerImpl& operator=(const USBAutorunBlockerImpl&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(const AutorunBlockerConfiguration& config) {
        std::unique_lock lock(m_configMutex);
        auto status = m_status.load(std::memory_order_acquire);
        if (status != AutorunModuleStatus::Uninitialized &&
            status != AutorunModuleStatus::Stopped) {
            return status == AutorunModuleStatus::Running;
        }

        if (!config.IsValid()) {
            SS_LOG_ERROR(LOG_CAT, L"Invalid configuration supplied to Initialize");
            return false;
        }

        m_status.store(AutorunModuleStatus::Initializing, std::memory_order_release);
        m_config = config;
        m_stats.Reset();
        m_status.store(AutorunModuleStatus::Running, std::memory_order_release);

        SS_LOG_INFO(LOG_CAT, L"USB Autorun Blocker initialized – policy=%hs",
            std::string(GetAutorunPolicyModeName(config.policyMode)).c_str());
        return true;
    }

    void Shutdown() {
        std::unique_lock lock(m_configMutex);
        auto status = m_status.load(std::memory_order_acquire);
        if (status == AutorunModuleStatus::Stopped ||
            status == AutorunModuleStatus::Uninitialized) {
            return;
        }
        m_status.store(AutorunModuleStatus::Stopping, std::memory_order_release);
        SS_LOG_INFO(LOG_CAT, L"USB Autorun Blocker shutting down");
        m_status.store(AutorunModuleStatus::Stopped, std::memory_order_release);
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        return m_status.load(std::memory_order_acquire) == AutorunModuleStatus::Running;
    }

    [[nodiscard]] AutorunModuleStatus GetStatus() const noexcept {
        return m_status.load(std::memory_order_acquire);
    }

    [[nodiscard]] bool UpdateConfiguration(const AutorunBlockerConfiguration& config) {
        if (!config.IsValid()) {
            SS_LOG_ERROR(LOG_CAT, L"Invalid configuration in UpdateConfiguration");
            return false;
        }
        std::unique_lock lock(m_configMutex);
        m_config = config;
        SS_LOG_INFO(LOG_CAT, L"Configuration updated – policy=%hs",
            std::string(GetAutorunPolicyModeName(config.policyMode)).c_str());
        return true;
    }

    [[nodiscard]] AutorunBlockerConfiguration GetConfiguration() const {
        std::shared_lock lock(m_configMutex);
        return m_config;
    }

    // ========================================================================
    // ENFORCEMENT
    // ========================================================================

    [[nodiscard]] EnforcementResult EnforcePolicy(const std::string& driveRoot) {
        EnforcementResult result;
        result.enforcementTime = std::chrono::system_clock::now();
        auto start = Clock::now();

        if (!IsInitialized()) {
            result.errorMessage = "Module not initialized";
            NotifyError(result.errorMessage, -1);
            return result;
        }

        // Snapshot config once for the entire enforcement operation
        AutorunBlockerConfiguration cfg = GetConfiguration();

        m_stats.drivesScanned.fetch_add(1, std::memory_order_relaxed);

        // 1. Find autorun.inf
        auto autorunPathOpt = FindAutorunFile(driveRoot);
        if (!autorunPathOpt) {
            if (cfg.autoVaccinate) {
                VaccinateDrive(driveRoot);
            }
            result.success = true;
            result.action = AutorunAction::Allowed;
            result.duration = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start);
            return result;
        }

        std::filesystem::path autorunPath = *autorunPathOpt;

        // 2. Check if it's our vaccine folder
        try {
            if (std::filesystem::is_directory(autorunPath)) {
                result.success = true;
                result.action = AutorunAction::Vaccinated;
                result.duration = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start);
                return result;
            }
        } catch (const std::exception& e) {
            SS_LOG_WARN(LOG_CAT, L"Error checking vaccine status: %hs", e.what());
        }

        // 3. Analyze
        result.analysis = AnalyzeAutorunFile(autorunPath);

        // 4. Decide action
        result.action = DetermineAction(result.analysis, cfg);

        // 5. Execute action
        result.success = ExecuteAction(autorunPath, result, cfg);

        // 6. Vaccinate after removal
        if (result.success &&
            (result.action == AutorunAction::Deleted ||
             result.action == AutorunAction::Quarantined)) {
            if (cfg.autoVaccinate) {
                VaccinateDrive(driveRoot);
            }
        }

        result.duration = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start);

        SS_LOG_INFO(LOG_CAT, L"Enforcement on %hs – action=%hs success=%s duration=%lldus",
            driveRoot.c_str(),
            std::string(GetAutorunActionName(result.action)).c_str(),
            result.success ? L"true" : L"false",
            static_cast<long long>(result.duration.count()));

        // H2: Copy callback under lock, invoke outside
        InvokeEnforcementCallback(result);

        return result;
    }

    [[nodiscard]] EnforcementResult EnforcePolicyOnFile(const std::filesystem::path& autorunPath) {
        EnforcementResult result;
        result.enforcementTime = std::chrono::system_clock::now();
        auto start = Clock::now();

        if (!IsInitialized()) {
            result.errorMessage = "Module not initialized";
            NotifyError(result.errorMessage, -1);
            return result;
        }

        AutorunBlockerConfiguration cfg = GetConfiguration();

        try {
            if (!std::filesystem::exists(autorunPath)) {
                result.errorMessage = "File not found";
                return result;
            }
            if (std::filesystem::is_directory(autorunPath)) {
                result.success = true;
                result.action = AutorunAction::Vaccinated;
                return result;
            }
        } catch (const std::exception& e) {
            result.errorMessage = std::string("Filesystem error: ") + e.what();
            return result;
        }

        result.analysis = AnalyzeAutorunFile(autorunPath);
        result.action = DetermineAction(result.analysis, cfg);
        result.success = ExecuteAction(autorunPath, result, cfg);
        result.duration = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start);

        InvokeEnforcementCallback(result);
        return result;
    }

    // ========================================================================
    // ANALYSIS
    // ========================================================================

    [[nodiscard]] AutorunAnalysisResult AnalyzeDrive(const std::string& driveRoot) {
        m_stats.drivesScanned.fetch_add(1, std::memory_order_relaxed);
        auto pathOpt = FindAutorunFile(driveRoot);
        if (pathOpt) return AnalyzeAutorunFile(*pathOpt);
        return AutorunAnalysisResult{};
    }

    [[nodiscard]] AutorunAnalysisResult AnalyzeAutorunFile(
            const std::filesystem::path& autorunPath) {
        AutorunAnalysisResult result;
        result.analysisTime = std::chrono::system_clock::now();

        std::wstring widePath = autorunPath.wstring();

        // C6: TOCTOU prevention — open with exclusive-write lock for the
        //     duration of analysis so the file cannot be swapped underneath us.
        ScopedHandle lockHandle(::CreateFileW(
            widePath.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,   // allow concurrent reads but block writes/deletes
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr));

        if (!lockHandle.IsValid()) {
            DWORD err = ::GetLastError();
            if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) {
                result.fileExists = false;
            } else {
                result.fileExists = true;
                SS_LOG_WARN(LOG_CAT, L"Cannot lock autorun file for analysis (err=%lu): %ls",
                    static_cast<unsigned long>(err), widePath.c_str());
            }
            return result;
        }
        result.fileExists = true;

        // Get file size from the locked handle
        LARGE_INTEGER fileSizeLI{};
        if (!::GetFileSizeEx(lockHandle.Get(), &fileSizeLI)) {
            SS_LOG_WARN(LOG_CAT, L"GetFileSizeEx failed for %ls", widePath.c_str());
            return result;
        }
        result.fileSize = static_cast<size_t>(fileSizeLI.QuadPart);

        if (result.fileSize > AutorunConstants::MAX_AUTORUN_SIZE) {
            result.riskScore += 20;
            SS_LOG_WARN(LOG_CAT, L"Autorun file exceeds size cap (%zu bytes): %ls",
                result.fileSize, widePath.c_str());
        }

        // C1: Compute SHA-256 hash while the file is write-locked.
        //     ComputeFileSHA256 opens a second read handle which is compatible
        //     with our FILE_SHARE_READ lock.
        {
            std::array<uint8_t, 32> hashBytes{};
            Utils::FileUtils::Error hashErr;
            if (Utils::FileUtils::ComputeFileSHA256(widePath, hashBytes, &hashErr)) {
                result.sha256 = BytesToHexString(hashBytes);
            } else {
                SS_LOG_WARN(LOG_CAT, L"SHA-256 computation failed for %ls: %hs",
                    widePath.c_str(), hashErr.message.c_str());
            }
        }

        // Read content for parsing (capped at MAX_AUTORUN_SIZE)
        std::string content;
        {
            Utils::FileUtils::Error readErr;
            if (!Utils::FileUtils::ReadAllTextUtf8(widePath, content, &readErr)) {
                SS_LOG_WARN(LOG_CAT, L"Failed to read autorun content for %ls: %hs",
                    widePath.c_str(), readErr.message.c_str());
                return result;
            }
        }
        if (content.size() > AutorunConstants::MAX_AUTORUN_SIZE) {
            content.resize(AutorunConstants::MAX_AUTORUN_SIZE);
        }

        // Parse
        result.entries = ParseAutorunContent(content);

        // Drive root for path validation (C7)
        std::wstring driveRootW = autorunPath.parent_path().wstring();

        // Analyze entries
        for (auto& entry : result.entries) {
            if (entry.isDangerous) {
                result.dangerousEntries.push_back(entry);
                result.riskScore += 25;

                if (result.primaryThreat == AutorunThreatType::None) {
                    result.primaryThreat = entry.threatType;
                }

                std::string lk = entry.key;
                LowercaseASCII(lk);
                if (lk == "open")           result.openCommand = entry.value;
                if (lk == "icon")           result.iconPath    = entry.value;
                if (lk == "label")          result.label       = entry.value;
                if (lk == "action")         result.actionCommand = entry.value;
                if (lk.starts_with("shell\\") && lk.ends_with("\\command"))
                    result.actionCommand = entry.value;

                // Heuristic: suspicious script/binary extensions in value
                if (ContainsCaseInsensitive(entry.value, ".vbs") ||
                    ContainsCaseInsensitive(entry.value, ".js")  ||
                    ContainsCaseInsensitive(entry.value, ".cmd") ||
                    ContainsCaseInsensitive(entry.value, ".bat") ||
                    ContainsCaseInsensitive(entry.value, ".scr") ||
                    ContainsCaseInsensitive(entry.value, ".pif") ||
                    ContainsCaseInsensitive(entry.value, ".hta")) {
                    result.riskScore += 30;
                }

                // Per-threat-type counter
                auto idx = static_cast<size_t>(entry.threatType);
                if (idx < m_stats.byThreatType.size()) {
                    m_stats.byThreatType[idx].fetch_add(1, std::memory_order_relaxed);
                }
            }

            // Extract metadata from benign keys
            if (!entry.isDangerous) {
                std::string lk = entry.key;
                LowercaseASCII(lk);
                if (lk == "icon"   && result.iconPath.empty())      result.iconPath = entry.value;
                if (lk == "label"  && result.label.empty())         result.label    = entry.value;
                if (lk == "action" && result.actionCommand.empty()) result.actionCommand = entry.value;
            }

            // C7: Validate file-reference paths stay under the drive root
            if (IsFileReferenceKey(entry.key) && !entry.value.empty()) {
                // Check for dangerous patterns in the raw path string
                if (IsDangerousPathCheck(entry.value)) {
                    if (!entry.isDangerous) {
                        entry.isDangerous = true;
                        entry.threatType = AutorunThreatType::ObfuscatedPath;
                        result.dangerousEntries.push_back(entry);
                    }
                    result.riskScore += 40;
                    SS_LOG_WARN(LOG_CAT, L"Dangerous path pattern in autorun entry line %zu: %hs",
                        entry.lineNumber, entry.value.c_str());
                }

                // Resolve relative to drive root and verify containment
                try {
                    std::filesystem::path refResolved = autorunPath.parent_path() / entry.value;
                    std::wstring wideResolved = refResolved.wstring();
                    Utils::FileUtils::Error pathErr;
                    if (!Utils::FileUtils::IsPathUnderRoot(
                            wideResolved, driveRootW, true, &pathErr)) {
                        if (!entry.isDangerous) {
                            entry.isDangerous = true;
                            entry.threatType = AutorunThreatType::ObfuscatedPath;
                            result.dangerousEntries.push_back(entry);
                        }
                        result.riskScore += 40;
                        SS_LOG_WARN(LOG_CAT,
                            L"Path escapes drive root at line %zu: %hs",
                            entry.lineNumber, entry.value.c_str());
                    }
                    result.referencedFiles.push_back(refResolved);
                    entry.resolvedPath = refResolved;
                } catch (const std::exception& e) {
                    SS_LOG_WARN(LOG_CAT, L"Path resolution failed for line %zu: %hs",
                        entry.lineNumber, e.what());
                }
            }
        }

        // C2: ThreatIntel lookup using the computed hash
        if (!result.sha256.empty()) {
            try {
                auto& tim = ThreatIntel::ThreatIntelManager::Instance();
                if (tim.IsInitialized()) {
                    auto lookupResult = tim.LookupHash("SHA256", result.sha256);
                    if (lookupResult.found) {
                        if (lookupResult.IsMalicious()) {
                            result.isMalicious = true;
                            result.riskScore += 80;
                            result.detectedFamily = "ThreatIntel.KnownMalicious";
                            result.matchedSignatures.push_back("ThreatIntel:Hash:SHA256");
                            SS_LOG_WARN(LOG_CAT,
                                L"Autorun file matches known malicious hash (ThreatIntel): %hs",
                                result.sha256.c_str());
                        } else if (lookupResult.IsSuspicious()) {
                            result.riskScore += 40;
                            SS_LOG_INFO(LOG_CAT,
                                L"Autorun file flagged as suspicious (ThreatIntel): %hs",
                                result.sha256.c_str());
                        }
                    }
                } else {
                    SS_LOG_DEBUG(LOG_CAT,
                        L"ThreatIntel not initialized – hash available for external lookup: %hs",
                        result.sha256.c_str());
                }
            } catch (const std::exception& e) {
                SS_LOG_WARN(LOG_CAT, L"ThreatIntel lookup exception: %hs", e.what());
            }
        }

        // Final risk determination
        if (result.riskScore >= 50) {
            result.isMalicious = true;
            m_stats.maliciousDetected.fetch_add(1, std::memory_order_relaxed);
        }

        m_stats.autorunFilesFound.fetch_add(1, std::memory_order_relaxed);
        return result;
    }

    [[nodiscard]] std::vector<AutorunEntry> ParseAutorunContent(std::string_view content) {
        std::vector<AutorunEntry> entries;
        entries.reserve(32);

        // Strip UTF-8 BOM if present
        if (content.size() >= 3 &&
            content[0] == '\xEF' && content[1] == '\xBB' && content[2] == '\xBF') {
            content = content.substr(3);
        }

        std::string currentSection;
        std::istringstream stream(std::string{content});
        std::string line;
        size_t lineNum = 0;

        while (std::getline(stream, line)) {
            ++lineNum;
            if (lineNum > kMaxAutorunLines) {
                SS_LOG_WARN(LOG_CAT, L"Autorun parser hit line cap (%zu), truncating analysis", kMaxAutorunLines);
                break;
            }

            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }

            if (line.size() > kMaxAutorunLineLength) {
                SS_LOG_WARN(LOG_CAT, L"Autorun parser rejected oversized line %zu", lineNum);
                continue;
            }

            std::string trimmed = StripControlCharacters(Trim(line));
            if (trimmed.empty() || trimmed[0] == ';') continue;

            // Section header
            if (trimmed.front() == '[' && trimmed.back() == ']') {
                currentSection = StripControlCharacters(trimmed.substr(1, trimmed.size() - 2));
                LowercaseASCII(currentSection);
                continue;
            }

            // Key=Value
            auto eqPos = trimmed.find('=');
            if (eqPos == std::string::npos) continue;

            AutorunEntry entry;
            entry.lineNumber = lineNum;
            entry.section = currentSection;
            entry.key   = StripControlCharacters(Trim(trimmed.substr(0, eqPos)));
            entry.value = StripControlCharacters(Trim(trimmed.substr(eqPos + 1)));

            if (entry.key.empty()) {
                continue;
            }

            std::string lowerKey = entry.key;
            LowercaseASCII(lowerKey);

            if (IsDangerousAutorunKey(lowerKey)) {
                entry.isDangerous = true;
                if (lowerKey == "open")
                    entry.threatType = AutorunThreatType::OpenCommand;
                else if (lowerKey == "shellexecute")
                    entry.threatType = AutorunThreatType::ShellExecute;
                else
                    entry.threatType = AutorunThreatType::ShellCommand;
            }

            entries.push_back(std::move(entry));
        }
        return entries;
    }

    // ========================================================================
    // VACCINATION
    // ========================================================================

    [[nodiscard]] VaccinationResult VaccinateDrive(const std::string& driveRoot) {
        VaccinationResult result;
        result.vaccinationTime = std::chrono::system_clock::now();
        result.drivePath = driveRoot;

        try {
            std::filesystem::path root(driveRoot);
            std::filesystem::path vaccinePath = root / AutorunConstants::VACCINE_FOLDER_NAME;
            result.vaccinePath = vaccinePath;

            // Remove existing regular file if present
            if (std::filesystem::exists(vaccinePath) &&
                !std::filesystem::is_directory(vaccinePath)) {
                std::filesystem::permissions(vaccinePath, std::filesystem::perms::all);
                std::filesystem::remove(vaccinePath);
            }

            // Create vaccination directory
            if (!std::filesystem::exists(vaccinePath)) {
                std::filesystem::create_directory(vaccinePath);
            }

            // Apply Hidden+System+ReadOnly attributes
            ::SetFileAttributesW(vaccinePath.c_str(),
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY);

            result.success = true;
            result.status = VaccinationStatus::Vaccinated;
            m_stats.drivesVaccinated.fetch_add(1, std::memory_order_relaxed);

            SS_LOG_INFO(LOG_CAT, L"Drive vaccinated: %hs", driveRoot.c_str());

        } catch (const std::exception& e) {
            result.success = false;
            result.status = VaccinationStatus::VaccinationFailed;
            result.errorMessage = e.what();
            m_stats.vaccinationFailures.fetch_add(1, std::memory_order_relaxed);
            SS_LOG_ERROR(LOG_CAT, L"Vaccination failed for %hs: %hs",
                driveRoot.c_str(), e.what());
        }

        // H2: callback outside lock
        InvokeVaccinationCallback(result);
        return result;
    }

    [[nodiscard]] VaccinationStatus GetVaccinationStatus(const std::string& driveRoot) {
        try {
            std::filesystem::path vp =
                std::filesystem::path(driveRoot) / AutorunConstants::VACCINE_FOLDER_NAME;
            if (std::filesystem::exists(vp) && std::filesystem::is_directory(vp)) {
                DWORD attrs = ::GetFileAttributesW(vp.c_str());
                if (attrs != INVALID_FILE_ATTRIBUTES &&
                    (attrs & FILE_ATTRIBUTE_HIDDEN) &&
                    (attrs & FILE_ATTRIBUTE_SYSTEM)) {
                    return VaccinationStatus::Vaccinated;
                }
                return VaccinationStatus::PartiallyVaccinated;
            }
        } catch (...) {}
        return VaccinationStatus::NotVaccinated;
    }

    [[nodiscard]] bool RemoveVaccination(const std::string& driveRoot) {
        try {
            std::filesystem::path vp =
                std::filesystem::path(driveRoot) / AutorunConstants::VACCINE_FOLDER_NAME;
            if (std::filesystem::exists(vp)) {
                ::SetFileAttributesW(vp.c_str(), FILE_ATTRIBUTE_NORMAL);
                std::filesystem::remove_all(vp);
                SS_LOG_INFO(LOG_CAT, L"Vaccination removed from %hs", driveRoot.c_str());
                return true;
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CAT, L"RemoveVaccination failed for %hs: %hs",
                driveRoot.c_str(), e.what());
        }
        return false;
    }

    [[nodiscard]] bool RepairVaccination(const std::string& driveRoot) {
        auto status = GetVaccinationStatus(driveRoot);
        if (status == VaccinationStatus::Vaccinated) return true;

        if (status == VaccinationStatus::PartiallyVaccinated) {
            // Re-apply attributes
            try {
                std::filesystem::path vp =
                    std::filesystem::path(driveRoot) / AutorunConstants::VACCINE_FOLDER_NAME;
                ::SetFileAttributesW(vp.c_str(),
                    FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY);
                SS_LOG_INFO(LOG_CAT, L"Vaccination repaired for %hs", driveRoot.c_str());
                return true;
            } catch (...) {}
        }

        return VaccinateDrive(driveRoot).success;
    }

    // ========================================================================
    // UTILITY
    // ========================================================================

    [[nodiscard]] std::optional<std::filesystem::path> FindAutorunFile(
            const std::string& driveRoot) {
        try {
            std::filesystem::path root(driveRoot);
            for (const char* name : AutorunConstants::AUTORUN_FILENAMES) {
                std::filesystem::path p = root / name;
                if (std::filesystem::exists(p) && std::filesystem::is_regular_file(p)) {
                    return p;
                }
            }
        } catch (const std::exception& e) {
            SS_LOG_WARN(LOG_CAT, L"FindAutorunFile error on %hs: %hs",
                driveRoot.c_str(), e.what());
        }
        return std::nullopt;
    }

    [[nodiscard]] bool IsDangerousPath(const std::string& path) const {
        if (IsDangerousPathCheck(path)) return true;

        // C5: Additionally use FileUtils::IsPathUnderRoot when a drive letter is
        //     present, verifying the path stays within its own drive root.
        if (path.size() >= 2 && std::isalpha(static_cast<unsigned char>(path[0]))
            && path[1] == ':') {
            std::wstring widePath = Utils::StringUtils::ToWide(path);
            std::wstring wideRoot = widePath.substr(0, 3);   // e.g. L"E:\"
            Utils::FileUtils::Error err;
            if (!Utils::FileUtils::IsPathUnderRoot(widePath, wideRoot, true, &err)) {
                return true;
            }
        }
        return false;
    }

    // ========================================================================
    // CALLBACKS (H2: always copy under lock, invoke outside)
    // ========================================================================

    void RegisterEnforcementCallback(EnforcementCallback callback) {
        std::lock_guard lock(m_callbackMutex);
        m_enforcementCallback = std::move(callback);
    }

    void RegisterVaccinationCallback(VaccinationCallback callback) {
        std::lock_guard lock(m_callbackMutex);
        m_vaccinationCallback = std::move(callback);
    }

    void RegisterErrorCallback(ErrorCallback callback) {
        std::lock_guard lock(m_callbackMutex);
        m_errorCallback = std::move(callback);
    }

    void UnregisterCallbacks() {
        std::lock_guard lock(m_callbackMutex);
        m_enforcementCallback = nullptr;
        m_vaccinationCallback = nullptr;
        m_errorCallback = nullptr;
    }

    // ========================================================================
    // STATISTICS (H3)
    // ========================================================================

    [[nodiscard]] AutorunStatisticsSnapshot GetStatisticsSnapshot() const {
        AutorunStatisticsSnapshot snap;
        snap.drivesScanned      = m_stats.drivesScanned.load(std::memory_order_relaxed);
        snap.autorunFilesFound  = m_stats.autorunFilesFound.load(std::memory_order_relaxed);
        snap.maliciousDetected  = m_stats.maliciousDetected.load(std::memory_order_relaxed);
        snap.filesBlocked       = m_stats.filesBlocked.load(std::memory_order_relaxed);
        snap.filesSanitized     = m_stats.filesSanitized.load(std::memory_order_relaxed);
        snap.filesDeleted       = m_stats.filesDeleted.load(std::memory_order_relaxed);
        snap.filesQuarantined   = m_stats.filesQuarantined.load(std::memory_order_relaxed);
        snap.drivesVaccinated   = m_stats.drivesVaccinated.load(std::memory_order_relaxed);
        snap.vaccinationFailures = m_stats.vaccinationFailures.load(std::memory_order_relaxed);
        for (size_t i = 0; i < snap.byThreatType.size(); ++i) {
            snap.byThreatType[i] = m_stats.byThreatType[i].load(std::memory_order_relaxed);
        }
        snap.startTime = AtomicValueLoadRelaxed(m_stats.startTime);
        return snap;
    }

    void ResetStatistics() {
        m_stats.Reset();
    }

    // ========================================================================
    // SELF-TEST
    // ========================================================================

    [[nodiscard]] bool SelfTest() {
        if (m_status.load(std::memory_order_acquire) != AutorunModuleStatus::Running) {
            SS_LOG_ERROR(LOG_CAT, L"Self-test failed: module not running");
            return false;
        }

        // Verify parsing of a known autorun.inf snippet
        constexpr const char* kTestContent =
            "[autorun]\nopen=test.exe\nicon=myicon.ico\n";
        auto entries = ParseAutorunContent(kTestContent);
        if (entries.size() != 2) {
            SS_LOG_ERROR(LOG_CAT,
                L"Self-test failed: parser returned %zu entries, expected 2",
                entries.size());
            return false;
        }

        bool foundDangerous = false;
        for (const auto& e : entries) {
            if (e.isDangerous && e.threatType == AutorunThreatType::OpenCommand)
                foundDangerous = true;
        }
        if (!foundDangerous) {
            SS_LOG_ERROR(LOG_CAT, L"Self-test failed: 'open' not flagged dangerous");
            return false;
        }

        // Verify free-function dangerous-key detection
        if (!IsDangerousAutorunKey("open") ||
            !IsDangerousAutorunKey("shellexecute") ||
            IsDangerousAutorunKey("label")) {
            SS_LOG_ERROR(LOG_CAT, L"Self-test failed: IsDangerousAutorunKey mismatch");
            return false;
        }

        // Verify dangerous-path detection
        if (!IsDangerousPathCheck("..\\..\\windows\\system32\\cmd.exe") ||
            !IsDangerousPathCheck("\\\\evil\\share\\payload.exe") ||
            IsDangerousPathCheck("readme.txt")) {
            SS_LOG_ERROR(LOG_CAT, L"Self-test failed: IsDangerousPathCheck mismatch");
            return false;
        }

        SS_LOG_INFO(LOG_CAT, L"Self-test passed");
        return true;
    }

private:
    // ========================================================================
    // INTERNAL HELPERS
    // ========================================================================

    /// Determine enforcement action from analysis + config.
    [[nodiscard]] AutorunAction DetermineAction(
            const AutorunAnalysisResult& analysis,
            const AutorunBlockerConfiguration& cfg) {
        if (!cfg.enabled) return AutorunAction::Allowed;

        if (analysis.isMalicious) {
            if (cfg.policyMode == AutorunPolicyMode::Quarantine)
                return AutorunAction::Quarantined;
            if (cfg.deleteOnMount) return AutorunAction::Deleted;
            return AutorunAction::Blocked;
        }

        if (analysis.dangerousEntries.empty()) return AutorunAction::Allowed;

        switch (cfg.policyMode) {
            case AutorunPolicyMode::Block:      return AutorunAction::Blocked;
            case AutorunPolicyMode::Delete:     return AutorunAction::Deleted;
            case AutorunPolicyMode::Sanitize:   return AutorunAction::Sanitized;
            case AutorunPolicyMode::Quarantine: return AutorunAction::Quarantined;
            case AutorunPolicyMode::Monitor:    return AutorunAction::Allowed;
            case AutorunPolicyMode::AllowTrusted:
            default:                            return AutorunAction::Allowed;
        }
    }

    /// Execute the enforcement action on the file.
    [[nodiscard]] bool ExecuteAction(
            const std::filesystem::path& path,
            EnforcementResult& result,
            const AutorunBlockerConfiguration& cfg) {
        try {
            switch (result.action) {
                case AutorunAction::Allowed:
                    return true;

                case AutorunAction::Blocked: {
                    // User-mode "block" = rename so the OS won't auto-execute it.
                    std::filesystem::path newPath = path;
                    newPath += L".blocked";
                    std::filesystem::rename(path, newPath);
                    result.newFilename = newPath.string();
                    m_stats.filesBlocked.fetch_add(1, std::memory_order_relaxed);
                    SS_LOG_INFO(LOG_CAT, L"Blocked (renamed): %ls", newPath.c_str());
                    return true;
                }

                case AutorunAction::Deleted: {
                    // C4: Quarantine-before-delete using QuarantineManager
                    if (cfg.quarantineBeforeDelete) {
                        std::wstring widePath = path.wstring();
                        auto& qm = Core::Engine::QuarantineManager::Instance();
                        auto qr = qm.QuarantineFile(widePath, L"Autorun.Deleted", 0);
                        if (qr.IsSuccess()) {
                            result.quarantinePath = std::filesystem::path(qr.quarantinePath);
                            m_stats.filesQuarantined.fetch_add(1, std::memory_order_relaxed);
                            m_stats.filesDeleted.fetch_add(1, std::memory_order_relaxed);
                            SS_LOG_INFO(LOG_CAT,
                                L"Quarantined-then-deleted: %ls", widePath.c_str());
                            return true;
                        }
                        SS_LOG_WARN(LOG_CAT,
                            L"Pre-delete quarantine failed, deleting directly: %ls",
                            widePath.c_str());
                    }
                    std::filesystem::permissions(path, std::filesystem::perms::all);
                    std::filesystem::remove(path);
                    m_stats.filesDeleted.fetch_add(1, std::memory_order_relaxed);
                    SS_LOG_INFO(LOG_CAT, L"Deleted: %ls", path.c_str());
                    return true;
                }

                case AutorunAction::Sanitized:
                    // C3: Real sanitization — remove dangerous lines
                    return ExecuteSanitize(path, result);

                case AutorunAction::Quarantined:
                    // C4: Full quarantine via QuarantineManager
                    return ExecuteQuarantine(path, result);

                case AutorunAction::Renamed: {
                    std::filesystem::path newPath = path;
                    newPath += L".disabled";
                    std::filesystem::rename(path, newPath);
                    result.newFilename = newPath.string();
                    SS_LOG_INFO(LOG_CAT, L"Renamed: %ls -> %ls",
                        path.c_str(), newPath.c_str());
                    return true;
                }

                case AutorunAction::Vaccinated:
                case AutorunAction::ErrorOccurred:
                default:
                    return false;
            }
        } catch (const std::exception& e) {
            result.errorMessage = e.what();
            SS_LOG_ERROR(LOG_CAT, L"ExecuteAction exception: %hs", e.what());
            NotifyError(result.errorMessage, static_cast<int>(::GetLastError()));
            return false;
        }
    }

    /// C3: Sanitize — read file, remove dangerous lines, atomic write-back.
    [[nodiscard]] bool ExecuteSanitize(
            const std::filesystem::path& path,
            EnforcementResult& result) {
        std::wstring widePath = path.wstring();

        // 1. Read entire content
        std::string content;
        Utils::FileUtils::Error fileErr;
        if (!Utils::FileUtils::ReadAllTextUtf8(widePath, content, &fileErr)) {
            result.errorMessage = "Sanitize read failed: " + fileErr.message;
            SS_LOG_ERROR(LOG_CAT, L"Sanitize: cannot read %ls: %hs",
                widePath.c_str(), fileErr.message.c_str());
            return false;
        }

        // 2. Parse to find dangerous lines
        auto entries = ParseAutorunContent(content);
        std::set<size_t> dangerousLines;
        for (const auto& entry : entries) {
            if (entry.isDangerous) {
                dangerousLines.insert(entry.lineNumber);
            }
        }

        if (dangerousLines.empty()) {
            // Nothing to sanitize
            result.action = AutorunAction::Allowed;
            return true;
        }

        // 3. Rebuild content without dangerous lines
        std::ostringstream sanitized;
        std::istringstream stream(content);
        std::string line;
        size_t lineNum = 0;
        while (std::getline(stream, line)) {
            ++lineNum;
            if (dangerousLines.contains(lineNum)) {
                result.linesRemoved.push_back(lineNum);
                SS_LOG_INFO(LOG_CAT,
                    L"Sanitized line %zu from %ls", lineNum, widePath.c_str());
            } else {
                sanitized << line << '\n';
            }
        }

        // 4. Atomic write-back (write to temp, rename)
        std::string sanitizedContent = sanitized.str();
        Utils::FileUtils::Error writeErr;
        if (!Utils::FileUtils::WriteAllTextUtf8Atomic(
                widePath, sanitizedContent, &writeErr)) {
            result.errorMessage = "Sanitize write failed: " + writeErr.message;
            SS_LOG_ERROR(LOG_CAT, L"Sanitize: atomic write failed for %ls: %hs",
                widePath.c_str(), writeErr.message.c_str());
            return false;
        }

        m_stats.filesSanitized.fetch_add(1, std::memory_order_relaxed);
        SS_LOG_INFO(LOG_CAT,
            L"Sanitized %zu dangerous line(s) from %ls",
            result.linesRemoved.size(), widePath.c_str());
        return true;
    }

    /// C4: Quarantine via QuarantineManager.
    [[nodiscard]] bool ExecuteQuarantine(
            const std::filesystem::path& path,
            EnforcementResult& result) {
        std::wstring widePath = path.wstring();
        auto& qm = Core::Engine::QuarantineManager::Instance();
        auto qr = qm.QuarantineFile(widePath, L"Autorun.Malicious", 0);

        if (qr.IsSuccess()) {
            result.quarantinePath = std::filesystem::path(qr.quarantinePath);
            m_stats.filesQuarantined.fetch_add(1, std::memory_order_relaxed);
            SS_LOG_INFO(LOG_CAT, L"Quarantined: %ls -> %ls",
                widePath.c_str(), qr.quarantinePath.c_str());
            return true;
        }

        result.errorMessage = Utils::StringUtils::ToNarrow(qr.message);
        SS_LOG_ERROR(LOG_CAT, L"Quarantine failed for %ls: %ls",
            widePath.c_str(), qr.message.c_str());
        return false;
    }

    // H2: Callback invocation helpers — copy under lock, invoke outside.
    void InvokeEnforcementCallback(const EnforcementResult& result) {
        EnforcementCallback cb;
        { std::lock_guard lock(m_callbackMutex); cb = m_enforcementCallback; }
        if (cb) {
            try {
                cb(result);
            } catch (...) {
                SS_LOG_WARN(LOG_CAT, L"Enforcement callback threw exception");
            }
        }
    }

    void InvokeVaccinationCallback(const VaccinationResult& result) {
        VaccinationCallback cb;
        { std::lock_guard lock(m_callbackMutex); cb = m_vaccinationCallback; }
        if (cb) {
            try {
                cb(result);
            } catch (...) {
                SS_LOG_WARN(LOG_CAT, L"Vaccination callback threw exception");
            }
        }
    }

    void NotifyError(const std::string& message, int code) {
        ErrorCallback cb;
        { std::lock_guard lock(m_callbackMutex); cb = m_errorCallback; }
        if (cb) {
            try {
                cb(message, code);
            } catch (...) {
                SS_LOG_WARN(LOG_CAT, L"Error callback threw exception");
            }
        }
    }

    // ========================================================================
    // DATA MEMBERS
    // ========================================================================
    mutable std::shared_mutex m_configMutex;   ///< Protects m_config
    mutable std::mutex        m_callbackMutex; ///< Protects callback members

    std::atomic<AutorunModuleStatus> m_status{AutorunModuleStatus::Uninitialized};
    AutorunBlockerConfiguration m_config;
    AutorunStatistics m_stats;

    EnforcementCallback m_enforcementCallback;
    VaccinationCallback m_vaccinationCallback;
    ErrorCallback       m_errorCallback;
};

// ============================================================================
// PUBLIC INTERFACE — MEYERS' SINGLETON & FORWARDING
// ============================================================================

USBAutorunBlocker& USBAutorunBlocker::Instance() noexcept {
    static USBAutorunBlocker instance;
    return instance;
}

bool USBAutorunBlocker::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

USBAutorunBlocker::USBAutorunBlocker()
    : m_impl(std::make_unique<USBAutorunBlockerImpl>()) {
    s_instanceCreated.store(true, std::memory_order_release);
}

USBAutorunBlocker::~USBAutorunBlocker() {
    s_instanceCreated.store(false, std::memory_order_release);
}

bool USBAutorunBlocker::Initialize(const AutorunBlockerConfiguration& config) {
    return m_impl->Initialize(config);
}

void USBAutorunBlocker::Shutdown() {
    m_impl->Shutdown();
}

bool USBAutorunBlocker::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

AutorunModuleStatus USBAutorunBlocker::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

bool USBAutorunBlocker::UpdateConfiguration(const AutorunBlockerConfiguration& config) {
    return m_impl->UpdateConfiguration(config);
}

AutorunBlockerConfiguration USBAutorunBlocker::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

EnforcementResult USBAutorunBlocker::EnforcePolicy(const std::string& driveRoot) {
    return m_impl->EnforcePolicy(driveRoot);
}

EnforcementResult USBAutorunBlocker::EnforcePolicyOnFile(
        const std::filesystem::path& autorunPath) {
    return m_impl->EnforcePolicyOnFile(autorunPath);
}

AutorunAnalysisResult USBAutorunBlocker::AnalyzeDrive(const std::string& driveRoot) {
    return m_impl->AnalyzeDrive(driveRoot);
}

AutorunAnalysisResult USBAutorunBlocker::AnalyzeAutorunFile(
        const std::filesystem::path& autorunPath) {
    return m_impl->AnalyzeAutorunFile(autorunPath);
}

VaccinationResult USBAutorunBlocker::VaccinateDrive(const std::string& driveRoot) {
    return m_impl->VaccinateDrive(driveRoot);
}

VaccinationStatus USBAutorunBlocker::GetVaccinationStatus(const std::string& driveRoot) {
    return m_impl->GetVaccinationStatus(driveRoot);
}

bool USBAutorunBlocker::RemoveVaccination(const std::string& driveRoot) {
    return m_impl->RemoveVaccination(driveRoot);
}

bool USBAutorunBlocker::RepairVaccination(const std::string& driveRoot) {
    return m_impl->RepairVaccination(driveRoot);
}

std::optional<std::filesystem::path> USBAutorunBlocker::FindAutorunFile(
        const std::string& driveRoot) {
    return m_impl->FindAutorunFile(driveRoot);
}

bool USBAutorunBlocker::IsDangerousPath(const std::string& path) const {
    return m_impl->IsDangerousPath(path);
}

std::vector<AutorunEntry> USBAutorunBlocker::ParseAutorunContent(
        std::string_view content) {
    return m_impl->ParseAutorunContent(content);
}

void USBAutorunBlocker::RegisterEnforcementCallback(EnforcementCallback callback) {
    m_impl->RegisterEnforcementCallback(std::move(callback));
}

void USBAutorunBlocker::RegisterVaccinationCallback(VaccinationCallback callback) {
    m_impl->RegisterVaccinationCallback(std::move(callback));
}

void USBAutorunBlocker::RegisterErrorCallback(ErrorCallback callback) {
    m_impl->RegisterErrorCallback(std::move(callback));
}

void USBAutorunBlocker::UnregisterCallbacks() {
    m_impl->UnregisterCallbacks();
}

AutorunStatisticsSnapshot USBAutorunBlocker::GetStatistics() const {
    return m_impl->GetStatisticsSnapshot();
}

void USBAutorunBlocker::ResetStatistics() {
    m_impl->ResetStatistics();
}

bool USBAutorunBlocker::SelfTest() {
    return m_impl->SelfTest();
}

std::string USBAutorunBlocker::GetVersionString() noexcept {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u",
        AutorunConstants::VERSION_MAJOR,
        AutorunConstants::VERSION_MINOR,
        AutorunConstants::VERSION_PATCH);
    try { return std::string(buf); } catch (...) { return {}; }
}

// ============================================================================
// H1: FREE UTILITY FUNCTIONS
// ============================================================================

std::string_view GetAutorunActionName(AutorunAction action) noexcept {
    switch (action) {
        case AutorunAction::Allowed:       return "Allowed";
        case AutorunAction::Blocked:       return "Blocked";
        case AutorunAction::Sanitized:     return "Sanitized";
        case AutorunAction::Deleted:       return "Deleted";
        case AutorunAction::Quarantined:   return "Quarantined";
        case AutorunAction::Renamed:       return "Renamed";
        case AutorunAction::Vaccinated:    return "Vaccinated";
        case AutorunAction::ErrorOccurred: return "ErrorOccurred";
        default:                           return "Unknown";
    }
}

std::string_view GetAutorunThreatTypeName(AutorunThreatType type) noexcept {
    switch (type) {
        case AutorunThreatType::None:             return "None";
        case AutorunThreatType::OpenCommand:      return "OpenCommand";
        case AutorunThreatType::ShellExecute:     return "ShellExecute";
        case AutorunThreatType::ShellCommand:     return "ShellCommand";
        case AutorunThreatType::SuspiciousIcon:   return "SuspiciousIcon";
        case AutorunThreatType::HiddenFile:       return "HiddenFile";
        case AutorunThreatType::ObfuscatedPath:   return "ObfuscatedPath";
        case AutorunThreatType::KnownMalware:     return "KnownMalware";
        case AutorunThreatType::MultipleCommands: return "MultipleCommands";
        case AutorunThreatType::NonStandardEntry: return "NonStandardEntry";
        default:                                  return "Unknown";
    }
}

std::string_view GetVaccinationStatusName(VaccinationStatus status) noexcept {
    switch (status) {
        case VaccinationStatus::NotVaccinated:       return "NotVaccinated";
        case VaccinationStatus::Vaccinated:          return "Vaccinated";
        case VaccinationStatus::PartiallyVaccinated: return "PartiallyVaccinated";
        case VaccinationStatus::VaccinationFailed:   return "VaccinationFailed";
        case VaccinationStatus::VaccinationRemoved:  return "VaccinationRemoved";
        default:                                     return "Unknown";
    }
}

std::string_view GetAutorunPolicyModeName(AutorunPolicyMode mode) noexcept {
    switch (mode) {
        case AutorunPolicyMode::Block:        return "Block";
        case AutorunPolicyMode::Sanitize:     return "Sanitize";
        case AutorunPolicyMode::Delete:       return "Delete";
        case AutorunPolicyMode::Quarantine:   return "Quarantine";
        case AutorunPolicyMode::Monitor:      return "Monitor";
        case AutorunPolicyMode::AllowTrusted: return "AllowTrusted";
        default:                              return "Unknown";
    }
}

bool IsAutorunKey(std::string_view key) noexcept {
    if (IsDangerousAutorunKey(key)) return true;

    try {
        std::string lower(key);
        std::transform(lower.begin(), lower.end(), lower.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        static constexpr const char* kSafeKeys[] = {
            "icon", "label", "action", "useautoplay"
        };
        for (const char* sk : kSafeKeys) {
            if (lower == sk) return true;
        }
    } catch (...) {}
    return false;
}

bool IsDangerousAutorunKey(std::string_view key) noexcept {
    try {
        std::string lower(key);
        std::transform(lower.begin(), lower.end(), lower.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        // Exact match against known dangerous keys
        for (const char* dk : AutorunConstants::DANGEROUS_KEYS) {
            if (lower == dk) return true;
        }

        // Catch any shell\<verb>\command variant
        if (lower.starts_with("shell\\") && lower.ends_with("\\command")) return true;
    } catch (...) {}
    return false;
}

}  // namespace USB
}  // namespace ShadowStrike
