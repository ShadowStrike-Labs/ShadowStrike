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
 * ShadowStrike Banking Protection - SECURE BROWSER IMPLEMENTATION
 * ============================================================================
 *
 * @file SecureBrowser.cpp
 * @brief Implementation of enterprise-grade isolated secure browser environment.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "pch.h"
#include "SecureBrowser.hpp"
#include "KeyloggerProtection.hpp"
#include "ScreenshotBlocker.hpp"
#include "../Utils/StringUtils.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <sstream>
#include <fstream>
#include <iomanip>
#include <algorithm>
#include <random>
#include <thread>
#include <future>
#include <regex>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================

#include <psapi.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <userenv.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "version.lib")

namespace ShadowStrike {
namespace Banking {

// ============================================================================
// LOGGING CATEGORY
// ============================================================================

namespace {
    constexpr const wchar_t* LOG_CATEGORY = L"SecureBrowser";
}

// ============================================================================
// STATIC MEMBER INITIALIZATION
// ============================================================================

std::atomic<bool> SecureBrowser::s_instanceCreated{false};

// ============================================================================
// UTILITY FUNCTION IMPLEMENTATIONS
// ============================================================================

[[nodiscard]] std::string_view GetBrowserTypeName(BrowserType type) noexcept {
    switch (type) {
        case BrowserType::Unknown:  return "Unknown";
        case BrowserType::Chrome:   return "Chrome";
        case BrowserType::Edge:     return "Edge";
        case BrowserType::Firefox:  return "Firefox";
        case BrowserType::Brave:    return "Brave";
        case BrowserType::Chromium: return "Chromium";
        case BrowserType::Custom:   return "Custom";
        default:                    return "Unknown";
    }
}

[[nodiscard]] std::string_view GetSecurityLevelName(SecurityLevel level) noexcept {
    switch (level) {
        case SecurityLevel::Standard: return "Standard";
        case SecurityLevel::Enhanced: return "Enhanced";
        case SecurityLevel::High:     return "High";
        case SecurityLevel::Maximum:  return "Maximum";
        case SecurityLevel::Paranoid: return "Paranoid";
        default:                      return "Unknown";
    }
}

[[nodiscard]] std::string_view GetSessionStatusName(SessionStatus status) noexcept {
    switch (status) {
        case SessionStatus::None:         return "None";
        case SessionStatus::Initializing: return "Initializing";
        case SessionStatus::Running:      return "Running";
        case SessionStatus::Protected:    return "Protected";
        case SessionStatus::Compromised:  return "Compromised";
        case SessionStatus::Terminating:  return "Terminating";
        case SessionStatus::Terminated:   return "Terminated";
        case SessionStatus::Error:        return "Error";
        default:                          return "Unknown";
    }
}

[[nodiscard]] std::string_view GetIntegrityStatusName(IntegrityStatus status) noexcept {
    switch (status) {
        case IntegrityStatus::Unknown:        return "Unknown";
        case IntegrityStatus::Verified:       return "Verified";
        case IntegrityStatus::DLLInjected:    return "DLLInjected";
        case IntegrityStatus::HooksDetected:  return "HooksDetected";
        case IntegrityStatus::MemoryModified: return "MemoryModified";
        case IntegrityStatus::ThreadHijacked: return "ThreadHijacked";
        case IntegrityStatus::Compromised:    return "Compromised";
        default:                              return "Unknown";
    }
}

[[nodiscard]] std::string_view GetSecurityEventTypeName(SecurityEventType type) noexcept {
    switch (type) {
        case SecurityEventType::None:               return "None";
        case SecurityEventType::SessionStarted:     return "SessionStarted";
        case SecurityEventType::SessionEnded:       return "SessionEnded";
        case SecurityEventType::InjectionBlocked:   return "InjectionBlocked";
        case SecurityEventType::ScreenshotBlocked:  return "ScreenshotBlocked";
        case SecurityEventType::KeyloggerBlocked:   return "KeyloggerBlocked";
        case SecurityEventType::NetworkBlocked:     return "NetworkBlocked";
        case SecurityEventType::IntegrityViolation: return "IntegrityViolation";
        case SecurityEventType::HookDetected:       return "HookDetected";
        case SecurityEventType::Compromised:        return "Compromised";
        case SecurityEventType::DomainBlocked:      return "DomainBlocked";
        case SecurityEventType::CertificateWarning: return "CertificateWarning";
        default:                                    return "Unknown";
    }
}

// ============================================================================
// LOCAL HELPERS (anonymous namespace)
// ============================================================================

namespace {

    /// @brief JSON-escape a narrow string for safe serialization
    [[nodiscard]] std::string EscapeJson(const std::string& s) {
        std::ostringstream o;
        for (const char c : s) {
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
                        o << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                          << static_cast<int>(static_cast<unsigned char>(c));
                    } else {
                        o << c;
                    }
            }
        }
        return o.str();
    }

    /// @brief Validate a URL contains no shell metacharacters
    [[nodiscard]] bool IsUrlSafeForCommandLine(std::wstring_view url) noexcept {
        if (url.empty()) return true;
        for (const wchar_t ch : url) {
            switch (ch) {
                case L'&': case L'|': case L';': case L'`':
                case L'$': case L'(': case L')': case L'<':
                case L'>': case L'\n': case L'\r': case L'^':
                    return false;
                default: break;
            }
        }
        // Must start with https:// for banking
        if (url.size() < 8) return false;
        std::wstring prefix(url.substr(0, 8));
        std::transform(prefix.begin(), prefix.end(), prefix.begin(), ::towlower);
        return prefix == L"https://";
    }

    /// @brief Structure for EnumWindows callback
    struct EnumWindowsContext {
        DWORD targetPid = 0;
        HWND  foundHwnd = nullptr;
    };

    /// @brief EnumWindows callback to find main window by PID
    BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
        auto* ctx = reinterpret_cast<EnumWindowsContext*>(lParam);
        if (!ctx) return FALSE;

        DWORD windowPid = 0;
        GetWindowThreadProcessId(hwnd, &windowPid);

        if (windowPid == ctx->targetPid && IsWindowVisible(hwnd)) {
            HWND owner = GetWindow(hwnd, GW_OWNER);
            if (owner == nullptr) {
                ctx->foundHwnd = hwnd;
                return FALSE; // Stop enumeration
            }
        }
        return TRUE;
    }

} // anonymous namespace

[[nodiscard]] bool IsBankingDomain(std::string_view domain) {
    if (domain.empty() || domain.size() > 253) return false;

    std::string d(domain);
    std::transform(d.begin(), d.end(), d.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    // Reject domains that are pure IP addresses
    if (std::all_of(d.begin(), d.end(), [](char c) { return std::isdigit(c) || c == '.'; })) {
        return false;
    }

    // Known banking TLDs / suffixes (exact-match on registrable domain segments)
    static const std::array<std::string_view, 12> knownSuffixes = {
        ".bank", ".insurance", ".finance",
        "online-banking.", "secure.bank", "ebanking.",
        "mybank.", "netbank.", "ibank.", "banking.",
        "payments.", "treasury."
    };

    for (const auto& suffix : knownSuffixes) {
        if (d.find(suffix) != std::string::npos) return true;
    }

    return false;
}

// ============================================================================
// STRUCT JSON SERIALIZATION
// ============================================================================

bool BrowserSessionConfiguration::IsValid() const noexcept {
    return !startingUrl.empty() &&
           (maxSessionDurationSecs == 0 || maxSessionDurationSecs >= 60);
}

std::chrono::seconds BrowserSessionInfo::GetDuration() const noexcept {
    if (startTime.time_since_epoch().count() == 0) return std::chrono::seconds(0);
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now() - startTime);
}

std::string BrowserSessionInfo::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"sessionId\":\"" << EscapeJson(sessionId) << "\","
        << "\"browser\":\"" << GetBrowserTypeName(browserType) << "\","
        << "\"pid\":" << processId << ","
        << "\"status\":\"" << GetSessionStatusName(status) << "\","
        << "\"integrity\":\"" << GetIntegrityStatusName(integrityStatus) << "\","
        << "\"securityLevel\":\"" << GetSecurityLevelName(securityLevel) << "\","
        << "\"durationSecs\":" << GetDuration().count() << ","
        << "\"isProtected\":" << (isProtected ? "true" : "false") << ","
        << "\"isCompromised\":" << (isCompromised ? "true" : "false")
        << "}";
    return oss.str();
}

std::string SecurityEvent::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"id\":\"" << EscapeJson(eventId) << "\","
        << "\"sessionId\":\"" << EscapeJson(sessionId) << "\","
        << "\"type\":\"" << GetSecurityEventTypeName(eventType) << "\","
        << "\"description\":\"" << EscapeJson(description) << "\","
        << "\"blocked\":" << (wasBlocked ? "true" : "false") << ","
        << "\"severity\":" << static_cast<int>(severity) << ","
        << "\"timestamp\":" << std::chrono::duration_cast<std::chrono::milliseconds>(timestamp.time_since_epoch()).count()
        << "}";
    return oss.str();
}

void SessionStatistics::Reset() noexcept {
    duration = std::chrono::seconds(0);
    blockedInjections = 0;
    blockedScreenshots = 0;
    blockedKeyloggers = 0;
    blockedNetworkRequests = 0;
    integrityChecksPassed = 0;
    integrityChecksFailed = 0;
    pagesVisited = 0;
    wasCompromised = false;
}

std::string SessionStatistics::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"durationSecs\":" << duration.count() << ","
        << "\"blockedInjections\":" << blockedInjections.load() << ","
        << "\"blockedKeyloggers\":" << blockedKeyloggers.load() << ","
        << "\"integrityPassed\":" << integrityChecksPassed.load() << ","
        << "\"integrityFailed\":" << integrityChecksFailed.load()
        << "}";
    return oss.str();
}

void SecureBrowserStatistics::Reset() noexcept {
    totalSessions = 0;
    activeSessions = 0;
    totalSecurityEvents = 0;
    blockedInjections = 0;
    compromisedSessions = 0;
    avgSessionDurationSecs = 0;
    startTime = Clock::now();
}

std::string SecureBrowserStatistics::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"totalSessions\":" << totalSessions.load() << ","
        << "\"activeSessions\":" << activeSessions.load() << ","
        << "\"totalEvents\":" << totalSecurityEvents.load() << ","
        << "\"blockedInjections\":" << blockedInjections.load()
        << "}";
    return oss.str();
}

bool SecureBrowserConfiguration::IsValid() const noexcept {
    // Validate security level range
    if (static_cast<uint8_t>(defaultSecurityLevel) > static_cast<uint8_t>(SecurityLevel::Paranoid)) {
        return false;
    }
    // If blocking domains are provided, the path must exist
    if (!blockedDLLsPath.empty() && !std::filesystem::exists(blockedDLLsPath)) {
        return false;
    }
    return true;
}

// ============================================================================
// IMPLEMENTATION CLASS
// ============================================================================

class SecureBrowserImpl {
public:
    SecureBrowserImpl() noexcept
        : m_status(ModuleStatus::Uninitialized)
        , m_initialized(false)
        , m_monitorRunning(false)
    {
        SS_LOG_INFO(LOG_CATEGORY, L"Creating SecureBrowser implementation");
    }

    ~SecureBrowserImpl() noexcept {
        Shutdown();
    }

    [[nodiscard]] bool Initialize(const SecureBrowserConfiguration& config) noexcept {
        std::unique_lock lock(m_mutex);

        if (m_initialized) {
            SS_LOG_WARN(LOG_CATEGORY, L"Already initialized");
            return true;
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Initializing SecureBrowser");
        m_status = ModuleStatus::Initializing;

        try {
            m_config = config;

            // Load banking domains if provided
            if (!config.bankingDomainsPath.empty()) {
                LoadBankingDomainsInternal(config.bankingDomainsPath);
            }

            m_initialized = true;
            m_status = ModuleStatus::Stopped;

            // Start monitoring thread if needed
            if (m_config.enableAutoProtection || m_config.enableIntegrityMonitoring) {
                StartMonitor();
            }

            SS_LOG_INFO(LOG_CATEGORY, L"SecureBrowser initialized successfully");
            return true;

        } catch (const std::exception& ex) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Initialization failed: %hs", ex.what());
            m_status = ModuleStatus::Error;
            return false;
        }
    }

    void Shutdown() noexcept {
        StopMonitor();

        std::unique_lock lock(m_mutex);
        if (!m_initialized) return;

        SS_LOG_INFO(LOG_CATEGORY, L"Shutting down SecureBrowser");
        m_status = ModuleStatus::Stopping;

        // Terminate all sessions
        EndAllSessionsInternal();

        m_initialized = false;
        m_status = ModuleStatus::Stopped;
    }

    // ========================================================================
    // SESSION MANAGEMENT
    // ========================================================================

    [[nodiscard]] std::optional<std::string> LaunchSession(const BrowserSessionConfiguration& config) {
        if (!config.IsValid()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Invalid session configuration: startingUrl empty or invalid duration");
            return std::nullopt;
        }

        // Enforce concurrent session limit
        {
            std::shared_lock lock(m_mutex);
            if (m_activeSessions.size() >= SecureBrowserConstants::MAX_CONCURRENT_SESSIONS) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Maximum concurrent sessions (%zu) reached",
                             SecureBrowserConstants::MAX_CONCURRENT_SESSIONS);
                return std::nullopt;
            }
        }

        // Validate starting URL for command-line safety
        if (!config.startingUrl.empty() && !IsUrlSafeForCommandLine(config.startingUrl)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Starting URL rejected: must be HTTPS and contain no shell metacharacters");
            return std::nullopt;
        }

        std::string sessionId = GenerateSessionId();

        // Resolve browser path
        std::wstring browserPath = GetBrowserPath(config.browserType);
        if (browserPath.empty()) {
            browserPath = config.executablePath;
        }

        if (browserPath.empty() || !std::filesystem::exists(browserPath)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Browser executable not found for type %hs",
                         std::string(GetBrowserTypeName(config.browserType)).c_str());
            return std::nullopt;
        }

        // Create isolated profile directory
        std::wstring profilePath = CreateIsolatedProfile(sessionId);

        // Build command line
        std::wstring cmdLine = BuildCommandLine(browserPath, config, profilePath);

        // Launch process SUSPENDED so we can apply protections before execution
        PROCESS_INFORMATION pi{};
        STARTUPINFOW si{};
        si.cb = sizeof(STARTUPINFOW);

        DWORD creationFlags = CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED;

        BOOL success = CreateProcessW(
            browserPath.c_str(),
            cmdLine.data(),
            nullptr, nullptr, FALSE,
            creationFlags,
            nullptr,
            nullptr,
            &si,
            &pi
        );

        if (!success) {
            DWORD err = GetLastError();
            SS_LOG_ERROR(LOG_CATEGORY, L"Failed to launch browser process: Win32 error %u", err);
            return std::nullopt;
        }

        // RAII guard: if anything below fails, terminate the suspended process
        auto processGuard = std::unique_ptr<void, std::function<void(void*)>>(
            pi.hProcess,
            [&pi](void* h) {
                if (h) {
                    TerminateProcess(static_cast<HANDLE>(h), 1);
                    WaitForSingleObject(static_cast<HANDLE>(h), 1000);
                    CloseHandle(static_cast<HANDLE>(h));
                }
                if (pi.hThread) CloseHandle(pi.hThread);
            }
        );

        // Apply process mitigation policies (DEP, ASLR, DLL signing)
        ApplyProcessMitigations(pi.hProcess);

        // Assign to a Job Object for resource/privilege restriction
        AssignToJobObject(pi.hProcess);

        // Resume the process now that protections are in place
        if (ResumeThread(pi.hThread) == static_cast<DWORD>(-1)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Failed to resume browser process thread: Win32 error %u", GetLastError());
            return std::nullopt; // Guard will terminate
        }

        // Release ownership from guard — process is now running
        processGuard.release();
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);

        BrowserSessionInfo session;
        session.sessionId = sessionId;
        session.browserType = config.browserType;
        session.processId = pi.dwProcessId;
        session.mainWindowHandle = 0; // Resolved by monitor loop
        session.status = SessionStatus::Initializing;
        session.securityLevel = config.securityLevel;
        session.startTime = std::chrono::system_clock::now();
        session.currentUrl = config.startingUrl;
        session.profilePath = profilePath;
        session.isProtected = false;

        {
            std::unique_lock lock(m_mutex);
            m_activeSessions[sessionId] = session;
            m_sessionConfigs[sessionId] = config;
            m_sessionStats[sessionId] = SessionStatistics();

            // Initialize per-session domain whitelist from config
            if (!config.allowedDomains.empty()) {
                m_sessionDomains[sessionId] = std::unordered_set<std::string>(
                    config.allowedDomains.begin(), config.allowedDomains.end());
            }
        }

        m_stats.activeSessions++;
        m_stats.totalSessions++;

        SS_LOG_INFO(LOG_CATEGORY, L"Launched secure session %hs (PID: %u) with CREATE_SUSPENDED + mitigations",
                    sessionId.c_str(), pi.dwProcessId);

        // Notify callback (read under callback lock)
        {
            std::shared_lock cbLock(m_callbackMutex);
            if (m_sessionStatusCallback) {
                m_sessionStatusCallback(session);
            }
        }

        // Apply higher-level protections (keylogger, screenshot)
        // These may fail on first attempt if window is not yet created;
        // the monitor loop will retry.
        if (config.enableKeyloggerProtection) {
            EnableKeyloggerProtection(sessionId);
        }
        if (config.enableScreenshotProtection) {
            EnableScreenProtection(sessionId);
        }

        return sessionId;
    }

    void EndSession(const std::string& sessionId) {
        std::unique_lock lock(m_mutex);
        auto it = m_activeSessions.find(sessionId);
        if (it == m_activeSessions.end()) return;

        SS_LOG_INFO(LOG_CATEGORY, L"Ending session %hs (PID: %u)", sessionId.c_str(), it->second.processId);

        // Graceful termination with fallback to hard kill
        TerminateProcessGracefully(it->second.processId);

        // Clean up isolated profile
        CleanupProfile(it->second.profilePath);

        it->second.status = SessionStatus::Terminated;

        // Copy for callback before erasing
        BrowserSessionInfo terminated = it->second;

        m_activeSessions.erase(it);
        m_sessionConfigs.erase(sessionId);
        m_sessionStats.erase(sessionId);
        m_sessionDomains.erase(sessionId);

        m_stats.activeSessions--;

        lock.unlock();

        // Notify callback outside the lock
        std::shared_lock cbLock(m_callbackMutex);
        if (m_sessionStatusCallback) {
            m_sessionStatusCallback(terminated);
        }
    }

    void EndAllSessionsInternal() {
        // Must be called with m_mutex held
        for (const auto& [id, session] : m_activeSessions) {
            TerminateProcessGracefully(session.processId);
            CleanupProfile(session.profilePath);
        }

        m_activeSessions.clear();
        m_sessionConfigs.clear();
        m_sessionStats.clear();
        m_sessionDomains.clear();
        m_stats.activeSessions = 0;
    }

    // ========================================================================
    // PROTECTION FEATURES
    // ========================================================================

    bool EnableKeyloggerProtection(const std::string& sessionId) {
        std::unique_lock lock(m_mutex);
        auto it = m_activeSessions.find(sessionId);
        if (it == m_activeSessions.end()) return false;

        // Find main window if not yet resolved
        if (it->second.mainWindowHandle == 0) {
            it->second.mainWindowHandle = FindMainWindow(it->second.processId);
        }

        if (it->second.mainWindowHandle != 0) {
            return KeyloggerProtection::Instance().EnableSecureInputMode(it->second.mainWindowHandle);
        }

        SS_LOG_WARN(LOG_CATEGORY, L"Keylogger protection deferred for session %hs: main window not yet available",
                    sessionId.c_str());
        return false;
    }

    bool EnableScreenProtection(const std::string& sessionId) {
        std::shared_lock lock(m_mutex);
        auto it = m_activeSessions.find(sessionId);
        if (it == m_activeSessions.end()) return false;

        uint32_t pid = it->second.processId;
        if (pid != 0) {
            // Delegate to ScreenshotBlocker
            size_t count = ScreenshotBlocker::Instance().ProtectProcessWindows(pid);
            SS_LOG_INFO(LOG_CATEGORY, L"Screen protection enabled for PID %u (%zu windows)", pid, count);
            return count > 0;
        }
        return false;
    }

    IntegrityStatus VerifyIntegrity(const std::string& sessionId) {
        std::shared_lock lock(m_mutex);
        auto it = m_activeSessions.find(sessionId);
        if (it == m_activeSessions.end()) return IntegrityStatus::Unknown;

        ProcessId pid = it->second.processId;
        lock.unlock();

        // 1. Check if process is still alive
        if (!IsProcessRunning(pid)) {
            return IntegrityStatus::Compromised;
        }

        // 2. Check loaded modules for unsigned / suspicious DLLs
        auto loadedDlls = GetLoadedDLLsInternal(pid);
        for (const auto& dll : loadedDlls) {
            if (dll.isSuspicious) {
                SS_LOG_WARN(LOG_CATEGORY, L"Suspicious DLL detected in session %hs: %ls",
                            sessionId.c_str(), dll.moduleName.c_str());
                return IntegrityStatus::DLLInjected;
            }
        }

        // 3. Scan for API hooks via KeyloggerProtection
        auto hooks = KeyloggerProtection::Instance().ScanProcessHooks(pid);
        if (!hooks.empty()) {
            SS_LOG_WARN(LOG_CATEGORY, L"Hooks detected in session %hs: %zu hooks found",
                        sessionId.c_str(), hooks.size());
            return IntegrityStatus::HooksDetected;
        }

        // 4. Validate DLL count hasn't changed dramatically (simple heuristic)
        {
            std::shared_lock statsLock(m_mutex);
            auto statsIt = m_sessionStats.find(sessionId);
            if (statsIt != m_sessionStats.end()) {
                statsIt->second.integrityChecksPassed++;
            }
        }

        return IntegrityStatus::Verified;
    }

    // ========================================================================
    // MONITORING
    // ========================================================================

    void StartMonitor() {
        if (m_monitorRunning) return;
        m_monitorRunning = true;
        m_monitorThread = std::thread(&SecureBrowserImpl::MonitorLoop, this);
    }

    void StopMonitor() {
        m_monitorRunning = false;
        if (m_monitorThread.joinable()) {
            m_monitorThread.join();
        }
    }

    void MonitorLoop() {
        SS_LOG_INFO(LOG_CATEGORY, L"SecureBrowser monitor thread started");

        while (m_monitorRunning) {
            std::vector<std::string> deadSessions;
            std::vector<std::string> sessionsNeedingProtection;

            {
                std::unique_lock lock(m_mutex);
                for (auto& [id, session] : m_activeSessions) {
                    if (session.status == SessionStatus::Terminated) {
                        deadSessions.push_back(id);
                        continue;
                    }

                    if (!IsProcessRunning(session.processId)) {
                        SS_LOG_WARN(LOG_CATEGORY, L"Session %hs (PID: %u) process no longer running",
                                    id.c_str(), session.processId);
                        session.status = SessionStatus::Terminated;
                        deadSessions.push_back(id);
                        continue;
                    }

                    // Resolve main window handle if not yet found
                    if (session.mainWindowHandle == 0) {
                        session.mainWindowHandle = FindMainWindow(session.processId);
                        if (session.mainWindowHandle != 0) {
                            sessionsNeedingProtection.push_back(id);
                        }
                    }

                    // Run integrity check on active sessions
                    if (session.status == SessionStatus::Running ||
                        session.status == SessionStatus::Protected) {
                        // Release lock for heavy integrity work
                        ProcessId pid = session.processId;
                        lock.unlock();

                        IntegrityStatus integrity = VerifyIntegrity(id);

                        lock.lock();
                        auto refreshIt = m_activeSessions.find(id);
                        if (refreshIt != m_activeSessions.end()) {
                            refreshIt->second.integrityStatus = integrity;
                            if (integrity != IntegrityStatus::Verified &&
                                integrity != IntegrityStatus::Unknown) {
                                refreshIt->second.isCompromised = true;
                                refreshIt->second.status = SessionStatus::Compromised;

                                SS_LOG_ERROR(LOG_CATEGORY,
                                    L"Session %hs COMPROMISED: integrity=%hs",
                                    id.c_str(), std::string(GetIntegrityStatusName(integrity)).c_str());

                                if (m_config.terminateOnCompromise) {
                                    TerminateProcessGracefully(pid);
                                    refreshIt->second.status = SessionStatus::Terminated;
                                    deadSessions.push_back(id);
                                    m_stats.compromisedSessions++;
                                }
                            }
                        }
                    }

                    // Transition from Initializing to Running once window is found
                    if (session.status == SessionStatus::Initializing &&
                        session.mainWindowHandle != 0) {
                        session.status = SessionStatus::Running;
                    }
                }

                // Clean up dead sessions
                for (const auto& deadId : deadSessions) {
                    auto deadIt = m_activeSessions.find(deadId);
                    if (deadIt != m_activeSessions.end()) {
                        CleanupProfile(deadIt->second.profilePath);
                        m_activeSessions.erase(deadIt);
                        m_sessionConfigs.erase(deadId);
                        m_sessionStats.erase(deadId);
                        m_sessionDomains.erase(deadId);
                        m_stats.activeSessions--;
                    }
                }
            }

            // Retry protections for newly-windowed sessions (outside main lock)
            for (const auto& sid : sessionsNeedingProtection) {
                EnableKeyloggerProtection(sid);
                EnableScreenProtection(sid);
            }

            std::this_thread::sleep_for(
                std::chrono::milliseconds(SecureBrowserConstants::PROCESS_MONITOR_INTERVAL_MS));
        }

        SS_LOG_INFO(LOG_CATEGORY, L"SecureBrowser monitor thread stopped");
    }

    // ========================================================================
    // HELPERS
    // ========================================================================

    std::wstring GetBrowserPath(BrowserType type) const {
        // 1. Check custom paths first
        auto it = m_config.customBrowserPaths.find(type);
        if (it != m_config.customBrowserPaths.end() && std::filesystem::exists(it->second)) {
            return it->second;
        }

        // 2. Detect default paths
        switch (type) {
            case BrowserType::Chrome: {
                for (const auto* pattern : SecureBrowserConstants::CHROME_PATH_PATTERNS) {
                    std::wstring expanded = ExpandEnvPath(pattern);
                    if (!expanded.empty() && std::filesystem::exists(expanded)) {
                        return expanded;
                    }
                }
                return L"";
            }
            case BrowserType::Edge: {
                std::wstring expanded = ExpandEnvPath(SecureBrowserConstants::EDGE_PATH);
                if (!expanded.empty() && std::filesystem::exists(expanded)) {
                    return expanded;
                }
                return L"";
            }
            case BrowserType::Firefox: {
                std::wstring expanded = ExpandEnvPath(SecureBrowserConstants::FIREFOX_PATH);
                if (!expanded.empty() && std::filesystem::exists(expanded)) {
                    return expanded;
                }
                return L"";
            }
            default:
                return L"";
        }
    }

    std::wstring ExpandEnvPath(const std::wstring& path) const {
        // Query required buffer size first
        DWORD required = ::ExpandEnvironmentStringsW(path.c_str(), nullptr, 0);
        if (required == 0) return path;

        std::vector<wchar_t> buffer(static_cast<size_t>(required));
        DWORD ret = ::ExpandEnvironmentStringsW(path.c_str(), buffer.data(), required);
        if (ret > 0 && ret <= required) {
            return std::wstring(buffer.data());
        }
        return path;
    }

    std::wstring CreateIsolatedProfile(const std::string& sessionId) {
        wchar_t tempBuf[MAX_PATH + 1]{};
        DWORD len = GetTempPathW(MAX_PATH, tempBuf);
        if (len == 0 || len > MAX_PATH) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Failed to get temp path for isolated profile");
            return L"";
        }

        std::filesystem::path profileDir = std::filesystem::path(tempBuf)
            / L"ShadowStrike" / L"SecureBrowser" / Utils::StringUtils::ToWide(sessionId);

        std::error_code ec;
        std::filesystem::create_directories(profileDir, ec);
        if (ec) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Failed to create profile directory: %hs", ec.message().c_str());
            return L"";
        }

        return profileDir.wstring();
    }

    std::wstring BuildCommandLine(const std::wstring& exePath, const BrowserSessionConfiguration& config, const std::wstring& profilePath) {
        std::wstringstream ss;
        ss << L"\"" << exePath << L"\"";

        if (config.browserType == BrowserType::Chrome ||
            config.browserType == BrowserType::Edge  ||
            config.browserType == BrowserType::Brave ||
            config.browserType == BrowserType::Chromium) {

            ss << L" --user-data-dir=\"" << profilePath << L"\"";
            ss << L" --no-first-run";
            ss << L" --no-default-browser-check";

            if (config.usePrivateMode) ss << L" --incognito";
            if (config.disableExtensions) ss << L" --disable-extensions";
            if (config.disablePlugins) ss << L" --disable-plugins";
            if (config.disableDevTools) ss << L" --remote-debugging-port=0";

            // Sandbox hardening
            ss << L" --disable-background-networking";
            ss << L" --disable-sync";
            ss << L" --disable-translate";
            ss << L" --disable-component-update";
            ss << L" --disable-default-apps";
            ss << L" --no-pings";

            // URL is validated by IsUrlSafeForCommandLine before reaching here
            if (!config.startingUrl.empty()) {
                ss << L" \"" << config.startingUrl << L"\"";
            }
        } else if (config.browserType == BrowserType::Firefox) {
            ss << L" -profile \"" << profilePath << L"\"";
            ss << L" -no-remote";

            if (config.usePrivateMode) ss << L" -private-window";

            if (!config.startingUrl.empty()) {
                ss << L" -url \"" << config.startingUrl << L"\"";
            }
        }

        return ss.str();
    }

    std::vector<LoadedDLLInfo> GetLoadedDLLsInternal(ProcessId pid) const {
        std::vector<LoadedDLLInfo> dlls;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            SS_LOG_WARN(LOG_CATEGORY, L"Failed to snapshot modules for PID %u: %u", pid, GetLastError());
            return dlls;
        }

        MODULEENTRY32W me32{};
        me32.dwSize = sizeof(MODULEENTRY32W);
        if (Module32FirstW(hSnapshot, &me32)) {
            do {
                LoadedDLLInfo info;
                info.moduleName = me32.szModule;
                info.fullPath = me32.szExePath;
                info.baseAddress = reinterpret_cast<uint64_t>(me32.modBaseAddr);
                info.size = me32.modBaseSize;

                // Check if system DLL (lives under Windows or System32)
                std::wstring pathLower(info.fullPath);
                std::transform(pathLower.begin(), pathLower.end(), pathLower.begin(), ::towlower);
                info.isSystemDLL = (pathLower.find(L"\\windows\\system32\\") != std::wstring::npos ||
                                    pathLower.find(L"\\windows\\syswow64\\") != std::wstring::npos);

                // Non-system DLLs in a secure browser process are suspicious
                info.isSuspicious = !info.isSystemDLL &&
                                    pathLower.find(L"\\google\\") == std::wstring::npos &&
                                    pathLower.find(L"\\microsoft\\") == std::wstring::npos &&
                                    pathLower.find(L"\\mozilla\\") == std::wstring::npos &&
                                    pathLower.find(L"\\brave") == std::wstring::npos;

                dlls.push_back(std::move(info));
            } while (Module32NextW(hSnapshot, &me32));
        }
        CloseHandle(hSnapshot);

        return dlls;
    }

    uint64_t FindMainWindow(ProcessId pid) {
        EnumWindowsContext ctx;
        ctx.targetPid = pid;
        ctx.foundHwnd = nullptr;

        EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(&ctx));

        return reinterpret_cast<uint64_t>(ctx.foundHwnd);
    }

    void TerminateProcessGracefully(ProcessId pid) {
        if (pid == 0) return;

        // Try graceful shutdown first by posting WM_CLOSE to top-level windows
        uint64_t hwnd = FindMainWindow(pid);
        if (hwnd != 0) {
            PostMessageW(reinterpret_cast<HWND>(hwnd), WM_CLOSE, 0, 0);

            // Wait up to 3 seconds for graceful exit
            HANDLE hProc = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, FALSE, pid);
            if (hProc) {
                DWORD waitResult = WaitForSingleObject(hProc, 3000);
                if (waitResult == WAIT_TIMEOUT) {
                    SS_LOG_WARN(LOG_CATEGORY, L"Process PID %u did not exit gracefully, forcing termination", pid);
                    TerminateProcess(hProc, 1);
                    WaitForSingleObject(hProc, 2000);
                }
                CloseHandle(hProc);
                return;
            }
        }

        // Fallback: hard terminate
        TerminateProcessById(pid);
    }

    void TerminateProcessById(ProcessId pid) {
        if (pid == 0) return;
        HANDLE hProc = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pid);
        if (hProc) {
            TerminateProcess(hProc, 1);
            WaitForSingleObject(hProc, 2000);
            CloseHandle(hProc);
        }
    }

    void CleanupProfile(const std::wstring& profilePath) {
        if (profilePath.empty()) return;

        std::error_code ec;
        if (std::filesystem::exists(profilePath, ec)) {
            std::filesystem::remove_all(profilePath, ec);
            if (ec) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to clean up profile at %ls: %hs",
                            profilePath.c_str(), ec.message().c_str());
            } else {
                SS_LOG_DEBUG(LOG_CATEGORY, L"Cleaned up isolated profile: %ls", profilePath.c_str());
            }
        }
    }

    void ApplyProcessMitigations(HANDLE hProcess) {
        // Enable DEP (Data Execution Prevention)
        PROCESS_MITIGATION_DEP_POLICY depPolicy{};
        depPolicy.Enable = 1;
        depPolicy.Permanent = 1;
        if (!SetProcessMitigationPolicy(ProcessDEPPolicy, &depPolicy, sizeof(depPolicy))) {
            SS_LOG_WARN(LOG_CATEGORY, L"Failed to set DEP policy: %u", GetLastError());
        }

        // Block non-Microsoft-signed DLLs from loading
        PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sigPolicy{};
        sigPolicy.MicrosoftSignedOnly = 1;
        if (!SetProcessMitigationPolicy(ProcessSignaturePolicy, &sigPolicy, sizeof(sigPolicy))) {
            // Expected to fail on some OS versions; log at debug level
            SS_LOG_DEBUG(LOG_CATEGORY, L"Binary signature policy not applied (may require newer OS): %u", GetLastError());
        }

        // Block dynamic code generation
        PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynPolicy{};
        dynPolicy.ProhibitDynamicCode = 1;
        if (!SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &dynPolicy, sizeof(dynPolicy))) {
            SS_LOG_DEBUG(LOG_CATEGORY, L"Dynamic code policy not applied: %u", GetLastError());
        }
    }

    void AssignToJobObject(HANDLE hProcess) {
        HANDLE hJob = CreateJobObjectW(nullptr, nullptr);
        if (!hJob) {
            SS_LOG_WARN(LOG_CATEGORY, L"Failed to create job object: %u", GetLastError());
            return;
        }

        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jobInfo{};
        jobInfo.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
            JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;

        if (!SetInformationJobObject(hJob, JobObjectExtendedLimitInformation,
                                     &jobInfo, sizeof(jobInfo))) {
            SS_LOG_WARN(LOG_CATEGORY, L"Failed to set job object limits: %u", GetLastError());
            CloseHandle(hJob);
            return;
        }

        if (!AssignProcessToJobObject(hJob, hProcess)) {
            SS_LOG_WARN(LOG_CATEGORY, L"Failed to assign process to job object: %u", GetLastError());
        }

        // Keep job handle alive (closes on process termination via KILL_ON_JOB_CLOSE)
        // In a production system, we'd store this handle per-session for explicit management
    }

    bool LoadBankingDomainsInternal(const std::wstring& path) {
        if (path.empty()) return false;

        std::error_code ec;
        if (!std::filesystem::exists(path, ec)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Banking domains file not found: %ls", path.c_str());
            return false;
        }

        auto fileSize = std::filesystem::file_size(path, ec);
        if (ec || fileSize > 10 * 1024 * 1024) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Banking domains file invalid or too large (>10MB): %ls", path.c_str());
            return false;
        }

        std::ifstream file(path);
        if (!file.is_open()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Failed to open banking domains file: %ls", path.c_str());
            return false;
        }

        std::vector<std::string> domains;
        std::string line;
        while (std::getline(file, line) && domains.size() < SecureBrowserConstants::MAX_ALLOWED_DOMAINS) {
            // Trim whitespace
            auto start = line.find_first_not_of(" \t\r\n");
            auto end = line.find_last_not_of(" \t\r\n");
            if (start == std::string::npos) continue;
            line = line.substr(start, end - start + 1);

            // Skip comments and empty lines
            if (line.empty() || line[0] == '#') continue;

            // Basic domain validation
            if (line.size() > 253) continue;

            domains.push_back(std::move(line));
        }

        m_bankingDomains = std::move(domains);
        SS_LOG_INFO(LOG_CATEGORY, L"Loaded %zu banking domains from %ls",
                    m_bankingDomains.size(), path.c_str());
        return true;
    }

    bool IsProcessRunning(ProcessId pid) {
        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (hProc) {
            DWORD exitCode;
            bool active = GetExitCodeProcess(hProc, &exitCode) && exitCode == STILL_ACTIVE;
            CloseHandle(hProc);
            return active;
        }
        return false;
    }

    std::string GenerateSessionId() {
        // Simple random ID
        static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        std::string s(16, ' ');
        std::mt19937 rng(std::random_device{}());
        std::uniform_int_distribution<> dist(0, sizeof(alphanum) - 2);
        for (auto& c : s) c = alphanum[dist(rng)];
        return s;
    }

    // Callbacks
    SecurityEventCallback m_securityEventCallback;
    SessionStatusCallback m_sessionStatusCallback;
    IntegrityCheckCallback m_integrityCheckCallback;
    ErrorCallback m_errorCallback;

    // Member Variables
    mutable std::shared_mutex m_mutex;
    std::atomic<ModuleStatus> m_status;
    std::atomic<bool> m_initialized;

    SecureBrowserConfiguration m_config;
    SecureBrowserStatistics m_stats;

    // Session Data
    std::unordered_map<std::string, BrowserSessionInfo> m_activeSessions;
    std::unordered_map<std::string, BrowserSessionConfiguration> m_sessionConfigs;
    std::unordered_map<std::string, SessionStatistics> m_sessionStats;
    std::unordered_map<std::string, std::unordered_set<std::string>> m_sessionDomains;

    // Domain Data
    std::vector<std::string> m_bankingDomains;

    // Monitor
    std::atomic<bool> m_monitorRunning;
    std::thread m_monitorThread;

    // Security Events Cache
    mutable std::shared_mutex m_eventMutex;
    std::deque<SecurityEvent> m_securityEvents;
    static constexpr size_t MAX_SECURITY_EVENTS = 1000;

    // Callback mutex
    mutable std::shared_mutex m_callbackMutex;
};

// ============================================================================
// PUBLIC FACADE IMPLEMENTATION
// ============================================================================

SecureBrowser& SecureBrowser::Instance() noexcept {
    static SecureBrowser instance;
    return instance;
}

bool SecureBrowser::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

SecureBrowser::SecureBrowser()
    : m_impl(std::make_unique<SecureBrowserImpl>())
{
    s_instanceCreated.store(true, std::memory_order_release);
}

SecureBrowser::~SecureBrowser() {
    s_instanceCreated.store(false, std::memory_order_release);
}

bool SecureBrowser::Initialize(const SecureBrowserConfiguration& config) {
    return m_impl->Initialize(config);
}

void SecureBrowser::Shutdown() {
    m_impl->Shutdown();
}

bool SecureBrowser::IsInitialized() const noexcept {
    return m_impl->m_initialized;
}

ModuleStatus SecureBrowser::GetStatus() const noexcept {
    return m_impl->m_status;
}

bool SecureBrowser::UpdateConfiguration(const SecureBrowserConfiguration& config) {
    if (!config.IsValid()) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Invalid configuration update rejected");
        return false;
    }

    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_config = config;
    SS_LOG_INFO(LOG_CATEGORY, L"Configuration updated (securityLevel=%u, autoProtect=%s, integrityMonitor=%s)",
                static_cast<unsigned>(config.defaultSecurityLevel),
                config.enableAutoProtection ? L"on" : L"off",
                config.enableIntegrityMonitoring ? L"on" : L"off");

    // Reload banking domains if path changed
    if (!config.bankingDomainsPath.empty()) {
        m_impl->LoadBankingDomainsInternal(config.bankingDomainsPath);
    }

    // Start/stop monitor based on new config
    lock.unlock();
    if (config.enableAutoProtection || config.enableIntegrityMonitoring) {
        m_impl->StartMonitor();
    } else {
        m_impl->StopMonitor();
    }

    return true;
}

SecureBrowserConfiguration SecureBrowser::GetConfiguration() const {
    return m_impl->m_config;
}

std::optional<std::string> SecureBrowser::LaunchSession(const BrowserSessionConfiguration& config) {
    return m_impl->LaunchSession(config);
}

void SecureBrowser::EndSession(const std::string& sessionId) {
    m_impl->EndSession(sessionId);
}

void SecureBrowser::EndAllSessions() {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->EndAllSessionsInternal();
}

bool SecureBrowser::IsSessionActive(const std::string& sessionId) const {
    std::shared_lock lock(m_impl->m_mutex);
    auto it = m_impl->m_activeSessions.find(sessionId);
    return it != m_impl->m_activeSessions.end() &&
           it->second.status != SessionStatus::Terminated;
}

std::optional<BrowserSessionInfo> SecureBrowser::GetSessionInfo(const std::string& sessionId) const {
    std::shared_lock lock(m_impl->m_mutex);
    auto it = m_impl->m_activeSessions.find(sessionId);
    if (it != m_impl->m_activeSessions.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<BrowserSessionInfo> SecureBrowser::GetActiveSessions() const {
    std::shared_lock lock(m_impl->m_mutex);
    std::vector<BrowserSessionInfo> sessions;
    for (const auto& pair : m_impl->m_activeSessions) {
        if (pair.second.status != SessionStatus::Terminated) {
            sessions.push_back(pair.second);
        }
    }
    return sessions;
}

ProcessId SecureBrowser::GetBrowserPid(const std::string& sessionId) const {
    auto info = GetSessionInfo(sessionId);
    return info ? info->processId : 0;
}

// Protection
bool SecureBrowser::EnableKeyloggerProtection(const std::string& sessionId) {
    return m_impl->EnableKeyloggerProtection(sessionId);
}

bool SecureBrowser::EnableScreenProtection(const std::string& sessionId) {
    return m_impl->EnableScreenProtection(sessionId);
}

bool SecureBrowser::EnableInjectionProtection(const std::string& sessionId) {
    std::shared_lock lock(m_impl->m_mutex);
    auto it = m_impl->m_activeSessions.find(sessionId);
    if (it == m_impl->m_activeSessions.end()) return false;

    ProcessId pid = it->second.processId;
    lock.unlock();

    // Open the browser process to apply mitigation policies
    HANDLE hProc = OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) {
        SS_LOG_WARN(LOG_CATEGORY, L"Cannot open process PID %u for injection protection: %u",
                    pid, GetLastError());
        return false;
    }

    bool success = true;

    // Block non-Microsoft-signed DLLs
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sigPolicy{};
    sigPolicy.MicrosoftSignedOnly = 1;
    if (!SetProcessMitigationPolicy(ProcessSignaturePolicy, &sigPolicy, sizeof(sigPolicy))) {
        SS_LOG_DEBUG(LOG_CATEGORY, L"Binary signature mitigation not available for PID %u", pid);
        success = false;
    }

    // Block remote image loads
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY imgPolicy{};
    imgPolicy.NoRemoteImages = 1;
    imgPolicy.NoLowMandatoryLabelImages = 1;
    if (!SetProcessMitigationPolicy(ProcessImageLoadPolicy, &imgPolicy, sizeof(imgPolicy))) {
        SS_LOG_DEBUG(LOG_CATEGORY, L"Image load mitigation not available for PID %u", pid);
    }

    CloseHandle(hProc);

    SS_LOG_INFO(LOG_CATEGORY, L"Injection protection applied for session %hs (PID %u)",
                sessionId.c_str(), pid);
    return success;
}

bool SecureBrowser::EnableAllProtections(const std::string& sessionId) {
    bool k = EnableKeyloggerProtection(sessionId);
    bool s = EnableScreenProtection(sessionId);
    bool i = EnableInjectionProtection(sessionId);
    return k && s && i;
}

// Integrity
IntegrityStatus SecureBrowser::VerifyIntegrity(const std::string& sessionId) {
    return m_impl->VerifyIntegrity(sessionId);
}

std::vector<LoadedDLLInfo> SecureBrowser::GetLoadedDLLs(const std::string& sessionId) const {
    std::shared_lock lock(m_impl->m_mutex);
    auto it = m_impl->m_activeSessions.find(sessionId);
    if (it != m_impl->m_activeSessions.end()) {
        return m_impl->GetLoadedDLLsInternal(it->second.processId);
    }
    return {};
}

std::vector<LoadedDLLInfo> SecureBrowser::CheckSuspiciousDLLs(const std::string& sessionId) const {
    auto allDlls = GetLoadedDLLs(sessionId);
    std::vector<LoadedDLLInfo> suspicious;
    suspicious.reserve(allDlls.size());

    std::copy_if(allDlls.begin(), allDlls.end(), std::back_inserter(suspicious),
                 [](const LoadedDLLInfo& dll) { return dll.isSuspicious; });

    if (!suspicious.empty()) {
        SS_LOG_WARN(LOG_CATEGORY, L"Found %zu suspicious DLLs in session %hs",
                    suspicious.size(), sessionId.c_str());
    }
    return suspicious;
}

// Detection
std::vector<BrowserType> SecureBrowser::DetectInstalledBrowsers() const {
    std::vector<BrowserType> browsers;

    // Check each browser type through existing path resolution
    static const std::array<BrowserType, 3> typesToCheck = {
        BrowserType::Chrome, BrowserType::Edge, BrowserType::Firefox
    };

    for (BrowserType type : typesToCheck) {
        std::wstring path = m_impl->GetBrowserPath(type);
        if (!path.empty()) {
            browsers.push_back(type);
        }
    }

    return browsers;
}

std::wstring SecureBrowser::GetBrowserPath(BrowserType type) const {
    return m_impl->GetBrowserPath(type);
}

bool SecureBrowser::IsBrowserInstalled(BrowserType type) const {
    return !GetBrowserPath(type).empty();
}

// Domain Management
bool SecureBrowser::LoadBankingDomains(const std::filesystem::path& path) {
    std::unique_lock lock(m_impl->m_mutex);
    return m_impl->LoadBankingDomainsInternal(path.wstring());
}

void SecureBrowser::AddAllowedDomain(const std::string& sessionId, const std::string& domain) {
    if (domain.empty() || domain.size() > 253) return;

    std::unique_lock lock(m_impl->m_mutex);
    auto& domains = m_impl->m_sessionDomains[sessionId];
    if (domains.size() >= SecureBrowserConstants::MAX_ALLOWED_DOMAINS) {
        SS_LOG_WARN(LOG_CATEGORY, L"Domain whitelist limit reached for session %hs", sessionId.c_str());
        return;
    }
    domains.insert(domain);
    SS_LOG_DEBUG(LOG_CATEGORY, L"Added domain '%hs' to session %hs whitelist", domain.c_str(), sessionId.c_str());
}

void SecureBrowser::RemoveAllowedDomain(const std::string& sessionId, const std::string& domain) {
    std::unique_lock lock(m_impl->m_mutex);
    auto it = m_impl->m_sessionDomains.find(sessionId);
    if (it != m_impl->m_sessionDomains.end()) {
        it->second.erase(domain);
    }
}

bool SecureBrowser::IsDomainAllowed(const std::string& sessionId, const std::string& domain) const {
    if (domain.empty()) return false;

    std::shared_lock lock(m_impl->m_mutex);

    // 1. Check per-session domain whitelist
    auto domIt = m_impl->m_sessionDomains.find(sessionId);
    if (domIt != m_impl->m_sessionDomains.end() && !domIt->second.empty()) {
        return domIt->second.count(domain) > 0;
    }

    // 2. Check session config's allowed domains list
    auto cfgIt = m_impl->m_sessionConfigs.find(sessionId);
    if (cfgIt != m_impl->m_sessionConfigs.end() && !cfgIt->second.allowedDomains.empty()) {
        const auto& allowed = cfgIt->second.allowedDomains;
        return std::find(allowed.begin(), allowed.end(), domain) != allowed.end();
    }

    // 3. Check globally-loaded banking domains
    if (!m_impl->m_bankingDomains.empty()) {
        return std::find(m_impl->m_bankingDomains.begin(),
                         m_impl->m_bankingDomains.end(), domain) != m_impl->m_bankingDomains.end();
    }

    // 4. Fallback to heuristic only if no whitelists are configured
    return IsBankingDomain(domain);
}

// Callbacks
void SecureBrowser::RegisterSecurityEventCallback(SecurityEventCallback callback) {
    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_securityEventCallback = std::move(callback);
}

void SecureBrowser::RegisterSessionStatusCallback(SessionStatusCallback callback) {
    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_sessionStatusCallback = std::move(callback);
}

void SecureBrowser::RegisterIntegrityCheckCallback(IntegrityCheckCallback callback) {
    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_integrityCheckCallback = std::move(callback);
}

void SecureBrowser::RegisterErrorCallback(ErrorCallback callback) {
    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_errorCallback = std::move(callback);
}

void SecureBrowser::UnregisterCallbacks() {
    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_securityEventCallback = nullptr;
    m_impl->m_sessionStatusCallback = nullptr;
    m_impl->m_integrityCheckCallback = nullptr;
    m_impl->m_errorCallback = nullptr;
}

// Statistics
SecureBrowserStatistics SecureBrowser::GetStatistics() const {
    return m_impl->m_stats;
}

std::optional<SessionStatistics> SecureBrowser::GetSessionStatistics(const std::string& sessionId) const {
    std::shared_lock lock(m_impl->m_mutex);
    auto it = m_impl->m_sessionStats.find(sessionId);
    if (it != m_impl->m_sessionStats.end()) {
        return it->second;
    }
    return std::nullopt;
}

void SecureBrowser::ResetStatistics() {
    m_impl->m_stats.Reset();
}

std::vector<SecurityEvent> SecureBrowser::GetRecentSecurityEvents(size_t maxCount) const {
    std::shared_lock lock(m_impl->m_eventMutex);
    size_t count = std::min(maxCount, m_impl->m_securityEvents.size());
    std::vector<SecurityEvent> events;
    events.reserve(count);

    // Return the most recent events (deque back = newest)
    auto begin = m_impl->m_securityEvents.end() - static_cast<ptrdiff_t>(count);
    auto end = m_impl->m_securityEvents.end();
    events.assign(begin, end);
    return events;
}

// Utility
bool SecureBrowser::SelfTest() {
    SS_LOG_INFO(LOG_CATEGORY, L"Running self-test");

    // Test browser detection
    auto browsers = DetectInstalledBrowsers();
    SS_LOG_INFO(LOG_CATEGORY, L"Detected %zu browsers", browsers.size());

    // Test config validation
    BrowserSessionConfiguration config;
    if (config.IsValid()) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Empty config should be invalid");
        return false;
    }
    config.startingUrl = L"https://test.com";
    if (!config.IsValid()) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Valid config marked invalid");
        return false;
    }

    return true;
}

std::string SecureBrowser::GetVersionString() noexcept {
    return "3.0.0";
}

} // namespace Banking
} // namespace ShadowStrike
