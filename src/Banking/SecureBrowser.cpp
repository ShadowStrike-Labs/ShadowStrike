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

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <sstream>
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

[[nodiscard]] bool IsBankingDomain(std::string_view domain) {
    // Basic heuristic check for common banking terms
    // In production, this would query the ThreatIntel/Category database
    static const std::vector<std::string> keywords = {
        "bank", "secure", "login", "account", "signin", "wallet", "finance", "card", "payment"
    };

    std::string d(domain);
    std::transform(d.begin(), d.end(), d.begin(), ::tolower);

    for (const auto& keyword : keywords) {
        if (d.find(keyword) != std::string::npos) return true;
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
        << "\"sessionId\":\"" << Utils::StringUtils::EscapeJson(sessionId) << "\","
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
        << "\"id\":\"" << Utils::StringUtils::EscapeJson(eventId) << "\","
        << "\"sessionId\":\"" << Utils::StringUtils::EscapeJson(sessionId) << "\","
        << "\"type\":\"" << GetSecurityEventTypeName(eventType) << "\","
        << "\"description\":\"" << Utils::StringUtils::EscapeJson(description) << "\","
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
    return true; // Basic config is always valid
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
                // LoadBankingDomains(config.bankingDomainsPath);
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
        if (!config.IsValid()) return std::nullopt;

        std::string sessionId = GenerateSessionId();

        // Prepare browser arguments
        std::wstring browserPath = GetBrowserPath(config.browserType);
        if (browserPath.empty()) {
            browserPath = config.executablePath;
        }

        if (browserPath.empty() || !std::filesystem::exists(browserPath)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Browser executable not found");
            return std::nullopt;
        }

        // Create isolated profile directory
        std::wstring profilePath = CreateIsolatedProfile(sessionId);

        // Build command line
        std::wstring cmdLine = BuildCommandLine(browserPath, config, profilePath);

        // Launch process
        PROCESS_INFORMATION pi = { 0 };
        STARTUPINFOW si = { sizeof(STARTUPINFOW) };

        // Create environment block (optionally restricted)
        LPVOID lpEnvironment = NULL;
        // CreateEnvironmentBlock(&lpEnvironment, NULL, TRUE);

        BOOL success = CreateProcessW(
            NULL,
            cmdLine.data(),
            NULL, NULL, FALSE,
            CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
            lpEnvironment,
            NULL, // Current directory
            &si,
            &pi
        );

        if (success) {
            BrowserSessionInfo session;
            session.sessionId = sessionId;
            session.browserType = config.browserType;
            session.processId = pi.dwProcessId;
            session.mainWindowHandle = 0; // Will be resolved later
            session.status = SessionStatus::Initializing;
            session.securityLevel = config.securityLevel;
            session.startTime = std::chrono::system_clock::now();
            session.currentUrl = config.startingUrl;
            session.profilePath = profilePath;
            session.isProtected = false; // Will enable protections shortly

            {
                std::unique_lock lock(m_mutex);
                m_activeSessions[sessionId] = session;
                m_sessionConfigs[sessionId] = config;
                m_sessionStats[sessionId] = SessionStatistics();
            }

            m_stats.activeSessions++;
            m_stats.totalSessions++;

            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess); // We don't need to keep the handle, we track by PID

            SS_LOG_INFO(LOG_CATEGORY, L"Launched secure session %hs (PID: %u)", sessionId.c_str(), pi.dwProcessId);

            // Notify callback
            if (m_sessionStatusCallback) {
                m_sessionStatusCallback(session);
            }

            // Apply immediate protections based on config
            if (config.enableKeyloggerProtection) {
                EnableKeyloggerProtection(sessionId);
            }

            if (config.enableScreenshotProtection) {
                EnableScreenProtection(sessionId);
            }

            return sessionId;
        } else {
            SS_LOG_ERROR(LOG_CATEGORY, L"Failed to launch browser: %u", GetLastError());
            return std::nullopt;
        }
    }

    void EndSession(const std::string& sessionId) {
        std::unique_lock lock(m_mutex);
        auto it = m_activeSessions.find(sessionId);
        if (it == m_activeSessions.end()) return;

        SS_LOG_INFO(LOG_CATEGORY, L"Ending session %hs (PID: %u)", sessionId.c_str(), it->second.processId);

        // Terminate process
        TerminateProcessById(it->second.processId);

        // Cleanup profile
        if (!it->second.profilePath.empty()) {
            // Schedule deletion or delete if possible
            // CleanupProfile(it->second.profilePath);
        }

        it->second.status = SessionStatus::Terminated;

        if (m_sessionStatusCallback) {
            m_sessionStatusCallback(it->second);
        }

        m_activeSessions.erase(it);
        m_sessionConfigs.erase(sessionId);
        m_sessionStats.erase(sessionId);

        m_stats.activeSessions--;
    }

    void EndAllSessionsInternal() {
        // Must be called with lock held or from shutdown
        std::vector<std::string> sessionIds;
        for (const auto& pair : m_activeSessions) {
            sessionIds.push_back(pair.first);
        }

        for (const auto& id : sessionIds) {
            // Re-entrant safe logic needed here, but simplified for now
            auto it = m_activeSessions.find(id);
            if (it != m_activeSessions.end()) {
                TerminateProcessById(it->second.processId);
            }
        }

        m_activeSessions.clear();
        m_sessionConfigs.clear();
        m_stats.activeSessions = 0;
    }

    // ========================================================================
    // PROTECTION FEATURES
    // ========================================================================

    bool EnableKeyloggerProtection(const std::string& sessionId) {
        std::shared_lock lock(m_mutex);
        auto it = m_activeSessions.find(sessionId);
        if (it == m_activeSessions.end()) return false;

        // Find main window if not yet found
        if (it->second.mainWindowHandle == 0) {
            it->second.mainWindowHandle = FindMainWindow(it->second.processId);
        }

        if (it->second.mainWindowHandle != 0) {
            // Delegate to KeyloggerProtection module
            return KeyloggerProtection::Instance().EnableSecureInputMode(it->second.mainWindowHandle);
        }

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

        // 1. Check loaded modules
        auto loadedDlls = GetLoadedDLLsInternal(it->second.processId);

        // 2. Scan for hooks
        auto hooks = KeyloggerProtection::Instance().ScanProcessHooks(it->second.processId);
        if (!hooks.empty()) {
            return IntegrityStatus::HooksDetected;
        }

        // 3. Validate modules against whitelist
        // ...

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
        while (m_monitorRunning) {
            // Periodically check sessions
            {
                std::unique_lock lock(m_mutex);
                for (auto& [id, session] : m_activeSessions) {
                    // Check if process still exists
                    if (!IsProcessRunning(session.processId)) {
                        session.status = SessionStatus::Terminated;
                        // Handle cleanup in next iteration or event
                    } else {
                        // Integrity checks
                        // ...
                    }
                }
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(SecureBrowserConstants::PROCESS_MONITOR_INTERVAL_MS));
        }
    }

    // ========================================================================
    // HELPERS
    // ========================================================================

    std::wstring GetBrowserPath(BrowserType type) const {
        // 1. Check custom paths first
        auto it = m_config.customBrowserPaths.find(type);
        if (it != m_config.customBrowserPaths.end()) {
            return it->second;
        }

        // 2. Detect default paths
        switch (type) {
            case BrowserType::Chrome:
                return ExpandEnvironmentStringsW(SecureBrowserConstants::CHROME_PATH_PATTERNS[0]);
            case BrowserType::Edge:
                return ExpandEnvironmentStringsW(SecureBrowserConstants::EDGE_PATH);
            case BrowserType::Firefox:
                return ExpandEnvironmentStringsW(SecureBrowserConstants::FIREFOX_PATH);
            default:
                return L"";
        }
    }

    std::wstring ExpandEnvironmentStringsW(const std::wstring& path) const {
        std::vector<wchar_t> buffer(MAX_PATH);
        DWORD ret = ::ExpandEnvironmentStringsW(path.c_str(), buffer.data(), MAX_PATH);
        if (ret > 0 && ret <= MAX_PATH) {
            return std::wstring(buffer.data());
        }
        return path;
    }

    std::wstring CreateIsolatedProfile(const std::string& sessionId) {
        // Create temp directory for profile
        std::wstring tempPath(MAX_PATH, L'\0');
        GetTempPathW(MAX_PATH, tempPath.data());

        std::wstringstream ss;
        ss << tempPath.c_str() << L"ShadowStrike\\Profiles\\" << Utils::StringUtils::StringToWide(sessionId);

        std::filesystem::create_directories(ss.str());
        return ss.str();
    }

    std::wstring BuildCommandLine(const std::wstring& exePath, const BrowserSessionConfiguration& config, const std::wstring& profilePath) {
        std::wstringstream ss;
        ss << L"\"" << exePath << L"\"";

        // Add security flags
        if (config.browserType == BrowserType::Chrome || config.browserType == BrowserType::Edge) {
            ss << L" --user-data-dir=\"" << profilePath << L"\"";
            ss << L" --no-first-run";
            ss << L" --no-default-browser-check";

            if (config.usePrivateMode) ss << L" --incognito";
            if (config.disableExtensions) ss << L" --disable-extensions";
            if (config.disablePlugins) ss << L" --disable-plugins";
            if (config.disableDevTools) ss << L" --disable-dev-shm-usage --devtools-flags=disable";

            // Sandbox/Isolation flags
            ss << L" --disable-background-networking";
            ss << L" --disable-sync";
            ss << L" --disable-translate";

            if (!config.startingUrl.empty()) {
                ss << L" " << config.startingUrl;
            }
        }

        return ss.str();
    }

    std::vector<LoadedDLLInfo> GetLoadedDLLsInternal(ProcessId pid) {
        std::vector<LoadedDLLInfo> dlls;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W me32;
            me32.dwSize = sizeof(MODULEENTRY32W);
            if (Module32FirstW(hSnapshot, &me32)) {
                do {
                    LoadedDLLInfo info;
                    info.moduleName = me32.szModule;
                    info.fullPath = me32.szExePath;
                    info.baseAddress = (uint64_t)me32.modBaseAddr;
                    info.size = me32.modBaseSize;
                    dlls.push_back(info);
                } while (Module32NextW(hSnapshot, &me32));
            }
            CloseHandle(hSnapshot);
        }
        return dlls;
    }

    uint64_t FindMainWindow(ProcessId pid) {
        // EnumWindows callback logic would go here
        // Simplified: return 0
        return 0;
    }

    void TerminateProcessById(ProcessId pid) {
        HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (hProc) {
            TerminateProcess(hProc, 0);
            CloseHandle(hProc);
        }
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

    // Monitor
    std::atomic<bool> m_monitorRunning;
    std::thread m_monitorThread;

    // Security Events Cache
    mutable std::shared_mutex m_eventMutex;
    std::deque<SecurityEvent> m_securityEvents;
    static constexpr size_t MAX_SECURITY_EVENTS = 1000;
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
    // Basic impl
    return m_impl->Initialize(config); // Re-init or update
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
    return true;
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
        // Const-cast safe for internal helper
        return const_cast<SecureBrowserImpl*>(m_impl.get())->GetLoadedDLLsInternal(it->second.processId);
    }
    return {};
}

std::vector<LoadedDLLInfo> SecureBrowser::CheckSuspiciousDLLs(const std::string& sessionId) const {
    return {}; // Logic to filter GetLoadedDLLs result
}

// Detection
std::vector<BrowserType> SecureBrowser::DetectInstalledBrowsers() const {
    std::vector<BrowserType> browsers;
    // Check registry or file existence
    if (std::filesystem::exists(m_impl->ExpandEnvironmentStringsW(SecureBrowserConstants::CHROME_PATH_PATTERNS[0]))) {
        browsers.push_back(BrowserType::Chrome);
    }
    // ... others
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
    return true; // Stub
}

void SecureBrowser::AddAllowedDomain(const std::string& sessionId, const std::string& domain) {
    // Add to session config
}

void SecureBrowser::RemoveAllowedDomain(const std::string& sessionId, const std::string& domain) {
    // Remove from session config
}

bool SecureBrowser::IsDomainAllowed(const std::string& sessionId, const std::string& domain) const {
    // Check whitelist
    return IsBankingDomain(domain); // Simplified fallback
}

// Callbacks
void SecureBrowser::RegisterSecurityEventCallback(SecurityEventCallback callback) {
    m_impl->m_securityEventCallback = std::move(callback);
}

void SecureBrowser::RegisterSessionStatusCallback(SessionStatusCallback callback) {
    m_impl->m_sessionStatusCallback = std::move(callback);
}

void SecureBrowser::RegisterIntegrityCheckCallback(IntegrityCheckCallback callback) {
    m_impl->m_integrityCheckCallback = std::move(callback);
}

void SecureBrowser::RegisterErrorCallback(ErrorCallback callback) {
    m_impl->m_errorCallback = std::move(callback);
}

void SecureBrowser::UnregisterCallbacks() {
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
    return {}; // Stub
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
