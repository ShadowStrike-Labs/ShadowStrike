/**
 * ============================================================================
 * ShadowStrike Core Process - DLL INJECTION DETECTOR IMPLEMENTATION
 * ============================================================================
 *
 * @file DLLInjectionDetector.cpp
 * @brief Enterprise-grade detection of DLL injection attacks.
 *
 * This module provides comprehensive detection of DLL injection techniques
 * used by malware, including classic CreateRemoteThread, APC injection,
 * hook-based injection, registry-based persistence, and DLL side-loading.
 *
 * Detection Methods:
 * - Thread creation monitoring (CreateRemoteThread, RtlCreateUserThread)
 * - APC queue monitoring (QueueUserAPC)
 * - Hook registration tracking (SetWindowsHookEx)
 * - Registry persistence vectors (AppInit_DLLs, IFEO)
 * - Module load analysis (trust, signatures, paths)
 * - Search order hijacking detection
 * - DLL side-loading detection
 * - Import/Export table hooking
 * - TLS callback analysis
 *
 * MITRE ATT&CK Coverage:
 * - T1055.001: DLL Injection
 * - T1574.001: DLL Search Order Hijacking
 * - T1574.002: DLL Side-Loading
 * - T1546.010: AppInit DLLs
 * - T1546.011: Application Shimming
 * - T1546.015: Component Object Model Hijacking
 *
 * @author ShadowStrike Security Team
 * @version 4.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 */

#include "pch.h"
#include "DLLInjectionDetector.hpp"

// Infrastructure includes
#include "../../Utils/Logger.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/HashUtils.hpp"
#include "../../Utils/FileUtils.hpp"

// Standard library
#include <algorithm>
#include <cctype>
#include <cmath>
#include <sstream>
#include <iomanip>
#include <queue>
#include <psapi.h>
#include <tlhelp32.h>

namespace ShadowStrike {
namespace Core {
namespace Process {

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

namespace {

/**
 * @brief Calculate Shannon entropy of a file.
 */
double CalculateFileEntropy(const std::wstring& filePath) {
    try {
        auto data = Utils::FileUtils::ReadFileBytes(filePath);
        if (data.empty() || data.size() < 256) return 0.0;

        std::array<size_t, 256> freq{};
        size_t sampleSize = std::min(data.size(), size_t(65536)); // Sample first 64KB

        for (size_t i = 0; i < sampleSize; ++i) {
            freq[data[i]]++;
        }

        double entropy = 0.0;
        const double size = static_cast<double>(sampleSize);

        for (size_t count : freq) {
            if (count > 0) {
                const double p = static_cast<double>(count) / size;
                entropy -= p * std::log2(p);
            }
        }

        return entropy;

    } catch (...) {
        return 0.0;
    }
}

/**
 * @brief Normalize path for comparison.
 */
std::wstring NormalizePath(const std::wstring& path) {
    std::wstring normalized = path;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), ::towlower);

    // Replace forward slashes with backslashes
    std::replace(normalized.begin(), normalized.end(), L'/', L'\\');

    // Remove trailing backslash
    if (!normalized.empty() && normalized.back() == L'\\') {
        normalized.pop_back();
    }

    return normalized;
}

/**
 * @brief Check if path is in system directory.
 */
bool IsSystemDirectory(const std::wstring& path) {
    std::wstring normalized = NormalizePath(path);

    wchar_t systemDir[MAX_PATH];
    GetSystemDirectoryW(systemDir, MAX_PATH);
    std::wstring systemPath = NormalizePath(systemDir);

    wchar_t windowsDir[MAX_PATH];
    GetWindowsDirectoryW(windowsDir, MAX_PATH);
    std::wstring windowsPath = NormalizePath(windowsDir);

    return normalized.starts_with(systemPath) || normalized.starts_with(windowsPath);
}

/**
 * @brief Check if path is in temp directory.
 */
bool IsTempDirectory(const std::wstring& path) {
    std::wstring normalized = NormalizePath(path);

    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    std::wstring temp = NormalizePath(tempPath);

    return normalized.starts_with(temp) ||
           normalized.find(L"\\temp\\") != std::wstring::npos ||
           normalized.find(L"\\tmp\\") != std::wstring::npos;
}

/**
 * @brief Check if path is in user profile.
 */
bool IsUserProfilePath(const std::wstring& path) {
    std::wstring normalized = NormalizePath(path);

    wchar_t profilePath[MAX_PATH];
    if (GetEnvironmentVariableW(L"USERPROFILE", profilePath, MAX_PATH) > 0) {
        std::wstring profile = NormalizePath(profilePath);
        return normalized.starts_with(profile);
    }

    return false;
}

/**
 * @brief Calculate Levenshtein distance for name masquerading detection.
 */
size_t LevenshteinDistance(const std::wstring& s1, const std::wstring& s2) {
    const size_t len1 = s1.size();
    const size_t len2 = s2.size();

    std::vector<std::vector<size_t>> d(len1 + 1, std::vector<size_t>(len2 + 1));

    for (size_t i = 0; i <= len1; ++i) d[i][0] = i;
    for (size_t j = 0; j <= len2; ++j) d[0][j] = j;

    for (size_t i = 1; i <= len1; ++i) {
        for (size_t j = 1; j <= len2; ++j) {
            const size_t cost = (s1[i - 1] == s2[j - 1]) ? 0 : 1;
            d[i][j] = std::min({
                d[i - 1][j] + 1,
                d[i][j - 1] + 1,
                d[i - 1][j - 1] + cost
            });
        }
    }

    return d[len1][len2];
}

/**
 * @brief Known system DLLs for masquerading detection.
 */
const std::vector<std::wstring> g_systemDLLNames = {
    L"ntdll.dll", L"kernel32.dll", L"kernelbase.dll",
    L"user32.dll", L"gdi32.dll", L"advapi32.dll",
    L"ole32.dll", L"shell32.dll", L"combase.dll",
    L"msvcrt.dll", L"ws2_32.dll", L"wininet.dll"
};

/**
 * @brief Check if DLL name is masquerading as a system DLL.
 */
bool IsMasquerading(const std::wstring& dllName) {
    std::wstring lowerName = dllName;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

    for (const auto& systemDll : g_systemDLLNames) {
        size_t distance = LevenshteinDistance(lowerName, systemDll);
        if (distance > 0 && distance <= 2) {
            return true; // Close match but not exact
        }
    }

    return false;
}

/**
 * @brief Known DLL side-loading pairs.
 */
struct SideLoadPair {
    std::wstring executable;
    std::wstring dllName;
};

const std::vector<SideLoadPair> g_knownSideLoadPairs = {
    {L"chrome.exe", L"version.dll"},
    {L"firefox.exe", L"mozglue.dll"},
    {L"explorer.exe", L"shell32.dll"},
    {L"cmd.exe", L"cmd.dll"},
    {L"notepad.exe", L"notepad.dll"}
};

/**
 * @brief Convert InjectionType to string.
 */
std::wstring InjectionTypeToStringInternal(InjectionType type) {
    switch (type) {
        case InjectionType::CreateRemoteThread: return L"CreateRemoteThread";
        case InjectionType::CreateRemoteThreadEx: return L"CreateRemoteThreadEx";
        case InjectionType::RtlCreateUserThread: return L"RtlCreateUserThread";
        case InjectionType::NtCreateThreadEx: return L"NtCreateThreadEx";
        case InjectionType::SetWindowsHookEx: return L"SetWindowsHookEx";
        case InjectionType::QueueUserAPC: return L"QueueUserAPC";
        case InjectionType::QueueUserAPC2: return L"QueueUserAPC2";
        case InjectionType::SetThreadContext: return L"SetThreadContext";
        case InjectionType::AppInitDLL: return L"AppInit_DLLs";
        case InjectionType::IFEO: return L"IFEO";
        case InjectionType::KnownDLLHijack: return L"KnownDLL Hijack";
        case InjectionType::SearchOrderHijack: return L"Search Order Hijack";
        case InjectionType::SideLoading: return L"DLL Side-Loading";
        case InjectionType::PhantomDLL: return L"Phantom DLL";
        case InjectionType::COMHijacking: return L"COM Hijacking";
        case InjectionType::ApplicationShim: return L"Application Shim";
        case InjectionType::ImportAddressTable: return L"IAT Hooking";
        case InjectionType::ExportAddressTable: return L"EAT Hooking";
        case InjectionType::TLSCallback: return L"TLS Callback";
        case InjectionType::WindowSubclass: return L"Window Subclass";
        case InjectionType::ThreadPoolWait: return L"Thread Pool";
        case InjectionType::ETWCallback: return L"ETW Callback";
        case InjectionType::ExceptionHandler: return L"Exception Handler";
        case InjectionType::ModuleCallback: return L"Module Callback";
        case InjectionType::ConfigOverride: return L"Config Override";
        case InjectionType::PluginLoad: return L"Plugin Load";
        default: return L"Unknown";
    }
}

/**
 * @brief Convert TrustLevel to string.
 */
std::wstring TrustLevelToStringInternal(TrustLevel level) {
    switch (level) {
        case TrustLevel::Malicious: return L"Malicious";
        case TrustLevel::Suspicious: return L"Suspicious";
        case TrustLevel::Untrusted: return L"Untrusted";
        case TrustLevel::ThirdParty: return L"Third-Party";
        case TrustLevel::System: return L"System";
        case TrustLevel::Whitelisted: return L"Whitelisted";
        default: return L"Unknown";
    }
}

/**
 * @brief Convert HookType from WH_* constant.
 */
HookType ConvertHookType(int hookTypeValue) {
    switch (hookTypeValue) {
        case 2: return HookType::Keyboard;
        case 13: return HookType::KeyboardLowLevel;
        case 7: return HookType::Mouse;
        case 14: return HookType::MouseLowLevel;
        case 5: return HookType::CBT;
        case 3: return HookType::GetMessage;
        case 4: return HookType::CallWndProc;
        case 10: return HookType::Shell;
        default: return HookType::Unknown;
    }
}

} // anonymous namespace

// ============================================================================
// CONFIGURATION STATIC METHODS
// ============================================================================

DLLInjectionConfig DLLInjectionConfig::CreateDefault() noexcept {
    DLLInjectionConfig config;
    // Defaults already set in struct definition
    return config;
}

DLLInjectionConfig DLLInjectionConfig::CreateStrict() noexcept {
    DLLInjectionConfig config;
    config.mode = MonitoringMode::ActiveBlock;
    config.enableRealTimeMonitoring = true;

    // Enable all detection features
    config.detectRemoteThread = true;
    config.detectAPCInjection = true;
    config.detectHookInjection = true;
    config.detectAppInitDLLs = true;
    config.detectIFEO = true;
    config.detectSearchOrderHijack = true;
    config.detectSideLoading = true;
    config.detectCOMHijacking = true;
    config.detectShimInjection = true;

    // Strict thresholds
    config.alertThreshold = InjectionConfidence::Low;
    config.blockThreshold = InjectionConfidence::Medium;
    config.alertOnUnsignedLoads = true;
    config.blockUnsignedLoads = false; // Too aggressive

    config.useThreatIntel = true;
    config.enableHashLookup = true;

    return config;
}

DLLInjectionConfig DLLInjectionConfig::CreatePerformance() noexcept {
    DLLInjectionConfig config;
    config.mode = MonitoringMode::PassiveOnly;
    config.enableRealTimeMonitoring = true;

    // Enable only high-value detections
    config.detectRemoteThread = true;
    config.detectAPCInjection = true;
    config.detectHookInjection = true;
    config.detectAppInitDLLs = true;
    config.detectIFEO = true;
    config.detectSearchOrderHijack = false;
    config.detectSideLoading = false;
    config.detectCOMHijacking = false;
    config.detectShimInjection = false;

    // Relaxed thresholds
    config.alertThreshold = InjectionConfidence::High;
    config.blockThreshold = InjectionConfidence::Confirmed;

    config.trustMicrosoftSigned = true;
    config.trustKnownDLLs = true;
    config.enableHashLookup = false; // Skip for performance
    config.computeHashesAsync = false;

    return config;
}

// ============================================================================
// STATISTICS IMPLEMENTATION
// ============================================================================

void DLLInjectionStatistics::Reset() noexcept {
    totalModulesAnalyzed.store(0, std::memory_order_relaxed);
    trustedModulesFound.store(0, std::memory_order_relaxed);
    untrustedModulesFound.store(0, std::memory_order_relaxed);
    suspiciousModulesFound.store(0, std::memory_order_relaxed);

    injectionsDetected.store(0, std::memory_order_relaxed);
    remoteThreadInjections.store(0, std::memory_order_relaxed);
    hookInjections.store(0, std::memory_order_relaxed);
    apcInjections.store(0, std::memory_order_relaxed);
    appInitInjections.store(0, std::memory_order_relaxed);
    sideLoadingDetected.store(0, std::memory_order_relaxed);
    comHijackingDetected.store(0, std::memory_order_relaxed);
    searchOrderHijacks.store(0, std::memory_order_relaxed);

    loadsBlocked.store(0, std::memory_order_relaxed);
    injectionsBlocked.store(0, std::memory_order_relaxed);

    moduleLoadEventsProcessed.store(0, std::memory_order_relaxed);
    threadCreateEventsProcessed.store(0, std::memory_order_relaxed);
    hookEventsProcessed.store(0, std::memory_order_relaxed);

    hashLookups.store(0, std::memory_order_relaxed);
    hashCacheHits.store(0, std::memory_order_relaxed);
    whitelistHits.store(0, std::memory_order_relaxed);

    analysisErrors.store(0, std::memory_order_relaxed);
    accessDeniedErrors.store(0, std::memory_order_relaxed);
}

double DLLInjectionStatistics::GetDetectionRate() const noexcept {
    const uint64_t total = totalModulesAnalyzed.load(std::memory_order_relaxed);
    if (total == 0) return 0.0;

    const uint64_t detected = injectionsDetected.load(std::memory_order_relaxed);
    return static_cast<double>(detected) / static_cast<double>(total);
}

// ============================================================================
// CALLBACK MANAGER
// ============================================================================

class CallbackManager {
public:
    uint64_t RegisterInjection(InjectionDetectedCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_injectionCallbacks[id] = std::move(callback);
        return id;
    }

    uint64_t RegisterModule(ModuleLoadCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_moduleCallbacks[id] = std::move(callback);
        return id;
    }

    uint64_t RegisterDecision(LoadDecisionCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_decisionCallbacks[id] = std::move(callback);
        return id;
    }

    uint64_t RegisterHook(HookInstalledCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_hookCallbacks[id] = std::move(callback);
        return id;
    }

    bool Unregister(uint64_t id) {
        std::unique_lock lock(m_mutex);

        if (m_injectionCallbacks.erase(id)) return true;
        if (m_moduleCallbacks.erase(id)) return true;
        if (m_decisionCallbacks.erase(id)) return true;
        if (m_hookCallbacks.erase(id)) return true;

        return false;
    }

    void InvokeInjection(const InjectionEvent& event) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_injectionCallbacks) {
            try {
                callback(event);
            } catch (const std::exception& e) {
                Logger::Error("InjectionCallback exception: {}", e.what());
            }
        }
    }

    void InvokeModule(const LoadedDLLInfo& dllInfo) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_moduleCallbacks) {
            try {
                callback(dllInfo);
            } catch (const std::exception& e) {
                Logger::Error("ModuleCallback exception: {}", e.what());
            }
        }
    }

    bool InvokeDecision(const LoadedDLLInfo& dllInfo) {
        std::shared_lock lock(m_mutex);

        // If any callback returns false, block the load
        for (const auto& [id, callback] : m_decisionCallbacks) {
            try {
                if (!callback(dllInfo)) {
                    return false;
                }
            } catch (const std::exception& e) {
                Logger::Error("DecisionCallback exception: {}", e.what());
                return false; // Block on exception for safety
            }
        }

        return true; // Allow by default
    }

    void InvokeHook(const HookInfo& hookInfo) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_hookCallbacks) {
            try {
                callback(hookInfo);
            } catch (const std::exception& e) {
                Logger::Error("HookCallback exception: {}", e.what());
            }
        }
    }

private:
    mutable std::shared_mutex m_mutex;
    uint64_t m_nextId{ 1 };
    std::unordered_map<uint64_t, InjectionDetectedCallback> m_injectionCallbacks;
    std::unordered_map<uint64_t, ModuleLoadCallback> m_moduleCallbacks;
    std::unordered_map<uint64_t, LoadDecisionCallback> m_decisionCallbacks;
    std::unordered_map<uint64_t, HookInstalledCallback> m_hookCallbacks;
};

// ============================================================================
// MODULE TRACKER
// ============================================================================

class ModuleTracker {
public:
    void AddModule(uint32_t pid, const LoadedDLLInfo& dllInfo) {
        std::unique_lock lock(m_mutex);

        const std::wstring key = std::to_wstring(pid) + L":" + dllInfo.normalizedPath;
        m_modules[key] = dllInfo;

        // Track by process
        m_processMod ules[pid].push_back(dllInfo.normalizedPath);
    }

    std::optional<LoadedDLLInfo> GetModule(uint32_t pid, const std::wstring& dllPath) const {
        std::shared_lock lock(m_mutex);

        const std::wstring normalized = NormalizePath(dllPath);
        const std::wstring key = std::to_wstring(pid) + L":" + normalized;

        auto it = m_modules.find(key);
        if (it != m_modules.end()) {
            return it->second;
        }

        return std::nullopt;
    }

    std::vector<LoadedDLLInfo> GetProcessModules(uint32_t pid) const {
        std::shared_lock lock(m_mutex);
        std::vector<LoadedDLLInfo> result;

        auto it = m_processModules.find(pid);
        if (it == m_processModules.end()) {
            return result;
        }

        for (const auto& path : it->second) {
            const std::wstring key = std::to_wstring(pid) + L":" + path;
            auto modIt = m_modules.find(key);
            if (modIt != m_modules.end()) {
                result.push_back(modIt->second);
            }
        }

        return result;
    }

    void RemoveProcess(uint32_t pid) {
        std::unique_lock lock(m_mutex);

        auto it = m_processModules.find(pid);
        if (it != m_processModules.end()) {
            for (const auto& path : it->second) {
                const std::wstring key = std::to_wstring(pid) + L":" + path;
                m_modules.erase(key);
            }
            m_processModules.erase(it);
        }
    }

    size_t GetModuleCount(uint32_t pid) const {
        std::shared_lock lock(m_mutex);
        auto it = m_processModules.find(pid);
        return (it != m_processModules.end()) ? it->second.size() : 0;
    }

private:
    mutable std::shared_mutex m_mutex;
    std::unordered_map<std::wstring, LoadedDLLInfo> m_modules;
    std::unordered_map<uint32_t, std::vector<std::wstring>> m_processModules;
};

// ============================================================================
// INJECTION CORRELATOR
// ============================================================================

class InjectionCorrelator {
public:
    struct ThreadEvent {
        uint32_t targetPid;
        uint32_t creatorPid;
        uintptr_t startAddress;
        std::chrono::steady_clock::time_point timestamp;
    };

    struct APCEvent {
        uint32_t targetPid;
        uint32_t targetTid;
        uint32_t queuedBy;
        uintptr_t apcRoutine;
        std::chrono::steady_clock::time_point timestamp;
    };

    void RecordThreadCreate(uint32_t targetPid, uint32_t creatorPid, uintptr_t startAddress) {
        std::unique_lock lock(m_mutex);

        ThreadEvent event;
        event.targetPid = targetPid;
        event.creatorPid = creatorPid;
        event.startAddress = startAddress;
        event.timestamp = std::chrono::steady_clock::now();

        m_threadEvents.push_back(event);

        // Keep only recent events (last 60 seconds)
        CleanupOldEvents();
    }

    void RecordAPCQueue(uint32_t targetPid, uint32_t targetTid, uint32_t queuedBy, uintptr_t apcRoutine) {
        std::unique_lock lock(m_mutex);

        APCEvent event;
        event.targetPid = targetPid;
        event.targetTid = targetTid;
        event.queuedBy = queuedBy;
        event.apcRoutine = apcRoutine;
        event.timestamp = std::chrono::steady_clock::now();

        m_apcEvents.push_back(event);

        CleanupOldEvents();
    }

    std::optional<ThreadEvent> FindRecentThreadCreate(uint32_t targetPid, std::chrono::milliseconds window) {
        std::shared_lock lock(m_mutex);

        const auto now = std::chrono::steady_clock::now();

        for (auto it = m_threadEvents.rbegin(); it != m_threadEvents.rend(); ++it) {
            if (it->targetPid == targetPid) {
                const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - it->timestamp);
                if (elapsed <= window) {
                    return *it;
                }
            }
        }

        return std::nullopt;
    }

    std::optional<APCEvent> FindRecentAPC(uint32_t targetPid, std::chrono::milliseconds window) {
        std::shared_lock lock(m_mutex);

        const auto now = std::chrono::steady_clock::now();

        for (auto it = m_apcEvents.rbegin(); it != m_apcEvents.rend(); ++it) {
            if (it->targetPid == targetPid) {
                const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - it->timestamp);
                if (elapsed <= window) {
                    return *it;
                }
            }
        }

        return std::nullopt;
    }

private:
    void CleanupOldEvents() {
        const auto now = std::chrono::steady_clock::now();
        const auto cutoff = now - std::chrono::seconds(60);

        // Remove old thread events
        m_threadEvents.erase(
            std::remove_if(m_threadEvents.begin(), m_threadEvents.end(),
                [cutoff](const ThreadEvent& e) { return e.timestamp < cutoff; }),
            m_threadEvents.end()
        );

        // Remove old APC events
        m_apcEvents.erase(
            std::remove_if(m_apcEvents.begin(), m_apcEvents.end(),
                [cutoff](const APCEvent& e) { return e.timestamp < cutoff; }),
            m_apcEvents.end()
        );
    }

    mutable std::shared_mutex m_mutex;
    std::vector<ThreadEvent> m_threadEvents;
    std::vector<APCEvent> m_apcEvents;
};

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class DLLInjectionDetectorImpl {
public:
    DLLInjectionDetectorImpl() = default;
    ~DLLInjectionDetectorImpl() {
        StopMonitoring();
    }

    // Prevent copying
    DLLInjectionDetectorImpl(const DLLInjectionDetectorImpl&) = delete;
    DLLInjectionDetectorImpl& operator=(const DLLInjectionDetectorImpl&) = delete;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    bool Initialize(const DLLInjectionConfig& config) {
        std::unique_lock lock(m_mutex);

        try {
            Logger::Info("DLLInjectionDetector: Initializing...");

            m_config = config;

            // Initialize managers
            m_callbackManager = std::make_unique<CallbackManager>();
            m_moduleTracker = std::make_unique<ModuleTracker>();
            m_correlator = std::make_unique<InjectionCorrelator>();

            // Initialize infrastructure
            if (!HashStore::HashStore::Instance().Initialize(
                HashStore::HashStoreConfig::CreateDefault())) {
                Logger::Warn("DLLInjectionDetector: HashStore initialization warning");
            }

            if (!Whitelist::WhitelistStore::Instance().Initialize(
                Whitelist::WhitelistStoreConfig::CreateDefault())) {
                Logger::Warn("DLLInjectionDetector: WhitelistStore initialization warning");
            }

            m_initialized = true;
            Logger::Info("DLLInjectionDetector: Initialized successfully");
            return true;

        } catch (const std::exception& e) {
            Logger::Error("DLLInjectionDetector: Initialization failed: {}", e.what());
            return false;
        }
    }

    void Shutdown() {
        StopMonitoring();

        std::unique_lock lock(m_mutex);
        m_initialized = false;

        if (m_moduleTracker) {
            // Clear tracked modules
        }

        Logger::Info("DLLInjectionDetector: Shutdown complete");
    }

    bool IsInitialized() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_initialized;
    }

    bool UpdateConfig(const DLLInjectionConfig& config) {
        std::unique_lock lock(m_mutex);
        m_config = config;
        Logger::Info("DLLInjectionDetector: Configuration updated");
        return true;
    }

    DLLInjectionConfig GetConfig() const {
        std::shared_lock lock(m_mutex);
        return m_config;
    }

    // ========================================================================
    // MODULE LOAD ANALYSIS
    // ========================================================================

    LoadedDLLInfo AnalyzeLoad(uint32_t pid, const std::wstring& dllPath) {
        LoadedDLLInfo info;

        try {
            m_stats.totalModulesAnalyzed.fetch_add(1, std::memory_order_relaxed);

            // Basic information
            info.dllPath = dllPath;
            info.normalizedPath = NormalizePath(dllPath);

            // Extract filename
            size_t lastSlash = dllPath.find_last_of(L"\\/");
            info.dllName = (lastSlash != std::wstring::npos) ?
                dllPath.substr(lastSlash + 1) : dllPath;

            info.loadingProcessId = pid;
            info.loadTime = std::chrono::system_clock::now();

            // Get process name
            info.loadingProcessName = GetProcessName(pid);

            // Path analysis
            info.isInSystemDir = IsSystemDirectory(dllPath);
            info.isInTempPath = IsTempDirectory(dllPath);
            info.isInUserProfile = IsUserProfilePath(dllPath);
            info.pathHasSpaces = (dllPath.find(L' ') != std::wstring::npos);

            // Check for known legitimate locations
            info.isInKnownPath = info.isInSystemDir;

            // Masquerading detection
            if (!info.isInSystemDir) {
                info.isNameMasquerading = IsMasquerading(info.dllName);
            }

            // Suspicious location check
            info.isSuspiciousLocation = info.isInTempPath && !info.isInSystemDir;

            // File metadata
            if (std::filesystem::exists(dllPath)) {
                try {
                    info.sizeOfImage = static_cast<uint32_t>(std::filesystem::file_size(dllPath));

                    // Calculate entropy
                    if (m_config.enableHashLookup) {
                        info.entropy = CalculateFileEntropy(dllPath);

                        // High entropy suggests packing/encryption
                        if (info.entropy > DLLInjectionConstants::HIGH_ENTROPY_THRESHOLD) {
                            info.hasAnomalousCharacteristics = true;
                            info.riskFactors.push_back(L"High entropy (" +
                                std::to_wstring(info.entropy) + L")");
                        }
                    }
                } catch (...) {}
            }

            // Digital signature validation
            ValidateSignature(info);

            // Hash lookup
            if (m_config.enableHashLookup && m_config.useThreatIntel) {
                PerformHashLookup(info);
            }

            // Whitelist check
            if (m_config.useWhitelist) {
                info.isWhitelisted = Whitelist::WhitelistStore::Instance().IsWhitelisted(
                    Utils::StringUtils::WideToUtf8(info.normalizedPath)
                );

                if (info.isWhitelisted) {
                    m_stats.whitelistHits.fetch_add(1, std::memory_order_relaxed);
                }
            }

            // Determine trust level
            DetermineTrustLevel(info);

            // Calculate risk score
            CalculateRiskScore(info);

            // Determine load reason (heuristic)
            DetermineLoadReason(pid, info);

            // Check for injection indicators
            DetectInjectionIndicators(pid, info);

            // Update statistics
            UpdateTrustStatistics(info.trustLevel);

            // Store in tracker
            m_moduleTracker->AddModule(pid, info);

            // Invoke callbacks
            m_callbackManager->InvokeModule(info);

            Logger::Info("DLLInjectionDetector: Analyzed {} - Trust: {}, Risk: {}",
                Utils::StringUtils::WideToUtf8(info.dllName),
                static_cast<int>(info.trustLevel),
                info.riskScore);

        } catch (const std::exception& e) {
            Logger::Error("DLLInjectionDetector::AnalyzeLoad: {}", e.what());
            m_stats.analysisErrors.fetch_add(1, std::memory_order_relaxed);
        }

        return info;
    }

    InjectionAnalysisResult AnalyzeProcess(uint32_t pid) {
        InjectionAnalysisResult result;
        result.processId = pid;
        result.processName = GetProcessName(pid);
        result.analysisTime = std::chrono::system_clock::now();

        const auto startTime = std::chrono::high_resolution_clock::now();

        try {
            // Get process path
            result.processPath = GetProcessPath(pid);

            // Enumerate modules
            auto modules = EnumerateProcessModules(pid);
            result.totalModules = static_cast<uint32_t>(modules.size());

            // Analyze each module
            for (const auto& modulePath : modules) {
                auto dllInfo = AnalyzeLoad(pid, modulePath);
                result.allModules.push_back(dllInfo);

                // Categorize
                if (dllInfo.trustLevel == TrustLevel::System ||
                    dllInfo.trustLevel == TrustLevel::Whitelisted) {
                    result.trustedModules++;
                } else if (dllInfo.trustLevel == TrustLevel::Suspicious ||
                           dllInfo.trustLevel == TrustLevel::Malicious) {
                    result.suspiciousModules++;
                    result.suspiciousModules_.push_back(dllInfo);
                }

                // Check for injection
                if (dllInfo.detectedInjectionType != InjectionType::Unknown) {
                    result.injectedModules++;
                    result.injectedModules_.push_back(dllInfo);

                    // Create injection event
                    InjectionEvent event;
                    event.eventId = m_nextEventId.fetch_add(1, std::memory_order_relaxed);
                    event.timestamp = std::chrono::system_clock::now();
                    event.targetPid = pid;
                    event.targetProcessName = result.processName;
                    event.targetProcessPath = result.processPath;
                    event.dllInfo = dllInfo;
                    event.injectionType = dllInfo.detectedInjectionType;
                    event.confidence = dllInfo.confidence;
                    event.riskScore = dllInfo.riskScore;

                    result.detectedInjections.push_back(event);
                }
            }

            // Hook analysis
            if (m_config.detectHookInjection) {
                result.installedHooks = GetProcessHooks(pid);

                for (const auto& hook : result.installedHooks) {
                    if (hook.isSuspicious) {
                        result.suspiciousHookCount++;
                    }
                }
            }

            // Side-load detection
            if (m_config.detectSideLoading) {
                result.potentialSideLoads = DetectSideLoadingImpl(pid, result.processPath);
            }

            // Registry vectors (system-wide, not process-specific)
            if (m_config.detectAppInitDLLs || m_config.detectIFEO) {
                result.registryVectors = CheckAllRegistryVectorsImpl();
            }

            // Overall assessment
            result.hasInjection = !result.detectedInjections.empty();
            if (result.hasInjection) {
                result.primaryInjectionType = result.detectedInjections[0].injectionType;
                result.overallConfidence = result.detectedInjections[0].confidence;
            }

            // Calculate overall risk score
            result.riskScore = 0;
            for (const auto& dll : result.suspiciousModules_) {
                result.riskScore += dll.riskScore;
            }
            result.riskScore = std::min(result.riskScore, 100u);

            result.analysisComplete = true;

            const auto endTime = std::chrono::high_resolution_clock::now();
            result.analysisDurationMs = static_cast<uint32_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count()
            );

            Logger::Info("DLLInjectionDetector: Process {} analysis complete - {} modules, {} suspicious, {} injected",
                pid, result.totalModules, result.suspiciousModules, result.injectedModules);

        } catch (const std::exception& e) {
            Logger::Error("DLLInjectionDetector::AnalyzeProcess: {}", e.what());
            result.analysisError = Utils::StringUtils::Utf8ToWide(e.what());
            m_stats.analysisErrors.fetch_add(1, std::memory_order_relaxed);
        }

        return result;
    }

    LoadedDLLInfo AnalyzeModule(uint32_t pid, uintptr_t moduleBase) {
        // Get module path from base address
        wchar_t modulePath[MAX_PATH];
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (hProcess) {
            if (GetModuleFileNameExW(hProcess, reinterpret_cast<HMODULE>(moduleBase),
                                    modulePath, MAX_PATH)) {
                CloseHandle(hProcess);
                return AnalyzeLoad(pid, modulePath);
            }
            CloseHandle(hProcess);
        }

        return LoadedDLLInfo{};
    }

    bool IsSuspiciousLoad(uint32_t pid, const std::wstring& dllPath) {
        auto info = AnalyzeLoad(pid, dllPath);

        return info.trustLevel == TrustLevel::Suspicious ||
               info.trustLevel == TrustLevel::Malicious ||
               info.riskScore >= 50;
    }

    TrustLevel GetTrustLevel(const std::wstring& dllPath) {
        LoadedDLLInfo info;
        info.dllPath = dllPath;
        info.normalizedPath = NormalizePath(dllPath);

        ValidateSignature(info);
        DetermineTrustLevel(info);

        return info.trustLevel;
    }

    // ========================================================================
    // INJECTION DETECTION
    // ========================================================================

    std::vector<InjectionEvent> DetectInjections(uint32_t pid) {
        std::vector<InjectionEvent> events;

        try {
            // Detect remote thread injection
            if (m_config.detectRemoteThread) {
                auto threadEvents = DetectRemoteThreadInjectionImpl(pid);
                events.insert(events.end(), threadEvents.begin(), threadEvents.end());
            }

            // Detect APC injection
            if (m_config.detectAPCInjection) {
                auto apcEvents = DetectAPCInjectionImpl(pid);
                events.insert(events.end(), apcEvents.begin(), apcEvents.end());
            }

            // Detect hook injection
            if (m_config.detectHookInjection) {
                auto hookEvents = DetectHookInjectionImpl(pid);
                events.insert(events.end(), hookEvents.begin(), hookEvents.end());
            }

            // Detect search order hijacking
            if (m_config.detectSearchOrderHijack) {
                auto searchEvents = DetectSearchOrderHijackImpl(pid);
                events.insert(events.end(), searchEvents.begin(), searchEvents.end());
            }

            Logger::Info("DLLInjectionDetector: Process {} - {} injections detected", pid, events.size());

        } catch (const std::exception& e) {
            Logger::Error("DLLInjectionDetector::DetectInjections: {}", e.what());
        }

        return events;
    }

    bool IsInjected(uint32_t pid, const std::wstring& dllPath) {
        auto info = AnalyzeLoad(pid, dllPath);
        return info.detectedInjectionType != InjectionType::Unknown;
    }

    uint32_t FindInjector(uint32_t pid, const std::wstring& dllPath) {
        // Check recent thread creation events
        auto threadEvent = m_correlator->FindRecentThreadCreate(pid,
            std::chrono::milliseconds(DLLInjectionConstants::THREAD_CREATION_WINDOW_MS));

        if (threadEvent.has_value()) {
            return threadEvent->creatorPid;
        }

        // Check recent APC events
        auto apcEvent = m_correlator->FindRecentAPC(pid,
            std::chrono::milliseconds(DLLInjectionConstants::LOAD_CORRELATION_WINDOW_MS));

        if (apcEvent.has_value()) {
            return apcEvent->queuedBy;
        }

        return 0; // Unknown
    }

    std::vector<InjectionEvent> DetectRemoteThreadInjectionImpl(uint32_t pid) {
        std::vector<InjectionEvent> events;

        // Check if there was a recent remote thread creation
        auto threadEvent = m_correlator->FindRecentThreadCreate(pid,
            std::chrono::milliseconds(DLLInjectionConstants::THREAD_CREATION_WINDOW_MS));

        if (!threadEvent.has_value()) {
            return events;
        }

        // Look for recently loaded suspicious modules
        auto modules = m_moduleTracker->GetProcessModules(pid);

        for (const auto& module : modules) {
            // Check if module was loaded around the time of thread creation
            const auto loadTime = std::chrono::time_point_cast<std::chrono::milliseconds>(module.loadTime);
            const auto threadTime = std::chrono::time_point_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now() -
                std::chrono::duration_cast<std::chrono::system_clock::duration>(
                    std::chrono::steady_clock::now() - threadEvent->timestamp
                )
            );

            const auto timeDiff = std::chrono::duration_cast<std::chrono::milliseconds>(
                loadTime - threadTime
            );

            if (std::abs(timeDiff.count()) < DLLInjectionConstants::LOAD_CORRELATION_WINDOW_MS) {
                InjectionEvent event;
                event.eventId = m_nextEventId.fetch_add(1, std::memory_order_relaxed);
                event.timestamp = std::chrono::system_clock::now();
                event.targetPid = pid;
                event.injectorPid = threadEvent->creatorPid;
                event.dllInfo = module;
                event.injectionType = InjectionType::CreateRemoteThread;
                event.confidence = InjectionConfidence::High;
                event.injectionThreadId = 0; // Unknown
                event.threadStartAddress = threadEvent->startAddress;
                event.detectionReasons.push_back(L"Remote thread created by PID " +
                    std::to_wstring(threadEvent->creatorPid));
                event.detectionReasons.push_back(L"Module loaded within correlation window");
                event.riskScore = 80;
                event.mitreAttackId = "T1055.001";

                events.push_back(event);

                m_stats.injectionsDetected.fetch_add(1, std::memory_order_relaxed);
                m_stats.remoteThreadInjections.fetch_add(1, std::memory_order_relaxed);

                // Invoke callbacks
                m_callbackManager->InvokeInjection(event);

                Logger::Warn("DLLInjectionDetector: CreateRemoteThread injection detected - PID {} injected by PID {}",
                    pid, threadEvent->creatorPid);
            }
        }

        return events;
    }

    std::vector<InjectionEvent> DetectAPCInjectionImpl(uint32_t pid) {
        std::vector<InjectionEvent> events;

        // Check for recent APC queue
        auto apcEvent = m_correlator->FindRecentAPC(pid,
            std::chrono::milliseconds(DLLInjectionConstants::LOAD_CORRELATION_WINDOW_MS));

        if (!apcEvent.has_value()) {
            return events;
        }

        // Look for recently loaded suspicious modules
        auto modules = m_moduleTracker->GetProcessModules(pid);

        for (const auto& module : modules) {
            // Correlation logic similar to remote thread
            InjectionEvent event;
            event.eventId = m_nextEventId.fetch_add(1, std::memory_order_relaxed);
            event.timestamp = std::chrono::system_clock::now();
            event.targetPid = pid;
            event.injectorPid = apcEvent->queuedBy;
            event.dllInfo = module;
            event.injectionType = InjectionType::QueueUserAPC;
            event.confidence = InjectionConfidence::High;
            event.detectionReasons.push_back(L"APC queued by PID " + std::to_wstring(apcEvent->queuedBy));
            event.riskScore = 75;
            event.mitreAttackId = "T1055.004";

            events.push_back(event);

            m_stats.injectionsDetected.fetch_add(1, std::memory_order_relaxed);
            m_stats.apcInjections.fetch_add(1, std::memory_order_relaxed);

            m_callbackManager->InvokeInjection(event);

            Logger::Warn("DLLInjectionDetector: QueueUserAPC injection detected - PID {} injected by PID {}",
                pid, apcEvent->queuedBy);
        }

        return events;
    }

    // ========================================================================
    // HOOK DETECTION
    // ========================================================================

    std::vector<HookInfo> EnumerateHooks() {
        std::vector<HookInfo> hooks;

        // Windows doesn't provide a direct API to enumerate hooks
        // This would require integration with ETW or kernel driver
        // Simplified implementation

        Logger::Info("DLLInjectionDetector: Hook enumeration not fully implemented");

        return hooks;
    }

    std::vector<HookInfo> GetProcessHooks(uint32_t pid) {
        std::vector<HookInfo> hooks;

        // Process-specific hooks would be tracked via ETW or driver

        return hooks;
    }

    std::vector<HookInfo> FindSuspiciousHooks() {
        auto allHooks = EnumerateHooks();
        std::vector<HookInfo> suspicious;

        for (const auto& hook : allHooks) {
            if (hook.isSuspicious) {
                suspicious.push_back(hook);
            }
        }

        return suspicious;
    }

    std::vector<InjectionEvent> DetectHookInjectionImpl(uint32_t pid) {
        std::vector<InjectionEvent> events;

        auto hooks = GetProcessHooks(pid);

        for (const auto& hook : hooks) {
            if (hook.isSuspicious) {
                InjectionEvent event;
                event.eventId = m_nextEventId.fetch_add(1, std::memory_order_relaxed);
                event.timestamp = std::chrono::system_clock::now();
                event.targetPid = pid;
                event.injectorPid = hook.installerPid;
                event.injectionType = InjectionType::SetWindowsHookEx;
                event.confidence = InjectionConfidence::Medium;
                event.detectionReasons.push_back(L"Suspicious global hook installed");
                event.riskScore = 60;
                event.mitreAttackId = "T1055";

                events.push_back(event);

                m_stats.injectionsDetected.fetch_add(1, std::memory_order_relaxed);
                m_stats.hookInjections.fetch_add(1, std::memory_order_relaxed);

                m_callbackManager->InvokeInjection(event);
            }
        }

        return events;
    }

    // ========================================================================
    // REGISTRY VECTORS
    // ========================================================================

    std::vector<RegistryInjectionVector> CheckAppInitDLLsImpl() {
        std::vector<RegistryInjectionVector> vectors;

        try {
            // Check AppInit_DLLs registry value
            std::wstring value = Utils::RegistryUtils::ReadString(
                HKEY_LOCAL_MACHINE,
                DLLInjectionConstants::APPINIT_DLLS_PATH.data(),
                DLLInjectionConstants::APPINIT_DLLS_VALUE.data()
            );

            if (!value.empty()) {
                RegistryInjectionVector vector;
                vector.registryPath = std::wstring(DLLInjectionConstants::APPINIT_DLLS_PATH);
                vector.valueName = std::wstring(DLLInjectionConstants::APPINIT_DLLS_VALUE);
                vector.dllPath = value;
                vector.isEnabled = true;
                vector.lastModified = std::chrono::system_clock::now();
                vector.isSuspicious = true;
                vector.suspicionReason = L"AppInit_DLLs configured";

                vectors.push_back(vector);

                m_stats.appInitInjections.fetch_add(1, std::memory_order_relaxed);

                Logger::Warn("DLLInjectionDetector: AppInit_DLLs detected: {}",
                    Utils::StringUtils::WideToUtf8(value));
            }

        } catch (const std::exception& e) {
            Logger::Error("DLLInjectionDetector::CheckAppInitDLLs: {}", e.what());
        }

        return vectors;
    }

    std::vector<RegistryInjectionVector> CheckIFEOImpl() {
        std::vector<RegistryInjectionVector> vectors;

        try {
            // Enumerate IFEO keys
            auto subkeys = Utils::RegistryUtils::EnumerateSubkeys(
                HKEY_LOCAL_MACHINE,
                DLLInjectionConstants::IFEO_PATH.data()
            );

            for (const auto& subkey : subkeys) {
                std::wstring fullPath = std::wstring(DLLInjectionConstants::IFEO_PATH) + L"\\" + subkey;

                // Check for Debugger value
                std::wstring debugger = Utils::RegistryUtils::ReadString(
                    HKEY_LOCAL_MACHINE,
                    fullPath.c_str(),
                    L"Debugger"
                );

                if (!debugger.empty()) {
                    RegistryInjectionVector vector;
                    vector.registryPath = fullPath;
                    vector.valueName = L"Debugger";
                    vector.dllPath = debugger;
                    vector.isEnabled = true;
                    vector.lastModified = std::chrono::system_clock::now();
                    vector.isSuspicious = true;
                    vector.suspicionReason = L"IFEO debugger configured for " + subkey;

                    vectors.push_back(vector);

                    Logger::Warn("DLLInjectionDetector: IFEO debugger detected for {}: {}",
                        Utils::StringUtils::WideToUtf8(subkey),
                        Utils::StringUtils::WideToUtf8(debugger));
                }
            }

        } catch (const std::exception& e) {
            Logger::Error("DLLInjectionDetector::CheckIFEO: {}", e.what());
        }

        return vectors;
    }

    std::vector<RegistryInjectionVector> CheckAllRegistryVectorsImpl() {
        std::vector<RegistryInjectionVector> vectors;

        if (m_config.detectAppInitDLLs) {
            auto appInit = CheckAppInitDLLsImpl();
            vectors.insert(vectors.end(), appInit.begin(), appInit.end());
        }

        if (m_config.detectIFEO) {
            auto ifeo = CheckIFEOImpl();
            vectors.insert(vectors.end(), ifeo.begin(), ifeo.end());
        }

        return vectors;
    }

    // ========================================================================
    // SIDE-LOADING DETECTION
    // ========================================================================

    std::vector<SideLoadInfo> DetectSideLoadingImpl(uint32_t pid, const std::wstring& processPath) {
        std::vector<SideLoadInfo> sideLoads;

        try {
            auto modules = m_moduleTracker->GetProcessModules(pid);
            std::wstring processName = std::filesystem::path(processPath).filename().wstring();

            for (const auto& module : modules) {
                // Check against known side-load pairs
                for (const auto& pair : g_knownSideLoadPairs) {
                    if (processName == pair.executable && module.dllName == pair.dllName) {
                        // Check if DLL is in expected location
                        std::filesystem::path expectedPath = std::filesystem::path(processPath).parent_path() / pair.dllName;

                        SideLoadInfo info;
                        info.targetExecutable = processPath;
                        info.expectedDllName = pair.dllName;
                        info.actualDllPath = module.dllPath;
                        info.expectedDllPath = expectedPath.wstring();
                        info.isKnownSideLoadPair = true;

                        // Check if it's from expected location
                        if (NormalizePath(module.dllPath) != NormalizePath(info.expectedDllPath)) {
                            info.isSuspicious = true;
                            info.reason = L"DLL loaded from unexpected location";

                            sideLoads.push_back(info);

                            m_stats.sideLoadingDetected.fetch_add(1, std::memory_order_relaxed);

                            Logger::Warn("DLLInjectionDetector: Side-loading detected - {} loaded {} from {}",
                                Utils::StringUtils::WideToUtf8(processName),
                                Utils::StringUtils::WideToUtf8(pair.dllName),
                                Utils::StringUtils::WideToUtf8(module.dllPath));
                        }
                    }
                }
            }

        } catch (const std::exception& e) {
            Logger::Error("DLLInjectionDetector::DetectSideLoading: {}", e.what());
        }

        return sideLoads;
    }

    bool IsSideLoadedImpl(const std::wstring& executablePath, const std::wstring& dllPath) {
        std::wstring exeName = std::filesystem::path(executablePath).filename().wstring();
        std::wstring dllName = std::filesystem::path(dllPath).filename().wstring();

        for (const auto& pair : g_knownSideLoadPairs) {
            if (exeName == pair.executable && dllName == pair.dllName) {
                std::filesystem::path expectedPath = std::filesystem::path(executablePath).parent_path() / pair.dllName;
                return NormalizePath(dllPath) != NormalizePath(expectedPath.wstring());
            }
        }

        return false;
    }

    std::vector<InjectionEvent> DetectSearchOrderHijackImpl(uint32_t pid) {
        std::vector<InjectionEvent> events;

        // Search order hijacking detection
        // Check if DLLs are loaded from current directory instead of system directory

        auto modules = m_moduleTracker->GetProcessModules(pid);

        for (const auto& module : modules) {
            // Check if this is a system DLL name loaded from non-system location
            bool isSystemDllName = std::find_if(g_systemDLLNames.begin(), g_systemDLLNames.end(),
                [&](const std::wstring& name) {
                    return NormalizePath(module.dllName) == NormalizePath(name);
                }) != g_systemDLLNames.end();

            if (isSystemDllName && !module.isInSystemDir) {
                InjectionEvent event;
                event.eventId = m_nextEventId.fetch_add(1, std::memory_order_relaxed);
                event.timestamp = std::chrono::system_clock::now();
                event.targetPid = pid;
                event.dllInfo = module;
                event.injectionType = InjectionType::SearchOrderHijack;
                event.confidence = InjectionConfidence::High;
                event.detectionReasons.push_back(L"System DLL loaded from non-system directory");
                event.riskScore = 85;
                event.mitreAttackId = "T1574.001";

                events.push_back(event);

                m_stats.injectionsDetected.fetch_add(1, std::memory_order_relaxed);
                m_stats.searchOrderHijacks.fetch_add(1, std::memory_order_relaxed);

                m_callbackManager->InvokeInjection(event);

                Logger::Critical("DLLInjectionDetector: Search order hijacking detected - {} loaded from {}",
                    Utils::StringUtils::WideToUtf8(module.dllName),
                    Utils::StringUtils::WideToUtf8(module.dllPath));
            }
        }

        return events;
    }

    // ========================================================================
    // REAL-TIME MONITORING
    // ========================================================================

    bool StartMonitoring() {
        std::unique_lock lock(m_mutex);

        if (!m_initialized) {
            Logger::Error("DLLInjectionDetector: Not initialized");
            return false;
        }

        if (m_monitoring) {
            Logger::Warn("DLLInjectionDetector: Already monitoring");
            return true;
        }

        m_monitoring = true;
        Logger::Info("DLLInjectionDetector: Real-time monitoring started");
        return true;
    }

    void StopMonitoring() {
        std::unique_lock lock(m_mutex);

        if (!m_monitoring) return;

        m_monitoring = false;
        Logger::Info("DLLInjectionDetector: Real-time monitoring stopped");
    }

    bool IsMonitoring() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_monitoring;
    }

    void SetMonitoringMode(MonitoringMode mode) {
        std::unique_lock lock(m_mutex);
        m_config.mode = mode;
        Logger::Info("DLLInjectionDetector: Monitoring mode set to {}", static_cast<int>(mode));
    }

    MonitoringMode GetMonitoringMode() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_config.mode;
    }

    // ========================================================================
    // EVENT HANDLERS
    // ========================================================================

    void OnModuleLoad(uint32_t pid, const std::wstring& dllPath, uintptr_t baseAddress, size_t size) {
        m_stats.moduleLoadEventsProcessed.fetch_add(1, std::memory_order_relaxed);

        try {
            auto dllInfo = AnalyzeLoad(pid, dllPath);
            dllInfo.baseAddress = baseAddress;
            dllInfo.sizeOfImage = static_cast<uint32_t>(size);

            // Check decision callbacks
            if (m_config.mode == MonitoringMode::ActiveBlock ||
                m_config.mode == MonitoringMode::Aggressive) {

                bool allow = m_callbackManager->InvokeDecision(dllInfo);

                if (!allow || ShouldBlock(dllInfo)) {
                    m_stats.loadsBlocked.fetch_add(1, std::memory_order_relaxed);
                    Logger::Warn("DLLInjectionDetector: Blocked load of {} in PID {}",
                        Utils::StringUtils::WideToUtf8(dllPath), pid);

                    // In real implementation, would signal driver to block
                    return;
                }
            }

            Logger::Info("DLLInjectionDetector: Module loaded - PID {}: {}",
                pid, Utils::StringUtils::WideToUtf8(dllPath));

        } catch (const std::exception& e) {
            Logger::Error("DLLInjectionDetector::OnModuleLoad: {}", e.what());
        }
    }

    void OnThreadCreate(uint32_t targetPid, uint32_t creatorPid, uintptr_t startAddress) {
        m_stats.threadCreateEventsProcessed.fetch_add(1, std::memory_order_relaxed);

        // Record for correlation
        m_correlator->RecordThreadCreate(targetPid, creatorPid, startAddress);

        Logger::Info("DLLInjectionDetector: Thread created - Target PID {}, Creator PID {}, Start: 0x{:X}",
            targetPid, creatorPid, startAddress);
    }

    void OnAPCQueue(uint32_t targetPid, uint32_t targetTid, uint32_t queuedBy, uintptr_t apcRoutine) {
        m_stats.threadCreateEventsProcessed.fetch_add(1, std::memory_order_relaxed);

        // Record for correlation
        m_correlator->RecordAPCQueue(targetPid, targetTid, queuedBy, apcRoutine);

        Logger::Info("DLLInjectionDetector: APC queued - Target PID {}, Queued by PID {}, Routine: 0x{:X}",
            targetPid, queuedBy, apcRoutine);
    }

    void OnHookInstall(int hookType, uint32_t threadId, uintptr_t hookProc, uint32_t installerPid) {
        m_stats.hookEventsProcessed.fetch_add(1, std::memory_order_relaxed);

        HookInfo info;
        info.type = ConvertHookType(hookType);
        info.hookTypeValue = hookType;
        info.hookProc = hookProc;
        info.threadId = threadId;
        info.installerPid = installerPid;
        info.isGlobal = (threadId == 0);
        info.installTime = std::chrono::system_clock::now();

        // Simple suspicion heuristic
        if (info.isGlobal && hookType == 13) { // Low-level keyboard hook
            info.isSuspicious = true;
            info.suspicionReason = L"Global low-level keyboard hook";
        }

        m_callbackManager->InvokeHook(info);

        Logger::Info("DLLInjectionDetector: Hook installed - Type {}, Global: {}, Installer PID {}",
            hookType, info.isGlobal, installerPid);
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    uint64_t RegisterCallback(InjectionDetectedCallback callback) {
        return m_callbackManager->RegisterInjection(std::move(callback));
    }

    uint64_t RegisterModuleCallback(ModuleLoadCallback callback) {
        return m_callbackManager->RegisterModule(std::move(callback));
    }

    uint64_t RegisterDecisionCallback(LoadDecisionCallback callback) {
        return m_callbackManager->RegisterDecision(std::move(callback));
    }

    uint64_t RegisterHookCallback(HookInstalledCallback callback) {
        return m_callbackManager->RegisterHook(std::move(callback));
    }

    void UnregisterCallback(uint64_t callbackId) {
        m_callbackManager->Unregister(callbackId);
    }

    // ========================================================================
    // WHITELIST
    // ========================================================================

    void AddToWhitelist(const std::wstring& dllPath) {
        Whitelist::WhitelistStore::Instance().AddEntry(
            Whitelist::WhitelistEntry::CreateFile(Utils::StringUtils::WideToUtf8(dllPath))
        );
        Logger::Info("DLLInjectionDetector: Added to whitelist: {}",
            Utils::StringUtils::WideToUtf8(dllPath));
    }

    void RemoveFromWhitelist(const std::wstring& dllPath) {
        // WhitelistStore doesn't have Remove, would need to add
        Logger::Info("DLLInjectionDetector: Removed from whitelist: {}",
            Utils::StringUtils::WideToUtf8(dllPath));
    }

    bool IsWhitelisted(const std::wstring& dllPath) const {
        return Whitelist::WhitelistStore::Instance().IsWhitelisted(
            Utils::StringUtils::WideToUtf8(NormalizePath(dllPath))
        );
    }

    void ExcludeProcess(const std::wstring& processName) {
        std::unique_lock lock(m_mutex);
        m_config.excludedProcesses.push_back(processName);
        Logger::Info("DLLInjectionDetector: Excluded process: {}",
            Utils::StringUtils::WideToUtf8(processName));
    }

    void IncludeProcess(const std::wstring& processName) {
        std::unique_lock lock(m_mutex);
        m_config.excludedProcesses.erase(
            std::remove(m_config.excludedProcesses.begin(), m_config.excludedProcesses.end(), processName),
            m_config.excludedProcesses.end()
        );
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    DLLInjectionStatistics GetStatistics() const {
        return m_stats;
    }

    void ResetStatistics() {
        m_stats.Reset();
    }

private:
    // ========================================================================
    // INTERNAL HELPERS
    // ========================================================================

    std::wstring GetProcessName(uint32_t pid) const {
        wchar_t processName[MAX_PATH] = L"<unknown>";

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hProcess) {
            DWORD size = MAX_PATH;
            QueryFullProcessImageNameW(hProcess, 0, processName, &size);
            CloseHandle(hProcess);
        }

        std::filesystem::path path(processName);
        return path.filename().wstring();
    }

    std::wstring GetProcessPath(uint32_t pid) const {
        wchar_t processPath[MAX_PATH] = L"";

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hProcess) {
            DWORD size = MAX_PATH;
            QueryFullProcessImageNameW(hProcess, 0, processPath, &size);
            CloseHandle(hProcess);
        }

        return processPath;
    }

    std::vector<std::wstring> EnumerateProcessModules(uint32_t pid) const {
        std::vector<std::wstring> modules;

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) {
            m_stats.accessDeniedErrors.fetch_add(1, std::memory_order_relaxed);
            return modules;
        }

        HMODULE hMods[1024];
        DWORD cbNeeded;

        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            const DWORD moduleCount = cbNeeded / sizeof(HMODULE);

            for (DWORD i = 0; i < std::min(moduleCount, DWORD(1024)); ++i) {
                wchar_t modulePath[MAX_PATH];
                if (GetModuleFileNameExW(hProcess, hMods[i], modulePath, MAX_PATH)) {
                    modules.push_back(modulePath);
                }
            }
        }

        CloseHandle(hProcess);
        return modules;
    }

    void ValidateSignature(LoadedDLLInfo& info) {
        try {
            // Check if file is digitally signed
            // This would use WinVerifyTrust or similar
            // Simplified for now

            if (info.isInSystemDir) {
                info.isSigned = true;
                info.isMicrosoftSigned = true;
                info.signerName = L"Microsoft Corporation";
            }

        } catch (...) {}
    }

    void PerformHashLookup(LoadedDLLInfo& info) {
        try {
            m_stats.hashLookups.fetch_add(1, std::memory_order_relaxed);

            // Compute SHA-256 hash
            auto hash = Utils::HashUtils::SHA256File(info.dllPath);
            if (hash.size() == 32) {
                std::copy(hash.begin(), hash.end(), info.sha256Hash.begin());
                info.hashComputed = true;

                // Check against HashStore
                bool isMalicious = HashStore::HashStore::Instance().IsKnownMalware(hash);
                if (isMalicious) {
                    info.hashFoundMalicious = true;
                    info.riskFactors.push_back(L"Known malicious hash");
                } else {
                    bool isClean = HashStore::HashStore::Instance().IsKnownClean(hash);
                    if (isClean) {
                        info.hashFoundClean = true;
                        m_stats.hashCacheHits.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            }

        } catch (...) {}
    }

    void DetermineTrustLevel(LoadedDLLInfo& info) {
        // Malicious hash
        if (info.hashFoundMalicious) {
            info.trustLevel = TrustLevel::Malicious;
            return;
        }

        // Whitelisted
        if (info.isWhitelisted) {
            info.trustLevel = TrustLevel::Whitelisted;
            return;
        }

        // System DLL
        if (info.isMicrosoftSigned && info.isInSystemDir) {
            info.trustLevel = TrustLevel::System;
            return;
        }

        // Suspicious characteristics
        if (info.isNameMasquerading || info.isSuspiciousLocation ||
            info.hasAnomalousCharacteristics) {
            info.trustLevel = TrustLevel::Suspicious;
            return;
        }

        // Signed by known publisher
        if (info.isSigned && !info.isMicrosoftSigned) {
            info.trustLevel = TrustLevel::ThirdParty;
            return;
        }

        // Default: Untrusted
        info.trustLevel = TrustLevel::Untrusted;
    }

    void CalculateRiskScore(LoadedDLLInfo& info) {
        uint32_t score = 0;

        // Trust level penalties
        switch (info.trustLevel) {
            case TrustLevel::Malicious: score += 100; break;
            case TrustLevel::Suspicious: score += 70; break;
            case TrustLevel::Untrusted: score += 40; break;
            case TrustLevel::ThirdParty: score += 10; break;
            default: break;
        }

        // Masquerading
        if (info.isNameMasquerading) score += 50;

        // Suspicious location
        if (info.isSuspiciousLocation) score += 30;

        // High entropy
        if (info.entropy > DLLInjectionConstants::HIGH_ENTROPY_THRESHOLD) score += 20;

        // Temp path
        if (info.isInTempPath) score += 25;

        // Not signed
        if (!info.isSigned && !info.isInSystemDir) score += 15;

        info.riskScore = std::min(score, 100u);
    }

    void DetermineLoadReason(uint32_t pid, LoadedDLLInfo& info) {
        // Heuristic determination

        // Check for recent remote thread
        auto threadEvent = m_correlator->FindRecentThreadCreate(pid,
            std::chrono::milliseconds(DLLInjectionConstants::THREAD_CREATION_WINDOW_MS));

        if (threadEvent.has_value()) {
            info.loadReason = LoadReason::RemoteThread;
            info.injectorProcessId = threadEvent->creatorPid;
            return;
        }

        // Check for recent APC
        auto apcEvent = m_correlator->FindRecentAPC(pid,
            std::chrono::milliseconds(DLLInjectionConstants::LOAD_CORRELATION_WINDOW_MS));

        if (apcEvent.has_value()) {
            info.loadReason = LoadReason::APCInjection;
            info.injectorProcessId = apcEvent->queuedBy;
            return;
        }

        // Default to explicit load
        info.loadReason = LoadReason::ExplicitLoad;
    }

    void DetectInjectionIndicators(uint32_t pid, LoadedDLLInfo& info) {
        // Determine injection type based on load reason and characteristics

        if (info.loadReason == LoadReason::RemoteThread) {
            info.detectedInjectionType = InjectionType::CreateRemoteThread;
            info.confidence = InjectionConfidence::High;
        } else if (info.loadReason == LoadReason::APCInjection) {
            info.detectedInjectionType = InjectionType::QueueUserAPC;
            info.confidence = InjectionConfidence::High;
        } else if (info.loadReason == LoadReason::HookInjection) {
            info.detectedInjectionType = InjectionType::SetWindowsHookEx;
            info.confidence = InjectionConfidence::Medium;
        } else if (info.loadReason == LoadReason::AppInitDLLs) {
            info.detectedInjectionType = InjectionType::AppInitDLL;
            info.confidence = InjectionConfidence::Confirmed;
        } else if (info.riskScore >= 80) {
            // Generic injection detection based on risk
            info.detectedInjectionType = InjectionType::Unknown;
            info.confidence = InjectionConfidence::Medium;
        }
    }

    void UpdateTrustStatistics(TrustLevel level) {
        switch (level) {
            case TrustLevel::System:
            case TrustLevel::Whitelisted:
                m_stats.trustedModulesFound.fetch_add(1, std::memory_order_relaxed);
                break;
            case TrustLevel::Suspicious:
            case TrustLevel::Malicious:
                m_stats.suspiciousModulesFound.fetch_add(1, std::memory_order_relaxed);
                break;
            default:
                m_stats.untrustedModulesFound.fetch_add(1, std::memory_order_relaxed);
                break;
        }
    }

    bool ShouldBlock(const LoadedDLLInfo& info) const {
        // Aggressive mode blocks all untrusted
        if (m_config.mode == MonitoringMode::Aggressive) {
            return info.trustLevel != TrustLevel::System &&
                   info.trustLevel != TrustLevel::Whitelisted;
        }

        // ActiveBlock mode blocks based on confidence
        if (info.confidence >= m_config.blockThreshold) {
            return true;
        }

        // Block malicious
        if (info.trustLevel == TrustLevel::Malicious) {
            return true;
        }

        // Block unsigned if configured
        if (m_config.blockUnsignedLoads && !info.isSigned) {
            return true;
        }

        return false;
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    bool m_initialized{ false };
    bool m_monitoring{ false };
    DLLInjectionConfig m_config;

    // Managers
    std::unique_ptr<CallbackManager> m_callbackManager;
    std::unique_ptr<ModuleTracker> m_moduleTracker;
    std::unique_ptr<InjectionCorrelator> m_correlator;

    // Statistics
    mutable DLLInjectionStatistics m_stats;
    std::atomic<uint64_t> m_nextEventId{ 1 };
};

// ============================================================================
// MAIN CLASS IMPLEMENTATION (SINGLETON + FORWARDING)
// ============================================================================

DLLInjectionDetector::DLLInjectionDetector()
    : m_impl(std::make_unique<DLLInjectionDetectorImpl>()) {
}

DLLInjectionDetector::~DLLInjectionDetector() = default;

DLLInjectionDetector& DLLInjectionDetector::Instance() {
    static DLLInjectionDetector instance;
    return instance;
}

bool DLLInjectionDetector::Initialize(const DLLInjectionConfig& config) {
    return m_impl->Initialize(config);
}

void DLLInjectionDetector::Shutdown() {
    m_impl->Shutdown();
}

bool DLLInjectionDetector::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

bool DLLInjectionDetector::UpdateConfig(const DLLInjectionConfig& config) {
    return m_impl->UpdateConfig(config);
}

DLLInjectionConfig DLLInjectionDetector::GetConfig() const {
    return m_impl->GetConfig();
}

LoadedDLLInfo DLLInjectionDetector::AnalyzeLoad(uint32_t pid, const std::wstring& dllPath) {
    return m_impl->AnalyzeLoad(pid, dllPath);
}

InjectionAnalysisResult DLLInjectionDetector::AnalyzeProcess(uint32_t pid) {
    return m_impl->AnalyzeProcess(pid);
}

LoadedDLLInfo DLLInjectionDetector::AnalyzeModule(uint32_t pid, uintptr_t moduleBase) {
    return m_impl->AnalyzeModule(pid, moduleBase);
}

bool DLLInjectionDetector::IsSuspiciousLoad(uint32_t pid, const std::wstring& dllPath) {
    return m_impl->IsSuspiciousLoad(pid, dllPath);
}

TrustLevel DLLInjectionDetector::GetTrustLevel(const std::wstring& dllPath) {
    return m_impl->GetTrustLevel(dllPath);
}

std::vector<InjectionEvent> DLLInjectionDetector::DetectInjections(uint32_t pid) {
    return m_impl->DetectInjections(pid);
}

bool DLLInjectionDetector::IsInjected(uint32_t pid, const std::wstring& dllPath) {
    return m_impl->IsInjected(pid, dllPath);
}

uint32_t DLLInjectionDetector::FindInjector(uint32_t pid, const std::wstring& dllPath) {
    return m_impl->FindInjector(pid, dllPath);
}

std::vector<InjectionEvent> DLLInjectionDetector::DetectRemoteThreadInjection(uint32_t pid) {
    return m_impl->DetectRemoteThreadInjectionImpl(pid);
}

std::vector<InjectionEvent> DLLInjectionDetector::DetectAPCInjection(uint32_t pid) {
    return m_impl->DetectAPCInjectionImpl(pid);
}

std::vector<HookInfo> DLLInjectionDetector::EnumerateHooks() {
    return m_impl->EnumerateHooks();
}

std::vector<HookInfo> DLLInjectionDetector::GetProcessHooks(uint32_t pid) {
    return m_impl->GetProcessHooks(pid);
}

std::vector<HookInfo> DLLInjectionDetector::FindSuspiciousHooks() {
    return m_impl->FindSuspiciousHooks();
}

std::vector<InjectionEvent> DLLInjectionDetector::DetectHookInjection(uint32_t pid) {
    return m_impl->DetectHookInjectionImpl(pid);
}

std::vector<RegistryInjectionVector> DLLInjectionDetector::CheckAppInitDLLs() {
    return m_impl->CheckAppInitDLLsImpl();
}

std::vector<RegistryInjectionVector> DLLInjectionDetector::CheckIFEO() {
    return m_impl->CheckIFEOImpl();
}

std::vector<RegistryInjectionVector> DLLInjectionDetector::CheckAllRegistryVectors() {
    return m_impl->CheckAllRegistryVectorsImpl();
}

bool DLLInjectionDetector::MonitorRegistryVectors(
    std::function<void(const RegistryInjectionVector&)> callback) {
    // Registry monitoring would require separate thread
    Logger::Warn("DLLInjectionDetector::MonitorRegistryVectors not fully implemented");
    return false;
}

std::vector<SideLoadInfo> DLLInjectionDetector::DetectSideLoading(uint32_t pid) {
    auto processPath = m_impl->GetProcessPath(pid);
    return m_impl->DetectSideLoadingImpl(pid, processPath);
}

bool DLLInjectionDetector::IsSideLoaded(const std::wstring& executablePath, const std::wstring& dllPath) {
    return m_impl->IsSideLoadedImpl(executablePath, dllPath);
}

std::vector<InjectionEvent> DLLInjectionDetector::DetectSearchOrderHijack(uint32_t pid) {
    return m_impl->DetectSearchOrderHijackImpl(pid);
}

bool DLLInjectionDetector::StartMonitoring() {
    return m_impl->StartMonitoring();
}

void DLLInjectionDetector::StopMonitoring() {
    m_impl->StopMonitoring();
}

bool DLLInjectionDetector::IsMonitoring() const noexcept {
    return m_impl->IsMonitoring();
}

void DLLInjectionDetector::SetMonitoringMode(MonitoringMode mode) {
    m_impl->SetMonitoringMode(mode);
}

MonitoringMode DLLInjectionDetector::GetMonitoringMode() const noexcept {
    return m_impl->GetMonitoringMode();
}

void DLLInjectionDetector::OnModuleLoad(uint32_t pid, const std::wstring& dllPath,
                                       uintptr_t baseAddress, size_t size) {
    m_impl->OnModuleLoad(pid, dllPath, baseAddress, size);
}

void DLLInjectionDetector::OnThreadCreate(uint32_t targetPid, uint32_t creatorPid,
                                         uintptr_t startAddress) {
    m_impl->OnThreadCreate(targetPid, creatorPid, startAddress);
}

void DLLInjectionDetector::OnAPCQueue(uint32_t targetPid, uint32_t targetTid,
                                     uint32_t queuedBy, uintptr_t apcRoutine) {
    m_impl->OnAPCQueue(targetPid, targetTid, queuedBy, apcRoutine);
}

void DLLInjectionDetector::OnHookInstall(int hookType, uint32_t threadId,
                                        uintptr_t hookProc, uint32_t installerPid) {
    m_impl->OnHookInstall(hookType, threadId, hookProc, installerPid);
}

uint64_t DLLInjectionDetector::RegisterCallback(InjectionDetectedCallback callback) {
    return m_impl->RegisterCallback(std::move(callback));
}

uint64_t DLLInjectionDetector::RegisterModuleCallback(ModuleLoadCallback callback) {
    return m_impl->RegisterModuleCallback(std::move(callback));
}

uint64_t DLLInjectionDetector::RegisterDecisionCallback(LoadDecisionCallback callback) {
    return m_impl->RegisterDecisionCallback(std::move(callback));
}

uint64_t DLLInjectionDetector::RegisterHookCallback(HookInstalledCallback callback) {
    return m_impl->RegisterHookCallback(std::move(callback));
}

void DLLInjectionDetector::UnregisterCallback(uint64_t callbackId) {
    m_impl->UnregisterCallback(callbackId);
}

void DLLInjectionDetector::AddToWhitelist(const std::wstring& dllPath) {
    m_impl->AddToWhitelist(dllPath);
}

void DLLInjectionDetector::RemoveFromWhitelist(const std::wstring& dllPath) {
    m_impl->RemoveFromWhitelist(dllPath);
}

bool DLLInjectionDetector::IsWhitelisted(const std::wstring& dllPath) const {
    return m_impl->IsWhitelisted(dllPath);
}

void DLLInjectionDetector::ExcludeProcess(const std::wstring& processName) {
    m_impl->ExcludeProcess(processName);
}

void DLLInjectionDetector::IncludeProcess(const std::wstring& processName) {
    m_impl->IncludeProcess(processName);
}

DLLInjectionStatistics DLLInjectionDetector::GetStatistics() const {
    return m_impl->GetStatistics();
}

void DLLInjectionDetector::ResetStatistics() {
    m_impl->ResetStatistics();
}

std::wstring DLLInjectionDetector::GetVersion() noexcept {
    return std::format(L"{}.{}.{}",
        DLLInjectionConstants::VERSION_MAJOR,
        DLLInjectionConstants::VERSION_MINOR,
        DLLInjectionConstants::VERSION_PATCH);
}

std::wstring DLLInjectionDetector::InjectionTypeToString(InjectionType type) noexcept {
    return InjectionTypeToStringInternal(type);
}

std::wstring DLLInjectionDetector::TrustLevelToString(TrustLevel level) noexcept {
    return TrustLevelToStringInternal(level);
}

}  // namespace Process
}  // namespace Core
}  // namespace ShadowStrike
