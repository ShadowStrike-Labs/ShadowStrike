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
#include "../../Utils/PE_sig_verf.hpp"

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
 * @brief RAII wrapper for Windows HANDLE (process handles, etc.).
 *
 * Prevents handle leaks on early returns, exceptions, or complex control flow.
 */
struct HandleGuard {
    HANDLE h;
    explicit HandleGuard(HANDLE handle) noexcept : h(handle) {}
    ~HandleGuard() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    HandleGuard(const HandleGuard&) = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;
    explicit operator bool() const noexcept { return h != nullptr && h != INVALID_HANDLE_VALUE; }
    HANDLE get() const noexcept { return h; }
};

/**
 * @brief Calculate Shannon entropy of a file.
 *
 * Only reads the first 64 KB via direct handle I/O to avoid allocating
 * the entire file into memory (potential DoS with large DLLs).
 */
double CalculateFileEntropy(const std::wstring& filePath) {
    try {
        constexpr DWORD SAMPLE_SIZE = 65536; // 64 KB sample

        HandleGuard hFile(CreateFileW(filePath.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (!hFile) return 0.0;

        std::array<uint8_t, SAMPLE_SIZE> buffer{};
        DWORD bytesRead = 0;
        if (!ReadFile(hFile.get(), buffer.data(), SAMPLE_SIZE, &bytesRead, nullptr) ||
            bytesRead < 256) {
            return 0.0;
        }

        std::array<size_t, 256> freq{};
        for (DWORD i = 0; i < bytesRead; ++i) {
            freq[buffer[i]]++;
        }

        double entropy = 0.0;
        const double dblSize = static_cast<double>(bytesRead);

        for (size_t count : freq) {
            if (count > 0) {
                const double p = static_cast<double>(count) / dblSize;
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
 * Handles \\?\ / \\.\, \SystemRoot\, \??\, \Device\HarddiskVolume*,
 * canonicalizes .. and ., lowercases for safe comparison.
 *
 * Kernel PsSetLoadImageNotifyRoutine sends paths like:
 *   \Device\HarddiskVolume3\Windows\System32\ntdll.dll
 *   \SystemRoot\System32\drivers\foo.sys
 *   \??\C:\Program Files\bar.dll
 * These must be normalized to standard Win32 paths for comparison.
 */
std::wstring NormalizePath(const std::wstring& path) {
    std::wstring normalized = path;

    // Strip extended-length and device path prefixes that can bypass string checks
    if (normalized.starts_with(L"\\\\?\\")) {
        normalized = normalized.substr(4);
    } else if (normalized.starts_with(L"\\\\.\\")) {
        normalized = normalized.substr(4);
    }

    // Handle kernel NT-style path prefixes
    // \??\C:\... → C:\...
    if (normalized.starts_with(L"\\??\\")) {
        normalized = normalized.substr(4);
    }

    // \SystemRoot\ → actual Windows directory
    {
        constexpr std::wstring_view kSystemRoot = L"\\SystemRoot\\";
        if (normalized.size() >= kSystemRoot.size()) {
            // Case-insensitive prefix check
            std::wstring prefix = normalized.substr(0, kSystemRoot.size());
            std::transform(prefix.begin(), prefix.end(), prefix.begin(), ::towlower);
            if (prefix == L"\\systemroot\\") {
                wchar_t winDir[MAX_PATH];
                if (GetWindowsDirectoryW(winDir, MAX_PATH) > 0) {
                    normalized = std::wstring(winDir) + L"\\" +
                                 normalized.substr(kSystemRoot.size());
                }
            }
        }
    }

    // \Device\HarddiskVolumeN\... → resolve via QueryDosDevice
    // This is expensive so we use a cached mapping.
    {
        constexpr std::wstring_view kDevPrefix = L"\\Device\\HarddiskVolume";
        if (normalized.size() >= kDevPrefix.size()) {
            std::wstring prefix = normalized.substr(0, kDevPrefix.size());
            std::transform(prefix.begin(), prefix.end(), prefix.begin(), ::towlower);
            if (prefix == L"\\device\\harddiskvolume") {
                // Find end of volume number
                size_t volEnd = kDevPrefix.size();
                while (volEnd < normalized.size() && normalized[volEnd] >= L'0' && normalized[volEnd] <= L'9') {
                    ++volEnd;
                }
                if (volEnd > kDevPrefix.size() && volEnd < normalized.size() && normalized[volEnd] == L'\\') {
                    std::wstring devicePath = normalized.substr(0, volEnd);
                    // Resolve via cached drive letter mapping
                    static const auto driveMap = []() {
                        std::unordered_map<std::wstring, std::wstring> map;
                        wchar_t drives[512];
                        if (GetLogicalDriveStringsW(512, drives)) {
                            for (const wchar_t* d = drives; *d; d += wcslen(d) + 1) {
                                wchar_t letter[3] = { d[0], d[1], L'\0' }; // e.g. "C:"
                                wchar_t target[MAX_PATH];
                                if (QueryDosDeviceW(letter, target, MAX_PATH)) {
                                    std::wstring key(target);
                                    std::transform(key.begin(), key.end(), key.begin(), ::towlower);
                                    map[key] = std::wstring(letter);
                                }
                            }
                        }
                        return map;
                    }();

                    std::wstring lowerDevice = devicePath;
                    std::transform(lowerDevice.begin(), lowerDevice.end(), lowerDevice.begin(), ::towlower);
                    auto it = driveMap.find(lowerDevice);
                    if (it != driveMap.end()) {
                        normalized = it->second + normalized.substr(volEnd);
                    }
                }
            }
        }
    }

    // Replace forward slashes with backslashes
    std::replace(normalized.begin(), normalized.end(), L'/', L'\\');

    // Canonicalize by resolving . and .. components
    std::vector<std::wstring> parts;
    std::wstring segment;
    std::wstringstream wss(normalized);
    bool isUNC = normalized.starts_with(L"\\\\");

    // Split on backslashes
    while (std::getline(wss, segment, L'\\')) {
        if (segment.empty() || segment == L".") {
            continue;
        } else if (segment == L"..") {
            // Don't pop past root (drive letter or UNC share)
            if (parts.size() > 1) {
                parts.pop_back();
            }
        } else {
            parts.push_back(segment);
        }
    }

    // Reassemble
    normalized.clear();
    if (isUNC) {
        normalized = L"\\\\";
    }
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i > 0) normalized += L'\\';
        normalized += parts[i];
    }

    // Lowercase for case-insensitive comparison
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), ::towlower);

    // Remove trailing backslash
    if (normalized.size() > 3 && normalized.back() == L'\\') {
        normalized.pop_back();
    }

    return normalized;
}

/**
 * @brief Cached system paths for hot-path performance.
 * Initialized on first use via Meyers' singleton pattern.
 */
struct CachedSystemPaths {
    std::wstring systemDir;
    std::wstring windowsDir;
    std::wstring tempDir;
    std::wstring userProfile;

    static const CachedSystemPaths& Get() {
        static CachedSystemPaths instance = []() {
            CachedSystemPaths p;
            wchar_t buf[MAX_PATH];
            if (GetSystemDirectoryW(buf, MAX_PATH) > 0)
                p.systemDir = NormalizePath(buf);
            if (GetWindowsDirectoryW(buf, MAX_PATH) > 0)
                p.windowsDir = NormalizePath(buf);
            if (GetTempPathW(MAX_PATH, buf) > 0)
                p.tempDir = NormalizePath(buf);
            if (GetEnvironmentVariableW(L"USERPROFILE", buf, MAX_PATH) > 0)
                p.userProfile = NormalizePath(buf);
            return p;
        }();
        return instance;
    }
};

/**
 * @brief Check if path is in system directory.
 */
bool IsSystemDirectory(const std::wstring& path) {
    std::wstring normalized = NormalizePath(path);
    const auto& cached = CachedSystemPaths::Get();
    return (!cached.systemDir.empty() && normalized.starts_with(cached.systemDir)) ||
           (!cached.windowsDir.empty() && normalized.starts_with(cached.windowsDir));
}

/**
 * @brief Check if path is in temp directory.
 */
bool IsTempDirectory(const std::wstring& path) {
    std::wstring normalized = NormalizePath(path);
    const auto& cached = CachedSystemPaths::Get();

    return (!cached.tempDir.empty() && normalized.starts_with(cached.tempDir)) ||
           normalized.find(L"\\temp\\") != std::wstring::npos ||
           normalized.find(L"\\tmp\\") != std::wstring::npos;
}

/**
 * @brief Check if path is in user profile.
 */
bool IsUserProfilePath(const std::wstring& path) {
    std::wstring normalized = NormalizePath(path);
    const auto& cached = CachedSystemPaths::Get();
    return !cached.userProfile.empty() && normalized.starts_with(cached.userProfile);
}

/**
 * @brief Calculate Levenshtein distance for name masquerading detection.
 *
 * Capped to MAX_DISTANCE_INPUT to prevent O(n*m) memory exhaustion from
 * adversarially-long filenames. DLL names beyond this length are never
 * plausible system DLL masquerades.
 */
size_t LevenshteinDistance(const std::wstring& s1, const std::wstring& s2) {
    constexpr size_t MAX_DISTANCE_INPUT = 64;
    const size_t len1 = std::min(s1.size(), MAX_DISTANCE_INPUT);
    const size_t len2 = std::min(s2.size(), MAX_DISTANCE_INPUT);

    // Fast-path: if length difference alone exceeds edit-distance threshold,
    // no need for full DP computation.
    if (len1 > len2 + 3 || len2 > len1 + 3) {
        return std::max(len1, len2);
    }

    std::vector<std::vector<size_t>> d(len1 + 1, std::vector<size_t>(len2 + 1));

    for (size_t i = 0; i <= len1; ++i) d[i][0] = i;
    for (size_t j = 0; j <= len2; ++j) d[0][j] = j;

    for (size_t i = 1; i <= len1; ++i) {
        for (size_t j = 1; j <= len2; ++j) {
            const size_t cost = (::towlower(s1[i - 1]) == ::towlower(s2[j - 1])) ? 0 : 1;
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
 *
 * Uses case-insensitive Levenshtein distance. Names longer than any system
 * DLL + 3 chars are skipped as a fast path (no plausible masquerade).
 */
bool IsMasquerading(const std::wstring& dllName) {
    if (dllName.size() > 32) return false; // No system DLL name is this long

    std::wstring lowerName = dllName;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

    for (const auto& systemDll : g_systemDLLNames) {
        if (lowerName == systemDll) return false; // Exact match = not masquerading
        size_t distance = LevenshteinDistance(lowerName, systemDll);
        if (distance > 0 && distance <= 2) {
            return true;
        }
    }

    return false;
}

/**
 * @brief Known DLL side-loading pairs.
 * Sourced from public threat intelligence: MITRE ATT&CK T1574.002 corpus,
 * CISA advisories, and observed APT campaigns.
 */
struct SideLoadPair {
    std::wstring executable;
    std::wstring dllName;
};

const std::vector<SideLoadPair> g_knownSideLoadPairs = {
    // Browsers
    {L"chrome.exe", L"version.dll"},
    {L"chrome.exe", L"wtsapi32.dll"},
    {L"msedge.exe", L"version.dll"},
    {L"firefox.exe", L"mozglue.dll"},
    // Microsoft tools
    {L"msbuild.exe", L"version.dll"},
    {L"devenv.exe", L"version.dll"},
    {L"winword.exe", L"wwlib.dll"},
    {L"excel.exe", L"xllex.dll"},
    {L"outlook.exe", L"olmapi32.dll"},
    {L"powerpnt.exe", L"ppcore.dll"},
    // System utilities
    {L"explorer.exe", L"shell32.dll"},
    {L"cmd.exe", L"cmd.dll"},
    {L"notepad.exe", L"notepad.dll"},
    {L"control.exe", L"version.dll"},
    {L"rundll32.exe", L"version.dll"},
    {L"mmc.exe", L"elsext.dll"},
    {L"cmstp.exe", L"version.dll"},
    // Common APT targets
    {L"vmtoolsd.exe", L"vsock.dll"},
    {L"vmnat.exe", L"shfolder.dll"},
    {L"putty.exe", L"winmm.dll"},
    {L"WinSCP.exe", L"dui70.dll"},
    {L"7z.exe", L"7z.dll"},
    {L"Acrobat.exe", L"AcroRd32.dll"},
    {L"AcroRd32.exe", L"rdrsefui.dll"},
    {L"winrar.exe", L"rar.dll"},
    // Signed vulnerable loaders used by APTs
    {L"dllhost.exe", L"comsvcs.dll"},
    {L"svchost.exe", L"version.dll"},
    {L"SearchProtocolHost.exe", L"msfte.dll"},
    {L"consent.exe", L"version.dll"},
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

    apcEventsProcessed.store(0, std::memory_order_relaxed);

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
                SS_LOG_ERROR(L"DLLInjection", L"InjectionCallback exception: %S", e.what());
            }
        }
    }

    void InvokeModule(const LoadedDLLInfo& dllInfo) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_moduleCallbacks) {
            try {
                callback(dllInfo);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"DLLInjection", L"ModuleCallback exception: %S", e.what());
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
                SS_LOG_ERROR(L"DLLInjection", L"DecisionCallback exception: %S", e.what());
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
                SS_LOG_ERROR(L"DLLInjection", L"HookCallback exception: %S", e.what());
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
        m_processModules[pid].push_back(dllInfo.normalizedPath);
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
    // Maximum number of events to retain per category.
    // Prevents unbounded memory growth under sustained injection attempts.
    static constexpr size_t MAX_EVENT_ENTRIES = 4096;

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

        // Hard cap: if still over limit after time-based cleanup, drop oldest entries
        if (m_threadEvents.size() > MAX_EVENT_ENTRIES) {
            m_threadEvents.erase(
                m_threadEvents.begin(),
                m_threadEvents.begin() + static_cast<ptrdiff_t>(m_threadEvents.size() - MAX_EVENT_ENTRIES)
            );
        }
        if (m_apcEvents.size() > MAX_EVENT_ENTRIES) {
            m_apcEvents.erase(
                m_apcEvents.begin(),
                m_apcEvents.begin() + static_cast<ptrdiff_t>(m_apcEvents.size() - MAX_EVENT_ENTRIES)
            );
        }
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
            SS_LOG_INFO(L"DLLInjection", L"Initializing...");

            m_config = config;

            // Initialize managers
            m_callbackManager = std::make_unique<CallbackManager>();
            m_moduleTracker = std::make_unique<ModuleTracker>();
            m_correlator = std::make_unique<InjectionCorrelator>();

            // NOTE: HashStore and WhitelistStore are NOT singletons.
            // They must be provisioned by the orchestrator layer and injected
            // via SetHashStore()/SetWhitelistStore() after Initialize().
            // Hash computation for individual files uses Utils::FileUtils::ComputeFileSHA256().
            // Hash-based threat intel lookup and whitelist lookup are optional
            // capabilities that activate only when external stores are connected.

            m_initialized = true;
            SS_LOG_INFO(L"DLLInjection", L"Initialized successfully");
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DLLInjection", L"Initialization failed: %S", e.what());
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

        SS_LOG_INFO(L"DLLInjection", L"Shutdown complete");
    }

    bool IsInitialized() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_initialized;
    }

    bool UpdateConfig(const DLLInjectionConfig& config) {
        std::unique_lock lock(m_mutex);
        m_config = config;
        SS_LOG_INFO(L"DLLInjection", L"Configuration updated");
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

        if (!m_initialized || !m_callbackManager || !m_moduleTracker || !m_correlator) {
            SS_LOG_WARN(L"DLLInjection", L"AnalyzeLoad called before initialization");
            return info;
        }

        // Check process exclusion
        if (IsProcessExcluded(pid)) {
            return info;
        }

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
            info.loadingProcessName = GetProcessNameCached(pid);

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
            if (m_config.useWhitelist && m_whitelistStore) {
                auto result = m_whitelistStore->IsPathWhitelisted(info.normalizedPath);
                info.isWhitelisted = result.isWhitelisted;

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

            SS_LOG_INFO(L"DLLInjection", L"Analyzed %S - Trust: %d, Risk: %u", Utils::StringUtils::ToNarrow(info.dllName).c_str(), static_cast<int>(info.trustLevel), info.riskScore);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DLLInjection", L"AnalyzeLoad: %S", e.what());
            m_stats.analysisErrors.fetch_add(1, std::memory_order_relaxed);
        }

        return info;
    }

    InjectionAnalysisResult AnalyzeProcess(uint32_t pid) {
        InjectionAnalysisResult result;
        result.processId = pid;
        result.processName = GetProcessNameCached(pid);
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

            SS_LOG_INFO(L"DLLInjection", L"Process %u analysis complete - %u modules, %u suspicious, %u injected", pid, result.totalModules, result.suspiciousModules, result.injectedModules);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DLLInjection", L"AnalyzeProcess: %S", e.what());
            result.analysisError = Utils::StringUtils::ToWide(e.what());
            m_stats.analysisErrors.fetch_add(1, std::memory_order_relaxed);
        }

        return result;
    }

    LoadedDLLInfo AnalyzeModule(uint32_t pid, uintptr_t moduleBase) {
        // Get module path from base address
        wchar_t modulePath[MAX_PATH];
        HandleGuard hProcess(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid));
        if (hProcess) {
            if (GetModuleFileNameExW(hProcess.get(), reinterpret_cast<HMODULE>(moduleBase),
                                    modulePath, MAX_PATH)) {
                return AnalyzeLoad(pid, modulePath);
            }
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

        if (!m_initialized || !m_callbackManager || !m_moduleTracker || !m_correlator) {
            return events;
        }

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

            SS_LOG_INFO(L"DLLInjection", L"Process %u - %zu injections detected", pid, events.size());

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DLLInjection", L"DetectInjections: %S", e.what());
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

        // Only flag if thread was created by a DIFFERENT process (cross-process injection)
        if (threadEvent->creatorPid == pid) {
            return events;
        }

        // Look for recently loaded modules that appeared after the remote thread
        auto modules = m_moduleTracker->GetProcessModules(pid);
        const auto now = std::chrono::system_clock::now();

        for (const auto& module : modules) {
            // Use elapsed-time comparison (avoids unreliable clock domain conversion).
            // A module loaded within the correlation window after the thread creation
            // is a strong injection indicator.
            const auto moduleAge = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - module.loadTime
            );
            const auto threadAge = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - threadEvent->timestamp
            );

            // Both ages measured from "now", so their difference approximates the
            // time gap between the thread creation and the module load.
            const auto gap = std::abs(moduleAge.count() - threadAge.count());

            if (gap < DLLInjectionConstants::LOAD_CORRELATION_WINDOW_MS) {
                // Skip trusted system modules — they are normal dependencies
                if (module.trustLevel == TrustLevel::System ||
                    module.trustLevel == TrustLevel::Whitelisted) {
                    continue;
                }

                InjectionEvent event;
                event.eventId = m_nextEventId.fetch_add(1, std::memory_order_relaxed);
                event.timestamp = std::chrono::system_clock::now();
                event.targetPid = pid;
                event.injectorPid = threadEvent->creatorPid;
                event.dllInfo = module;
                event.injectionType = InjectionType::CreateRemoteThread;
                event.confidence = InjectionConfidence::High;
                event.injectionThreadId = 0;
                event.threadStartAddress = threadEvent->startAddress;
                event.detectionReasons.push_back(L"Remote thread created by PID " +
                    std::to_wstring(threadEvent->creatorPid));
                event.detectionReasons.push_back(L"Untrusted module loaded within correlation window");
                event.riskScore = 80;
                event.mitreAttackId = "T1055.001";

                events.push_back(event);

                m_stats.injectionsDetected.fetch_add(1, std::memory_order_relaxed);
                m_stats.remoteThreadInjections.fetch_add(1, std::memory_order_relaxed);

                m_callbackManager->InvokeInjection(event);

                SS_LOG_WARN(L"DLLInjection", L"CreateRemoteThread injection detected - PID %u injected by PID %u, DLL: %S",
                            pid, threadEvent->creatorPid,
                            Utils::StringUtils::ToNarrow(module.dllName).c_str());
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

        // Only flag modules loaded within the APC correlation window,
        // not ALL modules in the process (which causes massive false positives).
        auto modules = m_moduleTracker->GetProcessModules(pid);

        for (const auto& module : modules) {
            // Correlate by checking if the module load time is within the APC window
            const auto now = std::chrono::system_clock::now();
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - module.loadTime
            );

            // Only flag modules loaded recently (within correlation window)
            if (elapsed.count() > DLLInjectionConstants::LOAD_CORRELATION_WINDOW_MS) {
                continue;
            }

            // Skip trusted system modules -- APC injection loads untrusted DLLs
            if (module.trustLevel == TrustLevel::System ||
                module.trustLevel == TrustLevel::Whitelisted) {
                continue;
            }

            InjectionEvent event;
            event.eventId = m_nextEventId.fetch_add(1, std::memory_order_relaxed);
            event.timestamp = std::chrono::system_clock::now();
            event.targetPid = pid;
            event.injectorPid = apcEvent->queuedBy;
            event.dllInfo = module;
            event.injectionType = InjectionType::QueueUserAPC;
            event.confidence = InjectionConfidence::High;
            event.detectionReasons.push_back(L"APC queued by PID " + std::to_wstring(apcEvent->queuedBy));
            event.detectionReasons.push_back(L"Module loaded within APC correlation window");
            event.riskScore = 75;
            event.mitreAttackId = "T1055.004";

            events.push_back(event);

            m_stats.injectionsDetected.fetch_add(1, std::memory_order_relaxed);
            m_stats.apcInjections.fetch_add(1, std::memory_order_relaxed);

            m_callbackManager->InvokeInjection(event);

            SS_LOG_WARN(L"DLLInjection", L"QueueUserAPC injection detected - PID %u injected by PID %u", pid, apcEvent->queuedBy);
        }

        return events;
    }

    // ========================================================================
    // HOOK DETECTION
    // ========================================================================

    std::vector<HookInfo> EnumerateHooks() {
        std::vector<HookInfo> hooks;

        // Windows provides no public usermode API to enumerate all installed hooks.
        // Full hook enumeration requires ETW (Microsoft-Windows-Win32k provider)
        // or a kernel driver hooking NtUserSetWindowsHookEx.
        // Until ETW/driver integration is wired, this returns an empty set.

        SS_LOG_DEBUG(L"DLLInjection", L"Hook enumeration requires ETW/driver integration");

        return hooks;
    }

    std::vector<HookInfo> GetProcessHooks(uint32_t pid) {
        std::vector<HookInfo> hooks;

        // Process-specific hook enumeration requires ETW or driver.
        // Without that infrastructure, we can only detect hooks that we
        // observe being installed via OnHookInstall() event callbacks.

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
            // Check if AppInit_DLLs loading is enabled
            DWORD loadEnabled = 0;
            Utils::RegistryUtils::QuickReadDWord(
                HKEY_LOCAL_MACHINE,
                DLLInjectionConstants::APPINIT_DLLS_PATH,
                DLLInjectionConstants::APPINIT_LOAD_VALUE,
                loadEnabled
            );

            // Check AppInit_DLLs registry value
            std::wstring value;
            Utils::RegistryUtils::QuickReadString(
                HKEY_LOCAL_MACHINE,
                DLLInjectionConstants::APPINIT_DLLS_PATH,
                DLLInjectionConstants::APPINIT_DLLS_VALUE,
                value
            );

            if (!value.empty()) {
                RegistryInjectionVector vector;
                vector.registryPath = std::wstring(DLLInjectionConstants::APPINIT_DLLS_PATH);
                vector.valueName = std::wstring(DLLInjectionConstants::APPINIT_DLLS_VALUE);
                vector.dllPath = value;
                vector.isEnabled = (loadEnabled != 0);
                vector.lastModified = std::chrono::system_clock::now();
                // Only suspicious if loading is actually enabled
                vector.isSuspicious = (loadEnabled != 0);
                vector.suspicionReason = (loadEnabled != 0)
                    ? L"AppInit_DLLs configured and ENABLED"
                    : L"AppInit_DLLs configured but disabled (LoadAppInit_DLLs=0)";

                vectors.push_back(vector);

                if (loadEnabled != 0) {
                    m_stats.appInitInjections.fetch_add(1, std::memory_order_relaxed);
                    SS_LOG_WARN(L"DLLInjection", L"AppInit_DLLs ENABLED: %S",
                                Utils::StringUtils::ToNarrow(value).c_str());
                } else {
                    SS_LOG_INFO(L"DLLInjection", L"AppInit_DLLs present but disabled: %S",
                                Utils::StringUtils::ToNarrow(value).c_str());
                }
            }

            // Also check WoW64 hive on 64-bit systems (T1546.010 completeness)
            std::wstring wow64Value;
            Utils::RegistryUtils::OpenOptions wow64Opts;
            wow64Opts.wow64_32 = true;
            Utils::RegistryUtils::QuickReadString(
                HKEY_LOCAL_MACHINE,
                DLLInjectionConstants::APPINIT_DLLS_PATH,
                DLLInjectionConstants::APPINIT_DLLS_VALUE,
                wow64Value,
                wow64Opts
            );
            if (!wow64Value.empty() && wow64Value != value) {
                DWORD wow64Enabled = 0;
                Utils::RegistryUtils::QuickReadDWord(
                    HKEY_LOCAL_MACHINE,
                    DLLInjectionConstants::APPINIT_DLLS_PATH,
                    DLLInjectionConstants::APPINIT_LOAD_VALUE,
                    wow64Enabled,
                    wow64Opts
                );

                RegistryInjectionVector wow64Vector;
                wow64Vector.registryPath = std::wstring(DLLInjectionConstants::APPINIT_DLLS_PATH) + L" (WoW64)";
                wow64Vector.valueName = std::wstring(DLLInjectionConstants::APPINIT_DLLS_VALUE);
                wow64Vector.dllPath = wow64Value;
                wow64Vector.isEnabled = (wow64Enabled != 0);
                wow64Vector.lastModified = std::chrono::system_clock::now();
                wow64Vector.isSuspicious = (wow64Enabled != 0);
                wow64Vector.suspicionReason = (wow64Enabled != 0)
                    ? L"WoW64 AppInit_DLLs configured and ENABLED"
                    : L"WoW64 AppInit_DLLs configured but disabled";

                vectors.push_back(wow64Vector);

                if (wow64Enabled != 0) {
                    m_stats.appInitInjections.fetch_add(1, std::memory_order_relaxed);
                    SS_LOG_WARN(L"DLLInjection", L"WoW64 AppInit_DLLs ENABLED: %S",
                                Utils::StringUtils::ToNarrow(wow64Value).c_str());
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DLLInjection", L"CheckAppInitDLLs: %S", e.what());
        }

        return vectors;
    }

    std::vector<RegistryInjectionVector> CheckIFEOImpl() {
        std::vector<RegistryInjectionVector> vectors;

        try {
            // Enumerate IFEO keys using RegistryKey RAII wrapper
            Utils::RegistryUtils::RegistryKey ifeoKey;
            if (!ifeoKey.Open(HKEY_LOCAL_MACHINE, DLLInjectionConstants::IFEO_PATH)) {
                return vectors; // Key doesn't exist or access denied
            }

            std::vector<std::wstring> subkeys;
            if (!ifeoKey.EnumKeys(subkeys)) {
                return vectors;
            }

            for (const auto& subkey : subkeys) {
                std::wstring fullPath = std::wstring(DLLInjectionConstants::IFEO_PATH) + L"\\" + subkey;

                // Check for Debugger value (classic IFEO persistence)
                std::wstring debugger;
                Utils::RegistryUtils::QuickReadString(
                    HKEY_LOCAL_MACHINE,
                    fullPath,
                    L"Debugger",
                    debugger
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

                    SS_LOG_WARN(L"DLLInjection", L"IFEO debugger detected for %S: %S",
                                Utils::StringUtils::ToNarrow(subkey).c_str(),
                                Utils::StringUtils::ToNarrow(debugger).c_str());
                }

                // Check for Application Verifier DLL injection (GlobalFlag + VerifierDlls)
                // This is a less well-known IFEO abuse vector used by APTs
                DWORD globalFlag = 0;
                Utils::RegistryUtils::QuickReadDWord(
                    HKEY_LOCAL_MACHINE,
                    fullPath,
                    L"GlobalFlag",
                    globalFlag
                );

                if (globalFlag != 0) {
                    std::wstring verifierDlls;
                    Utils::RegistryUtils::QuickReadString(
                        HKEY_LOCAL_MACHINE,
                        fullPath,
                        L"VerifierDlls",
                        verifierDlls
                    );

                    if (!verifierDlls.empty()) {
                        RegistryInjectionVector vector;
                        vector.registryPath = fullPath;
                        vector.valueName = L"VerifierDlls";
                        vector.dllPath = verifierDlls;
                        vector.isEnabled = true;
                        vector.lastModified = std::chrono::system_clock::now();
                        vector.isSuspicious = true;
                        vector.suspicionReason = L"IFEO Application Verifier DLL for " + subkey +
                                                 L" (GlobalFlag=0x" + std::format(L"{:X}", globalFlag) + L")";

                        vectors.push_back(vector);

                        SS_LOG_WARN(L"DLLInjection", L"IFEO VerifierDlls detected for %S: %S (GlobalFlag=0x%X)",
                                    Utils::StringUtils::ToNarrow(subkey).c_str(),
                                    Utils::StringUtils::ToNarrow(verifierDlls).c_str(),
                                    globalFlag);
                    }
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DLLInjection", L"CheckIFEO: %S", e.what());
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
            std::wstring lowerProcessName = processName;
            std::transform(lowerProcessName.begin(), lowerProcessName.end(),
                           lowerProcessName.begin(), ::towlower);

            for (const auto& module : modules) {
                std::wstring lowerDllName = module.dllName;
                std::transform(lowerDllName.begin(), lowerDllName.end(),
                               lowerDllName.begin(), ::towlower);

                // Check against known side-load pairs (case-insensitive)
                for (const auto& pair : g_knownSideLoadPairs) {
                    std::wstring lowerExe = pair.executable;
                    std::transform(lowerExe.begin(), lowerExe.end(), lowerExe.begin(), ::towlower);
                    std::wstring lowerDll = pair.dllName;
                    std::transform(lowerDll.begin(), lowerDll.end(), lowerDll.begin(), ::towlower);

                    if (lowerProcessName == lowerExe && lowerDllName == lowerDll) {
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

                            SS_LOG_WARN(L"DLLInjection", L"Side-loading detected - %S loaded %S from %S", Utils::StringUtils::ToNarrow(processName).c_str(), Utils::StringUtils::ToNarrow(pair.dllName).c_str(), Utils::StringUtils::ToNarrow(module.dllPath).c_str());
                        }
                    }
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DLLInjection", L"DetectSideLoading: %S", e.what());
        }

        return sideLoads;
    }

    bool IsSideLoadedImpl(const std::wstring& executablePath, const std::wstring& dllPath) {
        std::wstring exeName = std::filesystem::path(executablePath).filename().wstring();
        std::wstring dllName = std::filesystem::path(dllPath).filename().wstring();
        std::transform(exeName.begin(), exeName.end(), exeName.begin(), ::towlower);
        std::transform(dllName.begin(), dllName.end(), dllName.begin(), ::towlower);

        for (const auto& pair : g_knownSideLoadPairs) {
            std::wstring lowerExe = pair.executable;
            std::transform(lowerExe.begin(), lowerExe.end(), lowerExe.begin(), ::towlower);
            std::wstring lowerDll = pair.dllName;
            std::transform(lowerDll.begin(), lowerDll.end(), lowerDll.begin(), ::towlower);

            if (exeName == lowerExe && dllName == lowerDll) {
                std::filesystem::path expectedPath = std::filesystem::path(executablePath).parent_path() / pair.dllName;
                return NormalizePath(dllPath) != NormalizePath(expectedPath.wstring());
            }
        }

        return false;
    }

    /**
     * @brief Public entry point for side-loading detection (resolves process path internally).
     */
    std::vector<SideLoadInfo> DetectSideLoading(uint32_t pid) {
        if (!m_initialized || !m_moduleTracker) return {};
        auto processPath = GetProcessPath(pid);
        return DetectSideLoadingImpl(pid, processPath);
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

                SS_LOG_ERROR(L"DLLInjection", L"Search order hijacking detected - %S loaded from %S", Utils::StringUtils::ToNarrow(module.dllName).c_str(), Utils::StringUtils::ToNarrow(module.dllPath).c_str());
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
            SS_LOG_ERROR(L"DLLInjection", L"Not initialized");
            return false;
        }

        if (m_monitoring) {
            SS_LOG_WARN(L"DLLInjection", L"Already monitoring");
            return true;
        }

        m_monitoring = true;
        SS_LOG_INFO(L"DLLInjection", L"Real-time monitoring started");
        return true;
    }

    void StopMonitoring() {
        std::unique_lock lock(m_mutex);

        if (!m_monitoring) return;

        m_monitoring = false;
        SS_LOG_INFO(L"DLLInjection", L"Real-time monitoring stopped");
    }

    bool IsMonitoring() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_monitoring;
    }

    void SetMonitoringMode(MonitoringMode mode) {
        std::unique_lock lock(m_mutex);
        m_config.mode = mode;
        SS_LOG_INFO(L"DLLInjection", L"Monitoring mode set to %d", static_cast<int>(mode));
    }

    MonitoringMode GetMonitoringMode() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_config.mode;
    }

    // ========================================================================
    // EVENT HANDLERS
    // ========================================================================

    void OnModuleLoad(uint32_t pid, const std::wstring& dllPath, uintptr_t baseAddress, size_t size) {
        if (!m_initialized || !m_monitoring) return;
        if (!m_callbackManager || !m_moduleTracker || !m_correlator) return;

        m_stats.moduleLoadEventsProcessed.fetch_add(1, std::memory_order_relaxed);

        if (IsProcessExcluded(pid)) return;

        try {
            auto dllInfo = AnalyzeLoad(pid, dllPath);
            dllInfo.baseAddress = baseAddress;
            dllInfo.sizeOfImage = static_cast<uint32_t>(size);

            // Update the tracker entry with kernel-provided base/size
            m_moduleTracker->AddModule(pid, dllInfo);

            // Check decision callbacks
            if (m_config.mode == MonitoringMode::ActiveBlock ||
                m_config.mode == MonitoringMode::Aggressive) {

                bool allow = m_callbackManager->InvokeDecision(dllInfo);

                if (!allow || ShouldBlock(dllInfo)) {
                    m_stats.loadsBlocked.fetch_add(1, std::memory_order_relaxed);
                    SS_LOG_WARN(L"DLLInjection", L"Blocked load of %S in PID %u", Utils::StringUtils::ToNarrow(dllPath).c_str(), pid);

                    // In real implementation, would signal driver to block
                    return;
                }
            }

            SS_LOG_INFO(L"DLLInjection", L"Module loaded - PID %u: %S", pid, Utils::StringUtils::ToNarrow(dllPath).c_str());

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DLLInjection", L"OnModuleLoad: %S", e.what());
        }
    }

    void OnThreadCreate(uint32_t targetPid, uint32_t creatorPid, uintptr_t startAddress) {
        if (!m_initialized || !m_monitoring || !m_correlator) return;

        m_stats.threadCreateEventsProcessed.fetch_add(1, std::memory_order_relaxed);

        // Record for correlation
        m_correlator->RecordThreadCreate(targetPid, creatorPid, startAddress);

        // Cross-process thread creation is a strong injection signal
        if (targetPid != creatorPid) {
            SS_LOG_WARN(L"DLLInjection", L"Remote thread created - Target PID %u, Creator PID %u, Start: 0x%llX",
                        targetPid, creatorPid, static_cast<unsigned long long>(startAddress));
        } else {
            SS_LOG_DEBUG(L"DLLInjection", L"Thread created - PID %u, Start: 0x%llX",
                         targetPid, static_cast<unsigned long long>(startAddress));
        }
    }

    void OnAPCQueue(uint32_t targetPid, uint32_t targetTid, uint32_t queuedBy, uintptr_t apcRoutine) {
        if (!m_initialized || !m_monitoring || !m_correlator) return;

        m_stats.apcEventsProcessed.fetch_add(1, std::memory_order_relaxed);

        // Record for correlation
        m_correlator->RecordAPCQueue(targetPid, targetTid, queuedBy, apcRoutine);

        // Cross-process APC is always suspicious
        if (targetPid != queuedBy) {
            SS_LOG_WARN(L"DLLInjection", L"Remote APC queued - Target PID %u TID %u, Queued by PID %u, Routine: 0x%llX",
                        targetPid, targetTid, queuedBy, static_cast<unsigned long long>(apcRoutine));
        } else {
            SS_LOG_DEBUG(L"DLLInjection", L"APC queued - PID %u TID %u, Routine: 0x%llX",
                         targetPid, targetTid, static_cast<unsigned long long>(apcRoutine));
        }
    }

    void OnHookInstall(int hookType, uint32_t threadId, uintptr_t hookProc, uint32_t installerPid) {
        if (!m_initialized || !m_monitoring || !m_callbackManager) return;

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

        SS_LOG_INFO(L"DLLInjection", L"Hook installed - Type %d, Global: %d, Installer PID %u", hookType, info.isGlobal ? 1 : 0, installerPid);
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    uint64_t RegisterCallback(InjectionDetectedCallback callback) {
        if (!m_callbackManager) {
            SS_LOG_ERROR(L"DLLInjection", L"RegisterCallback called before Initialize");
            return 0;
        }
        return m_callbackManager->RegisterInjection(std::move(callback));
    }

    uint64_t RegisterModuleCallback(ModuleLoadCallback callback) {
        if (!m_callbackManager) {
            SS_LOG_ERROR(L"DLLInjection", L"RegisterModuleCallback called before Initialize");
            return 0;
        }
        return m_callbackManager->RegisterModule(std::move(callback));
    }

    uint64_t RegisterDecisionCallback(LoadDecisionCallback callback) {
        if (!m_callbackManager) {
            SS_LOG_ERROR(L"DLLInjection", L"RegisterDecisionCallback called before Initialize");
            return 0;
        }
        return m_callbackManager->RegisterDecision(std::move(callback));
    }

    uint64_t RegisterHookCallback(HookInstalledCallback callback) {
        if (!m_callbackManager) {
            SS_LOG_ERROR(L"DLLInjection", L"RegisterHookCallback called before Initialize");
            return 0;
        }
        return m_callbackManager->RegisterHook(std::move(callback));
    }

    void UnregisterCallback(uint64_t callbackId) {
        if (!m_callbackManager) return;
        m_callbackManager->Unregister(callbackId);
    }

    // ========================================================================
    // WHITELIST
    // ========================================================================

    void AddToWhitelist(const std::wstring& dllPath) {
        if (m_whitelistStore) {
            m_whitelistStore->AddPath(
                NormalizePath(dllPath),
                Whitelist::PathMatchMode::Exact,
                Whitelist::WhitelistReason::Custom,
                L"Added via DLLInjectionDetector"
            );
        }
        // Also track locally for fast in-memory lookup
        {
            std::unique_lock lock(m_mutex);
            m_localWhitelist.insert(NormalizePath(dllPath));
        }
        SS_LOG_INFO(L"DLLInjection", L"Added to whitelist: %S", Utils::StringUtils::ToNarrow(dllPath).c_str());
    }

    void RemoveFromWhitelist(const std::wstring& dllPath) {
        if (m_whitelistStore) {
            m_whitelistStore->RemovePath(
                NormalizePath(dllPath),
                Whitelist::PathMatchMode::Exact
            );
        }
        {
            std::unique_lock lock(m_mutex);
            m_localWhitelist.erase(NormalizePath(dllPath));
        }
        SS_LOG_INFO(L"DLLInjection", L"Removed from whitelist: %S", Utils::StringUtils::ToNarrow(dllPath).c_str());
    }

    bool IsWhitelisted(const std::wstring& dllPath) const {
        const std::wstring normalized = NormalizePath(dllPath);

        // Check local whitelist first (fast path)
        {
            std::shared_lock lock(m_mutex);
            if (m_localWhitelist.count(normalized) > 0) {
                return true;
            }
        }

        // Check external whitelist store if available
        if (m_whitelistStore) {
            auto result = m_whitelistStore->IsPathWhitelisted(normalized);
            return result.isWhitelisted;
        }

        return false;
    }

    void ExcludeProcess(const std::wstring& processName) {
        std::unique_lock lock(m_mutex);
        m_config.excludedProcesses.push_back(processName);
        SS_LOG_INFO(L"DLLInjection", L"Excluded process: %S", Utils::StringUtils::ToNarrow(processName).c_str());
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

    /**
     * @brief Check if a process is in the exclusion list.
     * Uses cached process name to avoid repeated handle opens.
     */
    bool IsProcessExcluded(uint32_t pid) {
        if (m_config.excludedProcesses.empty()) return false;

        std::wstring procName = GetProcessNameCached(pid);
        std::wstring lowerName = procName;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

        std::shared_lock lock(m_mutex);
        for (const auto& excluded : m_config.excludedProcesses) {
            std::wstring lowerExcluded = excluded;
            std::transform(lowerExcluded.begin(), lowerExcluded.end(), lowerExcluded.begin(), ::towlower);
            if (lowerName == lowerExcluded) return true;
        }
        return false;
    }

    /**
     * @brief Get process name with caching to avoid repeated handle opens.
     *
     * Process names are cached for up to 60 seconds. PID reuse within that
     * window is acceptable since the stale name would just cause a missed
     * exclusion which is fail-safe (analyze rather than skip).
     */
    std::wstring GetProcessNameCached(uint32_t pid) {
        {
            std::shared_lock lock(m_procCacheMutex);
            auto it = m_processNameCache.find(pid);
            if (it != m_processNameCache.end()) {
                const auto age = std::chrono::steady_clock::now() - it->second.second;
                if (age < std::chrono::seconds(60)) {
                    return it->second.first;
                }
            }
        }

        // Cache miss or stale — resolve and store
        std::wstring name = GetProcessName(pid);
        {
            std::unique_lock lock(m_procCacheMutex);
            // Evict if cache is too large (handles PID exhaustion attacks)
            if (m_processNameCache.size() > 20000) {
                m_processNameCache.clear();
            }
            m_processNameCache[pid] = { name, std::chrono::steady_clock::now() };
        }
        return name;
    }

    std::wstring GetProcessName(uint32_t pid) const {
        wchar_t processName[MAX_PATH] = L"<unknown>";

        HandleGuard hProcess(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        if (hProcess) {
            DWORD size = MAX_PATH;
            QueryFullProcessImageNameW(hProcess.get(), 0, processName, &size);
        }

        std::filesystem::path path(processName);
        return path.filename().wstring();
    }

    std::wstring GetProcessPath(uint32_t pid) const {
        wchar_t processPath[MAX_PATH] = L"";

        HandleGuard hProcess(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        if (hProcess) {
            DWORD size = MAX_PATH;
            QueryFullProcessImageNameW(hProcess.get(), 0, processPath, &size);
        }

        return processPath;
    }

    std::vector<std::wstring> EnumerateProcessModules(uint32_t pid) const {
        std::vector<std::wstring> modules;

        HandleGuard hProcess(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid));
        if (!hProcess) {
            m_stats.accessDeniedErrors.fetch_add(1, std::memory_order_relaxed);
            return modules;
        }

        // First call: determine how many bytes we need
        DWORD cbNeeded = 0;
        if (!EnumProcessModules(hProcess.get(), nullptr, 0, &cbNeeded) && cbNeeded == 0) {
            // Retry with a reasonable initial buffer — some processes fail with size 0
            cbNeeded = 1024 * sizeof(HMODULE);
        }

        // Cap to prevent adversarial allocation
        constexpr DWORD MAX_MODULE_BYTES = 65536 * sizeof(HMODULE);
        cbNeeded = std::min(cbNeeded, MAX_MODULE_BYTES);

        std::vector<HMODULE> hMods(cbNeeded / sizeof(HMODULE));
        DWORD cbActual = 0;

        if (EnumProcessModules(hProcess.get(), hMods.data(),
                               static_cast<DWORD>(hMods.size() * sizeof(HMODULE)), &cbActual)) {
            const DWORD moduleCount = cbActual / sizeof(HMODULE);

            for (DWORD i = 0; i < moduleCount; ++i) {
                wchar_t modulePath[MAX_PATH];
                if (GetModuleFileNameExW(hProcess.get(), hMods[i], modulePath, MAX_PATH)) {
                    modules.push_back(modulePath);
                }
            }
        }

        return modules;
    }

    void ValidateSignature(LoadedDLLInfo& info) {
        try {
            Utils::pe_sig_utils::PEFileSignatureVerifier verifier;
            // Allow cached CRLs to avoid blocking on network
            verifier.SetRevocationMode(Utils::pe_sig_utils::RevocationMode::OfflineAllowed);

            Utils::pe_sig_utils::SignatureInfo sigInfo;
            Utils::pe_sig_utils::Error sigErr;
            if (verifier.VerifyPESignature(info.dllPath, sigInfo, &sigErr)) {
                // Signature is valid and trusted
                info.isSigned = true;
                info.signerName = sigInfo.signerName;

                // Detect Microsoft signatures (covers "Microsoft Corporation",
                // "Microsoft Windows", "Microsoft Code Signing PCA", etc.)
                if (!sigInfo.signerName.empty()) {
                    std::wstring lowerSigner = sigInfo.signerName;
                    std::transform(lowerSigner.begin(), lowerSigner.end(),
                                   lowerSigner.begin(), ::towlower);
                    if (lowerSigner.find(L"microsoft") != std::wstring::npos) {
                        info.isMicrosoftSigned = true;
                    }
                }
            } else {
                // Signature absent or invalid
                info.isSigned = sigInfo.isSigned;  // may have sig but not valid
                if (sigInfo.isSigned && !sigInfo.isVerified) {
                    info.riskFactors.push_back(L"Invalid digital signature");
                }
            }
        } catch (...) {
            // Signature validation is best-effort for module load analysis.
            // If it throws, leave defaults (unsigned/untrusted).
        }
    }

    void PerformHashLookup(LoadedDLLInfo& info) {
        try {
            m_stats.hashLookups.fetch_add(1, std::memory_order_relaxed);

            // Compute SHA-256 hash using FileUtils (correct API)
            std::array<uint8_t, 32> hashArr{};
            if (!Utils::FileUtils::ComputeFileSHA256(info.dllPath, hashArr)) {
                return; // Hash computation failed, skip lookup
            }

            info.sha256Hash = hashArr;
            info.hashComputed = true;

            // Check against HashStore if externally provided
            if (m_hashStore && m_hashStore->IsInitialized()) {
                // Build HashValue for lookup
                SignatureStore::HashValue hv;
                hv.algorithm = SignatureStore::HashAlgorithm::SHA256;
                hv.length = 32;
                std::memcpy(hv.data.data(), hashArr.data(),
                            std::min<size_t>(32, hv.data.size()));

                auto result = m_hashStore->LookupHash(hv);
                if (result.has_value()) {
                    // Detected in hash database - check threat level
                    if (result->threatLevel >= SignatureStore::ThreatLevel::High) {
                        info.hashFoundMalicious = true;
                        info.riskFactors.push_back(L"Known malicious hash");
                    } else {
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

    // External store references (NOT owned, set by orchestrator)
    HashStore::HashStore* m_hashStore{ nullptr };
    Whitelist::WhitelistStore* m_whitelistStore{ nullptr };

    // Local whitelist for fast in-memory lookups
    std::unordered_set<std::wstring> m_localWhitelist;

    // Process name cache (pid → {name, timestamp})
    mutable std::shared_mutex m_procCacheMutex;
    std::unordered_map<uint32_t, std::pair<std::wstring, std::chrono::steady_clock::time_point>> m_processNameCache;

    // Statistics
    mutable DLLInjectionStatistics m_stats;
    std::atomic<uint64_t> m_nextEventId{ 1 };

    // ========================================================================
    // EXTERNAL STORE SETTERS (called by orchestrator after Initialize)
    // ========================================================================
public:
    void SetHashStore(HashStore::HashStore* store) noexcept {
        std::unique_lock lock(m_mutex);
        m_hashStore = store;
        SS_LOG_INFO(L"DLLInjection", L"HashStore connected: %S",
                    store ? "yes" : "no");
    }

    void SetWhitelistStore(Whitelist::WhitelistStore* store) noexcept {
        std::unique_lock lock(m_mutex);
        m_whitelistStore = store;
        SS_LOG_INFO(L"DLLInjection", L"WhitelistStore connected: %S",
                    store ? "yes" : "no");
    }
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
    // Continuous registry monitoring requires a dedicated background thread
    // calling RegNotifyChangeKeyValue on AppInit_DLLs and IFEO keys.
    // This is wired through the RealTimeProtection orchestrator's event loop;
    // direct polling from this module is not supported.
    // Use CheckAllRegistryVectors() for one-shot inspection instead.
    SS_LOG_DEBUG(L"DLLInjection", L"Continuous registry monitoring requires orchestrator integration");
    return false;
}

std::vector<SideLoadInfo> DLLInjectionDetector::DetectSideLoading(uint32_t pid) {
    return m_impl->DetectSideLoading(pid);
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

void DLLInjectionDetector::SetHashStore(HashStore::HashStore* store) noexcept {
    m_impl->SetHashStore(store);
}

void DLLInjectionDetector::SetWhitelistStore(Whitelist::WhitelistStore* store) noexcept {
    m_impl->SetWhitelistStore(store);
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
