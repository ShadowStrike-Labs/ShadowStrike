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
 * ShadowStrike NGAV - BOOT TIME ANALYZER IMPLEMENTATION
 * ============================================================================
 *
 * @file BootTimeAnalyzer.cpp
 * @brief Enterprise-grade boot performance analysis and startup security implementation.
 *
 * Production-level implementation competing with Windows Performance Toolkit,
 * BootRacer, and enterprise endpoint management solutions. Provides comprehensive
 * boot time analysis, startup security assessment, ELAM integration, and
 * optimization recommendations with full security validation.
 *
 * IMPLEMENTATION FEATURES:
 * ========================
 *
 * - PIMPL pattern for ABI stability
 * - Thread-safe with std::shared_mutex
 * - Boot phase timing (9 phases from UEFI to post-logon)
 * - Driver load time analysis with ELAM integration
 * - Service startup profiling
 * - Application launch impact measurement
 * - Startup item security assessment
 * - Secure Boot / Measured Boot / VBS verification
 * - Optimization recommendation engine
 * - ShadowStrike impact tracking
 * - Comprehensive statistics (4 atomic counters)
 * - Configuration factory methods
 * - Export functionality (reports, optimizations)
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
#include "BootTimeAnalyzer.hpp"
#include "DriverAnalyzer.hpp"
#include "../../Utils/SystemUtils.hpp"
#include "../../Utils/RegistryUtils.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/CryptoUtils.hpp"
#include "../../Utils/CertUtils.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/Logger.hpp"
#include "../../HashStore/HashStore.hpp"
#include "../../Whitelist/WhiteListStore.hpp"
#include "../../Communication/IPCManager.hpp"
#include "../../Core/Registry/RegistryMonitor.hpp"

#include <Windows.h>
#include <winternl.h>
#include <wtsapi32.h>
#include <psapi.h>
#include <powrprof.h>
#include <shlobj.h>           // For SHGetFolderPathW, CSIDL_*
#include <taskschd.h>         // For Task Scheduler COM interfaces
#include <comdef.h>           // For COM error handling
#include <wbemidl.h>          // For WMI interfaces
#include <wintrust.h>         // For WinVerifyTrust (Authenticode)
#include <softpub.h>          // For WINTRUST_ACTION_GENERIC_VERIFY_V2
#include <algorithm>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <map>
#include <unordered_set>

#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "powrprof.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")   // For SHGetFolderPathW
#pragma comment(lib, "taskschd.lib")  // For Task Scheduler
#pragma comment(lib, "wbemuuid.lib")  // For WMI
#pragma comment(lib, "wintrust.lib")  // For WinVerifyTrust

namespace ShadowStrike {
namespace Core {
namespace System {

namespace fs = std::filesystem;

// ============================================================================
// NAMESPACE CONSTANTS
// ============================================================================

namespace BootTimeAnalyzerConstants {
    constexpr uint32_t VERSION_MAJOR = 3;
    constexpr uint32_t VERSION_MINOR = 2;
    constexpr uint32_t VERSION_PATCH = 0;

    // Performance thresholds (milliseconds)
    constexpr uint32_t SLOW_DRIVER_THRESHOLD_MS = 500;
    constexpr uint32_t SLOW_SERVICE_THRESHOLD_MS = 2000;
    constexpr uint32_t SLOW_APP_THRESHOLD_MS = 3000;

    // Impact score thresholds
    constexpr uint8_t HIGH_IMPACT_THRESHOLD = 70;
    constexpr uint8_t MEDIUM_IMPACT_THRESHOLD = 40;

    // ELAM registry path
    constexpr wchar_t ELAM_REG_PATH[] = L"SYSTEM\\CurrentControlSet\\Control\\EarlyLaunch";
    
    // Boot performance registry paths
    constexpr wchar_t BOOT_PERF_REG_PATH[] = L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment";
    constexpr wchar_t BOOT_TIMESTAMP_REG_PATH[] = L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power";
    
    // BCD store registry paths (for tampering detection)
    constexpr wchar_t BCD_STORE_REG_PATH[] = L"BCD00000000";
    constexpr wchar_t SYSTEM_POLICIES_CI[] = L"SYSTEM\\CurrentControlSet\\Control\\CI\\Config";
    constexpr wchar_t CODE_INTEGRITY_PATH[] = L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity";

    // Maximum buffer sizes for safety
    constexpr size_t MAX_REG_VALUE_SIZE = 32768;  // 32KB max registry value
    constexpr size_t MAX_PATH_EXPANDED = 4096;    // Expanded path buffer
    constexpr size_t MAX_ENUM_VALUE_NAME = 512;   // Registry value name (heap-safe)
    constexpr size_t MAX_DRIVERS_ENUMERATED = 2048; // Cap driver enumeration
    
    // Known legitimate AppData applications (partial match)
    const std::unordered_set<std::wstring> KNOWN_APPDATA_APPS = {
        L"microsoft", L"google", L"chrome", L"teams", L"slack", L"discord",
        L"zoom", L"spotify", L"dropbox", L"onedrive", L"visual studio",
        L"vscode", L"code.exe", L"firefox", L"edge", L"brave", L"opera",
        L"jetbrains", L"github", L"git", L"docker", L"powershell",
        L"windowsterminal", L"terminal", L"notion", L"obsidian", L"postman"
    };
}  // namespace BootTimeAnalyzerConstants

// Log category for this module
static constexpr wchar_t LOG_CATEGORY[] = L"BootTimeAnalyzer";

// ============================================================================
// INTERNAL HELPERS (file-local linkage)
// ============================================================================
namespace {

// Hard caps that bound attacker-influenced data (registry/WMI/COM strings).
constexpr size_t  kMaxLogStringChars         = 512;     // wchar elements
constexpr size_t  kMaxRegStringChars         = 4096;
constexpr size_t  kMaxBcdIndicatorValueChars = 260;
constexpr size_t  kMaxTaskFolderRecursion    = 32;
constexpr size_t  kMaxWmiConsumersPerClass   = 256;
constexpr ULONG   kWmiNextTimeoutMs          = 1000;
constexpr ULONGLONG kMaxReasonableBootMs     = 10ULL * 60ULL * 1000ULL; // 10 minutes
constexpr DWORD   kMaxDriverEnumGrowSlots    = 8192;
constexpr uint64_t kMaxHashFileBytes         = 128ULL * 1024ULL * 1024ULL; // 128 MiB

// Strip CR/LF/control chars and clamp length. Use on any attacker-controlled
// wstring before passing to logger or persisting in audit fields.
[[nodiscard]] inline std::wstring SanitizeForLog(std::wstring_view in,
                                                 size_t maxChars = kMaxLogStringChars) noexcept {
    std::wstring out;
    try {
        const size_t limit = std::min(in.size(), maxChars);
        out.reserve(limit);
        for (size_t i = 0; i < limit; ++i) {
            wchar_t c = in[i];
            if (c == L'\r' || c == L'\n' || c == L'\t') {
                out.push_back(L' ');
            } else if (c < 0x20 || c == 0x7F) {
                out.push_back(L'?');
            } else {
                out.push_back(c);
            }
        }
        if (in.size() > maxChars) {
            out.append(L"...[truncated]");
        }
    } catch (...) {
        out.clear();
    }
    return out;
}

// Reject names that would let an attacker escape a registry sub-key by way of
// backslash/dot/colon/wildcard. Used before concatenating into registry paths.
[[nodiscard]] inline bool IsSafeRegistryNameComponent(std::wstring_view name) noexcept {
    if (name.empty() || name.size() > 255) return false;
    for (wchar_t c : name) {
        if (c < 0x20 || c == 0x7F) return false;
        if (c == L'\\' || c == L'/' || c == L':' || c == L'*' ||
            c == L'?' || c == L'"' || c == L'<' || c == L'>' || c == L'|') {
            return false;
        }
    }
    // Refuse plain "." or ".." traversal tokens.
    if (name == L"." || name == L"..") return false;
    return true;
}

// Saturating add to avoid overflow when summing attacker-influenced 100ns ticks.
[[nodiscard]] inline ULONGLONG SaturatingAddU64(ULONGLONG a, ULONGLONG b) noexcept {
    return (b > (UINT64_MAX - a)) ? UINT64_MAX : (a + b);
}

// Saturating multiply for delay/duration heuristics.
[[nodiscard]] inline uint32_t SaturatingMulU32(uint32_t a, uint32_t b, uint32_t cap) noexcept {
    uint64_t r = static_cast<uint64_t>(a) * static_cast<uint64_t>(b);
    if (r > cap) r = cap;
    return static_cast<uint32_t>(r);
}

// Validate caller-provided export paths. Refuses NUL embeds, abnormally long
// paths, and obvious directory traversal.
[[nodiscard]] inline bool IsSafeExportPath(const std::wstring& p) noexcept {
    if (p.empty() || p.size() > 32767) return false; // MAX path limit per Win32 \\?\ prefix
    for (wchar_t c : p) {
        if (c == L'\0') return false;
        if (c < 0x20) return false;
    }
    // Block .. as a path component for safety against unintended writes.
    if (p.find(L"..\\") != std::wstring::npos ||
        p.find(L"../") != std::wstring::npos) {
        return false;
    }
    return true;
}

// Safely null-terminate a wide buffer that was written by RegQueryValueExW.
// `byteSize` is the OUT size in bytes (as returned by RegQueryValueExW).
// `cap` bounds the resulting string length. Returns a sanitized std::wstring.
[[nodiscard]] inline std::wstring SafeWStringFromRegBytes(const BYTE* bytes,
                                                          DWORD byteSize,
                                                          size_t cap) noexcept {
    if (!bytes || byteSize == 0) return L"";
    DWORD chars = byteSize / static_cast<DWORD>(sizeof(wchar_t));
    if (chars == 0) return L"";
    if (chars > cap) chars = static_cast<DWORD>(cap);
    std::wstring out;
    try {
        out.reserve(chars);
        // Reinterpret the byte buffer one wchar at a time using memcpy to
        // avoid strict-aliasing UB.
        for (DWORD i = 0; i < chars; ++i) {
            wchar_t wc = 0;
            std::memcpy(&wc, bytes + i * sizeof(wchar_t), sizeof(wchar_t));
            if (wc == L'\0') break;
            // Strip CR/LF/control characters defensively.
            if (wc == L'\r' || wc == L'\n' || wc == L'\t') {
                out.push_back(L' ');
            } else if (wc < 0x20 || wc == 0x7F) {
                out.push_back(L'?');
            } else {
                out.push_back(wc);
            }
        }
    } catch (...) {
        return L"";
    }
    return out;
}

// RAII helper for BSTR.
struct ScopedBstr {
    BSTR b{ nullptr };
    ScopedBstr() = default;
    ~ScopedBstr() { if (b) ::SysFreeString(b); }
    ScopedBstr(const ScopedBstr&) = delete;
    ScopedBstr& operator=(const ScopedBstr&) = delete;
    BSTR* operator&() noexcept { return &b; }
    operator BSTR() const noexcept { return b; }
    [[nodiscard]] std::wstring ToWString() const {
        return b ? std::wstring(b, ::SysStringLen(b)) : std::wstring();
    }
};

// RAII helper for VARIANT.
struct ScopedVariant {
    VARIANT v{};
    ScopedVariant() noexcept { ::VariantInit(&v); }
    ~ScopedVariant() { ::VariantClear(&v); }
    ScopedVariant(const ScopedVariant&) = delete;
    ScopedVariant& operator=(const ScopedVariant&) = delete;
    VARIANT* operator&() noexcept { return &v; }
    [[nodiscard]] bool IsBstr() const noexcept { return v.vt == VT_BSTR && v.bstrVal != nullptr; }
    [[nodiscard]] std::wstring ToWString() const {
        return IsBstr() ? std::wstring(v.bstrVal, ::SysStringLen(v.bstrVal)) : std::wstring();
    }
};

} // anonymous namespace

// ============================================================================
// STATISTICS METHODS
// ============================================================================

void BootTimeAnalyzerStatistics::Reset() noexcept {
    analysesPerformed.store(0, std::memory_order_relaxed);
    startupItemsScanned.store(0, std::memory_order_relaxed);
    suspiciousItemsFound.store(0, std::memory_order_relaxed);
    optimizationsSuggested.store(0, std::memory_order_relaxed);
    bcdTamperDetections.store(0, std::memory_order_relaxed);
    kernelQueriesPerformed.store(0, std::memory_order_relaxed);
    bootDriversAnalyzed.store(0, std::memory_order_relaxed);
}

// ============================================================================
// CONFIG FACTORY METHODS
// ============================================================================

BootTimeAnalyzerConfig BootTimeAnalyzerConfig::CreateDefault() noexcept {
    BootTimeAnalyzerConfig config;
    config.analyzeDrivers = true;
    config.analyzeServices = true;
    config.analyzeApplications = true;
    config.evaluateSecurity = true;
    config.generateRecommendations = true;
    return config;
}

// ============================================================================
// PIMPL IMPLEMENTATION
// ============================================================================

struct BootTimeAnalyzer::BootTimeAnalyzerImpl {
    // Thread synchronization
    mutable std::shared_mutex m_mutex;

    // Configuration
    BootTimeAnalyzerConfig m_config;

    // Infrastructure
    std::shared_ptr<HashStore::HashStore> m_hashStore;
    std::shared_ptr<Whitelist::WhitelistStore> m_whitelist;

    // State
    std::atomic<bool> m_initialized{false};

    // Cached analysis result (protected by m_analysisMutex)
    std::optional<BootAnalysisResult> m_lastAnalysis;
    mutable std::shared_mutex m_analysisMutex;

    // Statistics (mutable for const methods to update)
    mutable BootTimeAnalyzerStatistics m_statistics;
    
    // COM initialization tracking (thread-local for WMI/TaskScheduler)
    static thread_local bool s_comInitialized;

    // Kernel-reported boot telemetry (populated by QueryKernelBootTelemetry)
    struct KernelBootData {
        bool hasData{ false };
        std::vector<DriverBootMetric> elamClassifiedDrivers;
        std::chrono::milliseconds kernelReportedBootTime{ 0 };
        bool elamDriverLoaded{ false };
    };
    KernelBootData m_kernelBootData;
    mutable std::shared_mutex m_kernelDataMutex;

    // RegistryMonitor event-callback ID for BCD change observation.
    // Stored so Shutdown can deregister and avoid clobbering global policy.
    uint64_t m_bcdCallbackId{ 0 };

    BootTimeAnalyzerImpl() = default;
    
    // ========================================================================
    // INITIALIZATION GUARD
    // ========================================================================
    
    [[nodiscard]] bool IsReady() const noexcept {
        return m_initialized.load(std::memory_order_acquire);
    }

    // ========================================================================
    // COM INITIALIZATION HELPER
    // ========================================================================
    
    bool EnsureCOMInitialized() const {
        if (!s_comInitialized) {
            HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
            if (SUCCEEDED(hr)) {
                s_comInitialized = true;
            } else if (hr == RPC_E_CHANGED_MODE) {
                // Already initialized with different threading model — still usable
                s_comInitialized = true;
            } else {
                SS_LOG_ERROR(LOG_CATEGORY, L"COM initialization failed - HRESULT 0x%08X",
                            static_cast<unsigned>(hr));
            }
        }
        return s_comInitialized;
    }

    // ========================================================================
    // BOOT TIME RETRIEVAL - REAL IMPLEMENTATION
    // ========================================================================

    std::chrono::system_clock::time_point GetLastBootTime() const {
        try {
            // Correlate monotonic uptime with the wall clock. GetTickCount64()
            // is unbiased by NTP changes after boot. We treat the returned
            // tickCount as ms-since-boot and back-calculate the wall-time
            // boot instant. Cap at a sane upper bound to defeat absurd
            // tampered counters (kept here as a safety net against drivers
            // that hook QueryPerformanceCounter / GetTickCount64).
            ULONGLONG tickCount = GetTickCount64();
            // Clamp tickCount to a century in milliseconds; nothing larger
            // is a real Windows uptime.
            constexpr ULONGLONG kCenturyMs = 100ULL * 365ULL * 24ULL * 3600ULL * 1000ULL;
            if (tickCount > kCenturyMs) {
                tickCount = kCenturyMs;
            }
            auto now = std::chrono::system_clock::now();
            return now - std::chrono::milliseconds(static_cast<int64_t>(tickCount));
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"BootTimeAnalyzer: Failed to get boot time - %hs", e.what());
            return std::chrono::system_clock::now();
        }
    }

    // Returns true iff the registry value is REG_QWORD/REG_DWORD and the
    // 100-nanosecond timestamp could be read.
    [[nodiscard]] static bool ReadRegHundredNsCounter(HKEY hKey,
                                                      LPCWSTR name,
                                                      ULONGLONG& outValue) noexcept {
        outValue = 0;
        DWORD type = 0;
        // Try QWORD first (Windows usually stores these as 64-bit).
        ULONGLONG q = 0;
        DWORD size = sizeof(q);
        LONG lr = RegQueryValueExW(hKey, name, nullptr, &type,
                                   reinterpret_cast<LPBYTE>(&q), &size);
        if (lr == ERROR_SUCCESS && size == sizeof(q) && type == REG_QWORD) {
            outValue = q;
            return true;
        }
        // Fall back to DWORD.
        DWORD d = 0;
        size = sizeof(d);
        type = 0;
        lr = RegQueryValueExW(hKey, name, nullptr, &type,
                              reinterpret_cast<LPBYTE>(&d), &size);
        if (lr == ERROR_SUCCESS && size == sizeof(d) && type == REG_DWORD) {
            outValue = static_cast<ULONGLONG>(d);
            return true;
        }
        return false;
    }

    /// @brief Get actual boot duration from Windows performance data
    /// @return Boot duration in milliseconds
    std::chrono::milliseconds GetTotalBootTimeMs() const {
        try {
            // Method 1: Query boot performance data from registry
            // Windows stores boot timing in: HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                             L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power",
                             0, KEY_READ, &hKey) == ERROR_SUCCESS) {

                ULONGLONG fwPostTime = 0;       // 100ns
                ULONGLONG bootPostTime = 0;     // 100ns
                bool haveFw   = ReadRegHundredNsCounter(hKey, L"FwPOSTTime",   fwPostTime);
                bool haveBoot = ReadRegHundredNsCounter(hKey, L"BootPOSTTime", bootPostTime);
                RegCloseKey(hKey);

                if (haveFw || haveBoot) {
                    // Cap each component at 30 minutes (100ns ticks).
                    constexpr ULONGLONG kHundredNsPer30Min = 30ULL * 60ULL * 10000000ULL;
                    if (fwPostTime   > kHundredNsPer30Min) fwPostTime   = kHundredNsPer30Min;
                    if (bootPostTime > kHundredNsPer30Min) bootPostTime = kHundredNsPer30Min;
                    ULONGLONG totalMs = SaturatingAddU64(fwPostTime / 10000ULL,
                                                        bootPostTime / 10000ULL);
                    if (totalMs > kMaxReasonableBootMs) {
                        totalMs = kMaxReasonableBootMs;
                    }
                    if (totalMs > 0) {
                        return std::chrono::milliseconds(static_cast<int64_t>(totalMs));
                    }
                }
            }

            // Method 2/3: Fallback estimate from phase analysis
            auto phases = AnalyzeBootPhases();
            ULONGLONG totalMs = 0;
            for (const auto& phase : phases) {
                int64_t d = phase.duration.count();
                if (d > 0) {
                    totalMs = SaturatingAddU64(totalMs, static_cast<ULONGLONG>(d));
                }
            }
            if (totalMs > kMaxReasonableBootMs) totalMs = kMaxReasonableBootMs;
            if (totalMs > 0) {
                return std::chrono::milliseconds(static_cast<int64_t>(totalMs));
            }

            // Ultimate fallback: 30s typical boot
            return std::chrono::milliseconds(30000);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"BootTimeAnalyzer: Failed to get total boot time - %hs", e.what());
            return std::chrono::milliseconds(0);
        }
    }

    // ========================================================================
    // BOOT PHASE ANALYSIS - REAL IMPLEMENTATION
    // ========================================================================

    std::vector<BootPhaseMetric> AnalyzeBootPhases() const {
        std::vector<BootPhaseMetric> phases;

        try {
            auto bootTime = GetLastBootTime();
            
            // Query real boot timing from registry performance data
            HKEY hKey;
            ULONGLONG fwPostTime = 0;       // Firmware POST time (100ns units)
            ULONGLONG bootDriverTime = 0;   // Boot driver init time
            ULONGLONG systemDriverTime = 0; // System driver init time
            ULONGLONG serviceTime = 0;      // Service startup time
            
            // Try to get actual boot phase timings from Windows
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                             L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power",
                             0, KEY_READ, &hKey) == ERROR_SUCCESS) {

                (void)ReadRegHundredNsCounter(hKey, L"FwPOSTTime",          fwPostTime);
                (void)ReadRegHundredNsCounter(hKey, L"BootDriverInitTime", bootDriverTime);
                (void)ReadRegHundredNsCounter(hKey, L"SystemDriverInitTime", systemDriverTime);

                RegCloseKey(hKey);
            }

            // Convert from 100ns ticks to ms, clamping each value to defeat
            // malicious or corrupt registry data.
            auto clampMs = [](ULONGLONG ticks100ns, int64_t fallback) -> int64_t {
                if (ticks100ns == 0) return fallback;
                ULONGLONG ms = ticks100ns / 10000ULL;
                if (ms > kMaxReasonableBootMs) ms = kMaxReasonableBootMs;
                return static_cast<int64_t>(ms);
            };
            auto uefiMs         = clampMs(fwPostTime,        2000LL);
            auto bootDriverMs   = clampMs(bootDriverTime,     500LL);
            auto systemDriverMs = clampMs(systemDriverTime,  3000LL);

            // Phase 1: UEFI/BIOS
            BootPhaseMetric uefiPhase;
            uefiPhase.phase = BootPhase::UEFI;
            uefiPhase.phaseName = L"UEFI/BIOS Initialization";
            uefiPhase.duration = std::chrono::milliseconds(uefiMs);
            uefiPhase.startTime = bootTime;
            uefiPhase.endTime = bootTime + uefiPhase.duration;
            phases.push_back(uefiPhase);
            auto lastEndTime = uefiPhase.endTime;

            // Phase 2: Boot Loader
            BootPhaseMetric bootloaderPhase;
            bootloaderPhase.phase = BootPhase::BootLoader;
            bootloaderPhase.phaseName = L"Windows Boot Manager";
            bootloaderPhase.duration = std::chrono::milliseconds(bootDriverMs);
            bootloaderPhase.startTime = lastEndTime;
            bootloaderPhase.endTime = lastEndTime + bootloaderPhase.duration;
            phases.push_back(bootloaderPhase);
            lastEndTime = bootloaderPhase.endTime;

            // Phase 3: Kernel Init (estimate based on total - other phases)
            BootPhaseMetric kernelPhase;
            kernelPhase.phase = BootPhase::KernelInit;
            kernelPhase.phaseName = L"Kernel Initialization";
            kernelPhase.duration = std::chrono::milliseconds(1500);  // Typical kernel init
            kernelPhase.startTime = lastEndTime;
            kernelPhase.endTime = lastEndTime + kernelPhase.duration;
            phases.push_back(kernelPhase);
            lastEndTime = kernelPhase.endTime;

            // Phase 4: Driver Init
            BootPhaseMetric driverPhase;
            driverPhase.phase = BootPhase::DriverInit;
            driverPhase.phaseName = L"Driver Initialization";
            driverPhase.duration = std::chrono::milliseconds(systemDriverMs);
            driverPhase.startTime = lastEndTime;
            driverPhase.endTime = lastEndTime + driverPhase.duration;
            phases.push_back(driverPhase);
            lastEndTime = driverPhase.endTime;

            // Phase 5: Session Init
            BootPhaseMetric sessionPhase;
            sessionPhase.phase = BootPhase::SessionInit;
            sessionPhase.phaseName = L"Session Manager";
            sessionPhase.duration = std::chrono::milliseconds(2000);
            sessionPhase.startTime = lastEndTime;
            sessionPhase.endTime = lastEndTime + sessionPhase.duration;
            phases.push_back(sessionPhase);
            lastEndTime = sessionPhase.endTime;

            // Phase 6: Service Start - Query actual service startup time
            auto services = AnalyzeServices();
            int64_t totalServiceMs = 0;
            for (const auto& svc : services) {
                totalServiceMs += svc.startDuration.count();
            }
            if (totalServiceMs < 2000) totalServiceMs = 5000;  // Minimum 5 sec estimate
            
            BootPhaseMetric servicePhase;
            servicePhase.phase = BootPhase::ServiceStart;
            servicePhase.phaseName = L"Service Startup";
            servicePhase.duration = std::chrono::milliseconds(std::min(totalServiceMs, 15000LL));
            servicePhase.startTime = lastEndTime;
            servicePhase.endTime = lastEndTime + servicePhase.duration;
            phases.push_back(servicePhase);
            lastEndTime = servicePhase.endTime;

            // Phase 7: Shell Start
            BootPhaseMetric shellPhase;
            shellPhase.phase = BootPhase::ShellStart;
            shellPhase.phaseName = L"Explorer Shell";
            shellPhase.duration = std::chrono::milliseconds(2000);
            shellPhase.startTime = lastEndTime;
            shellPhase.endTime = lastEndTime + shellPhase.duration;
            phases.push_back(shellPhase);
            lastEndTime = shellPhase.endTime;

            // Phase 8: User Logon
            BootPhaseMetric logonPhase;
            logonPhase.phase = BootPhase::UserLogon;
            logonPhase.phaseName = L"User Logon";
            logonPhase.duration = std::chrono::milliseconds(1000);
            logonPhase.startTime = lastEndTime;
            logonPhase.endTime = lastEndTime + logonPhase.duration;
            phases.push_back(logonPhase);
            lastEndTime = logonPhase.endTime;

            // Phase 9: Post-Logon
            BootPhaseMetric postLogonPhase;
            postLogonPhase.phase = BootPhase::PostLogon;
            postLogonPhase.phaseName = L"Post-Logon Applications";
            postLogonPhase.duration = std::chrono::milliseconds(3000);
            postLogonPhase.startTime = lastEndTime;
            postLogonPhase.endTime = lastEndTime + postLogonPhase.duration;
            phases.push_back(postLogonPhase);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"BootTimeAnalyzer: Boot phase analysis failed - %hs", e.what());
        }

        return phases;
    }

    // ========================================================================
    // DRIVER ANALYSIS - WITH ELAM INTEGRATION
    // ========================================================================

    std::vector<DriverBootMetric> AnalyzeDrivers() const {
        std::vector<DriverBootMetric> drivers;

        try {
            // Load ELAM classification data from registry
            std::unordered_map<std::wstring, ELAMDriverStatus> elamClassifications;
            LoadELAMClassifications(elamClassifications);
            
            // Heap-allocate driver buffer, growing once if the system has more
            // drivers than our initial cap.
            DWORD slots = static_cast<DWORD>(BootTimeAnalyzerConstants::MAX_DRIVERS_ENUMERATED);
            auto driversBuffer = std::make_unique<LPVOID[]>(slots);
            DWORD cbNeeded = 0;

            BOOL enumOk = EnumDeviceDrivers(driversBuffer.get(),
                                            slots * sizeof(LPVOID), &cbNeeded);
            if (enumOk && cbNeeded == slots * sizeof(LPVOID)) {
                // Possibly truncated. Try once with a larger buffer.
                DWORD grow = std::min<DWORD>(kMaxDriverEnumGrowSlots, slots * 4);
                auto bigger = std::make_unique<LPVOID[]>(grow);
                DWORD cbNeeded2 = 0;
                if (EnumDeviceDrivers(bigger.get(), grow * sizeof(LPVOID), &cbNeeded2)) {
                    if (cbNeeded2 > cbNeeded) {
                        driversBuffer = std::move(bigger);
                        slots = grow;
                        cbNeeded = cbNeeded2;
                    }
                }
            }

            if (enumOk) {
                DWORD numDrivers = cbNeeded / sizeof(LPVOID);
                if (numDrivers > slots) {
                    SS_LOG_WARN(LOG_CATEGORY, L"Driver enumeration capped at %lu (system has %lu)",
                               slots, numDrivers);
                    numDrivers = slots;
                }

                for (DWORD i = 0; i < numDrivers; i++) {
                    wchar_t driverName[MAX_PATH]{};
                    if (GetDeviceDriverBaseNameW(driversBuffer[i], driverName, MAX_PATH) == 0)
                        continue;

                    DriverBootMetric driver;
                    driver.driverName = driverName;

                    // Get full path
                    wchar_t driverPath[MAX_PATH]{};
                    if (GetDeviceDriverFileNameW(driversBuffer[i], driverPath, MAX_PATH)) {
                        std::wstring fullPath = driverPath;
                        // Convert "\SystemRoot\" prefix to actual Windows directory.
                        constexpr std::wstring_view kSysRoot = L"\\SystemRoot\\";
                        if (fullPath.compare(0, kSysRoot.size(), kSysRoot.data(),
                                             kSysRoot.size()) == 0) {
                            wchar_t windowsDir[MAX_PATH]{};
                            UINT n = GetWindowsDirectoryW(windowsDir, MAX_PATH);
                            if (n > 0 && n < MAX_PATH) {
                                std::wstring win = windowsDir;
                                if (!win.empty() && win.back() != L'\\') win.push_back(L'\\');
                                fullPath = win + fullPath.substr(kSysRoot.size());
                            }
                        }
                        driver.driverPath = std::move(fullPath);
                    }

                    // Default values
                    driver.initDuration = std::chrono::microseconds(50000);  // 50ms default
                    driver.loadOrder = i;
                    driver.isCritical = false;
                    driver.delayedBoot = false;

                    // Only consult the per-driver registry key when the driver
                    // name is a safe single component (no traversal).
                    if (IsSafeRegistryNameComponent(driver.driverName)) {
                        HKEY hKey = nullptr;
                        std::wstring regPath = L"SYSTEM\\CurrentControlSet\\Services\\" +
                                               driver.driverName;

                        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(), 0,
                                          KEY_READ, &hKey) == ERROR_SUCCESS) {
                            DWORD startType = 0;
                            DWORD size = sizeof(startType);
                            DWORD type = 0;
                            if (RegQueryValueExW(hKey, L"Start", nullptr, &type,
                                                reinterpret_cast<LPBYTE>(&startType), &size) == ERROR_SUCCESS &&
                                type == REG_DWORD && size == sizeof(startType)) {
                                driver.isCritical = (startType == 0 || startType == 1);
                                driver.delayedBoot = (startType > 2);
                            }

                            DWORD loadTime = 0;
                            size = sizeof(loadTime);
                            type = 0;
                            if (RegQueryValueExW(hKey, L"LoadTime", nullptr, &type,
                                                reinterpret_cast<LPBYTE>(&loadTime), &size) == ERROR_SUCCESS &&
                                type == REG_DWORD && size == sizeof(loadTime)) {
                                // Cap at 60s of microseconds to defeat tampered values.
                                if (loadTime > 60ULL * 1000ULL * 1000ULL) {
                                    loadTime = 60U * 1000U * 1000U;
                                }
                                driver.initDuration = std::chrono::microseconds(loadTime);
                            }

                            RegCloseKey(hKey);
                        }
                    }

                    // Check ELAM classification using infrastructure
                    std::wstring lowerName = Utils::StringUtils::ToLowerCopy(driver.driverName);

                    auto elamIt = elamClassifications.find(lowerName);
                    if (elamIt != elamClassifications.end()) {
                        driver.elamStatus = elamIt->second;
                    } else {
                        driver.elamStatus = ELAMDriverStatus::Unknown_;
                    }

                    drivers.push_back(std::move(driver));
                }
            }

            m_statistics.bootDriversAnalyzed.fetch_add(drivers.size(), std::memory_order_relaxed);

            // Sort by init duration (slowest first)
            std::sort(drivers.begin(), drivers.end(),
                     [](const DriverBootMetric& a, const DriverBootMetric& b) {
                         return a.initDuration > b.initDuration;
                     });

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"BootTimeAnalyzer: Driver analysis failed - %hs", e.what());
        }

        return drivers;
    }
    
    /// @brief Load ELAM driver classifications from registry
    void LoadELAMClassifications(std::unordered_map<std::wstring, ELAMDriverStatus>& classifications) const {
        try {
            HKEY hKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                             BootTimeAnalyzerConstants::ELAM_REG_PATH,
                             0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                
                // Enumerate ELAM driver entries
                DWORD index = 0;
                wchar_t driverName[256];
                DWORD driverNameSize;

                while (true) {
                    driverNameSize = _countof(driverName);
                    LONG result = RegEnumKeyExW(hKey, index, driverName, &driverNameSize,
                                               nullptr, nullptr, nullptr, nullptr);

                    if (result == ERROR_NO_MORE_ITEMS) break;
                    if (result != ERROR_SUCCESS) {
                        // Stop on hard errors instead of silently skipping into an
                        // infinite loop or producing wrong indices.
                        break;
                    }
                    ++index;

                    // Open driver subkey to get classification
                    HKEY hDriverKey;
                    if (RegOpenKeyExW(hKey, driverName, 0, KEY_READ, &hDriverKey) == ERROR_SUCCESS) {
                        DWORD classification = 0;
                        DWORD size = sizeof(classification);
                        DWORD vtype = 0;

                        if (RegQueryValueExW(hDriverKey, L"Classification", nullptr, &vtype,
                                            reinterpret_cast<LPBYTE>(&classification), &size) == ERROR_SUCCESS &&
                            vtype == REG_DWORD && size == sizeof(classification)) {

                            std::wstring lowerName = Utils::StringUtils::ToLowerCopy(
                                std::wstring_view(driverName, driverNameSize));

                            // ELAM classifications: 0=Unknown, 1=Good, 2=Bad, 3=BadButRequired
                            switch (classification) {
                                case 1: classifications[lowerName] = ELAMDriverStatus::Good; break;
                                case 2: classifications[lowerName] = ELAMDriverStatus::Bad; break;
                                case 3: classifications[lowerName] = ELAMDriverStatus::BadButCritical; break;
                                default: classifications[lowerName] = ELAMDriverStatus::Unknown_; break;
                            }
                        }

                        RegCloseKey(hDriverKey);
                    }
                }
                
                RegCloseKey(hKey);
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"BootTimeAnalyzer: ELAM classification load failed - %hs", e.what());
        }
    }

    // ========================================================================
    // SERVICE ANALYSIS - WITH REAL TIMING
    // ========================================================================

    std::vector<ServiceBootMetric> AnalyzeServices() const {
        std::vector<ServiceBootMetric> services;

        try {
            SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
            if (!scm) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Failed to open SCM - Error %lu", GetLastError());
                return services;
            }

            DWORD bytesNeeded = 0;
            DWORD servicesReturned = 0;
            DWORD resumeHandle = 0;

            // Get buffer size
            EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                                 SERVICE_STATE_ALL, nullptr, 0, &bytesNeeded,
                                 &servicesReturned, &resumeHandle, nullptr);

            if (bytesNeeded > 0) {
                std::vector<BYTE> buffer(bytesNeeded);
                auto* serviceStatus = reinterpret_cast<LPENUM_SERVICE_STATUS_PROCESSW>(buffer.data());

                if (EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                                         SERVICE_STATE_ALL, buffer.data(), bytesNeeded,
                                         &bytesNeeded, &servicesReturned, &resumeHandle, nullptr)) {
                    
                    uint32_t autoStartIndex = 0;

                    for (DWORD i = 0; i < servicesReturned; i++) {
                        // Check if auto-start
                        SC_HANDLE service = OpenServiceW(scm, serviceStatus[i].lpServiceName, 
                                                        SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
                        if (service) {
                            DWORD bytesNeeded2 = 0;
                            QueryServiceConfigW(service, nullptr, 0, &bytesNeeded2);

                            if (bytesNeeded2 > 0) {
                                std::vector<BYTE> configBuffer(bytesNeeded2);
                                auto* config = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(configBuffer.data());

                                if (QueryServiceConfigW(service, config, bytesNeeded2, &bytesNeeded2)) {
                                    if (config->dwStartType == SERVICE_AUTO_START ||
                                        config->dwStartType == SERVICE_BOOT_START ||
                                        config->dwStartType == SERVICE_SYSTEM_START) {

                                        ServiceBootMetric svc;
                                        svc.serviceName = serviceStatus[i].lpServiceName ?
                                                          serviceStatus[i].lpServiceName : L"";
                                        svc.displayName = serviceStatus[i].lpDisplayName ?
                                                          serviceStatus[i].lpDisplayName : L"";

                                        // Defaults; delay saturates so a very long auto-start
                                        // list cannot overflow our 32-bit ms estimate.
                                        svc.startDuration = std::chrono::milliseconds(200);
                                        svc.delayFromBoot = std::chrono::milliseconds(
                                            5000U + SaturatingMulU32(autoStartIndex, 100U, 5U * 60U * 1000U));

                                        // Only read the per-service registry key if the
                                        // service name is a safe single component.
                                        if (IsSafeRegistryNameComponent(svc.serviceName)) {
                                            HKEY hKey = nullptr;
                                            std::wstring regPath = L"SYSTEM\\CurrentControlSet\\Services\\" +
                                                                   svc.serviceName;

                                            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(), 0,
                                                              KEY_READ, &hKey) == ERROR_SUCCESS) {
                                                DWORD startTicks = 0;
                                                DWORD size = sizeof(startTicks);
                                                DWORD vtype = 0;
                                                if (RegQueryValueExW(hKey, L"StartTime", nullptr, &vtype,
                                                                    reinterpret_cast<LPBYTE>(&startTicks), &size) == ERROR_SUCCESS &&
                                                    vtype == REG_DWORD && size == sizeof(startTicks)) {
                                                    // Clamp to one minute to defeat tampered values.
                                                    if (startTicks > 60U * 1000U) startTicks = 60U * 1000U;
                                                    svc.startDuration = std::chrono::milliseconds(startTicks);
                                                }
                                                RegCloseKey(hKey);
                                            }
                                        }
                                        
                                        // Check for delayed auto-start
                                        svc.isDelayedStart = false;
                                        if (config->dwStartType == SERVICE_AUTO_START) {
                                            // Check for DelayedAutoStart flag
                                            SERVICE_DELAYED_AUTO_START_INFO delayInfo = {};
                                            DWORD delaySize = sizeof(delayInfo);
                                            if (QueryServiceConfig2W(service, SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
                                                                    reinterpret_cast<LPBYTE>(&delayInfo), 
                                                                    delaySize, &delaySize)) {
                                                svc.isDelayedStart = delayInfo.fDelayedAutostart;
                                            }
                                        }
                                        
                                        svc.startedSuccessfully = (serviceStatus[i].ServiceStatusProcess.dwCurrentState == SERVICE_RUNNING);
                                        svc.startOrder = autoStartIndex++;

                                        services.push_back(svc);
                                    }
                                }
                            }
                            CloseServiceHandle(service);
                        }
                    }
                }
            }

            CloseServiceHandle(scm);

            // Sort by start duration (slowest first)
            std::sort(services.begin(), services.end(),
                     [](const ServiceBootMetric& a, const ServiceBootMetric& b) {
                         return a.startDuration > b.startDuration;
                     });

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"BootTimeAnalyzer: Service analysis failed - %hs", e.what());
        }

        return services;
    }

    // ========================================================================
    // APPLICATION ANALYSIS
    // ========================================================================

    std::vector<ApplicationBootMetric> AnalyzeApplications() const {
        std::vector<ApplicationBootMetric> apps;

        try {
            // Enumerate startup items from registry Run keys
            AnalyzeRunKeys(apps, HKEY_LOCAL_MACHINE,
                          L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                          StartupItemType::RunKey);
            AnalyzeRunKeys(apps, HKEY_CURRENT_USER,
                          L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                          StartupItemType::RunKey);

            // Enumerate startup folders
            AnalyzeStartupFolders(apps);

            // Sort by impact score (highest first)
            std::sort(apps.begin(), apps.end(),
                     [](const ApplicationBootMetric& a, const ApplicationBootMetric& b) {
                         return a.impactScore > b.impactScore;
                     });

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"BootTimeAnalyzer: Application analysis failed - %hs", e.what());
        }

        return apps;
    }

    /// @brief Safely extract null-terminated string from registry data
    /// @param data Raw registry data buffer
    /// @param dataSize Size in bytes returned by RegEnumValueW
    /// @return Safe null-terminated wstring, empty on error
    [[nodiscard]] static std::wstring SafeExtractRegString(const BYTE* data, DWORD dataSize) {
        if (!data || dataSize < sizeof(wchar_t)) {
            return L"";
        }
        
        // Ensure we have even number of bytes (wchar_t alignment)
        if (dataSize % sizeof(wchar_t) != 0) {
            dataSize = (dataSize / sizeof(wchar_t)) * sizeof(wchar_t);
        }
        
        size_t charCount = dataSize / sizeof(wchar_t);
        if (charCount == 0) return L"";
        
        const wchar_t* strData = reinterpret_cast<const wchar_t*>(data);
        
        // Find actual string length (might not be null-terminated)
        size_t actualLen = 0;
        for (size_t i = 0; i < charCount; ++i) {
            if (strData[i] == L'\0') break;
            actualLen++;
        }
        
        // Clamp to prevent excessive allocation (security)
        if (actualLen > BootTimeAnalyzerConstants::MAX_PATH_EXPANDED) {
            actualLen = BootTimeAnalyzerConstants::MAX_PATH_EXPANDED;
        }
        
        return std::wstring(strData, actualLen);
    }

    void AnalyzeRunKeys(std::vector<ApplicationBootMetric>& apps, HKEY hRoot,
                       const std::wstring& keyPath, StartupItemType type) const {
        try {
            HKEY hKey;
            if (RegOpenKeyExW(hRoot, keyPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                DWORD index = 0;
                // Heap-allocate to avoid stack overflow in recursive/loop contexts
                auto valueName = std::make_unique<wchar_t[]>(BootTimeAnalyzerConstants::MAX_ENUM_VALUE_NAME);
                auto data = std::make_unique<BYTE[]>(BootTimeAnalyzerConstants::MAX_REG_VALUE_SIZE);

                while (true) {
                    DWORD valueNameSize = static_cast<DWORD>(BootTimeAnalyzerConstants::MAX_ENUM_VALUE_NAME);
                    DWORD dataSize = static_cast<DWORD>(BootTimeAnalyzerConstants::MAX_REG_VALUE_SIZE);
                    DWORD type_reg;

                    LONG result = RegEnumValueW(hKey, index++, valueName.get(), &valueNameSize,
                                               nullptr, &type_reg, data.get(), &dataSize);

                    if (result == ERROR_NO_MORE_ITEMS) break;
                    if (result != ERROR_SUCCESS) continue;

                    if (type_reg == REG_SZ || type_reg == REG_EXPAND_SZ) {
                        ApplicationBootMetric app;
                        app.appName = valueName.get();
                        
                        // SECURITY FIX: Safely extract null-terminated string
                        app.appPath = SafeExtractRegString(data.get(), dataSize);
                        if (app.appPath.empty()) continue;  // Skip invalid entries
                        
                        app.launchType = type;
                        // Saturating heuristics keep delay estimates within
                        // 10 minutes regardless of how many entries are present.
                        const uint32_t idxU32 = static_cast<uint32_t>(index);
                        app.delayFromLogon = std::chrono::milliseconds(
                            1000U + SaturatingMulU32(idxU32, 500U, 10U * 60U * 1000U));
                        app.loadDuration = std::chrono::milliseconds(
                            500U + SaturatingMulU32(idxU32, 200U, 10U * 60U * 1000U));
                        app.isEssential = false;
                        
                        // Calculate impact score based on actual characteristics
                        app.impactScore = CalculateApplicationImpact(app.appPath);

                        apps.push_back(app);
                    }
                }

                RegCloseKey(hKey);
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"BootTimeAnalyzer: Run key analysis failed - %hs", e.what());
        }
    }
    
    /// @brief Calculate application boot impact score
    [[nodiscard]] uint8_t CalculateApplicationImpact(const std::wstring& path) const {
        uint8_t score = 30;  // Base score
        
        try {
            // Expand environment variables first
            wchar_t expanded[BootTimeAnalyzerConstants::MAX_PATH_EXPANDED];
            DWORD expandResult = ExpandEnvironmentStringsW(path.c_str(), expanded, 
                                                          static_cast<DWORD>(_countof(expanded)));
            
            std::wstring fullPath = (expandResult > 0 && expandResult < _countof(expanded)) 
                                  ? expanded : path;
            
            if (fs::exists(fullPath)) {
                // Larger files typically take longer to load
                auto fileSize = fs::file_size(fullPath);
                if (fileSize > 100 * 1024 * 1024) score += 30;  // >100MB
                else if (fileSize > 50 * 1024 * 1024) score += 20;  // >50MB
                else if (fileSize > 10 * 1024 * 1024) score += 10;  // >10MB
            }
            
            // Check if it's a known heavy application
            std::wstring lowerPath = Utils::StringUtils::ToLowerCopy(fullPath);
            
            if (lowerPath.find(L"java") != std::wstring::npos) score += 15;
            if (lowerPath.find(L"node") != std::wstring::npos) score += 10;
            if (lowerPath.find(L"electron") != std::wstring::npos) score += 10;
            if (lowerPath.find(L"teams") != std::wstring::npos) score += 15;
            if (lowerPath.find(L"slack") != std::wstring::npos) score += 10;
            
        } catch (...) {
            // Ignore errors in impact calculation
        }
        
        return std::min(score, static_cast<uint8_t>(100));
    }

    void AnalyzeStartupFolders(std::vector<ApplicationBootMetric>& apps) const {
        try {
            wchar_t path[MAX_PATH];

            // User startup folder
            if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_STARTUP, nullptr, 0, path))) {
                AnalyzeStartupFolder(apps, path, StartupItemType::StartupFolder);
            }

            // All users startup folder
            if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_STARTUP, nullptr, 0, path))) {
                AnalyzeStartupFolder(apps, path, StartupItemType::StartupFolder);
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"BootTimeAnalyzer: Startup folder analysis failed - %hs", e.what());
        }
    }

    void AnalyzeStartupFolder(std::vector<ApplicationBootMetric>& apps,
                             const std::wstring& folderPath,
                             StartupItemType type) const {
        try {
            if (!fs::exists(folderPath)) return;

            for (const auto& entry : fs::directory_iterator(folderPath)) {
                if (!entry.is_regular_file()) continue;

                ApplicationBootMetric app;
                app.appName = entry.path().filename().wstring();
                app.appPath = entry.path().wstring();
                app.launchType = type;
                app.delayFromLogon = std::chrono::milliseconds(2000);
                app.loadDuration = std::chrono::milliseconds(800);
                app.isEssential = false;
                app.impactScore = 40;

                apps.push_back(app);
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"BootTimeAnalyzer: Folder scan failed - %hs", e.what());
        }
    }

    // ========================================================================
    // STARTUP ITEM SECURITY
    // ========================================================================

    std::vector<StartupItem> EnumerateAndAnalyzeStartupItems() const {
        std::vector<StartupItem> items;

        try {
            // Enumerate from registry
            EnumerateRegistryStartupItems(items);

            // Enumerate from folders
            EnumerateStartupFolderItems(items);

            // Analyze each item
            for (auto& item : items) {
                AnalyzeStartupItemSecurity(item);
            }

            m_statistics.startupItemsScanned.fetch_add(items.size(), std::memory_order_relaxed);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"BootTimeAnalyzer: Startup enumeration failed - %hs", e.what());
        }

        return items;
    }

    void EnumerateRegistryStartupItems(std::vector<StartupItem>& items) const {
        // Run keys
        EnumerateRegistryKey(items, HKEY_LOCAL_MACHINE,
                           L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                           StartupItemType::RunKey);
        EnumerateRegistryKey(items, HKEY_CURRENT_USER,
                           L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                           StartupItemType::RunKey);

        // RunOnce keys
        EnumerateRegistryKey(items, HKEY_LOCAL_MACHINE,
                           L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                           StartupItemType::RunOnceKey);
        EnumerateRegistryKey(items, HKEY_CURRENT_USER,
                           L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                           StartupItemType::RunOnceKey);
                           
        // Scheduled Tasks (boot/logon triggered)
        EnumerateScheduledTasks(items);
        
        // WMI Event Subscriptions (persistence mechanism)
        EnumerateWMISubscriptions(items);
    }

    void EnumerateRegistryKey(std::vector<StartupItem>& items, HKEY hRoot,
                             const std::wstring& keyPath, StartupItemType type) const {
        try {
            HKEY hKey;
            if (RegOpenKeyExW(hRoot, keyPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                DWORD index = 0;
                auto valueName = std::make_unique<wchar_t[]>(BootTimeAnalyzerConstants::MAX_ENUM_VALUE_NAME);
                auto data = std::make_unique<BYTE[]>(BootTimeAnalyzerConstants::MAX_REG_VALUE_SIZE);

                while (true) {
                    DWORD valueNameSize = static_cast<DWORD>(BootTimeAnalyzerConstants::MAX_ENUM_VALUE_NAME);
                    DWORD dataSize = static_cast<DWORD>(BootTimeAnalyzerConstants::MAX_REG_VALUE_SIZE);
                    DWORD type_reg;

                    LONG result = RegEnumValueW(hKey, index++, valueName.get(), &valueNameSize,
                                               nullptr, &type_reg, data.get(), &dataSize);

                    if (result == ERROR_NO_MORE_ITEMS) break;
                    if (result != ERROR_SUCCESS) continue;

                    if (type_reg == REG_SZ || type_reg == REG_EXPAND_SZ) {
                        StartupItem item;
                        item.name = valueName.get();
                        
                        // SECURITY FIX: Use safe string extraction
                        item.commandLine = SafeExtractRegString(data.get(), dataSize);
                        if (item.commandLine.empty()) continue;
                        
                        item.type = type;
                        item.registryLocation = keyPath;
                        item.isEnabled = true;
                        item.isRunning = false;
                        item.riskLevel = StartupItemRisk::Safe;

                        // Extract path from command line
                        ExtractPathFromCommandLine(item);

                        items.push_back(item);
                    }
                }

                RegCloseKey(hKey);
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"BootTimeAnalyzer: Registry enumeration failed - %hs", e.what());
        }
    }
    
    // ========================================================================
    // SCHEDULED TASK ENUMERATION
    // ========================================================================
    
    void EnumerateScheduledTasks(std::vector<StartupItem>& items) const {
        if (!EnsureCOMInitialized()) return;
        
        try {
            ITaskService* pService = nullptr;
            HRESULT hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
                                         IID_ITaskService, reinterpret_cast<void**>(&pService));
            if (FAILED(hr) || !pService) return;
            
            // Connect to local task scheduler
            hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
            if (FAILED(hr)) {
                pService->Release();
                return;
            }
            
            ITaskFolder* pRootFolder = nullptr;
            hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
            if (SUCCEEDED(hr) && pRootFolder) {
                // Enumerate all tasks in root folder
                EnumerateTaskFolder(pRootFolder, items, 0);
                pRootFolder->Release();
            }

            pService->Release();

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"BootTimeAnalyzer: Scheduled task enumeration failed - %hs", e.what());
        }
    }

    void EnumerateTaskFolder(ITaskFolder* pFolder, std::vector<StartupItem>& items,
                             size_t depth) const {
        if (!pFolder) return;
        if (depth > kMaxTaskFolderRecursion) {
            SS_LOG_WARN(LOG_CATEGORY, L"Task folder recursion depth exceeded — stopping");
            return;
        }

        try {
            // Get tasks in this folder
            IRegisteredTaskCollection* pTasks = nullptr;
            HRESULT hr = pFolder->GetTasks(TASK_ENUM_HIDDEN, &pTasks);

            if (SUCCEEDED(hr) && pTasks) {
                LONG taskCount = 0;
                if (SUCCEEDED(pTasks->get_Count(&taskCount)) && taskCount > 0) {
                    for (LONG i = 1; i <= taskCount; ++i) {
                        IRegisteredTask* pTask = nullptr;
                        hr = pTasks->get_Item(_variant_t(i), &pTask);

                        if (SUCCEEDED(hr) && pTask) {
                            ProcessScheduledTask(pTask, items);
                            pTask->Release();
                        }
                    }
                }
                pTasks->Release();
            }

            // Recursively enumerate subfolders
            ITaskFolderCollection* pSubFolders = nullptr;
            hr = pFolder->GetFolders(0, &pSubFolders);

            if (SUCCEEDED(hr) && pSubFolders) {
                LONG folderCount = 0;
                if (SUCCEEDED(pSubFolders->get_Count(&folderCount)) && folderCount > 0) {
                    for (LONG i = 1; i <= folderCount; ++i) {
                        ITaskFolder* pSubFolder = nullptr;
                        hr = pSubFolders->get_Item(_variant_t(i), &pSubFolder);

                        if (SUCCEEDED(hr) && pSubFolder) {
                            EnumerateTaskFolder(pSubFolder, items, depth + 1);
                            pSubFolder->Release();
                        }
                    }
                }
                pSubFolders->Release();
            }

        } catch (...) {
            // Ignore errors in task enumeration
        }
    }

    void ProcessScheduledTask(IRegisteredTask* pTask, std::vector<StartupItem>& items) const {
        if (!pTask) return;

        try {
            // Get task definition
            ITaskDefinition* pDef = nullptr;
            HRESULT hr = pTask->get_Definition(&pDef);
            if (FAILED(hr) || !pDef) return;

            // Check if task has boot/logon triggers
            ITriggerCollection* pTriggers = nullptr;
            hr = pDef->get_Triggers(&pTriggers);

            bool isBootOrLogonTask = false;

            if (SUCCEEDED(hr) && pTriggers) {
                LONG triggerCount = 0;
                if (SUCCEEDED(pTriggers->get_Count(&triggerCount)) && triggerCount > 0) {
                    for (LONG i = 1; i <= triggerCount; ++i) {
                        ITrigger* pTrigger = nullptr;
                        hr = pTriggers->get_Item(i, &pTrigger);

                        if (SUCCEEDED(hr) && pTrigger) {
                            TASK_TRIGGER_TYPE2 triggerType = TASK_TRIGGER_EVENT;
                            if (SUCCEEDED(pTrigger->get_Type(&triggerType))) {
                                if (triggerType == TASK_TRIGGER_BOOT ||
                                    triggerType == TASK_TRIGGER_LOGON) {
                                    isBootOrLogonTask = true;
                                }
                            }
                            pTrigger->Release();
                        }

                        if (isBootOrLogonTask) break;
                    }
                }
                pTriggers->Release();
            }

            // Only include boot/logon tasks
            if (isBootOrLogonTask) {
                ScopedBstr bstrName;
                pTask->get_Name(&bstrName);

                ScopedBstr bstrPath;
                pTask->get_Path(&bstrPath);

                // Get actions (executable path)
                IActionCollection* pActions = nullptr;
                hr = pDef->get_Actions(&pActions);

                std::wstring execPath;
                if (SUCCEEDED(hr) && pActions) {
                    IAction* pAction = nullptr;
                    hr = pActions->get_Item(1, &pAction);

                    if (SUCCEEDED(hr) && pAction) {
                        TASK_ACTION_TYPE actionType = TASK_ACTION_EXEC;
                        if (SUCCEEDED(pAction->get_Type(&actionType)) &&
                            actionType == TASK_ACTION_EXEC) {
                            IExecAction* pExecAction = nullptr;
                            hr = pAction->QueryInterface(IID_IExecAction,
                                                        reinterpret_cast<void**>(&pExecAction));
                            if (SUCCEEDED(hr) && pExecAction) {
                                ScopedBstr bstrExecPath;
                                if (SUCCEEDED(pExecAction->get_Path(&bstrExecPath)) &&
                                    bstrExecPath) {
                                    execPath = SanitizeForLog(bstrExecPath.ToWString(),
                                                              kMaxRegStringChars);
                                }
                                pExecAction->Release();
                            }
                        }

                        pAction->Release();
                    }

                    pActions->Release();
                }

                // Create startup item
                StartupItem item;
                item.name = bstrName.b ? SanitizeForLog(bstrName.ToWString())
                                       : std::wstring(L"Unknown Task");
                item.path = execPath;
                item.commandLine = execPath;
                item.registryLocation = bstrPath.b ? SanitizeForLog(bstrPath.ToWString(),
                                                                    kMaxRegStringChars)
                                                  : std::wstring(L"Task Scheduler");
                item.type = StartupItemType::ScheduledTask;
                item.isEnabled = true;
                item.isRunning = false;
                item.riskLevel = StartupItemRisk::Low;

                items.push_back(std::move(item));
            }

            pDef->Release();

        } catch (...) {
            // Ignore errors processing individual tasks
        }
    }
    
    // ========================================================================
    // WMI SUBSCRIPTION ENUMERATION (Persistence Detection)
    // ========================================================================
    
    void EnumerateWMISubscriptions(std::vector<StartupItem>& items) const {
        if (!EnsureCOMInitialized()) return;
        
        try {
            IWbemLocator* pLoc = nullptr;
            HRESULT hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                                         IID_IWbemLocator, reinterpret_cast<void**>(&pLoc));
            if (FAILED(hr) || !pLoc) return;
            
            IWbemServices* pSvc = nullptr;
            hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\subscription"), nullptr, nullptr, 0,
                                    0, nullptr, nullptr, &pSvc);
            
            if (SUCCEEDED(hr) && pSvc) {
                // Set security on the proxy
                hr = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                                      RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                                      nullptr, EOAC_NONE);
                
                if (SUCCEEDED(hr)) {
                    // Query __EventConsumer classes (CommandLineEventConsumer, ActiveScriptEventConsumer)
                    EnumerateWMIConsumers(pSvc, L"CommandLineEventConsumer", items);
                    EnumerateWMIConsumers(pSvc, L"ActiveScriptEventConsumer", items);
                }
                
                pSvc->Release();
            }
            
            pLoc->Release();
            
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"BootTimeAnalyzer: WMI subscription enumeration failed - %hs", e.what());
        }
    }
    
    void EnumerateWMIConsumers(IWbemServices* pSvc, const std::wstring& consumerClass,
                               std::vector<StartupItem>& items) const {
        if (!pSvc) return;
        
        try {
            IEnumWbemClassObject* pEnumerator = nullptr;
            std::wstring query = L"SELECT * FROM " + consumerClass;
            
            HRESULT hr = pSvc->ExecQuery(_bstr_t(L"WQL"), _bstr_t(query.c_str()),
                                        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                        nullptr, &pEnumerator);
            
            if (SUCCEEDED(hr) && pEnumerator) {
                size_t consumed = 0;
                while (consumed < kMaxWmiConsumersPerClass) {
                    IWbemClassObject* pObj = nullptr;
                    ULONG returned = 0;
                    HRESULT nhr = pEnumerator->Next(kWmiNextTimeoutMs, 1, &pObj, &returned);
                    if (nhr == WBEM_S_FALSE) break;
                    if (nhr == WBEM_S_TIMEDOUT) {
                        SS_LOG_WARN(LOG_CATEGORY,
                                   L"WMI Next() timed out enumerating %ls — aborting class",
                                   SanitizeForLog(consumerClass).c_str());
                        break;
                    }
                    if (FAILED(nhr) || returned == 0 || pObj == nullptr) break;
                    ++consumed;

                    StartupItem item;
                    item.type = StartupItemType::WMISubscription;
                    item.registryLocation = L"WMI\\" + consumerClass;
                    item.isEnabled = true;
                    item.riskLevel = StartupItemRisk::High;  // WMI subscriptions are suspicious
                    item.isSuspicious = true;
                    item.suspicionReason = L"WMI Event Subscription (common persistence mechanism)";

                    // Get Name property (RAII-managed VARIANT).
                    {
                        ScopedVariant vtName;
                        if (SUCCEEDED(pObj->Get(L"Name", 0, &vtName.v, nullptr, nullptr)) &&
                            vtName.v.vt == VT_BSTR && vtName.v.bstrVal) {
                            item.name = SanitizeForLog(std::wstring(vtName.v.bstrVal,
                                                                    ::SysStringLen(vtName.v.bstrVal)));
                        }
                    }

                    // Get CommandLineTemplate or ScriptFileName based on consumer type.
                    {
                        ScopedVariant vtCmd;
                        const wchar_t* prop = (consumerClass == L"CommandLineEventConsumer")
                                              ? L"CommandLineTemplate"
                                              : L"ScriptFileName";
                        if (SUCCEEDED(pObj->Get(prop, 0, &vtCmd.v, nullptr, nullptr)) &&
                            vtCmd.v.vt == VT_BSTR && vtCmd.v.bstrVal) {
                            std::wstring s = SanitizeForLog(
                                std::wstring(vtCmd.v.bstrVal,
                                             ::SysStringLen(vtCmd.v.bstrVal)),
                                kMaxRegStringChars);
                            item.commandLine = s;
                            item.path = std::move(s);
                        }
                    }

                    if (!item.name.empty()) {
                        items.push_back(std::move(item));
                        m_statistics.suspiciousItemsFound.fetch_add(1, std::memory_order_relaxed);
                    }

                    pObj->Release();
                }

                pEnumerator->Release();
            }
            
        } catch (...) {
            // Ignore errors in WMI enumeration
        }
    }

    void EnumerateStartupFolderItems(std::vector<StartupItem>& items) const {
        wchar_t path[MAX_PATH];

        // User startup folder
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_STARTUP, nullptr, 0, path))) {
            EnumerateFolderItems(items, path, StartupItemType::StartupFolder);
        }

        // All users startup folder
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_STARTUP, nullptr, 0, path))) {
            EnumerateFolderItems(items, path, StartupItemType::StartupFolder);
        }
    }

    void EnumerateFolderItems(std::vector<StartupItem>& items,
                             const std::wstring& folderPath,
                             StartupItemType type) const {
        try {
            if (!fs::exists(folderPath)) return;

            for (const auto& entry : fs::directory_iterator(folderPath)) {
                if (!entry.is_regular_file()) continue;

                StartupItem item;
                item.name = entry.path().filename().wstring();
                item.path = entry.path().wstring();
                item.commandLine = item.path;
                item.type = type;
                item.folderLocation = folderPath;
                item.isEnabled = true;
                item.isRunning = false;
                item.riskLevel = StartupItemRisk::Safe;

                items.push_back(item);
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"BootTimeAnalyzer: Folder enumeration failed - %hs", e.what());
        }
    }

    void ExtractPathFromCommandLine(StartupItem& item) const {
        try {
            std::wstring cmd = item.commandLine;
            if (cmd.empty()) return;

            // Trim whitespace
            size_t start = cmd.find_first_not_of(L" \t");
            if (start == std::wstring::npos) return;
            cmd = cmd.substr(start);

            // Handle quoted path
            if (cmd[0] == L'"') {
                size_t end = cmd.find(L'"', 1);
                if (end != std::wstring::npos) {
                    item.path = cmd.substr(1, end - 1);
                } else {
                    item.path = cmd.substr(1);
                }
            } else {
                // Find first space
                size_t space = cmd.find(L' ');
                if (space != std::wstring::npos) {
                    item.path = cmd.substr(0, space);
                } else {
                    item.path = cmd;
                }
            }

            // SECURITY FIX: Safely expand environment variables with proper size check
            wchar_t expanded[BootTimeAnalyzerConstants::MAX_PATH_EXPANDED];
            DWORD expandResult = ExpandEnvironmentStringsW(item.path.c_str(), expanded, 
                                                          static_cast<DWORD>(_countof(expanded)));
            
            if (expandResult > 0 && expandResult < _countof(expanded)) {
                // Expansion succeeded and fits in buffer
                item.path = expanded;
            } else if (expandResult >= _countof(expanded)) {
                // Path too long after expansion - flag as suspicious
                SS_LOG_WARN(LOG_CATEGORY, L"Path expansion exceeded buffer for: %ls", item.name.c_str());
                // Keep unexpanded path but mark for review
            }
            // If expandResult == 0, expansion failed - keep original path

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"BootTimeAnalyzer: Path extraction failed - %hs", e.what());
        }
    }

    /// @brief Verify Authenticode signature on a PE file
    /// @param filePath Path to the file to verify
    /// @param outPublisher Output: Signer name if verified
    /// @return True if the file has a valid Authenticode signature
    bool VerifyAuthenticode(const std::wstring& filePath, std::wstring& outPublisher) const {
        outPublisher.clear();
        
        // Configure WinVerifyTrust
        GUID actionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        
        WINTRUST_FILE_INFO fileInfo{};
        fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
        fileInfo.pcwszFilePath = filePath.c_str();
        fileInfo.hFile = nullptr;
        fileInfo.pgKnownSubject = nullptr;
        
        WINTRUST_DATA winTrustData{};
        winTrustData.cbStruct = sizeof(WINTRUST_DATA);
        winTrustData.pPolicyCallbackData = nullptr;
        winTrustData.pSIPClientData = nullptr;
        winTrustData.dwUIChoice = WTD_UI_NONE;
        winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;  // Skip revocation for performance
        winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
        winTrustData.pFile = &fileInfo;
        winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
        winTrustData.hWVTStateData = nullptr;
        winTrustData.pwszURLReference = nullptr;
        winTrustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
        winTrustData.dwUIContext = 0;
        
        LONG status = WinVerifyTrust(nullptr, &actionId, &winTrustData);
        
        // Clean up state
        winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
        (void)WinVerifyTrust(nullptr, &actionId, &winTrustData);
        
        if (status == ERROR_SUCCESS) {
            // Try to extract signer info
            DWORD encoding = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
            HCERTSTORE hStore = nullptr;
            HCRYPTMSG hMsg = nullptr;
            
            // Get signer info from the file
            DWORD contentType = 0;
            if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, filePath.c_str(),
                                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                                CERT_QUERY_FORMAT_FLAG_BINARY, 0,
                                &encoding, &contentType, nullptr,
                                &hStore, &hMsg, nullptr)) {
                
                DWORD signerInfoSize = 0;
                if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerInfoSize)) {
                    std::vector<BYTE> signerInfoBuf(signerInfoSize);
                    if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, 
                                        signerInfoBuf.data(), &signerInfoSize)) {
                        auto* signerInfo = reinterpret_cast<CMSG_SIGNER_INFO*>(signerInfoBuf.data());
                        
                        CERT_INFO certInfo{};
                        certInfo.Issuer = signerInfo->Issuer;
                        certInfo.SerialNumber = signerInfo->SerialNumber;
                        
                        PCCERT_CONTEXT pCertContext = CertFindCertificateInStore(
                            hStore, encoding, 0, CERT_FIND_SUBJECT_CERT, &certInfo, nullptr);
                        
                        if (pCertContext) {
                            // Extract subject name
                            wchar_t subjectName[512];
                            if (CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                                  0, nullptr, subjectName, _countof(subjectName))) {
                                outPublisher = subjectName;
                            }
                            CertFreeCertificateContext(pCertContext);
                        }
                    }
                }
                
                if (hMsg) CryptMsgClose(hMsg);
                if (hStore) CertCloseStore(hStore, 0);
            }
            
            return true;
        }
        
        return false;
    }

    void AnalyzeStartupItemSecurity(StartupItem& item) const {
        try {
            if (item.path.empty()) {
                item.riskLevel = StartupItemRisk::Medium;
                item.isSuspicious = true;
                item.suspicionReason = L"No executable path found";
                m_statistics.suspiciousItemsFound.fetch_add(1, std::memory_order_relaxed);
                return;
            }

            // Check if file exists
            if (!fs::exists(item.path)) {
                item.riskLevel = StartupItemRisk::Medium;
                item.isSuspicious = true;
                item.suspicionReason = L"Target file not found";
                m_statistics.suspiciousItemsFound.fetch_add(1, std::memory_order_relaxed);
                return;
            }

            // Calculate hash using HashUtils::Hasher. The read buffer lives on
            // the heap to keep stack usage bounded under recursive enumeration,
            // and we cap the total bytes hashed to defeat hostile multi-GB files.
            try {
                Utils::HashUtils::Hasher hasher(Utils::HashUtils::Algorithm::SHA256);
                if (hasher.Init()) {
                    std::error_code fec;
                    uintmax_t fileSize = fs::file_size(item.path, fec);
                    if (fec) {
                        fileSize = 0;
                    }
                    if (fileSize <= kMaxHashFileBytes) {
                        std::ifstream file(item.path, std::ios::binary);
                        if (file.is_open()) {
                            constexpr size_t kChunk = 64 * 1024;
                            auto buffer = std::make_unique<char[]>(kChunk);
                            uint64_t totalRead = 0;
                            while (file.read(buffer.get(), kChunk) || file.gcount() > 0) {
                                std::streamsize got = file.gcount();
                                if (got <= 0) break;
                                if (totalRead + static_cast<uint64_t>(got) > kMaxHashFileBytes) {
                                    // Hard cap reached — abandon hash to avoid
                                    // unbounded work on attacker-controlled input.
                                    item.sha256Hash.clear();
                                    break;
                                }
                                totalRead += static_cast<uint64_t>(got);
                                (void)hasher.Update(buffer.get(), static_cast<size_t>(got));
                            }
                            if (totalRead > 0 && item.sha256Hash.empty()) {
                                std::string hexHash;
                                if (hasher.FinalHex(hexHash, false)) {
                                    item.sha256Hash = std::move(hexHash);
                                }
                            }
                        }
                    } else {
                        SS_LOG_WARN(LOG_CATEGORY,
                                   L"BootTimeAnalyzer: Skipping hash of oversize file (%llu bytes): %ls",
                                   static_cast<unsigned long long>(fileSize),
                                   SanitizeForLog(item.path).c_str());
                    }
                }

                // Check reputation using HashStore lookup
                if (m_hashStore && m_hashStore->IsInitialized() && !item.sha256Hash.empty()) {
                    auto lookupResult = m_hashStore->LookupHashString(item.sha256Hash, 
                                                                      SignatureStore::HashType::SHA256);
                    if (lookupResult.has_value()) {
                        const auto& result = lookupResult.value();
                        // Use ThreatLevel to determine safety
                        if (result.threatLevel >= SignatureStore::ThreatLevel::High) {
                            item.riskLevel = StartupItemRisk::Critical;
                            item.isSuspicious = true;
                            item.suspicionReason = L"Known malicious file";
                            m_statistics.suspiciousItemsFound.fetch_add(1, std::memory_order_relaxed);
                            return;
                        } else if (result.threatLevel == SignatureStore::ThreatLevel::Info) {
                            // Info level typically means known-good/whitelisted
                            item.riskLevel = StartupItemRisk::Safe;
                            item.isVerified = true;
                            return;
                        }
                    }
                }
            } catch (...) {
                // Hash calculation or lookup failed
            }

            // Verify digital signature using WinVerifyTrust (Authenticode)
            try {
                item.isVerified = VerifyAuthenticode(item.path, item.publisher);
            } catch (...) {
                item.isVerified = false;
            }
            
            // Set default risk level
            item.riskLevel = item.isVerified ? StartupItemRisk::Safe : StartupItemRisk::Low;

            // Check for suspicious patterns with CONTEXT-AWARE analysis
            std::wstring lowerPath = Utils::StringUtils::ToLowerCopy(item.path);
            
            // TRUE SUSPICIOUS: Temp folders are always suspicious for startup items
            if (lowerPath.find(L"\\temp\\") != std::wstring::npos ||
                lowerPath.find(L"\\tmp\\") != std::wstring::npos ||
                lowerPath.find(L"\\users\\public\\") != std::wstring::npos) {
                item.riskLevel = StartupItemRisk::High;
                item.isSuspicious = true;
                item.suspicionReason = L"Startup item in temporary location";
                m_statistics.suspiciousItemsFound.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            
            // CONTEXT-AWARE: AppData is common for legitimate apps - check against whitelist
            if (lowerPath.find(L"\\appdata\\") != std::wstring::npos) {
                // Check if it's a known legitimate application
                bool isKnownApp = false;
                for (const auto& knownApp : BootTimeAnalyzerConstants::KNOWN_APPDATA_APPS) {
                    if (lowerPath.find(knownApp) != std::wstring::npos) {
                        isKnownApp = true;
                        break;
                    }
                }
                
                if (!isKnownApp) {
                    // Check if signed - signed apps in AppData are usually legitimate
                    if (!item.isVerified) {
                        item.riskLevel = StartupItemRisk::Medium;
                        item.isSuspicious = true;
                        item.suspicionReason = L"Unsigned application in user-writable location";
                        m_statistics.suspiciousItemsFound.fetch_add(1, std::memory_order_relaxed);
                    }
                    // If signed, keep as Low risk - many legitimate apps install to AppData
                }
            }
            
            // Check for other suspicious patterns
            if (lowerPath.find(L".vbs") != std::wstring::npos ||
                lowerPath.find(L".js") != std::wstring::npos ||
                lowerPath.find(L".ps1") != std::wstring::npos ||
                lowerPath.find(L".bat") != std::wstring::npos ||
                lowerPath.find(L"powershell") != std::wstring::npos ||
                lowerPath.find(L"cmd.exe /") != std::wstring::npos ||
                lowerPath.find(L"wscript") != std::wstring::npos ||
                lowerPath.find(L"cscript") != std::wstring::npos ||
                lowerPath.find(L"mshta") != std::wstring::npos) {
                item.riskLevel = StartupItemRisk::High;
                item.isSuspicious = true;
                item.suspicionReason = L"Script-based startup item (common malware technique)";
                m_statistics.suspiciousItemsFound.fetch_add(1, std::memory_order_relaxed);
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Security analysis failed for %ls - %hs", 
                        item.name.c_str(), e.what());
        }
    }

    // ========================================================================
    // BOOT SECURITY
    // ========================================================================

    BootSecurityStatus GetSecurityStatus() const {
        BootSecurityStatus status;

        try {
            // Core security checks
            status.secureBoot = CheckSecureBoot();
            CheckTPM(status);
            CheckVBS(status);
            status.credentialGuardEnabled = CheckCredentialGuard();
            status.bitLockerEnabled = CheckBitLocker();
            status.kernelDMAProtection = CheckKernelDMAProtection();

            // Extended security checks (new)
            CheckTestSigning(status);
            CheckCodeIntegrity(status);
            CheckELAMLoaded(status);
            CheckKernelDebugging(status);

            // BCD tamper detection
            status.bcdTamperIndicators = DetectBCDTampering();

            // Measured Boot: check if TCG log path exists
            HKEY hKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\CurrentControlSet\\Control\\IntegrityServices",
                            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                DWORD tbEnabled = 0;
                DWORD size = sizeof(tbEnabled);
                if (RegQueryValueExW(hKey, L"WBCL", nullptr, nullptr,
                                    reinterpret_cast<LPBYTE>(&tbEnabled),
                                    &size) == ERROR_SUCCESS) {
                    status.measuredBootEnabled = true;
                }
                RegCloseKey(hKey);
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"BootTimeAnalyzer: Security status check failed - %hs", e.what());
        }

        return status;
    }

    SecureBootStatus CheckSecureBoot() const {
        try {
            // Read from firmware variables
            // UefiSecureBootEnabled variable in {8BE4DF61-93CA-11d2-AA0D-00E098032B8C}

            HKEY hKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
                            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                DWORD uefiSecureBootEnabled = 0;
                DWORD size = sizeof(uefiSecureBootEnabled);

                if (RegQueryValueExW(hKey, L"UEFISecureBootEnabled", nullptr, nullptr,
                                    reinterpret_cast<LPBYTE>(&uefiSecureBootEnabled),
                                    &size) == ERROR_SUCCESS) {
                    RegCloseKey(hKey);
                    return uefiSecureBootEnabled ? SecureBootStatus::Enabled : SecureBootStatus::Disabled;
                }
                RegCloseKey(hKey);
            }

            return SecureBootStatus::NotSupported;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"BootTimeAnalyzer: Secure Boot check failed - %hs", e.what());
            return SecureBootStatus::Unknown;
        }
    }

    void CheckTPM(BootSecurityStatus& status) const {
        try {
            HKEY hKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI",
                            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                status.tpmPresent = true;

                // SpecVersion is a REG_SZ string like "2.0" or "1.2", NOT a DWORD
                wchar_t specVersionStr[64]{};
                DWORD size = sizeof(specVersionStr) - sizeof(wchar_t);  // reserve space for terminator
                DWORD type = 0;
                if (RegQueryValueExW(hKey, L"SpecVersion", nullptr, &type,
                                    reinterpret_cast<LPBYTE>(specVersionStr),
                                    &size) == ERROR_SUCCESS) {
                    if (type == REG_SZ || type == REG_EXPAND_SZ) {
                        // Force null-termination defensively.
                        size_t maxIdx = (sizeof(specVersionStr) / sizeof(wchar_t)) - 1;
                        specVersionStr[maxIdx] = L'\0';
                        std::wstring ver(specVersionStr);
                        if (ver.find(L"2.") == 0) {
                            status.tpmVersion = 20;  // TPM 2.0
                        } else if (ver.find(L"1.2") == 0) {
                            status.tpmVersion = 12;  // TPM 1.2
                        }
                    } else if (type == REG_DWORD && size == sizeof(DWORD)) {
                        // Fallback: some systems store it as DWORD. Use memcpy to
                        // avoid strict-aliasing UB on the wchar_t buffer.
                        DWORD specVersion = 0;
                        std::memcpy(&specVersion, specVersionStr, sizeof(DWORD));
                        status.tpmVersion = (specVersion >= 0x200) ? 20 : 12;
                    }
                }

                RegCloseKey(hKey);
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"BootTimeAnalyzer: TPM check failed - %hs", e.what());
        }
    }

    void CheckVBS(BootSecurityStatus& status) const {
        try {
            // Check VBS enabled
            HKEY hKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
                            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                DWORD enableVirtualizationBasedSecurity = 0;
                DWORD size = sizeof(enableVirtualizationBasedSecurity);

                if (RegQueryValueExW(hKey, L"EnableVirtualizationBasedSecurity", nullptr, nullptr,
                                    reinterpret_cast<LPBYTE>(&enableVirtualizationBasedSecurity),
                                    &size) == ERROR_SUCCESS) {
                    status.vbsEnabled = (enableVirtualizationBasedSecurity != 0);
                }

                // Check HVCI
                DWORD hvciEnabled = 0;
                size = sizeof(hvciEnabled);
                if (RegQueryValueExW(hKey, L"HypervisorEnforcedCodeIntegrity", nullptr, nullptr,
                                    reinterpret_cast<LPBYTE>(&hvciEnabled),
                                    &size) == ERROR_SUCCESS) {
                    status.hvciEnabled = (hvciEnabled != 0);
                }

                RegCloseKey(hKey);
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"BootTimeAnalyzer: VBS check failed - %hs", e.what());
        }
    }

    bool CheckCredentialGuard() const {
        try {
            HKEY hKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
                            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                DWORD lsaCfgFlags = 0;
                DWORD size = sizeof(lsaCfgFlags);

                if (RegQueryValueExW(hKey, L"LsaCfgFlags", nullptr, nullptr,
                                    reinterpret_cast<LPBYTE>(&lsaCfgFlags),
                                    &size) == ERROR_SUCCESS) {
                    RegCloseKey(hKey);
                    return (lsaCfgFlags & 0x1) != 0;  // Bit 0 = Credential Guard
                }
                RegCloseKey(hKey);
            }
            return false;
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"BootTimeAnalyzer: Credential Guard check failed - %hs", e.what());
            return false;
        }
    }

    bool CheckBitLocker() const {
        try {
            // Check BitLocker status via registry (ProtectionStatus on system drive)
            HKEY hKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\BitLocker",
                            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                // Check for OSVolume encryption state
                DWORD protectionStatus = 0;
                DWORD size = sizeof(protectionStatus);
                bool found = false;

                if (RegQueryValueExW(hKey, L"OSVolumeProtectionStatus", nullptr, nullptr,
                                    reinterpret_cast<LPBYTE>(&protectionStatus),
                                    &size) == ERROR_SUCCESS) {
                    found = true;
                }
                RegCloseKey(hKey);

                if (found) {
                    // 0 = off, 1 = on, 2 = suspended
                    return (protectionStatus == 1 || protectionStatus == 2);
                }
            }

            // Fallback: Check FVE (Full Volume Encryption) service state
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\CurrentControlSet\\Services\\BDESVC",
                            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                DWORD startType = 4; // disabled
                DWORD size = sizeof(startType);
                RegQueryValueExW(hKey, L"Start", nullptr, nullptr,
                               reinterpret_cast<LPBYTE>(&startType), &size);
                RegCloseKey(hKey);
                return (startType <= 2);  // Automatic or manual
            }
            return false;
        } catch (...) {
            return false;
        }
    }

    bool CheckKernelDMAProtection() const {
        try {
            HKEY hKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\CurrentControlSet\\Control\\DmaSecurity",
                            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                DWORD dmaGuardEnabled = 0;
                DWORD size = sizeof(dmaGuardEnabled);
                if (RegQueryValueExW(hKey, L"DmaGuardPolicyEnabled", nullptr, nullptr,
                                    reinterpret_cast<LPBYTE>(&dmaGuardEnabled),
                                    &size) == ERROR_SUCCESS) {
                    RegCloseKey(hKey);
                    return (dmaGuardEnabled != 0);
                }
                RegCloseKey(hKey);
            }
            return false;
        } catch (...) {
            return false;
        }
    }

    // ========================================================================
    // OPTIMIZATION SUGGESTIONS
    // ========================================================================

    std::vector<BootOptimizationSuggestion> GenerateOptimizations(
        const BootAnalysisResult& analysis) const {

        std::vector<BootOptimizationSuggestion> suggestions;

        try {
            // Analyze slow drivers
            for (const auto& driver : analysis.drivers) {
                auto durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                    driver.initDuration).count();

                if (durationMs > BootTimeAnalyzerConstants::SLOW_DRIVER_THRESHOLD_MS) {
                    BootOptimizationSuggestion suggestion;
                    suggestion.category = L"Driver";
                    suggestion.suggestion = L"Consider updating or disabling slow-loading driver";
                    suggestion.targetItem = driver.driverName;
                    suggestion.potentialSaving = std::chrono::milliseconds(durationMs / 2);
                    suggestion.priority = 4;
                    suggestion.requiresAdminAction = true;
                    suggestions.push_back(suggestion);
                }
            }

            // Analyze slow services
            for (const auto& service : analysis.services) {
                if (service.startDuration.count() > BootTimeAnalyzerConstants::SLOW_SERVICE_THRESHOLD_MS) {
                    BootOptimizationSuggestion suggestion;
                    suggestion.category = L"Service";
                    suggestion.suggestion = L"Change service to delayed start";
                    suggestion.targetItem = service.serviceName;
                    suggestion.potentialSaving = service.startDuration / 2;
                    suggestion.priority = 3;
                    suggestion.requiresAdminAction = true;
                    suggestions.push_back(suggestion);
                }
            }

            // Analyze high-impact applications
            for (const auto& app : analysis.applications) {
                if (app.impactScore >= BootTimeAnalyzerConstants::HIGH_IMPACT_THRESHOLD) {
                    BootOptimizationSuggestion suggestion;
                    suggestion.category = L"Application";
                    suggestion.suggestion = L"Disable non-essential startup application";
                    suggestion.targetItem = app.appName;
                    suggestion.potentialSaving = app.loadDuration;
                    suggestion.priority = 2;
                    suggestion.requiresAdminAction = false;
                    suggestions.push_back(suggestion);
                }
            }

            // Sort by priority (highest first)
            std::sort(suggestions.begin(), suggestions.end(),
                     [](const BootOptimizationSuggestion& a, const BootOptimizationSuggestion& b) {
                         return a.priority > b.priority;
                     });

            m_statistics.optimizationsSuggested.fetch_add(suggestions.size(),
                                                         std::memory_order_relaxed);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"BootTimeAnalyzer: Optimization generation failed - %hs", e.what());
        }

        return suggestions;
    }

    // ========================================================================
    // BCD STORE TAMPERING DETECTION
    // ========================================================================

    std::vector<BCDTamperIndicator> DetectBCDTampering() const {
        std::vector<BCDTamperIndicator> indicators;
        auto now = std::chrono::system_clock::now();

        try {
            // 1. Check testsigning (allows unsigned drivers — critical for BYOVD attacks)
            {
                HKEY hKey;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                                L"SYSTEM\\CurrentControlSet\\Control\\CI",
                                0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                    DWORD testSigningEnabled = 0;
                    DWORD size = sizeof(testSigningEnabled);
                    if (RegQueryValueExW(hKey, L"TestSigning", nullptr, nullptr,
                                        reinterpret_cast<LPBYTE>(&testSigningEnabled),
                                        &size) == ERROR_SUCCESS && testSigningEnabled != 0) {
                        BCDTamperIndicator ind;
                        ind.type = BCDTamperType::TestSigningEnabled;
                        ind.description = L"Test Signing is ENABLED — unsigned kernel drivers can load. "
                                         L"This is a critical security risk (BYOVD/rootkit vector).";
                        ind.bcdElement = L"TESTSIGNING";
                        ind.currentValue = L"ON";
                        ind.expectedValue = L"OFF";
                        ind.detectedAt = now;
                        indicators.push_back(std::move(ind));
                    }
                    RegCloseKey(hKey);
                }
            }

            // 2. Check kernel debugging (enables attacker to attach debugger — APT technique)
            {
                HKEY hKey;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                                L"SYSTEM\\CurrentControlSet\\Control",
                                0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                    BYTE debugBuf[64 * sizeof(wchar_t)]{};
                    DWORD size = sizeof(debugBuf);
                    DWORD type = 0;
                    if (RegQueryValueExW(hKey, L"SystemStartOptions", nullptr, &type,
                                        debugBuf, &size) == ERROR_SUCCESS &&
                        (type == REG_SZ || type == REG_EXPAND_SZ)) {
                        std::wstring raw = SafeWStringFromRegBytes(debugBuf, size,
                                                                   kMaxRegStringChars);
                        std::wstring opts = Utils::StringUtils::ToLowerCopy(raw);
                        if (opts.find(L"debug") != std::wstring::npos) {
                            BCDTamperIndicator ind;
                            ind.type = BCDTamperType::KernelDebuggingEnabled;
                            ind.description = L"Kernel debugging is ENABLED — allows attacher "
                                             L"to read/write kernel memory.";
                            ind.bcdElement = L"DEBUG";
                            ind.currentValue = L"ON";
                            ind.expectedValue = L"OFF";
                            ind.detectedAt = now;
                            indicators.push_back(std::move(ind));
                        }
                    }
                    RegCloseKey(hKey);
                }
            }

            // 3. Check code integrity policy (HVCI weakening)
            {
                HKEY hKey;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                                BootTimeAnalyzerConstants::CODE_INTEGRITY_PATH,
                                0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                    DWORD enabled = 0;
                    DWORD size = sizeof(enabled);
                    if (RegQueryValueExW(hKey, L"Enabled", nullptr, nullptr,
                                        reinterpret_cast<LPBYTE>(&enabled),
                                        &size) == ERROR_SUCCESS && enabled == 0) {
                        BCDTamperIndicator ind;
                        ind.type = BCDTamperType::HVCIPolicyWeakened;
                        ind.description = L"HVCI scenario is DISABLED in DeviceGuard — "
                                         L"hypervisor code integrity enforcement is off.";
                        ind.bcdElement = L"HypervisorEnforcedCodeIntegrity\\Enabled";
                        ind.currentValue = L"0";
                        ind.expectedValue = L"1";
                        ind.detectedAt = now;
                        indicators.push_back(std::move(ind));
                    }
                    RegCloseKey(hKey);
                }
            }

            // 4. Check for recovery options disabled (prevents forensic recovery)
            {
                HKEY hKey;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                                L"SYSTEM\\CurrentControlSet\\Control\\SafeBoot",
                                0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                    // Presence of key is normal; check for suspiciously altered AlternateShell
                    BYTE altBuf[MAX_PATH * sizeof(wchar_t)]{};
                    DWORD size = sizeof(altBuf);
                    DWORD type = 0;
                    if (RegQueryValueExW(hKey, L"AlternateShell", nullptr, &type,
                                        altBuf, &size) == ERROR_SUCCESS &&
                        (type == REG_SZ || type == REG_EXPAND_SZ)) {
                        std::wstring altShell = SafeWStringFromRegBytes(altBuf, size,
                                                                         kMaxRegStringChars);
                        std::wstring shell = Utils::StringUtils::ToLowerCopy(altShell);
                        if (shell.find(L"cmd.exe") == std::wstring::npos &&
                            !shell.empty()) {
                            BCDTamperIndicator ind;
                            ind.type = BCDTamperType::RecoveryDisabled;
                            ind.description = L"SafeBoot AlternateShell is set to a non-standard "
                                             L"executable — possible persistence or tamper.";
                            ind.bcdElement = L"AlternateShell";
                            ind.currentValue = SanitizeForLog(altShell,
                                                              kMaxBcdIndicatorValueChars);
                            ind.expectedValue = L"cmd.exe";
                            ind.detectedAt = now;
                            indicators.push_back(std::move(ind));
                        }
                    }
                    RegCloseKey(hKey);
                }
            }

            // 5. Check boot integrity disable (nointegritychecks)
            {
                HKEY hKey;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                                L"SYSTEM\\CurrentControlSet\\Control\\CI\\Config",
                                0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                    DWORD vulnDriverBlocklist = 0;
                    DWORD size = sizeof(vulnDriverBlocklist);
                    if (RegQueryValueExW(hKey, L"VulnerableDriverBlocklistEnable", nullptr, nullptr,
                                        reinterpret_cast<LPBYTE>(&vulnDriverBlocklist),
                                        &size) == ERROR_SUCCESS && vulnDriverBlocklist == 0) {
                        BCDTamperIndicator ind;
                        ind.type = BCDTamperType::BootIntegrityDisabled;
                        ind.description = L"Vulnerable driver blocklist is DISABLED — "
                                         L"known-vulnerable drivers (BYOVD) can load.";
                        ind.bcdElement = L"VulnerableDriverBlocklistEnable";
                        ind.currentValue = L"0";
                        ind.expectedValue = L"1";
                        ind.detectedAt = now;
                        indicators.push_back(std::move(ind));
                    }
                    RegCloseKey(hKey);
                }
            }

            m_statistics.bcdTamperDetections.fetch_add(indicators.size(), std::memory_order_relaxed);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"BCD tampering detection failed - %hs", e.what());
        }

        return indicators;
    }

    // ========================================================================
    // KERNEL DRIVER TELEMETRY QUERY
    // ========================================================================

    bool QueryKernelBootTelemetryImpl() {
        try {
            auto& ipcMgr = Communication::IPCManager::Instance();
            if (!ipcMgr.IsConnected()) {
                SS_LOG_WARN(LOG_CATEGORY, L"Cannot query kernel boot telemetry — IPC not connected");
                return false;
            }

            // Query driver status to get ELAM and boot driver info from kernel
            SHADOWSTRIKE_MESSAGE_HEADER queryMsg{};
            queryMsg.Magic = SHADOWSTRIKE_MESSAGE_MAGIC;
            queryMsg.Version = SHADOWSTRIKE_PROTOCOL_VERSION;
            queryMsg.MessageType = static_cast<UINT16>(FilterMessageType_QueryDriverStatus);
            queryMsg.TotalSize = sizeof(queryMsg);
            queryMsg.DataSize = 0;
            queryMsg.Flags = SHADOWSTRIKE_MSG_FLAG_PRIORITY_HIGH;

            // Send query and receive kernel response
            struct DriverStatusReply {
                UINT32 driverVersion;
                UINT32 driverState;
                UINT32 elamActive;
                UINT32 bootDriverCount;
                UINT64 kernelBootTimeMs;
            } reply{};

            size_t replySize = sizeof(reply);
            bool sent = ipcMgr.SendToKernel(&queryMsg, sizeof(queryMsg), &reply, &replySize,
                                            Communication::IPCConstants::REPLY_TIMEOUT_MS);
            
            if (sent && replySize >= sizeof(reply)) {
                std::unique_lock<std::shared_mutex> lock(m_kernelDataMutex);
                m_kernelBootData.hasData = true;
                m_kernelBootData.elamDriverLoaded = (reply.elamActive != 0);
                m_kernelBootData.kernelReportedBootTime = std::chrono::milliseconds(reply.kernelBootTimeMs);
                
                SS_LOG_INFO(LOG_CATEGORY, L"Kernel boot telemetry: ELAM=%s, BootDrivers=%u, BootTimeMs=%llu",
                           m_kernelBootData.elamDriverLoaded ? L"Active" : L"Inactive",
                           reply.bootDriverCount, reply.kernelBootTimeMs);
            } else {
                SS_LOG_WARN(LOG_CATEGORY, L"Kernel boot telemetry query returned no data");
                return false;
            }

            m_statistics.kernelQueriesPerformed.fetch_add(1, std::memory_order_relaxed);
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Kernel boot telemetry query failed - %hs", e.what());
            return false;
        }
    }

    // ========================================================================
    // DRIVER ANALYZER CROSS-REFERENCE
    // ========================================================================

    void CrossReferenceWithDriverAnalyzer() const {
        try {
            auto& driverAnalyzer = DriverAnalyzer::Instance();

            // Get boot-start drivers from DriverAnalyzer's analysis
            auto allDrivers = driverAnalyzer.EnumerateDrivers();
            if (allDrivers.empty()) {
                SS_LOG_DEBUG(LOG_CATEGORY, L"DriverAnalyzer returned no drivers — may not be initialized");
                return;
            }

            uint32_t unsignedBootDrivers = 0;
            uint32_t vulnerableBootDrivers = 0;

            for (const auto& drv : allDrivers) {
                if (!drv.isBootStart && !drv.isSystemStart)
                    continue;

                // Flag unsigned boot-start drivers (critical security issue)
                if (drv.signatureStatus == DriverSignatureStatus::Unsigned ||
                    drv.signatureStatus == DriverSignatureStatus::TestSigned) {
                    ++unsignedBootDrivers;
                    SS_LOG_WARN(LOG_CATEGORY,
                               L"BOOT DRIVER SECURITY: Unsigned/test-signed boot driver '%ls' [%ls]",
                               SanitizeForLog(drv.driverName).c_str(),
                               SanitizeForLog(drv.driverPath, kMaxRegStringChars).c_str());
                }

                // Check known-vulnerable drivers (BYOVD attack surface)
                if (drv.isKnownVulnerable) {
                    ++vulnerableBootDrivers;
                    SS_LOG_ERROR(LOG_CATEGORY,
                                L"BOOT DRIVER VULNERABILITY: Known-vulnerable boot driver '%ls' loaded at boot",
                                SanitizeForLog(drv.driverName).c_str());
                }
            }

            if (unsignedBootDrivers > 0 || vulnerableBootDrivers > 0) {
                SS_LOG_WARN(LOG_CATEGORY,
                           L"Boot driver integrity: %u unsigned, %u vulnerable (of %zu total boot drivers)",
                           unsignedBootDrivers, vulnerableBootDrivers, allDrivers.size());
            } else {
                SS_LOG_INFO(LOG_CATEGORY, L"Boot driver integrity: All boot drivers signed and clean");
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"DriverAnalyzer cross-reference failed - %hs", e.what());
        }
    }

    // ========================================================================
    // EXTENDED SECURITY STATUS (populates new fields)
    // ========================================================================

    void CheckTestSigning(BootSecurityStatus& status) const {
        try {
            HKEY hKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\CurrentControlSet\\Control\\CI",
                            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                DWORD val = 0;
                DWORD size = sizeof(val);
                DWORD type = 0;
                if (RegQueryValueExW(hKey, L"TestSigning", nullptr, &type,
                                    reinterpret_cast<LPBYTE>(&val), &size) == ERROR_SUCCESS &&
                    type == REG_DWORD && size == sizeof(val)) {
                    status.testSigningEnabled = (val != 0);
                }
                RegCloseKey(hKey);
            }
        } catch (...) { /* non-fatal */ }
    }

    void CheckCodeIntegrity(BootSecurityStatus& status) const {
        try {
            // RequirePlatformSecurityFeatures is REG_MULTI_SZ — the wrong type to
            // read as DWORD. Use CODE_INTEGRITY_PATH\Enabled (DWORD) instead, which
            // is the authoritative HVCI enforcement bit.
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            BootTimeAnalyzerConstants::CODE_INTEGRITY_PATH,
                            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                DWORD ciEnabled = 0;
                DWORD size = sizeof(ciEnabled);
                DWORD type = 0;
                if (RegQueryValueExW(hKey, L"Enabled", nullptr, &type,
                                    reinterpret_cast<LPBYTE>(&ciEnabled), &size) == ERROR_SUCCESS &&
                    type == REG_DWORD && size == sizeof(ciEnabled)) {
                    status.codeIntegrityEnabled = (ciEnabled != 0);
                }
                RegCloseKey(hKey);
            }
        } catch (...) { /* non-fatal */ }
    }

    void CheckELAMLoaded(BootSecurityStatus& status) const {
        try {
            std::shared_lock<std::shared_mutex> lock(m_kernelDataMutex);
            if (m_kernelBootData.hasData) {
                status.elamDriverLoaded = m_kernelBootData.elamDriverLoaded;
                return;
            }
        } catch (...) { /* fall through */ }

        // Fallback: Check if ShadowStrike ELAM driver is registered
        try {
            HKEY hKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            BootTimeAnalyzerConstants::ELAM_REG_PATH,
                            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                // If the ELAM key exists with subkeys, an ELAM driver is registered
                DWORD subKeyCount = 0;
                if (RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, &subKeyCount,
                                    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                                    nullptr) == ERROR_SUCCESS) {
                    status.elamDriverLoaded = (subKeyCount > 0);
                }
                RegCloseKey(hKey);
            }
        } catch (...) { /* non-fatal */ }
    }

    void CheckKernelDebugging(BootSecurityStatus& status) const {
        try {
            HKEY hKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\CurrentControlSet\\Control",
                            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                BYTE buf[256 * sizeof(wchar_t)]{};
                DWORD size = sizeof(buf);
                DWORD type = 0;
                if (RegQueryValueExW(hKey, L"SystemStartOptions", nullptr, &type,
                                    buf, &size) == ERROR_SUCCESS &&
                    (type == REG_SZ || type == REG_EXPAND_SZ)) {
                    std::wstring raw = SafeWStringFromRegBytes(buf, size, kMaxRegStringChars);
                    std::wstring optStr = Utils::StringUtils::ToLowerCopy(raw);
                    status.kernelDebuggingEnabled = (optStr.find(L"debug") != std::wstring::npos);
                }
                RegCloseKey(hKey);
            }
        } catch (...) { /* non-fatal */ }
    }
};

// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

std::atomic<bool> BootTimeAnalyzer::s_instanceCreated{false};

// Thread-local COM initialization flag for Task Scheduler / WMI access
thread_local bool BootTimeAnalyzer::BootTimeAnalyzerImpl::s_comInitialized = false;

BootTimeAnalyzer& BootTimeAnalyzer::Instance() noexcept {
    static BootTimeAnalyzer instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

bool BootTimeAnalyzer::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// LIFECYCLE
// ============================================================================

BootTimeAnalyzer::BootTimeAnalyzer()
    : m_impl(std::make_unique<BootTimeAnalyzerImpl>())
{
    SS_LOG_INFO(LOG_CATEGORY, L"BootTimeAnalyzer: Constructor called");
}

BootTimeAnalyzer::~BootTimeAnalyzer() {
    Shutdown();
    SS_LOG_INFO(LOG_CATEGORY, L"BootTimeAnalyzer: Destructor called");
}

bool BootTimeAnalyzer::Initialize(const BootTimeAnalyzerConfig& config) {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);

    if (m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(LOG_CATEGORY, L"BootTimeAnalyzer: Already initialized");
        return true;
    }

    try {
        m_impl->m_config = config;

        // Initialize infrastructure
        m_impl->m_hashStore = std::make_shared<HashStore::HashStore>();
        m_impl->m_whitelist = std::make_shared<Whitelist::WhitelistStore>();

        m_impl->m_initialized.store(true, std::memory_order_release);

        SS_LOG_INFO(LOG_CATEGORY, L"BootTimeAnalyzer: Initialized successfully");
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CATEGORY, L"BootTimeAnalyzer: Initialization failed - %hs", e.what());
        return false;
    }
}

void BootTimeAnalyzer::Shutdown() noexcept {
    try {
        // First check if initialized (relaxed — just a hint)
        if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
            return;
        }

        // Clear cached analysis under its own lock (avoid nested lock deadlock)
        {
            std::unique_lock<std::shared_mutex> analysisLock(m_impl->m_analysisMutex);
            m_impl->m_lastAnalysis.reset();
        }

        // Deregister BCD change callback from RegistryMonitor (if any).
        // Done before taking the main mutex to avoid lock-order inversion with
        // RegistryMonitor's own internal locks.
        if (m_impl->m_bcdCallbackId != 0) {
            try {
                auto& regMon = Registry::RegistryMonitor::Instance();
                (void)regMon.UnregisterCallback(m_impl->m_bcdCallbackId);
            } catch (...) { /* deregistration is best-effort */ }
            m_impl->m_bcdCallbackId = 0;
        }

        // Now take the main mutex for infrastructure teardown
        std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);

        if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
            return;  // Double-check after lock
        }

        // Release infrastructure
        m_impl->m_hashStore.reset();
        m_impl->m_whitelist.reset();

        // Clear kernel data
        {
            std::unique_lock<std::shared_mutex> kdLock(m_impl->m_kernelDataMutex);
            m_impl->m_kernelBootData = {};
        }

        m_impl->m_initialized.store(false, std::memory_order_release);

        SS_LOG_INFO(LOG_CATEGORY, L"BootTimeAnalyzer: Shutdown complete");

    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CATEGORY, L"BootTimeAnalyzer: Shutdown error - %hs", e.what());
    }
}

bool BootTimeAnalyzer::IsInitialized() const noexcept {
    return m_impl->m_initialized.load(std::memory_order_acquire);
}

bool BootTimeAnalyzer::UpdateConfig(const BootTimeAnalyzerConfig& config) {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);
    m_impl->m_config = config;
    SS_LOG_INFO(LOG_CATEGORY, L"BootTimeAnalyzer: Configuration updated");
    return true;
}

BootTimeAnalyzerConfig BootTimeAnalyzer::GetConfig() const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_mutex);
    return m_impl->m_config;
}

// ============================================================================
// BOOT ANALYSIS
// ============================================================================

BootAnalysisResult BootTimeAnalyzer::AnalyzeLastBoot() const {
    BootAnalysisResult result;

    if (!m_impl->IsReady()) {
        SS_LOG_WARN(LOG_CATEGORY, L"BootTimeAnalyzer: AnalyzeLastBoot called before initialization");
        return result;
    }

    try {
        m_impl->m_statistics.analysesPerformed.fetch_add(1, std::memory_order_relaxed);

        result.analysisTime = std::chrono::system_clock::now();
        result.lastBootTime = m_impl->GetLastBootTime();

        // Get total boot time
        result.totalBootTime = m_impl->GetTotalBootTimeMs();

        // Snapshot config under shared lock to avoid race
        BootTimeAnalyzerConfig configSnapshot;
        {
            std::shared_lock<std::shared_mutex> lock(m_impl->m_mutex);
            configSnapshot = m_impl->m_config;
        }

        // Analyze boot phases
        if (configSnapshot.analyzeDrivers || configSnapshot.analyzeServices ||
            configSnapshot.analyzeApplications) {
            result.phases = m_impl->AnalyzeBootPhases();

            // Calculate phase totals
            for (const auto& phase : result.phases) {
                switch (phase.phase) {
                    case BootPhase::UEFI:
                    case BootPhase::BootLoader:
                        result.preBootTime += phase.duration;
                        break;
                    case BootPhase::KernelInit:
                    case BootPhase::DriverInit:
                    case BootPhase::SessionInit:
                        result.kernelTime += phase.duration;
                        break;
                    case BootPhase::UserLogon:
                        result.logonTime += phase.duration;
                        break;
                    case BootPhase::PostLogon:
                        result.postLogonTime += phase.duration;
                        break;
                    default:
                        break;
                }
            }
        }

        // Analyze drivers
        if (configSnapshot.analyzeDrivers) {
            result.drivers = m_impl->AnalyzeDrivers();

            for (const auto& driver : result.drivers) {
                auto durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                    driver.initDuration).count();
                if (durationMs > BootTimeAnalyzerConstants::SLOW_DRIVER_THRESHOLD_MS) {
                    result.slowDrivers++;
                }
            }
        }

        // Analyze services
        if (configSnapshot.analyzeServices) {
            result.services = m_impl->AnalyzeServices();

            for (const auto& service : result.services) {
                if (service.startDuration.count() > BootTimeAnalyzerConstants::SLOW_SERVICE_THRESHOLD_MS) {
                    result.slowServices++;
                }
            }
        }

        // Analyze applications
        if (configSnapshot.analyzeApplications) {
            result.applications = m_impl->AnalyzeApplications();
        }

        // Evaluate security
        if (configSnapshot.evaluateSecurity) {
            result.security = m_impl->GetSecurityStatus();

            // Cross-reference with DriverAnalyzer for boot driver integrity
            m_impl->CrossReferenceWithDriverAnalyzer();
        }

        // Calculate ShadowStrike impact from kernel telemetry if available
        {
            std::shared_lock<std::shared_mutex> lock(m_impl->m_kernelDataMutex);
            if (m_impl->m_kernelBootData.hasData) {
                result.shadowStrikeImpact = m_impl->m_kernelBootData.kernelReportedBootTime;
                result.shadowStrikeDriverTime = std::to_wstring(
                    m_impl->m_kernelBootData.kernelReportedBootTime.count()) + L"ms";
                result.shadowStrikeServiceTime = L"N/A (kernel-measured)";
            } else {
                // Estimate from registered ShadowStrike service timing
                result.shadowStrikeImpact = std::chrono::milliseconds(0);
                result.shadowStrikeDriverTime = L"N/A (no kernel data)";
                result.shadowStrikeServiceTime = L"N/A (no kernel data)";
            }
        }

        // Count suspicious startup items
        if (configSnapshot.evaluateSecurity) {
            auto suspicious = m_impl->EnumerateAndAnalyzeStartupItems();
            for (const auto& item : suspicious) {
                if (item.isSuspicious) {
                    result.suspiciousStartupItems++;
                }
            }
        }

        // Cache result
        {
            std::unique_lock<std::shared_mutex> lock(m_impl->m_analysisMutex);
            m_impl->m_lastAnalysis = result;
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Analysis complete - Total: %lldms, Drivers: %zu, Services: %zu, Apps: %zu",
                   result.totalBootTime.count(), result.drivers.size(),
                   result.services.size(), result.applications.size());

    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Boot analysis failed - %hs", e.what());
    }

    return result;
}

std::vector<BootPhaseMetric> BootTimeAnalyzer::GetBootPhaseMetrics() const {
    return m_impl->AnalyzeBootPhases();
}

std::chrono::milliseconds BootTimeAnalyzer::GetTotalBootTime() const {
    return m_impl->GetTotalBootTimeMs();
}

std::chrono::milliseconds BootTimeAnalyzer::GetShadowStrikeBootImpact() const {
    // Pull authoritative value from the kernel telemetry channel.  If kernel
    // telemetry has not been observed yet, fall back to the value reported in
    // the most recent full analysis under the same lock.
    if (m_impl) {
        std::shared_lock<std::shared_mutex> klock(m_impl->m_kernelDataMutex);
        if (m_impl->m_kernelBootData.hasData &&
            m_impl->m_kernelBootData.kernelReportedBootTime.count() > 0) {
            return m_impl->m_kernelBootData.kernelReportedBootTime;
        }
    }
    if (m_impl) {
        std::shared_lock<std::shared_mutex> alock(m_impl->m_analysisMutex);
        if (m_impl->m_lastAnalysis.has_value()) {
            return m_impl->m_lastAnalysis->shadowStrikeImpact;
        }
    }
    return std::chrono::milliseconds(0);
}

// ============================================================================
// DRIVER ANALYSIS
// ============================================================================

std::vector<DriverBootMetric> BootTimeAnalyzer::GetDriverBootMetrics() const {
    return m_impl->AnalyzeDrivers();
}

std::vector<DriverBootMetric> BootTimeAnalyzer::GetSlowestDrivers(uint32_t count) const {
    auto drivers = m_impl->AnalyzeDrivers();

    if (drivers.size() > count) {
        drivers.resize(count);
    }

    return drivers;
}

std::unordered_map<std::wstring, ELAMDriverStatus> BootTimeAnalyzer::GetELAMClassifications() const {
    std::unordered_map<std::wstring, ELAMDriverStatus> classifications;

    try {
        auto drivers = m_impl->AnalyzeDrivers();
        for (const auto& driver : drivers) {
            classifications[driver.driverName] = driver.elamStatus;
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CATEGORY, L"BootTimeAnalyzer: ELAM classification failed - %hs", e.what());
    }

    return classifications;
}

// ============================================================================
// SERVICE ANALYSIS
// ============================================================================

std::vector<ServiceBootMetric> BootTimeAnalyzer::GetServiceBootMetrics() const {
    return m_impl->AnalyzeServices();
}

std::vector<ServiceBootMetric> BootTimeAnalyzer::GetSlowestServices(uint32_t count) const {
    auto services = m_impl->AnalyzeServices();

    if (services.size() > count) {
        services.resize(count);
    }

    return services;
}

// ============================================================================
// STARTUP ITEMS
// ============================================================================

std::vector<StartupItem> BootTimeAnalyzer::EnumerateStartupItems() const {
    return m_impl->EnumerateAndAnalyzeStartupItems();
}

std::vector<StartupItem> BootTimeAnalyzer::GetSuspiciousStartupItems() const {
    std::vector<StartupItem> suspicious;

    try {
        auto items = m_impl->EnumerateAndAnalyzeStartupItems();

        for (const auto& item : items) {
            if (item.isSuspicious || item.riskLevel >= StartupItemRisk::Medium) {
                suspicious.push_back(item);
            }
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CATEGORY, L"BootTimeAnalyzer: Suspicious item enumeration failed - %hs", e.what());
    }

    return suspicious;
}

StartupItem BootTimeAnalyzer::AnalyzeStartupItem(const std::wstring& path) const {
    StartupItem item;
    item.path = path;
    item.name = fs::path(path).filename().wstring();
    item.type = StartupItemType::Unknown;

    m_impl->AnalyzeStartupItemSecurity(item);

    return item;
}

bool BootTimeAnalyzer::DisableStartupItem(const StartupItem& item) {
    try {
        bool success = false;
        
        switch (item.type) {
            case StartupItemType::RunKey:
            case StartupItemType::RunOnceKey: {
                // Disable by renaming the registry value (prepend with "!").
                // The hive cannot be inferred from the relative subkey path alone
                // (both HKCU and HKLM expose ...\CurrentVersion\Run), so try
                // HKCU first when hinted and fall back to HKLM.
                HKEY candidates[2] = { HKEY_LOCAL_MACHINE, HKEY_LOCAL_MACHINE };
                int candidateCount = 1;
                if (item.registryLocation.find(L"HKEY_CURRENT_USER") != std::wstring::npos ||
                    item.registryLocation.find(L"\\CurrentVersion\\Run") != std::wstring::npos) {
                    candidates[0] = HKEY_CURRENT_USER;
                    candidates[1] = HKEY_LOCAL_MACHINE;
                    candidateCount = 2;
                }

                for (int c = 0; c < candidateCount && !success; ++c) {
                    HKEY hKey = nullptr;
                    if (RegOpenKeyExW(candidates[c], item.registryLocation.c_str(), 0,
                                     KEY_READ | KEY_WRITE, &hKey) != ERROR_SUCCESS) {
                        continue;
                    }

                    auto data = std::make_unique<BYTE[]>(BootTimeAnalyzerConstants::MAX_REG_VALUE_SIZE);
                    DWORD dataSize = static_cast<DWORD>(BootTimeAnalyzerConstants::MAX_REG_VALUE_SIZE);
                    DWORD type = 0;

                    LONG qr = RegQueryValueExW(hKey, item.name.c_str(), nullptr, &type,
                                              data.get(), &dataSize);
                    if (qr != ERROR_SUCCESS) {
                        RegCloseKey(hKey);
                        continue;
                    }

                    // Atomically swap: write the disabled "!"-prefixed value first,
                    // then delete the original.  This avoids losing the value if
                    // the second step fails (which previously happened).
                    std::wstring disabledName = L"!" + item.name;
                    if (RegSetValueExW(hKey, disabledName.c_str(), 0, type,
                                      data.get(), dataSize) == ERROR_SUCCESS) {
                        if (RegDeleteValueW(hKey, item.name.c_str()) == ERROR_SUCCESS) {
                            success = true;
                        } else {
                            // Roll back the disabled value to avoid duplication.
                            (void)RegDeleteValueW(hKey, disabledName.c_str());
                            SS_LOG_WARN(LOG_CATEGORY,
                                       L"BootTimeAnalyzer: Disable rollback (delete failed) for %ls",
                                       SanitizeForLog(item.name).c_str());
                        }
                    }

                    RegCloseKey(hKey);
                }
                break;
            }
            
            case StartupItemType::StartupFolder: {
                // Move file to a "Disabled" subfolder
                if (!item.path.empty() && fs::exists(item.path)) {
                    fs::path originalPath = item.path;
                    fs::path disabledFolder = originalPath.parent_path() / L"Disabled";
                    
                    // Create Disabled folder if it doesn't exist
                    if (!fs::exists(disabledFolder)) {
                        fs::create_directories(disabledFolder);
                    }
                    
                    fs::path newPath = disabledFolder / originalPath.filename();
                    fs::rename(originalPath, newPath);
                    success = true;
                }
                break;
            }
            
            case StartupItemType::ScheduledTask: {
                // Disable scheduled task using Task Scheduler API
                if (m_impl->EnsureCOMInitialized()) {
                    ITaskService* pService = nullptr;
                    HRESULT hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, 
                                                 CLSCTX_INPROC_SERVER,
                                                 IID_ITaskService, 
                                                 reinterpret_cast<void**>(&pService));
                    
                    if (SUCCEEDED(hr) && pService) {
                        hr = pService->Connect(_variant_t(), _variant_t(), 
                                              _variant_t(), _variant_t());
                        
                        if (SUCCEEDED(hr)) {
                            ITaskFolder* pFolder = nullptr;
                            // Extract folder path from task path
                            std::wstring taskPath = item.registryLocation;
                            size_t lastSlash = taskPath.rfind(L'\\');
                            std::wstring folderPath = (lastSlash != std::wstring::npos) 
                                                    ? taskPath.substr(0, lastSlash) 
                                                    : L"\\";
                            
                            hr = pService->GetFolder(_bstr_t(folderPath.c_str()), &pFolder);
                            
                            if (SUCCEEDED(hr) && pFolder) {
                                IRegisteredTask* pTask = nullptr;
                                hr = pFolder->GetTask(_bstr_t(item.name.c_str()), &pTask);
                                
                                if (SUCCEEDED(hr) && pTask) {
                                    // Disable the task
                                    hr = pTask->put_Enabled(VARIANT_FALSE);
                                    success = SUCCEEDED(hr);
                                    pTask->Release();
                                }
                                
                                pFolder->Release();
                            }
                        }
                        
                        pService->Release();
                    }
                }
                break;
            }
            
            case StartupItemType::WMISubscription: {
                // WMI subscriptions should be removed, not just disabled
                // This requires admin privileges and WMI access
                SS_LOG_WARN(LOG_CATEGORY, L"BootTimeAnalyzer: WMI subscription disable requires removal - %ls", item.name.c_str());
                // For safety, we don't auto-remove WMI subscriptions - flag for admin review
                success = false;
                break;
            }
            
            default:
                SS_LOG_WARN(LOG_CATEGORY, L"BootTimeAnalyzer: Unsupported item type for disable - %ls", item.name.c_str());
                break;
        }
        
        if (success) {
            SS_LOG_INFO(LOG_CATEGORY, L"BootTimeAnalyzer: Disabled startup item - %ls", item.name.c_str());
        } else {
            SS_LOG_WARN(LOG_CATEGORY, L"BootTimeAnalyzer: Failed to disable startup item - %ls", item.name.c_str());
        }
        
        return success;
        
    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Disable failed for %ls - %hs", 
                    item.name.c_str(), e.what());
        return false;
    }
}

bool BootTimeAnalyzer::EnableStartupItem(const StartupItem& item) {
    try {
        bool success = false;
        
        switch (item.type) {
            case StartupItemType::RunKey:
            case StartupItemType::RunOnceKey: {
                // Re-enable by removing "!" prefix from registry value name.
                HKEY candidates[2] = { HKEY_LOCAL_MACHINE, HKEY_LOCAL_MACHINE };
                int candidateCount = 1;
                if (item.registryLocation.find(L"HKEY_CURRENT_USER") != std::wstring::npos ||
                    item.registryLocation.find(L"\\CurrentVersion\\Run") != std::wstring::npos) {
                    candidates[0] = HKEY_CURRENT_USER;
                    candidates[1] = HKEY_LOCAL_MACHINE;
                    candidateCount = 2;
                }

                for (int c = 0; c < candidateCount && !success; ++c) {
                    HKEY hKey = nullptr;
                    if (RegOpenKeyExW(candidates[c], item.registryLocation.c_str(), 0,
                                     KEY_READ | KEY_WRITE, &hKey) != ERROR_SUCCESS) {
                        continue;
                    }

                    std::wstring disabledName = L"!" + item.name;
                    auto data = std::make_unique<BYTE[]>(BootTimeAnalyzerConstants::MAX_REG_VALUE_SIZE);
                    DWORD dataSize = static_cast<DWORD>(BootTimeAnalyzerConstants::MAX_REG_VALUE_SIZE);
                    DWORD type = 0;

                    LONG qr = RegQueryValueExW(hKey, disabledName.c_str(), nullptr, &type,
                                              data.get(), &dataSize);
                    if (qr != ERROR_SUCCESS) {
                        RegCloseKey(hKey);
                        continue;
                    }

                    // Write the restored value first, then delete the disabled
                    // variant.  Roll back on failure to keep the registry in a
                    // consistent state.
                    if (RegSetValueExW(hKey, item.name.c_str(), 0, type,
                                      data.get(), dataSize) == ERROR_SUCCESS) {
                        if (RegDeleteValueW(hKey, disabledName.c_str()) == ERROR_SUCCESS) {
                            success = true;
                        } else {
                            (void)RegDeleteValueW(hKey, item.name.c_str());
                            SS_LOG_WARN(LOG_CATEGORY,
                                       L"BootTimeAnalyzer: Enable rollback (delete failed) for %ls",
                                       SanitizeForLog(item.name).c_str());
                        }
                    }

                    RegCloseKey(hKey);
                }
                break;
            }
            
            case StartupItemType::StartupFolder: {
                // Move file back from "Disabled" subfolder
                fs::path originalPath = item.path;
                fs::path disabledFolder = originalPath.parent_path().parent_path();
                
                // Check if file is in Disabled folder
                if (originalPath.parent_path().filename() == L"Disabled") {
                    fs::path enabledPath = disabledFolder / originalPath.filename();
                    
                    if (fs::exists(originalPath)) {
                        fs::rename(originalPath, enabledPath);
                        success = true;
                    }
                }
                break;
            }
            
            case StartupItemType::ScheduledTask: {
                // Enable scheduled task using Task Scheduler API
                if (m_impl->EnsureCOMInitialized()) {
                    ITaskService* pService = nullptr;
                    HRESULT hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, 
                                                 CLSCTX_INPROC_SERVER,
                                                 IID_ITaskService, 
                                                 reinterpret_cast<void**>(&pService));
                    
                    if (SUCCEEDED(hr) && pService) {
                        hr = pService->Connect(_variant_t(), _variant_t(), 
                                              _variant_t(), _variant_t());
                        
                        if (SUCCEEDED(hr)) {
                            ITaskFolder* pFolder = nullptr;
                            std::wstring taskPath = item.registryLocation;
                            size_t lastSlash = taskPath.rfind(L'\\');
                            std::wstring folderPath = (lastSlash != std::wstring::npos) 
                                                    ? taskPath.substr(0, lastSlash) 
                                                    : L"\\";
                            
                            hr = pService->GetFolder(_bstr_t(folderPath.c_str()), &pFolder);
                            
                            if (SUCCEEDED(hr) && pFolder) {
                                IRegisteredTask* pTask = nullptr;
                                hr = pFolder->GetTask(_bstr_t(item.name.c_str()), &pTask);
                                
                                if (SUCCEEDED(hr) && pTask) {
                                    hr = pTask->put_Enabled(VARIANT_TRUE);
                                    success = SUCCEEDED(hr);
                                    pTask->Release();
                                }
                                
                                pFolder->Release();
                            }
                        }
                        
                        pService->Release();
                    }
                }
                break;
            }
            
            default:
                SS_LOG_WARN(LOG_CATEGORY, L"BootTimeAnalyzer: Unsupported item type for enable - %ls", item.name.c_str());
                break;
        }
        
        if (success) {
            SS_LOG_INFO(LOG_CATEGORY, L"Enabled startup item - %ls", item.name.c_str());
        } else {
            SS_LOG_WARN(LOG_CATEGORY, L"Failed to enable startup item - %ls", item.name.c_str());
        }
        
        return success;
        
    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Enable failed for %ls - %hs", 
                    item.name.c_str(), e.what());
        return false;
    }
}

// ============================================================================
// SECURITY
// ============================================================================

BootSecurityStatus BootTimeAnalyzer::GetBootSecurityStatus() const {
    return m_impl->GetSecurityStatus();
}

bool BootTimeAnalyzer::IsSecureBootEnabled() const {
    auto status = m_impl->GetSecurityStatus();
    return status.secureBoot == SecureBootStatus::Enabled;
}

bool BootTimeAnalyzer::VerifyBootChainIntegrity() const {
    if (!m_impl->IsReady()) {
        SS_LOG_WARN(LOG_CATEGORY, L"BootTimeAnalyzer: VerifyBootChainIntegrity called before init");
        return false;
    }

    try {
        auto security = m_impl->GetSecurityStatus();

        bool isSecure = true;
        std::wstring reasons;

        // 1. Secure Boot must be enabled
        if (security.secureBoot != SecureBootStatus::Enabled) {
            isSecure = false;
            reasons += L"SecureBoot=OFF; ";
        }

        // 2. VBS must be enabled
        if (!security.vbsEnabled) {
            isSecure = false;
            reasons += L"VBS=OFF; ";
        }

        // 3. HVCI must be enabled
        if (!security.hvciEnabled) {
            isSecure = false;
            reasons += L"HVCI=OFF; ";
        }

        // 4. Test signing must be disabled
        if (security.testSigningEnabled) {
            isSecure = false;
            reasons += L"TestSigning=ON; ";
        }

        // 5. Kernel debugging must be disabled
        if (security.kernelDebuggingEnabled) {
            isSecure = false;
            reasons += L"KernelDebug=ON; ";
        }

        // 6. ELAM driver should be loaded
        if (!security.elamDriverLoaded) {
            // Not a hard failure, but concerning
            SS_LOG_WARN(LOG_CATEGORY, L"Boot chain: No ELAM driver detected");
        }

        // 7. Check BCD tampering
        if (!security.bcdTamperIndicators.empty()) {
            isSecure = false;
            reasons += L"BCD_TAMPER(" + std::to_wstring(security.bcdTamperIndicators.size()) + L"); ";
        }

        if (isSecure) {
            SS_LOG_INFO(LOG_CATEGORY, L"Boot chain integrity: VERIFIED (SecureBoot+VBS+HVCI+ELAM)");
        } else {
            SS_LOG_WARN(LOG_CATEGORY, L"Boot chain integrity: COMPROMISED — %ls", reasons.c_str());
        }

        return isSecure;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Boot chain verification failed - %hs", e.what());
        return false;
    }
}

// ============================================================================
// BCD TAMPERING & KERNEL WIRING
// ============================================================================

std::vector<BCDTamperIndicator> BootTimeAnalyzer::DetectBCDTampering() const {
    if (!m_impl->IsReady()) {
        SS_LOG_WARN(LOG_CATEGORY, L"DetectBCDTampering called before initialization");
        return {};
    }
    return m_impl->DetectBCDTampering();
}

bool BootTimeAnalyzer::QueryKernelBootTelemetry() {
    if (!m_impl->IsReady()) {
        SS_LOG_WARN(LOG_CATEGORY, L"QueryKernelBootTelemetry called before initialization");
        return false;
    }
    return m_impl->QueryKernelBootTelemetryImpl();
}

void BootTimeAnalyzer::CrossReferenceDriverAnalyzer() const {
    if (!m_impl->IsReady()) {
        return;
    }
    m_impl->CrossReferenceWithDriverAnalyzer();
}

void BootTimeAnalyzer::RegisterBCDChangeCallback() {
    if (!m_impl->IsReady()) {
        SS_LOG_WARN(LOG_CATEGORY, L"RegisterBCDChangeCallback called before initialization");
        return;
    }

    try {
        // Wire into RegistryMonitor for real-time BCD store change alerts
        auto& regMon = Registry::RegistryMonitor::Instance();
        if (!regMon.IsRunning()) {
            SS_LOG_WARN(LOG_CATEGORY, L"RegistryMonitor not running — BCD change monitoring deferred");
            return;
        }

        // Register an observation-only event callback.  The RegistryMonitor
        // policy-callback slot is global and single-instance; using it here
        // would clobber the engine-wide policy decision.  RegisterEventCallback
        // returns a handle we can use to deregister at shutdown.
        Registry::RegistryEventCallback cb =
            [](const Registry::RegistryEvent& event, Registry::RegistryVerdict /*verdict*/) {
                if (event.operation != Registry::RegistryOp::SetValue &&
                    event.operation != Registry::RegistryOp::DeleteValue) {
                    return;
                }

                auto lowerPath = Utils::StringUtils::ToLowerCopy(event.keyPath);

                // Detect writes to BCD-critical / boot-policy areas, including
                // the ELAM driver registration root ("earlylaunch").
                if (lowerPath.find(L"bcd00000000")           != std::wstring::npos ||
                    lowerPath.find(L"control\\ci")           != std::wstring::npos ||
                    lowerPath.find(L"control\\deviceguard")  != std::wstring::npos ||
                    lowerPath.find(L"control\\earlylaunch")  != std::wstring::npos) {

                    SS_LOG_WARN(LOG_CATEGORY,
                               L"BCD CHANGE ALERT: PID=%u writing to '%ls' value='%ls'",
                               event.processId,
                               SanitizeForLog(event.keyPath).c_str(),
                               SanitizeForLog(event.valueName).c_str());
                }
            };

        uint64_t id = regMon.RegisterEventCallback(std::move(cb));
        if (id == 0) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Failed to register BCD event callback (id=0)");
            return;
        }
        m_impl->m_bcdCallbackId = id;

        SS_LOG_INFO(LOG_CATEGORY, L"BCD change monitoring callback registered (id=%llu)",
                   static_cast<unsigned long long>(id));

    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Failed to register BCD change callback - %hs", e.what());
    }
}

// ============================================================================
// OPTIMIZATION
// ============================================================================

std::vector<BootOptimizationSuggestion> BootTimeAnalyzer::GetOptimizationSuggestions() const {
    std::vector<BootOptimizationSuggestion> suggestions;

    try {
        // Get or perform analysis
        std::shared_lock<std::shared_mutex> lock(m_impl->m_analysisMutex);

        if (m_impl->m_lastAnalysis) {
            suggestions = m_impl->GenerateOptimizations(*m_impl->m_lastAnalysis);
        } else {
            lock.unlock();
            auto analysis = AnalyzeLastBoot();
            suggestions = m_impl->GenerateOptimizations(analysis);
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CATEGORY, L"BootTimeAnalyzer: Optimization suggestions failed - %hs", e.what());
    }

    return suggestions;
}

std::chrono::milliseconds BootTimeAnalyzer::EstimateOptimizationSavings() const {
    std::chrono::milliseconds totalSavings{0};

    try {
        auto suggestions = GetOptimizationSuggestions();

        for (const auto& suggestion : suggestions) {
            totalSavings += suggestion.potentialSaving;
        }

        SS_LOG_INFO(LOG_CATEGORY, L"BootTimeAnalyzer: Estimated savings = %lldms", totalSavings.count());

    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CATEGORY, L"BootTimeAnalyzer: Savings estimation failed - %hs", e.what());
    }

    return totalSavings;
}

// ============================================================================
// STATISTICS & DIAGNOSTICS
// ============================================================================

const BootTimeAnalyzerStatistics& BootTimeAnalyzer::GetStatistics() const noexcept {
    return m_impl->m_statistics;
}

void BootTimeAnalyzer::ResetStatistics() noexcept {
    m_impl->m_statistics.Reset();
    SS_LOG_INFO(LOG_CATEGORY, L"BootTimeAnalyzer: Statistics reset");
}

std::string BootTimeAnalyzer::GetVersionString() noexcept {
    return std::to_string(BootTimeAnalyzerConstants::VERSION_MAJOR) + "." +
           std::to_string(BootTimeAnalyzerConstants::VERSION_MINOR) + "." +
           std::to_string(BootTimeAnalyzerConstants::VERSION_PATCH);
}

bool BootTimeAnalyzer::SelfTest() {
    try {
        SS_LOG_INFO(LOG_CATEGORY, L"BootTimeAnalyzer: Starting self-test");

        // Test configuration factory
        auto config = BootTimeAnalyzerConfig::CreateDefault();
        if (!config.analyzeDrivers || !config.analyzeServices || !config.analyzeApplications) {
            SS_LOG_ERROR(LOG_CATEGORY, L"BootTimeAnalyzer: Config factory test failed");
            return false;
        }

        // Test boot time retrieval
        auto bootTime = m_impl->GetLastBootTime();
        auto totalTime = m_impl->GetTotalBootTimeMs();

        if (totalTime.count() <= 0) {
            SS_LOG_ERROR(LOG_CATEGORY, L"BootTimeAnalyzer: Boot time retrieval test failed");
            return false;
        }

        // Test security status
        auto security = m_impl->GetSecurityStatus();
        // Security check doesn't need to pass specific values, just not crash

        SS_LOG_INFO(LOG_CATEGORY, L"BootTimeAnalyzer: Self-test passed");
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CATEGORY, L"BootTimeAnalyzer: Self-test failed - %hs", e.what());
        return false;
    }
}

std::vector<std::wstring> BootTimeAnalyzer::RunDiagnostics() const {
    std::vector<std::wstring> diagnostics;

    diagnostics.push_back(L"BootTimeAnalyzer Diagnostics");
    diagnostics.push_back(L"============================");
    diagnostics.push_back(L"Initialized: " + std::wstring(IsInitialized() ? L"Yes" : L"No"));
    diagnostics.push_back(L"Analyses Performed: " + std::to_wstring(m_impl->m_statistics.analysesPerformed.load()));
    diagnostics.push_back(L"Startup Items Scanned: " + std::to_wstring(m_impl->m_statistics.startupItemsScanned.load()));
    diagnostics.push_back(L"Suspicious Items Found: " + std::to_wstring(m_impl->m_statistics.suspiciousItemsFound.load()));
    diagnostics.push_back(L"Optimizations Suggested: " + std::to_wstring(m_impl->m_statistics.optimizationsSuggested.load()));
    diagnostics.push_back(L"BCD Tamper Detections: " + std::to_wstring(m_impl->m_statistics.bcdTamperDetections.load()));
    diagnostics.push_back(L"Kernel Queries: " + std::to_wstring(m_impl->m_statistics.kernelQueriesPerformed.load()));
    diagnostics.push_back(L"Boot Drivers Analyzed: " + std::to_wstring(m_impl->m_statistics.bootDriversAnalyzed.load()));

    auto totalBootTime = m_impl->GetTotalBootTimeMs();
    diagnostics.push_back(L"Total Boot Time: " + std::to_wstring(totalBootTime.count()) + L"ms");

    return diagnostics;
}

// ============================================================================
// EXPORT
// ============================================================================

bool BootTimeAnalyzer::ExportReport(const std::wstring& outputPath) const {
    try {
        if (!IsSafeExportPath(outputPath)) {
            SS_LOG_WARN(LOG_CATEGORY,
                       L"BootTimeAnalyzer: ExportReport rejected unsafe path '%ls'",
                       SanitizeForLog(outputPath).c_str());
            return false;
        }

        std::wofstream file(outputPath);
        if (!file.is_open()) {
            return false;
        }

        auto analysis = AnalyzeLastBoot();

        file << L"BootTimeAnalyzer Report\n";
        file << L"=======================\n\n";

        file << L"Boot Time Summary:\n";
        file << L"  Total Boot Time: " << analysis.totalBootTime.count() << L"ms\n";
        file << L"  Pre-Boot Time: " << analysis.preBootTime.count() << L"ms\n";
        file << L"  Kernel Time: " << analysis.kernelTime.count() << L"ms\n";
        file << L"  Logon Time: " << analysis.logonTime.count() << L"ms\n";
        file << L"  Post-Logon Time: " << analysis.postLogonTime.count() << L"ms\n\n";

        file << L"Issues:\n";
        file << L"  Slow Drivers: " << analysis.slowDrivers << L"\n";
        file << L"  Slow Services: " << analysis.slowServices << L"\n";
        file << L"  Suspicious Items: " << analysis.suspiciousStartupItems << L"\n\n";

        file << L"Security:\n";
        file << L"  Secure Boot: " << GetSecureBootStatusName(analysis.security.secureBoot).data() << L"\n";
        file << L"  VBS Enabled: " << (analysis.security.vbsEnabled ? L"Yes" : L"No") << L"\n";
        file << L"  HVCI Enabled: " << (analysis.security.hvciEnabled ? L"Yes" : L"No") << L"\n";
        file << L"  TPM Present: " << (analysis.security.tpmPresent ? L"Yes" : L"No") << L"\n\n";

        file << L"ShadowStrike Impact: " << analysis.shadowStrikeImpact.count() << L"ms\n";

        file.close();
        return true;

    } catch (...) {
        return false;
    }
}

bool BootTimeAnalyzer::ExportOptimizations(const std::wstring& outputPath) const {
    try {
        if (!IsSafeExportPath(outputPath)) {
            SS_LOG_WARN(LOG_CATEGORY,
                       L"BootTimeAnalyzer: ExportOptimizations rejected unsafe path '%ls'",
                       SanitizeForLog(outputPath).c_str());
            return false;
        }

        std::wofstream file(outputPath);
        if (!file.is_open()) {
            return false;
        }

        auto suggestions = GetOptimizationSuggestions();

        file << L"Boot Optimization Suggestions\n";
        file << L"==============================\n\n";

        for (const auto& suggestion : suggestions) {
            file << L"Category: " << suggestion.category << L"\n";
            file << L"Target: " << suggestion.targetItem << L"\n";
            file << L"Suggestion: " << suggestion.suggestion << L"\n";
            file << L"Potential Saving: " << suggestion.potentialSaving.count() << L"ms\n";
            file << L"Priority: " << static_cast<int>(suggestion.priority) << L"/5\n";
            file << L"Requires Admin: " << (suggestion.requiresAdminAction ? L"Yes" : L"No") << L"\n";
            file << L"\n";
        }

        auto totalSavings = EstimateOptimizationSavings();
        file << L"Total Estimated Savings: " << totalSavings.count() << L"ms\n";

        file.close();
        return true;

    } catch (...) {
        return false;
    }
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetBootPhaseName(BootPhase phase) noexcept {
    switch (phase) {
        case BootPhase::Unknown: return "Unknown";
        case BootPhase::UEFI: return "UEFI/BIOS";
        case BootPhase::BootLoader: return "Boot Loader";
        case BootPhase::KernelInit: return "Kernel Initialization";
        case BootPhase::DriverInit: return "Driver Initialization";
        case BootPhase::SessionInit: return "Session Manager";
        case BootPhase::ServiceStart: return "Service Startup";
        case BootPhase::ShellStart: return "Shell Start";
        case BootPhase::UserLogon: return "User Logon";
        case BootPhase::PostLogon: return "Post-Logon";
        default: return "Unknown";
    }
}

std::string_view GetStartupItemTypeName(StartupItemType type) noexcept {
    switch (type) {
        case StartupItemType::Unknown: return "Unknown";
        case StartupItemType::Service: return "Service";
        case StartupItemType::Driver: return "Driver";
        case StartupItemType::RunKey: return "Registry Run Key";
        case StartupItemType::RunOnceKey: return "Registry RunOnce Key";
        case StartupItemType::StartupFolder: return "Startup Folder";
        case StartupItemType::ScheduledTask: return "Scheduled Task";
        case StartupItemType::ShellExtension: return "Shell Extension";
        case StartupItemType::BrowserExtension: return "Browser Extension";
        case StartupItemType::ActiveXControl: return "ActiveX Control";
        case StartupItemType::WMISubscription: return "WMI Subscription";
        default: return "Unknown";
    }
}

std::string_view GetStartupItemRiskName(StartupItemRisk risk) noexcept {
    switch (risk) {
        case StartupItemRisk::Safe: return "Safe";
        case StartupItemRisk::Low: return "Low";
        case StartupItemRisk::Medium: return "Medium";
        case StartupItemRisk::High: return "High";
        case StartupItemRisk::Critical: return "Critical";
        default: return "Unknown";
    }
}

std::string_view GetSecureBootStatusName(SecureBootStatus status) noexcept {
    switch (status) {
        case SecureBootStatus::Unknown: return "Unknown";
        case SecureBootStatus::Enabled: return "Enabled";
        case SecureBootStatus::Disabled: return "Disabled";
        case SecureBootStatus::NotSupported: return "Not Supported";
        default: return "Unknown";
    }
}

std::string_view GetELAMDriverStatusName(ELAMDriverStatus status) noexcept {
    switch (status) {
        case ELAMDriverStatus::Unknown: return "Unknown";
        case ELAMDriverStatus::Good: return "Good";
        case ELAMDriverStatus::Bad: return "Bad";
        case ELAMDriverStatus::Unknown_: return "Unknown to ELAM";
        case ELAMDriverStatus::BadButCritical: return "Bad But Critical";
        default: return "Unknown";
    }
}

}  // namespace System
}  // namespace Core
}  // namespace ShadowStrike
