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
 * ShadowStrike Banking Protection - BANKING TROJAN DETECTOR
 * ============================================================================
 *
 * @file BankingTrojanDetector.cpp
 * @brief Implementation of enterprise-grade banking trojan detection engine.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "pch.h"
#include "BankingTrojanDetector.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <sstream>
#include <iomanip>
#include <algorithm>
#include <thread>
#include <deque>
#include <cmath>
#include <limits>

// Windows networking — required for GetExtendedTcpTable / MIB_TCPTABLE_OWNER_PID
#include <iphlpapi.h>
#include <ws2tcpip.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace ShadowStrike {
namespace Banking {

// ============================================================================
// ANONYMOUS NAMESPACE — FILE-LOCAL HELPERS
// ============================================================================

namespace {

constexpr const wchar_t* LOG_CATEGORY = L"BankingTrojanDetector";

/// Max threat score clamp
constexpr double MAX_THREAT_SCORE = 100.0;

/// Shellcode heuristic: minimum NOP sled length
constexpr size_t MIN_NOP_SLED_LENGTH = 16;

/// Memory read chunk size for scanning
constexpr SIZE_T MEM_SCAN_CHUNK = 4096;
constexpr DWORD MAX_TCP_TABLE_BYTES = 32U * 1024U * 1024U;

template <typename T>
[[nodiscard]] T AtomicValueLoadRelaxed(const T& value) noexcept {
    return std::atomic_ref<T>(const_cast<T&>(value)).load(std::memory_order_relaxed);
}

template <typename T>
void AtomicValueStoreRelaxed(T& target, const T& value) noexcept {
    std::atomic_ref<T>(target).store(value, std::memory_order_relaxed);
}

/// DGA entropy threshold — legitimate domains rarely exceed this
constexpr double DGA_ENTROPY_THRESHOLD = 3.7;

/// DGA minimum label length
constexpr size_t DGA_MIN_LABEL_LENGTH = 8;

/// Common persistence Run key paths
constexpr const wchar_t* PERSISTENCE_RUN_KEYS[] = {
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices",
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
};

/// Narrow-string JSON escaping for telemetry serialization.
[[nodiscard]] std::string EscapeJsonStr(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (const char c : s) {
        switch (c) {
            case '\"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x",
                                  static_cast<unsigned>(static_cast<unsigned char>(c)));
                    out += buf;
                } else {
                    out += c;
                }
                break;
        }
    }
    return out;
}

/// Shannon entropy of a byte buffer.
[[nodiscard]] double ComputeEntropy(const uint8_t* data, size_t len) noexcept {
    if (len == 0) return 0.0;
    uint64_t freq[256]{};
    for (size_t i = 0; i < len; ++i)
        freq[data[i]]++;
    double entropy = 0.0;
    const double dlen = static_cast<double>(len);
    for (auto& f : freq) {
        if (f == 0) continue;
        const double p = static_cast<double>(f) / dlen;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

/// Shannon entropy of a string (for DGA detection).
[[nodiscard]] double ComputeStringEntropy(std::string_view s) noexcept {
    return ComputeEntropy(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

/// Clamp a value to [lo, hi].
[[nodiscard]] constexpr double ClampScore(double val, double lo = 0.0, double hi = MAX_THREAT_SCORE) noexcept {
    return (val < lo) ? lo : (val > hi) ? hi : val;
}

/// Safe family index — returns 0 for out-of-range enum values.
[[nodiscard]] constexpr size_t SafeFamilyIndex(TrojanFamily f) noexcept {
    const auto v = static_cast<uint16_t>(f);
    return (v < 32) ? static_cast<size_t>(v) : 0;
}

/// Safe method index.
[[nodiscard]] constexpr size_t SafeMethodIndex(DetectionMethod m) noexcept {
    const auto v = static_cast<uint16_t>(m);
    return (v < 16) ? static_cast<size_t>(v) : 0;
}

/// Generate a detection ID from system clock + PID.
[[nodiscard]] std::string GenerateDetectionId(uint32_t pid) {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const auto ticks = std::chrono::duration_cast<std::chrono::microseconds>(now).count();
    std::ostringstream oss;
    oss << "BTD-" << std::hex << std::uppercase << ticks << "-" << pid;
    return oss.str();
}

[[nodiscard]] bool AdvanceRegionAddress(uint8_t*& address, const MEMORY_BASIC_INFORMATION& mbi) noexcept {
    const auto base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
    if (mbi.RegionSize == 0 ||
        mbi.RegionSize > (std::numeric_limits<uintptr_t>::max)() - base) {
        return false;
    }
    const auto next = base + mbi.RegionSize;
    if (next <= reinterpret_cast<uintptr_t>(address)) {
        return false;
    }
    address = reinterpret_cast<uint8_t*>(next);
    return true;
}

} // anonymous namespace

// ============================================================================
// STATIC MEMBER INITIALIZATION
// ============================================================================

std::atomic<bool> BankingTrojanDetector::s_instanceCreated{false};

// ============================================================================
// UTILITY FUNCTION IMPLEMENTATIONS
// ============================================================================

[[nodiscard]] std::string_view GetTrojanFamilyName(TrojanFamily family) noexcept {
    switch (family) {
        case TrojanFamily::Unknown:         return "Unknown";
        case TrojanFamily::Zeus:            return "Zeus";
        case TrojanFamily::ZeusGameover:    return "ZeusGameover";
        case TrojanFamily::Emotet:          return "Emotet";
        case TrojanFamily::TrickBot:        return "TrickBot";
        case TrojanFamily::Dridex:          return "Dridex";
        case TrojanFamily::QakBot:          return "QakBot";
        case TrojanFamily::Gozi:            return "Gozi";
        case TrojanFamily::IcedID:          return "IcedID";
        case TrojanFamily::Carberp:         return "Carberp";
        case TrojanFamily::SpyEye:          return "SpyEye";
        case TrojanFamily::Citadel:         return "Citadel";
        case TrojanFamily::Kronos:          return "Kronos";
        case TrojanFamily::Ramnit:          return "Ramnit";
        case TrojanFamily::Vawtrak:         return "Vawtrak";
        case TrojanFamily::Tinba:           return "Tinba";
        case TrojanFamily::Panda:           return "Panda";
        case TrojanFamily::BankBot:         return "BankBot";
        case TrojanFamily::Custom:          return "Custom";
        default:                            return "Unknown";
    }
}

[[nodiscard]] std::string_view GetDetectionMethodName(DetectionMethod method) noexcept {
    switch (method) {
        case DetectionMethod::Unknown:           return "Unknown";
        case DetectionMethod::SignatureMatch:     return "SignatureMatch";
        case DetectionMethod::HeuristicAnalysis:  return "HeuristicAnalysis";
        case DetectionMethod::BehavioralAnalysis: return "BehavioralAnalysis";
        case DetectionMethod::MemoryScanning:     return "MemoryScanning";
        case DetectionMethod::APIHookDetection:   return "APIHookDetection";
        case DetectionMethod::WebInjectDetection: return "WebInjectDetection";
        case DetectionMethod::NetworkAnalysis:    return "NetworkAnalysis";
        case DetectionMethod::MachineLearning:    return "MachineLearning";
        case DetectionMethod::ThreatIntelMatch:   return "ThreatIntelMatch";
        case DetectionMethod::YaraRuleMatch:      return "YaraRuleMatch";
        default:                                  return "Unknown";
    }
}

[[nodiscard]] std::string_view GetSeverityName(ThreatSeverity severity) noexcept {
    switch (severity) {
        case ThreatSeverity::None:     return "None";
        case ThreatSeverity::Low:      return "Low";
        case ThreatSeverity::Medium:   return "Medium";
        case ThreatSeverity::High:     return "High";
        case ThreatSeverity::Critical: return "Critical";
        default:                       return "Unknown";
    }
}

[[nodiscard]] std::string_view GetHookTypeName(HookType type) noexcept {
    switch (type) {
        case HookType::Unknown:       return "Unknown";
        case HookType::InlineHook:    return "InlineHook";
        case HookType::IATHook:       return "IATHook";
        case HookType::EATHook:       return "EATHook";
        case HookType::VTableHook:    return "VTableHook";
        case HookType::DebugHook:     return "DebugHook";
        case HookType::PageGuardHook: return "PageGuardHook";
        default:                      return "Unknown";
    }
}

[[nodiscard]] std::string_view GetInjectionTechniqueName(InjectionTechnique tech) noexcept {
    switch (tech) {
        case InjectionTechnique::Unknown:           return "Unknown";
        case InjectionTechnique::DLLInjection:      return "DLLInjection";
        case InjectionTechnique::ProcessHollowing:  return "ProcessHollowing";
        case InjectionTechnique::AtomBombing:       return "AtomBombing";
        case InjectionTechnique::QueueUserAPC:      return "QueueUserAPC";
        case InjectionTechnique::SetWindowsHookEx:  return "SetWindowsHookEx";
        case InjectionTechnique::ReflectiveLoading: return "ReflectiveLoading";
        case InjectionTechnique::ThreadHijacking:   return "ThreadHijacking";
        case InjectionTechnique::SectionMapping:    return "SectionMapping";
        default:                                    return "Unknown";
    }
}

[[nodiscard]] std::string_view GetWebInjectTypeName(WebInjectType type) noexcept {
    switch (type) {
        case WebInjectType::Unknown:         return "Unknown";
        case WebInjectType::FormGrabber:     return "FormGrabber";
        case WebInjectType::HTMLInjection:   return "HTMLInjection";
        case WebInjectType::JSInjection:     return "JSInjection";
        case WebInjectType::DOMManipulation: return "DOMManipulation";
        case WebInjectType::ScreenCapture:   return "ScreenCapture";
        case WebInjectType::VideoCapture:    return "VideoCapture";
        default:                             return "Unknown";
    }
}

[[nodiscard]] std::string_view GetActionName(DetectionAction action) noexcept {
    switch (action) {
        case DetectionAction::None:       return "None";
        case DetectionAction::Alert:      return "Alert";
        case DetectionAction::Block:      return "Block";
        case DetectionAction::Quarantine: return "Quarantine";
        case DetectionAction::Terminate:  return "Terminate";
        case DetectionAction::Remediate:  return "Remediate";
        default:                          return "None";
    }
}

[[nodiscard]] bool IsBrowserProcess(std::wstring_view processName) noexcept {
    for (const auto* browser : BankingTrojanConstants::TARGET_BROWSERS) {
        if (Utils::StringUtils::IEquals(processName, browser)) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] double CalculateThreatScore(const DetectionResult& result) {
    double score = 0.0;

    // Weighted scoring per detection method
    for (const auto& method : result.detectionMethods) {
        switch (method) {
            case DetectionMethod::SignatureMatch:     score += 40.0; break;
            case DetectionMethod::MemoryScanning:     score += 25.0; break;
            case DetectionMethod::APIHookDetection:   score += 20.0; break;
            case DetectionMethod::NetworkAnalysis:    score += 30.0; break;
            case DetectionMethod::WebInjectDetection: score += 35.0; break;
            case DetectionMethod::BehavioralAnalysis: score += 20.0; break;
            case DetectionMethod::ThreatIntelMatch:   score += 45.0; break;
            case DetectionMethod::YaraRuleMatch:      score += 40.0; break;
            case DetectionMethod::MachineLearning:    score += 15.0; break;
            default: break;
        }
    }

    // Boost from number of hooks detected
    score += std::min(static_cast<double>(result.detectedHooks.size()) * 5.0, 25.0);

    // Boost from suspicious memory regions
    score += std::min(static_cast<double>(result.suspiciousMemory.size()) * 8.0, 24.0);

    // Boost from web injections
    score += std::min(static_cast<double>(result.webInjections.size()) * 10.0, 30.0);

    return ClampScore(score);
}

[[nodiscard]] ThreatSeverity DetermineSeverity(double threatScore) noexcept {
    if (threatScore >= BankingTrojanConstants::THREAT_SCORE_CRITICAL) return ThreatSeverity::Critical;
    if (threatScore >= BankingTrojanConstants::THREAT_SCORE_HIGH)     return ThreatSeverity::High;
    if (threatScore >= BankingTrojanConstants::THREAT_SCORE_MEDIUM)   return ThreatSeverity::Medium;
    if (threatScore >= BankingTrojanConstants::THREAT_SCORE_LOW)      return ThreatSeverity::Low;
    return ThreatSeverity::None;
}

// ============================================================================
// STRUCT JSON SERIALIZATION
// ============================================================================

std::string ProcessIndicator::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"pid\":" << pid << ","
        << "\"name\":\"" << EscapeJsonStr(Utils::StringUtils::ToNarrow(processName)) << "\","
        << "\"path\":\"" << EscapeJsonStr(Utils::StringUtils::ToNarrow(processPath)) << "\","
        << "\"parentPid\":" << parentPid << ","
        << "\"integrity\":" << integrityLevel << ","
        << "\"elevated\":" << (isElevated ? "true" : "false") << ","
        << "\"signed\":" << (isSigned ? "true" : "false")
        << "}";
    return oss.str();
}

std::string MemoryRegionInfo::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"baseAddress\":\"0x" << std::hex << baseAddress << "\","
        << "\"regionSize\":" << std::dec << regionSize << ","
        << "\"protection\":" << protection << ","
        << "\"executable\":" << (isExecutable ? "true" : "false") << ","
        << "\"private\":" << (isPrivate ? "true" : "false") << ","
        << "\"shellcode\":" << (hasShellcode ? "true" : "false") << ","
        << "\"entropy\":" << std::fixed << std::setprecision(2) << entropy
        << "}";
    return oss.str();
}

std::string ApiHookInfo::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"module\":\"" << EscapeJsonStr(Utils::StringUtils::ToNarrow(moduleName)) << "\","
        << "\"function\":\"" << EscapeJsonStr(functionName) << "\","
        << "\"originalAddr\":\"0x" << std::hex << originalAddress << "\","
        << "\"hookedAddr\":\"0x" << std::hex << hookedAddress << std::dec << "\","
        << "\"type\":\"" << GetHookTypeName(hookType) << "\","
        << "\"malicious\":" << (isMalicious ? "true" : "false") << ","
        << "\"confidence\":" << std::fixed << std::setprecision(2) << confidence
        << "}";
    return oss.str();
}

std::string WebInjectionInfo::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"urlPattern\":\"" << EscapeJsonStr(urlPattern) << "\","
        << "\"domain\":\"" << EscapeJsonStr(targetDomain) << "\","
        << "\"type\":\"" << GetWebInjectTypeName(injectType) << "\","
        << "\"active\":" << (isActive ? "true" : "false")
        << "}";
    return oss.str();
}

std::string NetworkConnectionInfo::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"remoteIP\":\"" << EscapeJsonStr(remoteIP) << "\","
        << "\"remotePort\":" << remotePort << ","
        << "\"localPort\":" << localPort << ","
        << "\"isC2\":" << (isC2 ? "true" : "false") << ","
        << "\"isDGA\":" << (isDGA ? "true" : "false") << ","
        << "\"domain\":\"" << EscapeJsonStr(domainName) << "\","
        << "\"bytesSent\":" << bytesSent << ","
        << "\"bytesReceived\":" << bytesReceived
        << "}";
    return oss.str();
}

std::string DetectionResult::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"id\":\"" << EscapeJsonStr(detectionId) << "\","
        << "\"detected\":" << (isThreatDetected ? "true" : "false") << ","
        << "\"family\":\"" << GetTrojanFamilyName(family) << "\","
        << "\"severity\":\"" << GetSeverityName(severity) << "\","
        << "\"score\":" << std::fixed << std::setprecision(1) << threatScore << ","
        << "\"confidence\":" << std::fixed << std::setprecision(2) << confidenceScore << ","
        << "\"action\":\"" << GetActionName(actionTaken) << "\","
        << "\"process\":" << processInfo.ToJson() << ","
        << "\"whitelisted\":" << (isWhitelisted ? "true" : "false")
        << "}";
    return oss.str();
}

std::string DetectionStatistics::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"scans\":" << totalScans.load(std::memory_order_relaxed) << ","
        << "\"threats\":" << threatsDetected.load(std::memory_order_relaxed) << ","
        << "\"quarantined\":" << threatsQuarantined.load(std::memory_order_relaxed) << ","
        << "\"remediated\":" << threatsRemediated.load(std::memory_order_relaxed) << ","
        << "\"falsePositives\":" << falsePositives.load(std::memory_order_relaxed) << ","
        << "\"whitelistHits\":" << whitelistHits.load(std::memory_order_relaxed)
        << "}";
    return oss.str();
}

std::string DetectionStatisticsSnapshot::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"scans\":" << totalScans << ","
        << "\"threats\":" << threatsDetected << ","
        << "\"quarantined\":" << threatsQuarantined << ","
        << "\"remediated\":" << threatsRemediated << ","
        << "\"falsePositives\":" << falsePositives << ","
        << "\"whitelistHits\":" << whitelistHits
        << "}";
    return oss.str();
}

void DetectionStatistics::Reset() noexcept {
    totalScans.store(0, std::memory_order_relaxed);
    threatsDetected.store(0, std::memory_order_relaxed);
    threatsQuarantined.store(0, std::memory_order_relaxed);
    threatsRemediated.store(0, std::memory_order_relaxed);
    falsePositives.store(0, std::memory_order_relaxed);
    whitelistHits.store(0, std::memory_order_relaxed);
    for (auto& f : byFamily) f.store(0, std::memory_order_relaxed);
    for (auto& m : byMethod) m.store(0, std::memory_order_relaxed);
    AtomicValueStoreRelaxed(startTime, Clock::now());
    AtomicValueStoreRelaxed(lastDetectionTime, SystemTimePoint{});
}

bool BankingTrojanDetectorConfiguration::IsValid() const noexcept {
    return threatScoreThreshold >= 0.0 && threatScoreThreshold <= 100.0 &&
           confidenceThreshold >= 0.0 && confidenceThreshold <= 1.0;
}

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class BankingTrojanDetectorImpl {
public:
    BankingTrojanDetectorImpl() noexcept
        : m_status(ModuleStatus::Uninitialized)
        , m_initialized(false)
        , m_running(false)
    {
        SS_LOG_INFO(LOG_CATEGORY, L"Creating BankingTrojanDetector implementation");
    }

    ~BankingTrojanDetectorImpl() noexcept {
        Shutdown();
    }

    // Non-copyable, non-movable
    BankingTrojanDetectorImpl(const BankingTrojanDetectorImpl&) = delete;
    BankingTrojanDetectorImpl& operator=(const BankingTrojanDetectorImpl&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(const BankingTrojanDetectorConfiguration& config) noexcept {
        std::unique_lock lock(m_mutex);

        if (m_initialized.load(std::memory_order_relaxed)) {
            SS_LOG_WARN(LOG_CATEGORY, L"Already initialized");
            return true;
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Initializing BankingTrojanDetector");
        m_status.store(ModuleStatus::Initializing, std::memory_order_release);

        try {
            if (!config.IsValid()) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Invalid configuration: threshold=%.1f confidence=%.2f",
                             config.threatScoreThreshold, config.confidenceThreshold);
                m_status.store(ModuleStatus::Error, std::memory_order_release);
                return false;
            }

            m_config = config;

            // Validate YARA rules path if provided
            if (!config.yaraRulesPath.empty()) {
                const std::filesystem::path yaraPath(config.yaraRulesPath);
                if (!std::filesystem::exists(yaraPath) || !std::filesystem::is_regular_file(yaraPath)) {
                    SS_LOG_ERROR(LOG_CATEGORY, L"YARA rules file not found or not a regular file: %ls",
                                 config.yaraRulesPath.c_str());
                    m_status.store(ModuleStatus::Error, std::memory_order_release);
                    return false;
                }
                SS_LOG_INFO(LOG_CATEGORY, L"YARA rules path validated: %ls", config.yaraRulesPath.c_str());
            }

            // Load whitelist
            m_whitelist.clear();
            for (const auto& proc : config.whitelistedProcesses) {
                m_whitelist.insert(Utils::StringUtils::ToLowerCopy(proc));
            }
            SS_LOG_INFO(LOG_CATEGORY, L"Loaded %zu whitelisted processes",
                         m_whitelist.size());

            m_stats.Reset();
            m_initialized.store(true, std::memory_order_release);
            m_status.store(ModuleStatus::Stopped, std::memory_order_release);

            SS_LOG_INFO(LOG_CATEGORY, L"BankingTrojanDetector initialized successfully");
            return true;

        } catch (const std::exception& ex) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Initialization failed: %hs", ex.what());
            m_status.store(ModuleStatus::Error, std::memory_order_release);
            return false;
        }
    }

    void Shutdown() noexcept {
        (void)Stop();

        std::unique_lock lock(m_mutex);
        if (!m_initialized.load(std::memory_order_relaxed)) return;

        SS_LOG_INFO(LOG_CATEGORY, L"Shutting down BankingTrojanDetector");
        m_status.store(ModuleStatus::Stopping, std::memory_order_release);

        {
            std::unique_lock hLock(m_historyMutex);
            m_recentDetections.clear();
        }
        m_whitelist.clear();
        m_detectionCallback = nullptr;
        m_errorCallback = nullptr;

        m_initialized.store(false, std::memory_order_release);
        m_status.store(ModuleStatus::Stopped, std::memory_order_release);
        SS_LOG_INFO(LOG_CATEGORY, L"BankingTrojanDetector shutdown complete");
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        return m_initialized.load(std::memory_order_acquire);
    }

    [[nodiscard]] ModuleStatus GetStatus() const noexcept {
        return m_status.load(std::memory_order_acquire);
    }

    [[nodiscard]] bool IsRunning() const noexcept {
        return m_running.load(std::memory_order_acquire);
    }

    [[nodiscard]] bool Start() noexcept {
        std::unique_lock lock(m_mutex);
        if (!m_initialized.load(std::memory_order_relaxed)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Cannot start: not initialized");
            return false;
        }
        if (m_status.load(std::memory_order_acquire) == ModuleStatus::Stopping) {
            SS_LOG_WARN(LOG_CATEGORY, L"Cannot start while stop is still in progress");
            return false;
        }
        if (m_running.load(std::memory_order_relaxed)) return true;

        SS_LOG_INFO(LOG_CATEGORY, L"Starting BankingTrojanDetector real-time protection");

        m_running.store(true, std::memory_order_release);
        m_status.store(ModuleStatus::Running, std::memory_order_release);

        if (m_config.enableRealTimeProtection) {
            try {
                m_scanThread = std::thread(&BankingTrojanDetectorImpl::ScanningLoop, this);
            } catch (const std::exception& ex) {
                m_running.store(false, std::memory_order_release);
                m_status.store(ModuleStatus::Error, std::memory_order_release);
                SS_LOG_ERROR(LOG_CATEGORY,
                    L"Failed to start scanning thread: %hs", ex.what());
                return false;
            }
        }

        return true;
    }

    [[nodiscard]] bool Stop() noexcept {
        {
            std::unique_lock lock(m_mutex);
            if (!m_running.load(std::memory_order_relaxed)) return true;

            SS_LOG_INFO(LOG_CATEGORY, L"Stopping BankingTrojanDetector");
            m_running.store(false, std::memory_order_release);
            m_status.store(ModuleStatus::Stopping, std::memory_order_release);
        }

        if (m_scanThread.joinable()) {
            m_scanThread.join();
        }

        m_status.store(ModuleStatus::Stopped, std::memory_order_release);
        return true;
    }

    void Pause() noexcept {
        if (m_running.load(std::memory_order_acquire)) {
            m_status.store(ModuleStatus::Paused, std::memory_order_release);
            SS_LOG_INFO(LOG_CATEGORY, L"Protection paused");
        }
    }

    void Resume() noexcept {
        if (m_running.load(std::memory_order_acquire) &&
            m_status.load(std::memory_order_acquire) == ModuleStatus::Paused) {
            m_status.store(ModuleStatus::Running, std::memory_order_release);
            SS_LOG_INFO(LOG_CATEGORY, L"Protection resumed");
        }
    }

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    [[nodiscard]] bool UpdateConfiguration(const BankingTrojanDetectorConfiguration& config) noexcept {
        if (!config.IsValid()) {
            SS_LOG_WARN(LOG_CATEGORY, L"Rejected invalid configuration update");
            return false;
        }
        std::unique_lock lock(m_mutex);
        m_config = config;

        // Re-populate whitelist
        m_whitelist.clear();
        for (const auto& proc : config.whitelistedProcesses) {
            m_whitelist.insert(Utils::StringUtils::ToLowerCopy(proc));
        }
        SS_LOG_INFO(LOG_CATEGORY, L"Configuration updated");
        return true;
    }

    [[nodiscard]] BankingTrojanDetectorConfiguration GetConfiguration() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_config;
    }

    // ========================================================================
    // PROCESS ANALYSIS
    // ========================================================================

    [[nodiscard]] DetectionResult AnalyzeProcess(uint32_t processId) {
        DetectionResult result;
        result.processInfo.pid = processId;
        const auto start = Clock::now();

        try {
            // 1. Retrieve real process info
            Utils::ProcessUtils::ProcessBasicInfo basicInfo;
            Utils::ProcessUtils::Error procErr;
            if (!Utils::ProcessUtils::GetProcessBasicInfo(
                    static_cast<Utils::ProcessUtils::ProcessId>(processId), basicInfo, &procErr)) {
                SS_LOG_WARN(LOG_CATEGORY, L"Cannot get info for PID %u — process may have exited", processId);
                result.analysisDuration = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start);
                m_stats.totalScans.fetch_add(1, std::memory_order_relaxed);
                return result;
            }

            result.processInfo.processName = basicInfo.name;
            result.processInfo.processPath = basicInfo.executablePath;
            result.processInfo.parentPid   = basicInfo.parentPid;
            result.processInfo.commandLine = basicInfo.commandLine;

            // Security info
            Utils::ProcessUtils::ProcessSecurityInfo secInfo;
            if (Utils::ProcessUtils::GetProcessSecurityInfo(
                    static_cast<Utils::ProcessUtils::ProcessId>(processId), secInfo)) {
                result.processInfo.userSid = secInfo.userSid;
                result.processInfo.isElevated = secInfo.isElevated;
            }

            // 2. Whitelist check
            if (IsWhitelisted(processId)) {
                result.isWhitelisted = true;
                result.whitelistReason = "Process whitelisted by configuration";
                m_stats.whitelistHits.fetch_add(1, std::memory_order_relaxed);
                result.analysisDuration = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start);
                m_stats.totalScans.fetch_add(1, std::memory_order_relaxed);
                return result;
            }

            // 3. Hash-based threat intel lookup
            if (m_config.enableThreatIntel && !basicInfo.executablePath.empty()) {
                std::vector<uint8_t> fileHash;
                if (Utils::HashUtils::ComputeFile(
                        Utils::HashUtils::Algorithm::SHA256, basicInfo.executablePath, fileHash)) {
                    const std::string hexHash = Utils::HashUtils::ToHexLower(fileHash.data(), fileHash.size());

                    // Copy hash into result
                    if (fileHash.size() == result.processInfo.fileHash.size()) {
                        std::copy(fileHash.begin(), fileHash.end(), result.processInfo.fileHash.begin());
                    }

                    auto& tiMgr = ThreatIntel::ThreatIntelManager::Instance();
                    double riskScore = 0.0;
                    std::string threatName;
                    if (tiMgr.IsKnownMalicious(hexHash, riskScore, threatName)) {
                        result.threatScore += riskScore * 0.5;
                        result.detectionMethods.push_back(DetectionMethod::ThreatIntelMatch);

                        ThreatIndicator indicator;
                        indicator.indicatorType = "HASH_MATCH";
                        indicator.indicatorValue = hexHash;
                        indicator.source = "ThreatIntel";
                        indicator.confidence = 0.95;
                        indicator.description = "SHA-256 matches known banking trojan";
                        result.indicators.push_back(std::move(indicator));
                    }
                }
            }

            // 4. Memory analysis
            BankingTrojanDetectorConfiguration localCfg;
            {
                std::shared_lock lock(m_mutex);
                localCfg = m_config;
            }

            if (localCfg.enableMemoryScanning) {
                auto memResult = AnalyzeProcessMemory(processId);
                if (memResult.isThreatDetected) {
                    result.suspiciousMemory = std::move(memResult.suspiciousMemory);
                    result.threatScore += memResult.threatScore;
                    result.detectionMethods.push_back(DetectionMethod::MemoryScanning);
                    result.indicators.insert(result.indicators.end(),
                        std::make_move_iterator(memResult.indicators.begin()),
                        std::make_move_iterator(memResult.indicators.end()));
                }
            }

            // 5. API hook detection
            if (localCfg.enableAPIHookDetection) {
                auto hooks = DetectAPIHooks(processId);
                if (!hooks.empty()) {
                    result.detectedHooks = std::move(hooks);
                    result.threatScore += std::min(
                        static_cast<double>(result.detectedHooks.size()) * 10.0, 40.0);
                    result.detectionMethods.push_back(DetectionMethod::APIHookDetection);

                    ThreatIndicator indicator;
                    indicator.indicatorType = "API_HOOK";
                    indicator.confidence = 0.8;
                    indicator.description = "Detected " +
                        std::to_string(result.detectedHooks.size()) + " suspicious API hooks";
                    result.indicators.push_back(std::move(indicator));
                }
            }

            // 6. Network analysis
            if (localCfg.enableNetworkMonitoring) {
                auto connections = AnalyzeNetworkConnections(processId);
                bool hasC2 = false;
                for (const auto& conn : connections) {
                    if (conn.isC2) { hasC2 = true; break; }
                }
                if (hasC2) {
                    result.networkConnections = std::move(connections);
                    result.threatScore += 35.0;
                    result.detectionMethods.push_back(DetectionMethod::NetworkAnalysis);

                    ThreatIndicator indicator;
                    indicator.indicatorType = "C2_COMMS";
                    indicator.confidence = 0.85;
                    indicator.description = "Detected C2 communication pattern";
                    result.indicators.push_back(std::move(indicator));
                }
            }

            // 7. Web injection detection (browser processes only)
            if (localCfg.enableWebInjectDetection && IsBrowserProcess(basicInfo.name)) {
                auto injections = DetectWebInjections(processId);
                if (!injections.empty()) {
                    result.webInjections = std::move(injections);
                    result.threatScore += 30.0;
                    result.detectionMethods.push_back(DetectionMethod::WebInjectDetection);

                    ThreatIndicator indicator;
                    indicator.indicatorType = "WEB_INJECT";
                    indicator.confidence = 0.9;
                    indicator.description = "Web injection detected in browser process";
                    result.indicators.push_back(std::move(indicator));
                }
            }

            // 8. Clamp and finalize score
            result.threatScore = ClampScore(result.threatScore);
            result.confidenceScore = result.indicators.empty() ? 0.0 :
                [&result]() {
                    double sum = 0.0;
                    for (const auto& ind : result.indicators)
                        sum += ind.confidence;
                    return sum / static_cast<double>(result.indicators.size());
                }();

            // 9. Threshold check
            if (result.threatScore >= localCfg.threatScoreThreshold &&
                result.confidenceScore >= localCfg.confidenceThreshold) {
                result.isThreatDetected = true;
                result.severity = DetermineSeverity(result.threatScore);
                result.family = IdentifyFamily(processId);
                result.familyName = std::string(GetTrojanFamilyName(result.family));
                result.detectionTime = std::chrono::system_clock::now();
                result.detectionId = GenerateDetectionId(processId);

                SS_LOG_WARN(LOG_CATEGORY,
                    L"Banking trojan detected: PID=%u name=%ls family=%hs score=%.1f severity=%hs",
                    processId, basicInfo.name.c_str(),
                    result.familyName.c_str(), result.threatScore,
                    std::string(GetSeverityName(result.severity)).c_str());

                // Remediation
                if (localCfg.autoQuarantine) {
                    if (QuarantineProcess(processId)) {
                        result.actionTaken = DetectionAction::Quarantine;
                        m_stats.threatsQuarantined.fetch_add(1, std::memory_order_relaxed);
                    } else {
                        SS_LOG_ERROR(LOG_CATEGORY, L"Quarantine failed for PID %u", processId);
                        result.actionTaken = DetectionAction::Alert;
                    }
                } else if (localCfg.autoTerminate) {
                    if (TerminateProcessById(processId)) {
                        result.actionTaken = DetectionAction::Terminate;
                    } else {
                        SS_LOG_ERROR(LOG_CATEGORY, L"Terminate failed for PID %u", processId);
                        result.actionTaken = DetectionAction::Alert;
                    }
                } else {
                    result.actionTaken = DetectionAction::Alert;
                }

                // Track stats
                m_stats.threatsDetected.fetch_add(1, std::memory_order_relaxed);
                m_stats.byFamily[SafeFamilyIndex(result.family)].fetch_add(1, std::memory_order_relaxed);
                for (const auto& dm : result.detectionMethods) {
                    m_stats.byMethod[SafeMethodIndex(dm)].fetch_add(1, std::memory_order_relaxed);
                }
                AtomicValueStoreRelaxed(m_stats.lastDetectionTime, std::chrono::system_clock::now());

                // Save to history
                {
                    std::unique_lock hLock(m_historyMutex);
                    m_recentDetections.push_back(result);
                    while (m_recentDetections.size() > 1000) {
                        m_recentDetections.pop_front();
                    }
                }

                // Invoke callback outside all locks
                NotifyDetection(result);
            }

        } catch (const std::exception& ex) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Analysis failed for PID %u: %hs", processId, ex.what());
            NotifyError("Analysis exception: " + std::string(ex.what()), -1);
        }

        result.analysisDuration = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start);
        m_stats.totalScans.fetch_add(1, std::memory_order_relaxed);
        return result;
    }

    [[nodiscard]] DetectionResult AnalyzeProcessByName(std::wstring_view processName) {
        std::vector<Utils::ProcessUtils::ProcessBasicInfo> processes;
        Utils::ProcessUtils::EnumerationOptions opts;
        opts.nameFilter = std::wstring(processName);
        Utils::ProcessUtils::Error err;

        if (!Utils::ProcessUtils::EnumerateProcesses(processes, opts, &err) || processes.empty()) {
            SS_LOG_WARN(LOG_CATEGORY, L"No processes found matching name: %ls",
                        std::wstring(processName).c_str());
            return {};
        }

        // Analyze the first match
        return AnalyzeProcess(processes.front().pid);
    }

    [[nodiscard]] DetectionResult AnalyzeProcessByPath(const std::filesystem::path& path) {
        std::vector<Utils::ProcessUtils::ProcessId> pids;
        Utils::ProcessUtils::Error err;
        if (!Utils::ProcessUtils::EnumerateProcesses(pids, &err)) {
            return {};
        }

        std::error_code pathEc;
        const auto canonicalTarget = std::filesystem::weakly_canonical(path, pathEc);
        if (pathEc) {
            SS_LOG_WARN(LOG_CATEGORY,
                L"AnalyzeProcessByPath rejected non-canonical path: %ls (%hs)",
                path.c_str(), pathEc.message().c_str());
            return {};
        }
        for (const auto pid : pids) {
            auto procPath = Utils::ProcessUtils::GetProcessPath(pid);
            if (procPath.has_value()) {
                std::error_code procEc;
                if (std::filesystem::weakly_canonical(procPath.value(), procEc) == canonicalTarget &&
                    !procEc) {
                    return AnalyzeProcess(pid);
                }
            }
        }

        SS_LOG_WARN(LOG_CATEGORY, L"No running process matches path: %ls", path.c_str());
        return {};
    }

    [[nodiscard]] std::vector<DetectionResult> ScanAllProcesses() {
        std::vector<DetectionResult> results;
        std::vector<Utils::ProcessUtils::ProcessId> pids;
        Utils::ProcessUtils::Error err;

        if (!Utils::ProcessUtils::EnumerateProcesses(pids, &err)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Failed to enumerate processes for full scan");
            return results;
        }

        const size_t count = std::min(pids.size(), BankingTrojanConstants::MAX_PROCESS_SCAN_COUNT);
        results.reserve(count);

        for (size_t i = 0; i < count; ++i) {
            if (!m_running.load(std::memory_order_acquire)) break;
            auto r = AnalyzeProcess(pids[i]);
            if (r.isThreatDetected) {
                results.push_back(std::move(r));
            }
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Full scan complete: %zu processes scanned, %zu threats",
                     count, results.size());
        return results;
    }

    [[nodiscard]] std::vector<DetectionResult> ScanBrowserProcesses() {
        std::vector<DetectionResult> results;
        std::vector<Utils::ProcessUtils::ProcessBasicInfo> processes;
        Utils::ProcessUtils::EnumerationOptions opts;
        Utils::ProcessUtils::Error err;

        if (!Utils::ProcessUtils::EnumerateProcesses(processes, opts, &err)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Failed to enumerate processes for browser scan");
            return results;
        }

        for (const auto& proc : processes) {
            if (!m_running.load(std::memory_order_acquire)) break;
            if (IsBrowserProcess(proc.name)) {
                auto r = AnalyzeProcess(proc.pid);
                if (r.isThreatDetected) {
                    results.push_back(std::move(r));
                }
            }
        }

        return results;
    }

    // ========================================================================
    // MEMORY ANALYSIS
    // ========================================================================

    [[nodiscard]] DetectionResult AnalyzeProcessMemory(uint32_t processId) {
        DetectionResult result;
        result.processInfo.pid = processId;

        HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                        FALSE, processId);
        if (!hProcess) {
            SS_LOG_DEBUG(LOG_CATEGORY, L"Cannot open PID %u for memory scan (access denied or exited)",
                         processId);
            return result;
        }

        // RAII handle guard
        struct HandleGuard {
            HANDLE h;
            ~HandleGuard() { if (h) ::CloseHandle(h); }
        } guard{hProcess};

        MEMORY_BASIC_INFORMATION mbi{};
        uint8_t* address = nullptr;
        size_t regionsScanned = 0;

        while (regionsScanned < BankingTrojanConstants::MAX_MEMORY_REGIONS) {
            if (!::VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)))
                break;

            const bool isCommitted = (mbi.State == MEM_COMMIT);
            const bool isExecutable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                       PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
            const bool isRWX = (mbi.Protect & PAGE_EXECUTE_READWRITE) != 0;
            const bool isPrivate = (mbi.Type == MEM_PRIVATE);

            if (isCommitted && (isRWX || (isExecutable && isPrivate)) &&
                mbi.RegionSize > 0 && mbi.RegionSize <= (64 * 1024 * 1024)) {
                // Read a sample of the region for entropy + shellcode check
                const SIZE_T sampleSize = static_cast<SIZE_T>(
                    std::min<uint64_t>(mbi.RegionSize, MEM_SCAN_CHUNK));
                std::vector<uint8_t> buffer(sampleSize);
                SIZE_T bytesRead = 0;

                if (::ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(),
                                        sampleSize, &bytesRead) && bytesRead > 0) {
                    buffer.resize(bytesRead);
                    const double entropy = ComputeEntropy(buffer.data(), bytesRead);

                    MemoryRegionInfo region;
                    region.baseAddress = reinterpret_cast<uint64_t>(mbi.BaseAddress);
                    region.regionSize = mbi.RegionSize;
                    region.protection = mbi.Protect;
                    region.state = mbi.State;
                    region.type = mbi.Type;
                    region.isExecutable = isExecutable;
                    region.isPrivate = isPrivate;
                    region.entropy = entropy;

                    bool suspicious = false;

                    // RWX private memory with high entropy is highly suspicious
                    if (isRWX && isPrivate && entropy > 6.0) {
                        suspicious = true;
                        region.hasShellcode = DetectShellcodeInBuffer(buffer);
                    }

                    // Executable private memory with high entropy (packed/encrypted code)
                    if (isExecutable && isPrivate && entropy > 7.0) {
                        suspicious = true;
                    }

                    if (suspicious) {
                        result.suspiciousMemory.push_back(std::move(region));
                        if (result.suspiciousMemory.size() >= BankingTrojanConstants::MAX_MEMORY_REGIONS) {
                            break;
                        }
                    }
                }
            }

            // Advance to next region, guarding against wraparound
            if (!AdvanceRegionAddress(address, mbi)) break;
            ++regionsScanned;
        }

        if (!result.suspiciousMemory.empty()) {
            result.isThreatDetected = true;
            result.threatScore = std::min(
                static_cast<double>(result.suspiciousMemory.size()) * 12.0, 35.0);

            ThreatIndicator indicator;
            indicator.indicatorType = "SUSPICIOUS_MEMORY";
            indicator.confidence = 0.7;
            indicator.description = std::to_string(result.suspiciousMemory.size()) +
                " suspicious memory region(s): RWX/high-entropy private";
            result.indicators.push_back(std::move(indicator));
        }

        return result;
    }

    [[nodiscard]] std::vector<MemoryRegionInfo> ScanMemoryRegions(uint32_t processId) {
        auto memResult = AnalyzeProcessMemory(processId);
        return std::move(memResult.suspiciousMemory);
    }

    [[nodiscard]] bool DetectShellcode(uint32_t processId, uint64_t address, size_t size) {
        if (size == 0 || size > (64 * 1024 * 1024)) return false;

        HANDLE hProcess = ::OpenProcess(PROCESS_VM_READ, FALSE, processId);
        if (!hProcess) return false;

        struct HandleGuard {
            HANDLE h;
            ~HandleGuard() { if (h) ::CloseHandle(h); }
        } guard{hProcess};

        const SIZE_T readSize = static_cast<SIZE_T>(std::min<size_t>(size, MEM_SCAN_CHUNK));
        std::vector<uint8_t> buffer(readSize);
        SIZE_T bytesRead = 0;

        if (!::ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(address),
                                 buffer.data(), readSize, &bytesRead) || bytesRead == 0) {
            return false;
        }
        buffer.resize(bytesRead);
        return DetectShellcodeInBuffer(buffer);
    }

    // ========================================================================
    // HOOK DETECTION
    // ========================================================================

    [[nodiscard]] std::vector<ApiHookInfo> DetectAPIHooks(uint32_t processId) {
        std::vector<ApiHookInfo> hooks;

        std::vector<Utils::ProcessUtils::ProcessModuleInfo> modules;
        Utils::ProcessUtils::Error err;
        if (!Utils::ProcessUtils::EnumerateProcessModules(
                static_cast<Utils::ProcessUtils::ProcessId>(processId), modules, &err)) {
            return hooks;
        }

        // Critical DLLs commonly hooked by banking trojans
        static constexpr std::wstring_view criticalModules[] = {
            L"ntdll.dll", L"kernel32.dll", L"kernelbase.dll",
            L"ws2_32.dll", L"wininet.dll", L"winhttp.dll",
            L"crypt32.dll", L"advapi32.dll", L"user32.dll"
        };

        for (const auto& mod : modules) {
            bool isCritical = false;
            for (const auto& cm : criticalModules) {
                if (Utils::StringUtils::IEquals(mod.name, cm)) {
                    isCritical = true;
                    break;
                }
            }
            if (!isCritical) continue;

            // Compare in-memory module prologue bytes against on-disk image
            auto diskHooks = CheckModuleForHooks(processId, mod);
            for (auto& h : diskHooks) {
                hooks.push_back(std::move(h));
                if (hooks.size() >= BankingTrojanConstants::MAX_HOOKED_FUNCTIONS) {
                    return hooks;
                }
            }
        }

        return hooks;
    }

    [[nodiscard]] std::vector<ApiHookInfo> DetectModuleHooks(
        uint32_t processId, std::wstring_view moduleName) {
        std::vector<Utils::ProcessUtils::ProcessModuleInfo> modules;
        Utils::ProcessUtils::Error err;
        if (!Utils::ProcessUtils::EnumerateProcessModules(
                static_cast<Utils::ProcessUtils::ProcessId>(processId), modules, &err)) {
            return {};
        }

        for (const auto& mod : modules) {
            if (Utils::StringUtils::IEquals(mod.name, moduleName)) {
                return CheckModuleForHooks(processId, mod);
            }
        }
        return {};
    }

    [[nodiscard]] bool RestoreHook(uint32_t processId, const ApiHookInfo& hook) {
        if (hook.originalAddress == 0 || hook.functionName.empty()) {
            SS_LOG_WARN(LOG_CATEGORY, L"Cannot restore hook: invalid hook info");
            return false;
        }

        // Read on-disk original bytes for the function prologue
        auto moduleBase = Utils::ProcessUtils::GetModuleBaseAddress(
            static_cast<Utils::ProcessUtils::ProcessId>(processId), hook.moduleName);
        if (!moduleBase.has_value()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Cannot find module %ls in PID %u for hook restore",
                         std::wstring(hook.moduleName).c_str(), processId);
            return false;
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Hook restoration requested for %hs in PID %u — requires elevated PROCESS_VM_WRITE",
                     hook.functionName.c_str(), processId);

        SS_LOG_WARN(LOG_CATEGORY,
            L"Hook restore is refused without verified original prologue bytes for %hs in PID %u (module base=%p)",
            hook.functionName.c_str(), processId, moduleBase.value());
        return false;
    }

    // ========================================================================
    // WEB INJECTION DETECTION
    // ========================================================================

    [[nodiscard]] std::vector<WebInjectionInfo> DetectWebInjections(uint32_t processId) {
        std::vector<WebInjectionInfo> injections;

        // Only scan browser processes
        auto procName = Utils::ProcessUtils::GetProcessName(
            static_cast<Utils::ProcessUtils::ProcessId>(processId));
        if (!procName.has_value() || !IsBrowserProcess(procName.value())) {
            return injections;
        }

        // Scan process memory for common web inject signatures
        HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                        FALSE, processId);
        if (!hProcess) return injections;

        struct HandleGuard {
            HANDLE h;
            ~HandleGuard() { if (h) ::CloseHandle(h); }
        } guard{hProcess};

        // Known web inject patterns (form grabber signatures)
        static constexpr const char* INJECT_PATTERNS[] = {
            "data_before", "data_after", "data_inject",   // Zeus-style config
            "set_url", "data_end",                        // Zeus/SpyEye web inject format
            "grabber", "formgrab",                        // Generic form grabber
            "document.forms", "XMLHttpRequest",           // JS injection patterns
        };

        MEMORY_BASIC_INFORMATION mbi{};
        uint8_t* addr = nullptr;
        size_t regionsScanned = 0;

        while (regionsScanned < BankingTrojanConstants::MAX_MEMORY_REGIONS / 2) {
            if (!::VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)))
                break;

            if (mbi.State == MEM_COMMIT && mbi.RegionSize > 0 &&
                mbi.RegionSize <= (16 * 1024 * 1024) &&
                (mbi.Protect & PAGE_READWRITE) != 0) {

                const SIZE_T readSize = static_cast<SIZE_T>(
                    std::min<uint64_t>(mbi.RegionSize, 8192));
                std::vector<uint8_t> buffer(readSize);
                SIZE_T bytesRead = 0;

                if (::ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(),
                                        readSize, &bytesRead) && bytesRead > 0) {
                    std::string_view content(
                        reinterpret_cast<const char*>(buffer.data()), bytesRead);

                    for (const auto* pattern : INJECT_PATTERNS) {
                        if (content.find(pattern) != std::string_view::npos) {
                            WebInjectionInfo info;
                            info.injectType = WebInjectType::FormGrabber;
                            info.targetDomain = "detected-in-memory";
                            info.isActive = true;
                            info.detectionTime = std::chrono::system_clock::now();

                            injections.push_back(std::move(info));

                            if (injections.size() >= BankingTrojanConstants::MAX_WEB_INJECTIONS) {
                                return injections;
                            }
                            break; // One match per region is sufficient
                        }
                    }
                }
            }

            if (!AdvanceRegionAddress(addr, mbi)) break;
            ++regionsScanned;
        }

        return injections;
    }

    [[nodiscard]] bool DetectFormGrabber(uint32_t processId) {
        auto injections = DetectWebInjections(processId);
        return std::any_of(injections.begin(), injections.end(),
            [](const WebInjectionInfo& info) {
                return info.injectType == WebInjectType::FormGrabber;
            });
    }

    // ========================================================================
    // NETWORK ANALYSIS
    // ========================================================================

    [[nodiscard]] std::vector<NetworkConnectionInfo> AnalyzeNetworkConnections(uint32_t processId) {
        std::vector<NetworkConnectionInfo> results;

        // Use GetExtendedTcpTable to get per-process TCP connections
        DWORD tableSize = 0;
        DWORD status = ::GetExtendedTcpTable(nullptr, &tableSize, FALSE, AF_INET,
                                             TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
        if (status != ERROR_INSUFFICIENT_BUFFER || tableSize == 0 ||
            tableSize > MAX_TCP_TABLE_BYTES) {
            SS_LOG_WARN(LOG_CATEGORY,
                L"GetExtendedTcpTable size query rejected: status=%lu bytes=%lu",
                status, tableSize);
            return results;
        }

        std::vector<uint8_t> tableBuffer(tableSize);
        status = ::GetExtendedTcpTable(tableBuffer.data(), &tableSize, FALSE, AF_INET,
                                       TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
        if (status == ERROR_INSUFFICIENT_BUFFER && tableSize > 0 &&
            tableSize <= MAX_TCP_TABLE_BYTES) {
            tableBuffer.resize(tableSize);
            status = ::GetExtendedTcpTable(tableBuffer.data(), &tableSize, FALSE, AF_INET,
                                           TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
        }
        if (status != NO_ERROR || tableSize < sizeof(DWORD)) {
            return results;
        }

        const auto* tcpTable = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(tableBuffer.data());
        const size_t maxRowsBySize =
            (tableSize >= offsetof(MIB_TCPTABLE_OWNER_PID, table))
                ? ((tableSize - offsetof(MIB_TCPTABLE_OWNER_PID, table)) /
                   sizeof(MIB_TCPROW_OWNER_PID))
                : 0;
        if (tcpTable->dwNumEntries > maxRowsBySize) {
            SS_LOG_WARN(LOG_CATEGORY,
                L"TCP table row count exceeds buffer bounds: rows=%lu max=%zu",
                tcpTable->dwNumEntries, maxRowsBySize);
            return results;
        }
        auto& tiMgr = ThreatIntel::ThreatIntelManager::Instance();

        for (DWORD i = 0; i < tcpTable->dwNumEntries && results.size() < BankingTrojanConstants::MAX_C2_SERVERS; ++i) {
            const auto& row = tcpTable->table[i];
            if (row.dwOwningPid != processId) continue;
            if (row.dwState != MIB_TCP_STATE_ESTAB) continue;

            IN_ADDR remoteAddr;
            remoteAddr.S_un.S_addr = row.dwRemoteAddr;
            char ipBuf[INET_ADDRSTRLEN]{};
            ::inet_ntop(AF_INET, &remoteAddr, ipBuf, sizeof(ipBuf));

            NetworkConnectionInfo conn;
            conn.remoteIP = ipBuf;
            conn.remotePort = ntohs(static_cast<uint16_t>(row.dwRemotePort));
            conn.localPort = ntohs(static_cast<uint16_t>(row.dwLocalPort));
            conn.protocol = 6; // TCP
            conn.connectionTime = std::chrono::system_clock::now();

            // Check against ThreatIntel
            if (tiMgr.IsInitialized()) {
                auto lookup = tiMgr.LookupIP(conn.remoteIP);
                if (lookup.IsMalicious()) {
                    conn.isC2 = true;
                    SS_LOG_WARN(LOG_CATEGORY,
                        L"C2 connection detected: PID=%u -> %hs:%u",
                        processId, conn.remoteIP.c_str(), conn.remotePort);
                }
            }

            results.push_back(std::move(conn));
        }

        return results;
    }

    [[nodiscard]] bool DetectC2Communication(uint32_t processId) {
        auto connections = AnalyzeNetworkConnections(processId);
        return std::any_of(connections.begin(), connections.end(),
            [](const NetworkConnectionInfo& c) { return c.isC2; });
    }

    [[nodiscard]] std::vector<std::string> DetectDGADomains(uint32_t processId) {
        std::vector<std::string> dgaDomains;

        auto connections = AnalyzeNetworkConnections(processId);
        for (const auto& conn : connections) {
            if (conn.domainName.empty()) continue;

            // Extract the second-level domain label
            const auto lastDot = conn.domainName.rfind('.');
            if (lastDot == std::string::npos) continue;
            const auto prevDot = conn.domainName.rfind('.', lastDot - 1);
            const std::string label = (prevDot == std::string::npos)
                ? conn.domainName.substr(0, lastDot)
                : conn.domainName.substr(prevDot + 1, lastDot - prevDot - 1);

            if (label.size() < DGA_MIN_LABEL_LENGTH) continue;

            // High entropy + long random-looking label suggests DGA
            const double entropy = ComputeStringEntropy(label);
            if (entropy > DGA_ENTROPY_THRESHOLD) {
                // Additional check: ratio of consonants to vowels
                size_t vowels = 0, consonants = 0;
                for (char c : label) {
                    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                    if (c >= 'a' && c <= 'z') {
                        if (c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u')
                            ++vowels;
                        else
                            ++consonants;
                    }
                }
                const double ratio = (vowels > 0)
                    ? static_cast<double>(consonants) / static_cast<double>(vowels)
                    : 10.0;

                // Natural English ~1.5-2.0 ratio; DGA domains often >3.0
                if (ratio > 3.0) {
                    dgaDomains.push_back(conn.domainName);
                    SS_LOG_INFO(LOG_CATEGORY, L"Potential DGA domain: %hs (entropy=%.2f ratio=%.1f)",
                                conn.domainName.c_str(), entropy, ratio);
                }
            }
        }
        return dgaDomains;
    }

    // ========================================================================
    // FAMILY IDENTIFICATION
    // ========================================================================

    [[nodiscard]] TrojanFamily IdentifyFamily(uint32_t processId) {
        // Check memory for known family-specific signatures
        HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                        FALSE, processId);
        if (!hProcess) return TrojanFamily::Unknown;

        struct HandleGuard {
            HANDLE h;
            ~HandleGuard() { if (h) ::CloseHandle(h); }
        } guard{hProcess};

        // Known family markers (mutex names, strings, config patterns)
        struct FamilyMarker {
            const char* pattern;
            TrojanFamily family;
        };
        static constexpr FamilyMarker markers[] = {
            {"__SYSTEM__",          TrojanFamily::Zeus},
            {"_AVIRA_",             TrojanFamily::Zeus},
            {".bit/",              TrojanFamily::Dridex},
            {"mrk_",               TrojanFamily::QakBot},
            {"GOLD",               TrojanFamily::Emotet},
            {"moduleconfig",       TrojanFamily::TrickBot},
            {"injectDll",          TrojanFamily::TrickBot},
            {"CBID",               TrojanFamily::Carberp},
            {"formgrabber32.dll",  TrojanFamily::Ramnit},
            {"botid=",             TrojanFamily::Gozi},
            {"gate.php",           TrojanFamily::Citadel},
        };

        MEMORY_BASIC_INFORMATION mbi{};
        uint8_t* addr = nullptr;
        size_t scanned = 0;
        constexpr size_t MAX_REGIONS = 2048;

        while (scanned < MAX_REGIONS) {
            if (!::VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)))
                break;

            if (mbi.State == MEM_COMMIT && mbi.RegionSize > 0 &&
                mbi.RegionSize <= (8 * 1024 * 1024)) {

                const SIZE_T readSize = static_cast<SIZE_T>(
                    std::min<uint64_t>(mbi.RegionSize, 4096));
                std::vector<uint8_t> buffer(readSize);
                SIZE_T bytesRead = 0;

                if (::ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(),
                                        readSize, &bytesRead) && bytesRead > 32) {
                    std::string_view content(
                        reinterpret_cast<const char*>(buffer.data()), bytesRead);

                    for (const auto& marker : markers) {
                        if (content.find(marker.pattern) != std::string_view::npos) {
                            SS_LOG_INFO(LOG_CATEGORY,
                                L"Family identified for PID %u: %hs (marker: %hs)",
                                processId,
                                std::string(GetTrojanFamilyName(marker.family)).c_str(),
                                marker.pattern);
                            return marker.family;
                        }
                    }
                }
            }

            if (!AdvanceRegionAddress(addr, mbi)) break;
            ++scanned;
        }

        return TrojanFamily::Unknown;
    }

    // ========================================================================
    // REMEDIATION
    // ========================================================================

    [[nodiscard]] bool QuarantineProcess(uint32_t processId) {
        SS_LOG_INFO(LOG_CATEGORY, L"Quarantining PID %u", processId);

        // 1. Suspend first to prevent further damage
        Utils::ProcessUtils::Error err;
        if (!Utils::ProcessUtils::SuspendProcess(
                static_cast<Utils::ProcessUtils::ProcessId>(processId), &err)) {
            SS_LOG_WARN(LOG_CATEGORY, L"Could not suspend PID %u prior to quarantine", processId);
        }

        // 2. Collect evidence: get path before termination
        auto procPath = Utils::ProcessUtils::GetProcessPath(
            static_cast<Utils::ProcessUtils::ProcessId>(processId));

        // 3. Terminate the process
        if (!Utils::ProcessUtils::TerminateProcess(
                static_cast<Utils::ProcessUtils::ProcessId>(processId), 1, &err)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Failed to terminate PID %u during quarantine", processId);
            // Attempt resume if terminate failed so we don't leave it suspended
            if (!Utils::ProcessUtils::ResumeProcess(
                    static_cast<Utils::ProcessUtils::ProcessId>(processId), &err)) {
                SS_LOG_ERROR(LOG_CATEGORY,
                    L"Failed to resume PID %u after quarantine termination failure: %hs",
                    processId, err.message.c_str());
            }
            return false;
        }

        SS_LOG_INFO(LOG_CATEGORY, L"PID %u terminated for quarantine", processId);

        // 4. If we have the executable path, log it for quarantine manager
        if (procPath.has_value() && !procPath.value().empty()) {
            SS_LOG_INFO(LOG_CATEGORY, L"Quarantine target: %ls", procPath.value().c_str());
            // The actual file quarantine (encrypt+move) is handled by the
            // QuarantineManager subsystem, which is notified via the detection callback.
        }

        return true;
    }

    [[nodiscard]] bool TerminateProcessById(uint32_t processId) {
        SS_LOG_INFO(LOG_CATEGORY, L"Terminating PID %u", processId);
        Utils::ProcessUtils::Error err;
        if (!Utils::ProcessUtils::TerminateProcess(
                static_cast<Utils::ProcessUtils::ProcessId>(processId), 1, &err)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Failed to terminate PID %u", processId);
            return false;
        }
        return true;
    }

    [[nodiscard]] bool RemovePersistence(uint32_t processId) {
        bool anyRemoved = false;

        // Get the executable path to match against persistence entries
        auto procPath = Utils::ProcessUtils::GetProcessPath(
            static_cast<Utils::ProcessUtils::ProcessId>(processId));
        if (!procPath.has_value() || procPath.value().empty()) {
            SS_LOG_WARN(LOG_CATEGORY, L"Cannot resolve PID %u path for persistence removal", processId);
            return false;
        }

        const std::wstring targetPath = procPath.value();
        const std::wstring targetPathLower = Utils::StringUtils::ToLowerCopy(targetPath);

        // Check HKCU and HKLM Run keys
        const HKEY roots[] = { HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE };

        for (HKEY root : roots) {
            for (const auto* keyPath : PERSISTENCE_RUN_KEYS) {
                Utils::RegistryUtils::RegistryKey regKey;
                Utils::RegistryUtils::Error regErr;
                Utils::RegistryUtils::OpenOptions opts;
                opts.access = KEY_READ | KEY_WRITE;

                if (!regKey.Open(root, keyPath, opts)) continue;

                std::vector<Utils::RegistryUtils::ValueInfo> values;
                if (!regKey.EnumValues(values)) continue;

                for (const auto& val : values) {
                    std::wstring data;
                    if (!regKey.ReadString(val.name, data)) continue;

                    const std::wstring dataLower = Utils::StringUtils::ToLowerCopy(data);
                    if (dataLower.find(targetPathLower) != std::wstring::npos) {
                        if (regKey.DeleteValue(val.name)) {
                            SS_LOG_INFO(LOG_CATEGORY,
                                L"Removed persistence entry: %ls\\%ls",
                                keyPath, val.name.c_str());
                            anyRemoved = true;
                        }
                    }
                }
            }
        }

        if (anyRemoved) {
            SS_LOG_INFO(LOG_CATEGORY, L"Persistence removal complete for PID %u", processId);
        }
        return anyRemoved;
    }

    [[nodiscard]] bool Remediate(const DetectionResult& detection) {
        if (!detection.isThreatDetected) return true;

        bool success = true;
        const uint32_t pid = detection.processInfo.pid;
        SS_LOG_INFO(LOG_CATEGORY, L"Starting full remediation for PID %u (%hs)",
                     pid, detection.familyName.c_str());

        // 1. Remove persistence before killing (so the process can't restart)
        BankingTrojanDetectorConfiguration localCfg;
        {
            std::shared_lock lock(m_mutex);
            localCfg = m_config;
        }

        if (localCfg.removePersistence) {
            if (!RemovePersistence(pid)) {
                SS_LOG_WARN(LOG_CATEGORY, L"Persistence removal incomplete for PID %u", pid);
            }
        }

        // 2. Quarantine the process
        if (!QuarantineProcess(pid)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Quarantine failed for PID %u — attempting terminate", pid);
            if (!TerminateProcessById(pid)) {
                success = false;
            }
        }

        if (success) {
            m_stats.threatsRemediated.fetch_add(1, std::memory_order_relaxed);
            SS_LOG_INFO(LOG_CATEGORY, L"Remediation complete for PID %u", pid);
        }
        return success;
    }

    // ========================================================================
    // WHITELIST
    // ========================================================================

    [[nodiscard]] bool IsWhitelisted(uint32_t processId) const {
        auto procName = Utils::ProcessUtils::GetProcessName(
            static_cast<Utils::ProcessUtils::ProcessId>(processId));
        if (!procName.has_value()) return false;

        std::shared_lock lock(m_mutex);
        const std::wstring nameLower = Utils::StringUtils::ToLowerCopy(procName.value());
        return m_whitelist.count(nameLower) > 0;
    }

    void AddToWhitelist(uint32_t processId, const std::string& reason) {
        auto procName = Utils::ProcessUtils::GetProcessName(
            static_cast<Utils::ProcessUtils::ProcessId>(processId));
        if (!procName.has_value()) {
            SS_LOG_WARN(LOG_CATEGORY, L"Cannot whitelist PID %u: name resolution failed", processId);
            return;
        }
        const std::wstring nameLower = Utils::StringUtils::ToLowerCopy(procName.value());

        std::unique_lock lock(m_mutex);
        m_whitelist.insert(nameLower);
        SS_LOG_INFO(LOG_CATEGORY, L"Whitelisted process %ls (PID %u): %hs",
                     nameLower.c_str(), processId, reason.c_str());
    }

    void RemoveFromWhitelist(uint32_t processId) {
        auto procName = Utils::ProcessUtils::GetProcessName(
            static_cast<Utils::ProcessUtils::ProcessId>(processId));
        if (!procName.has_value()) return;

        const std::wstring nameLower = Utils::StringUtils::ToLowerCopy(procName.value());
        std::unique_lock lock(m_mutex);
        m_whitelist.erase(nameLower);
        SS_LOG_INFO(LOG_CATEGORY, L"Removed %ls from whitelist", nameLower.c_str());
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void RegisterDetectionCallback(DetectionCallback cb) {
        std::unique_lock lock(m_callbackMutex);
        m_detectionCallback = std::move(cb);
    }

    void RegisterErrorCallback(ErrorCallback cb) {
        std::unique_lock lock(m_callbackMutex);
        m_errorCallback = std::move(cb);
    }

    void UnregisterCallbacks() {
        std::unique_lock lock(m_callbackMutex);
        m_detectionCallback = nullptr;
        m_errorCallback = nullptr;
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] DetectionStatisticsSnapshot GetStatisticsSnapshot() const noexcept {
        DetectionStatisticsSnapshot snap;
        snap.totalScans         = m_stats.totalScans.load(std::memory_order_relaxed);
        snap.threatsDetected    = m_stats.threatsDetected.load(std::memory_order_relaxed);
        snap.threatsQuarantined = m_stats.threatsQuarantined.load(std::memory_order_relaxed);
        snap.threatsRemediated  = m_stats.threatsRemediated.load(std::memory_order_relaxed);
        snap.falsePositives     = m_stats.falsePositives.load(std::memory_order_relaxed);
        snap.whitelistHits      = m_stats.whitelistHits.load(std::memory_order_relaxed);
        for (size_t i = 0; i < 32; ++i)
            snap.byFamily[i] = m_stats.byFamily[i].load(std::memory_order_relaxed);
        for (size_t i = 0; i < 16; ++i)
            snap.byMethod[i] = m_stats.byMethod[i].load(std::memory_order_relaxed);
        snap.startTime = AtomicValueLoadRelaxed(m_stats.startTime);
        snap.lastDetectionTime = AtomicValueLoadRelaxed(m_stats.lastDetectionTime);
        return snap;
    }

    void ResetStatistics() noexcept {
        m_stats.Reset();
        SS_LOG_INFO(LOG_CATEGORY, L"Statistics reset");
    }

    [[nodiscard]] std::vector<DetectionResult> GetRecentDetections(size_t maxCount) const {
        std::shared_lock lock(m_historyMutex);
        std::vector<DetectionResult> results;
        const size_t count = std::min(maxCount, m_recentDetections.size());
        results.reserve(count);

        auto it = m_recentDetections.rbegin();
        for (size_t i = 0; i < count && it != m_recentDetections.rend(); ++i, ++it) {
            results.push_back(*it);
        }
        return results;
    }

    // ========================================================================
    // INTERNAL: SCANNING LOOP
    // ========================================================================

    void ScanningLoop() {
        SS_LOG_INFO(LOG_CATEGORY, L"Real-time scanning thread started");

        while (m_running.load(std::memory_order_acquire)) {
            // Skip work if paused
            if (m_status.load(std::memory_order_acquire) == ModuleStatus::Paused) {
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(BankingTrojanConstants::REAL_TIME_SCAN_INTERVAL_MS));
                continue;
            }

            try {
                // Enumerate and scan browser processes
                std::vector<Utils::ProcessUtils::ProcessBasicInfo> processes;
                Utils::ProcessUtils::EnumerationOptions opts;
                Utils::ProcessUtils::Error err;

                if (Utils::ProcessUtils::EnumerateProcesses(processes, opts, &err)) {
                    for (const auto& proc : processes) {
                        if (!m_running.load(std::memory_order_acquire)) break;
                        if (m_status.load(std::memory_order_acquire) == ModuleStatus::Paused) break;

                        if (IsBrowserProcess(proc.name)) {
                            (void)AnalyzeProcess(proc.pid);
                        }
                    }
                }
            } catch (const std::exception& ex) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Scanning loop error: %hs", ex.what());
                NotifyError("Scanning loop exception: " + std::string(ex.what()), -2);
            }

            std::this_thread::sleep_for(
                std::chrono::milliseconds(BankingTrojanConstants::REAL_TIME_SCAN_INTERVAL_MS));
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Real-time scanning thread stopped");
    }

private:
    // ========================================================================
    // INTERNAL HELPERS
    // ========================================================================

    /// Detect shellcode patterns in a memory buffer.
    [[nodiscard]] static bool DetectShellcodeInBuffer(const std::vector<uint8_t>& buffer) noexcept {
        if (buffer.size() < MIN_NOP_SLED_LENGTH) return false;

        // Check for NOP sled (0x90 runs)
        size_t nopRun = 0;
        for (const auto b : buffer) {
            if (b == 0x90) {
                if (++nopRun >= MIN_NOP_SLED_LENGTH) return true;
            } else {
                nopRun = 0;
            }
        }

        // Check for common x86/x64 shellcode prologue patterns
        // These byte sequences appear at the start of many shellcode payloads
        if (buffer.size() >= 4) {
            // "call $+5; pop reg" — classic position-independent code
            if (buffer[0] == 0xE8 && buffer[1] == 0x00 && buffer[2] == 0x00 &&
                buffer[3] == 0x00 && buffer.size() > 4 && buffer[4] == 0x00) {
                if (buffer.size() > 5 && (buffer[5] & 0xF8) == 0x58) { // POP r32
                    return true;
                }
            }

            // "push byte XX; pop eax" shellcode pattern
            if (buffer[0] == 0x6A && buffer[2] == 0x58) {
                return true;
            }
        }

        // Check for high density of typical syscall/interrupt instructions
        size_t syscallCount = 0;
        for (size_t i = 0; i + 1 < buffer.size(); ++i) {
            if ((buffer[i] == 0xCD && buffer[i + 1] == 0x2E) ||   // INT 0x2E
                (buffer[i] == 0x0F && buffer[i + 1] == 0x05) ||   // SYSCALL
                (buffer[i] == 0x0F && buffer[i + 1] == 0x34)) {   // SYSENTER
                ++syscallCount;
            }
        }
        if (syscallCount >= 3) return true;

        return false;
    }

    /// Compare module in-memory function prologues against on-disk image.
    [[nodiscard]] std::vector<ApiHookInfo> CheckModuleForHooks(
        uint32_t processId,
        const Utils::ProcessUtils::ProcessModuleInfo& mod) {
        std::vector<ApiHookInfo> hooks;

        if (!mod.baseAddress || mod.path.empty()) return hooks;

        // Read the first bytes of the module's text section in-process
        constexpr SIZE_T PROLOGUE_SIZE = 16;
        uint8_t inMemory[PROLOGUE_SIZE]{};
        SIZE_T bytesRead = 0;

        if (!Utils::ProcessUtils::ReadProcessMemory(
                static_cast<Utils::ProcessUtils::ProcessId>(processId),
                mod.baseAddress, inMemory, PROLOGUE_SIZE, &bytesRead) ||
            bytesRead < 5) {
            return hooks;
        }

        // Read on-disk image for comparison
        Utils::MemoryUtils::MappedView diskView;
        if (!diskView.mapReadOnly(mod.path)) {
            return hooks;
        }

        if (!diskView.valid() || diskView.size() < PROLOGUE_SIZE) {
            return hooks;
        }

        // Compare entry point bytes: a JMP or CALL at the module base suggests hook
        const auto* diskBytes = static_cast<const uint8_t*>(diskView.data());

        // Check for common hook patterns at module entry
        // 0xE9 = JMP rel32 (5-byte inline hook)
        // 0xFF 0x25 = JMP [addr] (6-byte indirect hook)
        // 0x68 ... 0xC3 = PUSH addr; RET (6-byte push-ret hook)
        if (inMemory[0] == 0xE9 && diskBytes[0] != 0xE9) {
            ApiHookInfo hook;
            hook.moduleName = mod.name;
            hook.functionName = "ModuleEntry";
            hook.hookType = HookType::InlineHook;
            hook.originalAddress = reinterpret_cast<uint64_t>(mod.baseAddress);
            hook.isMalicious = true;
            hook.confidence = 0.85;

            int32_t offset = 0;
            std::memcpy(&offset, &inMemory[1], sizeof(offset));
            hook.hookedAddress = reinterpret_cast<uint64_t>(mod.baseAddress) + 5 + offset;

            hooks.push_back(std::move(hook));
        }

        if (inMemory[0] == 0xFF && inMemory[1] == 0x25 &&
            !(diskBytes[0] == 0xFF && diskBytes[1] == 0x25)) {
            ApiHookInfo hook;
            hook.moduleName = mod.name;
            hook.functionName = "ModuleEntry";
            hook.hookType = HookType::IATHook;
            hook.originalAddress = reinterpret_cast<uint64_t>(mod.baseAddress);
            hook.isMalicious = true;
            hook.confidence = 0.80;
            hooks.push_back(std::move(hook));
        }

        return hooks;
    }

    /// Invoke detection callback safely outside any locks.
    void NotifyDetection(const DetectionResult& result) {
        DetectionCallback cb;
        {
            std::shared_lock lock(m_callbackMutex);
            cb = m_detectionCallback;
        }
        if (cb) {
            try { cb(result); }
            catch (const std::exception& ex) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Detection callback threw: %hs", ex.what());
            } catch (...) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Detection callback threw unknown exception");
            }
        }
    }

    /// Invoke error callback safely outside any locks.
    void NotifyError(const std::string& msg, int code) {
        ErrorCallback cb;
        {
            std::shared_lock lock(m_callbackMutex);
            cb = m_errorCallback;
        }
        if (cb) {
            try { cb(msg, code); }
            catch (const std::exception& ex) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Error callback threw: %hs", ex.what());
            } catch (...) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Error callback threw unknown exception");
            }
        }
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    mutable std::shared_mutex m_historyMutex;
    mutable std::shared_mutex m_callbackMutex;

    std::atomic<ModuleStatus> m_status;
    std::atomic<bool> m_initialized;
    std::atomic<bool> m_running;

    BankingTrojanDetectorConfiguration m_config;
    DetectionStatistics m_stats;

    std::deque<DetectionResult> m_recentDetections;
    std::unordered_set<std::wstring> m_whitelist;

    DetectionCallback m_detectionCallback;
    ErrorCallback m_errorCallback;

    std::thread m_scanThread;
};

// ============================================================================
// PUBLIC FACADE IMPLEMENTATION
// ============================================================================

BankingTrojanDetector& BankingTrojanDetector::Instance() noexcept {
    static BankingTrojanDetector instance;
    return instance;
}

bool BankingTrojanDetector::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

BankingTrojanDetector::BankingTrojanDetector()
    : m_impl(std::make_unique<BankingTrojanDetectorImpl>())
{
    s_instanceCreated.store(true, std::memory_order_release);
}

BankingTrojanDetector::~BankingTrojanDetector() = default;

bool BankingTrojanDetector::Initialize(const BankingTrojanDetectorConfiguration& config) {
    return m_impl->Initialize(config);
}

void BankingTrojanDetector::Shutdown() {
    m_impl->Shutdown();
}

bool BankingTrojanDetector::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

ModuleStatus BankingTrojanDetector::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

bool BankingTrojanDetector::IsRunning() const noexcept {
    return m_impl->IsRunning();
}

bool BankingTrojanDetector::Start() {
    return m_impl->Start();
}

bool BankingTrojanDetector::Stop() {
    return m_impl->Stop();
}

void BankingTrojanDetector::Pause() {
    m_impl->Pause();
}

void BankingTrojanDetector::Resume() {
    m_impl->Resume();
}

bool BankingTrojanDetector::UpdateConfiguration(const BankingTrojanDetectorConfiguration& config) {
    return m_impl->UpdateConfiguration(config);
}

BankingTrojanDetectorConfiguration BankingTrojanDetector::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

DetectionResult BankingTrojanDetector::AnalyzeProcess(uint32_t processId) {
    return m_impl->AnalyzeProcess(processId);
}

DetectionResult BankingTrojanDetector::AnalyzeProcessByName(std::wstring_view processName) {
    return m_impl->AnalyzeProcessByName(processName);
}

DetectionResult BankingTrojanDetector::AnalyzeProcessByPath(const std::filesystem::path& path) {
    return m_impl->AnalyzeProcessByPath(path);
}

std::vector<DetectionResult> BankingTrojanDetector::ScanAllProcesses() {
    return m_impl->ScanAllProcesses();
}

std::vector<DetectionResult> BankingTrojanDetector::ScanBrowserProcesses() {
    return m_impl->ScanBrowserProcesses();
}

DetectionResult BankingTrojanDetector::AnalyzeProcessMemory(uint32_t processId) {
    return m_impl->AnalyzeProcessMemory(processId);
}

std::vector<MemoryRegionInfo> BankingTrojanDetector::ScanMemoryRegions(uint32_t processId) {
    return m_impl->ScanMemoryRegions(processId);
}

bool BankingTrojanDetector::DetectShellcode(uint32_t processId, uint64_t address, size_t size) {
    return m_impl->DetectShellcode(processId, address, size);
}

std::vector<ApiHookInfo> BankingTrojanDetector::DetectAPIHooks(uint32_t processId) {
    return m_impl->DetectAPIHooks(processId);
}

std::vector<ApiHookInfo> BankingTrojanDetector::DetectModuleHooks(
    uint32_t processId, std::wstring_view moduleName) {
    return m_impl->DetectModuleHooks(processId, moduleName);
}

bool BankingTrojanDetector::RestoreHook(uint32_t processId, const ApiHookInfo& hook) {
    return m_impl->RestoreHook(processId, hook);
}

std::vector<WebInjectionInfo> BankingTrojanDetector::DetectWebInjections(uint32_t processId) {
    return m_impl->DetectWebInjections(processId);
}

bool BankingTrojanDetector::DetectFormGrabber(uint32_t processId) {
    return m_impl->DetectFormGrabber(processId);
}

std::vector<NetworkConnectionInfo> BankingTrojanDetector::AnalyzeNetworkConnections(uint32_t processId) {
    return m_impl->AnalyzeNetworkConnections(processId);
}

bool BankingTrojanDetector::DetectC2Communication(uint32_t processId) {
    return m_impl->DetectC2Communication(processId);
}

std::vector<std::string> BankingTrojanDetector::DetectDGADomains(uint32_t processId) {
    return m_impl->DetectDGADomains(processId);
}

TrojanFamily BankingTrojanDetector::IdentifyFamily(uint32_t processId) {
    return m_impl->IdentifyFamily(processId);
}

std::string_view BankingTrojanDetector::GetFamilyName(TrojanFamily family) noexcept {
    return GetTrojanFamilyName(family);
}

bool BankingTrojanDetector::QuarantineProcess(uint32_t processId) {
    return m_impl->QuarantineProcess(processId);
}

bool BankingTrojanDetector::TerminateProcess(uint32_t processId) {
    return m_impl->TerminateProcessById(processId);
}

bool BankingTrojanDetector::RemovePersistence(uint32_t processId) {
    return m_impl->RemovePersistence(processId);
}

bool BankingTrojanDetector::Remediate(const DetectionResult& detection) {
    return m_impl->Remediate(detection);
}

bool BankingTrojanDetector::IsWhitelisted(uint32_t processId) const {
    return m_impl->IsWhitelisted(processId);
}

void BankingTrojanDetector::AddToWhitelist(uint32_t processId, const std::string& reason) {
    m_impl->AddToWhitelist(processId, reason);
}

void BankingTrojanDetector::RemoveFromWhitelist(uint32_t processId) {
    m_impl->RemoveFromWhitelist(processId);
}

void BankingTrojanDetector::RegisterDetectionCallback(DetectionCallback callback) {
    m_impl->RegisterDetectionCallback(std::move(callback));
}

void BankingTrojanDetector::RegisterErrorCallback(ErrorCallback callback) {
    m_impl->RegisterErrorCallback(std::move(callback));
}

void BankingTrojanDetector::UnregisterCallbacks() {
    m_impl->UnregisterCallbacks();
}

DetectionStatisticsSnapshot BankingTrojanDetector::GetStatistics() const {
    return m_impl->GetStatisticsSnapshot();
}

void BankingTrojanDetector::ResetStatistics() {
    m_impl->ResetStatistics();
}

std::vector<DetectionResult> BankingTrojanDetector::GetRecentDetections(size_t maxCount) const {
    return m_impl->GetRecentDetections(maxCount);
}

bool BankingTrojanDetector::SelfTest() {
    SS_LOG_INFO(LOG_CATEGORY, L"Running self-test");

    // 1. Verify severity calculation
    if (DetermineSeverity(95.0) != ThreatSeverity::Critical) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Self-test FAILED: severity calculation for 95.0 != Critical");
        return false;
    }
    if (DetermineSeverity(0.0) != ThreatSeverity::None) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Self-test FAILED: severity calculation for 0.0 != None");
        return false;
    }

    // 2. Verify configuration validation
    BankingTrojanDetectorConfiguration invalidCfg;
    invalidCfg.threatScoreThreshold = 101.0;
    if (invalidCfg.IsValid()) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Self-test FAILED: config validation accepted invalid threshold");
        return false;
    }
    invalidCfg.threatScoreThreshold = 50.0;
    invalidCfg.confidenceThreshold = -1.0;
    if (invalidCfg.IsValid()) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Self-test FAILED: config validation accepted negative confidence");
        return false;
    }

    // 3. Verify threat score clamping
    DetectionResult testResult;
    testResult.detectionMethods.push_back(DetectionMethod::SignatureMatch);
    testResult.detectionMethods.push_back(DetectionMethod::ThreatIntelMatch);
    testResult.detectionMethods.push_back(DetectionMethod::NetworkAnalysis);
    const double score = CalculateThreatScore(testResult);
    if (score < 0.0 || score > MAX_THREAT_SCORE) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Self-test FAILED: threat score %.1f out of bounds", score);
        return false;
    }

    // 4. Verify browser detection
    if (!IsBrowserProcess(L"chrome.exe")) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Self-test FAILED: chrome.exe not recognized as browser");
        return false;
    }
    if (IsBrowserProcess(L"notepad.exe")) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Self-test FAILED: notepad.exe incorrectly classified as browser");
        return false;
    }

    // 5. Verify DGA entropy calculation
    const double lowEntropy = ComputeStringEntropy("google");
    const double highEntropy = ComputeStringEntropy("xq7bfm9zk3pwvn");
    if (highEntropy <= lowEntropy) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Self-test FAILED: entropy comparison incorrect");
        return false;
    }

    SS_LOG_INFO(LOG_CATEGORY, L"Self-test PASSED (all checks)");
    return true;
}

std::string BankingTrojanDetector::GetVersionString() noexcept {
    return std::to_string(BankingTrojanConstants::VERSION_MAJOR) + "." +
           std::to_string(BankingTrojanConstants::VERSION_MINOR) + "." +
           std::to_string(BankingTrojanConstants::VERSION_PATCH);
}

} // namespace Banking
} // namespace ShadowStrike
