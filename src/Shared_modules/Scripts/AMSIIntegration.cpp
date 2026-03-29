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
 * ShadowStrike NGAV - AMSI INTEGRATION MODULE IMPLEMENTATION
 * ============================================================================
 *
 * @file AMSIIntegration.cpp
 * @brief Enterprise-grade Windows Antimalware Scan Interface (AMSI) integration
 *        providing bidirectional malware scanning and bypass detection.
 *
 * This implementation provides comprehensive AMSI capabilities for enterprise
 * endpoint protection with bidirectional scanning and bypass detection.
 *
 * @author ShadowStrike Security Team
 * @version 3.1.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "pch.h"
#include "AMSIIntegration.hpp"

// ============================================================================
// WINDOWS AMSI SDK
// ============================================================================

#include <amsi.h>
#pragma comment(lib, "amsi.lib")

#include <Psapi.h>
#pragma comment(lib, "Psapi.lib")

// ============================================================================
// STANDARD LIBRARY
// ============================================================================

#include <sstream>
#include <iomanip>
#include <algorithm>
#include <random>
#include <thread>
#include <condition_variable>
#include <cwctype>
#include <unordered_set>
#include <deque>
#include <list>

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE
// ============================================================================

#include "../Utils/StringUtils.hpp"
#include "PowerShellScanner.hpp"
#include "VBScriptScanner.hpp"
#include "JavaScriptScanner.hpp"
#include "MacroDetector.hpp"
#include "../Communication/AlertSystem.hpp"
#include "../Communication/TelemetryCollector.hpp"
#include "../Communication/IPCManager.hpp"
#include "../Communication/Communication.hpp"
#include "../Whitelist/WhiteListStore.hpp"
#include "../ThreatIntel/ThreatIntelStore.hpp"

namespace ShadowStrike {
namespace Scripts {

// ============================================================================
// LOGGING CATEGORY
// ============================================================================

static constexpr const wchar_t* LOG_CATEGORY = L"AMSIIntegration";

// ============================================================================
// STATIC MEMBER INITIALIZATION
// ============================================================================

std::atomic<bool> AMSIIntegration::s_instanceCreated{false};

// ============================================================================
// EXPECTED AMSI FUNCTION PROLOGUES (x64)
// ============================================================================

namespace {

// AmsiScanBuffer expected first bytes (varies by Windows version)
// These are checked to detect inline hooking/patching
constexpr std::array<uint8_t, 8> AMSI_SCAN_BUFFER_PROLOGUE_WIN10 = {
    0x4C, 0x8B, 0xDC,       // mov r11, rsp
    0x49, 0x89, 0x5B, 0x08, // mov qword ptr [r11+8], rbx
    0x49                     // (partial next instruction)
};

constexpr std::array<uint8_t, 8> AMSI_SCAN_BUFFER_PROLOGUE_WIN11 = {
    0x48, 0x89, 0x5C, 0x24, // mov qword ptr [rsp+...], rbx
    0x08, 0x48, 0x89, 0x6C  // ...
};

// Common bypass patterns to detect
constexpr std::array<uint8_t, 3> BYPASS_PATTERN_RET = { 0xC3, 0x00, 0x00 };           // ret
constexpr std::array<uint8_t, 3> BYPASS_PATTERN_XOR_EAX = { 0x31, 0xC0, 0xC3 };       // xor eax, eax; ret
constexpr std::array<uint8_t, 5> BYPASS_PATTERN_MOV_EAX = { 0xB8, 0x57, 0x00, 0x07, 0x80 }; // mov eax, 0x80070057

// Generate unique event ID
[[nodiscard]] std::string GenerateEventId() {
    static std::atomic<uint64_t> counter{0};
    auto now = std::chrono::system_clock::now();
    auto epoch = now.time_since_epoch();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();

    std::ostringstream oss;
    oss << "AMSI-" << std::hex << std::uppercase
        << ms << "-" << counter.fetch_add(1, std::memory_order_relaxed);
    return oss.str();
}

// Get current system time point
[[nodiscard]] SystemTimePoint GetCurrentSystemTime() {
    return std::chrono::system_clock::now();
}

// Format time point to ISO 8601
[[nodiscard]] std::string FormatTimePoint(const SystemTimePoint& tp) {
    auto time_t_val = std::chrono::system_clock::to_time_t(tp);
    std::tm tm_val{};
    gmtime_s(&tm_val, &time_t_val);

    std::ostringstream oss;
    oss << std::put_time(&tm_val, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

// Escape JSON string
[[nodiscard]] std::string EscapeJsonString(const std::string& input) {
    std::ostringstream oss;
    for (char c : input) {
        switch (c) {
            case '"':  oss << "\\\""; break;
            case '\\': oss << "\\\\"; break;
            case '\b': oss << "\\b";  break;
            case '\f': oss << "\\f";  break;
            case '\n': oss << "\\n";  break;
            case '\r': oss << "\\r";  break;
            case '\t': oss << "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    oss << "\\u" << std::hex << std::setfill('0')
                        << std::setw(4) << static_cast<int>(c);
                } else {
                    oss << c;
                }
        }
    }
    return oss.str();
}

// Convert bytes to hex string
[[nodiscard]] std::string BytesToHex(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    for (uint8_t b : bytes) {
        oss << std::hex << std::setfill('0') << std::setw(2)
            << static_cast<int>(b);
    }
    return oss.str();
}

}  // anonymous namespace

// ============================================================================
// STRUCTURE JSON SERIALIZATION IMPLEMENTATIONS
// ============================================================================

[[nodiscard]] std::string AmsiSessionInfo::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"sessionId\":" << sessionId << ",";
    oss << "\"sessionHandle\":" << sessionHandle << ",";
    oss << "\"processId\":" << processId << ",";
    oss << "\"applicationName\":\"" << EscapeJsonString(Utils::StringUtils::ToNarrow(applicationName)) << "\",";
    oss << "\"contentType\":" << static_cast<int>(contentType) << ",";
    oss << "\"scanCount\":" << scanCount << ",";
    oss << "\"detectionCount\":" << detectionCount << ",";
    oss << "\"startTime\":\"" << FormatTimePoint(startTime) << "\",";
    oss << "\"lastActivityTime\":\"" << FormatTimePoint(lastActivityTime) << "\",";
    oss << "\"isActive\":" << (isActive ? "true" : "false");
    oss << "}";
    return oss.str();
}

[[nodiscard]] std::string AmsiScanResponse::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"result\":" << static_cast<uint32_t>(result) << ",";
    oss << "\"isMalicious\":" << (isMalicious ? "true" : "false") << ",";
    oss << "\"threatName\":\"" << EscapeJsonString(threatName) << "\",";
    oss << "\"riskScore\":" << std::fixed << std::setprecision(2) << riskScore << ",";
    oss << "\"matchedSignatures\":[";
    for (size_t i = 0; i < matchedSignatures.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << EscapeJsonString(matchedSignatures[i]) << "\"";
    }
    oss << "],";
    oss << "\"contentHash\":\"" << EscapeJsonString(contentHash) << "\",";
    oss << "\"scanDurationUs\":" << scanDuration.count() << ",";
    oss << "\"timestamp\":\"" << FormatTimePoint(timestamp) << "\"";
    oss << "}";
    return oss.str();
}

[[nodiscard]] std::string AmsiBypassEvent::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"eventId\":\"" << EscapeJsonString(eventId) << "\",";
    oss << "\"processId\":" << processId << ",";
    oss << "\"threadId\":" << threadId << ",";
    oss << "\"processName\":\"" << EscapeJsonString(Utils::StringUtils::ToNarrow(processName)) << "\",";
    oss << "\"processPath\":\"" << EscapeJsonString(Utils::StringUtils::ToNarrow(processPath)) << "\",";
    oss << "\"techniques\":" << static_cast<uint32_t>(techniques) << ",";
    oss << "\"targetFunction\":\"" << EscapeJsonString(targetFunction) << "\",";
    oss << "\"targetAddress\":" << targetAddress << ",";
    oss << "\"originalBytes\":\"" << BytesToHex(originalBytes) << "\",";
    oss << "\"patchedBytes\":\"" << BytesToHex(patchedBytes) << "\",";
    oss << "\"wasRepaired\":" << (wasRepaired ? "true" : "false") << ",";
    oss << "\"repairSuccessful\":" << (repairSuccessful ? "true" : "false") << ",";
    oss << "\"details\":\"" << EscapeJsonString(details) << "\",";
    oss << "\"timestamp\":\"" << FormatTimePoint(timestamp) << "\"";
    oss << "}";
    return oss.str();
}

[[nodiscard]] std::string AmsiIntegrityReport::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"processId\":" << processId << ",";
    oss << "\"status\":" << static_cast<int>(status) << ",";
    oss << "\"amsiDllBase\":" << amsiDllBase << ",";
    oss << "\"amsiDllSize\":" << amsiDllSize << ",";
    oss << "\"amsiDllHash\":\"" << EscapeJsonString(amsiDllHash) << "\",";
    oss << "\"expectedHash\":\"" << EscapeJsonString(expectedHash) << "\",";
    oss << "\"functionStates\":[";
    for (size_t i = 0; i < functionStates.size(); ++i) {
        if (i > 0) oss << ",";
        const auto& fs = functionStates[i];
        oss << "{\"functionName\":\"" << EscapeJsonString(fs.functionName) << "\",";
        oss << "\"address\":" << fs.address << ",";
        oss << "\"isIntact\":" << (fs.isIntact ? "true" : "false") << ",";
        oss << "\"currentPrologue\":\"" << BytesToHex(fs.currentPrologue) << "\",";
        oss << "\"expectedPrologue\":\"" << BytesToHex(fs.expectedPrologue) << "\"}";
    }
    oss << "],";
    oss << "\"detectedBypasses\":" << static_cast<uint32_t>(detectedBypasses) << ",";
    oss << "\"timestamp\":\"" << FormatTimePoint(timestamp) << "\"";
    oss << "}";
    return oss.str();
}

void AMSIStatistics::Reset() noexcept {
    totalScans.store(0, std::memory_order_relaxed);
    maliciousDetected.store(0, std::memory_order_relaxed);
    cleanResults.store(0, std::memory_order_relaxed);
    sessionsCreated.store(0, std::memory_order_relaxed);
    bypassAttemptsDetected.store(0, std::memory_order_relaxed);
    bypassesRepaired.store(0, std::memory_order_relaxed);
    integrityChecks.store(0, std::memory_order_relaxed);
    integrityFailures.store(0, std::memory_order_relaxed);
    totalBytesScanned.store(0, std::memory_order_relaxed);
    cacheHits.store(0, std::memory_order_relaxed);
    cacheMisses.store(0, std::memory_order_relaxed);
    for (auto& ct : byContentType) {
        ct.store(0, std::memory_order_relaxed);
    }
    startTime = Clock::now();
}

[[nodiscard]] std::string AMSIStatisticsSnapshot::ToJson() const {
    auto uptimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now() - startTime).count();

    std::ostringstream oss;
    oss << "{";
    oss << "\"totalScans\":" << totalScans << ",";
    oss << "\"maliciousDetected\":" << maliciousDetected << ",";
    oss << "\"cleanResults\":" << cleanResults << ",";
    oss << "\"sessionsCreated\":" << sessionsCreated << ",";
    oss << "\"bypassAttemptsDetected\":" << bypassAttemptsDetected << ",";
    oss << "\"bypassesRepaired\":" << bypassesRepaired << ",";
    oss << "\"integrityChecks\":" << integrityChecks << ",";
    oss << "\"integrityFailures\":" << integrityFailures << ",";
    oss << "\"totalBytesScanned\":" << totalBytesScanned << ",";
    oss << "\"cacheHits\":" << cacheHits << ",";
    oss << "\"cacheMisses\":" << cacheMisses << ",";
    oss << "\"uptimeMs\":" << uptimeMs;
    oss << "}";
    return oss.str();
}

[[nodiscard]] bool AMSIConfiguration::IsValid() const noexcept {
    if (maxContentSize == 0 || maxContentSize > AMSIConstants::MAX_SCAN_CONTENT_SIZE) {
        return false;
    }
    if (integrityCheckIntervalMs < 1000) {
        return false;  // Minimum 1 second
    }
    return true;
}

// ============================================================================
// UTILITY FUNCTION IMPLEMENTATIONS
// ============================================================================

[[nodiscard]] std::string_view GetAmsiResultName(AmsiResult result) noexcept {
    switch (result) {
        case AmsiResult::Clean:               return "Clean";
        case AmsiResult::NotDetected:         return "NotDetected";
        case AmsiResult::BlockedByAdminStart: return "BlockedByAdminStart";
        case AmsiResult::BlockedByAdminEnd:   return "BlockedByAdminEnd";
        case AmsiResult::Detected:            return "Detected";
        case AmsiResult::Unknown:             return "Unknown";
        default:                              return "Unknown";
    }
}

[[nodiscard]] std::string_view GetAmsiContentTypeName(AmsiContentType type) noexcept {
    switch (type) {
        case AmsiContentType::Unknown:    return "Unknown";
        case AmsiContentType::PowerShell: return "PowerShell";
        case AmsiContentType::VBScript:   return "VBScript";
        case AmsiContentType::JScript:    return "JScript";
        case AmsiContentType::Macro:      return "Macro";
        case AmsiContentType::DotNetCLR:  return "DotNetCLR";
        case AmsiContentType::Binary:     return "Binary";
        case AmsiContentType::URL:        return "URL";
        case AmsiContentType::Custom:     return "Custom";
        default:                          return "Unknown";
    }
}

[[nodiscard]] std::string_view GetAmsiBypassTechniqueName(AmsiBypassTechnique tech) noexcept {
    switch (tech) {
        case AmsiBypassTechnique::Unknown:                return "Unknown";
        case AmsiBypassTechnique::AmsiScanBufferPatch:    return "AmsiScanBufferPatch";
        case AmsiBypassTechnique::AmsiInitializePatch:    return "AmsiInitializePatch";
        case AmsiBypassTechnique::AmsiOpenSessionPatch:   return "AmsiOpenSessionPatch";
        case AmsiBypassTechnique::AmsiContextCorruption:  return "AmsiContextCorruption";
        case AmsiBypassTechnique::ReflectionBypass:       return "ReflectionBypass";
        case AmsiBypassTechnique::CLRHooking:             return "CLRHooking";
        case AmsiBypassTechnique::DLLUnload:              return "DLLUnload";
        case AmsiBypassTechnique::DLLHijacking:           return "DLLHijacking";
        case AmsiBypassTechnique::MemoryProtectionChange: return "MemoryProtectionChange";
        case AmsiBypassTechnique::IATHooking:             return "IATHooking";
        case AmsiBypassTechnique::InlineHooking:          return "InlineHooking";
        case AmsiBypassTechnique::TramplineBypass:        return "TramplineBypass";
        case AmsiBypassTechnique::ETWBlinding:            return "ETWBlinding";
        case AmsiBypassTechnique::AmsiProviderBypass:     return "AmsiProviderBypass";
        case AmsiBypassTechnique::ForceError:             return "ForceError";
        default:                                          return "Unknown";
    }
}

[[nodiscard]] std::string_view GetAmsiIntegrityStatusName(AmsiIntegrityStatus status) noexcept {
    switch (status) {
        case AmsiIntegrityStatus::Unknown:   return "Unknown";
        case AmsiIntegrityStatus::Intact:    return "Intact";
        case AmsiIntegrityStatus::Tampered:  return "Tampered";
        case AmsiIntegrityStatus::Missing:   return "Missing";
        case AmsiIntegrityStatus::Corrupted: return "Corrupted";
        case AmsiIntegrityStatus::Repaired:  return "Repaired";
        default:                             return "Unknown";
    }
}

[[nodiscard]] bool IsAmsiResultMalicious(AmsiResult result) noexcept {
    if (result == AmsiResult::Unknown) return false;
    uint32_t value = static_cast<uint32_t>(result);
    return value >= static_cast<uint32_t>(AmsiResult::Detected);
}

// ============================================================================
// AMSI INTEGRATION IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class AMSIIntegrationImpl final {
public:
    AMSIIntegrationImpl() = default;
    ~AMSIIntegrationImpl() { Shutdown(); }

    // Non-copyable, non-movable
    AMSIIntegrationImpl(const AMSIIntegrationImpl&) = delete;
    AMSIIntegrationImpl& operator=(const AMSIIntegrationImpl&) = delete;
    AMSIIntegrationImpl(AMSIIntegrationImpl&&) = delete;
    AMSIIntegrationImpl& operator=(AMSIIntegrationImpl&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(const AMSIConfiguration& config) {
        std::unique_lock lock(m_mutex);

        if (m_status != ModuleStatus::Uninitialized &&
            m_status != ModuleStatus::Stopped) {
            SS_LOG_WARN(LOG_CATEGORY, L"AMSI already initialized");
            return true;
        }

        m_status = ModuleStatus::Initializing;

        // Validate configuration
        if (!config.IsValid()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Invalid AMSI configuration");
            m_status = ModuleStatus::Error;
            return false;
        }

        m_config = config;

        // Initialize AMSI context for system AMSI chain
        HRESULT hr = AmsiInitialize(AMSIConstants::PROVIDER_NAME, &m_amsiContext);
        if (FAILED(hr)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"AmsiInitialize failed: 0x%08X", hr);
            m_status = ModuleStatus::Error;
            return false;
        }

        // Store expected function prologues for integrity checking
        if (!CaptureExpectedPrologues()) {
            SS_LOG_WARN(LOG_CATEGORY, L"Failed to capture expected prologues");
            // Non-fatal - continue initialization
        }

        // Start integrity monitoring thread if enabled
        if (m_config.enableIntegrityMonitoring) {
            m_integrityMonitorRunning = true;
            m_integrityMonitorThread = std::thread(&AMSIIntegrationImpl::IntegrityMonitorLoop, this);
        }

        m_stats.Reset();
        m_status = ModuleStatus::Running;

        SS_LOG_INFO(LOG_CATEGORY, L"AMSI Integration initialized successfully");
        return true;
    }

    void Shutdown() {
        // Capture handles under lock, then release lock before joining thread
        HAMSICONTEXT capturedContext = nullptr;
        std::vector<std::pair<uint64_t, HAMSISSESSION>> capturedSessions;

        {
            std::unique_lock lock(m_mutex);

            if (m_status == ModuleStatus::Uninitialized ||
                m_status == ModuleStatus::Stopped) {
                return;
            }

            m_status = ModuleStatus::Stopping;

            // Capture AMSI context and sessions for cleanup outside lock
            capturedContext = m_amsiContext;
            m_amsiContext = nullptr;

            capturedSessions.reserve(m_sessions.size());
            for (auto& [id, session] : m_sessions) {
                if (session.sessionHandle != 0) {
                    capturedSessions.emplace_back(
                        id,
                        reinterpret_cast<HAMSISSESSION>(session.sessionHandle));
                }
            }
            m_sessions.clear();

            // Signal integrity monitor to stop
            m_integrityMonitorRunning = false;
        }

        // Wake and join the monitor thread without holding m_mutex
        m_integrityMonitorCV.notify_all();

        if (m_integrityMonitorThread.joinable()) {
            m_integrityMonitorThread.join();
        }

        // Close captured sessions and uninitialize (no lock needed, we own the handles)
        if (capturedContext != nullptr) {
            for (auto& [id, hSession] : capturedSessions) {
                AmsiCloseSession(capturedContext, hSession);
            }
            AmsiUninitialize(capturedContext);
        }

        // Final state update under lock
        {
            std::unique_lock lock(m_mutex);
            m_providerStatus = ProviderStatus::Unregistered;
            m_status = ModuleStatus::Stopped;
        }

        SS_LOG_INFO(LOG_CATEGORY, L"AMSI Integration shutdown complete");
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        return m_status == ModuleStatus::Running;
    }

    [[nodiscard]] ModuleStatus GetStatus() const noexcept {
        return m_status.load(std::memory_order_acquire);
    }

    [[nodiscard]] bool UpdateConfiguration(const AMSIConfiguration& config) {
        if (!config.IsValid()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Invalid configuration update");
            return false;
        }

        std::unique_lock lock(m_mutex);
        m_config = config;
        SS_LOG_INFO(LOG_CATEGORY, L"AMSI configuration updated");
        return true;
    }

    [[nodiscard]] AMSIConfiguration GetConfiguration() const {
        std::shared_lock lock(m_mutex);
        return m_config;
    }

    // ========================================================================
    // PROVIDER MANAGEMENT
    // ========================================================================

    [[nodiscard]] bool RegisterProvider() {
        std::unique_lock lock(m_mutex);

        if (m_providerStatus == ProviderStatus::Registered ||
            m_providerStatus == ProviderStatus::Active) {
            return true;
        }

        // Write AMSI provider registry key under
        // HKLM\SOFTWARE\Microsoft\AMSI\Providers\{our-GUID}
        // so Windows loads our provider DLL into AMSI-aware processes.
        HKEY hRawKey = nullptr;
        std::wstring registryPath = L"SOFTWARE\\Microsoft\\AMSI\\Providers\\";
        registryPath += AMSIConstants::PROVIDER_GUID;

        LONG regResult = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            registryPath.c_str(),
            0, nullptr,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE | KEY_WOW64_64KEY,
            nullptr,
            &hRawKey,
            nullptr);

        if (regResult != ERROR_SUCCESS) {
            SS_LOG_ERROR(LOG_CATEGORY,
                L"Failed to create AMSI provider registry key: %lu", regResult);
            m_providerStatus = ProviderStatus::Failed;
            return false;
        }

        // RAII guard: ensure the key is closed on all exit paths
        auto keyGuard = std::unique_ptr<
            std::remove_pointer_t<HKEY>, decltype(&RegCloseKey)>(hRawKey, &RegCloseKey);

        std::wstring providerName(AMSIConstants::PROVIDER_NAME);
        LONG setResult = RegSetValueExW(hRawKey, nullptr, 0, REG_SZ,
            reinterpret_cast<const BYTE*>(providerName.c_str()),
            static_cast<DWORD>((providerName.size() + 1) * sizeof(wchar_t)));

        if (setResult != ERROR_SUCCESS) {
            SS_LOG_ERROR(LOG_CATEGORY,
                L"Failed to set AMSI provider value: %lu", setResult);
            m_providerStatus = ProviderStatus::Failed;
            return false;
        }

        m_registrationVerifiedTime = Clock::now();
        m_providerStatus = ProviderStatus::Registered;
        SS_LOG_INFO(LOG_CATEGORY, L"AMSI provider registered at %ls", registryPath.c_str());
        return true;
    }

    [[nodiscard]] bool UnregisterProvider() {
        std::unique_lock lock(m_mutex);

        std::wstring registryPath = L"SOFTWARE\\Microsoft\\AMSI\\Providers\\";
        registryPath += AMSIConstants::PROVIDER_GUID;

        LONG regResult = RegDeleteKeyExW(
            HKEY_LOCAL_MACHINE,
            registryPath.c_str(),
            KEY_WOW64_64KEY,
            0);

        if (regResult != ERROR_SUCCESS && regResult != ERROR_FILE_NOT_FOUND) {
            SS_LOG_WARN(LOG_CATEGORY,
                L"Failed to remove AMSI provider registry key: %lu", regResult);
        }

        m_providerStatus = ProviderStatus::Unregistered;
        SS_LOG_INFO(LOG_CATEGORY, L"AMSI provider unregistered");
        return true;
    }

    [[nodiscard]] ProviderStatus GetProviderStatus() const noexcept {
        return m_providerStatus.load(std::memory_order_acquire);
    }

    [[nodiscard]] bool IsProviderRegistered() const noexcept {
        auto status = m_providerStatus.load(std::memory_order_acquire);
        return status == ProviderStatus::Registered ||
               status == ProviderStatus::Active;
    }

    // ========================================================================
    // SCANNING
    // ========================================================================

    [[nodiscard]] AmsiScanResponse ScanBuffer(const AmsiScanRequest& request) {
        AmsiScanResponse response;
        response.timestamp = GetCurrentSystemTime();

        if (m_status.load(std::memory_order_acquire) != ModuleStatus::Running) {
            SS_LOG_ERROR(LOG_CATEGORY, L"AMSI not initialized, scan rejected");
            response.result = AmsiResult::Unknown;
            InvokeErrorCallback("AMSI module not initialized", E_NOT_VALID_STATE);
            return response;
        }

        // Snapshot config under lock for thread-safe access
        const size_t maxContentSize = [&] {
            std::shared_lock lock(m_mutex);
            return m_config.maxContentSize;
        }();

        auto startTime = Clock::now();

        // Validate request
        if (request.content.empty()) {
            response.result = AmsiResult::Clean;
            SS_LOG_DEBUG(LOG_CATEGORY, L"Empty content, returning clean");
            return response;
        }

        if (request.content.size() > maxContentSize) {
            SS_LOG_WARN(LOG_CATEGORY, L"Content too large: %zu bytes",
                        request.content.size());
            response.result = AmsiResult::Unknown;
            InvokeErrorCallback("Content exceeds maximum size", ERROR_BUFFER_OVERFLOW);
            return response;
        }

        // Update statistics
        m_stats.totalScans.fetch_add(1, std::memory_order_relaxed);
        m_stats.totalBytesScanned.fetch_add(request.content.size(),
                                             std::memory_order_relaxed);

        if (static_cast<size_t>(request.contentType) < m_stats.byContentType.size()) {
            m_stats.byContentType[static_cast<size_t>(request.contentType)]
                .fetch_add(1, std::memory_order_relaxed);
        }

        // Compute content hash for caching/logging
        Utils::HashUtils::Hasher hasher(Utils::HashUtils::Algorithm::SHA256);
        if (hasher.Init()) {
            hasher.Update(request.content.data(), request.content.size());
            hasher.FinalHex(response.contentHash, false);
        }

        // FIX 6: Whitelist fast-path — skip scanning entirely for known-good hashes
        if (!response.contentHash.empty()) {
            try {
                if (IsWhitelistedImpl(response.contentHash)) {
                    response.result = AmsiResult::Clean;
                    response.isMalicious = false;
                    m_stats.cleanResults.fetch_add(1, std::memory_order_relaxed);
                    m_stats.cacheHits.fetch_add(1, std::memory_order_relaxed);

                    auto endTime = Clock::now();
                    response.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(
                        endTime - startTime);

                    SS_LOG_DEBUG(LOG_CATEGORY,
                        L"Content whitelisted, skipping scan: %ls", request.contentName.c_str());
                    InvokeScanCallback(response);
                    return response;
                }
            } catch (const std::exception& e) {
                SS_LOG_TRACE(LOG_CATEGORY,
                    L"Whitelist lookup unavailable: %hs", e.what());
            }
        }

        // FIX 5: ThreatIntel pre-scan — short-circuit if hash is known-malicious
        if (!response.contentHash.empty()) {
            try {
                double tiRiskScore = 0.0;
                std::string tiThreatName;
                if (QueryThreatIntelImpl(response.contentHash, tiRiskScore, tiThreatName)) {
                    response.result = AmsiResult::Detected;
                    response.isMalicious = true;
                    response.riskScore = tiRiskScore;
                    if (!tiThreatName.empty()) {
                        response.threatName = tiThreatName;
                    }
                    m_stats.maliciousDetected.fetch_add(1, std::memory_order_relaxed);

                    auto endTime = Clock::now();
                    response.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(
                        endTime - startTime);

                    SS_LOG_WARN(LOG_CATEGORY,
                        L"ThreatIntel pre-scan: malicious hash for %ls", request.contentName.c_str());
                    InvokeScanCallback(response);
                    return response;
                }
            } catch (const std::exception& e) {
                SS_LOG_TRACE(LOG_CATEGORY,
                    L"ThreatIntel lookup unavailable: %hs", e.what());
            }
        }

        // FIX 4: Check scan cache before calling system AMSI
        if (!response.contentHash.empty()) {
            auto cachedResult = LookupScanCache(response.contentHash);
            if (cachedResult.has_value()) {
                m_stats.cacheHits.fetch_add(1, std::memory_order_relaxed);
                response.result = cachedResult->result;
                response.isMalicious = cachedResult->isMalicious;
                response.threatName = cachedResult->threatName;
                response.riskScore = cachedResult->riskScore;

                if (response.isMalicious) {
                    m_stats.maliciousDetected.fetch_add(1, std::memory_order_relaxed);
                } else {
                    m_stats.cleanResults.fetch_add(1, std::memory_order_relaxed);
                }

                DispatchToSubScanner(request, response);

                auto endTime = Clock::now();
                response.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(
                    endTime - startTime);

                InvokeScanCallback(response);
                return response;
            }
            m_stats.cacheMisses.fetch_add(1, std::memory_order_relaxed);
        }

        // Get or create session
        HAMSISSESSION amsiSession = nullptr;
        if (request.sessionId != 0) {
            std::shared_lock lock(m_mutex);
            auto it = m_sessions.find(request.sessionId);
            if (it != m_sessions.end()) {
                amsiSession = reinterpret_cast<HAMSISSESSION>(it->second.sessionHandle);
            }
        }

        // Guard against ULONG overflow — AmsiScanBuffer takes ULONG length
        if (request.content.size() > static_cast<size_t>(MAXULONG)) {
            SS_LOG_ERROR(LOG_CATEGORY,
                L"Content size %zu exceeds ULONG maximum for AmsiScanBuffer",
                request.content.size());
            response.result = AmsiResult::Unknown;
            InvokeErrorCallback("Content exceeds ULONG maximum", ERROR_BUFFER_OVERFLOW);
            return response;
        }

        AMSI_RESULT amsiResult = AMSI_RESULT_NOT_DETECTED;
        HRESULT hr = AmsiScanBuffer(
            m_amsiContext,
            const_cast<void*>(static_cast<const void*>(request.content.data())),
            static_cast<ULONG>(request.content.size()),
            request.contentName.c_str(),
            amsiSession,
            &amsiResult
        );

        if (FAILED(hr)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"AmsiScanBuffer failed: 0x%08X", hr);
            response.result = AmsiResult::Unknown;
            InvokeErrorCallback("AmsiScanBuffer failed", hr);
            return response;
        }

        // Map AMSI result
        response.result = MapAmsiResult(amsiResult);
        response.isMalicious = AmsiResultIsMalware(amsiResult);

        if (response.isMalicious) {
            m_stats.maliciousDetected.fetch_add(1, std::memory_order_relaxed);
            response.threatName = "AMSI.Detected";
            response.riskScore = 100.0;

            SS_LOG_WARN(LOG_CATEGORY, L"Malicious content detected: %ls",
                        request.contentName.c_str());
        } else {
            m_stats.cleanResults.fetch_add(1, std::memory_order_relaxed);
        }

        // Dispatch to internal sub-scanners for deep behavioral analysis.
        // PowerShellScanner provides deobfuscation and pattern matching
        // that system AMSI providers may miss.
        DispatchToSubScanner(request, response);

        // FIX 4: Update scan cache with result
        if (!response.contentHash.empty()) {
            UpdateScanCache(response.contentHash, response);
        }

        // Calculate scan duration
        auto endTime = Clock::now();
        response.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(
            endTime - startTime);

        // Update session statistics
        if (request.sessionId != 0) {
            std::unique_lock lock(m_mutex);
            auto it = m_sessions.find(request.sessionId);
            if (it != m_sessions.end()) {
                it->second.scanCount++;
                if (response.isMalicious) {
                    it->second.detectionCount++;
                }
                it->second.lastActivityTime = response.timestamp;
            }
        }

        // Invoke callback
        InvokeScanCallback(response);

        return response;
    }

    [[nodiscard]] AmsiResult ScanBuffer(
        std::span<const uint8_t> buffer,
        std::wstring_view contentName,
        uint64_t sessionId) {

        AmsiScanRequest request;
        request.content = buffer;
        request.contentName = std::wstring(contentName);
        request.sessionId = sessionId;
        request.processId = GetCurrentProcessId();

        auto response = ScanBuffer(request);
        return response.result;
    }

    [[nodiscard]] AmsiResult ScanString(
        std::wstring_view content,
        std::wstring_view contentName,
        AmsiContentType type) {

        if (m_status.load(std::memory_order_acquire) != ModuleStatus::Running) {
            SS_LOG_ERROR(LOG_CATEGORY, L"AMSI not initialized for string scan");
            return AmsiResult::Unknown;
        }

        // Convert wide string to UTF-8 bytes
        std::string utf8Content = Utils::StringUtils::ToNarrow(content);

        AmsiScanRequest request;
        request.content = std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(utf8Content.data()),
            utf8Content.size());
        request.contentName = std::wstring(contentName);
        request.contentType = type;
        request.processId = GetCurrentProcessId();

        auto response = ScanBuffer(request);
        return response.result;
    }

    [[nodiscard]] AmsiResult ScanWithSystemAMSI(
        std::span<const uint8_t> buffer,
        std::wstring_view contentName) {

        if (m_status.load(std::memory_order_acquire) != ModuleStatus::Running) {
            SS_LOG_ERROR(LOG_CATEGORY, L"AMSI not initialized for system scan");
            return AmsiResult::Unknown;
        }

        if (m_amsiContext == nullptr) {
            SS_LOG_ERROR(LOG_CATEGORY, L"AMSI context not initialized");
            return AmsiResult::Unknown;
        }

        if (buffer.empty()) {
            return AmsiResult::Clean;
        }

        if (buffer.size() > static_cast<size_t>(MAXULONG)) {
            SS_LOG_ERROR(LOG_CATEGORY,
                L"Content size %zu exceeds ULONG maximum for system AMSI scan",
                buffer.size());
            return AmsiResult::Unknown;
        }

        std::wstring nameStorage(contentName);
        AMSI_RESULT result = AMSI_RESULT_NOT_DETECTED;
        HRESULT hr = AmsiScanBuffer(
            m_amsiContext,
            const_cast<void*>(static_cast<const void*>(buffer.data())),
            static_cast<ULONG>(buffer.size()),
            nameStorage.c_str(),
            nullptr,
            &result
        );

        if (FAILED(hr)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"System AMSI scan failed: 0x%08X", hr);
            return AmsiResult::Unknown;
        }

        return MapAmsiResult(result);
    }

    // ========================================================================
    // SESSION MANAGEMENT
    // ========================================================================

    [[nodiscard]] uint64_t OpenSession(
        std::wstring_view applicationName,
        uint32_t processId) {

        if (m_status.load(std::memory_order_acquire) != ModuleStatus::Running) {
            SS_LOG_ERROR(LOG_CATEGORY, L"AMSI not initialized, cannot open session");
            return 0;
        }

        std::unique_lock lock(m_mutex);

        if (m_sessions.size() >= AMSIConstants::MAX_SESSIONS) {
            SS_LOG_WARN(LOG_CATEGORY, L"Maximum sessions reached");
            return 0;
        }

        HAMSISSESSION amsiSession = nullptr;
        HRESULT hr = AmsiOpenSession(m_amsiContext, &amsiSession);
        if (FAILED(hr)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"AmsiOpenSession failed: 0x%08X", hr);
            return 0;
        }

        AmsiSessionInfo session;
        session.sessionId = m_nextSessionId++;
        session.sessionHandle = reinterpret_cast<uint64_t>(amsiSession);
        session.processId = processId != 0 ? processId : GetCurrentProcessId();
        session.applicationName = std::wstring(applicationName);
        session.startTime = GetCurrentSystemTime();
        session.lastActivityTime = session.startTime;
        session.isActive = true;

        m_sessions[session.sessionId] = session;
        m_stats.sessionsCreated.fetch_add(1, std::memory_order_relaxed);

        SS_LOG_DEBUG(LOG_CATEGORY, L"Opened AMSI session %llu for %ls",
                     session.sessionId, session.applicationName.c_str());

        return session.sessionId;
    }

    void CloseSession(uint64_t sessionId) {
        std::unique_lock lock(m_mutex);

        auto it = m_sessions.find(sessionId);
        if (it == m_sessions.end()) {
            return;
        }

        if (it->second.sessionHandle != 0) {
            AmsiCloseSession(m_amsiContext,
                reinterpret_cast<HAMSISSESSION>(it->second.sessionHandle));
        }

        SS_LOG_DEBUG(LOG_CATEGORY, L"Closed AMSI session %llu", sessionId);
        m_sessions.erase(it);
    }

    [[nodiscard]] std::optional<AmsiSessionInfo> GetSessionInfo(uint64_t sessionId) const {
        std::shared_lock lock(m_mutex);

        auto it = m_sessions.find(sessionId);
        if (it == m_sessions.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    [[nodiscard]] std::vector<AmsiSessionInfo> GetActiveSessions() const {
        std::shared_lock lock(m_mutex);

        std::vector<AmsiSessionInfo> result;
        result.reserve(m_sessions.size());

        for (const auto& [id, session] : m_sessions) {
            if (session.isActive) {
                result.push_back(session);
            }
        }
        return result;
    }

    // ========================================================================
    // INTEGRITY & BYPASS DETECTION
    // ========================================================================

    [[nodiscard]] AmsiIntegrityReport CheckIntegrity(uint32_t processId) {
        AmsiIntegrityReport report;
        report.processId = processId;
        report.timestamp = GetCurrentSystemTime();

        m_stats.integrityChecks.fetch_add(1, std::memory_order_relaxed);

        // Get amsi.dll module info
        HMODULE hAmsi = GetModuleHandleW(L"amsi.dll");
        if (hAmsi == nullptr) {
            report.status = AmsiIntegrityStatus::Missing;
            m_stats.integrityFailures.fetch_add(1, std::memory_order_relaxed);

            SS_LOG_WARN(LOG_CATEGORY, L"amsi.dll not loaded in process %u", processId);
            return report;
        }

        report.amsiDllBase = reinterpret_cast<uint64_t>(hAmsi);

        MODULEINFO modInfo{};
        if (GetModuleInformation(GetCurrentProcess(), hAmsi, &modInfo, sizeof(modInfo))) {
            report.amsiDllSize = modInfo.SizeOfImage;
        }

        // Check critical function prologues
        CheckFunctionIntegrity("AmsiScanBuffer", report);
        CheckFunctionIntegrity("AmsiInitialize", report);
        CheckFunctionIntegrity("AmsiOpenSession", report);

        // Determine overall status
        bool hasTampering = false;
        for (const auto& fs : report.functionStates) {
            if (!fs.isIntact) {
                hasTampering = true;
                break;
            }
        }

        if (hasTampering) {
            report.status = AmsiIntegrityStatus::Tampered;
            m_stats.integrityFailures.fetch_add(1, std::memory_order_relaxed);
            m_stats.bypassAttemptsDetected.fetch_add(1, std::memory_order_relaxed);

            // Detect bypass technique
            report.detectedBypasses = DetectBypassTechnique(report);

            // Create bypass event
            AmsiBypassEvent event;
            event.eventId = GenerateEventId();
            event.processId = processId;
            event.threadId = GetCurrentThreadId();
            event.techniques = report.detectedBypasses;
            event.timestamp = report.timestamp;

            // Get process info
            WCHAR processPath[MAX_PATH] = {};
            GetModuleFileNameW(nullptr, processPath, MAX_PATH);
            event.processPath = processPath;
            event.processName = std::filesystem::path(processPath).filename().wstring();

            // Store event and update bypass tracking maps
            {
                std::unique_lock lock(m_mutex);
                m_recentBypassEvents.push_back(event);
                while (m_recentBypassEvents.size() > AMSIConstants::MAX_BYPASS_EVENTS) {
                    m_recentBypassEvents.pop_front();
                }
                m_bypassDetectedProcesses.insert(processId);
                m_detectedBypassTechniques[processId] = report.detectedBypasses;
            }

            InvokeBypassCallback(event);
            ReportBypassToAlertSystemImpl(event);
            ReportBypassToBehaviorAnalyzerImpl(event);
            InvokeIntegrityCallback(processId, AmsiIntegrityStatus::Tampered);

            SS_LOG_ERROR(LOG_CATEGORY, L"AMSI tampering detected in process %u", processId);

            // Auto-repair if enabled
            if (m_config.enableAutoRepair) {
                if (RepairIntegrity(processId)) {
                    report.status = AmsiIntegrityStatus::Repaired;
                }
            }
        } else {
            report.status = AmsiIntegrityStatus::Intact;
        }

        return report;
    }

    [[nodiscard]] AmsiIntegrityReport CheckIntegrity() {
        return CheckIntegrity(GetCurrentProcessId());
    }

    [[nodiscard]] bool RepairIntegrity(uint32_t processId) {
        SS_LOG_INFO(LOG_CATEGORY, L"Attempting AMSI repair for process %u", processId);

        HMODULE hAmsi = GetModuleHandleW(L"amsi.dll");
        if (hAmsi == nullptr) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Cannot repair: amsi.dll not loaded");
            return false;
        }

        bool anyRepaired = false;

        // Restore all critical AMSI function prologues
        static constexpr const char* kFunctions[] = {
            "AmsiScanBuffer", "AmsiInitialize", "AmsiOpenSession"
        };

        for (const char* funcName : kFunctions) {
            auto pFunc = GetProcAddress(hAmsi, funcName);
            if (pFunc == nullptr) continue;

            // FIX 2: Hold single shared_lock scope through compare-and-repair
            // to close the TOCTOU window between reading expected bytes and restoring.
            std::shared_lock readLock(m_mutex);
            auto it = m_expectedPrologues.find(funcName);
            if (it == m_expectedPrologues.end()) continue;

            const auto& expectedBytes = it->second;

            std::vector<uint8_t> currentPrologue(expectedBytes.size());
            memcpy(currentPrologue.data(), pFunc, currentPrologue.size());

            if (currentPrologue == expectedBytes) continue;  // Already intact

            // Restore in-place while still holding the lock that protects
            // m_expectedPrologues so the expected bytes cannot change under us.
            void* target = reinterpret_cast<void*>(pFunc);
            DWORD oldProtect = 0;
            if (!VirtualProtect(target, expectedBytes.size(),
                                PAGE_EXECUTE_READWRITE, &oldProtect)) {
                SS_LOG_ERROR(LOG_CATEGORY,
                    L"VirtualProtect failed during repair of %hs", funcName);
                continue;
            }
            memcpy(target, expectedBytes.data(), expectedBytes.size());
            VirtualProtect(target, expectedBytes.size(), oldProtect, &oldProtect);
            FlushInstructionCache(GetCurrentProcess(), target, expectedBytes.size());

            readLock.unlock();

            anyRepaired = true;
            SS_LOG_INFO(LOG_CATEGORY, L"Restored %hs prologue", funcName);
        }

        if (anyRepaired) {
            m_stats.bypassesRepaired.fetch_add(1, std::memory_order_relaxed);
            SS_LOG_INFO(LOG_CATEGORY, L"AMSI repair successful for process %u", processId);
        } else {
            SS_LOG_WARN(LOG_CATEGORY,
                L"AMSI repair: no functions needed repair for process %u", processId);
        }

        return anyRepaired;
    }

    [[nodiscard]] bool RepairIntegrity() {
        return RepairIntegrity(GetCurrentProcessId());
    }

    [[nodiscard]] bool StartIntegrityMonitoring(uint32_t processId) {
        std::unique_lock lock(m_mutex);
        m_monitoredProcesses.insert(processId);
        SS_LOG_INFO(LOG_CATEGORY, L"Started integrity monitoring for process %u", processId);
        return true;
    }

    void StopIntegrityMonitoring(uint32_t processId) {
        std::unique_lock lock(m_mutex);
        m_monitoredProcesses.erase(processId);
        SS_LOG_INFO(LOG_CATEGORY, L"Stopped integrity monitoring for process %u", processId);
    }

    [[nodiscard]] bool IsAmsiBypassDetected(uint32_t processId) const {
        std::shared_lock lock(m_mutex);
        return m_bypassDetectedProcesses.find(processId) != m_bypassDetectedProcesses.end();
    }

    [[nodiscard]] AmsiBypassTechnique GetDetectedBypasses(uint32_t processId) const {
        std::shared_lock lock(m_mutex);
        auto it = m_detectedBypassTechniques.find(processId);
        if (it != m_detectedBypassTechniques.end()) {
            return it->second;
        }
        return AmsiBypassTechnique::Unknown;
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void RegisterScanCallback(ScanCallback callback) {
        std::unique_lock lock(m_callbackMutex);
        m_scanCallback = std::move(callback);
    }

    void RegisterBypassCallback(BypassCallback callback) {
        std::unique_lock lock(m_callbackMutex);
        m_bypassCallback = std::move(callback);
    }

    void RegisterIntegrityCallback(IntegrityCallback callback) {
        std::unique_lock lock(m_callbackMutex);
        m_integrityCallback = std::move(callback);
    }

    void RegisterErrorCallback(ErrorCallback callback) {
        std::unique_lock lock(m_callbackMutex);
        m_errorCallback = std::move(callback);
    }

    void UnregisterCallbacks() {
        std::unique_lock lock(m_callbackMutex);
        m_scanCallback = nullptr;
        m_bypassCallback = nullptr;
        m_integrityCallback = nullptr;
        m_errorCallback = nullptr;
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] AMSIStatisticsSnapshot GetStatistics() const {
        AMSIStatisticsSnapshot snapshot;
        snapshot.totalScans = m_stats.totalScans.load(std::memory_order_relaxed);
        snapshot.maliciousDetected = m_stats.maliciousDetected.load(std::memory_order_relaxed);
        snapshot.cleanResults = m_stats.cleanResults.load(std::memory_order_relaxed);
        snapshot.sessionsCreated = m_stats.sessionsCreated.load(std::memory_order_relaxed);
        snapshot.bypassAttemptsDetected = m_stats.bypassAttemptsDetected.load(std::memory_order_relaxed);
        snapshot.bypassesRepaired = m_stats.bypassesRepaired.load(std::memory_order_relaxed);
        snapshot.integrityChecks = m_stats.integrityChecks.load(std::memory_order_relaxed);
        snapshot.integrityFailures = m_stats.integrityFailures.load(std::memory_order_relaxed);
        snapshot.totalBytesScanned = m_stats.totalBytesScanned.load(std::memory_order_relaxed);
        snapshot.cacheHits = m_stats.cacheHits.load(std::memory_order_relaxed);
        snapshot.cacheMisses = m_stats.cacheMisses.load(std::memory_order_relaxed);
        for (size_t i = 0; i < snapshot.byContentType.size(); ++i) {
            snapshot.byContentType[i] = m_stats.byContentType[i].load(std::memory_order_relaxed);
        }
        snapshot.startTime = m_stats.startTime;
        return snapshot;
    }

    void ResetStatistics() {
        m_stats.Reset();
        SS_LOG_INFO(LOG_CATEGORY, L"AMSI statistics reset");
    }

    [[nodiscard]] std::vector<AmsiBypassEvent> GetRecentBypassEvents(size_t maxCount) const {
        std::shared_lock lock(m_mutex);

        size_t count = std::min(maxCount, m_recentBypassEvents.size());
        if (count == 0) return {};

        return std::vector<AmsiBypassEvent>(
            m_recentBypassEvents.end() - static_cast<ptrdiff_t>(count),
            m_recentBypassEvents.end());
    }

    [[nodiscard]] bool SelfTest() {
        SS_LOG_INFO(LOG_CATEGORY, L"Running AMSI self-test...");

        bool allPassed = true;

        // Test 1: Context initialization
        if (m_amsiContext == nullptr) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Self-test FAILED: AMSI context not initialized");
            allPassed = false;
        }

        // Test 2: Scan clean content
        {
            std::string cleanContent = "This is clean content for testing.";
            auto result = ScanBuffer(
                std::span<const uint8_t>(
                    reinterpret_cast<const uint8_t*>(cleanContent.data()),
                    cleanContent.size()),
                L"SelfTest.Clean",
                0);

            if (result != AmsiResult::Clean && result != AmsiResult::NotDetected) {
                SS_LOG_WARN(LOG_CATEGORY, L"Self-test: Clean content not detected as clean");
                // Not a failure - depends on other providers
            }
        }

        // Test 3: Session management
        {
            uint64_t sessionId = OpenSession(L"SelfTest", 0);
            if (sessionId == 0) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test FAILED: Cannot open session");
                allPassed = false;
            } else {
                auto sessionInfo = GetSessionInfo(sessionId);
                if (!sessionInfo.has_value()) {
                    SS_LOG_ERROR(LOG_CATEGORY, L"Self-test FAILED: Cannot get session info");
                    allPassed = false;
                }
                CloseSession(sessionId);
            }
        }

        // Test 4: Integrity check
        {
            auto report = CheckIntegrity();
            if (report.status == AmsiIntegrityStatus::Unknown) {
                SS_LOG_WARN(LOG_CATEGORY, L"Self-test: Integrity check returned unknown");
            }
        }

        if (allPassed) {
            SS_LOG_INFO(LOG_CATEGORY, L"AMSI self-test PASSED");
        } else {
            SS_LOG_ERROR(LOG_CATEGORY, L"AMSI self-test FAILED");
        }

        return allPassed;
    }

private:
    // ========================================================================
    // INTERNAL HELPERS
    // ========================================================================

    [[nodiscard]] AmsiResult MapAmsiResult(AMSI_RESULT result) const noexcept {
        switch (result) {
            case AMSI_RESULT_CLEAN:
                return AmsiResult::Clean;
            case AMSI_RESULT_NOT_DETECTED:
                return AmsiResult::NotDetected;
            case AMSI_RESULT_BLOCKED_BY_ADMIN_START:
                return AmsiResult::BlockedByAdminStart;
            case AMSI_RESULT_BLOCKED_BY_ADMIN_END:
                return AmsiResult::BlockedByAdminEnd;
            case AMSI_RESULT_DETECTED:
                return AmsiResult::Detected;
            default:
                return AmsiResult::Unknown;
        }
    }

    [[nodiscard]] bool CaptureExpectedPrologues() {
        // amsi.dll should already be loaded by AmsiInitialize.
        // Using GetModuleHandleW avoids incrementing the DLL reference count.
        HMODULE hAmsi = GetModuleHandleW(L"amsi.dll");
        if (hAmsi == nullptr) {
            SS_LOG_WARN(LOG_CATEGORY, L"amsi.dll not loaded; cannot capture prologues");
            return false;
        }

        // Capture AmsiScanBuffer prologue
        auto pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
        if (pAmsiScanBuffer != nullptr) {
            std::vector<uint8_t> prologue(AMSIConstants::AMSI_PROLOGUE_SIZE);
            memcpy(prologue.data(), pAmsiScanBuffer, prologue.size());
            m_expectedPrologues["AmsiScanBuffer"] = prologue;
        }

        // Capture AmsiInitialize prologue
        auto pAmsiInitialize = GetProcAddress(hAmsi, "AmsiInitialize");
        if (pAmsiInitialize != nullptr) {
            std::vector<uint8_t> prologue(AMSIConstants::AMSI_PROLOGUE_SIZE);
            memcpy(prologue.data(), pAmsiInitialize, prologue.size());
            m_expectedPrologues["AmsiInitialize"] = prologue;
        }

        // Capture AmsiOpenSession prologue
        auto pAmsiOpenSession = GetProcAddress(hAmsi, "AmsiOpenSession");
        if (pAmsiOpenSession != nullptr) {
            std::vector<uint8_t> prologue(AMSIConstants::AMSI_PROLOGUE_SIZE);
            memcpy(prologue.data(), pAmsiOpenSession, prologue.size());
            m_expectedPrologues["AmsiOpenSession"] = prologue;
        }

        return !m_expectedPrologues.empty();
    }

    void CheckFunctionIntegrity(const std::string& functionName,
                                AmsiIntegrityReport& report) {
        HMODULE hAmsi = GetModuleHandleW(L"amsi.dll");
        if (hAmsi == nullptr) return;

        auto pFunc = GetProcAddress(hAmsi, functionName.c_str());
        if (pFunc == nullptr) return;

        AmsiIntegrityReport::FunctionState state;
        state.functionName = functionName;
        state.address = reinterpret_cast<uint64_t>(pFunc);

        // Read current prologue
        state.currentPrologue.resize(AMSIConstants::AMSI_PROLOGUE_SIZE);
        memcpy(state.currentPrologue.data(), pFunc, state.currentPrologue.size());

        // Get expected prologue
        auto it = m_expectedPrologues.find(functionName);
        if (it != m_expectedPrologues.end()) {
            state.expectedPrologue = it->second;
            state.isIntact = (state.currentPrologue == state.expectedPrologue);
        } else {
            // Check for common bypass patterns
            state.isIntact = !IsCommonBypassPattern(state.currentPrologue);
        }

        report.functionStates.push_back(state);
    }

    [[nodiscard]] bool IsCommonBypassPattern(const std::vector<uint8_t>& prologue) const {
        if (prologue.empty()) return false;

        // Check for RET as first instruction (simplest bypass)
        if (prologue[0] == 0xC3) return true;

        // Check for NOP; RET
        if (prologue.size() >= 2 &&
            prologue[0] == 0x90 && prologue[1] == 0xC3) {
            return true;
        }

        // Check for XOR EAX, EAX; RET (force S_OK / clean result)
        if (prologue.size() >= 3 &&
            prologue[0] == 0x31 && prologue[1] == 0xC0 && prologue[2] == 0xC3) {
            return true;
        }

        // Check for MOV EAX, <imm32>; RET (force specific HRESULT)
        if (prologue.size() >= 6 && prologue[0] == 0xB8 && prologue[5] == 0xC3) {
            return true;
        }

        // Check for JMP rel32 (inline hook / trampoline)
        if (prologue[0] == 0xE9) return true;

        // Check for JMP [rip+disp32] (FF 25 xx xx xx xx) — IAT-style hook
        if (prologue.size() >= 6 &&
            prologue[0] == 0xFF && prologue[1] == 0x25) {
            return true;
        }

        // Check for INT3 (breakpoint, possible anti-debug sabotage)
        if (prologue[0] == 0xCC) return true;

        return false;
    }

    [[nodiscard]] AmsiBypassTechnique DetectBypassTechnique(
        const AmsiIntegrityReport& report) const {

        AmsiBypassTechnique techniques = AmsiBypassTechnique::Unknown;

        for (const auto& fs : report.functionStates) {
            if (fs.isIntact) continue;

            if (fs.functionName == "AmsiScanBuffer") {
                techniques |= AmsiBypassTechnique::AmsiScanBufferPatch;
            } else if (fs.functionName == "AmsiInitialize") {
                techniques |= AmsiBypassTechnique::AmsiInitializePatch;
            } else if (fs.functionName == "AmsiOpenSession") {
                techniques |= AmsiBypassTechnique::AmsiOpenSessionPatch;
            }

            // Check for inline hooking pattern (JMP rel32 or JMP [rip+disp32])
            if (!fs.currentPrologue.empty() &&
                (fs.currentPrologue[0] == 0xE9 || fs.currentPrologue[0] == 0xFF)) {
                techniques |= AmsiBypassTechnique::InlineHooking;
            }
        }

        return techniques;
    }

    [[nodiscard]] bool RestoreFunctionPrologue(const std::string& functionName,
                                                uint64_t address) {
        auto it = m_expectedPrologues.find(functionName);
        if (it == m_expectedPrologues.end()) {
            SS_LOG_WARN(LOG_CATEGORY, L"No expected prologue for %hs", functionName.c_str());
            return false;
        }

        void* target = reinterpret_cast<void*>(address);
        const auto& expectedBytes = it->second;

        // Change memory protection
        DWORD oldProtect = 0;
        if (!VirtualProtect(target, expectedBytes.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"VirtualProtect failed for %hs", functionName.c_str());
            return false;
        }

        // Restore bytes
        memcpy(target, expectedBytes.data(), expectedBytes.size());

        // Restore protection
        VirtualProtect(target, expectedBytes.size(), oldProtect, &oldProtect);

        // Flush instruction cache
        FlushInstructionCache(GetCurrentProcess(), target, expectedBytes.size());

        SS_LOG_INFO(LOG_CATEGORY, L"Restored prologue for %hs", functionName.c_str());
        return true;
    }

    void DispatchToSubScanner(const AmsiScanRequest& request,
                              AmsiScanResponse& response) {
        // Dispatch to the appropriate sub-scanner based on content type
        switch (request.contentType) {
            case AmsiContentType::PowerShell:
            case AmsiContentType::Unknown:
                DispatchToPowerShellScanner(request, response);
                break;

            case AmsiContentType::VBScript:
                DispatchToVBScriptScanner(request, response);
                break;

            case AmsiContentType::JScript:
                DispatchToJavaScriptScanner(request, response);
                break;

            case AmsiContentType::Macro:
                DispatchToMacroDetector(request, response);
                break;

            case AmsiContentType::DotNetCLR:
            case AmsiContentType::Binary:
            case AmsiContentType::URL:
            case AmsiContentType::Custom:
                SS_LOG_TRACE(LOG_CATEGORY,
                    L"No sub-scanner available for content type %d, relying on system AMSI",
                    static_cast<int>(request.contentType));
                break;
        }
    }

    void DispatchToPowerShellScanner(const AmsiScanRequest& request,
                                     AmsiScanResponse& response) {
        try {
            auto& psScanner = PowerShellScanner::getInstance();
            std::string contentDesc = Utils::StringUtils::ToNarrow(request.contentName);

            auto psResult = psScanner.scanMemory(
                std::span<const char>(
                    reinterpret_cast<const char*>(request.content.data()),
                    request.content.size()),
                contentDesc,
                request.processId);

            MergeScanResult(response, psResult.status == ScanStatus::MALICIOUS,
                psResult.status == ScanStatus::SUSPICIOUS,
                static_cast<double>(psResult.riskScore),
                psResult.threatName, psResult.matchedRules);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY,
                L"PowerShellScanner dispatch failed: %hs", e.what());
        }
    }

    void DispatchToVBScriptScanner(const AmsiScanRequest& request,
                                    AmsiScanResponse& response) {
        try {
            auto& vbsScanner = VBScriptScanner::Instance();
            if (!vbsScanner.IsInitialized()) {
                SS_LOG_TRACE(LOG_CATEGORY,
                    L"VBScriptScanner not initialized, skipping dispatch");
                return;
            }
            std::string source(
                reinterpret_cast<const char*>(request.content.data()),
                request.content.size());
            std::string sourceName = Utils::StringUtils::ToNarrow(request.contentName);

            auto vbsResult = vbsScanner.ScanSource(source, sourceName);

            MergeScanResult(response,
                vbsResult.status == VBSScanStatus::Malicious,
                vbsResult.status == VBSScanStatus::Suspicious,
                static_cast<double>(vbsResult.riskScore),
                vbsResult.threatName, {});
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY,
                L"VBScriptScanner dispatch failed: %hs", e.what());
        }
    }

    void DispatchToJavaScriptScanner(const AmsiScanRequest& request,
                                      AmsiScanResponse& response) {
        try {
            auto& jsScanner = JavaScriptScanner::Instance();
            if (!jsScanner.IsInitialized()) {
                SS_LOG_TRACE(LOG_CATEGORY,
                    L"JavaScriptScanner not initialized, skipping dispatch");
                return;
            }

            auto jsResult = jsScanner.ScanMemory(
                std::span<const char>(
                    reinterpret_cast<const char*>(request.content.data()),
                    request.content.size()),
                Utils::StringUtils::ToNarrow(request.contentName));

            MergeScanResult(response,
                jsResult.status == JSScanStatus::Malicious,
                jsResult.status == JSScanStatus::Suspicious,
                static_cast<double>(jsResult.riskScore),
                jsResult.threatName, {});
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY,
                L"JavaScriptScanner dispatch failed: %hs", e.what());
        }
    }

    void DispatchToMacroDetector(const AmsiScanRequest& request,
                                  AmsiScanResponse& response) {
        try {
            auto& macroDetector = MacroDetector::Instance();
            if (!macroDetector.IsInitialized()) {
                SS_LOG_TRACE(LOG_CATEGORY,
                    L"MacroDetector not initialized, skipping dispatch");
                return;
            }

            std::string fileName = Utils::StringUtils::ToNarrow(request.contentName);
            auto macroResult = macroDetector.ScanDocument(request.content, fileName);

            MergeScanResult(response,
                macroResult.status == MacroScanStatus::Malicious,
                macroResult.status == MacroScanStatus::Suspicious,
                static_cast<double>(macroResult.riskScore),
                macroResult.threatName, {});
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY,
                L"MacroDetector dispatch failed: %hs", e.what());
        }
    }

    /// Merge sub-scanner result into the AMSI response, escalating severity.
    void MergeScanResult(AmsiScanResponse& response,
                         bool isMalicious, bool isSuspicious,
                         double riskScore, const std::string& threatName,
                         const std::vector<std::string>& matchedRules) {
        if (isMalicious) {
            if (!response.isMalicious) {
                m_stats.maliciousDetected.fetch_add(1, std::memory_order_relaxed);
            }
            response.isMalicious = true;
            response.result = AmsiResult::Detected;
            if (response.riskScore < riskScore) {
                response.riskScore = riskScore;
            }
            if (!threatName.empty()) {
                response.threatName = threatName;
            }
        } else if (isSuspicious && !response.isMalicious) {
            if (response.riskScore < riskScore) {
                response.riskScore = riskScore;
            }
        }

        for (const auto& rule : matchedRules) {
            response.matchedSignatures.push_back(rule);
        }
    }

    void IntegrityMonitorLoop() {
        SS_LOG_INFO(LOG_CATEGORY, L"Integrity monitor thread started");

        while (m_integrityMonitorRunning) {
            // Wait for interval or stop signal
            {
                std::unique_lock lock(m_integrityMonitorMutex);
                m_integrityMonitorCV.wait_for(lock,
                    std::chrono::milliseconds(m_config.integrityCheckIntervalMs),
                    [this] { return !m_integrityMonitorRunning; });
            }

            if (!m_integrityMonitorRunning) break;

            // Check current process
            CheckIntegrity(GetCurrentProcessId());

            // Check monitored processes
            std::unordered_set<uint32_t> processesToCheck;
            {
                std::shared_lock lock(m_mutex);
                processesToCheck = m_monitoredProcesses;
            }

            for (uint32_t pid : processesToCheck) {
                if (!m_integrityMonitorRunning) break;
                if (pid == GetCurrentProcessId()) {
                    continue;  // Already checked above
                }
                // IMPL 8: Cross-process AMSI integrity check via ReadProcessMemory
                CheckCrossProcessIntegrity(pid);
            }
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Integrity monitor thread stopped");
    }

    void InvokeScanCallback(const AmsiScanResponse& response) {
        std::shared_lock lock(m_callbackMutex);
        if (m_scanCallback) {
            try {
                m_scanCallback(response);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Scan callback exception: %hs", e.what());
            }
        }
    }

    void InvokeBypassCallback(const AmsiBypassEvent& event) {
        std::shared_lock lock(m_callbackMutex);
        if (m_bypassCallback) {
            try {
                m_bypassCallback(event);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Bypass callback exception: %hs", e.what());
            }
        }
    }

    void InvokeIntegrityCallback(uint32_t processId, AmsiIntegrityStatus status) {
        std::shared_lock lock(m_callbackMutex);
        if (m_integrityCallback) {
            try {
                m_integrityCallback(processId, status);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Integrity callback exception: %hs", e.what());
            }
        }
    }

    void InvokeErrorCallback(const std::string& message, int code) {
        std::shared_lock lock(m_callbackMutex);
        if (m_errorCallback) {
            try {
                m_errorCallback(message, code);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Error callback exception: %hs", e.what());
            }
        }
    }

    // ========================================================================
    // SCAN CACHE (LRU with TTL)
    // ========================================================================

    struct CachedScanEntry {
        AmsiResult result = AmsiResult::Unknown;
        bool isMalicious = false;
        std::string threatName;
        double riskScore = 0.0;
        TimePoint insertTime{};
    };

    [[nodiscard]] std::optional<CachedScanEntry> LookupScanCache(
        const std::string& hash) const {

        std::unique_lock lock(m_scanCacheMutex);
        auto mapIt = m_scanCacheMap.find(hash);
        if (mapIt == m_scanCacheMap.end()) {
            return std::nullopt;
        }

        // Check TTL
        auto age = Clock::now() - mapIt->second->second.insertTime;
        if (age > std::chrono::seconds(AMSIConstants::SCAN_CACHE_TTL_SECONDS)) {
            // Expired - evict
            m_scanCacheLRU.erase(mapIt->second);
            m_scanCacheMap.erase(mapIt);
            return std::nullopt;
        }

        // Move to front (most recently used)
        m_scanCacheLRU.splice(m_scanCacheLRU.begin(), m_scanCacheLRU, mapIt->second);
        return mapIt->second->second;
    }

    void UpdateScanCache(const std::string& hash,
                         const AmsiScanResponse& response) {

        std::unique_lock lock(m_scanCacheMutex);

        // If already present, update and move to front
        auto mapIt = m_scanCacheMap.find(hash);
        if (mapIt != m_scanCacheMap.end()) {
            mapIt->second->second.result = response.result;
            mapIt->second->second.isMalicious = response.isMalicious;
            mapIt->second->second.threatName = response.threatName;
            mapIt->second->second.riskScore = response.riskScore;
            mapIt->second->second.insertTime = Clock::now();
            m_scanCacheLRU.splice(m_scanCacheLRU.begin(), m_scanCacheLRU, mapIt->second);
            return;
        }

        // Evict LRU if at capacity
        while (m_scanCacheLRU.size() >= AMSIConstants::MAX_SCAN_CACHE_ENTRIES) {
            auto& lruEntry = m_scanCacheLRU.back();
            m_scanCacheMap.erase(lruEntry.first);
            m_scanCacheLRU.pop_back();
        }

        // Insert at front
        CachedScanEntry entry;
        entry.result = response.result;
        entry.isMalicious = response.isMalicious;
        entry.threatName = response.threatName;
        entry.riskScore = response.riskScore;
        entry.insertTime = Clock::now();

        m_scanCacheLRU.emplace_front(hash, entry);
        m_scanCacheMap[hash] = m_scanCacheLRU.begin();
    }

    // ========================================================================
    // CROSS-PROCESS INTEGRITY CHECK
    // ========================================================================

    void CheckCrossProcessIntegrity(uint32_t pid) {
        // Open the target process with memory-read privileges
        HANDLE hProcess = OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (hProcess == nullptr) {
            DWORD err = GetLastError();
            if (err == ERROR_ACCESS_DENIED) {
                SS_LOG_TRACE(LOG_CATEGORY,
                    L"Cross-process integrity: access denied for PID %u", pid);
            } else if (err == ERROR_INVALID_PARAMETER) {
                // Process may have already exited
                SS_LOG_DEBUG(LOG_CATEGORY,
                    L"Cross-process integrity: PID %u no longer exists", pid);
                std::unique_lock lock(m_mutex);
                m_monitoredProcesses.erase(pid);
            } else {
                SS_LOG_WARN(LOG_CATEGORY,
                    L"Cross-process integrity: OpenProcess failed for PID %u: %lu", pid, err);
            }
            return;
        }
        auto processGuard = std::unique_ptr<
            std::remove_pointer_t<HANDLE>, decltype(&CloseHandle)>(hProcess, &CloseHandle);

        // Enumerate modules to find amsi.dll base in target process
        HMODULE hMods[512]{};
        DWORD cbNeeded = 0;
        if (!EnumProcessModulesEx(hProcess, hMods, sizeof(hMods),
                                   &cbNeeded, LIST_MODULES_ALL)) {
            SS_LOG_TRACE(LOG_CATEGORY,
                L"Cross-process integrity: EnumProcessModulesEx failed for PID %u", pid);
            return;
        }

        HMODULE hAmsiRemote = nullptr;
        DWORD moduleCount = cbNeeded / sizeof(HMODULE);
        for (DWORD i = 0; i < moduleCount; ++i) {
            WCHAR moduleName[MAX_PATH]{};
            if (GetModuleBaseNameW(hProcess, hMods[i], moduleName, MAX_PATH) > 0) {
                if (_wcsicmp(moduleName, L"amsi.dll") == 0) {
                    hAmsiRemote = hMods[i];
                    break;
                }
            }
        }

        if (hAmsiRemote == nullptr) {
            SS_LOG_TRACE(LOG_CATEGORY,
                L"amsi.dll not loaded in PID %u", pid);
            return;
        }

        m_stats.integrityChecks.fetch_add(1, std::memory_order_relaxed);

        // Check function prologues by reading remote process memory.
        // We use the same offsets as our own amsi.dll (assumes same DLL version).
        bool hasTampering = false;

        std::shared_lock readLock(m_mutex);
        for (const auto& [funcName, expectedBytes] : m_expectedPrologues) {
            // Get function offset from our own loaded amsi.dll
            HMODULE hAmsiLocal = GetModuleHandleW(L"amsi.dll");
            if (hAmsiLocal == nullptr) break;

            auto pFuncLocal = GetProcAddress(hAmsiLocal, funcName.c_str());
            if (pFuncLocal == nullptr) continue;

            // Calculate offset and apply to remote base
            auto offset = reinterpret_cast<uintptr_t>(pFuncLocal)
                        - reinterpret_cast<uintptr_t>(hAmsiLocal);
            auto remoteAddr = reinterpret_cast<const void*>(
                reinterpret_cast<uintptr_t>(hAmsiRemote) + offset);

            std::vector<uint8_t> remotePrologue(expectedBytes.size());
            SIZE_T bytesRead = 0;
            if (!ReadProcessMemory(hProcess, remoteAddr, remotePrologue.data(),
                                    remotePrologue.size(), &bytesRead)) {
                SS_LOG_TRACE(LOG_CATEGORY,
                    L"ReadProcessMemory failed for %hs in PID %u", funcName.c_str(), pid);
                continue;
            }

            if (bytesRead < remotePrologue.size()) continue;

            if (remotePrologue != expectedBytes) {
                hasTampering = true;
                SS_LOG_WARN(LOG_CATEGORY,
                    L"AMSI bypass detected in PID %u: %hs prologue tampered", pid, funcName.c_str());
            }
        }
        readLock.unlock();

        if (hasTampering) {
            m_stats.integrityFailures.fetch_add(1, std::memory_order_relaxed);
            m_stats.bypassAttemptsDetected.fetch_add(1, std::memory_order_relaxed);

            AmsiBypassEvent event;
            event.eventId = GenerateEventId();
            event.processId = pid;
            event.threadId = 0;
            event.techniques = AmsiBypassTechnique::AmsiScanBufferPatch;
            event.details = "Cross-process AMSI tampering detected via ReadProcessMemory";
            event.timestamp = GetCurrentSystemTime();

            // Attempt to get remote process name
            WCHAR remotePath[MAX_PATH]{};
            if (GetModuleFileNameExW(hProcess, nullptr, remotePath, MAX_PATH)) {
                event.processPath = remotePath;
                event.processName = std::filesystem::path(remotePath).filename().wstring();
            }

            {
                std::unique_lock lock(m_mutex);
                m_recentBypassEvents.push_back(event);
                while (m_recentBypassEvents.size() > AMSIConstants::MAX_BYPASS_EVENTS) {
                    m_recentBypassEvents.pop_front();
                }
                m_bypassDetectedProcesses.insert(pid);
            }

            InvokeBypassCallback(event);
            ReportBypassToAlertSystemImpl(event);
            ReportBypassToBehaviorAnalyzerImpl(event);
            InvokeIntegrityCallback(pid, AmsiIntegrityStatus::Tampered);

            SS_LOG_ERROR(LOG_CATEGORY,
                L"AMSI tampering detected in remote process %u", pid);

            // Request kernel block if configured
            std::shared_lock cfgLock(m_mutex);
            bool shouldTerminate = m_config.terminateOnRepeatedBypass;
            cfgLock.unlock();

            if (shouldTerminate) {
                RequestKernelProcessBlockImpl(pid,
                    L"Repeated AMSI bypass detected in script host");
            }
        }
    }

    // ========================================================================
    // CROSS-MODULE INTEGRATION (Impl helpers)
    // ========================================================================

    void ReportBypassToAlertSystemImpl(const AmsiBypassEvent& event) {
        try {
            if (!Communication::AlertSystem::HasInstance()) return;
            auto& alertSystem = Communication::AlertSystem::Instance();
            if (!alertSystem.IsInitialized()) return;

            std::string subject = "AMSI Bypass Detected - PID "
                + std::to_string(event.processId);
            std::string details = "Event: " + event.eventId
                + " | Process: " + Utils::StringUtils::ToNarrow(event.processName)
                + " | Technique: " + std::string(GetAmsiBypassTechniqueName(event.techniques))
                + " | Repaired: " + (event.wasRepaired ? "yes" : "no")
                + " | " + event.details;

            alertSystem.RaiseAlert(
                Communication::AlertSeverity::Critical,
                Communication::AlertType::Security,
                subject, details, "AMSIIntegration");

            SS_LOG_DEBUG(LOG_CATEGORY,
                L"Bypass alert dispatched to AlertSystem for PID %u", event.processId);
        } catch (const std::exception& e) {
            SS_LOG_WARN(LOG_CATEGORY,
                L"AlertSystem dispatch failed: %hs", e.what());
        }
    }

    void ReportBypassToBehaviorAnalyzerImpl(const AmsiBypassEvent& event) {
        // Report via TelemetryCollector as the integration bridge.
        // BehaviorAnalyzer's EvasionAMSIBypass (206) enum is referenced via
        // telemetry metadata; direct inclusion of BehaviorAnalyzer.hpp is
        // avoided to prevent circular dependency.
        try {
            if (!Communication::TelemetryCollector::HasInstance()) return;
            auto& telemetry = Communication::TelemetryCollector::Instance();

            std::map<std::string, std::string> data;
            data["eventId"] = event.eventId;
            data["processId"] = std::to_string(event.processId);
            data["processName"] = Utils::StringUtils::ToNarrow(event.processName);
            data["technique"] = std::string(GetAmsiBypassTechniqueName(event.techniques));
            data["techniqueId"] = std::to_string(static_cast<uint32_t>(event.techniques));
            data["repaired"] = event.wasRepaired ? "true" : "false";
            // BehaviorPatternType::EvasionAMSIBypass = 206
            data["behaviorPatternType"] = "206";

            telemetry.RecordCustom("amsi_bypass", data);

            SS_LOG_DEBUG(LOG_CATEGORY,
                L"Bypass telemetry emitted for PID %u (BehaviorPattern=206)", event.processId);
        } catch (const std::exception& e) {
            SS_LOG_WARN(LOG_CATEGORY,
                L"TelemetryCollector dispatch failed: %hs", e.what());
        }
    }

    [[nodiscard]] bool QueryThreatIntelImpl(const std::string& sha256Hash,
                                             double& outRiskScore,
                                             std::string& outThreatName) const {
        try {
            std::shared_lock lock(m_mutex);
            if (!m_threatIntelStore) {
                return false;
            }
            auto& store = *m_threatIntelStore;
            lock.unlock();

            auto result = store.LookupHash("sha256", sha256Hash);
            if (result.found && result.IsMalicious()) {
                outRiskScore = static_cast<double>(result.score);
                outThreatName = "ThreatIntel.Hash." + sha256Hash.substr(0, 8);
                return true;
            }
        } catch (const std::exception& e) {
            SS_LOG_TRACE(LOG_CATEGORY,
                L"ThreatIntel query failed (graceful): %hs", e.what());
        }
        return false;
    }

    [[nodiscard]] bool IsWhitelistedImpl(const std::string& sha256Hash) const {
        try {
            std::shared_lock lock(m_mutex);
            if (!m_whitelistStore) {
                return false;
            }
            auto& store = *m_whitelistStore;
            lock.unlock();

            auto result = store.IsHashWhitelisted(
                sha256Hash, Whitelist::HashAlgorithm::SHA256);
            return result.found;
        } catch (const std::exception& e) {
            SS_LOG_TRACE(LOG_CATEGORY,
                L"Whitelist lookup failed (graceful): %hs", e.what());
        }
        return false;
    }

    [[nodiscard]] bool RequestKernelProcessBlockImpl(uint32_t processId,
                                                      const std::wstring& reason) {
        try {
            if (!Communication::IPCManager::HasInstance()) {
                SS_LOG_WARN(LOG_CATEGORY,
                    L"IPCManager not available for kernel process block");
                return false;
            }
            auto& ipc = Communication::IPCManager::Instance();
            if (!ipc.IsConnected()) {
                SS_LOG_WARN(LOG_CATEGORY,
                    L"IPCManager not connected to kernel driver");
                return false;
            }

            // Serialize a process block control message as a flat buffer:
            // [MessageType:uint16(2)] [ProcessId:uint32(4)] [Verdict:uint8(1)]
            // [ThreatScore:uint8(1)] [ReasonLenWchars:uint16(2)] [Reason:wchar[]]
            std::wstring truncatedReason = reason.substr(0, 256);

            constexpr size_t kHeaderSize = 2 + 4 + 1 + 1 + 2;
            size_t reasonBytes = truncatedReason.size() * sizeof(wchar_t);
            size_t totalSize = kHeaderSize + reasonBytes;

            std::vector<uint8_t> msgBuffer(totalSize, 0);
            uint8_t* ptr = msgBuffer.data();

            // MessageType: use a reserved value indicating process block
            auto msgType = static_cast<uint16_t>(Communication::MessageType::ProcessNotify);
            memcpy(ptr, &msgType, 2); ptr += 2;

            memcpy(ptr, &processId, 4); ptr += 4;

            auto verdict = static_cast<uint8_t>(Communication::ScanVerdict::Block);
            memcpy(ptr, &verdict, 1); ptr += 1;

            uint8_t threatScore = 100;
            memcpy(ptr, &threatScore, 1); ptr += 1;

            auto reasonLen = static_cast<uint16_t>(truncatedReason.size());
            memcpy(ptr, &reasonLen, 2); ptr += 2;

            if (!truncatedReason.empty()) {
                memcpy(ptr, truncatedReason.data(), reasonBytes);
            }

            bool sent = ipc.SendToKernel(msgBuffer.data(), msgBuffer.size());

            if (sent) {
                SS_LOG_INFO(LOG_CATEGORY,
                    L"Kernel process block requested for PID %u: %ls",
                    processId, reason.c_str());
            } else {
                SS_LOG_ERROR(LOG_CATEGORY,
                    L"Failed to send kernel process block for PID %u", processId);
            }
            return sent;
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY,
                L"Kernel process block exception: %hs", e.what());
            return false;
        }
    }

    // ========================================================================
    // KERNEL BRIDGE (Impl helpers)
    // ========================================================================

    // Script host executable names (lowercase for case-insensitive comparison)
    [[nodiscard]] static bool IsScriptHostProcess(std::wstring_view imagePath) {
        static constexpr std::wstring_view kScriptHosts[] = {
            L"powershell.exe", L"pwsh.exe", L"cscript.exe",
            L"wscript.exe", L"mshta.exe", L"msbuild.exe", L"regsvr32.exe"
        };

        auto filename = std::filesystem::path(imagePath).filename().wstring();
        // Convert to lowercase for case-insensitive match
        for (auto& ch : filename) {
            ch = static_cast<wchar_t>(std::towlower(ch));
        }

        for (auto host : kScriptHosts) {
            if (filename == host) return true;
        }
        return false;
    }

    void OnKernelProcessNotifyImpl(uint32_t processId,
                                    std::wstring_view imagePath,
                                    std::wstring_view commandLine,
                                    bool isCreate) {
        if (isCreate) {
            if (IsScriptHostProcess(imagePath)) {
                SS_LOG_INFO(LOG_CATEGORY,
                    L"Script host detected: PID %u (%ls)", processId,
                    std::filesystem::path(imagePath).filename().c_str());

                StartIntegrityMonitoring(processId);
            }
        } else {
            // Process destruction - clean up monitoring state
            bool wasMonitored = false;
            {
                std::unique_lock lock(m_mutex);
                wasMonitored = (m_monitoredProcesses.erase(processId) > 0);
                m_bypassDetectedProcesses.erase(processId);
                m_detectedBypassTechniques.erase(processId);
            }

            if (wasMonitored) {
                SS_LOG_DEBUG(LOG_CATEGORY,
                    L"Script host exited: PID %u, cleaned up monitoring", processId);
            }
        }
    }

    void OnKernelImageLoadImpl(uint32_t processId,
                                std::wstring_view imagePath,
                                uint64_t imageBase,
                                size_t imageSize) {
        auto filename = std::filesystem::path(imagePath).filename().wstring();
        for (auto& ch : filename) {
            ch = static_cast<wchar_t>(std::towlower(ch));
        }

        if (filename != L"amsi.dll") return;

        SS_LOG_INFO(LOG_CATEGORY,
            L"amsi.dll loaded in PID %u at 0x%llX (size=%zu)",
            processId, imageBase, imageSize);

        // If this process is monitored, schedule an immediate integrity check
        bool isMonitored = false;
        {
            std::shared_lock lock(m_mutex);
            isMonitored = (m_monitoredProcesses.count(processId) > 0);
        }

        if (isMonitored) {
            if (processId == GetCurrentProcessId()) {
                // In-process: direct check
                CheckIntegrity(processId);
            } else {
                // Cross-process: use ReadProcessMemory path
                CheckCrossProcessIntegrity(processId);
            }
        }
    }

private:
    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    // Thread safety
    mutable std::shared_mutex m_mutex;
    mutable std::shared_mutex m_callbackMutex;

    // State
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    std::atomic<ProviderStatus> m_providerStatus{ProviderStatus::Unregistered};

    // Configuration
    AMSIConfiguration m_config;

    // AMSI handles
    HAMSICONTEXT m_amsiContext = nullptr;

    // Session management
    std::unordered_map<uint64_t, AmsiSessionInfo> m_sessions;
    uint64_t m_nextSessionId = 1;

    // Provider registration
    TimePoint m_registrationVerifiedTime{};

    // Expected function prologues (for integrity checking)
    std::unordered_map<std::string, std::vector<uint8_t>> m_expectedPrologues;

    // Integrity monitoring
    std::atomic<bool> m_integrityMonitorRunning{false};
    std::thread m_integrityMonitorThread;
    std::mutex m_integrityMonitorMutex;
    std::condition_variable m_integrityMonitorCV;
    std::unordered_set<uint32_t> m_monitoredProcesses;
    std::unordered_set<uint32_t> m_bypassDetectedProcesses;
    std::unordered_map<uint32_t, AmsiBypassTechnique> m_detectedBypassTechniques;

    // Recent bypass events (deque for O(1) pop_front)
    std::deque<AmsiBypassEvent> m_recentBypassEvents;

    // Statistics
    AMSIStatistics m_stats;

    // Callbacks
    ScanCallback m_scanCallback;
    BypassCallback m_bypassCallback;
    IntegrityCallback m_integrityCallback;
    ErrorCallback m_errorCallback;

    // Scan result cache: LRU eviction via list + unordered_map
    using ScanCacheList = std::list<std::pair<std::string, CachedScanEntry>>;
    mutable ScanCacheList m_scanCacheLRU;
    mutable std::unordered_map<std::string, ScanCacheList::iterator> m_scanCacheMap;
    mutable std::mutex m_scanCacheMutex;

    // External store references (set via dependency injection; nullable)
    std::shared_ptr<ThreatIntel::ThreatIntelStore> m_threatIntelStore;
    std::shared_ptr<Whitelist::WhitelistStore> m_whitelistStore;

public:
    /// @brief Inject ThreatIntelStore for hash reputation lookups
    void SetThreatIntelStore(std::shared_ptr<ThreatIntel::ThreatIntelStore> store) {
        std::unique_lock lock(m_mutex);
        m_threatIntelStore = std::move(store);
        SS_LOG_INFO(LOG_CATEGORY, L"ThreatIntelStore injected into AMSI integration");
    }

    /// @brief Inject WhitelistStore for hash whitelist lookups
    void SetWhitelistStore(std::shared_ptr<Whitelist::WhitelistStore> store) {
        std::unique_lock lock(m_mutex);
        m_whitelistStore = std::move(store);
        SS_LOG_INFO(LOG_CATEGORY, L"WhitelistStore injected into AMSI integration");
    }
};

// ============================================================================
// AMSIINTEGRATION PUBLIC INTERFACE IMPLEMENTATION
// ============================================================================

[[nodiscard]] AMSIIntegration& AMSIIntegration::Instance() noexcept {
    static AMSIIntegration instance;
    return instance;
}

[[nodiscard]] bool AMSIIntegration::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

AMSIIntegration::AMSIIntegration()
    : m_impl(std::make_unique<AMSIIntegrationImpl>()) {
    s_instanceCreated.store(true, std::memory_order_release);
}

AMSIIntegration::~AMSIIntegration() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    s_instanceCreated.store(false, std::memory_order_release);
}

[[nodiscard]] bool AMSIIntegration::Initialize(const AMSIConfiguration& config) {
    return m_impl->Initialize(config);
}

void AMSIIntegration::Shutdown() {
    m_impl->Shutdown();
}

[[nodiscard]] bool AMSIIntegration::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

[[nodiscard]] ModuleStatus AMSIIntegration::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

[[nodiscard]] bool AMSIIntegration::UpdateConfiguration(const AMSIConfiguration& config) {
    return m_impl->UpdateConfiguration(config);
}

[[nodiscard]] AMSIConfiguration AMSIIntegration::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

[[nodiscard]] bool AMSIIntegration::RegisterProvider() {
    return m_impl->RegisterProvider();
}

[[nodiscard]] bool AMSIIntegration::UnregisterProvider() {
    return m_impl->UnregisterProvider();
}

[[nodiscard]] ProviderStatus AMSIIntegration::GetProviderStatus() const noexcept {
    return m_impl->GetProviderStatus();
}

[[nodiscard]] bool AMSIIntegration::IsProviderRegistered() const noexcept {
    return m_impl->IsProviderRegistered();
}

[[nodiscard]] AmsiScanResponse AMSIIntegration::ScanBuffer(const AmsiScanRequest& request) {
    return m_impl->ScanBuffer(request);
}

[[nodiscard]] AmsiResult AMSIIntegration::ScanBuffer(
    std::span<const uint8_t> buffer,
    std::wstring_view contentName,
    uint64_t sessionId) {
    return m_impl->ScanBuffer(buffer, contentName, sessionId);
}

[[nodiscard]] AmsiResult AMSIIntegration::ScanString(
    std::wstring_view content,
    std::wstring_view contentName,
    AmsiContentType type) {
    return m_impl->ScanString(content, contentName, type);
}

[[nodiscard]] AmsiResult AMSIIntegration::ScanWithSystemAMSI(
    std::span<const uint8_t> buffer,
    std::wstring_view contentName) {
    return m_impl->ScanWithSystemAMSI(buffer, contentName);
}

[[nodiscard]] uint64_t AMSIIntegration::OpenSession(
    std::wstring_view applicationName,
    uint32_t processId) {
    return m_impl->OpenSession(applicationName, processId);
}

void AMSIIntegration::CloseSession(uint64_t sessionId) {
    m_impl->CloseSession(sessionId);
}

[[nodiscard]] std::optional<AmsiSessionInfo> AMSIIntegration::GetSessionInfo(
    uint64_t sessionId) const {
    return m_impl->GetSessionInfo(sessionId);
}

[[nodiscard]] std::vector<AmsiSessionInfo> AMSIIntegration::GetActiveSessions() const {
    return m_impl->GetActiveSessions();
}

[[nodiscard]] AmsiIntegrityReport AMSIIntegration::CheckIntegrity(uint32_t processId) {
    return m_impl->CheckIntegrity(processId);
}

[[nodiscard]] AmsiIntegrityReport AMSIIntegration::CheckIntegrity() {
    return m_impl->CheckIntegrity();
}

[[nodiscard]] bool AMSIIntegration::RepairIntegrity(uint32_t processId) {
    return m_impl->RepairIntegrity(processId);
}

[[nodiscard]] bool AMSIIntegration::RepairIntegrity() {
    return m_impl->RepairIntegrity();
}

[[nodiscard]] bool AMSIIntegration::StartIntegrityMonitoring(uint32_t processId) {
    return m_impl->StartIntegrityMonitoring(processId);
}

void AMSIIntegration::StopIntegrityMonitoring(uint32_t processId) {
    m_impl->StopIntegrityMonitoring(processId);
}

[[nodiscard]] bool AMSIIntegration::IsAmsiBypassDetected(uint32_t processId) const {
    return m_impl->IsAmsiBypassDetected(processId);
}

[[nodiscard]] AmsiBypassTechnique AMSIIntegration::GetDetectedBypasses(
    uint32_t processId) const {
    return m_impl->GetDetectedBypasses(processId);
}

void AMSIIntegration::RegisterScanCallback(ScanCallback callback) {
    m_impl->RegisterScanCallback(std::move(callback));
}

void AMSIIntegration::RegisterBypassCallback(BypassCallback callback) {
    m_impl->RegisterBypassCallback(std::move(callback));
}

void AMSIIntegration::RegisterIntegrityCallback(IntegrityCallback callback) {
    m_impl->RegisterIntegrityCallback(std::move(callback));
}

void AMSIIntegration::RegisterErrorCallback(ErrorCallback callback) {
    m_impl->RegisterErrorCallback(std::move(callback));
}

void AMSIIntegration::UnregisterCallbacks() {
    m_impl->UnregisterCallbacks();
}

[[nodiscard]] AMSIStatisticsSnapshot AMSIIntegration::GetStatistics() const {
    return m_impl->GetStatistics();
}

void AMSIIntegration::ResetStatistics() {
    m_impl->ResetStatistics();
}

[[nodiscard]] std::vector<AmsiBypassEvent> AMSIIntegration::GetRecentBypassEvents(
    size_t maxCount) const {
    return m_impl->GetRecentBypassEvents(maxCount);
}

[[nodiscard]] bool AMSIIntegration::SelfTest() {
    return m_impl->SelfTest();
}

[[nodiscard]] std::string AMSIIntegration::GetVersionString() noexcept {
    try {
        return "ShadowStrike AMSIIntegration v"
            + std::to_string(AMSIConstants::VERSION_MAJOR) + "."
            + std::to_string(AMSIConstants::VERSION_MINOR) + "."
            + std::to_string(AMSIConstants::VERSION_PATCH);
    } catch (...) {
        return "ShadowStrike AMSIIntegration v?.?.?";
    }
}

// ============================================================================
// KERNEL BRIDGE IMPLEMENTATIONS
// ============================================================================

void AMSIIntegration::OnKernelProcessNotify(uint32_t processId,
                                             std::wstring_view imagePath,
                                             std::wstring_view commandLine,
                                             bool isCreate) {
    m_impl->OnKernelProcessNotifyImpl(processId, imagePath, commandLine, isCreate);
}

void AMSIIntegration::OnKernelImageLoad(uint32_t processId,
                                         std::wstring_view imagePath,
                                         uint64_t imageBase,
                                         size_t imageSize) {
    m_impl->OnKernelImageLoadImpl(processId, imagePath, imageBase, imageSize);
}

[[nodiscard]] bool AMSIIntegration::RequestKernelProcessBlock(
    uint32_t processId,
    const std::wstring& reason) {
    return m_impl->RequestKernelProcessBlockImpl(processId, reason);
}

// ============================================================================
// CROSS-MODULE INTEGRATION IMPLEMENTATIONS
// ============================================================================

void AMSIIntegration::ReportBypassToBehaviorAnalyzer(const AmsiBypassEvent& event) {
    m_impl->ReportBypassToBehaviorAnalyzerImpl(event);
}

void AMSIIntegration::ReportBypassToAlertSystem(const AmsiBypassEvent& event) {
    m_impl->ReportBypassToAlertSystemImpl(event);
}

[[nodiscard]] bool AMSIIntegration::QueryThreatIntel(
    const std::string& sha256Hash,
    double& outRiskScore,
    std::string& outThreatName) const {
    return m_impl->QueryThreatIntelImpl(sha256Hash, outRiskScore, outThreatName);
}

[[nodiscard]] bool AMSIIntegration::IsWhitelisted(const std::string& sha256Hash) const {
    return m_impl->IsWhitelistedImpl(sha256Hash);
}

}  // namespace Scripts
}  // namespace ShadowStrike
