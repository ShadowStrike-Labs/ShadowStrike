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
 * endpoint protection, competing with CrowdStrike Falcon, Kaspersky, and
 * BitDefender's script scanning engines.
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
#include "AMSIIntegration.hpp"

// ============================================================================
// WINDOWS AMSI SDK
// ============================================================================

#include <amsi.h>
#pragma comment(lib, "amsi.lib")

// ============================================================================
// STANDARD LIBRARY
// ============================================================================

#include <sstream>
#include <iomanip>
#include <algorithm>
#include <random>
#include <thread>
#include <condition_variable>

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE
// ============================================================================

#include "../Utils/StringUtils.hpp"

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
constexpr std::array<uint8_t, 6> BYPASS_PATTERN_XOR_EAX = { 0x31, 0xC0, 0xC3 };       // xor eax, eax; ret
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

// Convert wide string to narrow string (UTF-8)
[[nodiscard]] std::string WideToUtf8(const std::wstring& wide) {
    if (wide.empty()) return {};

    int size = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(),
                                    static_cast<int>(wide.size()),
                                    nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};

    std::string result(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(),
                        static_cast<int>(wide.size()),
                        result.data(), size, nullptr, nullptr);
    return result;
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
    oss << "\"applicationName\":\"" << EscapeJsonString(WideToUtf8(applicationName)) << "\",";
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
    oss << "\"processName\":\"" << EscapeJsonString(WideToUtf8(processName)) << "\",";
    oss << "\"processPath\":\"" << EscapeJsonString(WideToUtf8(processPath)) << "\",";
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
    for (auto& ct : byContentType) {
        ct.store(0, std::memory_order_relaxed);
    }
    startTime = Clock::now();
}

[[nodiscard]] std::string AMSIStatistics::ToJson() const {
    auto uptimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now() - startTime).count();

    std::ostringstream oss;
    oss << "{";
    oss << "\"totalScans\":" << totalScans.load(std::memory_order_relaxed) << ",";
    oss << "\"maliciousDetected\":" << maliciousDetected.load(std::memory_order_relaxed) << ",";
    oss << "\"cleanResults\":" << cleanResults.load(std::memory_order_relaxed) << ",";
    oss << "\"sessionsCreated\":" << sessionsCreated.load(std::memory_order_relaxed) << ",";
    oss << "\"bypassAttemptsDetected\":" << bypassAttemptsDetected.load(std::memory_order_relaxed) << ",";
    oss << "\"bypassesRepaired\":" << bypassesRepaired.load(std::memory_order_relaxed) << ",";
    oss << "\"integrityChecks\":" << integrityChecks.load(std::memory_order_relaxed) << ",";
    oss << "\"integrityFailures\":" << integrityFailures.load(std::memory_order_relaxed) << ",";
    oss << "\"totalBytesScanned\":" << totalBytesScanned.load(std::memory_order_relaxed) << ",";
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
        std::unique_lock lock(m_mutex);

        if (m_status == ModuleStatus::Uninitialized ||
            m_status == ModuleStatus::Stopped) {
            return;
        }

        m_status = ModuleStatus::Stopping;

        // Stop integrity monitor
        m_integrityMonitorRunning = false;
        m_integrityMonitorCV.notify_all();

        lock.unlock();

        if (m_integrityMonitorThread.joinable()) {
            m_integrityMonitorThread.join();
        }

        lock.lock();

        // Close all sessions
        for (auto& [id, session] : m_sessions) {
            if (session.sessionHandle != 0) {
                AmsiCloseSession(m_amsiContext,
                    reinterpret_cast<HAMSISSESSION>(session.sessionHandle));
            }
        }
        m_sessions.clear();

        // Uninitialize AMSI
        if (m_amsiContext != nullptr) {
            AmsiUninitialize(m_amsiContext);
            m_amsiContext = nullptr;
        }

        m_providerStatus = ProviderStatus::Unregistered;
        m_status = ModuleStatus::Stopped;

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

        // Note: Full provider registration requires COM interface implementation
        // and registry entries. This is a simplified version that uses the
        // standard AMSI consumer interface.

        m_providerStatus = ProviderStatus::Registered;
        SS_LOG_INFO(LOG_CATEGORY, L"AMSI provider registered");
        return true;
    }

    [[nodiscard]] bool UnregisterProvider() {
        std::unique_lock lock(m_mutex);
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

        auto startTime = Clock::now();

        // Validate request
        if (request.content.empty()) {
            response.result = AmsiResult::Clean;
            SS_LOG_DEBUG(LOG_CATEGORY, L"Empty content, returning clean");
            return response;
        }

        if (request.content.size() > m_config.maxContentSize) {
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

        // Get or create session
        HAMSISSESSION amsiSession = nullptr;
        if (request.sessionId != 0) {
            std::shared_lock lock(m_mutex);
            auto it = m_sessions.find(request.sessionId);
            if (it != m_sessions.end()) {
                amsiSession = reinterpret_cast<HAMSISSESSION>(it->second.sessionHandle);
            }
        }

        // Perform AMSI scan
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

        // Convert wide string to UTF-8 bytes
        std::string utf8Content = WideToUtf8(std::wstring(content));

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

        // Direct scan using system AMSI without custom provider logic
        if (m_amsiContext == nullptr) {
            SS_LOG_ERROR(LOG_CATEGORY, L"AMSI context not initialized");
            return AmsiResult::Unknown;
        }

        AMSI_RESULT result = AMSI_RESULT_NOT_DETECTED;
        HRESULT hr = AmsiScanBuffer(
            m_amsiContext,
            const_cast<void*>(static_cast<const void*>(buffer.data())),
            static_cast<ULONG>(buffer.size()),
            std::wstring(contentName).c_str(),
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

            // Store event
            {
                std::unique_lock lock(m_mutex);
                m_recentBypassEvents.push_back(event);
                if (m_recentBypassEvents.size() > 1000) {
                    m_recentBypassEvents.erase(m_recentBypassEvents.begin());
                }
            }

            InvokeBypassCallback(event);
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

        // Note: Full repair requires reloading amsi.dll or restoring bytes
        // from disk. This is a simplified implementation that demonstrates
        // the repair flow.

        bool success = false;

        // Try to restore function prologues
        HMODULE hAmsi = GetModuleHandleW(L"amsi.dll");
        if (hAmsi == nullptr) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Cannot repair: amsi.dll not loaded");
            return false;
        }

        // Get function addresses
        auto pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
        if (pAmsiScanBuffer != nullptr) {
            success = RestoreFunctionPrologue("AmsiScanBuffer",
                reinterpret_cast<uint64_t>(pAmsiScanBuffer));
        }

        if (success) {
            m_stats.bypassesRepaired.fetch_add(1, std::memory_order_relaxed);
            SS_LOG_INFO(LOG_CATEGORY, L"AMSI repair successful for process %u", processId);
        } else {
            SS_LOG_ERROR(LOG_CATEGORY, L"AMSI repair failed for process %u", processId);
        }

        return success;
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

    [[nodiscard]] AMSIStatistics GetStatistics() const {
        // Return copy (atomic values are read safely)
        AMSIStatistics copy;
        copy.totalScans.store(m_stats.totalScans.load(std::memory_order_relaxed));
        copy.maliciousDetected.store(m_stats.maliciousDetected.load(std::memory_order_relaxed));
        copy.cleanResults.store(m_stats.cleanResults.load(std::memory_order_relaxed));
        copy.sessionsCreated.store(m_stats.sessionsCreated.load(std::memory_order_relaxed));
        copy.bypassAttemptsDetected.store(m_stats.bypassAttemptsDetected.load(std::memory_order_relaxed));
        copy.bypassesRepaired.store(m_stats.bypassesRepaired.load(std::memory_order_relaxed));
        copy.integrityChecks.store(m_stats.integrityChecks.load(std::memory_order_relaxed));
        copy.integrityFailures.store(m_stats.integrityFailures.load(std::memory_order_relaxed));
        copy.totalBytesScanned.store(m_stats.totalBytesScanned.load(std::memory_order_relaxed));
        copy.startTime = m_stats.startTime;
        return copy;
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
        HMODULE hAmsi = GetModuleHandleW(L"amsi.dll");
        if (hAmsi == nullptr) {
            // Try to load it
            hAmsi = LoadLibraryW(L"amsi.dll");
            if (hAmsi == nullptr) {
                return false;
            }
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

        // Check for RET as first instruction
        if (prologue[0] == 0xC3) return true;

        // Check for XOR EAX, EAX; RET
        if (prologue.size() >= 3 &&
            prologue[0] == 0x31 && prologue[1] == 0xC0 && prologue[2] == 0xC3) {
            return true;
        }

        // Check for MOV EAX, <error>; RET
        if (prologue.size() >= 6 && prologue[0] == 0xB8 && prologue[5] == 0xC3) {
            return true;
        }

        return false;
    }

    [[nodiscard]] AmsiBypassTechnique DetectBypassTechnique(
        const AmsiIntegrityReport& report) const {

        AmsiBypassTechnique techniques = AmsiBypassTechnique::Unknown;

        for (const auto& fs : report.functionStates) {
            if (fs.isIntact) continue;

            if (fs.functionName == "AmsiScanBuffer") {
                techniques = static_cast<AmsiBypassTechnique>(
                    static_cast<uint32_t>(techniques) |
                    static_cast<uint32_t>(AmsiBypassTechnique::AmsiScanBufferPatch));
            } else if (fs.functionName == "AmsiInitialize") {
                techniques = static_cast<AmsiBypassTechnique>(
                    static_cast<uint32_t>(techniques) |
                    static_cast<uint32_t>(AmsiBypassTechnique::AmsiInitializePatch));
            } else if (fs.functionName == "AmsiOpenSession") {
                techniques = static_cast<AmsiBypassTechnique>(
                    static_cast<uint32_t>(techniques) |
                    static_cast<uint32_t>(AmsiBypassTechnique::AmsiOpenSessionPatch));
            }

            // Check for inline hooking pattern
            if (!fs.currentPrologue.empty() &&
                (fs.currentPrologue[0] == 0xE9 || fs.currentPrologue[0] == 0xFF)) {
                techniques = static_cast<AmsiBypassTechnique>(
                    static_cast<uint32_t>(techniques) |
                    static_cast<uint32_t>(AmsiBypassTechnique::InlineHooking));
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
                // Note: Cross-process integrity checking requires additional
                // privileges and memory reading capabilities
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

    // Recent bypass events
    std::vector<AmsiBypassEvent> m_recentBypassEvents;

    // Statistics
    AMSIStatistics m_stats;

    // Callbacks
    ScanCallback m_scanCallback;
    BypassCallback m_bypassCallback;
    IntegrityCallback m_integrityCallback;
    ErrorCallback m_errorCallback;
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

[[nodiscard]] AMSIStatistics AMSIIntegration::GetStatistics() const {
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
    std::ostringstream oss;
    oss << "ShadowStrike AMSIIntegration v"
        << AMSIConstants::VERSION_MAJOR << "."
        << AMSIConstants::VERSION_MINOR << "."
        << AMSIConstants::VERSION_PATCH;
    return oss.str();
}

}  // namespace Scripts
}  // namespace ShadowStrike
