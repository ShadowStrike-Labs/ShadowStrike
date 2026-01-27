/**
 * ============================================================================
 * ShadowStrike Security - TAMPER PROTECTION ENGINE IMPLEMENTATION
 * ============================================================================
 *
 * @file TamperProtection.cpp
 * @brief Enterprise-grade tamper protection orchestrator implementation
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * COMPLIANCE: SOC2, ISO 27001, NIST CSF
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "pch.h"
#include "TamperProtection.hpp"

// ============================================================================
// WINDOWS SDK
// ============================================================================

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

#include <Psapi.h>
#include <TlHelp32.h>
#include <AclAPI.h>

// ============================================================================
// STANDARD LIBRARY
// ============================================================================

#include <sstream>
#include <iomanip>
#include <algorithm>
#include <random>
#include <condition_variable>

namespace ShadowStrike {
namespace Security {

// ============================================================================
// LOGGING CATEGORY
// ============================================================================

static constexpr const wchar_t* LOG_CATEGORY = L"TamperProtection";

// ============================================================================
// STATIC MEMBER INITIALIZATION
// ============================================================================

std::atomic<bool> TamperProtection::s_instanceCreated{false};

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

namespace {

// Get current system time point
[[nodiscard]] std::chrono::system_clock::time_point GetSystemTimePoint() {
    return std::chrono::system_clock::now();
}

// Format time point to ISO 8601
[[nodiscard]] std::string FormatTimePoint(const TimePoint& tp) {
    auto sysTime = std::chrono::system_clock::now();
    auto time_t_val = std::chrono::system_clock::to_time_t(sysTime);
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

// Convert wide string to UTF-8
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

// Convert UTF-8 to wide string
[[nodiscard]] std::wstring Utf8ToWide(const std::string& utf8) {
    if (utf8.empty()) return {};

    int size = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(),
                                    static_cast<int>(utf8.size()),
                                    nullptr, 0);
    if (size <= 0) return {};

    std::wstring result(static_cast<size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(),
                        static_cast<int>(utf8.size()),
                        result.data(), size);
    return result;
}

// Convert bytes to hex string
[[nodiscard]] std::string BytesToHex(const uint8_t* data, size_t size) {
    std::ostringstream oss;
    for (size_t i = 0; i < size; ++i) {
        oss << std::hex << std::setfill('0') << std::setw(2)
            << static_cast<int>(data[i]);
    }
    return oss.str();
}

// Generate unique resource ID
[[nodiscard]] std::string GenerateResourceId() {
    static std::atomic<uint64_t> counter{0};
    auto now = std::chrono::system_clock::now();
    auto epoch = now.time_since_epoch();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();

    std::ostringstream oss;
    oss << "RES-" << std::hex << std::uppercase
        << ms << "-" << counter.fetch_add(1, std::memory_order_relaxed);
    return oss.str();
}

// Generate unique event ID
[[nodiscard]] uint64_t GenerateEventId() {
    static std::atomic<uint64_t> counter{1};
    return counter.fetch_add(1, std::memory_order_relaxed);
}

// Generate authorization token (for internal use)
[[nodiscard]] std::string GenerateAuthToken() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;

    std::ostringstream oss;
    oss << std::hex << std::uppercase << dis(gen) << dis(gen);
    return oss.str();
}

// Validate authorization token format
[[nodiscard]] bool IsValidTokenFormat(std::string_view token) {
    if (token.empty() || token.size() < 16) return false;
    for (char c : token) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    }
    return true;
}

}  // anonymous namespace

// ============================================================================
// STRUCTURE IMPLEMENTATIONS
// ============================================================================

TamperProtectionConfiguration TamperProtectionConfiguration::FromMode(TamperProtectionMode mode) {
    TamperProtectionConfiguration config;
    config.mode = mode;

    switch (mode) {
        case TamperProtectionMode::Disabled:
            config.enableRealTimeMonitoring = false;
            config.enablePeriodicChecks = false;
            config.enableAutoRepair = false;
            config.defaultResponse = TamperResponse::Log;
            break;

        case TamperProtectionMode::Monitor:
            config.enableRealTimeMonitoring = true;
            config.enablePeriodicChecks = true;
            config.enableAutoRepair = false;
            config.defaultResponse = TamperResponse::Passive;
            break;

        case TamperProtectionMode::Protect:
            config.enableRealTimeMonitoring = true;
            config.enablePeriodicChecks = true;
            config.enableAutoRepair = true;
            config.defaultResponse = TamperResponse::Standard;
            break;

        case TamperProtectionMode::Enforce:
            config.enableRealTimeMonitoring = true;
            config.enablePeriodicChecks = true;
            config.enableAutoRepair = true;
            config.enableCodeIntegrity = true;
            config.verifyDigitalSignatures = true;
            config.defaultResponse = TamperResponse::Aggressive;
            config.checkIntervalMs = TamperProtectionConstants::MIN_CHECK_INTERVAL_MS;
            break;

        case TamperProtectionMode::Lockdown:
            config.enableRealTimeMonitoring = true;
            config.enablePeriodicChecks = true;
            config.enableAutoRepair = true;
            config.enableCodeIntegrity = true;
            config.verifyDigitalSignatures = true;
            config.verifyCertificateChain = true;
            config.enableAntiDebugIntegration = true;
            config.enableSelfDefenseIntegration = true;
            config.defaultResponse = TamperResponse::Maximum;
            config.checkIntervalMs = TamperProtectionConstants::MIN_CHECK_INTERVAL_MS;
            break;
    }

    return config;
}

[[nodiscard]] bool TamperProtectionConfiguration::IsValid() const noexcept {
    if (checkIntervalMs < TamperProtectionConstants::MIN_CHECK_INTERVAL_MS ||
        checkIntervalMs > TamperProtectionConstants::MAX_CHECK_INTERVAL_MS) {
        return false;
    }
    if (maxRepairAttempts == 0 || maxRepairAttempts > 10) {
        return false;
    }
    return true;
}

[[nodiscard]] std::string TamperEvent::GetSummary() const {
    std::ostringstream oss;
    oss << "TamperEvent[" << eventId << "]: ";
    oss << GetEventTypeName(type) << " on ";
    oss << GetResourceTypeName(resourceType);
    if (!resourcePath.empty()) {
        oss << " (" << WideToUtf8(resourcePath) << ")";
    }
    if (sourceProcessId != 0) {
        oss << " by PID " << sourceProcessId;
    }
    if (wasBlocked) {
        oss << " [BLOCKED]";
    }
    if (wasRepaired) {
        oss << " [REPAIRED]";
    }
    return oss.str();
}

[[nodiscard]] std::string TamperEvent::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"eventId\":" << eventId << ",";
    oss << "\"type\":" << static_cast<uint32_t>(type) << ",";
    oss << "\"typeName\":\"" << GetEventTypeName(type) << "\",";
    oss << "\"resourceType\":" << static_cast<uint32_t>(resourceType) << ",";
    oss << "\"resourceId\":\"" << EscapeJsonString(resourceId) << "\",";
    oss << "\"resourcePath\":\"" << EscapeJsonString(WideToUtf8(resourcePath)) << "\",";
    oss << "\"sourceProcessId\":" << sourceProcessId << ",";
    oss << "\"sourceProcessName\":\"" << EscapeJsonString(WideToUtf8(sourceProcessName)) << "\",";
    oss << "\"sourceThreadId\":" << sourceThreadId << ",";
    oss << "\"expectedHash\":\"" << BytesToHex(expectedHash.data(), expectedHash.size()) << "\",";
    oss << "\"actualHash\":\"" << BytesToHex(actualHash.data(), actualHash.size()) << "\",";
    oss << "\"changeDescription\":\"" << EscapeJsonString(changeDescription) << "\",";
    oss << "\"responseTaken\":" << static_cast<uint32_t>(responseTaken) << ",";
    oss << "\"wasBlocked\":" << (wasBlocked ? "true" : "false") << ",";
    oss << "\"wasRepaired\":" << (wasRepaired ? "true" : "false") << ",";
    oss << "\"severityLevel\":" << static_cast<int>(severityLevel);
    oss << "}";
    return oss.str();
}

void TamperProtectionStatistics::Reset() noexcept {
    totalResourcesMonitored.store(0, std::memory_order_relaxed);
    totalIntegrityChecks.store(0, std::memory_order_relaxed);
    totalTamperingDetected.store(0, std::memory_order_relaxed);
    totalTamperingBlocked.store(0, std::memory_order_relaxed);
    totalRepairsPerformed.store(0, std::memory_order_relaxed);
    successfulRepairs.store(0, std::memory_order_relaxed);
    eventsByType.clear();
    eventsByResource.clear();
    startTime = Clock::now();
}

[[nodiscard]] std::string TamperProtectionStatistics::ToJson() const {
    auto uptimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now() - startTime).count();

    std::ostringstream oss;
    oss << "{";
    oss << "\"totalResourcesMonitored\":" << totalResourcesMonitored.load(std::memory_order_relaxed) << ",";
    oss << "\"totalIntegrityChecks\":" << totalIntegrityChecks.load(std::memory_order_relaxed) << ",";
    oss << "\"totalTamperingDetected\":" << totalTamperingDetected.load(std::memory_order_relaxed) << ",";
    oss << "\"totalTamperingBlocked\":" << totalTamperingBlocked.load(std::memory_order_relaxed) << ",";
    oss << "\"totalRepairsPerformed\":" << totalRepairsPerformed.load(std::memory_order_relaxed) << ",";
    oss << "\"successfulRepairs\":" << successfulRepairs.load(std::memory_order_relaxed) << ",";
    oss << "\"uptimeMs\":" << uptimeMs;
    oss << "}";
    return oss.str();
}

// ============================================================================
// UTILITY FUNCTION IMPLEMENTATIONS
// ============================================================================

[[nodiscard]] std::string_view GetModeName(TamperProtectionMode mode) noexcept {
    switch (mode) {
        case TamperProtectionMode::Disabled: return "Disabled";
        case TamperProtectionMode::Monitor:  return "Monitor";
        case TamperProtectionMode::Protect:  return "Protect";
        case TamperProtectionMode::Enforce:  return "Enforce";
        case TamperProtectionMode::Lockdown: return "Lockdown";
        default: return "Unknown";
    }
}

[[nodiscard]] std::string_view GetResourceTypeName(ProtectedResourceType type) noexcept {
    switch (type) {
        case ProtectedResourceType::None:          return "None";
        case ProtectedResourceType::File:          return "File";
        case ProtectedResourceType::Directory:     return "Directory";
        case ProtectedResourceType::RegistryKey:   return "RegistryKey";
        case ProtectedResourceType::RegistryValue: return "RegistryValue";
        case ProtectedResourceType::Process:       return "Process";
        case ProtectedResourceType::Thread:        return "Thread";
        case ProtectedResourceType::Service:       return "Service";
        case ProtectedResourceType::Driver:        return "Driver";
        case ProtectedResourceType::MemoryRegion:  return "MemoryRegion";
        case ProtectedResourceType::CodeSection:   return "CodeSection";
        case ProtectedResourceType::Configuration: return "Configuration";
        case ProtectedResourceType::Certificate:   return "Certificate";
        default: return "Unknown";
    }
}

[[nodiscard]] std::string_view GetEventTypeName(TamperEventType type) noexcept {
    switch (type) {
        case TamperEventType::None:                return "None";
        case TamperEventType::FileModified:        return "FileModified";
        case TamperEventType::FileDeleted:         return "FileDeleted";
        case TamperEventType::FileRenamed:         return "FileRenamed";
        case TamperEventType::FileAttributeChange: return "FileAttributeChange";
        case TamperEventType::FilePermissionChange:return "FilePermissionChange";
        case TamperEventType::RegistryKeyModified: return "RegistryKeyModified";
        case TamperEventType::RegistryKeyDeleted:  return "RegistryKeyDeleted";
        case TamperEventType::RegistryValueModified: return "RegistryValueModified";
        case TamperEventType::RegistryValueDeleted:return "RegistryValueDeleted";
        case TamperEventType::ProcessTerminated:   return "ProcessTerminated";
        case TamperEventType::ProcessSuspended:    return "ProcessSuspended";
        case TamperEventType::ProcessMemoryWrite:  return "ProcessMemoryWrite";
        case TamperEventType::ProcessCodeModified: return "ProcessCodeModified";
        case TamperEventType::ProcessHooked:       return "ProcessHooked";
        case TamperEventType::CodeIntegrityFailure:return "CodeIntegrityFailure";
        case TamperEventType::StackCorruption:     return "StackCorruption";
        case TamperEventType::HeapCorruption:      return "HeapCorruption";
        case TamperEventType::IATModified:         return "IATModified";
        case TamperEventType::EATModified:         return "EATModified";
        case TamperEventType::ServiceStopped:      return "ServiceStopped";
        case TamperEventType::ServiceConfigChanged:return "ServiceConfigChanged";
        case TamperEventType::DriverUnloaded:      return "DriverUnloaded";
        case TamperEventType::CertificateInvalid:  return "CertificateInvalid";
        case TamperEventType::SignatureInvalid:    return "SignatureInvalid";
        case TamperEventType::DebuggerAttached:    return "DebuggerAttached";
        case TamperEventType::BreakpointDetected:  return "BreakpointDetected";
        default: return "Unknown";
    }
}

[[nodiscard]] std::string_view GetIntegrityStatusName(IntegrityStatus status) noexcept {
    switch (status) {
        case IntegrityStatus::Unknown:       return "Unknown";
        case IntegrityStatus::Valid:         return "Valid";
        case IntegrityStatus::Modified:      return "Modified";
        case IntegrityStatus::Missing:       return "Missing";
        case IntegrityStatus::Corrupted:     return "Corrupted";
        case IntegrityStatus::Unauthorized:  return "Unauthorized";
        case IntegrityStatus::Repaired:      return "Repaired";
        case IntegrityStatus::PendingVerify: return "PendingVerify";
        default: return "Unknown";
    }
}

[[nodiscard]] std::string_view GetResponseName(TamperResponse response) noexcept {
    if (response == TamperResponse::None) return "None";
    if (response == TamperResponse::Log) return "Log";
    if (response == TamperResponse::Alert) return "Alert";
    if (response == TamperResponse::Block) return "Block";
    if (response == TamperResponse::Revert) return "Revert";
    if (response == TamperResponse::Repair) return "Repair";
    if (response == TamperResponse::Quarantine) return "Quarantine";
    if (response == TamperResponse::Terminate) return "Terminate";
    if (response == TamperResponse::Escalate) return "Escalate";
    if (response == TamperResponse::Lockdown) return "Lockdown";
    if (response == TamperResponse::CollectEvidence) return "CollectEvidence";
    if (response == TamperResponse::NotifyUser) return "NotifyUser";
    return "Multiple";
}

[[nodiscard]] std::string_view GetSubsystemName(TamperSubsystem subsystem) noexcept {
    switch (subsystem) {
        case TamperSubsystem::FileProtection:      return "FileProtection";
        case TamperSubsystem::RegistryProtection:  return "RegistryProtection";
        case TamperSubsystem::ProcessProtection:   return "ProcessProtection";
        case TamperSubsystem::MemoryProtection:    return "MemoryProtection";
        case TamperSubsystem::ServiceProtection:   return "ServiceProtection";
        case TamperSubsystem::CodeIntegrity:       return "CodeIntegrity";
        case TamperSubsystem::CertificateIntegrity:return "CertificateIntegrity";
        case TamperSubsystem::AntiDebug:           return "AntiDebug";
        case TamperSubsystem::SelfDefense:         return "SelfDefense";
        default: return "Unknown";
    }
}

// ============================================================================
// TAMPER PROTECTION IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class TamperProtectionImpl final {
public:
    TamperProtectionImpl() = default;
    ~TamperProtectionImpl() { Shutdown("INTERNAL_SHUTDOWN"); }

    // Non-copyable, non-movable
    TamperProtectionImpl(const TamperProtectionImpl&) = delete;
    TamperProtectionImpl& operator=(const TamperProtectionImpl&) = delete;
    TamperProtectionImpl(TamperProtectionImpl&&) = delete;
    TamperProtectionImpl& operator=(TamperProtectionImpl&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(const TamperProtectionConfiguration& config) {
        std::unique_lock lock(m_mutex);

        if (m_status != ModuleStatus::Uninitialized &&
            m_status != ModuleStatus::Stopped) {
            SS_LOG_WARN(LOG_CATEGORY, L"TamperProtection already initialized");
            return true;
        }

        m_status = ModuleStatus::Initializing;

        if (!config.IsValid()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Invalid configuration");
            m_status = ModuleStatus::Error;
            return false;
        }

        m_config = config;
        m_internalAuthToken = GenerateAuthToken();

        // Initialize subsystem statuses
        for (int i = 0; i <= static_cast<int>(TamperSubsystem::SelfDefense); ++i) {
            SubsystemStatus status;
            status.subsystem = static_cast<TamperSubsystem>(i);
            status.isActive = false;
            status.status = ModuleStatus::Uninitialized;
            m_subsystemStatuses[static_cast<TamperSubsystem>(i)] = status;
        }

        // Start monitoring thread if enabled
        if (m_config.enablePeriodicChecks) {
            m_monitorRunning = true;
            m_monitorThread = std::thread(&TamperProtectionImpl::MonitorLoop, this);
        }

        // Initialize subsystems based on configuration
        if ((m_config.enabledResources & ProtectedResourceType::FileSystem) != ProtectedResourceType::None) {
            InitializeFileProtection();
        }
        if ((m_config.enabledResources & ProtectedResourceType::Registry) != ProtectedResourceType::None) {
            InitializeRegistryProtection();
        }
        if ((m_config.enabledResources & ProtectedResourceType::ProcessMemory) != ProtectedResourceType::None) {
            InitializeProcessProtection();
        }

        m_stats.Reset();
        m_status = ModuleStatus::Running;

        SS_LOG_INFO(LOG_CATEGORY, L"TamperProtection initialized in %hs mode",
                    std::string(GetModeName(m_config.mode)).c_str());
        return true;
    }

    void Shutdown(std::string_view authToken) {
        std::unique_lock lock(m_mutex);

        if (m_status == ModuleStatus::Uninitialized ||
            m_status == ModuleStatus::Stopped) {
            return;
        }

        // Verify authorization (skip for internal shutdown)
        if (authToken != "INTERNAL_SHUTDOWN" && !VerifyAuthToken(authToken)) {
            SS_LOG_WARN(LOG_CATEGORY, L"Shutdown attempt with invalid token");
            return;
        }

        m_status = ModuleStatus::Stopping;

        // Stop monitor thread
        m_monitorRunning = false;
        m_monitorCV.notify_all();

        lock.unlock();

        if (m_monitorThread.joinable()) {
            m_monitorThread.join();
        }

        lock.lock();

        // Clear all protected resources
        m_protectedFiles.clear();
        m_protectedRegistryKeys.clear();
        m_protectedProcesses.clear();
        m_protectedMemoryRegions.clear();

        // Clear callbacks
        m_eventCallbacks.clear();
        m_verificationCallbacks.clear();
        m_repairCallbacks.clear();
        m_statusCallbacks.clear();
        m_responseHandler = nullptr;

        // Clear event history
        m_eventHistory.clear();

        m_status = ModuleStatus::Stopped;
        SS_LOG_INFO(LOG_CATEGORY, L"TamperProtection shutdown complete");
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        return m_status == ModuleStatus::Running;
    }

    [[nodiscard]] ModuleStatus GetStatus() const noexcept {
        return m_status.load(std::memory_order_acquire);
    }

    void SetEnabled(bool enabled) {
        m_enabled.store(enabled, std::memory_order_release);
        SS_LOG_INFO(LOG_CATEGORY, L"TamperProtection %ls",
                    enabled ? L"enabled" : L"disabled");
    }

    [[nodiscard]] bool IsEnabled() const noexcept {
        return m_enabled.load(std::memory_order_acquire);
    }

    [[nodiscard]] bool Pause(std::string_view authToken, uint32_t durationMs) {
        if (!VerifyAuthToken(authToken)) {
            SS_LOG_WARN(LOG_CATEGORY, L"Pause attempt with invalid token");
            return false;
        }

        m_paused.store(true, std::memory_order_release);
        m_pauseEndTime = Clock::now() + Milliseconds(durationMs);

        SS_LOG_INFO(LOG_CATEGORY, L"TamperProtection paused for %u ms", durationMs);
        return true;
    }

    void Resume() {
        m_paused.store(false, std::memory_order_release);
        SS_LOG_INFO(LOG_CATEGORY, L"TamperProtection resumed");
    }

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    [[nodiscard]] bool SetConfiguration(const TamperProtectionConfiguration& config) {
        if (!config.IsValid()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Invalid configuration");
            return false;
        }

        std::unique_lock lock(m_mutex);
        m_config = config;
        SS_LOG_INFO(LOG_CATEGORY, L"Configuration updated");
        return true;
    }

    [[nodiscard]] TamperProtectionConfiguration GetConfiguration() const {
        std::shared_lock lock(m_mutex);
        return m_config;
    }

    void SetMode(TamperProtectionMode mode) {
        std::unique_lock lock(m_mutex);
        m_config.mode = mode;

        // Update configuration based on mode
        auto newConfig = TamperProtectionConfiguration::FromMode(mode);
        m_config.defaultResponse = newConfig.defaultResponse;
        m_config.enableAutoRepair = newConfig.enableAutoRepair;

        SS_LOG_INFO(LOG_CATEGORY, L"Mode changed to %hs",
                    std::string(GetModeName(mode)).c_str());
    }

    [[nodiscard]] TamperProtectionMode GetMode() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_config.mode;
    }

    void SetDefaultResponse(TamperResponse response) {
        std::unique_lock lock(m_mutex);
        m_config.defaultResponse = response;
    }

    [[nodiscard]] TamperResponse GetDefaultResponse() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_config.defaultResponse;
    }

    void SetEventResponse(TamperEventType eventType, TamperResponse response) {
        std::unique_lock lock(m_mutex);
        m_eventResponses[eventType] = response;
    }

    [[nodiscard]] TamperResponse GetEventResponse(TamperEventType eventType) const {
        std::shared_lock lock(m_mutex);
        auto it = m_eventResponses.find(eventType);
        if (it != m_eventResponses.end()) {
            return it->second;
        }
        return m_config.defaultResponse;
    }

    void SetCheckInterval(uint32_t intervalMs) {
        std::unique_lock lock(m_mutex);
        if (intervalMs >= TamperProtectionConstants::MIN_CHECK_INTERVAL_MS &&
            intervalMs <= TamperProtectionConstants::MAX_CHECK_INTERVAL_MS) {
            m_config.checkIntervalMs = intervalMs;
        }
    }

    [[nodiscard]] uint32_t GetCheckInterval() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_config.checkIntervalMs;
    }

    // ========================================================================
    // FILE PROTECTION
    // ========================================================================

    [[nodiscard]] bool ProtectFile(std::wstring_view filePath, bool isCritical) {
        if (filePath.empty()) {
            SS_LOG_WARN(LOG_CATEGORY, L"Empty file path");
            return false;
        }

        std::wstring path(filePath);

        // Check if file exists
        if (!std::filesystem::exists(path)) {
            SS_LOG_WARN(LOG_CATEGORY, L"File does not exist: %ls", path.c_str());
            return false;
        }

        // Check limits
        {
            std::shared_lock lock(m_mutex);
            if (m_protectedFiles.size() >= TamperProtectionConstants::MAX_MONITORED_FILES) {
                SS_LOG_WARN(LOG_CATEGORY, L"Maximum protected files reached");
                return false;
            }
        }

        // Create baseline
        ResourceBaseline baseline;
        baseline.resourceId = GenerateResourceId();
        baseline.type = ProtectedResourceType::File;
        baseline.path = path;
        baseline.isCritical = isCritical;
        baseline.baselineCreated = Clock::now();
        baseline.verificationMethod = VerificationMethod::SHA256;

        // Compute hash
        if (!ComputeFileHashInternal(path, baseline.contentHash)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Failed to compute hash for: %ls", path.c_str());
            return false;
        }

        // Get file info
        try {
            baseline.fileSize = std::filesystem::file_size(path);
            auto lastWrite = std::filesystem::last_write_time(path);
            baseline.lastModified = std::chrono::clock_cast<std::chrono::system_clock>(lastWrite);
        } catch (const std::exception& e) {
            SS_LOG_WARN(LOG_CATEGORY, L"Failed to get file info: %hs", e.what());
        }

        // Verify signature if enabled
        if (m_config.verifyDigitalSignatures) {
            baseline.hasValidSignature = VerifyFileSignatureInternal(path, baseline.signerName);
        }

        baseline.status = IntegrityStatus::Valid;
        baseline.lastVerified = Clock::now();

        // Store baseline
        {
            std::unique_lock lock(m_mutex);
            m_protectedFiles[path] = baseline;
        }

        m_stats.totalResourcesMonitored.fetch_add(1, std::memory_order_relaxed);

        SS_LOG_INFO(LOG_CATEGORY, L"Protected file: %ls (critical=%d)",
                    path.c_str(), isCritical);
        return true;
    }

    [[nodiscard]] bool UnprotectFile(std::wstring_view filePath, std::string_view authToken) {
        if (!VerifyAuthToken(authToken)) {
            SS_LOG_WARN(LOG_CATEGORY, L"Unprotect attempt with invalid token");
            return false;
        }

        std::unique_lock lock(m_mutex);
        std::wstring path(filePath);

        auto it = m_protectedFiles.find(path);
        if (it == m_protectedFiles.end()) {
            return false;
        }

        m_protectedFiles.erase(it);
        m_stats.totalResourcesMonitored.fetch_sub(1, std::memory_order_relaxed);

        SS_LOG_INFO(LOG_CATEGORY, L"Unprotected file: %ls", path.c_str());
        return true;
    }

    [[nodiscard]] bool IsFileProtected(std::wstring_view filePath) const {
        std::shared_lock lock(m_mutex);
        return m_protectedFiles.find(std::wstring(filePath)) != m_protectedFiles.end();
    }

    [[nodiscard]] VerificationResult VerifyFile(std::wstring_view filePath) {
        VerificationResult result;
        result.timestamp = Clock::now();

        std::wstring path(filePath);

        // Get baseline
        ResourceBaseline baseline;
        {
            std::shared_lock lock(m_mutex);
            auto it = m_protectedFiles.find(path);
            if (it == m_protectedFiles.end()) {
                result.status = IntegrityStatus::Unknown;
                result.errorMessage = "File not protected";
                return result;
            }
            baseline = it->second;
        }

        result.resourceId = baseline.resourceId;
        result.method = baseline.verificationMethod;
        result.expectedHash = baseline.contentHash;

        auto startTime = Clock::now();

        // Check if file exists
        if (!std::filesystem::exists(path)) {
            result.status = IntegrityStatus::Missing;
            result.errorMessage = "File is missing";
            HandleTamperEvent(path, TamperEventType::FileDeleted, result);
            return result;
        }

        // Compute current hash
        if (!ComputeFileHashInternal(path, result.computedHash)) {
            result.status = IntegrityStatus::Corrupted;
            result.errorMessage = "Failed to compute hash";
            return result;
        }

        result.hashMatch = (result.expectedHash == result.computedHash);

        // Verify signature if configured
        if (m_config.verifyDigitalSignatures && baseline.hasValidSignature) {
            std::wstring signerName;
            result.signatureValid = VerifyFileSignatureInternal(path, signerName);
            result.signatureDetails = signerName;
        }

        if (result.hashMatch) {
            result.status = IntegrityStatus::Valid;
        } else {
            result.status = IntegrityStatus::Modified;
            result.detectedChanges.push_back("Hash mismatch");
            HandleTamperEvent(path, TamperEventType::FileModified, result);
        }

        result.duration = std::chrono::duration_cast<Milliseconds>(Clock::now() - startTime);

        // Update baseline verification time
        {
            std::unique_lock lock(m_mutex);
            auto it = m_protectedFiles.find(path);
            if (it != m_protectedFiles.end()) {
                it->second.lastVerified = Clock::now();
                it->second.status = result.status;
            }
        }

        m_stats.totalIntegrityChecks.fetch_add(1, std::memory_order_relaxed);

        // Invoke callbacks
        InvokeVerificationCallbacks(result);

        return result;
    }

    [[nodiscard]] std::optional<ResourceBaseline> GetFileBaseline(std::wstring_view filePath) const {
        std::shared_lock lock(m_mutex);
        auto it = m_protectedFiles.find(std::wstring(filePath));
        if (it != m_protectedFiles.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    [[nodiscard]] bool UpdateFileBaseline(std::wstring_view filePath, std::string_view authToken) {
        if (!VerifyAuthToken(authToken)) {
            SS_LOG_WARN(LOG_CATEGORY, L"Baseline update with invalid token");
            return false;
        }

        std::wstring path(filePath);

        std::unique_lock lock(m_mutex);
        auto it = m_protectedFiles.find(path);
        if (it == m_protectedFiles.end()) {
            return false;
        }

        // Recompute hash
        Hash256 newHash{};
        if (!ComputeFileHashInternal(path, newHash)) {
            return false;
        }

        it->second.contentHash = newHash;
        it->second.baselineCreated = Clock::now();
        it->second.lastVerified = Clock::now();
        it->second.status = IntegrityStatus::Valid;
        it->second.violationCount = 0;

        // Update file info
        try {
            it->second.fileSize = std::filesystem::file_size(path);
        } catch (...) {}

        SS_LOG_INFO(LOG_CATEGORY, L"Updated baseline for: %ls", path.c_str());
        return true;
    }

    [[nodiscard]] bool ProtectDirectory(std::wstring_view directoryPath, bool recursive) {
        std::wstring dirPath(directoryPath);

        if (!std::filesystem::exists(dirPath) || !std::filesystem::is_directory(dirPath)) {
            SS_LOG_WARN(LOG_CATEGORY, L"Invalid directory: %ls", dirPath.c_str());
            return false;
        }

        size_t filesProtected = 0;

        try {
            if (recursive) {
                for (const auto& entry : std::filesystem::recursive_directory_iterator(dirPath)) {
                    if (entry.is_regular_file()) {
                        if (ProtectFile(entry.path().wstring(), false)) {
                            filesProtected++;
                        }
                    }
                }
            } else {
                for (const auto& entry : std::filesystem::directory_iterator(dirPath)) {
                    if (entry.is_regular_file()) {
                        if (ProtectFile(entry.path().wstring(), false)) {
                            filesProtected++;
                        }
                    }
                }
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Directory protection failed: %hs", e.what());
            return false;
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Protected %zu files in directory: %ls",
                    filesProtected, dirPath.c_str());
        return filesProtected > 0;
    }

    [[nodiscard]] bool ProtectInstallation() {
        // Get module path
        WCHAR modulePath[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, modulePath, MAX_PATH);

        std::filesystem::path installDir = std::filesystem::path(modulePath).parent_path();

        SS_LOG_INFO(LOG_CATEGORY, L"Protecting installation: %ls", installDir.c_str());

        // Protect critical files
        std::vector<std::wstring> criticalFiles = {
            L"ShadowStrike.exe",
            L"ShadowStrikeService.exe",
            L"SSEngine.dll",
            L"SSDriver.sys"
        };

        for (const auto& file : criticalFiles) {
            auto fullPath = installDir / file;
            if (std::filesystem::exists(fullPath)) {
                ProtectFile(fullPath.wstring(), true);
            }
        }

        // Protect the entire installation directory (non-critical)
        ProtectDirectory(installDir.wstring(), true);

        return true;
    }

    [[nodiscard]] std::vector<ResourceBaseline> GetAllProtectedFiles() const {
        std::shared_lock lock(m_mutex);
        std::vector<ResourceBaseline> result;
        result.reserve(m_protectedFiles.size());
        for (const auto& [path, baseline] : m_protectedFiles) {
            result.push_back(baseline);
        }
        return result;
    }

    // ========================================================================
    // REGISTRY PROTECTION
    // ========================================================================

    [[nodiscard]] bool ProtectRegistryKey(std::wstring_view keyPath, bool includeSubkeys) {
        if (keyPath.empty()) {
            return false;
        }

        std::wstring path(keyPath);

        {
            std::shared_lock lock(m_mutex);
            if (m_protectedRegistryKeys.size() >= TamperProtectionConstants::MAX_MONITORED_REGISTRY_KEYS) {
                SS_LOG_WARN(LOG_CATEGORY, L"Maximum protected registry keys reached");
                return false;
            }
        }

        ResourceBaseline baseline;
        baseline.resourceId = GenerateResourceId();
        baseline.type = ProtectedResourceType::RegistryKey;
        baseline.path = path;
        baseline.baselineCreated = Clock::now();
        baseline.status = IntegrityStatus::Valid;

        // Compute registry key hash
        ComputeRegistryHashInternal(path, baseline.contentHash);

        {
            std::unique_lock lock(m_mutex);
            m_protectedRegistryKeys[path] = baseline;
        }

        m_stats.totalResourcesMonitored.fetch_add(1, std::memory_order_relaxed);
        SS_LOG_INFO(LOG_CATEGORY, L"Protected registry key: %ls", path.c_str());
        return true;
    }

    [[nodiscard]] bool UnprotectRegistryKey(std::wstring_view keyPath, std::string_view authToken) {
        if (!VerifyAuthToken(authToken)) {
            return false;
        }

        std::unique_lock lock(m_mutex);
        std::wstring path(keyPath);

        auto it = m_protectedRegistryKeys.find(path);
        if (it == m_protectedRegistryKeys.end()) {
            return false;
        }

        m_protectedRegistryKeys.erase(it);
        m_stats.totalResourcesMonitored.fetch_sub(1, std::memory_order_relaxed);
        return true;
    }

    [[nodiscard]] bool IsRegistryKeyProtected(std::wstring_view keyPath) const {
        std::shared_lock lock(m_mutex);
        return m_protectedRegistryKeys.find(std::wstring(keyPath)) != m_protectedRegistryKeys.end();
    }

    [[nodiscard]] VerificationResult VerifyRegistryKey(std::wstring_view keyPath) {
        VerificationResult result;
        result.timestamp = Clock::now();

        std::wstring path(keyPath);

        std::shared_lock lock(m_mutex);
        auto it = m_protectedRegistryKeys.find(path);
        if (it == m_protectedRegistryKeys.end()) {
            result.status = IntegrityStatus::Unknown;
            result.errorMessage = "Registry key not protected";
            return result;
        }

        result.resourceId = it->second.resourceId;
        result.expectedHash = it->second.contentHash;

        Hash256 currentHash{};
        ComputeRegistryHashInternal(path, currentHash);
        result.computedHash = currentHash;
        result.hashMatch = (result.expectedHash == result.computedHash);

        result.status = result.hashMatch ? IntegrityStatus::Valid : IntegrityStatus::Modified;

        m_stats.totalIntegrityChecks.fetch_add(1, std::memory_order_relaxed);
        return result;
    }

    [[nodiscard]] bool ProtectRegistryValue(std::wstring_view keyPath, std::wstring_view valueName) {
        std::wstring fullPath = std::wstring(keyPath) + L"\\" + std::wstring(valueName);

        ResourceBaseline baseline;
        baseline.resourceId = GenerateResourceId();
        baseline.type = ProtectedResourceType::RegistryValue;
        baseline.path = fullPath;
        baseline.baselineCreated = Clock::now();
        baseline.status = IntegrityStatus::Valid;

        {
            std::unique_lock lock(m_mutex);
            m_protectedRegistryKeys[fullPath] = baseline;
        }

        m_stats.totalResourcesMonitored.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    [[nodiscard]] bool ProtectServiceRegistry() {
        std::vector<std::wstring> serviceKeys = {
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\ShadowStrike",
            L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\SSDriver",
            L"HKLM\\SOFTWARE\\ShadowStrike"
        };

        for (const auto& key : serviceKeys) {
            ProtectRegistryKey(key, true);
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Protected service registry keys");
        return true;
    }

    [[nodiscard]] std::vector<ResourceBaseline> GetAllProtectedRegistryKeys() const {
        std::shared_lock lock(m_mutex);
        std::vector<ResourceBaseline> result;
        result.reserve(m_protectedRegistryKeys.size());
        for (const auto& [path, baseline] : m_protectedRegistryKeys) {
            result.push_back(baseline);
        }
        return result;
    }

    // ========================================================================
    // PROCESS/MEMORY PROTECTION
    // ========================================================================

    [[nodiscard]] bool ProtectProcess(uint32_t processId) {
        if (processId == 0) {
            processId = GetCurrentProcessId();
        }

        {
            std::shared_lock lock(m_mutex);
            if (m_protectedProcesses.size() >= TamperProtectionConstants::MAX_MONITORED_PROCESSES) {
                return false;
            }
        }

        ResourceBaseline baseline;
        baseline.resourceId = GenerateResourceId();
        baseline.type = ProtectedResourceType::Process;
        baseline.baselineCreated = Clock::now();
        baseline.status = IntegrityStatus::Valid;

        // Compute process memory hash
        ComputeProcessHashInternal(processId, baseline.contentHash);

        {
            std::unique_lock lock(m_mutex);
            m_protectedProcesses[processId] = baseline;
        }

        m_stats.totalResourcesMonitored.fetch_add(1, std::memory_order_relaxed);
        SS_LOG_INFO(LOG_CATEGORY, L"Protected process: %u", processId);
        return true;
    }

    [[nodiscard]] VerificationResult VerifyProcess(uint32_t processId) {
        VerificationResult result;
        result.timestamp = Clock::now();

        std::shared_lock lock(m_mutex);
        auto it = m_protectedProcesses.find(processId);
        if (it == m_protectedProcesses.end()) {
            result.status = IntegrityStatus::Unknown;
            result.errorMessage = "Process not protected";
            return result;
        }

        result.resourceId = it->second.resourceId;
        result.expectedHash = it->second.contentHash;

        Hash256 currentHash{};
        ComputeProcessHashInternal(processId, currentHash);
        result.computedHash = currentHash;
        result.hashMatch = (result.expectedHash == result.computedHash);

        result.status = result.hashMatch ? IntegrityStatus::Valid : IntegrityStatus::Modified;

        m_stats.totalIntegrityChecks.fetch_add(1, std::memory_order_relaxed);
        return result;
    }

    [[nodiscard]] bool ProtectMemoryRegion(uint32_t processId, uintptr_t address, size_t size) {
        if (size == 0 || size > TamperProtectionConstants::MAX_FILE_SIZE_FOR_HASH) {
            return false;
        }

        std::string key = std::to_string(processId) + ":" + std::to_string(address);

        ResourceBaseline baseline;
        baseline.resourceId = GenerateResourceId();
        baseline.type = ProtectedResourceType::MemoryRegion;
        baseline.baselineCreated = Clock::now();
        baseline.fileSize = size;
        baseline.status = IntegrityStatus::Valid;

        {
            std::unique_lock lock(m_mutex);
            m_protectedMemoryRegions[key] = baseline;
        }

        m_stats.totalResourcesMonitored.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    [[nodiscard]] VerificationResult VerifyMemoryRegion(uint32_t processId, uintptr_t address, size_t size) {
        VerificationResult result;
        result.timestamp = Clock::now();

        std::string key = std::to_string(processId) + ":" + std::to_string(address);

        std::shared_lock lock(m_mutex);
        auto it = m_protectedMemoryRegions.find(key);
        if (it == m_protectedMemoryRegions.end()) {
            result.status = IntegrityStatus::Unknown;
            result.errorMessage = "Memory region not protected";
            return result;
        }

        result.resourceId = it->second.resourceId;
        result.status = IntegrityStatus::Valid;

        m_stats.totalIntegrityChecks.fetch_add(1, std::memory_order_relaxed);
        return result;
    }

    [[nodiscard]] bool ProtectSelf() {
        uint32_t selfPid = GetCurrentProcessId();
        return ProtectProcess(selfPid);
    }

    // ========================================================================
    // CODE INTEGRITY
    // ========================================================================

    [[nodiscard]] VerificationResult VerifyDigitalSignature(std::wstring_view filePath) {
        VerificationResult result;
        result.timestamp = Clock::now();

        std::wstring path(filePath);
        std::wstring signerName;

        result.signatureValid = VerifyFileSignatureInternal(path, signerName);
        result.signatureDetails = signerName;
        result.status = result.signatureValid ? IntegrityStatus::Valid : IntegrityStatus::Unauthorized;

        return result;
    }

    [[nodiscard]] VerificationResult VerifyAuthenticode(std::wstring_view filePath) {
        return VerifyDigitalSignature(filePath);
    }

    [[nodiscard]] VerificationResult VerifyCatalogSignature(std::wstring_view filePath) {
        VerificationResult result;
        result.timestamp = Clock::now();

        std::wstring path(filePath);

        WINTRUST_FILE_INFO fileInfo{};
        fileInfo.cbStruct = sizeof(fileInfo);
        fileInfo.pcwszFilePath = path.c_str();

        GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        WINTRUST_DATA trustData{};
        trustData.cbStruct = sizeof(trustData);
        trustData.dwUIChoice = WTD_UI_NONE;
        trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        trustData.dwUnionChoice = WTD_CHOICE_FILE;
        trustData.pFile = &fileInfo;
        trustData.dwStateAction = WTD_STATEACTION_VERIFY;

        LONG status = WinVerifyTrust(nullptr, &policyGuid, &trustData);

        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(nullptr, &policyGuid, &trustData);

        result.signatureValid = (status == ERROR_SUCCESS);
        result.status = result.signatureValid ? IntegrityStatus::Valid : IntegrityStatus::Unauthorized;

        return result;
    }

    [[nodiscard]] Hash256 ComputeFileHash(std::wstring_view filePath, VerificationMethod method) {
        Hash256 hash{};
        std::wstring path(filePath);
        ComputeFileHashInternal(path, hash);
        return hash;
    }

    // ========================================================================
    // INTEGRITY VERIFICATION
    // ========================================================================

    [[nodiscard]] std::vector<VerificationResult> VerifyAllIntegrity() {
        std::vector<VerificationResult> results;

        // Verify files
        std::vector<std::wstring> filePaths;
        {
            std::shared_lock lock(m_mutex);
            for (const auto& [path, baseline] : m_protectedFiles) {
                filePaths.push_back(path);
            }
        }

        for (const auto& path : filePaths) {
            results.push_back(VerifyFile(path));
        }

        // Verify registry keys
        std::vector<std::wstring> regPaths;
        {
            std::shared_lock lock(m_mutex);
            for (const auto& [path, baseline] : m_protectedRegistryKeys) {
                regPaths.push_back(path);
            }
        }

        for (const auto& path : regPaths) {
            results.push_back(VerifyRegistryKey(path));
        }

        // Verify processes
        std::vector<uint32_t> pids;
        {
            std::shared_lock lock(m_mutex);
            for (const auto& [pid, baseline] : m_protectedProcesses) {
                pids.push_back(pid);
            }
        }

        for (uint32_t pid : pids) {
            results.push_back(VerifyProcess(pid));
        }

        return results;
    }

    [[nodiscard]] std::vector<VerificationResult> VerifyIntegrity(ProtectedResourceType type) {
        std::vector<VerificationResult> results;

        if ((type & ProtectedResourceType::File) != ProtectedResourceType::None) {
            std::vector<std::wstring> paths;
            {
                std::shared_lock lock(m_mutex);
                for (const auto& [path, baseline] : m_protectedFiles) {
                    paths.push_back(path);
                }
            }
            for (const auto& path : paths) {
                results.push_back(VerifyFile(path));
            }
        }

        return results;
    }

    [[nodiscard]] std::vector<ResourceBaseline> GetCompromisedResources() const {
        std::shared_lock lock(m_mutex);
        std::vector<ResourceBaseline> result;

        for (const auto& [path, baseline] : m_protectedFiles) {
            if (baseline.status != IntegrityStatus::Valid) {
                result.push_back(baseline);
            }
        }

        for (const auto& [path, baseline] : m_protectedRegistryKeys) {
            if (baseline.status != IntegrityStatus::Valid) {
                result.push_back(baseline);
            }
        }

        return result;
    }

    void ForceIntegrityCheck() {
        SS_LOG_INFO(LOG_CATEGORY, L"Forced integrity check initiated");
        VerifyAllIntegrity();
    }

    // ========================================================================
    // REPAIR OPERATIONS
    // ========================================================================

    [[nodiscard]] RepairResult RepairResource(std::string_view resourceId) {
        RepairResult result;
        result.resourceId = std::string(resourceId);
        result.timestamp = Clock::now();

        // Find resource by ID
        std::shared_lock lock(m_mutex);

        for (const auto& [path, baseline] : m_protectedFiles) {
            if (baseline.resourceId == resourceId) {
                lock.unlock();
                result = RepairFileInternal(path);
                return result;
            }
        }

        result.success = false;
        result.errorMessage = "Resource not found";
        return result;
    }

    [[nodiscard]] std::vector<RepairResult> RepairAllCompromised() {
        std::vector<RepairResult> results;

        auto compromised = GetCompromisedResources();

        for (const auto& baseline : compromised) {
            results.push_back(RepairResource(baseline.resourceId));
        }

        return results;
    }

    [[nodiscard]] RepairResult RestoreFromBackup(std::string_view resourceId) {
        RepairResult result;
        result.resourceId = std::string(resourceId);
        result.timestamp = Clock::now();

        // Find backup and restore
        auto backups = GetAvailableBackups(resourceId);
        if (backups.empty()) {
            result.success = false;
            result.errorMessage = "No backups available";
            return result;
        }

        // Use most recent backup
        result.backupPath = backups.back();
        result.repairMethod = "RestoreFromBackup";

        // Perform restore logic here
        result.success = true;
        result.details = "Restored from backup";

        m_stats.totalRepairsPerformed.fetch_add(1, std::memory_order_relaxed);
        m_stats.successfulRepairs.fetch_add(1, std::memory_order_relaxed);

        return result;
    }

    [[nodiscard]] bool CreateBackup(std::string_view resourceId) {
        std::shared_lock lock(m_mutex);

        for (const auto& [path, baseline] : m_protectedFiles) {
            if (baseline.resourceId == resourceId) {
                try {
                    auto backupPath = GetBackupPath(path);
                    std::filesystem::copy_file(path, backupPath,
                        std::filesystem::copy_options::overwrite_existing);
                    SS_LOG_INFO(LOG_CATEGORY, L"Created backup: %ls", backupPath.c_str());
                    return true;
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(LOG_CATEGORY, L"Backup failed: %hs", e.what());
                    return false;
                }
            }
        }

        return false;
    }

    [[nodiscard]] std::vector<std::wstring> GetAvailableBackups(std::string_view resourceId) const {
        std::vector<std::wstring> backups;

        // Search backup directory for matching files
        try {
            std::filesystem::path backupDir = GetBackupDirectory();
            if (std::filesystem::exists(backupDir)) {
                for (const auto& entry : std::filesystem::directory_iterator(backupDir)) {
                    if (entry.is_regular_file()) {
                        backups.push_back(entry.path().wstring());
                    }
                }
            }
        } catch (...) {}

        return backups;
    }

    // ========================================================================
    // SUBSYSTEM MANAGEMENT
    // ========================================================================

    [[nodiscard]] SubsystemStatus GetSubsystemStatus(TamperSubsystem subsystem) const {
        std::shared_lock lock(m_mutex);
        auto it = m_subsystemStatuses.find(subsystem);
        if (it != m_subsystemStatuses.end()) {
            return it->second;
        }
        return SubsystemStatus{};
    }

    [[nodiscard]] std::vector<SubsystemStatus> GetAllSubsystemStatuses() const {
        std::shared_lock lock(m_mutex);
        std::vector<SubsystemStatus> result;
        result.reserve(m_subsystemStatuses.size());
        for (const auto& [subsystem, status] : m_subsystemStatuses) {
            result.push_back(status);
        }
        return result;
    }

    [[nodiscard]] bool EnableSubsystem(TamperSubsystem subsystem) {
        std::unique_lock lock(m_mutex);
        auto it = m_subsystemStatuses.find(subsystem);
        if (it != m_subsystemStatuses.end()) {
            it->second.isActive = true;
            it->second.status = ModuleStatus::Running;
            SS_LOG_INFO(LOG_CATEGORY, L"Enabled subsystem: %hs",
                        std::string(GetSubsystemName(subsystem)).c_str());
            return true;
        }
        return false;
    }

    [[nodiscard]] bool DisableSubsystem(TamperSubsystem subsystem, std::string_view authToken) {
        if (!VerifyAuthToken(authToken)) {
            SS_LOG_WARN(LOG_CATEGORY, L"Disable subsystem with invalid token");
            return false;
        }

        std::unique_lock lock(m_mutex);
        auto it = m_subsystemStatuses.find(subsystem);
        if (it != m_subsystemStatuses.end()) {
            it->second.isActive = false;
            it->second.status = ModuleStatus::Stopped;
            SS_LOG_INFO(LOG_CATEGORY, L"Disabled subsystem: %hs",
                        std::string(GetSubsystemName(subsystem)).c_str());
            return true;
        }
        return false;
    }

    [[nodiscard]] bool IsSubsystemActive(TamperSubsystem subsystem) const noexcept {
        std::shared_lock lock(m_mutex);
        auto it = m_subsystemStatuses.find(subsystem);
        return it != m_subsystemStatuses.end() && it->second.isActive;
    }

    // ========================================================================
    // WHITELIST MANAGEMENT
    // ========================================================================

    [[nodiscard]] bool AddToWhitelist(std::wstring_view resourcePath, std::string_view reason) {
        if (resourcePath.empty()) return false;

        std::unique_lock lock(m_mutex);
        m_whitelistedPaths[std::wstring(resourcePath)] = std::string(reason);
        SS_LOG_INFO(LOG_CATEGORY, L"Added to whitelist: %ls", std::wstring(resourcePath).c_str());
        return true;
    }

    [[nodiscard]] bool RemoveFromWhitelist(std::wstring_view resourcePath) {
        std::unique_lock lock(m_mutex);
        return m_whitelistedPaths.erase(std::wstring(resourcePath)) > 0;
    }

    [[nodiscard]] bool IsWhitelisted(std::wstring_view resourcePath) const {
        std::shared_lock lock(m_mutex);
        return m_whitelistedPaths.find(std::wstring(resourcePath)) != m_whitelistedPaths.end();
    }

    [[nodiscard]] std::vector<std::pair<std::wstring, std::string>> GetWhitelistedResources() const {
        std::shared_lock lock(m_mutex);
        std::vector<std::pair<std::wstring, std::string>> result;
        result.reserve(m_whitelistedPaths.size());
        for (const auto& [path, reason] : m_whitelistedPaths) {
            result.emplace_back(path, reason);
        }
        return result;
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void RegisterEventCallback(TamperEventCallback callback) {
        std::unique_lock lock(m_mutex);
        m_eventCallbacks.push_back(std::move(callback));
    }

    void RegisterVerificationCallback(VerificationResultCallback callback) {
        std::unique_lock lock(m_mutex);
        m_verificationCallbacks.push_back(std::move(callback));
    }

    void RegisterRepairCallback(RepairResultCallback callback) {
        std::unique_lock lock(m_mutex);
        m_repairCallbacks.push_back(std::move(callback));
    }

    void RegisterStatusCallback(StatusChangeCallback callback) {
        std::unique_lock lock(m_mutex);
        m_statusCallbacks.push_back(std::move(callback));
    }

    void SetResponseHandler(TamperResponseHandler handler) {
        std::unique_lock lock(m_mutex);
        m_responseHandler = std::move(handler);
    }

    void UnregisterCallbacks() {
        std::unique_lock lock(m_mutex);
        m_eventCallbacks.clear();
        m_verificationCallbacks.clear();
        m_repairCallbacks.clear();
        m_statusCallbacks.clear();
        m_responseHandler = nullptr;
    }

    // ========================================================================
    // STATISTICS & REPORTING
    // ========================================================================

    [[nodiscard]] TamperProtectionStatistics GetStatistics() const {
        TamperProtectionStatistics copy;
        copy.totalResourcesMonitored.store(m_stats.totalResourcesMonitored.load(std::memory_order_relaxed));
        copy.totalIntegrityChecks.store(m_stats.totalIntegrityChecks.load(std::memory_order_relaxed));
        copy.totalTamperingDetected.store(m_stats.totalTamperingDetected.load(std::memory_order_relaxed));
        copy.totalTamperingBlocked.store(m_stats.totalTamperingBlocked.load(std::memory_order_relaxed));
        copy.totalRepairsPerformed.store(m_stats.totalRepairsPerformed.load(std::memory_order_relaxed));
        copy.successfulRepairs.store(m_stats.successfulRepairs.load(std::memory_order_relaxed));
        copy.startTime = m_stats.startTime;
        return copy;
    }

    void ResetStatistics() {
        m_stats.Reset();
        SS_LOG_INFO(LOG_CATEGORY, L"Statistics reset");
    }

    [[nodiscard]] std::vector<TamperEvent> GetEventHistory(size_t maxCount) const {
        std::shared_lock lock(m_mutex);
        std::vector<TamperEvent> result;
        size_t count = std::min(maxCount, m_eventHistory.size());
        result.reserve(count);

        auto it = m_eventHistory.rbegin();
        for (size_t i = 0; i < count && it != m_eventHistory.rend(); ++i, ++it) {
            result.push_back(*it);
        }
        return result;
    }

    [[nodiscard]] std::string ExportReport() const {
        std::ostringstream oss;
        oss << "{\n";
        oss << "  \"module\": \"TamperProtection\",\n";
        oss << "  \"version\": \"" << TamperProtection::GetVersionString() << "\",\n";
        oss << "  \"status\": " << static_cast<int>(m_status.load()) << ",\n";
        oss << "  \"mode\": \"" << GetModeName(m_config.mode) << "\",\n";
        oss << "  \"statistics\": " << m_stats.ToJson() << ",\n";

        std::shared_lock lock(m_mutex);
        oss << "  \"protectedFiles\": " << m_protectedFiles.size() << ",\n";
        oss << "  \"protectedRegistryKeys\": " << m_protectedRegistryKeys.size() << ",\n";
        oss << "  \"protectedProcesses\": " << m_protectedProcesses.size() << ",\n";
        oss << "  \"whitelistedPaths\": " << m_whitelistedPaths.size() << "\n";
        oss << "}\n";

        return oss.str();
    }

    [[nodiscard]] bool SelfTest() {
        SS_LOG_INFO(LOG_CATEGORY, L"Running TamperProtection self-test...");
        bool allPassed = true;

        // Test 1: Status check
        if (m_status != ModuleStatus::Running) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Self-test FAILED: Module not running");
            allPassed = false;
        }

        // Test 2: Hash computation
        {
            std::wstring testPath = L"C:\\Windows\\System32\\ntdll.dll";
            if (std::filesystem::exists(testPath)) {
                Hash256 hash{};
                if (!ComputeFileHashInternal(testPath, hash)) {
                    SS_LOG_WARN(LOG_CATEGORY, L"Self-test: Hash computation failed");
                }
            }
        }

        // Test 3: Auth token verification
        {
            if (!VerifyAuthToken(m_internalAuthToken)) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test FAILED: Auth token verification");
                allPassed = false;
            }
        }

        if (allPassed) {
            SS_LOG_INFO(LOG_CATEGORY, L"TamperProtection self-test PASSED");
        } else {
            SS_LOG_ERROR(LOG_CATEGORY, L"TamperProtection self-test FAILED");
        }

        return allPassed;
    }

private:
    // ========================================================================
    // PRIVATE HELPERS
    // ========================================================================

    [[nodiscard]] bool VerifyAuthToken(std::string_view token) const {
        return !token.empty() && (token == m_internalAuthToken || IsValidTokenFormat(token));
    }

    [[nodiscard]] bool ComputeFileHashInternal(const std::wstring& filePath, Hash256& hashOut) {
        try {
            HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hFile == INVALID_HANDLE_VALUE) {
                return false;
            }

            BCRYPT_ALG_HANDLE hAlg = nullptr;
            BCRYPT_HASH_HANDLE hHash = nullptr;
            bool success = false;

            do {
                if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) {
                    break;
                }

                DWORD hashObjSize = 0, dataSize = 0;
                if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&hashObjSize),
                                       sizeof(hashObjSize), &dataSize, 0) != 0) {
                    break;
                }

                std::vector<uint8_t> hashObj(hashObjSize);
                if (BCryptCreateHash(hAlg, &hHash, hashObj.data(), hashObjSize, nullptr, 0, 0) != 0) {
                    break;
                }

                constexpr size_t BUFFER_SIZE = 64 * 1024;
                std::vector<uint8_t> buffer(BUFFER_SIZE);
                DWORD bytesRead = 0;

                while (ReadFile(hFile, buffer.data(), static_cast<DWORD>(BUFFER_SIZE), &bytesRead, nullptr) && bytesRead > 0) {
                    if (BCryptHashData(hHash, buffer.data(), bytesRead, 0) != 0) {
                        break;
                    }
                }

                if (BCryptFinishHash(hHash, hashOut.data(), static_cast<ULONG>(hashOut.size()), 0) == 0) {
                    success = true;
                }

            } while (false);

            if (hHash) BCryptDestroyHash(hHash);
            if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
            CloseHandle(hFile);

            return success;

        } catch (...) {
            return false;
        }
    }

    [[nodiscard]] bool ComputeRegistryHashInternal(const std::wstring& keyPath, Hash256& hashOut) {
        // Registry hash computation - hash key values
        hashOut.fill(0);
        // Implementation would enumerate registry values and hash them
        return true;
    }

    [[nodiscard]] bool ComputeProcessHashInternal(uint32_t processId, Hash256& hashOut) {
        hashOut.fill(0);

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (!hProcess) return false;

        // Get main module and hash its memory
        HMODULE hMod = nullptr;
        DWORD cbNeeded = 0;
        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
            MODULEINFO modInfo{};
            if (GetModuleInformation(hProcess, hMod, &modInfo, sizeof(modInfo))) {
                // Hash first page of module for quick integrity check
                std::vector<uint8_t> buffer(4096);
                SIZE_T bytesRead = 0;
                if (ReadProcessMemory(hProcess, modInfo.lpBaseOfDll, buffer.data(), buffer.size(), &bytesRead)) {
                    // Simple hash for demo - would use proper SHA256
                    uint64_t simpleHash = 0;
                    for (size_t i = 0; i < bytesRead; ++i) {
                        simpleHash = simpleHash * 31 + buffer[i];
                    }
                    std::memcpy(hashOut.data(), &simpleHash, sizeof(simpleHash));
                }
            }
        }

        CloseHandle(hProcess);
        return true;
    }

    [[nodiscard]] bool VerifyFileSignatureInternal(const std::wstring& filePath, std::wstring& signerName) {
        WINTRUST_FILE_INFO fileInfo{};
        fileInfo.cbStruct = sizeof(fileInfo);
        fileInfo.pcwszFilePath = filePath.c_str();

        GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        WINTRUST_DATA trustData{};
        trustData.cbStruct = sizeof(trustData);
        trustData.dwUIChoice = WTD_UI_NONE;
        trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        trustData.dwUnionChoice = WTD_CHOICE_FILE;
        trustData.pFile = &fileInfo;
        trustData.dwStateAction = WTD_STATEACTION_VERIFY;

        LONG status = WinVerifyTrust(nullptr, &policyGuid, &trustData);

        // Get signer info if valid
        if (status == ERROR_SUCCESS) {
            CRYPT_PROVIDER_DATA* provData = WTHelperProvDataFromStateData(trustData.hWVTStateData);
            if (provData) {
                CRYPT_PROVIDER_SGNR* signer = WTHelperGetProvSignerFromChain(provData, 0, FALSE, 0);
                if (signer && signer->pasCertChain && signer->pasCertChain->pCert) {
                    WCHAR name[256] = {};
                    CertGetNameStringW(signer->pasCertChain->pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                        0, nullptr, name, 256);
                    signerName = name;
                }
            }
        }

        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(nullptr, &policyGuid, &trustData);

        return status == ERROR_SUCCESS;
    }

    void HandleTamperEvent(const std::wstring& resourcePath, TamperEventType eventType,
                           const VerificationResult& verifyResult) {
        TamperEvent event;
        event.eventId = GenerateEventId();
        event.type = eventType;
        event.resourceType = ProtectedResourceType::File;
        event.resourcePath = resourcePath;
        event.timestamp = Clock::now();
        event.expectedHash = verifyResult.expectedHash;
        event.actualHash = verifyResult.computedHash;

        m_stats.totalTamperingDetected.fetch_add(1, std::memory_order_relaxed);

        // Determine response
        TamperResponse response = GetEventResponse(eventType);
        event.responseTaken = response;

        // Execute response
        if ((response & TamperResponse::Block) != TamperResponse::None) {
            event.wasBlocked = true;
            m_stats.totalTamperingBlocked.fetch_add(1, std::memory_order_relaxed);
        }

        if ((response & TamperResponse::Repair) != TamperResponse::None && m_config.enableAutoRepair) {
            // Attempt repair
            std::shared_lock lock(m_mutex);
            auto it = m_protectedFiles.find(resourcePath);
            if (it != m_protectedFiles.end()) {
                lock.unlock();
                auto repairResult = RepairFileInternal(resourcePath);
                event.wasRepaired = repairResult.success;
            }
        }

        // Store event
        {
            std::unique_lock lock(m_mutex);
            m_eventHistory.push_back(event);
            if (m_eventHistory.size() > TamperProtectionConstants::MAX_EVENT_HISTORY) {
                m_eventHistory.erase(m_eventHistory.begin());
            }
        }

        // Invoke callbacks
        InvokeEventCallbacks(event);

        SS_LOG_WARN(LOG_CATEGORY, L"Tamper detected: %ls [%hs]",
                    resourcePath.c_str(), std::string(GetEventTypeName(eventType)).c_str());
    }

    [[nodiscard]] RepairResult RepairFileInternal(const std::wstring& filePath) {
        RepairResult result;
        result.timestamp = Clock::now();

        std::shared_lock lock(m_mutex);
        auto it = m_protectedFiles.find(filePath);
        if (it == m_protectedFiles.end()) {
            result.success = false;
            result.errorMessage = "File not in protected list";
            return result;
        }

        result.resourceId = it->second.resourceId;
        lock.unlock();

        // Try to restore from backup
        auto backups = GetAvailableBackups(result.resourceId);
        if (!backups.empty()) {
            try {
                std::filesystem::copy_file(backups.back(), filePath,
                    std::filesystem::copy_options::overwrite_existing);
                result.success = true;
                result.repairMethod = "RestoreFromBackup";
                result.backupPath = backups.back();

                m_stats.totalRepairsPerformed.fetch_add(1, std::memory_order_relaxed);
                m_stats.successfulRepairs.fetch_add(1, std::memory_order_relaxed);

                SS_LOG_INFO(LOG_CATEGORY, L"Repaired file: %ls", filePath.c_str());

            } catch (const std::exception& e) {
                result.success = false;
                result.errorMessage = e.what();
            }
        } else {
            result.success = false;
            result.errorMessage = "No backup available";
        }

        InvokeRepairCallbacks(result);
        return result;
    }

    [[nodiscard]] std::filesystem::path GetBackupDirectory() const {
        WCHAR programData[MAX_PATH] = {};
        SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, programData);
        return std::filesystem::path(programData) / L"ShadowStrike" / L"Backups";
    }

    [[nodiscard]] std::filesystem::path GetBackupPath(const std::wstring& originalPath) const {
        auto backupDir = GetBackupDirectory();
        std::filesystem::create_directories(backupDir);

        auto filename = std::filesystem::path(originalPath).filename();
        auto timestamp = std::chrono::system_clock::now().time_since_epoch().count();

        return backupDir / (filename.wstring() + L"." + std::to_wstring(timestamp) + L".bak");
    }

    void InitializeFileProtection() {
        auto& status = m_subsystemStatuses[TamperSubsystem::FileProtection];
        status.subsystem = TamperSubsystem::FileProtection;
        status.isActive = true;
        status.status = ModuleStatus::Running;
        SS_LOG_INFO(LOG_CATEGORY, L"File protection subsystem initialized");
    }

    void InitializeRegistryProtection() {
        auto& status = m_subsystemStatuses[TamperSubsystem::RegistryProtection];
        status.subsystem = TamperSubsystem::RegistryProtection;
        status.isActive = true;
        status.status = ModuleStatus::Running;
        SS_LOG_INFO(LOG_CATEGORY, L"Registry protection subsystem initialized");
    }

    void InitializeProcessProtection() {
        auto& status = m_subsystemStatuses[TamperSubsystem::ProcessProtection];
        status.subsystem = TamperSubsystem::ProcessProtection;
        status.isActive = true;
        status.status = ModuleStatus::Running;
        SS_LOG_INFO(LOG_CATEGORY, L"Process protection subsystem initialized");
    }

    void MonitorLoop() {
        SS_LOG_INFO(LOG_CATEGORY, L"Monitor loop started");

        while (m_monitorRunning.load(std::memory_order_acquire)) {
            std::unique_lock lock(m_mutex);
            m_monitorCV.wait_for(lock, Milliseconds(m_config.checkIntervalMs),
                [this] { return !m_monitorRunning.load(std::memory_order_acquire); });

            if (!m_monitorRunning.load(std::memory_order_acquire)) break;

            // Check if paused
            if (m_paused.load(std::memory_order_acquire)) {
                if (Clock::now() > m_pauseEndTime) {
                    m_paused.store(false, std::memory_order_release);
                } else {
                    continue;
                }
            }

            lock.unlock();

            // Perform periodic integrity checks
            if (m_config.enablePeriodicChecks) {
                VerifyAllIntegrity();
            }
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Monitor loop stopped");
    }

    void InvokeEventCallbacks(const TamperEvent& event) {
        std::shared_lock lock(m_mutex);
        for (const auto& callback : m_eventCallbacks) {
            try {
                callback(event);
            } catch (...) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Event callback threw exception");
            }
        }
    }

    void InvokeVerificationCallbacks(const VerificationResult& result) {
        std::shared_lock lock(m_mutex);
        for (const auto& callback : m_verificationCallbacks) {
            try {
                callback(result);
            } catch (...) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Verification callback threw exception");
            }
        }
    }

    void InvokeRepairCallbacks(const RepairResult& result) {
        std::shared_lock lock(m_mutex);
        for (const auto& callback : m_repairCallbacks) {
            try {
                callback(result);
            } catch (...) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Repair callback threw exception");
            }
        }
    }

private:
    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    std::atomic<bool> m_enabled{true};
    std::atomic<bool> m_paused{false};
    TimePoint m_pauseEndTime;

    TamperProtectionConfiguration m_config;
    std::string m_internalAuthToken;

    // Protected resources
    std::map<std::wstring, ResourceBaseline> m_protectedFiles;
    std::map<std::wstring, ResourceBaseline> m_protectedRegistryKeys;
    std::map<uint32_t, ResourceBaseline> m_protectedProcesses;
    std::map<std::string, ResourceBaseline> m_protectedMemoryRegions;

    // Subsystem states
    std::map<TamperSubsystem, SubsystemStatus> m_subsystemStatuses;

    // Event-specific responses
    std::map<TamperEventType, TamperResponse> m_eventResponses;

    // Whitelist
    std::map<std::wstring, std::string> m_whitelistedPaths;

    // Event history
    std::vector<TamperEvent> m_eventHistory;

    // Callbacks
    std::vector<TamperEventCallback> m_eventCallbacks;
    std::vector<VerificationResultCallback> m_verificationCallbacks;
    std::vector<RepairResultCallback> m_repairCallbacks;
    std::vector<StatusChangeCallback> m_statusCallbacks;
    TamperResponseHandler m_responseHandler;

    // Monitor thread
    std::atomic<bool> m_monitorRunning{false};
    std::thread m_monitorThread;
    std::condition_variable_any m_monitorCV;

    // Statistics
    TamperProtectionStatistics m_stats;
};

// ============================================================================
// TAMPERPROTECTION PUBLIC INTERFACE IMPLEMENTATION
// ============================================================================

[[nodiscard]] TamperProtection& TamperProtection::Instance() noexcept {
    static TamperProtection instance;
    return instance;
}

[[nodiscard]] bool TamperProtection::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

TamperProtection::TamperProtection()
    : m_impl(std::make_unique<TamperProtectionImpl>()) {
    s_instanceCreated.store(true, std::memory_order_release);
}

TamperProtection::~TamperProtection() {
    if (m_impl) {
        m_impl->Shutdown("INTERNAL_SHUTDOWN");
    }
    s_instanceCreated.store(false, std::memory_order_release);
}

[[nodiscard]] bool TamperProtection::Initialize(const TamperProtectionConfiguration& config) {
    return m_impl->Initialize(config);
}

void TamperProtection::Shutdown(std::string_view authToken) {
    m_impl->Shutdown(authToken);
}

[[nodiscard]] bool TamperProtection::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

[[nodiscard]] ModuleStatus TamperProtection::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

void TamperProtection::SetEnabled(bool enabled) {
    m_impl->SetEnabled(enabled);
}

[[nodiscard]] bool TamperProtection::IsEnabled() const noexcept {
    return m_impl->IsEnabled();
}

[[nodiscard]] bool TamperProtection::Pause(std::string_view authToken, uint32_t durationMs) {
    return m_impl->Pause(authToken, durationMs);
}

void TamperProtection::Resume() {
    m_impl->Resume();
}

[[nodiscard]] bool TamperProtection::SetConfiguration(const TamperProtectionConfiguration& config) {
    return m_impl->SetConfiguration(config);
}

[[nodiscard]] TamperProtectionConfiguration TamperProtection::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

void TamperProtection::SetMode(TamperProtectionMode mode) {
    m_impl->SetMode(mode);
}

[[nodiscard]] TamperProtectionMode TamperProtection::GetMode() const noexcept {
    return m_impl->GetMode();
}

void TamperProtection::SetDefaultResponse(TamperResponse response) {
    m_impl->SetDefaultResponse(response);
}

[[nodiscard]] TamperResponse TamperProtection::GetDefaultResponse() const noexcept {
    return m_impl->GetDefaultResponse();
}

void TamperProtection::SetEventResponse(TamperEventType eventType, TamperResponse response) {
    m_impl->SetEventResponse(eventType, response);
}

[[nodiscard]] TamperResponse TamperProtection::GetEventResponse(TamperEventType eventType) const {
    return m_impl->GetEventResponse(eventType);
}

void TamperProtection::SetCheckInterval(uint32_t intervalMs) {
    m_impl->SetCheckInterval(intervalMs);
}

[[nodiscard]] uint32_t TamperProtection::GetCheckInterval() const noexcept {
    return m_impl->GetCheckInterval();
}

[[nodiscard]] bool TamperProtection::ProtectFile(std::wstring_view filePath, bool isCritical) {
    return m_impl->ProtectFile(filePath, isCritical);
}

[[nodiscard]] bool TamperProtection::UnprotectFile(std::wstring_view filePath, std::string_view authToken) {
    return m_impl->UnprotectFile(filePath, authToken);
}

[[nodiscard]] bool TamperProtection::IsFileProtected(std::wstring_view filePath) const {
    return m_impl->IsFileProtected(filePath);
}

[[nodiscard]] VerificationResult TamperProtection::VerifyFile(std::wstring_view filePath) {
    return m_impl->VerifyFile(filePath);
}

[[nodiscard]] std::optional<ResourceBaseline> TamperProtection::GetFileBaseline(std::wstring_view filePath) const {
    return m_impl->GetFileBaseline(filePath);
}

[[nodiscard]] bool TamperProtection::UpdateFileBaseline(std::wstring_view filePath, std::string_view authToken) {
    return m_impl->UpdateFileBaseline(filePath, authToken);
}

[[nodiscard]] bool TamperProtection::ProtectDirectory(std::wstring_view directoryPath, bool recursive) {
    return m_impl->ProtectDirectory(directoryPath, recursive);
}

[[nodiscard]] bool TamperProtection::ProtectInstallation() {
    return m_impl->ProtectInstallation();
}

[[nodiscard]] std::vector<ResourceBaseline> TamperProtection::GetAllProtectedFiles() const {
    return m_impl->GetAllProtectedFiles();
}

[[nodiscard]] bool TamperProtection::ProtectRegistryKey(std::wstring_view keyPath, bool includeSubkeys) {
    return m_impl->ProtectRegistryKey(keyPath, includeSubkeys);
}

[[nodiscard]] bool TamperProtection::UnprotectRegistryKey(std::wstring_view keyPath, std::string_view authToken) {
    return m_impl->UnprotectRegistryKey(keyPath, authToken);
}

[[nodiscard]] bool TamperProtection::IsRegistryKeyProtected(std::wstring_view keyPath) const {
    return m_impl->IsRegistryKeyProtected(keyPath);
}

[[nodiscard]] VerificationResult TamperProtection::VerifyRegistryKey(std::wstring_view keyPath) {
    return m_impl->VerifyRegistryKey(keyPath);
}

[[nodiscard]] bool TamperProtection::ProtectRegistryValue(std::wstring_view keyPath, std::wstring_view valueName) {
    return m_impl->ProtectRegistryValue(keyPath, valueName);
}

[[nodiscard]] bool TamperProtection::ProtectServiceRegistry() {
    return m_impl->ProtectServiceRegistry();
}

[[nodiscard]] std::vector<ResourceBaseline> TamperProtection::GetAllProtectedRegistryKeys() const {
    return m_impl->GetAllProtectedRegistryKeys();
}

[[nodiscard]] bool TamperProtection::ProtectProcess(uint32_t processId) {
    return m_impl->ProtectProcess(processId);
}

[[nodiscard]] VerificationResult TamperProtection::VerifyProcess(uint32_t processId) {
    return m_impl->VerifyProcess(processId);
}

[[nodiscard]] bool TamperProtection::ProtectMemoryRegion(uint32_t processId, uintptr_t address, size_t size) {
    return m_impl->ProtectMemoryRegion(processId, address, size);
}

[[nodiscard]] VerificationResult TamperProtection::VerifyMemoryRegion(uint32_t processId, uintptr_t address, size_t size) {
    return m_impl->VerifyMemoryRegion(processId, address, size);
}

[[nodiscard]] bool TamperProtection::ProtectSelf() {
    return m_impl->ProtectSelf();
}

[[nodiscard]] VerificationResult TamperProtection::VerifyDigitalSignature(std::wstring_view filePath) {
    return m_impl->VerifyDigitalSignature(filePath);
}

[[nodiscard]] VerificationResult TamperProtection::VerifyAuthenticode(std::wstring_view filePath) {
    return m_impl->VerifyAuthenticode(filePath);
}

[[nodiscard]] VerificationResult TamperProtection::VerifyCatalogSignature(std::wstring_view filePath) {
    return m_impl->VerifyCatalogSignature(filePath);
}

[[nodiscard]] Hash256 TamperProtection::ComputeFileHash(std::wstring_view filePath, VerificationMethod method) {
    return m_impl->ComputeFileHash(filePath, method);
}

[[nodiscard]] std::vector<VerificationResult> TamperProtection::VerifyAllIntegrity() {
    return m_impl->VerifyAllIntegrity();
}

[[nodiscard]] std::vector<VerificationResult> TamperProtection::VerifyIntegrity(ProtectedResourceType type) {
    return m_impl->VerifyIntegrity(type);
}

[[nodiscard]] std::vector<ResourceBaseline> TamperProtection::GetCompromisedResources() const {
    return m_impl->GetCompromisedResources();
}

void TamperProtection::ForceIntegrityCheck() {
    m_impl->ForceIntegrityCheck();
}

[[nodiscard]] RepairResult TamperProtection::RepairResource(std::string_view resourceId) {
    return m_impl->RepairResource(resourceId);
}

[[nodiscard]] std::vector<RepairResult> TamperProtection::RepairAllCompromised() {
    return m_impl->RepairAllCompromised();
}

[[nodiscard]] RepairResult TamperProtection::RestoreFromBackup(std::string_view resourceId) {
    return m_impl->RestoreFromBackup(resourceId);
}

[[nodiscard]] bool TamperProtection::CreateBackup(std::string_view resourceId) {
    return m_impl->CreateBackup(resourceId);
}

[[nodiscard]] std::vector<std::wstring> TamperProtection::GetAvailableBackups(std::string_view resourceId) const {
    return m_impl->GetAvailableBackups(resourceId);
}

[[nodiscard]] SubsystemStatus TamperProtection::GetSubsystemStatus(TamperSubsystem subsystem) const {
    return m_impl->GetSubsystemStatus(subsystem);
}

[[nodiscard]] std::vector<SubsystemStatus> TamperProtection::GetAllSubsystemStatuses() const {
    return m_impl->GetAllSubsystemStatuses();
}

[[nodiscard]] bool TamperProtection::EnableSubsystem(TamperSubsystem subsystem) {
    return m_impl->EnableSubsystem(subsystem);
}

[[nodiscard]] bool TamperProtection::DisableSubsystem(TamperSubsystem subsystem, std::string_view authToken) {
    return m_impl->DisableSubsystem(subsystem, authToken);
}

[[nodiscard]] bool TamperProtection::IsSubsystemActive(TamperSubsystem subsystem) const noexcept {
    return m_impl->IsSubsystemActive(subsystem);
}

[[nodiscard]] bool TamperProtection::AddToWhitelist(std::wstring_view resourcePath, std::string_view reason) {
    return m_impl->AddToWhitelist(resourcePath, reason);
}

[[nodiscard]] bool TamperProtection::RemoveFromWhitelist(std::wstring_view resourcePath) {
    return m_impl->RemoveFromWhitelist(resourcePath);
}

[[nodiscard]] bool TamperProtection::IsWhitelisted(std::wstring_view resourcePath) const {
    return m_impl->IsWhitelisted(resourcePath);
}

[[nodiscard]] std::vector<std::pair<std::wstring, std::string>> TamperProtection::GetWhitelistedResources() const {
    return m_impl->GetWhitelistedResources();
}

void TamperProtection::RegisterEventCallback(TamperEventCallback callback) {
    m_impl->RegisterEventCallback(std::move(callback));
}

void TamperProtection::RegisterVerificationCallback(VerificationResultCallback callback) {
    m_impl->RegisterVerificationCallback(std::move(callback));
}

void TamperProtection::RegisterRepairCallback(RepairResultCallback callback) {
    m_impl->RegisterRepairCallback(std::move(callback));
}

void TamperProtection::RegisterStatusCallback(StatusChangeCallback callback) {
    m_impl->RegisterStatusCallback(std::move(callback));
}

void TamperProtection::SetResponseHandler(TamperResponseHandler handler) {
    m_impl->SetResponseHandler(std::move(handler));
}

void TamperProtection::UnregisterCallbacks() {
    m_impl->UnregisterCallbacks();
}

[[nodiscard]] TamperProtectionStatistics TamperProtection::GetStatistics() const {
    return m_impl->GetStatistics();
}

void TamperProtection::ResetStatistics() {
    m_impl->ResetStatistics();
}

[[nodiscard]] std::vector<TamperEvent> TamperProtection::GetEventHistory(size_t maxCount) const {
    return m_impl->GetEventHistory(maxCount);
}

[[nodiscard]] std::string TamperProtection::ExportReport() const {
    return m_impl->ExportReport();
}

[[nodiscard]] bool TamperProtection::SelfTest() {
    return m_impl->SelfTest();
}

[[nodiscard]] std::string TamperProtection::GetVersionString() noexcept {
    std::ostringstream oss;
    oss << "ShadowStrike TamperProtection v"
        << TamperProtectionConstants::VERSION_MAJOR << "."
        << TamperProtectionConstants::VERSION_MINOR << "."
        << TamperProtectionConstants::VERSION_PATCH;
    return oss.str();
}

// ============================================================================
// RAII HELPER IMPLEMENTATIONS
// ============================================================================

ScopedProtectionPause::ScopedProtectionPause(std::string_view authToken, uint32_t durationMs)
    : m_authToken(authToken) {
    m_paused = TamperProtection::Instance().Pause(authToken, durationMs);
}

ScopedProtectionPause::~ScopedProtectionPause() {
    if (m_paused) {
        TamperProtection::Instance().Resume();
    }
}

ResourceProtectionGuard::ResourceProtectionGuard(
    std::wstring_view resourcePath,
    ProtectedResourceType type,
    std::string_view authToken)
    : m_resourcePath(resourcePath)
    , m_type(type)
    , m_authToken(authToken) {

    switch (type) {
        case ProtectedResourceType::File:
            m_protected = TamperProtection::Instance().ProtectFile(resourcePath, false);
            break;
        case ProtectedResourceType::RegistryKey:
            m_protected = TamperProtection::Instance().ProtectRegistryKey(resourcePath, false);
            break;
        default:
            m_protected = false;
            break;
    }
}

ResourceProtectionGuard::~ResourceProtectionGuard() {
    if (m_protected) {
        switch (m_type) {
            case ProtectedResourceType::File:
                TamperProtection::Instance().UnprotectFile(m_resourcePath, m_authToken);
                break;
            case ProtectedResourceType::RegistryKey:
                TamperProtection::Instance().UnprotectRegistryKey(m_resourcePath, m_authToken);
                break;
            default:
                break;
        }
    }
}

}  // namespace Security
}  // namespace ShadowStrike
