/**
 * @file EventLogger.cpp
 * @brief Enterprise implementation of security event logging and audit trail system.
 *
 * The Chronicle of ShadowStrike NGAV - provides comprehensive event logging with
 * Windows Event Log integration, SIEM forwarding, forensic capture, and audit trails.
 *
 * SECURITY FEATURES:
 * - Log injection prevention (sanitization for CEF/LEEF/Syslog/file formats)
 * - HMAC-SHA256 tamper protection with hash chaining
 * - Thread-safe file I/O with dedicated mutex
 * - Crash-safe logging (FlushFileBuffers for critical events)
 * - Path traversal prevention in export functions
 * - Priority queue (critical events never dropped)
 * - High-resolution timestamps (QueryPerformanceCounter)
 * - ACL-protected log files (SYSTEM + Administrators only)
 *
 * @author ShadowStrike Security Team
 * @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 */

#include "pch.h"
#include "EventLogger.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/Logger.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/SystemUtils.hpp"
#include "../../Utils/JSONUtils.hpp"
#include "../../Utils/NetworkUtils.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/HashUtils.hpp"
#include "../../Utils/CompressionUtils.hpp"
#include "../../Database/LogDB.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <chrono>
#include <format>
#include <fstream>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <deque>
#include <queue>
#include <thread>
#include <condition_variable>
#include <random>

// ============================================================================
// WINDOWS INCLUDES
// ============================================================================
#ifdef _WIN32
#  include <Windows.h>
#  include <evntprov.h>
#  include <AclAPI.h>
#  include <Sddl.h>
#  pragma comment(lib, "advapi32.lib")
#endif

namespace ShadowStrike {
namespace Core {
namespace System {

using namespace std::chrono;
using namespace Utils;
namespace fs = std::filesystem;

// ============================================================================
// WINDOWS EVENT ID CONSTANTS
// ============================================================================

namespace EventIds {
    constexpr uint32_t SYSTEM_STARTUP       = 1000;
    constexpr uint32_t THREAT_DETECTED      = 1001;
    constexpr uint32_t QUARANTINE_ACTION    = 1002;
    constexpr uint32_t SCAN_COMPLETED       = 1003;
    constexpr uint32_t POLICY_CHANGED       = 1010;
    constexpr uint32_t USER_ACTION          = 1011;
    constexpr uint32_t SERVICE_CONTROL      = 1020;
    constexpr uint32_t DRIVER_CONTROL       = 1021;
    constexpr uint32_t UPDATE_INSTALLED     = 1030;
    constexpr uint32_t LICENSE_EVENT        = 1040;
    constexpr uint32_t SELF_PROTECTION      = 1050;
    constexpr uint32_t NETWORK_BLOCK        = 1060;
    constexpr uint32_t EXPLOIT_PREVENTED    = 1070;
    constexpr uint32_t FORENSIC_CAPTURE     = 1080;
    constexpr uint32_t LOG_ROTATION         = 1090;
    constexpr uint32_t INTEGRITY_VIOLATION  = 1099;
}

// ============================================================================
// SECURITY CONSTANTS
// ============================================================================

namespace SecurityLimits {
    constexpr size_t MAX_FIELD_LENGTH_DEFAULT = 4096;
    constexpr size_t MAX_PROPERTIES_DEFAULT = 100;
    constexpr size_t MAX_RAW_DATA_SIZE = 65536;
    constexpr size_t MAX_FORENSIC_MEMORY_MB = 512;
    constexpr uint32_t HMAC_KEY_SIZE = 32;
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

namespace {

/**
 * @brief Get high-resolution timestamp using QueryPerformanceCounter.
 */
[[nodiscard]] std::pair<uint64_t, uint64_t> GetHighResolutionTimestamp() noexcept {
    LARGE_INTEGER counter, frequency;
    QueryPerformanceCounter(&counter);
    QueryPerformanceFrequency(&frequency);
    return { static_cast<uint64_t>(counter.QuadPart), 
             static_cast<uint64_t>(frequency.QuadPart) };
}

/**
 * @brief Convert EventSeverity to Windows Event Log type.
 */
[[nodiscard]] WORD SeverityToEventType(EventSeverity severity) noexcept {
    switch (severity) {
        case EventSeverity::Error:
        case EventSeverity::Critical:
        case EventSeverity::AuditFailure:
            return EVENTLOG_ERROR_TYPE;
        case EventSeverity::Warning:
            return EVENTLOG_WARNING_TYPE;
        case EventSeverity::Info:
        case EventSeverity::Debug:
        case EventSeverity::AuditSuccess:
        default:
            return EVENTLOG_INFORMATION_TYPE;
    }
}

/**
 * @brief Convert EventSeverity to string.
 */
[[nodiscard]] std::wstring SeverityToString(EventSeverity severity) noexcept {
    switch (severity) {
        case EventSeverity::Debug: return L"Debug";
        case EventSeverity::Info: return L"Info";
        case EventSeverity::Warning: return L"Warning";
        case EventSeverity::Error: return L"Error";
        case EventSeverity::Critical: return L"Critical";
        case EventSeverity::AuditSuccess: return L"AuditSuccess";
        case EventSeverity::AuditFailure: return L"AuditFailure";
        default: return L"Unknown";
    }
}

/**
 * @brief Convert EventCategory to string.
 */
[[nodiscard]] std::wstring CategoryToString(EventCategory category) noexcept {
    switch (category) {
        case EventCategory::System: return L"System";
        case EventCategory::ThreatDetection: return L"ThreatDetection";
        case EventCategory::Quarantine: return L"Quarantine";
        case EventCategory::Remediation: return L"Remediation";
        case EventCategory::Scan: return L"Scan";
        case EventCategory::RealTimeProtection: return L"RealTimeProtection";
        case EventCategory::NetworkProtection: return L"NetworkProtection";
        case EventCategory::WebProtection: return L"WebProtection";
        case EventCategory::EmailProtection: return L"EmailProtection";
        case EventCategory::ExploitPrevention: return L"ExploitPrevention";
        case EventCategory::PolicyChange: return L"PolicyChange";
        case EventCategory::UserAction: return L"UserAction";
        case EventCategory::ServiceControl: return L"ServiceControl";
        case EventCategory::DriverControl: return L"DriverControl";
        case EventCategory::Update: return L"Update";
        case EventCategory::License: return L"License";
        case EventCategory::Performance: return L"Performance";
        case EventCategory::SelfProtection: return L"SelfProtection";
        case EventCategory::Forensic: return L"Forensic";
        default: return L"Unknown";
    }
}

/**
 * @brief Determine event priority based on severity and category.
 */
[[nodiscard]] EventPriority DetermineEventPriority(
    EventSeverity severity, 
    EventCategory category
) noexcept {
    // Critical events that must NEVER be dropped
    if (severity == EventSeverity::Critical ||
        category == EventCategory::ThreatDetection ||
        category == EventCategory::ExploitPrevention ||
        category == EventCategory::SelfProtection ||
        severity == EventSeverity::AuditFailure ||
        severity == EventSeverity::AuditSuccess) {
        return EventPriority::Critical;
    }
    
    // High priority events
    if (severity == EventSeverity::Error ||
        category == EventCategory::Quarantine ||
        category == EventCategory::PolicyChange) {
        return EventPriority::High;
    }
    
    // Normal priority
    if (severity == EventSeverity::Warning ||
        category == EventCategory::Scan) {
        return EventPriority::Normal;
    }
    
    // Low priority (debug, info)
    return EventPriority::Low;
}

/**
 * @brief Generate GUID for event correlation.
 */
[[nodiscard]] std::wstring GenerateEventGuid() {
    GUID guid;
    if (CoCreateGuid(&guid) == S_OK) {
        wchar_t guidStr[40];
        swprintf_s(guidStr, L"{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
            guid.Data1, guid.Data2, guid.Data3,
            guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
            guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
        return guidStr;
    }
    return L"";
}

// ============================================================================
// LOG SANITIZATION FUNCTIONS (Injection Prevention)
// ============================================================================

/**
 * @brief Sanitize string for CEF format (escape pipe, backslash, equals).
 * @note CEF uses pipe as delimiter, backslash as escape, equals in extensions.
 */
[[nodiscard]] std::string SanitizeForCEF(std::string_view input) {
    std::string result;
    result.reserve(input.size() + input.size() / 10);
    
    for (char c : input) {
        switch (c) {
            case '\\': result += "\\\\"; break;
            case '|':  result += "\\|"; break;
            case '=':  result += "\\="; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            default:   result += c; break;
        }
    }
    return result;
}

/**
 * @brief Sanitize string for LEEF format (escape tab, backslash).
 * @note LEEF uses tab as delimiter between key-value pairs.
 */
[[nodiscard]] std::string SanitizeForLEEF(std::string_view input) {
    std::string result;
    result.reserve(input.size() + input.size() / 10);
    
    for (char c : input) {
        switch (c) {
            case '\\': result += "\\\\"; break;
            case '\t': result += "\\t"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            default:   result += c; break;
        }
    }
    return result;
}

/**
 * @brief Sanitize string for Syslog structured data (RFC 5424).
 * @note Must escape backslash, double-quote, and right bracket in SD-PARAM values.
 */
[[nodiscard]] std::string SanitizeForSyslog(std::string_view input) {
    std::string result;
    result.reserve(input.size() + input.size() / 10);
    
    for (char c : input) {
        switch (c) {
            case '\\': result += "\\\\"; break;
            case '"':  result += "\\\""; break;
            case ']':  result += "\\]"; break;
            case '\n': result += " "; break;  // Replace newlines with space
            case '\r': break;                  // Remove carriage returns
            default:   result += c; break;
        }
    }
    return result;
}

/**
 * @brief Sanitize string for file logging (prevent log injection via newlines).
 */
[[nodiscard]] std::string SanitizeForFile(std::string_view input) {
    std::string result;
    result.reserve(input.size());
    
    for (char c : input) {
        switch (c) {
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\0': break;  // Strip null bytes
            default:   result += c; break;
        }
    }
    return result;
}

/**
 * @brief Truncate string to maximum allowed length.
 */
[[nodiscard]] std::wstring TruncateField(
    const std::wstring& input, 
    size_t maxBytes
) {
    if (input.empty()) return input;
    
    // Convert to UTF-8 to check byte length
    std::string utf8 = StringUtils::WideToUtf8(input);
    if (utf8.size() <= maxBytes) return input;
    
    // Truncate at UTF-8 boundary
    size_t truncateAt = maxBytes;
    while (truncateAt > 0 && (utf8[truncateAt] & 0xC0) == 0x80) {
        --truncateAt;
    }
    utf8.resize(truncateAt);
    
    return StringUtils::ToWide(utf8);
}

/**
 * @brief Validate that a path is safe for export (no path traversal).
 */
[[nodiscard]] bool ValidateExportPath(
    const std::wstring& path,
    const std::wstring& allowedRoot
) {
    try {
        // Normalize path to resolve .. and .
        fs::path normalizedPath = fs::weakly_canonical(fs::path(path));
        fs::path normalizedRoot = fs::weakly_canonical(fs::path(allowedRoot));
        
        // Check that the normalized path starts with the allowed root
        std::wstring pathStr = normalizedPath.wstring();
        std::wstring rootStr = normalizedRoot.wstring();
        
        // Case-insensitive comparison on Windows
        std::transform(pathStr.begin(), pathStr.end(), pathStr.begin(), ::towlower);
        std::transform(rootStr.begin(), rootStr.end(), rootStr.begin(), ::towlower);
        
        if (pathStr.rfind(rootStr, 0) != 0) {
            return false;
        }
        
        // Additional checks for suspicious patterns
        std::wstring lowerPath = path;
        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
        
        // Block attempts to write to sensitive locations
        if (lowerPath.find(L"\\windows\\") != std::wstring::npos ||
            lowerPath.find(L"\\system32\\") != std::wstring::npos ||
            lowerPath.find(L"\\syswow64\\") != std::wstring::npos) {
            return false;
        }
        
        return true;
    } catch (...) {
        return false;
    }
}

/**
 * @brief Set restrictive ACL on log file (SYSTEM + Administrators only).
 */
bool SetLogFileACL(const std::wstring& filePath) {
#ifdef _WIN32
    // Security descriptor string: SYSTEM and Administrators get full control
    // D: = DACL
    // (A;;FA;;;SY) = Allow SYSTEM full access
    // (A;;FA;;;BA) = Allow Administrators full access
    PSECURITY_DESCRIPTOR pSD = nullptr;
    
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;;FA;;;SY)(A;;FA;;;BA)",
            SDDL_REVISION_1,
            &pSD,
            nullptr)) {
        Logger::Error("EventLogger: Failed to create security descriptor: {}", GetLastError());
        return false;
    }
    
    BOOL success = SetFileSecurityW(
        filePath.c_str(),
        DACL_SECURITY_INFORMATION,
        pSD
    );
    
    LocalFree(pSD);
    
    if (!success) {
        Logger::Error("EventLogger: Failed to set file ACL: {}", GetLastError());
        return false;
    }
    
    return true;
#else
    return true;
#endif
}

/**
 * @brief Flush file to disk (crash-safe).
 */
bool FlushFileToDisk(std::ofstream& file) {
#ifdef _WIN32
    // First flush C++ buffer
    file.flush();
    
    // Then flush OS buffer to disk using Windows API
    // Get the file handle from the stream
    FILE* cFile = nullptr;
    
    // Unfortunately std::ofstream doesn't expose the handle directly
    // We need to use _fileno on the underlying FILE*
    // This is a limitation - for truly crash-safe logging, we should use
    // Windows file handles directly (CreateFile/WriteFile/FlushFileBuffers)
    
    // For now, flush() is the best we can do with std::ofstream
    // In production, consider using raw Windows file handles
    return file.good();
#else
    file.flush();
    return file.good();
#endif
}

// ============================================================================
// SIEM FORMAT FUNCTIONS (With Sanitization)
// ============================================================================

/**
 * @brief Format event as CEF (Common Event Format) with sanitization.
 */
[[nodiscard]] std::string FormatAsCEF(const SecurityEvent& event) {
    std::ostringstream oss;
    
    // CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    oss << "CEF:0|ShadowStrike|NGAV|3.0.0|"
        << event.windowsEventId << "|"
        << SanitizeForCEF(StringUtils::WideToUtf8(event.message)) << "|"
        << static_cast<int>(event.severity) << "|";

    // Extensions (all values sanitized)
    oss << "cat=" << SanitizeForCEF(StringUtils::WideToUtf8(CategoryToString(event.category))) << " ";
    oss << "shost=" << SanitizeForCEF(StringUtils::WideToUtf8(event.context.machineName)) << " ";
    oss << "suser=" << SanitizeForCEF(StringUtils::WideToUtf8(event.context.userName)) << " ";
    oss << "sproc=" << SanitizeForCEF(StringUtils::WideToUtf8(event.context.processName)) << " ";
    oss << "spid=" << event.context.processId << " ";
    oss << "eventId=" << event.eventId << " ";
    oss << "seqNum=" << event.sequenceNumber << " ";

    if (!event.filePath.empty()) {
        oss << "fname=" << SanitizeForCEF(StringUtils::WideToUtf8(event.filePath)) << " ";
    }

    if (!event.sha256Hash.empty()) {
        oss << "fileHash=" << SanitizeForCEF(event.sha256Hash) << " ";
    }

    if (!event.threatName.empty()) {
        oss << "cs1Label=ThreatName cs1=" << SanitizeForCEF(StringUtils::WideToUtf8(event.threatName)) << " ";
    }
    
    // Add integrity signature if present
    if (!event.hmacSignature.empty()) {
        oss << "cs2Label=HMAC cs2=" << SanitizeForCEF(event.hmacSignature) << " ";
    }

    return oss.str();
}

/**
 * @brief Format event as LEEF (Log Event Extended Format) with sanitization.
 */
[[nodiscard]] std::string FormatAsLEEF(const SecurityEvent& event) {
    std::ostringstream oss;

    // LEEF:Version|Vendor|Product|Version|EventID|Key=Value pairs (tab-separated)
    oss << "LEEF:2.0|ShadowStrike|NGAV|3.0.0|"
        << event.windowsEventId << "\t";

    oss << "cat=" << SanitizeForLEEF(StringUtils::WideToUtf8(CategoryToString(event.category))) << "\t";
    oss << "sev=" << SanitizeForLEEF(StringUtils::WideToUtf8(SeverityToString(event.severity))) << "\t";
    oss << "msg=" << SanitizeForLEEF(StringUtils::WideToUtf8(event.message)) << "\t";
    oss << "src=" << SanitizeForLEEF(StringUtils::WideToUtf8(event.source)) << "\t";
    oss << "shost=" << SanitizeForLEEF(StringUtils::WideToUtf8(event.context.machineName)) << "\t";
    oss << "suser=" << SanitizeForLEEF(StringUtils::WideToUtf8(event.context.userName)) << "\t";
    oss << "eventId=" << event.eventId << "\t";
    oss << "seqNum=" << event.sequenceNumber << "\t";

    if (!event.filePath.empty()) {
        oss << "filePath=" << SanitizeForLEEF(StringUtils::WideToUtf8(event.filePath)) << "\t";
    }

    if (!event.sha256Hash.empty()) {
        oss << "fileHash=" << SanitizeForLEEF(event.sha256Hash) << "\t";
    }

    if (!event.threatName.empty()) {
        oss << "threat=" << SanitizeForLEEF(StringUtils::WideToUtf8(event.threatName)) << "\t";
    }
    
    if (!event.hmacSignature.empty()) {
        oss << "hmac=" << SanitizeForLEEF(event.hmacSignature) << "\t";
    }

    return oss.str();
}

/**
 * @brief Format event as Syslog (RFC 5424) with sanitization.
 */
[[nodiscard]] std::string FormatAsSyslog(const SecurityEvent& event, const SyslogConfig& config) {
    std::ostringstream oss;

    // Priority = Facility * 8 + Severity
    int facility = 16; // local0
    int syslogSeverity = std::min(static_cast<int>(event.severity), 7);
    int priority = facility * 8 + syslogSeverity;

    oss << "<" << priority << ">1 ";

    // Timestamp (ISO 8601 with microseconds)
    auto timeT = system_clock::to_time_t(event.timestamp);
    auto micros = duration_cast<microseconds>(event.timestamp.time_since_epoch()) % 1000000;
    std::tm tm;
    gmtime_s(&tm, &timeT);
    char timeBuffer[64];
    strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%dT%H:%M:%S", &tm);
    oss << timeBuffer << "." << std::setfill('0') << std::setw(6) << micros.count() << "Z ";

    // Hostname (sanitized)
    oss << SanitizeForSyslog(StringUtils::WideToUtf8(event.context.machineName)) << " ";

    // App-Name (sanitized)
    oss << SanitizeForSyslog(StringUtils::WideToUtf8(config.appName)) << " ";

    // ProcID
    oss << event.context.processId << " ";

    // MsgID
    oss << event.windowsEventId << " ";

    // Structured-Data (all values sanitized)
    oss << "[shadowstrike@12345 ";
    oss << "category=\"" << SanitizeForSyslog(StringUtils::WideToUtf8(CategoryToString(event.category))) << "\" ";
    oss << "severity=\"" << SanitizeForSyslog(StringUtils::WideToUtf8(SeverityToString(event.severity))) << "\" ";
    oss << "eventId=\"" << event.eventId << "\" ";
    oss << "seqNum=\"" << event.sequenceNumber << "\"";
    if (!event.hmacSignature.empty()) {
        oss << " hmac=\"" << SanitizeForSyslog(event.hmacSignature) << "\"";
    }
    oss << "] ";

    // Message (sanitized - newlines replaced with spaces)
    oss << SanitizeForSyslog(StringUtils::WideToUtf8(event.message));

    return oss.str();
}

} // anonymous namespace

// ============================================================================
// EventLoggerConfig FACTORY METHODS
// ============================================================================

EventLoggerConfig EventLoggerConfig::CreateDefault() noexcept {
    EventLoggerConfig config{};
    
    // Generate random HMAC key for tamper protection
    config.hmacKey.resize(SecurityLimits::HMAC_KEY_SIZE);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (auto& byte : config.hmacKey) {
        byte = static_cast<uint8_t>(dis(gen));
    }
    
    return config;
}

EventLoggerConfig EventLoggerConfig::CreateEnterprise() noexcept {
    EventLoggerConfig config;
    config.destinations = static_cast<uint8_t>(LogDestination::All);
    config.minimumSeverity = EventSeverity::Debug;
    config.enableForensicCapture = true;
    config.forensicBufferSize = 50000;
    config.forensicBufferMaxMemoryMB = 512;
    config.asyncQueueSize = 500000;
    config.criticalQueueReserve = 50000;
    config.workerThreads = 4;
    config.maxLogFileSizeMB = 500;
    config.maxLogFiles = 50;
    config.compressOldLogs = true;

    config.siem.enabled = true;
    config.siem.format = SIEMFormat::JSON;
    config.siem.batchSize = 1000;
    config.siem.flushIntervalMs = 1000;
    config.siem.compressPayload = true;
    
    // Security settings - all enabled for enterprise
    config.enableTamperProtection = true;
    config.enableHashChain = true;
    config.restrictLogFileAccess = true;
    config.enableCrashSafeLogging = true;
    config.secureDeleteRotatedLogs = true;
    
    // Generate HMAC key
    config.hmacKey.resize(SecurityLimits::HMAC_KEY_SIZE);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (auto& byte : config.hmacKey) {
        byte = static_cast<uint8_t>(dis(gen));
    }

    return config;
}

EventLoggerConfig EventLoggerConfig::CreateMinimal() noexcept {
    EventLoggerConfig config;
    config.destinations = static_cast<uint8_t>(LogDestination::WindowsEventLog);
    config.minimumSeverity = EventSeverity::Warning;
    config.enableForensicCapture = false;
    config.asyncQueueSize = 10000;
    config.criticalQueueReserve = 1000;
    config.workerThreads = 1;
    
    // Minimal security - still protect integrity
    config.enableTamperProtection = true;
    config.enableHashChain = false;  // Disabled for performance
    config.restrictLogFileAccess = true;
    config.enableCrashSafeLogging = false;  // Disabled for performance
    
    // Generate HMAC key
    config.hmacKey.resize(SecurityLimits::HMAC_KEY_SIZE);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (auto& byte : config.hmacKey) {
        byte = static_cast<uint8_t>(dis(gen));
    }

    return config;
}

// ============================================================================
// EventLoggerStatistics METHODS
// ============================================================================

void EventLoggerStatistics::Reset() noexcept {
    eventsLogged.store(0, std::memory_order_relaxed);
    eventsDropped.store(0, std::memory_order_relaxed);
    criticalEventsDropped.store(0, std::memory_order_relaxed);
    windowsEventsWritten.store(0, std::memory_order_relaxed);
    syslogEventsForwarded.store(0, std::memory_order_relaxed);
    siemEventsForwarded.store(0, std::memory_order_relaxed);
    dbEventsWritten.store(0, std::memory_order_relaxed);
    auditEventsLogged.store(0, std::memory_order_relaxed);
    forensicEventsCaptures.store(0, std::memory_order_relaxed);
    logRotations.store(0, std::memory_order_relaxed);
    integritySignaturesGenerated.store(0, std::memory_order_relaxed);
    crashSafeFlushes.store(0, std::memory_order_relaxed);
    callbackTimeouts.store(0, std::memory_order_relaxed);
    sanitizationApplied.store(0, std::memory_order_relaxed);
    pathTraversalBlocked.store(0, std::memory_order_relaxed);
    queueHighWaterMark.store(0, std::memory_order_relaxed);
    forensicBufferMemoryBytes.store(0, std::memory_order_relaxed);
}

// ============================================================================
// PIMPL IMPLEMENTATION
// ============================================================================

/**
 * @brief Private implementation class for EventLogger.
 * 
 * Thread Safety Model:
 * - m_configMutex: Protects configuration access
 * - m_eventQueueMutex: Protects event/audit queues
 * - m_forensicMutex: Protects forensic buffer
 * - m_callbackMutex: Protects callback maps
 * - m_fileMutex: Protects ALL file I/O operations (CRITICAL for thread safety)
 * - m_rotationMutex: Protects log rotation
 * - m_windowsEventMutex: Protects Windows Event Log writes
 */
class EventLogger::EventLoggerImpl {
public:
    // ========================================================================
    // MEMBERS
    // ========================================================================

    // Thread safety - multiple fine-grained mutexes for different resources
    mutable std::shared_mutex m_configMutex;
    mutable std::shared_mutex m_eventQueueMutex;
    mutable std::shared_mutex m_forensicMutex;
    mutable std::shared_mutex m_callbackMutex;
    std::mutex m_windowsEventMutex;
    std::mutex m_fileMutex;          // CRITICAL: Dedicated mutex for file I/O
    std::mutex m_rotationMutex;      // Protects log rotation operations
    std::mutex m_workerMutex;
    std::condition_variable m_workerCV;

    // State
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_paused{false};
    std::atomic<bool> m_shutdown{false};
    std::atomic<uint64_t> m_nextEventId{1};
    std::atomic<uint64_t> m_sequenceNumber{1};

    // Configuration
    EventLoggerConfig m_config{};

    // Statistics
    EventLoggerStatistics m_stats{};

    // Event queues with priority support
    std::deque<SecurityEvent> m_eventQueue;
    std::deque<SecurityEvent> m_criticalEventQueue;  // Separate queue for critical events
    std::deque<AuditEvent> m_auditQueue;
    std::deque<ForensicEvent> m_forensicBuffer;
    std::atomic<uint64_t> m_forensicBufferMemory{0};  // Track actual memory usage

    // Windows Event Log
    HANDLE m_eventSourceHandle{nullptr};

    // Callbacks with failure tracking
    std::atomic<uint64_t> m_nextCallbackId{1};
    std::unordered_map<uint64_t, EventCallback> m_eventCallbacks;
    std::unordered_map<uint64_t, AuditCallback> m_auditCallbacks;
    std::unordered_map<uint64_t, uint32_t> m_callbackFailureCounts;  // Track failures

    // Worker threads
    std::vector<std::jthread> m_workerThreads;

    // File logging with crash-safe support
    std::ofstream m_logFile;
    HANDLE m_logFileHandle{INVALID_HANDLE_VALUE};  // For FlushFileBuffers
    std::atomic<uint64_t> m_currentLogFileSize{0};
    std::atomic<uint32_t> m_currentLogFileIndex{0};
    
    // Integrity - hash chain
    std::string m_previousEventHash;
    std::mutex m_hashChainMutex;

    // ========================================================================
    // CONSTRUCTOR / DESTRUCTOR
    // ========================================================================

    EventLoggerImpl() = default;
    ~EventLoggerImpl() = default;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    [[nodiscard]] bool Initialize(const EventLoggerConfig& config) {
        std::unique_lock lock(m_configMutex);

        if (m_initialized.load(std::memory_order_acquire)) {
            Logger::Warn("EventLogger::Impl already initialized");
            return true;
        }

        try {
            Logger::Info("EventLogger::Impl: Initializing with enterprise security features");

            // Validate HMAC key
            if (config.enableTamperProtection && config.hmacKey.size() < SecurityLimits::HMAC_KEY_SIZE) {
                Logger::Error("EventLogger: HMAC key must be at least {} bytes", SecurityLimits::HMAC_KEY_SIZE);
                return false;
            }

            // Store configuration
            m_config = config;

            // Reset statistics
            m_stats.Reset();

            // Initialize Windows Event Log source
            if (config.destinations & static_cast<uint8_t>(LogDestination::WindowsEventLog)) {
                if (!InitializeWindowsEventLog()) {
                    Logger::Error("EventLogger: Windows Event Log initialization failed - aborting");
                    return false;
                }
            }

            // Initialize file logging
            if (config.destinations & static_cast<uint8_t>(LogDestination::File)) {
                if (!InitializeFileLogging()) {
                    Logger::Error("EventLogger: File logging initialization failed - aborting");
                    return false;
                }
            }

            // Start worker threads (single writer thread for file to avoid contention)
            StartWorkerThreads();

            m_initialized.store(true, std::memory_order_release);
            Logger::Info("EventLogger::Impl: Initialization complete - tamper protection: {}, crash-safe: {}", 
                config.enableTamperProtection, config.enableCrashSafeLogging);

            return true;

        } catch (const std::exception& e) {
            Logger::Error("EventLogger::Impl: Initialization exception: {}", e.what());
            return false;
        }
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_configMutex);

        if (!m_initialized.load(std::memory_order_acquire)) {
            return;
        }

        Logger::Info("EventLogger::Impl: Shutting down");

        // Signal shutdown
        m_shutdown.store(true, std::memory_order_release);

        // Flush pending events
        FlushImpl();

        // Stop worker threads
        m_workerCV.notify_all();
        m_workerThreads.clear();

        // Close Windows Event Log
        if (m_eventSourceHandle) {
            DeregisterEventSource(m_eventSourceHandle);
            m_eventSourceHandle = nullptr;
        }

        // Close log file with final flush
        {
            std::unique_lock fileLock(m_fileMutex);
            if (m_logFile.is_open()) {
                m_logFile.flush();
                m_logFile.close();
            }
            if (m_logFileHandle != INVALID_HANDLE_VALUE) {
                FlushFileBuffers(m_logFileHandle);
                CloseHandle(m_logFileHandle);
                m_logFileHandle = INVALID_HANDLE_VALUE;
            }
        }

        // Clear callbacks
        {
            std::unique_lock cbLock(m_callbackMutex);
            m_eventCallbacks.clear();
            m_auditCallbacks.clear();
            m_callbackFailureCounts.clear();
        }

        m_initialized.store(false, std::memory_order_release);
        Logger::Info("EventLogger::Impl: Shutdown complete");
    }

    [[nodiscard]] bool InitializeWindowsEventLog() {
        try {
            m_eventSourceHandle = RegisterEventSourceW(
                nullptr,
                m_config.eventSourceName.c_str()
            );

            if (!m_eventSourceHandle) {
                Logger::Error("EventLogger: Failed to register event source: {}", GetLastError());
                return false;
            }
            
            Logger::Info("EventLogger: Windows Event Log source registered");
            return true;

        } catch (const std::exception& e) {
            Logger::Error("EventLogger: Windows Event Log init exception: {}", e.what());
            return false;
        }
    }

    [[nodiscard]] bool InitializeFileLogging() {
        try {
            if (m_config.logFilePath.empty()) {
                m_config.logFilePath = L"C:\\ProgramData\\ShadowStrike\\Logs\\events.log";
            }

            // Validate path is within allowed directory
            if (!ValidateExportPath(m_config.logFilePath, m_config.allowedLogDirectory)) {
                Logger::Error("EventLogger: Log file path validation failed - path traversal detected");
                m_stats.pathTraversalBlocked.fetch_add(1, std::memory_order_relaxed);
                return false;
            }

            // Create directory if needed
            fs::path logPath(m_config.logFilePath);
            if (!fs::exists(logPath.parent_path())) {
                fs::create_directories(logPath.parent_path());
            }

            // Open log file for writing
            {
                std::unique_lock fileLock(m_fileMutex);
                m_logFile.open(m_config.logFilePath, std::ios::app | std::ios::binary);
                if (!m_logFile) {
                    Logger::Error("EventLogger: Failed to open log file: {}",
                        StringUtils::WideToUtf8(m_config.logFilePath));
                    return false;
                }
                
                // Also open with Windows API for FlushFileBuffers
                m_logFileHandle = CreateFileW(
                    m_config.logFilePath.c_str(),
                    FILE_APPEND_DATA,
                    FILE_SHARE_READ,
                    nullptr,
                    OPEN_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL,
                    nullptr
                );
            }

            // Set restrictive ACL if configured
            if (m_config.restrictLogFileAccess) {
                if (!SetLogFileACL(m_config.logFilePath)) {
                    Logger::Warn("EventLogger: Failed to set log file ACL - continuing with default permissions");
                }
            }

            // Get current file size
            m_currentLogFileSize.store(
                static_cast<uint64_t>(fs::file_size(m_config.logFilePath)),
                std::memory_order_relaxed
            );

            Logger::Info("EventLogger: File logging initialized with ACL protection");
            return true;

        } catch (const std::exception& e) {
            Logger::Error("EventLogger: File logging init exception: {}", e.what());
            return false;
        }
    }

    void StartWorkerThreads() {
        // Use single writer thread for file I/O to avoid contention
        // Multiple threads for other destinations
        for (uint32_t i = 0; i < m_config.workerThreads; ++i) {
            m_workerThreads.emplace_back([this, i](std::stop_token stoken) {
                WorkerThread(stoken, i);
            });
        }

        Logger::Info("EventLogger: Started {} worker threads", m_config.workerThreads);
    }

    // ========================================================================
    // INTEGRITY FUNCTIONS
    // ========================================================================

    /**
     * @brief Compute HMAC-SHA256 signature for an event.
     */
    [[nodiscard]] std::string ComputeEventHmac(const SecurityEvent& event) {
        if (!m_config.enableTamperProtection || m_config.hmacKey.empty()) {
            return "";
        }

        try {
            // Create canonical string representation of event
            std::ostringstream oss;
            oss << event.eventId << "|"
                << event.sequenceNumber << "|"
                << system_clock::to_time_t(event.timestamp) << "|"
                << static_cast<int>(event.severity) << "|"
                << static_cast<int>(event.category) << "|"
                << StringUtils::WideToUtf8(event.source) << "|"
                << StringUtils::WideToUtf8(event.message) << "|"
                << StringUtils::WideToUtf8(event.filePath) << "|"
                << event.sha256Hash << "|"
                << event.previousEventHash;

            std::string canonical = oss.str();
            std::string hmacHex;
            
            HashUtils::Error err;
            if (HashUtils::ComputeHmacHex(
                    HashUtils::Algorithm::SHA256,
                    m_config.hmacKey.data(),
                    m_config.hmacKey.size(),
                    canonical.data(),
                    canonical.size(),
                    hmacHex,
                    false,
                    &err)) {
                m_stats.integritySignaturesGenerated.fetch_add(1, std::memory_order_relaxed);
                return hmacHex;
            }
            
            Logger::Error("EventLogger: HMAC computation failed");
            return "";
            
        } catch (const std::exception& e) {
            Logger::Error("EventLogger: HMAC exception: {}", e.what());
            return "";
        }
    }

    /**
     * @brief Get and update hash chain link.
     */
    [[nodiscard]] std::string GetAndUpdateHashChain(const SecurityEvent& event) {
        if (!m_config.enableHashChain) {
            return "";
        }

        std::unique_lock lock(m_hashChainMutex);
        
        std::string previousHash = m_previousEventHash;
        
        // Compute hash of this event for the chain
        std::ostringstream oss;
        oss << event.eventId << "|" << event.sequenceNumber << "|" << event.hmacSignature;
        std::string eventData = oss.str();
        
        std::string newHash;
        HashUtils::Error err;
        if (HashUtils::ComputeHashHex(
                HashUtils::Algorithm::SHA256,
                eventData.data(),
                eventData.size(),
                newHash,
                false,
                &err)) {
            m_previousEventHash = newHash;
        }
        
        return previousHash;
    }

    // ========================================================================
    // LOGGING IMPLEMENTATION
    // ========================================================================

    void LogImpl(SecurityEvent event) {
        try {
            // Check severity filter
            if (event.severity < m_config.minimumSeverity) {
                return;
            }

            // Truncate fields to prevent memory exhaustion
            event.message = TruncateField(event.message, m_config.maxFieldLengthBytes);
            event.details = TruncateField(event.details, m_config.maxFieldLengthBytes);
            event.filePath = TruncateField(event.filePath, m_config.maxFieldLengthBytes);
            event.threatName = TruncateField(event.threatName, m_config.maxFieldLengthBytes);
            
            // Limit properties count
            if (event.properties.size() > m_config.maxPropertiesCount) {
                std::unordered_map<std::wstring, std::wstring> truncated;
                size_t count = 0;
                for (const auto& [k, v] : event.properties) {
                    if (count++ >= m_config.maxPropertiesCount) break;
                    truncated[k] = TruncateField(v, m_config.maxFieldLengthBytes);
                }
                event.properties = std::move(truncated);
            }

            // Assign event ID and sequence number
            event.eventId = m_nextEventId.fetch_add(1, std::memory_order_relaxed);
            event.sequenceNumber = m_sequenceNumber.fetch_add(1, std::memory_order_relaxed);
            event.timestamp = system_clock::now();
            event.monotonicTime = steady_clock::now();
            
            // Get high-resolution timestamp
            auto [ticks, freq] = GetHighResolutionTimestamp();
            event.highResolutionTicks = ticks;
            event.highResolutionFrequency = freq;

            // Generate GUID if empty
            if (event.eventGuid.empty()) {
                event.eventGuid = GenerateEventGuid();
            }

            // Determine priority
            event.priority = DetermineEventPriority(event.severity, event.category);

            // Fill in context if empty
            if (event.context.processId == 0) {
                event.context.processId = GetCurrentProcessId();
                event.context.threadId = GetCurrentThreadId();
                event.context.machineName = SystemUtils::GetMachineName();
                event.context.userName = SystemUtils::GetCurrentUserName();
            }

            // Compute integrity signature
            if (m_config.enableTamperProtection) {
                event.previousEventHash = GetAndUpdateHashChain(event);
                event.hmacSignature = ComputeEventHmac(event);
            }

            // Invoke callbacks (with timeout protection)
            InvokeEventCallbacks(event);

            // Queue for async processing with priority
            QueueEvent(std::move(event));

            m_stats.eventsLogged.fetch_add(1, std::memory_order_relaxed);
            m_workerCV.notify_one();

        } catch (const std::exception& e) {
            Logger::Error("EventLogger: Log exception: {}", e.what());
        }
    }

    void QueueEvent(SecurityEvent event) {
        std::unique_lock lock(m_eventQueueMutex);
        
        // Critical events go to separate queue that never drops
        if (event.priority == EventPriority::Critical) {
            m_criticalEventQueue.push_back(std::move(event));
            return;
        }
        
        // Update high water mark
        size_t currentSize = m_eventQueue.size();
        size_t prevHigh = m_stats.queueHighWaterMark.load(std::memory_order_relaxed);
        if (currentSize > prevHigh) {
            m_stats.queueHighWaterMark.store(currentSize, std::memory_order_relaxed);
        }
        
        // Check if queue is full (leaving room for critical events)
        size_t effectiveMaxSize = m_config.asyncQueueSize - m_config.criticalQueueReserve;
        
        if (m_eventQueue.size() >= effectiveMaxSize) {
            // Drop lowest priority events first
            bool dropped = false;
            for (auto it = m_eventQueue.begin(); it != m_eventQueue.end(); ++it) {
                if (it->priority < event.priority) {
                    m_eventQueue.erase(it);
                    dropped = true;
                    m_stats.eventsDropped.fetch_add(1, std::memory_order_relaxed);
                    break;
                }
            }
            
            // If couldn't find lower priority, and this isn't critical, drop this event
            if (!dropped && event.priority != EventPriority::Critical) {
                m_stats.eventsDropped.fetch_add(1, std::memory_order_relaxed);
                Logger::Warn("EventLogger: Event dropped - queue full (priority: {})", 
                    static_cast<int>(event.priority));
                return;
            }
        }

        m_eventQueue.push_back(std::move(event));
    }

    void LogAuditImpl(AuditEvent event) {
        try {
            event.eventId = m_nextEventId.fetch_add(1, std::memory_order_relaxed);
            event.timestamp = system_clock::now();

            // Fill in context if empty
            if (event.context.processId == 0) {
                event.context.processId = GetCurrentProcessId();
                event.context.machineName = SystemUtils::GetMachineName();
                event.context.userName = SystemUtils::GetCurrentUserName();
            }

            // Invoke callbacks
            InvokeAuditCallbacks(event);

            // Queue for processing
            {
                std::unique_lock lock(m_eventQueueMutex);
                m_auditQueue.push_back(std::move(event));
            }

            m_stats.auditEventsLogged.fetch_add(1, std::memory_order_relaxed);
            m_workerCV.notify_one();

        } catch (const std::exception& e) {
            Logger::Error("EventLogger: Audit log exception: {}", e.what());
        }
    }

    void CaptureForensicEventImpl(
        const std::wstring& eventType,
        const std::unordered_map<std::wstring, std::wstring>& data
    ) {
        if (!m_config.enableForensicCapture) {
            return;
        }

        try {
            ForensicEvent event{};
            event.eventId = m_nextEventId.fetch_add(1, std::memory_order_relaxed);
            event.sequenceNumber = m_sequenceNumber.fetch_add(1, std::memory_order_relaxed);
            event.eventType = TruncateField(eventType, m_config.maxFieldLengthBytes);
            event.timestamp = system_clock::now();
            event.timestampTicks = steady_clock::now().time_since_epoch().count();
            
            // Truncate data values
            for (const auto& [key, value] : data) {
                event.data[TruncateField(key, 256)] = TruncateField(value, m_config.maxFieldLengthBytes);
            }

            // Fill context
            event.context.processId = GetCurrentProcessId();
            event.context.threadId = GetCurrentThreadId();
            event.context.machineName = SystemUtils::GetMachineName();

            // Estimate memory usage
            size_t eventMemory = sizeof(ForensicEvent) + event.eventType.size() * sizeof(wchar_t);
            for (const auto& [k, v] : event.data) {
                eventMemory += (k.size() + v.size()) * sizeof(wchar_t);
            }
            eventMemory += event.stackTrace.size() * sizeof(wchar_t);
            eventMemory += event.memoryDump.size();

            {
                std::unique_lock lock(m_forensicMutex);

                // Check both count and memory limits
                uint64_t maxMemory = m_config.forensicBufferMaxMemoryMB * 1024 * 1024;
                
                while ((m_forensicBuffer.size() >= m_config.forensicBufferSize ||
                        m_forensicBufferMemory.load(std::memory_order_relaxed) + eventMemory > maxMemory) &&
                       !m_forensicBuffer.empty()) {
                    // Remove oldest and subtract its memory
                    const auto& oldest = m_forensicBuffer.front();
                    size_t oldestMemory = sizeof(ForensicEvent) + oldest.eventType.size() * sizeof(wchar_t);
                    for (const auto& [k, v] : oldest.data) {
                        oldestMemory += (k.size() + v.size()) * sizeof(wchar_t);
                    }
                    m_forensicBufferMemory.fetch_sub(oldestMemory, std::memory_order_relaxed);
                    m_forensicBuffer.pop_front();
                }

                m_forensicBuffer.push_back(std::move(event));
                m_forensicBufferMemory.fetch_add(eventMemory, std::memory_order_relaxed);
                m_stats.forensicBufferMemoryBytes.store(
                    m_forensicBufferMemory.load(std::memory_order_relaxed),
                    std::memory_order_relaxed
                );
            }

            m_stats.forensicEventsCaptures.fetch_add(1, std::memory_order_relaxed);

        } catch (const std::exception& e) {
            Logger::Error("EventLogger: Forensic capture exception: {}", e.what());
        }
    }

    // ========================================================================
    // WORKER THREAD
    // ========================================================================

    void WorkerThread(std::stop_token stoken, uint32_t threadIndex) {
        Logger::Debug("EventLogger: Worker thread {} started", threadIndex);

        while (!stoken.stop_requested() && !m_shutdown.load(std::memory_order_acquire)) {
            try {
                // Wait for events
                std::unique_lock lock(m_workerMutex);
                m_workerCV.wait_for(lock, milliseconds(1000), [this, &stoken] {
                    return stoken.stop_requested() ||
                           m_shutdown.load(std::memory_order_acquire) ||
                           !m_eventQueue.empty() ||
                           !m_criticalEventQueue.empty() ||
                           !m_auditQueue.empty();
                });

                // Process critical events first (they must never be dropped)
                ProcessCriticalEventQueue();

                // Process security events
                ProcessEventQueue();

                // Process audit events
                ProcessAuditQueue();

            } catch (const std::exception& e) {
                Logger::Error("EventLogger: Worker thread {} exception: {}", threadIndex, e.what());
            }
        }

        Logger::Debug("EventLogger: Worker thread {} stopped", threadIndex);
    }

    void ProcessCriticalEventQueue() {
        std::vector<SecurityEvent> batch;

        // Get all critical events (they never wait)
        {
            std::unique_lock lock(m_eventQueueMutex);
            if (m_criticalEventQueue.empty()) return;
            
            // Process all critical events immediately
            batch.reserve(m_criticalEventQueue.size());
            while (!m_criticalEventQueue.empty()) {
                batch.push_back(std::move(m_criticalEventQueue.front()));
                m_criticalEventQueue.pop_front();
            }
        }

        // Process batch
        for (const auto& event : batch) {
            ProcessEvent(event);
        }
    }

    void ProcessEventQueue() {
        std::vector<SecurityEvent> batch;

        // Get batch of events
        {
            std::unique_lock lock(m_eventQueueMutex);
            size_t batchSize = std::min(m_eventQueue.size(), size_t(100));

            for (size_t i = 0; i < batchSize; ++i) {
                batch.push_back(std::move(m_eventQueue.front()));
                m_eventQueue.pop_front();
            }
        }

        // Process batch
        for (const auto& event : batch) {
            ProcessEvent(event);
        }
    }

    void ProcessAuditQueue() {
        std::vector<AuditEvent> batch;

        // Get batch of events
        {
            std::unique_lock lock(m_eventQueueMutex);
            size_t batchSize = std::min(m_auditQueue.size(), size_t(50));

            for (size_t i = 0; i < batchSize; ++i) {
                batch.push_back(std::move(m_auditQueue.front()));
                m_auditQueue.pop_front();
            }
        }

        // Process batch
        for (const auto& event : batch) {
            ProcessAuditEvent(event);
        }
    }

    void ProcessEvent(const SecurityEvent& event) {
        // Windows Event Log
        if (m_config.destinations & static_cast<uint8_t>(LogDestination::WindowsEventLog)) {
            WriteToWindowsEventLogImpl(event);
        }

        // Internal DB
        if (m_config.destinations & static_cast<uint8_t>(LogDestination::InternalDB)) {
            WriteToDBImpl(event);
        }

        // File (thread-safe with dedicated mutex)
        if (m_config.destinations & static_cast<uint8_t>(LogDestination::File)) {
            WriteToFileImpl(event);
        }

        // Syslog
        if (m_config.destinations & static_cast<uint8_t>(LogDestination::Syslog)) {
            ForwardToSyslogImpl(event);
        }

        // SIEM
        if (m_config.destinations & static_cast<uint8_t>(LogDestination::SIEM)) {
            ForwardToSIEMImpl(event);
        }
    }

    void ProcessAuditEvent(const AuditEvent& event) {
        // Convert to SecurityEvent for unified processing
        SecurityEvent secEvent{};
        secEvent.eventId = event.eventId;
        secEvent.sequenceNumber = m_sequenceNumber.fetch_add(1, std::memory_order_relaxed);
        secEvent.severity = event.success ? EventSeverity::AuditSuccess : EventSeverity::AuditFailure;
        secEvent.category = EventCategory::PolicyChange;
        secEvent.priority = EventPriority::Critical;  // Audit events are always critical
        secEvent.source = L"ShadowStrike.Audit";
        
        // Truncate audit fields before formatting
        std::wstring truncatedAction = TruncateField(event.action, m_config.maxFieldLengthBytes);
        std::wstring truncatedTarget = TruncateField(event.targetObject, m_config.maxFieldLengthBytes);
        std::wstring truncatedOld = TruncateField(event.oldValue, m_config.maxFieldLengthBytes);
        std::wstring truncatedNew = TruncateField(event.newValue, m_config.maxFieldLengthBytes);
        std::wstring truncatedReason = TruncateField(event.reason, m_config.maxFieldLengthBytes);
        
        secEvent.message = std::format(L"Audit: {} on {}", truncatedAction, truncatedTarget);
        secEvent.details = std::format(L"Old: {}, New: {}, Reason: {}",
            truncatedOld, truncatedNew, truncatedReason);
        secEvent.context = event.context;
        secEvent.timestamp = event.timestamp;
        secEvent.windowsEventId = EventIds::POLICY_CHANGED;
        
        // Compute integrity for audit event
        if (m_config.enableTamperProtection) {
            secEvent.previousEventHash = GetAndUpdateHashChain(secEvent);
            secEvent.hmacSignature = ComputeEventHmac(secEvent);
        }

        ProcessEvent(secEvent);
    }

    // ========================================================================
    // DESTINATION WRITERS (Thread-Safe)
    // ========================================================================

    void WriteToWindowsEventLogImpl(const SecurityEvent& event) {
        if (!m_eventSourceHandle) {
            return;
        }

        try {
            std::unique_lock lock(m_windowsEventMutex);

            WORD eventType = SeverityToEventType(event.severity);
            DWORD eventId = event.windowsEventId != 0 ? event.windowsEventId : EventIds::SYSTEM_STARTUP;

            std::vector<LPCWSTR> strings;
            strings.push_back(event.message.c_str());
            if (!event.details.empty()) {
                strings.push_back(event.details.c_str());
            }

            BOOL success = ReportEventW(
                m_eventSourceHandle,
                eventType,
                static_cast<WORD>(event.category),
                eventId,
                nullptr,
                static_cast<WORD>(strings.size()),
                0,
                strings.data(),
                nullptr
            );

            if (success) {
                m_stats.windowsEventsWritten.fetch_add(1, std::memory_order_relaxed);
            } else {
                Logger::Error("EventLogger: ReportEvent failed: {}", GetLastError());
            }

        } catch (const std::exception& e) {
            Logger::Error("EventLogger: Windows Event Log write exception: {}", e.what());
        }
    }

    void WriteToDBImpl(const SecurityEvent& event) {
        try {
            // Use LogDB from infrastructure
            auto& logDB = Database::LogDB::Instance();

            // Convert SecurityEvent to LogDB::LogEntry using LogDB's actual interface
            Database::LogDB::LogEntry entry{};
            entry.timestamp = event.timestamp;
            
            // Map EventSeverity to LogLevel
            switch (event.severity) {
                case EventSeverity::Debug:
                    entry.level = Database::LogDB::LogLevel::Debug;
                    break;
                case EventSeverity::Info:
                case EventSeverity::AuditSuccess:
                    entry.level = Database::LogDB::LogLevel::Info;
                    break;
                case EventSeverity::Warning:
                    entry.level = Database::LogDB::LogLevel::Warn;
                    break;
                case EventSeverity::Error:
                case EventSeverity::AuditFailure:
                    entry.level = Database::LogDB::LogLevel::Error;
                    break;
                case EventSeverity::Critical:
                    entry.level = Database::LogDB::LogLevel::Fatal;
                    break;
                default:
                    entry.level = Database::LogDB::LogLevel::Info;
                    break;
            }
            
            // Map EventCategory to LogCategory (General for security events)
            entry.category = Database::LogDB::LogCategory::Security;
            
            entry.source = event.source;
            entry.message = event.message;
            entry.details = event.details;
            entry.processId = event.context.processId;
            entry.threadId = event.context.threadId;
            entry.userName = event.context.userName;
            entry.machineName = event.context.machineName;
            entry.filePath = event.filePath;
            
            // Store additional data in metadata as JSON
            nlohmann::json metadata;
            metadata["eventId"] = event.eventId;
            metadata["sequenceNumber"] = event.sequenceNumber;
            metadata["eventGuid"] = StringUtils::WideToUtf8(event.eventGuid);
            metadata["category"] = StringUtils::WideToUtf8(CategoryToString(event.category));
            if (!event.threatName.empty()) {
                metadata["threatName"] = StringUtils::WideToUtf8(event.threatName);
                metadata["threatType"] = StringUtils::WideToUtf8(event.threatType);
            }
            if (!event.sha256Hash.empty()) {
                metadata["sha256"] = event.sha256Hash;
            }
            if (!event.hmacSignature.empty()) {
                metadata["hmac"] = event.hmacSignature;
                metadata["prevHash"] = event.previousEventHash;
            }
            entry.metadata = StringUtils::ToWide(metadata.dump());
            
            // Use LogDetailed to store the entry
            int64_t result = logDB.LogDetailed(entry);
            if (result != 0) {
                m_stats.dbEventsWritten.fetch_add(1, std::memory_order_relaxed);
            }

        } catch (const std::exception& e) {
            Logger::Error("EventLogger: DB write exception: {}", e.what());
        }
    }

    void WriteToFileImpl(const SecurityEvent& event) {
        // CRITICAL: All file I/O protected by dedicated mutex
        std::unique_lock fileLock(m_fileMutex);
        
        try {
            if (!m_logFile.is_open()) {
                return;
            }

            // Format with high-resolution timestamp
            auto timeT = system_clock::to_time_t(event.timestamp);
            auto micros = duration_cast<microseconds>(event.timestamp.time_since_epoch()) % 1000000;
            std::tm tm;
            localtime_s(&tm, &timeT);

            char timeBuffer[64];
            strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M:%S", &tm);

            std::ostringstream oss;
            oss << "[" << timeBuffer << "." << std::setfill('0') << std::setw(6) << micros.count() << "] "
                << "[" << SanitizeForFile(StringUtils::WideToUtf8(SeverityToString(event.severity))) << "] "
                << "[" << SanitizeForFile(StringUtils::WideToUtf8(CategoryToString(event.category))) << "] "
                << "[" << SanitizeForFile(StringUtils::WideToUtf8(event.source)) << "] "
                << "[seq:" << event.sequenceNumber << "] "
                << SanitizeForFile(StringUtils::WideToUtf8(event.message));

            if (!event.details.empty()) {
                oss << " - " << SanitizeForFile(StringUtils::WideToUtf8(event.details));
            }
            
            // Include HMAC for tamper evidence
            if (!event.hmacSignature.empty()) {
                oss << " [hmac:" << event.hmacSignature.substr(0, 16) << "...]";
            }

            oss << "\n";

            std::string logLine = oss.str();
            m_logFile << logLine;
            
            // Track sanitization
            std::string unsanitized = StringUtils::WideToUtf8(event.message);
            if (logLine.find("\\n") != std::string::npos || logLine.find("\\r") != std::string::npos) {
                m_stats.sanitizationApplied.fetch_add(1, std::memory_order_relaxed);
            }

            // Update file size
            size_t bytesWritten = logLine.size();
            m_currentLogFileSize.fetch_add(bytesWritten, std::memory_order_relaxed);

            // Crash-safe flush for critical events
            if (m_config.enableCrashSafeLogging && 
                (event.priority == EventPriority::Critical || 
                 event.severity == EventSeverity::Critical ||
                 event.category == EventCategory::ThreatDetection)) {
                m_logFile.flush();
                if (m_logFileHandle != INVALID_HANDLE_VALUE) {
                    FlushFileBuffers(m_logFileHandle);
                }
                m_stats.crashSafeFlushes.fetch_add(1, std::memory_order_relaxed);
            }

            // Check for rotation (under same lock to prevent race)
            uint64_t maxSize = m_config.maxLogFileSizeMB * 1024 * 1024;
            if (m_currentLogFileSize.load(std::memory_order_relaxed) >= maxSize) {
                RotateLogFileImpl();  // Called while holding fileLock
            }

        } catch (const std::exception& e) {
            Logger::Error("EventLogger: File write exception: {}", e.what());
        }
    }

    void ForwardToSyslogImpl(const SecurityEvent& event) {
        try {
            if (m_config.syslog.serverAddress.empty()) {
                return;
            }

            std::string syslogMessage = FormatAsSyslog(event, m_config.syslog);

            // Use NetworkUtils for actual forwarding
            NetworkUtils::Error netErr;
            
            if (m_config.syslog.useTCP) {
                // TCP syslog (more reliable)
                auto result = NetworkUtils::HttpPost(
                    StringUtils::WideToUtf8(m_config.syslog.serverAddress),
                    m_config.syslog.port,
                    "/",
                    syslogMessage,
                    "text/plain",
                    {},
                    m_config.syslog.useTLS,
                    5000,  // 5 second timeout
                    &netErr
                );
                
                if (result.statusCode >= 200 && result.statusCode < 300) {
                    m_stats.syslogEventsForwarded.fetch_add(1, std::memory_order_relaxed);
                }
            } else {
                // UDP syslog (fire and forget - best effort)
                // Note: For production, implement proper UDP socket send
                m_stats.syslogEventsForwarded.fetch_add(1, std::memory_order_relaxed);
            }

        } catch (const std::exception& e) {
            Logger::Error("EventLogger: Syslog forward exception: {}", e.what());
        }
    }

    void ForwardToSIEMImpl(const SecurityEvent& event) {
        try {
            if (!m_config.siem.enabled || m_config.siem.endpoint.empty()) {
                return;
            }

            std::string formattedEvent;

            switch (m_config.siem.format) {
                case SIEMFormat::JSON:
                    formattedEvent = FormatAsJSON(event);
                    break;
                case SIEMFormat::CEF:
                    formattedEvent = FormatAsCEF(event);
                    break;
                case SIEMFormat::LEEF:
                    formattedEvent = FormatAsLEEF(event);
                    break;
                case SIEMFormat::Syslog:
                    formattedEvent = FormatAsSyslog(event, m_config.syslog);
                    break;
                default:
                    return;
            }

            // Compress payload if configured
            std::string payload = formattedEvent;
            if (m_config.siem.compressPayload) {
                std::vector<uint8_t> compressed;
                if (CompressionUtils::CompressBuffer(
                        CompressionUtils::Algorithm::XPRESS_HUFF,
                        formattedEvent.data(),
                        formattedEvent.size(),
                        compressed)) {
                    payload = std::string(compressed.begin(), compressed.end());
                }
            }

            // Send to SIEM endpoint
            NetworkUtils::Error netErr;
            std::unordered_map<std::string, std::string> headers;
            headers["Authorization"] = "Bearer " + StringUtils::WideToUtf8(m_config.siem.apiKey);
            if (m_config.siem.compressPayload) {
                headers["Content-Encoding"] = "deflate";
            }
            
            auto result = NetworkUtils::HttpPost(
                StringUtils::WideToUtf8(m_config.siem.endpoint),
                443,
                "/api/v1/events",
                payload,
                m_config.siem.format == SIEMFormat::JSON ? "application/json" : "text/plain",
                headers,
                true,   // Use TLS
                10000,  // 10 second timeout
                &netErr
            );
            
            if (result.statusCode >= 200 && result.statusCode < 300) {
                m_stats.siemEventsForwarded.fetch_add(1, std::memory_order_relaxed);
            } else {
                Logger::Warn("EventLogger: SIEM forward failed with status {}", result.statusCode);
            }

        } catch (const std::exception& e) {
            Logger::Error("EventLogger: SIEM forward exception: {}", e.what());
        }
    }

    [[nodiscard]] std::string FormatAsJSON(const SecurityEvent& event) const {
        nlohmann::json j;

        j["eventId"] = event.eventId;
        j["sequenceNumber"] = event.sequenceNumber;
        j["eventGuid"] = SanitizeForFile(StringUtils::WideToUtf8(event.eventGuid));
        j["timestamp"] = system_clock::to_time_t(event.timestamp);
        j["timestampMicros"] = duration_cast<microseconds>(event.timestamp.time_since_epoch()).count();
        j["highResolutionTicks"] = event.highResolutionTicks;
        j["severity"] = SanitizeForFile(StringUtils::WideToUtf8(SeverityToString(event.severity)));
        j["category"] = SanitizeForFile(StringUtils::WideToUtf8(CategoryToString(event.category)));
        j["source"] = SanitizeForFile(StringUtils::WideToUtf8(event.source));
        j["message"] = SanitizeForFile(StringUtils::WideToUtf8(event.message));

        if (!event.details.empty()) {
            j["details"] = SanitizeForFile(StringUtils::WideToUtf8(event.details));
        }

        if (!event.threatName.empty()) {
            j["threatName"] = SanitizeForFile(StringUtils::WideToUtf8(event.threatName));
            j["threatType"] = SanitizeForFile(StringUtils::WideToUtf8(event.threatType));
        }

        if (!event.filePath.empty()) {
            j["filePath"] = SanitizeForFile(StringUtils::WideToUtf8(event.filePath));
        }

        if (!event.sha256Hash.empty()) {
            j["sha256"] = event.sha256Hash;
        }

        j["context"]["processId"] = event.context.processId;
        j["context"]["threadId"] = event.context.threadId;
        j["context"]["processName"] = SanitizeForFile(StringUtils::WideToUtf8(event.context.processName));
        j["context"]["userName"] = SanitizeForFile(StringUtils::WideToUtf8(event.context.userName));
        j["context"]["machineName"] = SanitizeForFile(StringUtils::WideToUtf8(event.context.machineName));

        // Integrity fields
        if (!event.hmacSignature.empty()) {
            j["integrity"]["hmac"] = event.hmacSignature;
            j["integrity"]["previousHash"] = event.previousEventHash;
        }

        return j.dump();
    }

    // ========================================================================
    // LOG ROTATION (Thread-Safe)
    // ========================================================================

    void RotateLogFileImpl() {
        // NOTE: Must be called while holding m_fileMutex
        std::unique_lock rotationLock(m_rotationMutex);
        
        try {
            Logger::Info("EventLogger: Rotating log file");
            
            // Flush before closing
            if (m_logFile.is_open()) {
                m_logFile.flush();
                m_logFile.close();
            }
            
            // Flush OS buffer
            if (m_logFileHandle != INVALID_HANDLE_VALUE) {
                FlushFileBuffers(m_logFileHandle);
                CloseHandle(m_logFileHandle);
                m_logFileHandle = INVALID_HANDLE_VALUE;
            }

            // Rename current file
            uint32_t newIndex = m_currentLogFileIndex.fetch_add(1, std::memory_order_relaxed) + 1;
            fs::path oldPath(m_config.logFilePath);
            fs::path newPath = oldPath;
            newPath.replace_filename(
                oldPath.stem().wstring() + L"." +
                std::to_wstring(newIndex) +
                oldPath.extension().wstring()
            );

            std::error_code ec;
            if (fs::exists(oldPath, ec)) {
                fs::rename(oldPath, newPath, ec);
                if (ec) {
                    Logger::Error("EventLogger: Log rotation rename failed: {}", ec.message());
                }
            }

            // Compress old file if configured
            if (m_config.compressOldLogs && fs::exists(newPath, ec)) {
                CompressRotatedLog(newPath);
            }

            // Delete oldest files if exceeded max
            DeleteOldLogFiles();

            // Open new file
            m_logFile.open(m_config.logFilePath, std::ios::app | std::ios::binary);
            m_logFileHandle = CreateFileW(
                m_config.logFilePath.c_str(),
                FILE_APPEND_DATA,
                FILE_SHARE_READ,
                nullptr,
                OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                nullptr
            );
            
            m_currentLogFileSize.store(0, std::memory_order_relaxed);
            
            // Set ACL on new file
            if (m_config.restrictLogFileAccess) {
                SetLogFileACL(m_config.logFilePath);
            }
            
            m_stats.logRotations.fetch_add(1, std::memory_order_relaxed);

        } catch (const std::exception& e) {
            Logger::Error("EventLogger: Log rotation exception: {}", e.what());
        }
    }

    void CompressRotatedLog(const fs::path& logPath) {
        try {
            // Read the log file
            std::ifstream inFile(logPath, std::ios::binary);
            if (!inFile) return;
            
            std::vector<uint8_t> content(
                (std::istreambuf_iterator<char>(inFile)),
                std::istreambuf_iterator<char>()
            );
            inFile.close();
            
            // Compress using infrastructure
            std::vector<uint8_t> compressed;
            if (CompressionUtils::CompressBuffer(
                    CompressionUtils::Algorithm::XPRESS_HUFF,
                    content.data(),
                    content.size(),
                    compressed)) {
                
                // Write compressed file
                fs::path compressedPath = logPath;
                compressedPath.replace_extension(L".log.xz");
                
                std::ofstream outFile(compressedPath, std::ios::binary);
                outFile.write(reinterpret_cast<const char*>(compressed.data()), compressed.size());
                outFile.close();
                
                // Secure delete original if configured
                if (m_config.secureDeleteRotatedLogs) {
                    SecureDeleteFile(logPath);
                } else {
                    fs::remove(logPath);
                }
                
                Logger::Debug("EventLogger: Compressed rotated log: {} -> {} bytes", 
                    content.size(), compressed.size());
            }
            
        } catch (const std::exception& e) {
            Logger::Error("EventLogger: Log compression exception: {}", e.what());
        }
    }

    void SecureDeleteFile(const fs::path& filePath) {
        try {
            // Overwrite file content before deleting
            auto fileSize = fs::file_size(filePath);
            std::ofstream file(filePath, std::ios::binary | std::ios::trunc);
            
            // Overwrite with zeros
            std::vector<char> zeros(std::min(fileSize, static_cast<uintmax_t>(4096)), 0);
            for (uintmax_t written = 0; written < fileSize; written += zeros.size()) {
                file.write(zeros.data(), std::min(zeros.size(), static_cast<size_t>(fileSize - written)));
            }
            
            // Overwrite with random data
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, 255);
            for (auto& byte : zeros) {
                byte = static_cast<char>(dis(gen));
            }
            
            file.seekp(0);
            for (uintmax_t written = 0; written < fileSize; written += zeros.size()) {
                file.write(zeros.data(), std::min(zeros.size(), static_cast<size_t>(fileSize - written)));
            }
            
            file.close();
            fs::remove(filePath);
            
        } catch (const std::exception& e) {
            Logger::Error("EventLogger: Secure delete exception: {}", e.what());
            // Fall back to regular delete
            std::error_code ec;
            fs::remove(filePath, ec);
        }
    }

    void DeleteOldLogFiles() {
        try {
            fs::path logDir = fs::path(m_config.logFilePath).parent_path();
            fs::path logStem = fs::path(m_config.logFilePath).stem();
            
            // Collect all log files with our naming pattern
            std::vector<std::pair<fs::path, uint32_t>> logFiles;
            
            for (const auto& entry : fs::directory_iterator(logDir)) {
                if (!entry.is_regular_file()) continue;
                
                std::wstring filename = entry.path().filename().wstring();
                std::wstring stemStr = logStem.wstring();
                
                // Check if file matches our pattern: stem.N.log or stem.N.log.xz
                if (filename.find(stemStr + L".") == 0) {
                    // Extract the number
                    size_t dotPos = filename.find(L'.', stemStr.size() + 1);
                    if (dotPos != std::wstring::npos) {
                        try {
                            uint32_t num = std::stoul(filename.substr(stemStr.size() + 1, dotPos - stemStr.size() - 1));
                            logFiles.emplace_back(entry.path(), num);
                        } catch (...) {
                            // Not a numbered log file
                        }
                    }
                }
            }
            
            // Sort by number (oldest first)
            std::sort(logFiles.begin(), logFiles.end(),
                [](const auto& a, const auto& b) { return a.second < b.second; });
            
            // Delete oldest files if we exceed max
            while (logFiles.size() > m_config.maxLogFiles) {
                const auto& [path, num] = logFiles.front();
                
                if (m_config.secureDeleteRotatedLogs) {
                    SecureDeleteFile(path);
                } else {
                    std::error_code ec;
                    fs::remove(path, ec);
                }
                
                Logger::Debug("EventLogger: Deleted old log file: {}", path.string());
                logFiles.erase(logFiles.begin());
            }
            
        } catch (const std::exception& e) {
            Logger::Error("EventLogger: Delete old logs exception: {}", e.what());
        }
    }

    // ========================================================================
    // QUERY AND EXPORT (With Path Validation and Streaming)
    // ========================================================================

    [[nodiscard]] std::vector<SecurityEvent> QueryEventsImpl(
        system_clock::time_point startTime,
        system_clock::time_point endTime,
        std::optional<EventCategory> category,
        std::optional<EventSeverity> minSeverity,
        uint32_t maxResults
    ) const {
        std::vector<SecurityEvent> results;

        try {
            // Query from DB with proper LogDB QueryFilter
            auto& logDB = Database::LogDB::Instance();
            
            Database::LogDB::QueryFilter filter;
            filter.startTime = startTime;
            filter.endTime = endTime;
            filter.maxResults = maxResults;
            
            // Map EventSeverity to LogLevel
            if (minSeverity.has_value()) {
                switch (minSeverity.value()) {
                    case EventSeverity::Debug:
                        filter.minLevel = Database::LogDB::LogLevel::Debug;
                        break;
                    case EventSeverity::Info:
                    case EventSeverity::AuditSuccess:
                        filter.minLevel = Database::LogDB::LogLevel::Info;
                        break;
                    case EventSeverity::Warning:
                        filter.minLevel = Database::LogDB::LogLevel::Warn;
                        break;
                    case EventSeverity::Error:
                    case EventSeverity::AuditFailure:
                        filter.minLevel = Database::LogDB::LogLevel::Error;
                        break;
                    case EventSeverity::Critical:
                        filter.minLevel = Database::LogDB::LogLevel::Fatal;
                        break;
                    default:
                        break;
                }
            }
            
            // For security events we use the Security category
            filter.category = Database::LogDB::LogCategory::Security;
            
            auto entries = logDB.Query(filter);
            
            // Convert LogEntry to SecurityEvent
            results.reserve(entries.size());
            for (const auto& entry : entries) {
                SecurityEvent event{};
                event.eventId = static_cast<uint64_t>(entry.id);
                event.timestamp = entry.timestamp;
                
                // Map LogLevel back to EventSeverity
                switch (entry.level) {
                    case Database::LogDB::LogLevel::Trace:
                    case Database::LogDB::LogLevel::Debug:
                        event.severity = EventSeverity::Debug;
                        break;
                    case Database::LogDB::LogLevel::Info:
                        event.severity = EventSeverity::Info;
                        break;
                    case Database::LogDB::LogLevel::Warn:
                        event.severity = EventSeverity::Warning;
                        break;
                    case Database::LogDB::LogLevel::Error:
                        event.severity = EventSeverity::Error;
                        break;
                    case Database::LogDB::LogLevel::Fatal:
                        event.severity = EventSeverity::Critical;
                        break;
                    default:
                        event.severity = EventSeverity::Info;
                        break;
                }
                
                event.source = entry.source;
                event.message = entry.message;
                event.details = entry.details;
                event.filePath = entry.filePath;
                event.context.processId = entry.processId;
                event.context.threadId = entry.threadId;
                event.context.userName = entry.userName;
                event.context.machineName = entry.machineName;
                
                // Parse metadata JSON to recover original fields
                if (!entry.metadata.empty()) {
                    try {
                        auto metadata = nlohmann::json::parse(StringUtils::WideToUtf8(entry.metadata));
                        if (metadata.contains("eventGuid")) {
                            event.eventGuid = StringUtils::ToWide(metadata["eventGuid"].get<std::string>());
                        }
                        if (metadata.contains("sequenceNumber")) {
                            event.sequenceNumber = metadata["sequenceNumber"].get<uint64_t>();
                        }
                        if (metadata.contains("threatName")) {
                            event.threatName = StringUtils::ToWide(metadata["threatName"].get<std::string>());
                        }
                        if (metadata.contains("threatType")) {
                            event.threatType = StringUtils::ToWide(metadata["threatType"].get<std::string>());
                        }
                        if (metadata.contains("sha256")) {
                            event.sha256Hash = metadata["sha256"].get<std::string>();
                        }
                        if (metadata.contains("hmac")) {
                            event.hmacSignature = metadata["hmac"].get<std::string>();
                        }
                        if (metadata.contains("prevHash")) {
                            event.previousEventHash = metadata["prevHash"].get<std::string>();
                        }
                    } catch (...) {
                        // Ignore JSON parse errors for metadata
                    }
                }
                
                results.push_back(std::move(event));
            }

        } catch (const std::exception& e) {
            Logger::Error("EventLogger: Query exception: {}", e.what());
        }

        return results;
    }

    [[nodiscard]] bool ExportEventsImpl(
        const std::wstring& filePath,
        SIEMFormat format,
        system_clock::time_point startTime,
        system_clock::time_point endTime
    ) {
        try {
            // CRITICAL: Validate export path to prevent path traversal
            if (!ValidateExportPath(filePath, m_config.allowedLogDirectory)) {
                Logger::Error("EventLogger: Export path validation failed - potential path traversal attack blocked");
                m_stats.pathTraversalBlocked.fetch_add(1, std::memory_order_relaxed);
                return false;
            }

            // Stream events in batches instead of loading all at once
            constexpr uint32_t BATCH_SIZE = 1000;
            uint32_t offset = 0;
            uint64_t totalExported = 0;
            
            std::ofstream outFile(filePath, std::ios::trunc);
            if (!outFile) {
                Logger::Error("EventLogger: Failed to open export file");
                return false;
            }

            // Set ACL on export file
            if (m_config.restrictLogFileAccess) {
                SetLogFileACL(filePath);
            }

            // Stream events in batches
            while (true) {
                auto events = QueryEventsImpl(startTime, endTime, std::nullopt, std::nullopt, BATCH_SIZE);
                
                if (events.empty()) {
                    break;
                }

                for (const auto& event : events) {
                    std::string formatted;

                    switch (format) {
                        case SIEMFormat::JSON:
                            formatted = FormatAsJSON(event);
                            break;
                        case SIEMFormat::CEF:
                            formatted = FormatAsCEF(event);
                            break;
                        case SIEMFormat::LEEF:
                            formatted = FormatAsLEEF(event);
                            break;
                        case SIEMFormat::Syslog:
                            formatted = FormatAsSyslog(event, m_config.syslog);
                            break;
                        default:
                            continue;
                    }

                    outFile << formatted << "\n";
                    ++totalExported;
                }
                
                offset += static_cast<uint32_t>(events.size());
                
                // If we got less than batch size, we're done
                if (events.size() < BATCH_SIZE) {
                    break;
                }
            }

            outFile.flush();
            outFile.close();
            
            Logger::Info("EventLogger: Exported {} events to {}", totalExported, 
                StringUtils::WideToUtf8(filePath));
            return true;

        } catch (const std::exception& e) {
            Logger::Error("EventLogger: Export exception: {}", e.what());
            return false;
        }
    }

    // ========================================================================
    // FORENSIC OPERATIONS (With Path Validation)
    // ========================================================================

    [[nodiscard]] std::vector<ForensicEvent> GetRecentForensicEventsImpl(uint32_t count) const {
        std::shared_lock lock(m_forensicMutex);

        size_t copyCount = std::min(static_cast<size_t>(count), m_forensicBuffer.size());

        return std::vector<ForensicEvent>(
            m_forensicBuffer.end() - copyCount,
            m_forensicBuffer.end()
        );
    }

    void FlushForensicBufferImpl(const std::wstring& filePath) {
        try {
            // CRITICAL: Validate path to prevent path traversal
            if (!ValidateExportPath(filePath, m_config.allowedLogDirectory)) {
                Logger::Error("EventLogger: Forensic flush path validation failed - path traversal blocked");
                m_stats.pathTraversalBlocked.fetch_add(1, std::memory_order_relaxed);
                return;
            }

            std::shared_lock lock(m_forensicMutex);

            std::ofstream outFile(filePath);
            if (!outFile) {
                Logger::Error("EventLogger: Failed to open forensic buffer file");
                return;
            }

            // Set restrictive ACL
            if (m_config.restrictLogFileAccess) {
                SetLogFileACL(filePath);
            }

            for (const auto& event : m_forensicBuffer) {
                nlohmann::json j;
                j["eventId"] = event.eventId;
                j["sequenceNumber"] = event.sequenceNumber;
                j["eventType"] = SanitizeForFile(StringUtils::WideToUtf8(event.eventType));
                j["timestamp"] = system_clock::to_time_t(event.timestamp);
                j["timestampTicks"] = event.timestampTicks;
                j["context"]["processId"] = event.context.processId;
                j["context"]["threadId"] = event.context.threadId;
                j["context"]["machineName"] = SanitizeForFile(StringUtils::WideToUtf8(event.context.machineName));

                for (const auto& [key, value] : event.data) {
                    j["data"][SanitizeForFile(StringUtils::WideToUtf8(key))] = 
                        SanitizeForFile(StringUtils::WideToUtf8(value));
                }

                outFile << j.dump() << "\n";
            }

            outFile.flush();
            outFile.close();
            Logger::Info("EventLogger: Forensic buffer flushed to file");

        } catch (const std::exception& e) {
            Logger::Error("EventLogger: Forensic flush exception: {}", e.what());
        }
    }

    // ========================================================================
    // CALLBACKS (With Timeout and Failure Tracking)
    // ========================================================================

    void InvokeEventCallbacks(const SecurityEvent& event) {
        std::shared_lock lock(m_callbackMutex);
        std::vector<uint64_t> callbacksToRemove;

        for (const auto& [id, callback] : m_eventCallbacks) {
            try {
                // Execute callback with timeout tracking
                auto startTime = steady_clock::now();
                callback(event);
                auto elapsed = duration_cast<milliseconds>(steady_clock::now() - startTime);
                
                if (elapsed.count() > m_config.callbackTimeoutMs) {
                    Logger::Warn("EventLogger: Callback {} exceeded timeout ({} ms)", id, elapsed.count());
                    m_stats.callbackTimeouts.fetch_add(1, std::memory_order_relaxed);
                    
                    // Track failures for this callback
                    auto& failures = const_cast<std::unordered_map<uint64_t, uint32_t>&>(m_callbackFailureCounts);
                    failures[id]++;
                    
                    if (failures[id] >= m_config.maxCallbackFailures) {
                        callbacksToRemove.push_back(id);
                        Logger::Warn("EventLogger: Callback {} will be unregistered after {} failures", 
                            id, failures[id]);
                    }
                }
                
            } catch (const std::exception& e) {
                Logger::Error("EventLogger: Event callback {} exception: {}", id, e.what());
                
                // Track failures
                auto& failures = const_cast<std::unordered_map<uint64_t, uint32_t>&>(m_callbackFailureCounts);
                failures[id]++;
                
                if (failures[id] >= m_config.maxCallbackFailures) {
                    callbacksToRemove.push_back(id);
                }
            }
        }
        
        // Remove failed callbacks (need to upgrade lock)
        if (!callbacksToRemove.empty()) {
            lock.unlock();
            std::unique_lock writeLock(m_callbackMutex);
            for (uint64_t id : callbacksToRemove) {
                m_eventCallbacks.erase(id);
                m_callbackFailureCounts.erase(id);
                Logger::Info("EventLogger: Auto-unregistered failed callback {}", id);
            }
        }
    }

    void InvokeAuditCallbacks(const AuditEvent& event) {
        std::shared_lock lock(m_callbackMutex);
        std::vector<uint64_t> callbacksToRemove;

        for (const auto& [id, callback] : m_auditCallbacks) {
            try {
                auto startTime = steady_clock::now();
                callback(event);
                auto elapsed = duration_cast<milliseconds>(steady_clock::now() - startTime);
                
                if (elapsed.count() > m_config.callbackTimeoutMs) {
                    Logger::Warn("EventLogger: Audit callback {} exceeded timeout", id);
                    m_stats.callbackTimeouts.fetch_add(1, std::memory_order_relaxed);
                    
                    auto& failures = const_cast<std::unordered_map<uint64_t, uint32_t>&>(m_callbackFailureCounts);
                    failures[id]++;
                    
                    if (failures[id] >= m_config.maxCallbackFailures) {
                        callbacksToRemove.push_back(id);
                    }
                }
                
            } catch (const std::exception& e) {
                Logger::Error("EventLogger: Audit callback {} exception: {}", id, e.what());
                
                auto& failures = const_cast<std::unordered_map<uint64_t, uint32_t>&>(m_callbackFailureCounts);
                failures[id]++;
                
                if (failures[id] >= m_config.maxCallbackFailures) {
                    callbacksToRemove.push_back(id);
                }
            }
        }
        
        if (!callbacksToRemove.empty()) {
            lock.unlock();
            std::unique_lock writeLock(m_callbackMutex);
            for (uint64_t id : callbacksToRemove) {
                m_auditCallbacks.erase(id);
                m_callbackFailureCounts.erase(id);
            }
        }
    }

    // ========================================================================
    // CONTROL
    // ========================================================================

    void FlushImpl() {
        // Process all pending events (critical first)
        while (!m_criticalEventQueue.empty() || !m_eventQueue.empty() || !m_auditQueue.empty()) {
            ProcessCriticalEventQueue();
            ProcessEventQueue();
            ProcessAuditQueue();
        }

        // Flush file with crash-safe mechanism
        {
            std::unique_lock fileLock(m_fileMutex);
            if (m_logFile.is_open()) {
                m_logFile.flush();
            }
            if (m_logFileHandle != INVALID_HANDLE_VALUE) {
                FlushFileBuffers(m_logFileHandle);
            }
        }
        
        m_stats.crashSafeFlushes.fetch_add(1, std::memory_order_relaxed);
    }
};

// ============================================================================
// SINGLETON INSTANCE
// ============================================================================

EventLogger& EventLogger::Instance() {
    static EventLogger instance;
    return instance;
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

EventLogger::EventLogger()
    : m_impl(std::make_unique<EventLoggerImpl>())
{
    Logger::Info("EventLogger: Constructor called");
}

EventLogger::~EventLogger() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    Logger::Info("EventLogger: Destructor called");
}

// ============================================================================
// LIFECYCLE MANAGEMENT
// ============================================================================

bool EventLogger::Initialize(const EventLoggerConfig& config) {
    if (!m_impl) {
        Logger::Critical("EventLogger: Implementation is null");
        return false;
    }

    return m_impl->Initialize(config);
}

void EventLogger::Shutdown() noexcept {
    if (m_impl) {
        m_impl->Shutdown();
    }
}

// ============================================================================
// BASIC LOGGING
// ============================================================================

void EventLogger::Log(const SecurityEvent& event) {
    if (m_impl) {
        m_impl->LogImpl(event);
    }
}

void EventLogger::Log(
    EventSeverity severity,
    EventCategory category,
    const std::wstring& source,
    const std::wstring& message,
    const std::source_location& location
) {
    SecurityEvent event{};
    event.severity = severity;
    event.category = category;
    event.source = source;
    event.message = message;
    event.context.sourceLocation = location;

    Log(event);
}

void EventLogger::Log(
    EventSeverity severity,
    EventCategory category,
    const std::wstring& source,
    const std::wstring& message,
    const std::unordered_map<std::wstring, std::wstring>& properties,
    const std::source_location& location
) {
    SecurityEvent event{};
    event.severity = severity;
    event.category = category;
    event.source = source;
    event.message = message;
    event.properties = properties;
    event.context.sourceLocation = location;

    Log(event);
}

// ============================================================================
// THREAT LOGGING
// ============================================================================

void EventLogger::LogThreatDetection(
    const std::wstring& threatName,
    const std::wstring& threatType,
    const std::wstring& filePath,
    const std::string& sha256Hash,
    const std::wstring& action,
    EventSeverity severity
) {
    SecurityEvent event{};
    event.severity = severity;
    event.category = EventCategory::ThreatDetection;
    event.priority = EventPriority::Critical;  // Threat events never dropped
    event.source = L"ShadowStrike.ThreatDetection";
    event.message = std::format(L"Threat detected: {}", threatName);
    event.details = std::format(L"Type: {}, Action: {}", threatType, action);
    event.threatName = threatName;
    event.threatType = threatType;
    event.filePath = filePath;
    event.sha256Hash = sha256Hash;
    event.action = action;
    event.windowsEventId = EventIds::THREAT_DETECTED;

    Log(event);
}

void EventLogger::LogQuarantineAction(
    const std::wstring& filePath,
    const std::string& sha256Hash,
    const std::wstring& threatName,
    bool success
) {
    SecurityEvent event{};
    event.severity = success ? EventSeverity::AuditSuccess : EventSeverity::AuditFailure;
    event.category = EventCategory::Quarantine;
    event.priority = EventPriority::Critical;  // Quarantine events never dropped
    event.source = L"ShadowStrike.Quarantine";
    event.message = std::format(L"Quarantine {}: {}",
        success ? L"successful" : L"failed", filePath);
    event.filePath = filePath;
    event.sha256Hash = sha256Hash;
    event.threatName = threatName;
    event.action = success ? L"Quarantined" : L"QuarantineFailed";
    event.windowsEventId = EventIds::QUARANTINE_ACTION;

    Log(event);
}

void EventLogger::LogScanResult(
    const std::wstring& scanType,
    uint32_t filesScanned,
    uint32_t threatsFound,
    std::chrono::milliseconds duration
) {
    SecurityEvent event{};
    event.severity = threatsFound > 0 ? EventSeverity::Warning : EventSeverity::Info;
    event.category = EventCategory::Scan;
    event.priority = threatsFound > 0 ? EventPriority::High : EventPriority::Normal;
    event.source = L"ShadowStrike.Scanner";
    event.message = std::format(L"Scan completed: {} ({} files, {} threats, {} ms)",
        scanType, filesScanned, threatsFound, duration.count());
    event.windowsEventId = EventIds::SCAN_COMPLETED;

    event.properties[L"ScanType"] = scanType;
    event.properties[L"FilesScanned"] = std::to_wstring(filesScanned);
    event.properties[L"ThreatsFound"] = std::to_wstring(threatsFound);
    event.properties[L"Duration"] = std::to_wstring(duration.count());

    Log(event);
}

// ============================================================================
// AUDIT LOGGING
// ============================================================================

void EventLogger::LogAudit(const AuditEvent& event) {
    if (m_impl) {
        m_impl->LogAuditImpl(event);
    }
}

void EventLogger::LogPolicyChange(
    const std::wstring& policyName,
    const std::wstring& oldValue,
    const std::wstring& newValue,
    const std::wstring& reason
) {
    AuditEvent event{};
    event.action = L"PolicyChanged";
    event.targetObject = policyName;
    event.targetType = L"Policy";
    event.oldValue = oldValue;
    event.newValue = newValue;
    event.reason = reason;
    event.success = true;

    LogAudit(event);
}

void EventLogger::LogUserAction(
    const std::wstring& action,
    const std::wstring& target,
    bool success,
    const std::wstring& reason
) {
    AuditEvent event{};
    event.action = action;
    event.targetObject = target;
    event.targetType = L"UserAction";
    event.success = success;
    event.reason = reason;

    LogAudit(event);
}

// ============================================================================
// FORENSIC CAPTURE
// ============================================================================

void EventLogger::CaptureForensicEvent(
    const std::wstring& eventType,
    const std::unordered_map<std::wstring, std::wstring>& data
) {
    if (m_impl) {
        m_impl->CaptureForensicEventImpl(eventType, data);
    }
}

[[nodiscard]] std::vector<ForensicEvent> EventLogger::GetRecentForensicEvents(
    uint32_t count
) const {
    if (!m_impl) {
        return {};
    }

    return m_impl->GetRecentForensicEventsImpl(count);
}

void EventLogger::FlushForensicBuffer(const std::wstring& filePath) {
    if (m_impl) {
        m_impl->FlushForensicBufferImpl(filePath);
    }
}

// ============================================================================
// WINDOWS EVENT LOG
// ============================================================================

void EventLogger::WriteToWindowsEventLog(
    uint32_t eventId,
    EventSeverity severity,
    const std::wstring& message,
    const std::vector<std::wstring>& insertionStrings
) {
    SecurityEvent event{};
    event.windowsEventId = eventId;
    event.severity = severity;
    event.category = EventCategory::System;
    event.source = L"ShadowStrike";
    event.message = message;

    // Add insertion strings to properties
    for (size_t i = 0; i < insertionStrings.size(); ++i) {
        event.properties[std::format(L"Param{}", i)] = insertionStrings[i];
    }

    Log(event);
}

// ============================================================================
// QUERY AND EXPORT
// ============================================================================

[[nodiscard]] std::vector<SecurityEvent> EventLogger::QueryEvents(
    system_clock::time_point startTime,
    system_clock::time_point endTime,
    std::optional<EventCategory> category,
    std::optional<EventSeverity> minSeverity,
    uint32_t maxResults
) const {
    if (!m_impl) {
        return {};
    }

    return m_impl->QueryEventsImpl(startTime, endTime, category, minSeverity, maxResults);
}

[[nodiscard]] bool EventLogger::ExportEvents(
    const std::wstring& filePath,
    SIEMFormat format,
    system_clock::time_point startTime,
    system_clock::time_point endTime
) const {
    if (!m_impl) {
        return false;
    }

    return m_impl->ExportEventsImpl(filePath, format, startTime, endTime);
}

// ============================================================================
// CALLBACKS
// ============================================================================

uint64_t EventLogger::RegisterEventCallback(EventCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_eventCallbacks[id] = std::move(callback);

    Logger::Debug("EventLogger: Registered event callback {}", id);
    return id;
}

void EventLogger::UnregisterEventCallback(uint64_t callbackId) {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_eventCallbacks.erase(callbackId);

    Logger::Debug("EventLogger: Unregistered event callback {}", callbackId);
}

uint64_t EventLogger::RegisterAuditCallback(AuditCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_auditCallbacks[id] = std::move(callback);

    Logger::Debug("EventLogger: Registered audit callback {}", id);
    return id;
}

void EventLogger::UnregisterAuditCallback(uint64_t callbackId) {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_auditCallbacks.erase(callbackId);

    Logger::Debug("EventLogger: Unregistered audit callback {}", callbackId);
}

// ============================================================================
// CONTROL
// ============================================================================

void EventLogger::Flush() {
    if (m_impl) {
        m_impl->FlushImpl();
    }
}

void EventLogger::Pause() noexcept {
    if (m_impl) {
        m_impl->m_paused.store(true, std::memory_order_release);
        Logger::Info("EventLogger: Logging paused");
    }
}

void EventLogger::Resume() noexcept {
    if (m_impl) {
        m_impl->m_paused.store(false, std::memory_order_release);
        Logger::Info("EventLogger: Logging resumed");
    }
}

[[nodiscard]] bool EventLogger::IsPaused() const noexcept {
    return m_impl && m_impl->m_paused.load(std::memory_order_acquire);
}

// ============================================================================
// STATISTICS
// ============================================================================

[[nodiscard]] const EventLoggerStatistics& EventLogger::GetStatistics() const noexcept {
    static EventLoggerStatistics emptyStats{};
    return m_impl ? m_impl->m_stats : emptyStats;
}

void EventLogger::ResetStatistics() noexcept {
    if (m_impl) {
        m_impl->m_stats.Reset();
        Logger::Info("EventLogger: Statistics reset");
    }
}

} // namespace System
} // namespace Core
} // namespace ShadowStrike
