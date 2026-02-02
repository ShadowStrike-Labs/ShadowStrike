/**
 * ============================================================================
 * ShadowStrike Core System - EVENT LOGGER (The Chronicle)
 * ============================================================================
 *
 * @file EventLogger.hpp
 * @brief Enterprise-grade security event logging and audit trail system.
 *
 * This module provides comprehensive event logging capabilities including
 * Windows Event Log integration (ETW), internal audit trails, SIEM
 * forwarding, and forensic event capture.
 *
 * Key Capabilities:
 * =================
 * 1. EVENT LOG INTEGRATION
 *    - Windows Event Log writing
 *    - ETW (Event Tracing for Windows)
 *    - Custom event sources
 *    - Event categories/types
 *
 * 2. AUDIT TRAIL
 *    - Administrative action logging
 *    - Policy change tracking
 *    - User action recording
 *    - Chain of custody
 *
 * 3. SECURITY EVENTS
 *    - Threat detection events
 *    - Quarantine actions
 *    - Scan results
 *    - Real-time alerts
 *
 * 4. SIEM INTEGRATION
 *    - Syslog forwarding
 *    - CEF (Common Event Format)
 *    - LEEF (Log Event Extended Format)
 *    - JSON event streaming
 *
 * 5. FORENSIC CAPTURE
 *    - Pre-crash event buffer
 *    - High-fidelity timestamps
 *    - Process context
 *    - Stack traces
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see CrashHandler.hpp for crash-related logging
 * @see Database/LogDB.hpp for persistent storage
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/Logger.hpp"             // Base logging infrastructure
#include "../../Utils/StringUtils.hpp"        // String formatting
#include "../../Utils/SystemUtils.hpp"        // Machine info for events
#include "../../Utils/JSONUtils.hpp"          // JSON event formatting
#include "../../Database/LogDB.hpp"           // Persistent storage

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <shared_mutex>
#include <source_location>

namespace ShadowStrike {
namespace Core {
namespace System {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================
class EventLoggerImpl;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum EventSeverity
 * @brief Severity level of an event.
 */
enum class EventSeverity : uint8_t {
    Debug = 0,
    Info = 1,
    Warning = 2,
    Error = 3,
    Critical = 4,
    AuditSuccess = 5,
    AuditFailure = 6
};

/**
 * @enum EventCategory
 * @brief Category of security event.
 */
enum class EventCategory : uint16_t {
    System = 0,
    ThreatDetection = 1,
    Quarantine = 2,
    Remediation = 3,
    Scan = 4,
    RealTimeProtection = 5,
    NetworkProtection = 6,
    WebProtection = 7,
    EmailProtection = 8,
    ExploitPrevention = 9,
    PolicyChange = 10,
    UserAction = 11,
    ServiceControl = 12,
    DriverControl = 13,
    Update = 14,
    License = 15,
    Performance = 16,
    SelfProtection = 17,
    Forensic = 18
};

/**
 * @enum LogDestination
 * @brief Where to send log events.
 */
enum class LogDestination : uint8_t {
    None = 0,
    WindowsEventLog = 1 << 0,
    InternalDB = 1 << 1,
    File = 1 << 2,
    Syslog = 1 << 3,
    Console = 1 << 4,
    SIEM = 1 << 5,
    All = 0xFF
};

/**
 * @enum SIEMFormat
 * @brief SIEM output format.
 */
enum class SIEMFormat : uint8_t {
    JSON = 0,
    CEF = 1,                       // Common Event Format (ArcSight)
    LEEF = 2,                      // Log Event Extended Format (QRadar)
    Syslog = 3,                    // RFC 5424
    Custom = 4
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct EventContext
 * @brief Context information for an event.
 */
struct alignas(64) EventContext {
    uint32_t processId{ 0 };
    uint32_t threadId{ 0 };
    uint32_t sessionId{ 0 };
    std::wstring processName;
    std::wstring userName;
    std::wstring machineName;
    std::source_location sourceLocation;
};

/**
 * @enum EventPriority
 * @brief Priority level for queue management (high priority events never dropped).
 */
enum class EventPriority : uint8_t {
    Low = 0,        // Debug, Info
    Normal = 1,     // Warning
    High = 2,       // Error, Scan results
    Critical = 3    // Critical, ThreatDetection, Audit - NEVER dropped
};

/**
 * @struct SecurityEvent
 * @brief Complete security event record with integrity protection.
 */
struct alignas(64) SecurityEvent {
    // Identity
    uint64_t eventId{ 0 };
    uint64_t sequenceNumber{ 0 };     // Monotonic sequence for ordering
    uint32_t windowsEventId{ 0 };     // For Windows Event Log
    std::wstring eventGuid;
    
    // Classification
    EventSeverity severity{ EventSeverity::Info };
    EventCategory category{ EventCategory::System };
    EventPriority priority{ EventPriority::Normal };
    std::wstring subcategory;
    
    // Content
    std::wstring source;              // e.g., "ShadowStrike.RealTimeProtection"
    std::wstring message;
    std::wstring details;
    
    // Threat-specific
    std::wstring threatName;
    std::wstring threatType;
    std::wstring filePath;
    std::string sha256Hash;
    std::wstring action;              // e.g., "Quarantined", "Blocked"
    
    // Context
    EventContext context;
    
    // Timing (high resolution)
    std::chrono::system_clock::time_point timestamp;
    std::chrono::steady_clock::time_point monotonicTime;
    uint64_t highResolutionTicks{ 0 };   // QueryPerformanceCounter ticks
    uint64_t highResolutionFrequency{ 0 }; // QPC frequency for conversion
    
    // Additional data
    std::unordered_map<std::wstring, std::wstring> properties;
    std::vector<uint8_t> rawData;
    
    // Correlation
    std::wstring correlationId;       // For related events
    std::wstring parentEventId;
    
    // Integrity (tamper protection)
    std::string hmacSignature;        // HMAC-SHA256 of event content
    std::string previousEventHash;    // Hash chain to previous event
};

/**
 * @struct AuditEvent
 * @brief Administrative audit event.
 */
struct alignas(128) AuditEvent {
    uint64_t eventId{ 0 };
    std::wstring action;              // e.g., "PolicyChanged", "ServiceStopped"
    std::wstring targetObject;        // What was affected
    std::wstring targetType;          // Type of target
    std::wstring oldValue;
    std::wstring newValue;
    std::wstring reason;
    EventContext context;
    std::chrono::system_clock::time_point timestamp;
    bool success{ true };
};

/**
 * @struct ForensicEvent
 * @brief High-fidelity forensic event.
 */
struct alignas(128) ForensicEvent {
    uint64_t eventId{ 0 };
    uint64_t sequenceNumber{ 0 };
    std::wstring eventType;
    std::chrono::system_clock::time_point timestamp;
    uint64_t timestampTicks{ 0 };     // High-resolution
    EventContext context;
    std::wstring stackTrace;
    std::vector<uint8_t> memoryDump;
    std::unordered_map<std::wstring, std::wstring> data;
};

/**
 * @struct SyslogConfig
 * @brief Syslog forwarding configuration.
 */
struct alignas(32) SyslogConfig {
    std::wstring serverAddress;
    uint16_t port{ 514 };
    bool useTLS{ false };
    bool useTCP{ true };              // TCP vs UDP
    std::wstring facility;
    std::wstring appName{ L"ShadowStrike" };
};

/**
 * @struct SIEMConfig
 * @brief SIEM integration configuration.
 */
struct alignas(64) SIEMConfig {
    bool enabled{ false };
    SIEMFormat format{ SIEMFormat::JSON };
    std::wstring endpoint;
    std::wstring apiKey;
    uint32_t batchSize{ 100 };
    uint32_t flushIntervalMs{ 5000 };
    bool compressPayload{ true };
};

/**
 * @struct EventLoggerConfig
 * @brief Configuration for event logger.
 */
struct alignas(128) EventLoggerConfig {
    // Destinations
    uint8_t destinations{ static_cast<uint8_t>(LogDestination::WindowsEventLog) |
                          static_cast<uint8_t>(LogDestination::InternalDB) };
    
    // Filtering
    EventSeverity minimumSeverity{ EventSeverity::Info };
    std::vector<EventCategory> enabledCategories;
    
    // Windows Event Log
    std::wstring eventSourceName{ L"ShadowStrike" };
    std::wstring eventLogName{ L"Application" };
    
    // File logging
    std::wstring logFilePath;
    uint64_t maxLogFileSizeMB{ 100 };
    uint32_t maxLogFiles{ 10 };
    bool compressOldLogs{ true };
    std::wstring allowedLogDirectory{ L"C:\\ProgramData\\ShadowStrike\\Logs" };
    
    // Syslog
    SyslogConfig syslog;
    
    // SIEM
    SIEMConfig siem;
    
    // Forensic
    bool enableForensicCapture{ true };
    uint32_t forensicBufferSize{ 10000 };
    uint64_t forensicBufferMaxMemoryMB{ 256 };  // Memory cap in addition to count
    
    // Performance
    uint32_t asyncQueueSize{ 100000 };
    uint32_t workerThreads{ 2 };
    uint32_t criticalQueueReserve{ 10000 };     // Reserved slots for critical events
    
    // Security - Integrity
    bool enableTamperProtection{ true };
    std::vector<uint8_t> hmacKey;               // 32-byte key for HMAC-SHA256
    bool enableHashChain{ true };               // Chain events cryptographically
    
    // Security - Access Control
    bool restrictLogFileAccess{ true };         // Set ACL to SYSTEM+Admins only
    
    // Security - Field Limits (prevent memory exhaustion)
    uint32_t maxFieldLengthBytes{ 4096 };       // Max length per string field
    uint32_t maxPropertiesCount{ 100 };         // Max properties per event
    
    // Compliance
    bool enableCrashSafeLogging{ true };        // FlushFileBuffers after critical events
    bool secureDeleteRotatedLogs{ false };      // Overwrite before delete
    
    // Callback safety
    uint32_t callbackTimeoutMs{ 1000 };         // Max time for callback execution
    uint32_t maxCallbackFailures{ 5 };          // Failures before auto-unregister
    
    static EventLoggerConfig CreateDefault() noexcept;
    static EventLoggerConfig CreateEnterprise() noexcept;
    static EventLoggerConfig CreateMinimal() noexcept;
};

/**
 * @struct EventLoggerStatistics
 * @brief Runtime statistics with integrity metrics.
 */
struct alignas(128) EventLoggerStatistics {
    std::atomic<uint64_t> eventsLogged{ 0 };
    std::atomic<uint64_t> eventsDropped{ 0 };
    std::atomic<uint64_t> criticalEventsDropped{ 0 };   // Should always be 0
    std::atomic<uint64_t> windowsEventsWritten{ 0 };
    std::atomic<uint64_t> syslogEventsForwarded{ 0 };
    std::atomic<uint64_t> siemEventsForwarded{ 0 };
    std::atomic<uint64_t> dbEventsWritten{ 0 };
    std::atomic<uint64_t> auditEventsLogged{ 0 };
    std::atomic<uint64_t> forensicEventsCaptures{ 0 };
    std::atomic<uint64_t> logRotations{ 0 };
    std::atomic<uint64_t> integritySignaturesGenerated{ 0 };
    std::atomic<uint64_t> crashSafeFlushes{ 0 };
    std::atomic<uint64_t> callbackTimeouts{ 0 };
    std::atomic<uint64_t> sanitizationApplied{ 0 };     // Injection attempts blocked
    std::atomic<uint64_t> pathTraversalBlocked{ 0 };
    std::atomic<uint64_t> queueHighWaterMark{ 0 };      // Peak queue size
    std::atomic<uint64_t> forensicBufferMemoryBytes{ 0 };
    
    void Reset() noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using EventCallback = std::function<void(const SecurityEvent& event)>;
using AuditCallback = std::function<void(const AuditEvent& event)>;

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class EventLogger
 * @brief Enterprise-grade security event logging system.
 *
 * Thread-safe singleton providing comprehensive event logging
 * with multi-destination support and SIEM integration.
 */
class EventLogger {
public:
    /**
     * @brief Gets singleton instance.
     */
    static EventLogger& Instance();
    
    /**
     * @brief Initializes event logger.
     */
    bool Initialize(const EventLoggerConfig& config);
    
    /**
     * @brief Shuts down event logger (flushes pending events).
     */
    void Shutdown() noexcept;
    
    // ========================================================================
    // BASIC LOGGING
    // ========================================================================
    
    /**
     * @brief Logs a security event.
     */
    void Log(const SecurityEvent& event);
    
    /**
     * @brief Logs a simple message.
     */
    void Log(
        EventSeverity severity,
        EventCategory category,
        const std::wstring& source,
        const std::wstring& message,
        const std::source_location& location = std::source_location::current());
    
    /**
     * @brief Logs with properties.
     */
    void Log(
        EventSeverity severity,
        EventCategory category,
        const std::wstring& source,
        const std::wstring& message,
        const std::unordered_map<std::wstring, std::wstring>& properties,
        const std::source_location& location = std::source_location::current());
    
    // ========================================================================
    // THREAT LOGGING
    // ========================================================================
    
    /**
     * @brief Logs a threat detection event.
     */
    void LogThreatDetection(
        const std::wstring& threatName,
        const std::wstring& threatType,
        const std::wstring& filePath,
        const std::string& sha256Hash,
        const std::wstring& action,
        EventSeverity severity = EventSeverity::Warning);
    
    /**
     * @brief Logs a quarantine action.
     */
    void LogQuarantineAction(
        const std::wstring& filePath,
        const std::string& sha256Hash,
        const std::wstring& threatName,
        bool success);
    
    /**
     * @brief Logs a scan result.
     */
    void LogScanResult(
        const std::wstring& scanType,
        uint32_t filesScanned,
        uint32_t threatsFound,
        std::chrono::milliseconds duration);
    
    // ========================================================================
    // AUDIT LOGGING
    // ========================================================================
    
    /**
     * @brief Logs an audit event.
     */
    void LogAudit(const AuditEvent& event);
    
    /**
     * @brief Logs a policy change.
     */
    void LogPolicyChange(
        const std::wstring& policyName,
        const std::wstring& oldValue,
        const std::wstring& newValue,
        const std::wstring& reason);
    
    /**
     * @brief Logs a user action.
     */
    void LogUserAction(
        const std::wstring& action,
        const std::wstring& target,
        bool success,
        const std::wstring& reason = L"");
    
    // ========================================================================
    // FORENSIC CAPTURE
    // ========================================================================
    
    /**
     * @brief Captures a forensic event.
     */
    void CaptureForensicEvent(
        const std::wstring& eventType,
        const std::unordered_map<std::wstring, std::wstring>& data);
    
    /**
     * @brief Gets recent forensic events (for crash dumps).
     */
    [[nodiscard]] std::vector<ForensicEvent> GetRecentForensicEvents(
        uint32_t count = 100) const;
    
    /**
     * @brief Flushes forensic buffer to file.
     */
    void FlushForensicBuffer(const std::wstring& filePath);
    
    // ========================================================================
    // WINDOWS EVENT LOG
    // ========================================================================
    
    /**
     * @brief Writes directly to Windows Event Log.
     */
    void WriteToWindowsEventLog(
        uint32_t eventId,
        EventSeverity severity,
        const std::wstring& message,
        const std::vector<std::wstring>& insertionStrings = {});
    
    // ========================================================================
    // QUERY AND EXPORT
    // ========================================================================
    
    /**
     * @brief Queries events by filter.
     */
    [[nodiscard]] std::vector<SecurityEvent> QueryEvents(
        std::chrono::system_clock::time_point startTime,
        std::chrono::system_clock::time_point endTime,
        std::optional<EventCategory> category = std::nullopt,
        std::optional<EventSeverity> minSeverity = std::nullopt,
        uint32_t maxResults = 1000) const;
    
    /**
     * @brief Exports events to file.
     */
    [[nodiscard]] bool ExportEvents(
        const std::wstring& filePath,
        SIEMFormat format,
        std::chrono::system_clock::time_point startTime,
        std::chrono::system_clock::time_point endTime) const;
    
    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    /**
     * @brief Registers callback for events.
     */
    uint64_t RegisterEventCallback(EventCallback callback);
    
    /**
     * @brief Unregisters event callback.
     */
    void UnregisterEventCallback(uint64_t callbackId);
    
    /**
     * @brief Registers callback for audit events.
     */
    uint64_t RegisterAuditCallback(AuditCallback callback);
    
    /**
     * @brief Unregisters audit callback.
     */
    void UnregisterAuditCallback(uint64_t callbackId);
    
    // ========================================================================
    // CONTROL
    // ========================================================================
    
    /**
     * @brief Flushes all pending events.
     */
    void Flush();
    
    /**
     * @brief Pauses logging (events are queued).
     */
    void Pause() noexcept;
    
    /**
     * @brief Resumes logging.
     */
    void Resume() noexcept;
    
    /**
     * @brief Checks if logging is paused.
     */
    [[nodiscard]] bool IsPaused() const noexcept;
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] const EventLoggerStatistics& GetStatistics() const noexcept;
    void ResetStatistics() noexcept;

private:
    EventLogger();
    ~EventLogger();
    
    EventLogger(const EventLogger&) = delete;
    EventLogger& operator=(const EventLogger&) = delete;
    
    std::unique_ptr<EventLoggerImpl> m_impl;
};

// ============================================================================
// CONVENIENCE MACROS
// ============================================================================

#define SS_LOG_DEBUG(category, source, msg) \
    ShadowStrike::Core::System::EventLogger::Instance().Log( \
        ShadowStrike::Core::System::EventSeverity::Debug, \
        ShadowStrike::Core::System::EventCategory::category, \
        L##source, L##msg)

#define SS_LOG_INFO(category, source, msg) \
    ShadowStrike::Core::System::EventLogger::Instance().Log( \
        ShadowStrike::Core::System::EventSeverity::Info, \
        ShadowStrike::Core::System::EventCategory::category, \
        L##source, L##msg)

#define SS_LOG_WARNING(category, source, msg) \
    ShadowStrike::Core::System::EventLogger::Instance().Log( \
        ShadowStrike::Core::System::EventSeverity::Warning, \
        ShadowStrike::Core::System::EventCategory::category, \
        L##source, L##msg)

#define SS_LOG_ERROR(category, source, msg) \
    ShadowStrike::Core::System::EventLogger::Instance().Log( \
        ShadowStrike::Core::System::EventSeverity::Error, \
        ShadowStrike::Core::System::EventCategory::category, \
        L##source, L##msg)

#define SS_LOG_CRITICAL(category, source, msg) \
    ShadowStrike::Core::System::EventLogger::Instance().Log( \
        ShadowStrike::Core::System::EventSeverity::Critical, \
        ShadowStrike::Core::System::EventCategory::category, \
        L##source, L##msg)

}  // namespace System
}  // namespace Core
}  // namespace ShadowStrike
