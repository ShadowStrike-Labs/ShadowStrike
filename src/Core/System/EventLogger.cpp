/**
 * @file EventLogger.cpp
 * @brief Enterprise implementation of security event logging and audit trail system.
 *
 * The Chronicle of ShadowStrike NGAV - provides comprehensive event logging with
 * Windows Event Log integration, SIEM forwarding, forensic capture, and audit trails.
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
#include "../../Database/LogDB.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <chrono>
#include <format>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <deque>
#include <queue>
#include <thread>
#include <condition_variable>

// ============================================================================
// WINDOWS INCLUDES
// ============================================================================
#ifdef _WIN32
#  include <Windows.h>
#  include <evntprov.h>
#  pragma comment(lib, "advapi32.lib")
#endif

namespace ShadowStrike {
namespace Core {
namespace System {

using namespace std::chrono;
using namespace Utils;
namespace fs = std::filesystem;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

namespace {

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

/**
 * @brief Format event as CEF (Common Event Format).
 */
[[nodiscard]] std::string FormatAsCEF(const SecurityEvent& event) {
    // CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    std::ostringstream oss;

    oss << "CEF:0|ShadowStrike|NGAV|3.0.0|"
        << event.windowsEventId << "|"
        << StringUtils::WideToUtf8(event.message) << "|"
        << static_cast<int>(event.severity) << "|";

    // Extensions
    oss << "cat=" << StringUtils::WideToUtf8(CategoryToString(event.category)) << " ";
    oss << "shost=" << StringUtils::WideToUtf8(event.context.machineName) << " ";
    oss << "suser=" << StringUtils::WideToUtf8(event.context.userName) << " ";
    oss << "sproc=" << StringUtils::WideToUtf8(event.context.processName) << " ";
    oss << "spid=" << event.context.processId << " ";

    if (!event.filePath.empty()) {
        oss << "fname=" << StringUtils::WideToUtf8(event.filePath) << " ";
    }

    if (!event.sha256Hash.empty()) {
        oss << "fileHash=" << event.sha256Hash << " ";
    }

    if (!event.threatName.empty()) {
        oss << "cs1Label=ThreatName cs1=" << StringUtils::WideToUtf8(event.threatName) << " ";
    }

    return oss.str();
}

/**
 * @brief Format event as LEEF (Log Event Extended Format).
 */
[[nodiscard]] std::string FormatAsLEEF(const SecurityEvent& event) {
    // LEEF:Version|Vendor|Product|Version|EventID|Key=Value pairs
    std::ostringstream oss;

    oss << "LEEF:2.0|ShadowStrike|NGAV|3.0.0|"
        << event.windowsEventId << "\t";

    oss << "cat=" << StringUtils::WideToUtf8(CategoryToString(event.category)) << "\t";
    oss << "sev=" << StringUtils::WideToUtf8(SeverityToString(event.severity)) << "\t";
    oss << "msg=" << StringUtils::WideToUtf8(event.message) << "\t";
    oss << "src=" << StringUtils::WideToUtf8(event.source) << "\t";
    oss << "shost=" << StringUtils::WideToUtf8(event.context.machineName) << "\t";
    oss << "suser=" << StringUtils::WideToUtf8(event.context.userName) << "\t";

    if (!event.filePath.empty()) {
        oss << "filePath=" << StringUtils::WideToUtf8(event.filePath) << "\t";
    }

    if (!event.sha256Hash.empty()) {
        oss << "fileHash=" << event.sha256Hash << "\t";
    }

    if (!event.threatName.empty()) {
        oss << "threat=" << StringUtils::WideToUtf8(event.threatName) << "\t";
    }

    return oss.str();
}

/**
 * @brief Format event as Syslog (RFC 5424).
 */
[[nodiscard]] std::string FormatAsSyslog(const SecurityEvent& event, const SyslogConfig& config) {
    // <Priority>Version Timestamp Hostname App-Name ProcID MsgID Structured-Data Message
    std::ostringstream oss;

    // Priority = Facility * 8 + Severity
    int facility = 16; // local0
    int syslogSeverity = std::min(static_cast<int>(event.severity), 7);
    int priority = facility * 8 + syslogSeverity;

    oss << "<" << priority << ">1 ";

    // Timestamp (ISO 8601)
    auto timeT = system_clock::to_time_t(event.timestamp);
    std::tm tm;
    gmtime_s(&tm, &timeT);
    char timeBuffer[64];
    strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%dT%H:%M:%SZ", &tm);
    oss << timeBuffer << " ";

    // Hostname
    oss << StringUtils::WideToUtf8(event.context.machineName) << " ";

    // App-Name
    oss << StringUtils::WideToUtf8(config.appName) << " ";

    // ProcID
    oss << event.context.processId << " ";

    // MsgID
    oss << event.windowsEventId << " ";

    // Structured-Data
    oss << "[shadowstrike@12345 ";
    oss << "category=\"" << StringUtils::WideToUtf8(CategoryToString(event.category)) << "\" ";
    oss << "severity=\"" << StringUtils::WideToUtf8(SeverityToString(event.severity)) << "\"";
    oss << "] ";

    // Message
    oss << StringUtils::WideToUtf8(event.message);

    return oss.str();
}

} // anonymous namespace

// ============================================================================
// EventLoggerConfig FACTORY METHODS
// ============================================================================

EventLoggerConfig EventLoggerConfig::CreateDefault() noexcept {
    return EventLoggerConfig{};
}

EventLoggerConfig EventLoggerConfig::CreateEnterprise() noexcept {
    EventLoggerConfig config;
    config.destinations = static_cast<uint8_t>(LogDestination::All);
    config.minimumSeverity = EventSeverity::Debug;
    config.enableForensicCapture = true;
    config.forensicBufferSize = 50000;
    config.asyncQueueSize = 500000;
    config.workerThreads = 4;
    config.maxLogFileSizeMB = 500;
    config.maxLogFiles = 50;
    config.compressOldLogs = true;

    config.siem.enabled = true;
    config.siem.format = SIEMFormat::JSON;
    config.siem.batchSize = 1000;
    config.siem.flushIntervalMs = 1000;
    config.siem.compressPayload = true;

    return config;
}

EventLoggerConfig EventLoggerConfig::CreateMinimal() noexcept {
    EventLoggerConfig config;
    config.destinations = static_cast<uint8_t>(LogDestination::WindowsEventLog);
    config.minimumSeverity = EventSeverity::Warning;
    config.enableForensicCapture = false;
    config.asyncQueueSize = 10000;
    config.workerThreads = 1;

    return config;
}

// ============================================================================
// EventLoggerStatistics METHODS
// ============================================================================

void EventLoggerStatistics::Reset() noexcept {
    eventsLogged.store(0, std::memory_order_relaxed);
    eventsDropped.store(0, std::memory_order_relaxed);
    windowsEventsWritten.store(0, std::memory_order_relaxed);
    syslogEventsForwarded.store(0, std::memory_order_relaxed);
    siemEventsForwarded.store(0, std::memory_order_relaxed);
    dbEventsWritten.store(0, std::memory_order_relaxed);
    auditEventsLogged.store(0, std::memory_order_relaxed);
    forensicEventsCaptures.store(0, std::memory_order_relaxed);
}

// ============================================================================
// PIMPL IMPLEMENTATION
// ============================================================================

/**
 * @brief Private implementation class for EventLogger.
 */
class EventLogger::EventLoggerImpl {
public:
    // ========================================================================
    // MEMBERS
    // ========================================================================

    // Thread safety
    mutable std::shared_mutex m_configMutex;
    mutable std::shared_mutex m_eventQueueMutex;
    mutable std::shared_mutex m_forensicMutex;
    mutable std::shared_mutex m_callbackMutex;
    std::mutex m_windowsEventMutex;
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

    // Event queues
    std::deque<SecurityEvent> m_eventQueue;
    std::deque<AuditEvent> m_auditQueue;
    std::deque<ForensicEvent> m_forensicBuffer;

    // Windows Event Log
    HANDLE m_eventSourceHandle{nullptr};

    // Callbacks
    std::atomic<uint64_t> m_nextCallbackId{1};
    std::unordered_map<uint64_t, EventCallback> m_eventCallbacks;
    std::unordered_map<uint64_t, AuditCallback> m_auditCallbacks;

    // Worker threads
    std::vector<std::jthread> m_workerThreads;

    // File logging
    std::ofstream m_logFile;
    uint64_t m_currentLogFileSize{0};
    uint32_t m_currentLogFileIndex{0};

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
            Logger::Info("EventLogger::Impl: Initializing");

            // Store configuration
            m_config = config;

            // Reset statistics
            m_stats.Reset();

            // Initialize Windows Event Log source
            if (config.destinations & static_cast<uint8_t>(LogDestination::WindowsEventLog)) {
                InitializeWindowsEventLog();
            }

            // Initialize file logging
            if (config.destinations & static_cast<uint8_t>(LogDestination::File)) {
                InitializeFileLogging();
            }

            // Start worker threads
            StartWorkerThreads();

            m_initialized.store(true, std::memory_order_release);
            Logger::Info("EventLogger::Impl: Initialization complete");

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

        // Close log file
        if (m_logFile.is_open()) {
            m_logFile.close();
        }

        // Clear callbacks
        {
            std::unique_lock cbLock(m_callbackMutex);
            m_eventCallbacks.clear();
            m_auditCallbacks.clear();
        }

        m_initialized.store(false, std::memory_order_release);
        Logger::Info("EventLogger::Impl: Shutdown complete");
    }

    void InitializeWindowsEventLog() {
        try {
            m_eventSourceHandle = RegisterEventSourceW(
                nullptr,
                m_config.eventSourceName.c_str()
            );

            if (!m_eventSourceHandle) {
                Logger::Error("EventLogger: Failed to register event source: {}", GetLastError());
            } else {
                Logger::Info("EventLogger: Windows Event Log source registered");
            }

        } catch (const std::exception& e) {
            Logger::Error("EventLogger: Windows Event Log init exception: {}", e.what());
        }
    }

    void InitializeFileLogging() {
        try {
            if (m_config.logFilePath.empty()) {
                m_config.logFilePath = L"C:\\ProgramData\\ShadowStrike\\Logs\\events.log";
            }

            // Create directory if needed
            fs::path logPath(m_config.logFilePath);
            if (!fs::exists(logPath.parent_path())) {
                fs::create_directories(logPath.parent_path());
            }

            // Open log file
            m_logFile.open(m_config.logFilePath, std::ios::app);
            if (!m_logFile) {
                Logger::Error("EventLogger: Failed to open log file: {}",
                    StringUtils::WideToUtf8(m_config.logFilePath));
            } else {
                Logger::Info("EventLogger: File logging initialized");
            }

        } catch (const std::exception& e) {
            Logger::Error("EventLogger: File logging init exception: {}", e.what());
        }
    }

    void StartWorkerThreads() {
        for (uint32_t i = 0; i < m_config.workerThreads; ++i) {
            m_workerThreads.emplace_back([this](std::stop_token stoken) {
                WorkerThread(stoken);
            });
        }

        Logger::Info("EventLogger: Started {} worker threads", m_config.workerThreads);
    }

    // ========================================================================
    // LOGGING IMPLEMENTATION
    // ========================================================================

    void LogImpl(SecurityEvent event) {
        try {
            // Check if paused
            if (m_paused.load(std::memory_order_acquire)) {
                // Queue event even when paused
            }

            // Check severity filter
            if (event.severity < m_config.minimumSeverity) {
                return;
            }

            // Assign event ID
            event.eventId = m_nextEventId.fetch_add(1, std::memory_order_relaxed);
            event.timestamp = system_clock::now();
            event.monotonicTime = steady_clock::now();

            // Generate GUID if empty
            if (event.eventGuid.empty()) {
                event.eventGuid = GenerateEventGuid();
            }

            // Fill in context if empty
            if (event.context.processId == 0) {
                event.context.processId = GetCurrentProcessId();
                event.context.threadId = GetCurrentThreadId();
                event.context.machineName = SystemUtils::GetMachineName();
                event.context.userName = SystemUtils::GetCurrentUserName();
            }

            // Invoke callbacks
            InvokeEventCallbacks(event);

            // Queue for async processing
            {
                std::unique_lock lock(m_eventQueueMutex);

                if (m_eventQueue.size() >= m_config.asyncQueueSize) {
                    m_eventQueue.pop_front();
                    m_stats.eventsDropped.fetch_add(1, std::memory_order_relaxed);
                }

                m_eventQueue.push_back(std::move(event));
            }

            m_stats.eventsLogged.fetch_add(1, std::memory_order_relaxed);
            m_workerCV.notify_one();

        } catch (const std::exception& e) {
            Logger::Error("EventLogger: Log exception: {}", e.what());
        }
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
            event.eventType = eventType;
            event.timestamp = system_clock::now();
            event.timestampTicks = steady_clock::now().time_since_epoch().count();
            event.data = data;

            // Fill context
            event.context.processId = GetCurrentProcessId();
            event.context.threadId = GetCurrentThreadId();
            event.context.machineName = SystemUtils::GetMachineName();

            {
                std::unique_lock lock(m_forensicMutex);

                if (m_forensicBuffer.size() >= m_config.forensicBufferSize) {
                    m_forensicBuffer.pop_front();
                }

                m_forensicBuffer.push_back(std::move(event));
            }

            m_stats.forensicEventsCaptures.fetch_add(1, std::memory_order_relaxed);

        } catch (const std::exception& e) {
            Logger::Error("EventLogger: Forensic capture exception: {}", e.what());
        }
    }

    // ========================================================================
    // WORKER THREAD
    // ========================================================================

    void WorkerThread(std::stop_token stoken) {
        Logger::Debug("EventLogger: Worker thread started");

        while (!stoken.stop_requested() && !m_shutdown.load(std::memory_order_acquire)) {
            try {
                // Wait for events
                std::unique_lock lock(m_workerMutex);
                m_workerCV.wait_for(lock, milliseconds(1000), [this, &stoken] {
                    return stoken.stop_requested() ||
                           m_shutdown.load(std::memory_order_acquire) ||
                           !m_eventQueue.empty() ||
                           !m_auditQueue.empty();
                });

                // Process security events
                ProcessEventQueue();

                // Process audit events
                ProcessAuditQueue();

            } catch (const std::exception& e) {
                Logger::Error("EventLogger: Worker thread exception: {}", e.what());
            }
        }

        Logger::Debug("EventLogger: Worker thread stopped");
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

        // File
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
        secEvent.severity = event.success ? EventSeverity::AuditSuccess : EventSeverity::AuditFailure;
        secEvent.category = EventCategory::PolicyChange;
        secEvent.source = L"ShadowStrike.Audit";
        secEvent.message = std::format(L"Audit: {} on {}", event.action, event.targetObject);
        secEvent.details = std::format(L"Old: {}, New: {}, Reason: {}",
            event.oldValue, event.newValue, event.reason);
        secEvent.context = event.context;
        secEvent.timestamp = event.timestamp;

        ProcessEvent(secEvent);
    }

    // ========================================================================
    // DESTINATION WRITERS
    // ========================================================================

    void WriteToWindowsEventLogImpl(const SecurityEvent& event) {
        if (!m_eventSourceHandle) {
            return;
        }

        try {
            std::unique_lock lock(m_windowsEventMutex);

            WORD eventType = SeverityToEventType(event.severity);
            DWORD eventId = event.windowsEventId != 0 ? event.windowsEventId : 1000;

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

            // Store event (simplified - LogDB would have specific methods)
            // logDB.InsertEvent(event);

            m_stats.dbEventsWritten.fetch_add(1, std::memory_order_relaxed);

        } catch (const std::exception& e) {
            Logger::Error("EventLogger: DB write exception: {}", e.what());
        }
    }

    void WriteToFileImpl(const SecurityEvent& event) {
        try {
            if (!m_logFile.is_open()) {
                return;
            }

            // Format: [Timestamp] [Severity] [Category] [Source] Message
            auto timeT = system_clock::to_time_t(event.timestamp);
            std::tm tm;
            localtime_s(&tm, &timeT);

            char timeBuffer[64];
            strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M:%S", &tm);

            m_logFile << "[" << timeBuffer << "] "
                      << "[" << StringUtils::WideToUtf8(SeverityToString(event.severity)) << "] "
                      << "[" << StringUtils::WideToUtf8(CategoryToString(event.category)) << "] "
                      << "[" << StringUtils::WideToUtf8(event.source) << "] "
                      << StringUtils::WideToUtf8(event.message);

            if (!event.details.empty()) {
                m_logFile << " - " << StringUtils::WideToUtf8(event.details);
            }

            m_logFile << std::endl;

            m_currentLogFileSize += 256; // Approximate

            // Check for rotation
            if (m_currentLogFileSize >= m_config.maxLogFileSizeMB * 1024 * 1024) {
                RotateLogFile();
            }

        } catch (const std::exception& e) {
            Logger::Error("EventLogger: File write exception: {}", e.what());
        }
    }

    void ForwardToSyslogImpl(const SecurityEvent& event) {
        try {
            std::string syslogMessage = FormatAsSyslog(event, m_config.syslog);

            // Would send via NetworkUtils
            // NetworkUtils::SendUDP(m_config.syslog.serverAddress, m_config.syslog.port, syslogMessage);

            m_stats.syslogEventsForwarded.fetch_add(1, std::memory_order_relaxed);

        } catch (const std::exception& e) {
            Logger::Error("EventLogger: Syslog forward exception: {}", e.what());
        }
    }

    void ForwardToSIEMImpl(const SecurityEvent& event) {
        try {
            if (!m_config.siem.enabled) {
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

            // Would send to SIEM endpoint
            // NetworkUtils::SendHTTPS(m_config.siem.endpoint, formattedEvent, m_config.siem.apiKey);

            m_stats.siemEventsForwarded.fetch_add(1, std::memory_order_relaxed);

        } catch (const std::exception& e) {
            Logger::Error("EventLogger: SIEM forward exception: {}", e.what());
        }
    }

    [[nodiscard]] std::string FormatAsJSON(const SecurityEvent& event) const {
        nlohmann::json j;

        j["eventId"] = event.eventId;
        j["eventGuid"] = StringUtils::WideToUtf8(event.eventGuid);
        j["timestamp"] = system_clock::to_time_t(event.timestamp);
        j["severity"] = StringUtils::WideToUtf8(SeverityToString(event.severity));
        j["category"] = StringUtils::WideToUtf8(CategoryToString(event.category));
        j["source"] = StringUtils::WideToUtf8(event.source);
        j["message"] = StringUtils::WideToUtf8(event.message);

        if (!event.details.empty()) {
            j["details"] = StringUtils::WideToUtf8(event.details);
        }

        if (!event.threatName.empty()) {
            j["threatName"] = StringUtils::WideToUtf8(event.threatName);
            j["threatType"] = StringUtils::WideToUtf8(event.threatType);
        }

        if (!event.filePath.empty()) {
            j["filePath"] = StringUtils::WideToUtf8(event.filePath);
        }

        if (!event.sha256Hash.empty()) {
            j["sha256"] = event.sha256Hash;
        }

        j["context"]["processId"] = event.context.processId;
        j["context"]["processName"] = StringUtils::WideToUtf8(event.context.processName);
        j["context"]["userName"] = StringUtils::WideToUtf8(event.context.userName);
        j["context"]["machineName"] = StringUtils::WideToUtf8(event.context.machineName);

        return j.dump();
    }

    void RotateLogFile() {
        try {
            if (m_logFile.is_open()) {
                m_logFile.close();
            }

            // Rename current file
            m_currentLogFileIndex++;
            fs::path oldPath(m_config.logFilePath);
            fs::path newPath = oldPath;
            newPath.replace_filename(
                oldPath.stem().wstring() + L"." +
                std::to_wstring(m_currentLogFileIndex) +
                oldPath.extension().wstring()
            );

            if (fs::exists(oldPath)) {
                fs::rename(oldPath, newPath);
            }

            // Compress old file if configured
            if (m_config.compressOldLogs) {
                // Would compress using compression utilities
            }

            // Open new file
            m_logFile.open(m_config.logFilePath, std::ios::app);
            m_currentLogFileSize = 0;

            // Remove old files if exceeded max
            if (m_currentLogFileIndex > m_config.maxLogFiles) {
                // Delete oldest file
            }

        } catch (const std::exception& e) {
            Logger::Error("EventLogger: Log rotation exception: {}", e.what());
        }
    }

    // ========================================================================
    // QUERY AND EXPORT
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
            // Query from DB
            auto& logDB = Database::LogDB::Instance();

            // Would query LogDB with filters
            // results = logDB.QueryEvents(startTime, endTime, category, minSeverity, maxResults);

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
    ) const {
        try {
            // Query events
            auto events = QueryEventsImpl(startTime, endTime, std::nullopt, std::nullopt, 100000);

            std::ofstream outFile(filePath);
            if (!outFile) {
                return false;
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

                outFile << formatted << std::endl;
            }

            outFile.close();
            return true;

        } catch (const std::exception& e) {
            Logger::Error("EventLogger: Export exception: {}", e.what());
            return false;
        }
    }

    // ========================================================================
    // FORENSIC OPERATIONS
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
            std::shared_lock lock(m_forensicMutex);

            std::ofstream outFile(filePath);
            if (!outFile) {
                Logger::Error("EventLogger: Failed to open forensic buffer file");
                return;
            }

            for (const auto& event : m_forensicBuffer) {
                nlohmann::json j;
                j["eventId"] = event.eventId;
                j["sequenceNumber"] = event.sequenceNumber;
                j["eventType"] = StringUtils::WideToUtf8(event.eventType);
                j["timestamp"] = system_clock::to_time_t(event.timestamp);
                j["timestampTicks"] = event.timestampTicks;

                for (const auto& [key, value] : event.data) {
                    j["data"][StringUtils::WideToUtf8(key)] = StringUtils::WideToUtf8(value);
                }

                outFile << j.dump() << std::endl;
            }

            outFile.close();
            Logger::Info("EventLogger: Forensic buffer flushed to file");

        } catch (const std::exception& e) {
            Logger::Error("EventLogger: Forensic flush exception: {}", e.what());
        }
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void InvokeEventCallbacks(const SecurityEvent& event) {
        std::shared_lock lock(m_callbackMutex);

        for (const auto& [id, callback] : m_eventCallbacks) {
            try {
                callback(event);
            } catch (const std::exception& e) {
                Logger::Error("EventLogger: Event callback exception: {}", e.what());
            }
        }
    }

    void InvokeAuditCallbacks(const AuditEvent& event) {
        std::shared_lock lock(m_callbackMutex);

        for (const auto& [id, callback] : m_auditCallbacks) {
            try {
                callback(event);
            } catch (const std::exception& e) {
                Logger::Error("EventLogger: Audit callback exception: {}", e.what());
            }
        }
    }

    // ========================================================================
    // CONTROL
    // ========================================================================

    void FlushImpl() {
        // Process all pending events
        while (!m_eventQueue.empty() || !m_auditQueue.empty()) {
            ProcessEventQueue();
            ProcessAuditQueue();
        }

        // Flush file
        if (m_logFile.is_open()) {
            m_logFile.flush();
        }
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
    event.source = L"ShadowStrike.ThreatDetection";
    event.message = std::format(L"Threat detected: {}", threatName);
    event.details = std::format(L"Type: {}, Action: {}", threatType, action);
    event.threatName = threatName;
    event.threatType = threatType;
    event.filePath = filePath;
    event.sha256Hash = sha256Hash;
    event.action = action;
    event.windowsEventId = 1001; // Threat detection event

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
    event.source = L"ShadowStrike.Quarantine";
    event.message = std::format(L"Quarantine {}: {}",
        success ? L"successful" : L"failed", filePath);
    event.filePath = filePath;
    event.sha256Hash = sha256Hash;
    event.threatName = threatName;
    event.action = success ? L"Quarantined" : L"QuarantineFailed";
    event.windowsEventId = 1002; // Quarantine event

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
    event.source = L"ShadowStrike.Scanner";
    event.message = std::format(L"Scan completed: {} ({} files, {} threats, {} ms)",
        scanType, filesScanned, threatsFound, duration.count());
    event.windowsEventId = 1003; // Scan result event

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
