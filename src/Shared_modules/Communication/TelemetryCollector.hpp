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
 * ShadowStrike NGAV - TELEMETRY COLLECTOR MODULE
 * ============================================================================
 *
 * @file TelemetryCollector.hpp
 * @brief Enterprise-grade telemetry collection with privacy-preserving
 *        anonymization, intelligent batching, and global threat intelligence.
 *
 * Provides comprehensive telemetry capabilities including detection events,
 * system health metrics, crash reporting, and global threat sharing.
 *
 * TELEMETRY CAPABILITIES:
 * =======================
 *
 * 1. EVENT COLLECTION
 *    - Detection events
 *    - System health metrics
 *    - Performance data
 *    - Crash reports
 *    - Update events
 *    - Configuration changes
 *
 * 2. PRIVACY PROTECTION
 *    - PII scrubbing
 *    - IP anonymization
 *    - Username removal
 *    - Path normalization
 *    - Hash-only file data
 *    - Consent management
 *
 * 3. BATCHING & DELIVERY
 *    - Event queuing
 *    - Smart batching
 *    - Scheduled submission
 *    - Retry with backoff
 *    - Offline queueing
 *
 * 4. THREAT INTELLIGENCE
 *    - Sample submission
 *    - Detection sharing
 *    - Prevalence data
 *    - Regional stats
 *    - Trend analysis
 *
 * 5. HEALTH MONITORING
 *    - CPU/Memory usage
 *    - Scan performance
 *    - Module health
 *    - Error rates
 *    - Uptime tracking
 *
 * COMPLIANCE:
 * ===========
 * - GDPR compliant
 * - User consent required
 * - Data minimization
 * - Right to erasure
 *
 * @note Thread-safe singleton design.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#pragma once

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <map>
#include <unordered_map>
#include <queue>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <filesystem>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/NetworkUtils.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Communication {
    class TelemetryCollectorImpl;
}

namespace ShadowStrike {
namespace Communication {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace TelemetryConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Default batch size
    inline constexpr size_t DEFAULT_BATCH_SIZE = 100;
    
    /// @brief Maximum queue size
    inline constexpr size_t MAX_QUEUE_SIZE = 10000;
    
    /// @brief Default flush interval (hours)
    inline constexpr uint32_t DEFAULT_FLUSH_INTERVAL_HOURS = 24;
    
    /// @brief Retry backoff base (seconds)
    inline constexpr uint32_t RETRY_BACKOFF_BASE = 60;
    
    /// @brief Maximum retry attempts
    inline constexpr uint32_t MAX_RETRY_ATTEMPTS = 5;
    
    /// @brief Telemetry endpoint
    inline constexpr const char* TELEMETRY_ENDPOINT = "https://telemetry.shadowstrike.io/v3/collect";

}  // namespace TelemetryConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
namespace fs = std::filesystem;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Event type
 */
enum class TelemetryEventType : uint8_t {
    Detection       = 0,    ///< Threat detection
    Scan            = 1,    ///< Scan completed
    Update          = 2,    ///< Definition update
    Crash           = 3,    ///< Application crash
    Error           = 4,    ///< Error occurred
    Health          = 5,    ///< Health check
    Performance     = 6,    ///< Performance metric
    Configuration   = 7,    ///< Config change
    License         = 8,    ///< License event
    Feedback        = 9,    ///< User feedback
    Sample          = 10,   ///< Sample submission
    Custom          = 11
};

/**
 * @brief Consent level
 */
enum class ConsentLevel : uint8_t {
    None            = 0,    ///< No telemetry
    Required        = 1,    ///< Required data only
    Basic           = 2,    ///< Basic telemetry
    Full            = 3     ///< Full telemetry
};

/**
 * @brief Anonymization level
 */
enum class AnonymizationLevel : uint8_t {
    None            = 0,    ///< No anonymization (internal only)
    Basic           = 1,    ///< Remove obvious PII
    Standard        = 2,    ///< Standard PII removal
    Strict          = 3     ///< Maximum anonymization
};

/**
 * @brief Submission status
 */
enum class SubmissionStatus : uint8_t {
    Pending         = 0,
    InProgress      = 1,
    Submitted       = 2,
    Failed          = 3,
    Retrying        = 4,
    Expired         = 5
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Submitting      = 3,
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Telemetry event
 */
struct TelemetryEvent {
    /// @brief Event ID
    std::string eventId;
    
    /// @brief Event type
    TelemetryEventType eventType = TelemetryEventType::Detection;
    
    /// @brief Event subtype
    std::string subtype;
    
    /// @brief Payload (JSON)
    std::string payloadJson;
    
    /// @brief Timestamp
    uint64_t timestamp = 0;
    
    /// @brief System time
    SystemTimePoint systemTime;
    
    /// @brief Machine ID (anonymous)
    std::string machineId;
    
    /// @brief Product version
    std::string productVersion;
    
    /// @brief OS version
    std::string osVersion;
    
    /// @brief Is anonymized
    bool isAnonymized = false;
    
    /// @brief Anonymization level used
    AnonymizationLevel anonymizationLevel = AnonymizationLevel::Standard;
    
    /// @brief Status
    SubmissionStatus status = SubmissionStatus::Pending;
    
    /// @brief Retry count
    uint32_t retryCount = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Detection event data
 */
struct DetectionEventData {
    /// @brief Threat name
    std::string threatName;
    
    /// @brief Threat type
    std::string threatType;
    
    /// @brief File hash (SHA256)
    std::string fileHash;
    
    /// @brief File size
    uint64_t fileSize = 0;
    
    /// @brief Detection method
    std::string detectionMethod;
    
    /// @brief Action taken
    std::string actionTaken;
    
    /// @brief Detection timestamp
    uint64_t detectionTime = 0;
    
    /// @brief Signature version
    std::string signatureVersion;
    
    /// @brief False positive probability
    double fpProbability = 0.0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Health event data
 */
struct HealthEventData {
    /// @brief CPU usage (%)
    double cpuUsage = 0.0;
    
    /// @brief Memory usage (MB)
    uint64_t memoryUsageMB = 0;
    
    /// @brief Disk usage (MB)
    uint64_t diskUsageMB = 0;
    
    /// @brief Uptime (seconds)
    uint64_t uptimeSeconds = 0;
    
    /// @brief Scan queue size
    uint32_t scanQueueSize = 0;
    
    /// @brief Active scans
    uint32_t activeScans = 0;
    
    /// @brief Module health (name -> status)
    std::map<std::string, std::string> moduleHealth;
    
    /// @brief Error count
    uint32_t errorCount = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Performance event data
 */
struct PerformanceEventData {
    /// @brief Metric name
    std::string metricName;
    
    /// @brief Metric value
    double value = 0.0;
    
    /// @brief Unit
    std::string unit;
    
    /// @brief Context
    std::map<std::string, std::string> context;
    
    /// @brief Duration (ms)
    uint32_t durationMs = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Crash event data
 */
struct CrashEventData {
    /// @brief Exception type
    std::string exceptionType;
    
    /// @brief Exception message
    std::string exceptionMessage;
    
    /// @brief Stack trace (anonymized)
    std::string stackTrace;
    
    /// @brief Module name
    std::string moduleName;
    
    /// @brief Function name
    std::string functionName;
    
    /// @brief Thread ID
    uint32_t threadId = 0;
    
    /// @brief Is critical
    bool isCritical = false;
    
    /// @brief Minidump hash
    std::string minidumpHash;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Batch info
 */
struct TelemetryBatch {
    /// @brief Batch ID
    std::string batchId;
    
    /// @brief Events in batch
    std::vector<TelemetryEvent> events;
    
    /// @brief Created time
    SystemTimePoint createdTime;
    
    /// @brief Submitted time
    std::optional<SystemTimePoint> submittedTime;
    
    /// @brief Status
    SubmissionStatus status = SubmissionStatus::Pending;
    
    /// @brief Retry count
    uint32_t retryCount = 0;
    
    /// @brief Total size (bytes)
    size_t totalSize = 0;
    
    /// @brief Compressed size (bytes)
    size_t compressedSize = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct TelemetryStatistics {
    std::atomic<uint64_t> eventsRecorded{0};
    std::atomic<uint64_t> eventsSubmitted{0};
    std::atomic<uint64_t> eventsFailed{0};
    std::atomic<uint64_t> eventsDropped{0};
    std::atomic<uint64_t> batchesSubmitted{0};
    std::atomic<uint64_t> batchesFailed{0};
    std::atomic<uint64_t> bytesSubmitted{0};
    std::atomic<uint64_t> retryAttempts{0};
    std::atomic<uint64_t> anonymizationTime{0};  // microseconds
    std::array<std::atomic<uint64_t>, 16> byEventType{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct TelemetryConfiguration {
    /// @brief Enable telemetry
    bool enabled = true;
    
    /// @brief Consent level
    ConsentLevel consentLevel = ConsentLevel::Basic;
    
    /// @brief Anonymization level
    AnonymizationLevel anonymizationLevel = AnonymizationLevel::Standard;
    
    /// @brief Batch size
    size_t batchSize = TelemetryConstants::DEFAULT_BATCH_SIZE;
    
    /// @brief Max queue size
    size_t maxQueueSize = TelemetryConstants::MAX_QUEUE_SIZE;
    
    /// @brief Flush interval (hours)
    uint32_t flushIntervalHours = TelemetryConstants::DEFAULT_FLUSH_INTERVAL_HOURS;
    
    /// @brief Telemetry endpoint
    std::string endpoint = TelemetryConstants::TELEMETRY_ENDPOINT;
    
    /// @brief API key
    std::string apiKey;
    
    /// @brief Enable compression
    bool enableCompression = true;
    
    /// @brief Enable offline queue
    bool enableOfflineQueue = true;
    
    /// @brief Max retry attempts
    uint32_t maxRetryAttempts = TelemetryConstants::MAX_RETRY_ATTEMPTS;
    
    /// @brief Include health data
    bool includeHealth = true;
    
    /// @brief Include performance data
    bool includePerformance = true;
    
    /// @brief Include crash data
    bool includeCrash = true;
    
    /// @brief Sample submission enabled
    bool sampleSubmissionEnabled = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using EventCallback = std::function<void(const TelemetryEvent&)>;
using BatchCallback = std::function<void(const TelemetryBatch&)>;
using ConsentCallback = std::function<bool(ConsentLevel)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// TELEMETRY COLLECTOR CLASS
// ============================================================================

/**
 * @class TelemetryCollector
 * @brief Enterprise telemetry collection
 */
class TelemetryCollector final {
public:
    [[nodiscard]] static TelemetryCollector& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    TelemetryCollector(const TelemetryCollector&) = delete;
    TelemetryCollector& operator=(const TelemetryCollector&) = delete;
    TelemetryCollector(TelemetryCollector&&) = delete;
    TelemetryCollector& operator=(TelemetryCollector&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const TelemetryConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const TelemetryConfiguration& config);
    [[nodiscard]] TelemetryConfiguration GetConfiguration() const;

    // ========================================================================
    // EVENT RECORDING
    // ========================================================================
    
    /// @brief Record event
    void RecordEvent(const std::string& type, const std::string& data);
    
    /// @brief Record event (typed)
    void RecordEvent(const TelemetryEvent& event);
    
    /// @brief Record detection event
    void RecordDetection(const DetectionEventData& detection);
    
    /// @brief Record health event
    void RecordHealth(const HealthEventData& health);
    
    /// @brief Record performance event
    void RecordPerformance(const PerformanceEventData& perf);
    
    /// @brief Record crash event
    void RecordCrash(const CrashEventData& crash);
    
    /// @brief Record custom event
    void RecordCustom(
        const std::string& subtype,
        const std::map<std::string, std::string>& data);

    // ========================================================================
    // SUBMISSION
    // ========================================================================
    
    /// @brief Flush all queued events
    void Flush();
    
    /// @brief Flush asynchronously
    void FlushAsync();
    
    /// @brief Submit single event immediately
    [[nodiscard]] bool SubmitImmediate(const TelemetryEvent& event);
    
    /// @brief Get queue size
    [[nodiscard]] size_t GetQueueSize() const noexcept;
    
    /// @brief Is submission in progress
    [[nodiscard]] bool IsSubmitting() const noexcept;

    // ========================================================================
    // CONSENT MANAGEMENT
    // ========================================================================
    
    /// @brief Set consent level
    void SetConsentLevel(ConsentLevel level);
    
    /// @brief Get consent level
    [[nodiscard]] ConsentLevel GetConsentLevel() const noexcept;
    
    /// @brief Is telemetry consented
    [[nodiscard]] bool IsConsented() const noexcept;
    
    /// @brief Request consent (triggers callback)
    [[nodiscard]] bool RequestConsent(ConsentLevel requestedLevel);

    // ========================================================================
    // ANONYMIZATION
    // ========================================================================
    
    /// @brief Anonymize data
    [[nodiscard]] std::string Anonymize(
        const std::string& data,
        AnonymizationLevel level = AnonymizationLevel::Standard);
    
    /// @brief Anonymize path
    [[nodiscard]] std::string AnonymizePath(const fs::path& path);
    
    /// @brief Set anonymization level
    void SetAnonymizationLevel(AnonymizationLevel level);
    
    /// @brief Get machine ID (anonymous)
    [[nodiscard]] std::string GetAnonymousMachineId() const;

    // ========================================================================
    // HISTORY & MANAGEMENT
    // ========================================================================
    
    /// @brief Get pending events
    [[nodiscard]] std::vector<TelemetryEvent> GetPendingEvents(size_t limit = 100);
    
    /// @brief Get recent batches
    [[nodiscard]] std::vector<TelemetryBatch> GetRecentBatches(size_t limit = 10);
    
    /// @brief Clear queue
    void ClearQueue();
    
    /// @brief Opt out (clear all data)
    void OptOut();

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterEventCallback(EventCallback callback);
    void RegisterBatchCallback(BatchCallback callback);
    void RegisterConsentCallback(ConsentCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] TelemetryStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    TelemetryCollector();
    ~TelemetryCollector();
    
    std::unique_ptr<TelemetryCollectorImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetEventTypeName(TelemetryEventType type) noexcept;
[[nodiscard]] std::string_view GetConsentLevelName(ConsentLevel level) noexcept;
[[nodiscard]] std::string_view GetAnonymizationLevelName(AnonymizationLevel level) noexcept;
[[nodiscard]] std::string_view GetSubmissionStatusName(SubmissionStatus status) noexcept;

/// @brief Generate anonymous machine ID
[[nodiscard]] std::string GenerateAnonymousMachineId();

/// @brief Scrub PII from string
[[nodiscard]] std::string ScrubPII(const std::string& data);

/// @brief Hash sensitive data
[[nodiscard]] std::string HashSensitiveData(const std::string& data);

}  // namespace Communication
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_TELEMETRY_RECORD(type, data) \
    ::ShadowStrike::Communication::TelemetryCollector::Instance().RecordEvent(type, data)

#define SS_TELEMETRY_DETECTION(detection) \
    ::ShadowStrike::Communication::TelemetryCollector::Instance().RecordDetection(detection)

#define SS_TELEMETRY_HEALTH(health) \
    ::ShadowStrike::Communication::TelemetryCollector::Instance().RecordHealth(health)

#define SS_TELEMETRY_FLUSH() \
    ::ShadowStrike::Communication::TelemetryCollector::Instance().Flush()
