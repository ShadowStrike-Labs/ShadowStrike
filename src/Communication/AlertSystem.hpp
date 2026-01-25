/**
 * ============================================================================
 * ShadowStrike NGAV - ALERT SYSTEM MODULE
 * ============================================================================
 *
 * @file AlertSystem.hpp
 * @brief Enterprise-grade emergency alert system with multi-channel delivery,
 *        escalation management, and integration with security orchestration.
 *
 * Provides comprehensive alerting capabilities including email, webhooks, SMS,
 * SIEM integration, and local notifications with priority-based escalation.
 *
 * ALERT CAPABILITIES:
 * ===================
 *
 * 1. DELIVERY CHANNELS
 *    - SMTP email (TLS/SSL)
 *    - Webhook (Slack, Teams, Discord)
 *    - SMS (Twilio, AWS SNS)
 *    - Push notifications
 *    - Desktop notifications
 *    - Audible alarms
 *    - SIEM integration
 *
 * 2. ESCALATION MANAGEMENT
 *    - Priority-based routing
 *    - Time-based escalation
 *    - On-call schedules
 *    - Acknowledgment tracking
 *    - Auto-escalation
 *    - Suppression rules
 *
 * 3. ALERT TYPES
 *    - Threat detection
 *    - System health
 *    - Policy violations
 *    - Compliance alerts
 *    - Audit events
 *    - Operational alerts
 *
 * 4. INTEGRATION
 *    - SIEM (Splunk, QRadar, Sentinel)
 *    - SOAR platforms
 *    - Ticketing systems (ServiceNow, Jira)
 *    - PagerDuty/OpsGenie
 *    - Custom endpoints
 *
 * 5. MANAGEMENT
 *    - Alert deduplication
 *    - Correlation
 *    - Rate limiting
 *    - Maintenance windows
 *    - Alert history
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
#include <unordered_set>
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
    class AlertSystemImpl;
}

namespace ShadowStrike {
namespace Communication {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace AlertConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Maximum alerts per minute (rate limit)
    inline constexpr size_t MAX_ALERTS_PER_MINUTE = 100;
    
    /// @brief Default escalation timeout (minutes)
    inline constexpr uint32_t DEFAULT_ESCALATION_TIMEOUT = 15;
    
    /// @brief Maximum retry attempts
    inline constexpr uint32_t MAX_RETRY_ATTEMPTS = 3;
    
    /// @brief Alert history retention (hours)
    inline constexpr uint32_t HISTORY_RETENTION_HOURS = 168;  // 7 days
    
    /// @brief Maximum alert queue size
    inline constexpr size_t MAX_QUEUE_SIZE = 10000;

}  // namespace AlertConstants

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
 * @brief Alert severity
 */
enum class AlertSeverity : uint8_t {
    Info            = 0,
    Low             = 1,
    Medium          = 2,
    High            = 3,
    Critical        = 4,
    Emergency       = 5
};

/**
 * @brief Alert type
 */
enum class AlertType : uint8_t {
    ThreatDetection = 0,
    SystemHealth    = 1,
    PolicyViolation = 2,
    ComplianceAlert = 3,
    AuditEvent      = 4,
    Operational     = 5,
    Security        = 6,
    Performance     = 7,
    Custom          = 8
};

/**
 * @brief Delivery channel
 */
enum class DeliveryChannel : uint32_t {
    None            = 0,
    Email           = 1 << 0,
    Slack           = 1 << 1,
    Teams           = 1 << 2,
    Discord         = 1 << 3,
    SMS             = 1 << 4,
    PushNotification= 1 << 5,
    Desktop         = 1 << 6,
    Sound           = 1 << 7,
    SIEM            = 1 << 8,
    Webhook         = 1 << 9,
    Syslog          = 1 << 10,
    PagerDuty       = 1 << 11,
    OpsGenie        = 1 << 12,
    ServiceNow      = 1 << 13,
    All             = 0xFFFFFFFF
};

/**
 * @brief Alert status
 */
enum class AlertStatus : uint8_t {
    New             = 0,
    Pending         = 1,
    Sent            = 2,
    Acknowledged    = 3,
    Escalated       = 4,
    Resolved        = 5,
    Suppressed      = 6,
    Failed          = 7
};

/**
 * @brief Escalation level
 */
enum class EscalationLevel : uint8_t {
    Level1          = 0,    ///< On-call analyst
    Level2          = 1,    ///< Senior analyst
    Level3          = 2,    ///< Team lead
    Level4          = 3,    ///< Manager
    Level5          = 4     ///< Executive
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Processing      = 3,
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief SMTP configuration
 */
struct SMTPConfiguration {
    /// @brief Server hostname
    std::string server;
    
    /// @brief Port
    uint16_t port = 587;
    
    /// @brief Use TLS
    bool useTLS = true;
    
    /// @brief Username
    std::string username;
    
    /// @brief Password
    std::string password;
    
    /// @brief From address
    std::string fromAddress;
    
    /// @brief From name
    std::string fromName = "ShadowStrike Alert";
    
    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Webhook configuration
 */
struct WebhookConfiguration {
    /// @brief Webhook ID
    std::string webhookId;
    
    /// @brief Name
    std::string name;
    
    /// @brief URL
    std::string url;
    
    /// @brief Channel type
    DeliveryChannel channelType = DeliveryChannel::Webhook;
    
    /// @brief HTTP method
    std::string method = "POST";
    
    /// @brief Headers
    std::map<std::string, std::string> headers;
    
    /// @brief Auth token (optional)
    std::string authToken;
    
    /// @brief Template (JSON with placeholders)
    std::string payloadTemplate;
    
    /// @brief Is enabled
    bool enabled = true;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Alert recipient
 */
struct AlertRecipient {
    /// @brief Recipient ID
    std::string recipientId;
    
    /// @brief Name
    std::string name;
    
    /// @brief Email
    std::string email;
    
    /// @brief Phone (for SMS)
    std::string phone;
    
    /// @brief Escalation level
    EscalationLevel level = EscalationLevel::Level1;
    
    /// @brief Channels to use
    DeliveryChannel channels = DeliveryChannel::Email;
    
    /// @brief Is enabled
    bool enabled = true;
    
    /// @brief On-call schedule ID
    std::string scheduleId;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Alert definition
 */
struct Alert {
    /// @brief Alert ID
    std::string alertId;
    
    /// @brief Severity
    AlertSeverity severity = AlertSeverity::Medium;
    
    /// @brief Type
    AlertType type = AlertType::ThreatDetection;
    
    /// @brief Subject
    std::string subject;
    
    /// @brief Details/body
    std::string details;
    
    /// @brief Source (module that raised alert)
    std::string source;
    
    /// @brief Host name
    std::string hostname;
    
    /// @brief User affected
    std::string userName;
    
    /// @brief Additional data (JSON)
    std::string metadata;
    
    /// @brief Correlation ID (for dedup)
    std::string correlationId;
    
    /// @brief Status
    AlertStatus status = AlertStatus::New;
    
    /// @brief Current escalation level
    EscalationLevel escalationLevel = EscalationLevel::Level1;
    
    /// @brief Creation time
    SystemTimePoint createdTime;
    
    /// @brief Sent time
    SystemTimePoint sentTime;
    
    /// @brief Acknowledged time
    std::optional<SystemTimePoint> acknowledgedTime;
    
    /// @brief Acknowledged by
    std::string acknowledgedBy;
    
    /// @brief Channels used
    DeliveryChannel deliveryChannels = DeliveryChannel::None;
    
    /// @brief Retry count
    uint32_t retryCount = 0;
    
    /// @brief Error message (if failed)
    std::string errorMessage;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Escalation rule
 */
struct EscalationRule {
    /// @brief Rule ID
    std::string ruleId;
    
    /// @brief Name
    std::string name;
    
    /// @brief Minimum severity to apply
    AlertSeverity minSeverity = AlertSeverity::High;
    
    /// @brief Alert types to apply
    std::vector<AlertType> alertTypes;
    
    /// @brief Timeout before escalation (minutes)
    uint32_t timeoutMinutes = AlertConstants::DEFAULT_ESCALATION_TIMEOUT;
    
    /// @brief Recipients per level
    std::map<EscalationLevel, std::vector<std::string>> recipients;
    
    /// @brief Is enabled
    bool enabled = true;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Suppression rule
 */
struct SuppressionRule {
    /// @brief Rule ID
    std::string ruleId;
    
    /// @brief Name
    std::string name;
    
    /// @brief Match criteria (field -> pattern)
    std::map<std::string, std::string> criteria;
    
    /// @brief Duration (0 = permanent)
    std::chrono::minutes duration{0};
    
    /// @brief Start time
    SystemTimePoint startTime;
    
    /// @brief End time (optional)
    std::optional<SystemTimePoint> endTime;
    
    /// @brief Reason
    std::string reason;
    
    /// @brief Created by
    std::string createdBy;
    
    /// @brief Is active
    bool active = true;
    
    [[nodiscard]] bool IsExpired() const noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Delivery result
 */
struct DeliveryResult {
    /// @brief Alert ID
    std::string alertId;
    
    /// @brief Channel used
    DeliveryChannel channel = DeliveryChannel::None;
    
    /// @brief Success
    bool success = false;
    
    /// @brief Response code
    int responseCode = 0;
    
    /// @brief Response message
    std::string responseMessage;
    
    /// @brief Delivery time
    SystemTimePoint deliveryTime;
    
    /// @brief Duration (ms)
    uint32_t durationMs = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct AlertStatistics {
    std::atomic<uint64_t> totalAlerts{0};
    std::atomic<uint64_t> alertsSent{0};
    std::atomic<uint64_t> alertsFailed{0};
    std::atomic<uint64_t> alertsSuppressed{0};
    std::atomic<uint64_t> alertsAcknowledged{0};
    std::atomic<uint64_t> alertsEscalated{0};
    std::atomic<uint64_t> emailsSent{0};
    std::atomic<uint64_t> webhooksSent{0};
    std::atomic<uint64_t> smsSent{0};
    std::atomic<uint64_t> rateLimitHits{0};
    std::array<std::atomic<uint64_t>, 8> bySeverity{};
    std::array<std::atomic<uint64_t>, 16> byChannel{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct AlertConfiguration {
    /// @brief Enable alert system
    bool enabled = true;
    
    /// @brief SMTP configuration
    SMTPConfiguration smtp;
    
    /// @brief Webhooks
    std::vector<WebhookConfiguration> webhooks;
    
    /// @brief Recipients
    std::vector<AlertRecipient> recipients;
    
    /// @brief Escalation rules
    std::vector<EscalationRule> escalationRules;
    
    /// @brief Suppression rules
    std::vector<SuppressionRule> suppressionRules;
    
    /// @brief Default channels
    DeliveryChannel defaultChannels = DeliveryChannel::Email;
    
    /// @brief Rate limit (alerts per minute)
    size_t rateLimitPerMinute = AlertConstants::MAX_ALERTS_PER_MINUTE;
    
    /// @brief Enable deduplication
    bool enableDeduplication = true;
    
    /// @brief Dedup window (minutes)
    uint32_t dedupWindowMinutes = 5;
    
    /// @brief Play sound for critical
    bool playSoundCritical = true;
    
    /// @brief Retry failed alerts
    bool retryFailed = true;
    
    /// @brief Max retry attempts
    uint32_t maxRetryAttempts = AlertConstants::MAX_RETRY_ATTEMPTS;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using AlertCallback = std::function<void(const Alert&)>;
using DeliveryCallback = std::function<void(const DeliveryResult&)>;
using EscalationCallback = std::function<void(const Alert&, EscalationLevel)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// ALERT SYSTEM CLASS
// ============================================================================

/**
 * @class AlertSystem
 * @brief Enterprise alert management
 */
class AlertSystem final {
public:
    [[nodiscard]] static AlertSystem& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    AlertSystem(const AlertSystem&) = delete;
    AlertSystem& operator=(const AlertSystem&) = delete;
    AlertSystem(AlertSystem&&) = delete;
    AlertSystem& operator=(AlertSystem&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const std::string& configJson);
    [[nodiscard]] bool Initialize(const AlertConfiguration& config);
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const AlertConfiguration& config);
    [[nodiscard]] AlertConfiguration GetConfiguration() const;

    // ========================================================================
    // ALERT OPERATIONS
    // ========================================================================
    
    /// @brief Raise emergency alert
    void RaiseEmergency(const std::string& subject, const std::string& details);
    
    /// @brief Raise alert
    [[nodiscard]] std::string RaiseAlert(const Alert& alert);
    
    /// @brief Raise alert (convenience)
    [[nodiscard]] std::string RaiseAlert(
        AlertSeverity severity,
        AlertType type,
        const std::string& subject,
        const std::string& details,
        const std::string& source = "");
    
    /// @brief Acknowledge alert
    [[nodiscard]] bool AcknowledgeAlert(
        const std::string& alertId,
        const std::string& acknowledgedBy);
    
    /// @brief Resolve alert
    [[nodiscard]] bool ResolveAlert(
        const std::string& alertId,
        const std::string& resolvedBy,
        const std::string& resolution = "");
    
    /// @brief Escalate alert
    [[nodiscard]] bool EscalateAlert(
        const std::string& alertId,
        const std::string& reason = "");
    
    /// @brief Retry failed alert
    [[nodiscard]] bool RetryAlert(const std::string& alertId);

    // ========================================================================
    // ALERT MANAGEMENT
    // ========================================================================
    
    /// @brief Get alert by ID
    [[nodiscard]] std::optional<Alert> GetAlert(const std::string& alertId);
    
    /// @brief Get alerts by status
    [[nodiscard]] std::vector<Alert> GetAlertsByStatus(AlertStatus status);
    
    /// @brief Get recent alerts
    [[nodiscard]] std::vector<Alert> GetRecentAlerts(
        size_t limit = 100,
        std::optional<SystemTimePoint> since = std::nullopt);
    
    /// @brief Get pending alerts (unacknowledged)
    [[nodiscard]] std::vector<Alert> GetPendingAlerts();
    
    /// @brief Search alerts
    [[nodiscard]] std::vector<Alert> SearchAlerts(
        const std::string& query,
        std::optional<AlertSeverity> minSeverity = std::nullopt,
        std::optional<AlertType> type = std::nullopt);

    // ========================================================================
    // RECIPIENTS
    // ========================================================================
    
    /// @brief Add recipient
    [[nodiscard]] bool AddRecipient(const AlertRecipient& recipient);
    
    /// @brief Remove recipient
    [[nodiscard]] bool RemoveRecipient(const std::string& recipientId);
    
    /// @brief Get recipients
    [[nodiscard]] std::vector<AlertRecipient> GetRecipients() const;

    // ========================================================================
    // WEBHOOKS
    // ========================================================================
    
    /// @brief Add webhook
    [[nodiscard]] bool AddWebhook(const WebhookConfiguration& webhook);
    
    /// @brief Remove webhook
    [[nodiscard]] bool RemoveWebhook(const std::string& webhookId);
    
    /// @brief Test webhook
    [[nodiscard]] bool TestWebhook(const std::string& webhookId);
    
    /// @brief Get webhooks
    [[nodiscard]] std::vector<WebhookConfiguration> GetWebhooks() const;

    // ========================================================================
    // SUPPRESSION
    // ========================================================================
    
    /// @brief Add suppression rule
    [[nodiscard]] bool AddSuppressionRule(const SuppressionRule& rule);
    
    /// @brief Remove suppression rule
    [[nodiscard]] bool RemoveSuppressionRule(const std::string& ruleId);
    
    /// @brief Get suppression rules
    [[nodiscard]] std::vector<SuppressionRule> GetSuppressionRules() const;
    
    /// @brief Check if alert is suppressed
    [[nodiscard]] bool IsAlertSuppressed(const Alert& alert);

    // ========================================================================
    // ESCALATION
    // ========================================================================
    
    /// @brief Add escalation rule
    [[nodiscard]] bool AddEscalationRule(const EscalationRule& rule);
    
    /// @brief Remove escalation rule
    [[nodiscard]] bool RemoveEscalationRule(const std::string& ruleId);
    
    /// @brief Get escalation rules
    [[nodiscard]] std::vector<EscalationRule> GetEscalationRules() const;

    // ========================================================================
    // DELIVERY
    // ========================================================================
    
    /// @brief Send email
    [[nodiscard]] bool SendEmail(
        const std::string& to,
        const std::string& subject,
        const std::string& body,
        bool isHtml = false);
    
    /// @brief Send webhook
    [[nodiscard]] bool SendWebhook(
        const std::string& webhookId,
        const std::string& payload);
    
    /// @brief Get delivery history
    [[nodiscard]] std::vector<DeliveryResult> GetDeliveryHistory(
        const std::string& alertId);

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterAlertCallback(AlertCallback callback);
    void RegisterDeliveryCallback(DeliveryCallback callback);
    void RegisterEscalationCallback(EscalationCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] AlertStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    AlertSystem();
    ~AlertSystem();
    
    std::unique_ptr<AlertSystemImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetAlertSeverityName(AlertSeverity severity) noexcept;
[[nodiscard]] std::string_view GetAlertTypeName(AlertType type) noexcept;
[[nodiscard]] std::string_view GetDeliveryChannelName(DeliveryChannel channel) noexcept;
[[nodiscard]] std::string_view GetAlertStatusName(AlertStatus status) noexcept;
[[nodiscard]] std::string_view GetEscalationLevelName(EscalationLevel level) noexcept;

/// @brief Format alert for email
[[nodiscard]] std::string FormatAlertEmail(const Alert& alert);

/// @brief Format alert for Slack
[[nodiscard]] std::string FormatAlertSlack(const Alert& alert);

/// @brief Format alert for Teams
[[nodiscard]] std::string FormatAlertTeams(const Alert& alert);

/// @brief Get severity color (hex)
[[nodiscard]] std::string GetSeverityColor(AlertSeverity severity);

}  // namespace Communication
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_ALERT_EMERGENCY(subject, details) \
    ::ShadowStrike::Communication::AlertSystem::Instance().RaiseEmergency(subject, details)

#define SS_ALERT_CRITICAL(subject, details) \
    ::ShadowStrike::Communication::AlertSystem::Instance().RaiseAlert( \
        ::ShadowStrike::Communication::AlertSeverity::Critical, \
        ::ShadowStrike::Communication::AlertType::Security, \
        subject, details)

#define SS_ALERT_HIGH(subject, details) \
    ::ShadowStrike::Communication::AlertSystem::Instance().RaiseAlert( \
        ::ShadowStrike::Communication::AlertSeverity::High, \
        ::ShadowStrike::Communication::AlertType::ThreatDetection, \
        subject, details)
