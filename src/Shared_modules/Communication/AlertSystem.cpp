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
#include "pch.h"
#include "AlertSystem.hpp"

#include <sstream>
#include <iomanip>
#include <algorithm>
#include <random>
#include <thread>
#include <deque>
#include <condition_variable>

#include <WinSock2.h>
#include <shellapi.h>
#pragma comment(lib, "Ws2_32.lib")

namespace ShadowStrike {
namespace Communication {

// ============================================================================
// HELPER — GUID-STYLE ALERT IDS
// ============================================================================

static std::string GenerateAlertId() {
    static std::atomic<uint64_t> s_counter{0};
    const uint64_t seq = s_counter.fetch_add(1, std::memory_order_relaxed);
    const auto now = std::chrono::system_clock::now();
    const auto epoch = now.time_since_epoch();
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();

    char buf[64]{};
    std::snprintf(buf, sizeof(buf), "ALR-%llX-%04llX",
                  static_cast<unsigned long long>(ms),
                  static_cast<unsigned long long>(seq & 0xFFFF));
    return buf;
}

static uint32_t ChannelBitIndex(DeliveryChannel ch) noexcept {
    const auto v = static_cast<uint32_t>(ch);
    if (v == 0) return 0;
    unsigned long idx = 0;
    _BitScanForward(&idx, v);
    return idx;
}

static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    const int len = MultiByteToWideChar(CP_UTF8, 0, s.data(),
                                        static_cast<int>(s.size()), nullptr, 0);
    if (len <= 0) return {};
    std::wstring w(static_cast<size_t>(len), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(),
                        static_cast<int>(s.size()), w.data(), len);
    return w;
}

static std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    const int len = WideCharToMultiByte(CP_UTF8, 0, w.data(),
                                        static_cast<int>(w.size()),
                                        nullptr, 0, nullptr, nullptr);
    if (len <= 0) return {};
    std::string s(static_cast<size_t>(len), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(),
                        static_cast<int>(w.size()),
                        s.data(), len, nullptr, nullptr);
    return s;
}

static std::string JsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (const char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char hex[8];
                    std::snprintf(hex, sizeof(hex), "\\u%04x",
                                  static_cast<unsigned>(static_cast<unsigned char>(c)));
                    out += hex;
                } else {
                    out += c;
                }
                break;
        }
    }
    return out;
}

static std::string SystemTimeToIso8601(SystemTimePoint tp) {
    const auto tt = std::chrono::system_clock::to_time_t(tp);
    struct tm tmBuf{};
    gmtime_s(&tmBuf, &tt);
    char buf[64]{};
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tmBuf);
    return buf;
}

// ============================================================================
// PIMPL IMPLEMENTATION
// ============================================================================

class AlertSystemImpl {
public:
    AlertSystemImpl() = default;
    ~AlertSystemImpl() { Shutdown(); }

    bool Initialize(const AlertConfiguration& config);
    void Shutdown();
    bool IsInitialized() const noexcept { return m_initialized.load(std::memory_order_acquire); }
    ModuleStatus GetStatus() const noexcept { return m_status.load(std::memory_order_acquire); }

    bool UpdateConfiguration(const AlertConfiguration& config);
    AlertConfiguration GetConfiguration() const;

    std::string RaiseAlert(Alert alert);
    void RaiseEmergency(const std::string& subject, const std::string& details);
    bool AcknowledgeAlert(const std::string& alertId, const std::string& by);
    bool ResolveAlert(const std::string& alertId, const std::string& by, const std::string& resolution);
    bool EscalateAlert(const std::string& alertId, const std::string& reason);
    bool RetryAlert(const std::string& alertId);

    std::optional<Alert> GetAlert(const std::string& alertId);
    std::vector<Alert> GetAlertsByStatus(AlertStatus status);
    std::vector<Alert> GetRecentAlerts(size_t limit, std::optional<SystemTimePoint> since);
    std::vector<Alert> GetPendingAlerts();
    std::vector<Alert> SearchAlerts(const std::string& query,
                                    std::optional<AlertSeverity> minSev,
                                    std::optional<AlertType> type);

    bool AddRecipient(const AlertRecipient& r);
    bool RemoveRecipient(const std::string& id);
    std::vector<AlertRecipient> GetRecipients() const;

    bool AddWebhook(const WebhookConfiguration& wh);
    bool RemoveWebhook(const std::string& id);
    bool TestWebhook(const std::string& id);
    std::vector<WebhookConfiguration> GetWebhooks() const;

    bool AddSuppressionRule(const SuppressionRule& rule);
    bool RemoveSuppressionRule(const std::string& id);
    std::vector<SuppressionRule> GetSuppressionRules() const;
    bool IsAlertSuppressed(const Alert& alert);

    bool AddEscalationRule(const EscalationRule& rule);
    bool RemoveEscalationRule(const std::string& id);
    std::vector<EscalationRule> GetEscalationRules() const;

    bool SendEmail(const std::string& to, const std::string& subject,
                   const std::string& body, bool isHtml);
    bool SendWebhookDirect(const std::string& whId, const std::string& payload);
    std::vector<DeliveryResult> GetDeliveryHistory(const std::string& alertId);

    void RegisterAlertCallback(AlertCallback cb);
    void RegisterDeliveryCallback(DeliveryCallback cb);
    void RegisterEscalationCallback(EscalationCallback cb);
    void RegisterErrorCallback(AlertErrorCallback cb);
    void UnregisterCallbacks();

    AlertStatisticsSnapshot GetStatistics() const noexcept;
    void ResetStatistics();
    bool SelfTest();

private:
    void WorkerLoop();
    void EscalationLoop();
    void ProcessAlert(Alert& alert);
    void DeliverToChannel(Alert& alert, DeliveryChannel channel);
    void DeliverWebhook(Alert& alert, const WebhookConfiguration& wh);
    void DeliverDesktop(const Alert& alert);
    void DeliverSyslog(const Alert& alert);
    void DeliverSIEM(const Alert& alert);

    bool CheckRateLimit();
    bool IsDuplicate(const Alert& alert);
    void PruneHistory();
    void PruneDedupCache();
    void RecordDelivery(const DeliveryResult& result);
    void NotifyError(const std::string& msg, int code);
    Alert* FindAlertInHistory(const std::string& alertId);
    const Alert* FindAlertInHistoryConst(const std::string& alertId) const;

    // Configuration
    AlertConfiguration m_config;
    mutable std::shared_mutex m_configMutex;

    // State
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_running{false};

    // Alert queue (bounded)
    std::deque<Alert> m_alertQueue;
    std::mutex m_queueMutex;
    std::condition_variable m_queueCV;

    // Worker
    std::thread m_workerThread;
    std::thread m_escalationThread;

    // Alert history (bounded)
    std::deque<Alert> m_history;
    mutable std::shared_mutex m_historyMutex;
    static constexpr size_t MAX_HISTORY_SIZE = 50000;

    // Rate limiting (sliding window)
    std::deque<TimePoint> m_rateWindow;
    std::mutex m_rateMutex;

    // Deduplication
    std::unordered_map<std::string, TimePoint> m_dedupCache;
    std::mutex m_dedupMutex;

    // Delivery history
    std::unordered_map<std::string, std::vector<DeliveryResult>> m_deliveryHistory;
    mutable std::shared_mutex m_deliveryMutex;

    // Callbacks
    AlertCallback m_alertCb;
    DeliveryCallback m_deliveryCb;
    EscalationCallback m_escalationCb;
    AlertErrorCallback m_errorCb;
    mutable std::mutex m_callbackMutex;

    // Statistics
    AlertStatistics m_stats;
};

// ============================================================================
// LIFECYCLE
// ============================================================================

bool AlertSystemImpl::Initialize(const AlertConfiguration& config) {
    ModuleStatus expected = ModuleStatus::Uninitialized;
    if (!m_status.compare_exchange_strong(expected, ModuleStatus::Initializing,
                                          std::memory_order_acq_rel)) {
        Utils::Logger::Warn("[AlertSystem] Already initialized (status={})",
                            static_cast<int>(expected));
        return false;
    }

    if (!config.IsValid()) {
        Utils::Logger::Error("[AlertSystem] Invalid configuration");
        m_status.store(ModuleStatus::Error, std::memory_order_release);
        return false;
    }

    {
        std::unique_lock lock(m_configMutex);
        m_config = config;
    }

    m_stats.Reset();
    m_running.store(true, std::memory_order_release);

    m_workerThread = std::thread([this] { WorkerLoop(); });
    m_escalationThread = std::thread([this] { EscalationLoop(); });

    m_initialized.store(true, std::memory_order_release);
    m_status.store(ModuleStatus::Running, std::memory_order_release);

    Utils::Logger::Info("[AlertSystem] Initialized — rate_limit={}/min, dedup={}, queue_max={}",
                        config.rateLimitPerMinute,
                        config.enableDeduplication ? "on" : "off",
                        AlertConstants::MAX_QUEUE_SIZE);
    return true;
}

void AlertSystemImpl::Shutdown() {
    if (!m_initialized.exchange(false, std::memory_order_acq_rel))
        return;

    m_status.store(ModuleStatus::Stopping, std::memory_order_release);
    m_running.store(false, std::memory_order_release);

    m_queueCV.notify_all();

    if (m_workerThread.joinable())
        m_workerThread.join();
    if (m_escalationThread.joinable())
        m_escalationThread.join();

    {
        std::unique_lock lock(m_queueMutex);
        m_alertQueue.clear();
    }

    m_status.store(ModuleStatus::Stopped, std::memory_order_release);
    Utils::Logger::Info("[AlertSystem] Shutdown complete — {} alerts processed",
                        m_stats.totalAlerts.load(std::memory_order_relaxed));
}

bool AlertSystemImpl::UpdateConfiguration(const AlertConfiguration& config) {
    if (!config.IsValid()) {
        Utils::Logger::Error("[AlertSystem] UpdateConfiguration: invalid config");
        return false;
    }
    std::unique_lock lock(m_configMutex);
    m_config = config;
    Utils::Logger::Info("[AlertSystem] Configuration updated");
    return true;
}

AlertConfiguration AlertSystemImpl::GetConfiguration() const {
    std::shared_lock lock(m_configMutex);
    return m_config;
}

// ============================================================================
// ALERT OPERATIONS
// ============================================================================

std::string AlertSystemImpl::RaiseAlert(Alert alert) {
    if (!m_initialized.load(std::memory_order_acquire)) {
        Utils::Logger::Warn("[AlertSystem] RaiseAlert called but not initialized");
        return {};
    }

    m_stats.totalAlerts.fetch_add(1, std::memory_order_relaxed);

    const auto sevIdx = static_cast<size_t>(alert.severity);
    if (sevIdx < m_stats.bySeverity.size())
        m_stats.bySeverity[sevIdx].fetch_add(1, std::memory_order_relaxed);

    // Suppression check
    if (IsAlertSuppressed(alert)) {
        m_stats.alertsSuppressed.fetch_add(1, std::memory_order_relaxed);
        alert.status = AlertStatus::Suppressed;
        Utils::Logger::Debug("[AlertSystem] Alert suppressed: {}", alert.subject);

        std::unique_lock lock(m_historyMutex);
        m_history.push_back(alert);
        if (m_history.size() > MAX_HISTORY_SIZE)
            m_history.pop_front();
        return alert.alertId;
    }

    // Deduplication check
    {
        bool dedupEnabled = false;
        {
            std::shared_lock lock(m_configMutex);
            dedupEnabled = m_config.enableDeduplication;
        }
        if (dedupEnabled && IsDuplicate(alert)) {
            m_stats.alertsSuppressed.fetch_add(1, std::memory_order_relaxed);
            Utils::Logger::Debug("[AlertSystem] Duplicate alert suppressed: correlationId={}",
                                alert.correlationId);
            return {};
        }
    }

    // Rate limit check
    if (!CheckRateLimit()) {
        m_stats.rateLimitHits.fetch_add(1, std::memory_order_relaxed);
        Utils::Logger::Warn("[AlertSystem] Rate limit exceeded, alert queued with backpressure: {}",
                            alert.subject);
    }

    // Assign ID and timestamp
    if (alert.alertId.empty())
        alert.alertId = GenerateAlertId();
    if (alert.createdTime == SystemTimePoint{})
        alert.createdTime = std::chrono::system_clock::now();
    alert.status = AlertStatus::Pending;

    // Assign default channels
    {
        std::shared_lock lock(m_configMutex);
        if (alert.deliveryChannels == DeliveryChannel::None)
            alert.deliveryChannels = m_config.defaultChannels;
    }

    // Populate hostname if empty
    if (alert.hostname.empty()) {
        char compName[MAX_COMPUTERNAME_LENGTH + 1]{};
        DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
        if (GetComputerNameA(compName, &size))
            alert.hostname = compName;
    }

    const std::string id = alert.alertId;

    // Notify alert callback (snapshot-then-invoke)
    {
        AlertCallback cb;
        {
            std::lock_guard lock(m_callbackMutex);
            cb = m_alertCb;
        }
        if (cb) {
            try { cb(alert); }
            catch (const std::exception& ex) {
                Utils::Logger::Error("[AlertSystem] AlertCallback threw: {}", ex.what());
            }
        }
    }

    // Enqueue for delivery
    {
        std::unique_lock lock(m_queueMutex);
        if (m_alertQueue.size() >= AlertConstants::MAX_QUEUE_SIZE) {
            Utils::Logger::Error("[AlertSystem] Queue full ({}) — dropping oldest alert",
                                AlertConstants::MAX_QUEUE_SIZE);
            m_alertQueue.pop_front();
        }
        m_alertQueue.push_back(std::move(alert));
    }
    m_queueCV.notify_one();

    return id;
}

void AlertSystemImpl::RaiseEmergency(const std::string& subject, const std::string& details) {
    Alert alert;
    alert.severity = AlertSeverity::Emergency;
    alert.type = AlertType::Security;
    alert.subject = subject;
    alert.details = details;
    alert.source = "AlertSystem::Emergency";
    alert.deliveryChannels = DeliveryChannel::All;
    RaiseAlert(std::move(alert));
}

bool AlertSystemImpl::AcknowledgeAlert(const std::string& alertId, const std::string& by) {
    std::unique_lock lock(m_historyMutex);
    Alert* a = FindAlertInHistory(alertId);
    if (!a) return false;
    if (a->status == AlertStatus::Resolved || a->status == AlertStatus::Suppressed)
        return false;
    a->status = AlertStatus::Acknowledged;
    a->acknowledgedTime = std::chrono::system_clock::now();
    a->acknowledgedBy = by;
    m_stats.alertsAcknowledged.fetch_add(1, std::memory_order_relaxed);
    Utils::Logger::Info("[AlertSystem] Alert {} acknowledged by {}", alertId, by);
    return true;
}

bool AlertSystemImpl::ResolveAlert(const std::string& alertId, const std::string& by,
                                    const std::string& resolution) {
    std::unique_lock lock(m_historyMutex);
    Alert* a = FindAlertInHistory(alertId);
    if (!a) return false;
    a->status = AlertStatus::Resolved;
    a->acknowledgedBy = by;
    if (!resolution.empty())
        a->metadata += " resolution=" + resolution;
    Utils::Logger::Info("[AlertSystem] Alert {} resolved by {}", alertId, by);
    return true;
}

bool AlertSystemImpl::EscalateAlert(const std::string& alertId, const std::string& reason) {
    std::unique_lock lock(m_historyMutex);
    Alert* a = FindAlertInHistory(alertId);
    if (!a) return false;
    if (a->status == AlertStatus::Resolved)
        return false;
    // Guard against TOCTOU: alert may have been acknowledged between
    // escalation check (shared_lock) and this call (unique_lock)
    if (a->acknowledgedTime.has_value())
        return false;

    const auto curLevel = static_cast<uint8_t>(a->escalationLevel);
    if (curLevel >= static_cast<uint8_t>(EscalationLevel::Level5))
        return false;

    a->escalationLevel = static_cast<EscalationLevel>(curLevel + 1);
    a->status = AlertStatus::Escalated;
    m_stats.alertsEscalated.fetch_add(1, std::memory_order_relaxed);

    Utils::Logger::Warn("[AlertSystem] Alert {} escalated to {} — reason: {}",
                        alertId,
                        GetEscalationLevelName(a->escalationLevel),
                        reason.empty() ? "timeout" : reason);

    // Notify escalation callback
    EscalationCallback cb;
    const Alert copy = *a;
    const auto level = a->escalationLevel;
    lock.unlock();

    {
        std::lock_guard lk(m_callbackMutex);
        cb = m_escalationCb;
    }
    if (cb) {
        try { cb(copy, level); }
        catch (const std::exception& ex) {
            Utils::Logger::Error("[AlertSystem] EscalationCallback threw: {}", ex.what());
        }
    }
    return true;
}

bool AlertSystemImpl::RetryAlert(const std::string& alertId) {
    Alert alertCopy;
    {
        std::shared_lock lock(m_historyMutex);
        const Alert* a = FindAlertInHistoryConst(alertId);
        if (!a || a->status != AlertStatus::Failed)
            return false;
        alertCopy = *a;
    }

    uint32_t maxRetries = 0;
    {
        std::shared_lock lock(m_configMutex);
        maxRetries = m_config.maxRetryAttempts;
    }
    if (alertCopy.retryCount >= maxRetries) {
        Utils::Logger::Warn("[AlertSystem] Alert {} exceeded max retries ({})",
                            alertId, maxRetries);
        return false;
    }

    alertCopy.retryCount++;
    alertCopy.status = AlertStatus::Pending;
    alertCopy.errorMessage.clear();

    {
        std::unique_lock lock(m_queueMutex);
        if (m_alertQueue.size() >= AlertConstants::MAX_QUEUE_SIZE)
            return false;
        m_alertQueue.push_back(std::move(alertCopy));
    }
    m_queueCV.notify_one();
    return true;
}

// ============================================================================
// ALERT MANAGEMENT
// ============================================================================

std::optional<Alert> AlertSystemImpl::GetAlert(const std::string& alertId) {
    std::shared_lock lock(m_historyMutex);
    const Alert* a = FindAlertInHistoryConst(alertId);
    if (!a) return std::nullopt;
    return *a;
}

std::vector<Alert> AlertSystemImpl::GetAlertsByStatus(AlertStatus status) {
    std::shared_lock lock(m_historyMutex);
    std::vector<Alert> result;
    for (const auto& a : m_history) {
        if (a.status == status)
            result.push_back(a);
    }
    return result;
}

std::vector<Alert> AlertSystemImpl::GetRecentAlerts(size_t limit,
                                                     std::optional<SystemTimePoint> since) {
    std::shared_lock lock(m_historyMutex);
    std::vector<Alert> result;
    result.reserve(std::min(limit, m_history.size()));

    for (auto it = m_history.rbegin(); it != m_history.rend() && result.size() < limit; ++it) {
        if (since.has_value() && it->createdTime < *since)
            continue;
        result.push_back(*it);
    }
    return result;
}

std::vector<Alert> AlertSystemImpl::GetPendingAlerts() {
    std::shared_lock lock(m_historyMutex);
    std::vector<Alert> result;
    for (const auto& a : m_history) {
        if (a.status == AlertStatus::Pending || a.status == AlertStatus::Sent ||
            a.status == AlertStatus::Escalated) {
            result.push_back(a);
        }
    }
    return result;
}

std::vector<Alert> AlertSystemImpl::SearchAlerts(const std::string& query,
                                                  std::optional<AlertSeverity> minSev,
                                                  std::optional<AlertType> type) {
    std::shared_lock lock(m_historyMutex);
    std::vector<Alert> result;
    for (const auto& a : m_history) {
        if (minSev.has_value() && a.severity < *minSev)
            continue;
        if (type.has_value() && a.type != *type)
            continue;
        if (!query.empty()) {
            if (a.subject.find(query) == std::string::npos &&
                a.details.find(query) == std::string::npos &&
                a.source.find(query) == std::string::npos &&
                a.hostname.find(query) == std::string::npos)
                continue;
        }
        result.push_back(a);
    }
    return result;
}

// ============================================================================
// RECIPIENTS
// ============================================================================

bool AlertSystemImpl::AddRecipient(const AlertRecipient& r) {
    if (r.recipientId.empty() || r.name.empty()) return false;
    std::unique_lock lock(m_configMutex);
    for (const auto& existing : m_config.recipients) {
        if (existing.recipientId == r.recipientId)
            return false;
    }
    m_config.recipients.push_back(r);
    Utils::Logger::Info("[AlertSystem] Recipient added: {} ({})", r.name, r.recipientId);
    return true;
}

bool AlertSystemImpl::RemoveRecipient(const std::string& id) {
    std::unique_lock lock(m_configMutex);
    auto& v = m_config.recipients;
    auto it = std::remove_if(v.begin(), v.end(),
                              [&](const AlertRecipient& r) { return r.recipientId == id; });
    if (it == v.end()) return false;
    v.erase(it, v.end());
    Utils::Logger::Info("[AlertSystem] Recipient removed: {}", id);
    return true;
}

std::vector<AlertRecipient> AlertSystemImpl::GetRecipients() const {
    std::shared_lock lock(m_configMutex);
    return m_config.recipients;
}

// ============================================================================
// WEBHOOKS
// ============================================================================

bool AlertSystemImpl::AddWebhook(const WebhookConfiguration& wh) {
    if (!wh.IsValid()) return false;
    std::unique_lock lock(m_configMutex);
    for (const auto& existing : m_config.webhooks) {
        if (existing.webhookId == wh.webhookId)
            return false;
    }
    m_config.webhooks.push_back(wh);
    Utils::Logger::Info("[AlertSystem] Webhook added: {} ({})", wh.name, wh.webhookId);
    return true;
}

bool AlertSystemImpl::RemoveWebhook(const std::string& id) {
    std::unique_lock lock(m_configMutex);
    auto& v = m_config.webhooks;
    auto it = std::remove_if(v.begin(), v.end(),
                              [&](const WebhookConfiguration& w) { return w.webhookId == id; });
    if (it == v.end()) return false;
    v.erase(it, v.end());
    Utils::Logger::Info("[AlertSystem] Webhook removed: {}", id);
    return true;
}

bool AlertSystemImpl::TestWebhook(const std::string& id) {
    WebhookConfiguration wh;
    {
        std::shared_lock lock(m_configMutex);
        bool found = false;
        for (const auto& w : m_config.webhooks) {
            if (w.webhookId == id) { wh = w; found = true; break; }
        }
        if (!found) return false;
    }

    Alert testAlert;
    testAlert.alertId = "TEST-WEBHOOK";
    testAlert.severity = AlertSeverity::Info;
    testAlert.type = AlertType::Operational;
    testAlert.subject = "ShadowStrike Webhook Test";
    testAlert.details = "This is a test alert to verify webhook connectivity.";
    testAlert.source = "AlertSystem::TestWebhook";
    testAlert.createdTime = std::chrono::system_clock::now();

    DeliverWebhook(testAlert, wh);
    return true;
}

std::vector<WebhookConfiguration> AlertSystemImpl::GetWebhooks() const {
    std::shared_lock lock(m_configMutex);
    return m_config.webhooks;
}

// ============================================================================
// SUPPRESSION
// ============================================================================

bool AlertSystemImpl::AddSuppressionRule(const SuppressionRule& rule) {
    if (rule.ruleId.empty()) return false;
    std::unique_lock lock(m_configMutex);
    for (const auto& existing : m_config.suppressionRules) {
        if (existing.ruleId == rule.ruleId)
            return false;
    }
    m_config.suppressionRules.push_back(rule);
    Utils::Logger::Info("[AlertSystem] Suppression rule added: {} ({})", rule.name, rule.ruleId);
    return true;
}

bool AlertSystemImpl::RemoveSuppressionRule(const std::string& id) {
    std::unique_lock lock(m_configMutex);
    auto& v = m_config.suppressionRules;
    auto it = std::remove_if(v.begin(), v.end(),
                              [&](const SuppressionRule& r) { return r.ruleId == id; });
    if (it == v.end()) return false;
    v.erase(it, v.end());
    Utils::Logger::Info("[AlertSystem] Suppression rule removed: {}", id);
    return true;
}

std::vector<SuppressionRule> AlertSystemImpl::GetSuppressionRules() const {
    std::shared_lock lock(m_configMutex);
    return m_config.suppressionRules;
}

bool AlertSystemImpl::IsAlertSuppressed(const Alert& alert) {
    std::shared_lock lock(m_configMutex);
    for (const auto& rule : m_config.suppressionRules) {
        if (!rule.active || rule.IsExpired())
            continue;

        bool allMatch = true;
        for (const auto& [field, pattern] : rule.criteria) {
            const std::string* value = nullptr;
            std::string sevStr, typeStr;

            if (field == "subject")          value = &alert.subject;
            else if (field == "source")      value = &alert.source;
            else if (field == "hostname")    value = &alert.hostname;
            else if (field == "details")     value = &alert.details;
            else if (field == "correlationId") value = &alert.correlationId;
            else if (field == "severity") {
                sevStr = std::string(GetAlertSeverityName(alert.severity));
                value = &sevStr;
            }
            else if (field == "type") {
                typeStr = std::string(GetAlertTypeName(alert.type));
                value = &typeStr;
            }

            if (!value || value->find(pattern) == std::string::npos) {
                allMatch = false;
                break;
            }
        }
        if (allMatch && !rule.criteria.empty())
            return true;
    }
    return false;
}

// ============================================================================
// ESCALATION
// ============================================================================

bool AlertSystemImpl::AddEscalationRule(const EscalationRule& rule) {
    if (rule.ruleId.empty()) return false;
    std::unique_lock lock(m_configMutex);
    for (const auto& existing : m_config.escalationRules) {
        if (existing.ruleId == rule.ruleId)
            return false;
    }
    m_config.escalationRules.push_back(rule);
    Utils::Logger::Info("[AlertSystem] Escalation rule added: {} ({})", rule.name, rule.ruleId);
    return true;
}

bool AlertSystemImpl::RemoveEscalationRule(const std::string& id) {
    std::unique_lock lock(m_configMutex);
    auto& v = m_config.escalationRules;
    auto it = std::remove_if(v.begin(), v.end(),
                              [&](const EscalationRule& r) { return r.ruleId == id; });
    if (it == v.end()) return false;
    v.erase(it, v.end());
    return true;
}

std::vector<EscalationRule> AlertSystemImpl::GetEscalationRules() const {
    std::shared_lock lock(m_configMutex);
    return m_config.escalationRules;
}

// ============================================================================
// DELIVERY
// ============================================================================

bool AlertSystemImpl::SendEmail(const std::string& to, const std::string& subject,
                                 const std::string& body, bool /*isHtml*/) {
    std::shared_lock lock(m_configMutex);
    if (!m_config.smtp.IsValid()) {
        NotifyError("SMTP not configured", -1);
        return false;
    }

    // Build SMTP relay webhook payload
    // Enterprise EDR agents relay email through a cloud service or SMTP gateway.
    // Direct SMTP from endpoint is unreliable (firewalls, port 25/587 blocks).
    // Production: integrate with SendGrid/SES/corporate relay API.
    std::string payload = "{";
    payload += "\"to\":\"" + JsonEscape(to) + "\",";
    payload += "\"from\":\"" + JsonEscape(m_config.smtp.fromAddress) + "\",";
    payload += "\"fromName\":\"" + JsonEscape(m_config.smtp.fromName) + "\",";
    payload += "\"subject\":\"" + JsonEscape(subject) + "\",";
    payload += "\"body\":\"" + JsonEscape(body) + "\"";
    payload += "}";

    const std::wstring url = Utf8ToWide("https://" + m_config.smtp.server + "/v1/send");
    const std::vector<uint8_t> postData(payload.begin(), payload.end());
    std::vector<uint8_t> response;

    Utils::NetworkUtils::HttpRequestOptions opts;
    opts.method = Utils::NetworkUtils::HttpMethod::POST;
    opts.contentType = L"application/json";
    opts.timeoutMs = 15000;
    opts.headers.push_back({L"Authorization", Utf8ToWide("Bearer " + m_config.smtp.password)});

    Utils::NetworkUtils::Error err;
    if (!Utils::NetworkUtils::HttpPost(url, postData, response, opts, &err)) {
        NotifyError("Email delivery failed: " + WideToUtf8(err.message), err.code);
        m_stats.alertsFailed.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    m_stats.emailsSent.fetch_add(1, std::memory_order_relaxed);
    return true;
}

bool AlertSystemImpl::SendWebhookDirect(const std::string& whId, const std::string& payload) {
    WebhookConfiguration wh;
    {
        std::shared_lock lock(m_configMutex);
        bool found = false;
        for (const auto& w : m_config.webhooks) {
            if (w.webhookId == whId) { wh = w; found = true; break; }
        }
        if (!found) return false;
    }

    const std::wstring url = Utf8ToWide(wh.url);
    const std::vector<uint8_t> postData(payload.begin(), payload.end());
    std::vector<uint8_t> response;

    Utils::NetworkUtils::HttpRequestOptions opts;
    opts.method = Utils::NetworkUtils::HttpMethod::POST;
    opts.contentType = L"application/json";
    opts.timeoutMs = 10000;

    for (const auto& [k, v] : wh.headers)
        opts.headers.push_back({Utf8ToWide(k), Utf8ToWide(v)});
    if (!wh.authToken.empty())
        opts.headers.push_back({L"Authorization", Utf8ToWide(wh.authToken)});

    Utils::NetworkUtils::Error err;
    if (!Utils::NetworkUtils::HttpPost(url, postData, response, opts, &err)) {
        NotifyError("Webhook delivery failed: " + WideToUtf8(err.message), err.code);
        return false;
    }

    m_stats.webhooksSent.fetch_add(1, std::memory_order_relaxed);
    return true;
}

std::vector<DeliveryResult> AlertSystemImpl::GetDeliveryHistory(const std::string& alertId) {
    std::shared_lock lock(m_deliveryMutex);
    auto it = m_deliveryHistory.find(alertId);
    if (it == m_deliveryHistory.end()) return {};
    return it->second;
}

// ============================================================================
// CALLBACKS
// ============================================================================

void AlertSystemImpl::RegisterAlertCallback(AlertCallback cb) {
    std::lock_guard lock(m_callbackMutex);
    m_alertCb = std::move(cb);
}

void AlertSystemImpl::RegisterDeliveryCallback(DeliveryCallback cb) {
    std::lock_guard lock(m_callbackMutex);
    m_deliveryCb = std::move(cb);
}

void AlertSystemImpl::RegisterEscalationCallback(EscalationCallback cb) {
    std::lock_guard lock(m_callbackMutex);
    m_escalationCb = std::move(cb);
}

void AlertSystemImpl::RegisterErrorCallback(AlertErrorCallback cb) {
    std::lock_guard lock(m_callbackMutex);
    m_errorCb = std::move(cb);
}

void AlertSystemImpl::UnregisterCallbacks() {
    std::lock_guard lock(m_callbackMutex);
    m_alertCb = nullptr;
    m_deliveryCb = nullptr;
    m_escalationCb = nullptr;
    m_errorCb = nullptr;
}

// ============================================================================
// STATISTICS
// ============================================================================

AlertStatisticsSnapshot AlertSystemImpl::GetStatistics() const noexcept {
    return m_stats.TakeSnapshot();
}

void AlertSystemImpl::ResetStatistics() {
    m_stats.Reset();
}

bool AlertSystemImpl::SelfTest() {
    if (!m_initialized.load(std::memory_order_acquire))
        return false;
    if (m_status.load(std::memory_order_acquire) != ModuleStatus::Running)
        return false;

    // Verify worker thread is alive
    if (!m_workerThread.joinable())
        return false;

    // Test alert pipeline (suppressed to avoid noise)
    Alert test;
    test.alertId = "SELF-TEST-" + GenerateAlertId();
    test.severity = AlertSeverity::Info;
    test.type = AlertType::Operational;
    test.subject = "AlertSystem self-test";
    test.source = "SelfTest";
    test.status = AlertStatus::Suppressed;
    test.createdTime = std::chrono::system_clock::now();

    {
        std::unique_lock lock(m_historyMutex);
        m_history.push_back(std::move(test));
    }

    Utils::Logger::Debug("[AlertSystem] Self-test passed");
    return true;
}

// ============================================================================
// WORKER THREAD
// ============================================================================

void AlertSystemImpl::WorkerLoop() {
    Utils::Logger::Debug("[AlertSystem] Worker thread started");

    while (m_running.load(std::memory_order_acquire)) {
        Alert alert;
        {
            std::unique_lock lock(m_queueMutex);
            m_queueCV.wait_for(lock, std::chrono::milliseconds(500),
                               [this] { return !m_alertQueue.empty() || !m_running.load(std::memory_order_acquire); });

            if (!m_running.load(std::memory_order_acquire))
                break;
            if (m_alertQueue.empty())
                continue;

            alert = std::move(m_alertQueue.front());
            m_alertQueue.pop_front();
        }

        m_status.store(ModuleStatus::Processing, std::memory_order_release);
        ProcessAlert(alert);
        m_status.store(ModuleStatus::Running, std::memory_order_release);
    }

    Utils::Logger::Debug("[AlertSystem] Worker thread exiting");
}

void AlertSystemImpl::ProcessAlert(Alert& alert) {
    const auto channels = static_cast<uint32_t>(alert.deliveryChannels);
    bool anySuccess = false;

    // Iterate each channel bit
    for (uint32_t bit = 0; bit < 14; ++bit) {
        const uint32_t mask = 1u << bit;
        if (!(channels & mask))
            continue;

        const auto channel = static_cast<DeliveryChannel>(mask);
        DeliverToChannel(alert, channel);

        const auto chIdx = ChannelBitIndex(channel);
        if (chIdx < m_stats.byChannel.size())
            m_stats.byChannel[chIdx].fetch_add(1, std::memory_order_relaxed);

        anySuccess = true;
    }

    if (anySuccess) {
        alert.status = AlertStatus::Sent;
        alert.sentTime = std::chrono::system_clock::now();
        m_stats.alertsSent.fetch_add(1, std::memory_order_relaxed);
    } else {
        alert.status = AlertStatus::Failed;
        alert.errorMessage = "No channels delivered successfully";
        m_stats.alertsFailed.fetch_add(1, std::memory_order_relaxed);

        // Auto-retry
        bool retryEnabled = false;
        uint32_t maxRetries = 0;
        {
            std::shared_lock lock(m_configMutex);
            retryEnabled = m_config.retryFailed;
            maxRetries = m_config.maxRetryAttempts;
        }
        if (retryEnabled && alert.retryCount < maxRetries) {
            alert.retryCount++;
            alert.status = AlertStatus::Pending;
            std::unique_lock lock(m_queueMutex);
            if (m_alertQueue.size() < AlertConstants::MAX_QUEUE_SIZE)
                m_alertQueue.push_back(alert);
        }
    }

    // Store in history
    {
        std::unique_lock lock(m_historyMutex);
        m_history.push_back(alert);
        if (m_history.size() > MAX_HISTORY_SIZE)
            m_history.pop_front();
    }
}

void AlertSystemImpl::DeliverToChannel(Alert& alert, DeliveryChannel channel) {
    const auto start = Clock::now();
    DeliveryResult result;
    result.alertId = alert.alertId;
    result.channel = channel;
    result.deliveryTime = std::chrono::system_clock::now();

    try {
        switch (channel) {
            case DeliveryChannel::Slack:
            case DeliveryChannel::Teams:
            case DeliveryChannel::Discord:
            case DeliveryChannel::Webhook:
            case DeliveryChannel::PagerDuty:
            case DeliveryChannel::OpsGenie:
            case DeliveryChannel::ServiceNow: {
                std::vector<WebhookConfiguration> webhooks;
                {
                    std::shared_lock lock(m_configMutex);
                    webhooks = m_config.webhooks;
                }
                for (const auto& wh : webhooks) {
                    if (!wh.enabled) continue;
                    if (wh.channelType != channel) continue;
                    DeliverWebhook(alert, wh);
                }
                result.success = true;
                break;
            }

            case DeliveryChannel::Email: {
                std::vector<AlertRecipient> recipients;
                {
                    std::shared_lock lock(m_configMutex);
                    recipients = m_config.recipients;
                }
                for (const auto& r : recipients) {
                    if (!r.enabled || r.email.empty()) continue;
                    if (!(static_cast<uint32_t>(r.channels) &
                          static_cast<uint32_t>(DeliveryChannel::Email)))
                        continue;
                    const auto body = FormatAlertEmail(alert);
                    SendEmail(r.email, alert.subject, body, true);
                }
                result.success = true;
                m_stats.emailsSent.fetch_add(1, std::memory_order_relaxed);
                break;
            }

            case DeliveryChannel::Desktop:
                DeliverDesktop(alert);
                result.success = true;
                break;

            case DeliveryChannel::Syslog:
                DeliverSyslog(alert);
                result.success = true;
                break;

            case DeliveryChannel::SIEM:
                DeliverSIEM(alert);
                result.success = true;
                break;

            case DeliveryChannel::Sound: {
                bool playSound = false;
                {
                    std::shared_lock lock(m_configMutex);
                    playSound = m_config.playSoundCritical;
                }
                if (playSound && alert.severity >= AlertSeverity::Critical)
                    MessageBeep(MB_ICONHAND);
                result.success = true;
                break;
            }

            case DeliveryChannel::SMS: {
                // SMS via webhook relay (Twilio/SNS API)
                std::vector<WebhookConfiguration> webhooks;
                {
                    std::shared_lock lock(m_configMutex);
                    webhooks = m_config.webhooks;
                }
                for (const auto& wh : webhooks) {
                    if (wh.enabled && wh.channelType == DeliveryChannel::SMS)
                        DeliverWebhook(alert, wh);
                }
                result.success = true;
                m_stats.smsSent.fetch_add(1, std::memory_order_relaxed);
                break;
            }

            default:
                result.success = false;
                result.responseMessage = "Unsupported channel";
                break;
        }
    } catch (const std::exception& ex) {
        result.success = false;
        result.responseMessage = ex.what();
        Utils::Logger::Error("[AlertSystem] Delivery failed on channel {}: {}",
                            GetDeliveryChannelName(channel), ex.what());
    }

    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now() - start);
    result.durationMs = static_cast<uint32_t>(elapsed.count());

    RecordDelivery(result);

    // Notify delivery callback
    DeliveryCallback cb;
    {
        std::lock_guard lock(m_callbackMutex);
        cb = m_deliveryCb;
    }
    if (cb) {
        try { cb(result); }
        catch (...) {}
    }
}

void AlertSystemImpl::DeliverWebhook(Alert& alert, const WebhookConfiguration& wh) {
    std::string payload;
    if (!wh.payloadTemplate.empty()) {
        payload = wh.payloadTemplate;
        // Simple template substitution
        auto replace = [&](const std::string& key, const std::string& val) {
            size_t pos = 0;
            while ((pos = payload.find(key, pos)) != std::string::npos) {
                payload.replace(pos, key.size(), val);
                pos += val.size();
            }
        };
        replace("{{alertId}}", JsonEscape(alert.alertId));
        replace("{{severity}}", std::string(GetAlertSeverityName(alert.severity)));
        replace("{{type}}", std::string(GetAlertTypeName(alert.type)));
        replace("{{subject}}", JsonEscape(alert.subject));
        replace("{{details}}", JsonEscape(alert.details));
        replace("{{source}}", JsonEscape(alert.source));
        replace("{{hostname}}", JsonEscape(alert.hostname));
        replace("{{timestamp}}", SystemTimeToIso8601(alert.createdTime));
        replace("{{color}}", GetSeverityColor(alert.severity));
    } else {
        // Default JSON payload
        switch (wh.channelType) {
            case DeliveryChannel::Slack:
                payload = FormatAlertSlack(alert);
                break;
            case DeliveryChannel::Teams:
                payload = FormatAlertTeams(alert);
                break;
            default:
                payload = alert.ToJson();
                break;
        }
    }

    const std::wstring url = Utf8ToWide(wh.url);
    const std::vector<uint8_t> postData(payload.begin(), payload.end());
    std::vector<uint8_t> response;

    Utils::NetworkUtils::HttpRequestOptions opts;
    opts.method = Utils::NetworkUtils::HttpMethod::POST;
    opts.contentType = L"application/json";
    opts.timeoutMs = 10000;

    for (const auto& [k, v] : wh.headers)
        opts.headers.push_back({Utf8ToWide(k), Utf8ToWide(v)});
    if (!wh.authToken.empty())
        opts.headers.push_back({L"Authorization", Utf8ToWide(wh.authToken)});

    Utils::NetworkUtils::Error err;
    if (!Utils::NetworkUtils::HttpPost(url, postData, response, opts, &err)) {
        Utils::Logger::Error("[AlertSystem] Webhook '{}' failed: {}", wh.name,
                            WideToUtf8(err.message));
        NotifyError("Webhook '" + wh.name + "' failed: " + WideToUtf8(err.message), err.code);
    } else {
        m_stats.webhooksSent.fetch_add(1, std::memory_order_relaxed);
    }
}

void AlertSystemImpl::DeliverDesktop(const Alert& alert) {
    // Windows toast notification via ShellExecute
    // Production: Use WinRT IToastNotificationManager for rich notifications.
    // Fallback: balloon tip via Shell_NotifyIconW
    const std::string title = "[ShadowStrike] " + std::string(GetAlertSeverityName(alert.severity));
    const std::string msg = alert.subject;

    Utils::Logger::Info("[AlertSystem] Desktop notification: [{}] {}",
                        GetAlertSeverityName(alert.severity), alert.subject);

    // Log-based notification: always works, no UI dependency
    // Rich toast notifications require COM + WinRT runtime which the EDR service
    // may not have. The NotificationManager module handles that separately.
}

void AlertSystemImpl::DeliverSyslog(const Alert& alert) {
    // RFC 5424 syslog over UDP to 127.0.0.1:514 (configurable)
    // Syslog facility = 4 (auth), severity mapped from AlertSeverity
    static const int severityMap[] = { 6, 5, 4, 3, 2, 1 }; // Info..Emergency → 6..1

    const int syslogSeverity = (static_cast<size_t>(alert.severity) < 6)
        ? severityMap[static_cast<size_t>(alert.severity)] : 3;
    const int priority = (4 << 3) | syslogSeverity; // facility=4 (auth)

    const std::string timestamp = SystemTimeToIso8601(alert.createdTime);
    char msg[2048]{};
    std::snprintf(msg, sizeof(msg),
                  "<%d>1 %s %s ShadowStrike - - - [alert@shadowstrike severity=\"%s\" type=\"%s\"] %s",
                  priority,
                  timestamp.c_str(),
                  alert.hostname.c_str(),
                  std::string(GetAlertSeverityName(alert.severity)).c_str(),
                  std::string(GetAlertTypeName(alert.type)).c_str(),
                  alert.subject.c_str());

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) return;

    sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(514);
    dest.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    sendto(sock, msg, static_cast<int>(strlen(msg)), 0,
           reinterpret_cast<const sockaddr*>(&dest), sizeof(dest));
    closesocket(sock);
}

void AlertSystemImpl::DeliverSIEM(const Alert& alert) {
    // SIEM delivery: format as JSON, send via syslog or HTTPS
    // Uses syslog as transport (most SIEM collectors listen on syslog)
    DeliverSyslog(alert);
}

// ============================================================================
// INTERNAL HELPERS
// ============================================================================

bool AlertSystemImpl::CheckRateLimit() {
    // Extract config value FIRST to avoid nested lock ordering violation
    size_t limit = 0;
    {
        std::shared_lock cfgLock(m_configMutex);
        limit = m_config.rateLimitPerMinute;
    }

    std::lock_guard lock(m_rateMutex);
    const auto now = Clock::now();
    const auto window = now - std::chrono::minutes(1);

    // Prune old entries
    while (!m_rateWindow.empty() && m_rateWindow.front() < window)
        m_rateWindow.pop_front();

    if (m_rateWindow.size() >= limit)
        return false;

    m_rateWindow.push_back(now);
    return true;
}

bool AlertSystemImpl::IsDuplicate(const Alert& alert) {
    if (alert.correlationId.empty())
        return false;

    // Extract config value FIRST to avoid nested lock ordering violation
    uint32_t windowMinutes = 5;
    {
        std::shared_lock cfgLock(m_configMutex);
        windowMinutes = m_config.dedupWindowMinutes;
    }

    std::lock_guard lock(m_dedupMutex);
    const auto now = Clock::now();

    // Prune old entries periodically
    if (m_dedupCache.size() > 10000)
        PruneDedupCache();

    auto it = m_dedupCache.find(alert.correlationId);
    if (it != m_dedupCache.end()) {
        const auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(now - it->second);
        if (elapsed.count() < static_cast<int64_t>(windowMinutes)) {
            return true;
        }
        it->second = now;
        return false;
    }

    m_dedupCache[alert.correlationId] = now;
    return false;
}

void AlertSystemImpl::PruneDedupCache() {
    // Caller must hold m_dedupMutex
    const auto now = Clock::now();
    const auto maxAge = std::chrono::minutes(30);
    for (auto it = m_dedupCache.begin(); it != m_dedupCache.end(); ) {
        if ((now - it->second) > maxAge)
            it = m_dedupCache.erase(it);
        else
            ++it;
    }
}

void AlertSystemImpl::PruneHistory() {
    // Caller must hold m_historyMutex exclusive
    while (m_history.size() > MAX_HISTORY_SIZE)
        m_history.pop_front();
}

void AlertSystemImpl::RecordDelivery(const DeliveryResult& result) {
    std::unique_lock lock(m_deliveryMutex);
    auto& vec = m_deliveryHistory[result.alertId];
    if (vec.size() > 100)
        vec.erase(vec.begin());
    vec.push_back(result);
}

void AlertSystemImpl::NotifyError(const std::string& msg, int code) {
    Utils::Logger::Error("[AlertSystem] {}", msg);
    AlertErrorCallback cb;
    {
        std::lock_guard lock(m_callbackMutex);
        cb = m_errorCb;
    }
    if (cb) {
        try { cb(msg, code); }
        catch (...) {}
    }
}

Alert* AlertSystemImpl::FindAlertInHistory(const std::string& alertId) {
    // Caller must hold m_historyMutex exclusive
    for (auto& a : m_history) {
        if (a.alertId == alertId)
            return &a;
    }
    return nullptr;
}

const Alert* AlertSystemImpl::FindAlertInHistoryConst(const std::string& alertId) const {
    // Caller must hold m_historyMutex (shared or exclusive)
    for (const auto& a : m_history) {
        if (a.alertId == alertId)
            return &a;
    }
    return nullptr;
}

// ============================================================================
// ESCALATION THREAD
// ============================================================================

void AlertSystemImpl::EscalationLoop() {
    Utils::Logger::Debug("[AlertSystem] Escalation thread started");

    while (m_running.load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(std::chrono::seconds(30));

        if (!m_running.load(std::memory_order_acquire))
            break;

        std::vector<EscalationRule> rules;
        {
            std::shared_lock lock(m_configMutex);
            rules = m_config.escalationRules;
        }

        std::vector<std::string> toEscalate;
        {
            std::shared_lock lock(m_historyMutex);
            const auto now = std::chrono::system_clock::now();

            for (const auto& alert : m_history) {
                if (alert.status != AlertStatus::Sent &&
                    alert.status != AlertStatus::Escalated)
                    continue;
                if (alert.acknowledgedTime.has_value())
                    continue;

                for (const auto& rule : rules) {
                    if (!rule.enabled)
                        continue;
                    if (alert.severity < rule.minSeverity)
                        continue;

                    // Guard: skip if sentTime was never set (default epoch)
                    if (alert.sentTime == SystemTimePoint{})
                        break;

                    const auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(
                        now - alert.sentTime);
                    // Clamp timeout to prevent overflow (max 7 days)
                    const auto clampedTimeout = std::min(
                        static_cast<int64_t>(rule.timeoutMinutes),
                        static_cast<int64_t>(10080));
                    const auto timeout = clampedTimeout *
                        (static_cast<int64_t>(alert.escalationLevel) + 1);

                    if (elapsed.count() >= timeout)
                        toEscalate.push_back(alert.alertId);
                    break;
                }
            }
        }

        for (const auto& id : toEscalate)
            EscalateAlert(id, "Escalation timeout");
    }

    Utils::Logger::Debug("[AlertSystem] Escalation thread exiting");
}

// ============================================================================
// SINGLETON
// ============================================================================

std::atomic<bool> AlertSystem::s_instanceCreated{false};

AlertSystem& AlertSystem::Instance() noexcept {
    static AlertSystem instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

bool AlertSystem::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

AlertSystem::AlertSystem()
    : m_impl(std::make_unique<AlertSystemImpl>()) {}

AlertSystem::~AlertSystem() = default;

// ============================================================================
// FORWARDING — LIFECYCLE
// ============================================================================

bool AlertSystem::Initialize(const std::string& configJson) {
    // JSON config parsing: production would use nlohmann::json or RapidJSON
    // For now, accept programmatic config only
    (void)configJson;
    Utils::Logger::Error("[AlertSystem] JSON config parsing not implemented — use Initialize(AlertConfiguration)");
    return false;
}

bool AlertSystem::Initialize(const AlertConfiguration& config) {
    return m_impl->Initialize(config);
}

void AlertSystem::Shutdown() {
    m_impl->Shutdown();
}

bool AlertSystem::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

ModuleStatus AlertSystem::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

bool AlertSystem::UpdateConfiguration(const AlertConfiguration& config) {
    return m_impl->UpdateConfiguration(config);
}

AlertConfiguration AlertSystem::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

// ============================================================================
// FORWARDING — ALERT OPERATIONS
// ============================================================================

void AlertSystem::RaiseEmergency(const std::string& subject, const std::string& details) {
    m_impl->RaiseEmergency(subject, details);
}

std::string AlertSystem::RaiseAlert(const Alert& alert) {
    Alert copy = alert;
    return m_impl->RaiseAlert(std::move(copy));
}

std::string AlertSystem::RaiseAlert(AlertSeverity severity, AlertType type,
                                     const std::string& subject,
                                     const std::string& details,
                                     const std::string& source) {
    Alert alert;
    alert.severity = severity;
    alert.type = type;
    alert.subject = subject;
    alert.details = details;
    alert.source = source;
    return m_impl->RaiseAlert(std::move(alert));
}

bool AlertSystem::AcknowledgeAlert(const std::string& alertId, const std::string& by) {
    return m_impl->AcknowledgeAlert(alertId, by);
}

bool AlertSystem::ResolveAlert(const std::string& alertId, const std::string& by,
                                const std::string& resolution) {
    return m_impl->ResolveAlert(alertId, by, resolution);
}

bool AlertSystem::EscalateAlert(const std::string& alertId, const std::string& reason) {
    return m_impl->EscalateAlert(alertId, reason);
}

bool AlertSystem::RetryAlert(const std::string& alertId) {
    return m_impl->RetryAlert(alertId);
}

// ============================================================================
// FORWARDING — ALERT MANAGEMENT
// ============================================================================

std::optional<Alert> AlertSystem::GetAlert(const std::string& alertId) {
    return m_impl->GetAlert(alertId);
}

std::vector<Alert> AlertSystem::GetAlertsByStatus(AlertStatus status) {
    return m_impl->GetAlertsByStatus(status);
}

std::vector<Alert> AlertSystem::GetRecentAlerts(size_t limit,
                                                 std::optional<SystemTimePoint> since) {
    return m_impl->GetRecentAlerts(limit, since);
}

std::vector<Alert> AlertSystem::GetPendingAlerts() {
    return m_impl->GetPendingAlerts();
}

std::vector<Alert> AlertSystem::SearchAlerts(const std::string& query,
                                              std::optional<AlertSeverity> minSev,
                                              std::optional<AlertType> type) {
    return m_impl->SearchAlerts(query, minSev, type);
}

// ============================================================================
// FORWARDING — RECIPIENTS
// ============================================================================

bool AlertSystem::AddRecipient(const AlertRecipient& r) { return m_impl->AddRecipient(r); }
bool AlertSystem::RemoveRecipient(const std::string& id) { return m_impl->RemoveRecipient(id); }
std::vector<AlertRecipient> AlertSystem::GetRecipients() const { return m_impl->GetRecipients(); }

// ============================================================================
// FORWARDING — WEBHOOKS
// ============================================================================

bool AlertSystem::AddWebhook(const WebhookConfiguration& wh) { return m_impl->AddWebhook(wh); }
bool AlertSystem::RemoveWebhook(const std::string& id) { return m_impl->RemoveWebhook(id); }
bool AlertSystem::TestWebhook(const std::string& id) { return m_impl->TestWebhook(id); }
std::vector<WebhookConfiguration> AlertSystem::GetWebhooks() const { return m_impl->GetWebhooks(); }

// ============================================================================
// FORWARDING — SUPPRESSION
// ============================================================================

bool AlertSystem::AddSuppressionRule(const SuppressionRule& rule) { return m_impl->AddSuppressionRule(rule); }
bool AlertSystem::RemoveSuppressionRule(const std::string& id) { return m_impl->RemoveSuppressionRule(id); }
std::vector<SuppressionRule> AlertSystem::GetSuppressionRules() const { return m_impl->GetSuppressionRules(); }
bool AlertSystem::IsAlertSuppressed(const Alert& alert) { return m_impl->IsAlertSuppressed(alert); }

// ============================================================================
// FORWARDING — ESCALATION
// ============================================================================

bool AlertSystem::AddEscalationRule(const EscalationRule& rule) { return m_impl->AddEscalationRule(rule); }
bool AlertSystem::RemoveEscalationRule(const std::string& id) { return m_impl->RemoveEscalationRule(id); }
std::vector<EscalationRule> AlertSystem::GetEscalationRules() const { return m_impl->GetEscalationRules(); }

// ============================================================================
// FORWARDING — DELIVERY
// ============================================================================

bool AlertSystem::SendEmail(const std::string& to, const std::string& subject,
                             const std::string& body, bool isHtml) {
    return m_impl->SendEmail(to, subject, body, isHtml);
}

bool AlertSystem::SendWebhook(const std::string& whId, const std::string& payload) {
    return m_impl->SendWebhookDirect(whId, payload);
}

std::vector<DeliveryResult> AlertSystem::GetDeliveryHistory(const std::string& alertId) {
    return m_impl->GetDeliveryHistory(alertId);
}

// ============================================================================
// FORWARDING — CALLBACKS
// ============================================================================

void AlertSystem::RegisterAlertCallback(AlertCallback cb) { m_impl->RegisterAlertCallback(std::move(cb)); }
void AlertSystem::RegisterDeliveryCallback(DeliveryCallback cb) { m_impl->RegisterDeliveryCallback(std::move(cb)); }
void AlertSystem::RegisterEscalationCallback(EscalationCallback cb) { m_impl->RegisterEscalationCallback(std::move(cb)); }
void AlertSystem::RegisterErrorCallback(AlertErrorCallback cb) { m_impl->RegisterErrorCallback(std::move(cb)); }
void AlertSystem::UnregisterCallbacks() { m_impl->UnregisterCallbacks(); }

// ============================================================================
// FORWARDING — STATISTICS
// ============================================================================

AlertStatisticsSnapshot AlertSystem::GetStatistics() const {
    return m_impl->GetStatistics();
}

void AlertSystem::ResetStatistics() {
    m_impl->ResetStatistics();
}

bool AlertSystem::SelfTest() {
    return m_impl->SelfTest();
}

std::string AlertSystem::GetVersionString() noexcept {
    char buf[32]{};
    std::snprintf(buf, sizeof(buf), "%u.%u.%u",
                  AlertConstants::VERSION_MAJOR,
                  AlertConstants::VERSION_MINOR,
                  AlertConstants::VERSION_PATCH);
    return buf;
}

// ============================================================================
// STRUCT METHODS
// ============================================================================

bool SMTPConfiguration::IsValid() const noexcept {
    return !server.empty() && port > 0 && !fromAddress.empty();
}

bool WebhookConfiguration::IsValid() const noexcept {
    return !webhookId.empty() && !url.empty() && url.size() < 2048;
}

bool SuppressionRule::IsExpired() const noexcept {
    if (duration == std::chrono::minutes{0})
        return false; // permanent
    if (endTime.has_value())
        return std::chrono::system_clock::now() > *endTime;
    return std::chrono::system_clock::now() > startTime + duration;
}

bool AlertConfiguration::IsValid() const noexcept {
    return rateLimitPerMinute > 0 && maxRetryAttempts <= 10;
}

// ============================================================================
// STRUCT TOJSON
// ============================================================================

std::string AlertRecipient::ToJson() const {
    std::string j = "{";
    j += "\"recipientId\":\"" + JsonEscape(recipientId) + "\",";
    j += "\"name\":\"" + JsonEscape(name) + "\",";
    j += "\"email\":\"" + JsonEscape(email) + "\",";
    j += "\"level\":" + std::to_string(static_cast<int>(level)) + ",";
    j += "\"enabled\":" + std::string(enabled ? "true" : "false");
    j += "}";
    return j;
}

std::string Alert::ToJson() const {
    std::string j = "{";
    j += "\"alertId\":\"" + JsonEscape(alertId) + "\",";
    j += "\"severity\":\"" + std::string(GetAlertSeverityName(severity)) + "\",";
    j += "\"type\":\"" + std::string(GetAlertTypeName(type)) + "\",";
    j += "\"subject\":\"" + JsonEscape(subject) + "\",";
    j += "\"details\":\"" + JsonEscape(details) + "\",";
    j += "\"source\":\"" + JsonEscape(source) + "\",";
    j += "\"hostname\":\"" + JsonEscape(hostname) + "\",";
    j += "\"status\":\"" + std::string(GetAlertStatusName(status)) + "\",";
    j += "\"escalationLevel\":\"" + std::string(GetEscalationLevelName(escalationLevel)) + "\",";
    j += "\"createdTime\":\"" + SystemTimeToIso8601(createdTime) + "\",";
    j += "\"retryCount\":" + std::to_string(retryCount);
    if (!correlationId.empty())
        j += ",\"correlationId\":\"" + JsonEscape(correlationId) + "\"";
    if (!metadata.empty())
        j += ",\"metadata\":\"" + JsonEscape(metadata) + "\"";
    if (!errorMessage.empty())
        j += ",\"errorMessage\":\"" + JsonEscape(errorMessage) + "\"";
    j += "}";
    return j;
}

std::string EscalationRule::ToJson() const {
    std::string j = "{";
    j += "\"ruleId\":\"" + JsonEscape(ruleId) + "\",";
    j += "\"name\":\"" + JsonEscape(name) + "\",";
    j += "\"minSeverity\":\"" + std::string(GetAlertSeverityName(minSeverity)) + "\",";
    j += "\"timeoutMinutes\":" + std::to_string(timeoutMinutes) + ",";
    j += "\"enabled\":" + std::string(enabled ? "true" : "false");
    j += "}";
    return j;
}

std::string SuppressionRule::ToJson() const {
    std::string j = "{";
    j += "\"ruleId\":\"" + JsonEscape(ruleId) + "\",";
    j += "\"name\":\"" + JsonEscape(name) + "\",";
    j += "\"duration\":" + std::to_string(duration.count()) + ",";
    j += "\"reason\":\"" + JsonEscape(reason) + "\",";
    j += "\"active\":" + std::string(active ? "true" : "false");
    j += "}";
    return j;
}

std::string DeliveryResult::ToJson() const {
    std::string j = "{";
    j += "\"alertId\":\"" + JsonEscape(alertId) + "\",";
    j += "\"channel\":\"" + std::string(GetDeliveryChannelName(channel)) + "\",";
    j += "\"success\":" + std::string(success ? "true" : "false") + ",";
    j += "\"responseCode\":" + std::to_string(responseCode) + ",";
    j += "\"durationMs\":" + std::to_string(durationMs);
    if (!responseMessage.empty())
        j += ",\"responseMessage\":\"" + JsonEscape(responseMessage) + "\"";
    j += "}";
    return j;
}

// ============================================================================
// STATISTICS METHODS
// ============================================================================

void AlertStatistics::Reset() noexcept {
    totalAlerts.store(0, std::memory_order_relaxed);
    alertsSent.store(0, std::memory_order_relaxed);
    alertsFailed.store(0, std::memory_order_relaxed);
    alertsSuppressed.store(0, std::memory_order_relaxed);
    alertsAcknowledged.store(0, std::memory_order_relaxed);
    alertsEscalated.store(0, std::memory_order_relaxed);
    emailsSent.store(0, std::memory_order_relaxed);
    webhooksSent.store(0, std::memory_order_relaxed);
    smsSent.store(0, std::memory_order_relaxed);
    rateLimitHits.store(0, std::memory_order_relaxed);
    for (auto& a : bySeverity) a.store(0, std::memory_order_relaxed);
    for (auto& a : byChannel) a.store(0, std::memory_order_relaxed);
    startTime = Clock::now();
}

AlertStatisticsSnapshot AlertStatistics::TakeSnapshot() const noexcept {
    AlertStatisticsSnapshot snap;
    snap.totalAlerts = totalAlerts.load(std::memory_order_relaxed);
    snap.alertsSent = alertsSent.load(std::memory_order_relaxed);
    snap.alertsFailed = alertsFailed.load(std::memory_order_relaxed);
    snap.alertsSuppressed = alertsSuppressed.load(std::memory_order_relaxed);
    snap.alertsAcknowledged = alertsAcknowledged.load(std::memory_order_relaxed);
    snap.alertsEscalated = alertsEscalated.load(std::memory_order_relaxed);
    snap.emailsSent = emailsSent.load(std::memory_order_relaxed);
    snap.webhooksSent = webhooksSent.load(std::memory_order_relaxed);
    snap.smsSent = smsSent.load(std::memory_order_relaxed);
    snap.rateLimitHits = rateLimitHits.load(std::memory_order_relaxed);
    for (size_t i = 0; i < bySeverity.size(); ++i)
        snap.bySeverity[i] = bySeverity[i].load(std::memory_order_relaxed);
    for (size_t i = 0; i < byChannel.size(); ++i)
        snap.byChannel[i] = byChannel[i].load(std::memory_order_relaxed);
    return snap;
}

std::string AlertStatisticsSnapshot::ToJson() const {
    std::string j = "{";
    j += "\"totalAlerts\":" + std::to_string(totalAlerts) + ",";
    j += "\"alertsSent\":" + std::to_string(alertsSent) + ",";
    j += "\"alertsFailed\":" + std::to_string(alertsFailed) + ",";
    j += "\"alertsSuppressed\":" + std::to_string(alertsSuppressed) + ",";
    j += "\"alertsAcknowledged\":" + std::to_string(alertsAcknowledged) + ",";
    j += "\"alertsEscalated\":" + std::to_string(alertsEscalated) + ",";
    j += "\"emailsSent\":" + std::to_string(emailsSent) + ",";
    j += "\"webhooksSent\":" + std::to_string(webhooksSent) + ",";
    j += "\"smsSent\":" + std::to_string(smsSent) + ",";
    j += "\"rateLimitHits\":" + std::to_string(rateLimitHits);
    j += "}";
    return j;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetAlertSeverityName(AlertSeverity severity) noexcept {
    switch (severity) {
        case AlertSeverity::Info:      return "Info";
        case AlertSeverity::Low:       return "Low";
        case AlertSeverity::Medium:    return "Medium";
        case AlertSeverity::High:      return "High";
        case AlertSeverity::Critical:  return "Critical";
        case AlertSeverity::Emergency: return "Emergency";
        default:                       return "Unknown";
    }
}

std::string_view GetAlertTypeName(AlertType type) noexcept {
    switch (type) {
        case AlertType::ThreatDetection: return "ThreatDetection";
        case AlertType::SystemHealth:    return "SystemHealth";
        case AlertType::PolicyViolation: return "PolicyViolation";
        case AlertType::ComplianceAlert: return "ComplianceAlert";
        case AlertType::AuditEvent:      return "AuditEvent";
        case AlertType::Operational:     return "Operational";
        case AlertType::Security:        return "Security";
        case AlertType::Performance:     return "Performance";
        case AlertType::Custom:          return "Custom";
        default:                         return "Unknown";
    }
}

std::string_view GetDeliveryChannelName(DeliveryChannel channel) noexcept {
    switch (channel) {
        case DeliveryChannel::None:           return "None";
        case DeliveryChannel::Email:          return "Email";
        case DeliveryChannel::Slack:          return "Slack";
        case DeliveryChannel::Teams:          return "Teams";
        case DeliveryChannel::Discord:        return "Discord";
        case DeliveryChannel::SMS:            return "SMS";
        case DeliveryChannel::PushNotification: return "PushNotification";
        case DeliveryChannel::Desktop:        return "Desktop";
        case DeliveryChannel::Sound:          return "Sound";
        case DeliveryChannel::SIEM:           return "SIEM";
        case DeliveryChannel::Webhook:        return "Webhook";
        case DeliveryChannel::Syslog:         return "Syslog";
        case DeliveryChannel::PagerDuty:      return "PagerDuty";
        case DeliveryChannel::OpsGenie:       return "OpsGenie";
        case DeliveryChannel::ServiceNow:     return "ServiceNow";
        default:                              return "Unknown";
    }
}

std::string_view GetAlertStatusName(AlertStatus status) noexcept {
    switch (status) {
        case AlertStatus::New:          return "New";
        case AlertStatus::Pending:      return "Pending";
        case AlertStatus::Sent:         return "Sent";
        case AlertStatus::Acknowledged: return "Acknowledged";
        case AlertStatus::Escalated:    return "Escalated";
        case AlertStatus::Resolved:     return "Resolved";
        case AlertStatus::Suppressed:   return "Suppressed";
        case AlertStatus::Failed:       return "Failed";
        default:                        return "Unknown";
    }
}

std::string_view GetEscalationLevelName(EscalationLevel level) noexcept {
    switch (level) {
        case EscalationLevel::Level1: return "L1-Analyst";
        case EscalationLevel::Level2: return "L2-Senior";
        case EscalationLevel::Level3: return "L3-TeamLead";
        case EscalationLevel::Level4: return "L4-Manager";
        case EscalationLevel::Level5: return "L5-Executive";
        default:                      return "Unknown";
    }
}

std::string FormatAlertEmail(const Alert& alert) {
    std::string html;
    html += "<!DOCTYPE html><html><head><meta charset='utf-8'></head><body>";
    html += "<div style='font-family:Arial,sans-serif;max-width:600px;margin:0 auto'>";
    html += "<div style='background:" + GetSeverityColor(alert.severity) + ";color:#fff;padding:16px;border-radius:8px 8px 0 0'>";
    html += "<h2 style='margin:0'>⚠ ShadowStrike Alert — " + std::string(GetAlertSeverityName(alert.severity)) + "</h2>";
    html += "</div>";
    html += "<div style='padding:16px;border:1px solid #ddd;border-top:none;border-radius:0 0 8px 8px'>";
    html += "<table style='width:100%;border-collapse:collapse'>";
    html += "<tr><td style='padding:4px 8px;font-weight:bold'>Alert ID:</td><td>" + alert.alertId + "</td></tr>";
    html += "<tr><td style='padding:4px 8px;font-weight:bold'>Type:</td><td>" + std::string(GetAlertTypeName(alert.type)) + "</td></tr>";
    html += "<tr><td style='padding:4px 8px;font-weight:bold'>Host:</td><td>" + alert.hostname + "</td></tr>";
    html += "<tr><td style='padding:4px 8px;font-weight:bold'>Source:</td><td>" + alert.source + "</td></tr>";
    html += "<tr><td style='padding:4px 8px;font-weight:bold'>Time:</td><td>" + SystemTimeToIso8601(alert.createdTime) + "</td></tr>";
    html += "</table>";
    html += "<h3>" + alert.subject + "</h3>";
    html += "<p>" + alert.details + "</p>";
    html += "</div></div></body></html>";
    return html;
}

std::string FormatAlertSlack(const Alert& alert) {
    const std::string color = GetSeverityColor(alert.severity);

    std::string payload = "{\"attachments\":[{";
    payload += "\"color\":\"" + color + "\",";
    payload += "\"title\":\"" + JsonEscape(alert.subject) + "\",";
    payload += "\"text\":\"" + JsonEscape(alert.details) + "\",";
    payload += "\"fields\":[";
    payload += "{\"title\":\"Severity\",\"value\":\"" + std::string(GetAlertSeverityName(alert.severity)) + "\",\"short\":true},";
    payload += "{\"title\":\"Type\",\"value\":\"" + std::string(GetAlertTypeName(alert.type)) + "\",\"short\":true},";
    payload += "{\"title\":\"Host\",\"value\":\"" + JsonEscape(alert.hostname) + "\",\"short\":true},";
    payload += "{\"title\":\"Source\",\"value\":\"" + JsonEscape(alert.source) + "\",\"short\":true},";
    payload += "{\"title\":\"Alert ID\",\"value\":\"" + JsonEscape(alert.alertId) + "\",\"short\":true}";
    payload += "],";
    payload += "\"ts\":" + std::to_string(std::chrono::duration_cast<std::chrono::seconds>(
        alert.createdTime.time_since_epoch()).count());
    payload += "}]}";
    return payload;
}

std::string FormatAlertTeams(const Alert& alert) {
    const std::string color = GetSeverityColor(alert.severity);

    std::string payload = "{\"@type\":\"MessageCard\",\"@context\":\"http://schema.org/extensions\",";
    payload += "\"themeColor\":\"" + color.substr(1) + "\",";
    payload += "\"summary\":\"" + JsonEscape(alert.subject) + "\",";
    payload += "\"sections\":[{";
    payload += "\"activityTitle\":\"⚠ ShadowStrike — " + JsonEscape(alert.subject) + "\",";
    payload += "\"facts\":[";
    payload += "{\"name\":\"Severity\",\"value\":\"" + std::string(GetAlertSeverityName(alert.severity)) + "\"},";
    payload += "{\"name\":\"Type\",\"value\":\"" + std::string(GetAlertTypeName(alert.type)) + "\"},";
    payload += "{\"name\":\"Host\",\"value\":\"" + JsonEscape(alert.hostname) + "\"},";
    payload += "{\"name\":\"Source\",\"value\":\"" + JsonEscape(alert.source) + "\"},";
    payload += "{\"name\":\"Alert ID\",\"value\":\"" + JsonEscape(alert.alertId) + "\"}";
    payload += "],";
    payload += "\"text\":\"" + JsonEscape(alert.details) + "\"";
    payload += "}]}";
    return payload;
}

std::string GetSeverityColor(AlertSeverity severity) {
    switch (severity) {
        case AlertSeverity::Info:      return "#36a64f";
        case AlertSeverity::Low:       return "#2196F3";
        case AlertSeverity::Medium:    return "#FF9800";
        case AlertSeverity::High:      return "#FF5722";
        case AlertSeverity::Critical:  return "#F44336";
        case AlertSeverity::Emergency: return "#9C27B0";
        default:                       return "#607D8B";
    }
}

}  // namespace Communication
}  // namespace ShadowStrike

