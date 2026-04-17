#include "pch.h"
#include "Products/Community/PhantomEDR/IncidentResponse/AlertCorrelator.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <format>
#include <iterator>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <ranges>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include "Products/Community/PhantomEDR/IncidentResponse/IncidentManager.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"

namespace ShadowStrike::Products::PhantomEDR::IncidentResponse {

namespace {

using json = nlohmann::json;
using Clock = std::chrono::system_clock;
using ShadowStrike::Communication::Alert;
using ShadowStrike::Communication::AlertSeverity;
using ShadowStrike::Communication::AlertType;
using ShadowStrike::Products::PhantomEDR::Telemetry::EventSeverity;
using ShadowStrike::Products::PhantomEDR::Telemetry::FileEventData;
using ShadowStrike::Products::PhantomEDR::Telemetry::TelemetryEvent;
using ShadowStrike::Utils::Logger;

constexpr wchar_t kWideLogCategory[] = L"IncidentResponse";
constexpr std::string_view kLogPrefix = "[AlertCorrelator]";
constexpr auto kDefaultCorrelationWindow = std::chrono::minutes(5);
constexpr auto kWorkerWakeInterval = std::chrono::seconds(30);
constexpr auto kEscalationWindow = std::chrono::seconds(60);
constexpr size_t kMaxBufferedAlerts = 4096;
constexpr size_t kMaxBufferedEvents = 4096;

enum class CandidateKind : uint8_t {
    SameHost = 0,
    SameProcess = 1,
    KillChain = 2,
    Rule = 3
};

enum class KillChainStage : uint8_t {
    Recon = 0,
    InitialAccess = 1,
    Execution = 2,
    Persistence = 3
};

struct CorrelatedAlertRecord {
    Alert alert;
    Clock::time_point observedAt{};
    std::optional<uint32_t> processId;
    std::vector<std::string> mitreAttackIds;
    std::vector<std::wstring> filePaths;
};

struct CorrelationCandidate {
    CandidateKind kind = CandidateKind::SameHost;
    std::vector<std::string> entityKeys;
    std::string fingerprintKey;
    std::string reason;
    std::string title;
    std::string description;
    std::vector<CorrelatedAlertRecord> alerts;
    std::vector<TelemetryEvent> events;
    std::vector<std::string> mitreAttackIds;
    std::vector<std::wstring> affectedFiles;
    std::vector<uint32_t> affectedProcessIds;
    IncidentSeverity severity = IncidentSeverity::Medium;
    double score = 0.0;
};

template <typename T>
void AppendUnique(std::vector<T>& target, const T& value)
{
    if (std::find(target.begin(), target.end(), value) == target.end()) {
        target.push_back(value);
    }
}

template <typename T>
void AppendUniqueRange(std::vector<T>& target, const std::vector<T>& values)
{
    for (const auto& value : values) {
        AppendUnique(target, value);
    }
}

[[nodiscard]] std::string JoinStrings(const std::vector<std::string>& values, std::string_view separator)
{
    std::string output;
    for (size_t index = 0; index < values.size(); ++index) {
        if (index > 0) {
            output.append(separator);
        }
        output.append(values[index]);
    }
    return output;
}

[[nodiscard]] std::optional<json> ParseMetadata(std::string_view metadata)
{
    if (metadata.empty()) {
        return std::nullopt;
    }

    try {
        return json::parse(metadata, nullptr, true, true);
    }
    catch (const std::exception& ex) {
        Logger::Debug("{} Invalid alert metadata ignored: {}", kLogPrefix, ex.what());
        return std::nullopt;
    }
}

[[nodiscard]] std::optional<uint32_t> ExtractAlertProcessId(const Alert& alert)
{
    const auto metadata = ParseMetadata(alert.metadata);
    if (!metadata.has_value() || !metadata->is_object()) {
        return std::nullopt;
    }

    static constexpr std::array<std::string_view, 3> kProcessIdKeys = {
        "processId",
        "process_id",
        "pid"
    };

    for (const auto key : kProcessIdKeys) {
        const auto it = metadata->find(key);
        if (it == metadata->end()) {
            continue;
        }

        if (it->is_number_unsigned()) {
            return it->get<uint32_t>();
        }
        if (it->is_number_integer()) {
            const auto value = it->get<int64_t>();
            if (value >= 0 && value <= std::numeric_limits<uint32_t>::max()) {
                return static_cast<uint32_t>(value);
            }
        }
        if (it->is_string()) {
            try {
                const auto parsed = std::stoull(it->get<std::string>());
                if (parsed <= std::numeric_limits<uint32_t>::max()) {
                    return static_cast<uint32_t>(parsed);
                }
            }
            catch (...) {
            }
        }
    }

    return std::nullopt;
}

[[nodiscard]] std::vector<std::string> ExtractMitreAttackIds(const Alert& alert)
{
    std::vector<std::string> mitreIds;
    const auto metadata = ParseMetadata(alert.metadata);
    if (!metadata.has_value() || !metadata->is_object()) {
        return mitreIds;
    }

    static constexpr std::array<std::string_view, 4> kArrayKeys = {
        "mitreAttackIds",
        "mitre_attack_ids",
        "mitreAttackId",
        "mitre_attack_id"
    };

    for (const auto key : kArrayKeys) {
        const auto it = metadata->find(key);
        if (it == metadata->end()) {
            continue;
        }

        if (it->is_string()) {
            AppendUnique(mitreIds, it->get<std::string>());
            continue;
        }

        if (!it->is_array()) {
            continue;
        }

        for (const auto& item : *it) {
            if (item.is_string()) {
                AppendUnique(mitreIds, item.get<std::string>());
            }
        }
    }

    return mitreIds;
}

[[nodiscard]] std::vector<std::wstring> ExtractAlertFilePaths(const Alert& alert)
{
    std::vector<std::wstring> filePaths;
    const auto metadata = ParseMetadata(alert.metadata);
    if (!metadata.has_value() || !metadata->is_object()) {
        return filePaths;
    }

    static constexpr std::array<std::string_view, 5> kFileKeys = {
        "filePath",
        "path",
        "file",
        "targetPath",
        "affectedFiles"
    };

    for (const auto key : kFileKeys) {
        const auto it = metadata->find(key);
        if (it == metadata->end()) {
            continue;
        }

        if (it->is_string()) {
            AppendUnique(filePaths, ShadowStrike::Utils::StringUtils::ToWide(it->get<std::string>()));
            continue;
        }

        if (!it->is_array()) {
            continue;
        }

        for (const auto& item : *it) {
            if (item.is_string()) {
                AppendUnique(filePaths, ShadowStrike::Utils::StringUtils::ToWide(item.get<std::string>()));
            }
        }
    }

    return filePaths;
}

[[nodiscard]] IncidentSeverity ToIncidentSeverity(const AlertSeverity severity) noexcept
{
    switch (severity) {
        case AlertSeverity::Info:      return IncidentSeverity::Info;
        case AlertSeverity::Low:       return IncidentSeverity::Low;
        case AlertSeverity::Medium:    return IncidentSeverity::Medium;
        case AlertSeverity::High:      return IncidentSeverity::High;
        case AlertSeverity::Critical:
        case AlertSeverity::Emergency: return IncidentSeverity::Critical;
    }

    return IncidentSeverity::Medium;
}

[[nodiscard]] IncidentSeverity ToIncidentSeverity(const EventSeverity severity) noexcept
{
    switch (severity) {
        case EventSeverity::Info:     return IncidentSeverity::Info;
        case EventSeverity::Low:      return IncidentSeverity::Low;
        case EventSeverity::Medium:   return IncidentSeverity::Medium;
        case EventSeverity::High:     return IncidentSeverity::High;
        case EventSeverity::Critical: return IncidentSeverity::Critical;
    }

    return IncidentSeverity::Medium;
}

[[nodiscard]] int SeverityRank(const IncidentSeverity severity) noexcept
{
    return static_cast<int>(severity);
}

[[nodiscard]] IncidentSeverity MaxSeverity(const IncidentSeverity lhs, const IncidentSeverity rhs) noexcept
{
    return SeverityRank(lhs) >= SeverityRank(rhs) ? lhs : rhs;
}

[[nodiscard]] IncidentSeverity EscalateSeverity(const IncidentSeverity severity) noexcept
{
    switch (severity) {
        case IncidentSeverity::Info:     return IncidentSeverity::Low;
        case IncidentSeverity::Low:      return IncidentSeverity::Medium;
        case IncidentSeverity::Medium:   return IncidentSeverity::High;
        case IncidentSeverity::High:
        case IncidentSeverity::Critical: return IncidentSeverity::Critical;
    }

    return IncidentSeverity::Critical;
}

[[nodiscard]] double SeverityWeight(const IncidentSeverity severity) noexcept
{
    switch (severity) {
        case IncidentSeverity::Info:     return 10.0;
        case IncidentSeverity::Low:      return 25.0;
        case IncidentSeverity::Medium:   return 45.0;
        case IncidentSeverity::High:     return 65.0;
        case IncidentSeverity::Critical: return 85.0;
    }

    return 45.0;
}

[[nodiscard]] bool StartsWithAny(std::string_view value, const std::initializer_list<std::string_view> prefixes)
{
    for (const auto prefix : prefixes) {
        if (value.starts_with(prefix)) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] std::optional<KillChainStage> GetKillChainStage(std::string_view mitreId)
{
    if (StartsWithAny(mitreId, {"T159", "T1046", "T1595"})) {
        return KillChainStage::Recon;
    }
    if (StartsWithAny(mitreId, {"T1566", "T1190", "T1133", "T1189", "T1078"})) {
        return KillChainStage::InitialAccess;
    }
    if (StartsWithAny(mitreId, {"T1059", "T1204", "T1047", "T1106", "T1559"})) {
        return KillChainStage::Execution;
    }
    if (StartsWithAny(mitreId, {"T1547", "T1543", "T1546", "T1053", "T1136", "T1574"})) {
        return KillChainStage::Persistence;
    }
    return std::nullopt;
}

[[nodiscard]] std::wstring ExtractFilePathFromEvent(const TelemetryEvent& event)
{
    if (std::holds_alternative<FileEventData>(event.payload)) {
        return std::get<FileEventData>(event.payload).filePath;
    }
    return {};
}

[[nodiscard]] CorrelatedAlertRecord MakeAlertRecord(const Alert& alert)
{
    CorrelatedAlertRecord record;
    record.alert = alert;
    record.observedAt = alert.createdTime.time_since_epoch().count() == 0 ? Clock::now() : alert.createdTime;
    record.processId = ExtractAlertProcessId(alert);
    record.mitreAttackIds = ExtractMitreAttackIds(alert);
    record.filePaths = ExtractAlertFilePaths(alert);
    return record;
}

[[nodiscard]] std::string DeterminePrimaryEntity(const CorrelationCandidate& candidate)
{
    if (!candidate.entityKeys.empty()) {
        return candidate.entityKeys.front();
    }
    return candidate.fingerprintKey;
}

[[nodiscard]] std::string BuildFingerprint(const CorrelationCandidate& candidate)
{
    std::vector<std::string> alertIds;
    alertIds.reserve(candidate.alerts.size());
    for (const auto& alert : candidate.alerts) {
        if (!alert.alert.alertId.empty()) {
            alertIds.push_back(alert.alert.alertId);
        }
    }
    std::sort(alertIds.begin(), alertIds.end());
    return std::format("{}|{}", candidate.fingerprintKey, JoinStrings(alertIds, ","));
}

[[nodiscard]] double CalculateScore(const CorrelationCandidate& candidate, const std::chrono::seconds window)
{
    if (candidate.alerts.empty()) {
        return 0.0;
    }

    auto earliest = candidate.alerts.front().observedAt;
    auto latest = candidate.alerts.front().observedAt;
    for (const auto& alert : candidate.alerts) {
        earliest = std::min(earliest, alert.observedAt);
        latest = std::max(latest, alert.observedAt);
    }

    const auto spanSeconds = std::max<int64_t>(
        1,
        std::chrono::duration_cast<std::chrono::seconds>(latest - earliest).count());
    const auto windowSeconds = std::max<int64_t>(1, window.count());
    const auto density = 1.0 - std::clamp(static_cast<double>(spanSeconds) / static_cast<double>(windowSeconds), 0.0, 1.0);

    const double countComponent = std::min(25.0, static_cast<double>(candidate.alerts.size()) * 5.0);
    const double attackComponent = std::min(20.0, static_cast<double>(candidate.mitreAttackIds.size()) * 4.0);
    const double densityComponent = density * 15.0;
    const double kindBonus = candidate.kind == CandidateKind::KillChain ? 10.0 : 0.0;

    return std::clamp(
        SeverityWeight(candidate.severity) + countComponent + attackComponent + densityComponent + kindBonus,
        0.0,
        100.0);
}

} // namespace

class AlertCorrelatorImpl {
public:
    [[nodiscard]] bool Initialize();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const;

    void IngestAlert(const Alert& alert);
    void IngestTelemetryEvent(const TelemetryEvent& event);

    [[nodiscard]] bool AddCorrelationRule(const CorrelationRule& rule);
    [[nodiscard]] bool RemoveCorrelationRule(std::string_view ruleId);
    [[nodiscard]] std::vector<CorrelationRule> GetCorrelationRules() const;

    void FlushPendingCorrelations();

    [[nodiscard]] uint64_t GetTotalAlertsProcessed() const noexcept
    {
        return m_totalAlertsProcessed.load(std::memory_order_relaxed);
    }

    [[nodiscard]] uint64_t GetTotalIncidentsCreated() const noexcept
    {
        return m_totalIncidentsCreated.load(std::memory_order_relaxed);
    }

private:
    void WorkerLoop(std::stop_token stopToken);
    void PruneExpiredStateUnlocked(const Clock::time_point& now);
    [[nodiscard]] std::vector<CorrelationCandidate> BuildCandidates(
        const std::vector<CorrelatedAlertRecord>& alerts,
        const std::vector<TelemetryEvent>& events,
        const std::vector<CorrelationRule>& rules) const;
    [[nodiscard]] std::vector<CorrelationCandidate> BuildSameHostCandidates(
        const std::vector<CorrelatedAlertRecord>& alerts,
        const std::vector<TelemetryEvent>& events) const;
    [[nodiscard]] std::vector<CorrelationCandidate> BuildSameProcessCandidates(
        const std::vector<CorrelatedAlertRecord>& alerts,
        const std::vector<TelemetryEvent>& events) const;
    [[nodiscard]] std::vector<CorrelationCandidate> BuildKillChainCandidates(
        const std::vector<CorrelatedAlertRecord>& alerts,
        const std::vector<TelemetryEvent>& events) const;
    [[nodiscard]] std::vector<CorrelationCandidate> BuildRuleCandidates(
        const std::vector<CorrelatedAlertRecord>& alerts,
        const std::vector<CorrelationRule>& rules) const;
    void EnrichCandidate(CorrelationCandidate& candidate, const std::chrono::seconds& window) const;
    [[nodiscard]] bool HasRecentFingerprint(std::string_view fingerprint) const;
    void RememberFingerprint(const std::string& fingerprint, const Clock::time_point& now);
    [[nodiscard]] std::optional<std::string> FindActiveIncidentId(const std::vector<std::string>& keys) const;
    void BindIncidentKeys(const std::vector<std::string>& keys, const std::string& incidentId);
    void UnbindClosedIncidentKeys(const std::string& incidentId);
    void CreateOrUpdateIncident(const CorrelationCandidate& candidate);

    mutable std::shared_mutex m_stateMutex;
    std::deque<CorrelatedAlertRecord> m_recentAlerts;
    std::deque<TelemetryEvent> m_recentEvents;
    std::vector<CorrelationRule> m_rules;
    std::unordered_map<std::string, std::string> m_entityIncidentMap;
    std::unordered_map<std::string, Clock::time_point> m_recentFingerprints;

    std::mutex m_signalMutex;
    std::mutex m_flushMutex;
    std::condition_variable m_signalCondition;
    bool m_pendingWork = false;
    std::jthread m_workerThread;
    std::atomic<bool> m_initialized{false};
    std::atomic<uint64_t> m_totalAlertsProcessed{0};
    std::atomic<uint64_t> m_totalIncidentsCreated{0};
};

bool AlertCorrelatorImpl::Initialize()
{
    bool expected = false;
    if (!m_initialized.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        Logger::Debug("{} Already initialized", kLogPrefix);
        return true;
    }

    if (!IncidentManager::Instance().IsInitialized() && !IncidentManager::Instance().Initialize()) {
        m_initialized.store(false, std::memory_order_release);
        Logger::Error("{} IncidentManager initialization failed", kLogPrefix);
        return false;
    }

    {
        std::unique_lock lock(m_stateMutex);
        m_recentAlerts.clear();
        m_recentEvents.clear();
        m_entityIncidentMap.clear();
        m_recentFingerprints.clear();
        m_rules.clear();
        m_rules.push_back(
            CorrelationRule{
                .ruleId = "default-threat-burst",
                .name = "Threat burst per host",
                .description = "Correlates multiple threat-detection alerts on the same host.",
                .timeWindowSeconds = static_cast<uint32_t>(kDefaultCorrelationWindow.count()),
                .minAlertCount = 3,
                .requiredAlertTypes = {AlertType::ThreatDetection},
                .minSeverity = IncidentSeverity::Medium,
                .enabled = true
            });
        m_rules.push_back(
            CorrelationRule{
                .ruleId = "default-policy-mixed-signal",
                .name = "Mixed policy and security activity",
                .description = "Escalates when policy violations and security alerts co-occur.",
                .timeWindowSeconds = static_cast<uint32_t>(kDefaultCorrelationWindow.count()),
                .minAlertCount = 2,
                .requiredAlertTypes = {AlertType::PolicyViolation, AlertType::Security},
                .minSeverity = IncidentSeverity::Medium,
                .enabled = true
            });
    }

    m_totalAlertsProcessed.store(0, std::memory_order_relaxed);
    m_totalIncidentsCreated.store(0, std::memory_order_relaxed);
    m_workerThread = std::jthread([this](std::stop_token token) { WorkerLoop(token); });

    Logger::Info("{} Initialized correlation engine with {} second window", kLogPrefix, kDefaultCorrelationWindow.count());
    return true;
}

void AlertCorrelatorImpl::Shutdown()
{
    if (!m_initialized.exchange(false, std::memory_order_acq_rel)) {
        return;
    }

    if (m_workerThread.joinable()) {
        m_workerThread.request_stop();
        {
            std::lock_guard lock(m_signalMutex);
            m_pendingWork = true;
        }
        m_signalCondition.notify_all();
        m_workerThread.join();
    }

    std::unique_lock lock(m_stateMutex);
    m_recentAlerts.clear();
    m_recentEvents.clear();
    m_rules.clear();
    m_entityIncidentMap.clear();
    m_recentFingerprints.clear();

    Logger::Info("{} Shutdown complete", kLogPrefix);
}

bool AlertCorrelatorImpl::IsInitialized() const
{
    return m_initialized.load(std::memory_order_acquire);
}

void AlertCorrelatorImpl::IngestAlert(const Alert& alert)
{
    if (!IsInitialized()) {
        return;
    }

    {
        std::unique_lock lock(m_stateMutex);
        m_recentAlerts.push_back(MakeAlertRecord(alert));
        const auto now = Clock::now();
        PruneExpiredStateUnlocked(now);
        while (m_recentAlerts.size() > kMaxBufferedAlerts) {
            m_recentAlerts.pop_front();
        }
    }

    m_totalAlertsProcessed.fetch_add(1, std::memory_order_relaxed);
    {
        std::lock_guard lock(m_signalMutex);
        m_pendingWork = true;
    }
    m_signalCondition.notify_one();
}

void AlertCorrelatorImpl::IngestTelemetryEvent(const TelemetryEvent& event)
{
    if (!IsInitialized()) {
        return;
    }

    {
        std::unique_lock lock(m_stateMutex);
        m_recentEvents.push_back(event);
        const auto now = Clock::now();
        PruneExpiredStateUnlocked(now);
        while (m_recentEvents.size() > kMaxBufferedEvents) {
            m_recentEvents.pop_front();
        }
    }

    {
        std::lock_guard lock(m_signalMutex);
        m_pendingWork = true;
    }
    m_signalCondition.notify_one();
}

bool AlertCorrelatorImpl::AddCorrelationRule(const CorrelationRule& rule)
{
    if (!IsInitialized() || rule.ruleId.empty() || rule.name.empty() || rule.minAlertCount == 0) {
        return false;
    }

    std::unique_lock lock(m_stateMutex);
    const auto existing = std::ranges::find(m_rules, rule.ruleId, &CorrelationRule::ruleId);
    if (existing != m_rules.end()) {
        *existing = rule;
    } else {
        m_rules.push_back(rule);
    }
    return true;
}

bool AlertCorrelatorImpl::RemoveCorrelationRule(std::string_view ruleId)
{
    if (!IsInitialized() || ruleId.empty()) {
        return false;
    }

    std::unique_lock lock(m_stateMutex);
    const auto originalSize = m_rules.size();
    std::erase_if(m_rules, [ruleId](const CorrelationRule& rule) {
        return rule.ruleId == ruleId;
    });
    return m_rules.size() != originalSize;
}

std::vector<CorrelationRule> AlertCorrelatorImpl::GetCorrelationRules() const
{
    std::shared_lock lock(m_stateMutex);
    return m_rules;
}

void AlertCorrelatorImpl::WorkerLoop(std::stop_token stopToken)
{
    while (!stopToken.stop_requested()) {
        std::unique_lock lock(m_signalMutex);
        m_signalCondition.wait_for(
            lock,
            kWorkerWakeInterval,
            [this, &stopToken]() {
                return stopToken.stop_requested() || m_pendingWork;
            });
        m_pendingWork = false;
        lock.unlock();

        if (stopToken.stop_requested()) {
            break;
        }

        FlushPendingCorrelations();
    }
}

void AlertCorrelatorImpl::PruneExpiredStateUnlocked(const Clock::time_point& now)
{
    const auto cutoff = now - kDefaultCorrelationWindow;
    while (!m_recentAlerts.empty() && m_recentAlerts.front().observedAt < cutoff) {
        m_recentAlerts.pop_front();
    }
    while (!m_recentEvents.empty() && m_recentEvents.front().timestamp < cutoff) {
        m_recentEvents.pop_front();
    }

    for (auto it = m_recentFingerprints.begin(); it != m_recentFingerprints.end();) {
        if (it->second < cutoff) {
            it = m_recentFingerprints.erase(it);
        } else {
            ++it;
        }
    }
}

std::vector<CorrelationCandidate> AlertCorrelatorImpl::BuildSameHostCandidates(
    const std::vector<CorrelatedAlertRecord>& alerts,
    const std::vector<TelemetryEvent>& events) const
{
    std::unordered_map<std::string, std::vector<CorrelatedAlertRecord>> alertsByHost;
    for (const auto& alert : alerts) {
        if (!alert.alert.hostname.empty()) {
            alertsByHost[alert.alert.hostname].push_back(alert);
        }
    }

    std::vector<CorrelationCandidate> candidates;
    for (auto& [hostname, hostAlerts] : alertsByHost) {
        if (hostAlerts.size() < 2) {
            continue;
        }

        CorrelationCandidate candidate;
        candidate.kind = CandidateKind::SameHost;
        candidate.entityKeys.push_back("host:" + hostname);
        candidate.fingerprintKey = "same-host:" + hostname;
        candidate.reason = "Same-host correlation";
        candidate.title = std::format("Correlated threat activity on host {}", hostname);
        candidate.description = std::format(
            "{} alerts were raised for host {} within the active correlation window.",
            hostAlerts.size(),
            hostname);
        candidate.alerts = std::move(hostAlerts);

        std::unordered_set<uint32_t> processIds;
        for (const auto& alert : candidate.alerts) {
            if (alert.processId.has_value()) {
                processIds.insert(*alert.processId);
            }
        }
        for (const auto& event : events) {
            if (event.processId != 0 && processIds.contains(event.processId)) {
                candidate.events.push_back(event);
            }
        }

        candidates.push_back(std::move(candidate));
    }

    return candidates;
}

std::vector<CorrelationCandidate> AlertCorrelatorImpl::BuildSameProcessCandidates(
    const std::vector<CorrelatedAlertRecord>& alerts,
    const std::vector<TelemetryEvent>& events) const
{
    std::unordered_map<uint32_t, std::vector<CorrelatedAlertRecord>> alertsByProcess;
    for (const auto& alert : alerts) {
        if (alert.processId.has_value() && *alert.processId != 0) {
            alertsByProcess[*alert.processId].push_back(alert);
        }
    }

    std::unordered_map<uint32_t, std::vector<TelemetryEvent>> eventsByProcess;
    for (const auto& event : events) {
        if (event.processId != 0) {
            eventsByProcess[event.processId].push_back(event);
        }
    }

    std::vector<CorrelationCandidate> candidates;
    for (auto& [processId, processAlerts] : alertsByProcess) {
        auto processEventsIt = eventsByProcess.find(processId);
        const size_t eventCount = processEventsIt == eventsByProcess.end() ? 0 : processEventsIt->second.size();
        if (processAlerts.size() < 2 && eventCount < 2) {
            continue;
        }

        CorrelationCandidate candidate;
        candidate.kind = CandidateKind::SameProcess;
        const std::string processKey = "proc:" + std::to_string(processId);
        candidate.entityKeys.push_back(processKey);
        if (!processAlerts.empty() && !processAlerts.front().alert.hostname.empty()) {
            candidate.entityKeys.insert(candidate.entityKeys.begin(), "host:" + processAlerts.front().alert.hostname);
        }
        candidate.fingerprintKey = "same-process:" + std::to_string(processId);
        candidate.reason = "Same-process correlation";
        candidate.title = std::format("Correlated threat activity for process {}", processId);
        candidate.description = std::format(
            "Multiple alerts and telemetry events reference process {} inside the active correlation window.",
            processId);
        candidate.alerts = std::move(processAlerts);
        if (processEventsIt != eventsByProcess.end()) {
            candidate.events = processEventsIt->second;
        }
        candidates.push_back(std::move(candidate));
    }

    return candidates;
}

std::vector<CorrelationCandidate> AlertCorrelatorImpl::BuildKillChainCandidates(
    const std::vector<CorrelatedAlertRecord>& alerts,
    const std::vector<TelemetryEvent>& events) const
{
    std::unordered_map<std::string, std::vector<CorrelatedAlertRecord>> groups;
    for (const auto& alert : alerts) {
        std::string key;
        if (!alert.alert.hostname.empty()) {
            key = "host:" + alert.alert.hostname;
        } else if (!alert.alert.userName.empty()) {
            key = "user:" + alert.alert.userName;
        } else if (alert.processId.has_value()) {
            key = "proc:" + std::to_string(*alert.processId);
        }
        if (!key.empty()) {
            groups[key].push_back(alert);
        }
    }

    std::vector<CorrelationCandidate> candidates;
    for (auto& [entityKey, entityAlerts] : groups) {
        std::unordered_set<KillChainStage> stages;
        std::vector<TelemetryEvent> relatedEvents;
        std::unordered_set<uint32_t> processIds;

        for (const auto& alert : entityAlerts) {
            for (const auto& mitreId : alert.mitreAttackIds) {
                if (const auto stage = GetKillChainStage(mitreId); stage.has_value()) {
                    stages.insert(*stage);
                }
            }
            if (alert.processId.has_value()) {
                processIds.insert(*alert.processId);
            }
        }

        for (const auto& event : events) {
            if (event.processId != 0 && processIds.contains(event.processId)) {
                relatedEvents.push_back(event);
                if (!event.mitreAttackId.empty()) {
                    if (const auto stage = GetKillChainStage(event.mitreAttackId); stage.has_value()) {
                        stages.insert(*stage);
                    }
                }
            }
        }

        if (stages.size() < 3 || entityAlerts.size() < 2) {
            continue;
        }

        CorrelationCandidate candidate;
        candidate.kind = CandidateKind::KillChain;
        candidate.entityKeys.push_back(entityKey);
        candidate.entityKeys.push_back("killchain:" + entityKey);
        candidate.fingerprintKey = "killchain:" + entityKey;
        candidate.reason = "Kill-chain progression";
        candidate.title = std::format("Kill-chain progression detected for {}", entityKey);
        candidate.description = std::format(
            "Correlated ATT&CK techniques indicate a recon-to-persistence progression for {}.",
            entityKey);
        candidate.alerts = std::move(entityAlerts);
        candidate.events = std::move(relatedEvents);
        candidates.push_back(std::move(candidate));
    }

    return candidates;
}

std::vector<CorrelationCandidate> AlertCorrelatorImpl::BuildRuleCandidates(
    const std::vector<CorrelatedAlertRecord>& alerts,
    const std::vector<CorrelationRule>& rules) const
{
    const auto now = Clock::now();
    std::vector<CorrelationCandidate> candidates;

    for (const auto& rule : rules) {
        if (!rule.enabled) {
            continue;
        }

        std::unordered_map<std::string, std::vector<CorrelatedAlertRecord>> alertsByEntity;
        const auto cutoff = now - std::chrono::seconds(rule.timeWindowSeconds);
        for (const auto& alert : alerts) {
            if (alert.observedAt < cutoff) {
                continue;
            }

            std::string key;
            if (!alert.alert.hostname.empty()) {
                key = "host:" + alert.alert.hostname;
            } else if (alert.processId.has_value()) {
                key = "proc:" + std::to_string(*alert.processId);
            } else if (!alert.alert.correlationId.empty()) {
                key = "corr:" + alert.alert.correlationId;
            }
            if (!key.empty()) {
                alertsByEntity[key].push_back(alert);
            }
        }

        for (auto& [entityKey, entityAlerts] : alertsByEntity) {
            if (entityAlerts.size() < rule.minAlertCount) {
                continue;
            }

            std::unordered_set<AlertType> alertTypes;
            IncidentSeverity maxSeverity = IncidentSeverity::Info;
            for (const auto& alert : entityAlerts) {
                alertTypes.insert(alert.alert.type);
                maxSeverity = MaxSeverity(maxSeverity, ToIncidentSeverity(alert.alert.severity));
            }

            if (SeverityRank(maxSeverity) < SeverityRank(rule.minSeverity)) {
                continue;
            }

            bool matchesTypes = true;
            for (const auto type : rule.requiredAlertTypes) {
                if (!alertTypes.contains(type)) {
                    matchesTypes = false;
                    break;
                }
            }
            if (!matchesTypes) {
                continue;
            }

            CorrelationCandidate candidate;
            candidate.kind = CandidateKind::Rule;
            candidate.entityKeys.push_back(entityKey);
            candidate.entityKeys.push_back("rule:" + rule.ruleId + ":" + entityKey);
            candidate.fingerprintKey = "rule:" + rule.ruleId + ":" + entityKey;
            candidate.reason = "Correlation rule match";
            candidate.title = std::format("Correlation rule triggered: {}", rule.name);
            candidate.description = std::format(
                "Rule '{}' triggered for {} with {} qualifying alerts.",
                rule.name,
                entityKey,
                entityAlerts.size());
            candidate.alerts = std::move(entityAlerts);
            candidates.push_back(std::move(candidate));
        }
    }

    return candidates;
}

void AlertCorrelatorImpl::EnrichCandidate(CorrelationCandidate& candidate, const std::chrono::seconds& window) const
{
    IncidentSeverity severity = IncidentSeverity::Info;
    size_t rapidAlertCount = 0;
    const auto now = Clock::now();

    for (const auto& alert : candidate.alerts) {
        severity = MaxSeverity(severity, ToIncidentSeverity(alert.alert.severity));
        AppendUniqueRange(candidate.mitreAttackIds, alert.mitreAttackIds);
        AppendUniqueRange(candidate.affectedFiles, alert.filePaths);
        if (alert.processId.has_value()) {
            AppendUnique(candidate.affectedProcessIds, *alert.processId);
        }
        if (now - alert.observedAt <= kEscalationWindow) {
            ++rapidAlertCount;
        }
    }

    for (const auto& event : candidate.events) {
        severity = MaxSeverity(severity, ToIncidentSeverity(event.severity));
        if (event.processId != 0) {
            AppendUnique(candidate.affectedProcessIds, event.processId);
        }
        if (!event.mitreAttackId.empty()) {
            AppendUnique(candidate.mitreAttackIds, event.mitreAttackId);
        }

        const auto filePath = ExtractFilePathFromEvent(event);
        if (!filePath.empty()) {
            AppendUnique(candidate.affectedFiles, filePath);
        }
    }

    if (rapidAlertCount >= 5) {
        severity = EscalateSeverity(severity);
        candidate.description += " Alert velocity exceeded escalation threshold.";
    }

    candidate.severity = severity;
    candidate.score = CalculateScore(candidate, window);
}

std::vector<CorrelationCandidate> AlertCorrelatorImpl::BuildCandidates(
    const std::vector<CorrelatedAlertRecord>& alerts,
    const std::vector<TelemetryEvent>& events,
    const std::vector<CorrelationRule>& rules) const
{
    std::vector<CorrelationCandidate> candidates;
    auto hostCandidates = BuildSameHostCandidates(alerts, events);
    candidates.insert(
        candidates.end(),
        std::make_move_iterator(hostCandidates.begin()),
        std::make_move_iterator(hostCandidates.end()));

    auto processCandidates = BuildSameProcessCandidates(alerts, events);
    candidates.insert(
        candidates.end(),
        std::make_move_iterator(processCandidates.begin()),
        std::make_move_iterator(processCandidates.end()));

    auto killChainCandidates = BuildKillChainCandidates(alerts, events);
    candidates.insert(
        candidates.end(),
        std::make_move_iterator(killChainCandidates.begin()),
        std::make_move_iterator(killChainCandidates.end()));

    auto ruleCandidates = BuildRuleCandidates(alerts, rules);
    candidates.insert(
        candidates.end(),
        std::make_move_iterator(ruleCandidates.begin()),
        std::make_move_iterator(ruleCandidates.end()));

    for (auto& candidate : candidates) {
        EnrichCandidate(candidate, std::chrono::duration_cast<std::chrono::seconds>(kDefaultCorrelationWindow));
    }

    std::sort(
        candidates.begin(),
        candidates.end(),
        [](const CorrelationCandidate& lhs, const CorrelationCandidate& rhs) {
            return lhs.score > rhs.score;
        });

    return candidates;
}

bool AlertCorrelatorImpl::HasRecentFingerprint(std::string_view fingerprint) const
{
    std::shared_lock lock(m_stateMutex);
    return m_recentFingerprints.contains(std::string(fingerprint));
}

void AlertCorrelatorImpl::RememberFingerprint(const std::string& fingerprint, const Clock::time_point& now)
{
    std::unique_lock lock(m_stateMutex);
    m_recentFingerprints[fingerprint] = now;
}

std::optional<std::string> AlertCorrelatorImpl::FindActiveIncidentId(const std::vector<std::string>& keys) const
{
    std::shared_lock lock(m_stateMutex);
    for (const auto& key : keys) {
        if (const auto it = m_entityIncidentMap.find(key); it != m_entityIncidentMap.end()) {
            return it->second;
        }
    }
    return std::nullopt;
}

void AlertCorrelatorImpl::BindIncidentKeys(const std::vector<std::string>& keys, const std::string& incidentId)
{
    std::unique_lock lock(m_stateMutex);
    for (const auto& key : keys) {
        m_entityIncidentMap[key] = incidentId;
    }
}

void AlertCorrelatorImpl::UnbindClosedIncidentKeys(const std::string& incidentId)
{
    std::unique_lock lock(m_stateMutex);
    for (auto it = m_entityIncidentMap.begin(); it != m_entityIncidentMap.end();) {
        if (it->second == incidentId) {
            it = m_entityIncidentMap.erase(it);
        } else {
            ++it;
        }
    }
}

void AlertCorrelatorImpl::CreateOrUpdateIncident(const CorrelationCandidate& candidate)
{
    const std::string fingerprint = BuildFingerprint(candidate);
    if (HasRecentFingerprint(fingerprint)) {
        return;
    }

    auto existingIncidentId = FindActiveIncidentId(candidate.entityKeys);
    auto& incidentManager = IncidentManager::Instance();
    Incident incident;

    if (existingIncidentId.has_value()) {
        const auto existingIncident = incidentManager.GetIncident(*existingIncidentId);
        if (existingIncident.has_value() &&
            existingIncident->status != IncidentStatus::Closed &&
            existingIncident->status != IncidentStatus::FalsePositive) {
            incident = *existingIncident;
        } else if (existingIncidentId.has_value()) {
            UnbindClosedIncidentKeys(*existingIncidentId);
            existingIncidentId.reset();
        }
    }

    const auto now = Clock::now();
    if (!existingIncidentId.has_value()) {
        incident.incidentId.clear();
        incident.title = candidate.title;
        incident.description = candidate.description;
        incident.severity = candidate.severity;
        incident.status = IncidentStatus::New;
        incident.phase = IncidentPhase::New;
        incident.createdAt = now;
        incident.updatedAt = now;
        incident.score = candidate.score;
        incident.notes.emplace_back(now, std::format("Incident created by {}.", candidate.reason));
    } else {
        incident.title = candidate.title;
        incident.description = candidate.description;
        incident.severity = MaxSeverity(incident.severity, candidate.severity);
        incident.updatedAt = now;
        incident.score = std::max(incident.score, candidate.score);
        incident.notes.emplace_back(
            now,
            std::format(
                "Correlation update: {} with {} alerts and {} telemetry events.",
                candidate.reason,
                candidate.alerts.size(),
                candidate.events.size()));
    }

    for (const auto& alert : candidate.alerts) {
        if (!alert.alert.alertId.empty()) {
            AppendUnique(incident.relatedAlertIds, alert.alert.alertId);
        }
    }
    for (const auto& event : candidate.events) {
        if (event.eventId != 0) {
            AppendUnique(incident.relatedEventIds, event.eventId);
        }
    }
    AppendUniqueRange(incident.mitreAttackIds, candidate.mitreAttackIds);
    AppendUniqueRange(incident.affectedFiles, candidate.affectedFiles);
    AppendUniqueRange(incident.affectedProcessIds, candidate.affectedProcessIds);

    std::string incidentId = existingIncidentId.value_or({});
    if (incidentId.empty()) {
        incidentId = incidentManager.CreateIncident(incident);
        if (incidentId.empty()) {
            return;
        }
        m_totalIncidentsCreated.fetch_add(1, std::memory_order_relaxed);
    } else {
        incident.incidentId = incidentId;
        if (!incidentManager.UpdateIncident(incident)) {
            return;
        }
    }

    BindIncidentKeys(candidate.entityKeys, incidentId);
    RememberFingerprint(fingerprint, now);
    SS_LOG_INFO(
        kWideLogCategory,
        L"Created or updated incident %hs from correlation candidate %hs",
        incidentId.c_str(),
        DeterminePrimaryEntity(candidate).c_str());
}

void AlertCorrelatorImpl::FlushPendingCorrelations()
{
    if (!IsInitialized()) {
        return;
    }

    std::lock_guard flushLock(m_flushMutex);

    std::vector<CorrelatedAlertRecord> alerts;
    std::vector<TelemetryEvent> events;
    std::vector<CorrelationRule> rules;

    {
        std::unique_lock lock(m_stateMutex);
        const auto now = Clock::now();
        PruneExpiredStateUnlocked(now);
        alerts.assign(m_recentAlerts.begin(), m_recentAlerts.end());
        events.assign(m_recentEvents.begin(), m_recentEvents.end());
        rules = m_rules;
    }

    if (alerts.size() < 2) {
        return;
    }

    auto candidates = BuildCandidates(alerts, events, rules);
    for (const auto& candidate : candidates) {
        if (candidate.alerts.size() < 2 || candidate.score < 35.0) {
            continue;
        }
        CreateOrUpdateIncident(candidate);
    }
}

AlertCorrelator& AlertCorrelator::Instance()
{
    static AlertCorrelator instance;
    return instance;
}

AlertCorrelator::AlertCorrelator()
    : m_impl(std::make_unique<AlertCorrelatorImpl>())
{
}

AlertCorrelator::~AlertCorrelator() = default;

bool AlertCorrelator::Initialize()
{
    return m_impl->Initialize();
}

void AlertCorrelator::Shutdown()
{
    m_impl->Shutdown();
}

bool AlertCorrelator::IsInitialized() const
{
    return m_impl->IsInitialized();
}

void AlertCorrelator::IngestAlert(const Alert& alert)
{
    m_impl->IngestAlert(alert);
}

void AlertCorrelator::IngestTelemetryEvent(const TelemetryEvent& event)
{
    m_impl->IngestTelemetryEvent(event);
}

bool AlertCorrelator::AddCorrelationRule(const CorrelationRule& rule)
{
    return m_impl->AddCorrelationRule(rule);
}

bool AlertCorrelator::RemoveCorrelationRule(std::string_view ruleId)
{
    return m_impl->RemoveCorrelationRule(ruleId);
}

std::vector<CorrelationRule> AlertCorrelator::GetCorrelationRules() const
{
    return m_impl->GetCorrelationRules();
}

void AlertCorrelator::FlushPendingCorrelations()
{
    m_impl->FlushPendingCorrelations();
}

uint64_t AlertCorrelator::GetTotalAlertsProcessed() const
{
    return m_impl->GetTotalAlertsProcessed();
}

uint64_t AlertCorrelator::GetTotalIncidentsCreated() const
{
    return m_impl->GetTotalIncidentsCreated();
}

} // namespace ShadowStrike::Products::PhantomEDR::IncidentResponse
