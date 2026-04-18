/*
 * ShadowStrike - Enterprise NGAV/EDR/XDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */

/// @file SOAREngine.cpp
/// @brief Local SOAR execution engine with queued playbook processing.

#include <format>
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"
#include "PhantomCore/Database/DatabaseManager.hpp"
#include "Products/Community/PhantomXDR/SOARLocal/SOARTypes.hpp"
#include "Products/Community/PhantomXDR/XDRCorrelation/XDRTypes.hpp"
#include "Products/Community/PhantomXDR/SOARLocal/SOARPlaybooks.hpp"
#include "Products/Community/PhantomXDR/SOARLocal/SOAREngine.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>

namespace ShadowStrike::Products::PhantomXDR::SOARLocal {

namespace {

constexpr const char* kLogPrefix = "[XDR::SOAR::Engine]";
constexpr size_t kMaxQueuedExecutions = 2048;
constexpr size_t kMaxCachedExecutions = 256;
constexpr uint32_t kMaxHistoryLimit = 1000;

using Clock = std::chrono::system_clock;
using DB    = ShadowStrike::Database::DatabaseManager;
using DBErr = ShadowStrike::Database::DatabaseError;
namespace SU = ShadowStrike::Utils::StringUtils;
using ShadowStrike::Utils::Logger;
namespace XC = ShadowStrike::Products::PhantomXDR::XDRCorrelation;

[[nodiscard]] int64_t ToUnixMillis(const TimePoint timePoint) noexcept {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        timePoint.time_since_epoch()).count();
}

[[nodiscard]] TimePoint FromUnixMillis(const int64_t milliseconds) noexcept {
    return Clock::time_point(
        std::chrono::duration_cast<Clock::duration>(std::chrono::milliseconds(milliseconds)));
}

[[nodiscard]] std::string_view ActionTypeToString(const ActionType type) noexcept {
    switch (type) {
        case ActionType::IsolateEndpoint: return "IsolateEndpoint";
        case ActionType::BlockIP:         return "BlockIP";
        case ActionType::BlockDomain:     return "BlockDomain";
        case ActionType::KillProcess:     return "KillProcess";
        case ActionType::QuarantineFile:  return "QuarantineFile";
        case ActionType::BlockSender:     return "BlockSender";
        case ActionType::DisableAccount:  return "DisableAccount";
        case ActionType::AlertSOC:        return "AlertSOC";
        case ActionType::LogEvent:        return "LogEvent";
        case ActionType::RunScript:       return "RunScript";
    }
    return "LogEvent";
}

[[nodiscard]] std::string_view DomainToString(const XC::XDREventDomain domain) noexcept {
    switch (domain) {
        case XC::XDREventDomain::Endpoint: return "Endpoint";
        case XC::XDREventDomain::Network:  return "Network";
        case XC::XDREventDomain::Identity: return "Identity";
        case XC::XDREventDomain::Email:    return "Email";
        case XC::XDREventDomain::Cloud:    return "Cloud";
        default:                           return "Unknown";
    }
}

[[nodiscard]] bool ActionRequiresTarget(const ActionType type) noexcept {
    switch (type) {
        case ActionType::AlertSOC:
        case ActionType::LogEvent:
            return false;
        case ActionType::RunScript:
            return false;
        default:
            return true;
    }
}

[[nodiscard]] uint8_t SeverityFromVerdict(const XC::CorrelationVerdict verdict) noexcept {
    switch (verdict) {
        case XC::CorrelationVerdict::Benign:        return 0;
        case XC::CorrelationVerdict::Informational: return 25;
        case XC::CorrelationVerdict::Suspicious:    return 60;
        case XC::CorrelationVerdict::Malicious:     return 80;
        case XC::CorrelationVerdict::Critical:      return 100;
    }
    return 0;
}

[[nodiscard]] std::string GenerateExecutionId() {
    static std::atomic<uint64_t> sequence{0};
    const auto now = Clock::now().time_since_epoch().count();
    return std::format(
        "SOAR-EXEC-{:X}-{:04X}",
        now,
        sequence.fetch_add(1, std::memory_order_relaxed) & 0xFFFFU);
}

[[nodiscard]] std::string HexEncode(std::string_view value) {
    static constexpr char kHexDigits[] = "0123456789ABCDEF";

    std::string encoded;
    encoded.reserve(value.size() * 2);
    for (const unsigned char ch : value) {
        encoded.push_back(kHexDigits[(ch >> 4U) & 0x0FU]);
        encoded.push_back(kHexDigits[ch & 0x0FU]);
    }
    return encoded;
}

[[nodiscard]] std::string HexDecode(std::string_view value) {
    auto hexValue = [](const char ch) noexcept -> uint8_t {
        if (ch >= '0' && ch <= '9') return static_cast<uint8_t>(ch - '0');
        if (ch >= 'A' && ch <= 'F') return static_cast<uint8_t>(ch - 'A' + 10);
        if (ch >= 'a' && ch <= 'f') return static_cast<uint8_t>(ch - 'a' + 10);
        return 0;
    };

    if ((value.size() % 2U) != 0U) {
        return {};
    }

    std::string decoded;
    decoded.reserve(value.size() / 2U);
    for (size_t index = 0; index < value.size(); index += 2U) {
        const auto high = hexValue(value[index]);
        const auto low  = hexValue(value[index + 1U]);
        decoded.push_back(static_cast<char>((high << 4U) | low));
    }
    return decoded;
}

[[nodiscard]] std::string SerializeParameters(const std::map<std::string, std::string>& parameters) {
    std::string serialized;
    for (auto it = parameters.begin(); it != parameters.end(); ++it) {
        if (!serialized.empty()) {
            serialized.push_back(';');
        }

        serialized += HexEncode(it->first);
        serialized.push_back('=');
        serialized += HexEncode(it->second);
    }
    return serialized;
}

[[nodiscard]] std::map<std::string, std::string> DeserializeParameters(std::string_view serialized) {
    std::map<std::string, std::string> parameters;
    size_t cursor = 0;

    while (cursor < serialized.size()) {
        const auto pairEnd = serialized.find(';', cursor);
        const auto token = serialized.substr(
            cursor,
            pairEnd == std::string_view::npos ? std::string_view::npos : pairEnd - cursor);

        const auto separator = token.find('=');
        if (separator != std::string_view::npos && separator > 0U) {
            parameters.emplace(
                HexDecode(token.substr(0, separator)),
                HexDecode(token.substr(separator + 1U)));
        }

        if (pairEnd == std::string_view::npos) {
            break;
        }
        cursor = pairEnd + 1U;
    }

    return parameters;
}

void ReplaceAll(std::string& value, const std::string_view needle, const std::string_view replacement) {
    if (needle.empty()) {
        return;
    }

    size_t position = 0;
    while ((position = value.find(needle, position)) != std::string::npos) {
        value.replace(position, needle.size(), replacement);
        position += replacement.size();
    }
}

struct ExecutionContext {
    std::string hostName;
    std::string userName;
    std::string ipAddress;
    std::string fileHash;
    std::string domain;
    std::string sender;
    std::string processId;
    uint8_t     maxSeverity{0};
};

[[nodiscard]] ExecutionContext BuildExecutionContext(const std::vector<XC::XDREvent>& events) {
    ExecutionContext context;

    for (const auto& event : events) {
        context.maxSeverity = std::max(context.maxSeverity, event.severity);

        if (context.hostName.empty() && !event.hostName.empty()) {
            context.hostName = event.hostName;
        }
        if (context.userName.empty() && !event.userName.empty()) {
            context.userName = event.userName;
        }
        if (context.ipAddress.empty() && !event.ipAddress.empty()) {
            context.ipAddress = event.ipAddress;
        }
        if (context.fileHash.empty() && !event.fileHash.empty()) {
            context.fileHash = event.fileHash;
        }
        if (context.processId.empty() && event.processId != 0U) {
            context.processId = std::to_string(event.processId);
        }

        if (const auto it = event.metadata.find("domain");
            context.domain.empty() && it != event.metadata.end()) {
            context.domain = it->second;
        }
        if (const auto it = event.metadata.find("dnsQuery");
            context.domain.empty() && it != event.metadata.end()) {
            context.domain = it->second;
        }
        if (const auto it = event.metadata.find("destinationDomain");
            context.domain.empty() && it != event.metadata.end()) {
            context.domain = it->second;
        }
        if (const auto it = event.metadata.find("sender");
            context.sender.empty() && it != event.metadata.end()) {
            context.sender = it->second;
        }
        if (const auto it = event.metadata.find("from");
            context.sender.empty() && it != event.metadata.end()) {
            context.sender = it->second;
        }
    }

    return context;
}

[[nodiscard]] std::string ResolveTemplate(std::string value, const ExecutionContext& context) {
    ReplaceAll(value, "{hostName}", context.hostName);
    ReplaceAll(value, "{userName}", context.userName);
    ReplaceAll(value, "{ipAddress}", context.ipAddress);
    ReplaceAll(value, "{fileHash}", context.fileHash);
    ReplaceAll(value, "{domain}", context.domain);
    ReplaceAll(value, "{sender}", context.sender);
    ReplaceAll(value, "{processId}", context.processId);
    return value;
}

[[nodiscard]] std::map<std::string, std::string> ResolveParameters(
    const std::map<std::string, std::string>& parameters,
    const ExecutionContext& context)
{
    std::map<std::string, std::string> resolved;
    for (const auto& [key, value] : parameters) {
        resolved.emplace(key, ResolveTemplate(value, context));
    }
    return resolved;
}

[[nodiscard]] bool DomainMatches(
    const std::string_view expectedDomain,
    const std::vector<XC::XDREvent>& events)
{
    if (expectedDomain.empty()) {
        return true;
    }

    return std::any_of(
        events.begin(),
        events.end(),
        [expectedDomain](const XC::XDREvent& event) {
            return DomainToString(event.domain) == expectedDomain;
        });
}

} // anonymous namespace

class SOAREngineImpl {
public:
    struct ExecutionRequest {
        std::string executionId;
        Playbook    playbook;
        std::string triggerId;
        std::vector<XC::XDREvent> events;
    };

    std::atomic<bool> initialized{false};
    std::atomic<bool> running{false};
    std::atomic<uint64_t> totalExecuted{0};
    std::atomic<uint64_t> totalSucceeded{0};
    std::atomic<uint64_t> totalFailed{0};

    mutable std::shared_mutex cacheMutex;
    std::unordered_map<std::string, PlaybookExecution> executionCache;
    std::deque<std::string> executionOrder;

    std::mutex queueMutex;
    std::condition_variable_any queueCv;
    std::deque<ExecutionRequest> executionQueue;
    std::jthread workerThread;

    [[nodiscard]] bool Initialize();
    void               Shutdown();
    [[nodiscard]] bool CreateSchema() const;
    [[nodiscard]] bool LoadStatistics();
    [[nodiscard]] std::vector<std::string> HandleCorrelationMatch(
        const XC::CorrelationMatch& match,
        const std::vector<XC::XDREvent>& events);
    [[nodiscard]] std::optional<std::string> ExecutePlaybook(
        std::string_view playbookId,
        std::string_view triggerId);
    [[nodiscard]] std::vector<PlaybookExecution> GetExecutionHistory(uint32_t limit) const;
    [[nodiscard]] std::optional<PlaybookExecution> GetExecutionById(std::string_view executionId) const;
    [[nodiscard]] SOARStatistics GetStatistics() const;
    void BackgroundLoop(std::stop_token stopToken);

private:
    [[nodiscard]] bool QueueExecution(
        const Playbook& playbook,
        std::string triggerId,
        std::vector<XC::XDREvent> events,
        std::string* executionIdOut);
    [[nodiscard]] bool MatchesCorrelationTrigger(
        const Playbook& playbook,
        const XC::CorrelationMatch& match,
        const std::vector<XC::XDREvent>& events,
        uint8_t severity) const;
    [[nodiscard]] PlaybookExecution ExecuteRequest(const ExecutionRequest& request);
    [[nodiscard]] SOARAction ExecuteAction(const SOARAction& actionTemplate, const ExecutionContext& context) const;
    [[nodiscard]] bool PersistExecution(const PlaybookExecution& execution) const;
    void CacheExecution(const PlaybookExecution& execution);
    [[nodiscard]] std::vector<SOARAction> LoadActionResults(std::string_view executionId) const;
};

bool SOAREngineImpl::CreateSchema() const {
    auto& db = DB::Instance();
    DBErr err;

    constexpr std::string_view kSchema = R"SQL(
        CREATE TABLE IF NOT EXISTS xdr_soar_executions (
            execution_id     TEXT PRIMARY KEY,
            playbook_id      TEXT NOT NULL,
            trigger_id       TEXT NOT NULL,
            start_time_ms    INTEGER NOT NULL,
            end_time_ms      INTEGER NOT NULL,
            success          INTEGER NOT NULL,
            summary          TEXT DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_xdr_soar_exec_playbook
            ON xdr_soar_executions(playbook_id, start_time_ms DESC);

        CREATE TABLE IF NOT EXISTS xdr_soar_action_results (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            execution_id     TEXT NOT NULL REFERENCES xdr_soar_executions(execution_id) ON DELETE CASCADE,
            action_id        TEXT NOT NULL,
            action_type      INTEGER NOT NULL,
            target           TEXT DEFAULT '',
            parameters       TEXT DEFAULT '',
            result           INTEGER NOT NULL,
            result_detail    TEXT DEFAULT '',
            executed_at_ms   INTEGER NOT NULL,
            action_order     INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_xdr_soar_action_exec
            ON xdr_soar_action_results(execution_id, action_order);
    )SQL";

    if (!db.Execute(kSchema, &err)) {
        Logger::Error("{} Failed to create SOAR execution schema: {}",
            kLogPrefix, SU::ToNarrow(err.message));
        return false;
    }

    return true;
}

bool SOAREngineImpl::LoadStatistics() {
    auto& db = DB::Instance();
    DBErr err;

    auto result = db.Query(
        "SELECT COUNT(*) AS total_executed, "
        "COALESCE(SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END), 0) AS total_succeeded, "
        "COALESCE(SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END), 0) AS total_failed "
        "FROM xdr_soar_executions",
        &err);
    if (err.HasError()) {
        Logger::Error("{} Failed to load SOAR statistics: {}",
            kLogPrefix, SU::ToNarrow(err.message));
        return false;
    }

    if (result.Next()) {
        totalExecuted.store(static_cast<uint64_t>(result.GetInt64(0)), std::memory_order_release);
        totalSucceeded.store(static_cast<uint64_t>(result.GetInt64(1)), std::memory_order_release);
        totalFailed.store(static_cast<uint64_t>(result.GetInt64(2)), std::memory_order_release);
    }

    return true;
}

bool SOAREngineImpl::Initialize() {
    if (initialized.load(std::memory_order_acquire)) {
        return true;
    }

    auto& db = DB::Instance();
    if (!db.IsInitialized()) {
        Logger::Error("{} DatabaseManager is not initialized", kLogPrefix);
        return false;
    }

    if (!SOARPlaybooks::Instance().Initialize()) {
        Logger::Error("{} SOAR playbook manager failed to initialize", kLogPrefix);
        return false;
    }

    Logger::Info("{} Initializing SOAR engine...", kLogPrefix);

    if (!CreateSchema()) {
        return false;
    }
    if (!LoadStatistics()) {
        return false;
    }

    initialized.store(true, std::memory_order_release);
    running.store(true, std::memory_order_release);
    workerThread = std::jthread([this](std::stop_token stopToken) { BackgroundLoop(stopToken); });

    Logger::Info("{} SOAR engine initialized successfully", kLogPrefix);
    return true;
}

void SOAREngineImpl::Shutdown() {
    if (!initialized.exchange(false, std::memory_order_acq_rel)) {
        return;
    }

    Logger::Info("{} Shutting down SOAR engine...", kLogPrefix);
    running.store(false, std::memory_order_release);
    queueCv.notify_all();

    if (workerThread.joinable()) {
        workerThread.request_stop();
        workerThread.join();
    }

    {
        std::unique_lock queueLock(queueMutex);
        executionQueue.clear();
    }
    {
        std::unique_lock cacheLock(cacheMutex);
        executionCache.clear();
        executionOrder.clear();
    }

    Logger::Info("{} SOAR engine shut down", kLogPrefix);
}

bool SOAREngineImpl::QueueExecution(
    const Playbook& playbook,
    std::string triggerId,
    std::vector<XC::XDREvent> events,
    std::string* executionIdOut)
{
    ExecutionRequest request;
    request.executionId = GenerateExecutionId();
    request.playbook = playbook;
    request.triggerId = std::move(triggerId);
    request.events = std::move(events);

    {
        std::unique_lock lock(queueMutex);
        if (executionQueue.size() >= kMaxQueuedExecutions) {
            Logger::Warn("{} Execution queue is full (limit={}); dropping playbook '{}'",
                kLogPrefix, kMaxQueuedExecutions, playbook.playbookId);
            return false;
        }

        executionQueue.push_back(request);
    }

    if (executionIdOut != nullptr) {
        *executionIdOut = request.executionId;
    }

    queueCv.notify_one();
    Logger::Info("{} Queued playbook '{}' for trigger '{}'",
        kLogPrefix, playbook.playbookId, request.triggerId);
    return true;
}

bool SOAREngineImpl::MatchesCorrelationTrigger(
    const Playbook& playbook,
    const XC::CorrelationMatch& match,
    const std::vector<XC::XDREvent>& events,
    const uint8_t severity) const
{
    if (playbook.status != PlaybookStatus::Active) {
        return false;
    }

    const auto& trigger = playbook.trigger;
    switch (trigger.type) {
        case TriggerType::CorrelationMatch:
            return (trigger.sourceRuleId.empty() || trigger.sourceRuleId == match.ruleId) &&
                   DomainMatches(trigger.domainFilter, events);

        case TriggerType::SeverityThreshold:
            return severity >= trigger.minSeverity && DomainMatches(trigger.domainFilter, events);

        case TriggerType::ManualTrigger:
        case TriggerType::ScheduledScan:
            return false;
    }

    return false;
}

std::vector<std::string> SOAREngineImpl::HandleCorrelationMatch(
    const XC::CorrelationMatch& match,
    const std::vector<XC::XDREvent>& events)
{
    if (!initialized.load(std::memory_order_acquire)) {
        Logger::Warn("{} HandleCorrelationMatch called before initialization", kLogPrefix);
        return {};
    }

    uint8_t severity = SeverityFromVerdict(match.verdict);
    for (const auto& event : events) {
        severity = std::max(severity, event.severity);
    }

    std::vector<std::string> executionIds;
    for (const auto& playbook : SOARPlaybooks::Instance().GetActivePlaybooks()) {
        if (!MatchesCorrelationTrigger(playbook, match, events, severity)) {
            continue;
        }

        std::string executionId;
        if (QueueExecution(playbook, match.matchId, events, &executionId)) {
            executionIds.push_back(std::move(executionId));
        }
    }

    if (!executionIds.empty()) {
        Logger::Info("{} Correlation match '{}' queued {} SOAR playbook execution(s)",
            kLogPrefix, match.matchId, executionIds.size());
    }

    return executionIds;
}

std::optional<std::string> SOAREngineImpl::ExecutePlaybook(
    const std::string_view playbookId,
    const std::string_view triggerId)
{
    if (!initialized.load(std::memory_order_acquire)) {
        Logger::Warn("{} ExecutePlaybook called before initialization", kLogPrefix);
        return std::nullopt;
    }

    const auto playbook = SOARPlaybooks::Instance().GetPlaybook(playbookId);
    if (!playbook.has_value()) {
        Logger::Warn("{} Requested manual execution for unknown playbook '{}'",
            kLogPrefix, playbookId);
        return std::nullopt;
    }

    if (playbook->status == PlaybookStatus::Disabled) {
        Logger::Warn("{} Manual execution rejected because playbook '{}' is disabled",
            kLogPrefix, playbookId);
        return std::nullopt;
    }

    std::string executionId;
    const std::string effectiveTrigger = triggerId.empty()
        ? std::format("MANUAL-{}", GenerateExecutionId())
        : std::string(triggerId);

    if (!QueueExecution(*playbook, effectiveTrigger, {}, &executionId)) {
        return std::nullopt;
    }

    return executionId;
}

SOARAction SOAREngineImpl::ExecuteAction(
    const SOARAction& actionTemplate,
    const ExecutionContext& context) const
{
    SOARAction action = actionTemplate;
    action.target = ResolveTemplate(actionTemplate.target, context);
    action.parameters = ResolveParameters(actionTemplate.parameters, context);
    action.executedAt = Clock::now();

    if (ActionRequiresTarget(action.type) && action.target.empty()) {
        action.result = ActionResult::Skipped;
        action.resultDetail = "No resolved target available for action";
        Logger::Warn("{} Skipping action '{}' ({}) because target resolution failed",
            kLogPrefix, action.actionId, ActionTypeToString(action.type));
        return action;
    }

    switch (action.type) {
        case ActionType::IsolateEndpoint:
            Logger::Warn("{} Stub isolate endpoint request issued for host='{}'",
                kLogPrefix, action.target);
            action.result = ActionResult::Success;
            action.resultDetail = std::format("Endpoint isolation request prepared for '{}'", action.target);
            break;

        case ActionType::BlockIP:
            Logger::Warn("{} Stub block IP request issued for address='{}'",
                kLogPrefix, action.target);
            action.result = ActionResult::Success;
            action.resultDetail = std::format("Network block prepared for IP '{}'", action.target);
            break;

        case ActionType::BlockDomain:
            Logger::Warn("{} Stub block domain request issued for domain='{}'",
                kLogPrefix, action.target);
            action.result = ActionResult::Success;
            action.resultDetail = std::format("Domain block prepared for '{}'", action.target);
            break;

        case ActionType::KillProcess:
            Logger::Warn("{} Stub kill process request issued for process='{}'",
                kLogPrefix, action.target);
            action.result = ActionResult::Success;
            action.resultDetail = std::format("Process termination prepared for '{}'", action.target);
            break;

        case ActionType::QuarantineFile:
            Logger::Warn("{} Stub quarantine file request issued for artifact='{}'",
                kLogPrefix, action.target);
            action.result = ActionResult::Success;
            action.resultDetail = std::format("Quarantine prepared for artifact '{}'", action.target);
            break;

        case ActionType::BlockSender:
            Logger::Warn("{} Stub block sender request issued for sender='{}'",
                kLogPrefix, action.target);
            action.result = ActionResult::Success;
            action.resultDetail = std::format("Sender block prepared for '{}'", action.target);
            break;

        case ActionType::DisableAccount:
            Logger::Warn("{} Stub disable account request issued for account='{}'",
                kLogPrefix, action.target);
            action.result = ActionResult::Success;
            action.resultDetail = std::format("Account disable prepared for '{}'", action.target);
            break;

        case ActionType::AlertSOC:
            Logger::Info("{} SOC alert generated for route='{}'",
                kLogPrefix, action.target.empty() ? "soc://default" : action.target);
            action.result = ActionResult::Success;
            action.resultDetail = std::format(
                "SOC alert routed to '{}'",
                action.target.empty() ? "soc://default" : action.target);
            break;

        case ActionType::LogEvent:
            Logger::Info("{} SOAR event logged for action '{}'", kLogPrefix, action.actionId);
            action.result = ActionResult::Success;
            action.resultDetail = "SOAR audit event logged";
            break;

        case ActionType::RunScript: {
            const auto it = action.parameters.find("scriptName");
            const std::string scriptName = it == action.parameters.end()
                ? (action.target.empty() ? "unspecified" : action.target)
                : it->second;
            Logger::Warn("{} Stub automation script invocation prepared for '{}'",
                kLogPrefix, scriptName);
            action.result = ActionResult::Success;
            action.resultDetail = std::format("Automation script '{}' prepared for execution", scriptName);
            break;
        }
    }

    return action;
}

PlaybookExecution SOAREngineImpl::ExecuteRequest(const ExecutionRequest& request) {
    PlaybookExecution execution;
    execution.executionId = request.executionId;
    execution.playbookId = request.playbook.playbookId;
    execution.triggerId = request.triggerId;
    execution.startTime = Clock::now();

    const auto context = BuildExecutionContext(request.events);

    uint32_t succeeded = 0;
    uint32_t failed = 0;
    uint32_t skipped = 0;

    for (const auto& actionTemplate : request.playbook.actions) {
        auto action = ExecuteAction(actionTemplate, context);
        switch (action.result) {
            case ActionResult::Success: ++succeeded; break;
            case ActionResult::Failed:
            case ActionResult::TimedOut: ++failed; break;
            case ActionResult::Skipped: ++skipped; break;
            case ActionResult::Pending: ++failed; break;
        }
        execution.actionResults.push_back(std::move(action));
    }

    execution.endTime = Clock::now();
    execution.success = (failed == 0U);
    execution.summary = std::format(
        "Executed {} action(s): {} succeeded, {} failed, {} skipped",
        execution.actionResults.size(),
        succeeded,
        failed,
        skipped);

    return execution;
}

bool SOAREngineImpl::PersistExecution(const PlaybookExecution& execution) const {
    auto& db = DB::Instance();
    DBErr err;

    auto transaction = db.BeginTransaction(ShadowStrike::Database::Transaction::Type::Immediate, &err);
    if (transaction == nullptr || err.HasError()) {
        Logger::Error("{} Failed to begin execution transaction for '{}': {}",
            kLogPrefix, execution.executionId, SU::ToNarrow(err.message));
        return false;
    }

    constexpr std::string_view kUpsertExecution = R"SQL(
        INSERT INTO xdr_soar_executions
            (execution_id, playbook_id, trigger_id, start_time_ms, end_time_ms, success, summary)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(execution_id) DO UPDATE SET
            playbook_id = excluded.playbook_id,
            trigger_id = excluded.trigger_id,
            start_time_ms = excluded.start_time_ms,
            end_time_ms = excluded.end_time_ms,
            success = excluded.success,
            summary = excluded.summary
    )SQL";

    if (!transaction->ExecuteWithParams(
            kUpsertExecution,
            &err,
            execution.executionId,
            execution.playbookId,
            execution.triggerId,
            ToUnixMillis(execution.startTime),
            ToUnixMillis(execution.endTime),
            execution.success ? 1 : 0,
            execution.summary)) {
        (void)transaction->Rollback();
        Logger::Error("{} Failed to persist execution '{}': {}",
            kLogPrefix, execution.executionId, SU::ToNarrow(err.message));
        return false;
    }

    err.Clear();
    if (!transaction->ExecuteWithParams(
            "DELETE FROM xdr_soar_action_results WHERE execution_id = ?",
            &err,
            execution.executionId)) {
        (void)transaction->Rollback();
        Logger::Error("{} Failed to clear existing action results for execution '{}': {}",
            kLogPrefix, execution.executionId, SU::ToNarrow(err.message));
        return false;
    }

    constexpr std::string_view kInsertResult = R"SQL(
        INSERT INTO xdr_soar_action_results
            (execution_id, action_id, action_type, target, parameters, result,
             result_detail, executed_at_ms, action_order)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    )SQL";

    for (size_t index = 0; index < execution.actionResults.size(); ++index) {
        const auto& action = execution.actionResults[index];
        err.Clear();
        if (!transaction->ExecuteWithParams(
                kInsertResult,
                &err,
                execution.executionId,
                action.actionId,
                static_cast<int>(action.type),
                action.target,
                SerializeParameters(action.parameters),
                static_cast<int>(action.result),
                action.resultDetail,
                ToUnixMillis(action.executedAt),
                static_cast<int>(index))) {
            (void)transaction->Rollback();
            Logger::Error("{} Failed to persist action result '{}' for execution '{}': {}",
                kLogPrefix, action.actionId, execution.executionId, SU::ToNarrow(err.message));
            return false;
        }
    }

    err.Clear();
    if (!transaction->Commit(&err)) {
        Logger::Error("{} Failed to commit execution '{}' transaction: {}",
            kLogPrefix, execution.executionId, SU::ToNarrow(err.message));
        return false;
    }

    return true;
}

void SOAREngineImpl::CacheExecution(const PlaybookExecution& execution) {
    std::unique_lock lock(cacheMutex);

    if (!executionCache.contains(execution.executionId)) {
        executionOrder.push_back(execution.executionId);
        while (executionOrder.size() > kMaxCachedExecutions) {
            executionCache.erase(executionOrder.front());
            executionOrder.pop_front();
        }
    }

    executionCache[execution.executionId] = execution;
}

std::vector<SOARAction> SOAREngineImpl::LoadActionResults(const std::string_view executionId) const {
    auto& db = DB::Instance();
    DBErr err;

    auto result = db.QueryWithParams(
        "SELECT action_id, action_type, target, parameters, result, result_detail, executed_at_ms "
        "FROM xdr_soar_action_results WHERE execution_id = ? ORDER BY action_order ASC",
        &err,
        std::string(executionId));
    if (err.HasError()) {
        Logger::Warn("{} Failed to load action results for execution '{}': {}",
            kLogPrefix, executionId, SU::ToNarrow(err.message));
        return {};
    }

    std::vector<SOARAction> actions;
    while (result.Next()) {
        SOARAction action;
        action.actionId = result.GetString(0);
        action.type = static_cast<ActionType>(result.GetInt(1));
        action.target = result.GetString(2);
        action.parameters = DeserializeParameters(result.GetString(3));
        action.result = static_cast<ActionResult>(result.GetInt(4));
        action.resultDetail = result.GetString(5);
        action.executedAt = FromUnixMillis(result.GetInt64(6));
        actions.push_back(std::move(action));
    }

    return actions;
}

std::vector<PlaybookExecution> SOAREngineImpl::GetExecutionHistory(const uint32_t limit) const {
    const uint32_t boundedLimit = std::clamp(limit == 0U ? 50U : limit, 1U, kMaxHistoryLimit);

    auto& db = DB::Instance();
    DBErr err;

    auto result = db.QueryWithParams(
        "SELECT execution_id, playbook_id, trigger_id, start_time_ms, end_time_ms, success, summary "
        "FROM xdr_soar_executions ORDER BY start_time_ms DESC LIMIT ?",
        &err,
        static_cast<int>(boundedLimit));
    if (err.HasError()) {
        Logger::Warn("{} Failed to query execution history: {}", kLogPrefix, SU::ToNarrow(err.message));
        return {};
    }

    std::vector<PlaybookExecution> history;
    while (result.Next()) {
        PlaybookExecution execution;
        execution.executionId = result.GetString(0);
        execution.playbookId = result.GetString(1);
        execution.triggerId = result.GetString(2);
        execution.startTime = FromUnixMillis(result.GetInt64(3));
        execution.endTime = FromUnixMillis(result.GetInt64(4));
        execution.success = result.GetInt(5) != 0;
        execution.summary = result.GetString(6);
        execution.actionResults = LoadActionResults(execution.executionId);
        history.push_back(std::move(execution));
    }

    return history;
}

std::optional<PlaybookExecution> SOAREngineImpl::GetExecutionById(const std::string_view executionId) const {
    {
        std::shared_lock lock(cacheMutex);
        if (const auto it = executionCache.find(std::string(executionId)); it != executionCache.end()) {
            return it->second;
        }
    }

    auto& db = DB::Instance();
    DBErr err;

    auto result = db.QueryWithParams(
        "SELECT execution_id, playbook_id, trigger_id, start_time_ms, end_time_ms, success, summary "
        "FROM xdr_soar_executions WHERE execution_id = ?",
        &err,
        std::string(executionId));
    if (err.HasError()) {
        Logger::Warn("{} Failed to query execution '{}': {}",
            kLogPrefix, executionId, SU::ToNarrow(err.message));
        return std::nullopt;
    }
    if (!result.Next()) {
        return std::nullopt;
    }

    PlaybookExecution execution;
    execution.executionId = result.GetString(0);
    execution.playbookId = result.GetString(1);
    execution.triggerId = result.GetString(2);
    execution.startTime = FromUnixMillis(result.GetInt64(3));
    execution.endTime = FromUnixMillis(result.GetInt64(4));
    execution.success = result.GetInt(5) != 0;
    execution.summary = result.GetString(6);
    execution.actionResults = LoadActionResults(execution.executionId);

    return execution;
}

SOARStatistics SOAREngineImpl::GetStatistics() const {
    SOARStatistics statistics;
    statistics.totalExecuted = totalExecuted.load(std::memory_order_acquire);
    statistics.totalSucceeded = totalSucceeded.load(std::memory_order_acquire);
    statistics.totalFailed = totalFailed.load(std::memory_order_acquire);
    return statistics;
}

void SOAREngineImpl::BackgroundLoop(std::stop_token stopToken) {
    Logger::Info("{} Background SOAR execution thread started", kLogPrefix);

    while (!stopToken.stop_requested() && running.load(std::memory_order_acquire)) {
        std::optional<ExecutionRequest> request;

        {
            std::unique_lock lock(queueMutex);
            queueCv.wait_for(
                lock,
                std::chrono::seconds(1),
                [&]() {
                    return stopToken.stop_requested() ||
                           !running.load(std::memory_order_acquire) ||
                           !executionQueue.empty();
                });

            if (stopToken.stop_requested() || !running.load(std::memory_order_acquire)) {
                break;
            }
            if (executionQueue.empty()) {
                continue;
            }

            request = std::move(executionQueue.front());
            executionQueue.pop_front();
        }

        auto execution = ExecuteRequest(*request);
        if (!PersistExecution(execution)) {
            Logger::Error("{} Execution '{}' could not be persisted",
                kLogPrefix, execution.executionId);
        }

        CacheExecution(execution);
        totalExecuted.fetch_add(1, std::memory_order_relaxed);
        if (execution.success) {
            totalSucceeded.fetch_add(1, std::memory_order_relaxed);
        } else {
            totalFailed.fetch_add(1, std::memory_order_relaxed);
        }

        Logger::Info("{} Completed SOAR execution '{}' for playbook '{}' success={} summary={}",
            kLogPrefix, execution.executionId, execution.playbookId, execution.success, execution.summary);
    }

    Logger::Info("{} Background SOAR execution thread exiting", kLogPrefix);
}

SOAREngine& SOAREngine::Instance() {
    static SOAREngine instance;
    return instance;
}

bool SOAREngine::HasInstance() noexcept {
    return Instance().IsInitialized();
}

SOAREngine::SOAREngine()
    : m_impl(std::make_unique<SOAREngineImpl>()) {
}

SOAREngine::~SOAREngine() {
    Shutdown();
}

bool SOAREngine::Initialize() {
    return m_impl->Initialize();
}

void SOAREngine::Shutdown() {
    m_impl->Shutdown();
}

bool SOAREngine::IsInitialized() const noexcept {
    return m_impl->initialized.load(std::memory_order_acquire);
}

std::vector<std::string> SOAREngine::HandleCorrelationMatch(
    const XC::CorrelationMatch& match,
    const std::vector<XC::XDREvent>& events)
{
    return m_impl->HandleCorrelationMatch(match, events);
}

std::optional<std::string> SOAREngine::ExecutePlaybook(
    const std::string_view playbookId,
    const std::string_view triggerId)
{
    return m_impl->ExecutePlaybook(playbookId, triggerId);
}

std::vector<PlaybookExecution> SOAREngine::GetExecutionHistory(const uint32_t limit) const {
    return m_impl->GetExecutionHistory(limit);
}

std::optional<PlaybookExecution> SOAREngine::GetExecutionById(const std::string_view executionId) const {
    return m_impl->GetExecutionById(executionId);
}

SOARStatistics SOAREngine::GetStatistics() const {
    return m_impl->GetStatistics();
}

} // namespace ShadowStrike::Products::PhantomXDR::SOARLocal
