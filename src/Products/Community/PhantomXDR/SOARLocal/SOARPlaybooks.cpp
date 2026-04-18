/*
 * ShadowStrike - Enterprise NGAV/EDR/XDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */

/// @file SOARPlaybooks.cpp
/// @brief Local SOAR playbook persistence, CRUD, and default installation.

#include <format>
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"
#include "PhantomCore/Database/DatabaseManager.hpp"
#include "Products/Community/PhantomXDR/SOARLocal/SOARTypes.hpp"
#include "Products/Community/PhantomXDR/SOARLocal/SOARPlaybooks.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <memory>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <unordered_map>

namespace ShadowStrike::Products::PhantomXDR::SOARLocal {

namespace {

constexpr const char* kLogPrefix = "[XDR::SOAR::Playbooks]";
constexpr size_t kMaxPlaybooks = 256;
constexpr size_t kMaxActionsPerPlaybook = 32;

using Clock = std::chrono::system_clock;
using DB    = ShadowStrike::Database::DatabaseManager;
using DBErr = ShadowStrike::Database::DatabaseError;
namespace SU = ShadowStrike::Utils::StringUtils;
using ShadowStrike::Utils::Logger;

[[nodiscard]] int64_t ToUnixMillis(const TimePoint timePoint) noexcept {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        timePoint.time_since_epoch()).count();
}

[[nodiscard]] TimePoint FromUnixMillis(const int64_t milliseconds) noexcept {
    return Clock::time_point(
        std::chrono::duration_cast<Clock::duration>(std::chrono::milliseconds(milliseconds)));
}

[[nodiscard]] std::string_view DomainToString(const std::string_view domain) noexcept {
    return domain;
}

[[nodiscard]] std::string_view PlaybookStatusToString(const PlaybookStatus status) noexcept {
    switch (status) {
        case PlaybookStatus::Disabled: return "Disabled";
        case PlaybookStatus::Active:   return "Active";
        case PlaybookStatus::Testing:  return "Testing";
    }
    return "Active";
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

[[nodiscard]] std::string_view TriggerTypeToString(const TriggerType type) noexcept {
    switch (type) {
        case TriggerType::CorrelationMatch: return "CorrelationMatch";
        case TriggerType::SeverityThreshold: return "SeverityThreshold";
        case TriggerType::ManualTrigger:     return "ManualTrigger";
        case TriggerType::ScheduledScan:     return "ScheduledScan";
    }
    return "CorrelationMatch";
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

[[nodiscard]] Playbook CreateDefaultPlaybook(
    const std::string& playbookId,
    const std::string& name,
    const std::string& description,
    const PlaybookTrigger& trigger,
    std::vector<SOARAction> actions)
{
    Playbook playbook;
    playbook.playbookId = playbookId;
    playbook.name = name;
    playbook.description = description;
    playbook.status = PlaybookStatus::Active;
    playbook.trigger = trigger;
    playbook.actions = std::move(actions);
    playbook.createdAt = Clock::now();
    playbook.updatedAt = playbook.createdAt;
    return playbook;
}

[[nodiscard]] std::vector<Playbook> BuildDefaultPlaybooks() {
    return {
        CreateDefaultPlaybook(
            "DEFAULT-SOAR-PHISHING",
            "Phishing Response",
            "Contain phishing-driven execution chains by removing the payload, blocking the sender, and escalating to the SOC.",
            PlaybookTrigger{ TriggerType::CorrelationMatch, "DEFAULT-PHISH-EXEC", 0, "Email" },
            {
                SOARAction{ "phish-quarantine-file", ActionType::QuarantineFile, "{fileHash}", { { "reason", "phishing_attachment" } } },
                SOARAction{ "phish-block-sender", ActionType::BlockSender, "{sender}", { { "reason", "phishing_campaign" } } },
                SOARAction{ "phish-alert-soc", ActionType::AlertSOC, "soc://tier2", { { "category", "phishing" }, { "priority", "high" } } },
            }),
        CreateDefaultPlaybook(
            "DEFAULT-SOAR-RANSOMWARE",
            "Ransomware Containment",
            "Contain probable ransomware activity by isolating the endpoint, terminating the malicious process, and quarantining the payload.",
            PlaybookTrigger{ TriggerType::SeverityThreshold, "", 90, "Endpoint" },
            {
                SOARAction{ "ransomware-isolate-host", ActionType::IsolateEndpoint, "{hostName}", { { "reason", "critical_ransomware_signal" } } },
                SOARAction{ "ransomware-kill-process", ActionType::KillProcess, "{processId}", { { "reason", "ransomware_containment" } } },
                SOARAction{ "ransomware-quarantine-file", ActionType::QuarantineFile, "{fileHash}", { { "reason", "ransomware_payload" } } },
            }),
        CreateDefaultPlaybook(
            "DEFAULT-SOAR-LATERAL",
            "Lateral Movement Response",
            "Disrupt active lateral movement by blocking the source IP, disabling the account, and escalating to the SOC.",
            PlaybookTrigger{ TriggerType::CorrelationMatch, "DEFAULT-CRED-LATERAL", 0, "Network" },
            {
                SOARAction{ "lateral-block-ip", ActionType::BlockIP, "{ipAddress}", { { "reason", "lateral_movement" } } },
                SOARAction{ "lateral-disable-account", ActionType::DisableAccount, "{userName}", { { "reason", "suspected_account_abuse" } } },
                SOARAction{ "lateral-alert-soc", ActionType::AlertSOC, "soc://tier3", { { "category", "lateral_movement" }, { "priority", "critical" } } },
            }),
        CreateDefaultPlaybook(
            "DEFAULT-SOAR-CREDTHEFT",
            "Credential Theft Response",
            "Contain credential theft signals by disabling the affected account and notifying the SOC.",
            PlaybookTrigger{ TriggerType::SeverityThreshold, "", 75, "Identity" },
            {
                SOARAction{ "credtheft-disable-account", ActionType::DisableAccount, "{userName}", { { "reason", "credential_theft" } } },
                SOARAction{ "credtheft-alert-soc", ActionType::AlertSOC, "soc://tier2", { { "category", "credential_theft" }, { "priority", "high" } } },
            }),
        CreateDefaultPlaybook(
            "DEFAULT-SOAR-C2",
            "C2 Beacon Response",
            "Shut down command-and-control reachability by blocking the domain and IP, then isolating the host.",
            PlaybookTrigger{ TriggerType::CorrelationMatch, "DEFAULT-C2-EXEC", 0, "Network" },
            {
                SOARAction{ "c2-block-domain", ActionType::BlockDomain, "{domain}", { { "reason", "c2_beacon" } } },
                SOARAction{ "c2-block-ip", ActionType::BlockIP, "{ipAddress}", { { "reason", "c2_beacon" } } },
                SOARAction{ "c2-isolate-endpoint", ActionType::IsolateEndpoint, "{hostName}", { { "reason", "c2_containment" } } },
            }),
        CreateDefaultPlaybook(
            "DEFAULT-SOAR-BRUTEFORCE",
            "Brute Force Response",
            "Block brute-force follow-on activity by disabling the user account and blocking the attacker IP.",
            PlaybookTrigger{ TriggerType::CorrelationMatch, "DEFAULT-BRUTE-LOGON", 0, "Identity" },
            {
                SOARAction{ "bruteforce-disable-account", ActionType::DisableAccount, "{userName}", { { "reason", "identity_bruteforce" } } },
                SOARAction{ "bruteforce-block-ip", ActionType::BlockIP, "{ipAddress}", { { "reason", "identity_bruteforce" } } },
            }),
    };
}

} // anonymous namespace

class SOARPlaybooksImpl {
public:
    std::atomic<bool> initialized{false};
    mutable std::shared_mutex mutex;
    std::unordered_map<std::string, Playbook> playbooks;

    [[nodiscard]] bool Initialize();
    void               Shutdown();
    [[nodiscard]] bool CreateSchema() const;
    [[nodiscard]] bool LoadPlaybooksFromDb();
    [[nodiscard]] bool AddPlaybook(const Playbook& playbook);
    [[nodiscard]] bool RemovePlaybook(std::string_view playbookId);
    [[nodiscard]] bool UpdatePlaybook(const Playbook& playbook);
    [[nodiscard]] std::optional<Playbook> GetPlaybook(std::string_view playbookId) const;
    [[nodiscard]] std::vector<Playbook> GetActivePlaybooks() const;
    [[nodiscard]] std::vector<Playbook> GetAllPlaybooks() const;
    [[nodiscard]] uint32_t GetPlaybookCount() const;
    [[nodiscard]] bool InstallDefaultPlaybooks();

private:
    [[nodiscard]] bool PersistPlaybook(const Playbook& playbook) const;
    [[nodiscard]] bool DeletePlaybookFromDb(std::string_view playbookId) const;
    [[nodiscard]] std::optional<Playbook> ValidateAndNormalize(const Playbook& playbook) const;
};

bool SOARPlaybooksImpl::CreateSchema() const {
    auto& db = DB::Instance();
    DBErr err;

    constexpr std::string_view kSchema = R"SQL(
        CREATE TABLE IF NOT EXISTS xdr_soar_playbooks (
            playbook_id      TEXT PRIMARY KEY,
            name             TEXT NOT NULL,
            description      TEXT DEFAULT '',
            status           INTEGER NOT NULL,
            trigger_type     INTEGER NOT NULL,
            source_rule_id   TEXT DEFAULT '',
            min_severity     INTEGER DEFAULT 0,
            domain_filter    TEXT DEFAULT '',
            created_at_ms    INTEGER NOT NULL,
            updated_at_ms    INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_xdr_soar_playbooks_status
            ON xdr_soar_playbooks(status);

        CREATE TABLE IF NOT EXISTS xdr_soar_playbook_actions (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            playbook_id      TEXT NOT NULL REFERENCES xdr_soar_playbooks(playbook_id) ON DELETE CASCADE,
            action_id        TEXT NOT NULL,
            action_type      INTEGER NOT NULL,
            target           TEXT DEFAULT '',
            parameters       TEXT DEFAULT '',
            action_order     INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_xdr_soar_playbook_actions_playbook
            ON xdr_soar_playbook_actions(playbook_id, action_order);
    )SQL";

    if (!db.Execute(kSchema, &err)) {
        Logger::Error("{} Failed to create SOAR playbook schema: {}",
            kLogPrefix, SU::ToNarrow(err.message));
        return false;
    }

    return true;
}

std::optional<Playbook> SOARPlaybooksImpl::ValidateAndNormalize(const Playbook& playbook) const {
    if (playbook.playbookId.empty() || playbook.name.empty()) {
        Logger::Warn("{} Rejecting playbook with empty identifier or name", kLogPrefix);
        return std::nullopt;
    }

    if (playbook.actions.empty()) {
        Logger::Warn("{} Rejecting playbook '{}' without actions", kLogPrefix, playbook.playbookId);
        return std::nullopt;
    }

    if (playbook.actions.size() > kMaxActionsPerPlaybook) {
        Logger::Warn("{} Rejecting playbook '{}' with {} actions (limit={})",
            kLogPrefix, playbook.playbookId, playbook.actions.size(), kMaxActionsPerPlaybook);
        return std::nullopt;
    }

    Playbook normalized = playbook;
    const auto now = Clock::now();
    if (normalized.createdAt == TimePoint{}) {
        normalized.createdAt = now;
    }
    if (normalized.updatedAt == TimePoint{}) {
        normalized.updatedAt = now;
    }

    for (auto& action : normalized.actions) {
        if (action.actionId.empty()) {
            Logger::Warn("{} Rejecting playbook '{}' because one or more actions have empty IDs",
                kLogPrefix, playbook.playbookId);
            return std::nullopt;
        }

        action.result = ActionResult::Pending;
        action.resultDetail.clear();
        action.executedAt = TimePoint{};
    }

    return normalized;
}

bool SOARPlaybooksImpl::PersistPlaybook(const Playbook& playbook) const {
    auto& db = DB::Instance();
    DBErr err;

    auto transaction = db.BeginTransaction(ShadowStrike::Database::Transaction::Type::Immediate, &err);
    if (transaction == nullptr || err.HasError()) {
        Logger::Error("{} Failed to begin playbook transaction for '{}': {}",
            kLogPrefix, playbook.playbookId, SU::ToNarrow(err.message));
        return false;
    }

    constexpr std::string_view kUpsertPlaybook = R"SQL(
        INSERT INTO xdr_soar_playbooks
            (playbook_id, name, description, status, trigger_type, source_rule_id,
             min_severity, domain_filter, created_at_ms, updated_at_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(playbook_id) DO UPDATE SET
            name = excluded.name,
            description = excluded.description,
            status = excluded.status,
            trigger_type = excluded.trigger_type,
            source_rule_id = excluded.source_rule_id,
            min_severity = excluded.min_severity,
            domain_filter = excluded.domain_filter,
            updated_at_ms = excluded.updated_at_ms
    )SQL";

    if (!transaction->ExecuteWithParams(
            kUpsertPlaybook,
            &err,
            playbook.playbookId,
            playbook.name,
            playbook.description,
            static_cast<int>(playbook.status),
            static_cast<int>(playbook.trigger.type),
            playbook.trigger.sourceRuleId,
            static_cast<int>(playbook.trigger.minSeverity),
            playbook.trigger.domainFilter,
            ToUnixMillis(playbook.createdAt),
            ToUnixMillis(playbook.updatedAt))) {
        (void)transaction->Rollback();
        Logger::Error("{} Failed to persist playbook '{}': {}",
            kLogPrefix, playbook.playbookId, SU::ToNarrow(err.message));
        return false;
    }

    err.Clear();
    if (!transaction->ExecuteWithParams(
            "DELETE FROM xdr_soar_playbook_actions WHERE playbook_id = ?",
            &err,
            playbook.playbookId)) {
        (void)transaction->Rollback();
        Logger::Error("{} Failed to clear existing actions for playbook '{}': {}",
            kLogPrefix, playbook.playbookId, SU::ToNarrow(err.message));
        return false;
    }

    constexpr std::string_view kInsertAction = R"SQL(
        INSERT INTO xdr_soar_playbook_actions
            (playbook_id, action_id, action_type, target, parameters, action_order)
        VALUES (?, ?, ?, ?, ?, ?)
    )SQL";

    for (size_t index = 0; index < playbook.actions.size(); ++index) {
        const auto& action = playbook.actions[index];
        err.Clear();
        if (!transaction->ExecuteWithParams(
                kInsertAction,
                &err,
                playbook.playbookId,
                action.actionId,
                static_cast<int>(action.type),
                action.target,
                SerializeParameters(action.parameters),
                static_cast<int>(index))) {
            (void)transaction->Rollback();
            Logger::Error("{} Failed to persist action '{}' for playbook '{}': {}",
                kLogPrefix, action.actionId, playbook.playbookId, SU::ToNarrow(err.message));
            return false;
        }
    }

    err.Clear();
    if (!transaction->Commit(&err)) {
        Logger::Error("{} Failed to commit playbook '{}' transaction: {}",
            kLogPrefix, playbook.playbookId, SU::ToNarrow(err.message));
        return false;
    }

    return true;
}

bool SOARPlaybooksImpl::DeletePlaybookFromDb(const std::string_view playbookId) const {
    auto& db = DB::Instance();
    DBErr err;

    if (!db.ExecuteWithParams(
            "DELETE FROM xdr_soar_playbooks WHERE playbook_id = ?",
            &err,
            std::string(playbookId))) {
        Logger::Error("{} Failed to delete playbook '{}': {}",
            kLogPrefix, playbookId, SU::ToNarrow(err.message));
        return false;
    }

    return true;
}

bool SOARPlaybooksImpl::LoadPlaybooksFromDb() {
    auto& db = DB::Instance();
    DBErr err;

    auto result = db.Query(
        "SELECT playbook_id, name, description, status, trigger_type, source_rule_id, "
        "min_severity, domain_filter, created_at_ms, updated_at_ms "
        "FROM xdr_soar_playbooks",
        &err);
    if (err.HasError()) {
        Logger::Error("{} Failed to load SOAR playbooks: {}", kLogPrefix, SU::ToNarrow(err.message));
        return false;
    }

    std::unordered_map<std::string, Playbook> loadedPlaybooks;

    while (result.Next()) {
        Playbook playbook;
        playbook.playbookId = result.GetString(0);
        playbook.name = result.GetString(1);
        playbook.description = result.GetString(2);
        playbook.status = static_cast<PlaybookStatus>(result.GetInt(3));
        playbook.trigger.type = static_cast<TriggerType>(result.GetInt(4));
        playbook.trigger.sourceRuleId = result.GetString(5);
        playbook.trigger.minSeverity = static_cast<uint8_t>(result.GetInt(6));
        playbook.trigger.domainFilter = result.GetString(7);
        playbook.createdAt = FromUnixMillis(result.GetInt64(8));
        playbook.updatedAt = FromUnixMillis(result.GetInt64(9));

        DBErr actionErr;
        auto actionResult = db.QueryWithParams(
            "SELECT action_id, action_type, target, parameters, action_order "
            "FROM xdr_soar_playbook_actions WHERE playbook_id = ? ORDER BY action_order ASC",
            &actionErr,
            playbook.playbookId);
        if (actionErr.HasError()) {
            Logger::Warn("{} Failed to load actions for playbook '{}': {}",
                kLogPrefix, playbook.playbookId, SU::ToNarrow(actionErr.message));
        } else {
            while (actionResult.Next()) {
                SOARAction action;
                action.actionId = actionResult.GetString(0);
                action.type = static_cast<ActionType>(actionResult.GetInt(1));
                action.target = actionResult.GetString(2);
                action.parameters = DeserializeParameters(actionResult.GetString(3));
                playbook.actions.push_back(std::move(action));
            }
        }

        loadedPlaybooks.emplace(playbook.playbookId, std::move(playbook));
    }

    {
        std::unique_lock lock(mutex);
        playbooks = std::move(loadedPlaybooks);
    }

    Logger::Info("{} Loaded {} SOAR playbooks from database", kLogPrefix, playbooks.size());
    return true;
}

bool SOARPlaybooksImpl::Initialize() {
    if (initialized.load(std::memory_order_acquire)) {
        return true;
    }

    auto& db = DB::Instance();
    if (!db.IsInitialized()) {
        Logger::Error("{} DatabaseManager is not initialized", kLogPrefix);
        return false;
    }

    Logger::Info("{} Initializing SOAR playbook manager...", kLogPrefix);

    if (!CreateSchema()) {
        return false;
    }

    if (!LoadPlaybooksFromDb()) {
        return false;
    }

    if (playbooks.empty() && !InstallDefaultPlaybooks()) {
        Logger::Warn("{} Default SOAR playbook installation reported failures", kLogPrefix);
    }

    initialized.store(true, std::memory_order_release);
    Logger::Info("{} SOAR playbook manager initialized with {} playbooks",
        kLogPrefix, playbooks.size());
    return true;
}

void SOARPlaybooksImpl::Shutdown() {
    if (!initialized.exchange(false, std::memory_order_acq_rel)) {
        return;
    }

    std::unique_lock lock(mutex);
    const auto cleared = playbooks.size();
    playbooks.clear();
    Logger::Info("{} SOAR playbook manager shut down (cleared {} playbooks)",
        kLogPrefix, cleared);
}

bool SOARPlaybooksImpl::AddPlaybook(const Playbook& playbook) {
    const auto normalized = ValidateAndNormalize(playbook);
    if (!normalized.has_value()) {
        return false;
    }

    std::unique_lock lock(mutex);
    if (playbooks.size() >= kMaxPlaybooks) {
        Logger::Warn("{} Cannot add playbook '{}' because the manager is at capacity ({})",
            kLogPrefix, playbook.playbookId, kMaxPlaybooks);
        return false;
    }

    if (playbooks.contains(normalized->playbookId)) {
        Logger::Warn("{} Playbook '{}' already exists",
            kLogPrefix, normalized->playbookId);
        return false;
    }

    if (!PersistPlaybook(*normalized)) {
        return false;
    }

    playbooks.emplace(normalized->playbookId, *normalized);
    Logger::Info("{} Added SOAR playbook '{}' ({})",
        kLogPrefix, normalized->playbookId, normalized->name);
    return true;
}

bool SOARPlaybooksImpl::RemovePlaybook(const std::string_view playbookId) {
    std::unique_lock lock(mutex);
    auto it = playbooks.find(std::string(playbookId));
    if (it == playbooks.end()) {
        return false;
    }

    if (!DeletePlaybookFromDb(playbookId)) {
        return false;
    }

    playbooks.erase(it);
    Logger::Info("{} Removed SOAR playbook '{}'", kLogPrefix, playbookId);
    return true;
}

bool SOARPlaybooksImpl::UpdatePlaybook(const Playbook& playbook) {
    const auto normalized = ValidateAndNormalize(playbook);
    if (!normalized.has_value()) {
        return false;
    }

    std::unique_lock lock(mutex);
    auto it = playbooks.find(normalized->playbookId);
    if (it == playbooks.end()) {
        Logger::Warn("{} Playbook '{}' not found for update",
            kLogPrefix, normalized->playbookId);
        return false;
    }

    Playbook persisted = *normalized;
    persisted.createdAt = it->second.createdAt == TimePoint{} ? persisted.createdAt : it->second.createdAt;
    persisted.updatedAt = Clock::now();

    if (!PersistPlaybook(persisted)) {
        return false;
    }

    it->second = std::move(persisted);
    Logger::Info("{} Updated SOAR playbook '{}' (status={})",
        kLogPrefix, playbook.playbookId, PlaybookStatusToString(it->second.status));
    return true;
}

std::optional<Playbook> SOARPlaybooksImpl::GetPlaybook(const std::string_view playbookId) const {
    std::shared_lock lock(mutex);
    const auto it = playbooks.find(std::string(playbookId));
    if (it == playbooks.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::vector<Playbook> SOARPlaybooksImpl::GetActivePlaybooks() const {
    std::shared_lock lock(mutex);
    std::vector<Playbook> activePlaybooks;
    activePlaybooks.reserve(playbooks.size());
    for (const auto& [playbookId, playbook] : playbooks) {
        (void)playbookId;
        if (playbook.status == PlaybookStatus::Active) {
            activePlaybooks.push_back(playbook);
        }
    }
    return activePlaybooks;
}

std::vector<Playbook> SOARPlaybooksImpl::GetAllPlaybooks() const {
    std::shared_lock lock(mutex);
    std::vector<Playbook> allPlaybooks;
    allPlaybooks.reserve(playbooks.size());
    for (const auto& [playbookId, playbook] : playbooks) {
        (void)playbookId;
        allPlaybooks.push_back(playbook);
    }
    return allPlaybooks;
}

uint32_t SOARPlaybooksImpl::GetPlaybookCount() const {
    std::shared_lock lock(mutex);
    return static_cast<uint32_t>(playbooks.size());
}

bool SOARPlaybooksImpl::InstallDefaultPlaybooks() {
    Logger::Info("{} Installing default SOAR playbooks...", kLogPrefix);

    uint32_t installed = 0;
    uint32_t skipped = 0;

    for (const auto& playbook : BuildDefaultPlaybooks()) {
        if (GetPlaybook(playbook.playbookId).has_value()) {
            ++skipped;
            continue;
        }

        if (AddPlaybook(playbook)) {
            ++installed;
            continue;
        }

        Logger::Warn("{} Default playbook '{}' could not be installed",
            kLogPrefix, playbook.playbookId);
    }

    Logger::Info("{} Default SOAR playbook installation complete (installed={}, skipped={})",
        kLogPrefix, installed, skipped);
    return installed > 0U || skipped == BuildDefaultPlaybooks().size();
}

SOARPlaybooks& SOARPlaybooks::Instance() {
    static SOARPlaybooks instance;
    return instance;
}

bool SOARPlaybooks::HasInstance() noexcept {
    return Instance().IsInitialized();
}

SOARPlaybooks::SOARPlaybooks()
    : m_impl(std::make_unique<SOARPlaybooksImpl>()) {
}

SOARPlaybooks::~SOARPlaybooks() {
    Shutdown();
}

bool SOARPlaybooks::Initialize() {
    return m_impl->Initialize();
}

void SOARPlaybooks::Shutdown() {
    m_impl->Shutdown();
}

bool SOARPlaybooks::IsInitialized() const noexcept {
    return m_impl->initialized.load(std::memory_order_acquire);
}

bool SOARPlaybooks::AddPlaybook(const Playbook& playbook) {
    return m_impl->AddPlaybook(playbook);
}

bool SOARPlaybooks::RemovePlaybook(const std::string_view playbookId) {
    return m_impl->RemovePlaybook(playbookId);
}

bool SOARPlaybooks::UpdatePlaybook(const Playbook& playbook) {
    return m_impl->UpdatePlaybook(playbook);
}

std::optional<Playbook> SOARPlaybooks::GetPlaybook(const std::string_view playbookId) const {
    return m_impl->GetPlaybook(playbookId);
}

std::vector<Playbook> SOARPlaybooks::GetActivePlaybooks() const {
    return m_impl->GetActivePlaybooks();
}

std::vector<Playbook> SOARPlaybooks::GetAllPlaybooks() const {
    return m_impl->GetAllPlaybooks();
}

uint32_t SOARPlaybooks::GetPlaybookCount() const {
    return m_impl->GetPlaybookCount();
}

bool SOARPlaybooks::InstallDefaultPlaybooks() {
    return m_impl->InstallDefaultPlaybooks();
}

} // namespace ShadowStrike::Products::PhantomXDR::SOARLocal
