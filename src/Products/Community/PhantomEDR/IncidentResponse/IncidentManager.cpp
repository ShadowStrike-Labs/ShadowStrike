#include "pch.h"
#include "Products/Community/PhantomEDR/IncidentResponse/IncidentManager.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <ctime>
#include <format>
#include <iomanip>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_set>

#include <nlohmann/json.hpp>

#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/Utils/HashUtils.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"

namespace ShadowStrike::Products::PhantomEDR::IncidentResponse {

namespace {

using json = nlohmann::json;
using Clock = std::chrono::system_clock;
using ShadowStrike::Database::DatabaseError;
using ShadowStrike::Database::DatabaseManager;
using ShadowStrike::Utils::HashUtils::Algorithm;

constexpr std::string_view kLogPrefix = "[IncidentManager]";
constexpr std::string_view kCreateTableSql = R"(
    CREATE TABLE IF NOT EXISTS incidents (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        severity INTEGER NOT NULL,
        status INTEGER NOT NULL,
        phase INTEGER NOT NULL,
        assignee TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        closed_at TEXT,
        score REAL NOT NULL,
        affected_process_ids TEXT NOT NULL,
        affected_files TEXT NOT NULL,
        related_alert_ids TEXT NOT NULL,
        related_event_ids TEXT NOT NULL,
        mitre_attack_ids TEXT NOT NULL,
        containment_actions TEXT NOT NULL,
        remediation_actions TEXT NOT NULL,
        notes TEXT NOT NULL
    );
)";

constexpr std::string_view kCreateIndexSql = R"(
    CREATE INDEX IF NOT EXISTS idx_incidents_status_created ON incidents(status, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_incidents_severity_created ON incidents(severity, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_incidents_updated ON incidents(updated_at DESC);
)";

constexpr std::string_view kInsertIncidentSql = R"(
    INSERT INTO incidents (
        id, title, description, severity, status, phase, assignee,
        created_at, updated_at, closed_at, score,
        affected_process_ids, affected_files, related_alert_ids, related_event_ids,
        mitre_attack_ids, containment_actions, remediation_actions, notes
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
)";

constexpr std::string_view kUpdateIncidentSql = R"(
    UPDATE incidents
       SET title = ?,
           description = ?,
           severity = ?,
           status = ?,
           phase = ?,
           assignee = ?,
           created_at = ?,
           updated_at = ?,
           closed_at = ?,
           score = ?,
           affected_process_ids = ?,
           affected_files = ?,
           related_alert_ids = ?,
           related_event_ids = ?,
           mitre_attack_ids = ?,
           containment_actions = ?,
           remediation_actions = ?,
           notes = ?
     WHERE id = ?;
)";

[[nodiscard]] bool IsDefaultTimePoint(const Clock::time_point& value) noexcept
{
    return value.time_since_epoch().count() == 0;
}

[[nodiscard]] std::string ToIso8601(const Clock::time_point& value)
{
    if (IsDefaultTimePoint(value)) {
        return {};
    }

    const auto timeT = Clock::to_time_t(value);
    std::tm utcTime{};
    gmtime_s(&utcTime, &timeT);

    std::ostringstream stream;
    stream << std::put_time(&utcTime, "%Y-%m-%dT%H:%M:%SZ");
    return stream.str();
}

[[nodiscard]] std::optional<Clock::time_point> FromIso8601(std::string_view value)
{
    if (value.empty()) {
        return std::nullopt;
    }

    std::tm utcTime{};
    std::istringstream stream{std::string(value)};
    stream >> std::get_time(&utcTime, "%Y-%m-%dT%H:%M:%SZ");
    if (stream.fail()) {
        return std::nullopt;
    }

    const time_t rawTime = _mkgmtime(&utcTime);
    if (rawTime < 0) {
        return std::nullopt;
    }

    return Clock::from_time_t(rawTime);
}

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

template <typename EnumT>
[[nodiscard]] std::string SerializeEnumVector(const std::vector<EnumT>& values)
{
    json array = json::array();
    for (const auto value : values) {
        array.push_back(static_cast<int>(value));
    }
    return array.dump();
}

template <typename EnumT>
[[nodiscard]] std::vector<EnumT> DeserializeEnumVector(std::string_view serialized)
{
    std::vector<EnumT> values;
    if (serialized.empty()) {
        return values;
    }

    try {
        const auto array = json::parse(serialized, nullptr, true, true);
        if (!array.is_array()) {
            return values;
        }

        values.reserve(array.size());
        for (const auto& item : array) {
            if (item.is_number_integer()) {
                values.push_back(static_cast<EnumT>(item.get<int>()));
            }
        }
    }
    catch (const std::exception& ex) {
        ShadowStrike::Utils::Logger::Warn(
            "{} Failed to deserialize enum vector: {}",
            kLogPrefix,
            ex.what());
    }

    return values;
}

[[nodiscard]] std::string SerializeStringVector(const std::vector<std::string>& values)
{
    return json(values).dump();
}

[[nodiscard]] std::vector<std::string> DeserializeStringVector(std::string_view serialized)
{
    std::vector<std::string> values;
    if (serialized.empty()) {
        return values;
    }

    try {
        const auto array = json::parse(serialized, nullptr, true, true);
        if (!array.is_array()) {
            return values;
        }

        values.reserve(array.size());
        for (const auto& item : array) {
            if (item.is_string()) {
                values.push_back(item.get<std::string>());
            }
        }
    }
    catch (const std::exception& ex) {
        ShadowStrike::Utils::Logger::Warn(
            "{} Failed to deserialize string vector: {}",
            kLogPrefix,
            ex.what());
    }

    return values;
}

[[nodiscard]] std::string SerializeWideStringVector(const std::vector<std::wstring>& values)
{
    json array = json::array();
    for (const auto& value : values) {
        array.push_back(ShadowStrike::Utils::StringUtils::ToNarrow(value));
    }
    return array.dump();
}

[[nodiscard]] std::vector<std::wstring> DeserializeWideStringVector(std::string_view serialized)
{
    std::vector<std::wstring> values;
    if (serialized.empty()) {
        return values;
    }

    try {
        const auto array = json::parse(serialized, nullptr, true, true);
        if (!array.is_array()) {
            return values;
        }

        values.reserve(array.size());
        for (const auto& item : array) {
            if (item.is_string()) {
                values.push_back(ShadowStrike::Utils::StringUtils::ToWide(item.get<std::string>()));
            }
        }
    }
    catch (const std::exception& ex) {
        ShadowStrike::Utils::Logger::Warn(
            "{} Failed to deserialize wide string vector: {}",
            kLogPrefix,
            ex.what());
    }

    return values;
}

[[nodiscard]] std::string SerializeUInt32Vector(const std::vector<uint32_t>& values)
{
    return json(values).dump();
}

[[nodiscard]] std::vector<uint32_t> DeserializeUInt32Vector(std::string_view serialized)
{
    std::vector<uint32_t> values;
    if (serialized.empty()) {
        return values;
    }

    try {
        const auto array = json::parse(serialized, nullptr, true, true);
        if (!array.is_array()) {
            return values;
        }

        values.reserve(array.size());
        for (const auto& item : array) {
            if (item.is_number_unsigned()) {
                values.push_back(item.get<uint32_t>());
            } else if (item.is_number_integer()) {
                const auto rawValue = item.get<int64_t>();
                if (rawValue >= 0 && rawValue <= std::numeric_limits<uint32_t>::max()) {
                    values.push_back(static_cast<uint32_t>(rawValue));
                }
            }
        }
    }
    catch (const std::exception& ex) {
        ShadowStrike::Utils::Logger::Warn(
            "{} Failed to deserialize uint32 vector: {}",
            kLogPrefix,
            ex.what());
    }

    return values;
}

[[nodiscard]] std::string SerializeUInt64Vector(const std::vector<uint64_t>& values)
{
    return json(values).dump();
}

[[nodiscard]] std::vector<uint64_t> DeserializeUInt64Vector(std::string_view serialized)
{
    std::vector<uint64_t> values;
    if (serialized.empty()) {
        return values;
    }

    try {
        const auto array = json::parse(serialized, nullptr, true, true);
        if (!array.is_array()) {
            return values;
        }

        values.reserve(array.size());
        for (const auto& item : array) {
            if (item.is_number_unsigned()) {
                values.push_back(item.get<uint64_t>());
            } else if (item.is_number_integer()) {
                const auto rawValue = item.get<int64_t>();
                if (rawValue >= 0) {
                    values.push_back(static_cast<uint64_t>(rawValue));
                }
            }
        }
    }
    catch (const std::exception& ex) {
        ShadowStrike::Utils::Logger::Warn(
            "{} Failed to deserialize uint64 vector: {}",
            kLogPrefix,
            ex.what());
    }

    return values;
}

[[nodiscard]] std::string SerializeNotes(const std::vector<IncidentNote>& notes)
{
    json array = json::array();
    for (const auto& [timestamp, message] : notes) {
        array.push_back(
            {
                {"timestamp", ToIso8601(timestamp)},
                {"message", message}
            });
    }
    return array.dump();
}

[[nodiscard]] std::vector<IncidentNote> DeserializeNotes(std::string_view serialized)
{
    std::vector<IncidentNote> notes;
    if (serialized.empty()) {
        return notes;
    }

    try {
        const auto array = json::parse(serialized, nullptr, true, true);
        if (!array.is_array()) {
            return notes;
        }

        notes.reserve(array.size());
        for (const auto& item : array) {
            if (!item.is_object()) {
                continue;
            }

            const auto timestampIt = item.find("timestamp");
            const auto messageIt = item.find("message");
            if (timestampIt == item.end() || !timestampIt->is_string() ||
                messageIt == item.end() || !messageIt->is_string()) {
                continue;
            }

            const auto parsedTime = FromIso8601(timestampIt->get<std::string>());
            if (!parsedTime.has_value()) {
                continue;
            }

            notes.emplace_back(*parsedTime, messageIt->get<std::string>());
        }
    }
    catch (const std::exception& ex) {
        ShadowStrike::Utils::Logger::Warn(
            "{} Failed to deserialize notes: {}",
            kLogPrefix,
            ex.what());
    }

    return notes;
}

[[nodiscard]] IncidentPhase PhaseForStatus(const IncidentStatus status) noexcept
{
    switch (status) {
        case IncidentStatus::New:           return IncidentPhase::New;
        case IncidentStatus::Triaged:       return IncidentPhase::Triaged;
        case IncidentStatus::Investigating: return IncidentPhase::Investigating;
        case IncidentStatus::Containing:    return IncidentPhase::Containing;
        case IncidentStatus::Remediating:   return IncidentPhase::Remediating;
        case IncidentStatus::Closed:        return IncidentPhase::Closed;
        case IncidentStatus::FalsePositive: return IncidentPhase::FalsePositive;
    }

    return IncidentPhase::New;
}

[[nodiscard]] bool IsClosedStatus(const IncidentStatus status) noexcept
{
    return status == IncidentStatus::Closed || status == IncidentStatus::FalsePositive;
}

[[nodiscard]] bool IsValidTransition(const IncidentStatus currentStatus, const IncidentStatus newStatus) noexcept
{
    if (currentStatus == newStatus) {
        return true;
    }

    switch (currentStatus) {
        case IncidentStatus::New:
            return newStatus == IncidentStatus::Triaged || newStatus == IncidentStatus::FalsePositive;
        case IncidentStatus::Triaged:
            return newStatus == IncidentStatus::Investigating || newStatus == IncidentStatus::FalsePositive;
        case IncidentStatus::Investigating:
            return newStatus == IncidentStatus::Containing ||
                   newStatus == IncidentStatus::Remediating ||
                   newStatus == IncidentStatus::FalsePositive;
        case IncidentStatus::Containing:
            return newStatus == IncidentStatus::Remediating ||
                   newStatus == IncidentStatus::Investigating;
        case IncidentStatus::Remediating:
            return newStatus == IncidentStatus::Closed ||
                   newStatus == IncidentStatus::Investigating;
        case IncidentStatus::Closed:
        case IncidentStatus::FalsePositive:
            return false;
    }

    return false;
}

[[nodiscard]] Incident NormalizeIncident(Incident incident)
{
    const auto now = Clock::now();
    if (incident.incidentId.empty()) {
        incident.incidentId = {};
    }
    if (incident.title.empty()) {
        incident.title = "Untitled Incident";
    }
    if (incident.description.empty()) {
        incident.description = "No description provided.";
    }
    if (IsDefaultTimePoint(incident.createdAt)) {
        incident.createdAt = now;
    }
    if (IsDefaultTimePoint(incident.updatedAt)) {
        incident.updatedAt = incident.createdAt;
    }
    incident.phase = PhaseForStatus(incident.status);
    incident.score = std::clamp(incident.score, 0.0, 100.0);

    if (IsClosedStatus(incident.status) && !incident.closedAt.has_value()) {
        incident.closedAt = incident.updatedAt;
    }
    if (!IsClosedStatus(incident.status)) {
        incident.closedAt.reset();
    }

    return incident;
}

[[nodiscard]] std::string BuildIncidentId()
{
    static std::mutex generatorMutex;
    static std::mt19937_64 generator(std::random_device{}());

    const auto now = Clock::now().time_since_epoch().count();
    uint64_t randomValue = 0;
    {
        std::lock_guard lock(generatorMutex);
        randomValue = generator();
    }

    const std::string material = std::format("{}-{}", now, randomValue);
    std::string digest;
    if (!ShadowStrike::Utils::HashUtils::ComputeHex(
            Algorithm::SHA256,
            material.data(),
            material.size(),
            digest,
            false,
            nullptr)) {
        const std::array<uint8_t, sizeof(uint64_t)> randomBytes = {
            static_cast<uint8_t>((randomValue >> 56) & 0xFF),
            static_cast<uint8_t>((randomValue >> 48) & 0xFF),
            static_cast<uint8_t>((randomValue >> 40) & 0xFF),
            static_cast<uint8_t>((randomValue >> 32) & 0xFF),
            static_cast<uint8_t>((randomValue >> 24) & 0xFF),
            static_cast<uint8_t>((randomValue >> 16) & 0xFF),
            static_cast<uint8_t>((randomValue >> 8) & 0xFF),
            static_cast<uint8_t>(randomValue & 0xFF)
        };
        digest = ShadowStrike::Utils::HashUtils::ToHexLower(randomBytes.data(), randomBytes.size());
    }

    return std::format("INC-{}-{}", digest.substr(0, 12), digest.substr(12, 6));
}

[[nodiscard]] std::string DbErrorToNarrow(const DatabaseError& error)
{
    return ShadowStrike::Utils::StringUtils::ToNarrow(error.message);
}

} // namespace

class IncidentManagerImpl {
public:
    [[nodiscard]] bool Initialize();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const;
    [[nodiscard]] std::string CreateIncident(const Incident& incident);
    [[nodiscard]] bool UpdateIncident(const Incident& incident);
    [[nodiscard]] std::optional<Incident> GetIncident(std::string_view incidentId) const;
    [[nodiscard]] std::vector<Incident> QueryIncidents(const IncidentQueryParams& params) const;
    [[nodiscard]] bool TransitionStatus(std::string_view incidentId, IncidentStatus newStatus);
    [[nodiscard]] bool AddNote(std::string_view incidentId, std::string_view note);
    [[nodiscard]] bool AssignIncident(std::string_view incidentId, std::string_view assignee);
    [[nodiscard]] bool MergeIncidents(std::string_view primaryId, std::string_view secondaryId);
    [[nodiscard]] uint64_t GetOpenIncidentCount() const;
    [[nodiscard]] std::vector<Incident> GetRecentIncidents(size_t count) const;

private:
    [[nodiscard]] std::optional<Incident> QueryIncidentByIdUnlocked(std::string_view incidentId) const;
    [[nodiscard]] bool PersistIncidentUnlocked(const Incident& incident) const;
    [[nodiscard]] Incident ReadIncidentRow(ShadowStrike::Database::QueryResult& result) const;

    mutable std::shared_mutex m_mutex;
    bool m_initialized = false;
};

bool IncidentManagerImpl::Initialize()
{
    std::unique_lock lock(m_mutex);
    if (m_initialized) {
        ShadowStrike::Utils::Logger::Debug("{} Already initialized", kLogPrefix);
        return true;
    }

    auto& databaseManager = DatabaseManager::Instance();
    if (!databaseManager.IsInitialized()) {
        ShadowStrike::Utils::Logger::Error(
            "{} DatabaseManager is not initialized; incident storage unavailable",
            kLogPrefix);
        return false;
    }

    DatabaseError error;
    if (!databaseManager.Execute(kCreateTableSql.data(), &error)) {
        ShadowStrike::Utils::Logger::Error(
            "{} Failed to create incidents table: {}",
            kLogPrefix,
            DbErrorToNarrow(error));
        return false;
    }

    if (!databaseManager.Execute(kCreateIndexSql.data(), &error)) {
        ShadowStrike::Utils::Logger::Error(
            "{} Failed to create incident indices: {}",
            kLogPrefix,
            DbErrorToNarrow(error));
        return false;
    }

    m_initialized = true;
    ShadowStrike::Utils::Logger::Info("{} Initialized incident storage", kLogPrefix);
    return true;
}

void IncidentManagerImpl::Shutdown()
{
    std::unique_lock lock(m_mutex);
    if (!m_initialized) {
        return;
    }

    m_initialized = false;
    ShadowStrike::Utils::Logger::Info("{} Shutdown complete", kLogPrefix);
}

bool IncidentManagerImpl::IsInitialized() const
{
    std::shared_lock lock(m_mutex);
    return m_initialized;
}

std::string IncidentManagerImpl::CreateIncident(const Incident& incident)
{
    std::unique_lock lock(m_mutex);
    if (!m_initialized) {
        ShadowStrike::Utils::Logger::Warn("{} CreateIncident called before initialization", kLogPrefix);
        return {};
    }

    Incident storedIncident = NormalizeIncident(incident);
    if (storedIncident.incidentId.empty()) {
        storedIncident.incidentId = BuildIncidentId();
    }

    DatabaseError error;
    auto& databaseManager = DatabaseManager::Instance();
    if (!databaseManager.ExecuteWithParams(
            kInsertIncidentSql,
            &error,
            storedIncident.incidentId,
            storedIncident.title,
            storedIncident.description,
            static_cast<int>(storedIncident.severity),
            static_cast<int>(storedIncident.status),
            static_cast<int>(storedIncident.phase),
            storedIncident.assignee,
            ToIso8601(storedIncident.createdAt),
            ToIso8601(storedIncident.updatedAt),
            storedIncident.closedAt.has_value() ? ToIso8601(*storedIncident.closedAt) : std::string{},
            storedIncident.score,
            SerializeUInt32Vector(storedIncident.affectedProcessIds),
            SerializeWideStringVector(storedIncident.affectedFiles),
            SerializeStringVector(storedIncident.relatedAlertIds),
            SerializeUInt64Vector(storedIncident.relatedEventIds),
            SerializeStringVector(storedIncident.mitreAttackIds),
            SerializeEnumVector(storedIncident.containmentActions),
            SerializeEnumVector(storedIncident.remediationActions),
            SerializeNotes(storedIncident.notes))) {
        ShadowStrike::Utils::Logger::Error(
            "{} Failed to create incident {}: {}",
            kLogPrefix,
            storedIncident.incidentId,
            DbErrorToNarrow(error));
        return {};
    }

    ShadowStrike::Utils::Logger::Info(
        "{} Created incident {} with severity {}",
        kLogPrefix,
        storedIncident.incidentId,
        static_cast<int>(storedIncident.severity));
    return storedIncident.incidentId;
}

bool IncidentManagerImpl::PersistIncidentUnlocked(const Incident& incident) const
{
    DatabaseError error;
    const Incident normalizedIncident = NormalizeIncident(incident);
    auto& databaseManager = DatabaseManager::Instance();

    const bool success = databaseManager.ExecuteWithParams(
        kUpdateIncidentSql,
        &error,
        normalizedIncident.title,
        normalizedIncident.description,
        static_cast<int>(normalizedIncident.severity),
        static_cast<int>(normalizedIncident.status),
        static_cast<int>(normalizedIncident.phase),
        normalizedIncident.assignee,
        ToIso8601(normalizedIncident.createdAt),
        ToIso8601(normalizedIncident.updatedAt),
        normalizedIncident.closedAt.has_value() ? ToIso8601(*normalizedIncident.closedAt) : std::string{},
        normalizedIncident.score,
        SerializeUInt32Vector(normalizedIncident.affectedProcessIds),
        SerializeWideStringVector(normalizedIncident.affectedFiles),
        SerializeStringVector(normalizedIncident.relatedAlertIds),
        SerializeUInt64Vector(normalizedIncident.relatedEventIds),
        SerializeStringVector(normalizedIncident.mitreAttackIds),
        SerializeEnumVector(normalizedIncident.containmentActions),
        SerializeEnumVector(normalizedIncident.remediationActions),
        SerializeNotes(normalizedIncident.notes),
        normalizedIncident.incidentId);

    if (!success) {
        ShadowStrike::Utils::Logger::Error(
            "{} Failed to update incident {}: {}",
            kLogPrefix,
            normalizedIncident.incidentId,
            DbErrorToNarrow(error));
        return false;
    }

    if (databaseManager.GetChangedRowCount() <= 0) {
        ShadowStrike::Utils::Logger::Warn(
            "{} Update affected no rows for incident {}",
            kLogPrefix,
            normalizedIncident.incidentId);
        return false;
    }

    return true;
}

bool IncidentManagerImpl::UpdateIncident(const Incident& incident)
{
    std::unique_lock lock(m_mutex);
    if (!m_initialized) {
        return false;
    }
    if (incident.incidentId.empty()) {
        ShadowStrike::Utils::Logger::Warn("{} UpdateIncident rejected empty incident ID", kLogPrefix);
        return false;
    }

    return PersistIncidentUnlocked(incident);
}

Incident IncidentManagerImpl::ReadIncidentRow(ShadowStrike::Database::QueryResult& result) const
{
    Incident incident;
    incident.incidentId = result.GetString("id");
    incident.title = result.GetString("title");
    incident.description = result.GetString("description");
    incident.severity = static_cast<IncidentSeverity>(result.GetInt("severity"));
    incident.status = static_cast<IncidentStatus>(result.GetInt("status"));
    incident.phase = static_cast<IncidentPhase>(result.GetInt("phase"));
    incident.assignee = result.GetString("assignee");
    incident.createdAt = FromIso8601(result.GetString("created_at")).value_or(Clock::time_point{});
    incident.updatedAt = FromIso8601(result.GetString("updated_at")).value_or(Clock::time_point{});
    incident.closedAt = FromIso8601(result.GetString("closed_at"));
    incident.score = result.GetDouble("score");
    incident.affectedProcessIds = DeserializeUInt32Vector(result.GetString("affected_process_ids"));
    incident.affectedFiles = DeserializeWideStringVector(result.GetString("affected_files"));
    incident.relatedAlertIds = DeserializeStringVector(result.GetString("related_alert_ids"));
    incident.relatedEventIds = DeserializeUInt64Vector(result.GetString("related_event_ids"));
    incident.mitreAttackIds = DeserializeStringVector(result.GetString("mitre_attack_ids"));
    incident.containmentActions = DeserializeEnumVector<ContainmentAction>(result.GetString("containment_actions"));
    incident.remediationActions = DeserializeEnumVector<RemediationAction>(result.GetString("remediation_actions"));
    incident.notes = DeserializeNotes(result.GetString("notes"));
    return incident;
}

std::optional<Incident> IncidentManagerImpl::QueryIncidentByIdUnlocked(std::string_view incidentId) const
{
    DatabaseError error;
    auto result = DatabaseManager::Instance().QueryWithParams(
        "SELECT * FROM incidents WHERE id = ? LIMIT 1;",
        &error,
        std::string(incidentId));
    if (error.HasError()) {
        ShadowStrike::Utils::Logger::Error(
            "{} Failed to query incident {}: {}",
            kLogPrefix,
            incidentId,
            DbErrorToNarrow(error));
        return std::nullopt;
    }

    if (!result.Next()) {
        return std::nullopt;
    }

    return ReadIncidentRow(result);
}

std::optional<Incident> IncidentManagerImpl::GetIncident(std::string_view incidentId) const
{
    std::shared_lock lock(m_mutex);
    if (!m_initialized || incidentId.empty()) {
        return std::nullopt;
    }
    return QueryIncidentByIdUnlocked(incidentId);
}

std::vector<Incident> IncidentManagerImpl::QueryIncidents(const IncidentQueryParams& params) const
{
    std::shared_lock lock(m_mutex);
    std::vector<Incident> incidents;
    if (!m_initialized) {
        return incidents;
    }

    std::string sql = "SELECT * FROM incidents WHERE 1 = 1";
    std::vector<std::string> boundParameters;

    if (params.status.has_value()) {
        sql += " AND status = ?";
        boundParameters.push_back(std::to_string(static_cast<int>(*params.status)));
    }
    if (params.minSeverity.has_value()) {
        sql += " AND severity >= ?";
        boundParameters.push_back(std::to_string(static_cast<int>(*params.minSeverity)));
    }
    if (params.startTime.has_value()) {
        sql += " AND created_at >= ?";
        boundParameters.push_back(ToIso8601(*params.startTime));
    }
    if (params.endTime.has_value()) {
        sql += " AND created_at <= ?";
        boundParameters.push_back(ToIso8601(*params.endTime));
    }

    sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?;";
    const uint32_t maxResults = std::clamp<uint32_t>(params.maxResults, 1U, 1000U);
    boundParameters.push_back(std::to_string(maxResults));
    boundParameters.push_back(std::to_string(params.offset));

    DatabaseError error;
    auto result = DatabaseManager::Instance().QueryWithParamsVector(sql, boundParameters, &error);
    if (error.HasError()) {
        ShadowStrike::Utils::Logger::Error(
            "{} Failed to query incidents: {}",
            kLogPrefix,
            DbErrorToNarrow(error));
        return incidents;
    }

    while (result.Next()) {
        incidents.push_back(ReadIncidentRow(result));
    }

    return incidents;
}

bool IncidentManagerImpl::TransitionStatus(std::string_view incidentId, IncidentStatus newStatus)
{
    std::unique_lock lock(m_mutex);
    if (!m_initialized || incidentId.empty()) {
        return false;
    }

    auto incident = QueryIncidentByIdUnlocked(incidentId);
    if (!incident.has_value()) {
        return false;
    }

    if (!IsValidTransition(incident->status, newStatus)) {
        ShadowStrike::Utils::Logger::Warn(
            "{} Invalid incident status transition {} -> {} for {}",
            kLogPrefix,
            static_cast<int>(incident->status),
            static_cast<int>(newStatus),
            incidentId);
        return false;
    }

    incident->status = newStatus;
    incident->phase = PhaseForStatus(newStatus);
    incident->updatedAt = Clock::now();
    if (IsClosedStatus(newStatus)) {
        incident->closedAt = incident->updatedAt;
    }

    return PersistIncidentUnlocked(*incident);
}

bool IncidentManagerImpl::AddNote(std::string_view incidentId, std::string_view note)
{
    std::unique_lock lock(m_mutex);
    if (!m_initialized || incidentId.empty() || note.empty()) {
        return false;
    }

    auto incident = QueryIncidentByIdUnlocked(incidentId);
    if (!incident.has_value()) {
        return false;
    }

    incident->notes.emplace_back(Clock::now(), std::string(note));
    incident->updatedAt = Clock::now();
    return PersistIncidentUnlocked(*incident);
}

bool IncidentManagerImpl::AssignIncident(std::string_view incidentId, std::string_view assignee)
{
    std::unique_lock lock(m_mutex);
    if (!m_initialized || incidentId.empty()) {
        return false;
    }

    auto incident = QueryIncidentByIdUnlocked(incidentId);
    if (!incident.has_value()) {
        return false;
    }

    incident->assignee = std::string(assignee);
    incident->updatedAt = Clock::now();
    incident->notes.emplace_back(
        incident->updatedAt,
        std::format("Incident assigned to {}", assignee.empty() ? "unassigned" : std::string(assignee)));
    return PersistIncidentUnlocked(*incident);
}

bool IncidentManagerImpl::MergeIncidents(std::string_view primaryId, std::string_view secondaryId)
{
    std::unique_lock lock(m_mutex);
    if (!m_initialized || primaryId.empty() || secondaryId.empty() || primaryId == secondaryId) {
        return false;
    }

    auto primaryIncident = QueryIncidentByIdUnlocked(primaryId);
    auto secondaryIncident = QueryIncidentByIdUnlocked(secondaryId);
    if (!primaryIncident.has_value() || !secondaryIncident.has_value()) {
        return false;
    }

    AppendUniqueRange(primaryIncident->affectedProcessIds, secondaryIncident->affectedProcessIds);
    AppendUniqueRange(primaryIncident->affectedFiles, secondaryIncident->affectedFiles);
    AppendUniqueRange(primaryIncident->relatedAlertIds, secondaryIncident->relatedAlertIds);
    AppendUniqueRange(primaryIncident->relatedEventIds, secondaryIncident->relatedEventIds);
    AppendUniqueRange(primaryIncident->mitreAttackIds, secondaryIncident->mitreAttackIds);
    AppendUniqueRange(primaryIncident->containmentActions, secondaryIncident->containmentActions);
    AppendUniqueRange(primaryIncident->remediationActions, secondaryIncident->remediationActions);
    primaryIncident->notes.insert(
        primaryIncident->notes.end(),
        secondaryIncident->notes.begin(),
        secondaryIncident->notes.end());
    primaryIncident->severity = std::max(primaryIncident->severity, secondaryIncident->severity);
    primaryIncident->score = std::max(primaryIncident->score, secondaryIncident->score);
    primaryIncident->updatedAt = Clock::now();
    primaryIncident->notes.emplace_back(
        primaryIncident->updatedAt,
        std::format("Merged incident {} into {}", secondaryId, primaryId));

    secondaryIncident->relatedAlertIds.clear();
    secondaryIncident->relatedEventIds.clear();
    secondaryIncident->status = IncidentStatus::Closed;
    secondaryIncident->phase = IncidentPhase::Closed;
    secondaryIncident->updatedAt = primaryIncident->updatedAt;
    secondaryIncident->closedAt = primaryIncident->updatedAt;
    secondaryIncident->notes.emplace_back(
        secondaryIncident->updatedAt,
        std::format("Incident merged into {}", primaryId));

    DatabaseError error;
    auto transaction = DatabaseManager::Instance().BeginTransaction(
        ShadowStrike::Database::Transaction::Type::Immediate,
        &error);
    if (!transaction || !transaction->IsActive()) {
        ShadowStrike::Utils::Logger::Error(
            "{} Failed to begin merge transaction: {}",
            kLogPrefix,
            DbErrorToNarrow(error));
        return false;
    }

    const bool primaryUpdated = transaction->ExecuteWithParams(
        kUpdateIncidentSql,
        &error,
        primaryIncident->title,
        primaryIncident->description,
        static_cast<int>(primaryIncident->severity),
        static_cast<int>(primaryIncident->status),
        static_cast<int>(primaryIncident->phase),
        primaryIncident->assignee,
        ToIso8601(primaryIncident->createdAt),
        ToIso8601(primaryIncident->updatedAt),
        primaryIncident->closedAt.has_value() ? ToIso8601(*primaryIncident->closedAt) : std::string{},
        primaryIncident->score,
        SerializeUInt32Vector(primaryIncident->affectedProcessIds),
        SerializeWideStringVector(primaryIncident->affectedFiles),
        SerializeStringVector(primaryIncident->relatedAlertIds),
        SerializeUInt64Vector(primaryIncident->relatedEventIds),
        SerializeStringVector(primaryIncident->mitreAttackIds),
        SerializeEnumVector(primaryIncident->containmentActions),
        SerializeEnumVector(primaryIncident->remediationActions),
        SerializeNotes(primaryIncident->notes),
        primaryIncident->incidentId);

    const bool secondaryUpdated = primaryUpdated && transaction->ExecuteWithParams(
        kUpdateIncidentSql,
        &error,
        secondaryIncident->title,
        secondaryIncident->description,
        static_cast<int>(secondaryIncident->severity),
        static_cast<int>(secondaryIncident->status),
        static_cast<int>(secondaryIncident->phase),
        secondaryIncident->assignee,
        ToIso8601(secondaryIncident->createdAt),
        ToIso8601(secondaryIncident->updatedAt),
        secondaryIncident->closedAt.has_value() ? ToIso8601(*secondaryIncident->closedAt) : std::string{},
        secondaryIncident->score,
        SerializeUInt32Vector(secondaryIncident->affectedProcessIds),
        SerializeWideStringVector(secondaryIncident->affectedFiles),
        SerializeStringVector(secondaryIncident->relatedAlertIds),
        SerializeUInt64Vector(secondaryIncident->relatedEventIds),
        SerializeStringVector(secondaryIncident->mitreAttackIds),
        SerializeEnumVector(secondaryIncident->containmentActions),
        SerializeEnumVector(secondaryIncident->remediationActions),
        SerializeNotes(secondaryIncident->notes),
        secondaryIncident->incidentId);

    if (!secondaryUpdated || !transaction->Commit(&error)) {
        transaction->Rollback(nullptr);
        ShadowStrike::Utils::Logger::Error(
            "{} Failed to merge incidents {} and {}: {}",
            kLogPrefix,
            primaryId,
            secondaryId,
            DbErrorToNarrow(error));
        return false;
    }

    return true;
}

uint64_t IncidentManagerImpl::GetOpenIncidentCount() const
{
    std::shared_lock lock(m_mutex);
    if (!m_initialized) {
        return 0;
    }

    DatabaseError error;
    auto result = DatabaseManager::Instance().QueryWithParams(
        "SELECT COUNT(*) AS open_count FROM incidents WHERE status NOT IN (?, ?);",
        &error,
        static_cast<int>(IncidentStatus::Closed),
        static_cast<int>(IncidentStatus::FalsePositive));
    if (error.HasError() || !result.Next()) {
        if (error.HasError()) {
            ShadowStrike::Utils::Logger::Error(
                "{} Failed to count open incidents: {}",
                kLogPrefix,
                DbErrorToNarrow(error));
        }
        return 0;
    }

    return static_cast<uint64_t>(result.GetInt64("open_count"));
}

std::vector<Incident> IncidentManagerImpl::GetRecentIncidents(size_t count) const
{
    std::shared_lock lock(m_mutex);
    std::vector<Incident> incidents;
    if (!m_initialized || count == 0) {
        return incidents;
    }

    const int limitedCount = static_cast<int>(std::min<size_t>(count, 1000));
    DatabaseError error;
    auto result = DatabaseManager::Instance().QueryWithParams(
        "SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?;",
        &error,
        limitedCount);
    if (error.HasError()) {
        ShadowStrike::Utils::Logger::Error(
            "{} Failed to retrieve recent incidents: {}",
            kLogPrefix,
            DbErrorToNarrow(error));
        return incidents;
    }

    while (result.Next()) {
        incidents.push_back(ReadIncidentRow(result));
    }

    return incidents;
}

IncidentManager& IncidentManager::Instance()
{
    static IncidentManager instance;
    return instance;
}

IncidentManager::IncidentManager()
    : m_impl(std::make_unique<IncidentManagerImpl>())
{
}

IncidentManager::~IncidentManager() = default;

bool IncidentManager::Initialize()
{
    return m_impl->Initialize();
}

void IncidentManager::Shutdown()
{
    m_impl->Shutdown();
}

bool IncidentManager::IsInitialized() const
{
    return m_impl->IsInitialized();
}

std::string IncidentManager::CreateIncident(const Incident& incident)
{
    return m_impl->CreateIncident(incident);
}

bool IncidentManager::UpdateIncident(const Incident& incident)
{
    return m_impl->UpdateIncident(incident);
}

std::optional<Incident> IncidentManager::GetIncident(std::string_view incidentId) const
{
    return m_impl->GetIncident(incidentId);
}

std::vector<Incident> IncidentManager::QueryIncidents(const IncidentQueryParams& params) const
{
    return m_impl->QueryIncidents(params);
}

bool IncidentManager::TransitionStatus(std::string_view incidentId, IncidentStatus newStatus)
{
    return m_impl->TransitionStatus(incidentId, newStatus);
}

bool IncidentManager::AddNote(std::string_view incidentId, std::string_view note)
{
    return m_impl->AddNote(incidentId, note);
}

bool IncidentManager::AssignIncident(std::string_view incidentId, std::string_view assignee)
{
    return m_impl->AssignIncident(incidentId, assignee);
}

bool IncidentManager::MergeIncidents(std::string_view primaryId, std::string_view secondaryId)
{
    return m_impl->MergeIncidents(primaryId, secondaryId);
}

uint64_t IncidentManager::GetOpenIncidentCount() const
{
    return m_impl->GetOpenIncidentCount();
}

std::vector<Incident> IncidentManager::GetRecentIncidents(size_t count) const
{
    return m_impl->GetRecentIncidents(count);
}

} // namespace ShadowStrike::Products::PhantomEDR::IncidentResponse
