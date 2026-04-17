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
#include "Products/Community/PhantomEDR/ThreatHunting/IOCScanner.hpp"

#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/ThreatIntel/ThreatIntelFormat.hpp"
#include "PhantomCore/ThreatIntel/ThreatIntelLookup.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"
#include "Products/Community/PhantomEDR/Telemetry/TelemetryTypes.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <optional>
#include <shared_mutex>
#include <span>
#include <string_view>
#include <unordered_map>

namespace ShadowStrike::Products::PhantomEDR::ThreatHunting {

class IOCScannerImpl final {
public:
    std::atomic<bool> initialized{ false };
    mutable std::shared_mutex mutex;
    uint32_t maxScanMatches = 50000;
};

namespace {

using ShadowStrike::Database::DatabaseError;
using ShadowStrike::Database::DatabaseManager;
using ShadowStrike::Database::QueryResult;
using ShadowStrike::ThreatIntel::BatchLookupResult;
using ShadowStrike::ThreatIntel::IOCType;
using ShadowStrike::ThreatIntel::ThreatIntelLookup;
using ShadowStrike::ThreatIntel::ThreatLookupResult;
using ShadowStrike::Utils::Logger;
namespace StringUtils = ShadowStrike::Utils::StringUtils;
namespace Telemetry = ShadowStrike::Products::PhantomEDR::Telemetry;

constexpr std::string_view kWatchListTable = "hunt_ioc_watchlist";
constexpr uint32_t kProgressLogInterval = 100;

struct EventRow final {
    uint64_t eventId = 0;
    int64_t timestampNs = 0;
    uint32_t processId = 0;
    std::string processName;
    std::string userName;
    std::string payloadJson;
    std::string metadataJson;
};

struct ScanOutcome final {
    std::vector<IOCScanResult> hits;
    uint64_t eventsScanned = 0;
};

[[nodiscard]] int64_t ToEpochSeconds(const std::chrono::system_clock::time_point& timePoint) noexcept {
    return std::chrono::duration_cast<std::chrono::seconds>(timePoint.time_since_epoch()).count();
}

[[nodiscard]] int64_t ToEpochNanoseconds(const std::chrono::system_clock::time_point& timePoint) noexcept {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(timePoint.time_since_epoch()).count();
}

[[nodiscard]] std::chrono::system_clock::time_point FromEpochSeconds(const int64_t value) noexcept {
    return std::chrono::system_clock::time_point{
        std::chrono::duration_cast<std::chrono::system_clock::duration>(std::chrono::seconds(value))
    };
}

[[nodiscard]] std::chrono::system_clock::time_point FromEpochNanoseconds(const int64_t value) noexcept {
    return std::chrono::system_clock::time_point{
        std::chrono::duration_cast<std::chrono::system_clock::duration>(std::chrono::nanoseconds(value))
    };
}

[[nodiscard]] std::string ToLowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](const unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

[[nodiscard]] std::string EscapeLikeValue(std::string_view value) {
    std::string escaped;
    escaped.reserve(value.size() + 8);
    for (const char ch : value) {
        if (ch == '\\' || ch == '%' || ch == '_') {
            escaped.push_back('\\');
        }
        escaped.push_back(ch);
    }
    return escaped;
}

[[nodiscard]] std::string MakeContainsPattern(std::string_view value) {
    return "%" + EscapeLikeValue(value) + "%";
}

[[nodiscard]] bool HasTimeBounds(
    const std::optional<std::chrono::system_clock::time_point>& startTime,
    const std::optional<std::chrono::system_clock::time_point>& endTime) noexcept {
    return startTime.has_value() || endTime.has_value();
}

[[nodiscard]] EventRow ReadEventRow(QueryResult& result) {
    EventRow row;
    row.eventId = static_cast<uint64_t>(std::max<int64_t>(0, result.GetInt64(0)));
    row.timestampNs = result.GetInt64(1);
    row.processId = static_cast<uint32_t>(std::max(0, result.GetInt(2)));
    row.processName = result.IsNull(3) ? std::string{} : result.GetString(3);
    row.userName = result.IsNull(4) ? std::string{} : result.GetString(4);
    row.payloadJson = result.IsNull(5) ? std::string{} : result.GetString(5);
    row.metadataJson = result.IsNull(6) ? std::string{} : result.GetString(6);
    return row;
}

[[nodiscard]] IOCType ToThreatIntelType(const IOCCategory category) noexcept {
    switch (category) {
        case IOCCategory::FileHash: return IOCType::FileHash;
        case IOCCategory::IPv4: return IOCType::IPv4;
        case IOCCategory::IPv6: return IOCType::IPv6;
        case IOCCategory::Domain: return IOCType::Domain;
        case IOCCategory::URL: return IOCType::URL;
        case IOCCategory::MutexName: return IOCType::MutexName;
        case IOCCategory::RegistryKey: return IOCType::RegistryKey;
        case IOCCategory::NamedPipe: return IOCType::NamedPipe;
        case IOCCategory::ProcessName: return IOCType::ProcessName;
        case IOCCategory::Email: return IOCType::Email;
        case IOCCategory::JA3: return IOCType::JA3;
        case IOCCategory::UserAgent: return IOCType::UserAgent;
    }
    return IOCType::Reserved;
}

[[nodiscard]] ThreatIntelLookup& GetThreatIntelLookup() {
    static ThreatIntelLookup lookup;
    return lookup;
}

[[nodiscard]] std::string BuildThreatIntelSummary(const ThreatLookupResult& lookup) {
    if (!lookup.found) {
        return {};
    }

    return std::format(" | intel(found={}, score={}, source={}, malicious={})",
        lookup.found ? "true" : "false",
        static_cast<uint32_t>(lookup.threatScore),
        lookup.GetSourceString(),
        lookup.IsMalicious() ? "true" : "false");
}

[[nodiscard]] IOCScanResult MakeScanResult(
    const IOCEntry& ioc,
    const EventRow& row,
    std::string context,
    const ThreatLookupResult* intelResult = nullptr) {
    IOCScanResult hit;
    hit.ioc = ioc;
    hit.eventId = row.eventId;
    hit.eventTime = FromEpochNanoseconds(row.timestampNs);
    hit.processId = row.processId;
    hit.processName = StringUtils::ToWide(row.processName);
    hit.userName = StringUtils::ToWide(row.userName);
    if (intelResult != nullptr) {
        context += BuildThreatIntelSummary(*intelResult);
    }
    hit.matchContext = std::move(context);
    return hit;
}

[[nodiscard]] std::string BuildBaseSearchSql(std::string whereClause) {
    return
        "SELECT event_id, timestamp_ns, process_id, process_name, user_name, payload_json, metadata_json "
        "FROM telemetry_events" + std::move(whereClause) + " ORDER BY timestamp_ns DESC LIMIT ?;";
}

void AppendWhere(std::string& whereClause, const std::string& fragment) {
    whereClause += whereClause.empty() ? " WHERE " : " AND ";
    whereClause += fragment;
}

[[nodiscard]] std::vector<std::string> BuildSearchParams(
    const std::vector<std::string>& baseParams,
    const std::optional<std::chrono::system_clock::time_point>& startTime,
    const std::optional<std::chrono::system_clock::time_point>& endTime,
    const uint32_t limit) {
    auto params = baseParams;
    if (startTime.has_value()) {
        params.push_back(std::to_string(ToEpochNanoseconds(*startTime)));
    }
    if (endTime.has_value()) {
        params.push_back(std::to_string(ToEpochNanoseconds(*endTime)));
    }
    params.push_back(std::to_string(limit));
    return params;
}

void AppendTimeBounds(
    std::string& whereClause,
    const std::optional<std::chrono::system_clock::time_point>& startTime,
    const std::optional<std::chrono::system_clock::time_point>& endTime) {
    if (startTime.has_value()) {
        AppendWhere(whereClause, "timestamp_ns >= ?");
    }
    if (endTime.has_value()) {
        AppendWhere(whereClause, "timestamp_ns <= ?");
    }
}

[[nodiscard]] ScanOutcome ExecuteSearch(
    const IOCEntry& ioc,
    std::string whereClause,
    std::vector<std::string> baseParams,
    const std::optional<std::chrono::system_clock::time_point>& startTime,
    const std::optional<std::chrono::system_clock::time_point>& endTime,
    const uint32_t limit,
    std::string_view matchContext,
    const ThreatLookupResult* intelResult = nullptr) {
    AppendTimeBounds(whereClause, startTime, endTime);
    auto params = BuildSearchParams(baseParams, startTime, endTime, limit);

    DatabaseError error{};
    auto result = DatabaseManager::Instance().QueryWithParamsVector(BuildBaseSearchSql(std::move(whereClause)), params, &error);
    if (error.HasError()) {
        Logger::Error("IOCScanner: telemetry IOC search failed category={} value={} context={} code={} msg={}",
            ToString(ioc.category), ioc.value, StringUtils::ToNarrow(error.context), error.sqliteCode, StringUtils::ToNarrow(error.message));
        return {};
    }

    ScanOutcome outcome;
    outcome.hits.reserve(limit);
    while (result.Next()) {
        ++outcome.eventsScanned;
        outcome.hits.emplace_back(MakeScanResult(ioc, ReadEventRow(result), std::string(matchContext), intelResult));
    }
    return outcome;
}

[[nodiscard]] bool EnsureWatchListSchema() {
    DatabaseError error{};
    if (!DatabaseManager::Instance().TableExists(kWatchListTable, &error)) {
        if (error.HasError()) {
            Logger::Error("IOCScanner: failed to verify watchlist table context={} code={} msg={}",
                StringUtils::ToNarrow(error.context), error.sqliteCode, StringUtils::ToNarrow(error.message));
            return false;
        }
    }

    if (!DatabaseManager::Instance().Execute(R"(
        CREATE TABLE IF NOT EXISTS hunt_ioc_watchlist (
            value TEXT NOT NULL,
            category INTEGER NOT NULL,
            source TEXT,
            description TEXT,
            severity INTEGER NOT NULL,
            added_at INTEGER NOT NULL,
            expires_at INTEGER,
            PRIMARY KEY (value, category)
        );
    )", &error)) {
        Logger::Error("IOCScanner: failed to create watchlist table context={} code={} msg={}",
            StringUtils::ToNarrow(error.context), error.sqliteCode, StringUtils::ToNarrow(error.message));
        return false;
    }

    if (!DatabaseManager::Instance().Execute(
        "CREATE INDEX IF NOT EXISTS idx_hunt_ioc_watchlist_added_at ON hunt_ioc_watchlist(added_at DESC);",
        &error)) {
        Logger::Error("IOCScanner: failed to create watchlist index context={} code={} msg={}",
            StringUtils::ToNarrow(error.context), error.sqliteCode, StringUtils::ToNarrow(error.message));
        return false;
    }

    return true;
}

[[nodiscard]] ThreatLookupResult LookupIOCIntel(
    const IOCEntry& ioc,
    const std::unordered_map<std::string, ThreatLookupResult>& hashIntelCache) {
    switch (ioc.category) {
        case IOCCategory::FileHash: {
            const auto it = hashIntelCache.find(ToLowerAscii(ioc.value));
            return it == hashIntelCache.end() ? ThreatLookupResult{} : it->second;
        }
        case IOCCategory::IPv4:
            return GetThreatIntelLookup().LookupIPv4(ioc.value);
        case IOCCategory::IPv6:
            return GetThreatIntelLookup().LookupIPv6(ioc.value);
        case IOCCategory::Domain:
            return GetThreatIntelLookup().LookupDomain(ioc.value);
        default:
            return GetThreatIntelLookup().Lookup(ToThreatIntelType(ioc.category), ioc.value);
    }
}

[[nodiscard]] ScanOutcome ScanSingleIOC(
    const IOCEntry& ioc,
    const std::optional<std::chrono::system_clock::time_point>& startTime,
    const std::optional<std::chrono::system_clock::time_point>& endTime,
    const uint32_t limit,
    const std::unordered_map<std::string, ThreatLookupResult>& hashIntelCache) {
    const ThreatLookupResult intelResult = LookupIOCIntel(ioc, hashIntelCache);
    const ThreatLookupResult* intelPtr = intelResult.found ? &intelResult : nullptr;
    const std::string pattern = MakeContainsPattern(ioc.value);

    switch (ioc.category) {
        case IOCCategory::FileHash:
            return ExecuteSearch(
                ioc,
                " WHERE (payload_json LIKE ? ESCAPE '\\' OR metadata_json LIKE ? ESCAPE '\\')",
                { pattern, pattern },
                startTime,
                endTime,
                limit,
                "Matched file hash in telemetry payload",
                intelPtr);
        case IOCCategory::IPv4:
        case IOCCategory::IPv6:
            return ExecuteSearch(
                ioc,
                std::format(" WHERE category IN ({}, {}) AND (payload_json LIKE ? ESCAPE '\\' OR metadata_json LIKE ? ESCAPE '\\')",
                    static_cast<int>(Telemetry::EventCategory::Network),
                    static_cast<int>(Telemetry::EventCategory::DNS)),
                { pattern, pattern },
                startTime,
                endTime,
                limit,
                "Matched network IOC in telemetry",
                intelPtr);
        case IOCCategory::Domain:
        case IOCCategory::URL:
        case IOCCategory::JA3:
        case IOCCategory::UserAgent:
        case IOCCategory::Email:
            return ExecuteSearch(
                ioc,
                std::format(" WHERE category IN ({}, {}) AND (payload_json LIKE ? ESCAPE '\\' OR metadata_json LIKE ? ESCAPE '\\')",
                    static_cast<int>(Telemetry::EventCategory::Network),
                    static_cast<int>(Telemetry::EventCategory::DNS)),
                { pattern, pattern },
                startTime,
                endTime,
                limit,
                "Matched network telemetry IOC",
                intelPtr);
        case IOCCategory::MutexName:
            return ExecuteSearch(
                ioc,
                " WHERE (metadata_json LIKE ? ESCAPE '\\' OR payload_json LIKE ? ESCAPE '\\')",
                { pattern, pattern },
                startTime,
                endTime,
                limit,
                "Matched mutex name in telemetry metadata",
                intelPtr);
        case IOCCategory::NamedPipe:
            return ExecuteSearch(
                ioc,
                " WHERE (metadata_json LIKE ? ESCAPE '\\' OR payload_json LIKE ? ESCAPE '\\')",
                { pattern, pattern },
                startTime,
                endTime,
                limit,
                "Matched named pipe in telemetry metadata",
                intelPtr);
        case IOCCategory::ProcessName:
            return ExecuteSearch(
                ioc,
                " WHERE process_name = ? COLLATE NOCASE",
                { ioc.value },
                startTime,
                endTime,
                limit,
                "Matched process name column",
                intelPtr);
        case IOCCategory::RegistryKey:
            return ExecuteSearch(
                ioc,
                std::format(" WHERE category = {} AND (payload_json LIKE ? ESCAPE '\\' OR metadata_json LIKE ? ESCAPE '\\')",
                    static_cast<int>(Telemetry::EventCategory::Registry)),
                { pattern, pattern },
                startTime,
                endTime,
                limit,
                "Matched registry IOC in telemetry",
                intelPtr);
    }

    return {};
}

[[nodiscard]] IOCScanSummary BuildEmptySummary() {
    IOCScanSummary summary;
    summary.startedAt = std::chrono::system_clock::now();
    summary.completedAt = summary.startedAt;
    return summary;
}

[[nodiscard]] bool IsExpired(const IOCEntry& ioc, const std::chrono::system_clock::time_point now) noexcept {
    return ioc.expiresAt != std::chrono::system_clock::time_point{} && ioc.expiresAt <= now;
}

} // namespace

IOCScanner::IOCScanner()
    : m_impl(std::make_unique<IOCScannerImpl>()) {
}

IOCScanner::~IOCScanner() = default;

IOCScanner& IOCScanner::Instance() {
    static IOCScanner instance;
    return instance;
}

bool IOCScanner::Initialize() {
    std::unique_lock lock(m_impl->mutex);
    if (m_impl->initialized.load(std::memory_order_acquire)) {
        return true;
    }

    if (!EnsureWatchListSchema()) {
        return false;
    }

    m_impl->initialized.store(true, std::memory_order_release);
    Logger::Info("IOCScanner: initialized with maxScanMatches={}", m_impl->maxScanMatches);
    return true;
}

void IOCScanner::Shutdown() {
    std::unique_lock lock(m_impl->mutex);
    m_impl->initialized.store(false, std::memory_order_release);
    Logger::Info("IOCScanner: shutdown complete");
}

bool IOCScanner::IsInitialized() const noexcept {
    return m_impl->initialized.load(std::memory_order_acquire);
}

IOCScanSummary IOCScanner::ScanIOCs(const std::vector<IOCEntry>& iocs) {
    return ScanIOCs(iocs, {}, {});
}

IOCScanSummary IOCScanner::ScanIOCs(
    const std::vector<IOCEntry>& iocs,
    const std::chrono::system_clock::time_point startTime,
    const std::chrono::system_clock::time_point endTime) {
    const auto startedClock = std::chrono::steady_clock::now();
    IOCScanSummary summary;
    summary.startedAt = std::chrono::system_clock::now();

    std::shared_lock lock(m_impl->mutex);
    if (!m_impl->initialized.load(std::memory_order_acquire)) {
        Logger::Warn("IOCScanner: ScanIOCs requested before initialization");
        summary.completedAt = std::chrono::system_clock::now();
        summary.executionTime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startedClock);
        return summary;
    }

    const auto now = std::chrono::system_clock::now();
    const std::optional<std::chrono::system_clock::time_point> boundedStart =
        startTime == std::chrono::system_clock::time_point{} ? std::optional<std::chrono::system_clock::time_point>{} : startTime;
    const std::optional<std::chrono::system_clock::time_point> boundedEnd =
        endTime == std::chrono::system_clock::time_point{} ? std::optional<std::chrono::system_clock::time_point>{} : endTime;

    std::vector<std::string> hashValues;
    hashValues.reserve(iocs.size());
    for (const auto& ioc : iocs) {
        if (!ioc.value.empty() && ioc.category == IOCCategory::FileHash && !IsExpired(ioc, now)) {
            hashValues.push_back(ioc.value);
        }
    }

    std::unordered_map<std::string, ThreatLookupResult> hashIntelCache;
    if (!hashValues.empty()) {
        std::vector<std::string_view> views;
        views.reserve(hashValues.size());
        for (const auto& hash : hashValues) {
            views.emplace_back(hash);
        }

        const BatchLookupResult batch = GetThreatIntelLookup().BatchLookupHashes(std::span<const std::string_view>(views.data(), views.size()));
        for (size_t index = 0; index < views.size() && index < batch.results.size(); ++index) {
            hashIntelCache.emplace(ToLowerAscii(std::string(views[index])), batch.results[index]);
        }
    }

    for (size_t index = 0; index < iocs.size(); ++index) {
        const IOCEntry& ioc = iocs[index];
        if (ioc.value.empty()) {
            Logger::Warn("IOCScanner: skipping empty IOC at index={}", index);
            continue;
        }
        if (IsExpired(ioc, now)) {
            Logger::Debug("IOCScanner: skipping expired IOC value={} category={}", ioc.value, ToString(ioc.category));
            continue;
        }

        const uint32_t remainingCapacity = summary.hits.size() >= m_impl->maxScanMatches
            ? 0U
            : static_cast<uint32_t>(m_impl->maxScanMatches - summary.hits.size());
        if (remainingCapacity == 0) {
            Logger::Warn("IOCScanner: result cap reached at {} hits", m_impl->maxScanMatches);
            break;
        }

        const ScanOutcome outcome = ScanSingleIOC(ioc, boundedStart, boundedEnd, remainingCapacity, hashIntelCache);
        summary.totalIOCsScanned++;
        summary.totalEventsScanned += outcome.eventsScanned;
        summary.totalHits += outcome.hits.size();
        summary.hits.insert(summary.hits.end(), outcome.hits.begin(), outcome.hits.end());

        if ((summary.totalIOCsScanned % kProgressLogInterval) == 0 || index + 1 == iocs.size()) {
            Logger::Info("IOCScanner: progress scanned={}/{} hits={} eventsScanned={} bounded={}",
                summary.totalIOCsScanned,
                iocs.size(),
                summary.totalHits,
                summary.totalEventsScanned,
                HasTimeBounds(boundedStart, boundedEnd) ? "true" : "false");
        }
    }

    summary.completedAt = std::chrono::system_clock::now();
    summary.executionTime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startedClock);
    Logger::Info("IOCScanner: ScanIOCs complete scanned={} hits={} durationMs={}",
        summary.totalIOCsScanned, summary.totalHits, summary.executionTime.count());
    return summary;
}

bool IOCScanner::AddWatchList(const std::vector<IOCEntry>& iocs) {
    std::shared_lock lock(m_impl->mutex);
    if (!m_impl->initialized.load(std::memory_order_acquire)) {
        Logger::Warn("IOCScanner: AddWatchList requested before initialization");
        return false;
    }

    DatabaseError error{};
    auto transaction = DatabaseManager::Instance().BeginTransaction(ShadowStrike::Database::Transaction::Type::Immediate, &error);
    if (transaction == nullptr || error.HasError()) {
        Logger::Error("IOCScanner: failed to begin watchlist transaction context={} code={} msg={}",
            StringUtils::ToNarrow(error.context), error.sqliteCode, StringUtils::ToNarrow(error.message));
        return false;
    }

    const auto now = std::chrono::system_clock::now();
    for (const auto& ioc : iocs) {
        if (ioc.value.empty()) {
            continue;
        }

        const auto addedAt = ioc.addedAt == std::chrono::system_clock::time_point{} ? now : ioc.addedAt;
        const std::optional<int64_t> expiresAt =
            ioc.expiresAt == std::chrono::system_clock::time_point{} ? std::optional<int64_t>{} : ToEpochSeconds(ioc.expiresAt);

        const bool ok = expiresAt.has_value()
            ? transaction->ExecuteWithParams(
                "INSERT OR REPLACE INTO hunt_ioc_watchlist(value, category, source, description, severity, added_at, expires_at) "
                "VALUES(?, ?, ?, ?, ?, ?, ?);",
                &error,
                ioc.value,
                static_cast<int>(ioc.category),
                ioc.source,
                ioc.description,
                static_cast<int>(ioc.severity),
                ToEpochSeconds(addedAt),
                *expiresAt)
            : transaction->ExecuteWithParams(
                "INSERT OR REPLACE INTO hunt_ioc_watchlist(value, category, source, description, severity, added_at, expires_at) "
                "VALUES(?, ?, ?, ?, ?, ?, NULL);",
                &error,
                ioc.value,
                static_cast<int>(ioc.category),
                ioc.source,
                ioc.description,
                static_cast<int>(ioc.severity),
                ToEpochSeconds(addedAt));

        if (!ok || error.HasError()) {
            Logger::Error("IOCScanner: failed to add watchlist IOC value={} context={} code={} msg={}",
                ioc.value, StringUtils::ToNarrow(error.context), error.sqliteCode, StringUtils::ToNarrow(error.message));
            transaction->Rollback();
            return false;
        }
    }

    if (!transaction->Commit()) {
        Logger::Error("IOCScanner: failed to commit watchlist transaction");
        return false;
    }

    Logger::Info("IOCScanner: added {} IOC(s) to watchlist", iocs.size());
    return true;
}

bool IOCScanner::RemoveFromWatchList(const std::string& iocValue) {
    std::shared_lock lock(m_impl->mutex);
    if (!m_impl->initialized.load(std::memory_order_acquire)) {
        Logger::Warn("IOCScanner: RemoveFromWatchList requested before initialization");
        return false;
    }

    if (iocValue.empty()) {
        return false;
    }

    DatabaseError error{};
    const bool success = DatabaseManager::Instance().ExecuteWithParams(
        "DELETE FROM hunt_ioc_watchlist WHERE value = ?;",
        &error,
        iocValue);
    if (!success || error.HasError()) {
        Logger::Error("IOCScanner: failed to remove watchlist IOC value={} context={} code={} msg={}",
            iocValue, StringUtils::ToNarrow(error.context), error.sqliteCode, StringUtils::ToNarrow(error.message));
        return false;
    }

    Logger::Info("IOCScanner: removed IOC value={} from watchlist", iocValue);
    return true;
}

std::vector<IOCEntry> IOCScanner::GetWatchList() {
    std::shared_lock lock(m_impl->mutex);
    if (!m_impl->initialized.load(std::memory_order_acquire)) {
        Logger::Warn("IOCScanner: GetWatchList requested before initialization");
        return {};
    }

    DatabaseError error{};
    const auto nowSeconds = ToEpochSeconds(std::chrono::system_clock::now());
    auto result = DatabaseManager::Instance().QueryWithParams(
        "SELECT value, category, source, description, severity, added_at, expires_at "
        "FROM hunt_ioc_watchlist "
        "WHERE expires_at IS NULL OR expires_at > ? "
        "ORDER BY added_at DESC;",
        &error,
        nowSeconds);

    if (error.HasError()) {
        Logger::Error("IOCScanner: failed to query watchlist context={} code={} msg={}",
            StringUtils::ToNarrow(error.context), error.sqliteCode, StringUtils::ToNarrow(error.message));
        return {};
    }

    std::vector<IOCEntry> watchList;
    while (result.Next()) {
        IOCEntry ioc;
        ioc.value = result.GetString(0);
        ioc.category = static_cast<IOCCategory>(result.GetInt(1));
        ioc.source = result.IsNull(2) ? std::string{} : result.GetString(2);
        ioc.description = result.IsNull(3) ? std::string{} : result.GetString(3);
        ioc.severity = static_cast<RuleSeverity>(result.GetInt(4));
        ioc.addedAt = FromEpochSeconds(result.GetInt64(5));
        if (!result.IsNull(6)) {
            ioc.expiresAt = FromEpochSeconds(result.GetInt64(6));
        }
        watchList.emplace_back(std::move(ioc));
    }

    return watchList;
}

IOCScanSummary IOCScanner::ScanWatchList() {
    const std::vector<IOCEntry> watchList = GetWatchList();
    if (watchList.empty()) {
        Logger::Info("IOCScanner: ScanWatchList found no active watchlist entries");
        return BuildEmptySummary();
    }

    Logger::Info("IOCScanner: scanning {} watchlist IOC(s)", watchList.size());
    return ScanIOCs(watchList);
}

} // namespace ShadowStrike::Products::PhantomEDR::ThreatHunting
