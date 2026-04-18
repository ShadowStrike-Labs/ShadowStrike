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
#include "PhishingCorrelator.hpp"

#include <format>
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <deque>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace ShadowStrike::Products::PhantomXDR::EmailThreat {

namespace SU = ShadowStrike::Utils::StringUtils;
using ShadowStrike::Database::DatabaseError;
using ShadowStrike::Database::DatabaseManager;
using ShadowStrike::Database::QueryResult;
using ShadowStrike::Utils::Logger;

namespace {

constexpr std::string_view kSchemaSql = R"(
    CREATE TABLE IF NOT EXISTS xdr_email_correlations (
        message_id           TEXT PRIMARY KEY,
        verdict              INTEGER NOT NULL,
        confidence           REAL NOT NULL,
        attachment_hashes    TEXT,
        execution_matches    TEXT,
        timeline_data        TEXT,
        matched_urls         TEXT,
        related_senders      TEXT,
        escalated            INTEGER NOT NULL,
        created_at           INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_xdr_email_correlations_time ON xdr_email_correlations(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_xdr_email_correlations_verdict ON xdr_email_correlations(verdict);
)";

constexpr std::size_t kMaxCacheEntries = 512;
constexpr std::size_t kMaxExecutionMatches = 64;
constexpr std::size_t kMaxUrlMatches = 64;
constexpr std::size_t kMaxSenderMatches = 32;
constexpr int64_t kSleepSliceMs = 500;

[[nodiscard]] std::string ToLowerAscii(std::string_view value) {
    std::string lowered;
    lowered.reserve(value.size());
    for (const unsigned char ch : value) {
        lowered.push_back(static_cast<char>(std::tolower(ch)));
    }
    return lowered;
}

[[nodiscard]] std::string TrimAscii(std::string_view value) {
    std::size_t start = 0;
    std::size_t end = value.size();
    while (start < end && std::isspace(static_cast<unsigned char>(value[start])) != 0) {
        ++start;
    }
    while (end > start && std::isspace(static_cast<unsigned char>(value[end - 1])) != 0) {
        --end;
    }
    return std::string(value.substr(start, end - start));
}

[[nodiscard]] std::string EscapeStorageString(std::string_view input) {
    std::string escaped;
    escaped.reserve(input.size() + 8);
    for (const char ch : input) {
        switch (ch) {
        case '\\': escaped += "\\\\"; break;
        case '\n': escaped += "\\n"; break;
        case '\r': escaped += "\\r"; break;
        case '\t': escaped += "\\t"; break;
        case '|': escaped += "\\p"; break;
        default: escaped.push_back(ch); break;
        }
    }
    return escaped;
}

[[nodiscard]] std::string UnescapeStorageString(std::string_view input) {
    std::string value;
    value.reserve(input.size());
    for (std::size_t index = 0; index < input.size(); ++index) {
        if (input[index] == '\\' && index + 1 < input.size()) {
            ++index;
            switch (input[index]) {
            case 'n': value.push_back('\n'); break;
            case 'r': value.push_back('\r'); break;
            case 't': value.push_back('\t'); break;
            case 'p': value.push_back('|'); break;
            case '\\': value.push_back('\\'); break;
            default:
                value.push_back(input[index]);
                break;
            }
            continue;
        }
        value.push_back(input[index]);
    }
    return value;
}

[[nodiscard]] std::string SerializeStringList(const std::vector<std::string>& values) {
    std::ostringstream stream;
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (index != 0) {
            stream << '\n';
        }
        stream << EscapeStorageString(values[index]);
    }
    return stream.str();
}

[[nodiscard]] std::vector<std::string> DeserializeStringList(std::string_view serialized) {
    std::vector<std::string> values;
    std::string current;
    for (std::size_t index = 0; index < serialized.size(); ++index) {
        if (serialized[index] == '\n') {
            values.push_back(UnescapeStorageString(current));
            current.clear();
            continue;
        }
        current.push_back(serialized[index]);
    }
    if (!current.empty() || !serialized.empty()) {
        values.push_back(UnescapeStorageString(current));
    }
    return values;
}

[[nodiscard]] int64_t ToUnixSeconds(const std::chrono::system_clock::time_point timePoint) {
    return std::chrono::duration_cast<std::chrono::seconds>(timePoint.time_since_epoch()).count();
}

[[nodiscard]] std::chrono::system_clock::time_point FromUnixSeconds(const int64_t seconds) {
    return std::chrono::system_clock::time_point{std::chrono::seconds(seconds)};
}

[[nodiscard]] std::string ExtractHostFromUrl(std::string_view url) {
    std::string normalized = TrimAscii(url);
    if (normalized.empty()) {
        return {};
    }
    std::size_t scheme = normalized.find("://");
    std::size_t hostStart = scheme == std::string::npos ? 0 : scheme + 3;
    if (hostStart >= normalized.size()) {
        return {};
    }

    if (normalized[hostStart] == '[') {
        const std::size_t end = normalized.find(']', hostStart + 1);
        if (end == std::string::npos) {
            return {};
        }
        return ToLowerAscii(normalized.substr(hostStart + 1, end - hostStart - 1));
    }

    std::size_t hostEnd = hostStart;
    while (hostEnd < normalized.size()) {
        const char ch = normalized[hostEnd];
        if (ch == '/' || ch == ':' || ch == '?' || ch == '#') {
            break;
        }
        ++hostEnd;
    }
    return ToLowerAscii(normalized.substr(hostStart, hostEnd - hostStart));
}

[[nodiscard]] bool TableExists(const std::string& tableName) {
    DatabaseError dbError{};
    auto result = DatabaseManager::Instance().QueryWithParams(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name = ?",
        &dbError,
        tableName);

    if (dbError.HasError()) {
        Logger::Error("PhishingCorrelator: table existence query failed table={} code={} msg={}",
            tableName,
            dbError.sqliteCode,
            SU::ToNarrow(dbError.message));
        return false;
    }
    if (!result.Next()) {
        return false;
    }
    return result.GetInt(0) > 0;
}

[[nodiscard]] std::string ExtractJsonStringField(std::string_view payload, std::string_view fieldName) {
    const std::string token = std::format("\"{}\":\"", fieldName);
    const std::size_t start = payload.find(token);
    if (start == std::string::npos) {
        return {};
    }
    std::size_t cursor = start + token.size();
    std::string value;
    bool escaped = false;
    while (cursor < payload.size()) {
        const char ch = payload[cursor++];
        if (escaped) {
            value.push_back(ch);
            escaped = false;
            continue;
        }
        if (ch == '\\') {
            escaped = true;
            continue;
        }
        if (ch == '"') {
            break;
        }
        value.push_back(ch);
    }
    return value;
}

[[nodiscard]] std::string SerializeExecutionMatch(const EndpointExecutionMatch& match) {
    return std::format("{}|{}|{}|{}|{}|{}|{}|{}",
        match.timestamp,
        match.processId,
        EscapeStorageString(match.processName),
        EscapeStorageString(match.processPath),
        EscapeStorageString(match.commandLine),
        EscapeStorageString(match.userName),
        EscapeStorageString(match.sourceTable),
        EscapeStorageString(match.sourceEvent));
}

[[nodiscard]] std::vector<EndpointExecutionMatch> DeserializeExecutionMatches(std::string_view serialized) {
    std::vector<EndpointExecutionMatch> matches;
    for (const auto& row : DeserializeStringList(serialized)) {
        std::vector<std::string> parts;
        std::string current;
        bool escaped = false;
        for (const char ch : row) {
            if (escaped) {
                current.push_back('\\');
                current.push_back(ch);
                escaped = false;
                continue;
            }
            if (ch == '\\') {
                escaped = true;
                continue;
            }
            if (ch == '|') {
                parts.push_back(UnescapeStorageString(current));
                current.clear();
                continue;
            }
            current.push_back(ch);
        }
        parts.push_back(UnescapeStorageString(current));
        if (parts.size() != 8) {
            continue;
        }
        EndpointExecutionMatch match;
        match.timestamp = std::strtoll(parts[0].c_str(), nullptr, 10);
        match.processId = static_cast<uint32_t>(std::strtoul(parts[1].c_str(), nullptr, 10));
        match.processName = parts[2];
        match.processPath = parts[3];
        match.commandLine = parts[4];
        match.userName = parts[5];
        match.sourceTable = parts[6];
        match.sourceEvent = parts[7];
        matches.push_back(std::move(match));
    }
    return matches;
}

[[nodiscard]] std::string SerializeTimelineEvent(const CorrelationTimelineEvent& event) {
    return std::format("{}|{}|{}|{}",
        event.timestamp,
        EscapeStorageString(event.phase),
        EscapeStorageString(event.description),
        EscapeStorageString(event.artifact));
}

[[nodiscard]] std::vector<CorrelationTimelineEvent> DeserializeTimeline(std::string_view serialized) {
    std::vector<CorrelationTimelineEvent> timeline;
    for (const auto& row : DeserializeStringList(serialized)) {
        std::vector<std::string> parts;
        std::string current;
        bool escaped = false;
        for (const char ch : row) {
            if (escaped) {
                current.push_back('\\');
                current.push_back(ch);
                escaped = false;
                continue;
            }
            if (ch == '\\') {
                escaped = true;
                continue;
            }
            if (ch == '|') {
                parts.push_back(UnescapeStorageString(current));
                current.clear();
                continue;
            }
            current.push_back(ch);
        }
        parts.push_back(UnescapeStorageString(current));
        if (parts.size() != 4) {
            continue;
        }
        CorrelationTimelineEvent event;
        event.timestamp = std::strtoll(parts[0].c_str(), nullptr, 10);
        event.phase = parts[1];
        event.description = parts[2];
        event.artifact = parts[3];
        timeline.push_back(std::move(event));
    }
    return timeline;
}

void AppendUnique(std::vector<std::string>& values, const std::string& value) {
    if (value.empty()) {
        return;
    }
    if (std::find(values.begin(), values.end(), value) == values.end()) {
        values.push_back(value);
    }
}

void AppendTimeline(std::vector<CorrelationTimelineEvent>& timeline,
                    const int64_t timestamp,
                    std::string phase,
                    std::string description,
                    std::string artifact) {
    CorrelationTimelineEvent event;
    event.timestamp = timestamp;
    event.phase = std::move(phase);
    event.description = std::move(description);
    event.artifact = std::move(artifact);
    timeline.push_back(std::move(event));
}

[[nodiscard]] std::vector<std::string> CollectAttachmentHashes(const EmailAnalysisResult& analysisResult) {
    std::vector<std::string> hashes;
    hashes.reserve(analysisResult.attachmentsAnalyzed.size());
    for (const auto& attachment : analysisResult.attachmentsAnalyzed) {
        if (!attachment.sha256.empty()) {
            hashes.push_back(attachment.sha256);
        }
    }
    return hashes;
}

[[nodiscard]] std::vector<EndpointExecutionMatch> QueryIncidentRecorderByHash(std::string_view attachmentHash) {
    std::vector<EndpointExecutionMatch> matches;
    if (attachmentHash.empty() || !TableExists("processes")) {
        return matches;
    }

    DatabaseError dbError{};
    auto query = DatabaseManager::Instance().QueryWithParams(
        "SELECT process_id, process_name, process_path, command_line, start_time, user_name FROM processes WHERE lower(hex(hash)) = lower(?) ORDER BY start_time DESC LIMIT ?",
        &dbError,
        std::string(attachmentHash),
        static_cast<int64_t>(kMaxExecutionMatches));

    if (dbError.HasError()) {
        Logger::Error("PhishingCorrelator: process hash query failed code={} msg={}",
            dbError.sqliteCode,
            SU::ToNarrow(dbError.message));
        return matches;
    }

    while (query.Next()) {
        EndpointExecutionMatch match;
        match.processId = query.IsNull(0) ? 0U : static_cast<uint32_t>(query.GetInt64(0));
        match.processName = query.IsNull(1) ? std::string{} : query.GetString(1);
        match.processPath = query.IsNull(2) ? std::string{} : query.GetString(2);
        match.commandLine = query.IsNull(3) ? std::string{} : query.GetString(3);
        match.timestamp = query.IsNull(4) ? 0 : query.GetInt64(4);
        match.userName = query.IsNull(5) ? std::string{} : query.GetString(5);
        match.sourceTable = "processes";
        match.sourceEvent = "process_start";
        matches.push_back(std::move(match));
    }
    return matches;
}

[[nodiscard]] std::vector<EndpointExecutionMatch> QueryTelemetryByHash(std::string_view attachmentHash) {
    std::vector<EndpointExecutionMatch> matches;
    if (attachmentHash.empty() || !TableExists("telemetry_events")) {
        return matches;
    }

    const std::string likePattern = std::format("%\\\"imageHash\\\":\\\"{}\\\"%", attachmentHash);

    DatabaseError dbError{};
    auto query = DatabaseManager::Instance().QueryWithParams(
        "SELECT timestamp_ns, process_id, process_name, process_path, user_name, payload_json FROM telemetry_events WHERE category = 0 AND payload_json LIKE ? ORDER BY timestamp_ns DESC LIMIT ?",
        &dbError,
        likePattern,
        static_cast<int64_t>(kMaxExecutionMatches));

    if (dbError.HasError()) {
        Logger::Error("PhishingCorrelator: telemetry hash query failed code={} msg={}",
            dbError.sqliteCode,
            SU::ToNarrow(dbError.message));
        return matches;
    }

    while (query.Next()) {
        EndpointExecutionMatch match;
        match.timestamp = query.IsNull(0) ? 0 : query.GetInt64(0) / 1000000000LL;
        match.processId = query.IsNull(1) ? 0U : static_cast<uint32_t>(query.GetInt64(1));
        match.processName = query.IsNull(2) ? std::string{} : query.GetString(2);
        match.processPath = query.IsNull(3) ? std::string{} : query.GetString(3);
        match.userName = query.IsNull(4) ? std::string{} : query.GetString(4);
        const std::string payload = query.IsNull(5) ? std::string{} : query.GetString(5);
        match.commandLine = ExtractJsonStringField(payload, "commandLine");
        match.sourceTable = "telemetry_events";
        match.sourceEvent = "process_created";
        matches.push_back(std::move(match));
    }
    return matches;
}

[[nodiscard]] std::vector<std::string> QuerySenderHistory(std::string_view sender, std::string_view currentMessageId) {
    std::vector<std::string> matches;
    if (sender.empty() || !TableExists("xdr_email_scan_results")) {
        return matches;
    }

    DatabaseError dbError{};
    auto query = DatabaseManager::Instance().QueryWithParams(
        "SELECT message_id FROM xdr_email_scan_results WHERE lower(header_from) = lower(?) AND message_id <> ? ORDER BY analyzed_at DESC LIMIT ?",
        &dbError,
        std::string(sender),
        std::string(currentMessageId),
        static_cast<int64_t>(kMaxSenderMatches));

    if (dbError.HasError()) {
        Logger::Error("PhishingCorrelator: sender history query failed code={} msg={}",
            dbError.sqliteCode,
            SU::ToNarrow(dbError.message));
        return matches;
    }

    while (query.Next()) {
        if (!query.IsNull(0)) {
            matches.push_back(query.GetString(0));
        }
    }
    return matches;
}

[[nodiscard]] std::vector<std::pair<std::string, int64_t>> QueryUrlVisits(std::string_view host) {
    std::vector<std::pair<std::string, int64_t>> matches;
    if (host.empty() || !TableExists("telemetry_events")) {
        return matches;
    }

    const std::string dnsPattern = std::format("%\\\"dnsQuery\\\":\\\"{}\\\"%", host);
    const std::string pathPattern = std::format("%{}%", host);

    DatabaseError dbError{};
    auto query = DatabaseManager::Instance().QueryWithParams(
        "SELECT timestamp_ns, payload_json FROM telemetry_events WHERE category IN (3,4) AND (payload_json LIKE ? OR payload_json LIKE ?) ORDER BY timestamp_ns DESC LIMIT ?",
        &dbError,
        dnsPattern,
        pathPattern,
        static_cast<int64_t>(kMaxUrlMatches));

    if (dbError.HasError()) {
        Logger::Error("PhishingCorrelator: url telemetry query failed code={} msg={}",
            dbError.sqliteCode,
            SU::ToNarrow(dbError.message));
        return matches;
    }

    while (query.Next()) {
        const int64_t timestamp = query.IsNull(0) ? 0 : query.GetInt64(0) / 1000000000LL;
        const std::string payload = query.IsNull(1) ? std::string{} : query.GetString(1);
        const std::string dnsQuery = ExtractJsonStringField(payload, "dnsQuery");
        const std::string remoteAddr = ExtractJsonStringField(payload, "remoteAddr");
        if (!dnsQuery.empty()) {
            matches.emplace_back(dnsQuery, timestamp);
        } else if (!remoteAddr.empty()) {
            matches.emplace_back(remoteAddr, timestamp);
        } else {
            matches.emplace_back(std::string(host), timestamp);
        }
    }
    return matches;
}

[[nodiscard]] PhishingCorrelation LoadCorrelationFromRow(QueryResult& query) {
    PhishingCorrelation correlation;
    correlation.emailMessageId = query.IsNull("message_id") ? std::string{} : query.GetString("message_id");
    correlation.verdict = static_cast<EmailVerdict>(query.IsNull("verdict") ? 0 : query.GetInt("verdict"));
    correlation.confidence = query.IsNull("confidence") ? 0.0 : query.GetDouble("confidence");
    correlation.attachmentHashes = query.IsNull("attachment_hashes") ? std::vector<std::string>{} : DeserializeStringList(query.GetString("attachment_hashes"));
    correlation.endpointExecutionsMatched = query.IsNull("execution_matches") ? std::vector<EndpointExecutionMatch>{} : DeserializeExecutionMatches(query.GetString("execution_matches"));
    correlation.timeline = query.IsNull("timeline_data") ? std::vector<CorrelationTimelineEvent>{} : DeserializeTimeline(query.GetString("timeline_data"));
    correlation.matchedUrls = query.IsNull("matched_urls") ? std::vector<std::string>{} : DeserializeStringList(query.GetString("matched_urls"));
    correlation.relatedSenders = query.IsNull("related_senders") ? std::vector<std::string>{} : DeserializeStringList(query.GetString("related_senders"));
    correlation.escalated = !query.IsNull("escalated") && query.GetInt("escalated") != 0;
    return correlation;
}

[[nodiscard]] EmailVerdict EscalateVerdict(const EmailAnalysisResult& analysisResult,
                                           const std::vector<EndpointExecutionMatch>& executionMatches,
                                           const std::vector<std::string>& matchedUrls) {
    if (!executionMatches.empty()) {
        return EmailVerdict::Malicious;
    }
    if (!matchedUrls.empty()) {
        if (analysisResult.verdict == EmailVerdict::Suspicious || analysisResult.verdict == EmailVerdict::Clean) {
            return EmailVerdict::Phishing;
        }
    }
    return analysisResult.verdict;
}

void SortTimeline(std::vector<CorrelationTimelineEvent>& timeline) {
    std::sort(timeline.begin(), timeline.end(), [](const CorrelationTimelineEvent& left, const CorrelationTimelineEvent& right) {
        if (left.timestamp != right.timestamp) {
            return left.timestamp < right.timestamp;
        }
        if (left.phase != right.phase) {
            return left.phase < right.phase;
        }
        return left.description < right.description;
    });
}

[[nodiscard]] bool VerdictEscalated(const EmailVerdict originalVerdict, const EmailVerdict newVerdict) {
    return static_cast<int>(newVerdict) > static_cast<int>(originalVerdict);
}

} // namespace

class PhishingCorrelatorImpl final {
public:
    std::atomic<bool> initialized{false};
    std::atomic<uint64_t> totalCorrelations{0};
    std::atomic<uint64_t> escalatedCorrelations{0};
    std::atomic<uint64_t> attachmentExecutionMatches{0};
    std::atomic<uint64_t> urlVisitMatches{0};
    std::atomic<uint64_t> senderMatches{0};
    std::atomic<uint64_t> timelineEventsPersisted{0};
    std::atomic<uint64_t> databaseFailures{0};
    mutable std::shared_mutex mutex;
    std::unordered_map<std::string, PhishingCorrelation> cache;
    std::deque<std::string> cacheOrder;
    std::jthread maintenanceThread;

    void StartMaintenanceThread() {
        maintenanceThread = std::jthread([this](const std::stop_token stopToken) {
            MaintenanceLoop(stopToken);
        });
    }

    void MaintenanceLoop(const std::stop_token stopToken) {
        while (!stopToken.stop_requested()) {
            {
                std::unique_lock lock(mutex);
                while (cacheOrder.size() > kMaxCacheEntries) {
                    const std::string oldest = cacheOrder.front();
                    cacheOrder.pop_front();
                    cache.erase(oldest);
                }
            }
            for (int64_t slept = 0; slept < 10 && !stopToken.stop_requested(); ++slept) {
                std::this_thread::sleep_for(std::chrono::milliseconds(kSleepSliceMs));
            }
        }
    }

    void UpdateCache(const PhishingCorrelation& correlation) {
        if (correlation.emailMessageId.empty()) {
            return;
        }
        std::unique_lock lock(mutex);
        cache[correlation.emailMessageId] = correlation;
        cacheOrder.push_back(correlation.emailMessageId);
        while (cacheOrder.size() > kMaxCacheEntries) {
            const std::string oldest = cacheOrder.front();
            cacheOrder.pop_front();
            cache.erase(oldest);
        }
    }
};

PhishingCorrelator::PhishingCorrelator()
    : m_impl(std::make_unique<PhishingCorrelatorImpl>()) {
}

PhishingCorrelator::~PhishingCorrelator() = default;

bool PhishingCorrelator::Initialize() {
    auto& db = DatabaseManager::Instance();
    if (!db.IsInitialized()) {
        Logger::Error("PhishingCorrelator: DatabaseManager is not initialized");
        return false;
    }

    DatabaseError dbError{};
    if (!db.Execute(kSchemaSql, &dbError)) {
        Logger::Error("PhishingCorrelator: schema initialization failed code={} msg={}",
            dbError.sqliteCode,
            SU::ToNarrow(dbError.message));
        m_impl->databaseFailures.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    m_impl->initialized.store(true, std::memory_order_release);
    m_impl->StartMaintenanceThread();
    Logger::Info("PhishingCorrelator: initialized successfully");
    return true;
}

void PhishingCorrelator::Shutdown() {
    m_impl->initialized.store(false, std::memory_order_release);
    if (m_impl->maintenanceThread.joinable()) {
        m_impl->maintenanceThread.request_stop();
        m_impl->maintenanceThread.join();
    }
    std::unique_lock lock(m_impl->mutex);
    m_impl->cache.clear();
    m_impl->cacheOrder.clear();
}

bool PhishingCorrelator::IsInitialized() const noexcept {
    return m_impl->initialized.load(std::memory_order_acquire);
}

PhishingCorrelation PhishingCorrelator::CorrelateEmail(const EmailAnalysisResult& analysisResult) {
    PhishingCorrelation correlation;
    correlation.emailMessageId = analysisResult.header.messageId;
    correlation.attachmentHashes = CollectAttachmentHashes(analysisResult);
    correlation.verdict = analysisResult.verdict;
    correlation.confidence = analysisResult.confidence;

    if (!IsInitialized()) {
        Logger::Warn("PhishingCorrelator: CorrelateEmail called before Initialize");
        return correlation;
    }
    if (correlation.emailMessageId.empty()) {
        Logger::Warn("PhishingCorrelator: refusing to correlate email without Message-ID");
        return correlation;
    }

    const int64_t analysisTimestamp = ToUnixSeconds(analysisResult.analyzedAt);
    AppendTimeline(correlation.timeline,
        analysisTimestamp,
        "email_received",
        std::format("Email analyzed with verdict {} and confidence {:.1f}", static_cast<int>(analysisResult.verdict), analysisResult.confidence),
        correlation.emailMessageId);

    std::vector<EndpointExecutionMatch> combinedMatches;
    for (const auto& attachmentHash : correlation.attachmentHashes) {
        auto recorderMatches = QueryIncidentRecorderByHash(attachmentHash);
        auto telemetryMatches = QueryTelemetryByHash(attachmentHash);
        combinedMatches.insert(combinedMatches.end(),
            std::make_move_iterator(recorderMatches.begin()),
            std::make_move_iterator(recorderMatches.end()));
        combinedMatches.insert(combinedMatches.end(),
            std::make_move_iterator(telemetryMatches.begin()),
            std::make_move_iterator(telemetryMatches.end()));
    }

    std::sort(combinedMatches.begin(), combinedMatches.end(), [](const EndpointExecutionMatch& left, const EndpointExecutionMatch& right) {
        if (left.timestamp != right.timestamp) {
            return left.timestamp > right.timestamp;
        }
        if (left.processId != right.processId) {
            return left.processId < right.processId;
        }
        return left.processName < right.processName;
    });

    std::unordered_set<std::string> seenExecutionKeys;
    for (const auto& match : combinedMatches) {
        const std::string key = std::format("{}:{}:{}:{}", match.timestamp, match.processId, match.sourceTable, match.processName);
        if (!seenExecutionKeys.insert(key).second) {
            continue;
        }
        correlation.endpointExecutionsMatched.push_back(match);
        if (correlation.endpointExecutionsMatched.size() >= kMaxExecutionMatches) {
            break;
        }
    }

    for (const auto& execution : correlation.endpointExecutionsMatched) {
        AppendTimeline(correlation.timeline,
            execution.timestamp,
            "attachment_executed",
            std::format("Attachment-linked execution observed: {} (pid {} via {})",
                execution.processName.empty() ? execution.processPath : execution.processName,
                execution.processId,
                execution.sourceTable),
            execution.commandLine.empty() ? execution.processPath : execution.commandLine);
    }

    std::set<std::string> uniqueUrlSignals;
    for (const auto& url : analysisResult.linksExtracted) {
        const std::string host = ExtractHostFromUrl(url);
        if (host.empty()) {
            continue;
        }
        for (const auto& [signal, timestamp] : QueryUrlVisits(host)) {
            if (uniqueUrlSignals.insert(signal).second) {
                correlation.matchedUrls.push_back(signal);
                AppendTimeline(correlation.timeline,
                    timestamp,
                    "url_visited",
                    std::format("Network telemetry matched email-hosted URL signal {}", signal),
                    host);
                if (correlation.matchedUrls.size() >= kMaxUrlMatches) {
                    break;
                }
            }
        }
        if (correlation.matchedUrls.size() >= kMaxUrlMatches) {
            break;
        }
    }

    const auto senderHistory = QuerySenderHistory(analysisResult.header.from, correlation.emailMessageId);
    for (const auto& priorMessageId : senderHistory) {
        correlation.relatedSenders.push_back(priorMessageId);
        AppendTimeline(correlation.timeline,
            analysisTimestamp,
            "sender_reuse",
            std::format("Sender previously seen in message {}", priorMessageId),
            analysisResult.header.from);
        if (correlation.relatedSenders.size() >= kMaxSenderMatches) {
            break;
        }
    }

    correlation.verdict = EscalateVerdict(analysisResult, correlation.endpointExecutionsMatched, correlation.matchedUrls);
    correlation.escalated = VerdictEscalated(analysisResult.verdict, correlation.verdict);
    correlation.confidence = std::clamp(
        analysisResult.confidence +
            static_cast<double>(correlation.endpointExecutionsMatched.size() * 20U) +
            static_cast<double>(correlation.matchedUrls.size() * 8U) +
            static_cast<double>(correlation.relatedSenders.size() * 4U),
        0.0,
        100.0);

    if (correlation.escalated) {
        AppendTimeline(correlation.timeline,
            analysisTimestamp,
            "severity_escalated",
            std::format("Correlation escalated verdict from {} to {}",
                static_cast<int>(analysisResult.verdict),
                static_cast<int>(correlation.verdict)),
            correlation.emailMessageId);
    }

    SortTimeline(correlation.timeline);

    DatabaseError dbError{};
    std::vector<std::string> serializedExecutions;
    serializedExecutions.reserve(correlation.endpointExecutionsMatched.size());
    for (const auto& match : correlation.endpointExecutionsMatched) {
        serializedExecutions.push_back(SerializeExecutionMatch(match));
    }

    std::vector<std::string> serializedTimeline;
    serializedTimeline.reserve(correlation.timeline.size());
    for (const auto& event : correlation.timeline) {
        serializedTimeline.push_back(SerializeTimelineEvent(event));
    }

    const bool stored = DatabaseManager::Instance().ExecuteWithParams(
        "INSERT OR REPLACE INTO xdr_email_correlations (message_id, verdict, confidence, attachment_hashes, execution_matches, timeline_data, matched_urls, related_senders, escalated, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        &dbError,
        correlation.emailMessageId,
        static_cast<int>(correlation.verdict),
        correlation.confidence,
        SerializeStringList(correlation.attachmentHashes),
        SerializeStringList(serializedExecutions),
        SerializeStringList(serializedTimeline),
        SerializeStringList(correlation.matchedUrls),
        SerializeStringList(correlation.relatedSenders),
        correlation.escalated ? 1 : 0,
        analysisTimestamp);

    if (!stored) {
        Logger::Error("PhishingCorrelator: failed to persist correlation code={} msg={}",
            dbError.sqliteCode,
            SU::ToNarrow(dbError.message));
        m_impl->databaseFailures.fetch_add(1, std::memory_order_relaxed);
    } else {
        m_impl->timelineEventsPersisted.fetch_add(correlation.timeline.size(), std::memory_order_relaxed);
    }

    m_impl->totalCorrelations.fetch_add(1, std::memory_order_relaxed);
    m_impl->attachmentExecutionMatches.fetch_add(correlation.endpointExecutionsMatched.size(), std::memory_order_relaxed);
    m_impl->urlVisitMatches.fetch_add(correlation.matchedUrls.size(), std::memory_order_relaxed);
    m_impl->senderMatches.fetch_add(correlation.relatedSenders.size(), std::memory_order_relaxed);
    if (correlation.escalated) {
        m_impl->escalatedCorrelations.fetch_add(1, std::memory_order_relaxed);
    }

    m_impl->UpdateCache(correlation);
    Logger::Info("PhishingCorrelator: correlated message_id={} verdict={} confidence={:.1f} executions={} url_matches={} sender_matches={}",
        correlation.emailMessageId,
        static_cast<int>(correlation.verdict),
        correlation.confidence,
        correlation.endpointExecutionsMatched.size(),
        correlation.matchedUrls.size(),
        correlation.relatedSenders.size());
    return correlation;
}

std::vector<PhishingCorrelation> PhishingCorrelator::GetCorrelations(const std::size_t limit) const {
    std::vector<PhishingCorrelation> correlations;
    if (!IsInitialized()) {
        return correlations;
    }

    DatabaseError dbError{};
    auto query = DatabaseManager::Instance().QueryWithParams(
        "SELECT message_id, verdict, confidence, attachment_hashes, execution_matches, timeline_data, matched_urls, related_senders, escalated, created_at FROM xdr_email_correlations ORDER BY created_at DESC LIMIT ?",
        &dbError,
        static_cast<int64_t>(limit));

    if (dbError.HasError()) {
        Logger::Error("PhishingCorrelator: GetCorrelations query failed code={} msg={}",
            dbError.sqliteCode,
            SU::ToNarrow(dbError.message));
        m_impl->databaseFailures.fetch_add(1, std::memory_order_relaxed);
        return correlations;
    }

    while (query.Next()) {
        correlations.push_back(LoadCorrelationFromRow(query));
    }
    return correlations;
}

std::vector<CorrelationTimelineEvent> PhishingCorrelator::GetAttackTimeline(std::string_view messageId) const {
    if (messageId.empty()) {
        return {};
    }

    {
        std::shared_lock lock(m_impl->mutex);
        const auto it = m_impl->cache.find(std::string(messageId));
        if (it != m_impl->cache.end()) {
            return it->second.timeline;
        }
    }

    DatabaseError dbError{};
    auto query = DatabaseManager::Instance().QueryWithParams(
        "SELECT message_id, verdict, confidence, attachment_hashes, execution_matches, timeline_data, matched_urls, related_senders, escalated, created_at FROM xdr_email_correlations WHERE message_id = ? LIMIT 1",
        &dbError,
        std::string(messageId));

    if (dbError.HasError()) {
        Logger::Error("PhishingCorrelator: GetAttackTimeline query failed code={} msg={}",
            dbError.sqliteCode,
            SU::ToNarrow(dbError.message));
        m_impl->databaseFailures.fetch_add(1, std::memory_order_relaxed);
        return {};
    }
    if (!query.Next()) {
        return {};
    }

    PhishingCorrelation correlation = LoadCorrelationFromRow(query);
    m_impl->UpdateCache(correlation);
    return correlation.timeline;
}

PhishingCorrelationStatistics PhishingCorrelator::GetStatistics() const noexcept {
    PhishingCorrelationStatistics statistics;
    statistics.totalCorrelations = m_impl->totalCorrelations.load(std::memory_order_relaxed);
    statistics.escalatedCorrelations = m_impl->escalatedCorrelations.load(std::memory_order_relaxed);
    statistics.attachmentExecutionMatches = m_impl->attachmentExecutionMatches.load(std::memory_order_relaxed);
    statistics.urlVisitMatches = m_impl->urlVisitMatches.load(std::memory_order_relaxed);
    statistics.senderMatches = m_impl->senderMatches.load(std::memory_order_relaxed);
    statistics.timelineEventsPersisted = m_impl->timelineEventsPersisted.load(std::memory_order_relaxed);
    statistics.databaseFailures = m_impl->databaseFailures.load(std::memory_order_relaxed);
    return statistics;
}

} // namespace ShadowStrike::Products::PhantomXDR::EmailThreat
