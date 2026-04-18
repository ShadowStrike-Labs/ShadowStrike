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
#include "DNSAnalyzer.hpp"

#include <format>
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"

#include <windows.h>
#include <windns.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <deque>
#include <numeric>
#include <optional>
#include <ranges>
#include <set>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace ShadowStrike::Products::PhantomXDR::NetworkDetection {

namespace SU = ShadowStrike::Utils::StringUtils;
using ShadowStrike::Database::DatabaseError;
using ShadowStrike::Database::DatabaseManager;
using ShadowStrike::Database::QueryResult;

namespace {

constexpr std::wstring_view kLogCategory = L"PhantomXDR.Network.DNS";
constexpr size_t kMaxHistoryEntries = 4096;
constexpr size_t kMaxCacheEntriesPerPass = 16384;
constexpr size_t kMaxDomainLength = 253;
constexpr size_t kMaxLabelLength = 63;
constexpr std::chrono::seconds kCachePollInterval{15};
constexpr std::chrono::minutes kFrequencyWindow{5};
constexpr double kHighEntropyThreshold = 3.85;
constexpr double kDgaThreshold = 0.74;
constexpr size_t kTunnelingFrequencyThreshold = 25;
constexpr size_t kLongQueryThreshold = 52;

using DnsCacheTimestamp = std::chrono::steady_clock::time_point;

struct DNS_CACHE_ENTRY_W_COMPAT {
    DNS_CACHE_ENTRY_W_COMPAT* pNext;
    PWSTR pszName;
    WORD wType;
    WORD wDataLength;
    DWORD dwFlags;
};

using DnsGetCacheDataTableFn = BOOL(WINAPI*)(DNS_CACHE_ENTRY_W_COMPAT*);

struct DomainObservation {
    std::deque<SystemTimePoint> queryTimes;
    size_t txtCount = 0;
    double rollingEntropy = 0.0;
    DNSQuery lastQuery;
};

[[nodiscard]] std::string Narrow(std::wstring_view value) {
    return SU::ToNarrow(value);
}

[[nodiscard]] std::wstring Wide(std::string_view value) {
    return SU::ToWide(value);
}

void LogDatabaseError(std::string_view context, const DatabaseError& err) {
    if (!err.HasError()) {
        return;
    }

    const auto message = SU::ToWide(std::format("{}: {}", context, Narrow(err.message)));
    ShadowStrike::Utils::Logger::Instance().LogMessage(
        ShadowStrike::Utils::LogLevel::Error,
        kLogCategory.data(),
        message);
}

[[nodiscard]] std::string NormalizeDomain(std::string_view domain) {
    std::string normalized;
    normalized.reserve(domain.size());

    for (const unsigned char ch : domain) {
        if (std::isalnum(ch) != 0 || ch == '-' || ch == '.' || ch == '_') {
            normalized.push_back(static_cast<char>(std::tolower(ch)));
        }
    }

    while (!normalized.empty() && normalized.back() == '.') {
        normalized.pop_back();
    }

    return normalized;
}

[[nodiscard]] std::vector<std::string> SplitLabels(std::string_view domain) {
    std::vector<std::string> labels;
    size_t start = 0;

    while (start < domain.size()) {
        const size_t end = domain.find('.', start);
        const size_t length = (end == std::string_view::npos) ? domain.size() - start : end - start;
        labels.emplace_back(domain.substr(start, length));
        if (end == std::string_view::npos) {
            break;
        }
        start = end + 1;
    }

    return labels;
}

[[nodiscard]] std::string BaseDomain(std::string_view domain) {
    const auto labels = SplitLabels(domain);
    if (labels.size() <= 2) {
        return std::string(domain);
    }

    return labels[labels.size() - 2] + "." + labels.back();
}

[[nodiscard]] bool IsLikelyValidDomain(std::string_view domain) {
    if (domain.empty() || domain.size() > kMaxDomainLength) {
        return false;
    }

    const auto labels = SplitLabels(domain);
    if (labels.empty()) {
        return false;
    }

    for (const auto& label : labels) {
        if (label.empty() || label.size() > kMaxLabelLength) {
            return false;
        }

        if (label.front() == '-' || label.back() == '-') {
            return false;
        }

        const bool valid = std::ranges::all_of(label, [](unsigned char ch) {
            return std::isalnum(ch) != 0 || ch == '-' || ch == '_';
        });

        if (!valid) {
            return false;
        }
    }

    return true;
}

[[nodiscard]] double ShannonEntropy(std::string_view value) {
    if (value.empty()) {
        return 0.0;
    }

    std::array<size_t, 256> histogram{};
    for (const unsigned char ch : value) {
        ++histogram[ch];
    }

    double entropy = 0.0;
    const double length = static_cast<double>(value.size());
    for (const size_t count : histogram) {
        if (count == 0) {
            continue;
        }

        const double p = static_cast<double>(count) / length;
        entropy -= p * std::log2(p);
    }

    return entropy;
}

[[nodiscard]] double BigramRarity(std::string_view domain) {
    static const std::array<std::string_view, 40> commonBigrams = {
        "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd",
        "ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar",
        "st", "to", "nt", "ng", "se", "ha", "as", "ou", "io", "le",
        "ve", "co", "me", "de", "hi", "ri", "ro", "ic", "ne", "ea"
    };

    std::string compact;
    compact.reserve(domain.size());
    for (const unsigned char ch : domain) {
        if (std::isalnum(ch) != 0) {
            compact.push_back(static_cast<char>(std::tolower(ch)));
        }
    }

    if (compact.size() < 2) {
        return 0.0;
    }

    size_t uncommon = 0;
    size_t total = 0;
    for (size_t i = 0; i + 1 < compact.size(); ++i) {
        const std::string_view bigram{compact.data() + i, 2};
        const bool common = std::ranges::find(commonBigrams, bigram) != commonBigrams.end();
        uncommon += common ? 0u : 1u;
        ++total;
    }

    return total == 0 ? 0.0 : static_cast<double>(uncommon) / static_cast<double>(total);
}

[[nodiscard]] double DigitRatio(std::string_view value) {
    if (value.empty()) {
        return 0.0;
    }

    const size_t digits = std::ranges::count_if(value, [](unsigned char ch) {
        return std::isdigit(ch) != 0;
    });

    return static_cast<double>(digits) / static_cast<double>(value.size());
}

[[nodiscard]] size_t LongestConsonantRun(std::string_view value) {
    size_t longest = 0;
    size_t current = 0;
    for (const unsigned char ch : value) {
        const char lower = static_cast<char>(std::tolower(ch));
        const bool vowel = lower == 'a' || lower == 'e' || lower == 'i' || lower == 'o' || lower == 'u';
        if (std::isalpha(ch) != 0 && !vowel) {
            ++current;
            longest = std::max(longest, current);
        } else {
            current = 0;
        }
    }
    return longest;
}

[[nodiscard]] double Clamp01(double value) {
    return std::clamp(value, 0.0, 1.0);
}

[[nodiscard]] double CalculateDgaProbability(std::string_view domain) {
    const auto labels = SplitLabels(domain);
    if (labels.empty()) {
        return 0.0;
    }

    std::string secondLevel = labels.size() >= 2 ? labels[labels.size() - 2] : labels.front();
    if (secondLevel.empty()) {
        secondLevel = std::string(domain);
    }

    const double entropy = ShannonEntropy(secondLevel);
    const double rarity = BigramRarity(secondLevel);
    const double digits = DigitRatio(secondLevel);
    const double lengthComponent = Clamp01((static_cast<double>(secondLevel.size()) - 12.0) / 18.0);
    const double consonantComponent = Clamp01(static_cast<double>(LongestConsonantRun(secondLevel)) / 8.0);

    const double score =
        (Clamp01((entropy - 2.8) / 1.5) * 0.30) +
        (rarity * 0.25) +
        (digits * 0.15) +
        (lengthComponent * 0.15) +
        (consonantComponent * 0.15);

    return Clamp01(score);
}

[[nodiscard]] std::string ToIso8601(SystemTimePoint timestamp) {
    if (timestamp.time_since_epoch().count() == 0) {
        timestamp = std::chrono::system_clock::now();
    }

    const auto tt = std::chrono::system_clock::to_time_t(timestamp);
    std::tm tmUtc{};
    gmtime_s(&tmUtc, &tt);

    char buffer[32]{};
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &tmUtc);
    return std::string(buffer);
}

[[nodiscard]] bool IsTxtQuery(uint16_t type) noexcept {
    return type == DNS_TYPE_TEXT || type == DNS_TYPE_NULL || type == 16 || type == 10;
}

} // namespace

class DNSAnalyzerImpl final {
public:
    [[nodiscard]] bool Initialize() {
        std::unique_lock lock(m_mutex);
        if (m_initialized) {
            return true;
        }

        if (!EnsureSchemaLocked()) {
            ++m_stats.errors;
            return false;
        }

        LoadWhitelistLocked();
        m_cacheThread = std::jthread([this](std::stop_token token) { CacheMonitorLoop(token); });
        m_initialized = true;
        return true;
    }

    void Shutdown() {
        std::unique_lock lock(m_mutex);
        if (!m_initialized) {
            return;
        }

        if (m_cacheThread.joinable()) {
            m_cacheThread.request_stop();
        }
        lock.unlock();
        if (m_cacheThread.joinable()) {
            m_cacheThread.join();
        }
        lock.lock();

        m_domainHistory.clear();
        m_suspiciousDomains.clear();
        m_dgaDetections.clear();
        m_tunnelingDetections.clear();
        m_recentCacheFingerprints.clear();
        m_initialized = false;
    }

    [[nodiscard]] DNSQuery AnalyzeQuery(const DNSQuery& input) {
        DNSQuery query = input;
        query.timestamp = query.timestamp.time_since_epoch().count() == 0 ? std::chrono::system_clock::now() : query.timestamp;
        query.queryName = NormalizeDomain(query.queryName);
        query.queryLength = static_cast<uint32_t>(query.queryName.size());
        query.labelCount = static_cast<uint32_t>(SplitLabels(query.queryName).size());

        std::unique_lock lock(m_mutex);
        if (!m_initialized) {
            ++m_stats.errors;
            return query;
        }

        if (!IsLikelyValidDomain(query.queryName)) {
            ++m_stats.errors;
            return query;
        }

        ++m_stats.totalQueries;
        query.whitelisted = m_whitelist.contains(query.queryName) || m_whitelist.contains(BaseDomain(query.queryName));
        if (query.whitelisted) {
            ++m_stats.whitelistedQueries;
            PersistQueryLocked(query, false, false);
            return query;
        }

        query.entropyScore = ShannonEntropy(query.queryName);
        query.dgaProbability = CalculateDgaProbability(query.queryName);

        auto& observation = m_domainHistory[BaseDomain(query.queryName)];
        observation.lastQuery = query;
        observation.rollingEntropy = observation.rollingEntropy == 0.0
            ? query.entropyScore
            : ((observation.rollingEntropy * 4.0) + query.entropyScore) / 5.0;
        if (IsTxtQuery(query.type)) {
            ++observation.txtCount;
        }

        observation.queryTimes.push_back(query.timestamp);
        while (!observation.queryTimes.empty() &&
               (query.timestamp - observation.queryTimes.front()) > kFrequencyWindow) {
            observation.queryTimes.pop_front();
        }

        const bool longQuery = query.queryLength >= kLongQueryThreshold;
        const bool highEntropy = query.entropyScore >= kHighEntropyThreshold;
        const bool frequent = observation.queryTimes.size() >= kTunnelingFrequencyThreshold;
        const bool txtAbuse = observation.txtCount >= 5 && IsTxtQuery(query.type);
        const bool highDga = query.dgaProbability >= kDgaThreshold;

        query.tunnelingSuspected = (longQuery && highEntropy) || (frequent && highEntropy) || txtAbuse;
        query.suspicious = query.tunnelingSuspected || highDga;

        if (highDga) {
            ++m_stats.dgaDetections;
            PushBounded(m_dgaDetections, query);
            m_suspiciousDomains.insert(query.queryName);
        }

        if (query.tunnelingSuspected) {
            ++m_stats.tunnelingDetections;
            PushBounded(m_tunnelingDetections, query);
            m_suspiciousDomains.insert(query.queryName);
        }

        PersistQueryLocked(query, highDga, query.tunnelingSuspected);
        return query;
    }

    [[nodiscard]] std::vector<std::string> GetSuspiciousDomains(size_t limit) const {
        std::shared_lock lock(m_mutex);
        std::vector<std::string> result;
        result.reserve(std::min(limit, m_suspiciousDomains.size()));
        for (const auto& value : m_suspiciousDomains) {
            if (result.size() >= limit) {
                break;
            }
            result.push_back(value);
        }
        std::sort(result.begin(), result.end());
        return result;
    }

    [[nodiscard]] std::vector<DNSQuery> GetDGADetections(size_t limit) const {
        std::shared_lock lock(m_mutex);
        return CopyTail(m_dgaDetections, limit);
    }

    [[nodiscard]] std::vector<DNSQuery> GetTunnelingDetections(size_t limit) const {
        std::shared_lock lock(m_mutex);
        return CopyTail(m_tunnelingDetections, limit);
    }

    [[nodiscard]] bool AddWhitelistDomain(std::string_view domain) {
        const auto normalized = NormalizeDomain(domain);
        if (!IsLikelyValidDomain(normalized)) {
            return false;
        }

        std::unique_lock lock(m_mutex);
        if (m_whitelist.contains(normalized)) {
            return true;
        }

        DatabaseError err;
        const bool ok = DatabaseManager::Instance().ExecuteWithParams(
            "INSERT OR IGNORE INTO xdr_dns_whitelist(domain, created_at) VALUES(?, ?)",
            &err,
            normalized,
            ToIso8601(std::chrono::system_clock::now()));
        if (!ok) {
            LogDatabaseError("AddWhitelistDomain", err);
            ++m_stats.errors;
            return false;
        }

        m_whitelist.insert(normalized);
        return true;
    }

    [[nodiscard]] DNSAnalyzerStatistics GetStatistics() const {
        std::shared_lock lock(m_mutex);
        return m_stats;
    }

private:
    template <typename T>
    static void PushBounded(std::vector<T>& collection, const T& value) {
        collection.push_back(value);
        if (collection.size() > kMaxHistoryEntries) {
            collection.erase(collection.begin(), collection.begin() + static_cast<ptrdiff_t>(collection.size() - kMaxHistoryEntries));
        }
    }

    template <typename T>
    [[nodiscard]] static std::vector<T> CopyTail(const std::vector<T>& collection, size_t limit) {
        if (limit >= collection.size()) {
            return collection;
        }
        return std::vector<T>(collection.end() - static_cast<ptrdiff_t>(limit), collection.end());
    }

    [[nodiscard]] bool EnsureSchemaLocked() {
        DatabaseError err;
        const char* sql = R"SQL(
            CREATE TABLE IF NOT EXISTS xdr_dns_queries(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                query_name TEXT NOT NULL,
                query_type INTEGER NOT NULL,
                ttl INTEGER NOT NULL,
                entropy_score REAL NOT NULL,
                dga_probability REAL NOT NULL,
                suspicious INTEGER NOT NULL,
                tunneling INTEGER NOT NULL,
                whitelisted INTEGER NOT NULL,
                process_id INTEGER NOT NULL,
                process_name TEXT NOT NULL,
                response_ips TEXT NOT NULL,
                observed_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_xdr_dns_queries_name ON xdr_dns_queries(query_name);
            CREATE INDEX IF NOT EXISTS idx_xdr_dns_queries_time ON xdr_dns_queries(observed_at);
            CREATE TABLE IF NOT EXISTS xdr_dns_whitelist(
                domain TEXT PRIMARY KEY,
                created_at TEXT NOT NULL
            );
        )SQL";

        const bool ok = DatabaseManager::Instance().Execute(sql, &err);
        if (!ok) {
            LogDatabaseError("EnsureSchema", err);
        }
        return ok;
    }

    void LoadWhitelistLocked() {
        DatabaseError err;
        QueryResult rows = DatabaseManager::Instance().Query("SELECT domain FROM xdr_dns_whitelist", &err);
        if (err.HasError()) {
            LogDatabaseError("LoadWhitelist", err);
            ++m_stats.errors;
            return;
        }

        m_whitelist.clear();
        while (rows.Next()) {
            m_whitelist.insert(NormalizeDomain(rows.GetString("domain")));
        }
    }

    void PersistQueryLocked(const DNSQuery& query, bool dgaDetected, bool tunnelingDetected) {
        std::ostringstream responses;
        for (size_t i = 0; i < query.responseIps.size(); ++i) {
            if (i != 0) {
                responses << ',';
            }
            responses << query.responseIps[i];
        }

        DatabaseError err;
        const bool ok = DatabaseManager::Instance().ExecuteWithParams(
            "INSERT INTO xdr_dns_queries("
            "query_name, query_type, ttl, entropy_score, dga_probability, suspicious, tunneling, whitelisted, "
            "process_id, process_name, response_ips, observed_at"
            ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            &err,
            query.queryName,
            static_cast<int>(query.type),
            static_cast<int>(query.ttl),
            query.entropyScore,
            query.dgaProbability,
            (dgaDetected || tunnelingDetected) ? 1 : 0,
            tunnelingDetected ? 1 : 0,
            query.whitelisted ? 1 : 0,
            static_cast<int>(query.processId),
            Narrow(query.processName),
            responses.str(),
            ToIso8601(query.timestamp));
        if (!ok) {
            LogDatabaseError("PersistQuery", err);
            ++m_stats.errors;
        }
    }

    void CacheMonitorLoop(std::stop_token token) {
        while (!token.stop_requested()) {
            EnumerateDnsCache();
            std::this_thread::sleep_for(kCachePollInterval);
        }
    }

    void EnumerateDnsCache() {
        HMODULE dnsApi = ::GetModuleHandleW(L"dnsapi.dll");
        if (dnsApi == nullptr) {
            return;
        }

        const auto fn = reinterpret_cast<DnsGetCacheDataTableFn>(::GetProcAddress(dnsApi, "DnsGetCacheDataTable"));
        if (fn == nullptr) {
            return;
        }

        DNS_CACHE_ENTRY_W_COMPAT entry{};
        if (!fn(&entry)) {
            std::unique_lock lock(m_mutex);
            ++m_stats.errors;
            return;
        }

        std::vector<DNSQuery> snapshot;
        snapshot.reserve(128);

        size_t count = 0;
        for (auto* current = entry.pNext; current != nullptr && count < kMaxCacheEntriesPerPass; current = current->pNext, ++count) {
            if (current->pszName == nullptr) {
                continue;
            }

            const std::string domain = NormalizeDomain(SU::ToNarrow(current->pszName));
            if (!IsLikelyValidDomain(domain)) {
                continue;
            }

            DNSQuery query;
            query.queryName = domain;
            query.type = current->wType;
            query.ttl = 0;
            query.timestamp = std::chrono::system_clock::now();
            snapshot.push_back(std::move(query));
        }

        const auto now = std::chrono::steady_clock::now();
        std::unique_lock lock(m_mutex);
        ++m_stats.cacheEnumerations;

        for (const auto& query : snapshot) {
            const std::string fingerprint = std::format("{}:{}", query.queryName, query.type);
            const auto it = m_recentCacheFingerprints.find(fingerprint);
            if (it != m_recentCacheFingerprints.end() && (now - it->second) < kCachePollInterval) {
                continue;
            }
            m_recentCacheFingerprints[fingerprint] = now;
            lock.unlock();
            [[maybe_unused]] const auto analyzedQuery = AnalyzeQuery(query);
            lock.lock();
        }
    }

    mutable std::shared_mutex m_mutex;
    std::jthread m_cacheThread;
    bool m_initialized = false;
    DNSAnalyzerStatistics m_stats{};
    std::unordered_set<std::string> m_whitelist;
    std::unordered_map<std::string, DomainObservation> m_domainHistory;
    std::unordered_set<std::string> m_suspiciousDomains;
    std::vector<DNSQuery> m_dgaDetections;
    std::vector<DNSQuery> m_tunnelingDetections;
    std::unordered_map<std::string, DnsCacheTimestamp> m_recentCacheFingerprints;
};

DNSAnalyzer::DNSAnalyzer() : m_impl(std::make_unique<DNSAnalyzerImpl>()) {}
DNSAnalyzer::~DNSAnalyzer() = default;

bool DNSAnalyzer::Initialize() { return m_impl->Initialize(); }
void DNSAnalyzer::Shutdown() { m_impl->Shutdown(); }
DNSQuery DNSAnalyzer::AnalyzeQuery(const DNSQuery& query) { return m_impl->AnalyzeQuery(query); }
std::vector<std::string> DNSAnalyzer::GetSuspiciousDomains(size_t limit) const { return m_impl->GetSuspiciousDomains(limit); }
std::vector<DNSQuery> DNSAnalyzer::GetDGADetections(size_t limit) const { return m_impl->GetDGADetections(limit); }
std::vector<DNSQuery> DNSAnalyzer::GetTunnelingDetections(size_t limit) const { return m_impl->GetTunnelingDetections(limit); }
bool DNSAnalyzer::AddWhitelistDomain(std::string_view domain) { return m_impl->AddWhitelistDomain(domain); }
DNSAnalyzerStatistics DNSAnalyzer::GetStatistics() const { return m_impl->GetStatistics(); }

} // namespace ShadowStrike::Products::PhantomXDR::NetworkDetection
