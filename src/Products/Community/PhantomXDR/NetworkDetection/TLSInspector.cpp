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
#include "TLSInspector.hpp"

#include <format>
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"

#include <windows.h>
#include <wincrypt.h>

#include <algorithm>
#include <array>
#include <iomanip>
#include <numeric>
#include <optional>
#include <set>
#include <sstream>
#include <unordered_map>

namespace ShadowStrike::Products::PhantomXDR::NetworkDetection {

namespace SU = ShadowStrike::Utils::StringUtils;
using ShadowStrike::Database::DatabaseError;
using ShadowStrike::Database::DatabaseManager;
using ShadowStrike::Database::QueryResult;

namespace {

constexpr std::wstring_view kLogCategory = L"PhantomXDR.Network.TLS";
constexpr size_t kMaxStoredAnomalies = 2048;
constexpr std::chrono::days kShortCertificateValidity = std::chrono::days(14);

[[nodiscard]] std::string Narrow(std::wstring_view value) {
    return SU::ToNarrow(value);
}

void LogDatabaseError(std::string_view context, const DatabaseError& err) {
    if (!err.HasError()) {
        return;
    }

    const std::wstring message = SU::ToWide(std::format("{}: {}", context, Narrow(err.message)));
    ShadowStrike::Utils::Logger::Instance().LogMessage(
        ShadowStrike::Utils::LogLevel::Error,
        kLogCategory.data(),
        message);
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

[[nodiscard]] bool IsGreaseValue(uint16_t value) noexcept {
    return (value & 0x0F0F) == 0x0A0A && static_cast<uint8_t>(value >> 8) == static_cast<uint8_t>(value & 0xFF);
}

[[nodiscard]] std::string JoinVector(const std::vector<uint16_t>& values) {
    std::ostringstream stream;
    bool first = true;
    for (const uint16_t value : values) {
        if (IsGreaseValue(value)) {
            continue;
        }
        if (!first) {
            stream << '-';
        }
        stream << value;
        first = false;
    }
    return stream.str();
}

[[nodiscard]] std::string BuildJa3String(const TLSSession& session) {
    return std::format("{},{},{},{},{}",
        session.clientVersion,
        JoinVector(session.clientCipherSuites),
        JoinVector(session.clientExtensions),
        JoinVector(session.ellipticCurves),
        JoinVector(session.ecPointFormats));
}

[[nodiscard]] std::string BuildJa3sString(const TLSSession& session) {
    return std::format("{},{},{}",
        session.serverVersion,
        session.selectedCipher,
        JoinVector(session.serverExtensions));
}

[[nodiscard]] std::string Md5Hex(std::string_view input) {
    HCRYPTPROV provider = 0;
    HCRYPTHASH hash = 0;

    if (!::CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return {};
    }

    if (!::CryptCreateHash(provider, CALG_MD5, 0, 0, &hash)) {
        ::CryptReleaseContext(provider, 0);
        return {};
    }

    if (!::CryptHashData(hash, reinterpret_cast<const BYTE*>(input.data()), static_cast<DWORD>(input.size()), 0)) {
        ::CryptDestroyHash(hash);
        ::CryptReleaseContext(provider, 0);
        return {};
    }

    DWORD hashLength = 16;
    std::array<BYTE, 16> bytes{};
    const BOOL ok = ::CryptGetHashParam(hash, HP_HASHVAL, bytes.data(), &hashLength, 0);
    ::CryptDestroyHash(hash);
    ::CryptReleaseContext(provider, 0);
    if (!ok) {
        return {};
    }

    std::ostringstream stream;
    stream << std::hex << std::setfill('0');
    for (DWORD i = 0; i < hashLength; ++i) {
        stream << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return stream.str();
}

[[nodiscard]] std::string ToLowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

[[nodiscard]] std::optional<std::string> ExtractCommonName(std::string_view subject) {
    const auto lower = ToLowerAscii(std::string(subject));
    const size_t pos = lower.find("cn=");
    if (pos == std::string::npos) {
        return std::nullopt;
    }

    size_t end = lower.find(',', pos);
    if (end == std::string::npos) {
        end = lower.size();
    }

    std::string cn = lower.substr(pos + 3, end - (pos + 3));
    cn.erase(0, cn.find_first_not_of(' '));
    cn.erase(cn.find_last_not_of(' ') + 1);
    return cn.empty() ? std::nullopt : std::optional<std::string>(cn);
}

[[nodiscard]] bool HostMatchesPattern(std::string_view host, std::string_view pattern) {
    const std::string normalizedHost = ToLowerAscii(std::string(host));
    const std::string normalizedPattern = ToLowerAscii(std::string(pattern));
    if (normalizedHost == normalizedPattern) {
        return true;
    }

    if (normalizedPattern.starts_with("*.")) {
        const std::string suffix = normalizedPattern.substr(1);
        return normalizedHost.size() > suffix.size() && normalizedHost.ends_with(suffix);
    }

    return false;
}

[[nodiscard]] bool HasSuspiciousIssuer(std::string_view issuer) {
    static const std::array<std::string_view, 8> indicators = {
        "localhost", "testing", "example", "invalid", "temp", "lab", "unknown", "self"
    };

    const std::string lowered = ToLowerAscii(std::string(issuer));
    return std::ranges::any_of(indicators, [&lowered](std::string_view marker) {
        return lowered.find(marker) != std::string::npos;
    });
}

template <typename T>
void PushBounded(std::vector<T>& collection, const T& item) {
    collection.push_back(item);
    if (collection.size() > kMaxStoredAnomalies) {
        collection.erase(collection.begin(), collection.begin() + static_cast<ptrdiff_t>(collection.size() - kMaxStoredAnomalies));
    }
}

} // namespace

class TLSInspectorImpl final {
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

        LoadClassificationsLocked();
        m_initialized = true;
        return true;
    }

    void Shutdown() {
        std::unique_lock lock(m_mutex);
        m_classifications.clear();
        m_certAnomalies.clear();
        m_initialized = false;
    }

    [[nodiscard]] TLSSession InspectSession(const TLSSession& input) {
        TLSSession session = input;
        session.timestamp = session.timestamp.time_since_epoch().count() == 0 ? std::chrono::system_clock::now() : session.timestamp;

        std::unique_lock lock(m_mutex);
        if (!m_initialized) {
            ++m_stats.errors;
            return session;
        }

        ++m_stats.totalSessions;

        if (session.ja3Hash.empty() && !session.clientCipherSuites.empty()) {
            const std::string ja3 = BuildJa3String(session);
            session.ja3Hash = Md5Hex(ja3);
            ++m_stats.calculatedJa3;
        }

        if (session.ja3sHash.empty() && session.serverVersion != 0 && session.selectedCipher != 0) {
            session.ja3sHash = Md5Hex(BuildJa3sString(session));
        }

        TLSAnomalyFlag flags = static_cast<TLSAnomalyFlag>(session.anomalyFlags);
        const auto now = std::chrono::system_clock::now();

        if (session.selfSigned || (!session.certIssuer.empty() && session.certIssuer == session.certSubject)) {
            flags |= TLSAnomalyFlag::SelfSigned;
        }

        if (session.certExpiry.time_since_epoch().count() != 0 && session.certExpiry < now) {
            flags |= TLSAnomalyFlag::Expired;
        }

        if (session.certNotBefore.time_since_epoch().count() != 0 &&
            session.certExpiry.time_since_epoch().count() != 0 &&
            (session.certExpiry - session.certNotBefore) <= kShortCertificateValidity) {
            flags |= TLSAnomalyFlag::ShortValidity;
        }

        if (session.serverName.empty()) {
            flags |= TLSAnomalyFlag::MissingSni;
        } else if (const auto cn = ExtractCommonName(session.certSubject); cn.has_value()) {
            if (!HostMatchesPattern(session.serverName, *cn)) {
                flags |= TLSAnomalyFlag::DomainMismatch;
            }
        }

        if (HasSuspiciousIssuer(session.certIssuer)) {
            flags |= TLSAnomalyFlag::SuspiciousIssuer;
        }

        const auto it = m_classifications.find(session.ja3Hash);
        if (it != m_classifications.end()) {
            const std::string classification = ToLowerAscii(it->second);
            if (classification.find("malicious") != std::string::npos ||
                classification.find("c2") != std::string::npos ||
                classification.find("botnet") != std::string::npos) {
                flags |= TLSAnomalyFlag::KnownMaliciousJa3;
                ++m_stats.maliciousJa3Matches;
            }
        } else if (!session.ja3Hash.empty()) {
            flags |= TLSAnomalyFlag::UnknownFingerprint;
        }

        session.anomalyFlags = static_cast<uint32_t>(flags);
        if (session.anomalyFlags != 0U) {
            ++m_stats.certificateAnomalies;
            PushBounded(m_certAnomalies, session);
        }

        PersistSessionLocked(session);
        return session;
    }

    [[nodiscard]] std::vector<std::string> GetKnownMaliciousJA3() const {
        std::shared_lock lock(m_mutex);
        std::vector<std::string> values;
        for (const auto& [hash, classification] : m_classifications) {
            const auto lowered = ToLowerAscii(classification);
            if (lowered.find("malicious") != std::string::npos ||
                lowered.find("c2") != std::string::npos ||
                lowered.find("botnet") != std::string::npos) {
                values.push_back(hash);
            }
        }
        std::sort(values.begin(), values.end());
        return values;
    }

    [[nodiscard]] bool AddJA3Classification(std::string_view ja3Hash, std::string_view classification, std::string_view notes) {
        if (ja3Hash.empty() || classification.empty()) {
            return false;
        }

        std::unique_lock lock(m_mutex);
        DatabaseError err;
        const bool ok = DatabaseManager::Instance().ExecuteWithParams(
            "INSERT INTO xdr_tls_ja3(hash, classification, notes, updated_at) VALUES(?, ?, ?, ?) "
            "ON CONFLICT(hash) DO UPDATE SET classification=excluded.classification, notes=excluded.notes, updated_at=excluded.updated_at",
            &err,
            std::string(ja3Hash),
            std::string(classification),
            std::string(notes),
            ToIso8601(std::chrono::system_clock::now()));
        if (!ok) {
            LogDatabaseError("AddJA3Classification", err);
            ++m_stats.errors;
            return false;
        }

        m_classifications[std::string(ja3Hash)] = std::string(classification);
        return true;
    }

    [[nodiscard]] std::vector<TLSSession> GetCertAnomalies(size_t limit) const {
        std::shared_lock lock(m_mutex);
        if (limit >= m_certAnomalies.size()) {
            return m_certAnomalies;
        }
        return std::vector<TLSSession>(m_certAnomalies.end() - static_cast<ptrdiff_t>(limit), m_certAnomalies.end());
    }

    [[nodiscard]] TLSInspectorStatistics GetStatistics() const {
        std::shared_lock lock(m_mutex);
        return m_stats;
    }

private:
    [[nodiscard]] bool EnsureSchemaLocked() {
        DatabaseError err;
        const char* sql = R"SQL(
            CREATE TABLE IF NOT EXISTS xdr_tls_ja3(
                hash TEXT PRIMARY KEY,
                classification TEXT NOT NULL,
                notes TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS xdr_tls_sessions(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ja3_hash TEXT NOT NULL,
                ja3s_hash TEXT NOT NULL,
                server_name TEXT NOT NULL,
                cert_issuer TEXT NOT NULL,
                cert_subject TEXT NOT NULL,
                anomaly_flags INTEGER NOT NULL,
                process_id INTEGER NOT NULL,
                process_name TEXT NOT NULL,
                observed_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_xdr_tls_sessions_ja3 ON xdr_tls_sessions(ja3_hash);
            CREATE INDEX IF NOT EXISTS idx_xdr_tls_sessions_time ON xdr_tls_sessions(observed_at);
        )SQL";

        const bool ok = DatabaseManager::Instance().Execute(sql, &err);
        if (!ok) {
            LogDatabaseError("EnsureSchema", err);
        }
        return ok;
    }

    void LoadClassificationsLocked() {
        DatabaseError err;
        QueryResult rows = DatabaseManager::Instance().Query("SELECT hash, classification FROM xdr_tls_ja3", &err);
        if (err.HasError()) {
            LogDatabaseError("LoadClassifications", err);
            ++m_stats.errors;
            return;
        }

        m_classifications.clear();
        while (rows.Next()) {
            m_classifications[rows.GetString("hash")] = rows.GetString("classification");
        }
    }

    void PersistSessionLocked(const TLSSession& session) {
        DatabaseError err;
        const bool ok = DatabaseManager::Instance().ExecuteWithParams(
            "INSERT INTO xdr_tls_sessions("
            "ja3_hash, ja3s_hash, server_name, cert_issuer, cert_subject, anomaly_flags, process_id, process_name, observed_at"
            ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
            &err,
            session.ja3Hash,
            session.ja3sHash,
            session.serverName,
            session.certIssuer,
            session.certSubject,
            static_cast<int>(session.anomalyFlags),
            static_cast<int>(session.processId),
            Narrow(session.processName),
            ToIso8601(session.timestamp));
        if (!ok) {
            LogDatabaseError("PersistSession", err);
            ++m_stats.errors;
        }
    }

    mutable std::shared_mutex m_mutex;
    bool m_initialized = false;
    TLSInspectorStatistics m_stats{};
    std::unordered_map<std::string, std::string> m_classifications;
    std::vector<TLSSession> m_certAnomalies;
};

TLSInspector::TLSInspector() : m_impl(std::make_unique<TLSInspectorImpl>()) {}
TLSInspector::~TLSInspector() = default;

bool TLSInspector::Initialize() { return m_impl->Initialize(); }
void TLSInspector::Shutdown() { m_impl->Shutdown(); }
TLSSession TLSInspector::InspectSession(const TLSSession& session) { return m_impl->InspectSession(session); }
std::vector<std::string> TLSInspector::GetKnownMaliciousJA3() const { return m_impl->GetKnownMaliciousJA3(); }
bool TLSInspector::AddJA3Classification(std::string_view ja3Hash, std::string_view classification, std::string_view notes) {
    return m_impl->AddJA3Classification(ja3Hash, classification, notes);
}
std::vector<TLSSession> TLSInspector::GetCertAnomalies(size_t limit) const { return m_impl->GetCertAnomalies(limit); }
TLSInspectorStatistics TLSInspector::GetStatistics() const { return m_impl->GetStatistics(); }

} // namespace ShadowStrike::Products::PhantomXDR::NetworkDetection
