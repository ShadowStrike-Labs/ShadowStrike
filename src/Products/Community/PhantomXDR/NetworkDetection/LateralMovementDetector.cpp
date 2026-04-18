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
#include "LateralMovementDetector.hpp"

#include <format>
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"

#include <windows.h>

#include <algorithm>
#include <array>
#include <deque>
#include <set>
#include <unordered_map>

namespace ShadowStrike::Products::PhantomXDR::NetworkDetection {

namespace SU = ShadowStrike::Utils::StringUtils;
using ShadowStrike::Database::DatabaseError;
using ShadowStrike::Database::DatabaseManager;
using ShadowStrike::Database::QueryResult;

namespace {

constexpr std::wstring_view kLogCategory = L"PhantomXDR.Network.Lateral";
constexpr size_t kMaxDetections = 2048;
constexpr std::chrono::minutes kChainWindow{15};

struct ChainState {
    std::deque<LateralMovementEvent> events;
    std::set<std::string> targets;
    std::set<NetworkProtocol> protocols;
};

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

[[nodiscard]] bool IsPrivateIpv4(std::string_view ip) {
    return ip.starts_with("10.") ||
           ip.starts_with("192.168.") ||
           ip.starts_with("127.") ||
           (ip.starts_with("172.") && ip.size() > 4 && std::isdigit(static_cast<unsigned char>(ip[4])) != 0);
}

[[nodiscard]] std::string LocalHostname() {
    char buffer[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD size = static_cast<DWORD>(std::size(buffer));
    if (::GetComputerNameA(buffer, &size) == 0) {
        return "localhost";
    }
    return std::string(buffer, size);
}

[[nodiscard]] std::string ToLowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

[[nodiscard]] std::optional<NetworkProtocol> ProtocolFromConnection(const NetworkConnection& connection) {
    if (connection.destinationPort == 445 || connection.sourcePort == 445) {
        return NetworkProtocol::SMB;
    }
    if (connection.destinationPort == 135 || connection.sourcePort == 135) {
        return NetworkProtocol::WMI;
    }
    if (connection.destinationPort == 3389 || connection.sourcePort == 3389) {
        return NetworkProtocol::RDP;
    }
    if (connection.destinationPort == 22 || connection.sourcePort == 22) {
        return NetworkProtocol::SSH;
    }
    return std::nullopt;
}

[[nodiscard]] bool IsSuspiciousProcess(std::wstring_view processName) {
    const std::string lowered = ToLowerAscii(Narrow(processName));
    static const std::array<std::string_view, 10> indicators = {
        "psexec", "psexesvc", "paexec", "wmic", "wmiprvse", "powershell", "mstsc", "cmd.exe", "sc.exe", "winrs"
    };

    return std::ranges::any_of(indicators, [&lowered](std::string_view indicator) {
        return lowered.find(indicator) != std::string::npos;
    });
}

[[nodiscard]] std::string CredentialTypeForProcess(std::wstring_view processName, NetworkProtocol protocol) {
    const std::string lowered = ToLowerAscii(Narrow(processName));
    if (lowered.find("psexec") != std::string::npos || lowered.find("paexec") != std::string::npos) {
        return "ServiceControl";
    }
    if (lowered.find("wmic") != std::string::npos || lowered.find("wmiprvse") != std::string::npos) {
        return "WMIExec";
    }
    if (lowered.find("mstsc") != std::string::npos) {
        return "InteractiveRdp";
    }
    if (protocol == NetworkProtocol::SMB) {
        return "NTLMOrKerberos";
    }
    if (protocol == NetworkProtocol::WMI) {
        return "DCOM";
    }
    if (protocol == NetworkProtocol::RDP) {
        return "InteractiveLogon";
    }
    return "Unknown";
}

template <typename T>
void PushBounded(std::vector<T>& values, const T& item) {
    values.push_back(item);
    if (values.size() > kMaxDetections) {
        values.erase(values.begin(), values.begin() + static_cast<ptrdiff_t>(values.size() - kMaxDetections));
    }
}

} // namespace

class LateralMovementDetectorImpl final {
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

        m_localHostname = LocalHostname();
        m_initialized = true;
        return true;
    }

    void Shutdown() {
        std::unique_lock lock(m_mutex);
        m_detections.clear();
        m_chains.clear();
        m_chainState.clear();
        m_initialized = false;
    }

    [[nodiscard]] std::optional<LateralMovementEvent> AnalyzeConnection(const NetworkConnection& connection) {
        std::unique_lock lock(m_mutex);
        if (!m_initialized) {
            ++m_stats.errors;
            return std::nullopt;
        }

        ++m_stats.analyzedConnections;

        const auto protocol = ProtocolFromConnection(connection);
        if (!protocol.has_value()) {
            return std::nullopt;
        }

        const bool remotePrivate = IsPrivateIpv4(connection.destinationIp);
        if (!remotePrivate) {
            return std::nullopt;
        }

        double confidence = 0.35;
        std::vector<std::string> techniques;
        techniques.emplace_back("RemoteAdminProtocol");

        if (connection.direction == ConnectionDirection::Outbound) {
            confidence += 0.15;
            techniques.emplace_back("OutboundAdministrativeConnection");
        }

        if (IsSuspiciousProcess(connection.processName)) {
            confidence += 0.20;
            techniques.emplace_back("SuspiciousAdminTool");
        }

        if (*protocol == NetworkProtocol::SMB) {
            confidence += 0.15;
            techniques.emplace_back("RemoteServiceControl");
        } else if (*protocol == NetworkProtocol::WMI) {
            confidence += 0.20;
            techniques.emplace_back("RemoteProcessViaWMI");
        } else if (*protocol == NetworkProtocol::RDP) {
            confidence += 0.10;
            techniques.emplace_back("InteractiveRemoteDesktop");
        }

        if (connection.isNewConnection) {
            confidence += 0.05;
        }

        confidence = std::clamp(confidence, 0.0, 1.0);
        if (confidence < 0.55) {
            return std::nullopt;
        }

        LateralMovementEvent event;
        event.sourceHost = m_localHostname;
        event.targetHost = connection.destinationIp;
        event.protocol = *protocol;
        event.credentialType = CredentialTypeForProcess(connection.processName, *protocol);
        event.timestamp = connection.timestamp.time_since_epoch().count() == 0 ? std::chrono::system_clock::now() : connection.timestamp;
        event.processId = connection.processId;
        event.processName = connection.processName;
        event.confidence = confidence;
        event.techniques = std::move(techniques);

        ++m_stats.detections;
        if (confidence >= 0.80) {
            ++m_stats.highConfidenceDetections;
        }

        PushBounded(m_detections, event);
        UpdateChainLocked(event);
        PersistEventLocked(event);
        return event;
    }

    [[nodiscard]] std::vector<LateralMovementEvent> GetDetections(size_t limit) const {
        std::shared_lock lock(m_mutex);
        if (limit >= m_detections.size()) {
            return m_detections;
        }
        return std::vector<LateralMovementEvent>(m_detections.end() - static_cast<ptrdiff_t>(limit), m_detections.end());
    }

    [[nodiscard]] std::vector<LateralMovementChain> GetLateralChains(size_t limit) const {
        std::shared_lock lock(m_mutex);
        if (limit >= m_chains.size()) {
            return m_chains;
        }
        return std::vector<LateralMovementChain>(m_chains.end() - static_cast<ptrdiff_t>(limit), m_chains.end());
    }

    [[nodiscard]] LateralMovementStatistics GetStatistics() const {
        std::shared_lock lock(m_mutex);
        return m_stats;
    }

private:
    [[nodiscard]] bool EnsureSchemaLocked() {
        DatabaseError err;
        const char* sql = R"SQL(
            CREATE TABLE IF NOT EXISTS xdr_lateral_events(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_host TEXT NOT NULL,
                target_host TEXT NOT NULL,
                protocol INTEGER NOT NULL,
                credential_type TEXT NOT NULL,
                process_id INTEGER NOT NULL,
                process_name TEXT NOT NULL,
                confidence REAL NOT NULL,
                techniques TEXT NOT NULL,
                observed_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS xdr_lateral_chains(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_host TEXT NOT NULL,
                score REAL NOT NULL,
                unique_targets INTEGER NOT NULL,
                unique_protocols INTEGER NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );
        )SQL";

        const bool ok = DatabaseManager::Instance().Execute(sql, &err);
        if (!ok) {
            LogDatabaseError("EnsureSchema", err);
        }
        return ok;
    }

    void UpdateChainLocked(const LateralMovementEvent& event) {
        auto& state = m_chainState[event.sourceHost];
        state.events.push_back(event);
        state.targets.insert(event.targetHost);
        state.protocols.insert(event.protocol);

        while (!state.events.empty() && (event.timestamp - state.events.front().timestamp) > kChainWindow) {
            const auto expired = state.events.front();
            state.events.pop_front();
            RebuildChainIndexes(state);
            if (state.events.empty()) {
                break;
            }
        }

        if (state.targets.size() >= 2 || state.protocols.size() >= 2) {
            LateralMovementChain chain;
            chain.sourceHost = event.sourceHost;
            chain.events.assign(state.events.begin(), state.events.end());
            chain.uniqueTargets = state.targets.size();
            chain.uniqueProtocols = state.protocols.size();
            chain.firstSeen = state.events.front().timestamp;
            chain.lastSeen = state.events.back().timestamp;
            chain.score = std::clamp(
                (static_cast<double>(chain.uniqueTargets) * 0.35) +
                (static_cast<double>(chain.uniqueProtocols) * 0.25) +
                (chain.events.back().confidence * 0.40),
                0.0,
                1.0);

            PushBounded(m_chains, chain);
            m_stats.chainCount = static_cast<uint64_t>(m_chains.size());
            PersistChainLocked(chain);
        }
    }

    static void RebuildChainIndexes(ChainState& state) {
        state.targets.clear();
        state.protocols.clear();
        for (const auto& event : state.events) {
            state.targets.insert(event.targetHost);
            state.protocols.insert(event.protocol);
        }
    }

    void PersistEventLocked(const LateralMovementEvent& event) {
        std::string techniques;
        for (size_t i = 0; i < event.techniques.size(); ++i) {
            if (i != 0) {
                techniques += ',';
            }
            techniques += event.techniques[i];
        }

        DatabaseError err;
        const bool ok = DatabaseManager::Instance().ExecuteWithParams(
            "INSERT INTO xdr_lateral_events("
            "source_host, target_host, protocol, credential_type, process_id, process_name, confidence, techniques, observed_at"
            ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
            &err,
            event.sourceHost,
            event.targetHost,
            static_cast<int>(event.protocol),
            event.credentialType,
            static_cast<int>(event.processId),
            Narrow(event.processName),
            event.confidence,
            techniques,
            ToIso8601(event.timestamp));
        if (!ok) {
            LogDatabaseError("PersistEvent", err);
            ++m_stats.errors;
        }
    }

    void PersistChainLocked(const LateralMovementChain& chain) {
        DatabaseError err;
        const bool ok = DatabaseManager::Instance().ExecuteWithParams(
            "INSERT INTO xdr_lateral_chains(source_host, score, unique_targets, unique_protocols, first_seen, last_seen) "
            "VALUES(?, ?, ?, ?, ?, ?)",
            &err,
            chain.sourceHost,
            chain.score,
            static_cast<int>(chain.uniqueTargets),
            static_cast<int>(chain.uniqueProtocols),
            ToIso8601(chain.firstSeen),
            ToIso8601(chain.lastSeen));
        if (!ok) {
            LogDatabaseError("PersistChain", err);
            ++m_stats.errors;
        }
    }

    mutable std::shared_mutex m_mutex;
    bool m_initialized = false;
    std::string m_localHostname;
    LateralMovementStatistics m_stats{};
    std::vector<LateralMovementEvent> m_detections;
    std::vector<LateralMovementChain> m_chains;
    std::unordered_map<std::string, ChainState> m_chainState;
};

LateralMovementDetector::LateralMovementDetector() : m_impl(std::make_unique<LateralMovementDetectorImpl>()) {}
LateralMovementDetector::~LateralMovementDetector() = default;

bool LateralMovementDetector::Initialize() { return m_impl->Initialize(); }
void LateralMovementDetector::Shutdown() { m_impl->Shutdown(); }
std::optional<LateralMovementEvent> LateralMovementDetector::AnalyzeConnection(const NetworkConnection& connection) {
    return m_impl->AnalyzeConnection(connection);
}
std::vector<LateralMovementEvent> LateralMovementDetector::GetDetections(size_t limit) const { return m_impl->GetDetections(limit); }
std::vector<LateralMovementChain> LateralMovementDetector::GetLateralChains(size_t limit) const { return m_impl->GetLateralChains(limit); }
LateralMovementStatistics LateralMovementDetector::GetStatistics() const { return m_impl->GetStatistics(); }

} // namespace ShadowStrike::Products::PhantomXDR::NetworkDetection
