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
#include "NetworkSensor.hpp"

#include <format>
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include "BeaconDetector.hpp"
#include "DNSAnalyzer.hpp"
#include "LateralMovementDetector.hpp"
#include "TLSInspector.hpp"

#include <algorithm>
#include <array>
#include <deque>
#include <unordered_map>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace ShadowStrike::Products::PhantomXDR::NetworkDetection {

namespace SU = ShadowStrike::Utils::StringUtils;
using ShadowStrike::Database::DatabaseError;
using ShadowStrike::Database::DatabaseManager;

namespace {

constexpr std::wstring_view kLogCategory = L"PhantomXDR.Network.Sensor";
constexpr size_t kMaxProcessCache = 2048;

struct ScopedHandle final {
    explicit ScopedHandle(HANDLE handle = nullptr) noexcept : m_handle(handle) {}
    ~ScopedHandle() {
        if (m_handle != nullptr && m_handle != INVALID_HANDLE_VALUE) {
            ::CloseHandle(m_handle);
        }
    }

    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;

    [[nodiscard]] HANDLE get() const noexcept { return m_handle; }

private:
    HANDLE m_handle;
};

struct TrackedConnection {
    NetworkConnection connection;
    SystemTimePoint firstSeen{};
    SystemTimePoint lastSeen{};
    bool longLivedEmitted = false;
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

[[nodiscard]] std::string Ipv4ToString(DWORD address) {
    IN_ADDR addr{};
    addr.S_un.S_addr = address;
    char buffer[INET_ADDRSTRLEN]{};
    if (::InetNtopA(AF_INET, &addr, buffer, static_cast<DWORD>(std::size(buffer))) == nullptr) {
        return {};
    }
    return std::string(buffer);
}

[[nodiscard]] std::string Ipv6ToString(const UCHAR address[16]) {
    IN6_ADDR addr{};
    std::memcpy(&addr, address, sizeof(addr));
    char buffer[INET6_ADDRSTRLEN]{};
    if (::InetNtopA(AF_INET6, &addr, buffer, static_cast<DWORD>(std::size(buffer))) == nullptr) {
        return {};
    }
    return std::string(buffer);
}

[[nodiscard]] NetworkProtocol GuessProtocol(uint16_t localPort, uint16_t remotePort, bool isUdp) {
    const uint16_t observedPort = remotePort != 0 ? remotePort : localPort;
    switch (observedPort) {
    case 53:
        return NetworkProtocol::DNS;
    case 80:
    case 8080:
        return NetworkProtocol::HTTP;
    case 443:
    case 8443:
        return NetworkProtocol::HTTPS;
    case 445:
        return NetworkProtocol::SMB;
    case 3389:
        return NetworkProtocol::RDP;
    case 135:
        return NetworkProtocol::WMI;
    case 22:
        return NetworkProtocol::SSH;
    default:
        return isUdp ? NetworkProtocol::UDP : NetworkProtocol::TCP;
    }
}

[[nodiscard]] bool IsLoopback(std::string_view ip) {
    return ip == "127.0.0.1" || ip == "::1";
}

[[nodiscard]] ConnectionDirection DetermineDirection(const NetworkConnection& connection) {
    if (IsLoopback(connection.destinationIp) || IsLoopback(connection.sourceIp) || connection.sourceIp == connection.destinationIp) {
        return ConnectionDirection::Local;
    }

    const bool localPortEphemeral = connection.sourcePort >= 49152;
    const bool remotePortEphemeral = connection.destinationPort >= 49152;
    if (localPortEphemeral && !remotePortEphemeral) {
        return ConnectionDirection::Outbound;
    }
    if (!localPortEphemeral && remotePortEphemeral) {
        return ConnectionDirection::Inbound;
    }
    return ConnectionDirection::Outbound;
}

[[nodiscard]] std::wstring TcpStateToString(DWORD state) {
    switch (state) {
    case MIB_TCP_STATE_CLOSED: return L"CLOSED";
    case MIB_TCP_STATE_LISTEN: return L"LISTEN";
    case MIB_TCP_STATE_SYN_SENT: return L"SYN_SENT";
    case MIB_TCP_STATE_SYN_RCVD: return L"SYN_RCVD";
    case MIB_TCP_STATE_ESTAB: return L"ESTABLISHED";
    case MIB_TCP_STATE_FIN_WAIT1: return L"FIN_WAIT1";
    case MIB_TCP_STATE_FIN_WAIT2: return L"FIN_WAIT2";
    case MIB_TCP_STATE_CLOSE_WAIT: return L"CLOSE_WAIT";
    case MIB_TCP_STATE_CLOSING: return L"CLOSING";
    case MIB_TCP_STATE_LAST_ACK: return L"LAST_ACK";
    case MIB_TCP_STATE_TIME_WAIT: return L"TIME_WAIT";
    case MIB_TCP_STATE_DELETE_TCB: return L"DELETE_TCB";
    default: return L"UNKNOWN";
    }
}

[[nodiscard]] std::string ConnectionKey(const NetworkConnection& connection) {
    return std::format("{}:{}-{}:{}-{}-{}",
        connection.sourceIp,
        connection.sourcePort,
        connection.destinationIp,
        connection.destinationPort,
        static_cast<int>(connection.protocol),
        connection.processId);
}

} // namespace

class NetworkSensorImpl final {
public:
    [[nodiscard]] bool Initialize(const NetworkSensorSettings& settings) {
        std::unique_lock lock(m_mutex);
        if (m_initialized) {
            return true;
        }

        WSADATA wsaData{};
        if (::WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            ++m_stats.errors;
            return false;
        }
        m_wsaReady = true;

        m_settings = settings;
        if (!EnsureSchemaLocked()) {
            ++m_stats.errors;
            return false;
        }

        m_initialized = DNSAnalyzer::Instance().Initialize() &&
                        TLSInspector::Instance().Initialize() &&
                        LateralMovementDetector::Instance().Initialize() &&
                        BeaconDetector::Instance().Initialize();
        return m_initialized;
    }

    void Shutdown() {
        StopCapture();

        std::unique_lock lock(m_mutex);
        m_activeMap.clear();
        m_history.clear();
        m_processNameCache.clear();
        m_initialized = false;
        lock.unlock();

        BeaconDetector::Instance().Shutdown();
        LateralMovementDetector::Instance().Shutdown();
        TLSInspector::Instance().Shutdown();
        DNSAnalyzer::Instance().Shutdown();

        if (m_wsaReady) {
            ::WSACleanup();
            m_wsaReady = false;
        }
    }

    [[nodiscard]] bool StartCapture() {
        std::unique_lock lock(m_mutex);
        if (!m_initialized) {
            ++m_stats.errors;
            return false;
        }

        if (m_running) {
            return true;
        }

        m_running = true;
        m_worker = std::jthread([this](std::stop_token token) { CaptureLoop(token); });
        return true;
    }

    void StopCapture() {
        std::jthread worker;
        {
            std::unique_lock lock(m_mutex);
            if (!m_running) {
                return;
            }
            m_running = false;
            worker = std::move(m_worker);
        }

        if (worker.joinable()) {
            worker.request_stop();
            worker.join();
        }
    }

    [[nodiscard]] std::vector<NetworkConnection> GetActiveConnections() const {
        std::shared_lock lock(m_mutex);
        std::vector<NetworkConnection> result;
        result.reserve(m_activeMap.size());
        for (const auto& [_, tracked] : m_activeMap) {
            result.push_back(tracked.connection);
        }
        return result;
    }

    [[nodiscard]] std::vector<NetworkConnection> GetConnectionHistory(size_t limit) const {
        std::shared_lock lock(m_mutex);
        if (limit >= m_history.size()) {
            return m_history;
        }
        return std::vector<NetworkConnection>(m_history.end() - static_cast<ptrdiff_t>(limit), m_history.end());
    }

    [[nodiscard]] NetworkSensorStatistics GetStatistics() const {
        std::shared_lock lock(m_mutex);
        NetworkSensorStatistics stats = m_stats;
        stats.activeConnections = m_activeMap.size();
        stats.historyEntries = m_history.size();
        return stats;
    }

private:
    [[nodiscard]] bool EnsureSchemaLocked() {
        DatabaseError err;
        const char* sql = R"SQL(
            CREATE TABLE IF NOT EXISTS xdr_network_connections(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT NOT NULL,
                source_port INTEGER NOT NULL,
                destination_ip TEXT NOT NULL,
                destination_port INTEGER NOT NULL,
                protocol INTEGER NOT NULL,
                direction INTEGER NOT NULL,
                process_id INTEGER NOT NULL,
                process_name TEXT NOT NULL,
                state TEXT NOT NULL,
                duration_ms INTEGER NOT NULL,
                event_kind TEXT NOT NULL,
                observed_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_xdr_network_connections_time ON xdr_network_connections(observed_at);
        )SQL";

        const bool ok = DatabaseManager::Instance().Execute(sql, &err);
        if (!ok) {
            LogDatabaseError("EnsureSchema", err);
        }
        return ok;
    }

    void CaptureLoop(std::stop_token token) {
        while (!token.stop_requested()) {
            PollConnections();
            std::this_thread::sleep_for(m_settings.pollingInterval);
        }
    }

    void PollConnections() {
        std::unordered_map<std::string, NetworkConnection> snapshot;
        EnumerateTcp4(snapshot);
        if (m_settings.enumerateIpv6) {
            EnumerateTcp6(snapshot);
        }
        EnumerateUdp4(snapshot);
        if (m_settings.enumerateIpv6) {
            EnumerateUdp6(snapshot);
        }

        std::vector<NetworkConnection> emitted;
        const auto now = std::chrono::system_clock::now();

        {
            std::unique_lock lock(m_mutex);
            ++m_stats.pollingCycles;

            for (auto& [key, connection] : snapshot) {
                auto current = m_activeMap.find(key);
                if (current == m_activeMap.end()) {
                    TrackedConnection tracked;
                    tracked.connection = connection;
                    tracked.connection.isNewConnection = true;
                    tracked.firstSeen = now;
                    tracked.lastSeen = now;
                    m_activeMap.emplace(key, tracked);
                    PushHistoryLocked(tracked.connection);
                    emitted.push_back(tracked.connection);
                    ++m_stats.newConnections;
                    PersistConnectionLocked(tracked.connection, "new");
                    continue;
                }

                current->second.lastSeen = now;
                current->second.connection.timestamp = now;
                current->second.connection.duration =
                    std::chrono::duration_cast<std::chrono::milliseconds>(current->second.lastSeen - current->second.firstSeen);
                current->second.connection.state = connection.state;

                if (!current->second.longLivedEmitted &&
                    current->second.connection.duration >= std::chrono::duration_cast<std::chrono::milliseconds>(m_settings.longLivedThreshold)) {
                    current->second.longLivedEmitted = true;
                    current->second.connection.isLongLived = true;
                    emitted.push_back(current->second.connection);
                    PushHistoryLocked(current->second.connection);
                    ++m_stats.longLivedConnections;
                    PersistConnectionLocked(current->second.connection, "long-lived");
                }
            }

            for (auto it = m_activeMap.begin(); it != m_activeMap.end();) {
                if (snapshot.contains(it->first)) {
                    ++it;
                    continue;
                }

                NetworkConnection closed = it->second.connection;
                closed.timestamp = now;
                closed.duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - it->second.firstSeen);
                closed.isClosedConnection = true;
                emitted.push_back(closed);
                PushHistoryLocked(closed);
                ++m_stats.closedConnections;
                PersistConnectionLocked(closed, "closed");
                it = m_activeMap.erase(it);
            }
        }

        for (const auto& connection : emitted) {
            FeedDetectors(connection);
        }
    }

    void EnumerateTcp4(std::unordered_map<std::string, NetworkConnection>& snapshot) {
        ULONG bufferLength = 0;
        if (::GetExtendedTcpTable(nullptr, &bufferLength, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER) {
            return;
        }

        std::vector<std::byte> buffer(bufferLength);
        if (::GetExtendedTcpTable(buffer.data(), &bufferLength, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
            std::unique_lock lock(m_mutex);
            ++m_stats.errors;
            return;
        }

        const auto* table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buffer.data());
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const auto& row = table->table[i];
            NetworkConnection connection;
            connection.sourceIp = Ipv4ToString(row.dwLocalAddr);
            connection.sourcePort = ntohs(static_cast<u_short>(row.dwLocalPort));
            connection.destinationIp = Ipv4ToString(row.dwRemoteAddr);
            connection.destinationPort = ntohs(static_cast<u_short>(row.dwRemotePort));
            connection.protocol = GuessProtocol(connection.sourcePort, connection.destinationPort, false);
            connection.direction = DetermineDirection(connection);
            connection.processId = row.dwOwningPid;
            connection.processName = ResolveProcessName(row.dwOwningPid);
            connection.timestamp = std::chrono::system_clock::now();
            connection.state = TcpStateToString(row.dwState);
            connection.loopback = IsLoopback(connection.destinationIp);
            snapshot[ConnectionKey(connection)] = std::move(connection);
        }
    }

    void EnumerateTcp6(std::unordered_map<std::string, NetworkConnection>& snapshot) {
        ULONG bufferLength = 0;
        if (::GetExtendedTcpTable(nullptr, &bufferLength, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER) {
            return;
        }

        std::vector<std::byte> buffer(bufferLength);
        if (::GetExtendedTcpTable(buffer.data(), &bufferLength, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
            std::unique_lock lock(m_mutex);
            ++m_stats.errors;
            return;
        }

        const auto* table = reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(buffer.data());
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const auto& row = table->table[i];
            NetworkConnection connection;
            connection.sourceIp = Ipv6ToString(row.ucLocalAddr);
            connection.sourcePort = ntohs(static_cast<u_short>(row.dwLocalPort));
            connection.destinationIp = Ipv6ToString(row.ucRemoteAddr);
            connection.destinationPort = ntohs(static_cast<u_short>(row.dwRemotePort));
            connection.protocol = GuessProtocol(connection.sourcePort, connection.destinationPort, false);
            connection.direction = DetermineDirection(connection);
            connection.processId = row.dwOwningPid;
            connection.processName = ResolveProcessName(row.dwOwningPid);
            connection.timestamp = std::chrono::system_clock::now();
            connection.state = TcpStateToString(row.dwState);
            connection.loopback = IsLoopback(connection.destinationIp);
            snapshot[ConnectionKey(connection)] = std::move(connection);
        }
    }

    void EnumerateUdp4(std::unordered_map<std::string, NetworkConnection>& snapshot) {
        ULONG bufferLength = 0;
        if (::GetExtendedUdpTable(nullptr, &bufferLength, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) != ERROR_INSUFFICIENT_BUFFER) {
            return;
        }

        std::vector<std::byte> buffer(bufferLength);
        if (::GetExtendedUdpTable(buffer.data(), &bufferLength, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) != NO_ERROR) {
            std::unique_lock lock(m_mutex);
            ++m_stats.errors;
            return;
        }

        const auto* table = reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(buffer.data());
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const auto& row = table->table[i];
            NetworkConnection connection;
            connection.sourceIp = Ipv4ToString(row.dwLocalAddr);
            connection.sourcePort = ntohs(static_cast<u_short>(row.dwLocalPort));
            connection.destinationIp.clear();
            connection.destinationPort = 0;
            connection.protocol = GuessProtocol(connection.sourcePort, 0, true);
            connection.direction = ConnectionDirection::Local;
            connection.processId = row.dwOwningPid;
            connection.processName = ResolveProcessName(row.dwOwningPid);
            connection.timestamp = std::chrono::system_clock::now();
            connection.state = L"UDP";
            snapshot[ConnectionKey(connection)] = std::move(connection);
        }
    }

    void EnumerateUdp6(std::unordered_map<std::string, NetworkConnection>& snapshot) {
        ULONG bufferLength = 0;
        if (::GetExtendedUdpTable(nullptr, &bufferLength, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0) != ERROR_INSUFFICIENT_BUFFER) {
            return;
        }

        std::vector<std::byte> buffer(bufferLength);
        if (::GetExtendedUdpTable(buffer.data(), &bufferLength, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0) != NO_ERROR) {
            std::unique_lock lock(m_mutex);
            ++m_stats.errors;
            return;
        }

        const auto* table = reinterpret_cast<const MIB_UDP6TABLE_OWNER_PID*>(buffer.data());
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const auto& row = table->table[i];
            NetworkConnection connection;
            connection.sourceIp = Ipv6ToString(row.ucLocalAddr);
            connection.sourcePort = ntohs(static_cast<u_short>(row.dwLocalPort));
            connection.destinationIp.clear();
            connection.destinationPort = 0;
            connection.protocol = GuessProtocol(connection.sourcePort, 0, true);
            connection.direction = ConnectionDirection::Local;
            connection.processId = row.dwOwningPid;
            connection.processName = ResolveProcessName(row.dwOwningPid);
            connection.timestamp = std::chrono::system_clock::now();
            connection.state = L"UDP";
            snapshot[ConnectionKey(connection)] = std::move(connection);
        }
    }

    [[nodiscard]] std::wstring ResolveProcessName(uint32_t pid) {
        if (pid == 0) {
            return L"System";
        }

        {
            std::shared_lock lock(m_mutex);
            const auto it = m_processNameCache.find(pid);
            if (it != m_processNameCache.end()) {
                return it->second;
            }
        }

        std::wstring result = L"<unknown>";
        ScopedHandle handle(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        if (handle.get() != nullptr) {
            std::array<wchar_t, MAX_PATH> path{};
            DWORD size = static_cast<DWORD>(path.size());
            if (::QueryFullProcessImageNameW(handle.get(), 0, path.data(), &size) != 0) {
                std::wstring_view fullPath(path.data(), size);
                const size_t lastSlash = fullPath.find_last_of(L"\\/");
                result = lastSlash == std::wstring_view::npos
                    ? std::wstring(fullPath)
                    : std::wstring(fullPath.substr(lastSlash + 1));
            }
        }

        std::unique_lock lock(m_mutex);
        if (m_processNameCache.size() >= kMaxProcessCache) {
            m_processNameCache.erase(m_processNameCache.begin());
        }
        m_processNameCache[pid] = result;
        return result;
    }

    void PushHistoryLocked(const NetworkConnection& connection) {
        m_history.push_back(connection);
        if (m_history.size() > m_settings.maxHistoryEntries) {
            m_history.erase(m_history.begin(), m_history.begin() + static_cast<ptrdiff_t>(m_history.size() - m_settings.maxHistoryEntries));
        }
    }

    void PersistConnectionLocked(const NetworkConnection& connection, std::string_view eventKind) {
        DatabaseError err;
        const bool ok = DatabaseManager::Instance().ExecuteWithParams(
            "INSERT INTO xdr_network_connections("
            "source_ip, source_port, destination_ip, destination_port, protocol, direction, process_id, process_name, state, duration_ms, event_kind, observed_at"
            ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            &err,
            connection.sourceIp,
            static_cast<int>(connection.sourcePort),
            connection.destinationIp,
            static_cast<int>(connection.destinationPort),
            static_cast<int>(connection.protocol),
            static_cast<int>(connection.direction),
            static_cast<int>(connection.processId),
            Narrow(connection.processName),
            Narrow(connection.state),
            static_cast<int64_t>(connection.duration.count()),
            std::string(eventKind),
            ToIso8601(connection.timestamp));
        if (!ok) {
            LogDatabaseError("PersistConnection", err);
            ++m_stats.errors;
        }
    }

    void FeedDetectors(const NetworkConnection& connection) {
        BeaconDetector::Instance().RecordConnection(connection);
        [[maybe_unused]] const auto lateralEvent = LateralMovementDetector::Instance().AnalyzeConnection(connection);

        if (connection.protocol == NetworkProtocol::HTTPS) {
            TLSSession session;
            session.sourceIp = connection.sourceIp;
            session.sourcePort = connection.sourcePort;
            session.destinationIp = connection.destinationIp;
            session.destinationPort = connection.destinationPort;
            session.processId = connection.processId;
            session.processName = connection.processName;
            session.timestamp = connection.timestamp;
            session.serverName = connection.destinationIp;
            [[maybe_unused]] const auto inspectedSession = TLSInspector::Instance().InspectSession(session);
        }

        if (connection.protocol == NetworkProtocol::DNS && !connection.destinationIp.empty()) {
            DNSQuery query;
            query.queryName = connection.destinationIp;
            query.type = 1;
            query.timestamp = connection.timestamp;
            query.processId = connection.processId;
            query.processName = connection.processName;
            [[maybe_unused]] const auto analyzedQuery = DNSAnalyzer::Instance().AnalyzeQuery(query);
        }
    }

    mutable std::shared_mutex m_mutex;
    bool m_initialized = false;
    bool m_running = false;
    bool m_wsaReady = false;
    NetworkSensorSettings m_settings{};
    NetworkSensorStatistics m_stats{};
    std::jthread m_worker;
    std::unordered_map<std::string, TrackedConnection> m_activeMap;
    std::vector<NetworkConnection> m_history;
    std::unordered_map<uint32_t, std::wstring> m_processNameCache;
};

NetworkSensor::NetworkSensor() : m_impl(std::make_unique<NetworkSensorImpl>()) {}
NetworkSensor::~NetworkSensor() = default;

bool NetworkSensor::Initialize(const NetworkSensorSettings& settings) { return m_impl->Initialize(settings); }
void NetworkSensor::Shutdown() { m_impl->Shutdown(); }
bool NetworkSensor::StartCapture() { return m_impl->StartCapture(); }
void NetworkSensor::StopCapture() { m_impl->StopCapture(); }
std::vector<NetworkConnection> NetworkSensor::GetActiveConnections() const { return m_impl->GetActiveConnections(); }
std::vector<NetworkConnection> NetworkSensor::GetConnectionHistory(size_t limit) const { return m_impl->GetConnectionHistory(limit); }
NetworkSensorStatistics NetworkSensor::GetStatistics() const { return m_impl->GetStatistics(); }

} // namespace ShadowStrike::Products::PhantomXDR::NetworkDetection
