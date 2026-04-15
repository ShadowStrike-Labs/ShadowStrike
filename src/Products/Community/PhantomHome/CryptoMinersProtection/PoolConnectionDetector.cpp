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
/**
 * ============================================================================
 * ShadowStrike CryptoMiner Protection - POOL CONNECTION DETECTOR IMPLEMENTATION
 * ============================================================================
 *
 * This implementation intentionally performs bounded, snapshot-based connection
 * analysis and explicit cleartext Stratum parsing. It does not pretend to do
 * DPI on encrypted traffic it cannot see.
 */

#include "pch.h"
#include "PoolConnectionDetector.hpp"

#include "../../../../PhantomCore/Utils/FileUtils.hpp"
#include "../../../../PhantomCore/Utils/Logger.hpp"
#include "../../../../PhantomCore/Utils/StringUtils.hpp"
#include "../../../../PhantomCore/ThreatIntel/ThreatIntelManager.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <deque>
#include <format>
#include <fstream>
#include <iphlpapi.h>
#include <limits>
#include <nlohmann/json.hpp>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <unordered_set>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>

namespace ShadowStrike::CryptoMiners {

using SystemClock = std::chrono::system_clock;
using Json = nlohmann::json;

namespace PoolSignatures {

static const std::array<std::string_view, 80> KNOWN_POOL_HOSTNAMES = {
    "pool.supportxmr.com", "xmr.nanopool.org", "pool.minexmr.com",
    "xmr-eu1.nanopool.org", "xmr-us1.nanopool.org", "xmr-asia1.nanopool.org",
    "monerohash.com", "xmrpool.eu", "monero.crypto-pool.fr",
    "stratum.slushpool.com", "btc.ss.poolin.com", "btc.viabtc.com",
    "stratum.antpool.com", "ss.btc.com", "stratum.f2pool.com",
    "eth.nanopool.org", "eth-eu1.nanopool.org", "eth-us-east1.nanopool.org",
    "eth-asia1.nanopool.org", "eu1.ethermine.org", "us1.ethermine.org",
    "asia1.ethermine.org", "eth.2miners.com", "eth.f2pool.com",
    "rvn.2miners.com", "ravencoin.2miners.com", "rvn.minermore.com",
    "zec.nanopool.org", "zec-eu1.nanopool.org", "zec.2miners.com",
    "zec.flypool.org", "zec.slushpool.com", "ltc.antpool.com",
    "ltc.f2pool.com", "ltc.viabtc.com", "etc.ethermine.org",
    "etc.2miners.com", "etc.nanopool.org", "ergo.2miners.com",
    "ergo.herominers.com", "pool.hashvault.pro", "mining-pool.eu",
    "yiimp.eu", "pool.mn", "mine.zpool.ca", "prohashing.com",
    "stratum.nicehash.com", "stratum.eu.nicehash.com", "stratum.usa.nicehash.com",
    "stratum.hk.nicehash.com", "stratum.jp.nicehash.com", "stratum.in.nicehash.com",
    "pool.btc.com", "ss.antpool.com", "stratum-btc.antpool.com",
    "stratum-eth.antpool.com", "pool.bw.com", "miningpoolhub.com",
    "multipool.us", "hub.miningpoolhub.com", "pool.electroneum.com",
    "pool.cortexminer.com", "pool.woolypooly.com"
};

static const std::array<std::string_view, 50> MALICIOUS_POOL_HOSTNAMES = {
    "monerohash.com", "moneroocean.stream", "xmr.pool.minergate.com",
    "pool.minexmr.com", "mine.moneropool.com", "xmr.crypto-pool.fr",
    "pooldd.com", "pool.supportxmr.com", "xmrpool.eu",
    "coinhive.com", "coin-hive.com", "authedmine.com",
    "crypto-loot.com", "webminepool.com", "jsecoin.com",
    "coinblind.com", "coin-have.com", "kisshentai.net",
    "monerominer.rocks", "ppoi.org", "minero.cc",
    "privatepool.io", "darkpool.to", "anonymouspool.com",
    "hiddenpool.net", "secretmine.com", "stealthpool.org",
    "miningproxy.org", "proxypool.io", "cryptoproxy.net",
    "onionpool.com", "torpool.org", "darknetmine.com",
    "monero.herominers.com", "xmr.nanopool.org", "gulf.moneroocean.stream",
    "pool.hashvault.pro", "fastpool.xyz", "cryptonight.net",
    "mine.c3pool.com", "xmr-eu.dwarfpool.com", "xmr.suprnova.cc"
};

static const std::array<std::string_view, 20> STRATUM_METHODS = {
    "mining.subscribe", "mining.authorize", "mining.submit",
    "mining.notify", "mining.set_difficulty", "mining.set_extranonce",
    "client.reconnect", "client.get_version", "client.show_message",
    "eth_submitwork", "eth_submithashrate", "eth_getwork",
    "eth_submitlogin", "login", "getjob", "submit",
    "keepalived", "job", "result", "error"
};

static const std::array<std::string_view, 15> STRATUM_PATTERNS = {
    R"({"id":)", R"({"method":"mining.)", R"({"method":"eth_)",
    R"("mining.subscribe")", R"("mining.authorize")", R"("mining.submit")",
    R"("mining.notify")", R"("eth_submitwork")", R"("eth_getwork")",
    R"("jsonrpc":"2.0")", R"("stratum")", R"("extranonce")",
    R"("difficulty")", R"("target")", R"("job_id")"
};

struct WalletPattern {
    MinedCryptocurrency crypto;
    std::string_view pattern;
};

static const std::array<WalletPattern, 8> WALLET_PATTERNS = {{
    {MinedCryptocurrency::Bitcoin, R"(^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|^bc1[a-z0-9]{39,59}$)"},
    {MinedCryptocurrency::Ethereum, R"(^0x[a-fA-F0-9]{40}$)"},
    {MinedCryptocurrency::Monero, R"(^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$|^8[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$)"},
    {MinedCryptocurrency::Litecoin, R"(^[LM][a-km-zA-HJ-NP-Z1-9]{26,33}$)"},
    {MinedCryptocurrency::Zcash, R"(^t1[a-zA-Z0-9]{33}$|^t3[a-zA-Z0-9]{33}$)"},
    {MinedCryptocurrency::Ravencoin, R"(^R[a-km-zA-HJ-NP-Z1-9]{33}$)"},
    {MinedCryptocurrency::EthClassic, R"(^0x[a-fA-F0-9]{40}$)"},
    {MinedCryptocurrency::Ergo, R"(^9[a-zA-Z0-9]{50,}$)"}
}};

static const std::array<std::string_view, 12> PROXY_KEYWORDS = {
    "proxy", "relay", "gateway", "forward", "tunnel", "vpn",
    "onion", "tor", "socks", "anon", "stealth", "hidden"
};

static const std::array<std::string_view, 6> DOH_HINTS = {
    "dns-query", "resolve?name=", "application/dns-json",
    "application/dns-message", "doh", "dns.google"
};

}  // namespace PoolSignatures

namespace {

constexpr size_t kMaxJsonMessageBytes = 16 * 1024;
constexpr size_t kMaxWalletCandidateLength = 128;
constexpr size_t kMaxWorkerNameLength = 64;
constexpr size_t kMaxHostnameLength = 255;
constexpr uint16_t kHttpsPort = 443;
constexpr uint16_t kAltHttpsPort = 8443;
constexpr uint16_t kLegacyTlsPoolPort = 14444;

class ScopedHandle final {
public:
    explicit ScopedHandle(HANDLE handle = nullptr) noexcept : m_handle(handle) {}
    ~ScopedHandle() {
        if (m_handle != nullptr && m_handle != INVALID_HANDLE_VALUE) {
            ::CloseHandle(m_handle);
        }
    }

    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;

    ScopedHandle(ScopedHandle&& other) noexcept : m_handle(other.m_handle) {
        other.m_handle = nullptr;
    }

    ScopedHandle& operator=(ScopedHandle&& other) noexcept {
        if (this != &other) {
            if (m_handle != nullptr && m_handle != INVALID_HANDLE_VALUE) {
                ::CloseHandle(m_handle);
            }
            m_handle = other.m_handle;
            other.m_handle = nullptr;
        }
        return *this;
    }

    [[nodiscard]] HANDLE get() const noexcept { return m_handle; }

private:
    HANDLE m_handle;
};

struct ParsedEndpoint {
    std::string original;
    std::string scheme;
    std::string host;
    std::string pathAndQuery;
    uint16_t port = 0;
    bool valid = false;
};

struct EnumeratedConnection {
    uint32_t processId = 0;
    std::wstring processName;
    std::string localIp;
    uint16_t localPort = 0;
    std::string remoteIp;
    uint16_t remotePort = 0;
    ConnectionState state = ConnectionState::Unknown;
    bool encryptedHeuristic = false;
};

[[nodiscard]] std::wstring ToWide(std::string_view value) {
    return Utils::StringUtils::ToWide(value);
}

[[nodiscard]] std::string ToNarrow(std::wstring_view value) {
    return Utils::StringUtils::ToNarrow(value);
}

[[nodiscard]] std::string TrimCopy(std::string_view input) {
    size_t begin = 0;
    while (begin < input.size() && std::isspace(static_cast<unsigned char>(input[begin])) != 0) {
        ++begin;
    }

    size_t end = input.size();
    while (end > begin && std::isspace(static_cast<unsigned char>(input[end - 1])) != 0) {
        --end;
    }

    return std::string(input.substr(begin, end - begin));
}

[[nodiscard]] std::string ToLowerUtf8(std::string_view input) {
    std::wstring wide = Utils::StringUtils::ToWide(input);
    wide = Utils::StringUtils::ToLowerCopy(wide);
    return Utils::StringUtils::ToNarrow(wide);
}

[[nodiscard]] bool IsNumeric(std::string_view value) {
    return !value.empty() && std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return std::isdigit(c) != 0;
    });
}

[[nodiscard]] std::optional<uint16_t> ParsePort(std::string_view value) {
    if (!IsNumeric(value)) {
        return std::nullopt;
    }

    unsigned long parsed = 0;
    try {
        parsed = std::stoul(std::string(value));
    } catch (...) {
        return std::nullopt;
    }

    if (parsed == 0 || parsed > std::numeric_limits<uint16_t>::max()) {
        return std::nullopt;
    }

    return static_cast<uint16_t>(parsed);
}

[[nodiscard]] bool HasDotBoundarySuffix(std::string_view host, std::string_view suffix) {
    if (host == suffix) {
        return true;
    }

    if (host.size() <= suffix.size()) {
        return false;
    }

    return host.ends_with(suffix) && host[host.size() - suffix.size() - 1] == '.';
}

[[nodiscard]] size_t CountMissingEndpointIndicators(
    const std::unordered_set<std::string>& indicators,
    const ParsedEndpoint& parsed)
{
    size_t missing = indicators.contains(parsed.host) ? 0U : 1U;
    if (parsed.port != 0) {
        const std::string hostPort = std::format("{}:{}", parsed.host, parsed.port);
        if (!indicators.contains(hostPort)) {
            ++missing;
        }
    }
    return missing;
}

void InsertEndpointIndicators(std::unordered_set<std::string>& indicators, const ParsedEndpoint& parsed) {
    indicators.insert(parsed.host);
    if (parsed.port != 0) {
        indicators.insert(std::format("{}:{}", parsed.host, parsed.port));
    }
}

[[nodiscard]] bool ContainsKeyword(std::string_view text, const std::array<std::string_view, 12>& keywords) {
    for (const auto keyword : keywords) {
        if (text.find(keyword) != std::string_view::npos) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] bool ContainsKeyword(std::string_view text, const std::array<std::string_view, 6>& keywords) {
    for (const auto keyword : keywords) {
        if (text.find(keyword) != std::string_view::npos) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] bool MatchesPoolHostname(std::string_view host, const auto& list) {
    for (const auto candidate : list) {
        if (HasDotBoundarySuffix(host, candidate)) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] std::optional<std::string> FindMatchingPoolHostname(std::string_view host, const auto& list) {
    for (const auto candidate : list) {
        if (HasDotBoundarySuffix(host, candidate)) {
            return std::string(candidate);
        }
    }
    return std::nullopt;
}

[[nodiscard]] bool IsLikelyTextPayload(std::span<const uint8_t> payload) {
    if (payload.empty()) {
        return false;
    }

    size_t printable = 0;
    size_t nulCount = 0;
    for (uint8_t byte : payload) {
        if (byte == 0) {
            ++nulCount;
            continue;
        }
        if (std::isprint(byte) != 0 || std::isspace(byte) != 0) {
            ++printable;
        }
    }

    if (nulCount > 0) {
        return false;
    }

    return printable * 100 >= payload.size() * 85;
}

[[nodiscard]] std::string SanitizeBoundedText(std::string_view value, size_t maxLength) {
    const size_t boundedLength = std::min(maxLength, value.size());
    std::string sanitized;
    sanitized.reserve(boundedLength);

    for (size_t i = 0; i < boundedLength; ++i) {
        const unsigned char c = static_cast<unsigned char>(value[i]);
        if (std::isprint(c) != 0 || std::isspace(c) != 0) {
            sanitized.push_back(static_cast<char>(c));
        }
    }

    return sanitized;
}

[[nodiscard]] std::string RedactSensitive(std::string_view value) {
    if (value.empty()) {
        return {};
    }

    constexpr size_t visible = 4;
    if (value.size() <= visible * 2) {
        return std::string(value.size(), '*');
    }

    return std::format("{}***{}", value.substr(0, visible), value.substr(value.size() - visible));
}

[[nodiscard]] std::string BuildConnectionKey(uint32_t processId,
    std::string_view localIp,
    uint16_t localPort,
    std::string_view remoteIp,
    uint16_t remotePort,
    PoolProtocolType protocol)
{
    return std::format("{}|{}|{}|{}|{}|{}",
        processId,
        localIp,
        localPort,
        remoteIp,
        remotePort,
        static_cast<unsigned>(protocol));
}

[[nodiscard]] bool IsKnownEncryptedPoolPort(uint16_t port) noexcept {
    return port == kHttpsPort || port == kAltHttpsPort || port == kLegacyTlsPoolPort;
}

[[nodiscard]] bool IsPrivateOrReservedIPv4(uint32_t addressNetworkOrder) noexcept {
    const uint32_t hostOrder = ntohl(addressNetworkOrder);
    const uint8_t a = static_cast<uint8_t>((hostOrder >> 24) & 0xFF);
    const uint8_t b = static_cast<uint8_t>((hostOrder >> 16) & 0xFF);

    if (a == 0 || a == 10 || a == 127) {
        return true;
    }
    if (a == 169 && b == 254) {
        return true;
    }
    if (a == 172 && b >= 16 && b <= 31) {
        return true;
    }
    if (a == 192 && b == 168) {
        return true;
    }
    if (a >= 224) {
        return true;
    }
    if (a == 100 && b >= 64 && b <= 127) {
        return true;
    }
    if (a == 198 && (b == 18 || b == 19)) {
        return true;
    }

    return false;
}

[[nodiscard]] bool IsPrivateOrReservedIPv6(const IN6_ADDR& address) noexcept {
    if (IN6_IS_ADDR_LOOPBACK(&address) || IN6_IS_ADDR_LINKLOCAL(&address) || IN6_IS_ADDR_MULTICAST(&address)) {
        return true;
    }

    return (address.u.Byte[0] & 0xFEU) == 0xFCU;
}

[[nodiscard]] bool IsRoutablePublicIp(std::string_view ip) {
    IN_ADDR ipv4{};
    if (::InetPtonA(AF_INET, std::string(ip).c_str(), &ipv4) == 1) {
        return !IsPrivateOrReservedIPv4(ipv4.S_un.S_addr);
    }

    IN6_ADDR ipv6{};
    if (::InetPtonA(AF_INET6, std::string(ip).c_str(), &ipv6) == 1) {
        return !IsPrivateOrReservedIPv6(ipv6);
    }

    return false;
}

[[nodiscard]] bool IsIpLiteral(std::string_view value) {
    IN_ADDR ipv4{};
    if (::InetPtonA(AF_INET, std::string(value).c_str(), &ipv4) == 1) {
        return true;
    }

    IN6_ADDR ipv6{};
    return ::InetPtonA(AF_INET6, std::string(value).c_str(), &ipv6) == 1;
}

[[nodiscard]] std::string IpV4ToString(DWORD addressNetworkOrder) {
    IN_ADDR address{};
    address.S_un.S_addr = addressNetworkOrder;

    char buffer[INET_ADDRSTRLEN] = {};
    if (::InetNtopA(AF_INET, &address, buffer, static_cast<DWORD>(std::size(buffer))) == nullptr) {
        return {};
    }

    return buffer;
}

[[nodiscard]] std::string IpV6ToString(const UCHAR bytes[16]) {
    IN6_ADDR address{};
    std::copy_n(bytes, 16, address.u.Byte);

    char buffer[INET6_ADDRSTRLEN] = {};
    if (::InetNtopA(AF_INET6, &address, buffer, static_cast<DWORD>(std::size(buffer))) == nullptr) {
        return {};
    }

    return buffer;
}

[[nodiscard]] std::wstring GetProcessImageName(uint32_t processId) {
    ScopedHandle process(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId));
    if (process.get() == nullptr) {
        return {};
    }

    std::wstring buffer(32768, L'\0');
    DWORD size = static_cast<DWORD>(buffer.size());
    if (!::QueryFullProcessImageNameW(process.get(), 0, buffer.data(), &size)) {
        return {};
    }

    buffer.resize(size);
    return buffer;
}

[[nodiscard]] ConnectionState MapTcpState(DWORD state) noexcept {
    switch (state) {
        case MIB_TCP_STATE_SYN_SENT:
        case MIB_TCP_STATE_SYN_RCVD:
            return ConnectionState::Connecting;
        case MIB_TCP_STATE_ESTAB:
            return ConnectionState::Connected;
        case MIB_TCP_STATE_CLOSE_WAIT:
        case MIB_TCP_STATE_FIN_WAIT1:
        case MIB_TCP_STATE_FIN_WAIT2:
        case MIB_TCP_STATE_LAST_ACK:
        case MIB_TCP_STATE_CLOSING:
        case MIB_TCP_STATE_TIME_WAIT:
            return ConnectionState::Disconnected;
        default:
            return ConnectionState::Unknown;
    }
}

[[nodiscard]] bool IsInspectableTcpState(DWORD state) noexcept {
    return state == MIB_TCP_STATE_ESTAB || state == MIB_TCP_STATE_SYN_SENT || state == MIB_TCP_STATE_SYN_RCVD;
}

[[nodiscard]] std::vector<EnumeratedConnection> EnumerateTcpConnections(std::optional<uint32_t> processIdFilter) {
    std::vector<EnumeratedConnection> results;

    auto appendRows = [&](ULONG family) {
        DWORD bufferSize = 0;
        const DWORD query = ::GetExtendedTcpTable(nullptr,
            &bufferSize,
            FALSE,
            family,
            TCP_TABLE_OWNER_PID_ALL,
            0);

        if (query != ERROR_INSUFFICIENT_BUFFER || bufferSize == 0) {
            return;
        }

        std::vector<std::byte> buffer(bufferSize);
        if (::GetExtendedTcpTable(buffer.data(),
            &bufferSize,
            FALSE,
            family,
            TCP_TABLE_OWNER_PID_ALL,
            0) != NO_ERROR) {
            return;
        }

        if (family == AF_INET) {
            auto* table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buffer.data());
            for (DWORD index = 0; index < table->dwNumEntries; ++index) {
                const auto& row = table->table[index];
                if (processIdFilter.has_value() && row.dwOwningPid != processIdFilter.value()) {
                    continue;
                }
                if (!IsInspectableTcpState(row.dwState)) {
                    continue;
                }

                const uint16_t remotePort = ntohs(static_cast<u_short>(row.dwRemotePort));
                if (remotePort == 0) {
                    continue;
                }

                EnumeratedConnection connection;
                connection.processId = row.dwOwningPid;
                connection.localIp = IpV4ToString(row.dwLocalAddr);
                connection.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
                connection.remoteIp = IpV4ToString(row.dwRemoteAddr);
                connection.remotePort = remotePort;
                connection.state = MapTcpState(row.dwState);
                connection.encryptedHeuristic = IsKnownEncryptedPoolPort(connection.remotePort);
                connection.processName = GetProcessImageName(connection.processId);

                if (!connection.remoteIp.empty()) {
                    results.push_back(std::move(connection));
                }
            }
            return;
        }

        auto* table = reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(buffer.data());
        for (DWORD index = 0; index < table->dwNumEntries; ++index) {
            const auto& row = table->table[index];
            if (processIdFilter.has_value() && row.dwOwningPid != processIdFilter.value()) {
                continue;
            }
            if (!IsInspectableTcpState(row.dwState)) {
                continue;
            }

            const uint16_t remotePort = ntohs(static_cast<u_short>(row.dwRemotePort));
            if (remotePort == 0) {
                continue;
            }

            EnumeratedConnection connection;
            connection.processId = row.dwOwningPid;
            connection.localIp = IpV6ToString(row.ucLocalAddr);
            connection.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
            connection.remoteIp = IpV6ToString(row.ucRemoteAddr);
            connection.remotePort = remotePort;
            connection.state = MapTcpState(row.dwState);
            connection.encryptedHeuristic = IsKnownEncryptedPoolPort(connection.remotePort);
            connection.processName = GetProcessImageName(connection.processId);

            if (!connection.remoteIp.empty()) {
                results.push_back(std::move(connection));
            }
        }
    };

    appendRows(AF_INET);
    appendRows(AF_INET6);
    return results;
}

[[nodiscard]] ParsedEndpoint ParseEndpoint(std::string_view input) {
    ParsedEndpoint endpoint;
    endpoint.original = TrimCopy(input);
    if (endpoint.original.empty() || endpoint.original.size() > 4096) {
        return endpoint;
    }

    std::string working = endpoint.original;
    const auto schemePos = working.find("://");
    if (schemePos != std::string::npos) {
        endpoint.scheme = ToLowerUtf8(working.substr(0, schemePos));
        working.erase(0, schemePos + 3);
    }

    const auto atPos = working.rfind('@');
    if (atPos != std::string::npos) {
        working.erase(0, atPos + 1);
    }

    const auto pathPos = working.find_first_of("/?#");
    std::string hostPort = pathPos == std::string::npos ? working : working.substr(0, pathPos);
    endpoint.pathAndQuery = pathPos == std::string::npos ? std::string{} : working.substr(pathPos);

    if (hostPort.empty()) {
        return endpoint;
    }

    if (hostPort.front() == '[') {
        const auto closing = hostPort.find(']');
        if (closing == std::string::npos) {
            return endpoint;
        }

        endpoint.host = hostPort.substr(1, closing - 1);
        if (closing + 1 < hostPort.size() && hostPort[closing + 1] == ':') {
            const auto parsedPort = ParsePort(hostPort.substr(closing + 2));
            if (!parsedPort.has_value()) {
                return endpoint;
            }
            endpoint.port = parsedPort.value();
        }
    } else {
        const size_t colonCount = static_cast<size_t>(std::count(hostPort.begin(), hostPort.end(), ':'));
        if (colonCount == 1) {
            const auto colonPos = hostPort.rfind(':');
            const auto parsedPort = ParsePort(hostPort.substr(colonPos + 1));
            if (parsedPort.has_value()) {
                endpoint.host = hostPort.substr(0, colonPos);
                endpoint.port = parsedPort.value();
            } else {
                endpoint.host = hostPort;
            }
        } else {
            endpoint.host = hostPort;
        }
    }

    endpoint.host = ToLowerUtf8(TrimCopy(endpoint.host));
    while (!endpoint.host.empty() && endpoint.host.back() == '.') {
        endpoint.host.pop_back();
    }

    endpoint.pathAndQuery = ToLowerUtf8(endpoint.pathAndQuery);
    endpoint.valid = !endpoint.host.empty() && endpoint.host.size() <= kMaxHostnameLength;
    return endpoint;
}

[[nodiscard]] bool IsMonitoredPort(const PoolConnectionDetectorConfiguration& config, uint16_t port) {
    if (IsStratumPort(port)) {
        return true;
    }

    return std::find(config.monitorPorts.begin(), config.monitorPorts.end(), port) != config.monitorPorts.end();
}

[[nodiscard]] const std::vector<std::pair<MinedCryptocurrency, std::regex>>& CompiledWalletPatterns() {
    static const auto patterns = [] {
        std::vector<std::pair<MinedCryptocurrency, std::regex>> compiled;
        compiled.reserve(PoolSignatures::WALLET_PATTERNS.size());
        for (const auto& entry : PoolSignatures::WALLET_PATTERNS) {
            compiled.emplace_back(entry.crypto,
                std::regex(std::string(entry.pattern), std::regex_constants::optimize));
        }
        return compiled;
    }();

    return patterns;
}

[[nodiscard]] std::optional<MinedCryptocurrency> MatchWalletCrypto(std::string_view candidate) {
    if (candidate.empty() || candidate.size() > kMaxWalletCandidateLength) {
        return std::nullopt;
    }

    for (const auto& [crypto, pattern] : CompiledWalletPatterns()) {
        if (std::regex_match(candidate.begin(), candidate.end(), pattern)) {
            return crypto;
        }
    }

    return std::nullopt;
}

[[nodiscard]] std::optional<std::string> ExtractWalletCandidate(std::string_view login) {
    const std::string trimmed = TrimCopy(login);
    if (trimmed.empty() || trimmed.size() > kMaxWalletCandidateLength + kMaxWorkerNameLength + 8) {
        return std::nullopt;
    }

    for (const char separator : {'.', '/', ':', '+'}) {
        const auto pos = trimmed.find(separator);
        const std::string candidate = pos == std::string::npos ? trimmed : trimmed.substr(0, pos);
        if (MatchWalletCrypto(candidate).has_value()) {
            return candidate;
        }
    }

    if (MatchWalletCrypto(trimmed).has_value()) {
        return trimmed;
    }

    return std::nullopt;
}

[[nodiscard]] std::optional<std::string> ExtractWorkerCandidate(std::string_view login) {
    const std::string trimmed = TrimCopy(login);
    if (trimmed.empty()) {
        return std::nullopt;
    }

    for (const char separator : {'.', '/', ':', '+'}) {
        const auto pos = trimmed.find(separator);
        if (pos == std::string::npos || pos + 1 >= trimmed.size()) {
            continue;
        }

        std::string worker = trimmed.substr(pos + 1);
        worker = TrimCopy(worker);
        if (worker.empty() || worker.size() > kMaxWorkerNameLength) {
            return std::nullopt;
        }

        if (!std::all_of(worker.begin(), worker.end(), [](unsigned char c) {
                return std::isalnum(c) != 0 || c == '_' || c == '-' || c == '.';
            })) {
            return std::nullopt;
        }

        return worker;
    }

    return std::nullopt;
}

[[nodiscard]] std::optional<uint64_t> ExtractJsonMessageId(const Json& value) {
    if (value.is_number_unsigned()) {
        return value.get<uint64_t>();
    }
    if (value.is_number_integer()) {
        const auto signedValue = value.get<int64_t>();
        if (signedValue >= 0) {
            return static_cast<uint64_t>(signedValue);
        }
        return std::nullopt;
    }
    if (value.is_string()) {
        const std::string stringValue = value.get<std::string>();
        if (!IsNumeric(stringValue)) {
            return std::nullopt;
        }
        try {
            return std::stoull(stringValue);
        } catch (...) {
            return std::nullopt;
        }
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<std::string> FirstParseableJsonObject(std::string_view payload) {
    const std::string sanitized = SanitizeBoundedText(payload, kMaxJsonMessageBytes);
    if (sanitized.empty()) {
        return std::nullopt;
    }

    auto parsed = Json::parse(sanitized, nullptr, false);
    if (!parsed.is_discarded() && parsed.is_object()) {
        return sanitized;
    }

    std::istringstream stream(sanitized);
    std::string line;
    while (std::getline(stream, line)) {
        line = TrimCopy(line);
        if (line.empty()) {
            continue;
        }
        if (line.size() > kMaxJsonMessageBytes) {
            continue;
        }
        parsed = Json::parse(line, nullptr, false);
        if (!parsed.is_discarded() && parsed.is_object()) {
            return line;
        }
    }

    return std::nullopt;
}

[[nodiscard]] PoolProtocolType DetermineProtocol(const ParsedEndpoint& endpoint, bool encrypted) {
    if (endpoint.scheme == "wss" || endpoint.scheme == "ws") {
        return PoolProtocolType::StratumOverWebSocket;
    }
    if (endpoint.scheme == "stratum+ssl" || endpoint.scheme == "stratum+tls") {
        return PoolProtocolType::StratumOverTls;
    }
    if (endpoint.scheme == "stratum+tcp") {
        return PoolProtocolType::Stratum;
    }
    if (endpoint.host.find("nicehash") != std::string::npos) {
        return PoolProtocolType::NiceHashStratum;
    }
    if (endpoint.host.find("eth") != std::string::npos) {
        return encrypted ? PoolProtocolType::StratumOverTls : PoolProtocolType::EthereumStratum;
    }
    if (encrypted) {
        return PoolProtocolType::StratumOverTls;
    }
    return PoolProtocolType::Stratum;
}

[[nodiscard]] bool LooksDgaLike(std::string_view host) {
    std::istringstream stream{std::string(host)};
    std::string label;
    while (std::getline(stream, label, '.')) {
        if (label.size() < 18) {
            continue;
        }

        size_t digitCount = 0;
        size_t vowelCount = 0;
        for (unsigned char c : label) {
            if (std::isdigit(c) != 0) {
                ++digitCount;
            }
            switch (static_cast<char>(std::tolower(c))) {
                case 'a':
                case 'e':
                case 'i':
                case 'o':
                case 'u':
                    ++vowelCount;
                    break;
                default:
                    break;
            }
        }

        if (digitCount * 4 >= label.size() || vowelCount * 6 <= label.size()) {
            return true;
        }
    }

    return false;
}

[[nodiscard]] bool LooksProxyLike(const ParsedEndpoint& endpoint) {
    return ContainsKeyword(endpoint.host, PoolSignatures::PROXY_KEYWORDS) ||
           ContainsKeyword(endpoint.pathAndQuery, PoolSignatures::PROXY_KEYWORDS) ||
           endpoint.host.ends_with(".onion");
}

[[nodiscard]] bool LooksDoHEvasionLike(const ParsedEndpoint& endpoint) {
    return ContainsKeyword(endpoint.pathAndQuery, PoolSignatures::DOH_HINTS) &&
        (MatchesPoolHostname(endpoint.pathAndQuery, PoolSignatures::KNOWN_POOL_HOSTNAMES) ||
         MatchesPoolHostname(endpoint.pathAndQuery, PoolSignatures::MALICIOUS_POOL_HOSTNAMES) ||
         endpoint.pathAndQuery.find("stratum") != std::string::npos ||
         endpoint.pathAndQuery.find("pool") != std::string::npos);
}

[[nodiscard]] Json ParseJsonNoThrow(std::string_view text) {
    return Json::parse(text, nullptr, false);
}

}  // namespace

class PoolConnectionDetectorImpl {
public:
    mutable std::shared_mutex m_mutex;
    PoolConnectionDetectorConfiguration m_config;
    std::atomic<bool> m_initialized{false};
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    PoolDetectorStatistics m_statistics;

    std::unordered_map<std::string, PoolConnectionInfo> m_activeConnections;
    mutable std::shared_mutex m_connectionsMutex;

    std::deque<PoolDetectionResult> m_recentDetections;
    mutable std::shared_mutex m_detectionsMutex;
    static constexpr size_t MAX_RECENT_DETECTIONS = 1000;

    std::unordered_map<std::string, PoolEndpointInfo> m_knownPools;
    mutable std::shared_mutex m_poolsMutex;

    std::unordered_set<std::string> m_blacklistedPools;
    std::unordered_set<std::string> m_manualBlacklistedPools;
    mutable std::shared_mutex m_blacklistMutex;

    std::unordered_set<std::string> m_whitelistedPools;
    mutable std::shared_mutex m_whitelistMutex;

    std::vector<PoolConnectionCallback> m_connectionCallbacks;
    std::vector<StratumDetectedCallback> m_stratumCallbacks;
    std::vector<ErrorCallback> m_errorCallbacks;
    mutable std::mutex m_callbacksMutex;

    // Use direct singleton access instead of storing a raw pointer — eliminates
    // use-after-free risk if Shutdown() races with GetPoolInfoInternal().
    // ThreatIntelManager is a Meyers' singleton and safe to call at any time.
    static constexpr bool kUseThreatIntelDirectAccess = true;

    [[nodiscard]] bool Initialize(const PoolConnectionDetectorConfiguration& config);
    void Shutdown();

    [[nodiscard]] bool IsStratumTrafficInternal(std::span<const uint8_t> payload);
    [[nodiscard]] std::optional<StratumMessage> ParseStratumMessageInternal(std::span<const uint8_t> payload);
    [[nodiscard]] StratumCommand ParseStratumCommand(const std::string& method) const;

    [[nodiscard]] bool IsPoolEndpointInternal(const std::string& ip, uint16_t port) const;
    [[nodiscard]] bool IsPoolHostnameInternal(const std::string& hostname) const;
    [[nodiscard]] std::optional<PoolEndpointInfo> GetPoolInfoInternal(const std::string& address, uint16_t port) const;

    [[nodiscard]] std::optional<std::string> ExtractWalletAddressInternal(std::span<const uint8_t> payload);
    [[nodiscard]] std::optional<std::string> ExtractWorkerNameInternal(std::span<const uint8_t> payload);
    [[nodiscard]] MinedCryptocurrency DetectCryptocurrency(const std::string& walletAddress) const;
    [[nodiscard]] bool ValidateWalletAddressInternal(std::string_view address, MinedCryptocurrency crypto) const;

    [[nodiscard]] std::vector<PoolConnectionInfo> GetActiveConnectionsInternal();
    [[nodiscard]] std::vector<PoolConnectionInfo> GetProcessConnectionsInternal(uint32_t processId);
    [[nodiscard]] bool TrackConnection(PoolConnectionInfo& conn);
    void RemoveMissingConnections(const std::unordered_set<std::string>& observed, std::optional<uint32_t> processId);
    void AddRecentDetection(const PoolConnectionInfo& conn, double confidence);
    [[nodiscard]] std::vector<PoolConnectionInfo> CollectConnections(std::optional<uint32_t> processId);
    [[nodiscard]] std::optional<PoolConnectionInfo> AnalyzeConnection(const EnumeratedConnection& connection);

    [[nodiscard]] bool BlockPoolAddressInternal(const std::string& address, bool persistManual = true);
    void UnblockPoolAddressInternal(const std::string& address);
    [[nodiscard]] bool IsBlacklistedInternal(const std::string& address) const;
    [[nodiscard]] bool IsWhitelistedInternal(const std::string& address) const;
    void LoadBuiltinBlacklist();
    void LoadBuiltinPools();
    void RefreshBlacklistState(const PoolConnectionDetectorConfiguration& config);
    [[nodiscard]] bool LoadPoolBlacklistInternal(const std::filesystem::path& path);

    void InvokeConnectionCallbacks(const PoolConnectionInfo& conn);
    void InvokeStratumCallbacks(const PoolDetectionResult& result);
    void InvokeErrorCallbacks(const std::string& message, int code);

    [[nodiscard]] std::string GenerateDetectionId() const;
    [[nodiscard]] double CalculateConfidence(bool hasStratum, bool hasWallet, bool hasEndpointIndicator, bool isBlacklisted) const;
};

bool PoolConnectionDetectorImpl::Initialize(const PoolConnectionDetectorConfiguration& config) {
    if (m_initialized.exchange(true, std::memory_order_acq_rel)) {
        return true;
    }

    if (!config.IsValid()) {
        m_initialized.store(false, std::memory_order_release);
        m_status.store(ModuleStatus::Error, std::memory_order_release);
        Utils::Logger::Error("PoolConnectionDetector: rejected invalid configuration");
        return false;
    }

    try {
        {
            std::unique_lock lock(m_mutex);
            m_config = config;
        }

        m_status.store(ModuleStatus::Initializing, std::memory_order_release);
        // ThreatIntel accessed via singleton directly — no raw pointer stored.

        {
            std::unique_lock lock(m_whitelistMutex);
            m_whitelistedPools.clear();
            for (const auto& value : config.whitelistedPools) {
                const ParsedEndpoint parsed = ParseEndpoint(value);
                if (parsed.valid) {
                    m_whitelistedPools.insert(parsed.host);
                    if (parsed.port != 0) {
                        m_whitelistedPools.insert(std::format("{}:{}", parsed.host, parsed.port));
                    }
                }
            }
        }

        LoadBuiltinPools();
        RefreshBlacklistState(config);

        m_statistics.Reset();
        m_status.store(ModuleStatus::Running, std::memory_order_release);
        Utils::Logger::Info("PoolConnectionDetector: initialized with {} known pool indicators",
            m_knownPools.size());
        return true;
    } catch (const std::exception& ex) {
        m_initialized.store(false, std::memory_order_release);
        m_status.store(ModuleStatus::Error, std::memory_order_release);
        Utils::Logger::Error("PoolConnectionDetector: initialization failed - {}", ex.what());
        return false;
    }
}

void PoolConnectionDetectorImpl::Shutdown() {
    if (!m_initialized.exchange(false, std::memory_order_acq_rel)) {
        return;
    }

    m_status.store(ModuleStatus::Stopping, std::memory_order_release);

    {
        std::unique_lock lock(m_connectionsMutex);
        m_activeConnections.clear();
    }
    {
        std::unique_lock lock(m_detectionsMutex);
        m_recentDetections.clear();
    }
    {
        std::unique_lock lock(m_poolsMutex);
        m_knownPools.clear();
    }
    {
        std::unique_lock lock(m_blacklistMutex);
        m_blacklistedPools.clear();
        m_manualBlacklistedPools.clear();
    }
    {
        std::unique_lock lock(m_whitelistMutex);
        m_whitelistedPools.clear();
    }
    {
        std::lock_guard lock(m_callbacksMutex);
        m_connectionCallbacks.clear();
        m_stratumCallbacks.clear();
        m_errorCallbacks.clear();
    }

    // ThreatIntel accessed via singleton — no raw pointer to clear.
    m_status.store(ModuleStatus::Stopped, std::memory_order_release);
}

bool PoolConnectionDetectorImpl::IsStratumTrafficInternal(std::span<const uint8_t> payload) {
    PoolConnectionDetectorConfiguration config;
    {
        std::shared_lock lock(m_mutex);
        config = m_config;
    }

    if (!config.enableStratumDetection || !config.enableDeepPacketInspection) {
        return false;
    }

    if (payload.empty() || payload.size() > PoolDetectorConstants::MAX_PAYLOAD_INSPECT_SIZE || !IsLikelyTextPayload(payload)) {
        return false;
    }

    const std::string sanitized = SanitizeBoundedText(std::string_view(reinterpret_cast<const char*>(payload.data()), payload.size()), kMaxJsonMessageBytes);
    if (sanitized.empty()) {
        return false;
    }

    const std::string lower = ToLowerUtf8(sanitized);
    if (lower.find("stratum+tcp://") != std::string::npos ||
        lower.find("stratum+ssl://") != std::string::npos ||
        lower.find("stratum+tls://") != std::string::npos) {
        return true;
    }

    const auto firstJson = FirstParseableJsonObject(lower);
    if (!firstJson.has_value()) {
        return false;
    }

    const Json json = ParseJsonNoThrow(firstJson.value());
    if (json.is_discarded() || !json.is_object()) {
        return false;
    }

    if (json.contains("method") && json["method"].is_string()) {
        const std::string method = ToLowerUtf8(json["method"].get<std::string>());
        return std::find(PoolSignatures::STRATUM_METHODS.begin(),
            PoolSignatures::STRATUM_METHODS.end(),
            method) != PoolSignatures::STRATUM_METHODS.end();
    }

    for (const auto pattern : PoolSignatures::STRATUM_PATTERNS) {
        if (lower.find(pattern) != std::string::npos) {
            return true;
        }
    }

    return false;
}

std::optional<StratumMessage> PoolConnectionDetectorImpl::ParseStratumMessageInternal(std::span<const uint8_t> payload) {
    PoolConnectionDetectorConfiguration config;
    {
        std::shared_lock lock(m_mutex);
        config = m_config;
    }

    if (!config.enableStratumDetection || !config.enableDeepPacketInspection) {
        return std::nullopt;
    }

    if (payload.empty() || payload.size() > PoolDetectorConstants::MAX_PAYLOAD_INSPECT_SIZE || !IsLikelyTextPayload(payload)) {
        return std::nullopt;
    }

    const auto firstJson = FirstParseableJsonObject(std::string_view(reinterpret_cast<const char*>(payload.data()), payload.size()));
    if (!firstJson.has_value()) {
        return std::nullopt;
    }

    const Json json = ParseJsonNoThrow(firstJson.value());
    if (json.is_discarded() || !json.is_object()) {
        return std::nullopt;
    }

    StratumMessage message;
    message.rawMessage = SanitizeBoundedText(firstJson.value(), kMaxJsonMessageBytes);
    message.timestamp = SystemClock::now();

    if (json.contains("id")) {
        if (const auto id = ExtractJsonMessageId(json["id"]); id.has_value()) {
            message.messageId = id.value();
        }
    }

    if (json.contains("method") && json["method"].is_string()) {
        message.isRequest = true;
        message.method = json["method"].get<std::string>();
        message.command = ParseStratumCommand(ToLowerUtf8(message.method));
        if (json.contains("params")) {
            message.params = SanitizeBoundedText(json["params"].dump(), kMaxJsonMessageBytes);
        }
    } else if (json.contains("result")) {
        message.isRequest = false;
        message.result = SanitizeBoundedText(json["result"].dump(), kMaxJsonMessageBytes);
    }

    if (json.contains("error") && !json["error"].is_null()) {
        message.hasError = true;
        if (json["error"].is_object() && json["error"].contains("message") && json["error"]["message"].is_string()) {
            message.errorMessage = SanitizeBoundedText(json["error"]["message"].get<std::string>(), 256);
        } else {
            message.errorMessage = SanitizeBoundedText(json["error"].dump(), 256);
        }
    }

    return message;
}

StratumCommand PoolConnectionDetectorImpl::ParseStratumCommand(const std::string& method) const {
    if (method == "mining.subscribe") return StratumCommand::Subscribe;
    if (method == "mining.authorize") return StratumCommand::Authorize;
    if (method == "mining.submit") return StratumCommand::Submit;
    if (method == "mining.notify") return StratumCommand::Notify;
    if (method == "mining.set_difficulty") return StratumCommand::SetDifficulty;
    if (method == "mining.set_extranonce") return StratumCommand::SetExtranonce;
    if (method == "client.reconnect") return StratumCommand::Reconnect;
    if (method == "client.get_version") return StratumCommand::GetVersion;
    if (method == "eth_submitwork") return StratumCommand::EthSubmitWork;
    if (method == "eth_submithashrate") return StratumCommand::EthSubmitHashrate;
    if (method == "eth_getwork") return StratumCommand::EthGetWork;
    if (method == "login" || method == "eth_submitlogin") return StratumCommand::Login;
    if (method == "keepalived") return StratumCommand::KeepAlive;
    return StratumCommand::Unknown;
}

bool PoolConnectionDetectorImpl::IsPoolEndpointInternal(const std::string& ip, uint16_t port) const {
    return GetPoolInfoInternal(ip, port).has_value();
}

bool PoolConnectionDetectorImpl::IsPoolHostnameInternal(const std::string& hostname) const {
    return GetPoolInfoInternal(hostname, 0).has_value();
}

std::optional<PoolEndpointInfo> PoolConnectionDetectorImpl::GetPoolInfoInternal(const std::string& address, uint16_t port) const {
    const ParsedEndpoint parsed = ParseEndpoint(address);
    if (!parsed.valid) {
        return std::nullopt;
    }

    PoolConnectionDetectorConfiguration config;
    {
        std::shared_lock lock(m_mutex);
        config = m_config;
    }

    const uint16_t effectivePort = port != 0 ? port : parsed.port;
    const bool isIp = IsIpLiteral(parsed.host);
    if (isIp && !IsRoutablePublicIp(parsed.host) && effectivePort == 0) {
        return std::nullopt;
    }

    if (IsWhitelistedInternal(address) || IsWhitelistedInternal(parsed.host)) {
        return std::nullopt;
    }

    PoolEndpointInfo info;
    info.address = parsed.host;
    info.port = effectivePort;
    info.lastSeen = SystemClock::now();
    info.requiresTLS = IsKnownEncryptedPoolPort(effectivePort) || parsed.scheme == "https" ||
        parsed.scheme == "wss" || parsed.scheme == "stratum+ssl" || parsed.scheme == "stratum+tls";

    bool endpointIndicator = false;
    bool maliciousIndicator = false;

    {
        std::shared_lock lock(m_poolsMutex);
        const auto it = m_knownPools.find(parsed.host);
        if (it != m_knownPools.end()) {
            info = it->second;
            info.port = effectivePort != 0 ? effectivePort : info.port;
            info.lastSeen = SystemClock::now();
            info.requiresTLS = info.requiresTLS || IsKnownEncryptedPoolPort(info.port) || parsed.scheme == "https" ||
                parsed.scheme == "wss" || parsed.scheme == "stratum+ssl" || parsed.scheme == "stratum+tls";
            endpointIndicator = true;
            maliciousIndicator = info.isBlacklisted || info.status == PoolStatus::KnownMalicious;
        }
    }

    if (const auto it = FindMatchingPoolHostname(parsed.host, PoolSignatures::MALICIOUS_POOL_HOSTNAMES); it.has_value()) {
        info.poolName = it.value();
        info.status = PoolStatus::KnownMalicious;
        info.isBlacklisted = true;
        info.threatIntelSource = "builtin-malicious-pool-host";
        maliciousIndicator = true;
        endpointIndicator = true;
    } else if (const auto it = FindMatchingPoolHostname(parsed.host, PoolSignatures::KNOWN_POOL_HOSTNAMES); it.has_value()) {
        info.poolName = it.value();
        info.status = PoolStatus::KnownPublic;
        info.threatIntelSource = "builtin-known-pool-host";
        endpointIndicator = true;
    }

    if (IsBlacklistedInternal(parsed.host) ||
        (effectivePort != 0 && IsBlacklistedInternal(std::format("{}:{}", parsed.host, effectivePort)))) {
        info.isBlacklisted = true;
        info.status = PoolStatus::KnownMalicious;
        info.threatIntelSource = info.threatIntelSource.empty() ? "configured-blacklist" : info.threatIntelSource;
        maliciousIndicator = true;
        endpointIndicator = true;
    }

    if (LooksProxyLike(parsed)) {
        info.status = PoolStatus::Proxy;
        info.threatIntelSource = info.threatIntelSource.empty() ? "proxy-evasion-heuristic" : info.threatIntelSource;
        endpointIndicator = true;
    }

    if (LooksDoHEvasionLike(parsed)) {
        info.status = PoolStatus::Proxy;
        info.requiresTLS = true;
        info.threatIntelSource = info.threatIntelSource.empty() ? "doh-evasion-heuristic" : info.threatIntelSource;
        endpointIndicator = true;
    }

    if (!isIp && LooksDgaLike(parsed.host) && (parsed.host.find("pool") != std::string::npos || IsMonitoredPort(config, effectivePort))) {
        info.status = PoolStatus::Private;
        info.threatIntelSource = info.threatIntelSource.empty() ? "dga-like-pool-domain" : info.threatIntelSource;
        endpointIndicator = true;
    }

    if (effectivePort != 0 && IsMonitoredPort(config, effectivePort) && (!isIp || IsRoutablePublicIp(parsed.host))) {
        if (info.status == PoolStatus::Unknown) {
            info.status = PoolStatus::Private;
        }
        endpointIndicator = true;
    }

    const auto& threatIntel = ThreatIntel::ThreatIntelManager::Instance();
    if (threatIntel.IsInitialized()) {
        auto intel = isIp ? threatIntel.LookupIP(parsed.host) : threatIntel.LookupDomain(parsed.host);
        if (intel.IsKnownGood()) {
            return std::nullopt;
        }
        if (intel.IsMalicious()) {
            info.status = PoolStatus::KnownMalicious;
            info.isBlacklisted = true;
            info.threatIntelSource = "threat-intel";
            maliciousIndicator = true;
            endpointIndicator = true;
        } else if (intel.IsSuspicious()) {
            if (info.status == PoolStatus::Unknown) {
                info.status = PoolStatus::Private;
            }
            if (info.threatIntelSource.empty()) {
                info.threatIntelSource = "threat-intel-suspicious";
            }
            endpointIndicator = true;
        }
    }

    if (!endpointIndicator && !maliciousIndicator) {
        return std::nullopt;
    }

    info.protocols.push_back(DetermineProtocol(parsed, info.requiresTLS));
    if (info.poolName.empty()) {
        info.poolName = parsed.host;
    }

    const auto cryptocurrency = DetectCryptocurrency(parsed.host);
    if (cryptocurrency != MinedCryptocurrency::Unknown) {
        info.cryptocurrencies.push_back(cryptocurrency);
    }

    return info;
}

std::optional<std::string> PoolConnectionDetectorImpl::ExtractWalletAddressInternal(std::span<const uint8_t> payload) {
    PoolConnectionDetectorConfiguration config;
    {
        std::shared_lock lock(m_mutex);
        config = m_config;
    }

    if (!config.extractWalletAddresses || payload.empty() || payload.size() > PoolDetectorConstants::MAX_PAYLOAD_INSPECT_SIZE) {
        return std::nullopt;
    }

    if (!config.enableDeepPacketInspection) {
        return std::nullopt;
    }

    const auto firstJson = FirstParseableJsonObject(std::string_view(reinterpret_cast<const char*>(payload.data()), payload.size()));
    if (firstJson.has_value()) {
        const Json json = ParseJsonNoThrow(firstJson.value());
        if (!json.is_discarded() && json.is_object() && json.contains("params")) {
            const Json& params = json["params"];
            if (params.is_array()) {
                for (const auto& value : params) {
                    if (!value.is_string()) {
                        continue;
                    }
                    if (const auto wallet = ExtractWalletCandidate(value.get<std::string>()); wallet.has_value()) {
                        m_statistics.walletsExtracted.fetch_add(1, std::memory_order_relaxed);
                        return wallet;
                    }
                }
            } else if (params.is_object()) {
                for (const char* key : {"login", "user", "username", "wallet", "address"}) {
                    if (params.contains(key) && params[key].is_string()) {
                        if (const auto wallet = ExtractWalletCandidate(params[key].get<std::string>()); wallet.has_value()) {
                            m_statistics.walletsExtracted.fetch_add(1, std::memory_order_relaxed);
                            return wallet;
                        }
                    }
                }
            }
        }
    }

    const std::string sanitized = SanitizeBoundedText(std::string_view(reinterpret_cast<const char*>(payload.data()), payload.size()), kMaxJsonMessageBytes);
    // Extract wallet-like tokens by scanning for alphanumeric runs, then validate each.
    // This avoids running std::regex_search across the full payload on MSVC (known to be slow).
    size_t pos = 0;
    while (pos < sanitized.size()) {
        // Skip non-alphanumeric characters
        if (!std::isalnum(static_cast<unsigned char>(sanitized[pos]))) {
            ++pos;
            continue;
        }
        // Found start of an alphanumeric token
        const size_t tokenStart = pos;
        while (pos < sanitized.size() && std::isalnum(static_cast<unsigned char>(sanitized[pos]))) {
            ++pos;
        }
        const size_t tokenLen = pos - tokenStart;
        // Wallet addresses are typically 25-128 chars; skip tokens outside this range
        if (tokenLen >= 25 && tokenLen <= kMaxWalletCandidateLength) {
            const std::string_view candidate(sanitized.data() + tokenStart, tokenLen);
            if (MatchWalletCrypto(candidate).has_value()) {
                m_statistics.walletsExtracted.fetch_add(1, std::memory_order_relaxed);
                return std::string(candidate);
            }
        }
    }

    return std::nullopt;
}

std::optional<std::string> PoolConnectionDetectorImpl::ExtractWorkerNameInternal(std::span<const uint8_t> payload) {
    PoolConnectionDetectorConfiguration config;
    {
        std::shared_lock lock(m_mutex);
        config = m_config;
    }

    if (!config.enableDeepPacketInspection) {
        return std::nullopt;
    }

    if (payload.empty() || payload.size() > PoolDetectorConstants::MAX_PAYLOAD_INSPECT_SIZE) {
        return std::nullopt;
    }

    const auto firstJson = FirstParseableJsonObject(std::string_view(reinterpret_cast<const char*>(payload.data()), payload.size()));
    if (!firstJson.has_value()) {
        return std::nullopt;
    }

    const Json json = ParseJsonNoThrow(firstJson.value());
    if (json.is_discarded() || !json.is_object() || !json.contains("params")) {
        return std::nullopt;
    }

    const Json& params = json["params"];
    if (params.is_array()) {
        for (const auto& value : params) {
            if (!value.is_string()) {
                continue;
            }
            if (const auto worker = ExtractWorkerCandidate(value.get<std::string>()); worker.has_value()) {
                return worker;
            }
        }
    } else if (params.is_object()) {
        for (const char* key : {"login", "user", "username", "worker", "rig", "workername"}) {
            if (!params.contains(key) || !params[key].is_string()) {
                continue;
            }
            if (const auto worker = ExtractWorkerCandidate(params[key].get<std::string>()); worker.has_value()) {
                return worker;
            }
            if (std::strcmp(key, "worker") == 0 || std::strcmp(key, "rig") == 0 || std::strcmp(key, "workername") == 0) {
                const std::string worker = TrimCopy(params[key].get<std::string>());
                if (!worker.empty() && worker.size() <= kMaxWorkerNameLength) {
                    return worker;
                }
            }
        }
    }

    return std::nullopt;
}

MinedCryptocurrency PoolConnectionDetectorImpl::DetectCryptocurrency(const std::string& walletAddress) const {
    if (const auto crypto = MatchWalletCrypto(walletAddress); crypto.has_value()) {
        return crypto.value();
    }

    const std::string lower = ToLowerUtf8(walletAddress);
    if (lower.find("xmr") != std::string::npos || lower.find("monero") != std::string::npos) {
        return MinedCryptocurrency::Monero;
    }
    if (lower.find("eth") != std::string::npos || lower.find("ether") != std::string::npos) {
        return MinedCryptocurrency::Ethereum;
    }
    if (lower.find("btc") != std::string::npos || lower.find("bitcoin") != std::string::npos) {
        return MinedCryptocurrency::Bitcoin;
    }
    if (lower.find("zec") != std::string::npos || lower.find("zcash") != std::string::npos) {
        return MinedCryptocurrency::Zcash;
    }
    if (lower.find("rvn") != std::string::npos || lower.find("ravencoin") != std::string::npos) {
        return MinedCryptocurrency::Ravencoin;
    }
    return MinedCryptocurrency::Unknown;
}

bool PoolConnectionDetectorImpl::ValidateWalletAddressInternal(std::string_view address, MinedCryptocurrency crypto) const {
    if (address.empty() || address.size() > kMaxWalletCandidateLength) {
        return false;
    }

    for (const auto& [entryCrypto, pattern] : CompiledWalletPatterns()) {
        if (entryCrypto == crypto && std::regex_match(address.begin(), address.end(), pattern)) {
            return true;
        }
    }

    return false;
}

std::vector<PoolConnectionInfo> PoolConnectionDetectorImpl::GetActiveConnectionsInternal() {
    return CollectConnections(std::nullopt);
}

std::vector<PoolConnectionInfo> PoolConnectionDetectorImpl::GetProcessConnectionsInternal(uint32_t processId) {
    return CollectConnections(processId);
}

bool PoolConnectionDetectorImpl::TrackConnection(PoolConnectionInfo& conn) {
    std::unique_lock lock(m_connectionsMutex);

    auto it = m_activeConnections.find(conn.connectionId);
    if (it != m_activeConnections.end()) {
        conn.connectionTime = it->second.connectionTime;

        bool trackDuration = false;
        {
            std::shared_lock configLock(m_mutex);
            trackDuration = m_config.trackConnectionDuration;
        }
        if (trackDuration) {
            conn.durationSecs = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(SystemClock::now() - conn.connectionTime).count());
        } else {
            conn.durationSecs = 0;
        }

        const bool changed = it->second.state != conn.state ||
            it->second.remoteHostname != conn.remoteHostname ||
            it->second.walletAddress != conn.walletAddress ||
            it->second.workerName != conn.workerName ||
            it->second.protocol != conn.protocol;

        it->second = conn;
        return changed;
    }

    if (m_activeConnections.size() >= PoolDetectorConstants::MAX_TRACKED_CONNECTIONS) {
        auto oldest = m_activeConnections.begin();
        for (auto current = m_activeConnections.begin(); current != m_activeConnections.end(); ++current) {
            if (current->second.connectionTime < oldest->second.connectionTime) {
                oldest = current;
            }
        }
        m_activeConnections.erase(oldest);
    }

    conn.connectionTime = SystemClock::now();
    conn.durationSecs = 0;
    m_activeConnections.emplace(conn.connectionId, conn);
    return true;
}

void PoolConnectionDetectorImpl::RemoveMissingConnections(
    const std::unordered_set<std::string>& observed,
    std::optional<uint32_t> processId)
{
    const auto now = SystemClock::now();
    std::unique_lock lock(m_connectionsMutex);
    for (auto it = m_activeConnections.begin(); it != m_activeConnections.end();) {
        const bool sameProcess = !processId.has_value() || it->second.processId == processId.value();
        const bool expired = now - it->second.poolInfo.lastSeen > std::chrono::seconds(PoolDetectorConstants::CONNECTION_TIMEOUT_SECS);
        if ((sameProcess && !observed.contains(it->first)) || expired) {
            it = m_activeConnections.erase(it);
            continue;
        }
        ++it;
    }
}

void PoolConnectionDetectorImpl::AddRecentDetection(const PoolConnectionInfo& conn, double confidence) {
    PoolDetectionResult result;
    result.detectionId = GenerateDetectionId();
    result.isPoolConnectionDetected = true;
    result.connectionInfo = conn;
    result.isConfirmedMining = confidence >= 70.0 || conn.poolInfo.isBlacklisted;
    result.confidenceScore = confidence;
    result.wasBlocked = false;
    result.detectionTime = SystemClock::now();

    {
        std::unique_lock lock(m_detectionsMutex);
        if (m_recentDetections.size() >= MAX_RECENT_DETECTIONS) {
            m_recentDetections.pop_front();
        }
        m_recentDetections.push_back(result);
    }

}

std::vector<PoolConnectionInfo> PoolConnectionDetectorImpl::CollectConnections(std::optional<uint32_t> processId) {
    const ModuleStatus status = m_status.load(std::memory_order_acquire);
    if (!m_initialized.load(std::memory_order_acquire) || status == ModuleStatus::Stopped || status == ModuleStatus::Stopping || status == ModuleStatus::Paused) {
        return {};
    }

    struct DeferredNotification {
        PoolConnectionInfo connection;
        double confidence = 0.0;
    };

    std::vector<PoolConnectionInfo> results;
    std::vector<DeferredNotification> deferredNotifications;
    std::unordered_set<std::string> observed;

    for (const auto& liveConnection : EnumerateTcpConnections(processId)) {
        m_statistics.connectionsAnalyzed.fetch_add(1, std::memory_order_relaxed);
        auto analyzed = AnalyzeConnection(liveConnection);
        if (!analyzed.has_value()) {
            continue;
        }

        PoolConnectionInfo connection = std::move(analyzed.value());
        observed.insert(connection.connectionId);

        const bool newOrChanged = TrackConnection(connection);
        results.push_back(connection);

        if (!newOrChanged) {
            continue;
        }

        const bool blacklisted = connection.poolInfo.isBlacklisted;
        const bool endpointIndicator = connection.poolInfo.status != PoolStatus::Unknown;
        const double confidence = CalculateConfidence(false,
            !connection.walletAddress.empty(),
            endpointIndicator,
            blacklisted);

        const auto protocolIndex = static_cast<size_t>(connection.protocol);
        if (protocolIndex < m_statistics.byProtocol.size()) {
            m_statistics.byProtocol[protocolIndex].fetch_add(1, std::memory_order_relaxed);
        }
        const auto cryptoIndex = static_cast<size_t>(connection.cryptocurrency);
        if (cryptoIndex < m_statistics.byCrypto.size()) {
            m_statistics.byCrypto[cryptoIndex].fetch_add(1, std::memory_order_relaxed);
        }

        m_statistics.poolConnectionsDetected.fetch_add(1, std::memory_order_relaxed);
        deferredNotifications.push_back({connection, confidence});
    }

    RemoveMissingConnections(observed, processId);

    for (const auto& notification : deferredNotifications) {
        InvokeConnectionCallbacks(notification.connection);
        AddRecentDetection(notification.connection, notification.confidence);
    }

    return results;
}

std::optional<PoolConnectionInfo> PoolConnectionDetectorImpl::AnalyzeConnection(const EnumeratedConnection& connection) {
    if (connection.remoteIp.empty() || connection.remotePort == 0 || !IsRoutablePublicIp(connection.remoteIp)) {
        return std::nullopt;
    }

    auto poolInfo = GetPoolInfoInternal(connection.remoteIp, connection.remotePort);
    PoolConnectionDetectorConfiguration config;
    {
        std::shared_lock lock(m_mutex);
        config = m_config;
    }

    if (!poolInfo.has_value() && !IsMonitoredPort(config, connection.remotePort)) {
        return std::nullopt;
    }

    if (!poolInfo.has_value()) {
        poolInfo = PoolEndpointInfo{};
        poolInfo->address = connection.remoteIp;
        poolInfo->port = connection.remotePort;
        poolInfo->status = PoolStatus::Private;
        poolInfo->lastSeen = SystemClock::now();
        poolInfo->requiresTLS = connection.encryptedHeuristic;
        poolInfo->protocols.push_back(connection.encryptedHeuristic ? PoolProtocolType::StratumOverTls : PoolProtocolType::Stratum);
        poolInfo->poolName = connection.remoteIp;
    }

    PoolConnectionInfo result;
    result.processId = connection.processId;
    result.processName = connection.processName;
    result.localIP = connection.localIp;
    result.localPort = connection.localPort;
    result.remoteIP = connection.remoteIp;
    result.remotePort = connection.remotePort;
    result.remoteHostname.clear();
    result.poolInfo = *poolInfo;
    result.state = connection.state;
    result.protocol = poolInfo->protocols.empty() ?
        (connection.encryptedHeuristic ? PoolProtocolType::StratumOverTls : PoolProtocolType::Stratum) :
        poolInfo->protocols.front();
    result.cryptocurrency = poolInfo->cryptocurrencies.empty() ? MinedCryptocurrency::Unknown : poolInfo->cryptocurrencies.front();
    result.isEncrypted = poolInfo->requiresTLS || connection.encryptedHeuristic;
    result.bytesSent = 0;
    result.bytesReceived = 0;
    result.connectionId = BuildConnectionKey(result.processId,
        result.localIP,
        result.localPort,
        result.remoteIP,
        result.remotePort,
        result.protocol);

    return result;
}

bool PoolConnectionDetectorImpl::BlockPoolAddressInternal(const std::string& address, bool persistManual) {
    const ParsedEndpoint parsed = ParseEndpoint(address);
    if (!parsed.valid) {
        return false;
    }

    std::unique_lock lock(m_blacklistMutex);
    const size_t activeRequired = CountMissingEndpointIndicators(m_blacklistedPools, parsed);
    const size_t manualRequired = persistManual ? CountMissingEndpointIndicators(m_manualBlacklistedPools, parsed) : 0U;
    if (m_blacklistedPools.size() + activeRequired > PoolDetectorConstants::MAX_KNOWN_POOLS ||
        (persistManual && m_manualBlacklistedPools.size() + manualRequired > PoolDetectorConstants::MAX_KNOWN_POOLS)) {
        return false;
    }

    InsertEndpointIndicators(m_blacklistedPools, parsed);
    if (persistManual) {
        InsertEndpointIndicators(m_manualBlacklistedPools, parsed);
    }
    return true;
}

void PoolConnectionDetectorImpl::UnblockPoolAddressInternal(const std::string& address) {
    const ParsedEndpoint parsed = ParseEndpoint(address);
    if (!parsed.valid) {
        return;
    }

    std::unique_lock lock(m_blacklistMutex);
    m_blacklistedPools.erase(parsed.host);
    m_manualBlacklistedPools.erase(parsed.host);
    if (parsed.port != 0) {
        const std::string hostPort = std::format("{}:{}", parsed.host, parsed.port);
        m_blacklistedPools.erase(hostPort);
        m_manualBlacklistedPools.erase(hostPort);
    }
}

bool PoolConnectionDetectorImpl::IsBlacklistedInternal(const std::string& address) const {
    const ParsedEndpoint parsed = ParseEndpoint(address);
    if (!parsed.valid) {
        return false;
    }

    std::shared_lock lock(m_blacklistMutex);
    if (m_blacklistedPools.contains(parsed.host)) {
        return true;
    }
    if (parsed.port != 0 && m_blacklistedPools.contains(std::format("{}:{}", parsed.host, parsed.port))) {
        return true;
    }

    if (!IsIpLiteral(parsed.host)) {
        for (const auto& indicator : m_blacklistedPools) {
            if (indicator.find(':') == std::string::npos && HasDotBoundarySuffix(parsed.host, indicator)) {
                return true;
            }
        }
    }

    return false;
}

bool PoolConnectionDetectorImpl::IsWhitelistedInternal(const std::string& address) const {
    const ParsedEndpoint parsed = ParseEndpoint(address);
    if (!parsed.valid) {
        return false;
    }

    std::shared_lock lock(m_whitelistMutex);
    if (m_whitelistedPools.contains(parsed.host)) {
        return true;
    }
    if (parsed.port != 0 && m_whitelistedPools.contains(std::format("{}:{}", parsed.host, parsed.port))) {
        return true;
    }

    if (!IsIpLiteral(parsed.host)) {
        for (const auto& indicator : m_whitelistedPools) {
            if (indicator.find(':') == std::string::npos && HasDotBoundarySuffix(parsed.host, indicator)) {
                return true;
            }
        }
    }

    return false;
}

void PoolConnectionDetectorImpl::LoadBuiltinBlacklist() {
    std::unique_lock lock(m_blacklistMutex);
    for (const auto pool : PoolSignatures::MALICIOUS_POOL_HOSTNAMES) {
        if (m_blacklistedPools.size() >= PoolDetectorConstants::MAX_KNOWN_POOLS) {
            break;
        }
        m_blacklistedPools.insert(std::string(pool));
    }
}

void PoolConnectionDetectorImpl::LoadBuiltinPools() {
    std::unique_lock lock(m_poolsMutex);
    m_knownPools.clear();

    for (const auto pool : PoolSignatures::KNOWN_POOL_HOSTNAMES) {
        PoolEndpointInfo info;
        info.address = std::string(pool);
        info.poolName = std::string(pool);
        info.status = PoolStatus::KnownPublic;
        info.lastSeen = SystemClock::now();
        info.protocols.push_back(PoolProtocolType::Stratum);
        m_knownPools.emplace(info.address, std::move(info));
    }

    for (const auto pool : PoolSignatures::MALICIOUS_POOL_HOSTNAMES) {
        PoolEndpointInfo info;
        info.address = std::string(pool);
        info.poolName = std::string(pool);
        info.status = PoolStatus::KnownMalicious;
        info.lastSeen = SystemClock::now();
        info.isBlacklisted = true;
        info.protocols.push_back(PoolProtocolType::Stratum);
        m_knownPools[info.address] = std::move(info);
    }
}

void PoolConnectionDetectorImpl::RefreshBlacklistState(const PoolConnectionDetectorConfiguration& config) {
    {
        std::unique_lock lock(m_blacklistMutex);
        m_blacklistedPools = m_manualBlacklistedPools;
    }

    if (config.blockMaliciousPools) {
        LoadBuiltinBlacklist();
    }

    if (!config.poolBlacklistPath.empty() && !LoadPoolBlacklistInternal(config.poolBlacklistPath)) {
        Utils::Logger::Warn("PoolConnectionDetector: custom pool blacklist could not be loaded from {}",
            ToNarrow(config.poolBlacklistPath));
    }
}

bool PoolConnectionDetectorImpl::LoadPoolBlacklistInternal(const std::filesystem::path& path) {
    Utils::FileUtils::Error fileError;
    std::string content;
    if (!Utils::FileUtils::ReadAllTextUtf8(path.wstring(), content, &fileError)) {
        Utils::Logger::Error("PoolConnectionDetector: failed to read blacklist {} - {}",
            path.string(),
            fileError.message);
        return false;
    }

    std::istringstream stream(content);
    std::string line;
    size_t added = 0;

    while (std::getline(stream, line)) {
        line = TrimCopy(line);
        if (line.empty() || line[0] == '#') {
            continue;
        }
        if (added >= PoolDetectorConstants::MAX_KNOWN_POOLS) {
            Utils::Logger::Warn("PoolConnectionDetector: blacklist import truncated at {} entries",
                PoolDetectorConstants::MAX_KNOWN_POOLS);
            break;
        }
        if (BlockPoolAddressInternal(line, false)) {
            ++added;
        }
    }

    return true;
}

void PoolConnectionDetectorImpl::InvokeConnectionCallbacks(const PoolConnectionInfo& conn) {
    std::vector<PoolConnectionCallback> callbacks;
    {
        std::lock_guard lock(m_callbacksMutex);
        callbacks = m_connectionCallbacks;
    }

    for (const auto& callback : callbacks) {
        try {
            callback(conn);
        } catch (const std::exception& ex) {
            Utils::Logger::Error("PoolConnectionDetector: connection callback failed - {}", ex.what());
        }
    }
}

void PoolConnectionDetectorImpl::InvokeStratumCallbacks(const PoolDetectionResult& result) {
    std::vector<StratumDetectedCallback> callbacks;
    {
        std::lock_guard lock(m_callbacksMutex);
        callbacks = m_stratumCallbacks;
    }

    for (const auto& callback : callbacks) {
        try {
            callback(result);
        } catch (const std::exception& ex) {
            Utils::Logger::Error("PoolConnectionDetector: detection callback failed - {}", ex.what());
        }
    }
}

void PoolConnectionDetectorImpl::InvokeErrorCallbacks(const std::string& message, int code) {
    std::vector<ErrorCallback> callbacks;
    {
        std::lock_guard lock(m_callbacksMutex);
        callbacks = m_errorCallbacks;
    }

    for (const auto& callback : callbacks) {
        try {
            callback(message, code);
        } catch (...) {
        }
    }
}

std::string PoolConnectionDetectorImpl::GenerateDetectionId() const {
    static std::atomic<uint64_t> counter{0};
    const auto tick = SystemClock::now().time_since_epoch().count();
    return std::format("PDET-{:016X}-{:08X}", tick, counter.fetch_add(1, std::memory_order_relaxed));
}

double PoolConnectionDetectorImpl::CalculateConfidence(
    bool hasStratum,
    bool hasWallet,
    bool hasEndpointIndicator,
    bool isBlacklisted) const
{
    double score = 0.0;
    if (hasStratum) {
        score += 40.0;
    }
    if (hasWallet) {
        score += 30.0;
    }
    if (hasEndpointIndicator) {
        score += 25.0;
    }
    if (isBlacklisted) {
        score += 50.0;
    }
    return std::min(score, 100.0);
}

std::atomic<bool> PoolConnectionDetector::s_instanceCreated{false};

PoolConnectionDetector& PoolConnectionDetector::Instance() noexcept {
    static PoolConnectionDetector instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

bool PoolConnectionDetector::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

PoolConnectionDetector::PoolConnectionDetector()
    : m_impl(std::make_unique<PoolConnectionDetectorImpl>()) {}

PoolConnectionDetector::~PoolConnectionDetector() {
    if (m_impl) {
        m_impl->Shutdown();
    }
}

bool PoolConnectionDetector::Initialize(const PoolConnectionDetectorConfiguration& config) {
    return m_impl != nullptr && m_impl->Initialize(config);
}

void PoolConnectionDetector::Shutdown() {
    if (m_impl) {
        m_impl->Shutdown();
    }
}

bool PoolConnectionDetector::IsInitialized() const noexcept {
    return m_impl != nullptr && m_impl->m_initialized.load(std::memory_order_acquire);
}

ModuleStatus PoolConnectionDetector::GetStatus() const noexcept {
    return m_impl != nullptr ? m_impl->m_status.load(std::memory_order_acquire) : ModuleStatus::Uninitialized;
}

bool PoolConnectionDetector::Start() {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    const ModuleStatus current = m_impl->m_status.load(std::memory_order_acquire);
    if (current == ModuleStatus::Stopping || current == ModuleStatus::Error) {
        return false;
    }

    m_impl->m_status.store(ModuleStatus::Running, std::memory_order_release);
    return true;
}

bool PoolConnectionDetector::Stop() {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    m_impl->m_status.store(ModuleStatus::Stopping, std::memory_order_release);
    {
        std::unique_lock lock(m_impl->m_connectionsMutex);
        m_impl->m_activeConnections.clear();
    }
    m_impl->m_status.store(ModuleStatus::Stopped, std::memory_order_release);
    return true;
}

void PoolConnectionDetector::Pause() {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return;
    }
    const auto current = m_impl->m_status.load(std::memory_order_acquire);
    if (current == ModuleStatus::Running) {
        m_impl->m_status.store(ModuleStatus::Paused, std::memory_order_release);
    }
}

void PoolConnectionDetector::Resume() {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return;
    }
    if (m_impl->m_status.load(std::memory_order_acquire) == ModuleStatus::Paused) {
        m_impl->m_status.store(ModuleStatus::Running, std::memory_order_release);
    }
}

bool PoolConnectionDetector::UpdateConfiguration(const PoolConnectionDetectorConfiguration& config) {
    if (!m_impl || !config.IsValid()) {
        return false;
    }

    {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_config = config;
    }

    {
        std::unique_lock lock(m_impl->m_whitelistMutex);
        m_impl->m_whitelistedPools.clear();
        for (const auto& entry : config.whitelistedPools) {
            const ParsedEndpoint parsed = ParseEndpoint(entry);
            if (!parsed.valid) {
                continue;
            }
            m_impl->m_whitelistedPools.insert(parsed.host);
            if (parsed.port != 0) {
                m_impl->m_whitelistedPools.insert(std::format("{}:{}", parsed.host, parsed.port));
            }
        }
    }

    m_impl->RefreshBlacklistState(config);

    return true;
}

PoolConnectionDetectorConfiguration PoolConnectionDetector::GetConfiguration() const {
    if (!m_impl) {
        return {};
    }

    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_config;
}

bool PoolConnectionDetector::IsStratumTraffic(std::span<const uint8_t> payload) {
    return m_impl != nullptr && m_impl->IsStratumTrafficInternal(payload);
}

std::optional<StratumMessage> PoolConnectionDetector::ParseStratumMessage(std::span<const uint8_t> payload) {
    if (!m_impl) {
        return std::nullopt;
    }

    auto parsed = m_impl->ParseStratumMessageInternal(payload);
    if (parsed.has_value()) {
        m_impl->m_statistics.stratumSessionsDetected.fetch_add(1, std::memory_order_relaxed);
        PoolConnectionDetectorConfiguration config;
        {
            std::shared_lock lock(m_impl->m_mutex);
            config = m_impl->m_config;
        }
        if (config.logStratumMessages) {
            Utils::Logger::Info("PoolConnectionDetector: parsed Stratum message {}",
                std::string(GetStratumCommandName(parsed->command)));
        }

        PoolDetectionResult result;
        result.detectionId = m_impl->GenerateDetectionId();
        result.isPoolConnectionDetected = false;
        result.stratumMessages.push_back(*parsed);
        result.isConfirmedMining = parsed->command != StratumCommand::Unknown;
        result.confidenceScore = parsed->command == StratumCommand::Authorize || parsed->command == StratumCommand::Submit ? 75.0 : 45.0;
        result.detectionTime = SystemClock::now();
        m_impl->InvokeStratumCallbacks(result);
    }
    return parsed;
}

bool PoolConnectionDetector::IsPoolEndpoint(const std::string& ip, uint16_t port) const {
    return m_impl != nullptr && m_impl->IsPoolEndpointInternal(ip, port);
}

bool PoolConnectionDetector::IsPoolHostname(const std::string& hostname) const {
    return m_impl != nullptr && m_impl->IsPoolHostnameInternal(hostname);
}

std::optional<PoolEndpointInfo> PoolConnectionDetector::GetPoolInfo(const std::string& address, uint16_t port) const {
    return m_impl != nullptr ? m_impl->GetPoolInfoInternal(address, port) : std::nullopt;
}

std::optional<std::string> PoolConnectionDetector::ExtractWalletAddress(std::span<const uint8_t> payload) {
    return m_impl != nullptr ? m_impl->ExtractWalletAddressInternal(payload) : std::nullopt;
}

std::optional<std::string> PoolConnectionDetector::ExtractWorkerName(std::span<const uint8_t> payload) {
    return m_impl != nullptr ? m_impl->ExtractWorkerNameInternal(payload) : std::nullopt;
}

std::vector<PoolConnectionInfo> PoolConnectionDetector::GetActiveConnections() {
    return m_impl != nullptr ? m_impl->GetActiveConnectionsInternal() : std::vector<PoolConnectionInfo>{};
}

std::vector<PoolConnectionInfo> PoolConnectionDetector::GetProcessConnections(uint32_t processId) {
    return m_impl != nullptr ? m_impl->GetProcessConnectionsInternal(processId) : std::vector<PoolConnectionInfo>{};
}

bool PoolConnectionDetector::BlockPoolAddress(const std::string& address) {
    return m_impl != nullptr && m_impl->BlockPoolAddressInternal(address);
}

void PoolConnectionDetector::UnblockPoolAddress(const std::string& address) {
    if (m_impl) {
        m_impl->UnblockPoolAddressInternal(address);
    }
}

bool PoolConnectionDetector::LoadPoolBlacklist(const std::filesystem::path& path) {
    return m_impl != nullptr && m_impl->LoadPoolBlacklistInternal(path);
}

void PoolConnectionDetector::AddToBlacklist(const PoolEndpointInfo& pool) {
    if (!m_impl) {
        return;
    }

    if (!pool.address.empty()) {
        (void)m_impl->BlockPoolAddressInternal(pool.port == 0 ? pool.address : std::format("{}:{}", pool.address, pool.port));
    }
    for (const auto& ip : pool.ipAddresses) {
        (void)m_impl->BlockPoolAddressInternal(pool.port == 0 ? ip : std::format("{}:{}", ip, pool.port));
    }
}

bool PoolConnectionDetector::IsBlacklisted(const std::string& address) const {
    return m_impl != nullptr && m_impl->IsBlacklistedInternal(address);
}

void PoolConnectionDetector::RegisterConnectionCallback(PoolConnectionCallback callback) {
    if (!m_impl || !callback) {
        return;
    }

    std::lock_guard lock(m_impl->m_callbacksMutex);
    m_impl->m_connectionCallbacks.push_back(std::move(callback));
}

void PoolConnectionDetector::RegisterStratumDetectedCallback(StratumDetectedCallback callback) {
    if (!m_impl || !callback) {
        return;
    }

    std::lock_guard lock(m_impl->m_callbacksMutex);
    m_impl->m_stratumCallbacks.push_back(std::move(callback));
}

void PoolConnectionDetector::RegisterErrorCallback(ErrorCallback callback) {
    if (!m_impl || !callback) {
        return;
    }

    std::lock_guard lock(m_impl->m_callbacksMutex);
    m_impl->m_errorCallbacks.push_back(std::move(callback));
}

void PoolConnectionDetector::UnregisterCallbacks() {
    if (!m_impl) {
        return;
    }

    std::lock_guard lock(m_impl->m_callbacksMutex);
    m_impl->m_connectionCallbacks.clear();
    m_impl->m_stratumCallbacks.clear();
    m_impl->m_errorCallbacks.clear();
}

PoolDetectorStatistics PoolConnectionDetector::GetStatistics() const {
    return m_impl != nullptr ? PoolDetectorStatistics(m_impl->m_statistics) : PoolDetectorStatistics{};
}

void PoolConnectionDetector::ResetStatistics() {
    if (m_impl) {
        m_impl->m_statistics.Reset();
    }
}

std::vector<PoolDetectionResult> PoolConnectionDetector::GetRecentDetections(size_t maxCount) const {
    if (!m_impl) {
        return {};
    }

    std::vector<PoolDetectionResult> results;
    std::shared_lock lock(m_impl->m_detectionsMutex);
    const size_t count = std::min(maxCount, m_impl->m_recentDetections.size());
    results.reserve(count);

    auto it = m_impl->m_recentDetections.rbegin();
    for (size_t index = 0; index < count && it != m_impl->m_recentDetections.rend(); ++index, ++it) {
        results.push_back(*it);
    }

    return results;
}

bool PoolConnectionDetector::SelfTest() {
    PoolConnectionDetectorConfiguration config;
    config.blockMaliciousPools = true;
    config.logStratumMessages = false;

    if (!Initialize(config)) {
        return false;
    }

    const std::string sample = R"({"id":1,"method":"mining.authorize","params":["0x0123456789abcdef0123456789abcdef01234567.worker","x"]})";
    const std::span<const uint8_t> payload(reinterpret_cast<const uint8_t*>(sample.data()), sample.size());

    const bool stratumDetected = IsStratumTraffic(payload);
    const auto parsed = ParseStratumMessage(payload);
    const auto wallet = ExtractWalletAddress(payload);
    const auto worker = ExtractWorkerName(payload);
    const auto knownPool = GetPoolInfo("stratum+ssl://pool.supportxmr.com:443");

    return stratumDetected &&
        parsed.has_value() && parsed->command == StratumCommand::Authorize &&
        wallet.has_value() && worker.has_value() &&
        knownPool.has_value() && knownPool->requiresTLS;
}

std::string PoolConnectionDetector::GetVersionString() noexcept {
    return std::format("{}.{}.{}",
        PoolDetectorConstants::VERSION_MAJOR,
        PoolDetectorConstants::VERSION_MINOR,
        PoolDetectorConstants::VERSION_PATCH);
}

PoolDetectorStatistics::PoolDetectorStatistics(const PoolDetectorStatistics& other) noexcept {
    *this = other;
}

PoolDetectorStatistics& PoolDetectorStatistics::operator=(const PoolDetectorStatistics& other) noexcept {
    if (this == &other) {
        return *this;
    }

    connectionsAnalyzed.store(other.connectionsAnalyzed.load(std::memory_order_relaxed), std::memory_order_relaxed);
    poolConnectionsDetected.store(other.poolConnectionsDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
    stratumSessionsDetected.store(other.stratumSessionsDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
    connectionsBlocked.store(other.connectionsBlocked.load(std::memory_order_relaxed), std::memory_order_relaxed);
    walletsExtracted.store(other.walletsExtracted.load(std::memory_order_relaxed), std::memory_order_relaxed);
    sharesDetected.store(other.sharesDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);

    for (size_t i = 0; i < byProtocol.size(); ++i) {
        byProtocol[i].store(other.byProtocol[i].load(std::memory_order_relaxed), std::memory_order_relaxed);
    }
    for (size_t i = 0; i < byCrypto.size(); ++i) {
        byCrypto[i].store(other.byCrypto[i].load(std::memory_order_relaxed), std::memory_order_relaxed);
    }
    startTime = other.startTime;
    return *this;
}

void PoolDetectorStatistics::Reset() noexcept {
    connectionsAnalyzed.store(0, std::memory_order_relaxed);
    poolConnectionsDetected.store(0, std::memory_order_relaxed);
    stratumSessionsDetected.store(0, std::memory_order_relaxed);
    connectionsBlocked.store(0, std::memory_order_relaxed);
    walletsExtracted.store(0, std::memory_order_relaxed);
    sharesDetected.store(0, std::memory_order_relaxed);
    for (auto& counter : byProtocol) {
        counter.store(0, std::memory_order_relaxed);
    }
    for (auto& counter : byCrypto) {
        counter.store(0, std::memory_order_relaxed);
    }
    startTime = Clock::now();
}

std::string PoolDetectorStatistics::ToJson() const {
    Json json = {
        {"connectionsAnalyzed", connectionsAnalyzed.load(std::memory_order_relaxed)},
        {"poolConnectionsDetected", poolConnectionsDetected.load(std::memory_order_relaxed)},
        {"stratumSessionsDetected", stratumSessionsDetected.load(std::memory_order_relaxed)},
        {"connectionsBlocked", connectionsBlocked.load(std::memory_order_relaxed)},
        {"walletsExtracted", walletsExtracted.load(std::memory_order_relaxed)},
        {"sharesDetected", sharesDetected.load(std::memory_order_relaxed)}
    };
    return json.dump(2);
}

bool PoolConnectionDetectorConfiguration::IsValid() const noexcept {
    if (monitorPorts.size() > 1024 || whitelistedPools.size() > PoolDetectorConstants::MAX_KNOWN_POOLS) {
        return false;
    }

    std::set<uint16_t> uniquePorts;
    for (const auto port : monitorPorts) {
        if (port == 0 || !uniquePorts.insert(port).second) {
            return false;
        }
    }

    if (poolBlacklistPath.size() > Utils::FileUtils::MAX_REASONABLE_PATH_LENGTH) {
        return false;
    }

    for (const auto& entry : whitelistedPools) {
        const ParsedEndpoint parsed = ParseEndpoint(entry);
        if (!parsed.valid) {
            return false;
        }
    }

    return true;
}

std::string PoolEndpointInfo::ToJson() const {
    Json json = {
        {"address", address},
        {"port", port},
        {"ipAddresses", ipAddresses},
        {"poolName", poolName},
        {"poolOperator", poolOperator},
        {"status", static_cast<int>(status)},
        {"requiresTLS", requiresTLS},
        {"isBlacklisted", isBlacklisted},
        {"threatIntelSource", threatIntelSource}
    };
    return json.dump(2);
}

std::string PoolConnectionInfo::ToJson() const {
    Json json = {
        {"connectionId", connectionId},
        {"processId", processId},
        {"processName", ToNarrow(processName)},
        {"localIP", localIP},
        {"localPort", localPort},
        {"remoteIP", remoteIP},
        {"remotePort", remotePort},
        {"remoteHostname", remoteHostname},
        {"state", static_cast<int>(state)},
        {"protocol", static_cast<int>(protocol)},
        {"cryptocurrency", static_cast<int>(cryptocurrency)},
        {"isEncrypted", isEncrypted},
        {"walletAddress", RedactSensitive(walletAddress)},
        {"workerName", workerName},
        {"bytesSent", bytesSent},
        {"bytesReceived", bytesReceived},
        {"sharesSubmitted", sharesSubmitted},
        {"sharesAccepted", sharesAccepted},
        {"sharesRejected", sharesRejected},
        {"durationSecs", durationSecs}
    };
    return json.dump(2);
}

std::string StratumMessage::ToJson() const {
    Json paramsJson = Json::object();
    if (!params.empty()) {
        paramsJson = Json::parse(params, nullptr, false);
        if (paramsJson.is_discarded()) {
            paramsJson = params;
        }
    }

    Json resultJson = Json::object();
    if (!result.empty()) {
        resultJson = Json::parse(result, nullptr, false);
        if (resultJson.is_discarded()) {
            resultJson = result;
        }
    }

    Json json = {
        {"messageId", messageId},
        {"command", static_cast<int>(command)},
        {"method", method},
        {"params", paramsJson},
        {"result", resultJson},
        {"isRequest", isRequest},
        {"hasError", hasError},
        {"errorMessage", errorMessage},
        {"rawMessagePreview", SanitizeBoundedText(rawMessage, 256)}
    };
    return json.dump(2);
}

std::string PoolDetectionResult::ToJson() const {
    Json connectionJson = Json::parse(connectionInfo.ToJson(), nullptr, false);
    if (connectionJson.is_discarded()) {
        connectionJson = Json::object();
    }

    Json json = {
        {"detectionId", detectionId},
        {"isPoolConnectionDetected", isPoolConnectionDetected},
        {"isConfirmedMining", isConfirmedMining},
        {"confidenceScore", confidenceScore},
        {"wasBlocked", wasBlocked},
        {"connectionInfo", connectionJson}
    };
    return json.dump(2);
}

std::string_view GetPoolProtocolTypeName(PoolProtocolType type) noexcept {
    switch (type) {
        case PoolProtocolType::Unknown: return "Unknown";
        case PoolProtocolType::Stratum: return "Stratum";
        case PoolProtocolType::StratumV2: return "Stratum v2";
        case PoolProtocolType::NiceHashStratum: return "NiceHash Stratum";
        case PoolProtocolType::EthProxy: return "EthProxy";
        case PoolProtocolType::GetWork: return "GetWork";
        case PoolProtocolType::GetBlockTemplate: return "GetBlockTemplate";
        case PoolProtocolType::EthereumStratum: return "Ethereum Stratum";
        case PoolProtocolType::CryptoNightStratum: return "CryptoNight Stratum";
        case PoolProtocolType::StratumOverTls: return "Stratum over TLS";
        case PoolProtocolType::StratumOverWebSocket: return "Stratum over WebSocket";
        case PoolProtocolType::JsonRpc: return "JSON-RPC";
        default: return "Unknown";
    }
}

std::string_view GetPoolStatusName(PoolStatus status) noexcept {
    switch (status) {
        case PoolStatus::Unknown: return "Unknown";
        case PoolStatus::KnownPublic: return "Known Public";
        case PoolStatus::KnownMalicious: return "Known Malicious";
        case PoolStatus::Private: return "Private";
        case PoolStatus::P2P: return "P2P";
        case PoolStatus::Proxy: return "Proxy";
        default: return "Unknown";
    }
}

std::string_view GetConnectionStateName(ConnectionState state) noexcept {
    switch (state) {
        case ConnectionState::Unknown: return "Unknown";
        case ConnectionState::Connecting: return "Connecting";
        case ConnectionState::Connected: return "Connected";
        case ConnectionState::Authenticating: return "Authenticating";
        case ConnectionState::Authenticated: return "Authenticated";
        case ConnectionState::Mining: return "Mining";
        case ConnectionState::Disconnected: return "Disconnected";
        case ConnectionState::Blocked: return "Blocked";
        default: return "Unknown";
    }
}

std::string_view GetStratumCommandName(StratumCommand cmd) noexcept {
    switch (cmd) {
        case StratumCommand::Unknown: return "Unknown";
        case StratumCommand::Subscribe: return "mining.subscribe";
        case StratumCommand::Authorize: return "mining.authorize";
        case StratumCommand::Submit: return "mining.submit";
        case StratumCommand::Notify: return "mining.notify";
        case StratumCommand::SetDifficulty: return "mining.set_difficulty";
        case StratumCommand::SetExtranonce: return "mining.set_extranonce";
        case StratumCommand::Reconnect: return "client.reconnect";
        case StratumCommand::GetVersion: return "client.get_version";
        case StratumCommand::EthSubmitWork: return "eth_submitWork";
        case StratumCommand::EthSubmitHashrate: return "eth_submitHashrate";
        case StratumCommand::EthGetWork: return "eth_getWork";
        case StratumCommand::Login: return "login";
        case StratumCommand::KeepAlive: return "keepalived";
        default: return "Unknown";
    }
}

std::string_view GetMinedCryptocurrencyName(MinedCryptocurrency crypto) noexcept {
    switch (crypto) {
        case MinedCryptocurrency::Unknown: return "Unknown";
        case MinedCryptocurrency::Bitcoin: return "Bitcoin";
        case MinedCryptocurrency::Ethereum: return "Ethereum";
        case MinedCryptocurrency::Monero: return "Monero";
        case MinedCryptocurrency::Litecoin: return "Litecoin";
        case MinedCryptocurrency::Ravencoin: return "Ravencoin";
        case MinedCryptocurrency::Zcash: return "Zcash";
        case MinedCryptocurrency::EthClassic: return "Ethereum Classic";
        case MinedCryptocurrency::Ergo: return "Ergo";
        case MinedCryptocurrency::Other: return "Other";
        default: return "Unknown";
    }
}

bool IsStratumPort(uint16_t port) noexcept {
    for (const auto configuredPort : PoolDetectorConstants::STRATUM_PORTS) {
        if (configuredPort == port) {
            return true;
        }
    }
    return false;
}

bool ValidateWalletAddress(std::string_view address, MinedCryptocurrency crypto) {
    if (address.empty() || address.size() > kMaxWalletCandidateLength) {
        return false;
    }

    for (const auto& [entryCrypto, pattern] : CompiledWalletPatterns()) {
        if (entryCrypto == crypto && std::regex_match(address.begin(), address.end(), pattern)) {
            return true;
        }
    }

    return false;
}

}  // namespace ShadowStrike::CryptoMiners
