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
#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomXDR::NetworkDetection {

using SystemTimePoint = std::chrono::system_clock::time_point;

enum class NetworkProtocol : uint8_t {
    TCP,
    UDP,
    ICMP,
    DNS,
    HTTP,
    HTTPS,
    SMB,
    RDP,
    WMI,
    SSH,
    Unknown
};

enum class ConnectionDirection : uint8_t {
    Inbound,
    Outbound,
    Local
};

enum class ThreatIndicator : uint8_t {
    None,
    DGA,
    Tunneling,
    Beacon,
    LateralMovement,
    C2,
    DataExfil
};

enum class TLSAnomalyFlag : uint32_t {
    None = 0,
    SelfSigned = 1u << 0,
    Expired = 1u << 1,
    DomainMismatch = 1u << 2,
    ShortValidity = 1u << 3,
    SuspiciousIssuer = 1u << 4,
    MissingSni = 1u << 5,
    KnownMaliciousJa3 = 1u << 6,
    UnknownFingerprint = 1u << 7
};

[[nodiscard]] constexpr TLSAnomalyFlag operator|(TLSAnomalyFlag lhs, TLSAnomalyFlag rhs) noexcept {
    return static_cast<TLSAnomalyFlag>(static_cast<uint32_t>(lhs) | static_cast<uint32_t>(rhs));
}

[[nodiscard]] constexpr TLSAnomalyFlag operator&(TLSAnomalyFlag lhs, TLSAnomalyFlag rhs) noexcept {
    return static_cast<TLSAnomalyFlag>(static_cast<uint32_t>(lhs) & static_cast<uint32_t>(rhs));
}

constexpr TLSAnomalyFlag& operator|=(TLSAnomalyFlag& lhs, TLSAnomalyFlag rhs) noexcept {
    lhs = lhs | rhs;
    return lhs;
}

struct NetworkConnection {
    std::string sourceIp;
    uint16_t sourcePort = 0;
    std::string destinationIp;
    uint16_t destinationPort = 0;
    NetworkProtocol protocol = NetworkProtocol::Unknown;
    ConnectionDirection direction = ConnectionDirection::Outbound;
    uint64_t bytesSent = 0;
    uint64_t bytesReceived = 0;
    uint32_t processId = 0;
    std::wstring processName;
    SystemTimePoint timestamp{};
    std::chrono::milliseconds duration{};
    std::wstring state;
    std::vector<ThreatIndicator> indicators;
    bool isNewConnection = false;
    bool isClosedConnection = false;
    bool isLongLived = false;
    bool loopback = false;
};

struct DNSQuery {
    std::string queryName;
    uint16_t type = 1;
    std::vector<std::string> responseIps;
    uint32_t ttl = 0;
    double entropyScore = 0.0;
    double dgaProbability = 0.0;
    SystemTimePoint timestamp{};
    uint32_t processId = 0;
    std::wstring processName;
    uint32_t queryLength = 0;
    uint32_t labelCount = 0;
    bool suspicious = false;
    bool tunnelingSuspected = false;
    bool whitelisted = false;
};

struct TLSSession {
    std::string sourceIp;
    uint16_t sourcePort = 0;
    std::string destinationIp;
    uint16_t destinationPort = 0;
    uint32_t processId = 0;
    std::wstring processName;
    SystemTimePoint timestamp{};
    std::string ja3Hash;
    std::string ja3sHash;
    std::string serverName;
    std::string certIssuer;
    std::string certSubject;
    SystemTimePoint certNotBefore{};
    SystemTimePoint certExpiry{};
    uint32_t anomalyFlags = 0;
    uint16_t clientVersion = 0;
    uint16_t serverVersion = 0;
    uint16_t selectedCipher = 0;
    std::vector<uint16_t> clientCipherSuites;
    std::vector<uint16_t> clientExtensions;
    std::vector<uint16_t> ellipticCurves;
    std::vector<uint16_t> ecPointFormats;
    std::vector<uint16_t> serverExtensions;
    bool resumedSession = false;
    bool selfSigned = false;
};

struct BeaconPattern {
    std::string destination;
    double intervalMeanSeconds = 0.0;
    double intervalStdDevSeconds = 0.0;
    double jitterRatio = 0.0;
    size_t sampleCount = 0;
    double confidence = 0.0;
    std::vector<double> intervals;
    SystemTimePoint lastSeen{};
    uint32_t processId = 0;
    std::wstring processName;
};

struct LateralMovementEvent {
    std::string sourceHost;
    std::string targetHost;
    NetworkProtocol protocol = NetworkProtocol::Unknown;
    std::string credentialType;
    SystemTimePoint timestamp{};
    uint32_t processId = 0;
    std::wstring processName;
    double confidence = 0.0;
    std::vector<std::string> techniques;
};

struct LateralMovementChain {
    std::string sourceHost;
    std::vector<LateralMovementEvent> events;
    double score = 0.0;
    size_t uniqueTargets = 0;
    size_t uniqueProtocols = 0;
    SystemTimePoint firstSeen{};
    SystemTimePoint lastSeen{};
};

struct NetworkSensorSettings {
    std::chrono::milliseconds pollingInterval{5000};
    std::chrono::minutes longLivedThreshold{5};
    size_t maxHistoryEntries = 10000;
    bool enumerateIpv6 = true;
};

struct BeaconDetectorSettings {
    size_t minimumSampleCount = 6;
    double maxJitterRatio = 0.35;
    std::chrono::hours analysisWindow{24};
    double suspicionThreshold = 0.65;
};

struct NetworkSensorStatistics {
    uint64_t pollingCycles = 0;
    uint64_t newConnections = 0;
    uint64_t closedConnections = 0;
    uint64_t longLivedConnections = 0;
    uint64_t activeConnections = 0;
    uint64_t historyEntries = 0;
    uint64_t errors = 0;
};

struct DNSAnalyzerStatistics {
    uint64_t totalQueries = 0;
    uint64_t whitelistedQueries = 0;
    uint64_t dgaDetections = 0;
    uint64_t tunnelingDetections = 0;
    uint64_t cacheEnumerations = 0;
    uint64_t errors = 0;
};

struct TLSInspectorStatistics {
    uint64_t totalSessions = 0;
    uint64_t calculatedJa3 = 0;
    uint64_t maliciousJa3Matches = 0;
    uint64_t certificateAnomalies = 0;
    uint64_t errors = 0;
};

struct LateralMovementStatistics {
    uint64_t analyzedConnections = 0;
    uint64_t detections = 0;
    uint64_t highConfidenceDetections = 0;
    uint64_t chainCount = 0;
    uint64_t errors = 0;
};

struct BeaconDetectorStatistics {
    uint64_t recordedConnections = 0;
    uint64_t analyzedDestinations = 0;
    uint64_t detectedPatterns = 0;
    uint64_t suspiciousDestinations = 0;
    uint64_t errors = 0;
};

} // namespace ShadowStrike::Products::PhantomXDR::NetworkDetection
