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
#include <optional>
#include <string>
#include <vector>

namespace ShadowStrike::Products::PhantomXDR::IdentityProtection {

using IdentityTimestamp = std::chrono::system_clock::time_point;

enum class LogonType : uint8_t {
    Interactive = 2,
    Network = 3,
    Batch = 4,
    Service = 5,
    Unlock = 7,
    NetworkCleartext = 8,
    NewCredentials = 9,
    RemoteInteractive = 10,
    CachedInteractive = 11
};

enum class IdentityThreat : uint8_t {
    None = 0,
    BruteForce,
    PasswordSpray,
    Kerberoasting,
    DCSync,
    GoldenTicket,
    SilverTicket,
    PassTheHash,
    PassTheTicket,
    OverPassTheHash,
    CredentialDumping,
    ImpossibleTravel,
    AnomalousAccess,
    PrivilegeEscalation
};

struct LogonEvent {
    IdentityTimestamp timestamp{};
    std::wstring userName;
    std::wstring domain;
    LogonType logonType{LogonType::Interactive};
    std::wstring sourceIP;
    std::wstring sourceHost;
    std::wstring workstation;
    bool success{false};
    uint32_t eventId{0};
    std::wstring logonId;
};

struct GroupChangeEvent {
    IdentityTimestamp timestamp{};
    std::wstring actor;
    std::wstring targetUser;
    std::wstring groupName;
    std::wstring changeType;
    std::wstring domain;
};

struct CredentialAccessEvent {
    IdentityTimestamp timestamp{};
    std::wstring process;
    std::wstring target;
    std::wstring accessType;
    bool success{false};
};

struct IdentityAlert {
    IdentityThreat threatType{IdentityThreat::None};
    uint32_t severity{0};
    std::wstring evidence;
    std::wstring affectedUser;
    std::wstring sourceIP;
    std::wstring mitreTechnique;
    IdentityTimestamp timestamp{};
};

struct UserBehaviorProfile {
    std::wstring userName;
    std::vector<uint8_t> normalLogonTimes;
    std::vector<std::wstring> normalWorkstations;
    std::vector<std::wstring> normalSourceIPs;
    std::vector<std::wstring> typicalAccessedResources;
    double riskScore{0.0};
};

struct ADMonitorStatistics {
    uint64_t totalEventsProcessed{0};
    uint64_t logonEvents{0};
    uint64_t failedLogons{0};
    uint64_t groupChanges{0};
    uint64_t kerberosEvents{0};
    uint64_t alertsRaised{0};
    uint64_t bruteForceDetections{0};
    uint64_t passwordSprayDetections{0};
    uint64_t kerberoastingDetections{0};
    uint64_t dcsyncDetections{0};
    bool monitoringActive{false};
};

struct IdentityAnalyticsStatistics {
    uint64_t profilesBuilt{0};
    uint64_t logonsAnalyzed{0};
    uint64_t anomaliesRaised{0};
    uint64_t impossibleTravelDetections{0};
    uint64_t anomalousAccessDetections{0};
    uint64_t privilegeEscalationDetections{0};
    uint64_t highRiskUsers{0};
    uint32_t baselineLearningDays{7};
};

struct CredentialProtectionStatistics {
    uint64_t lsassChecks{0};
    uint64_t credentialAccessEvents{0};
    uint64_t credentialAlerts{0};
    uint64_t passTheHashDetections{0};
    uint64_t credentialDumpingDetections{0};
    uint64_t honeypotDeployments{0};
    bool lsassProtected{false};
    bool honeypotActive{false};
};

} // namespace ShadowStrike::Products::PhantomXDR::IdentityProtection
