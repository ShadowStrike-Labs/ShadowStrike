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
 * @file ShadowCopyProtector_ValueContracts_Tests.cpp
 * @brief Value-contract coverage for Ransomware::ShadowCopyProtector.
 */

#include "pch.h"
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "../../../src/PhantomCore/RansomwareProtection/ShadowCopyProtector.hpp"

namespace {

using namespace ShadowStrike::Ransomware;
using ::testing::HasSubstr;

TEST(ShadowCopyProtectorValueContractTests, ConfigStatisticsSerializationHelpersAndVersionRemainStable) {
    ShadowCopyProtectorConfiguration config;
    EXPECT_TRUE(config.IsValid());

    auto invalidEntry = config;
    invalidEntry.whitelist.push_back(L"");
    EXPECT_FALSE(invalidEntry.IsValid());

    auto invalidLimit = config;
    invalidLimit.whitelist.assign(ShadowCopyConstants::MAX_WHITELIST_ENTRIES + 1, L"C:\\safe.exe");
    EXPECT_FALSE(invalidLimit.IsValid());

    auto validLimit = config;
    validLimit.whitelist.assign(ShadowCopyConstants::MAX_WHITELIST_ENTRIES, L"C:\\safe.exe");
    EXPECT_TRUE(validLimit.IsValid());

    ShadowCopyStatistics stats;
    stats.attacksBlocked.store(3, std::memory_order_relaxed);
    stats.processesKilled.store(2, std::memory_order_relaxed);
    stats.processesBlockedKernel.store(1, std::memory_order_relaxed);
    stats.snapshotDecreaseAlerts.store(4, std::memory_order_relaxed);
    stats.currentShadowCopies.store(5, std::memory_order_relaxed);
    stats.byAttackType[static_cast<size_t>(VSSAttackType::CommandLineDelete)].store(
        7, std::memory_order_relaxed);
    EXPECT_THAT(stats.ToJson(), HasSubstr("CommandLineDelete"));
    stats.Reset();

    EXPECT_EQ(stats.attacksBlocked.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.processesKilled.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.processesBlockedKernel.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.snapshotDecreaseAlerts.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.currentShadowCopies.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(
        stats.byAttackType[static_cast<size_t>(VSSAttackType::CommandLineDelete)].load(
            std::memory_order_relaxed),
        0u);
    EXPECT_LT(
        std::chrono::duration_cast<std::chrono::seconds>(Clock::now() - stats.startTime).count(),
        2);

    ShadowCopyInfo info;
    info.shadowId = L"shadow-1";
    info.volume = L"C:\\";
    info.isProtected = true;
    info.providerId = L"provider-1";
    EXPECT_THAT(info.ToJson(), HasSubstr("\"shadowId\": \"shadow-1\""));
    EXPECT_THAT(info.ToJson(), HasSubstr("\"providerId\": \"provider-1\""));

    VSSAttackEvent event;
    event.attackType = VSSAttackType::WMIDelete;
    event.processName = L"wmic.exe";
    event.details = L"delete shadow copies";
    EXPECT_THAT(event.ToJson(), HasSubstr("\"attackTypeName\": \"WMIDelete\""));
    EXPECT_THAT(event.ToJson(), HasSubstr("\"details\": \"delete shadow copies\""));

    ShadowCopyStatisticsSnapshot snapshot;
    snapshot.attacksBlocked = 5;
    snapshot.currentShadowCopies = 3;
    snapshot.uptimeSeconds = 11;
    snapshot.byAttackType[static_cast<size_t>(VSSAttackType::WMIDelete)] = 2;
    EXPECT_THAT(snapshot.ToJson(), HasSubstr("\"WMIDelete\": 2"));
    EXPECT_THAT(snapshot.ToJson(), HasSubstr("\"uptimeSeconds\": 11"));

    EXPECT_EQ(GetVSSAttackTypeName(VSSAttackType::ProviderDisable), "ProviderDisable");
    EXPECT_EQ(GetShadowCopyStateName(ShadowCopyState::Corrupted), "Corrupted");
    EXPECT_EQ(GetVSSAttackTypeName(static_cast<VSSAttackType>(0xFF)), "Unknown");
    EXPECT_EQ(ShadowCopyProtector::GetVersionString(), "3.1.0");
}

// ============================================================================
// Outcome-reporting contract
//
// VSSAttackEvent::wasBlocked used to default to TRUE, so any event that simply
// forgot to assign it claimed a block - and ReportThreatToAlertSystem turns a
// true value into a Critical alert titled "Blocked". A default cannot be found
// by grepping for an assignment, which is precisely what hid it, so the default
// itself is asserted here.
// ============================================================================
TEST(ShadowCopyProtectorValueContractTests, ADefaultConstructedEventClaimsNothing) {
    VSSAttackEvent event;

    // THE DISCRIMINATOR: fails against the previous header, where wasBlocked
    // defaulted to true.
    EXPECT_FALSE(event.wasBlocked)
        << "a default-constructed VSS attack event must not claim a block";
    EXPECT_FALSE(event.blockRequested)
        << "a default-constructed VSS attack event must not claim a block was requested";

    // Both flags must reach the JSON, because that payload is what an operator
    // and the alert pipeline actually read.
    const std::string json = event.ToJson();
    EXPECT_THAT(json, HasSubstr("\"blockRequested\""));
    EXPECT_THAT(json, HasSubstr("\"wasBlocked\""));
}

// The gap counter must survive a COPY, not merely exist. ShadowCopyStatistics
// hand-writes its copy constructor and assignment operator to load atomics
// safely, so a member added to the declaration alone is silently dropped on
// every copy - and GetStatistics() copies. That turns the counter into a
// structural zero that looks healthy from outside, which is the same failure
// mode as a saturation metric nothing ever writes.
TEST(ShadowCopyProtectorValueContractTests, TheUnperformedBlockCounterSurvivesCopyAndReset) {
    ShadowCopyStatistics stats;
    stats.attacksBlocked.store(2, std::memory_order_relaxed);
    stats.blockRequestedNotPerformed.store(9, std::memory_order_relaxed);

    const ShadowCopyStatistics copied(stats);
    EXPECT_EQ(copied.blockRequestedNotPerformed.load(std::memory_order_relaxed), 9u)
        << "the hand-written copy constructor dropped the counter";

    ShadowCopyStatistics assigned;
    assigned = stats;
    EXPECT_EQ(assigned.blockRequestedNotPerformed.load(std::memory_order_relaxed), 9u)
        << "the hand-written assignment operator dropped the counter";

    EXPECT_THAT(stats.ToJson(), HasSubstr("blockRequestedNotPerformed"));

    stats.Reset();
    EXPECT_EQ(stats.blockRequestedNotPerformed.load(std::memory_order_relaxed), 0u)
        << "Reset() must clear the counter or it becomes a stale delta baseline";

    ShadowCopyStatisticsSnapshot snapshot;
    snapshot.blockRequestedNotPerformed = 4;
    EXPECT_THAT(snapshot.ToJson(), HasSubstr("blockRequestedNotPerformed"));
}

}  // namespace
