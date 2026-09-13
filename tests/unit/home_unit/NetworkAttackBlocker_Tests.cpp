/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file NetworkAttackBlocker_Tests.cpp
 * @brief Per-detector enablement and mode, for the module that answers "is the network attacked".
 *
 * NabThreatKind has eight members plus a Count sentinel, and each detector can be switched off
 * independently. The property worth holding is that the switch is real and per-kind: if
 * SetDetectorEnabled wrote to the wrong slot, or IsDetectorEnabled read a shared flag, the UI would
 * report a detector as enabled while a different one was actually toggled - and a user who
 * disabled port-scan detection to stop a false positive could silently lose ARP spoofing coverage.
 *
 * Every case restores the original state, because this is a process-wide singleton shared with any
 * other suite that touches it.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/NetworkAttackBlocker/NetworkAttackBlocker.hpp"

#include <array>
#include <vector>

namespace ShadowStrike::Products::Home::Test {
namespace {

constexpr std::size_t kKindCount = static_cast<std::size_t>(NabThreatKind::Count);

class NetworkAttackBlockerTest : public ::testing::Test {
protected:
    void SetUp() override {
        for (std::size_t i = 0; i < kKindCount; ++i) {
            m_original[i] = nab.IsDetectorEnabled(static_cast<NabThreatKind>(i));
        }
        m_originalMode = nab.Mode();
    }

    void TearDown() override {
        for (std::size_t i = 0; i < kKindCount; ++i) {
            nab.SetDetectorEnabled(static_cast<NabThreatKind>(i), m_original[i]);
        }
        nab.SetMode(m_originalMode);
    }

    NetworkAttackBlocker& nab = NetworkAttackBlocker::Instance();
    std::array<bool, kKindCount> m_original{};
    ProtectionMode m_originalMode{ProtectionMode::Balanced};
};

TEST_F(NetworkAttackBlockerTest, EveryDetectorCanBeToggledIndependently) {
    // Disable exactly one kind at a time and require that only that kind changed. This is what
    // catches a wrong-slot write or a shared flag.
    for (std::size_t target = 0; target < kKindCount; ++target) {
        for (std::size_t i = 0; i < kKindCount; ++i) {
            nab.SetDetectorEnabled(static_cast<NabThreatKind>(i), true);
        }
        nab.SetDetectorEnabled(static_cast<NabThreatKind>(target), false);

        for (std::size_t i = 0; i < kKindCount; ++i) {
            const bool expected = (i != target);
            EXPECT_EQ(expected, nab.IsDetectorEnabled(static_cast<NabThreatKind>(i)))
                << "disabling kind " << target << " changed kind " << i;
        }
    }
}

TEST_F(NetworkAttackBlockerTest, ADisabledDetectorStaysDisabled) {
    // Anti-vacuity: if IsDetectorEnabled always returned true the case above would still pass for
    // every index except the target, so assert the negative directly.
    nab.SetDetectorEnabled(NabThreatKind::PortScan, false);
    EXPECT_FALSE(nab.IsDetectorEnabled(NabThreatKind::PortScan));
    nab.SetDetectorEnabled(NabThreatKind::PortScan, true);
    EXPECT_TRUE(nab.IsDetectorEnabled(NabThreatKind::PortScan));
}

TEST_F(NetworkAttackBlockerTest, TheModeRoundTrips) {
    for (const auto mode : {ProtectionMode::Passive, ProtectionMode::Balanced,
                            ProtectionMode::Aggressive}) {
        nab.SetMode(mode);
        EXPECT_EQ(mode, nab.Mode()) << "the mode did not persist through SetMode";
    }
}

TEST_F(NetworkAttackBlockerTest, TheStatusIsSelfConsistent) {
    const auto status = nab.GetStatus();
    // The 24-hour counters are subsets of the total, so neither may exceed it. A counter that
    // exceeds its own total means the UI can display a blocked count larger than the event count.
    EXPECT_LE(status.eventsBlocked24h, status.eventsTotal)
        << "more events were blocked in 24h than have ever been recorded";
    EXPECT_LE(status.eventsLogged24h, status.eventsTotal)
        << "more events were logged in 24h than have ever been recorded";
    EXPECT_LE(status.recent.size(), 64u)
        << "the recent-event ring exceeded its documented size of 64";
}

}  // namespace
}  // namespace ShadowStrike::Products::Home::Test
