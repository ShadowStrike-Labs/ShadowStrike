/**
 * ============================================================================
 * ShadowStrike - IPC PER-MESSAGE-TYPE STATISTICS CONTRACT
 * ============================================================================
 *
 * @file IpcStatistics_Tests.cpp
 * @brief Pins the per-message-type counter array against the message type enum.
 *
 * @par Why this is a separate translation unit
 * These assertions need IPCManager.hpp. That header cannot be included in the
 * same translation unit as Communication.hpp, because the two declare
 * ShadowStrike::Communication::FileScanCallback and ::ProcessNotifyCallback with
 * DIFFERENT types under the same fully-qualified names:
 *
 *   IPCManager.hpp:696    std::function<SHADOWSTRIKE_SCAN_VERDICT(const FILE_SCAN_REQUEST&)>
 *   Communication.hpp:436 std::function<ScanVerdictReply(const FileScanRequest&)>
 *
 * Including both yields C2371. IPCManager.cpp is compiled against the first and
 * MessageDispatcher.cpp against the second, so two modules in this product hold
 * different ideas of the same callback contract and it builds only because no
 * translation unit has ever needed both. That is recorded as its own finding; the
 * split here is so this file does not depend on it being resolved.
 *
 * @par What is being pinned
 * IPCStatistics::byMessageType was a hardcoded std::array of 16 while
 * SHADOWSTRIKE_MESSAGE_TYPE already ran past 40, and every counting site guards
 * with `if (idx < byMessageType.size())`. So every message type with an ordinal
 * of 16 or more was counted nowhere, and the bounds check is precisely what made
 * that invisible - no overflow, no warning, just a permanent zero.
 *
 * The types that fell off the end were not a random tail. They were every alert
 * class the driver can raise: handle alerts, ransomware alerts, behavioural,
 * memory, network, syscall and self-protection alerts. Anyone reading the
 * statistics to answer "is the kernel reporting anything?" got "no" regardless of
 * the truth, which is worse than an absent counter because it argues against the
 * symptom being investigated.
 *
 * @copyright ShadowStrike Labs. Licensed under AGPL-3.0.
 */

#include <gtest/gtest.h>

#include <cstddef>

#include "PhantomCore/Communication/IPCManager.hpp"

namespace {
constexpr size_t kSlots = ShadowStrike::Communication::IPCConstants::MESSAGE_TYPE_SLOTS;
}  // namespace

TEST(IpcStatisticsContractTest, EveryMessageTypeHasACounterSlot) {
    // The contract: the array is indexed by message type, so it must be at least
    // as large as the number of message types. Derived, not chosen.
    EXPECT_GE(kSlots, static_cast<size_t>(FilterMessageType_Max))
        << "a message type with no slot is counted as zero forever";
}

TEST(IpcStatisticsContractTest, EveryAlertTypeIsCountable) {
    // Named individually because these are the ones the old sizing dropped, and
    // they are exactly the security-relevant types. Each of these previously
    // reported zero received no matter how many arrived.
    struct Named { SHADOWSTRIKE_MESSAGE_TYPE type; const char* name; };
    const Named kAlerts[] = {
        { FilterMessageType_HandleAlert,        "HandleAlert"        },
        { FilterMessageType_RansomwareAlert,    "RansomwareAlert"    },
        { FilterMessageType_BehavioralAlert,    "BehavioralAlert"    },
        { FilterMessageType_MemoryAlert,        "MemoryAlert"        },
        { FilterMessageType_NetworkAlert,       "NetworkAlert"       },
        { FilterMessageType_SyscallAlert,       "SyscallAlert"       },
        { FilterMessageType_SelfProtectAlert,   "SelfProtectAlert"   },
        { FilterMessageType_FileOperationEvent, "FileOperationEvent" },
    };

    for (const auto& a : kAlerts) {
        EXPECT_LT(static_cast<size_t>(a.type), kSlots)
            << a.name << " (ordinal " << static_cast<int>(a.type)
            << ") has no statistics slot, so it can only ever report zero";
    }
}

TEST(IpcStatisticsContractTest, TheOldSixteenSlotCeilingWouldHaveDroppedTheseTypes) {
    // The discriminator. This test's value is that it FAILS against the previous
    // sizing: each of these ordinals is at or above the old ceiling of 16, so the
    // guard silently skipped them. If a future change reorders the enum such that
    // these fall below 16, this stops discriminating and should be revisited
    // rather than deleted.
    EXPECT_GE(static_cast<size_t>(FilterMessageType_HandleAlert), 16u);
    EXPECT_GE(static_cast<size_t>(FilterMessageType_RansomwareAlert), 16u);
    EXPECT_GE(static_cast<size_t>(FilterMessageType_BehavioralAlert), 16u);
    EXPECT_GE(static_cast<size_t>(FilterMessageType_FileOperationEvent), 16u);

    // And the array really is bigger than the old literal now.
    EXPECT_GT(kSlots, 16u);
}

TEST(IpcStatisticsContractTest, NewMessageTypesAreAppendedNotInserted) {
    // The type number is on the wire. An enumerator inserted anywhere other than
    // immediately before _Max renumbers every type after it, which silently
    // re-labels whole message classes between a driver and a service built at
    // different times.
    EXPECT_EQ(static_cast<int>(FilterMessageType_FileOperationEvent) + 1,
              static_cast<int>(FilterMessageType_Max))
        << "the most recently added type must be the last real enumerator";
}

TEST(IpcStatisticsContractTest, LiveAndSnapshotArraysAgreeInSize) {
    // The snapshot is copied element-by-element from the live array. If the two
    // sizes ever diverge, the copy loop bounded by the live array either drops
    // counters or writes past the snapshot.
    ShadowStrike::Communication::IPCStatistics live{};
    const auto snap = ShadowStrike::Communication::TakeSnapshot(live);

    EXPECT_EQ(live.byMessageType.size(), snap.byMessageType.size());
    EXPECT_EQ(kSlots, snap.byMessageType.size());
    EXPECT_EQ(live.byVerdict.size(), snap.byVerdict.size());
}
