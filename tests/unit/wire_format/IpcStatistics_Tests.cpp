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


// ============================================================================
// THE PROCESS NOTIFICATION PAYLOAD LAYOUT
// ============================================================================
//
// ProcessNotifyRequest is a REINTERPRET_CAST of bytes the kernel wrote, so its
// layout is a wire contract, not an implementation detail -- and it had no test.
// That matters more now than it did: while the verdict was being discarded, a
// misparse here produced a wrong answer nobody acted on. Once the verdict actually
// reaches the kernel, the same misparse decides whether a process runs.
//
// The kernel's SHADOWSTRIKE_PROCESS_NOTIFICATION opens with an SS_MESSAGE_HEADER
// that PnpSendProcessNotification never populates -- it zeroes the whole buffer and
// fills only the fields after it. The user-mode struct mirrors that dead header
// deliberately, because dropping it would shift every field by 40 bytes and read
// the process id out of the middle of nothing.
TEST(IpcStatisticsContractTest, ProcessNotifyRequestMatchesTheKernelPayload) {
    using ShadowStrike::Communication::ProcessNotifyRequest;

    // Both sides must agree on the fixed part, because the kernel copies the
    // variable-length image path and command line to exactly this offset
    // (BufferPtr = Notification + 1) and user mode reads them from
    // this + sizeof(ProcessNotifyRequest).
    EXPECT_EQ(sizeof(SHADOWSTRIKE_PROCESS_NOTIFICATION), sizeof(ProcessNotifyRequest))
        << "the fixed part is the offset of the variable data; a disagreement here "
           "makes the image path and command line unreadable while every field "
           "still looks plausible";

    // The dead inner header is 40 bytes and the real fields follow it. Pinned so a
    // future 'cleanup' that removes it from one side only fails here rather than in
    // the field.
    EXPECT_EQ(40u, sizeof(SHADOWSTRIKE_MESSAGE_HEADER));
    EXPECT_EQ(40u, offsetof(ProcessNotifyRequest, processId));
    EXPECT_EQ(44u, offsetof(ProcessNotifyRequest, parentProcessId));
    EXPECT_EQ(48u, offsetof(ProcessNotifyRequest, creatingProcessId));
    EXPECT_EQ(52u, offsetof(ProcessNotifyRequest, creatingThreadId));
    EXPECT_EQ(56u, offsetof(ProcessNotifyRequest, isCreation));
    EXPECT_EQ(57u, offsetof(ProcessNotifyRequest, imagePathLength));
    EXPECT_EQ(59u, offsetof(ProcessNotifyRequest, commandLineLength));
    EXPECT_EQ(61u, sizeof(ProcessNotifyRequest));

    // Field-by-field agreement with the kernel declaration, so the two cannot
    // drift independently.
    EXPECT_EQ(offsetof(SHADOWSTRIKE_PROCESS_NOTIFICATION, ProcessId),
              offsetof(ProcessNotifyRequest, processId));
    EXPECT_EQ(offsetof(SHADOWSTRIKE_PROCESS_NOTIFICATION, ParentProcessId),
              offsetof(ProcessNotifyRequest, parentProcessId));
    EXPECT_EQ(offsetof(SHADOWSTRIKE_PROCESS_NOTIFICATION, CreatingProcessId),
              offsetof(ProcessNotifyRequest, creatingProcessId));
    EXPECT_EQ(offsetof(SHADOWSTRIKE_PROCESS_NOTIFICATION, CreatingThreadId),
              offsetof(ProcessNotifyRequest, creatingThreadId));
    EXPECT_EQ(offsetof(SHADOWSTRIKE_PROCESS_NOTIFICATION, Create),
              offsetof(ProcessNotifyRequest, isCreation));
    EXPECT_EQ(offsetof(SHADOWSTRIKE_PROCESS_NOTIFICATION, ImagePathLength),
              offsetof(ProcessNotifyRequest, imagePathLength));
    EXPECT_EQ(offsetof(SHADOWSTRIKE_PROCESS_NOTIFICATION, CommandLineLength),
              offsetof(ProcessNotifyRequest, commandLineLength));
}

// The dispatcher validates the variable-length bounds by subtracting the fixed
// size from DataSize. That subtraction is only safe because the fixed size is
// checked first, and it is only meaningful because the lengths are byte counts of
// wide characters rather than character counts.
TEST(IpcStatisticsContractTest, ProcessNotifyVariableLengthsAreByteCounts) {
    using ShadowStrike::Communication::ProcessNotifyRequest;

    // Lengths are 16-bit, so the largest declarable path cannot exceed what the
    // bounds check can represent after being widened to 32 bits.
    EXPECT_EQ(2u, sizeof(decltype(ProcessNotifyRequest::imagePathLength)));
    EXPECT_EQ(2u, sizeof(decltype(ProcessNotifyRequest::commandLineLength)));

    // A byte count converts to a character count by dividing by sizeof(wchar_t).
    // If these were character counts the accessors would read twice the data they
    // should, straight off the end of the frame.
    alignas(8) unsigned char raw[sizeof(ProcessNotifyRequest) + 16] = {};
    auto* req = reinterpret_cast<ProcessNotifyRequest*>(raw);
    req->imagePathLength = 8;      // 8 BYTES == 4 wide characters
    req->commandLineLength = 6;    // 6 BYTES == 3 wide characters

    EXPECT_EQ(4u, req->imagePathCharLen());
    EXPECT_EQ(3u, req->commandLineCharLen());

    // The command line begins after the image path, not after the struct.
    const auto* base = reinterpret_cast<const unsigned char*>(req);
    EXPECT_EQ(base + sizeof(ProcessNotifyRequest),
              reinterpret_cast<const unsigned char*>(req->imagePathData()));
    EXPECT_EQ(base + sizeof(ProcessNotifyRequest) + 8,
              reinterpret_cast<const unsigned char*>(req->commandLineData()));
}

// ============================================================================
// GENERIC SUBSCRIBER FAN-OUT
// ============================================================================
//
// The generic (non-verdict) kernel message feed used to be a SINGLE
// std::function. Eight modules registered against it - RealTimeProtection,
// ProcessInjectionDetector, AtomBombingDetector, StackPivotDetector,
// ROPProtection, BufferOverflowProtection, FileProtection and SelfDefense - so
// the last registrant silently evicted the other seven and exactly one of eight
// consumers ever saw a kernel event.
//
// HONEST LIMIT, stated because it bounds what these tests prove: DELIVERY runs
// inside IPCManager::DispatchMessage, which needs a loaded driver and a live
// filter port, so it cannot be exercised here. What IS asserted is MEMBERSHIP -
// and membership is precisely where the defect lived. "The last caller wins" is
// a statement about the subscriber list, not about the dispatch loop.
//
// These cases cannot fail against the previous code because the previous API had
// a different signature and no way to ask how many subscribers exist. They
// discriminate instead against the plausible WRONG implementations of this API:
// appending without de-duplicating (every message delivered twice to a module
// that re-initializes), and removing one subscriber by clearing the list (which
// is exactly what SelfDefense and FileProtection each did to the other, via
// RegisterGenericHandler(nullptr) against the old slot).

namespace {

// Every case measures against a baseline rather than an absolute count, so no
// case depends on which other cases have run or on what production code has
// registered in this process.
ShadowStrike::Communication::IPCManager& Ipc() {
    return ShadowStrike::Communication::IPCManager::Instance();
}

auto NoopSubscriber() {
    return [](SHADOWSTRIKE_MESSAGE_TYPE, const void*, size_t) {};
}

}  // namespace

TEST(GenericSubscriberFanOut, EverySubscriberSurvivesTheNextRegistration) {
    const size_t baseline = Ipc().GenericSubscriberCount();

    Ipc().RegisterGenericHandler("fanout.test.first", NoopSubscriber());
    EXPECT_EQ(baseline + 1, Ipc().GenericSubscriberCount());

    Ipc().RegisterGenericHandler("fanout.test.second", NoopSubscriber());
    EXPECT_EQ(baseline + 2, Ipc().GenericSubscriberCount())
        << "A second registration evicted the first: the feed is behaving as a "
           "slot again, which is the defect this fan-out replaced.";

    Ipc().RegisterGenericHandler("fanout.test.third", NoopSubscriber());
    EXPECT_EQ(baseline + 3, Ipc().GenericSubscriberCount());

    Ipc().UnregisterGenericHandler("fanout.test.first");
    Ipc().UnregisterGenericHandler("fanout.test.second");
    Ipc().UnregisterGenericHandler("fanout.test.third");
    EXPECT_EQ(baseline, Ipc().GenericSubscriberCount());
}

TEST(GenericSubscriberFanOut, ReRegisteringOneNameReplacesRatherThanDuplicates) {
    const size_t baseline = Ipc().GenericSubscriberCount();

    Ipc().RegisterGenericHandler("fanout.test.repeat", NoopSubscriber());
    Ipc().RegisterGenericHandler("fanout.test.repeat", NoopSubscriber());
    Ipc().RegisterGenericHandler("fanout.test.repeat", NoopSubscriber());

    EXPECT_EQ(baseline + 1, Ipc().GenericSubscriberCount())
        << "A module that re-initializes accumulated duplicate subscriptions, so "
           "every kernel event would be delivered to it more than once.";

    Ipc().UnregisterGenericHandler("fanout.test.repeat");
    EXPECT_EQ(baseline, Ipc().GenericSubscriberCount());
}

TEST(GenericSubscriberFanOut, RemovingOneSubscriberLeavesTheOthers) {
    const size_t baseline = Ipc().GenericSubscriberCount();

    // SelfDefense and FileProtection both subscribe to SelfProtectAlert, and
    // each used to clear the entire feed on its own teardown. This is that case.
    Ipc().RegisterGenericHandler("fanout.test.keeper", NoopSubscriber());
    Ipc().RegisterGenericHandler("fanout.test.leaver", NoopSubscriber());
    ASSERT_EQ(baseline + 2, Ipc().GenericSubscriberCount());

    Ipc().UnregisterGenericHandler("fanout.test.leaver");

    EXPECT_EQ(baseline + 1, Ipc().GenericSubscriberCount())
        << "Removing one subscriber took others with it - one module's shutdown "
           "would silently disable every other module's kernel event handling.";

    Ipc().UnregisterGenericHandler("fanout.test.keeper");
    EXPECT_EQ(baseline, Ipc().GenericSubscriberCount());
}

TEST(GenericSubscriberFanOut, ANullHandlerFromAKnownSubscriberRemovesOnlyItself) {
    const size_t baseline = Ipc().GenericSubscriberCount();

    Ipc().RegisterGenericHandler("fanout.test.legacyA", NoopSubscriber());
    Ipc().RegisterGenericHandler("fanout.test.legacyB", NoopSubscriber());
    ASSERT_EQ(baseline + 2, Ipc().GenericSubscriberCount());

    // The pre-fan-out unregister idiom was RegisterGenericHandler(nullptr).
    // It is still honoured, but scoped to the caller that names itself.
    Ipc().RegisterGenericHandler("fanout.test.legacyA", nullptr);

    EXPECT_EQ(baseline + 1, Ipc().GenericSubscriberCount());

    Ipc().UnregisterGenericHandler("fanout.test.legacyB");
    EXPECT_EQ(baseline, Ipc().GenericSubscriberCount());
}

TEST(GenericSubscriberFanOut, AnUnnamedSubscriptionIsRefused) {
    const size_t baseline = Ipc().GenericSubscriberCount();

    // An unnamed subscriber can never be removed and can never be attributed in
    // a log. Accepting one reintroduces the condition that made the original
    // defect invisible: every registrant logged an identical line.
    Ipc().RegisterGenericHandler("", NoopSubscriber());

    EXPECT_EQ(baseline, Ipc().GenericSubscriberCount());
}

TEST(GenericSubscriberFanOut, UnregisteringAnUnknownNameIsHarmless) {
    const size_t baseline = Ipc().GenericSubscriberCount();

    Ipc().UnregisterGenericHandler("fanout.test.neverRegistered");

    EXPECT_EQ(baseline, Ipc().GenericSubscriberCount())
        << "A shutdown path whose name disagrees with its registration path must "
           "not be able to damage the feed.";
}
