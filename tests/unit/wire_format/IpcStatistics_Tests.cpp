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

    // A LIVE SUBSCRIBER IS REGISTERED FIRST ON PURPOSE. Asserting only that an
    // empty feed stays empty cannot fail: if UnregisterGenericHandler cleared
    // the whole list instead of matching one name, a zero baseline would still
    // read zero afterwards and the test would pass while the feed was being
    // destroyed. The survivor is what makes this observable.
    Ipc().RegisterGenericHandler("fanout.test.bystander", NoopSubscriber());
    ASSERT_EQ(baseline + 1, Ipc().GenericSubscriberCount());

    Ipc().UnregisterGenericHandler("fanout.test.neverRegistered");

    EXPECT_EQ(baseline + 1, Ipc().GenericSubscriberCount())
        << "A shutdown path whose name disagrees with its registration path must "
           "not be able to damage the feed.";

    Ipc().UnregisterGenericHandler("fanout.test.bystander");
    EXPECT_EQ(baseline, Ipc().GenericSubscriberCount());
}

// ============================================================================
// REGISTRY SUBSCRIBER FAN-OUT
// ============================================================================
//
// RegisterRegistryHandler used to assign a single member, and TWO production
// modules registered against it: RealTimeProtection (from Start()) and
// RegistryProtection (from Initialize()). AntivirusService runs
// Impl::Initialize() before Impl::Start() at all three of its call sites, so
// RegistryProtection registered first and was silently evicted on every single
// startup, taking its whole kernel-event pipeline with it.
//
// SAME HONEST LIMIT AS THE GENERIC SUITE: delivery runs inside DispatchMessage,
// which needs a loaded driver and a live filter port, so these cases assert
// MEMBERSHIP. That is where the defect lived - "the last caller wins" is a
// statement about the subscriber list, not about the dispatch loop.

namespace {

auto NoopRegistrySubscriber() {
    return [](const ShadowStrike::Communication::RegistryOpRequest&) -> SHADOWSTRIKE_SCAN_VERDICT {
        return Verdict_Clean;
    };
}

}  // namespace

TEST(RegistrySubscriberFanOut, EverySubscriberSurvivesTheNextRegistration) {
    const size_t baseline = Ipc().RegistrySubscriberCount();

    Ipc().RegisterRegistryHandler("regfanout.test.first", NoopRegistrySubscriber());
    Ipc().RegisterRegistryHandler("regfanout.test.second", NoopRegistrySubscriber());

    // THE FIELD SYMPTOM, stated as an assertion: two registrations must produce
    // two subscribers. Before this change the second call overwrote the first
    // and the count could never exceed one.
    EXPECT_EQ(baseline + 2, Ipc().RegistrySubscriberCount());

    Ipc().UnregisterRegistryHandler("regfanout.test.first");
    Ipc().UnregisterRegistryHandler("regfanout.test.second");
    EXPECT_EQ(baseline, Ipc().RegistrySubscriberCount());
}

TEST(RegistrySubscriberFanOut, ReRegisteringOneNameReplacesRatherThanDuplicates) {
    const size_t baseline = Ipc().RegistrySubscriberCount();

    Ipc().RegisterRegistryHandler("regfanout.test.repeat", NoopRegistrySubscriber());
    Ipc().RegisterRegistryHandler("regfanout.test.repeat", NoopRegistrySubscriber());

    // A module that re-initializes must not accumulate duplicate deliveries.
    EXPECT_EQ(baseline + 1, Ipc().RegistrySubscriberCount());

    Ipc().UnregisterRegistryHandler("regfanout.test.repeat");
    EXPECT_EQ(baseline, Ipc().RegistrySubscriberCount());
}

TEST(RegistrySubscriberFanOut, RemovingOneSubscriberLeavesTheOthers) {
    const size_t baseline = Ipc().RegistrySubscriberCount();

    Ipc().RegisterRegistryHandler("regfanout.test.keep", NoopRegistrySubscriber());
    Ipc().RegisterRegistryHandler("regfanout.test.drop", NoopRegistrySubscriber());
    ASSERT_EQ(baseline + 2, Ipc().RegistrySubscriberCount());

    Ipc().UnregisterRegistryHandler("regfanout.test.drop");

    // RegistryProtection's teardown used to call RegisterRegistryHandler(nullptr),
    // which cleared the SLOT - so self-protection shutting down disabled kernel
    // registry dispatch for every other module. Self-protection shutdown is
    // exactly what an attacker triggers first.
    EXPECT_EQ(baseline + 1, Ipc().RegistrySubscriberCount());

    Ipc().UnregisterRegistryHandler("regfanout.test.keep");
    EXPECT_EQ(baseline, Ipc().RegistrySubscriberCount());
}

TEST(RegistrySubscriberFanOut, ANullHandlerFromAKnownSubscriberRemovesOnlyItself) {
    const size_t baseline = Ipc().RegistrySubscriberCount();

    Ipc().RegisterRegistryHandler("regfanout.test.legacyA", NoopRegistrySubscriber());
    Ipc().RegisterRegistryHandler("regfanout.test.legacyB", NoopRegistrySubscriber());
    ASSERT_EQ(baseline + 2, Ipc().RegistrySubscriberCount());

    // The legacy idiom is still honoured, but scoped to its caller.
    Ipc().RegisterRegistryHandler("regfanout.test.legacyA", nullptr);

    EXPECT_EQ(baseline + 1, Ipc().RegistrySubscriberCount());

    Ipc().UnregisterRegistryHandler("regfanout.test.legacyB");
    EXPECT_EQ(baseline, Ipc().RegistrySubscriberCount());
}

TEST(RegistrySubscriberFanOut, AnUnnamedSubscriptionIsRefused) {
    const size_t baseline = Ipc().RegistrySubscriberCount();

    Ipc().RegisterRegistryHandler("", NoopRegistrySubscriber());

    EXPECT_EQ(baseline, Ipc().RegistrySubscriberCount());
}

TEST(RegistrySubscriberFanOut, UnregisteringAnUnknownNameIsHarmless) {
    const size_t baseline = Ipc().RegistrySubscriberCount();

    // Live subscriber first, for the same reason as the generic case above: an
    // assertion that an empty feed stays empty cannot detect an Unregister that
    // clears everything.
    Ipc().RegisterRegistryHandler("regfanout.test.bystander", NoopRegistrySubscriber());
    ASSERT_EQ(baseline + 1, Ipc().RegistrySubscriberCount());

    Ipc().UnregisterRegistryHandler("regfanout.test.neverRegistered");

    EXPECT_EQ(baseline + 1, Ipc().RegistrySubscriberCount())
        << "Unregistering an unknown name removed a subscriber that was there.";

    Ipc().UnregisterRegistryHandler("regfanout.test.bystander");
    EXPECT_EQ(baseline, Ipc().RegistrySubscriberCount());
}

// ============================================================================
// REGISTRY VERDICT COMBINATION
// ============================================================================
//
// Fanning out a VERDICT-returning callback needs a combining rule, and the
// obvious implementation is wrong. These cases pin the rule and, more
// importantly, pin the reason it cannot be simplified.

TEST(RegistryVerdictCombination, TheEnumsOwnOrderWouldGiveTheWrongAnswer) {
    // THIS CASE EXISTS TO DOCUMENT THE TRAP, so a future reader who wants to
    // replace CombineKernelVerdicts with std::max can see why that fails
    // before they try it. SHADOWSTRIKE_SCAN_VERDICT is declared in
    // detection-vocabulary order, NOT severity order.
    EXPECT_GT(static_cast<int>(Verdict_Timeout), static_cast<int>(Verdict_Malicious));
    EXPECT_GT(static_cast<int>(Verdict_Error), static_cast<int>(Verdict_Malicious));
    EXPECT_GT(static_cast<int>(Verdict_Suspicious), static_cast<int>(Verdict_Malicious));

    // So a numeric maximum would rank a transient failure above a conviction.
    // The combiner must not.
    EXPECT_EQ(Verdict_Malicious,
              ShadowStrike::Communication::IPCManager::CombineKernelVerdicts(
                  Verdict_Malicious, Verdict_Timeout));
}

TEST(RegistryVerdictCombination, MaliciousOutranksEveryOtherVerdict) {
    using Ipc_ = ShadowStrike::Communication::IPCManager;

    // Malicious is the only value the driver turns into STATUS_ACCESS_DENIED, so
    // a subscriber asking to deny must never be overruled by another subscriber
    // reporting that it saw nothing.
    for (const auto other : { Verdict_Unknown, Verdict_Clean, Verdict_Suspicious,
                              Verdict_Error, Verdict_Timeout }) {
        EXPECT_EQ(Verdict_Malicious, Ipc_::CombineKernelVerdicts(Verdict_Malicious, other))
            << "Malicious lost to verdict " << static_cast<int>(other);
        EXPECT_EQ(Verdict_Malicious, Ipc_::CombineKernelVerdicts(other, Verdict_Malicious))
            << "Malicious lost to verdict " << static_cast<int>(other) << " (reversed)";
    }
}

TEST(RegistryVerdictCombination, CombinationIsOrderIndependent) {
    using Ipc_ = ShadowStrike::Communication::IPCManager;

    // A subscriber list is a set, not a sequence. If the combined verdict
    // depended on registration order it would reintroduce exactly the property
    // being removed: an answer decided by who happened to register last.
    constexpr SHADOWSTRIKE_SCAN_VERDICT all[] = {
        Verdict_Unknown, Verdict_Clean, Verdict_Malicious,
        Verdict_Suspicious, Verdict_Error, Verdict_Timeout
    };
    for (const auto a : all) {
        for (const auto b : all) {
            EXPECT_EQ(Ipc_::CombineKernelVerdicts(a, b),
                      Ipc_::CombineKernelVerdicts(b, a))
                << "Asymmetric for a=" << static_cast<int>(a)
                << " b=" << static_cast<int>(b);
        }
    }
}

TEST(RegistryVerdictCombination, CleanIsTheIdentityAndUnknownIsNotDiscarded) {
    using Ipc_ = ShadowStrike::Communication::IPCManager;

    // Clean is the seed the fan-out starts from, so it must be the identity:
    // otherwise a single quiet subscriber would set a floor on the result.
    for (const auto other : { Verdict_Unknown, Verdict_Malicious, Verdict_Suspicious,
                              Verdict_Error, Verdict_Timeout }) {
        EXPECT_EQ(other, Ipc_::CombineKernelVerdicts(Verdict_Clean, other))
            << "Clean altered verdict " << static_cast<int>(other);
    }

    // And an undetermined answer must outrank a clean one - "I could not tell"
    // is not evidence of cleanliness, the same rule the trust path follows.
    EXPECT_EQ(Verdict_Unknown, Ipc_::CombineKernelVerdicts(Verdict_Clean, Verdict_Unknown));
}

// ============================================================================
// PROCESS AND IMAGE-LOAD SUBSCRIBER FAN-OUT
// ============================================================================
//
// The last two single-assignment verdict slots. Both were contested by two
// production modules and both resolved by "whoever registered last", with no
// log line naming either party:
//
//   ProcessNotify  RealTimeProtection.cpp:1357  vs  ProcessMonitor.cpp:1623
//   ImageLoad      RealTimeProtection.cpp:1361  vs  ReflectiveDLLDetector.cpp:2542
//
// Both contests were LATENT rather than active, and that was measured rather
// than hoped: nothing in production calls ProcessMonitor::Initialize() or
// ReflectiveDLLDetector::Instance().Initialize(). So unlike the registry slot
// these had not yet cost coverage - they were armed, not fired. Wiring either
// module up would have silently replaced RealTimeProtection's process analysis
// or its image-load analysis wholesale.
//
// DELIBERATELY NOT MIRRORED CASE-FOR-CASE from the registry suite. The four
// feeds now share ONE implementation (UpsertNamedSubscriber), and cross-wiring
// one feed's member into another feed's registration cannot compile because the
// subscription types differ. What is worth asserting is what the type system
// does NOT check: that each feed is additive in its own right, and that the
// shared helper keeps the four feeds independent.

namespace {

auto NoopProcessSubscriber() {
    return [](const ShadowStrike::Communication::ProcessNotifyRequest&)
               -> SHADOWSTRIKE_SCAN_VERDICT { return Verdict_Clean; };
}

auto NoopImageLoadSubscriber() {
    return [](const ShadowStrike::Communication::ImageLoadRequest&)
               -> SHADOWSTRIKE_SCAN_VERDICT { return Verdict_Clean; };
}

}  // namespace

TEST(ProcessSubscriberFanOut, EverySubscriberSurvivesTheNextRegistration) {
    const size_t baseline = Ipc().ProcessSubscriberCount();

    Ipc().RegisterProcessHandler("procfanout.test.first", NoopProcessSubscriber());
    EXPECT_EQ(baseline + 1, Ipc().ProcessSubscriberCount());

    Ipc().RegisterProcessHandler("procfanout.test.second", NoopProcessSubscriber());
    EXPECT_EQ(baseline + 2, Ipc().ProcessSubscriberCount())
        << "A second registration evicted the first. On THIS feed that is the "
           "difference between the kernel receiving a considered verdict and "
           "receiving one module's opinion while another module's detector is "
           "silently dead.";

    Ipc().UnregisterProcessHandler("procfanout.test.first");
    Ipc().UnregisterProcessHandler("procfanout.test.second");
    EXPECT_EQ(baseline, Ipc().ProcessSubscriberCount());
}

TEST(ProcessSubscriberFanOut, ReRegisteringOneNameReplacesRatherThanDuplicates) {
    const size_t baseline = Ipc().ProcessSubscriberCount();

    Ipc().RegisterProcessHandler("procfanout.test.repeat", NoopProcessSubscriber());
    Ipc().RegisterProcessHandler("procfanout.test.repeat", NoopProcessSubscriber());

    // This is what makes an RTP Stop()/Start() cycle safe: InitializeIPCManager
    // re-registers on every Start() and nothing in production ever calls
    // UnregisterHandlers(), so without same-name replacement a restart would
    // accumulate a duplicate subscriber and the kernel would pay for RTP's
    // whole process analysis twice inside one reply budget.
    EXPECT_EQ(baseline + 1, Ipc().ProcessSubscriberCount())
        << "Re-registering one name duplicated the subscriber instead of "
           "replacing it.";

    Ipc().UnregisterProcessHandler("procfanout.test.repeat");
    EXPECT_EQ(baseline, Ipc().ProcessSubscriberCount());
}

TEST(ProcessSubscriberFanOut, RemovingOneSubscriberLeavesTheOthers) {
    const size_t baseline = Ipc().ProcessSubscriberCount();

    Ipc().RegisterProcessHandler("procfanout.test.keep", NoopProcessSubscriber());
    Ipc().RegisterProcessHandler("procfanout.test.drop", NoopProcessSubscriber());
    ASSERT_EQ(baseline + 2, Ipc().ProcessSubscriberCount());

    Ipc().UnregisterProcessHandler("procfanout.test.drop");
    EXPECT_EQ(baseline + 1, Ipc().ProcessSubscriberCount())
        << "Removing one subscriber cleared more than itself - the teardown "
           "defect that made a self-protection shutdown disable a feed for "
           "every other module.";

    Ipc().UnregisterProcessHandler("procfanout.test.keep");
    EXPECT_EQ(baseline, Ipc().ProcessSubscriberCount());
}

TEST(ProcessSubscriberFanOut, AnUnnamedSubscriptionIsRefused) {
    const size_t baseline = Ipc().ProcessSubscriberCount();

    Ipc().RegisterProcessHandler("", NoopProcessSubscriber());

    EXPECT_EQ(baseline, Ipc().ProcessSubscriberCount())
        << "An unnamed subscriber was accepted. It could never be removed or "
           "attributed in a log, which is the condition that kept the original "
           "evictions invisible.";
}

TEST(ImageLoadSubscriberFanOut, EverySubscriberSurvivesTheNextRegistration) {
    const size_t baseline = Ipc().ImageLoadSubscriberCount();

    Ipc().RegisterImageLoadHandler("imgfanout.test.first", NoopImageLoadSubscriber());
    Ipc().RegisterImageLoadHandler("imgfanout.test.second", NoopImageLoadSubscriber());

    EXPECT_EQ(baseline + 2, Ipc().ImageLoadSubscriberCount())
        << "A second registration evicted the first on the highest-frequency "
           "kernel feed in the product.";

    Ipc().UnregisterImageLoadHandler("imgfanout.test.first");
    Ipc().UnregisterImageLoadHandler("imgfanout.test.second");
    EXPECT_EQ(baseline, Ipc().ImageLoadSubscriberCount());
}

TEST(ImageLoadSubscriberFanOut, ANullHandlerFromAKnownSubscriberRemovesOnlyItself) {
    const size_t baseline = Ipc().ImageLoadSubscriberCount();

    Ipc().RegisterImageLoadHandler("imgfanout.test.stay", NoopImageLoadSubscriber());
    Ipc().RegisterImageLoadHandler("imgfanout.test.legacy", NoopImageLoadSubscriber());
    ASSERT_EQ(baseline + 2, Ipc().ImageLoadSubscriberCount());

    // The legacy Register(nullptr) teardown idiom, which used to clear the
    // whole slot. Honoured, but scoped to its caller.
    Ipc().RegisterImageLoadHandler("imgfanout.test.legacy", nullptr);
    EXPECT_EQ(baseline + 1, Ipc().ImageLoadSubscriberCount())
        << "A null handler cleared the feed rather than removing its own "
           "subscription.";

    Ipc().UnregisterImageLoadHandler("imgfanout.test.stay");
    EXPECT_EQ(baseline, Ipc().ImageLoadSubscriberCount());
}

TEST(ImageLoadSubscriberFanOut, UnregisteringAnUnknownNameIsHarmless) {
    const size_t baseline = Ipc().ImageLoadSubscriberCount();

    // A live subscriber has to be present for this to be able to fail at all.
    // Asserting that an empty feed stays empty would pass even if Unregister
    // cleared the entire list, which is the defect worth guarding against here.
    Ipc().RegisterImageLoadHandler("imgfanout.test.bystander", NoopImageLoadSubscriber());
    ASSERT_EQ(baseline + 1, Ipc().ImageLoadSubscriberCount());

    Ipc().UnregisterImageLoadHandler("imgfanout.test.never.registered");

    EXPECT_EQ(baseline + 1, Ipc().ImageLoadSubscriberCount())
        << "Unregistering a name that was never subscribed removed a live "
           "subscriber - a mismatched shutdown path must not damage the feed.";

    Ipc().UnregisterImageLoadHandler("imgfanout.test.bystander");
    EXPECT_EQ(baseline, Ipc().ImageLoadSubscriberCount());
}

TEST(SubscriberFeedsAreIndependent, RegisteringOnOneFeedDoesNotDisturbTheOthers) {
    // THE PROPERTY THE SHARED HELPER HAS TO PRESERVE. All four feeds now route
    // through one UpsertNamedSubscriber template, which is deliberate - four
    // copies of these semantics is how this codebase has drifted before. The
    // risk that trade introduces is a feed being wired to the wrong member, so
    // this asserts the thing a reader most needs to be true: each feed's
    // membership answers only for itself.
    const size_t procBase = Ipc().ProcessSubscriberCount();
    const size_t imgBase  = Ipc().ImageLoadSubscriberCount();
    const size_t regBase  = Ipc().RegistrySubscriberCount();
    const size_t genBase  = Ipc().GenericSubscriberCount();

    Ipc().RegisterProcessHandler("independence.test", NoopProcessSubscriber());
    EXPECT_EQ(procBase + 1, Ipc().ProcessSubscriberCount());
    EXPECT_EQ(imgBase,  Ipc().ImageLoadSubscriberCount()) << "process leaked into image-load";
    EXPECT_EQ(regBase,  Ipc().RegistrySubscriberCount())  << "process leaked into registry";
    EXPECT_EQ(genBase,  Ipc().GenericSubscriberCount())   << "process leaked into generic";

    Ipc().RegisterImageLoadHandler("independence.test", NoopImageLoadSubscriber());
    EXPECT_EQ(imgBase + 1,  Ipc().ImageLoadSubscriberCount());
    EXPECT_EQ(procBase + 1, Ipc().ProcessSubscriberCount()) << "image-load disturbed process";
    EXPECT_EQ(regBase,      Ipc().RegistrySubscriberCount());
    EXPECT_EQ(genBase,      Ipc().GenericSubscriberCount());

    Ipc().RegisterRegistryHandler("independence.test", NoopRegistrySubscriber());
    Ipc().RegisterGenericHandler("independence.test", NoopSubscriber());
    EXPECT_EQ(regBase + 1, Ipc().RegistrySubscriberCount());
    EXPECT_EQ(genBase + 1, Ipc().GenericSubscriberCount());

    // The same name on four feeds must be four independent subscriptions, so
    // removing it from one must leave the other three intact.
    Ipc().UnregisterProcessHandler("independence.test");
    EXPECT_EQ(procBase,     Ipc().ProcessSubscriberCount());
    EXPECT_EQ(imgBase + 1,  Ipc().ImageLoadSubscriberCount())
        << "Unregistering one feed removed a same-named subscriber from another.";
    EXPECT_EQ(regBase + 1,  Ipc().RegistrySubscriberCount());
    EXPECT_EQ(genBase + 1,  Ipc().GenericSubscriberCount());

    Ipc().UnregisterImageLoadHandler("independence.test");
    Ipc().UnregisterRegistryHandler("independence.test");
    Ipc().UnregisterGenericHandler("independence.test");
    EXPECT_EQ(imgBase, Ipc().ImageLoadSubscriberCount());
    EXPECT_EQ(regBase, Ipc().RegistrySubscriberCount());
    EXPECT_EQ(genBase, Ipc().GenericSubscriberCount());
}
