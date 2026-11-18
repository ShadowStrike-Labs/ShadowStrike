/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for RealTime\RealTimeProtection deterministic contracts.
 *
 * Focus:
 *   - RTP preset factories and statistics/performance reset helpers
 *   - exclusion/cache/status accessors that are safe without full initialization
 *   - callback registration and unregistration contracts
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "../../../src/PhantomCore/RealTime/RealTimeProtection.hpp"
#include "RealTime_TestUtils.hpp"

namespace ShadowStrike::RealTime::Tests {

class RealTimeProtectionTest : public ::testing::Test {
protected:
    RealTimeProtection& rtp = RealTimeProtection::Instance();

    void SetUp() override {
        rtp.Stop();
        rtp.ClearAllExclusions();
        rtp.ClearVerdictCache();
        rtp.ResetStatistics();
    }

    void TearDown() override {
        rtp.ClearAllExclusions();
        rtp.ClearVerdictCache();
        rtp.Stop();
    }
};

TEST_F(RealTimeProtectionTest, ConfigFactoriesAndResetHelpersRemainStable) {
    const auto defaults = RTPConfig::CreateDefault();
    const auto highSecurity = RTPConfig::CreateHighSecurity();
    const auto highPerformance = RTPConfig::CreateHighPerformance();
    const auto server = RTPConfig::CreateServerOptimized();
    const auto workstation = RTPConfig::CreateWorkstationOptimized();

    EXPECT_TRUE(defaults.enabled);
    EXPECT_EQ(ProtectionMode::BLOCK_KNOWN, defaults.mode);
    EXPECT_EQ(FailurePolicy::FAIL_OPEN, defaults.failurePolicy);

    EXPECT_EQ(ProtectionMode::BLOCK_UNKNOWN, highSecurity.mode);
    EXPECT_EQ(FailurePolicy::FAIL_CLOSED, highSecurity.failurePolicy);
    EXPECT_TRUE(highSecurity.scanOnWrite);
    EXPECT_TRUE(highSecurity.scanOnRename);
    EXPECT_TRUE(highSecurity.inspectHTTPS);
    EXPECT_EQ(120000u, highSecurity.scanTimeoutMs);

    EXPECT_EQ(ProtectionMode::BLOCK_KNOWN, highPerformance.mode);
    EXPECT_FALSE(highPerformance.scanOnWrite);
    EXPECT_FALSE(highPerformance.scanArchives);
    EXPECT_TRUE(highPerformance.throttleOnHighCPU);
    EXPECT_EQ(2u, highPerformance.maxConcurrentScans);

    EXPECT_TRUE(server.scanOnWrite);
    EXPECT_TRUE(server.scanOnExecute);
    EXPECT_TRUE(server.monitorProcessCreation);

    EXPECT_EQ(ProtectionMode::BLOCK_SUSPICIOUS, workstation.mode);
    EXPECT_TRUE(workstation.scanOnOpen);
    EXPECT_TRUE(workstation.scanOnExecute);
    EXPECT_TRUE(workstation.monitorProcessCreation);

    PerformanceMetrics metrics;
    metrics.totalScans.store(5, std::memory_order_relaxed);
    metrics.cacheHits.store(2, std::memory_order_relaxed);
    metrics.pendingScanQueue.store(3, std::memory_order_relaxed);
    metrics.kernelErrors.store(1, std::memory_order_relaxed);
    metrics.Reset();

    EXPECT_EQ(0u, metrics.totalScans.load(std::memory_order_relaxed));
    EXPECT_EQ(0u, metrics.cacheHits.load(std::memory_order_relaxed));
    EXPECT_EQ(0u, metrics.pendingScanQueue.load(std::memory_order_relaxed));
    EXPECT_EQ(0u, metrics.kernelErrors.load(std::memory_order_relaxed));

    RTPStatistics stats;
    stats.totalEvents.store(11, std::memory_order_relaxed);
    stats.filesBlocked.store(4, std::memory_order_relaxed);
    stats.threatsDetected.store(7, std::memory_order_relaxed);
    stats.kernelThreatAlerts.store(5, std::memory_order_relaxed);
    stats.kernelTelemetryEvents.store(6, std::memory_order_relaxed);
    stats.performance.cacheSize.store(9, std::memory_order_relaxed);
    stats.Reset();

    EXPECT_EQ(0u, stats.totalEvents.load(std::memory_order_relaxed));
    EXPECT_EQ(0u, stats.filesBlocked.load(std::memory_order_relaxed));
    EXPECT_EQ(0u, stats.threatsDetected.load(std::memory_order_relaxed));
    // A counter absent from Reset() keeps its pre-reset value, which makes every
    // rate computed after a reset wrong in a way nothing reports.
    EXPECT_EQ(0u, stats.kernelThreatAlerts.load(std::memory_order_relaxed));
    EXPECT_EQ(0u, stats.kernelTelemetryEvents.load(std::memory_order_relaxed));
    EXPECT_EQ(0u, stats.performance.cacheSize.load(std::memory_order_relaxed));
}

TEST_F(RealTimeProtectionTest, StatusExclusionAndCacheAccessorsRemainSafe) {
    EXPECT_EQ(ProtectionState::UNINITIALIZED, rtp.GetState());
    EXPECT_EQ(rtp.GetStatus().state, rtp.GetState());
    EXPECT_EQ(rtp.GetStatus().mode, rtp.GetProtectionMode());
    EXPECT_EQ(static_cast<size_t>(ComponentType::COMPONENT_COUNT), rtp.GetStatus().components.size());

    const ComponentStatus invalidComponent = rtp.GetComponentStatus(ComponentType::COMPONENT_COUNT);
    EXPECT_EQ(ComponentType::COMPONENT_COUNT, invalidComponent.type);
    EXPECT_EQ(ProtectionComponentState::UNINITIALIZED, invalidComponent.state);

    EXPECT_TRUE(rtp.AddPathExclusion(L"C:\\Trusted"));
    EXPECT_TRUE(rtp.AddPathExclusion(L"C:\\Trusted"));
    EXPECT_TRUE(rtp.AddProcessExclusion(L"trusted.exe"));
    EXPECT_TRUE(rtp.AddProcessExclusion(L"trusted.exe"));
    EXPECT_TRUE(rtp.AddHashExclusion(L"deadbeef"));
    EXPECT_TRUE(rtp.AddHashExclusion(L"deadbeef"));

    const auto exclusions = rtp.GetExclusions();
    EXPECT_EQ(2u, exclusions.at(L"paths").size());
    EXPECT_EQ(2u, exclusions.at(L"processes").size());
    EXPECT_EQ(2u, exclusions.at(L"hashes").size());
    EXPECT_TRUE(exclusions.contains(L"extensions"));

    std::array<uint8_t, 32> zeroHash{};
    EXPECT_FALSE(rtp.QueryVerdictCache(zeroHash).has_value());
    EXPECT_EQ(0u, rtp.GetCacheSize());

    EXPECT_FALSE(rtp.RemovePathExclusion(L"C:\\Missing"));
    EXPECT_FALSE(rtp.RemoveProcessExclusion(L"missing.exe"));
    EXPECT_FALSE(rtp.RemoveHashExclusion(L"missing"));

    rtp.ClearAllExclusions();
    EXPECT_TRUE(rtp.GetExclusions().at(L"paths").empty());
    EXPECT_TRUE(rtp.GetExclusions().at(L"processes").empty());
    EXPECT_TRUE(rtp.GetExclusions().at(L"hashes").empty());
}

TEST_F(RealTimeProtectionTest, CallbackRegistrationAndUnregistrationRemainDeterministic) {
    RTPConfig updated = RTPConfig::CreateHighSecurity();
    updated.scanOnOpen = false;
    updated.mode = ProtectionMode::BLOCK_SUSPICIOUS;
    ASSERT_TRUE(rtp.UpdateConfig(updated));
    EXPECT_FALSE(rtp.GetConfig().scanOnOpen);
    EXPECT_EQ(ProtectionMode::BLOCK_SUSPICIOUS, rtp.GetProtectionMode());

    rtp.SetProtectionMode(ProtectionMode::MONITOR_ONLY);
    EXPECT_EQ(ProtectionMode::MONITOR_ONLY, rtp.GetProtectionMode());
    EXPECT_EQ(ProtectionMode::MONITOR_ONLY, rtp.GetConfig().mode);
    EXPECT_FALSE(rtp.Pause(0, L"not-started"));
    EXPECT_FALSE(rtp.Resume());

    const uint64_t nullFileScanId = rtp.RegisterFileScanCallback({});
    const uint64_t nullProcessId = rtp.RegisterProcessNotifyCallback({});
    const uint64_t nullThreatId = rtp.RegisterThreatDetectionCallback({});
    const uint64_t nullStateId = rtp.RegisterStateChangeCallback({});
    const uint64_t nullComponentId = rtp.RegisterComponentStatusCallback({});
    const uint64_t nullNotificationId = rtp.RegisterNotificationCallback({});
    const uint64_t fileScanId = rtp.RegisterFileScanCallback(
        [](const RTPFileScanRequest&, ScanResult&) { return false; });
    const uint64_t processId = rtp.RegisterProcessNotifyCallback(
        [](const RTPProcessNotifyRequest&, bool&) {});
    const uint64_t threatId = rtp.RegisterThreatDetectionCallback(
        [](const ThreatEvent&) {});
    const uint64_t stateId = rtp.RegisterStateChangeCallback(
        [](ProtectionState, ProtectionState, std::wstring_view) {});
    const uint64_t componentId = rtp.RegisterComponentStatusCallback(
        [](ComponentType, ProtectionComponentState, ProtectionComponentState) {});
    const uint64_t notificationId = rtp.RegisterNotificationCallback(
        [](NotificationSeverity, std::wstring_view, std::wstring_view,
            const std::optional<ThreatEvent>&) {});

    // An EMPTY callback is REFUSED and 0 is the invalid-id sentinel this test already
    // uses for everything else. These asserted the opposite - that registering {} hands
    // back a live id - which would mean the protection engine later invokes an empty
    // std::function and throws bad_function_call on a path that owes the kernel a
    // verdict. Refusing at registration is the only safe answer, so the registry never
    // holds a callback that cannot be called.
    EXPECT_EQ(0u, nullFileScanId);
    EXPECT_EQ(0u, nullProcessId);
    EXPECT_EQ(0u, nullThreatId);
    EXPECT_EQ(0u, nullStateId);
    EXPECT_EQ(0u, nullComponentId);
    EXPECT_EQ(0u, nullNotificationId);
    EXPECT_NE(0u, fileScanId);
    EXPECT_NE(0u, processId);
    EXPECT_NE(0u, threatId);
    EXPECT_NE(0u, stateId);
    EXPECT_NE(0u, componentId);
    EXPECT_NE(0u, notificationId);

    EXPECT_FALSE(rtp.UnregisterCallback(nullFileScanId));
    // Unregistering an id that was never issued fails, and 0 is never issued - the same
    // reasoning as the block above, and consistent with the last line of this test,
    // which already requires a second unregister of a real id to return false.
    EXPECT_FALSE(rtp.UnregisterCallback(nullProcessId));
    EXPECT_FALSE(rtp.UnregisterCallback(nullThreatId));
    EXPECT_FALSE(rtp.UnregisterCallback(nullStateId));
    EXPECT_FALSE(rtp.UnregisterCallback(nullComponentId));
    EXPECT_FALSE(rtp.UnregisterCallback(nullNotificationId));
    EXPECT_TRUE(rtp.UnregisterCallback(fileScanId));
    EXPECT_TRUE(rtp.UnregisterCallback(processId));
    EXPECT_TRUE(rtp.UnregisterCallback(threatId));
    EXPECT_TRUE(rtp.UnregisterCallback(stateId));
    EXPECT_TRUE(rtp.UnregisterCallback(componentId));
    EXPECT_TRUE(rtp.UnregisterCallback(notificationId));
    EXPECT_FALSE(rtp.UnregisterCallback(notificationId));
}

// ---------------------------------------------------------------------------
// Task 186: the off-thread process-notify fan-out queue admission policy.
//
// AdmitProcessNotifyEvent is the pure, lock-free core of the bounded hand-off
// that moves the ransomware/script fan-out off the thread the kernel blocks
// CreateProcess on. These cases pin the three properties task 186 requires of
// it: a bound that never grows, counted drop-OLDEST on overflow, and FIFO order
// so a pid's create is drained before its exit (FileBackupManager depends on it).
// ---------------------------------------------------------------------------

namespace {

ProcessNotifyEvent MakeEvent(std::uint32_t pid, bool isCreation) {
    ProcessNotifyEvent ev;
    ev.pid = pid;
    ev.parentPid = 4;
    ev.imagePath = L"C:\\Windows\\System32\\vssadmin.exe";
    ev.commandLine = L"vssadmin delete shadows /all /quiet";
    ev.isCreation = isCreation;
    return ev;
}

}  // namespace

TEST(ProcessNotifyQueueAdmission, AdmitsBelowCapacityWithoutDropping) {
    std::deque<ProcessNotifyEvent> q;
    EXPECT_FALSE(Detail::AdmitProcessNotifyEvent(q, MakeEvent(100, true), 4));
    EXPECT_FALSE(Detail::AdmitProcessNotifyEvent(q, MakeEvent(101, true), 4));
    EXPECT_EQ(2u, q.size());
    // FIFO: first admitted is at the front, newest at the back.
    EXPECT_EQ(100u, q.front().pid);
    EXPECT_EQ(101u, q.back().pid);
}

TEST(ProcessNotifyQueueAdmission, OverflowDropsTheOldestAndReportsIt) {
    std::deque<ProcessNotifyEvent> q;
    constexpr std::size_t cap = 3;
    EXPECT_FALSE(Detail::AdmitProcessNotifyEvent(q, MakeEvent(1, true), cap));
    EXPECT_FALSE(Detail::AdmitProcessNotifyEvent(q, MakeEvent(2, true), cap));
    EXPECT_FALSE(Detail::AdmitProcessNotifyEvent(q, MakeEvent(3, true), cap));
    EXPECT_EQ(cap, q.size());

    // At capacity, the next admission must evict the OLDEST (pid 1) and say so.
    EXPECT_TRUE(Detail::AdmitProcessNotifyEvent(q, MakeEvent(4, true), cap));
    EXPECT_EQ(cap, q.size());      // capped, never grows
    EXPECT_EQ(2u, q.front().pid);  // pid 1 (oldest) was dropped, not pid 3/4
    EXPECT_EQ(4u, q.back().pid);   // newest retained

    // A second overflow drops the new oldest (pid 2) and again reports a drop.
    EXPECT_TRUE(Detail::AdmitProcessNotifyEvent(q, MakeEvent(5, true), cap));
    EXPECT_EQ(cap, q.size());
    EXPECT_EQ(3u, q.front().pid);
    EXPECT_EQ(5u, q.back().pid);
}

TEST(ProcessNotifyQueueAdmission, DrainsInFifoOrderSoCreatePrecedesExit) {
    std::deque<ProcessNotifyEvent> q;
    constexpr std::size_t cap = 8;
    Detail::AdmitProcessNotifyEvent(q, MakeEvent(10, true),  cap);  // 10 create
    Detail::AdmitProcessNotifyEvent(q, MakeEvent(11, true),  cap);  // 11 create
    Detail::AdmitProcessNotifyEvent(q, MakeEvent(10, false), cap);  // 10 exit
    ASSERT_EQ(3u, q.size());

    // The worker drains front-to-back; pid 10's create must come out before its
    // exit, the ordering FileBackupManager's exit-side commit depends on.
    EXPECT_EQ(10u, q[0].pid); EXPECT_TRUE(q[0].isCreation);
    EXPECT_EQ(11u, q[1].pid); EXPECT_TRUE(q[1].isCreation);
    EXPECT_EQ(10u, q[2].pid); EXPECT_FALSE(q[2].isCreation);
}

TEST(ProcessNotifyQueueAdmission, OwnsItsStringsAcrossTheBoundary) {
    std::deque<ProcessNotifyEvent> q;
    std::wstring img = L"C:\\Temp\\evil.exe";
    std::wstring cmd = L"evil.exe --payload";
    ProcessNotifyEvent ev;
    ev.pid = 7;
    ev.isCreation = true;
    ev.imagePath = img;
    ev.commandLine = cmd;
    Detail::AdmitProcessNotifyEvent(q, std::move(ev), 16);

    // Mutate the sources after admission. The queued copy must be unaffected,
    // because the kernel-handler locals that produced it are gone by the time the
    // worker runs - a reference or a view would dangle; an owned copy does not.
    img = L"overwritten";
    cmd = L"overwritten";
    ASSERT_EQ(1u, q.size());
    EXPECT_EQ(L"C:\\Temp\\evil.exe", q.front().imagePath);
    EXPECT_EQ(L"evil.exe --payload", q.front().commandLine);
}

TEST(ProcessNotifyQueueAdmission, ZeroCapacityAdmitsNothingAndReportsDrop) {
    std::deque<ProcessNotifyEvent> q;
    // Degenerate bound: admit nothing, report a drop, and never pop_front an empty
    // deque (which would be undefined behaviour).
    EXPECT_TRUE(Detail::AdmitProcessNotifyEvent(q, MakeEvent(1, true), 0));
    EXPECT_TRUE(q.empty());
}

// ---------------------------------------------------------------------------
// EvaluateThreadInjection maps the kernel's forwarded thread-injection verdict
// (task 130) to a user-mode alert decision. The driver already scored the thread
// start address, so user-mode alerts only at the kernel's actionable risk
// (High/Critical) and names the injector before the target.
// ---------------------------------------------------------------------------
TEST(ThreadInjectionVerdictTests, HighRiskAlertsAtHighSeverityAndNamesInjectorThenTarget) {
    const auto v = Detail::EvaluateThreadInjection(
        /*creatorPid*/ 1337u, /*targetPid*/ 4242u, /*injectionScore*/ 550u,
        /*indicators*/ 0x00000004u | 0x00000008u,  // unbacked-start + rwx-start
        /*riskLevel*/ 3u,                            // TnRiskHigh
        /*startAddress*/ 0x7ff612340000ull);

    EXPECT_TRUE(v.shouldAlert);
    EXPECT_EQ(v.severityRank, 3);

    const auto injectorPos = v.details.find("injector PID 1337");
    const auto targetPos = v.details.find("target PID 4242");
    EXPECT_NE(injectorPos, std::string::npos);
    EXPECT_NE(targetPos, std::string::npos);
    EXPECT_LT(injectorPos, targetPos);
    EXPECT_NE(v.details.find("unbacked-start"), std::string::npos);
    EXPECT_NE(v.details.find("rwx-start"), std::string::npos);
    EXPECT_NE(v.details.find("score: 550"), std::string::npos);
    EXPECT_NE(v.details.find("0x7FF612340000"), std::string::npos);
}

TEST(ThreadInjectionVerdictTests, CriticalRiskAlertsAtCriticalSeverity) {
    const auto v = Detail::EvaluateThreadInjection(
        10u, 20u, 750u, 0x00004000u /* shellcode */, 4u /* TnRiskCritical */, 0x1000ull);
    EXPECT_TRUE(v.shouldAlert);
    EXPECT_EQ(v.severityRank, 4);
    EXPECT_NE(v.details.find("shellcode"), std::string::npos);
}

TEST(ThreadInjectionVerdictTests, BelowHighRiskNeverAlerts) {
    // None(0), Low(1), Medium(2) - benign cross-process threads (e.g. process
    // startup) land here and must not raise an alert.
    for (std::uint32_t risk : { 0u, 1u, 2u }) {
        const auto v = Detail::EvaluateThreadInjection(1u, 2u, 300u, 0x1u, risk, 0x1000ull);
        EXPECT_FALSE(v.shouldAlert) << "risk=" << risk;
        EXPECT_EQ(v.severityRank, 0) << "risk=" << risk;
        EXPECT_TRUE(v.details.empty()) << "risk=" << risk;
    }
}

// ---------------------------------------------------------------------------
// ExtractBoundedWidePath is the parse behind FilterMessageType_DeferredScanRequest
// (task 376). It reads an untrusted kernel payload, so the bounds arithmetic is
// the security-critical part: it must never trust the frame's declared length
// over what was actually delivered - that conflation is the task 91 defect class.
// ---------------------------------------------------------------------------
namespace {
// A payload is [fixedHeaderSize bytes][path as raw UTF-16], no implicit terminator.
std::vector<std::uint8_t> BuildDeferredPayload(std::size_t fixedHeaderSize,
                                               const std::wstring& path) {
    std::vector<std::uint8_t> buf(fixedHeaderSize, 0u);
    const auto* p = reinterpret_cast<const std::uint8_t*>(path.data());
    buf.insert(buf.end(), p, p + path.size() * sizeof(wchar_t));
    return buf;
}
}  // namespace

TEST(ExtractBoundedWidePathTests, ReturnsThePathWhenWellFormed) {
    const std::wstring path = L"\\Device\\HarddiskVolume3\\docs\\invoice.exe";
    auto buf = BuildDeferredPayload(72, path);
    auto r = Detail::ExtractBoundedWidePath(buf.data(), buf.size(), 72,
                                            path.size() * sizeof(wchar_t));
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, path);
}

TEST(ExtractBoundedWidePathTests, RejectsNullPayload) {
    EXPECT_FALSE(Detail::ExtractBoundedWidePath(nullptr, 100, 72, 8).has_value());
}

TEST(ExtractBoundedWidePathTests, RejectsPayloadShorterThanTheFixedHeader) {
    std::vector<std::uint8_t> buf(40, 0u);
    EXPECT_FALSE(Detail::ExtractBoundedWidePath(buf.data(), buf.size(), 72, 8).has_value());
}

TEST(ExtractBoundedWidePathTests, ClampsDeclaredLengthToWhatWasDelivered) {
    // The frame CLAIMS a 400-byte path but only 3 wchars (6 bytes) followed the
    // header. Trusting the claim would read ~394 bytes past the buffer; the clamp
    // must bound the read to the delivered 6 bytes. This is the task 91 defense.
    const std::wstring path = L"abc";
    auto buf = BuildDeferredPayload(72, path);
    auto r = Detail::ExtractBoundedWidePath(buf.data(), buf.size(), 72, 400);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, L"abc");
}

TEST(ExtractBoundedWidePathTests, FloorsAnOddDeclaredLengthToEven) {
    // 7 is odd and cannot be a whole number of UTF-16 code units; flooring to 6
    // yields 3 wchars rather than reading a trailing half code unit.
    const std::wstring path = L"abc";
    auto buf = BuildDeferredPayload(72, path);
    auto r = Detail::ExtractBoundedWidePath(buf.data(), buf.size(), 72, 7);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, L"abc");
}

TEST(ExtractBoundedWidePathTests, TrimsTrailingNuls) {
    const std::wstring path = L"x.exe";
    auto buf = BuildDeferredPayload(72, path);
    buf.insert(buf.end(), 2 * sizeof(wchar_t), 0u);   // driver-written terminator(s)
    auto r = Detail::ExtractBoundedWidePath(buf.data(), buf.size(), 72,
                                            (path.size() + 2) * sizeof(wchar_t));
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, L"x.exe");
}

TEST(ExtractBoundedWidePathTests, RejectsAPathUnderOneWideChar) {
    std::vector<std::uint8_t> buf(73, 0u);   // one stray byte after the header
    EXPECT_FALSE(Detail::ExtractBoundedWidePath(buf.data(), buf.size(), 72, 1).has_value());
}

TEST(ExtractBoundedWidePathTests, RejectsAnAllNulPath) {
    std::vector<std::uint8_t> buf(72 + 4, 0u);   // two NUL wchars, no real content
    EXPECT_FALSE(Detail::ExtractBoundedWidePath(buf.data(), buf.size(), 72, 4).has_value());
}

}  // namespace ShadowStrike::RealTime::Tests
