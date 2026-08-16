#include "../../../src/pch.h"
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <nlohmann/json.hpp>
#include "../../../src/PhantomCore/SelfProtection/TamperProtection.hpp"

#include <atomic>
#include <filesystem>
#include <fstream>
#include <optional>
#include <system_error>

namespace {

using nlohmann::json;
using namespace ShadowStrike::Security;

json ParseJson(const std::string& text) {
    return json::parse(text);
}

TEST(TamperProtectionTests, ModePresetsAndValidationStayConsistent) {
    const TamperProtectionConfiguration disabled =
        TamperProtectionConfiguration::FromMode(TamperProtectionMode::Disabled);
    EXPECT_FALSE(disabled.enableRealTimeMonitoring);
    EXPECT_FALSE(disabled.enablePeriodicChecks);
    EXPECT_FALSE(disabled.enableAutoRepair);
    EXPECT_EQ(disabled.defaultResponse, TamperResponse::Log);

    const TamperProtectionConfiguration lockdown =
        TamperProtectionConfiguration::FromMode(TamperProtectionMode::Lockdown);
    EXPECT_TRUE(lockdown.enableRealTimeMonitoring);
    EXPECT_TRUE(lockdown.enableAutoRepair);
    EXPECT_TRUE(lockdown.verifyCertificateChain);
    EXPECT_TRUE(lockdown.enableAntiDebugIntegration);
    EXPECT_EQ(lockdown.defaultResponse, TamperResponse::Maximum);
    EXPECT_TRUE(lockdown.IsValid());

    TamperProtectionConfiguration invalid = lockdown;
    invalid.checkIntervalMs = TamperProtectionConstants::MIN_CHECK_INTERVAL_MS - 1;
    EXPECT_FALSE(invalid.IsValid());

    invalid = lockdown;
    invalid.maxRepairAttempts = 11;
    EXPECT_FALSE(invalid.IsValid());
}

TEST(TamperProtectionTests, TamperEventsSummariesAndJsonTrackRepairActions) {
    TamperEvent event{};
    event.eventId = 71;
    event.type = TamperEventType::FileModified;
    event.resourceType = ProtectedResourceType::File;
    event.resourceId = "agent-binary";
    event.resourcePath = L"C:\\Program Files\\ShadowStrike\\agent.exe";
    event.sourceProcessId = 808;
    event.sourceProcessName = L"attacker.exe";
    event.sourceThreadId = 15;
    event.changeDescription = "Unexpected code section mutation";
    event.responseTaken = TamperResponse::Repair;
    event.wasBlocked = true;
    event.wasRepaired = true;
    event.severityLevel = 9;
    event.expectedHash.fill(0x11);
    event.actualHash.fill(0x22);

    const std::string summary = event.GetSummary();
    EXPECT_THAT(summary, ::testing::HasSubstr("FileModified on File"));
    EXPECT_THAT(summary, ::testing::HasSubstr("agent.exe"));
    EXPECT_THAT(summary, ::testing::HasSubstr("by PID 808"));
    EXPECT_THAT(summary, ::testing::HasSubstr("[BLOCKED]"));
    EXPECT_THAT(summary, ::testing::HasSubstr("[REPAIRED]"));

    const json payload = ParseJson(event.ToJson());
    EXPECT_EQ(payload.at("eventId").get<int>(), 71);
    EXPECT_EQ(payload.at("typeName").get<std::string>(), "FileModified");
    EXPECT_EQ(payload.at("resourceId").get<std::string>(), "agent-binary");
    EXPECT_EQ(payload.at("resourcePath").get<std::string>(),
              "C:\\Program Files\\ShadowStrike\\agent.exe");
    EXPECT_EQ(payload.at("responseTaken").get<int>(),
              static_cast<int>(TamperResponse::Repair));
    EXPECT_TRUE(payload.at("wasBlocked").get<bool>());
    EXPECT_TRUE(payload.at("wasRepaired").get<bool>());
    EXPECT_EQ(payload.at("severityLevel").get<int>(), 9);
    EXPECT_EQ(payload.at("expectedHash").get<std::string>().size(), 64U);
    EXPECT_EQ(payload.at("actualHash").get<std::string>().size(), 64U);

    event.eventId = 72;
    event.resourcePath.clear();
    event.sourceProcessId = 0;
    event.sourceProcessName = L"hidden.exe";
    event.wasBlocked = false;
    event.wasRepaired = false;

    const std::string pidlessSummary = event.GetSummary();
    EXPECT_THAT(pidlessSummary, ::testing::HasSubstr("FileModified on File"));
    EXPECT_THAT(pidlessSummary, ::testing::Not(::testing::HasSubstr("by PID")));
    EXPECT_THAT(pidlessSummary, ::testing::Not(::testing::HasSubstr("hidden.exe")));
}

TEST(TamperProtectionTests, StatisticsAndHelperNamesRemainStable) {
    TamperProtectionStatistics stats{};
    stats.totalResourcesMonitored = 12;
    stats.totalIntegrityChecks = 50;
    stats.totalTamperingDetected = 3;
    stats.totalTamperingBlocked = 2;
    stats.totalRepairsPerformed = 2;
    stats.successfulRepairs = 2;
    stats.uptimeMs = 1500;

    const json payload = ParseJson(stats.ToJson());
    EXPECT_EQ(payload.at("totalResourcesMonitored").get<int>(), 12);
    EXPECT_EQ(payload.at("totalTamperingDetected").get<int>(), 3);
    EXPECT_EQ(payload.at("successfulRepairs").get<int>(), 2);
    EXPECT_EQ(payload.at("uptimeMs").get<int>(), 1500);

    EXPECT_EQ(GetModeName(TamperProtectionMode::Enforce), "Enforce");
    EXPECT_EQ(GetResourceTypeName(ProtectedResourceType::CodeSection), "CodeSection");
    EXPECT_EQ(GetEventTypeName(TamperEventType::DebuggerAttached), "DebuggerAttached");
    EXPECT_EQ(GetIntegrityStatusName(IntegrityStatus::Unauthorized), "Unauthorized");
    EXPECT_EQ(GetResponseName(TamperResponse::Repair), "Repair");
    EXPECT_EQ(GetResponseName(TamperResponse::Standard), "Multiple");
    EXPECT_EQ(GetSubsystemName(TamperSubsystem::FileProtection), "FileProtection");
}

// ============================================================================
// RESPONSE ACCOUNTING AND THE RESPONSE HANDLER
//
// TamperResponse is a flag set and the shipped profiles request flags this
// module does not implement (Enforce -> Aggressive includes Revert|Terminate,
// Lockdown -> Maximum includes every flag). responseRequested now records the
// intent and responseTaken records only what was carried out.
//
// Two defects are pinned here:
//   1. TamperProtection::SetResponseHandler had ZERO invocation sites, so a
//      handler could be registered and was never consulted on any path.
//   2. The periodic integrity verifier reported every detection as blocked,
//      because the default Protect profile requests Standard (Log|Alert|Block)
//      and the Block flag alone was taken as proof of a block - on a path that
//      fires only AFTER a file is already deleted or already modified.
// ============================================================================

namespace {

/// Create a probe file, baseline it, then delete it so the next verification is
/// a post-hoc detection. Returns false if the engine could not baseline it,
/// which the caller must assert on so a test cannot pass vacuously.
[[nodiscard]] bool StageDeletedProbeFile(TamperProtection& engine,
                                         const std::filesystem::path& path) {
    {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) {
            return false;
        }
        out << "baseline-content";
    }
    if (!engine.ProtectFile(path.wstring(), false)) {
        return false;
    }
    std::error_code ec;
    std::filesystem::remove(path, ec);
    return !ec;
}

}  // namespace

TEST(TamperProtectionResponseAccounting, PostHocDetectionIsNeverReportedAsBlocked) {
    auto& engine = TamperProtection::Instance();

    // The engine is a process-wide singleton, so another suite may already have
    // started it and Initialize answering false is not itself a failure. The
    // real preconditions are asserted below, so this cannot pass vacuously.
    (void)engine.Initialize(TamperProtectionMode::Protect);

    // State the premise explicitly rather than leaning on a profile default:
    // the policy asks for Block.
    engine.SetDefaultResponse(TamperResponse::Standard);
    ASSERT_NE(static_cast<uint32_t>(engine.GetDefaultResponse()) &
                  static_cast<uint32_t>(TamperResponse::Block),
              0u)
        << "premise: the configured response must include Block";

    const auto probe =
        std::filesystem::temp_directory_path() / L"phantom_tamper_posthoc_probe.bin";

    const auto before = engine.GetStatistics();
    ASSERT_TRUE(StageDeletedProbeFile(engine, probe))
        << "precondition: the engine must be running and able to baseline a file";

    const auto verification = engine.VerifyFile(probe.wstring());
    EXPECT_EQ(verification.status, IntegrityStatus::Missing);

    const auto after = engine.GetStatistics();
    ASSERT_EQ(after.totalTamperingDetected, before.totalTamperingDetected + 1)
        << "precondition: the deletion must have been detected";

    // THE DISCRIMINATOR. The policy requested Block, but the file was already
    // gone before we looked, so nothing was prevented. Previously the Block flag
    // alone set wasBlocked and incremented this counter on every detection,
    // inverting the meaning of the module's headline statistic.
    EXPECT_EQ(after.totalTamperingBlocked, before.totalTamperingBlocked)
        << "a post-hoc integrity finding must not be counted as prevented tampering";
    EXPECT_GT(after.responsesNotCarriedOut, before.responsesNotCarriedOut)
        << "a requested Block that cannot be performed must be counted, not dropped";

    const auto history = engine.GetEventHistory(8);
    ASSERT_FALSE(history.empty());
    const auto& event = history.front();  // GetEventHistory answers newest first
    EXPECT_EQ(event.type, TamperEventType::FileDeleted);
    EXPECT_FALSE(event.wasBlocked);
    EXPECT_NE(static_cast<uint32_t>(event.responseRequested) &
                  static_cast<uint32_t>(TamperResponse::Block),
              0u)
        << "the requested response must still record that Block was asked for";
    EXPECT_EQ(static_cast<uint32_t>(event.responseTaken) &
                  static_cast<uint32_t>(TamperResponse::Block),
              0u)
        << "the taken response must not claim a Block that never happened";
}

TEST(TamperProtectionResponseAccounting, ResponseHandlerIsConsultedAndOverridesThePolicy) {
    auto& engine = TamperProtection::Instance();
    (void)engine.Initialize(TamperProtectionMode::Protect);
    engine.SetDefaultResponse(TamperResponse::Standard);

    std::atomic<int> invocations{ 0 };
    engine.SetResponseHandler(
        [&invocations](const TamperEvent&) -> std::optional<TamperResponse> {
            invocations.fetch_add(1, std::memory_order_relaxed);
            return TamperResponse::Log;  // deliberately narrower than the policy
        });

    const auto probe =
        std::filesystem::temp_directory_path() / L"phantom_tamper_handler_probe.bin";

    const bool staged = StageDeletedProbeFile(engine, probe);
    if (staged) {
        (void)engine.VerifyFile(probe.wstring());
    }

    // Capture everything, then clear the handler BEFORE asserting: a failing
    // assertion must not leak a process-wide handler into other suites.
    const int invoked = invocations.load(std::memory_order_relaxed);
    const auto history = engine.GetEventHistory(8);
    engine.SetResponseHandler(nullptr);

    ASSERT_TRUE(staged) << "precondition: the probe file must have been baselined";

    // THE DISCRIMINATOR. SetResponseHandler had zero invocation sites, so before
    // this change a registered handler was never called on any path.
    EXPECT_GE(invoked, 1) << "a registered response handler must actually be consulted";

    ASSERT_FALSE(history.empty());
    const auto& event = history.front();
    EXPECT_EQ(event.responseRequested, TamperResponse::Log)
        << "the handler's answer must replace the configured policy";
    EXPECT_EQ(static_cast<uint32_t>(event.responseRequested) &
                  static_cast<uint32_t>(TamperResponse::Block),
              0u)
        << "the policy's Block must not survive a handler that declined it";
}

TEST(TamperProtectionResponseAccounting, EventJsonReportsRequestedAndTakenSeparately) {
    TamperEvent event;
    event.eventId = 77;
    event.type = TamperEventType::FileModified;
    event.responseRequested = TamperResponse::Aggressive;
    event.responseTaken = TamperResponse::Passive;
    event.wasBlocked = false;

    const json payload = ParseJson(event.ToJson());
    EXPECT_EQ(payload.at("responseRequested").get<uint32_t>(),
              static_cast<uint32_t>(TamperResponse::Aggressive));
    EXPECT_EQ(payload.at("responseTaken").get<uint32_t>(),
              static_cast<uint32_t>(TamperResponse::Passive));
    EXPECT_FALSE(payload.at("wasBlocked").get<bool>());

    // The two fields must be able to disagree - that is the entire point of
    // separating them, and a serializer that emitted only one could not show an
    // operator that a requested action was skipped.
    EXPECT_NE(payload.at("responseRequested").get<uint32_t>(),
              payload.at("responseTaken").get<uint32_t>());
}

TEST(TamperProtectionResponseAccounting, StatisticsJsonExposesTheUnexecutedResponseCount) {
    TamperProtectionStatistics stats;
    stats.totalTamperingDetected = 9;
    stats.totalTamperingBlocked = 0;
    stats.responsesNotCarriedOut = 4;

    const json payload = ParseJson(stats.ToJson());
    EXPECT_EQ(payload.at("totalTamperingDetected").get<uint64_t>(), 9u);
    EXPECT_EQ(payload.at("totalTamperingBlocked").get<uint64_t>(), 0u);
    EXPECT_EQ(payload.at("responsesNotCarriedOut").get<uint64_t>(), 4u)
        << "the gap between requested and carried-out responses must be measurable";
}

}  // namespace
