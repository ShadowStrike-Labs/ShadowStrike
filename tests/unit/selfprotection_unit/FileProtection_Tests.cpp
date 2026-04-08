#include "../../../src/pch.h"
#include <nlohmann/json.hpp>
#include "../../../src/Shared_modules/SelfProtection/FileProtection.hpp"

namespace {

using nlohmann::json;
using namespace ShadowStrike::Security;

json ParseJson(const std::string& text) {
    return json::parse(text);
}

TEST(FileProtectionTests, ProtectionModesAndValidationRemainCoherent) {
    const FileProtectionConfiguration disabled =
        FileProtectionConfiguration::FromMode(FileProtectionMode::Disabled);
    EXPECT_FALSE(disabled.enableKernelFiltering);
    EXPECT_FALSE(disabled.enableSignatureValidation);
    EXPECT_FALSE(disabled.enableIntegrityMonitoring);
    EXPECT_FALSE(disabled.enableAutoBackup);
    EXPECT_EQ(disabled.defaultResponse, FileProtectionResponse::None);

    const FileProtectionConfiguration strict =
        FileProtectionConfiguration::FromMode(FileProtectionMode::Strict);
    EXPECT_TRUE(strict.enableKernelFiltering);
    EXPECT_TRUE(strict.requireShadowStrikeSignature);
    EXPECT_TRUE(strict.enableAutoBackup);
    EXPECT_TRUE(strict.enableRealTimeMonitoring);
    EXPECT_EQ(strict.defaultResponse, FileProtectionResponse::Aggressive);
    EXPECT_TRUE(strict.IsValid());

    FileProtectionConfiguration invalid = strict;
    invalid.integrityCheckIntervalMs = 999;
    EXPECT_FALSE(invalid.IsValid());

    invalid = strict;
    invalid.maxBackupVersions = 101;
    EXPECT_FALSE(invalid.IsValid());
}

TEST(FileProtectionTests, EventsSerializeDecisionAndOperationNamesConsistently) {
    const auto readWrite = static_cast<FileOperation>(
        static_cast<uint32_t>(FileOperation::Read) |
        static_cast<uint32_t>(FileOperation::Write));

    FileProtectionEvent event{};
    event.eventId = 17;
    event.type = FileProtectionEventType::OperationBlocked;
    event.filePath = L"C:\\Program Files\\ShadowStrike\\agent.exe";
    event.operation = readWrite;
    event.decision = FileOperationDecision::Block;
    event.sourceProcessId = 1337;
    event.sourceProcessName = L"evil.exe";
    event.wasBlocked = true;
    event.description = "Denied protected file overwrite";

    const std::string summary = event.GetSummary();
    EXPECT_THAT(summary, ::testing::HasSubstr("Blocked Read on C:\\Program Files\\ShadowStrike\\agent.exe"));
    EXPECT_THAT(summary, ::testing::HasSubstr("by PID 1337 (evil.exe)"));

    const json payload = ParseJson(event.ToJson());
    EXPECT_EQ(payload.at("eventId").get<int>(), 17);
    EXPECT_EQ(payload.at("operation").get<std::string>(), "Read");
    EXPECT_EQ(payload.at("decision").get<int>(),
              static_cast<int>(FileOperationDecision::Block));
    EXPECT_EQ(payload.at("sourceProcessName").get<std::string>(), "evil.exe");
    EXPECT_TRUE(payload.at("wasBlocked").get<bool>());
    EXPECT_EQ(payload.at("description").get<std::string>(), "Denied protected file overwrite");

    event.type = FileProtectionEventType::IntegrityViolation;
    event.sourceProcessId = 0;
    event.sourceProcessName = L"ghost.exe";
    event.wasBlocked = false;
    event.wasRestored = false;

    const std::string pidlessSummary = event.GetSummary();
    EXPECT_THAT(pidlessSummary,
                ::testing::HasSubstr("Integrity violation on C:\\Program Files\\ShadowStrike\\agent.exe"));
    EXPECT_THAT(pidlessSummary, ::testing::Not(::testing::HasSubstr("by PID")));
    EXPECT_THAT(pidlessSummary, ::testing::Not(::testing::HasSubstr("ghost.exe")));
}

TEST(FileProtectionTests, StatisticsAndHelperNamesExposeStableContracts) {
    FileProtectionStatistics stats{};
    stats.totalProtectedFiles = 4;
    stats.totalProtectedDirectories = 2;
    stats.totalOperations = 90;
    stats.totalBlocked = 7;
    stats.ransomwareDetections = 1;
    stats.filesRestored = 2;

    const json payload = ParseJson(stats.ToJson());
    EXPECT_EQ(payload.at("totalProtectedFiles").get<int>(), 4);
    EXPECT_EQ(payload.at("totalOperations").get<int>(), 90);
    EXPECT_EQ(payload.at("totalBlocked").get<int>(), 7);
    EXPECT_EQ(payload.at("filesRestored").get<int>(), 2);
    EXPECT_GE(payload.at("uptimeMs").get<int64_t>(), 0);

    const auto combinedOperation = static_cast<FileOperation>(
        static_cast<uint32_t>(FileOperation::Delete) |
        static_cast<uint32_t>(FileOperation::Write));
    EXPECT_EQ(GetProtectionModeName(FileProtectionMode::Strict), "Strict");
    EXPECT_EQ(GetFileOperationName(combinedOperation), "Write");
    EXPECT_EQ(GetProtectionTypeName(ProtectionType::NoDelete), "NoDelete");
    EXPECT_EQ(GetIntegrityStatusName(FileIntegrityStatus::Restored), "Restored");
    EXPECT_EQ(GetSignatureStatusName(SignatureStatus::ShadowStrike), "ShadowStrike");
}

}  // namespace
