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
 * @file FileBackupManager_Tests.cpp
 * @brief Comprehensive GTest coverage for Ransomware::FileBackupManager.
 *
 * Coverage focus:
 * - configuration and policy validation, statistics reset, serialization, and versioning
 * - RAM and disk-backed JIT backup flows on real temporary files
 * - rollback, restore callback delivery, usage counters, and commit cleanup
 * - path validation and policy exclusion behavior for unsupported backup requests
 */

#include "pch.h"

#include "RansomwareProtection_TestUtils.hpp"
#include "../../../src/Shared_modules/RansomwareProtection/FileBackupManager.hpp"

#include <future>

namespace {

using namespace ShadowStrike::Ransomware;
using namespace ShadowStrike::Tests::RansomwareProtection;
using ::testing::HasSubstr;

class FileBackupManagerTest : public TempDirectoryFixture {
protected:
    void SetUp() override {
        TempDirectoryFixture::SetUp();

        auto& manager = FileBackupManager::Instance();
        manager.Shutdown();
        manager.ResetStatistics();

        FileBackupManagerConfiguration config;
        config.cacheDirectory = MakePath(L"cache").wstring();
        config.autoCleanup = false;
        config.defaultPolicy.enabled = true;
        config.defaultPolicy.ramThreshold = 4096;
        ASSERT_TRUE(manager.Initialize(config));
    }

    void TearDown() override {
        auto& manager = FileBackupManager::Instance();
        manager.SetBackupCompleteCallback(nullptr);
        manager.SetRestoreCompleteCallback(nullptr);
        manager.SetProgressCallback(nullptr);
        manager.Shutdown();
        TempDirectoryFixture::TearDown();
    }
};

TEST(FileBackupManagerValueTests, ConfigurationPoliciesStatisticsUtilitiesAndVersionRemainStable) {
    FileBackupManagerConfiguration config;
    EXPECT_TRUE(config.IsValid());

    auto invalidRam = config;
    invalidRam.maxRamCacheSize = BackupConstants::MAX_RAM_CACHE_SIZE * 2 + 1;
    EXPECT_FALSE(invalidRam.IsValid());

    auto invalidDisk = config;
    invalidDisk.maxDiskCacheSize = BackupConstants::MAX_DISK_CACHE_SIZE * 4 + 1;
    EXPECT_FALSE(invalidDisk.IsValid());

    auto invalidCleanup = config;
    invalidCleanup.cleanupIntervalSecs = 0;
    EXPECT_FALSE(invalidCleanup.IsValid());

    auto invalidCleanupHigh = config;
    invalidCleanupHigh.cleanupIntervalSecs = 86401;
    EXPECT_FALSE(invalidCleanupHigh.IsValid());

    BackupPolicy policy;
    EXPECT_TRUE(policy.ShouldBackup(L"C:\\Data\\report.docx", 128));
    EXPECT_FALSE(policy.ShouldBackup(L"C:\\Data\\report.docx", 0));
    policy.maxFileSize = 128;
    EXPECT_TRUE(policy.ShouldBackup(L"C:\\Data\\report.docx", 128));
    EXPECT_FALSE(policy.ShouldBackup(L"C:\\Data\\report.docx", 129));
    policy.enabled = false;
    EXPECT_FALSE(policy.ShouldBackup(L"C:\\Data\\report.docx", 128));

    BackupStatistics stats;
    stats.filesBackedUp.store(4, std::memory_order_relaxed);
    stats.filesRestored.store(3, std::memory_order_relaxed);
    stats.filesCommitted.store(2, std::memory_order_relaxed);
    stats.backupFailures.store(1, std::memory_order_relaxed);
    stats.restoreFailures.store(5, std::memory_order_relaxed);
    stats.bytesBackedUp.store(64, std::memory_order_relaxed);
    stats.bytesRestored.store(32, std::memory_order_relaxed);
    stats.currentRamUsage.store(16, std::memory_order_relaxed);
    stats.currentDiskUsage.store(8, std::memory_order_relaxed);
    stats.activeBackups.store(7, std::memory_order_relaxed);
    stats.Reset();

    EXPECT_EQ(stats.filesBackedUp.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.filesRestored.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.filesCommitted.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.backupFailures.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.restoreFailures.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.bytesBackedUp.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.bytesRestored.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.currentRamUsage.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.currentDiskUsage.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.activeBackups.load(std::memory_order_relaxed), 0u);
    EXPECT_THAT(stats.ToJson(), HasSubstr("\"filesBackedUp\": 0"));

    BackupEntry entry;
    entry.backupId = "backup-1";
    entry.originalPath = L"C:\\Data\\important.txt";
    entry.originalSize = 17;
    entry.storageType = BackupStorageType::Disk;
    entry.status = BackupStatus::Completed;
    EXPECT_THAT(entry.ToJson(), HasSubstr("\"backupId\": \"backup-1\""));
    EXPECT_THAT(entry.ToJson(), HasSubstr("\"originalPath\": \"C:\\\\Data\\\\important.txt\""));

    RestoreResult restore;
    restore.originalPath = L"C:\\Data\\important.txt";
    restore.backupId = "backup-1";
    restore.status = RestoreStatus::Success;
    restore.bytesRestored = 17;
    restore.errorMessage = "permission denied";
    EXPECT_THAT(restore.ToJson(), HasSubstr("\"bytesRestored\": 17"));
    EXPECT_THAT(restore.ToJson(), HasSubstr("\"error\": \"permission denied\""));

    RollbackResult rollback;
    rollback.pid = 9001;
    rollback.filesAttempted = 3;
    rollback.filesRestored = 2;
    rollback.filesFailed = 1;
    EXPECT_THAT(rollback.ToJson(), HasSubstr("\"pid\": 9001"));
    EXPECT_THAT(rollback.ToJson(), HasSubstr("\"filesFailed\": 1"));

    BackupStatisticsSnapshot snapshot;
    snapshot.filesBackedUp = 4;
    snapshot.currentRamUsage = 8;
    snapshot.currentDiskUsage = 2;
    snapshot.startTime = Clock::now() - std::chrono::seconds(2);
    EXPECT_THAT(snapshot.ToJson(), HasSubstr("\"filesBackedUp\": 4"));
    EXPECT_THAT(snapshot.ToJson(), HasSubstr("\"ramUsage\": 8"));
    EXPECT_THAT(snapshot.ToJson(), HasSubstr("\"uptimeSeconds\":"));

    EXPECT_EQ(GetStorageTypeName(BackupStorageType::Encrypted), "Encrypted");
    EXPECT_EQ(GetBackupStatusName(BackupStatus::Expired), "Expired");
    EXPECT_EQ(GetRestoreStatusName(RestoreStatus::AccessDenied), "AccessDenied");
    EXPECT_EQ(FileBackupManager::GetVersionString(), "3.1.0");
}

TEST_F(FileBackupManagerTest, RamBackupsPopulateStateUsageCountersAndCompleteCallback) {
    auto& manager = FileBackupManager::Instance();
    const auto source = WriteText(L"docs\\note.txt", "ShadowStrike backup payload");

    std::promise<BackupEntry> callbackPromise;
    auto callbackFuture = callbackPromise.get_future();
    std::atomic<bool> callbackDelivered{ false };
    manager.SetBackupCompleteCallback(
        [&](const BackupEntry& entry) {
            if (!callbackDelivered.exchange(true)) {
                callbackPromise.set_value(entry);
            }
        });

    const uint32_t pid = 4101;
    const auto backupId = manager.BackupFileTo(source.wstring(), pid, BackupStorageType::RAM);

    ASSERT_TRUE(backupId.has_value());
    ASSERT_EQ(callbackFuture.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    const auto callbackEntry = callbackFuture.get();

    EXPECT_EQ(callbackEntry.backupId, *backupId);
    EXPECT_EQ(callbackEntry.storageType, BackupStorageType::RAM);
    EXPECT_EQ(callbackEntry.originalPath, source.wstring());
    EXPECT_TRUE(manager.IsBackedUp(source.wstring(), pid));

    const auto backup = manager.GetBackup(source.wstring(), pid);
    ASSERT_TRUE(backup.has_value());
    EXPECT_EQ(backup->backupId, *backupId);
    EXPECT_EQ(backup->storageType, BackupStorageType::RAM);
    ASSERT_TRUE(backup->memoryData);
    EXPECT_FALSE(backup->memoryData->empty());

    EXPECT_EQ(manager.GetBackupCount(pid), 1u);
    EXPECT_EQ(manager.GetTotalBackupCount(), 1u);
    EXPECT_EQ(manager.GetBackupsForProcess(pid).size(), 1u);
    EXPECT_EQ(manager.GetActiveBackups().size(), 1u);
    EXPECT_GT(manager.GetRamCacheUsage(), 0u);

    const auto stats = manager.GetStatistics();
    EXPECT_EQ(stats.filesBackedUp, 1u);
    EXPECT_EQ(stats.activeBackups, 1u);
    EXPECT_EQ(stats.currentRamUsage, manager.GetRamCacheUsage());
}

TEST_F(FileBackupManagerTest, DiskBackupsRollbackModifiedFilesAndCommitRemovesCacheArtifacts) {
    auto& manager = FileBackupManager::Instance();
    const auto source = WriteText(L"docs\\ledger.txt", "original-ledger-content");

    const uint32_t pid = 4202;
    const auto backupId = manager.BackupFileTo(source.wstring(), pid, BackupStorageType::Disk);
    ASSERT_TRUE(backupId.has_value());

    const auto backup = manager.GetBackup(source.wstring(), pid);
    ASSERT_TRUE(backup.has_value());
    EXPECT_EQ(backup->storageType, BackupStorageType::Disk);
    EXPECT_FALSE(backup->backupPath.empty());
    EXPECT_TRUE(std::filesystem::exists(backup->backupPath));
    EXPECT_GT(manager.GetDiskCacheUsage(), 0u);

    const auto mutated = WriteText(L"docs\\ledger.txt", "mutated-by-ransomware");
    EXPECT_EQ(mutated, source);

    std::promise<RestoreResult> restorePromise;
    auto restoreFuture = restorePromise.get_future();
    std::atomic<bool> restoreDelivered{ false };
    manager.SetRestoreCompleteCallback(
        [&](const RestoreResult& result) {
            if (!restoreDelivered.exchange(true)) {
                restorePromise.set_value(result);
            }
        });

    const auto rollback = manager.RollbackChanges(pid);

    EXPECT_EQ(rollback.filesAttempted, 1u);
    EXPECT_EQ(rollback.filesRestored, 1u);
    EXPECT_EQ(rollback.filesFailed, 0u);
    EXPECT_EQ(ReadTextFile(source), "original-ledger-content");

    ASSERT_EQ(restoreFuture.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    const auto callbackResult = restoreFuture.get();
    EXPECT_EQ(callbackResult.status, RestoreStatus::Success);
    EXPECT_TRUE(callbackResult.integrityVerified);

    manager.CommitChanges(pid);

    EXPECT_EQ(manager.GetBackupCount(pid), 0u);
    EXPECT_EQ(manager.GetTotalBackupCount(), 0u);
    EXPECT_EQ(manager.GetActiveBackups().size(), 0u);
    EXPECT_EQ(manager.GetDiskCacheUsage(), 0u);
    EXPECT_FALSE(std::filesystem::exists(backup->backupPath));

    const auto missingAfterCommit = manager.RestoreFile(source.wstring(), pid);
    EXPECT_EQ(missingAfterCommit.status, RestoreStatus::NotFound);

    manager.CommitChanges(pid);

    const auto stats = manager.GetStatistics();
    EXPECT_EQ(stats.filesBackedUp, 1u);
    EXPECT_EQ(stats.filesRestored, 1u);
    EXPECT_EQ(stats.filesCommitted, 1u);
}

TEST_F(FileBackupManagerTest, CacheInternalPathsExcludedPoliciesAndMissingRestoresReturnSafeDefaults) {
    auto& manager = FileBackupManager::Instance();
    const auto protectedInternal = WriteText(L"cache\\internal.txt", "internal-cache-file");
    const auto external = WriteText(L"docs\\external.txt", "candidate");

    EXPECT_FALSE(manager.BackupFile(protectedInternal.wstring(), 5001));

    BackupPolicy excludedPolicy;
    excludedPolicy.excludeExtensions = { L".txt" };
    EXPECT_FALSE(manager.BackupFileEx(external.wstring(), 5001, excludedPolicy).has_value());

    const auto missing = manager.RestoreFile("missing-backup-id");
    EXPECT_EQ(missing.status, RestoreStatus::NotFound);
    EXPECT_THAT(missing.errorMessage, HasSubstr("not found"));

    const auto statsBeforeCommit = manager.GetStatistics();
    manager.CommitBackup("missing-backup-id");
    EXPECT_EQ(manager.GetStatistics().filesCommitted, statsBeforeCommit.filesCommitted);
}

}  // namespace
