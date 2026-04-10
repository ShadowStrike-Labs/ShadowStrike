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
 * @file VolumeSnapshotService_ValueContracts_Tests.cpp
 * @brief Value-contract coverage for Ransomware::VolumeSnapshotService.
 */

#include "pch.h"

#include "../../../src/Shared_modules/RansomwareProtection/VolumeSnapshotService.hpp"

namespace {

using namespace ShadowStrike::Ransomware;
using ::testing::HasSubstr;

TEST(VolumeSnapshotServiceValueContractTests, ConfigStatisticsHelpersAndVersionRemainStable) {
    VolumeSnapshotConfiguration config;
    EXPECT_TRUE(config.IsValid());

    auto invalidMaxSnapshots = config;
    invalidMaxSnapshots.maxSnapshotsPerVolume = 0;
    EXPECT_FALSE(invalidMaxSnapshots.IsValid());

    auto invalidMaxSnapshotsHigh = config;
    invalidMaxSnapshotsHigh.maxSnapshotsPerVolume = 513;
    EXPECT_FALSE(invalidMaxSnapshotsHigh.IsValid());

    auto invalidStoragePercent = config;
    invalidStoragePercent.defaultStorageLimitPercent = 81;
    EXPECT_FALSE(invalidStoragePercent.IsValid());

    auto invalidInterval = config;
    invalidInterval.monitoringIntervalSeconds = 0;
    EXPECT_FALSE(invalidInterval.IsValid());

    auto invalidIntervalHigh = config;
    invalidIntervalHigh.monitoringIntervalSeconds = 86401;
    EXPECT_FALSE(invalidIntervalHigh.IsValid());

    auto validBoundary = config;
    validBoundary.maxSnapshotsPerVolume = 512;
    validBoundary.defaultStorageLimitPercent = 80;
    validBoundary.monitoringIntervalSeconds = 86400;
    EXPECT_TRUE(validBoundary.IsValid());

    VolumeSnapshotStatistics stats;
    stats.snapshotsCreated.store(1, std::memory_order_relaxed);
    stats.snapshotsDeleted.store(2, std::memory_order_relaxed);
    stats.snapshotsMounted.store(3, std::memory_order_relaxed);
    stats.filesRestored.store(4, std::memory_order_relaxed);
    stats.directoriesRestored.store(5, std::memory_order_relaxed);
    stats.operationsFailed.store(6, std::memory_order_relaxed);
    stats.totalCreationTimeMs.store(7, std::memory_order_relaxed);
    stats.totalDeletionTimeMs.store(8, std::memory_order_relaxed);
    stats.totalRestorationTimeMs.store(9, std::memory_order_relaxed);
    stats.currentOperations.store(10, std::memory_order_relaxed);
    stats.emergencySnapshotsCreated.store(11, std::memory_order_relaxed);
    stats.byType[static_cast<size_t>(SnapshotType::Transportable)].store(12, std::memory_order_relaxed);
    stats.byResult[static_cast<size_t>(VSSResult::Timeout)].store(13, std::memory_order_relaxed);
    EXPECT_THAT(stats.ToJson(), HasSubstr("\"snapshotsCreated\":1"));
    EXPECT_THAT(stats.ToJson(), HasSubstr("\"emergencySnapshotsCreated\":11"));
    stats.Reset();

    EXPECT_EQ(stats.snapshotsCreated.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.snapshotsDeleted.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.snapshotsMounted.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.filesRestored.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.directoriesRestored.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.operationsFailed.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.totalCreationTimeMs.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.totalDeletionTimeMs.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.totalRestorationTimeMs.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.currentOperations.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.emergencySnapshotsCreated.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(
        stats.byType[static_cast<size_t>(SnapshotType::Transportable)].load(std::memory_order_relaxed),
        0u);
    EXPECT_EQ(
        stats.byResult[static_cast<size_t>(VSSResult::Timeout)].load(std::memory_order_relaxed),
        0u);

    SnapshotInfo snapshotInfo;
    snapshotInfo.snapshotId = L"shadow-1";
    snapshotInfo.volumeName = L"\\\\?\\Volume{abc}\\";
    snapshotInfo.type = SnapshotType::Transportable;
    snapshotInfo.state = SnapshotState::Committed;
    snapshotInfo.sizeBytes = 4096;
    EXPECT_THAT(snapshotInfo.ToJson(), HasSubstr("\"snapshotId\":\"shadow-1\""));
    EXPECT_THAT(snapshotInfo.ToJson(), HasSubstr("\"sizeBytes\":4096"));

    VolumeInfo volumeInfo;
    volumeInfo.volumeName = L"\\\\?\\Volume{abc}\\";
    volumeInfo.mountPoint = L"C:\\";
    volumeInfo.fileSystem = L"NTFS";
    volumeInfo.snapshotCount = 3;
    volumeInfo.vssSupported = true;
    EXPECT_THAT(volumeInfo.ToJson(), HasSubstr("\"mountPoint\":\"C:\\\\\""));
    EXPECT_THAT(volumeInfo.ToJson(), HasSubstr("\"snapshotCount\":3"));

    WriterInfo writerInfo;
    writerInfo.writerName = L"Shadow Writer";
    writerInfo.state = WriterState::Failed;
    writerInfo.lastError = E_ACCESSDENIED;
    EXPECT_THAT(writerInfo.ToJson(), HasSubstr("\"writerName\":\"Shadow Writer\""));
    EXPECT_THAT(writerInfo.ToJson(), HasSubstr("\"state\":5"));

    SnapshotOperation operation;
    operation.operationId = L"op-1";
    operation.type = OperationType::Create;
    operation.state = OperationState::Failed;
    operation.progressPercent = 25;
    operation.errorMessage = "timeout";
    EXPECT_THAT(operation.ToJson(), HasSubstr("\"operationId\":\"op-1\""));
    EXPECT_THAT(operation.ToJson(), HasSubstr("\"errorMessage\":\"timeout\""));

    VolumeSnapshotStatisticsSnapshot snapshot;
    snapshot.snapshotsCreated = 2;
    snapshot.currentOperations = 1;
    snapshot.emergencySnapshotsCreated = 4;
    snapshot.uptimeSeconds = 6;
    snapshot.byType[static_cast<size_t>(SnapshotType::Transportable)] = 5;
    EXPECT_THAT(snapshot.ToJson(), HasSubstr("\"type\":\"Transportable\""));
    EXPECT_THAT(snapshot.ToJson(), HasSubstr("\"uptimeSeconds\":6"));

    EXPECT_EQ(GetVSSResultName(VSSResult::ProviderVeto), "ProviderVeto");
    EXPECT_EQ(GetSnapshotTypeName(SnapshotType::Transportable), "Transportable");
    EXPECT_EQ(GetSnapshotStateName(SnapshotState::Committed), "Committed");
    EXPECT_EQ(GetWriterStateName(WriterState::Failed), "Failed");
    EXPECT_EQ(GetVSSResultName(static_cast<VSSResult>(0xFF)), "UnknownError");
    EXPECT_EQ(VolumeSnapshotService::GetVersionString(), "3.1.0");
}

}  // namespace
