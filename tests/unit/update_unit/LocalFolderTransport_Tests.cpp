/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for deterministic LocalFolderTransport contracts.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <vector>

#include "../../../src/Shared_modules/Update/IUpdateTransport.hpp"
#include "Update_TestUtils.hpp"

namespace ShadowStrike::Update::Test {
namespace {

[[nodiscard]] const RemotePackageInfo* FindPackage(
    const std::vector<RemotePackageInfo>& packages,
    std::string_view packageId) {
    const auto it = std::find_if(packages.begin(), packages.end(), [packageId](const auto& pkg) {
        return pkg.packageId == packageId;
    });
    return it == packages.end() ? nullptr : &(*it);
}

}  // namespace

TEST(LocalFolderTransportTest, AvailabilityNameAndDirectoryMutationBehave) {
    ScopedTempDir tempDir(L"transport_available_");
    const auto missingDir = tempDir.Path() / "missing";
    LocalFolderTransport transport(missingDir);

    EXPECT_EQ(transport.GetName(), "LocalFolderTransport");
    EXPECT_FALSE(transport.IsAvailable());
    EXPECT_EQ(transport.GetStagingDirectory(), missingDir);

    transport.SetStagingDirectory(tempDir.Path());
    EXPECT_EQ(transport.GetStagingDirectory(), tempDir.Path());
    EXPECT_TRUE(transport.IsAvailable());

    transport.CancelFetch();
    EXPECT_TRUE(transport.IsCancelled());
}

TEST(LocalFolderTransportTest, QueryAvailablePackagesSurfacesMetadataAndFiltersUnsupportedFiles) {
    ScopedTempDir tempDir(L"transport_query_");

    WriteAllBytes(tempDir.File(L"main.pkg"), std::vector<uint8_t>{1, 2, 3, 4});
    WriteAllText(tempDir.File(L"main.manifest"), "version=2026.04.08\nmandatory=true\n");
    WriteAllBytes(tempDir.File(L"delta.delta"), std::vector<uint8_t>{5, 6, 7});
    WriteAllBytes(tempDir.File(L"suite.spkg"), std::vector<uint8_t>{8, 9});
    WriteAllBytes(tempDir.File(L"ignored.txt"), std::vector<uint8_t>{1});
    WriteAllBytes(tempDir.File(L"zero.pkg"), std::vector<uint8_t>{});

    LocalFolderTransport transport(tempDir.Path());
    const auto packages = transport.QueryAvailablePackages("stable");

    ASSERT_EQ(packages.size(), 3u);

    const auto* mainPackage = FindPackage(packages, "main");
    ASSERT_NE(mainPackage, nullptr);
    EXPECT_EQ(mainPackage->version, "2026.04.08");
    EXPECT_TRUE(mainPackage->isMandatory);
    EXPECT_FALSE(mainPackage->isDelta);
    EXPECT_FALSE(mainPackage->checksum.empty());

    const auto* deltaPackage = FindPackage(packages, "delta");
    ASSERT_NE(deltaPackage, nullptr);
    EXPECT_TRUE(deltaPackage->isDelta);
    EXPECT_EQ(deltaPackage->size, 3u);

    const auto* suitePackage = FindPackage(packages, "suite");
    ASSERT_NE(suitePackage, nullptr);
    EXPECT_FALSE(suitePackage->isDelta);

    EXPECT_EQ(FindPackage(packages, "ignored"), nullptr);
    EXPECT_EQ(FindPackage(packages, "zero"), nullptr);
}

TEST(LocalFolderTransportTest, FetchPackageCopiesContentAndReportsProgress) {
    ScopedTempDir sourceDir(L"transport_source_");
    ScopedTempDir destinationDir(L"transport_dest_");

    std::vector<uint8_t> payload(128 * 1024, 0x5A);
    WriteAllBytes(sourceDir.File(L"payload.pkg"), payload);

    LocalFolderTransport transport(sourceDir.Path());

    TransportProgress lastProgress;
    bool progressCalled = false;
    const auto destination = destinationDir.Path() / "nested" / "payload.pkg";
    const auto result = transport.FetchPackage(
        "payload.pkg",
        destination,
        [&lastProgress, &progressCalled](const TransportProgress& progress) {
            progressCalled = true;
            lastProgress = progress;
        });

    ASSERT_TRUE(result.success);
    EXPECT_EQ(result.localPath, destination);
    EXPECT_EQ(result.bytesTransferred, payload.size());
    EXPECT_TRUE(progressCalled);
    EXPECT_EQ(lastProgress.totalBytes, payload.size());
    EXPECT_EQ(lastProgress.bytesTransferred, payload.size());
    EXPECT_EQ(lastProgress.progressPercent, 100);
    EXPECT_EQ(ReadAllBytes(destination), payload);
}

TEST(LocalFolderTransportTest, MissingSourceReturnsActionableError) {
    ScopedTempDir tempDir(L"transport_missing_");
    LocalFolderTransport transport(tempDir.Path());

    const auto result = transport.FetchPackage("missing.pkg", tempDir.File(L"out.pkg"));
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.errorCode, ERROR_FILE_NOT_FOUND);
    EXPECT_TRUE(Contains(result.errorMessage, "Source file not found"));
}

TEST(LocalFolderTransportTest, QueryHandlesCaseInsensitiveExtensionsAndDuplicatePackageIds) {
    ScopedTempDir tempDir(L"transport_dupes_");

    WriteAllBytes(tempDir.File(L"caps.PKG"), std::vector<uint8_t>{1, 2, 3});
    WriteAllText(tempDir.File(L"caps.manifest"), "version=9.9.9\n");
    WriteAllBytes(tempDir.File(L"same.pkg"), std::vector<uint8_t>{4, 5});
    WriteAllBytes(tempDir.File(L"same.SSDP"), std::vector<uint8_t>{6, 7, 8});

    LocalFolderTransport transport(tempDir.Path());
    const auto packages = transport.QueryAvailablePackages("stable");

    ASSERT_EQ(packages.size(), 3u);

    const auto* capsPackage = FindPackage(packages, "caps");
    ASSERT_NE(capsPackage, nullptr);
    EXPECT_EQ(capsPackage->version, "9.9.9");
    EXPECT_FALSE(capsPackage->isDelta);

    const auto duplicateIds = std::count_if(packages.begin(), packages.end(), [](const auto& pkg) {
        return pkg.packageId == "same";
    });
    EXPECT_EQ(duplicateIds, 2);

    const auto ssdpCount = std::count_if(packages.begin(), packages.end(), [](const auto& pkg) {
        return pkg.packageId == "same" && pkg.isDelta;
    });
    EXPECT_EQ(ssdpCount, 1);
}

TEST(LocalFolderTransportTest, CancellationCleansPartialOutputAndNextFetchResetsState) {
    ScopedTempDir sourceDir(L"transport_cancel_source_");
    ScopedTempDir destinationDir(L"transport_cancel_dest_");

    std::vector<uint8_t> payload(2 * 1024 * 1024, 0xA5);
    WriteAllBytes(sourceDir.File(L"payload.pkg"), payload);

    LocalFolderTransport transport(sourceDir.Path());
    bool cancellationRequested = false;
    const auto destination = destinationDir.Path() / "payload.pkg";

    const auto cancelled = transport.FetchPackage(
        "payload.pkg",
        destination,
        [&transport, &cancellationRequested](const TransportProgress& progress) {
            if (!cancellationRequested && progress.bytesTransferred > 0) {
                cancellationRequested = true;
                transport.CancelFetch();
            }
        });

    EXPECT_FALSE(cancelled.success);
    EXPECT_EQ(cancelled.errorCode, ERROR_CANCELLED);
    EXPECT_TRUE(Contains(cancelled.errorMessage, "cancelled"));
    EXPECT_TRUE(cancellationRequested);
    EXPECT_TRUE(transport.IsCancelled());
    EXPECT_FALSE(std::filesystem::exists(destination));

    const auto retry = transport.FetchPackage("payload.pkg", destination);
    ASSERT_TRUE(retry.success);
    EXPECT_FALSE(transport.IsCancelled());
    EXPECT_EQ(retry.bytesTransferred, payload.size());
    EXPECT_EQ(ReadAllBytes(destination), payload);
}

}  // namespace ShadowStrike::Update::Test
