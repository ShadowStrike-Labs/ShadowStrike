/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * The operator network blocklist loads from the data directory (task 78).
 *
 * RealTimeProtection passed the relative path "data/ip_blocklist.txt". A service's
 * working directory is System32, so the path never named the intended file and the
 * list never loaded. The loader now refuses a relative path, treats an absent list as
 * the normal "no operator entries" state, and the service passes
 * DataStorePaths::NetworkBlocklist().
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>

#include "../../../src/PhantomCore/RealTime/NetworkTrafficFilter.hpp"
#include "../../../src/PhantomCore/Utils/DataStorePaths.hpp"

namespace ShadowStrike::RealTime::Tests {
namespace {

std::filesystem::path BlocklistScratchDir() {
    auto dir = std::filesystem::temp_directory_path() / "phantom-blocklist-load";
    std::filesystem::create_directories(dir);
    return dir;
}

// Switches the working directory for one scope and always restores it.
class WorkingDirectoryGuard {
public:
    explicit WorkingDirectoryGuard(const std::filesystem::path& to)
        : m_saved(std::filesystem::current_path()) {
        std::filesystem::current_path(to);
    }
    ~WorkingDirectoryGuard() {
        std::error_code ec;
        std::filesystem::current_path(m_saved, ec);
    }
    WorkingDirectoryGuard(const WorkingDirectoryGuard&) = delete;
    WorkingDirectoryGuard& operator=(const WorkingDirectoryGuard&) = delete;

private:
    std::filesystem::path m_saved;
};

}  // namespace

// The relative path must be refused even when it DOES name a file from the current
// directory - otherwise "refused" and "absent" are indistinguishable.
TEST(NetworkBlocklistLoadTest, ARelativePathIsRefused) {
    auto& filter = NetworkTrafficFilter::Instance();
    const auto dir = BlocklistScratchDir();
    std::filesystem::create_directories(dir / "data");
    {
        std::ofstream out(dir / "data" / "ip_blocklist.txt");
        out << "relative-only.example\n";
    }
    {
        WorkingDirectoryGuard cwd(dir);
        ASSERT_TRUE(std::filesystem::exists(L"data/ip_blocklist.txt"));
        EXPECT_FALSE(filter.LoadBlockListFromFile(L"data/ip_blocklist.txt"));
    }
    EXPECT_FALSE(filter.IsDomainBlocked("relative-only.example"))
        << "a relative path was resolved and its entries were loaded";
    filter.UnblockDomain("relative-only.example");
    EXPECT_FALSE(filter.LoadBlockListFromFile(L""));
    std::error_code ec;
    std::filesystem::remove_all(dir / "data", ec);
}

TEST(NetworkBlocklistLoadTest, AnAbsentListLoadsNothing) {
    auto& filter = NetworkTrafficFilter::Instance();
    const auto missing = BlocklistScratchDir() / "not-present.txt";
    std::error_code ec;
    std::filesystem::remove(missing, ec);
    EXPECT_FALSE(filter.LoadBlockListFromFile(missing.wstring()));
}

TEST(NetworkBlocklistLoadTest, AListAtAnAbsolutePathLoadsBothKinds) {
    auto& filter = NetworkTrafficFilter::Instance();
    const auto file = BlocklistScratchDir() / "operator-list.txt";
    {
        std::ofstream out(file);
        out << "# operator list\n203.0.113.77  # documentation range\n\n  Blocked-Host.Example \n";
    }
    EXPECT_TRUE(filter.LoadBlockListFromFile(file.wstring()));
    EXPECT_TRUE(filter.IsIPBlocked(IPAddress::FromString("203.0.113.77")));
    EXPECT_TRUE(filter.IsDomainBlocked("blocked-host.example"));

    // The filter is a process-wide singleton; leave it as it was found.
    filter.UnblockIP(IPAddress::FromString("203.0.113.77"));
    filter.UnblockDomain("blocked-host.example");
    std::error_code ec;
    std::filesystem::remove(file, ec);
}

TEST(NetworkBlocklistLoadTest, TheServicePathIsAbsoluteAndInTheDataDirectory) {
    const std::filesystem::path path =
        std::filesystem::path(Utils::DataStorePaths::NetworkBlocklist()).lexically_normal();
    const std::filesystem::path dataDir =
        std::filesystem::path(Utils::DataStorePaths::GetDataDirectory()).lexically_normal();
    EXPECT_TRUE(path.is_absolute()) << path.string();
    EXPECT_EQ(path.parent_path(), dataDir) << path.string();
    EXPECT_EQ(path.filename().wstring(), std::wstring(L"ip_blocklist.txt"));
}

}  // namespace ShadowStrike::RealTime::Tests
