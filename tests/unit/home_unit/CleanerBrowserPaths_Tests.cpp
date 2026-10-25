// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * ShadowStrike Phantom - Privacy cleaner browser path tests
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 */

/**
 * @file CleanerBrowserPaths_Tests.cpp
 * @brief Pins that a browser profile path is absolute, because the allow-list for deletion is built from them.
 *
 * GetAllowedCleanerRoots appends GetBrowserProfilePaths' output to the set of locations the cleaner is
 * permitted to erase, and CleanerPathStartsWith normalises with weakly_canonical - which resolves a RELATIVE
 * path against the current working directory. Two of the seven SHGetFolderPathW calls in the module ignored
 * their result, and since the buffers are zero-initialised a failure left the base path empty and every
 * profile path relative.
 *
 * So "every path returned here is absolute" is the property that keeps the allow-list meaning what it says.
 * It cannot be tested by forcing the Win32 call to fail, so it is asserted directly on the output.
 *
 * CloseBrowser is deliberately NOT exercised. It enumerates processes and terminates every match, so calling
 * it in a test would close the browser of whoever is running the suite.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "PhantomCore/Utils/BrowserLocator.hpp"
#include "Products/Community/PhantomHome/Privacy/PrivacyCleaner.hpp"

namespace {

using ShadowStrike::Privacy::BrowserType;
using ShadowStrike::Privacy::GetBrowserPath;
using ShadowStrike::Privacy::GetBrowserProfilePaths;
using ShadowStrike::Privacy::IsBrowserRunning;

constexpr BrowserType kAllBrowsers[] = {
    BrowserType::Chrome, BrowserType::Firefox, BrowserType::Edge, BrowserType::Opera,
    BrowserType::Brave,  BrowserType::Vivaldi, BrowserType::Chromium,
};

const char* Name(BrowserType browser) {
    switch (browser) {
        case BrowserType::Chrome:   return "Chrome";
        case BrowserType::Firefox:  return "Firefox";
        case BrowserType::Edge:     return "Edge";
        case BrowserType::Opera:    return "Opera";
        case BrowserType::Brave:    return "Brave";
        case BrowserType::Vivaldi:  return "Vivaldi";
        case BrowserType::Chromium: return "Chromium";
        default:                    return "(other)";
    }
}

TEST(CleanerBrowserPaths, EveryProfilePathIsAbsolute) {
    // The invariant the fix exists for. A relative path here becomes an allowed DELETION root resolved
    // against whatever directory the process was started in.
    for (const BrowserType browser : kAllBrowsers) {
        const auto paths = GetBrowserProfilePaths(browser);
        for (const auto& path : paths) {
            EXPECT_TRUE(path.is_absolute())
                << Name(browser) << " yielded the relative profile path '" << path.string()
                << "'. GetAllowedCleanerRoots appends these to the delete allow-list, where a relative path "
                   "resolves against the current working directory.";
            EXPECT_FALSE(path.empty()) << Name(browser) << " yielded an empty profile path";
        }
    }
}

TEST(CleanerBrowserPaths, EveryProfilePathHasARootNameAndDirectory) {
    // Stronger than is_absolute on Windows, where a path beginning with a single backslash has a root
    // directory but no drive, and would still resolve somewhere unintended.
    for (const BrowserType browser : kAllBrowsers) {
        for (const auto& path : GetBrowserProfilePaths(browser)) {
            EXPECT_FALSE(path.root_name().empty())
                << Name(browser) << ": '" << path.string() << "' has no drive";
            EXPECT_FALSE(path.root_directory().empty())
                << Name(browser) << ": '" << path.string() << "' has no root directory";
        }
    }
}

TEST(CleanerBrowserPaths, ProfilePathsAreReturnedForTheKnownBrowsers) {
    // Non-vacuity. Without this the two cases above would pass against a function returning nothing at all -
    // which is exactly what the fix does when the folder query fails, so the distinction matters.
    std::size_t withPaths = 0;
    for (const BrowserType browser : kAllBrowsers) {
        if (!GetBrowserProfilePaths(browser).empty()) {
            ++withPaths;
        }
    }
    EXPECT_EQ(std::size(kAllBrowsers), withPaths)
        << "on a machine where CSIDL_APPDATA and CSIDL_LOCAL_APPDATA both resolve, every known browser "
           "should yield at least one profile path";
}

TEST(CleanerBrowserPaths, EachBrowserHasItsOwnProfileLocation) {
    // A switch that fell through would give two browsers the same path, and the cleaner would then erase one
    // browser's data while reporting the other.
    std::vector<std::filesystem::path> seen;
    for (const BrowserType browser : kAllBrowsers) {
        for (const auto& path : GetBrowserProfilePaths(browser)) {
            for (const auto& other : seen) {
                EXPECT_NE(other, path)
                    << Name(browser) << " shares a profile path with an earlier browser: " << path.string();
            }
            seen.push_back(path);
        }
    }
}

/// Points %LocalAppData% at a scratch directory for the life of the object, so a per-user install
/// can be planted without depending on what this machine has installed.
class ScopedLocalAppData {
public:
    ScopedLocalAppData() : m_dir(std::filesystem::temp_directory_path() / L"ss_task316_lad") {
        std::filesystem::create_directories(m_dir);
        wchar_t buf[32768] = {};
        const DWORD n = ::GetEnvironmentVariableW(L"LOCALAPPDATA", buf, 32768);
        m_had = n > 0 && n < 32768;
        m_old = m_had ? std::wstring(buf, n) : std::wstring{};
        ::SetEnvironmentVariableW(L"LOCALAPPDATA", m_dir.c_str());
    }
    ~ScopedLocalAppData() {
        ::SetEnvironmentVariableW(L"LOCALAPPDATA", m_had ? m_old.c_str() : nullptr);
        std::error_code ec;
        std::filesystem::remove_all(m_dir, ec);
    }
    [[nodiscard]] std::filesystem::path Plant(const std::filesystem::path& relative) const {
        const auto p = m_dir / relative;
        std::filesystem::create_directories(p.parent_path());
        std::ofstream(p) << "not a browser";
        return p;
    }
private:
    std::filesystem::path m_dir;
    std::wstring m_old;
    bool m_had = false;
};

TEST(CleanerBrowserPaths, AnExecutablePathIsReturnedOnlyWhenItExists) {
    // Task 316: six literals were returned whether or not the browser was installed there, and Chromium
    // had none. Every answer is now either empty or an existing absolute file.
    for (const BrowserType browser : kAllBrowsers) {
        const auto path = GetBrowserPath(browser);
        if (path.empty()) continue;
        EXPECT_TRUE(path.is_absolute()) << Name(browser);
        EXPECT_TRUE(std::filesystem::is_regular_file(path)) << Name(browser) << ": " << path.string();
    }
}

TEST(CleanerBrowserPaths, APerUserInstallIsFound) {
    // Chromium's only install form is per-user; Vivaldi and Opera default to per-user too.
    ScopedLocalAppData lad;
    const auto chromium = lad.Plant(L"Chromium\\Application\\chrome.exe");
    const auto vivaldi = lad.Plant(L"Vivaldi\\Application\\vivaldi.exe");
    std::error_code ec;
    EXPECT_TRUE(std::filesystem::equivalent(chromium, GetBrowserPath(BrowserType::Chromium), ec));
    EXPECT_TRUE(std::filesystem::equivalent(vivaldi, GetBrowserPath(BrowserType::Vivaldi), ec));
}

TEST(CleanerBrowserPaths, ChromiumIsNotMistakenForGoogleChrome) {
    // Chromium runs as chrome.exe. Detection must match the image path, or IsBrowserRunning(Chromium)
    // would answer for Chrome and CloseBrowser(Chromium) would terminate it. A Chromium executable
    // that is not running cannot be running, whatever chrome.exe processes exist.
    ScopedLocalAppData lad;
    (void)lad.Plant(L"Chromium\\Application\\chrome.exe");
    EXPECT_FALSE(IsBrowserRunning(BrowserType::Chromium));
}

TEST(BrowserLocator, EveryBrowserHasEnvironmentAnchoredCandidates) {
    using ShadowStrike::Utils::Browser::ExecutablePathPatterns;
    using ShadowStrike::Utils::Browser::ImagePathMatchRequired;
    using ShadowStrike::Utils::Browser::InstalledBrowser;
    using ShadowStrike::Utils::Browser::ProcessImageName;
    for (const auto b : {InstalledBrowser::Chrome, InstalledBrowser::Edge, InstalledBrowser::Firefox,
                         InstalledBrowser::Opera, InstalledBrowser::Brave, InstalledBrowser::Vivaldi,
                         InstalledBrowser::Chromium}) {
        const auto patterns = ExecutablePathPatterns(b);
        EXPECT_GE(patterns.size(), 2u);
        for (const auto p : patterns) {
            EXPECT_EQ(L'%', p.front()) << "a candidate not anchored on a known folder is a relative guess";
            EXPECT_TRUE(p.ends_with(L".exe"));
        }
        EXPECT_FALSE(ProcessImageName(b).empty());
        EXPECT_EQ(b == InstalledBrowser::Chromium, ImagePathMatchRequired(b))
            << "only an image name shared with another browser needs a path match";
    }
    EXPECT_EQ(ProcessImageName(InstalledBrowser::Chrome), ProcessImageName(InstalledBrowser::Chromium));
}

TEST(CleanerBrowserPaths, TheRunningCheckAnswersWithoutThrowing) {
    // Whether a browser is running depends on the machine, so the answer is not asserted - only that asking
    // is safe and consistent within a single call sequence. An unknown enum value must answer false rather
    // than fall through to an empty process name comparison.
    for (const BrowserType browser : kAllBrowsers) {
        EXPECT_NO_THROW({ (void)IsBrowserRunning(browser); }) << Name(browser);
    }
    EXPECT_FALSE(IsBrowserRunning(static_cast<BrowserType>(200)))
        << "an unrecognised browser has no process name, so nothing can be running";
}

}  // namespace
