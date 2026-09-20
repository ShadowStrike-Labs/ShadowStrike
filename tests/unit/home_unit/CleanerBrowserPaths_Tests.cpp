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
#include <vector>

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

TEST(CleanerBrowserPaths, SixOfSevenBrowsersHaveARecordedExecutablePath) {
    // PINNED AS IT BEHAVES, and the asymmetry is the finding. Six cases in the switch set executablePath;
    // Chromium's sets only profilePaths and processName, so GetBrowserPath(Chromium) returns nothing.
    //
    // The six that are set are hardcoded literals, so a path is returned whether or not the browser is
    // installed and whether or not it lives there - Chrome is frequently under Program Files (x86) or in
    // LOCALAPPDATA for a per-user install. SecureBrowser::GetBrowserPath solves this properly by expanding
    // several patterns and testing fs::exists on each, returning empty when none match. Copying that here is
    // filed; if these start returning empty, that landed - update the filing rather than this case.
    for (const BrowserType browser : kAllBrowsers) {
        const auto path = GetBrowserPath(browser);
        if (browser == BrowserType::Chromium) {
            EXPECT_TRUE(path.empty())
                << "Chromium gained an executable path, which is the gap this case records";
            continue;
        }
        EXPECT_FALSE(path.empty()) << Name(browser) << " has no recorded executable path";
        EXPECT_TRUE(path.is_absolute()) << Name(browser) << ": '" << path.string() << "'";
    }
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
