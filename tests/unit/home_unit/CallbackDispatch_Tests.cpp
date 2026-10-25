/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file CallbackDispatch_Tests.cpp
 * @brief Callback registries that accepted registrations and never dispatched (task 300).
 *
 * Each registry below had a declaration, a push_back and a clear, and no dispatch. The cases
 * register, trigger the event through the public API, and require exactly the expected calls.
 * Each callback also calls back into its module, which deadlocks if dispatch runs under the
 * module's own lock. USBDeviceMonitor's policy and error callbacks and OutlookScanner's error
 * callbacks have no public trigger without a device or Outlook, and are held by the contract
 * guard CallbackRegistriesAreDispatchedTests.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

#include "Products/Community/PhantomHome/Banking/CertificatePinning.hpp"
#include "Products/Community/PhantomHome/WebProtection/FirefoxAddonScanner.hpp"
#include "Products/Community/PhantomHome/WebProtection/TrackerBlocker.hpp"

namespace {

class ScratchDir {
public:
    explicit ScratchDir(const wchar_t* name) : m_dir(std::filesystem::temp_directory_path() / name) {
        std::filesystem::create_directories(m_dir);
    }
    ~ScratchDir() { std::error_code ec; std::filesystem::remove_all(m_dir, ec); }
    [[nodiscard]] std::filesystem::path Write(const wchar_t* file, const char* text) const {
        const auto p = m_dir / file;
        std::ofstream(p, std::ios::binary) << text;
        return p;
    }
    [[nodiscard]] const std::filesystem::path& Path() const { return m_dir; }
private:
    std::filesystem::path m_dir;
};

TEST(CallbackDispatch, CertificatePinChangesNotifyAfterTheStoreIsUnlocked) {
    using ShadowStrike::Banking::CertificatePinning;
    auto& pinning = CertificatePinning::Instance();
    std::vector<std::pair<std::string, bool>> seen;
    size_t pinsSeenInsideCallback = 0;
    pinning.RegisterPinUpdateCallback([&](const std::string& domain, bool added) {
        seen.emplace_back(domain, added);
        pinsSeenInsideCallback = pinning.GetPins(domain).size();   // re-entrant: no deadlock
    });
    const std::string domain = "task300-pins.example.com";
    const std::string hash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";   // 32 zero bytes
    pinning.AddSPKIPin("Task300-Pins.Example.com", hash, false);
    const size_t insideAfterAdd = pinsSeenInsideCallback;
    pinning.AddSPKIPin(domain, "not base64 at all", false);                    // rejected: no event
    pinning.RemovePin(domain);
    pinning.RemovePin(domain);                                                 // already gone: no event
    pinning.UnregisterCallbacks();

    const std::vector<std::pair<std::string, bool>> expected = {{domain, true}, {domain, false}};
    EXPECT_EQ(expected, seen);
    EXPECT_EQ(1u, insideAfterAdd) << "the callback ran before the pin was visible";
}

TEST(CallbackDispatch, LoadingATrackerBlocklistNotifiesUpdateCallbacks) {
    using ShadowStrike::WebBrowser::BlocklistInfo;
    using ShadowStrike::WebBrowser::BlocklistSource;
    using ShadowStrike::WebBrowser::TrackerBlocker;
    auto& blocker = TrackerBlocker::Instance();
    if (!blocker.IsInitialized()) (void)blocker.Initialize();
    ASSERT_TRUE(blocker.IsInitialized());

    ScratchDir dir(L"ss_task300_tb");
    const auto list = dir.Write(L"task300-list.txt", "! comment\n||task300-a.example^\n||task300-b.example^\n");
    std::vector<BlocklistInfo> seen;
    size_t listsSeenInsideCallback = 0;
    const auto id = blocker.RegisterUpdateCallback([&](const BlocklistInfo& info) {
        seen.push_back(info);
        listsSeenInsideCallback = blocker.GetBlocklists().size();   // re-entrant: no deadlock
    });
    const bool loaded = blocker.LoadBlocklist(list, BlocklistSource::Custom, "task300");
    blocker.UnregisterUpdateCallback(id);
    (void)blocker.UnloadBlocklist(seen.empty() ? std::string("task300-list.txt") : seen.front().id);

    ASSERT_TRUE(loaded);
    ASSERT_EQ(1u, seen.size());
    EXPECT_EQ(2u, seen.front().ruleCount);
    EXPECT_GE(listsSeenInsideCallback, 1u);
}

TEST(CallbackDispatch, AnUnreadableFirefoxProfileReportsAnError) {
    using ShadowStrike::WebBrowser::FirefoxAddonScanner;
    auto& scanner = FirefoxAddonScanner::Instance();
    if (!scanner.IsInitialized()) (void)scanner.Initialize();
    ASSERT_TRUE(scanner.IsInitialized());

    ScratchDir dir(L"ss_task300_ff");
    (void)dir.Write(L"extensions.json", "{ this is not json");
    std::vector<int> codes;
    scanner.RegisterErrorCallback([&](const std::string& message, int code) {
        codes.push_back(code);
        EXPECT_FALSE(message.empty());
        (void)scanner.GetStatistics();   // re-entrant: no deadlock
    });
    (void)scanner.ScanProfile(dir.Path());
    scanner.UnregisterCallbacks();

    EXPECT_EQ(1u, codes.size()) << "a corrupt add-on registry was skipped without notice";
}

TEST(CallbackDispatch, AReadableEmptyFirefoxProfileReportsNothing) {
    using ShadowStrike::WebBrowser::FirefoxAddonScanner;
    auto& scanner = FirefoxAddonScanner::Instance();
    if (!scanner.IsInitialized()) (void)scanner.Initialize();
    ScratchDir dir(L"ss_task300_ff2");
    (void)dir.Write(L"extensions.json", R"({"addons":[]})");
    int calls = 0;
    scanner.RegisterErrorCallback([&](const std::string&, int) { ++calls; });
    (void)scanner.ScanProfile(dir.Path());
    scanner.UnregisterCallbacks();
    EXPECT_EQ(0, calls);
}

}  // namespace
