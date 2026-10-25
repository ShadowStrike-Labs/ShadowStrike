// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * ShadowStrike Phantom - Module self-test guard
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 */

/**
 * @file ModuleSelfTest_Tests.cpp
 * @brief Calls SelfTest on every reachable module, because nothing else in the product did.
 *
 * Each module writes a SelfTest encoding real invariants - AttachmentScanner's checks PE detection,
 * extension classification and high-risk extension detection in three lines - and every one of them was dead
 * weight, because no code anywhere in the tree called any of them. Two of the three examined by hand had been
 * returning false permanently:
 *
 *   FirefoxAddonScanner::SelfTest  the Critical permission tier was unreachable      fixed 111119b7
 *   AttachmentScanner::SelfTest    magic typing could not match a two-byte header    fixed cf530cf6
 *
 * Neither failure was visible, because a self-test nobody runs is a comment. This file runs them.
 *
 * SCOPE. Four namespaces the duplicate-type sweep showed to be collision-free, so their headers can share one
 * translation unit. Banking and Backup headers now compose too (BankingHeadersCompose_Tests.cpp,
 * BackupHeadersCompose_Tests.cpp); their modules belong here once their implementations are linked into
 * this binary (task 264).
 *
 * Initialize was not idempotent (288, fixed): the second call returned false, indistinguishable from a genuine
 * failure. So state is tested first, initialisation attempted only if needed, and the state re-checked rather
 * than the return value trusted.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <string>

#include "Products/Community/PhantomHome/WebProtection/AdBlocker.hpp"
#include "Products/Community/PhantomHome/WebProtection/BrowserProtection.hpp"
#include "Products/Community/PhantomHome/WebProtection/ChromeExtensionScanner.hpp"
#include "Products/Community/PhantomHome/WebProtection/FirefoxAddonScanner.hpp"
#include "Products/Community/PhantomHome/WebProtection/MaliciousDownloadBlocker.hpp"
#include "Products/Community/PhantomHome/WebProtection/PhishingDetector.hpp"
#include "Products/Community/PhantomHome/WebProtection/SafeBrowsingAPI.hpp"
#include "Products/Community/PhantomHome/WebProtection/TrackerBlocker.hpp"

#include "Products/Community/PhantomHome/USB_Protection/BadUSBDetector.hpp"
#include "Products/Community/PhantomHome/USB_Protection/DeviceControlManager.hpp"
#include "Products/Community/PhantomHome/USB_Protection/USBAutorunBlocker.hpp"
#include "Products/Community/PhantomHome/USB_Protection/USBDeviceMonitor.hpp"
#include "Products/Community/PhantomHome/USB_Protection/USBScanner.hpp"

#include "Products/Community/PhantomHome/CryptoMinersProtection/BrowserMinerDetector.hpp"
#include "Products/Community/PhantomHome/CryptoMinersProtection/CPUUsageAnalyzer.hpp"
#include "Products/Community/PhantomHome/CryptoMinersProtection/CryptoMinerDetector.hpp"
#include "Products/Community/PhantomHome/CryptoMinersProtection/GPUMiningDetector.hpp"
#include "Products/Community/PhantomHome/CryptoMinersProtection/PoolConnectionDetector.hpp"

#include "Products/Community/PhantomHome/IoT/IoTDeviceScanner.hpp"
#include "Products/Community/PhantomHome/IoT/SmartHomeProtection.hpp"

#include "Products/Community/PhantomHome/GameMode/GameModeManager.hpp"
#include "Products/Community/PhantomHome/GameMode/GameProcessDetector.hpp"
#include "Products/Community/PhantomHome/GameMode/OverlayProtection.hpp"

namespace {

/// @brief Initialise if needed, then run the module's own self-test.
///
/// Every failure message names the module, because a bare false from one of twenty-one is not actionable.
template <typename T>
void ExpectSelfTestPasses(const char* moduleName, T& instance) {
    if (!instance.IsInitialized()) {
        (void)instance.Initialize();
    }
    ASSERT_TRUE(instance.IsInitialized())
        << moduleName << " could not be initialised, so its self-test was not reached";

    // Task 288: Initialize on a running module is success, and leaves it running.
    EXPECT_TRUE(instance.Initialize())
        << moduleName << "::Initialize returned false on an already-initialised module, which a caller "
                         "cannot tell from a real failure";
    EXPECT_TRUE(instance.IsInitialized()) << moduleName << " stopped being initialised after a second Initialize";

    EXPECT_TRUE(instance.SelfTest())
        << moduleName << "::SelfTest returned false. Read the module's own error log line - the self-test "
                         "names which of its checks failed, and it is asserting something the module itself "
                         "considers a requirement.";
}

// ============================================================================
// Web protection
// ============================================================================

TEST(ModuleSelfTest, WebProtectionModulesPassTheirOwnChecks) {
    ExpectSelfTestPasses("AdBlocker", ::ShadowStrike::WebBrowser::AdBlocker::Instance());
    ExpectSelfTestPasses("BrowserProtection", ::ShadowStrike::WebBrowser::BrowserProtection::Instance());
    ExpectSelfTestPasses("ChromeExtensionScanner",
                         ::ShadowStrike::WebBrowser::ChromeExtensionScanner::Instance());
    ExpectSelfTestPasses("FirefoxAddonScanner",
                         ::ShadowStrike::WebBrowser::FirefoxAddonScanner::Instance());
    ExpectSelfTestPasses("MaliciousDownloadBlocker",
                         ::ShadowStrike::WebBrowser::MaliciousDownloadBlocker::Instance());
    ExpectSelfTestPasses("PhishingDetector", ::ShadowStrike::WebBrowser::PhishingDetector::Instance());
    ExpectSelfTestPasses("SafeBrowsingAPI", ::ShadowStrike::WebBrowser::SafeBrowsingAPI::Instance());
    ExpectSelfTestPasses("TrackerBlocker", ::ShadowStrike::WebBrowser::TrackerBlocker::Instance());
}

// ============================================================================
// USB protection
// ============================================================================

// The BrowserProtection self-test used to add its own names to the live lists and remove them
// again, so a user entry with the same name was deleted (task 248). The names below are the
// ones it used; a self-test must leave every entry exactly where it found it.
TEST(ModuleSelfTest, BrowserProtectionSelfTestLeavesTheUsersListsAlone) {
    auto& bp = ::ShadowStrike::WebBrowser::BrowserProtection::Instance();
    if (!bp.IsInitialized()) {
        (void)bp.Initialize();
    }
    ASSERT_TRUE(bp.IsInitialized());
    const std::string blocked = "test-selftest-malware.example.com";
    const std::string allowed = "test-selftest-safe.example.com";
    ASSERT_TRUE(bp.AddToBlocklist(blocked));
    ASSERT_TRUE(bp.AddToAllowlist(allowed));

    const bool ok = bp.SelfTest();
    const bool stillBlocked = bp.IsInBlocklist(blocked);
    const bool stillAllowed = bp.IsInAllowlist(allowed);
    (void)bp.RemoveFromBlocklist(blocked);
    (void)bp.RemoveFromAllowlist(allowed);

    EXPECT_TRUE(ok);
    EXPECT_TRUE(stillBlocked) << "the self-test removed a user's blocklist entry";
    EXPECT_TRUE(stillAllowed) << "the self-test removed a user's allowlist entry";
}

TEST(ModuleSelfTest, UsbProtectionModulesPassTheirOwnChecks) {
    ExpectSelfTestPasses("BadUSBDetector", ::ShadowStrike::USB::BadUSBDetector::Instance());
    ExpectSelfTestPasses("DeviceControlManager", ::ShadowStrike::USB::DeviceControlManager::Instance());
    ExpectSelfTestPasses("USBAutorunBlocker", ::ShadowStrike::USB::USBAutorunBlocker::Instance());
    ExpectSelfTestPasses("USBDeviceMonitor", ::ShadowStrike::USB::USBDeviceMonitor::Instance());
    ExpectSelfTestPasses("USBScanner", ::ShadowStrike::USB::USBScanner::Instance());
}

// ============================================================================
// Crypto miner protection
// ============================================================================

TEST(ModuleSelfTest, CryptoMinerModulesPassTheirOwnChecks) {
    ExpectSelfTestPasses("BrowserMinerDetector",
                         ::ShadowStrike::CryptoMiners::BrowserMinerDetector::Instance());
    ExpectSelfTestPasses("CPUUsageAnalyzer", ::ShadowStrike::CryptoMiners::CPUUsageAnalyzer::Instance());
    ExpectSelfTestPasses("CryptoMinerDetector",
                         ::ShadowStrike::CryptoMiners::CryptoMinerDetector::Instance());
    ExpectSelfTestPasses("GPUMiningDetector", ::ShadowStrike::CryptoMiners::GPUMiningDetector::Instance());
    ExpectSelfTestPasses("PoolConnectionDetector",
                         ::ShadowStrike::CryptoMiners::PoolConnectionDetector::Instance());
}

// ============================================================================
// Game mode
// ============================================================================

TEST(ModuleSelfTest, GameModeModulesPassTheirOwnChecks) {
    ExpectSelfTestPasses("GameModeManager", ::ShadowStrike::GameMode::GameModeManager::Instance());
    ExpectSelfTestPasses("GameProcessDetector", ::ShadowStrike::GameMode::GameProcessDetector::Instance());
    ExpectSelfTestPasses("OverlayProtection", ::ShadowStrike::GameMode::OverlayProtection::Instance());
}

// ============================================================================
// IoT
//
// The duplicate-type sweep found no divergence in ShadowStrike::IoT, so these headers share this translation
// unit. IoT/IPLeakProtection is NOT here: its source file has the same NAME as Privacy/IPLeakProtection.cpp,
// so MSBuild writes both to IPLeakProtection.obj and one silently overwrites the other - MSB8027, which then
// leaves Privacy symbols unresolved. That needs an ObjectFileName override or, better, the decision
// about which of the two modules survives. Filed.
// ============================================================================

TEST(ModuleSelfTest, IoTModulesPassTheirOwnChecks) {
    ExpectSelfTestPasses("IoT::IoTDeviceScanner", ::ShadowStrike::IoT::IoTDeviceScanner::Instance());
    ExpectSelfTestPasses("IoT::SmartHomeProtection", ::ShadowStrike::IoT::SmartHomeProtection::Instance());
}

}  // namespace
