/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file BadUSBDeviceIdentity_Tests.cpp
 * @brief How a USB device's identity alone decides whether it is treated as an attack tool.
 *
 * A BadUSB device is a keystroke injector dressed as a flash drive, so the product has to judge one
 * from its USB identity before anything is typed. Two mechanisms do that, and they are calibrated very
 * differently:
 *
 *   KNOWN_BAD_DEVICES matches an exact VID AND PID. Seven entries, each a specific attack tool. The
 *   table carries an explicit exclusion note explaining that FTDI 0x0403:0x6001 was left OUT because
 *   too many legitimate FTDI-based devices exist - serial adapters, lab equipment, industrial
 *   controllers - and the false-positive rate would be unacceptable.
 *
 *   IsSuspiciousVendor matches a VID alone, for six microcontroller vendors. It used to decide a
 *   Suspicious verdict by itself - every STM32 board and Raspberry Pi Pico - which is what the FTDI
 *   note calls unacceptable. Since task 280 it counts only when the device also presents a keyboard,
 *   so an attack tool with a modified product id is still caught and a serial adapter is not.
 *
 * Also pinned: the free IsVIDPIDKnownMalicious and the member IsKnownBadDevice are separate copies of
 * the same loop over the same table. They cannot disagree on data, only on logic, so they are required
 * here to agree on every input.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/USB_Protection/BadUSBDetector.hpp"

#include <cstdint>
#include <utility>
#include <vector>

namespace ShadowStrike::USB::Test {
namespace {

/// Every entry of BadUSBConstants::KNOWN_BAD_DEVICES, restated so a case can assert against the table
/// without reaching into it - and so that dropping an entry from the product fails a test here.
const std::vector<std::pair<std::uint16_t, std::uint16_t>>& KnownBadPairs() {
    static const std::vector<std::pair<std::uint16_t, std::uint16_t>> pairs = {
        {0x1FC9, 0x000C},  // USB Rubber Ducky
        {0x2E8A, 0x000A},  // Bash Bunny MK2
        {0x16D0, 0x0753},  // Digispark
        {0x2341, 0x0001},  // Arduino HID
        {0x16C0, 0x0483},  // Teensy HID
        {0x1B4F, 0x9203},  // SparkFun Pro Micro
        {0x239A, 0x000E},  // Adafruit HID
    };
    return pairs;
}

constexpr std::uint16_t kFtdiVid = 0x0403;   ///< Deliberately excluded from the table
constexpr std::uint16_t kFtdiPid = 0x6001;
constexpr std::uint16_t kStmVid = 0x0483;    ///< STMicroelectronics - a suspicious VID
constexpr std::uint16_t kRpiVid = 0x2E8A;    ///< Raspberry Pi - a suspicious VID

class BadUSBDeviceIdentityTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        // Initialize is not idempotent (filed 288), so the STATE is tested rather than the return value - 
        // otherwise this suite would only pass when it is the first to initialise the singleton, which is an accident of test ordering.
        if (!BadUSBDetector::Instance().IsInitialized()) {
            (void)BadUSBDetector::Instance().Initialize();
        }
        ASSERT_TRUE(BadUSBDetector::Instance().IsInitialized())
            << "the detector could not be initialised, so no verdict below would mean anything";
    }
};

// ============================================================================================
// The exact-match table
// ============================================================================================

TEST_F(BadUSBDeviceIdentityTest, EveryKnownAttackToolIsRecognised) {
    for (const auto& [vid, pid] : KnownBadPairs()) {
        EXPECT_TRUE(IsVIDPIDKnownMalicious(vid, pid))
            << "VID_" << std::hex << vid << " PID_" << pid
            << " is in KNOWN_BAD_DEVICES but was not recognised";
    }
}

TEST_F(BadUSBDeviceIdentityTest, AnUnlistedDeviceIsNotKnownBad) {
    // Anti-vacuity: without this the case above would pass for a function that always returns true.
    EXPECT_FALSE(IsVIDPIDKnownMalicious(0x046D, 0xC52B)) << "an ordinary mouse receiver";
    EXPECT_FALSE(IsVIDPIDKnownMalicious(0x0000, 0x0000));
    EXPECT_FALSE(IsVIDPIDKnownMalicious(0xFFFF, 0xFFFF));
}

TEST_F(BadUSBDeviceIdentityTest, TheTableMatchesOnBothIdsNotJustTheVendor) {
    // The table is deliberately VID+PID. A vendor whose id appears in it must not be condemned by the
    // vendor id alone, or the table would be a vendor blocklist wearing a product-id column.
    for (const auto& [vid, pid] : KnownBadPairs()) {
        const auto otherPid = static_cast<std::uint16_t>(pid ^ 0x5A5A);
        EXPECT_FALSE(IsVIDPIDKnownMalicious(vid, otherPid))
            << "VID_" << std::hex << vid << " matched with a product id that is not in the table";
    }
}

TEST_F(BadUSBDeviceIdentityTest, TheFtdiExclusionHolds) {
    // KNOWN_BAD_DEVICES carries a comment stating FTDI 0x0403:0x6001 is excluded on purpose because
    // the false-positive rate over legitimate FTDI serial adapters, lab equipment and industrial
    // controllers would be unacceptable. If this now fails, that decision was reversed - read the
    // comment and this case before accepting the change.
    EXPECT_FALSE(IsVIDPIDKnownMalicious(kFtdiVid, kFtdiPid))
        << "FTDI was added to the known-bad table, contradicting the exclusion note beside it";
}

TEST_F(BadUSBDeviceIdentityTest, TheTwoCopiesOfTheKnownBadCheckAgree) {
    // A free function and a member function each run their own loop over the same table. They cannot
    // disagree on data, only if one is edited alone - which is what this case exists to catch.
    auto& detector = BadUSBDetector::Instance();
    std::vector<std::pair<std::uint16_t, std::uint16_t>> probes = KnownBadPairs();
    probes.push_back({kFtdiVid, kFtdiPid});
    probes.push_back({0x046D, 0xC52B});
    probes.push_back({kStmVid, 0x5740});
    probes.push_back({0x1FC9, 0x0001});  // a known-bad vendor with an unlisted product id

    for (const auto& [vid, pid] : probes) {
        EXPECT_EQ(IsVIDPIDKnownMalicious(vid, pid), detector.IsKnownBadDevice(vid, pid))
            << "the free and member known-bad checks disagree for VID_" << std::hex << vid
            << " PID_" << pid << ", so one of the two duplicated loops was changed alone";
    }
}

// ============================================================================================
// The vendor-wide check - pinned as it stands, not endorsed
// ============================================================================================

TEST_F(BadUSBDeviceIdentityTest, AKnownAttackToolIsReportedAsKnownBad) {
    auto& detector = BadUSBDetector::Instance();
    for (const auto& [vid, pid] : KnownBadPairs()) {
        EXPECT_EQ(DeviceAnalysisResult::KnownBadDevice, detector.AnalyzeDevice(vid, pid, true))
            << "VID_" << std::hex << vid << " PID_" << pid << " is a listed attack tool";
    }
}

TEST_F(BadUSBDeviceIdentityTest, AnOrdinaryDeviceIsReportedSafe) {
    // Anti-vacuity for the case below: the analyser must be capable of answering Safe, or "Suspicious"
    // would carry no information.
    auto& detector = BadUSBDetector::Instance();
    EXPECT_EQ(DeviceAnalysisResult::Safe, detector.AnalyzeDevice(0x046D, 0xC52B, true));
    EXPECT_EQ(DeviceAnalysisResult::Safe, detector.AnalyzeDevice(kFtdiVid, kFtdiPid, true))
        << "an FTDI serial adapter must be Safe - that is the whole point of the exclusion note";
}

TEST_F(BadUSBDeviceIdentityTest, AMicrocontrollerVendorAloneIsNotSuspicious) {
    // An STM32 virtual COM port and a Raspberry Pi Pico in its boot loader present no keyboard.
    auto& detector = BadUSBDetector::Instance();
    EXPECT_EQ(DeviceAnalysisResult::Safe, detector.AnalyzeDevice(kStmVid, 0x5740, false));
    EXPECT_EQ(DeviceAnalysisResult::Safe, detector.AnalyzeDevice(kRpiVid, 0x0003, false));
}

TEST_F(BadUSBDeviceIdentityTest, AMicrocontrollerVendorPresentingAKeyboardIsSuspicious) {
    // The coverage the vendor check exists for: an attack tool with a modified product id is still a
    // keyboard. Unlisted product ids, so the exact-match table cannot be what catches them.
    auto& detector = BadUSBDetector::Instance();
    for (const std::uint16_t vid : {0x16C0, 0x16D0, 0x1FC9, 0x2E8A, 0x1D6B, 0x0483}) {
        EXPECT_EQ(DeviceAnalysisResult::Suspicious, detector.AnalyzeDevice(vid, 0x7777, true))
            << "VID_" << std::hex << vid;
    }
    EXPECT_EQ(DeviceAnalysisResult::Safe, detector.AnalyzeDevice(0x046D, 0xC31C, true))
        << "an ordinary keyboard vendor is not suspicious";
}

TEST_F(BadUSBDeviceIdentityTest, AListedAttackToolIsKnownBadWithoutKeyboardEvidence) {
    auto& detector = BadUSBDetector::Instance();
    for (const auto& [vid, pid] : KnownBadPairs()) {
        EXPECT_EQ(DeviceAnalysisResult::KnownBadDevice, detector.AnalyzeDevice(vid, pid, false));
    }
}

TEST_F(BadUSBDeviceIdentityTest, TheSelfTestNeverReachesEnforcement) {
    // Task 338. SelfTest fed 200 keystrokes per second through the live pipeline, which the module
    // correctly judged an attack - and its response terminated every recently started cmd, pwsh,
    // powershell, wscript, cscript and mshta process on the machine running the test.
    auto& detector = BadUSBDetector::Instance();
    const auto before = detector.GetStatistics().attacksDetected;
    EXPECT_TRUE(detector.SelfTest());
    EXPECT_EQ(before, detector.GetStatistics().attacksDetected)
        << "the self-test was detected as an attack, so it ran the real response";
    EXPECT_FALSE(detector.IsAttackInProgress());
}

TEST_F(BadUSBDeviceIdentityTest, TheVendorIdAndProductIdAreNotInterchangeable) {
    // 0x0483 is BOTH a suspicious vendor id (STMicroelectronics) and the product id of the Teensy HID
    // entry, whose vendor id is 0x16C0. Reversing the pair must not produce a known-bad verdict, which
    // is the concrete reason the two fields must never be compared symmetrically.
    auto& detector = BadUSBDetector::Instance();
    EXPECT_TRUE(IsVIDPIDKnownMalicious(0x16C0, 0x0483)) << "the Teensy HID entry, in the right order";
    EXPECT_FALSE(IsVIDPIDKnownMalicious(0x0483, 0x16C0))
        << "the reversed pair was treated as the same device, so the two id fields are being compared "
           "without regard to which is which";
    EXPECT_NE(DeviceAnalysisResult::KnownBadDevice, detector.AnalyzeDevice(0x0483, 0x16C0, true));
}

}  // namespace
}  // namespace ShadowStrike::USB::Test
